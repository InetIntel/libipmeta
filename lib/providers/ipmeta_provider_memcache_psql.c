/* This source code is Copyright (c) 2023 Georgia Tech Research Corporation. All
 * Rights Reserved. Permission to copy, modify, and distribute this software and
 * its documentation for academic research and education purposes, without fee,
 * and without a written agreement is hereby granted, provided that the above
 * copyright notice, this paragraph and the following three paragraphs appear in
 * all copies. Permission to make use of this software for other than academic
 * research and education purposes may be obtained by contacting:
 *
 *  Office of Technology Licensing
 *  Georgia Institute of Technology
 *  926 Dalney Street, NW
 *  Atlanta, GA 30318
 *  404.385.8066
 *  techlicensing@gtrc.gatech.edu
 *
 * This software program and documentation are copyrighted by Georgia Tech
 * Research Corporation (GTRC). The software program and documentation are 
 * supplied "as is", without any accompanying services from GTRC. GTRC does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH RESEARCH CORPORATION HAS
 * NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * This source code is part of the libipmeta software. The original libipmeta
 * software is Copyright (c) 2013-2020 The Regents of the University of
 * California. All rights reserved. Permission to copy, modify, and distribute
 * this software for academic research and education purposes is subject to the
 * conditions and copyright notices in the source code files and in the
 * included LICENSE file.
 */

/* This source file was written by Shane Alcock, on behalf of the
 * Internet Intelligence Lab at the Georgia Institute of Technology.
 */

#include "config.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "ipvx_utils.h"

#ifdef HAVE_LIBPQ
#include <postgresql/libpq-fe.h>
#endif

#include "libipmeta_int.h"
#include "ipmeta_provider_memcache_psql.h"

#ifdef HAVE_LIBMEMCACHED
#include <libmemcached/memcached.h>
#endif

#define PROVIDER_NAME "memcache_psql"

#define STATE(p) (IPMETA_PROVIDER_STATE(memcache_psql, p))

const char *QUERY_PFX_SQL_BASE =
    "SELECT * FROM %s_lookup WHERE prefix::inet >>= inet $1 "
    "ORDER BY published DESC, netmask(prefix) DESC LIMIT 1";

#define QUERY_PFX_PARAM_COUNT 1

static ipmeta_provider_t ipmeta_provider_memcache_psql = {
    IPMETA_PROVIDER_MEMCACHE_PSQL, PROVIDER_NAME,
    IPMETA_PROVIDER_GENERATE_PTRS(memcache_psql) };

typedef struct ipmeta_provider_memcache_psql_state {
#ifdef HAVE_LIBMEMCACHED
    memcached_st *mc_hdl;
#endif

    char *mc_host;
    int mc_port;

    char *psql_dbname;
    char *psql_host;
    char *psql_port;
    char *psql_user;
    char *psql_password;

    char *provider;

#ifdef HAVE_LIBPQ
    PGconn *pgconn;
    PGresult *query_pfx_stmt;
#endif
} ipmeta_provider_memcache_psql_state_t;

static void usage(void) {
    fprintf(stderr,
        "Usage: %s [ <arguments> ]\n"
        "    -H <host>  The IP or hostname of the PSQL server (default: localhost)\n"
        "    -P <port>  The port number of the PSQL service (default: 5672)\n"
        "    -U <user>  The username to log in with (default: postgres)\n"
        "    -A <password> The password to log in with (default: no password) \n"
        "    -d <dbname>  The name of the database (default: ipmeta)\n"
        "    -M <host>  The IP or hostname where the memcached service is running  (default: localhost)\n"
        "    -C <port>  The listening port number for memcached (default: 11211)\n"
        "    -p <provider>  The metadata provider to use when querying the PSQL database (default: ipinfo)\n",
        PROVIDER_NAME);
}

static int parse_args(ipmeta_provider_memcache_psql_state_t *state, int argc,
        char **argv) {

    int opt;
    char *ptr = NULL;

    if (argc == 0) {
        usage();
        return -1;
    }

    optind = 1;
    while ((opt = getopt(argc, argv, "H:P:d:U:A:p:M:C:?")) >= 0) {
        switch(opt) {
            case 'H':
                state->psql_host = strdup(optarg);
                break;
            case 'P':
                state->psql_port = strdup(optarg);
                break;
            case 'd':
                state->psql_dbname = strdup(optarg);
                break;
            case 'U':
                state->psql_user = strdup(optarg);
                break;
            case 'A':
                state->psql_password = strdup(optarg);
                break;
            case 'M':
                state->mc_host = strdup(optarg);
                break;
            case 'C':
                state->mc_port = atoi(optarg);
                break;
            case 'p':
                state->provider = strdup(optarg);
                break;
            case '?':
            case ':':
            default:
                usage();
                return -1;
        }
    }

    if (optind != argc) {
        ipmeta_log(__func__, "ERROR: extra arguments to %s", PROVIDER_NAME);
        usage();
        return -1;
    }

    if (state->psql_host == NULL) {
        state->psql_host = strdup("localhost");
    }
    if (state->psql_port == NULL) {
        state->psql_port = strdup("5672");
    }
    if (state->psql_dbname == NULL) {
        state->psql_dbname = strdup("ipmeta");
    }
    if (state->psql_user == NULL) {
        state->psql_user = strdup("postgres");
    }
    if (state->provider == NULL) {
        state->provider = strdup("ipinfo");
    }

    if (state->mc_port <= 0 || state->mc_port > 65535) {
        ipmeta_log(__func__, "using default memcached port number: 11211");
        state->mc_port = 11211;
    }
    if (state->mc_host == NULL) {
        ipmeta_log(__func__, "using default memcached host: localhost");
        state->mc_host = strdup("localhost");
    }
    return 0;
}

static int connect_pgsql(ipmeta_provider_memcache_psql_state_t *state) {

    char query_sql[2048];

#ifdef HAVE_LIBPQ
    snprintf(query_sql, 2048, QUERY_PFX_SQL_BASE, state->provider);

    state->pgconn = PQsetdbLogin(state->psql_host, state->psql_port,
            NULL, NULL, state->psql_dbname, state->psql_user,
            state->psql_password);
    if (PQstatus(state->pgconn) == CONNECTION_BAD) {
        ipmeta_log(__func__, "failed to connect to PSQL database: %s",
                PQerrorMessage(state->pgconn));
        return -1;
    }

    state->query_pfx_stmt = PQprepare(state->pgconn, "query_pfx_stmt",
            query_sql, QUERY_PFX_PARAM_COUNT, NULL);
    if (PQresultStatus(state->query_pfx_stmt) != PGRES_COMMAND_OK) {
        ipmeta_log(__func__, "failed to prepare prefix query statement: %s",
                PQerrorMessage(state->pgconn));
        return -1;
    }
#endif

    return 0;
}

static int setup_memcached(ipmeta_provider_memcache_psql_state_t *state) {

#ifdef HAVE_LIBMEMCACHED
    memcached_return_t rc;

    state->mc_hdl = memcached_create(NULL);
    rc = memcached_server_add(state->mc_hdl, state->mc_host, state->mc_port);

    if (rc != MEMCACHED_SUCCESS) {
        ipmeta_log(__func__,
                "unable to add memcached server to server list: %d", rc);
        return -1;
    }
#endif

    return 0;
}

ipmeta_provider_t *ipmeta_provider_memcache_psql_alloc() {
    return &ipmeta_provider_memcache_psql;
}

int ipmeta_provider_memcache_psql_init(ipmeta_provider_t *provider, int argc,
        char **argv) {

    ipmeta_provider_memcache_psql_state_t *state = NULL;
    if ((state = calloc(1, sizeof(ipmeta_provider_memcache_psql_state_t)))
            == NULL) {
        ipmeta_log(__func__,
                "unable to allocate ipmeta_provider_memcache_psql_state_t");
        return -1;
    }

    ipmeta_provider_register_state(provider, state);
    if (parse_args(state, argc, argv) != 0) {
        return -1;
    }

    if (connect_pgsql(state) == -1) {
        ipmeta_log(__func__,
                "failed to connect to postgresql database");
        return -1;
    }

    if (setup_memcached(state) == -1) {
        ipmeta_log(__func__,
                "failed to setup memcached instance");
        return -1;
    }

    return 0;
}

void ipmeta_provider_memcache_psql_free(ipmeta_provider_t *provider) {
    ipmeta_provider_memcache_psql_state_t *state = STATE(provider);

    if (state == NULL) {
        return;
    }

#ifdef HAVE_LIBMEMCACHED
    if (state->mc_hdl) {
        memcached_free(state->mc_hdl);
    }
#endif

#ifdef HAVE_LIBPQ
    if (state->query_pfx_stmt) {
        PQclear(state->query_pfx_stmt);
    }

    if (state->pgconn) {
        PQfinish(state->pgconn);
    }
#endif

    if (state->provider) {
        free(state->provider);
    }

    if (state->mc_host) {
        free(state->mc_host);
    }

    if (state->psql_dbname) {
        free(state->psql_dbname);
    }

    if (state->psql_user) {
        free(state->psql_user);
    }

    if (state->psql_password) {
        free(state->psql_password);
    }

    if (state->psql_host) {
        free(state->psql_host);
    }

    if (state->psql_port) {
        free(state->psql_port);
    }
    free(state);
}

#define family_size(fam) \
    ((fam) == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))

static int lookup_prefix(ipmeta_provider_memcache_psql_state_t *state,
        ipvx_prefix_t *pfx, ipmeta_record_set_t *records) {

#ifdef HAVE_LIBPQ
#ifdef HAVE_LIBMEMCACHED
    char tofind[INET6_ADDRSTRLEN + 4];
    PGresult *pg_res;
    int cols = 0, i;
    ipmeta_record_t *rec;
    char *value;

    if (ipvx_ntop_pfx(pfx, tofind) == NULL) {
        return IPMETA_ERR_INPUT;
    }


    pg_res = PQexecPrepared(state->pgconn, "query_pfx_stmt",
            QUERY_PFX_PARAM_COUNT, (const char **)(&tofind), NULL, NULL, 0);
    if (PQntuples(pg_res) < 0) {
        ipmeta_log(__func__, "ERROR: querying postgresql for prefix %s -- %s",
                tofind, PQerrorMessage(state->pgconn));
        PQclear(pg_res);
        return IPMETA_ERR_INTERNAL;
    }

    cols = PQnfields(pg_res);
    if (PQntuples(pg_res) > 0) {
        rec = calloc(1, sizeof(ipmeta_record_t));
    } else {
        rec = NULL;
    }

    for (i = 0; i < PQnfields(pg_res); i++) {
        value = PQgetvalue(pg_res, 0, i);
    }

    PQclear(pg_res);

#endif /* HAVE_LIBMEMCACHED */
#endif /* HAVE_LIBPQ */

    return 0;
}

int ipmeta_provider_memcache_psql_lookup_pfx(ipmeta_provider_t *provider,
        int family, void *addrp, uint8_t pfxlen, ipmeta_record_set_t *records) {

    ipvx_prefix_t pfx;
    ipmeta_provider_memcache_psql_state_t *state = STATE(provider);

    if (state == NULL) {
        return 0;
    }
    pfx.family = family;
    pfx.masklen = pfxlen;
    memcpy(&pfx.addr, (uint8_t *)addrp, family_size(family));

    return lookup_prefix(state, &pfx, records);
}

int ipmeta_provider_memcache_psql_lookup_addr(ipmeta_provider_t *provider,
        int family, void *addrp, ipmeta_record_set_t *found) {

    ipvx_prefix_t pfx;
    ipmeta_provider_memcache_psql_state_t *state = STATE(provider);

    if (state == NULL) {
        return 0;
    }
    pfx.family = family;
    if (family == AF_INET) {
        pfx.masklen = 32;
    } else {
        pfx.masklen = 128;
    }
    memcpy(&pfx.addr, (uint8_t *)addrp, family_size(family));

    return lookup_prefix(state, &pfx, found);
}

