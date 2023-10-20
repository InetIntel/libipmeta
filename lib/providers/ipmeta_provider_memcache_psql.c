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
#include <math.h>

#include "libcsv/csv.h"
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

enum {
    IPINFO_PSQL_COLUMN_PREFIX = 0,
    IPINFO_PSQL_COLUMN_SOURCE = 1,
    IPINFO_PSQL_COLUMN_PUBLISHED = 2,
    IPINFO_PSQL_COLUMN_COUNTRY_CODE = 3,
    IPINFO_PSQL_COLUMN_CONTINENT_CODE = 4,
    IPINFO_PSQL_COLUMN_REGION = 5,
    IPINFO_PSQL_COLUMN_CITY = 6,
    IPINFO_PSQL_COLUMN_POST_CODE = 7,
    IPINFO_PSQL_COLUMN_LATITUDE = 8,
    IPINFO_PSQL_COLUMN_LONGITUDE = 9,
    IPINFO_PSQL_COLUMN_TIMEZONE = 10,
};

enum {
    IPINFO_MC_COLUMN_COUNTRY_CODE = 0,
    IPINFO_MC_COLUMN_CONTINENT_CODE = 1,
    IPINFO_MC_COLUMN_REGION = 2,
    IPINFO_MC_COLUMN_CITY = 3,
    IPINFO_MC_COLUMN_POST_CODE = 4,
    IPINFO_MC_COLUMN_LATITUDE = 5,
    IPINFO_MC_COLUMN_LONGITUDE = 6,
    IPINFO_MC_COLUMN_TIMEZONE = 7,
    IPINFO_MC_COLUMN_NUMIPS = 8,
    IPINFO_MC_COLUMN_END
};

const char *QUERY_PFX_SQL_BASE =
    "SELECT * FROM ("
    "    SELECT * FROM %s_lookup WHERE prefix::inet && $1::inet "
    ") WHERE published = (SELECT MAX(published) FROM ipmeta_records) "
    " ORDER BY prefix ASC";

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

    uint8_t disable_memcache;
    ipmeta_record_t *record;
    ipmeta_record_set_t *lookup_results;
    int column_num;
    int lookup_record_cnt;
    uint64_t lookup_ip_cnt;

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

#ifdef HAVE_LIBPQ
static int process_psql_row_ipinfo(PGresult *pg_res, int row_id, int cols,
        ipmeta_record_t *rec, uint64_t *numips) {

    char *value;
    int i;
    ipvx_prefix_t pfx;

    if (rec == NULL) {
        ipmeta_log(__func__,
                "NULL record provided, cannot populate from database row");
        return -1;
    }

    if (pg_res == NULL) {
        ipmeta_log(__func__,
                "NULL query result provided, cannot parse row %d", row_id);
        return -1;
    }

    for (i = 0; i < cols; i++) {
        value = PQgetvalue(pg_res, row_id, i);

        switch(i) {
        case IPINFO_PSQL_COLUMN_PREFIX:
            if (ipvx_pton_pfx(value, &pfx) < 0) {
                ipmeta_log(__func__,
                    "invalid prefix returned by PSQL query: %s", value);
                return -1;
            }
            if (pfx.family == AF_INET) {
                *numips = pow(2, (32 - pfx.masklen));
            } else if (pfx.family == AF_INET6) {
                *numips = pow(2, (128 - pfx.masklen));
            } else {
                *numips = 0;
            }
            break;
        case IPINFO_PSQL_COLUMN_SOURCE:
            rec->source = IPMETA_PROVIDER_MEMCACHE_PSQL;
            break;
        case IPINFO_PSQL_COLUMN_PUBLISHED:
            // not included in the record, so skip
            break;
        case IPINFO_PSQL_COLUMN_COUNTRY_CODE:
            strncpy(rec->country_code, value, 2);
            break;
        case IPINFO_PSQL_COLUMN_CONTINENT_CODE:
            strncpy(rec->continent_code, value, 2);
            break;
        case IPINFO_PSQL_COLUMN_REGION:
            rec->region = strdup(value);
            break;
        case IPINFO_PSQL_COLUMN_CITY:
            rec->city = strdup(value);
            break;
        case IPINFO_PSQL_COLUMN_POST_CODE:
            rec->post_code = strdup(value);
            break;
        case IPINFO_PSQL_COLUMN_LATITUDE:
            rec->latitude = strtod(value, NULL);
            break;
        case IPINFO_PSQL_COLUMN_LONGITUDE:
            rec->longitude = strtod(value, NULL);
            break;
        case IPINFO_PSQL_COLUMN_TIMEZONE:
            rec->timezone = strdup(value);
            break;
        default:
            ipmeta_log(__func__,
                "unexpected number of columns returned by PSQL query: %d", cols);
            return -1;
        }
    }
    return 0;

}
#endif

static void parse_memcached_cell(void *s, size_t i, void *data) {
    ipmeta_provider_memcache_psql_state_t *state;
    char *tok = (char *)s;

    state = (ipmeta_provider_memcache_psql_state_t *)data;

    if (state->record == NULL) {
        state->record = calloc(1, sizeof(ipmeta_record_t));
    }

    switch(state->column_num) {
        case IPINFO_MC_COLUMN_COUNTRY_CODE:
            strncpy(state->record->country_code, tok, 2);
            break;
        case IPINFO_MC_COLUMN_CONTINENT_CODE:
            strncpy(state->record->continent_code, tok, 2);
            break;
        case IPINFO_MC_COLUMN_REGION:
            state->record->region = strdup(tok);
            break;
        case IPINFO_MC_COLUMN_CITY:
            state->record->city = strdup(tok);
            break;
        case IPINFO_MC_COLUMN_POST_CODE:
            state->record->post_code = strdup(tok);
            break;
        case IPINFO_MC_COLUMN_LATITUDE:
            state->record->latitude = strtod(tok, NULL);
            break;
        case IPINFO_MC_COLUMN_LONGITUDE:
            state->record->longitude = strtod(tok, NULL);
            break;
        case IPINFO_MC_COLUMN_TIMEZONE:
            state->record->timezone = strdup(tok);
            break;
        case IPINFO_MC_COLUMN_NUMIPS:
            state->lookup_ip_cnt = strtol(tok, NULL, 10);
            break;
        default:
            ipmeta_log(__func__, "Unexpected trailing column %d in memcached prefix data: %s", state->column_num, tok);
            return;
    }

    state->column_num += 1;
}

static void parse_memcached_row(int c, void *data) {
    ipmeta_provider_memcache_psql_state_t *state;
    state = (ipmeta_provider_memcache_psql_state_t *)data;

    if (state->record == NULL) {
        return;
    }


    if (state->column_num != IPINFO_MC_COLUMN_END) {
        ipmeta_log(__func__, "Unexpected number of columns in memcached prefix data: %d\n", state->column_num);
        return;
    }

    if (state->lookup_results == NULL) {
        ipmeta_clean_record(state->record);
    }

    state->record->source = IPMETA_PROVIDER_MEMCACHE_PSQL;
    if (ipmeta_record_set_add_record(state->lookup_results, state->record,
                state->lookup_ip_cnt) != 0) {
        return;
    }

    state->record = NULL;
    state->lookup_record_cnt += 1;
    state->column_num = 0;
}


#if HAVE_LIBMEMCACHED
static int memcache_lookup(ipmeta_provider_memcache_psql_state_t *state,
        char *tofind, char *first_key, ipmeta_record_set_t *records,
        int *rec_count) {

    char mc_key[1024];
    char *value;
    int pfx_cnt, i;
    memcached_return_t rc;
    size_t vallen;
    uint32_t flags;
    ipmeta_record_t *rec;
    struct csv_parser csvp;

    if (state->disable_memcache) {
        return 0;
    }

    value = memcached_get(state->mc_hdl, first_key, strlen(first_key),
        &vallen, &flags, &rc);
    if (rc == MEMCACHED_NOTFOUND) {
        return 0;
    }
    if (rc != MEMCACHED_SUCCESS) {
        return -1;
    }

    pfx_cnt = (int) strtol(value, NULL, 10);
    free(value);
    if (pfx_cnt == 0) {
        return 0;
    }

    csv_init(&csvp, CSV_STRICT | CSV_REPALL_NL | CSV_STRICT_FINI |
            CSV_APPEND_NULL | CSV_EMPTY_IS_NULL);
    state->lookup_record_cnt = 0;
    state->lookup_ip_cnt = 0;
    state->lookup_results = records;
    state->column_num = 0;

    for (i = 0; i < pfx_cnt; i++) {
        snprintf(mc_key, 1024, "ipmeta_ipinfo_pfx_%s_%d", tofind, i);
        value = memcached_get(state->mc_hdl, mc_key, strlen(mc_key),
                &vallen, &flags, &rc);
        if (csv_parse(&csvp, value, vallen, parse_memcached_cell,
                parse_memcached_row, state) != (int) vallen) {
            ipmeta_log(__func__, "CSV parsing error: %s",
                    csv_strerror(csv_error(&csvp)));
            state->lookup_results = NULL;
            free(value);
            csv_free(&csvp);
            return -1;
        }
        free(value);
    }
    if (csv_fini(&csvp, parse_memcached_cell, parse_memcached_row, state) != 0) {
        ipmeta_log(__func__, "CSV parsing error: %s",
                csv_strerror(csv_error(&csvp)));
        state->lookup_results = NULL;
        csv_free(&csvp);
        return -1;
    }
    *rec_count = state->lookup_record_cnt;
    state->lookup_results = NULL;
    csv_free(&csvp);
    return *rec_count;
}
#endif

#define family_size(fam) \
    ((fam) == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))

static int lookup_prefix(ipmeta_provider_memcache_psql_state_t *state,
        ipvx_prefix_t *pfx, ipmeta_record_set_t *records) {

#ifdef HAVE_LIBPQ
#ifdef HAVE_LIBMEMCACHED
    const char *params[QUERY_PFX_PARAM_COUNT];
    char tofind[INET6_ADDRSTRLEN + 4];
    PGresult *pg_res;
    int rows = 0, r, cols, mc_res;
    ipmeta_record_t *rec;
    int rec_count = 0;
    uint64_t numips = 0;
    char mc_key[1024];
    char cache_str[4096];
    char row_cnt_str[32];
    int nocache = 0;
    memcached_return_t rc;

    if (ipvx_ntop_pfx(pfx, tofind) == NULL) {
        return IPMETA_ERR_INPUT;
    }

    snprintf(mc_key, 1024, "ipmeta_ipinfo_pfxcnt_%s", tofind);

    mc_res = memcache_lookup(state, tofind, mc_key, records, &rec_count);
    if (mc_res < 0) {
        ipmeta_log(__func__,
                "Error during memcached lookup for %s, falling back to DB",
                tofind);
        state->disable_memcache = 1;
    }
    if (mc_res > 0) {
        return rec_count;
    }

    params[0] = tofind;

    pg_res = PQexecPrepared(state->pgconn, "query_pfx_stmt",
            QUERY_PFX_PARAM_COUNT, params, NULL, NULL, 0);
    if (PQntuples(pg_res) < 0) {
        ipmeta_log(__func__, "ERROR: querying postgresql for prefix %s -- %s",
                tofind, PQerrorMessage(state->pgconn));
        PQclear(pg_res);
        return IPMETA_ERR_INTERNAL;
    }


    cols = PQnfields(pg_res);
    rows = PQntuples(pg_res);

    if (rows <= 0) {
        return 0;
    }

    if (state->disable_memcache == 0) {
        snprintf(row_cnt_str, 32, "%d", rows);
        rc = memcached_set(state->mc_hdl, mc_key, strlen(mc_key),
            row_cnt_str, strlen(row_cnt_str), 24 * 60 * 60, 0);
        if (rc != MEMCACHED_SUCCESS) {
            ipmeta_log(__func__, "Unable to cache SQL query result for %s",
                    tofind);
            nocache = 1;
        }
    }

    for (r = 0; r < rows; r++) {
        rec = calloc(1, sizeof(ipmeta_record_t));

        /* TODO make this more generic, use function pointers from the
         * provider itself... */
        if (strcmp(state->provider, "ipinfo") == 0) {
            if (process_psql_row_ipinfo(pg_res, r, cols, rec, &numips) < 0) {
                ipmeta_free_record(rec);
                rec_count = -1;
                break;
            }
        }

        if (ipmeta_record_set_add_record(records, rec, numips) != 0) {
            ipmeta_free_record(rec);
            rec_count = -1;
            break;
        }

        if (state->disable_memcache == 0 && nocache == 0) {
            snprintf(mc_key, 1024, "ipmeta_ipinfo_pfx_%s_%d", tofind, r);
            /* Add individual record to memcache */
            snprintf(cache_str, 4096, "%s,%s,%s,%s,%s,%.6f,%.6f,%s,%lu\n",
                    rec->country_code, rec->continent_code, rec->region,
                    rec->city, rec->post_code, rec->latitude, rec->longitude,
                    rec->timezone, numips);

            rc = memcached_set(state->mc_hdl, mc_key, strlen(mc_key), cache_str,
                    strlen(cache_str), 24 * 60 * 60, 0);
            if (rc != MEMCACHED_SUCCESS) {
                ipmeta_log(__func__, "Unable to cache SQL query result for %s",
                        tofind);
                nocache = 1;
            }
        }

        rec_count += 1;
    }
    PQclear(pg_res);

#endif /* HAVE_LIBMEMCACHED */
#endif /* HAVE_LIBPQ */

    return rec_count;
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

