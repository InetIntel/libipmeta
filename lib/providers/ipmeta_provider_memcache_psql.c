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
#include <time.h>

#include "libcsv/csv.h"
#include "utils.h"
#include "ipvx_utils.h"
#include "khash.h"

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

KHASH_SET_INIT_STR(str_set)
KHASH_MAP_INIT_STR(ll_map, double)
KHASH_MAP_INIT_STR(num_map, uint64_t)

enum {
    IPINFO_PSQL_COLUMN_FIRSTADDR = 0,
    IPINFO_PSQL_COLUMN_LASTADDR = 1,
    IPINFO_PSQL_COLUMN_PREFIX = 2,
    IPINFO_PSQL_COLUMN_SOURCE = 3,
    IPINFO_PSQL_COLUMN_PUBLISHED = 4,
    IPINFO_PSQL_COLUMN_COUNTRY_CODE = 5,
    IPINFO_PSQL_COLUMN_CONTINENT_CODE = 6,
    IPINFO_PSQL_COLUMN_REGION = 7,
    IPINFO_PSQL_COLUMN_CITY = 8,
    IPINFO_PSQL_COLUMN_POST_CODE = 9,
    IPINFO_PSQL_COLUMN_LATITUDE = 10,
    IPINFO_PSQL_COLUMN_LONGITUDE = 11,
    IPINFO_PSQL_COLUMN_TIMEZONE = 12,
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
    "    SELECT * FROM %s_lookup WHERE firstaddr BETWEEN $1 AND $2 "
    "    OR lastaddr BETWEEN $1 AND $2 "
    ") WHERE published = $3 "
    " ORDER BY prefix ASC";

const char *QUERY_ENCAP_PFX_SQL_BASE =
    "SELECT * FROM ("
    "    SELECT * FROM %s_lookup WHERE published = $2 AND firstaddr <= $1 "
    "    ORDER BY firstaddr DESC LIMIT 10) "
    "WHERE lastaddr >= $1";


const char *GET_LATEST_TIMESTAMP_SQL =
    "SELECT datatimestamp FROM ipmeta_uploads WHERE source = $1 "
    "ORDER BY uploaded DESC LIMIT 1";

#define QUERY_PFX_PARAM_COUNT 3
#define QUERY_ENCAP_PFX_PARAM_COUNT 2
#define GET_LATEST_TS_PARAM_COUNT 1
#define MAX_CACHE_SIZE (1024 * 1024 * 10)
#define MORE_CACHED_FLAG "MORE..."

const uint8_t MORE_CACHED_FLAG_BYTES[7] = {
    0x4D, 0x4F, 0x52, 0x45, 0x2E, 0x2E, 0x2E
};
#define MORE_CACHED_FLAG_LEN 7

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

    char *max_published;
    time_t last_max_pub_check;

    uint8_t disable_memcache;
    uint8_t more_cached_records;
    ipmeta_record_t *record;
    ipmeta_record_set_t *lookup_results;
    int column_num;
    int lookup_record_cnt;
    uint64_t lookup_ip_cnt;

    char *accum_cache;

    uint32_t cache_hits;
    uint32_t cache_misses;

    ipmeta_record_t *freelist_head;

    /** set of timezone strings */
    kh_str_set_t *timezones;

    /** set of region name strings */
    kh_str_set_t *regions;

    /** set of city name strings */
    kh_str_set_t *cities;

    /** set of postcode strings */
    kh_str_set_t *postcodes;

    /** set of latitudes and longitudes */
    kh_ll_map_t *latlongs;

    /** set of "numbers of IPs" */
    kh_num_map_t *numips;

#ifdef HAVE_LIBPQ
    PGconn *pgconn;
    PGresult *query_pfx_stmt;
    PGresult *query_encap_stmt;
    PGresult *query_latest_ts_stmt;
#endif
} ipmeta_provider_memcache_psql_state_t;

static inline char *sanitize(char *orig, char *repl) {
    char *r, *w;

    r = orig; w = repl;

    while (*r) {
        if (*r == ',') {
            r++;
            continue;
        }
        if (*r == '"') {
            *r = 0x27;  // single quote
            continue;
        }
        *w = *r;
        r++; w++;
    }
    *w = '\0';
    return repl;
}

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

    snprintf(query_sql, 2048, QUERY_ENCAP_PFX_SQL_BASE, state->provider);
    state->query_encap_stmt = PQprepare(state->pgconn, "query_encap_stmt",
            query_sql, QUERY_ENCAP_PFX_PARAM_COUNT, NULL);
    if (PQresultStatus(state->query_encap_stmt) != PGRES_COMMAND_OK) {
        ipmeta_log(__func__, "failed to prepare encap query statement: %s",
                PQerrorMessage(state->pgconn));
        return -1;
    }
    state->query_latest_ts_stmt = PQprepare(state->pgconn, "query_ts_stmt",
            GET_LATEST_TIMESTAMP_SQL, GET_LATEST_TS_PARAM_COUNT, NULL);
    if (PQresultStatus(state->query_latest_ts_stmt) != PGRES_COMMAND_OK) {
        ipmeta_log(__func__, "failed to prepare timestamp query statement: %s",
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

static inline double insert_ll_into_map(char *latlong, kh_ll_map_t **map) {
    int ret;
    khiter_t k;

    if (latlong == NULL) {
        return -1.0;
    }
    k = kh_get(ll_map, *map, latlong);
    if (k != kh_end(*map)) {
        return (double) kh_value(*map, k);
    } else {
        k = kh_put(ll_map, *map, latlong, &ret);
        if (ret >= 0) {
            kh_key(*map, k) = strdup(latlong);
            kh_value(*map, k) = strtod(latlong, NULL);
            return (double) kh_value(*map, k);
        }
    }
    return -1.0;
}

static inline uint64_t insert_number_into_set(char *numstr,
        kh_num_map_t **map) {
    int ret;
    khiter_t k;

    if (numstr == NULL) {
        return 0;
    }
    k = kh_get(num_map, *map, numstr);
    if (k != kh_end(*map)) {
        return (uint64_t) kh_value(*map, k);
    } else {
        k = kh_put(num_map, *map, numstr, &ret);
        if (ret >= 0) {
            kh_key(*map, k) = strdup(numstr);
            kh_value(*map, k) = (uint64_t) strtol(numstr, NULL, 10);
            return (uint64_t) kh_value(*map, k);
        }
    }
    return 0;
}

static inline char *insert_name_into_set(char *name, kh_str_set_t **set,
        uint8_t sanitize_req) {
    int ret;
    char sanitized[1024];
    khiter_t k;

    if (name == NULL) {
        return NULL;
    }

    if (sanitize_req) {
        if (strlen(name) >= 1023) {
            ipmeta_log(__func__,
                    "unable to parse location token because it is too long: %s",
                    name);
            return NULL;
        }
        sanitize(name, sanitized);
        name = sanitized;
    }

    k = kh_get(str_set, *set, name);
    if (k != kh_end(*set)) {
        return (char *) kh_key(*set, k);
    } else {
        k = kh_put(str_set, *set, name, &ret);
        if (ret >= 0) {
            kh_key(*set, k) = strdup(name);
            return (char *) kh_key(*set, k);
        }
    }
    return NULL;
}

static void rec_free(ipmeta_record_t *rec, void *arg) {

    /* All of our strings should be in the maps of region names, post codes,
     * etc so we don't want to free them.
     */
    ipmeta_provider_memcache_psql_state_t *state =
            (ipmeta_provider_memcache_psql_state_t *)arg;

    rec->next = state->freelist_head;
    state->freelist_head = rec;
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

    state->freelist_head = NULL;
    state->timezones = kh_init(str_set);
    state->regions = kh_init(str_set);
    state->postcodes = kh_init(str_set);
    state->cities = kh_init(str_set);
    state->latlongs = kh_init(ll_map);
    state->numips = kh_init(num_map);

    ipmeta_provider_register_state(provider, state);
    if (parse_args(state, argc, argv) != 0) {
        return -1;
    }

    if (setup_memcached(state) == -1) {
        ipmeta_log(__func__,
                "failed to setup memcached instance");
        return -1;
    }

    srand(time(NULL));
    return 0;
}

void ipmeta_provider_memcache_psql_free(ipmeta_provider_t *provider) {
    ipmeta_provider_memcache_psql_state_t *state = STATE(provider);
    khiter_t k;
    ipmeta_record_t *ptr, *tmp;

    if (state == NULL) {
        return;
    }

    ipmeta_log(__func__,
            "Total cache hits: %u      Total cache misses: %u",
            state->cache_hits, state->cache_misses);

    ptr = state->freelist_head;
    while (ptr) {
        tmp = ptr;
        ptr = ptr->next;
        free(tmp);
    }

    if (state->timezones) {
        for (k = 0; k < kh_end(state->timezones); ++k) {
            if (kh_exist(state->timezones, k)) {
                free((void *)kh_key(state->timezones, k));
            }
        }
        kh_destroy(str_set, state->timezones);
    }

    if (state->regions) {
        for (k = 0; k < kh_end(state->regions); ++k) {
            if (kh_exist(state->regions, k)) {
                free((void *)kh_key(state->regions, k));
            }
        }
        kh_destroy(str_set, state->regions);
    }

    if (state->cities) {
        for (k = 0; k < kh_end(state->cities); ++k) {
            if (kh_exist(state->cities, k)) {
                free((void *)kh_key(state->cities, k));
            }
        }
        kh_destroy(str_set, state->cities);
    }

    if (state->postcodes) {
        for (k = 0; k < kh_end(state->postcodes); ++k) {
            if (kh_exist(state->postcodes, k)) {
                free((void *)kh_key(state->postcodes, k));
            }
        }
        kh_destroy(str_set, state->postcodes);
    }

    if (state->latlongs) {
        for (k = 0; k < kh_end(state->latlongs); ++k) {
            if (kh_exist(state->latlongs, k)) {
                free((void *)kh_key(state->latlongs, k));
            }
        }
        kh_destroy(ll_map, state->latlongs);
    }

    if (state->numips) {
        for (k = 0; k < kh_end(state->numips); ++k) {
            if (kh_exist(state->numips, k)) {
                free((void *)kh_key(state->numips, k));
            }
        }
        kh_destroy(num_map, state->numips);
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
    if (state->query_encap_stmt) {
        PQclear(state->query_encap_stmt);
    }
    if (state->query_latest_ts_stmt) {
        PQclear(state->query_latest_ts_stmt);
    }

    if (state->pgconn) {
        PQfinish(state->pgconn);
    }
#endif

    if (state->max_published) {
        free(state->max_published);
    }

    if (state->accum_cache) {
        free(state->accum_cache);
    }

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
static int process_psql_row_ipinfo(ipmeta_provider_memcache_psql_state_t *state,
        PGresult *pg_res, int row_id, int cols,
        ipmeta_record_t *rec, uint64_t *numips,
        ipvx_prefix_t *pfx) {

    char *value;
    int i;

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
        case IPINFO_PSQL_COLUMN_FIRSTADDR:
        case IPINFO_PSQL_COLUMN_LASTADDR:
            break;
        case IPINFO_PSQL_COLUMN_PREFIX:
            if (ipvx_pton_pfx(value, pfx) < 0) {
                ipmeta_log(__func__,
                    "invalid prefix returned by PSQL query: %s", value);
                return -1;
            }
            if (pfx->family == AF_INET) {
                *numips = pow(2, (32 - pfx->masklen));
            } else if (pfx->family == AF_INET6) {
                *numips = pow(2, (128 - pfx->masklen));
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
            rec->region = insert_name_into_set(value, &(state->regions), 1);
            break;
        case IPINFO_PSQL_COLUMN_CITY:
            rec->city = insert_name_into_set(value, &(state->cities), 1);
            break;
        case IPINFO_PSQL_COLUMN_POST_CODE:
            rec->post_code = insert_name_into_set(value, &(state->postcodes),
                    1);
            break;
        case IPINFO_PSQL_COLUMN_LATITUDE:
            rec->latitude = insert_ll_into_map(value, &(state->latlongs));
            break;
        case IPINFO_PSQL_COLUMN_LONGITUDE:
            rec->longitude = insert_ll_into_map(value, &(state->latlongs));
            break;
        case IPINFO_PSQL_COLUMN_TIMEZONE:
            rec->timezone = insert_name_into_set(value, &(state->timezones), 0);
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

    if (tok == NULL) {
        state->column_num += 1;
        return;
    }

    if (state->record == NULL) {
        if (state->freelist_head) {
            state->record = state->freelist_head;
            state->freelist_head = state->record->next;
            memset(state->record, 0, sizeof(ipmeta_record_t));
        } else {
            state->record = calloc(1, sizeof(ipmeta_record_t));
        }
        strncpy(state->record->country_code, "??", 2);
        strncpy(state->record->continent_code, "??", 2);
    }

    switch(state->column_num) {
        case IPINFO_MC_COLUMN_COUNTRY_CODE:
            if (tok[2] != '\0') {
                if (memcmp(MORE_CACHED_FLAG_BYTES, tok, MORE_CACHED_FLAG_LEN)
                        == 0) {
                    /* flag to indicate we need to move on to the next page */
                    state->more_cached_records = 1;
                    break;
                } else {
                    strncpy(state->record->country_code, "??", 2);
                }
            } else {
                strncpy(state->record->country_code, tok, 2);
            }
            break;
        case IPINFO_MC_COLUMN_CONTINENT_CODE:
            strncpy(state->record->continent_code, tok, 2);
            break;
        case IPINFO_MC_COLUMN_REGION:
            state->record->region = insert_name_into_set(tok,
                    &(state->regions), 0);
            break;
        case IPINFO_MC_COLUMN_CITY:
            state->record->city = insert_name_into_set(tok, &(state->cities),
                    0);
            break;
        case IPINFO_MC_COLUMN_POST_CODE:
            state->record->post_code = insert_name_into_set(tok,
                    &(state->postcodes), 0);
            break;
        case IPINFO_MC_COLUMN_LATITUDE:
            state->record->latitude = insert_ll_into_map(tok,
                    &(state->latlongs));
            break;
        case IPINFO_MC_COLUMN_LONGITUDE:
            state->record->longitude = insert_ll_into_map(tok,
                    &(state->latlongs));
            break;
        case IPINFO_MC_COLUMN_TIMEZONE:
            state->record->timezone = insert_name_into_set(tok,
                    &(state->timezones), 0);
            break;
        case IPINFO_MC_COLUMN_NUMIPS:
            state->lookup_ip_cnt = insert_number_into_set(tok,
                    &(state->numips));
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

    /* We've hit the "MORE..." flag, so ignore this (final) row */
    if (state->more_cached_records) {
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

static int parse_csv_cached_rows(ipmeta_provider_memcache_psql_state_t *state,
        char *value, size_t vallen) {

    char *nextline, *thisline;
    char *tok, *endtok;
    int i;

    thisline = strtok_r(value, "\n", &nextline);
    while (thisline) {
        i = 0;

        tok = thisline;
        endtok = strchr(tok, ',');

        while (endtok) {
            if (tok == endtok) {
                /* consecutive ,, i.e. no value */
                parse_memcached_cell(NULL, i, state);
            } else {
                *endtok = '\0';
                parse_memcached_cell(tok, i, state);
            }
            i++;
            tok = endtok + 1;
            endtok = strchr(tok, ',');
        }
        if (tok != NULL) {
            parse_memcached_cell(tok, i, state);
        }

        parse_memcached_row(i, state);
        thisline = strtok_r(NULL, "\n", &nextline);
    }

    return 0;
}

#if HAVE_LIBMEMCACHED
static int memcache_lookup(ipmeta_provider_memcache_psql_state_t *state,
        char *tofind, uint32_t page,
        ipmeta_record_set_t *records, int *rec_count) {

    char mc_key[1024];
    char *value;
    int pfx_cnt, i;
    memcached_return_t rc;
    size_t vallen;
    uint32_t flags;
    ipmeta_record_t *rec;
    struct csv_parser csvp;

    if (state->disable_memcache) {
        state->cache_misses ++;
        return 0;
    }

    state->more_cached_records = 0;
    snprintf(mc_key, 1024, "ipmeta_ipinfo_%s_page_%u", tofind, page);

    value = memcached_get(state->mc_hdl, mc_key, strlen(mc_key),
        &vallen, &flags, &rc);
    if (rc == MEMCACHED_NOTFOUND) {
        state->cache_misses ++;
        return 0;
    }
    if (rc != MEMCACHED_SUCCESS) {
        state->cache_misses ++;
        return -1;
    }

    state->cache_hits ++;

    //csv_init(&csvp, CSV_STRICT | CSV_REPALL_NL | CSV_STRICT_FINI |
    //        CSV_APPEND_NULL | CSV_EMPTY_IS_NULL);
    state->lookup_record_cnt = 0;
    state->lookup_ip_cnt = 0;
    state->lookup_results = records;
    state->column_num = 0;

    parse_csv_cached_rows(state, value, vallen);

/*
    if (csv_parse(&csvp, value, vallen, parse_memcached_cell,
                            parse_memcached_row, state) != (int) vallen) {
            ipmeta_log("memcache_psql", "CSV parsing error: %s",
                            csv_strerror(csv_error(&csvp)));
            state->lookup_results = NULL;
            free(value);
            csv_free(&csvp);
            return -1;
    }
*/
    free(value);
/*
    if (csv_fini(&csvp, parse_memcached_cell, parse_memcached_row, state) != 0) {
        ipmeta_log(__func__, "CSV parsing error: %s",
                csv_strerror(csv_error(&csvp)));
        state->lookup_results = NULL;
        csv_free(&csvp);
        return -1;
    }
*/
    *rec_count = state->lookup_record_cnt;
    state->lookup_results = NULL;
//    csv_free(&csvp);
    return *rec_count;
}
#endif

#define family_size(fam) \
    ((fam) == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))

static ipmeta_record_t *generate_unknown_record(
        ipmeta_provider_t *provider,
        ipmeta_provider_memcache_psql_state_t *state, ipvx_prefix_t *pfx,
        uint64_t *numips) {

    ipmeta_record_t *rec;

    if (state->freelist_head) {
        rec = state->freelist_head;
        state->freelist_head = rec->next;
        memset(rec, 0, sizeof(ipmeta_record_t));
    } else {
        rec = calloc(1, sizeof(ipmeta_record_t));
    }
    rec->id = 0;
    rec->source = ipmeta_get_provider_id(provider);
    strncpy(rec->country_code, "??", 2);
    strncpy(rec->continent_code, "??", 2);
    rec->latitude = -100;   // deliberately invalid
    rec->longitude = -200;  // deliberately invalid;

    if (pfx->family == AF_INET) {
        *numips = pow(2, (32 - pfx->masklen));
    } else if (pfx->family == AF_INET6) {
        *numips = pow(2, (128 - pfx->masklen));
    } else {
        *numips = 0;
    }
    return rec;
}

static int update_latest_pub(ipmeta_provider_memcache_psql_state_t *state) {

    struct timeval tv;
    PGresult *pg_res;
    const char *tsparams[GET_LATEST_TS_PARAM_COUNT];
    int rows, cols;
    char *ts_string;

    gettimeofday(&tv, NULL);
    if (tv.tv_sec - state->last_max_pub_check >= (12 * 60 * 60)) {
        /* grab the timestamp of the most recent completed DB update */
        tsparams[0] = state->provider;
        pg_res = PQexecPrepared(state->pgconn, "query_ts_stmt",
                GET_LATEST_TS_PARAM_COUNT, tsparams, NULL, NULL, 0);
        if (PQntuples(pg_res) < 0) {
            ipmeta_log(__func__,
                    "ERROR: querying postgresql for latest timestamp -- %s",
                    PQerrorMessage(state->pgconn));
            PQclear(pg_res);
            return IPMETA_ERR_INTERNAL;
        }
        cols = PQnfields(pg_res);
        rows = PQntuples(pg_res);
        if (rows <= 0 || cols <= 0) {
            ipmeta_log(__func__,
                    "WARNING: no results for latest timestamp query, DB lookups are going to fail");
            return 0;
        }
        ts_string = PQgetvalue(pg_res, 0, 0);
        if (ts_string != NULL) {
            if (state->max_published) {
                free(state->max_published);
            }
            state->max_published = strdup(ts_string);
        }
        state->last_max_pub_check = tv.tv_sec;
        PQclear(pg_res);
    }
    return 1;
}

static int lookup_prefix(ipmeta_provider_t *provider,
        ipmeta_provider_memcache_psql_state_t *state,
        ipvx_prefix_t *pfx, ipmeta_record_set_t *records) {

    int rec_count = 0;
    uint64_t numips = 0, maxnumips;
    ipmeta_record_t *rec;
#ifdef HAVE_LIBPQ
#ifdef HAVE_LIBMEMCACHED
    const char *params[QUERY_PFX_PARAM_COUNT];
    char firststr[128];
    char laststr[128];
    char tofind[INET6_ADDRSTRLEN + 4];
    ipvx_prefix_t bound, foundpfx;
    PGresult *pg_res;
    int rows = 0, r, cols, mc_res;
    char mc_key[1024];
    char cache_str[4096];
    int nocache = 0;
    memcached_return_t rc;

    uint32_t page = 1;
    int cache_used = 0;
    int expire_offset;

    if (ipvx_ntop_pfx(pfx, tofind) == NULL) {
        return IPMETA_ERR_INPUT;
    }

    ipmeta_record_set_require_free(records, rec_free, state);

    do {
        mc_res = memcache_lookup(state, tofind, page, records, &rec_count);
        if (mc_res < 0) {
            ipmeta_log(__func__,
                    "Error during memcached lookup for %s:%u, using DB instead",
                    tofind, page);
            state->disable_memcache = 1;
            break;
        }

        if (mc_res == 0) {
            break;
        }
        page ++;
    } while (state->more_cached_records);


    if (rec_count > 0) {
        return rec_count;
    }

    if (state->pgconn == NULL && connect_pgsql(state) == -1) {
        ipmeta_log(__func__,
                "failed to connect to postgresql database");
        return -1;
    }

    if ((r = update_latest_pub(state)) <= 0) {
        return r;
    }

    if (state->max_published == NULL) {
        return IPMETA_ERR_INPUT;
    }

    if (pfx->family == AF_INET) {
        ipvx_first_addr(pfx, &bound);
        snprintf(firststr, 128, "%u", ntohl(bound.addr.v4.s_addr));

        ipvx_last_addr(pfx, &bound);
        snprintf(laststr, 128, "%u", ntohl(bound.addr.v4.s_addr));
    } else {
        //ipmeta_log(__func__,
        //        "ERROR: IPv6 prefix queries are not supported yet!");
        return IPMETA_ERR_INPUT;
    }

    if (pfx->family == AF_INET && pfx->masklen < 32) {
        params[0] = firststr;
        params[1] = laststr;
        params[2] = state->max_published;

        pg_res = PQexecPrepared(state->pgconn, "query_pfx_stmt",
                QUERY_PFX_PARAM_COUNT, params, NULL, NULL, 0);
        if (PQntuples(pg_res) < 0) {
            ipmeta_log(__func__,
                    "ERROR: querying postgresql for v4 prefix %s -- %s",
                    tofind, PQerrorMessage(state->pgconn));
            PQclear(pg_res);
            return IPMETA_ERR_INTERNAL;
        }

        cols = PQnfields(pg_res);
        rows = PQntuples(pg_res);
        if (rows <= 0) {
            rows = 0;
            PQclear(pg_res);
        }
    } else {
        rows = 0;
    }

    if (rows == 0) {
        /* try looking for an encapsulating prefix instead */
        params[0] = firststr;
        params[1] = state->max_published;
        pg_res = PQexecPrepared(state->pgconn, "query_encap_stmt",
                QUERY_ENCAP_PFX_PARAM_COUNT, params, NULL, NULL, 0);
        if (PQntuples(pg_res) < 0) {
            ipmeta_log(__func__,
                    "ERROR: querying postgresql for encap v4 prefix %s -- %s",
                    tofind, PQerrorMessage(state->pgconn));
            PQclear(pg_res);
            return IPMETA_ERR_INTERNAL;
        }

        cols = PQnfields(pg_res);
        rows = PQntuples(pg_res);
    }

    if (rows <= 0) {
        return 0;
    }

    page = 1;
    if (state->accum_cache == NULL) {
        state->accum_cache = calloc(MAX_CACHE_SIZE, sizeof(char));
    }

    /* Set cache expiry time to a random 5 minute interval ranging between 22
     * and 26 hours, so our cache entries don't all expire at the same time
     */
    expire_offset = 5 * (rand() % 48);

    for (r = 0; r < rows; r++) {
        if (state->freelist_head) {
            rec = state->freelist_head;
            state->freelist_head = rec->next;
            memset(rec, 0, sizeof(ipmeta_record_t));
        } else {
            rec = calloc(1, sizeof(ipmeta_record_t));
        }

        /* TODO make this more generic, use function pointers from the
         * provider itself... */
        if (strcmp(state->provider, "ipinfo") == 0) {
            if (process_psql_row_ipinfo(state, pg_res, r, cols, rec,
                    &numips, &foundpfx) < 0) {
                ipmeta_free_record(rec);
                rec_count = -1;
                break;
            }
        }

        if (pfx->family == AF_INET) {
            maxnumips = pow(2, (32 - pfx->masklen));
        } else {
            maxnumips = pow(2, (128 - pfx->masklen));
        }
        if (numips > maxnumips) {
            /* query returned an encapsulating prefix */
            numips = maxnumips;
        }

        if (ipmeta_record_set_add_record(records, rec, numips) != 0) {
            ipmeta_free_record(rec);
            rec_count = -1;
            break;
        }

        if (state->disable_memcache == 0 && nocache == 0) {
            int add_len = 0;
            /* Add individual record to memcache */
            snprintf(cache_str, 4096, "%s,%s,%s,%s,%s,%.6f,%.6f,%s,%lu\n",
                    rec->country_code, rec->continent_code, rec->region,
                    rec->city, rec->post_code, rec->latitude, rec->longitude,
                    rec->timezone, numips);

            add_len = strlen(cache_str);
            /* +2 because we need a \n and a \0 after the more flag */
            if (MAX_CACHE_SIZE - cache_used < add_len +
                        MORE_CACHED_FLAG_LEN + 2) {
                memcpy(state->accum_cache + cache_used, MORE_CACHED_FLAG_BYTES,
                        MORE_CACHED_FLAG_LEN);
                cache_used += MORE_CACHED_FLAG_LEN;
                state->accum_cache[cache_used] = '\n';
                state->accum_cache[cache_used + 1] = '\0';
                cache_used ++;

                snprintf(mc_key, 1024, "ipmeta_ipinfo_%s_page_%u", tofind,
                        page);
                rc = memcached_set(state->mc_hdl, mc_key, strlen(mc_key),
                        state->accum_cache, cache_used,
                        22 * 60 * 60 + expire_offset, 0);
                if (rc != MEMCACHED_SUCCESS) {
                    ipmeta_log(__func__,
                            "Unable to cache SQL query result for %s:%u -- %s",
                            tofind, page,
                            memcached_last_error_message(state->mc_hdl));
                    nocache = 1;
                }
                page ++;
                cache_used = 0;
            }
            strncpy(state->accum_cache + cache_used, cache_str, add_len);
            cache_used += add_len;
        }

        rec_count += 1;
    }

    if (rec_count > 0 && cache_used > 0) {
        snprintf(mc_key, 1024, "ipmeta_ipinfo_%s_page_%u", tofind, page);
        rc = memcached_set(state->mc_hdl, mc_key, strlen(mc_key),
                        state->accum_cache, cache_used,
                        22 * 60 * 60 + expire_offset, 0);
        if (rc != MEMCACHED_SUCCESS) {
            ipmeta_log(__func__,
                    "Unable to cache SQL query result for %s:%u -- %s",
                    tofind, page,
                    memcached_last_error_message(state->mc_hdl));
            nocache = 1;
        }
    }

    PQclear(pg_res);

#endif /* HAVE_LIBMEMCACHED */
#endif /* HAVE_LIBPQ */

    if (rec_count == 0) {
        rec = generate_unknown_record(provider, state, pfx, &numips);
        if (ipmeta_record_set_add_record(records, rec, numips) != 0) {
            ipmeta_free_record(rec);
            return -1;
        }
        rec_count = 1;
    }

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

    return lookup_prefix(provider, state, &pfx, records);
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

    return lookup_prefix(provider, state, &pfx, found);
}

