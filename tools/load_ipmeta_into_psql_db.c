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
#include <postgresql/libpq-fe.h>

#include "wandio.h"

#include "khash.h"
#include "utils.h"
#include "libcsv/csv.h"
#include "ipvx_utils.h"

#include "libipmeta_int.h"
#include "ipmeta_provider.h"
#include "ipmeta_parsing_helpers.h"

#define BUFFER_LEN 1024

const char *INSERT_IPMETA_UPLOAD_SQL =
    "INSERT INTO ipmeta_uploads (datatimestamp, uploaded, source) VALUES "
    "($1, $2, $3)";

const char *INSERT_IPINFO_PREFIX_BOUNDS_SQL =
    "INSERT INTO ipmeta_prefix_bounds (record_id, prefix, firstaddr, lastaddr) "
    "VALUES ($1, $2, $3, $4) "
    "ON CONFLICT DO NOTHING";

const char *INSERT_IPMETA_LOCATION_SQL =
    "INSERT INTO ipmeta_locations (country_code, continent_code, "
    "region_code, city_code, timezone) VALUES ($1, $2, $3, $4, $5) "
    "RETURNING id";

const char *SELECT_IPMETA_LOCATION_SQL =
    "SELECT id FROM ipmeta_locations WHERE country_code = $1 AND "
    "continent_code = $2 AND region_code = $3 AND city_code = $4";

const char *INSERT_IPMETA_RECORD_SQL =
    "INSERT INTO ipmeta_records (source, published, "
    "location, post_code, latitude, longitude) "
    "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id";

const char *SELECT_UNKNOWN_REGIONS_META_SQL =
    "SELECT mddb_entity_attribute.value, mddb_entity.code, mddb_entity.name "
    "FROM mddb_entity JOIN mddb_entity_attribute ON "
    "mddb_entity.id = mddb_entity_attribute.metadata_id "
    "WHERE mddb_entity.name LIKE '%Unknown Region%' AND "
    "mddb_entity_attribute.key = 'country_code'";

const char *SELECT_CITY_NAME_SQL =
    "SELECT mddb_entity.id FROM mddb_entity JOIN mddb_entity_attribute ON "
    "mddb_entity.id = mddb_entity_attribute.metadata_id "
    "WHERE mddb_entity.type_id = 5 AND "
    "mddb_entity.name = $2 AND "
    "mddb_entity_attribute.key = 'region_code' AND "
    "mddb_entity_attribute.value = $1 ";

const char *INSERT_METADATA_CITY_SQL =
    "INSERT INTO mddb_entity (type_id, code, name) VALUES "
    "(5, $1, $2) RETURNING id";

const char *INSERT_METADATA_CITY_ATTR_SQL =
    "INSERT INTO mddb_entity_attribute (metadata_id, key, value) VALUES "
    "($1, $2, $3)";

const char *LOOKUP_MAX_CITY_CODE_SQL =
    "SELECT max(code::int) FROM mddb_entity WHERE type_id = 5";

#define INSERT_IPMETA_UPLOAD_PARAM_COUNT 3
#define INSERT_IPINFO_PREFIX_BOUNDS_PARAM_COUNT 4
#define INSERT_IPMETA_LOCATION_PARAM_COUNT 5
#define INSERT_IPMETA_RECORD_PARAM_COUNT 6
#define SELECT_IPMETA_LOCATION_PARAM_COUNT 4
#define SELECT_CITY_NAME_PARAM_COUNT 2
#define INSERT_METADATA_CITY_PARAM_COUNT 2
#define INSERT_METADATA_CITY_ATTR_PARAM_COUNT 3

// convert char[2] to uint16_t
#define c2_to_u16(c2) (((c2)[0] << 8) | (c2)[1])

typedef struct city_lookup {
    const char **region_codes;
    const char **city_codes;
    int used;
    int alloc;
} city_lookup_t;

typedef struct ll_region {
    const char *region_name;
    const char *region_code;
} ll_region_t;

KHASH_INIT(u16u16, uint16_t, uint16_t, 1, kh_int_hash_func, kh_int_hash_equal)

KHASH_SET_INIT_STR(str_set)
KHASH_MAP_INIT_STR(ll_region_map, ll_region_t)
KHASH_MAP_INIT_STR(city_map, city_lookup_t *)

// convert uint16_t to char[2]
#define u16_to_c2(u16, c2)                                                     \
  do {                                                                         \
    (c2)[0] = (((u16) >> 8) & 0xFF);                                           \
    (c2)[1] = ((u16) & 0xFF);                                                  \
  } while (0)

/** Holds the state for an instance of this provider */
typedef struct inserter_state {
    char *locations_file;
    char *psql_host;
    char *psql_port;
    char *psql_username;
    char *psql_password;
    char *psql_dbname;
    char *meta_psql_host;
    char *meta_psql_port;
    char *meta_psql_username;
    char *meta_psql_password;
    char *meta_psql_dbname;
    char *timestamp_str;
    char *regions_file;

    uint8_t skip_ipv6;

    PGconn *pgconn;
    PGresult *insert_upload_stmt;
    PGresult *insert_pfx_bounds_stmt;
    PGresult *insert_loc_stmt;
    PGresult *insert_rec_stmt;
    PGresult *select_loc_stmt;
    PGresult *select_city_stmt;
    PGresult *insert_city_stmt;
    PGresult *insert_city_attr_stmt;
    uint8_t psql_error;
    int trans_size;

    PGconn *meta_pgconn;
    PGresult *lookup_city_stmt;
    int next_city_id;

    struct csv_parser parser;
    int current_line;
    int current_column;
    int first_column;
    int next_record_id;
    void (*parse_row)(int, void *);
    ipmeta_record_t *record;
    char *rec_lat;
    char *rec_long;
    ipvx_prefix_t block_lower;
    ipvx_prefix_t block_upper;
    khiter_t reg_k;

    const char *current_filename;

    /** map from country to continent */
    khash_t(u16u16) *country_continent;
    khash_t(ll_region_map) *regions_map;
    khash_t(ll_region_map) *unknown_regions_map;
    khash_t(city_map) *city_codes_map;

} ipmeta_inserter_state_t;

/** The columns in a ipinfo locations CSV file */
typedef enum column_list {
    LOCATION_COL_STARTIP,       ///< Range Start IP
    LOCATION_COL_ENDIP,         ///< Range End IP
    LOCATION_COL_JOINKEY,       ///< Join key (ignored)
    LOCATION_COL_CITY,          ///< City String
    LOCATION_COL_REGION,        ///< Region String
    LOCATION_COL_COUNTRY,       ///< 2 Char Country Code
    LOCATION_COL_LAT,           ///< Latitude
    LOCATION_COL_LONG,          ///< Longitude
    LOCATION_COL_POSTCODE,      ///< Postal Code String
    LOCATION_COL_TZ,            ///< Time Zone
    LOCATION_COL_ENDCOL,        ///< 1 past the last column ID
} location_cols_t;

typedef enum region_col_list {
    REGION_MAP_LATITUDE,
    REGION_MAP_LONGITUDE,
    REGION_MAP_LATLONG_STR,
    REGION_MAP_REGION_ID,
    REGION_MAP_REGION_NAME,
    REGION_MAP_REGION_CODED
} region_map_cols_t;

/** Prints usage information to stderr */
static void usage(char *progname) {
    fprintf(stderr,
        "Usage: %s -l <ipinfo file> -r <region map file> \n"
        "    -l <file>  The file containing the location data\n"
        "    -r <file>  The file containing the lat-long to IODA region mappings\n\n"
        "    -H <host>  The IP or hostname of the PSQL server for the IPInfo database\n"
        "    -P <port>  The port number of the PSQL service for the IPInfo database (default: 5672)\n"
        "    -U <user>  The username to log in to the IPInfo database with (default: postgres)\n"
        "    -A <password> The password to log in to the IPInfo database with (default: no password) \n"
        "    -d <dbname>  The name of the IPInfo database (default: ipmeta)\n\n"
        "    -s <host>  The IP or hostname of the PSQL server for the IODA metadata database\n"
        "    -m <port>  The port number of the PSQL service for the IODA metadata database (default: 5672)\n"
        "    -R <user>  The username to log in to the IODA metadata database with (default: postgres)\n"
        "    -X <password> The password to log in to the IODA metadata database with (default: no password) \n"
        "    -M <dbname>  The name of the IODA metadata database (default: ioda_api_v2)\n",
        progname);
}

static int parse_args(ipmeta_inserter_state_t *state, int argc, char **argv) {
    int opt;
    char *ptr = NULL;

    /* no args */
    if (argc == 0) {
      usage(argv[0]);
      return -1;
    }

    optind = 1;
    while ((opt = getopt(argc, argv, "4l:H:r:P:d:U:A:s:m:R:X:M:?")) >= 0) {
        switch (opt) {
            case 'l':
                if (state->locations_file) {
                    fprintf(stderr,
                            "ERROR: only one location file is allowed\n");
                    return -1;
                }
                state->locations_file = strdup(optarg);
                break;
            case 'r':
                if (state->regions_file) {
                    fprintf(stderr,
                            "ERROR: only one region map file is allowed\n");
                    return -1;
                }
                state->regions_file = strdup(optarg);
                break;
            case '4':
                state->skip_ipv6 = 1;
                break;
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
                state->psql_username = strdup(optarg);
                break;
            case 'A':
                state->psql_password = strdup(optarg);
                break;
            case 's':
                state->meta_psql_host = strdup(optarg);
                break;
            case 'm':
                state->meta_psql_port = strdup(optarg);
                break;
            case 'M':
                state->meta_psql_dbname = strdup(optarg);
                break;
            case 'R':
                state->meta_psql_username = strdup(optarg);
                break;
            case 'X':
                state->meta_psql_password = strdup(optarg);
                break;
            case '?':
            case ':':
            default:
                usage(argv[0]);
                return -1;
        }
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
    if (state->psql_username == NULL) {
        state->psql_username = strdup("postgres");
    }

    if (state->meta_psql_host == NULL) {
        state->meta_psql_host = strdup("localhost");
    }
    if (state->meta_psql_port == NULL) {
        state->meta_psql_port = strdup("5672");
    }
    if (state->meta_psql_dbname == NULL) {
        state->meta_psql_dbname = strdup("ioda_api_v2");
    }
    if (state->meta_psql_username == NULL) {
        state->meta_psql_username = strdup("postgres");
    }

    if (optind != argc) {
        fprintf(stderr, "ERROR: extra arguments to %s\n", argv[0]);
        usage(argv[0]);
        return -1;
    }

    if (state->locations_file == NULL) {
        fprintf(stderr,
                "ERROR: locations file must be specified using -l!\n");
        usage(argv[0]);
        return -1;
    }
    if (state->regions_file == NULL) {
        state->regions_file = strdup("/data/ipinfo-region-map.csv");
    }
    return 0;
}

/* If the file naming scheme changes, then this is going to fall over
 * very badly....
 */
static char *derive_timestamp_from_filename(const char *filename) {
    char founddate[32];
    char tstr[64];

    char *last_slash = strrchr(filename, '/');
    if (last_slash == NULL) {
        last_slash = (char *)filename;
    } else {
        last_slash ++;
    }
    if (strlen(last_slash) < 10) {
        fprintf(stderr, "filename format should be YYYY-MM-DD.standard_location.csv.gz\n");
        return NULL;
    }
    if (last_slash[0] < '0' || last_slash[0] > '9' ||
            last_slash[1] < '0' || last_slash[1] > '9' ||
            last_slash[2] < '0' || last_slash[2] > '9' ||
            last_slash[3] < '0' || last_slash[3] > '9' ||
            last_slash[5] < '0' || last_slash[5] > '9' ||
            last_slash[6] < '0' || last_slash[6] > '9' ||
            last_slash[8] < '0' || last_slash[8] > '9' ||
            last_slash[9] < '0' || last_slash[9] > '9' ||
            last_slash[4] != '-' || last_slash[7] != '-'
            ) {
        fprintf(stderr, "filename format should be YYYY-MM-DD.standard_location.csv.gz\n");
        return NULL;
    }
    strncpy(founddate, last_slash, 10);
    founddate[10] = '\0';

    snprintf(tstr, 64, "%s 00:00:00", founddate);
    return strdup(tstr);
}

static void insert_upload_time_row(ipmeta_inserter_state_t *state) {

    const char *params[INSERT_IPMETA_UPLOAD_PARAM_COUNT];
    time_t t = time(NULL);
    struct tm tm;
    char timestr[1024];
    PGresult *pg_res;

    gmtime_r(&t, &tm);
    strftime(timestr, 1000, "%F %T", &tm);

    params[0] = state->timestamp_str;
    params[1] = timestr;
    params[2] = "ipinfo";

    pg_res = PQexecPrepared(state->pgconn, "insert_upload",
            INSERT_IPMETA_UPLOAD_PARAM_COUNT, params, NULL, NULL, 0);

    if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error while inserting new ipmeta upload entry: %s\n",
                        PQerrorMessage(state->pgconn));
    }
    PQclear(pg_res);
}

static void parse_ll_region_cell(void *s, size_t i, void *data) {
    ipmeta_inserter_state_t *state = (ipmeta_inserter_state_t *)(data);
    char *tok = (char *)s;
    int ret;
    khiter_t k;
    ll_region_t reg;

    switch(state->current_column) {
        case REGION_MAP_LATITUDE:
            state->reg_k = -1;
            break;
        case REGION_MAP_LONGITUDE:
        case REGION_MAP_REGION_CODED:
            break;
        case REGION_MAP_LATLONG_STR:
            if (tok != NULL) {
                k = kh_get(ll_region_map, state->regions_map, tok);
                if (k != kh_end(state->regions_map)) {
                    fprintf(stderr, "WARNING: %s appears multiple times in region mapping file?\n", tok);
                    state->reg_k = k;
                    break;
                }
                k = kh_put(ll_region_map, state->regions_map, tok, &ret);
                if (ret >= 0) {
                    kh_key(state->regions_map, k) = strdup(tok);
                    reg.region_code = NULL;
                    reg.region_name = NULL;
                    kh_value(state->regions_map, k) = reg;
                    state->reg_k = k;
                } else {
                    fprintf(stderr, "ERROR: while inserting region map entry for %s\n", tok);
                    state->reg_k = -1;
                }
            }
            break;
        case REGION_MAP_REGION_ID:
            if (tok == NULL) {
                fprintf(stderr, "WARNING: no region ID on line %u\n",
                        state->current_line);
                break;
            }
            if (state->reg_k == -1) {
                fprintf(stderr, "WARNING: no saved latlong key for line %u\n",
                        state->current_line);
                break;
            }
            reg = kh_value(state->regions_map, state->reg_k);
            reg.region_code = strdup(tok);
            kh_value(state->regions_map, state->reg_k) = reg;
            break;
        case REGION_MAP_REGION_NAME:
            if (tok == NULL) {
                fprintf(stderr, "WARNING: no region name on line %u\n",
                        state->current_line);
                break;
            }
            if (state->reg_k == -1) {
                fprintf(stderr, "WARNING: no saved latlong key for line %u\n",
                        state->current_line);
                break;
            }
            reg = kh_value(state->regions_map, state->reg_k);
            reg.region_name = strdup(tok);
            kh_value(state->regions_map, state->reg_k) = reg;
            break;
    }
    state->current_column ++;
}

static void parse_ipinfo_cell(void *s, size_t i, void *data) {
    ipmeta_inserter_state_t *state = (ipmeta_inserter_state_t *)(data);
    char *tok = (char *)s;
    char *end;
    unsigned char buf[sizeof(struct in6_addr)];
    int ret;

#define rec (state->record)  /* convenient code abbreviation */

    switch(state->current_column) {
        case LOCATION_COL_STARTIP:
            if (strchr(tok, ':')) {
                /* ipv6 */
                if (state->skip_ipv6) {
                    rec->id = 0;
                    break;
                }
                state->block_lower.family = AF_INET6;
                state->block_lower.masklen = 128;
                ret = inet_pton(AF_INET6, tok, &(state->block_lower.addr.v6));
            } else {
                state->block_lower.family = AF_INET;
                state->block_lower.masklen = 32;
                ret = inet_pton(AF_INET, tok, &(state->block_lower.addr.v4));
            }
            if (ret <= 0) {
                col_invalid(state, "Invalid start IP", tok);
            }
            rec->id = state->next_record_id;
            state->next_record_id ++;
            break;
        case LOCATION_COL_ENDIP:
            if (strchr(tok, ':')) {
                /* ipv6 */
                if (state->skip_ipv6) {
                    rec->id = 0;
                    break;
                }
                state->block_upper.family = AF_INET6;
                state->block_upper.masklen = 128;
                ret = inet_pton(AF_INET6, tok, &(state->block_upper.addr.v6));
            } else {
                state->block_upper.family = AF_INET;
                state->block_upper.masklen = 32;
                ret = inet_pton(AF_INET, tok, &(state->block_upper.addr.v4));
            }
            if (ret <= 0) {
                col_invalid(state, "Invalid end IP", tok);
            }
            break;
        case LOCATION_COL_COUNTRY:
            // country code
            if (!tok || !*tok || (tok[0] == '-' && tok[1] == '-')) {
                rec->country_code[0] = '?';
                rec->country_code[1] = '?';
            } else if (strlen(tok) != 2) {
                col_invalid(state, "Invalid country code", tok);
            } else {
                memcpy(rec->country_code, tok, 2);
            }
            break;
        case LOCATION_COL_CITY:
            if (tok) {
                rec->city = strdup(tok);
            }
            break;
        case LOCATION_COL_REGION:
            if (tok) {
                rec->region = strdup(tok);
            }
            break;
        case LOCATION_COL_POSTCODE:
            if (tok) {
                rec->post_code = strdup(tok);
            }
            break;
        case LOCATION_COL_TZ:
            if (tok) {
                rec->timezone = strdup(tok);
            }
            break;
        case LOCATION_COL_LAT:
            if (tok) {
                state->rec_lat = strdup(tok);
            }
            break;
        case LOCATION_COL_LONG:
            if (tok) {
                state->rec_long = strdup(tok);
            }
            break;
        case LOCATION_COL_JOINKEY:
            break; // unused
        default:
            col_invalid(state, "Unexpected trailing column", tok);
    }
#undef rec
    state->current_column++;
}

static int64_t insert_record_into_psql(ipmeta_inserter_state_t *state,
        int64_t loc_id) {
    PGresult *pg_res;
    const char *values[INSERT_IPMETA_RECORD_PARAM_COUNT];
    int64_t retid = -1;

    char loc_id_str[32];

    snprintf(loc_id_str, 32, "%ld", loc_id);

    values[0] = "ipinfo";
    values[1] = state->timestamp_str;
    values[2] = loc_id_str;
    values[3] = state->record->post_code;
    values[4] = state->rec_lat;
    values[5] = state->rec_long;

    pg_res = PQexecPrepared(state->pgconn, "insert_record",
            INSERT_IPMETA_RECORD_PARAM_COUNT, values, NULL, NULL, 0);

    if (PQresultStatus(pg_res) == PGRES_TUPLES_OK) {
        retid = strtoll(PQgetvalue(pg_res, 0, 0), NULL, 10);
    } else {
        fprintf(stderr, "Error while inserting new ipmeta record entry: %s\n",
                        PQerrorMessage(state->pgconn));
    }
    PQclear(pg_res);
    return retid;
}

static const char *insert_new_city(ipmeta_inserter_state_t *state,
        ll_region_t *reg, char *space) {

    PGresult *ins_res;
    const char *city_params[INSERT_METADATA_CITY_PARAM_COUNT];
    const char *attr_params[INSERT_METADATA_CITY_ATTR_PARAM_COUNT];
    char *cityid = NULL;

    char codestring[32];
    char fqidstr[256];

    /* city was not in the metadata db, so we should try to add it */
    assert(state->next_city_id >= 0);
    snprintf(codestring, 32, "%d", state->next_city_id);
    city_params[0] = codestring;
    city_params[1] = state->record->city;
    state->next_city_id ++;

    ins_res = PQexecPrepared(state->meta_pgconn, "insert_city",
            INSERT_METADATA_CITY_PARAM_COUNT, city_params, NULL, NULL, 0);
    if (PQresultStatus(ins_res) == PGRES_TUPLES_OK) {
        cityid = PQgetvalue(ins_res, 0, 0);
    } else {
        fprintf(stderr, "Error while inserting new metadata city: %s\n",
                PQerrorMessage(state->meta_pgconn));
    }
    if (cityid == NULL) {
        PQclear(ins_res);
        return NULL;
    }

    strncpy(space, cityid, 32);
    PQclear(ins_res);
    /* insert attributes */

    /* insert fqid */
    snprintf(fqidstr, 256, "geo.ipinfo.%s.%s.%s.%s",
            state->record->continent_code, state->record->country_code,
            reg->region_code, space);

    attr_params[0] = space;
    attr_params[1] = "fqid";
    attr_params[2] = fqidstr;
    ins_res = PQexecPrepared(state->meta_pgconn, "insert_city_attr",
            INSERT_METADATA_CITY_ATTR_PARAM_COUNT, attr_params, NULL, NULL, 0);
    if (PQresultStatus(ins_res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Error while inserting metadata attribute for new city: %s\n",
                PQerrorMessage(state->meta_pgconn));
    }
    PQclear(ins_res);

    /* insert region code and region name */
    attr_params[1] = "region_code";
    attr_params[2] = reg->region_code;

    ins_res = PQexecPrepared(state->meta_pgconn, "insert_city_attr",
            INSERT_METADATA_CITY_ATTR_PARAM_COUNT, attr_params, NULL, NULL, 0);
    if (PQresultStatus(ins_res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Error while inserting metadata attribute for new city: %s\n",
                PQerrorMessage(state->meta_pgconn));
    }

    PQclear(ins_res);

    attr_params[1] = "region_name";
    attr_params[2] = reg->region_name;

    ins_res = PQexecPrepared(state->meta_pgconn, "insert_city_attr",
            INSERT_METADATA_CITY_ATTR_PARAM_COUNT, attr_params, NULL, NULL, 0);
    if (PQresultStatus(ins_res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Error while inserting metadata attribute for new city: %s\n",
                PQerrorMessage(state->meta_pgconn));
    }

    PQclear(ins_res);

    /* insert country code */

    attr_params[1] = "country_code";
    attr_params[2] = state->record->country_code;

    ins_res = PQexecPrepared(state->meta_pgconn, "insert_city_attr",
            INSERT_METADATA_CITY_ATTR_PARAM_COUNT, attr_params, NULL, NULL, 0);
    if (PQresultStatus(ins_res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Error while inserting metadata attribute for new city: %s\n",
                PQerrorMessage(state->meta_pgconn));
    }

    PQclear(ins_res);

    /* XXX check if we need country name as well */

    return space;
}

static const char *lookup_city_code(ipmeta_inserter_state_t *state,
        ll_region_t *reg) {

    PGresult *pg_res;
    const char *select_params[SELECT_CITY_NAME_PARAM_COUNT];
    const char *city_code = NULL;
    char city_code_space[32];
    khiter_t k;
    city_lookup_t *cmap = NULL;
    int i, khret;

    assert(state->record->city != NULL);
    assert(reg->region_code != NULL);
    assert(reg->region_name != NULL);

    /* first try and find in local cache */
    k = kh_get(city_map, state->city_codes_map, state->record->city);
    if (k != kh_end(state->city_codes_map)) {
        cmap = kh_value(state->city_codes_map, k);

        // kh_value(state->city_codes_map, k) is a struct storing an
        // an array of region codes and an array of corresponding city codes
        // because a city name is not unique to just one region (e.g.
        // London, UK vs London, Ontario). Also Singapore is a city that
        // spans multiple regions.
        //
        // if we don't find our region code in the array, then we'll
        // need to find the city code in the DB and add it to the
        // array -- so keep the kh_value for this city name because we
        // can use it later without having to do the lookup again.

        for (i = 0; i < cmap->used; i++) {
            if (cmap->region_codes[i] == NULL) {
                break;
            }
            if (strcmp(cmap->region_codes[i], reg->region_code) == 0) {
                city_code = cmap->city_codes[i];
                break;
            }
        }
    }

    if (city_code != NULL) {
        return city_code;
    }

    /* otherwise, try and look up the city name in the metadata database */
    select_params[0] = reg->region_code;
    select_params[1] = state->record->city;

    pg_res = PQexecPrepared(state->meta_pgconn, "select_city",
            SELECT_CITY_NAME_PARAM_COUNT, select_params, NULL, NULL, 0);
    if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Error while attempting to find city '%s,%s' in the metadata DB\n", state->record->city, reg->region_code);
        PQclear(pg_res);
        return NULL;
    }
    if (PQntuples(pg_res) != 0) {
        if (PQntuples(pg_res) > 1) {
            fprintf(stderr, "WARNING: multiple city entries for %s,%s in metadata DB (using first one... )\n", state->record->city, reg->region_code);
        }

        city_code = (const char *)PQgetvalue(pg_res, 0, 0);
    }

    if (city_code == NULL) {
        memset(city_code_space, 0, 32);
        city_code = insert_new_city(state, reg, city_code_space);
        if (city_code == NULL) {
            return NULL;
        }
    }

    /* add to the local city map */
    if (k == kh_end(state->city_codes_map)) {
        city_lookup_t *newcity;

        newcity = calloc(1, sizeof(city_lookup_t));
        k = kh_put(city_map, state->city_codes_map, state->record->city,
                &khret);
        kh_key(state->city_codes_map, k) = strdup(state->record->city);
        kh_value(state->city_codes_map, k) = newcity;

        newcity->region_codes = calloc(16, sizeof(char *));
        newcity->city_codes = calloc(16, sizeof(char *));
        newcity->alloc = 16;
        cmap = newcity;
    }

    while (cmap->used >= cmap->alloc) {
        fprintf(stderr, "%s\n", state->record->city);
        cmap->region_codes = realloc(cmap->region_codes,
                (cmap->used + 16) * sizeof(char *));
        cmap->city_codes = realloc(cmap->city_codes,
                (cmap->used + 16) * sizeof(char *));
        cmap->alloc += 16;
    }
    assert(cmap->used < cmap->alloc);
    cmap->region_codes[cmap->used] = strdup(reg->region_code);
    cmap->city_codes[cmap->used] = strdup(city_code);
    cmap->used ++;
    return city_code;
}

static ll_region_t lookup_region_code(ipmeta_inserter_state_t *state) {

    char latlong[1024];
    khiter_t k;
    ll_region_t reg;

    if (state->rec_lat != NULL && state->rec_long != NULL) {
        snprintf(latlong, 1024, "%s,%s", state->rec_lat, state->rec_long);

        k = kh_get(ll_region_map, state->regions_map, latlong);
        if (k != kh_end(state->regions_map)) {
            reg = kh_value(state->regions_map, k);
            return reg;
        }
    }

    k = kh_get(ll_region_map, state->unknown_regions_map,
            state->record->country_code);
    if (k == kh_end(state->unknown_regions_map)) {
        reg.region_name = NULL;
        reg.region_code = NULL;
    } else {
        reg = kh_value(state->unknown_regions_map, k);
    }
    return reg;
}

static int64_t insert_location_into_psql(ipmeta_inserter_state_t *state) {

    PGresult *pg_res, *ins_res;
    const char *values[INSERT_IPMETA_LOCATION_PARAM_COUNT];
    int64_t retid = -1;
    char def_region_label[1024];
    char def_city_label[1024];
    ll_region_t cached_region;

    assert(INSERT_IPMETA_LOCATION_PARAM_COUNT >=
            SELECT_IPMETA_LOCATION_PARAM_COUNT);

    values[0] = state->record->country_code;
    values[1] = state->record->continent_code;

    cached_region = lookup_region_code(state);
    if (cached_region.region_code == NULL) {
        cached_region.region_code = "0";
        cached_region.region_name = "Unknown Region in Unknown Country";
    }

    values[2] = cached_region.region_code;
    if (state->record->city == NULL) {
        values[3] = NULL;
    } else {
        values[3] = lookup_city_code(state, &cached_region);
        if (values[3] == NULL) {
            return -1;
        }
    }
    values[4] = state->record->timezone;

    pg_res = PQexecPrepared(state->pgconn, "select_location",
            SELECT_IPMETA_LOCATION_PARAM_COUNT, values, NULL, NULL, 0);
    if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
        printf("%s\n", values[3]);
        fprintf(stderr, "Error while checking if location exists: %s\n",
                PQerrorMessage(state->pgconn));
    }

    if (PQntuples(pg_res) > 0) {
        retid = strtoll(PQgetvalue(pg_res, 0, 0), NULL, 10);
    } else {
        ins_res = PQexecPrepared(state->pgconn, "insert_location",
                INSERT_IPMETA_LOCATION_PARAM_COUNT, values, NULL, NULL, 0);
        if (PQresultStatus(ins_res) == PGRES_TUPLES_OK) {
            retid = strtoll(PQgetvalue(ins_res, 0, 0), NULL, 10);
        } else {
            fprintf(stderr, "Error while inserting new location entry: %s\n",
                    PQerrorMessage(state->pgconn));
            assert(0);
        }
        PQclear(ins_res);
    }
    PQclear(pg_res);
    return retid;
}

static int insert_pfx_into_psql(ipmeta_inserter_state_t *state,
        ipvx_prefix_list_t *pfx_node, int64_t rec_id) {

    PGresult *pg_res;
    const char *bounds_values[INSERT_IPINFO_PREFIX_BOUNDS_PARAM_COUNT];
    ipvx_prefix_t res;
    char pfxstr[INET_ADDRSTRLEN + 4];
    char firststr[INET_ADDRSTRLEN + 4];
    char laststr[INET_ADDRSTRLEN + 4];

    char firstnum[128];
    char lastnum[128];

    char rec_id_str[32];
    int ret = 0;

    if (ipvx_ntop_pfx(&(pfx_node->prefix), pfxstr) == NULL) {
        fprintf(stderr, "Unable to convert ipvx prefix to string\n");
        return -1;
    }

    ipvx_first_addr(&(pfx_node->prefix), &res);
    snprintf(firstnum, 128, "%u", ntohl(res.addr.v4.s_addr));
    ipvx_last_addr(&(pfx_node->prefix), &res);
    snprintf(lastnum, 128, "%u", ntohl(res.addr.v4.s_addr));
    if (ipvx_ntop_pfx(&res, laststr) == NULL) {
        fprintf(stderr, "Unable to convert ipvx last addr to string\n");
        return -1;
    }

    snprintf(rec_id_str, 32, "%ld", rec_id);

    bounds_values[0] = rec_id_str;
    bounds_values[1] = pfxstr;
    bounds_values[2] = firstnum;
    bounds_values[3] = lastnum;

    pg_res = PQexecPrepared(state->pgconn, "insert_pfx_bounds",
            INSERT_IPINFO_PREFIX_BOUNDS_PARAM_COUNT, bounds_values,
            NULL, NULL, 0);
    if (PQresultStatus(pg_res) == PGRES_FATAL_ERROR) {
        fprintf(stderr, "Execution of prepared statement failed: %s\n",
                PQresultErrorMessage(pg_res));
        ret = -1;
    } else if (PQresultStatus(pg_res) == PGRES_COMMAND_OK) {
        ret = 1;
    } else {
        fprintf(stderr,
                "Non fatal error when executing prepared statement: %s\n",
                PQresultErrorMessage(pg_res));
        ret = -1;
    }

    PQclear(pg_res);
    return ret;
}

static void parse_ll_region_row(int c, void *data) {
    ipmeta_inserter_state_t *state = (ipmeta_inserter_state_t *)(data);

    state->current_line ++;
    state->current_column = 0;
}

static void parse_ipinfo_row(int c, void *data) {
    ipmeta_inserter_state_t *state = (ipmeta_inserter_state_t *)(data);
    ipvx_prefix_list_t *pfx_list=NULL, *pfx_node;
    PGresult *pg_res;
    int64_t loc_id, rec_id;

    khiter_t khiter;

    if (state->psql_error) {
        goto rowdone;
    }

    if (state->current_column != LOCATION_COL_ENDCOL) {
        fprintf(stderr, "Row contains an unexpected number of columns?\n");
        goto rowdone;
    }

    if (state->record == NULL || state->record->id == 0) {
        //row_error(state, "%s", "Row did not produce a valid record");
        goto rowdone;
    }

    char *cc = state->record->country_code;
    if ((khiter = kh_get(u16u16, state->country_continent, c2_to_u16(cc))) ==
            kh_end(state->country_continent)) {
        fprintf(stderr, "Unknown country code (%s)\n", cc);
        goto rowdone;
    }

    uint16_t cont = kh_value(state->country_continent, khiter);
    u16_to_c2(cont, state->record->continent_code);

    if (ipvx_range_to_prefix(&state->block_lower, &state->block_upper,
            &pfx_list) != 0) {
        fprintf(stderr, "Could not convert IP range to prefixes\n");
        goto rowdone;
    }
    if (pfx_list == NULL) {
        goto rowdone;
    }

    if (state->trans_size >= 10000000) {
        pg_res = PQexec(state->pgconn, "COMMIT");
        if (PQresultStatus(pg_res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Failed to commit transaction: %s\n",
                    PQerrorMessage(state->pgconn));
            state->psql_error = 1;
            PQclear(pg_res);
            goto rowdone;
        }
        PQclear(pg_res);
        state->trans_size = 0;
    }

    if (state->trans_size == 0) {
        pg_res = PQexec(state->pgconn, "BEGIN");
        if (PQresultStatus(pg_res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Failed to begin transaction: %s\n",
                    PQerrorMessage(state->pgconn));
            state->psql_error = 1;
            PQclear(pg_res);
            goto rowdone;
        }
        PQclear(pg_res);
        state->trans_size = 1;
    }

    loc_id = insert_location_into_psql(state);
    if (loc_id <= 0) {
        state->psql_error = 1;
        goto rowdone;
    }

    rec_id = insert_record_into_psql(state, loc_id);
    if (rec_id <= 0) {
        state->psql_error = 1;
        goto rowdone;
    }

    for (pfx_node = pfx_list; pfx_node != NULL; pfx_node = pfx_node->next) {
        if (pfx_node->prefix.family != AF_INET) {
            continue;
        }
        // do insertion here
        if (insert_pfx_into_psql(state, pfx_node, rec_id) < 0) {
            state->psql_error = 1;
            goto rowdone;
        }
        state->trans_size ++;
    }

rowdone:
    if (pfx_list) {
        ipvx_prefix_list_free(pfx_list);
    }

    state->current_line ++;
    state->current_column = 0;
    ipmeta_clean_record(state->record);
    if (state->rec_lat) {
        free(state->rec_lat);
    }
    if (state->rec_long) {
        free(state->rec_long);
    }

    return;
}

static void load_country_continent_map(ipmeta_inserter_state_t *state) {
    // populate the country2continent hash
    int country_cnt;
    const char **countries;
    const char **continents;
    state->country_continent = kh_init(u16u16);
    /* Note we actually call the maxmind version of the function here,
     * as it does the same thing as what we would do ourselves. There
     * is no reason for us to duplicate that, so let's just reuse the
     * existing methods.
     */
    country_cnt = ipmeta_provider_maxmind_get_iso2_list(&countries);
    ipmeta_provider_maxmind_get_country_continent_list(&continents);
    for (int i = 0; i < country_cnt; i++) {
        // create a mapping for this country
        int khret;
        khiter_t k = kh_put(u16u16, state->country_continent,
                            c2_to_u16(countries[i]), &khret);
        kh_value(state->country_continent, k) = c2_to_u16(continents[i]);
    }
}

static int lookup_unknown_regions(ipmeta_inserter_state_t *state) {

    PGresult *pg_res = NULL;
    int r, i, ret;
    khiter_t k;
    char *value;
    ll_region_t reg;

    pg_res = PQexec(state->meta_pgconn, SELECT_UNKNOWN_REGIONS_META_SQL);
    if (PQresultStatus(pg_res) == PGRES_FATAL_ERROR) {
        fprintf(stderr, "Execution of unknown region lookup failed: %s\n",
                PQresultErrorMessage(pg_res));
        goto lookup_fail;
    } else if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
        fprintf(stderr,
                "Non fatal error when executing unknown region lookup: %d %s\n",
                PQresultStatus(pg_res), PQresultErrorMessage(pg_res));
        goto lookup_fail;
    }

    state->unknown_regions_map = kh_init(ll_region_map);
    for (r = 0; r < PQntuples(pg_res); r++) {
        k = -1;
        for (i = 0; i < 3; i++) {
            value = PQgetvalue(pg_res, r, i);
            if (i == 0) {
                /* country code */
                if (value && value[0] == '?') {
                    break;
                } else {
                    k = kh_get(ll_region_map, state->unknown_regions_map,
                            value);
                    if (k != kh_end(state->unknown_regions_map)) {
                        /* shouldn't happen, but whatever... */

                    } else {
                        k = kh_put(ll_region_map,
                                state->unknown_regions_map, value, &ret);
                        if (ret < 0) {
                            goto lookup_fail;
                        }
                        kh_key(state->unknown_regions_map, k) =
                                strdup(value);
                        reg.region_code = NULL;
                        reg.region_name = NULL;
                    }
                }
            } else if (i == 1) {
                if (k == -1) {
                    break;
                }
                reg.region_code = strdup(value);
            } else if (i == 2) {
                if (k == -1) {
                    break;
                }
                reg.region_name = strdup(value);
            }
        }
        if (k != -1) {
            kh_value(state->unknown_regions_map, k) = reg;
        }
    }

    PQclear(pg_res);

    pg_res = PQexec(state->meta_pgconn, LOOKUP_MAX_CITY_CODE_SQL);
    if (PQresultStatus(pg_res) == PGRES_FATAL_ERROR) {
        fprintf(stderr, "Execution of max city code lookup failed: %s\n",
                PQresultErrorMessage(pg_res));
        goto lookup_fail;
    } else if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
        fprintf(stderr,
                "Non fatal error when executing max city code lookup: %d %s\n",
                PQresultStatus(pg_res), PQresultErrorMessage(pg_res));
        goto lookup_fail;
    }

    if (PQntuples(pg_res) <= 0) {
        state->next_city_id = 0;
    } else {
        value = PQgetvalue(pg_res, 0, 0);
        if (value == NULL || strlen(value) == 0) {
            state->next_city_id = 0;
        } else {
            state->next_city_id = strtoul(value, NULL, 10) + 1;
        }
    }
    PQclear(pg_res);

    return 0;

lookup_fail:
    PQclear(pg_res);
    return -1;
}

static int load_region_latlongs(ipmeta_inserter_state_t *state,
        const char *filename) {
    io_t *file = NULL;
    char buffer[BUFFER_LEN];
    int read;
    int rc = -1;

    /* connect to metadata db */
    state->meta_pgconn = PQsetdbLogin(state->meta_psql_host,
            state->meta_psql_port,
            NULL, NULL, state->meta_psql_dbname, state->meta_psql_username,
            state->meta_psql_password);
    if (PQstatus(state->meta_pgconn) == CONNECTION_BAD) {
        fprintf(stderr, "failed to connect to IODA metadata database: %s\n",
                PQerrorMessage(state->meta_pgconn));
        goto end;
    }

    if (lookup_unknown_regions(state) < 0) {
        fprintf(stderr, "failed to fetch unknown region IDs from IODA metadata database\n");
        goto end;
    }

    state->regions_map = kh_init(ll_region_map);
    state->city_codes_map = kh_init(city_map);

    if ((file = wandio_create(filename)) == NULL) {
        fprintf(stderr, "failed to open file '%s'\n", filename);
        goto end;
    }
    state->first_column = -1;
    state->current_line = 0;
    state->parse_row = NULL;

    while (state->first_column < 0) {
        read = wandio_fgets(file, &buffer, BUFFER_LEN, 0);
        if (read < 0) {
            fprintf(stderr, "error reading file: %s\n", filename);
            goto end;
        }
        if (read == 0) {
            fprintf(stderr, "Empty file: %s\n", filename);
            goto end;
        }
        if (startswith(buffer, "latitude,")) {
            state->current_column = state->first_column = 0;
            state->parse_row = parse_ll_region_row;
        } else {
            fprintf(stderr, "%s is not a valid region mapping file\n",
                    filename);
            goto end;
        }
    }

    csv_init(&(state->parser), CSV_STRICT | CSV_REPALL_NL | CSV_STRICT_FINI |
            CSV_APPEND_NULL | CSV_EMPTY_IS_NULL);
    while ((read = wandio_read(file, &buffer, BUFFER_LEN)) > 0) {
        if (csv_parse(&(state->parser), buffer, read, parse_ll_region_cell,
                state->parse_row, state) != read) {
            fprintf(stderr, "Error parsing region mapping file\n");
            fprintf(stderr, "CSV Error: %s\n",
                 csv_strerror(csv_error(&(state->parser))));
            goto end;
        }
    }
    if (read < 0) {
        fprintf(stderr, "Error reading file %s\n", filename);
        goto end;
    }

    if (csv_fini(&(state->parser), parse_ll_region_cell, state->parse_row,
            state) != 0) {
        fprintf(stderr, "Error parsing region mapping file\n");
        fprintf(stderr, "CSV Error: %s\n",
                csv_strerror(csv_error(&(state->parser))));
        goto end;
    }
    rc = 0;

end:
    csv_free(&(state->parser));
    wandio_destroy(file);
    return rc;
}

static int read_ipinfo_file(ipmeta_inserter_state_t *state,
        const char *filename) {
    io_t *file = NULL;
    char buffer[BUFFER_LEN];
    int read;
    int rc = -1;

    /* connect to db */
    state->pgconn = PQsetdbLogin(state->psql_host, state->psql_port,
            NULL, NULL, state->psql_dbname, state->psql_username,
            state->psql_password);
    if (PQstatus(state->pgconn) == CONNECTION_BAD) {
        fprintf(stderr, "failed to connect to PSQL database: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    state->select_city_stmt = PQprepare(state->meta_pgconn, "select_city",
            SELECT_CITY_NAME_SQL, SELECT_CITY_NAME_PARAM_COUNT, NULL);
    if (PQresultStatus(state->select_city_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of lookup city statement failed: %s\n",
                PQerrorMessage(state->meta_pgconn));
        goto end;
    }

    state->insert_city_stmt = PQprepare(state->meta_pgconn, "insert_city",
            INSERT_METADATA_CITY_SQL, INSERT_METADATA_CITY_PARAM_COUNT, NULL);
    if (PQresultStatus(state->insert_city_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of insert city statement failed: %s\n",
                PQerrorMessage(state->meta_pgconn));
        goto end;
    }

    state->insert_city_attr_stmt = PQprepare(state->meta_pgconn,
            "insert_city_attr", INSERT_METADATA_CITY_ATTR_SQL,
            INSERT_METADATA_CITY_ATTR_PARAM_COUNT, NULL);
    if (PQresultStatus(state->insert_city_attr_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Preparation of insert city attr statement failed: %s\n",
                PQerrorMessage(state->meta_pgconn));
        goto end;
    }

    state->insert_upload_stmt = PQprepare(state->pgconn, "insert_upload",
            INSERT_IPMETA_UPLOAD_SQL, INSERT_IPMETA_UPLOAD_PARAM_COUNT,
            NULL);
    if (PQresultStatus(state->insert_upload_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of insert upload statement failed: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    state->insert_pfx_bounds_stmt = PQprepare(state->pgconn,
            "insert_pfx_bounds",
            INSERT_IPINFO_PREFIX_BOUNDS_SQL,
            INSERT_IPINFO_PREFIX_BOUNDS_PARAM_COUNT, NULL);
    if (PQresultStatus(state->insert_pfx_bounds_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "Preparation of insert prefix bounds statement failed: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    state->insert_loc_stmt = PQprepare(state->pgconn, "insert_location",
            INSERT_IPMETA_LOCATION_SQL, INSERT_IPMETA_LOCATION_PARAM_COUNT,
            NULL);
    if (PQresultStatus(state->insert_loc_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of insert location statement failed: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    state->insert_rec_stmt = PQprepare(state->pgconn, "insert_record",
            INSERT_IPMETA_RECORD_SQL, INSERT_IPMETA_RECORD_PARAM_COUNT,
            NULL);
    if (PQresultStatus(state->insert_rec_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of insert record statement failed: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    state->select_loc_stmt = PQprepare(state->pgconn, "select_location",
            SELECT_IPMETA_LOCATION_SQL, SELECT_IPMETA_LOCATION_PARAM_COUNT,
            NULL);
    if (PQresultStatus(state->select_loc_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of select location statement failed: %s\n",
                PQerrorMessage(state->pgconn));
        goto end;
    }

    if ((file = wandio_create(filename)) == NULL) {
        fprintf(stderr, "failed to open file '%s'\n", filename);
        goto end;
    }
    state->next_record_id = 1;
    state->current_filename = filename;
    state->first_column = -1;
    state->current_line = 0;
    state->parse_row = NULL;
    state->rec_lat = NULL;
    state->rec_long = NULL;

    state->timestamp_str = derive_timestamp_from_filename(filename);
    if (state->timestamp_str == NULL) {
        goto end;
    }

    state->record = calloc(1, sizeof(ipmeta_record_t));

    while (state->first_column < 0) {
        read = wandio_fgets(file, &buffer, BUFFER_LEN, 0);
        if (read < 0) {
            fprintf(stderr, "error reading file: %s\n", filename);
            goto end;
        }
        if (read == 0) {
            fprintf(stderr, "Empty file: %s\n", filename);
            goto end;
        }
        if (startswith(buffer, "start_ip,")) {
            state->current_column = state->first_column = 0;
            state->parse_row = parse_ipinfo_row;
            state->block_lower.family = AF_INET;
            state->block_lower.masklen = 32;
            state->block_upper.family = AF_INET;
            state->block_upper.masklen = 32;
            if (!state->country_continent) {
                load_country_continent_map(state);
            }
        } else {
            break;
        }
        state->current_line ++;
        continue;
    }
    csv_init(&(state->parser), CSV_STRICT | CSV_REPALL_NL | CSV_STRICT_FINI |
            CSV_APPEND_NULL | CSV_EMPTY_IS_NULL);
    while ((read = wandio_read(file, &buffer, BUFFER_LEN)) > 0) {
        if (csv_parse(&(state->parser), buffer, read, parse_ipinfo_cell,
                state->parse_row, state) != read) {
            fprintf(stderr, "Error parsing ipinfo locations file\n");
            fprintf(stderr, "CSV Error: %s\n",
                 csv_strerror(csv_error(&(state->parser))));
            goto end;
        }
        if (state->psql_error) {
            goto end;
        }
    }
    if (read < 0) {
        fprintf(stderr, "Error reading file %s\n", filename);
        goto end;
    }

    if (csv_fini(&(state->parser), parse_ipinfo_cell, state->parse_row,
            state) != 0) {
        fprintf(stderr, "Error parsing ipinfo locations file\n");
        fprintf(stderr, "CSV Error: %s\n",
                csv_strerror(csv_error(&(state->parser))));
        goto end;
    }
    rc = 0;

    /* update complete, insert the upload row */
    insert_upload_time_row(state);

end:
    csv_free(&(state->parser));
    wandio_destroy(file);
    PQclear(state->insert_upload_stmt);
    PQclear(state->insert_pfx_bounds_stmt);
    PQclear(state->insert_rec_stmt);
    PQclear(state->insert_loc_stmt);
    PQclear(state->select_loc_stmt);
    PQclear(state->insert_city_stmt);
    PQclear(state->select_city_stmt);
    PQclear(state->insert_city_attr_stmt);
    PQfinish(state->pgconn);
    return rc;
}

void free_ipmeta_inserter_state(ipmeta_inserter_state_t *state) {
    khiter_t k;
    int i;
    city_lookup_t *cmap;
    ll_region_t reg;

    if (state == NULL) {
        return;
    }

    if (state->regions_file) {
        free(state->regions_file);
    }

    if (state->locations_file) {
        free(state->locations_file);
        state->locations_file = NULL;
    }

    if (state->timestamp_str) {
        free(state->timestamp_str);
    }

    if (state->psql_dbname) {
        free(state->psql_dbname);
    }

    if (state->psql_username) {
        free(state->psql_username);
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

    if (state->meta_psql_dbname) {
        free(state->meta_psql_dbname);
    }

    if (state->meta_psql_username) {
        free(state->meta_psql_username);
    }

    if (state->meta_psql_password) {
        free(state->meta_psql_password);
    }

    if (state->meta_psql_host) {
        free(state->meta_psql_host);
    }

    if (state->meta_psql_port) {
        free(state->meta_psql_port);
    }

    if (state->country_continent) {
        kh_destroy(u16u16, state->country_continent);
        state->country_continent = NULL;
    }

    if (state->regions_map) {
        for (k = 0; k < kh_end(state->regions_map); ++k) {
            if (kh_exist(state->regions_map, k)) {
                free((void *)kh_key(state->regions_map, k));
                reg = kh_value(state->regions_map, k);

                if (reg.region_name) {
                    free((void *)reg.region_name);
                }
                if (reg.region_code) {
                    free((void *)reg.region_code);
                }
            }
        }
        kh_destroy(ll_region_map, state->regions_map);
    }

    if (state->city_codes_map) {
        for (k = 0; k < kh_end(state->city_codes_map); ++k) {
            if (kh_exist(state->city_codes_map, k)) {
                cmap = kh_value(state->city_codes_map, k);
                for (i = 0; i < cmap->used; i++) {
                    free((void *)cmap->region_codes[i]);
                    free((void *)cmap->city_codes[i]);
                }
                free(cmap->region_codes);
                free(cmap->city_codes);
                free((void *)kh_key(state->city_codes_map, k));
                free(cmap);
            }
        }
        kh_destroy(city_map, state->city_codes_map);
    }

    if (state->unknown_regions_map) {
        for (k = 0; k < kh_end(state->unknown_regions_map); ++k) {
            if (kh_exist(state->unknown_regions_map, k)) {
                free((void *)kh_key(state->unknown_regions_map, k));
                reg = kh_value(state->unknown_regions_map, k);

                if (reg.region_name) {
                    free((void *)reg.region_name);
                }
                if (reg.region_code) {
                    free((void *)reg.region_code);
                }
            }
        }
        kh_destroy(ll_region_map, state->unknown_regions_map);
    }

    if (state->rec_lat) {
        free(state->rec_lat);
    }
    if (state->rec_long) {
        free(state->rec_long);
    }
    ipmeta_free_record(state->record);
    free(state);
    return;
}

int main(int argc, char *argv[]) {
    ipmeta_inserter_state_t *state = calloc(1, sizeof(ipmeta_inserter_state_t));

    state->next_city_id = -1;
    if (parse_args(state, argc, argv) < 0) {
        fprintf(stderr, "Failed to parse arguments... exiting\n");
        return -1;
    }

    if (load_region_latlongs(state, state->regions_file) != 0) {
        fprintf(stderr, "Failed to parse IODA region mapping file\n");
        goto endprog;
    }

    if (read_ipinfo_file(state, state->locations_file) != 0) {
        fprintf(stderr, "Failed to parse locations file\n");
    }

endprog:
    free_ipmeta_inserter_state(state);
    return 0;
}

