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

const char *INSERT_IPINFO_PREFIX_SQL =
    "INSERT INTO ipmeta_prefixes (id, prefix, source, published, location, "
    "post_code, latitude, longitude) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
    "ON CONFLICT DO NOTHING";

const char *INSERT_IPMETA_LOCATION_SQL =
    "INSERT INTO ipmeta_locations (country_code, continent_code, region, "
    "city, timezone) VALUES ($1, $2, $3, $4, $5) RETURNING id";

const char *SELECT_IPMETA_LOCATION_SQL =
    "SELECT id FROM ipmeta_locations WHERE country_code = $1 AND "
    "continent_code = $2 AND region = $3 AND city = $4";

#define INSERT_IPINFO_PREFIX_PARAM_COUNT 8
#define INSERT_IPMETA_LOCATION_PARAM_COUNT 5
#define SELECT_IPMETA_LOCATION_PARAM_COUNT 4

// convert char[2] to uint16_t
#define c2_to_u16(c2) (((c2)[0] << 8) | (c2)[1])

KHASH_INIT(u16u16, uint16_t, uint16_t, 1, kh_int_hash_func, kh_int_hash_equal)

KHASH_SET_INIT_STR(str_set)

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
    char *timestamp_str;

    uint8_t skip_ipv6;

    PGconn *pgconn;
    PGresult *insert_pfx_stmt;
    PGresult *insert_loc_stmt;
    PGresult *select_loc_stmt;
    uint8_t psql_error;
    int trans_size;

    struct csv_parser parser;
    int current_line;
    int current_column;
    int first_column;
    int next_record_id;
    void (*parse_row)(int, void *);
    ipmeta_record_t *record;
    ipvx_prefix_t block_lower;
    ipvx_prefix_t block_upper;

    const char *current_filename;

    /** map from country to continent */
    khash_t(u16u16) *country_continent;

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

/** Prints usage information to stderr */
static void usage(char *progname) {
    fprintf(stderr,
        "Usage: %s -l locations\n"
        "    -l <file>  The file containing the location data\n"
        "    -H <host>  The IP or hostname of the PSQL server\n"
        "    -P <port>  The port number of the PSQL service (default: 5672)\n"
        "    -U <user>  The username to log in with (default: postgres)\n"
        "    -A <password> The password to log in with (default: no password) \n"
        "    -d <dbname>  The name of the database (default: ipmeta)\n",
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
    while ((opt = getopt(argc, argv, "4l:H:P:d:U:A:?")) >= 0) {
        switch (opt) {
            case 'l':
                if (state->locations_file) {
                    fprintf(stderr,
                            "ERROR: only one location file is allowed\n");
                    return -1;
                }
                state->locations_file = strdup(optarg);
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
            if (tok && *tok) {
                rec->latitude = strtod(tok, &end);
                if (end == tok || *end || rec->latitude < -90 ||
                        rec->latitude > 90) {
                    col_invalid(state, "Invalid latitude", tok);
                }
            }
            break;
        case LOCATION_COL_LONG:
            if (tok && *tok) {
                rec->longitude = strtod(tok, &end);
                if (end == tok || *end || rec->longitude < -180 ||
                        rec->longitude > 180) {
                    col_invalid(state, "Invalid longitude", tok);
                }
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

static int64_t insert_location_into_psql(ipmeta_inserter_state_t *state) {

    PGresult *pg_res, *ins_res;
    const char *values[INSERT_IPMETA_LOCATION_PARAM_COUNT];
    int64_t retid = -1;

    assert(INSERT_IPMETA_LOCATION_PARAM_COUNT >=
            SELECT_IPMETA_LOCATION_PARAM_COUNT);

    values[0] = state->record->country_code;
    values[1] = state->record->continent_code;
    if (state->record->region == NULL) {
        if (state->record->city) {
            values[2] = state->record->city;
        } else {
            values[2] = "Unknown Region";
        }
    } else {
        values[2] = state->record->region;
    }

    if (state->record->city == NULL) {
        values[3] = "Unknown City";
    } else {
        values[3] = state->record->city;
    }
    values[4] = state->record->timezone;

    pg_res = PQexecPrepared(state->pgconn, "select_location",
            SELECT_IPMETA_LOCATION_PARAM_COUNT, values, NULL, NULL, 0);
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
        }
        PQclear(ins_res);
    }
    PQclear(pg_res);
    return retid;
}

static int insert_pfx_into_psql(ipmeta_inserter_state_t *state,
        ipvx_prefix_list_t *pfx_node, int64_t loc_id) {

    PGresult *pg_res;
    const char *values[INSERT_IPINFO_PREFIX_PARAM_COUNT];
    char pfxstr[INET_ADDRSTRLEN + 4];

    char idstr[32];
    char loc_id_str[32];
    char latstr[32];
    char longstr[32];
    int ret = 0;

    if (ipvx_ntop_pfx(&(pfx_node->prefix), pfxstr) == NULL) {
        fprintf(stderr, "Unable to convert ipvx prefix to string\n");
        return -1;
    }

#define rec (state->record)  /* convenient code abbreviation */
    snprintf(idstr, 32, "%u", rec->id);
    snprintf(loc_id_str, 32, "%ld", loc_id);
    snprintf(latstr, 32, "%.6f", rec->latitude);
    snprintf(longstr, 32, "%.6f", rec->longitude);


    values[0] = idstr;
    values[1] = pfxstr;
    values[2] = "ipinfo";
    values[3] = state->timestamp_str;
    values[4] = loc_id_str;
    values[5] = rec->post_code;
    values[6] = latstr;
    values[7] = longstr;
#undef rec

    pg_res = PQexecPrepared(state->pgconn, "insert_ipmeta",
            INSERT_IPINFO_PREFIX_PARAM_COUNT, values, NULL, NULL, 0);
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

static void parse_ipinfo_row(int c, void *data) {
    ipmeta_inserter_state_t *state = (ipmeta_inserter_state_t *)(data);
    ipvx_prefix_list_t *pfx_list=NULL, *pfx_node;
    PGresult *pg_res;
    int64_t loc_id;

    khiter_t khiter;

    if (state->psql_error) {
        goto rowdone;
    }

    if (state->current_column != LOCATION_COL_ENDCOL) {
        fprintf(stderr, "Row contains an unexpected number of columns?\n");
        goto rowdone;
    }

    check_column_count(state, LOCATION_COL_ENDCOL);
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

    if (state->trans_size >= 10000) {
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

    for (pfx_node = pfx_list; pfx_node != NULL; pfx_node = pfx_node->next) {
        // do insertion here
        if (insert_pfx_into_psql(state, pfx_node, loc_id) < 0) {
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

static int read_ipinfo_file(ipmeta_inserter_state_t *state,
        const char *filename) {
    io_t *file;
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

    state->insert_pfx_stmt = PQprepare(state->pgconn, "insert_ipmeta",
            INSERT_IPINFO_PREFIX_SQL, INSERT_IPINFO_PREFIX_PARAM_COUNT, NULL);
    if (PQresultStatus(state->insert_pfx_stmt) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of insert prefix statement failed: %s\n",
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

end:
    csv_free(&(state->parser));
    wandio_destroy(file);
    PQclear(state->insert_pfx_stmt);
    PQclear(state->insert_loc_stmt);
    PQclear(state->select_loc_stmt);
    PQfinish(state->pgconn);
    return rc;
}

void free_ipmeta_inserter_state(ipmeta_inserter_state_t *state) {
    khiter_t k;

    if (state == NULL) {
        return;
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

    if (state->country_continent) {
        kh_destroy(u16u16, state->country_continent);
        state->country_continent = NULL;
    }

    ipmeta_free_record(state->record);
    free(state);
    return;
}

int main(int argc, char *argv[]) {
    ipmeta_inserter_state_t *state = calloc(1, sizeof(ipmeta_inserter_state_t));

    if (parse_args(state, argc, argv) < 0) {
        fprintf(stderr, "Failed to parse arguments... exiting\n");
        return -1;
    }

    if (read_ipinfo_file(state, state->locations_file) != 0) {
        fprintf(stderr, "Failed to parse locations file\n");
    }

    free_ipmeta_inserter_state(state);
    return 0;
}

