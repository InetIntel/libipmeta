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

#include "libipmeta_int.h"
#include "config.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wandio.h"

#include "khash.h"
#include "utils.h"
#include "csv.h"
#include "ipvx_utils.h"

#include "ipmeta_ds.h"
#include "ipmeta_provider_ipinfo.h"
#include "ipmeta_parsing_helpers.h"

#define PROVIDER_NAME "ipinfo"

#define STATE(provname) (IPMETA_PROVIDER_STATE(ipinfo, provname))

#define BUFFER_LEN 1024

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

/** The basic fields that every instance of this provider have in common */
static ipmeta_provider_t ipmeta_provider_ipinfo = {
    IPMETA_PROVIDER_IPINFO, PROVIDER_NAME,
    IPMETA_PROVIDER_GENERATE_PTRS(ipinfo) };

/** Holds the state for an instance of this provider */
typedef struct ipmeta_provider_ipinfo_state {
    char *locations_file;
    uint8_t skip_ipv6;

    struct csv_parser parser;
    int current_line;
    int current_column;
    int first_column;
    int next_record_id;
    void (*parse_row)(int, void *);
    ipmeta_record_t *record;
    ipvx_prefix_t block_lower;
    ipvx_prefix_t block_upper;
    int rec_prefix_count;

    ipvx_prefix_t block_lower_first;
    ipvx_prefix_t block_upper_last;

    const char *current_filename;

    /** map from country to continent */
    khash_t(u16u16) *country_continent;

    /** set of region ID strings */
    kh_str_set_t *regions;

} ipmeta_provider_ipinfo_state_t;

/** The columns in a ipinfo locations CSV file */
typedef enum column_list {
    LOCATION_COL_STARTIP,       ///< Range Start IP
    LOCATION_COL_ENDIP,         ///< Range End IP
    LOCATION_COL_REGION,        ///< Region String
    LOCATION_COL_COUNTRY,       ///< 2 Char Country Code
    LOCATION_COL_ENDCOL,        ///< 1 past the last column ID
} location_cols_t;

/** Prints usage information to stderr */
static void usage(ipmeta_provider_t *provider) {
    fprintf(stderr,
        "provider usage: %s -l locations\n"
        "    -l <file>  The file containing the pre-processed location data\n",
        provider->name);
}

static int parse_args(ipmeta_provider_t *provider, int argc, char **argv) {
    ipmeta_provider_ipinfo_state_t *state = STATE(provider);
    int opt;
    char *ptr = NULL;

    /* no args */
    if (argc == 0) {
      usage(provider);
      return -1;
    }

    optind = 1;
    while ((opt = getopt(argc, argv, "4l:?")) >= 0) {
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
            case '?':
            case ':':
            default:
                usage(provider);
                return -1;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "ERROR: extra arguments to %s\n", provider->name);
        usage(provider);
        return -1;
    }

    if (state->locations_file == NULL) {
        fprintf(stderr,
                "ERROR: %s locations file must be specified using -l!\n",
                provider->name);
        usage(provider);
        return -1;
    }
    return 0;
}

static char *insert_name_into_set(char *name, kh_str_set_t **set) {
    int ret;
    khiter_t k;

    if (name == NULL) {
        return NULL;
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

static void insert_ipinfo_record(ipmeta_provider_t *provider,
        ipmeta_provider_ipinfo_state_t *state) {

    ipvx_prefix_list_t *pfx_list, *pfx_node;

    khiter_t khiter;

    if (state->record == NULL || state->record->id == 0 ||
            state->rec_prefix_count == 0) {
        goto insdone;
    }

    if (state->block_lower_first.family == AF_UNSPEC ||
            state->block_upper_last.family == AF_UNSPEC) {
        goto insdone;
    }

    char *cc = state->record->country_code;
    if ((khiter = kh_get(u16u16, state->country_continent, c2_to_u16(cc))) ==
            kh_end(state->country_continent)) {
        fprintf(stderr, "ERROR: Unknown country code (%s)\n", cc);
        goto insdone;
    }
    uint16_t cont = kh_value(state->country_continent, khiter);
    u16_to_c2(cont, state->record->continent_code);

    /* store the numeric equivalent of the region code
     *
     * consider caching if start-up performance is an issue due to
     * repeated string-to-integer conversions XXX
     */
    if (state->record->region) {
        char *endptr;
        unsigned long conv = strtoul(state->record->region, &endptr, 10);
        if ((errno == EINVAL || errno == ERANGE) && conv == ULONG_MAX) {
            fprintf(stderr,
                "ERROR: strtoul failure (input was '%s')\n",
                state->record->region);
            goto insdone;
        }

        if (endptr == state->record->region) {
            fprintf(stderr,
                "ERROR: region must be a valid numeric identifier (not '%s')\n",
                state->record->region);
            goto insdone;
        }

        if (conv > UINT16_MAX) {
            fprintf(stderr,
                "ERROR: region code was unexpectedly large: %lu\n", conv);
            goto insdone;
        }
        state->record->region_code = (uint16_t)conv;
    }

    ipmeta_provider_insert_record(provider, state->record);
    /* pre-cache record FQIDs for faster future lookup */
    ipmeta_derive_geo_fqid_from_record(provider, state->record,
            IPMETA_GEO_DETAIL_REGION);

    if (ipvx_range_to_prefix(&state->block_lower_first,
            &state->block_upper_last, &pfx_list) != 0) {
        fprintf(stderr, "%s\n", "Could not convert IP range to prefixes");
        goto insdone;
    }
    if (pfx_list == NULL) {
        goto insdone;
    }

    for (pfx_node = pfx_list; pfx_node != NULL; pfx_node = pfx_node->next) {
        if (ipmeta_provider_associate_record(provider,
                pfx_node->prefix.family, &(pfx_node->prefix.addr),
                pfx_node->prefix.masklen, state->record) != 0) {
            fprintf(stderr, "%s\n", "Failed to associate record with prefix");
            goto insdone;
        }
    }
    ipvx_prefix_list_free(pfx_list);

insdone:
    state->record = malloc_zero(sizeof(ipmeta_record_t));
    state->record->id = state->next_record_id;
    state->next_record_id ++;
    state->rec_prefix_count = 0;

    memcpy(&(state->block_lower_first), &(state->block_lower),
            sizeof(ipvx_prefix_t));
    memcpy(&(state->block_upper_last), &(state->block_upper),
            sizeof(ipvx_prefix_t));
}

static void parse_ipinfo_cell(void *s, size_t i, void *data) {
    ipmeta_provider_t *provider = (ipmeta_provider_t *)data;
    ipmeta_provider_ipinfo_state_t *state = STATE(provider);
    char *tok = (char *)s;
    char *end;
    unsigned char buf[sizeof(struct in6_addr)];
    int ret;
    char cc[2];
    char *region = NULL;

#define rec (state->record)  /* convenient code abbreviation */

    switch(state->current_column) {
        case LOCATION_COL_STARTIP:
            if (rec == NULL) {
                rec = malloc_zero(sizeof(ipmeta_record_t));
                rec->id = state->next_record_id;
                state->next_record_id ++;
                state->rec_prefix_count = 0;
            }

            if (strchr(tok, ':')) {
                /* ipv6 */
                if (state->skip_ipv6) {
                    state->block_lower.family = AF_UNSPEC;
                    break;
                }
                state->block_lower.family = AF_INET6;
                state->block_lower.masklen = 128;
                ret = inet_pton(AF_INET6, tok,
                        &(state->block_lower.addr.v6));
            } else {
                state->block_lower.family = AF_INET;
                state->block_lower.masklen = 32;
                ret = inet_pton(AF_INET, tok, &(state->block_lower.addr.v4));
            }

            if (ret <= 0) {
                col_invalid(state, "Invalid start IP", tok);
            }
            if (state->rec_prefix_count == 0) {
                memcpy(&(state->block_lower_first), &(state->block_lower),
                        sizeof(ipvx_prefix_t));
            }
            break;
        case LOCATION_COL_ENDIP:
            if (strchr(tok, ':')) {
                /* ipv6 */
                if (state->skip_ipv6) {
                    state->block_upper.family = AF_UNSPEC;
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
                cc[0] = cc[1] = '?';
            } else if (strlen(tok) != 2) {
                col_invalid(state, "Invalid country code", tok);
            } else {
                memcpy(cc, tok, 2);
            }

            if (state->rec_prefix_count > 0 && (cc[0] != rec->country_code[0]
                    || cc[1] != rec->country_code[1])) {
                insert_ipinfo_record(provider, state);
            }
            rec->country_code[0] = cc[0];
            rec->country_code[1] = cc[1];
            break;
        case LOCATION_COL_REGION:
            region = insert_name_into_set(tok, &(state->regions));
            if (state->rec_prefix_count > 0) {
                if (region == NULL && rec->region != NULL) {
                    insert_ipinfo_record(provider, state);
                } else if (region != NULL && rec->region == NULL) {
                    insert_ipinfo_record(provider, state);
                } else if (region != NULL && strcmp(region, rec->region) != 0) {
                    insert_ipinfo_record(provider, state);
                }
            }
            rec->region = region;
            break;
        default:
            col_invalid(state, "Unexpected trailing column", tok);
    }
#undef rec
    state->current_column++;
}

static void parse_ipinfo_row(int c, void *data) {
    ipmeta_provider_t *provider = (ipmeta_provider_t *)data;
    ipmeta_provider_ipinfo_state_t *state = STATE(provider);

    check_column_count(state, LOCATION_COL_ENDCOL);

    state->rec_prefix_count ++;
    state->current_line ++;
    state->current_column = 0;

    memcpy(&(state->block_upper_last), &(state->block_upper),
            sizeof(ipvx_prefix_t));
    return;
}

static void load_country_continent_map(ipmeta_provider_ipinfo_state_t *state) {
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

static int read_ipinfo_file(ipmeta_provider_t *provider, const char *filename) {
    ipmeta_provider_ipinfo_state_t *state = STATE(provider);
    io_t *file;
    char buffer[BUFFER_LEN];
    int read;
    int rc = -1;

    if ((file = wandio_create(filename)) == NULL) {
        ipmeta_log(__func__, "failed to open file '%s'", filename);
        goto end;
    }
    state->next_record_id = 1;
    state->current_filename = filename;
    state->first_column = -1;
    state->current_line = 0;
    state->parse_row = NULL;

    state->regions = kh_init(str_set);

    while (state->first_column < 0) {
        read = wandio_fgets(file, &buffer, BUFFER_LEN, 0);
        if (read < 0) {
            ipmeta_log(__func__, "error reading file: %s", filename);
            goto end;
        }
        if (read == 0) {
            ipmeta_log(__func__, "Empty file: %s", filename);
            goto end;
        }
        if (startswith(buffer, "start_ip,")) {
            state->current_column = state->first_column = 0;
            state->parse_row = parse_ipinfo_row;
            state->record = NULL;
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
                state->parse_row, provider) != read) {
            ipmeta_log(__func__, "Error parsing %s file", provider->name);
            ipmeta_log(__func__, "CSV Error: %s",
                 csv_strerror(csv_error(&(state->parser))));
            goto end;
        }
    }
    if (read < 0) {
        ipmeta_log(__func__, "Error reading file %s", filename);
        goto end;
    }

    if (csv_fini(&(state->parser), parse_ipinfo_cell, state->parse_row,
            provider) != 0) {
        ipmeta_log(__func__, "Error parsing %s file %s", provider->name,
                filename);
        ipmeta_log(__func__, "CSV Error: %s",
                csv_strerror(csv_error(&(state->parser))));
        goto end;
    }

    if (state->rec_prefix_count > 0) {
        insert_ipinfo_record(provider, state);
    }
    rc = 0;

end:
    csv_free(&(state->parser));
    wandio_destroy(file);
    return rc;
}

/* ===== PUBLIC FUNCTIONS BELOW THIS POINT ===== */

ipmeta_provider_t *ipmeta_provider_ipinfo_alloc() {
    return &ipmeta_provider_ipinfo;
}

int ipmeta_provider_ipinfo_init(ipmeta_provider_t *provider, int argc,
        char **argv) {

    ipmeta_provider_ipinfo_state_t *state = NULL;
    if ((state = malloc_zero(sizeof(ipmeta_provider_ipinfo_state_t))) == NULL) {
        ipmeta_log(__func__, "could not malloc ipmeta_provider_ipinfo_state_t");
        return -1;
    }
    state->skip_ipv6 = 0;
    ipmeta_provider_register_state(provider, state);

    if (parse_args(provider, argc, argv) != 0) {
        return -1;
    }

    if (read_ipinfo_file(provider, state->locations_file) != 0) {
        ipmeta_log(__func__, "failed to parse locations file");
        goto err;
    }

    return 0;
err:
    usage(provider);
    return -1;
}

void ipmeta_provider_ipinfo_free(ipmeta_provider_t *provider) {
    ipmeta_provider_ipinfo_state_t *state = STATE(provider);
    khiter_t k;

    if (state != NULL) {
        if (state->locations_file) {
            free(state->locations_file);
            state->locations_file = NULL;
        }

        if (state->regions) {
            for (k = 0; k < kh_end(state->regions); ++k) {
                if (kh_exist(state->regions, k)) {
                    free((void *)kh_key(state->regions, k));
                }
            }
            kh_destroy(str_set, state->regions);
        }


        if (state->country_continent) {
            kh_destroy(u16u16, state->country_continent);
            state->country_continent = NULL;
        }

        if (state->record) {
            ipmeta_free_record(state->record);
        }

        ipmeta_provider_free_state(provider);
    }
    return;
}

int ipmeta_provider_ipinfo_lookup_pfx(ipmeta_provider_t *provider, int family,
    void *addrp, uint8_t pfxlen, ipmeta_record_set_t *records)
{
  /* just call the lookup helper func in provider manager */
  return ipmeta_provider_lookup_pfx(provider, family, addrp, pfxlen, records);
}

int ipmeta_provider_ipinfo_lookup_addr(ipmeta_provider_t *provider, int family,
    void *addrp, ipmeta_record_set_t *found)
{
  /* just call the lookup helper func in provider manager */
  return ipmeta_provider_lookup_addr(provider, family, addrp, found);
}

void ipmeta_provider_ipinfo_free_record(ipmeta_record_t *record)
{
    if (record == NULL) {
        return;
    }
    memset(record, 0, sizeof(ipmeta_record_t));
    free(record);
}
