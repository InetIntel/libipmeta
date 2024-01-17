#!/usr/bin/python3

import sys, string, argparse, csv, gzip
import ipaddress

latlongs = {}

def parse_unknowns_file(unkfile):
    unknowns = {}

    with open(unkfile, "r") as f:
        for line in f:
            s = line.strip().split(",")
            if len(s) != 2:
                continue
            unknowns[s[0]] = s[1]

    return unknowns

def parse_latlong_file(llfile):
    latlongs = {}
    with open(llfile, newline='') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            assert(len(row) == 6)
            if row[0] == "latitude":
                continue
            if (row[0], row[1]) not in latlongs:
                latlongs[(row[0], row[1])] = row[3]
    return latlongs

def lookup_region(cc, lat, longg, unknowns, latlongs):
    if (lat, longg) in latlongs:
        return latlongs[(lat, longg)]

    if cc not in unknowns:
        return "0"
    return unknowns[cc]

def process_ipinfo_for_ioda(ipfile, outpath, unknowns, latlongs):
    try:
        with gzip.open(outpath, "wt") as out:
            out.write("start_ip,end_ip,region,country\n")
            with gzip.open(ipfile, "rt", newline='') as ff:
                reader = csv.reader(ff, delimiter=',')
                for row in reader:
                    assert(len(row) == 10)
                    if row[0] == "start_ip":
                        continue
                    cc = row[5]
                    start = row[0]
                    end = row[1]
                    region = lookup_region(cc, row[6], row[7], unknowns,
                            latlongs)
                    out.write("%s,%s,%s,%s\n" % (start, end, region, cc))
    except IOError as e:
        print(f'IO Error: {e}')
        return
    except Exception as e:
        print(f'Unexpected Error: {e}')
        return

parser = argparse.ArgumentParser();
parser.add_argument("-u", "--unknown", type=str, help="File containing the unknown region codes for each country code")
parser.add_argument("-l", "--latlongs", type=str, help="File containing the IODA region ID that matches each lat-long datapoint in an IPInfo snapshot")
parser.add_argument("-i", "--ipinfo", type=str, help="The IPInfo snapshot file to process")
parser.add_argument("-o", "--output", type=str, help="The file to write the processed output into")

args = parser.parse_args()

if args.unknown is None:
    print("Error: must provide location of unknown region codes file")
    parser.print_help()
    sys.exit(1)


if args.latlongs is None:
    print("Error: must provide location of lat-long to region mappings file")
    parser.print_help()
    sys.exit(1)


if args.ipinfo is None:
    print("Error: must provide an IPInfo snapshot file")
    parser.print_help()
    sys.exit(1)

if args.output is None:
    print("Error: must provide a path for an output file")
    parser.print_help()
    sys.exit(1)

unknowns = parse_unknowns_file(args.unknown)
latlongs = parse_latlong_file(args.latlongs)

process_ipinfo_for_ioda(args.ipinfo, args.output, unknowns, latlongs)
