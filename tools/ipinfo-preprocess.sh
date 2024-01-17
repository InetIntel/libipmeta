#!/bin/bash

OPTSTRING=":u:r:i:o:"

usage() {
    >&2 echo "Required arguments: "
    >&2 echo "    -u <file>    File containing the unknown region codes for each country."
    >&2 echo "    -r <file>    File containing the region names and IDs for each lat-long pair."
    >&2 echo "    -i <file>    The IPInfo data file to process."
    >&2 echo "    -o <file>    The file to write the processed output to. "
    >&2 echo "                 Note that this file will be gzip-compressed."

    exit 1
}

UNKNOWN=""
REGIONMAP=""
INPUT=""
OUTPUT=""

while getopts ${OPTSTRING} opt; do
    case $opt in
        u)
            UNKNOWN=$OPTARG
            ;;
        r)
            REGIONMAP=$OPTARG
            ;;
        i)
            INPUT=$OPTARG
            ;;
        o)
            OUTPUT=$OPTARG
            ;;
        \?)
            usage
            ;;
        :)
            usage
            ;;
    esac
done

if [[ ${UNKNOWN} == "" ]]; then
    echo "-u option must be set"
    usage
fi
if [[ ${REGIONMAP} == "" ]]; then
    echo "-r option must be set"
    usage
fi
if [[ ${INPUT} == "" ]]; then
    echo "-i option must be set"
    usage
fi
if [[ ${OUTPUT} == "" ]]; then
    echo "-o option must be set"
    usage
fi

echo "Preprocessing ${INPUT}"

python3 process-ipinfo.py -u ${UNKNOWN} -l ${REGIONMAP} -i ${INPUT} -o /tmp/ipinfo-processed.gz

echo "Processing complete, sorting output...."

zcat /tmp/ipinfo-processed.gz | grep -v ":" | sort -k1,1 -k2,2 -k3,3 -k4,4 -n -t. | gzip -1 -c > ${OUTPUT}

rm /tmp/ipinfo-processed.gz
