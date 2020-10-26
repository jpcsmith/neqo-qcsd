#!/usr/bin/env bash
set -eo pipefail

# TODO: Ensure that they are set
readonly PCAP_FILE="$1"
readonly CSV_FILE="$2"
readonly HTTPS_PORT=7443
readonly INTERFACE=lo

TSHARK_PID=


tshark_start() {
    local -r pcap_file="$1"

    echo "Starting tshark..." 1>&2
    tshark -i "${INTERFACE}" -f "port ${HTTPS_PORT}" -w "${pcap_file}" &
    TSHARK_PID="$!"

    echo "Waiting for tshark to initialise..." 1>&2
    sleep 3
}

tshark_stop() {
    echo "Sending SIGTERM to tshark with pid ${TSHARK_PID}" 1>&2
    kill -TERM "${TSHARK_PID}"
    TSHARK_PID=
}



capture_no_shaping() {
    local -r pcap="$1"

    tshark_start "${pcap}"
    CSDEF_NO_SHAPING=true ./request-vanilla.sh
    tshark_stop
}



main() {
    local -r pcap_file="${1:?Missing for the target PCAP file argument}"

    capture_no_shaping "${pcap_file}"
    capture_
}


main "$@"
