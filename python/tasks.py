"""Tasks and routines
"""
import sys
from io import StringIO
import pandas as pd
from invoke import task

SERVER_PORTS = [80, 443, 7443]


@task
def extract_har_urls(conn, harfile):
    """Extract the URLs from the specified HAR file.

    Escaped and print one URL per line, for use in bash with mapfile.
    """
    result = conn.run(
        f"jq  -j '.log.entries | map(.request.url) | join(\" \")' {harfile}",
        hide="stdout")

    for url in result.stdout.split(" "):
        print(url)


@task
def pcap_to_csv(conn, pcapfile):
    """Convert the PCAP to a CSV file.

    Convert the PCAP to a CSV with relative timestamps and signed packet
    sizes.
    """
    result = conn.run(
        f"tshark -r {pcapfile} -Tfields -E separator=',' "
        "-e frame.time_epoch -e frame.len -e udp.srcport -e tcp.srcport ",
        hide="stdout")

    csv = StringIO(result.stdout)
    data = pd.read_csv(
        csv, header=None, names=["timestamp", "size", "udp.port", "tcp.port"])
    assert not (data["size"] > 1600).any()

    # Zero the timestamps
    data = data.sort_values(by="timestamp")
    data["timestamp"] -= data.loc[0, "timestamp"]

    # Set the direction
    outgoing_mask = (data[["udp.port", "tcp.port"]]
                     .isin(SERVER_PORTS).any(axis=1))
    data["dir"] = 1
    data.loc[outgoing_mask, "dir"] = -1

    # Create signed packet sizes
    data["size"] *= data["dir"]

    data[["timestamp", "size"]].to_csv(sys.stdout, header=False, index=False)


@task
def pcap_with_padding_to_csv(conn, pcapfile):
    """Convert the PCAP to a CSV file.

    Convert the PCAP to a CSV with relative timestamps and signed packet
    sizes.
    """
    result = conn.run(
        f"tshark -r {pcapfile} -Tfields -E separator='%' "
        "-e frame.time_epoch -e frame.len -e udp.srcport -e tcp.srcport -e quic.frame_type ",
        hide="stdout")

    csv = StringIO(result.stdout)
    data = pd.read_csv(
        csv, header=None, names=["timestamp", "size", "udp.port", "tcp.port", "quic.frame_type"], sep='%')
    assert not (data["size"] > 1600).any()

    # Zero the timestamps
    data = data.sort_values(by="timestamp")
    data["timestamp"] -= data.loc[0, "timestamp"]

    # Set the direction
    outgoing_mask = (data[["udp.port", "tcp.port"]]
                     .isin(SERVER_PORTS).any(axis=1))
    data["dir"] = 1
    data.loc[outgoing_mask, "dir"] = -1

    # Create signed packet sizes
    data["size"] *= data["dir"]

    data[["timestamp", "size", "quic.frame_type"]].to_csv(sys.stdout, header=False, index=False)