import sys
from io import StringIO
import pandas as pd
from invoke import task
# determine OS
from sys import platform

PCAPFILE = "data/lo0-ns1717-ws2-nc125-wc3.pcapng"

@task
def pcap_to_csv(conn, pcapfile):
    """Convert the PCAP to a CSV file.

    Convert the PCAP to a CSV with relative timestamps and signed packet
    sizes.
    """
    result = conn.run(
        f"tshark -r {pcapfile} -Tfields "
        "-e frame.time_epoch -e frame.len -e udp.srcport -e quic.stream.stream_id -e quic.frame_type",
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


@task
def plot_server(conn):
  f = open(PCAPFILE, "r")

  f.close()
