"""Tasks for performing captures, with and without shaping.
"""
# pylint: disable=too-many-arguments
import os
import time
import signal
from contextlib import contextmanager

from io import StringIO
import pandas as pd
import numpy as np
from matplotlib import pyplot as plt

# determine OS
from sys import platform
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Optional

from invoke import task


NEQO_LOG = "neqo_transport=info,debug"
LOCAL_NETLOC = "{}:7443".format(
    "localhost" if platform == "linux" else "host.docker.internal")
DEFAULT_NETLOC = {
    "vanilla": "vanilla.neqo-test.com:7443",
    "weather": "weather.neqo-test.com:7443",
}

PCAPFILE = "data/lo0-ns1717-ws2-nc125-wc3.pcapng"
SERVER_PORTS = [80, 443, 7443]
DUMMYSTREAMS = ['0', '4', '8', '12', '16']

RATE = 0.05 #ms

PALETTE = {'blue': '#4898de',
           'purple': '#a7a3e0',
           'fucsia': '#dab4da',
           'pink': '#f4cddb',
           'rosepink': '#ffb7b6',
           'coral': '#ffae75',
           'orange': '#f7b819'}



def _load_urls(name: str, netloc: str, local: bool):
    netloc = netloc or (LOCAL_NETLOC if local else DEFAULT_NETLOC[name])
    urls = Path(f"urls/{name}.txt").read_text().split()
    urls = [urlunsplit(urlsplit(url)._replace(scheme="https", netloc=netloc))
            for url in urls]
    return urls


@task
def neqo_request(conn, name, netloc=None, local=False, shaping=True, log=False):
    """Request the URLs associated with a domain.

    Use the default local netloc by passing specifying local as true.

    The argument netloc is an optional network locality such as
    localhost:443 that replaces the default.
    """
    urls = ' '.join(_load_urls(name, netloc, local))

    client_binary = {
        "linux": "../target/debug/neqo-client",
        "darwin": ("docker exec -w $PWD -e LD_LIBRARY_PATH=$PWD/../target"
                   "/debug/build/neqo-crypto-044e50838ff4228a/out/dist/Debug"
                   "/lib/ -e SSLKEYLOGFILE=out.log")
                   + (" -e RUST_LOG=")+(NEQO_LOG if log else "")
                   + (" -e CSDEF_NO_SHAPING=")+("" if shaping else "yes")
                   + (" neqo-qcd ../target/debug/neqo-client")
    }[platform]


    conn.run(f"{client_binary} {urls}", echo=True, env={
        "SSLKEYLOGFILE": "out.log",
        "RUST_LOG": NEQO_LOG if log else "",
        "CSDEF_NO_SHAPING": "" if shaping else "yes"
    })



@contextmanager
def capture(
    conn,
    out_pcap: str,
    interface: Optional[str] = "lo" if platform=="linux" else "lo0",
    filter_: str = "port 7443"
):
    """Create a context manager for capturing a trace with tshark.
    """
    iface_flag = ("" if platform=="linux" else f"-i en2") if interface is None else f"-i {interface}"
    promise = conn.run(
        f"tshark {iface_flag} -f '{filter_}' -w '{out_pcap}'",
        asynchronous=True, echo=True)
    time.sleep(3)

    try:
        yield promise
    finally:
        os.kill(promise.runner.process.pid, signal.SIGTERM)
        promise.join()


@task
def collect_quic(conn, name, out_pcap, netloc=None, local=False, shaping=True):
    """Collect a trace of the vanilla template with QUIC, with or without
    shaping.

    Note that when specifying a different netloc, tshark currently only
    captures on port 7443.
    """
    with capture(conn, out_pcap, interface=("lo" if local else None)):
        neqo_request(conn, name, netloc=netloc, local=local, shaping=shaping)


@task
def collect_tcp(conn, name, out_pcap, netloc=None, local=False):
    """Collect a trace of the vanilla template with TCP.

    Note that when specifying a different netloc, tshark currently only
    captures on port 7443.
    """
    with capture(conn, out_pcap, interface=("lo" if local else None)):
        urls = ' '.join(_load_urls(name, netloc, local))
        conn.run(f"curl --insecure --silent --show-error {urls}",
                 hide="stdout", echo=True)


@task
def list_urls(conn, in_har):
    """List the URLs present the .har archive with an HTTP status code
    of 200.
    """
    conn.run("jq -r '.log.entries | map(select(.response.status == 200) "
             f"| .request.url)[]' {in_har}", echo=False)


@task
def start_local_server(conn):
    """Start the local test server.
    """
    args = {
        "linux": "--net host",
        "darwin": ("-p 80:80 -p 443:443/udp -p 443:443/tcp -p 7443:7443/udp "
                   "-p 7443:7443/tcp")
    }[platform]
    conn.run(f"docker run -d --rm --name vanilla {args} vanilla-srv", echo=True)

#####################################

def parse_data(ctx, pcapfile):
    """extract useful informations from the PCAP
        Returns a pandas dataframe
    """
    # print("Parsing pcap.")
    result = ctx.run(
        f"tshark -r {pcapfile} -Tfields -E separator='%' "
        "-e frame.time_epoch -e frame.len -e udp.srcport -e quic.stream.stream_id -e quic.frame_type",
        hide="stdout")

    csv = StringIO(result.stdout)
    data = pd.read_csv(
        csv, header=None, names=["timestamp", "size", "udp.port", "quic.stream_id", "quic.frame_type"], sep='%')
    assert not (data["size"] > 1600).any()

    # Zero the timestamps
    data = data.sort_values(by="timestamp")
    data["timestamp"] -= data.loc[0, "timestamp"]

    return data

def parse_unshaped(ctx, pcapfile):
    """Parse a trace for a capture with CSDEF_NO_SHAPING
    """
    result = ctx.run(
        f"tshark -r {pcapfile} -Tfields -E separator=',' "
        "-e frame.time_epoch -e frame.len -e udp.srcport",
        hide="stdout")

    csv = StringIO(result.stdout)
    data = pd.read_csv(
        csv, header=None, names=["timestamp", "size", "udp.port"])
    assert not (data["size"] > 1600).any()

    # Zero the timestamps
    data = data.sort_values(by="timestamp")
    data["timestamp"] -= data.loc[0, "timestamp"]

    return data

def plot_server_dummy(data_rx, ax):
    """ Plots the dummy packets from the server (RX) side
    """
    # print("plot server dummy")
    dummy_mask = data_rx["quic.stream_id"].isin(DUMMYSTREAMS)
    data_dummy = data_rx.loc[dummy_mask]
    # data_dummy["size"] = data_dummy["size"].abs()
    data_rx_filtered = data_rx.drop(data_dummy.index)
    # data_rx_filtered["size"] = data_rx_filtered["size"].abs()

    binned = make_binned(data_dummy, RATE, keepZeros=True)
    binned_rx = make_binned(data_rx_filtered, RATE, keepZeros=True)

    # plot only dummy
    ax[0].bar(binned["bins"], binned["size"], width=0.04, color=PALETTE["orange"])

    # plot data+dummy

    # set the bottoms for multiple bars
    dim = max(len(binned_rx), len(binned))
    bottoms = np.zeros(dim)
    bottoms[:len(binned)] = binned_rx["size"]
    ax[1].bar(binned_rx["bins"], binned_rx["size"], width=0.04, color=PALETTE["blue"])
    ax[1].bar(binned["bins"], binned["size"], width=0.04, bottom=bottoms, color=PALETTE["orange"])


    return ax

def plot_client_dummy(data_tx, ax):
    """ Plot dummy 
    """
    # print("plot client dummy")
    # TODO get also padding in other packets with regex (\W(0)\W)|(\A0)|(\W0\Z)
    pad_mask = data_tx["quic.frame_type"] == '0'
    data_pad = data_tx.loc[pad_mask]
    data_tx_filtered = data_tx.drop(data_pad.index)

    binned = make_binned(data_pad, RATE, keepZeros=True)
    binned_tx = make_binned(data_tx_filtered, RATE, keepZeros=True)

    # plot dummy
    ax[0].bar(binned["bins"], binned["size"], width=0.04, color=PALETTE["rosepink"])

    # plot data+dummy
    # set the bottoms for multiple bars
    dim = max(len(binned_tx), len(binned))
    bottoms = np.zeros(dim)
    bottoms[:len(binned_tx)] = binned_tx["size"]
    ax[1].bar(binned_tx["bins"], binned_tx["size"], width=0.04, color=PALETTE["blue"], label="Normal packets")
    ax[1].bar(binned["bins"], binned["size"], width=0.04, bottom=bottoms, color=PALETTE["rosepink"], label="Dummy packets")


    return ax

def plot_unshaped(data, ax):
    # Set the direction
    outgoing_mask = (data[["udp.port"]]
                     .isin(SERVER_PORTS).any(axis=1))
    data["dir"] = 1
    data.loc[outgoing_mask, "dir"] = -1

    # Create signed packet sizes
    data["size"] *= data["dir"]

    data_rx = data.loc[outgoing_mask]
    data_tx = data.loc[~outgoing_mask]

    binned_tx = make_binned(data_tx, RATE)
    binned_rx = make_binned(data_rx, RATE)

    ax[2].bar(binned_tx["bins"], binned_tx["size"], width=0.04, color=PALETTE["blue"])
    ax[2].bar(binned_rx["bins"], binned_rx["size"], width=0.04, color=PALETTE["blue"])

    return ax

def make_binned(data, rate, keepZeros=False): 
    binned = data.copy()
    bins = np.arange(0, np.ceil(binned["timestamp"].max()), rate) 
    binned["bins"] =  pd.cut(binned["timestamp"], bins=bins, right=False, labels=bins[:-1]) 
    binned = binned.groupby("bins")["size"].sum() 
    if keepZeros:
        binned = binned.reset_index()
    else:
        binned = binned[binned != 0].reset_index()
    return binned

@task
def plot_dummy(ctx, pcapfile, pcapfile_unshaped):
    """Plots the dummy traffic from a PCAP trace
    """

    data = parse_data(ctx, pcapfile)
    data_unshaped = parse_unshaped(ctx, pcapfile_unshaped)
    # print("filtering rx and tx traffic")
    # Set the direction
    outgoing_mask = (data[["udp.port"]]
                     .isin(SERVER_PORTS).any(axis=1))
    data["dir"] = 1
    data.loc[outgoing_mask, "dir"] = -1

    # Create signed packet sizes
    data["size"] *= data["dir"]

    data_rx = data.loc[outgoing_mask]
    data_tx = data.loc[~outgoing_mask]

    # Prepare the graph
    fig, ax = plt.subplots(3, 1, sharex=True, sharey=False)
    ax[0].set_title("Dummy Trace")
    ax[0].set_facecolor('0.85')
    ax[0].grid(color='w', linewidth=1)
    ax[0].set_axisbelow(True)
    ax[0].hlines(0.0, -0.1, data_unshaped["timestamp"].max(), linewidth=1, color='w')
    ax[0].set_ylabel("Bytes")

    ax[1].set_title("Trace with dummy packets")
    ax[1].set_facecolor('0.85')
    ax[1].grid(color='w', linewidth=1)
    ax[1].set_axisbelow(True)
    ax[1].hlines(0.0, -0.1, data["timestamp"].max(), linewidth=1, color='w')
    ax[1].set_ylabel("Bytes")

    ax[2].set_title("Unshaped Trace")
    ax[2].set_facecolor('0.85')
    ax[2].grid(color='w', linewidth=1)
    ax[2].set_axisbelow(True)
    ax[2].hlines(0.0, -0.1, data_unshaped["timestamp"].max(), linewidth=1, color='w')
    ax[2].set_xlabel("Time [seconds]")
    ax[2].set_ylabel("Bytes")
    # plots server
    plot_server_dummy(data_rx, ax)
    # plot client
    plot_client_dummy(data_tx, ax)
    # plot unshaped
    plot_unshaped(data_unshaped, ax)

    # Plot the graph
    plt.show()
