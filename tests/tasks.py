"""Tasks for performing captures, with and without shaping.
"""
import os
import time
import signal
from contextlib import contextmanager

from io import StringIO
import pandas as pd
import numpy as np
from matplotlib import pyplot as plt

from invoke import task
# determine OS
from sys import platform


HOSTNAME = "https://localhost:7443" if platform == "linux" else "https://host.docker.internal:7443"

URLS = {
    "vanilla": [
        HOSTNAME + path for path in (
            "/", "/css/bootstrap.min.css", "/css/fontAwesome.css",
            "/css/hero-slider.css", "/css/templatemo-main.css",
            "/css/owl-carousel.css",
            "/js/vendor/modernizr-2.8.3-respond-1.4.2.min.js",
            "/img/1st-item.jpg", "/img/2nd-item.jpg", "/img/3rd-item.jpg",
            "/img/4th-item.jpg", "/img/5th-item.jpg", "/img/6th-item.jpg",
            "/img/1st-tab.jpg", "/img/2nd-tab.jpg", "/img/3rd-tab.jpg",
            "/img/4th-tab.jpg", "/js/vendor/bootstrap.min.js", "/js/plugins.js",
            "/js/main.js", "/img/1st-section.jpg", "/img/2nd-section.jpg",
            "/img/3rd-section.jpg", "/img/4th-section.jpg",
            "/img/5th-section.jpg", "/fonts/fontawesome-webfont.woff2?v=4.7.0",
            "/img/prev.png", "/img/next.png", "/img/loading.gif",
            "/img/close.png"
        )
    ]

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



@contextmanager
def capture(
    conn, out_pcap: str, interface: str = "lo", filter_: str = "port 7443"
):
    """Create a context manager for capturing a trace with tshark.
    """
    promise = conn.run(
        f"tshark -i {interface} -f '{filter_}' -w '{out_pcap}'",
        asynchronous=True, echo=True)
    time.sleep(3)

    try:
        yield promise
    finally:
        os.kill(promise.runner.process.pid, signal.SIGTERM)
        promise.join()


@task
def collect_quic(conn, out_pcap, shaping=True):
    """Collect a trace of the vanilla template with QUIC, with or without
    shaping.
    """
    with capture(conn, out_pcap):
        urls = ' '.join(URLS["vanilla"])
        if platform == "linux":
            conn.run(f"../target/debug/neqo-client {urls}", echo=True, env={
                "SSLKEYLOGFILE": "out.log",
                "CSDEF_NO_SHAPING": "" if shaping else "yes"
            })
        elif platform == "darwin":
            conn.run(f"docker exec -w $PWD -e LD_LIBRARY_PATH=$PWD/../target/debug/build/neqo-crypto-044e50838ff4228a/out/dist/Debug/lib/ neqo-qcd ../target/debug/neqo-client {urls}",
                echo=True, env={
                    "SSLKEYLOGFILE": "out.log",
                    "CSDEF_NO_SHAPING": "" if shaping else "yes"
            })
        else:
            raise Exception("OS not supported")
        



@task
def collect_tcp(conn, out_pcap):
    """Collect a trace of the vanilla template with TCP.
    """
    with capture(conn, out_pcap):
        urls = ' '.join(URLS["vanilla"])
        conn.run(f"curl --insecure --silent --show-error {urls}",
                 hide="stdout", echo=True)


#####################################


def parse_data(ctx, pcapfile):
    """extract useful informations from the PCAP
        Returns a pandas dataframe
    """
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

def plot_server_dummy(data_rx, ax):
    """ Plots the dummy packets from the server (RX) side
    """
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
    bottoms = np.zeros(len(binned_rx))
    bottoms[:len(binned)] = binned["size"]
    ax[1].bar(binned["bins"], binned["size"], width=0.04, color=PALETTE["orange"])
    ax[1].bar(binned_rx["bins"], binned_rx["size"], width=0.04, bottom=bottoms, color=PALETTE["blue"])


    return ax

def plot_client_dummy(data_tx, ax):
    """ Plot dummy 
    """
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
    bottoms = np.zeros(len(binned_tx))
    bottoms[:len(binned)] = binned["size"]
    ax[1].bar(binned["bins"], binned["size"], width=0.04, color=PALETTE["rosepink"])
    ax[1].bar(binned_tx["bins"], binned_tx["size"], width=0.04, bottom=bottoms, color=PALETTE["blue"])


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
def plot_dummy(ctx, pcapfile):
    """Plots the dummy traffic from a PCAP trace

    """

    data = parse_data(ctx, pcapfile)

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
    ax[1].set_title("Trace with dummy packets")
    ax[1].set_facecolor('0.85')
    ax[1].grid(color='w', linewidth=1)
    ax[2].set_title("Unshaped Trace")
    ax[2].set_facecolor('0.85')
    ax[2].grid(color='w', linewidth=1)
    # plots server
    plot_server_dummy(data_rx, ax)
    plot_client_dummy(data_tx, ax)
    # Plot the graph
    plt.show()
