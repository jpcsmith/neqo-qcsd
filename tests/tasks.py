"""Tasks for performing captures, with and without shaping.
"""
import os
import time
import signal
from contextlib import contextmanager

from invoke import task


URLS = {
    "vanilla": [
        "https://localhost:7443" + path for path in (
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
        conn.run(f"../target/debug/neqo-client {urls}", echo=True, env={
            "SSLKEYLOGFILE": "out.log",
            "CSDEF_NO_SHAPING": "" if shaping else "yes"
        })


@task
def collect_tcp(conn, out_pcap):
    """Collect a trace of the vanilla template with TCP.
    """
    with capture(conn, out_pcap):
        urls = ' '.join(URLS["vanilla"])
        conn.run(f"curl --insecure --silent --show-error {urls}",
                 hide="stdout", echo=True)
