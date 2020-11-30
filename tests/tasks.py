"""Tasks for performing captures, with and without shaping.
"""
# pylint: disable=too-many-arguments
import os
import time
import signal
from contextlib import contextmanager
from sys import platform
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Optional

from invoke import task


LOCAL_NETLOC = "{}:7443".format(
    "localhost" if platform == "linux" else "host.docker.internal")
DEFAULT_NETLOC = {
    "vanilla": "vanilla.neqo-test.com:7443",
    "weather": "weather.neqo-test.com:7443",
}


def _load_urls(name: str, netloc: str, local: bool):
    netloc = netloc or (LOCAL_NETLOC if local else DEFAULT_NETLOC[name])
    urls = Path(f"urls/{name}.txt").read_text().split()
    urls = [urlunsplit(urlsplit(url)._replace(scheme="https", netloc=netloc))
            for url in urls]
    return urls


@task
def neqo_request(conn, name, netloc=None, local=False, shaping=True):
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
                   "/lib/ neqo-qcd ../target/debug/neqo-client")
    }[platform]

    conn.run(f"{client_binary} {urls}", echo=True, env={
        "SSLKEYLOGFILE": "out.log",
        "CSDEF_NO_SHAPING": "" if shaping else "yes"
    })


@contextmanager
def capture(
    conn,
    out_pcap: str,
    interface: Optional[str] = "lo",
    filter_: str = "port 7443"
):
    """Create a context manager for capturing a trace with tshark.
    """
    iface_flag = "" if interface is None else f"-i {interface}"
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
