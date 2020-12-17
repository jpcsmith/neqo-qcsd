"""Methods for extracting URL dependencies."""
import json
import itertools
from pathlib import Path
from typing import Sequence, Tuple, Union


def _extract_from_har_entry(entry):
    dependencies = set()

    if "url" in entry["_initiator"]:
        dependencies.add(entry["_initiator"]["url"])

    if "stack" in entry["_initiator"]:
        for frame in entry["_initiator"]["stack"]["callFrames"]:
            dependencies.add(frame["url"])

    for header in entry["request"]["headers"]:
        if header["name"] == "referer":
            dependencies.add(header["value"])
            break

    if not dependencies:
        return [(entry["request"]["url"], "")]
    return [(entry["request"]["url"], dep) for dep in dependencies]


def extract_from_har(har: Union[str, dict]) -> Sequence[Tuple[str, str]]:
    """Extract a URL dependency graph from HAR logs.

    Return a sequence of edges (target, dependency).  The `har`
    argument can either be a file path or the json-decoded HAR.
    """
    if isinstance(har, str):
        har = json.loads(Path(har).read_text())
        assert isinstance(har, dict)

    entries = [_extract_from_har_entry(e) for e in har["log"]["entries"]
               if e["response"]["status"] == 200]

    return list(set(itertools.chain.from_iterable(entries)))
