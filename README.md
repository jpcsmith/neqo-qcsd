# Neqo-QCSD, a fork of Neqo with the QCSD

This repository contains the the QCSD library and source code associated with the paper "QCSD: A QUIC Client-Side Website-Fingerprinting Defence Framework" (USENIX Security 2022). It is built upon Mozilla's QUIC-HTTP/3 library "Neqo". The primary changes to the repository are as follows:

- `neqo-csdef`. The `neqo-csdef` crate contains the library code for orchestrating defences on the connection with QCSD. Code has been added to the `neqo-http3` and `neqo-transport` crates to utilise QCSD.
- `neqo-client` and `neqo-client-mp`. These crates contain modified version of the original `neqo-client` test client, and enable downloading URLs while enacting live defences. 

The code for running the experiments and futher details can be found at https://github.com/jpcsmith/qcsd-experiments.

The code in this repository has been tested on a fresh installation of Ubuntu 20.04 with rust version 1.51. Additionally, building the binary requires the following dependencies `build-essential mercurial gyp ninja-build libz-dev clang`, which can be installed with apt.
The file cargo lock file `Cargo.lock` details a known working configuration of dependent rust packages, and is used by cargo to build the binaries.


The contents of the original README are provided below.

---
# Neqo, an Implementation of QUIC written in Rust

![neqo logo](https://github.com/mozilla/neqo/raw/main/neqo.png "neqo logo")

To run test HTTP/3 programs (neqo-client and neqo-server):

* `cargo build`
* `./target/debug/neqo-server [::]:12345 --db ./test-fixture/db`
* `./target/debug/neqo-client http://127.0.0.1:12345/`

## Faster Builds with Separate NSS/NSPR

You can clone NSS (https://hg.mozilla.org/projects/nss) and NSPR
(https://hg.mozilla.org/projects/nspr) into the same directory and export an
environment variable called `NSS_DIR` pointing to NSS.  This causes the build to
use the existing NSS checkout.  However, in order to run anything that depends
on NSS, you need to set `$\[DY]LD\_LIBRARY\_PATH` to point to
`$NSS_DIR/../dist/Debug/lib`.

Note: If you did not compile NSS separately, you need to have mercurial (hg), installed.
NSS builds require gyp, and ninja (or ninja-build) to be present also.

## Debugging Neqo

### Using SSLKEYLOGFILE to decrypt Wireshark logs

[Info here](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)

TODO: What is the minimum Wireshark version needed?
TODO: Above link may be incorrect, protocol now called TLS instead of SSL?

### Using RUST_LOG effectively

As documented in the [env_logger documentation](https://docs.rs/env_logger/),
the `RUST_LOG` environment variable can be used to selectively enable log messages
from Rust code. This works for Neqo's cmdline tools, as well as for when Neqo is
incorporated into Gecko, although [Gecko needs to be built in debug mode](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Configuring_Build_Options).

Some examples:
1. `RUST_LOG=neqo_transport::dump ./mach run` lists sent and received QUIC
   packets and their frames' contents only.
1. `RUST_LOG=neqo_transport=debug,neqo_http3=trace,info ./mach run` sets a
   'debug' log level for transport, 'trace' level for http3, and 'info' log
   level for all other Rust crates, both Neqo and others used by Gecko.
1. `RUST_LOG=neqo=trace,error ./mach run` sets `trace` level for all modules
   starting with "neqo", and sets `error` as minimum log level for other
   unrelated Rust log messages.


### Trying In-development Neqo code in Gecko

In a checked-out copy of Gecko source, set paths for the four Neqo crates to
local versions in `netwerk/socket/neqo_glue/Cargo.toml`. For example, if Neqo
was checked out to /home/alice/git/neqo, change:

```
neqo-http3 = { tag = "v0.1.7", git = "https://github.com/mozilla/neqo" }
neqo-transport = { tag = "v0.1.7", git = "https://github.com/mozilla/neqo" }
neqo-common = { tag = "v0.1.7", git = "https://github.com/mozilla/neqo" }
```

to

```
neqo-http3 = { path = "/home/alice/git/neqo/neqo-http3" }
neqo-transport = { path = "/home/alice/git/neqo/neqo-transport" }
neqo-common = { path = "/home/alice/git/neqo/neqo-common" }
```

and

```
[dependencies.neqo-crypto]
tag = "v0.1.7"
git = "https://github.com/mozilla/neqo"
default-features = false
features = ["gecko"]
```

to

```
[dependencies.neqo-crypto]
path = "/home/alice/git/neqo/neqo-crypto"
default-features = false
features = ["gecko"]
```

Note: Using newer Neqo code with Gecko may also require changes (likely to `neqo_glue`) if
something has changed.

Compile Gecko as usual with `./mach build`.
