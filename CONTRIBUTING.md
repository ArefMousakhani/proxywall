# Contributing

Thanks for helping. The project is small on purpose: Python standard library
only (plus PyGObject for the interface), one event loop, one nftables table.

## Getting started

```sh
git clone https://github.com/ArefMousakhani/proxywall.git
cd proxywall
make test          # ~10 s, no privileges
make integration   # ~45 s, real nftables rules inside private namespaces, no root
```

Needed on the machine: Python ≥ 3.10, `nftables`, `iproute2`, `util-linux`
(`unshare`, `setpriv`), and `python3-gi` with GTK 3 for the interface.

`make integration` needs unprivileged user namespaces. On Ubuntu 24.04 and
later that may require
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

## Working on the interface

```sh
make run-dev
```

starts the service with `PROXYWALL_FIREWALL=none` (no privileges, nothing is
captured or blocked) and opens the window against it. `make screenshots`
renders every state to `docs/images/` without opening a window.

`proxywall/geodata.py` (country table, map grid) and `data/flags/` are generated:
see the headers of `tools/gen_geodata.py` and `tools/gen_flags.py`.

## Rules of the house

- **Fail closed.** No change may add a path where traffic leaves directly
  because something went wrong. If you touch `firewall.py`, `daemon.py` or
  `tproxy.py`, add or extend a test in `tests/integration/test_netns.py` that
  proves it.
- **No new runtime dependencies** without a very good reason.
- Python 3.10 compatible, 120 columns, no formatter wars.
- User-facing text is plain language: say what happened and what to do.
- Update `CHANGELOG.md` and the docs with the change.

## Layout

See the source map at the end of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Releasing

1. Bump `__version__` in `proxywall/__init__.py` and add a `CHANGELOG.md` entry.
2. `make test integration deb`
3. Tag `vX.Y.Z` and push the tag. The *Release* workflow builds the package and attaches it to a GitHub release.
