#!/bin/sh
# Runs the end-to-end tests in private user/network/mount namespaces.
# No root required; nothing on the real system is touched.
set -eu
cd "$(dirname "$0")/../.."
exec unshare --user --map-root-user --net --mount \
    env PROXYWALL_NETNS_TEST=1 python3 -m unittest -v "$@" tests/integration/test_netns.py
