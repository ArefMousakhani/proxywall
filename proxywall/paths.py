"""Filesystem locations. Every path can be overridden through the environment,
which is how the test-suite and development mode run without touching /var or /run."""

import os

STATE_DIR = os.environ.get("PROXYWALL_STATE_DIR", "/var/lib/proxywall")
RUNTIME_DIR = os.environ.get("PROXYWALL_RUNTIME_DIR", "/run/proxywall")

CONFIG_FILE = os.path.join(STATE_DIR, "config.json")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
FAKEIP_FILE = os.path.join(STATE_DIR, "fakeip.json")
BOOT_RULES_FILE = os.path.join(STATE_DIR, "boot.nft")

SOCKET_PATH = os.environ.get("PROXYWALL_SOCKET", os.path.join(RUNTIME_DIR, "control.sock"))
