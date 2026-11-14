PYTHON ?= python3
DEV_DIR ?= $(CURDIR)/.dev

.PHONY: test integration deb run-dev screenshots clean

test:
	$(PYTHON) -m unittest tests.test_units tests.test_daemon

integration:
	tests/integration/run.sh

deb:
	packaging/build-deb.sh

# Service without a firewall (no privileges needed) plus the window, for UI work.
run-dev:
	@mkdir -p $(DEV_DIR)
	@PROXYWALL_FIREWALL=none PROXYWALL_STATE_DIR=$(DEV_DIR)/state PROXYWALL_RUNTIME_DIR=$(DEV_DIR)/run \
		$(PYTHON) -m proxywall.daemon & pid=$$!; \
	trap 'kill $$pid' EXIT INT TERM; sleep 1; \
	PROXYWALL_SOCKET=$(DEV_DIR)/run/control.sock $(PYTHON) -m proxywall.gui

screenshots:
	$(PYTHON) tools/screenshots.py docs/images

clean:
	rm -rf dist $(DEV_DIR)
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
