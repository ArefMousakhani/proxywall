# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-14

First release.

### Added

- System-wide capture of TCP and DNS through a SOCKS5 or HTTP CONNECT proxy, with optional username/password.
- Fail-closed nftables firewall: traffic is rejected, never sent directly, when the proxy or the service is down.
- Always-on kill switch that also holds while disconnected and from early boot.
- Built-in DNS server with placeholder addresses, so proxied host names never reach the local resolver.
- Exclusion list for domains, addresses and networks; *Allow local network* option.
- Capture of forwarded traffic (containers, virtual machines).
- GTK 3 desktop interface with tray icon, `proxywall` command line tool.
- Debian package with a sandboxed systemd service.

[1.0.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.0.0
