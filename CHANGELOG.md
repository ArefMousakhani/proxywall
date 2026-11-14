# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-14

### Added

- Blocked countries: choose countries (list with flags in the settings, or `proxywall block-country`) that your traffic must never come out in. Proxied connections are held until the exit country has been checked, and refused, with open ones cut, while it is on the list or cannot be established. New settings `blocked_countries` and `country_check_seconds`, new states `country_blocked` and `checking`.
- The window shows where your traffic comes out: country flag, city, a small world map and the coordinates.
- The tray icon becomes the flag of that country, in a green frame, while connected (red frame when the country is blocked).
- `proxywall status` prints the location; the status reply carries `country_name`, `city`, `latitude`, `longitude` and `location_exact`.
- New setting `geo_url` (default `https://ipwho.is/`), asked through the proxy for the city and coordinates of the public IP. When it is empty or the service does not answer, the capital of the country is shown instead, from a table shipped with the package.

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

[1.1.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.1.0
[1.0.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.0.0
