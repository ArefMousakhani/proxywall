# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.3.1] - 2026-11-15

### Fixed

- SSH and share-link servers (VLESS, VMess, Trojan, Shadowsocks) did not connect on machines where another firewall rewrites packet marks on incoming traffic, as VPN clients do: ProxyWall's own rule refused the service's connection to its helper, so the server showed "the tunnel is starting" and tests ended with "the helper did not start". The rule that keeps other programs away from the helper's local port is now applied where connections leave a program, like the kill switch itself.
- That rule no longer resets the answer to an unrelated local connection whose own port happened to fall in the helper range.

## [1.3.0] - 2026-11-15

### Added

- A list of saved servers: add as many as you like, paste several links at once, click the one to use, switch while connected. `proxywall server list|add|use|remove|test` does the same from a terminal.
- Server tests: ping to the server, exit country, and whether a small page (`test_url`, Google's by default) can be fetched through it. Tests use the service's own connections, work behind the kill switch, and do not fetch the page through an exit in a blocked country.
- Internet latency while connected, next to the latency to the server (one small request every 30 seconds).

### Changed

- The window is larger and has two panes: the connection on the left, servers and settings on the right. It can be resized.
- An existing configuration is kept: its proxy becomes the first server in the list.

## [1.2.0] - 2026-11-14

### Added

- SSH tunnels as the way out (password or private key), through the system's OpenSSH client. The server's host key is pinned on first use.
- VLESS, VMess, Trojan and Shadowsocks servers from a share link, through Xray: TLS, REALITY, XTLS-Vision, WebSocket, gRPC, HTTPUpgrade, XHTTP, Shadowsocks AEAD and 2022.
- The settings window has four kinds of server: SOCKS5, HTTP, SSH and LINK. `proxywall set-proxy` accepts the same links and `ssh://`, with `--key` for a private key.
- New settings `proxy.link`, `proxy.private_key`, `engine_path`, `engine_port`.

The firewall, bypass list and blocked countries apply to these servers unchanged: the helper process is reached only by the service, and its connection to the server is the only one the firewall lets out.

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

[1.3.1]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.3.1
[1.3.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.3.0
[1.2.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.2.0
[1.1.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.1.0
[1.0.0]: https://github.com/ArefMousakhani/proxywall/releases/tag/v1.0.0
