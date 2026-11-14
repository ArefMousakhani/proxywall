# ProxyWall: system-wide SOCKS5 / HTTP proxy client for Linux with a kill switch

[![Latest release](https://img.shields.io/github/v/release/ArefMousakhani/proxywall?label=release)](https://github.com/ArefMousakhani/proxywall/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)

**English** | [فارسی](README.fa.md)

**Send all traffic of your Linux desktop through a SOCKS5 or HTTP proxy, and never go online without it.**

ProxyWall turns a plain proxy (`192.168.1.5:1080`, a proxy shared from your phone, an SSH tunnel, a V2Ray / Xray / sing-box / Shadowsocks local port, a corporate HTTP proxy…) into something that behaves like an always-on VPN client: every application is captured, DNS cannot leak, and a firewall kill switch keeps the machine closed whenever the proxy is unreachable. There is no "fall back to a direct connection".

<p align="center">
  <img src="docs/images/connected.png" width="240" alt="ProxyWall connected: all traffic goes through the SOCKS5 proxy">
  <img src="docs/images/unreachable.png" width="240" alt="ProxyWall kill switch: proxy unreachable, traffic is blocked">
  <img src="docs/images/settings.png" width="240" alt="ProxyWall settings: proxy address and bypass list">
</p>

## The problem it solves

You have a proxy, not a VPN, and you want the *whole computer* to use it:

- The desktop's "network proxy" setting is ignored by many programs (terminals, package managers, games, Electron apps, anything written in Go).
- Setting `http_proxy` or using `proxychains` works one command at a time and misses everything else.
- When the proxy drops, applications silently reconnect **directly**, exposing your real IP address.
- DNS lookups still go to your local resolver, so the names you visit leak, and on networks with tampered DNS you get wrong answers.
- Some sites (local or domestic ones) should **not** go through the proxy at all.

ProxyWall fixes all five with one switch.

| | System-wide | Kill switch | DNS through the proxy | Bypass list by domain | Desktop app |
| --- | :---: | :---: | :---: | :---: | :---: |
| Desktop proxy settings | partly | no | depends on the app | yes | yes |
| `proxychains` | per command | no | yes | addresses only | no |
| `redsocks` + hand-written iptables | yes | manual | manual | no | no |
| `tun2socks` + manual routing | yes | manual | manual | no | no |
| **ProxyWall** | **yes** | **yes, fail-closed** | **yes** | **yes** | **yes** |

## Features

- **System-wide.** No per-application proxy settings. Browsers, terminals, package managers, containers: everything that uses TCP goes through the proxy.
- **Fail-closed firewall (kill switch).** If the proxy dies, the Wi-Fi changes, or ProxyWall itself crashes, traffic is rejected. It is never rerouted directly.
- **Always-on mode.** With the *Firewall* switch on, the internet stays blocked while you are disconnected, including right after a reboot, before you log in.
- **No DNS leaks.** Applications never learn real addresses for proxied sites; host names are resolved by the proxy.
- **Exclusion list (split tunnelling).** Domains (`*.ir`, `example.com`), single addresses and networks (`10.1.0.0/16`) that should bypass the proxy.
- **SOCKS5 and HTTP CONNECT** proxies, with optional username and password.
- **Small and auditable.** Pure Python standard library plus `nftables`; no bundled binaries. The privileged service runs with a single capability inside a systemd sandbox.
- **Desktop app, tray icon and CLI.**

## Install

Requirements: a systemd-based distribution with Python ≥ 3.10, `nftables` and GTK 3. Developed and tested on Linux Mint 22 (Ubuntu 24.04 base). Debian 12 and Ubuntu 22.04 meet the same requirements but have not been tested yet.

**From a release (Debian, Ubuntu, Linux Mint):** download `proxywall_<version>_all.deb` from the [latest release](https://github.com/ArefMousakhani/proxywall/releases/latest), then

```sh
sudo apt install ./proxywall_1.0.0_all.deb
```

**From source:**

```sh
git clone https://github.com/ArefMousakhani/proxywall.git
cd proxywall
make deb
sudo apt install ./dist/proxywall_1.0.0_all.deb
```

`apt` pulls in the few dependencies (`python3-gi`, `nftables`, …), starts the `proxywall` service and adds **ProxyWall** to the application menu (*Internet* category).

## Use

1. Open **ProxyWall** from the menu.
2. Click the gear, enter the proxy (type, address, port, and credentials if it needs them) and **Save**. You can also paste a whole URL such as `socks5://user:pass@192.168.1.5:1080` into the address box.
3. Press the big power button.

| The window says | Meaning |
| --- | --- |
| **CONNECTED** (green) | Everything goes through the proxy. |
| **CONNECTING** (amber) | Waiting for the proxy to answer. Traffic is already blocked from going out directly. |
| **NO PROXY** (red) | The proxy cannot be reached. Traffic is blocked until it is back; ProxyWall keeps retrying every few seconds. |
| **BLOCKED** (red) | You are disconnected and the *Firewall* switch is on: nothing leaves the machine. |
| **OFF** (grey) | Disconnected, firewall off: normal direct networking. |

Closing the window does not disconnect anything. The connection belongs to a system service; the window and the tray icon are only a remote control.

### The Firewall switch

While you are connected the firewall is **always** active; that is what guarantees that nothing bypasses the proxy. The switch decides what happens when you are *not* connected:

| Firewall switch | Connected | Disconnected | After a reboot |
| --- | --- | --- | --- |
| **Off** | proxy only | direct internet | restores the last state |
| **On** | proxy only | internet blocked | internet blocked until connected |

### Exclusions (bypass list)

In *Settings → Bypass the proxy*, one entry per line:

| Entry | Matches |
| --- | --- |
| `*.ir` | every domain ending in `.ir` |
| `example.com` | `example.com` and all of its subdomains |
| `192.0.2.10` | one address |
| `10.1.0.0/16`, `2001:db8::/32` | a network |

Excluded destinations always go out directly, also while the firewall is blocking everything else. *Allow local network* does the same for private address ranges (your router, printer, NAS, and usually the proxy itself).

### Command line

```sh
proxywall set-proxy socks5://user:pass@192.168.1.5:1080
proxywall exclude add '*.ir' 10.1.0.0/16
proxywall kill-switch on
proxywall connect
proxywall status
proxywall logs
```

`proxywall --help` lists everything; see [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for every setting.

## How it works

```mermaid
flowchart LR
    app[Any application] -->|DNS query| dns[ProxyWall DNS<br>answers with a placeholder address]
    app -->|TCP connection| nft{nftables}
    nft -->|redirect| relay[ProxyWall relay]
    nft -->|UDP, ICMP, anything else| drop([rejected])
    relay -->|excluded domain or address| direct([direct])
    relay -->|everything else| proxy[SOCKS5 / HTTP proxy]
    relay -.->|proxy unreachable| drop
```

1. **Capture.** One nftables table redirects every new TCP connection, and every DNS query, to the ProxyWall service on the local machine. Traffic forwarded for containers and virtual machines is captured the same way.
2. **Names stay names.** The built-in DNS server answers each lookup instantly with a placeholder address from `198.18.0.0/15`. When the application connects to it, ProxyWall maps it back to the host name and asks the *proxy* to connect to that name. Your local resolver never sees it.
3. **Decide.** Excluded names and addresses are connected directly; everything else is handed to the proxy.
4. **Stay closed.** The same table rejects all traffic that is not the service's own, local, or excluded. The rules do not depend on the proxy being healthy or on the service being alive, so a failure of either leaves nothing but a closed door.

More detail, including the exact rule set, is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Limitations

Read these before relying on ProxyWall:

- **TCP and DNS only.** SOCKS5 UDP relaying is not implemented and HTTP proxies cannot carry UDP. While the firewall is active, other UDP (QUIC/HTTP3, most VoIP and games) and ping are *rejected*, not tunnelled. Browsers fall back to TCP automatically.
- **A proxy is not encryption.** ProxyWall guarantees that traffic goes to your proxy or nowhere. Whether the hop to the proxy is encrypted depends on the proxy; plain SOCKS5 and HTTP proxies are not.
- **HTTP proxies must allow `CONNECT` to the ports you use.** Many only allow 443. SOCKS5 is the better choice when you have one.
- **A proxy running on this same computer** (for example a local tunnel client listening on `127.0.0.1`) must be able to reach its own server: add that server's address to the bypass list, otherwise its traffic is captured too and loops.
- **Do not run it together with another VPN client's firewall.** Two kill switches will block each other.
- **Excluded domains are matched by name.** An application that resolves names itself (DNS-over-HTTPS in a browser) is still proxied and still cannot leak; for HTTPS and HTTP, exclusions keep working because ProxyWall reads the host name from the connection. For other protocols such an application's excluded domains go through the proxy.
- Just after disconnecting, applications may hold placeholder addresses for a second or two; a retry fixes it.

## FAQ

**How do I use a SOCKS5 proxy for the whole system on Linux?**
Install ProxyWall, enter the proxy address and press connect. Every program is captured by the firewall; nothing has to be configured per application.

**Does it work with V2Ray, Xray, sing-box, Shadowsocks, or `ssh -D`?**
Yes. Anything that offers a SOCKS5 or HTTP proxy port works. If that client runs on the *same* computer, add its remote server's IP address to the bypass list (see [Limitations](#limitations)).

**Is ProxyWall a VPN?**
No. It does not encrypt anything by itself and it carries TCP and DNS, not all IP traffic. It gives a proxy the two things people usually want from a VPN client: system-wide capture and a kill switch.

**What happens when the proxy goes down?**
Connections fail immediately and stay blocked until the proxy answers again. Traffic is never sent directly.

**Can some sites skip the proxy?**
Yes: add domains (`*.ir`), addresses or networks to the bypass list.

**Does it work on GNOME, KDE, Wayland?**
The service and the command line work everywhere. The window is GTK 3 and runs on any desktop; the tray icon needs XApp (Cinnamon, MATE, Xfce) or AppIndicator support.

## Security model

- The service (`proxywalld`) runs as root with **only `CAP_NET_ADMIN`**, under systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, system-call filter, no access to `/home`).
- It is controlled over a Unix socket. Root and regular login accounts may use it; system and service accounts may not. See [SECURITY.md](SECURITY.md).
- The proxy password is stored in `/var/lib/proxywall/config.json`, readable by root only, and is never sent back to the interface.
- The public IP shown in the window is fetched through the proxy from `https://www.cloudflare.com/cdn-cgi/trace`. Set `ip_check_url` to an empty value to turn that off.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| The window says **SERVICE STOPPED** | `sudo systemctl start proxywall`, then `journalctl -u proxywall -e` if it does not stay up |
| **NO PROXY** | Check address, port and type; the reason is printed under the status and in `proxywall logs` |
| I am locked out and need the internet now | `sudo proxywall reset-firewall` |
| One site must not use the proxy | add it to the bypass list |

More in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Development

```sh
make test          # unit tests + service tests (no privileges)
make integration   # end-to-end tests with real nftables rules, in private namespaces (no root)
make run-dev       # service without a firewall + GUI, for working on the interface
make deb           # dist/proxywall_<version>_all.deb
```

The integration suite builds a small "internet" out of network namespaces and proves, among other things, that traffic is blocked rather than leaked when the proxy or the service is killed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Uninstall

```sh
sudo apt remove proxywall     # stops the service and removes the firewall
sudo apt purge proxywall      # also deletes the saved settings
```

## License

[MIT](LICENSE)
