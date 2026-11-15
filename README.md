# ProxyWall: system-wide proxy client for Linux with a kill switch (SOCKS5, HTTP, SSH, VLESS, VMess, Trojan, Shadowsocks)

[![Latest release](https://img.shields.io/github/v/release/ArefMousakhani/proxywall?label=release)](https://github.com/ArefMousakhani/proxywall/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)

**English** | [فارسی](README.fa.md)

**Send all traffic of your Linux desktop through a SOCKS5 or HTTP proxy, an SSH server, or a VLESS / VMess / Trojan / Shadowsocks server, and never go online without it.**

ProxyWall turns a plain proxy (`192.168.1.5:1080`, a proxy shared from your phone, an SSH tunnel, a V2Ray / Xray / sing-box / Shadowsocks local port, a corporate HTTP proxy…) into something that behaves like an always-on VPN client: every application is captured, DNS cannot leak, and a firewall kill switch keeps the machine closed whenever the proxy is unreachable. There is no "fall back to a direct connection".

<p align="center">
  <img src="docs/images/connected.png" width="760" alt="ProxyWall connected: status, map of the exit location, and the list of saved servers with ping and internet test results">
</p>
<p align="center">
  <img src="docs/images/country-blocked.png" width="375" alt="ProxyWall blocking all traffic because the server comes out in a blocked country">
  <img src="docs/images/server-link.png" width="375" alt="ProxyWall server form: SOCKS5, HTTP, SSH or a VLESS / VMess / Trojan / Shadowsocks share link">
</p>
<p align="center">
  <img src="docs/images/tray.png" width="190" alt="ProxyWall tray icon: the flag of the country your traffic comes out in, with a green frame">
  <br><sub>While connected, the tray icon is the flag of the country your traffic comes out in.</sub>
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
- **SSH tunnels** (password or private key), using the system's OpenSSH.
- **VLESS, VMess, Trojan and Shadowsocks** servers from a share link (`vless://`, `vmess://`, `trojan://`, `ss://`), including TLS, REALITY, XTLS-Vision, WebSocket, gRPC, HTTPUpgrade and XHTTP, through [Xray](https://github.com/XTLS/Xray-core).
- **Small and auditable.** Pure Python standard library plus `nftables`; no bundled binaries. The privileged service runs with a single capability inside a systemd sandbox.
- **Block exit countries.** Pick the countries your traffic must never come out in. Nothing is sent until the exit has been checked, and if the proxy starts coming out in one of them (or its country cannot be checked), everything is blocked at once.
- **See where you come out.** The window shows the country flag, city, a small world map and the coordinates of your public IP; the tray icon turns into that country's flag while you are connected.
- **Many servers, one click.** Save as many servers as you like (paste a whole list of links at once), click the one to use, and switch while connected.
- **Test before you use.** For every saved server: ping to the server, and whether a small page (Google's by default) can be fetched through it, with the time it took. Nothing is connected or switched by a test.
- **Two latencies while connected:** to the server, and through it to the internet.
- **Desktop app, tray icon and CLI.**

## Install

Requirements: a systemd-based distribution with Python ≥ 3.10, `nftables` and GTK 3. Developed and tested on Linux Mint 22 (Ubuntu 24.04 base). Debian 12 and Ubuntu 22.04 meet the same requirements but have not been tested yet.

**From a release (Debian, Ubuntu, Linux Mint):** download `proxywall_<version>_all.deb` from the [latest release](https://github.com/ArefMousakhani/proxywall/releases/latest), then

```sh
sudo apt install ./proxywall_1.3.1_all.deb
```

**From source:**

```sh
git clone https://github.com/ArefMousakhani/proxywall.git
cd proxywall
make deb
sudo apt install ./dist/proxywall_1.3.1_all.deb
```

`apt` pulls in the few dependencies (`python3-gi`, `nftables`, …), starts the `proxywall` service and adds **ProxyWall** to the application menu (*Internet* category).

## Use

1. Open **ProxyWall** from the menu.
2. Press **Add** (or copy one or more share links and press **Paste links**), choose the kind of server and **Save**:
   - **SOCKS5 / HTTP:** address, port, and credentials if it needs them. You can also paste a whole URL such as `socks5://user:pass@192.168.1.5:1080` into the address box.
   - **SSH:** address, port, user name, and a password or a private key file.
   - **LINK:** paste the `vless://`, `vmess://`, `trojan://` or `ss://` link of your server.
3. Click the server you want in the list, and press the big power button.

### Servers and tests

The right half of the window is the list of saved servers. The one in use has a green dot; clicking another one switches to it, also while connected (connections running through the old server are cut, and nothing goes out directly in between).

**Test all**, or the circular arrow on a row, measures a server without using it:

| Shown | Meaning |
| --- | --- |
| `48 ms` | "ping": the time to open a connection to the server itself |
| `Internet 182 ms` (green) | the round trip *through* the server to a small page (by default `https://www.google.com/generate_204`), timed on an already open connection so that it reflects the line, not the handshakes |
| `No internet` (red) | the server answers, but nothing comes back through it: wrong password or id, or the server has no way out |
| `No answer` (red) | the server itself cannot be reached |
| flag | the country the server comes out in |

Tests are made by the service with its own connections, so they also work while the firewall blocks everything else. If you block countries, a server that comes out in one of them is reported as such and the page is **not** fetched through it.

While you are connected, the left side shows two latencies: *Server latency* (to the proxy) and *Internet* (through it to the test page, measured with a tiny request every 30 seconds, which costs your connection nothing noticeable).

| The window says | Meaning |
| --- | --- |
| **CONNECTED** (green) | Everything goes through the proxy. The map and the flag show where it comes out. |
| **CONNECTING** (amber) | Waiting for the proxy to answer. Traffic is already blocked from going out directly. |
| **NO PROXY** (red) | The proxy cannot be reached. Traffic is blocked until it is back; ProxyWall keeps retrying every few seconds. |
| **COUNTRY BLOCKED** (red) | The proxy comes out in a country you blocked. Nothing is sent through it. |
| **CHECKING** (amber) | Countries are blocked and the exit country is not established yet (or the check fails). Traffic waits. |
| **BLOCKED** (red) | You are disconnected and the *Firewall* switch is on: nothing leaves the machine. |
| **OFF** (grey) | Disconnected, firewall off: normal direct networking. |

Closing the window does not disconnect anything. The connection belongs to a system service; the window and the tray icon are only a remote control.

### Other protocols (SSH, VLESS, VMess, Trojan, Shadowsocks)

ProxyWall speaks SOCKS5 and HTTP itself. For the others it starts a helper next to the service and uses it as its proxy, so the firewall, the bypass list and the blocked countries work exactly the same:

| Server | Helper | What you need |
| --- | --- | --- |
| SSH | `ssh` (OpenSSH client) | already installed on most systems; otherwise `sudo apt install openssh-client` |
| VLESS, VMess, Trojan, Shadowsocks | [Xray](https://github.com/XTLS/Xray-core) | the `xray` program in `/usr/local/bin`, `/usr/bin` or anywhere on the `PATH` ([install instructions](https://github.com/XTLS/Xray-install)); a different place can be set with `proxywall config engine_path=/path/to/xray` |

The helper's own connection to your server is the only thing the firewall lets out, the same way as with a plain proxy. Its local port is closed to every other program.

Supported in share links: TLS, REALITY and XTLS-Vision; raw TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP transports; Shadowsocks AEAD and 2022 ciphers. Not supported: Hysteria, TUIC, WireGuard, NaiveProxy and Shadowsocks plugins (Xray does not speak them), and subscription URLs (paste the links themselves instead).

The first time an SSH server is used, its host key is remembered in `/var/lib/proxywall/known_hosts`; if it later changes, ProxyWall refuses to connect and says so.

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

### Blocked countries

In *Settings → Blocked countries*, tick the countries your traffic must never come out in (for example the country you are in, when the point of the proxy is to appear somewhere else). From then on:

- After connecting, **nothing is handed to the proxy until a check has shown where it comes out**.
- Every new connection needs a check that is at most 5 seconds old. A connection that arrives later waits for a new one.
- When the exit is in a blocked country, the window turns red (**COUNTRY BLOCKED**), open connections through the proxy are cut and new ones are refused. ProxyWall keeps checking and opens again by itself when the exit has moved out.
- When the country **cannot be established** (the check fails, or nobody knows the address), traffic is blocked as well.

What you should know:

- The check is one small request through the proxy to the IP service (Cloudflare by default). It is the only way to learn where the exit is, so that one request does leave through a blocked exit. Nothing from your programs goes with it.
- If the exit moves while you are connected, connections opened before the next check, at most 5 seconds, can still leave through the new exit. `proxywall config country_check_seconds=0` checks before **every** connection instead; each new connection then waits for one check (about a second through a typical proxy).
- A proxy that sends every connection out through a different address cannot be policed this way.
- Countries come from geo-IP databases, which are occasionally wrong. When the two services disagree, the stricter answer wins.
- Your bypass list and the local network do not use the proxy and stay reachable.

### Command line

```sh
proxywall set-proxy socks5://user:pass@192.168.1.5:1080
proxywall set-proxy 'vless://uuid@example.com:443?security=reality&pbk=...&type=tcp'   # or vmess:// trojan:// ss://
proxywall set-proxy ssh://me@example.com --key ~/.ssh/id_ed25519
proxywall exclude add '*.ir' 10.1.0.0/16
proxywall block-country add IR
proxywall server add 'trojan://secret@nl.example.net:443#Amsterdam' http://10.0.0.2:8080
proxywall server test            # ping and internet check for every saved server
proxywall server use Amsterdam
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

- **TCP and DNS only.** UDP relaying is not implemented for any kind of server, and HTTP proxies cannot carry UDP. While the firewall is active, other UDP (QUIC/HTTP3, most VoIP and games) and ping are *rejected*, not tunnelled. Browsers fall back to TCP automatically.
- **A proxy is not encryption.** ProxyWall guarantees that traffic goes to your proxy or nowhere. Whether the hop to the proxy is encrypted depends on the proxy; plain SOCKS5 and HTTP proxies are not.
- **HTTP proxies must allow `CONNECT` to the ports you use.** Many only allow 443. SOCKS5 is the better choice when you have one.
- **A proxy running on this same computer** (for example a local tunnel client listening on `127.0.0.1`) must be able to reach its own server: add that server's address to the bypass list, otherwise its traffic is captured too and loops.
- **Do not run it together with another VPN client's firewall.** Two kill switches will block each other.
- **Excluded domains are matched by name.** An application that resolves names itself (DNS-over-HTTPS in a browser) is still proxied and still cannot leak; for HTTPS and HTTP, exclusions keep working because ProxyWall reads the host name from the connection. For other protocols such an application's excluded domains go through the proxy.
- Just after disconnecting, applications may hold placeholder addresses for a second or two; a retry fixes it.

## FAQ

**How do I use a SOCKS5 proxy for the whole system on Linux?**
Install ProxyWall, enter the proxy address and press connect. Every program is captured by the firewall; nothing has to be configured per application.

**Does it work with VLESS, VMess, Trojan, Shadowsocks or SSH servers?**
Yes, directly: paste the share link, or fill in the SSH form. See [Other protocols](#other-protocols-ssh-vless-vmess-trojan-shadowsocks).

**Does it work with another client such as sing-box, NekoRay or `ssh -D`?**
Yes. Anything that offers a SOCKS5 or HTTP proxy port works. If that client runs on the *same* computer, add its remote server's IP address to the bypass list (see [Limitations](#limitations)).

**Is ProxyWall a VPN?**
No. It does not encrypt anything by itself and it carries TCP and DNS, not all IP traffic. It gives a proxy the two things people usually want from a VPN client: system-wide capture and a kill switch.

**What happens when the proxy goes down?**
Connections fail immediately and stay blocked until the proxy answers again. Traffic is never sent directly.

**Can I make sure I never appear with an IP address from a certain country?**
Yes: add it under *Blocked countries*. Traffic is held until the exit country is known and blocked while it is on your list. Read [Blocked countries](#blocked-countries) for the exact guarantee.

**Can some sites skip the proxy?**
Yes: add domains (`*.ir`), addresses or networks to the bypass list.

**Does it work on GNOME, KDE, Wayland?**
The service and the command line work everywhere. The window is GTK 3 and runs on any desktop; the tray icon needs XApp (Cinnamon, MATE, Xfce) or AppIndicator support.

## Security model

- The service (`proxywalld`) runs as root with **only `CAP_NET_ADMIN`**, under systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, system-call filter, no access to `/home`).
- It is controlled over a Unix socket. Root and regular login accounts may use it; system and service accounts may not. See [SECURITY.md](SECURITY.md).
- The proxy password, share link and SSH private key are stored in `/var/lib/proxywall/config.json`, readable by root only, and are never sent back to the interface.
- The public IP shown in the window is fetched through the proxy from `https://www.cloudflare.com/cdn-cgi/trace`, and its city and coordinates from `https://ipwho.is/`. Both requests travel through the proxy, so those services see the proxy's address, not yours. Set `geo_url` to an empty value to skip the second one (the map then shows the capital of the country), or `ip_check_url` to turn both off.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| The window says **SERVICE STOPPED** | `sudo systemctl start proxywall`, then `journalctl -u proxywall -e` if it does not stay up |
| **NO PROXY** | Check address, port and type; the reason is printed under the status and in `proxywall logs` |
| I am locked out and need the internet now | `sudo proxywall reset-firewall` |
| One site must not use the proxy | add it to the bypass list |
| **COUNTRY BLOCKED** | the proxy comes out in a country on your list: fix the proxy, or change the list in *Settings → Blocked countries* |

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

The flag images come from [flag-icons](https://github.com/lipis/flag-icons) (MIT). The country table and the map are derived from [Natural Earth](https://www.naturalearthdata.com) and the tz database (public domain).
