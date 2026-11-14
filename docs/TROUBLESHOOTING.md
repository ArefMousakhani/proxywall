# Troubleshooting

Start with these two commands; they answer most questions:

```sh
proxywall status
proxywall logs
```

For per-connection detail turn on debug logging (`proxywall config log_level=debug`, and `log_level=info` when done). Debug logs contain the host names you connect to.

## I have no internet and need it back right now

```sh
sudo proxywall reset-firewall
```

This stops the service and deletes its firewall table. It works even when the service is broken. If the *Firewall* switch is on, the block returns when the service starts again; turn it off with `proxywall kill-switch off` once the service runs.

Manual equivalent, if the command is unavailable:

```sh
sudo systemctl stop proxywall
sudo rm -f /var/lib/proxywall/boot.nft
sudo nft delete table inet proxywall
```

## The window says SERVICE STOPPED

```sh
sudo systemctl start proxywall
systemctl status proxywall
journalctl -u proxywall -e
```

## NO PROXY / "cannot reach the proxy"

The exact reason is shown under the status.

| Message | Usual cause |
| --- | --- |
| `Connection refused` | wrong port, or the proxy program is not running |
| `timed out`, `No route to host` | wrong address, different network, or a firewall on the proxy machine |
| `the server is not a SOCKS5 proxy` | it is an HTTP proxy: switch the type (and the other way round for "not an HTTP proxy") |
| `rejected the username or password` | credentials |
| `requires a username and password` | fill in the credentials |

Check from a terminal, bypassing ProxyWall's interface entirely:

```sh
curl -v --proxy socks5h://192.168.1.5:1080 https://example.com     # SOCKS5
curl -v --proxy http://192.168.1.5:8080 https://example.com        # HTTP
```

(While ProxyWall is connected this test itself travels through the proxy when the proxy is not on your local network, so disconnect first.)

## A share link or SSH server does not connect

The reason is shown under the status and in `proxywall logs`.

| Message | Meaning |
| --- | --- |
| `needs Xray, which is not installed` | install Xray, or point `engine_path` at it (README, *Other protocols*) |
| `... links are not supported` | Hysteria, TUIC, WireGuard and NaiveProxy need a different program; run that client yourself and give ProxyWall its SOCKS5 port |
| `no answer through the server` | the helper runs but nothing comes back: wrong id/password in the link, the server is down, or it blocks DNS to `remote_dns` (try `proxywall config remote_dns=8.8.8.8`) |
| `the server rejected the username, password or key` | SSH login failed |
| `the server's host key has changed` | the SSH server is not the one seen the first time; if that is expected, `sudo rm /var/lib/proxywall/known_hosts` |

`proxywall config log_level=debug` adds the helper's own output to `proxywall logs`.

## COUNTRY BLOCKED

The proxy comes out in a country on your list (*Settings → Blocked countries*); the address and country are shown in the window and by `proxywall status`. Nothing is sent through the proxy until its exit moves. ProxyWall checks again every few seconds, so there is nothing to click once the proxy is fixed.

If the country is wrong (geo-IP databases sometimes are), either remove the country (`proxywall block-country remove XX`) or stop asking the second service (`proxywall config geo_url=`).

## CHECKING does not go away

Countries are blocked, and ProxyWall cannot find out where the proxy comes out, so it sends nothing. The reason is printed under the status. Usually the IP service (`ip_check_url`) is unreachable through this proxy: try another one, for example `proxywall config ip_check_url=https://ipinfo.io/json`.

## Everything became slower after blocking a country

With `country_check_seconds=0` every new connection waits for a check. Set it back to `5`.

## Connected, but some sites do not load

- **HTTP proxy:** many only permit `CONNECT` to port 443. Plain `http://` sites and other ports then fail. Use a SOCKS5 proxy or relax the proxy's rules.
- **The site needs UDP** (some video calls, games): not supported, see the limitations in the README.
- **A domestic site blocks foreign visitors:** add it to the bypass list.

## The proxy runs on this computer and nothing works

A local proxy or tunnel client (listening on `127.0.0.1`) has to reach its own server, and that traffic is captured like everything else, which makes a loop. Add the server's IP address (or the network it is in) to the bypass list:

```sh
proxywall exclude add 203.0.113.50
```

## An excluded domain still goes through the proxy

- Entries match by host name. Check the spelling with `proxywall exclude list`.
- If the application uses its own encrypted DNS (DNS-over-HTTPS in a browser), ProxyWall recognises the name only for HTTPS and HTTP connections. Other protocols need an address exclusion.
- With debug logging on, each connection is listed as `direct` or `proxy`.

## Names do not resolve while connected

ProxyWall answers DNS itself. Two system settings can get in the way:

- **DNSSEC validation in systemd-resolved** (`DNSSEC=yes` in `/etc/systemd/resolved.conf`) rejects the placeholder answers. Set `DNSSEC=no` or `allow-downgrade` and run `sudo systemctl restart systemd-resolved`.
- **DNS-over-TLS in systemd-resolved** (`DNSOverTLS=yes`) keeps working, but then lookups are ordinary proxied connections and domain exclusions apply only to HTTPS and HTTP.

## Docker containers lost their network

Container traffic is forwarded through the host and is captured too, so it goes through the proxy. If containers cannot connect at all:

- Another firewall (for example `ufw` with a default "deny incoming" policy) may be dropping the redirected packets. Allow the two ProxyWall ports from the Docker bridge: `sudo ufw allow in on docker0 to any port 47201,47253 proto tcp` and `sudo ufw allow in on docker0 to any port 47253 proto udp`.
- With *Allow local network* off, container networks are not treated as local. Turn it on or add the Docker subnet (e.g. `172.17.0.0/16`) to the bypass list.

## Right after disconnecting, sites fail for a moment

Applications may still hold placeholder addresses (`198.18.x.x`) for a second or two. Reload the page.

## It conflicts with my VPN client

Another client's kill switch will block ProxyWall's connection to the proxy, and ProxyWall will block the VPN. Use one at a time: disconnect the other client and turn off its firewall before connecting.

## Seeing what the firewall does

```sh
sudo nft list table inet proxywall
```

If the table is absent, ProxyWall is not filtering anything.
