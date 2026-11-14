# Configuration and command reference

Settings are changed from the window, with the `proxywall` command, or both; they end up in `/var/lib/proxywall/config.json`. Do not edit that file while the service is running: use the commands below, which validate the input and apply it immediately.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `proxy.type` | `socks5` | `socks5` or `http` (HTTP CONNECT) |
| `proxy.host` | *(empty)* | IP address or host name of the proxy |
| `proxy.port` | `1080` | port of the proxy |
| `proxy.username`, `proxy.password` | *(empty)* | credentials, if the proxy needs them |
| `kill_switch` | `false` | the *Firewall* switch: block all traffic whenever you are not connected, also after a reboot |
| `allow_lan` | `true` | private and link-local networks bypass the proxy |
| `exclude` | `[]` | domains, addresses and networks that bypass the proxy |
| `direct_dns` | `[]` | DNS servers for excluded and local names; empty = the system's |
| `remote_dns` | `1.1.1.1` | resolver reached through the proxy for record types other than `A`/`AAAA` |
| `ip_check_url` | Cloudflare trace URL | fetched through the proxy to show your public IP and its country; empty = never |
| `geo_url` | `https://ipwho.is/` | asked through the proxy where that IP is (city and coordinates for the map); empty = never |
| `tcp_port`, `dns_port` | `47201`, `47253` | local ports the firewall redirects to |
| `fwmark` | `0x5057` (20567) | firewall mark of the service's own sockets; change it only if it collides with other software |
| `log_level` | `info` | `debug`, `info`, `warning` or `error` |

With *Allow LAN* on, these ranges go out directly: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, multicast and broadcast, and for IPv6 `fc00::/7`, `fe80::/10`, `ff01::/16`, `ff02::/16`.

### Location

The flag, the map and the coordinates describe the public IP address your traffic comes out of, not you. Two requests, both sent **through the proxy**, feed them:

1. `ip_check_url` returns the address and its country (this picks the flag).
2. `geo_url` returns the city and coordinates. It is asked again only when the address changes. Any service that answers with JSON containing `latitude`/`longitude` (or `lat`/`lon`, or `loc`) works: `https://ipwho.is/`, `https://ipinfo.io/json`, `http://ip-api.com/json`.

If `geo_url` is empty or does not answer, the map points at the capital of the country and the coordinates are prefixed with `≈`. That table is part of the package, so nothing is requested. With `ip_check_url` empty nothing is looked up at all and the location stays blank.

### Exclusion syntax

| Entry | Matches |
| --- | --- |
| `example.com` | `example.com` and every subdomain |
| `*.example.com`, `.example.com` | the same (the wildcard is only a familiar spelling) |
| `*.ir` | a whole top-level domain |
| `192.0.2.10` | one IPv4 address |
| `198.51.100.0/24` | an IPv4 network |
| `2001:db8::/32` | an IPv6 network |

Pasted URLs are reduced to their host (`https://example.com/page` → `example.com`). Internationalised names are accepted (`*.ایران`). Entries that would match everything (`*`, `0.0.0.0/0`) are refused.

Address exclusions are enforced by the firewall itself and cover every protocol. Domain exclusions apply to TCP; excluded names are still resolved through ProxyWall's DNS server.

## `proxywall` command

```
proxywall status [--json]            show the connection status (exit code 0 when healthy)
proxywall connect [--wait SECONDS]   send all traffic through the proxy
proxywall disconnect                 stop using the proxy
proxywall set-proxy URL              socks5://[user:pass@]host[:port]  or  http://...
proxywall kill-switch on|off         the Firewall switch
proxywall lan on|off                 Allow LAN
proxywall exclude list
proxywall exclude add ENTRY...
proxywall exclude remove ENTRY...
proxywall config [KEY=VALUE...]      show the configuration, or change any setting
proxywall logs [-n COUNT]            recent service messages
sudo proxywall reset-firewall        emergency: remove the firewall and stop the service
```

Examples:

```sh
proxywall set-proxy 'socks5://alice:s3cret@192.168.1.5:1080'
proxywall config remote_dns=9.9.9.9 log_level=debug
proxywall config ip_check_url=            # never look up the public IP (and no location)
proxywall config geo_url=                 # no city lookup: the map shows the country's capital
proxywall config 'direct_dns=["192.168.1.1"]'
proxywall status --json | jq .state
```

Exit codes: `0` success, `1` the service rejected the request, `2` bad arguments, `3` not connected, `4` the service is not running.

## Who may control ProxyWall

Root and regular login accounts (UID between `UID_MIN` and `UID_MAX` in `/etc/login.defs`, normally 1000–60000). System accounts are refused.

## Service

```sh
systemctl status proxywall
journalctl -u proxywall -e
sudo systemctl restart proxywall     # safe: the firewall stays applied while it restarts
```

The interface can start with your session: *Settings → Open at login* creates `~/.config/autostart/proxywall.desktop`. The connection itself does not depend on it; the service restores the last state at boot on its own.
