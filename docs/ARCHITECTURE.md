# Architecture

ProxyWall has two halves:

| Part | Runs as | Job |
| --- | --- | --- |
| `proxywalld` (`proxywall/daemon.py`) | system service, root with only `CAP_NET_ADMIN` | owns the firewall, the DNS server and the relay |
| `proxywall-gui`, `proxywall` | you | remote controls that talk to the service over `/run/proxywall/control.sock` |

Everything is Python standard library on a single `asyncio` event loop; the only external program is `nft`, plus `xray` or `ssh` when the server is not a plain SOCKS5 or HTTP proxy.

## The life of a connection

Say Firefox opens `https://example.org` while ProxyWall is connected and `*.ir` is excluded.

1. **DNS.** Firefox asks the system resolver, which sends a query to port 53 of some server. nftables redirects that packet to ProxyWall's DNS server (`dnsserver.py`). It answers at once with a placeholder, e.g. `198.18.0.7`, and remembers `198.18.0.7 ↔ example.org` (`fakeip.py`). No query leaves the machine.
2. **Connect.** Firefox connects to `198.18.0.7:443`. nftables redirects the connection to the relay (`tproxy.py`), which asks the kernel for the original destination (`SO_ORIGINAL_DST`) and maps it back to `example.org`.
3. **Route.** `example.org` is not excluded, so the relay opens a connection to the proxy and sends `CONNECT example.org:443` (SOCKS5 or HTTP, `upstream.py`). The *proxy* resolves the name.
4. **Relay.** Bytes are copied both ways until either side closes.

For `https://site.ir` step 3 differs: the name is excluded, so the service resolves it with the network's own DNS server and connects directly. For a destination given as an address in an excluded network, nftables lets the packets through untouched and the service is not involved at all.

### Why placeholder addresses

A transparent proxy only sees IP addresses. Without the placeholder trick it would have to let the local resolver do the lookup (a DNS leak, and wrong answers on networks that tamper with DNS) and could not apply domain rules. The range `198.18.0.0/15` is reserved for benchmarking and is not routed on the internet, so it cannot collide with a real site. The map is least-recently-used over ~131,000 addresses and is saved to disk so that a service restart is invisible to running applications.

### DNS answers

| Query | Answer |
| --- | --- |
| `A` | placeholder address, TTL 1 s |
| `AAAA`, `HTTPS`, `SVCB` | empty: applications use the `A` record |
| local names (`printer`, `nas.local`, private reverse zones) with *Allow LAN* on | forwarded to the network's DNS servers |
| other types (`TXT`, `MX`, `SRV`, …) of an excluded name | forwarded to the network's DNS servers |
| other types of any other name | DNS-over-TCP to `remote_dns`, **through the proxy** |

The service itself never calls the system resolver (it would get its own placeholders back). The proxy's host name and excluded names are resolved by `resolver.py` over marked sockets, using the servers from `/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf`, or `direct_dns` when set.

### Literal addresses and DNS-over-HTTPS

Connections to real addresses (the application did its own resolving, or the user typed an IP) are proxied by address. To keep *domain* exclusions effective for those, the relay reads the TLS server name or the HTTP `Host` header on ports 443 and 80 before choosing a route. The name is used only for the decision; the connection still goes to the address the application chose.

## The firewall

All rules live in one table, `inet proxywall`, replaced atomically on every change (`firewall.py`). Sketch:

```
table inet proxywall {
    set bypass4 / bypass6          # LAN ranges (if allowed) + excluded addresses

    chain capture_local  (nat, output)       chain capture_forwarded (nat, prerouting)
        marked by the daemon      -> accept      (same rules, for routed traffic)
        destination is local      -> accept
        port 53                   -> redirect to the DNS server
        destination in bypass set -> accept
        tcp                       -> redirect to the relay

    chain killswitch_local (filter, output)  chain killswitch_forwarded (filter, forward)
        unmarked, to a helper port -> reject     destination in bypass set -> accept
        marked by the daemon      -> accept      anything else             -> reject
        loopback / local          -> accept
        destination in bypass set -> accept
        IPv6 neighbour discovery, DHCP -> accept
        anything else             -> reject

    chain guard_ports (filter, input)
        the daemon's two ports are reachable only by redirected connections
}
```

Properties worth noticing:

- **The rules do not know whether the proxy works.** They express "to the daemon, or nowhere". Proxy down → the relay cannot complete connections → applications get an immediate reset. Daemon dead → redirected connections are refused by the kernel. Neither case has a path to the network.
- **Only the daemon's sockets get out.** Each outbound socket is tagged with a firewall mark (`SO_MARK`, default `0x5057`), which needs `CAP_NET_ADMIN`. Other processes cannot imitate it.
- **Existing connections are cut on connect.** There is no "established → accept" rule in the output chain, so a download that started before you connected does not continue outside the proxy.
- **Rejected, not dropped.** TCP gets a reset and UDP an ICMP error, so applications fail fast (and browsers fall back from QUIC to TCP at once) instead of hanging.

## State machine

Desired state is two facts kept on disk: the configuration and `enabled` (does the user want to be connected). `Core.reconcile()` in `daemon.py` makes the running system match.

| `enabled` | kill switch | firewall | effect |
| --- | --- | --- | --- |
| no | off | removed | normal networking |
| no | on | applied | everything blocked, exclusions direct |
| yes | any | applied | everything through the proxy, exclusions direct; nothing through the proxy while its exit is in a blocked country |

Ordering is chosen so that every transition passes through "closed", never "open": listeners start before the rules that feed them, and rules are removed before listeners stop.

Shutting the service down (`systemctl stop`, upgrade, crash) deliberately leaves the firewall applied. The only ways to remove it are *Disconnect* with the kill switch off, uninstalling the package, or `sudo proxywall reset-firewall`.

### Boot

Whenever the firewall is applied, the same rule set is written to `/var/lib/proxywall/boot.nft`. The unit is ordered before `network-pre.target` and loads that file in `ExecStartPre`, so a machine with the kill switch on has its rules before any interface is configured, even if the Python service then failed to start.

### Health monitor

`monitor.py` probes the proxy (TCP connect; for SOCKS5 also the authentication handshake) every 10 s while it is reachable and every 3 s while it is not. It drives the status shown in the interface and nothing else. Routing never depends on it.

The monitor also asks, through the proxy, for the public IP (`ip_check_url`, every 15 minutes) and, when that address changes, for its city and coordinates (`geo_url`). `geo.py` parses the replies and falls back to the capital of the country from `geodata.py`, a generated table that also holds the 75×28 land grid the interface draws its map from. The interface composes the flag tray icon itself and keeps it in `~/.cache/proxywall/`.

### Helper processes (SSH and share links)

`upstream.py` speaks SOCKS5 and HTTP CONNECT. For every other kind of server `engine.py` runs a child process that offers a local SOCKS5 port, and the daemon uses that port as its proxy:

| Server | Process | Its connection to the server |
| --- | --- | --- |
| `vless`, `vmess`, `trojan`, `shadowsocks` | `xray run -c /run/proxywall/engine.json`, generated by `links.py` from the share link | Xray sets the firewall mark on its outbound socket (`sockopt.mark`) |
| `ssh` | `ssh -N -D 127.0.0.1:<engine_port>` | `ProxyCommand` is `proxywall.pipe`, which opens the marked socket and hands it to ssh |

So the rule "only marked sockets leave" still holds, and nothing was added to the bypass sets. The daemon resolves the server's name itself and passes an address; SNI and `Host` are set to the original name. The local port is closed to other programs twice over: Xray asks for a password that only the daemon knows (generated at start), and the firewall rejects unmarked connections to the port (ssh cannot ask for a password). That rule sits in the output chain, next to the kill switch: the mark is checked where a connection leaves its program, because other firewalls on the machine (VPN clients restoring connection marks) may rewrite it before the packet arrives again on loopback. The configuration file with the secrets is mode 0600 and removed when the helper stops. A helper that exits is restarted with a growing pause; while it is down, connections fail and nothing leaves.

Because a local SOCKS port answers even when the server behind it is dead, the health check for these servers sends a DNS query to `remote_dns` through the tunnel and waits for the reply.

### Saved servers and tests

The configuration holds a list of servers; `proxy` is a copy of the one named by `active_server`, so the rest of the daemon never needs to know there is a list. Choosing another server is an ordinary configuration change: the helper is restarted if there is one, the monitor forgets what it knew, and the relay tasks that were using the old server are cancelled.

`tester.py` measures servers on request, up to four at a time: a TCP connection to the server, the exit country through it, and `test_url` through it. Helpers for SSH and share-link servers run on `engine_port+1 … +9`, which the firewall guards like `engine_port` itself. Results live in memory only and are dropped when a server is edited.

### Country gate

When `blocked_countries` is set, the monitor is also a gate. `tproxy.py` (and the DNS server, for lookups it forwards through the proxy) calls `Monitor.permit()` before every dial to the proxy. It answers yes only on the strength of a check that started no longer than `country_check_seconds` ago and found the exit outside every blocked country; otherwise the caller waits for a check that is new enough, and gets no if that check fails, times out, or finds no country at all. A positive answer is never carried over a change of proxy, a loss of the proxy or a change of the list: each of those cancels the running check and resets the verdict. Finding a blocked country cancels every relay task that is using the proxy.

Like the rest of the design this can only close things: the firewall still forces all traffic into the relay, and the gate adds one more reason for the relay to refuse.

## Control protocol

Newline-delimited JSON over the Unix socket:

```
-> {"cmd": "status"}
<- {"ok": true, "state": "connected", "proxy": "socks5://192.168.1.5:1080", ...}
```

Commands: `status`, `connect`, `disconnect`, `get_config`, `set_config`, `logs`, `refresh_ip`. Authorisation uses the kernel-verified peer credentials of each connection (`SO_PEERCRED`).

## Files

| Path | Content |
| --- | --- |
| `/var/lib/proxywall/config.json` | settings (mode 0600, contains the proxy password) |
| `/var/lib/proxywall/state.json` | whether the user wants to be connected |
| `/var/lib/proxywall/boot.nft` | rule set restored at boot; exists only while the firewall should be on |
| `/var/lib/proxywall/fakeip.json` | placeholder map |
| `/run/proxywall/control.sock` | control socket |

## Source map

| Module | Responsibility |
| --- | --- |
| `daemon.py` | state machine, commands, lifecycle |
| `firewall.py` | nftables rule set |
| `tproxy.py` | transparent TCP relay, SNI/Host detection |
| `dnsserver.py`, `dnsmsg.py`, `fakeip.py` | DNS front end and placeholder pool |
| `resolver.py` | the daemon's own DNS client |
| `upstream.py` | SOCKS5 and HTTP CONNECT |
| `engine.py`, `links.py`, `pipe.py` | helper processes: Xray for share links, ssh; link parsing; marked pipe for ssh |
| `rules.py`, `config.py` | exclusion matching, settings validation |
| `monitor.py` | proxy health, public IP, internet latency |
| `tester.py` | ping and internet test of saved servers |
| `geo.py`, `geodata.py` | location of the public IP: reply parsing, country table, map grid |
| `control.py`, `client.py` | control socket, both ends |
| `cli.py`, `gui/` | user interfaces |
