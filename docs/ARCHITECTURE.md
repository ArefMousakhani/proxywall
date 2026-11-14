# Architecture

ProxyWall has two halves:

| Part | Runs as | Job |
| --- | --- | --- |
| `proxywalld` (`proxywall/daemon.py`) | system service, root with only `CAP_NET_ADMIN` | owns the firewall, the DNS server and the relay |
| `proxywall-gui`, `proxywall` | you | remote controls that talk to the service over `/run/proxywall/control.sock` |

Everything is Python standard library on a single `asyncio` event loop; the only external program is `nft`.

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
        marked by the daemon      -> accept      destination in bypass set -> accept
        loopback / local          -> accept      anything else             -> reject
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
| yes | any | applied | everything through the proxy, exclusions direct |

Ordering is chosen so that every transition passes through "closed", never "open": listeners start before the rules that feed them, and rules are removed before listeners stop.

Shutting the service down (`systemctl stop`, upgrade, crash) deliberately leaves the firewall applied. The only ways to remove it are *Disconnect* with the kill switch off, uninstalling the package, or `sudo proxywall reset-firewall`.

### Boot

Whenever the firewall is applied, the same rule set is written to `/var/lib/proxywall/boot.nft`. The unit is ordered before `network-pre.target` and loads that file in `ExecStartPre`, so a machine with the kill switch on has its rules before any interface is configured, even if the Python service then failed to start.

### Health monitor

`monitor.py` probes the proxy (TCP connect; for SOCKS5 also the authentication handshake) every 10 s while it is reachable and every 3 s while it is not. It drives the status shown in the interface and nothing else. Routing never depends on it.

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
| `rules.py`, `config.py` | exclusion matching, settings validation |
| `monitor.py` | proxy health and public IP |
| `control.py`, `client.py` | control socket, both ends |
| `cli.py`, `gui/` | user interfaces |
