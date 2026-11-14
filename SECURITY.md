# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
[private vulnerability reporting](https://github.com/ArefMousakhani/proxywall/security/advisories/new), and
include the version (`proxywall --version`), your distribution, and steps to
reproduce. You should get a first answer within a week.

Especially interesting: any way for traffic to leave the machine outside the
proxy while the firewall is applied, and any way for an unauthorised local
account to control the service or read the proxy password.

## What ProxyWall promises

While the firewall is applied (connected, or disconnected with the *Firewall*
switch on):

- No packet from a local application or a forwarded container reaches a
  non-excluded, non-local destination except through the configured proxy.
- This holds when the proxy is unreachable, when the service crashes or is
  stopped, and from before network interfaces come up at boot.
- Host names of proxied destinations are not sent to the local DNS servers.

## What it does not promise

- **Confidentiality towards the proxy or on the path to it.** SOCKS5 and HTTP
  proxies are not encrypted tunnels.
- **Protection from root.** Root, and any process with `CAP_NET_ADMIN`, can
  remove the firewall or mark its own sockets.
- **Protection of excluded destinations.** Exclusions and the local network go
  out directly by design, also while everything else is blocked.
- **Separation between users of the same computer.** Every regular login
  account may connect, disconnect and change settings (but cannot read the
  stored password).

## Hardening in place

- The service keeps a single capability (`CAP_NET_ADMIN`) and runs under a
  systemd sandbox: read-only file system except its state directory, no access
  to home directories or devices, system-call filter, no new privileges.
- Control requests are authorised from kernel-verified peer credentials.
- The configuration file is mode 0600 and the password is write-only over the
  control socket.
- The service's listening ports accept only connections that the firewall
  redirected to them.
