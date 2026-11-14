"""stdin/stdout <-> TCP, over a socket that carries the firewall mark.

Used as ssh's ProxyCommand, so that the SSH connection leaves through the
firewall the same way the daemon's own sockets do:

    python3 -m proxywall.pipe ADDRESS PORT MARK
"""

import os
import selectors
import socket
import sys

SO_MARK = getattr(socket, "SO_MARK", 36)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    address, port, mark = args[0], int(args[1]), int(args[2])
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if mark:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
    sock.settimeout(12)
    try:
        sock.connect((address, port))
    except OSError as exc:
        sys.stderr.write(f"proxywall pipe: connection refused or failed: {exc}\n")
        return 1
    sock.settimeout(None)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    selector = selectors.DefaultSelector()
    selector.register(0, selectors.EVENT_READ, "in")
    selector.register(sock, selectors.EVENT_READ, "net")
    open_ends = 2
    while open_ends:
        for key, _ in selector.select():
            if key.data == "in":
                data = os.read(0, 65536)
                if data:
                    sock.sendall(data)
                else:
                    selector.unregister(0)
                    open_ends -= 1
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            else:
                data = sock.recv(65536)
                if data:
                    view = memoryview(data)
                    while view:
                        view = view[os.write(1, view):]
                else:
                    return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
