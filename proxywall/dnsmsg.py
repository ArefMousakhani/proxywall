"""The small part of the DNS wire format that ProxyWall needs (RFC 1035)."""

import os
import struct

A, NS, CNAME, SOA, PTR, AAAA, OPT, SVCB, HTTPS, ANY = 1, 2, 5, 6, 12, 28, 41, 64, 65, 255
NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5

_OPT_RR = b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"  # EDNS0, 1232 byte payload


class DNSError(ValueError):
    pass


def read_name(data, off):
    """Decode a (possibly compressed) name. Returns (lower-case name, next offset)."""
    labels, end, hops = [], None, 0
    while True:
        if off >= len(data):
            raise DNSError("truncated name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DNSError("truncated pointer")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 32:
                raise DNSError("compression loop")
            continue
        if length & 0xC0:
            raise DNSError("bad label")
        off += 1
        if off + length > len(data):
            raise DNSError("truncated label")
        labels.append(data[off:off + length].decode("latin-1"))
        off += length
        if len(labels) > 127:
            raise DNSError("name too long")
    return ".".join(labels).lower(), (off if end is None else end)


def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("latin-1")
        if not 0 < len(raw) < 64:
            raise DNSError("bad label")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


class Query:
    __slots__ = ("id", "opcode", "rd", "name", "qtype", "qclass", "question", "edns")


def parse_query(data):
    if len(data) < 12:
        raise DNSError("short message")
    qid, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    if flags & 0x8000:
        raise DNSError("not a query")
    if qd != 1:
        raise DNSError("expected exactly one question")
    name, off = read_name(data, 12)
    if off + 4 > len(data):
        raise DNSError("truncated question")
    query = Query()
    query.id = qid
    query.opcode = (flags >> 11) & 0xF
    query.rd = bool(flags & 0x0100)
    query.name = name
    query.qtype, query.qclass = struct.unpack("!2H", data[off:off + 4])
    query.question = bytes(data[12:off + 4])
    query.edns = ar > 0 and an == 0 and ns == 0 and data[off + 4:off + 7] == b"\x00\x00\x29"
    return query


def build_response(query, rcode=NOERROR, answers=()):
    """*answers* is a sequence of ``(rtype, ttl, rdata)`` for the queried name."""
    flags = 0x8000 | (query.opcode << 11) | (0x0100 if query.rd else 0) | 0x0080 | rcode
    out = bytearray(struct.pack("!6H", query.id, flags, 1, len(answers), 0, 1 if query.edns else 0))
    out += query.question
    for rtype, ttl, rdata in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    if query.edns:
        out += _OPT_RR
    return bytes(out)


def build_query(name, qtype, qid=None):
    if qid is None:
        qid = int.from_bytes(os.urandom(2), "big")
    return struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!2H", qtype, 1)


def parse_response(data):
    """Returns ``(rcode, truncated, [(rtype, ttl, rdata), ...])`` for the answer section."""
    if len(data) < 12:
        raise DNSError("short message")
    _, flags, qd, an, _, _ = struct.unpack("!6H", data[:12])
    if not flags & 0x8000:
        raise DNSError("not a response")
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = read_name(data, off)
        if off + 10 > len(data):
            raise DNSError("truncated record")
        rtype, _, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > len(data):
            raise DNSError("truncated rdata")
        answers.append((rtype, ttl, bytes(data[off:off + rdlen])))
        off += rdlen
    return flags & 0xF, bool(flags & 0x0200), answers
