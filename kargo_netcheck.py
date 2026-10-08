#!/usr/bin/env python3
"""Verify the firewall rules Kargo devices need. Python stdlib only.

Usage:
    python3 kargo_netcheck.py            # run every check
    python3 kargo_netcheck.py dns|tcp|stun|tls [options]
"""
import argparse
import random
import socket
import ssl
import struct
import sys
import time
import zlib

OK, FAIL, PARTIAL = 0, 1, 2


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

DNS_CHECKS = [
    ("sdn.kargo.zone", "13.56.25.183"),
]

QTYPE_A = 1
QCLASS_IN = 1


def resolve_system(host):
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def build_dns_query(host, txid):
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack(">B", len(label)) + label.encode("ascii") for label in host.rstrip(".").split("."))
    return header + qname + b"\x00" + struct.pack(">HH", QTYPE_A, QCLASS_IN)


def skip_dns_name(data, off):
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def parse_dns_answer(data, txid):
    resp_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if resp_id != txid:
        raise ValueError(f"transaction id mismatch (0x{resp_id:04X} != 0x{txid:04X})")
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"server returned rcode={rcode}")
    off = 12
    for _ in range(qdcount):
        off = skip_dns_name(data, off) + 4
    addrs = []
    for _ in range(ancount):
        off = skip_dns_name(data, off)
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == QTYPE_A and rclass == QCLASS_IN and rdlen == 4:
            addrs.append(socket.inet_ntop(socket.AF_INET, rdata))
    return sorted(set(addrs))


def resolve_with_server(host, server, timeout, retries):
    txid = random.getrandbits(16)
    payload = build_dns_query(host, txid)
    last_err = None
    for attempt in range(1, retries + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                print(f"[send] attempt {attempt}/{retries}: A query for {host} -> {server}:53/UDP")
                sock.sendto(payload, (server, 53))
                data, _ = sock.recvfrom(4096)
                print(f"[recv] {len(data)} bytes from {server}:53")
                return parse_dns_answer(data, txid)
            except socket.timeout:
                last_err = "timeout"
                print(f"[recv] attempt {attempt}: no response (timeout {timeout}s)")
            except OSError as e:
                last_err = str(e)
                print(f"[recv] attempt {attempt}: error {e}")
    raise OSError(f"all attempts failed: {last_err}")


def run_dns(args):
    resolver = f"{args.server}:53/UDP" if args.server else "system resolver"
    print(f"== DNS check via {resolver} ==")

    failed = False
    for host, expected in DNS_CHECKS:
        try:
            if args.server:
                addrs = resolve_with_server(host, args.server, args.timeout, args.retries)
            else:
                addrs = resolve_system(host)
        except (OSError, ValueError) as e:
            print(f"[resolve] FAILED: {host}: {e}")
            failed = True
            continue

        print(f"[resolve] {host} -> {', '.join(addrs) if addrs else '(no A records)'}")
        if addrs == [expected]:
            print(f"[check] {host}: OK (expected {expected})")
        else:
            print(f"[check] {host}: MISMATCH (expected only {expected})")
            failed = True

    if failed:
        print("\nRESULT: FAIL - DNS answers are missing or altered.")
        return FAIL
    print("\nRESULT: OK - DNS answers match expected addresses.")
    return OK


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

TCP_TARGETS = [
    ("54.153.23.224", 8022),
    ("edp12.devicecloud.com", 3199),
    ("sdn.kargo.zone", 443),
    ("sdn.kargo.zone", 80),
]


def check_tcp(host, port, timeout, retries):
    last_err = None
    for attempt in range(1, retries + 1):
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                peer = sock.getpeername()
                ms = (time.monotonic() - start) * 1000
                print(f"[connect] {host}:{port}/TCP -> {peer[0]} OK ({ms:.0f} ms)")
                return True
        except socket.timeout:
            last_err = f"timeout {timeout}s"
        except OSError as e:
            last_err = str(e)
        print(f"[connect] {host}:{port}/TCP attempt {attempt}/{retries}: FAILED ({last_err})")
    return False


def parse_target(value):
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError(f"expected host:port, got {value!r}")
    return host, int(port)


def run_tcp(args):
    targets = args.targets or TCP_TARGETS
    print(f"== TCP connectivity check: {len(targets)} target(s) ==")

    failed = [f"{h}:{p}" for h, p in targets if not check_tcp(h, p, args.timeout, args.retries)]

    if failed:
        print(f"\nRESULT: FAIL - blocked or unreachable: {', '.join(failed)}")
        return FAIL
    print("\nRESULT: OK - all TCP ports reachable.")
    return OK


# ---------------------------------------------------------------------------
# STUN (UDP 3478)
# ---------------------------------------------------------------------------

MAGIC_COOKIE = 0x2112A442
MAGIC_COOKIE_HALF = 0x2112
TXID_LEN = 12
HEADER_LEN = 20

TAILSCALE_REQUEST = 0x0001
RFC5389_REQUEST = 0x0003

ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_XOR_MAPPED_ADDRESS_ALT = 0x8020

SOFTWARE = b"tailnode"


def build_stun_request(msg_type, txid):
    software_attr = struct.pack(">H", ATTR_SOFTWARE) + struct.pack(">H", len(SOFTWARE)) + SOFTWARE
    attrs_len = len(software_attr) + 8
    header = struct.pack(">H", msg_type) + struct.pack(">H", attrs_len) + struct.pack(">I", MAGIC_COOKIE) + txid
    fp = (zlib.crc32(header + software_attr) ^ 0x5354554E) & 0xFFFFFFFF
    fingerprint_attr = struct.pack(">H", ATTR_FINGERPRINT) + struct.pack(">H", 4) + struct.pack(">I", fp)
    return header + software_attr + fingerprint_attr


def send_stun_probe(host, port, timeout, retries, msg_type):
    addr = None
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        family = infos[0][0]
        addr = infos[0][4]
        print(f"[resolve] {host} -> {addr[0]} (family={family})")
    except socket.gaierror as e:
        print(f"[resolve] FAILED: cannot resolve {host}: {e}")
        return None

    txid = bytes(random.getrandbits(8) for _ in range(TXID_LEN))
    payload = build_stun_request(msg_type, txid)
    last_err = None

    for attempt in range(1, retries + 1):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET if family == socket.AF_INET else socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            print(f"[send] attempt {attempt}/{retries}: {len(payload)} bytes STUN binding request (type 0x{msg_type:04X}) -> {host}:{port}/UDP")
            sock.sendto(payload, addr)
            data, _ = sock.recvfrom(2048)
            print(f"[recv] {len(data)} bytes from {addr[0]}:{addr[1]}")
            return data, addr, txid
        except socket.timeout:
            last_err = "timeout"
            print(f"[recv] attempt {attempt}: no response (timeout {timeout}s)")
        except OSError as e:
            last_err = str(e)
            print(f"[recv] attempt {attempt}: error {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    print(f"[recv] all attempts failed: {last_err}")
    return None


def is_stun(b):
    return len(b) >= HEADER_LEN and (b[0] & 0xC0) == 0 and b[4:8] == struct.pack(">I", MAGIC_COOKIE)


def foreach_stun_attr(body, fn):
    off = 0
    n = len(body)
    while off + 4 <= n:
        attr_type = struct.unpack(">H", body[off:off + 2])[0]
        attr_len = struct.unpack(">H", body[off + 2:off + 4])[0]
        value = body[off + 4:off + 4 + attr_len]
        attr_len_with_pad = (attr_len + 3) & ~3
        off += 4 + attr_len_with_pad
        fn(attr_type, value)


def xor_mapped(txid, value):
    if len(value) < 4:
        return None
    family = value[1]
    xor_port = struct.unpack(">H", value[2:4])[0]
    port = xor_port ^ MAGIC_COOKIE_HALF
    addr_field = value[4:]
    if family == 0x01:
        addr_len = 4
    elif family == 0x02:
        addr_len = 16
    else:
        return None
    if len(addr_field) < addr_len:
        return None
    xored = addr_field[:addr_len]
    raw = bytearray()
    mc = struct.pack(">I", MAGIC_COOKIE)
    for i in range(addr_len):
        if i < 4:
            raw.append(xored[i] ^ mc[i])
        else:
            raw.append(xored[i] ^ txid[i - 4])
    if family == 0x01:
        ip = socket.inet_ntop(socket.AF_INET, bytes(raw[:4]))
    else:
        ip = socket.inet_ntop(socket.AF_INET6, bytes(raw[:16]))
    return f"{ip}:{port}"


def parse_stun_response(data, txid):
    result = {
        "ok": False,
        "message_type": f"0x{struct.unpack('>H', data[:2])[0]:04X}",
        "magic_cookie": f"0x{struct.unpack('>I', data[4:8])[0]:08X}",
        "message_length": struct.unpack(">H", data[2:4])[0],
        "txn_matches": data[8:20] == txid,
        "public_endpoint": None,
    }

    if not is_stun(data):
        result["reason"] = f"not a STUN packet (magic 0x{struct.unpack('>I', data[4:8])[0]:08X})"
        return result

    if data[0] != 0x01:
        result["reason"] = f"not a success response (class byte 0x{data[0]:02X})"
        return result

    result["ok"] = True
    body = data[20:]

    def collect(attr_type, value):
        if attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS_ALT):
            ep = xor_mapped(txid, value)
            if ep:
                result["public_endpoint"] = ep
        elif attr_type == ATTR_MAPPED_ADDRESS and result["public_endpoint"] is None:
            if len(value) >= 6 and value[1] == 0x01:
                port = struct.unpack(">H", value[2:4])[0]
                ip = ".".join(str(value[4 + i]) for i in range(4))
                result["public_endpoint"] = f"{ip}:{port}"

    try:
        foreach_stun_attr(body, collect)
    except Exception as e:
        result["reason"] = f"attribute parse error: {e}"

    return result


def run_stun(args):
    msg_type = TAILSCALE_REQUEST if args.request_type == "tailscale" else RFC5389_REQUEST
    print(f"== STUN UDP connectivity check: {args.host}:{args.port} (request type 0x{msg_type:04X}) ==")

    result = send_stun_probe(args.host, args.port, args.timeout, args.retries, msg_type)
    if result is None:
        print("\nRESULT: UNREACHABLE - could not complete STUN exchange from this network.")
        return FAIL

    response_data, peer, txid = result
    parsed = parse_stun_response(response_data, txid)
    print(f"\n[parse] message_type={parsed['message_type']} magic={parsed['magic_cookie']} "
          f"len={parsed['message_length']} txn_matches={parsed['txn_matches']}")
    if parsed.get("reason"):
        print(f"[parse] {parsed['reason']}")
    if parsed.get("public_endpoint"):
        print(f"[parse] reflexive public endpoint = {parsed['public_endpoint']}")

    if parsed["ok"]:
        print(f"\nRESULT: REACHABLE - valid STUN binding response from {peer[0]}:{peer[1]}.")
        return OK

    print("\nRESULT: PARTIAL - UDP reachable but response is not a valid STUN binding success response.")
    return PARTIAL


# ---------------------------------------------------------------------------
# TLS (no SSL/TLS inspection)
# ---------------------------------------------------------------------------

# Endpoints that must present a publicly trusted Let's Encrypt certificate.
LETSENCRYPT_TARGETS = [
    ("t01.tunnel.kargo.zone", 443),
    ("sdn.kargo.zone", 443),
]

# edp12.devicecloud.com:3199 is not an HTTPS server, but it does a TLS handshake
# with a Digi certificate that is not in public trust stores, so only the
# certificate subject is checked.
DIGI_TARGET = ("edp12.devicecloud.com", 3199)
DIGI_SUBJECT = [("C", "US"), ("O", "Digi International, Inc."), ("CN", "Digi International Server CA")]

OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}


def name_to_dict(name):
    return {k: v for rdn in name for (k, v) in rdn}


def fmt_name(name):
    return ", ".join(f"{k}={v}" for k, v in name_to_dict(name).items())


def fmt_der_name(attrs):
    return "; ".join(f"{k}={v}" for k, v in attrs)


def der_read(data, off):
    tag = data[off]
    length = data[off + 1]
    off += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, data[off:off + length], off + length


def der_children(data):
    off = 0
    while off < len(data):
        tag, value, off = der_read(data, off)
        yield tag, value


def oid_str(b):
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def parse_der_name(value):
    attrs = []
    for _, rdn in der_children(value):
        for _, atv in der_children(rdn):
            (_, oid), (_, val) = list(der_children(atv))[:2]
            oid = oid_str(oid)
            attrs.append((OID_NAMES.get(oid, oid), val.decode("utf-8", "replace")))
    return attrs


def cert_subject_issuer(der):
    """Return (subject, issuer) as [(attr, value), ...] from an unverified DER cert."""
    _, cert, _ = der_read(der, 0)
    _, tbs, _ = der_read(cert, 0)
    fields = list(der_children(tbs))
    if fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    # serialNumber, signature, issuer, validity, subject
    return parse_der_name(fields[4][1]), parse_der_name(fields[2][1])


def tls_handshake(host, port, ctx, timeout, retries):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return tls.version(), tls.getpeercert(), tls.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError:
            raise
        except (socket.timeout, OSError) as e:
            last_err = e
            print(f"[tls] {host}:{port} attempt {attempt}/{retries}: {type(e).__name__}: {e}")
    raise last_err


def unverified_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_letsencrypt(host, port, timeout, retries):
    print(f"\n-- {host}:{port} (expect Let's Encrypt) --")
    try:
        version, cert, _ = tls_handshake(host, port, ssl.create_default_context(), timeout, retries)
    except ssl.SSLCertVerificationError as e:
        print(f"[verify] FAILED: {e.verify_message}")
        try:
            _, _, der = tls_handshake(host, port, unverified_ctx(), timeout, retries)
            subject, issuer = cert_subject_issuer(der)
            print(f"[cert] presented subject: {fmt_der_name(subject)}")
            print(f"[cert] presented issuer:  {fmt_der_name(issuer)}")
        except (OSError, ValueError, IndexError):
            pass
        print("[check] FAIL - certificate is not publicly trusted (TLS inspection?)")
        return False
    except OSError as e:
        print(f"[check] FAIL - TLS handshake failed: {e}")
        return False

    issuer = name_to_dict(cert["issuer"])
    print(f"[tls] {version}, chain verified, hostname matches")
    print(f"[cert] subject: {fmt_name(cert['subject'])}")
    print(f"[cert] issuer:  {fmt_name(cert['issuer'])}")
    print(f"[cert] valid:   {cert['notBefore']} -> {cert['notAfter']}")
    if issuer.get("organizationName") != "Let's Encrypt":
        print("[check] FAIL - issuer is not Let's Encrypt (TLS inspection?)")
        return False
    print("[check] OK")
    return True


def check_digi(host, port, timeout, retries):
    print(f"\n-- {host}:{port} (expect subject {fmt_der_name(DIGI_SUBJECT)}) --")
    try:
        version, _, der = tls_handshake(host, port, unverified_ctx(), timeout, retries)
    except OSError as e:
        print(f"[check] FAIL - TLS handshake failed: {e}")
        return False

    print(f"[tls] {version}")
    try:
        subject, issuer = cert_subject_issuer(der)
    except (ValueError, IndexError) as e:
        print(f"[check] FAIL - could not parse certificate: {e}")
        return False
    print(f"[cert] subject: {fmt_der_name(subject)}")
    print(f"[cert] issuer:  {fmt_der_name(issuer)}")

    if subject != DIGI_SUBJECT:
        print("[check] FAIL - certificate subject is not the Digi one (TLS inspection?)")
        return False
    print("[check] OK")
    return True


def run_tls(args):
    print("== TLS certificate check (no SSL/TLS inspection) ==")
    results = [check_letsencrypt(h, p, args.timeout, args.retries) for h, p in LETSENCRYPT_TARGETS]
    results.append(check_digi(*DIGI_TARGET, args.timeout, args.retries))

    if not all(results):
        print("\nRESULT: FAIL - unexpected certificate or handshake failure.")
        return FAIL
    print("\nRESULT: OK - all endpoints present the expected certificates.")
    return OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

CHECKS = [
    ("dns", "DNS", run_dns),
    ("tcp", "TCP ports", run_tcp),
    ("stun", "STUN UDP 3478", run_stun),
    ("tls", "TLS / no inspection", run_tls),
]

STATUS = {OK: "PASS", PARTIAL: "PARTIAL", FAIL: "FAIL"}


def run_all(parsers):
    results = []
    for key, name, fn in CHECKS:
        print(f"\n{'#' * 70}\n# {name}\n{'#' * 70}", flush=True)
        try:
            code = fn(parsers[key].parse_args([]))
        except Exception as e:
            print(f"\nRESULT: FAIL - unexpected error: {type(e).__name__}: {e}")
            code = FAIL
        results.append((name, code))

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    for name, code in results:
        print(f"  {STATUS[code]:8} {name}")

    codes = [c for _, c in results]
    if FAIL in codes:
        return FAIL
    return PARTIAL if PARTIAL in codes else OK


def build_parser():
    parser = argparse.ArgumentParser(
        description="Verify the firewall rules Kargo devices need. Runs every check when no command is given.",
    )
    sub = parser.add_subparsers(dest="command", metavar="{all,dns,tcp,stun,tls}")
    sub.add_parser("all", help="run every check (default)")

    p = sub.add_parser("dns", help="sdn.kargo.zone resolves to 13.56.25.183")
    p.add_argument("--server", default=None,
                   help="query this DNS server directly over UDP 53 (e.g. 8.8.8.8); "
                        "default uses the system resolver")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=3)
    p.set_defaults(func=run_dns)

    p = sub.add_parser("tcp", help="outbound TCP ports are open")
    p.add_argument("targets", nargs="*", type=parse_target, metavar="HOST:PORT",
                   help="override the default target list")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=2)
    p.set_defaults(func=run_tcp)

    p = sub.add_parser("stun", help="STUN binding over UDP 3478")
    p.add_argument("--host", default="sdn.kargo.zone")
    p.add_argument("--port", type=int, default=3478)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--request-type", choices=["tailscale", "standard"], default="tailscale",
                   help="tailscale=0x0001 (what tailscaled sends); standard=0x0003 (RFC 5389)")
    p.set_defaults(func=run_stun)

    p = sub.add_parser("tls", help="certificates are not replaced by TLS inspection")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=3)
    p.set_defaults(func=run_tls)

    return parser, sub.choices


def main():
    parser, parsers = build_parser()
    args = parser.parse_args()
    if args.command in (None, "all"):
        sys.exit(run_all(parsers))
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
