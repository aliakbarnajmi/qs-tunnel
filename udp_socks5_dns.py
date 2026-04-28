#!/usr/bin/env python3
"""
UDP DNS TXT Query via SOCKS5 Proxy (Xray/V2Ray)
------------------------------------------------
Source  : Iran        2.144.1.1
Proxy   : Turkey via Xray → 127.0.0.1:10808  (remote: 185.226.92.59)
Dest    : Germany     217.160.172.5 : 53/UDP
Query   : TXT record for  x2xmb67kon7qvdv023q329wi7qzp0kf3bw75us.a.domain.ir

Usage (source server – Iran):
    python3 udp_socks5_dns.py

Usage (destination server – Germany), requires root for port 53:
    python3 udp_socks5_dns.py --listen [port]
"""

import socket
import struct
import random
import time
import sys

# ─────────────────── CONFIG ───────────────────
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 13000            # Local Xray SOCKS5 listener
DST_IP     = "162.222.205.61"
DST_PORT   = 53
DOMAIN     = "x2xmb67kon7qvdv023q329wi7qzp0kf3bw75us.a.domain.ir"
UDP_TIMEOUT = 20
# ──────────────────────────────────────────────


# ══════════════════════════════════════════════
#   DNS PACKET BUILDER
# ══════════════════════════════════════════════

def build_dns_query(domain: str, qtype: int = 16) -> bytes:
    """
    Build a raw DNS query packet.
      qtype = 16  →  TXT  (default)
      qtype =  1  →  A
    """
    txid   = random.randint(0, 65535)
    flags  = 0x0100          # Standard query, Recursion Desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)

    question = b""
    for label in domain.rstrip(".").split("."):
        encoded = label.encode()
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"                        # root label
    question += struct.pack("!HH", qtype, 1)   # QTYPE, QCLASS=IN

    return header + question


def parse_dns_query_name(pkt: bytes) -> str:
    """Quick-and-dirty QNAME parser — skips the 12-byte DNS header."""
    offset, labels = 12, []
    while offset < len(pkt):
        length = pkt[offset]
        if length == 0:
            break
        labels.append(pkt[offset + 1 : offset + 1 + length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(labels)


# ══════════════════════════════════════════════
#   METHOD 1 : SOCKS5 UDP ASSOCIATE  (preferred)
#   RFC 1928 §7
# ══════════════════════════════════════════════

def socks5_udp_associate(proxy_host: str, proxy_port: int):
    """
    Open a SOCKS5 control TCP connection and request UDP ASSOCIATE.

    Returns (tcp_control_sock, relay_ip, relay_port).

    ⚠️  The TCP control socket MUST remain open while UDP traffic flows.
        Closing it will tear down the relay session.
    """
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10)
    tcp.connect((proxy_host, proxy_port))

    # 1) Greeting: VER=5, NMETHODS=1, METHOD=0x00 (NO AUTH)
    tcp.sendall(b"\x05\x01\x00")
    resp = tcp.recv(2)
    if len(resp) < 2 or resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5: auth negotiation failed → {resp.hex()}")

    # 2) UDP ASSOCIATE request
    #    VER CMD RSV ATYP  BND.ADDR(0.0.0.0)  BND.PORT(0)
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = tcp.recv(10)

    if len(resp) < 2 or resp[1] != 0x00:
        codes = {
            0x01: "general failure",
            0x02: "connection not allowed",
            0x03: "network unreachable",
            0x04: "host unreachable",
            0x05: "connection refused",
            0x07: "command not supported",
        }
        rep = resp[1] if len(resp) > 1 else "?"
        raise ConnectionError(
            f"UDP ASSOCIATE rejected — REP={rep:#04x} "
            f"({codes.get(rep, 'unknown')})"
        )

    # Parse BND address (where we should send UDP datagrams)
    atyp = resp[3]
    if atyp == 0x01:          # IPv4
        relay_ip   = socket.inet_ntoa(resp[4:8])
        relay_port = struct.unpack("!H", resp[8:10])[0]
    elif atyp == 0x03:        # domain name
        dlen       = resp[4]
        relay_ip   = resp[5 : 5 + dlen].decode()
        relay_port = struct.unpack("!H", resp[5 + dlen : 7 + dlen])[0]
    else:
        raise ValueError(f"Unexpected ATYP={atyp:#04x} in UDP ASSOCIATE reply")

    # Xray may return 0.0.0.0 → use the proxy IP instead
    if relay_ip in ("0.0.0.0", "::"):
        relay_ip = proxy_host

    return tcp, relay_ip, relay_port


def build_socks5_udp_header(dst_ip: str, dst_port: int) -> bytes:
    """
    SOCKS5 UDP request header (RFC 1928 §7):
      +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   |    4     |    2     | variable |
    """
    return (
        struct.pack("!HBB", 0, 0, 0x01)   # RSV=0, FRAG=0, ATYP=IPv4
        + socket.inet_aton(dst_ip)
        + struct.pack("!H", dst_port)
    )


def send_via_udp_associate(proxy_host, proxy_port, dst_ip, dst_port, domain):
    """Send DNS TXT query using SOCKS5 UDP ASSOCIATE."""
    print("\n[METHOD 1] SOCKS5 UDP ASSOCIATE")
    print(f"  Connecting to Xray SOCKS5 at {proxy_host}:{proxy_port} ...")

    tcp_ctrl, relay_ip, relay_port = socks5_udp_associate(proxy_host, proxy_port)
    print(f"  [+] UDP relay assigned : {relay_ip}:{relay_port}")

    dns_pkt    = build_dns_query(domain)       # TXT query
    udp_hdr    = build_socks5_udp_header(dst_ip, dst_port)
    full_dgram = udp_hdr + dns_pkt

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(UDP_TIMEOUT)

    print(f"  Sending datagram  ({len(full_dgram)} bytes)  →  relay {relay_ip}:{relay_port}")
    print(f"  DNS payload (hex) : {dns_pkt.hex()}")
    print(f"  Final destination : {dst_ip}:{dst_port}  (TXT {domain})")
    udp.sendto(full_dgram, (relay_ip, relay_port))
    print(f"  [+] Sent!  Proxy will forward the UDP packet to {dst_ip}:{dst_port}")

    # Try to receive a response (optional — dest may be a passive listener)
    try:
        data, addr = udp.recvfrom(4096)
        dns_resp = data[10:]    # strip 10-byte SOCKS5 UDP header
        print(f"  [+] Response received ({len(dns_resp)} bytes) from {addr}")
        print(f"      Hex : {dns_resp.hex()}")
    except socket.timeout:
        print(f"  [i] No response within {UDP_TIMEOUT} s — this is normal if the dest is a raw listener")

    udp.close()
    tcp_ctrl.close()   # closes control channel → proxy cleans up UDP relay
    print("  [+] Done.")


# ══════════════════════════════════════════════
#   METHOD 2 : DNS-over-TCP via SOCKS5 CONNECT
#              Fallback when UDP ASSOCIATE is unsupported
# ══════════════════════════════════════════════

def send_via_tcp_connect(proxy_host, proxy_port, dst_ip, dst_port, domain):
    """
    Fallback: tunnel a length-prefixed DNS query over TCP (RFC 1035 §4.2.2)
    via a SOCKS5 CONNECT.  Works even when the proxy blocks UDP ASSOCIATE.
    Requires the destination to listen on TCP/53.
    """
    print("\n[METHOD 2] DNS-over-TCP via SOCKS5 CONNECT  (fallback)")
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10)
    tcp.connect((proxy_host, proxy_port))

    # Auth
    tcp.sendall(b"\x05\x01\x00")
    if tcp.recv(2)[1] != 0x00:
        raise ConnectionError("SOCKS5 NO-AUTH rejected")

    # CONNECT to destination
    req = (b"\x05\x01\x00\x01"
           + socket.inet_aton(dst_ip)
           + struct.pack("!H", dst_port))
    tcp.sendall(req)
    resp = tcp.recv(10)
    if resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5 CONNECT failed, REP={resp[1]:#04x}")
    print(f"  [+] TCP tunnel established  →  {dst_ip}:{dst_port}")

    dns_pkt = build_dns_query(domain)
    # DNS/TCP: 2-byte big-endian length prefix
    tcp.sendall(struct.pack("!H", len(dns_pkt)) + dns_pkt)
    print(f"  [+] DNS TXT query sent ({len(dns_pkt)} bytes)  for  {domain}")

    try:
        raw_len  = tcp.recv(2)
        resp_len = struct.unpack("!H", raw_len)[0]
        resp_data = tcp.recv(resp_len)
        print(f"  [+] DNS response : {resp_data.hex()}")
    except Exception as e:
        print(f"  [i] No response or parse error : {e}")

    tcp.close()
    print("  [+] Done.")


# ══════════════════════════════════════════════
#   DESTINATION SERVER LISTENER
#   Run on Germany server:
#       sudo python udp_socks5_dns.py --listen 53
# ══════════════════════════════════════════════

def start_udp_listener(listen_port: int = 53):
    """
    Passive UDP listener — run this on the DESTINATION server.
    Prints every incoming packet and tries to decode it as a DNS query.
    Root / sudo is required for port 53.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", listen_port))
    except PermissionError:
        sys.exit(f"[!] Cannot bind port {listen_port} — run with sudo / root.")

    print(f"[LISTENER] Listening on UDP 0.0.0.0:{listen_port}  (Ctrl-C to stop)\n")
    while True:
        data, addr = sock.recvfrom(4096)
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}]  ← packet from {addr[0]}:{addr[1]}  ({len(data)} bytes)")
        print(f"         HEX  : {data.hex()}")
        if len(data) >= 12:
            try:
                name = parse_dns_query_name(data)
                qtype_raw = struct.unpack_from("!H", data, 12 + sum(len(l) + 1 for l in name.split(".")) + 1)[0]
                qtypes = {1: "A", 16: "TXT", 28: "AAAA", 5: "CNAME"}
                print(f"         DNS  : QTYPE={qtypes.get(qtype_raw, qtype_raw)}  QNAME={name}")
            except Exception:
                pass
        print()


# ══════════════════════════════════════════════
#   ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":

    if "--listen" in sys.argv:
        idx  = sys.argv.index("--listen")
        port = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else DST_PORT
        start_udp_listener(port)
        sys.exit(0)

    print("=" * 62)
    print("  UDP / DNS TXT → SOCKS5 (Xray)  —  Test Module")
    print("=" * 62)
    print(f"  Source  (Iran)    : 2.144.1.1")
    print(f"  Proxy   (Turkey)  : {PROXY_HOST}:{PROXY_PORT}  → 185.226.92.59")
    print(f"  Dest    (Germany) : {DST_IP}:{DST_PORT}/udp")
    print(f"  Domain            : {DOMAIN}")
    print("=" * 62)

    try:
        send_via_udp_associate(PROXY_HOST, PROXY_PORT, DST_IP, DST_PORT, DOMAIN)
    except Exception as e:
        print(f"\n  [-] UDP ASSOCIATE failed : {e}")
        print("  [*] Retrying with TCP fallback …")
        try:
            send_via_tcp_connect(PROXY_HOST, PROXY_PORT, DST_IP, DST_PORT, DOMAIN)
        except Exception as e2:
            print(f"  [-] TCP fallback also failed : {e2}")
            sys.exit(1)
