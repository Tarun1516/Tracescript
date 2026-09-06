#!/usr/bin/env python3
"""Generate synthetic .pcap captures for TraceScript tests.

This is for *lab testing only*. The output mimics traffic that an analyst might
observe on a controlled network while investigating forensic scenarios. It is
not a real capture; destination IPs and MAC addresses are arbitrary.

Three files are produced:

    dns_only.pcap        - just DNS queries over UDP/53
    mixed.pcap           - DNS over UDP/TCP plus an HTTP GET
    long_run_c.pcap      - 200 DNS queries (stress test)

The script overwrites existing files. Run it from the test_data directory or
pass an output directory as the only argument.
"""

import argparse
import os
import struct
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE = 1

DNS_PORT = 53


def dns_name(name: str) -> bytes:
    parts = name.split(".")
    out = bytearray()
    for p in parts:
        out.append(len(p))
        out.extend(p.encode("ascii"))
    out.append(0)
    return bytes(out)


def dns_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    txid = 0x1234
    flags = 0x0100
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    q = dns_name(name) + struct.pack(">HH", qtype, qclass)
    return header + q


def ip_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) | header[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_packet(src: str, dst: str, payload: bytes, proto: int = 17) -> bytes:
    src_b = bytes(int(o) for o in src.split("."))
    dst_b = bytes(int(o) for o in dst.split("."))
    total_len = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total_len,
        0x0000, 0x4000,
        64, proto, 0,
        src_b, dst_b,
    )
    chk = ip_checksum(header)
    header = header[:10] + struct.pack(">H", chk) + header[12:]
    return header + payload


def udp_packet(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def tcp_packet(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    """Build a minimal TCP segment with a 20-byte header and the given payload."""
    seq = 1
    ack = 1
    data_off = 5  # 20 bytes
    return struct.pack(
        ">HHIIBBHHH",
        sport, dport, seq, ack,
        (data_off << 4), flags,
        0xFFFF, 0, 0,
    ) + payload


def eth_frame(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def pcap_packet(data: bytes, ts_sec: int, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def write_pcap(path: Path, frames: list[tuple[int, bytes]]) -> None:
    with path.open("wb") as f:
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            0, 0,
            PCAP_SNAPLEN, PCAP_LINKTYPE,
        ))
        for ts, frame in frames:
            f.write(pcap_packet(frame, ts))
    print(f"wrote {path} ({path.stat().st_size} bytes, {len(frames)} frames)")


def make_dns_only(out: Path) -> None:
    src_mac = bytes.fromhex("aabbccddeeff")
    dst_mac = bytes.fromhex("112233445566")
    queries = [
        (1700000000, "192.168.1.10", "example.com", 1, False),
        (1700000005, "192.168.1.12", "suspicious.xyz", 1, True),
        (1700000010, "192.168.1.10", "github.com", 1, False),
        (1700000015, "192.168.1.13", "very-long-suspicious-domain-name-that-exceeds-the-threshold.invalid", 1, True),
        (1700000020, "192.168.1.14", "google.com", 28, False),
        (1700000025, "192.168.1.12", "tracker.evil.tld", 1, False),
        (1700000030, "192.168.1.10", "rust-lang.org", 1, False),
    ]
    frames = []
    for ts, src_ip, qname, qtype, _ in queries:
        dns = dns_query(qname, qtype=qtype)
        udp = udp_packet(54321, DNS_PORT, dns)
        ip = ipv4_packet(src_ip, "192.168.1.1", udp, proto=17)
        frames.append((ts, eth_frame(src_mac, dst_mac, 0x0800, ip)))
    write_pcap(out, frames)


def make_mixed(out: Path) -> None:
    """DNS queries over UDP/TCP plus an HTTP GET."""
    src_mac = bytes.fromhex("aabbccddeeff")
    dst_mac = bytes.fromhex("112233445566")
    frames = []

    # DNS over UDP
    for i, qname in enumerate(["alpha.example", "beta.example", "gamma.xyz"]):
        dns = dns_query(qname)
        udp = udp_packet(53000 + i, DNS_PORT, dns)
        ip = ipv4_packet("192.168.1.10", "192.168.1.1", udp)
        frames.append((1700000100 + i, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # DNS over TCP (DNS message length-prefixed in TCP, but TraceScript ignores the
    # length prefix; the embedded message is still parsed if it lands at the right
    # offset).
    dns = dns_query("over-tcp.example", qtype=1)
    # DNS over TCP is prefixed with a 2-byte length field — pad it.
    tcp_payload = struct.pack(">H", len(dns)) + dns
    tcp = tcp_packet(54000, DNS_PORT, tcp_payload, flags=0x18)
    ip = ipv4_packet("192.168.1.10", "192.168.1.1", tcp, proto=6)
    frames.append((1700000200, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # HTTP GET
    http_req = (
        b"GET /search?q=hello HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: lab-fuzz/1.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    tcp = tcp_packet(54100, 80, http_req, flags=0x18)
    ip = ipv4_packet("192.168.1.20", "10.0.0.1", tcp, proto=6)
    frames.append((1700000300, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # SYN (no payload) — should still register a tcp_connection event with flags=S
    tcp = tcp_packet(54101, 443, b"", flags=0x02)
    ip = ipv4_packet("192.168.1.20", "10.0.0.1", tcp, proto=6)
    frames.append((1700000301, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    write_pcap(out, frames)


def make_long(out: Path, n: int = 200) -> None:
    src_mac = bytes.fromhex("aabbccddeeff")
    dst_mac = bytes.fromhex("112233445566")
    frames = []
    domains = [
        "alpha.com", "beta.com", "gamma.com", "delta.xyz", "epsilon.io",
        "zeta.test", "eta.example", "theta.com", "iota.invalid",
    ]
    for i in range(n):
        qname = f"{i:04d}.{domains[i % len(domains)]}"
        dns = dns_query(qname)
        udp = udp_packet(53000 + (i % 1000), DNS_PORT, dns)
        ip = ipv4_packet(f"192.168.1.{1 + (i % 250)}", "192.168.1.1", udp)
        frames.append((1701000000 + i, eth_frame(src_mac, dst_mac, 0x0800, ip)))
    write_pcap(out, frames)


def make_complex(out: Path) -> None:
    """A 'realistic' capture exercising every supported event:

    - several DNS-over-UDP queries including a couple of suspicious TLDs
    - DNS-over-TCP (with the length prefix) plus its 2-byte TCP SYN
    - HTTP GET with multiple headers
    - a TLS ClientHello-shaped binary payload on port 443 (we don't decode it
      but the runtime emits a `tcp_connection` event with the right flags)
    - a few ICMP ping frames (so a `len > 50` filter actually has something to do)
    - one packet that's a single ARP so the runtime correctly ignores it
    """
    src_mac = bytes.fromhex("aabbccddeeff")
    dst_mac = bytes.fromhex("112233445566")
    frames = []

    # 1. DNS over UDP (multiple queries)
    for i, q in enumerate(
        ["login.example", "evil.xyz", "api.legit", "cdn.legit", "phish.invalid"]
    ):
        dns = dns_query(q)
        udp = udp_packet(53000 + i, DNS_PORT, dns)
        ip = ipv4_packet("10.0.0.5", "8.8.8.8", udp)
        frames.append((1702000000 + i, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # 2. ICMP echo request (large payload so length-filter can hit)
    icmp_payload = b"\x00" * 100
    icmp = bytes([0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]) + icmp_payload
    ip = ipv4_packet("10.0.0.5", "8.8.8.8", icmp, proto=1)
    frames.append((1702000010, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # 3. TCP SYN to port 443 (TLS ClientHello-ish)
    tls_hello = bytes(range(0, 64))  # arbitrary binary
    tcp = tcp_packet(49152, 443, tls_hello, flags=0x02)  # SYN only
    ip = ipv4_packet("10.0.0.5", "1.1.1.1", tcp, proto=6)
    frames.append((1702000020, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # 4. HTTP GET with Host and User-Agent
    http_req = (
        b"GET /api/v1/users/42 HTTP/1.1\r\n"
        b"Host: api.legit\r\n"
        b"User-Agent: lab-bot/2.0\r\n"
        b"Accept: application/json\r\n"
        b"X-Trace-Id: 12345\r\n"
        b"\r\n"
    )
    tcp = tcp_packet(49153, 80, http_req, flags=0x18)  # PSH+ACK
    ip = ipv4_packet("10.0.0.5", "1.1.1.1", tcp, proto=6)
    frames.append((1702000030, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # 5. DNS over TCP (length-prefixed)
    dns_msg = dns_query("over-tcp.legit")
    tcp_payload = struct.pack(">H", len(dns_msg)) + dns_msg
    tcp = tcp_packet(49154, DNS_PORT, tcp_payload, flags=0x18)
    ip = ipv4_packet("10.0.0.5", "8.8.8.8", tcp, proto=6)
    frames.append((1702000040, eth_frame(src_mac, dst_mac, 0x0800, ip)))

    # 6. ARP (ignored by the runtime)
    arp = bytes(28)  # minimal ARP
    frames.append((1702000050, dst_mac + src_mac + struct.pack(">H", 0x0806) + arp))

    write_pcap(out, frames)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("outdir", nargs="?", default=".")
    args = parser.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    make_dns_only(outdir / "dns_only.pcap")
    make_mixed(outdir / "mixed.pcap")
    make_long(outdir / "long_run.pcap", n=200)
    make_complex(outdir / "complex.pcap")


if __name__ == "__main__":
    main()