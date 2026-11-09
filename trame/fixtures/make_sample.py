#!/usr/bin/env python3
"""Generate fixtures/sample.pcapng: a 14-second office capture used by tests and the demo.

Scenario (all addresses are private or from documentation ranges, except the
well-known public resolver and GitHub's API address):
  * ARP between this host and the home router
  * DNS lookups (one slow answer, one NXDOMAIN for wpad.lan)
  * TLS 1.3 session to api.github.com
  * SMB2 file copy from a NAS with a burst of packet loss
  * Three refused connections to 203.0.113.50:8080
  * A server that only speaks TLS 1.0
  * QUIC video stream
  * mDNS printer announcements
  * Plain HTTP request with Basic credentials to an IP camera

Requires scapy. Run: python3 fixtures/make_sample.py
"""
import os
import random
import struct

from scapy.all import (ARP, DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP,
                       wrpcapng)

random.seed(20261109)
OUT = os.path.join(os.path.dirname(__file__), "sample.pcapng")

ME_MAC, GW_MAC = "a4:83:e7:2c:91:0f", "e4:9e:12:5b:03:a8"
NAS_MAC, PRN_MAC, CAM_MAC = "00:11:32:7a:4c:e1", "30:05:5c:12:9a:77", "bc:32:5f:01:22:9d"
ME, GW, NAS, PRN, CAM = "192.168.1.24", "192.168.1.1", "192.168.1.40", "192.168.1.52", "192.168.1.60"
DNS_SRV, GH, CDN, OLD, DEV = "1.1.1.1", "140.82.121.6", "198.51.100.80", "198.51.100.23", "203.0.113.50"

T0 = 1793430000.0  # 2026-10-31 (any fixed epoch works)
pkts = []


def add(t, p):
    p.time = T0 + t
    pkts.append(p)


def eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def out(dst_ip_mac=GW_MAC):
    return eth(ME_MAC, dst_ip_mac)


def inn(src_mac=GW_MAC):
    return eth(src_mac, ME_MAC)


# ---------------------------------------------------------------- TLS helpers
def tls_record(ctype, body, version=0x0303):
    return struct.pack("!BHH", ctype, version, len(body)) + body


def handshake(htype, body):
    return struct.pack("!B", htype) + len(body).to_bytes(3, "big") + body


def ext(etype, data):
    return struct.pack("!HH", etype, len(data)) + data


def client_hello(sni, versions=(0x0304, 0x0303), alpn=(b"h2", b"http/1.1")):
    sni_b = sni.encode()
    server_name = struct.pack("!H", len(sni_b) + 3) + b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
    sv = bytes([len(versions) * 2]) + b"".join(struct.pack("!H", v) for v in versions)
    alpn_list = b"".join(bytes([len(a)]) + a for a in alpn)
    exts = (ext(0, server_name) + ext(43, sv) + ext(16, struct.pack("!H", len(alpn_list)) + alpn_list)
            + ext(10, b"\x00\x04\x00\x1d\x00\x17") + ext(13, b"\x00\x04\x04\x03\x08\x04"))
    suites = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030]
    body = (struct.pack("!H", 0x0303) + bytes(random.getrandbits(8) for _ in range(32)) + b"\x20"
            + bytes(random.getrandbits(8) for _ in range(32))
            + struct.pack("!H", len(suites) * 2) + b"".join(struct.pack("!H", s) for s in suites)
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return tls_record(22, handshake(1, body), 0x0301)


def server_hello(suite, legacy=0x0303, selected=None):
    exts = ext(43, struct.pack("!H", selected)) if selected else b""
    body = (struct.pack("!H", legacy) + bytes(random.getrandbits(8) for _ in range(32)) + b"\x00"
            + struct.pack("!H", suite) + b"\x00")
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    return tls_record(22, handshake(2, body), legacy if legacy < 0x0303 else 0x0303)


def app_data(n):
    return tls_record(23, bytes(random.getrandbits(8) for _ in range(n)))


# ---------------------------------------------------------------- TCP session helper
class Tcp:
    def __init__(self, cip, cport, sip, sport, cmac_out, smac_in, isn_c=None, isn_s=None):
        self.c, self.cp, self.s, self.sp = cip, cport, sip, sport
        self.mo, self.mi = cmac_out, smac_in
        self.cs = isn_c if isn_c is not None else random.getrandbits(32)
        self.ss = isn_s if isn_s is not None else random.getrandbits(32)

    def c2s(self, t, flags, data=b"", win=2058, opts=None, seq=None, advance=True):
        s = self.cs if seq is None else seq
        p = self.mo / IP(src=self.c, dst=self.s, ttl=64) / TCP(sport=self.cp, dport=self.sp, flags=flags, seq=s,
                                                             ack=self.ss if "A" in flags else 0, window=win,
                                                             options=opts or [])
        if data:
            p = p / Raw(data)
        add(t, p)
        if advance and seq is None:
            self.cs = (self.cs + len(data) + (1 if ("S" in flags or "F" in flags) else 0)) & 0xFFFFFFFF
        return p

    def s2c(self, t, flags, data=b"", win=501, opts=None, seq=None, ttl=52, advance=True):
        s = self.ss if seq is None else seq
        p = self.mi / IP(src=self.s, dst=self.c, ttl=ttl) / TCP(sport=self.sp, dport=self.cp, flags=flags, seq=s,
                                                              ack=self.cs if "A" in flags else 0, window=win,
                                                              options=opts or [])
        if data:
            p = p / Raw(data)
        add(t, p)
        if advance and seq is None:
            self.ss = (self.ss + len(data) + (1 if ("S" in flags or "F" in flags) else 0)) & 0xFFFFFFFF
        return p


SYN_OPTS = [("MSS", 1460), ("NOP", None), ("WScale", 6), ("SAckOK", b"")]

# ---------------------------------------------------------------- ARP
for i in range(8):
    t = 0.15 + i * 1.7
    add(t, eth(ME_MAC, "ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=ME_MAC, psrc=ME, pdst=GW))
    add(t + 0.0012, eth(GW_MAC, ME_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW, hwdst=ME_MAC, pdst=ME))


# ---------------------------------------------------------------- DNS
def dns_pair(t, qname, qtype, answer, delay, qid, sport, rcode=0, ttl=60):
    q = out() / IP(src=ME, dst=DNS_SRV) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    add(t, q)
    an = DNSRR(rrname=qname, type=qtype, ttl=ttl, rdata=answer) if answer else None
    r = inn() / IP(src=DNS_SRV, dst=ME, ttl=57) / UDP(sport=53, dport=sport) / DNS(
        id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an)
    add(t + delay, r)


dns_pair(0.401, "api.github.com", "A", GH, 0.017, 0x3f1a, 61002)
dns_pair(0.402, "api.github.com", "AAAA", None, 0.016, 0x3f1b, 61003)
dns_pair(2.110, "wpad.lan", "A", None, 0.021, 0x5512, 61004, rcode=3)
dns_pair(4.990, "video.cdn-exemple.net", "A", CDN, 0.412, 0x8c02, 61005, ttl=30)
dns_pair(9.380, "portail.exemple.org", "A", OLD, 0.016, 0x9a31, 61006, ttl=3600)
for k in range(10):
    dns_pair(1.0 + k * 1.15, f"telemetry{k % 3}.exemple.net", "A", f"198.51.100.{120 + k % 3}",
             0.012 + random.random() * 0.012, 0xa000 + k, 61100 + k)

# ---------------------------------------------------------------- TLS 1.3 to GitHub
gh = Tcp(ME, 52814, GH, 443, out(), inn())
gh.c2s(0.421, "S", opts=SYN_OPTS, win=65535)
gh.s2c(0.447, "SA", opts=[("MSS", 1436), ("NOP", None), ("WScale", 10), ("SAckOK", b"")], win=65535)
gh.c2s(0.447, "A")
gh.c2s(0.449, "PA", client_hello("api.github.com"))
gh.s2c(0.476, "PA", server_hello(0x1301, selected=0x0304) + tls_record(20, b"\x01") + app_data(1100))
gh.c2s(0.478, "PA", tls_record(20, b"\x01") + app_data(53))
gh.c2s(0.481, "PA", app_data(412))
t = 0.533
for i in range(60):
    gh.s2c(t, "A", app_data(1380))
    if i % 2:
        gh.c2s(t + 0.0004, "A")
    t += 0.0019
gh.c2s(6.802, "FA")
gh.s2c(6.828, "FA")
gh.c2s(6.828, "A")


# ---------------------------------------------------------------- SMB2 copy from the NAS, with losses
def smb2(cmd, response, payload=b"", msg_id=0):
    flags = 1 if response else 0
    hdr = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, 0, cmd, 1, flags, 0, msg_id, 0, 0, 0x4000_0000_0001)
           + b"\x00" * 16)
    body = hdr + payload
    return struct.pack("!I", len(body)) + body  # NetBIOS session header (type 0)


nas = Tcp(ME, 50211, NAS, 445, eth(ME_MAC, NAS_MAC), eth(NAS_MAC, ME_MAC))
nas.c2s(1.102, "S", opts=SYN_OPTS, win=65535)
nas.s2c(1.1029, "SA", opts=[("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", b"")], win=65160, ttl=64)
nas.c2s(1.1031, "A")
nas.c2s(1.105, "PA", smb2(0, False, b"\x24\x00" + b"\x00" * 34, 0))
nas.s2c(1.106, "PA", smb2(0, True, b"\x41\x00\x01\x00\x11\x03" + b"\x00" * 58, 0), ttl=64)
nas.c2s(1.121, "PA", smb2(8, False, b"\x31\x00" + b"\x00" * 46, 1))
SEG = 1448
n_seg = 1400
t = 1.122
lost = set(range(520, 532))  # a burst of losses around 4.9 s
recovered = []
for i in range(n_seg):
    seq = nas.ss
    data = bytes(random.getrandbits(8) for _ in range(SEG)) if i == 0 else os.urandom(SEG)
    if i in lost:
        recovered.append((seq, data))
        nas.ss = (nas.ss + SEG) & 0xFFFFFFFF
    else:
        nas.s2c(t, "A", data, ttl=64)
        if recovered and i == max(lost) + 1:
            # receiver complains with duplicate ACKs for the first missing byte
            first_missing = recovered[0][0]
            for d in range(3):
                add(t + 0.0002 + d * 0.0003, eth(ME_MAC, NAS_MAC) / IP(src=ME, dst=NAS) / TCP(
                    sport=50211, dport=445, flags="A", seq=nas.cs, ack=first_missing, window=2058))
            for k, (rseq, rdata) in enumerate(recovered):
                nas.s2c(t + 0.021 + k * 0.004, "A", rdata, seq=rseq, ttl=64, advance=False)
            t += 0.021 + len(recovered) * 0.004
            recovered = []
        if i % 2 == 1:
            nas.c2s(t + 0.0001, "A")
    t += 0.0091 if 500 <= i < 560 else 0.0088
nas.c2s(13.902, "FA")
nas.s2c(13.903, "FA", ttl=64)
nas.c2s(13.903, "A")

# ---------------------------------------------------------------- refused connections
for k, (t, port) in enumerate([(3.201, 51522), (3.712, 51523), (4.713, 51524)]):
    s = Tcp(ME, port, DEV, 8080, out(), inn())
    s.c2s(t, "S", opts=SYN_OPTS, win=64240)
    s.s2c(t + 0.017, "RA", win=0)

# ---------------------------------------------------------------- server stuck on TLS 1.0
old = Tcp(ME, 52990, OLD, 443, out(), inn())
old.c2s(9.401, "S", opts=SYN_OPTS, win=64240)
old.s2c(9.432, "SA", opts=[("MSS", 1380)], win=8192, ttl=49)
old.c2s(9.432, "A")
old.c2s(9.434, "PA", client_hello("portail.exemple.org", versions=(0x0304, 0x0303)))
old.s2c(9.466, "PA", server_hello(0x002f, legacy=0x0301), ttl=49)
old.c2s(9.467, "PA", tls_record(21, b"\x02\x46"))
old.c2s(9.468, "FA")
old.s2c(9.499, "FA", ttl=49)
old.c2s(9.499, "A")

# ---------------------------------------------------------------- QUIC video
dcid = bytes(random.getrandbits(8) for _ in range(8))
scid = bytes(random.getrandbits(8) for _ in range(8))


def quic_long(ptype, dc, sc, n):
    first = 0xC0 | (ptype << 4) | 0x01
    hdr = bytes([first]) + struct.pack("!I", 1) + bytes([len(dc)]) + dc + bytes([len(sc)]) + sc
    if ptype == 0:
        hdr += b"\x00"  # token length
    return hdr + struct.pack("!H", 0x4000 | n) + os.urandom(n)  # length (2-byte varint) + protected payload


add(5.403, out() / IP(src=ME, dst=CDN) / UDP(sport=60311, dport=443) / Raw(quic_long(0, dcid, scid, 1200)))
add(5.434, inn() / IP(src=CDN, dst=ME, ttl=55) / UDP(sport=443, dport=60311) / Raw(quic_long(0, scid, dcid, 1200)))
add(5.435, inn() / IP(src=CDN, dst=ME, ttl=55) / UDP(sport=443, dport=60311) / Raw(quic_long(2, scid, dcid, 900)))
add(5.436, out() / IP(src=ME, dst=CDN) / UDP(sport=60311, dport=443) / Raw(quic_long(2, dcid, scid, 90)))
t = 5.47
while t < 14.15:
    add(t, inn() / IP(src=CDN, dst=ME, ttl=55) / UDP(sport=443, dport=60311) / Raw(bytes([0x40 | 0x01]) + scid + os.urandom(1300)))
    if random.random() < 0.12:
        add(t + 0.0005, out() / IP(src=ME, dst=CDN) / UDP(sport=60311, dport=443) / Raw(bytes([0x41]) + dcid + os.urandom(40)))
    t += 0.011 + random.random() * 0.01

# ---------------------------------------------------------------- mDNS printer
for k in range(6):
    add(0.9 + k * 2.3, eth(PRN_MAC, "01:00:5e:00:00:fb") / IP(src=PRN, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=DNSRR(rrname="_ipp._tcp.local", type="PTR", ttl=4500, rdata="Imprimante-Bureau._ipp._tcp.local")))

# ---------------------------------------------------------------- HTTP with Basic credentials to a camera
cam = Tcp(ME, 53400, CAM, 80, eth(ME_MAC, CAM_MAC), eth(CAM_MAC, ME_MAC))
cam.c2s(7.800, "S", opts=SYN_OPTS, win=64240)
cam.s2c(7.802, "SA", opts=[("MSS", 1460)], win=5840, ttl=64)
cam.c2s(7.802, "A")
cam.c2s(7.803, "PA", b"GET /snapshot.jpg HTTP/1.1\r\nHost: 192.168.1.60\r\nUser-Agent: curl/8.5.0\r\n"
                     b"Authorization: Basic YWRtaW46YWRtaW4=\r\nAccept: */*\r\n\r\n")
cam.s2c(7.840, "PA", b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 1200\r\n\r\n" + os.urandom(1200), ttl=64)
cam.c2s(7.841, "A")
cam.c2s(7.900, "FA")
cam.s2c(7.901, "FA", ttl=64)
cam.c2s(7.901, "A")

pkts.sort(key=lambda p: p.time)
wrpcapng(OUT, pkts)
print(f"wrote {OUT}: {len(pkts)} packets, {os.path.getsize(OUT) / 1e6:.1f} MB")
