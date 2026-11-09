//! Cross-frame analysis: TCP stream tracking, conversations, hosts, findings and
//! an activity timeline.
//!
//! Findings carry a `kind` and parameters only. Wording (beginner and expert,
//! any language) belongs to the interface.

use crate::capture::RawPacket;
use crate::dissect::app::tls_version_name;
use crate::dissect::net::is_private;
use crate::dissect::{Meta, Note, PacketCtx, TcpMeta, L4};
use crate::tree::fmt_mac;
use serde::Serialize;
use serde_json::{json, Value as Json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

pub const TIMELINE_BINS: usize = 120;
pub const CONV_BINS: usize = 48;
pub const GROUPS: [&str; 9] = [
    "secure", "dns", "file", "web", "tcp", "udp", "local", "icmp", "other",
];

/// What the first pass knows about each frame.
pub struct FrameInfo {
    pub meta: Meta,
    pub proto: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Endpoint {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Conversation {
    pub id: u32,
    /// "tcp", "udp", "arp", "icmp" or "other".
    pub transport: &'static str,
    pub a: Endpoint,
    pub b: Endpoint,
    /// Most specific protocol seen, e.g. "TLS", "SMB2", "DNS".
    pub app: String,
    /// Colour group, one of [`GROUPS`].
    pub group: &'static str,
    pub packets: u32,
    pub bytes: u64,
    pub a_to_b: [u64; 2],
    pub b_to_a: [u64; 2],
    pub start: f64,
    pub end: f64,
    pub first_frame: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_stream: Option<u32>,
    /// Handshake round trip (SYN → SYN/ACK), seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt: Option<f64>,
    /// "open", "refused", "no_answer", "closed", "reset" or "" for non-TCP.
    pub state: &'static str,
    pub retrans: u32,
    pub lost: u32,
    pub dup_acks: u32,
    pub zero_win: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    pub dns_queries: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_max_ms: Option<f64>,
    pub bins: Vec<u32>,
    pub severity: &'static str,
}

#[derive(Serialize, Clone, Debug)]
pub struct Host {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Names learnt from DNS answers, TLS SNI, HTTP Host and mDNS.
    pub names: Vec<String>,
    /// "local", "public", "multicast" or "broadcast".
    pub scope: &'static str,
    /// "self", "gateway" or "".
    pub role: &'static str,
    /// Ports this host answered on (it acts as a server there).
    pub services: Vec<u16>,
    pub packets: u32,
    pub bytes: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub kind: &'static str,
    /// "crit", "warn" or "info".
    pub severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conv: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    pub params: Json,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Timeline {
    pub groups: Vec<&'static str>,
    pub bin_width: f64,
    /// bins[i][g] = frames of group g in bin i.
    pub bins: Vec<Vec<u32>>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ProtoCount {
    pub proto: String,
    pub frames: u32,
    pub bytes: u64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Summary {
    pub frames: u32,
    pub bytes: u64,
    pub duration: f64,
    pub start: f64,
    pub protocols: Vec<ProtoCount>,
}

#[derive(Default)]
pub struct Analysis {
    pub ctxs: Vec<PacketCtx>,
    pub conv_of: Vec<Option<u32>>,
    pub convs: Vec<Conversation>,
    pub hosts: Vec<Host>,
    pub findings: Vec<Finding>,
    pub timeline: Timeline,
    pub summary: Summary,
}

#[derive(Default, Clone)]
struct Dir {
    isn: Option<u32>,
    next: Option<u32>,
    last_ack: Option<u32>,
    last_ack_frame: u32,
    last_win: u16,
    dup: u32,
    syn_ws: Option<Option<u8>>,
    data_pkts: u32,
    retrans: u32,
}

#[derive(Default)]
struct Stream {
    a: (Option<IpAddr>, u16),
    dirs: [Dir; 2],
    syn_time: Option<f64>,
    synack_time: Option<f64>,
    hs_done_time: Option<f64>,
    syns: u32,
    synack: bool,
    rst_from_b: bool,
    rst_frame: Option<u32>,
    rst_time: f64,
    fin: bool,
    rst: bool,
    tls: Option<(u16, u32)>,
    lost: u32,
    dup_acks: u32,
    zero_win: u32,
    first_issue: Option<(u32, f64)>,
    last_issue: f64,
    conv: u32,
    packets_b: u32,
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn group_of(app: &str) -> &'static str {
    GROUPS
        .iter()
        .copied()
        .find(|g| *g == app)
        .unwrap_or("other")
}

fn app_label(proto: &str) -> Option<&'static str> {
    Some(match proto {
        p if p.starts_with("TLS") || p.starts_with("SSL") => "TLS",
        "QUIC" => "QUIC",
        "DNS" => "DNS",
        "MDNS" => "mDNS",
        "SMB2" | "NBSS" => "SMB2",
        "SMB" => "SMB",
        "HTTP" => "HTTP",
        "DHCP" => "DHCP",
        "NTP" => "NTP",
        "SSDP" => "SSDP",
        "ARP" => "ARP",
        "ICMP" | "ICMPv6" => "ICMP",
        _ => return None,
    })
}

fn scope_of(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v) if v.is_multicast() => "multicast",
        IpAddr::V4(v) if v.is_broadcast() || v.octets()[3] == 255 => "broadcast",
        IpAddr::V6(v) if v.is_multicast() => "multicast",
        _ if is_private(ip) => "local",
        _ => "public",
    }
}

const WEAK_PASSWORDS: [&str; 10] = [
    "admin", "password", "1234", "12345", "123456", "root", "default", "guest", "0000", "pass",
];

pub fn analyze(packets: &[RawPacket], frames: &[FrameInfo]) -> Analysis {
    let n = packets.len();
    let t0 = packets.first().map(|p| p.ts).unwrap_or(0.0);
    let t_end = packets.iter().map(|p| p.ts).fold(t0, f64::max);
    let duration = (t_end - t0).max(1e-6);
    let mut an = Analysis {
        ctxs: Vec::with_capacity(n),
        conv_of: vec![None; n],
        ..Default::default()
    };

    let mut streams: Vec<Stream> = Vec::new();
    let mut stream_idx: HashMap<(IpAddr, u16, IpAddr, u16), u32> = HashMap::new();
    let mut udp_idx: HashMap<(IpAddr, u16, IpAddr, u16), u32> = HashMap::new();
    let mut conv_idx: HashMap<String, u32> = HashMap::new();
    let mut conv_apps: Vec<HashMap<&'static str, u32>> = Vec::new();
    let mut conv_groups: Vec<HashMap<&'static str, u32>> = Vec::new();
    let mut hosts: BTreeMap<IpAddr, Host> = BTreeMap::new();
    let mut dns_pending: HashMap<(u16, IpAddr, u16, String), (u32, f64)> = HashMap::new();
    let mut dns_times: Vec<(u32, f64, String, u32)> = Vec::new();
    let mut dns_unanswered: Vec<(u32, f64, String, u32)> = Vec::new();
    let mut nxdomain: Vec<(String, u32, u32)> = Vec::new();
    let mut servfail: Vec<(String, u32, u32)> = Vec::new();
    let mut arp_macs: HashMap<IpAddr, Vec<([u8; 6], u32)>> = HashMap::new();
    let mut mac_ip: HashMap<[u8; 6], IpAddr> = HashMap::new();
    let mut basic_auth: Vec<(u32, u32, String, String)> = Vec::new();
    let mut http_clear: HashMap<u32, String> = HashMap::new();
    let mut icmp_unreach: Vec<(u32, f64, String, u8)> = Vec::new();
    let mut syn_targets: HashMap<(IpAddr, IpAddr), HashSet<u16>> = HashMap::new();
    let mut proto_counts: HashMap<String, (u32, u64)> = HashMap::new();
    let mut timeline = vec![vec![0u32; GROUPS.len()]; TIMELINE_BINS];
    let mut convs: Vec<Conversation> = Vec::new();
    let mut prev_ts = t0;

    for (i, (p, fi)) in packets.iter().zip(frames).enumerate() {
        let m = &fi.meta;
        let num = i as u32 + 1;
        let rel = p.ts - t0;
        let mut ctx = PacketCtx {
            number: num,
            rel_time: rel,
            delta: p.ts - prev_ts,
            ..Default::default()
        };
        prev_ts = p.ts;
        let size = p.orig_len as u64;
        let e = proto_counts.entry(fi.proto.clone()).or_default();
        e.0 += 1;
        e.1 += size;
        let bin =
            ((rel / duration) * TIMELINE_BINS as f64).min(TIMELINE_BINS as f64 - 1.0) as usize;
        let group = group_of(m.app);
        timeline[bin][GROUPS.iter().position(|g| *g == group).unwrap()] += 1;

        for (ip, is_src) in [(m.ip_src, true), (m.ip_dst, false)] {
            let Some(ip) = ip else { continue };
            let h = hosts.entry(ip).or_insert_with(|| Host {
                ip: ip.to_string(),
                mac: None,
                names: Vec::new(),
                scope: scope_of(&ip),
                role: "",
                services: Vec::new(),
                packets: 0,
                bytes: 0,
            });
            h.packets += 1;
            h.bytes += size;
            if is_src && h.scope == "local" {
                if let Some(mac) = m.eth_src {
                    h.mac.get_or_insert_with(|| fmt_mac(&mac));
                    mac_ip.entry(mac).or_insert(ip);
                }
            }
        }

        // ---- conversation key
        let (key, transport, a, b) = conv_key(m);
        let cid = if let Some(key) = key {
            let next_id = convs.len() as u32;
            let id = *conv_idx.entry(key).or_insert(next_id);
            if id == next_id {
                let (mut a, mut b) = (a.unwrap(), b.unwrap());
                // TCP: the side that sent the SYN is the initiator.
                if let Some(t) = &m.tcp {
                    if t.has(TcpMeta::SYN) && t.has(TcpMeta::ACK) {
                        std::mem::swap(&mut a, &mut b);
                    }
                }
                convs.push(Conversation {
                    id,
                    transport,
                    a,
                    b,
                    app: String::new(),
                    group: "other",
                    packets: 0,
                    bytes: 0,
                    a_to_b: [0, 0],
                    b_to_a: [0, 0],
                    start: rel,
                    end: rel,
                    first_frame: num,
                    tcp_stream: None,
                    rtt: None,
                    state: "",
                    retrans: 0,
                    lost: 0,
                    dup_acks: 0,
                    zero_win: 0,
                    sni: None,
                    tls_version: None,
                    http_host: None,
                    dns_queries: 0,
                    dns_max_ms: None,
                    bins: vec![0; CONV_BINS],
                    severity: "ok",
                });
                conv_apps.push(HashMap::new());
                conv_groups.push(HashMap::new());
            }
            let c = &mut convs[id as usize];
            c.packets += 1;
            c.bytes += size;
            c.end = rel;
            let from_a = m.ip_src.map(|ip| ip.to_string()) == Some(c.a.ip.clone())
                && (c.a.port.is_none() || c.a.port == Some(m.sport))
                || m.ip_src.is_none()
                    && m.arp.as_ref().and_then(|x| x.sip).map(|x| x.to_string())
                        == Some(c.a.ip.clone());
            let dir = if from_a { &mut c.a_to_b } else { &mut c.b_to_a };
            dir[0] += 1;
            dir[1] += size;
            let cb = ((rel / duration) * CONV_BINS as f64).min(CONV_BINS as f64 - 1.0) as usize;
            c.bins[cb] += 1;
            if let Some(l) = app_label(&fi.proto) {
                *conv_apps[id as usize].entry(l).or_default() += 1;
            }
            *conv_groups[id as usize].entry(group).or_default() += 1;
            an.conv_of[i] = Some(id);
            Some(id)
        } else {
            None
        };

        // ---- TCP stream analysis
        if let (Some(t), Some(src), Some(dst)) = (&m.tcp, m.ip_src, m.ip_dst) {
            let k1 = (src, m.sport, dst, m.dport);
            let k2 = (dst, m.dport, src, m.sport);
            let sid = match stream_idx.get(&k1).or_else(|| stream_idx.get(&k2)) {
                Some(&s) => s,
                None => {
                    let s = streams.len() as u32;
                    stream_idx.insert(k1, s);
                    let mut st = Stream {
                        a: (Some(src), m.sport),
                        conv: cid.unwrap_or(0),
                        ..Default::default()
                    };
                    if t.has(TcpMeta::SYN) && t.has(TcpMeta::ACK) {
                        st.a = (Some(dst), m.dport);
                    }
                    streams.push(st);
                    s
                }
            };
            ctx.tcp_stream = Some(sid);
            if let Some(c) = cid {
                convs[c as usize].tcp_stream = Some(sid);
            }
            let st = &mut streams[sid as usize];
            let d = if st.a == (Some(src), m.sport) { 0 } else { 1 };
            if d == 1 {
                st.packets_b += 1;
            }
            let syn = t.has(TcpMeta::SYN);
            let fin = t.has(TcpMeta::FIN);
            let rst = t.has(TcpMeta::RST);
            let ack = t.has(TcpMeta::ACK);
            if syn {
                st.dirs[d].isn = Some(t.seq);
                st.dirs[d].syn_ws = Some(t.wscale);
                if !ack {
                    st.syns += 1;
                    st.syn_time.get_or_insert(rel);
                    syn_targets.entry((src, dst)).or_default().insert(m.dport);
                } else {
                    st.synack = true;
                    st.synack_time.get_or_insert(rel);
                }
            }
            if st.dirs[d].isn.is_none() {
                st.dirs[d].isn = Some(t.seq.wrapping_sub(1));
            }
            if ack && st.dirs[1 - d].isn.is_none() {
                st.dirs[1 - d].isn = Some(t.ack.wrapping_sub(1));
            }
            ctx.base_seq = st.dirs[d].isn;
            ctx.base_ack = if ack { st.dirs[1 - d].isn } else { None };
            ctx.win_shift = match (&st.dirs[d].syn_ws, &st.dirs[1 - d].syn_ws) {
                (Some(Some(mine)), Some(Some(_))) if !syn => Some(*mine),
                (Some(_), Some(_)) if !syn => Some(0),
                _ => None,
            };
            if rst {
                st.rst = true;
                if d == 1 && st.rst_frame.is_none() {
                    st.rst_from_b = true;
                    st.rst_frame = Some(num);
                    st.rst_time = rel;
                }
            }
            if fin {
                st.fin = true;
            }
            if st.hs_done_time.is_none()
                && !syn
                && ack
                && d == 0
                && st.synack
                && st.syn_time.is_some()
            {
                st.hs_done_time = Some(rel);
            }
            if let (Some(s0), Some(done)) = (st.syn_time, st.hs_done_time) {
                ctx.initial_rtt = Some(done - s0);
            }

            let len = t.payload_len;
            let seglen = len + syn as u32 + fin as u32;
            let dir = &mut st.dirs[d];
            let mut keepalive = false;
            if let Some(next) = dir.next {
                if len <= 1 && !syn && !fin && !rst && t.seq == next.wrapping_sub(1) {
                    keepalive = true;
                    ctx.notes.push(Note::KeepAlive);
                }
            }
            if t.win == 0 && !rst && !syn && !fin {
                ctx.notes.push(Note::ZeroWindow);
                st.zero_win += 1;
            }
            let dir = &mut st.dirs[d];
            if seglen > 0 && !rst {
                if len > 0 {
                    dir.data_pkts += 1;
                }
                match dir.next {
                    Some(next) if !keepalive && seq_lt(t.seq, next) => {
                        ctx.notes.push(Note::Retransmission);
                        dir.retrans += 1;
                    }
                    Some(next) if !keepalive && seq_gt(t.seq, next) => {
                        ctx.notes.push(Note::LostSegment);
                        st.lost += 1;
                    }
                    _ => {}
                }
                let dir = &mut st.dirs[d];
                let end = t.seq.wrapping_add(seglen);
                dir.next = Some(match dir.next {
                    Some(nx) if seq_gt(nx, end) => nx,
                    _ => end,
                });
            }
            let dir = &mut st.dirs[d];
            if ack && len == 0 && !syn && !fin && !rst {
                if dir.last_ack == Some(t.ack) && t.win == dir.last_win && !keepalive {
                    dir.dup += 1;
                    ctx.notes.push(Note::DupAck {
                        of: dir.last_ack_frame,
                        n: dir.dup,
                    });
                    st.dup_acks += 1;
                } else if dir.last_ack != Some(t.ack) {
                    dir.last_ack = Some(t.ack);
                    dir.last_ack_frame = num;
                    dir.dup = 0;
                }
            } else if ack && st.dirs[d].last_ack != Some(t.ack) {
                let dir = &mut st.dirs[d];
                dir.last_ack = Some(t.ack);
                dir.last_ack_frame = num;
                dir.dup = 0;
            }
            st.dirs[d].last_win = t.win;
            if ctx.notes.iter().any(|n| {
                matches!(
                    n,
                    Note::Retransmission | Note::LostSegment | Note::DupAck { .. }
                )
            }) {
                st.first_issue.get_or_insert((num, rel));
                st.last_issue = rel;
            }
            if let Some(tls) = &m.tls {
                if let Some(v) = tls.server_version {
                    if tls.handshakes.contains(&2) && st.tls.is_none() {
                        st.tls = Some((v, num));
                    }
                }
            }
            if let Some((v, from)) = st.tls {
                if num >= from {
                    ctx.tls_version = Some(v);
                }
            }
        }

        // ---- UDP stream index (for udp.stream)
        if m.l4 == L4::Udp {
            if let (Some(src), Some(dst)) = (m.ip_src, m.ip_dst) {
                let k1 = (src, m.sport, dst, m.dport);
                let k2 = (dst, m.dport, src, m.sport);
                let next = udp_idx.len() as u32;
                let id = match udp_idx.get(&k1).or_else(|| udp_idx.get(&k2)) {
                    Some(&s) => s,
                    None => {
                        udp_idx.insert(k1, next);
                        next
                    }
                };
                ctx.udp_stream = Some(id);
            }
        }

        // ---- DNS matching and names
        if let (Some(dns), Some(src), Some(dst)) = (&m.dns, m.ip_src, m.ip_dst) {
            if !dns.mdns {
                if !dns.response {
                    dns_pending.insert((dns.id, src, m.sport, dns.qname.clone()), (num, rel));
                    if let Some(c) = cid {
                        convs[c as usize].dns_queries += 1;
                    }
                } else if let Some((qf, qt)) =
                    dns_pending.remove(&(dns.id, dst, m.dport, dns.qname.clone()))
                {
                    let dt = rel - qt;
                    ctx.dns_time = Some(dt);
                    ctx.dns_response_to = Some(qf);
                    if let Some(qctx) = an.ctxs.get_mut(qf as usize - 1) {
                        qctx.dns_response_in = Some(num);
                    }
                    dns_times.push((num, dt, dns.qname.clone(), cid.unwrap_or(0)));
                    if let Some(c) = cid {
                        let c = &mut convs[c as usize];
                        c.dns_max_ms = Some(c.dns_max_ms.unwrap_or(0.0).max(dt * 1000.0));
                    }
                }
                if dns.response && dns.rcode == 3 {
                    nxdomain.push((dns.qname.clone(), num, cid.unwrap_or(0)));
                }
                if dns.response && dns.rcode == 2 {
                    servfail.push((dns.qname.clone(), num, cid.unwrap_or(0)));
                }
            }
            if dns.response {
                for (name, ip) in &dns.addrs {
                    let label = if dns.mdns {
                        name.trim_end_matches(".local").to_string()
                    } else {
                        dns.qname.clone()
                    };
                    let h = hosts.entry(*ip).or_insert_with(|| Host {
                        ip: ip.to_string(),
                        mac: None,
                        names: Vec::new(),
                        scope: scope_of(ip),
                        role: "",
                        services: Vec::new(),
                        packets: 0,
                        bytes: 0,
                    });
                    if !h.names.contains(&label) {
                        h.names.push(label);
                    }
                }
                if dns.mdns {
                    if let Some(h) = hosts.get_mut(&src) {
                        for t in &dns.ptrs {
                            let inst = t
                                .split("._")
                                .next()
                                .unwrap_or(t)
                                .trim_end_matches(".local")
                                .to_string();
                            if !inst.is_empty()
                                && !inst.starts_with('_')
                                && !h.names.contains(&inst)
                            {
                                h.names.push(inst);
                            }
                        }
                    }
                }
            }
        }

        // ---- TLS SNI, HTTP host and credentials
        if let (Some(tls), Some(dst)) = (&m.tls, m.ip_dst) {
            if let Some(sni) = &tls.sni {
                if let Some(h) = hosts.get_mut(&dst) {
                    if !h.names.contains(sni) {
                        h.names.push(sni.clone());
                    }
                }
                if let Some(c) = cid {
                    convs[c as usize].sni.get_or_insert(sni.clone());
                }
            }
        }
        if let (Some(http), Some(dst)) = (&m.http, m.ip_dst) {
            if let Some(c) = cid {
                if let Some(host) = &http.host {
                    convs[c as usize].http_host.get_or_insert(host.clone());
                    if host.parse::<IpAddr>().is_err() {
                        if let Some(h) = hosts.get_mut(&dst) {
                            let name = host.split(':').next().unwrap_or(host).to_string();
                            if !h.names.contains(&name) {
                                h.names.push(name);
                            }
                        }
                    }
                }
                if let Some(cred) = &http.basic {
                    let (user, pass) = cred.split_once(':').unwrap_or((cred.as_str(), ""));
                    basic_auth.push((c, num, user.to_string(), pass.to_string()));
                }
                if http.method.is_some() {
                    http_clear
                        .entry(c)
                        .or_insert_with(|| http.host.clone().unwrap_or_else(|| dst.to_string()));
                }
            }
        }

        // ---- ARP: who claims which address
        if let Some(arp) = &m.arp {
            if let Some(sip) = arp.sip {
                let v = arp_macs.entry(sip).or_default();
                if !v.iter().any(|(mac, _)| *mac == arp.smac) {
                    v.push((arp.smac, num));
                }
                if v.len() > 1 {
                    ctx.arp_duplicate = true;
                }
                mac_ip.entry(arp.smac).or_insert(sip);
                let h = hosts.entry(sip).or_insert_with(|| Host {
                    ip: sip.to_string(),
                    mac: None,
                    names: Vec::new(),
                    scope: scope_of(&sip),
                    role: "",
                    services: Vec::new(),
                    packets: 0,
                    bytes: 0,
                });
                h.mac.get_or_insert_with(|| fmt_mac(&arp.smac));
            }
        }

        if let (Some((t, c, v6)), Some(src)) = (m.icmp, m.ip_src) {
            if (!v6 && t == 3) || (v6 && t == 1) {
                icmp_unreach.push((num, rel, src.to_string(), c));
            }
        }

        an.ctxs.push(ctx);
    }

    // ---- DNS queries that never got an answer (ignore the last 2 s of the capture)
    for ((_, _, _, name), (frame, t)) in dns_pending {
        if duration - t > 2.0 {
            dns_unanswered.push((frame, t, name, an.conv_of[frame as usize - 1].unwrap_or(0)));
        }
    }

    // ---- finish conversations from stream state
    for st in &streams {
        let c = &mut convs[st.conv as usize];
        c.rtt = match (st.syn_time, st.synack_time) {
            (Some(a), Some(b)) if b >= a => Some(b - a),
            _ => None,
        };
        c.retrans = st.dirs[0].retrans + st.dirs[1].retrans;
        c.lost = st.lost;
        c.dup_acks = st.dup_acks;
        c.zero_win = st.zero_win;
        c.state = if st.syns > 0 && !st.synack && st.rst_from_b {
            "refused"
        } else if st.syns > 0 && !st.synack && st.packets_b == 0 {
            "no_answer"
        } else if st.rst {
            "reset"
        } else if st.fin {
            "closed"
        } else {
            "open"
        };
        c.tls_version = st.tls.map(|(v, _)| tls_version_name(v).to_string());
        if st.synack {
            if let (Some(ip), port) = (c.b.ip.parse::<IpAddr>().ok(), c.b.port) {
                if let (Some(h), Some(port)) = (hosts.get_mut(&ip), port) {
                    if !h.services.contains(&port) {
                        h.services.push(port);
                    }
                }
            }
        }
    }
    for (i, c) in convs.iter_mut().enumerate() {
        let apps = &conv_apps[i];
        c.app = apps
            .iter()
            .max_by_key(|(k, v)| (**v, **k))
            .map(|(k, _)| k.to_string())
            .unwrap_or_else(|| c.transport.to_uppercase());
        if c.app == "TLS" && c.tls_version.is_none() && c.transport == "tcp" {
            c.tls_version = None;
        }
        let groups = &conv_groups[i];
        let pick = groups
            .iter()
            .filter(|(g, _)| !matches!(**g, "tcp" | "udp" | "other"))
            .max_by_key(|(g, v)| (**v, **g))
            .map(|(g, _)| *g);
        c.group = pick
            .or_else(|| {
                groups
                    .iter()
                    .max_by_key(|(g, v)| (**v, **g))
                    .map(|(g, _)| *g)
            })
            .unwrap_or("other");
    }

    // ---- this host and the gateway
    let mut initiated: HashMap<String, u32> = HashMap::new();
    for c in &convs {
        if let Ok(ip) = c.a.ip.parse::<IpAddr>() {
            if scope_of(&ip) == "local" {
                *initiated.entry(c.a.ip.clone()).or_default() += 1;
            }
        }
    }
    let me = initiated
        .iter()
        .max_by_key(|(ip, n)| {
            (
                **n,
                hosts
                    .get(&ip.parse::<IpAddr>().unwrap())
                    .map(|h| h.packets)
                    .unwrap_or(0),
            )
        })
        .map(|(ip, _)| ip.clone());
    if let Some(me_ip) = me.as_ref().and_then(|s| s.parse::<IpAddr>().ok()) {
        if let Some(h) = hosts.get_mut(&me_ip) {
            h.role = "self";
        }
        let mut gw_macs: HashMap<[u8; 6], u32> = HashMap::new();
        for fi in frames {
            let m = &fi.meta;
            if m.ip_src == Some(me_ip)
                && m.ip_dst.map(|d| scope_of(&d) == "public").unwrap_or(false)
            {
                if let Some(mac) = m.eth_dst {
                    *gw_macs.entry(mac).or_default() += 1;
                }
            }
        }
        if let Some((mac, _)) = gw_macs.into_iter().max_by_key(|(_, n)| *n) {
            if let Some(ip) = mac_ip.get(&mac) {
                if let Some(h) = hosts.get_mut(ip) {
                    h.role = "gateway";
                    h.mac.get_or_insert_with(|| fmt_mac(&mac));
                }
            }
        }
    }

    // ---- findings
    let mut f: Vec<Finding> = Vec::new();
    let flag = |convs: &mut Vec<Conversation>, c: u32, sev: &'static str| {
        let s = &mut convs[c as usize].severity;
        let rank = |x: &str| match x {
            "crit" => 3,
            "warn" => 2,
            "info" => 1,
            _ => 0,
        };
        if rank(sev) > rank(s) {
            *s = sev;
        }
    };

    // Refused and unanswered connections, grouped by service.
    let mut refused: BTreeMap<(String, u16), Vec<&Stream>> = BTreeMap::new();
    let mut silent: BTreeMap<(String, u16), Vec<&Stream>> = BTreeMap::new();
    for st in &streams {
        let c = &convs[st.conv as usize];
        let key = (c.b.ip.clone(), c.b.port.unwrap_or(0));
        match c.state {
            "refused" => refused.entry(key).or_default().push(st),
            "no_answer" => silent.entry(key).or_default().push(st),
            _ => {}
        }
    }
    for ((ip, port), list) in refused {
        let first = list[0];
        let rtt = first.syn_time.map(|s| first.rst_time - s).unwrap_or(0.0);
        for st in &list {
            flag(&mut convs, st.conv, "crit");
        }
        f.push(Finding {
            kind: "tcp_refused",
            severity: "crit",
            conv: Some(first.conv),
            frame: first.rst_frame,
            time: Some(first.rst_time),
            params: json!({"host": ip, "port": port, "attempts": list.len(), "reply_ms": (rtt * 1000.0 * 10.0).round() / 10.0,
                            "convs": list.iter().map(|s| s.conv).collect::<Vec<_>>()}),
        });
    }
    for ((ip, port), list) in silent {
        let first = list[0];
        for st in &list {
            flag(&mut convs, st.conv, "warn");
        }
        f.push(Finding {
            kind: "tcp_no_answer",
            severity: "warn",
            conv: Some(first.conv),
            frame: Some(convs[first.conv as usize].first_frame),
            time: first.syn_time,
            params: json!({"host": ip, "port": port, "attempts": list.iter().map(|s| s.syns).sum::<u32>()}),
        });
    }

    // Packet loss.
    for st in &streams {
        let (d, dir) = if st.dirs[0].retrans >= st.dirs[1].retrans {
            (0, &st.dirs[0])
        } else {
            (1, &st.dirs[1])
        };
        let retrans = dir.retrans;
        if retrans < 3 {
            continue;
        }
        let pct = retrans as f64 * 100.0 / dir.data_pkts.max(1) as f64;
        if pct < 0.2 {
            continue;
        }
        let sev = if pct >= 3.0 { "crit" } else { "warn" };
        let c = &convs[st.conv as usize];
        let (from, to) = if d == 0 {
            (c.a.ip.clone(), c.b.ip.clone())
        } else {
            (c.b.ip.clone(), c.a.ip.clone())
        };
        let (frame, start) = st.first_issue.unwrap_or((c.first_frame, c.start));
        let (app, pkts) = (c.app.clone(), dir.data_pkts);
        flag(&mut convs, st.conv, sev);
        f.push(Finding {
            kind: "tcp_loss",
            severity: sev,
            conv: Some(st.conv),
            frame: Some(frame),
            time: Some(start),
            params: json!({"retrans": retrans, "packets": pkts, "pct": (pct * 100.0).round() / 100.0, "from": from, "to": to,
                            "start": start, "end": st.last_issue, "dup_acks": st.dup_acks, "lost": st.lost, "app": app}),
        });
    }
    for st in &streams {
        if st.zero_win > 0 {
            let c = &convs[st.conv as usize];
            let (a, b) = (c.a.ip.clone(), c.b.ip.clone());
            flag(&mut convs, st.conv, "warn");
            f.push(Finding {
                kind: "tcp_zero_window",
                severity: "warn",
                conv: Some(st.conv),
                frame: None,
                time: None,
                params: json!({"count": st.zero_win, "a": a, "b": b}),
            });
        }
    }

    // DNS.
    let mut times: Vec<f64> = dns_times.iter().map(|x| x.1).collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = times.get(times.len() / 2).copied().unwrap_or(0.0);
    let mut slow: Vec<&(u32, f64, String, u32)> = dns_times
        .iter()
        .filter(|x| x.1 > 0.2 && x.1 > median * 4.0)
        .collect();
    slow.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    for (frame, dt, name, conv) in slow.into_iter().take(3) {
        flag(&mut convs, *conv, "warn");
        f.push(Finding {
            kind: "dns_slow",
            severity: "warn",
            conv: Some(*conv),
            frame: Some(*frame),
            time: Some(an.ctxs[*frame as usize - 1].rel_time),
            params: json!({"name": name, "ms": (dt * 1000.0).round(), "median_ms": (median * 1000.0).round(), "answered": times.len()}),
        });
    }
    if !dns_unanswered.is_empty() {
        let (frame, t, _, conv) = dns_unanswered[0].clone();
        flag(&mut convs, conv, "warn");
        let names: Vec<String> = dns_unanswered
            .iter()
            .map(|x| x.2.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        f.push(Finding {
            kind: "dns_unanswered",
            severity: "warn",
            conv: Some(conv),
            frame: Some(frame),
            time: Some(t),
            params: json!({"names": names, "count": dns_unanswered.len()}),
        });
    }
    for (list, kind, sev) in [
        (&servfail, "dns_servfail", "warn"),
        (&nxdomain, "dns_nxdomain", "info"),
    ] {
        if let Some((_, frame, conv)) = list.first() {
            let mut names: Vec<String> = Vec::new();
            for (n, _, _) in list.iter() {
                if !names.contains(n) {
                    names.push(n.clone());
                }
            }
            flag(&mut convs, *conv, sev);
            f.push(Finding {
                kind,
                severity: sev,
                conv: Some(*conv),
                frame: Some(*frame),
                time: Some(an.ctxs[*frame as usize - 1].rel_time),
                params: json!({"names": names}),
            });
        }
    }

    // TLS.
    let mut old_streams = HashSet::new();
    for (si, st) in streams.iter().enumerate() {
        if let Some((v, frame)) = st.tls {
            if v < 0x0303 {
                old_streams.insert(si);
                let c = &convs[st.conv as usize];
                let host = c.sni.clone().unwrap_or_else(|| c.b.ip.clone());
                flag(&mut convs, st.conv, "warn");
                f.push(Finding {
                    kind: "tls_old",
                    severity: "warn",
                    conv: Some(st.conv),
                    frame: Some(frame),
                    time: Some(an.ctxs[frame as usize - 1].rel_time),
                    params: json!({"host": host, "version": tls_version_name(v)}),
                });
            }
        }
    }
    for (i, fi) in frames.iter().enumerate() {
        if let Some(tls) = &fi.meta.tls {
            if let Some((2, desc)) = tls.alert {
                let sid = an.ctxs[i].tcp_stream;
                if sid
                    .map(|s| old_streams.contains(&(s as usize)))
                    .unwrap_or(false)
                {
                    continue;
                }
                let conv = an.conv_of[i];
                let host = conv
                    .map(|c| {
                        convs[c as usize]
                            .sni
                            .clone()
                            .unwrap_or_else(|| convs[c as usize].b.ip.clone())
                    })
                    .unwrap_or_default();
                if let Some(c) = conv {
                    flag(&mut convs, c, "warn");
                }
                f.push(Finding {
                    kind: "tls_alert",
                    severity: "warn",
                    conv,
                    frame: Some(i as u32 + 1),
                    time: Some(an.ctxs[i].rel_time),
                    params: json!({"host": host, "desc": crate::dissect::app::alert_desc(desc), "code": desc}),
                });
            }
        }
    }

    // HTTP credentials and clear-text web.
    let mut auth_convs = HashSet::new();
    for (conv, frame, user, pass) in &basic_auth {
        auth_convs.insert(*conv);
        let c = &convs[*conv as usize];
        let host = c.http_host.clone().unwrap_or_else(|| c.b.ip.clone());
        let weak = pass.is_empty()
            || pass == user
            || WEAK_PASSWORDS.contains(&pass.to_lowercase().as_str());
        flag(&mut convs, *conv, "crit");
        f.push(Finding {
            kind: "http_basic_auth",
            severity: "crit",
            conv: Some(*conv),
            frame: Some(*frame),
            time: Some(an.ctxs[*frame as usize - 1].rel_time),
            params: json!({"host": host, "user": user, "weak_password": weak}),
        });
    }
    for (conv, host) in &http_clear {
        let c = &convs[*conv as usize];
        let public =
            c.b.ip
                .parse::<IpAddr>()
                .map(|ip| scope_of(&ip) == "public")
                .unwrap_or(false);
        if public && !auth_convs.contains(conv) {
            let frame = c.first_frame;
            flag(&mut convs, *conv, "info");
            f.push(Finding {
                kind: "http_cleartext",
                severity: "info",
                conv: Some(*conv),
                frame: Some(frame),
                time: None,
                params: json!({"host": host}),
            });
        }
    }

    // ARP conflicts, port scans, ICMP errors.
    for (ip, macs) in &arp_macs {
        if macs.len() > 1 {
            f.push(Finding {
                kind: "arp_conflict",
                severity: "crit",
                conv: None,
                frame: Some(macs[1].1),
                time: Some(an.ctxs[macs[1].1 as usize - 1].rel_time),
                params: json!({"ip": ip.to_string(), "macs": macs.iter().map(|(m, _)| fmt_mac(m)).collect::<Vec<_>>()}),
            });
        }
    }
    for ((src, dst), ports) in &syn_targets {
        if ports.len() >= 15 {
            f.push(Finding { kind: "port_scan", severity: "crit", conv: None, frame: None, time: None, params: json!({"src": src.to_string(), "dst": dst.to_string(), "ports": ports.len()}) });
        }
    }
    if let Some((frame, t, _, _)) = icmp_unreach.first() {
        let hosts_list: Vec<String> = icmp_unreach
            .iter()
            .map(|x| x.2.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        f.push(Finding {
            kind: "icmp_unreachable",
            severity: "warn",
            conv: an.conv_of[*frame as usize - 1],
            frame: Some(*frame),
            time: Some(*t),
            params: json!({"count": icmp_unreach.len(), "from": hosts_list}),
        });
    }

    let rank = |s: &str| match s {
        "crit" => 0,
        "warn" => 1,
        _ => 2,
    };
    f.sort_by(|a, b| {
        rank(a.severity).cmp(&rank(b.severity)).then(
            a.time
                .unwrap_or(f64::MAX)
                .partial_cmp(&b.time.unwrap_or(f64::MAX))
                .unwrap(),
        )
    });

    let mut protocols: Vec<ProtoCount> = proto_counts
        .into_iter()
        .map(|(proto, (frames, bytes))| ProtoCount {
            proto,
            frames,
            bytes,
        })
        .collect();
    protocols.sort_by(|a, b| b.frames.cmp(&a.frames));
    an.summary = Summary {
        frames: n as u32,
        bytes: packets.iter().map(|p| p.orig_len as u64).sum(),
        duration: t_end - t0,
        start: t0,
        protocols,
    };
    an.timeline = Timeline {
        groups: GROUPS.to_vec(),
        bin_width: duration / TIMELINE_BINS as f64,
        bins: timeline,
    };
    an.convs = convs;
    an.hosts = hosts.into_values().collect();
    an.findings = f;
    an
}

/// Conversation key, transport, and the two endpoints in first-seen order.
fn conv_key(
    m: &Meta,
) -> (
    Option<String>,
    &'static str,
    Option<Endpoint>,
    Option<Endpoint>,
) {
    if let Some(arp) = &m.arp {
        let (Some(s), Some(t)) = (arp.sip, arp.tip) else {
            return (None, "arp", None, None);
        };
        let (x, y) = if s <= t { (s, t) } else { (t, s) };
        let (a, b) = if arp.op == 2 { (t, s) } else { (s, t) };
        return (
            Some(format!("arp|{x}|{y}")),
            "arp",
            Some(Endpoint {
                ip: a.to_string(),
                port: None,
            }),
            Some(Endpoint {
                ip: b.to_string(),
                port: None,
            }),
        );
    }
    let (Some(src), Some(dst)) = (m.ip_src, m.ip_dst) else {
        return (None, "other", None, None);
    };
    let (transport, ports) = match m.l4 {
        L4::Tcp => ("tcp", true),
        L4::Udp => ("udp", true),
        L4::Icmp => ("icmp", false),
        L4::None => ("other", false),
    };
    let ea = Endpoint {
        ip: src.to_string(),
        port: ports.then_some(m.sport),
    };
    let eb = Endpoint {
        ip: dst.to_string(),
        port: ports.then_some(m.dport),
    };
    let (x, y) = if (src, m.sport) <= (dst, m.dport) {
        ((src, m.sport), (dst, m.dport))
    } else {
        ((dst, m.dport), (src, m.sport))
    };
    // UDP services (DNS, NTP, mDNS…) are grouped per client and server: each query uses a new
    // source port, but people think of it as one exchange.
    let service = m.l4 == L4::Udp && (m.dport < 1024 || m.dport == 5353) && m.sport >= 1024;
    let service_rev = m.l4 == L4::Udp && (m.sport < 1024 || m.sport == 5353) && m.dport >= 1024;
    let key = if service {
        format!("udpsvc|{src}|{dst}|{}", m.dport)
    } else if service_rev {
        format!("udpsvc|{dst}|{src}|{}", m.sport)
    } else if ports {
        format!("{transport}|{}|{}|{}|{}", x.0, x.1, y.0, y.1)
    } else {
        format!("{transport}|{}|{}", x.0, y.0)
    };
    (Some(key), transport, Some(ea), Some(eb))
}
