//! Frame dissection: link layer → network → transport → application.

pub(crate) mod app;
pub(crate) mod net;
mod transport;

use crate::capture::RawPacket;
use crate::tree::{Field, Value};
use serde::Serialize;
use std::net::IpAddr;

/// Facts computed across frames by [`crate::analysis`] and shown inside a frame,
/// the way Wireshark shows `[SEQ/ACK analysis]`.
#[derive(Clone, Debug, Default)]
pub struct PacketCtx {
    pub number: u32,
    pub rel_time: f64,
    pub delta: f64,
    pub tcp_stream: Option<u32>,
    pub udp_stream: Option<u32>,
    pub base_seq: Option<u32>,
    pub base_ack: Option<u32>,
    /// Window scale shift for this sender, once both sides agreed on scaling.
    pub win_shift: Option<u8>,
    pub notes: Vec<Note>,
    pub initial_rtt: Option<f64>,
    /// TLS version negotiated on this stream, known from this frame on.
    pub tls_version: Option<u16>,
    pub dns_time: Option<f64>,
    pub dns_response_in: Option<u32>,
    pub dns_response_to: Option<u32>,
    pub arp_duplicate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Note {
    Retransmission,
    LostSegment,
    DupAck { of: u32, n: u32 },
    ZeroWindow,
    KeepAlive,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum L4 {
    #[default]
    None,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, Default)]
pub struct TcpMeta {
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub win: u16,
    pub wscale: Option<u8>,
    pub mss: Option<u16>,
    pub payload_len: u32,
}

impl TcpMeta {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsMeta {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub qname: String,
    pub qtype: u16,
    /// (name, address) pairs from A/AAAA answers.
    pub addrs: Vec<(String, IpAddr)>,
    /// PTR targets (mDNS service announcements).
    pub ptrs: Vec<String>,
    pub mdns: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TlsMeta {
    pub content_types: Vec<u8>,
    pub handshakes: Vec<u8>,
    pub sni: Option<String>,
    pub client_versions: Vec<u16>,
    /// Version chosen by the server (supported_versions extension, or legacy field).
    pub server_version: Option<u16>,
    pub cipher: Option<u16>,
    pub alert: Option<(u8, u8)>,
    pub record_version: u16,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct HttpMeta {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    /// Decoded "user:password" from a Basic Authorization header.
    pub basic: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ArpMeta {
    pub op: u16,
    pub smac: [u8; 6],
    pub sip: Option<IpAddr>,
    pub tip: Option<IpAddr>,
}

#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub eth_src: Option<[u8; 6]>,
    pub eth_dst: Option<[u8; 6]>,
    pub ip_src: Option<IpAddr>,
    pub ip_dst: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub l4: L4,
    pub sport: u16,
    pub dport: u16,
    pub tcp: Option<TcpMeta>,
    pub dns: Option<DnsMeta>,
    pub tls: Option<TlsMeta>,
    pub http: Option<HttpMeta>,
    pub arp: Option<ArpMeta>,
    pub quic: bool,
    pub smb2: Option<(u16, bool)>,
    pub icmp: Option<(u8, u8, bool)>,
    /// Highest protocol layer, for colours and conversation labels.
    pub app: &'static str,
}

/// One dissected frame.
#[derive(Debug, Default)]
pub struct Dissection {
    pub tree: Vec<Field>,
    pub proto: String,
    pub info: String,
    pub src: String,
    pub dst: String,
    pub meta: Meta,
    /// Protocol stack, e.g. "eth:ethertype:ip:tcp:tls".
    pub stack: Vec<&'static str>,
}

impl Dissection {
    pub(crate) fn set_proto(&mut self, p: impl Into<String>, app: &'static str) {
        self.proto = p.into();
        self.meta.app = app;
    }
    pub(crate) fn malformed(&mut self, at: usize, what: &str) {
        self.tree.push(
            Field::proto(
                "_ws.malformed",
                format!("[Paquet malformé : {what}]"),
                at,
                0,
            )
            .with_note("error"),
        );
        if !self.info.contains("[Malformed") {
            self.info.push_str(" [Malformed Packet]");
        }
    }
}

/// Dissect one frame. `ctx` carries cross-frame facts (pass an empty context for a first pass).
pub fn dissect(p: &RawPacket, ctx: &PacketCtx) -> Dissection {
    let mut d = Dissection {
        proto: "Frame".into(),
        ..Default::default()
    };
    let data = &p.data;
    let mut frame = Field::proto(
        "frame",
        format!(
            "Trame {} : {} octets sur le fil, {} capturés",
            ctx.number,
            p.orig_len,
            data.len()
        ),
        0,
        data.len(),
    );
    frame.push(Field::new(
        "frame.number",
        format!("Numéro : {}", ctx.number),
        Value::Uint(ctx.number as u64),
        0,
        0,
    ));
    frame.push(Field::new(
        "frame.time_relative",
        format!("Temps depuis le début : {:.6} s", ctx.rel_time),
        Value::Float(ctx.rel_time),
        0,
        0,
    ));
    frame.push(Field::new(
        "frame.time_delta",
        format!("Écart avec la trame précédente : {:.6} s", ctx.delta),
        Value::Float(ctx.delta),
        0,
        0,
    ));
    frame.push(Field::new(
        "frame.len",
        format!("Longueur : {} octets", p.orig_len),
        Value::Uint(p.orig_len as u64),
        0,
        0,
    ));
    frame.push(Field::new(
        "frame.cap_len",
        format!("Capturé : {} octets", data.len()),
        Value::Uint(data.len() as u64),
        0,
        0,
    ));
    d.tree.push(frame);
    d.stack.push("frame");

    match p.linktype {
        1 => net::ethernet(data, 0, &mut d, ctx),
        101 | 228 | 229 => net::ip_any(data, 0, &mut d, ctx),
        0 | 108 => {
            // BSD loopback: 4-byte address family in host order.
            if data.len() >= 4 {
                d.tree
                    .push(Field::proto("null", "Boucle locale (BSD)", 0, 4));
                net::ip_any(data, 4, &mut d, ctx);
            }
        }
        113 => {
            if data.len() >= 16 {
                let proto = u16::from_be_bytes([data[14], data[15]]);
                d.tree
                    .push(Field::proto("sll", "Linux cooked capture", 0, 16));
                net::ethertype(proto, data, 16, &mut d, ctx);
            }
        }
        276 => {
            if data.len() >= 20 {
                let proto = u16::from_be_bytes([data[0], data[1]]);
                d.tree
                    .push(Field::proto("sll", "Linux cooked capture v2", 0, 20));
                net::ethertype(proto, data, 20, &mut d, ctx);
            }
        }
        other => {
            d.proto = format!("LINKTYPE {other}");
            d.info = "Type de lien non pris en charge".into();
        }
    }

    // Frame protocols, like Wireshark's frame.protocols.
    let stack = d.stack.join(":");
    if let Some(f) = d.tree.first_mut() {
        f.push(Field::new(
            "frame.protocols",
            format!("Protocoles : {stack}"),
            Value::Str(stack),
            0,
            0,
        ));
    }
    if d.meta.app.is_empty() {
        d.meta.app = "other";
    }
    d
}

// ---- small byte helpers shared by dissectors ----

pub(crate) fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
pub(crate) fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
