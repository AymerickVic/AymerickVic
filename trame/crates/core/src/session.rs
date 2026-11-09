//! An opened capture: the API used by the CLI, the WebAssembly build and the desktop app.

use crate::analysis::{analyze, Analysis, FrameInfo};
use crate::capture::{self, CaptureError, RawPacket};
use crate::dissect::{dissect, Dissection, Note, PacketCtx, TcpMeta, L4};
use crate::filter::{Filter, FilterError};
use serde::Serialize;
use serde_json::{json, Value as Json};

#[derive(Serialize, Clone, Debug)]
pub struct Row {
    pub n: u32,
    pub t: f64,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub len: u32,
    pub info: String,
    /// Colour group of the frame.
    pub g: &'static str,
    /// Expert flag: "warn" or "error" when the frame carries an analysis note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<&'static str>,
}

pub struct Session {
    pub format: &'static str,
    pub truncated: bool,
    packets: Vec<RawPacket>,
    rows: Vec<Row>,
    analysis: Analysis,
    cache: Option<(String, Vec<u32>)>,
}

impl Session {
    pub fn open(bytes: &[u8]) -> Result<Session, CaptureError> {
        let cap = capture::read(bytes)?;
        // Pass 1: per-frame facts.
        let frames: Vec<FrameInfo> = cap
            .packets
            .iter()
            .map(|p| {
                let d = dissect(p, &PacketCtx::default());
                FrameInfo {
                    meta: d.meta,
                    proto: d.proto,
                }
            })
            .collect();
        // Cross-frame analysis.
        let analysis = analyze(&cap.packets, &frames);
        // Pass 2: display rows with the analysis applied.
        let rows = cap
            .packets
            .iter()
            .zip(&analysis.ctxs)
            .map(|(p, ctx)| {
                let d = dissect(p, ctx);
                row(&d, p, ctx)
            })
            .collect();
        Ok(Session {
            format: cap.format,
            truncated: cap.truncated,
            packets: cap.packets,
            rows,
            analysis,
            cache: None,
        })
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn analysis(&self) -> &Analysis {
        &self.analysis
    }

    /// Everything the summary and map views need.
    pub fn overview(&self) -> Json {
        let a = &self.analysis;
        json!({
            "format": self.format,
            "truncated": self.truncated,
            "summary": a.summary,
            "hosts": a.hosts,
            "convs": a.convs,
            "findings": a.findings,
            "timeline": a.timeline,
        })
    }

    pub fn dissect(&self, n: u32) -> Option<Dissection> {
        let i = n.checked_sub(1)? as usize;
        Some(dissect(self.packets.get(i)?, &self.analysis.ctxs[i]))
    }

    /// Frame numbers matching a display filter (empty filter = every frame).
    pub fn select(&mut self, filter: &str) -> Result<&[u32], FilterError> {
        let filter = filter.trim();
        if self.cache.as_ref().map(|c| c.0 != filter).unwrap_or(true) {
            let list: Vec<u32> = if filter.is_empty() {
                (1..=self.packets.len() as u32).collect()
            } else {
                let f = Filter::parse(filter)?;
                self.packets
                    .iter()
                    .zip(&self.analysis.ctxs)
                    .enumerate()
                    .filter(|(_, (p, ctx))| f.matches(&dissect(p, ctx).tree))
                    .map(|(i, _)| i as u32 + 1)
                    .collect()
            };
            self.cache = Some((filter.to_string(), list));
        }
        Ok(&self.cache.as_ref().unwrap().1)
    }

    /// One page of the packet list.
    pub fn rows(&mut self, filter: &str, offset: usize, limit: usize) -> Result<Json, FilterError> {
        let total = self.packets.len();
        let list = self.select(filter)?.to_vec();
        let page: Vec<&Row> = list
            .iter()
            .skip(offset)
            .take(limit)
            .map(|n| &self.rows[*n as usize - 1])
            .collect();
        Ok(json!({"total": total, "matched": list.len(), "offset": offset, "rows": page}))
    }

    /// Position of a frame in the current filtered list.
    pub fn index_of(&mut self, filter: &str, frame: u32) -> Result<Option<usize>, FilterError> {
        Ok(self.select(filter)?.binary_search(&frame).ok())
    }

    /// Field tree and raw bytes of one frame.
    pub fn frame(&self, n: u32) -> Option<Json> {
        let d = self.dissect(n)?;
        let p = &self.packets[n as usize - 1];
        Some(json!({
            "n": n,
            "row": self.rows[n as usize - 1],
            "tree": d.tree,
            "bytes": crate::dissect::hex(&p.data),
            "conv": self.analysis.conv_of[n as usize - 1],
        }))
    }

    /// The exchange inside one conversation, as a short list of events for a sequence diagram.
    pub fn conversation(&self, id: u32, max: usize) -> Option<Json> {
        let c = self.analysis.convs.get(id as usize)?;
        let mut events: Vec<Json> = Vec::new();
        let mut handshake_open = true;
        for (i, conv) in self.analysis.conv_of.iter().enumerate() {
            if *conv != Some(id) {
                continue;
            }
            let p = &self.packets[i];
            let ctx = &self.analysis.ctxs[i];
            let d = dissect(p, ctx);
            let m = &d.meta;
            let src_ip = m
                .ip_src
                .map(|x| x.to_string())
                .or_else(|| m.arp.as_ref().and_then(|a| a.sip).map(|x| x.to_string()));
            let from_a = src_ip.as_deref() == Some(c.a.ip.as_str())
                && (c.a.port.is_none() || c.a.port == Some(m.sport));
            let dir = if from_a { "ab" } else { "ba" };
            let mut detail = json!({});
            let kind: &str = event_kind(&d, ctx, &mut detail, &mut handshake_open);
            if kind == "ack_quiet" {
                if let Some(last) = events.last_mut() {
                    let acks = last["acks"].as_u64().unwrap_or(0) + 1;
                    last["acks"] = json!(acks);
                }
                continue;
            }
            let mergeable = matches!(
                kind,
                "data" | "tls_data" | "quic_data" | "retrans" | "dupack" | "ack"
            );
            if mergeable {
                if let Some(last) = events.last_mut() {
                    if last["kind"] == kind && last["dir"] == dir {
                        last["count"] = json!(last["count"].as_u64().unwrap_or(1) + 1);
                        last["bytes"] =
                            json!(last["bytes"].as_u64().unwrap_or(0) + p.orig_len as u64);
                        last["t_end"] = json!(ctx.rel_time);
                        continue;
                    }
                }
            }
            events.push(json!({
                "frame": i + 1, "t": ctx.rel_time, "dir": dir, "kind": kind, "proto": d.proto, "info": d.info,
                "count": 1, "bytes": p.orig_len, "detail": detail,
            }));
        }
        let total = events.len();
        if total > max {
            let head = max * 2 / 3;
            let tail = max - head - 1;
            let skipped = total - head - tail;
            let mut kept: Vec<Json> = events[..head].to_vec();
            kept.push(json!({"kind": "gap", "count": skipped, "t": events[head]["t"], "dir": "ab", "frame": events[head]["frame"]}));
            kept.extend_from_slice(&events[total - tail..]);
            events = kept;
        }
        Some(json!({"conv": c, "events": events}))
    }
}

fn row(d: &Dissection, p: &RawPacket, ctx: &PacketCtx) -> Row {
    let malformed = d.tree.iter().any(|f| f.name == "_ws.malformed");
    let alert = d
        .meta
        .tls
        .as_ref()
        .and_then(|t| t.alert)
        .map(|a| a.0 == 2)
        .unwrap_or(false);
    let rst = d
        .meta
        .tcp
        .as_ref()
        .map(|t| t.has(TcpMeta::RST))
        .unwrap_or(false);
    let x = if malformed || alert || rst || ctx.arp_duplicate {
        Some("error")
    } else if !ctx.notes.is_empty()
        || d.meta
            .dns
            .as_ref()
            .map(|x| x.response && x.rcode != 0)
            .unwrap_or(false)
    {
        Some("warn")
    } else {
        None
    };
    Row {
        n: ctx.number,
        t: ctx.rel_time,
        src: d.src.clone(),
        dst: d.dst.clone(),
        proto: d.proto.clone(),
        len: p.orig_len,
        info: d.info.clone(),
        g: crate::analysis::GROUPS
            .iter()
            .copied()
            .find(|g| *g == d.meta.app)
            .unwrap_or("other"),
        x,
    }
}

fn event_kind(
    d: &Dissection,
    ctx: &PacketCtx,
    detail: &mut Json,
    handshake_open: &mut bool,
) -> &'static str {
    let m = &d.meta;
    if let Some(a) = &m.arp {
        return if a.op == 2 {
            "arp_reply"
        } else {
            "arp_request"
        };
    }
    if let Some(dns) = &m.dns {
        *detail = json!({"name": dns.qname, "rcode": dns.rcode, "ms": ctx.dns_time.map(|t| (t * 10000.0).round() / 10.0),
                          "answers": dns.addrs.iter().map(|(_, ip)| ip.to_string()).collect::<Vec<_>>()});
        return if !dns.response {
            "dns_query"
        } else if dns.rcode != 0 {
            "dns_error"
        } else if ctx.dns_time.map(|t| t > 0.2).unwrap_or(false) {
            "dns_slow"
        } else {
            "dns_response"
        };
    }
    if m.l4 == L4::Icmp {
        return "icmp";
    }
    if m.quic {
        return if d.info.starts_with("Protected") {
            "quic_data"
        } else {
            "quic_handshake"
        };
    }
    if let Some(t) = &m.tcp {
        if ctx.notes.contains(&Note::Retransmission) {
            return "retrans";
        }
        if ctx.notes.iter().any(|n| matches!(n, Note::DupAck { .. })) {
            return "dupack";
        }
        if t.has(TcpMeta::RST) {
            return "rst";
        }
        if t.has(TcpMeta::SYN) {
            *detail = json!({"mss": t.mss, "port": m.dport});
            return if t.has(TcpMeta::ACK) { "synack" } else { "syn" };
        }
        let lost = ctx.notes.contains(&Note::LostSegment);
        if lost {
            *detail = json!({"lost": true});
        }
        if t.has(TcpMeta::FIN) {
            return "fin";
        }
        if t.payload_len == 0 {
            if *handshake_open {
                *handshake_open = false;
                return "ack";
            }
            return "ack_quiet";
        }
        *handshake_open = false;
        if let Some(tls) = &m.tls {
            if let Some((lvl, desc)) = tls.alert {
                *detail = json!({"level": lvl, "desc": crate::dissect::app::alert_desc(desc)});
                return "tls_alert";
            }
            if tls.handshakes.contains(&1) {
                *detail = json!({"sni": tls.sni, "versions": tls.client_versions.iter().map(|v| crate::dissect::app::tls_version_name(*v)).collect::<Vec<_>>()});
                return "tls_client_hello";
            }
            if tls.handshakes.contains(&2) {
                *detail = json!({"version": tls.server_version.map(crate::dissect::app::tls_version_name)});
                return "tls_server_hello";
            }
            return if lost { "lost" } else { "tls_data" };
        }
        if let Some(h) = &m.http {
            *detail = json!({"method": h.method, "uri": h.uri, "status": h.status, "host": h.host, "basic": h.basic.is_some()});
            return if h.status.is_some() {
                "http_response"
            } else {
                "http_request"
            };
        }
        if let Some((cmd, resp)) = m.smb2 {
            *detail = json!({"cmd": cmd, "info": d.info});
            return if resp { "smb_response" } else { "smb_request" };
        }
        return if lost { "lost" } else { "data" };
    }
    "data"
}
