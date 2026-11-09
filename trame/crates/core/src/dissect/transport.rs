//! TCP (RFC 9293) and UDP (RFC 768).

use super::{app, be16, be32, Dissection, Note, PacketCtx, TcpMeta, L4};
use crate::tree::{Field, Value};

const FLAG_NAMES: [(u16, &str, &str); 9] = [
    (0x001, "FIN", "tcp.flags.fin"),
    (0x002, "SYN", "tcp.flags.syn"),
    (0x004, "RST", "tcp.flags.reset"),
    (0x008, "PSH", "tcp.flags.push"),
    (0x010, "ACK", "tcp.flags.ack"),
    (0x020, "URG", "tcp.flags.urg"),
    (0x040, "ECE", "tcp.flags.ece"),
    (0x080, "CWR", "tcp.flags.cwr"),
    (0x100, "AE", "tcp.flags.ae"),
];

pub fn flags_str(flags: u16) -> String {
    FLAG_NAMES
        .iter()
        .filter(|(b, _, _)| flags & b != 0)
        .map(|(_, n, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn tcp(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    if b.len() < o + 20 {
        return d.malformed(o, "en-tête TCP trop court");
    }
    let sport = be16(b, o).unwrap();
    let dport = be16(b, o + 2).unwrap();
    let seq = be32(b, o + 4).unwrap();
    let ack = be32(b, o + 8).unwrap();
    let hl = ((b[o + 12] >> 4) as usize) * 4;
    let flags = (((b[o + 12] & 0x01) as u16) << 8) | b[o + 13] as u16;
    let win = be16(b, o + 14).unwrap();
    let csum = be16(b, o + 16).unwrap();
    let urg = be16(b, o + 18).unwrap();
    if hl < 20 || b.len() < o + hl {
        return d.malformed(o, "longueur d'en-tête TCP invalide");
    }
    let payload = b.len() - (o + hl);
    let rel_seq = ctx
        .base_seq
        .map(|base| seq.wrapping_sub(base))
        .unwrap_or(seq);
    let rel_ack = ctx
        .base_ack
        .map(|base| ack.wrapping_sub(base))
        .unwrap_or(ack);
    let scaled = ctx
        .win_shift
        .map(|s| (win as u64) << s)
        .unwrap_or(win as u64);

    let mut f = Field::proto(
        "tcp",
        format!(
            "Transmission Control Protocol, port {sport} → {dport}, Seq {rel_seq}{}, Len {payload}",
            if flags & 0x10 != 0 {
                format!(", Ack {rel_ack}")
            } else {
                String::new()
            }
        ),
        o,
        hl,
    );
    f.push(Field::new(
        "tcp.srcport",
        format!("Port source : {sport}"),
        Value::Uint(sport as u64),
        o,
        2,
    ));
    f.push(Field::new(
        "tcp.dstport",
        format!("Port destination : {dport}"),
        Value::Uint(dport as u64),
        o + 2,
        2,
    ));
    f.push(Field::hidden("tcp.port", Value::Uint(sport as u64), o, 2));
    f.push(Field::hidden(
        "tcp.port",
        Value::Uint(dport as u64),
        o + 2,
        2,
    ));
    if let Some(s) = ctx.tcp_stream {
        f.push(Field::new(
            "tcp.stream",
            format!("Numéro de flux : {s}"),
            Value::Uint(s as u64),
            o,
            0,
        ));
    }
    f.push(Field::new(
        "tcp.len",
        format!("Longueur des données : {payload}"),
        Value::Uint(payload as u64),
        o,
        0,
    ));
    f.push(Field::new(
        "tcp.seq",
        format!("Numéro de séquence : {rel_seq} (relatif)"),
        Value::Uint(rel_seq as u64),
        o + 4,
        4,
    ));
    f.push(Field::new(
        "tcp.seq_raw",
        format!("Numéro de séquence brut : {seq}"),
        Value::Uint(seq as u64),
        o + 4,
        4,
    ));
    let syn_fin = (flags & 0x003 != 0) as u32;
    let next = rel_seq.wrapping_add(payload as u32 + syn_fin);
    f.push(Field::new(
        "tcp.nxtseq",
        format!("Prochain numéro attendu : {next}"),
        Value::Uint(next as u64),
        o,
        0,
    ));
    f.push(Field::new(
        "tcp.ack",
        format!("Numéro d'acquittement : {rel_ack} (relatif)"),
        Value::Uint(rel_ack as u64),
        o + 8,
        4,
    ));
    f.push(Field::new(
        "tcp.ack_raw",
        format!("Numéro d'acquittement brut : {ack}"),
        Value::Uint(ack as u64),
        o + 8,
        4,
    ));
    f.push(Field::new(
        "tcp.hdr_len",
        format!("Longueur d'en-tête : {hl} octets"),
        Value::Uint(hl as u64),
        o + 12,
        1,
    ));
    let mut ff = Field::new(
        "tcp.flags",
        format!("Drapeaux : 0x{flags:03x} ({})", flags_str(flags)),
        Value::Uint(flags as u64),
        o + 12,
        2,
    );
    for (bit, name, key) in FLAG_NAMES {
        let on = flags & bit != 0;
        ff.push(Field::new(
            key,
            format!("{name} : {}", if on { "oui" } else { "non" }),
            Value::Bool(on),
            o + 12,
            2,
        ));
    }
    f.push(ff);
    f.push(Field::new(
        "tcp.window_size_value",
        format!("Fenêtre : {win}"),
        Value::Uint(win as u64),
        o + 14,
        2,
    ));
    f.push(Field::new(
        "tcp.window_size",
        format!(
            "Fenêtre effective : {scaled}{}",
            if ctx.win_shift.is_some() {
                ""
            } else {
                " (facteur d'échelle inconnu)"
            }
        ),
        Value::Uint(scaled),
        o + 14,
        2,
    ));
    f.push(Field::new(
        "tcp.checksum",
        format!("Somme de contrôle : 0x{csum:04x}"),
        Value::Uint(csum as u64),
        o + 16,
        2,
    ));
    f.push(Field::new(
        "tcp.urgent_pointer",
        format!("Pointeur urgent : {urg}"),
        Value::Uint(urg as u64),
        o + 18,
        2,
    ));

    let mut meta = TcpMeta {
        seq,
        ack,
        flags,
        win,
        payload_len: payload as u32,
        ..Default::default()
    };
    let mut opt_text = Vec::new();
    if hl > 20 {
        let mut of = Field::proto(
            "tcp.options",
            format!("Options : {} octets", hl - 20),
            o + 20,
            hl - 20,
        );
        let mut p = o + 20;
        while p < o + hl {
            let kind = b[p];
            match kind {
                0 => break,
                1 => {
                    of.push(Field::proto(
                        "tcp.options.nop",
                        "Pas d'opération (NOP)",
                        p,
                        1,
                    ));
                    p += 1;
                }
                _ => {
                    let Some(&len) = b.get(p + 1) else { break };
                    let len = len as usize;
                    if len < 2 || p + len > o + hl {
                        of.push(
                            Field::proto("tcp.options.bad", "Option invalide", p, 1)
                                .with_note("warn"),
                        );
                        break;
                    }
                    match (kind, len) {
                        (2, 4) => {
                            let v = be16(b, p + 2).unwrap();
                            meta.mss = Some(v);
                            opt_text.push(format!("MSS={v}"));
                            of.push(Field::new(
                                "tcp.options.mss_val",
                                format!("Taille max de segment : {v}"),
                                Value::Uint(v as u64),
                                p,
                                4,
                            ));
                        }
                        (3, 3) => {
                            let v = b[p + 2];
                            meta.wscale = Some(v);
                            opt_text.push(format!("WS={}", 1u32 << v.min(14)));
                            of.push(Field::new(
                                "tcp.options.wscale.shift",
                                format!("Facteur d'échelle : {v} (×{})", 1u32 << v.min(14)),
                                Value::Uint(v as u64),
                                p,
                                3,
                            ));
                        }
                        (4, 2) => {
                            opt_text.push("SACK_PERM".into());
                            of.push(Field::new(
                                "tcp.options.sack_perm",
                                "SACK autorisé",
                                Value::Bool(true),
                                p,
                                2,
                            ));
                        }
                        (5, _) => {
                            let mut sf = Field::proto(
                                "tcp.options.sack",
                                "Accusés sélectifs (SACK)",
                                p,
                                len,
                            );
                            let mut q = p + 2;
                            while q + 8 <= p + len {
                                let le =
                                    be32(b, q).unwrap().wrapping_sub(ctx.base_ack.unwrap_or(0));
                                let re = be32(b, q + 4)
                                    .unwrap()
                                    .wrapping_sub(ctx.base_ack.unwrap_or(0));
                                sf.push(Field::new(
                                    "tcp.options.sack_le",
                                    format!("Bloc : {le}–{re}"),
                                    Value::Uint(le as u64),
                                    q,
                                    8,
                                ));
                                q += 8;
                            }
                            of.push(sf);
                        }
                        (8, 10) => {
                            let tsv = be32(b, p + 2).unwrap();
                            let tse = be32(b, p + 6).unwrap();
                            opt_text.push(format!("TSval={tsv} TSecr={tse}"));
                            of.push(Field::new(
                                "tcp.options.timestamp.tsval",
                                format!("Horodatage : {tsv}, écho {tse}"),
                                Value::Uint(tsv as u64),
                                p,
                                10,
                            ));
                        }
                        _ => {
                            of.push(Field::proto(
                                "tcp.option",
                                format!("Option {kind} ({len} octets)"),
                                p,
                                len,
                            ));
                        }
                    }
                    p += len;
                }
            }
        }
        f.push(of);
    }

    // Cross-frame analysis, Wireshark's [SEQ/ACK analysis].
    let mut prefix = String::new();
    if !ctx.notes.is_empty() || ctx.initial_rtt.is_some() {
        let mut af = Field::proto("tcp.analysis", "[Analyse SEQ/ACK]", o, 0);
        if let Some(rtt) = ctx.initial_rtt {
            af.push(Field::new(
                "tcp.analysis.initial_rtt",
                format!("Aller-retour initial : {:.3} ms", rtt * 1000.0),
                Value::Float(rtt),
                o,
                0,
            ));
        }
        if !ctx.notes.is_empty() {
            af.push(Field::hidden("tcp.analysis.flags", Value::None, o, 0));
        }
        for n in &ctx.notes {
            let (key, label, text) = match n {
                Note::Retransmission => (
                    "tcp.analysis.retransmission",
                    "Ce segment a déjà été envoyé : retransmission".to_string(),
                    "[TCP Retransmission] ".to_string(),
                ),
                Note::LostSegment => (
                    "tcp.analysis.lost_segment",
                    "Un segment précédent manque dans la capture".to_string(),
                    "[TCP Previous segment not captured] ".to_string(),
                ),
                Note::DupAck { of, n } => (
                    "tcp.analysis.duplicate_ack",
                    format!("Acquittement en double n°{n} de la trame {of}"),
                    format!("[TCP Dup ACK {of}#{n}] "),
                ),
                Note::ZeroWindow => (
                    "tcp.analysis.zero_window",
                    "Fenêtre nulle : le destinataire est saturé".to_string(),
                    "[TCP ZeroWindow] ".to_string(),
                ),
                Note::KeepAlive => (
                    "tcp.analysis.keep_alive",
                    "Maintien de connexion (keep-alive)".to_string(),
                    "[TCP Keep-Alive] ".to_string(),
                ),
            };
            af.push(Field::new(key, label, Value::Bool(true), o, 0).with_note("warn"));
            prefix.push_str(&text);
        }
        f.push(af);
    }

    d.tree.push(f);
    d.stack.push("tcp");
    d.meta.l4 = L4::Tcp;
    d.meta.sport = sport;
    d.meta.dport = dport;
    d.set_proto("TCP", "tcp");
    let ack_part = if flags & 0x10 != 0 {
        format!(" Ack={rel_ack}")
    } else {
        String::new()
    };
    let opts = if opt_text.is_empty() {
        String::new()
    } else {
        format!(" {}", opt_text.join(" "))
    };
    d.info = format!(
        "{prefix}{sport} → {dport} [{}] Seq={rel_seq}{ack_part} Win={scaled} Len={payload}{opts}",
        flags_str(flags)
    );
    d.meta.tcp = Some(meta);
    if payload > 0 && ctx.notes.contains(&Note::Retransmission) {
        // Like Wireshark, retransmitted bytes are not handed to the application dissector.
        d.tree.push(Field::new(
            "tcp.payload",
            format!("Données retransmises : {payload} octets"),
            Value::Bytes(b[o + hl..(o + hl + 32).min(b.len())].to_vec()),
            o + hl,
            payload,
        ));
    } else if payload > 0 {
        if let Some(last) = d.tree.last_mut() {
            last.push(Field::hidden(
                "tcp.payload",
                Value::Bytes(b[o + hl..(o + hl + 32).min(b.len())].to_vec()),
                o + hl,
                payload,
            ));
        }
        let tcp_info = d.info.clone();
        app::tcp_payload(b, o + hl, d, ctx, sport, dport);
        // Keep the TCP analysis prefix visible on application rows.
        if !prefix.is_empty() && d.info != tcp_info {
            d.info = format!("{prefix}{}", d.info);
        }
    }
}

pub fn udp(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    if b.len() < o + 8 {
        return d.malformed(o, "en-tête UDP trop court");
    }
    let sport = be16(b, o).unwrap();
    let dport = be16(b, o + 2).unwrap();
    let len = be16(b, o + 4).unwrap();
    let csum = be16(b, o + 6).unwrap();
    let mut f = Field::proto(
        "udp",
        format!("User Datagram Protocol, port {sport} → {dport}"),
        o,
        8,
    );
    f.push(Field::new(
        "udp.srcport",
        format!("Port source : {sport}"),
        Value::Uint(sport as u64),
        o,
        2,
    ));
    f.push(Field::new(
        "udp.dstport",
        format!("Port destination : {dport}"),
        Value::Uint(dport as u64),
        o + 2,
        2,
    ));
    f.push(Field::hidden("udp.port", Value::Uint(sport as u64), o, 2));
    f.push(Field::hidden(
        "udp.port",
        Value::Uint(dport as u64),
        o + 2,
        2,
    ));
    f.push(Field::new(
        "udp.length",
        format!("Longueur : {len}"),
        Value::Uint(len as u64),
        o + 4,
        2,
    ));
    f.push(Field::new(
        "udp.checksum",
        format!("Somme de contrôle : 0x{csum:04x}"),
        Value::Uint(csum as u64),
        o + 6,
        2,
    ));
    if let Some(s) = ctx.udp_stream {
        f.push(Field::new(
            "udp.stream",
            format!("Numéro de flux : {s}"),
            Value::Uint(s as u64),
            o,
            0,
        ));
    }
    d.tree.push(f);
    d.stack.push("udp");
    d.meta.l4 = L4::Udp;
    d.meta.sport = sport;
    d.meta.dport = dport;
    d.set_proto("UDP", "udp");
    let end = if (len as usize) >= 8 {
        (o + len as usize).min(b.len())
    } else {
        b.len()
    };
    d.info = format!("{sport} → {dport} Len={}", end.saturating_sub(o + 8));
    if end > o + 8 {
        app::udp_payload(&b[..end], o + 8, d, ctx, sport, dport);
    }
}
