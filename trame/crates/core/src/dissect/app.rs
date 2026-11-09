//! Application protocols: DNS/mDNS (RFC 1035, 6762), TLS (RFC 8446, 5246),
//! QUIC (RFC 9000), HTTP/1.x (RFC 9112), SMB2 over NetBIOS (MS-SMB2), DHCP (RFC 2131),
//! NTP (RFC 5905) and SSDP.

use super::{be16, be32, hex, Dissection, DnsMeta, HttpMeta, PacketCtx, TlsMeta};
use crate::tree::{Field, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn tcp_payload(
    b: &[u8],
    o: usize,
    d: &mut Dissection,
    ctx: &PacketCtx,
    sport: u16,
    dport: u16,
) {
    let p = &b[o..];
    let port = |x: u16| sport == x || dport == x;
    if looks_tls(p) {
        return tls(b, o, d, ctx);
    }
    if looks_http(p) {
        return http(b, o, d);
    }
    if port(445) || port(139) {
        return nbss(b, o, d);
    }
    if port(53) && p.len() > 14 {
        return dns(b, o + 2, d, false);
    }
    if port(443) || port(8443) {
        d.tree.push(Field::proto(
            "tls.continuation",
            format!("Suite de données chiffrées ({} octets)", p.len()),
            o,
            p.len(),
        ));
        d.set_proto(
            tls_version_name(ctx.tls_version.unwrap_or(0x0303)),
            "secure",
        );
        d.info = "Continuation Data".into();
        return;
    }
    data(b, o, d);
}

pub fn udp_payload(
    b: &[u8],
    o: usize,
    d: &mut Dissection,
    _ctx: &PacketCtx,
    sport: u16,
    dport: u16,
) {
    let port = |x: u16| sport == x || dport == x;
    if port(5353) {
        return dns(b, o, d, true);
    }
    if port(53) {
        return dns(b, o, d, false);
    }
    if port(443) && b.get(o).is_some_and(|f| f & 0x40 != 0) {
        return quic(b, o, d);
    }
    if port(67) || port(68) {
        return dhcp(b, o, d);
    }
    if port(123) {
        return ntp(b, o, d);
    }
    if port(1900) {
        return ssdp(b, o, d);
    }
    data(b, o, d);
}

fn data(b: &[u8], o: usize, d: &mut Dissection) {
    let n = b.len() - o;
    d.tree.push(Field::new(
        "data",
        format!("Données : {n} octets"),
        Value::Bytes(b[o..o + n.min(64)].to_vec()),
        o,
        n,
    ));
    d.stack.push("data");
}

// ------------------------------------------------------------------ DNS

fn dns_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        _ => format!("Unknown ({t})"),
    }
}

fn rcode_text(r: u8) -> &'static str {
    match r {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        _ => "Other",
    }
}

/// Read a (possibly compressed) DNS name starting at `p`. `base` is the start of the DNS message.
/// Returns the name and the offset just after it in the original position.
fn dns_name(b: &[u8], base: usize, mut p: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(p)? as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(p + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (((len & 0x3F) << 8) | *b.get(p + 1)? as usize) + base;
            if end.is_none() {
                end = Some(p + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= b.len() {
                return None;
            }
            p = ptr;
            continue;
        }
        let label = b.get(p + 1..p + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += 1 + len;
        if labels.len() > 128 {
            return None;
        }
    }
    let name = if labels.is_empty() {
        "<Root>".to_string()
    } else {
        labels.join(".")
    };
    Some((name, end?))
}

pub fn dns(b: &[u8], o: usize, d: &mut Dissection, mdns: bool) {
    if b.len() < o + 12 {
        return d.malformed(o, "DNS trop court");
    }
    let id = be16(b, o).unwrap();
    let flags = be16(b, o + 2).unwrap();
    let qd = be16(b, o + 4).unwrap();
    let an = be16(b, o + 6).unwrap();
    let ns = be16(b, o + 8).unwrap();
    let ar = be16(b, o + 10).unwrap();
    let response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xF) as u8;
    let rcode = (flags & 0xF) as u8;
    let (key, title) = if mdns {
        ("mdns", "Multicast Domain Name System")
    } else {
        ("dns", "Domain Name System")
    };
    let mut f = Field::proto(
        key,
        format!("{title} ({})", if response { "réponse" } else { "requête" }),
        o,
        b.len() - o,
    );
    f.push(Field::new(
        "dns.id",
        format!("Identifiant : 0x{id:04x}"),
        Value::Uint(id as u64),
        o,
        2,
    ));
    let mut ff = Field::new(
        "dns.flags",
        format!("Drapeaux : 0x{flags:04x}"),
        Value::Uint(flags as u64),
        o + 2,
        2,
    );
    ff.push(Field::new(
        "dns.flags.response",
        format!("Réponse : {}", if response { "oui" } else { "non" }),
        Value::Bool(response),
        o + 2,
        2,
    ));
    ff.push(Field::new(
        "dns.flags.opcode",
        format!("Opcode : {opcode}"),
        Value::Uint(opcode as u64),
        o + 2,
        2,
    ));
    ff.push(Field::new(
        "dns.flags.recdesired",
        format!("Récursion demandée : {}", (flags & 0x0100 != 0) as u8),
        Value::Bool(flags & 0x0100 != 0),
        o + 2,
        2,
    ));
    if response {
        ff.push(Field::new(
            "dns.flags.authoritative",
            format!("Réponse officielle : {}", (flags & 0x0400 != 0) as u8),
            Value::Bool(flags & 0x0400 != 0),
            o + 2,
            2,
        ));
        ff.push(Field::new(
            "dns.flags.rcode",
            format!("Résultat : {} ({rcode})", rcode_text(rcode)),
            Value::Uint(rcode as u64),
            o + 2,
            2,
        ));
    }
    f.push(ff);
    f.push(Field::new(
        "dns.count.queries",
        format!("Questions : {qd}"),
        Value::Uint(qd as u64),
        o + 4,
        2,
    ));
    f.push(Field::new(
        "dns.count.answers",
        format!("Réponses : {an}"),
        Value::Uint(an as u64),
        o + 6,
        2,
    ));
    f.push(Field::new(
        "dns.count.auth_rr",
        format!("Autorités : {ns}"),
        Value::Uint(ns as u64),
        o + 8,
        2,
    ));
    f.push(Field::new(
        "dns.count.add_rr",
        format!("Additionnels : {ar}"),
        Value::Uint(ar as u64),
        o + 10,
        2,
    ));

    let mut meta = DnsMeta {
        id,
        response,
        rcode,
        mdns,
        ..Default::default()
    };
    let mut p = o + 12;
    let mut first_q = String::new();
    if qd > 0 {
        let mut qf = Field::proto("dns.queries", "Questions", p, 0);
        let start = p;
        for _ in 0..qd.min(64) {
            let Some((name, np)) = dns_name(b, o, p) else {
                break;
            };
            let (Some(t), Some(c)) = (be16(b, np), be16(b, np + 2)) else {
                break;
            };
            let mut q = Field::proto(
                "dns.qry",
                format!(
                    "{name} : type {}, classe {}",
                    dns_type(t),
                    if c & 0x7FFF == 1 { "IN" } else { "autre" }
                ),
                p,
                np + 4 - p,
            );
            q.push(Field::new(
                "dns.qry.name",
                format!("Nom : {name}"),
                Value::Str(name.clone()),
                p,
                np - p,
            ));
            q.push(Field::new(
                "dns.qry.type",
                format!("Type : {} ({t})", dns_type(t)),
                Value::Uint(t as u64),
                np,
                2,
            ));
            q.push(Field::new(
                "dns.qry.class",
                format!("Classe : 0x{c:04x}"),
                Value::Uint(c as u64),
                np + 2,
                2,
            ));
            if meta.qname.is_empty() {
                meta.qname = name.clone();
                meta.qtype = t;
                first_q = format!("{} {name}", dns_type(t));
            }
            qf.push(q);
            p = np + 4;
        }
        qf.len = p - start;
        f.push(qf);
    }
    let mut answers_text = Vec::new();
    for (section, count, key, label) in [
        (0, an, "dns.answers", "Réponses"),
        (1, ns, "dns.authority", "Autorités"),
        (2, ar, "dns.additional", "Additionnels"),
    ] {
        if count == 0 {
            continue;
        }
        let start = p;
        let mut sf = Field::proto(key, label, p, 0);
        for _ in 0..count.min(256) {
            let Some((name, np)) = dns_name(b, o, p) else {
                break;
            };
            let (Some(t), Some(c), Some(ttl), Some(rdlen)) = (
                be16(b, np),
                be16(b, np + 2),
                be32(b, np + 4),
                be16(b, np + 8),
            ) else {
                break;
            };
            let rd = np + 10;
            let rdlen = rdlen as usize;
            if rd + rdlen > b.len() {
                break;
            }
            let mut rf = Field::proto("dns.resp", "", p, rd + rdlen - p);
            rf.push(Field::new(
                "dns.resp.name",
                format!("Nom : {name}"),
                Value::Str(name.clone()),
                p,
                np - p,
            ));
            rf.push(Field::new(
                "dns.resp.type",
                format!("Type : {} ({t})", dns_type(t)),
                Value::Uint(t as u64),
                np,
                2,
            ));
            if t != 41 {
                rf.push(Field::new(
                    "dns.resp.class",
                    format!("Classe : 0x{c:04x}"),
                    Value::Uint(c as u64),
                    np + 2,
                    2,
                ));
                rf.push(Field::new(
                    "dns.resp.ttl",
                    format!("Durée de validité : {ttl} s"),
                    Value::Uint(ttl as u64),
                    np + 4,
                    4,
                ));
            }
            let text = match (t, rdlen) {
                (1, 4) => {
                    let ip = Ipv4Addr::new(b[rd], b[rd + 1], b[rd + 2], b[rd + 3]);
                    rf.push(Field::new(
                        "dns.a",
                        format!("Adresse : {ip}"),
                        Value::Ip(ip.into()),
                        rd,
                        4,
                    ));
                    if section == 0 {
                        meta.addrs.push((name.clone(), IpAddr::V4(ip)));
                    }
                    format!("A {ip}")
                }
                (28, 16) => {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[rd..rd + 16]).unwrap());
                    rf.push(Field::new(
                        "dns.aaaa",
                        format!("Adresse : {ip}"),
                        Value::Ip(ip.into()),
                        rd,
                        16,
                    ));
                    if section == 0 {
                        meta.addrs.push((name.clone(), IpAddr::V6(ip)));
                    }
                    format!("AAAA {ip}")
                }
                (5, _) | (12, _) | (2, _) => {
                    let target = dns_name(b, o, rd).map(|x| x.0).unwrap_or_default();
                    let k = match t {
                        5 => "dns.cname",
                        12 => "dns.ptr.domain_name",
                        _ => "dns.ns",
                    };
                    rf.push(Field::new(
                        k,
                        format!("Cible : {target}"),
                        Value::Str(target.clone()),
                        rd,
                        rdlen,
                    ));
                    if t == 12 {
                        meta.ptrs.push(target.clone());
                    }
                    format!("{} {target}", dns_type(t))
                }
                (41, _) => {
                    rf.label = format!("OPT (EDNS0), taille UDP {c}");
                    String::new()
                }
                _ => {
                    rf.push(Field::new(
                        "dns.resp.data",
                        format!("Données : {rdlen} octets"),
                        Value::Bytes(b[rd..rd + rdlen.min(64)].to_vec()),
                        rd,
                        rdlen,
                    ));
                    dns_type(t)
                }
            };
            if rf.label.is_empty() {
                rf.label = format!("{name} : {text}, TTL {ttl}");
            }
            if section == 0 && !text.is_empty() {
                answers_text.push(text);
            }
            sf.push(rf);
            p = rd + rdlen;
        }
        sf.len = p - start;
        f.push(sf);
    }
    d.tree.push(f);
    d.stack.push(key);
    d.set_proto(
        if mdns { "MDNS" } else { "DNS" },
        if mdns { "local" } else { "dns" },
    );
    let kind = if opcode == 0 {
        "Standard query"
    } else {
        "Query"
    };
    d.info = if response {
        let err = if rcode != 0 {
            format!(" {}", rcode_text(rcode))
        } else {
            String::new()
        };
        format!(
            "{kind} response 0x{id:04x}{err} {first_q} {}",
            answers_text.join(" ")
        )
        .trim_end()
        .replace("  ", " ")
    } else {
        format!("{kind} 0x{id:04x} {first_q}")
            .trim_end()
            .to_string()
    };
    d.meta.dns = Some(meta);
}

// ------------------------------------------------------------------ TLS

fn looks_tls(p: &[u8]) -> bool {
    p.len() >= 5 && (20..=24).contains(&p[0]) && p[1] == 3 && p[2] <= 4
}

pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => "TLS",
    }
}

fn cipher_name(c: u16) -> String {
    match c {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
        _ => format!("0x{c:04x}"),
    }
}

pub fn alert_desc(a: u8) -> &'static str {
    match a {
        0 => "Close Notify",
        10 => "Unexpected Message",
        20 => "Bad Record MAC",
        40 => "Handshake Failure",
        42 => "Bad Certificate",
        43 => "Unsupported Certificate",
        44 => "Certificate Revoked",
        45 => "Certificate Expired",
        46 => "Certificate Unknown",
        47 => "Illegal Parameter",
        48 => "Unknown CA",
        50 => "Decode Error",
        51 => "Decrypt Error",
        70 => "Protocol Version",
        71 => "Insufficient Security",
        80 => "Internal Error",
        90 => "User Canceled",
        109 => "Missing Extension",
        112 => "Unrecognized Name",
        116 => "Certificate Required",
        120 => "No Application Protocol",
        _ => "Unknown",
    }
}

fn tls(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    let at = d.tree.len();
    let mut meta = TlsMeta::default();
    let mut infos: Vec<String> = Vec::new();
    let mut p = o;
    let mut col_version = 0u16;
    let mut seen_ccs = false;
    while p + 5 <= b.len() && looks_tls(&b[p..]) {
        let ct = b[p];
        let ver = be16(b, p + 1).unwrap();
        let len = be16(b, p + 3).unwrap() as usize;
        let body_end = (p + 5 + len).min(b.len());
        let partial = p + 5 + len > b.len();
        if meta.record_version == 0 {
            meta.record_version = ver;
        }
        col_version = col_version.max(ver);
        meta.content_types.push(ct);
        let ct_name = match ct {
            20 => "Change Cipher Spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            24 => "Heartbeat",
            _ => "?",
        };
        let mut rf = Field::proto(
            "tls.record",
            format!(
                "Enregistrement {}, {ct_name}{}",
                tls_version_name(ver),
                if partial {
                    " (suite dans un autre segment)"
                } else {
                    ""
                }
            ),
            p,
            body_end - p,
        );
        // In TLS 1.3 every record after the ServerHello is "opaque" application data (RFC 8446 §5.2).
        let in13 = ctx.tls_version == Some(0x0304) || meta.server_version == Some(0x0304);
        let ct_key = if in13 && ct == 23 {
            "tls.record.opaque_type"
        } else {
            "tls.record.content_type"
        };
        rf.push(Field::new(
            ct_key,
            format!("Type de contenu : {ct_name} ({ct})"),
            Value::Uint(ct as u64),
            p,
            1,
        ));
        rf.push(Field::new(
            "tls.record.version",
            format!("Version : {} (0x{ver:04x})", tls_version_name(ver)),
            Value::Uint(ver as u64),
            p + 1,
            2,
        ));
        rf.push(Field::new(
            "tls.record.length",
            format!("Longueur : {len}"),
            Value::Uint(len as u64),
            p + 3,
            2,
        ));
        let q = p + 5;
        match ct {
            20 => {
                seen_ccs = true;
                infos.push("Change Cipher Spec".into());
            }
            21 if body_end >= q + 2 => {
                let lvl = b[q];
                let desc = b[q + 1];
                let mut af = Field::proto(
                    "tls.alert_message",
                    format!(
                        "Alerte : {}, {}",
                        if lvl == 2 { "fatale" } else { "avertissement" },
                        alert_desc(desc)
                    ),
                    q,
                    2,
                );
                af.push(Field::new(
                    "tls.alert_message.level",
                    format!("Niveau : {lvl}"),
                    Value::Uint(lvl as u64),
                    q,
                    1,
                ));
                af.push(Field::new(
                    "tls.alert_message.desc",
                    format!("Description : {} ({desc})", alert_desc(desc)),
                    Value::Uint(desc as u64),
                    q + 1,
                    1,
                ));
                rf.push(af.with_note(if lvl == 2 { "error" } else { "warn" }));
                meta.alert = Some((lvl, desc));
                infos.push(format!(
                    "Alert (Level: {}, Description: {})",
                    if lvl == 2 { "Fatal" } else { "Warning" },
                    alert_desc(desc)
                ));
            }
            21 => infos.push("Encrypted Alert".into()),
            22 => {
                let ht = b.get(q).copied().unwrap_or(0);
                let hl = b
                    .get(q + 1..q + 4)
                    .map(|x| ((x[0] as usize) << 16) | ((x[1] as usize) << 8) | x[2] as usize)
                    .unwrap_or(0);
                let plausible = matches!(ht, 1 | 2 | 4 | 8 | 11 | 12 | 13 | 14 | 15 | 16 | 20)
                    && hl + 4 <= len.max(4)
                    && !seen_ccs;
                if plausible {
                    meta.handshakes.push(ht);
                    let mut hf = Field::proto(
                        "tls.handshake",
                        format!("Poignée de main : {}", hs_name(ht)),
                        q,
                        (4 + hl).min(body_end - q),
                    );
                    hf.push(Field::new(
                        "tls.handshake.type",
                        format!("Type : {} ({ht})", hs_name(ht)),
                        Value::Uint(ht as u64),
                        q,
                        1,
                    ));
                    hf.push(Field::new(
                        "tls.handshake.length",
                        format!("Longueur : {hl}"),
                        Value::Uint(hl as u64),
                        q + 1,
                        3,
                    ));
                    let mut info = hs_name(ht).to_string();
                    if ht == 1 || ht == 2 {
                        hello(
                            b,
                            q + 4,
                            (q + 4 + hl).min(body_end),
                            ht == 1,
                            &mut hf,
                            &mut meta,
                        );
                        if ht == 1 {
                            if let Some(s) = &meta.sni {
                                info = format!("Client Hello (SNI={s})");
                            }
                        }
                    }
                    rf.push(hf);
                    infos.push(info);
                } else {
                    infos.push("Encrypted Handshake Message".into());
                }
            }
            23 => infos.push("Application Data".into()),
            _ => {}
        }
        rf.label = rf
            .label
            .replace(
                ct_name,
                &format!("{ct_name} — {}", infos.last().cloned().unwrap_or_default()),
            )
            .replace(&format!("{ct_name} — {ct_name}"), ct_name);
        d.tree.push(rf);
        p = body_end;
        if partial {
            break;
        }
    }
    if p < b.len() {
        d.tree.push(Field::proto(
            "tls.continuation",
            format!("Données TLS supplémentaires ({} octets)", b.len() - p),
            p,
            b.len() - p,
        ));
    }
    // Wrap the records in one "tls" node, as Wireshark does.
    let records: Vec<Field> = d.tree.drain(at..).collect();
    let mut node = Field::proto("tls", "Transport Layer Security", o, b.len() - o);
    node.children = records;
    d.tree.push(node);
    d.stack.push("tls");
    let version = meta
        .server_version
        .filter(|v| *v == 0x0304)
        .or(ctx.tls_version)
        .unwrap_or(col_version);
    d.set_proto(tls_version_name(version), "secure");
    // Collapse repeated record names the way Wireshark does ("Application Data, Application Data" → one).
    let mut uniq: Vec<String> = Vec::new();
    for i in infos {
        if uniq.last() != Some(&i) {
            uniq.push(i);
        }
    }
    d.info = uniq.join(", ");
    d.meta.tls = Some(meta);
}

fn hs_name(t: u8) -> &'static str {
    match t {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

fn hello(b: &[u8], q: usize, end: usize, client: bool, hf: &mut Field, meta: &mut TlsMeta) {
    let Some(ver) = be16(b, q) else { return };
    hf.push(Field::new(
        "tls.handshake.version",
        format!("Version annoncée : {} (0x{ver:04x})", tls_version_name(ver)),
        Value::Uint(ver as u64),
        q,
        2,
    ));
    let mut p = q + 2 + 32;
    let Some(&sid_len) = b.get(p) else { return };
    p += 1 + sid_len as usize;
    if client {
        let Some(cs_len) = be16(b, p) else { return };
        let cs_len = cs_len as usize;
        let mut cf = Field::proto(
            "tls.handshake.ciphersuites",
            format!("Suites de chiffrement proposées : {}", cs_len / 2),
            p,
            2 + cs_len,
        );
        for i in 0..cs_len / 2 {
            if let Some(c) = be16(b, p + 2 + i * 2) {
                cf.push(Field::new(
                    "tls.handshake.ciphersuite",
                    cipher_name(c),
                    Value::Uint(c as u64),
                    p + 2 + i * 2,
                    2,
                ));
            }
        }
        hf.push(cf);
        p += 2 + cs_len;
        let Some(&comp) = b.get(p) else { return };
        p += 1 + comp as usize;
        if !meta.client_versions.contains(&ver) {
            meta.client_versions.push(ver);
        }
    } else {
        let Some(c) = be16(b, p) else { return };
        hf.push(Field::new(
            "tls.handshake.ciphersuite",
            format!("Suite choisie : {}", cipher_name(c)),
            Value::Uint(c as u64),
            p,
            2,
        ));
        meta.cipher = Some(c);
        meta.server_version = Some(ver);
        p += 3;
    }
    let Some(ext_len) = be16(b, p) else { return };
    let ext_end = (p + 2 + ext_len as usize).min(end);
    let mut ef = Field::proto("tls.handshake.extensions", "Extensions", p, ext_end - p);
    p += 2;
    while p + 4 <= ext_end {
        let et = be16(b, p).unwrap();
        let el = be16(b, p + 2).unwrap() as usize;
        let e = p + 4;
        if e + el > ext_end {
            break;
        }
        match et {
            0 if el >= 5 => {
                let nl = be16(b, e + 3).unwrap_or(0) as usize;
                if let Some(name) = b.get(e + 5..e + 5 + nl) {
                    let s = String::from_utf8_lossy(name).into_owned();
                    ef.push(Field::new(
                        "tls.handshake.extensions_server_name",
                        format!("Nom du serveur (SNI) : {s}"),
                        Value::Str(s.clone()),
                        e + 5,
                        nl,
                    ));
                    meta.sni = Some(s);
                }
            }
            43 => {
                let mut vf = Field::proto(
                    "tls.handshake.extensions.supported_versions",
                    "Versions prises en charge",
                    p,
                    4 + el,
                );
                if client {
                    let n = b.get(e).copied().unwrap_or(0) as usize;
                    meta.client_versions.clear();
                    for i in 0..n / 2 {
                        if let Some(v) = be16(b, e + 1 + i * 2) {
                            if v & 0x0F0F != 0x0A0A {
                                meta.client_versions.push(v);
                            }
                            vf.push(Field::new(
                                "tls.handshake.extensions.supported_version",
                                format!("{} (0x{v:04x})", tls_version_name(v)),
                                Value::Uint(v as u64),
                                e + 1 + i * 2,
                                2,
                            ));
                        }
                    }
                } else if let Some(v) = be16(b, e) {
                    meta.server_version = Some(v);
                    vf.push(Field::new(
                        "tls.handshake.extensions.supported_version",
                        format!("Version choisie : {} (0x{v:04x})", tls_version_name(v)),
                        Value::Uint(v as u64),
                        e,
                        2,
                    ));
                }
                ef.push(vf);
            }
            16 if el >= 2 => {
                let mut q2 = e + 2;
                while q2 < e + el {
                    let l = b[q2] as usize;
                    if let Some(proto) = b.get(q2 + 1..q2 + 1 + l) {
                        let s = String::from_utf8_lossy(proto).into_owned();
                        ef.push(Field::new(
                            "tls.handshake.extensions_alpn_str",
                            format!("Protocole applicatif (ALPN) : {s}"),
                            Value::Str(s.clone()),
                            q2 + 1,
                            l,
                        ));
                        meta.alpn.push(s);
                    }
                    q2 += 1 + l;
                }
            }
            _ => {
                ef.push(Field::new(
                    "tls.handshake.extension.type",
                    format!("Extension {} ({el} octets)", ext_name(et)),
                    Value::Uint(et as u64),
                    p,
                    4 + el,
                ));
            }
        }
        p = e + el;
    }
    hf.push(ef);
}

fn ext_name(t: u16) -> String {
    match t {
        10 => "supported_groups".into(),
        11 => "ec_point_formats".into(),
        13 => "signature_algorithms".into(),
        23 => "extended_master_secret".into(),
        35 => "session_ticket".into(),
        45 => "psk_key_exchange_modes".into(),
        51 => "key_share".into(),
        65037 => "encrypted_client_hello".into(),
        65281 => "renegotiation_info".into(),
        _ => format!("{t}"),
    }
}

// ------------------------------------------------------------------ QUIC

fn quic(b: &[u8], o: usize, d: &mut Dissection) {
    let first = b[o];
    let n = b.len() - o;
    let mut f = Field::proto("quic", "QUIC IETF", o, n);
    d.stack.push("quic");
    d.set_proto("QUIC", "secure");
    d.meta.quic = true;
    if first & 0x80 != 0 {
        let (Some(ver), Some(&dl)) = (be32(b, o + 1), b.get(o + 5)) else {
            return d.malformed(o, "QUIC incomplet");
        };
        let dl = dl as usize;
        let dcid = b.get(o + 6..o + 6 + dl).map(hex).unwrap_or_default();
        let sl = b.get(o + 6 + dl).copied().unwrap_or(0) as usize;
        let scid = b
            .get(o + 7 + dl..o + 7 + dl + sl)
            .map(hex)
            .unwrap_or_default();
        let pt = (first >> 4) & 3;
        let name = if ver == 0 {
            "Version Negotiation"
        } else {
            ["Initial", "0-RTT", "Handshake", "Retry"][pt as usize]
        };
        f.push(Field::new(
            "quic.header_form",
            "Forme d'en-tête : longue",
            Value::Uint(1),
            o,
            1,
        ));
        f.push(Field::new(
            "quic.long.packet_type",
            format!("Type de paquet : {name}"),
            Value::Uint(pt as u64),
            o,
            1,
        ));
        f.push(Field::new(
            "quic.version",
            format!("Version : 0x{ver:08x}"),
            Value::Uint(ver as u64),
            o + 1,
            4,
        ));
        f.push(Field::new(
            "quic.dcid",
            format!("ID de connexion destination : {dcid}"),
            Value::Str(dcid.clone()),
            o + 6,
            dl,
        ));
        f.push(Field::new(
            "quic.scid",
            format!("ID de connexion source : {scid}"),
            Value::Str(scid.clone()),
            o + 7 + dl,
            sl,
        ));
        d.info = format!("{name}, DCID={dcid}, SCID={scid}");
    } else {
        f.push(Field::new(
            "quic.header_form",
            "Forme d'en-tête : courte",
            Value::Uint(0),
            o,
            1,
        ));
        f.push(Field::proto(
            "quic.protected_payload",
            format!("Contenu protégé : {} octets", n - 1),
            o + 1,
            n - 1,
        ));
        d.info = "Protected Payload".into();
    }
    d.tree.push(f);
}

// ------------------------------------------------------------------ HTTP/1.x

const METHODS: [&str; 9] = [
    "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

fn looks_http(p: &[u8]) -> bool {
    METHODS.iter().any(|m| p.starts_with(m.as_bytes())) || p.starts_with(b"HTTP/1.")
}

fn http(b: &[u8], o: usize, d: &mut Dissection) {
    let p = &b[o..];
    let head_end = p
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|x| x + 4)
        .unwrap_or(p.len());
    let head = String::from_utf8_lossy(&p[..head_end]);
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("").to_string();
    let mut f = Field::proto(
        "http",
        "Hypertext Transfer Protocol (non chiffré)",
        o,
        p.len(),
    );
    let mut meta = HttpMeta::default();
    let mut off = o;
    let mut content_type = None;
    if first.starts_with("HTTP/1.") {
        let mut parts = first.splitn(3, ' ');
        let _ver = parts.next();
        let code: u16 = parts.next().and_then(|c| c.parse().ok()).unwrap_or(0);
        let phrase = parts.next().unwrap_or("").to_string();
        f.push(Field::new(
            "http.response",
            format!("Réponse : {first}"),
            Value::Bool(true),
            o,
            first.len(),
        ));
        f.push(Field::new(
            "http.response.code",
            format!("Code : {code}"),
            Value::Uint(code as u64),
            o + 9,
            3,
        ));
        f.push(Field::new(
            "http.response.phrase",
            format!("Message : {phrase}"),
            Value::Str(phrase),
            o + 13,
            0,
        ));
        meta.status = Some(code);
    } else {
        let mut parts = first.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let uri = parts.next().unwrap_or("").to_string();
        let ver = parts.next().unwrap_or("").to_string();
        f.push(Field::new(
            "http.request",
            format!("Requête : {first}"),
            Value::Bool(true),
            o,
            first.len(),
        ));
        f.push(Field::new(
            "http.request.method",
            format!("Méthode : {method}"),
            Value::Str(method.clone()),
            o,
            method.len(),
        ));
        f.push(Field::new(
            "http.request.uri",
            format!("Chemin : {uri}"),
            Value::Str(uri.clone()),
            o + method.len() + 1,
            uri.len(),
        ));
        f.push(Field::new(
            "http.request.version",
            format!("Version : {ver}"),
            Value::Str(ver),
            o,
            0,
        ));
        meta.method = Some(method);
        meta.uri = Some(uri);
    }
    off += first.len() + 2;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let len = line.len();
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim().to_string();
            let key = match k.to_ascii_lowercase().as_str() {
                "host" => {
                    meta.host = Some(v.clone());
                    "http.host"
                }
                "user-agent" => "http.user_agent",
                "content-type" => {
                    content_type = Some(v.clone());
                    "http.content_type"
                }
                "content-length" => "http.content_length_header",
                "server" => "http.server",
                "cookie" => "http.cookie",
                "location" => "http.location",
                "authorization" => "http.authorization",
                _ => "http.header",
            };
            let mut hf = Field::new(key, line.to_string(), Value::Str(v.clone()), off, len);
            if key == "http.authorization" {
                hf = hf.with_note("error");
                if let Some(enc) = v.strip_prefix("Basic ") {
                    if let Some(dec) = base64(enc.trim()) {
                        let s = String::from_utf8_lossy(&dec).into_owned();
                        hf.push(
                            Field::new(
                                "http.authbasic",
                                format!("Identifiants en clair : {s}"),
                                Value::Str(s.clone()),
                                off,
                                len,
                            )
                            .with_note("error"),
                        );
                        meta.basic = Some(s);
                    }
                }
            }
            f.push(hf);
        }
        off += len + 2;
    }
    if head_end < p.len() {
        f.push(Field::proto(
            "http.file_data",
            format!("Contenu : {} octets", p.len() - head_end),
            o + head_end,
            p.len() - head_end,
        ));
    }
    d.tree.push(f);
    d.stack.push("http");
    d.set_proto("HTTP", "web");
    d.info = match (&meta.status, content_type) {
        (Some(_), Some(ct)) => format!("{first}  ({ct})"),
        _ => format!("{first} "),
    };
    d.meta.http = Some(meta);
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------ NetBIOS session + SMB2

fn smb2_cmd(c: u16) -> &'static str {
    match c {
        0 => "Negotiate Protocol",
        1 => "Session Setup",
        2 => "Session Logoff",
        3 => "Tree Connect",
        4 => "Tree Disconnect",
        5 => "Create",
        6 => "Close",
        7 => "Flush",
        8 => "Read",
        9 => "Write",
        10 => "Lock",
        11 => "Ioctl",
        12 => "Cancel",
        13 => "KeepAlive",
        14 => "Find",
        15 => "Notify",
        16 => "GetInfo",
        17 => "SetInfo",
        18 => "Break",
        _ => "Unknown",
    }
}

fn nbss(b: &[u8], o: usize, d: &mut Dissection) {
    let p = &b[o..];
    let is_hdr = p.len() >= 8 && p[0] == 0 && (&p[4..8] == b"\xfeSMB" || &p[4..8] == b"\xffSMB");
    if !is_hdr {
        d.tree.push(Field::proto(
            "nbss",
            format!(
                "NetBIOS Session Service, suite d'un message ({} octets)",
                p.len()
            ),
            o,
            p.len(),
        ));
        d.stack.push("nbss");
        d.set_proto("NBSS", "file");
        d.info = "NBSS Continuation Message".into();
        return;
    }
    let len = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | p[3] as usize;
    let mut nf = Field::proto("nbss", "NetBIOS Session Service", o, 4);
    nf.push(Field::new(
        "nbss.length",
        format!("Longueur : {len}"),
        Value::Uint(len as u64),
        o + 1,
        3,
    ));
    d.tree.push(nf);
    d.stack.push("nbss");
    let s = o + 4;
    if &p[4..8] == b"\xffSMB" {
        d.tree.push(
            Field::proto("smb", "SMB (version 1, obsolète)", s, p.len() - 4).with_note("warn"),
        );
        d.stack.push("smb");
        d.set_proto("SMB", "file");
        d.info = "SMB1".into();
        return;
    }
    let (Some(cmd), Some(flags), Some(msg)) = (
        b.get(s + 12..s + 14),
        b.get(s + 16..s + 20),
        b.get(s + 24..s + 32),
    ) else {
        return d.malformed(s, "en-tête SMB2 incomplet");
    };
    let cmd = u16::from_le_bytes([cmd[0], cmd[1]]);
    let flags = u32::from_le_bytes([flags[0], flags[1], flags[2], flags[3]]);
    let msg = u64::from_le_bytes(msg.try_into().unwrap());
    let resp = flags & 1 != 0;
    let mut f = Field::proto(
        "smb2",
        format!(
            "SMB2 : {} {}",
            smb2_cmd(cmd),
            if resp { "Response" } else { "Request" }
        ),
        s,
        p.len() - 4,
    );
    f.push(Field::new(
        "smb2.cmd",
        format!("Commande : {} ({cmd})", smb2_cmd(cmd)),
        Value::Uint(cmd as u64),
        s + 12,
        2,
    ));
    f.push(Field::new(
        "smb2.flags.response",
        format!("Réponse : {}", if resp { "oui" } else { "non" }),
        Value::Bool(resp),
        s + 16,
        4,
    ));
    f.push(Field::new(
        "smb2.msg_id",
        format!("Identifiant de message : {msg}"),
        Value::Uint(msg),
        s + 24,
        8,
    ));
    if cmd == 0 && resp {
        if let Some(dia) = b.get(s + 68..s + 70) {
            let v = u16::from_le_bytes([dia[0], dia[1]]);
            f.push(Field::new(
                "smb2.dialect",
                format!(
                    "Dialecte retenu : {}.{}.{}",
                    v >> 8,
                    (v >> 4) & 0xF,
                    v & 0xF
                ),
                Value::Uint(v as u64),
                s + 68,
                2,
            ));
        }
    }
    d.tree.push(f);
    d.stack.push("smb2");
    d.set_proto("SMB2", "file");
    d.meta.smb2 = Some((cmd, resp));
    d.info = format!(
        "{} {}",
        smb2_cmd(cmd),
        if resp { "Response" } else { "Request" }
    );
}

// ------------------------------------------------------------------ DHCP, NTP, SSDP

fn dhcp(b: &[u8], o: usize, d: &mut Dissection) {
    if b.len() < o + 240 {
        return data(b, o, d);
    }
    let op = b[o];
    let xid = be32(b, o + 4).unwrap();
    let yi = Ipv4Addr::new(b[o + 16], b[o + 17], b[o + 18], b[o + 19]);
    let mut f = Field::proto(
        "dhcp",
        "Dynamic Host Configuration Protocol",
        o,
        b.len() - o,
    );
    f.push(Field::new(
        "dhcp.type",
        format!("Type : {}", if op == 1 { "requête" } else { "réponse" }),
        Value::Uint(op as u64),
        o,
        1,
    ));
    f.push(Field::new(
        "dhcp.id",
        format!("Transaction : 0x{xid:08x}"),
        Value::Uint(xid as u64),
        o + 4,
        4,
    ));
    f.push(Field::new(
        "dhcp.ip.your",
        format!("Adresse attribuée : {yi}"),
        Value::Ip(yi.into()),
        o + 16,
        4,
    ));
    let mut msg = 0u8;
    let mut p = o + 240;
    while p + 2 <= b.len() {
        let code = b[p];
        if code == 255 {
            break;
        }
        if code == 0 {
            p += 1;
            continue;
        }
        let l = b[p + 1] as usize;
        let Some(v) = b.get(p + 2..p + 2 + l) else {
            break;
        };
        match code {
            53 if l == 1 => {
                msg = v[0];
                f.push(Field::new(
                    "dhcp.option.dhcp",
                    format!("Message : {}", dhcp_msg(msg)),
                    Value::Uint(msg as u64),
                    p,
                    2 + l,
                ));
            }
            12 => {
                let s = String::from_utf8_lossy(v).into_owned();
                f.push(Field::new(
                    "dhcp.option.hostname",
                    format!("Nom de l'appareil : {s}"),
                    Value::Str(s),
                    p,
                    2 + l,
                ));
            }
            50 if l == 4 => {
                let ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                f.push(Field::new(
                    "dhcp.option.requested_ip_address",
                    format!("Adresse demandée : {ip}"),
                    Value::Ip(ip.into()),
                    p,
                    2 + l,
                ));
            }
            _ => {}
        }
        p += 2 + l;
    }
    d.tree.push(f);
    d.stack.push("dhcp");
    d.set_proto("DHCP", "local");
    d.info = format!("DHCP {} - Transaction ID 0x{xid:08x}", dhcp_msg(msg));
}

fn dhcp_msg(m: u8) -> &'static str {
    match m {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Message",
    }
}

fn ntp(b: &[u8], o: usize, d: &mut Dissection) {
    let Some(&first) = b.get(o) else { return };
    let ver = (first >> 3) & 7;
    let mode = first & 7;
    let mode_s = match mode {
        3 => "client",
        4 => "server",
        _ => "other",
    };
    let mut f = Field::proto("ntp", "Network Time Protocol", o, b.len() - o);
    f.push(Field::new(
        "ntp.flags.vn",
        format!("Version : {ver}"),
        Value::Uint(ver as u64),
        o,
        1,
    ));
    f.push(Field::new(
        "ntp.flags.mode",
        format!("Mode : {mode_s}"),
        Value::Uint(mode as u64),
        o,
        1,
    ));
    d.tree.push(f);
    d.stack.push("ntp");
    d.set_proto("NTP", "local");
    d.info = format!("NTP Version {ver}, {mode_s}");
}

fn ssdp(b: &[u8], o: usize, d: &mut Dissection) {
    let p = &b[o..];
    let first = String::from_utf8_lossy(
        &p[..p
            .iter()
            .position(|&c| c == b'\r')
            .unwrap_or(p.len().min(80))],
    )
    .into_owned();
    d.tree.push(Field::proto(
        "ssdp",
        "Simple Service Discovery Protocol",
        o,
        p.len(),
    ));
    d.stack.push("ssdp");
    d.set_proto("SSDP", "local");
    d.info = first;
}
