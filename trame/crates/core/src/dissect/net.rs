//! Ethernet, 802.1Q, ARP, IPv4, IPv6, ICMP and ICMPv6.

use super::{be16, transport, Dissection, PacketCtx, L4};
use crate::dissect::ArpMeta;
use crate::tree::{fmt_mac, Field, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn mac_at(b: &[u8], o: usize) -> Option<[u8; 6]> {
    b.get(o..o + 6)?.try_into().ok()
}

pub(crate) fn mac_label(m: &[u8; 6]) -> String {
    if *m == [0xff; 6] {
        "Broadcast (ff:ff:ff:ff:ff:ff)".into()
    } else {
        fmt_mac(m)
    }
}

pub fn ethernet(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    let (Some(dst), Some(src), Some(et)) = (mac_at(b, o), mac_at(b, o + 6), be16(b, o + 12)) else {
        d.malformed(o, "en-tête Ethernet incomplet");
        return;
    };
    let mut f = Field::proto(
        "eth",
        format!("Ethernet II, de {} vers {}", fmt_mac(&src), mac_label(&dst)),
        o,
        14,
    );
    f.push(Field::new(
        "eth.dst",
        format!("Destination : {}", mac_label(&dst)),
        Value::Mac(dst),
        o,
        6,
    ));
    f.push(Field::new(
        "eth.src",
        format!("Source : {}", fmt_mac(&src)),
        Value::Mac(src),
        o + 6,
        6,
    ));
    f.push(Field::hidden("eth.addr", Value::Mac(dst), o, 6));
    f.push(Field::hidden("eth.addr", Value::Mac(src), o + 6, 6));
    f.push(Field::new(
        "eth.type",
        format!("Type : {} (0x{et:04x})", ethertype_name(et)),
        Value::Uint(et as u64),
        o + 12,
        2,
    ));
    d.tree.push(f);
    d.stack.extend(["eth", "ethertype"]);
    d.meta.eth_src = Some(src);
    d.meta.eth_dst = Some(dst);
    d.src = fmt_mac(&src);
    d.dst = if dst == [0xff; 6] {
        "Broadcast".into()
    } else {
        fmt_mac(&dst)
    };
    d.set_proto("ETH", "eth");
    d.info = format!("Ethernet, type 0x{et:04x}");
    ethertype(et, b, o + 14, d, ctx);
}

fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "802.1Q",
        0x88CC => "LLDP",
        _ => "inconnu",
    }
}

pub fn ethertype(t: u16, b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    match t {
        0x0800 => ipv4(b, o, d, ctx),
        0x86DD => ipv6(b, o, d, ctx),
        0x0806 => arp(b, o, d, ctx),
        0x8100 | 0x88A8 => {
            let (Some(tci), Some(inner)) = (be16(b, o), be16(b, o + 2)) else {
                d.malformed(o, "étiquette VLAN incomplète");
                return;
            };
            let id = tci & 0x0FFF;
            let mut f = Field::proto("vlan", format!("802.1Q, VLAN {id}"), o, 4);
            f.push(Field::new(
                "vlan.id",
                format!("VLAN : {id}"),
                Value::Uint(id as u64),
                o,
                2,
            ));
            f.push(Field::new(
                "vlan.priority",
                format!("Priorité : {}", tci >> 13),
                Value::Uint((tci >> 13) as u64),
                o,
                2,
            ));
            d.tree.push(f);
            d.stack.push("vlan");
            ethertype(inner, b, o + 4, d, ctx);
        }
        0x88CC => {
            d.tree.push(Field::proto(
                "lldp",
                "Link Layer Discovery Protocol",
                o,
                b.len() - o.min(b.len()),
            ));
            d.stack.push("lldp");
            d.set_proto("LLDP", "local");
            d.info = "Annonce d'équipement réseau (LLDP)".into();
        }
        _ => {}
    }
}

pub fn ip_any(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    match b.get(o).map(|v| v >> 4) {
        Some(4) => ipv4(b, o, d, ctx),
        Some(6) => ipv6(b, o, d, ctx),
        _ => d.malformed(o, "version IP inconnue"),
    }
}

fn arp(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    let (Some(htype), Some(ptype), Some(&hlen), Some(&plen), Some(op)) = (
        be16(b, o),
        be16(b, o + 2),
        b.get(o + 4),
        b.get(o + 5),
        be16(b, o + 6),
    ) else {
        d.malformed(o, "ARP incomplet");
        return;
    };
    d.stack.push("arp");
    d.set_proto("ARP", "local");
    let mut f = Field::proto("arp", "", o, 8);
    f.push(Field::new(
        "arp.hw.type",
        format!("Type de matériel : {htype}"),
        Value::Uint(htype as u64),
        o,
        2,
    ));
    f.push(Field::new(
        "arp.proto.type",
        format!("Type de protocole : 0x{ptype:04x}"),
        Value::Uint(ptype as u64),
        o + 2,
        2,
    ));
    let op_name = match op {
        1 => "requête",
        2 => "réponse",
        _ => "autre",
    };
    f.push(Field::new(
        "arp.opcode",
        format!("Opération : {op_name} ({op})"),
        Value::Uint(op as u64),
        o + 6,
        2,
    ));
    if hlen == 6 && plen == 4 && b.len() >= o + 28 {
        let smac = mac_at(b, o + 8).unwrap();
        let sip = Ipv4Addr::new(b[o + 14], b[o + 15], b[o + 16], b[o + 17]);
        let tmac = mac_at(b, o + 18).unwrap();
        let tip = Ipv4Addr::new(b[o + 24], b[o + 25], b[o + 26], b[o + 27]);
        f.label = format!("Address Resolution Protocol ({op_name})");
        f.len = 28;
        f.push(Field::new(
            "arp.src.hw_mac",
            format!("MAC de l'émetteur : {}", fmt_mac(&smac)),
            Value::Mac(smac),
            o + 8,
            6,
        ));
        f.push(Field::new(
            "arp.src.proto_ipv4",
            format!("IP de l'émetteur : {sip}"),
            Value::Ip(sip.into()),
            o + 14,
            4,
        ));
        f.push(Field::new(
            "arp.dst.hw_mac",
            format!("MAC de la cible : {}", fmt_mac(&tmac)),
            Value::Mac(tmac),
            o + 18,
            6,
        ));
        f.push(Field::new(
            "arp.dst.proto_ipv4",
            format!("IP de la cible : {tip}"),
            Value::Ip(tip.into()),
            o + 24,
            4,
        ));
        if ctx.arp_duplicate {
            f.push(
                Field::new(
                    "arp.duplicate-address-detected",
                    "[Une autre machine annonce déjà cette adresse IP]",
                    Value::Bool(true),
                    o + 14,
                    4,
                )
                .with_note("error"),
            );
        }
        d.info = match op {
            1 if sip == tip => format!("ARP Announcement for {sip}"),
            1 => format!("Who has {tip}? Tell {sip}"),
            2 => format!("{sip} is at {}", fmt_mac(&smac)),
            _ => format!("ARP opcode {op}"),
        };
        d.meta.arp = Some(ArpMeta {
            op,
            smac,
            sip: Some(sip.into()),
            tip: Some(tip.into()),
        });
    } else {
        f.label = "Address Resolution Protocol".into();
        d.info = format!("ARP opcode {op}");
    }
    d.tree.push(f);
}

fn ipv4(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    let Some(&vihl) = b.get(o) else {
        return d.malformed(o, "IPv4 vide");
    };
    let ihl = ((vihl & 0x0F) as usize) * 4;
    if ihl < 20 || b.len() < o + ihl {
        return d.malformed(o, "en-tête IPv4 trop court");
    }
    let tos = b[o + 1];
    let total = be16(b, o + 2).unwrap() as usize;
    let id = be16(b, o + 4).unwrap();
    let ff = be16(b, o + 6).unwrap();
    let ttl = b[o + 8];
    let proto = b[o + 9];
    let csum = be16(b, o + 10).unwrap();
    let src = Ipv4Addr::new(b[o + 12], b[o + 13], b[o + 14], b[o + 15]);
    let dst = Ipv4Addr::new(b[o + 16], b[o + 17], b[o + 18], b[o + 19]);
    let df = ff & 0x4000 != 0;
    let mf = ff & 0x2000 != 0;
    let frag = (ff & 0x1FFF) as usize * 8;
    let end = if total >= ihl {
        (o + total).min(b.len())
    } else {
        b.len()
    };

    let mut f = Field::proto(
        "ip",
        format!("Internet Protocol v4, de {src} vers {dst}"),
        o,
        ihl,
    );
    f.push(Field::new(
        "ip.version",
        "Version : 4",
        Value::Uint(4),
        o,
        1,
    ));
    f.push(Field::new(
        "ip.hdr_len",
        format!("Longueur d'en-tête : {ihl} octets"),
        Value::Uint(ihl as u64),
        o,
        1,
    ));
    f.push(Field::new(
        "ip.dsfield",
        format!("Services différenciés : 0x{tos:02x} (DSCP {})", tos >> 2),
        Value::Uint(tos as u64),
        o + 1,
        1,
    ));
    f.push(Field::new(
        "ip.len",
        format!("Longueur totale : {total}"),
        Value::Uint(total as u64),
        o + 2,
        2,
    ));
    f.push(Field::new(
        "ip.id",
        format!("Identification : 0x{id:04x} ({id})"),
        Value::Uint(id as u64),
        o + 4,
        2,
    ));
    let mut flags = Field::new(
        "ip.flags",
        format!(
            "Drapeaux : 0x{:x}{}",
            ff >> 13,
            if df { ", Ne pas fragmenter" } else { "" }
        ),
        Value::Uint((ff >> 13) as u64),
        o + 6,
        1,
    );
    flags.push(Field::new(
        "ip.flags.df",
        format!("Ne pas fragmenter : {}", df as u8),
        Value::Bool(df),
        o + 6,
        1,
    ));
    flags.push(Field::new(
        "ip.flags.mf",
        format!("Autres fragments : {}", mf as u8),
        Value::Bool(mf),
        o + 6,
        1,
    ));
    f.push(flags);
    f.push(Field::new(
        "ip.frag_offset",
        format!("Position du fragment : {frag}"),
        Value::Uint(frag as u64),
        o + 6,
        2,
    ));
    f.push(Field::new(
        "ip.ttl",
        format!("Durée de vie (TTL) : {ttl}"),
        Value::Uint(ttl as u64),
        o + 8,
        1,
    ));
    f.push(Field::new(
        "ip.proto",
        format!("Protocole : {} ({proto})", ip_proto_name(proto)),
        Value::Uint(proto as u64),
        o + 9,
        1,
    ));
    f.push(Field::new(
        "ip.checksum",
        format!("Somme de contrôle : 0x{csum:04x}"),
        Value::Uint(csum as u64),
        o + 10,
        2,
    ));
    f.push(Field::new(
        "ip.src",
        format!("Source : {src}"),
        Value::Ip(src.into()),
        o + 12,
        4,
    ));
    f.push(Field::new(
        "ip.dst",
        format!("Destination : {dst}"),
        Value::Ip(dst.into()),
        o + 16,
        4,
    ));
    f.push(Field::hidden("ip.addr", Value::Ip(src.into()), o + 12, 4));
    f.push(Field::hidden("ip.addr", Value::Ip(dst.into()), o + 16, 4));
    d.tree.push(f);
    d.stack.push("ip");
    d.meta.ip_src = Some(src.into());
    d.meta.ip_dst = Some(dst.into());
    d.meta.ttl = Some(ttl);
    d.src = src.to_string();
    d.dst = dst.to_string();
    d.set_proto("IPv4", "other");
    d.info = format!("Protocole IP {proto}");
    if frag > 0 {
        d.info = format!("Fragmented IP protocol (proto={proto}, off={frag})");
        return;
    }
    l4(proto, b, o + ihl, end, d, ctx);
}

fn ipv6(b: &[u8], o: usize, d: &mut Dissection, ctx: &PacketCtx) {
    if b.len() < o + 40 {
        return d.malformed(o, "en-tête IPv6 trop court");
    }
    let plen = be16(b, o + 4).unwrap() as usize;
    let mut nxt = b[o + 6];
    let hlim = b[o + 7];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[o + 8..o + 24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[o + 24..o + 40]).unwrap());
    let mut f = Field::proto(
        "ipv6",
        format!("Internet Protocol v6, de {src} vers {dst}"),
        o,
        40,
    );
    f.push(Field::new(
        "ipv6.plen",
        format!("Longueur des données : {plen}"),
        Value::Uint(plen as u64),
        o + 4,
        2,
    ));
    f.push(Field::new(
        "ipv6.nxt",
        format!("En-tête suivant : {} ({nxt})", ip_proto_name(nxt)),
        Value::Uint(nxt as u64),
        o + 6,
        1,
    ));
    f.push(Field::new(
        "ipv6.hlim",
        format!("Limite de sauts : {hlim}"),
        Value::Uint(hlim as u64),
        o + 7,
        1,
    ));
    f.push(Field::new(
        "ipv6.src",
        format!("Source : {src}"),
        Value::Ip(src.into()),
        o + 8,
        16,
    ));
    f.push(Field::new(
        "ipv6.dst",
        format!("Destination : {dst}"),
        Value::Ip(dst.into()),
        o + 24,
        16,
    ));
    f.push(Field::hidden("ipv6.addr", Value::Ip(src.into()), o + 8, 16));
    f.push(Field::hidden(
        "ipv6.addr",
        Value::Ip(dst.into()),
        o + 24,
        16,
    ));
    let end = (o + 40 + plen).min(b.len());
    let mut p = o + 40;
    // Skip extension headers we do not decode: hop-by-hop, routing, destination options, fragment.
    loop {
        match nxt {
            0 | 43 | 60 => {
                let (Some(&n), Some(&l)) = (b.get(p), b.get(p + 1)) else {
                    break;
                };
                let len = (l as usize + 1) * 8;
                f.push(Field::proto(
                    "ipv6.ext",
                    format!("En-tête d'extension {nxt} ({len} octets)"),
                    p,
                    len,
                ));
                nxt = n;
                p += len;
            }
            44 => {
                let Some(&n) = b.get(p) else { break };
                let off = be16(b, p + 2).unwrap_or(0) >> 3;
                f.push(Field::proto("ipv6.fragment", "En-tête de fragment", p, 8));
                nxt = n;
                p += 8;
                if off != 0 {
                    nxt = 59;
                }
            }
            _ => break,
        }
    }
    d.tree.push(f);
    d.stack.push("ipv6");
    d.meta.ip_src = Some(src.into());
    d.meta.ip_dst = Some(dst.into());
    d.meta.ttl = Some(hlim);
    d.src = src.to_string();
    d.dst = dst.to_string();
    d.set_proto("IPv6", "other");
    d.info = format!("Protocole IP {nxt}");
    l4(nxt, b, p, end, d, ctx);
}

fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        58 => "ICMPv6",
        _ => "autre",
    }
}

fn l4(proto: u8, b: &[u8], o: usize, end: usize, d: &mut Dissection, ctx: &PacketCtx) {
    let b = &b[..end.max(o).min(b.len())];
    match proto {
        6 => transport::tcp(b, o, d, ctx),
        17 => transport::udp(b, o, d, ctx),
        1 => icmp(b, o, d, false),
        58 => icmp(b, o, d, true),
        2 => {
            d.tree.push(Field::proto(
                "igmp",
                "Internet Group Management Protocol",
                o,
                b.len().saturating_sub(o),
            ));
            d.stack.push("igmp");
            d.set_proto("IGMP", "local");
            d.info = "Abonnement multicast (IGMP)".into();
        }
        _ => {}
    }
}

fn icmp(b: &[u8], o: usize, d: &mut Dissection, v6: bool) {
    let (Some(&t), Some(&c)) = (b.get(o), b.get(o + 1)) else {
        return d.malformed(o, "ICMP incomplet");
    };
    let (name, key, tkey, ckey) = if v6 {
        ("ICMPv6", "icmpv6", "icmpv6.type", "icmpv6.code")
    } else {
        ("ICMP", "icmp", "icmp.type", "icmp.code")
    };
    let what = icmp_text(t, c, v6);
    let mut f = Field::proto(
        key,
        format!(
            "{} : {what}",
            if v6 {
                "Internet Control Message Protocol v6"
            } else {
                "Internet Control Message Protocol"
            }
        ),
        o,
        b.len() - o,
    );
    f.push(Field::new(
        tkey,
        format!("Type : {t}"),
        Value::Uint(t as u64),
        o,
        1,
    ));
    f.push(Field::new(
        ckey,
        format!("Code : {c}"),
        Value::Uint(c as u64),
        o + 1,
        1,
    ));
    if let Some(cs) = be16(b, o + 2) {
        f.push(Field::new(
            if v6 {
                "icmpv6.checksum"
            } else {
                "icmp.checksum"
            },
            format!("Somme de contrôle : 0x{cs:04x}"),
            Value::Uint(cs as u64),
            o + 2,
            2,
        ));
    }
    d.tree.push(f);
    d.stack.push(key);
    d.meta.l4 = L4::Icmp;
    d.meta.icmp = Some((t, c, v6));
    d.set_proto(
        name,
        if v6 && (133..=137).contains(&t) {
            "local"
        } else {
            "icmp"
        },
    );
    d.info = what;
}

fn icmp_text(t: u8, c: u8, v6: bool) -> String {
    if v6 {
        return match t {
            1 => format!("Destination unreachable (code {c})"),
            2 => "Packet too big".into(),
            3 => "Time exceeded".into(),
            128 => "Echo (ping) request".into(),
            129 => "Echo (ping) reply".into(),
            133 => "Router Solicitation".into(),
            134 => "Router Advertisement".into(),
            135 => "Neighbor Solicitation".into(),
            136 => "Neighbor Advertisement".into(),
            _ => format!("Type {t}, code {c}"),
        };
    }
    match t {
        0 => "Echo (ping) reply".into(),
        8 => "Echo (ping) request".into(),
        3 => format!(
            "Destination unreachable ({})",
            match c {
                0 => "Network unreachable",
                1 => "Host unreachable",
                3 => "Port unreachable",
                4 => "Fragmentation needed",
                13 => "Communication administratively filtered",
                _ => "other",
            }
        ),
        11 => "Time-to-live exceeded".into(),
        5 => "Redirect".into(),
        _ => format!("Type {t}, code {c}"),
    }
}

pub(crate) fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_loopback(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
