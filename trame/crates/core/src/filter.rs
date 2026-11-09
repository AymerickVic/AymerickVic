//! Display filters with Wireshark's syntax.
//!
//! Supported: field presence (`dns`), comparisons (`==` `!=` `<` `<=` `>` `>=`
//! and their word forms `eq` `ne` `lt` `le` `gt` `ge`), `contains`, `matches`
//! (case-insensitive substring for now), bitwise test (`tcp.flags & 0x02`),
//! sets (`tcp.port in {80 443}`), CIDR (`ip.addr == 192.168.0.0/16`),
//! `&&`/`and`, `||`/`or`, `!`/`not` and parentheses.
//!
//! As in Wireshark, `a == x` is true when any occurrence of `a` equals `x`, and
//! `a != x` is true when `a` is present and no occurrence equals `x`.

use crate::tree::{Field, Value};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub struct FilterError {
    pub message: String,
    pub at: usize,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (position {})", self.message, self.at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Matches,
    BitAnd,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Exists(String),
    Cmp(String, Op, Lit),
    In(String, Vec<Lit>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone)]
pub struct Lit {
    raw: String,
    num: Option<f64>,
    ip: Option<(IpAddr, u8)>,
    mac: Option<Vec<u8>>,
}

impl Lit {
    fn new(raw: String, quoted: bool) -> Lit {
        if quoted {
            return Lit {
                raw,
                num: None,
                ip: None,
                mac: None,
            };
        }
        let num = if let Some(h) = raw.strip_prefix("0x") {
            u64::from_str_radix(h, 16).ok().map(|v| v as f64)
        } else {
            match raw.as_str() {
                "true" | "True" | "TRUE" => Some(1.0),
                "false" | "False" | "FALSE" => Some(0.0),
                _ => raw.parse::<f64>().ok(),
            }
        };
        let ip = {
            let (addr, bits) = raw
                .split_once('/')
                .map(|(a, b)| (a, b.parse::<u8>().ok()))
                .unwrap_or((raw.as_str(), None));
            addr.parse::<IpAddr>()
                .ok()
                .map(|ip| (ip, bits.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })))
        };
        let mac = {
            let parts: Vec<&str> = raw.split([':', '-', '.']).collect();
            if parts.len() >= 2
                && parts
                    .iter()
                    .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
            {
                Some(
                    parts
                        .iter()
                        .map(|p| u8::from_str_radix(p, 16).unwrap())
                        .collect(),
                )
            } else {
                None
            }
        };
        Lit { raw, num, ip, mac }
    }
}

/// Protocol prefixes this engine knows. A filter on any other prefix is rejected
/// so typos (`tpc.port`) are reported instead of silently matching nothing.
pub const PROTOCOLS: &[&str] = &[
    "frame", "eth", "vlan", "arp", "ip", "ipv6", "icmp", "icmpv6", "igmp", "tcp", "udp", "dns",
    "mdns", "tls", "quic", "http", "nbss", "smb", "smb2", "dhcp", "ntp", "ssdp", "lldp", "data",
    "sll", "null", "_ws",
];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Op(&'static str),
}

fn lex(s: &str) -> Result<Vec<(Tok, usize)>, FilterError> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let two = s.get(i..i + 2).unwrap_or("");
        match two {
            "==" | "!=" | "<=" | ">=" | "&&" | "||" => {
                let t: &'static str = match two {
                    "==" => "==",
                    "!=" => "!=",
                    "<=" => "<=",
                    ">=" => ">=",
                    "&&" => "&&",
                    _ => "||",
                };
                out.push((Tok::Op(t), i));
                i += 2;
                continue;
            }
            _ => {}
        }
        match c {
            b'(' => out.push((Tok::LParen, i)),
            b')' => out.push((Tok::RParen, i)),
            b'{' => out.push((Tok::LBrace, i)),
            b'}' => out.push((Tok::RBrace, i)),
            b',' => out.push((Tok::Comma, i)),
            b'<' => out.push((Tok::Op("<"), i)),
            b'>' => out.push((Tok::Op(">"), i)),
            b'!' => out.push((Tok::Op("!"), i)),
            b'~' => out.push((Tok::Op("~"), i)),
            b'&' => out.push((Tok::Op("&"), i)),
            b'=' => out.push((Tok::Op("=="), i)),
            b'"' => {
                let start = i;
                let mut v = String::new();
                i += 1;
                loop {
                    match b.get(i) {
                        None => {
                            return Err(FilterError {
                                message: "Guillemet non fermé".into(),
                                at: start,
                            })
                        }
                        Some(b'"') => break,
                        Some(b'\\') => {
                            if let Some(&n) = b.get(i + 1) {
                                v.push(n as char);
                            }
                            i += 2;
                            continue;
                        }
                        Some(_) => {
                            let ch = s[i..].chars().next().unwrap();
                            v.push(ch);
                            i += ch.len_utf8();
                            continue;
                        }
                    }
                }
                out.push((Tok::Str(v), start));
            }
            _ => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric()
                        || matches!(b[i], b'_' | b'.' | b':' | b'-' | b'/'))
                {
                    i += 1;
                }
                if i == start {
                    return Err(FilterError {
                        message: format!(
                            "Caractère inattendu « {} »",
                            &s[i..].chars().next().unwrap()
                        ),
                        at: i,
                    });
                }
                out.push((Tok::Word(s[start..i].to_string()), start));
                continue;
            }
        }
        i += 1;
    }
    Ok(out)
}

struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    len: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.0)
    }
    fn at(&self) -> usize {
        self.toks.get(self.pos).map(|t| t.1).unwrap_or(self.len)
    }
    fn err<T>(&self, m: impl Into<String>) -> Result<T, FilterError> {
        Err(FilterError {
            message: m.into(),
            at: self.at(),
        })
    }
    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }
    fn or(&mut self) -> Result<Expr, FilterError> {
        let mut l = self.and()?;
        while matches!(self.peek(), Some(Tok::Op("||"))) || self.is_word("or") {
            self.pos += 1;
            let r = self.and()?;
            l = Expr::Or(Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn and(&mut self) -> Result<Expr, FilterError> {
        let mut l = self.not()?;
        while matches!(self.peek(), Some(Tok::Op("&&"))) || self.is_word("and") {
            self.pos += 1;
            let r = self.not()?;
            l = Expr::And(Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn not(&mut self) -> Result<Expr, FilterError> {
        if matches!(self.peek(), Some(Tok::Op("!"))) || self.is_word("not") {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }
    fn literal(&mut self) -> Result<Lit, FilterError> {
        match self.toks.get(self.pos).cloned() {
            Some((Tok::Word(w), _)) => {
                self.pos += 1;
                Ok(Lit::new(w, false))
            }
            Some((Tok::Str(s), _)) => {
                self.pos += 1;
                Ok(Lit::new(s, true))
            }
            _ => self.err("Valeur attendue après l'opérateur"),
        }
    }
    fn primary(&mut self) -> Result<Expr, FilterError> {
        match self.toks.get(self.pos).cloned() {
            Some((Tok::LParen, _)) => {
                self.pos += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return self.err("Parenthèse fermante attendue");
                }
                self.pos += 1;
                Ok(e)
            }
            Some((Tok::Word(name), at)) => {
                let proto = name.split('.').next().unwrap_or("");
                if !PROTOCOLS.contains(&proto) {
                    return Err(FilterError {
                        message: format!("Champ ou protocole inconnu : « {name} »"),
                        at,
                    });
                }
                self.pos += 1;
                let op = match self.peek() {
                    Some(Tok::Op("==")) => Some(Op::Eq),
                    Some(Tok::Op("!=")) => Some(Op::Ne),
                    Some(Tok::Op("<")) => Some(Op::Lt),
                    Some(Tok::Op("<=")) => Some(Op::Le),
                    Some(Tok::Op(">")) => Some(Op::Gt),
                    Some(Tok::Op(">=")) => Some(Op::Ge),
                    Some(Tok::Op("~")) => Some(Op::Matches),
                    Some(Tok::Op("&")) => Some(Op::BitAnd),
                    Some(Tok::Word(w)) => match w.as_str() {
                        "eq" => Some(Op::Eq),
                        "ne" => Some(Op::Ne),
                        "lt" => Some(Op::Lt),
                        "le" => Some(Op::Le),
                        "gt" => Some(Op::Gt),
                        "ge" => Some(Op::Ge),
                        "contains" => Some(Op::Contains),
                        "matches" => Some(Op::Matches),
                        "in" => {
                            self.pos += 1;
                            if self.peek() != Some(&Tok::LBrace) {
                                return self.err("« { » attendu après « in »");
                            }
                            self.pos += 1;
                            let mut set = Vec::new();
                            while self.peek() != Some(&Tok::RBrace) {
                                if self.peek().is_none() {
                                    return self.err("« } » attendu");
                                }
                                if self.peek() == Some(&Tok::Comma) {
                                    self.pos += 1;
                                    continue;
                                }
                                set.push(self.literal()?);
                            }
                            self.pos += 1;
                            return Ok(Expr::In(name, set));
                        }
                        _ => None,
                    },
                    _ => None,
                };
                match op {
                    Some(op) => {
                        self.pos += 1;
                        let lit = self.literal()?;
                        Ok(Expr::Cmp(name, op, lit))
                    }
                    None => Ok(Expr::Exists(name)),
                }
            }
            Some((Tok::Str(_), _)) => self.err("Un nom de champ est attendu ici, pas une valeur"),
            Some(_) => self.err("Expression attendue"),
            None => self.err("Le filtre se termine trop tôt"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Filter {
    expr: Expr,
    names: Vec<String>,
}

impl Filter {
    pub fn parse(s: &str) -> Result<Filter, FilterError> {
        let toks = lex(s)?;
        if toks.is_empty() {
            return Err(FilterError {
                message: "Filtre vide".into(),
                at: 0,
            });
        }
        let mut p = Parser {
            toks,
            pos: 0,
            len: s.len(),
        };
        let expr = p.or()?;
        if p.pos < p.toks.len() {
            return p.err("Élément inattendu : il manque peut-être « && » ou « || »");
        }
        let mut names = Vec::new();
        collect(&expr, &mut names);
        Ok(Filter { expr, names })
    }

    /// Evaluate against a dissected frame's field tree.
    pub fn matches(&self, tree: &[Field]) -> bool {
        let mut idx: HashMap<&str, Vec<&Value>> = HashMap::new();
        let mut all = Vec::new();
        for f in tree {
            f.walk(&mut all);
        }
        for f in all {
            if self.names.iter().any(|n| n == f.name) {
                idx.entry(f.name).or_default().push(&f.value);
            }
        }
        eval(&self.expr, &idx)
    }
}

fn collect(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Exists(n) | Expr::Cmp(n, _, _) | Expr::In(n, _) => {
            if !out.contains(n) {
                out.push(n.clone())
            }
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            collect(a, out);
            collect(b, out);
        }
        Expr::Not(a) => collect(a, out),
    }
}

fn eval(e: &Expr, idx: &HashMap<&str, Vec<&Value>>) -> bool {
    match e {
        Expr::Exists(n) => idx.contains_key(n.as_str()),
        // Wireshark 4: `a != x` holds when `a` is present and no occurrence equals x.
        Expr::Cmp(n, Op::Ne, lit) => idx
            .get(n.as_str())
            .map(|vs| !vs.iter().any(|v| cmp(v, Op::Eq, lit)))
            .unwrap_or(false),
        Expr::Cmp(n, op, lit) => idx
            .get(n.as_str())
            .map(|vs| vs.iter().any(|v| cmp(v, *op, lit)))
            .unwrap_or(false),
        Expr::In(n, set) => idx
            .get(n.as_str())
            .map(|vs| vs.iter().any(|v| set.iter().any(|l| cmp(v, Op::Eq, l))))
            .unwrap_or(false),
        Expr::And(a, b) => eval(a, idx) && eval(b, idx),
        Expr::Or(a, b) => eval(a, idx) || eval(b, idx),
        Expr::Not(a) => !eval(a, idx),
    }
}

fn ord(a: f64, op: Op, b: f64) -> bool {
    match op {
        Op::Eq => a == b,
        Op::Ne => a != b,
        Op::Lt => a < b,
        Op::Le => a <= b,
        Op::Gt => a > b,
        Op::Ge => a >= b,
        Op::BitAnd => (a as u64) & (b as u64) != 0,
        _ => false,
    }
}

fn in_net(ip: &IpAddr, net: &IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits.min(32) as u32)
            };
            (u32::from(*a) & m) == (u32::from(*n) & m)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits.min(128) as u32)
            };
            (u128::from(*a) & m) == (u128::from(*n) & m)
        }
        _ => false,
    }
}

fn cmp(v: &Value, op: Op, lit: &Lit) -> bool {
    match v {
        Value::Uint(x) => lit.num.map(|n| ord(*x as f64, op, n)).unwrap_or(false),
        Value::Float(x) => lit.num.map(|n| ord(*x, op, n)).unwrap_or(false),
        Value::Bool(x) => lit
            .num
            .map(|n| ord(*x as u8 as f64, op, n))
            .unwrap_or(false),
        Value::Ip(ip) => match (op, lit.ip) {
            (Op::Eq, Some((net, bits))) => in_net(ip, &net, bits),
            _ => false,
        },
        Value::Mac(m) => match (op, &lit.mac) {
            (Op::Eq, Some(l)) => l.as_slice() == m,
            _ => false,
        },
        Value::Str(s) => match op {
            Op::Eq => *s == lit.raw,
            Op::Contains => s.contains(&lit.raw),
            Op::Matches => s.to_lowercase().contains(&lit.raw.to_lowercase()),
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                ord(s.as_str().cmp(lit.raw.as_str()) as i8 as f64, op, 0.0)
            }
            _ => false,
        },
        Value::Bytes(b) => match op {
            Op::Eq => lit.mac.as_deref() == Some(b.as_slice()),
            Op::Contains => {
                let needle = lit
                    .mac
                    .clone()
                    .unwrap_or_else(|| lit.raw.as_bytes().to_vec());
                !needle.is_empty() && b.windows(needle.len()).any(|w| w == needle.as_slice())
            }
            _ => false,
        },
        Value::None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tree() -> Vec<Field> {
        let mut ip = Field::proto("ip", "", 0, 20);
        ip.push(Field::new(
            "ip.src",
            "",
            Value::Ip(Ipv4Addr::new(192, 168, 1, 24).into()),
            0,
            4,
        ));
        ip.push(Field::hidden(
            "ip.addr",
            Value::Ip(Ipv4Addr::new(192, 168, 1, 24).into()),
            0,
            4,
        ));
        ip.push(Field::hidden(
            "ip.addr",
            Value::Ip(Ipv4Addr::new(1, 1, 1, 1).into()),
            0,
            4,
        ));
        let mut tcp = Field::proto("tcp", "", 20, 20);
        tcp.push(Field::new("tcp.port", "", Value::Uint(443), 0, 2));
        tcp.push(Field::new("tcp.port", "", Value::Uint(52814), 0, 2));
        tcp.push(Field::new("tcp.flags", "", Value::Uint(0x012), 0, 2));
        tcp.push(Field::new("tcp.flags.syn", "", Value::Bool(true), 0, 2));
        let mut tls = Field::proto("tls", "", 40, 10);
        tls.push(Field::new(
            "tls.handshake.extensions_server_name",
            "",
            Value::Str("api.github.com".into()),
            0,
            0,
        ));
        vec![ip, tcp, tls]
    }

    fn m(s: &str) -> bool {
        Filter::parse(s).unwrap().matches(&tree())
    }

    #[test]
    fn wireshark_semantics() {
        assert!(m("tcp"));
        assert!(!m("udp"));
        assert!(m("tcp.port == 443"));
        assert!(m("tcp.port eq 52814 and tls"));
        assert!(!m("tcp.port != 443"));
        assert!(m("ip.addr == 192.168.0.0/16"));
        assert!(m("ip.addr == 1.1.1.1 && !dns"));
        assert!(m("tcp.flags.syn == 1"));
        assert!(m("tcp.flags & 0x02"));
        assert!(m("tcp.port in {80 443}"));
        assert!(m(
            "tls.handshake.extensions_server_name contains \"github\""
        ));
        assert!(m("tls.handshake.extensions_server_name matches \"GITHUB\""));
        assert!(m("(udp || tcp) && not icmp"));
        assert!(!m("tcp.port > 60000"));
    }

    #[test]
    fn helpful_errors() {
        assert!(Filter::parse("tpc.port == 80")
            .unwrap_err()
            .message
            .contains("inconnu"));
        assert!(Filter::parse("tcp.port ==").is_err());
        assert!(Filter::parse("tcp.port == 80 udp").is_err());
        assert!(Filter::parse("(tcp").is_err());
        assert!(Filter::parse("dns.qry.name == \"oops").is_err());
    }
}
