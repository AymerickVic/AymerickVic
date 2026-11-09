//! Field tree produced by the dissectors.
//!
//! Field names follow Wireshark's display-filter names (`ip.src`, `tcp.flags.syn`,
//! `dns.qry.name`…) so that filters written for Wireshark keep working.

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    None,
    Uint(u64),
    Float(f64),
    Bool(bool),
    Str(String),
    Ip(IpAddr),
    Mac([u8; 6]),
    Bytes(Vec<u8>),
}

impl Value {
    /// The value written the way a display filter expects it, or `None` for protocol nodes.
    pub fn filter_literal(&self) -> Option<String> {
        Some(match self {
            Value::None => return None,
            Value::Uint(v) => v.to_string(),
            Value::Float(v) => format!("{v}"),
            Value::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
            Value::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            Value::Ip(ip) => ip.to_string(),
            Value::Mac(m) => fmt_mac(m),
            Value::Bytes(b) => b
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: &'static str,
    pub label: String,
    pub value: Value,
    /// Byte offset in the frame and length, for hex highlighting.
    pub off: usize,
    pub len: usize,
    /// Hidden fields are filterable but not shown (like Wireshark's `ip.addr`).
    pub hidden: bool,
    /// Expert note: "warn" or "error" style, shown in colour.
    pub note: Option<&'static str>,
    pub children: Vec<Field>,
}

impl Field {
    pub fn new(
        name: &'static str,
        label: impl Into<String>,
        value: Value,
        off: usize,
        len: usize,
    ) -> Self {
        Field {
            name,
            label: label.into(),
            value,
            off,
            len,
            hidden: false,
            note: None,
            children: Vec::new(),
        }
    }
    pub fn proto(name: &'static str, label: impl Into<String>, off: usize, len: usize) -> Self {
        Field::new(name, label, Value::None, off, len)
    }
    pub fn hidden(name: &'static str, value: Value, off: usize, len: usize) -> Self {
        let mut f = Field::new(name, "", value, off, len);
        f.hidden = true;
        f
    }
    pub fn with_note(mut self, n: &'static str) -> Self {
        self.note = Some(n);
        self
    }
    pub fn push(&mut self, f: Field) -> &mut Self {
        self.children.push(f);
        self
    }
    /// Visit every field depth-first.
    pub fn walk<'a>(&'a self, out: &mut Vec<&'a Field>) {
        out.push(self);
        for c in &self.children {
            c.walk(out);
        }
    }
}

impl Serialize for Field {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let visible: Vec<&Field> = self.children.iter().filter(|c| !c.hidden).collect();
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("n", self.name)?;
        m.serialize_entry("l", &self.label)?;
        m.serialize_entry("o", &self.off)?;
        m.serialize_entry("s", &self.len)?;
        if let Some(v) = self.value.filter_literal() {
            m.serialize_entry("v", &v)?;
        }
        if let Some(n) = self.note {
            m.serialize_entry("x", n)?;
        }
        if !visible.is_empty() {
            m.serialize_entry("c", &visible)?;
        }
        m.end()
    }
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}
