//! pcap (libpcap) and pcapng readers.

use std::fmt;

#[derive(Debug, PartialEq)]
pub enum CaptureError {
    TooShort,
    UnknownFormat,
    BadBlock(usize),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::TooShort => write!(f, "the file is too short to be a capture"),
            CaptureError::UnknownFormat => write!(f, "not a pcap or pcapng file"),
            CaptureError::BadBlock(at) => write!(f, "corrupted block at byte {at}"),
        }
    }
}

impl std::error::Error for CaptureError {}

#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Absolute timestamp, seconds since the Unix epoch.
    pub ts: f64,
    /// Length on the wire (may be larger than `data.len()` when the capture was sliced).
    pub orig_len: u32,
    /// Link-layer type (LINKTYPE_* value).
    pub linktype: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct CaptureFile {
    pub format: &'static str,
    pub packets: Vec<RawPacket>,
    /// The file ended in the middle of a record or block: what came before is still usable.
    pub truncated: bool,
}

#[derive(Clone, Copy)]
struct Endian {
    le: bool,
}

impl Endian {
    fn u16(self, b: &[u8], o: usize) -> Option<u16> {
        let s: [u8; 2] = b.get(o..o + 2)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(s)
        } else {
            u16::from_be_bytes(s)
        })
    }
    fn u32(self, b: &[u8], o: usize) -> Option<u32> {
        let s: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(s)
        } else {
            u32::from_be_bytes(s)
        })
    }
}

/// Detect the format from the first bytes and read every packet.
pub fn read(buf: &[u8]) -> Result<CaptureFile, CaptureError> {
    if buf.len() < 4 {
        return Err(CaptureError::TooShort);
    }
    match &buf[0..4] {
        [0x0A, 0x0D, 0x0D, 0x0A] => read_pcapng(buf),
        [0xD4, 0xC3, 0xB2, 0xA1]
        | [0xA1, 0xB2, 0xC3, 0xD4]
        | [0x4D, 0x3C, 0xB2, 0xA1]
        | [0xA1, 0xB2, 0x3C, 0x4D] => read_pcap(buf),
        _ => Err(CaptureError::UnknownFormat),
    }
}

fn read_pcap(buf: &[u8]) -> Result<CaptureFile, CaptureError> {
    if buf.len() < 24 {
        return Err(CaptureError::TooShort);
    }
    let (le, nanos) = match &buf[0..4] {
        [0xD4, 0xC3, 0xB2, 0xA1] => (true, false),
        [0xA1, 0xB2, 0xC3, 0xD4] => (false, false),
        [0x4D, 0x3C, 0xB2, 0xA1] => (true, true),
        _ => (false, true),
    };
    let e = Endian { le };
    let network = e.u32(buf, 20).unwrap_or(1);
    // LINKTYPE values above 0xFFFF carry FCS info in the upper bits; keep the type itself.
    let linktype = (network & 0xFFFF) as u16;
    let div = if nanos { 1e9 } else { 1e6 };
    let mut cap = CaptureFile {
        format: "pcap",
        ..Default::default()
    };
    let mut o = 24;
    while o + 16 <= buf.len() {
        let sec = e.u32(buf, o).unwrap() as f64;
        let frac = e.u32(buf, o + 4).unwrap() as f64;
        let incl = e.u32(buf, o + 8).unwrap() as usize;
        let orig = e.u32(buf, o + 12).unwrap();
        let start = o + 16;
        if incl > 0x0400_0000 {
            return Err(CaptureError::BadBlock(o));
        }
        if start + incl > buf.len() {
            cap.truncated = true;
            break;
        }
        cap.packets.push(RawPacket {
            ts: sec + frac / div,
            orig_len: orig,
            linktype,
            data: buf[start..start + incl].to_vec(),
        });
        o = start + incl;
    }
    if o < buf.len() && o + 16 > buf.len() {
        cap.truncated = true;
    }
    Ok(cap)
}

struct Iface {
    linktype: u16,
    /// Seconds per timestamp unit.
    unit: f64,
    snaplen: u32,
}

fn read_pcapng(buf: &[u8]) -> Result<CaptureFile, CaptureError> {
    let mut cap = CaptureFile {
        format: "pcapng",
        ..Default::default()
    };
    let mut e = Endian { le: true };
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut o = 0;
    while o + 12 <= buf.len() {
        // The section header decides byte order for everything after it.
        if buf[o..o + 4] == [0x0A, 0x0D, 0x0D, 0x0A] {
            match buf.get(o + 8..o + 12) {
                Some([0x4D, 0x3C, 0x2B, 0x1A]) => e = Endian { le: true },
                Some([0x1A, 0x2B, 0x3C, 0x4D]) => e = Endian { le: false },
                _ => return Err(CaptureError::BadBlock(o)),
            }
            ifaces.clear();
        }
        let btype = e.u32(buf, o).unwrap();
        let blen = e.u32(buf, o + 4).unwrap() as usize;
        if blen < 12 || blen % 4 != 0 {
            return Err(CaptureError::BadBlock(o));
        }
        if o + blen > buf.len() {
            cap.truncated = true;
            break;
        }
        let body = &buf[o + 8..o + blen - 4];
        match btype {
            0x0000_0001 => {
                let linktype = e.u16(body, 0).unwrap_or(1);
                let snaplen = e.u32(body, 4).unwrap_or(0);
                let mut unit = 1e-6;
                let mut p = 8;
                while p + 4 <= body.len() {
                    let code = e.u16(body, p).unwrap();
                    let len = e.u16(body, p + 2).unwrap() as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && len >= 1 {
                        let v = body[p + 4];
                        unit = if v & 0x80 == 0 {
                            10f64.powi(-(v as i32))
                        } else {
                            2f64.powi(-((v & 0x7F) as i32))
                        };
                    }
                    p += 4 + ((len + 3) & !3);
                }
                ifaces.push(Iface {
                    linktype,
                    unit,
                    snaplen,
                });
            }
            0x0000_0006 | 0x0000_0002 => {
                let (iface_id, hi, lo, caplen, origlen, data_off) = if btype == 6 {
                    (
                        e.u32(body, 0),
                        e.u32(body, 4),
                        e.u32(body, 8),
                        e.u32(body, 12),
                        e.u32(body, 16),
                        20,
                    )
                } else {
                    (
                        e.u16(body, 0).map(u32::from),
                        e.u32(body, 4),
                        e.u32(body, 8),
                        e.u32(body, 12),
                        e.u32(body, 16),
                        20,
                    )
                };
                let (Some(iface_id), Some(hi), Some(lo), Some(caplen), Some(origlen)) =
                    (iface_id, hi, lo, caplen, origlen)
                else {
                    return Err(CaptureError::BadBlock(o));
                };
                let caplen = caplen as usize;
                let iface = ifaces.get(iface_id as usize);
                let data = body
                    .get(data_off..data_off + caplen)
                    .ok_or(CaptureError::BadBlock(o))?;
                let raw = ((hi as u64) << 32) | lo as u64;
                cap.packets.push(RawPacket {
                    ts: raw as f64 * iface.map(|i| i.unit).unwrap_or(1e-6),
                    orig_len: origlen,
                    linktype: iface.map(|i| i.linktype).unwrap_or(1),
                    data: data.to_vec(),
                });
            }
            0x0000_0003 => {
                let origlen = e.u32(body, 0).unwrap_or(0);
                let iface = ifaces.first();
                let mut caplen = (origlen as usize).min(body.len().saturating_sub(4));
                if let Some(i) = iface {
                    if i.snaplen > 0 {
                        caplen = caplen.min(i.snaplen as usize);
                    }
                }
                cap.packets.push(RawPacket {
                    ts: cap.packets.last().map(|p| p.ts).unwrap_or(0.0),
                    orig_len: origlen,
                    linktype: iface.map(|i| i.linktype).unwrap_or(1),
                    data: body[4..4 + caplen].to_vec(),
                });
            }
            _ => {}
        }
        o += blen;
    }
    Ok(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap_le(packets: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut v = vec![
            0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 1, 0, 0,
            0,
        ];
        for (s, us, d) in packets {
            v.extend(s.to_le_bytes());
            v.extend(us.to_le_bytes());
            v.extend((d.len() as u32).to_le_bytes());
            v.extend((d.len() as u32).to_le_bytes());
            v.extend_from_slice(d);
        }
        v
    }

    #[test]
    fn reads_pcap_and_keeps_partial_file() {
        let mut f = pcap_le(&[(10, 500_000, &[1, 2, 3]), (11, 0, &[4, 5])]);
        let c = read(&f).unwrap();
        assert_eq!(c.packets.len(), 2);
        assert_eq!(c.packets[0].ts, 10.5);
        assert!(!c.truncated);
        f.truncate(f.len() - 1);
        let c = read(&f).unwrap();
        assert_eq!(c.packets.len(), 1);
        assert!(c.truncated);
    }

    #[test]
    fn rejects_other_files() {
        assert_eq!(
            read(b"PK\x03\x04hello").unwrap_err(),
            CaptureError::UnknownFormat
        );
    }
}
