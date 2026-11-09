//! Captures come from untrusted sources: no input may crash the engine.

use trame_core::capture::RawPacket;
use trame_core::dissect::{dissect, PacketCtx};
use trame_core::filter::Filter;
use trame_core::Session;

#[test]
fn truncated_and_corrupted_frames_never_panic() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sample.pcapng"
    ))
    .unwrap();
    let s = Session::open(&bytes).unwrap();
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let ctx = PacketCtx::default();
    let filter =
        Filter::parse("tcp.port == 443 || dns.qry.name contains \"a\" || tls.handshake.type == 1")
            .unwrap();
    // One frame of each protocol is enough to reach every dissector.
    for n in [
        1u32, 3, 10, 11, 107, 110, 112, 288, 479, 866, 875, 948, 1448, 1449, 1855, 1864, 1865,
    ] {
        let frame = s.frame(n).unwrap();
        let hex = frame["bytes"].as_str().unwrap();
        let data: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        for cut in 0..data.len() {
            let p = RawPacket {
                ts: 0.0,
                orig_len: data.len() as u32,
                linktype: 1,
                data: data[..cut].to_vec(),
            };
            let d = dissect(&p, &ctx);
            filter.matches(&d.tree);
        }
        for _ in 0..300 {
            let mut v = data.clone();
            for _ in 0..1 + rnd() % 6 {
                let i = (rnd() as usize) % v.len();
                v[i] = rnd() as u8;
            }
            for lt in [1u16, 101, 113, 0] {
                let p = RawPacket {
                    ts: 0.0,
                    orig_len: v.len() as u32,
                    linktype: lt,
                    data: v.clone(),
                };
                let d = dissect(&p, &ctx);
                filter.matches(&d.tree);
            }
        }
    }
}

#[test]
fn corrupted_files_are_rejected_or_partially_read() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sample.pcapng"
    ))
    .unwrap();
    for cut in [0, 3, 12, 28, 100, 5000, bytes.len() / 2, bytes.len() - 1] {
        let _ = Session::open(&bytes[..cut]);
    }
    let mut v = bytes[..20000].to_vec();
    for i in (40..v.len()).step_by(97) {
        v[i] ^= 0x5A;
    }
    let _ = Session::open(&v);
}
