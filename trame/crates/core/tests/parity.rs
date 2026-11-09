//! Trame must read the sample capture exactly like Wireshark does.
//! Reference files come from `fixtures/make_expected.sh` (tshark).

use std::path::PathBuf;
use trame_core::Session;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn session() -> Session {
    let bytes = std::fs::read(fixtures().join("sample.pcapng")).expect("fixture");
    Session::open(&bytes).expect("capture opens")
}

/// tshark prints some integers in hex (0x0012); compare numbers as numbers.
fn norm(v: &str) -> String {
    v.split(',')
        .map(|x| match x.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16)
                .map(|n| n.to_string())
                .unwrap_or_else(|_| x.to_string()),
            None => x.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn values(s: &Session, n: u32, name: &str) -> String {
    let d = s.dissect(n).unwrap();
    let mut all = Vec::new();
    for f in &d.tree {
        f.walk(&mut all);
    }
    let v: Vec<String> = all
        .iter()
        .filter(|f| f.name == name)
        .filter_map(|f| f.value.filter_literal())
        .map(|v| v.trim_matches('"').to_string())
        .collect();
    norm(&v.join(","))
}

#[test]
fn fields_match_tshark() {
    let s = session();
    let names: Vec<String> = std::fs::read_to_string(fixtures().join("expected/fields.list"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(String::from)
        .collect();
    let expected = std::fs::read_to_string(fixtures().join("expected/fields.tsv")).unwrap();
    let mut errors = Vec::new();
    let mut rows = 0;
    for (i, line) in expected.lines().enumerate() {
        rows += 1;
        let cols: Vec<&str> = line.split('\t').collect();
        for (k, name) in names.iter().enumerate() {
            let want = norm(cols.get(k).copied().unwrap_or(""));
            let got = values(&s, i as u32 + 1, name);
            if want != got && errors.len() < 20 {
                errors.push(format!(
                    "frame {} {name}: tshark={want:?} trame={got:?}",
                    i + 1
                ));
            }
        }
    }
    assert_eq!(rows, s.len(), "frame count");
    assert!(
        errors.is_empty(),
        "{} differences:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn protocol_column_matches_tshark() {
    let mut s = session();
    let expected = std::fs::read_to_string(fixtures().join("expected/protocols.txt")).unwrap();
    let rows = s.rows("", 0, usize::MAX).unwrap();
    let rows = rows["rows"].as_array().unwrap();
    let diffs: Vec<String> = expected
        .lines()
        .zip(rows)
        .filter(|(want, r)| r["proto"].as_str().unwrap() != *want)
        .map(|(want, r)| format!("frame {}: tshark={want} trame={}", r["n"], r["proto"]))
        .take(20)
        .collect();
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

#[test]
fn display_filters_match_tshark() {
    let mut s = session();
    let expected = std::fs::read_to_string(fixtures().join("expected/filters.tsv")).unwrap();
    let mut errors = Vec::new();
    for line in expected.lines() {
        let (frames, filter) = line.split_once('\t').unwrap();
        let want: Vec<u32> = frames
            .split(',')
            .filter(|x| !x.is_empty())
            .map(|x| x.parse().unwrap())
            .collect();
        match s.select(filter) {
            Ok(got) if got == want.as_slice() => {}
            Ok(got) => errors.push(format!(
                "{filter}: tshark {} frames, trame {}",
                want.len(),
                got.len()
            )),
            Err(e) => errors.push(format!("{filter}: {e}")),
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn findings_cover_the_scenario() {
    let s = session();
    let kinds: Vec<&str> = s.analysis().findings.iter().map(|f| f.kind).collect();
    for k in [
        "tcp_refused",
        "http_basic_auth",
        "dns_slow",
        "tcp_loss",
        "tls_old",
        "dns_nxdomain",
    ] {
        assert!(kinds.contains(&k), "missing finding {k}: {kinds:?}");
    }
    let hosts = &s.analysis().hosts;
    let role = |ip: &str| {
        hosts
            .iter()
            .find(|h| h.ip == ip)
            .map(|h| h.role)
            .unwrap_or("")
    };
    assert_eq!(role("192.168.1.24"), "self");
    assert_eq!(role("192.168.1.1"), "gateway");
    let printer = hosts.iter().find(|h| h.ip == "192.168.1.52").unwrap();
    assert!(printer.names.iter().any(|n| n == "Imprimante-Bureau"));
}
