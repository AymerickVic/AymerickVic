//! `trame`: read a capture from the command line.
//!
//!   trame summary FILE                     findings, hosts and conversations
//!   trame list FILE [-Y FILTER] [-c N]     packet list, like `tshark -r`
//!   trame show FILE FRAME                  field tree and hex dump of one frame
//!   trame fields FILE -e FIELD... [-Y F]   one line per frame, like `tshark -T fields`
//!   trame json overview|rows|frame|conv FILE [ARG]   raw JSON used by the interface

use std::process::ExitCode;
use trame_core::tree::Field;
use trame_core::Session;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  trame summary FILE\n  trame list FILE [-Y FILTER] [-c COUNT]\n  trame show FILE FRAME\n  trame fields FILE -e FIELD [-e FIELD...] [-Y FILTER]\n  trame json overview|rows|frame|conv FILE [ARG]"
    );
    ExitCode::from(2)
}

fn open(path: &str) -> Result<Session, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path} : {e}"))?;
    Session::open(&bytes).map_err(|e| format!("{path} : {e}"))
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(path)) = (args.first(), args.get(1)) else {
        return usage();
    };
    let mut s = match open(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trame: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rest = &args[2..];
    let result = match cmd.as_str() {
        "summary" => summary(&s),
        "list" => list(&mut s, rest),
        "show" => show(&s, rest),
        "fields" => fields(&mut s, rest),
        "json" => json(&mut s, rest),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("trame: {e}");
            ExitCode::FAILURE
        }
    }
}

fn summary(s: &Session) -> Result<(), String> {
    let a = s.analysis();
    println!(
        "{} trames, {:.1} s, {} octets ({})",
        a.summary.frames, a.summary.duration, a.summary.bytes, s.format
    );
    println!("\nConstats");
    if a.findings.is_empty() {
        println!("  rien à signaler");
    }
    for f in &a.findings {
        println!(
            "  [{}] {} {}  (trame {})",
            f.severity,
            f.kind,
            f.params,
            f.frame.map(|x| x.to_string()).unwrap_or("-".into())
        );
    }
    println!("\nAppareils");
    for h in &a.hosts {
        println!(
            "  {:<16} {:<9} {:<8} {}",
            h.ip,
            h.scope,
            h.role,
            h.names.join(", ")
        );
    }
    println!("\nConversations");
    for c in &a.convs {
        let ep = |e: &trame_core::analysis::Endpoint| match e.port {
            Some(p) => format!("{}:{p}", e.ip),
            None => e.ip.clone(),
        };
        println!(
            "  {:>3} {:<6} {:<22} → {:<22} {:>6} paq. {:>10} o  {}",
            c.id,
            c.app,
            ep(&c.a),
            ep(&c.b),
            c.packets,
            c.bytes,
            c.severity
        );
    }
    Ok(())
}

fn list(s: &mut Session, rest: &[String]) -> Result<(), String> {
    let filter = opt(rest, "-Y").unwrap_or_default();
    let count = opt(rest, "-c")
        .and_then(|c| c.parse().ok())
        .unwrap_or(usize::MAX);
    let page = s.rows(&filter, 0, count).map_err(|e| e.to_string())?;
    for r in page["rows"].as_array().unwrap() {
        println!(
            "{:>6} {:>11.6} {:>15} → {:<15} {:<8} {:>5} {}",
            r["n"],
            r["t"].as_f64().unwrap(),
            r["src"].as_str().unwrap(),
            r["dst"].as_str().unwrap(),
            r["proto"].as_str().unwrap(),
            r["len"],
            r["info"].as_str().unwrap()
        );
    }
    Ok(())
}

fn print_tree(f: &Field, depth: usize) {
    if f.hidden {
        return;
    }
    let mark = match f.note {
        Some("error") => " (!)",
        Some("warn") => " (?)",
        _ => "",
    };
    println!("{}{}{}", "    ".repeat(depth), f.label, mark);
    for c in &f.children {
        print_tree(c, depth + 1);
    }
}

fn show(s: &Session, rest: &[String]) -> Result<(), String> {
    let n: u32 = rest
        .first()
        .and_then(|x| x.parse().ok())
        .ok_or("numéro de trame attendu")?;
    let d = s.dissect(n).ok_or(format!("pas de trame {n}"))?;
    for f in &d.tree {
        print_tree(f, 0);
    }
    let frame = s.frame(n).unwrap();
    let hex = frame["bytes"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    println!();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let h: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let a: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{:04x}  {:<48} {}", i * 16, h.join(" "), a);
    }
    Ok(())
}

fn fields(s: &mut Session, rest: &[String]) -> Result<(), String> {
    let names: Vec<&String> = rest
        .iter()
        .enumerate()
        .filter(|(i, _)| *i > 0 && rest[i - 1] == "-e")
        .map(|(_, v)| v)
        .collect();
    if names.is_empty() {
        return Err("au moins un -e CHAMP est attendu".into());
    }
    let filter = opt(rest, "-Y").unwrap_or_default();
    let frames = s.select(&filter).map_err(|e| e.to_string())?.to_vec();
    for n in frames {
        let d = s.dissect(n).unwrap();
        let mut all = Vec::new();
        for f in &d.tree {
            f.walk(&mut all);
        }
        let cols: Vec<String> = names
            .iter()
            .map(|name| {
                all.iter()
                    .filter(|f| f.name == name.as_str())
                    .filter_map(|f| f.value.filter_literal())
                    .map(|v| v.trim_matches('"').to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();
        println!("{}", cols.join("\t"));
    }
    Ok(())
}

fn json(s: &mut Session, rest: &[String]) -> Result<(), String> {
    let what = rest.first().map(String::as_str).unwrap_or("overview");
    let arg = rest.get(1).cloned().unwrap_or_default();
    let v = match what {
        "overview" => s.overview(),
        "rows" => s.rows(&arg, 0, 200).map_err(|e| e.to_string())?,
        "frame" => s
            .frame(arg.parse().map_err(|_| "numéro de trame attendu")?)
            .ok_or("trame inconnue")?,
        "conv" => s
            .conversation(
                arg.parse().map_err(|_| "numéro de conversation attendu")?,
                60,
            )
            .ok_or("conversation inconnue")?,
        _ => return Err(format!("vue inconnue : {what}")),
    };
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
    Ok(())
}
