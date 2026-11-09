//! Trame engine.
//!
//! * [`capture`] reads pcap and pcapng files.
//! * [`dissect`] turns one frame into a field tree (names follow Wireshark's
//!   display-filter fields so experts keep their habits).
//! * [`analysis`] looks across frames: TCP streams, conversations, hosts and
//!   findings written for people who are not network experts.
//! * [`filter`] parses and evaluates Wireshark-style display filters.
//! * [`session`] ties everything together behind a small API used by the CLI,
//!   the WebAssembly build and, later, the desktop app.
//!
//! Every dissector here is written from the protocol specifications (RFCs and
//! vendor documents), not from Wireshark's source code.

pub mod analysis;
pub mod capture;
pub mod dissect;
pub mod filter;
pub mod session;
pub mod tree;

pub use session::Session;
