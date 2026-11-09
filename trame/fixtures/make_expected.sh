#!/usr/bin/env bash
# Record Wireshark's (tshark's) view of fixtures/sample.pcapng.
# The parity test in crates/core/tests/parity.rs compares Trame against these files,
# so CI does not need Wireshark installed. Re-run after changing the fixture.
set -euo pipefail
cd "$(dirname "$0")"
FIELDS=$(grep -v '^#' expected/fields.list)
ARGS=(); for f in $FIELDS; do ARGS+=(-e "$f"); done
tshark -r sample.pcapng -T fields -E occurrence=a -E separator=/t -E aggregator=, "${ARGS[@]}" 2>/dev/null > expected/fields.tsv
tshark -r sample.pcapng -T fields -e _ws.col.Protocol 2>/dev/null > expected/protocols.txt
: > expected/filters.tsv
grep -v '^#' expected/filters.list | while IFS= read -r f; do
  printf '%s\t%s\n' "$(tshark -r sample.pcapng -Y "$f" -T fields -e frame.number 2>/dev/null | paste -sd, -)" "$f" >> expected/filters.tsv
done
echo "tshark $(tshark --version | head -1 | awk '{print $3}')" > expected/VERSION
