#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo '[1/5] Python compile + unit tests'
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v

echo '[2/5] Go engine'
if command -v go >/dev/null 2>&1; then (cd engines/go && go test ./...); else echo 'SKIP: Go is not installed'; fi

echo '[3/5] C engine'
if command -v cc >/dev/null 2>&1; then
  temp_binary="$(mktemp)"
  trap 'rm -f "$temp_binary"' EXIT
  cc -std=c11 -O2 -Wall -Wextra -Werror engines/c/system_audit.c -o "$temp_binary"
  "$temp_binary" >/dev/null
else echo 'SKIP: C compiler is not installed'; fi

echo '[4/5] Java engine'
if command -v java >/dev/null 2>&1; then
  temp_output="$(mktemp)"
  java engines/java/NoxtracePomAudit.java examples/pom-sample.xml >"$temp_output"
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["dependency_count"] == 2' "$temp_output"
  rm -f "$temp_output"
else echo 'SKIP: Java is not installed'; fi

echo '[5/5] Rust engine'
if command -v cargo >/dev/null 2>&1; then
  cargo test --manifest-path engines/rust/Cargo.toml
  cargo run --quiet --manifest-path engines/rust/Cargo.toml -- pcap examples/empty.pcap
else echo 'SKIP: Rust/Cargo is not installed in this environment'; fi

echo 'All available checks passed.'
