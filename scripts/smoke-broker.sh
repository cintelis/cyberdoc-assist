#!/usr/bin/env bash
# Boots the broker and checks it actually serves: its signing key, a 9-digit
# session code, the viewer page, and an audit log whose hash chain verifies.
# Run after the build to confirm the deployed server comes up end to end.
#
# Assumes `cargo build -p assist-broker` has run; override BROKER_BIN otherwise.
# Uses only curl + grep, so it runs anywhere the broker does.
set -euo pipefail

PORT="${PORT:-8799}"
BASE="http://127.0.0.1:${PORT}"
BIN="${BROKER_BIN:-$(pwd)/target/debug/assist-broker}"
[ -x "$BIN" ] || BIN="${BIN}.exe" # Windows
work="$(mktemp -d)"

cleanup() {
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true # let the OS release the seed/audit files
  fi
  rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

# Run in a throwaway dir: the broker writes broker-key.seed and audit.jsonl there.
( cd "$work" && exec "$BIN" --listen "127.0.0.1:${PORT}" ) &
pid=$!

ready=
for _ in $(seq 40); do
  if curl -fsS "$BASE/api/key" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { echo "FAIL: broker did not start"; exit 1; }

curl -fsS "$BASE/api/key" | grep -q '"alg":"ML-DSA-65"' \
  || { echo "FAIL: signing key not served as ML-DSA-65"; exit 1; }

code=$(curl -fsS -X POST "$BASE/api/sessions" | grep -oE '"code":"[0-9]+"' | grep -oE '[0-9]+')
echo "$code" | grep -Eq '^[0-9]{9}$' || { echo "FAIL: bad session code: '$code'"; exit 1; }

curl -fsS "$BASE/" | grep -q "CyberDoc" || { echo "FAIL: viewer page not served"; exit 1; }

curl -fsS "$BASE/api/audit" | grep -q '"verified":true' \
  || { echo "FAIL: audit chain did not verify"; exit 1; }

echo "OK: key=ML-DSA-65, issued code=$code, viewer served, audit chain verified"
