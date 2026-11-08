#!/usr/bin/env bash
# End-to-end, loopback-only test. Never opens a LAN-facing port.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
chmod 700 "$tmp"
receiver_pid=""
cleanup() {
  if [[ -n "$receiver_pid" ]]; then
    kill "$receiver_pid" 2>/dev/null || true
    wait "$receiver_pid" 2>/dev/null || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
cd "$root"
go build -o "$tmp/gc-sync" ./cmd/sync
mkdir -m 700 "$tmp/received" "$tmp/senddir"
printf 'GoreeCloud Sync encrypted loopback transfer\n' > "$tmp/senddir/sample.txt"
chmod 600 "$tmp/senddir/sample.txt"
umask 077
"$tmp/gc-sync" -receive-dir "$tmp/received" -receive-listen '127.0.0.1:0' > "$tmp/announce.jsonl" 2> "$tmp/receiver.log" &
receiver_pid="$!"
for ((i=0;i<100;i++)); do
  [[ -s "$tmp/announce.jsonl" ]] && break
  if ! kill -0 "$receiver_pid" 2>/dev/null; then
    echo 'Receiver exited before printing connection instructions' >&2
    exit 1
  fi
  sleep 0.05
done
[[ -s "$tmp/announce.jsonl" ]] || { echo 'Receiver did not announce after timeout' >&2; exit 1; }
readarray -t values < <(python3 - "$tmp/announce.jsonl" <<'PY'
import json,sys
with open(sys.argv[1]) as fh:
    d=json.loads(fh.readline())
print(d['listen'])
print(d['pairingKey'])
PY
)
url="${values[0]}"
key="${values[1]}"
printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/senddir/sample.txt" -send-url "$url" > "$tmp/receipt.json"
for ((i=0;i<100;i++)); do
  if ! kill -0 "$receiver_pid" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$receiver_pid" 2>/dev/null; then echo 'Receiver did not exit after one transfer' >&2; exit 1; fi
wait "$receiver_pid" || { echo 'Receiver process reported error' >&2; exit 1; }
receiver_pid=""
cmp "$tmp/senddir/sample.txt" "$tmp/received/sample.txt"
python3 - "$tmp/receipt.json" "$tmp/announce.jsonl" <<'PY'
import json,sys
with open(sys.argv[1]) as f: r=json.load(f)
with open(sys.argv[2]) as f:
    f.readline()
    r2=json.loads(f.readline())
assert r==r2, (r,r2)
assert r['status']=='received' and r['filename']=='sample.txt'
assert r['bytes']==len(b'GoreeCloud Sync encrypted loopback transfer\n')
PY
if "$tmp/gc-sync" -receive-dir "$tmp/received" -receive-timeout '31m' >/dev/null 2>&1; then
  echo 'Unsafe receive timeout accepted' >&2
  exit 1
fi
if "$tmp/gc-sync" -receive-dir "$tmp/received" -receive-listen '0.0.0.0:0' >/dev/null 2>&1; then
  echo 'Non-loopback listen was accepted without -allow-lan' >&2
  exit 1
fi
printf 'PASS: one-time encrypted Nearby Send, authenticated receipt, no LAN exposure by default\n'
