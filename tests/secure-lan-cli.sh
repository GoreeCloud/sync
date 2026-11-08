#!/usr/bin/env bash
# Single-use session-key-pinned TLS + manually pinned mutual device identity.
# Everything is loopback and temporary; no public/LAN listeners are opened.
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
mkdir -m 700 "$tmp/out" "$tmp/in"
printf 'TLS and mutual-identity private transfer\n' > "$tmp/in/secure.txt"
chmod 600 "$tmp/in/secure.txt"
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action init > "$tmp/sender.json"
"$tmp/gc-sync" -device-dir "$tmp/receiver-id" -device-action init > "$tmp/receiver.json"
readarray -t trust < <(python3 - "$tmp/sender.json" "$tmp/receiver.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));r=json.load(open(sys.argv[2]))
print(s['publicKey']);print(s['fingerprint']);print(r['publicKey']);print(r['fingerprint'])
PY
)
"$tmp/gc-sync" -device-dir "$tmp/receiver-id" -device-action trust -trust-public "${trust[0]}" -peer-fingerprint "${trust[1]}" > /dev/null
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action trust -trust-public "${trust[2]}" -peer-fingerprint "${trust[3]}" > /dev/null
"$tmp/gc-sync" -receive-dir "$tmp/out" -receive-listen 127.0.0.1:0 -receive-tls \
  -receive-timeout 20s -device-dir "$tmp/receiver-id" -require-sender-fingerprint "${trust[1]}" \
  > "$tmp/announce.jsonl" 2> "$tmp/receiver.log" &
receiver_pid="$!"
for ((i=0; i<120; i++)); do
  [[ -s "$tmp/announce.jsonl" ]] && break
  if ! kill -0 "$receiver_pid" 2>/dev/null; then echo 'TLS receiver exited early' >&2; exit 1; fi
  sleep 0.05
done
[[ -s "$tmp/announce.jsonl" ]] || { echo 'TLS receiver did not announce' >&2; exit 1; }
readarray -t values < <(python3 - "$tmp/announce.jsonl" "${trust[3]}" <<'PY'
import json,sys
s=json.loads(open(sys.argv[1]).readline())
assert s['listen'].startswith('https://127.0.0.1:'), s
assert s['requireSender'] and s['deviceFingerprint']==sys.argv[2]
print(s['listen']);print(s['pairingKey'])
PY
)
url="${values[0]}"; key="${values[1]}"
# Incorrect session secret must fail before the upload is accepted.
wrong="$(python3 - <<'PY'
import base64
print(base64.urlsafe_b64encode(bytes([7])*32).rstrip(b'=').decode())
PY
)"
if printf '%s\n' "$wrong" | "$tmp/gc-sync" -send-file "$tmp/in/secure.txt" -send-url "$url" \
    -device-dir "$tmp/sender-id" -peer-fingerprint "${trust[3]}" -mutual-auth > /dev/null 2>&1; then
  echo 'Unrelated TLS session key accepted' >&2; exit 1
fi
[[ ! -e "$tmp/out/secure.txt" ]]
# Omitting the explicit mutual-auth flag is a downgrade and must fail.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/in/secure.txt" -send-url "$url" \
    -device-dir "$tmp/sender-id" -peer-fingerprint "${trust[3]}" > /dev/null 2>&1; then
  echo 'Mutual authentication silently downgraded' >&2; exit 1
fi
[[ ! -e "$tmp/out/secure.txt" ]]
# Successfully authenticated one-time transfer over TLS.
printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/in/secure.txt" -send-url "$url" \
  -device-dir "$tmp/sender-id" -peer-fingerprint "${trust[3]}" -mutual-auth > "$tmp/result.json"
for ((i=0; i<120; i++)); do
  if ! kill -0 "$receiver_pid" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$receiver_pid" 2>/dev/null; then echo 'TLS receiver did not exit' >&2; exit 1; fi
wait "$receiver_pid"
receiver_pid=""
cmp "$tmp/in/secure.txt" "$tmp/out/secure.txt"
python3 - "$tmp/result.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['status']=='received' and r['filename']=='secure.txt'
PY
# Refuse insecure network URLs before connecting or transmitting any bytes.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/in/secure.txt" \
    -send-url 'http://192.168.1.2:12345/send' >/dev/null 2>&1; then
  echo 'Plain HTTP private-LAN destination accepted' >&2; exit 1
fi
if "$tmp/gc-sync" -receive-dir "$tmp/out" -allow-lan -receive-listen '0.0.0.0:0' -receive-tls >/dev/null 2>&1; then
  echo 'Wildcard listening address accepted' >&2; exit 1
fi
printf 'PASS: TLS1.3 pinned to ephemeral pairing key, mutual identity proof, no plaintext LAN downgrade\n'
