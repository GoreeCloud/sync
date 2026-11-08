#!/usr/bin/env bash
# End-to-end persistent receiver identity and manually pinned trust on loopback.
# No LAN/VPS listener is started; no secret is provided on the command line.
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
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action init > "$tmp/sender-id.json"
"$tmp/gc-sync" -device-dir "$tmp/receiver-id" -device-action init > "$tmp/receiver-id.json"
"$tmp/gc-sync" -device-dir "$tmp/attacker-id" -device-action init > "$tmp/attacker-id.json"
"$tmp/gc-sync" -device-dir "$tmp/receiver-id" -device-action show > "$tmp/show.json"
cmp "$tmp/receiver-id.json" "$tmp/show.json"
[[ "$(stat -c %a "$tmp/receiver-id/identity.json")" == '600' ]]
[[ "$(stat -c %a "$tmp/receiver-id")" == '700' ]]
python3 - "$tmp/receiver-id.json" "$tmp/sender-id.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));s=json.load(open(sys.argv[2]));
assert r['fingerprint'].startswith('sha256:') and len(r['fingerprint'])==71
assert r['algorithm']=='Ed25519' and len(r['publicKey'])==43
assert not any('seed' in k.lower() or 'private' in k.lower() for k in r)
assert r['fingerprint']!=s['fingerprint']
PY
readarray -t trust < <(python3 - "$tmp/receiver-id.json" "$tmp/sender-id.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); s=json.load(open(sys.argv[2]));
print(r['publicKey']);print(r['fingerprint']);print(s['fingerprint'])
PY
)
public="${trust[0]}"
receiver_fp="${trust[1]}"
sender_fp="${trust[2]}"
# A fingerprint taken from the wrong device must never be silently trusted.
if "$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action trust -trust-public "$public" -peer-fingerprint "$sender_fp" > /dev/null 2>&1; then
  echo 'Mismatched receiver fingerprint was trusted' >&2
  exit 1
fi
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action trust -trust-public "$public" -peer-fingerprint "$receiver_fp" > "$tmp/trust.json"
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action list > "$tmp/trust-list.json"
python3 - "$tmp/trust.json" "$tmp/trust-list.json" "$receiver_fp" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); lst=json.load(open(sys.argv[2]));
assert len(lst)==1 and r==lst[0] and r['fingerprint']==sys.argv[3]
PY
if "$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action trust -trust-public "$public" -peer-fingerprint "$receiver_fp" >/dev/null 2>&1; then
  echo 'Existing trust was overwritten' >&2
  exit 1
fi
mkdir -m 700 "$tmp/received" "$tmp/to-send"
printf 'sender verified receiver identity\n' > "$tmp/to-send/identity-proof.txt"
chmod 600 "$tmp/to-send/identity-proof.txt"
umask 077
"$tmp/gc-sync" -receive-dir "$tmp/received" -receive-listen '127.0.0.1:0' -device-dir "$tmp/receiver-id" > "$tmp/announcement.jsonl" 2> "$tmp/receiver.log" &
receiver_pid="$!"
for ((i=0;i<120;i++)); do
  [[ -s "$tmp/announcement.jsonl" ]] && break
  if ! kill -0 "$receiver_pid" 2>/dev/null; then echo 'Receiver failed before announcement' >&2; exit 1; fi
  sleep 0.05
done
[[ -s "$tmp/announcement.jsonl" ]] || { echo 'No receiver announcement' >&2; exit 1; }
readarray -t values < <(python3 - "$tmp/announcement.jsonl" "$receiver_fp" <<'PY'
import json,sys
x=json.loads(open(sys.argv[1]).readline())
assert x['deviceFingerprint']==sys.argv[2]
print(x['listen']);print(x['pairingKey'])
PY
)
url="${values[0]}"; key="${values[1]}"
# Trying the wrong pin must be rejected prior to writing a file.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/to-send/identity-proof.txt" -send-url "$url" -device-dir "$tmp/sender-id" -peer-fingerprint "$sender_fp" > /dev/null 2>&1; then
  echo 'Untrusted identity pin accepted' >&2
  exit 1
fi
[[ ! -e "$tmp/received/identity-proof.txt" ]]
# Successful identity verification and one-time encrypted transfer.
printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/to-send/identity-proof.txt" -send-url "$url" -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" > "$tmp/receipt.json"
for ((i=0;i<120;i++)); do
  if ! kill -0 "$receiver_pid" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$receiver_pid" 2>/dev/null; then echo 'Receiver did not shut down' >&2; exit 1; fi
wait "$receiver_pid"
receiver_pid=""
cmp "$tmp/to-send/identity-proof.txt" "$tmp/received/identity-proof.txt"
python3 - "$tmp/receipt.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['status']=='received' and r['filename']=='identity-proof.txt'
PY
# An unpaired listener can never satisfy a pinned-identity sender request.
"$tmp/gc-sync" -receive-dir "$tmp/received" -receive-listen '127.0.0.1:0' > "$tmp/second.jsonl" 2> "$tmp/second.log" &
receiver_pid="$!"
for ((i=0;i<120;i++)); do
  [[ -s "$tmp/second.jsonl" ]] && break
  sleep 0.05
done
[[ -s "$tmp/second.jsonl" ]] || { echo 'Second receiver failed' >&2; exit 1; }
readarray -t values < <(python3 - "$tmp/second.jsonl" <<'PY'
import json,sys
x=json.loads(open(sys.argv[1]).readline());print(x['listen']);print(x['pairingKey'])
PY
)
if printf '%s\n' "${values[1]}" | "$tmp/gc-sync" -send-file "$tmp/to-send/identity-proof.txt" -send-url "${values[0]}" -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" >/dev/null 2>&1; then
  echo 'Sender silently fell back to unpaired Nearby Send' >&2
  exit 1
fi
# Even with the correct one-time transfer secret, a different receiver's
# persistent identity cannot satisfy the pinned-identity requirement.
kill "$receiver_pid" 2>/dev/null || true
wait "$receiver_pid" 2>/dev/null || true
receiver_pid=""
mkdir -m 700 "$tmp/attacker-received"
"$tmp/gc-sync" -receive-dir "$tmp/attacker-received" -receive-listen '127.0.0.1:0' -device-dir "$tmp/attacker-id" > "$tmp/attacker-announce.jsonl" 2> "$tmp/attacker.log" &
receiver_pid="$!"
for ((i=0;i<120;i++)); do
  [[ -s "$tmp/attacker-announce.jsonl" ]] && break
  sleep 0.05
done
[[ -s "$tmp/attacker-announce.jsonl" ]] || { echo 'Attacker test server did not start' >&2; exit 1; }
readarray -t malicious < <(python3 - "$tmp/attacker-announce.jsonl" <<'PYCODE'
import json,sys
v=json.loads(open(sys.argv[1]).readline());print(v['listen']);print(v['pairingKey'])
PYCODE
)
if printf '%s\n' "${malicious[1]}" | "$tmp/gc-sync" -send-file "$tmp/to-send/identity-proof.txt" -send-url "${malicious[0]}" -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" >/dev/null 2>&1; then
  echo 'Impersonating device passed a pinned public-key challenge' >&2
  exit 1
fi
[[ ! -e "$tmp/attacker-received/identity-proof.txt" ]]
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action untrust -peer-fingerprint "$receiver_fp" > "$tmp/untrusted.json"
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action list > "$tmp/empty.json"
python3 - "$tmp/empty.json" "$tmp/untrusted.json" "$receiver_fp" <<'PYCODE'
import json,sys
assert json.load(open(sys.argv[1]))==[]
x=json.load(open(sys.argv[2]));assert x['status']=='untrusted' and x['fingerprint']==sys.argv[3]
PYCODE
printf 'PASS: private Ed25519 identities, explicit verified trust, pinned receiver proof, no fallback, impersonation refusal and untrust\n'
