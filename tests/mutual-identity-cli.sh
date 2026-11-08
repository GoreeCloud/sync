#!/usr/bin/env bash
# Strict mutual device identity acceptance. Uses loopback and synthetic data.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)";chmod 700 "$tmp"
receiver_pid=""
cleanup(){ if [[ -n "$receiver_pid" ]]; then kill "$receiver_pid" 2>/dev/null || true;wait "$receiver_pid" 2>/dev/null || true;fi;rm -rf -- "$tmp"; }
trap cleanup EXIT
cd "$root"
go build -o "$tmp/gc-sync" ./cmd/sync
for name in sender receiver intruder; do
  "$tmp/gc-sync" -device-dir "$tmp/$name-id" -device-action init > "$tmp/$name-public.json"
done
readarray -t ids < <(python3 - "$tmp" <<'PY'
import json,sys,pathlib
p=pathlib.Path(sys.argv[1]); data=[json.load(open(p/f'{name}-public.json')) for name in ('sender','receiver','intruder')]
for value in data:print(value['publicKey']);print(value['fingerprint'])
PY
)
sender_pub="${ids[0]}"; sender_fp="${ids[1]}"
receiver_pub="${ids[2]}";receiver_fp="${ids[3]}"
intruder_pub="${ids[4]}";intruder_fp="${ids[5]}"
"$tmp/gc-sync" -device-dir "$tmp/sender-id" -device-action trust -trust-public "$receiver_pub" -peer-fingerprint "$receiver_fp" >/dev/null
"$tmp/gc-sync" -device-dir "$tmp/receiver-id" -device-action trust -trust-public "$sender_pub" -peer-fingerprint "$sender_fp" >/dev/null
"$tmp/gc-sync" -device-dir "$tmp/intruder-id" -device-action trust -trust-public "$receiver_pub" -peer-fingerprint "$receiver_fp" >/dev/null
mkdir -m 700 "$tmp/received" "$tmp/senddir"
printf 'mutual identity verified\n' > "$tmp/senddir/approved.txt"
chmod 600 "$tmp/senddir/approved.txt"
umask 077
"$tmp/gc-sync" -receive-dir "$tmp/received" -receive-listen '127.0.0.1:0' \
 -device-dir "$tmp/receiver-id" -require-sender-fingerprint "$sender_fp" > "$tmp/announce.jsonl" 2> "$tmp/receiver.log" &
receiver_pid="$!"
for ((i=0;i<120;i++));do
  [[ -s "$tmp/announce.jsonl" ]] && break
  if ! kill -0 "$receiver_pid" 2>/dev/null;then echo 'Mutual receiver exited' >&2;exit 1;fi
  sleep 0.05
done
[[ -s "$tmp/announce.jsonl" ]] || { echo 'Receiver did not announce' >&2;exit 1; }
readarray -t session < <(python3 - "$tmp/announce.jsonl" "$receiver_fp" <<'PY'
import json,sys
x=json.loads(open(sys.argv[1]).readline());assert x['requireSender'] is True and x['deviceFingerprint']==sys.argv[2]
print(x['listen']);print(x['pairingKey'])
PY
)
endpoint="${session[0]}"; key="${session[1]}"
# Sender pin alone without explicit -mutual-auth must fail closed.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/senddir/approved.txt" -send-url "$endpoint" \
 -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" >/dev/null 2>&1;then
 echo 'Receiver requested mutual but one-way sender was accepted' >&2;exit 1
fi
# A sender knowing the one-time pairing secret but lacking identity proof fails.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/senddir/approved.txt" -send-url "$endpoint" >/dev/null 2>&1;then
 echo 'Unverified sender was accepted by mutual receiver' >&2;exit 1
fi
# Impersonator has its own valid Ed25519 identity and correct receiver pin and
# one-time key, but receiver never trusted its public key.
if printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/senddir/approved.txt" -send-url "$endpoint" \
 -device-dir "$tmp/intruder-id" -peer-fingerprint "$receiver_fp" -mutual-auth >/dev/null 2>&1;then
 echo 'Impersonating sender was accepted by mutual receiver' >&2;exit 1
fi
[[ ! -e "$tmp/received/approved.txt" ]]
# Both peers verified each other and the signed proof binds the exact upload.
printf '%s\n' "$key" | "$tmp/gc-sync" -send-file "$tmp/senddir/approved.txt" -send-url "$endpoint" \
 -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" -mutual-auth > "$tmp/receipt.json"
for ((i=0;i<120;i++));do
 if ! kill -0 "$receiver_pid" 2>/dev/null;then break;fi
 sleep 0.05
done
if kill -0 "$receiver_pid" 2>/dev/null;then echo 'Receiver did not stop after success' >&2;exit 1;fi
wait "$receiver_pid";receiver_pid=""
cmp "$tmp/senddir/approved.txt" "$tmp/received/approved.txt"
python3 - "$tmp/receipt.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['status']=='received' and x['filename']=='approved.txt'
PY
# Sender explicit mutual mode must not downgrade to a receiver that does not
# demand sender identity, even when the receiver itself has a trusted key.
mkdir -m 700 "$tmp/unused"
"$tmp/gc-sync" -receive-dir "$tmp/unused" -receive-listen '127.0.0.1:0' -device-dir "$tmp/receiver-id" > "$tmp/unmutual.jsonl" 2> "$tmp/unmutual.log" &
receiver_pid="$!"
for ((i=0;i<120;i++));do [[ -s "$tmp/unmutual.jsonl" ]] && break;sleep 0.05;done
[[ -s "$tmp/unmutual.jsonl" ]] || { echo 'Unmutual receiver did not announce' >&2;exit 1; }
readarray -t session < <(python3 - "$tmp/unmutual.jsonl" <<'PY'
import json,sys
x=json.loads(open(sys.argv[1]).readline());assert not x.get('requireSender',False)
print(x['listen']);print(x['pairingKey'])
PY
)
if printf '%s\n' "${session[1]}" | "$tmp/gc-sync" -send-file "$tmp/senddir/approved.txt" -send-url "${session[0]}" \
 -device-dir "$tmp/sender-id" -peer-fingerprint "$receiver_fp" -mutual-auth >/dev/null 2>&1;then
 echo 'Mutual sender silently downgraded to receiver-only identity' >&2;exit 1
fi
[[ ! -e "$tmp/unused/approved.txt" ]]
printf 'PASS: mutual identity proof, exact encrypted transfer binding, intruder refusal, both downgrade directions\n'
