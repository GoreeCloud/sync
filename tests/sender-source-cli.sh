#!/usr/bin/env bash
# Verify sender rejects source symlinks without using a LAN-facing listener.
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
mkdir -m 700 "$tmp/inbox" "$tmp/source" "$tmp/hidden"
printf 'safe transfer\n' > "$tmp/source/legitimate.txt"
printf 'sensitive content must not transfer\n' > "$tmp/hidden/sensitive.txt"
chmod 600 "$tmp/source/legitimate.txt" "$tmp/hidden/sensitive.txt"
ln -s "$tmp/hidden/sensitive.txt" "$tmp/source/linked.txt"
ln -s "$tmp/hidden" "$tmp/source/linked-parent"
umask 077
"$tmp/gc-sync" -receive-dir "$tmp/inbox" -receive-listen 127.0.0.1:0 > "$tmp/announcement.jsonl" 2> "$tmp/receive.err" &
receiver_pid=$!
for ((i=0;i<100;i++)); do
  [[ -s "$tmp/announcement.jsonl" ]] && break
  if ! kill -0 "$receiver_pid" 2>/dev/null; then
    echo 'receiver exited prematurely' >&2; exit 1
  fi
  sleep 0.05
done
[[ -s "$tmp/announcement.jsonl" ]] || { echo 'receiver did not announce' >&2; exit 1; }
readarray -t info < <(python3 - "$tmp/announcement.jsonl" <<'PY'
import json,sys
with open(sys.argv[1]) as f: v=json.loads(f.readline())
print(v['listen']); print(v['pairingKey'])
PY
)
url="${info[0]}"; key="${info[1]}"
for bad in "$tmp/source/linked.txt" "$tmp/source/linked-parent/sensitive.txt" "$tmp/source"; do
  if printf '%s\n' "$key" | "$tmp/gc-sync" -send-url "$url" -send-file "$bad" > "$tmp/forbidden.json" 2> "$tmp/forbidden.err"; then
    echo "sender accepted invalid source $bad" >&2; exit 1
  fi
done
[[ -z "$(find "$tmp/inbox" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo 'sender uploaded invalid source' >&2; exit 1; }
kill -0 "$receiver_pid" 2>/dev/null || { echo 'receiver exited after rejected source' >&2; exit 1; }
printf '%s\n' "$key" | "$tmp/gc-sync" -send-url "$url" -send-file "$tmp/source/legitimate.txt" > "$tmp/receipt.json"
for ((i=0;i<100;i++)); do
  if ! kill -0 "$receiver_pid" 2>/dev/null; then break; fi
  sleep 0.05
done
wait "$receiver_pid"
receiver_pid=""
cmp "$tmp/source/legitimate.txt" "$tmp/inbox/legitimate.txt"
python3 - "$tmp/receipt.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1])); assert v['status']=='received' and v['filename']=='legitimate.txt'
PY
[[ ! -e "$tmp/inbox/linked.txt" && ! -e "$tmp/inbox/sensitive.txt" ]]
printf 'PASS: sender rejects symbolic link sources and nonfiles before upload; ordinary encrypted transfer still succeeds\n'
