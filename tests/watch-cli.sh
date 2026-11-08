#!/usr/bin/env bash
# Foreground watch acceptance: read-only, change-driven NDJSON, explicit shutdown.
set -euo pipefail
root=$(mktemp -d)
watch_pid=""
cleanup(){ if [[ -n "$watch_pid" ]]; then kill -TERM "$watch_pid" 2>/dev/null || true; wait "$watch_pid" 2>/dev/null || true; fi; rm -rf "$root"; }
trap cleanup EXIT
src="$root/src"; dst="$root/dst"
mkdir -p "$src" "$dst"
printf 'common\n' > "$src/shared.txt"
cp "$src/shared.txt" "$dst/shared.txt"
printf 'excluded\n' > "$src/skip.tmp"
go build -o "$root/sync" ./cmd/sync
"$root/sync" -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -watch -watch-interval 1s >"$root/events.ndjson" 2>"$root/watch-errors.log" &
watch_pid=$!
for _ in {1..80}; do if grep -q '"type":"snapshot"' "$root/events.ndjson" 2>/dev/null; then break; fi; kill -0 "$watch_pid" 2>/dev/null || { cat "$root/watch-errors.log"; exit 1; }; sleep 0.1; done
grep -q '"type":"snapshot"' "$root/events.ndjson"
printf 'excluded edit\n' > "$src/skip.tmp"
sleep 1.2
if grep -q '"type":"changed"' "$root/events.ndjson"; then echo 'FAIL: excluded-only change triggered watch' >&2; exit 1; fi
printf 'changed\n' > "$src/shared.txt"
for _ in {1..80}; do if grep -q '"type":"changed"' "$root/events.ndjson" 2>/dev/null; then break; fi; kill -0 "$watch_pid" 2>/dev/null || { cat "$root/watch-errors.log"; exit 1; }; sleep 0.1; done
grep -q '"type":"changed"' "$root/events.ndjson"
kill -TERM "$watch_pid" 2>/dev/null || true
wait "$watch_pid" || { cat "$root/watch-errors.log"; exit 1; }
watch_pid=""
node - "$root/events.ndjson" <<'JS'
const fs=require('fs');const events=fs.readFileSync(process.argv[2],'utf8').trim().split('\n').map(JSON.parse);
if(events.length!==2 || events[0].type!=='snapshot'||events[1].type!=='changed'||events[1].sequence!==2||!events[1].readOnly||events[1].plan.different!==1||events[1].plan.changes.some(x=>x.path==='skip.tmp')) process.exit(1);
JS
test "$(cat "$dst/shared.txt")" = "common"
if "$root/sync" -plan-source "$src" -plan-target "$dst" -watch -apply-additions >/dev/null 2>"$root/bad-option.log"; then echo 'FAIL: watch accepted destructive flag' >&2; exit 1; fi
if "$root/sync" -plan-source "$src" -plan-target "$dst" -watch -watch-interval 1ms >/dev/null 2>"$root/interval-error.log"; then echo 'FAIL: watch accepted unsafe interval' >&2; exit 1; fi
test "$(cat "$dst/shared.txt")" = "common"
echo 'PASS: read-only change-driven Sync watch, exclusions, controlled shutdown, write-mode rejection'
