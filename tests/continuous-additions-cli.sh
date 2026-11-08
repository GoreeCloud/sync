#!/usr/bin/env bash
# Foreground opt-in local additions-only synchronization acceptance.
set -euo pipefail
root=$(mktemp -d)
pid=''
cleanup(){ if [[ -n "$pid" ]]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$root"; }
trap cleanup EXIT
left="$root/left";right="$root/right";mkdir -p "$left" "$right"
go build -o "$root/sync" ./cmd/sync
state="$root/state.json"
"$root/sync" -plan-source "$left" -plan-target "$right" -exclude '*.tmp' -sync-state "$state" -init-sync-state >"$root/state-init.json"
node - "$root/state-init.json" <<'JS'
const s=require(process.argv[2]); if(s.mode!=='sync-state-initialized'||s.phase!=='ready'||s.files!==0)process.exit(1);
JS
printf 'left\n' > "$left/left.txt"
printf 'right\n' > "$right/right.txt"
printf 'ignore\n' > "$left/ignored.tmp"
"$root/sync" -plan-source "$left" -plan-target "$right" -exclude '*.tmp' -sync-state "$state" -sync-additions -sync-interval 1s >"$root/events.ndjson" 2>"$root/errors.log" &
pid=$!
for _ in {1..100};do grep -q '"type":"snapshot"' "$root/events.ndjson" 2>/dev/null && break; kill -0 "$pid" 2>/dev/null || { cat "$root/errors.log"; exit 1; }; sleep 0.1;done
grep -q '"type":"snapshot"' "$root/events.ndjson"
test "$(cat "$left/right.txt")" = right
test "$(cat "$right/left.txt")" = left
test ! -e "$right/ignored.tmp"
printf 'new\n' > "$left/new.txt"
for _ in {1..100};do [[ -f "$right/new.txt" ]] && break; kill -0 "$pid" 2>/dev/null || { cat "$root/errors.log"; exit 1; }; sleep 0.1;done
test "$(cat "$right/new.txt")" = new
# Create a conflict, then make sure a fresh addition is NOT applied in that cycle.
printf 'L conflict\n' > "$left/left.txt"
printf 'R conflict\n' > "$right/left.txt"
printf 'blocked\n' > "$left/blocked.txt"
for _ in {1..100};do if ! kill -0 "$pid" 2>/dev/null;then break;fi; sleep 0.1;done
if kill -0 "$pid" 2>/dev/null;then echo 'FAIL: did not stop after conflict' >&2;exit 1;fi
if wait "$pid"; then echo 'FAIL: conflict exited successfully' >&2; exit 1; fi
pid=''
test ! -e "$right/blocked.txt"
node - "$root/events.ndjson" <<'JS'
const fs=require('fs');const a=fs.readFileSync(process.argv[2],'utf8').trim().split('\n').map(JSON.parse);
if(a.length!==3||a[0].type!=='snapshot'||a[1].type!=='applied'||a[2].type!=='stopped'||a[2].result.applied||!a[2].error||a[1].result.rightCreated.join()!=='new.txt') process.exit(1);
JS
if "$root/sync" -plan-source "$left" -plan-target "$right" -sync-additions -watch >/dev/null 2>&1;then echo 'FAIL: accepted watch+sync' >&2;exit 1;fi
if "$root/sync" -plan-source "$left" -plan-target "$right" -sync-additions -apply-both-additions >/dev/null 2>&1;then echo 'FAIL: accepted conflicting copy modes' >&2;exit 1;fi
if "$root/sync" -plan-source "$left" -plan-target "$right" -sync-interval 1s >/dev/null 2>&1;then echo 'FAIL: accepted interval without explicit opt-in' >&2;exit 1;fi
if "$root/sync" -plan-source "$left" -plan-target "$right" -sync-additions >/dev/null 2>&1;then echo 'FAIL: accepted sync without durable state' >&2;exit 1;fi
# A file previously shared on both sides must NOT be silently resurrected
# when one side removes it during an ongoing foreground run.
left2="$root/left2";right2="$root/right2";mkdir -p "$left2" "$right2"
printf 'shared\n' > "$left2/shared.txt"; cp "$left2/shared.txt" "$right2/shared.txt"
"$root/sync" -plan-source "$left2" -plan-target "$right2" -sync-state "$root/state2.json" -init-sync-state >/dev/null
"$root/sync" -plan-source "$left2" -plan-target "$right2" -sync-state "$root/state2.json" -sync-additions -sync-interval 1s >"$root/deletion-events.ndjson" 2>"$root/deletion-errors.log" &
pid=$!
for _ in {1..100};do grep -q '"type":"snapshot"' "$root/deletion-events.ndjson" 2>/dev/null && break; kill -0 "$pid" 2>/dev/null || { cat "$root/deletion-errors.log"; exit 1; }; sleep 0.1;done
grep -q '"type":"snapshot"' "$root/deletion-events.ndjson"
rm "$right2/shared.txt"
printf 'new\n' > "$left2/other.txt"
for _ in {1..100};do if ! kill -0 "$pid" 2>/dev/null;then break;fi;sleep 0.1;done
if kill -0 "$pid" 2>/dev/null;then echo 'FAIL: did not stop on deletion' >&2; exit 1;fi
if wait "$pid";then echo 'FAIL: deletion guard returned success' >&2;exit 1;fi
pid=''
test ! -e "$right2/shared.txt"
test ! -e "$right2/other.txt"
node - "$root/deletion-events.ndjson" <<'JS'
const fs=require('fs');const a=fs.readFileSync(process.argv[2],'utf8').trim().split('\n').map(JSON.parse);
if(a.length!==2||a[1].type!=='stopped'||!a[1].error.includes('manual deletion/change review'))process.exit(1);
JS
echo 'PASS: durable foreground additions, exclusions, conflicts, deletion stop and incompatible-mode rejection'
