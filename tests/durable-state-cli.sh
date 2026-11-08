#!/usr/bin/env bash
# Durable startup, restart deletion safety, and private-state CLI acceptance.
set -euo pipefail
work=$(mktemp -d)
pid=''
cleanup() { if [[ -n "$pid" ]]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$work"; }
trap cleanup EXIT
left="$work/left";right="$work/right";mkdir -p "$left" "$right" "$work/state-dir"
printf 'agreed\n' >"$left/common.txt";cp "$left/common.txt" "$right/common.txt"
go build -o "$work/gcsync" ./cmd/sync
state="$work/state-dir/checkpoint.json"
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -init-sync-state >"$work/init.json"
[[ $(stat -c %a "$state") == 600 ]]
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -init-sync-state >/dev/null 2>&1;then echo 'FAIL: overwrote a checkpoint' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$right" -plan-target "$left" -sync-state "$state" -inspect-sync-state >/dev/null 2>&1;then echo 'FAIL: accepted swapped folders' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -inspect-sync-state -exclude '*.tmp' >/dev/null 2>&1;then echo 'FAIL: accepted changed exclusions' >&2;exit 1;fi
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -inspect-sync-state >"$work/status.json"
node - "$work/status.json" <<'JS'
const s=require(process.argv[2]); if(s.mode!=='sync-state-inspection'||s.phase!=='ready'||s.files!==1||s.generation!==1||!s.checksum)process.exit(1);
JS
printf 'new-left\n' > "$left/left-only.txt"
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -sync-additions -sync-interval 1s >"$work/events" 2>"$work/stderr" &
pid=$!
for _ in {1..100};do grep -q '"type":"snapshot"' "$work/events" 2>/dev/null && break; kill -0 "$pid" 2>/dev/null || { cat "$work/stderr";exit 1; };sleep 0.1;done
grep -q '"type":"snapshot"' "$work/events"
[[ $(cat "$right/left-only.txt") == 'new-left' ]]
kill -TERM "$pid";wait "$pid";pid=''
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -audit-sync-state >"$work/good-audit.json"
node - "$work/good-audit.json" <<'JS'
const s=require(process.argv[2]); if(s.mode!=='durable-sync-state-audit'||s.safeToRun!==true||s.issuesCount!==0)process.exit(1);
JS
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -inspect-sync-state >"$work/status2.json"
node - "$work/status2.json" <<'JS'
const s=require(process.argv[2]); if(s.phase!=='ready'||s.files!==2||s.generation!==3)process.exit(1);
JS
# A deletion BETWEEN processes must not become an addition on restart.
rm "$right/left-only.txt"
printf 'unrelated\n' > "$left/unrelated.txt"
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -sync-additions -sync-interval 1s >"$work/restart-events" 2>"$work/restart-errors";then echo 'FAIL: resurrection of deleted shared file' >&2;exit 1;fi
grep -q 'manual deletion/change review' "$work/restart-errors"
test ! -e "$right/left-only.txt"
test ! -e "$right/unrelated.txt"
"$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -audit-sync-state >"$work/bad-audit.json"
node - "$work/bad-audit.json" <<'JS'
const s=require(process.argv[2]); if(s.safeToRun!==false||s.issuesCount!==1||s.issues[0].reason!=='previously-shared-missing-target'||s.newSourceOnly!==1)process.exit(1);
JS
# A duplicate process must not run without an explicit state.
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-additions >/dev/null 2>&1;then echo 'FAIL: accepted unsafe stateless restart' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" >/dev/null 2>&1;then echo 'FAIL: accepted an unused state flag' >&2;exit 1;fi
# Report corruption without modifying either directory.
printf '{}' >> "$state"
if "$work/gcsync" -plan-source "$left" -plan-target "$right" -sync-state "$state" -inspect-sync-state >/dev/null 2>&1;then echo 'FAIL: accepted tampered checkpoint' >&2;exit 1;fi
echo 'PASS: private durable state init, restart/deletion refusal, identity bindings and corruption rejection'
