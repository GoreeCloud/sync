#!/usr/bin/env bash
# Regression of explicit zero-copy recovery from a complete, private pending journal.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/left" "$work/right" "$work/state"
printf 'known unchanged\n' > "$work/left/common.txt"
cp "$work/left/common.txt" "$work/right/common.txt"
state="$work/state/sync.json"
go build -o "$work/gcsync" ./cmd/sync
"$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -init-sync-state > /dev/null
printf 'new private data\n' > "$work/left/new.txt"
# Fixture simulates a crash immediately after the write-ahead journal was persisted,
# before any copy. SHA-256 matches Go's encoding/json struct field order for this
# bounded ASCII-only test fixture. This helper is NOT a user-facing recovery path.
node - "$state" "$work/left/new.txt" <<'JS'
const fs=require('node:fs');const crypto=require('node:crypto');
const [stateFile,sourceFile]=process.argv.slice(2);
const s=JSON.parse(fs.readFileSync(stateFile,'utf8'));
const payload=fs.readFileSync(sourceFile);
s.generation++;
s.phase='pending';
s.pending=[{path:'new.txt',direction:'source-to-target',size:payload.length,sha256:crypto.createHash('sha256').update(payload).digest('hex')}];
s.checksum='';
s.checksum=crypto.createHash('sha256').update(JSON.stringify(s)).digest('hex');
fs.writeFileSync(stateFile,JSON.stringify(s,null,2)+'\n',{mode:0o600});
JS
"$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -check-pending-recovery > "$work/not-yet.json"
node - "$work/not-yet.json" <<'JS'
const r=require(process.argv[2]);if(r.eligible!==false||r.phase!=='pending'||r.pendingFiles!==1||!r.reason||r.pendingReview[0].leftStatus!=='match'||r.pendingReview[0].rightStatus!=='missing'||r.pendingReview[0].complete!==false)process.exit(1);
JS
if "$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -finalize-completed-batch > /dev/null 2>"$work/expected-failure"; then
  echo 'FAIL: accepted incomplete batch' >&2;exit 1
fi
test ! -e "$work/right/new.txt"
test ! -e "$state.recovery-g2.json"
# The user has ALREADY restored matching bytes; recovery must perform no copy.
cp "$work/left/new.txt" "$work/right/new.txt"
left_before=$(sha256sum "$work/left/new.txt" | awk '{print $1}')
right_before=$(sha256sum "$work/right/new.txt" | awk '{print $1}')
"$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -check-pending-recovery > "$work/eligible.json"
node - "$work/eligible.json" <<'JS'
const r=require(process.argv[2]);if(r.eligible!==true||r.pendingFiles!==1||r.pendingReview[0].leftStatus!=='match'||r.pendingReview[0].rightStatus!=='match'||r.pendingReview[0].complete!==true||r.unplannedFiles!==0)process.exit(1);
JS
"$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -finalize-completed-batch > "$work/done.json"
node - "$work/done.json" "$state" <<'JS'
const fs=require('node:fs');const r=require(process.argv[2]);const s=JSON.parse(fs.readFileSync(process.argv[3]));
if(r.mode!=='completed-batch-finalized'||r.filesCopied!==0||r.filesDeleted!==0||r.pendingCleared!==1||s.phase!=='ready'||s.generation!==3||s.files.length!==2)process.exit(1);
if(r.backupPath!==process.argv[3]+'.recovery-g2.json')process.exit(1);
const backup=JSON.parse(fs.readFileSync(r.backupPath));if(backup.phase!=='pending'||backup.generation!==2)process.exit(1);
JS
test "$(stat -c '%a' "$state.recovery-g2.json")" = 600
test "$(sha256sum "$work/left/new.txt" | awk '{print $1}')" = "$left_before"
test "$(sha256sum "$work/right/new.txt" | awk '{print $1}')" = "$right_before"
if "$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -finalize-completed-batch >/dev/null 2>&1; then
  echo 'FAIL: finalized a ready journal' >&2;exit 1
fi
rm "$work/right/new.txt"
if "$work/gcsync" -plan-source "$work/left" -plan-target "$work/right" -sync-state "$state" -sync-additions -sync-interval 1s >/dev/null 2>&1; then
 echo 'FAIL: resurrected deletion after recovery' >&2;exit 1
fi
test ! -e "$work/right/new.txt"
echo 'PASS: pending batch proof, explicit zero-copy finalize, preserved archive and restart deletion safety'
