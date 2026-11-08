#!/usr/bin/env bash
# Read-only receiver audit, no network listener and no automatic deletion.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
chmod 700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT
cd "$root"
go build -o "$tmp/sync" ./cmd/sync
mkdir -m 700 "$tmp/inbox"
"$tmp/sync" -audit-receive-dir "$tmp/inbox" > "$tmp/clean.json"
python3 - "$tmp/clean.json" <<'PY1'
import json,sys
v=json.load(open(sys.argv[1])); assert v['status']=='clear' and v['stageResidueCount']==0
PY1
printf 'do not auto-delete' > "$tmp/inbox/.gcsend-stage-crash"
chmod 600 "$tmp/inbox/.gcsend-stage-crash"
set +e
"$tmp/sync" -audit-receive-dir "$tmp/inbox" > "$tmp/residue.json" 2> "$tmp/audit.err"
status=$?
set -e
[[ "$status" -eq 2 ]] || { echo "expected manual-review exit 2, got $status" >&2; exit 1; }
python3 - "$tmp/residue.json" <<'PY2'
import json,sys
v=json.load(open(sys.argv[1])); assert v['status']=='manual-review-required' and v['stageResidueCount']==1 and v['stageResidues']==['.gcsend-stage-crash']
PY2
if "$tmp/sync" -receive-dir "$tmp/inbox" -receive-listen 127.0.0.1:0 > "$tmp/announce.json" 2> "$tmp/receiver.err"; then
  echo 'receiver accepted crash residue' >&2; exit 1
fi
[[ ! -s "$tmp/announce.json" ]] || { echo 'receiver announced with unsafe residue' >&2; exit 1; }
[[ "$(cat "$tmp/inbox/.gcsend-stage-crash")" == 'do not auto-delete' ]] || exit 1
if "$tmp/sync" -audit-receive-dir "$tmp/inbox" -receive-dir "$tmp/inbox" >/dev/null 2>&1; then
  echo 'combined receiver and audit modes were accepted' >&2; exit 1
fi
# Simulate an explicit owner-reviewed quarantine to a separate private folder.
mkdir -m 700 "$tmp/quarantine"
mv -- "$tmp/inbox/.gcsend-stage-crash" "$tmp/quarantine/staged-pending-inspection"
"$tmp/sync" -audit-receive-dir "$tmp/inbox" > "$tmp/cleared.json"
python3 - "$tmp/cleared.json" <<'PY3'
import json,sys
assert json.load(open(sys.argv[1]))['stageResidueCount']==0
PY3
[[ "$(cat "$tmp/quarantine/staged-pending-inspection")" == 'do not auto-delete' ]] || exit 1
printf 'PASS: private Nearby Send residue audit, preflight fail closed, read-only reporting, manual review
'
