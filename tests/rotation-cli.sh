#!/usr/bin/env bash
# Local, no-network device key rollover / trust staging acceptance test.
# Never rotates a real key or silently deletes an existing trust record.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
chmod 700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT
cd "$root"
go build -o "$tmp/gc-sync" ./cmd/sync
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action init > "$tmp/peer.json"
"$tmp/gc-sync" -device-dir "$tmp/old" -device-action init > "$tmp/old.json"
"$tmp/gc-sync" -device-dir "$tmp/new" -device-action init > "$tmp/new.json"
readarray -t fingerprints < <(python3 - "$tmp/old.json" "$tmp/new.json" <<'PY'
import json,sys
old=json.load(open(sys.argv[1]));new=json.load(open(sys.argv[2]));
print(old['publicKey']);print(old['fingerprint']);print(new['fingerprint'])
PY
)
old_public="${fingerprints[0]}"
old_fp="${fingerprints[1]}"
new_fp="${fingerprints[2]}"
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action trust -trust-public "$old_public" -peer-fingerprint "$old_fp" > /dev/null
"$tmp/gc-sync" -device-dir "$tmp/old" -device-action rotation-proof -rotation-dir "$tmp/new" > "$tmp/rotation.json"
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-verify -rotation-proof "$tmp/rotation.json" -peer-fingerprint "$old_fp" > "$tmp/verified.json"
python3 - "$tmp/rotation.json" "$tmp/verified.json" "$new_fp" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]));v=json.load(open(sys.argv[2]));
assert p['version']==1
assert p['new']==v and p['new']['fingerprint']==sys.argv[3]
assert len(p['oldSignature'])==86 and len(p['newSignature'])==86
assert 'seed' not in json.dumps(p).lower() and 'private' not in json.dumps(p).lower()
PY
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action list > "$tmp/before.json"
python3 - "$tmp/before.json" "$old_fp" <<'PY'
import json,sys
lst=json.load(open(sys.argv[1]));assert len(lst)==1 and lst[0]['fingerprint']==sys.argv[2]
PY
# A rotation proof alone cannot silently grant trust. A wrong new fingerprint
# must fail even when both cryptographic signatures are valid.
if "$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-trust -rotation-proof "$tmp/rotation.json" -peer-fingerprint "$old_fp" -new-fingerprint "$old_fp" >/dev/null 2>&1;then
  echo 'Unverified replacement identity was trusted' >&2;exit 1
fi
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-trust -rotation-proof "$tmp/rotation.json" -peer-fingerprint "$old_fp" -new-fingerprint "$new_fp" > "$tmp/staged.json"
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action list > "$tmp/after.json"
python3 - "$tmp/after.json" "$old_fp" "$new_fp" <<'PY'
import json,sys
lst=json.load(open(sys.argv[1]));assert set(x['fingerprint'] for x in lst)==set(sys.argv[2:])
PY
if "$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-trust -rotation-proof "$tmp/rotation.json" -peer-fingerprint "$old_fp" -new-fingerprint "$new_fp" >/dev/null 2>&1;then
  echo 'Existing replacement pin was overwritten' >&2;exit 1
fi
# Altering any part of the signed relationship invalidates the proof.
python3 - "$tmp/rotation.json" "$tmp/tampered.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]));p['new']['fingerprint']='sha256:'+'0'*64
with open(sys.argv[2],'w') as f: json.dump(p,f)
PY
if "$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-verify -rotation-proof "$tmp/tampered.json" -peer-fingerprint "$old_fp" >/dev/null 2>&1;then
  echo 'Tampered rotation proof was accepted' >&2;exit 1
fi
# A trust record is removed only when explicitly selected.
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action untrust -peer-fingerprint "$old_fp" > /dev/null
if "$tmp/gc-sync" -device-dir "$tmp/peer" -device-action rotation-verify -rotation-proof "$tmp/rotation.json" -peer-fingerprint "$old_fp" >/dev/null 2>&1;then
  echo 'Revoked old key was still accepted as predecessor' >&2;exit 1
fi
"$tmp/gc-sync" -device-dir "$tmp/peer" -device-action list > "$tmp/final.json"
python3 - "$tmp/final.json" "$new_fp" <<'PY'
import json,sys
lst=json.load(open(sys.argv[1]));assert len(lst)==1 and lst[0]['fingerprint']==sys.argv[2]
PY
printf 'PASS: signed rotation proof, pinned-old verification, independent replacement check, manual staged trust and revocation\n'
