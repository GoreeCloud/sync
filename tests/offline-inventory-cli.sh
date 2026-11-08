#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/left" "$work/right" "$work/left-id" "$work/right-id" "$work/out"
export GOTOOLCHAIN=local
go build -o "$work/gcsync" ./cmd/sync
"$work/gcsync" -device-action init -device-dir "$work/right-id" >"$work/peer.json"
"$work/gcsync" -device-action init -device-dir "$work/left-id" >"$work/local.json"
peer_fp=$(node -p 'require(process.argv[1]).fingerprint' "$work/peer.json")
peer_public=$(node -p 'require(process.argv[1]).publicKey' "$work/peer.json")
printf 'shared\n' >"$work/left/shared.txt"
printf 'shared\n' >"$work/right/shared.txt"
printf 'local\n' >"$work/left/local.txt"
printf 'peer\n' >"$work/right/peer.txt"
printf 'alpha\n' >"$work/left/different.txt"
printf 'omega\n' >"$work/right/different.txt"
printf 'secret stuff\n' >"$work/right/ignored.tmp"
"$work/gcsync" -device-action trust -device-dir "$work/left-id" -trust-public "$peer_public" -peer-fingerprint "$peer_fp" >/dev/null
"$work/gcsync" -plan-source "$work/right" -device-dir "$work/right-id" -exclude '*.tmp' -export-inventory "$work/out/remote.json" >"$work/export.json"
[[ "$(stat -c %a "$work/out/remote.json")" == 600 ]]
"$work/gcsync" -plan-source "$work/left" -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" -exclude '*.tmp' -compare-inventory "$work/out/remote.json" >"$work/compare.json"
node - "$work/compare.json" "$peer_fp" <<'JS'
const fs=require('fs');
const result=JSON.parse(fs.readFileSync(process.argv[2]));
if(result.mode!=='signed-offline-inventory'||result.trustedPeer!==process.argv[3]||!result.plan.readOnly||result.plan.identical!==1||result.plan.sourceOnly!==1||result.plan.targetOnly!==1||result.plan.different!==1)process.exit(1);
JS
if "$work/gcsync" -plan-source "$work/left" -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" -compare-inventory "$work/out/remote.json" >/dev/null 2>&1;then echo 'FAIL: ignores mismatched exclusions' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$work/right" -device-dir "$work/right-id" -export-inventory "$work/right/inside.json" >/dev/null 2>&1;then echo 'FAIL: signed export inside scanned root' >&2;exit 1;fi
test ! -e "$work/right/inside.json"
if "$work/gcsync" -plan-source "$work/left" -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" -compare-inventory "$work/out/remote.json" -apply-additions -plan-target "$work/right" >/dev/null 2>&1;then echo 'FAIL: signed inventory triggered writes' >&2;exit 1;fi
node - "$work/out/remote.json" "$work/out/tampered.json" <<'JS'
const fs=require('fs'), source=JSON.parse(fs.readFileSync(process.argv[2]));
source.files[0].size++;
fs.writeFileSync(process.argv[3],JSON.stringify(source),{mode:0o600});
JS
if "$work/gcsync" -plan-source "$work/left" -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" -exclude '*.tmp' -compare-inventory "$work/out/tampered.json" >/dev/null 2>&1;then echo 'FAIL: signature bypass' >&2;exit 1;fi
"$work/gcsync" -device-action untrust -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" >/dev/null
if "$work/gcsync" -plan-source "$work/left" -device-dir "$work/left-id" -peer-fingerprint "$peer_fp" -exclude '*.tmp' -compare-inventory "$work/out/remote.json" >/dev/null 2>&1;then echo 'FAIL: removed trust still works' >&2;exit 1;fi
[[ $(cat "$work/right/peer.txt") == peer ]]
test ! -e "$work/left/peer.txt"
echo 'PASS: signed offline inventory, trusted peer validation, private export, excludes, tamper and no-write policy'
