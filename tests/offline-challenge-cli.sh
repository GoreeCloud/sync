#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/peer" "$work/local" "$work/peer-id" "$work/local-id" "$work/out"
export GOTOOLCHAIN=local
go build -o "$work/gcsync" ./cmd/sync
"$work/gcsync" -device-action init -device-dir "$work/peer-id" >"$work/peer.json"
"$work/gcsync" -device-action init -device-dir "$work/local-id" >"$work/local.json"
peer_fp=$(node -p 'require(process.argv[1]).fingerprint' "$work/peer.json")
peer_public=$(node -p 'require(process.argv[1]).publicKey' "$work/peer.json")
"$work/gcsync" -device-action trust -device-dir "$work/local-id" -trust-public "$peer_public" -peer-fingerprint "$peer_fp" >/dev/null
printf 'shared' > "$work/peer/shared.txt"
printf 'shared' > "$work/local/shared.txt"
"$work/gcsync" -new-inventory-challenge > "$work/challenge.json"
"$work/gcsync" -new-inventory-challenge > "$work/other.json"
challenge=$(node -p 'require(process.argv[1]).challenge' "$work/challenge.json")
other=$(node -p 'require(process.argv[1]).challenge' "$work/other.json")
[[ ${#challenge} -eq 64 && "$challenge" != "$other" ]]
if "$work/gcsync" -new-inventory-challenge -plan-source "$work/local" >/dev/null 2>&1; then echo 'FAIL: challenge generator allowed work mode' >&2; exit 1; fi
"$work/gcsync" -plan-source "$work/peer" -device-dir "$work/peer-id" -inventory-challenge "$challenge" -export-inventory "$work/out/challenged.json" >/dev/null
[[ $(stat -c %a "$work/out/challenged.json") == 600 ]]
"$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$peer_fp" -expect-inventory-challenge "$challenge" -compare-inventory "$work/out/challenged.json" >"$work/result.json"
node - "$work/result.json" <<'JS'
const fs=require('fs'), result=JSON.parse(fs.readFileSync(process.argv[2]));
if(!result.challengeVerified||!result.plan.readOnly||result.plan.identical!==1)process.exit(1);
JS
if "$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$peer_fp" -compare-inventory "$work/out/challenged.json" >/dev/null 2>&1;then echo 'FAIL: challenged inventory downgrade' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$peer_fp" -expect-inventory-challenge "$other" -compare-inventory "$work/out/challenged.json" >/dev/null 2>&1;then echo 'FAIL: mismatched challenge accepted' >&2;exit 1;fi
"$work/gcsync" -plan-source "$work/peer" -device-dir "$work/peer-id" -export-inventory "$work/out/legacy.json" >/dev/null
if "$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$peer_fp" -expect-inventory-challenge "$challenge" -compare-inventory "$work/out/legacy.json" >/dev/null 2>&1;then echo 'FAIL: unchallenged replay accepted' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$work/peer" -device-dir "$work/peer-id" -inventory-challenge INVALID -export-inventory "$work/out/invalid.json" >/dev/null 2>&1;then echo 'FAIL: invalid challenge accepted' >&2;exit 1;fi
test ! -e "$work/out/invalid.json"
test "$(cat "$work/local/shared.txt")" = shared
echo 'PASS: fresh challenge, signed export, trusted compare, replay mismatch, downgrade refusal, private no-overwrite and read-only policy'
