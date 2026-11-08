#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/local" "$work/peer" "$work/tickets" "$work/out" "$work/local-id" "$work/peer-id"
export GOTOOLCHAIN=local
go build -o "$work/gcsync" ./cmd/sync
"$work/gcsync" -device-action init -device-dir "$work/local-id" >"$work/local-id.json"
"$work/gcsync" -device-action init -device-dir "$work/peer-id" >"$work/peer-id.json"
fp=$(node -p 'require(process.argv[1]).fingerprint' "$work/peer-id.json")
key=$(node -p 'require(process.argv[1]).publicKey' "$work/peer-id.json")
"$work/gcsync" -device-action trust -device-dir "$work/local-id" -trust-public "$key" -peer-fingerprint "$fp" >/dev/null
printf 'matching' >"$work/local/file.txt"
printf 'matching' >"$work/peer/file.txt"
ticket="$work/tickets/request.json"
"$work/gcsync" -new-inventory-challenge -challenge-ticket "$ticket" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" >"$work/issued.json"
challenge=$(node -p 'require(process.argv[1]).challenge' "$work/issued.json")
[[ ${#challenge} -eq 64 && $(stat -c %a "$ticket") == 600 ]]
node - "$work/issued.json" <<'JS'
const result=require(process.argv[2]);if(!result.oneUseTicketIssued)process.exit(1);
JS
"$work/gcsync" -plan-source "$work/peer" -device-dir "$work/peer-id" -inventory-challenge "$challenge" -export-inventory "$work/out/response.json" >/dev/null
"$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$ticket" -compare-inventory "$work/out/response.json" >"$work/result.json"
node - "$work/result.json" <<'JS'
const v=require(process.argv[2]);if(!v.challengeVerified||!v.oneUseChallengeConsumed||!v.plan.readOnly||v.plan.identical!==1)process.exit(1);
JS
[[ $(stat -c %a "$ticket.used") == 600 ]]
if "$work/gcsync" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$ticket" -compare-inventory "$work/out/response.json" >/dev/null 2>&1;then echo 'FAIL: replay accepted' >&2;exit 1;fi
rm "$ticket"
if "$work/gcsync" -new-inventory-challenge -challenge-ticket "$ticket" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" >/dev/null 2>&1;then echo 'FAIL: reused spent ticket name' >&2;exit 1;fi
if "$work/gcsync" -plan-source "$work/peer" -device-dir "$work/peer-id" -challenge-ticket "$ticket" -export-inventory "$work/out/incorrect.json" >/dev/null 2>&1;then echo 'FAIL: ticket accepted for export' >&2;exit 1;fi
if "$work/gcsync" -challenge-ticket "$ticket" >/dev/null 2>&1;then echo 'FAIL: dangling ticket mode ignored' >&2;exit 1;fi
[[ $(cat "$work/local/file.txt") == matching ]]
echo 'PASS: private one-use challenge issue, trusted signed peer comparison, spent marker, restart/reissue refusal and CLI mode guardrails'
