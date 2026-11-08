#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/local" "$work/peer" "$work/local-id" "$work/peer-id" "$work/tickets" "$work/secure-local" "$work/secure-peer" "$work/exports"
export GOTOOLCHAIN=local
go build -o "$work/gcsync" ./cmd/sync
"$work/gcsync" -device-action init -device-dir "$work/local-id" > "$work/local-id.json"
"$work/gcsync" -device-action init -device-dir "$work/peer-id" > "$work/peer-id.json"
fp=$(node -p 'require(process.argv[1]).fingerprint' "$work/peer-id.json")
public=$(node -p 'require(process.argv[1]).publicKey' "$work/peer-id.json")
"$work/gcsync" -device-action trust -device-dir "$work/local-id" -trust-public "$public" -peer-fingerprint "$fp" > /dev/null
printf 'not-a-public-filename' > "$work/peer/private-family-file.txt"
printf 'not-a-public-filename' > "$work/local/private-family-file.txt"
"$work/gcsync" -new-inventory-key "$work/secure-local/exchange.key" > "$work/key-created.json"
[[ $(stat -c '%a' "$work/secure-local/exchange.key") == 600 ]]
if grep -qE '[a-f0-9]{64}' "$work/key-created.json"; then echo 'FAIL: secret leaked to stdout' >&2; exit 1; fi
# Simulate a separately authenticated confidential out-of-band transfer of the key.
cp -p "$work/secure-local/exchange.key" "$work/secure-peer/exchange.key"
if "$work/gcsync" -new-inventory-key "$work/secure-local/exchange.key" >/dev/null 2>&1; then echo 'FAIL: key overwritten' >&2; exit 1; fi
if "$work/gcsync" -new-inventory-key "$work/secure-local/invalid.key" -plan-source "$work/local" >/dev/null 2>&1; then echo 'FAIL: keygen combined with work' >&2; exit 1; fi
[[ ! -e "$work/secure-local/invalid.key" ]]
"$work/gcsync" -new-inventory-challenge -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/one.json" > "$work/challenge.json"
nonce=$(node -p 'require(process.argv[1]).challenge' "$work/challenge.json")
"$work/gcsync" -export-inventory "$work/exports/encrypted.json" -plan-source "$work/peer" -device-dir "$work/peer-id" -inventory-challenge "$nonce" -inventory-key-file "$work/secure-peer/exchange.key" > "$work/exported.json"
[[ $(stat -c '%a' "$work/exports/encrypted.json") == 600 ]]
if grep -q 'private-family-file' "$work/exports/encrypted.json"; then echo 'FAIL: plaintext filename leaked' >&2; exit 1; fi
node - "$work/exports/encrypted.json" <<'JS'
const o=require(process.argv[2]);
if(Object.keys(o).sort().join(',')!=='algorithm,ciphertext,nonce,version' || o.algorithm!=='AES-256-GCM' || o.version!==2)process.exit(1);
const encrypted=Buffer.from(o.ciphertext,'base64url'); if((encrypted.length-16)%65536!==0)process.exit(1);
JS
if "$work/gcsync" -compare-inventory "$work/exports/encrypted.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/one.json" >/dev/null 2>&1; then echo 'FAIL: encrypted envelope accepted in plaintext mode' >&2; exit 1; fi
"$work/gcsync" -compare-inventory "$work/exports/encrypted.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/one.json" -inventory-key-file "$work/secure-local/exchange.key" > "$work/result.json"
node - "$work/result.json" <<'JS'
const o=require(process.argv[2]);if(!o.challengeVerified||!o.oneUseChallengeConsumed||o.plan.identical!==1)process.exit(1);
JS
[[ -f "$work/tickets/one.json.used" ]]
if "$work/gcsync" -compare-inventory "$work/exports/encrypted.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/one.json" -inventory-key-file "$work/secure-local/exchange.key" >/dev/null 2>&1; then echo 'FAIL: replay accepted' >&2;exit 1;fi
# A wrong key must NOT consume the ticket.
"$work/gcsync" -new-inventory-challenge -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/two.json" > "$work/challenge2.json"
nonce2=$(node -p 'require(process.argv[1]).challenge' "$work/challenge2.json")
"$work/gcsync" -export-inventory "$work/exports/encrypted2.json" -plan-source "$work/peer" -device-dir "$work/peer-id" -inventory-challenge "$nonce2" -inventory-key-file "$work/secure-peer/exchange.key" >/dev/null
"$work/gcsync" -new-inventory-key "$work/secure-local/wrong.key" >/dev/null
if "$work/gcsync" -compare-inventory "$work/exports/encrypted2.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -challenge-ticket "$work/tickets/two.json" -inventory-key-file "$work/secure-local/wrong.key" >/dev/null 2>&1; then echo 'FAIL: wrong key accepted' >&2;exit 1;fi
[[ ! -e "$work/tickets/two.json.used" ]]
"$work/gcsync" -export-inventory "$work/exports/plain.json" -plan-source "$work/peer" -device-dir "$work/peer-id" >/dev/null
if "$work/gcsync" -compare-inventory "$work/exports/plain.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -inventory-key-file "$work/secure-local/exchange.key" >/dev/null 2>&1; then echo 'FAIL: plaintext downgrade accepted' >&2;exit 1;fi
python3 - "$work/exports/encrypted2.json" "$work/exports/tampered.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));x['ciphertext']='AAAA';open(sys.argv[2],'w').write(json.dumps(x))
PY
if "$work/gcsync" -compare-inventory "$work/exports/tampered.json" -plan-source "$work/local" -device-dir "$work/local-id" -peer-fingerprint "$fp" -inventory-key-file "$work/secure-local/exchange.key" >/dev/null 2>&1; then echo 'FAIL: corrupted envelope accepted' >&2;exit 1;fi
[[ $(cat "$work/local/private-family-file.txt") == not-a-public-filename ]]
echo 'PASS: confidential offline inventory AES-GCM exchange, no plaintext metadata, pinned trusted signer, one-use ticket, tamper/wrong-key/downgrade rejection'
