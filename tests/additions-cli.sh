#!/usr/bin/env bash
# Synthetic filesystem acceptance for an opt-in local additions-only operation.
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
src="$root/source"
dst="$root/target"
mkdir -p "$src/nested" "$dst"
printf 'new-content\n' > "$src/nested/new.txt"
printf 'match\n' > "$src/match.txt"
printf 'match\n' > "$dst/match.txt"
printf 'target-only\n' > "$dst/keep.txt"
printf 'temporary\n' > "$src/skip.tmp"
mkdir "$src/private"
printf 'sensitive\n' > "$src/private/secret.txt"

go run ./cmd/sync -plan-source "$src" -plan-target "$dst" > "$root/plan.json"
node -e 'const x=require(process.argv[1]);if(!x.readOnly||x.sourceOnly!==3||x.targetOnly!==1||x.different!==0)process.exit(1)' "$root/plan.json"
go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -exclude 'private/**' > "$root/filtered.json"
node -e 'const x=require(process.argv[1]);if(!x.readOnly||x.sourceOnly!==1||x.targetOnly!==1||x.different!==0)process.exit(1)' "$root/filtered.json"
test ! -e "$dst/nested/new.txt"

go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -exclude 'private/**' -apply-additions > "$root/result.json"
node -e 'const x=require(process.argv[1]);if(!x.applied||x.created.length!==1||x.created[0]!=="nested/new.txt")process.exit(1)' "$root/result.json"
test "$(cat "$dst/nested/new.txt")" = 'new-content'
test ! -e "$dst/skip.tmp"
test ! -e "$dst/private/secret.txt"
test "$(cat "$dst/keep.txt")" = 'target-only'

go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -exclude 'private/**' -apply-additions > "$root/repeated.json"
node -e 'const x=require(process.argv[1]);if(!x.applied||x.created.length!==0)process.exit(1)' "$root/repeated.json"

printf 'different\n' > "$src/match.txt"
if go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -exclude 'private/**' -apply-additions > "$root/conflict.json" 2> "$root/error.log"; then
  echo 'FAIL: expected conflict to refuse replication' >&2
  exit 1
fi
node -e 'const x=require(process.argv[1]);if(x.applied||x.conflicts!==1||x.created.length!==0)process.exit(1)' "$root/conflict.json"
test "$(cat "$dst/match.txt")" = 'match'
test "$(cat "$dst/keep.txt")" = 'target-only'
echo 'PASS: plan, explicit exclusions, safe additions, idempotence, conflict refusal, target preservation'
