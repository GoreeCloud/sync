#!/usr/bin/env bash
# Synthetic two-direction, additions-only manual copy acceptance.
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
src="$root/left"; dst="$root/right"
mkdir -p "$src" "$dst"
printf 'A\n' > "$src/from-left.txt"
printf 'B\n' > "$dst/from-right.txt"
printf 'shared\n' > "$src/shared.txt"; cp "$src/shared.txt" "$dst/shared.txt"
printf 'left skip\n' > "$src/skip.tmp";printf 'right skip\n' > "$dst/skip.tmp"
go build -o "$root/sync" ./cmd/sync
"$root/sync" -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -apply-both-additions > "$root/result.json"
node - "$root/result.json" <<'JS'
const r=require(process.argv[2]);if(!r.applied||r.mode!=='bidirectional-additions-only'||r.unChanged||r.conflicts!==0||r.leftCreated.join()!=='from-right.txt'||r.rightCreated.join()!=='from-left.txt'||r.bytesWritten!==4)process.exit(1)
JS
test "$(cat "$src/from-right.txt")" = 'B'
test "$(cat "$dst/from-left.txt")" = 'A'
test "$(cat "$src/skip.tmp")" = 'left skip'
test "$(cat "$dst/skip.tmp")" = 'right skip'
"$root/sync" -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -apply-both-additions > "$root/repeat.json"
node - "$root/repeat.json" <<'JS'
const r=require(process.argv[2]);if(!r.applied||r.leftCreated.length||r.rightCreated.length)process.exit(1)
JS
printf 'conflict left\n' > "$src/shared.txt"
printf 'conflict right\n' > "$dst/shared.txt"
printf 'not transferred\n' > "$src/blocked.txt"
if "$root/sync" -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -apply-both-additions >"$root/refused.json" 2>"$root/refusal.log"; then echo 'FAIL: accepted conflict' >&2; exit 1; fi
node - "$root/refused.json" <<'JS'
const r=require(process.argv[2]);if(r.applied||r.conflicts!==1||r.leftCreated.length||r.rightCreated.length)process.exit(1)
JS
test ! -e "$dst/blocked.txt"
if "$root/sync" -plan-source "$src" -plan-target "$dst" -apply-both-additions -apply-additions > /dev/null 2>"$root/mixed-error.log"; then echo 'FAIL: accepted mixed write modes' >&2; exit 1; fi
if "$root/sync" -plan-source "$src" -plan-target "$dst" -apply-both-additions -watch > /dev/null 2>"$root/watch-error.log"; then echo 'FAIL: accepted watcher with writes' >&2; exit 1; fi
echo 'PASS: symmetric additions-only copy, exclusions, idempotence, preflight conflict refusal and unsafe-mode rejection'
