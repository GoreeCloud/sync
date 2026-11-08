#!/usr/bin/env bash
# Synthetic, non-destructive three-way sync planning acceptance.
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
src="$root/source"; dst="$root/target"; baseline="$root/initial-baseline.json"
mkdir -p "$src" "$dst"
printf 'unchanged\n' > "$src/keep.txt"
cp "$src/keep.txt" "$dst/keep.txt"
printf 'before\n' > "$src/edited.txt"
cp "$src/edited.txt" "$dst/edited.txt"
printf 'remove me\n' > "$src/deleted.txt"
cp "$src/deleted.txt" "$dst/deleted.txt"
printf 'ignore-a\n' > "$src/skip.tmp"
printf 'ignore-b\n' > "$dst/skip.tmp"

# A previous common state is written once, privately, outside both roots.
go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -capture-baseline "$baseline" > "$root/capture.json"
node -e 'const x=require(process.argv[1]);if(x.mode!=="baseline-captured"||x.files!==3||x.version!==2)process.exit(1)' "$root/capture.json"
test "$(stat -c %a "$baseline")" = "600"
# Never overwrite a baseline, including on repeat capture.
if go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -capture-baseline "$baseline" >/dev/null 2>"$root/overwrite-error.log"; then echo 'FAIL: overwrote baseline' >&2; exit 1; fi

# Only one-sided changes; these should not be mislabeled as conflicts.
printf 'source edit\n' > "$src/edited.txt"
rm "$dst/deleted.txt"
printf 'new addition\n' > "$src/new.txt"
go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -baseline "$baseline" > "$root/plan.json"
node - <<'JS' "$root/plan.json"
const fs=require('fs');let p=JSON.parse(fs.readFileSync(process.argv[2]));
const map=Object.fromEntries(p.changes.map(x=>[x.path,x.status]));
if(!p.readOnly||p.conflicts!==0||p.baselineFiles!==3||map['keep.txt']!=='unchanged'||map['edited.txt']!=='source-modified'||map['deleted.txt']!=='target-deleted'||map['new.txt']!=='source-added'||map['skip.tmp'])process.exit(1);
JS
# Checkpoints bind to the exact source/target direction and local folder roots.
if go run ./cmd/sync -plan-source "$dst" -plan-target "$src" -exclude '*.tmp' -baseline "$baseline" >/dev/null 2> "$root/swapped-error.log"; then echo 'FAIL: accepted swapped baseline roots' >&2; exit 1; fi
unrelated="$root/unrelated"; mkdir -p "$unrelated"
if go run ./cmd/sync -plan-source "$src" -plan-target "$unrelated" -exclude '*.tmp' -baseline "$baseline" >/dev/null 2> "$root/unrelated-error.log"; then echo 'FAIL: accepted unrelated baseline target' >&2; exit 1; fi
# A true independent edit changes status, but no bytes are overwritten.
printf 'target also edited\n' > "$dst/edited.txt"
go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -baseline "$baseline" > "$root/conflict.json"
node -e 'const p=require(process.argv[1]);if(p.conflicts!==1||p.changes.find(x=>x.path==="edited.txt").status!=="conflict-modify-modify")process.exit(1)' "$root/conflict.json"
test "$(cat "$src/edited.txt")" = 'source edit'
test "$(cat "$dst/edited.txt")" = 'target also edited'

# Fail-closed on filters that differ from the immutable checkpoint.
if go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -baseline "$baseline" > /dev/null 2> "$root/filter-error.log"; then echo 'FAIL: accepted mismatched exclusions' >&2; exit 1; fi
# A checkpoint must not be created inside an inventoried folder.
if go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -capture-baseline "$src/inside.json" >/dev/null 2>"$root/inside-error.log"; then echo 'FAIL: accepted internal baseline' >&2; exit 1; fi
test ! -e "$src/inside.json"
test -e "$src/new.txt" && test ! -e "$dst/new.txt"
# Never permit a historical plan to perform additions in the same command.
if go run ./cmd/sync -plan-source "$src" -plan-target "$dst" -exclude '*.tmp' -baseline "$baseline" -apply-additions >/dev/null 2>"$root/mode-error.log"; then echo 'FAIL: mixed read-only and write modes' >&2; exit 1; fi
echo 'PASS: immutable baseline, unilateral edits/deletions, real conflicts, unchanged files and no writes'
