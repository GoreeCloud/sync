#!/usr/bin/env python3
"""Verify every bundled source file against a complete SHA-256 manifest.

Rejects additions, omissions, duplicate/malformed entries and altered contents.
Only the manifest itself and the top-level .git metadata directory are exempt.
This is a source-integrity check, NOT a signature or a trust anchor.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

ENTRY = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")


def verify(root: pathlib.Path, manifest: pathlib.Path) -> list[str]:
    root = root.absolute()
    manifest = manifest.absolute()
    errors: list[str] = []
    if manifest.parent != root or manifest.name != "SOURCE_SHA256SUMS.txt":
        return ["manifest must be SOURCE_SHA256SUMS.txt in the source root"]
    if manifest.is_symlink() or not manifest.is_file():
        return ["manifest missing or symbolic link"]
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [f"cannot read manifest: {exc}"]
    expected: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        match = ENTRY.fullmatch(line)
        if match is None:
            errors.append(f"invalid manifest entry at line {number}")
            continue
        digest, name = match.groups()
        path = pathlib.PurePosixPath(name)
        if (name == "SOURCE_SHA256SUMS.txt" or name.startswith("./")
            or path.is_absolute() or "\\" in name
            or any(part in (".", "..", "") for part in path.parts)
            or path.as_posix() != name or path.parts[0] == ".git"):
            errors.append(f"unsafe or excluded manifest name at line {number}: {name!r}")
            continue
        if name in expected:
            errors.append(f"duplicate manifest entry at line {number}: {name!r}")
        else:
            expected[name] = digest
    actual: dict[str, pathlib.Path] = {}
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root)
        if relative.parts[0] == ".git" or relative.as_posix() == "SOURCE_SHA256SUMS.txt":
            continue
        name = relative.as_posix()
        if candidate.is_symlink():
            errors.append(f"symbolic link is not allowed in source: {name!r}")
        elif candidate.is_file():
            actual[name] = candidate
        elif not candidate.is_dir():
            errors.append(f"special file is not allowed in source: {name!r}")
    for name in sorted(set(expected) - set(actual)):
        errors.append(f"listed source missing: {name!r}")
    for name in sorted(set(actual) - set(expected)):
        errors.append(f"unlisted source file: {name!r}")
    for name in sorted(set(expected) & set(actual)):
        try:
            h = hashlib.sha256()
            with actual[name].open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != expected[name]:
                errors.append(f"checksum mismatch: {name!r}")
        except OSError as exc:
            errors.append(f"unreadable source file {name!r}: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.absolute()
    errors = verify(root, root / "SOURCE_SHA256SUMS.txt")
    if errors:
        for error in errors:
            print("FAIL:", error, file=sys.stderr)
        return 1
    print("PASS: exhaustive source manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
