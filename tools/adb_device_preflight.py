#!/usr/bin/env python3
"""Read-only Android ABI preflight for a user-selected, authorized ADB device.

No APK or executable is installed, transferred, started, or modified on device.
The explicit ADB serial is not included in output to minimize identifier exposure.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys

SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PROPERTIES = (
    "ro.product.model",
    "ro.build.version.sdk",
    "ro.product.cpu.abilist",
    "ro.product.cpu.abi",
)
ABI_RE = re.compile(r"[a-zA-Z0-9_.-]{1,64}\Z")


class ProbeError(Exception):
    """A device check could not be completed without assuming compatibility."""


def call_adb(adb: str, *args: str) -> str:
    try:
        result = subprocess.run(
            [adb, *args], capture_output=True, text=True, timeout=8,
            check=False, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("ADB unavailable or device query timed out") from exc
    if result.returncode != 0:
        raise ProbeError("ADB command failed; verify device authorization and connection")
    return result.stdout


def probe(adb: str, serial: str) -> dict[str, object]:
    if SERIAL_RE.fullmatch(serial) is None:
        raise ProbeError("invalid explicit ADB device selector")
    devices = call_adb(adb, "devices", "-l")
    found: list[str] = []
    for line in devices.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == serial:
            found.append(fields[1])
    if len(found) != 1 or found[0] != "device":
        raise ProbeError("selected device is not uniquely present and authorized")

    properties: dict[str, str] = {}
    for key in PROPERTIES:
        value = call_adb(adb, "-s", serial, "shell", "getprop", key).strip()
        if "\n" in value or "\r" in value or len(value) > 160:
            raise ProbeError("unexpected Android property response")
        properties[key] = value
    version = properties["ro.build.version.sdk"]
    if not version.isascii() or not version.isdecimal() or not 1 <= int(version) <= 999:
        raise ProbeError("Android SDK version missing or invalid")
    abis = [a.strip() for a in properties["ro.product.cpu.abilist"].split(",") if a.strip()]
    if not abis:
        abis = [properties["ro.product.cpu.abi"]]
    if len(abis) > 16 or any(ABI_RE.fullmatch(a) is None for a in abis):
        raise ProbeError("device ABI list missing or malformed")
    abis = list(dict.fromkeys(abis))
    arm64 = "arm64-v8a" in abis
    arm32 = "armeabi-v7a" in abis
    target = "android/arm64" if arm64 and int(version) >= 21 else None
    if target:
        limitation = "Compile-only target exists; actual runtime and installation remain unverified"
    elif arm32:
        limitation = "32-bit ARM requires Android/arm external cgo linking and platform validation; no supported build is packaged"
    else:
        limitation = "No matching tested Android CLI build target; do not deploy a different architecture"
    return {
        "check": "read-only-android-device-preflight",
        "model": properties["ro.product.model"] or "unknown",
        "androidSdk": int(version),
        "abis": abis,
        "candidateGoTarget": target,
        "runtimeVerified": False,
        "deploymentPerformed": False,
        "limitation": limitation,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="Exact pre-authorized device selector from adb devices -l")
    parser.add_argument("--adb", default=shutil.which("adb"), help="Path to trusted Android SDK adb executable")
    args = parser.parse_args(argv)
    try:
        if not args.adb:
            raise ProbeError("ADB not found; provide --adb to a trusted platform-tools executable")
        result = probe(args.adb, args.serial)
    except ProbeError as exc:
        print(json.dumps({"check": "read-only-android-device-preflight", "ok": False, "error": str(exc)}))
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
