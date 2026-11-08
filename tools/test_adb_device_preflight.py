"""Synthetic ADB preflight contract tests; never contacts an actual device."""

import contextlib
import io
import json
import subprocess
import unittest
from unittest import mock

import adb_device_preflight as preflight


class StubADB:
    def __init__(self, serial="test-device", abis="arm64-v8a,armeabi-v7a", sdk="36", state="device"):
        self.serial, self.abis, self.sdk, self.state = serial, abis, sdk, state
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[1:] == ["devices", "-l"]:
            output = f"List of devices attached\n{self.serial}\t{self.state} model:sample\n"
        else:
            if args[1:5] != ["-s", self.serial, "shell", "getprop"]:
                raise AssertionError(f"unexpected or mutating ADB call: {args}")
            output = {
                "ro.product.model": "Test Android",
                "ro.build.version.sdk": self.sdk,
                "ro.product.cpu.abilist": self.abis,
                "ro.product.cpu.abi": self.abis.split(",")[0],
            }[args[5]] + "\n"
        return subprocess.CompletedProcess(args, 0, output, "")


class TestADBReadOnlyPreflight(unittest.TestCase):
    def test_arm64_compile_candidate_not_runtime_certification(self):
        adb = StubADB()
        with mock.patch.object(preflight.subprocess, "run", side_effect=adb):
            result = preflight.probe("/trusted/adb", "test-device")
        self.assertEqual(result["candidateGoTarget"], "android/arm64")
        self.assertFalse(result["runtimeVerified"])
        self.assertFalse(result["deploymentPerformed"])
        self.assertEqual(len(adb.calls), 5)
        self.assertNotIn("test-device", json.dumps(result))

    def test_32_bit_arm_is_explicitly_unsupported(self):
        adb = StubADB(abis="armeabi-v7a", sdk="34")
        with mock.patch.object(preflight.subprocess, "run", side_effect=adb):
            result = preflight.probe("/trusted/adb", "test-device")
        self.assertIsNone(result["candidateGoTarget"])
        self.assertIn("external cgo", result["limitation"])

    def test_wrong_serial_never_issues_device_shell(self):
        adb = StubADB()
        with mock.patch.object(preflight.subprocess, "run", side_effect=adb):
            with self.assertRaises(preflight.ProbeError):
                preflight.probe("/trusted/adb", "another-device")
        self.assertEqual(len(adb.calls), 1)

    def test_offline_device_never_issues_device_shell(self):
        adb = StubADB(state="offline")
        with mock.patch.object(preflight.subprocess, "run", side_effect=adb):
            with self.assertRaises(preflight.ProbeError):
                preflight.probe("/trusted/adb", "test-device")
        self.assertEqual(len(adb.calls), 1)

    def test_invalid_selector_cannot_be_command_option(self):
        with mock.patch.object(preflight.subprocess, "run") as runner:
            for selector in ("-s", "../device", "device\nexample", "x" * 130, ""):
                with self.assertRaises(preflight.ProbeError):
                    preflight.probe("/trusted/adb", selector)
            runner.assert_not_called()

    def test_invalid_sdk_or_abi_fails_closed(self):
        for values in ({"sdk": "not-a-number"}, {"abis": "../../something"}, {"abis": ""}, {"sdk": "9999"}):
            adb = StubADB(**values)
            with mock.patch.object(preflight.subprocess, "run", side_effect=adb):
                with self.assertRaises(preflight.ProbeError):
                    preflight.probe("/trusted/adb", "test-device")

    def test_timeout_fails_closed(self):
        with mock.patch.object(preflight.subprocess, "run", side_effect=subprocess.TimeoutExpired("adb", 8)):
            with self.assertRaises(preflight.ProbeError):
                preflight.probe("/trusted/adb", "test-device")

    def test_cli_prints_no_device_serial(self):
        adb = StubADB()
        output = io.StringIO()
        with mock.patch.object(preflight.subprocess, "run", side_effect=adb), contextlib.redirect_stdout(output):
            code = preflight.main(["--adb", "/trusted/adb", "--serial", "test-device"])
        self.assertEqual(code, 0)
        self.assertNotIn("test-device", output.getvalue())
        self.assertTrue(json.loads(output.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
