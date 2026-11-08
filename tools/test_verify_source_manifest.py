#!/usr/bin/env python3
"""Tests for exhaustive source manifest validation, without touching the repo."""

import hashlib
import pathlib
import tempfile
import unittest

from verify_source_manifest import verify


class VerifySourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.manifest = self.root / "SOURCE_SHA256SUMS.txt"
        self.folder = self.root / "nested"
        self.folder.mkdir()
        self.data = self.folder / "data.txt"
        self.data.write_bytes(b"original")
        self.record("nested/data.txt", b"original")

    def record(self, name, content):
        self.manifest.write_text(f"{hashlib.sha256(content).hexdigest()}  {name}\n")

    def test_valid_source_and_ignored_git_folder(self):
        (self.root / ".git").mkdir()
        (self.root / ".git" / "index").write_bytes(b"git metadata")
        self.assertEqual([], verify(self.root, self.manifest))

    def test_new_unlisted_source_fails(self):
        (self.root / "surprise.txt").write_bytes(b"unexpected")
        self.assertTrue(any("unlisted" in x for x in verify(self.root, self.manifest)))

    def test_changed_source_fails(self):
        self.data.write_bytes(b"altered")
        self.assertTrue(any("mismatch" in x for x in verify(self.root, self.manifest)))

    def test_missing_source_fails(self):
        self.data.unlink()
        self.assertTrue(any("missing" in x for x in verify(self.root, self.manifest)))

    def test_duplicate_manifest_entry_fails(self):
        self.manifest.write_text(self.manifest.read_text() * 2)
        self.assertTrue(any("duplicate" in x for x in verify(self.root, self.manifest)))

    def test_path_escape_and_unlisted_file_fail(self):
        self.manifest.write_text("0" * 64 + "  ../outside.txt\n")
        self.assertTrue(any("unsafe" in x for x in verify(self.root, self.manifest)))

    def test_source_symlink_fails(self):
        link = self.root / "linked.txt"
        try:
            link.symlink_to(self.data)
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertTrue(any("symbolic link" in x for x in verify(self.root, self.manifest)))

    def test_bad_manifest_line_fails(self):
        self.manifest.write_text("not a checksum\n")
        self.assertTrue(any("invalid manifest" in x for x in verify(self.root, self.manifest)))


if __name__ == "__main__":
    unittest.main()
