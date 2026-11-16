#!/usr/bin/env python3
"""Tests for scripts/patch_a115f_legacy_fscrypt_vold_rc.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHER = ROOT / "scripts" / "patch_a115f_legacy_fscrypt_vold_rc.py"

SAMPLE = (
    "service vold /system/bin/vold \\\n"
    "    --blkid_context=u:r:blkid:s0 \\\n"
    "    --fsck_context=u:r:fsck:s0\n"
    "    class core\n"
    "    ioprio be 2\n"
    "    socket knoxnative stream 0660 system system\n"
    "\n"
    "on late-fs\n"
    "    start vold\n"
)


class PatchVoldRcTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def write_rc(self, text: str, name: str = "vold.rc", newline: str = "\n") -> Path:
        path = Path(self.tempdir.name) / name
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        return path

    def run_patcher(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PATCHER), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )

    def read(self, path: Path) -> str:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            return handle.read()

    def test_inserts_after_multiline_command(self) -> None:
        path = self.write_rc(SAMPLE)
        result = self.run_patcher(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        patched = self.read(path)
        lines = patched.splitlines()
        command_end = lines.index("    --fsck_context=u:r:fsck:s0")
        setenv_index = next(
            index
            for index, line in enumerate(lines)
            if line.strip() == "setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so"
        )
        class_index = lines.index("    class core")
        self.assertEqual(setenv_index, command_end + 1)
        self.assertLess(setenv_index, class_index)

    def test_is_idempotent(self) -> None:
        path = self.write_rc(SAMPLE)
        self.assertEqual(self.run_patcher(path).returncode, 0)
        first = self.read(path)
        result = self.run_patcher(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already patched", result.stdout)
        self.assertEqual(first, self.read(path))
        self.assertEqual(first.count("setenv LD_PRELOAD"), 1)

    def test_single_line_service(self) -> None:
        path = self.write_rc(
            "service vold /system/bin/vold --blkid_context=a --fsck_context=b\n"
            "    class core\n"
        )
        self.assertEqual(self.run_patcher(path).returncode, 0)
        lines = self.read(path).splitlines()
        setenv_index = next(i for i, line in enumerate(lines) if "setenv LD_PRELOAD" in line)
        self.assertEqual(setenv_index, 1)
        self.assertEqual(lines[2].strip(), "class core")

    def test_conflicting_preload_is_rejected(self) -> None:
        conflicting = SAMPLE.replace(
            "    class core\n",
            "    setenv LD_PRELOAD /vendor/lib64/other_shim.so\n    class core\n",
        )
        path = self.write_rc(conflicting)
        result = self.run_patcher(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting LD_PRELOAD", result.stderr)
        self.assertEqual(self.read(path), conflicting)

    def test_missing_service_is_rejected(self) -> None:
        path = self.write_rc("on boot\n    start vold\n")
        result = self.run_patcher(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no 'service vold' block", result.stderr)

    def test_missing_file_is_rejected(self) -> None:
        result = self.run_patcher(Path(self.tempdir.name) / "does-not-exist.rc")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("file not found", result.stderr)

    def test_crlf_is_preserved(self) -> None:
        path = self.write_rc(SAMPLE.replace("\n", "\r\n"))
        self.assertEqual(self.run_patcher(path).returncode, 0)
        patched = self.read(path)
        self.assertIn(
            "setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so\r\n",
            patched,
        )
        self.assertNotIn("\n", patched.replace("\r\n", ""))


if __name__ == "__main__":
    unittest.main()
