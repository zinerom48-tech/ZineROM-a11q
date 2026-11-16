#!/usr/bin/env python3
"""Exercise the in-ROM legacy-fscrypt mod install path.

``scripts/make_rom.sh`` sources this mod through
``scripts/internal/apply_modules.sh``.  The full ROM build cannot yet run in
CI because ``.github/workflows/build.yml`` fails while installing a
runner-specific kernel package (ISSUE-028), so this test drives the mod
directly with the real helper scripts, the real ``SET_METADATA``
implementation, and a synthetic donor init/vold.rc layout.

Covered:
  * target compile and the wrapper/shim ELF checks;
  * moving the donor init to init.real without changing its bytes;
  * installing the wrapper and shim, preserving the ueventd symlink;
  * exactly-once fs_config/file_context entries for all three paths;
  * exactly one LD_PRELOAD line in vold.rc;
  * a second run is idempotent;
  * a non-symlink ueventd and a foreign init.real abort before modifying init.

The fixture donor init is synthetic (a valid ELF64/AArch64 header plus a
marker) rather than a 3.6 MB vendor blob.  The real donor init/vold.rc were
verified separately; this test guards the install logic that make_rom.sh runs.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BASH = os.environ.get("A115F_TEST_BASH") or shutil.which("bash")
TARGET_CC = os.environ.get("A115F_TEST_CC", "clang")
HOST_CC = os.environ.get("A115F_TEST_HOST_CC", "cc")

SHIM_REL = "system/lib64/liba115f_fscrypt_shim.so"
SETENV = "setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so"

FS_CONFIG = (
    "system/bin/init 0 0 750 capabilities=0x0\n"
    "system/bin/ueventd 0 0 750 capabilities=0x0\n"
    "system/lib64/liba115f_fscrypt_shim.so 0 0 644 capabilities=0x0\n"
)
FILE_CONTEXT = (
    "/system/bin/init u:object_r:init_exec:s0\n"
    "/system/bin/ueventd u:object_r:init_exec:s0\n"
    "/system/lib64/liba115f_fscrypt_shim\\.so u:object_r:system_lib_file:s0\n"
)
VOLD_RC = (
    "service vold /system/bin/vold \\\n"
    "    --blkid_context=u:r:blkid:s0 \\\n"
    "    --fsck_context=u:r:fsck:s0\n"
    "    class core\n"
    "    ioprio be 2\n"
    "\n"
    "on late-fs\n"
    "    start vold\n"
)

# Mirror scripts/internal/apply_modules.sh: source the helpers and the mod
# with errexit active, so a fail-closed return aborts the driver.
DRIVER = """#!/usr/bin/env bash
set -e
export WORK_DIR="$1"
export TMP_DIR="$2"
export SRC_DIR="$3"
export TARGET_CODENAME=a115f
export TARGET_SINGLE_SYSTEM_IMAGE=qssi
export TARGET_HAS_SYSTEM_EXT=false
source "$SRC_DIR/scripts/utils/common_utils.sh"
source "$SRC_DIR/unica/mods/zz_a115f_legacy_fscrypt/customize.sh"
"""


def to_bash_path(value: Path | str) -> str:
    """Return a path usable by MSYS bash when the host is Windows."""
    if os.name != "nt":
        return str(value)
    path = Path(value)
    if not path.is_absolute() or not path.drive:
        return str(value)
    drive = path.drive.rstrip(":").lower()
    return f"/{drive}{path.as_posix().split(':', 1)[1]}"


def command_available(command: str) -> bool:
    return Path(command).is_file() or bool(shutil.which(command))


def donor_init_bytes() -> bytes:
    data = bytearray(4096)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # ELFCLASS64
    data[5] = 1  # little-endian
    data[6] = 1  # EV_CURRENT
    struct.pack_into("<H", data, 16, 3)  # ET_DYN, like the donor init
    struct.pack_into("<H", data, 18, 0xB7)  # EM_AARCH64
    payload = b"A115F_TEST_DONOR_INIT\n"
    data[64 : 64 + len(payload)] = payload
    return bytes(data)


class LegacyFscryptModInstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if BASH is None:
            if os.name == "nt":
                raise unittest.SkipTest("bash is not available on this Windows workstation")
            raise AssertionError("bash is required for the mod-install test")
        for label, command in (("target compiler", TARGET_CC), ("host compiler", HOST_CC)):
            if not command_available(command):
                if os.name == "nt":
                    raise unittest.SkipTest(f"{label} {command!r} is not available")
                raise AssertionError(f"{label} {command!r} is required for the mod-install test")

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.base = Path(self.tempdir.name)
        self.driver = self.base / "run_mod.sh"
        with open(self.driver, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(DRIVER)

    def make_work(self, name: str) -> tuple[Path, Path]:
        root = self.base / name
        work = root / "work"
        tmp = root / "tmp"
        bin_dir = work / "system" / "system" / "bin"
        etc_dir = work / "system" / "system" / "etc" / "init"
        configs = work / "configs"
        for directory in (bin_dir, etc_dir, configs, tmp):
            directory.mkdir(parents=True, exist_ok=True)

        with open(bin_dir / "init", "wb") as handle:
            handle.write(donor_init_bytes())
        (bin_dir / "ueventd").symlink_to("init")
        with open(etc_dir / "vold.rc", "w", encoding="utf-8", newline="") as handle:
            handle.write(VOLD_RC)
        with open(configs / "fs_config-system", "w", encoding="utf-8", newline="") as handle:
            handle.write(FS_CONFIG)
        with open(configs / "file_context-system", "w", encoding="utf-8", newline="") as handle:
            handle.write(FILE_CONTEXT)
        return work, tmp

    def run_mod(self, work: Path, tmp: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["CC"] = to_bash_path(TARGET_CC)
        env["HOST_CC"] = to_bash_path(HOST_CC)
        return subprocess.run(
            [
                BASH,
                to_bash_path(self.driver),
                to_bash_path(work),
                to_bash_path(tmp),
                to_bash_path(ROOT),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def assert_installed(self, work: Path) -> None:
        donor = donor_init_bytes()
        init_path = work / "system" / "system" / "bin" / "init"
        init_real = work / "system" / "system" / "bin" / "init.real"
        ueventd = work / "system" / "system" / "bin" / "ueventd"
        shim = work / "system" / SHIM_REL
        vold_rc = work / "system" / "system" / "etc" / "init" / "vold.rc"

        self.assertTrue(init_real.is_file(), "init.real was not created")
        self.assertEqual(init_real.read_bytes(), donor, "donor init bytes changed")
        self.assertIn(b"A115F_FSCRYPT_WRAPPER", init_path.read_bytes(), "wrapper was not installed")
        self.assertTrue(ueventd.is_symlink(), "ueventd is no longer a symlink")
        self.assertEqual(os.readlink(ueventd), "init")
        self.assertTrue(shim.is_file(), "shim was not installed")
        self.assertIn(b"SHIM_LOADED", shim.read_bytes())

        rc_text = vold_rc.read_text(encoding="utf-8")
        self.assertEqual(rc_text.count(SETENV), 1, "vold.rc LD_PRELOAD count is not 1")

        fs_lines = (work / "configs" / "fs_config-system").read_text(encoding="utf-8").splitlines()
        self.assertEqual(fs_lines.count("system/bin/init 0 0 0750 capabilities=0x0"), 1)
        self.assertEqual(fs_lines.count("system/bin/init 0 0 750 capabilities=0x0"), 0)
        self.assertEqual(fs_lines.count("system/bin/init.real 0 0 0750 capabilities=0x0"), 1)
        self.assertEqual(fs_lines.count("system/lib64/liba115f_fscrypt_shim.so 0 0 0644 capabilities=0x0"), 1)

        fc_lines = (work / "configs" / "file_context-system").read_text(encoding="utf-8").splitlines()
        self.assertEqual(fc_lines.count("/system/bin/init u:object_r:init_exec:s0"), 1)
        self.assertEqual(fc_lines.count("/system/bin/init\\.real u:object_r:init_exec:s0"), 1)
        self.assertEqual(
            fc_lines.count("/system/lib64/liba115f_fscrypt_shim\\.so u:object_r:system_lib_file:s0"),
            1,
        )

    def test_first_install(self) -> None:
        work, tmp = self.make_work("first")
        result = self.run_mod(work, tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_installed(work)

    def test_second_run_is_idempotent(self) -> None:
        work, tmp = self.make_work("idempotent")
        first = self.run_mod(work, tmp)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self.run_mod(work, tmp)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assert_installed(work)

    def test_non_symlink_ueventd_aborts_before_moving_init(self) -> None:
        work, tmp = self.make_work("bad_ueventd")
        ueventd = work / "system" / "system" / "bin" / "ueventd"
        ueventd.unlink()
        with open(ueventd, "w", encoding="utf-8", newline="") as handle:
            handle.write("not a symlink\n")

        result = self.run_mod(work, tmp)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a symlink", result.stdout + result.stderr)
        self.assertEqual((work / "system" / "system" / "bin" / "init").read_bytes(), donor_init_bytes())
        self.assertFalse((work / "system" / "system" / "bin" / "init.real").exists())

    def test_foreign_init_real_aborts_without_touching_init(self) -> None:
        work, tmp = self.make_work("foreign_init_real")
        init = work / "system" / "system" / "bin" / "init"
        with open(work / "system" / "system" / "bin" / "init.real", "wb") as handle:
            handle.write(donor_init_bytes())

        result = self.run_mod(work, tmp)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("init.real already exists", result.stdout + result.stderr)
        self.assertEqual(init.read_bytes(), donor_init_bytes())


if __name__ == "__main__":
    unittest.main()
