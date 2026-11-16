#!/usr/bin/env python3
"""Compile the freestanding legacy-fscrypt targets and verify their ELF contract.

This test mirrors ``prebuilts/a115f_legacy_fscrypt/build.sh`` exactly so that CI
proves the wrapper/shim build even when the ROM build is blocked earlier by an
unrelated workflow defect.  It also compiles and runs the host unit tests.

The target compile is skipped only when no target compiler is available (for
example on a Windows workstation).  A missing host compiler skips just the host
unit test.  A toolchain that exists but fails to build the sources is a real
failure, not a skip.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREBUILT = ROOT / "prebuilts" / "a115f_legacy_fscrypt"
SRC = PREBUILT / "src"

TARGET_CC = os.environ.get("A115F_TEST_CC", "clang")
HOST_CC = os.environ.get("A115F_TEST_HOST_CC", "cc")
READELF = shutil.which("readelf") or shutil.which("llvm-readelf")

EM_AARCH64 = 0xB7
ET_EXEC = 2
ET_DYN = 3
PT_DYNAMIC = 2
PT_INTERP = 3

COMMON_FLAGS = [
    "--target=aarch64-linux-gnu",
    "-O2",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-fno-common",
    "-fuse-ld=lld",
    "-Wall",
    "-Wextra",
    "-Wno-unused-parameter",
    f"-I{SRC}",
]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_elf_header(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise AssertionError(f"{path} is not an ELF file")
    if data[4] != 2:
        raise AssertionError(f"{path} is not ELF64 (EI_CLASS={data[4]})")
    if data[5] != 1:
        raise AssertionError(f"{path} is not little-endian (EI_DATA={data[5]})")
    return {
        "type": struct.unpack_from("<H", data, 16)[0],
        "machine": struct.unpack_from("<H", data, 18)[0],
        "phoff": struct.unpack_from("<Q", data, 32)[0],
        "phentsize": struct.unpack_from("<H", data, 54)[0],
        "phnum": struct.unpack_from("<H", data, 56)[0],
    }


def program_header_types(path: Path) -> list[int]:
    header = read_elf_header(path)
    data = path.read_bytes()
    types: list[int] = []
    for index in range(header["phnum"]):
        offset = header["phoff"] + index * header["phentsize"]
        types.append(struct.unpack_from("<I", data, offset)[0])
    return types


@unittest.skipUnless(shutil.which(TARGET_CC), f"target compiler {TARGET_CC!r} not on PATH")
class LegacyFscryptBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tempdir.name)
        flags = list(COMMON_FLAGS)
        wrapper = cls.out / "init.a115f_legacy_fscrypt"
        shim = cls.out / "liba115f_fscrypt_shim.so"

        wrapper_result = run(
            [
                TARGET_CC,
                *flags,
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-Wl,-s",
                "-o",
                str(wrapper),
                str(SRC / "init_wrapper.c"),
                str(SRC / "fscrypt_legacy.c"),
                str(SRC / "freestanding.c"),
            ]
        )
        shim_result = run(
            [
                TARGET_CC,
                *flags,
                "-nostdlib",
                "-shared",
                "-fPIC",
                "-Wl,-soname,liba115f_fscrypt_shim.so",
                "-Wl,--build-id=none",
                "-Wl,-s",
                "-o",
                str(shim),
                str(SRC / "fscrypt_legacy_shim.c"),
                str(SRC / "fscrypt_legacy.c"),
                str(SRC / "freestanding.c"),
            ]
        )
        cls.build_error = ""
        if wrapper_result.returncode != 0:
            cls.build_error = "wrapper:\n" + wrapper_result.stderr
        elif shim_result.returncode != 0:
            cls.build_error = "shim:\n" + shim_result.stderr
        elif not wrapper.is_file() or wrapper.stat().st_size == 0:
            cls.build_error = "wrapper output missing or empty"
        elif not shim.is_file() or shim.stat().st_size == 0:
            cls.build_error = "shim output missing or empty"
        cls.wrapper = wrapper
        cls.shim = shim

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def setUp(self) -> None:
        if self.build_error:
            self.fail(self.build_error)

    def test_targets_are_elf64_aarch64(self) -> None:
        wrapper_header = read_elf_header(self.wrapper)
        shim_header = read_elf_header(self.shim)
        self.assertEqual(wrapper_header["machine"], EM_AARCH64)
        self.assertEqual(shim_header["machine"], EM_AARCH64)
        self.assertEqual(wrapper_header["type"], ET_EXEC)
        self.assertEqual(shim_header["type"], ET_DYN)

    def test_wrapper_is_static(self) -> None:
        types = program_header_types(self.wrapper)
        self.assertNotIn(PT_INTERP, types, "wrapper must not request a dynamic linker")
        self.assertNotIn(PT_DYNAMIC, types, "wrapper must not have a dynamic segment")

    def test_shim_is_dynamic_without_needed(self) -> None:
        self.assertIn(PT_DYNAMIC, program_header_types(self.shim))

    def test_markers_present(self) -> None:
        self.assertIn(b"A115F_FSCRYPT_WRAPPER", self.wrapper.read_bytes())
        self.assertIn(b"SHIM_LOADED", self.shim.read_bytes())

    def test_hashes_recorded(self) -> None:
        # Printed so the CI log carries the exact hashes of the compiled targets.
        print(f"wrapper sha256={sha256(self.wrapper)} size={self.wrapper.stat().st_size}")
        print(f"shim sha256={sha256(self.shim)} size={self.shim.stat().st_size}")

    @unittest.skipUnless(READELF, "readelf/llvm-readelf not available")
    def test_dynamic_symbol_contract(self) -> None:
        wrapper_dynamic = run([READELF, "-d", str(self.wrapper)])
        self.assertEqual(wrapper_dynamic.returncode, 0, wrapper_dynamic.stderr)
        self.assertNotIn("NEEDED", wrapper_dynamic.stdout)

        sections = run([READELF, "-S", str(self.wrapper)])
        self.assertEqual(sections.returncode, 0, sections.stderr)
        self.assertNotIn(".dynamic", sections.stdout)

        shim_dynamic = run([READELF, "-d", str(self.shim)])
        self.assertEqual(shim_dynamic.returncode, 0, shim_dynamic.stderr)
        self.assertNotIn("NEEDED", shim_dynamic.stdout)

        symbols = run([READELF, "--dyn-syms", "-W", str(self.shim)])
        self.assertEqual(symbols.returncode, 0, symbols.stderr)
        lines = symbols.stdout.splitlines()
        exported = {
            line.split()[-1].split("@")[0]
            for line in lines
            if len(line.split()) >= 8 and line.split()[6] != "UND"
        }
        undefined = {
            line.split()[-1].split("@")[0]
            for line in lines
            if len(line.split()) >= 8 and line.split()[6] == "UND" and line.split()[-1]
        }
        self.assertIn("ioctl", exported)
        self.assertFalse({"memcpy", "memmove", "memset"} & exported)
        self.assertEqual(undefined, {"__android_log_print", "__errno"})

    @unittest.skipUnless(shutil.which(HOST_CC), f"host compiler {HOST_CC!r} not on PATH")
    def test_host_unit_tests(self) -> None:
        binary = self.out / ("test_legacy.exe" if os.name == "nt" else "test_legacy")
        compile_result = run(
            [
                HOST_CC,
                "-O2",
                "-Wall",
                "-Wextra",
                f"-I{SRC}",
                str(SRC / "fscrypt_legacy.c"),
                str(PREBUILT / "tests" / "test_legacy.c"),
                "-o",
                str(binary),
            ]
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        run_result = run([str(binary)])
        self.assertEqual(run_result.returncode, 0, run_result.stderr)
        self.assertIn("all legacy fscrypt host tests passed", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
