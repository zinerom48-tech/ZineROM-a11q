#!/usr/bin/env python3
"""Insert the A115F legacy-fscrypt LD_PRELOAD into a vold init rc file.

The donor system image exposes vold as:

    service vold /system/bin/vold \\
        --blkid_context=... \\
        --fsck_context=...
        class core
        ...

A ``setenv`` service option must be added after the complete (possibly
backslash-continued) command and before the next option. This script is
idempotent and fails if a different LD_PRELOAD is already present.

Usage: patch_a115f_legacy_fscrypt_vold_rc.py <path-to-vold.rc>
Exit: 0 patched or already patched, 1 error.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

SETENV_VALUE = "setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so"
SETENV_INDENT = "    "

SERVICE_RE = re.compile(r"^service\s+vold(?:\s|$)")
TOP_LEVEL_RE = re.compile(r"^\S")


def _find_service(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if SERVICE_RE.match(line):
            return index
    return None


def _command_end(lines: list[str], start: int) -> int:
    """Return the index of the last line of the service command."""
    index = start
    while True:
        if index >= len(lines):
            raise ValueError("unterminated service command (file ended after a backslash)")
        if not lines[index].rstrip().endswith("\\"):
            return index
        index += 1


def _block_end(lines: list[str], start: int) -> int:
    """Return the last line index of the service block (before the next section)."""
    index = start
    while index + 1 < len(lines):
        nxt = lines[index + 1]
        stripped = nxt.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("#"):
            index += 1
            continue
        if TOP_LEVEL_RE.match(nxt):
            break
        index += 1
    return index


def patch_text(text: str) -> tuple[str, bool]:
    lines = text.splitlines(keepends=True)
    start = _find_service(lines)
    if start is None:
        raise ValueError("no 'service vold' block found")

    command_end = _command_end(lines, start)
    block_end = _block_end(lines, start)

    already = False
    for line in lines[start : block_end + 1]:
        if "LD_PRELOAD" not in line:
            continue
        if line.strip() == SETENV_VALUE:
            already = True
            continue
        raise ValueError("conflicting LD_PRELOAD line: " + line.strip())
    if already:
        return text, False

    newline = "\r\n" if lines[command_end].endswith("\r\n") else "\n"
    insertion = SETENV_INDENT + SETENV_VALUE + newline
    lines.insert(command_end + 1, insertion)
    return "".join(lines), True


def patch_file(path: str) -> bool:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        original = handle.read()

    updated, changed = patch_text(original)
    if not changed:
        return False

    directory = os.path.dirname(os.path.abspath(path)) or "."
    mode = os.stat(path).st_mode
    fd, temp_path = tempfile.mkstemp(prefix=".vold.rc.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: patch_a115f_legacy_fscrypt_vold_rc.py <vold.rc>", file=sys.stderr)
        return 2

    path = argv[1]
    if not os.path.isfile(path):
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    try:
        changed = patch_file(path)
    except (OSError, ValueError) as error:
        print(f"error: {path}: {error}", file=sys.stderr)
        return 1

    if changed:
        print(f"patched {path}: {SETENV_VALUE}")
    else:
        print(f"already patched {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
