#!/usr/bin/env bash
#
# Build the A115F legacy fscrypt bridge binaries.
#
# Outputs (into OUT_DIR, default ./out):
#   init.a115f_legacy_fscrypt   static aarch64 ELF, installed as
#                               /system/bin/init; the donor system init
#                               becomes /system/bin/init.real
#   liba115f_fscrypt_shim.so    aarch64 shared object, LD_PRELOADed into vold
#
# The target compilation deliberately uses only compiler-provided freestanding
# headers. Do not add a libc dependency to the wrapper: it runs before the
# dynamic linker is usable and must create keyrings before SELinux policy is
# loaded.
#
# Usage:
#   OUT_DIR=/path build.sh
#   build.sh --host-test
#
# Env:
#   CC       target compiler (default: clang)
#   HOST_CC  host compiler for --host-test (default: cc)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$HERE/out}"
CC="${CC:-clang}"
HOST_CC="${HOST_CC:-cc}"
SRC="$HERE/src"

if [[ "${1:-}" == "--host-test" ]]; then
    mkdir -p "$OUT_DIR"
    "$HOST_CC" -O2 -Wall -Wextra -I"$SRC" \
        "$SRC/fscrypt_legacy.c" "$HERE/tests/test_legacy.c" \
        -o "$OUT_DIR/test_legacy"
    "$OUT_DIR/test_legacy"
    exit 0
fi

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: target compiler '$CC' not found" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

COMMON=(
    --target=aarch64-linux-gnu
    -O2
    -ffreestanding
    -fno-builtin
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -fno-unwind-tables
    -fno-common
    -fuse-ld=lld
    -Wall
    -Wextra
    -Wno-unused-parameter
    -I"$SRC"
)

WRAPPER="$OUT_DIR/init.a115f_legacy_fscrypt"
SHIM="$OUT_DIR/liba115f_fscrypt_shim.so"

echo "Compiling $WRAPPER"
"$CC" "${COMMON[@]}" \
    -nostdlib -static -no-pie \
    -Wl,-e,_start -Wl,--build-id=none -Wl,-s \
    -o "$WRAPPER" \
    "$SRC/init_wrapper.c" "$SRC/fscrypt_legacy.c" "$SRC/freestanding.c"

echo "Compiling $SHIM"
"$CC" "${COMMON[@]}" \
    -nostdlib -shared -fPIC \
    -Wl,-soname,liba115f_fscrypt_shim.so -Wl,--build-id=none -Wl,-s \
    -o "$SHIM" \
    "$SRC/fscrypt_legacy_shim.c" "$SRC/fscrypt_legacy.c" "$SRC/freestanding.c"

for f in "$WRAPPER" "$SHIM"; do
    if [[ ! -s "$f" ]]; then
        echo "error: expected output missing or empty: $f" >&2
        exit 1
    fi
done

echo "Built:"
ls -l "$WRAPPER" "$SHIM"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$WRAPPER" "$SHIM"
fi
