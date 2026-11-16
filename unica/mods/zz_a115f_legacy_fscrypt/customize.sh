#!/usr/bin/env bash
#
# A115F legacy fscrypt bridge.
#
# The A11 4.9.227 kernel implements only the legacy fscrypt keyring, while the
# One UI 7 donor init/vold have no legacy fallback. This mod:
#   1. compiles the freestanding /system/bin/init wrapper and the 64-bit vold
#      LD_PRELOAD shim;
#   2. moves the donor init to /system/bin/init.real and installs the wrapper
#      as /system/bin/init (the wrapper creates PID 1's session + fscrypt
#      keyrings before SELinux policy is loaded, then execs the real init);
#   3. installs the shim into /system/lib64;
#   4. adds the LD_PRELOAD setenv to the donor vold.rc.
#
# /system/bin/ueventd is a symlink to /system/bin/init. The wrapper preserves
# argv[0] and passes ueventd through without keyring setup, so the donor init's
# basename-based ueventd mode is preserved.
#
# This mod is fail-closed: an unexpected init layout, missing tool, failed
# compile, or failed metadata update aborts the ROM build.
#
# Sourced by scripts/internal/apply_modules.sh; do not execute directly.

SKIPUNZIP=1

A115F_FSCRYPT_TAG="A115F legacy fscrypt bridge"
A115F_FSCRYPT_MARKER="A115F_FSCRYPT_WRAPPER"

if [ "$TARGET_CODENAME" != "a115f" ]; then
    LOG "- Skipping $A115F_FSCRYPT_TAG for $TARGET_CODENAME"
    return 0
fi

A115F_LEGACY_PREBUILT="$SRC_DIR/prebuilts/a115f_legacy_fscrypt"
A115F_SYSTEM_ROOT="$WORK_DIR/system/system"
A115F_SYSTEM_INIT="$A115F_SYSTEM_ROOT/bin/init"
A115F_SYSTEM_INIT_REAL="$A115F_SYSTEM_ROOT/bin/init.real"
A115F_SYSTEM_UEVENTD="$A115F_SYSTEM_ROOT/bin/ueventd"
A115F_VOLD_RC="$A115F_SYSTEM_ROOT/etc/init/vold.rc"
A115F_SHIM_REL="system/lib64/liba115f_fscrypt_shim.so"
A115F_SHIM_DST="$WORK_DIR/system/$A115F_SHIM_REL"
A115F_BUILD_ROOT="$TMP_DIR/a115f_legacy_fscrypt"
A115F_OUT_ROOT="$A115F_BUILD_ROOT/out"

for a115f_tool in bash clang xxd python3; do
    if ! command -v "$a115f_tool" >/dev/null 2>&1; then
        LOGE "$A115F_FSCRYPT_TAG: required tool not found: $a115f_tool"
        return 1
    fi
done

if [ ! -f "$A115F_LEGACY_PREBUILT/build.sh" ]; then
    LOGE "$A115F_FSCRYPT_TAG: build script not found: $A115F_LEGACY_PREBUILT/build.sh"
    return 1
fi
if [ ! -f "$A115F_SYSTEM_INIT" ] || [ -L "$A115F_SYSTEM_INIT" ]; then
    LOGE "$A115F_FSCRYPT_TAG: $A115F_SYSTEM_INIT is missing or not a regular file"
    return 1
fi
if [ ! -L "$A115F_SYSTEM_UEVENTD" ]; then
    LOGE "$A115F_FSCRYPT_TAG: $A115F_SYSTEM_UEVENTD is not a symlink; the init wrapper would break ueventd"
    return 1
fi
A115F_UEVENTD_TARGET="$(readlink "$A115F_SYSTEM_UEVENTD")"
if [ "$A115F_UEVENTD_TARGET" != "init" ] && [ "$A115F_UEVENTD_TARGET" != "./init" ]; then
    LOGE "$A115F_FSCRYPT_TAG: unexpected ueventd symlink target: $A115F_UEVENTD_TARGET"
    return 1
fi
if [ ! -f "$A115F_VOLD_RC" ]; then
    LOGE "$A115F_FSCRYPT_TAG: vold.rc not found: $A115F_VOLD_RC"
    return 1
fi

check_dynamic_layout() {
    local WRAPPER="$1"
    local SHIM="$2"
    local UNDEFINED

    if ! command -v readelf >/dev/null 2>&1; then
        LOG "  readelf not available; skipping dynamic-section and symbol checks"
        return 0
    fi

    if readelf -l "$WRAPPER" | grep -q 'INTERP'; then
        LOGE "$A115F_FSCRYPT_TAG: wrapper requests a dynamic linker (PT_INTERP)"
        return 1
    fi
    if readelf -S "$WRAPPER" | grep -q '\.dynamic'; then
        LOGE "$A115F_FSCRYPT_TAG: wrapper contains a .dynamic section"
        return 1
    fi
    if readelf -d "$WRAPPER" | grep -q 'NEEDED'; then
        LOGE "$A115F_FSCRYPT_TAG: wrapper has a DT_NEEDED dependency"
        return 1
    fi
    if readelf -d "$SHIM" | grep -q 'NEEDED'; then
        LOGE "$A115F_FSCRYPT_TAG: shim has a DT_NEEDED dependency"
        return 1
    fi
    if ! readelf --dyn-syms -W "$SHIM" | grep -Eq '[[:space:]]ioctl$'; then
        LOGE "$A115F_FSCRYPT_TAG: shim does not export ioctl"
        return 1
    fi
    if readelf --dyn-syms -W "$SHIM" | grep -Eq '[[:space:]](memcpy|memmove|memset)$'; then
        LOGE "$A115F_FSCRYPT_TAG: shim exports a libc memory symbol"
        return 1
    fi

    UNDEFINED="$(readelf --dyn-syms -W "$SHIM" \
        | awk '$7 == "UND" && $8 != "" { print $8 }' \
        | sed 's/@.*//' | sort -u | tr '\n' ' ' || true)"
    if [ "$UNDEFINED" != "__android_log_print __errno " ]; then
        LOGE "$A115F_FSCRYPT_TAG: unexpected shim imports: '$UNDEFINED'"
        return 1
    fi
    return 0
}

check_elf64_aarch64() {
    local FILE="$1"
    local MAGIC CLASS MACHINE

    MAGIC="$(xxd -p -l 4 "$FILE")"
    CLASS="$(xxd -p -s 4 -l 1 "$FILE")"
    MACHINE="$(xxd -p -s 18 -l 2 "$FILE")"

    if [ "$MAGIC" != "7f454c46" ] || [ "$CLASS" != "02" ] || [ "$MACHINE" != "b700" ]; then
        LOGE "$A115F_FSCRYPT_TAG: unexpected ELF layout: $FILE (magic=$MAGIC class=$CLASS machine=$MACHINE)"
        return 1
    fi
    return 0
}

check_elf_type() {
    local FILE="$1"
    local EXPECTED_TYPE="$2"
    local TYPE

    TYPE="$(xxd -p -s 16 -l 2 "$FILE")"
    if [ "$TYPE" != "$EXPECTED_TYPE" ]; then
        LOGE "$A115F_FSCRYPT_TAG: unexpected ELF type: $FILE (type=$TYPE expected=$EXPECTED_TYPE)"
        return 1
    fi
    return 0
}

LOG "- Compiling the legacy fscrypt init wrapper and vold shim"
rm -rf "$A115F_BUILD_ROOT"
mkdir -p "$A115F_OUT_ROOT"
if ! OUT_DIR="$A115F_OUT_ROOT" bash "$A115F_LEGACY_PREBUILT/build.sh"; then
    LOGE "$A115F_FSCRYPT_TAG: compilation failed"
    return 1
fi

A115F_HOST_CC="${HOST_CC:-cc}"
if command -v "$A115F_HOST_CC" >/dev/null 2>&1; then
    LOG "- Running host unit tests for the legacy key helpers"
    if ! OUT_DIR="$A115F_OUT_ROOT" HOST_CC="$A115F_HOST_CC" \
            bash "$A115F_LEGACY_PREBUILT/build.sh" --host-test; then
        LOGE "$A115F_FSCRYPT_TAG: host unit tests failed"
        return 1
    fi
else
    LOG "  host compiler '$A115F_HOST_CC' not found; skipping host unit tests"
fi

if command -v python3 >/dev/null 2>&1; then
    LOG "- Running vold.rc patcher unit tests"
    if ! ( cd "$SRC_DIR" && python3 -m unittest discover -s tests \
            -p 'test_legacy_fscrypt_vold_rc.py' ); then
        LOGE "$A115F_FSCRYPT_TAG: vold.rc patcher unit tests failed"
        return 1
    fi
fi

A115F_WRAPPER="$A115F_OUT_ROOT/init.a115f_legacy_fscrypt"
A115F_SHIM="$A115F_OUT_ROOT/liba115f_fscrypt_shim.so"
if [ ! -s "$A115F_WRAPPER" ] || [ ! -s "$A115F_SHIM" ]; then
    LOGE "$A115F_FSCRYPT_TAG: compiler did not produce both binaries"
    return 1
fi
if ! check_elf64_aarch64 "$A115F_WRAPPER" || ! check_elf_type "$A115F_WRAPPER" "0200"; then
    return 1
fi
if ! check_elf64_aarch64 "$A115F_SHIM" || ! check_elf_type "$A115F_SHIM" "0300"; then
    return 1
fi
if ! grep -aq "$A115F_FSCRYPT_MARKER" "$A115F_WRAPPER"; then
    LOGE "$A115F_FSCRYPT_TAG: wrapper marker missing from compiled binary"
    return 1
fi
if ! grep -aq "SHIM_LOADED" "$A115F_SHIM"; then
    LOGE "$A115F_FSCRYPT_TAG: shim marker missing from compiled binary"
    return 1
fi
if ! check_dynamic_layout "$A115F_WRAPPER" "$A115F_SHIM"; then
    return 1
fi

if [ -e "$A115F_SYSTEM_INIT_REAL" ] || [ -L "$A115F_SYSTEM_INIT_REAL" ]; then
    if ! grep -aq "$A115F_FSCRYPT_MARKER" "$A115F_SYSTEM_INIT"; then
        LOGE "$A115F_FSCRYPT_TAG: /system/bin/init.real already exists but /system/bin/init is not the wrapper"
        return 1
    fi
    LOG "- Keeping existing /system/bin/init.real (already patched)"
else
    if ! check_elf64_aarch64 "$A115F_SYSTEM_INIT"; then
        return 1
    fi
    LOG "- Moving donor /system/bin/init to /system/bin/init.real"
    mv "$A115F_SYSTEM_INIT" "$A115F_SYSTEM_INIT_REAL" || return 1
fi
if [ ! -f "$A115F_SYSTEM_INIT_REAL" ] || [ -L "$A115F_SYSTEM_INIT_REAL" ]; then
    LOGE "$A115F_FSCRYPT_TAG: /system/bin/init.real is missing or not a regular file"
    return 1
fi
if ! check_elf64_aarch64 "$A115F_SYSTEM_INIT_REAL"; then
    return 1
fi

LOG "- Installing the init wrapper as /system/bin/init"
cp -a "$A115F_WRAPPER" "$A115F_SYSTEM_INIT" || return 1
chmod 0750 "$A115F_SYSTEM_INIT"
chmod 0750 "$A115F_SYSTEM_INIT_REAL"
if ! cmp -s "$A115F_WRAPPER" "$A115F_SYSTEM_INIT"; then
    LOGE "$A115F_FSCRYPT_TAG: init wrapper copy verification failed"
    return 1
fi
if ! SET_METADATA "system" "system/bin/init" 0 0 0750 "u:object_r:init_exec:s0"; then
    LOGE "$A115F_FSCRYPT_TAG: failed to add /system/bin/init metadata"
    return 1
fi
if ! SET_METADATA "system" "system/bin/init.real" 0 0 0750 "u:object_r:init_exec:s0"; then
    LOGE "$A115F_FSCRYPT_TAG: failed to add /system/bin/init.real metadata"
    return 1
fi

LOG "- Installing the vold shim at /$A115F_SHIM_REL"
mkdir -p "$(dirname "$A115F_SHIM_DST")"
cp -a "$A115F_SHIM" "$A115F_SHIM_DST" || return 1
chmod 0644 "$A115F_SHIM_DST"
if ! cmp -s "$A115F_SHIM" "$A115F_SHIM_DST"; then
    LOGE "$A115F_FSCRYPT_TAG: shim copy verification failed"
    return 1
fi
if ! SET_METADATA "system" "$A115F_SHIM_REL" 0 0 0644 "u:object_r:system_lib_file:s0"; then
    LOGE "$A115F_FSCRYPT_TAG: failed to add shim metadata"
    return 1
fi

LOG "- Adding LD_PRELOAD to /system/etc/init/vold.rc"
if ! python3 "$SRC_DIR/scripts/patch_a115f_legacy_fscrypt_vold_rc.py" "$A115F_VOLD_RC"; then
    LOGE "$A115F_FSCRYPT_TAG: vold.rc patch failed"
    return 1
fi
if ! grep -qF "setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so" "$A115F_VOLD_RC"; then
    LOGE "$A115F_FSCRYPT_TAG: vold.rc verification failed"
    return 1
fi

LOG "- $A115F_FSCRYPT_TAG installed (static build only; device test pending)"
LOG "  init.real: $(sha256sum "$A115F_SYSTEM_INIT_REAL" | cut -d ' ' -f 1)"
LOG "  init:      $(sha256sum "$A115F_SYSTEM_INIT" | cut -d ' ' -f 1)"
LOG "  shim:      $(sha256sum "$A115F_SHIM_DST" | cut -d ' ' -f 1)"

return 0
