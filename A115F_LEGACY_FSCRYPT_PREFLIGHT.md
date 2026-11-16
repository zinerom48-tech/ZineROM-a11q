# A115F legacy-fscrypt donor preflight

Date: 2026-11-16. Scope: static verification of the `zz_a115f_legacy_fscrypt`
mod's assumptions against the reconstructed donor system image
(`system_full.dat`, 3,213,774,848 bytes, Galaxy A05s `A057FXXUFDZH2`). No device
test was performed. Readiness remains R0.

## Donor layout

| Check | Result |
|---|---|
| `/system/bin/init` | Regular file, mode 0755, 3,644,816 bytes, ELF64 AArch64 `ET_DYN`, `PT_INTERP=/system/bin/bootstrap/linker64`, 23 `DT_NEEDED`, SHA-256 `e56989362bcf2533b5b3684ca665977669da55123e422889b9ba2f42723ce159` |
| `/system/bin/ueventd` | Symlink, mode 120755, size 4, target `init` |
| `/system/bin/init.real` | Absent |
| `/system/bin/bootstrap/linker64` | Present, `system/bin/bootstrap/linker64`, 2,169,360 bytes |
| `/system/lib64/bootstrap` | Present: `libc.so`, `libdl.so`, `libdl_android.so`, `libm.so`, hwasan variants |
| `/system/etc/init/vold.rc` | SHA-256 `6cad6ced7bb5357b5eaab320206f186f7b54c3471ae7fc18ac77b0c2dfbb34e4`; single `service vold` with a 3-line backslash-continued command followed by `class core`; no `seccomp_policy` |
| `/system/bin/vold` | 1,374,376 bytes; `DT_NEEDED` includes `liblog.so`, `libc.so`, `libc++.so`, `libfscrypt.so`, `libkeyutils.so` |

The audited `init` and `vold.rc` are byte-identical to the files extracted from
`system_full.dat`.

## Why replacing `init` with a static wrapper is safe

- AOSP 12 `first_stage_init.cpp` executes `/system/bin/init selinux_setup`
  before SELinux policy is loaded. The wrapper creates PID 1's session and
  `fscrypt` keyrings there, then execs `/system/bin/init.real`.
- AOSP 12 `selinux.cpp` re-execs `{"/system/bin/init", "second_stage"}` after
  loading policy. The wrapper runs again; it searches for the existing
  `fscrypt` keyring before calling `add_key`, so the second run reports
  `FSCRYPT_OK` instead of failing with `EEXIST`.
- `selinux_android_restorecon("/system/bin/init", 0)` is hardcoded. The mod
  labels both `init` and `init.real` `u:object_r:init_exec:s0`.
- Donor `init` is a bootstrap executable: its `PT_INTERP` is
  `/system/bin/bootstrap/linker64`. Bionic `fix_lib_paths()` inserts
  `/system/lib64/bootstrap` before `/system/lib64` only in the linker built
  without `__ANDROID_APEX__`, i.e. the linker named by `PT_INTERP`. Moving the
  file to `/system/bin/init.real` keeps the same interpreter, directory, and
  namespace selection; bionic has no basename special case for `init`.
- `GetExecutablePath()` is used only by `init`'s `subcontext` mode, not by the
  normal first/second-stage path.
- `service ueventd /system/bin/ueventd` follows the `ueventd -> init` symlink;
  the wrapper detects `argv[0]` basename `ueventd` and passes through without
  creating keyrings.

## `vold.rc` patcher

The real patcher and its 7 unit tests were run with portable Python 3.12.10:

```text
test_conflicting_preload_is_rejected ... ok
test_crlf_is_preserved ... ok
test_inserts_after_multiline_command ... ok
test_is_idempotent ... ok
test_missing_file_is_rejected ... ok
test_missing_service_is_rejected ... ok
test_single_line_service ... ok
Ran 7 tests ... OK
```

Patching the actual donor `vold.rc` inserts exactly one line before
`class core`:

```text
    setenv LD_PRELOAD /system/lib64/liba115f_fscrypt_shim.so
```

A second run reports `already patched` and leaves the file unchanged.

## Remaining unverified assumptions

- Runtime `LD_PRELOAD` handling by Samsung `vold` (`AT_SECURE=0`, default
  linker namespace, `ioctl` interposition).
- Runtime keyring inheritance and SELinux key permissions for the pre-policy
  keyrings (labeled in the kernel domain before policy load).
- Whether the built ROM actually boots to the framework. No ROM build or device
  test exists yet.
