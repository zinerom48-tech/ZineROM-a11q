/*
 * A115F legacy fscrypt bridge - shared declarations.
 *
 * The Galaxy A11 SM-A115F kernel is 4.9.227 and only implements the legacy
 * fscrypt key interface: v1 encryption keys are installed as "logon" keys
 * named ext4:<hex>, f2fs:<hex> and fscrypt:<hex> inside a "fscrypt" keyring
 * that is nested under the process session keyring. The kernel's fscrypt
 * SET_POLICY path resolves them with request_key().
 *
 * The One UI 7 donor (Galaxy A05s) vold only knows the modern
 * FS_IOC_ADD/REMOVE/GET_STATUS ioctls and was built without the userspace
 * legacy fallback. This file describes the legacy payload and the helpers
 * used by both the pre-policy /system/bin/init wrapper and the vold shim.
 *
 * The layouts below are copied from the Android 15 uapi header:
 *   struct fscrypt_key_specifier         40 bytes (type at 0, descriptor at 8)
 *   struct fscrypt_add_key_arg           80-byte header, raw[] at 80
 *   struct fscrypt_remove_key_arg        64 bytes
 *   struct fscrypt_get_key_status_arg   128 bytes
 */

#ifndef A115F_FSCRYPT_LEGACY_H
#define A115F_FSCRYPT_LEGACY_H

#include <stddef.h>
#include <stdint.h>

#define A115F_FSCRYPT_KEY_SIZE 64U
#define A115F_FSCRYPT_DESCRIPTOR_SIZE 8U
#define A115F_FSCRYPT_KEY_SPECIFIER_SIZE 40U
#define A115F_FSCRYPT_ADD_KEY_HEADER_SIZE 80U
#define A115F_FSCRYPT_KEY_SPEC_DESCRIPTOR_OFFSET 8U
#define A115F_FSCRYPT_KEYRING_NAME "fscrypt"

/* struct fscrypt_key_specifier.type */
#define A115F_FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR 1U
#define A115F_FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER 2U

/* fs/crypto/keyring.c / fscrypt.h status values */
#define A115F_FSCRYPT_STATUS_ABSENT 1U
#define A115F_FSCRYPT_STATUS_PRESENT 2U
#define A115F_FSCRYPT_STATUS_INCOMPLETELY_REMOVED 3U
#define A115F_FSCRYPT_STATUS_FLAG_ADDED_BY_SELF 1U

#define A115F_FSCRYPT_REMOVAL_FLAG_FILES_BUSY 1U
#define A115F_FSCRYPT_REMOVAL_FLAG_OTHER_USERS 2U

/* ioctl request encoding: _IOWR('f', 23/24/26, struct ...) */
#define A115F_FS_IOC_ADD_ENCRYPTION_KEY 0xC0506617UL
#define A115F_FS_IOC_REMOVE_ENCRYPTION_KEY 0xC0406618UL
#define A115F_FS_IOC_GET_ENCRYPTION_KEY_STATUS 0xC080661AU

/* keyctl options and special keyring ids (Linux keyctl(2)). */
#define A115F_KEYCTL_GET_KEYRING_ID 0
#define A115F_KEYCTL_UNLINK 9
#define A115F_KEYCTL_SEARCH 10
#define A115F_KEY_SPEC_SESSION_KEYRING (-3)
#define A115F_KEY_SPEC_USER_SESSION_KEYRING (-5)

/* errno values used by the bridge (asm-generic/errno-base.h, errno.h). */
#define A115F_EPERM 1
#define A115F_ENOENT 2
#define A115F_EIO 5
#define A115F_ENOMEM 12
#define A115F_EFAULT 14
#define A115F_EINVAL 22
#define A115F_ENOTTY 25
#define A115F_EOPNOTSUPP 95
#define A115F_ENOKEY 126
#define A115F_EKEYREJECTED 129

/*
 * struct fscrypt_key (the legacy key payload). Size is exactly 72 bytes:
 * mode at 0, raw[64] at 4, size at 68. The compiler inserts no padding
 * because every field is naturally aligned.
 */
struct a115f_fscrypt_key {
    uint32_t mode;
    uint8_t raw[A115F_FSCRYPT_KEY_SIZE];
    uint32_t size;
};

/*
 * First 144 bytes of struct fscrypt_add_key_arg. The real struct has a
 * flexible raw[] array; vold allocates sizeof(header) + raw_size, which is
 * 80 + 64 == 144 for a v1 descriptor key. We only ever read the first 64
 * payload bytes, so this fixed-size view is safe.
 */
struct a115f_fscrypt_add_key_arg {
    uint8_t key_spec[A115F_FSCRYPT_KEY_SPECIFIER_SIZE]; /* 0 */
    uint32_t raw_size;                                  /* 40 */
    uint32_t key_id;                                    /* 44 */
    uint32_t reserved[7];                               /* 48 */
    uint32_t flags;                                     /* 76 */
    uint8_t raw[A115F_FSCRYPT_KEY_SIZE];                /* 80 */
};

struct a115f_fscrypt_remove_key_arg {
    uint8_t key_spec[A115F_FSCRYPT_KEY_SPECIFIER_SIZE]; /* 0 */
    uint32_t removal_status_flags;                      /* 40 */
    uint32_t reserved[5];                               /* 44 */
};

struct a115f_fscrypt_get_key_status_arg {
    uint8_t key_spec[A115F_FSCRYPT_KEY_SPECIFIER_SIZE]; /* 0 */
    uint32_t reserved[6];                               /* 40 */
    uint32_t status;                                    /* 64 */
    uint32_t status_flags;                              /* 68 */
    uint32_t user_count;                                /* 72 */
    uint32_t out_reserved[13];                          /* 76 */
};

/*
 * Syscall ABI used by the pure helpers. The callbacks return the raw
 * Linux syscall convention (>= 0 or -errno), not libc errno semantics.
 *
 * Arguments are uintptr_t rather than unsigned long: on aarch64/Linux the
 * two are identical, but uintptr_t stays pointer-sized on LLP64 hosts so
 * the unit tests can pass real string pointers through the fake callbacks.
 */
typedef long (*a115f_keyctl_fn)(int option, uintptr_t arg2, uintptr_t arg3,
                                uintptr_t arg4, uintptr_t arg5);
typedef long (*a115f_add_key_fn)(const char *type, const char *description, const void *payload,
                                 size_t plen, int32_t keyring);

struct a115f_key_ops {
    a115f_keyctl_fn keyctl;
    a115f_add_key_fn add_key;
};

/* Fill the 72-byte legacy payload: mode 0, raw key, size 64. */
void a115f_legacy_key_payload(const uint8_t raw[A115F_FSCRYPT_KEY_SIZE],
                              struct a115f_fscrypt_key *out);

/*
 * Build "<prefix>:<16 lowercase hex chars>" from an 8-byte v1 descriptor.
 * `out` must have room for at least 32 bytes.
 */
void a115f_legacy_key_name(const char *prefix,
                           const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE], char *out);

/*
 * Install all three legacy keys. Returns 0 on success or -errno. Like AOSP
 * installKeyLegacy(), the first add_key() failure aborts the sequence.
 */
int a115f_legacy_install(const struct a115f_key_ops *ops,
                         const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE],
                         const uint8_t raw[A115F_FSCRYPT_KEY_SIZE]);

/*
 * Remove all three legacy keys. Like AOSP evictKeyLegacy(), this is NOT
 * idempotent: every name is searched and unlinked, and a missing key or a
 * failed unlink makes the call fail. Returns 0 only if all three succeeded.
 */
int a115f_legacy_evict(const struct a115f_key_ops *ops,
                       const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE]);

/*
 * Report whether any of the three legacy keys exists. A missing fscrypt
 * keyring is reported as ABSENT rather than as an error, so vold's
 * waitForBusyFiles() sees a stable "nothing to evict" answer.
 */
int a115f_legacy_status(const struct a115f_key_ops *ops,
                        const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE], uint32_t *status,
                        uint32_t *status_flags, uint32_t *user_count);

/* Argument validation, no syscalls; used by the shim and host tests. */
int a115f_add_arg_check(const struct a115f_fscrypt_add_key_arg *arg);
int a115f_remove_arg_check(const struct a115f_fscrypt_remove_key_arg *arg);
int a115f_status_arg_check(const struct a115f_fscrypt_get_key_status_arg *arg);

#endif /* A115F_FSCRYPT_LEGACY_H */
