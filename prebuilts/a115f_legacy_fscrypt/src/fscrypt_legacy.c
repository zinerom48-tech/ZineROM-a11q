/*
 * A115F legacy fscrypt bridge - pure legacy key helpers.
 *
 * No libc calls and no arch-specific code live here so the same object can
 * be linked into the freestanding /system/bin/init wrapper, the vold
 * LD_PRELOAD shim, and a host unit test.
 */

#include "fscrypt_legacy.h"

static uint32_t a115f_read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void a115f_legacy_key_payload(const uint8_t raw[A115F_FSCRYPT_KEY_SIZE],
                              struct a115f_fscrypt_key *out) {
    if (out == NULL) {
        return;
    }
    out->mode = 0;
    out->size = A115F_FSCRYPT_KEY_SIZE;
    for (size_t i = 0; i < A115F_FSCRYPT_KEY_SIZE; i++) {
        out->raw[i] = (raw != NULL) ? raw[i] : 0;
    }
}

void a115f_legacy_key_name(const char *prefix,
                           const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE], char *out) {
    static const char hex[] = "0123456789abcdef";
    size_t pos = 0;

    if (out == NULL) {
        return;
    }
    if (prefix != NULL) {
        while (prefix[pos] != '\0' && pos < 16) {
            out[pos] = prefix[pos];
            pos++;
        }
    }
    out[pos++] = ':';
    for (size_t i = 0; i < A115F_FSCRYPT_DESCRIPTOR_SIZE; i++) {
        uint8_t b = (descriptor != NULL) ? descriptor[i] : 0;
        out[pos++] = hex[(b >> 4) & 0x0f];
        out[pos++] = hex[b & 0x0f];
    }
    out[pos] = '\0';
}

static long a115f_find_fscrypt_keyring(const struct a115f_key_ops *ops) {
    if (ops == NULL || ops->keyctl == NULL) {
        return -A115F_EINVAL;
    }
    return ops->keyctl(A115F_KEYCTL_SEARCH, (uintptr_t)(long)A115F_KEY_SPEC_SESSION_KEYRING,
                       (uintptr_t) "keyring",
                       (uintptr_t) A115F_FSCRYPT_KEYRING_NAME, 0);
}

int a115f_legacy_install(const struct a115f_key_ops *ops,
                         const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE],
                         const uint8_t raw[A115F_FSCRYPT_KEY_SIZE]) {
    static const char *const prefixes[] = {"ext4", "f2fs", "fscrypt"};
    struct a115f_fscrypt_key payload;
    long ring;

    if (ops == NULL || ops->keyctl == NULL || ops->add_key == NULL || descriptor == NULL ||
        raw == NULL) {
        return -A115F_EINVAL;
    }

    ring = a115f_find_fscrypt_keyring(ops);
    if (ring == -A115F_ENOKEY) {
        /* The pre-policy init wrapper normally creates the keyring. If it did
         * not run (or was blocked), create it lazily in vold's session so at
         * least vold's own SET_POLICY path can install and find the keys. */
        ring = ops->add_key("keyring", A115F_FSCRYPT_KEYRING_NAME, NULL, 0,
                            A115F_KEY_SPEC_SESSION_KEYRING);
    }
    if (ring < 0) {
        return (int)ring;
    }

    a115f_legacy_key_payload(raw, &payload);

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char name[32];
        long key_id;

        a115f_legacy_key_name(prefixes[i], descriptor, name);
        key_id = ops->add_key("logon", name, &payload, sizeof(payload), (int32_t)ring);
        if (key_id < 0) {
            return (int)key_id;
        }
    }
    return 0;
}

int a115f_legacy_evict(const struct a115f_key_ops *ops,
                       const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE]) {
    static const char *const prefixes[] = {"ext4", "f2fs", "fscrypt"};
    long ring;
    int result = 0;

    if (ops == NULL || ops->keyctl == NULL || descriptor == NULL) {
        return -A115F_EINVAL;
    }

    ring = a115f_find_fscrypt_keyring(ops);
    if (ring < 0) {
        return (int)ring;
    }

    /* AOSP evictKeyLegacy() tries every prefix and returns false if any
     * search or unlink failed. Do not stop at the first failure. */
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char name[32];
        long key_id;
        long unlink_result;

        a115f_legacy_key_name(prefixes[i], descriptor, name);
        key_id = ops->keyctl(A115F_KEYCTL_SEARCH, (uintptr_t)ring,
                             (uintptr_t) "logon",
                             (uintptr_t)name, 0);
        if (key_id < 0) {
            if (result == 0) {
                result = (int)key_id;
            }
            continue;
        }
        unlink_result = ops->keyctl(A115F_KEYCTL_UNLINK, (uintptr_t)key_id,
                                    (uintptr_t)ring, 0, 0);
        if (unlink_result < 0 && result == 0) {
            result = (int)unlink_result;
        }
    }
    return result;
}

int a115f_legacy_status(const struct a115f_key_ops *ops,
                        const uint8_t descriptor[A115F_FSCRYPT_DESCRIPTOR_SIZE], uint32_t *status,
                        uint32_t *status_flags, uint32_t *user_count) {
    static const char *const prefixes[] = {"ext4", "f2fs", "fscrypt"};
    int found = 0;
    long ring;

    if (status == NULL || status_flags == NULL || user_count == NULL) {
        return -A115F_EINVAL;
    }
    if (ops == NULL || ops->keyctl == NULL || descriptor == NULL) {
        return -A115F_EINVAL;
    }

    ring = a115f_find_fscrypt_keyring(ops);
    if (ring < 0) {
        *status = A115F_FSCRYPT_STATUS_ABSENT;
        *status_flags = 0;
        *user_count = 0;
        return 0;
    }

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char name[32];
        long key_id;

        a115f_legacy_key_name(prefixes[i], descriptor, name);
        key_id = ops->keyctl(A115F_KEYCTL_SEARCH, (uintptr_t)ring,
                             (uintptr_t) "logon",
                             (uintptr_t)name, 0);
        if (key_id >= 0) {
            found = 1;
        }
    }

    *status = found ? A115F_FSCRYPT_STATUS_PRESENT : A115F_FSCRYPT_STATUS_ABSENT;
    *status_flags = found ? A115F_FSCRYPT_STATUS_FLAG_ADDED_BY_SELF : 0;
    *user_count = found ? 1 : 0;
    return 0;
}

int a115f_add_arg_check(const struct a115f_fscrypt_add_key_arg *arg) {
    uint32_t type;

    if (arg == NULL) {
        /* This is the shape of AOSP's legacy-support probe: ADD with a NULL
         * argument. Donor vold does not perform that probe, but returning
         * ENOTTY here matches the kernel a legacy vold expects. */
        return -A115F_ENOTTY;
    }

    type = a115f_read_le32(arg->key_spec);
    if (type != A115F_FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR) {
        /* Type 2 (identifier) and the hardware-wrapped types need a kernel
         * that implements the modern keyring; this kernel does not. */
        return -A115F_EOPNOTSUPP;
    }
    if (arg->raw_size != A115F_FSCRYPT_KEY_SIZE) {
        return -A115F_EINVAL;
    }
    if (arg->key_id != 0) {
        return -A115F_EINVAL;
    }
    if (arg->flags != 0) {
        return -A115F_EOPNOTSUPP;
    }
    return 0;
}

int a115f_remove_arg_check(const struct a115f_fscrypt_remove_key_arg *arg) {
    uint32_t type;

    if (arg == NULL) {
        return -A115F_EINVAL;
    }
    type = a115f_read_le32(arg->key_spec);
    if (type != A115F_FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR) {
        return -A115F_EOPNOTSUPP;
    }
    return 0;
}

int a115f_status_arg_check(const struct a115f_fscrypt_get_key_status_arg *arg) {
    uint32_t type;

    if (arg == NULL) {
        return -A115F_EINVAL;
    }
    type = a115f_read_le32(arg->key_spec);
    if (type != A115F_FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR) {
        return -A115F_EOPNOTSUPP;
    }
    return 0;
}
