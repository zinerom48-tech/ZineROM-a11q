/*
 * Host tests for the pure legacy fscrypt helpers.
 *
 * These tests do not touch a device, a kernel, or SELinux. They pin the
 * UAPI offsets, the legacy key names/payload shape, the argument checks,
 * and the install/evict/status state machine against a fake keyring.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "fscrypt_legacy.h"

static int g_failures;

#define CHECK(cond)                                                                              \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                      \
            g_failures++;                                                                        \
        }                                                                                        \
    } while (0)

#define CHECK_EQ_INT(expected, actual)                                                           \
    do {                                                                                         \
        long e_ = (long)(expected);                                                              \
        long a_ = (long)(actual);                                                                \
        if (e_ != a_) {                                                                          \
            fprintf(stderr, "FAIL %s:%d: expected %ld, got %ld\n", __FILE__, __LINE__, e_, a_);  \
            g_failures++;                                                                        \
        }                                                                                        \
    } while (0)

struct fake_key {
    int present;
    char name[32];
    uint8_t payload[sizeof(struct a115f_fscrypt_key)];
};

#define FAKE_MAX_KEYS 8

static struct fake_key g_keys[FAKE_MAX_KEYS];
static int g_fscrypt_keyring = 1;

static int fake_find_name(const char *name) {
    for (int i = 0; i < FAKE_MAX_KEYS; i++) {
        if (g_keys[i].present && strcmp(g_keys[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static long fake_keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                        unsigned long arg5) {
    (void)arg5;
    if (option == A115F_KEYCTL_GET_KEYRING_ID) {
        return 7;
    }
    if (option == A115F_KEYCTL_SEARCH) {
        const char *type = (const char *)(uintptr_t)arg3;
        const char *description = (const char *)(uintptr_t)arg4;
        if (strcmp(type, "keyring") == 0) {
            if (strcmp(description, A115F_FSCRYPT_KEYRING_NAME) == 0) {
                return g_fscrypt_keyring ? 100 : -A115F_ENOKEY;
            }
            return -A115F_ENOKEY;
        }
        if (strcmp(type, "logon") == 0) {
            int index = fake_find_name(description);
            return (index >= 0) ? (index + 1) : -A115F_ENOKEY;
        }
        return -A115F_ENOKEY;
    }
    if (option == A115F_KEYCTL_UNLINK) {
        long key_id = (long)arg2;
        long ring = (long)arg3;
        (void)ring;
        if (key_id < 1 || key_id > FAKE_MAX_KEYS) {
            return -A115F_ENOKEY;
        }
        if (!g_keys[key_id - 1].present) {
            return -A115F_ENOKEY;
        }
        g_keys[key_id - 1].present = 0;
        return 0;
    }
    return -A115F_EINVAL;
}

static long fake_add_key(const char *type, const char *description, const void *payload,
                         size_t plen, int32_t keyring) {
    (void)keyring;
    if (strcmp(type, "keyring") == 0) {
        if (strcmp(description, A115F_FSCRYPT_KEYRING_NAME) != 0) {
            return -A115F_EINVAL;
        }
        if (plen != 0 || payload != NULL) {
            return -A115F_EINVAL;
        }
        g_fscrypt_keyring = 1;
        return 100;
    }
    if (strcmp(type, "logon") != 0) {
        return -A115F_EINVAL;
    }
    if (plen != sizeof(struct a115f_fscrypt_key)) {
        return -A115F_EINVAL;
    }
    for (int i = 0; i < FAKE_MAX_KEYS; i++) {
        if (!g_keys[i].present) {
            g_keys[i].present = 1;
            snprintf(g_keys[i].name, sizeof(g_keys[i].name), "%s", description);
            memcpy(g_keys[i].payload, payload, plen);
            return 200 + i;
        }
    }
    return -A115F_ENOMEM;
}

static struct a115f_key_ops make_ops(void) {
    struct a115f_key_ops ops;
    ops.keyctl = fake_keyctl;
    ops.add_key = fake_add_key;
    return ops;
}

static void reset_fake(void) {
    memset(g_keys, 0, sizeof(g_keys));
    g_fscrypt_keyring = 1;
}

static void fill_add_arg(struct a115f_fscrypt_add_key_arg *arg, uint32_t type, uint32_t raw_size) {
    memset(arg, 0, sizeof(*arg));
    arg->key_spec[0] = (uint8_t)(type & 0xff);
    arg->key_spec[1] = (uint8_t)((type >> 8) & 0xff);
    arg->key_spec[2] = (uint8_t)((type >> 16) & 0xff);
    arg->key_spec[3] = (uint8_t)((type >> 24) & 0xff);
    arg->raw_size = raw_size;
    for (size_t i = 0; i < sizeof(arg->raw); i++) {
        arg->raw[i] = (uint8_t)(0xa0 + i);
    }
}

static void test_layouts(void) {
    CHECK_EQ_INT(72, sizeof(struct a115f_fscrypt_key));
    CHECK_EQ_INT(0, offsetof(struct a115f_fscrypt_key, mode));
    CHECK_EQ_INT(4, offsetof(struct a115f_fscrypt_key, raw));
    CHECK_EQ_INT(68, offsetof(struct a115f_fscrypt_key, size));

    CHECK_EQ_INT(144, sizeof(struct a115f_fscrypt_add_key_arg));
    CHECK_EQ_INT(40, offsetof(struct a115f_fscrypt_add_key_arg, raw_size));
    CHECK_EQ_INT(44, offsetof(struct a115f_fscrypt_add_key_arg, key_id));
    CHECK_EQ_INT(76, offsetof(struct a115f_fscrypt_add_key_arg, flags));
    CHECK_EQ_INT(80, offsetof(struct a115f_fscrypt_add_key_arg, raw));

    CHECK_EQ_INT(64, sizeof(struct a115f_fscrypt_remove_key_arg));
    CHECK_EQ_INT(40, offsetof(struct a115f_fscrypt_remove_key_arg, removal_status_flags));

    CHECK_EQ_INT(128, sizeof(struct a115f_fscrypt_get_key_status_arg));
    CHECK_EQ_INT(64, offsetof(struct a115f_fscrypt_get_key_status_arg, status));
    CHECK_EQ_INT(68, offsetof(struct a115f_fscrypt_get_key_status_arg, status_flags));
    CHECK_EQ_INT(72, offsetof(struct a115f_fscrypt_get_key_status_arg, user_count));
}

static void test_names_and_payload(void) {
    const uint8_t descriptor[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const uint8_t raw[64] = {0};
    char name[32];
    struct a115f_fscrypt_key key;

    a115f_legacy_key_name("ext4", descriptor, name);
    CHECK(strcmp(name, "ext4:0001020304050607") == 0);
    a115f_legacy_key_name("f2fs", descriptor, name);
    CHECK(strcmp(name, "f2fs:0001020304050607") == 0);
    a115f_legacy_key_name("fscrypt", descriptor, name);
    CHECK(strcmp(name, "fscrypt:0001020304050607") == 0);

    a115f_legacy_key_payload(raw, &key);
    CHECK_EQ_INT(0, key.mode);
    CHECK_EQ_INT(64, key.size);
    CHECK(key.raw[0] == 0 && key.raw[63] == 0);
}

static void test_arg_checks(void) {
    struct a115f_fscrypt_add_key_arg add;
    struct a115f_fscrypt_remove_key_arg remove;
    struct a115f_fscrypt_get_key_status_arg status;

    fill_add_arg(&add, 1, 64);
    CHECK_EQ_INT(0, a115f_add_arg_check(&add));
    CHECK_EQ_INT(-A115F_ENOTTY, a115f_add_arg_check(NULL));

    fill_add_arg(&add, 2, 64);
    CHECK_EQ_INT(-A115F_EOPNOTSUPP, a115f_add_arg_check(&add));

    fill_add_arg(&add, 1, 32);
    CHECK_EQ_INT(-A115F_EINVAL, a115f_add_arg_check(&add));

    fill_add_arg(&add, 1, 64);
    add.key_id = 1;
    CHECK_EQ_INT(-A115F_EINVAL, a115f_add_arg_check(&add));

    fill_add_arg(&add, 1, 64);
    add.flags = 1;
    CHECK_EQ_INT(-A115F_EOPNOTSUPP, a115f_add_arg_check(&add));

    memset(&remove, 0, sizeof(remove));
    remove.key_spec[0] = 1;
    CHECK_EQ_INT(0, a115f_remove_arg_check(&remove));
    remove.key_spec[0] = 2;
    CHECK_EQ_INT(-A115F_EOPNOTSUPP, a115f_remove_arg_check(&remove));
    CHECK_EQ_INT(-A115F_EINVAL, a115f_remove_arg_check(NULL));

    memset(&status, 0, sizeof(status));
    status.key_spec[0] = 1;
    CHECK_EQ_INT(0, a115f_status_arg_check(&status));
    status.key_spec[0] = 2;
    CHECK_EQ_INT(-A115F_EOPNOTSUPP, a115f_status_arg_check(&status));
    CHECK_EQ_INT(-A115F_EINVAL, a115f_status_arg_check(NULL));
}

static void test_install_evict_status(void) {
    const uint8_t descriptor[8] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67};
    const uint8_t raw[64] = {0};
    struct a115f_key_ops ops = make_ops();
    uint32_t status = 0;
    uint32_t status_flags = 0;
    uint32_t user_count = 0;

    reset_fake();
    CHECK_EQ_INT(0, a115f_legacy_install(&ops, descriptor, raw));
    CHECK_EQ_INT(3, g_keys[0].present + g_keys[1].present + g_keys[2].present);
    CHECK(strcmp(g_keys[0].name, "ext4:deadbeef01234567") == 0);
    CHECK(strcmp(g_keys[1].name, "f2fs:deadbeef01234567") == 0);
    CHECK(strcmp(g_keys[2].name, "fscrypt:deadbeef01234567") == 0);
    CHECK_EQ_INT(0, ((const struct a115f_fscrypt_key *)g_keys[0].payload)->mode);
    CHECK_EQ_INT(64, ((const struct a115f_fscrypt_key *)g_keys[0].payload)->size);

    CHECK_EQ_INT(0, a115f_legacy_status(&ops, descriptor, &status, &status_flags, &user_count));
    CHECK_EQ_INT(A115F_FSCRYPT_STATUS_PRESENT, status);
    CHECK_EQ_INT(A115F_FSCRYPT_STATUS_FLAG_ADDED_BY_SELF, status_flags);
    CHECK_EQ_INT(1, user_count);

    CHECK_EQ_INT(0, a115f_legacy_evict(&ops, descriptor));
    CHECK_EQ_INT(0, g_keys[0].present + g_keys[1].present + g_keys[2].present);

    CHECK_EQ_INT(0, a115f_legacy_status(&ops, descriptor, &status, &status_flags, &user_count));
    CHECK_EQ_INT(A115F_FSCRYPT_STATUS_ABSENT, status);
    CHECK_EQ_INT(0, status_flags);
    CHECK_EQ_INT(0, user_count);
}

static void test_evict_is_not_idempotent(void) {
    const uint8_t descriptor[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t raw[64] = {0};
    struct a115f_key_ops ops = make_ops();

    reset_fake();
    CHECK_EQ_INT(0, a115f_legacy_install(&ops, descriptor, raw));
    g_keys[1].present = 0; /* simulate a partially evicted keyring */
    CHECK_EQ_INT(-A115F_ENOKEY, a115f_legacy_evict(&ops, descriptor));
    CHECK_EQ_INT(0, g_keys[0].present);
    CHECK_EQ_INT(0, g_keys[2].present);
}

static void test_missing_keyring(void) {
    const uint8_t descriptor[8] = {0};
    const uint8_t raw[64] = {0};
    struct a115f_key_ops ops = make_ops();
    uint32_t status = 0;
    uint32_t status_flags = 0;
    uint32_t user_count = 0;

    reset_fake();
    g_fscrypt_keyring = 0;
    /* install creates the keyring lazily if the pre-policy wrapper did not. */
    CHECK_EQ_INT(0, a115f_legacy_install(&ops, descriptor, raw));
    CHECK_EQ_INT(1, g_fscrypt_keyring);
    CHECK_EQ_INT(3, g_keys[0].present + g_keys[1].present + g_keys[2].present);
    CHECK_EQ_INT(0, a115f_legacy_status(&ops, descriptor, &status, &status_flags, &user_count));
    CHECK_EQ_INT(A115F_FSCRYPT_STATUS_PRESENT, status);
}

static void test_evict_missing_keyring(void) {
    const uint8_t descriptor[8] = {0};
    struct a115f_key_ops ops = make_ops();
    uint32_t status = 0;
    uint32_t status_flags = 0;
    uint32_t user_count = 0;

    reset_fake();
    g_fscrypt_keyring = 0;
    CHECK_EQ_INT(-A115F_ENOKEY, a115f_legacy_evict(&ops, descriptor));
    CHECK_EQ_INT(0, a115f_legacy_status(&ops, descriptor, &status, &status_flags, &user_count));
    CHECK_EQ_INT(A115F_FSCRYPT_STATUS_ABSENT, status);
}

int main(void) {
    test_layouts();
    test_names_and_payload();
    test_arg_checks();
    test_install_evict_status();
    test_evict_is_not_idempotent();
    test_missing_keyring();
    test_evict_missing_keyring();

    if (g_failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", g_failures);
        return 1;
    }
    printf("all legacy fscrypt host tests passed\n");
    return 0;
}
