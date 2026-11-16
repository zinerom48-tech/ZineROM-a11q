/*
 * A115F legacy fscrypt bridge - vold ioctl shim (LD_PRELOAD).
 *
 * Donor vold (One UI 7, Galaxy A05s) only issues the modern fscrypt key
 * ioctls. The A11 4.9 kernel returns ENOTTY for all three. This shim calls
 * the real ioctl first and translates only on ENOTTY:
 *
 *   FS_IOC_ADD_ENCRYPTION_KEY        -> add_key("logon", ext4/f2fs/fscrypt:<hex>)
 *   FS_IOC_REMOVE_ENCRYPTION_KEY     -> keyctl(SEARCH)+keyctl(UNLINK) all three
 *   FS_IOC_GET_ENCRYPTION_KEY_STATUS -> report PRESENT/ABSENT
 *
 * The keys are installed into the "fscrypt" keyring that the pre-policy
 * /init wrapper created under PID 1's session keyring. vold inherits that
 * session keyring, so the kernel's request_key() lookup finds the keys.
 *
 * This object is compiled freestanding: it imports only __errno and
 * __android_log_print, both already loaded in vold's process.
 */

#include <stdarg.h>

#include "a115f_syscalls.h"
#include "fscrypt_legacy.h"

extern int *__errno(void);
extern int __android_log_print(int prio, const char *tag, const char *fmt, ...);

#define A115F_SHIM_TAG "A115F_FSCRYPT"
#define A115F_ANDROID_LOG_INFO 4

static void a115f_shim_log(const char *message) {
    __android_log_print(A115F_ANDROID_LOG_INFO, A115F_SHIM_TAG, "%s", message);
}

static void a115f_shim_log_errno(const char *message, int error) {
    __android_log_print(A115F_ANDROID_LOG_INFO, A115F_SHIM_TAG, "%s %d", message, error);
}

__attribute__((constructor)) static void a115f_shim_loaded(void) {
    a115f_shim_log("SHIM_LOADED");
}

static const struct a115f_key_ops a115f_ops = {
        .keyctl = a115f_sys_keyctl,
        .add_key = a115f_sys_add_key,
};

static int a115f_translate_add(const struct a115f_fscrypt_add_key_arg *arg) {
    int check = a115f_add_arg_check(arg);
    int result;

    if (check == -A115F_ENOTTY) {
        /* Defensive legacy-support probe shape; donor vold does not use it. */
        a115f_shim_log("ADD_PROBE_ENOTTY");
        return check;
    }
    if (check < 0) {
        a115f_shim_log_errno("ADD_UNSUPPORTED", -check);
        return check;
    }

    result = a115f_legacy_install(&a115f_ops, arg->key_spec + A115F_FSCRYPT_KEY_SPEC_DESCRIPTOR_OFFSET,
                                  arg->raw);
    if (result < 0) {
        a115f_shim_log_errno("ADD_FAIL", -result);
    } else {
        a115f_shim_log("ADD_OK");
    }
    return result;
}

static int a115f_translate_remove(struct a115f_fscrypt_remove_key_arg *arg) {
    int check = a115f_remove_arg_check(arg);
    int result;

    if (check < 0) {
        a115f_shim_log_errno("REMOVE_UNSUPPORTED", -check);
        return check;
    }

    result = a115f_legacy_evict(&a115f_ops, arg->key_spec + A115F_FSCRYPT_KEY_SPEC_DESCRIPTOR_OFFSET);
    if (result < 0) {
        a115f_shim_log_errno("REMOVE_FAIL", -result);
    } else {
        arg->removal_status_flags = 0;
        a115f_shim_log("REMOVE_OK");
    }
    return result;
}

static int a115f_translate_status(struct a115f_fscrypt_get_key_status_arg *arg) {
    uint32_t status = A115F_FSCRYPT_STATUS_ABSENT;
    uint32_t status_flags = 0;
    uint32_t user_count = 0;
    int check = a115f_status_arg_check(arg);
    int result;

    if (check < 0) {
        a115f_shim_log_errno("STATUS_UNSUPPORTED", -check);
        return check;
    }

    result = a115f_legacy_status(&a115f_ops,
                                 arg->key_spec + A115F_FSCRYPT_KEY_SPEC_DESCRIPTOR_OFFSET, &status,
                                 &status_flags, &user_count);
    if (result < 0) {
        a115f_shim_log_errno("STATUS_FAIL", -result);
        return result;
    }

    arg->status = status;
    arg->status_flags = status_flags;
    arg->user_count = user_count;
    a115f_shim_log(status == A115F_FSCRYPT_STATUS_PRESENT ? "STATUS_PRESENT" : "STATUS_ABSENT");
    return 0;
}

static int a115f_translate(unsigned long request, void *arg) {
    if (request == A115F_FS_IOC_ADD_ENCRYPTION_KEY) {
        return a115f_translate_add((const struct a115f_fscrypt_add_key_arg *)arg);
    }
    if (request == A115F_FS_IOC_REMOVE_ENCRYPTION_KEY) {
        return a115f_translate_remove((struct a115f_fscrypt_remove_key_arg *)arg);
    }
    if (request == A115F_FS_IOC_GET_ENCRYPTION_KEY_STATUS) {
        return a115f_translate_status((struct a115f_fscrypt_get_key_status_arg *)arg);
    }
    return -A115F_EINVAL;
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    void *arg;
    long result;
    int error;

    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);

    /* Always let the kernel decide first. This keeps every unrelated ioctl
     * on the exact original path and avoids guessing which requests are
     * filesystem-specific. */
    result = a115f_sys_ioctl(fd, request, arg);
    if (result >= 0) {
        return (int)result;
    }

    error = (int)-result;
    if (error != A115F_ENOTTY) {
        *__errno() = error;
        return -1;
    }

    if (request == A115F_FS_IOC_ADD_ENCRYPTION_KEY ||
        request == A115F_FS_IOC_REMOVE_ENCRYPTION_KEY ||
        request == A115F_FS_IOC_GET_ENCRYPTION_KEY_STATUS) {
        int translated = a115f_translate(request, arg);
        if (translated < 0) {
            *__errno() = -translated;
            return -1;
        }
        return 0;
    }

    /* Not one of ours: preserve the original ENOTTY result. */
    *__errno() = error;
    return -1;
}
