/*
 * A115F legacy fscrypt bridge - pre-policy /system/bin/init wrapper.
 *
 * The A11 4.9.227 kernel implements only the legacy fscrypt keyring, while
 * the One UI 7 donor init/vold have no legacy fallback.  The donor init also
 * removed AOSP's FscryptInstallKeyring() call, so PID 1 never creates the
 * session keyring that all Android services inherit.
 *
 * This wrapper is installed as /system/bin/init.  The real donor init is
 * moved to /system/bin/init.real.  The wrapper runs in the same PID 1 process
 * and creates the session keyring plus the named "fscrypt" keyring before it
 * execs the real init (for the "selinux_setup" stage this is before SELinux
 * policy is loaded).  The keyrings are inherited by every service, so vold
 * can install keys that all processes can find via request_key().
 *
 * /system/bin/ueventd is a symlink to /system/bin/init.  The wrapper
 * deliberately preserves argv[0] and skips keyring setup when invoked as
 * ueventd, so the real init's basename-based ueventd mode is unchanged.
 *
 * Failure must never turn a boot into a panic: log and exec the real init
 * anyway.  The wrapper is statically linked and uses raw syscalls only, so it
 * has no libc or dynamic-linker dependency at the point where init starts.
 */

#include "a115f_syscalls.h"
#include "fscrypt_legacy.h"

#define A115F_WRAPPER_TAG "A115F_FSCRYPT_WRAPPER: "
#define A115F_INIT_REAL "/system/bin/init.real"

static size_t a115f_strlen(const char *s) {
    size_t n = 0;
    if (s == NULL) {
        return 0;
    }
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

static int a115f_streq(const char *a, const char *b) {
    size_t i = 0;
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) {
            return 0;
        }
        i++;
    }
    return a[i] == '\0' && b[i] == '\0';
}

static int a115f_basename_is_ueventd(const char *path) {
    const char *base = path;
    if (path == NULL) {
        return 0;
    }
    for (const char *p = path; *p != '\0'; p++) {
        if (*p == '/') {
            base = p + 1;
        }
    }
    return a115f_streq(base, "ueventd");
}

static void a115f_append(char *buf, size_t capacity, size_t *pos, const char *s) {
    size_t n = a115f_strlen(s);
    for (size_t i = 0; i < n && *pos + 1 < capacity; i++) {
        buf[(*pos)++] = s[i];
    }
    buf[*pos] = '\0';
}

static void a115f_append_long(char *buf, size_t capacity, size_t *pos, long value) {
    char digits[24];
    int n = 0;
    unsigned long v;

    if (value < 0) {
        a115f_append(buf, capacity, pos, "-");
        v = (unsigned long)(-(value + 1)) + 1UL;
    } else {
        v = (unsigned long)value;
    }
    if (v == 0) {
        digits[n++] = '0';
    } else {
        while (v != 0 && n < (int)sizeof(digits)) {
            digits[n++] = (char)('0' + (v % 10UL));
            v /= 10UL;
        }
    }
    while (n > 0) {
        char one[2];
        one[0] = digits[--n];
        one[1] = '\0';
        a115f_append(buf, capacity, pos, one);
    }
}

static void a115f_write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long n = a115f_sys_write(fd, buf + off, len - off);
        if (n <= 0) {
            return;
        }
        off += (size_t)n;
    }
}

/*
 * Best-effort early logging. /dev may not be populated yet, so try kmsg,
 * then console, and finally inherited stderr. Creating the kmsg node is
 * safe because init runs with full privileges and policy is not loaded yet.
 */
static void a115f_klog(const char *message, long value, int with_value) {
    char buf[192];
    size_t pos = 0;
    long fd;

    a115f_append(buf, sizeof(buf), &pos, A115F_WRAPPER_TAG);
    a115f_append(buf, sizeof(buf), &pos, message);
    if (with_value) {
        a115f_append(buf, sizeof(buf), &pos, " ");
        a115f_append_long(buf, sizeof(buf), &pos, value);
    }
    a115f_append(buf, sizeof(buf), &pos, "\n");

    fd = a115f_sys_openat(A115F_AT_FDCWD, "/dev/kmsg", A115F_O_WRONLY | A115F_O_CLOEXEC, 0);
    if (fd < 0) {
        a115f_sys_mkdirat(A115F_AT_FDCWD, "/dev", 0755);
        a115f_sys_mknodat(A115F_AT_FDCWD, "/dev/kmsg", A115F_S_IFCHR | 0600, A115F_DEV_KMSG);
        fd = a115f_sys_openat(A115F_AT_FDCWD, "/dev/kmsg", A115F_O_WRONLY | A115F_O_CLOEXEC, 0);
    }
    if (fd >= 0) {
        a115f_write_all((int)fd, buf, pos);
        a115f_sys_close((int)fd);
        return;
    }

    fd = a115f_sys_openat(A115F_AT_FDCWD, "/dev/console", A115F_O_WRONLY | A115F_O_CLOEXEC, 0);
    if (fd >= 0) {
        a115f_write_all((int)fd, buf, pos);
        a115f_sys_close((int)fd);
        return;
    }

    a115f_write_all(2, buf, pos);
}

static void a115f_create_keyrings(void) {
    long session;
    long fscrypt;

    session = a115f_sys_keyctl(A115F_KEYCTL_GET_KEYRING_ID,
                               (unsigned long)(long)A115F_KEY_SPEC_SESSION_KEYRING, 1, 0, 0);
    if (session < 0) {
        a115f_klog("SESSION_FAIL", -session, 1);
    } else {
        a115f_klog("SESSION_OK", session, 1);
    }

    fscrypt = a115f_sys_keyctl(A115F_KEYCTL_SEARCH,
                               (unsigned long)(long)A115F_KEY_SPEC_SESSION_KEYRING,
                               (unsigned long)(uintptr_t) "keyring",
                               (unsigned long)(uintptr_t) A115F_FSCRYPT_KEYRING_NAME, 0);
    if (fscrypt < 0) {
        /* Match AOSP FscryptInstallKeyring(): search first, create only if
         * absent. KEY_SPEC_SESSION_KEYRING also creates the session keyring
         * if the earlier GET_KEYRING_ID call failed for any reason. */
        fscrypt = a115f_sys_add_key("keyring", A115F_FSCRYPT_KEYRING_NAME, NULL, 0,
                                    A115F_KEY_SPEC_SESSION_KEYRING);
    }
    if (fscrypt < 0) {
        a115f_klog("FSCRYPT_FAIL", -fscrypt, 1);
    } else {
        a115f_klog("FSCRYPT_OK", fscrypt, 1);
    }
}

__attribute__((used)) void a115f_c_main(unsigned long *sp) {
    unsigned long argc;
    char **argv;
    char **envp;
    int passthrough = 0;

    if (sp == NULL) {
        argc = 0;
        argv = NULL;
        envp = NULL;
    } else {
        argc = sp[0];
        argv = (char **)(sp + 1);
        envp = (argc > 0) ? (argv + argc + 1) : (argv + 1);
    }

    a115f_klog("ENTER", 0, 0);

    if (argv != NULL && argc > 0 && a115f_basename_is_ueventd(argv[0])) {
        /* ueventd is a child process, not PID 1. It must not create keyrings
         * and must reach the real init's ueventd mode with argv[0] intact. */
        a115f_klog("UEVENTD_PASSTHROUGH", 0, 0);
        passthrough = 1;
    }

    if (!passthrough) {
        a115f_create_keyrings();
    }

    /* Preserve argv[0] (ueventd mode is selected by its basename). Only
     * synthesize argv when the kernel started us with an empty vector. */
    if (argv == NULL || argc == 0) {
        static char *fallback_argv[] = {(char *)A115F_INIT_REAL, NULL};
        argv = fallback_argv;
        envp = NULL;
    }

    a115f_klog("EXEC " A115F_INIT_REAL, 0, 0);
    {
        long result = a115f_sys_execve(A115F_INIT_REAL, argv, envp);
        a115f_klog("EXEC_FAIL", -result, 1);
    }

    a115f_syscall1(A115F_SYS_exit, 127);
    __builtin_unreachable();
}

__attribute__((naked, noreturn, used)) void _start(void) {
    __asm__ volatile(
        "mov x0, sp\n"
        "bl a115f_c_main\n"
        "mov x0, #127\n"
        "mov x8, #93\n"
        "svc #0\n");
}
