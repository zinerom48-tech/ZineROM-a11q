/*
 * A115F legacy fscrypt bridge - raw aarch64 syscall helpers.
 *
 * This header is compiled only for aarch64. It deliberately has no libc
 * dependency so the same helpers can be linked into:
 *   - the freestanding /init wrapper (no dynamic linker at all), and
 *   - the vold LD_PRELOAD shim (libc is present, but we do not call it).
 *
 * Raw syscalls return the kernel convention: a non-negative value on
 * success, or -errno on failure. Callers must not use the libc `errno`
 * convention here.
 */

#ifndef A115F_SYSCALLS_H
#define A115F_SYSCALLS_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__aarch64__)
#error "a115f_syscalls.h is only for aarch64"
#endif

/* Linux arm64 syscall numbers (asm-generic/unistd.h). */
#define A115F_SYS_ioctl 29
#define A115F_SYS_mknodat 33
#define A115F_SYS_mkdirat 34
#define A115F_SYS_openat 56
#define A115F_SYS_close 57
#define A115F_SYS_write 64
#define A115F_SYS_exit 93
#define A115F_SYS_add_key 217
#define A115F_SYS_keyctl 219
#define A115F_SYS_execve 221

#define A115F_AT_FDCWD (-100)
#define A115F_O_RDONLY 0
#define A115F_O_WRONLY 1
#define A115F_O_CLOEXEC 02000000

#define A115F_S_IFCHR 0020000
#define A115F_S_IFDIR 0040000

/* Linux generic makedev() for small major/minor values. */
#define A115F_MAKEDEV(major, minor) \
    ((((uint32_t)(major) & 0xfffU) << 8) | ((uint32_t)(minor) & 0xffU))

#define A115F_DEV_KMSG A115F_MAKEDEV(1, 11)
#define A115F_DEV_CONSOLE A115F_MAKEDEV(5, 1)

static inline long a115f_syscall1(long n, long a0) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long a115f_syscall3(long n, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2)
                     : "memory");
    return x0;
}

static inline long a115f_syscall5(long n, long a0, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "memory");
    return x0;
}

static inline long a115f_sys_openat(int dirfd, const char *path, int flags, int mode) {
    return a115f_syscall5(A115F_SYS_openat, (long)dirfd, (long)(uintptr_t)path, (long)flags,
                          (long)mode, 0);
}

static inline long a115f_sys_close(int fd) {
    return a115f_syscall1(A115F_SYS_close, (long)fd);
}

static inline long a115f_sys_write(int fd, const void *buf, size_t len) {
    return a115f_syscall3(A115F_SYS_write, (long)fd, (long)(uintptr_t)buf, (long)len);
}

static inline long a115f_sys_mkdirat(int dirfd, const char *path, int mode) {
    return a115f_syscall3(A115F_SYS_mkdirat, (long)dirfd, (long)(uintptr_t)path, (long)mode);
}

static inline long a115f_sys_mknodat(int dirfd, const char *path, int mode, uint32_t dev) {
    return a115f_syscall5(A115F_SYS_mknodat, (long)dirfd, (long)(uintptr_t)path, (long)mode,
                          (long)dev, 0);
}

static inline long a115f_sys_execve(const char *path, char *const argv[], char *const envp[]) {
    return a115f_syscall3(A115F_SYS_execve, (long)(uintptr_t)path, (long)(uintptr_t)argv,
                          (long)(uintptr_t)envp);
}

static inline long a115f_sys_ioctl(int fd, unsigned long request, void *arg) {
    return a115f_syscall3(A115F_SYS_ioctl, (long)fd, (long)request, (long)(uintptr_t)arg);
}

static inline long a115f_sys_add_key(const char *type, const char *description, const void *payload,
                                     size_t plen, int32_t keyring) {
    return a115f_syscall5(A115F_SYS_add_key, (long)(uintptr_t)type, (long)(uintptr_t)description,
                          (long)(uintptr_t)payload, (long)plen, (long)keyring);
}

static inline long a115f_sys_keyctl(int option, unsigned long arg2, unsigned long arg3,
                                    unsigned long arg4, unsigned long arg5) {
    return a115f_syscall5(A115F_SYS_keyctl, (long)option, (long)arg2, (long)arg3, (long)arg4,
                          (long)arg5);
}

#endif /* A115F_SYSCALLS_H */
