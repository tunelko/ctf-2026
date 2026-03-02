// intercept.c - LD_PRELOAD to intercept memfd_create write() calls
// Dumps the stage2 binary data written to memfd
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdint.h>

static int memfd = -1;

// Intercept syscall to catch memfd_create (319 = 0x13f)
long syscall(long number, ...) {
    long (*real_syscall)(long, ...) = dlsym(RTLD_NEXT, "syscall");

    if (number == 319) { // SYS_memfd_create
        __builtin_va_list ap;
        __builtin_va_start(ap, number);
        const char *name = __builtin_va_arg(ap, const char *);
        unsigned int flags = __builtin_va_arg(ap, unsigned int);
        __builtin_va_end(ap);

        long fd = real_syscall(number, name, flags);
        memfd = (int)fd;
        fprintf(stderr, "[INTERCEPT] memfd_create('%s', %u) = %ld\n", name, flags, fd);
        return fd;
    }

    // Forward other syscalls
    __builtin_va_list ap;
    __builtin_va_start(ap, number);
    long a1 = __builtin_va_arg(ap, long);
    long a2 = __builtin_va_arg(ap, long);
    long a3 = __builtin_va_arg(ap, long);
    __builtin_va_end(ap);
    return real_syscall(number, a1, a2, a3);
}

// Intercept write to dump stage2 data
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");

    if (fd == memfd && memfd != -1) {
        fprintf(stderr, "[INTERCEPT] write(memfd=%d, buf, %zu) - dumping to stage2.so\n", fd, count);
        FILE *out = fopen("stage2.so", "ab");
        if (out) {
            fwrite(buf, 1, count, out);
            fclose(out);
        }
    }

    return real_write(fd, buf, count);
}
