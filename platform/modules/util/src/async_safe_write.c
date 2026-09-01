/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Async-signal-safe fd writers. See async_safe_write.h. These are the exact
 * primitives the fatal-signal crash handler has always used, lifted verbatim
 * so the live self-backtrace handler reuses one audited copy. Do not add
 * malloc/stdio/locks here — callers depend on strict async-signal-safety. */

#include "util/async_safe_write.h"

#include <string.h>
#include <unistd.h>

int asw_write_uint(int fd, unsigned long v)
{
    char buf[32];
    int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    while (v > 0) { buf[n++] = (char)('0' + (v % 10)); v /= 10; }
    /* reverse */
    for (int i = 0; i < n / 2; i++) {
        char t = buf[i]; buf[i] = buf[n - 1 - i]; buf[n - 1 - i] = t;
    }
    return (int)write(fd, buf, (size_t)n);
}

int asw_write_hex(int fd, unsigned long v)
{
    static const char H[] = "0123456789abcdef";
    char buf[18];
    int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    while (v > 0) { buf[n++] = H[v & 0xF]; v >>= 4; }
    for (int i = 0; i < n / 2; i++) {
        char t = buf[i]; buf[i] = buf[n - 1 - i]; buf[n - 1 - i] = t;
    }
    return (int)write(fd, buf, (size_t)n);
}

int asw_write_str(int fd, const char *s)
{
    if (!s) return 0;
    return (int)write(fd, s, strlen(s));
}
