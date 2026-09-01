/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one full-write loop. Contract in util/write_all.h. */

#include "util/write_all.h"

#include <errno.h>
#include <unistd.h>

bool zcl_write_all(int fd, const void *buf, size_t len)
{
    if (len == 0)
        return true;
    if (fd < 0 || !buf) {
        errno = EINVAL;
        return false;
    }

    const char *p = (const char *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false; /* no progress possible; errno is not set by write */
        done += (size_t)n;
    }
    return true;
}
