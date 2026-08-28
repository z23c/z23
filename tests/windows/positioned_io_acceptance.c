/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/positioned_io.h"

#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main(void)
{
    const char *path = "positioned_io_acceptance.tmp";
    uint8_t original[64];
    uint8_t replacement[32];
    uint8_t actual[64];
    memset(original, 0x11, sizeof(original));
    memset(replacement, 0x22, sizeof(replacement));

    int fd = _open(path, _O_CREAT | _O_TRUNC | _O_RDWR | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
    if (fd < 0 || _write(fd, original, sizeof(original)) != sizeof(original) ||
        _lseeki64(fd, 7, SEEK_SET) != 7 ||
        platform_positioned_write(fd, replacement, sizeof(replacement), 32) != 32 ||
        _telli64(fd) != 7 || _lseeki64(fd, 0, SEEK_SET) != 0 ||
        _read(fd, actual, sizeof(actual)) != sizeof(actual)) {
        if (fd >= 0) _close(fd);
        remove(path);
        return 1;
    }
    _close(fd);
    remove(path);
    if (memcmp(actual, original, 32) != 0 ||
        memcmp(actual + 32, replacement, 32) != 0)
        return 1;
    puts("positioned_io_acceptance: PASS");
    return 0;
}
