/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native acceptance for the descriptor-backed read mapping seam. */
#include "platform/read_mapping.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(void)
{
    char path[
#if defined(_WIN32)
        MAX_PATH
#else
        64
#endif
    ];
#if defined(_WIN32)
    char temp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp) ||
        !GetTempFileNameA(temp, "z23", 0, path)) return 1;
    int fd = _open(path, _O_BINARY | _O_RDWR | _O_TRUNC,
                   _S_IREAD | _S_IWRITE);
#else
    memcpy(path, "/tmp/z23-read-mapping-XXXXXX",
           sizeof("/tmp/z23-read-mapping-XXXXXX"));
    int fd = mkstemp(path);
#endif
    if (fd < 0) return 2;
    uint8_t expected[64];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (uint8_t)i;
#if defined(_WIN32)
    if (_write(fd, expected, sizeof(expected)) != sizeof(expected) ||
        _commit(fd) != 0) return 3;
#else
    if (write(fd, expected, sizeof(expected)) != (ssize_t)sizeof(expected) ||
        fsync(fd) != 0) return 3;
#endif

    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open(&mapping, fd, sizeof(expected))) return 4;
    if (mapping.size != sizeof(expected) ||
        memcmp(mapping.data, expected, sizeof(expected)) != 0) return 5;
    platform_read_mapping_advise_sequential(&mapping);
    platform_read_mapping_close(&mapping);
    platform_read_mapping_close(&mapping);
    if (mapping.data || mapping.size || mapping.native_mapping) return 6;
    if (platform_read_mapping_open(&mapping, fd, 0)) return 7;

#if defined(_WIN32)
    _close(fd);
    DeleteFileA(path);
#else
    close(fd);
    unlink(path);
#endif
    puts("read_mapping_acceptance: PASS");
    return 0;
}
