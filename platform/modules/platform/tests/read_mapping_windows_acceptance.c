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

static bool create_temp_path(char *path)
{
#if defined(_WIN32)
    char temp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp) ||
        !GetTempFileNameA(temp, "z23", 0, path)) return false;
    return true;
#else
    memcpy(path, "/tmp/z23-read-mapping-XXXXXX",
           sizeof("/tmp/z23-read-mapping-XXXXXX"));
    return true;
#endif
}

static int open_temp_file(char *path)
{
#if defined(_WIN32)
    return _open(path, _O_BINARY | _O_RDWR | _O_TRUNC,
                 _S_IREAD | _S_IWRITE);
#else
    return mkstemp(path);
#endif
}

static void fill_expected_bytes(uint8_t *expected, size_t size)
{
    for (size_t i = 0; i < size; ++i) expected[i] = (uint8_t)i;
}

static bool write_expected_and_sync(int fd, const uint8_t *expected,
                                    size_t size)
{
#if defined(_WIN32)
    if (_write(fd, expected, size) != size ||
        _commit(fd) != 0) return false;
#else
    if (write(fd, expected, size) != (ssize_t)size ||
        fsync(fd) != 0) return false;
#endif
    return true;
}

static bool mapping_matches_expected(
    const struct platform_read_mapping *mapping, const uint8_t *expected,
    size_t size)
{
    if (mapping->size != size ||
        memcmp(mapping->data, expected, size) != 0) return false;
    return true;
}

static bool mapping_is_cleared(const struct platform_read_mapping *mapping)
{
    if (mapping->data || mapping->size ||
        mapping->native_mapping) return false;
    return true;
}

static void close_and_delete_temp_file(int fd, const char *path)
{
#if defined(_WIN32)
    _close(fd);
    DeleteFileA(path);
#else
    close(fd);
    unlink(path);
#endif
}

int main(void)
{
    char path[
#if defined(_WIN32)
        MAX_PATH
#else
        64
#endif
    ];
    if (!create_temp_path(path)) return 1;
    int fd = open_temp_file(path);
    if (fd < 0) return 2;
    uint8_t expected[64];
    fill_expected_bytes(expected, sizeof(expected));
    if (!write_expected_and_sync(fd, expected, sizeof(expected))) return 3;

    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open(&mapping, fd, sizeof(expected))) return 4;
    if (!mapping_matches_expected(&mapping, expected, sizeof(expected)))
        return 5;
    platform_read_mapping_advise_sequential(&mapping);
    platform_read_mapping_close(&mapping);
    platform_read_mapping_close(&mapping);
    if (!mapping_is_cleared(&mapping)) return 6;
    if (platform_read_mapping_open(&mapping, fd, 0)) return 7;

    close_and_delete_temp_file(fd, path);
    puts("read_mapping_acceptance: PASS");
    return 0;
}
