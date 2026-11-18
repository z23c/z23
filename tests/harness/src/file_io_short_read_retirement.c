/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: prove whole-file readers retire a partially filled owned
 * allocation before returning a short-read failure. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "test/test_core.h"
#include "util/file_io.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool file_io_inject_short_read;
static size_t file_io_short_read_bytes;
static size_t file_io_expected_allocation;
static bool file_io_freed_allocation_zero;

static void *file_io_observe_malloc(size_t n, const char *tag)
{
    (void)tag;
    void *ptr = malloc(n);
    if (ptr && file_io_inject_short_read)
        memset(ptr, 0xa5, n);
    return ptr;
}

static size_t file_io_observe_fread(void *ptr, size_t size, size_t count,
                                    FILE *stream)
{
    if (!file_io_inject_short_read)
        return fread(ptr, size, count, stream);
    (void)stream;
    if (size != 1 || count == 0)
        return 0;
    file_io_short_read_bytes = count - 1;
    memset(ptr, 0xa5, file_io_short_read_bytes);
    return file_io_short_read_bytes;
}

static void file_io_observe_free(void *ptr)
{
    if (file_io_inject_short_read && ptr) {
        const uint8_t *bytes = ptr;
        file_io_freed_allocation_zero = true;
        for (size_t i = 0; i < file_io_expected_allocation; i++)
            file_io_freed_allocation_zero =
                file_io_freed_allocation_zero && bytes[i] == 0;
    }
    free(ptr);
}

static void file_io_short_read_reset(size_t allocation_len)
{
    file_io_inject_short_read = true;
    file_io_short_read_bytes = 0;
    file_io_expected_allocation = allocation_len;
    file_io_freed_allocation_zero = false;
}

#undef zcl_malloc
#define zcl_malloc file_io_observe_malloc
#define fread file_io_observe_fread
#define free file_io_observe_free
#define zcl_read_whole_file file_io_short_observed_read
#define zcl_read_whole_file_text file_io_short_observed_read_text
#define zcl_read_whole_file_text_unbuffered file_io_short_observed_read_text_unbuffered
#include "../../../platform/modules/util/src/file_io.c"
#undef zcl_read_whole_file_text_unbuffered
#undef zcl_read_whole_file_text
#undef zcl_read_whole_file
#undef free
#undef fread
#undef zcl_malloc

static bool file_io_binary_short_read_retired(const char *path)
{
    file_io_short_read_reset(4);
    uint8_t *bytes = NULL;
    size_t length = 0;
    bool okay = !file_io_short_observed_read(
        path, 4, &bytes, &length, "file_io_short_read_test") && !bytes &&
        length == 0 && file_io_short_read_bytes == 3 &&
        file_io_freed_allocation_zero;
    file_io_inject_short_read = false;
    return okay;
}

static bool file_io_text_short_read_retired(const char *path)
{
    file_io_short_read_reset(5);
    char *text = NULL;
    size_t length = 0;
    bool okay = !file_io_short_observed_read_text(
        path, 4, &text, &length, "file_io_short_read_test") && !text &&
        length == 0 && file_io_short_read_bytes == 3 &&
        file_io_freed_allocation_zero;
    file_io_inject_short_read = false;
    return okay;
}

static bool file_io_unbuffered_short_read_retired(const char *path)
{
    file_io_short_read_reset(5);
    char *text = NULL;
    size_t length = 0;
    bool okay = !file_io_short_observed_read_text_unbuffered(
        path, 4, &text, &length, "file_io_short_read_test") && !text &&
        length == 0 && file_io_short_read_bytes == 3 &&
        file_io_freed_allocation_zero;
    file_io_inject_short_read = false;
    return okay;
}

int file_io_short_read_retirement_cases(void);
int file_io_short_read_retirement_cases(void)
{
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "file_io_short_read");
    bool prepared = false;
    if (fd >= 0) {
        bool wrote = write(fd, "read", 4) == 4;
        bool closed = close(fd) == 0;
        prepared = wrote && closed;
    }

    bool binary_ok = prepared && file_io_binary_short_read_retired(path);
    bool text_ok = prepared && file_io_text_short_read_retired(path);
    bool unbuffered_ok = prepared && file_io_unbuffered_short_read_retired(path);
    bool okay = binary_ok && text_ok && unbuffered_ok;
    if (fd >= 0)
        (void)unlink(path);
    printf("path_check: short whole-file reads retire owned buffers... %s\n",
           okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
}
