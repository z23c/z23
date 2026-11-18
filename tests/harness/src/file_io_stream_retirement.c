/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: prove whole-file readers acquire their stream through the portable
 * no-inherit opener before any file bytes enter an owned allocation. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/file_stream.h"
#include "test/test_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>

static unsigned file_io_observed_opens;
static unsigned file_io_observed_buffer_changes;
static bool file_io_refuse_buffer_change;
static bool file_io_buffer_mode_correct;

static int file_io_observe_setvbuf(FILE *stream, char *buf, int mode, size_t size)
{
    file_io_observed_buffer_changes++;
    file_io_buffer_mode_correct = file_io_buffer_mode_correct &&
                                  mode == _IONBF && buf == NULL && size == 0;
    if (file_io_refuse_buffer_change) return 1;
    return setvbuf(stream, buf, mode, size);
}
static bool file_io_observed_cloexec;

static FILE *file_io_observe_open(const char *path)
{
    FILE *stream = platform_file_stream_open_read(path);
    ++file_io_observed_opens;
    int fd = stream ? fileno(stream) : -1;
    file_io_observed_cloexec = file_io_observed_cloexec && fd >= 0 &&
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
    return stream;
}

#define platform_file_stream_open_read file_io_observe_open
#define setvbuf file_io_observe_setvbuf
#define zcl_read_whole_file file_io_observed_read
#define zcl_read_whole_file_text file_io_observed_read_text
#define zcl_read_whole_file_text_unbuffered file_io_observed_read_text_unbuffered
#define zcl_read_whole_file_text_unbuffered_checked file_io_observed_read_text_unbuffered_checked
#include "../../../platform/modules/util/src/file_io.c"
#undef zcl_read_whole_file_text_unbuffered_checked
#undef zcl_read_whole_file_text_unbuffered
#undef zcl_read_whole_file_text
#undef setvbuf
#undef zcl_read_whole_file
#undef platform_file_stream_open_read
static bool file_io_read_expected(const char *path, size_t cap, const char *expected)
{
    char *text = NULL;
    size_t len = 0;
    bool ok = file_io_observed_read_text_unbuffered(path, cap, &text, &len,
                                                     "file_io_stream_test");
    ok = ok && text && len == strlen(expected) && strcmp(text, expected) == 0;
    free(text);
    return ok;
}

static bool file_io_fixture_paths(const char *path)
{
    char empty[PATH_MAX], link[PATH_MAX];
    int fd = test_mkstemp(empty, sizeof(empty), "file_io_empty");
    if (fd < 0) return false;
    bool ok = close(fd) == 0;
    ok = file_io_read_expected(empty, 4, "") && ok;
    int n = snprintf(link, sizeof(link), "%s.link", path);
    bool linked = n > 0 && (size_t)n < sizeof(link) && symlink(path, link) == 0;
    if (linked) ok = file_io_read_expected(link, 4, "read") && ok;
    else ok = false;
    (void)unlink(empty);
    char *text = NULL;
    size_t len = 99;
    bool missing = !file_io_observed_read_text_unbuffered(empty, 4, &text, &len,
                                                           "file_io_stream_test");
    ok = missing && !text && len == 0 && ok;
    if (linked) (void)unlink(link);
    return ok;
}

static bool file_io_optin_cases(const char *path)
{
    file_io_observed_buffer_changes = 0;
    file_io_buffer_mode_correct = true;
    file_io_refuse_buffer_change = false;
    bool ok = file_io_read_expected(path, 4, "read") &&
              file_io_observed_buffer_changes == 1;
    char *text = NULL;
    size_t len = 99;
    bool over = !file_io_observed_read_text_unbuffered(path, 3, &text, &len,
                                                        "file_io_stream_test");
    ok = ok && over && !text && len == 0;
    ok = file_io_fixture_paths(path) && ok;
    file_io_refuse_buffer_change = true;
    ok = file_io_read_expected(path, 4, "read") && ok;
    file_io_refuse_buffer_change = false;
    return file_io_buffer_mode_correct && ok;
}

static bool file_io_default_stream_ok(bool binary_ok, bool text_ok)
{
    return binary_ok && text_ok && file_io_observed_opens == 2 &&
           file_io_observed_cloexec && file_io_observed_buffer_changes == 0;
}
#endif

int file_io_stream_retirement_cases(void);
int file_io_stream_retirement_cases(void)
{
#ifdef _WIN32
    puts("path_check: whole-file stream refuses inheritance... UNOBSERVED (Windows runtime required)");
    return 0;
#else
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "file_io_stream");
    bool prepared = false;
    if (fd >= 0) {
        bool wrote = write(fd, "read", 4) == 4;
        bool closed = close(fd) == 0;
        prepared = wrote && closed;
    }
    file_io_observed_opens = 0;
    file_io_observed_buffer_changes = 0;
    file_io_observed_cloexec = true;
    uint8_t *bytes = NULL;
    size_t length = 0;
    bool read_ok = prepared && file_io_observed_read(
        path, 4, &bytes, &length, "file_io_stream_test");
    bool binary_ok = read_ok && length == 4 && memcmp(bytes, "read", 4) == 0;
    free(bytes);
    char *text = NULL;
    length = 0;
    bool text_ok = prepared && file_io_observed_read_text(
        path, 4, &text, &length, "file_io_stream_test") && length == 4 &&
        strcmp(text, "read") == 0;
    free(text);
    bool okay = file_io_default_stream_ok(binary_ok, text_ok);
    okay = file_io_optin_cases(path) && okay;
    if (fd >= 0)
        (void)unlink(path);
    printf("path_check: whole-file stream refuses inheritance... %s\n",
        okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
#endif
}
