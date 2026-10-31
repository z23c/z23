/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "clip_player.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FILE_SIZE 1000

static unsigned char content[FILE_SIZE];
static struct zapp_clip_source source;
static int calls;
static int64_t traced_offset;
static size_t traced_size;
static ssize_t traced_result;

static void trace(void *user, int64_t offset, size_t size, ssize_t result)
{
    ++*(int *)user;
    traced_offset = offset;
    traced_size = size;
    traced_result = result;
}
static ssize_t trickle(int fd, void *buffer, size_t size, off_t offset)
{
    ++calls;
    return pread(fd, buffer, size < 7 ? size : 7, offset);
}
static ssize_t truncated(int fd, void *buffer, size_t size, off_t offset)
{
    ++calls;
    return offset >= 30 ? 0 : pread(fd, buffer, size < 30 - (size_t)offset ? size : 30 - (size_t)offset, offset);
}
static ssize_t interrupted(int fd, void *buffer, size_t size, off_t offset)
{
    if (calls++ == 0) { errno = EINTR; return -1; }
    return pread(fd, buffer, size, offset);
}
/* Answers every request in full, even past the end, so that only the clamp in read_at keeps reads inside the file. */
static ssize_t endless(int fd, void *buffer, size_t size, off_t offset)
{
    (void)fd; (void)offset;
    memset(buffer, 0xab, size);
    return (ssize_t)size;
}
static ssize_t broken(int fd, void *buffer, size_t size, off_t offset)
{
    (void)fd; (void)buffer; (void)size; (void)offset;
    errno = EIO;
    return -1;
}

static void mapping(void)
{
    unsigned char out[200];
    assert(zapp_clip_source_read_at(&source, 0, out, 100) == 100 && !memcmp(out, content, 100));
    assert(zapp_clip_source_read_at(&source, 500, out, 100) == 100 && !memcmp(out, content + 500, 100));
    assert(zapp_clip_source_read_at(&source, 950, out, 100) == 50 && !memcmp(out, content + 950, 50));
    assert(zapp_clip_source_read_at(&source, 999, out, 1) == 1 && out[0] == content[999]);
}

static void end_of_file(void)
{
    unsigned char out[16];
    assert(zapp_clip_source_read_at(&source, FILE_SIZE, out, 16) == -1);
    assert(zapp_clip_source_read_at(&source, FILE_SIZE + 500, out, 16) == -1);
    assert(zapp_clip_source_read_at(&source, -1, out, 16) == -1);
    assert(zapp_clip_source_read_at(&source, 10, out, 0) == 0);
    assert(zapp_clip_source_read_at(&source, FILE_SIZE, out, 0) == 0);
}

static void short_reads(void)
{
    unsigned char out[100];
    ssize_t (*real)(int, void *, size_t, off_t) = source.pread_fn;
    source.pread_fn = trickle;
    calls = 0;
    assert(zapp_clip_source_read_at(&source, 40, out, 100) == 100 && !memcmp(out, content + 40, 100));
    assert(calls == 15);
    source.pread_fn = truncated;
    assert(zapp_clip_source_read_at(&source, 10, out, 100) == 20 && !memcmp(out, content + 10, 20));
    assert(zapp_clip_source_read_at(&source, 40, out, 100) == -1);
    source.pread_fn = interrupted;
    calls = 0;
    assert(zapp_clip_source_read_at(&source, 5, out, 10) == 10 && !memcmp(out, content + 5, 10));
    source.pread_fn = broken;
    assert(zapp_clip_source_read_at(&source, 5, out, 10) == -1);
    source.pread_fn = real;
}

static void clamped_to_the_file(void)
{
    unsigned char out[100];
    ssize_t (*real)(int, void *, size_t, off_t) = source.pread_fn;
    source.pread_fn = endless;
    assert(zapp_clip_source_read_at(&source, 950, out, 100) == 50);
    assert(zapp_clip_source_read_at(&source, 0, out, 100) == 100);
    assert(zapp_clip_source_read_at(&source, FILE_SIZE, out, 100) == -1);
    assert(zapp_clip_source_read_at(&source, FILE_SIZE + 500, out, 100) == -1);
    assert(zapp_clip_source_read_at(&source, -1, out, 100) == -1);
    source.pread_fn = real;
}

static void tracing(void)
{
    unsigned char out[64];
    int count = 0;
    source.trace = trace;
    source.trace_user = &count;
    assert(zapp_clip_source_read_at(&source, 960, out, 64) == 40);
    assert(count == 1 && traced_offset == 960 && traced_size == 64 && traced_result == 40);
    assert(zapp_clip_source_read_at(&source, 2000, out, 64) == -1);
    assert(count == 2 && traced_offset == 2000 && traced_result == -1);
    source.trace = NULL;
}

static void fitting(void)
{
    int w = 0, h = 0;
    zapp_clip_fit(1080, 2220, 480, 854, &w, &h);
    assert(w == 1080 && h == 1921);
    zapp_clip_fit(2000, 1000, 480, 854, &w, &h);
    assert(h == 1000 && w == 562);
    zapp_clip_fit(480, 854, 480, 854, &w, &h);
    assert(w == 480 && h == 854);
    zapp_clip_fit(300, 400, 0, 0, &w, &h);
    assert(w == 300 && h == 400);
}

int main(int argc, char **argv)
{
    char path[512];
    if (argc != 2 || snprintf(path, sizeof(path), "%s/source.bin", argv[1]) >= (int)sizeof(path)) return 2;
    for (size_t i = 0; i < sizeof(content); ++i) content[i] = (unsigned char)(i * 7 % 251);
    FILE *f = fopen(path, "wb");
    assert(f != NULL && fwrite(content, 1, sizeof(content), f) == sizeof(content) && fclose(f) == 0);
    assert(zapp_clip_source_open(&source, path) && source.size == FILE_SIZE);
    mapping();
    end_of_file();
    short_reads();
    clamped_to_the_file();
    tracing();
    fitting();
    zapp_clip_source_close(&source);
    assert(source.fd == -1);
    struct zapp_clip_source missing;
    snprintf(path, sizeof(path), "%s/none.bin", argv[1]);
    assert(!zapp_clip_source_open(&missing, path));
    puts("clips_player_test ok");
    return 0;
}
