/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "params.h"
#include "zsha256/zsha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CHUNK = 1 << 20 };

static void say(char *why, size_t cap, const char *text)
{
    if (why && cap) snprintf(why, cap, "%s", text);
}

static bool sync_directory(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0) close(fd);
    return ok;
}

/* Removes the named files, their .part forms and the directory; nothing else, so a directory that
 * holds anything unexpected stays. */
static void discard(const struct zapp_param_file *set, size_t count, const char *dir)
{
    for (size_t i = 0; i < count; i++) {
        char file[1400], part[1400];
        snprintf(file, sizeof(file), "%s/%s", dir, set[i].name);
        snprintf(part, sizeof(part), "%s/%s.part", dir, set[i].name);
        (void)unlink(file);
        (void)unlink(part);
    }
    (void)rmdir(dir);
}

static bool write_all(int fd, const uint8_t *buf, size_t len)
{
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

static ssize_t read_at(int fd, uint8_t *buf, size_t len, uint64_t at)
{
    ssize_t n;
    do n = pread(fd, buf, len, (off_t)at); while (n < 0 && errno == EINTR);
    return n;
}

/* Copies [offset, offset + size) of from to the new file path and flushes it. */
static bool copy_out(int from, uint64_t offset, uint64_t size, const char *path, uint8_t *buf)
{
    int to = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok = to >= 0;
    for (uint64_t done = 0; ok && done < size;) {
        size_t want = size - done < CHUNK ? (size_t)(size - done) : CHUNK;
        ssize_t n = read_at(from, buf, want, offset + done);
        ok = n > 0 && write_all(to, buf, (size_t)n);
        done += ok ? (uint64_t)n : 0;
    }
    ok = ok && fsync(to) == 0;
    if (to >= 0 && close(to) != 0) ok = false;
    return ok;
}

/* Reads the copy back from storage and compares its length and SHA-256 with the pin. */
static bool copy_matches(const char *path, const struct zapp_param_file *want, uint8_t *buf, bool *io_error)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    zsha256_ctx ctx;
    uint64_t total = 0;
    *io_error = fd < 0;
    zsha256_init(&ctx);
    for (ssize_t n = 1; fd >= 0 && n > 0; total += (uint64_t)n) {
        n = read_at(fd, buf, CHUNK, total);
        if (n < 0) *io_error = true;
        if (n > 0) zsha256_update(&ctx, buf, (size_t)n);
        if (n < 0) break;
    }
    if (fd >= 0) close(fd);
    if (*io_error) return false;
    uint8_t digest[ZSHA256_DIGEST_LEN];
    char hex[ZSHA256_HEX_LEN];
    zsha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    return total == want->size && strcmp(hex, want->sha256) == 0;
}

static enum zapp_params_result fail(enum zapp_params_result code, char *why, size_t cap, const char *text)
{
    say(why, cap, text);
    return code;
}

/* Copies and verifies one file into dir. */
static enum zapp_params_result stage(const struct zapp_param_file *f, const struct zapp_params_source *source,
                                     const char *dir, uint8_t *buf, char *why, size_t cap)
{
    uint64_t offset = 0, length = 0;
    int from = source->open(source->ctx, f->name, &offset, &length);
    char part[1400], file[1400];
    if (from < 0) return fail(ZAPP_PARAMS_MISSING, why, cap, "The packaged proving parameters are missing from this app.");
    if (length != f->size) {
        close(from);
        return fail(ZAPP_PARAMS_SIZE, why, cap, "A packaged proving parameter file has the wrong size. Nothing was kept.");
    }
    if (snprintf(part, sizeof(part), "%s/%s.part", dir, f->name) >= (int)sizeof(part) ||
        snprintf(file, sizeof(file), "%s/%s", dir, f->name) >= (int)sizeof(file)) {
        close(from);
        return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameter folder path is too long.");
    }
    bool copied = copy_out(from, offset, f->size, part, buf);
    close(from);
    bool io = false;
    if (!copied) return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameters could not be written to private storage. Nothing was kept.");
    if (!copy_matches(part, f, buf, &io))
        return io ? fail(ZAPP_PARAMS_IO, why, cap, "The copied proving parameters could not be read back. Nothing was kept.")
                  : fail(ZAPP_PARAMS_HASH, why, cap, "A copied proving parameter file did not match its pinned hash. Nothing was kept.");
    if (rename(part, file) != 0) return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameters could not be stored. Nothing was kept.");
    return ZAPP_PARAMS_OK;
}

static enum zapp_params_result publish(const struct zapp_param_file *set, size_t count, const char *tmp,
                                         const char *final, const char *files, char *why, size_t cap)
{
    if (!sync_directory(tmp) || rename(tmp, final) != 0)
        return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameters could not be stored. Nothing was kept.");
    if (!sync_directory(files)) {   /* the rename may not survive a crash, so the directory must not stay */
        discard(set, count, final);
        return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameters could not be stored. Nothing was kept.");
    }
    return ZAPP_PARAMS_OK;
}

static bool verify_dir(const struct zapp_param_file *set, size_t count, const char *dir, uint8_t *buf)
{
    for (size_t i = 0; i < count; i++) {
        char file[1400];
        bool io;
        if (snprintf(file, sizeof(file), "%s/%s", dir, set[i].name) >= (int)sizeof(file) ||
            !copy_matches(file, &set[i], buf, &io))
            return false;
    }
    return true;
}

bool zapp_params_verify_set(const struct zapp_param_file *set, size_t count, const char *files)
{
    char dir[1100];
    if (!zapp_params_present_set(set, count, files) || !zapp_params_path(files, dir, sizeof(dir))) return false;
    uint8_t *buf = malloc(CHUNK);
    bool ok = buf && verify_dir(set, count, dir, buf);
    free(buf);
    return ok;
}

bool zapp_params_verify(const char *files)
{
    return zapp_params_verify_set(zapp_param_files, ZAPP_PARAMS_COUNT, files);
}

enum zapp_params_result zapp_params_install_set(const struct zapp_param_file *set, size_t count,
                                                const struct zapp_params_source *source,
                                                const char *files, char *why, size_t cap)
{
    char final[1100], tmp[1100];
    if (!source || !source->open || !zapp_params_path(files, final, sizeof(final)) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", final) >= (int)sizeof(tmp))
        return fail(ZAPP_PARAMS_IO, why, cap, "The proving parameter folder path is too long.");
    uint8_t *buf = malloc(CHUNK);
    if (!buf) {
        discard(set, count, final);   /* a copy this call cannot check is not kept */
        return fail(ZAPP_PARAMS_IO, why, cap, "Not enough memory to copy the proving parameters.");
    }
    if (zapp_params_present_set(set, count, files) && verify_dir(set, count, final, buf)) {
        free(buf);
        return ZAPP_PARAMS_OK;
    }
    discard(set, count, final);   /* absent, wrong size or corrupt: replace from the package */
    discard(set, count, tmp);
    enum zapp_params_result rc = ZAPP_PARAMS_OK;
    if (mkdir(tmp, 0700) != 0) rc = fail(ZAPP_PARAMS_IO, why, cap, "The private proving parameter folder could not be created.");
    for (size_t i = 0; rc == ZAPP_PARAMS_OK && i < count; i++) rc = stage(&set[i], source, tmp, buf, why, cap);
    if (rc == ZAPP_PARAMS_OK) rc = publish(set, count, tmp, final, files, why, cap);
    if (rc != ZAPP_PARAMS_OK) discard(set, count, tmp);
    free(buf);
    return rc;
}

enum zapp_params_result zapp_params_install(const struct zapp_params_source *source, const char *files,
                                            char *why, size_t cap)
{
    return zapp_params_install_set(zapp_param_files, ZAPP_PARAMS_COUNT, source, files, why, cap);
}
