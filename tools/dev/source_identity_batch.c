/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Native NUL-path batch hashing and mode capture for source_identity.v2.
 * Output remains byte-identical to GNU sha256sum --zero and stat -c %f.
 */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "zsha256/zsha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID
#error "source identity batch input id is required"
#endif

typedef enum {
    BATCH_HASH,
    BATCH_MODE,
} batch_mode;

static int report_path_error(const char *action, const char *path)
{
    fprintf(stderr, "source-identity-batch: %s %s: %s\n",
            action, path, strerror(errno));
    return 1;
}

static int read_path(char **buffer, size_t *capacity, bool *at_eof)
{
    size_t length = 0;
    *at_eof = false;
    for (;;) {
        int byte = fgetc(stdin);
        if (byte == EOF) {
            if (ferror(stdin)) {
                fprintf(stderr, "source-identity-batch: stdin read failed\n");
                return -1;
            }
            if (length != 0) {
                fprintf(stderr,
                        "source-identity-batch: unterminated NUL record\n");
                return -1;
            }
            *at_eof = true;
            return 0;
        }
        if (byte == 0) {
            if (length == 0) {
                fprintf(stderr, "source-identity-batch: empty path record\n");
                return -1;
            }
            (*buffer)[length] = '\0';
            return 0;
        }
        if (length + 1 >= *capacity) {
            if (*capacity > SIZE_MAX / 2) {
                fprintf(stderr, "source-identity-batch: path is too long\n");
                return -1;
            }
            size_t next_capacity = *capacity * 2;
            char *next = zcl_realloc(*buffer, next_capacity,
                                     "source identity path");
            if (next == nullptr) {
                fprintf(stderr,
                        "source-identity-batch: path allocation failed\n");
                return -1;
            }
            *buffer = next;
            *capacity = next_capacity;
        }
        (*buffer)[length++] = (char)(unsigned char)byte;
    }
}

static bool same_snapshot(const struct stat *left, const struct stat *right)
{
    bool same = left->st_dev == right->st_dev &&
                left->st_ino == right->st_ino &&
                left->st_mode == right->st_mode &&
                left->st_size == right->st_size;
#if defined(__APPLE__)
    return same &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return same && left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static int digest_fd(int fd, const char *path,
                     uint8_t digest[ZSHA256_DIGEST_LEN])
{
    zsha256_ctx hash;
    zsha256_init(&hash);
    unsigned char bytes[64 * 1024];
    uint64_t total = 0;
    for (;;) {
        ssize_t count = read(fd, bytes, sizeof bytes);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            errno = saved;
            return report_path_error("could not read", path);
        }
        if (count == 0)
            break;
        if (total > UINT64_MAX / 8u - (uint64_t)count) {
            fprintf(stderr, "source-identity-batch: file is too large: %s\n",
                    path);
            return 1;
        }
        total += (uint64_t)count;
        zsha256_update(&hash, bytes, (size_t)count);
    }
    zsha256_final(&hash, digest);
    return 0;
}

static int emit_hash(const char *path,
                     const uint8_t digest[ZSHA256_DIGEST_LEN])
{
    char hex[2 * ZSHA256_DIGEST_LEN + 1u];
    zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, hex);
    size_t path_length = strlen(path);
    if (fwrite(hex, 1, sizeof hex - 1u, stdout) != sizeof hex - 1u ||
        fwrite("  ", 1, 2, stdout) != 2 ||
        fwrite(path, 1, path_length, stdout) != path_length ||
        fputc(0, stdout) == EOF) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

static int hash_path(const char *path)
{
    struct stat before;
    if (lstat(path, &before) != 0)
        return report_path_error("could not stat", path);
    if (!S_ISREG(before.st_mode)) {
        fprintf(stderr,
                "source-identity-batch: hash input is not regular: %s\n",
                path);
        return 1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return report_path_error("could not open", path);
    struct stat opened;
    if (fstat(fd, &opened) != 0 || !same_snapshot(&before, &opened)) {
        int saved = errno;
        close(fd);
        errno = saved;
        fprintf(stderr,
                "source-identity-batch: file changed before hashing: %s\n",
                path);
        return 1;
    }

    uint8_t digest[ZSHA256_DIGEST_LEN];
    int status = digest_fd(fd, path, digest);
    struct stat after;
    if (status == 0 &&
        (fstat(fd, &after) != 0 || !same_snapshot(&opened, &after))) {
        fprintf(stderr,
                "source-identity-batch: file changed while hashing: %s\n",
                path);
        status = 1;
    }
    if (close(fd) != 0 && status == 0)
        status = report_path_error("could not close", path);
    struct stat path_after;
    if (status == 0 &&
        (lstat(path, &path_after) != 0 ||
         !same_snapshot(&before, &path_after))) {
        fprintf(stderr,
                "source-identity-batch: path changed while hashing: %s\n",
                path);
        status = 1;
    }
    return status == 0 ? emit_hash(path, digest) : status;
}

static int mode_path(const char *path)
{
    struct stat metadata;
    if (lstat(path, &metadata) != 0)
        return report_path_error("could not stat", path);
    if (printf("%" PRIxMAX "\n", (uintmax_t)metadata.st_mode) < 0) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "identity") == 0) {
        printf("zcl.source_identity_batch.v1 %s\n",
               ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID);
        return ferror(stdout) ? 1 : 0;
    }
    batch_mode mode;
    if (argc == 2 && strcmp(argv[1], "hash") == 0)
        mode = BATCH_HASH;
    else if (argc == 2 && strcmp(argv[1], "mode") == 0)
        mode = BATCH_MODE;
    else {
        fprintf(stderr, "usage: source-identity-batch hash|mode|identity\n");
        return 2;
    }

    size_t capacity = 256;
    char *path = zcl_malloc(capacity, "source identity path");
    if (path == nullptr) {
        fprintf(stderr, "source-identity-batch: path allocation failed\n");
        return 1;
    }
    if (setvbuf(stdout, nullptr, _IOFBF, 64 * 1024) != 0) {
        fprintf(stderr, "source-identity-batch: output buffering failed\n");
        free(path);
        return 1;
    }

    int status = 0;
    for (;;) {
        bool at_eof;
        if (read_path(&path, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        status = mode == BATCH_HASH ? hash_path(path) : mode_path(path);
        if (status != 0)
            break;
    }
    if (status == 0 && fflush(stdout) != 0) {
        fprintf(stderr, "source-identity-batch: output flush failed\n");
        status = 1;
    }
    free(path);
    return status;
}
