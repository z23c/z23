/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the postmortem capsule's `.cap.gz` container layer — ustar header
 * encoding/decoding, the gzip read/write/skip helpers built on zlib, and the
 * single-member extractor the capsule readers use.
 *
 * Split out of postmortem.c along the file-size ceiling seam: that file keeps
 * the capsule itself (crash hook, async-signal-safe capture, manifest,
 * load/validate/compress), and postmortem_inventory.c keeps the capsule
 * directory's list/summarise/prune surface. Nothing here knows what a capsule
 * MEANS — it only knows the archive format. The three symbols that cross back
 * are declared in postmortem_internal.h.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "postmortem_internal.h"

#include "platform/clock.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

static bool all_zero_block(const uint8_t *buf, size_t len)
{
    if (!buf) return true;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return false;
    }
    return true;
}

static unsigned long parse_octal_field(const uint8_t *buf, size_t len)
{
    unsigned long v = 0;
    size_t i = 0;
    while (i < len && (buf[i] == ' ' || buf[i] == '\0')) i++;
    for (; i < len && buf[i] >= '0' && buf[i] <= '7'; i++)
        v = (v << 3) + (unsigned long)(buf[i] - '0');
    return v;
}

static void write_octal_field(uint8_t *dst, size_t len, unsigned long v)
{
    if (!dst || len == 0) return;
    memset(dst, '0', len);
    dst[len - 1] = '\0';
    if (len >= 2) dst[len - 2] = ' ';
    size_t pos = len >= 2 ? len - 2 : len - 1;
    while (v > 0 && pos > 0) {
        dst[--pos] = (uint8_t)('0' + (v & 7u));
        v >>= 3;
    }
}

int gz_write_all(gzFile gz, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        unsigned chunk = len > (1u << 30) ? (1u << 30) : (unsigned)len;
        int wrote = gzwrite(gz, p, chunk);
        if (wrote <= 0) return -EIO;
        p += (size_t)wrote;
        len -= (size_t)wrote;
    }
    return 0;
}

static int gz_read_all(gzFile gz, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        unsigned chunk = len > (1u << 30) ? (1u << 30) : (unsigned)len;
        int got = gzread(gz, p, chunk);
        if (got <= 0) return -EIO;
        p += (size_t)got;
        len -= (size_t)got;
    }
    return 0;
}

static int gz_skip(gzFile gz, size_t len)
{
    uint8_t buf[4096];
    while (len > 0) {
        size_t want = len < sizeof(buf) ? len : sizeof(buf);
        int rc = gz_read_all(gz, buf, want);
        if (rc != 0) return rc;
        len -= want;
    }
    return 0;
}

static int tar_write_header(gzFile gz, const char *name, size_t size)
{
    if (!gz || !name || !*name || strlen(name) > 100) return -EINVAL;
    uint8_t h[TAR_BLOCK_SIZE];
    memset(h, 0, sizeof(h));
    snprintf((char *)h, 100, "%s", name);
    write_octal_field(h + 100, 8, 0644);
    write_octal_field(h + 108, 8, 0);
    write_octal_field(h + 116, 8, 0);
    write_octal_field(h + 124, 12, (unsigned long)size);
    write_octal_field(h + 136, 12, (unsigned long)clock_now_wall_ms() / 1000);
    memset(h + 148, ' ', 8);
    h[156] = '0';
    memcpy(h + 257, "ustar", 5);
    memcpy(h + 263, "00", 2);

    unsigned int sum = 0;
    for (size_t i = 0; i < sizeof(h); i++) sum += h[i];
    snprintf((char *)(h + 148), 8, "%06o", sum);
    h[154] = '\0';
    h[155] = ' ';
    return gz_write_all(gz, h, sizeof(h));
}

int tar_write_file(gzFile gz, const char *archive_name,
                   const char *path)
{
    if (!gz || !archive_name || !path) return -EINVAL;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return -errno;
    if (st.st_size < 0) return -EINVAL;

    int rc = tar_write_header(gz, archive_name, (size_t)st.st_size);
    if (rc != 0) return rc;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -errno;
    uint8_t buf[8192];
    size_t remaining = (size_t)st.st_size;
    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        size_t got = fread(buf, 1, want, fp);
        if (got == 0) {
            fclose(fp);
            return -EIO;
        }
        rc = gz_write_all(gz, buf, got);
        if (rc != 0) {
            fclose(fp);
            return rc;
        }
        remaining -= got;
    }
    fclose(fp);

    size_t pad = (TAR_BLOCK_SIZE - ((size_t)st.st_size % TAR_BLOCK_SIZE)) %
                 TAR_BLOCK_SIZE;
    if (pad > 0) {
        uint8_t zero[TAR_BLOCK_SIZE] = {0};
        rc = gz_write_all(gz, zero, pad);
    }
    return rc;
}

int gz_read_tar_member(const char *archive_path, const char *member,
                       uint8_t **out, size_t *len_out,
                       size_t max_len)
{
    if (!archive_path || !member || !out || !len_out) return -EINVAL;
    *out = NULL;
    *len_out = 0;
    gzFile gz = gzopen(archive_path, "rb");
    if (!gz) return errno ? -errno : -EIO;

    int rc = 0;
    for (;;) {
        uint8_t h[TAR_BLOCK_SIZE];
        rc = gz_read_all(gz, h, sizeof(h));
        if (rc != 0) break;
        if (all_zero_block(h, sizeof(h))) {
            rc = -ENOENT;
            break;
        }
        char name[101];
        memcpy(name, h, 100);
        name[100] = '\0';
        size_t size = (size_t)parse_octal_field(h + 124, 12);
        size_t pad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) %
                     TAR_BLOCK_SIZE;
        if (strcmp(name, member) == 0) {
            if (size > max_len) {
                rc = -E2BIG;
                break;
            }
            uint8_t *buf = zcl_malloc(size + 1, "postmortem.tar.member");
            if (!buf) {
                rc = -ENOMEM;
                break;
            }
            rc = gz_read_all(gz, buf, size);
            if (rc == 0) {
                buf[size] = '\0';
                *out = buf;
                *len_out = size;
            } else {
                free(buf);
            }
            break;
        }
        rc = gz_skip(gz, size + pad);
        if (rc != 0) break;
    }
    gzclose(gz);
    return rc;
}

