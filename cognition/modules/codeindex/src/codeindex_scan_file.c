/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bind codeindex scans to one stable source-file identity. */

#include "codeindex_priv.h"

#include "platform/positioned_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool ci_scan_open_stable_source(
    struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *before,
    const char *root, const char *relpath)
{
    platform_positioned_file_init(file);
    return platform_positioned_file_open_beneath(file, root, relpath) &&
        platform_positioned_file_snapshot(file, before) &&
        before->size <= SIZE_MAX;
}

/* Status codes for ci_scan_read_source_contents; the caller logs the
 * failure, this helper frees the buffer and closes the file first. */
enum ci_scan_read_status {
    CI_SCAN_READ_OK = 0,
    CI_SCAN_READ_ALLOC_FAILED,
    CI_SCAN_READ_FAILED,
};

static enum ci_scan_read_status ci_scan_read_source_contents(
    struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *before,
    char **buf_out, size_t *len_out)
{
    size_t cap = before->size ? (size_t)before->size : 1u, len = 0;
    char *buf = zcl_malloc(cap, "ci_filebuf");
    if (!buf) {
        platform_positioned_file_close(file);
        return CI_SCAN_READ_ALLOC_FAILED;
    }
    while (len < (size_t)before->size) {
        int64_t r = platform_positioned_file_read(
            file, buf + len, (size_t)before->size - len, len);
        if (r <= 0) {
            free(buf);
            platform_positioned_file_close(file);
            return CI_SCAN_READ_FAILED;
        }
        len += (size_t)r;
    }
    *buf_out = buf;
    *len_out = len;
    return CI_SCAN_READ_OK;
}

static bool ci_scan_source_unchanged(
    struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *before,
    struct platform_positioned_file_snapshot *after)
{
    return platform_positioned_file_snapshot(file, after) &&
        before->size == after->size && before->volume == after->volume &&
        before->file_low == after->file_low &&
        before->file_high == after->file_high &&
        before->modified_seconds == after->modified_seconds &&
        before->modified_nanoseconds == after->modified_nanoseconds &&
        before->changed_seconds == after->changed_seconds &&
        before->changed_nanoseconds == after->changed_nanoseconds;
}

static void ci_scan_hash_contents(const char *buf, size_t len,
                                  uint8_t out_sha3[32])
{
    static const uint8_t tag = 0x02;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    if (len) sha3_256_write(&ctx, (const unsigned char *)buf, len);
    sha3_256_finalize(&ctx, out_sha3);
}

static bool ci_scan_path_is_header(const char *relpath)
{
    size_t rl = strlen(relpath);
    return rl >= 2 && relpath[rl - 2] == '.' && relpath[rl - 1] == 'h';
}

bool ci_scan_file(const char *root, const char *relpath,
                  ci_sym_cb on_sym, ci_ref_cb on_ref, void *user,
                  uint8_t out_sha3[32], char purpose_out[CI_FILE_PURPOSE_MAX])
{
    if (purpose_out) purpose_out[0] = '\0';
    if (!root || !relpath || !on_sym || !on_ref)
        LOG_FAIL("codeindex", "null arg to scan_file");

    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    if (!ci_scan_open_stable_source(&file, &before, root, relpath))
        LOG_FAIL("codeindex", "open stable source %s", relpath);

    char *buf = NULL;
    size_t len = 0;
    enum ci_scan_read_status read_status =
        ci_scan_read_source_contents(&file, &before, &buf, &len);
    if (read_status == CI_SCAN_READ_ALLOC_FAILED)
        LOG_FAIL("codeindex", "alloc filebuf");
    if (read_status == CI_SCAN_READ_FAILED)
        LOG_FAIL("codeindex", "read stable source %s", relpath);

    bool stable = ci_scan_source_unchanged(&file, &before, &after);
    platform_positioned_file_close(&file);
    if (!stable) {
        free(buf);
        LOG_FAIL("codeindex", "source changed while scanning %s", relpath);
    }

    if (out_sha3) ci_scan_hash_contents(buf, len, out_sha3);

    bool is_header = ci_scan_path_is_header(relpath);
    char group[64];
    ci_group_for_path(relpath, group);
    ci_scan_text(buf, len, relpath, is_header, group, on_sym, on_ref, user,
                 purpose_out);
    free(buf);
    return true;
}
