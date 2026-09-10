/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Scan, SHA-256 and order a beta6 serve directory into a manifest file list.
 *
 * Port of CollectBootstrapSnapshotFiles + HashBootstrapSnapshotFile
 * (bootstrap.cpp:3399-3511). The serve tree is opened read-only and never
 * written. Two properties are wire contract with the client:
 *
 *  - the per-file SHA-256 lands in the manifest REVERSED, because the C++ hashes
 *    into a hex string and re-parses it with uint256S, which reads hex
 *    right-to-left (bootstrap.cpp:3431);
 *  - every chainstate/ entry sorts before every blocks/ entry, each group
 *    lexicographic, so a growable block bundle only appends indices at the tail
 *    and never shifts a chainstate file's nFileIndex mid-download
 *    (bootstrap.cpp:3498-3508).
 */
#include "services/beta6_bootstrap.h"

#include "crypto/sha256.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Streaming hash buffer. Heap, never stack: the C++ learned the same lesson on
 * a 512 KiB worker stack (bootstrap.cpp:3410-3415). */
#define BETA6_HASH_BUFFER_BYTES (1024u * 1024u)

struct beta6_scan {
    const char *root;
    struct beta6_bs_file *files;
    size_t count;
    size_t capacity;
    uint64_t total_bytes;
    unsigned char *buffer;
    char *err;
    size_t err_size;
};

static void scan_fail(struct beta6_scan *scan, const char *fmt, const char *arg)
{
    if (scan->err && scan->err_size)
        snprintf(scan->err, scan->err_size, fmt, arg);
}

/* HashBootstrapSnapshotFile: SHA-256 the whole file, then store it the way
 * uint256S("0x" + HexStr(digest)) does — reversed. */
static bool hash_file(struct beta6_scan *scan, const struct platform_positioned_file *file,
                      uint64_t size, struct uint256 *out)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = BETA6_HASH_BUFFER_BYTES;
        if (size - offset < (uint64_t)want)
            want = (size_t)(size - offset);
        int64_t got = platform_positioned_file_read(file, scan->buffer, want, offset);
        if (got <= 0)
            return false;
        sha256_write(&ctx, scan->buffer, (size_t)got);
        offset += (uint64_t)got;
    }
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    for (size_t i = 0; i < 32; i++)
        out->data[i] = digest[31 - i];
    return true;
}

static bool scan_reserve(struct beta6_scan *scan)
{
    if (scan->count < scan->capacity)
        return true;
    size_t next = scan->capacity ? scan->capacity * 2 : 256;
    if (next > BETA6_BS_MAX_FILES)
        next = BETA6_BS_MAX_FILES;
    if (next <= scan->count) {
        scan_fail(scan, "beta6 bootstrap source holds too many files: %s", scan->root);
        return false;
    }
    struct beta6_bs_file *grown = realloc(scan->files, next * sizeof(*grown));
    if (!grown) {
        scan_fail(scan, "out of memory scanning beta6 bootstrap source: %s", scan->root);
        return false;
    }
    scan->files = grown;
    scan->capacity = next;
    return true;
}

/* Open, stat, hash and record one regular file named by its path relative to
 * the serve root. */
static bool scan_record_file(struct beta6_scan *scan, const char *relative)
{
    if (!beta6_bs_is_data_path(relative)) {
        scan_fail(scan, "beta6 bootstrap source contains unsafe relative path: %s",
                  relative);
        return false;
    }
    if (!scan_reserve(scan))
        return false;

    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, scan->root, relative)) {
        scan_fail(scan, "could not open beta6 bootstrap snapshot file: %s", relative);
        return false;
    }
    struct platform_positioned_file_snapshot stamp;
    uint64_t size = 0;
    bool ok = platform_positioned_file_size(&file, &size) &&
              platform_positioned_file_snapshot(&file, &stamp);

    struct beta6_bs_file *entry = &scan->files[scan->count];
    memset(entry, 0, sizeof(*entry));
    if (ok)
        ok = hash_file(scan, &file, size, &entry->sha256);
    platform_positioned_file_close(&file);
    if (!ok) {
        scan_fail(scan, "error reading beta6 bootstrap snapshot file: %s", relative);
        return false;
    }
    if (size > UINT64_MAX - scan->total_bytes) {
        scan_fail(scan, "beta6 bootstrap snapshot byte size overflow: %s", relative);
        return false;
    }

    snprintf(entry->path, sizeof(entry->path), "%s", relative);
    entry->size = size;
    entry->mtime_seconds = stamp.modified_seconds;
    scan->total_bytes += size;
    scan->count++;
    return true;
}

static bool join_relative(char *out, size_t out_size, const char *prefix, const char *name)
{
    int written = prefix[0] ? snprintf(out, out_size, "%s/%s", prefix, name)
                            : snprintf(out, out_size, "%s", name);
    return written > 0 && (size_t)written < out_size;
}

static bool scan_directory(struct beta6_scan *scan, const char *relative_prefix);

static bool scan_children(struct beta6_scan *scan, const char *relative_prefix,
                          const struct platform_directory_list *list, bool are_dirs)
{
    char relative[BETA6_BS_MAX_PATH_LEN];
    for (size_t i = 0; i < list->count; i++) {
        if (!join_relative(relative, sizeof(relative), relative_prefix,
                           list->entries[i].name)) {
            scan_fail(scan, "beta6 bootstrap source path is too long under: %s",
                      relative_prefix);
            return false;
        }
        bool ok = are_dirs ? scan_directory(scan, relative)
                           : scan_record_file(scan, relative);
        if (!ok)
            return false;
    }
    return true;
}

static bool scan_directory(struct beta6_scan *scan, const char *relative_prefix)
{
    char absolute[4096];
    int written = relative_prefix[0]
                      ? snprintf(absolute, sizeof(absolute), "%s/%s", scan->root,
                                 relative_prefix)
                      : snprintf(absolute, sizeof(absolute), "%s", scan->root);
    if (written <= 0 || (size_t)written >= sizeof(absolute)) {
        scan_fail(scan, "beta6 bootstrap source path is too long: %s", relative_prefix);
        return false;
    }

    struct platform_directory_list dirs = { 0 };
    struct platform_directory_list files = { 0 };
    if (!platform_directory_list_children_sorted(absolute, &dirs, &files)) {
        scan_fail(scan, "could not read beta6 bootstrap source directory: %s", absolute);
        return false;
    }
    bool ok = scan_children(scan, relative_prefix, &files, false) &&
              scan_children(scan, relative_prefix, &dirs, true);
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    return ok;
}

static bool path_is_chainstate(const char *path)
{
    return strncmp(path, "chainstate/", 11) == 0;
}

static int compare_files(const void *lhs, const void *rhs)
{
    const struct beta6_bs_file *a = lhs;
    const struct beta6_bs_file *b = rhs;
    bool a_chain = path_is_chainstate(a->path);
    bool b_chain = path_is_chainstate(b->path);
    if (a_chain != b_chain)
        return a_chain ? -1 : 1;
    return strcmp(a->path, b->path);
}

bool beta6_bs_collect_files(const char *source_dir, struct beta6_bs_manifest *manifest,
                            char *err, size_t err_size)
{
    if (!source_dir || !manifest)
        return false;
    if (!beta6_bs_source_paths_exist(source_dir)) {
        if (err && err_size)
            snprintf(err, err_size, "beta6 bootstrap source is incomplete: %s", source_dir);
        return false;
    }

    struct beta6_scan scan = { .root = source_dir, .err = err, .err_size = err_size };
    scan.buffer = malloc(BETA6_HASH_BUFFER_BYTES);
    if (!scan.buffer) {
        scan_fail(&scan, "out of memory scanning beta6 bootstrap source: %s", source_dir);
        return false;
    }
    bool ok = scan_directory(&scan, "");
    free(scan.buffer);
    if (!ok) {
        free(scan.files);
        return false;
    }
    if (scan.count == 0) {
        scan_fail(&scan, "beta6 bootstrap source holds no files: %s", source_dir);
        free(scan.files);
        return false;
    }

    qsort(scan.files, scan.count, sizeof(*scan.files), compare_files);
    manifest->files = scan.files;
    manifest->file_count = scan.count;
    manifest->snapshot_bytes = scan.total_bytes;
    return true;
}
