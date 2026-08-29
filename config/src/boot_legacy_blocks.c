/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_legacy_blocks.h"

#include "config/file_ops.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool boot_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}

static bool boot_file_snapshot(const char *path,
                               struct platform_positioned_file_snapshot *out)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_snapshot(&file, out);
    platform_positioned_file_close(&file);
    return ok;
}

static bool boot_copy_no_clobber(
    const char *src, const char *dst,
    const struct platform_positioned_file_snapshot *expected)
{
    struct platform_positioned_file input;
    struct platform_private_file output;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    struct platform_private_file_identity output_id;
    platform_positioned_file_init(&input);
    platform_private_file_init(&output);
    if (!platform_positioned_file_open(&input, src) ||
        !platform_positioned_file_snapshot(&input, &before) ||
        !boot_snapshot_equal(&before, expected) ||
        !platform_private_file_create(dst, &output) ||
        !platform_private_file_identity(&output, &output_id)) {
        platform_positioned_file_close(&input);
        platform_private_file_close(&output);
        return false;
    }
    uint8_t bytes[64 * 1024];
    uint64_t offset = 0;
    bool ok = true;
    while (offset < before.size) {
        size_t want = before.size - offset < sizeof(bytes)
                          ? (size_t)(before.size - offset)
                          : sizeof(bytes);
        int64_t got = platform_positioned_file_read(&input, bytes, want, offset);
        if (got != (int64_t)want ||
            !platform_private_file_write_at(&output, bytes, want, offset)) {
            ok = false;
            break;
        }
        offset += want;
    }
    ok = ok && platform_private_file_flush(&output) &&
         platform_positioned_file_snapshot(&input, &after) &&
         boot_snapshot_equal(&before, &after);
    platform_positioned_file_close(&input);
    if (!ok)
        (void)platform_private_file_retire_if_identity(&output, dst,
                                                       &output_id);
    platform_private_file_close(&output);
    return ok;
}

static bool boot_legacy_blocks_dir(char *out, size_t out_n,
                                   const char *datadir)
{
    if (!out || out_n == 0 || !datadir || !*datadir)
        return false;

    int n = snprintf(out, out_n, "%s/blocks", datadir);
    return n >= 0 && (size_t)n < out_n;
}

bool boot_legacy_default_blocks_dir(char *out, size_t out_n)
{
    if (!out || out_n == 0)
        return false;

    const char *home = getenv("HOME");
    const char *appdata = getenv("APPDATA");
    const char *bases[3] = {NULL};
    int nbases = 0;

    if (appdata && appdata[0]) {
        bases[nbases++] = appdata;
    }
    if (home && home[0]) {
        bases[nbases++] = home; /* placeholder: macOS path built below */
        bases[nbases++] = home; /* placeholder: Unix dot-dir built below */
    }

    for (int i = 0; i < nbases; i++) {
        const char *base = bases[i];
        const char *suffix = "/.zclassic";
        if (i == 0 && appdata)
            suffix = "/Zclassic";
        else if (i == 1 && home)
            suffix = "/Library/Application Support/Zclassic";

        int n = snprintf(out, out_n, "%s%s/blocks", base, suffix);
        if (n < 0 || (size_t)n >= out_n)
            continue;

        struct stat st;
        if (stat(out, &st) == 0 && S_ISDIR(st.st_mode))
            return true;
    }

    out[0] = '\0';
    return false;
}

static bool boot_legacy_file_path(char *out, size_t out_n,
                                  const char *blocks_dir,
                                  const char *prefix,
                                  int file_index)
{
    if (!out || out_n == 0 || !blocks_dir || !*blocks_dir ||
        !prefix || !*prefix || file_index < 0)
        return false;

    int n = snprintf(out, out_n, "%s/%s%05d.dat", blocks_dir, prefix,
                     file_index);
    return n >= 0 && (size_t)n < out_n;
}

static bool boot_link_or_copy_import_block_file(const char *src,
                                                const char *dst,
                                                const char *prefix,
                                                int file_index,
                                                long long bytes,
                                                bool announce)
{
    struct platform_positioned_file_snapshot source;
    if (!boot_file_snapshot(src, &source))
        return false;
    struct platform_private_file_identity source_id = {
        .volume = source.volume,
        .file = source.file_low,
    };
    bool already_same = false;
    if (platform_private_file_link_no_clobber(src, dst, &source_id,
                                               &already_same)) {
        if (announce && file_index % 10 == 0)
            printf("  linked %s%05d.dat (%lld MB)\n",
                   prefix, file_index, bytes >> 20);
        return true;
    }

    int link_errno = errno;
    if (already_same)
        return true;
    if (announce) {
        printf("  copying %s%05d.dat (%lld MB)...\n",
               prefix, file_index, bytes >> 20);
        fflush(stdout);
    }

    if (platform_private_path_absent(dst) &&
        boot_copy_no_clobber(src, dst, &source))
        return true;

    int copy_errno = errno;
    LOG_WARN("boot",
             "[boot] failed to link/copy %s%05d.dat from %s to %s "
             "(link errno=%d %s, copy errno=%d %s)",
             prefix, file_index, src, dst,
             link_errno, strerror(link_errno),
             copy_errno, strerror(copy_errno));
    return false;
}

struct boot_legacy_block_file_import_result
boot_legacy_import_block_files(const char *legacy_blocks_dir,
                               const char *datadir,
                               int max_files)
{
    struct boot_legacy_block_file_import_result result = {0};

    char dst_blocks_dir[1024];
    if (!boot_legacy_blocks_dir(dst_blocks_dir, sizeof(dst_blocks_dir),
                                datadir)) {
        result.truncated_path = true;
        return result;
    }
    result.destination_ready = true;

    if (!legacy_blocks_dir || !*legacy_blocks_dir || max_files <= 0)
        return result;

    for (int fi = 0; fi < max_files; fi++) {
        char src_path[1200], dst_path[1200];
        if (!boot_legacy_file_path(src_path, sizeof(src_path),
                                   legacy_blocks_dir, "blk", fi) ||
            !boot_legacy_file_path(dst_path, sizeof(dst_path),
                                   dst_blocks_dir, "blk", fi)) {
            result.truncated_path = true;
            break;
        }

        struct platform_positioned_file_snapshot src_st, dst_st;
        if (!boot_file_snapshot(src_path, &src_st)) {
            if (fi > 2)
                break;
            continue;
        }
        result.source_available = true;

        /* Preserve the historical boot behavior: if the blk file already
         * exists with the same size, this index is complete enough for this
         * pass and rev linking is left to the later warm-boot helper. */
        if (boot_file_snapshot(dst_path, &dst_st) &&
            dst_st.size == src_st.size)
            continue;

        int index_failures = 0;
        if (!boot_link_or_copy_import_block_file(
                src_path, dst_path, "blk", fi,
                (long long)src_st.size, true))
            index_failures++;

        if (!boot_legacy_file_path(src_path, sizeof(src_path),
                                   legacy_blocks_dir, "rev", fi) ||
            !boot_legacy_file_path(dst_path, sizeof(dst_path),
                                   dst_blocks_dir, "rev", fi)) {
            result.truncated_path = true;
            break;
        }
        if (boot_file_snapshot(src_path, &src_st)) {
            if (!boot_link_or_copy_import_block_file(
                    src_path, dst_path, "rev", fi,
                    (long long)src_st.size, false))
                index_failures++;
        }

        if (index_failures > 0) {
            result.failures += index_failures;
            LOG_WARN("boot",
                     "[boot] %d zclassicd block-file import operation(s) "
                     "failed for file index %d",
                     index_failures, fi);
        }
    }

    return result;
}

/* Hardlink src -> dst if dst is absent. Returns true only when this call
 * created the link. A failure is counted and its errno remembered (first one
 * wins) so the caller can report the whole pass in one line; EEXIST is not a
 * failure — it means another writer won the race and the file is there. */
static bool boot_legacy_link_if_missing(const char *src, const char *dst,
                                        int *failures, int *first_errno)
{
    struct platform_positioned_file_snapshot existing;
    if (boot_file_snapshot(dst, &existing))
        return false;
    struct platform_positioned_file_snapshot source;
    if (!boot_file_snapshot(src, &source))
        return false;
    struct platform_private_file_identity source_id = {
        .volume = source.volume,
        .file = source.file_low,
    };
    bool already_same = false;
    if (platform_private_file_link_no_clobber(src, dst, &source_id,
                                               &already_same))
        return true;
    if (already_same || boot_file_snapshot(dst, &existing))
        return false;
    if (platform_private_path_absent(dst) &&
        boot_copy_no_clobber(src, dst, &source))
        return true;
    (*failures)++;
    if (*first_errno == 0)
        *first_errno = errno;
    return false;
}

struct boot_legacy_block_file_link_result
boot_legacy_link_missing_block_files(const char *legacy_blocks_dir,
                                     const char *datadir,
                                     int max_files)
{
    struct boot_legacy_block_file_link_result result = {0};

    char dst_blocks_dir[1024];
    if (!boot_legacy_blocks_dir(dst_blocks_dir, sizeof(dst_blocks_dir),
                                datadir)) {
        result.truncated_path = true;
        return result;
    }
    result.destination_ready = true;

    if (!legacy_blocks_dir || !*legacy_blocks_dir || max_files <= 0)
        return result;

    int first_errno = 0;
    for (int fi = 0; fi < max_files; fi++) {
        char src[1200], dst[1200];
        if (!boot_legacy_file_path(src, sizeof(src), legacy_blocks_dir,
                                   "blk", fi) ||
            !boot_legacy_file_path(dst, sizeof(dst), dst_blocks_dir,
                                   "blk", fi)) {
            result.truncated_path = true;
            break;
        }

        struct platform_positioned_file_snapshot ss;
        if (!boot_file_snapshot(src, &ss)) {
            if (fi > 2)
                break;
            continue;
        }
        result.source_available = true;

        /* A missing blk file IS load-bearing: block bodies are read straight
         * out of blk%05d.dat by the refold, catchup, wallet-scan and
         * file-service paths, so a link that silently does not happen shows
         * up much later as an unexplained body-read hole. */
        if (boot_legacy_link_if_missing(src, dst, &result.failures,
                                        &first_errno))
            result.linked++;

        if (!boot_legacy_file_path(src, sizeof(src), legacy_blocks_dir,
                                   "rev", fi) ||
            !boot_legacy_file_path(dst, sizeof(dst), dst_blocks_dir,
                                   "rev", fi)) {
            result.truncated_path = true;
            break;
        }
        /* rev%05d.dat is undo data, and it IS read: bg_validation's
         * read_block_undo() recovers each block's spent outputs from it so the
         * ECDSA script signatures can be checked. A missing rev file does not
         * make the node wrong — the block still advances verified_height on
         * header/structure/shielded proofs and the gap is counted in
         * script_verif_skipped_no_undo — but it silently narrows what
         * "verified" covers. Not counted in `linked` (that counter is
         * historically blk-only), counted in `failures`, which is also the
         * early warning for whatever would hit blk files next (EXDEV across
         * filesystems, ENOSPC, EPERM). */
        if (boot_file_snapshot(src, &ss))
            (void)boot_legacy_link_if_missing(src, dst, &result.failures,
                                              &first_errno);
    }

    /* One aggregated line, not one per file: a cross-filesystem legacy
     * datadir makes every one of the 256 candidates fail identically, and
     * 256 warnings would bury the boot log. */
    if (result.failures > 0)
        LOG_WARN("boot",
                 "[boot] %d legacy block-file hardlink(s) failed while "
                 "linking %s into %s (first errno=%d %s); the blk/rev files "
                 "for those indexes are absent from this datadir — block "
                 "bodies get re-fetched from peers, missing undo data leaves "
                 "those heights script-unverified",
                 result.failures, legacy_blocks_dir, dst_blocks_dir,
                 first_errno, strerror(first_errno));

    return result;
}
