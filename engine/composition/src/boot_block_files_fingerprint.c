/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reads the fingerprint of the block files under <datadir>/blocks that the
 * clean-shutdown marker records, so a verified fast restart can tell that no
 * block file changed while the node was down. */

#include "config/boot_block_files_fingerprint.h"

#include "config/boot_shutdown_marker.h"
#include "base/serialize_le.h"
#include "platform/file_metadata.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

enum { BOOT_BLOCK_FILE_SLOTS = 256 };

static void bbf_put_u64(struct sha3_256_ctx *h, uint64_t v)
{
    unsigned char b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(h, b, sizeof(b));
}

/* Hash one file's identity. True when the slot holds a regular file, false
 * with *refused unset when it is absent, false with *refused set when the
 * entry exists but is not a plain regular file. */
static bool bbf_add_slot(struct sha3_256_ctx *h, const char *path,
                         uint64_t slot, bool *refused)
{
    struct platform_file_metadata md;
    enum platform_file_metadata_result r =
        platform_file_metadata_read(path, &md);
    if (r == PLATFORM_FILE_METADATA_MISSING)
        return false;
    if (r != PLATFORM_FILE_METADATA_OK) {
        *refused = true;
        return false;
    }
    bbf_put_u64(h, slot);
    bbf_put_u64(h, md.size);
    bbf_put_u64(h, (uint64_t)md.modified_seconds);
    bbf_put_u64(h, md.modified_nanoseconds);
    return true;
}

bool boot_block_files_fingerprint_read(
    const char *datadir, struct boot_block_files_fingerprint *out)
{
    if (!datadir || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    char path[1100];
    bool refused = false;
    uint32_t count = 0;
    for (int i = 0; i < BOOT_BLOCK_FILE_SLOTS && !refused; i++) {
        int n = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", datadir,
                         i);
        if (n < 0 || (size_t)n >= sizeof(path))
            return false;
        if (bbf_add_slot(&h, path, (uint64_t)i, &refused))
            count++;
    }
    int n = snprintf(path, sizeof(path), "%s/blocks/blk_sync.dat", datadir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    if (!refused && bbf_add_slot(&h, path, BOOT_BLOCK_FILE_SLOTS, &refused))
        count++;
    if (refused || count == 0)
        return false;
    out->count = count;
    sha3_256_finalize(&h, out->sha3);
    return true;
}

bool boot_block_files_scan_may_skip(
    bool fast_restart_taken, const struct shutdown_clean_binding *recorded,
    const struct boot_block_files_fingerprint *now)
{
    return fast_restart_taken && recorded && recorded->fr_valid &&
           recorded->bf_valid && now && recorded->bf_count == now->count &&
           memcmp(recorded->bf_sha3, now->sha3, sizeof(now->sha3)) == 0;
}
