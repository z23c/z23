/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * undo_rev_index — a self-verifying locator for zclassicd undo (rev) records.
 *
 * A node seeded from a consensus bundle clears BLOCK_HAVE_UNDO and nUndoPos
 * below the seed, yet the zclassicd revNNNNN.dat files are still in
 * <datadir>/blocks. Each record is
 *     [4-byte network magic][u32 LE size][CBlockUndo bytes][32-byte checksum]
 * with checksum = double-SHA256(parent block hash || CBlockUndo bytes), the
 * UndoWriteToDisk binding. The record does not name its block, so it is found
 * by trying the parent hash against a record's checksum.
 *
 * A record is accepted ONLY when that checksum matches AND the undo
 * deserializer consumes exactly the framed payload. No offset is trusted, and
 * nothing is written or persisted: the in-memory slot lists (offset and size
 * per record, at most two rev files at a time) are the whole state. */

#ifndef ZCL_UNDO_REV_INDEX_H
#define ZCL_UNDO_REV_INDEX_H

#include "coins/undo.h"
#include "core/uint256.h"
#include "platform/positioned_file.h"
#include "util/sync.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UNDO_REV_CACHE_FILES 2
#define UNDO_REV_MAGIC_SIZE 4

enum undo_rev_status {
    UNDO_REV_FOUND = 0,   /* verified record deserialized into *out */
    UNDO_REV_NOT_FOUND,   /* rev files read, no record binds this parent */
    UNDO_REV_AMBIGUOUS,   /* two records pass checksum and shape */
    UNDO_REV_NO_FILE,     /* no rev file could be opened */
    UNDO_REV_ERROR,       /* bad arguments or allocation failure */
};

struct undo_rev_slot {
    uint64_t offset;      /* start of the CBlockUndo bytes */
    uint32_t size;        /* CBlockUndo byte count (checksum follows) */
};

struct undo_rev_cached_file {
    int file_no;          /* -1 when the entry is empty */
    struct platform_positioned_file file;
    struct undo_rev_slot *slots;
    size_t count;
    size_t capacity;
};

struct undo_rev_locator {
    char datadir[512];
    unsigned char magic[UNDO_REV_MAGIC_SIZE];
    struct undo_rev_cached_file cache[UNDO_REV_CACHE_FILES];
    int mru;              /* cache index used last; the other is evicted */
    int cursor_file;      /* file of the last hit, -1 when cold */
    size_t cursor_slot;   /* the record expected next in that file */
    unsigned full_misses; /* consecutive lookups that scanned and found nothing */
    zcl_mutex_t lock;
};

bool undo_rev_locator_init(struct undo_rev_locator *loc, const char *datadir,
                           const unsigned char magic[UNDO_REV_MAGIC_SIZE]);
void undo_rev_locator_free(struct undo_rev_locator *loc);

typedef bool (*undo_rev_accept_fn)(const struct block_undo *undo, void *ctx);

/* Find and parse the undo record bound to `parent` (the hash of the block's
 * PARENT). hint_file < 0 means unknown; a known file is tried first. On
 * UNDO_REV_FOUND *out owns its allocations (block_undo_free); on any other
 * status *out is empty. */
enum undo_rev_status undo_rev_locator_read(struct undo_rev_locator *loc,
                                           const struct uint256 *parent,
                                           int hint_file,
                                           undo_rev_accept_fn accept, void *accept_ctx,
                                           struct block_undo *out);

/* Process-wide locator behind its own lock, for the validation walk and the
 * sampler. Re-initialised when datadir or magic change. */
enum undo_rev_status undo_rev_shared_read(
    const char *datadir, const unsigned char magic[UNDO_REV_MAGIC_SIZE],
    const struct uint256 *parent, int hint_file, undo_rev_accept_fn accept,
    void *accept_ctx, struct block_undo *out);

#endif /* ZCL_UNDO_REV_INDEX_H */
