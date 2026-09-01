/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "models/chain_snapshot.h"
#include <stdio.h>
#include <string.h>

bool chain_snapshot_validate(struct chain_snapshot *snap)
{
    snap->src_valid = false;
    memset(&snap->blocks, 0, sizeof(snap->blocks));
    memset(&snap->index, 0, sizeof(snap->index));
    memset(&snap->chainstate, 0, sizeof(snap->chainstate));

    struct ar_errors errors;
    ar_errors_clear(&errors);
    validates_string_present(&errors, snap->src_dir, "src_dir");
    validates_string_present(&errors, snap->dst_dir, "dst_dir");
    if (ar_errors_any(&errors)) {
        char msg[512];
        ar_errors_full_messages(&errors, msg, sizeof(msg));
        printf("chain_snapshot: invalid: %s\n", msg);
        return false;
    }

    /* Build owned path buffers */
    snprintf(snap->blocks_src, sizeof(snap->blocks_src),
             "%s/blocks", snap->src_dir);
    snprintf(snap->blocks_dst, sizeof(snap->blocks_dst),
             "%s/blocks", snap->dst_dir);
    snprintf(snap->index_src, sizeof(snap->index_src),
             "%s/blocks/index", snap->src_dir);
    snprintf(snap->index_dst, sizeof(snap->index_dst),
             "%s/blocks/index", snap->dst_dir);
    snprintf(snap->cs_src, sizeof(snap->cs_src),
             "%s/chainstate", snap->src_dir);
    snprintf(snap->cs_dst, sizeof(snap->cs_dst),
             "%s/chainstate", snap->dst_dir);

    /* Wire child models to owned buffers */
    snap->blocks.src_dir = snap->blocks_src;
    snap->blocks.dst_dir = snap->blocks_dst;
    snap->index.src_dir = snap->index_src;
    snap->index.dst_dir = snap->index_dst;
    snap->chainstate.src_dir = snap->cs_src;
    snap->chainstate.dst_dir = snap->cs_dst;

    /* ── Validate BlockData ── */
    if (!block_data_validate(&snap->blocks, &errors)) {
        char msg[512];
        ar_errors_full_messages(&errors, msg, sizeof(msg));
        printf("chain_snapshot: block_data invalid: %s\n", msg);
        return false;
    }

    /* ── Validate block index LevelDB (optional) ── */
    snap->src_has_index = leveldb_store_validate(&snap->index, &errors);

    /* ── Validate chainstate LevelDB ── */
    if (!leveldb_store_validate(&snap->chainstate, &errors)) {
        char msg[512];
        ar_errors_full_messages(&errors, msg, sizeof(msg));
        printf("chain_snapshot: chainstate invalid: %s\n", msg);
        return false;
    }

    /* Populate legacy accessors */
    snap->src_block_files = snap->blocks.num_blk_files;
    snap->src_blocks_bytes = snap->blocks.blk_bytes + snap->blocks.rev_bytes;
    snap->src_chainstate_bytes = snap->chainstate.total_bytes;
    snap->src_valid = true;

    printf("chain_snapshot: validated %d block files (%.1f GB), "
           "chainstate %.0f MB, index=%s\n",
           snap->src_block_files,
           (double)snap->src_blocks_bytes / (1024.0 * 1024.0 * 1024.0),
           (double)snap->src_chainstate_bytes / (1024.0 * 1024.0),
           snap->src_has_index ? "yes" : "no");
    return true;
}

bool chain_snapshot_save(struct chain_snapshot *snap)
{
    if (!snap->src_valid)
        return false;

    snap->copy_blocks_ok = block_data_save(&snap->blocks);
    if (snap->src_has_index) {
        snap->index.label = "block_index";
        snap->copy_index_ok = leveldb_store_save(&snap->index);
    } else {
        snap->copy_index_ok = false;
    }
    snap->chainstate.label = "chainstate";
    snap->copy_chainstate_ok = leveldb_store_save(&snap->chainstate);
    snap->files_copied = snap->src_block_files;

    printf("chain_snapshot: copy complete. blocks=%s index=%s chainstate=%s\n",
           snap->copy_blocks_ok ? "ok" : "FAIL",
           snap->copy_index_ok ? "ok" : "FAIL",
           snap->copy_chainstate_ok ? "ok" : "FAIL");
    return snap->copy_blocks_ok && snap->copy_chainstate_ok;
}
