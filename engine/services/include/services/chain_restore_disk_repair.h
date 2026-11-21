/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Disk Repair — disk-backed active-chain reconstruction helpers. */

#ifndef ZCL_CHAIN_RESTORE_DISK_REPAIR_H
#define ZCL_CHAIN_RESTORE_DISK_REPAIR_H

struct main_state;
struct block_index;
struct active_chain;

/* Rebuild missing active-chain skips bottom-up; caller keeps slots stable. */
void chain_restore_rebuild_skip_from_genesis(struct active_chain *c, int tip_h);

int chain_restore_rebuild_active_chain_from_disk(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir);

int chain_restore_rebuild_active_chain_from_block_files(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir);

#endif /* ZCL_CHAIN_RESTORE_DISK_REPAIR_H */
