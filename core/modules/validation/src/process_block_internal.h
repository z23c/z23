/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal declarations shared across the process_block_* translation
 * units (process_block.c, process_block_core.c, process_block_index.c,
 * process_block_tip_child.c, process_block_tip_publish.c,
 * process_block_contextual_header.c, process_block_runtime_hooks.c,
 * process_block_failed_child.c,
 * process_block_self_heal.c,
 * process_block_self_heal_hot_loop.c,
 * process_block_self_heal_scan_state.c,
 * process_block_flush_policy.c, process_block_crash_hooks.c). Not intended
 * for use outside this directory; the public surface lives in
 * <validation/process_block.h>. */

#ifndef ZCL_VALIDATION_PROCESS_BLOCK_INTERNAL_H
#define ZCL_VALIDATION_PROCESS_BLOCK_INTERNAL_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "validation/process_block.h"
#include "validation/process_block_internals.h"

struct main_state;
struct coins_view_cache;
struct block_index;
struct transaction;
struct uint256;
struct validation_state;
struct coins_view_sqlite;
struct incremental_merkle_tree;
struct block_tree_db;
struct disk_block_index;
struct node_db;
struct wallet;
struct tx_mempool;

/* ── Defaults / tunables ─────────────────────────────────────── */
#define SELF_HEAL_SCAN_DEFAULT_DEPTH 250000
#define SELF_HEAL_MAX_RECOVERY_ATTEMPTS 100
#define ACTIVE_TIP_CHILD_CONNECT_DEFAULT_LIMIT 128

/* ── Shared file-scope globals (own definitions in named .c file)
 * Exposed here as extern so the split modules can read them
 * without going through getter calls in hot paths. */

/* Owner: process_block_runtime_hooks.c (g_active_block_tree is declared in
 * <validation/process_block.h>; boot assigns it once the tree is open) */
extern volatile sig_atomic_t g_shutdown_requested;      /* defined in boot.c */
extern _Atomic int g_body_pull_active;                  /* public in process_block.h */

/* Owner: process_block_crash_hooks.c */
extern _Atomic int g_test_crash_stage_storage;

/* Owner: process_block_self_heal.c */
extern int s_utxo_fail_count;
extern int s_utxo_fail_height;
extern int s_utxo_hot_loop_reported_height;
extern int s_utxo_activation_paused_height;

/* Owner: process_block_self_heal_scan_state.c */
extern _Atomic uint64_t g_self_heal_tx_index_hits;
extern _Atomic uint64_t g_self_heal_scan_hits;
extern _Atomic uint64_t g_self_heal_scan_exhausted;
extern _Atomic uint64_t g_self_heal_scan_blocks_checked_total;

/* ── Internal helpers shared by the process-block translation units ── */

/* process_block.c */
struct node_db *process_block_node_db_internal(void);
bool process_block_live_height(int height);

/* process_block_runtime_hooks.c */
void process_block_kick_gap_fill(void);
enum process_block_tip_publish_result process_block_publish_tip(
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    bool persist_coins_best,
    const struct process_block_tip_evidence *verified);
enum process_block_tip_publish_result process_block_clear_tip(
    struct main_state *ms,
    const char *reason);
const char *process_block_tip_publish_result_name(
    enum process_block_tip_publish_result result);

/* process_block_crash_hooks.c */
/* Hot-path stage check. Kept inline so the cost is one atomic load per
 * site; the static inline reads the storage variable owned by
 * process_block_crash_hooks.c. */
static inline void process_block_check_crash_stage(
    enum process_block_crash_stage here)
{
    enum process_block_crash_stage armed =
        (enum process_block_crash_stage)atomic_load_explicit(
            &g_test_crash_stage_storage, memory_order_relaxed);
    if (__builtin_expect(armed == here, 0)) {
        fprintf(stderr,
                "[crash-test] process_block: _exit(137) at stage=%s\n",
                process_block_crash_stage_name(here));
        fflush(stderr);
        _exit(137);
    }
}

/* process_block_self_heal.c */
bool process_block_is_missing_utxo_failure(
    const struct validation_state *state);

void process_block_note_utxo_failure(struct main_state *ms,
                                     struct coins_view_cache *coins_tip,
                                     int height,
                                     const char *datadir);

/* process_block_self_heal_hot_loop.c */
void process_block_maybe_write_needs_reimport_flag(int height,
                                                   const char *datadir);
void process_block_maybe_trigger_hot_loop_exit(int height,
                                               const char *datadir);

/* process_block_flush_policy.c */
struct coins_view_sqlite *process_block_coins_sqlite_ptr(void);
bool sapling_tree_persist_once(void);

/* process_block_index.c helpers. find_block_pos +
 * block_index_refresh_header are used by accept_block.c.
 * g_last_block_file_size is updated by accept_block.c after on-disk write.
 * block_index_hydrate_from_disk refreshes imported/restored index entries
 * from verified block bytes. */
struct block_header;
struct disk_block_pos;
bool find_block_pos(struct disk_block_pos *pos, unsigned int block_size,
                    const char *datadir);
void block_index_refresh_header(struct block_index *pindex,
                                const struct block_header *header);
extern unsigned int g_last_block_file_size; /* defined in process_block_index.c */
void block_index_snapshot_for_persist(struct disk_block_index *dbi,
                                      const struct block_index *pindex);
bool block_index_hydrate_from_disk(struct block_index *pindex,
                                   const char *datadir);

/* accept_block_header.c helpers. add_to_block_index is used by the
 * header-admit reducer stage through the public accept_block_header.h
 * contract. process_block_should_skip_contextual_header lives in
 * process_block_contextual_header.c and is declared in
 * <validation/process_block.h> (public). */
struct block_index *add_to_block_index(struct main_state *ms,
                                       const struct block_header *header);

/* process_block_tip_publish.c helpers. update_tip is used by historical
 * tip-publication tests and process-block internals; process_block_commit_tip
 * is also wrapped by
 * process_block_commit_tip_ext for the chain-advance protocol. */
struct coins_view_cache;
bool update_tip(struct main_state *ms, struct block_index *pindex_new);
bool process_block_commit_tip(struct main_state *ms,
                              struct coins_view_cache *coins_tip,
                              struct block_index *new_tip,
                              const char *reason,
                              bool update_header_tip,
                              bool persist_coins_best,
                              const struct process_block_tip_evidence *verified);

/* Chain-selection helpers exposed for keeper tests and active-tip repair
 * paths. */
struct block_index *find_most_work_chain(struct main_state *ms);

/* process_block_tip_child.c helpers exposed for active-tip repair paths. */
bool process_block_verify_active_tip_child_on_disk(
    const struct block_index *candidate,
    const struct block_index *tip,
    const char *datadir);
struct block_index *find_best_active_tip_child(struct main_state *ms,
                                               struct block_index *tip,
                                               const char *datadir);
struct block_index *find_verified_unlinked_active_tip_child(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir);

#endif /* ZCL_VALIDATION_PROCESS_BLOCK_INTERNAL_H */
