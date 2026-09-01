/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_PROCESS_BLOCK_H
#define ZCL_VALIDATION_PROCESS_BLOCK_H

#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include <stdbool.h>
#include <stdatomic.h>

#define MIN_BLOCKS_TO_KEEP 288

struct self_heal_scan_stats {
    uint64_t tx_index_hits;
    uint64_t scan_hits;
    uint64_t scan_exhausted;
    uint64_t scan_blocks_checked_total;
};

bool accept_block_header(const struct block_header *header,
                         struct validation_state *state,
                         struct main_state *ms,
                         const struct chain_params *params,
                         struct block_index **ppindex);

/* The historical block-connection entry points were deleted by the reducer
 * refactor. reducer_ingest_block / reducer_kick (see
 * services/chain_activation_service.h) are now the sole block-connect
 * engine. accept_block_header (below) survives because header admit still
 * uses it. */

/* Fast-sync body-pull / direct-import mode flag.
 *
 * When set to 1 by legacy_body_pull / legacy_direct_import before its
 * ingest loop, the per-block validation path defers durability writes:
 *
 *   - block_tree_db_write_block_index_sync → async (no fsync per block).
 *   - block_tree_db_write_tx_index         → async (LevelDB memtable).
 *   - wallet_sync_transaction / Sapling trial-decrypt → skipped (a
 *     single wallet_rescan runs at the end of the import).
 *
 * Caller MUST clear back to 0 after the loop. Crash safety is still
 * provided by coins.db's per-block commit (at-tip kill-9 invariant).
 *
 * This is the dominant per-block cost after defer_proof_validation_below
 * evidence-mode strips ECDSA + Groth16 + Ed25519. Throughput depends on the
 * bulk-ingest writer path batching durability work behind this flag. */
extern _Atomic int g_body_pull_active;

void process_block_self_heal_stats_snapshot(
    struct self_heal_scan_stats *out);
int process_block_self_heal_scan_depth_limit(void);
bool process_block_self_heal_scan_enabled(void);

struct node_db;
void process_block_set_node_db(struct node_db *ndb);

/* Optional app-owned wakeup hook for the background body gap filler.
 * Validation owns chain selection; boot owns the service implementation. */
typedef void (*process_block_gap_fill_kick_fn)(void *ctx);
void process_block_set_gap_fill_kick(process_block_gap_fill_kick_fn fn,
                                     void *ctx);

/* Active block-index database. Owned and opened by the composition root,
 * which publishes it here once the tree is open; NULL until then and in
 * tests that never open one. Declared in validation because that is where
 * the definition lives -- config/ sits ABOVE lib/, so the pointer cannot be
 * defined up there and read back down by name. */
struct block_tree_db;
extern struct block_tree_db *g_active_block_tree;

/* The composition root's single chain-activation controller. Validation
 * decides what became invalid or valid again; the reducer owns acting on
 * it. The controller instance is boot-owned, so validation reaches it
 * through this hook rather than naming a config/ symbol. Returns NULL when
 * unregistered, and every call site already treats that as "no reducer to
 * kick". */
struct chain_activation_controller;
typedef struct chain_activation_controller *
    (*process_block_activation_controller_fn)(void);
void process_block_set_activation_controller(
    process_block_activation_controller_fn fn);
struct chain_activation_controller *process_block_activation_controller(void);

struct process_block_tip_evidence {
    bool header_ancestry_linked;
    bool chainwork_recomputed;
    bool nakamoto_selected_best_work;
    bool block_bytes_hash_checked;
    bool utxo_sha3_verified;
    bool mmb_flyclient_proof_verified;
    bool chunk_hash_coverage_verified;
    bool full_validation_complete;
};

enum process_block_tip_publish_result {
    PROCESS_BLOCK_TIP_PUBLISH_OK = 0,
    PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED,
    PROCESS_BLOCK_TIP_PUBLISH_REJECTED_DB_BUSY,
    PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST,
    PROCESS_BLOCK_TIP_PUBLISH_REJECTED,
};

/* Boot-owned publication hooks for active-tip changes. Validation owns
 * connect/selection decisions; boot owns the app service/repository boundary
 * that publishes those decisions. */
typedef enum process_block_tip_publish_result
(*process_block_commit_tip_fn)(
    void *ctx,
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    bool persist_coins_best,
    const struct process_block_tip_evidence *verified);

typedef enum process_block_tip_publish_result
(*process_block_clear_tip_fn)(void *ctx,
                              struct main_state *ms,
                              const char *reason);

void process_block_set_tip_publication_hooks(
    process_block_commit_tip_fn commit_tip,
    process_block_clear_tip_fn clear_tip,
    void *ctx);

/* Configure the coins flush policy (short-term → long-term layer bridge).
 * block_interval=0 disables block-based flushing (default).
 * During IBD, set block_interval=1000 for aggressive batching. */
void set_flush_policy(int64_t interval_secs, size_t max_entries,
                      int block_interval);

/* Set the SQLite handle for UTXO commitment persistence.
 * Must be called before any blocks are processed. */
struct coins_view_sqlite;
void set_coins_sqlite_for_commitment(struct coins_view_sqlite *cvs);
void set_sapling_tree_for_flush(struct incremental_merkle_tree *tree);

/* Configure the flat-file sapling checkpoint path. Call once
 * from boot.c with the node's datadir; the helper derives
 * `<datadir>/sapling_tree_ckpt.dat`. After this is set, the commit
 * path flushes the checkpoint every `SAPLING_CHECKPOINT_BLOCK_INTERVAL`
 * blocks so crash-recovery replays ≤ that many blocks instead of the
 * full 2.6M-block Sapling history. Passing NULL disables the
 * checkpoint (used by unit tests). */
void set_sapling_checkpoint_datadir(const char *datadir);

/* Read back the configured flat-file sapling checkpoint path (the
 * `<datadir>/sapling_tree_ckpt.dat` derived by the setter above), or NULL when
 * no datadir was set.  Lets a recovery path load the verified frontier the node
 * already maintains without re-deriving the datadir. */
const char *sapling_checkpoint_path(void);

/* ── Flat-file sapling checkpoint: write + introspection ─────────
 *
 * The load/resume path already existed (boot + sapling_tree_rebuild);
 * these wire the periodic WRITE that was previously unimplemented, so a
 * clean restart resumes replay from the last checkpoint (≤
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL blocks) instead of re-folding the
 * whole Sapling history. `set_sapling_checkpoint_datadir` must have been
 * called first (a NULL/empty path makes every call a safe no-op).
 *
 * `tree` is serialized and written keyed by {height, block_hash, root}.
 * Rate-limited: an actual on-disk write happens at most once every
 * SAPLING_CHECKPOINT_BLOCK_INTERVAL calls unless `force` is true (used at
 * catchup completion / shutdown). Returns true iff a write occurred.
 *
 * BOUND TO THE REDUCER FOLD CURSOR: a call whose `height` exceeds the
 * reducer's own applied frontier (coins_applied_height - 1, derived via
 * reducer_frontier_derive_coins_best_now) is refused regardless of `force`
 * — the checkpoint file must never be stamped at a height the reducer has
 * not itself provably applied. Without this bound, a fast-moving projection
 * lane (e.g. node_db_catchup_service, which is not gated on proof
 * validation and can race far ahead of utxo_apply) can overwrite a
 * previously-good, in-window checkpoint with one the empty-frontier healer
 * (sapling_anchor_frontier_unavailable.c tier1) and boot.c's own load-verify
 * path can no longer trust. When the reducer frontier cannot be derived
 * (legacy/pre-migration datadir, hermetic caller with no progress_store
 * open) this fails OPEN — unchanged pre-existing behavior. */
#define SAPLING_CHECKPOINT_BLOCK_INTERVAL 10000
struct incremental_merkle_tree;
bool sapling_tree_flat_checkpoint_note(
    const struct incremental_merkle_tree *tree, int64_t height,
    const uint8_t block_hash[32], bool force);

/* Load-side outcome for the flat-file sapling checkpoint, surfaced via the
 * `z23 dumpstate sapling_checkpoint`. */
enum sapling_ckpt_load_result {
    SAPLING_CKPT_LOAD_NONE = 0,     /* no load attempted yet */
    SAPLING_CKPT_LOAD_ABSENT,       /* no file / read error → full replay */
    SAPLING_CKPT_LOAD_VERIFIED,     /* loaded + binding verified → fast resume */
    SAPLING_CKPT_LOAD_DISCARDED,    /* loaded but binding failed → deleted + replay */
};
void sapling_ckpt_record_load(enum sapling_ckpt_load_result result,
                              int64_t height, const char *detail);

/* Snapshot of flat-file checkpoint activity for diagnostics. */
struct sapling_ckpt_stats {
    int64_t last_write_height;   /* -1 if never written this run */
    int64_t writes;              /* successful on-disk writes */
    int64_t write_fails;         /* failed write attempts */
    int64_t last_load_height;    /* height of the last load attempt (-1) */
    int          last_load_result;   /* enum sapling_ckpt_load_result */
    char         last_load_detail[32];
    char         path[512];      /* configured checkpoint path ("" if unset) */
};
void sapling_ckpt_get_stats(struct sapling_ckpt_stats *out);

/* test-only surface: drives update_tip directly so a unit test
 * can verify tip-publisher rejection propagates to the caller.
 * Returns false if the publisher refused the commit; returns true if the
 * tip was advanced (or cleared, when pindex_new == NULL). Do NOT
 * call from production code — go through reducer tip-finalization or an
 * explicit trusted bootstrap/repair API. */
bool process_block_test_update_tip(struct main_state *ms,
                                    struct block_index *pindex_new);

/* Test-only crash-injection hook for the tip-publication ordering protocol.
 *
 * The atomicity test (test_chain_advance_atomicity.c) forks a child,
 * arms a crash stage with `process_block_test_set_crash_stage(...)`,
 * runs one block through the reducer/tip publication path, and the child
 * `_exit(137)`s at the named protocol point. The parent reboots the datadir,
 * asserts
 * tip ≥ pre-kill tip.
 *
 * Stages fire in order:
 *   PBCS_AFTER_CONNECT_BLOCK     in-mem coins view mutated, nothing on disk
 *   PBCS_AFTER_COINS_VIEW_FLUSH  coins cache → coins_tip (RAM), still no disk
 *   PBCS_AFTER_UPDATE_TIP        tip publisher done; in-memory tip advanced
 *   PBCS_AFTER_BLOCK_INDEX_WRITE LevelDB block_index entry durable
 *   PBCS_AFTER_COINS_DISK_FLUSH  coins.db UTXOs durable and not ahead of index
 *
 * Default PBCS_NONE: hook is a no-op (one atomic_load + branch per
 * stage; negligible). Production never sets a stage. */
enum process_block_crash_stage {
    PBCS_NONE = 0,
    PBCS_AFTER_CONNECT_BLOCK,
    PBCS_AFTER_COINS_VIEW_FLUSH,
    PBCS_AFTER_UPDATE_TIP,
    PBCS_AFTER_BLOCK_INDEX_WRITE,
    PBCS_AFTER_COINS_DISK_FLUSH,
    PBCS_NUM_STAGES
};

const char *process_block_crash_stage_name(enum process_block_crash_stage s);

/* result codes for process_block_propagate_failed_child. Values
 * are stable and tested directly; add new codes at the end. */
enum propagate_failed_child_result {
    PROPAGATE_FAILED_CHILD_OK                 =  0, /* walk ran; propagated_out set */
    PROPAGATE_FAILED_CHILD_SKIP_PARENT_FAILED =  1, /* OOM guard (see below) */
    PROPAGATE_FAILED_CHILD_SKIP_RATE_LIMITED  =  2, /* OOM guard (see below) */
    PROPAGATE_FAILED_CHILD_MALLOC_FAILED      = -1, /* allocator returned NULL */
};

/* minimum wall-clock interval between full propagation walks
 * when the caller opts into rate-limiting (non-NULL last_propagate_sec).
 * At a live-tip block_map size of ~3M entries, each walk is ~24 MB of
 * scratch + an O(N log N) qsort; firing once per FSM flap event can
 * pin the node under sustained RSS + CPU pressure. Ten seconds lets
 * genuine back-to-back validation failures still propagate without
 * amplifying a stall into resource exhaustion. */
#define PROPAGATE_FAILED_CHILD_MIN_INTERVAL_SEC 10

/* test-only surface: propagate BLOCK_FAILED_CHILD from a failed
 * `pindex_root` through all descendants recorded in `map`. Caller
 * MUST have set a BLOCK_FAILED_MASK bit on pindex_root itself before
 * invoking.
 *
 * Guards (prevent an OOM amplifier):
 *   - SKIP_PARENT_FAILED when pindex_root->pprev is itself already in
 *     BLOCK_FAILED_MASK. The prior propagation from the ancestor
 *     already covered this subtree; re-walking the block_map would
 *     burn ~24 MB + O(N log N) to accomplish nothing.
 *   - SKIP_RATE_LIMITED when last_propagate_sec is non-NULL AND
 *     now_sec - *last_propagate_sec < PROPAGATE_FAILED_CHILD_MIN_INTERVAL_SEC.
 *     Callers that need an unconditional walk (tests, explicit flush
 *     paths) pass last_propagate_sec=NULL. On OK return with a non-NULL
 *     pointer, *last_propagate_sec is updated to now_sec.
 *
 * On OK return, *propagated_out (may be NULL) receives the count of
 * descendants newly marked; unchanged on SKIP or MALLOC_FAILED. */
enum propagate_failed_child_result
process_block_propagate_failed_child(struct block_map *map,
                                      const struct block_index *pindex_root,
                                      time_t now_sec,
                                      time_t *last_propagate_sec,
                                      size_t *propagated_out);

/* decide whether to bypass contextual_check_block_header for
 * an incoming header. Returns true when the check would spuriously
 * fail, i.e. one of:
 *
 *  (a) Old-IBD / scrambled-height case (pre-existing behavior):
 *      tip > 100000 AND pindex_prev->nHeight < tip - 1000.
 *
 * (b) Post-FlyClient-snapshot tail (new ):
 *      the PoW averaging window cannot be walked back contiguously
 *      from pindex_prev for `consensus->nPowAveragingWindow` steps.
 *      Hit when the snapshot placed a tip_h whose pprev chain is
 *      not populated for the tail region, causing
 *      GetNextWorkRequired to return the weakest-allowed nBits and
 *      every real peer's batch to reject with bad-diffbits.
 *
 * NULL pindex_prev returns false (the caller's existing NULL check
 * handles that branch). NULL ms or consensus is undefined. */
bool process_block_should_skip_contextual_header(
    const struct main_state *ms,
    const struct block_index *pindex_prev,
    const struct consensus_params *consensus);

void process_block_clear_utxo_activation_pause_range(int scan_start,
                                                     int scan_end);

/* expose paused-height so the sync watchdog can
 * detect when activation has been silently paused after an unrecovered
 * UTXO mismatch. Returns -1 when activation is not paused.
 *
 * The pause state is set inside
 * process_block_maybe_trigger_hot_loop_exit() at
 * core/modules/validation/src/process_block_self_heal_hot_loop.c — specifically
 * the branch that fires when a reimport attempt was already made
 * recently (last_reimport_attempted marker) and still failed to heal the
 * chain, so the hot-loop exit refuses to auto-restart and pauses instead.
 * That helper is reached through the self-heal failure coordinator
 * (process_block_note_utxo_failure() in process_block_self_heal.c), not
 * from process_block.c directly. Without watchdog coverage the sync state
 * stays in BLOCKS_DOWNLOAD with no height progress event — invisible. */
int process_block_get_utxo_activation_paused_height(void);

/* Signal that a staged activation drain reached the per-pass
 * tip_child_connect_limit (128 blocks by default) and may have more children
 * ready to connect. The activation controller drain loop should schedule
 * another reducer pass when this is true even if deferred_pending is 0.
 * Cleared at the start of each drain pass. */
bool process_block_active_tip_has_pending(void);

#ifdef ZCL_TESTING
void process_block_test_set_utxo_fail_state(int height, int count);
int  process_block_test_get_utxo_fail_count(void);
int  process_block_test_get_utxo_activation_paused_height(void);
/* directly set the pause height to drive watchdog tests
 * without exercising the full hot-loop-exit failure path. */
void process_block_test_set_utxo_activation_paused_height(int height);
void process_block_test_trigger_hot_loop_check(int height,
                                               const char *datadir);
void process_block_test_note_utxo_failure(int height, const char *datadir);
void process_block_test_fail_next_sapling_persists(int n);
bool process_block_test_persist_sapling_tree(bool force);
extern _Atomic bool g_sapling_tree_rebuilding;
/* Exercise the real nakamoto_selected_best_work predicate
 * (process_block_tip_is_best_work) directly: returns true when no
 * connectable competing chain beats `tip` in map_block_index. Used by
 * the torn-index regression to prove a stale/torn higher-work fork above
 * tip does NOT veto promotion, while a genuine linked higher-work fork
 * still does. */
bool process_block_test_tip_is_best_work(const struct main_state *ms,
                                         const struct block_index *tip);
#endif

#endif
