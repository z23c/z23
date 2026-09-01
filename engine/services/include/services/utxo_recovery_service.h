/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO Recovery Service — boot-time UTXO wipe, import, restore, and
 * integrity operations, all gated through recovery_policy.
 *
 * Invariant
 * ---------
 * Every destructive UTXO operation (wipe, import, restore) is policy-gated:
 * an unguarded recovery path can wipe the entire UTXO set.
 *
 * All functions take explicit parameters — no globals.
 */

#ifndef ZCL_SERVICES_UTXO_RECOVERY_SERVICE_H
#define ZCL_SERVICES_UTXO_RECOVERY_SERVICE_H

#include <stdbool.h>
#include <stdint.h>
#include "core/uint256.h"
#include "services/chain_state_validator.h"
#include "util/result.h"

/* Forward declarations */
struct sqlite3;
struct main_state;
struct coins_view_sqlite;
struct coins_view_cache;
struct node_db;
struct chain_params;
struct block_index;
struct chain_activation_controller;
struct db_service;

/* ── Context for recovery operations ───────────────────────── */

struct utxo_recovery_ctx {
    struct main_state *state;
    struct coins_view_sqlite *coins_sqlite;
    struct coins_view_cache *coins_tip;
    struct node_db *ndb;
    const char *datadir;
    const struct chain_params *params;
    struct chain_activation_controller *activation_ctl;
    struct db_service *db_service;   /* NULL if not started */
};

/* ── Policy-gated UTXO wipe ───────────────────────────────── */

/* Wipe the UTXO set after checking recovery_policy.
 * Returns ZCL_OK if the wipe was allowed and executed; a policy ZCL_ERR
 * (code -41) if recovery_policy refused; a persistence ZCL_ERR (code -42)
 * if node_db_wipe_utxos failed to delete the rows.
 * `reason` is a grep-able tag, e.g. "boot.reimport_utxos_flag".
 * This is the gate that stands between a bug and a wiped UTXO set.
 * Do not bypass. */
struct zcl_result utxo_recovery_wipe(struct node_db *ndb, const char *reason);

/* ── Auto-reimport flag ───────────────────────────────────── */

/* Prepare for reimport: clear migration flag (the actual UTXO wipe
 * happens at the start of utxo_recovery_import_ldb). Returns ZCL_OK on
 * success, or a persistence ZCL_ERR if clearing the flag failed. */
struct zcl_result utxo_recovery_prepare_reimport(struct node_db *ndb);

/* ── LDB→SQLite UTXO import ──────────────────────────────── */

struct utxo_import_result {
    struct zcl_result status; /* rich status for service-result discipline */
    bool imported;          /* UTXOs were successfully imported */
    bool skip_activate;     /* caller should skip reducer activation */
    int height;             /* discovered import height */
    uint64_t utxo_count;    /* number of UTXOs imported */
    char anchor_reason[64]; /* activation anchor reason, if set */
};

/* Import UTXOs from LevelDB chainstate to SQLite.
 * Handles: LOCK file copy, policy-gated wipe, SHA3 verification,
 * chain tip / anchor creation. */
struct utxo_import_result utxo_recovery_import_ldb(
    struct utxo_recovery_ctx *ctx);

/* Point-in-time copy of a (possibly live) zclassicd chainstate LevelDB from
 * cs_path to import_path.  Retries until no source file changed while the copy
 * ran, so the image can never be torn mid-write; refuses with a non-ok
 * zcl_result if the source never goes quiet.  Never touches cs_path (the copied
 * LOCK, if any, is the caller's to remove).  Implemented in
 * utxo_recovery_ldb_copy.c — exposed so the borrowed-frontier cure
 * (sapling_anchor_frontier_unavailable tier-1b) can borrow a live chainstate
 * read-only. */
struct zcl_result utxo_recovery_copy_chainstate_stable(const char *cs_path,
                                                       const char *import_path);

/* ── Chain tip restoration ───────────────────────────────── */

struct chain_restore_result {
    struct zcl_result status; /* rich status for service-result discipline */
    bool restored;          /* chain tip was successfully restored */
    bool skip_activate;     /* caller should skip reducer activation */
    int restored_height;    /* restored tip height, -1 if none */
    struct uint256 restored_hash; /* restored tip hash, null if none */
    char anchor_reason[64]; /* activation anchor reason, if set */
};

/* Restore chain tip from coins DB best block hash.
 * Creates placeholder anchor if coins_best_block is ahead of index.
 * Falls back to fast_rebuild_chainstate if coins DB is empty. When the
 * canonical coins store is wired AND genuinely empty (pre-fold instant-on
 * with prefetched bodies ahead of the validated headers), the scan_fallback
 * commit is rolled back to genesis — a tip with no state behind it is a
 * phantasm. An unwired (NULL) coins view keeps the legacy anchor commit. */
struct chain_restore_result utxo_recovery_restore_chain_tip(
    struct utxo_recovery_ctx *ctx,
    struct block_index *scan_fallback);

/* The Invariant A INDEX authority: true iff `bi` is hash-linked
 * (contiguous pprev, height decrementing by exactly 1) down to a trust
 * root — genesis, the compiled SHA3 UTXO anchor extent, or a root at
 * anchor/anchor+1 (snapshot-anchored nodes). A detached island rooted
 * above the anchor is NOT derivable state no matter what the progress
 * logs or the coins cursor claim — even a fabricated anchor row can vouch
 * for a detached island otherwise.
 * Every boot-time tip PROMOTION of a real block must pass this before
 * reaching CSR. O(height - anchor) pointer hops; boot/recovery only. */
bool utxo_recovery_block_trust_rooted(const struct block_index *bi);

/* The walker behind utxo_recovery_block_trust_rooted, exposed so the
 * header-band planner can name the island root: returns NULL when `bi`
 * is trust-rooted, else the island root — the lowest contiguously
 * pprev-linked ancestor of `bi` (descent breaks on pprev==NULL or a
 * height tear above the anchor extent). NULL input returns NULL
 * (callers gate on a real block first). */
const struct block_index *utxo_recovery_block_ancestry_break(
    const struct block_index *bi);

/* ── Scoped ancestry-height relink (LDB-import header-only tear) ─────── */

/* Typed-blocker id raised when utxo_recovery_relink_scrambled_ancestry finds a
 * GENUINE hash-linkage break (a NULL/foreign parent above the attested SHA3
 * anchor extent) rather than a repairable height-label scramble. Fail-closed:
 * the repair changes nothing and names this blocker so the header-band planner /
 * operator drives the missing-parent backfill. Carries coins_tip / refuse_at /
 * anchor in its reason. */
#define UTXO_RECOVERY_ANCESTRY_TEAR_BLOCKER_ID "utxo_recovery.ancestry_tear"

enum utxo_recovery_ancestry_repair_result {
    UTXO_ANCESTRY_REPAIR_NOOP = 0,   /* tip already trust-rooted — nothing done */
    UTXO_ANCESTRY_REPAIR_FIXED,      /* relabeled >=1 header-only height(s); tip now trust-rooted */
    UTXO_ANCESTRY_REPAIR_REFUSED,    /* genuine hash-linkage break — typed blocker set, no mutation */
};

struct utxo_recovery_ancestry_repair {
    enum utxo_recovery_ancestry_repair_result result;
    int32_t fixed;           /* count of height labels corrected (FIXED path) */
    int32_t island_root_h;   /* detected island-root height (context), -1 if none */
    int32_t refuse_at_h;     /* height of the hash-linkage break (REFUSED), -1 otherwise */
};

/* SCOPED, non-destructive ancestry-height relink for the LDB-import
 * header-only height-tear class.
 *
 * FAILURE THIS CURES: an LDB import can scramble the stored nHeight of a
 * HEADER-ONLY ancestor below the reducer window, so `tip`'s pprev chain is
 * hash-linked (contiguous parent pointers) but height-torn — Invariant A
 * (utxo_recovery_block_ancestry_break) then correctly refuses the (real) coins
 * tip as a detached island, active_chain_tip() stays NULL, and the consensus
 * bundle install refuses (before_consistent=0). Neither boot repair pass reaches
 * it: block_index_repair_heights/_pprev are watermark-gated AND the pprev pass
 * reads the block BODY (header-only nodes have none and are skipped).
 *
 * WHAT IT DOES: walks `tip`'s ancestry down its pprev links (the block-index
 * STORE's own hash linkage — set at load from each record's prev_hash, so this
 * is header-only-INCLUSIVE and never reads a block body), tracking the
 * authoritative height from the trusted coins tip (decrement by 1 per hop). For
 * each parent whose stored nHeight disagrees with child.nHeight-1 while the hash
 * linkage AGREES (parent is a genuine, self-consistent node in the map), it
 * corrects the label. A NULL/foreign parent ABOVE the attested SHA3 anchor
 * extent is a real linkage break, NOT a label scramble: it FAILS CLOSED (typed
 * blocker UTXO_RECOVERY_ANCESTRY_TEAR_BLOCKER_ID, changes nothing). Bounded to
 * ~(tip.height - anchor) hops; two-pass so a refusal never mutates.
 *
 * FAIL-CLOSED (mutating nothing) on the shapes a height relabel CANNOT cure: a
 * pprev CYCLE / lasso (Floyd-detected — a wrong pprev wired from a scrambled
 * height by the loader's by-height fallback), a genuine missing-parent break, or
 * a terminus whose hash is not the compiled checkpoint block (wrong lineage).
 * PASS 2 is JOURNALED: a mutation that does not end up trust-rooting the tip is
 * REVERTED before returning (the boot shutdown persists the flat index
 * unconditionally, so an unverified label must never survive the call).
 *
 * Runs ONLY when the caller has already detected a detached island
 * (utxo_recovery_block_ancestry_break(tip) != NULL) — it NOOP early-returns on a
 * trust-rooted tip, so healthy datadirs pay nothing beyond that one gate walk.
 * Idempotent. On FIXED it relabels nHeight AND rebuilds pskip for the mutated
 * nodes (pskip is built FROM nHeight, NOT height-independent); nChainWork/
 * nChainTx are pprev+nBits-derived and unaffected. */
struct utxo_recovery_ancestry_repair
utxo_recovery_relink_scrambled_ancestry(struct main_state *ms,
                                        struct block_index *tip);

/* PART C — register the provenance-matched cold-import seed anchor as a
 * trust-root terminus for the Invariant A frontier gate. The cold-import UTXO
 * snapshot base (and the cured coins tip a shielded-history import registers)
 * is a SHA3-attested trust root ABOVE the compiled SHA3 anchor; without this,
 * utxo_recovery_block_ancestry_break() flags it a detached island and a
 * restart past the seed refuses the coins tip into genesis. Set ONCE at boot
 * by the restore path (single-threaded) before any background consumer runs;
 * read lock-free in ancestry_break. Pass (NULL, -1) — every normal / P2P-origin
 * datadir — to clear, so behaviour is identical to before. */
void utxo_recovery_set_cold_import_trust_anchor(const struct uint256 *hash,
                                                int32_t height);

/* ── Header band hole (installed-above-frontier) ─────────────── */

/* Typed-blocker id recorded when state is installed ABOVE the
 * trust-rooted header frontier, leaving a header hole ("the band")
 * between the contiguous frontier and the installed island. A cold-import
 * anchor installed above the header frontier leaves that band unrequested
 * forever without this blocker. It is a loud CACHE of a fact derived from pprev
 * contiguity — never an authority. Set by the producers below + the
 * boot scan in chain_restore_finalize; cleared by
 * syncsvc_header_band_after_batch when the band closes. */
#define HEADER_BAND_BLOCKER_ID "header_band_hole"

/* THE band producer + boot catch-all: if `tip` (an installed anchor,
 * seed, or active tip) is not trust-rooted, derive the island root from
 * pprev contiguity and record the band fact (blocker +
 * EV_RECOVERY_ACTION + WARN). NEVER blocks — the install proceeds
 * exactly as before. Deliberately ancestry-derived, NOT log-frontier
 * derived: the reducer log frontier collapses to the compiled SHA3
 * anchor on a fresh progress db, which false-recorded a band on every
 * clean two-step cold-import. Record-only. */
void utxo_recovery_note_band_unrooted_tip(const struct block_index *tip,
                                          const char *producer);

/* ── Validation recovery execution ───────────────────────── */

struct recovery_exec_result {
    struct zcl_result status; /* rich status for recovery execution */
    bool skip_activate;     /* caller should skip reducer activation */
    bool recovered;         /* a recovery action was taken */
    /* A BULK reload of the projection tables (utxos / transactions /
     * tx_outputs / tx_inputs / ...) is about to run, so the caller may drop
     * the secondary indexes and rebuild them once at the end. Set ONLY by the
     * wipe / reset-to-genesis path.
     *
     * Refusing to wipe (recover_stale_metadata) sets `recovered` but must NOT
     * set this: nothing bulk-loads afterwards, so dropping the indexes there
     * opens a ~2 s window and then pays a full rebuild of every projection
     * index on the next normal_mode call. Measured on a 6.74 GB node.db: the
     * drop frees 452,715 pages = 1,854 MB of index B-tree, and rebuilding it
     * costs 36.9 s on NVMe with a fully warm page cache. On a seek-bound disk
     * the sort runs cannot stay resident and it degrades to an external merge
     * sort against a ~120-IOPS spindle. */
    bool bulk_reload_pending;
};

enum utxo_count_check_level {
    UTXO_COUNT_CHECK_OK = 0,
    UTXO_COUNT_CHECK_INFO_STALE_REFERENCE,
    UTXO_COUNT_CHECK_WARNING,
    UTXO_COUNT_CHECK_CRITICAL
};

struct utxo_count_check_result {
    enum utxo_count_check_level level;
    int blocks_past_checkpoint;
    double pct_delta;
};

struct utxo_count_check_result utxo_recovery_classify_count_check(
    int tip_height,
    int checkpoint_height,
    uint64_t checkpoint_count,
    uint64_t actual_count);

/* Stale-vs-corruption split for an XOR commitment mismatch (call only
 * after utxo_commitment_equal() returned false). computed > saved = the
 * set advanced past a frozen checkpoint (stale, legitimate); computed <=
 * saved = rows vanished or same-count-different-hash (a silent-truncation
 * corruption candidate). See the
 * implementation comment for the full rationale. */
bool utxo_recovery_xor_mismatch_is_corruption_candidate(
    uint64_t saved_count,
    uint64_t computed_count);

/* Execute recovery based on validate_coins_chain_agreement result.
 * Handles REIMPORT, WIPE_WAIT, RESET_CHAIN, and BOOT_OK integrity
 * checks (stale genesis wipe, UTXO count sanity, XOR commitment). */
struct recovery_exec_result utxo_recovery_execute(
    struct utxo_recovery_ctx *ctx,
    struct boot_validation_result *vr);

/* Boot preflight: if coins_best_block is stale but the durable sync
 * projection names a later consensus-backed tip, advance the coins cursor
 * after applying the same bounded one-block overshoot guard used by the
 * normal UTXO rewind path. Returns true only when a repair was made. */
bool utxo_recovery_repair_stale_cursor_from_sync_projection(
    struct node_db *ndb);

/* L1 torn-legacy-coins boot recovery (the §3 dual-store tear).
 *
 * Fires ONLY from the boot gate AFTER coins_view_sqlite_open() returned false
 * with the torn-legacy shape: node.db `utxos` has rows but `coins_best_block`
 * is UNSET (the crash lost the legacy mirror's lazy batch + tip anchor, while
 * the tear-PROOF reducer authority coins_kv committed every block atomically).
 *
 * Recovery is gated on coins_kv being the PROVEN-healthy authority:
 *   (1) coins_kv_migration_complete == 1  (read-flip done; coins_kv is sole),
 *   (2) coins_kv_count(progress_db) > 0   (it actually holds the live set),
 *   (3) coins_kv_get_applied_height found  (it has a durable applied frontier).
 * If ANY predicate fails, the function returns false and the caller's FATAL is
 * preserved unchanged (no safety gate is weakened).
 *
 * On the proven-healthy path it re-seeds `coins_best_block` to the block hash
 * at `MAX(height) FROM utxos` — the height the LEGACY mirror actually reaches,
 * NEVER the (further-ahead) coins_kv frontier — so the SHA3 snapshot served to
 * peers stays self-consistent with its committed anchor. The chosen height's
 * block must be consensus-backed on disk (a node.db `blocks` row with
 * status>=3); otherwise the function refuses (returns false → FATAL preserved).
 *
 * Reset-safe: it only WRITES the anchor (never deletes a *_log row, never
 * lowers coins_kv, never resets the tip). progress_db is the live
 * progress_store_db() handle (already open at the gate). Returns true ONLY
 * when the anchor was durably written and a retry of coins_view_sqlite_open
 * is warranted; false otherwise (caller must FATAL). */
bool utxo_recovery_heal_torn_legacy_coins_anchor(
    struct node_db *ndb,
    struct sqlite3 *progress_db,
    const char *datadir);

/* ── UTXO cleanup ────────────────────────────────────────── */

/* Typed-blocker id (see util/blocker.h) raised when utxo_recovery_clean_
 * above_tip's guard REFUSES a proposed rewind — either a multi-block
 * overshoot or a single-block overshoot past UTXO_BOOT_REWIND_MAX_ROWS —
 * AND the overshoot could not be classified as mirror-only (see below).
 * Advance-or-named-blocker law: this refusal is a no-op an operator must
 * investigate (block_index/coins drift), never a log line alone. Carries
 * tip_height/max_height/row_count/guard in its reason text. Cleared the
 * next time the function runs and finds nothing above tip, or successfully
 * auto-heals a bounded or mirror-only overshoot — see utxo_recovery_service.c. */
#define UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID "utxo_recovery.rewind_overshoot"

/* Delete UTXOs with height above chain tip.
 * SAFETY: a single-block overshoot of <= UTXO_BOOT_REWIND_MAX_ROWS (32) rows
 * is always auto-healable. A LARGER overshoot is also auto-healed, UNGUARDED,
 * when it is provably MIRROR-ONLY: the kernel coins_kv store is the
 * proven authority (coins_kv_is_proven_authority) AND its own durable
 * applied-height-derived coins-best (coins_applied_height - 1) matches tip_h
 * exactly — i.e. the kernel itself holds nothing above the cursor, so every
 * row above tip lives solely in the node.db `utxos` mirror, a derived
 * projection consensus reads never depend on (utxo_mirror_sync_service.h).
 * (Deliberately not reducer_frontier_derive_coins_best_now: that helper also
 * cross-checks a hash witness against validate_headers_log/tip_finalize_log
 * and hard-fails the whole derivation on any read error there — including
 * "table absent", legitimate early in boot or on a coins_kv-only store — and
 * a pure height check needs no hash witness.)
 * Any other overshoot shape (legacy/non-canonical datadir, or the kernel's
 * OWN derived height disagreeing with tip_h) is refused — tip is likely
 * wrong, or the KERNEL store itself has rows above the cursor, either of
 * which is genuine block_index/coins drift and stays owner-investigated. A
 * refusal raises UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID (dumpstate
 * blocker / zcl_state subsystem=blocker).
 * Returns count of UTXOs deleted (0 if refused or none found).
 * NOTE: this is also the single heal mechanism reused by the continuous
 * orphan_utxo_above_tip Condition; the boot.c one-shot caller is a
 * boot-ordering requirement (runs before the Condition engine registers). */
int utxo_recovery_clean_above_tip(struct node_db *ndb,
                                   struct main_state *state);

/* ── Shielded value backfill ─────────────────────────────── */

/* Backfill sprout_value/sapling_value into SQLite blocks table
 * from block files on disk. Idempotent — skips already-populated.
 * Covers the whole active chain (height 1..tip); the boot path uses the
 * cursor-bounded suffix walk below, not this force-full variant.
 * On success returns ZCL_OK and, if out_updated != NULL, writes the
 * count of blocks updated. On failure returns a non-ok zcl_result
 * (-50/-51 = invalid args, -52 = write/persistence failure) and leaves
 * *out_updated untouched. */
struct zcl_result utxo_recovery_backfill_shielded(struct node_db *ndb,
                                     struct db_service *dbsvc,
                                     struct main_state *state,
                                     const char *datadir,
                                     int *out_updated);

/* Backfill blocks.{sprout,sapling}_value for the height suffix
 * (start_height-1, tip_height] via active-chain height lookups (NOT a full
 * block-map scan). Only rows carrying a nonzero JoinSplit/Sapling value are
 * written. The durable `shielded_backfill_height` cursor is advanced to the
 * highest height actually resolved, inside the same transaction as the covering
 * rows (crash-safe), and only ever forward. Returns the same zcl_result codes
 * as utxo_recovery_backfill_shielded(). */
struct zcl_result utxo_recovery_backfill_shielded_range(struct node_db *ndb,
                                     struct db_service *dbsvc,
                                     struct main_state *state,
                                     const char *datadir,
                                     int start_height,
                                     int tip_height,
                                     int *out_updated);

/* Pure planner for the cursor-gated suffix backfill: given the persisted
 * cursor `done_cursor` (-1 if unset) and the current `tip_height`, return the
 * first height to (re)compute — done_cursor+1, or 1 when unset — when
 * (done_cursor, tip_height] is non-empty and tip_height > 1000. Returns 0 to
 * SKIP (cursor already covers the tip, or tip too shallow). */
int utxo_recovery_shielded_backfill_start(int64_t done_cursor, int tip_height);

/* Boot-time shielded-value backfill, cursor-gated. Ensures
 * blocks.{sprout,sapling}_value are populated through tip_height, skipping the
 * O(chain) disk walk when the persisted `shielded_backfill_height` cursor
 * already covers it (the --importblockindex path stamps that cursor). Safe
 * no-op for tip_height <= 1000 or a closed db. Keeps the walk off the RPC-bind
 * critical path on a fresh 2-step datadir. */
void utxo_recovery_backfill_shielded_if_needed(struct node_db *ndb,
                                               struct db_service *dbsvc,
                                               struct main_state *state,
                                               const char *datadir,
                                               int tip_height);

#endif /* ZCL_SERVICES_UTXO_RECOVERY_SERVICE_H */
