/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier — the L0 authority: compute H* (the deepest
 * provably-consistent height) and served_floor from durable progress.kv
 * state. Read-only; no writes, no transactions of its own.
 *
 * H* is the single number every reconciliation gates on. It is computed
 * once at boot/condition-check time from the durable stage logs and the
 * coins-applied frontier — never read from a drifted in-RAM int or a
 * served-tip that can advance past a torn prefix. L1 (flag/cursor reset)
 * and L2 (coin rewind) both clamp to this value rather than re-deriving
 * a private frontier, so all three layers agree on one boundary.
 *
 * The contract:
 *   - [0, H*] is a provably-consistent prefix: every success-checked log
 *     shows a contiguous ok=1 run up to H*, the validate_headers and
 *     script_validate hashes agree where both are present, and the coins
 *     frontier does not contradict it.
 *   - [H*+1, ...] has SOME defect (a hole, an ok=0 row, or a hash split).
 *   - H* >= TRUSTED_ANCHOR (the SHA3 UTXO checkpoint height) ALWAYS — the
 *     algorithm never rewinds across the irreversible finality floor.
 *   - served_floor = MAX(tip_finalize_log.height WHERE ok=1), reported
 *     SEPARATELY so L1 can HOLD a tip finalized above H* (a T10 torn
 *     view) rather than re-serving unstable blocks.
 */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_H
#define ZCL_JOBS_REDUCER_FRONTIER_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/uint256.h"

struct json_value;

/* The compiled-in SHA3 UTXO checkpoint height — the irreversible floor H*
 * may never fall below ON MAINNET. Mirrors the MAINNET
 * get_sha3_utxo_checkpoint()->height; exposed as a named constant so callers
 * and tests can assert the mainnet clamp without pulling in lib/chain.
 * Verified equal to the live mainnet checkpoint by the regression test.
 *
 * NETWORK NOTE: this constant is the MAINNET value. The SHA3 UTXO checkpoint
 * is a mainnet artifact (a specific mainnet block at 3,056,758); testnet and
 * regtest have no such checkpoint, so their finality floor is genesis (0).
 * The RUNTIME floor every read site uses is reducer_frontier_floor() ->
 * reducer_frontier_compiled_anchor(), which is network-derived: it returns
 * this constant on mainnet and 0 on testnet/regtest. Code that must compute a
 * floor without the runtime helper (e.g. the refold gate) keys the same
 * network branch off chain_params_get()->strNetworkID. This macro stays the
 * mainnet number so existing mainnet-only assertions/tests are unchanged.
 *
 * SELF-DERIVED SOURCING (Pillar 3, docs/work/self-verified-tip-plan.md):
 * reducer_frontier_compiled_anchor() no longer trusts ONLY this baked literal.
 * It first asks whether THIS node has its own SHA3-verified anchor artifact —
 * <datadir>/utxo-anchor.snapshot, produced either by the offline -mint-anchor
 * ceremony (config/src/boot_mint_anchor.c) or the in-fold self-mint hook
 * (services/anchor_selfmint.h) — and prefers that self-derived height when
 * the artifact is present and its recorded SHA3/count/height reproduce the
 * compiled checkpoint exactly. A present-but-MISMATCHED artifact is REFUSED
 * (never adopted) and the read falls back to this macro; an ABSENT artifact
 * also falls back to this macro. The self-derived value can therefore only
 * ever CONFIRM this constant today — it becomes load-bearing (able to
 * legitimately advance past this literal) only once a later lane teaches the
 * fold to mint a NEW anchor beyond genesis's single baked checkpoint. See
 * reducer_frontier_compiled_anchor() in reducer_frontier.c. */
#define REDUCER_FRONTIER_TRUSTED_ANCHOR ((int32_t)3056758)

/* The FLOOR H* and the L1 reconcile operate at. On a NORMAL boot this is the
 * compiled SHA3 checkpoint anchor (REDUCER_FRONTIER_TRUSTED_ANCHOR via
 * reducer_frontier_compiled_anchor() / the test override) — H* never rewinds
 * across finality and a below-anchor cursor is a defect the heal fixes.
 *
 * EXCEPTION — a from-genesis staged refold (jobs/refold_progress.h): while
 * refold_in_progress() is true the fold is legitimately re-walking the frozen
 * prefix from genesis, so the floor drops to 0 — below-anchor H* is REPORTED
 * (not clamped up) and a below-anchor cursor is NOT flagged as a defect. This
 * changes only the H*-reporting floor + whether the self-repair runs; it
 * changes NO validation rule. Returns 0 during a refold, else the compiled
 * anchor. Cheap (atomic cache read + at most the compiled-anchor read). */
int32_t reducer_frontier_floor(void);

/* The PROVABLE TIP cache (H*), served to EXTERNAL consumers (getblockcount,
 * P2P version.start_height, `z23 status`, explorer tip, getblock
 * confirmations). It is a single cached atomic refreshed ONCE per finalized
 * advance and ONCE per reorg rewind — never per RPC (compute_hstar is O(n)).
 *
 * Internal sync-window callers (header-admit window, snapshot lookahead, the
 * watchdog/reconcile/lag detectors, MMR catchup) keep reading
 * active_chain_height() — they legitimately need the lookahead/window tip,
 * which can sit ABOVE H* by the pipeline depth. This cache is the SEPARATE,
 * provable-prefix number, equal to the real tip at steady state and LOWER
 * mid-fold or after a reorg.
 *
 * Init value is a -1 "unpublished" sentinel that the getter maps to 0 (the
 * honest "nothing proven yet" before the first publish — see the .c). The
 * getter is a plain lock-free atomic load; never takes progress_store_tx_lock(). */
int32_t reducer_frontier_provable_tip_cached(void);

/* Height safe to advertise to EXTERNAL consumers during boot. Once H* has
 * been published, this is exactly reducer_frontier_provable_tip_cached().
 * During the short pre-publish boot window, fall back to the durable
 * tip_finalize witness instead of advertising height 0 to peers and public
 * bootstrap clients. Returns 0 only when no published or durable served tip is
 * available. */
int32_t reducer_frontier_external_tip_height(void);

/* True once the provable-tip cache has been published a real H* (not the -1
 * "unpublished" sentinel). The tip_finalize step uses this to warm the cache
 * exactly once at boot when the node comes up already at tip — there is no
 * finalize advance or reorg rewind to publish through, so getblockcount would
 * otherwise serve 0 until the next network block. Lock-free atomic load. */
bool reducer_frontier_provable_tip_is_published(void);

/* Refresh the cached provable tip (H*). Stores `hstar` verbatim — the caller
 * passes the value it just computed via reducer_frontier_compute_hstar (which
 * already clamps to the finality floor), so this never re-clamps and faithfully
 * mirrors a reorg-LOWERED H*. Called under progress_store_tx_lock at three
 * sites (all in tip_finalize_stage.c): the finalize advance, the reorg-rewind
 * (rewind_cursor_if_active_chain_reorged), and a one-time boot warm during
 * tip_finalize_stage_init / step_once (gated on is_published) so a node that
 * comes up already at tip serves the true H* without waiting for the next
 * advance.
 * Cross-thread-safe (atomic store); the getter is the matching atomic load. */
void reducer_frontier_provable_tip_set(int32_t hstar);

/* Reset the cached provable tip to the finality anchor — mirrors the
 * tip_finalize g_last_advance_height reset on shutdown / test_reset so a stale
 * high value from a prior run/test group cannot leak into a fresh boot. */
void reducer_frontier_provable_tip_reset(void);

/* Durable trusted-base declaration (progress_meta, 8-byte LE height blob +
 * 32-byte hash blob — the coins_applied_height storage convention). Written
 * RAISE-ONLY by the cold-import/snapshot seed (tip_finalize_anchor.c);
 * read by reducer_trusted_anchor as an anchor candidate vetted by the same
 * reducer_anchor_candidate_ok gate as a tip_finalize_log 'anchor' row.
 *
 * WHY a meta key and not (only) the anchor row: the anchor row at H is
 * pipeline-owned — the very first forward step REPLACES it with the
 * 'finalized' row for the H→H+1 transition (log_insert is INSERT OR
 * REPLACE, and the finalized row at H is the only durable source of
 * hash(H+1) for the boot resolver, so the replacement is correct). A
 * cold-import datadir whose ONLY anchor row was the seed's then starves
 * reducer_trusted_anchor back to the compiled checkpoint, the frontier
 * walk reads the legitimately log-less import region as an 88k hole, and
 * the I4.3 sweep HOLD-wedges an otherwise healthy at-tip node. A trust
 * DECLARATION must not live in a row the pipeline consumes. */
#define REDUCER_TRUSTED_BASE_HEIGHT_KEY "reducer_trusted_base_height"
#define REDUCER_TRUSTED_BASE_HASH_KEY   "reducer_trusted_base_hash"

/* Durable EXTERNAL-SEED floor (progress_meta, 8-byte LE height blob — the
 * same storage convention). Written ONCE (absent-guarded) by the paths where
 * the node's state genuinely arrived from an externally-verified seed rather
 * than local connection: the cold-import wedge heal
 * (block_index_loader_rebuild.c) and the consensus-state bundle install
 * (consensus_state_snapshot_install_activate.c). Deliberately NOT written by
 * reindex_epilogue (a from-genesis full replay through connect_block — locally
 * derived, despite trusted_seed=true there meaning "strongest trust root")
 * nor by runtime re-seeds, and NOT advanced by anchor finalization — unlike
 * REDUCER_TRUSTED_BASE_HEIGHT_KEY, which tip_finalize keeps raising toward
 * tip and which is therefore useless as a "where did the seeded extent end"
 * marker. Consumer: bg_validation starts a fresh walk at floor+1 — the
 * extent at/below the floor is certified by the sealed compiled checkpoint +
 * the SHA3-verified seed and carries no undo data to script-verify against. */
#define REDUCER_SEED_FLOOR_HEIGHT_KEY "reducer_seed_floor_height"

/* Canonical SELECT-only readers for the durable trusted-base declaration.
 * An absent declaration is a successful read with found=false; malformed or
 * partially-present metadata fails closed. */
bool reducer_frontier_trusted_base_height_read(sqlite3 *db, int32_t *height,
                                                bool *found);
bool reducer_frontier_trusted_base_read(sqlite3 *db, int32_t *height,
                                        uint8_t hash[32], bool *found);
bool reducer_frontier_trusted_base_matches(sqlite3 *db, int32_t height,
                                           const uint8_t hash[32]);

/* Canonical SELECT-only reader for the external-seed floor. An absent
 * declaration is a successful read with found=false (a from-genesis or
 * locally-reindexed node has no seeded extent); malformed fails closed. */
bool reducer_seed_floor_height_read(sqlite3 *db, int32_t *height, bool *found);

/* Write-once declaration of the external-seed floor: no-op success when the
 * key is already present (the FIRST seed defines the seeded extent; later
 * seeds/boots never move it backward or forward), fails closed on a
 * malformed stored value. Runs in the caller's ambient transaction. */
bool reducer_seed_floor_declare_if_absent(sqlite3 *db, int32_t height);

/* Compute H* (deepest provably-consistent height) and served_floor from
 * durable state.
 *
 * Called under progress_store_tx_lock with read-only access to progress_db
 * (progress.kv: stage_cursor, progress_meta, *_log tables) and the coins
 * store (whose applied-frontier == progress_meta['coins_applied_height']).
 *
 * Returns false on a DB read error; true on success (both out params are
 * always set on success). Sets *hstar to >= REDUCER_FRONTIER_TRUSTED_ANCHOR
 * (never below the SHA3 checkpoint). Sets *served_floor to
 * MAX(tip_finalize_log.height WHERE ok=1), or 0 if no ok=1 rows exist.
 *
 * PURE SELECT-only — issues no INSERT/UPDATE/DELETE and opens no
 * transaction of its own. The caller MUST already hold
 * progress_store_tx_lock() so the durable snapshot is consistent. */
bool reducer_frontier_compute_hstar(
    sqlite3 *progress_db,           /* progress.kv handle (lock held by caller) */
    int32_t *hstar,                 /* OUT: deepest provably-consistent height */
    int32_t *served_floor           /* OUT: MAX(tip_finalize ok=1 height), or 0 */
);

/* The contiguous ok=1 prefix of ONE success-checked *_log above the trusted
 * anchor — the same per-log frontier reducer_frontier_compute_hstar MIN-folds.
 * The single DRY reader callers use to derive a per-stage frontier instead of
 * duplicating the anchor/cursor/contiguity SQL:
 *   - validate_headers_log -> the validated HEADER frontier (Invariant A: a tip
 *     is committable only at or below this height).
 *   - utxo_apply_log -> the APPLIED frontier (the coin-tear test compares
 *     coins_applied against THIS, not the tip_finalize-pinned global MIN H*,
 *     so legitimate pipeline depth is never misread as a tear).
 *
 * Reads the trusted anchor + the named stage cursor internally and acquires
 * progress_store_tx_lock() itself (recursive; safe whether or not the caller
 * already holds it). SELECT-only — no writes, no transaction of its own.
 *
 * NOTE: O(cursor - anchor) rows streamed in ONE ranged scan (single
 * prepare; ~0.04 us/height vs 2.3 us/height for the old per-height probe).
 * Still call off the hot reducer-tick path — at boot, condition-check,
 * reconcile, or commit-prepare; periodic callers should memoize via
 * reducer_frontier_log_frontier_above below.
 *
 * Returns false on a DB read error (*out_h is then meaningless); true on
 * success with *out_h in [anchor, cursor-1]. */
bool reducer_frontier_log_frontier(
    sqlite3 *progress_db,           /* progress.kv handle */
    const char *log_table,          /* e.g. "validate_headers_log" */
    const char *cursor_name,        /* e.g. "validate_headers" */
    int32_t *out_h                  /* OUT: contiguous ok=1 prefix height */
);

/* Delta variant of reducer_frontier_log_frontier for callers that already
 * PROVED contiguity up to `verified_floor` on an earlier pass (e.g. the
 * 60 s invariant sweep memoizing its last clean frontier): extends the
 * contiguous ok=1 run from `verified_floor` upward in ONE ranged scan,
 * skipping the trusted-anchor read/re-validation entirely. O(rows above
 * the floor), not O(cursor - anchor) — the cost no longer grows with
 * uptime.
 *
 * CALLER CONTRACT: `verified_floor` MUST be a height this same log was
 * previously verified contiguous-ok=1 through (or the trusted anchor),
 * under a cursor that has NOT rewound since (a cursor rewind means an
 * unwind deleted rows — invalidate the memo and re-walk via
 * reducer_frontier_log_frontier). Acquires progress_store_tx_lock()
 * itself (recursive). SELECT-only. Returns false on a DB read error;
 * true with *out_h >= verified_floor otherwise. */
bool reducer_frontier_log_frontier_above(
    sqlite3 *progress_db,           /* progress.kv handle */
    const char *log_table,          /* e.g. "utxo_apply_log" */
    const char *cursor_name,        /* e.g. "utxo_apply" */
    int32_t verified_floor,         /* previously verified ok=1 height */
    int32_t *out_h                  /* OUT: contiguous ok=1 prefix height */
);

/* ── F1: log-derived stage cursor (the LOG is the read authority) ─────────
 *
 * Return stage `name`'s cursor value DERIVED from its own success-checked
 * *_log's contiguous ok=1 prefix (the same per-stage frontier compute_hstar
 * MIN-folds), expressed in `name`'s native cursor frame so it is a drop-in for
 * the raw stage_cursor read the eight Job stages otherwise perform:
 *   - upstream stage (validate_headers, script_validate, body_persist,
 *     proof_validate, utxo_apply): value = contiguous-ok=1-prefix HEIGHT + 1
 *     (the "next height to process" frame).
 *   - tip_finalize (served-tip frame): value = the contiguous-ok=1-prefix
 *     HEIGHT itself.
 *   - a stage with NO success-checked *_log (header_admit, body_fetch — not in
 *     the H* success-check set k_logs): value = the raw stage_cursor row (there
 *     is no log frontier to derive from).
 *
 * The result is CLAMPED to the raw stage_cursor row: the log may only LOWER the
 * value to the proven frontier (a durable hole / ok=0 below the cursor), never
 * RAISE it above the durable cursor. In a healthy, contiguous state the derived
 * value EQUALS the raw cursor exactly — the F1 dual-write / single-read
 * equivalence (the stage_cursor table keeps being written; it just stops being
 * the READ authority on this path). `*found` reports whether a raw stage_cursor
 * row exists (nullable).
 *
 * SELECT-only; acquires progress_store_tx_lock() itself (recursive, safe
 * whether or not the caller already holds it). Returns false on a DB read error
 * (*out then meaningless). The bounded log walk is O(cursor - anchor) — the
 * same delta-above-the-sealed-anchor cost class as compute_hstar, NOT O(chain);
 * keep it off the hot per-block tick (the eight stages already memoize it via
 * the batch-generation cache in jobs/stage_helpers.h stage_cursor_read_or_zero). */
bool reducer_frontier_stage_cursor_derived(
    sqlite3 *progress_db,           /* progress.kv handle */
    const char *name,               /* stage cursor name, e.g. "validate_headers" */
    uint64_t *out,                  /* OUT: log-derived cursor (cursor frame) */
    bool *found                     /* OUT (nullable): raw stage_cursor row present */
);

#ifdef ZCL_TESTING
/* Clear the thread-local derived-cursor memo. Tests that reuse cursor names
 * across freshly-opened in-memory fixtures call this between fixtures so a
 * prior fixture's cached frontier cannot survive into the next. */
void reducer_frontier_stage_cursor_derived_reset_memo_for_testing(void);
#endif

/* Hash recorded by ONE stage log at `height` (e.g. validate_headers_log.hash).
 * The Invariant A restore clamp uses it to derive the frontier tip hash when
 * the in-RAM pprev chain is torn between the frontier and a restore candidate
 * (log-as-truth: the stage's own recorded hash names the frontier block).
 *
 * *found=false on an absent row or a NULL hash (cold-import prefix) — that is
 * success, not an error. Returns false only on a real DB read error. Acquires
 * progress_store_tx_lock() itself (recursive; safe whether or not the caller
 * already holds it). SELECT-only. */
bool reducer_frontier_log_hash_at(
    sqlite3 *progress_db,           /* progress.kv handle */
    const char *log_table,          /* e.g. "validate_headers_log" */
    const char *hash_col,           /* e.g. "hash" */
    int32_t height,
    uint8_t out[32],                /* OUT: the 32-byte hash when *found */
    bool *found                     /* OUT: row + non-NULL 32B hash present */
);

/* MIN(height) over a stage log — the oldest height the log still covers.
 * The stage logs are rolling WINDOWS (rows below the window get pruned /
 * were never written under an anchor seed), so a height BELOW this floor
 * is "log-unknown": the log cannot refute it, only fail to vouch for it.
 * The Invariant A clamp uses this to fail OPEN (index authority only) for
 * candidates beneath the window instead of clamping an 86K-block rollback
 * to the compiled anchor.
 *
 * *found=false when the table is empty — success, not an error. Returns
 * false only on a real DB read error. Acquires progress_store_tx_lock()
 * itself (recursive). SELECT-only. */
bool reducer_frontier_log_coverage_floor(
    sqlite3 *progress_db,           /* progress.kv handle */
    const char *log_table,          /* e.g. "validate_headers_log" */
    int32_t *out_lo,                /* OUT: MIN(height) when *found */
    bool *found                     /* OUT: table has at least one row */
);

/* Derive the coins-best fact from progress.kv's own co-committed state.
 * THE derivation (docs/work/canonical-frontier-derived-state-plan.md
 * step 6): the answer is computed from coins_applied_height — co-committed in
 * the SAME BEGIN IMMEDIATE as every coin mutation + utxo_apply cursor move
 * (storage/coins_kv.h) — never from the separately-written node_state
 * 'coins_best_block' key, which is a CACHE that can drift and is never
 * consulted here.
 *
 * Height: *out_height = coins_applied_height - 1.
 * Hash, two durable-log witnesses (SELECT-only):
 *   1. tip_finalize_log read CONVENTION-AWARE (tip_finalize_stage_block_hash_at,
 *      jobs/tip_finalize_stage.h): a finalized ok=1 row at h-1 carries the
 *      LOOKAHEAD hash(h); an anchor seed row at h carries the block's own
 *      hash(h). (The raw row AT h carries hash(h+1) for finalized rows —
 *      reading it as "hash at h" is the inconsistent authority-pair shape
 *      this API refuses to produce.)
 *   2. validate_headers_log.hash at that height (own-hash by construction) —
 *      covers the <=1-block pipeline window where utxo_apply leads
 *      tip_finalize (Invariant B bound); the Invariant A trust root.
 * When BOTH witnesses resolve they must byte-agree; a cross-log mismatch is
 * a throttled WARN with *hash_found=false (don't guess between durable logs).
 * Neither resolving => *hash_found=false; either way the HEIGHT stays
 * authoritative (callers may resolve height->hash via their own block index,
 * never the reverse).
 *
 * *found requires the PROVEN-AUTHORITY predicate (coins_kv_is_proven_authority,
 * storage/coins_kv.h): coins_applied_height present AND the coins_kv migration
 * stamp set AND a non-empty set — the same three rungs the L1 torn-anchor heal
 * demands. *found=false (success, not error) on pre-migration / virgin
 * datadirs and on authority-proof read errors — callers then fall back to
 * their stricter labeled legacy gates. Returns false only on a real DB read
 * error in the hash rungs. SELECT-only; acquires progress_store_tx_lock()
 * itself (recursive). */
bool reducer_frontier_derive_coins_best(
    sqlite3 *progress_db,     /* progress.kv handle */
    int32_t *out_height,      /* OUT: coins_applied_height - 1 */
    uint8_t  out_hash[32],    /* OUT: hash at that height when *hash_found */
    bool    *hash_found,      /* OUT: hash resolved from a durable log */
    bool    *found);          /* OUT: coins_applied_height present */

/* Convenience form over the SINGLETON progress store (progress_store_db()):
 * one cheap point-read at each decision point — derive, don't cache.
 * Returns true iff the store is open AND coins_applied_height is present
 * (the canonical-datadir signal: every legacy node_state/mirror anchor is
 * a mere cache). false => legacy datadir / store closed / read error — the
 * caller keeps its labeled legacy fallback. out_hash and out_hash_found
 * may be NULL when only the height is needed. */
bool reducer_frontier_derive_coins_best_now(
    int32_t *out_height,      /* OUT: coins_applied_height - 1 */
    uint8_t  out_hash[32],    /* OUT (nullable): hash when *out_hash_found */
    bool    *out_hash_found); /* OUT (nullable): hash from a durable log */

/* ── Body torn-read repair note (lane E3) ────────────────────────────────
 *
 * When stage_repair_read_active_block_checked (reducer_frontier_replay.c)
 * cannot read the canonical body for a HAVE_DATA height — the on-disk bytes
 * are torn/truncated (the pread failed) or read fine but hash to the WRONG
 * block — a read that only DEFERs wedges every downstream stage forever
 * (e.g. "read_active_block_checked: disk read failed h=3143721 (nFile=49
 * pos=129998574) — repair defers", plus a repeating downstream
 * "prevout_unresolved").
 *
 * The repair records the failing height here — an event-driven note, NO
 * new scan pass. It deliberately does NOT clear BLOCK_HAVE_DATA from inside the
 * progress-locked replay (that would be a side-channel write racing the
 * reducer's single writer). Instead the have_data_unreadable Condition consumes
 * this note OFF-LOCK, re-verifies the body is genuinely unreadable, and clears
 * BLOCK_HAVE_DATA through the same seam body_persist uses — so body_fetch
 * re-downloads the body and the stages revalidate it. Bounded: after
 * REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX consecutive failures at one height
 * a typed TRANSIENT blocker (reducer_frontier.body_read_torn) is raised naming
 * height/nFile/pos/reason, so a torn body is a NAMED blocker, never a silent
 * hot loop. A successful read at the noted height clears the note + blocker
 * (the normal revalidation flow). */
#define REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX 3

enum reducer_frontier_body_read_reason {
    REDUCER_FRONTIER_BODY_READ_OK    = 0,
    REDUCER_FRONTIER_BODY_READ_DISK  = 1, /* pread failed: torn/truncated bytes */
    REDUCER_FRONTIER_BODY_READ_WRONG = 2, /* read ok but hashed to wrong block */
};

/* Record a failing canonical-body read at `height` (torn bytes / wrong block).
 * Called by stage_repair_read_active_block_checked (and, in tests, to simulate
 * it). Lowest-height-first — a higher failing height never displaces a lower
 * pending one — and raises the typed blocker once the quarantine bound is
 * crossed. A short independent mutex publishes height, hash, position,
 * reason, count, and generation as one coherent record even when validation
 * and reducer readers fail concurrently. */
struct reducer_frontier_body_read_note {
    bool active;
    int height;
    int file;
    int64_t pos;
    int count;
    enum reducer_frontier_body_read_reason reason;
    struct uint256 block_hash;
    uint64_t generation;
};

uint64_t reducer_frontier_body_read_note_record(
    int height, int nFile, int64_t pos,
    enum reducer_frontier_body_read_reason reason,
    const struct uint256 *block_hash);
bool reducer_frontier_body_read_note_snapshot(
    struct reducer_frontier_body_read_note *out);

/* Lowest height a canonical body read is currently failing at, or -1 if none.
 * Compatibility accessors each read a coherent snapshot; repair consumers
 * use reducer_frontier_body_read_note_snapshot directly. */
int64_t reducer_frontier_body_read_note_height(void);
bool    reducer_frontier_body_read_note_active(void);
int     reducer_frontier_body_read_note_file(void);
int64_t reducer_frontier_body_read_note_pos(void);
const char *reducer_frontier_body_read_reason_name(
    enum reducer_frontier_body_read_reason r);

/* Clear only the exact generation and block hash that a successful read or
 * witness observed. A same-height reorg or newer concurrent failure cannot be
 * cleared through an older snapshot. */
bool reducer_frontier_body_read_note_clear_if(
    const struct reducer_frontier_body_read_note *expected);

#ifdef ZCL_TESTING
/* Test seams: reset all note state; observe the consecutive-failure counter.
 * (Drive a note via reducer_frontier_body_read_note_record.) */
void reducer_frontier_body_read_note_reset_for_testing(void);
int  reducer_frontier_body_read_note_count_for_testing(void);
#endif

/* `z23 dumpstate reducer_frontier`: read-only snapshot of the L0
 * reducer authority. Reports H*, served_floor, raw stage cursors,
 * success-checked log frontiers, coins_applied_height, and first
 * validate_headers failure. Never writes progress.kv. */
bool reducer_frontier_dump_state_json(struct json_value *out,
                                      const char *key);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_H */
