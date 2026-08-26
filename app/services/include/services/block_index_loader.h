/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Loader: block_index.bin flat cache, SQLite cache, LevelDB block
 * tree compatibility, and projection-backed boot rebuild.
 *
 * Background
 * ----------
 * This service isolates block-index I/O behind a clean boundary. The flat,
 * SQLite, and LevelDB loaders remain compatibility/fallback paths; the
 * reducer-aligned boot path rebuilds from block_index_projection through
 * load_block_index_from_projection().
 *
 * On-disk flat format (block_index.bin)
 * -------------------------------------
 *   [48B embedded "BIIE" version/size/SHA3 integrity header]
 *   [4B payload magic "ZCLI" = 0x5A434C49]
 *   [4B count (LE)]
 *   [count * 172B block_index_flat entries, height-sorted]
 *
 * Each entry is a packed struct containing hash, prev_hash, height,
 * PoW metadata, chain_work, and Sapling root.
 *
 * Integrity is verified before row admission by the sibling
 * block_index_integrity service using the embedded SHA3-256 header.
 */

#ifndef ZCL_SERVICES_BLOCK_INDEX_LOADER_H
#define ZCL_SERVICES_BLOCK_INDEX_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

/* Forward declarations — avoids pulling in heavy headers */
struct main_state;
struct node_db;
struct chain_params;
struct block_tree_db;
struct block_index_projection;
struct sqlite3;

/* ── Flat file (block_index.bin) ─────────────────────────── */

/* Save all block_index entries to a height-sorted flat file.
 * Creates <datadir>/block_index.bin.  Overwrites if present. */
struct block_index_flat_identity {
    uint8_t payload_sha3[32];
    uint64_t payload_size;
    uint64_t row_count;
};

void save_block_index_flat(const char *datadir, struct main_state *ms);
struct zcl_result save_block_index_flat_identity(
    const char *datadir, struct main_state *ms,
    struct block_index_flat_identity *out);
bool block_index_flat_verified_identity(
    const char *datadir, struct block_index_flat_identity *out);
bool block_index_projection_bind_saved_flat(
    struct block_index_projection *bip,
    const struct block_index_flat_identity *identity);
/* True only when the verified flat identity is projection-bound and its
 * dirty journal contains a well-formed row for hash at height. Used by the
 * boot ladder to distinguish a recoverable stale flat tip from corruption. */
bool block_index_projection_bound_covers_tip(
    struct block_index_projection *bip, const char *datadir,
    const uint8_t hash[32], int32_t height);

/* Load block_index.bin via mmap.  Returns .ok=true if >= 1 entry loaded.
 * Allocates a contiguous arena for all entries, links pprev by hash,
 * recomputes nChainWork/nChainTx from pprev chain. On failure the result
 * self-describes the cause (open/fstat/mmap/format/size failures), each a
 * distinct negative code; the previous bare-bool true/false maps to .ok. */
struct zcl_result load_block_index_flat(const char *datadir, struct main_state *ms);

/* Point-read one entry's block hash + sapling root straight from
 * block_index.bin WITHOUT
 * the full multi-million-entry arena load: mmap, embedded-integrity verify
 * (a legacy sidecar-only file is REFUSED — a bind this load-bearing does not
 * read unverified bytes), binary search the height-sorted flat rows. This is
 * the ONLY store that carries hashFinalSaplingRoot for header-only heights:
 * the blocks projection writes rows on body fold / lean sync / block import
 * only (replay-canary FAIL#6), and the event-log block_index projection is
 * empty for a bulk P2P header sync (FAIL#7 — no EV_BLOCK_HEADER events).
 * The -import-complete-shielded verb derives its tip bind here. Returns
 * .ok=true with out_root filled on an exact-height hit; .ok=false with a
 * self-describing message on any integrity/format failure or a missing row
 * (the message carries the flat tip so "save predates the header" is
 * distinguishable from corruption). Siblings at one height return an
 * arbitrary row — a caller binding a frontier against a foreign root fails
 * CLOSED downstream, never a silent misbind. */
struct zcl_result block_index_flat_header_at(const char *datadir,
                                             int32_t height,
                                             uint8_t out_hash[32],
                                             uint8_t out_root[32]);

/* load_block_index_flat ALWAYS re-derives the pointer-graph-derived fields
 * (nChainWork, nChainTx, skip links, cached branch id) through the canonical
 * forward pass — measured ~861ms on a 3.19M-entry index. The former Tier-2 P2
 * "trust-flat" fast-restart arm that skipped this pass under a verified-clean
 * shutdown binding was removed: it saved <1s but a stale binding (saved best
 * tip <= the coins/fold tip) left pindex_best_header pinned at the coins tip and
 * converged the reducer drive with unfolded bodies (a live wedge). The big
 * fast-restart win — skipping the disk chain-restore + finalize rebuild — is
 * unaffected; it lives in boot_fast_restart_try, not here. */

/* ── SQLite cache (block_index_cache table) ──────────────── */

/* Write all block_index entries to the block_index_cache table.
 * Commits in 50K-row batches for write throughput. */
void save_block_index_recent(struct node_db *ndb, struct main_state *ms);

/* Load block_index from the block_index_cache table.
 * Returns .ok=true if >= 1 entry loaded.  Requires >= 1000 cached rows.
 * The previous bare-bool true/false maps to .ok.
 *
 * Integrity envelope (Wave N hardening, docs/work/FORWARD_PLAN.md item 7.3,
 * services/block_index_cache_envelope.h): a mismatch DEMOTES the cache
 * (discarded, named TRANSIENT blocker, .ok=false so the loader ladder falls
 * through to the next rung) — it is a pure, re-derivable cache, so this
 * NEVER refuses boot. An ABSENT envelope (a cache written before this
 * feature existed) falls back to the pre-existing COUNT(*)>1000 trust. */
struct zcl_result load_block_index_sqlite(struct node_db *ndb, struct main_state *ms);

/* ── node.db `blocks` table hydrate (--importblockindex sink) ─────── */

/* Hydrate the in-memory block_index map from the node.db `blocks` table — the
 * sink the `--importblockindex` CLI bulk-loads header rows into. That import
 * writes NO flat file, NO block_index_cache, and NO datadir LevelDB, so on a
 * freshly-imported datadir every other loader rung leaves a genesis-only map
 * and the node serves H*=0 until the legacy pull rescues it; this rung closes
 * that hole.
 *
 * Each row's header is re-serialized and its PoW hash recomputed; a row whose
 * stored `hash` does not equal that value (J5) is QUARANTINED per-row —
 * db_block_delete purges it, a typed blocker names height+hash+reason, a
 * dumpstate counter (block_index_blocks_hydrate_quarantined) increments, and
 * the load CONTINUES with the remaining rows (the purged height re-fetches via
 * header sync + body_fetch). Only a grossly-shredded table refuses whole.
 * Parent linkage is asserted via the pprev link pass, and nChainWork is
 * recomputed from the linked chain (the imported chain_work column is zero).
 * Entries install HONESTLY as header-only: BLOCK_VALID level clamped to at
 * most BLOCK_VALID_TREE, no HAVE_DATA/HAVE_UNDO (bodies fetched lazily via
 * P2P) — higher validity is never fabricated.
 *
 * Intended as a boot loader rung that fires ONLY when the earlier rungs leave a
 * (near-)empty map yet `blocks` has rows. Returns .ok=true on a non-empty
 * hydrate (even with some rows quarantined); .ok=false (map untouched by the
 * refusal paths) on an empty table, a prepare error, all-rows-poisoned, or the
 * gross-corruption refusal. */
struct zcl_result load_block_index_from_blocks_table(struct node_db *ndb,
                                                     struct main_state *ms);

/* Dumpstate-visible tally (process-monotonic) of poisoned `blocks` rows purged
 * by the load_block_index_from_blocks_table per-row quarantine (J5). Surfaced
 * by diag_block_index_dump_state_json. Reentrant/lock-free. */
int64_t block_index_blocks_hydrate_quarantined(void);

/* Outer bound shared by the per-row quarantine loaders (blocks-hydrate + flat):
 * localized corruption heals per-row (skip + quarantine the offending row), but
 * a source with more than this many poisoned rows is grossly shredded — defer to
 * the whole-file re-derive / reindex recovery rather than seed a lace-riddled
 * map. */
#define BLOCKS_HYDRATE_MAX_QUARANTINE 4096

/* Dumpstate-visible tally (process-monotonic) of block_index.bin flat rows
 * dropped by the per-row PoW-target admission gate in load_block_index_flat.
 * The flat cache stores no solution to hash-bind or re-check Equihash, so this
 * gate re-checks only that each stored hash still meets its own PoW difficulty
 * target; a failing row is dropped from the map (header sync + body_fetch
 * re-supply it). Surfaced by diag_block_index_dump_state_json. Reentrant. */
int64_t block_index_flat_row_quarantined(void);

/* ── LevelDB block tree ──────────────────────────────────── */

/* Load block_index from LevelDB block tree database.
 * Post-processes: recomputes nChainWork, nChainTx, skip links,
 * branch IDs, and failed-child propagation.
 * If btdb_open is false and no entries exist, inserts genesis.
 *
 * Returns ZCL_OK on success (including the empty-but-genesis-seeded case).
 * On failure the result self-describes the cause (Law 2, "one way out"):
 *   code -1  LevelDB block-tree deserialization failed (corruption)
 *   code -2  out of memory allocating the post-load sort array (io/resource)
 *   code -3  csr rejected the genesis tip commit (integrity)
 * The previous bare-bool true/false maps to .ok true/false. */
struct zcl_result load_block_index(struct main_state *ms,
                       const struct chain_params *params,
                       struct block_tree_db *btdb, bool btdb_open);

/* ── Shared internal helpers ─────────────────────────────────────── */

struct block_index;

/* Persisted-FAILED-bit trust policy verdict for one just-loaded entry
 * (block_index_apply_persisted_failure_trust). */
enum block_index_failure_trust_action {
    BLOCK_FAILURE_TRUST_NONE = 0, /* no persisted FAILED bit — left untouched */
    BLOCK_FAILURE_TRUST_STRIPPED, /* below the ROM checkpoint — bits stripped */
    BLOCK_FAILURE_TRUST_DEMOTED,  /* above — demoted to a revalidation candidate */
};

/* Reconcile a just-loaded block_index entry's PERSISTED negative verdict against
 * the baked ROM checkpoint trust boundary. Called per entry by the flat and
 * SQLite loaders (single-threaded, right after nHeight + nStatus are seated),
 * so it is O(1) per entry and adds NO extra boot-time scan.
 *
 *   Below the baked ROM checkpoint height (get_rom_state_checkpoint()->height):
 *     the state is checkpoint-trusted and re-derived from the baked keystone —
 *     STRIP any persisted BLOCK_FAILED_VALID/FAILED_CHILD (never trust a
 *     persisted verdict below the ROM), and do not flag revalidation.
 *
 *   Above it: a persisted FAILED verdict is a revalidation CANDIDATE, never
 *     final — clear the real FAILED bits (so a STALE bit can never exclude this
 *     block from find_most_work_chain / promote_best_header before revalidation
 *     re-confirms it — the "stale BLOCK_FAILED_VALID wedges tip" class) and set
 *     the node-local BLOCK_REVALIDATE_PENDING marker. The stages re-run full
 *     validation when the fold reaches the block; a GENUINE failure is re-set
 *     fresh by the connect path, so behavior for genuinely-failed blocks is
 *     unchanged (no weakening).
 *
 * The BLOCK_REVALIDATE_PENDING marker is runtime-derived: any bit a prior save
 * round-tripped to disk is cleared first, so it reflects only THIS load. Returns
 * the action taken (for the caller's per-load summary + the process counters). */
enum block_index_failure_trust_action
block_index_apply_persisted_failure_trust(struct block_index *pindex,
                                           int32_t checkpoint_height);

/* Process-monotonic tallies of persisted FAILED bits the loaders reconciled:
 * stripped below the ROM checkpoint, or demoted to revalidation candidates above
 * it. Surfaced by diag_block_index_dump_state_json. Reentrant/lock-free. */
int64_t block_index_failed_bits_stripped(void);
int64_t block_index_failed_bits_demoted(void);

/* Forward pass over a height-sorted block_index array: recompute
 * nChainWork, nChainTx, skip links, cached branch id, and failed-child
 * propagation from each entry's (already-linked) pprev. Shared by the
 * LevelDB loader (load_block_index) and the projection rebuild so both compute
 * the pointer-graph-derived fields identically. `sorted` must be height-ASC
 * ordered. */
void block_index_forward_pass(struct block_index **sorted, size_t count);

/* Publish the max-chainwork header of a just-loaded, forward-passed map into
 * pindex_best_header and seat it in the active_chain[] window (THE LINCHPIN so
 * active_chain_tip() is non-NULL over a freshly-hydrated header map). Shared by
 * the LevelDB rung and the `blocks`-table hydrate (block_index_blocks_hydrate.c)
 * so both anchor the getheaders locator identically. Idempotent + work-ranked
 * (never downgrades); changes only which header the locator anchors at, never
 * consensus validity/coins/H*. `sorted` must be height-ASC. */
void promote_best_header_after_load(struct main_state *ms,
                                    struct block_index **sorted, size_t count);

/* ── Projection-backed boot rebuild (event_log -> projection -> map) ───── */

/* Rebuild the in-memory block_index map purely from the
 * block_index_projection (the log-derived authoritative source), then
 * seed the active tip from the tip_finalize cursor in progress.kv.
 *
 * This is the reducer-aligned boot rebuild. It does NOT touch any
 * $HOME/.zclassic path.
 *
 * Sequence:
 *   1. block_index_projection_catch_up(bip) — drain the event log.
 *   2. block_index_projection_iterate — fold every disk_block_index into
 *      ms->map_block_index via chainstate_insert_block_index (fields per
 *      block_index_db.c. Block-file payload positions are copied exactly;
 *      the projection records this node's own positions in the same format).
 *   3. Link pprev via the carried hashPrev.
 *   4. Forward pass: recompute nChainWork, nChainTx, skip links, branch
 *      ids, failed-child propagation (mirrors load_block_index post-load).
 *   5. Seed the tip: read the tip_finalize cursor from `progress_db`
 *      (stage_cursor table), look up the finalized tip hash at cursor-1,
 *      find that block_index, set the authoritative tip + publish via
 *      chain_set_active_tip.
 *
 * Empty projection (cold datadir) → no entries folded, no tip set,
 * returns ZCL_OK (the node sits at genesis; fast_sync seeds it).
 *
 * `bip` is the open projection; `progress_db` is the progress.kv handle
 * (progress_store_db()). Both may be NULL — a NULL `bip` makes this a
 * no-op (returns ZCL_OK, empty map); a NULL `progress_db` skips the tip
 * seed (map rebuilt, no tip published).
 *
 * Returns .ok=true on success (including the empty case), .ok=false on a
 * hard fold/iterate error — the previous bare-bool true/false maps to .ok. */
struct zcl_result load_block_index_from_projection(struct main_state *ms,
                                      const struct chain_params *params,
                                      struct block_index_projection *bip,
                                      struct sqlite3 *progress_db);

/* Max forward gap the finalized-tip seed will adopt in one shot, measured
 * against the SAME effective_floor that drives the walk (cur_h for the
 * extend branch, 0 for the genesis-root branch). A larger gap means the
 * active chain is not yet at the coins/UTXO frontier (the full-restore
 * loaders' job), so the seed no-ops instead of walking the whole chain —
 * this is the load-bearing mainnet refusal (≈3.1M > 50000). */
#define BLOCK_INDEX_LOADER_SEED_MAX_GAP 50000

/* FORWARD-ONLY finalized-tip seed for the NORMAL boot path.
 *
 * After the normal loaders establish the active tip from the coins/UTXO
 * authority, this adopts the durable tip_finalize frontier ONLY when it is a
 * strictly-higher, CONTIGUOUS forward extension — every intermediate block
 * HAVE_DATA + script-valid + failure-free.
 *
 * TWO structural branches, selected SOLELY on active_chain_cached_tip()==NULL:
 *   - cached tip != NULL (extend-live-chain): the pprev walk down to the cached
 *     tip's height MUST land pointer-equal on that cached active tip — a pure
 *     forward extension, never a fork.
 *   - cached tip == NULL (genesis-root): the durable finalized tip exists but
 *     the coins authority never installed a cached tip (the kill-9-at-genesis
 *     class). Walk pprev all the way to height 0, requiring the terminus to be
 *     the CANONICAL genesis (params->consensus.hashGenesisBlock), then install
 *     + densify the [0..tip] window. This is the load-bearing recovery for a
 *     fresh node that mined N blocks, was kill-9'd, and rebooted to a NULL
 *     cached active tip.
 *
 * Both branches are bounded by BLOCK_INDEX_LOADER_SEED_MAX_GAP against the
 * SAME effective_floor that drives the walk (cached tip height for extend, 0
 * for genesis-root) — so a pathological NULL-tip mainnet boot (tip≈3.1M,
 * floor=0) REFUSES rather than walking millions of pprev links. A runtime
 * finalized<=coins precondition (coins_kv_get_applied_height >= tip_height)
 * gates install so a height with no coins behind it is never published.
 *
 * It never rewinds the tip, never swaps a fork, and never mutates the
 * tip_finalize_log or any cursor (read only), so a sparse/header-only frontier
 * yields a no-op rather than a hole.
 *
 * Returns 1 = seeded forward, 0 = no-op, -1 = error.
 *
 * WIRED at config/src/boot_services.c right after staged_sync_supervisor_register
 * (which runs tip_finalize_stage_init → registers the chain-height authority and
 * seeds it from the coins-restore tip). That is the race-free window: the
 * authority is live (so active_chain_height reads the real coins tip, not the
 * genesis value seen earlier in boot) but the runtime services / reducer ingest
 * have not started yet. Safe to call anywhere: it no-ops unless the finalized
 * frontier is a small, strictly-higher, contiguous have-data + script-valid
 * extension landing on the current tip. */
int block_index_loader_seed_tip_from_finalized(struct main_state *ms,
                                               const struct chain_params *params,
                                               struct sqlite3 *progress_db);

/* DURABLE, crash-recoverable cold-import staged-sync seed.
 *
 * A cold LDB import (utxo_recovery_import_ldb, ldb_import_found branch) seeds
 * the coins set + CSR-commits the public tip to H but NEVER seeds the 8 staged
 * reducer stage logs, so reducer_frontier_compute_hstar stays at the compiled
 * checkpoint and the staged-sync reducer cannot advance past the import floor. The
 * import path writes a DURABLE anchor (cold_import_seed_anchor_height/hash) to
 * node_db state; this consumer re-derives the wedge EVERY boot from that
 * durable marker plus the live frontier, so a kill-9 mid-seed self-heals on the
 * next boot.
 *
 * Fires the TRUSTED seed (tip_finalize_stage_seed_anchor(H, hash, true) — the
 * same fast-sync trust model snapshot_apply.c uses) ONLY when ALL hold:
 *   (1) the durable anchor (H, hash) is present (a real ldb_import_found ran),
 *   (2) the live active tip is exactly that (H, hash) and H >= the SHA3
 *       checkpoint anchor (partial/rewound import is excluded),
 *   (3) reducer_frontier_compute_hstar(progress_db) is far below H (the
 *       genuinely-pinned signal — NOT the tip_finalize cursor, which the boot
 *       reconcile clamp force-stamps to H+1 on every cold-import boot).
 * It sets coins_applied_height = H+1 first (the utxo_apply cursor convention),
 * then seeds. Forward-only, deletes no rows, idempotent (the gate self-clears
 * once H* == H). Returns 1 = seeded, 0 = no-op, -1 = error.
 *
 * WIRED right after block_index_loader_seed_tip_from_finalized in boot_services.c. */
int block_index_loader_seed_stages_from_cold_import(struct main_state *ms,
                                                    struct node_db *ndb,
                                                    struct sqlite3 *progress_db);

/* SYNC-STRENGTH W1-L1 — cold-start auto-seed from an imported block index.
 *
 * A fresh node built via the two-step recipe (`--importblockindex <legacy
 * datadir>` then a normal boot) has the FULL header/block index but an EMPTY
 * coins_kv and NO durable cold-import seed provenance key — `--importblockindex`
 * seeds ONLY the block index, never coins_kv or the reducer cursors — so
 * block_index_loader_seed_stages_from_cold_import returns 0 and the reducer
 * folds the eight stages from GENESIS instead of resuming at the baked SHA3
 * checkpoint anchor (h=3,056,758).
 *
 * When (1) coins_kv is EMPTY, (2) the loaded block index contains the checkpoint
 * block at exactly the checkpoint height (the header chain WAS imported past the
 * anchor), and (3) a SHA3-checkpoint-bound anchor snapshot artifact is reachable
 * (<datadir>/utxo-anchor.snapshot, fully body-SHA3-verified AND independently
 * bound to the compiled checkpoint — boot_refold_from_anchor_artifact_available,
 * the W1-L3 gate), this routes the cold start through the EXISTING atomic anchor
 * installer boot_refold_from_anchor_reset: it FULL-resets coins_kv, re-seeds the
 * SHA3-verified anchor set, HARD-ASSERTS it == the compiled checkpoint (FATAL on
 * mismatch), forces the 8 stage cursors to the anchor, and seeds the tip_finalize
 * base there — all under the installer's own transactions (all-or-nothing; never
 * a mixed-provenance seed). The fold then climbs the ~131k-block TAIL from the
 * anchor to the imported header tip over bodies the body_fetch stage pulls
 * lazily (the from-genesis mechanism, started 3.05M blocks higher), then marks
 * refold_from_anchor so the L0 floor holds at the anchor.
 *
 * We do NOT set COLD_IMPORT_SEED_HEIGHT_KEY: the from-anchor reset forces the
 * cursors to the anchor directly (a superset of what that key achieves) and
 * clears the cold-import provenance, so arming both would double-seed with
 * conflicting provenance — the single-provenance atomic install IS this path.
 *
 * FAIL-CLOSED: if the checkpoint or the verified snapshot is absent, returns
 * 0 — the caller falls through to the UNCHANGED genesis-fold behavior; never a
 * faked seed. Consensus validity math is untouched (only WHERE the reducer
 * cursors start changes, and only after the anchor set re-verifies against the
 * baked checkpoint). Returns 1 iff a from-anchor refold was armed (caller then
 * SKIPS the cold-import seed), else 0 (int return matches the sibling
 * block_index_loader_seed_stages_from_cold_import convention). WIRED into the
 * seed-vs-anchor decision in boot_services.c, after
 * boot_refold_from_anchor_arm_if_torn. */
int block_index_loader_arm_cold_start_from_index(struct main_state *ms,
                                                 struct node_db *ndb,
                                                 struct sqlite3 *progress_db);

/* (2a.5) BOOT-TIME TORN-IMPORT GATE — the durable forward-evidence verdict
 * that runs on a cold-import boot BEFORE the forward-only early-return (the
 * live wedge sits in the forward-applied region). Its own focused TU; the
 * full contract + the THREE-condition durability guard live in
 * block_index_loader_torn_gate.c.
 *
 * Returns true iff a GENUINELY-UNRECOVERABLE tear fired the verdict (the caller
 * MUST then refuse to bless and return its no-bless 0 — the gate stamps
 * NOTHING, so H* stays pinned at the compiled checkpoint). false = no tear /
 * transient-only / not-yet-refused → the caller proceeds. Caller passes the
 * already-validated seed height H and the SHA3 checkpoint. */
bool block_index_loader_torn_import_gate_fires(struct main_state *ms,
                                               struct sqlite3 *progress_db,
                                               int32_t H, int32_t checkpoint);

/* PURE detect predicate — the SAME three-condition durability guard as
 * block_index_loader_torn_import_gate_fires, but with NO event/blocker
 * side-effects. Returns true iff a genuinely-unrecoverable tear is present;
 * *out_hole_h / *out_ceiling (nullable) receive the load-bearing coordinates.
 * The boot from-anchor auto-arm consults this so it can decide to REPAIR (refold
 * from the anchor) instead of paging an operator; the gate-fires verdict above
 * remains the FATAL fallback when arming is impossible. Read-only on
 * progress.kv. */
bool block_index_loader_torn_import_detect(struct main_state *ms,
                                           struct sqlite3 *progress_db,
                                           int32_t checkpoint,
                                           int32_t *out_hole_h,
                                           int32_t *out_ceiling);

/* Shared projection-rebuild front door for boot (see the .c for contract).
 * Folds block_index_projection into ms's map, accepts iff the folded map has
 * > min_entries nodes. `publish_tip`=true publishes the cursor tip (the
 * projection-as-authority -rebuildfromlog path); =false does a PURE map
 * rebuild with NO tip publish (the kill-9 fallback — the coins authority +
 * the guarded forward seed own the tip). Returns .ok=true on accept; the
 * previous bare-bool true/false maps to .ok. */
struct zcl_result boot_try_rebuild_block_index_from_projection(struct main_state *ms,
                                                  const struct chain_params *params,
                                                  size_t min_entries,
                                                  bool publish_tip);

/* Projection top-up for the NORMAL boot path (defect #10, task #29).
 *
 * The flat/LevelDB loaders only know the last boot-time save; every block
 * connected since then exists durably ONLY in the event log → projection.
 * This folds the projection over the loaded map RAISE-ONLY: applies
 * HAVE_DATA + nFile/nDataPos an entry lacks, raises nTx and the
 * BLOCK_VALID level, inserts entries the loaders never saw (with pprev
 * link + bounded chainwork), and recovers nTx from the block file for
 * legacy rows emitted with n_tx=0 (hash-bound read-back). It never
 * lowers a field, never copies FAILED bits, and refuses rows whose
 * height disagrees with the loaded entry (logged, counted).
 *
 * Call AFTER the legacy loaders and BEFORE boot's nChainTx propagation
 * pass, which turns the topped-up nTx into the connected nChainTx chain
 * the boot scan and active-chain rebuild key on. NULL projection → no-op
 * true. Returns false only on a hard projection iterate/OOM error. */
bool block_index_projection_topup_with(struct block_index_projection *bip,
                                       struct main_state *ms,
                                       const char *datadir);
bool block_index_projection_topup(struct main_state *ms,
                                  const char *datadir);

/* node.db forward-extent top-up — cold-import restart-fragility fix.
 *
 * A node that cold-imported a UTXO snapshot (seed anchor at H_seed) and
 * forward-synced past it has, after a flat-index reload, the contiguous
 * chain up to ~H_seed in the map PLUS the seed anchor as a DETACHED
 * non-genesis root (its pprev chain to genesis is legitimately absent —
 * a UTXO-snapshot base is not P2P-downloaded). coins_best (the coins
 * authority) is the forward tip; the window (H_seed, coins_best] is
 * body-backed/connected (status>=3) in node.db `blocks` but is NOT
 * linked into the in-memory block index, so the seed anchor stays an
 * orphan tip and the coins-best restore refuses → tip drops to genesis.
 *
 * This folds ONLY that prev-linked, body-backed window [H_seed+1 ..
 * coins_best] from node.db `blocks` into ms->map_block_index RAISE-ONLY:
 * it inserts entries the loaders never saw (with pprev link + bounded
 * chainwork), applies HAVE_DATA + nFile/nDataPos an entry lacks, and
 * raises nTx + the BLOCK_VALID level. It NEVER lowers a field, never
 * copies FAILED bits, refuses (logs) any height conflict, and bounds the
 * scan to the window (hundreds of rows — never a full chain scan).
 *
 * STRICT NO-OP when there is no durable cold-import seed anchor (any
 * normal / P2P-origin datadir), when the window is empty, or when the
 * seed anchor block is not held in the map at exactly H_seed.
 *
 * Call AT THE SAME boot point as block_index_projection_topup (after the
 * legacy loaders, before the nChainTx propagation pass). `ndb` is the
 * open node.db (the seed-anchor provenance + `blocks` source); a NULL or
 * closed `ndb` makes it a no-op true. `progress_db` is the coins
 * authority (coins_best = coins_applied_height - 1); a NULL `progress_db`
 * makes it a no-op true. Returns false only on a hard alloc error. */
bool block_index_node_db_topup_with(struct main_state *ms,
                                    struct node_db *ndb,
                                    struct sqlite3 *progress_db,
                                    const char *datadir);
bool block_index_node_db_topup(struct main_state *ms,
                               struct node_db *ndb,
                               const char *datadir);

#endif /* ZCL_SERVICES_BLOCK_INDEX_LOADER_H */
