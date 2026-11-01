/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Evidence Controller — native-first chain-state state machine.
 *
 * This service sits above chain_state_repository.  The repository is
 * the single writer for concrete tip pointers; this controller is the
 * evidence gate that decides whether a transition is allowed and
 * persists the publishable chain-state evidence that explains why.
 */

#ifndef ZCL_SERVICES_CHAIN_EVIDENCE_AUTHORITY_SERVICE_H
#define ZCL_SERVICES_CHAIN_EVIDENCE_AUTHORITY_SERVICE_H

#include "core/uint256.h"
#include "chain/chain.h"
#include "services/chain_state_service.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct node_db;

enum chain_evidence_controller_state {
    CEC_EMPTY = 0,
    CEC_HEADERS_WORK_VALIDATED,
    CEC_SNAPSHOT_UTXO_HASH_VERIFIED,
    CEC_TIP_FOLLOWING,
    CEC_BACKGROUND_VALIDATING,
    CEC_FULLY_VALIDATED,
    CEC_CONTRADICTION_FROZEN,
    CEC_NUM_STATES
};

enum chain_evidence_controller_result {
    CEC_OK = 0,
    CEC_REJECTED_NULL_ARG,
    CEC_REJECTED_FROZEN,
    CEC_REJECTED_BAD_STATE,
    CEC_REJECTED_BAD_PROOF,
    CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE,
    CEC_REJECTED_UTXO_AHEAD_OF_INDEX,
    CEC_REJECTED_CSR,
    CEC_REJECTED_PERSIST,
    /* Retryable, never freezes: the persisted active tip is not the tip the
     * caller asked about (a live advance moved it). */
    CEC_REJECTED_TIP_MOVED,
};

enum chain_evidence_source_class {
    CEC_SOURCE_CLASS_UNKNOWN = 0,
    CEC_SOURCE_CLASS_NATIVE_P2P,
    CEC_SOURCE_CLASS_SNAPSHOT,
    CEC_SOURCE_CLASS_LOCAL_IMPORT,
    CEC_SOURCE_CLASS_LEGACY_ADVISORY,
};

enum chain_evidence_publish_state {
    CEC_PUBLISH_NOT_PUBLISHABLE = 0,
    CEC_PUBLISH_LOCAL_EVIDENCE,
    CEC_PUBLISH_FROZEN_CONTRADICTION,
};

/* Durable provenance for CEC_FULLY_VALIDATED.  The state enum alone is not
 * enough: assisted validation must remain bound to its snapshot evidence,
 * while a genesis/full-history fold has no snapshot record by design. */
enum chain_evidence_full_validation_origin {
    CEC_FULL_VALIDATION_UNKNOWN = 0,
    CEC_FULL_VALIDATION_GENESIS_HISTORY,
    CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT,
};

struct chain_evidence_controller {
    struct node_db *ndb;                 /* non-owning */
    struct chain_state_repository *csr;  /* non-owning */
    enum chain_evidence_controller_state state;
    char contradiction_reason[192];
};

struct chain_evidence_record {
    enum chain_evidence_source_class source_class;
    enum chain_evidence_publish_state publish_state;
    bool header_ancestry_linked;
    bool chainwork_recomputed;
    bool nakamoto_selected_best_work;
    bool block_bytes_hash_checked;
    bool utxo_sha3_verified;
    bool mmb_flyclient_proof_verified;
    bool chunk_hash_coverage_verified;
    bool full_validation_complete;
};

struct chain_evidence_controller_snapshot_meta {
    int32_t anchor_height;
    struct uint256 anchor_hash;
    struct uint256 utxo_sha3;
    uint64_t utxo_count;
    uint8_t chainwork[32];
    uint8_t mmb_root[32];
    uint32_t finality_depth;
    uint32_t schema_version;
    const char *producer;
    struct chain_evidence_record verified;
};

struct chain_evidence_controller_tip_request {
    struct block_index *new_tip;
    int utxo_max_height;
    bool update_header_tip;
    const char *reason;
    struct chain_evidence_record verified;
};

struct chain_evidence_controller_view {
    enum chain_evidence_controller_state state;
    int active_tip_height;
    int header_tip_height;
    int persisted_active_tip_height;
    int snapshot_anchor_height;
    int background_validation_height;
    int utxo_max_height;
    int coins_best_block_height;
    int sqlite_max_height;
    struct uint256 active_tip_hash;
    struct uint256 header_tip_hash;
    struct uint256 persisted_active_tip_hash;
    struct uint256 coins_best_block_hash;
    bool has_active_tip_hash;
    bool has_header_tip_hash;
    bool has_persisted_active_tip_hash;
    bool has_coins_best_block_hash;
    enum chain_evidence_source_class active_tip_source_class;
    enum chain_evidence_publish_state publish_state;
    enum chain_evidence_full_validation_origin full_validation_origin;
    bool missing_active_tip_evidence;
    bool publish_state_not_local;
    bool active_tip_hash_mismatch;
    bool csr_cursor_mismatch;
    bool repaired_active_tip_evidence;
    struct chain_evidence_record block_index_evidence_state;
    struct chain_evidence_record active_tip_evidence;
    struct chain_evidence_record snapshot_evidence;
    bool snapshot_evidence_loaded;
    struct chain_evidence_record header_chain_evidence;
    char health_reason[128];
    char contradiction_reason[192];
};

const char *chain_evidence_controller_state_name(enum chain_evidence_controller_state state);
const char *chain_evidence_controller_result_name(enum chain_evidence_controller_result result);
const char *chain_evidence_source_class_name(enum chain_evidence_source_class source);
const char *chain_evidence_publish_state_name(enum chain_evidence_publish_state state);
const char *chain_evidence_full_validation_origin_name(
    enum chain_evidence_full_validation_origin origin);

void chain_evidence_controller_init(struct chain_evidence_controller *authority,
                         struct node_db *ndb,
                         struct chain_state_repository *csr);

/* Bind a controller for observation only. Unlike the boot/reconciliation
 * initializer above, this never repairs or persists evidence. Use it on
 * status/diagnostic paths, especially while holding sqlite3_db_mutex(). */
void chain_evidence_controller_init_readonly(
    struct chain_evidence_controller *authority, struct node_db *ndb,
    struct chain_state_repository *csr);

/* Bind a controller with NO node.db access at all (not even the readonly
 * state load): the bounded snapshot loads state itself, under its try-entered
 * connection mutex.  For live-node dumpers that must never wait on node.db. */
void chain_evidence_controller_init_unloaded(
    struct chain_evidence_controller *authority, struct node_db *ndb,
    struct chain_state_repository *csr);

enum chain_evidence_controller_state chain_evidence_controller_load_state(
    struct chain_evidence_controller *authority);

enum chain_evidence_controller_state
chain_evidence_controller_load_state_readonly(
    struct chain_evidence_controller *authority);

enum chain_evidence_controller_result chain_evidence_controller_import_snapshot_evidence(
    struct chain_evidence_controller *authority,
    const struct chain_evidence_controller_snapshot_meta *snapshot);

enum chain_evidence_controller_result chain_evidence_controller_promote_tip(
    struct chain_evidence_controller *authority,
    const struct chain_evidence_controller_tip_request *request);

/* Live-path durable evidence follow for a tip the reducer ALREADY committed.
 *
 * promote_tip is the boot / import publication boundary and the only writer of
 * the persisted cec.active_tip_* keys — but it also drives csr_commit_tip. The
 * running node advances the served tip through the tip_finalize reducer
 * (active_chain_move_window_tip), which never re-enters promote_tip, so the
 * persisted active-tip evidence froze at the last boot reconcile while the
 * served tip advanced every block. That stale evidence made the health check's
 * active_tip_hash_mismatch (live tip vs persisted) degrade further per block
 * (TASK #33). This advances ONLY the durable evidence keys (the exact set
 * promote_tip / reconstruct write) for the already-committed `finalized_tip`,
 * with no CSR commit, plus aligns the in-memory coins-view best-block cursor so
 * csr_cursor_mismatch clears. It NEVER freezes and NEVER blocks the caller: a
 * persist miss logs loudly and returns false (health degrades honestly; the
 * next drain retries). Returns true on success or when the persisted
 * evidence already names this exact tip.
 *
 * LOCK ORDER: takes csr->lock. csr_snapshot never nests csr->lock with
 * coins_kv/progress.kv; it releases the repository lock before sampling those
 * external stores. NEVER call from the reducer drive — it already holds
 * coins_kv, and blocking on csr there deadlocks the reducer drive.
 * The drive calls chain_evidence_note_finalized_tip below; the health-collect
 * path drains. */
bool chain_evidence_controller_record_finalized_tip(
    struct chain_evidence_controller *authority,
    struct block_index *finalized_tip,
    const char *reason);

/* EVIDENCE WRITE LOCK. One process-wide mutex (controllers are per-call stack
 * structs over one shared node_db handle, so it cannot live in them) held
 * across the whole check+load+write of every writer of the cec.active_tip_*
 * evidence keys that can race the genesis walk: earn_active_tip_evidence,
 * the live-advance record (chain_evidence_controller_record_finalized_tip's
 * evidence persist), and mark_fully_validated(_at_tip). It is INNERMOST and
 * non-recursive: take it only after cs_main, csr->lock, the coins/progress
 * locks; while holding it touch only the node_db handle and never take any
 * of those. Earn and the tip-bound mark never join a transaction another
 * writer already opened on the handle (they refuse, transient). Not covered:
 * promote_tip and boot reconcile, which run in their own caller-owned
 * transaction. */
void chain_evidence_write_lock(void);
void chain_evidence_write_unlock(void);

/* Why an earn was refused; the failing zcl_result.code carries it.
 * TRANSIENT (CEC_EARN_TIP_MOVED, CEC_EARN_STORE_BUSY): nothing was written
 * and a later publish pass can succeed, because the live follow had not
 * caught up to the walk's tip, moved it, or the store/transaction was busy.
 * FINAL for the given inputs (CEC_EARN_FINAL, CEC_EARN_NOT_LOCAL_IMPORT):
 * bad arguments, a flag not established, or a persisted record that is not a
 * local import with ancestry and chainwork; retrying the same call cannot
 * change that (the next pass re-derives its inputs). */
enum chain_evidence_earn_outcome {
    CEC_EARN_OK = 0,
    CEC_EARN_FINAL = -1,
    CEC_EARN_TIP_MOVED = -2,
    CEC_EARN_STORE_BUSY = -3,
    CEC_EARN_NOT_LOCAL_IMPORT = -4,
};

/* Upgrade the persisted LOCAL_IMPORT active-tip record with the two flags the
 * genesis walk established for exactly this tip (bytes via the walk, best
 * work via the core predicate). The persisted record must name tip_hash at
 * tip_height; that check, the load and the three evidence-key writes run in
 * ONE transaction, so flags are never attached to a different tip. */
struct zcl_result chain_evidence_controller_earn_active_tip_evidence(
    struct chain_evidence_controller *authority,
    const struct uint256 *tip_hash, int tip_height,
    bool nakamoto_selected_best_work, bool block_bytes_hash_checked);

/* Reducer-side half of the live evidence follow: stamp the just-published
 * tip into a pending slot guarded by ONE leaf mutex (nothing else is ever
 * acquired while it is held), safe under any lock the drive holds. */
void chain_evidence_note_finalized_tip(const struct block_index *finalized_tip);

/* Test/monolith isolation: clear the process-wide pending-tip slot so one
 * fixture's synthetic finalized tip cannot be drained by a later fixture. */
void chain_evidence_pending_tip_test_reset(void);

/* Health-side half: if a published tip is pending, run record_finalized_tip
 * for it under the caller's (health-collect) lock order — csr->lock before
 * coins_kv. If no pending slot exists but the current CSR tip is ahead of
 * cec.active_tip_*, retry the same durable follow for the current tip; this
 * covers startup/deploy races where SQLite contention left persisted evidence
 * stale and no reducer note survived in memory. Call AFTER
 * chain_evidence_controller_init and BEFORE the snapshot, so the mismatch the
 * follow clears is never observed. Returns false only when a record attempt
 * failed (slot/current tip will be retried on the next drain); true when
 * drained, repaired, or already current. */
bool chain_evidence_drain_pending_tip(
    struct chain_evidence_controller *authority);

/* Off-thread chain-evidence maintenance for the health collector: runs
 * chain_evidence_controller_init (state load, boot reconcile) and
 * chain_evidence_drain_pending_tip on one helper thread and waits at most
 * wait_ms.  PENDING = not finished in time (or an older run is still in
 * flight): the caller must report the tick stale/unavailable, never fresh.
 * The helper keeps running and completes when node.db frees up; the next
 * request retries.  Quiesce joins the helper (shutdown, tests). */
enum cec_maint_result { CEC_MAINT_DONE = 0, CEC_MAINT_PENDING };
enum cec_maint_result chain_evidence_maintain_bounded(
    struct node_db *ndb, struct chain_state_repository *csr, int wait_ms);
void chain_evidence_maintain_quiesce(void);

/* Guard A (coins-durability): the genuine applied coins frontier is the height
 * of the block whose hash is coins_best_block (the connect_block authority).
 * cec.coins_best_block_height must NEVER be persisted above it, or recovery
 * anchors promoted ahead of the applied coins poison MAX(ok=1) (the
 * coins-durability desync). Returns min(requested_height, frontier); refusal-
 * only — returns requested_height unchanged when coins_best_block is zero or
 * unresolvable (fresh datadir / snapshot anchor), so a legitimate advance is
 * never blocked. On the normal forward path coins==tip so this is a no-op. */
int chain_evidence_clamp_coins_height_to_frontier(
    struct chain_evidence_controller *authority, int requested_height);



enum chain_evidence_controller_result chain_evidence_controller_mark_fully_validated(
    struct chain_evidence_controller *authority,
    const struct uint256 *utxo_sha3);

/* Genesis publication bound to the exact active tip the caller verified.
 * The persisted active tip not naming tip_hash returns CEC_REJECTED_TIP_MOVED
 * (retryable, writes nothing, never freezes); genuinely missing evidence for
 * that tip still freezes, as mark_fully_validated does. Read, check and write
 * run in one transaction. */
enum chain_evidence_controller_result
chain_evidence_controller_mark_fully_validated_at_tip(
    struct chain_evidence_controller *authority,
    const struct uint256 *utxo_sha3, const struct uint256 *tip_hash);

void chain_evidence_controller_freeze(struct chain_evidence_controller *authority,
                           const char *reason);

/* Non-blocking snapshot for live-node diagnostics: same view, but every lock
 * on the path is a bounded try.  Returns false (view not usable) when the
 * chain-state or progress-store lock is busy. */
bool chain_evidence_controller_snapshot_bounded(
    struct chain_evidence_controller *authority,
    struct chain_evidence_controller_view *out);

void chain_evidence_controller_snapshot(struct chain_evidence_controller *authority,
                             struct chain_evidence_controller_view *out);

struct zcl_result chain_evidence_controller_mark_block_evidence(
    struct chain_evidence_controller *authority,
    const struct uint256 *block_hash,
    const struct chain_evidence_record *evidence);

bool chain_evidence_record_has_block_index_required(
    const struct chain_evidence_record *evidence);

bool chain_evidence_record_has_snapshot_required(
    const struct chain_evidence_record *evidence);

/* Re-arm the once-per-process startup reconcile so the NEXT controller
 * construction (every health probe constructs one) re-derives active-tip
 * evidence. For runtime structural repairs — e.g. the header band closure
 * relinking the tip's ancestry — so a stale contradiction_frozen freeze
 * does not outlive the condition that caused it. `why` is a grep-able
 * tag for the log line. */
void chain_evidence_request_startup_reconcile(const char *why);

#ifdef ZCL_TESTING
typedef void (*chain_evidence_earn_test_hook_fn)(
    struct chain_evidence_controller *authority);
/* Runs after the earn's early check and before its transaction: the window
 * the in-transaction check closes. */
/* Threads currently blocked in (or entering) chain_evidence_write_lock. */
int chain_evidence_write_lock_test_waiters(void);
typedef void (*chain_evidence_live_test_hook_fn)(void);
/* Runs inside the live-advance evidence persist, after its transaction is
 * open (or joined) and before it writes: the parking point for the
 * two-thread test. */
void chain_evidence_live_test_set_after_begin_hook(
    chain_evidence_live_test_hook_fn fn);
void chain_evidence_earn_test_set_before_write_hook(
    chain_evidence_earn_test_hook_fn fn);
void chain_evidence_controller_test_fail_commit_after_csr(bool fail);
/* Clears the process-lifetime startup-reconcile once-guard so each test
 * case gets a fresh reconcile run (production never resets it). */
void chain_evidence_controller_test_reset_startup_reconcile(void);
#endif

#endif /* ZCL_SERVICES_CHAIN_EVIDENCE_AUTHORITY_SERVICE_H */
