/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain state repository — single writer for chain-tip mutations.
 *
 * Invariant
 * ---------
 * The chain tip has six independent on-disk sources of truth
 * (block_index.bin, SQLite `blocks`, and four more). An unguarded mutation
 * site that updates one without the others lets a boot path trust whichever
 * metadata it reads first and delete "everything above tip" on a stale view.
 *
 * Every chain-tip mutation must go through
 * csr_commit_tip(). Internally the six sources are updated under one
 * mutex; if any cross-check fails, NOTHING changes and a structured
 * EV_CHAIN_TIP_REJECTED event is emitted with the reason.
 *
 * The six sources of truth
 * ------------------------
 *   1. block_index.bin (in-memory `block_map`)
 *   2. SQLite `blocks` table (queried for cross-validation)
 *   3. coins_view_cache::hash_block (the coins_best_block hash)
 *   4. active_chain tip pointer
 *   5. pindex_best_header (best-known header tip)
 *   6. wallet scan height (optional, may be NULL)
 *
 * The repository never owns any of these — pointers are non-owning. The
 * caller wires the repository to the existing global state at boot time
 * and frees the underlying objects normally.
 */

#ifndef ZCL_SERVICES_CHAIN_STATE_SERVICE_H
#define ZCL_SERVICES_CHAIN_STATE_SERVICE_H

#include "chain/chain.h"
#include "validation/chainstate.h"
#include "coins/coins_view.h"
#include "models/database.h"
#include "core/uint256.h"
#include "services/recovery_policy.h"
#include "util/result.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct db_service;

/* ── Result of a tip commit ─────────────────────────────────────
 * CSR_OK means all six sources of truth were updated atomically.
 * Any other value means NOTHING changed — the repository state is
 * exactly what it was before the call. */
enum csr_result {
    CSR_OK = 0,
    CSR_REJECTED_NULL_INPUT,         /* commit, repo, or new_tip was NULL */
    CSR_REJECTED_NOT_INITIALIZED,    /* csr_init was not called */
    CSR_REJECTED_TIP_NOT_IN_INDEX,   /* new_tip not registered in block_map */
    CSR_REJECTED_HASH_MISMATCH,      /* phashBlock != block_map entry hash */
    CSR_REJECTED_MISSING_PREV,       /* pprev not NULL but absent from block_map */
    CSR_REJECTED_STALE_INDEX,        /* block_map disagrees with SQLite blocks */
    CSR_REJECTED_UTXO_DELTA_TOO_BIG, /* would orphan more UTXOs than allowed */
    CSR_REJECTED_COINS_MISMATCH,     /* commit->new_coins_best != new_tip hash */
    CSR_REJECTED_HEADER_REGRESSION,  /* header tip would move backward without auth */
    CSR_REJECTED_ROLLBACK_AUTH,      /* rollback/clear auth is absent or invalid */
    CSR_REJECTED_PERSIST,            /* durable metadata persistence failed */
    CSR_REJECTED_DB_BUSY,            /* SQLite writer was busy/locked */
    CSR_REJECTED_OOM,                /* active_chain realloc failure */
    CSR_NUM_RESULTS                  /* sentinel */
};

const char *csr_result_name(enum csr_result r);

/* ── Repository ─────────────────────────────────────────────────
 * Holds non-owning pointers to the six sources of truth plus a
 * mutex that serialises all commits. Initialise with csr_init();
 * release with csr_free() (which destroys the mutex but does NOT
 * touch any of the underlying state). */
struct chain_state_repository {
    pthread_mutex_t lock;
    bool            initialized;

    /* Sources of truth (non-owning). ndb and wallet_scan_h may be NULL
     * — the repository skips checks/updates that depend on them. */
    struct block_map        *block_map;       /* in-memory block index */
    struct active_chain     *chain_active;    /* tip pointer cache */
    struct block_index     **pindex_best_hdr; /* slot for header tip */
    struct coins_view_cache *coins_tip;       /* coins_best_block cache */
    struct node_db          *ndb;             /* SQLite blocks + utxos */
    struct db_service       *db_service;      /* optional serialized writer */
    int64_t                 *wallet_scan_h;   /* optional wallet scan height */

    /* Tunables */
    int64_t max_utxo_orphan_rows; /* default 1000 — see csr_set_max_utxo_orphan_rows */
    int     stale_index_height_gap; /* default 100 — see csr_set_stale_index_gap  */

    /* Counters for observability (read-only via csr_snapshot) */
    uint64_t commits_ok;
    uint64_t commits_rejected[CSR_NUM_RESULTS];
    /* Monotonic equality token for lock-free consumers that validate an
     * expensive header-ancestry snapshot before committing cached results. */
    _Atomic uint64_t header_generation;
    int      last_persist_sqlite_rc;
    char     last_persist_error[160];
};

/* ── Read-only view ─────────────────────────────────────────────
 * Captured by csr_snapshot. Repository-owned memory is copied under csr->lock;
 * external progress.kv/node.db counts are sampled only after that lock is
 * released. The counts may therefore be one commit newer than the frontier,
 * which is preferable to creating a csr->progress lock-order edge. */
struct chain_state_view {
    int             tip_height;        /* active_chain tip height (-1 if none) */
    struct uint256  tip_hash;          /* active_chain tip hash (zero if none) */
    int             header_height;     /* pindex_best_header height (-1 if none) */
    struct uint256  coins_best_block;  /* coins_view_cache::hash_block */
    int64_t         utxo_count;        /* node_db UTXO row count, -1 if unknown */
    int64_t         sql_max_height;    /* SQLite MAX(blocks.height), -1 if unknown */
    bool            consistent;        /* tip_hash == coins_best_block */
    uint64_t        commits_ok;
    uint64_t        commits_rejected_total;
};

/* Cheap, no-SQL frontier view for health/agent surfaces.  The repository lock
 * and the active-window writer lock are held in that order while the three
 * pointers are copied.  `bound_to_expected_state` prevents a detached or
 * stale singleton binding from being mistaken for the caller's node. */
struct chain_state_frontier_view {
    bool initialized;
    bool bound_to_expected_state;
    struct active_chain_window_snapshot window;
    struct block_index *header_tip;
};

enum chain_state_rollback_source {
    CSR_ROLLBACK_SOURCE_NONE = 0,
    CSR_ROLLBACK_SOURCE_VALIDATION,
    CSR_ROLLBACK_SOURCE_HEADER_SYNC,
    CSR_ROLLBACK_SOURCE_SNAPSHOT,
    CSR_ROLLBACK_SOURCE_RESTORE,
    CSR_ROLLBACK_SOURCE_BOOT_REPAIR,
    CSR_ROLLBACK_SOURCE_UTXO_REPAIR,
    CSR_ROLLBACK_SOURCE_REINDEX,
    CSR_ROLLBACK_SOURCE_TEST,
};

struct chain_state_rollback_authorization {
    enum chain_state_rollback_source source;
    enum policy_decision             decision;
    int64_t                          from_height;
    int64_t                          to_height;
    int64_t                          max_depth;
    const char                      *evidence_class;
    const char                      *reason;
};

/* ── Commit description ─────────────────────────────────────────
 * The caller fills this in and passes it to csr_commit_tip. */
struct chain_state_commit {
    struct block_index *new_tip;            /* required, must be in block_map */
    struct uint256      new_coins_best;     /* required, must equal new_tip hash */
    int64_t             expected_utxo_count;/* >0 = check actual matches within 50% */
    bool                update_header_tip;  /* also bump *pindex_best_hdr */
    bool                persist_coins_best; /* write coins_best_block before publishing */
    const struct chain_state_rollback_authorization
                       *rollback_auth;      /* required to bypass rollback guards */
    int64_t             wallet_scan_height; /* applied if >=0 and wallet_scan_h is set */
    const char         *reason;             /* logged & shown in events; required */
};

struct chain_state_header_commit {
    struct block_index *new_header_tip;     /* required, must be in block_map */
    const struct chain_state_rollback_authorization
                       *rollback_auth;      /* required for header regression */
    const char         *reason;             /* logged; required */
};

struct chain_state_clear_commit {
    const struct chain_state_rollback_authorization
                       *rollback_auth;      /* required to clear active tip */
    const char         *reason;             /* logged; required */
};

/* ── Lifecycle ─────────────────────────────────────────────────
 * Pass NULL for any source you don't have wired up yet — the
 * repository will skip the related cross-checks gracefully. The
 * minimum useful set is {block_map, chain_active, coins_tip}. */
void csr_init(struct chain_state_repository *csr,
              struct block_map        *block_map,
              struct active_chain     *chain_active,
              struct block_index     **pindex_best_hdr,
              struct coins_view_cache *coins_tip,
              struct node_db          *ndb,
              int64_t                 *wallet_scan_h);

void csr_free(struct chain_state_repository *csr);
void csr_set_db_service(struct chain_state_repository *csr,
                        struct db_service *db_service);

/* ── Process-lifetime singleton ─────────────────────────────────
 * Call-site migrations reach the repository through this accessor
 * rather than threading a pointer through every function. The
 * singleton's mutex is lazily initialized on first access (via
 * pthread_once) so callers never hit an uninitialized lock, but
 * `initialized` stays false until boot wires real pointers with
 * csr_init(csr_instance(), ...). Any commit attempt before that
 * returns CSR_REJECTED_NOT_INITIALIZED with no side effects.
 *
 * Never pass this pointer to csr_free() in normal operation — the singleton
 * lives for the entire process and its pthread_once-owned mutex is never
 * destroyed. */
struct chain_state_repository *csr_instance(void);

#ifdef ZCL_TESTING
/* Monolithic-test isolation only. The caller must ensure all repository users
 * are quiescent; detaches every borrowed singleton binding without changing
 * the production lifecycle or destroying the pthread_once-owned mutex. */
void csr_test_reset_singleton(void);
#endif

/* ── Mutation entry point ─────────────────────────────────────── */
enum csr_result csr_commit_tip(struct chain_state_repository *csr,
                                const struct chain_state_commit *commit);
struct zcl_result csr_commit_tip_result(
    struct chain_state_repository *csr,
    const struct chain_state_commit *commit);
enum csr_result csr_commit_header_tip(
    struct chain_state_repository *csr,
    const struct chain_state_header_commit *commit);
/* Advance-only best-header publication.  Candidate identity is validated and
 * the work/height comparison plus assignment happen under one CSR lock, so a
 * stale caller can never overwrite a newer header.  A valid non-winning
 * candidate returns CSR_OK with *promoted=false. */
enum csr_result csr_promote_header_tip(
    struct chain_state_repository *csr,
    struct active_chain *expected_chain,
    struct block_index **expected_header_slot,
    struct block_index *candidate,
    const char *reason,
    bool *promoted);
enum csr_result csr_clear_active_tip(
    struct chain_state_repository *csr,
    const struct chain_state_clear_commit *commit);
bool csr_restore_in_memory_view(struct chain_state_repository *csr,
                                struct block_index *old_tip,
                                struct block_index *old_header,
                                const struct uint256 *old_coins_best);

/* Align ONLY the in-memory coins-view best-block cursor to `hash`, under
 * csr->lock (so a concurrent csr_snapshot reader never observes a torn
 * write). The live reducer advances the served tip via the tip_finalize
 * stage and applies UTXOs via the utxo_apply stage, but neither touches this
 * cursor — so after boot it froze at the boot value while the served tip
 * advanced, surfacing as chain_evidence's csr_cursor_mismatch (live tip hash
 * != live coins cursor hash). On the linear forward path the served tip IS
 * the coins frontier, so the reducer's post-finalize follow calls this to
 * keep csr_snapshot self-consistent. This does NOT persist anything and does
 * NOT move the tip/header — it is purely the in-memory cursor. Returns false
 * (no-op) on a null/uninitialized csr or null hash. */
bool csr_align_coins_best_block(struct chain_state_repository *csr,
                                const struct uint256 *hash);

/* ── Read-only introspection ──────────────────────────────────── */
void csr_snapshot(struct chain_state_repository *csr,
                   struct chain_state_view *out);

/* Cheap header-tip-only read: in-memory pindex_best_hdr height under the
 * repository lock, no SQLite queries. Returns -1 if csr is NULL/uninitialized
 * or no header tip is set yet. Prefer this over csr_snapshot() for callers
 * on a frequent tick that only need the header height. */
int64_t csr_header_height(struct chain_state_repository *csr);

/* Snapshot the validated best-header pointer under the repository lock.
 * Block-index objects have process lifetime, so the returned object remains
 * readable after the lock is released.  NULL means uninitialized/no header. */
struct block_index *csr_header_tip_snapshot(
    struct chain_state_repository *csr);
uint64_t csr_header_generation(const struct chain_state_repository *csr);

/* Captures the served/indexed/header frontier windows into *out under the
 * repository lock. Returns ZCL_OK only when out is non-NULL, csr is
 * initialized, AND the caller's expected_chain/expected_header_slot still
 * match the repository's bound state; a non-ok result names which
 * precondition failed (DEFENSIVE_CODING.md §2). */
struct zcl_result csr_capture_frontiers(
    struct chain_state_repository *csr,
    struct active_chain *expected_chain,
    struct block_index **expected_header_slot,
    int requested_height,
    struct chain_state_frontier_view *out);

/* ── Tunables ─────────────────────────────────────────────────── */

/* Reject a tip commit that would orphan more than this many UTXO rows
 * (i.e. when SQLite already holds significantly more UTXOs than the
 * proposed tip implies). Defaults to 1000. Set to INT64_MAX to disable.
 * The orphan check can also be bypassed per-commit with a typed
 * rollback_auth whose policy decision is POLICY_ALLOW. */
void csr_set_max_utxo_orphan_rows(struct chain_state_repository *csr,
                                   int64_t max_rows);

/* If SQLite reports a max block height more than this many blocks above
 * the proposed new tip, treat it as a stale-index condition. Defaults to
 * 100. Combined with the orphan-rows guard above, this is what catches
 * the h=60-vs-h=3M boot bug. */
void csr_set_stale_index_gap(struct chain_state_repository *csr, int gap);

#endif /* ZCL_SERVICES_CHAIN_STATE_SERVICE_H */
