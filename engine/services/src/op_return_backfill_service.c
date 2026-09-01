// one-result-type-ok:bounded-backfill-progress-counter
/* E2 override: this module's public surface is a bounded best-effort
 * background walk (op_return_backfill_run_once returns the count of
 * blocks folded this batch; 0 is a normal "nothing to do yet" state, not
 * a failure) plus registration/JSON-dump helpers, same shape as the
 * sibling authority_projection_audit / invariant_sentinel sweeps. A
 * per-height read/save failure is already fail-loud via LOG_WARN and
 * simply stops the batch for a retry next tick (see op_return_backfill_
 * run_once) — a zcl_result on the outer entry points would duplicate
 * that channel with a code/message callers must not branch on. */
// repair-rung-ok:test_op_return_index
// TENACITY I3: this is NOT a consensus-state repair rung — op_return_index
// is a rebuildable, non-consensus PROJECTION (never consulted by
// utxo_apply/consensus), and this service only ever POPULATES it forward
// from already-validated, already-persisted block bodies (never patches a
// torn write). test_op_return_index's backfill-e2e case proves a
// truncate + fresh re-derive reproduces the exact same row set and
// running digest, i.e. there is no "bad state" here to repair — the same
// populate-only shape as nullifier_backfill_service.c.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * op_return_backfill_service — see services/op_return_backfill_service.h. */

#include "services/op_return_backfill_service.h"

#include "chain/chain.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "models/zanc.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "services/index_fold_guard.h"
#include "storage/disk_block_io.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"  /* GetDataDir */
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static _Atomic uint64_t g_backfill_ticks          = 0;
static _Atomic uint64_t g_backfill_blocks_folded  = 0;
static _Atomic uint64_t g_backfill_rows_seen      = 0;
static _Atomic uint64_t g_backfill_holes          = 0;
static _Atomic uint64_t g_backfill_oversize_blocks = 0;
static _Atomic int64_t  g_backfill_last_height    = -1;
/* Base adoptions this process. Counted into the supervisor progress marker:
 * adopting a base IS state moving forward, and a tick that adopted one must
 * not look like a tick that achieved nothing. */
static _Atomic uint64_t g_backfill_base_seeds     = 0;
/* Declared ONCE per process (the fact is standing, not recurring) — see
 * index_fold_declare_partial_coverage. */
static _Atomic bool     g_backfill_partial_declared = false;

/* ── Unreadable-body latch + backoff ────────────────────────────────
 *
 * A body the index flags BLOCK_HAVE_DATA but that does not read back is not a
 * transient. Nothing in this process repairs a height this far below the fold
 * frontier: the have_data_unreadable Condition only inspects tip+1 and the
 * reducer stages. Live 2026-08-23 (node1) this service re-read h=1 every ~3 s
 * for 14.5 h — 12,435 identical failures, 12,435 identical WARN lines, and not
 * one of them could ever have succeeded. A batch that fails identically
 * forever must back off and latch into a named condition, not hot-loop.
 *
 * So: count consecutive failures at ONE height; retry on a geometric schedule
 * (the 2 s tick, then 4, 8, ... capped at 15 min) instead of every tick; and
 * once the retry budget is spent name the standing fact through the shared
 * index-fold guard. The blocker is the REPORT, never a silencer — the retry
 * keeps running on the slow schedule, the supervisor still sees BLOCKED (so
 * its NO_PROGRESS quiet clock still runs), and any successful fold at that
 * height clears the latch and the blocker together. */
#define BACKFILL_UNREADABLE_NAME_AFTER   5      /* attempts before naming it */
#define BACKFILL_UNREADABLE_MAX_DELAY_US ((int64_t)15 * 60 * 1000 * 1000)
static _Atomic int64_t  g_unreadable_height   = -1;
static _Atomic uint64_t g_unreadable_attempts = 0;
static _Atomic int64_t  g_unreadable_next_us  = 0;   /* monotonic due time */
static _Atomic uint64_t g_unreadable_deferrals = 0;  /* ticks the backoff ate */

static const char *g_backfill_datadir = NULL; /* process-lifetime string */

#ifdef ZCL_TESTING
struct node_db *g_op_return_backfill_test_ndb;
struct main_state *g_op_return_backfill_test_ms;
const char *g_op_return_backfill_test_datadir;
/* -1 = "ask the kernel authority" (production path). >=0 injects a snapshot
 * seed floor without a progress_store, so the adoption path is testable. */
_Atomic int64_t g_op_return_backfill_test_seed_floor = -1;
#endif

void op_return_backfill_set_datadir(const char *datadir)
{
    g_backfill_datadir = datadir;
}

static struct node_db *backfill_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_op_return_backfill_test_ndb) return g_op_return_backfill_test_ndb;
#endif
    return app_runtime_node_db();
}

static struct main_state *backfill_main_state(void)
{
#ifdef ZCL_TESTING
    if (g_op_return_backfill_test_ms) return g_op_return_backfill_test_ms;
#endif
    return app_runtime_main_state();
}

static const char *backfill_datadir(void)
{
#ifdef ZCL_TESTING
    if (g_op_return_backfill_test_datadir) return g_op_return_backfill_test_datadir;
#endif
    /* The body writer persists under the NET-SPECIFIC datadir
     * (GetDataDir(true) — <base>/regtest on regtest/testnet; see
     * reducer_ingest_service.c), so reads must resolve the same directory.
     * On mainnet GetDataDir(true)==base and this is byte-identical to the
     * wired base datadir. */
    static char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    return net_dir[0] ? net_dir : g_backfill_datadir;
}

/* The snapshot-seed floor, or false when this datadir has none (from-genesis)
 * or the kernel authority cannot be read. */
static bool backfill_seed_floor(int64_t *floor_out)
{
    *floor_out = -1;
#ifdef ZCL_TESTING
    int64_t inj = atomic_load(&g_op_return_backfill_test_seed_floor);
    if (inj >= 0) {
        *floor_out = inj;
        return true;
    }
#endif
    return index_fold_snapshot_seed_floor(floor_out);
}

/* Adopt `seed_floor` as the catalog's declared base: the chain restarts at
 * seed_floor+1 with a derived IV, rows outside the new range are pruned, and
 * the coverage limit becomes a NAMED standing declaration instead of a
 * per-tick spin. Returns true when the new state is durably persisted. */
static bool backfill_adopt_base(struct node_db *ndb,
                                struct op_return_index_cursor *cur,
                                int64_t seed_floor,
                                const uint8_t *floor_block_hash)
{
    struct op_return_index_cursor next;
    memset(&next, 0, sizeof(next));
    next.base_height = (int32_t)(seed_floor + 1);
    op_return_index_make_base_digest(next.base_height, floor_block_hash,
                                     next.base_digest);
    /* "based, nothing folded yet" — the next fold is base_height itself. */
    next.height = next.base_height - 1;
    memcpy(next.digest, next.base_digest, 32);

    if (!op_return_index_set_cursor(ndb, &next))
        LOG_FAIL("op_return_index",
                 "backfill: failed to persist adopted base_height=%d",
                 next.base_height);

    /* Rows below the new base are outside the declared range: the digest
     * chain does not cover them and no verifier could reproduce them. */
    if (!op_return_index_prune_below(ndb, next.base_height))
        LOG_WARN("op_return_index",
                 "backfill: prune below adopted base_height=%d failed — rows "
                 "outside the declared range may linger",
                 next.base_height);

    *cur = next;
    atomic_fetch_add(&g_backfill_base_seeds, 1);
    index_fold_declare_partial_coverage("op_return_index", "op_return_index",
                                        (int64_t)next.base_height, seed_floor);
    atomic_store(&g_backfill_partial_declared, true);
    return true;
}

/* Drop the latch (and the blocker it raised) — the height folded, or the fold
 * moved somewhere else entirely. Safe to call when nothing is latched. */
static void backfill_unreadable_clear(void)
{
    if (atomic_exchange(&g_unreadable_height, -1) < 0)
        return;
    atomic_store(&g_unreadable_attempts, 0);
    atomic_store(&g_unreadable_next_us, 0);
    index_fold_clear_unreadable_body("op_return_index");
}

/* True when `h` is the latched height AND its backoff has not expired: skip
 * the read entirely this tick. A different height clears the latch — the fold
 * moved, so the old fact no longer stands. */
static bool backfill_unreadable_defer_at(int32_t h)
{
    int64_t latched = atomic_load(&g_unreadable_height);
    if (latched < 0)
        return false;
    if (latched != (int64_t)h) {
        backfill_unreadable_clear();
        return false;
    }
    if (platform_time_monotonic_us() >= atomic_load(&g_unreadable_next_us))
        return false;              /* due: let this tick re-read it */
    atomic_fetch_add(&g_unreadable_deferrals, 1);
    return true;
}

/* Record one failed read at `h`: extend the backoff and, once the retry budget
 * is spent, name the standing condition. The FIRST failure at a height still
 * logs in full — the operator gets the height, the position and the fact, once
 * — and after that the named blocker carries it. */
static void backfill_unreadable_note(struct block_index *bi, int32_t h)
{
    uint64_t attempts;
    if (atomic_exchange(&g_unreadable_height, (int64_t)h) != (int64_t)h) {
        atomic_store(&g_unreadable_attempts, 1);
        attempts = 1;
        LOG_WARN("op_return_index",
                 "backfill: h=%d body unreadable (index says HAVE_DATA at "
                 "file=%d pos=%u) — backing off; the standing fact will be "
                 "named as op_return_index.body_unreadable if it persists",
                 h, block_index_file_load(bi), block_index_data_pos_load(bi));
    } else {
        attempts = atomic_fetch_add(&g_unreadable_attempts, 1) + 1;
    }

    /* Geometric: 2s, 4s, 8s ... capped. Shift is bounded by the cap check, so
     * it can never reach an undefined shift width. */
    int64_t delay = (int64_t)OP_RETURN_BACKFILL_PERIOD_SECS * 1000 * 1000;
    for (uint64_t i = 1; i < attempts && delay < BACKFILL_UNREADABLE_MAX_DELAY_US; i++)
        delay *= 2;
    if (delay > BACKFILL_UNREADABLE_MAX_DELAY_US)
        delay = BACKFILL_UNREADABLE_MAX_DELAY_US;
    atomic_store(&g_unreadable_next_us, platform_time_monotonic_us() + delay);

    if (attempts >= BACKFILL_UNREADABLE_NAME_AFTER)
        index_fold_note_unreadable_body("op_return_index", "op_return_index",
                                        (int64_t)h, attempts);
}

/* ── One bounded batch ──────────────────────────────────────────────
 *
 * This function used to return a bare `int folded`, and returned 0 from FIVE
 * structurally different states: not wired yet, cannot read my own cursor,
 * caught up, allocation failed, and wanted to fold but could not. Only one of
 * those (caught up) is healthy. The supervisor saw one number and could not
 * tell them apart, which is how this service reached ticks_run 13083 with
 * blocks_folded 0 while reporting stall_reason "none".
 *
 * `op_return_backfill_last_outcome()` publishes the distinction so the tick
 * can report the RESULT rather than the activity. The bare-int entry point is
 * kept byte-identical for its existing callers (tests + the manual re-run
 * path) — it just forwards. */
enum op_return_backfill_outcome {
    OP_RETURN_BACKFILL_PROGRESSED = 0, /* folded >= 1 block this run */
    OP_RETURN_BACKFILL_IDLE,           /* caught up: nothing to do, healthy */
    OP_RETURN_BACKFILL_NOT_WIRED,      /* DB/chain not up yet (early boot) */
    OP_RETURN_BACKFILL_BLOCKED,        /* wanted to fold and could not */
};

static _Atomic int g_backfill_outcome = OP_RETURN_BACKFILL_NOT_WIRED;

static enum op_return_backfill_outcome backfill_run_once_typed(int *folded_out)
{
    if (folded_out) *folded_out = 0;

    struct node_db *ndb = backfill_ndb();
    struct main_state *ms = backfill_main_state();
    const char *datadir = backfill_datadir();
    if (!ndb || !ndb->open || !ms || !datadir || !datadir[0])
        return OP_RETURN_BACKFILL_NOT_WIRED; /* early boot / unit tests */

    struct op_return_index_cursor cur;
    if (!op_return_index_get_cursor(ndb, &cur))
        /* Deliberately NOT idle: a service that cannot read its own cursor is
         * broken, not caught up, and it is the detector's job to say so. A
         * REFUSED state version (a legacy v1 record) lands here too — it is a
         * refusal that needs an operator, not a quiet no-op. */
        return OP_RETURN_BACKFILL_BLOCKED;

    /* An already-adopted base is a STANDING fact: re-declare it once per
     * process so a restart does not make the coverage limit invisible. */
    if (cur.base_height > 0 &&
        !atomic_load(&g_backfill_partial_declared)) {
        int64_t floor = -1;
        (void)backfill_seed_floor(&floor);
        index_fold_declare_partial_coverage("op_return_index",
                                            "op_return_index",
                                            (int64_t)cur.base_height,
                                            floor >= 0 ? floor
                                                       : cur.base_height - 1);
        atomic_store(&g_backfill_partial_declared, true);
    }

    int32_t cursor = cur.height;
    uint8_t digest[32];
    memcpy(digest, cur.digest, 32);

    int32_t hstar = reducer_frontier_provable_tip_cached();
    if (hstar < 0) hstar = 0;
    if (cursor >= hstar)
        return OP_RETURN_BACKFILL_IDLE; /* caught up to the provable frontier */

    int32_t target = cursor + OP_RETURN_BACKFILL_BATCH_BLOCKS;
    if (target > hstar) target = hstar;

    struct op_return_index_row *rows = zcl_malloc(
        (size_t)OP_RETURN_BACKFILL_MAX_ROWS_PER_BLOCK * sizeof(*rows),
        "op_return_backfill/rows");
    if (!rows) {
        LOG_WARN("op_return_index", "backfill: rows buffer alloc failed");
        return OP_RETURN_BACKFILL_BLOCKED;
    }

    int folded = 0;
    bool base_adopted = false;
    for (int32_t h = cursor + 1; h <= target; h++) {
        /* Still backing off a body that will not read: skip WITHOUT the read,
         * the 2 MB buffer and the log line. Nothing above h can fold either —
         * the fold is forward-only — so break, exactly as the miss would. */
        if (backfill_unreadable_defer_at(h))
            break;

        struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi || !bi->phashBlock ||
            !(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
            atomic_fetch_add(&g_backfill_holes, 1);

            /* Below the snapshot-seed floor the body was NEVER downloaded and
             * never will be by this fold — the old behaviour (name a blocker
             * and break) meant the catalog stayed empty forever and fired
             * op_return_index.below_snapshot_seed on every tick, 2,877 times
             * on the canonical node. The owner's decision is not to backfill
             * pre-seed bodies, so the catalog DECLARES the range it covers
             * instead: adopt the floor as the base, prune anything outside the
             * new range, and keep the coverage limit named via
             * *.partial_coverage. Guarded by base_height <= seed_floor so an
             * already-adopted base can never re-adopt (that would rewrite a
             * published digest chain from under a verifier). */
            int64_t seed_floor = -1;
            if (backfill_seed_floor(&seed_floor) && seed_floor >= 0 &&
                (int64_t)h <= seed_floor &&
                (int64_t)cur.base_height <= seed_floor) {
                struct block_index *fbi =
                    active_chain_at(&ms->chain_active, (int32_t)seed_floor);
                const uint8_t *floor_hash =
                    (fbi && fbi->phashBlock) ? fbi->phashBlock->data : NULL;
                if (backfill_adopt_base(ndb, &cur, seed_floor, floor_hash)) {
                    base_adopted = true;
                    /* The batch window was computed from the OLD cursor; stop
                     * here and let the next tick fold forward from the base. */
                    break;
                }
                /* Persist failed — fall through to the named blocker below so
                 * the condition stays visible rather than looking adopted. */
            }

            /* Name the floor (same pattern as address_index/txindex): below
             * the snapshot-seed floor this is a structural DEPENDENCY
             * (bodies never downloaded on a seeded datadir — the fold can
             * never cross), above it a transient gap. Without this the only
             * signal is catalog_lag_exceeded's "stalled and must resume",
             * which is false on a seeded datadir. The named blocker carries
             * the signal — no per-tick WARN (address_index_service stays
             * silent here for the same reason). */
            index_fold_note_absent_body("op_return_index", "op_return_index",
                                        ndb->db, h);
            break;
        }

        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_index_pread(&blk, bi, datadir)) {
            block_free(&blk);
            if (h == 0) {
                /* Genesis carries BLOCK_HAVE_DATA with a fake (file=0,pos=0)
                 * on seeded datadirs — its body was never written to this
                 * node's blk files, so a pread hashes whatever sits at
                 * offset 0 and the fold wedges on h=0 forever. The real
                 * genesis coinbase has no OP_RETURN outputs, so folding zero
                 * rows when the body is unreadable is byte-identical to
                 * folding the real body. When a body IS present (fixtures,
                 * a future full import) the normal path reads it and
                 * extracts whatever rows it carries — extraction parity with
                 * the state auditor is preserved. Same fact pattern as
                 * bg_validation_service.c ("if (h == 0) continue;"). */
                uint8_t genesis_digest[32];
                op_return_index_fold_block_digest(cur.base_height,
                                                  cur.base_digest, digest, 0,
                                                  bi->phashBlock->data,
                                                  rows, 0, genesis_digest);
                cur.height = 0;
                memcpy(cur.digest, genesis_digest, 32);
                if (!op_return_index_set_cursor(ndb, &cur)) {
                    LOG_WARN("op_return_index",
                             "backfill: cursor persist failed at h=0 (genesis)");
                    break;
                }
                memcpy(digest, genesis_digest, 32);
                folded++;
                atomic_store(&g_backfill_last_height, 0);
                continue;
            }
            atomic_fetch_add(&g_backfill_holes, 1);
            backfill_unreadable_note(bi, h);
            break;
        }
        /* Read back: whatever was latched here is over. */
        backfill_unreadable_clear();

        size_t n = 0;
        (void)op_return_index_apply_block_rows(
            ndb, &blk, h, rows, OP_RETURN_BACKFILL_MAX_ROWS_PER_BLOCK, &n);
        atomic_fetch_add(&g_backfill_rows_seen, (uint64_t)n);

        if (n > OP_RETURN_BACKFILL_MAX_ROWS_PER_BLOCK) {
            /* Every row is already saved (apply_block_rows never truncates
             * the inserts) but the digest buffer above only holds the cap
             * — folding a partial set would silently diverge the chain
             * from a peer that saw the full set. Stop the batch loudly; a
             * real-chain block should never hit this. */
            atomic_fetch_add(&g_backfill_oversize_blocks, 1);
            LOG_WARN("op_return_index",
                     "backfill: h=%d has %zu OP_RETURN outputs > cap=%d — "
                     "digest fold SKIPPED, cursor will not advance past %d",
                     h, n, OP_RETURN_BACKFILL_MAX_ROWS_PER_BLOCK, h - 1);
            block_free(&blk);
            break;
        }

        uint8_t new_digest[32];
        op_return_index_fold_block_digest(cur.base_height, cur.base_digest,
                                          digest, h, bi->phashBlock->data,
                                          rows, n, new_digest);
        cur.height = h;
        memcpy(cur.digest, new_digest, 32);
        if (!op_return_index_set_cursor(ndb, &cur)) {
            block_free(&blk);
            LOG_WARN("op_return_index",
                     "backfill: cursor persist failed at h=%d", h);
            break;
        }
        memcpy(digest, new_digest, 32);
        block_free(&blk);
        folded++;
        atomic_store(&g_backfill_last_height, h);
    }

    free(rows);
    if (folded > 0)
        atomic_fetch_add(&g_backfill_blocks_folded, (uint64_t)folded);
    if (folded_out) *folded_out = folded;
    /* Adopting the declared base is real, durable, forward state movement —
     * it is not "ran and achieved nothing". Reporting it as PROGRESSED is
     * honest precisely because the marker (see backfill_progress_marker)
     * counts base adoptions too, so it genuinely moves. */
    if (base_adopted)
        return OP_RETURN_BACKFILL_PROGRESSED;
    /* Wanted to fold (cursor < frontier, proven above) and folded nothing:
     * a hole, an unreadable body, or a failed cursor persist. Blocked. */
    return folded > 0 ? OP_RETURN_BACKFILL_PROGRESSED
                      : OP_RETURN_BACKFILL_BLOCKED;
}

int op_return_backfill_run_once(void)
{
    int folded = 0;
    atomic_store(&g_backfill_outcome,
                 (int)backfill_run_once_typed(&folded));
    return folded;
}

/* ── Supervision (no dedicated thread — root supervisor drives on_tick) ── */

static struct liveness_contract g_backfill_contract;
static _Atomic supervisor_child_id g_backfill_id = SUPERVISOR_INVALID_ID;

/* How long a run of blocked/not-wired ticks is allowed to last before the
 * supervisor calls this child stuck. The period is 2 s, so this is ~450
 * consecutive fruitless runs — far past any legitimate transient (a body
 * arriving late, the DB opening at boot) and far short of the 13083 the live
 * node reached in silence. */
#define OP_RETURN_BACKFILL_MAX_QUIET_US ((int64_t)15 * 60 * 1000 * 1000)

/* Results, not activity. Blocks folded is the primary result; base adoptions
 * are counted in because adopting the declared base advances durable state
 * without folding a block, and a marker that ignored it would let a genuinely
 * productive tick look frozen. Both components are monotone, so the marker is
 * monotone. */
static int64_t backfill_progress_marker(void)
{
    return (int64_t)atomic_load(&g_backfill_blocks_folded) +
           (int64_t)atomic_load(&g_backfill_base_seeds);
}

static void backfill_tick(struct liveness_contract *c)
{
    (void)c;
    (void)op_return_backfill_run_once();
    atomic_fetch_add(&g_backfill_ticks, 1);

    supervisor_child_id id = atomic_load(&g_backfill_id);
    switch ((enum op_return_backfill_outcome)
                atomic_load(&g_backfill_outcome)) {
    case OP_RETURN_BACKFILL_PROGRESSED:
        supervisor_progress(id, backfill_progress_marker());
        break;
    case OP_RETURN_BACKFILL_IDLE:
        /* Caught up to the frontier. Healthy, and must not be called stuck —
         * but it does not move the marker, so it cannot claim credit either. */
        supervisor_progress_idle(id);
        break;
    case OP_RETURN_BACKFILL_NOT_WIRED:
    case OP_RETURN_BACKFILL_BLOCKED:
        /* Report NEITHER. Leaving the quiet clock alone is the whole point:
         * these are the states that must accumulate into a NO_PROGRESS stall.
         * A backfill still unwired 15 minutes into a boot is as much a defect
         * as one wedged on a missing body.
         *
         * No on_stall/blocker is wired here on purpose. This fact already has
         * an operator-facing owner — catalog.op_return_index.lag_exceeded, and
         * index_fold_note_absent_body's below_snapshot_seed for the structural
         * case. A second name for one fact is the cloned-ledger anti-pattern;
         * what was missing was the SUPERVISOR telling the truth about it. */
        break;
    }
    supervisor_tick(id);
}

void op_return_backfill_register(void)
{
    supervisor_domains_init();
    if (atomic_load(&g_backfill_id) != SUPERVISOR_INVALID_ID)
        return;
    liveness_contract_init(&g_backfill_contract, "chain.op_return_backfill");
    atomic_store(&g_backfill_contract.period_secs,
                (int64_t)OP_RETURN_BACKFILL_PERIOD_SECS);
    atomic_store(&g_backfill_contract.deadline_secs, (int64_t)0);
    g_backfill_contract.on_tick = backfill_tick;
    g_backfill_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_backfill_contract);
    atomic_store(&g_backfill_id, id);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("op_return_index", "backfill: supervisor register failed");
    /* Count results, not activity: a run of fruitless ticks now becomes a
     * NO_PROGRESS stall instead of a healthy-looking ticks_run counter. Armed
     * AFTER register so the child id is valid. */
    supervisor_set_progress_max_quiet(id, OP_RETURN_BACKFILL_MAX_QUIET_US);
}

void op_return_backfill_reset_for_test(void)
{
    atomic_store(&g_backfill_ticks, 0);
    atomic_store(&g_backfill_blocks_folded, 0);
    atomic_store(&g_backfill_rows_seen, 0);
    atomic_store(&g_backfill_holes, 0);
    atomic_store(&g_backfill_oversize_blocks, 0);
    atomic_store(&g_backfill_last_height, -1);
    atomic_store(&g_backfill_base_seeds, 0);
    atomic_store(&g_backfill_partial_declared, false);
    atomic_store(&g_unreadable_deferrals, 0);
    backfill_unreadable_clear();
    index_fold_clear_partial_coverage("op_return_index");
}

/* ── `z23 dumpstate op_return_index` ─────────────────────────── */

bool op_return_index_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    json_push_kv_int(out, "ticks", (int64_t)atomic_load(&g_backfill_ticks));
    json_push_kv_int(out, "blocks_folded",
                     (int64_t)atomic_load(&g_backfill_blocks_folded));
    json_push_kv_int(out, "rows_seen",
                     (int64_t)atomic_load(&g_backfill_rows_seen));
    json_push_kv_int(out, "holes", (int64_t)atomic_load(&g_backfill_holes));
    json_push_kv_int(out, "oversize_blocks",
                     (int64_t)atomic_load(&g_backfill_oversize_blocks));
    json_push_kv_int(out, "last_folded_height",
                     atomic_load(&g_backfill_last_height));
    json_push_kv_int(out, "base_seeds",
                     (int64_t)atomic_load(&g_backfill_base_seeds));
    /* The unreadable-body latch. -1 = nothing latched. A non-negative height
     * with a climbing attempt count is the fold standing still on a torn body,
     * and `unreadable_deferrals` is how many ticks the backoff has SAVED (the
     * read + 2 MB buffer + WARN line each would have cost). */
    json_push_kv_int(out, "unreadable_height",
                     atomic_load(&g_unreadable_height));
    json_push_kv_int(out, "unreadable_attempts",
                     (int64_t)atomic_load(&g_unreadable_attempts));
    json_push_kv_int(out, "unreadable_deferrals",
                     (int64_t)atomic_load(&g_unreadable_deferrals));

    struct node_db *ndb = backfill_ndb();
    bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "wired", db_open);

    /* Name the persisted record shape: a REFUSED (legacy_v1/unknown) record
     * is why cursor_height reads -1, and an operator must be able to see
     * that without guessing. */
    enum op_return_index_state_version sv =
        db_open ? op_return_index_state_version(ndb)
                : OP_RETURN_INDEX_STATE_UNKNOWN;
    json_push_kv_str(out, "state_version",
                     op_return_index_state_version_name(sv));

    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.height = -1;
    bool have_cursor = db_open && op_return_index_get_cursor(ndb, &cur);
    int32_t cursor = have_cursor ? cur.height : -1;
    json_push_kv_int(out, "cursor_height", cursor);
    char digest_hex[65] = {0};
    if (have_cursor) HexStr(cur.digest, 32, false, digest_hex,
                            sizeof(digest_hex));
    json_push_kv_str(out, "cursor_digest", digest_hex);

    /* The declared range travels with the digest — an anchor built from
     * cursor_digest commits to [base_height, cursor_height] and nothing
     * else. */
    json_push_kv_int(out, "base_height", have_cursor ? cur.base_height : -1);
    char base_hex[65] = {0};
    if (have_cursor) HexStr(cur.base_digest, 32, false, base_hex,
                            sizeof(base_hex));
    json_push_kv_str(out, "base_digest", base_hex);
    json_push_kv_bool(out, "partial_coverage",
                      have_cursor && cur.base_height > 0);

    int32_t hstar = reducer_frontier_provable_tip_cached();
    json_push_kv_int(out, "provable_tip", hstar);
    json_push_kv_int(out, "blocks_remaining",
        (have_cursor && hstar > cursor) ? (int64_t)(hstar - cursor) : 0);

    if (db_open) {
        int64_t total = op_return_index_count(ndb);
        int64_t znam = op_return_index_count_by_tag_text(ndb, "ZNAM");
        int64_t zslp = op_return_index_count_by_tag_text(ndb, "SLP");
        int64_t zanc = op_return_index_count_by_tag_text(ndb, "ZANC");
        int64_t known = znam + zslp + zanc;
        int64_t other = total - known;
        if (other < 0) other = 0;
        json_push_kv_int(out, "total_rows", total);
        json_push_kv_int(out, "znam_rows", znam);
        json_push_kv_int(out, "zslp_rows", zslp);
        json_push_kv_int(out, "zanc_rows", zanc);
        json_push_kv_int(out, "other_rows", other);
    }
    return true;
}

/* ── `z23 dumpstate zepoch` ──────────────────────────────────
 *
 * Epoch-anchor status snapshot (the Bounded Node keystone, v1: no
 * background service, anchoring is an operator decision via
 * `core epoch anchor`): the catalog cursor (height + digest), the current
 * epoch (cursor/1000), and whether any ZANC anchor labeled zepoch@<H>
 * with H inside the current epoch already exists. Label semantics match
 * tools/command/native_epoch_command.c exactly. */

/* Latest zepoch anchor at-or-above min_height, newest first. Labels are
 * "zepoch@<H>" (H = the catalog cursor height the anchor committed). */
static bool zepoch_find_anchor(struct node_db *ndb, int32_t min_height,
                               struct zanc_anchor *out)
{
    struct zanc_anchor rows[100];
    int n = db_zanc_list(ndb, rows, 100);
    bool found = false;
    int32_t best = -1;
    for (int i = 0; i < n; i++) {
        if (strncmp(rows[i].label, "zepoch@", 7) != 0)
            continue;
        const char *hstr = rows[i].label + 7;
        if (!hstr[0])
            continue;
        char *end = NULL;
        long h = strtol(hstr, &end, 10);
        if (!end || *end != '\0' || h < min_height)
            continue;
        if (!found || h > best) {
            best = (int32_t)h;
            *out = rows[i];
            found = true;
        }
    }
    return found;
}

bool zepoch_status_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    struct node_db *ndb = backfill_ndb();
    bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "wired", db_open);

    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.height = -1;
    bool have_cursor = db_open && op_return_index_get_cursor(ndb, &cur);
    int32_t cursor = have_cursor ? cur.height : -1;
    json_push_kv_int(out, "tip_height", cursor);
    char digest_hex[65] = {0};
    if (have_cursor) HexStr(cur.digest, 32, false, digest_hex,
                            sizeof(digest_hex));
    json_push_kv_str(out, "catalog_digest", digest_hex);

    /* An epoch anchor commits to the catalog digest, and that digest covers
     * [base_height, tip_height] — never implicitly the whole chain. Publish
     * the range next to the digest so a reader of the anchor is never left
     * to assume genesis. */
    json_push_kv_int(out, "base_height", have_cursor ? cur.base_height : -1);
    char base_hex[65] = {0};
    if (have_cursor) HexStr(cur.base_digest, 32, false, base_hex,
                            sizeof(base_hex));
    json_push_kv_str(out, "base_digest", base_hex);
    json_push_kv_bool(out, "partial_coverage",
                      have_cursor && cur.base_height > 0);
    json_push_kv_str(out, "state_version",
                     op_return_index_state_version_name(
                         db_open ? op_return_index_state_version(ndb)
                                 : OP_RETURN_INDEX_STATE_UNKNOWN));

    int64_t epoch = (have_cursor && cursor >= 0) ? cursor / 1000 : -1;
    json_push_kv_int(out, "epoch", epoch);
    json_push_kv_int(out, "epoch_start", epoch >= 0 ? epoch * 1000 : -1);

    bool anchored = false;
    if (db_open && epoch >= 0) {
        struct zanc_anchor a;
        if (zepoch_find_anchor(ndb, (int32_t)(epoch * 1000), &a)) {
            anchored = true;
            json_push_kv_str(out, "anchor_label", a.label);
            char txid_hex[65];
            HexStr(a.txid, 32, false, txid_hex, sizeof(txid_hex));
            json_push_kv_str(out, "anchor_txid", txid_hex);
            json_push_kv_int(out, "anchor_height", a.height);
            char ad_hex[65];
            HexStr(a.digest, 32, false, ad_hex, sizeof(ad_hex));
            json_push_kv_str(out, "anchor_digest", ad_hex);
            json_push_kv_bool(out, "digest_match",
                              have_cursor &&
                              memcmp(a.digest, cur.digest, 32) == 0);
        }
    }
    json_push_kv_bool(out, "anchored", anchored);
    return true;
}
