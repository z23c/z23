// one-result-type-ok:bounded-backfill-progress-counter
/* E2 override: this module's public surface is a bounded best-effort
 * background walk (zslp_ledger_backfill_run_once returns the count of
 * heights folded this batch; 0 is a normal "nothing to do yet" state, not a
 * failure) plus registration/JSON-dump helpers — the same shape as the
 * sibling op_return_backfill_service. A per-height DB failure is fail-loud
 * via LOG_WARN inside zslp_ledger_apply_height and simply stops the batch
 * for a retry next tick; a zcl_result on the outer entry points would
 * duplicate that channel with a code/message callers must not branch on. */
// repair-rung-ok:test_zslp_ledger
// TENACITY I3: this is NOT a consensus-state repair rung — zslp_ledger is a
// rebuildable, non-consensus PROJECTION (never consulted by
// utxo_apply/consensus), and this service only ever POPULATES it forward
// from already-validated, already-persisted node.db projections
// (zslp_transfers / tx_outputs / tx_inputs), never patching a torn write.
// test_zslp_ledger's rebuild case proves a truncate + fresh re-derive
// reproduces the exact same row set and running digest — the same
// populate-only shape as op_return_backfill_service.c.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zslp_ledger_backfill_service — see services/zslp_ledger_backfill_service.h. */

#include "services/zslp_ledger_backfill_service.h"

#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <string.h>

/* services -> controllers is an upward include the shape-direction gate
 * rejects for new entries; declare the one accessor locally instead, the
 * same seam catalog_completeness.c uses. */
extern int node_db_sync_get_tip_height(struct node_db *ndb);

static _Atomic uint64_t g_backfill_ticks         = 0;
static _Atomic uint64_t g_backfill_blocks_folded = 0;
static _Atomic int64_t  g_backfill_last_height   = -1;

#ifdef ZCL_TESTING
struct node_db *g_zslp_ledger_backfill_test_ndb;
#endif

static struct node_db *backfill_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_zslp_ledger_backfill_test_ndb) return g_zslp_ledger_backfill_test_ndb;
#endif
    return app_runtime_node_db();
}

/* ── One bounded batch ────────────────────────────────────────────── */

int zslp_ledger_backfill_run_once(void)
{
    struct node_db *ndb = backfill_ndb();
    if (!ndb || !ndb->open)
        return 0; /* not wired yet (early boot / unit tests) — benign */

    int32_t cursor = -1;
    uint8_t digest[32];
    if (!zslp_ledger_get_cursor(ndb, &cursor, digest))
        return 0;

    int32_t hstar = reducer_frontier_provable_tip_cached();
    if (hstar < 0) hstar = 0;
    /* Projection-readiness gate (2026-08-02 C5 collect wedge): the rows
     * this backfill reads (zslp_transfers / tx_outputs / tx_inputs) are
     * written ONLY by explorer_index_block — inside the node_db catchup
     * pass, or inline in the regtest tip feed's async connect job. Folding
     * to bare H* raced ahead of the projection writer and folded "empty"
     * heights whose projections did not exist yet, permanently advancing
     * the cursor past a real mint block (its ledger row never existed and
     * the store token gate correctly answered 0 forever). Fold only up to
     * the catchup projection tip (SYNC_PROJECTION_TIP_HEIGHT_KEY via
     * node_db_sync_get_tip_height, -1 before the first catchup commit →
     * nothing to fold yet); the next tick closes the rest once the
     * projection writer commits. */
    {
        int32_t proj_tip = node_db_sync_get_tip_height(ndb);
        if (proj_tip < hstar) hstar = proj_tip;
    }
    if (cursor >= hstar)
        return 0; /* fully caught up to the (projection-backed) frontier */

    int32_t target = cursor + ZSLP_LEDGER_BACKFILL_BATCH_BLOCKS;
    if (target > hstar) target = hstar;

    int folded = 0;
    for (int32_t h = cursor + 1; h <= target; h++) {
        uint8_t new_digest[32];
        if (!zslp_ledger_apply_height(ndb, h, digest, new_digest)) {
            LOG_WARN("zslp_ledger",
                     "backfill: apply_height failed at h=%d — stopping this "
                     "batch, retrying next tick", h);
            break;
        }
        if (!zslp_ledger_set_cursor(ndb, h, new_digest)) {
            LOG_WARN("zslp_ledger",
                     "backfill: cursor persist failed at h=%d", h);
            break;
        }
        memcpy(digest, new_digest, 32);
        folded++;
        atomic_store(&g_backfill_last_height, h);
    }

    if (folded > 0)
        atomic_fetch_add(&g_backfill_blocks_folded, (uint64_t)folded);
    return folded;
}

/* ── Supervision (no dedicated thread — root supervisor drives on_tick) ── */

static struct liveness_contract g_backfill_contract;
static _Atomic supervisor_child_id g_backfill_id = SUPERVISOR_INVALID_ID;

static void backfill_tick(struct liveness_contract *c)
{
    (void)c;
    (void)zslp_ledger_backfill_run_once();
    atomic_fetch_add(&g_backfill_ticks, 1);
    supervisor_progress(atomic_load(&g_backfill_id),
                        (int64_t)atomic_load(&g_backfill_blocks_folded));
    supervisor_tick(atomic_load(&g_backfill_id));
}

void zslp_ledger_backfill_register(void)
{
    supervisor_domains_init();
    if (atomic_load(&g_backfill_id) != SUPERVISOR_INVALID_ID)
        return;
    liveness_contract_init(&g_backfill_contract, "chain.zslp_ledger_backfill");
    atomic_store(&g_backfill_contract.period_secs,
                 (int64_t)ZSLP_LEDGER_BACKFILL_PERIOD_SECS);
    atomic_store(&g_backfill_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_backfill_contract.progress_max_quiet_us, (int64_t)0);
    g_backfill_contract.on_tick = backfill_tick;
    g_backfill_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_backfill_contract);
    atomic_store(&g_backfill_id, id);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("zslp_ledger", "backfill: supervisor register failed");
}

void zslp_ledger_backfill_reset_for_test(void)
{
    atomic_store(&g_backfill_ticks, 0);
    atomic_store(&g_backfill_blocks_folded, 0);
    atomic_store(&g_backfill_last_height, -1);
}

/* ── `z23 dumpstate zslp_ledger` ─────────────────────────────── */

bool zslp_ledger_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    json_push_kv_int(out, "ticks", (int64_t)atomic_load(&g_backfill_ticks));
    json_push_kv_int(out, "blocks_folded",
                     (int64_t)atomic_load(&g_backfill_blocks_folded));
    json_push_kv_int(out, "last_folded_height",
                     atomic_load(&g_backfill_last_height));

    struct node_db *ndb = backfill_ndb();
    bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "wired", db_open);

    int32_t cursor = -1;
    uint8_t digest[32] = {0};
    bool have_cursor = db_open && zslp_ledger_get_cursor(ndb, &cursor, digest);
    json_push_kv_int(out, "cursor_height", have_cursor ? cursor : -1);
    char digest_hex[65] = {0};
    if (have_cursor) HexStr(digest, 32, false, digest_hex, sizeof(digest_hex));
    json_push_kv_str(out, "cursor_digest", digest_hex);

    int32_t hstar = reducer_frontier_provable_tip_cached();
    json_push_kv_int(out, "provable_tip", hstar);
    json_push_kv_int(out, "projection_tip",
        db_open ? node_db_sync_get_tip_height(ndb) : -1);
    json_push_kv_int(out, "blocks_remaining",
        (have_cursor && hstar > cursor) ? (int64_t)(hstar - cursor) : 0);
    json_push_kv_bool(out, "strict_validity_caught_up",
        have_cursor && hstar >= 0 && cursor >= hstar);

    if (db_open) {
        json_push_kv_int(out, "total_rows", zslp_ledger_count(ndb));
        json_push_kv_int(out, "unspent_rows", zslp_ledger_unspent_count(ndb));
        json_push_kv_int(out, "valid_transactions",
            zslp_validity_count(ndb, ZSLP_VALIDITY_VALID));
        json_push_kv_int(out, "invalid_transactions",
            zslp_validity_count(ndb, ZSLP_VALIDITY_INVALID));
        json_push_kv_int(out, "unknown_transactions",
            zslp_validity_count(ndb, ZSLP_VALIDITY_UNKNOWN));
    }
    return true;
}
