// one-result-type-ok:state-dump-and-predicates
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * invariant_sentinel_state - validation-pack health, dumpstate, and test reset.
 */

#include "services/invariant_sentinel.h"

#include "invariant_sentinel_internal.h"
#include "json/json.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

/* ── health + dump ──────────────────────────────────────────────── */

static const char *const k_pack_blockers[] = {
    "chain.linkage_violation",
    "chain.coinbase_label_mismatch",
    "authority.pair_self_check",
    "window.consistency",
    "coins.commitment_spot_check",
    "mirror.divergence_located",
    "seed.linkage_gate",
};

bool invariant_sentinel_healthy(char *detail, int detail_cap)
{
    if (detail && detail_cap > 0)
        detail[0] = '\0';
    bool ok = !chain_linkage_hold_active();
    for (size_t i = 0;
         i < sizeof(k_pack_blockers) / sizeof(k_pack_blockers[0]); i++) {
        if (blocker_exists(k_pack_blockers[i])) {
            ok = false;
            if (detail && detail_cap > 0 && !detail[0])
                snprintf(detail, (size_t)detail_cap, "%s",
                         k_pack_blockers[i]);
        }
    }
    return ok;
}

/* Counter accessors for the cross-module dump (seed gate + locator
 * register theirs through these setters to keep ONE dumper). */
static _Atomic uint64_t g_seed_gate_runs = 0;
static _Atomic uint64_t g_seed_gate_refusals = 0;
static _Atomic uint64_t g_locator_runs = 0;
static _Atomic int g_locator_first_div_h = -1;
static _Atomic uint64_t g_loader_height_fallbacks = 0;

void invariant_sentinel_note_seed_gate(bool refused)
{
    atomic_fetch_add(&g_seed_gate_runs, 1);
    if (refused)
        atomic_fetch_add(&g_seed_gate_refusals, 1);
}

void invariant_sentinel_note_locator(int first_div_h)
{
    atomic_fetch_add(&g_locator_runs, 1);
    if (first_div_h >= 0)
        atomic_store(&g_locator_first_div_h, first_div_h);
}

void invariant_sentinel_note_loader_height_fallback(void)
{
    atomic_fetch_add(&g_loader_height_fallbacks, 1);
}

bool invariant_sentinel_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    json_set_object(out);

    bool hold_active = false;
    int refuse_from = -1;
    char ids[96], reason[CHAIN_HOLD_REASON_MAX];
    chain_linkage_hold_snapshot(&hold_active, &refuse_from, ids,
                                (int)sizeof(ids), reason,
                                (int)sizeof(reason));
    json_push_kv_bool(out, "hold_active", hold_active);
    json_push_kv_int(out, "hold_refuse_from_h", (int64_t)refuse_from);
    json_push_kv_str(out, "hold_check_ids", ids);
    json_push_kv_str(out, "hold_reason", reason);

    json_push_kv_int(out, "linkage_violations_total",
                     (int64_t)chain_linkage_violations_total());
    json_push_kv_int(out, "hold_refusals_total",
                     (int64_t)chain_linkage_hold_refusals_total());
    json_push_kv_int(out, "offtip_switches_total",
                     (int64_t)chain_linkage_offtip_switches_total());

    json_push_kv_int(out, "pair_checks_total",
                     (int64_t)atomic_load(&g_isn_pair_checks_total));
    json_push_kv_int(out, "pair_violations_total",
                     (int64_t)atomic_load(&g_isn_pair_violations_total));

    json_push_kv_int(out, "sweeps_total",
                     (int64_t)atomic_load(&g_isn_sweeps_total));
    json_push_kv_int(out, "sweep_violations_total",
                     (int64_t)atomic_load(&g_isn_sweep_violations_total));
    json_push_kv_int(out, "last_sweep_unix",
                     atomic_load(&g_isn_last_sweep_unix));

    json_push_kv_int(out, "commitment_audits_total",
                     (int64_t)atomic_load(&g_isn_commitment_audits_total));
    json_push_kv_int(out, "commitment_mismatches_total",
                     (int64_t)atomic_load(&g_isn_commitment_mismatches_total));
    json_push_kv_int(out, "commitment_skipped_tip_moved",
                     (int64_t)atomic_load(&g_isn_commitment_skipped_tip_moved));
    json_push_kv_int(out, "last_audit_unix",
                     atomic_load(&g_isn_last_audit_unix));

    json_push_kv_int(out, "seed_gate_runs",
                     (int64_t)atomic_load(&g_seed_gate_runs));
    json_push_kv_int(out, "seed_gate_refusals",
                     (int64_t)atomic_load(&g_seed_gate_refusals));
    json_push_kv_int(out, "locator_runs",
                     (int64_t)atomic_load(&g_locator_runs));
    json_push_kv_int(out, "locator_first_div_h",
                     (int64_t)atomic_load(&g_locator_first_div_h));
    json_push_kv_int(out, "loader_height_fallbacks",
                     (int64_t)atomic_load(&g_loader_height_fallbacks));

    pthread_mutex_lock(&g_isn_detail_lock);
    json_push_kv_str(out, "last_sweep_detail", g_isn_last_sweep_detail);
    json_push_kv_str(out, "last_pair_detail", g_isn_last_pair_detail);
    pthread_mutex_unlock(&g_isn_detail_lock);

    struct json_value blockers = {0};
    json_set_object(&blockers);
    for (size_t i = 0;
         i < sizeof(k_pack_blockers) / sizeof(k_pack_blockers[0]); i++)
        json_push_kv_bool(&blockers, k_pack_blockers[i],
                          blocker_exists(k_pack_blockers[i]));
    json_push_kv(out, "blockers", &blockers);
    json_free(&blockers);

    char detail[BLOCKER_ID_MAX];
    json_push_kv_bool(out, "healthy",
                      invariant_sentinel_healthy(detail,
                                                 (int)sizeof(detail)));
    return true;
}

#ifdef ZCL_TESTING
void invariant_sentinel_reset_for_testing(void)
{
    g_isn_test_ndb = NULL;
    atomic_store(&g_isn_pair_checks_total, (uint64_t)0);
    atomic_store(&g_isn_pair_violations_total, (uint64_t)0);
    atomic_store(&g_isn_sweeps_total, (uint64_t)0);
    atomic_store(&g_isn_sweep_violations_total, (uint64_t)0);
    atomic_store(&g_isn_commitment_audits_total, (uint64_t)0);
    atomic_store(&g_isn_commitment_mismatches_total, (uint64_t)0);
    atomic_store(&g_isn_commitment_skipped_tip_moved, (uint64_t)0);
    atomic_store(&g_isn_sweep_blocker_active, false);
    atomic_store(&g_isn_audit_blocker_active, false);
    atomic_store(&g_isn_commitment_candidate_streak, 0);
    atomic_store(&g_seed_gate_runs, (uint64_t)0);
    atomic_store(&g_seed_gate_refusals, (uint64_t)0);
    atomic_store(&g_locator_runs, (uint64_t)0);
    atomic_store(&g_locator_first_div_h, -1);
    g_isn_prev_sweep_valid = false;
    g_isn_prev_reorg_total = 0;
    g_isn_prev_tip_finalize_cursor = -1;
    g_isn_pending_valid = false;
    g_isn_pending_first_bad_h = -1;
    g_isn_pending_invariant[0] = '\0';
    g_isn_memo_ua_frontier = -1;
    g_isn_memo_ua_cursor = -1;
    pthread_mutex_lock(&g_isn_detail_lock);
    g_isn_last_sweep_detail[0] = '\0';
    g_isn_last_pair_detail[0] = '\0';
    pthread_mutex_unlock(&g_isn_detail_lock);
}

void invariant_sentinel_set_node_db_for_testing(struct node_db *ndb)
{
    g_isn_test_ndb = ndb;
}
#endif
