/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/stage_repair.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "validation/process_block_revalidate.h"

#include <stdio.h>
#include <stdatomic.h>

static _Atomic int64_t g_target_at_detect = -1;
static _Atomic int64_t g_tip_height_at_check = -1;
static _Atomic int64_t g_tip_unchanged_since = 0;
static _Atomic int64_t g_tip_at_detect = -1;
static _Atomic int64_t g_tip_age_at_detect = 0;
static _Atomic int g_validate_repair_owner_height = -1;
static _Atomic int g_validate_repair_owner_mode = STAGE_REPAIR_POISON_NONE;
static _Atomic int g_reducer_owner_target = -1;
static _Atomic int g_reducer_owner_hstar = -1;
static _Atomic int g_reducer_owner_reason = 0;
static _Atomic int64_t g_last_remedy_target = -1;
static _Atomic int g_last_remedy_result = REVAL_NOT_ATTEMPTED;
static _Atomic int g_last_remedy_treated_ok = 0;
static _Atomic int64_t g_last_witness_tip_height = -1;
static _Atomic int g_last_witness_advanced_since_detect = 0;
static _Atomic int g_last_witness_target_failed_present = 0;
static _Atomic int g_last_witness_target_have_data_present = 0;

enum block_failed_stall_type {
    BF_STALL_NONE = 0,
    BF_STALL_FAILED_MASK,
    BF_STALL_NO_ADVANCE,
};

static _Atomic int g_stall_type_at_detect = BF_STALL_NONE;

enum reducer_frontier_owner_reason {
    RFO_NONE = 0,
    RFO_REPAIR,
    RFO_COIN_TEAR,
    RFO_COIN_UNKNOWN,
    RFO_VALUE_OVERFLOW,
    RFO_STALE_SCRIPT,
    RFO_COIN_BACKFILL,
    RFO_TIPFIN_BACKFILL,
    RFO_NONCANONICAL,
    RFO_REORG_RESIDUE_TIPFIN,
    RFO_PENDING_FINALIZE,
};

static const char *reducer_owner_reason_name(int reason)
{
    switch ((enum reducer_frontier_owner_reason)reason) {
    case RFO_NONE:                 return "none";
    case RFO_REPAIR:               return "frontier_repair";
    case RFO_COIN_TEAR:            return "coin_tear";
    case RFO_COIN_UNKNOWN:         return "coin_unknown";
    case RFO_VALUE_OVERFLOW:       return "value_overflow";
    case RFO_STALE_SCRIPT:         return "stale_script";
    case RFO_COIN_BACKFILL:        return "coin_backfill";
    case RFO_TIPFIN_BACKFILL:      return "tipfin_backfill";
    case RFO_NONCANONICAL:         return "noncanonical_rows";
    case RFO_REORG_RESIDUE_TIPFIN: return "reorg_residue_tipfin";
    case RFO_PENDING_FINALIZE:     return "pending_finalize";
    }
    return "unknown";
}

static const char *stall_type_name(int stall_type)
{
    switch ((enum block_failed_stall_type)stall_type) {
    case BF_STALL_NONE:        return "none";
    case BF_STALL_FAILED_MASK: return "failed_mask";
    case BF_STALL_NO_ADVANCE:  return "no_advance";
    }
    return "unknown";
}

static bool validate_repairable_mode(
    enum stage_repair_header_solution_poison mode)
{
    return mode == STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS ||
           mode == STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;
}

static bool repairable_validate_frontier_owns_stall(int64_t stall_target,
                                                    int *out_height,
                                                    int *out_mode)
{
    if (out_height)
        *out_height = -1;
    if (out_mode)
        *out_mode = STAGE_REPAIR_POISON_NONE;

    sqlite3 *db = progress_store_db();
    if (!db || stall_target < 0)
        return false;

    int repair_height = -1;
    if (!stage_repair_header_solution_repairable_validate_frontier(
            db, &repair_height) ||
        repair_height < 0 || repair_height > stall_target)
        return false;

    enum stage_repair_header_solution_poison mode =
        stage_repair_header_solution_poison_mode(db, repair_height);
    if (!validate_repairable_mode(mode)) {
        LOG_WARN("condition",
                 "block_failed_mask_at_tip: repair_height=%d poison_mode=%d not repairable",
                 repair_height, (int)mode);
        return false;
    }

    if (out_height)
        *out_height = repair_height;
    if (out_mode)
        *out_mode = (int)mode;
    return true;
}

static void remember_validate_repair_owner(int repair_height, int mode,
                                           int64_t stall_target)
{
    atomic_store(&g_validate_repair_owner_mode, mode);
    int prev = atomic_exchange(&g_validate_repair_owner_height, repair_height);
    if (prev != repair_height) {
        LOG_WARN("condition",
                 "[condition:block_failed_mask_at_tip] delegated no_advance "
                 "stall_target=%lld repair_height=%d repair_mode=%d owner="
                 "stale_validate_headers_repair",
                 (long long)stall_target, repair_height, mode);
    }
}

static int reducer_frontier_owner_reason(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (!rr)
        return RFO_NONE;
    if (rr->refused_coin_tear)
        return RFO_COIN_TEAR;
    if (rr->refused_coin_unknown)
        return RFO_COIN_UNKNOWN;
    if (rr->value_overflow_repair_owner_refused ||
        rr->value_overflow_repair_genuinely_invalid ||
        rr->value_overflow_repair_marker_seen)
        return RFO_VALUE_OVERFLOW;
    if (rr->stale_script_repair_attempted ||
        rr->stale_script_repair_genuinely_invalid ||
        rr->stale_script_repair_marker_seen)
        return RFO_STALE_SCRIPT;
    if (rr->coin_backfill_attempted || rr->coin_backfill_owner_refused ||
        rr->coin_backfill_genuinely_invalid)
        return RFO_COIN_BACKFILL;
    if (rr->tipfin_backfill_refused_reason != 0 ||
        rr->tipfin_backfill_count > 0 ||
        rr->tipfin_backfill_marker_seen)
        return RFO_TIPFIN_BACKFILL;
    if (rr->noncanonical_found > 0)
        return RFO_NONCANONICAL;
    if (rr->reorg_residue_tipfin_found > 0)
        return RFO_REORG_RESIDUE_TIPFIN;
    if (rr->repaired)
        return RFO_REPAIR;
    return RFO_NONE;
}

static void remember_reducer_frontier_owner(
    int64_t stall_target,
    int stall_type,
    const struct stage_reducer_frontier_reconcile_result *rr,
    int reason)
{
    atomic_store(&g_reducer_owner_hstar, rr ? rr->hstar : -1);
    atomic_store(&g_reducer_owner_reason, reason);
    int prev_target = atomic_exchange(&g_reducer_owner_target,
                                      (int)stall_target);
    if (prev_target != (int)stall_target) {
        LOG_WARN("condition",
                 "[condition:block_failed_mask_at_tip] delegated %s "
                 "stall_target=%lld hstar=%d coins_applied=%d sweep_top=%d "
                 "reason=%s owner=reducer_frontier_reconcile_light",
                 stall_type == BF_STALL_NO_ADVANCE ? "no_advance" :
                                                      "failed_mask",
                 (long long)stall_target,
                 rr ? rr->hstar : -1,
                 rr ? rr->coins_applied_height : -1,
                 rr ? rr->sweep_top : -1,
                 reducer_owner_reason_name(reason));
    }
}

static struct block_index *find_have_data_next(struct main_state *ms,
                                               int target);

static bool reducer_frontier_owns_stall(struct main_state *ms,
                                        int64_t stall_target,
                                        int stall_type)
{
    sqlite3 *db = progress_store_db();
    if (!db || !ms || stall_target < 0)
        return false;

    if (stall_type == BF_STALL_NO_ADVANCE) {
        int h = (int)stall_target;
        if ((int64_t)h == stall_target) {
            struct block_index *bi = find_have_data_next(ms, h);
            if (bi && bi->phashBlock && utxo_apply_stage_succeeded_at(h)) {
                uint8_t finalized[32] = {0};
                if (!tip_finalize_stage_block_hash_at(db, h, finalized)) {
                    remember_reducer_frontier_owner(
                        stall_target, stall_type, NULL,
                        RFO_PENDING_FINALIZE);
                    return true;
                }
            }
        }
    }

    struct stage_reducer_frontier_reconcile_result rr;
    bool have_rr = stage_reducer_frontier_reconcile_light_needed(db, ms, &rr);
    int reason = have_rr ? reducer_frontier_owner_reason(&rr) : RFO_NONE;
    if (reason == RFO_NONE)
        return false;

    remember_reducer_frontier_owner(stall_target, stall_type,
                                    have_rr ? &rr : NULL, reason);
    return true;
}

static struct block_index *find_failed_next(struct main_state *ms, int target)
{
    if (!ms) return NULL;
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (p && p->nHeight == target && (p->nStatus & BLOCK_FAILED_MASK))
            return p;
    }
    return NULL;
}

static struct block_index *find_have_data_next(struct main_state *ms, int target)
{
    if (!ms) return NULL;
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (!tip || !tip->phashBlock)
        return NULL;

    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (p && p->nHeight == target &&
            p->pprev == tip &&
            (p->nStatus & BLOCK_HAVE_DATA) &&
            !(p->nStatus & BLOCK_FAILED_MASK))
            return p;
    }
    return NULL;
}

static int64_t current_tip_height(struct main_state *ms)
{
    return ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
}

static int64_t target_height(void)
{
    struct main_state *ms = condition_engine_main_state();
    int64_t tip = current_tip_height(ms);
    return tip >= 0 ? tip + 1 : -1;
}

static bool detect_block_failed_mask_at_tip(void)
{
    struct main_state *ms = condition_engine_main_state();
    int64_t target = target_height();
    if (target >= 0 && find_failed_next(ms, (int)target) != NULL) {
        if (reducer_frontier_owns_stall(ms, target, BF_STALL_FAILED_MASK))
            return false;
        atomic_store(&g_target_at_detect, target);
        atomic_store(&g_tip_at_detect, current_tip_height(ms));
        atomic_store(&g_tip_age_at_detect, 0);
        atomic_store(&g_stall_type_at_detect, BF_STALL_FAILED_MASK);
        return true;
    }

    int64_t tip = current_tip_height(ms);
    int64_t now = platform_time_wall_unix();
    int64_t prev_tip = atomic_load(&g_tip_height_at_check);
    if (prev_tip != tip) {
        atomic_store(&g_tip_height_at_check, tip);
        atomic_store(&g_tip_unchanged_since, now);
        return false;
    }

    int64_t unchanged_since = atomic_load(&g_tip_unchanged_since);
    if (unchanged_since == 0) {
        atomic_store(&g_tip_unchanged_since, now);
        return false;
    }

    int64_t tip_age_s = now - unchanged_since;
    if (tip >= 0 && target >= 0 && tip_age_s >= 300 &&
        find_have_data_next(ms, (int)target) != NULL) {
        int repair_height = -1;
        int repair_mode = STAGE_REPAIR_POISON_NONE;
        if (repairable_validate_frontier_owns_stall(
                target, &repair_height, &repair_mode)) {
            remember_validate_repair_owner(repair_height, repair_mode, target);
            return false;
        }
        if (reducer_frontier_owns_stall(ms, target, BF_STALL_NO_ADVANCE))
            return false;
        atomic_store(&g_validate_repair_owner_height, -1);
        atomic_store(&g_validate_repair_owner_mode, STAGE_REPAIR_POISON_NONE);
        atomic_store(&g_target_at_detect, target);
        atomic_store(&g_tip_at_detect, tip);
        atomic_store(&g_tip_age_at_detect, tip_age_s);
        atomic_store(&g_stall_type_at_detect, BF_STALL_NO_ADVANCE);
        return true;
    }

    return false;
}

static enum condition_remedy_result remedy_block_failed_mask_at_tip(void)
{
    struct main_state *ms = condition_engine_main_state();
    int64_t target = atomic_load(&g_target_at_detect);
    if (target < 0)
        target = target_height();
    if (!ms || target < 0)
        return COND_REMEDY_SKIP;
    struct uint256 out_hash;
    enum reval_result r =
        process_block_revalidate((int)target, ms, &out_hash);
    int stall_type = atomic_load(&g_stall_type_at_detect);
    bool treated_ok =
        (stall_type == BF_STALL_NO_ADVANCE &&
         r == REVAL_HEIGHT_NOT_FOUND) ||
        r == REVAL_RECOVERED ||
        r == REVAL_NO_FAILURE;
    atomic_store(&g_last_remedy_target, target);
    atomic_store(&g_last_remedy_result, (int)r);
    atomic_store(&g_last_remedy_treated_ok, treated_ok ? 1 : 0);
    LOG_WARN("condition",
             "[condition:block_failed_mask_at_tip] target=%lld "
             "stall_type=%s tip_age_s=%lld result=%s treated_ok=%s",
             (long long)target,
             stall_type == BF_STALL_NO_ADVANCE ? "no_advance"
                                                : "failed_mask",
             (long long)atomic_load(&g_tip_age_at_detect),
             reval_result_name(r), treated_ok ? "true" : "false");
    if (treated_ok)
        return COND_REMEDY_OK;
    return COND_REMEDY_FAILED;
}

static bool witness_block_failed_mask_at_tip(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = condition_engine_main_state();
    int64_t target = atomic_load(&g_target_at_detect);
    int stall_type = atomic_load(&g_stall_type_at_detect);
    if (!ms || target < 0)
        return false;
    int64_t tip = current_tip_height(ms);
    atomic_store(&g_last_witness_tip_height, tip);
    atomic_store(&g_last_witness_advanced_since_detect,
                 tip > atomic_load(&g_tip_at_detect) ? 1 : 0);
    atomic_store(&g_last_witness_target_failed_present,
                 find_failed_next(ms, (int)target) != NULL ? 1 : 0);
    atomic_store(&g_last_witness_target_have_data_present,
                 find_have_data_next(ms, (int)target) != NULL ? 1 : 0);
    if (reducer_frontier_owns_stall(ms, target, stall_type))
        return true;
    if (stall_type == BF_STALL_NO_ADVANCE) {
        int repair_height = -1;
        int repair_mode = STAGE_REPAIR_POISON_NONE;
        if (repairable_validate_frontier_owns_stall(
                target, &repair_height, &repair_mode)) {
            remember_validate_repair_owner(repair_height, repair_mode, target);
            return true;
        }
        return tip > atomic_load(&g_tip_at_detect);
    }
    return find_failed_next(ms, (int)target) == NULL;
}

static bool detail_block_failed_mask_at_tip(struct json_value *out)
{
    if (!out)
        return false;

    int validate_owner = atomic_load(&g_validate_repair_owner_height);
    int reducer_target = atomic_load(&g_reducer_owner_target);
    const char *delegated_owner = "none";
    if (reducer_target >= 0)
        delegated_owner = "reducer_frontier_reconcile_light";
    else if (validate_owner >= 0)
        delegated_owner = "stale_validate_headers_repair";

    bool ok = true;
    ok = ok && json_push_kv_int(out, "block_target_height",
                                atomic_load(&g_target_at_detect));
    ok = ok && json_push_kv_int(out, "tip_height_at_detect",
                                atomic_load(&g_tip_at_detect));
    ok = ok && json_push_kv_int(out, "tip_age_s",
                                atomic_load(&g_tip_age_at_detect));
    ok = ok && json_push_kv_str(
        out, "stall_type",
        stall_type_name(atomic_load(&g_stall_type_at_detect)));
    ok = ok && json_push_kv_int(out, "validate_repair_owner_height",
                                validate_owner);
    ok = ok && json_push_kv_int(out, "validate_repair_owner_mode",
                                atomic_load(&g_validate_repair_owner_mode));
    ok = ok && json_push_kv_str(out, "delegated_owner", delegated_owner);
    ok = ok && json_push_kv_int(out, "last_remedy_target_height",
                                atomic_load(&g_last_remedy_target));
    ok = ok && json_push_kv_str(
        out, "last_remedy_result",
        reval_result_name((enum reval_result)atomic_load(
            &g_last_remedy_result)));
    ok = ok && json_push_kv_bool(
        out, "last_remedy_treated_ok",
        atomic_load(&g_last_remedy_treated_ok) != 0);
    ok = ok && json_push_kv_int(out, "last_witness_tip_height",
                                atomic_load(&g_last_witness_tip_height));
    ok = ok && json_push_kv_bool(
        out, "last_witness_advanced_since_detect",
        atomic_load(&g_last_witness_advanced_since_detect) != 0);
    ok = ok && json_push_kv_bool(
        out, "last_witness_target_failed_present",
        atomic_load(&g_last_witness_target_failed_present) != 0);
    ok = ok && json_push_kv_bool(
        out, "last_witness_target_have_data_present",
        atomic_load(&g_last_witness_target_have_data_present) != 0);
    ok = ok && json_push_kv_str(
        out, "remedy_contract",
        "height_not_found is accepted only for no_advance; final success requires delegated owner, target failure cleared, or observed tip advance");
    ok = ok && json_push_kv_int(out, "reducer_frontier_owner_target",
                                reducer_target);
    ok = ok && json_push_kv_int(out, "reducer_frontier_owner_hstar",
                                atomic_load(&g_reducer_owner_hstar));
    ok = ok && json_push_kv_str(
        out, "reducer_frontier_owner_reason",
        reducer_owner_reason_name(atomic_load(&g_reducer_owner_reason)));
    return ok;
}

static struct condition c_block_failed_mask_at_tip = {
    .name = "block_failed_mask_at_tip",
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 30,
    .max_attempts = 5,
    .detect = detect_block_failed_mask_at_tip,
    .remedy = remedy_block_failed_mask_at_tip,
    .witness = witness_block_failed_mask_at_tip,
    .detail = detail_block_failed_mask_at_tip,
    .witness_window_secs = 60,
};

void register_block_failed_mask_at_tip(void)
{
    (void)condition_register(&c_block_failed_mask_at_tip);
}

bool block_failed_mask_at_tip_recovery_exhausted(int *target_height,
                                                 int *attempts_out)
{
    struct condition_state *s = &c_block_failed_mask_at_tip.state;
    int attempts = atomic_load(&s->attempts);
    int max_attempts = c_block_failed_mask_at_tip.max_attempts > 0
        ? c_block_failed_mask_at_tip.max_attempts : 1;
    int last_outcome = atomic_load(&s->last_outcome);
    int stall_type = atomic_load(&g_stall_type_at_detect);
    bool exhausted_outcome = last_outcome == COND_REMEDY_FAILED ||
        (stall_type == BF_STALL_NO_ADVANCE &&
         last_outcome == COND_REMEDY_UNWITNESSED);
    bool exhausted = atomic_load(&s->currently_active) &&
        attempts >= max_attempts &&
        exhausted_outcome;

    if (exhausted &&
        reducer_frontier_owns_stall(condition_engine_main_state(),
                                    atomic_load(&g_target_at_detect),
                                    stall_type)) {
        exhausted = false;
    }

    if (target_height)
        *target_height = (int)atomic_load(&g_target_at_detect);
    if (attempts_out)
        *attempts_out = attempts;
    return exhausted;
}

bool block_failed_mask_at_tip_recovery_exhausted_is_no_advance(void)
{
    return atomic_load(&g_stall_type_at_detect) == BF_STALL_NO_ADVANCE;
}

#ifdef ZCL_TESTING
void block_failed_mask_at_tip_test_reset(void)
{
    atomic_store(&g_target_at_detect, -1);
    atomic_store(&g_tip_height_at_check, -1);
    atomic_store(&g_tip_unchanged_since, 0);
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_tip_age_at_detect, 0);
    atomic_store(&g_validate_repair_owner_height, -1);
    atomic_store(&g_validate_repair_owner_mode, STAGE_REPAIR_POISON_NONE);
    atomic_store(&g_reducer_owner_target, -1);
    atomic_store(&g_reducer_owner_hstar, -1);
    atomic_store(&g_reducer_owner_reason, RFO_NONE);
    atomic_store(&g_stall_type_at_detect, BF_STALL_NONE);
    atomic_store(&g_last_remedy_target, -1);
    atomic_store(&g_last_remedy_result, REVAL_NOT_ATTEMPTED);
    atomic_store(&g_last_remedy_treated_ok, 0);
    atomic_store(&g_last_witness_tip_height, -1);
    atomic_store(&g_last_witness_advanced_since_detect, 0);
    atomic_store(&g_last_witness_target_failed_present, 0);
    atomic_store(&g_last_witness_target_have_data_present, 0);
    condition_reset_state(&c_block_failed_mask_at_tip);
}

int block_failed_mask_at_tip_test_stall_type(void)
{
    return atomic_load(&g_stall_type_at_detect);
}

int block_failed_mask_at_tip_test_target_height(void)
{
    return (int)atomic_load(&g_target_at_detect);
}

int block_failed_mask_at_tip_test_validate_repair_owner_height(void)
{
    return atomic_load(&g_validate_repair_owner_height);
}

int block_failed_mask_at_tip_test_reducer_owner_target(void)
{
    return atomic_load(&g_reducer_owner_target);
}

int block_failed_mask_at_tip_test_reducer_owner_hstar(void)
{
    return atomic_load(&g_reducer_owner_hstar);
}

int block_failed_mask_at_tip_test_reducer_owner_reason(void)
{
    return atomic_load(&g_reducer_owner_reason);
}

void block_failed_mask_at_tip_test_mark_exhausted(int target_height)
{
    struct condition_state *s = &c_block_failed_mask_at_tip.state;
    atomic_store(&g_target_at_detect, target_height);
    atomic_store(&g_tip_at_detect, target_height - 1);
    atomic_store(&g_stall_type_at_detect, BF_STALL_FAILED_MASK);
    atomic_store(&s->currently_active, true);
    atomic_store(&s->attempts, c_block_failed_mask_at_tip.max_attempts);
    atomic_store(&s->last_outcome, COND_REMEDY_FAILED);
}

void block_failed_mask_at_tip_test_mark_no_advance_exhausted(
    int target_height,
    int tip_height)
{
    struct condition_state *s = &c_block_failed_mask_at_tip.state;
    atomic_store(&g_target_at_detect, target_height);
    atomic_store(&g_tip_at_detect, tip_height);
    atomic_store(&g_stall_type_at_detect, BF_STALL_NO_ADVANCE);
    atomic_store(&s->currently_active, true);
    atomic_store(&s->attempts, c_block_failed_mask_at_tip.max_attempts);
    atomic_store(&s->last_outcome, COND_REMEDY_UNWITNESSED);
}
#endif
