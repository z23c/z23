/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_status — see jobs/rom_compile_status.h. Pure composition over
 * existing accessors; issues no INSERT/UPDATE/DELETE of its own (the one
 * progress_meta read below is the SAME SELECT-only pattern
 * refold_progress_dump_state_json already uses for the identical key). */

#include "jobs/rom_compile_status.h"

#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/tip_finalize_stage.h"
#include "util/stage.h"
#include "controllers/chain_segment_controller.h"
#include "services/seal_service.h"
#include "config/bundle_exporter.h"
#include "storage/progress_store.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "chain/checkpoints.h"
#include "json/json.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "core/utiltime.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── cross-call rate sample ──────────────────────────────────────────────
 * Best-effort, in-process only: two successive calls to this dumper (any
 * caller — dumpstate RPC, ops.rom) let us derive blk/s and ETA without a
 * second background producer. The FIRST call in a process's lifetime (or
 * after a test reset) has no prior sample, so it reports rate=0 / eta
 * unknown rather than guessing. Lock-free: a torn read only costs one wrong
 * rate sample on the diagnostic path, never correctness. */
static _Atomic int64_t g_rcs_last_us     = 0;
static _Atomic int32_t g_rcs_last_height = -1;

#ifdef ZCL_TESTING
void rom_compile_status_test_reset_rate_sample(void)
{
    atomic_store(&g_rcs_last_us, 0);
    atomic_store(&g_rcs_last_height, -1);
}
#endif

static void rcs_sample(int32_t height, double *out_rate_blk_s)
{
    *out_rate_blk_s = 0.0;
    int64_t now_us = GetTimeMicros();
    int64_t prev_us = atomic_load(&g_rcs_last_us);
    int32_t prev_h  = atomic_load(&g_rcs_last_height);
    if (prev_us > 0 && prev_h >= 0 && now_us > prev_us) {
        double dt_s = (double)(now_us - prev_us) / 1e6;
        if (dt_s > 0.0) {
            int64_t dh = (int64_t)height - (int64_t)prev_h;
            if (dh > 0)
                *out_rate_blk_s = (double)dh / dt_s;
        }
    }
    atomic_store(&g_rcs_last_us, now_us);
    atomic_store(&g_rcs_last_height, height);
}

static void hex_prefix(const uint8_t *bytes, size_t n, char *out, size_t cap)
{
    size_t w = 0;
    for (size_t i = 0; i < n && w + 2 < cap; i++)
        w += (size_t)snprintf(out + w, cap - w, "%02x", bytes[i]);
    if (cap > 0) out[w < cap ? w : cap - 1] = '\0';
}

static void eta_human(int64_t eta_s, char *out, size_t cap)
{
    if (eta_s < 0) {
        snprintf(out, cap, "unknown");
        return;
    }
    snprintf(out, cap, "%lldh%02lldm%02llds",
             (long long)(eta_s / 3600), (long long)((eta_s % 3600) / 60),
             (long long)(eta_s % 60));
}

struct rcs_stage_row {
    const char *abbrev;
    const char *name;
    int64_t (*ewma)(void);
    uint64_t (*cursor)(void);
};

static const struct rcs_stage_row k_stage_rows[8] = {
    { "ha", "header_admit",     header_admit_stage_step_us_ewma,
      header_admit_stage_cursor },
    { "vh", "validate_headers", validate_headers_stage_step_us_ewma,
      validate_headers_stage_cursor },
    { "bf", "body_fetch",       body_fetch_stage_step_us_ewma,
      body_fetch_stage_cursor },
    { "bp", "body_persist",     body_persist_stage_step_us_ewma,
      body_persist_stage_cursor },
    { "sv", "script_validate",  script_validate_stage_step_us_ewma,
      script_validate_stage_cursor },
    { "pv", "proof_validate",   proof_validate_stage_step_us_ewma,
      proof_validate_stage_cursor },
    { "ua", "utxo_apply",       utxo_apply_stage_step_us_ewma,
      utxo_apply_stage_cursor },
    { "tf", "tip_finalize",     tip_finalize_stage_step_us_ewma,
      tip_finalize_stage_cursor },
};

static void push_stages(struct json_value *out, const char **bottleneck_abbrev)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    size_t slow = 0;
    int64_t slow_ewma = -1;
    for (size_t i = 0; i < 8; i++) {
        int64_t ewma_us = k_stage_rows[i].ewma();
        if (ewma_us > slow_ewma) { slow_ewma = ewma_us; slow = i; }
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "abbrev", k_stage_rows[i].abbrev);
        json_push_kv_str(&item, "stage", k_stage_rows[i].name);
        json_push_kv_int(&item, "cursor", (int64_t)k_stage_rows[i].cursor());
        json_push_kv_int(&item, "step_us_ewma", ewma_us);
        json_push_kv_int(&item, "steps_per_sec",
                         ewma_us > 0
                             ? (int64_t)(1000000.0 / (double)ewma_us + 0.5)
                             : 0);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(out, "stages", &arr);
    json_free(&arr);
    *bottleneck_abbrev = k_stage_rows[slow].abbrev;
}

static void push_layers(struct json_value *out)
{
    struct json_value layers;
    json_init(&layers);
    json_set_object(&layers);

    /* Layer 1 — ROM checkpoint: the compiled SHA3 UTXO commitment. Always
     * present (it is baked into the binary), so this layer is always
     * "filled" in the ladder render. */
    {
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        json_push_kv_bool(&l, "present", cp != NULL);
        json_push_kv_int(&l, "height",
                         cp ? (int64_t)cp->height
                            : (int64_t)REDUCER_FRONTIER_TRUSTED_ANCHOR);
        char prefix[9] = {0};
        if (cp) hex_prefix(cp->sha3_hash, 4, prefix, sizeof(prefix));
        json_push_kv_str(&l, "sha3_prefix", prefix);
        json_push_kv(&layers, "rom_checkpoint", &l);
        json_free(&l);
    }

    /* Layer 2 — sealed history: write-once SHA3-committed block-body
     * segments (engine/modules/storage/chain_segment.{c,h}). Composed via the EXISTING
     * chain_segments dumper — no directory-resolution logic duplicated
     * here. */
    {
        struct json_value seg;
        json_init(&seg);
        bool ok = chain_segment_dump_state_json(&seg, NULL);
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        int64_t segment_count = ok ? json_get_int(json_get(&seg, "segment_count")) : 0;
        int64_t present_count =
            ok ? json_get_int(json_get(&seg, "present_count")) : 0;
        json_push_kv_bool(&l, "present", ok && segment_count > 0);
        json_push_kv_int(&l, "segment_count", segment_count);
        json_push_kv_int(&l, "present_count", present_count);
        /* verified_count == the store's chain_segment_stat.verified_count (the
         * cheap present-and-matching-header pass the dumper reports); the
         * manifest ladder row reads it. */
        json_push_kv_int(&l, "verified_count", present_count);
        json_push_kv_int(&l, "min_height",
                         ok ? json_get_int(json_get(&seg, "min_height")) : -1);
        json_push_kv_int(&l, "max_height",
                         ok ? json_get_int(json_get(&seg, "max_height")) : -1);
        json_push_kv(&layers, "sealed_history", &l);
        json_free(&l);
        json_free(&seg);
    }

    /* Layer 3 — sealed base+receipt state: the state-seal ring
     * (engine/modules/storage/seal_kv.h), composed via the EXISTING seal dumper. Reports
     * the highest RATIFIED grid-point seal. */
    {
        struct json_value seal;
        json_init(&seal);
        bool ok = seal_dump_state_json(&seal, NULL);
        int32_t best_height = -1;
        bool any_ratified = false;
        const struct json_value *slots = ok ? json_get(&seal, "slots") : NULL;
        if (slots && slots->type == JSON_ARR) {
            for (size_t i = 0; i < slots->num_children; i++) {
                const struct json_value *slot = json_at(slots, i);
                if (json_get_bool(json_get(slot, "ratified"))) {
                    int64_t h = json_get_int(json_get(slot, "height"));
                    if (!any_ratified || h > best_height) {
                        best_height = (int32_t)h;
                        any_ratified = true;
                    }
                }
            }
        }
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        json_push_kv_bool(&l, "present", any_ratified);
        json_push_kv_int(&l, "ratified_height", best_height);
        json_push_kv(&layers, "sealed_base_receipt", &l);
        json_free(&l);
        json_free(&seal);
    }

    /* Layer 4 — delta: the coins-applied frontier co-committed with every
     * coin mutation (jobs/reducer_frontier.h derivation, never a separate
     * cache). */
    {
        int32_t coins_best = -1;
        bool found = false;
        bool ok = reducer_frontier_derive_coins_best_now(&coins_best, NULL,
                                                         NULL);
        found = ok;
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        json_push_kv_bool(&l, "present", found && coins_best >= 0);
        json_push_kv_int(&l, "coins_best_height", found ? coins_best : -1);
        json_push_kv(&layers, "delta", &l);
        json_free(&l);
    }

    /* Layer 5 — tip ring: the provable-tip served to external consumers. */
    {
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        int32_t hstar = reducer_frontier_provable_tip_cached();
        json_push_kv_bool(&l, "present", hstar > 0);
        json_push_kv_int(&l, "hstar", hstar);
        json_push_kv_int(&l, "external_tip_height",
                         reducer_frontier_external_tip_height());
        json_push_kv(&layers, "tip_ring", &l);
        json_free(&l);
    }

    /* Layer 6 — bundle export: the standing live consensus-state bundle
     * exporter (config/bundle_exporter.h). The last exported generation is the
     * head of the ROM pipeline that others re-serve. Composed via the EXISTING
     * exporter dumper; graceful present=false when the exporter never opened a
     * session (no state) or never exported. */
    {
        struct json_value bx;
        json_init(&bx);
        bool ok = bundle_exporter_dump_state_json(&bx, NULL);
        int64_t last_height =
            ok ? json_get_int(json_get(&bx, "last_export_height")) : 0;
        const struct json_value *gens = ok ? json_get(&bx, "generations") : NULL;
        int64_t gen_count =
            (gens && gens->type == JSON_ARR) ? (int64_t)gens->num_children : 0;
        struct json_value l;
        json_init(&l);
        json_set_object(&l);
        json_push_kv_bool(&l, "present", ok && last_height > 0);
        json_push_kv_int(&l, "last_height", last_height);
        json_push_kv_int(&l, "generations", gen_count);
        json_push_kv(&layers, "bundle_export", &l);
        json_free(&l);
        json_free(&bx);
    }

    json_push_kv(out, "layers", &layers);
    json_free(&layers);
}

/* ── shielded-history import -> resume transition telemetry ──────────────
 *
 * Makes the shielded_history_import_service.c (-import-complete-shielded)
 * cure OBSERVABLE end to end: both activation cursors, whether the standing
 * gap blockers (utxo_apply.anchor_backfill_gap / .nullifier_backfill_gap)
 * are still latched, the durable row counts a completed import actually
 * wrote (anchor_kv/nullifier_kv — otherwise the -import-complete-shielded
 * run's counts are lost to stdout the moment that one-shot process exits),
 * and the reducer's own resume cursor (utxo_apply_stage_cursor — the SAME
 * live counter fold.height already derives from) so "is it actually
 * recovering?" is a `dumpstate rom_compile` / `ops.rom` read, not a
 * log-grep. Read-only: one best-effort progress.kv snapshot under a
 * NON-BLOCKING trylock (same "diagnostics are observational, never queue
 * behind the reducer" contract as reducer_frontier_dump_state_json) — a
 * busy store reports itself busy rather than blocking the caller. */
static void push_shielded_import(struct json_value *out)
{
    struct json_value si;
    json_init(&si);
    json_set_object(&si);

    bool anchor_gap_blocker = blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    bool nf_gap_blocker = blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID);

    sqlite3 *db = progress_store_db();
    json_push_kv_bool(&si, "progress_store_open", db != NULL);

    bool snapshot_ok = false;
    bool sprout_a_found = false, sapling_a_found = false, nf_found = false;
    int64_t sprout_a_cursor = -1, sapling_a_cursor = -1, nf_cursor = -1;
    int64_t sprout_a_count = 0, sapling_a_count = 0;
    int64_t sprout_nf_count = 0, sapling_nf_count = 0;

    if (db && progress_store_tx_trylock()) {
        snapshot_ok =
            anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT,
                                        &sprout_a_cursor, &sprout_a_found) &&
            anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                        &sapling_a_cursor, &sapling_a_found) &&
            nullifier_kv_activation_cursor(db, &nf_cursor, &nf_found) &&
            anchor_kv_row_count(db, ANCHOR_POOL_SPROUT, &sprout_a_count) &&
            anchor_kv_row_count(db, ANCHOR_POOL_SAPLING, &sapling_a_count) &&
            nullifier_kv_row_count(db, NULLIFIER_POOL_SPROUT,
                                   &sprout_nf_count) &&
            nullifier_kv_row_count(db, NULLIFIER_POOL_SAPLING,
                                   &sapling_nf_count);
        progress_store_tx_unlock();
    }
    json_push_kv_bool(&si, "snapshot_complete", snapshot_ok);
    json_push_kv_str(&si, "snapshot_status",
                     !db ? "progress_store_closed"
                         : snapshot_ok ? "available"
                                       : "progress_store_busy_or_error");

    bool anchor_cursor_known = sprout_a_found && sapling_a_found;
    bool anchor_gap = !snapshot_ok || !anchor_cursor_known ||
                      sprout_a_cursor > 0 || sapling_a_cursor > 0 ||
                      anchor_gap_blocker;
    struct json_value anchor;
    json_init(&anchor);
    json_set_object(&anchor);
    json_push_kv_bool(&anchor, "cursor_known", anchor_cursor_known);
    json_push_kv_int(&anchor, "sprout_activation_cursor", sprout_a_cursor);
    json_push_kv_int(&anchor, "sapling_activation_cursor", sapling_a_cursor);
    json_push_kv_bool(&anchor, "gap_blocker_active", anchor_gap_blocker);
    json_push_kv_bool(&anchor, "gap", anchor_gap);
    json_push_kv_int(&anchor, "sprout_anchors_imported", sprout_a_count);
    json_push_kv_int(&anchor, "sapling_anchors_imported", sapling_a_count);
    json_push_kv(&si, "anchor", &anchor);
    json_free(&anchor);

    bool nf_gap = !snapshot_ok || !nf_found || nf_cursor > 0 || nf_gap_blocker;
    struct json_value nf;
    json_init(&nf);
    json_set_object(&nf);
    json_push_kv_bool(&nf, "cursor_known", nf_found);
    json_push_kv_int(&nf, "activation_cursor", nf_cursor);
    json_push_kv_bool(&nf, "gap_blocker_active", nf_gap_blocker);
    json_push_kv_bool(&nf, "gap", nf_gap);
    json_push_kv_int(&nf, "sprout_nullifiers_imported", sprout_nf_count);
    json_push_kv_int(&nf, "sapling_nullifiers_imported", sapling_nf_count);
    json_push_kv(&si, "nullifier", &nf);
    json_free(&nf);

    /* The SAME live cursor fold.height derives from (both gaps hold shielded
     * spends behind this stage, jobs/utxo_apply_stage.h) — named here too so
     * an operator reading only the shielded_import section still sees the
     * resume height climbing without cross-referencing fold.height. */
    json_push_kv_int(&si, "utxo_apply_next_height",
                     (int64_t)utxo_apply_stage_cursor());

    const char *status;
    if (!snapshot_ok)
        status = "unknown_snapshot_unavailable";
    else if (anchor_gap)
        status = "gap_anchor_backfill_pending";
    else if (nf_gap)
        status = "gap_nullifier_backfill_pending";
    else
        status = "complete";
    json_push_kv_str(&si, "status", status);

    json_push_kv(out, "shielded_import", &si);
    json_free(&si);
}

bool rom_compile_status_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("rom_compile", "dump_state_json: NULL out");
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.rom_compile.v1");
    json_push_kv_int(out, "captured_at", (int64_t)platform_time_wall_time_t());

    bool from_anchor = refold_from_anchor_active();
    bool active = refold_in_progress();
    const char *mode = from_anchor ? "from_anchor"
                     : active      ? "from_genesis"
                                   : "idle";

    int32_t target = (int32_t)REDUCER_FRONTIER_TRUSTED_ANCHOR;
    if (from_anchor) {
        int32_t t = 0;
        /* Lock-free cached read (refold_progress) — never the blocking progress
         * lock on this RPC dump path. Falls back to the compiled anchor. */
        if (refold_from_anchor_target_cached(&t) && t > 0)
            target = t;
    }

    /* utxo_apply names the NEXT height to process (see
     * ops.debug.producer's identical convention) — the fold's own live
     * cursor, read in-process with no DB round trip. */
    uint64_t cursor = utxo_apply_stage_cursor();
    int64_t height = cursor > 0 ? (int64_t)cursor - 1 : 0;

    double percent = 0.0;
    if (target > 0) {
        percent = 100.0 * (double)height / (double)target;
        if (percent < 0.0) percent = 0.0;
        if (percent > 100.0) percent = 100.0;
    }
    int64_t remaining = (int64_t)target > height ? (int64_t)target - height : 0;

    double rate_blk_s = 0.0;
    rcs_sample((int32_t)height, &rate_blk_s);
    int64_t eta_s = (rate_blk_s > 0.0 && remaining > 0)
                        ? (int64_t)((double)remaining / rate_blk_s)
                        : -1;
    char eta_str[32];
    eta_human(eta_s, eta_str, sizeof(eta_str));

    struct json_value fold;
    json_init(&fold);
    json_set_object(&fold);
    json_push_kv_bool(&fold, "active", active);
    json_push_kv_str(&fold, "mode", mode);
    json_push_kv_int(&fold, "height", height);
    json_push_kv_int(&fold, "target", target);
    json_push_kv_real(&fold, "percent", percent);
    json_push_kv_int(&fold, "remaining_blocks", remaining);
    json_push_kv_real(&fold, "rate_blk_s", rate_blk_s);
    json_push_kv_int(&fold, "eta_seconds", eta_s);
    json_push_kv_str(&fold, "eta_human", eta_str);
    json_push_kv(out, "fold", &fold);
    json_free(&fold);

    const char *bottleneck = "";
    push_stages(out, &bottleneck);
    json_push_kv_str(out, "bottleneck_stage", bottleneck);
    json_push_kv_int(out, "commit_us_ewma", stage_batch_commit_us_ewma());

    push_layers(out);
    push_shielded_import(out);
    return true;
}
