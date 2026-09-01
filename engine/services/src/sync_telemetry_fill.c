// one-result-type-ok:telemetry-fill-provider — a telemetry provider's failure
// reason does not travel in its return value, it travels in the SNAPSHOT: each
// leaf carries its own presence plus a static reason token, which is strictly
// more information than one struct zcl_result per call could hold (this file
// can, and does, report "hstar is fine, network_tip is unavailable because no
// peer height has been observed" in the same answer). The bool is reserved for
// the one thing that is not a per-leaf fact — a NULL snapshot — and the
// signature itself is fixed by the frozen render contract
// (util/telemetry_render.h) and by the `*_dump_state_fill` shape
// tools/scripts/check_dumper_never_blocks.sh scans.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_telemetry_fill — the `sync` domain's typed snapshot provider.
 * Contract, threading rules and the never-blocks argument: services/sync_telemetry.h.
 *
 * WHAT IS AND IS NOT HERE. Values only. There is no json_push_kv_* in this
 * file and there must never be one: telemetry_render() is the single place a
 * telemetry field becomes JSON, and a collector that hand-writes a key
 * reintroduces the unannotated, unrenderable field the whole layer exists to
 * make impossible (tools/lint/check_telemetry_ontology.sh, TABLE rule 4).
 * There is no health decision here either — a verdict comes from the TL_LEAF
 * row's rule through telemetry_ontology_annotate(), never from a provider.
 *
 * HOW A LEAF IS WRITTEN. Through the TELEMETRY_SET_* / TELEMETRY_*_LEAF macros
 * only, so a value and its provenance are written together and neither can
 * arrive without the other. The member token is the one spelled in
 * util/telemetry/sync_fields.def; it is not spelled anywhere else in the
 * repository, so struct/key/path drift is unrepresentable rather than policed.
 *
 * WHY THE COUNTERS ARE `present`, NOT `unavailable`, WHEN THEY READ 0. Every
 * stage accessor returns 0 both before the stage is initialised and when the
 * counter genuinely is 0, and no public accessor distinguishes the two. A 0
 * read off a published atomic IS a real read, so it is recorded PRESENT; the
 * pre-init case is what values.frontier.hstar_published exists to disambiguate.
 * Writing UNAVAILABLE here would claim a failure the provider did not observe.
 */

#include "services/sync_telemetry.h"

#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/header_admit_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/telemetry_snapshots.h"

#include <sqlite3.h>
#include <stdint.h>

/* Fixed-point scale of the TFU_BPS_X1000 leaves: blocks per second x1000. */
#define SYNC_TL_BPS_SCALE 1000

/* One microsecond-per-step EWMA converted to the x1000 blocks-per-second the
 * TFU_BPS_X1000 unit promises. Returns false when the stage has never stepped
 * (EWMA 0 — see stage_record_step_timing's floor-to-1, which is what makes 0
 * mean "never sampled" rather than "instantaneous"), so the caller reports the
 * leaf UNAVAILABLE instead of publishing a division by zero as a rate. */
static bool step_us_to_bps_x1000(int64_t step_us, int64_t *out)
{
    if (step_us <= 0)
        return false; // raw-return-ok:never-stepped-is-a-presence-not-an-error
    *out = ((int64_t)1000000 * SYNC_TL_BPS_SCALE) / step_us;
    return true;
}

/* The six ladder rungs this domain times, in ladder order. Held as a local
 * table rather than six comparisons so the bottleneck search below cannot
 * drift out of step with the leaves that publish the same six numbers. */
struct sync_tl_rung {
    const char *name;
    int64_t step_us;
};

/* ── frontier: the reducer L0 authority ──────────────────────────────────
 * Everything here except coins_applied_height is a lock-free published
 * scalar. The durable read is the LAST thing this function does, behind a
 * trylock, so a lost race costs exactly two leaves and never the group. */
static void fill_frontier(struct sync_snapshot *s)
{
    int64_t hstar_h = (int64_t)reducer_frontier_provable_tip_cached();
    TELEMETRY_SET_I64(s, hstar, hstar_h, TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_BOOL(s, hstar_published,
                       reducer_frontier_provable_tip_is_published(),
                       TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_I64(s, finality_floor, reducer_frontier_floor(),
                      TELEMETRY_SRC_CONFIG);

    /* -1 is the monitor's "no handshake-complete peer has been evaluated yet"
     * sentinel. Publishing it as a height would be a lie and publishing 0
     * would be a worse one, so both this leaf and the gap derived from it
     * report UNAVAILABLE with their own reason token. */
    int64_t peer_h = (int64_t)sync_monitor_peer_height_cached();
    if (peer_h >= 0) {
        TELEMETRY_SET_I64(s, network_tip, peer_h,
                          TELEMETRY_SRC_PEER_REPORTED);
        TELEMETRY_SET_I64(s, hstar_to_network_tip_gap,
                          peer_h > hstar_h ? peer_h - hstar_h : 0,
                          TELEMETRY_SRC_DERIVED);
    } else {
        TELEMETRY_UNAVAILABLE_LEAF(s, network_tip, "no_peer_height_observed");
        TELEMETRY_UNAVAILABLE_LEAF(s, hstar_to_network_tip_gap,
                                   "network_tip_unknown");
    }

    sqlite3 *db = progress_store_db();
    if (!db) {
        TELEMETRY_SET_BOOL(s, durable_snapshot_read, false,
                           TELEMETRY_SRC_IN_PROCESS);
        TELEMETRY_UNAVAILABLE_LEAF(s, coins_applied_height,
                                   "progress_store_not_open");
        return;
    }
    /* TRYLOCK, never the blocking acquire — see the file header and
     * check_dumper_never_blocks. A reducer drain legitimately owns this store
     * for the length of its outer transaction; the honest answer under that is
     * "busy", not a queued RPC worker. */
    if (!progress_store_tx_trylock()) {
        TELEMETRY_SET_BOOL(s, durable_snapshot_read, false,
                           TELEMETRY_SRC_IN_PROCESS);
        TELEMETRY_UNAVAILABLE_LEAF(s, coins_applied_height,
                                   "progress_store_busy");
        return;
    }
    TELEMETRY_SET_BOOL(s, durable_snapshot_read, true,
                       TELEMETRY_SRC_IN_PROCESS);
    int32_t applied = -1;
    bool found = false;
    /* One indexed single-row read of progress_meta — bounded by construction,
     * so it cannot become the unbounded scan the gate's sibling rule forbids. */
    if (!coins_kv_get_applied_height(db, &applied, &found))
        TELEMETRY_UNAVAILABLE_LEAF(s, coins_applied_height,
                                   "coins_applied_read_failed");
    else if (!found)
        TELEMETRY_UNAVAILABLE_LEAF(s, coins_applied_height,
                                   "coins_applied_row_absent");
    else
        TELEMETRY_SET_I64(s, coins_applied_height, applied,
                          TELEMETRY_SRC_DURABLE_STORE);
    progress_store_tx_unlock();
}

/* ── headers: rungs 1-2 ──────────────────────────────────────────────── */
static void fill_headers(struct sync_snapshot *s)
{
    TELEMETRY_SET_I64(s, header_admit_cursor,
                      header_admit_stage_cursor(), TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, header_admit_admitted_total,
                      header_admit_stage_admitted_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, header_admit_produced_total,
                      header_admit_stage_produced_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, header_admit_reorg_rewind_total,
                      header_admit_stage_reorg_rewind_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, header_admit_step_us_ewma,
                      header_admit_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);

    TELEMETRY_SET_I64(s, validate_headers_cursor,
                      validate_headers_stage_cursor(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, validate_headers_passed_total,
                      validate_headers_stage_passed_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, validate_headers_failed_total,
                      validate_headers_stage_failed_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, validate_headers_step_us_ewma,
                      validate_headers_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);
}

/* ── bodies: rungs 3-4 ───────────────────────────────────────────────── */
static void fill_bodies(struct sync_snapshot *s)
{
    TELEMETRY_SET_I64(s, body_fetch_cursor,
                      body_fetch_stage_cursor(), TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_fetch_observed_total,
                      body_fetch_stage_observed_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_fetch_skipped_total,
                      body_fetch_stage_skipped_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_fetch_step_us_ewma,
                      body_fetch_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);

    TELEMETRY_SET_I64(s, body_persist_cursor,
                      body_persist_stage_cursor(), TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_persist_verified_total,
                      body_persist_stage_verified_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_persist_read_failed_total,
                      body_persist_stage_read_failed_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_persist_header_mismatch_total,
                      body_persist_stage_header_mismatch_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_persist_merkle_mismatch_total,
                      body_persist_stage_merkle_mismatch_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, body_persist_step_us_ewma,
                      body_persist_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);
}

/* ── apply: rungs 7-8 ────────────────────────────────────────────────── */
static void fill_apply(struct sync_snapshot *s)
{
    TELEMETRY_SET_I64(s, utxo_apply_cursor,
                      utxo_apply_stage_cursor(), TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, utxo_apply_verified_total,
                      utxo_apply_stage_verified_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, utxo_apply_spend_unknown_total,
                      utxo_apply_stage_spend_unknown_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, utxo_apply_internal_error_total,
                      utxo_apply_stage_internal_error_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, utxo_apply_step_us_ewma,
                      utxo_apply_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);

    /* "The stage has never gone select-idle" is not an unread value, it is a
     * height that does not exist — NOT_APPLICABLE, which the render layer
     * counts separately and does NOT hold against completeness. */
    int64_t idle_h = utxo_apply_stage_select_idle_height();
    if (idle_h >= 0)
        TELEMETRY_SET_I64(s, utxo_apply_select_idle_height, idle_h,
                          TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_NOT_APPLICABLE_LEAF(s, utxo_apply_select_idle_height,
                                      "no_select_idle_observed");

    TELEMETRY_SET_I64(s, tip_finalize_cursor,
                      tip_finalize_stage_cursor(), TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, tip_finalize_finalized_total,
                      tip_finalize_stage_finalized_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, tip_finalize_reorg_detected_total,
                      tip_finalize_stage_reorg_detected_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, tip_finalize_utxo_count_diverged_total,
                      tip_finalize_stage_utxo_count_diverged_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, tip_finalize_successor_pending_total,
                      tip_finalize_stage_successor_pending_total(),
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, tip_finalize_step_us_ewma,
                      tip_finalize_stage_step_us_ewma(),
                      TELEMETRY_SRC_IN_PROCESS);

    /* The accessor returns "" when no step has blocked in this process. An
     * empty string in a closed-token field reads as a missing token, so the
     * absence is spelled with a token of its own — the field table says so. */
    const char *blocked = tip_finalize_stage_last_blocked_reason();
    TELEMETRY_SET_TEXT(s, tip_finalize_last_blocked_reason,
                       (blocked && blocked[0]) ? blocked : "none",
                       TELEMETRY_SRC_IN_PROCESS);
}

/* ── rate: derived from the ladder's own step timings ────────────────── */
static void fill_rate(struct sync_snapshot *s)
{
    const struct sync_tl_rung rungs[] = {
        { "header_admit",     header_admit_stage_step_us_ewma() },
        { "validate_headers", validate_headers_stage_step_us_ewma() },
        { "body_fetch",       body_fetch_stage_step_us_ewma() },
        { "body_persist",     body_persist_stage_step_us_ewma() },
        { "utxo_apply",       utxo_apply_stage_step_us_ewma() },
        { "tip_finalize",     tip_finalize_stage_step_us_ewma() },
    };

    int64_t bps = 0;
    if (step_us_to_bps_x1000(tip_finalize_stage_step_us_ewma(), &bps))
        TELEMETRY_SET_I64(s, tip_finalize_blocks_per_sec_x1000, bps,
                          TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, tip_finalize_blocks_per_sec_x1000,
                                   "stage_never_stepped");

    if (step_us_to_bps_x1000(utxo_apply_stage_step_us_ewma(), &bps))
        TELEMETRY_SET_I64(s, utxo_apply_blocks_per_sec_x1000, bps,
                          TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_apply_blocks_per_sec_x1000,
                                   "stage_never_stepped");

    const struct sync_tl_rung *worst = NULL;
    for (size_t i = 0; i < sizeof(rungs) / sizeof(rungs[0]); i++) {
        if (rungs[i].step_us <= 0)
            continue;
        if (!worst || rungs[i].step_us > worst->step_us)
            worst = &rungs[i];
    }
    if (worst) {
        TELEMETRY_SET_TEXT(s, slowest_stage, worst->name,
                           TELEMETRY_SRC_DERIVED);
        TELEMETRY_SET_I64(s, slowest_stage_step_us, worst->step_us,
                          TELEMETRY_SRC_DERIVED);
    } else {
        TELEMETRY_UNAVAILABLE_LEAF(s, slowest_stage, "no_stage_has_stepped");
        TELEMETRY_UNAVAILABLE_LEAF(s, slowest_stage_step_us,
                                   "no_stage_has_stepped");
    }
}

bool sync_dump_state_fill(struct sync_snapshot *s)
{
    if (!s)
        LOG_FAIL("sync_telemetry", "dump_state_fill: snapshot is NULL");

    /* First, so every other leaf's observed_unix is at or after it — the
     * ordering the meta leaf's own `means` promises a reader. */
    TELEMETRY_SET_I64(s, collected_unix, telemetry_now_unix(),
                      TELEMETRY_SRC_IN_PROCESS);

    fill_frontier(s);
    fill_headers(s);
    fill_bodies(s);
    fill_apply(s);
    fill_rate(s);
    return true;
}
