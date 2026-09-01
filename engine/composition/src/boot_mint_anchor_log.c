/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: On-disk mint-progress.log telemetry for the offline -mint-anchor
 * producer (S1.4). The producer runs WITHOUT RPC — no dumpstate is reachable —
 * so this throttled append is the only offline surface for "how fast is the
 * fold and which of the eight stages is the bottleneck right now". */

#include "config/boot.h"

#include "jobs/header_admit_stage.h"            /* header_admit_stage_step_us_ewma */
#include "jobs/validate_headers_stage.h"        /* validate_headers_stage_step_us_ewma */
#include "jobs/body_fetch_stage.h"              /* body_fetch_stage_step_us_ewma */
#include "jobs/body_persist_stage.h"            /* body_persist_stage_step_us_ewma */
#include "jobs/script_validate_stage.h"         /* script_validate_stage_step_us_ewma */
#include "jobs/proof_validate_stage.h"          /* proof_validate_stage_step_us_ewma */
#include "jobs/utxo_apply_stage.h"              /* utxo_apply_stage_step_us_ewma */
#include "jobs/tip_finalize_stage.h"            /* tip_finalize_stage_step_us_ewma */
#include "jobs/pv_lookahead.h"                  /* pv_lookahead_hit_total */
#include "util/stage.h"                         /* stage_batch_commit_us_ewma */
#include "core/utiltime.h"                      /* GetTimeMicros */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

bool boot_mint_anchor_should_log_progress(int32_t applied_through,
                                          int32_t anchor)
{
    const int kProgressEvery = 10000;
    return (applied_through % kProgressEvery) == 0 ||
           applied_through >= anchor - 16;
}

/* Resolve the on-disk progress-log path: $ZCL_MINT_PROGRESS_LOG, else
 * <datadir>/mint-progress.log. */
void boot_mint_anchor_progress_log_path(const char *datadir, char *out,
                                        size_t n)
{
    const char *env = getenv("ZCL_MINT_PROGRESS_LOG");
    if (env && env[0])
        snprintf(out, n, "%s", env);
    else
        snprintf(out, n, "%s/mint-progress.log", datadir ? datadir : ".");
}

/* Per-stage step-timing EWMA snapshot for the mint-progress.log line below.
 * Same pipeline order + abbreviations as
 * boot_mint_anchor_report_frontier_walled's cursor report (ha, vh, bf, bp,
 * sv, pv, ua, tf), so the two reports read consistently side by side. */
static void mint_stage_ewma_collect(const char *abbrev_out[8], int64_t ewma_out[8])
{
    static const char *const abbrev[8] = {
        "ha", "vh", "bf", "bp", "sv", "pv", "ua", "tf" };
    for (int i = 0; i < 8; i++)
        abbrev_out[i] = abbrev[i];
    ewma_out[0] = header_admit_stage_step_us_ewma();
    ewma_out[1] = validate_headers_stage_step_us_ewma();
    ewma_out[2] = body_fetch_stage_step_us_ewma();
    ewma_out[3] = body_persist_stage_step_us_ewma();
    ewma_out[4] = script_validate_stage_step_us_ewma();
    ewma_out[5] = proof_validate_stage_step_us_ewma();
    ewma_out[6] = utxo_apply_stage_step_us_ewma();
    ewma_out[7] = tip_finalize_stage_step_us_ewma();
}

/* Append one throttled progress line to the on-disk mint-progress.log so a
 * long fold is observable FROM DISK. Throttled to ~every 5s of wall time; the
 * final-anchor line is always written. Rate is computed over the interval since
 * the last write (blocks/s), ETA from the remaining span at that rate. All
 * best-effort — a failure to open/write NEVER affects the fold.
 *
 * The line also carries the eight stages' live step_us_ewma (in-process only —
 * a different process, e.g. `anchorstatus`, cannot read them; this log line is
 * the only durable trace of the snapshot) so one `tail -1 mint-progress.log`
 * names the slowest stage (`slow=<abbrev>:<ewma_us>us`) without attaching a
 * debugger or sampling /proc/<pid>/wchan. */
void boot_mint_anchor_progress_log_tick(const char *path, int32_t through,
                                        int32_t anchor, int64_t start_us,
                                        bool force)
{
    static int64_t last_write_us   = 0;
    static int32_t last_write_h     = -1;
    const int64_t  kEveryUs        = 5 * 1000 * 1000;  /* 5s */

    int64_t now_us = GetTimeMicros();
    if (last_write_us == 0) {            /* first call: seed the interval base */
        last_write_us = start_us > 0 ? start_us : now_us;
        last_write_h  = through;
    }
    int64_t since_us = now_us - last_write_us;
    if (!force && since_us < kEveryUs)
        return;

    double interval_s = since_us > 0 ? (double)since_us / 1e6 : 0.0;
    int32_t d_h       = through - last_write_h;
    double  rate      = interval_s > 0.0 ? (double)d_h / interval_s : 0.0;
    int32_t remaining = anchor > through ? anchor - through : 0;
    long    eta_s     = rate > 0.0 ? (long)((double)remaining / rate) : -1;
    double  elapsed_s = start_us > 0 ? (double)(now_us - start_us) / 1e6 : 0.0;

    const char *stage_abbrev[8];
    int64_t     stage_ewma[8];
    mint_stage_ewma_collect(stage_abbrev, stage_ewma);
    int slow = 0;
    for (int i = 1; i < 8; i++)
        if (stage_ewma[i] > stage_ewma[slow])
            slow = i;
    /* Outer batch-COMMIT wall time — kept OUT of the slow= max scan above
     * (it is not one of the eight stages); a separate token so the remaining
     * per-batch fsync cost is visible next to the per-step timings. */
    int64_t commit_ewma = stage_batch_commit_us_ewma();

    char stages_buf[240];
    int  off = snprintf(stages_buf, sizeof(stages_buf), "stages=[");
    for (int i = 0; i < 8 && off > 0 && (size_t)off < sizeof(stages_buf); i++)
        off += snprintf(stages_buf + off, sizeof(stages_buf) - (size_t)off,
                        "%s%s:%lldus", i == 0 ? "" : " ", stage_abbrev[i],
                        (long long)stage_ewma[i]);
    if (off > 0 && (size_t)off < sizeof(stages_buf))
        snprintf(stages_buf + off, sizeof(stages_buf) - (size_t)off, "]");

    /* pv lookahead cache hit rate (jobs/pv_lookahead.h): hits/misses since the
     * pool started. 0/0 when the pool is off (misses count only while it runs). */
    unsigned long long pvla_hits = pv_lookahead_hit_total();
    unsigned long long pvla_misses = pv_lookahead_miss_total();

    FILE *f = fopen(path, "a");
    if (!f)
        return;                          /* best-effort: never block the fold */
    if (eta_s >= 0)
        fprintf(f,
                "mint height=%d / %d rate=%.1f blk/s eta=%ld:%02ld:%02ld "
                "elapsed=%.0fs slow=%s:%lldus cm:%lldus pvla=%llu/%llu %s\n",
                through, anchor, rate,
                eta_s / 3600, (eta_s % 3600) / 60, eta_s % 60, elapsed_s,
                stage_abbrev[slow], (long long)stage_ewma[slow],
                (long long)commit_ewma, pvla_hits, pvla_misses, stages_buf);
    else
        fprintf(f,
                "mint height=%d / %d rate=%.1f blk/s eta=unknown "
                "elapsed=%.0fs slow=%s:%lldus cm:%lldus pvla=%llu/%llu %s\n",
                through, anchor, rate, elapsed_s,
                stage_abbrev[slow], (long long)stage_ewma[slow],
                (long long)commit_ewma, pvla_hits, pvla_misses, stages_buf);
    fclose(f);

    last_write_us = now_us;
    last_write_h  = through;
}

/* Test-only forwarder (declared in config/boot.h) so the
 * reducer_step_drain_harness test group can drive one tick and assert the
 * on-disk line without duplicating this TU's throttle/format logic. */
void boot_mint_anchor_progress_log_tick_for_test(const char *path,
                                                 int32_t through,
                                                 int32_t anchor,
                                                 int64_t start_us,
                                                 bool force)
{
    boot_mint_anchor_progress_log_tick(path, through, anchor, start_us, force);
}
