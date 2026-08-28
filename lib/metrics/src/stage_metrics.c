/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-reducer-stage Prometheus telemetry — implementation. See
 * stage_metrics.h for the contract and the layering rationale.
 */

#include "metrics/stage_metrics.h"
#include "util/stage.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>

/* Fixed pipeline order — the single source of truth every caller (the
 * boot_metrics_external_gauges() writer and this module's own render
 * path) must agree on by index. */
static const char *const k_stage_names[METRICS_STAGE_COUNT] = {
    "header_admit",
    "validate_headers",
    "body_fetch",
    "body_persist",
    "script_validate",
    "proof_validate",
    "utxo_apply",
    "tip_finalize",
};

static _Atomic int64_t g_stage_cursor[METRICS_STAGE_COUNT];
static _Atomic int64_t g_stage_step_us_ewma[METRICS_STAGE_COUNT];

const char *metrics_stage_name(int index)
{
    if (index < 0 || index >= METRICS_STAGE_COUNT) return NULL;
    return k_stage_names[index];
}

void metrics_stage_set_samples(const int64_t cursor[METRICS_STAGE_COUNT],
                                const int64_t step_us_ewma[METRICS_STAGE_COUNT])
{
    if (!cursor || !step_us_ewma) return;
    for (int i = 0; i < METRICS_STAGE_COUNT; i++) {
        atomic_store(&g_stage_cursor[i], cursor[i]);
        atomic_store(&g_stage_step_us_ewma[i], step_us_ewma[i]);
    }
}

/* Same bounded vsnprintf-append convention as prometheus_metrics.c's
 * file-local `append()` — duplicated rather than shared because both are
 * small, file-scoped helpers with no other consumer. */
__attribute__((format(printf, 4, 5)))
static size_t stage_append(char *buf, size_t cap, size_t pos, const char *fmt, ...)
{
    if (pos >= cap) return pos;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, cap - pos, fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    if ((size_t)n >= cap - pos) return cap - 1;
    return pos + (size_t)n;
}

size_t metrics_stage_render_prometheus(char *buf, size_t cap, size_t pos)
{
    if (!buf || cap == 0) return pos;

    pos = stage_append(buf, cap, pos,
        "# HELP zcl_stage_step_us_ewma Reducer stage per-step EWMA duration, microseconds\n"
        "# TYPE zcl_stage_step_us_ewma gauge\n");
    for (int i = 0; i < METRICS_STAGE_COUNT; i++) {
        pos = stage_append(buf, cap, pos,
            "zcl_stage_step_us_ewma{stage=\"%s\"} %lld\n",
            k_stage_names[i],
            (long long)atomic_load(&g_stage_step_us_ewma[i]));
    }

    /* TYPE gauge, not counter: stage_repair can force a stage's cursor
     * backward (a rewind), so the value is not guaranteed monotonic and a
     * Prometheus `counter` would mislead rate()/increase() on a repair
     * episode. */
    pos = stage_append(buf, cap, pos,
        "# HELP zcl_stage_cursor Reducer stage cursor (last processed height)\n"
        "# TYPE zcl_stage_cursor gauge\n");
    for (int i = 0; i < METRICS_STAGE_COUNT; i++) {
        pos = stage_append(buf, cap, pos,
            "zcl_stage_cursor{stage=\"%s\"} %lld\n",
            k_stage_names[i],
            (long long)atomic_load(&g_stage_cursor[i]));
    }

    /* stage_batch_commit_us_ewma() is a lib/util accessor (lib/util/
     * include/util/stage.h) — no external-gauges seam needed, read live. */
    pos = stage_append(buf, cap, pos,
        "# HELP zcl_stage_batch_commit_us_ewma Batch commit duration EWMA, microseconds (shared across stages)\n"
        "# TYPE zcl_stage_batch_commit_us_ewma gauge\n"
        "zcl_stage_batch_commit_us_ewma %lld\n",
        (long long)stage_batch_commit_us_ewma());

    return pos;
}
