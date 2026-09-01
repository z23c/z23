/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-reducer-stage Prometheus telemetry (Phase E4).
 *
 * The eight reducer stages (header_admit -> validate_headers -> body_fetch
 * -> body_persist -> script_validate -> proof_validate -> utxo_apply ->
 * tip_finalize; see docs/HOW_THE_NODE_WORKS.md) already expose a live
 * cursor + step_us_ewma pair via the per-stage headers under
 * engine/jobs/include/jobs (e.g. header_admit_stage.h) and their diagnostics
 * dumpers (`dumpstate <stage>`). This module renders
 * that same data as bounded-cardinality Prometheus series:
 *
 *   zcl_stage_step_us_ewma{stage="..."} <us>
 *   zcl_stage_cursor{stage="..."}       <height>
 *   zcl_stage_batch_commit_us_ewma      <us>   (shared across stages)
 *
 * lib/ code cannot include app/jobs headers (that would be a lib -> app
 * layering violation), so the per-stage samples arrive via the same
 * external-gauges seam the other periodic gauges use: the app-layer
 * writer is boot_metrics_external_gauges() in
 * engine/composition/src/boot_node_utilities.c, which populates the stage_cursor /
 * stage_step_us_ewma arrays on struct metrics_external_gauges once per
 * metrics tick; engine/modules/metrics/src/metrics.c forwards them here via
 * metrics_stage_set_samples(). The shared batch_commit_us_ewma gauge is
 * read directly from platform/modules/util/include/util/stage.h at render time — that
 * accessor is already lib-layer, so no seam is needed for it.
 *
 * Cardinality is fixed and bounded: exactly METRICS_STAGE_COUNT stages,
 * never more — there is no dynamic registration path. */

#ifndef ZCL_METRICS_STAGE_METRICS_H
#define ZCL_METRICS_STAGE_METRICS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fixed reducer-stage pipeline order — never grows without a matching
 * change to the pipeline itself (docs/HOW_THE_NODE_WORKS.md). */
#define METRICS_STAGE_COUNT 8

/* Canonical stage name for index [0, METRICS_STAGE_COUNT). NULL for an
 * out-of-range index. The fixed pipeline order is:
 *   0 header_admit, 1 validate_headers, 2 body_fetch, 3 body_persist,
 *   4 script_validate, 5 proof_validate, 6 utxo_apply, 7 tip_finalize. */
const char *metrics_stage_name(int index);

/* Set the live per-stage snapshot for this tick. Both arrays are indexed
 * in the same fixed METRICS_STAGE_COUNT order as metrics_stage_name().
 * Thread-safe (atomics only, no lock); safe to call from the metrics
 * thread every tick. `cursor` values are non-negative reducer heights;
 * `step_us_ewma` mirrors the app-layer <stage>_stage_step_us_ewma()
 * accessor (0 before the stage's first observed step). */
void metrics_stage_set_samples(const int64_t cursor[METRICS_STAGE_COUNT],
                                const int64_t step_us_ewma[METRICS_STAGE_COUNT]);

/* Append this module's Prometheus series at `pos` in `buf` (capacity
 * `cap`), following the same `pos = append(buf, cap, pos, fmt, ...)`
 * accumulation convention engine/modules/metrics/src/prometheus_metrics.c uses for
 * every other block in metrics_prometheus_render_prometheus(). Returns the
 * new pos. Safe with buf==NULL only when cap==0 (returns pos unchanged). */
size_t metrics_stage_render_prometheus(char *buf, size_t cap, size_t pos);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_METRICS_STAGE_METRICS_H */
