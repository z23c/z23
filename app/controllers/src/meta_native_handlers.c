/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native bodies for metrics and consensus-report commands. See
 * controllers/native_handler_body.h for their shared contract. */

#include "controllers/meta_native_handlers.h"

#include "json/json.h"
#include "metrics/prometheus_metrics.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Set a contextual allocation failure and return NULL. */
static char *meta_native_oom(struct zcl_native_body_err *err, size_t cap,
                             const char *what)
{
    err->status = ZCL_NATIVE_BODY_INTERNAL;
    snprintf(err->message, sizeof(err->message), "malloc failed for %s", what);
    if (cap > 0)
        LOG_NULL("native.meta", "malloc failed for %s (%zu bytes)", what, cap);
    LOG_NULL("native.meta", "malloc failed for %s", what);
}

/* ── Metrics command body ─────────────────────────────────────────────────── */

char *zcl_native_metrics_body(const struct json_value *args,
                              struct zcl_native_body_err *err)
{
    (void)args;
    size_t cap = 131072;
    char *raw = zcl_malloc(cap, "metrics_raw");
    if (!raw)
        return meta_native_oom(err, cap, "metrics buffer");
    size_t n = metrics_prometheus_render_prometheus(raw, cap);

    /* Wrap the Prometheus text in the native command's JSON envelope.
     * Escape quotes and newlines. */
    size_t out_cap = n * 2 + 128;
    char *out = zcl_malloc(out_cap, "metrics_json_body");
    if (!out) {
        free(raw);
        return meta_native_oom(err, out_cap, "metrics JSON envelope");
    }
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_cap - pos,
        "{\"format\":\"prometheus\",\"text\":\"");
    for (size_t i = 0; i < n && pos + 4 < out_cap; i++) {
        char c = raw[i];
        if (c == '"')       { out[pos++] = '\\'; out[pos++] = '"'; }
        else if (c == '\\') { out[pos++] = '\\'; out[pos++] = '\\'; }
        else if (c == '\n') { out[pos++] = '\\'; out[pos++] = 'n'; }
        else if (c == '\r') { out[pos++] = '\\'; out[pos++] = 'r'; }
        else if (c == '\t') { out[pos++] = '\\'; out[pos++] = 't'; }
        else                { out[pos++] = c; }
    }
    pos += (size_t)snprintf(out + pos, out_cap - pos, "\"}");

    free(raw);
    return out;
}

/* ── Consensus-report command body ────────────────────────────────────────── */

/* Consensus-reject counter snapshot.
 * Surfaces the `EV_CONSENSUS_REJECT_TX`/`_BLOCK` ring as a bounded
 * (kind, reason) -> count table plus per-kind totals and overflow
 * buckets. This is the dashboards/alerting view; the per-hash
 * `z23 core consensus reject explain` is the targeted companion. */
char *zcl_native_consensus_report_body(const struct json_value *args,
                                       struct zcl_native_body_err *err)
{
    (void)args;
    /* Cap large enough for the full 48-slot table plus overflow +
     * totals envelope (worst case ~= 48 x 80 bytes per entry). */
    char body[8192];
    size_t n = metrics_prometheus_consensus_report_json(body, sizeof(body));
    if (n == 0) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "consensus report generation returned empty");
        LOG_NULL("native.meta", "consensus_report_json returned 0 bytes");
    }
    char *out = strdup(body);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "strdup failed for consensus report");
        LOG_NULL("native.meta", "strdup failed for consensus_report (%zu bytes)", n);
    }
    return out;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in lib/hotswap/include/hotswap/hotswap.h). Stages every native command
 * leaf this controller owns; the resident bridge re-points them at THIS
 * TU's freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * ops.metrics: zcl_native_metrics_body ignores `args` ((void)args) and
 * unconditionally renders the Prometheus text buffer into a JSON envelope
 * with no top-level "error" key, so the empty-args self-test dispatch
 * succeeds. core.consensus.report is equally args-free ((void)args) and
 * would work as a probe too — either is valid; ops.metrics is kept as the
 * pilot probe. See config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "ops.metrics"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_consensus_report, zcl_native_consensus_report_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_metrics, zcl_native_metrics_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "core.consensus.report", tramp_consensus_report },
    { "ops.metrics",           tramp_metrics },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=ops.metrics` build
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node/release TU. The
 * module re-points ONLY the `ops.metrics` leaf to this TU's freshly-compiled
 * body via the same zcl_native_bridge_run() seam the leaf provider uses. See
 * hotswap_module.h and hotswap_activate() (lib/hotswap). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_metrics, zcl_native_metrics_body)

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_metrics(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

/* core.consensus.report renders metrics_prometheus_consensus_report_json()
 * into a fixed buffer and ignores `args`. It READS a Prometheus counter table;
 * it decides no consensus rule, validates no block, and touches no state root
 * — structurally the same class as ops.metrics beside it. The sealed consensus
 * tree stays unswappable; this is its observability projection. */
ZCL_HOTSWAP_TRAMPOLINE(module_tramp_consensus_report, zcl_native_consensus_report_body)

static const struct zcl_hotswap_leaf k_module_leaves[] = {
    { "ops.metrics",           module_tramp_metrics },
    { "core.consensus.report", module_tramp_consensus_report },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_metrics)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
