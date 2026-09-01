// one-result-type-ok:telemetry-fill-provider — the sole export is a dumpstate
// dumper, whose `bool <name>_dump_state_json(struct json_value *, const char *)`
// signature is the diagnostics-registry ABI (CLAUDE.md "Adding state
// introspection") and is what check_dumper_never_blocks.sh scans for by name; a
// struct zcl_result return would make this dumper invisible to the very gate
// that proves it never blocks. There is also nothing for a result to carry: a
// domain this fold could not collect is reported IN the document as
// collected:false with a static reason token and judged unknown, which is more
// information than one per-call message, and the bool is reserved for a NULL
// output.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The whole-node telemetry rollup. Contract and rationale:
 * services/telemetry_rollup.h.
 *
 * WHY THE ROLLUPS ARE DELIBERATELY TERSE. A single domain's `health` block
 * measures ~4 KB at three findings, because every finding carries its
 * means/implies/next prose. Eight of those would be ~32 KB against a
 * 4096-byte RESULT budget, and an over-budget reply in this registry is
 * EMPTY, not truncated (command_registry.c write_bounded_json) — the rollup
 * would return nothing at all on exactly the unhealthy node it exists to
 * describe. So `summary` and `health` carry counts and one enum per domain
 * and no prose; the prose lives one drill-down away in the per-domain leaf,
 * and the controller's `reply.next[]` names it. `alerts_active` is the one
 * projection that carries findings, it is served under the LIST budget, and
 * it bounds them explicitly and states how many it dropped.
 */

#include "services/telemetry_rollup.h"

#include "json/json.h"
#include "services/telemetry_providers.h"
#include "util/telemetry_render.h"

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* How many findings `alerts_active` carries. The LIST budget is 8192 bytes and
 * a finding with its prose runs to roughly 1.3 KB, so six is the honest
 * ceiling. Going over does not truncate the reply, it empties it. */
#define TR_ALERTS_MAX 6

/* Bounds the per-call row array. The domain registry holds 8 and is frozen;
 * this is the "someone quadrupled it" guard, not an expectation. */
#define TR_DOMAINS_MAX 32

struct tr_domain_row {
    const struct telemetry_provider *provider;
    struct telemetry_domain_verdict verdict;
    bool collected;
    const char *reason; /* static token; set only when !collected */
};

/* Collect and judge every registered domain. Never fails as a whole: a domain
 * whose collector refused is recorded as UNKNOWN with a reason and still
 * appears in the output, because "storage could not be read" is an answer and
 * silently shortening the list is not. UNKNOWN outranks OK in the enum, so a
 * node that cannot be read can never roll up as healthy. */
static size_t tr_collect_all(struct tr_domain_row *rows, size_t rows_cap)
{
    size_t n = telemetry_provider_count();
    if (n > rows_cap)
        n = rows_cap;

    size_t buf_sz = telemetry_snapshot_max_size();
    void *buf = zcl_malloc(buf_sz, "telemetry_rollup_snapshot");

    for (size_t i = 0; i < n; i++) {
        const struct telemetry_provider *p = telemetry_provider_at(i);
        rows[i] = (struct tr_domain_row){.provider = p};
        rows[i].verdict.state = TELEMETRY_HEALTH_UNKNOWN;

        if (!buf) {
            rows[i].reason = "rollup_out_of_memory";
            continue;
        }
        if (!telemetry_provider_collect(p, buf, buf_sz)) {
            rows[i].reason = "collector_could_not_read_this_domain";
            continue;
        }
        if (!telemetry_evaluate(p->schema, buf, &rows[i].verdict)) {
            rows[i].verdict = (struct telemetry_domain_verdict){
                .state = TELEMETRY_HEALTH_UNKNOWN};
            rows[i].reason = "verdict_could_not_be_evaluated";
            continue;
        }
        rows[i].collected = true;
    }

    free(buf);
    return n;
}

/* The fold: the WORST state any domain is in. The enum is ordered
 * ok < unknown < degraded < unhealthy precisely so this is a max(), not a
 * policy decision spread across call sites. */
static enum telemetry_health tr_worst(const struct tr_domain_row *rows,
                                      size_t n, size_t *out_idx)
{
    enum telemetry_health worst = TELEMETRY_HEALTH_OK;
    size_t idx = n; /* n == "no domain is worse than ok" */
    for (size_t i = 0; i < n; i++) {
        if (rows[i].verdict.state > worst) {
            worst = rows[i].verdict.state;
            idx = i;
        }
    }
    if (out_idx)
        *out_idx = idx;
    return worst;
}

static void tr_push_null(struct json_value *obj, const char *key)
{
    struct json_value v;
    json_init(&v);
    json_set_null(&v);
    (void)json_push_kv(obj, key, &v);
    json_free(&v);
}

/* One compact object per domain: the enum, the counts behind it, and nothing
 * else. No prose — see the file header. */
static void tr_push_domains(struct json_value *out,
                            const struct tr_domain_row *rows, size_t n)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);

    for (size_t i = 0; i < n; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "domain", rows[i].provider->domain);
        (void)json_push_kv_str(&o, "health",
                               telemetry_health_name(rows[i].verdict.state));
        (void)json_push_kv_bool(&o, "collected", rows[i].collected);
        /* The drill-down path, so a caller never has to build one by string
         * concatenation to act on this row. */
        (void)json_push_kv_str(&o, "leaf", rows[i].provider->domain);
        if (rows[i].collected) {
            (void)json_push_kv_int(&o, "rules_evaluated",
                                   (int64_t)rows[i].verdict.rules_evaluated);
            (void)json_push_kv_int(&o, "unhealthy_fields",
                                   (int64_t)rows[i].verdict.unhealthy_count);
            (void)json_push_kv_int(&o, "unknown_fields",
                                   (int64_t)rows[i].verdict.unknown_count);
        } else {
            /* Unknown is never silent: it always says why. */
            (void)json_push_kv_str(&o, "reason",
                                   rows[i].reason ? rows[i].reason
                                                  : "unstated");
        }
        (void)json_push_back(&arr, &o);
        json_free(&o);
    }

    (void)json_push_kv(out, "domains", &arr);
    json_free(&arr);
}

static void tr_build_health(struct json_value *out,
                            const struct tr_domain_row *rows, size_t n)
{
    size_t worst_idx = n;
    enum telemetry_health worst = tr_worst(rows, n, &worst_idx);

    (void)json_push_kv_str(out, "schema", "zcl.telemetry.health.v1");
    (void)json_push_kv_str(out, "health", telemetry_health_name(worst));
    (void)json_push_kv_int(out, "domains_total", (int64_t)n);
    (void)json_push_kv_int(out, "collected_unix", telemetry_now_unix());
    if (worst_idx < n)
        (void)json_push_kv_str(out, "worst_domain",
                               rows[worst_idx].provider->domain);
    else
        tr_push_null(out, "worst_domain");
    tr_push_domains(out, rows, n);
}

static void tr_build_summary(struct json_value *out,
                             const struct tr_domain_row *rows, size_t n)
{
    size_t worst_idx = n;
    enum telemetry_health worst = tr_worst(rows, n, &worst_idx);

    size_t unhealthy_total = 0, unknown_total = 0, uncollected = 0;
    for (size_t i = 0; i < n; i++) {
        unhealthy_total += rows[i].verdict.unhealthy_count;
        unknown_total += rows[i].verdict.unknown_count;
        if (!rows[i].collected)
            uncollected++;
    }

    (void)json_push_kv_str(out, "schema", "zcl.telemetry.summary.v1");
    (void)json_push_kv_str(out, "health", telemetry_health_name(worst));
    (void)json_push_kv_int(out, "collected_unix", telemetry_now_unix());
    (void)json_push_kv_int(out, "domains_total", (int64_t)n);
    (void)json_push_kv_int(out, "domains_uncollected", (int64_t)uncollected);
    (void)json_push_kv_int(out, "unhealthy_fields_total",
                           (int64_t)unhealthy_total);
    (void)json_push_kv_int(out, "unknown_fields_total", (int64_t)unknown_total);

    /* The bottleneck, named. Explicitly null when nothing is worse than ok —
     * "there isn't one" is an answer; an omitted key is not. */
    if (worst_idx < n) {
        struct json_value b;
        json_init(&b);
        json_set_object(&b);
        (void)json_push_kv_str(&b, "domain", rows[worst_idx].provider->domain);
        (void)json_push_kv_str(
            &b, "health",
            telemetry_health_name(rows[worst_idx].verdict.state));
        if (!rows[worst_idx].collected)
            (void)json_push_kv_str(&b, "reason",
                                   rows[worst_idx].reason
                                       ? rows[worst_idx].reason
                                       : "unstated");
        (void)json_push_kv(out, "bottleneck", &b);
        json_free(&b);
    } else {
        tr_push_null(out, "bottleneck");
    }

    tr_push_domains(out, rows, n);
}

static void tr_build_alerts(struct json_value *out,
                            const struct tr_domain_row *rows, size_t n)
{
    (void)json_push_kv_str(out, "schema", "zcl.telemetry.alerts.v1");
    (void)json_push_kv_int(out, "collected_unix", telemetry_now_unix());

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);

    size_t emitted = 0, matched = 0, evaluator_truncated = 0;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].verdict.findings_truncated)
            evaluator_truncated++;
        for (size_t f = 0; f < rows[i].verdict.finding_count; f++) {
            const struct telemetry_finding *fd = &rows[i].verdict.findings[f];
            /* Only rules that are actually FAILING. An unreadable field is a
             * completeness fact, reported by `summary`, not an alert; padding
             * an alert feed with unknowns is how it stops being read. */
            if (fd->health != TELEMETRY_HEALTH_DEGRADED &&
                fd->health != TELEMETRY_HEALTH_UNHEALTHY)
                continue;
            matched++;
            if (emitted >= TR_ALERTS_MAX)
                continue;

            struct json_value o;
            json_init(&o);
            json_set_object(&o);
            (void)json_push_kv_str(&o, "domain", rows[i].provider->domain);
            (void)json_push_kv_str(&o, "path", fd->path ? fd->path : "");
            (void)json_push_kv_str(&o, "health",
                                   telemetry_health_name(fd->health));
            if (!fd->value_known)
                tr_push_null(&o, "value");
            else if (fd->value_is_bool)
                (void)json_push_kv_bool(&o, "value", fd->value_b);
            else
                (void)json_push_kv_int(&o, "value", fd->value_i);
            (void)json_push_kv_str(&o, "healthy_range", fd->healthy_range);
            (void)json_push_kv_str(&o, "means", fd->means ? fd->means : "");
            (void)json_push_kv_str(&o, "implies",
                                   fd->implies ? fd->implies : "");
            (void)json_push_kv_str(&o, "next", fd->next ? fd->next : "");
            (void)json_push_back(&arr, &o);
            json_free(&o);
            emitted++;
        }
    }

    (void)json_push_kv(out, "alerts", &arr);
    json_free(&arr);

    (void)json_push_kv_int(out, "active_total", (int64_t)matched);
    (void)json_push_kv_int(out, "listed", (int64_t)emitted);
    /* Dropping is always stated with its cause. Two causes, two keys: this
     * projection's page limit, and the evaluator's own per-domain cap. */
    (void)json_push_kv_int(out, "dropped_for_reply_budget",
                           (int64_t)(matched - emitted));
    (void)json_push_kv_int(out, "domains_with_findings_truncated",
                           (int64_t)evaluator_truncated);
}

bool telemetry_rollup_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;

    struct tr_domain_row rows[TR_DOMAINS_MAX];
    size_t n = tr_collect_all(rows, TR_DOMAINS_MAX);

    bool unrecognized = false;
    if (!key || !*key || strcmp(key, "summary") == 0) {
        tr_build_summary(out, rows, n);
    } else if (strcmp(key, "health") == 0) {
        tr_build_health(out, rows, n);
    } else if (strcmp(key, "alerts_active") == 0) {
        tr_build_alerts(out, rows, n);
    } else {
        /* Fall back to the summary, and SAY SO. A guessed projection that
         * looks like a real answer is the failure this whole tree exists to
         * remove. */
        unrecognized = true;
        tr_build_summary(out, rows, n);
    }
    if (unrecognized)
        (void)json_push_kv_bool(out, "key_unrecognized", true);

    return true;
}
