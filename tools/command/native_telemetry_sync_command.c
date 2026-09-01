/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `ops.telemetry.sync` branch — the three leaves over
 * the typed sync domain snapshot (docs/TELEMETRY_CONTRACT.md, "the four
 * layers"). This file is the CONTROL layer and nothing else:
 *
 *   summary   pick a view, fill one snapshot, render it, and name the rung the
 *             ladder is currently stuck behind
 *   stages    project the rendered document into one row per ladder rung
 *   stage     the same projection for ONE named rung, with that rung's
 *             per-leaf provenance
 *
 * WHAT THIS FILE MAY NOT DO, and how it stays honest about it:
 *
 *   it names no telemetry field.  Every field key it emits is `leaf->key`, read
 *     out of the domain's own descriptor table (util/telemetry_render.h). The
 *     only hand-written keys are envelope structure — "stage", "fields",
 *     "bottleneck" — which are not fields of the sync domain and carry no
 *     ontology row. Spelling a field name here would recreate the drift the
 *     one-token field table exists to make unrepresentable.
 *   it decides no health.  Every verdict comes from telemetry_evaluate(), the
 *     same evaluator telemetry_render() folds into the document.
 *   it renders no value.  Values are copied out of the ALREADY-RENDERED
 *     document; this file never turns a snapshot member into JSON, because
 *     telemetry_render() is the one place that happens.
 *
 * THE STAGE DIMENSION IS DERIVED, NEVER LISTED. The sync table flattens the
 * ladder to one leaf per rung and encodes the rung in the leaf's own name
 * (`body_persist_cursor`, not `bodies.persist_cursor`) — that is the table's
 * stated design, so it is a structure this file may read rather than a
 * convention it invents. A rung is exactly a leaf whose key ends in `_cursor`;
 * the rung's name is that key minus the suffix, and the rung's fields are every
 * leaf whose key begins `<rung>_`. Nothing here holds a list of stage names, so
 * a rung added to the field table appears in `stages` with no edit here, and a
 * rung removed disappears — the two cannot fall out of step.
 *
 * BUDGETS BITE SILENTLY, so this file measures instead of hoping. An
 * over-budget reply is written by the kernel as an EMPTY document, not a
 * truncated one (write_bounded_json, engine/modules/kernel/src/command_registry.c), and
 * the native CLI's whole envelope buffer is ZCL_COMMAND_LIST_BUDGET+1 bytes. A
 * FULL sync document is 44 values PLUS a provenance entry each and does not
 * fit. telemetry_reply_render_fitting() (platform/modules/util) therefore sizes every
 * document with a json_write() probe and steps the view down until it fits,
 * recording that it did so, and reporting the measurement when even the
 * smallest view overflows. A stated downgrade is diagnosable; an empty reply
 * is not.
 *
 * Layering: a transport adapter over the telemetry render layer. Opens no
 * database, takes no lock, contacts no node: the provider it calls
 * (services/sync_telemetry.h) reads lock-free publications and one trylocked
 * durable row, so these leaves are safe to call at any point in a node's life.
 */

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/sync_telemetry.h"
#include "util/telemetry_render.h"
#include "util/telemetry_reply.h"
#include "util/telemetry_snapshots.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The suffix that makes a leaf a ladder rung. See the file header: this is the
 * sync table's own naming rule, read rather than invented. */
#define TLS_CURSOR_SUFFIX "_cursor"
#define TLS_CURSOR_SUFFIX_LEN (sizeof(TLS_CURSOR_SUFFIX) - 1)

/* Ceilings, not guesses: the ladder has six rungs today and a rung name is a
 * C identifier fragment. Both are checked at use, so overflowing either drops
 * rungs from the REPORT rather than corrupting memory — and the count the
 * reply carries is the number actually rendered, so the loss is visible. */
#define TLS_MAX_STAGES 16
#define TLS_STAGE_NAME_MAX 48

/* How many bytes of the reply frame the DATA document may occupy. The CLI
 * writes the whole envelope into ZCL_COMMAND_LIST_BUDGET+1 bytes; the rest is
 * status, exit code, schema id and the next[] array. 1536 bytes of headroom
 * covers a full next[] entry (128 + 512 + 160) twice over. */
#define TLS_DATA_FRAME ((size_t)ZCL_COMMAND_LIST_BUDGET - 1536u)

struct tls_stage_set {
    char name[TLS_MAX_STAGES][TLS_STAGE_NAME_MAX];
    size_t count;
    bool overflowed; /* the table has more rungs than this reply can carry */
};

/* ── the stage dimension, read off the descriptor table ──────────────── */

static void tls_stage_set_build(const struct telemetry_domain_schema *s,
                                struct tls_stage_set *out)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < s->leaf_count; i++) {
        const char *key = s->leaves[i].key;
        size_t n = strlen(key);
        if (n <= TLS_CURSOR_SUFFIX_LEN)
            continue;
        size_t stem = n - TLS_CURSOR_SUFFIX_LEN;
        if (strcmp(key + stem, TLS_CURSOR_SUFFIX) != 0)
            continue;
        if (stem >= TLS_STAGE_NAME_MAX || out->count >= TLS_MAX_STAGES) {
            out->overflowed = true;
            continue;
        }
        memcpy(out->name[out->count], key, stem);
        out->name[out->count][stem] = '\0';
        out->count++;
    }
}

/* Does `key` belong to `stage`? `<stage>_` and nothing shorter, so
 * `body_fetch` never claims `body_persist_cursor`. */
static bool tls_key_in_stage(const char *key, const char *stage)
{
    size_t n = strlen(stage);
    return strncmp(key, stage, n) == 0 && key[n] == '_';
}

static bool tls_stage_index(const struct tls_stage_set *set, const char *name,
                            size_t *out_idx)
{
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->name[i], name) == 0) {
            if (out_idx)
                *out_idx = i;
            return true;
        }
    }
    return false;
}

/* The valid set, for the typed unknown-stage error. Truncation is stated with
 * a trailing ellipsis rather than silently cutting a name in half. */
static void tls_stage_csv(const struct tls_stage_set *set, char *buf,
                          size_t cap)
{
    if (!cap)
        return;
    buf[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < set->count; i++) {
        size_t need = strlen(set->name[i]) + (i ? 1u : 0u);
        if (used + need + 4u >= cap) {
            (void)snprintf(buf + used, cap - used, ",...");
            return;
        }
        int n = snprintf(buf + used, cap - used, "%s%s", i ? "," : "",
                         set->name[i]);
        if (n < 0)
            return;
        used += (size_t)n;
    }
}

/* ── typed reads off the snapshot, for the bottleneck search only ────────
 * These read the value a leaf's own descriptor points at, exactly as
 * test_telemetry_sync.c does. They produce no JSON — the moment a value is to
 * be SHOWN it comes out of the rendered document instead. A leaf that is not
 * PRESENT has no value to compare, and says so by returning false. */

static const struct telemetry_leaf *tls_leaf_by_key(
    const struct telemetry_domain_schema *s, const char *key)
{
    for (size_t i = 0; i < s->leaf_count; i++) {
        if (strcmp(s->leaves[i].key, key) == 0)
            return &s->leaves[i];
    }
    return NULL;
}

static const struct telemetry_leaf_meta *tls_meta(
    const void *snap, const struct telemetry_leaf *lf)
{
    return (const struct telemetry_leaf_meta *)(const void *)
        ((const char *)snap + lf->meta_off);
}

static bool tls_leaf_i64(const void *snap, const struct telemetry_leaf *lf,
                         int64_t *out)
{
    if (!lf || lf->ctype != TLC_I64)
        return false;
    if (tls_meta(snap, lf)->presence != TELEMETRY_PRESENT)
        return false;
    memcpy(out, (const char *)snap + lf->value_off, sizeof *out);
    return true;
}

/* ── the bottleneck ──────────────────────────────────────────────────────
 * Which rung is the ladder waiting on? Two answers, in priority order, and the
 * reply always says which one it gave:
 *
 *   cursor_deficit_to_upstream  a rung whose cursor sits BELOW its immediate
 *       upstream's is holding heights the ladder has already admitted. The rung
 *       with the largest such deficit is where the fold is queued, and during a
 *       cold sync that is the whole story (headers at the tip, bodies far
 *       behind => body_fetch). This is an ORDERING over published cursors, not
 *       a threshold: no number is invented and nothing is judged.
 *   slowest_step_us_ewma        every rung is level, so nothing is queued and
 *       the honest bottleneck is the rung that costs the most per step — which
 *       the domain already publishes as values.rate.slowest_stage. Read, never
 *       recomputed.
 *
 * When neither is knowable the stage is null and the reason token says why, so
 * "no bottleneck" and "could not tell" never look alike.
 *
 * KNOWN GAP, stated rather than hidden: the deficit search lives here because
 * the sync field table publishes no furthest-behind leaf. It belongs in the
 * provider as a TL_LEAF pair (a rung name and its deficit); until it moves
 * there, `ops telemetry sync summary` is the only surface that answers it. */
struct tls_bottleneck {
    const char *stage;   /* NULL when unknown */
    const char *basis;
    bool behind_known;
    int64_t behind_blocks;
    const char *reason;  /* "" unless stage is NULL */
};

static void tls_bottleneck_find(const struct telemetry_domain_schema *s,
                                const void *snap,
                                const struct tls_stage_set *set,
                                struct tls_bottleneck *out)
{
    memset(out, 0, sizeof *out);
    out->basis = "none";
    out->reason = "no_cursor_is_readable_and_no_stage_has_stepped";

    char key[TLS_STAGE_NAME_MAX + TLS_CURSOR_SUFFIX_LEN + 1];
    bool have_prev = false;
    int64_t prev = 0;
    int64_t worst = 0;
    size_t worst_idx = 0;
    bool found = false;
    bool any_cursor = false;

    for (size_t i = 0; i < set->count; i++) {
        int n = snprintf(key, sizeof key, "%s%s", set->name[i],
                         TLS_CURSOR_SUFFIX);
        int64_t cur = 0;
        if (n < 0 || (size_t)n >= sizeof key ||
            !tls_leaf_i64(snap, tls_leaf_by_key(s, key), &cur)) {
            /* An unreadable rung breaks the chain: the NEXT rung's deficit
             * would be measured against a cursor two rungs up, which is not a
             * deficit at all. Restart the pairing rather than report a number
             * whose meaning changed. */
            have_prev = false;
            continue;
        }
        any_cursor = true;
        if (have_prev && prev > cur && (!found || prev - cur > worst)) {
            worst = prev - cur;
            worst_idx = i;
            found = true;
        }
        prev = cur;
        have_prev = true;
    }

    if (found) {
        out->stage = set->name[worst_idx];
        out->basis = "cursor_deficit_to_upstream";
        out->behind_known = true;
        out->behind_blocks = worst;
        out->reason = "";
        return;
    }

    /* Level ladder: fall back to the rung the domain itself designates as the
     * slowest. Its own presence carries the reason when it has none. */
    const struct telemetry_leaf *slow = tls_leaf_by_key(s, "slowest_stage");
    if (slow && slow->ctype == TLC_TEXT) {
        const struct telemetry_leaf_meta *m = tls_meta(snap, slow);
        if (m->presence == TELEMETRY_PRESENT) {
            out->stage = (const char *)snap + slow->value_off;
            out->basis = "slowest_step_us_ewma";
            out->reason = "";
            return;
        }
        if (m->reason && m->reason[0])
            out->reason = any_cursor ? m->reason
                                     : "no_cursor_is_readable";
    } else if (any_cursor) {
        out->reason = "ladder_is_level_and_no_slowest_stage_leaf_exists";
    }
}

static bool tls_push_bottleneck(struct json_value *doc,
                                const struct tls_bottleneck *b)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = true;
    if (b->stage) {
        ok &= json_push_kv_str(&o, "stage", b->stage);
    } else {
        struct json_value nul;
        json_init(&nul);
        json_set_null(&nul);
        ok &= json_push_kv(&o, "stage", &nul);
        json_free(&nul);
    }
    ok &= json_push_kv_str(&o, "basis", b->basis);
    if (b->behind_known)
        ok &= json_push_kv_int(&o, "behind_blocks", b->behind_blocks);
    ok &= json_push_kv_str(&o, "reason", b->reason);
    ok &= json_push_kv_str(&o, "drill_down", "ops.telemetry.sync.stage");
    ok &= json_push_kv(doc, "bottleneck", &o);
    json_free(&o);
    return ok;
}

/* ── rendering, sized before it is shipped ───────────────────────────── */

/* The ladder itself is telemetry_reply_render_fitting() in platform/modules/util — it is
 * domain-agnostic and every ops.telemetry.* leaf needs it. What stays here is
 * only the part that is this leaf's business: what to SAY when the document
 * does not fit. */

/* ── projection: the rendered document, sliced by rung ───────────────── */

/* Copy every value belonging to `stage` out of `doc.values`, keyed by the
 * leaf's own key. Returns the number copied; a leaf the view did not render is
 * skipped rather than invented. */
static size_t tls_push_stage_fields(struct json_value *row,
                                    const struct telemetry_domain_schema *s,
                                    const struct json_value *values,
                                    const char *stage, bool *ok)
{
    struct json_value fields;
    json_init(&fields);
    json_set_object(&fields);
    size_t n = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        if (!tls_key_in_stage(lf->key, stage))
            continue;
        const struct json_value *g = json_get(values, lf->group);
        const struct json_value *v = g ? json_get(g, lf->key) : NULL;
        if (!v)
            continue;
        *ok &= json_push_kv(&fields, lf->key, v);
        n++;
    }
    *ok &= json_push_kv(row, "fields", &fields);
    json_free(&fields);
    return n;
}

/* The rung's own verdict: the loudest health any of its leaves earned, taken
 * from the domain verdict rather than recomputed. */
static enum telemetry_health tls_stage_health(
    const struct telemetry_domain_verdict *v, const char *stage)
{
    enum telemetry_health worst = TELEMETRY_HEALTH_OK;
    for (size_t i = 0; i < v->finding_count; i++) {
        if (!tls_key_in_stage(v->findings[i].key, stage))
            continue;
        if (v->findings[i].health > worst)
            worst = v->findings[i].health;
    }
    return worst;
}

/* The group a rung's leaves live in — read off the first leaf that claims the
 * rung, so a regrouped table needs no edit here. */
static const char *tls_stage_group(const struct telemetry_domain_schema *s,
                                   const char *stage)
{
    for (size_t i = 0; i < s->leaf_count; i++) {
        if (tls_key_in_stage(s->leaves[i].key, stage))
            return s->leaves[i].group;
    }
    return "";
}

static bool tls_push_stage_row(struct json_value *arr,
                               const struct telemetry_domain_schema *s,
                               const struct json_value *doc,
                               const struct telemetry_domain_verdict *verdict,
                               const char *stage)
{
    const struct json_value *values = json_get(doc, "values");
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = true;
    ok &= json_push_kv_str(&row, "stage", stage);
    ok &= json_push_kv_str(&row, "group", tls_stage_group(s, stage));
    ok &= json_push_kv_str(&row, "health",
                           telemetry_health_name(tls_stage_health(verdict,
                                                                  stage)));
    size_t n = tls_push_stage_fields(&row, s, values, stage, &ok);
    ok &= json_push_kv_int(&row, "field_count", (int64_t)n);
    ok &= json_push_back(arr, &row);
    json_free(&row);
    return ok;
}

/* The per-leaf provenance for ONE rung, lifted verbatim out of the rendered
 * document's `leaves` plane. This is why `stage` renders at FULL: below FULL
 * the render layer reports provenance only for leaves that are not plainly
 * present, and "one stage in full detail" means all of it. */
static bool tls_push_stage_provenance(struct json_value *out,
                                      const struct telemetry_domain_schema *s,
                                      const struct json_value *doc,
                                      const char *stage)
{
    const struct json_value *src = json_get(doc, "leaves");
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = true;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        if (!tls_key_in_stage(lf->key, stage))
            continue;
        const struct json_value *e = src ? json_get(src, lf->path) : NULL;
        if (e)
            ok &= json_push_kv(&o, lf->path, e);
    }
    ok &= json_push_kv(out, "leaves", &o);
    json_free(&o);
    return ok;
}

/* Header shared by both projections, plus the two whole-snapshot blocks a
 * reader needs to know whether the rows can be trusted. Both are copied out of
 * the rendered document rather than recomputed. */
static bool tls_push_projection_header(struct json_value *out,
                                       const struct telemetry_domain_schema *s,
                                       const struct json_value *doc,
                                       const struct telemetry_domain_verdict *v,
                                       const struct tls_stage_set *set)
{
    bool ok = true;
    ok &= json_push_kv_str(out, "domain_schema", s->schema_id);
    ok &= json_push_kv_str(out, "domain", s->domain);
    /* Stated, not implied: both projections cut their rows from a FULL render
     * regardless of --view, because a rung row that dropped fields by tier
     * would be a different shape per caller. --view is honoured by `summary`,
     * which ships the document itself; here it is ignored, and saying so beats
     * letting a caller infer it from a byte count that never changes. */
    ok &= json_push_kv_str(out, "projection_detail", "full");
    ok &= json_push_kv_int(out, "stage_count", (int64_t)set->count);
    ok &= json_push_kv_bool(out, "stage_set_truncated", set->overflowed);

    struct json_value h;
    json_init(&h);
    json_set_object(&h);
    ok &= json_push_kv_str(&h, "state", telemetry_health_name(v->state));
    ok &= json_push_kv_int(&h, "rules_evaluated", (int64_t)v->rules_evaluated);
    ok &= json_push_kv_int(&h, "unhealthy_count", (int64_t)v->unhealthy_count);
    ok &= json_push_kv_int(&h, "unknown_count", (int64_t)v->unknown_count);
    ok &= json_push_kv(out, "health", &h);
    json_free(&h);

    const struct json_value *c = json_get(doc, "completeness");
    if (c)
        ok &= json_push_kv(out, "completeness", c);
    const struct json_value *f = json_get(doc, "freshness");
    if (f)
        ok &= json_push_kv(out, "freshness", f);
    return ok;
}

/* ── shared handler prologue ─────────────────────────────────────────── */

/* Fill one snapshot and judge it. Every handler starts here, so a provider
 * failure is one typed error rather than three. */
static bool tls_prepare(struct sync_snapshot *snap,
                        const struct telemetry_domain_schema **out_schema,
                        struct telemetry_domain_verdict *verdict,
                        struct tls_stage_set *set,
                        struct zcl_command_reply *reply)
{
    memset(snap, 0, sizeof *snap);
    const struct telemetry_domain_schema *s = &g_sync_schema;
    *out_schema = s;

    /* A one-shot native CLI process never ran app_init(). The provider's
     * finality-floor read goes through reducer_frontier_floor() ->
     * chain_params_get(), which ASSERTS pCurrentParams non-NULL — so without
     * this the leaf aborts the process with a core dump rather than answering.
     * Verified, not assumed: it did exactly that before this line existed. The
     * same one-liner with the same reason is already carried by
     * tools/command/native_offline_query.c; the RPC bridge path selects in
     * bridge_ensure_rpc_client(), and these three leaves never go through the
     * bridge. Idempotent, so an in-node caller that already selected — the
     * only caller for which these numbers are non-zero — is unaffected.
     * Mainnet-only, matching the bridge's own choice. */
    chain_params_select(CHAIN_MAIN);

    if (!sync_dump_state_fill(snap)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "SNAPSHOT_UNAVAILABLE", "execute", false, false,
                               "the sync telemetry provider did not fill a "
                               "snapshot",
                               "engine/services/src/sync_telemetry_fill.c");
        return false;
    }
    if (!telemetry_evaluate(s, snap, verdict)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "EVALUATE_FAILED",
                               "execute", false, false,
                               "the telemetry evaluator did not judge the sync "
                               "snapshot", s->domain);
        return false;
    }
    tls_stage_set_build(s, set);
    return true;
}

static void tls_render_failed(struct zcl_command_reply *reply,
                              const char *domain)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                           "execute", false, false,
                           "the telemetry render layer did not produce a "
                           "document", domain);
}

/* Nothing fit. The reader gets the measurement, because "it did not fit" with
 * no number is not actionable and an empty body is worse than either. */
static void tls_reply_too_large(struct zcl_command_reply *reply,
                                const char *what, size_t bytes)
{
    char evidence[160];
    (void)snprintf(evidence, sizeof evidence,
                   "%s: the smallest view still renders %zu bytes against a "
                   "%zu byte frame", what, bytes, (size_t)TLS_DATA_FRAME);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "REPLY_TOO_LARGE",
                           "execute", false, false,
                           "even the summary view exceeds this leaf's reply "
                           "budget", evidence);
}

static void tls_encode_failed(struct zcl_command_reply *reply,
                              const char *what)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "REPLY_BUILD_FAILED",
                           "execute", false, false,
                           "ran out of memory building the reply document",
                           what);
}

/* ── ops.telemetry.sync.summary ──────────────────────────────────────── */

void zcl_native_handle_telemetry_sync_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct sync_snapshot snap;
    const struct telemetry_domain_schema *s = NULL;
    struct telemetry_domain_verdict verdict;
    struct tls_stage_set set;
    if (!tls_prepare(&snap, &s, &verdict, &set, reply))
        return;

    bool unrecognized = false;
    enum telemetry_view want =
        telemetry_view_parse(request->view, NULL, &unrecognized);

    struct telemetry_reply_fit fit;
    if (!telemetry_reply_render_fitting(s, &snap, want, TLS_DATA_FRAME,
                                        &reply->data, &fit) ||
        !fit.rendered) {
        tls_render_failed(reply, s->domain);
        return;
    }
    if (!fit.fits) {
        /* Even the smallest view overflows. Shipping it would produce a reply
         * with an empty body, which reads as "nothing to report". Say the
         * measurement out loud instead. */
        tls_reply_too_large(reply, "ops.telemetry.sync.summary", fit.bytes);
        return;
    }
    enum telemetry_view got = fit.view;

    bool ok = true;
    if (got != want) {
        /* The reply says it shrank and what it was asked for; the alternative
         * is a silently empty document. */
        ok &= json_push_kv_bool(&reply->data, "view_downgraded", true);
        ok &= json_push_kv_str(&reply->data, "view_requested",
                               telemetry_view_name(want));
        ok &= json_push_kv_str(&reply->data, "view_downgraded_reason",
                               "the requested view does not fit the reply "
                               "budget");
    }
    if (unrecognized)
        ok &= json_push_kv_bool(&reply->data, "view_key_unrecognized", true);

    struct tls_bottleneck b;
    tls_bottleneck_find(s, &snap, &set, &b);
    ok &= tls_push_bottleneck(&reply->data, &b);
    if (!ok) {
        tls_encode_failed(reply, "ops.telemetry.sync.summary");
        return;
    }

    if (b.stage) {
        char input[192];
        int n = snprintf(input, sizeof input, "{\"stage\":\"%s\"}", b.stage);
        if (n > 0 && (size_t)n < sizeof input)
            (void)zcl_command_reply_add_next(
                reply, "ops.telemetry.sync.stage", input,
                b.behind_known
                    ? "open the rung the ladder is furthest behind on"
                    : "open the rung that costs the most per step");
    } else {
        (void)zcl_command_reply_add_next(
            reply, "ops.telemetry.sync.stages", "{}",
            "no rung is behind and none has stepped — list the whole ladder");
    }
}

/* ── ops.telemetry.sync.stages ───────────────────────────────────────── */

void zcl_native_handle_telemetry_sync_stages(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct sync_snapshot snap;
    const struct telemetry_domain_schema *s = NULL;
    struct telemetry_domain_verdict verdict;
    struct tls_stage_set set;
    if (!tls_prepare(&snap, &s, &verdict, &set, reply))
        return;

    /* FULL, because a row must carry every field its rung publishes; the rows
     * are a projection, not the document, so the render's own size never
     * reaches the wire. */
    struct json_value doc;
    json_init(&doc);
    if (!telemetry_render(s, &snap, TLV_FULL, NULL, &doc)) {
        json_free(&doc);
        tls_render_failed(reply, s->domain);
        return;
    }

    json_set_object(&reply->data);
    bool ok = tls_push_projection_header(&reply->data, s, &doc, &verdict, &set);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < set.count; i++)
        ok &= tls_push_stage_row(&arr, s, &doc, &verdict, set.name[i]);
    ok &= json_push_kv(&reply->data, "stages", &arr);
    json_free(&arr);
    json_free(&doc);

    if (!ok) {
        tls_encode_failed(reply, "ops.telemetry.sync.stages");
        return;
    }

    struct tls_bottleneck b;
    tls_bottleneck_find(s, &snap, &set, &b);
    if (b.stage) {
        char input[192];
        int n = snprintf(input, sizeof input, "{\"stage\":\"%s\"}", b.stage);
        if (n > 0 && (size_t)n < sizeof input)
            (void)zcl_command_reply_add_next(
                reply, "ops.telemetry.sync.stage", input,
                "open the rung this ladder is waiting on");
    }
    /* Always a way forward, even when no rung is nameable — a reply with an
     * empty next[] is a dead end for a caller walking the tree. */
    (void)zcl_command_reply_add_next(reply, "ops.telemetry.sync.summary", "{}",
                                     "the posture these rows were cut from");
}

/* ── ops.telemetry.sync.stage ────────────────────────────────────────── */

void zcl_native_handle_telemetry_sync_stage(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct sync_snapshot snap;
    const struct telemetry_domain_schema *s = NULL;
    struct telemetry_domain_verdict verdict;
    struct tls_stage_set set;
    if (!tls_prepare(&snap, &s, &verdict, &set, reply))
        return;

    char valid[256];
    tls_stage_csv(&set, valid, sizeof valid);

    const char *stage = json_get_str(json_get(request->input, "stage"));
    if (!stage || !stage[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_STAGE",
                               "normalize", false, false,
                               "stage is required; name one reducer stage",
                               valid);
        (void)zcl_command_reply_add_next(reply, "ops.telemetry.sync.stages",
                                         "{}", "list every reducer stage");
        return;
    }
    size_t idx = 0;
    if (!tls_stage_index(&set, stage, &idx)) {
        /* Never an empty reply: the valid set is the evidence, so one call
         * both refuses and tells the caller what would have worked. */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_STAGE",
                               "normalize", false, false,
                               "no such reducer stage in the sync telemetry "
                               "ladder", valid);
        (void)zcl_command_reply_add_next(reply, "ops.telemetry.sync.stages",
                                         "{}", "list every reducer stage");
        return;
    }

    struct json_value doc;
    json_init(&doc);
    if (!telemetry_render(s, &snap, TLV_FULL, NULL, &doc)) {
        json_free(&doc);
        tls_render_failed(reply, s->domain);
        return;
    }

    json_set_object(&reply->data);
    bool ok = tls_push_projection_header(&reply->data, s, &doc, &verdict, &set);
    ok &= json_push_kv_int(&reply->data, "ladder_index", (int64_t)idx);
    ok &= json_push_kv_str(&reply->data, "upstream_stage",
                           idx > 0 ? set.name[idx - 1] : "");
    /* The upstream drill-down is DATA, not a next[] step, and that is forced:
     * push_next_array() (engine/modules/kernel/src/command_registry.c) refuses any next[]
     * entry whose command equals the command being served — a loop guard — and
     * a refusal there aborts the whole serialization, so the caller receives an
     * EMPTY reply reported as RESPONSE_BUDGET_EXCEEDED rather than a document
     * with one link missing. Stage-to-stage is exactly that self-reference.
     * Measured, not reasoned: every rung but the first returned 296 bytes of
     * overflow envelope until this link moved out of next[]. */
    if (idx > 0) {
        char invocation[160];
        int w = snprintf(invocation, sizeof invocation,
                         "ops telemetry sync stage --stage=%s",
                         set.name[idx - 1]);
        ok &= w > 0 && (size_t)w < sizeof invocation &&
              json_push_kv_str(&reply->data, "upstream_invocation",
                               invocation);
    }

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    ok &= tls_push_stage_row(&arr, s, &doc, &verdict, set.name[idx]);
    ok &= json_push_kv(&reply->data, "stages", &arr);
    json_free(&arr);
    ok &= tls_push_stage_provenance(&reply->data, s, &doc, set.name[idx]);
    json_free(&doc);

    if (!ok) {
        tls_encode_failed(reply, "ops.telemetry.sync.stage");
        return;
    }

    (void)zcl_command_reply_add_next(
        reply, "ops.telemetry.sync.stages", "{}",
        idx > 0 ? "compare this rung against the upstream rung that bounds it"
                : "compare this rung against the rest of the ladder");
    (void)zcl_command_reply_add_next(reply, "ops.telemetry.sync.summary", "{}",
                                     "the whole ladder and its bottleneck");
}
