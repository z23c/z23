/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_zcode — the `zcode` telemetry domain end to end: its field
 * table, its collector, and the one leaf that is READY over them.
 *
 * WHAT EACH CHECK BUYS, because a telemetry test that only asserts "a reply
 * came back" is worse than no test — an error envelope is a non-empty reply:
 *
 *   meaning is complete     every leaf resolves to an ontology row with a
 *                           `means`, and to `implies` + `next` unless the row
 *                           is TFR_INFO. A number with no stated meaning is
 *                           the defect this whole layer exists to remove.
 *   nothing is UNSET        the collector touches every leaf on every path.
 *                           UNSET is a provider defect, never a state, so
 *                           this is checked with the store CLOSED as well as
 *                           reachable — the closed path is the one a lane is
 *                           most likely to forget.
 *   unreadable != broken    a leaf we could not read judges UNKNOWN, never
 *                           UNHEALTHY. Getting this backwards sends an
 *                           operator to diagnose a store that was merely busy.
 *   the leaf really answers ops.telemetry.zcode.summary is dispatched through
 *                           the real registry and the machine envelope's
 *                           "ok" must be TRUE — not merely present, and not
 *                           merely non-empty.
 *   it fits its budget      over-budget is an EMPTY reply, not a truncated
 *                           one, so the byte count is asserted rather than
 *                           hoped for.
 *   the refusals are honest swarm and installs must still be PLANNED and must
 *                           fail closed. If someone flips them READY without
 *                           a provider, this is what catches it.
 *
 * Datadir discipline: every path that could open a store runs against an
 * isolated temp dir via SetDataDir. Nothing here touches the operator's node.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/zcode_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_render:
 * TEST/ASSERT mint a per-function label and these checks are independent. */
#define TZ_CHECK(name, cond)                                                  \
    do {                                                                      \
        printf("%s... ", (name));                                             \
        if (cond) { printf("OK\n"); }                                         \
        else { printf("FAIL (%s)\n", #cond); failures++; }                    \
    } while (0)

/* Point the process at a throwaway datadir with hosting OFF. Every check in
 * this file runs under it; not one of them may reach the live node. */
static void tz_isolate(const char *tag)
{
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "telemetry_zcode", tag);
    SetDataDir(dd);
}

static const struct json_value *dig2(const struct json_value *o,
                                     const char *a, const char *b)
{
    return json_get(json_get(o, a), b);
}

/* ── 1. every leaf carries its meaning ───────────────────────────────── */

static int check_every_leaf_has_meaning(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("zcode");
    TZ_CHECK("[zcode] the domain is registered", s != NULL);
    if (!s)
        return failures;
    TZ_CHECK("[zcode] the schema id is versioned",
             s->schema_id && strcmp(s->schema_id, "zcl.telemetry.zcode.v1") == 0);
    /* Shrink-only floor: a domain that silently loses its rows must fail here
     * rather than pass over an empty set. */
    TZ_CHECK("[zcode] the field table still has its rows", s->leaf_count >= 12);

    size_t no_row = 0, no_means = 0, no_implies = 0, no_next = 0, judged = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, lf->path);
        if (!f) { no_row++; continue; }
        if (!f->means || !f->means[0])
            no_means++;
        if (f->rule == TFR_INFO)
            continue;
        judged++;
        if (!f->implies || !f->implies[0])
            no_implies++;
        if (!f->next || !f->next[0])
            no_next++;
    }
    TZ_CHECK("[zcode] every leaf resolves to an ontology row", no_row == 0);
    TZ_CHECK("[zcode] every leaf states what it means", no_means == 0);
    TZ_CHECK("[zcode] every judged leaf states what a bad value implies",
             no_implies == 0);
    TZ_CHECK("[zcode] every judged leaf names the next command", no_next == 0);
    /* A domain with no judged row can never report anything but ok, which is
     * indistinguishable from having no telemetry at all. */
    TZ_CHECK("[zcode] at least one leaf carries a real health rule",
             judged >= 1);
    return failures;
}

/* ── 2. a filled snapshot leaves nothing UNSET ───────────────────────── */

static int check_fill_leaves_nothing_unset(void)
{
    int failures = 0;
    tz_isolate("unset");
    const struct telemetry_domain_schema *s = telemetry_domain_find("zcode");
    if (!s)
        return failures;

    struct zcode_snapshot snap = {0};
    TZ_CHECK("[fill] the collector reports success",
             zcode_dump_state_fill(&snap));

    size_t unset = 0, no_reason = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_leaf_meta *m =
            (const struct telemetry_leaf_meta *)(const void *)
                ((const char *)&snap + lf->meta_off);
        if (m->presence == TELEMETRY_UNSET) { unset++; continue; }
        /* A non-present leaf owes a static reason token — that token is the
         * whole difference between "busy" and "empty". */
        if (m->presence != TELEMETRY_PRESENT && (!m->reason || !m->reason[0]))
            no_reason++;
    }
    TZ_CHECK("[fill] the collector touches every leaf, store closed included",
             unset == 0);
    TZ_CHECK("[fill] every non-present leaf carries a static reason token",
             no_reason == 0);

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(s, &snap, TLV_NORMAL, NULL, &out);
    TZ_CHECK("[fill] the filled snapshot renders", ok);
    TZ_CHECK("[fill] the renderer counts zero unset leaves",
             json_get_int(dig2(&out, "completeness", "unset")) == 0);
    TZ_CHECK("[fill] the renderer reports no provider defect",
             !json_get_bool(dig2(&out, "completeness", "provider_defect")));
    /* With hosting off there is no store, so the store leaves are a real
     * answer (not_applicable) rather than a failed read. */
    TZ_CHECK("[fill] a closed store reports not_applicable, not unavailable",
             json_get_int(dig2(&out, "completeness", "not_applicable")) > 0 &&
             json_get_int(dig2(&out, "completeness", "unavailable")) == 0);
    TZ_CHECK("[fill] hosting is reported off on a default datadir",
             !json_get_bool(dig2(json_get(&out, "values"), "store",
                                 "hosting_enabled")));
    json_free(&out);
    return failures;
}

/* ── 3. unreadable is UNKNOWN, never UNHEALTHY ───────────────────────── */

static int check_unavailable_is_unknown_not_unhealthy(void)
{
    int failures = 0;
    tz_isolate("unknown");
    const struct telemetry_domain_schema *s = telemetry_domain_find("zcode");
    if (!s)
        return failures;

    /* Start from a snapshot whose judged leaves are all healthy, so the
     * verdict below can only come from the leaf we take away. */
    struct zcode_snapshot snap = {0};
    (void)zcode_dump_state_fill(&snap);
    TELEMETRY_SET_I64(&snap, tracked_packages, 3, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, quota_rejects_total, 0, TELEMETRY_SRC_IN_PROCESS);

    struct telemetry_domain_verdict v;
    TZ_CHECK("[unknown] a healthy snapshot evaluates",
             telemetry_evaluate(s, &snap, &v));
    TZ_CHECK("[unknown] a healthy snapshot is ok",
             v.state == TELEMETRY_HEALTH_OK && v.unhealthy_count == 0);

    /* Now lose exactly one judged leaf to a lost race. */
    TELEMETRY_UNAVAILABLE_LEAF(&snap, quota_rejects_total,
                               "package_store_busy");
    TZ_CHECK("[unknown] the degraded snapshot evaluates",
             telemetry_evaluate(s, &snap, &v));
    TZ_CHECK("[unknown] a leaf we could not read is UNKNOWN, not UNHEALTHY",
             v.state == TELEMETRY_HEALTH_UNKNOWN);
    TZ_CHECK("[unknown] and it is not counted as a rule failure",
             v.unhealthy_count == 0 && v.unknown_count == 1);

    /* And the judged rule still bites when the value IS readable and bad —
     * otherwise the check above would pass on a domain with no rules at all. */
    TELEMETRY_SET_I64(&snap, quota_rejects_total, 7, TELEMETRY_SRC_IN_PROCESS);
    TZ_CHECK("[unknown] the refused-admission rule evaluates",
             telemetry_evaluate(s, &snap, &v));
    TZ_CHECK("[unknown] a nonzero quota rejection is a real finding",
             v.unhealthy_count == 1 && v.state == TELEMETRY_HEALTH_DEGRADED);
    return failures;
}

/* ── 4. the READY leaf answers, and the PLANNED ones refuse ──────────── */

static const struct zcl_command_spec *find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static size_t exec_leaf(const struct zcl_command_registry *reg,
                        const char *path, char *out, size_t out_size,
                        enum zcl_command_exit *code)
{
    const struct zcl_command_spec *spec = find_spec(reg, path);
    if (!spec)
        return 0;
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, path, "normal", 0, 0,
                                                 NULL, out, out_size, code);
    json_free(&input);
    return n;
}

static int check_summary_leaf_answers(void)
{
    int failures = 0;
    tz_isolate("summary");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        find_spec(reg, "ops.telemetry.zcode.summary");
    TZ_CHECK("[leaf] ops.telemetry.zcode.summary is registered", spec != NULL);
    if (!spec)
        return failures;
    TZ_CHECK("[leaf] it is READY with a handler",
             spec->availability == ZCL_COMMAND_READY && spec->handler != NULL);

    size_t declared = spec->budget_bytes > 0 ? (size_t)spec->budget_bytes
                                             : ZCL_COMMAND_RESULT_BUDGET;
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];
    memset(out, 0, sizeof(out));
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = exec_leaf(reg, "ops.telemetry.zcode.summary", out, sizeof(out),
                         &code);
    /* Over budget is an EMPTY document, not a short one, so a zero length is
     * the budget failure and must be reported as such. */
    TZ_CHECK("[leaf] the reply is non-empty (a zero length means the "
             "document was refused for exceeding its byte budget)", n > 0);
    TZ_CHECK("[leaf] the reply fits the leaf's declared budget",
             n > 0 && n <= declared);
    TZ_CHECK("[leaf] the exit code is OK", code == ZCL_COMMAND_EXIT_OK);

    struct json_value doc;
    json_init(&doc);
    bool parsed = n > 0 && json_read(&doc, out, n);
    TZ_CHECK("[leaf] the reply parses as JSON", parsed);
    /* THE assertion: ok must be TRUE. An error envelope is also a valid,
     * non-empty, parseable document — asserting anything weaker than this
     * passes on a totally broken build. */
    TZ_CHECK("[leaf] the machine envelope reports ok:true",
             parsed && json_get(&doc, "ok") &&
             json_get_bool(json_get(&doc, "ok")));
    const struct json_value *data = parsed ? json_get(&doc, "data") : NULL;
    TZ_CHECK("[leaf] the body IS the telemetry document",
             data && json_get(data, "schema") && json_get(data, "values") &&
             json_get(data, "health") && json_get(data, "completeness") &&
             json_get(data, "leaves") && json_get(data, "freshness"));
    TZ_CHECK("[leaf] it names the zcode domain",
             data && json_get_str(json_get(data, "domain")) &&
             strcmp(json_get_str(json_get(data, "domain")), "zcode") == 0);
    TZ_CHECK("[leaf] no leaf is unset in the served document",
             data && json_get_int(dig2(data, "completeness", "unset")) == 0);

    /* ── the WORST-CASE budget proof ──────────────────────────────────
     * The measurement above is one state. The document grows with the
     * number of NON-present leaves, because those report provenance at
     * every view tier, and with the number of findings, because each one
     * carries its full means/implies/next. The store-busy path has one more
     * non-present leaf than the store-closed path measured above, so
     * proving the closed path fits proves nothing about the busy one — and
     * over budget is an EMPTY reply, not a short one.
     *
     * So: render the worst case explicitly, and calibrate the envelope
     * overhead from the reply we just measured rather than guessing it. */
    const struct telemetry_domain_schema *s = telemetry_domain_find("zcode");
    if (parsed && data && s) {
        char buf[1u << 16];
        size_t closed_doc = json_write(data, buf, sizeof buf);
        size_t envelope = (closed_doc > 0 && n > closed_doc) ? n - closed_doc
                                                             : n;

        struct zcode_snapshot busy = {0};
        (void)zcode_dump_state_fill(&busy);
        /* Exactly the state vcs_package_store_try_totals reports BUSY:
         * store_open unknown too, because the pointer was never seen. */
        TELEMETRY_UNAVAILABLE_LEAF(&busy, store_open, "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, quota_bytes, "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, tracked_packages,
                                   "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, cas_chunks, "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, manifest_bytes_total,
                                   "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, evictions_total,
                                   "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, gc_orphans_total,
                                   "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, quota_rejects_total,
                                   "package_store_busy");
        TELEMETRY_UNAVAILABLE_LEAF(&busy, last_release_accept,
                                   "package_store_busy");
        struct json_value bdoc;
        json_init(&bdoc);
        size_t busy_bytes = 0;
        if (telemetry_render(s, &busy, TLV_NORMAL, NULL, &bdoc))
            busy_bytes = json_write(&bdoc, buf, sizeof buf);
        json_free(&bdoc);
        printf("    (store-closed reply %zu, store-busy document %zu + %zu "
               "envelope, declared budget %zu)\n",
               n, busy_bytes, envelope, declared);
        TZ_CHECK("[budget] the store-busy worst case renders", busy_bytes > 0);
        TZ_CHECK("[budget] the worst case fits the leaf's DECLARED budget "
                 "(over budget is an empty reply, so this must hold in every "
                 "state, not just the one that happened to be measured)",
                 busy_bytes > 0 && busy_bytes + envelope <= declared);
    }
    json_free(&doc);
    return failures;
}

static int check_planned_leaves_refuse(void)
{
    int failures = 0;
    tz_isolate("planned");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static const char *const k_planned[] = {
        "ops.telemetry.zcode.swarm",
        "ops.telemetry.zcode.installs",
    };
    for (size_t i = 0; i < sizeof k_planned / sizeof k_planned[0]; i++) {
        const struct zcl_command_spec *spec = find_spec(reg, k_planned[i]);
        char label[160];
        snprintf(label, sizeof label,
                 "[planned] %s is PLANNED with a reason naming what is "
                 "missing", k_planned[i]);
        TZ_CHECK(label, spec && spec->availability == ZCL_COMMAND_PLANNED &&
                        spec->handler == NULL &&
                        spec->availability_reason &&
                        strlen(spec->availability_reason) > 40);
        if (!spec)
            continue;
        static char out[ZCL_COMMAND_RESULT_BUDGET + 1];
        memset(out, 0, sizeof(out));
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        (void)exec_leaf(reg, k_planned[i], out, sizeof(out), &code);
        snprintf(label, sizeof label,
                 "[planned] %s fails closed rather than returning an empty "
                 "object", k_planned[i]);
        TZ_CHECK(label, code != ZCL_COMMAND_EXIT_OK);
    }
    return failures;
}

/* ── 5. the collector never blocks behind an open store ──────────────── */

/* Prove the trylock path is real, not decorative: with the store's own lock
 * NOT held the collector reads it, and the accessor it uses reports CLOSED
 * (a fact about the node) rather than BUSY (a fact about the call) when no
 * store exists. Collapsing those two is how a busy store becomes an empty
 * one in a report. */
static int check_closed_is_not_busy(void)
{
    int failures = 0;
    tz_isolate("closed");
    struct vcs_package_store_totals t;
    memset(&t, 0xa5, sizeof t);
    enum vcs_package_store_totals_result r = vcs_package_store_try_totals(&t);
    TZ_CHECK("[trylock] no store open reports CLOSED, never BUSY",
             r == VCS_PACKAGE_STORE_TOTALS_CLOSED);
    TZ_CHECK("[trylock] the output is zeroed on the closed path",
             t.tracked_packages == 0 && t.cas_chunks == 0 &&
             t.quota_bytes == 0);
    TZ_CHECK("[trylock] and last_release_accept is the none token",
             t.last_release_accept &&
             strcmp(t.last_release_accept, "none") == 0);
    TZ_CHECK("[trylock] a null output is refused by name",
             vcs_package_store_try_totals(NULL) ==
                 VCS_PACKAGE_STORE_TOTALS_NULL);
    return failures;
}

int test_telemetry_zcode(void)
{
    int failures = 0;
    failures += check_every_leaf_has_meaning();
    failures += check_fill_leaves_nothing_unset();
    failures += check_unavailable_is_unknown_not_unhealthy();
    failures += check_closed_is_not_busy();
    failures += check_summary_leaf_answers();
    failures += check_planned_leaves_refuse();
    SetDataDir("");
    printf("=== telemetry_zcode: %d failures ===\n", failures);
    return failures;
}
