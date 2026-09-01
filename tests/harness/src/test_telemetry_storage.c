/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_storage — the `storage` telemetry domain end to end: its
 * field table, its collector, and the three READY `ops.telemetry.storage.*`
 * leaves that serve it.
 *
 * What each block here is defending, and why a weaker check would not:
 *
 *   meaning coverage      every leaf resolves to an ontology row carrying
 *                         means, and — unless it is TFR_INFO — implies and
 *                         next. A leaf with a rule and no `next` tells an
 *                         operator something is wrong and nothing about where
 *                         to go, which is the state this whole surface exists
 *                         to remove.
 *   nothing left UNSET    the collector must set a presence for EVERY leaf on
 *                         EVERY path. TELEMETRY_UNSET == 0, so a forgotten
 *                         field is silent unless something counts it; this
 *                         counts it, over a snapshot the real collector
 *                         filled, not a hand-built one.
 *   unreadable != broken  a judged leaf we could not read is UNKNOWN, never
 *                         UNHEALTHY. Asserted PER LEAF rather than over the
 *                         domain state, because in a test process most of the
 *                         storage subsystems are legitimately closed and the
 *                         domain rolls up degraded for real reasons. The
 *                         same leaf is then given a genuinely bad value and
 *                         must come back UNHEALTHY, so "unknown" is proof the
 *                         rule discriminates rather than proof it never fires.
 *   ok:true, not non-empty
 *                         each leaf is dispatched through the REAL catalog and
 *                         its envelope parsed. A next[] entry naming the
 *                         command being served makes push_next_array reject
 *                         the entire reply and the CLI reports the total loss
 *                         as a budget overflow over an empty document — an
 *                         "is the reply non-empty" assertion passes on that
 *                         296-byte error envelope. Only ok:true catches it.
 *
 * ISOLATION. This test drives handlers that call node_rpc_call(), whose
 * default target is the OPERATOR'S LIVE NODE via the datadir cookie. Both the
 * datadir and the RPC client are pinned to a hermetic tmp dir, and the RPC
 * test hook is installed so no socket is opened at all. Without that pinning a
 * green run here would be green because of the running node.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/storage_telemetry.h"
#include "util/safe_alloc.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same idiom as test_telemetry_render:
 * these checks are numerous and independent, and are more useful reported
 * individually than folded under one TEST() label. */
#define TS_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

static const struct json_value *dig2(const struct json_value *o,
                                     const char *a, const char *b)
{
    return json_get(json_get(o, a), b);
}

/* The leaf meta stored beside a value, addressed the way the render layer
 * addresses it — by the descriptor's byte offset, not by member name. */
static const struct telemetry_leaf_meta *meta_of(const void *snap,
                                                 const struct telemetry_leaf *lf)
{
    return (const struct telemetry_leaf_meta *)(const void *)
        ((const char *)snap + lf->meta_off);
}

static struct telemetry_leaf_meta *meta_of_mut(void *snap,
                                               const struct telemetry_leaf *lf)
{
    return (struct telemetry_leaf_meta *)(void *)
        ((char *)snap + lf->meta_off);
}

static const struct telemetry_leaf *leaf_by_path(
    const struct telemetry_domain_schema *s, const char *path)
{
    for (size_t i = 0; i < s->leaf_count; i++)
        if (strcmp(s->leaves[i].path, path) == 0)
            return &s->leaves[i];
    return NULL;
}

/* The `state` string the rendered document gives one leaf, read out of
 * health.unhealthy[]. A leaf judged ok is absent from that array by design, so
 * "ok" is the honest answer for a miss. */
static const char *finding_state(const struct json_value *doc,
                                 const char *path)
{
    const struct json_value *arr = dig2(doc, "health", "unhealthy");
    if (!arr || arr->type != JSON_ARR)
        return "ok";
    for (size_t i = 0; i < arr->num_children; i++) {
        const struct json_value *f = &arr->children[i];
        const char *p = json_get_str(json_get(f, "path"));
        if (p && strcmp(p, path) == 0) {
            const char *st = json_get_str(json_get(f, "state"));
            return st ? st : "";
        }
    }
    return "ok";
}

/* ── 1. every leaf carries meaning ──────────────────────────────────────── */

static int check_meaning_rows(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("storage");
    TS_CHECK("[storage] the domain is registered", s != NULL);
    if (!s)
        return failures;

    TS_CHECK("[storage] the table declares more than the frozen meta group",
             s->leaf_count > 1 && s->group_count >= 3);

    int no_row = 0, no_means = 0, no_implies = 0, no_next = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup("storage", lf->path);
        if (!f) { no_row++; continue; }
        if (!f->means || !f->means[0])
            no_means++;
        if (f->rule == TFR_INFO)
            continue;
        /* A judged row owes both halves: what a bad value means, and the one
         * command to run next. */
        if (!f->implies || !f->implies[0])
            no_implies++;
        if (!f->next || !f->next[0])
            no_next++;
    }
    TS_CHECK("[storage] every leaf resolves to an ontology row", no_row == 0);
    TS_CHECK("[storage] every leaf states what it means", no_means == 0);
    TS_CHECK("[storage] every judged leaf states what a bad value implies",
             no_implies == 0);
    TS_CHECK("[storage] every judged leaf names the next command",
             no_next == 0);

    /* The two rows that carry an absolute threshold are the only ones allowed
     * to, and both are pinned to the node's own configured default. A silent
     * edit to either is a health rule changing meaning. */
    const struct telemetry_field *fb =
        telemetry_field_lookup("storage", "values.disk.free_bytes");
    TS_CHECK("[storage] the free-space floor is the node's own refuse "
             "threshold (1 GiB), not an invented number",
             fb && fb->rule == TFR_MIN_ABS && fb->threshold == 1073741824 &&
             fb->severity == TFS_CRITICAL);
    const struct telemetry_field *pa =
        telemetry_field_lookup("storage", "values.disk.poll_age_seconds");
    TS_CHECK("[storage] the poll-age ceiling is ten default poll intervals",
             pa && pa->rule == TFR_MAX_ABS && pa->threshold == 600);
    return failures;
}

/* ── 2. the collector leaves nothing UNSET ──────────────────────────────── */

static int check_fill_sets_every_leaf(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("storage");
    if (!s)
        return failures;

    struct storage_snapshot snap = {0};
    TS_CHECK("[storage] the collector fills a zeroed snapshot",
             storage_dump_state_fill(&snap));

    int unset = 0, silent = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf_meta *m = meta_of(&snap, &s->leaves[i]);
        if (m->presence == TELEMETRY_UNSET) {
            printf("  [storage] UNSET leaf: %s\n", s->leaves[i].path);
            unset++;
            continue;
        }
        /* Not-present owes a greppable static reason; an empty one is how a
         * collector hides which subsystem it lost. */
        if (m->presence != TELEMETRY_PRESENT &&
            (!m->reason || !m->reason[0])) {
            printf("  [storage] reasonless non-present leaf: %s\n",
                   s->leaves[i].path);
            silent++;
        }
    }
    TS_CHECK("[storage] the collector leaves NO leaf unset — an unset leaf is "
             "a field the collector forgot", unset == 0);
    TS_CHECK("[storage] every unreadable leaf names why", silent == 0);

    /* The same fact through the rendered document, which is what an operator
     * actually reads: completeness must agree with the walk above. */
    struct json_value doc;
    json_init(&doc);
    bool rendered = storage_telemetry_dump_state_json(&doc, "full");
    TS_CHECK("[storage] the domain renders at full detail", rendered);
    TS_CHECK("[storage] completeness reports zero unset leaves and no "
             "provider defect",
             json_get_int(dig2(&doc, "completeness", "unset")) == 0 &&
             !json_get_bool(dig2(&doc, "completeness", "provider_defect")));
    TS_CHECK("[storage] the document carries the frozen schema id",
             json_get_str(json_get(&doc, "schema")) &&
             strcmp(json_get_str(json_get(&doc, "schema")),
                    "zcl.telemetry.storage.v1") == 0);

    /* MEASURED, and recorded rather than worked around. The render layer emits
     * `health` LAST and each finding carries the field table's full
     * means/implies/next prose, so on a process where most leaves are
     * unreadable the verdict is by far the largest section of the document —
     * larger, on its own, than a RESULT leaf's whole 4096-byte contract. The
     * shared projector therefore commits `values` and drops `health`, and says
     * so in `_page.truncated`. This lane does not step the view down to make it
     * fit (that helper is being promoted into the shared layer); it states the
     * size here so the number is a fact and not a guess. */
    {
        static char buf[262144];
        size_t all = json_write(&doc, buf, sizeof buf);
        const struct json_value *h = json_get(&doc, "health");
        struct json_value hcopy;
        json_init(&hcopy);
        if (h)
            json_copy(&hcopy, h);
        size_t hsz = h ? json_write(&hcopy, buf, sizeof buf) : 0;
        json_free(&hcopy);
        printf("  [storage] full document %zu bytes, of which health is %zu "
               "(%lld findings); RESULT contract is %u\n",
               all, hsz,
               (long long)json_get_int(dig2(&doc, "health", "unknown_count")),
               (unsigned)ZCL_COMMAND_RESULT_BUDGET);
    }
    json_free(&doc);
    return failures;
}

/* ── 3. unavailable is unknown, a bad value is unhealthy ────────────────── */

static int check_unavailable_is_unknown(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("storage");
    if (!s)
        return failures;
    const char *k_path = "values.disk.free_bytes";
    const struct telemetry_leaf *lf = leaf_by_path(s, k_path);
    TS_CHECK("[storage] free_bytes is in the descriptor table", lf != NULL);
    if (!lf)
        return failures;

    /* (a) deliberately unavailable. */
    struct storage_snapshot snap = {0};
    (void)storage_dump_state_fill(&snap);
    TELEMETRY_UNAVAILABLE_LEAF(&snap, free_bytes, "test_forced_unavailable");

    struct json_value doc;
    json_init(&doc);
    bool ok = telemetry_render(&g_storage_schema, &snap, TLV_FULL, "disk",
                               &doc);
    TS_CHECK("[storage] a domain with an unavailable leaf still renders", ok);
    const struct json_value *v = json_get(dig2(&doc, "values", "disk"),
                                          "free_bytes");
    TS_CHECK("[storage] an unavailable leaf renders its key as null rather "
             "than vanishing", v != NULL && v->type == JSON_NULL);
    TS_CHECK("[storage] an unavailable CRITICAL leaf is judged unknown, NOT "
             "unhealthy — 'we could not read it' must never read as 'it is "
             "broken'",
             strcmp(finding_state(&doc, k_path), "unknown") == 0);
    json_free(&doc);

    /* (b) the same leaf with a genuinely bad value. Without this, (a) would
     * also pass on a rule that never fires at all. */
    struct storage_snapshot bad = {0};
    (void)storage_dump_state_fill(&bad);
    TELEMETRY_SET_I64(&bad, free_bytes, 1024, TELEMETRY_SRC_IN_PROCESS);
    json_init(&doc);
    ok = telemetry_render(&g_storage_schema, &bad, TLV_FULL, "disk", &doc);
    TS_CHECK("[storage] a domain with a failing leaf still renders", ok);
    TS_CHECK("[storage] 1 KiB free trips the refuse floor as unhealthy, so "
             "the unknown verdict above is discrimination and not silence",
             ok && strcmp(finding_state(&doc, k_path), "unhealthy") == 0);
    json_free(&doc);

    /* (c) a leaf the collector marked NOT_APPLICABLE is also unknown, never a
     * finding of fault: not-applicable is a real answer about configuration. */
    struct storage_snapshot na = {0};
    (void)storage_dump_state_fill(&na);
    const struct telemetry_leaf *proj =
        leaf_by_path(s, "values.database.projection_handle_independent");
    if (proj) {
        struct telemetry_leaf_meta *m = meta_of_mut(&na, proj);
        m->presence = TELEMETRY_NOT_APPLICABLE;
        m->reason = "test_forced_not_applicable";
        json_init(&doc);
        ok = telemetry_render(&g_storage_schema, &na, TLV_FULL, "database",
                              &doc);
        TS_CHECK("[storage] a not-applicable leaf is unknown, not unhealthy",
                 ok && strcmp(finding_state(&doc,
                     "values.database.projection_handle_independent"),
                     "unknown") == 0);
        json_free(&doc);
    }
    return failures;
}

/* ── 4. the commands ────────────────────────────────────────────────────── */

/* Stand in for the node: answer `dumpstate` from the in-process registry, so
 * the DIAG row wiring is exercised too and no socket is ever opened. */
static char *ts_rpc_hook(const char *method, const char *params_json)
{
    if (!method || strcmp(method, "dumpstate") != 0 || !params_json)
        return NULL;
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    if (!json_read(&params, params_json, strlen(params_json))) {
        json_free(&params);
        json_free(&result);
        return NULL;
    }
    bool ok = diag_rpc_dumpstate(&params, false, &result);
    json_free(&params);
    if (!ok) {
        json_free(&result);
        return NULL;
    }
    /* Generous: the full-detail document is several KB, and the point of the
     * measurement below is what the ENVELOPE does with it, not what a short
     * buffer here would do. */
    size_t cap = 262144;
    char *buf = zcl_malloc(cap, "test storage telemetry rpc body");
    if (!buf) {
        json_free(&result);
        return NULL;
    }
    size_t n = json_write(&result, buf, cap);
    json_free(&result);
    if (n == 0 || n >= cap) {
        free(buf);
        return NULL;
    }
    return buf;
}

static const struct zcl_command_spec *spec_for(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    return reg ? zcl_command_registry_find(reg, path, NULL) : NULL;
}

/* Dispatch one leaf through the real catalog and report the envelope. */
static int exec_leaf(const char *path, const char *view, bool want_ok,
                     size_t *out_bytes)
{
    int failures = 0;
    char label[192];
    const struct zcl_command_spec *spec = spec_for(path);
    snprintf(label, sizeof label, "[storage] %s is in the catalog", path);
    TS_CHECK(label, spec != NULL);
    if (!spec)
        return failures;

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        zcl_command_catalog(), spec, NULL, &input, false, path, view, 0, 0,
        NULL, out, sizeof out, &exit_code);
    json_free(&input);
    if (out_bytes)
        *out_bytes = n;

    snprintf(label, sizeof label,
             "[storage] %s serializes a reply (over budget writes an EMPTY "
             "document, so a zero here is an overflow, not a short answer)",
             path);
    TS_CHECK(label, n > 0);
    if (n == 0)
        return failures;

    struct json_value env;
    json_init(&env);
    bool parsed = json_read(&env, out, n) && env.type == JSON_OBJ;
    snprintf(label, sizeof label, "[storage] %s returns a JSON envelope", path);
    TS_CHECK(label, parsed);
    if (!parsed) {
        json_free(&env);
        return failures;
    }
    bool got = json_get_bool(json_get(&env, "ok"));
    snprintf(label, sizeof label, "[storage] %s reports ok:%s", path,
             want_ok ? "true" : "false");
    if (want_ok && !got) {
        const struct json_value *err = json_get(&env, "error");
        printf("  [storage] %s failed: code=%s message=%s\n", path,
               json_get_str(json_get(err, "code")),
               json_get_str(json_get(err, "message")));
    }
    TS_CHECK(label, got == want_ok);

    if (want_ok) {
        /* The reply must actually carry the rendered domain, not just a
         * successful-looking envelope around nothing. */
        const struct json_value *data = json_get(&env, "data");
        const char *sch = json_get_str(json_get(data, "schema"));
        snprintf(label, sizeof label,
                 "[storage] %s carries the rendered storage domain", path);
        TS_CHECK(label, data && data->type == JSON_OBJ && sch &&
                        strcmp(sch, "zcl.telemetry.storage.v1") == 0 &&
                        json_get(data, "values") != NULL);

        /* The shared projector fits whole top-level sections into the byte
         * contract and states what it could not fit. A dropped section is
         * acceptable; a dropped section presented as a complete answer is not,
         * so the page descriptor must exist and must carry a resume cursor
         * whenever it truncated. */
        const struct json_value *page = json_get(data, "_page");
        bool trunc = json_get_bool(json_get(page, "truncated"));
        snprintf(label, sizeof label,
                 "[storage] %s states its own paging, and a truncated page "
                 "always carries a resume cursor", path);
        TS_CHECK(label, page != NULL && page->type == JSON_OBJ &&
                        (!trunc || json_get(page, "next_cursor") != NULL));
        /* Measured, not assumed. When the projector drops a section it names
         * the resume index; printing the section it stopped AT is the only way
         * a reader learns WHICH part of the document did not fit, and this
         * lane deliberately does not step the view down to make it fit — the
         * shared budget helper owns that. */
        long long total = json_get_int(json_get(page, "total_fields"));
        long long inc = json_get_int(json_get(page, "included"));
        printf("  [storage] %s envelope: %zu bytes (contract %u), "
               "sections %lld/%lld truncated=%s values=%s health=%s\n", path, n,
               (unsigned)ZCL_COMMAND_RESULT_BUDGET, inc, total,
               trunc ? "yes" : "no",
               json_get(data, "values") ? "yes" : "DROPPED",
               json_get(data, "health") ? "yes" : "DROPPED");
    }
    json_free(&env);
    return failures;
}

static int check_commands(void)
{
    int failures = 0;
    node_rpc_client_set_test_hook(ts_rpc_hook);

    size_t bytes = 0;
    failures += exec_leaf("ops.telemetry.storage.summary", "normal", true,
                          &bytes);
    failures += exec_leaf("ops.telemetry.storage.database", "normal", true,
                          &bytes);
    failures += exec_leaf("ops.telemetry.storage.disk", "normal", true,
                          &bytes);
    /* Honest gap: nothing publishes cache occupancy, so the leaf fails closed
     * and names what is missing rather than answering with an empty object. */
    failures += exec_leaf("ops.telemetry.storage.cache", "normal", false,
                          &bytes);
    {
        const struct zcl_command_spec *cache =
            spec_for("ops.telemetry.storage.cache");
        TS_CHECK("[storage] the cache leaf is PLANNED with a reason naming "
                 "what is missing",
                 cache && cache->availability == ZCL_COMMAND_PLANNED &&
                 cache->availability_reason && cache->availability_reason[0]);
    }

    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* ── entry point ────────────────────────────────────────────────────────── */

int test_telemetry_storage(void)
{
    printf("\n=== telemetry storage domain tests ===\n");
    int failures = 0;

    /* Pin BOTH the datadir and the RPC client target to a hermetic tmp dir.
     * Dozens of nominally read-only paths in this tree default to the
     * operator's live datadir; a test that reaches it passes for the wrong
     * reason on this host and fails on a machine with no node. */
    char dir[256];
    test_make_tmpdir(dir, sizeof dir, "telemetry_storage", "datadir");
    SetDataDir(dir);
    node_rpc_client_init(dir, 39232);

    failures += check_meaning_rows();
    failures += check_fill_sets_every_leaf();
    failures += check_unavailable_is_unknown();
    failures += check_commands();

    printf("=== telemetry_storage: %d failures ===\n", failures);
    return failures;
}
