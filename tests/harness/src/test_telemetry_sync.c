/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_sync — the `sync` domain's field table and its provider.
 *
 * test_telemetry_render already proves the RENDERER. This group proves the two
 * things that are the DOMAIN's own responsibility and that no generic test can
 * see, because both are properties of one specific table and one specific
 * collector:
 *
 *   the table is fully annotated   every TL_LEAF resolves to an ontology row
 *                                  carrying means, and — unless it is
 *                                  TFR_INFO — implies and next as well. A
 *                                  field that ships without meaning is the
 *                                  original defect the ontology exists to
 *                                  close, and a table-driven domain emits
 *                                  from a generic renderer, so nothing else
 *                                  in the suite would notice.
 *   the provider forgot nothing    a snapshot sync_dump_state_fill() filled
 *                                  has NO leaf left at TELEMETRY_UNSET. UNSET
 *                                  is the zero value, so a forgotten leaf is
 *                                  exactly the case that reads as a plausible
 *                                  0 to anyone who does not check presence.
 *
 * plus the two behaviours a reader's decisions rest on: health is derived
 * identically at every view tier, and a leaf we could not read is judged
 * UNKNOWN rather than broken.
 *
 * The ordering rules get a bite check as well. A rule nobody has watched fail
 * is a decoration: the ladder-inversion case below drives the four
 * TFR_MAX_RATIO_OF rows unhealthy on purpose, so a future edit that guts them
 * into TFR_INFO fails here instead of silently judging nothing.
 *
 * ISOLATION. sync_dump_state_fill() reaches progress_store_db(), and its
 * durable branch resolves whatever datadir this process has. A test without
 * SetDataDir would read the operator's RUNNING node and pass for the wrong
 * reason — that has happened in this repository. The datadir is therefore
 * pinned to a hermetic per-pid temp directory for the whole group; nothing
 * here opens the store, so the honest outcome is the not-open branch.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "services/sync_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_render:
 * these checks are numerous, independent, and more useful reported one by
 * one than collapsed behind a single TEST() label. */
#define TS_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

static const struct telemetry_domain_schema *sync_schema(void)
{
    return &g_sync_schema;
}

/* The descriptor for one leaf, by its ontology path. NULL when the table has
 * no such row — which is itself a finding at every call site below. */
static const struct telemetry_leaf *leaf_by_path(const char *path)
{
    const struct telemetry_domain_schema *s = sync_schema();
    for (size_t i = 0; i < s->leaf_count; i++) {
        if (strcmp(s->leaves[i].path, path) == 0)
            return &s->leaves[i];
    }
    return NULL;
}

static struct telemetry_leaf_meta *meta_of(struct sync_snapshot *snap,
                                           const struct telemetry_leaf *lf)
{
    return (struct telemetry_leaf_meta *)(void *)((char *)snap + lf->meta_off);
}

static int64_t *i64_of(struct sync_snapshot *snap,
                       const struct telemetry_leaf *lf)
{
    return (int64_t *)(void *)((char *)snap + lf->value_off);
}

/* Overwrite one already-filled i64 leaf, keeping its provenance PRESENT. The
 * ladder-ordering cases need to place specific heights against each other. */
static void set_i64_at(struct sync_snapshot *snap, const char *path,
                       int64_t v, int *failures)
{
    const struct telemetry_leaf *lf = leaf_by_path(path);
    if (!lf || lf->ctype != TLC_I64) {
        printf("  (no i64 leaf at %s)\n", path);
        (*failures)++;
        return;
    }
    *i64_of(snap, lf) = v;
    *meta_of(snap, lf) = (struct telemetry_leaf_meta){
        .presence = TELEMETRY_PRESENT,
        .source = TELEMETRY_SRC_IN_PROCESS,
        .observed_unix = telemetry_now_unix(),
        .age_ms = 0,
        .reason = "" };
}

static void set_bool_at(struct sync_snapshot *snap, const char *path,
                        bool v, int *failures)
{
    const struct telemetry_leaf *lf = leaf_by_path(path);
    if (!lf || lf->ctype != TLC_BOOL) {
        printf("  (no bool leaf at %s)\n", path);
        (*failures)++;
        return;
    }
    *(bool *)(void *)((char *)snap + lf->value_off) = v;
    *meta_of(snap, lf) = (struct telemetry_leaf_meta){
        .presence = TELEMETRY_PRESENT,
        .source = TELEMETRY_SRC_IN_PROCESS,
        .observed_unix = telemetry_now_unix(),
        .age_ms = 0,
        .reason = "" };
}

static void make_unavailable_at(struct sync_snapshot *snap, const char *path,
                                int *failures)
{
    const struct telemetry_leaf *lf = leaf_by_path(path);
    if (!lf) {
        printf("  (no leaf at %s)\n", path);
        (*failures)++;
        return;
    }
    *meta_of(snap, lf) = (struct telemetry_leaf_meta){
        .presence = TELEMETRY_UNAVAILABLE,
        .source = TELEMETRY_SRC_UNSET,
        .observed_unix = -1,
        .age_ms = -1,
        .reason = "test_forced_unavailable" };
}

static const struct telemetry_finding *finding_at(
        const struct telemetry_domain_verdict *v, const char *path)
{
    for (size_t i = 0; i < v->finding_count; i++) {
        if (strcmp(v->findings[i].path, path) == 0)
            return &v->findings[i];
    }
    return NULL;
}

/* The "nothing is wrong" baseline the negative cases are measured against:
 * every rung below its upstream, and H* published. On a test process no fold
 * has run, so hstar_published is legitimately false and its EXPECT_TRUE rule
 * legitimately fires; pinning it true here is what lets the cases below
 * attribute a verdict to the ONE leaf each of them manipulates. */
static void make_ladder_consistent(struct sync_snapshot *snap, int *failures)
{
    set_bool_at(snap, "values.frontier.hstar_published", true, failures);
    set_i64_at(snap, "values.headers.header_admit_cursor", 1000, failures);
    set_i64_at(snap, "values.headers.validate_headers_cursor", 900, failures);
    set_i64_at(snap, "values.bodies.body_fetch_cursor", 800, failures);
    set_i64_at(snap, "values.bodies.body_persist_cursor", 700, failures);
    set_i64_at(snap, "values.apply.utxo_apply_cursor", 600, failures);
    set_i64_at(snap, "values.apply.tip_finalize_cursor", 500, failures);
}

/* ── 1. the table is fully annotated ─────────────────────────────────── */

static int check_table_is_annotated(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = sync_schema();

    TS_CHECK("[sync] the domain is registered under the ontology subsystem "
             "name its rules are filed under",
             telemetry_domain_find("sync") == s &&
             strcmp(s->domain, "sync") == 0 &&
             strcmp(s->schema_id, "zcl.telemetry.sync.v1") == 0);

    /* Shrink guard. The ladder is six rungs plus the frontier and the rate
     * pair; a table that collapsed below this stopped modelling the ladder
     * and every check under it would pass vacuously over what was left. */
    TS_CHECK("[sync] the table still carries the whole ladder",
             s->leaf_count >= 40 && s->group_count >= 6);

    int no_row = 0, no_means = 0, no_implies = 0, no_next = 0;
    int orphan_group = 0, judged = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        bool in_group = false;
        for (size_t g = 0; g < s->group_count && !in_group; g++)
            in_group = strcmp(s->groups[g].name, lf->group) == 0;
        if (!in_group) {
            orphan_group++;
            printf("  leaf %s names group '%s', which the table does not "
                   "declare\n", lf->path, lf->group);
        }
        const struct telemetry_field *f =
            telemetry_field_lookup("sync", lf->path);
        if (!f) {
            no_row++;
            printf("  leaf %s has NO ontology row\n", lf->path);
            continue;
        }
        if (!f->means || !f->means[0]) {
            no_means++;
            printf("  leaf %s ships an empty means\n", lf->path);
        }
        if (f->rule == TFR_INFO)
            continue;
        judged++;
        if (!f->implies || !f->implies[0]) {
            no_implies++;
            printf("  judged leaf %s ships an empty implies\n", lf->path);
        }
        if (!f->next || !f->next[0]) {
            no_next++;
            printf("  judged leaf %s ships an empty next\n", lf->path);
        }
    }
    TS_CHECK("[sync] every leaf belongs to a declared group",
             orphan_group == 0);
    TS_CHECK("[sync] every leaf resolves to an ontology row", no_row == 0);
    TS_CHECK("[sync] every leaf states what it counts", no_means == 0);
    TS_CHECK("[sync] every JUDGED leaf states what an unhealthy value implies",
             no_implies == 0);
    TS_CHECK("[sync] every JUDGED leaf names the next command to run",
             no_next == 0);
    /* A table that judged nothing would satisfy every check above while
     * carrying no health contract at all. */
    TS_CHECK("[sync] the ladder actually judges something", judged >= 8);

    /* Each ratio rule must point at a leaf that EXISTS in this same table,
     * or the evaluator silently reports the row ABSENT forever. */
    int dangling = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_field *f =
            telemetry_field_lookup("sync", s->leaves[i].path);
        if (!f || (f->rule != TFR_MIN_RATIO_OF && f->rule != TFR_MAX_RATIO_OF))
            continue;
        if (!f->operand || !leaf_by_path(f->operand)) {
            dangling++;
            printf("  ratio leaf %s references missing operand '%s'\n",
                   s->leaves[i].path, f->operand ? f->operand : "(null)");
        }
    }
    TS_CHECK("[sync] every ratio rule's operand is a leaf of this domain",
             dangling == 0);
    return failures;
}

/* ── 2. the provider forgot nothing ──────────────────────────────────── */

static int check_provider_leaves_nothing_unset(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = sync_schema();
    struct sync_snapshot snap = {0};

    TS_CHECK("[sync] the provider refuses a NULL snapshot",
             !sync_dump_state_fill(NULL));
    TS_CHECK("[sync] the provider fills a zero-initialised snapshot",
             sync_dump_state_fill(&snap));

    int unset = 0, no_reason = 0, no_source = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_leaf_meta *m = meta_of(&snap, lf);
        if (m->presence == TELEMETRY_UNSET) {
            unset++;
            printf("  leaf %s was left UNSET by the provider\n", lf->path);
            continue;
        }
        /* A non-present leaf owes a static reason token; without one a
         * reader is told "not available" and nothing else. */
        if (m->presence != TELEMETRY_PRESENT &&
            (!m->reason || !m->reason[0])) {
            no_reason++;
            printf("  leaf %s is %s with no reason token\n", lf->path,
                   telemetry_presence_name(m->presence));
        }
        if (m->presence == TELEMETRY_PRESENT && m->source == TELEMETRY_SRC_UNSET) {
            no_source++;
            printf("  leaf %s is present with no source\n", lf->path);
        }
    }
    TS_CHECK("[sync] NO leaf is left at TELEMETRY_UNSET — an unset leaf is a "
             "provider that forgot a field, reported as a plausible 0",
             unset == 0);
    TS_CHECK("[sync] every non-present leaf carries a static reason token",
             no_reason == 0);
    TS_CHECK("[sync] every present leaf records where its value came from",
             no_source == 0);

    /* The same fact, read the way an agent reads it. */
    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(s, &snap, TLV_FULL, NULL, &doc);
    TS_CHECK("[sync] the filled snapshot renders", rendered);
    TS_CHECK("[sync] completeness reports zero unset leaves and no provider "
             "defect",
             json_get_int(json_get(json_get(&doc, "completeness"),
                                   "unset")) == 0 &&
             !json_get_bool(json_get(json_get(&doc, "completeness"),
                                     "provider_defect")));
    TS_CHECK("[sync] every leaf in the table is accounted for in the tallies",
             (size_t)(json_get_int(json_get(json_get(&doc, "completeness"),
                                            "present")) +
                      json_get_int(json_get(json_get(&doc, "completeness"),
                                            "unavailable")) +
                      json_get_int(json_get(json_get(&doc, "completeness"),
                                            "not_applicable")) +
                      json_get_int(json_get(json_get(&doc, "completeness"),
                                            "truncated"))) == s->leaf_count);
    json_free(&doc);
    return failures;
}

/* ── 3. health is derived, and the view prunes output only ───────────── */

static int check_renders_at_every_view(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = sync_schema();
    struct sync_snapshot snap = {0};
    (void)sync_dump_state_fill(&snap);
    make_ladder_consistent(&snap, &failures);

    struct telemetry_domain_verdict v;
    TS_CHECK("[sync] the domain evaluates", telemetry_evaluate(s, &snap, &v));
    const char *want = telemetry_health_name(v.state);

    static const enum telemetry_view k_views[] = {
        TLV_SUMMARY, TLV_NORMAL, TLV_FULL,
    };
    int missing_section = 0, wrong_state = 0, empty_doc = 0;
    size_t rendered_at[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        struct json_value doc;
        json_init(&doc);
        if (!telemetry_render(s, &snap, k_views[i], NULL, &doc)) {
            missing_section++;
            json_free(&doc);
            continue;
        }
        static const char *const k_need[] = {
            "schema", "domain", "view", "values", "leaves",
            "completeness", "freshness", "health", "_health",
        };
        for (size_t k = 0; k < sizeof(k_need) / sizeof(k_need[0]); k++) {
            if (!json_get(&doc, k_need[k])) {
                missing_section++;
                printf("  view %s lost section '%s'\n",
                       telemetry_view_name(k_views[i]), k_need[k]);
            }
        }
        const char *got = json_get_str(json_get(json_get(&doc, "health"),
                                                "state"));
        if (!got || strcmp(got, want) != 0) {
            wrong_state++;
            printf("  view %s reported health '%s', evaluator said '%s'\n",
                   telemetry_view_name(k_views[i]), got ? got : "(null)",
                   want);
        }
        rendered_at[i] = (size_t)json_get_int(
            json_get(json_get(&doc, "completeness"), "leaves_rendered"));
        if (rendered_at[i] == 0)
            empty_doc++;
        json_free(&doc);
    }
    TS_CHECK("[sync] every view renders the whole document shape",
             missing_section == 0);
    TS_CHECK("[sync] health is DERIVED — the same verdict at summary, normal "
             "and full, never authored per view", wrong_state == 0);
    TS_CHECK("[sync] no view renders an empty document", empty_doc == 0);
    /* The tier must actually prune, or "the view filters rendering only"
     * would be true of a filter that filters nothing. */
    TS_CHECK("[sync] a deeper view renders strictly more leaves",
             rendered_at[0] < rendered_at[1] &&
             rendered_at[1] < rendered_at[2] &&
             rendered_at[2] == s->leaf_count);
    return failures;
}

/* ── 4. unreadable is UNKNOWN, never broken ──────────────────────────── */

static int check_unavailable_is_unknown_not_unhealthy(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = sync_schema();
    /* A CRITICAL EXPECT_ZERO row: the loudest rule in the domain, so if a
     * missed read were mis-mapped this is where it would shout. */
    const char *crit = "values.apply.tip_finalize_utxo_count_diverged_total";

    /* (a) present and violated -> UNHEALTHY. Proves the rule BITES, so the
     * unknown case below is not passing because nothing is judged. */
    {
        struct sync_snapshot snap = {0};
        (void)sync_dump_state_fill(&snap);
        make_ladder_consistent(&snap, &failures);
        set_i64_at(&snap, crit, 1, &failures);
        struct telemetry_domain_verdict v;
        (void)telemetry_evaluate(s, &snap, &v);
        const struct telemetry_finding *f = finding_at(&v, crit);
        TS_CHECK("[sync] a violated CRITICAL rule drives the domain unhealthy",
                 v.state == TELEMETRY_HEALTH_UNHEALTHY &&
                 v.unhealthy_count >= 1 &&
                 f && f->health == TELEMETRY_HEALTH_UNHEALTHY);
    }

    /* (b) the same row, unreadable -> UNKNOWN, and the domain must NOT be
     * unhealthy on the strength of a read it never made. */
    {
        struct sync_snapshot snap = {0};
        (void)sync_dump_state_fill(&snap);
        make_ladder_consistent(&snap, &failures);
        set_i64_at(&snap, crit, 0, &failures);
        make_unavailable_at(&snap, crit, &failures);
        struct telemetry_domain_verdict v;
        (void)telemetry_evaluate(s, &snap, &v);
        const struct telemetry_finding *f = finding_at(&v, crit);
        TS_CHECK("[sync] an unreadable CRITICAL leaf is judged unknown, not "
                 "unhealthy",
                 f && f->health == TELEMETRY_HEALTH_UNKNOWN);
        TS_CHECK("[sync] an unreadable leaf raises no unhealthy count",
                 v.unhealthy_count == 0 &&
                 v.state != TELEMETRY_HEALTH_UNHEALTHY);
        TS_CHECK("[sync] unknown still outranks ok, so the reply cannot claim "
                 "health over a leaf it could not read",
                 v.unknown_count >= 1 && v.state >= TELEMETRY_HEALTH_UNKNOWN);

        struct json_value doc;
        json_init(&doc);
        (void)telemetry_render(s, &snap, TLV_FULL, NULL, &doc);
        const struct json_value *leaf =
            json_get(json_get(&doc, "leaves"), crit);
        const char *pres = json_get_str(json_get(leaf, "presence"));
        const char *why = json_get_str(json_get(leaf, "reason"));
        TS_CHECK("[sync] the rendered leaf says unavailable and why",
                 pres && strcmp(pres, "unavailable") == 0 &&
                 why && strcmp(why, "test_forced_unavailable") == 0);
        TS_CHECK("[sync] the unreadable leaf still renders its key, as null",
                 json_get(json_get(json_get(&doc, "values"), "apply"),
                          "tip_finalize_utxo_count_diverged_total") != NULL);
        json_free(&doc);
    }
    return failures;
}

/* ── 5. the ladder-ordering rules bite ───────────────────────────────── */

static int check_ladder_ordering_rules_bite(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = sync_schema();
    static const char *const k_downstream[] = {
        "values.headers.validate_headers_cursor",
        "values.bodies.body_fetch_cursor",
        "values.bodies.body_persist_cursor",
        "values.apply.utxo_apply_cursor",
        "values.apply.tip_finalize_cursor",
    };
    const size_t n = sizeof(k_downstream) / sizeof(k_downstream[0]);

    {
        struct sync_snapshot snap = {0};
        (void)sync_dump_state_fill(&snap);
        make_ladder_consistent(&snap, &failures);
        struct telemetry_domain_verdict v;
        (void)telemetry_evaluate(s, &snap, &v);
        int flagged = 0;
        for (size_t i = 0; i < n; i++)
            if (finding_at(&v, k_downstream[i]))
                flagged++;
        TS_CHECK("[sync] an ordered ladder trips no ordering rule",
                 flagged == 0);
        TS_CHECK("[sync] the ordering rules were actually evaluated, not "
                 "skipped for want of a denominator", v.rules_evaluated >= n);
    }

    /* Invert every rung: each downstream cursor above its upstream. */
    {
        struct sync_snapshot snap = {0};
        (void)sync_dump_state_fill(&snap);
        set_i64_at(&snap, "values.headers.header_admit_cursor", 100, &failures);
        set_i64_at(&snap, "values.headers.validate_headers_cursor", 200,
                   &failures);
        set_i64_at(&snap, "values.bodies.body_fetch_cursor", 300, &failures);
        set_i64_at(&snap, "values.bodies.body_persist_cursor", 400, &failures);
        set_i64_at(&snap, "values.apply.utxo_apply_cursor", 500, &failures);
        set_i64_at(&snap, "values.apply.tip_finalize_cursor", 600, &failures);
        struct telemetry_domain_verdict v;
        (void)telemetry_evaluate(s, &snap, &v);
        int flagged = 0;
        for (size_t i = 0; i < n; i++) {
            const struct telemetry_finding *f = finding_at(&v, k_downstream[i]);
            if (f && f->health == TELEMETRY_HEALTH_DEGRADED)
                flagged++;
            else
                printf("  %s did not report the inversion\n", k_downstream[i]);
        }
        TS_CHECK("[sync] every rung reports a downstream cursor that ran "
                 "ahead of its upstream", flagged == (int)n);
        TS_CHECK("[sync] a torn ladder is degraded, not silently ok",
                 v.state >= TELEMETRY_HEALTH_DEGRADED);
    }
    return failures;
}

int test_telemetry_sync(void)
{
    printf("\n=== telemetry sync domain tests ===\n");
    int failures = 0;

    /* Hermetic datadir for the whole group. sync_dump_state_fill() resolves
     * progress_store_db(), and a test that let that reach the operator's live
     * node would pass by reading a running node's state — the exact defect
     * this comment exists to prevent recurring. */
    char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "telemetry_sync", "datadir");
    SetDataDir(datadir);

    failures += check_table_is_annotated();
    failures += check_provider_leaves_nothing_unset();
    failures += check_renders_at_every_view();
    failures += check_unavailable_is_unknown_not_unhealthy();
    failures += check_ladder_ordering_rules_bite();

    test_cleanup_tmpdir(datadir);
    printf("=== telemetry_sync: %d failures ===\n", failures);
    return failures;
}
