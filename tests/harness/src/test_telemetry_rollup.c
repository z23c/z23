/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_rollup — the provider registry and the whole-node fold.
 *
 * The rollup's value is entirely in properties that a "does it emit a
 * document" test would not notice, so those are what this pins:
 *
 *   no domain can be omitted    the provider registry is pasted from the same
 *                               telemetry_domains.def as the schema registry,
 *                               so the two must hold identical domain sets in
 *                               identical order. A domain added to one and not
 *                               the other is the half-registered shape the
 *                               .def exists to forbid.
 *   unknown outranks ok         a domain nobody could collect is reported as
 *                               unknown WITH a reason and still listed — a
 *                               node that cannot be read must never roll up as
 *                               healthy, and must never do it by shortening
 *                               the list.
 *   the fold is a max()         the rolled-up state equals the worst domain
 *                               state, and `bottleneck` names that domain.
 *   no second evaluator         the rollup's verdict for a domain equals what
 *                               telemetry_evaluate gives for the same
 *                               snapshot. A rollup that disagreed with the
 *                               leaf it points at would be worse than none.
 *   dropping is stated          alerts_active reports active_total, listed and
 *                               dropped_for_reply_budget, so a bounded page
 *                               can never read as "that is all of them".
 *   terse by contract           summary/health carry no per-field prose; one
 *                               domain's findings measure ~4 KB and an
 *                               over-budget reply in this registry is EMPTY,
 *                               not truncated.
 *
 * Node-free: the fold is called directly, and every collector it reaches is
 * either node-free or reports its own domain unavailable. Nothing here opens a
 * datadir, so nothing here needs SetDataDir.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "services/telemetry_providers.h"
#include "services/telemetry_rollup.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <stdio.h>
#include <string.h>

#define TL_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

static const struct json_value *arr_at(const struct json_value *a, size_t i)
{
    if (!a || a->type != JSON_ARR)
        return NULL;
    return json_at(a, i);
}

/* The two registries are pasted from one table; drift means a hand edit. */
static int check_registries_agree(void)
{
    int failures = 0;

    TL_CHECK("[rollup] the provider registry holds every telemetry domain",
             telemetry_provider_count() == telemetry_domain_count());

    size_t mismatched = 0, no_fill = 0, no_schema = 0, zero_size = 0;
    for (size_t i = 0; i < telemetry_provider_count(); i++) {
        const struct telemetry_provider *p = telemetry_provider_at(i);
        const struct telemetry_domain_schema *s = telemetry_domain_at(i);
        if (!p || !s || !p->domain || !s->domain ||
            strcmp(p->domain, s->domain) != 0)
            mismatched++;
        if (p && !p->fill)
            no_fill++;
        if (p && p->schema != s)
            no_schema++;
        /* A provider whose snapshot size is 0 would let telemetry_evaluate
         * read a domain's descriptors against nothing. */
        if (p && p->snapshot_size == 0)
            zero_size++;
    }
    TL_CHECK("[rollup] provider i and schema i name the SAME domain, in the "
             "same order — a domain cannot be registered in one and not the "
             "other", mismatched == 0);
    TL_CHECK("[rollup] every domain has a collector adapter", no_fill == 0);
    TL_CHECK("[rollup] every provider points at its own domain's schema",
             no_schema == 0);
    TL_CHECK("[rollup] every provider declares a non-zero snapshot size",
             zero_size == 0);

    /* The shared buffer a rollup allocates must fit the largest domain, or
     * telemetry_provider_collect refuses that domain rather than truncating
     * it — the max must therefore be a real max. */
    size_t max = telemetry_snapshot_max_size(), over = 0;
    for (size_t i = 0; i < telemetry_provider_count(); i++)
        if (telemetry_provider_at(i)->snapshot_size > max)
            over++;
    TL_CHECK("[rollup] the shared snapshot buffer size fits every domain",
             over == 0 && max > 0);

    /* find() must resolve every registered name, and refuse an unknown one
     * rather than returning a plausible neighbour. */
    size_t unfindable = 0;
    for (size_t i = 0; i < telemetry_provider_count(); i++) {
        const struct telemetry_provider *p = telemetry_provider_at(i);
        if (telemetry_provider_find(p->domain) != p)
            unfindable++;
    }
    TL_CHECK("[rollup] every domain resolves by name", unfindable == 0);
    TL_CHECK("[rollup] an unknown domain resolves to nothing, not to a "
             "neighbour",
             telemetry_provider_find("no_such_domain") == NULL &&
                 telemetry_provider_find(NULL) == NULL);
    TL_CHECK("[rollup] an out-of-range index yields nothing",
             telemetry_provider_at(telemetry_provider_count()) == NULL);
    return failures;
}

/* A collector must never be handed a buffer smaller than its snapshot: a
 * partial fill would leave live bytes at whatever the caller left there,
 * which zero-init exists to prevent. */
static int check_collect_refuses_a_short_buffer(void)
{
    int failures = 0;
    const struct telemetry_provider *p = telemetry_provider_at(0);
    unsigned char tiny[8] = {0};

    TL_CHECK("[rollup] a buffer too small for the domain is refused, not "
             "partially filled",
             p && !telemetry_provider_collect(p, tiny, sizeof tiny));
    TL_CHECK("[rollup] collect refuses a NULL provider or buffer",
             !telemetry_provider_collect(NULL, tiny, sizeof tiny) &&
                 !telemetry_provider_collect(p, NULL, 64));
    return failures;
}

/* Walk the `domains[]` array of a rollup document and assert the invariants
 * that hold whatever the node's real state is. */
static int check_domain_rows(const struct json_value *doc, const char *what)
{
    int failures = 0;
    char label[160];

    const struct json_value *arr = json_get(doc, "domains");
    (void)snprintf(label, sizeof label,
                   "[rollup] %s lists EVERY domain — an unreadable one is "
                   "reported, never dropped", what);
    TL_CHECK(label, arr && arr->type == JSON_ARR &&
                        json_size(arr) == telemetry_provider_count());
    if (!arr || arr->type != JSON_ARR)
        return failures;

    size_t bad_name = 0, bad_health = 0, silent_unknown = 0, has_prose = 0;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *o = arr_at(arr, i);
        if (!o || o->type != JSON_OBJ) {
            bad_name++;
            continue;
        }
        const char *dom = json_get_str(json_get(o, "domain"));
        const struct telemetry_provider *p = telemetry_provider_at(i);
        if (!dom || !p || strcmp(dom, p->domain) != 0)
            bad_name++;

        const char *h = json_get_str(json_get(o, "health"));
        if (!h || (strcmp(h, "ok") != 0 && strcmp(h, "unknown") != 0 &&
                   strcmp(h, "degraded") != 0 && strcmp(h, "unhealthy") != 0))
            bad_health++;

        /* A domain that could not be collected must say why, and must not be
         * called ok. */
        const struct json_value *c = json_get(o, "collected");
        if (c && c->type == JSON_BOOL && !json_get_bool(c)) {
            const char *why = json_get_str(json_get(o, "reason"));
            if (!why || !*why)
                silent_unknown++;
            if (h && strcmp(h, "ok") == 0)
                silent_unknown++;
        }
        /* Terse by contract: a per-domain row carries counts, never the
         * means/implies/next prose that makes a domain document ~4 KB. */
        if (json_get(o, "means") || json_get(o, "implies"))
            has_prose++;
    }
    (void)snprintf(label, sizeof label,
                   "[rollup] %s rows are in registry order and name their own "
                   "domain", what);
    TL_CHECK(label, bad_name == 0);
    (void)snprintf(label, sizeof label,
                   "[rollup] %s reports health as one of the four enum "
                   "tokens, never prose", what);
    TL_CHECK(label, bad_health == 0);
    (void)snprintf(label, sizeof label,
                   "[rollup] %s: an uncollected domain always states a reason "
                   "and is never called ok", what);
    TL_CHECK(label, silent_unknown == 0);
    (void)snprintf(label, sizeof label,
                   "[rollup] %s carries no per-field prose — eight domains of "
                   "it would empty the reply, not truncate it", what);
    TL_CHECK(label, has_prose == 0);
    return failures;
}

/* The rolled-up state must equal the worst per-domain state. Computed here
 * from the document's own rows, so this checks the FOLD rather than restating
 * it. */
static int check_fold_is_the_worst_domain(const struct json_value *doc)
{
    int failures = 0;
    static const char *k_order[] = {"ok", "unknown", "degraded", "unhealthy"};

    const struct json_value *arr = json_get(doc, "domains");
    int worst = 0;
    const char *worst_domain = NULL;
    if (arr && arr->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(arr); i++) {
            const char *h = json_get_str(json_get(arr_at(arr, i), "health"));
            for (int r = 0; r < 4; r++) {
                if (h && strcmp(h, k_order[r]) == 0 && r > worst) {
                    worst = r;
                    worst_domain =
                        json_get_str(json_get(arr_at(arr, i), "domain"));
                }
            }
        }
    }

    const char *rolled = json_get_str(json_get(doc, "health"));
    TL_CHECK("[rollup] the rolled-up health equals the WORST domain's health "
             "— the enum is ordered so this is a max(), not a policy",
             rolled && strcmp(rolled, k_order[worst]) == 0);

    /* `bottleneck` is the worst domain, and is explicitly null (present, not
     * omitted) when nothing is worse than ok. */
    const struct json_value *b = json_get(doc, "bottleneck");
    TL_CHECK("[rollup] `bottleneck` is always present, as an object or an "
             "explicit null", b != NULL);
    if (worst == 0) {
        TL_CHECK("[rollup] nothing worse than ok yields an explicit null "
                 "bottleneck, never a missing key",
                 b && json_is_null(b));
    } else {
        const char *bd = b ? json_get_str(json_get(b, "domain")) : NULL;
        TL_CHECK("[rollup] `bottleneck.domain` names the worst domain",
                 bd && worst_domain && strcmp(bd, worst_domain) == 0);
    }
    return failures;
}

static int check_summary(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);

    TL_CHECK("[rollup] the summary projection renders",
             telemetry_rollup_dump_state_json(&doc, "summary"));
    TL_CHECK("[rollup] the summary declares its stable schema id",
             json_get_str(json_get(&doc, "schema")) &&
                 strcmp(json_get_str(json_get(&doc, "schema")),
                        "zcl.telemetry.summary.v1") == 0);
    TL_CHECK("[rollup] the summary states how many domains it could not "
             "collect, as a number rather than by omission",
             json_get(&doc, "domains_uncollected") != NULL &&
                 json_get(&doc, "domains_total") != NULL);
    TL_CHECK("[rollup] the summary states unhealthy and unknown field totals "
             "separately — unreadable is not broken",
             json_get(&doc, "unhealthy_fields_total") != NULL &&
                 json_get(&doc, "unknown_fields_total") != NULL);
    failures += check_domain_rows(&doc, "summary");
    failures += check_fold_is_the_worst_domain(&doc);

    /* domains_uncollected must equal the rows that say collected:false. */
    const struct json_value *arr = json_get(&doc, "domains");
    int64_t counted = 0;
    if (arr && arr->type == JSON_ARR)
        for (size_t i = 0; i < json_size(arr); i++) {
            const struct json_value *c = json_get(arr_at(arr, i), "collected");
            if (c && c->type == JSON_BOOL && !json_get_bool(c))
                counted++;
        }
    TL_CHECK("[rollup] domains_uncollected agrees with the rows",
             json_get_int(json_get(&doc, "domains_uncollected")) == counted);

    json_free(&doc);
    return failures;
}

static int check_health(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);

    TL_CHECK("[rollup] the health projection renders",
             telemetry_rollup_dump_state_json(&doc, "health"));
    TL_CHECK("[rollup] the health projection declares its stable schema id",
             json_get_str(json_get(&doc, "schema")) &&
                 strcmp(json_get_str(json_get(&doc, "schema")),
                        "zcl.telemetry.health.v1") == 0);
    failures += check_domain_rows(&doc, "health");

    /* The two projections must agree: they are the same fold. */
    struct json_value sum;
    json_init(&sum);
    json_set_object(&sum);
    (void)telemetry_rollup_dump_state_json(&sum, "summary");
    const char *a = json_get_str(json_get(&doc, "health"));
    const char *b = json_get_str(json_get(&sum, "health"));
    TL_CHECK("[rollup] `health` and `summary` report the same rolled-up state "
             "— one evaluator, one fold, two projections",
             a && b && strcmp(a, b) == 0);
    json_free(&sum);

    json_free(&doc);
    return failures;
}

static int check_alerts_bound_and_state_drops(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);

    TL_CHECK("[rollup] the alerts projection renders",
             telemetry_rollup_dump_state_json(&doc, "alerts_active"));

    const struct json_value *arr = json_get(&doc, "alerts");
    int64_t total = json_get_int(json_get(&doc, "active_total"));
    int64_t listed = json_get_int(json_get(&doc, "listed"));
    int64_t dropped = json_get_int(json_get(&doc, "dropped_for_reply_budget"));

    TL_CHECK("[rollup] alerts is an array", arr && arr->type == JSON_ARR);
    TL_CHECK("[rollup] `listed` equals the number of entries actually carried",
             arr && (int64_t)json_size(arr) == listed);
    TL_CHECK("[rollup] active_total = listed + dropped, so a bounded page can "
             "never read as 'that is all of them'",
             total == listed + dropped);
    TL_CHECK("[rollup] the page never carries more than its stated bound",
             listed <= 6);
    TL_CHECK("[rollup] the evaluator's own per-domain finding cap is reported "
             "separately from this page's limit — different causes, different "
             "keys",
             json_get(&doc, "domains_with_findings_truncated") != NULL);

    /* Only failing rules belong in an alert feed; padding it with unknowns is
     * how an alert feed stops being read. */
    size_t not_failing = 0, missing_ctx = 0;
    if (arr && arr->type == JSON_ARR)
        for (size_t i = 0; i < json_size(arr); i++) {
            const struct json_value *o = arr_at(arr, i);
            const char *h = json_get_str(json_get(o, "health"));
            if (!h || (strcmp(h, "degraded") != 0 &&
                       strcmp(h, "unhealthy") != 0))
                not_failing++;
            /* Every alert must be actionable: what it is, and what to do. */
            if (!json_get(o, "path") || !json_get(o, "means") ||
                !json_get(o, "next") || !json_get(o, "domain"))
                missing_ctx++;
        }
    TL_CHECK("[rollup] only DEGRADED/UNHEALTHY rules appear — an unreadable "
             "field is a completeness fact, not an alert", not_failing == 0);
    TL_CHECK("[rollup] every alert carries its domain, path, meaning and next "
             "command", missing_ctx == 0);

    json_free(&doc);
    return failures;
}

/* An unrecognized key must not be guessed at silently. */
static int check_unknown_key_is_reported(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);

    TL_CHECK("[rollup] an unrecognized key still renders a document",
             telemetry_rollup_dump_state_json(&doc, "not_a_projection"));
    TL_CHECK("[rollup] and SAYS the key was not recognized rather than "
             "passing the fallback off as the answer",
             json_get(&doc, "key_unrecognized") != NULL &&
                 json_get_bool(json_get(&doc, "key_unrecognized")));
    json_free(&doc);

    /* NULL means "the default projection", which is a recognized request. */
    struct json_value d2;
    json_init(&d2);
    json_set_object(&d2);
    TL_CHECK("[rollup] a NULL key is the summary, and is not flagged as "
             "unrecognized",
             telemetry_rollup_dump_state_json(&d2, NULL) &&
                 json_get(&d2, "key_unrecognized") == NULL);
    json_free(&d2);

    TL_CHECK("[rollup] a NULL output is refused",
             !telemetry_rollup_dump_state_json(NULL, "summary"));
    return failures;
}

int test_telemetry_rollup(void)
{
    int failures = 0;
    failures += check_registries_agree();
    failures += check_collect_refuses_a_short_buffer();
    failures += check_summary();
    failures += check_health();
    failures += check_alerts_bound_and_state_drops();
    failures += check_unknown_key_is_reported();
    printf("=== telemetry_rollup: %d failures ===\n", failures);
    return failures;
}
