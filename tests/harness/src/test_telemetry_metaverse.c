/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_metaverse — the `metaverse` telemetry domain end to end: the
 * field table, the provider (contexts/commons/services/src/metaverse_telemetry_fill.c), and
 * the two command outcomes the branch is allowed to have.
 *
 * What each check exists to stop, in the order they run:
 *
 *   MEANING IS NOT OPTIONAL. Every TL_LEAF row must resolve to an ontology row
 *   carrying `means`, and every JUDGED row must also carry `implies` and
 *   `next`. A number with a rule but no next step sends an operator nowhere.
 *
 *   NO LEAF IS UNSET AFTER A FILL. TELEMETRY_UNSET is zero, so a field the
 *   provider forgot renders as a counted provider defect. This asserts the
 *   provider forgot none — including the eight per-kind reader flags, which
 *   are the rows most likely to be missed when a kind is added.
 *
 *   UNREADABLE IS UNKNOWN, NOT BROKEN. A leaf marked UNAVAILABLE must be
 *   judged `unknown` and must not push the domain to `unhealthy`. Confusing
 *   "we could not read it" with "we read it and it is wrong" is the defect the
 *   whole presence enum exists to remove.
 *
 *   READY MEANS ok:true, AND IT FITS. `ops.telemetry.metaverse.properties` is
 *   dispatched through the real registry and must come back ok:true inside its
 *   contract budget. Asserting only "the reply is non-empty" is not enough: an
 *   over-budget reply is an EMPTY document reported as RESPONSE_BUDGET_EXCEEDED
 *   and an error envelope is non-empty too. The observed byte count is printed
 *   so the headroom is a measurement, not a hope.
 *
 *   PLANNED MEANS PLANNED. `market` and `services` must still fail closed with
 *   COMMAND_PLANNED and exit 3, and must state a reason. This domain's honesty
 *   is the point of it: `market` has no backing subsystem at all, and the
 *   broker keeps its state in an operator-named directory, so neither can be
 *   answered here. A future lane that wires one of them to an empty object
 *   breaks this test, which is exactly what should happen.
 *
 * DATADIR: this domain is node-free by construction — the provider reads only
 * compiled-in tables. GetDataDir() is nonetheless pinned to a hermetic tmp dir
 * for the whole run, because a command dispatched through the registry must
 * never be able to reach the operator's live node by default, and a test that
 * relies on the handler being well behaved cannot prove that it is.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "metaverse/property_id.h"
#include "services/metaverse_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_render:
 * TEST/ASSERT mint a per-function `_test_next` label, and these checks are
 * numerous, independent, and more useful reported one at a time. */
#define TM_CHECK(name, cond)                                                  \
    do {                                                                      \
        printf("%s... ", (name));                                             \
        if (cond) { printf("OK\n"); }                                         \
        else { printf("FAIL (%s)\n", #cond); failures++; }                    \
    } while (0)

static const struct json_value *dig2(const struct json_value *o,
                                     const char *a, const char *b)
{
    return json_get(json_get(o, a), b);
}

static const struct json_value *dig3(const struct json_value *o,
                                     const char *a, const char *b,
                                     const char *c)
{
    return json_get(dig2(o, a, b), c);
}

/* ── 1. every leaf carries meaning ───────────────────────────────────── */

static int check_every_leaf_has_meaning(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("metaverse");
    TM_CHECK("[metaverse] the domain is registered", s != NULL);
    if (!s)
        return failures;

    /* Shrink guard: the field table has a meta group plus the catalog group,
     * and one reader flag per property kind. A table that lost its rows would
     * otherwise pass every loop below vacuously. */
    TM_CHECK("[metaverse] the field table still carries its rows",
             s->leaf_count >= (size_t)METAVERSE_KIND_COUNT + 4u);

    size_t no_row = 0, no_means = 0, hollow_judged = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, lf->path);
        if (!f) { no_row++; continue; }
        if (!f->means || !f->means[0])
            no_means++;
        if (f->rule != TFR_INFO &&
            (!f->implies || !f->implies[0] || !f->next || !f->next[0]))
            hollow_judged++;
    }
    TM_CHECK("[metaverse] every leaf resolves to an ontology meaning row",
             no_row == 0);
    TM_CHECK("[metaverse] every leaf states what it means", no_means == 0);
    TM_CHECK("[metaverse] every JUDGED leaf states what an unhealthy value "
             "implies and the exact next step", hollow_judged == 0);
    return failures;
}

/* ── 2. a filled snapshot leaves nothing unset ───────────────────────── */

static int check_fill_leaves_nothing_unset(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("metaverse");
    if (!s)
        return failures;

    struct metaverse_snapshot snap = {0};
    TM_CHECK("[metaverse] the provider fills its snapshot",
             metaverse_dump_state_fill(&snap));

    struct json_value out;
    json_init(&out);
    TM_CHECK("[metaverse] the filled snapshot renders",
             telemetry_render(s, &snap, TLV_FULL, NULL, &out));

    TM_CHECK("[metaverse] no leaf is UNSET after a fill — a forgotten field "
             "would be a counted provider defect, never a plausible zero",
             json_get_int(dig2(&out, "completeness", "unset")) == 0);
    TM_CHECK("[metaverse] the provider reports no defect",
             !json_get_bool(dig2(&out, "completeness", "provider_defect")));
    TM_CHECK("[metaverse] every leaf is present on a healthy host",
             json_get_int(dig2(&out, "completeness", "present")) ==
                 (int64_t)s->leaf_count);
    TM_CHECK("[metaverse] the document is complete",
             json_get_bool(dig2(&out, "completeness", "complete")));

    /* The values themselves, against the registry the provider read. The point
     * is not the literal 8: it is that the counts partition the vocabulary, so
     * a kind can neither be double-counted nor vanish. */
    int64_t declared = json_get_int(dig3(&out, "values", "catalog",
                                         "kinds_declared"));
    int64_t readable = json_get_int(dig3(&out, "values", "catalog",
                                         "kinds_readable"));
    int64_t unreadable = json_get_int(dig3(&out, "values", "catalog",
                                           "kinds_unreadable"));
    TM_CHECK("[metaverse] kinds_declared is the vocabulary minus the reserved "
             "UNKNOWN zero", declared == (int64_t)METAVERSE_KIND_COUNT - 1);
    TM_CHECK("[metaverse] readable + unreadable accounts for every declared "
             "kind — a kind can neither be counted twice nor disappear",
             readable + unreadable == declared);
    TM_CHECK("[metaverse] at least one kind can actually be projected",
             readable >= 1);
    TM_CHECK("[metaverse] every declared kind resolves to a row keyed to "
             "itself", json_get_bool(dig3(&out, "values", "catalog",
                                          "registry_complete")));
    TM_CHECK("[metaverse] the content kind's reader flag agrees with the "
             "registry",
             json_get_bool(dig3(&out, "values", "catalog", "reader_content")));
    TM_CHECK("[metaverse] the ZNAM reader flag tracks its newly wired "
             "canonical-model adapter",
             dig3(&out, "values", "catalog", "reader_znam_name") != NULL &&
                 json_get_bool(dig3(&out, "values", "catalog",
                                    "reader_znam_name")));
    TM_CHECK("[metaverse] the ZSLP reader flag tracks its canonical-model "
             "adapter",
             dig3(&out, "values", "catalog", "reader_zslp_asset") != NULL &&
                 json_get_bool(dig3(&out, "values", "catalog",
                                    "reader_zslp_asset")));
    TM_CHECK("[metaverse] a domain whose leaves all read cleanly is ok",
             json_get_str(dig2(&out, "health", "state")) &&
                 strcmp(json_get_str(dig2(&out, "health", "state")), "ok") == 0);
    json_free(&out);
    return failures;
}

/* ── 3. unreadable is unknown, never unhealthy ───────────────────────── */

static int check_unavailable_is_unknown_not_unhealthy(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("metaverse");
    if (!s)
        return failures;

    /* registry_complete is the domain's one CRITICAL rule (TFR_EXPECT_TRUE).
     * Marking it unavailable is therefore the sharpest possible version of the
     * question: a leaf we could not read must not fire the critical rule. */
    struct metaverse_snapshot snap = {0};
    (void)metaverse_dump_state_fill(&snap);
    TELEMETRY_UNAVAILABLE_LEAF(&snap, registry_complete, "test_forced_gap");

    struct json_value out;
    json_init(&out);
    TM_CHECK("[metaverse] a snapshot with a forced gap still renders",
             telemetry_render(s, &snap, TLV_FULL, NULL, &out));

    const char *state = json_get_str(dig2(&out, "health", "state"));
    TM_CHECK("[metaverse] an unreadable CRITICAL leaf is judged unknown, not "
             "unhealthy", state && strcmp(state, "unknown") == 0);
    TM_CHECK("[metaverse] the unknown is counted",
             json_get_int(dig2(&out, "health", "unknown_count")) >= 1);
    TM_CHECK("[metaverse] no rule is reported as failing",
             json_get_int(dig2(&out, "health", "unhealthy_count")) == 0);

    const struct json_value *leaf =
        dig2(&out, "leaves", "values.catalog.registry_complete");
    const char *presence = json_get_str(json_get(leaf, "presence"));
    const char *reason = json_get_str(json_get(leaf, "reason"));
    TM_CHECK("[metaverse] the leaf says it is unavailable",
             presence && strcmp(presence, "unavailable") == 0);
    TM_CHECK("[metaverse] and carries a static reason token, so the gap is "
             "greppable rather than mysterious",
             reason && strcmp(reason, "test_forced_gap") == 0);
    TM_CHECK("[metaverse] completeness counts the gap",
             json_get_int(dig2(&out, "completeness", "unavailable")) == 1 &&
                 !json_get_bool(dig2(&out, "completeness", "complete")));
    json_free(&out);
    return failures;
}

/* ── 4/5. the two command outcomes ───────────────────────────────────── */

static const struct zcl_command_spec *find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static size_t exec_leaf(const struct zcl_command_registry *reg,
                        const struct zcl_command_spec *spec, const char *view,
                        char *out, size_t out_size,
                        enum zcl_command_exit *exit_code)
{
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
                                                 spec->path, view, 0, 0, NULL,
                                                 out, out_size, exit_code);
    json_free(&input);
    return n;
}

static int check_ready_leaf_answers(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s =
        find_spec(reg, "ops.telemetry.metaverse.properties");
    TM_CHECK("[metaverse] the properties leaf is registered", s != NULL);
    if (!s)
        return failures;
    TM_CHECK("[metaverse] it is READY", s->availability == ZCL_COMMAND_READY);
    TM_CHECK("[metaverse] it is bound to its handler",
             s->handler == zcl_native_handle_telemetry_metaverse_properties);
    TM_CHECK("[metaverse] it declares no input key, so it can never be "
             "pointed at a datadir", s->input_keys && s->input_keys[0] == '\0');

    static const char *const k_views[] = { "summary", "normal", "full" };
    size_t budget = s->budget_bytes ? (size_t)s->budget_bytes
                                    : (size_t)ZCL_COMMAND_RESULT_BUDGET;
    for (size_t v = 0; v < sizeof k_views / sizeof k_views[0]; v++) {
        static char out[ZCL_COMMAND_LIST_BUDGET * 4];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = exec_leaf(reg, s, k_views[v], out, sizeof out, &code);
        printf("  [metaverse] view=%s reply=%zu bytes (budget %zu)\n",
               k_views[v], n, budget);
        /* An over-budget reply is EMPTY, not truncated, so a zero length here
         * is the budget failure — assert the length AND the envelope. */
        TM_CHECK("[metaverse] the reply fits its contract budget", n > 0);
        TM_CHECK("[metaverse] the reply fits with headroom", n <= budget);
        TM_CHECK("[metaverse] exit is OK", code == ZCL_COMMAND_EXIT_OK);
        /* ok:true, not merely non-empty: an error envelope is non-empty too. */
        TM_CHECK("[metaverse] the envelope reports ok:true",
                 n > 0 && strstr(out, "\"ok\":true") != NULL);
        TM_CHECK("[metaverse] and carries the domain's schema id",
                 n > 0 && strstr(out, "zcl.telemetry.metaverse.v1") != NULL);
        TM_CHECK("[metaverse] the summary tier still carries the headline "
                 "counts", n > 0 && strstr(out, "kinds_readable") != NULL);
    }
    return failures;
}

static int check_planned_leaves_still_refuse(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static const char *const k_planned[] = {
        "ops.telemetry.metaverse.market",
        "ops.telemetry.metaverse.services",
    };
    for (size_t i = 0; i < sizeof k_planned / sizeof k_planned[0]; i++) {
        const struct zcl_command_spec *s = find_spec(reg, k_planned[i]);
        TM_CHECK("[metaverse] the planned leaf is registered", s != NULL);
        if (!s)
            continue;
        TM_CHECK("[metaverse] it is PLANNED, not quietly READY",
                 s->availability == ZCL_COMMAND_PLANNED);
        TM_CHECK("[metaverse] it names what is missing",
                 s->availability_reason && s->availability_reason[0]);
        TM_CHECK("[metaverse] no handler is bound to it", s->handler == NULL);

        static char out[ZCL_COMMAND_LIST_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        size_t n = exec_leaf(reg, s, "normal", out, sizeof out, &code);
        TM_CHECK("[metaverse] it answers rather than vanishing", n > 0);
        TM_CHECK("[metaverse] it fails closed with exit 3",
                 code == ZCL_COMMAND_EXIT_BLOCKED && (int)code == 3);
        TM_CHECK("[metaverse] the error code is COMMAND_PLANNED",
                 n > 0 && strstr(out, "COMMAND_PLANNED") != NULL);
        TM_CHECK("[metaverse] the refusal is not dressed up as a success",
                 n > 0 && strstr(out, "\"ok\":false") != NULL);
    }

    /* The specific reason `market` is declared and refused: nothing backs it.
     * This wording is a decision, not an accident — a later lane that wires it
     * to an empty object to make the branch look whole must trip here. */
    const struct zcl_command_spec *m =
        find_spec(reg, "ops.telemetry.metaverse.market");
    TM_CHECK("[metaverse] market still says no market subsystem exists",
             m && m->availability_reason &&
                 strstr(m->availability_reason, "no property market subsystem "
                        "exists in this build") != NULL);
    return failures;
}

int test_telemetry_metaverse(void)
{
    printf("\n=== telemetry_metaverse ===\n");
    /* Hermetic datadir for the whole run. Nothing here should reach a datadir
     * at all; pinning it is what proves that rather than assuming it. */
    char dd[256];
    test_make_tmpdir(dd, sizeof dd, "telemetry_metaverse", "datadir");
    SetDataDir(dd);

    int failures = 0;
    failures += check_every_leaf_has_meaning();
    failures += check_fill_leaves_nothing_unset();
    failures += check_unavailable_is_unknown_not_unhealthy();
    failures += check_ready_leaf_answers();
    failures += check_planned_leaves_still_refuse();

    SetDataDir("");
    ClearDataDirCache();
    printf("=== telemetry_metaverse: %d failures ===\n", failures);
    return failures;
}
