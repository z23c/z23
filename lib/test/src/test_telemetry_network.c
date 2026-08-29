/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_network — the `network` telemetry domain end to end: the
 * field table, the provider that fills it, and the four `ops.telemetry.network`
 * leaves that render it.
 *
 * These are not "does it emit a document" checks. Each one pins a defect that
 * this domain could plausibly ship with and that no other test would catch:
 *
 *   a leaf with no meaning        a TL_LEAF row is self-registering, so a row
 *                                 with an empty `means`, or a JUDGED row with
 *                                 no `implies`/`next`, would render a number an
 *                                 operator cannot act on. Checked per row.
 *
 *   a leaf the provider forgot    TELEMETRY_UNSET == 0, so a field the
 *                                 collector never writes renders as a
 *                                 plausible-looking null with presence "unset".
 *                                 After a real fill NO leaf may be unset — that
 *                                 is the whole point of the presence enum
 *                                 starting there.
 *
 *   unreadable read as broken     a leaf marked UNAVAILABLE must fold to health
 *                                 `unknown`, never `unhealthy`. Getting this
 *                                 wrong sends an operator to a subsystem that
 *                                 is fine.
 *
 *   an empty reply that passes    over-budget serialization returns a ZERO-byte
 *                                 document, and a test that only asserts
 *                                 "non-empty" is satisfied by a 296-byte error
 *                                 envelope. Every leaf below is driven through
 *                                 the real registry serializer and asserted
 *                                 `"ok":true`, with its serialized byte count
 *                                 printed so a budget regression is visible
 *                                 before it becomes an empty reply.
 *
 * DATADIR. The provider opens no file and the render layer performs no I/O, so
 * nothing here should touch a datadir at all — which is exactly why the datadir
 * is pinned to a hermetic tmp dir before the first call. A test that reads the
 * operator's running node and passes for the wrong reason has genuinely
 * happened in this repository; pinning makes that impossible rather than
 * unlikely.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/network_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, matching test_telemetry_render: the
 * checks are numerous and independent, and each is more useful reported on its
 * own line than as a jump out of the function on the first failure. */
#define TN_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

static const struct telemetry_domain_schema *net_schema(void)
{
    return telemetry_domain_find("network");
}

/* ── 1. every leaf carries an actionable meaning row ─────────────────── */

static int check_meaning_rows(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = net_schema();
    TN_CHECK("[network] the domain is registered and non-empty",
             s != NULL && s->leaf_count > 0 && s->group_count > 0);
    if (!s)
        return failures;

    int missing_row = 0, empty_means = 0, judged_without_next = 0;
    int bad_unit = 0, ratio_without_operand = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, lf->path);
        if (!f) { missing_row++; continue; }
        if (!f->means || !f->means[0])
            empty_means++;
        if (f->rule != TFR_INFO &&
            (!f->implies || !f->implies[0] || !f->next || !f->next[0]))
            judged_without_next++;
        /* A bool leaf judged with a numeric rule, or a counter judged as a
         * bool, is a row that can never fire correctly. */
        if (lf->ctype == TLC_BOOL && lf->unit != TFU_BOOL)
            bad_unit++;
        if ((f->rule == TFR_MIN_RATIO_OF || f->rule == TFR_MAX_RATIO_OF) &&
            (!f->operand || !f->operand[0]))
            ratio_without_operand++;
    }
    TN_CHECK("[network] every leaf resolves to a meaning row in the merged "
             "ontology", missing_row == 0);
    TN_CHECK("[network] every leaf states what it counts", empty_means == 0);
    TN_CHECK("[network] every JUDGED leaf states what a bad value implies and "
             "the next command", judged_without_next == 0);
    TN_CHECK("[network] every bool leaf is declared with the bool unit",
             bad_unit == 0);
    TN_CHECK("[network] every ratio rule names its denominator",
             ratio_without_operand == 0);

    /* The four commands are four views of ONE snapshot, so each group the
     * controller filters on has to exist and has to carry at least one
     * summary-tier leaf, or `summary` would render an empty group. */
    static const char *const k_groups[] = { "meta", "peers", "tor",
                                            "transport" };
    int missing_group = 0;
    for (size_t g = 0; g < sizeof k_groups / sizeof k_groups[0]; g++) {
        bool found = false;
        for (size_t i = 0; i < s->group_count; i++)
            if (strcmp(s->groups[i].name, k_groups[g]) == 0)
                found = true;
        if (!found)
            missing_group++;
    }
    TN_CHECK("[network] every group a command filters on exists in the schema",
             missing_group == 0);
    return failures;
}

/* ── 2. a real fill leaves nothing unset ─────────────────────────────── */

static const struct telemetry_leaf_meta *leaf_meta_of(
    const struct telemetry_domain_schema *s, const void *snap, size_t i)
{
    const char *base = (const char *)snap + s->leaves[i].meta_off;
    return (const struct telemetry_leaf_meta *)(const void *)base;
}

static int check_fill_completeness(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = net_schema();
    if (!s)
        return failures;

    struct network_snapshot snap = {0};
    TN_CHECK("[network] the provider accepts a zeroed snapshot",
             network_dump_state_fill(&snap));
    TN_CHECK("[network] the provider refuses a NULL snapshot",
             !network_dump_state_fill(NULL));

    /* THE check. Every leaf must have been written with SOMETHING — a value,
     * an unavailable, or a not_applicable. UNSET means the collector forgot
     * it, and no amount of downstream rendering can recover that. */
    int unset = 0, reasonless = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf_meta *m = leaf_meta_of(s, &snap, i);
        if (m->presence == TELEMETRY_UNSET) {
            printf("  unset leaf: %s\n", s->leaves[i].path);
            unset++;
        } else if (m->presence != TELEMETRY_PRESENT &&
                   (!m->reason || !m->reason[0])) {
            printf("  reasonless leaf: %s\n", s->leaves[i].path);
            reasonless++;
        }
    }
    TN_CHECK("[network] a filled snapshot leaves NO leaf unset", unset == 0);
    TN_CHECK("[network] every non-present leaf carries a static reason token",
             reasonless == 0);
    TN_CHECK("[network] schema-v1 Noise capability alias stays identical",
             snap.v2_offered_by_default == snap.noise_offered_by_default &&
             snap.v2_offered_by_default_meta.presence ==
                 snap.noise_offered_by_default_meta.presence);
    TN_CHECK("[network] schema-v1 Noise peer alias stays identical",
             snap.peers_advertising_v2_now ==
                 snap.peers_advertising_noise_now &&
             snap.peers_advertising_v2_now_meta.presence ==
                 snap.peers_advertising_noise_now_meta.presence);
    TN_CHECK("[network] schema-v1 Noise high-water alias stays identical",
             snap.v2_advertising_high_water ==
                 snap.noise_advertising_high_water &&
             snap.v2_advertising_high_water_meta.presence ==
                 snap.noise_advertising_high_water_meta.presence);

    /* The render layer's own tally must agree, and must not report a provider
     * defect. This is the machine-readable form of the two checks above. */
    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(s, &snap, TLV_FULL, NULL, &doc);
    TN_CHECK("[network] a filled snapshot renders", rendered);
    const struct json_value *c = json_get(&doc, "completeness");
    TN_CHECK("[network] completeness reports zero unset leaves",
             c && json_get_int(json_get(c, "unset")) == 0);
    TN_CHECK("[network] completeness reports no provider defect",
             c && json_get_bool(json_get(c, "provider_defect")) == false);
    TN_CHECK("[network] completeness accounts for every leaf",
             c && json_get_int(json_get(c, "leaves_total")) ==
                     (int64_t)s->leaf_count);

    /* Two leaves answer in ANY process because they are compile-time facts,
     * not live reads. If both went unavailable the reply would be vacuous
     * wherever it is run, which is the outcome this domain must not have. */
    const struct json_value *floor =
        json_get(json_get(json_get(&doc, "values"), "peers"),
                 "outbound_floor_target");
    TN_CHECK("[network] the compiled outbound floor answers in any process",
             floor && floor->type == JSON_INT && json_get_int(floor) > 0);
    const struct json_value *build =
        json_get(json_get(json_get(&doc, "values"), "tor"), "tor_build");
    const char *build_s = build ? json_get_str(build) : NULL;
    TN_CHECK("[network] which Tor this binary linked answers in any process",
             build_s && (strcmp(build_s, "real_tor") == 0 ||
                         strcmp(build_s, "tor_stub") == 0));
    json_free(&doc);
    return failures;
}

/* ── 3. unreadable is unknown, never unhealthy ───────────────────────── */

/* Find a leaf whose rule actually judges, so the check exercises the
 * verdict path rather than a descriptive row that could never be unhealthy. */
static const struct telemetry_leaf *first_judged_leaf(
    const struct telemetry_domain_schema *s)
{
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, s->leaves[i].path);
        if (f && f->rule != TFR_INFO)
            return &s->leaves[i];
    }
    return NULL;
}

static int check_unavailable_is_unknown(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = net_schema();
    if (!s)
        return failures;
    const struct telemetry_leaf *judged = first_judged_leaf(s);
    TN_CHECK("[network] the domain carries at least one judged leaf",
             judged != NULL);
    if (!judged)
        return failures;

    /* A snapshot that is healthy everywhere EXCEPT one deliberately
     * unreadable leaf. Building it by hand rather than by running the
     * collector is the point: the collector's own result depends on whether a
     * node happens to be in this process, and this check must not. */
    struct network_snapshot snap = {0};
    (void)network_dump_state_fill(&snap);
    TELEMETRY_SET_I64(&snap, outbound_healthy, 8, TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(&snap, outbound_floor_satisfied, true,
                       TELEMETRY_SRC_DERIVED);
    TELEMETRY_SET_I64(&snap, healthy_group_count, 4,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, dial_attempts_total, 100,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, handshakes_completed_total, 90,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, pre_handshake_disconnects_total, 1,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, dial_timeouts_total, 1,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&snap, rejected_total, 0, TELEMETRY_SRC_IN_PROCESS);

    struct telemetry_domain_verdict healthy;
    TN_CHECK("[network] a fully-readable healthy snapshot evaluates",
             telemetry_evaluate(s, &snap, &healthy));
    TN_CHECK("[network] a fully-readable healthy snapshot is not unhealthy",
             healthy.state != TELEMETRY_HEALTH_UNHEALTHY &&
             healthy.state != TELEMETRY_HEALTH_DEGRADED);

    /* Now break exactly one thing: make a JUDGED leaf unreadable. */
    TELEMETRY_UNAVAILABLE_LEAF(&snap, outbound_healthy, "unit_test_forced");
    struct telemetry_domain_verdict blind;
    TN_CHECK("[network] the same snapshot with one unreadable leaf evaluates",
             telemetry_evaluate(s, &snap, &blind));
    TN_CHECK("[network] an unreadable JUDGED leaf raises unknown",
             blind.unknown_count > healthy.unknown_count);
    TN_CHECK("[network] an unreadable leaf is NOT reported as unhealthy",
             blind.state == TELEMETRY_HEALTH_UNKNOWN &&
             blind.unhealthy_count == healthy.unhealthy_count);

    /* And the opposite direction: a leaf that IS readable and IS wrong must
     * still be reported, so the check above cannot be satisfied by a
     * evaluator that never says unhealthy at all. */
    TELEMETRY_SET_I64(&snap, outbound_healthy, 0, TELEMETRY_SRC_IN_PROCESS);
    struct telemetry_domain_verdict broken;
    TN_CHECK("[network] a readable, out-of-range leaf still evaluates",
             telemetry_evaluate(s, &snap, &broken));
    TN_CHECK("[network] a readable peerless node IS reported unhealthy",
             broken.state == TELEMETRY_HEALTH_UNHEALTHY &&
             broken.unhealthy_count > 0);
    return failures;
}

/* ── 4. each command returns ok:true, and fits its budget ────────────── */

static const struct zcl_command_spec *find_leaf(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static int check_one_command(const struct zcl_command_registry *reg,
                             const char *path, const char *want_group)
{
    int failures = 0;
    char label[160];
    const struct zcl_command_spec *spec = find_leaf(reg, path);
    (void)snprintf(label, sizeof label, "[network] %s is READY with a handler",
                   path);
    TN_CHECK(label, spec != NULL &&
                    spec->availability == ZCL_COMMAND_READY &&
                    spec->handler != NULL);
    if (!spec || !spec->handler)
        return failures;

    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    static char out[64 * 1024];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal",
                                                 0, 0, NULL,
                                                 out, sizeof out, &exit_code);
    json_free(&input);

    /* Over-budget serialization writes a ZERO-length document, so a non-empty
     * reply is the first thing to establish — but it is nowhere near enough:
     * a 296-byte error envelope is also non-empty. */
    (void)snprintf(label, sizeof label,
                   "[network] %s serializes a non-empty reply (%zu bytes of "
                   "%d budget)", path, n, spec->budget_bytes);
    TN_CHECK(label, n > 0);
    if (n == 0)
        return failures;

    struct json_value env;
    json_init(&env);
    bool parsed = json_read(&env, out, n);
    (void)snprintf(label, sizeof label, "[network] %s returns parseable JSON",
                   path);
    TN_CHECK(label, parsed && env.type == JSON_OBJ);

    /* THE assertion. `ok` is the envelope's own verdict; asserting only
     * "non-empty" is what let a previous lane's test pass on a build whose
     * every reply was the total-loss error envelope. */
    (void)snprintf(label, sizeof label, "[network] %s returns ok:true", path);
    TN_CHECK(label, json_get_bool(json_get(&env, "ok")) == true);
    (void)snprintf(label, sizeof label, "[network] %s exits 0", path);
    TN_CHECK(label, exit_code == ZCL_COMMAND_EXIT_OK);

    const struct json_value *data = json_get(&env, "data");
    (void)snprintf(label, sizeof label,
                   "[network] %s carries the telemetry document", path);
    TN_CHECK(label, data && json_get(data, "values") &&
                    json_get(data, "health") &&
                    json_get(data, "completeness") &&
                    json_get(data, "leaves"));

    (void)snprintf(label, sizeof label,
                   "[network] %s names the network schema", path);
    const char *schema = data ? json_get_str(json_get(data, "schema")) : NULL;
    TN_CHECK(label, schema && strcmp(schema, "zcl.telemetry.network.v1") == 0);

    if (want_group) {
        (void)snprintf(label, sizeof label,
                       "[network] %s renders the %s group and only that group",
                       path, want_group);
        const struct json_value *vals = data ? json_get(data, "values") : NULL;
        TN_CHECK(label, vals && json_size(vals) == 1 &&
                        json_get(vals, want_group) != NULL);
        (void)snprintf(label, sizeof label,
                       "[network] %s reports its group filter matched", path);
        TN_CHECK(label,
                 data && json_get_bool(json_get(data, "group_filter_matched")));
    }

    /* Trap: a next[] entry naming the command being served makes the whole
     * reply a total loss, and the CLI misreports it as a budget overflow. The
     * ok:true assertion above already catches it; this names it so a failure
     * points straight at the cause instead of at the byte count. */
    const struct json_value *next = json_get(&env, "next");
    int self_ref = 0;
    for (size_t i = 0; next && i < json_size(next); i++) {
        const char *cmd = json_get_str(json_get(json_at(next, i), "command"));
        if (cmd && strcmp(cmd, path) == 0)
            self_ref++;
    }
    (void)snprintf(label, sizeof label,
                   "[network] %s never points next[] at itself", path);
    TN_CHECK(label, self_ref == 0);
    json_free(&env);
    return failures;
}

static int check_commands(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TN_CHECK("[network] the command catalog is available", reg != NULL);
    if (!reg)
        return failures;
    failures += check_one_command(reg, "ops.telemetry.network.summary", NULL);
    failures += check_one_command(reg, "ops.telemetry.network.peers", "peers");
    failures += check_one_command(reg, "ops.telemetry.network.tor", "tor");
    failures += check_one_command(reg, "ops.telemetry.network.transport",
                                  "transport");
    return failures;
}

int test_telemetry_network(void)
{
    printf("\n=== network telemetry domain tests ===\n");
    int failures = 0;

    /* Nothing below should touch a datadir. Pinning one guarantees that a
     * future change which starts to cannot silently read the operator's live
     * node and pass for the wrong reason. */
    char tmpdir[256];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "telemetry_network", "datadir");
    SetDataDir(tmpdir);

    failures += check_meaning_rows();
    failures += check_fill_completeness();
    failures += check_unavailable_is_unknown();
    failures += check_commands();

    SetDataDir("");
    ClearDataDirCache();
    printf("network telemetry: %d failure(s)\n", failures);
    return failures;
}
