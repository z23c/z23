/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_runtime — the `runtime` telemetry domain: its field table,
 * its collector, and the three leaves over it.
 *
 * What each check is FOR, because "the command returned something" is not a
 * property worth a test:
 *
 *   every leaf carries meaning     a field with no ontology row renders with no
 *                                  healthy range, no implication and no next
 *                                  step, and the render layer silently judges
 *                                  it unknown forever.
 *   the collector forgets nothing  TELEMETRY_UNSET is a provider defect, not a
 *                                  value. A filled snapshot with even one unset
 *                                  leaf means the collector skipped a field,
 *                                  and this is the check that names which.
 *   unreadable is not broken       a leaf the node could not report must render
 *                                  UNKNOWN. Reporting it UNHEALTHY sends an
 *                                  operator to a subsystem that is fine.
 *   the aggregates are arithmetic  ticks_run is activity and progress_marker is
 *                                  results; the fixture below contains a child
 *                                  that ran twenty times and produced nothing,
 *                                  and the count has to find exactly it.
 *   ok:true, not just non-empty    an over-budget reply comes back as a ~300
 *                                  byte error envelope, which satisfies
 *                                  "non-empty" and satisfies nothing else.
 *
 * The node is faked at the RPC seam (node_rpc_client_set_test_hook), so no
 * check here contacts a running node and none of them can pass because the
 * owner's node happened to be up. SetDataDir still points at an isolated temp
 * directory: the CLI's RPC-client init resolves a cookie path under the
 * datadir, and a test must never resolve that to the live one.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/runtime_telemetry.h"
#include "util/safe_alloc.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_render:
 * these checks are numerous and independent, and are more useful reported
 * individually than collapsed behind one TEST label. */
#define RT_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* ── the faked node ──────────────────────────────────────────────────────
 * Four dumpstate subsystems, returned verbatim. The supervisor fixture is
 * shaped to exercise every aggregate at once:
 *
 *   chain.a   ticked, progressed            -> not counted as "no results"
 *   chain.b   ticked 20x, marker 0, idle 0  -> IS counted; oldest live tick
 *   net.c     ticked 5x, all of them idle   -> legitimately quiet, not counted
 *   old.d     completed, ancient heartbeat  -> excluded from the worst age
 *
 * so worst_tick_age_us must be chain.b's 9000 and not old.d's 99999999. */

static const char k_sup_state[] =
    "\"running\":true,\"thread_alive\":true,\"tick_ms\":1000,"
    "\"sweep_heartbeat\":10,\"sweep_last_age_us\":1000,"
    "\"tick_runner_running\":true,\"tick_runner_last_hb_age_us\":900,"
    "\"tick_runner_stall_fires\":0,\"progress_undeclared_count\":3,"
    "\"child_headroom\":60,\"child_count\":4,"
    "\"domains\":[{\"name\":\"chain\",\"child_count\":2,\"children\":["
    "{\"name\":\"chain.a\",\"last_tick_age_us\":500,\"progress_marker\":7,"
    "\"completed\":false,\"stall_reason\":\"none\",\"ticks_run\":10,"
    "\"idle_ticks\":0,\"stall_fires\":0},"
    "{\"name\":\"chain.b\",\"last_tick_age_us\":9000,\"progress_marker\":0,"
    "\"completed\":false,\"stall_reason\":\"none\",\"ticks_run\":20,"
    "\"idle_ticks\":0,\"stall_fires\":2}]}],"
    "\"root_orphans\":["
    "{\"name\":\"net.c\",\"last_tick_age_us\":100,\"progress_marker\":0,"
    "\"completed\":false,\"stall_reason\":\"none\",\"ticks_run\":5,"
    "\"idle_ticks\":5,\"stall_fires\":0},"
    "{\"name\":\"old.d\",\"last_tick_age_us\":99999999,\"progress_marker\":3,"
    "\"completed\":true,\"stall_reason\":\"none\",\"ticks_run\":1,"
    "\"idle_ticks\":0,\"stall_fires\":0}]";

static const char k_topo_state[] =
    "\"source\":\"sysfs\",\"logical_cpus\":32,\"physical_cores\":16,"
    "\"l3_domains\":2";

static const char k_mem_state_full[] =
    "\"level\":\"nominal\",\"current_bytes\":1000,"
    "\"denominator_bytes\":10000,\"denominator_basis\":\"cgroup_high\","
    "\"rss_bytes\":900,\"last_poll_unix\":1700000000,"
    "\"polling_active\":true";

/* Same dump with `polling_active` gone: one JUDGED bool the node did not
 * report. This is the unreadable-is-not-broken fixture. */
static const char k_mem_state_gap[] =
    "\"level\":\"nominal\",\"current_bytes\":1000,"
    "\"denominator_bytes\":10000,\"denominator_basis\":\"cgroup_high\","
    "\"rss_bytes\":900,\"last_poll_unix\":1700000000";

/* The state BOTH organs are in before they have measured anything. Unlike
 * current_bytes / denominator_bytes / rss_bytes, which the memory organ
 * initialises to -1, `last_poll_unix` starts at 0 and hw_profile's `ram_bytes`
 * is 0 when the probe fails or has not run — so the "never measured" spelling
 * here is a plausible number (1970-01-01, and a machine with no RAM) rather
 * than an obvious sentinel. That is precisely the shape this whole layer exists
 * to refuse to publish. */
static const char k_mem_state_prepoll[] =
    "\"level\":\"nominal\",\"current_bytes\":-1,"
    "\"denominator_bytes\":-1,\"denominator_basis\":\"system_ram\","
    "\"rss_bytes\":-1,\"last_poll_unix\":0,"
    "\"polling_active\":true";

static const char k_hw_state[] =
    "\"ram_bytes\":68719476736,\"ram_class\":\"high\"";

static const char k_hw_state_unprobed[] =
    "\"ram_bytes\":0,\"ram_class\":\"unknown\"";

enum rt_mode {
    RT_MODE_FULL = 0,   /* every subsystem answers completely */
    RT_MODE_MEM_GAP,    /* mem_pressure answers, minus one judged field */
    RT_MODE_PREPOLL,    /* both organs answer, having measured nothing yet */
    RT_MODE_DEAD,       /* nothing answers at all */
};
static enum rt_mode g_mode = RT_MODE_FULL;

static char *rt_reply(const char *subsystem, const char *state)
{
    char buf[4096];
    int n = snprintf(buf, sizeof buf,
                     "{\"subsystem\":\"%s\",\"description\":\"fixture\","
                     "\"captured_at\":1700000001,\"state\":{%s}}",
                     subsystem, state);
    if (n < 0 || (size_t)n >= sizeof buf)
        return NULL;
    char *out = zcl_malloc((size_t)n + 1, "test_telemetry_runtime_reply");
    if (!out)
        return NULL;
    memcpy(out, buf, (size_t)n + 1);
    return out;
}

static char *rt_hook(const char *method, const char *params_json)
{
    if (!method || strcmp(method, "dumpstate") != 0 || !params_json)
        return NULL;
    if (g_mode == RT_MODE_DEAD)
        return NULL;
    if (strstr(params_json, "supervisor"))
        return rt_reply("supervisor", k_sup_state);
    if (strstr(params_json, "cpu_topology"))
        return rt_reply("cpu_topology", k_topo_state);
    if (strstr(params_json, "mem_pressure")) {
        const char *st = k_mem_state_full;
        if (g_mode == RT_MODE_MEM_GAP)
            st = k_mem_state_gap;
        else if (g_mode == RT_MODE_PREPOLL)
            st = k_mem_state_prepoll;
        return rt_reply("mem_pressure", st);
    }
    if (strstr(params_json, "hw_profile"))
        return rt_reply("hw_profile", g_mode == RT_MODE_PREPOLL
                                          ? k_hw_state_unprobed
                                          : k_hw_state);
    return NULL;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static const struct telemetry_leaf_meta *rt_meta(
    const struct runtime_snapshot *s, const struct telemetry_leaf *lf)
{
    const char *base = (const char *)s + lf->meta_off;
    return (const struct telemetry_leaf_meta *)(const void *)base;
}

static const struct telemetry_leaf *rt_find_leaf(const char *key)
{
    for (size_t i = 0; i < g_runtime_schema.leaf_count; i++)
        if (strcmp(g_runtime_schema.leaves[i].key, key) == 0)
            return &g_runtime_schema.leaves[i];
    return NULL;
}

static int64_t rt_value(const struct json_value *doc, const char *group,
                        const char *key)
{
    return json_get_int(json_get(json_get(json_get(doc, "values"), group),
                                 key));
}

/* ── 1. every leaf carries meaning ───────────────────────────────────── */

static int check_every_leaf_has_meaning(void)
{
    int failures = 0;
    size_t no_row = 0, no_means = 0, hollow_judged = 0;
    for (size_t i = 0; i < g_runtime_schema.leaf_count; i++) {
        const struct telemetry_leaf *lf = &g_runtime_schema.leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup("runtime", lf->path);
        if (!f) {
            printf("  [runtime] no ontology row for %s\n", lf->path);
            no_row++;
            continue;
        }
        if (!f->means || !f->means[0]) {
            printf("  [runtime] empty means on %s\n", lf->path);
            no_means++;
        }
        /* A row that carries a VERDICT owes the reader what the verdict
         * implies and where to look next. TFR_INFO rows carry neither by
         * design — they state a fact and judge nothing. */
        if (f->rule != TFR_INFO &&
            (!f->implies || !f->implies[0] || !f->next || !f->next[0])) {
            printf("  [runtime] judged row with no implies/next: %s\n",
                   lf->path);
            hollow_judged++;
        }
    }
    RT_CHECK("[runtime] the domain declares leaves at all",
             g_runtime_schema.leaf_count >= 20);
    RT_CHECK("[runtime] every leaf resolves to an ontology row", no_row == 0);
    RT_CHECK("[runtime] every leaf says what it counts", no_means == 0);
    RT_CHECK("[runtime] every judged leaf says what it implies and what to "
             "read next", hollow_judged == 0);
    return failures;
}

/* ── 2. the collector leaves nothing unset ───────────────────────────── */

static int check_collector_fills_every_leaf(void)
{
    int failures = 0;
    g_mode = RT_MODE_FULL;

    struct runtime_snapshot snap = {0};
    const char *why = "unwritten";
    bool filled = runtime_dump_state_fill(&snap, &why);
    RT_CHECK("[runtime] the collector reports success against a live node",
             filled);
    RT_CHECK("[runtime] a successful fill names no failure reason",
             why && why[0] == '\0');

    size_t unset = 0, missing_reason = 0;
    for (size_t i = 0; i < g_runtime_schema.leaf_count; i++) {
        const struct telemetry_leaf *lf = &g_runtime_schema.leaves[i];
        const struct telemetry_leaf_meta *m = rt_meta(&snap, lf);
        if (m->presence == TELEMETRY_UNSET) {
            printf("  [runtime] collector never wrote %s\n", lf->path);
            unset++;
        } else if (m->presence != TELEMETRY_PRESENT &&
                   (!m->reason || !m->reason[0])) {
            printf("  [runtime] non-present leaf with no reason: %s\n",
                   lf->path);
            missing_reason++;
        }
    }
    RT_CHECK("[runtime] a filled snapshot leaves NO leaf unset — an unset leaf "
             "is a field the collector forgot", unset == 0);
    RT_CHECK("[runtime] every non-present leaf carries a static reason token",
             missing_reason == 0);

    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(&g_runtime_schema, &snap, TLV_FULL, NULL,
                                     &doc);
    RT_CHECK("[runtime] the filled snapshot renders", rendered);
    if (rendered) {
        const struct json_value *c = json_get(&doc, "completeness");
        RT_CHECK("[runtime] completeness reports zero unset",
                 json_get_int(json_get(c, "unset")) == 0);
        RT_CHECK("[runtime] completeness reports no provider defect",
                 !json_get_bool(json_get(c, "provider_defect")));
        RT_CHECK("[runtime] the whole domain reads as complete",
                 json_get_bool(json_get(c, "complete")));

        /* The aggregates, computed over the fixture above. */
        RT_CHECK("[runtime] ticks_run_total sums ACTIVITY over every child",
                 rt_value(&doc, "services", "ticks_run_total") == 36);
        RT_CHECK("[runtime] idle_ticks_total counts only the ran-and-had-"
                 "nothing-to-do ticks",
                 rt_value(&doc, "services", "idle_ticks_total") == 5);
        RT_CHECK("[runtime] children_no_results finds the child that ran and "
                 "produced nothing, and not the one that was idle by design",
                 rt_value(&doc, "services", "children_no_results") == 1);
        RT_CHECK("[runtime] stall_fires_total is cumulative across children",
                 rt_value(&doc, "services", "stall_fires_total") == 2);
        RT_CHECK("[runtime] children_stalled is the LIVE stall count, not the "
                 "historical fire count",
                 rt_value(&doc, "services", "children_stalled") == 0);
        RT_CHECK("[runtime] the worst tick age skips a COMPLETED child, whose "
                 "heartbeat is allowed to be ancient",
                 rt_value(&doc, "services", "worst_tick_age_us") == 9000);
        RT_CHECK("[runtime] the worst tick age names the child it belongs to",
                 json_get_str(json_get(json_get(json_get(&doc, "values"),
                                                "services"),
                                       "worst_tick_child")) &&
                 strcmp(json_get_str(json_get(json_get(json_get(&doc,
                                                                "values"),
                                                       "services"),
                                              "worst_tick_child")),
                        "chain.b") == 0);

        /* Nothing in the fixture breaks a rule, so the whole domain is ok.
         * This is the check that would catch a threshold pointed the wrong
         * way — a rule that fires on a healthy node is worse than no rule. */
        RT_CHECK("[runtime] a healthy fixture judges ok on every rule",
                 json_get_str(json_get(json_get(&doc, "health"), "state")) &&
                 strcmp(json_get_str(json_get(json_get(&doc, "health"),
                                              "state")), "ok") == 0);
    }
    json_free(&doc);
    return failures;
}

/* ── 3. unreadable is UNKNOWN, never UNHEALTHY ───────────────────────── */

static int check_unavailable_leaf_is_unknown(void)
{
    int failures = 0;
    g_mode = RT_MODE_MEM_GAP;

    struct runtime_snapshot snap = {0};
    const char *why = "";
    bool filled = runtime_dump_state_fill(&snap, &why);
    RT_CHECK("[runtime] a dump missing one field is still a successful fill",
             filled);

    const struct telemetry_leaf *lf = rt_find_leaf("mem_polling_active");
    RT_CHECK("[runtime] the fixture's missing field is a real leaf",
             lf != NULL);
    if (lf) {
        const struct telemetry_leaf_meta *m = rt_meta(&snap, lf);
        RT_CHECK("[runtime] a field absent from the dump is UNAVAILABLE, not "
                 "a false bool", m->presence == TELEMETRY_UNAVAILABLE);
        RT_CHECK("[runtime] and it names why",
                 m->reason && strcmp(m->reason, "field_absent_from_dump") == 0);
    }

    struct json_value doc;
    json_init(&doc);
    if (telemetry_render(&g_runtime_schema, &snap, TLV_FULL, NULL, &doc)) {
        const char *state =
            json_get_str(json_get(json_get(&doc, "health"), "state"));
        RT_CHECK("[runtime] one unreadable JUDGED leaf makes the domain "
                 "unknown — not unhealthy, and not ok",
                 state && strcmp(state, "unknown") == 0);
        RT_CHECK("[runtime] nothing is reported unhealthy on a read failure",
                 json_get_int(json_get(json_get(&doc, "health"),
                                       "unhealthy_count")) == 0);
        RT_CHECK("[runtime] the unreadable leaf is counted as unknown",
                 json_get_int(json_get(json_get(&doc, "health"),
                                       "unknown_count")) == 1);
        RT_CHECK("[runtime] completeness counts the unavailable leaf",
                 json_get_int(json_get(json_get(&doc, "completeness"),
                                       "unavailable")) == 1);
        RT_CHECK("[runtime] an unavailable leaf is still not an unset one",
                 json_get_int(json_get(json_get(&doc, "completeness"),
                                       "unset")) == 0);
    } else {
        RT_CHECK("[runtime] the gapped snapshot renders", false);
    }
    json_free(&doc);
    return failures;
}

/* ── 3b. "never measured" is never published as a number ─────────────── */

static int check_never_measured_is_not_a_value(void)
{
    int failures = 0;
    g_mode = RT_MODE_PREPOLL;

    struct runtime_snapshot snap = {0};
    const char *why = "";
    RT_CHECK("[runtime] a pre-poll node is still a successful fill",
             runtime_dump_state_fill(&snap, &why));

    /* Each of these is a leaf whose producer spells "not measured yet" as a
     * value that would read as real: 1970 for a timestamp, 0 bytes for a
     * machine's RAM, and -1 for the three the memory organ initialises. None
     * of them may reach the document as a number. */
    static const char *const k_unmeasured[] = {
        "mem_last_poll_unix", "ram_bytes",
        "mem_current_bytes", "mem_denominator_bytes", "rss_bytes",
    };
    size_t published = 0, no_reason = 0;
    for (size_t i = 0; i < sizeof k_unmeasured / sizeof k_unmeasured[0]; i++) {
        const struct telemetry_leaf *lf = rt_find_leaf(k_unmeasured[i]);
        if (!lf) {
            printf("  [runtime] %s is not a leaf\n", k_unmeasured[i]);
            published++;
            continue;
        }
        const struct telemetry_leaf_meta *m = rt_meta(&snap, lf);
        if (m->presence != TELEMETRY_UNAVAILABLE) {
            printf("  [runtime] %s published a never-measured value as %s\n",
                   k_unmeasured[i], telemetry_presence_name(m->presence));
            published++;
        } else if (!m->reason ||
                   strcmp(m->reason, "value_unknown_sentinel") != 0) {
            printf("  [runtime] %s is unavailable but does not say why\n",
                   k_unmeasured[i]);
            no_reason++;
        }
    }
    RT_CHECK("[runtime] a never-measured value is UNAVAILABLE, never a "
             "plausible 0, -1 or 1970 timestamp", published == 0);
    RT_CHECK("[runtime] and each one names the sentinel as the reason",
             no_reason == 0);

    /* The leaves the same dump DID answer are unaffected — an organ that has
     * not polled still knows whether it is registered to poll. */
    const struct telemetry_leaf *lf = rt_find_leaf("mem_polling_active");
    RT_CHECK("[runtime] a field the organ genuinely knows is still present",
             lf && rt_meta(&snap, lf)->presence == TELEMETRY_PRESENT);

    g_mode = RT_MODE_FULL;
    return failures;
}

/* ── 4. the three leaves answer ok:true ──────────────────────────────── */

static const struct zcl_command_spec *rt_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static size_t rt_exec(const struct zcl_command_registry *reg,
                      const struct zcl_command_spec *spec,
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
                                                 spec->path, "normal", 0, 0,
                                                 NULL, out, out_size,
                                                 exit_code);
    json_free(&input);
    return n;
}

static int check_commands_answer(void)
{
    int failures = 0;
    static const char *const k_paths[] = {
        "ops.telemetry.runtime.services",
        "ops.telemetry.runtime.threads",
        "ops.telemetry.runtime.resources",
    };
    static const char *const k_groups[] = { "services", "threads", "resources" };
    const size_t n_paths = sizeof k_paths / sizeof k_paths[0];
    const struct zcl_command_registry *reg = zcl_command_catalog();

    g_mode = RT_MODE_FULL;
    size_t not_ready = 0, not_ok = 0, wrong_group = 0, over_budget = 0;
    for (size_t i = 0; i < n_paths; i++) {
        const struct zcl_command_spec *spec = rt_spec(reg, k_paths[i]);
        if (!spec || spec->availability != ZCL_COMMAND_READY) {
            printf("  [runtime] %s is not a READY leaf\n", k_paths[i]);
            not_ready++;
            continue;
        }
        char out[ZCL_COMMAND_RESULT_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = rt_exec(reg, spec, out, sizeof out, &code);
        printf("  [runtime] %s -> %zu bytes (budget %u)\n", k_paths[i], n,
               (unsigned)ZCL_COMMAND_RESULT_BUDGET);
        if (n > ZCL_COMMAND_RESULT_BUDGET)
            over_budget++;
        struct json_value doc;
        /* Over budget is an EMPTY reply, not a truncated one, so a zero-length
         * or unparsable document is the overflow symptom — never "it worked". */
        if (n == 0 || !json_read(&doc, out, n) || doc.type != JSON_OBJ) {
            printf("  [runtime] %s returned no parsable envelope\n",
                   k_paths[i]);
            not_ok++;
            json_free(&doc);
            continue;
        }
        if (!json_get_bool(json_get(&doc, "ok")) ||
            code != ZCL_COMMAND_EXIT_OK) {
            printf("  [runtime] %s ok=false exit=%d\n", k_paths[i], (int)code);
            not_ok++;
        }
        const struct json_value *data = json_get(&doc, "data");
        const char *filter = json_get_str(json_get(data, "group_filter"));
        if (!filter || strcmp(filter, k_groups[i]) != 0 ||
            !json_get_bool(json_get(data, "group_filter_matched")) ||
            !json_get(json_get(data, "values"), k_groups[i])) {
            printf("  [runtime] %s did not render group %s\n", k_paths[i],
                   k_groups[i]);
            wrong_group++;
        }
        json_free(&doc);
    }
    RT_CHECK("[runtime] all three leaves are READY", not_ready == 0);
    RT_CHECK("[runtime] all three leaves return ok:true with exit OK",
             not_ok == 0);
    RT_CHECK("[runtime] each leaf renders its own group and says which",
             wrong_group == 0);
    RT_CHECK("[runtime] no leaf exceeds the RESULT budget", over_budget == 0);
    return failures;
}

/* ── 5. a dead node fails closed, it does not answer emptily ─────────── */

static int check_dead_node_fails_closed(void)
{
    int failures = 0;
    g_mode = RT_MODE_DEAD;

    struct runtime_snapshot snap = {0};
    const char *why = "";
    RT_CHECK("[runtime] the collector refuses when nothing answers",
             !runtime_dump_state_fill(&snap, &why));
    RT_CHECK("[runtime] and names the transport as the reason",
             why && strcmp(why, "node_unreachable") == 0);

    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        rt_spec(reg, "ops.telemetry.runtime.services");
    RT_CHECK("[runtime] the services leaf is in the catalog", spec != NULL);
    if (spec) {
        char out[ZCL_COMMAND_RESULT_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        size_t n = rt_exec(reg, spec, out, sizeof out, &code);
        struct json_value doc;
        if (n > 0 && json_read(&doc, out, n) && doc.type == JSON_OBJ) {
            RT_CHECK("[runtime] a dead node produces ok:false, never an empty "
                     "success", !json_get_bool(json_get(&doc, "ok")));
            RT_CHECK("[runtime] the refusal is retryable transport, not a "
                     "telemetry verdict", code == ZCL_COMMAND_EXIT_TRANSIENT);
            RT_CHECK("[runtime] and it names the failure",
                     json_get_str(json_get(json_get(&doc, "error"), "code")) &&
                     strcmp(json_get_str(json_get(json_get(&doc, "error"),
                                                  "code")),
                            "NODE_UNAVAILABLE") == 0);
        } else {
            RT_CHECK("[runtime] the dead-node reply parses", false);
        }
        json_free(&doc);
    }
    g_mode = RT_MODE_FULL;
    return failures;
}

int test_telemetry_runtime(void)
{
    int failures = 0;

    /* Isolated datadir FIRST: the RPC client resolves its cookie path under
     * the datadir at init, and the default is the owner's live node. */
    char datadir[512];
    test_make_tmpdir(datadir, sizeof datadir, "telemetry_runtime", "datadir");
    SetDataDir(datadir);
    node_rpc_client_init(datadir, 39232);
    node_rpc_client_set_test_hook(rt_hook);

    failures += check_every_leaf_has_meaning();
    failures += check_collector_fills_every_leaf();
    failures += check_unavailable_leaf_is_unknown();
    failures += check_never_measured_is_not_a_value();
    failures += check_commands_answer();
    failures += check_dead_node_fails_closed();

    node_rpc_client_set_test_hook(NULL);
    (void)test_rm_rf_recursive(datadir);
    printf("=== telemetry_runtime: %d failures ===\n", failures);
    return failures;
}
