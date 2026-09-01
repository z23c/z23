/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_agents — the `agents` telemetry domain end to end: its field
 * table, its collector, and the three native leaves that render it.
 *
 * WHAT THESE CHECKS DEFEND, each a real defect class rather than a smoke test:
 *
 *   every leaf carries meaning     a value with no means/implies/next is a
 *                                  number an operator cannot act on. Judged
 *                                  rows owe all three; TFR_INFO rows owe
 *                                  `means` and are explicitly allowed to leave
 *                                  implies/next empty (the same split
 *                                  check_telemetry_ontology.sh enforces).
 *   a filled snapshot has no UNSET a leaf the collector forgot renders as null
 *                                  and is counted a provider defect — the
 *                                  point being that forgetting is VISIBLE, so
 *                                  this test proves the agents collector
 *                                  forgets nothing on a normal fill.
 *   unreadable is UNKNOWN          with the node unreachable, the domain's one
 *                                  CRITICAL rule is unavailable-with-a-reason
 *                                  and must report `unknown`, never
 *                                  `unhealthy`: calling a read that did not
 *                                  happen a fault sends an operator to the
 *                                  wrong subsystem. The one finding worse than
 *                                  unknown is store_readable=false, which the
 *                                  collector positively established and which
 *                                  carries the next command to run.
 *   ok:true, not merely non-empty  a next[] entry naming the command being
 *                                  served makes the kernel abandon the WHOLE
 *                                  document, which the CLI then misreports as
 *                                  a budget overrun. A non-empty reply proves
 *                                  nothing; these assert ok:true and, for
 *                                  belt and braces, that no next entry names
 *                                  its own command.
 *   no credential is published     the domain describes what other agents may
 *                                  do to this node, so the rendered bytes are
 *                                  scanned for the canned session ids and
 *                                  accounts the fixture feeds in. None may
 *                                  appear.
 *
 * ISOLATION. The collector reads the node over loopback RPC, so every check
 * runs behind node_rpc_client_set_test_hook with canned bodies — no socket, no
 * node.db, and no dependence on whether a node happens to be running. The
 * datadir is pointed at a per-pid temp directory for the duration anyway: the
 * RPC client resolves a cookie path from it, and a test that leaves it at the
 * default reads the operator's live node and can pass for the wrong reason. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/agents_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* One label-free assertion per line, for the same reason as
 * test_telemetry_render: TEST/ASSERT mint a per-function `_test_next` label,
 * and these checks are numerous, independent, and worth reporting one by one
 * rather than jumping out on the first failure. */
#define TA_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* ── the canned node ──────────────────────────────────────────────────────
 * Five grant rows chosen so that every branch of the collector's scan is
 * exercised by exactly one of them, and so the expected aggregate is a
 * hand-checkable constant rather than whatever the code happens to produce.
 *
 *   A  usable, ANY recipient, never expires, spending 250000 of a 500000
 *      window that has NOT rolled  -> the permille worst case, 500
 *   B  usable, allowlisted, expires in 600 s, window rolled long ago
 *      -> its 199999 debit is stale and must count as ZERO
 *   C  revoked
 *   D  expired but never revoked
 *   E  window_seconds = 0: impossible under the table's CHECK, so it is the
 *      malformed row. Still not revoked and never expiring, so it is also
 *      usable — the collector counts it in BOTH places on purpose.
 *
 * The session ids and accounts are distinctive strings so the no-credential
 * check can grep the rendered bytes for them. */
#define TA_SID_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
#define TA_SID_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
#define TA_ACCT_A "t1TelemetryFixtureAccountAlpha"
#define TA_ACCT_B "t1TelemetryFixtureAccountBravo"
#define TA_ACCT_C "t1TelemetryFixtureAccountCharlie"
#define TA_ALLOWLIST "t1TelemetryFixtureRecipientDelta"

enum ta_mode { TA_MODE_HEALTHY = 0, TA_MODE_NODE_DOWN, TA_MODE_DB_CLOSED };

static enum ta_mode g_mode = TA_MODE_HEALTHY;
static int64_t g_now = 0;

static char *ta_dup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out)
        memcpy(out, s, n);
    return out;
}

static char *ta_fmt(const char *fmt, ...)
{
    va_list ap;
    char buf[4096];
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return NULL;
    return ta_dup(buf);
}

static char *ta_grant_page(void)
{
    return ta_fmt(
        "{\"ok\":true,\"session_count\":5,\"sessions\":["
        /* A */
        "{\"session_id\":\"" TA_SID_A "\",\"account\":\"" TA_ACCT_A "\","
        "\"max_per_tx_zat\":100000,\"max_per_window_zat\":500000,"
        "\"window_seconds\":3600,\"window_start_epoch\":%lld,"
        "\"spent_in_window_zat\":250000,\"recipient_allowlist\":\"\","
        "\"created_at\":%lld,\"expires_at\":0,\"revoked\":0},"
        /* B */
        "{\"session_id\":\"" TA_SID_B "\",\"account\":\"" TA_ACCT_B "\","
        "\"max_per_tx_zat\":50000,\"max_per_window_zat\":200000,"
        "\"window_seconds\":60,\"window_start_epoch\":%lld,"
        "\"spent_in_window_zat\":199999,"
        "\"recipient_allowlist\":\"" TA_ALLOWLIST "\","
        "\"created_at\":%lld,\"expires_at\":%lld,\"revoked\":0},"
        /* C */
        "{\"session_id\":\"c\",\"account\":\"" TA_ACCT_A "\","
        "\"max_per_tx_zat\":900000,\"max_per_window_zat\":900000,"
        "\"window_seconds\":3600,\"window_start_epoch\":%lld,"
        "\"spent_in_window_zat\":0,\"recipient_allowlist\":\"\","
        "\"created_at\":%lld,\"expires_at\":0,\"revoked\":1},"
        /* D */
        "{\"session_id\":\"d\",\"account\":\"" TA_ACCT_B "\","
        "\"max_per_tx_zat\":800000,\"max_per_window_zat\":800000,"
        "\"window_seconds\":3600,\"window_start_epoch\":%lld,"
        "\"spent_in_window_zat\":0,\"recipient_allowlist\":\"\","
        "\"created_at\":%lld,\"expires_at\":%lld,\"revoked\":0},"
        /* E */
        "{\"session_id\":\"e\",\"account\":\"" TA_ACCT_C "\","
        "\"max_per_tx_zat\":1,\"max_per_window_zat\":0,"
        "\"window_seconds\":0,\"window_start_epoch\":%lld,"
        "\"spent_in_window_zat\":0,\"recipient_allowlist\":\"\","
        "\"created_at\":%lld,\"expires_at\":0,\"revoked\":0}"
        "]}",
        (long long)g_now, (long long)(g_now - 7200),          /* A */
        (long long)(g_now - 600), (long long)(g_now - 100),
        (long long)(g_now + 600),                             /* B */
        (long long)g_now, (long long)(g_now - 50),            /* C */
        (long long)g_now, (long long)(g_now - 60),
        (long long)(g_now - 10),                              /* D */
        (long long)g_now, (long long)(g_now - 1));            /* E */
}

/* The transport error stub node_rpc_call returns when it cannot reach the
 * node. Using the REAL failure shape matters: a hook that returned NULL would
 * exercise a branch the production client never takes. */
static char *ta_transport_error(void)
{
    return ta_dup("{\"error\":{\"code\":-1,\"message\":\"connect failed\"}}");
}

static char *ta_hook(const char *method, const char *params_json)
{
    if (g_mode == TA_MODE_NODE_DOWN)
        return ta_transport_error();
    const char *p = params_json ? params_json : "";
    bool db_open = g_mode != TA_MODE_DB_CLOSED;

    if (method && strcmp(method, "agentsession") == 0) {
        if (!db_open)
            return ta_dup("{\"ok\":false,\"why\":\"DB_UNAVAILABLE\"}");
        return ta_grant_page();
    }
    if (!method || strcmp(method, "dumpstate") != 0)
        return ta_transport_error();

    if (strstr(p, "agent_sessions"))
        return ta_fmt("{\"subsystem\":\"agent_sessions\",\"captured_at\":%lld,"
                      "\"state\":{\"db_open\":%s,\"count\":5}}",
                      (long long)g_now, db_open ? "true" : "false");
    if (strstr(p, "principals"))
        /* count 3 with a 2-row page: the dumper's own paging, so the two
         * login figures must come back TRUNCATED rather than as a quiet
         * undercount. */
        return ta_fmt("{\"subsystem\":\"principals\",\"captured_at\":%lld,"
                      "\"state\":{\"db_open\":%s,\"count\":3,\"principals\":["
                      "{\"address\":\"" TA_ACCT_A "\",\"last_login\":%lld},"
                      "{\"address\":\"" TA_ACCT_B "\",\"last_login\":0}]}}",
                      (long long)g_now, db_open ? "true" : "false",
                      (long long)(g_now - 120));
    if (strstr(p, "auth"))
        return ta_fmt("{\"subsystem\":\"auth\",\"captured_at\":%lld,"
                      "\"state\":{\"db_open\":%s,\"pending\":4}}",
                      (long long)g_now, db_open ? "true" : "false");
    if (strstr(p, "self_backtrace"))
        return ta_fmt("{\"subsystem\":\"self_backtrace\",\"captured_at\":%lld,"
                      "\"state\":{\"installed\":true,\"dump_count\":7,"
                      "\"last_thread_count\":3}}",
                      (long long)g_now);
    return ta_dup("\"dumpstate: unknown subsystem\"");
}

/* ── small readers ───────────────────────────────────────────────────────── */

static int64_t dig_int(const struct json_value *o, const char *a,
                       const char *b, const char *c)
{
    return json_get_int(json_get(json_get(json_get(o, a), b), c));
}

/* `leaves` is an OBJECT keyed by the leaf's full ontology path, not an array
 * of {key,...} rows. */
static const struct json_value *leaf_meta(const struct json_value *doc,
                                          const char *path)
{
    return json_get(json_get(doc, "leaves"), path);
}

static bool leaf_presence_is(const struct json_value *doc, const char *path,
                             const char *want)
{
    const char *p = json_get_str(json_get(leaf_meta(doc, path), "presence"));
    return p && strcmp(p, want) == 0;
}

static bool leaf_reason_is(const struct json_value *doc, const char *path,
                           const char *want)
{
    const char *r = json_get_str(json_get(leaf_meta(doc, path), "reason"));
    return r && strcmp(r, want) == 0;
}

/* ── 1. every leaf carries meaning ───────────────────────────────────────── */

static int check_every_leaf_has_meaning(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("agents");
    TA_CHECK("[meaning] the agents domain is registered", s != NULL);
    if (!s)
        return failures;
    TA_CHECK("[meaning] the agents field table is not a stub", s->leaf_count > 10);

    size_t no_row = 0, no_means = 0, judged = 0, judged_silent = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup("agents", lf->path);
        if (!f) {
            no_row++;
            printf("  (no ontology row for %s)\n", lf->path);
            continue;
        }
        if (!f->means || !f->means[0])
            no_means++;
        if (f->rule == TFR_INFO)
            continue;
        judged++;
        if (!f->implies || !f->implies[0] || !f->next || !f->next[0]) {
            judged_silent++;
            printf("  (judged row with empty implies/next: %s)\n", lf->path);
        }
    }
    TA_CHECK("[meaning] every agents leaf resolves to an ontology row",
             no_row == 0);
    TA_CHECK("[meaning] every agents leaf states what it counts",
             no_means == 0);
    TA_CHECK("[meaning] the domain carries at least one real health rule, so "
             "it is not all-INFO by accident", judged >= 3);
    TA_CHECK("[meaning] every JUDGED leaf states what a bad value implies and "
             "the next command to run", judged_silent == 0);
    return failures;
}

/* ── 2. a filled snapshot leaves no leaf UNSET ───────────────────────────── */

static int check_fill_leaves_nothing_unset(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("agents");
    if (!s)
        return failures;

    g_mode = TA_MODE_HEALTHY;
    struct agents_snapshot snap = { 0 };
    agents_dump_state_fill(&snap);

    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(s, &snap, TLV_FULL, NULL, &doc);
    TA_CHECK("[fill] the filled snapshot renders", rendered);
    if (!rendered) {
        json_free(&doc);
        return failures;
    }

    TA_CHECK("[fill] no leaf is left UNSET — the collector sets every one",
             json_get_int(json_get(json_get(&doc, "completeness"), "unset")) == 0);
    TA_CHECK("[fill] no provider defect: every non-present leaf carries a "
             "static reason token",
             json_get_bool(json_get(json_get(&doc, "completeness"),
                                    "provider_defect")) == false);
    TA_CHECK("[fill] every leaf in the table is rendered at full view",
             json_get_int(json_get(json_get(&doc, "completeness"),
                                   "leaves_rendered")) == (int64_t)s->leaf_count);

    /* The hand-checkable aggregate. Five rows: A and B usable and well formed,
     * C revoked, D expired, E malformed-but-usable. */
    TA_CHECK("[fill] store_readable is true when the node answers",
             json_get_bool(json_get(json_get(json_get(&doc, "values"),
                                             "sessions"), "store_readable")));
    TA_CHECK("[fill] sessions_total is the node's own row count",
             dig_int(&doc, "values", "sessions", "sessions_total") == 5);
    TA_CHECK("[fill] sessions_usable counts A, B and E",
             dig_int(&doc, "values", "sessions", "sessions_usable") == 3);
    TA_CHECK("[fill] sessions_revoked counts C",
             dig_int(&doc, "values", "sessions", "sessions_revoked") == 1);
    TA_CHECK("[fill] sessions_expired counts D",
             dig_int(&doc, "values", "sessions", "sessions_expired") == 1);
    TA_CHECK("[fill] session_holders counts the three distinct accounts",
             dig_int(&doc, "values", "sessions", "session_holders") == 3);
    TA_CHECK("[fill] malformed_rows catches the window_seconds=0 row",
             dig_int(&doc, "values", "sessions", "malformed_rows") == 1);
    TA_CHECK("[fill] scan_truncated is false when the page covered the table",
             json_get_bool(json_get(json_get(json_get(&doc, "values"),
                                             "sessions"),
                                    "scan_truncated")) == false);

    TA_CHECK("[fill] grants_any_recipient counts A and E, not the "
             "allowlisted B",
             dig_int(&doc, "values", "grants", "grants_any_recipient") == 2);
    TA_CHECK("[fill] grants_never_expire counts A and E",
             dig_int(&doc, "values", "grants", "grants_never_expire") == 2);
    TA_CHECK("[fill] max_per_tx_zat_highest is A's cap",
             dig_int(&doc, "values", "grants", "max_per_tx_zat_highest")
                 == 100000);
    TA_CHECK("[fill] max_per_window_zat_highest is A's cap",
             dig_int(&doc, "values", "grants", "max_per_window_zat_highest")
                 == 500000);
    {
        int64_t soon = dig_int(&doc, "values", "grants",
                               "soonest_expiry_seconds");
        TA_CHECK("[fill] soonest_expiry_seconds is B's remaining lifetime",
                 soon > 500 && soon <= 600);
    }

    /* B's window rolled 600 s ago against a 60 s window, so its 199999-zat
     * debit is stale and the next authorize would see zero. A collector that
     * summed the raw column would report 449999 here. */
    TA_CHECK("[activity] window_spent_zat_total counts only the LIVE window",
             dig_int(&doc, "values", "activity", "window_spent_zat_total")
                 == 250000);
    TA_CHECK("[activity] grants_with_spend counts only A",
             dig_int(&doc, "values", "activity", "grants_with_spend") == 1);
    TA_CHECK("[activity] window_used_permille_worst is A at half its cap",
             dig_int(&doc, "values", "activity", "window_used_permille_worst")
                 == 500);
    TA_CHECK("[activity] auth publishes the pending-challenge COUNT",
             dig_int(&doc, "values", "activity", "auth_challenges_pending")
                 == 4);
    TA_CHECK("[activity] the backtrace handler state comes from the node",
             json_get_bool(json_get(json_get(json_get(&doc, "values"),
                                             "activity"),
                                    "backtrace_handler_armed")));
    TA_CHECK("[activity] backtrace_dumps_total is the node's counter",
             dig_int(&doc, "values", "activity", "backtrace_dumps_total") == 7);

    /* The principals dumper answered count=3 behind a 2-row page, so the two
     * login figures are floors and must SAY so. */
    TA_CHECK("[activity] principals_total is the registry's own count",
             dig_int(&doc, "values", "sessions", "principals_total") == 3);
    TA_CHECK("[activity] a figure derived from a capped page is TRUNCATED, "
             "not a quiet undercount",
             leaf_presence_is(&doc, "values.activity.principals_ever_logged_in",
                              "truncated"));
    TA_CHECK("[activity] the truncated leaf names WHY it is a floor",
             leaf_reason_is(&doc, "values.activity.principals_ever_logged_in",
                            "principal_page_capped"));

    /* Nothing that could be presented to spend, and nothing that names an
     * identity, may appear in the bytes. */
    {
        size_t need = json_write(&doc, NULL, 0) + 1;
        char *buf = malloc(need);
        bool clean = false;
        if (buf) {
            json_write(&doc, buf, need);
            clean = !strstr(buf, TA_SID_A) && !strstr(buf, TA_SID_B) &&
                    !strstr(buf, TA_ACCT_A) && !strstr(buf, TA_ACCT_B) &&
                    !strstr(buf, TA_ACCT_C) && !strstr(buf, TA_ALLOWLIST);
            free(buf);
        }
        TA_CHECK("[security] no session id, account or allowlisted address "
                 "reaches the rendered document", clean);
    }

    json_free(&doc);
    return failures;
}

/* ── 3. unreadable is UNKNOWN, never UNHEALTHY ───────────────────────────── */

static int check_node_down_is_unknown_not_unhealthy(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("agents");
    if (!s)
        return failures;

    g_mode = TA_MODE_NODE_DOWN;
    struct agents_snapshot snap = { 0 };
    agents_dump_state_fill(&snap);

    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(s, &snap, TLV_FULL, NULL, &doc);
    TA_CHECK("[down] the snapshot still renders with the node unreachable",
             rendered);
    if (!rendered) {
        json_free(&doc);
        return failures;
    }

    TA_CHECK("[down] still no UNSET leaf: an unreachable node is reported, "
             "not skipped",
             json_get_int(json_get(json_get(&doc, "completeness"),
                                   "unset")) == 0);
    /* Exactly two leaves survive an unreachable node, and both are real
     * answers rather than guesses: collected_unix (this process's own clock)
     * and store_readable=false (the collector positively established the node
     * did not answer). Everything else is unavailable-with-a-reason. */
    TA_CHECK("[down] every leaf but the two the collector can still answer "
             "for itself reports unavailable",
             json_get_int(json_get(json_get(&doc, "completeness"),
                                   "unavailable"))
                 == (int64_t)s->leaf_count - 2);
    TA_CHECK("[down] no provider defect — each one carries a reason token",
             json_get_bool(json_get(json_get(&doc, "completeness"),
                                    "provider_defect")) == false);
    TA_CHECK("[down] the reason names the transport, not a guess",
             leaf_reason_is(&doc, "values.sessions.sessions_total",
                            "node_unreachable"));

    /* THE property this check exists for. malformed_rows is the domain's one
     * CRITICAL rule (TFR_EXPECT_ZERO). Unread, it must be UNKNOWN — the
     * evaluator bug this layer replaced read a missing value as a zero-ish
     * false and drove a domain critical on a read it never performed. */
    TA_CHECK("[down] the CRITICAL leaf is unavailable, with a reason",
             leaf_presence_is(&doc, "values.sessions.malformed_rows",
                              "unavailable") &&
                 leaf_reason_is(&doc, "values.sessions.malformed_rows",
                                "node_unreachable"));
    {
        /* The `unhealthy` array carries every finding with its own state, not
         * only the faults — so the assertion is about STATES, not membership.
         * Exactly one finding may be worse than unknown, and it must be the
         * one the collector positively established. */
        const struct json_value *arr =
            json_get(json_get(&doc, "health"), "unhealthy");
        size_t n = (arr && arr->type == JSON_ARR) ? arr->num_children : 0;
        const char *critical_state = NULL;
        size_t not_unknown = 0;
        bool the_one_is_store = false;
        for (size_t i = 0; i < n; i++) {
            const struct json_value *f = json_at(arr, i);
            const char *p = json_get_str(json_get(f, "path"));
            const char *st = json_get_str(json_get(f, "state"));
            if (p && strcmp(p, "values.sessions.malformed_rows") == 0)
                critical_state = st;
            if (st && strcmp(st, "unknown") != 0) {
                not_unknown++;
                the_one_is_store =
                    p && strcmp(p, "values.sessions.store_readable") == 0 &&
                    strcmp(st, "degraded") == 0;
            }
        }
        TA_CHECK("[down] the domain's one CRITICAL rule, unread, reports "
                 "UNKNOWN — never unhealthy on a read that did not happen",
                 critical_state && strcmp(critical_state, "unknown") == 0);
        /* store_readable=false is the one genuine finding, and it is the
         * useful one: it carries the next command to run. Collapsing the
         * whole domain to `unknown` instead would bury it. */
        TA_CHECK("[down] exactly one finding is worse than unknown, and it is "
                 "the fact the collector actually established",
                 not_unknown == 1 && the_one_is_store);
    }
    {
        const char *state =
            json_get_str(json_get(json_get(&doc, "health"), "state"));
        TA_CHECK("[down] a WARN-severity finding degrades the domain rather "
                 "than declaring it unhealthy",
                 state && strcmp(state, "degraded") == 0);
    }
    TA_CHECK("[down] the unread leaves are counted as unknown, not as faults",
             json_get_int(json_get(json_get(&doc, "health"),
                                   "unknown_count")) > 0);
    json_free(&doc);

    /* A node that is UP but whose node.db is closed is a different fact, and
     * the reason token has to say which one happened. */
    g_mode = TA_MODE_DB_CLOSED;
    struct agents_snapshot closed = { 0 };
    agents_dump_state_fill(&closed);
    struct json_value doc2;
    json_init(&doc2);
    if (telemetry_render(s, &closed, TLV_FULL, NULL, &doc2)) {
        TA_CHECK("[closed] a reachable node with a closed database reports "
                 "node_db_closed, not node_unreachable",
                 leaf_reason_is(&doc2, "values.sessions.sessions_total",
                                "node_db_closed"));
        TA_CHECK("[closed] store_readable is false, and false is a real "
                 "answer rather than an unavailable leaf",
                 json_get_bool(json_get(json_get(json_get(&doc2, "values"),
                                                 "sessions"),
                                        "store_readable")) == false);
        TA_CHECK("[closed] no UNSET leaf on this path either",
                 json_get_int(json_get(json_get(&doc2, "completeness"),
                                       "unset")) == 0);
    } else {
        TA_CHECK("[closed] the db-closed snapshot renders", false);
    }
    json_free(&doc2);

    g_mode = TA_MODE_HEALTHY;
    return failures;
}

/* ── 4. the three leaves answer ok:true ──────────────────────────────────── */

static int exec_leaf(const char *path, const char *view, char *out,
                     size_t out_size, int *failures)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        reg ? zcl_command_registry_find(reg, path, NULL) : NULL;
    out[0] = '\0';
    if (!spec) {
        printf("  (no spec for %s)\n", path);
        (*failures)++;
        return 0;
    }
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
                                                 path, view, 0, 0, NULL,
                                                 out, out_size, &code);
    json_free(&input);
    return (int)n;
}

static int check_one_leaf(const char *path, const char *group)
{
    int failures = 0;
    /* One byte over the leaf's declared LIST budget, so a reply that filled
     * the budget exactly is still distinguishable from one that overran it. */
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];
    char label[192];

    /* An over-budget reply is EMPTY, not truncated, so the budget question is
     * answered by MEASURING the widest view and printing it — not by adding a
     * step-down path here. `full` is the worst case: it renders every leaf of
     * the group plus a provenance block for each. */
    int n_full = exec_leaf(path, "full", out, sizeof(out), &failures);
    snprintf(label, sizeof(label),
             "[cmd] %s fits its budget at the WIDEST view", path);
    TA_CHECK(label, n_full > 0 && (size_t)n_full <= ZCL_COMMAND_LIST_BUDGET);
    printf("  (%s --view=full: %d bytes of %u budget)\n", path, n_full,
           (unsigned)ZCL_COMMAND_LIST_BUDGET);

    int n = exec_leaf(path, "normal", out, sizeof(out), &failures);
    snprintf(label, sizeof(label), "[cmd] %s renders bytes", path);
    TA_CHECK(label, n > 0);
    if (n <= 0)
        return failures;
    printf("  (%s --view=normal: %d bytes of %u budget)\n", path, n,
           (unsigned)ZCL_COMMAND_LIST_BUDGET);

    struct json_value root;
    json_init(&root);
    if (!json_read(&root, out, strlen(out)) || root.type != JSON_OBJ) {
        snprintf(label, sizeof(label), "[cmd] %s returns a JSON object", path);
        TA_CHECK(label, false);
        json_free(&root);
        return failures;
    }

    /* The assertion that matters. An over-budget reply is EMPTY, not
     * truncated, and a self-referencing next[] entry produces ok:false with an
     * empty document — both of which a "non-empty output" check would pass. */
    snprintf(label, sizeof(label), "[cmd] %s answers ok:true", path);
    TA_CHECK(label, json_get_bool(json_get(&root, "ok")));

    const char *filter =
        json_get_str(json_get(json_get(&root, "data"), "group_filter"));
    snprintf(label, sizeof(label), "[cmd] %s reports its own group filter",
             path);
    TA_CHECK(label, filter && strcmp(filter, group) == 0);

    snprintf(label, sizeof(label),
             "[cmd] %s renders the %s group's values", path, group);
    TA_CHECK(label,
             json_get(json_get(json_get(&root, "data"), "values"), group)
                 != NULL);

    snprintf(label, sizeof(label),
             "[cmd] %s judges the WHOLE domain, not just its own group", path);
    TA_CHECK(label, json_get(json_get(&root, "data"), "health") != NULL);

    /* The trap that has already destroyed a reply here: a next entry naming
     * the command being served makes the kernel abandon the entire document.
     * ok:true above already proves it did not happen, but assert the shape
     * directly so a future edit is caught at the cause, not the symptom. */
    {
        const struct json_value *arr = json_get(&root, "next");
        bool self_ref = false;
        size_t count = (arr && arr->type == JSON_ARR) ? arr->num_children : 0;
        for (size_t i = 0; i < count; i++) {
            const char *cmd = json_get_str(json_get(json_at(arr, i), "command"));
            if (cmd && strcmp(cmd, path) == 0)
                self_ref = true;
        }
        snprintf(label, sizeof(label),
                 "[cmd] %s offers next steps and none is itself", path);
        TA_CHECK(label, count > 0 && !self_ref);
    }
    json_free(&root);
    return failures;
}

static int check_commands_answer(void)
{
    int failures = 0;
    g_mode = TA_MODE_HEALTHY;
    failures += check_one_leaf("ops.telemetry.agents.sessions", "sessions");
    failures += check_one_leaf("ops.telemetry.agents.grants", "grants");
    failures += check_one_leaf("ops.telemetry.agents.activity", "activity");

    /* The LARGEST document this domain can produce is not the healthy one: a
     * non-present leaf reports its provenance at EVERY view tier, so a node
     * that is down turns every leaf into a value plus a provenance block AND
     * adds a health finding per judged rule. Measure that case explicitly —
     * an over-budget reply here would be an empty document, and the failure
     * would look like a wedged node rather than a byte count. */
    g_mode = TA_MODE_NODE_DOWN;
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];
    int n = exec_leaf("ops.telemetry.agents.sessions", "full", out,
                      sizeof(out), &failures);
    printf("  (worst case — node down, sessions --view=full: %d bytes of %u "
           "budget)\n", n, (unsigned)ZCL_COMMAND_LIST_BUDGET);
    TA_CHECK("[cmd] the WORST-CASE document (node down, widest view) still "
             "fits the declared budget",
             n > 0 && (size_t)n <= ZCL_COMMAND_LIST_BUDGET);
    {
        struct json_value root;
        json_init(&root);
        bool ok = json_read(&root, out, strlen(out)) &&
                  json_get_bool(json_get(&root, "ok"));
        TA_CHECK("[cmd] and it still answers ok:true, so an unreachable node "
                 "is a reported fact rather than a failed command", ok);
        json_free(&root);
    }
    g_mode = TA_MODE_HEALTHY;
    return failures;
}

/* ── entry point ─────────────────────────────────────────────────────────── */

int test_telemetry_agents(void)
{
    int failures = 0;
    char dir[256];

    /* Isolate the datadir BEFORE anything can resolve one. The RPC client
     * derives its cookie path from it, and the default is the operator's live
     * node — a test that reads that can pass for entirely the wrong reason. */
    test_make_tmpdir(dir, sizeof(dir), "telemetry_agents", "main");
    SetDataDir(dir);
    ClearDataDirCache();

    /* The clock the layer under test uses, not a raw one: the fixture ages
     * are compared against timestamps the collector stamps with this same
     * accessor, so drawing them from a different source would make the
     * freshness assertions depend on which clock ran first. */
    g_now = telemetry_now_unix();
    node_rpc_client_set_test_hook(ta_hook);

    failures += check_every_leaf_has_meaning();
    failures += check_fill_leaves_nothing_unset();
    failures += check_node_down_is_unknown_not_unhealthy();
    failures += check_commands_answer();

    node_rpc_client_set_test_hook(NULL);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);

    printf("=== telemetry_agents: %d failures ===\n", failures);
    return failures;
}
