/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.test.history — which test groups failed recently, and how
 *          often, read from the runner's persistent group ledger.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────
 *
 * WHY. A failing group is visible exactly until the next run overwrites
 * .cache/test-timing/last-run.json. The parallel runner therefore appends
 * one JSON object per EXECUTED group to group-history.jsonl (written by
 * tests/harness/src/group_history.c, schema zcl.test_group_history.v1);
 * this leaf reads that ledger and answers the follow-up question — which
 * groups fail REPEATEDLY — from receipts, never from memory.
 *
 * INPUT (zcl.dev_test_history_input.v1)
 *   ledger  optional string. The JSONL ledger, read as given. Absent
 *           means the runner's conventional .cache/test-timing/
 *           group-history.jsonl.
 *   since   optional string. ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ". Rows
 *           whose ts compares below it are ignored for the table. A
 *           present-but-misshapen since is BAD_INPUT, never a silent
 *           unfiltered read.
 *   limit   optional integer 1..200. Bounds the groups reply. Default 20.
 *           Out of range is BAD_INPUT, never a silent clamp.
 *
 * LEDGER ROW (one JSON object per line; unknown keys ignored)
 *   {"ts":"2026-11-17T18:00:00Z","group":"alpha","rc":0,
 *    "verdict":"PASS","wall_ms":1234,"load_flaky":0,"tree":"<40-hex>"}
 * A line that is not one JSON object is counted in `malformed` and
 * skipped, never fatal. Blank lines are skipped silently.
 *
 * OUTPUT (zcl.dev_test_history.v1) on ok=true
 *   leaf            "dev.test.history"
 *   ledger          the ledger path read
 *   exists          false when the ledger file was absent — a TRUE ZERO:
 *                   rows 0, malformed 0, failing_groups 0, groups []. A
 *                   missing ledger is reported as exactly that, never as
 *                   a guess or an error.
 *   rows            well-formed rows read (before since filtering)
 *   malformed       lines skipped for not being one JSON object
 *   failing_groups  distinct groups with at least one FAIL in the window
 *   truncated       true when the limit cut failing groups from groups
 *   groups          failures first: {group, attempts, fail, flaky,
 *                   last_fail_ts, last_fail_rc, last_fail_tree}, sorted
 *                   fail desc, then most-recent failure desc, then name.
 *                   attempts/flaky count every kept row of the group; the
 *                   last_fail_* fields describe its most recent FAIL.
 *
 * FAILURE. A ledger that exists but cannot be read is LEDGER_UNREADABLE.
 * A bad since or limit is BAD_INPUT. A missing ledger is NOT a failure.
 *
 * PROCESS RULE. This leaf runs no process and writes nothing. popen(),
 * system() and a shell command string are forbidden and gated.
 *
 * The acceptance bar is tests/harness/src/test_devtesthistory.c.
 */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "native_ledger_reader_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DTH_LEAF "dev.test.history"
#define DTH_DEFAULT_LEDGER ".cache/test-timing/group-history.jsonl"
#define DTH_LINE_MAX 8192u
#define DTH_TS_LEN 20u
#define DTH_LIMIT_DEFAULT 20
#define DTH_LIMIT_MAX 200

struct dth_group {
    char *name;
    int64_t attempts;
    int64_t fail;
    int64_t flaky;
    char last_fail_ts[DTH_TS_LEN + 1];
    int64_t last_fail_rc;
    char last_fail_tree[64];
};

struct dth_table {
    struct dth_group *items;
    size_t n;
    size_t cap;
};

static void dth_table_free(struct dth_table *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < t->n; i++)
        free(t->items[i].name);
    free(t->items);
    t->items = NULL;
    t->n = 0;
    t->cap = 0;
}

/* The group's slot, first-seen order; NULL only on allocation failure. */
static struct dth_group *dth_find_or_add(struct dth_table *t, const char *name)
{
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->items[i].name, name) == 0)
            return &t->items[i];
    }
    if (t->n == t->cap) {
        size_t next = t->cap ? t->cap * 2u : 16u;
        struct dth_group *grown = zcl_realloc(t->items,
                                              next * sizeof(*grown),
                                              "dev_test_history_groups");
        if (!grown)
            return NULL;
        t->items = grown;
        t->cap = next;
    }
    struct dth_group *g = &t->items[t->n];
    memset(g, 0, sizeof(*g));
    g->name = zcl_strdup(name, "dev_test_history_group");
    if (!g->name)
        return NULL;
    t->n++;
    return g;
}

/* ISO-8601 UTC of exactly the ledger shape: "YYYY-MM-DDTHH:MM:SSZ". */
/* ISO-8601 UTC ledger ts shape: zcl_ledger_since_valid. */

static void dth_refuse(struct zcl_command_reply *reply,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, const char *message,
                       const char *evidence, const char *next_action)
{
    (void)fprintf(stderr, "dev.test.history: %s: %s\n", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, false, message, evidence);
    if (next_action)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s", next_action);
}

/* Blank-line test: zcl_ledger_line_blank (native_ledger_reader_internal.h). */

/* Adds one ledger row to the table; false on allocation failure. */
static bool dth_tally_row(struct dth_table *table,
                          const struct json_value *row, const char *since)
{
    const char *name = json_get_str(json_get(row, "group"));
    const char *ts = json_get_str(json_get(row, "ts"));
    if (!name[0])
        return true;
    if (since && !(strlen(ts) >= DTH_TS_LEN &&
                   strncmp(ts, since, DTH_TS_LEN) >= 0))
        return true;
    struct dth_group *g = dth_find_or_add(table, name);
    if (!g)
        return false;
    g->attempts++;
    if (json_get_int(json_get(row, "load_flaky")) != 0)
        g->flaky++;
    if (strcmp(json_get_str(json_get(row, "verdict")), "FAIL") != 0)
        return true;
    g->fail++;
    if (strlen(ts) >= DTH_TS_LEN &&
        strncmp(ts, g->last_fail_ts, DTH_TS_LEN) > 0) {
        (void)snprintf(g->last_fail_ts, sizeof(g->last_fail_ts), "%.*s",
                       (int)DTH_TS_LEN, ts);
        g->last_fail_rc = json_get_int(json_get(row, "rc"));
        (void)snprintf(g->last_fail_tree, sizeof(g->last_fail_tree), "%s",
                       json_get_str(json_get(row, "tree")));
    }
    return true;
}

struct dth_scan {
    int64_t rows, malformed;
    bool alloc_ok, read_ok;
};

static void dth_scan_ledger(FILE *fp, const char *since,
                            struct dth_table *table, struct dth_scan *scan)
{
    char line[DTH_LINE_MAX];
    scan->alloc_ok = true;
    scan->read_ok = true;
    while (fgets(line, sizeof(line), fp)) {
        if (!strchr(line, '\n') && !feof(fp)) {
            int c;
            do {
                c = fgetc(fp);
            } while (c != '\n' && c != EOF);
            scan->malformed++;
            continue;
        }
        if (zcl_ledger_line_blank(line))
            continue;
        struct json_value row;
        json_init(&row);
        if (!json_read(&row, line, strlen(line)) || row.type != JSON_OBJ) {
            scan->malformed++;
            json_free(&row);
            continue;
        }
        scan->rows++;
        bool tallied = dth_tally_row(table, &row, since);
        json_free(&row);
        if (!tallied) {
            scan->alloc_ok = false;
            break;
        }
    }
    if (ferror(fp))
        scan->read_ok = false;
    if (fclose(fp) != 0)
        scan->read_ok = false;
}

/* Failures first, then most-recent failure, then name: insertion sort,
 * the table holds at most a few hundred registry names. */
static void dth_sort_groups(struct dth_table *t)
{
    for (size_t a = 1; a < t->n; a++) {
        struct dth_group key = t->items[a];
        size_t b = a;
        while (b > 0) {
            const struct dth_group *prev = &t->items[b - 1];
            int by_fail = (prev->fail < key.fail) -
                          (prev->fail > key.fail);
            /* key precedes prev when key's failure is NEWER, so a
             * lexicographically smaller prev timestamp swaps right. */
            int by_ts = strncmp(prev->last_fail_ts, key.last_fail_ts,
                                DTH_TS_LEN);
            int by_name = strcmp(prev->name, key.name);
            if (by_fail > 0 || (by_fail == 0 && by_ts < 0) ||
                (by_fail == 0 && by_ts == 0 && by_name > 0)) {
                t->items[b] = t->items[b - 1];
                b--;
            } else {
                break;
            }
        }
        t->items[b] = key;
    }
}

/* Renders the bounded groups array; false on allocation failure. */
static bool dth_render_groups(struct dth_table *t, int64_t limit,
                              struct json_value *groups, bool *truncated)
{
    size_t listed = 0;
    for (size_t i = 0; i < t->n; i++) {
        if (t->items[i].fail == 0)
            continue;
        if ((int64_t)listed >= limit) {
            *truncated = true;
            break;
        }
        struct dth_group *g = &t->items[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        if (!json_push_kv_str(&entry, "group", g->name) ||
            !json_push_kv_int(&entry, "attempts", g->attempts) ||
            !json_push_kv_int(&entry, "fail", g->fail) ||
            !json_push_kv_int(&entry, "flaky", g->flaky) ||
            !json_push_kv_str(&entry, "last_fail_ts", g->last_fail_ts) ||
            !json_push_kv_int(&entry, "last_fail_rc", g->last_fail_rc) ||
            !json_push_kv_str(&entry, "last_fail_tree", g->last_fail_tree) ||
            !json_push_back(groups, &entry)) {
            json_free(&entry);
            return false;
        }
        json_free(&entry);
        listed++;
    }
    return true;
}

/* Validates ledger/since/limit, refusing BAD_INPUT shapes; false means
 * the reply already carries the refusal. */
static bool dth_parse_inputs(struct zcl_command_reply *reply,
                             const struct json_value *input,
                             const char **ledger_out, const char **since_out,
                             int64_t *limit_out)
{
    const struct json_value *ledger_value = json_get(input, "ledger");
    if (ledger_value && ledger_value->type != JSON_STR) {
        dth_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate",
                   "input key 'ledger' must be a string path when present",
                   "dev.test.history reads one named JSONL ledger",
                   "drop 'ledger' or name one file");
        return false;
    }
    const char *ledger = ledger_value ? json_get_str(ledger_value) : NULL;
    if (ledger && !ledger[0]) {
        dth_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate",
                   "input key 'ledger' must be a nonempty path when present",
                   "dev.test.history reads one named JSONL ledger",
                   "drop 'ledger' or name one file");
        return false;
    }
    *ledger_out = ledger ? ledger : DTH_DEFAULT_LEDGER;

    const struct json_value *since_value = json_get(input, "since");
    *since_out = since_value ? json_get_str(since_value) : NULL;
    if (since_value && !zcl_ledger_since_valid(*since_out)) {
        dth_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate",
                   "input key 'since' must be ISO-8601 UTC "
                   "YYYY-MM-DDTHH:MM:SSZ",
                   "dev.test.history time filter",
                   "rerun with --since=2026-11-17T00:00:00Z");
        return false;
    }

    *limit_out = DTH_LIMIT_DEFAULT;
    const struct json_value *lv = json_get(input, "limit");
    if (lv) {
        if (lv->type != JSON_INT ||
            json_get_int(lv) < 1 || json_get_int(lv) > DTH_LIMIT_MAX) {
            dth_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                       "validate",
                       "input key 'limit' must be an integer from 1 to 200",
                       "dev.test.history reply bound",
                       "drop 'limit' or pass --limit=20");
            return false;
        }
        *limit_out = json_get_int(lv);
    }
    return true;
}

/* The true zero: no ledger means no group ever executed here. Reported as
 * exactly that — never as an error, never as a guess. */
static void dth_reply_missing(struct zcl_command_reply *reply)
{
    (void)json_push_kv_bool(&reply->data, "exists", false);
    (void)json_push_kv_int(&reply->data, "rows", 0);
    (void)json_push_kv_int(&reply->data, "malformed", 0);
    (void)json_push_kv_int(&reply->data, "failing_groups", 0);
    (void)json_push_kv_bool(&reply->data, "truncated", false);
    struct json_value groups;
    json_init(&groups);
    json_set_array(&groups);
    (void)json_push_kv(&reply->data, "groups", &groups);
    json_free(&groups);
}

void zcl_native_handle_dev_test_history(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DTH_LEAF);

    const char *ledger = NULL, *since = NULL;
    int64_t limit = DTH_LIMIT_DEFAULT;
    if (!dth_parse_inputs(reply, request ? request->input : NULL, &ledger,
                          &since, &limit))
        return;

    (void)json_push_kv_str(&reply->data, "ledger", ledger);

    FILE *fp = fopen(ledger, "r");
    if (!fp) {
        if (errno != ENOENT) {
            char msg[512];
            (void)snprintf(msg, sizeof(msg),
                           "ledger '%s' cannot be opened: %s", ledger,
                           strerror(errno));
            dth_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "LEDGER_UNREADABLE",
                       "read", msg, "dev.test.history reads one named file",
                       "check the ledger path and permissions, then rerun");
            return;
        }
        dth_reply_missing(reply);
        return;
    }

    struct dth_table table;
    memset(&table, 0, sizeof(table));
    struct dth_scan scan = {0};
    dth_scan_ledger(fp, since, &table, &scan);
    if (!scan.read_ok) {
        char msg[512];
        (void)snprintf(msg, sizeof(msg),
                       "ledger '%s' failed while being read", ledger);
        dth_table_free(&table);
        dth_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "LEDGER_UNREADABLE",
                   "read", msg, "dev.test.history reads one named file",
                   "check the ledger file, then rerun");
        return;
    }
    if (!scan.alloc_ok) {
        dth_table_free(&table);
        dth_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while aggregating the ledger",
                   "dev.test.history per-group table",
                   "retry with a smaller ledger");
        return;
    }

    dth_sort_groups(&table);
    int64_t failing = 0;
    for (size_t i = 0; i < table.n; i++) {
        if (table.items[i].fail > 0)
            failing++;
    }

    (void)json_push_kv_bool(&reply->data, "exists", true);
    (void)json_push_kv_int(&reply->data, "rows", scan.rows);
    (void)json_push_kv_int(&reply->data, "malformed", scan.malformed);
    (void)json_push_kv_int(&reply->data, "failing_groups", failing);

    struct json_value groups;
    json_init(&groups);
    json_set_array(&groups);
    bool truncated = false;
    bool rendered = dth_render_groups(&table, limit, &groups, &truncated);
    if (rendered) {
        (void)json_push_kv_bool(&reply->data, "truncated", truncated);
        (void)json_push_kv(&reply->data, "groups", &groups);
    }
    json_free(&groups);
    dth_table_free(&table);
    if (!rendered) {
        dth_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while rendering the groups table",
                   "dev.test.history groups array",
                   "retry with a smaller limit");
        return;
    }
}
