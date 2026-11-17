/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.proof.lint_catches — which lint gates caught nothing
 *          recently, and each gate's catch count, read from the lint
 *          driver's persistent gate-catch ledger.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────
 *
 * WHY. FORWARD_PLAN item 3 says a gate with no catch in four weeks moves
 * to a scheduled sweep — but nothing counted catches. `z23-lint run`
 * therefore appends one zcl.lint_gate_catches.v1 line per EXECUTED gate
 * to .cache/lint-timing/gate-catches.jsonl (written by
 * tools/lint/lintc/run_report.c); this leaf reads that ledger back and
 * answers the measurement question from receipts, never from memory.
 * It is the only change: no sweep policy, no gate selection, no land or
 * proof wiring reads this. The ledger records; it never decides. It
 * lives under dev.proof because the catch ledger measures the gates the
 * land proof runs; the input, refusal and counter shapes are the shared
 * ledger-reader internals (native_ledger_reader_internal.h) already
 * used by dev.test.history and dev.agent.outcomes.
 *
 * INPUT (zcl.dev_lint_catches_input.v1)
 *   ledger  optional string. The JSONL ledger, read as given. Absent
 *           means the driver's conventional .cache/lint-timing/
 *           gate-catches.jsonl.
 *   since   optional string. ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ". Rows
 *           whose ts compares below it are ignored for the table — the
 *           last-N-days question is since = now minus N days. Absent
 *           means the whole ledger. A present-but-misshapen since is
 *           BAD_INPUT, never a silent unfiltered read.
 *   limit   optional integer 1..200. Bounds the gates and zero_catch
 *           arrays. Default 20. Out of range is BAD_INPUT.
 *
 * LEDGER ROW (one JSON object per line; unknown keys ignored)
 *   {"ts":"2026-11-17T18:00:00Z","gate":"check-x","rc":3,"ms":12}
 * A catch is rc != 0. A line that is not one JSON object is counted in
 * `malformed` and skipped, never fatal. Blank lines are skipped
 * silently. A gate absent from the window has no row here and is not
 * listed: no data is reported as no data, never as a zero.
 *
 * OUTPUT (zcl.dev_lint_catches.v1) on ok=true
 *   leaf            "dev.proof.lint_catches"
 *   ledger          the ledger path read
 *   since           the window cutoff as given, echoed only when present
 *   exists          false when the ledger file was absent — a TRUE ZERO:
 *                   rows 0, malformed 0, kept 0, zero_catch_count 0 and
 *                   empty arrays. A missing ledger is reported as
 *                   exactly that, never as a guess or an error.
 *   rows            well-formed rows read (before the window filter)
 *   malformed       lines skipped for not being one JSON object
 *   kept            rows inside the window
 *   zero_catch_count distinct gates with kept rows and no catch among them
 *   truncated       true when limit cut rows from either array
 *   gates           catches first: {gate, attempts, catches,
 *                   last_catch_ts, last_catch_rc} (the shared counter's
 *                   events/last_event fields), sorted catches desc,
 *                   then most-recent catch desc, then name. attempts
 *                   counts every kept row of the gate; the last_catch_*
 *                   fields are "" and 0 when it never caught.
 *   zero_catch      the names of the zero-catch gates, same bound
 *
 * FAILURE. A ledger that exists but cannot be read is
 * LEDGER_UNREADABLE. A bad since or limit is BAD_INPUT. A missing ledger
 * is NOT a failure.
 *
 * PROCESS RULE. This leaf runs no process and writes nothing. popen(),
 * system() and a shell command string are forbidden and gated.
 *
 * The acceptance bar is tests/harness/src/test_devlintcatches.c.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "native_ledger_reader_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLC_LEAF "dev.proof.lint_catches"
#define DLC_DEFAULT_LEDGER ".cache/lint-timing/gate-catches.jsonl"
#define DLC_LINE_MAX 8192u
#define DLC_LIMIT_MAX 200

/* Adds one ledger row inside the window to the table; false on
 * allocation failure. */
static bool dlc_tally_row(struct zcl_ledger_counter_table *table,
                          const struct json_value *row)
{
    const char *name = json_get_str(json_get(row, "gate"));
    const char *ts = json_get_str(json_get(row, "ts"));
    if (!name[0])
        return true;
    struct zcl_ledger_counter *g =
        zcl_ledger_counter_find_or_add(table, name, "dev_lint_catches_gates");
    if (!g)
        return false;
    g->attempts++;
    int64_t rc = json_get_int(json_get(row, "rc"));
    if (rc == 0)
        return true;
    g->events++;
    if (strncmp(ts, g->last_event_ts, ZCL_LEDGER_TS_LEN) > 0) {
        (void)snprintf(g->last_event_ts, sizeof(g->last_event_ts), "%.*s",
                       (int)ZCL_LEDGER_TS_LEN, ts);
        g->last_event_rc = rc;
    }
    return true;
}

/* A row is kept when its ts is at or after the cutoff; no cutoff keeps
 * everything. A row outside the window counts nowhere: absence of data
 * stays absence. */
static bool dlc_row_kept(const struct json_value *row, const char *since)
{
    const char *ts = json_get_str(json_get(row, "ts"));
    if (!since)
        return true;
    return strlen(ts) >= ZCL_LEDGER_TS_LEN &&
           strncmp(ts, since, ZCL_LEDGER_TS_LEN) >= 0;
}

struct dlc_scan {
    int64_t rows, malformed, kept;
    bool alloc_ok, read_ok;
};

static void dlc_scan_ledger(FILE *fp, const char *since,
                            struct zcl_ledger_counter_table *table,
                            struct dlc_scan *scan)
{
    char line[DLC_LINE_MAX];
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
        bool kept = dlc_row_kept(&row, since);
        bool tallied = true;
        if (kept) {
            tallied = dlc_tally_row(table, &row);
            if (tallied)
                scan->kept++;
        }
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

/* Renders the bounded gates array; false on allocation failure. */
static bool dlc_render_gates(struct zcl_ledger_counter_table *t, int64_t limit,
                             struct json_value *gates, bool *truncated)
{
    size_t listed = 0;
    for (size_t i = 0; i < t->n; i++) {
        if ((int64_t)listed >= limit) {
            *truncated = true;
            break;
        }
        struct zcl_ledger_counter *g = &t->items[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        if (!json_push_kv_str(&entry, "gate", g->name) ||
            !json_push_kv_int(&entry, "attempts", g->attempts) ||
            !json_push_kv_int(&entry, "catches", g->events) ||
            !json_push_kv_str(&entry, "last_catch_ts", g->last_event_ts) ||
            !json_push_kv_int(&entry, "last_catch_rc", g->last_event_rc) ||
            !json_push_back(gates, &entry)) {
            json_free(&entry);
            return false;
        }
        json_free(&entry);
        listed++;
    }
    return true;
}

/* Renders the bounded zero_catch names array; false on allocation
 * failure. A gate with kept rows and zero catches among them. */
static bool dlc_render_zero(struct zcl_ledger_counter_table *t, int64_t limit,
                            struct json_value *zero, bool *truncated)
{
    size_t listed = 0;
    for (size_t i = 0; i < t->n; i++) {
        if (t->items[i].events != 0)
            continue;
        if ((int64_t)listed >= limit) {
            *truncated = true;
            break;
        }
        struct json_value name;
        json_init(&name);
        json_set_str(&name, t->items[i].name);
        if (!json_push_back(zero, &name)) {
            json_free(&name);
            return false;
        }
        listed++;
    }
    return true;
}

/* The true zero: no ledger means no gate ever ran here. Reported as
 * exactly that — never as an error, never as a guess. */
static void dlc_reply_missing(struct zcl_command_reply *reply)
{
    (void)json_push_kv_bool(&reply->data, "exists", false);
    (void)json_push_kv_int(&reply->data, "rows", 0);
    (void)json_push_kv_int(&reply->data, "malformed", 0);
    (void)json_push_kv_int(&reply->data, "kept", 0);
    (void)json_push_kv_int(&reply->data, "zero_catch_count", 0);
    (void)json_push_kv_bool(&reply->data, "truncated", false);
    struct json_value empty;
    json_init(&empty);
    json_set_array(&empty);
    (void)json_push_kv(&reply->data, "gates", &empty);
    json_free(&empty);
    json_init(&empty);
    json_set_array(&empty);
    (void)json_push_kv(&reply->data, "zero_catch", &empty);
    json_free(&empty);
}

void zcl_native_handle_dev_lint_catches(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DLC_LEAF);

    const char *ledger = NULL, *since = NULL;
    int64_t limit = 20;
    if (!zcl_ledger_parse_reader_inputs(reply, DLC_LEAF,
                                        request ? request->input : NULL,
                                        DLC_DEFAULT_LEDGER, DLC_LIMIT_MAX,
                                        &ledger, &since, &limit))
        return;

    (void)json_push_kv_str(&reply->data, "ledger", ledger);
    if (since)
        (void)json_push_kv_str(&reply->data, "since", since);

    FILE *fp = fopen(ledger, "r");
    if (!fp) {
        if (errno != ENOENT) {
            char msg[512];
            (void)snprintf(msg, sizeof(msg),
                           "ledger '%s' cannot be opened: %s", ledger,
                           strerror(errno));
            zcl_ledger_refuse(reply, DLC_LEAF, ZCL_COMMAND_EXIT_FAILED,
                              "LEDGER_UNREADABLE", "read", msg,
                              "dev.proof.lint_catches reads one named file",
                              "check the ledger path and permissions, then rerun");
            return;
        }
        dlc_reply_missing(reply);
        return;
    }

    struct zcl_ledger_counter_table table;
    memset(&table, 0, sizeof(table));
    struct dlc_scan scan = {0};
    dlc_scan_ledger(fp, since, &table, &scan);
    if (!scan.read_ok) {
        char msg[512];
        (void)snprintf(msg, sizeof(msg),
                       "ledger '%s' failed while being read", ledger);
        zcl_ledger_counter_table_free(&table);
        zcl_ledger_refuse(reply, DLC_LEAF, ZCL_COMMAND_EXIT_FAILED,
                          "LEDGER_UNREADABLE", "read", msg,
                          "dev.proof.lint_catches reads one named file",
                          "check the ledger file, then rerun");
        return;
    }
    if (!scan.alloc_ok) {
        zcl_ledger_counter_table_free(&table);
        zcl_ledger_refuse(reply, DLC_LEAF, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                          "aggregate",
                          "out of memory while aggregating the ledger",
                          "dev.proof.lint_catches per-gate table",
                          "retry with a smaller ledger");
        return;
    }

    zcl_ledger_counter_sort_events_first(&table);
    int64_t zero = 0;
    for (size_t i = 0; i < table.n; i++) {
        if (table.items[i].events == 0)
            zero++;
    }

    (void)json_push_kv_bool(&reply->data, "exists", true);
    (void)json_push_kv_int(&reply->data, "rows", scan.rows);
    (void)json_push_kv_int(&reply->data, "malformed", scan.malformed);
    (void)json_push_kv_int(&reply->data, "kept", scan.kept);
    (void)json_push_kv_int(&reply->data, "zero_catch_count", zero);

    struct json_value gates, zero_names;
    json_init(&gates);
    json_set_array(&gates);
    json_init(&zero_names);
    json_set_array(&zero_names);
    bool truncated = false;
    bool rendered = dlc_render_gates(&table, limit, &gates, &truncated);
    if (rendered)
        rendered = dlc_render_zero(&table, limit, &zero_names, &truncated);
    if (rendered) {
        (void)json_push_kv_bool(&reply->data, "truncated", truncated);
        (void)json_push_kv(&reply->data, "gates", &gates);
        (void)json_push_kv(&reply->data, "zero_catch", &zero_names);
    }
    json_free(&gates);
    json_free(&zero_names);
    zcl_ledger_counter_table_free(&table);
    if (!rendered) {
        zcl_ledger_refuse(reply, DLC_LEAF, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                          "aggregate",
                          "out of memory while rendering the gates table",
                          "dev.proof.lint_catches arrays",
                          "retry with a smaller limit");
        return;
    }
}
