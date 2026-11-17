/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.outcomes — route units to models from the unit-outcome
 *          ledger, so "which model gets which unit" is read from receipts.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Which executor gets which unit is currently a paragraph someone
 * remembers. The fleet already appends one JSON object per finished unit to
 * a shared ledger; this leaf reads that ledger and answers the routing
 * question from receipts, never from prose.
 *
 * INPUT (zcl.agent_outcomes_input.v1)
 *   ledger  REQUIRED string. Path to the JSONL ledger file, read as given.
 *   model   optional string. When present, only rows naming that model are
 *           aggregated; rows/malformed still describe the whole file.
 *   since   optional string. ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ". Rows whose
 *           ts compares below it are ignored. A present-but-misshapen since
 *           is BAD_INPUT, never a silent unfiltered read.
 *   usage_log optional string. A JSONL file or directory of model-host
 *           usage logs; adds a "usage" object. Contract and formats live in
 *           native_devagent_usage.c.
 *
 * LEDGER ROW (one JSON object per line; unknown keys ignored)
 *   {"ts":"2026-09-04T02:25:37Z","unit":"situation/a1","model":"glm-5.3-flash",
 *    "verdict":"PASS","files_changed":1,"groups_ran":1,"groups_failed":0,
 *    "completion_tokens":22844,"why":""}
 * Verdicts: PASS, FAIL, UNVERIFIED, TIMEOUT, NO_RECEIPT. `why` is a short
 * failure-class string (rate_limited, response_refused, circuit) or empty.
 * A line that is not one JSON object is counted in `malformed` and skipped,
 * never fatal. Blank lines are skipped silently. A row that names no model
 * is counted in `rows` but attributed to no executor.
 *
 * OUTPUT (zcl.agent_outcomes.v1) on ok=true
 *   leaf        "dev.agent.outcomes"
 *   ledger      the ledger path as given
 *   rows        well-formed rows read (before model/since filtering)
 *   malformed   lines skipped for not being one JSON object
 *   by_model    first-seen order: {model, attempts, pass, fail, unverified,
 *               no_receipt, timeout, pass_rate (pass/attempts, 0 when none),
 *               completion_tokens_total, why:[{why, count}] by count desc}
 *   recommendation  one "<model>: route <kind>" string per model with
 *               attempts >= 3 — "one-file units with a pinned test" when
 *               pass_rate >= 0.5, "doc-only units" when unverified > pass,
 *               "nothing until quota recovers" when the most common why is
 *               rate_limited, else "review before routing" — followed by the
 *               constant closing line "verdicts come from receipts; a model's
 *               own report is never evidence".
 *
 * FAILURE. A missing ledger key is ok=false, status "BAD_INPUT". A ledger
 * that does not exist is "LEDGER_NOT_FOUND"; one that cannot be opened or
 * read is "LEDGER_UNREADABLE". All name the path.
 *
 * PROCESS RULE. This leaf runs no process and writes nothing. popen(),
 * system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_outcomes.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"
#include "command/native_devagent_usage_internal.h"
#include "native_ledger_reader_internal.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVO_LEAF "dev.agent.outcomes"
#define DVO_LINE_MAX 8192u
#define DVO_SINCE_LEN 20u
#define DVO_MIN_ATTEMPTS 3
#define DVO_CLOSING \
    "verdicts come from receipts; a model's own report is never evidence"

struct dvo_why {
    char *name;
    int64_t count;
};

struct dvo_model {
    char *name;
    int64_t attempts;
    int64_t pass;
    int64_t fail;
    int64_t unverified;
    int64_t no_receipt;
    int64_t timeout;
    int64_t tokens;
    struct dvo_why *whys;
    size_t nwhy;
    size_t capwhy;
};

struct dvo_table {
    struct dvo_model *items;
    size_t n;
    size_t cap;
};

static void dvo_table_free(struct dvo_table *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < t->n; i++) {
        free(t->items[i].name);
        for (size_t j = 0; j < t->items[i].nwhy; j++)
            free(t->items[i].whys[j].name);
        free(t->items[i].whys);
    }
    free(t->items);
    t->items = NULL;
    t->n = 0;
    t->cap = 0;
}

static struct dvo_model *dvo_find_or_add(struct dvo_table *t, const char *name)
{
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->items[i].name, name) == 0)
            return &t->items[i];
    }
    if (t->n == t->cap) {
        size_t next = t->cap ? t->cap * 2u : 8u;
        struct dvo_model *grown = zcl_realloc(t->items,
                                             next * sizeof(*grown),
                                             "devagent_outcomes_models");
        if (!grown)
            return NULL;
        t->items = grown;
        t->cap = next;
    }
    struct dvo_model *m = &t->items[t->n];
    memset(m, 0, sizeof(*m));
    m->name = zcl_strdup(name, "devagent_outcomes_model");
    if (!m->name)
        return NULL;
    t->n++;
    return m;
}

static bool dvo_add_why(struct dvo_model *m, const char *why)
{
    if (!why || !why[0])
        return true;
    for (size_t i = 0; i < m->nwhy; i++) {
        if (strcmp(m->whys[i].name, why) == 0) {
            m->whys[i].count++;
            return true;
        }
    }
    if (m->nwhy == m->capwhy) {
        size_t next = m->capwhy ? m->capwhy * 2u : 4u;
        struct dvo_why *grown = zcl_realloc(m->whys, next * sizeof(*grown),
                                           "devagent_outcomes_whys");
        if (!grown)
            return false;
        m->whys = grown;
        m->capwhy = next;
    }
    m->whys[m->nwhy].name = zcl_strdup(why, "devagent_outcomes_why");
    if (!m->whys[m->nwhy].name)
        return false;
    m->whys[m->nwhy].count = 1;
    m->nwhy++;
    return true;
}

/* ISO-8601 UTC of exactly the ledger shape: "YYYY-MM-DDTHH:MM:SSZ"
 * (zcl_ledger_since_valid in native_ledger_reader_internal.h). */

static void dvo_refuse(struct zcl_command_reply *reply,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, const char *message,
                       const char *evidence, const char *next_action,
                       bool human)
{
    (void)fprintf(stderr, "dev.agent.outcomes: %s: %s\n", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, false, message, evidence);
    if (next_action)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s", next_action);
    reply->error.human_action_required = human;
}

/* Blank-line test: zcl_ledger_line_blank (native_ledger_reader_internal.h). */

/* Reads the optional string filter `key`; false with the reply refused when
 * it is present but not acceptable. */
static bool dvo_read_filter(struct zcl_command_reply *reply,
                            const struct json_value *input, const char *key,
                            bool (*valid)(const char *text),
                            const char *message, const char *evidence,
                            const char *next, const char **out)
{
    const struct json_value *v = json_get(input, key);
    *out = NULL;
    if (!v)
        return true;
    const char *text = json_get_str(v);
    if (v->type != JSON_STR || !valid(text)) {
        dvo_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate",
                   message, evidence, next, false);
        return false;
    }
    *out = text;
    return true;
}

static bool dvo_nonempty(const char *text) { return text[0] != '\0'; }

static void dvo_refuse_open(struct zcl_command_reply *reply, const char *ledger)
{
    char msg[512];
    (void)snprintf(msg, sizeof(msg), "ledger '%s' cannot be opened: %s",
                   ledger, strerror(errno));
    if (errno == ENOENT) {
        char next[640];
        (void)snprintf(next, sizeof(next),
                       "append unit rows to %s, then rerun", ledger);
        dvo_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "LEDGER_NOT_FOUND",
                   "read", msg, "dev.agent.outcomes reads one named file",
                   next, true);
    } else {
        dvo_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "LEDGER_UNREADABLE",
                   "read", msg, "dev.agent.outcomes reads one named file",
                   "check the ledger path and permissions, then rerun", true);
    }
}

/* Adds one ledger row to the per-model table; false on allocation failure. */
static bool dvo_tally_row(struct dvo_table *table, const struct json_value *row,
                          const char *filter, const char *since)
{
    const char *mname = json_get_str(json_get(row, "model"));
    bool keep = mname[0] != '\0' && (!filter || strcmp(mname, filter) == 0);
    if (keep && since) {
        const char *ts = json_get_str(json_get(row, "ts"));
        keep = strlen(ts) >= DVO_SINCE_LEN &&
               strncmp(ts, since, DVO_SINCE_LEN) >= 0;
    }
    if (!keep)
        return true;
    struct dvo_model *m = dvo_find_or_add(table, mname);
    const char *verdict = json_get_str(json_get(row, "verdict"));
    const char *why = json_get_str(json_get(row, "why"));
    int64_t tokens = json_get_int(json_get(row, "completion_tokens"));
    if (!m || !dvo_add_why(m, why))
        return false;
    m->attempts++;
    if (strcmp(verdict, "PASS") == 0)
        m->pass++;
    else if (strcmp(verdict, "FAIL") == 0)
        m->fail++;
    else if (strcmp(verdict, "UNVERIFIED") == 0)
        m->unverified++;
    else if (strcmp(verdict, "NO_RECEIPT") == 0)
        m->no_receipt++;
    else if (strcmp(verdict, "TIMEOUT") == 0)
        m->timeout++;
    if (tokens > 0)
        m->tokens += tokens;
    return true;
}

struct dvo_scan {
    int64_t rows, malformed;
    bool alloc_ok, read_ok;
};

static void dvo_scan_ledger(FILE *fp, const char *filter, const char *since,
                            struct dvo_table *table, struct dvo_scan *scan)
{
    char line[DVO_LINE_MAX];
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
        bool tallied = dvo_tally_row(table, &row, filter, since);
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

/* Failure classes, most common first; ties read A-first. */
static void dvo_sort_whys(struct dvo_model *m)
{
    for (size_t a = 1; a < m->nwhy; a++) {
        struct dvo_why key = m->whys[a];
        size_t b = a;
        while (b > 0 && (m->whys[b - 1].count < key.count ||
                         (m->whys[b - 1].count == key.count &&
                          strcmp(m->whys[b - 1].name, key.name) > 0))) {
            m->whys[b] = m->whys[b - 1];
            b--;
        }
        m->whys[b] = key;
    }
}

static void dvo_push_model(struct json_value *by_model,
                           const struct dvo_model *m, double rate)
{
    struct json_value entry;
    json_init(&entry);
    json_set_object(&entry);
    (void)json_push_kv_str(&entry, "model", m->name);
    (void)json_push_kv_int(&entry, "attempts", m->attempts);
    (void)json_push_kv_int(&entry, "pass", m->pass);
    (void)json_push_kv_int(&entry, "fail", m->fail);
    (void)json_push_kv_int(&entry, "unverified", m->unverified);
    (void)json_push_kv_int(&entry, "no_receipt", m->no_receipt);
    (void)json_push_kv_int(&entry, "timeout", m->timeout);
    (void)json_push_kv_real(&entry, "pass_rate", rate);
    (void)json_push_kv_int(&entry, "completion_tokens_total", m->tokens);
    struct json_value whys;
    json_init(&whys);
    json_set_array(&whys);
    for (size_t j = 0; j < m->nwhy; j++) {
        struct json_value wrow;
        json_init(&wrow);
        json_set_object(&wrow);
        (void)json_push_kv_str(&wrow, "why", m->whys[j].name);
        (void)json_push_kv_int(&wrow, "count", m->whys[j].count);
        (void)json_push_back(&whys, &wrow);
        json_free(&wrow);
    }
    (void)json_push_kv(&entry, "why", &whys);
    json_free(&whys);
    (void)json_push_back(by_model, &entry);
    json_free(&entry);
}

static const char *dvo_route_kind(const struct dvo_model *m, double rate)
{
    if (rate >= 0.5)
        return "one-file units with a pinned test";
    if (m->unverified > m->pass)
        return "doc-only units";
    if (m->nwhy > 0 && strcmp(m->whys[0].name, "rate_limited") == 0)
        return "nothing until quota recovers";
    return "review before routing";
}

/* Appends "<model>: route <kind>"; false on allocation failure. */
static bool dvo_push_recommendation(struct json_value *recommendation,
                                    const struct dvo_model *m, double rate)
{
    const char *kind = dvo_route_kind(m, rate);
    size_t need = strlen(m->name) + strlen(": route ") + strlen(kind) + 1u;
    char *text = zcl_malloc(need, "devagent_outcomes_line");
    if (!text)
        return false;
    (void)snprintf(text, need, "%s: route %s", m->name, kind);
    struct json_value line_value;
    json_init(&line_value);
    json_set_str(&line_value, text);
    free(text);
    (void)json_push_back(recommendation, &line_value);
    json_free(&line_value);
    return true;
}

/* Fills by_model and recommendation from the table; false on allocation
 * failure. */
static bool dvo_render_table(struct dvo_table *table,
                             struct json_value *by_model,
                             struct json_value *recommendation)
{
    for (size_t i = 0; i < table->n; i++) {
        struct dvo_model *m = &table->items[i];
        dvo_sort_whys(m);
        double rate = m->attempts > 0 ? (double)m->pass / (double)m->attempts
                                      : 0.0;
        dvo_push_model(by_model, m, rate);
        if (m->attempts >= DVO_MIN_ATTEMPTS &&
            !dvo_push_recommendation(recommendation, m, rate))
            return false;
    }
    return true;
}

void zcl_native_handle_dev_agent_outcomes(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVO_LEAF);

    const struct json_value *input = request ? request->input : NULL;
    const char *ledger = json_get_str(json_get(input, "ledger"));
    if (!ledger || !ledger[0]) {
        dvo_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate",
                   "missing required input key 'ledger'",
                   "dev.agent.outcomes reads one named JSONL ledger",
                   "rerun with --ledger=<path-to-outcomes.jsonl>", false);
        return;
    }

    const char *filter = NULL;
    const char *since = NULL;
    if (!dvo_read_filter(reply, input, "model", dvo_nonempty,
                         "input key 'model' must be a nonempty string",
                         "dev.agent.outcomes model filter",
                         "drop 'model' or name one model", &filter) ||
        !dvo_read_filter(
            reply, input, "since", zcl_ledger_since_valid,
            "input key 'since' must be ISO-8601 UTC YYYY-MM-DDTHH:MM:SSZ",
            "dev.agent.outcomes time filter",
            "rerun with --since=2026-09-04T02:25:37Z", &since))
        return;

    FILE *fp = fopen(ledger, "r");
    if (!fp) {
        dvo_refuse_open(reply, ledger);
        return;
    }

    struct dvo_table table;
    memset(&table, 0, sizeof(table));
    struct dvo_scan scan = {0};
    dvo_scan_ledger(fp, filter, since, &table, &scan);
    if (!scan.read_ok) {
        char msg[512];
        (void)snprintf(msg, sizeof(msg),
                       "ledger '%s' failed while being read", ledger);
        dvo_table_free(&table);
        dvo_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "LEDGER_UNREADABLE",
                   "read", msg, "dev.agent.outcomes reads one named file",
                   "check the ledger file, then rerun", true);
        return;
    }
    if (!scan.alloc_ok) {
        dvo_table_free(&table);
        dvo_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while aggregating the ledger",
                   "dev.agent.outcomes per-model table",
                   "retry with a smaller ledger", false);
        return;
    }

    (void)json_push_kv_str(&reply->data, "ledger", ledger);
    (void)json_push_kv_int(&reply->data, "rows", scan.rows);
    (void)json_push_kv_int(&reply->data, "malformed", scan.malformed);

    struct json_value by_model;
    json_init(&by_model);
    json_set_array(&by_model);
    struct json_value recommendation;
    json_init(&recommendation);
    json_set_array(&recommendation);
    if (!dvo_render_table(&table, &by_model, &recommendation)) {
        json_free(&by_model);
        json_free(&recommendation);
        dvo_table_free(&table);
        dvo_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while rendering recommendations",
                   "dev.agent.outcomes recommendation array",
                   "retry with a smaller ledger", false);
        return;
    }
    struct json_value closing;
    json_init(&closing);
    json_set_str(&closing, DVO_CLOSING);
    (void)json_push_back(&recommendation, &closing);
    json_free(&closing);
    (void)json_push_kv(&reply->data, "by_model", &by_model);
    json_free(&by_model);
    (void)json_push_kv(&reply->data, "recommendation", &recommendation);
    json_free(&recommendation);
    dvo_table_free(&table);
    dvu_push_usage(input, filter, since, reply);
}
