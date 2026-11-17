/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: shared internals for the JSONL outcome-ledger readers
 *          (dev.agent.outcomes, dev.test.history, dev.proof.lint_catches).
 *          One header so the leaves cannot drift on what a ledger line
 *          IS: blank lines are skipped silently, `since` is exactly the
 *          ISO-8601 UTC instant shape the writers emit, a refusal is
 *          one shape, ledger/since/limit inputs are validated one way,
 *          and the per-name counter table (attempts, events, the most
 *          recent event) is one implementation the tallying readers
 *          share. The helpers here are the duplicate-candidate floor's
 *          share point: a new ledger reader reuses them instead of
 *          growing a private copy of the same shapes.
 *
 * Include from exactly one .c per binary; everything here is static
 * inline and owns no state beyond what the caller hands it. The
 * refusal helper writes its one diagnostic line to stderr, exactly as
 * every reader did before the shape was shared. */

#ifndef ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H
#define ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H

#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Blank for ledger purposes: only spaces, tabs, CRs and newlines. */
static inline bool zcl_ledger_line_blank(const char *line)
{
    for (const char *p = line; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            return false;
    }
    return true;
}

/* ISO-8601 UTC of exactly the ledger shape: "YYYY-MM-DDTHH:MM:SSZ"
 * (20 characters, digit positions checked, separators fixed). */
static inline bool zcl_ledger_since_valid(const char *s)
{
    if (!s || strlen(s) != 20)
        return false;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z')
        return false;
    static const int digits[] = {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18};
    for (size_t i = 0; i < sizeof(digits) / sizeof(digits[0]); i++) {
        char c = s[digits[i]];
        if (c < '0' || c > '9')
            return false;
    }
    return true;
}

/* One ledger row's worth of a named counter: every kept row of the name
 * is one attempt; an `event` is the outcome the reader counts (a FAIL
 * verdict for test history, a non-zero rc for gate catches), with the
 * ts and rc of the most recent one. */
#define ZCL_LEDGER_TS_LEN 20u

struct zcl_ledger_counter {
    char *name;
    int64_t attempts;
    int64_t events;
    char last_event_ts[ZCL_LEDGER_TS_LEN + 1];
    int64_t last_event_rc;
};

struct zcl_ledger_counter_table {
    struct zcl_ledger_counter *items;
    size_t n;
    size_t cap;
};

static inline void zcl_ledger_counter_table_free(
    struct zcl_ledger_counter_table *t)
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

/* The name's slot, first-seen order; NULL only on allocation failure. */
static inline struct zcl_ledger_counter *zcl_ledger_counter_find_or_add(
    struct zcl_ledger_counter_table *t, const char *name, const char *owner)
{
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->items[i].name, name) == 0)
            return &t->items[i];
    }
    if (t->n == t->cap) {
        size_t next = t->cap ? t->cap * 2u : 16u;
        struct zcl_ledger_counter *grown =
            zcl_realloc(t->items, next * sizeof(*grown), owner);
        if (!grown)
            return NULL;
        t->items = grown;
        t->cap = next;
    }
    struct zcl_ledger_counter *c = &t->items[t->n];
    memset(c, 0, sizeof(*c));
    c->name = zcl_strdup(name, owner);
    if (!c->name)
        return NULL;
    t->n++;
    return c;
}

/* Events first, then most-recent event, then name: insertion sort, the
 * table holds at most a few hundred registry names. */
static inline void zcl_ledger_counter_sort_events_first(
    struct zcl_ledger_counter_table *t)
{
    for (size_t a = 1; a < t->n; a++) {
        struct zcl_ledger_counter key = t->items[a];
        size_t b = a;
        while (b > 0) {
            const struct zcl_ledger_counter *prev = &t->items[b - 1];
            int by_events = (prev->events < key.events) -
                            (prev->events > key.events);
            /* key precedes prev when key's event is NEWER, so a
             * lexicographically smaller prev timestamp swaps right. */
            int by_ts = strncmp(prev->last_event_ts, key.last_event_ts,
                                ZCL_LEDGER_TS_LEN);
            int by_name = strcmp(prev->name, key.name);
            if (by_events > 0 || (by_events == 0 && by_ts < 0) ||
                (by_events == 0 && by_ts == 0 && by_name > 0)) {
                t->items[b] = t->items[b - 1];
                b--;
            } else {
                break;
            }
        }
        t->items[b] = key;
    }
}

/* The readers' one refusal shape: the code and message on stderr, the
 * structured refusal on the reply, and the optional next action. */
static inline void zcl_ledger_refuse(struct zcl_command_reply *reply,
                                     const char *leaf,
                                     enum zcl_command_exit exit_code,
                                     const char *code, const char *phase,
                                     const char *message, const char *evidence,
                                     const char *next_action)
{
    (void)fprintf(stderr, "%s: %s: %s\n", leaf, code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, false, message, evidence);
    if (next_action)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s", next_action);
}

/* Validates the readers' shared ledger/since/limit inputs, refusing
 * BAD_INPUT shapes; false means the reply already carries the refusal.
 * `leaf` names the reader in the messages; `default_ledger` is the
 * conventional path used when no ledger key is present; `limit_max` is
 * the reader's own reply bound (the registry already bounds integers
 * to 1..1000000 before this runs). */
static inline bool zcl_ledger_parse_reader_inputs(
    struct zcl_command_reply *reply, const char *leaf,
    const struct json_value *input, const char *default_ledger,
    int64_t limit_max, const char **ledger_out, const char **since_out,
    int64_t *limit_out)
{
    const struct json_value *ledger_value = json_get(input, "ledger");
    if (ledger_value && ledger_value->type != JSON_STR) {
        zcl_ledger_refuse(reply, leaf, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                          "validate",
                          "input key 'ledger' must be a string path when present",
                          "%s reads one named JSONL ledger",
                          "drop 'ledger' or name one file");
        return false;
    }
    const char *ledger = ledger_value ? json_get_str(ledger_value) : NULL;
    if (ledger && !ledger[0]) {
        zcl_ledger_refuse(reply, leaf, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                          "validate",
                          "input key 'ledger' must be a nonempty path when present",
                          "%s reads one named JSONL ledger",
                          "drop 'ledger' or name one file");
        return false;
    }
    *ledger_out = ledger ? ledger : default_ledger;

    const struct json_value *since_value = json_get(input, "since");
    *since_out = since_value ? json_get_str(since_value) : NULL;
    if (since_value && !zcl_ledger_since_valid(*since_out)) {
        zcl_ledger_refuse(reply, leaf, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                          "validate",
                          "input key 'since' must be ISO-8601 UTC "
                          "YYYY-MM-DDTHH:MM:SSZ",
                          "%s time filter",
                          "rerun with --since=2026-11-17T00:00:00Z");
        return false;
    }

    *limit_out = 20;
    const struct json_value *lv = json_get(input, "limit");
    if (lv) {
        if (lv->type != JSON_INT || json_get_int(lv) < 1 ||
            json_get_int(lv) > limit_max) {
            zcl_ledger_refuse(reply, leaf, ZCL_COMMAND_EXIT_INVALID,
                              "BAD_INPUT", "validate",
                              "input key 'limit' must be an integer from 1 to 200",
                              "%s reply bound", "drop 'limit' or pass --limit=20");
            return false;
        }
        *limit_out = json_get_int(lv);
    }
    return true;
}

#endif /* ZCL_TOOLS_NATIVE_LEDGER_READER_INTERNAL_H */
