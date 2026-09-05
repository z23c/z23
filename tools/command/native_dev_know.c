/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.fleet.know — ask what the fleet has written down about a
 *          subject before acting on it. `z23 dev know` is its alias.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. The routing table, the landing rules and the proof-trap list were
 * prose across the docs/agent pages that every specialist re-read, re-pasted
 * and re-derived. They are rows now (engine/composition/fleet_facts.def), and
 * this is the one way to ask them. It reads that table and nothing else: no
 * file, no process, no node, no datadir.
 *
 * INPUT (zcl.dev_know_input.v1)
 *   subject       required string. A term from the table's closed vocabulary.
 *   relation      optional string. One of the declared relations.
 *   context       optional string. One of the declared contexts.
 *   budget_bytes  optional int, 256..16384, default 4096.
 *
 * OUTPUT (zcl.dev_know.v1) on ok=true
 *   leaf, subject, relation, context   the ask, echoed
 *   rows[]        {subject, relation, object, context, provenance,
 *                  confidence, why}
 *   row_count, total, truncated, unknown, budget_bytes
 *
 * RULE. A subject with no row is answered with ONE row whose confidence is
 * "unknown" — never an empty array, which a caller reads as a denial. A
 * relation or context outside the closed vocabulary is REFUSED with the whole
 * vocabulary in the message, because guessing which near-miss was meant is
 * how a table grows a second spelling of the same relation.
 *
 * BUDGET. Rows are emitted until the next one would take the reply past
 * budget_bytes. A cut always sets truncated:true and still reports `total`,
 * so no row is ever dropped silently.
 */

#include "command/native_command.h"

#include "fleetfacts/fleet_facts.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

#define DKN_LEAF "dev.fleet.know"
#define DKN_BUDGET_MIN 256
#define DKN_BUDGET_MAX 16384
#define DKN_BUDGET_DEFAULT 4096
/* Braces, seven keys and their quotes and commas, per row. Measured against
 * the emitted shape and rounded up: the budget must never promise a reply
 * smaller than the one that comes back. */
#define DKN_ROW_OVERHEAD 140

static const char *dkn_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;

    if (!v || v->type != JSON_STR || !json_get_str(v))
        return "";
    return json_get_str(v);
}

/* Join a closed vocabulary into one line, so a refusal teaches the caller the
 * whole set instead of only that its guess was wrong. */
static void dkn_join(char *out, size_t cap, size_t count,
                     const char *(*at)(size_t))
{
    size_t used = 0;

    if (cap == 0)
        return;
    out[0] = '\0';
    for (size_t i = 0; i < count; i++) {
        const char *name = at(i);
        int w;

        if (!name)
            continue;
        w = snprintf(out + used, cap - used, "%s%s", used ? ", " : "", name);
        if (w < 0 || (size_t)w >= cap - used)
            return;
        used += (size_t)w;
    }
}

static bool dkn_in_vocabulary(const char *want, size_t count,
                              const char *(*at)(size_t))
{
    for (size_t i = 0; i < count; i++) {
        const char *name = at(i);

        if (name && strcmp(name, want) == 0)
            return true;
    }
    return false;
}

static void dkn_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *message, const char *next_action)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "ask", false, false,
                           message, "engine/composition/fleet_facts.def");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action);
}

/* Refuse a filter the table cannot express, and say what it can. */
static bool dkn_reject_unknown_filter(struct zcl_command_reply *reply,
                                      const char *kind, const char *value,
                                      size_t count, const char *(*at)(size_t))
{
    char list[512];
    char msg[768];

    if (value[0] == '\0' || dkn_in_vocabulary(value, count, at))
        return false;
    dkn_join(list, sizeof(list), count, at);
    (void)snprintf(msg, sizeof(msg),
                   "'%s' is not a declared %s. The closed set is: %s", value,
                   kind, list);
    dkn_refuse(reply, "UNKNOWN_VOCABULARY", msg,
               "reask with one of the listed values, or add a row to "
               "engine/composition/fleet_facts.def");
    return true;
}

static size_t dkn_row_bytes(const struct zcl_fleet_fact_v1 *row)
{
    return strlen(row->subject) + strlen(row->relation) + strlen(row->object) +
           strlen(row->context) + strlen(row->why) + strlen(row->provenance) +
           DKN_ROW_OVERHEAD;
}

static void dkn_push_row(struct json_value *arr,
                         const struct zcl_fleet_fact_v1 *row)
{
    struct json_value obj;

    json_init(&obj);
    json_set_object(&obj);
    (void)json_push_kv_str(&obj, "subject", row->subject);
    (void)json_push_kv_str(&obj, "relation", row->relation);
    (void)json_push_kv_str(&obj, "object", row->object);
    (void)json_push_kv_str(&obj, "context", row->context);
    (void)json_push_kv_str(&obj, "provenance", row->provenance);
    (void)json_push_kv_str(&obj, "confidence",
                           zcl_fleet_facts_confidence_name(row->confidence));
    (void)json_push_kv_str(&obj, "why", row->why);
    (void)json_push_back(arr, &obj);
    json_free(&obj);
}

void zcl_native_handle_dev_know(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct zcl_fleet_facts_answer_v1 answer;
    struct json_value rows;
    const struct json_value *input = request ? request->input : NULL;
    const char *subject, *relation, *context;
    const struct json_value *budget_value;
    int64_t budget = DKN_BUDGET_DEFAULT;
    size_t used = 0, emitted = 0;

    if (!reply)
        return;

    subject = dkn_str(input, "subject");
    relation = dkn_str(input, "relation");
    context = dkn_str(input, "context");

    if (subject[0] == '\0') {
        dkn_refuse(reply, "SUBJECT_REQUIRED",
                   "dev.know answers about one subject and was given none",
                   "z23 dev know --subject <term>");
        return;
    }
    if (dkn_reject_unknown_filter(reply, "relation", relation,
                                  zcl_fleet_facts_relation_count(),
                                  zcl_fleet_facts_relation_at))
        return;
    if (dkn_reject_unknown_filter(reply, "context", context,
                                  zcl_fleet_facts_context_count(),
                                  zcl_fleet_facts_context_at))
        return;

    budget_value = input ? json_get(input, "budget_bytes") : NULL;
    if (budget_value && budget_value->type == JSON_INT)
        budget = json_get_int(budget_value);
    if (budget < DKN_BUDGET_MIN)
        budget = DKN_BUDGET_MIN;
    if (budget > DKN_BUDGET_MAX)
        budget = DKN_BUDGET_MAX;

    if (!zcl_fleet_facts_query(subject, relation, context,
                               ZCL_FLEET_FACTS_MAX_ROWS, &answer)) {
        dkn_refuse(reply, "ASK_MALFORMED",
                   "the fleet fact table refused this ask as malformed",
                   "z23 dev know --subject <term>");
        return;
    }

    (void)json_push_kv_str(&reply->data, "leaf", DKN_LEAF);
    (void)json_push_kv_str(&reply->data, "subject", subject);
    (void)json_push_kv_str(&reply->data, "relation", relation);
    (void)json_push_kv_str(&reply->data, "context", context);

    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < answer.row_count; i++) {
        size_t cost = dkn_row_bytes(&answer.rows[i]);

        /* The first row always goes out: an answer that fits in no budget is
         * still the answer, and a caller who set the budget too low must see
         * a row plus truncated:true, not an empty list. */
        if (emitted > 0 && used + cost > (size_t)budget)
            break;
        dkn_push_row(&rows, &answer.rows[i]);
        used += cost;
        emitted++;
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);

    (void)json_push_kv_int(&reply->data, "row_count", (int64_t)emitted);
    (void)json_push_kv_int(&reply->data, "total", (int64_t)answer.total);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            emitted < answer.total);
    (void)json_push_kv_bool(&reply->data, "unknown", answer.unknown);
    (void)json_push_kv_int(&reply->data, "budget_bytes", budget);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
