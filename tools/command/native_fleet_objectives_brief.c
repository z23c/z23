/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives.brief` leaf — turns the objective that
 *          `fleet objectives` would pick next into a zcl.work_card.v1-shaped
 *          card, from the per-objective row in
 *          engine/composition/objective_work.def.
 *
 * WHAT IT DECIDES. Nothing new: the pick is zcl_objectives_next over the
 * rows `fleet.objectives` itself measured. With runner_ok_only the rows are
 * first narrowed to the ones whose work row says an unattended runner may
 * take them, then the same function picks the largest-gap unmet row. The
 * leaf reads what fleet.objectives reads and writes nothing. */

#include "native_fleet_objectives.h"

#include "json/json.h"
#include "util/log_macros.h"
#include "command/work_card.h"

#include <stdio.h>
#include <string.h>

struct brief_work {
    const char *id;
    int runner_ok;
    const char *owned;
    const char *acceptance;
    const char *stop_if;
};

static const struct brief_work k_work[] = {
#define Z23_OBJECTIVE_WORK(id_, runner_ok_, owned_, acceptance_, stop_if_) \
    {id_, runner_ok_, owned_, acceptance_, stop_if_},
#include "../../engine/composition/objective_work.def"
#undef Z23_OBJECTIVE_WORK
};

/* Every card forbids these, whatever the objective: the consensus core, the
 * reducer, the wallet, and the land driver. */
#define BRIEF_FORBIDDEN \
    "core/,engine/reducer/,contexts/wallet/,tools/command/native_dev_land*"

static const struct brief_work *brief_find(const char *id)
{
    for (size_t i = 0; i < sizeof(k_work) / sizeof(k_work[0]); i++)
        if (id && strcmp(k_work[i].id, id) == 0)
            return &k_work[i];
    return NULL;
}

/* A boolean input. runner_ok_only is in the input validator's closed boolean
 * key list, so a CLI or MCP caller sends a JSON boolean; a direct caller that
 * skips the validator may still send "true" or "1" as text. Both count. */
static bool brief_flag(const struct zcl_command_request *request,
                       const char *key)
{
    const struct json_value *v;
    const char *s;
    if (!request || !request->input)
        return false;
    v = json_get(request->input, key);
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return json_get_bool(v);
    s = json_get_str(v);
    return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0);
}

/* Pushes `key`: an array of the comma-separated tokens of `csv`. */
static bool brief_push_csv(struct json_value *obj, const char *key,
                           const char *csv)
{
    struct json_value arr;
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    while (ok && *csv) {
        size_t n = strcspn(csv, ",");
        char token[256];
        struct json_value item;
        if (n >= sizeof(token))
            n = sizeof(token) - 1;
        memcpy(token, csv, n);
        token[n] = '\0';
        json_init(&item);
        json_set_str(&item, token);
        ok = json_push_back(&arr, &item);
        json_free(&item);
        csv += strcspn(csv, ",");
        if (*csv == ',')
            csv++;
    }
    ok = ok && json_push_kv(obj, key, &arr);
    json_free(&arr);
    return ok;
}

/* Pushes `key`: an array holding the one string `text`. */
static bool brief_push_one(struct json_value *obj, const char *key,
                           const char *text)
{
    struct json_value arr, item;
    bool ok;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&item);
    json_set_str(&item, text);
    ok = json_push_back(&arr, &item) && json_push_kv(obj, key, &arr);
    json_free(&item);
    json_free(&arr);
    return ok;
}

/* "objective-<id with '-' for '_'>", a kebab name a work card accepts. */
static void brief_name(const char *id, char *out, size_t cap)
{
    size_t n = (size_t)snprintf(out, cap, "objective-%s", id);
    if (n >= cap)
        n = cap - 1;
    for (size_t i = 0; i < n; i++)
        if (out[i] == '_')
            out[i] = '-';
}

static bool brief_push_objective(struct json_value *card,
                                 const struct json_value *next,
                                 const struct brief_work *work)
{
    struct json_value obj;
    bool ok;
    json_init(&obj);
    json_set_object(&obj);
    ok = json_push_kv_str(&obj, "id", work->id) &&
         json_push_kv_int(&obj, "value", json_get_int(json_get(next, "value"))) &&
         json_push_kv_int(&obj, "target",
                          json_get_int(json_get(next, "target"))) &&
         json_push_kv_real(&obj, "gap", json_get_real(json_get(next, "gap"))) &&
         json_push_kv_str(&obj, "unit", json_get_str(json_get(next, "unit"))) &&
         json_push_kv_str(&obj, "why", json_get_str(json_get(next, "why"))) &&
         json_push_kv_bool(&obj, "runner_ok", work->runner_ok != 0) &&
         json_push_kv(card, "objective", &obj);
    json_free(&obj);
    return ok;
}

/* Builds the card for the picked objective `next` into `card`. */
static bool brief_build(struct json_value *card, const struct json_value *next,
                        const struct brief_work *work)
{
    char name[WORK_CARD_NAME_MAX + 1], outcome[512];
    bool is_max = strcmp(json_get_str(json_get(next, "direction")), "max") == 0;
    brief_name(work->id, name, sizeof(name));
    (void)snprintf(outcome, sizeof(outcome),
                   "Move %s from %lld to %s %lld %s.", work->id,
                   (long long)json_get_int(json_get(next, "value")),
                   is_max ? "at least" : "at most",
                   (long long)json_get_int(json_get(next, "target")),
                   json_get_str(json_get(next, "unit")));
    return json_push_kv_str(card, "schema", WORK_CARD_SCHEMA_ID) &&
           json_push_kv_str(card, "name", name) &&
           json_push_kv_str(card, "level",
                            work->runner_ok ? "sonnet" : "opus") &&
           json_push_kv_str(card, "outcome", outcome) &&
           brief_push_csv(card, "owned", work->owned) &&
           brief_push_csv(card, "forbidden", BRIEF_FORBIDDEN) &&
           brief_push_one(card, "contract",
                          "Keep behaviour unchanged; never weaken a test, "
                          "assertion, threshold or baseline.") &&
           json_push_kv_str(card, "acceptance", work->acceptance) &&
           brief_push_one(card, "stop_if", work->stop_if) &&
           brief_push_objective(card, next, work);
}

/* The measured rows narrowed to `only_id` (when set) and to runner_ok rows
 * (when `runner_only`), as a new array. False on allocation failure. */
static bool brief_narrow(const struct json_value *rows, const char *only_id,
                         bool runner_only, struct json_value *out)
{
    json_set_array(out);
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        const char *id = json_get_str(json_get(row, "id"));
        const struct brief_work *work = brief_find(id);
        if (only_id && (!id || strcmp(id, only_id) != 0))
            continue;
        if (runner_only && (!work || !work->runner_ok))
            continue;
        if (!json_push_back(out, row)) {
            LOG_ERROR("fleet.objectives.brief",
                      "cannot narrow the objective rows: out of memory");
            return false;
        }
    }
    return true;
}

/* Why an explicit `id` gave no card: met, unmeasured, or not runner-ok. */
static void brief_refuse_id(struct zcl_command_reply *reply,
                            const struct json_value *rows, const char *id,
                            bool runner_only)
{
    char message[192];
    const char *status = "not in the measured rows";
    const struct brief_work *work = brief_find(id);
    for (size_t i = 0; i < rows->num_children; i++)
        if (strcmp(json_get_str(json_get(&rows->children[i], "id")), id) == 0)
            status = json_get_str(json_get(&rows->children[i], "status"));
    if (runner_only && work && !work->runner_ok)
        (void)snprintf(message, sizeof(message),
                       "objective %s is not runner_ok; a human takes it", id);
    else
        (void)snprintf(message, sizeof(message),
                       "objective %s has nothing to brief: status %.100s", id,
                       status);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "OBJECTIVE_NOT_ACTIONABLE",
                           "decide", false, false, message,
                           "z23-dev fleet objectives");
}

/* Fills the reply from the narrowed rows; the pick is zcl_objectives_next. */
static void brief_reply(struct zcl_command_reply *reply,
                        const struct json_value *rows, const char *id,
                        bool runner_only)
{
    struct json_value narrowed, next;
    const struct brief_work *work = NULL;
    bool ok;
    json_init(&narrowed);
    json_init(&next);
    ok = brief_narrow(rows, id, runner_only, &narrowed) &&
         zcl_objectives_next(&narrowed, &next);
    if (ok && !json_is_null(&next))
        work = brief_find(json_get_str(json_get(&next, "id")));
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BRIEF_ALLOC",
                               "decide", false, false,
                               "cannot build the pick: out of memory", "");
    } else if (json_is_null(&next) && id) {
        brief_refuse_id(reply, rows, id, runner_only);
    } else if (json_is_null(&next)) {
        (void)json_push_kv_str(&reply->data, "schema", WORK_CARD_SCHEMA_ID);
        (void)json_push_kv_str(&reply->data, "none",
                               runner_only
                                   ? "no runner_ok objective is measured and unmet"
                                   : "no objective is measured and unmet");
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    } else if (!work || !brief_build(&reply->data, &next, work)) {
        LOG_ERROR("fleet.objectives.brief", "no card for the picked objective %s",
                  json_get_str(json_get(&next, "id")));
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BRIEF_BUILD",
                               "decide", false, false,
                               "cannot build the work card for the pick", "");
    } else {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    }
    json_free(&next);
    json_free(&narrowed);
}

void zcl_native_handle_fleet_objectives_brief(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zcl_command_reply measured;
    const char *id = (request && request->input)
                         ? json_get_str(json_get(request->input, "id"))
                         : NULL;
    bool runner_only = brief_flag(request, "runner_ok_only");
    const struct json_value *rows;

    if (reply)
        zcl_command_reply_init(reply, WORK_CARD_SCHEMA_ID);
    if (!reply)
        return;
    if (id && !id[0])
        id = NULL;
    if (id && !brief_find(id)) {
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "unknown objective id '%.80s': not in the closed catalog",
                       id);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_OBJECTIVE",
                               "normalize", false, false, message,
                               "z23-dev fleet objectives lists every id");
        return;
    }
    memset(&measured, 0, sizeof(measured));
    zcl_native_handle_fleet_objectives(request, &measured);
    rows = json_get(&measured.data, "objectives");
    if (measured.status != ZCL_COMMAND_STATUS_PASSED || !rows) {
        LOG_ERROR("fleet.objectives.brief", "the objectives did not measure");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "OBJECTIVES_FAILED",
                               "decide", false, false,
                               "fleet.objectives could not measure the catalog",
                               "z23-dev fleet objectives");
    } else {
        brief_reply(reply, rows, id, runner_only);
    }
    zcl_command_reply_free(&measured);
}
