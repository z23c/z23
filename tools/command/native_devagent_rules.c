/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.rules — render the compiled agent rule table, whole or
 *          filtered to one checkout situation.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. The rules are DATA, in engine/composition/agent_rules.def, precisely
 * so no agent has to remember them and no second copy can drift. This leaf
 * is the only renderer of that table.
 *
 * SOURCE. Include "../../engine/composition/agent_rules.def" from this file with
 * ZCL_AGENT_SITUATION(id, test_prose) and ZCL_AGENT_RULE(id, situation,
 * value, say) defined locally, twice if convenient. Nothing is read from
 * disk; the table is compiled in and its row order is the report order.
 *
 * INPUT (zcl.agent_rules_input.v1)
 *   cwd        optional string, accepted and ignored here (every dev.agent
 *              leaf takes it so a caller can pass one input shape).
 *   situation  optional string. When present it must be a ZCL_AGENT_SITUATION
 *              id; the rules array is then only the rows whose `when` equals
 *              it. When absent every row is reported.
 *
 * OUTPUT (zcl.agent_rules.v1) on ok=true
 *   leaf        "dev.agent.rules"
 *   situations  array of {id, test} — every ZCL_AGENT_SITUATION row, always
 *               complete and never filtered.
 *   rules       array of {id, when, value, say} in table order, filtered when
 *               `situation` was given.
 *   count       number of elements in rules.
 *   source      "engine/composition/agent_rules.def"
 *   topics      ["push_target","commit_scope","gate_command","gate_skip",
 *                "force_push","history"] — in that order.
 *
 * FAILURE. A `situation` that is not a declared ZCL_AGENT_SITUATION id is
 * ok=false, status "UNKNOWN_SITUATION", with a message naming the value and
 * the declared ids. An empty result set is never reported as success.
 *
 * PROCESS RULE. This leaf runs no process at all. If it ever needs Git, use
 * zcl_spawn_capture() from util/spawn.h; popen(), system() and a shell
 * command string are forbidden and gated.
 *
 * Implement this file only; the test tools/harness/src/test_devagent_rules.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVR_LEAF "dev.agent.rules"

/* All topics, in the exact order the contract requires. */
static const char *const dvr_topics[] = {
    "push_target", "commit_scope", "gate_command",
    "gate_skip",   "force_push",   "history",
};
#define DVR_TOPIC_COUNT (sizeof(dvr_topics) / sizeof(dvr_topics[0]))

/* Every ZCL_AGENT_SITUATION id, so an unknown filter can be refused by name
 * and so its message can name what IS declared. */
static const char *const dvr_situations[] = {
#define ZCL_AGENT_SITUATION(id_, test_prose_) #id_,
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION
};
#define DVR_SITUATION_COUNT (sizeof(dvr_situations) / sizeof(dvr_situations[0]))

static bool dvr_known_situation(const char *situation)
{
    for (size_t i = 0; i < DVR_SITUATION_COUNT; i++) {
        if (strcmp(dvr_situations[i], situation) == 0)
            return true;
    }
    return false;
}

void zcl_native_handle_dev_agent_rules(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *filter = NULL;
    struct json_value situations, rules, topics, row;

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVR_LEAF);

    if (request && request->input) {
        const struct json_value *v = json_get(request->input, "situation");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            filter = json_get_str(v);
    }

    if (filter && !dvr_known_situation(filter)) {
        char msg[256];
        char known[192];
        size_t used = 0;

        known[0] = '\0';
        for (size_t i = 0; i < DVR_SITUATION_COUNT; i++) {
            int w = snprintf(known + used, sizeof(known) - used, "%s%s",
                             used == 0 ? "" : ", ", dvr_situations[i]);
            if (w < 0 || (size_t)w >= sizeof(known) - used)
                break;
            used += (size_t)w;
        }
        (void)snprintf(msg, sizeof(msg),
                       "unknown situation \"%s\"; declared situations: %s",
                       filter, known);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNKNOWN_SITUATION",
                               "resolve", false, false, msg,
                               "tools/command/native_devagent_rules.c");
        return;
    }

    json_init(&situations);
    json_set_array(&situations);
    json_init(&rules);
    json_set_array(&rules);
    json_init(&topics);
    json_set_array(&topics);
    json_init(&row);

#define ZCL_AGENT_SITUATION(id_, test_prose_)                                \
    do {                                                                     \
        json_set_object(&row);                                              \
        (void)json_push_kv_str(&row, "id", #id_);                           \
        (void)json_push_kv_str(&row, "test", test_prose_);                  \
        (void)json_push_back(&situations, &row);                            \
    } while (0);
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)                        \
    do {                                                                     \
        if (!filter || strcmp(filter, #situation_) == 0) {                  \
            json_set_object(&row);                                          \
            (void)json_push_kv_str(&row, "id", #id_);                       \
            (void)json_push_kv_str(&row, "when", #situation_);              \
            (void)json_push_kv_str(&row, "value", value_);                  \
            (void)json_push_kv_str(&row, "say", say_);                      \
            (void)json_push_back(&rules, &row);                             \
        }                                                                    \
    } while (0);
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION

    json_free(&row);

    /* topics is a plain array of strings. */
    for (size_t i = 0; i < DVR_TOPIC_COUNT; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, dvr_topics[i]);
        (void)json_push_back(&topics, &s);
        json_free(&s);
    }

    (void)json_push_kv(&reply->data, "situations", &situations);
    (void)json_push_kv(&reply->data, "rules", &rules);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)rules.num_children);
    (void)json_push_kv_str(&reply->data, "source",
                           "engine/composition/agent_rules.def");
    (void)json_push_kv(&reply->data, "topics", &topics);

    json_free(&situations);
    json_free(&rules);
    json_free(&topics);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
