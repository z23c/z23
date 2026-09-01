/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Render immutable blocker snapshots as diagnostics JSON. */

#include "util/blocker.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

static void push_last_retired(struct json_value *out)
{
    struct blocker_retirement_info last;
    struct json_value value;
    json_init(&value);
    json_set_object(&value);
    if (blocker_last_retired(&last)) {
        json_push_kv_str(&value, "id", last.id);
        json_push_kv_str(&value, "owner", last.owner_subsystem);
        json_push_kv_int(&value, "retired_at_us", last.retired_at_us);
        json_push_kv_int(&value, "fire_count_at_retirement",
                         (int64_t)last.fire_count_at_retirement);
        json_push_kv_str(&value, "reason", last.reason);
    }
    json_push_kv(out, "last_retired", &value);
    json_free(&value);
}

static void push_blockers(struct json_value *out,
                          const struct blocker_snapshot *snaps, int count)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    for (int i = 0; i < count; i++) {
        struct json_value child;
        json_init(&child);
        json_set_object(&child);
        json_push_kv_str(&child, "id", snaps[i].id);
        json_push_kv_str(&child, "owner", snaps[i].owner_subsystem);
        json_push_kv_str(&child, "class",
                         blocker_class_name((enum blocker_class)snaps[i].class));
        json_push_kv_int(&child, "age_us", snaps[i].age_us);
        json_push_kv_int(&child, "deadline_remaining_us",
                         snaps[i].deadline_remaining_us);
        json_push_kv_str(&child, "escape_action", snaps[i].escape_action);
        json_push_kv_int(&child, "retry_count", snaps[i].retry_count);
        json_push_kv_int(&child, "retry_budget", snaps[i].retry_budget);
        json_push_kv_int(&child, "fire_count", snaps[i].fire_count);
        json_push_kv_str(&child, "reason", snaps[i].reason);
        json_push_kv_bool(&child, "escalated", snaps[i].escalated);
        json_push_kv_int(&child, "deadline_rearm_count",
                         snaps[i].deadline_rearm_count);
        json_push_kv_str(&child, "caused_by", snaps[i].caused_by);
        json_push_kv_str(&child, "cause_detail", snaps[i].cause_detail);
        /* Hand-off: what the node attempts, or the decision a person owes.
         * `escape_action` above answers only "does the supervisor sweep
         * dispatch something"; it is empty for every condition-healed and
         * every OWNER blocker alike, which is exactly the ambiguity that
         * made a standing blocker unreadable. */
        struct blocker_handoff h;
        (void)blocker_resolve_handoff(snaps[i].id, &h);
        json_push_kv_str(&child, "remedy", h.remedy);
        json_push_kv_str(&child, "remedy_kind", blocker_handoff_kind_name(h.kind));
        json_push_kv_bool(&child, "needs_human", h.kind == BLOCKER_HANDOFF_HUMAN);
        json_push_kv_str(&child, "operator_decision", h.decision);
        json_push_kv_bool(&child, "standing",
                          h.kind == BLOCKER_HANDOFF_HUMAN &&
                          snaps[i].age_us >=
                              (int64_t)BLOCKER_STANDING_AGE_SECS * 1000000);
        json_push_back(&array, &child);
        json_free(&child);
    }
    json_push_kv(out, "blockers", &array);
    json_free(&array);
}

static bool blocker_id_is_active(const struct blocker_snapshot *snaps,
                                 int count, const char *id)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(snaps[i].id, id) == 0)
            return true;
    }
    return false;
}

static bool blocker_id_is_referenced(const struct blocker_snapshot *snaps,
                                     int count, int candidate)
{
    for (int i = 0; i < count; i++) {
        if (i != candidate && snaps[i].caused_by[0] != '\0' &&
            strcmp(snaps[i].caused_by, snaps[candidate].id) == 0)
            return true;
    }
    return false;
}

static void push_string(struct json_value *array, const char *value)
{
    struct json_value string;
    json_init(&string);
    json_set_str(&string, value);
    json_push_back(array, &string);
    json_free(&string);
}

static void push_causal_classes(struct json_value *out,
                                const struct blocker_snapshot *snaps,
                                int count)
{
    struct json_value roots, symptoms, orphans;
    json_init(&roots);    json_set_array(&roots);
    json_init(&symptoms); json_set_array(&symptoms);
    json_init(&orphans);  json_set_array(&orphans);

    for (int i = 0; i < count; i++) {
        if (snaps[i].caused_by[0] == '\0')
            continue;
        push_string(&symptoms, snaps[i].id);
        if (!blocker_id_is_active(snaps, count, snaps[i].caused_by))
            push_string(&orphans, snaps[i].id);
    }
    for (int i = 0; i < count; i++) {
        if (snaps[i].caused_by[0] == '\0' &&
            blocker_id_is_referenced(snaps, count, i))
            push_string(&roots, snaps[i].id);
    }

    json_push_kv(out, "root_blocker_ids", &roots);
    json_push_kv(out, "symptom_blocker_ids", &symptoms);
    json_push_kv(out, "orphaned_symptom_ids", &orphans);
    json_free(&roots);
    json_free(&symptoms);
    json_free(&orphans);
}

bool blocker_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct blocker_snapshot snaps[BLOCKER_CAP];
    uint64_t generation = 0;
    int escape_dispatched = 0;
    int rate_limit_ms = 0;
    int count = blocker_snapshot_all_with_meta(
        snaps, BLOCKER_CAP, &generation, &escape_dispatched, &rate_limit_ms);
    int counts[4] = {0, 0, 0, 0};
    int escalated_count = 0;
    /* Hand-off totals — the one-line answer to "is anything being
     * attempted, and how much is waiting on me?". `undeclared_decision`
     * is the visible remaining debt: bound OWNER, but nobody has written
     * down what the operator is supposed to decide. */
    int automatic_count = 0, human_count = 0;
    int standing_count = 0, undeclared_decision_count = 0;
    for (int i = 0; i < count; i++) {
        if (snaps[i].class >= 0 && snaps[i].class < 4)
            counts[snaps[i].class]++;
        if (snaps[i].escalated)
            escalated_count++;
        struct blocker_handoff h;
        (void)blocker_resolve_handoff(snaps[i].id, &h);
        if (h.kind == BLOCKER_HANDOFF_AUTOMATIC) {
            automatic_count++;
        } else if (h.kind == BLOCKER_HANDOFF_HUMAN) {
            human_count++;
            if (!h.decision[0])
                undeclared_decision_count++;
            if (snaps[i].age_us >= (int64_t)BLOCKER_STANDING_AGE_SECS * 1000000)
                standing_count++;
        }
    }

    json_push_kv_int(out, "active_count", count);
    json_push_kv_int(out, "permanent_count", counts[BLOCKER_PERMANENT]);
    json_push_kv_int(out, "transient_count", counts[BLOCKER_TRANSIENT]);
    json_push_kv_int(out, "dependency_count", counts[BLOCKER_DEPENDENCY]);
    json_push_kv_int(out, "resource_count", counts[BLOCKER_RESOURCE]);
    json_push_kv_int(out, "generation", (int64_t)generation);
    json_push_kv_int(out, "escape_dispatched_total", escape_dispatched);
    json_push_kv_int(out, "rate_limit_ms", rate_limit_ms);
    json_push_kv_int(out, "escalated_count", escalated_count);
    json_push_kv_int(out, "automatic_remedy_count", automatic_count);
    json_push_kv_int(out, "human_handoff_count", human_count);
    json_push_kv_int(out, "standing_handoff_count", standing_count);
    json_push_kv_int(out, "undeclared_decision_count", undeclared_decision_count);
    json_push_kv_int(out, "transient_retired_total",
                     (int64_t)blocker_retired_transient_count());
    push_last_retired(out);
    push_blockers(out, snaps, count);
    push_causal_classes(out, snaps, count);

    char reason[288] = "";
    if (count > 0) {
        /* Lead with the disposition, not just the count: "3 active, all
         * handed off to a person and standing for hours" and "3 active,
         * remedies running" are the same number and opposite situations. */
        snprintf(reason, sizeof(reason),
                 "%d active blocker(s) (%d auto-remedied, %d awaiting an "
                 "operator decision, %d standing >%ds); first: %s owner=%s "
                 "class=%s (%s)",
                 count, automatic_count, human_count, standing_count,
                 BLOCKER_STANDING_AGE_SECS,
                 snaps[0].id, snaps[0].owner_subsystem,
                 blocker_class_name((enum blocker_class)snaps[0].class),
                 snaps[0].reason);
    }
    diag_push_health(out, count == 0, reason);
    return true;
}
