/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the default fleet.steer.brief snapshot; see the header. A pure
 * rewrite of an already-built reply: it opens no file and reads no source. */

#include "command/native_fleet_steer_compact.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    FCP_TASKS,
    FCP_CANDIDATES,
    FCP_LANDINGS,
    FCP_CHANGES,
    FCP_WORKERS,
    FCP_WORK,
    FCP_LISTS
};

static const struct {
    const char *key;
    size_t cap;
} fcp_lists[FCP_LISTS] = {
    [FCP_TASKS] = {"tasks", ZCL_FMC_COMPACT_TASKS},
    [FCP_CANDIDATES] = {"candidates", ZCL_FMC_COMPACT_CANDIDATES},
    [FCP_LANDINGS] = {"landings", ZCL_FMC_COMPACT_LANDINGS},
    [FCP_CHANGES] = {"changes", ZCL_FMC_COMPACT_CHANGES},
    [FCP_WORKERS] = {"workers", ZCL_FMC_COMPACT_WORKERS},
    [FCP_WORK] = {"work", ZCL_FMC_COMPACT_WORK},
};

/* How each existing coverage key tells what the head left out. */
enum fcp_op { FCP_ADD, FCP_SUB, FCP_CLEAR, FCP_SET };

static const struct {
    const char *key;
    enum fcp_op op;
    size_t list;
} fcp_counts[] = {
    {"tasks_dropped", FCP_ADD, FCP_TASKS},
    {"tasks_sources_complete", FCP_CLEAR, FCP_TASKS},
    {"candidates_shown", FCP_SUB, FCP_CANDIDATES},
    {"candidates_dropped", FCP_ADD, FCP_CANDIDATES},
    {"candidates_complete", FCP_CLEAR, FCP_CANDIDATES},
    {"landings_shown", FCP_SUB, FCP_LANDINGS},
    {"landings_more", FCP_SET, FCP_LANDINGS},
    {"changes_dropped", FCP_ADD, FCP_CHANGES},
    {"changes_truncated", FCP_SET, FCP_CHANGES},
    {"workers_truncated", FCP_SET, FCP_WORKERS},
};

/* The task fields a next step turns on, and the screen line renders. */
static const char *const fcp_task_keys[] = {
    "detail", "source", "seq", "attempt", "ref", "source_ts", "freshness",
    "observed_age_s", "phase", "local", "base", "state", "reason", "priority",
    "blocker", "owner", "incomplete", "next_safe_command",
};

struct fcp_state {
    long long cut[FCP_LISTS];
    long long dead[FCP_LISTS];
    size_t cap[FCP_LISTS];
    long long window;
    long long stale;
    struct json_value unseen;
};

static const char *fcp_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

/* A historical task is a past landing outcome, and a worker whose state
 * is unknown because its newest evidence is older than the alive window
 * is stale: both are left out like a stale session. */
static bool fcp_live(size_t list, const struct json_value *row, long long window)
{
    const struct json_value *age = json_get(row, "age_s");
    if (list == FCP_TASKS)
        return !json_get_bool(json_get(row, "historical"));
    if (list != FCP_WORKERS || strcmp(fcp_str(row, "state"), "unknown") != 0)
        return true;
    return !age || age->type != JSON_INT || json_get_int(age) <= window;
}

/* Rows each list keeps and leaves out. */
static void fcp_cuts(const struct json_value *data, bool cap_changes,
                     struct fcp_state *st)
{
    const struct json_value *window = json_get(data, "alive_window_s");
    st->window = window && window->type == JSON_INT ? json_get_int(window) : 900;
    for (size_t i = 0; i < FCP_LISTS; i++) {
        const struct json_value *rows = json_get(data, fcp_lists[i].key);
        size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u, live = 0;
        st->cap[i] = i == FCP_CHANGES && !cap_changes ? SIZE_MAX : fcp_lists[i].cap;
        for (size_t r = 0; r < n; r++)
            live += fcp_live(i, json_at(rows, r), st->window);
        size_t kept = live < st->cap[i] ? live : st->cap[i];
        st->cut[i] = (long long)(n - kept);
        st->dead[i] = (long long)(n - live);
    }
}

/* Session rows that carry an observation. A stale row is counted, a role
 * never observed (observed_via UNKNOWN: every field is UNKNOWN) is named. */
static bool fcp_sessions(struct json_value *out, const struct json_value *rows,
                         struct fcp_state *st)
{
    struct json_value kept, role;
    bool ok = true;
    json_init(&kept);
    json_set_array(&kept);
    for (size_t i = 0; ok && i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        if (strcmp(fcp_str(row, "state"), "stale") == 0) {
            st->stale++;
        } else if (strcmp(fcp_str(row, "observed_via"), "UNKNOWN") == 0) {
            json_init(&role);
            json_set_str(&role, fcp_str(row, "role"));
            ok = role.type == JSON_STR && json_push_back(&st->unseen, &role);
            json_free(&role);
        } else {
            ok = json_push_back(&kept, row);
        }
    }
    ok = ok && json_push_kv(out, "sessions", &kept) &&
         json_push_kv_int(out, "stale_omitted", st->stale) &&
         json_push_kv(out, "sessions_unseen", &st->unseen);
    json_free(&kept);
    return ok;
}

/* The proof pair's status, only when the pair is exact. */
static bool fcp_slim_proof(struct json_value *o, const struct json_value *proof)
{
    const struct json_value *status = json_get(proof, "status");
    struct json_value p;
    bool ok;
    if (!json_get_bool(json_get(proof, "exact_pair")) || !status ||
        status->type != JSON_STR)
        return true;
    json_init(&p);
    json_set_object(&p);
    ok = json_push_kv_bool(&p, "exact_pair", true) &&
         json_push_kv(&p, "status", status) && json_push_kv(o, "proof", &p);
    json_free(&p);
    return ok;
}

static bool fcp_slim_task(struct json_value *arr, const struct json_value *row)
{
    struct json_value o;
    bool ok = true;
    json_init(&o);
    json_set_object(&o);
    for (size_t i = 0; ok && i < sizeof(fcp_task_keys) / sizeof(fcp_task_keys[0]); i++) {
        const struct json_value *v = json_get(row, fcp_task_keys[i]);
        if (v && v->type != JSON_NULL)
            ok = json_push_kv(&o, fcp_task_keys[i], v);
    }
    ok = ok && fcp_slim_proof(&o, json_get(row, "proof")) && json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

/* The first live rows of one list; tasks slimmed. */
static bool fcp_head(struct json_value *out, size_t list,
                     const struct json_value *rows, const struct fcp_state *st)
{
    struct json_value kept;
    bool ok = true;
    json_init(&kept);
    json_set_array(&kept);
    for (size_t i = 0; ok && i < json_size(rows) && json_size(&kept) < st->cap[list]; i++) {
        const struct json_value *row = json_at(rows, i);
        if (!fcp_live(list, row, st->window))
            continue;
        ok = list == FCP_TASKS ? fcp_slim_task(&kept, row) : json_push_back(&kept, row);
    }
    ok = ok && json_push_kv(out, fcp_lists[list].key, &kept);
    if (ok && list == FCP_WORK)
        ok = json_push_kv_int(out, "work_omitted", st->cut[FCP_WORK]);
    if (ok && list == FCP_WORKERS)
        ok = json_push_kv_int(out, "workers_stale_omitted", st->dead[FCP_WORKERS]);
    json_free(&kept);
    return ok;
}

/* One coverage key rewritten; *handled false when key is not one. */
static bool fcp_count(struct json_value *out, const char *key,
                      const struct json_value *v, const struct fcp_state *st,
                      bool *handled)
{
    for (size_t i = 0; i < sizeof(fcp_counts) / sizeof(fcp_counts[0]); i++) {
        if (strcmp(key, fcp_counts[i].key) != 0)
            continue;
        long long cut = st->cut[fcp_counts[i].list];
        bool numeric = fcp_counts[i].op == FCP_ADD || fcp_counts[i].op == FCP_SUB;
        *handled = true;
        if (v->type != (numeric ? JSON_INT : JSON_BOOL))
            return false;
        if (numeric)
            return json_push_kv_int(out, key, json_get_int(v) +
                                    (fcp_counts[i].op == FCP_ADD ? cut : -cut));
        return json_push_kv_bool(out, key, fcp_counts[i].op == FCP_CLEAR
                                               ? json_get_bool(v) && cut == 0
                                               : json_get_bool(v) || cut > 0);
    }
    *handled = false;
    return true;
}

/* Fixed prose the full reply carries for a reader new to it. */
static bool fcp_prose(const char *key)
{
    static const char *const keys[] = {
        "directive_definition", "sessions_active_basis", "tasks_coverage_reason",
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (strcmp(key, keys[i]) == 0)
            return true;
    return false;
}

static bool fcp_member(struct json_value *out, const char *key,
                       const struct json_value *v, struct fcp_state *st)
{
    bool handled = false;
    if (fcp_prose(key))
        return true;
    if (strcmp(key, "sessions") == 0 && v->type == JSON_ARR)
        return fcp_sessions(out, v, st);
    for (size_t i = 0; i < FCP_LISTS; i++)
        if (strcmp(key, fcp_lists[i].key) == 0 && v->type == JSON_ARR)
            return fcp_head(out, i, v, st);
    if (!fcp_count(out, key, v, st, &handled))
        return false;
    return handled || json_push_kv(out, key, v);
}

bool zcl_fmc_brief_compact(struct json_value *data, bool cap_changes)
{
    struct fcp_state st;
    struct json_value out;
    bool ok = data && data->type == JSON_OBJ;
    if (!ok)
        return false;
    memset(&st, 0, sizeof(st));
    fcp_cuts(data, cap_changes, &st);
    json_init(&st.unseen);
    json_set_array(&st.unseen);
    json_init(&out);
    json_set_object(&out);
    for (size_t i = 0; ok && i < data->num_children; i++)
        ok = data->keys[i] && fcp_member(&out, data->keys[i], &data->children[i], &st);
    ok = ok && json_push_kv_bool(&out, "compact", true);
    json_free(&st.unseen);
    if (!ok) {
        json_free(&out);
        return false;
    }
    json_free(data);
    *data = out;
    return true;
}
