/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the default fleet.steer.brief snapshot; see the header. A pure
 * rewrite of an already-built reply: it opens no file and reads no source. */

#include "command/native_fleet_steer_compact.h"

#include <stddef.h>
#include <string.h>

enum { FCP_TASKS, FCP_CANDIDATES, FCP_LANDINGS, FCP_LISTS };

static const struct {
    const char *key;
    size_t cap;
} fcp_lists[FCP_LISTS] = {
    [FCP_TASKS] = {"tasks", ZCL_FMC_COMPACT_TASKS},
    [FCP_CANDIDATES] = {"candidates", ZCL_FMC_COMPACT_CANDIDATES},
    [FCP_LANDINGS] = {"landings", ZCL_FMC_COMPACT_LANDINGS},
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
};

struct fcp_state {
    long long cut[FCP_LISTS];
    long long stale;
    struct json_value unseen;
};

static const char *fcp_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
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

static bool fcp_head(struct json_value *out, const char *key,
                     const struct json_value *rows, size_t cap)
{
    struct json_value kept;
    bool ok = true;
    json_init(&kept);
    json_set_array(&kept);
    for (size_t i = 0; ok && i < json_size(rows) && i < cap; i++)
        ok = json_push_back(&kept, json_at(rows, i));
    ok = ok && json_push_kv(out, key, &kept);
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

static bool fcp_member(struct json_value *out, const char *key,
                       const struct json_value *v, struct fcp_state *st)
{
    bool handled = false;
    if (strcmp(key, "directive_definition") == 0)
        return true;
    if (strcmp(key, "sessions") == 0 && v->type == JSON_ARR)
        return fcp_sessions(out, v, st);
    for (size_t i = 0; i < FCP_LISTS; i++)
        if (strcmp(key, fcp_lists[i].key) == 0 && v->type == JSON_ARR)
            return fcp_head(out, key, v, fcp_lists[i].cap);
    if (!fcp_count(out, key, v, st, &handled))
        return false;
    return handled || json_push_kv(out, key, v);
}

bool zcl_fmc_brief_compact(struct json_value *data)
{
    struct fcp_state st;
    struct json_value out;
    bool ok = data && data->type == JSON_OBJ;
    if (!ok)
        return false;
    memset(&st, 0, sizeof(st));
    for (size_t i = 0; i < FCP_LISTS; i++) {
        const struct json_value *rows = json_get(data, fcp_lists[i].key);
        size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
        st.cut[i] = n > fcp_lists[i].cap ? (long long)(n - fcp_lists[i].cap) : 0;
    }
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
