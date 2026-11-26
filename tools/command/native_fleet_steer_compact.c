/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the default fleet.steer.brief snapshot; see the header. A pure
 * rewrite of an already-built reply: it opens no file and reads no source. */

#include "command/native_fleet_steer_compact.h"

#include "command/native_devagent.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* strtoll */
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

#define FCP_TOKEN_CAP 4096u

struct fcp_state {
    long long cut[FCP_LISTS];
    long long dead[FCP_LISTS];
    size_t cap[FCP_LISTS];
    /* Leading rows a head skips: the newest changes, which the cursor
     * leaves pending. */
    size_t skip[FCP_LISTS];
    long long window;
    long long stale;
    long long sessions_cut;
    const struct json_value *open_work;
    char cursor[FCP_TOKEN_CAP];
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

/* A work line whose directive is still open is never cut. */
static bool fcp_pinned(size_t list, const struct json_value *row,
                       const struct fcp_state *st)
{
    const struct json_value *open = st->open_work;
    if (list != FCP_WORK || row->type != JSON_STR || !open || open->type != JSON_ARR)
        return false;
    const char *line = json_get_str(row);
    for (size_t i = 0; line && i < json_size(open); i++) {
        const struct json_value *o = json_at(open, i);
        if (o && o->type == JSON_STR && json_get_str(o) &&
            strcmp(json_get_str(o), line) == 0)
            return true;
    }
    return false;
}

/* The lowest row_offset a change row holds in the stream `name[0..len)`,
 * or `off` when none is lower. */
static long long fcp_stream_floor(const struct json_value *rows, const char *name,
                                  size_t len, long long off)
{
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const char *s = fcp_str(row, "stream");
        const struct json_value *start = json_get(row, "row_offset");
        if (strlen(s) == len && strncmp(s, name, len) == 0 && start &&
            start->type == JSON_INT && json_get_int(start) < off)
            off = json_get_int(start);
    }
    return off;
}

/* One "<stream>:<offset>" entry of `end`, moved back to its oldest change
 * row, appended to out. seq.max is not a stream and is left out. */
static bool fcp_token_entry(const char *p, const char *stop,
                            const struct json_value *rows, char *out,
                            size_t cap, size_t *used, bool *first)
{
    const char *colon = memchr(p, ':', (size_t)(stop - p));
    char *tail = NULL;
    if (!colon || colon == p)
        return false;
    size_t len = (size_t)(colon - p);
    if (len == 7 && strncmp(p, "seq.max", 7) == 0)
        return true;
    errno = 0;
    long long off = strtoll(colon + 1, &tail, 10);
    if (errno != 0 || tail != stop || off < 0)
        return false;
    off = fcp_stream_floor(rows, p, len, off);
    int w = snprintf(out + *used, cap - *used, "%s%.*s:%lld", *first ? "" : ",",
                     (int)len, p, off);
    if (w < 0 || (size_t)w >= cap - *used)
        return false;
    *used += (size_t)w;
    *first = false;
    return true;
}

/* The token in front of every change row: `end` with each stream moved
 * back to its oldest change row. The changes are the newest rows of the
 * pass, so each stream's share is a tail of it. */
static bool fcp_window_start(const char *end, const struct json_value *rows,
                             char *out, size_t cap)
{
    const char *bar = strchr(end, '|');
    bool first = true;
    if (!bar || (size_t)(bar - end) + 1u >= cap)
        return false;
    size_t used = (size_t)(bar - end) + 1u;
    memcpy(out, end, used);
    out[used] = '\0';
    for (const char *p = bar + 1; *p;) {
        const char *comma = strchr(p, ',');
        const char *stop = comma ? comma : p + strlen(p);
        if (!fcp_token_entry(p, stop, rows, out, cap, &used, &first))
            return false;
        p = comma ? comma + 1 : stop;
    }
    return true;
}

/* The changes kept are the oldest `keep` (the tail of the newest-first
 * list), and the cursor resumes right after them: the next brief that
 * passes it as since returns every change left out, once. False, and
 * nothing cut, when the rows carry no exact stream position. */
static bool fcp_changes_cursor(const struct json_value *data, size_t keep,
                               char *out, size_t cap)
{
    const struct json_value *rows = json_get(data, "changes");
    const char *end = fcp_str(data, "cursor_token");
    char start[FCP_TOKEN_CAP];
    struct json_value kept;
    size_t n = json_size(rows);
    bool ok = end[0] && keep <= n && fcp_window_start(end, rows, start, sizeof(start));
    if (!ok)
        return false;
    json_init(&kept);
    json_set_array(&kept);
    for (size_t i = n; ok && i > n - keep; i--)
        ok = json_push_back(&kept, json_at(rows, i - 1));
    ok = ok && zcl_devagent_mail_cursor_prefix(start, end, &kept, out, cap);
    json_free(&kept);
    return ok;
}

/* Rows one list keeps and leaves out. */
static void fcp_list_cut(const struct json_value *data, size_t i,
                         struct fcp_state *st)
{
    const struct json_value *rows = json_get(data, fcp_lists[i].key);
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
    size_t live = 0, pinned = 0;
    for (size_t r = 0; r < n; r++) {
        const struct json_value *row = json_at(rows, r);
        if (fcp_pinned(i, row, st))
            pinned++;
        else
            live += fcp_live(i, row, st->window);
    }
    size_t kept = pinned + (live < st->cap[i] ? live : st->cap[i]);
    st->cut[i] = (long long)(n - kept);
    st->dead[i] = (long long)(n - live - pinned);
}

static void fcp_cuts(const struct json_value *data, bool cap_changes,
                     struct fcp_state *st)
{
    const struct json_value *window = json_get(data, "alive_window_s");
    st->window = window && window->type == JSON_INT ? json_get_int(window) : 900;
    for (size_t i = 0; i < FCP_LISTS; i++) {
        st->cap[i] = i == FCP_CHANGES && !cap_changes ? SIZE_MAX : fcp_lists[i].cap;
        fcp_list_cut(data, i, st);
    }
    if (st->cut[FCP_CHANGES] <= 0)
        return;
    if (fcp_changes_cursor(data, st->cap[FCP_CHANGES], st->cursor,
                           sizeof(st->cursor))) {
        st->skip[FCP_CHANGES] = (size_t)st->cut[FCP_CHANGES];
        return;
    }
    /* No exact resume point: every change stays. */
    st->cursor[0] = '\0';
    st->cap[FCP_CHANGES] = SIZE_MAX;
    st->cut[FCP_CHANGES] = 0;
}

/* Session rows that carry an observation, at most ZCL_FMC_COMPACT_SESSIONS
 * after the stale filter. A stale row is counted, a role never observed
 * (observed_via UNKNOWN: every field is UNKNOWN) is named. */
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
        } else if (json_size(&kept) >= ZCL_FMC_COMPACT_SESSIONS) {
            st->sessions_cut++;
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

/* The rows of one list that survive: pinned rows, then live rows up to
 * the cap, after the skipped head; tasks slimmed. */
static bool fcp_head(struct json_value *out, size_t list,
                     const struct json_value *rows, const struct fcp_state *st)
{
    struct json_value kept;
    size_t others = 0;
    bool ok = true;
    json_init(&kept);
    json_set_array(&kept);
    for (size_t i = st->skip[list]; ok && i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        if (!fcp_pinned(list, row, st)) {
            if (!fcp_live(list, row, st->window) || others >= st->cap[list])
                continue;
            others++;
        }
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

/* The cursor after the kept changes, and the session cap's own cut. */
static bool fcp_rewrite(struct json_value *out, const char *key,
                        const struct json_value *v, const struct fcp_state *st,
                        bool *handled)
{
    *handled = true;
    if (strcmp(key, "cursor_token") == 0 && st->cursor[0])
        return json_push_kv_str(out, key, st->cursor);
    if (strcmp(key, "sessions_truncated") == 0 && v->type == JSON_BOOL)
        return json_push_kv_bool(out, key, json_get_bool(v) || st->sessions_cut > 0);
    return fcp_count(out, key, v, st, handled);
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
    if (!fcp_rewrite(out, key, v, st, &handled))
        return false;
    return handled || json_push_kv(out, key, v);
}

bool zcl_fmc_brief_compact(struct json_value *data, bool cap_changes,
                           const struct json_value *open_work)
{
    struct fcp_state st;
    struct json_value out;
    bool ok = data && data->type == JSON_OBJ;
    if (!ok)
        return false;
    memset(&st, 0, sizeof(st));
    st.open_work = open_work;
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
