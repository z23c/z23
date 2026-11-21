/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: see native_dev_land_main_red.h. Pure functions over a bounded
 *          window of outcome rows; no file, process or clock access. */

#include "command/native_dev_land_main_red.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

static uint64_t dlmr_fnv(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static bool dlmr_name_char(char c, bool dash)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || (dash && c == '-');
}

static bool dlmr_copy_name(const char *p, bool dash, char *out, size_t cap)
{
    size_t n = 0;
    while (dlmr_name_char(p[n], dash))
        n++;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = 0;
    return true;
}

/* test rows read "test <group>: FAIL at ..." or "test <group>: exit code=";
 * lint rows carry "FAIL check-<gate>" on their first line. Anything else
 * (compile errors, rebase, push, worktree rows) names no group. */
bool dlmr_group_of(const char *dimension, const char *detail, char *out,
                   size_t cap)
{
    if (out && cap)
        out[0] = 0;
    if (!dimension || !detail || !out || cap == 0)
        return false;
    if (strcmp(dimension, "test") == 0) {
        if (strncmp(detail, "test ", 5) != 0)
            return false;
        return dlmr_copy_name(detail + 5, false, out, cap);
    }
    if (strcmp(dimension, "lint") == 0) {
        size_t line = strcspn(detail, "\n");
        const char *at = detail;
        while ((at = strstr(at, "FAIL check-")) != NULL &&
               (size_t)(at - detail) < line) {
            if (dlmr_copy_name(at + 5, true, out, cap))
                return true;
            at += 5;
        }
    }
    return false;
}

/* Where a test failed: the first line of its detail up to the child-exit
 * tag or the log path, which differ per attempt. Lint details carry only
 * timings, so a gate has no site. */
static uint64_t dlmr_site(const char *dimension, const char *detail)
{
    size_t n = strcspn(detail, "\n");
    const char *cut;
    if (strcmp(dimension, "test") != 0)
        return 0;
    if ((cut = strstr(detail, " [child_proof")) != NULL && (size_t)(cut - detail) < n)
        n = (size_t)(cut - detail);
    if ((cut = strstr(detail, "; log:")) != NULL && (size_t)(cut - detail) < n)
        n = (size_t)(cut - detail);
    return dlmr_fnv(detail, n);
}

void dlmr_note(struct dlmr_window *w, long long seq, const char *state,
               const char *dimension, const char *worktree, const char *tip,
               const char *detail)
{
    struct dlmr_entry e;
    if (!w || !state)
        return;
    memset(&e, 0, sizeof(e));
    e.seq = seq;
    e.pos = w->seen++;
    if (strcmp(state, "landed") == 0) {
        e.kind = 1;
    } else if (strcmp(state, "failed") == 0 &&
               dlmr_group_of(dimension ? dimension : "", detail ? detail : "",
                             e.group, sizeof(e.group))) {
        const char *who = worktree && worktree[0] ? worktree : (tip ? tip : "");
        e.kind = 2;
        (void)snprintf(e.dimension, sizeof(e.dimension), "%s", dimension);
        e.candidate = dlmr_fnv(who, strlen(who));
        e.site = dlmr_site(dimension, detail);
    } else {
        return; /* not a signal either way */
    }
    if (w->count == DLMR_WINDOW) {
        memmove(&w->e[0], &w->e[1], (DLMR_WINDOW - 1) * sizeof(w->e[0]));
        w->count--;
    }
    w->e[w->count++] = e;
}

static bool dlmr_same(const struct dlmr_entry *a, const struct dlmr_entry *b)
{
    return a->kind == 2 && b->kind == 2 && a->site == b->site &&
           strcmp(a->dimension, b->dimension) == 0 &&
           strcmp(a->group, b->group) == 0;
}

static bool dlmr_newest_of_key(const struct dlmr_window *w, size_t i)
{
    for (size_t j = i + 1; j < w->count; j++)
        if (dlmr_same(&w->e[j], &w->e[i]))
            return false;
    return true;
}

static bool dlmr_seen_candidate(const uint64_t *seen, size_t n, uint64_t c)
{
    for (size_t k = 0; k < n; k++)
        if (seen[k] == c)
            return true;
    return false;
}

/* Build the suspect whose newest failure is entry i. Walk back over the
 * key's failures while each is within DLMR_GAP rows of the one after it. */
static bool dlmr_build(const struct dlmr_window *w, size_t i,
                       struct dlmr_suspect *s)
{
    size_t chain[DLMR_WINDOW], n = 0, ncand = 0, prev = w->e[i].pos;
    uint64_t seen[DLMR_WINDOW];
    if (w->seen - w->e[i].pos > DLMR_GAP)
        return false; /* the failure is old news */
    for (size_t j = i + 1; j-- > 0;) {
        if (!dlmr_same(&w->e[j], &w->e[i]))
            continue;
        if (prev - w->e[j].pos > DLMR_GAP)
            break;
        prev = w->e[j].pos;
        chain[n++] = j;
        if (!dlmr_seen_candidate(seen, ncand, w->e[j].candidate))
            seen[ncand++] = w->e[j].candidate;
    }
    if (ncand < DLMR_K)
        return false;
    for (size_t j = i + 1; j < w->count; j++)
        if (w->e[j].kind == 1)
            return false; /* a landing after the newest failure may repair it */
    memset(s, 0, sizeof(*s));
    (void)snprintf(s->dimension, sizeof(s->dimension), "%s", w->e[i].dimension);
    (void)snprintf(s->group, sizeof(s->group), "%s", w->e[i].group);
    s->total = n;
    s->first_seq = w->e[chain[n - 1]].seq;
    /* chain[] is newest first: keep the first row, then the newest others. */
    s->rows[s->nrows++] = s->first_seq;
    size_t room = DLMR_ROWS_MAX - 1;
    size_t take = n - 1 < room ? n - 1 : room;
    for (size_t k = take; k-- > 0;)
        s->rows[s->nrows++] = w->e[chain[k]].seq;
    return true;
}

size_t dlmr_suspects(const struct dlmr_window *w, struct dlmr_suspect *out,
                     size_t cap)
{
    size_t n = 0;
    if (!w || !out)
        return 0;
    for (size_t i = 0; i < w->count && n < cap; i++) {
        if (w->e[i].kind != 2 || !dlmr_newest_of_key(w, i))
            continue;
        if (dlmr_build(w, i, &out[n]))
            n++;
    }
    return n;
}

size_t dlmr_line(const struct dlmr_suspect *s, char *out, size_t cap)
{
    size_t used;
    int w;
    if (!s || !out || cap == 0)
        return 0;
    w = snprintf(out, cap, "main may be red for %s: rows ", s->group);
    if (w < 0 || (size_t)w >= cap)
        return 0;
    used = (size_t)w;
    for (size_t i = 0; i < s->nrows; i++) {
        w = snprintf(out + used, cap - used, "%s%lld", i ? ", " : "",
                     s->rows[i]);
        if (w < 0 || (size_t)w >= cap - used)
            return 0;
        used += (size_t)w;
    }
    w = snprintf(out + used, cap - used, " failed it%s; land the repair first",
                 s->total > s->nrows ? " (and others)" : "");
    if (w < 0 || (size_t)w >= cap - used)
        return 0;
    return used + (size_t)w;
}

void dlmr_row_hint(const struct dlmr_suspect *sus, size_t n, long long seq,
                   char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    for (size_t i = 0; sus && i < n; i++)
        for (size_t k = 0; k < sus[i].nrows; k++)
            if (sus[i].rows[k] == seq) {
                if (dlmr_line(&sus[i], out, cap) == 0)
                    out[0] = 0;
                return;
            }
}

bool dlmr_push_status(struct json_value *data, const struct dlmr_suspect *sus,
                      size_t n)
{
    struct json_value list;
    bool ok = true;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; ok && i < n; i++) {
        struct json_value item, rows;
        char line[256];
        json_init(&item);
        json_set_object(&item);
        json_init(&rows);
        json_set_array(&rows);
        for (size_t k = 0; k < sus[i].nrows; k++) {
            struct json_value v;
            json_init(&v);
            json_set_int(&v, sus[i].rows[k]);
            ok = ok && json_push_back(&rows, &v);
            json_free(&v);
        }
        if (dlmr_line(&sus[i], line, sizeof(line)) == 0)
            line[0] = 0;
        ok = ok && json_push_kv_str(&item, "dimension", sus[i].dimension) &&
             json_push_kv_str(&item, "group", sus[i].group) &&
             json_push_kv_int(&item, "first_seq", sus[i].first_seq) &&
             json_push_kv_int(&item, "failures", (long long)sus[i].total) &&
             json_push_kv(&item, "rows", &rows) &&
             json_push_kv_str(&item, "hint", line) &&
             json_push_back(&list, &item);
        json_free(&rows);
        json_free(&item);
    }
    ok = ok && json_push_kv(data, "main_red", &list);
    json_free(&list);
    return ok;
}

bool dlmr_push_row_hint(struct json_value *item, const struct dlmr_suspect *sus,
                        size_t n, long long seq)
{
    char hint[256];
    dlmr_row_hint(sus, n, seq, hint, sizeof(hint));
    return hint[0] == 0 || json_push_kv_str(item, "main_red_hint", hint);
}

bool dlmr_screen(const struct dlmr_suspect *sus, size_t n, char *screen,
                 size_t cap, size_t *used)
{
    for (size_t i = 0; i < n; i++) {
        char line[256];
        int w;
        if (dlmr_line(&sus[i], line, sizeof(line)) == 0)
            continue;
        w = snprintf(screen + *used, cap - *used, "  %s\n", line);
        if (w <= 0 || (size_t)w >= cap - *used)
            return false;
        *used += (size_t)w;
    }
    return true;
}
