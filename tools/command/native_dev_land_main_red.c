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

static bool dlmr_path_char(char c)
{
    return dlmr_name_char(c, true) || c == '.' || c == '/' || c == '+';
}

/* A source-looking token: a known extension, not absolute, not under a
 * scratch or build tree, and not the shared baseline file every complexity
 * failure points at in its fix hint. */
static bool dlmr_site_path(const char *p, size_t n)
{
    static const char *const ext[] = {"c", "h", "sh", "md", "txt", "mk", "def",
                                      "json", "jsonl", "sql", "s"};
    size_t dot = n;
    if (n < 3 || p[0] == '/' || p[0] == '.' || strncmp(p, "build/", 6) == 0)
        return false;
    for (size_t i = 0; i + 8 <= n; i++)
        if (memcmp(p + i, "baseline", 8) == 0)
            return false;
    while (dot > 0 && p[dot - 1] != '.')
        dot--;
    if (dot == 0)
        return false;
    for (size_t k = 0; k < sizeof(ext) / sizeof(ext[0]); k++)
        if (strlen(ext[k]) == n - dot && memcmp(p + dot, ext[k], n - dot) == 0)
            return true;
    return false;
}

/* The end of the verdict text: before the log path, child tag or truncation
 * note that follow it. */
static const char *dlmr_verdict_end(const char *p)
{
    static const char *const stop[] = {"; log:", " [child_proof",
                                       "[detail truncated]"};
    const char *end = p + strlen(p);
    for (size_t k = 0; k < sizeof(stop) / sizeof(stop[0]); k++) {
        const char *cut = strstr(p, stop[k]);
        if (cut && cut < end)
            end = cut;
    }
    return end;
}

/* The first source file the verdict names, hashed; 0 for none. */
static uint64_t dlmr_path_site(const char *p, const char *end)
{
    for (const char *q = p; q < end;) {
        size_t n = 0;
        while (q + n < end && dlmr_path_char(q[n]))
            n++;
        if (n == 0) {
            q++;
            continue;
        }
        if (dlmr_site_path(q, n)) {
            uint64_t h = dlmr_fnv(q, n);
            return h ? h : 1;
        }
        q += n;
    }
    return 0;
}

/* The first "FAIL <name>:" the verdict names (a metric or check), hashed. */
static uint64_t dlmr_symbol_site(const char *p, const char *end)
{
    for (const char *q = p; q < end; q++) {
        size_t n = 0;
        if (strncmp(q, "FAIL ", 5) != 0)
            continue;
        while (q + 5 + n < end && dlmr_name_char(q[5 + n], false))
            n++;
        if (n >= 3 && q + 5 + n < end && q[5 + n] == ':' &&
            strncmp(q + 5, "check", 5) != 0) {
            uint64_t h = dlmr_fnv(q + 5, n) ^ 0x9e3779b97f4a7c15ULL;
            return h ? h : 1;
        }
    }
    return 0;
}

/* Where a lint gate failed, read from the verdict text that follows its
 * "FAIL check-<gate>": the first source file it names (line numbers are
 * dropped, they move), else the first "FAIL <name>:" it names (a failing
 * metric or check). Timings, "(rc=1)", child tags, log paths and absolute
 * paths are per-run noise and never count. 0 when nothing is named. */
uint64_t dlmr_lint_site(const char *detail)
{
    const char *at, *p, *end;
    uint64_t site;
    if (!detail || (at = strstr(detail, "FAIL check-")) == NULL)
        return 0;
    p = at + 5;
    while (dlmr_name_char(*p, true))
        p++;
    end = dlmr_verdict_end(p);
    site = dlmr_path_site(p, end);
    return site ? site : dlmr_symbol_site(p, end);
}

/* Where a test failed: the first line of its detail up to the child-exit
 * tag or the log path, which differ per attempt. */
static uint64_t dlmr_site(const char *dimension, const char *detail)
{
    size_t n = strcspn(detail, "\n");
    const char *cut;
    if (strcmp(dimension, "lint") == 0)
        return dlmr_lint_site(detail);
    if ((cut = strstr(detail, " [child_proof")) != NULL && (size_t)(cut - detail) < n)
        n = (size_t)(cut - detail);
    if ((cut = strstr(detail, "; log:")) != NULL && (size_t)(cut - detail) < n)
        n = (size_t)(cut - detail);
    return dlmr_fnv(detail, n);
}

/* Fill e from a failed row; false when the row is no keyed signal. */
static bool dlmr_failed_entry(struct dlmr_entry *e, const char *dimension,
                              const char *worktree, const char *tip,
                              const char *detail)
{
    const char *who = worktree && worktree[0] ? worktree : (tip ? tip : "");
    if (!dimension || !detail ||
        !dlmr_group_of(dimension, detail, e->group, sizeof(e->group)))
        return false;
    e->site = dlmr_site(dimension, detail);
    if (e->site == 0 && strcmp(dimension, "lint") == 0)
        return false; /* a gate name alone is not a key */
    e->kind = 2;
    (void)snprintf(e->dimension, sizeof(e->dimension), "%s", dimension);
    e->candidate = dlmr_fnv(who, strlen(who));
    return true;
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
    e.tip = dlmr_fnv(tip ? tip : "", tip ? strlen(tip) : 0);
    if (strcmp(state, "landed") == 0)
        e.kind = 1;
    else if (strcmp(state, "failed") != 0 ||
             !dlmr_failed_entry(&e, dimension, worktree, tip, detail))
        return; /* not a signal either way */
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

/* Is the chain ending at entry i still worth a word? Live while no landing
 * followed and the failure is recent; "was suspect" for DLMR_AFTER rows after
 * the first landing that followed. */
static bool dlmr_live(const struct dlmr_window *w, size_t i, bool *cleared)
{
    size_t j = i + 1;
    while (j < w->count && w->e[j].kind != 1)
        j++;
    *cleared = j < w->count;
    if (*cleared)
        return w->seen - w->e[j].pos <= DLMR_AFTER;
    return w->seen - w->e[i].pos <= DLMR_GAP;
}

/* Build the suspect whose newest failure is entry i. Walk back over the
 * key's failures while each is within DLMR_GAP rows of the one after it. */
static bool dlmr_build(const struct dlmr_window *w, size_t i,
                       struct dlmr_suspect *s)
{
    size_t chain[DLMR_WINDOW], n = 0, ncand = 0, prev = w->e[i].pos;
    uint64_t seen[DLMR_WINDOW];
    bool cleared = false;
    if (!dlmr_live(w, i, &cleared))
        return false; /* old news */
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
    memset(s, 0, sizeof(*s));
    s->cleared = cleared;
    (void)snprintf(s->dimension, sizeof(s->dimension), "%s", w->e[i].dimension);
    (void)snprintf(s->group, sizeof(s->group), "%s", w->e[i].group);
    s->total = n;
    s->first_seq = w->e[chain[n - 1]].seq;
    /* chain[] is newest first: keep the first row, then the newest others. */
    s->rows[s->nrows] = s->first_seq;
    s->tips[s->nrows++] = w->e[chain[n - 1]].tip;
    size_t room = DLMR_ROWS_MAX - 1;
    size_t take = n - 1 < room ? n - 1 : room;
    for (size_t k = take; k-- > 0;) {
        s->rows[s->nrows] = w->e[chain[k]].seq;
        s->tips[s->nrows++] = w->e[chain[k]].tip;
    }
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
    w = snprintf(out, cap, "main may %s red for %s: rows ",
                 s->cleared ? "have been" : "be", s->group);
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
    w = snprintf(out + used, cap - used, " failed it%s; %s",
                 s->total > s->nrows ? " (and others)" : "",
                 s->cleared
                     ? "a landing followed, check whether it repaired main before resubmitting"
                     : "check main before resubmitting");
    if (w < 0 || (size_t)w >= cap - used)
        return 0;
    return used + (size_t)w;
}

static void dlmr_hint_for(const struct dlmr_suspect *sus, size_t n,
                          long long seq, const char *tip, bool cleared,
                          char *out, size_t cap)
{
    uint64_t t = dlmr_fnv(tip ? tip : "", tip ? strlen(tip) : 0);
    if (!out || cap == 0)
        return;
    out[0] = 0;
    for (size_t i = 0; sus && i < n; i++) {
        if (sus[i].cleared != cleared)
            continue;
        for (size_t k = 0; k < sus[i].nrows; k++)
            if (sus[i].rows[k] == seq && sus[i].tips[k] == t) {
                if (dlmr_line(&sus[i], out, cap) == 0)
                    out[0] = 0;
                return;
            }
    }
}

void dlmr_row_hint(const struct dlmr_suspect *sus, size_t n, long long seq,
                   const char *tip, char *out, size_t cap)
{
    dlmr_hint_for(sus, n, seq, tip, false, out, cap);
}

void dlmr_row_was_suspect(const struct dlmr_suspect *sus, size_t n,
                          long long seq, const char *tip, char *out,
                          size_t cap)
{
    dlmr_hint_for(sus, n, seq, tip, true, out, cap);
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
        if (sus[i].cleared)
            continue;
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
                        size_t n, long long seq, const char *tip)
{
    char hint[256], was[256];
    dlmr_row_hint(sus, n, seq, tip, hint, sizeof(hint));
    dlmr_row_was_suspect(sus, n, seq, tip, was, sizeof(was));
    return (hint[0] == 0 || json_push_kv_str(item, "main_red_hint", hint)) &&
           (was[0] == 0 || json_push_kv_str(item, "main_red_was_suspect", was));
}

bool dlmr_screen(const struct dlmr_suspect *sus, size_t n, char *screen,
                 size_t cap, size_t *used)
{
    for (size_t i = 0; i < n; i++) {
        char line[256];
        int w;
        if (sus[i].cleared || dlmr_line(&sus[i], line, sizeof(line)) == 0)
            continue;
        w = snprintf(screen + *used, cap - *used, "  %s\n", line);
        if (w <= 0 || (size_t)w >= cap - *used)
            return false;
        *used += (size_t)w;
    }
    return true;
}
