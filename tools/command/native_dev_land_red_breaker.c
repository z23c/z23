/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: see native_dev_land_red_breaker.h. The pure policy reads only its
 *          arguments and the environment; the driver glue reads the queue
 *          and outcome rows, the changed paths through the land leaf's git
 *          seam and, for a passed proof, its retained test log. Queue rows
 *          change only through the leaf's locked rewrite helpers. */

#include "command/native_dev_land_red_breaker.h"

#include "base/safe_alloc.h"
#include "command/native_dev_land_main_red.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── pure policy ─────────────────────────────────────────────────────── */

static uint64_t dlrb_fnv(uint64_t h, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* A setting's decimal value within [lo, hi], else `def`. */
static long long dlrb_setting(const char *s, long long def, long long lo,
                              long long hi)
{
    char *end = NULL;
    if (!s || !*s)
        return def;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    return errno || *end || v < lo || v > hi ? def : v;
}

void dlrb_policy_read(struct dlrb_policy *p)
{
    const char *on = getenv("ZCL_LAND_RED_MAIN");
    p->enabled = !(on && strcmp(on, "0") == 0);
    p->k = (unsigned)dlrb_setting(getenv("ZCL_LAND_RED_MAIN_K"), 2, 1, 8);
    p->age_s = dlrb_setting(getenv("ZCL_LAND_RED_MAIN_AGE_S"), 7200, 1,
                            7LL * 86400);
    p->max_s = dlrb_setting(getenv("ZCL_LAND_RED_MAIN_MAX_S"), 43200, 1,
                            30LL * 86400);
}

long long dlrb_now(void)
{
#if defined(ZCL_TESTING)
    long long fixed = dlrb_setting(getenv("ZCL_LAND_RED_MAIN_NOW"), 0, 1,
                                   LLONG_MAX);
    if (fixed > 0)
        return fixed;
#endif
    return (long long)platform_time_wall_unix();
}

/* Test group names: ASCII letters, digits and underscores. */
static bool dlrb_name_char(char c)
{
    return isalnum((unsigned char)c) != 0 || c == '_';
}

/* A cleared marker may name several groups joined by '+'. */
static bool dlrb_list_char(char c)
{
    return dlrb_name_char(c) || c == '+';
}

static bool dlrb_text_ok(const char *g, bool list)
{
    size_t n = 0;
    while (g && (list ? dlrb_list_char(g[n]) : dlrb_name_char(g[n])))
        n++;
    return g && n > 0 && n < DLRB_GROUP_MAX && g[n] == '\0';
}

static bool dlrb_group_ok(const char *g)
{
    return dlrb_text_ok(g, false);
}

/* Is `group` one of the '+'-joined names of `list`? */
static bool dlrb_list_has(const char *list, const char *group)
{
    size_t len = strlen(group);
    for (const char *p = list; *p;) {
        size_t n = strcspn(p, "+");
        if (n == len && strncmp(p, group, n) == 0)
            return true;
        p += n + (p[n] == '+');
    }
    return false;
}

/* A positive decimal of at most 18 digits ending at `stop`; the position
 * after `stop` (or the terminator itself), or NULL. */
static const char *dlrb_number(const char *p, char stop, long long *out)
{
    size_t n = 0;
    long long v = 0;
    while (p[n] >= '0' && p[n] <= '9' && n < 18)
        v = v * 10 + (p[n++] - '0');
    if (n == 0 || p[n] != stop || v <= 0)
        return NULL;
    *out = v;
    return stop ? p + n + 1 : p + n;
}

bool dlrb_mark_parse(const char *field, struct dlrb_mark *m)
{
    const char *p = NULL;
    size_t n = 0;
    memset(m, 0, sizeof(*m));
    if (field && strncmp(field, "parked:", 7) == 0)
        p = field + 7;
    else if (field && strncmp(field, "cleared:", 8) == 0)
        p = field + 8;
    if (!p)
        return false;
    m->cleared = field[0] == 'c';
    while (m->cleared ? dlrb_list_char(p[n]) : dlrb_name_char(p[n]))
        n++;
    if (n == 0 || n >= sizeof(m->group) || p[n] != ':')
        return false;
    memcpy(m->group, p, n);
    p = dlrb_number(p + n + 1, ':', &m->since);
    p = p ? dlrb_number(p, ':', &m->since_at) : NULL;
    p = p ? dlrb_number(p, '\0', &m->at) : NULL;
    return p != NULL;
}

bool dlrb_field_ok(const char *field)
{
    struct dlrb_mark m;
    return field && (!field[0] || dlrb_mark_parse(field, &m));
}

bool dlrb_mark_format(const struct dlrb_mark *m, char *out, size_t cap)
{
    if (!dlrb_text_ok(m->group, m->cleared) || m->since <= 0 || m->since_at <= 0 ||
        m->at <= 0)
        return false;
    int w = snprintf(out, cap, "%s:%s:%lld:%lld:%lld",
                     m->cleared ? "cleared" : "parked", m->group, m->since,
                     m->since_at, m->at);
    return w > 0 && (size_t)w < cap;
}

uint64_t dlrb_lane(const char *worktree, const char *note)
{
    uint64_t h = dlrb_fnv(1469598103934665603ULL, worktree, strlen(worktree));
    h = dlrb_fnv(h, "", 1);
    return dlrb_fnv(h, note, strlen(note));
}

static uint64_t dlrb_path_hash(const char *path, size_t len)
{
    return dlrb_fnv(1469598103934665603ULL, path, len);
}

static bool dlrb_hash_in(const struct dlrb_files *f, uint64_t h)
{
    for (size_t i = 0; i < f->n; i++)
        if (f->h[i] == h)
            return true;
    return false;
}

void dlrb_files_add(struct dlrb_files *f, const char *path, size_t len)
{
    uint64_t h = dlrb_path_hash(path, len);
    if (!f->known || len == 0 || dlrb_hash_in(f, h))
        return;
    if (f->n == DLRB_FILES_MAX) {
        f->known = false;
        return;
    }
    f->h[f->n++] = h;
}

void dlrb_files_parse(struct dlrb_files *f, const char *lines)
{
    memset(f, 0, sizeof(*f));
    f->known = lines != NULL;
    while (f->known && *lines) {
        size_t n = strcspn(lines, "\n");
        size_t len = n;
        while (len > 0 && lines[len - 1] == '\r')
            len--;
        dlrb_files_add(f, lines, len);
        lines += n + (lines[n] == '\n');
    }
}

bool dlrb_files_has(const struct dlrb_files *f, const char *path)
{
    return f->known && dlrb_hash_in(f, dlrb_path_hash(path, strlen(path)));
}

bool dlrb_files_disjoint(const struct dlrb_files *a,
                         const struct dlrb_files *b)
{
    if (!a->known || !b->known)
        return false;
    for (size_t i = 0; i < a->n; i++)
        if (dlrb_hash_in(b, a->h[i]))
            return false;
    return true;
}

static bool dlrb_qualifies(const struct dlrb_fail *f,
                           const struct dlrb_fail *cur,
                           const struct dlrb_fail *const *chosen, size_t got)
{
    if (f->lane == cur->lane || !dlrb_files_disjoint(&f->files, &cur->files))
        return false;
    for (size_t j = 0; j < got; j++)
        if (f->lane == chosen[j]->lane ||
            !dlrb_files_disjoint(&f->files, &chosen[j]->files))
            return false;
    return true;
}

size_t dlrb_trip_pick(const struct dlrb_fail *cands, size_t n,
                      const struct dlrb_fail *cur, unsigned k,
                      long long *since, long long *since_at)
{
    const struct dlrb_fail *chosen[8];
    size_t got = 0;
    if (!cur->files.known)
        return 0;
    for (size_t i = 0; i < n && got < k && got < 8; i++)
        if (dlrb_qualifies(&cands[i], cur, chosen, got))
            chosen[got++] = &cands[i];
    if (got) {
        *since = chosen[got - 1]->seq;
        *since_at = chosen[got - 1]->at;
    }
    return got;
}

bool dlrb_is_parked(const struct dl_row *r)
{
    return strcmp(r->state, "queued") == 0 && strcmp(r->phase, DLRB_PHASE) == 0;
}

static struct dlrb_episode *dlrb_episode_slot(struct dlrb_episode *out,
                                              size_t *m, size_t cap,
                                              const char *group)
{
    for (size_t i = 0; i < *m; i++)
        if (strcmp(out[i].group, group) == 0)
            return &out[i];
    if (*m == cap)
        return NULL;
    struct dlrb_episode *e = &out[(*m)++];
    memset(e, 0, sizeof(*e));
    (void)snprintf(e->group, sizeof(e->group), "%s", group);
    return e;
}

size_t dlrb_episodes(const struct dl_row *rows, size_t n,
                     struct dlrb_episode *out, size_t cap)
{
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        struct dlrb_mark mk;
        if (!dlrb_is_parked(&rows[i]) ||
            !dlrb_mark_parse(rows[i].red_main, &mk) || mk.cleared)
            continue;
        struct dlrb_episode *e = dlrb_episode_slot(out, &m, cap, mk.group);
        if (!e)
            continue;
        e->parked++;
        if (!e->since_at || mk.since_at < e->since_at) {
            e->since = mk.since;
            e->since_at = mk.since_at;
        }
        if (mk.at > e->newest_at)
            e->newest_at = mk.at;
    }
    return m;
}

bool dlrb_episode_live(const struct dlrb_episode *e,
                       const struct dlrb_policy *p, long long now)
{
    return e->parked > 0 && e->newest_at >= now - p->age_s &&
           e->since_at >= now - p->max_s;
}

/* ── driver glue: rows, files, ledger ────────────────────────────────── */

size_t dlrb_append(const struct dl_row *r, char *out, size_t cap,
                   size_t size)
{
    char member[192];
    if (!r->red_main[0] || !dlrb_field_ok(r->red_main) || size < 2)
        return size;
    int n = snprintf(member, sizeof(member), ",\"red_main\":\"%.127s\"}\n",
                     r->red_main);
    if (n <= 0 || n >= (int)sizeof(member) || (size_t)n >= cap - (size - 2))
        return size;
    memcpy(out + size - 2, member, (size_t)n + 1);
    return size - 2 + (size_t)n;
}

static bool dlrb_load(const struct dl_dirs *d, struct dl_row **rows,
                      size_t *n)
{
    char qpath[4096 + 32];
    *rows = NULL;
    *n = 0;
    return snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) <
               (int)sizeof(qpath) &&
           dl_load_rows(qpath, rows, n, NULL, 0);
}

/* The paths base..local changes, through the land leaf's git seam. */
static void dlrb_row_files(const char *wt, const char *base,
                           const char *local, struct dlrb_files *f)
{
    enum { DLRB_DIFF_CAP = 65536 };
    memset(f, 0, sizeof(*f));
    if (!dl_sha_ok(base) || !dl_sha_ok(local))
        return;
    char *out = zcl_calloc(1, DLRB_DIFF_CAP, "dev.land.red.files");
    const char *args[] = { "diff", "--no-renames", "--name-only", base,
                           local, "--", NULL };
    if (out && dl_git(wt, args, out, DLRB_DIFF_CAP, DL_GIT_TIMEOUT_MS) == 0 &&
        strlen(out) + 1 < DLRB_DIFF_CAP)
        dlrb_files_parse(f, out);
    free(out);
}

struct dlrb_cand {
    long long seq, at;
    uint64_t lane;
    char base[80], local[80];
};

struct dlrb_scan {
    const char *group;
    long long horizon;
    struct dlrb_cand c[DLRB_CANDS];
    size_t n;
};

static bool dlrb_clears(const struct dl_row *r, const char *group)
{
    struct dlrb_mark m;
    return strcmp(r->state, "landed") == 0 &&
           dlrb_mark_parse(r->red_main, &m) && m.cleared &&
           dlrb_list_has(m.group, group);
}

static bool dlrb_scan_visit(const struct dl_row *r, void *context)
{
    struct dlrb_scan *s = context;
    char g[DLRB_GROUP_MAX];
    if (dlrb_clears(r, s->group)) {
        s->n = 0; /* evidence before a clearing landing never counts */
        return true;
    }
    if (strcmp(r->state, "failed") != 0 || strcmp(r->dimension, "test") != 0 ||
        r->terminal_recorded_at < s->horizon ||
        !dlmr_group_of("test", r->detail, g, sizeof(g)) ||
        strcmp(g, s->group) != 0)
        return true;
    if (s->n == DLRB_CANDS) {
        memmove(&s->c[0], &s->c[1], sizeof(s->c[0]) * (DLRB_CANDS - 1));
        s->n--;
    }
    struct dlrb_cand *c = &s->c[s->n++];
    c->seq = r->seq;
    c->at = r->terminal_recorded_at;
    c->lane = dlrb_lane(r->worktree, r->note);
    (void)snprintf(c->base, sizeof(c->base), "%.79s", r->base);
    (void)snprintf(c->local, sizeof(c->local), "%.79s", r->local);
    return true;
}

/* Newest first, each with the paths its own pair changed. */
static void dlrb_scan_fails(const struct dl_dirs *d, const struct dlrb_scan *s,
                            struct dlrb_fail *f)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct dlrb_cand *c = &s->c[s->n - 1 - i];
        f[i].seq = c->seq;
        f[i].at = c->at;
        f[i].lane = c->lane;
        dlrb_row_files(d->wt, c->base, c->local, &f[i].files);
    }
}

/* Does the ledger trip on `group` for this failure? */
static bool dlrb_ledger_trip(const struct dl_dirs *d, const char *group,
                             const struct dlrb_fail *cur,
                             const struct dlrb_policy *p, long long now,
                             struct dlrb_mark *m)
{
    char path[4096 + 32];
    struct dlrb_scan *s = zcl_calloc(1, sizeof(*s), "dev.land.red.scan");
    struct dlrb_fail *f = zcl_calloc(DLRB_CANDS, sizeof(*f), "dev.land.red.fail");
    size_t got = 0;
    bool fits = snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) <
                (int)sizeof(path);
    if (s && f && fits) {
        s->group = group;
        s->horizon = now - p->age_s;
        if (dl_history_read(path, dlrb_scan_visit, s, NULL, 0)) {
            dlrb_scan_fails(d, s, f);
            got = dlrb_trip_pick(f, s->n, cur, p->k, &m->since, &m->since_at);
        }
    }
    free(s);
    free(f);
    return got >= p->k;
}

static bool dlrb_live_mark(const struct dl_row *rows, size_t n,
                           const char *group, const struct dlrb_policy *p,
                           long long now, struct dlrb_mark *m)
{
    struct dlrb_episode e[DLRB_EPISODES];
    size_t count = dlrb_episodes(rows, n, e, DLRB_EPISODES);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(e[i].group, group) != 0 ||
            !dlrb_episode_live(&e[i], p, now))
            continue;
        m->since = e[i].since;
        m->since_at = e[i].since_at;
        return true;
    }
    return false;
}

/* A row parked on `group` before and released by an age-out, still within
 * the episode's maximum. */
static bool dlrb_remembers(const struct dl_row *r, const char *group,
                           const struct dlrb_policy *p, long long now,
                           struct dlrb_mark *m)
{
    struct dlrb_mark x;
    if (!dlrb_mark_parse(r->red_main, &x) || x.cleared ||
        strcmp(x.group, group) != 0 || x.since_at < now - p->max_s)
        return false;
    m->since = x.since;
    m->since_at = x.since_at;
    return true;
}

static bool dlrb_memory_mark(const struct dl_row *rows, size_t n,
                             const struct dl_row *row, const char *group,
                             const struct dlrb_policy *p, long long now,
                             struct dlrb_mark *m)
{
    if (dlrb_remembers(row, group, p, now, m))
        return true;
    for (size_t i = 0; row->proof_intent[0] && i < n; i++)
        if (rows[i].seq != row->seq && strcmp(rows[i].state, "queued") == 0 &&
            strcmp(rows[i].proof_intent, row->proof_intent) == 0 &&
            dlrb_remembers(&rows[i], group, p, now, m))
            return true;
    return false;
}

/* Park or not; *fresh when this failure starts a new episode. */
static bool dlrb_decide(const struct dl_dirs *d, const struct dl_row *row,
                        const char *group, const struct dlrb_fail *cur,
                        const struct dlrb_policy *p, struct dlrb_mark *m,
                        bool *fresh)
{
    struct dl_row *rows = NULL;
    size_t n = 0;
    long long now = dlrb_now();
    bool park = false;
    memset(m, 0, sizeof(*m));
    (void)snprintf(m->group, sizeof(m->group), "%s", group);
    m->at = now;
    *fresh = false;
    if (!dlrb_load(d, &rows, &n))
        return false;
    park = dlrb_live_mark(rows, n, group, p, now, m) ||
           dlrb_memory_mark(rows, n, row, group, p, now, m);
    free(rows);
    if (!park)
        park = *fresh = dlrb_ledger_trip(d, group, cur, p, now, m);
    return park;
}

/* ── parking and release ─────────────────────────────────────────────── */

static void dlrb_park_fields(struct dl_row *r, const struct dlrb_mark *m,
                             const char *why)
{
    if (!dlrb_mark_format(m, r->red_main, sizeof(r->red_main)))
        r->red_main[0] = '\0';
    (void)snprintf(r->state, sizeof(r->state), "queued");
    (void)snprintf(r->phase, sizeof(r->phase), DLRB_PHASE);
    (void)snprintf(r->dimension, sizeof(r->dimension), "main_red");
    (void)snprintf(r->detail, sizeof(r->detail),
                   "main red on %.71s since seq %lld: parked, not failed; "
                   "requeued for a fresh proof when a proof passes %.71s or "
                   "the evidence ages out; failure: %.600s",
                   m->group, m->since, m->group, why ? why : "");
    r->local[0] = '\0';
    r->base[0] = '\0';
    r->tree[0] = '\0';
    r->proof_intent[0] = '\0';
    r->train_commit[0] = '\0';
    r->train_group[0] = '\0';
    r->producer_recovered = 0;
    dl_publication_clear(r);
}

/* One row, proven alone, whose only failure is the red group. The first
 * row parked in an episode posts its one board alert. */
static bool dlrb_park(const struct dl_dirs *d, struct dl_row *row,
                      const struct dlrb_mark *m, bool fresh,
                      const char *detail, struct zcl_command_reply *reply)
{
    char why[640];
    (void)snprintf(why, sizeof(why), "%.600s", detail ? detail : "");
    dl_log(row, "main red: parked instead of failed: ");
    dl_log(row, why);
    dl_log(row, "\n");
    dlrb_park_fields(row, m, why);
    if (!dl_commit_or_report(d, row, false, reply, "parked"))
        return true;
    dl_step_reply(reply, row, "parked");
    (void)json_push_kv_str(&reply->data, "red_main_group", m->group);
    (void)json_push_kv_int(&reply->data, "parked_rows", 1);
    if (fresh)
        (void)dl_board_post(d, row, "main_red");
    return true;
}

/* One "Failed groups:" list line of the test runner ("  - G: exit ..."). */
static void dlrb_failed_line(const char *line, const char *group,
                             size_t *mine, size_t *other)
{
    size_t n = strcspn(line + 4, ":");
    if (n == strlen(group) && strncmp(line + 4, group, n) == 0)
        (*mine)++;
    else
        (*other)++;
}

bool dlrb_log_only_group(const char *path, const char *group)
{
    char line[4096];
    size_t mine = 0, other = 0;
    bool in_list = false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Failed groups:", 14) == 0) {
            in_list = true;
            mine = other = 0;
        } else if (in_list && strncmp(line, "  - ", 4) == 0) {
            dlrb_failed_line(line, group, &mine, &other);
        } else if (strncmp(line, "      ", 6) != 0) {
            in_list = false;
        }
    }
    (void)fclose(f);
    return mine > 0 && other == 0;
}

/* Is `group` the only failed group of the settled attempt's test log? An
 * unreadable log is not proof of it. */
bool dlrb_failed_only(const struct dl_row *row, const char *group)
{
    char path[4600];
    if (!row->failed_proof.root[0] || !row->failed_proof.attempt[0])
        return false;
    int w = snprintf(path, sizeof(path),
                     "%.4096s/.cache/zcl-dev-proof/attempts/%.143s/logs/"
                     "%.64s-%.64s.test.log", row->failed_proof.root,
                     row->failed_proof.attempt, row->local, row->base);
    return w > 0 && (size_t)w < sizeof(path) &&
           dlrb_log_only_group(path, group);
}

static bool dlrb_only_group(const struct dl_row *row, const char *group)
{
    return dl_stubbed() /* stub failures name exactly one group */ ||
           dlrb_failed_only(row, group);
}

bool dlrb_on_failure(const struct dl_dirs *d, struct dl_row *row,
                     const char *group, const char *detail,
                     struct zcl_command_reply *reply)
{
    struct dlrb_policy p;
    struct dlrb_fail cur;
    struct dlrb_mark m;
    bool fresh = false;
    char own[DLRB_GROUP_MAX + 32];
    dlrb_policy_read(&p);
    if (!p.enabled || !dlrb_group_ok(group) || !dlrb_only_group(row, group))
        return false;
    memset(&cur, 0, sizeof(cur));
    cur.lane = dlrb_lane(row->worktree, row->note);
    dlrb_row_files(d->wt, row->base, row->local, &cur.files);
    (void)snprintf(own, sizeof(own), "tests/harness/src/%s.c", group);
    /* A change to the group's own test is a likely fix: never parked. */
    if (!cur.files.known || dlrb_files_has(&cur.files, own))
        return false;
    if (!dlrb_decide(d, row, group, &cur, &p, &m, &fresh))
        return false;
    /* A train is never bisected on a red group: its members prove alone,
     * so the ones that do not run the group still land. */
    if (dl_train_formed(row) && dl_train_release_solo(d, row, detail, reply))
        return true;
    return dlrb_park(d, row, &m, fresh, detail, reply);
}

struct dlrb_release {
    const char *group;
    bool clear;
    long long stale_before;
    size_t count;
};

static void dlrb_release_one(struct dl_row *r, const struct dlrb_release *rel,
                             const struct dlrb_mark *m)
{
    if (dlrb_is_parked(r)) {
        (void)snprintf(r->phase, sizeof(r->phase), "rebase");
        r->dimension[0] = '\0';
        /* Proven alone because main was red: once it is clear the row may
         * ride a train again. */
        if (rel->clear)
            r->train_solo = 0;
        (void)snprintf(r->detail, sizeof(r->detail),
                       "main red on %.71s %s: requeued for a complete fresh "
                       "proof on the newest main", rel->group,
                       rel->clear ? "cleared by a passing proof" : "aged out");
    }
    if (rel->clear || m->since_at < rel->stale_before)
        r->red_main[0] = '\0';
}

static int dlrb_release_rows(struct dl_row *rows, size_t n, void *context)
{
    struct dlrb_release *rel = context;
    for (size_t i = 0; i < n; i++) {
        struct dlrb_mark m;
        if (strcmp(rows[i].state, "queued") != 0 ||
            !dlrb_mark_parse(rows[i].red_main, &m) || m.cleared ||
            strcmp(m.group, rel->group) != 0 ||
            (!dlrb_is_parked(&rows[i]) && !rel->clear))
            continue;
        dlrb_release_one(&rows[i], rel, &m);
        rel->count++;
    }
    return rel->count ? 1 : 0;
}

static void dlrb_release(const struct dl_dirs *d, const char *group,
                         bool clear, long long stale_before)
{
    struct dlrb_release rel = { group, clear, stale_before, 0 };
    (void)dl_rows_edit(d, dlrb_release_rows, &rel);
}

void dlrb_tend(const struct dl_dirs *d)
{
    struct dlrb_policy p;
    struct dlrb_episode e[DLRB_EPISODES];
    struct dl_row *rows = NULL;
    size_t n = 0;
    dlrb_policy_read(&p);
    if (!dlrb_load(d, &rows, &n))
        return;
    size_t count = dlrb_episodes(rows, n, e, DLRB_EPISODES);
    free(rows);
    long long now = dlrb_now();
    for (size_t i = 0; i < count; i++)
        if (!p.enabled || !dlrb_episode_live(&e[i], &p, now))
            dlrb_release(d, e[i].group, !p.enabled, now - p.max_s);
}

/* ── clearing ────────────────────────────────────────────────────────── */

static bool dlrb_log_has(const char *path, const char *needle)
{
    char line[4096];
    bool found = false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f))
        found = strncmp(line, needle, strlen(needle)) == 0;
    (void)fclose(f);
    return found;
}

/* Does a retained attempt of this exact pair show `group` passing? */
bool dlrb_attempts_show(const char *wt, const char *local,
                               const char *base, const char *group)
{
    char dir[4200], prefix[168], needle[128], path[4600];
    struct dirent *e;
    bool ran = false;
    (void)snprintf(dir, sizeof(dir), "%.4096s/.cache/zcl-dev-proof/attempts", wt);
    (void)snprintf(prefix, sizeof(prefix), "%.64s-%.64s.", local, base);
    (void)snprintf(needle, sizeof(needle), "==================== %.71s (PASS",
                   group);
    DIR *dh = opendir(dir);
    if (!dh)
        return false;
    while (!ran && (e = readdir(dh)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) != 0)
            continue;
        int w = snprintf(path, sizeof(path),
                         "%s/%.255s/logs/%.64s-%.64s.test.log", dir,
                         e->d_name, local, base);
        ran = w > 0 && (size_t)w < sizeof(path) && dlrb_log_has(path, needle);
    }
    (void)closedir(dh);
    return ran;
}

#if defined(ZCL_TESTING)
static bool dlrb_tree_has(const char *wt, const char *commit, const char *path)
{
    char spec[160];
    const char *args[] = { "cat-file", "-e", spec, NULL };
    (void)snprintf(spec, sizeof(spec), "%.64s:%.64s", commit, path);
    return dl_sha_ok(commit) &&
           dl_git(wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
}
#endif

static bool dlrb_proof_ran(const struct dl_dirs *d, const struct dl_row *row,
                           const char *group)
{
    if (!dl_sha_ok(row->local) || !dl_sha_ok(row->base))
        return false;
#if defined(ZCL_TESTING)
    if (dl_stubbed())
        return dlrb_tree_has(d->wt, row->local, "red-fix");
#endif
    if (dl_stubbed())
        return false;
    return dlrb_attempts_show(d->wt, row->local, row->base, group);
}

/* Add a distinct group. A group past DLRB_RECENT_MAX is never dropped
 * silently: the set is marked overflowed and the caller stays conservative. */
void dlrb_groups_add(struct dlrb_groups *gs, const char *group)
{
    for (size_t i = 0; i < gs->n; i++)
        if (strcmp(gs->g[i], group) == 0)
            return;
    if (gs->n < DLRB_RECENT_MAX)
        (void)snprintf(gs->g[gs->n++], DLRB_GROUP_MAX, "%s", group);
    else
        gs->overflow = true;
}

/* Groups queued rows are parked on or remember. */
static void dlrb_marked_groups(const struct dl_row *rows, size_t n,
                               struct dlrb_groups *gs)
{
    for (size_t i = 0; i < n; i++) {
        struct dlrb_mark x;
        if (strcmp(rows[i].state, "queued") == 0 &&
            dlrb_mark_parse(rows[i].red_main, &x) && !x.cleared)
            dlrb_groups_add(gs, x.group);
    }
}

struct dlrb_recent {
    long long horizon;
    struct dlrb_groups *gs;
};

/* Groups of recent test failures: a landing that passes one of them has
 * fixed main for the evidence the ledger holds, parked rows or not. */
static bool dlrb_recent_visit(const struct dl_row *r, void *context)
{
    struct dlrb_recent *rc = context;
    char g[DLRB_GROUP_MAX];
    if (strcmp(r->state, "failed") == 0 && strcmp(r->dimension, "test") == 0 &&
        r->terminal_recorded_at >= rc->horizon &&
        dlmr_group_of("test", r->detail, g, sizeof(g)) && dlrb_group_ok(g))
        dlrb_groups_add(rc->gs, g);
    return true;
}

static void dlrb_recent_groups(const struct dl_dirs *d,
                               const struct dlrb_policy *p,
                               struct dlrb_groups *gs)
{
    char path[4096 + 32];
    struct dlrb_recent rc = { dlrb_now() - p->age_s, gs };
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) <
        (int)sizeof(path))
        (void)dl_history_read(path, dlrb_recent_visit, &rc, NULL, 0);
}

/* Append `group` to the '+'-joined `list` when it fits; false when it does
 * not (the list is left unchanged). */
bool dlrb_list_add(char *list, size_t cap, const char *group)
{
    size_t have = strlen(list);
    int w = snprintf(list + have, cap - have, "%s%s", have ? "+" : "", group);
    if (w < 0 || (size_t)w >= cap - have) {
        list[have] = '\0';
        return false;
    }
    return true;
}

void dlrb_on_pass(const struct dl_dirs *d, struct dl_row *row)
{
    struct dlrb_policy p;
    struct dlrb_groups gs = { .n = 0 };
    struct dlrb_mark mk = { .cleared = true };
    struct dl_row *rows = NULL;
    size_t n = 0;
    dlrb_policy_read(&p);
    if (!p.enabled || !dlrb_load(d, &rows, &n))
        return;
    dlrb_marked_groups(rows, n, &gs);
    free(rows);
    dlrb_recent_groups(d, &p, &gs);
    if (gs.overflow)
        dl_log(row, "main red: more recently failed groups than one pass "
                    "checks; the extra ones keep their evidence until a "
                    "clean signal\n");
    for (size_t i = 0; i < gs.n; i++) {
        if (!dlrb_proof_ran(d, row, gs.g[i]))
            continue;
        /* A group the marker cannot name must keep its evidence and its
         * parked rows, or the landing would clear what it never records. */
        if (!dlrb_list_add(mk.group, sizeof(mk.group), gs.g[i])) {
            dl_log(row, "main red: a passed group does not fit the cleared "
                        "marker; its evidence stays until a later pass\n");
            continue;
        }
        dl_log(row, "main red: this proof passed a group with recent "
                    "failures; its evidence and parked rows are cleared\n");
        dlrb_release(d, gs.g[i], true, 0);
    }
    mk.since = row->seq > 0 ? row->seq : 1;
    mk.since_at = mk.at = dlrb_now();
    if (mk.group[0] &&
        !dlrb_mark_format(&mk, row->red_main, sizeof(row->red_main)))
        row->red_main[0] = '\0';
}

/* ── status ──────────────────────────────────────────────────────────── */

static void dlrb_line(const struct dlrb_episode *e, char *out, size_t cap)
{
    (void)snprintf(out, cap, "main red on %.71s since seq %lld: %zu parked",
                   e->group, e->since, e->parked);
}

static bool dlrb_push_one(struct json_value *arr, const struct dlrb_episode *e)
{
    struct json_value item;
    char line[160];
    dlrb_line(e, line, sizeof(line));
    json_init(&item);
    json_set_object(&item);
    bool ok = json_push_kv_str(&item, "group", e->group) &&
              json_push_kv_int(&item, "since_seq", e->since) &&
              json_push_kv_int(&item, "since_unix", e->since_at) &&
              json_push_kv_int(&item, "newest_parked_unix", e->newest_at) &&
              json_push_kv_int(&item, "parked", (int64_t)e->parked) &&
              json_push_kv_str(&item, "line", line) &&
              json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

bool dlrb_push_status(struct json_value *data, const struct dl_row *rows,
                      size_t n)
{
    struct dlrb_episode e[DLRB_EPISODES];
    struct json_value arr;
    size_t count = dlrb_episodes(rows, n, e, DLRB_EPISODES);
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; ok && i < count; i++)
        ok = dlrb_push_one(&arr, &e[i]);
    ok = ok && json_push_kv(data, "main_red_breaker", &arr);
    json_free(&arr);
    return ok;
}

bool dlrb_screen(const struct dl_row *rows, size_t n, char *screen,
                 size_t cap, size_t *used)
{
    struct dlrb_episode e[DLRB_EPISODES];
    size_t count = dlrb_episodes(rows, n, e, DLRB_EPISODES);
    for (size_t i = 0; i < count; i++) {
        char line[160];
        dlrb_line(&e[i], line, sizeof(line));
        int w = snprintf(screen + *used, cap - *used, "  %s\n", line);
        if (w <= 0 || (size_t)w >= cap - *used)
            return false;
        *used += (size_t)w;
    }
    return true;
}

#if defined(ZCL_TESTING)
int dlrb_stub_read(const char *stub, const char *wt, const char *local,
                   char *dimension, size_t dim_cap, char *detail, size_t cap)
{
    const char *g = getenv("ZCL_LAND_PROOF_STUB_RED_GROUP");
    if (strcmp(stub, "red") != 0)
        return 0;
    if (!g || !dlrb_group_ok(g))
        g = "test_red_fixture";
    if (!dlrb_tree_has(wt, local, "red-break") &&
        (dlrb_tree_has(wt, local, "red-fix") ||
         dlrb_tree_has(wt, local, "red-skip"))) {
        (void)snprintf(detail, cap, "proof stub: red pass");
        return 1;
    }
    (void)snprintf(dimension, dim_cap, "test");
    (void)snprintf(detail, cap,
                   "test %.71s: FAIL at tests/harness/src/%.71s.c:7 "
                   "(stub red main)", g, g);
    return 2;
}
#endif
