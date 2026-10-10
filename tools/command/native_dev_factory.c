/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.agent.factory (alias dev.factory): a read-only report of factory waste over a window of the last
 * `hours` (default 48, 1..720). It replaces a host-side script and reads four
 * sources, each overridable by an environment variable for tests:
 *
 *   jobs      ZCL_DEV_FACTORY_JOBS      devbuild job ledger (JSONL)
 *   land      ZCL_DEV_FACTORY_LAND_DIR  directory holding outcomes.jsonl
 *   attempts  ZCL_DEV_FACTORY_ATTEMPTS  proof attempt directories
 *   proc      ZCL_DEV_FACTORY_PROC      stands in for /proc (pressure/ files)
 *
 * Output (zcl.dev_factory.v1): hours, window_s, jobs{...}, land_outcomes{...},
 * proof_attempts{...}, host{...}. Every source carries source = "ok" or
 * "absent". A malformed line is counted in skipped_lines; a line over
 * FAC_MAX_LINE bytes is counted in oversized_lines and never parsed; more
 * rows than the per-source cap makes that source report "refused_rows" with
 * no statistics, never a silently truncated sample. Percentiles are
 * nearest-rank. Nothing is written.
 *
 * Jobs also report first_job_per_cwd (the earliest ledger row of each cwd,
 * a cold-start proxy, against the rest), cold_build_seconds_estimate (a
 * proxy: first-job run time above the non-first median of its class) and
 * failed_runs_named / failed_runs_unnamed, where a failed run is named when
 * <cwd>/build/test-verdict.json ended within 120 s of it and lists groups.
 * cold_t_fast_* counts t-fast runs with cpu_s above 600 (cold builds), their
 * run_s total and how many ran without a -j token; warm_t_fast_n counts the
 * rest. */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/statvfs.h>
#endif

#define FAC_DEFAULT_HOURS 48
#define FAC_MAX_HOURS 720
#define FAC_MAX_LINE (1u << 20)
#define FAC_MAX_JOBS 200000u
#define FAC_MAX_DETAILS 1024u
#define FAC_MAX_ATTEMPTS 20000u
#define FAC_MAX_GROUPS 64u
#define FAC_DETAIL_BYTES 60u
#define FAC_TOP 8u
#define FAC_LANES 3
#define FAC_PATH 4096u
#define FAC_PAIR 82u
#define FAC_MAX_CWDS 4096u
#define FAC_CWD_SLOTS 8192u
#define FAC_VERDICT_MAX (1u << 16)
#define FAC_VERDICT_SKEW_S 120.0
#define FAC_NAME 64u
#define FAC_MAX_NAMES 64u
#define FAC_COLD_CPU_S 600.0 /* a t-fast run above this cpu_s is a cold build */

enum fac_class {
    FAC_LAND, FAC_T_FAST, FAC_LINT, FAC_PREPARE, FAC_BUILD, FAC_OTHER,
    FAC_NCLASS
};

static const char *const fac_class_names[FAC_NCLASS] = {
    "land", "t_fast", "lint", "prepare", "build", "other",
};

/* One input source's bookkeeping. */
struct fac_src {
    bool absent;
    bool refused_rows;
    int64_t skipped;
    int64_t oversized;
};

typedef bool (*fac_line_fn)(const char *line, size_t len, void *ctx,
                            struct fac_src *src);

/* ── bounded line reader ─────────────────────────────────────────────────── */

/* Read the rest of an oversized line up to its newline. */
static void fac_drain_line(FILE *fp)
{
    int c;
    do {
        c = fgetc(fp);
    } while (c != EOF && c != '\n');
}

/* Walk `path` line by line. Oversized lines are counted and skipped. The
 * callback returns false to stop (row cap reached). False when the file
 * cannot be opened (src->absent set). */
static bool fac_each_line(const char *path, fac_line_fn fn, void *ctx,
                          struct fac_src *src)
{
    FILE *fp = fopen(path, "r");
    char *buf;
    if (!fp) {
        src->absent = true;
        return false;
    }
    buf = zcl_malloc(FAC_MAX_LINE + 2u, "dev_factory_line");
    if (!buf) {
        (void)fclose(fp);
        src->absent = true;
        return false;
    }
    while (fgets(buf, (int)(FAC_MAX_LINE + 2u), fp)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[--len] = '\0';
        else if (len > FAC_MAX_LINE) {
            src->oversized++;
            fac_drain_line(fp);
            continue;
        }
        if (len > FAC_MAX_LINE) {
            src->oversized++;
            continue;
        }
        if (len == 0)
            continue;
        if (!fn(buf, len, ctx, src))
            break;
    }
    free(buf);
    (void)fclose(fp);
    return true;
}

/* ── small helpers ───────────────────────────────────────────────────────── */

static bool fac_num(const struct json_value *v, double *out)
{
    if (v && v->type == JSON_INT) {
        *out = (double)json_get_int(v);
        return true;
    }
    if (v && v->type == JSON_REAL) {
        *out = json_get_real(v);
        return true;
    }
    return false;
}

static double fac_field(const struct json_value *row, const char *key)
{
    double d = 0;
    return fac_num(json_get(row, key), &d) ? d : 0;
}

static const char *fac_text(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s ? s : "";
}

static int fac_cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Nearest-rank percentile of a sorted array. */
static double fac_pct(const double *sorted, size_t n, double p)
{
    size_t rank;
    if (n == 0)
        return 0;
    rank = (size_t)(p * (double)n);
    if ((double)rank < p * (double)n)
        rank++;
    if (rank < 1)
        rank = 1;
    return sorted[rank - 1];
}

/* Resolve one source path: the env override, else $HOME/<rel>. */
static bool fac_path(const char *over, const char *rel, char *out, size_t cap)
{
    const char *home;
    int n;
    if (over && over[0])
        n = snprintf(out, cap, "%s", over);
    else if ((home = getenv("HOME")) && home[0])
        n = snprintf(out, cap, "%s/%s", home, rel);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

static void fac_push_src(struct json_value *obj, const struct fac_src *s)
{
    const char *state = s->absent ? "absent"
                        : s->refused_rows ? "refused_rows" : "ok";
    (void)json_push_kv_str(obj, "source", state);
    (void)json_push_kv_int(obj, "skipped_lines", s->skipped);
    (void)json_push_kv_int(obj, "oversized_lines", s->oversized);
}

/* Attach `child` under `key` and release it. */
static void fac_attach(struct json_value *obj, const char *key,
                       struct json_value *child)
{
    (void)json_push_kv(obj, key, child);
    json_free(child);
}

static void fac_new_obj(struct json_value *v)
{
    json_init(v);
    json_set_object(v);
}

/* Days since 1970-01-01 of a proleptic Gregorian date. */
static int64_t fac_days_from_civil(int64_t y, int64_t m, int64_t d)
{
    int64_t era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* "YYYY-MM-DDTHH:MM:SS[...]" in UTC to epoch seconds; false when malformed. */
static bool fac_parse_iso(const char *s, int64_t *out)
{
    int y, mo, d, h, mi, se;
    if (!s || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi,
                     &se) != 6)
        return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60)
        return false;
    *out = fac_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

/* ── jobs ────────────────────────────────────────────────────────────────── */

struct fac_job {
    int cls;
    bool lander;
    bool lane_side;
    bool has_tree;
    bool first;    /* earliest ledger row of its cwd */
    bool parallel; /* cmd carries a -j token */
    int rc;
    int64_t seq, ledger_idx, slot; /* slot: first-seen table, -1 untracked */
    size_t cwd_off;                /* cwd starts at key + cwd_off */
    double queued, started, ended, wait_s, run_s, cpu_s;
    char *key; /* tree 0x1f cmd 0x1f cwd */
};

/* Earliest (queued, idx) ledger row seen for one cwd, over the whole ledger. */
struct fac_cwd {
    char *cwd;
    double queued;
    int64_t idx;
};

struct fac_jobs {
    struct fac_job *v;
    size_t n, cap;
    double window_start;
    struct fac_cwd *cwds; /* open addressing, FAC_CWD_SLOTS entries */
    size_t ncwds;
    int64_t rows;    /* valid ledger rows, every project */
    bool cwd_cap_hit; /* a cwd could not be tracked (table or path cap) */
};

/* Saturating increment: a count never wraps. */
static void fac_inc(int64_t *v)
{
    if (*v < INT64_MAX)
        (*v)++;
}

static int fac_classify(const char *cmd)
{
    if (strstr(cmd, "dev land") || strstr(cmd, "dev proof"))
        return FAC_LAND;
    if (strstr(cmd, "t-fast"))
        return FAC_T_FAST;
    if (strstr(cmd, "lint"))
        return FAC_LINT;
    if (strstr(cmd, "prepare"))
        return FAC_PREPARE;
    if (strncmp(cmd, "make", 4) == 0 || strstr(cmd, " make "))
        return FAC_BUILD;
    return FAC_OTHER;
}

static char *fac_make_key(const char *tree, const char *cmd, const char *cwd)
{
    size_t n = strlen(tree) + strlen(cmd) + strlen(cwd) + 3;
    char *k = zcl_malloc(n, "dev_factory_key");
    if (k)
        (void)snprintf(k, n, "%s\x1f%s\x1f%s", tree, cmd, cwd);
    return k;
}

static bool fac_job_grow(struct fac_jobs *j)
{
    struct fac_job *nv;
    size_t ncap;
    if (j->n < j->cap)
        return true;
    ncap = j->cap ? j->cap * 2 : 1024;
    nv = zcl_realloc(j->v, ncap * sizeof(*nv), "dev_factory_jobs");
    if (!nv)
        return false;
    j->v = nv;
    j->cap = ncap;
    return true;
}

static uint64_t fac_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ull;
    return h;
}

/* Slot of `cwd` in the first-seen table, keeping the earliest (queued, idx)
 * row of each cwd. -1 when it cannot be tracked (empty, too long, table or
 * allocation full); those cases set cwd_cap_hit. */
static int64_t fac_cwd_slot(struct fac_jobs *j, const char *cwd, double queued,
                            int64_t idx)
{
    size_t len = strlen(cwd), mask = FAC_CWD_SLOTS - 1, s;
    struct fac_cwd *e;
    if (len == 0)
        return -1;
    if (len >= FAC_PATH) {
        j->cwd_cap_hit = true;
        return -1;
    }
    s = (size_t)fac_hash(cwd) & mask;
    while (j->cwds[s].cwd && strcmp(j->cwds[s].cwd, cwd) != 0)
        s = (s + 1) & mask;
    e = &j->cwds[s];
    if (e->cwd) {
        if (queued < e->queued || (queued == e->queued && idx < e->idx)) {
            e->queued = queued;
            e->idx = idx;
        }
        return (int64_t)s;
    }
    if (j->ncwds < FAC_MAX_CWDS)
        e->cwd = zcl_malloc(len + 1, "dev_factory_cwd");
    if (!e->cwd) {
        j->cwd_cap_hit = true;
        return -1;
    }
    memcpy(e->cwd, cwd, len + 1);
    e->queued = queued;
    e->idx = idx;
    j->ncwds++;
    return (int64_t)s;
}

/* True when a whitespace-separated token of cmd is -j or -j<digits>. */
static bool fac_has_j(const char *cmd)
{
    const char *p = cmd;
    while (*p) {
        const char *t;
        while (*p == ' ' || *p == '\t')
            p++;
        t = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (p - t >= 2 && t[0] == '-' && t[1] == 'j') {
            if (p - t == 2 || (t[2] >= '0' && t[2] <= '9'))
                return true;
        }
    }
    return false;
}

static void fac_job_fill(struct fac_job *jb, const struct json_value *row,
                         int64_t seq)
{
    const char *cmd = fac_text(row, "cmd");
    const char *cwd = fac_text(row, "cwd");
    const char *tree = fac_text(row, "tree");
    memset(jb, 0, sizeof(*jb));
    jb->slot = -1;
    jb->parallel = fac_has_j(cmd);
    jb->cwd_off = strlen(tree) + strlen(cmd) + 2;
    jb->cls = fac_classify(cmd);
    jb->lander = strstr(cmd, "land drive") || strstr(cmd, "land step");
    jb->lane_side = jb->cls == FAC_LINT && !strstr(cwd, "/dev/land/wt");
    jb->has_tree = tree[0] != '\0';
    jb->rc = (int)fac_field(row, "rc");
    jb->seq = seq;
    jb->queued = fac_field(row, "queued");
    jb->started = fac_field(row, "started");
    jb->ended = fac_field(row, "ended");
    jb->wait_s = fac_field(row, "wait_s");
    jb->run_s = fac_field(row, "run_s");
    jb->cpu_s = fac_field(row, "cpu_s");
    jb->key = fac_make_key(tree, cmd, cwd);
}

static bool fac_job_line(const char *line, size_t len, void *ctx,
                         struct fac_src *src)
{
    struct fac_jobs *j = ctx;
    struct json_value row;
    double queued;
    int64_t idx, slot;
    json_init(&row);
    if (!json_read(&row, line, len) || row.type != JSON_OBJ ||
        !fac_num(json_get(&row, "queued"), &queued)) {
        src->skipped++;
        json_free(&row);
        return true;
    }
    idx = j->rows;
    fac_inc(&j->rows);
    slot = fac_cwd_slot(j, fac_text(&row, "cwd"), queued, idx);
    if (strcmp(fac_text(&row, "project"), "z23") == 0 &&
        queued >= j->window_start) {
        if (j->n >= FAC_MAX_JOBS) {
            src->refused_rows = true;
            json_free(&row);
            return false;
        }
        if (!fac_job_grow(j)) {
            src->absent = true;
            json_free(&row);
            return false;
        }
        fac_job_fill(&j->v[j->n], &row, (int64_t)j->n);
        j->v[j->n].ledger_idx = idx;
        j->v[j->n].slot = slot;
        j->n++;
    }
    json_free(&row);
    return true;
}

static void fac_jobs_free(struct fac_jobs *j)
{
    for (size_t i = 0; i < j->n; i++)
        free(j->v[i].key);
    free(j->v);
    if (j->cwds)
        for (size_t s = 0; s < FAC_CWD_SLOTS; s++)
            free(j->cwds[s].cwd);
    free(j->cwds);
}

/* Mark each window job that is the earliest ledger row of its cwd. */
static void fac_mark_first(struct fac_jobs *j)
{
    for (size_t i = 0; i < j->n; i++) {
        struct fac_job *jb = &j->v[i];
        const struct fac_cwd *e;
        if (jb->slot < 0)
            continue;
        e = &j->cwds[jb->slot];
        jb->first = e->queued == jb->queued && e->idx == jb->ledger_idx;
    }
}

static void fac_class_stats(const struct fac_jobs *j, int cls, double *w,
                            double *r, struct json_value *out)
{
    size_t n = 0;
    int64_t failed = 0;
    double run_sum = 0, cpu_sum = 0;
    for (size_t i = 0; i < j->n; i++) {
        const struct fac_job *jb = &j->v[i];
        if (jb->cls != cls)
            continue;
        w[n] = jb->wait_s;
        r[n] = jb->run_s;
        n++;
        failed += jb->rc != 0;
        run_sum += jb->run_s;
        cpu_sum += jb->cpu_s;
    }
    qsort(w, n, sizeof(*w), fac_cmp_double);
    qsort(r, n, sizeof(*r), fac_cmp_double);
    (void)json_push_kv_int(out, "n", (int64_t)n);
    (void)json_push_kv_real(out, "wait_p50_s", fac_pct(w, n, 0.50));
    (void)json_push_kv_real(out, "wait_p95_s", fac_pct(w, n, 0.95));
    (void)json_push_kv_real(out, "run_p50_s", fac_pct(r, n, 0.50));
    (void)json_push_kv_real(out, "run_sum_s", run_sum);
    (void)json_push_kv_real(out, "cpu_sum_s", cpu_sum);
    (void)json_push_kv_int(out, "failed", failed);
}

static bool fac_classes(const struct fac_jobs *j, struct json_value *out)
{
    double *w = zcl_malloc((j->n + 1) * sizeof(*w), "dev_factory_w");
    double *r = zcl_malloc((j->n + 1) * sizeof(*r), "dev_factory_r");
    bool ok = w && r;
    for (int c = 0; ok && c < FAC_NCLASS; c++) {
        struct json_value one;
        fac_new_obj(&one);
        fac_class_stats(j, c, w, r, &one);
        fac_attach(out, fac_class_names[c], &one);
    }
    free(w);
    free(r);
    return ok;
}

static int fac_cmp_job_queued(const void *a, const void *b)
{
    const struct fac_job *x = a, *y = b;
    if (x->queued != y->queued)
        return x->queued < y->queued ? -1 : 1;
    return (x->seq > y->seq) - (x->seq < y->seq);
}

/* Index of the slot holding `key`, or the empty slot where it belongs. */
static size_t fac_slot(const char *const *tab, size_t mask, const char *key)
{
    size_t i = (size_t)fac_hash(key) & mask;
    while (tab[i] && strcmp(tab[i], key) != 0)
        i = (i + 1) & mask;
    return i;
}

/* Non-land jobs repeating an earlier rc==0 job's (tree, cmd, cwd). */
static int64_t fac_duplicates(struct fac_jobs *j)
{
    size_t cap = 16, mask;
    const char **tab;
    int64_t dup = 0;
    while (cap < j->n * 2 + 2)
        cap *= 2;
    mask = cap - 1;
    tab = zcl_calloc(cap, sizeof(*tab), "dev_factory_dup");
    if (!tab)
        return -1;
    qsort(j->v, j->n, sizeof(*j->v), fac_cmp_job_queued);
    for (size_t i = 0; i < j->n; i++) {
        const struct fac_job *jb = &j->v[i];
        size_t s;
        if (jb->cls == FAC_LAND || !jb->has_tree || !jb->key)
            continue;
        s = fac_slot(tab, mask, jb->key);
        dup += tab[s] != NULL;
        if (jb->rc == 0 && !tab[s])
            tab[s] = jb->key;
    }
    free(tab);
    return dup;
}

struct fac_iv {
    double s, e;
};

static int fac_cmp_iv(const void *a, const void *b)
{
    return fac_cmp_double(a, b);
}

/* [started, ended] clipped to the window; false when empty. */
static bool fac_clip(const struct fac_job *jb, double ws, double now,
                     struct fac_iv *iv)
{
    iv->s = jb->started > ws ? jb->started : ws;
    iv->e = jb->ended < now ? jb->ended : now;
    return jb->started > 0 && iv->e > iv->s;
}

/* Union length of the lander jobs' clipped intervals, and the sum of every
 * job's clipped run time. */
static bool fac_busy(const struct fac_jobs *j, double now, double *lander,
                     double *lanes)
{
    struct fac_iv *iv = zcl_malloc((j->n + 1) * sizeof(*iv), "dev_factory_iv");
    size_t n = 0;
    double cur_s = 0, cur_e = 0;
    if (!iv)
        return false;
    *lander = 0;
    *lanes = 0;
    for (size_t i = 0; i < j->n; i++) {
        struct fac_iv one;
        if (!fac_clip(&j->v[i], j->window_start, now, &one))
            continue;
        *lanes += one.e - one.s;
        if (j->v[i].lander)
            iv[n++] = one;
    }
    qsort(iv, n, sizeof(*iv), fac_cmp_iv);
    for (size_t i = 0; i < n; i++) {
        if (i == 0 || iv[i].s > cur_e) {
            *lander += cur_e - cur_s;
            cur_s = iv[i].s;
            cur_e = iv[i].e;
        } else if (iv[i].e > cur_e) {
            cur_e = iv[i].e;
        }
    }
    *lander += n ? cur_e - cur_s : 0;
    free(iv);
    return true;
}

static void fac_lane_lint(const struct fac_jobs *j, struct json_value *out)
{
    struct json_value ll;
    int64_t n = 0, failed = 0;
    for (size_t i = 0; i < j->n; i++) {
        n += j->v[i].lane_side;
        failed += j->v[i].lane_side && j->v[i].rc != 0;
    }
    fac_new_obj(&ll);
    (void)json_push_kv_int(&ll, "n", n);
    (void)json_push_kv_int(&ll, "failed", failed);
    fac_attach(out, "lane_lint", &ll);
}

/* Run times of the window jobs with first == want_first, in class cls (any
 * class when cls < 0), sorted into r. Returns the count and sets *sum. */
static size_t fac_collect_run(const struct fac_jobs *j, bool want_first,
                              int cls, double *r, double *sum)
{
    size_t n = 0;
    *sum = 0;
    for (size_t i = 0; i < j->n; i++) {
        const struct fac_job *jb = &j->v[i];
        if (jb->first != want_first || (cls >= 0 && jb->cls != cls))
            continue;
        r[n++] = jb->run_s;
        *sum += jb->run_s;
    }
    qsort(r, n, sizeof(*r), fac_cmp_double);
    return n;
}

static void fac_run_emit(struct json_value *out, const char *key,
                         const double *r, size_t n, double sum)
{
    struct json_value one;
    fac_new_obj(&one);
    (void)json_push_kv_int(&one, "n", (int64_t)n);
    (void)json_push_kv_real(&one, "run_p50_s", fac_pct(r, n, 0.50));
    (void)json_push_kv_real(&one, "run_p95_s", fac_pct(r, n, 0.95));
    (void)json_push_kv_real(&one, "run_sum_s", sum);
    fac_attach(out, key, &one);
}

/* The first job per cwd against the rest, by run time. */
static void fac_first_report(const struct fac_jobs *j, double *r,
                             struct json_value *out)
{
    struct json_value fp;
    double sum = 0;
    size_t n;
    fac_new_obj(&fp);
    n = fac_collect_run(j, true, -1, r, &sum);
    fac_run_emit(&fp, "first", r, n, sum);
    n = fac_collect_run(j, false, -1, r, &sum);
    fac_run_emit(&fp, "non_first", r, n, sum);
    (void)json_push_kv_int(&fp, "tracked_cwds", (int64_t)j->ncwds);
    (void)json_push_kv_bool(&fp, "cwd_cap_hit", j->cwd_cap_hit);
    fac_attach(out, "first_job_per_cwd", &fp);
}

/* Proxy for cold-build seconds: each first job's run time above the median
 * run time of the non-first jobs of its class. A first job whose class has
 * no non-first job has no baseline and adds nothing (counted in
 * *unbaselined). */
static double fac_cold_estimate(const struct fac_jobs *j, double *r,
                                int64_t *unbaselined)
{
    double total = 0;
    for (int c = 0; c < FAC_NCLASS; c++) {
        double sum = 0;
        size_t n = fac_collect_run(j, false, c, r, &sum);
        double base = fac_pct(r, n, 0.50);
        for (size_t i = 0; i < j->n; i++) {
            const struct fac_job *jb = &j->v[i];
            if (!jb->first || jb->cls != c)
                continue;
            if (n == 0)
                fac_inc(unbaselined);
            else if (jb->run_s > base)
                total += jb->run_s - base;
        }
    }
    return total;
}

static void fac_first_section(const struct fac_jobs *j, struct json_value *out)
{
    double *r = zcl_malloc((j->n + 1) * sizeof(*r), "dev_factory_first");
    double est;
    int64_t unbaselined = 0;
    if (!r)
        return;
    fac_first_report(j, r, out);
    est = fac_cold_estimate(j, r, &unbaselined);
    (void)json_push_kv_real(out, "cold_build_seconds_estimate", est);
    (void)json_push_kv_str(out, "cold_build_basis", "proxy");
    (void)json_push_kv_int(out, "cold_build_unbaselined_first_jobs",
                           unbaselined);
    free(r);
}

/* Cold t-fast builds: a t-fast or t-fast-exact run whose cpu_s exceeds
 * FAC_COLD_CPU_S. Reports the count, their total run time, how many ran
 * without -j, and the warm t-fast runs at or below the threshold. */
static void fac_cold_section(const struct fac_jobs *j, struct json_value *out)
{
    int64_t cold = 0, serial = 0, warm = 0;
    double run_sum = 0;
    for (size_t i = 0; i < j->n; i++) {
        const struct fac_job *jb = &j->v[i];
        if (jb->cls != FAC_T_FAST)
            continue;
        if (jb->cpu_s > FAC_COLD_CPU_S) {
            fac_inc(&cold);
            run_sum += jb->run_s;
            if (!jb->parallel)
                fac_inc(&serial);
        } else {
            fac_inc(&warm);
        }
    }
    (void)json_push_kv_real(out, "cold_t_fast_cpu_threshold_s",
                            FAC_COLD_CPU_S);
    (void)json_push_kv_int(out, "cold_t_fast_n", cold);
    (void)json_push_kv_real(out, "cold_t_fast_run_s", run_sum);
    (void)json_push_kv_int(out, "cold_t_fast_without_j", serial);
    (void)json_push_kv_int(out, "warm_t_fast_n", warm);
}

/* ── failed runs named by a test verdict ─────────────────────────────────── */

struct fac_name {
    char key[FAC_NAME];
    int64_t n;
};

struct fac_verdict {
    int64_t named, unnamed, overflow;
    size_t nn;
    struct fac_name names[FAC_MAX_NAMES];
};

static void fac_verdict_note(struct fac_verdict *v, const char *name)
{
    for (size_t i = 0; i < v->nn; i++) {
        if (strcmp(v->names[i].key, name) == 0) {
            fac_inc(&v->names[i].n);
            return;
        }
    }
    if (v->nn >= FAC_MAX_NAMES) {
        fac_inc(&v->overflow);
        return;
    }
    (void)snprintf(v->names[v->nn].key, sizeof(v->names[v->nn].key), "%s",
                   name);
    v->names[v->nn].n = 1;
    v->nn++;
}

/* Read `<cwd>/build/test-verdict.json`, a JSON object. False when absent,
 * oversized or not an object; doc is then not to be freed. */
static bool fac_verdict_read(const char *cwd, struct json_value *doc)
{
    char path[FAC_PATH + 32];
    char *buf;
    FILE *fp;
    size_t len = 0;
    bool ok = false;
    if (snprintf(path, sizeof(path), "%s/build/test-verdict.json", cwd) >=
        (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
    if (!fp)
        return false;
    buf = zcl_malloc(FAC_VERDICT_MAX + 1u, "dev_factory_verdict");
    if (buf) {
        len = fread(buf, 1, FAC_VERDICT_MAX + 1u, fp);
        if (len <= FAC_VERDICT_MAX) {
            json_init(doc);
            ok = json_read(doc, buf, len) && doc->type == JSON_OBJ;
            if (!ok)
                json_free(doc);
        }
        free(buf);
    }
    (void)fclose(fp);
    return ok;
}

/* ended_unix within the skew of the run's own end time. */
static bool fac_verdict_match(const struct json_value *doc, double ended)
{
    double vu = 0, d;
    if (!fac_num(json_get(doc, "ended_unix"), &vu))
        return false;
    d = vu - ended;
    return d <= FAC_VERDICT_SKEW_S && d >= -FAC_VERDICT_SKEW_S;
}

/* Note each non-empty string of failed_groups; true when there was one. */
static bool fac_verdict_names(const struct json_value *doc,
                              struct fac_verdict *v)
{
    const struct json_value *arr = json_get(doc, "failed_groups");
    bool any = false;
    if (!arr || arr->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *s = json_at(arr, i);
        const char *name = s && s->type == JSON_STR ? json_get_str(s) : NULL;
        if (name && name[0]) {
            fac_verdict_note(v, name);
            any = true;
        }
    }
    return any;
}

/* A failed run is named when its cwd's verdict ended with it and names at
 * least one failed group; any other failed run is unnamed. */
static void fac_verdict_job(const struct fac_job *jb, struct fac_verdict *v)
{
    struct json_value doc;
    const char *cwd;
    bool named = false;
    if (jb->rc == 0)
        return;
    cwd = jb->key ? jb->key + jb->cwd_off : "";
    if (cwd[0] && fac_verdict_read(cwd, &doc)) {
        named = fac_verdict_match(&doc, jb->ended) && fac_verdict_names(&doc, v);
        json_free(&doc);
    }
    if (named)
        fac_inc(&v->named);
    else
        fac_inc(&v->unnamed);
}

static int fac_cmp_name(const void *a, const void *b)
{
    const struct fac_name *x = a, *y = b;
    if (x->n != y->n)
        return x->n > y->n ? -1 : 1;
    return strcmp(x->key, y->key);
}

static void fac_failed_section(const struct fac_jobs *j, struct json_value *out)
{
    struct fac_verdict *v = zcl_calloc(1, sizeof(*v), "dev_factory_verdicts");
    struct json_value names;
    size_t shown;
    if (!v)
        return;
    for (size_t i = 0; i < j->n; i++)
        fac_verdict_job(&j->v[i], v);
    (void)json_push_kv_int(out, "failed_runs_named", v->named);
    (void)json_push_kv_int(out, "failed_runs_unnamed", v->unnamed);
    qsort(v->names, v->nn, sizeof(*v->names), fac_cmp_name);
    json_init(&names);
    json_set_array(&names);
    shown = v->nn < FAC_TOP ? v->nn : FAC_TOP;
    for (size_t i = 0; i < shown; i++) {
        struct json_value row;
        fac_new_obj(&row);
        (void)json_push_kv_str(&row, "group", v->names[i].key);
        (void)json_push_kv_int(&row, "n", v->names[i].n);
        (void)json_push_back(&names, &row);
        json_free(&row);
    }
    fac_attach(out, "failed_groups", &names);
    (void)json_push_kv_int(out, "failed_groups_overflow", v->overflow);
    free(v);
}

static void fac_jobs_report(struct fac_jobs *j, double now, double window_s,
                            struct json_value *out)
{
    struct json_value classes;
    double lander = 0, lanes = 0;
    (void)json_push_kv_int(out, "total", (int64_t)j->n);
    fac_new_obj(&classes);
    (void)fac_classes(j, &classes);
    fac_attach(out, "classes", &classes);
    (void)json_push_kv_int(out, "duplicates", fac_duplicates(j));
    if (fac_busy(j, now, &lander, &lanes)) {
        (void)json_push_kv_real(out, "lander_busy_pct",
                                lander * 100.0 / window_s);
        (void)json_push_kv_real(out, "lanes_busy_pct",
                                lanes * 100.0 / (FAC_LANES * window_s));
    }
    fac_lane_lint(j, out);
    fac_first_section(j, out);
    fac_cold_section(j, out);
    fac_failed_section(j, out);
}

static void fac_jobs_section(double now, double window_s,
                             struct json_value *out)
{
    struct fac_jobs j = {0};
    struct fac_src src = {0};
    char path[FAC_PATH];
    j.window_start = now - window_s;
    j.cwds = zcl_calloc(FAC_CWD_SLOTS, sizeof(*j.cwds), "dev_factory_cwds");
    if (!j.cwds ||
        !fac_path(getenv("ZCL_DEV_FACTORY_JOBS"),
                  ".local/state/development/devbuild.jobs.jsonl", path,
                  sizeof(path)))
        src.absent = true;
    else
        (void)fac_each_line(path, fac_job_line, &j, &src);
    fac_push_src(out, &src);
    if (!src.absent && !src.refused_rows) {
        fac_mark_first(&j);
        fac_jobs_report(&j, now, window_s, out);
    }
    fac_jobs_free(&j);
}

/* ── land outcomes ───────────────────────────────────────────────────────── */

struct fac_detail {
    char text[FAC_DETAIL_BYTES + 1];
    int64_t n;
};

struct fac_outcomes {
    double window_start;
    int64_t counts[5]; /* landed failed conflict cancelled other */
    struct fac_detail details[FAC_MAX_DETAILS];
    size_t ndetails;
    int64_t detail_overflow;
};

static const char *const fac_states[4] = {"landed", "failed", "conflict",
                                          "cancelled"};

static int fac_state_index(const char *state)
{
    for (int i = 0; i < 4; i++)
        if (strcmp(state, fac_states[i]) == 0)
            return i;
    return 4;
}

/* First FAC_DETAIL_BYTES bytes of `s`, backed off to a UTF-8 boundary. */
static void fac_cut_detail(const char *s, char *out)
{
    size_t len = strlen(s);
    if (len > FAC_DETAIL_BYTES) {
        len = FAC_DETAIL_BYTES;
        while (len > 0 && ((unsigned char)s[len] & 0xC0) == 0x80)
            len--;
    }
    memcpy(out, s, len);
    out[len] = '\0';
}

static void fac_note_detail(struct fac_outcomes *o, const char *detail)
{
    char cut[FAC_DETAIL_BYTES + 1];
    fac_cut_detail(detail, cut);
    for (size_t i = 0; i < o->ndetails; i++) {
        if (strcmp(o->details[i].text, cut) == 0) {
            o->details[i].n++;
            return;
        }
    }
    if (o->ndetails >= FAC_MAX_DETAILS) {
        o->detail_overflow++;
        return;
    }
    memcpy(o->details[o->ndetails].text, cut, sizeof(cut));
    o->details[o->ndetails].n = 1;
    o->ndetails++;
}

static bool fac_outcome_line(const char *line, size_t len, void *ctx,
                             struct fac_src *src)
{
    struct fac_outcomes *o = ctx;
    struct json_value row;
    int64_t ts;
    int idx;
    json_init(&row);
    if (!json_read(&row, line, len) || row.type != JSON_OBJ ||
        !fac_parse_iso(fac_text(&row, "ts"), &ts)) {
        src->skipped++;
        json_free(&row);
        return true;
    }
    if ((double)ts >= o->window_start) {
        idx = fac_state_index(fac_text(&row, "state"));
        o->counts[idx]++;
        if (idx != 0)
            fac_note_detail(o, fac_text(&row, "detail"));
    }
    json_free(&row);
    return true;
}

static int fac_cmp_detail(const void *a, const void *b)
{
    const struct fac_detail *x = a, *y = b;
    if (x->n != y->n)
        return x->n > y->n ? -1 : 1;
    return strcmp(x->text, y->text);
}

static void fac_outcomes_report(struct fac_outcomes *o, struct json_value *out)
{
    struct json_value counts, top;
    size_t shown;
    fac_new_obj(&counts);
    for (int i = 0; i < 4; i++)
        (void)json_push_kv_int(&counts, fac_states[i], o->counts[i]);
    (void)json_push_kv_int(&counts, "other", o->counts[4]);
    fac_attach(out, "counts", &counts);
    qsort(o->details, o->ndetails, sizeof(*o->details), fac_cmp_detail);
    json_init(&top);
    json_set_array(&top);
    shown = o->ndetails < FAC_TOP ? o->ndetails : FAC_TOP;
    for (size_t i = 0; i < shown; i++) {
        struct json_value row;
        fac_new_obj(&row);
        (void)json_push_kv_str(&row, "detail", o->details[i].text);
        (void)json_push_kv_int(&row, "n", o->details[i].n);
        (void)json_push_back(&top, &row);
        json_free(&row);
    }
    fac_attach(out, "top_non_landed", &top);
    (void)json_push_kv_int(out, "detail_overflow", o->detail_overflow);
}

static void fac_outcomes_section(double now, double window_s,
                                 struct json_value *out)
{
    struct fac_outcomes *o = zcl_calloc(1, sizeof(*o), "dev_factory_outcomes");
    struct fac_src src = {0};
    char dir[FAC_PATH], path[FAC_PATH + 32];
    if (!o) {
        src.absent = true;
        fac_push_src(out, &src);
        return;
    }
    o->window_start = now - window_s;
    if (!fac_path(getenv("ZCL_DEV_FACTORY_LAND_DIR"), ".local/state/z23/dev/land", dir,
                  sizeof(dir)) ||
        snprintf(path, sizeof(path), "%s/outcomes.jsonl", dir) >=
            (int)sizeof(path))
        src.absent = true;
    else
        (void)fac_each_line(path, fac_outcome_line, o, &src);
    fac_push_src(out, &src);
    if (!src.absent)
        fac_outcomes_report(o, out);
    free(o);
}

/* ── proof attempts ──────────────────────────────────────────────────────── */

struct fac_att {
    char pair[FAC_PAIR];
    char key[64];
    bool real;
    int64_t test_ms, cpu_ms, lock_ms;
};

struct fac_group {
    char key[64];
    int64_t n, test_ms, cpu_ms, lock_max, lock_sum;
};

struct fac_phase_ctx {
    bool saw_test, saw_lint;
    int64_t test_ms, cpu_ms, lock_ms;
};

static int64_t fac_token_int(const char *tok)
{
    return (int64_t)strtoll(tok, NULL, 10);
}

/* One key=value token of a phases line. */
static void fac_phase_token(const char *tok, bool is_test,
                            struct fac_phase_ctx *p)
{
    if (is_test && strncmp(tok, "elapsed_ms=", 11) == 0)
        p->test_ms = fac_token_int(tok + 11);
    else if (strncmp(tok, "lint_wall_ms=", 13) == 0)
        p->saw_lint = true;
    else if (strncmp(tok, "proof_cpu_children_ms=", 22) == 0)
        p->cpu_ms = fac_token_int(tok + 22);
    else if (strncmp(tok, "queue_lock_wait_ms=", 19) == 0)
        p->lock_ms = fac_token_int(tok + 19);
}

static bool fac_phase_line(const char *line, size_t len, void *ctx,
                           struct fac_src *src)
{
    struct fac_phase_ctx *p = ctx;
    char *copy = zcl_malloc(len + 1, "dev_factory_phase");
    char *save = NULL;
    bool is_test;
    (void)src;
    if (!copy)
        return false;
    memcpy(copy, line, len + 1);
    is_test = strstr(line, "step=test") != NULL;
    p->saw_test = p->saw_test || is_test;
    for (char *t = strtok_r(copy, " \t\r", &save); t;
         t = strtok_r(NULL, " \t\r", &save))
        fac_phase_token(t, is_test, p);
    free(copy);
    return true;
}

static bool fac_selection_line(const char *line, size_t len, void *ctx,
                               struct fac_src *src)
{
    char *key = ctx;
    const char *sel = strstr(line, "test_selection=");
    const char *reason;
    char word[24] = "", why[40] = "unknown";
    (void)len;
    (void)src;
    if (!sel || key[0])
        return true;
    (void)sscanf(sel + 15, "%23s", word);
    reason = strstr(line, "reason=");
    if (reason)
        (void)sscanf(reason + 7, "%39s", why);
    if (strcmp(word, "exact") == 0)
        (void)snprintf(key, 64, "exact");
    else
        (void)snprintf(key, 64, "universal:%s", why);
    return true;
}

/* The selection key of an attempt dir, "unknown" when it has no log. */
static void fac_selection(const char *adir, char *key)
{
    char logs[FAC_PATH + 8], path[FAC_PATH + 320];
    struct fac_src ignore = {0};
    DIR *d;
    struct dirent *e;
    key[0] = '\0';
    if (snprintf(logs, sizeof(logs), "%s/logs", adir) >= (int)sizeof(logs))
        return;
    d = opendir(logs);
    while (d && (e = readdir(d)) && !key[0]) {
        size_t n = strlen(e->d_name);
        if (n > 19 && strcmp(e->d_name + n - 19, ".test-selection.log") == 0 &&
            snprintf(path, sizeof(path), "%s/%s", logs, e->d_name) <
                (int)sizeof(path))
            (void)fac_each_line(path, fac_selection_line, key, &ignore);
    }
    if (d)
        (void)closedir(d);
    if (!key[0])
        (void)snprintf(key, 64, "unknown");
}

static void fac_pair_of(const char *name, char *pair)
{
    size_t n = strcspn(name, ".");
    if (n >= FAC_PAIR)
        n = FAC_PAIR - 1;
    memcpy(pair, name, n);
    pair[n] = '\0';
}

static void fac_read_attempt(const char *dir, const char *name,
                             struct fac_att *a)
{
    char adir[FAC_PATH + 300], path[FAC_PATH + 340];
    struct fac_phase_ctx p = {0};
    struct fac_src ignore = {0};
    memset(a, 0, sizeof(*a));
    fac_pair_of(name, a->pair);
    (void)snprintf(adir, sizeof(adir), "%s/%s", dir, name);
    (void)snprintf(path, sizeof(path), "%s/phases.txt", adir);
    (void)fac_each_line(path, fac_phase_line, &p, &ignore);
    a->real = p.saw_test || p.saw_lint;
    a->test_ms = p.test_ms;
    a->cpu_ms = p.cpu_ms;
    a->lock_ms = p.lock_ms;
    if (a->real)
        fac_selection(adir, a->key);
}

struct fac_atts {
    struct fac_att *v;
    size_t n;
    bool refused;
};

/* Is `name` an attempt dir modified inside the window? */
static bool fac_attempt_in_window(const char *dir, const char *name, double ws)
{
    char path[FAC_PATH + 300];
    struct stat st;
    if (name[0] == '.' ||
        snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
        return false;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           (double)st.st_mtime >= ws;
}

static bool fac_scan_attempts(const char *dir, double ws, struct fac_atts *as)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d)
        return false;
    while ((e = readdir(d))) {
        if (!fac_attempt_in_window(dir, e->d_name, ws))
            continue;
        if (as->n >= FAC_MAX_ATTEMPTS) {
            as->refused = true;
            break;
        }
        fac_read_attempt(dir, e->d_name, &as->v[as->n++]);
    }
    (void)closedir(d);
    return true;
}

static int fac_cmp_pair(const void *a, const void *b)
{
    return strcmp(((const struct fac_att *)a)->pair,
                  ((const struct fac_att *)b)->pair);
}

/* (commit, base) pairs with more than one real proof. */
static int64_t fac_superseded(struct fac_atts *as)
{
    int64_t sup = 0;
    size_t i = 0;
    qsort(as->v, as->n, sizeof(*as->v), fac_cmp_pair);
    while (i < as->n) {
        size_t j = i;
        int64_t real = 0;
        while (j < as->n && strcmp(as->v[j].pair, as->v[i].pair) == 0)
            real += as->v[j++].real;
        sup += real > 1;
        i = j;
    }
    return sup;
}

static struct fac_group *fac_group_for(struct fac_group *g, size_t *ng,
                                       const char *key)
{
    for (size_t i = 0; i < *ng; i++)
        if (strcmp(g[i].key, key) == 0)
            return &g[i];
    if (*ng >= FAC_MAX_GROUPS)
        return &g[FAC_MAX_GROUPS - 1];
    memset(&g[*ng], 0, sizeof(g[*ng]));
    (void)snprintf(g[*ng].key, sizeof(g[*ng].key), "%s", key);
    return &g[(*ng)++];
}

static void fac_group_emit(const struct fac_group *g, struct json_value *arr)
{
    struct json_value row;
    fac_new_obj(&row);
    (void)json_push_kv_str(&row, "key", g->key);
    (void)json_push_kv_int(&row, "n", g->n);
    (void)json_push_kv_real(&row, "avg_test_s",
                            (double)g->test_ms / 1000.0 / (double)g->n);
    (void)json_push_kv_real(&row, "avg_cpu_h",
                            (double)g->cpu_ms / 3600000.0 / (double)g->n);
    (void)json_push_kv_int(&row, "lock_wait_max_ms", g->lock_max);
    (void)json_push_kv_int(&row, "lock_wait_sum_ms", g->lock_sum);
    (void)json_push_back(arr, &row);
    json_free(&row);
}

static void fac_attempts_report(struct fac_atts *as, struct json_value *out)
{
    struct fac_group groups[FAC_MAX_GROUPS];
    struct json_value by, lock;
    size_t ng = 0;
    int64_t real = 0, lmax = 0, lsum = 0;
    for (size_t i = 0; i < as->n; i++) {
        const struct fac_att *a = &as->v[i];
        lsum += a->lock_ms;
        lmax = a->lock_ms > lmax ? a->lock_ms : lmax;
        if (a->real) {
            struct fac_group *g = fac_group_for(groups, &ng, a->key);
            real++;
            g->n++;
            g->test_ms += a->test_ms;
            g->cpu_ms += a->cpu_ms;
            g->lock_sum += a->lock_ms;
            g->lock_max = a->lock_ms > g->lock_max ? a->lock_ms : g->lock_max;
        }
    }
    (void)json_push_kv_int(out, "attempts", (int64_t)as->n);
    (void)json_push_kv_int(out, "short_refusals", (int64_t)as->n - real);
    (void)json_push_kv_int(out, "real", real);
    (void)json_push_kv_int(out, "superseded", fac_superseded(as));
    fac_new_obj(&lock);
    (void)json_push_kv_int(&lock, "max", lmax);
    (void)json_push_kv_int(&lock, "sum", lsum);
    fac_attach(out, "lock_wait_ms", &lock);
    json_init(&by);
    json_set_array(&by);
    for (size_t i = 0; i < ng; i++)
        fac_group_emit(&groups[i], &by);
    fac_attach(out, "by_selection", &by);
}

static void fac_attempts_section(double now, double window_s,
                                 struct json_value *out)
{
    struct fac_atts as = {0};
    struct fac_src src = {0};
    char dir[FAC_PATH];
    as.v = zcl_malloc(FAC_MAX_ATTEMPTS * sizeof(*as.v), "dev_factory_attempts");
    if (!as.v || !fac_path(getenv("ZCL_DEV_FACTORY_ATTEMPTS"),
                           ".local/state/z23/dev/land/wt/.cache/"
                           "zcl-dev-proof/attempts",
                           dir, sizeof(dir)) ||
        !fac_scan_attempts(dir, now - window_s, &as))
        src.absent = true;
    src.refused_rows = as.refused;
    fac_push_src(out, &src);
    if (!src.absent && !src.refused_rows)
        fac_attempts_report(&as, out);
    free(as.v);
}

/* ── host ────────────────────────────────────────────────────────────────── */

/* "some avg10=A avg60=B avg300=C ..." into an object; false if unreadable. */
static bool fac_pressure_one(const char *proc, const char *name,
                             struct json_value *out)
{
    char path[FAC_PATH + 64], line[256];
    double a10, a60, a300;
    FILE *fp;
    bool ok;
    if (snprintf(path, sizeof(path), "%s/pressure/%s", proc, name) >=
        (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
    if (!fp)
        return false;
    ok = fgets(line, sizeof(line), fp) &&
         sscanf(line, "some avg10=%lf avg60=%lf avg300=%lf", &a10, &a60,
                &a300) == 3;
    (void)fclose(fp);
    if (!ok)
        return false;
    fac_new_obj(out);
    (void)json_push_kv_real(out, "avg10", a10);
    (void)json_push_kv_real(out, "avg60", a60);
    (void)json_push_kv_real(out, "avg300", a300);
    return true;
}

static void fac_push_null(struct json_value *obj, const char *key)
{
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    fac_attach(obj, key, &nul);
}

/* Bytes in use on /dev/shm, or false when statvfs fails. */
static bool fac_shm_used(int64_t *used)
{
#if defined(_WIN32)
    (void)used;
    return false;
#else
    struct statvfs sv;
    if (statvfs("/dev/shm", &sv) != 0)
        return false;
    *used = (int64_t)(sv.f_blocks - sv.f_bfree) * (int64_t)sv.f_frsize;
    return true;
#endif
}

static void fac_host_section(struct json_value *out)
{
    static const char *const names[3] = {"memory", "io", "cpu"};
    const char *over = getenv("ZCL_DEV_FACTORY_PROC");
    const char *proc = over && over[0] ? over : "/proc";
    struct json_value pressure;
    int64_t used = 0;
    fac_new_obj(&pressure);
    for (int i = 0; i < 3; i++) {
        struct json_value one;
        if (fac_pressure_one(proc, names[i], &one))
            fac_attach(&pressure, names[i], &one);
        else
            fac_push_null(&pressure, names[i]);
    }
    fac_attach(out, "pressure", &pressure);
    if (fac_shm_used(&used))
        (void)json_push_kv_int(out, "shm_used_bytes", used);
    else
        fac_push_null(out, "shm_used_bytes");
}

/* ── entry ───────────────────────────────────────────────────────────────── */

static bool fac_hours(const struct json_value *input, int64_t *hours)
{
    const struct json_value *v = input ? json_get(input, "hours") : NULL;
    *hours = FAC_DEFAULT_HOURS;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_INT)
        return false;
    *hours = json_get_int(v);
    return *hours >= 1 && *hours <= FAC_MAX_HOURS;
}

void zcl_native_handle_dev_factory(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct json_value jobs, land, att, host;
    int64_t hours;
    double now, window_s;
    if (!reply)
        return;
    if (!fac_hours(request ? request->input : NULL, &hours)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                               "normalize", false, false,
                               "hours is an integer in 1..720",
                               "input.hours");
        return;
    }
    now = (double)platform_time_wall_unix();
    window_s = (double)hours * 3600.0;
    fac_new_obj(&jobs);
    fac_new_obj(&land);
    fac_new_obj(&att);
    fac_new_obj(&host);
    fac_jobs_section(now, window_s, &jobs);
    fac_outcomes_section(now, window_s, &land);
    fac_attempts_section(now, window_s, &att);
    fac_host_section(&host);
    (void)json_push_kv_int(&reply->data, "hours", hours);
    (void)json_push_kv_int(&reply->data, "window_s", (int64_t)window_s);
    (void)json_push_kv_int(&reply->data, "now", (int64_t)now);
    fac_attach(&reply->data, "jobs", &jobs);
    fac_attach(&reply->data, "land_outcomes", &land);
    fac_attach(&reply->data, "proof_attempts", &att);
    fac_attach(&reply->data, "host", &host);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
