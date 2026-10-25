/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The D1, D2 and D4 readers (see the header). The ledger is read
 *          with a bounded line reader; a malformed line is skipped and
 *          counted, never guessed at. A zero counter in rows.tsv means
 *          unknown, so it counts as missing, not as a measured zero. */

#include "native_fleet_goals_delivery.h"

#include "base/format_attribute.h"
#include "base/safe_alloc.h"
#include "json/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GD_LINE_CAP 8192u
#define GD_FIELDS 22u
#define GD_DIGITS 18u
#define GD_BOXES 16u
#define GD_FIRST_IDS 2u
#define GD_LANES_MAX 4096u
#define GD_NAME 104u

/* ── ledger scan ──────────────────────────────────────────────────────── */

/* One valid `result` row. Pointers live only for the callback. */
struct gd_row {
    int64_t ts;
    int64_t turns;
    int64_t tin;
    int64_t tout;
    const char *box;
    const char *task;
};
typedef void (*gd_row_fn)(const struct gd_row *row, void *user);

/* 1 = a line, 2 = an overflowed line (drained), 0 = end, -1 = read error. */
static int gd_read_line(FILE *f, char *buf, size_t cap)
{
    size_t n = 0;
    bool over = false;
    int ch = 0;
    while ((ch = fgetc(f)) != EOF && ch != '\n') {
        if (ch == 0 || n + 1u >= cap)
            over = true;
        else
            buf[n++] = (char)ch;
    }
    buf[n] = '\0';
    if (ferror(f))
        return -1;
    if (ch == EOF && n == 0 && !over)
        return 0;
    if (n > 0 && buf[n - 1] == '\r')
        buf[--n] = '\0';
    return over ? 2 : 1;
}

static bool gd_digits(const char *s, int64_t *out)
{
    int64_t v = 0;
    size_t len = strlen(s);
    if (len == 0 || len > GD_DIGITS)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

/* Splits on tabs; true only for exactly GD_FIELDS fields. */
static bool gd_split(char *line, char *fields[GD_FIELDS])
{
    size_t n = 0;
    char *p = line;
    for (;;) {
        if (n == GD_FIELDS)
            return false;
        fields[n++] = p;
        p = strchr(p, '\t');
        if (!p)
            return n == GD_FIELDS;
        *p++ = '\0';
    }
}

/* Parses one data line. 0 = malformed, 1 = valid non-result row, 2 = result
 * row filled into `row`. */
static int gd_parse(char *line, struct gd_row *row)
{
    char *f[GD_FIELDS];
    int64_t cache;
    bool result;
    if (!gd_split(line, f))
        return 0;
    result = strcmp(f[1], "result") == 0;
    if (!result && strcmp(f[1], "predict") != 0)
        return 0;
    if (!gd_digits(f[10], &row->tin) || !gd_digits(f[11], &row->tout) ||
        !gd_digits(f[12], &cache) || !gd_digits(f[15], &row->turns))
        return 0;
    if (!result)
        return 1;
    if (!zcl_objectives_parse_iso8601(f[0], &row->ts))
        return 0;
    row->box = f[2];
    row->task = f[3];
    return 2;
}

/* Feeds every valid result row to `fn`. False, with `reason`, when the file
 * cannot be read. The header line is not a row. */
static bool gd_scan(const char *path, gd_row_fn fn, void *user,
                    int64_t *skipped, char *reason, size_t cap)
{
    char line[GD_LINE_CAP];
    struct gd_row row;
    size_t line_no = 0;
    int status;
    FILE *f = path ? fopen(path, "rb") : NULL;
    if (!f) {
        (void)snprintf(reason, cap, "missing experiment ledger");
        return false;
    }
    while ((status = gd_read_line(f, line, sizeof(line))) > 0) {
        int kind;
        line_no++;
        if (line_no == 1)
            continue;
        kind = status == 2 ? 0 : gd_parse(line, &row);
        if (kind == 0)
            (*skipped)++;
        else if (kind == 2)
            fn(&row, user);
    }
    if (fclose(f) != 0 || status < 0) {
        (void)snprintf(reason, cap, "unreadable experiment ledger");
        return false;
    }
    return true;
}

/* Appends to a bounded buffer; silently stops at the cap. */
static void gd_cat(char *buf, size_t cap, const char *fmt, ...)
    ZCL_PRINTF_LIKE(3, 4);
static void gd_cat(char *buf, size_t cap, const char *fmt, ...)
{
    size_t len = strlen(buf);
    va_list ap;
    if (len + 1u >= cap)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(buf + len, cap - len, fmt, ap);
    va_end(ap);
}

static int64_t gd_start(const struct zcl_goals_delivery_in *in)
{
    int64_t start = in->now - ZCL_GOALS_DELIVERY_WINDOW_S;
    return start > ZCL_GOALS_DELIVERY_FIX_EPOCH ? start
                                                : ZCL_GOALS_DELIVERY_FIX_EPOCH;
}

/* ── D1 ───────────────────────────────────────────────────────────────── */

struct gd_box {
    char name[32];
    int64_t rows;
    int64_t bad;
    char first[GD_FIRST_IDS][32];
    size_t nfirst;
};

struct gd_d1 {
    int64_t start;
    int64_t end;
    int64_t total;
    struct gd_box box[GD_BOXES];
    size_t n;
};

static struct gd_box *gd_d1_box(struct gd_d1 *s, const char *name)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->box[i].name, name) == 0)
            return &s->box[i];
    if (s->n == GD_BOXES)
        return &s->box[GD_BOXES - 1u];
    if (s->n == GD_BOXES - 1u)
        name = "(other)";
    memset(&s->box[s->n], 0, sizeof(s->box[s->n]));
    (void)snprintf(s->box[s->n].name, sizeof(s->box[s->n].name), "%s", name);
    return &s->box[s->n++];
}

static void gd_d1_row(const struct gd_row *r, void *user)
{
    struct gd_d1 *s = user;
    struct gd_box *b;
    if (r->ts < s->start || r->ts > s->end)
        return;
    b = gd_d1_box(s, r->box);
    s->total++;
    b->rows++;
    if (r->turns > 0 && r->tin > 0 && r->tout > 0)
        return;
    b->bad++;
    if (b->nfirst < GD_FIRST_IDS)
        (void)snprintf(b->first[b->nfirst++], sizeof(b->first[0]), "%s",
                       r->task);
}

static void gd_d1_detail(const struct gd_d1 *s, char *out, size_t cap)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct gd_box *b = &s->box[i];
        if (b->bad == 0)
            continue;
        gd_cat(out, cap, "%s%s %lld of %lld incomplete (first", out[0] ? "; " : "",
               b->name, (long long)b->bad, (long long)b->rows);
        for (size_t k = 0; k < b->nfirst; k++)
            gd_cat(out, cap, " %s", b->first[k]);
        gd_cat(out, cap, ")");
    }
}

struct zcl_goal_result zcl_goals_delivery_d1(
    const struct zcl_goals_delivery_in *in)
{
    static const char next[] =
        "make every executor write turns, tokens_in and tokens_out on each "
        "result row (the rows.tsv column list)";
    struct gd_d1 s;
    char why[96] = "";
    char detail[200] = "";
    int64_t skipped = 0;
    int64_t bad = 0;
    memset(&s, 0, sizeof(s));
    s.start = gd_start(in);
    s.end = in->now;
    if (!gd_scan(in->rows_tsv, gd_d1_row, &s, &skipped, why, sizeof(why)))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "%s", why);
    if (s.total == 0)
        return zcl_goal_make(
            ZCL_GOAL_UNMEASURED, next,
            "no result rows in the trailing 7 d at or after "
            "2026-10-23T18:05Z; %lld malformed skipped",
            (long long)skipped);
    for (size_t i = 0; i < s.n; i++)
        bad += s.box[i].bad;
    gd_d1_detail(&s, detail, sizeof(detail));
    if (bad > 0)
        return zcl_goal_make(
            ZCL_GOAL_FAIL, next,
            "%lld of %lld result rows lack requests or tokens: %s; %lld "
            "malformed skipped",
            (long long)bad, (long long)s.total, detail, (long long)skipped);
    return zcl_goal_make(
        ZCL_GOAL_PARTIAL, next,
        "all %lld result rows complete on %zu box labels (roster %zu; box "
        "labels are not host names, so per-host coverage is unproven); %lld "
        "malformed skipped",
        (long long)s.total, s.n, in->admitted_hosts, (long long)skipped);
}

/* ── shared index and lane helpers ────────────────────────────────────── */

/* The caller's prebuilt index, else one built here into `own`. NULL on an
 * allocation failure. */
static const struct zcl_agent_index *gd_index(
    const struct zcl_goals_delivery_in *in, struct zcl_agent_index *own)
{
    if (in->index)
        return in->index;
    return zcl_objectives_agent_index_build(own) ? own : NULL;
}

static int gd_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* ── D2 ───────────────────────────────────────────────────────────────── */

struct gd_lane {
    char name[GD_NAME];
    int64_t turns;
    int64_t agents;
};

struct gd_d2 {
    int64_t start;
    int64_t end;
    struct gd_lane *lanes; /* sorted by name once loading ends */
    size_t n;
    size_t cap;
    bool oom;
    bool truncated;
    const struct zcl_agent_index *ix;
};

static int gd_cmp_lane(const void *a, const void *b)
{
    return strcmp(((const struct gd_lane *)a)->name,
                  ((const struct gd_lane *)b)->name);
}

static bool gd_note_lane(const char *note, char *out, size_t cap)
{
    const char *colon = note ? strchr(note, ':') : NULL;
    size_t n = colon ? (size_t)(colon - note) : 0;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, note, n);
    out[n] = '\0';
    return true;
}

static bool gd_d2_has(const struct gd_d2 *s, const char *name)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->lanes[i].name, name) == 0)
            return true;
    return false;
}

static void gd_d2_add(struct gd_d2 *s, const char *name)
{
    if (s->n == GD_LANES_MAX) {
        s->truncated = true;
        return;
    }
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2u : 64u;
        struct gd_lane *grown =
            zcl_realloc(s->lanes, cap * sizeof(*grown), "gd_landed_lanes");
        if (!grown) {
            s->oom = true;
            return;
        }
        s->lanes = grown;
        s->cap = cap;
    }
    memset(&s->lanes[s->n], 0, sizeof(s->lanes[s->n]));
    (void)snprintf(s->lanes[s->n++].name, GD_NAME, "%s", name);
}

static void gd_d2_landed(const struct json_value *row, void *user)
{
    struct gd_d2 *s = user;
    const char *state = json_get_str(json_get(row, "state"));
    char lane[GD_NAME];
    int64_t when;
    if (!state || strcmp(state, "landed") != 0 || s->oom)
        return;
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &when) ||
        when < s->end - ZCL_GOALS_DELIVERY_WINDOW_S || when > s->end)
        return;
    if (gd_note_lane(json_get_str(json_get(row, "note")), lane, sizeof(lane)) &&
        !gd_d2_has(s, lane))
        gd_d2_add(s, lane);
}

static void gd_d2_row(const struct gd_row *r, void *user)
{
    struct gd_d2 *s = user;
    struct gd_lane key, *hit;
    const char *lane;
    if (r->ts < s->start)
        return;
    lane = zcl_objectives_agent_lane(s->ix, r->task);
    if (!lane || s->n == 0)
        return;
    (void)snprintf(key.name, sizeof(key.name), "%s", lane);
    hit = bsearch(&key, s->lanes, s->n, sizeof(*s->lanes), gd_cmp_lane);
    if (hit) {
        hit->turns += r->turns;
        hit->agents++;
    }
}

/* Median of the joined lanes' turn sums (mean of the two middles, rounded
 * down); *joined gets how many lanes joined. */
static bool gd_d2_median(const struct gd_d2 *s, size_t *joined, int64_t *med)
{
    int64_t *v = zcl_malloc((s->n ? s->n : 1u) * sizeof(*v), "gd_turns");
    size_t k = 0;
    if (!v)
        return false;
    for (size_t i = 0; i < s->n; i++)
        if (s->lanes[i].agents > 0)
            v[k++] = s->lanes[i].turns;
    qsort(v, k, sizeof(*v), gd_cmp_i64);
    *joined = k;
    if (k == 0)
        *med = 0;
    else if (k % 2u)
        *med = v[k / 2u];
    else
        *med = v[k / 2u - 1u] + (v[k / 2u] - v[k / 2u - 1u]) / 2;
    free(v);
    return true;
}

static struct zcl_goal_result gd_d2_grade(struct gd_d2 *s, int64_t skipped)
{
    static const char next[] =
        "land lanes whose agents carry write:/cx: labels and record turns in "
        "rows.tsv";
    size_t joined = 0;
    int64_t med = 0;
    if (!gd_d2_median(s, &joined, &med))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "out of memory");
    if (joined == 0)
        return zcl_goal_make(
            ZCL_GOAL_UNMEASURED, next,
            "%zu landed lanes in 7 d, none joins an indexed agent with a "
            "result row at or after 2026-10-23T18:05Z; %lld malformed skipped",
            s->n, (long long)skipped);
    return zcl_goal_make(
        med > ZCL_GOALS_DELIVERY_D2_MAX_REQUESTS ? ZCL_GOAL_FAIL
                                                 : ZCL_GOAL_PARTIAL,
        next,
        "median %lld requests per accepted change over %zu of %zu landed "
        "lanes (bar %d; indexed agents on this host only, sums can only be "
        "undercounted)%s; %lld malformed skipped",
        (long long)med, joined, s->n, ZCL_GOALS_DELIVERY_D2_MAX_REQUESTS,
        s->truncated ? ", lane cap hit" : "", (long long)skipped);
}

struct zcl_goal_result zcl_goals_delivery_d2(
    const struct zcl_goals_delivery_in *in)
{
    static const char next[] = "run `z23 fleet land` so outcomes.jsonl records "
                               "landed lanes";
    struct zcl_agent_index own = {0};
    struct gd_d2 s = {0};
    struct zcl_goal_result res;
    char why[96] = "";
    int64_t skipped = 0;
    s.start = gd_start(in);
    s.end = in->now;
    s.ix = gd_index(in, &own);
    if (!s.ix)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "out of memory");
    if (!in->outcomes ||
        !zcl_objectives_ledger_walk(in->outcomes, gd_d2_landed, &s, why,
                                    sizeof(why)))
        res = zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "outcomes: %s",
                            in->outcomes ? why : "no outcomes path");
    else if (s.oom)
        res = zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "out of memory");
    else if (s.n == 0)
        res = zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                            "no lane landed in the trailing 7 d");
    else {
        qsort(s.lanes, s.n, sizeof(*s.lanes), gd_cmp_lane);
        if (gd_scan(in->rows_tsv, gd_d2_row, &s, &skipped, why, sizeof(why)))
            res = gd_d2_grade(&s, skipped);
        else
            res = zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "%s", why);
    }
    free(s.lanes);
    zcl_objectives_agent_index_free(&own);
    return res;
}

/* ── D4 ───────────────────────────────────────────────────────────────── */

#define GD_F_WRITE 1u
#define GD_F_REV 2u /* review, review1 or review2: any non-author review */
#define GD_F_FIX 4u

struct gd_dl {
    char name[GD_NAME];
    unsigned flags;
    int64_t ts; /* newest result row of any agent of the lane, 0 = none */
};

static unsigned gd_kind_flag(const char *kind)
{
    if (strcmp(kind, "write") == 0 || strcmp(kind, "cx") == 0)
        return GD_F_WRITE;
    if (strcmp(kind, "review") == 0 || strcmp(kind, "review1") == 0 ||
        strcmp(kind, "review2") == 0)
        return GD_F_REV;
    return strcmp(kind, "fix") == 0 ? GD_F_FIX : 0u;
}

static int gd_cmp_dl(const void *a, const void *b)
{
    return strcmp(((const struct gd_dl *)a)->name,
                  ((const struct gd_dl *)b)->name);
}

/* Newest first; the lane name breaks a tie so the cut is deterministic. */
static int gd_cmp_dl_newest(const void *a, const void *b)
{
    const struct gd_dl *x = *(const struct gd_dl *const *)a;
    const struct gd_dl *y = *(const struct gd_dl *const *)b;
    if (x->ts != y->ts)
        return x->ts < y->ts ? 1 : -1;
    return strcmp(x->name, y->name);
}

struct gd_d4 {
    struct gd_dl *dl; /* one per lane, sorted by name */
    size_t n;
    const struct zcl_agent_index *ix;
};

/* One entry per distinct lane of the index, kind flags merged. */
static bool gd_d4_build(struct gd_d4 *s)
{
    size_t m = s->ix->n;
    s->dl = zcl_malloc((m ? m : 1u) * sizeof(*s->dl), "gd_deliveries");
    if (!s->dl)
        return false;
    for (size_t i = 0; i < m; i++) {
        memset(&s->dl[i], 0, sizeof(s->dl[i]));
        (void)snprintf(s->dl[i].name, GD_NAME, "%s", s->ix->items[i].lane);
        s->dl[i].flags = gd_kind_flag(s->ix->items[i].kind);
    }
    qsort(s->dl, m, sizeof(*s->dl), gd_cmp_dl);
    for (size_t i = 0; i < m; i++) {
        if (s->n > 0 && strcmp(s->dl[s->n - 1u].name, s->dl[i].name) == 0)
            s->dl[s->n - 1u].flags |= s->dl[i].flags;
        else
            s->dl[s->n++] = s->dl[i];
    }
    return true;
}

static void gd_d4_row(const struct gd_row *r, void *user)
{
    struct gd_d4 *s = user;
    struct gd_dl key, *hit;
    const char *lane = zcl_objectives_agent_lane(s->ix, r->task);
    if (!lane || s->n == 0)
        return;
    (void)snprintf(key.name, sizeof(key.name), "%s", lane);
    hit = bsearch(&key, s->dl, s->n, sizeof(*s->dl), gd_cmp_dl);
    if (hit && r->ts > hit->ts)
        hit->ts = r->ts;
}

static struct zcl_goal_result gd_d4_grade(struct gd_d4 *s, int64_t skipped)
{
    static const char next[] =
        "record review verdicts per delivery so first-time acceptance is "
        "measured, not inferred from labels";
    const struct gd_dl **pick = zcl_malloc((s->n ? s->n : 1u) * sizeof(*pick),
                                           "gd_pick");
    size_t k = 0, first = 0;
    if (!pick)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "out of memory");
    for (size_t i = 0; i < s->n; i++)
        if ((s->dl[i].flags & GD_F_WRITE) && s->dl[i].ts > 0)
            pick[k++] = &s->dl[i];
    if (k < ZCL_GOALS_DELIVERY_D4_SAMPLE) {
        free(pick);
        return zcl_goal_make(
            ZCL_GOAL_UNMEASURED, next,
            "%zu deliveries with a write:/cx: agent and a result row, need "
            "%u; %lld malformed skipped",
            k, ZCL_GOALS_DELIVERY_D4_SAMPLE, (long long)skipped);
    }
    qsort(pick, k, sizeof(*pick), gd_cmp_dl_newest);
    for (size_t i = 0; i < ZCL_GOALS_DELIVERY_D4_SAMPLE; i++)
        if ((pick[i]->flags & (GD_F_REV | GD_F_FIX)) == GD_F_REV)
            first++;
    free(pick);
    return zcl_goal_make(
        first >= ZCL_GOALS_DELIVERY_D4_MIN_FIRST_TIME ? ZCL_GOAL_PARTIAL
                                                      : ZCL_GOAL_FAIL,
        next,
        "%zu of the newest %u deliveries have a review and no fix round "
        "(bar %u); a label proxy, verdicts are not recorded and a renamed "
        "rejected lane would hide; %lld malformed skipped",
        first, ZCL_GOALS_DELIVERY_D4_SAMPLE,
        ZCL_GOALS_DELIVERY_D4_MIN_FIRST_TIME, (long long)skipped);
}

struct zcl_goal_result zcl_goals_delivery_d4(
    const struct zcl_goals_delivery_in *in)
{
    static const char next[] = "run an agent job labelled write:<lane> with "
                               "a review: (or review1:) reviewer";
    struct zcl_agent_index own = {0};
    struct gd_d4 s = {0};
    struct zcl_goal_result res;
    char why[96] = "";
    int64_t skipped = 0;
    s.ix = gd_index(in, &own);
    if (!s.ix || !gd_d4_build(&s)) {
        zcl_objectives_agent_index_free(&own);
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "out of memory");
    }
    if (gd_scan(in->rows_tsv, gd_d4_row, &s, &skipped, why, sizeof(why)))
        res = gd_d4_grade(&s, skipped);
    else
        res = zcl_goal_make(ZCL_GOAL_UNMEASURED, next, "%s", why);
    free(s.dl);
    zcl_objectives_agent_index_free(&own);
    return res;
}
