/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The tokens_per_landed_commit producer. A landed lane is a landed
 *          row of the land outcomes file in the trailing 7 days. The row
 *          names its lane by the basename of its `worktree` (the absolute
 *          lane path) when that is present and fits; otherwise by the text
 *          before the first `:` of its note, as before. Its worker agents
 *          come from the agent meta index (native_fleet_objectives_lanes.c:
 *          agent id -> lane for the write/cx/review/review1/review2/fix/
 *          design/check job labels). Its cost is the
 *          sum, over those agents' `result` rows of the experiment ledger
 *          (rows.tsv, 22 tab-separated columns), of tokens_in (uncached
 *          input including cache creation) plus tokens_out. Cache reads
 *          (tokens_cache) are kept apart for the detail line. The value is
 *          the median of that cost over the landed lanes that join at least
 *          one agent.
 *
 * A malformed ledger line is skipped and counted, never guessed at. The
 * ledger is read with a bounded line reader, one line at a time.
 */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TPC_WINDOW_S ((int64_t)7 * 86400)
#define TPC_LINE_CAP 8192u
#define TPC_FIELDS 22u
#define TPC_TOKEN_DIGITS 18u
#define TPC_LANES_MAX 4096u

/* One landed lane and what its worker agents spent. */
struct tpc_lane {
    char name[104];
    int64_t tokens; /* uncached input + output */
    int64_t cache;  /* cache reads, detail only */
    int64_t agents; /* ledger result rows joined to this lane */
};

struct tpc_landed {
    int64_t start;
    int64_t end;
    struct tpc_lane *lanes;
    size_t n;
    size_t cap;
    bool oom;
    bool truncated;
};

/* One result row of the ledger: the agent that spent it and what it cost. */
struct tpc_result {
    const char *agent; /* task_id: the agent id */
    const char *model; /* the model column, raw */
    int64_t tokens;    /* uncached input + output */
    int64_t cache;     /* cache reads */
};

typedef void (*tpc_result_fn)(const struct tpc_result *r, void *user);

/* One joined agent row kept for the per-role report: its role and model
 * bucket (role index * TPC_MODELS + model index, set by tpc_fold_row) and
 * its cost. */
struct tpc_sample {
    uint8_t bucket;
    int64_t tokens;
    int64_t cache;
};

struct tpc_samples {
    struct tpc_sample *v;
    size_t n;
    size_t cap;
    bool oom;
};

/* The fold a result row feeds: the landed lanes, and the samples when the
 * per-role report asks for them (NULL for the KPI, which keeps none). */
struct tpc_fold {
    const struct zcl_agent_index *ix;
    struct tpc_landed *l;
    struct tpc_samples *s;
};

static int64_t tpc_now(const struct zcl_objectives_options *options)
{
    return options && options->now > 0 ? options->now
                                       : platform_time_wall_unix();
}

/* $XDG_STATE_HOME/zclassic23/experiments/rows.tsv, else the same path under
 * ~/.local/state. The state root of the rest of z23 is not this one. */
static bool tpc_default_ledger(char *out, size_t cap)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    int n;
    if (xdg && xdg[0])
        n = snprintf(out, cap, "%s/zclassic23/experiments/rows.tsv", xdg);
    else if (home && home[0])
        n = snprintf(out, cap,
                     "%s/.local/state/zclassic23/experiments/rows.tsv", home);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

static bool tpc_resolve_ledger(const struct zcl_objectives_options *options,
                               char *buf, size_t cap, const char **out)
{
    if (options && options->experiments) {
        *out = options->experiments;
        return true;
    }
    if (!tpc_default_ledger(buf, cap))
        return false;
    *out = buf;
    return true;
}

bool zcl_objectives_experiments_path(
    const struct zcl_objectives_options *options, char *buf, size_t cap,
    const char **out)
{
    return tpc_resolve_ledger(options, buf, cap, out);
}

/* Reads one physical line into `buf` (NUL-terminated, at most cap - 1 bytes
 * kept). 1 = a line, 2 = a line that overflowed the cap (drained to its end),
 * 0 = end of file, -1 = a read error. */
static int tpc_read_line(FILE *f, char *buf, size_t cap, size_t *len)
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
    *len = n;
    return over ? 2 : 1;
}

static bool tpc_digits(const char *s, int64_t *out)
{
    int64_t v = 0;
    size_t len = strlen(s);
    if (len == 0 || len > TPC_TOKEN_DIGITS)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

/* Splits `line` on tabs into `fields`. Returns the field count, or
 * TPC_FIELDS + 1 when the line has more fields than that. */
static size_t tpc_split(char *line, char *fields[TPC_FIELDS])
{
    size_t n = 0;
    char *p = line;
    for (;;) {
        if (n == TPC_FIELDS)
            return n + 1u;
        fields[n++] = p;
        p = strchr(p, '\t');
        if (!p)
            return n;
        *p++ = '\0';
    }
}

static struct tpc_lane *tpc_find_lane(struct tpc_landed *l, const char *name)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->lanes[i].name, name) == 0)
            return &l->lanes[i];
    return NULL;
}

static struct tpc_lane *tpc_add_lane(struct tpc_landed *l, const char *name)
{
    struct tpc_lane *slot;
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2u : 64u;
        struct tpc_lane *grown = zcl_realloc(l->lanes, cap * sizeof(*grown), "landed_lanes");
        if (!grown) {
            l->oom = true;
            return NULL;
        }
        l->lanes = grown;
        l->cap = cap;
    }
    slot = &l->lanes[l->n++];
    memset(slot, 0, sizeof(*slot));
    (void)snprintf(slot->name, sizeof(slot->name), "%s", name);
    return slot;
}

/* Saturating sum: a report total never wraps. */
static int64_t tpc_add(int64_t a, int64_t b)
{
    return (b > 0 && a > INT64_MAX - b) ? INT64_MAX : a + b;
}

/* The per-role report's buckets: nine roles (the eight job labels, then
 * "other") by four model families (haiku, sonnet, opus, other). */
#define TPC_ROLES 9u
#define TPC_MODELS 4u
#define TPC_BUCKETS (TPC_ROLES * TPC_MODELS)
static const char *const tpc_roles[TPC_ROLES] = {
    "write", "cx", "review", "review1", "review2", "fix", "design", "check",
    "other"};
static const char *const tpc_models[TPC_MODELS] = {"haiku", "sonnet", "opus",
                                                   "other"};

/* The role index of an agent's job kind (the label text before ':'). */
static size_t tpc_role_index(const char *kind)
{
    for (size_t i = 0; kind && i + 1u < TPC_ROLES; i++)
        if (strcmp(kind, tpc_roles[i]) == 0)
            return i;
    return TPC_ROLES - 1u;
}

/* The model family of a ledger model string: haiku, sonnet or opus, found
 * as a substring (claude-haiku-5-5 is haiku); anything else is other. */
static size_t tpc_model_index(const char *model)
{
    static const char *const keys[] = {"haiku", "sonnet", "opus"};
    for (size_t i = 0; model && i < 3u; i++)
        if (strstr(model, keys[i]))
            return i;
    return TPC_MODELS - 1u;
}

static bool tpc_samples_push(struct tpc_samples *s, struct tpc_sample sample)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2u : 256u;
        struct tpc_sample *grown =
            zcl_realloc(s->v, cap * sizeof(*grown), "tpc_samples");
        if (!grown) {
            s->oom = true;
            return false;
        }
        s->v = grown;
        s->cap = cap;
    }
    s->v[s->n++] = sample;
    return true;
}

/* Folds one result row into the landed lane its agent joined. The KPI and
 * the per-role report both read through here, so they cannot disagree on
 * which rows count. */
static void tpc_fold_row(const struct tpc_result *r, void *user)
{
    struct tpc_fold *f = user;
    const char *lane = zcl_objectives_agent_lane(f->ix, r->agent);
    struct tpc_lane *hit = lane ? tpc_find_lane(f->l, lane) : NULL;
    struct tpc_sample sample;
    if (!hit)
        return;
    hit->tokens = tpc_add(hit->tokens, r->tokens);
    hit->cache = tpc_add(hit->cache, r->cache);
    hit->agents++;
    if (!f->s)
        return;
    sample.bucket = (uint8_t)(tpc_role_index(
                                  zcl_objectives_agent_kind(f->ix, r->agent)) *
                                  TPC_MODELS +
                              tpc_model_index(r->model));
    sample.tokens = r->tokens;
    sample.cache = r->cache;
    (void)tpc_samples_push(f->s, sample);
}

/* The lane a land note names: the text before its first ':'. */
static bool tpc_note_lane(const char *note, char *out, size_t cap)
{
    const char *colon = note ? strchr(note, ':') : NULL;
    size_t n = colon ? (size_t)(colon - note) : 0;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, note, n);
    out[n] = '\0';
    return true;
}

/* The lane a land row names: the basename of its "worktree" when that is
 * present and fits, else the note's lane prefix. json_get_str gives "" for a
 * missing key, which is absent here too. */
static bool tpc_row_lane(const struct json_value *row, char *out, size_t cap)
{
    const char *wt = json_get_str(json_get(row, "worktree"));
    size_t n = strlen(wt), start;
    while (n > 0 && wt[n - 1] == '/')
        n--;
    start = n;
    while (start > 0 && wt[start - 1] != '/')
        start--;
    if (n > start && n - start < cap) {
        memcpy(out, wt + start, n - start);
        out[n - start] = '\0';
        return true;
    }
    return tpc_note_lane(json_get_str(json_get(row, "note")), out, cap);
}

static void tpc_landed_row(const struct json_value *row, void *user)
{
    struct tpc_landed *l = user;
    const char *state = json_get_str(json_get(row, "state"));
    char lane[104];
    int64_t when;
    if (!state || strcmp(state, "landed") != 0 || l->oom)
        return;
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &when) ||
        when < l->start || when > l->end)
        return;
    if (!tpc_row_lane(row, lane, sizeof(lane)) || tpc_find_lane(l, lane))
        return;
    if (l->n >= TPC_LANES_MAX)
        l->truncated = true;
    else
        (void)tpc_add_lane(l, lane);
}

/* Parses one ledger line and offers each valid result row to fn. False when
 * the line is malformed: the wrong field count, an unknown kind, or a token
 * column that is not a plain decimal count. A predict row is valid and
 * offered to nothing. */
static bool tpc_row(char *line, tpc_result_fn fn, void *user)
{
    char *fields[TPC_FIELDS];
    struct tpc_result r;
    int64_t tin, tout;
    if (tpc_split(line, fields) != TPC_FIELDS)
        return false;
    if (strcmp(fields[1], "predict") != 0 && strcmp(fields[1], "result") != 0)
        return false;
    if (!tpc_digits(fields[10], &tin) || !tpc_digits(fields[11], &tout) ||
        !tpc_digits(fields[12], &r.cache))
        return false;
    if (strcmp(fields[1], "result") != 0)
        return true;
    r.agent = fields[3];
    r.model = fields[8];
    r.tokens = tin + tout;
    fn(&r, user);
    return true;
}

/* Walks the experiment ledger, offering every valid result row to fn.
 * False with `reason` set when the file is missing or unreadable. The
 * header line is not a row. */
static bool tpc_scan_ledger(const char *path, tpc_result_fn fn, void *user,
                            int64_t *skipped, char *reason, size_t cap)
{
    char line[TPC_LINE_CAP];
    size_t len = 0;
    size_t line_no = 0;
    int status;
    FILE *f = fopen(path, "rb");
    if (!f) {
        (void)snprintf(reason, cap, "missing experiment ledger %s", path);
        return false;
    }
    while ((status = tpc_read_line(f, line, sizeof(line), &len)) > 0) {
        line_no++;
        if (line_no > 1 && (status == 2 || !tpc_row(line, fn, user)))
            (*skipped)++;
    }
    if (fclose(f) != 0 || status < 0) {
        (void)snprintf(reason, cap, "unreadable experiment ledger %s", path);
        return false;
    }
    return true;
}

static int tpc_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Median of a sorted array (the mean of the two middles, rounded down) and
 * its p90 (nearest rank). */
static int64_t tpc_median(const int64_t *v, size_t n)
{
    if (n % 2u)
        return v[n / 2u];
    return v[n / 2u - 1u] + (v[n / 2u] - v[n / 2u - 1u]) / 2;
}

static int64_t tpc_p90(const int64_t *v, size_t n)
{
    return v[(n * 9u + 9u) / 10u - 1u];
}

/* Collects the joined lanes' token and cache sums, sorts both, and fills the
 * measured value and its detail. */
static bool tpc_fill(const struct tpc_landed *l, size_t joined,
                     const struct zcl_agent_index *ix, int64_t skipped,
                     struct zcl_objective_value *v)
{
    int64_t *tok = zcl_malloc(joined * sizeof(*tok), "tpc_tokens");
    int64_t *cac = zcl_malloc(joined * sizeof(*cac), "tpc_cache");
    size_t k = 0;
    if (!tok || !cac) {
        free(tok);
        free(cac);
        return false;
    }
    for (size_t i = 0; i < l->n; i++) {
        if (l->lanes[i].agents == 0)
            continue;
        tok[k] = l->lanes[i].tokens;
        cac[k++] = l->lanes[i].cache;
    }
    qsort(tok, joined, sizeof(*tok), tpc_cmp_i64);
    qsort(cac, joined, sizeof(*cac), tpc_cmp_i64);
    v->measured = true;
    v->value = tpc_median(tok, joined);
    (void)snprintf(v->note, sizeof(v->note),
                   "%zu landed lanes joined, %zu landed without an agent, p90 "
                   "%lld, cache-read median %lld%s%s, %lld malformed lines "
                   "skipped",
                   joined, l->n - joined, (long long)tpc_p90(tok, joined),
                   (long long)tpc_median(cac, joined),
                   l->truncated ? ", lane cap hit" : "",
                   ix->capped ? ", meta file cap hit" : "",
                   (long long)skipped);
    free(tok);
    free(cac);
    return true;
}

/* Each unmeasured branch names its cause first: the status column is short,
 * so the cause must lead the reason. */
static struct zcl_objective_value tpc_unmeasured(struct zcl_objective_value v,
                                                const char *why)
{
    v.measured = false;
    (void)snprintf(v.reason, sizeof(v.reason), "%s", why);
    return v;
}

static size_t tpc_joined(const struct tpc_landed *l)
{
    size_t joined = 0;
    for (size_t i = 0; i < l->n; i++)
        if (l->lanes[i].agents > 0)
            joined++;
    return joined;
}

/* The scan proper, with the index and landed list built. */
static bool tpc_ledger_present(const char *path, char *reason, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        (void)snprintf(reason, cap, "missing experiment ledger %s", path);
        return false;
    }
    (void)fclose(f);
    return true;
}

static struct zcl_objective_value tpc_measure_in(
    struct zcl_objective_value v, const char *ledger,
    const struct zcl_agent_index *ix, struct tpc_landed *landed)
{
    int64_t skipped = 0;
    size_t joined;
    struct tpc_fold fold = {ix, landed, NULL};
    if (!tpc_scan_ledger(ledger, tpc_fold_row, &fold, &skipped, v.reason,
                         sizeof(v.reason)))
        return v;
    joined = tpc_joined(landed);
    if (joined == 0) {
        (void)snprintf(v.reason, sizeof(v.reason),
                       "no landed lane joins a worker agent (%zu landed, %zu "
                       "agent labels indexed%s)",
                       landed->n, ix->n, ix->capped ? ", file cap hit" : "");
        return v;
    }
    if (!tpc_fill(landed, joined, ix, skipped, &v))
        return tpc_unmeasured(v, "out of memory joining agent token rows");
    return v;
}

struct zcl_objective_value zcl_objectives_tokens_per_landed_commit(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v;
    struct tpc_landed landed;
    struct zcl_agent_index ix;
    char ledger_buf[1024], outcomes_buf[1024];
    const char *ledger = NULL, *outcomes = NULL;
    int64_t now = tpc_now(options);

    memset(&v, 0, sizeof(v));
    memset(&landed, 0, sizeof(landed));
    landed.start = now - TPC_WINDOW_S;
    landed.end = now;

    if (!tpc_resolve_ledger(options, ledger_buf, sizeof(ledger_buf), &ledger))
        return tpc_unmeasured(v, "no experiment ledger path (no HOME)");
    if (!zcl_objectives_outcomes_path(options, outcomes_buf,
                                      sizeof(outcomes_buf), &outcomes))
        return tpc_unmeasured(v, "state root unavailable");
    if (!zcl_objectives_ledger_walk(outcomes, tpc_landed_row, &landed,
                                    v.reason, sizeof(v.reason))) {
        free(landed.lanes);
        return v;
    }
    if (landed.oom) {
        free(landed.lanes);
        return tpc_unmeasured(v, "out of memory reading landed lanes");
    }
    if (!tpc_ledger_present(ledger, v.reason, sizeof(v.reason))) {
        free(landed.lanes);
        return v;
    }
    if (landed.n == 0)
        return tpc_unmeasured(v, "no landed row in 7 days");
    if (!zcl_objectives_agent_index_build(&ix)) {
        zcl_objectives_agent_index_free(&ix);
        free(landed.lanes);
        return tpc_unmeasured(v, "out of memory indexing agent meta files");
    }
    v = tpc_measure_in(v, ledger, &ix, &landed);
    zcl_objectives_agent_index_free(&ix);
    free(landed.lanes);
    return v;
}

/* ── fleet.objectives.value: the per-role, per-model spend report ─────── */

#define TPV_SCHEMA_OUT "zcl.fleet_objectives_value.v1"
#define TPV_LEAF "fleet.objectives.value"
#define TPV_SCREEN_MAX 8192u

/* Everything the report reads: the landed lanes, the agent index, the joined
 * samples, the malformed-line count, and the non-empty groups in report
 * order. */
struct tpv_group {
    size_t bucket;
    size_t agents;
    int64_t fresh;
    int64_t fresh_median;
    int64_t cache_median;
};

struct tpv_read {
    struct tpc_landed landed;
    struct zcl_agent_index ix;
    struct tpc_samples samples;
    int64_t skipped;
    struct tpv_group groups[TPC_BUCKETS];
    size_t n;
    int64_t total;
};

static void tpv_free(struct tpv_read *rd)
{
    free(rd->landed.lanes);
    zcl_objectives_agent_index_free(&rd->ix);
    free(rd->samples.v);
}

/* Fills the group of one bucket from its samples. A bucket with no sample
 * keeps agents 0. False on an allocation failure. */
static bool tpv_group_of(const struct tpc_samples *s, size_t bucket,
                         struct tpv_group *g)
{
    int64_t *tok, *cac;
    size_t n = 0, k = 0;
    for (size_t i = 0; i < s->n; i++)
        if (s->v[i].bucket == bucket)
            n++;
    memset(g, 0, sizeof(*g));
    g->bucket = bucket;
    g->agents = n;
    if (n == 0)
        return true;
    tok = zcl_malloc(n * sizeof(*tok), "tpv_tokens");
    cac = zcl_malloc(n * sizeof(*cac), "tpv_cache");
    if (!tok || !cac) {
        free(tok);
        free(cac);
        return false;
    }
    for (size_t i = 0; i < s->n; i++) {
        if (s->v[i].bucket != bucket)
            continue;
        tok[k] = s->v[i].tokens;
        cac[k++] = s->v[i].cache;
        g->fresh = tpc_add(g->fresh, s->v[i].tokens);
    }
    qsort(tok, n, sizeof(*tok), tpc_cmp_i64);
    qsort(cac, n, sizeof(*cac), tpc_cmp_i64);
    g->fresh_median = tpc_median(tok, n);
    g->cache_median = tpc_median(cac, n);
    free(tok);
    free(cac);
    return true;
}

/* Biggest fresh total first; a tie goes to the earlier bucket. */
static int tpv_cmp_group(const void *a, const void *b)
{
    const struct tpv_group *x = a, *y = b;
    if (x->fresh != y->fresh)
        return x->fresh > y->fresh ? -1 : 1;
    return (x->bucket > y->bucket) - (x->bucket < y->bucket);
}

/* The non-empty groups, sorted, and the fresh total over them. */
static bool tpv_groups(struct tpv_read *rd)
{
    size_t n = 0;
    for (size_t b = 0; b < TPC_BUCKETS; b++) {
        struct tpv_group g;
        if (!tpv_group_of(&rd->samples, b, &g))
            return false;
        if (g.agents == 0)
            continue;
        rd->groups[n++] = g;
        rd->total = tpc_add(rd->total, g.fresh);
    }
    rd->n = n;
    qsort(rd->groups, n, sizeof(*rd->groups), tpv_cmp_group);
    return true;
}

/* A group's whole-percent share of the fresh total, rounded down. */
static int64_t tpv_share(int64_t fresh, int64_t total)
{
    return total > 0 ? (int64_t)((double)fresh * 100.0 / (double)total) : 0;
}

/* Reads the outcomes and the ledger into rd. False, with reason set, when
 * either input is missing or unreadable. */
static bool tpv_read(const struct zcl_objectives_options *options,
                     struct tpv_read *rd, char *reason, size_t cap)
{
    char ledger_buf[1024], outcomes_buf[1024];
    const char *ledger = NULL, *outcomes = NULL;
    struct tpc_fold fold = {&rd->ix, &rd->landed, &rd->samples};
    int64_t now = tpc_now(options);
    rd->landed.start = now - TPC_WINDOW_S;
    rd->landed.end = now;
    if (!tpc_resolve_ledger(options, ledger_buf, sizeof(ledger_buf), &ledger)) {
        (void)snprintf(reason, cap, "no experiment ledger path (no HOME)");
        return false;
    }
    if (!zcl_objectives_outcomes_path(options, outcomes_buf,
                                      sizeof(outcomes_buf), &outcomes)) {
        (void)snprintf(reason, cap, "state root unavailable");
        return false;
    }
    if (!zcl_objectives_ledger_walk(outcomes, tpc_landed_row, &rd->landed,
                                    reason, cap))
        return false;
    if (rd->landed.oom) {
        (void)snprintf(reason, cap, "out of memory reading landed lanes");
        return false;
    }
    if (!tpc_ledger_present(ledger, reason, cap))
        return false;
    if (!zcl_objectives_agent_index_build(&rd->ix)) {
        (void)snprintf(reason, cap, "out of memory indexing agent meta files");
        return false;
    }
    fold.ix = &rd->ix;
    if (!tpc_scan_ledger(ledger, tpc_fold_row, &fold, &rd->skipped, reason,
                         cap))
        return false;
    if (rd->samples.oom) {
        (void)snprintf(reason, cap, "out of memory joining agent token rows");
        return false;
    }
    return tpv_groups(rd);
}

/* Appends one formatted piece of the screen, never past cap - 1. */
static void tpv_add(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    int w;
    if (*used + 1u >= cap)
        return;
    va_start(ap, fmt);
    w = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (w < 0)
        return;
    *used = (size_t)w >= cap - *used ? cap - 1u : *used + (size_t)w;
}

static void tpv_screen_row(char *out, size_t cap, size_t *used,
                           const struct tpv_group *g, int64_t total)
{
    tpv_add(out, cap, used, "%-8s %-6s %6zu %14lld %12lld %12lld %5lld\n",
            tpc_roles[g->bucket / TPC_MODELS],
            tpc_models[g->bucket % TPC_MODELS], g->agents,
            (long long)g->fresh, (long long)g->fresh_median,
            (long long)g->cache_median, (long long)tpv_share(g->fresh, total));
}

/* The plain-text table: one line per group, then the totals line. */
static void tpv_screen(char *out, size_t cap, const struct tpv_read *rd,
                       size_t joined, size_t agents)
{
    size_t used = 0;
    out[0] = '\0';
    tpv_add(out, cap, &used, "%-8s %-6s %6s %14s %12s %12s %5s\n", "role",
            "model", "agents", "fresh_total", "fresh_median", "cache_median",
            "share");
    for (size_t i = 0; i < rd->n; i++)
        tpv_screen_row(out, cap, &used, &rd->groups[i], rd->total);
    tpv_add(out, cap, &used,
            "landed %zu, joined %zu, agents %zu, fresh tokens %lld, %lld "
            "malformed lines skipped\n",
            rd->landed.n, joined, agents, (long long)rd->total,
            (long long)rd->skipped);
}

static bool tpv_push_rows(struct json_value *data, const struct tpv_read *rd)
{
    struct json_value rows;
    bool ok = true;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; ok && i < rd->n; i++) {
        const struct tpv_group *g = &rd->groups[i];
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        ok = json_push_kv_str(&o, "role", tpc_roles[g->bucket / TPC_MODELS]) &&
             json_push_kv_str(&o, "model", tpc_models[g->bucket % TPC_MODELS]) &&
             json_push_kv_int(&o, "agents", (int64_t)g->agents) &&
             json_push_kv_int(&o, "fresh_total", g->fresh) &&
             json_push_kv_int(&o, "fresh_median", g->fresh_median) &&
             json_push_kv_int(&o, "cache_median", g->cache_median) &&
             json_push_kv_int(&o, "share_pct", tpv_share(g->fresh, rd->total)) &&
             json_push_back(&rows, &o);
        json_free(&o);
    }
    ok = ok && json_push_kv(data, "rows", &rows);
    json_free(&rows);
    return ok;
}

static bool tpv_push_totals(struct json_value *data, const struct tpv_read *rd,
                            size_t joined, size_t agents)
{
    struct json_value t;
    bool ok;
    json_init(&t);
    json_set_object(&t);
    ok = json_push_kv_int(&t, "lanes_landed", (int64_t)rd->landed.n) &&
         json_push_kv_int(&t, "lanes_joined", (int64_t)joined) &&
         json_push_kv_int(&t, "agents", (int64_t)agents) &&
         json_push_kv_int(&t, "fresh_total", rd->total) &&
         json_push_kv(data, "totals", &t);
    json_free(&t);
    return ok;
}

/* Builds the reply data from a finished read. False, with reason set, when
 * the object cannot be built. */
static bool tpv_build(struct json_value *data, const struct tpv_read *rd,
                      char *reason, size_t cap)
{
    char screen[TPV_SCREEN_MAX];
    size_t joined = tpc_joined(&rd->landed), agents = 0;
    bool ok;
    for (size_t i = 0; i < rd->n; i++)
        agents += rd->groups[i].agents;
    tpv_screen(screen, sizeof(screen), rd, joined, agents);
    ok = json_push_kv_str(data, "schema", TPV_SCHEMA_OUT) &&
         tpv_push_rows(data, rd) &&
         tpv_push_totals(data, rd, joined, agents) &&
         json_push_kv_int(data, "skipped", rd->skipped) &&
         json_push_kv_str(data, "screen", screen);
    if (!ok)
        (void)snprintf(reason, cap, "out of memory building the %s report",
                       TPV_LEAF);
    return ok;
}

bool zcl_objectives_value_data(const struct zcl_objectives_options *options,
                               struct json_value *data, char *reason,
                               size_t cap)
{
    struct tpv_read rd;
    bool ok;
    memset(&rd, 0, sizeof(rd));
    ok = tpv_read(options, &rd, reason, cap) && tpv_build(data, &rd, reason, cap);
    tpv_free(&rd);
    return ok;
}

static const char *tpv_input_str(const struct zcl_command_request *request,
                                 const char *key)
{
    const char *v;
    if (!request || !request->input)
        return NULL;
    v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

/* The `fleet.objectives.value` leaf: read-only. `outcomes` and `experiments`
 * point the reader at a fixture; absent, the state root and the experiment
 * ledger default as they do for tokens_per_landed_commit. */
void zcl_native_handle_fleet_objectives_value(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zcl_objectives_options options;
    char reason[ZCL_OBJECTIVES_REASON_MAX] = "";
    if (!reply)
        return;
    zcl_command_reply_init(reply, TPV_SCHEMA_OUT);
    memset(&options, 0, sizeof(options));
    options.outcomes = tpv_input_str(request, "outcomes");
    options.experiments = tpv_input_str(request, "experiments");
    if (zcl_objectives_value_data(&options, &reply->data, reason,
                                  sizeof(reason))) {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
        return;
    }
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "VALUE_UNREADABLE",
                           "decide", false, false, reason,
                           "pass outcomes= and experiments= to point at the "
                           "land outcomes file and the experiment ledger");
}
