/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The tokens_per_landed_commit producer. A landed lane is a landed
 *          row of the land outcomes file in the trailing 7 days whose note
 *          starts `<lane>:`. Its worker agents come from the agent meta
 *          index (native_fleet_objectives_lanes.c: agent id -> lane for the
 *          write/cx/review/review1/review2/fix job labels). Its cost is the
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
    if (!tpc_note_lane(json_get_str(json_get(row, "note")), lane,
                       sizeof(lane)) ||
        tpc_find_lane(l, lane))
        return;
    if (l->n >= TPC_LANES_MAX)
        l->truncated = true;
    else
        (void)tpc_add_lane(l, lane);
}

/* Folds one ledger line into the landed lane its agent joined. False when
 * the line is malformed: the wrong field count, an unknown kind, or a token
 * column that is not a plain decimal count. */
static bool tpc_row(char *line, const struct zcl_agent_index *ix,
                    struct tpc_landed *l)
{
    char *fields[TPC_FIELDS];
    int64_t tin, tout, cache;
    const char *lane;
    struct tpc_lane *hit;
    if (tpc_split(line, fields) != TPC_FIELDS)
        return false;
    if (strcmp(fields[1], "predict") != 0 && strcmp(fields[1], "result") != 0)
        return false;
    if (!tpc_digits(fields[10], &tin) || !tpc_digits(fields[11], &tout) ||
        !tpc_digits(fields[12], &cache))
        return false;
    if (strcmp(fields[1], "result") != 0)
        return true;
    lane = zcl_objectives_agent_lane(ix, fields[3]);
    hit = lane ? tpc_find_lane(l, lane) : NULL;
    if (hit) {
        hit->tokens += tin + tout;
        hit->cache += cache;
        hit->agents++;
    }
    return true;
}

/* Walks the experiment ledger. False with `reason` set when the file is
 * missing or unreadable. The header line is not a row. */
static bool tpc_scan_ledger(const char *path, const struct zcl_agent_index *ix,
                            struct tpc_landed *l, int64_t *skipped,
                            char *reason, size_t cap)
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
        if (line_no > 1 && (status == 2 || !tpc_row(line, ix, l)))
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
    if (!tpc_scan_ledger(ledger, ix, landed, &skipped, v.reason,
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
