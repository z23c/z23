/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: generate engine/composition/fleet_observations.def from the
 *          experiment ledger. See tools/dev/fleet_observe.h for the
 *          contract; tools/dev/fleet_observe_main.c is the CLI shim. */
#define _POSIX_C_SOURCE 200809L
#include "fleet_observe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── closed vocabularies (docs/agent/EXECUTOR_HEURISTICS.md) ──────── */

static const char *const k_task_classes[] = {
    "read", "verify", "unit_docs", "unit_c23_one_file", "lane_multi_file",
    "rebase_land", "diagnose", "land_train", "unknown",
};
static const char *const k_executors[] = {
    "claude-fable", "claude-opus", "claude-sonnet", "claude-haiku", "grok",
    "glm", "codex", "muse", "mac",
};
static const char *const k_kinds[] = {"predict", "result"};
static const char *const k_outcomes[] = {
    "LAND", "FIX_LAND", "FIX", "HOLD", "READY", "blocked", "timeout",
    "wrong", "landed", "failed", "unknown",
};

static bool in_list(const char *v, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (v && strcmp(v, list[i]) == 0)
            return true;
    return false;
}

#define IN(v, arr) in_list((v), (arr), sizeof(arr) / sizeof((arr)[0]))

bool fo_task_class_known(const char *v) { return IN(v, k_task_classes); }
bool fo_executor_known(const char *v) { return IN(v, k_executors); }
bool fo_kind_known(const char *v) { return IN(v, k_kinds); }
bool fo_outcome_known(const char *v) { return IN(v, k_outcomes); }

bool fo_outcome_is_land(const char *outcome)
{
    return outcome && (strcmp(outcome, "LAND") == 0 ||
                        strcmp(outcome, "FIX_LAND") == 0 ||
                        strcmp(outcome, "READY") == 0 ||
                        strcmp(outcome, "landed") == 0);
}

/* ── timestamp parsing ────────────────────────────────────────────────── */

static bool digits(const char *s, int n, int *out)
{
    int v = 0;

    for (int i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

/* Days from the civil epoch (1970-01-01) to (y, m, d), Howard Hinnant's
 * days_from_civil — exact, no libc timegm() dependency. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;                      /* [0, 399] */
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1; /* [0,365]*/
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;          /* [0,146096]*/
    return era * 146097 + doe - 719468;
}

bool fo_parse_iso8601(const char *s, int64_t *out)
{
    int y, mo, d, h, mi, se;

    if (!s || !out || strlen(s) != 20)
        return false;
    if (!digits(s, 4, &y) || s[4] != '-' || !digits(s + 5, 2, &mo) ||
        s[7] != '-' || !digits(s + 8, 2, &d) || s[10] != 'T' ||
        !digits(s + 11, 2, &h) || s[13] != ':' || !digits(s + 14, 2, &mi) ||
        s[16] != ':' || !digits(s + 17, 2, &se) || s[19] != 'Z')
        return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60)
        return false;
    *out = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

/* ── line parsing ─────────────────────────────────────────────────────── */

#define FO_FIELD_COUNT 22

static void fo_err(char *err, size_t cap, size_t line_no, const char *msg)
{
    if (!err || cap == 0)
        return;
    (void)snprintf(err, cap, "rows.tsv:%zu: %s", line_no, msg);
}

bool fo_parse_line(const char *line, size_t line_no, struct fo_row *out,
                    char *err, size_t err_cap)
{
    char buf[FO_LINE_CAP];
    char *fields[FO_FIELD_COUNT];
    size_t n = 0;
    char *p, *save = NULL;

    if (!line || !out) {
        fo_err(err, err_cap, line_no, "null row");
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (strlen(line) >= sizeof(buf)) {
        fo_err(err, err_cap, line_no, "row longer than the line cap");
        return false;
    }
    (void)snprintf(buf, sizeof(buf), "%s", line);

    p = strtok_r(buf, "\t", &save);
    while (p && n < FO_FIELD_COUNT) {
        fields[n++] = p;
        p = strtok_r(NULL, "\t", &save);
    }
    if (p != NULL || n != FO_FIELD_COUNT) {
        fo_err(err, err_cap, line_no, "does not have 22 tab-separated fields");
        return false;
    }

    /* columns: 0 ts 1 kind 2 box 3 task_id 4 task_class 5 story 6 executor
     * 7 harness 8 model 9 effort 10..16 token/turn/wall ints 17 outcome
     * 18..20 lines_added/removed/defects 21 note */
    if (!fo_parse_iso8601(fields[0], &out->ts_unix)) {
        fo_err(err, err_cap, line_no, "ts is not a valid ISO-8601 UTC stamp");
        return false;
    }
    if (!fo_kind_known(fields[1])) {
        fo_err(err, err_cap, line_no, "kind is not predict or result");
        return false;
    }
    if (!fo_task_class_known(fields[4])) {
        fo_err(err, err_cap, line_no,
               "task_class is outside the closed vocabulary in docs/agent/EXECUTOR_HEURISTICS.md");
        return false;
    }
    if (!fo_executor_known(fields[6])) {
        fo_err(err, err_cap, line_no,
               "executor is outside the closed vocabulary in docs/agent/EXECUTOR_HEURISTICS.md");
        return false;
    }
    if (!fo_outcome_known(fields[17])) {
        fo_err(err, err_cap, line_no,
               "outcome is outside the closed vocabulary in docs/agent/EXECUTOR_HEURISTICS.md");
        return false;
    }

    (void)snprintf(out->kind, sizeof(out->kind), "%s", fields[1]);
    (void)snprintf(out->task_class, sizeof(out->task_class), "%s", fields[4]);
    (void)snprintf(out->executor, sizeof(out->executor), "%s", fields[6]);
    (void)snprintf(out->outcome, sizeof(out->outcome), "%s", fields[17]);
    return true;
}

/* ── aggregation ──────────────────────────────────────────────────────── */

int64_t fo_latest_ts(const struct fo_row *rows, size_t row_count)
{
    int64_t latest = 0;

    for (size_t i = 0; i < row_count; i++)
        if (rows[i].ts_unix > latest)
            latest = rows[i].ts_unix;
    return latest;
}

static struct fo_pair *fo_find_pair(struct fo_pair *pairs, size_t *count,
                                     size_t cap, const char *executor,
                                     const char *task_class)
{
    for (size_t i = 0; i < *count; i++)
        if (strcmp(pairs[i].executor, executor) == 0 &&
            strcmp(pairs[i].task_class, task_class) == 0)
            return &pairs[i];
    if (*count >= cap)
        return NULL;
    struct fo_pair *p = &pairs[(*count)++];
    memset(p, 0, sizeof(*p));
    (void)snprintf(p->executor, sizeof(p->executor), "%s", executor);
    (void)snprintf(p->task_class, sizeof(p->task_class), "%s", task_class);
    return p;
}

size_t fo_aggregate(const struct fo_row *rows, size_t row_count,
                     int64_t anchor_unix, int window_days,
                     struct fo_pair *pairs, size_t pairs_cap)
{
    size_t count = 0;
    int64_t floor_ts = anchor_unix - (int64_t)window_days * 86400;

    for (size_t i = 0; i < row_count; i++) {
        const struct fo_row *r = &rows[i];
        struct fo_pair *p;

        if (strcmp(r->kind, "result") != 0)
            continue;
        if (r->ts_unix < floor_ts || r->ts_unix > anchor_unix)
            continue;
        p = fo_find_pair(pairs, &count, pairs_cap, r->executor,
                          r->task_class);
        if (!p)
            continue; /* pairs_cap exhausted; caller sized it generously */
        p->n++;
        if (fo_outcome_is_land(r->outcome))
            p->land++;
        if (strcmp(r->outcome, "FIX_LAND") == 0)
            p->fix_land++;
    }
    return count;
}

/* ── classification ───────────────────────────────────────────────────── */

size_t fo_classify(const struct fo_pair *pair, struct fo_observation *out2)
{
    size_t k = 0;
    bool routable, refused, probe;

    if (pair->n <= 0)
        return 0;

    routable = pair->n >= FO_ROUTABLE_MIN_N &&
               pair->land * FO_ROUTABLE_MIN_P_DEN >=
                   pair->n * FO_ROUTABLE_MIN_P_NUM;
    refused = !routable && pair->land == 0 && pair->n >= FO_REFUSED_MIN_N;
    probe = !routable && !refused && pair->n < FO_PROBE_MAX_N;

    (void)snprintf(out2[k].subject, sizeof(out2[k].subject), "%s",
                   pair->executor);
    (void)snprintf(out2[k].object, sizeof(out2[k].object), "%s",
                   pair->task_class);
    out2[k].num = pair->land;
    out2[k].den = pair->n;
    (void)snprintf(out2[k].relation, sizeof(out2[k].relation), "%s",
                   routable ? "routable_for"
                   : refused ? "refused_for"
                   : probe  ? "probe_for"
                            : "observed_for");
    k++;

    if (pair->fix_land * FO_FINISHER_MIN_P_DEN >=
        pair->n * FO_FINISHER_MIN_P_NUM) {
        (void)snprintf(out2[k].subject, sizeof(out2[k].subject), "%s",
                       pair->executor);
        (void)snprintf(out2[k].object, sizeof(out2[k].object), "%s",
                       pair->task_class);
        (void)snprintf(out2[k].relation, sizeof(out2[k].relation), "%s",
                       "handles_with_finisher");
        out2[k].num = pair->fix_land;
        out2[k].den = pair->n;
        k++;
    }
    return k;
}

/* ── ledger file reading ──────────────────────────────────────────────── */

bool fo_read_ledger(const char *path, struct fo_row *rows, size_t cap,
                    size_t *count_out, char *err, size_t err_cap)
{
    FILE *f;
    char line[FO_LINE_CAP];
    size_t line_no = 0, count = 0;

    if (count_out)
        *count_out = 0;
    f = path ? fopen(path, "r") : NULL;
    if (!f) {
        if (err && err_cap)
            (void)snprintf(err, err_cap, "cannot open ledger '%s'",
                           path ? path : "(null)");
        return false;
    }
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        line_no++;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (line_no == 1)
            continue; /* header */
        if (len == 0)
            continue; /* trailing blank line */
        if (count >= cap) {
            if (err && err_cap)
                (void)snprintf(err, err_cap,
                               "rows.tsv:%zu: more rows than the %zu-row cap",
                               line_no, cap);
            (void)fclose(f);
            return false;
        }
        if (!fo_parse_line(line, line_no, &rows[count], err, err_cap)) {
            (void)fclose(f);
            return false;
        }
        count++;
    }
    (void)fclose(f);
    if (count_out)
        *count_out = count;
    return true;
}

/* ── rendering ────────────────────────────────────────────────────────── */

static int fo_cmp_obs(const void *a, const void *b)
{
    const struct fo_observation *x = a, *y = b;
    int c = strcmp(x->subject, y->subject);

    if (c) return c;
    c = strcmp(x->object, y->object);
    if (c) return c;
    return strcmp(x->relation, y->relation);
}

size_t fo_render_def(const struct fo_observation *obs, size_t obs_count,
                      int window_days, int64_t generated_unix,
                      const char *source_desc, char *out, size_t out_cap)
{
    struct fo_observation sorted[FO_MAX_OBS_ROWS];
    size_t n = obs_count > FO_MAX_OBS_ROWS ? FO_MAX_OBS_ROWS : obs_count;
    size_t used = 0;
    int w;

    memcpy(sorted, obs, n * sizeof(*obs));
    qsort(sorted, n, sizeof(sorted[0]), fo_cmp_obs);

#define FO_APPEND(...)                                                      \
    do {                                                                    \
        w = snprintf(out ? out + used : NULL, out ? out_cap - used : 0,     \
                     __VA_ARGS__);                                          \
        if (w > 0)                                                          \
            used += (size_t)w;                                             \
    } while (0)

    FO_APPEND(
        "/* Copyright 2026 Rhett Creighton - Apache License 2.0 */\n"
        "/*\n"
        " * fleet_observations.def — GENERATED. Do not hand-edit.\n"
        " *\n"
        " * Regenerate with:\n"
        " *   build/bin/z23-fleet-observe --ledger=<path> --days=%d "
        "--out=engine/composition/fleet_observations.def\n"
        " *\n"
        " * Source for the committed copy: %s (the live ledger at\n"
        " * $XDG_STATE_HOME/zclassic23/experiments/rows.tsv is used only when\n"
        " * an operator runs the tool by hand). tools/lint/"
        "check_fleet_observations.sh\n"
        " * regenerates from that same fixture and diffs this file: a hand "
        "edit\n"
        " * fails the gate. window_days=%d, generated_unix=%lld.\n"
        " *\n"
        " * FLEET_OBSERVED(subject_, relation_, object_, context_, num_, "
        "den_,\n"
        " *                window_days_, generated_unix_) — subject is an "
        "executor,\n"
        " * object a task_class, both from the ledger's closed vocabulary "
        "(docs/agent/EXECUTOR_HEURISTICS.md, \"Ledger columns\").\n"
        " * relation is one of routable_for, refused_for, probe_for, "
        "observed_for\n"
        " * or handles_with_finisher — ground verdicts a generator computed, "
        "never\n"
        " * a number a reader has to interpret. See tools/dev/"
        "fleet_observe.h for\n"
        " * the exact thresholds.\n"
        " */\n"
        "#ifndef FLEET_OBSERVED\n"
        "#define FLEET_OBSERVED(subject_, relation_, object_, context_, "
        "num_, den_, window_days_, generated_unix_)\n"
        "#define ZCL_FLEET_OBSERVED_LOCAL_\n"
        "#endif\n\n",
        window_days, source_desc, window_days, (long long)generated_unix);

    for (size_t i = 0; i < n; i++) {
        FO_APPEND("FLEET_OBSERVED(\"%s\", \"%s\", \"%s\", \"observation\", "
                   "%lld, %lld, %d, %lld)\n",
                   sorted[i].subject, sorted[i].relation, sorted[i].object,
                   (long long)sorted[i].num, (long long)sorted[i].den,
                   window_days, (long long)generated_unix);
    }

    FO_APPEND(
        "\n#ifdef ZCL_FLEET_OBSERVED_LOCAL_\n"
        "#undef FLEET_OBSERVED\n"
        "#undef ZCL_FLEET_OBSERVED_LOCAL_\n"
        "#endif\n");
#undef FO_APPEND
    return used;
}
