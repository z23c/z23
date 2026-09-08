/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — join measured agents to
 *          plan loops (loops.tsv) and append one plan+cost snapshot
 *          (snapshots.tsv). See tools/dev/mvp_ledger.h for the contract.
 *
 * ANCESTRY. This file runs no subprocess. `landed` is decided against an
 * ancestry list the caller produced with ONE `git rev-list` and passed in
 * by path, so the decision is reproducible from files alone and a reader
 * can check it without trusting this program's process handling. Without
 * that list `landed` is -1 ("not asked"), never a guessed 0. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "mvp_ledger_internal.h"

/* ── inputs read from files ───────────────────────────────────────────── */

static bool mvl_first_token(const char *line, char *dst, size_t cap)
{
    size_t n = 0;

    while (line[n] == ' ' || line[n] == '\t')
        line++;
    if (line[0] == '\0' || line[0] == '#')
        return false;
    while (line[n] != '\0' && line[n] != ' ' && line[n] != '\t')
        n++;
    if (n >= cap)
        return false;
    memcpy(dst, line, n);
    dst[n] = '\0';
    return true;
}

/* Reads a `<path>` of whitespace-separated rows, taking the first column of
 * every non-comment row into `rows`. Shared by the train pick list and the
 * ancestry list: both are one-token-per-line files. */
static bool mvl_read_first_column(const char *path, char *rows, size_t stride,
                                  size_t cap, size_t *count, char *err,
                                  size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_column_line");
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    *count = 0;
    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot read the list");
        free(buf);
        return false;
    }
    while (ok) {
        int rc = mvl_read_line(f, buf, MVL_LINE_CAP + 2);

        if (rc == 0)
            break;
        line_no++;
        if (rc < 0) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_line_too_long: line exceeds MVL_LINE_CAP bytes");
            ok = false;
            break;
        }
        if (*count >= cap) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_overflow: more rows than the bounded table holds");
            ok = false;
            break;
        }
        if (mvl_first_token(buf, rows + *count * stride, stride))
            (*count)++;
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

bool mvl_read_train_lanes(const char *path, char (*lanes)[MVL_LANE_CAP],
                          size_t cap, size_t *count, char *err,
                          size_t err_cap)
{
    return mvl_read_first_column(path, lanes[0], MVL_LANE_CAP, cap, count,
                                 err, err_cap);
}

bool mvl_read_ancestry(const char *path, char (*out)[MVL_ID_CAP], size_t cap,
                       size_t *count, char *err, size_t err_cap)
{
    return mvl_read_first_column(path, out[0], MVL_ID_CAP, cap, count, err,
                                 err_cap);
}

static bool mvl_hex_run(const char *s, size_t want)
{
    for (size_t i = 0; i < want; i++) {
        char c = s[i];
        bool digit = (c >= '0' && c <= '9');
        bool lower = (c >= 'a' && c <= 'f');

        if (!digit && !lower)
            return false;
    }
    return true;
}

bool mvl_evidence_landed(const char *evidence, const char (*anc)[MVL_ID_CAP],
                         size_t anc_count)
{
    size_t n = strlen(evidence);

    if (n < 7 || !mvl_hex_run(evidence, n))
        return false;
    for (size_t i = 0; i < anc_count; i++)
        if (strncmp(anc[i], evidence, n) == 0)
            return true;
    return false;
}

/* ── the join ─────────────────────────────────────────────────────────── */

static void mvl_add_share(struct mvl_join *j, const struct mvl_agent *a,
                          int64_t div)
{
    if (div <= 0)
        return;
    j->agents++;
    j->tokens_out += a->tokens_out / div;
    j->tokens_in += a->tokens_in / div;
    j->tool_uses += a->tool_uses / div;
    j->wall_s += (a->last_unix - a->first_unix) / div;
}

/* The measured window is the DIRECT agents' window only: a train assembler
 * worked on many loops at once, so stretching a loop's clock over the whole
 * train would report a wall nobody spent on it. */
static void mvl_widen(struct mvl_join *j, const struct mvl_agent *a)
{
    if (a->first_utc[0] == '\0')
        return;
    if (j->first_utc[0] == '\0' || strcmp(a->first_utc, j->first_utc) < 0)
        mvl_copy(j->first_utc, sizeof j->first_utc, a->first_utc);
    if (strcmp(a->last_utc, j->last_utc) > 0)
        mvl_copy(j->last_utc, sizeof j->last_utc, a->last_utc);
}

static void mvl_join_direct(const struct mvl_plan *plan,
                            const struct mvl_agents *agents,
                            struct mvl_join *joins)
{
    for (size_t i = 0; i < plan->loop_count; i++) {
        const char *lane = plan->loops[i].lane;

        if (lane[0] == '\0' || strcmp(lane, "-") == 0)
            continue;
        for (size_t k = 0; k < agents->count; k++) {
            const struct mvl_agent *a = &agents->rows[k];

            if (strcmp(a->lane, lane) != 0)
                continue;
            mvl_add_share(&joins[i], a, 1);
            mvl_widen(&joins[i], a);
            if (strcmp(a->kind, "verify") == 0)
                joins[i].verifier_rounds++;
        }
    }
}

static bool mvl_lane_on_train(const char *lane, char (*lanes)[MVL_LANE_CAP],
                              size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(lanes[i], lane) == 0)
            return true;
    return false;
}

static void mvl_split_assembler(const struct mvl_plan *plan,
                                const struct mvl_agent *a,
                                const char *trains_dir,
                                struct mvl_join *joins)
{
    char (*lanes)[MVL_LANE_CAP] = zcl_calloc(MVL_MAX_TRAIN_LANES,
                                             MVL_LANE_CAP, "mvl_train_lanes");
    char path[MVL_PATH_CAP];
    char err[MVL_ERR_CAP];
    size_t count = 0;
    int64_t members = 0;

    if (!lanes)
        return;
    if (!mvl_path_of(path, sizeof path, trains_dir, "/", a->lane,
                     "/late_picks.txt")) {
        free(lanes);
        return;
    }
    if (mvl_read_train_lanes(path, lanes, MVL_MAX_TRAIN_LANES, &count, err,
                             sizeof err)) {
        for (size_t i = 0; i < plan->loop_count; i++)
            if (mvl_lane_on_train(plan->loops[i].lane, lanes, count))
                members++;
        for (size_t i = 0; members > 0 && i < plan->loop_count; i++)
            if (mvl_lane_on_train(plan->loops[i].lane, lanes, count))
                mvl_add_share(&joins[i], a, members);
    }
    free(lanes);
}

static void mvl_split_design(const struct mvl_plan *plan,
                             const struct mvl_agent *a, struct mvl_join *joins)
{
    int64_t members = 0;

    for (size_t i = 0; i < plan->loop_count; i++)
        if (strstr(plan->loops[i].evidence, a->lane) != NULL)
            members++;
    for (size_t i = 0; members > 0 && i < plan->loop_count; i++)
        if (strstr(plan->loops[i].evidence, a->lane) != NULL)
            mvl_add_share(&joins[i], a, members);
}

void mvl_join_loops(const struct mvl_plan *plan,
                    const struct mvl_agents *agents, const char *trains_dir,
                    const char (*anc)[MVL_ID_CAP], size_t anc_count,
                    struct mvl_join *joins)
{
    for (size_t i = 0; i < plan->loop_count; i++) {
        memset(&joins[i], 0, sizeof joins[i]);
        joins[i].landed = anc_count > 0 ? 0 : -1;
    }
    mvl_join_direct(plan, agents, joins);
    for (size_t k = 0; k < agents->count; k++) {
        const struct mvl_agent *a = &agents->rows[k];

        if (trains_dir && strcmp(a->kind, "assemble") == 0)
            mvl_split_assembler(plan, a, trains_dir, joins);
        if (strcmp(a->kind, "design") == 0)
            mvl_split_design(plan, a, joins);
    }
    for (size_t i = 0; anc_count > 0 && i < plan->loop_count; i++)
        if (mvl_evidence_landed(plan->loops[i].evidence, anc, anc_count))
            joins[i].landed = 1;
}

/* ── loops.tsv ────────────────────────────────────────────────────────── */

static const char *mvl_cell(const char *s)
{
    return (s && s[0] != '\0') ? s : "-";
}

bool mvl_write_loops(const char *path, const struct mvl_plan *plan,
                     const struct mvl_join *joins, char *err, size_t err_cap)
{
    FILE *f = fopen(path, "w");

    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot write loops.tsv");
        return false;
    }
    fprintf(f, "id\ttitle\tstate\tlane\tevidence\tagents\ttokens_out\t"
               "tokens_in\ttool_uses\twall_s\tfirst_utc\tlast_utc\t"
               "verifier_rounds\tlanded\n");
    for (size_t i = 0; i < plan->loop_count; i++) {
        const struct mvl_loop *l = &plan->loops[i];
        const struct mvl_join *j = &joins[i];
        char landed[8];

        (void)snprintf(landed, sizeof landed, "%s",
                       j->landed < 0 ? "-" : (j->landed ? "1" : "0"));
        fprintf(f,
                "%s\t%s\t%s\t%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%s\t%s"
                "\t%lld\t%s\n",
                l->id, mvl_cell(l->title), mvl_cell(l->state),
                mvl_cell(l->lane), mvl_cell(l->evidence),
                (long long)j->agents, (long long)j->tokens_out,
                (long long)j->tokens_in, (long long)j->tool_uses,
                (long long)j->wall_s, mvl_cell(j->first_utc),
                mvl_cell(j->last_utc), (long long)j->verifier_rounds, landed);
    }
    if (fclose(f) != 0) {
        mvl_err(err, err_cap, path, 0, "mvl_open: loops.tsv did not close");
        return false;
    }
    return true;
}

/* ── snapshots.tsv ────────────────────────────────────────────────────── */

const char *mvl_snapshots_header(void)
{
    return "utc\tlanded\ttrain\tready\tin_flight\tdesigning\tverify_first\t"
           "queued\tdropped\tverified_pct\ttokens_out\ttokens_in\t"
           "tool_uses\tagent_wall_s\torigin_main\tnote";
}

static void mvl_cost_totals(const struct mvl_agents *agents, int64_t *out)
{
    for (int i = 0; i < 4; i++)
        out[i] = 0;
    for (size_t i = 0; i < agents->count; i++) {
        out[0] += agents->rows[i].tokens_out;
        out[1] += agents->rows[i].tokens_in;
        out[2] += agents->rows[i].tool_uses;
        out[3] += agents->rows[i].last_unix - agents->rows[i].first_unix;
    }
}

bool mvl_append_snapshot(const char *path, const struct mvl_plan *plan,
                         const struct mvl_agents *agents, const char *utc,
                         const char *origin_main, const char *note,
                         char *err, size_t err_cap)
{
    const int64_t *t = plan->totals;
    int64_t all = plan->universe > 0 ? plan->universe : 1;
    int64_t cost[4];
    bool fresh;
    FILE *f;

    if (!mvl_check_header(path, mvl_snapshots_header(), err, err_cap))
        return false;
    fresh = mvl_ledger_is_fresh(path);
    f = fopen(path, "a");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot append the snapshot");
        return false;
    }
    if (fresh)
        fprintf(f, "%s\n", mvl_snapshots_header());
    mvl_cost_totals(agents, cost);
    fprintf(f,
            "%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld"
            "\t%lld\t%lld\t%lld\t%s\t%s\n",
            utc, (long long)t[MVL_STATE_LANDED], (long long)t[MVL_STATE_TRAIN],
            (long long)t[MVL_STATE_READY], (long long)t[MVL_STATE_IN_FLIGHT],
            (long long)t[MVL_STATE_DESIGNING],
            (long long)t[MVL_STATE_VERIFY_FIRST],
            (long long)t[MVL_STATE_QUEUED], (long long)t[MVL_STATE_DROPPED],
            (long long)((100 * (t[MVL_STATE_LANDED] + t[MVL_STATE_TRAIN]))
                        / all),
            (long long)cost[0], (long long)cost[1], (long long)cost[2],
            (long long)cost[3], mvl_cell(origin_main), mvl_cell(note));
    if (fclose(f) != 0) {
        mvl_err(err, err_cap, path, 0,
                "mvl_open: snapshots.tsv did not close");
        return false;
    }
    return true;
}
