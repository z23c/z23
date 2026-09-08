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

bool mvl_read_train_lanes(const char *path, struct mvl_names *lanes,
                          char *err, size_t err_cap)
{
    return mvl_read_first_column(path, lanes->rows[0], MVL_LANE_CAP,
                                 lanes->cap, &lanes->count, err, err_cap);
}

/* Reads `ZCL_TEST_GROUP(<name>)` out of a test_group_catalog.def. Anything
 * else in the file — the licence header, the comments explaining a group —
 * is not a registration and is passed over. */
static bool mvl_group_of_line(const char *line, char *dst, size_t cap)
{
    const char *p = strstr(line, "ZCL_TEST_GROUP(");
    const char *end;
    size_t n;

    if (!p)
        return false;
    p += strlen("ZCL_TEST_GROUP(");
    end = strchr(p, ')');
    if (!end)
        return false;
    n = (size_t)(end - p);
    if (n == 0 || n >= cap)
        return false;
    memcpy(dst, p, n);
    dst[n] = '\0';
    return true;
}

bool mvl_read_groups(const char *path, struct mvl_names *out, char *err,
                     size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_group_line");
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_err(err, err_cap, path, 0,
                "mvl_open: cannot read the test-group catalog");
        free(buf);
        return false;
    }
    while (ok) {
        char group[MVL_LANE_CAP];
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
        if (!mvl_group_of_line(buf, group, sizeof group))
            continue;
        if (mvl_names_add(out, group))
            continue;
        mvl_err(err, err_cap, path, line_no,
                "mvl_overflow: more test groups than MVL_MAX_NAMES");
        ok = false;
    }
    (void)fclose(f);
    free(buf);
    return ok;
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

/* True when the `len` bytes at `sha` are a hex prefix of some ancestry
 * commit. Seven is git's own shortest unambiguous abbreviation; below that
 * a "sha" is a word that happens to be hex. */
static bool mvl_sha_in_ancestry(const char *sha, size_t len,
                                const char (*anc)[MVL_ID_CAP],
                                size_t anc_count)
{
    if (len < 7 || len > MVL_ID_CAP - 1 || !mvl_hex_run(sha, len))
        return false;
    for (size_t i = 0; i < anc_count; i++)
        if (strncmp(anc[i], sha, len) == 0)
            return true;
    return false;
}

/* The `b` of an `a..b` range, or NULL when there is no range separator. */
static const char *mvl_range_tip(const char *evidence)
{
    const char *dots = strstr(evidence, "..");

    return dots ? dots + 2 : NULL;
}

static bool mvl_all_hex_list(const char *evidence)
{
    size_t start = 0;
    size_t i = 0;

    for (;; i++) {
        if (evidence[i] != ',' && evidence[i] != '\0')
            continue;
        if (i - start < 7 || !mvl_hex_run(evidence + start, i - start))
            return false;
        if (evidence[i] == '\0')
            return true;
        start = i + 1;
    }
}

enum mvl_evidence_kind mvl_evidence_kind_of(const char *evidence)
{
    const char *tip;

    if (!evidence || evidence[0] == '\0' || strcmp(evidence, "-") == 0)
        return MVL_EVIDENCE_NONE;
    if (strncmp(evidence, "ONLY=", 5) == 0 && evidence[5] != '\0')
        return MVL_EVIDENCE_SWEEP;
    tip = mvl_range_tip(evidence);
    if (tip)
        return mvl_hex_run(tip, strlen(tip)) && strlen(tip) >= 7
               ? MVL_EVIDENCE_RANGE : MVL_EVIDENCE_OTHER;
    if (mvl_all_hex_list(evidence))
        return MVL_EVIDENCE_COMMIT;
    return MVL_EVIDENCE_OTHER;
}

/* Every sha of a comma list must be an ancestor: the row cites them all as
 * the work, so one of them still in flight means the work is not landed. */
static bool mvl_commit_list_landed(const char *evidence,
                                   const char (*anc)[MVL_ID_CAP],
                                   size_t anc_count)
{
    size_t start = 0;

    for (size_t i = 0;; i++) {
        if (evidence[i] != ',' && evidence[i] != '\0')
            continue;
        if (!mvl_sha_in_ancestry(evidence + start, i - start, anc, anc_count))
            return false;
        if (evidence[i] == '\0')
            return true;
        start = i + 1;
    }
}

bool mvl_evidence_landed(const char *evidence, const char (*anc)[MVL_ID_CAP],
                         size_t anc_count)
{
    enum mvl_evidence_kind kind = mvl_evidence_kind_of(evidence);
    const char *tip;

    if (anc_count == 0)
        return false;
    if (kind == MVL_EVIDENCE_COMMIT)
        return mvl_commit_list_landed(evidence, anc, anc_count);
    if (kind != MVL_EVIDENCE_RANGE)
        return false;
    tip = mvl_range_tip(evidence);
    return mvl_sha_in_ancestry(tip, strlen(tip), anc, anc_count);
}

/* ── what proves a loop ───────────────────────────────────────────────── */

static enum mvl_verified_by mvl_sweep_result(const char *evidence,
                                             const struct mvl_names *groups)
{
    if (!groups)
        return MVL_VERIFIED_SWEEP_NOT_ASKED;
    return mvl_names_has(groups, evidence + 5) ? MVL_VERIFIED_SWEEP
                                               : MVL_VERIFIED_SWEEP_UNREGISTERED;
}

enum mvl_verified_by mvl_loop_verified_by(const struct mvl_loop *loop,
                                          const struct mvl_evidence_world *w)
{
    enum mvl_evidence_kind kind = mvl_evidence_kind_of(loop->evidence);
    enum mvl_verified_by sweep = MVL_VERIFIED_NO;

    if (kind == MVL_EVIDENCE_COMMIT || kind == MVL_EVIDENCE_RANGE) {
        if (mvl_evidence_landed(loop->evidence, w->ancestry,
                                w->ancestry_count))
            return MVL_VERIFIED_LANDED;
    }
    if (kind == MVL_EVIDENCE_SWEEP) {
        sweep = mvl_sweep_result(loop->evidence, w->groups);
        if (sweep == MVL_VERIFIED_SWEEP)
            return MVL_VERIFIED_SWEEP;
    }
    if (mvl_names_has(w->verdict_lanes, loop->lane))
        return MVL_VERIFIED_VERDICT;
    return sweep;
}

bool mvl_is_verified(enum mvl_verified_by by)
{
    return by == MVL_VERIFIED_LANDED || by == MVL_VERIFIED_SWEEP
           || by == MVL_VERIFIED_VERDICT;
}

const char *mvl_verified_by_name(enum mvl_verified_by by)
{
    switch (by) {
    case MVL_VERIFIED_LANDED:
        return "landed";
    case MVL_VERIFIED_SWEEP:
        return "sweep";
    case MVL_VERIFIED_VERDICT:
        return "verdict";
    case MVL_VERIFIED_SWEEP_UNREGISTERED:
        return "sweep_group_unregistered";
    case MVL_VERIFIED_SWEEP_NOT_ASKED:
        return "sweep_not_asked";
    case MVL_VERIFIED_NO:
        break;
    }
    return "-";
}

size_t mvl_report_sweep_refusals(const struct mvl_plan *plan,
                                 const struct mvl_evidence_world *world,
                                 const char *plan_path, FILE *sink)
{
    size_t refused = 0;

    for (size_t i = 0; i < plan->loop_count; i++) {
        const struct mvl_loop *l = &plan->loops[i];

        if (mvl_loop_verified_by(l, world) != MVL_VERIFIED_SWEEP_UNREGISTERED)
            continue;
        refused++;
        fprintf(sink,
                "z23-mvp-ledger: %s:%zu: sweep_group_unregistered: %s cites"
                " %s, which the catalog at the ancestry ref does not"
                " register — %s counts as UNVERIFIED\n",
                plan_path, l->line_no, l->id, l->evidence, l->id);
    }
    return refused;
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

            /* Assemblers and design workflows are attributed ONLY by their
             * split below. Letting them also match a loop by lane name
             * would charge the same agent to the same loop twice, which is
             * exactly what happens when a design row's loop= and evidence=
             * both name the workflow. */
            if (strcmp(a->kind, "design") == 0)
                continue;
            if (strcmp(a->kind, "assemble") == 0)
                continue;
            if (strcmp(a->lane, lane) != 0)
                continue;
            mvl_add_share(&joins[i], a, 1);
            mvl_widen(&joins[i], a);
            if (strcmp(a->kind, "verify") == 0)
                joins[i].verifier_rounds++;
        }
    }
}

static void mvl_split_assembler(const struct mvl_plan *plan,
                                const struct mvl_agent *a,
                                const char *trains_dir,
                                struct mvl_join *joins)
{
    struct mvl_names lanes = {0};
    char path[MVL_PATH_CAP];
    char err[MVL_ERR_CAP];
    int64_t members = 0;

    if (!mvl_names_alloc(&lanes, MVL_MAX_TRAIN_LANES))
        return;
    if (!mvl_path_of(path, sizeof path, trains_dir, "/", a->lane,
                     "/late_picks.txt")) {
        mvl_names_free(&lanes);
        return;
    }
    if (mvl_read_train_lanes(path, &lanes, err, sizeof err)) {
        for (size_t i = 0; i < plan->loop_count; i++)
            if (mvl_names_has(&lanes, plan->loops[i].lane))
                members++;
        for (size_t i = 0; members > 0 && i < plan->loop_count; i++)
            if (mvl_names_has(&lanes, plan->loops[i].lane))
                mvl_add_share(&joins[i], a, members);
    }
    mvl_names_free(&lanes);
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
                    const struct mvl_evidence_world *world,
                    struct mvl_join *joins)
{
    for (size_t i = 0; i < plan->loop_count; i++) {
        memset(&joins[i], 0, sizeof joins[i]);
        joins[i].landed = world->ancestry_count > 0 ? 0 : -1;
    }
    mvl_join_direct(plan, agents, joins);
    for (size_t k = 0; k < agents->count; k++) {
        const struct mvl_agent *a = &agents->rows[k];

        if (trains_dir && strcmp(a->kind, "assemble") == 0)
            mvl_split_assembler(plan, a, trains_dir, joins);
        if (strcmp(a->kind, "design") == 0)
            mvl_split_design(plan, a, joins);
    }
    for (size_t i = 0; i < plan->loop_count; i++) {
        joins[i].verified_by = mvl_loop_verified_by(&plan->loops[i], world);
        if (joins[i].verified_by == MVL_VERIFIED_LANDED)
            joins[i].landed = 1;
    }
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
               "verifier_rounds\tlanded\tverified_by\n");
    for (size_t i = 0; i < plan->loop_count; i++) {
        const struct mvl_loop *l = &plan->loops[i];
        const struct mvl_join *j = &joins[i];
        char landed[8];

        (void)snprintf(landed, sizeof landed, "%s",
                       j->landed < 0 ? "-" : (j->landed ? "1" : "0"));
        fprintf(f,
                "%s\t%s\t%s\t%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%s\t%s"
                "\t%lld\t%s\t%s\n",
                l->id, mvl_cell(l->title), mvl_cell(l->state),
                mvl_cell(l->lane), mvl_cell(l->evidence),
                (long long)j->agents, (long long)j->tokens_out,
                (long long)j->tokens_in, (long long)j->tool_uses,
                (long long)j->wall_s, mvl_cell(j->first_utc),
                mvl_cell(j->last_utc), (long long)j->verifier_rounds, landed,
                mvl_verified_by_name(j->verified_by));
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
