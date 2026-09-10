/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — the KPI the owner asked
 *          for on 2026-09-08: VERIFIED MVP PROGRESS PER TOKEN. Numerator:
 *          base plan loops whose verifier wrote LAND at or after t0.
 *          Denominator: every measured agent in the window, in three token
 *          views, of which TCU is primary. This file also carries the XP
 *          game the same KPI is scored as (mode `xp`): the dev.land outcome
 *          reader, the milestone multiplier read from the plan's own
 *          titles, and the scoring rules. See tools/dev/mvp_ledger.h. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "json/json.h"
#include "mvp_ledger_internal.h"
#include "platform/directory_compat.h"

/* ── which lanes a verifier landed after t0 ───────────────────────────── */

/* `vfaillocator4` names lane `faillocator`: drop the leading v, then the
 * round number a re-verification appends. */
static bool mvl_lane_of_verdict_dir(const char *dir, char *lane, size_t cap)
{
    size_t n;

    if (dir[0] != 'v' || dir[1] == '\0')
        return false;
    mvl_copy(lane, cap, dir + 1);
    n = strlen(lane);
    while (n > 0 && lane[n - 1] >= '0' && lane[n - 1] <= '9')
        lane[--n] = '\0';
    return n > 0;
}

/* The VERDICT's own modified time, from the one directory listing that also
 * proves the file is a real regular file. Returns false when the directory
 * holds no VERDICT with a valid metadata snapshot. */
static bool mvl_verdict_mtime(const char *dir, int64_t *mtime_out)
{
    struct platform_directory_list files = {0};
    bool found = false;

    if (!platform_directory_list_regular_sorted(dir, &files))
        return false;
    for (size_t i = 0; i < files.count; i++) {
        if (strcmp(files.entries[i].name, "VERDICT") != 0)
            continue;
        if (!files.entries[i].snapshot_valid)
            break;
        *mtime_out = files.entries[i].modified_seconds;
        found = true;
        break;
    }
    platform_directory_list_free(&files);
    return found;
}

static bool mvl_verdict_is_land(const char *dir, char *err, size_t err_cap)
{
    char path[MVL_PATH_CAP];
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_verdict_line");
    FILE *f;
    bool land = false;

    if (!buf) {
        mvl_err(err, err_cap, dir, 0, "mvl_overflow: no line buffer");
        return false;
    }
    if (!mvl_path_of(path, sizeof path, dir, "/VERDICT", "", "")) {
        mvl_err(err, err_cap, dir, 0,
                "mvl_overflow: VERDICT path longer than MVL_PATH_CAP");
        free(buf);
        return false;
    }
    f = fopen(path, "r");
    if (f) {
        if (mvl_read_line(f, buf, MVL_LINE_CAP + 2) == 1)
            land = strncmp(buf, "LAND", 4) == 0;
        (void)fclose(f);
    }
    free(buf);
    return land;
}

bool mvl_verified_lanes(const char *scratch_dir, int64_t t0_unix,
                        struct mvl_names *lanes, char *err, size_t err_cap)
{
    struct platform_directory_list dirs = {0};
    bool ok = true;

    if (!platform_directory_list_real_sorted(scratch_dir, &dirs)) {
        mvl_err(err, err_cap, scratch_dir, 0,
                "mvl_open: cannot list the scratch directory");
        return false;
    }
    for (size_t i = 0; ok && i < dirs.count; i++) {
        char lane[MVL_LANE_CAP];
        char path[MVL_PATH_CAP];
        int64_t mtime = 0;

        if (!mvl_lane_of_verdict_dir(dirs.entries[i].name, lane, sizeof lane))
            continue;
        if (!mvl_path_of(path, sizeof path, scratch_dir, "/",
                         dirs.entries[i].name, ""))
            continue;
        if (!mvl_verdict_mtime(path, &mtime) || mtime < t0_unix)
            continue;
        if (!mvl_verdict_is_land(path, err, err_cap))
            continue;
        if (mvl_names_add(lanes, lane))
            continue;
        mvl_err(err, err_cap, scratch_dir, lanes->count,
                "mvl_overflow: more verified lanes than the table holds");
        ok = false;
    }
    platform_directory_list_free(&dirs);
    return ok;
}

/* ── the KPI itself ───────────────────────────────────────────────────── */

static void mvl_kpi_numerator(const struct mvl_plan *plan,
                              const struct mvl_evidence_world *world,
                              struct mvl_kpi *out)
{
    for (size_t i = 0; i < plan->loop_count; i++) {
        const struct mvl_loop *l = &plan->loops[i];
        enum mvl_verified_by by = mvl_loop_verified_by(l, world);

        if (!l->counted) {
            out->verified_subrows += mvl_is_verified(by) ? 1 : 0;
            continue;
        }
        if (mvl_is_verified(by))
            out->verified_loops++;
        if (by == MVL_VERIFIED_LANDED)
            out->landed_loops++;
        if (by == MVL_VERIFIED_SWEEP)
            out->sweep_loops++;
        if (by == MVL_VERIFIED_SWEEP_UNREGISTERED)
            out->sweep_unregistered++;
    }
}

static void mvl_kpi_denominator(const struct mvl_agents *agents,
                                struct mvl_kpi *out)
{
    int64_t tcu_hundredths = 0;

    for (size_t i = 0; i < agents->count; i++) {
        const struct mvl_agent *a = &agents->rows[i];

        out->tokens_out += a->tokens_out;
        out->tokens_raw += a->tokens_out + a->tokens_in;
        tcu_hundredths += a->tokens_out * MVL_TCU_OUT;
        tcu_hundredths += a->tokens_input * MVL_TCU_INPUT;
        tcu_hundredths += a->tokens_cache_creation * MVL_TCU_CACHE_CREATION;
        tcu_hundredths += a->tokens_cache_read * MVL_TCU_CACHE_READ;
    }
    out->tcu = tcu_hundredths / MVL_TCU_SCALE;
}

void mvl_compute_kpi(const struct mvl_plan *plan,
                     const struct mvl_agents *agents,
                     const struct mvl_evidence_world *world,
                     struct mvl_kpi *out)
{
    memset(out, 0, sizeof *out);
    mvl_kpi_numerator(plan, world, out);
    mvl_kpi_denominator(agents, out);
}

/* Verified loops per million TCU, in thousandths — the ratio is carried as
 * an integer so the KPI never moves with the host's floating point. */
static int64_t mvl_loops_per_mtcu_milli(const struct mvl_kpi *kpi)
{
    if (kpi->tcu <= 0)
        return 0;
    return (kpi->verified_loops * 1000000000LL) / kpi->tcu;
}

static int64_t mvl_tcu_per_loop(const struct mvl_kpi *kpi)
{
    if (kpi->verified_loops <= 0)
        return 0;
    return kpi->tcu / kpi->verified_loops;
}

const char *mvl_kpi_header(void)
{
    return "utc\twindow\tverified_loops\tverified_subrows\tlanded_loops\t"
           "sweep_loops\tsweep_unregistered\ttokens_raw\ttokens_out\ttcu\t"
           "loops_per_mtcu\ttcu_per_loop\tnote";
}

static const char *mvl_kpi_cell(const char *s)
{
    return (s && s[0] != '\0') ? s : "-";
}

bool mvl_append_kpi(const char *path, const struct mvl_kpi *kpi,
                    const char *utc, const char *window, const char *note,
                    char *err, size_t err_cap)
{
    int64_t milli = mvl_loops_per_mtcu_milli(kpi);
    bool fresh;
    FILE *f;

    if (!mvl_check_header(path, mvl_kpi_header(), err, err_cap))
        return false;
    fresh = mvl_ledger_is_fresh(path);
    f = fopen(path, "a");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot append the KPI row");
        return false;
    }
    if (fresh)
        fprintf(f, "%s\n", mvl_kpi_header());
    fprintf(f, "%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld"
               "\t%lld.%03lld\t%lld\t%s\n",
            utc, mvl_kpi_cell(window), (long long)kpi->verified_loops,
            (long long)kpi->verified_subrows, (long long)kpi->landed_loops,
            (long long)kpi->sweep_loops, (long long)kpi->sweep_unregistered,
            (long long)kpi->tokens_raw, (long long)kpi->tokens_out,
            (long long)kpi->tcu, (long long)(milli / 1000),
            (long long)(milli % 1000), (long long)mvl_tcu_per_loop(kpi),
            mvl_kpi_cell(note));
    if (fclose(f) != 0) {
        mvl_err(err, err_cap, path, 0, "mvl_open: kpi.tsv did not close");
        return false;
    }
    return true;
}

size_t mvl_render_kpi(const struct mvl_kpi *kpi, char *out, size_t out_cap)
{
    int64_t milli = mvl_loops_per_mtcu_milli(kpi);
    int n = snprintf(out, out_cap,
                     "kpi: %lld verified loops (%lld landed, %lld sweep,"
                     " +%lld sub-rows) for %lld TCU = %lld.%03lld"
                     " loops/MTCU, %lld TCU/loop\n",
                     (long long)kpi->verified_loops,
                     (long long)kpi->landed_loops,
                     (long long)kpi->sweep_loops,
                     (long long)kpi->verified_subrows, (long long)kpi->tcu,
                     (long long)(milli / 1000), (long long)(milli % 1000),
                     (long long)mvl_tcu_per_loop(kpi));

    return n > 0 ? (size_t)n : 0;
}

/* ── the XP game: dev.land outcome rows ───────────────────────────────── */

static const char *mvl_json_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;

    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static int64_t mvl_json_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;

    return (v && v->type == JSON_INT) ? json_get_int(v) : 0;
}

/* True when `name` — the last element of `worktree` — sits directly under a
 * `trains` directory, which is how a train assembler's worktree is laid
 * out. `name` points PAST the separator, so the eight bytes before it are
 * the "/trains/" this looks for. */
static bool mvl_worktree_is_train(const char *worktree, const char *name)
{
    static const char k_trains[] = "/trains/";
    size_t n = sizeof k_trains - 1;

    return (size_t)(name - worktree) >= n
           && strncmp(name - n, k_trains, n) == 0;
}

/* The lane a worktree path names: its last element — except under
 * `.z23/trains/<n>`, where the lane is `train<n>`, because that is the name
 * `Assemble train <n>` gives the same worker everywhere else in this
 * ledger. One outcome row must join the rest without a second identity.
 * That directory holds both shapes (`trains/53` and `trains/train53`), so a
 * name that already begins with `train` is left exactly as it is. */
static void mvl_agent_of_worktree(const char *worktree, char *dst, size_t cap)
{
    const char *slash;

    mvl_copy(dst, cap, "-");
    if (!worktree || worktree[0] == '\0')
        return;
    slash = strrchr(worktree, '/');
    if (!slash) {
        mvl_copy(dst, cap, worktree);
        return;
    }
    if (slash[1] == '\0')
        return;
    if (mvl_worktree_is_train(worktree, slash + 1)
        && strncmp(slash + 1, "train", 5) != 0)
        (void)snprintf(dst, cap, "train%s", slash + 1);
    else
        mvl_copy(dst, cap, slash + 1);
}

/* Reads one outcome line. A line that is not one JSON object, or carries no
 * string "state", is refused BY LINE NUMBER: the row is skipped and named,
 * never silently dropped. */
static bool mvl_outcome_of_line(const char *line, size_t line_no,
                                struct mvl_outcome *o, const char **why)
{
    struct json_value root;
    const char *state;
    bool ok = false;

    json_init(&root);
    *why = "mvl_bad_json: line is not one JSON object";
    if (json_read(&root, line, strlen(line)) && root.type == JSON_OBJ) {
        state = mvl_json_str(&root, "state");
        *why = "mvl_plan_field: outcome row has no string \"state\"";
        if (state) {
            memset(o, 0, sizeof *o);
            mvl_copy(o->state, sizeof o->state, state);
            mvl_copy(o->utc, sizeof o->utc, mvl_json_str(&root, "ts"));
            mvl_copy(o->detail, sizeof o->detail,
                     mvl_json_str(&root, "detail"));
            mvl_agent_of_worktree(mvl_json_str(&root, "worktree"), o->agent,
                                  sizeof o->agent);
            o->seq = mvl_json_int(&root, "seq");
            o->line_no = line_no;
            ok = true;
        }
    }
    json_free(&root);
    return ok;
}

static void mvl_report_gap(FILE *refusals, const char *path, size_t line_no,
                           const char *why)
{
    if (refusals)
        fprintf(refusals, "z23-mvp-ledger: %s:%zu: %s\n", path, line_no, why);
}

bool mvl_read_outcomes(const char *path, struct mvl_outcomes *out,
                       FILE *refusals, char *err, size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_outcome_line");
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_report_gap(refusals, path, 0,
                       "mvl_open: no dev.land outcome ledger here — no"
                       " penalty and no combo is scored from it");
        free(buf);
        return true;
    }
    out->present = true;
    while (ok) {
        int rc = mvl_read_line(f, buf, MVL_LINE_CAP + 2);
        const char *why = NULL;

        if (rc == 0)
            break;
        line_no++;
        if (rc < 0) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_line_too_long: line exceeds MVL_LINE_CAP bytes");
            ok = false;
            break;
        }
        if (buf[0] == '\0')
            continue;
        if (out->count >= out->cap) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_overflow: more outcome rows than MVL_MAX_OUTCOMES");
            ok = false;
            break;
        }
        if (mvl_outcome_of_line(buf, line_no, &out->rows[out->count], &why))
            out->count++;
        else
            mvl_report_gap(refusals, path, line_no, why);
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

/* ── the XP game: the multiplier a milestone's title earns ────────────── */

/* The P0 words: consensus, custody and the money, the node and its state.
 * A milestone whose title names one of these is the work the project is
 * FOR, so its loops pay three times. `reaches tip` is spelled out because
 * the bare word tip is a substring of ordinary English. */
static const char *const k_xp_p0_words[] = {
    "consensus", "wallet", "custody", "payment", "shielded",
    "node", "sync", "store", "reaches tip",
};

/* The next tier: the machinery correctness depends on — the proof, the
 * publication, the receipt, the candidate lifecycle. */
static const char *const k_xp_p1_words[] = {
    "proof", "publication", "receipt", "evidence", "lifecycle", "candidate",
};

static char mvl_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive substring: the plan writes titles in sentence case and a
 * multiplier must not turn on a capital letter. */
static bool mvl_title_names(const char *title, const char *word)
{
    for (size_t i = 0; title[i] != '\0'; i++) {
        size_t k = 0;

        while (word[k] != '\0' && mvl_lower(title[i + k]) == word[k])
            k++;
        if (word[k] == '\0')
            return true;
    }
    return false;
}

static bool mvl_title_names_any(const char *title, const char *const *words,
                                size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (mvl_title_names(title, words[i]))
            return true;
    return false;
}

int mvl_milestone_multiplier(const char *title)
{
    if (!title)
        return MVL_XP_MULT_P2;
    if (mvl_title_names_any(title, k_xp_p0_words,
                            sizeof k_xp_p0_words / sizeof k_xp_p0_words[0]))
        return MVL_XP_MULT_P0;
    if (mvl_title_names_any(title, k_xp_p1_words,
                            sizeof k_xp_p1_words / sizeof k_xp_p1_words[0]))
        return MVL_XP_MULT_P1;
    return MVL_XP_MULT_P2;
}

/* ── the XP game: the board ───────────────────────────────────────────── */

/* Everything one payment needs, so the scoring rules below read as the
 * rules and not as parameter plumbing. */
struct mvl_xp_ctx {
    const struct mvl_plan *plan;
    const struct mvl_evidence_world *world;
    struct mvl_xp_board *board;
    struct mvl_xp_events *events;
    const struct mvl_join *joins;
};

static struct mvl_xp_agent *mvl_xp_row(struct mvl_xp_board *board,
                                       const char *agent)
{
    struct mvl_xp_agent *row;

    for (size_t i = 0; i < board->count; i++)
        if (strcmp(board->rows[i].agent, agent) == 0)
            return &board->rows[i];
    if (board->count >= board->cap)
        return NULL;
    row = &board->rows[board->count++];
    memset(row, 0, sizeof *row);
    mvl_copy(row->agent, sizeof row->agent, agent);
    return row;
}

const struct mvl_xp_agent *mvl_xp_find(const struct mvl_xp_board *board,
                                       const char *agent)
{
    for (size_t i = 0; i < board->count; i++)
        if (strcmp(board->rows[i].agent, agent) == 0)
            return &board->rows[i];
    return NULL;
}

/* One payment: the agent's total moves and the event that explains it is
 * appended. A payment that cannot be written as an event is refused rather
 * than credited, because an XP nobody can trace back is not evidence. */
static bool mvl_xp_pay(struct mvl_xp_ctx *c, const char *agent,
                       enum mvl_xp_kind kind, const char *subject,
                       const char *evidence, int64_t xp, int mult,
                       bool provisional)
{
    struct mvl_xp_agent *row = mvl_xp_row(c->board, agent);
    struct mvl_xp_event *e;

    if (!row || c->events->count >= c->events->cap)
        return false;
    e = &c->events->rows[c->events->count++];
    memset(e, 0, sizeof *e);
    mvl_copy(e->agent, sizeof e->agent, agent);
    mvl_copy(e->subject, sizeof e->subject, subject);
    mvl_copy(e->evidence, sizeof e->evidence, evidence);
    e->xp = xp;
    e->multiplier = mult;
    e->kind = kind;
    e->provisional = provisional;
    row->xp += xp;
    return true;
}

static bool mvl_xp_is_paid_lane(const char *lane)
{
    return lane[0] != '\0' && strcmp(lane, "-") != 0;
}

/* A loop is paid only when the EVIDENCE proves it: a commit reachable from
 * origin/main, or a registered sweep group. A verifier's verdict counts
 * toward the KPI but not toward XP — a stranger cannot recheck it from the
 * two files this tool was given. */
static bool mvl_xp_loop_pays(const struct mvl_xp_ctx *c,
                             const struct mvl_loop *l)
{
    enum mvl_verified_by by;

    if (!l->counted || strcmp(l->state, "LANDED") != 0)
        return false;
    if (!mvl_xp_is_paid_lane(l->lane))
        return false;
    by = mvl_loop_verified_by(l, c->world);
    return by == MVL_VERIFIED_LANDED || by == MVL_VERIFIED_SWEEP;
}

static int64_t mvl_xp_pct(int64_t base, int64_t pct)
{
    return base * pct / MVL_XP_PCT;
}

static bool mvl_xp_pay_review(struct mvl_xp_ctx *c, const struct mvl_loop *l,
                              int64_t base, int mult)
{
    char note[MVL_EVIDENCE_CAP];

    (void)snprintf(note, sizeof note, "INDEPENDENT REVIEW by %s (plan line"
                   " %zu)", l->reviewer, l->line_no);
    return mvl_xp_pay(c, l->reviewer, MVL_XP_KIND_REVIEW, l->id, note,
                      mvl_xp_pct(base, MVL_XP_REVIEW_PCT), mult, false);
}

static bool mvl_xp_pay_speed(struct mvl_xp_ctx *c, const struct mvl_loop *l,
                             int64_t wall_s, int64_t base, int mult)
{
    char why[MVL_EVIDENCE_CAP];

    (void)snprintf(why, sizeof why, "wall_s=%lld < median %lld",
                   (long long)wall_s, (long long)c->board->median_wall_s);
    return mvl_xp_pay(c, l->lane, MVL_XP_KIND_SPEED, l->id, why,
                      mvl_xp_pct(base, MVL_XP_SPEED_PCT), mult, false);
}

static bool mvl_xp_score_loop(struct mvl_xp_ctx *c, size_t i)
{
    const struct mvl_loop *l = &c->plan->loops[i];
    struct mvl_xp_agent *row;
    int64_t base, wall_s;
    int mult;
    bool reviewed;

    if (!mvl_xp_loop_pays(c, l))
        return true;
    mult = c->board->multipliers[l->milestone];
    base = (int64_t)MVL_XP_LOOP * mult;
    reviewed = l->reviewer[0] != '\0';
    if (!mvl_xp_pay(c, l->lane, MVL_XP_KIND_LOOP, l->id, l->evidence,
                    reviewed ? base : mvl_xp_pct(base, MVL_XP_PROVISIONAL_PCT),
                    mult, !reviewed))
        return false;
    row = mvl_xp_row(c->board, l->lane);
    row->loops++;
    row->reviewed += reviewed ? 1 : 0;
    if (reviewed && !mvl_xp_pay_review(c, l, base, mult))
        return false;
    wall_s = c->joins ? c->joins[i].wall_s : 0;
    if (!c->board->speed_asked || wall_s <= 0
        || wall_s >= c->board->median_wall_s)
        return true;
    return mvl_xp_pay_speed(c, l, wall_s, base, mult);
}

/* ── the XP game: the median close time ───────────────────────────────── */

static int mvl_int64_cmp(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a;
    int64_t y = *(const int64_t *)b;

    return x < y ? -1 : (x > y ? 1 : 0);
}

/* The median wall clock of the loops XP pays for. Without an agents.tsv no
 * loop carries a clock at all, and then the speed bonus is NOT ASKED rather
 * than answered no — a bonus invented from a missing measurement would be
 * exactly the hand-set score this game refuses. */
static void mvl_xp_median(struct mvl_xp_ctx *c, int64_t *scratch)
{
    size_t n = 0;

    c->board->speed_asked = false;
    c->board->median_wall_s = 0;
    if (!c->joins)
        return;
    for (size_t i = 0; i < c->plan->loop_count; i++)
        if (mvl_xp_loop_pays(c, &c->plan->loops[i]) && c->joins[i].wall_s > 0)
            scratch[n++] = c->joins[i].wall_s;
    if (n == 0)
        return;
    qsort(scratch, n, sizeof *scratch, mvl_int64_cmp);
    c->board->median_wall_s = scratch[n / 2];
    c->board->speed_asked = true;
}

/* ── the XP game: a parent's own acceptance ───────────────────────────── */

static int mvl_xp_group_of(const struct mvl_loop *l, bool by_feature)
{
    return by_feature ? l->feature : l->milestone;
}

/* True when loop `at` is the first of its group to name its lane, so a
 * parent's pot is split once per distinct author, not once per loop. */
static bool mvl_xp_lane_first(const struct mvl_plan *p, size_t at, int group,
                              bool by_feature)
{
    for (size_t i = 0; i < at; i++) {
        const struct mvl_loop *l = &p->loops[i];

        if (!l->counted || mvl_xp_group_of(l, by_feature) != group)
            continue;
        if (strcmp(l->lane, p->loops[at].lane) == 0)
            return false;
    }
    return true;
}

struct mvl_xp_group {
    int64_t loops;
    int64_t paid;
    int64_t lanes;
};

static void mvl_xp_scan_group(struct mvl_xp_ctx *c, int group,
                              bool by_feature, struct mvl_xp_group *out)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < c->plan->loop_count; i++) {
        const struct mvl_loop *l = &c->plan->loops[i];

        if (!l->counted || mvl_xp_group_of(l, by_feature) != group)
            continue;
        out->loops++;
        if (!mvl_xp_loop_pays(c, l))
            continue;
        out->paid++;
        if (mvl_xp_lane_first(c->plan, i, group, by_feature))
            out->lanes++;
    }
}

/* Pays a parent's pot, split evenly over the distinct authors under it.
 * Called ONLY when the parent's own line says ACCEPTED and every child loop
 * is proved: child completion alone never closes a parent. */
static bool mvl_xp_pay_group(struct mvl_xp_ctx *c, int group, bool by_feature,
                             int64_t pot, const char *subject,
                             const char *evidence)
{
    struct mvl_xp_group scan;
    int mult = 0;

    mvl_xp_scan_group(c, group, by_feature, &scan);
    if (scan.loops == 0 || scan.paid != scan.loops || scan.lanes == 0)
        return true;
    for (size_t i = 0; i < c->plan->loop_count; i++) {
        const struct mvl_loop *l = &c->plan->loops[i];

        if (!l->counted || mvl_xp_group_of(l, by_feature) != group)
            continue;
        mult = c->board->multipliers[l->milestone];
        if (!mvl_xp_lane_first(c->plan, i, group, by_feature))
            continue;
        if (!mvl_xp_pay(c, l->lane,
                        by_feature ? MVL_XP_KIND_FEATURE
                                   : MVL_XP_KIND_MILESTONE,
                        subject, evidence, pot * mult / scan.lanes, mult,
                        false))
            return false;
    }
    return true;
}

static bool mvl_xp_score_parents(struct mvl_xp_ctx *c)
{
    char subject[MVL_ID_TEXT_CAP];

    for (size_t i = 0; i < c->plan->feature_count; i++) {
        const struct mvl_feature *f = &c->plan->features[i];

        if (!f->accepted)
            continue;
        (void)snprintf(subject, sizeof subject, "%s.%s",
                       c->plan->milestones[f->milestone].id, f->id);
        if (!mvl_xp_pay_group(c, (int)i, true, MVL_XP_FEATURE, subject,
                              "the feature line carries state=ACCEPTED"))
            return false;
    }
    for (size_t i = 0; i < c->plan->milestone_count; i++) {
        const struct mvl_milestone *m = &c->plan->milestones[i];

        if (!m->accepted)
            continue;
        if (!mvl_xp_pay_group(c, (int)i, false, MVL_XP_MILESTONE, m->id,
                              "the milestone line carries state=ACCEPTED"))
            return false;
    }
    return true;
}

/* ── the XP game: what the dev.land ledger costs and pays ─────────────── */

/* A landing that failed because origin/main moved under it is not a mistake
 * anyone made, so it is exempt. Every other failure costs. */
static bool mvl_xp_base_moved(const char *detail)
{
    return strstr(detail, "head_changed") != NULL
           || strstr(detail, "origin/main moved") != NULL;
}

static int mvl_xp_outcome_cmp(const void *a, const void *b)
{
    const struct mvl_outcome *const *x = a;
    const struct mvl_outcome *const *y = b;
    int c = strcmp((*x)->utc, (*y)->utc);

    if (c != 0)
        return c;
    return (*x)->line_no < (*y)->line_no ? -1
                                         : ((*x)->line_no > (*y)->line_no);
}

static bool mvl_xp_penalty(struct mvl_xp_ctx *c, const struct mvl_outcome *o)
{
    char subject[MVL_ID_TEXT_CAP];

    if (mvl_xp_base_moved(o->detail))
        return true;
    (void)snprintf(subject, sizeof subject, "outcome %lld", (long long)o->seq);
    return mvl_xp_pay(c, o->agent, MVL_XP_KIND_PENALTY, subject, o->detail,
                      -(int64_t)MVL_XP_FAIL_PENALTY, 1, false);
}

static bool mvl_xp_combo(struct mvl_xp_ctx *c, const struct mvl_outcome *o)
{
    char subject[MVL_ID_TEXT_CAP];
    char why[MVL_EVIDENCE_CAP];

    (void)snprintf(subject, sizeof subject, "outcome %lld", (long long)o->seq);
    (void)snprintf(why, sizeof why,
                   "%d landings in a row, none failed between, through %s",
                   MVL_XP_COMBO_RUN, o->utc[0] != '\0' ? o->utc : "-");
    return mvl_xp_pay(c, o->agent, MVL_XP_KIND_COMBO, subject, why,
                      MVL_XP_COMBO, 1, false);
}

/* Folds the outcome ledger in timestamp order: a failure costs and breaks
 * the streak, a landing extends it, and a cancelled row does neither. */
static bool mvl_xp_fold_outcomes(struct mvl_xp_ctx *c,
                                 const struct mvl_outcomes *outcomes,
                                 const struct mvl_outcome **order,
                                 int64_t *streak)
{
    for (size_t i = 0; i < outcomes->count; i++)
        order[i] = &outcomes->rows[i];
    qsort(order, outcomes->count, sizeof *order, mvl_xp_outcome_cmp);
    for (size_t i = 0; i < outcomes->count; i++) {
        const struct mvl_outcome *o = order[i];
        struct mvl_xp_agent *row = mvl_xp_row(c->board, o->agent);
        size_t at;

        if (!row)
            return false;
        at = (size_t)(row - c->board->rows);
        if (strcmp(o->state, "failed") == 0) {
            streak[at] = 0;
            if (!mvl_xp_penalty(c, o))
                return false;
        } else if (strcmp(o->state, "landed") == 0) {
            streak[at]++;
            if (streak[at] < MVL_XP_COMBO_RUN)
                continue;
            streak[at] = 0;
            if (!mvl_xp_combo(c, o))
                return false;
        }
    }
    return true;
}

/* ── the XP game: the token-efficiency league ─────────────────────────── */

static int64_t mvl_agent_tcu(const struct mvl_agent *a)
{
    int64_t hundredths = a->tokens_out * MVL_TCU_OUT
                         + a->tokens_input * MVL_TCU_INPUT
                         + a->tokens_cache_creation * MVL_TCU_CACHE_CREATION
                         + a->tokens_cache_read * MVL_TCU_CACHE_READ;

    return hundredths / MVL_TCU_SCALE;
}

/* Every measured agent's spend lands on its lane, including a lane that
 * earned nothing: an agent that spent tokens for no verified progress is
 * exactly what this KPI exists to show. */
static bool mvl_xp_fold_tcu(struct mvl_xp_board *board,
                            const struct mvl_agents *agents)
{
    for (size_t i = 0; i < agents->count; i++) {
        const struct mvl_agent *a = &agents->rows[i];
        struct mvl_xp_agent *row;

        if (!mvl_xp_is_paid_lane(a->lane))
            continue;
        row = mvl_xp_row(board, a->lane);
        if (!row)
            return false;
        row->tcu += mvl_agent_tcu(a);
    }
    return true;
}

int64_t mvl_xp_per_mtcu_milli(const struct mvl_xp_agent *agent)
{
    if (!agent || agent->tcu <= 0)
        return 0;
    return (agent->xp * 1000000000LL) / agent->tcu;
}

/* Ranked agents first, then the best ratio, then the higher XP, then the
 * name. An agent with no measured tokens is UNRANKED rather than last: a
 * ratio with a zero denominator is not a worse ratio. */
static int mvl_xp_rank_cmp(const void *a, const void *b)
{
    const struct mvl_xp_agent *x = a;
    const struct mvl_xp_agent *y = b;
    int64_t rx, ry;

    if ((x->tcu > 0) != (y->tcu > 0))
        return x->tcu > 0 ? -1 : 1;
    rx = mvl_xp_per_mtcu_milli(x);
    ry = mvl_xp_per_mtcu_milli(y);
    if (rx != ry)
        return rx > ry ? -1 : 1;
    if (x->xp != y->xp)
        return x->xp > y->xp ? -1 : 1;
    return strcmp(x->agent, y->agent);
}

void mvl_xp_rank(struct mvl_xp_board *board)
{
    int rank = 0;

    qsort(board->rows, board->count, sizeof *board->rows, mvl_xp_rank_cmp);
    for (size_t i = 0; i < board->count; i++)
        board->rows[i].rank = board->rows[i].tcu > 0 ? ++rank : 0;
}

/* ── the XP game: one scored board ────────────────────────────────────── */

struct mvl_xp_scratch {
    struct mvl_join *joins;
    int64_t *walls;
    const struct mvl_outcome **order;
    int64_t *streak;
};

static bool mvl_xp_scratch_alloc(struct mvl_xp_scratch *s,
                                 const struct mvl_outcomes *outcomes,
                                 size_t agent_cap)
{
    size_t n = outcomes->count > 0 ? outcomes->count : 1;

    memset(s, 0, sizeof *s);
    s->joins = zcl_calloc(MVL_MAX_LOOPS, sizeof *s->joins, "mvl_xp_joins");
    s->walls = zcl_calloc(MVL_MAX_LOOPS, sizeof *s->walls, "mvl_xp_walls");
    s->order = zcl_calloc(n, sizeof *s->order, "mvl_xp_order");
    s->streak = zcl_calloc(agent_cap, sizeof *s->streak, "mvl_xp_streak");
    return s->joins && s->walls && s->order && s->streak;
}

static void mvl_xp_scratch_free(struct mvl_xp_scratch *s)
{
    free(s->joins);
    free(s->walls);
    free((void *)s->order);
    free(s->streak);
    memset(s, 0, sizeof *s);
}

static void mvl_xp_multipliers(const struct mvl_plan *plan,
                               struct mvl_xp_board *board)
{
    for (size_t i = 0; i < plan->milestone_count; i++)
        board->multipliers[i] =
            mvl_milestone_multiplier(plan->milestones[i].title);
}

bool mvl_compute_xp(const struct mvl_plan *plan,
                    const struct mvl_agents *agents,
                    const struct mvl_evidence_world *world,
                    const struct mvl_outcomes *outcomes,
                    struct mvl_xp_board *board, struct mvl_xp_events *events,
                    char *err, size_t err_cap)
{
    struct mvl_xp_scratch s;
    struct mvl_xp_ctx c = {plan, world, board, events, NULL};
    bool ok = true;

    board->count = 0;
    events->count = 0;
    board->main_red_asked = false;
    board->outcomes_present = outcomes->present;
    if (!mvl_xp_scratch_alloc(&s, outcomes, board->cap)) {
        mvl_err(err, err_cap, "-", 0, "mvl_overflow: no XP scratch tables");
        mvl_xp_scratch_free(&s);
        return false;
    }
    mvl_xp_multipliers(plan, board);
    mvl_join_loops(plan, agents, NULL, world, s.joins);
    c.joins = s.joins;
    mvl_xp_median(&c, s.walls);
    for (size_t i = 0; ok && i < plan->loop_count; i++)
        ok = mvl_xp_score_loop(&c, i);
    ok = ok && mvl_xp_score_parents(&c);
    ok = ok && mvl_xp_fold_outcomes(&c, outcomes, s.order, s.streak);
    ok = ok && mvl_xp_fold_tcu(board, agents);
    if (!ok)
        mvl_err(err, err_cap, "-", 0,
                "mvl_overflow: more XP rows than the bounded tables hold");
    mvl_xp_rank(board);
    mvl_xp_scratch_free(&s);
    return ok;
}
