/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — the plan of record: parse
 *          the milestone/feature/loop grammar and render the progress bars.
 *          The render is byte-for-byte the stopgap
 *          scratch/northstar/progress.sh it replaces. See
 *          tools/dev/mvp_ledger.h for the contract. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "mvp_ledger_internal.h"

/* Painted left to right in enum order; MVL_STATE_OTHER paints nothing. */
static const char *const k_state_names[MVL_STATE_COUNT] = {
    "LANDED", "TRAIN", "READY", "IN-FLIGHT", "DESIGNING",
    "VERIFY_FIRST", "QUEUED", "DROPPED", "OTHER",
};
static const char *const k_state_glyphs[MVL_STATE_COUNT] = {
    "█", "▓", "▒", "▒", "▒",
    "░", "·", "x", "",
};

/* ── bounded formatting ───────────────────────────────────────────────── */

static char *mvl_at(char *out, size_t cap, size_t used)
{
    return (out && used < cap) ? out + used : NULL;
}

static size_t mvl_room(size_t cap, size_t used)
{
    return used < cap ? cap - used : 0;
}

static size_t mvl_appendf(char *out, size_t cap, size_t used, const char *fmt,
                          ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(mvl_at(out, cap, used), mvl_room(cap, used), fmt, ap);
    va_end(ap);
    return used + (n > 0 ? (size_t)n : 0);
}

static bool mvl_is_continuation(unsigned char b)
{
    return (b >> 6) == 2;
}

/* Bytes of `s` holding at most `chars` UTF-8 code points. */
static size_t mvl_prefix_bytes(const char *s, size_t chars, size_t *chars_out)
{
    size_t bytes = 0;
    size_t seen = 0;

    while (s[bytes] != '\0') {
        if (!mvl_is_continuation((unsigned char)s[bytes])) {
            if (seen == chars)
                break;
            seen++;
        }
        bytes++;
    }
    *chars_out = seen;
    return bytes;
}

/* awk's `%-<width>s` over a UTF-8 locale pads by CHARACTERS, and the plan
 * has a milestone title made of arrows. Padding by bytes here would shift
 * that whole row, so the stopgap's output would no longer match. */
static size_t mvl_pad(char *out, size_t cap, size_t used, const char *s,
                      size_t width)
{
    size_t chars = 0;
    size_t bytes = mvl_prefix_bytes(s, width, &chars);

    used = mvl_appendf(out, cap, used, "%.*s", (int)bytes, s);
    while (chars < width) {
        used = mvl_appendf(out, cap, used, " ");
        chars++;
    }
    return used;
}

static size_t mvl_repeat(char *out, size_t cap, size_t used, const char *g,
                         int64_t times)
{
    for (int64_t i = 0; i < times; i++)
        used = mvl_appendf(out, cap, used, "%s", g);
    return used;
}

/* ── plan parsing ─────────────────────────────────────────────────────── */

static bool mvl_two_digits(const char *s)
{
    if (s[0] < '0' || s[0] > '9')
        return false;
    return s[1] >= '0' && s[1] <= '9';
}

/* Copies the value of ` | <key>=` up to the next ` | ` or end of line. */
static bool mvl_field(const char *line, const char *key, char *dst,
                      size_t cap)
{
    char needle[32];
    const char *p;
    const char *end;

    (void)snprintf(needle, sizeof needle, "| %s=", key);
    p = strstr(line, needle);
    if (!p)
        return false;
    p += strlen(needle);
    end = strstr(p, " | ");
    if (!end)
        end = p + strlen(p);
    while (end > p && end[-1] == ' ')
        end--;
    if ((size_t)(end - p) >= cap)
        end = p + cap - 1;
    memcpy(dst, p, (size_t)(end - p));
    dst[end - p] = '\0';
    return true;
}

static enum mvl_state mvl_state_of(const char *name)
{
    for (int i = 0; i < MVL_STATE_OTHER; i++)
        if (strcmp(name, k_state_names[i]) == 0)
            return (enum mvl_state)i;
    return MVL_STATE_OTHER;
}

static void mvl_title_of(const char *rest, char *dst, size_t cap)
{
    const char *bar = strstr(rest, " | ");
    size_t n = bar ? (size_t)(bar - rest) : strlen(rest);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, rest, n);
    dst[n] = '\0';
}

/* A parent line is ACCEPTED only when its OWN state= says so. Nothing a
 * child row carries can set this, which is the whole point of the rule. */
static bool mvl_line_accepted(const char *line)
{
    char state[MVL_STATE_CAP];

    if (!mvl_field(line, "state", state, sizeof state))
        return false;
    return strcmp(state, "ACCEPTED") == 0;
}

static bool mvl_plan_milestone(const char *line, struct mvl_plan *plan,
                               size_t line_no, char *err, size_t err_cap)
{
    struct mvl_milestone *m;

    if (plan->milestone_count >= MVL_MAX_MILESTONES) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_overflow: more milestones than MVL_MAX_MILESTONES");
        return false;
    }
    m = &plan->milestones[plan->milestone_count++];
    memset(m, 0, sizeof *m);
    mvl_copy(m->id, sizeof m->id, line);
    m->id[3] = '\0';
    mvl_title_of(line + 4, m->title, sizeof m->title);
    m->line_no = line_no;
    m->accepted = mvl_line_accepted(line);
    return true;
}

/* Records the feature line and hands back its id, which the loop rows under
 * it compose their own ids from. A feature past the table's bound is
 * refused rather than absorbed, exactly as a milestone is. */
static bool mvl_plan_feature(const char *line, char *feature, size_t feat_cap,
                             struct mvl_plan *plan, size_t line_no, char *err,
                             size_t err_cap)
{
    struct mvl_feature *f;

    mvl_copy(feature, feat_cap, line + 2);
    feature[3] = '\0';
    if (plan->feature_count >= MVL_MAX_FEATURES) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_overflow: more features than MVL_MAX_FEATURES");
        return false;
    }
    f = &plan->features[plan->feature_count++];
    memset(f, 0, sizeof *f);
    mvl_copy(f->id, sizeof f->id, feature);
    mvl_title_of(line + 6, f->title, sizeof f->title);
    f->line_no = line_no;
    f->milestone = (int)plan->milestone_count - 1;
    f->accepted = mvl_line_accepted(line);
    return true;
}

/* The agent an `INDEPENDENT REVIEW by <agent>` note names. The phrase is
 * matched anywhere in the row rather than inside one note= field, because a
 * plan row carries several note= fields and a review is a review wherever
 * the reviewer wrote it. */
static void mvl_loop_reviewer(const char *line, char *dst, size_t cap)
{
    static const char k_phrase[] = "INDEPENDENT REVIEW by ";
    const char *p = strstr(line, k_phrase);
    size_t n = 0;

    dst[0] = '\0';
    if (!p)
        return;
    p += sizeof k_phrase - 1;
    while (p[n] != '\0' && p[n] != ' ' && p[n] != ',' && p[n] != '|'
           && p[n] != '(' && p[n] != ')')
        n++;
    if (n == 0 || n >= cap)
        return;
    memcpy(dst, p, n);
    dst[n] = '\0';
}

static bool mvl_plan_loop(const char *line, const char *feature,
                          struct mvl_plan *plan, size_t line_no, char *err,
                          size_t err_cap)
{
    struct mvl_loop *l;
    const char *rest = line + 4;
    char state[MVL_STATE_CAP];
    size_t idlen = 0;

    if (plan->loop_count >= MVL_MAX_LOOPS) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_overflow: more loops than MVL_MAX_LOOPS");
        return false;
    }
    if (plan->milestone_count == 0) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_plan_field: loop line before any milestone line");
        return false;
    }
    l = &plan->loops[plan->loop_count++];
    memset(l, 0, sizeof *l);
    l->line_no = line_no;
    while (rest[idlen] != '\0' && rest[idlen] != ' ')
        idlen++;
    l->counted = (idlen == 3);
    (void)snprintf(l->id, sizeof l->id, "%s.%s.%.*s",
                   plan->milestones[plan->milestone_count - 1].id, feature,
                   (int)idlen, rest);
    l->milestone = (int)plan->milestone_count - 1;
    l->feature = plan->feature_count > 0 ? (int)plan->feature_count - 1 : -1;
    mvl_title_of(rest + idlen + (rest[idlen] == ' ' ? 1 : 0), l->title,
                 sizeof l->title);
    mvl_loop_reviewer(line, l->reviewer, sizeof l->reviewer);
    if (!mvl_field(line, "state", state, sizeof state)
        || !mvl_field(line, "loop", l->lane, sizeof l->lane)
        || !mvl_field(line, "evidence", l->evidence, sizeof l->evidence)) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_plan_field: loop line lacks state=, loop= or evidence=");
        return false;
    }
    mvl_copy(l->state, sizeof l->state, state);
    l->state_id = mvl_state_of(state);
    if (!l->counted)
        return true;
    plan->milestones[l->milestone].counts[l->state_id]++;
    plan->totals[l->state_id]++;
    plan->universe++;
    return true;
}

static bool mvl_plan_line(const char *line, char *feature, size_t feat_cap,
                          struct mvl_plan *plan, size_t line_no, char *err,
                          size_t err_cap)
{
    if (line[0] == 'M' && mvl_two_digits(line + 1) && line[3] == ' ')
        return mvl_plan_milestone(line, plan, line_no, err, err_cap);
    if (strncmp(line, "  F", 3) == 0 && mvl_two_digits(line + 3)
        && line[5] == ' ')
        return mvl_plan_feature(line, feature, feat_cap, plan, line_no, err,
                                err_cap);
    if (strncmp(line, "    L", 5) == 0 && mvl_two_digits(line + 5))
        return mvl_plan_loop(line, feature, plan, line_no, err, err_cap);
    return true;
}

bool mvl_parse_plan(const char *path, struct mvl_plan *out, char *err,
                    size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_plan_line");
    char feature[8] = "F00";
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot read the plan");
        free(buf);
        return false;
    }
    for (;;) {
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
        if (!mvl_plan_line(buf, feature, sizeof feature, out, line_no, err,
                           err_cap)) {
            ok = false;
            break;
        }
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

/* ── the progress render ──────────────────────────────────────────────── */

static int64_t mvl_mid(const int64_t *c)
{
    return c[MVL_STATE_READY] + c[MVL_STATE_IN_FLIGHT] + c[MVL_STATE_DESIGNING];
}

static int64_t mvl_queued(const int64_t *c)
{
    return c[MVL_STATE_VERIFY_FIRST] + c[MVL_STATE_QUEUED];
}

static const char *mvl_emoji(int64_t verified, int64_t mid)
{
    if (verified == MVL_MILESTONE_LOOPS)
        return "\U0001f3c1";
    if (verified >= MVL_MILESTONE_LOOPS / 2)
        return "\U0001f680";
    if (verified > 0)
        return "\U0001f527";
    return mid > 0 ? "\U0001f527" : "⬜";
}

static size_t mvl_render_row(const struct mvl_milestone *m, char *out,
                             size_t cap, size_t used)
{
    int64_t done = m->counts[MVL_STATE_LANDED];
    int64_t ver = m->counts[MVL_STATE_TRAIN];
    int64_t mid = mvl_mid(m->counts);
    int64_t q = mvl_queued(m->counts);
    int64_t pct = (100 * (done + ver)) / MVL_MILESTONE_LOOPS;

    used = mvl_appendf(out, cap, used, "%s ", mvl_emoji(done + ver, mid));
    used = mvl_pad(out, cap, used, m->id, 3);
    used = mvl_appendf(out, cap, used, " ");
    used = mvl_pad(out, cap, used, m->title, 52);
    used = mvl_appendf(out, cap, used, " ");
    for (int i = 0; i < MVL_STATE_COUNT; i++)
        used = mvl_repeat(out, cap, used, k_state_glyphs[i], m->counts[i]);
    return mvl_appendf(out, cap, used,
                       " %3lld%%  %2lld %2lld %2lld %2lld\n",
                       (long long)pct, (long long)done, (long long)ver,
                       (long long)mid, (long long)q);
}

static size_t mvl_render_total(const struct mvl_plan *plan, char *out,
                               size_t cap, size_t used)
{
    const int64_t *t = plan->totals;
    int64_t all = plan->universe > 0 ? plan->universe : 1;
    int64_t d = t[MVL_STATE_LANDED];
    int64_t v = t[MVL_STATE_TRAIN];
    int64_t fills[3];
    int64_t painted = 0;

    fills[0] = (MVL_TOTAL_BAR_WIDTH * d) / all;
    fills[1] = (MVL_TOTAL_BAR_WIDTH * v) / all;
    fills[2] = (MVL_TOTAL_BAR_WIDTH * mvl_mid(t)) / all;
    used = mvl_appendf(out, cap, used, "\nMVP  [");
    for (int i = 0; i < 3; i++) {
        used = mvl_repeat(out, cap, used, k_state_glyphs[i], fills[i]);
        painted += fills[i];
    }
    used = mvl_repeat(out, cap, used, k_state_glyphs[MVL_STATE_VERIFY_FIRST],
                      MVL_TOTAL_BAR_WIDTH - painted);
    used = mvl_appendf(out, cap, used, "] %lld/%lld verified (%lld%%)\n",
                       (long long)(d + v), (long long)plan->universe,
                       (long long)((100 * (d + v)) / all));
    return mvl_appendf(out, cap, used,
                       "✅ landed %lld · \U0001f682 on a train %lld"
                       " · \U0001f7e1 ready/in-flight/designing %lld"
                       " · ⬜ queued or verify-first %lld\n"
                       "legend: █ landed  ▓ on a train  ▒"
                       " ready/in-flight/designing  ░ verify-first"
                       " (capability may already exist)  · queued\n",
                       (long long)d, (long long)v, (long long)mvl_mid(t),
                       (long long)mvl_queued(t));
}

size_t mvl_render_progress(const struct mvl_plan *plan, char *out,
                           size_t out_cap)
{
    size_t used = 0;

    used = mvl_appendf(out, out_cap, used, "   ");
    used = mvl_pad(out, out_cap, used, "", 3);
    used = mvl_appendf(out, out_cap, used, " ");
    used = mvl_pad(out, out_cap, used, "MILESTONE", 52);
    used = mvl_appendf(out, out_cap, used, " ");
    used = mvl_pad(out, out_cap, used, "12 LOOPS", 13);
    used = mvl_appendf(out, out_cap, used,
                       " done   ✅ \U0001f682 \U0001f7e1 ⬜\n");
    for (size_t i = 0; i < plan->milestone_count; i++)
        used = mvl_render_row(&plan->milestones[i], out, out_cap, used);
    return mvl_render_total(plan, out, out_cap, used);
}

size_t mvl_render_cost(const struct mvl_agents *agents, char *out,
                       size_t out_cap)
{
    int64_t tokens_out = 0;
    int64_t tokens_in = 0;
    int64_t tool_uses = 0;
    int64_t wall = 0;

    for (size_t i = 0; i < agents->count; i++) {
        tokens_out += agents->rows[i].tokens_out;
        tokens_in += agents->rows[i].tokens_in;
        tool_uses += agents->rows[i].tool_uses;
        wall += agents->rows[i].last_unix - agents->rows[i].first_unix;
    }
    return mvl_appendf(out, out_cap, 0,
                       "cost so far: %lld out / %lld in tokens, %lld tool"
                       " uses, %lld.%01lld agent-hours across %zu agents\n",
                       (long long)tokens_out, (long long)tokens_in,
                       (long long)tool_uses, (long long)(wall / 3600),
                       (long long)((wall % 3600) * 10 / 3600), agents->count);
}

/* ── the XP leaderboard (mode `xp`) ───────────────────────────────────── */

/* The multiplier table is printed with every leaderboard on purpose: a
 * score whose weights are invisible cannot be checked, and these weights
 * are derived from the plan's own milestone titles. */
static size_t mvl_render_multipliers(const struct mvl_plan *plan,
                                     const struct mvl_xp_board *board,
                                     char *out, size_t cap, size_t used)
{
    used = mvl_appendf(out, cap, used,
                       "multipliers (from the plan's own milestone"
                       " titles)\n");
    for (size_t i = 0; i < plan->milestone_count; i++) {
        used = mvl_appendf(out, cap, used, "  %s x%d  ",
                           plan->milestones[i].id, board->multipliers[i]);
        used = mvl_pad(out, cap, used, plan->milestones[i].title, 56);
        used = mvl_appendf(out, cap, used, "\n");
    }
    return mvl_appendf(out, cap, used, "\n");
}

static size_t mvl_render_xp_row(const struct mvl_xp_agent *a, char *out,
                                size_t cap, size_t used)
{
    int64_t milli = mvl_xp_per_mtcu_milli(a);

    if (a->rank > 0)
        used = mvl_appendf(out, cap, used, "%4d ", a->rank);
    else
        used = mvl_appendf(out, cap, used, "   - ");
    used = mvl_pad(out, cap, used, a->agent, 20);
    used = mvl_appendf(out, cap, used, " %5lld %8lld %9lld %13lld  ",
                       (long long)a->loops, (long long)a->reviewed,
                       (long long)a->xp, (long long)a->tcu);
    if (a->tcu <= 0)
        return mvl_appendf(out, cap, used, "unranked (no TOKENS rows)\n");
    return mvl_appendf(out, cap, used, "%lld.%03lld\n",
                       (long long)(milli / 1000),
                       (long long)(milli < 0 ? -milli % 1000 : milli % 1000));
}

/* The gaps this run could not answer. A rule that had no signal says so
 * here rather than paying a guessed bonus or a guessed penalty. */
static size_t mvl_render_xp_gaps(const struct mvl_xp_board *board, char *out,
                                 size_t cap, size_t used)
{
    if (board->speed_asked)
        used = mvl_appendf(out, cap, used,
                           "speed bonus: +%d%% under the median close of"
                           " %lld s\n", MVL_XP_SPEED_PCT,
                           (long long)board->median_wall_s);
    else
        used = mvl_appendf(out, cap, used,
                           "speed bonus: NOT ASKED — no scored loop carried"
                           " a wall clock (no measured agents.tsv), so no"
                           " loop was paid one\n");
    used = mvl_appendf(out, cap, used,
                       "origin/main-red penalty: NOT ASKED — no input this"
                       " tool reads names an event that put origin/main"
                       " red, so no -200 row exists\n");
    return mvl_appendf(out, cap, used,
                       "dev.land outcomes: %s\n",
                       board->outcomes_present
                           ? "read"
                           : "ABSENT — no penalty and no combo scored");
}

size_t mvl_render_xp(const struct mvl_plan *plan,
                     const struct mvl_xp_board *board, char *out,
                     size_t out_cap)
{
    size_t used = mvl_appendf(out, out_cap, 0,
                              "XP — verified MVP progress per token, scored"
                              " (rules v1, evidence only)\n\n");

    used = mvl_render_multipliers(plan, board, out, out_cap, used);
    used = mvl_appendf(out, out_cap, used, "rank ");
    used = mvl_pad(out, out_cap, used, "agent", 20);
    used = mvl_appendf(out, out_cap, used,
                       " loops reviewed        XP           TCU  "
                       "xp/MTCU\n");
    for (size_t i = 0; i < board->count; i++)
        used = mvl_render_xp_row(&board->rows[i], out, out_cap, used);
    used = mvl_appendf(out, out_cap, used, "\n");
    return mvl_render_xp_gaps(board, out, out_cap, used);
}

/* A JSON string cell. Lane names are word-shaped, but a quote or a
 * backslash arriving from a plan row must never break the object. */
static size_t mvl_render_json_str(const char *s, char *out, size_t cap,
                                  size_t used)
{
    used = mvl_appendf(out, cap, used, "\"");
    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char b = (unsigned char)s[i];

        if (b == '"' || b == '\\')
            used = mvl_appendf(out, cap, used, "\\%c", (char)b);
        else if (b < 0x20)
            used = mvl_appendf(out, cap, used, " ");
        else
            used = mvl_appendf(out, cap, used, "%c", (char)b);
    }
    return mvl_appendf(out, cap, used, "\"");
}

static size_t mvl_render_json_agent(const struct mvl_xp_agent *a, char *out,
                                    size_t cap, size_t used, bool first)
{
    used = mvl_appendf(out, cap, used, first ? "{" : ",{");
    used = mvl_appendf(out, cap, used, "\"agent\":");
    used = mvl_render_json_str(a->agent, out, cap, used);
    return mvl_appendf(out, cap, used,
                       ",\"loops\":%lld,\"reviewed\":%lld,\"xp\":%lld,"
                       "\"tcu\":%lld,\"xp_per_mtcu_milli\":%lld,"
                       "\"rank\":%d,\"ranked\":%s}",
                       (long long)a->loops, (long long)a->reviewed,
                       (long long)a->xp, (long long)a->tcu,
                       (long long)mvl_xp_per_mtcu_milli(a), a->rank,
                       a->rank > 0 ? "true" : "false");
}

size_t mvl_render_xp_json(const struct mvl_plan *plan,
                          const struct mvl_xp_board *board, char *out,
                          size_t out_cap)
{
    size_t used = mvl_appendf(out, out_cap, 0,
                              "{\"kind\":\"mvp_xp_v1\",\"multipliers\":{");

    for (size_t i = 0; i < plan->milestone_count; i++) {
        used = mvl_appendf(out, out_cap, used, i == 0 ? "" : ",");
        used = mvl_render_json_str(plan->milestones[i].id, out, out_cap,
                                   used);
        used = mvl_appendf(out, out_cap, used, ":%d",
                           board->multipliers[i]);
    }
    used = mvl_appendf(out, out_cap, used,
                       "},\"speed_asked\":%s,\"median_wall_s\":%lld,"
                       "\"main_red_asked\":false,\"outcomes_present\":%s,"
                       "\"agents\":[",
                       board->speed_asked ? "true" : "false",
                       (long long)board->median_wall_s,
                       board->outcomes_present ? "true" : "false");
    for (size_t i = 0; i < board->count; i++)
        used = mvl_render_json_agent(&board->rows[i], out, out_cap, used,
                                     i == 0);
    return mvl_appendf(out, out_cap, used, "]}\n");
}
