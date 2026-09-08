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

static bool mvl_plan_milestone(const char *line, struct mvl_plan *plan,
                               size_t line_no, char *err, size_t err_cap)
{
    struct mvl_milestone *m;
    char *done;
    char title[MVL_TITLE_CAP];

    if (plan->milestone_count >= MVL_MAX_MILESTONES) {
        mvl_err(err, err_cap, "plan", line_no,
                "mvl_overflow: more milestones than MVL_MAX_MILESTONES");
        return false;
    }
    m = &plan->milestones[plan->milestone_count++];
    memset(m, 0, sizeof *m);
    mvl_copy(m->id, sizeof m->id, line);
    m->id[3] = '\0';
    mvl_copy(title, sizeof title, line + 4);
    done = strstr(title, " | done=");
    if (done)
        *done = '\0';
    mvl_copy(m->title, sizeof m->title, title);
    return true;
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
    mvl_title_of(rest + idlen + (rest[idlen] == ' ' ? 1 : 0), l->title,
                 sizeof l->title);
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
        && line[5] == ' ') {
        mvl_copy(feature, feat_cap, line + 2);
        feature[3] = '\0';
        return true;
    }
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
