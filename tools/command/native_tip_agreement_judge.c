/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The windowed judge over the off-host tip-hash agreement ledger
 *          that tools/scripts/tip_agreement_probe.sh appends to. Every row
 *          whose ts lies in [now - window_hours*3600, now] is graded, not
 *          only the last one: agreement is an accrual claim ("our tip hash
 *          matched genuinely remote peers, repeatedly, across a day"), and
 *          one row cannot say that.
 *
 * Verdicts all fail closed, in this order: STALE (no ledger, no parseable ts,
 * newest sample too old, nothing inside the window), MALFORMED (an outcome
 * the judge does not know, or a spliced line), DISAGREE (checked BEFORE the
 * evidence-volume rules so a real divergence is never masked by a thin
 * window), NO_EVIDENCE, THIN_EVIDENCE, PASS. A sample says "agrees" cleanly
 * only when the recorder looked for rivals at every height and found none; a
 * missing rival key is UNKNOWN, never zero. Exit: 0 PASS, 2 STALE, else 1. */

#include "native_evidence_judge_util.h"

#include "services/tip_agreement_watch.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TIP_FILE_MAX ((size_t)1 << 30)
#define TIP_DEF_MIN_DISTINCT_PEERS TIP_AGREEMENT_MIN_DISTINCT_PEERS

struct tip_sum {
    int64_t total, agrees, disagrees, cna, malformed, parseable;
    int64_t contested, unresolved, clean;
    int64_t min_peers, min_ctl, newest, span_lo, span_hi;
};

struct tip_ctx {
    const struct zcl_tip_judge_opts *o;
    const struct tip_sum *s;
    int64_t age; /* -1 = no newest sample to measure */
};

/* Non-overlapping occurrences of `needle` in `line`. */
static int tip_count(const char *line, const char *needle)
{
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = line; (p = strstr(p, needle)) != NULL; p += len)
        n++;
    return n;
}

/* The first `"key":-?[0-9]+` of the line. Trailing characters after the
 * digits are ignored, as the awk reader this replaces ignored them; an
 * occurrence not followed by an integer is skipped for the next one. */
static bool tip_num(const char *line, const char *key, int64_t *v)
{
    char needle[64];
    const char *p = line;
    if (snprintf(needle, sizeof(needle), "\"%s\":", key) >= (int)sizeof(needle))
        return false;
    while ((p = strstr(p, needle)) != NULL) {
        const char *q = p + strlen(needle);
        const char *digits = *q == '-' ? q + 1 : q;
        p = q;
        if (*digits >= '0' && *digits <= '9') {
            *v = (int64_t)strtoll(q, NULL, 10);
            return true;
        }
    }
    return false;
}

static void tip_note_min(int64_t *min, int64_t v)
{
    if (*min < 0 || v < *min)
        *min = v;
}

/* An agreeing sample: witness count, recorded control, and whether the
 * recorder proved there was no rival. */
static void tip_grade_agree(const char *line, int64_t ts, struct tip_sum *s)
{
    int64_t peers = 0, ctl = 0, cp = 0, ru = 0;
    bool have_cp, have_ru;
    s->agrees++;
    if (!tip_num(line, "modal_remote_peers", &peers))
        peers = 0; /* unmeasured witnesses never count as strong */
    tip_note_min(&s->min_peers, peers);
    if (!tip_num(line, "min_distinct_peers", &ctl))
        ctl = 0;
    tip_note_min(&s->min_ctl, ctl);
    have_cp = tip_num(line, "contested_peers", &cp);
    have_ru = tip_num(line, "rival_heights_unresolved", &ru);
    if (have_cp && cp > 0) {
        s->contested++;
    } else if (!have_cp || !have_ru || ru > 0) {
        s->unresolved++;
    } else {
        s->clean++;
        if (s->span_lo < 0 || ts < s->span_lo)
            s->span_lo = ts;
        if (s->span_hi < 0 || ts > s->span_hi)
            s->span_hi = ts;
    }
}

static void tip_grade_outcome(const char *line, int64_t ts, struct tip_sum *s)
{
    char outcome[32] = "";
    (void)ej_field_str(line, "outcome", outcome, sizeof(outcome));
    if (strcmp(outcome, "agrees") == 0)
        tip_grade_agree(line, ts, s);
    else if (strcmp(outcome, "disagrees") == 0)
        s->disagrees++;
    else if (strcmp(outcome, "could-not-ask") == 0)
        s->cna++;
    else
        s->malformed++;
}

/* One ledger line. A line carrying two ts or two outcome keys can only be a
 * torn write that a later append landed on top of; it is MALFORMED rather
 * than graded with one sample's timestamp and another's outcome. */
static void tip_grade_line(const char *line, int64_t now, int64_t winsecs,
                           struct tip_sum *s)
{
    int64_t ts;
    if (tip_count(line, "\"ts\":") > 1 || tip_count(line, "\"outcome\":\"") > 1) {
        s->malformed++;
        return;
    }
    if (!tip_num(line, "ts", &ts) || ts > now)
        return; /* future samples cannot refresh or accrue evidence */
    s->parseable++;
    if (ts > s->newest)
        s->newest = ts;
    if (ts < now - winsecs)
        return;
    s->total++;
    tip_grade_outcome(line, ts, s);
}

/* The buffer is modified: each line is cut at its newline. */
static void tip_scan(char *buf, int64_t now, int64_t winsecs, struct tip_sum *s)
{
    memset(s, 0, sizeof(*s));
    s->min_peers = s->min_ctl = s->newest = s->span_lo = s->span_hi = -1;
    for (char *line = buf; line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        tip_grade_line(line, now, winsecs, s);
        line = nl ? nl + 1 : NULL;
    }
}

static int64_t tip_span(const struct tip_sum *s)
{
    return s->span_hi < 0 ? -1 : s->span_hi - s->span_lo;
}

static void tip_dash(char *dst, size_t cap, int64_t v)
{
    if (v == -1)
        (void)snprintf(dst, cap, "-");
    else
        (void)snprintf(dst, cap, "%lld", (long long)v);
}

/* The one report line. A number that is -1 is a sentinel for "no
 * measurement" and prints as "-", never as a count of minus one. */
static void tip_emit(const struct tip_ctx *c, struct zcl_judge_result *out,
                     const char *token, const char *reason)
{
    char mp[24], span[24], age[24];
    const struct tip_sum *s = c->s;
    tip_dash(mp, sizeof(mp), s->min_peers);
    tip_dash(span, sizeof(span), tip_span(s));
    tip_dash(age, sizeof(age), c->age);
    ej_verdict(out, strcmp(token, "PASS") == 0 ? 0 : strcmp(token, "STALE") == 0 ? 2 : 1,
               token, reason);
    ej_cat(out,
           "tip-agreement-judge: VERDICT=%s reason=%s window_hours=%lld "
           "samples=%lld agrees=%lld clean_agrees=%lld contested=%lld "
           "unverifiable=%lld disagrees=%lld could_not_ask=%lld "
           "min_peers_seen=%s clean_span_s=%s newest_age_s=%s "
           "ledger=owner_private\n",
           token, reason, (long long)c->o->window_hours, (long long)s->total,
           (long long)s->agrees, (long long)s->clean, (long long)s->contested,
           (long long)s->unresolved, (long long)s->disagrees, (long long)s->cna,
           mp, span, age);
}

static void tip_emitf(const struct tip_ctx *c, struct zcl_judge_result *out,
                      const char *token, const char *fmt, ...)
    ZCL_PRINTF_LIKE(4, 5);

static void tip_emitf(const struct tip_ctx *c, struct zcl_judge_result *out,
                      const char *token, const char *fmt, ...)
{
    char reason[ZCL_JUDGE_REASON_MAX];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(reason, sizeof(reason), fmt, args);
    va_end(args);
    tip_emit(c, out, token, reason);
}

/* STALE: nothing recent and inside the window to grade. */
static bool tip_stale(const struct tip_ctx *c, struct zcl_judge_result *out)
{
    if (c->s->parseable == 0) {
        tip_emit(c, out, "STALE", "no_line_with_parseable_ts");
    } else if (c->age > c->o->max_age_secs) {
        tip_emitf(c, out, "STALE", "newest_sample_age_%llds_gt_%llds",
                  (long long)c->age, (long long)c->o->max_age_secs);
    } else if (c->s->total == 0) {
        tip_emit(c, out, "STALE", "no_samples_inside_window");
    } else {
        return false;
    }
    return true;
}

/* MALFORMED and DISAGREE, ahead of every evidence-volume rule. */
static bool tip_refuse(const struct tip_ctx *c, struct zcl_judge_result *out)
{
    const struct tip_sum *s = c->s;
    int64_t max = c->o->max_disagree;
    if (s->malformed > 0)
        tip_emitf(c, out, "MALFORMED", "%lld_samples_with_unrecognised_outcome",
                  (long long)s->malformed);
    else if (s->disagrees > max)
        tip_emitf(c, out, "DISAGREE", "%lld_disagreeing_samples_gt_max_%lld",
                  (long long)s->disagrees, (long long)max);
    else if (s->contested > max)
        tip_emitf(c, out, "DISAGREE",
                  "%lld_agreeing_samples_carried_contesting_remote_hosts_gt_max_%lld",
                  (long long)s->contested, (long long)max);
    else
        return false;
    return true;
}

/* NO_EVIDENCE and THIN_EVIDENCE: too few clean samples, too short a span,
 * too few witnesses, or a ledger written with a weakened control. */
static bool tip_thin(const struct tip_ctx *c, struct zcl_judge_result *out)
{
    const struct tip_sum *s = c->s;
    const struct zcl_tip_judge_opts *o = c->o;
    if (s->clean == 0)
        tip_emitf(c, out, "NO_EVIDENCE",
                  "zero_clean_agreeing_samples_in_window_%lld_could_not_ask_%lld_unverifiable",
                  (long long)s->cna, (long long)s->unresolved);
    else if (s->clean < o->min_agree)
        tip_emitf(c, out, "THIN_EVIDENCE",
                  "only_%lld_clean_agreeing_samples_lt_min_%lld_with_%lld_unverifiable",
                  (long long)s->clean, (long long)o->min_agree,
                  (long long)s->unresolved);
    else if (tip_span(s) < o->min_span_secs)
        tip_emitf(c, out, "THIN_EVIDENCE",
                  "clean_agreeing_samples_span_only_%llds_lt_min_%llds",
                  (long long)tip_span(s), (long long)o->min_span_secs);
    else if (s->min_peers < o->min_distinct_peers)
        tip_emitf(c, out, "THIN_EVIDENCE",
                  "an_agreeing_sample_had_only_%lld_distinct_remote_peers_lt_%lld",
                  (long long)s->min_peers, (long long)o->min_distinct_peers);
    else if (s->min_ctl < o->min_distinct_peers)
        tip_emitf(c, out, "THIN_EVIDENCE",
                  "ledger_written_with_weakened_control_min_distinct_peers_%lld_lt_%lld",
                  (long long)s->min_ctl, (long long)o->min_distinct_peers);
    else
        return false;
    return true;
}

static void tip_ladder(const struct tip_ctx *c, struct zcl_judge_result *out)
{
    if (tip_stale(c, out) || tip_refuse(c, out) || tip_thin(c, out))
        return;
    tip_emitf(c, out, "PASS",
              "%lld_clean_agreeing_samples_ge_%lld_spanning_%llds_each_backed_by_ge_%lld_distinct_remote_peers_with_no_contesting_host",
              (long long)c->s->clean, (long long)c->o->min_agree,
              (long long)tip_span(c->s), (long long)c->o->min_distinct_peers);
}

bool zcl_tip_agreement_judge(const struct zcl_tip_judge_opts *opts,
                             struct zcl_judge_result *out)
{
    struct tip_sum sum;
    struct tip_ctx ctx = {opts, &sum, -1};
    size_t len = 0;
    char *buf;
    int64_t now;
    if (!opts || !opts->file || !out)
        return false;
    memset(out, 0, sizeof(*out));
    now = opts->now_set ? opts->now_unix : ej_now(0);
    buf = ej_slurp(opts->file, TIP_FILE_MAX, &len);
    if (!buf) {
        memset(&sum, 0, sizeof(sum));
        sum.min_peers = sum.span_hi = -1;
        tip_emit(&ctx, out, "STALE", "no_ledger_file");
        return true;
    }
    bool embedded_nul = memchr(buf, '\0', len) != NULL;
    tip_scan(buf, now, opts->window_hours * 3600, &sum);
    if (embedded_nul) sum.malformed++;
    if (sum.parseable > 0) {
        ctx.age = now - sum.newest;
        if (ctx.age < 0)
            ctx.age = 0;
    }
    tip_ladder(&ctx, out);
    free(buf);
    return true;
}

bool zcl_tip_judge_defaults(struct zcl_tip_judge_opts *opts, char *err,
                            size_t err_cap)
{
    int64_t now = 0;
    int r;
    memset(opts, 0, sizeof(*opts));
    opts->window_hours = ZCL_TIP_DEF_WINDOW_HOURS;
    opts->max_age_secs = ZCL_TIP_DEF_MAX_AGE_SECS;
    opts->min_agree = ZCL_TIP_DEF_MIN_AGREE;
    opts->min_distinct_peers = TIP_DEF_MIN_DISTINCT_PEERS;
    opts->max_disagree = ZCL_TIP_DEF_MAX_DISAGREE;
    opts->min_span_secs = ZCL_TIP_DEF_MIN_SPAN_SECS;
    r = ej_env_int("ZCL_PARITY_JUDGE_NOW", getenv("ZCL_PARITY_JUDGE_NOW"), &now,
                   err, err_cap);
    opts->now_unix = now;
    opts->now_set = r > 0;
    return r >= 0;
}

static bool tip_loosens(char *err, size_t cap, const char *flag, int64_t v,
                        int64_t def, const char *dir)
{
    (void)snprintf(err, cap,
                   "%s=%lld LOOSENS the shipped contract (default %lld); this judge accepts only %s %lld - a red gate is fixed by fixing the node, never by widening the judge",
                   flag, (long long)v, (long long)def, dir, (long long)def);
    return false;
}

bool zcl_tip_judge_check(const struct zcl_tip_judge_opts *o, char *err,
                         size_t err_cap)
{
    if (o->window_hours < 0 || o->max_age_secs < 0 || o->min_agree < 0 ||
        o->min_distinct_peers < 0 || o->max_disagree < 0 || o->min_span_secs < 0) {
        (void)snprintf(err, err_cap, "every tip-agreement knob must be a non-negative integer");
        return false;
    }
    if (o->window_hours > ZCL_TIP_DEF_WINDOW_HOURS)
        return tip_loosens(err, err_cap, "window_hours", o->window_hours,
                           ZCL_TIP_DEF_WINDOW_HOURS, "<=");
    if (o->max_age_secs > ZCL_TIP_DEF_MAX_AGE_SECS)
        return tip_loosens(err, err_cap, "max_age_secs", o->max_age_secs,
                           ZCL_TIP_DEF_MAX_AGE_SECS, "<=");
    if (o->max_disagree > ZCL_TIP_DEF_MAX_DISAGREE)
        return tip_loosens(err, err_cap, "max_disagree", o->max_disagree,
                           ZCL_TIP_DEF_MAX_DISAGREE, "<=");
    if (o->min_agree < ZCL_TIP_DEF_MIN_AGREE)
        return tip_loosens(err, err_cap, "min_agree", o->min_agree,
                           ZCL_TIP_DEF_MIN_AGREE, ">=");
    if (o->min_span_secs < ZCL_TIP_DEF_MIN_SPAN_SECS)
        return tip_loosens(err, err_cap, "min_span_secs", o->min_span_secs,
                           ZCL_TIP_DEF_MIN_SPAN_SECS, ">=");
    if (o->min_distinct_peers < TIP_DEF_MIN_DISTINCT_PEERS) {
        (void)snprintf(err, err_cap,
                       "min_distinct_peers must be >= %d (one peer must never be able to manufacture agreement)",
                       TIP_DEF_MIN_DISTINCT_PEERS);
        return false;
    }
    return true;
}
