/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The MVP C6 soak window judge. Reads the hourly evidence ledger
 *          and returns MET, NOT_MET or INSUFFICIENT over the trailing window
 *          anchored at the last sample, with the same report lines and
 *          verdict ladder the soak_evidence.sh judge printed.
 *
 * The verdict comes from parsed data only: an empty or short ledger is an
 * explicit INSUFFICIENT, never a pass. Exit: 0 MET, 1 NOT_MET, 2 otherwise. */

#include "native_evidence_judge_util.h"

#include "base/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOAK_FILE_MAX ((size_t)1 << 30)
#define SOAK_SHA_HEX 64

struct soak_sample {
    int64_t ts;
    bool ok, sec_ok, sec_review, sec_known;
    struct ej_num soak_h, zd_h, gap, nrestarts, aet, rss;
    char bin[SOAK_SHA_HEX + 1]; /* "" unknown, else 64 hex digits */
};

struct soak_stats {
    int64_t covered_sec, hole_max, op, ambiguous, soak_null, zd_null;
    int64_t ok_cnt, gap0, gapgt0, review, unknown, sec_gap, eligible;
    int64_t bin_known, bin_ids, cnt;
    bool have_max_gap, have_nr, have_rss;
    int64_t max_gap, nr_first, nr_last, rss_first, rss_last;
    char bin_id1[SOAK_SHA_HEX + 1];
};

static bool soak_hex64(const char *p)
{
    for (int i = 0; i < SOAK_SHA_HEX; i++)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
            return false;
    return true;
}

/* `"binary_sha256":("<64 hex>"|null)`; anything else leaves it unknown. */
static void soak_parse_bin(const char *line, char *bin)
{
    const char *p = line;
    bin[0] = '\0';
    while ((p = strstr(p, "\"binary_sha256\":")) != NULL) {
        p += strlen("\"binary_sha256\":");
        if (strncmp(p, "null", 4) == 0)
            return;
        if (p[0] == '"' && soak_hex64(p + 1) && p[1 + SOAK_SHA_HEX] == '"') {
            memcpy(bin, p + 1, SOAK_SHA_HEX);
            bin[SOAK_SHA_HEX] = '\0';
            return;
        }
    }
}

static bool soak_parse_line(char *line, struct soak_sample *s)
{
    struct ej_num ts = ej_field_num(line, "ts", true);
    if (ts.kind != EJ_NUM)
        return false;
    s->ts = ts.n;
    s->ok = strstr(line, "\"ok\":true") != NULL;
    s->sec_ok = strstr(line, "\"security_posture_ok\":true") != NULL;
    s->sec_review = strstr(line, "\"security_review_required\":true") != NULL;
    s->sec_known =
        (strstr(line, "\"security_review_required\":true") ||
         strstr(line, "\"security_review_required\":false")) &&
        (strstr(line, "\"security_posture_ok\":true") ||
         strstr(line, "\"security_posture_ok\":false"));
    s->soak_h = ej_field_num(line, "soak_height", true);
    s->zd_h = ej_field_num(line, "zd_height", true);
    s->gap = ej_field_num(line, "gap", true);
    s->nrestarts = ej_field_num(line, "nrestarts", true);
    s->aet = ej_field_num(line, "active_enter_ts", true);
    s->rss = ej_field_num(line, "rss_kb", true);
    soak_parse_bin(line, s->bin);
    return true;
}

/* Splits the ledger in place; returns the samples, counting lines that carry
 * no timestamp as malformed. */
static struct soak_sample *soak_parse(char *buf, size_t *n, int64_t *malformed)
{
    size_t cap = 1024;
    struct soak_sample *v = zcl_malloc(cap * sizeof(*v), "soak samples");
    char *line = buf;
    *n = 0;
    *malformed = 0;
    while (v && line) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (nl || *line) {
            if (*n == cap) {
                struct soak_sample *grown =
                    zcl_realloc(v, cap * 2 * sizeof(*v), "soak samples");
                if (!grown) {
                    free(v);
                    return NULL;
                }
                v = grown;
                cap *= 2;
            }
            if (soak_parse_line(line, &v[*n]))
                (*n)++;
            else
                (*malformed)++;
        }
        line = nl ? nl + 1 : NULL;
    }
    return v;
}

static void soak_scan_restarts(const struct soak_sample *s, size_t i,
                               struct soak_stats *st, int64_t *prev_nr,
                               int64_t *prev_aet, bool *have_prev_nr,
                               bool *have_prev_aet)
{
    bool has_a = s[i].aet.kind == EJ_NUM;
    int64_t r, a = has_a ? s[i].aet.n : 0;
    if (s[i].nrestarts.kind != EJ_NUM)
        return;
    r = s[i].nrestarts.n;
    if (!st->have_nr) {
        st->have_nr = true;
        st->nr_first = r;
    }
    st->nr_last = r;
    if (*have_prev_nr) {
        bool jumped = has_a && *have_prev_aet && a > *prev_aet + 5;
        if (r < *prev_nr || (jumped && r == *prev_nr))
            st->op++;
        else if (jumped && r > *prev_nr)
            st->ambiguous += r - *prev_nr;
    }
    *prev_nr = r;
    *have_prev_nr = true;
    if (has_a) {
        *prev_aet = a;
        *have_prev_aet = true;
    }
}

static void soak_scan_posture(const struct soak_sample *s, struct soak_stats *st)
{
    if (s->soak_h.kind != EJ_NUM)
        st->soak_null++;
    else if (s->zd_h.kind != EJ_NUM)
        st->zd_null++;
    if (s->sec_review)
        st->review++;
    if (!s->sec_known)
        st->unknown++;
    if (s->sec_known && !s->sec_ok)
        st->sec_gap++;
    if (s->ok && s->sec_ok)
        st->eligible++;
}

static void soak_scan_gap(const struct soak_sample *s, struct soak_stats *st)
{
    if (!s->ok || s->gap.kind != EJ_NUM)
        return;
    st->ok_cnt++;
    st->gap0 += s->gap.n == 0;
    st->gapgt0 += s->gap.n > 0;
    if (!st->have_max_gap || s->gap.n > st->max_gap)
        st->max_gap = s->gap.n;
    st->have_max_gap = true;
}

static void soak_scan_one(const struct soak_sample *s, struct soak_stats *st)
{
    soak_scan_posture(s, st);
    soak_scan_gap(s, st);
    if (s->rss.kind == EJ_NUM) {
        if (!st->have_rss)
            st->rss_first = s->rss.n;
        st->have_rss = true;
        st->rss_last = s->rss.n;
    }
    if (s->bin[0]) {
        st->bin_known++;
        if (!st->bin_id1[0])
            memcpy(st->bin_id1, s->bin, sizeof(st->bin_id1));
        else if (strcmp(s->bin, st->bin_id1) != 0)
            st->bin_ids++;
    }
}

static void soak_scan(const struct soak_sample *s, size_t i0, size_t n,
                      struct soak_stats *st)
{
    int64_t prev_nr = 0, prev_aet = 0;
    bool have_prev_nr = false, have_prev_aet = false;
    memset(st, 0, sizeof(*st));
    st->cnt = (int64_t)(n - i0);
    st->covered_sec = s[n - 1].ts - s[i0].ts;
    for (size_t i = i0; i < n; i++) {
        if (i > i0 && s[i].ts - s[i - 1].ts > st->hole_max)
            st->hole_max = s[i].ts - s[i - 1].ts;
        soak_scan_one(&s[i], st);
        soak_scan_restarts(s, i, st, &prev_nr, &prev_aet, &have_prev_nr,
                           &have_prev_aet);
    }
}

/* First window sample: the first at or after the cutoff before the last. */
static size_t soak_window_start(const struct soak_sample *s, size_t n,
                                int64_t window_hours)
{
    int64_t cutoff = s[n - 1].ts - window_hours * 3600 -
                     ZCL_SOAK_WINDOW_SLACK_SEC;
    size_t i0 = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i].ts < cutoff)
            i0 = i + 1;
        else
            break;
    }
    return i0 >= n ? n - 1 : i0;
}

static void soak_set(struct zcl_judge_result *out, const char *v,
                     const char *fmt, ...) ZCL_PRINTF_LIKE(3, 4);

static void soak_set(struct zcl_judge_result *out, const char *v,
                     const char *fmt, ...)
{
    char reason[ZCL_JUDGE_REASON_MAX];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(reason, sizeof(reason), fmt, args);
    va_end(args);
    ej_verdict(out, 0, v, reason);
}

/* The criterion ladder after the identity checks. */
static void soak_ladder_liveness(const struct soak_stats *st,
                                 struct zcl_judge_result *out, double gap0_pct)
{
    int64_t cnt = st->cnt;
    if (st->op > 0)
        soak_set(out, "NOT_MET", "operator_intervention_detected_x%lld",
                 (long long)st->op);
    else if (st->review > 0)
        soak_set(out, "NOT_MET", "security_review_required_in_%lld_of_%lld_samples",
                 (long long)st->review, (long long)cnt);
    else if (st->hole_max > ZCL_SOAK_HOLE_THRESHOLD_SEC)
        soak_set(out, "NOT_MET", "sampling_hole_%llds_gt_%ds",
                 (long long)st->hole_max, ZCL_SOAK_HOLE_THRESHOLD_SEC);
    else if (st->soak_null * 100 > cnt * (100 - ZCL_SOAK_GAP0_MIN_PCT))
        soak_set(out, "NOT_MET", "soak_unreachable_in_%lld_of_%lld_samples",
                 (long long)st->soak_null, (long long)cnt);
    else if (st->ok_cnt * 100 < cnt * 90)
        soak_set(out, "INSUFFICIENT", "oracle_coverage_thin_ok_%lld_of_%lld",
                 (long long)st->ok_cnt, (long long)cnt);
    else if (gap0_pct < ZCL_SOAK_GAP0_MIN_PCT)
        soak_set(out, "NOT_MET", "gap_nonzero_in_%lld_of_%lld_ok_samples",
                 (long long)(st->ok_cnt - st->gap0), (long long)st->ok_cnt);
    else
        out->verdict[0] = '\0';
}

static void soak_ladder(const struct soak_stats *st, int64_t window_hours,
                        struct zcl_judge_result *out, double gap0_pct)
{
    int64_t cnt = st->cnt, need = window_hours * 3600;
    if (cnt < 2)
        soak_set(out, "INSUFFICIENT", "too_few_samples");
    else if (st->covered_sec + ZCL_SOAK_WINDOW_SLACK_SEC < need)
        soak_set(out, "INSUFFICIENT", "window_short_%llds_lt_%llds_slack%ds",
                 (long long)st->covered_sec, (long long)need,
                 ZCL_SOAK_WINDOW_SLACK_SEC);
    else if (st->bin_ids > 0)
        soak_set(out, "NOT_MET",
                 "binary_identity_changed_in_%lld_of_%lld_identity_samples",
                 (long long)st->bin_ids, (long long)st->bin_known);
    else
        soak_ladder_liveness(st, out, gap0_pct);
    if (out->verdict[0])
        return;
    if (st->unknown > 0)
        soak_set(out, "INSUFFICIENT", "security_posture_unknown_in_%lld_of_%lld_samples",
                 (long long)st->unknown, (long long)cnt);
    else if (st->sec_gap > 0)
        soak_set(out, "NOT_MET", "security_posture_gap_in_%lld_of_%lld_samples",
                 (long long)st->sec_gap, (long long)cnt);
    else if (st->bin_known != cnt)
        soak_set(out, "INSUFFICIENT", "binary_identity_unknown_in_%lld_of_%lld_samples",
                 (long long)(cnt - st->bin_known), (long long)cnt);
    else
        soak_set(out, "MET", "covered_%.1fh_hole_max_%llds_gap0_%.2fpct",
                 (double)st->covered_sec / 3600.0, (long long)st->hole_max,
                 gap0_pct);
}

static void soak_render(const struct soak_stats *st, const struct soak_sample *s,
                        size_t n, size_t i0, size_t file_n, int64_t malformed,
                        const struct zcl_soak_judge_opts *o, int64_t now,
                        struct zcl_judge_result *out)
{
    int64_t last = s[n - 1].ts;
    out->covered_hours = (double)st->covered_sec / 3600.0;
    out->newest_age_sec = now - last;
    ej_cat(out, "soak-evidence: judge window_hours=%lld file=%s file_samples=%zu window_samples=%lld malformed=%lld\n",
           (long long)o->window_hours, o->file, file_n, (long long)st->cnt,
           (long long)malformed);
    ej_cat(out, "soak-evidence: window_covered_hours=%.3f window_covered_sec=%lld first_ts=%lld last_ts=%lld last_sample_age_sec=%lld allow_stale=%d\n",
           (double)st->covered_sec / 3600.0, (long long)st->covered_sec,
           (long long)s[i0].ts, (long long)last, (long long)(now - last),
           o->allow_stale ? 1 : 0);
    ej_cat(out, "soak-evidence: max_sampling_hole_sec=%lld hole_threshold_sec=%d\n",
           (long long)st->hole_max, ZCL_SOAK_HOLE_THRESHOLD_SEC);
}

static void soak_render_counts(const struct soak_stats *st,
                               struct zcl_judge_result *out, double gap0_pct)
{
    char restarts[32] = "null", max_gap[32] = "null";
    char rss_first[32] = "null", rss_last[32] = "null";
    if (st->have_nr)
        (void)snprintf(restarts, sizeof(restarts), "%lld",
                       (long long)(st->nr_last - st->nr_first));
    if (st->have_max_gap)
        (void)snprintf(max_gap, sizeof(max_gap), "%lld", (long long)st->max_gap);
    if (st->have_rss) {
        (void)snprintf(rss_first, sizeof(rss_first), "%lld", (long long)st->rss_first);
        (void)snprintf(rss_last, sizeof(rss_last), "%lld", (long long)st->rss_last);
    }
    ej_cat(out, "soak-evidence: restarts_in_window=%s ambiguous_restarts=%lld operator_interventions=%lld (NRestarts delta; in-binary watchdog self-recycles count as AUTONOMOUS recovery \xe2\x80\x94 count reported, the criterion text decides; ambiguous = restarts in AET-jump intervals where a manual reset-then-climb is indistinguishable at hourly sampling resolution; strict soak_harness math counts ANY observed downtime as FAIL_CRASH)\n",
           restarts, (long long)st->ambiguous, (long long)st->op);
    ej_cat(out, "soak-evidence: ok_samples=%lld/%lld soak_null_samples=%lld zd_null_samples=%lld samples_with_gap_gt0=%lld max_gap=%s gap0_pct=%.2f\n",
           (long long)st->ok_cnt, (long long)st->cnt, (long long)st->soak_null,
           (long long)st->zd_null, (long long)st->gapgt0, max_gap, gap0_pct);
    ej_cat(out, "soak-evidence: window_eligible_samples=%lld/%lld security_review_required_samples=%lld security_posture_unknown_samples=%lld security_posture_gap_samples=%lld\n",
           (long long)st->eligible, (long long)st->cnt, (long long)st->review,
           (long long)st->unknown, (long long)st->sec_gap);
    ej_cat(out, "soak-evidence: rss_first_kb=%s rss_last_kb=%s\n", rss_first, rss_last);
    ej_cat(out, "soak-evidence: binary_identity_samples=%lld/%lld distinct_beyond_first=%lld identity=%s\n",
           (long long)st->bin_known, (long long)st->cnt, (long long)st->bin_ids,
           st->bin_id1[0] ? st->bin_id1 : "null");
}

static void soak_finish(struct zcl_judge_result *out)
{
    if (strcmp(out->verdict, "MET") == 0)
        out->exit_code = 0;
    else if (strcmp(out->verdict, "NOT_MET") == 0)
        out->exit_code = 1;
    else
        out->exit_code = 2;
    ej_cat(out, "soak-evidence: VERDICT=%s reason=%s\n", out->verdict,
           out->reason);
}

static bool soak_judge_samples(const struct zcl_soak_judge_opts *o,
                               const struct soak_sample *s, size_t n,
                               int64_t malformed, struct zcl_judge_result *out)
{
    struct soak_stats st;
    int64_t now = ej_now(o->now_unix);
    size_t i0;
    double gap0_pct;
    if (n == 0) {
        ej_cat(out, "soak-evidence: judge window_hours=%lld file=%s file_samples=0 malformed=%lld\n",
               (long long)o->window_hours, o->file, (long long)malformed);
        soak_set(out, "INSUFFICIENT", "empty_log");
        soak_finish(out);
        return true;
    }
    i0 = soak_window_start(s, n, o->window_hours);
    soak_scan(s, i0, n, &st);
    gap0_pct = st.ok_cnt > 0 ? 100.0 * (double)st.gap0 / (double)st.ok_cnt : 0.0;
    soak_render(&st, s, n, i0, n, malformed, o, now, out);
    soak_render_counts(&st, out, gap0_pct);
    soak_ladder(&st, o->window_hours, out, gap0_pct);
    if (strcmp(out->verdict, "MET") == 0 && !o->allow_stale &&
        now - s[n - 1].ts > ZCL_SOAK_HOLE_THRESHOLD_SEC)
        soak_set(out, "INSUFFICIENT", "stale_evidence_age_%llds",
                 (long long)(now - s[n - 1].ts));
    soak_finish(out);
    return true;
}

bool zcl_soak_judge(const struct zcl_soak_judge_opts *opts,
                    struct zcl_judge_result *out)
{
    struct soak_sample *samples;
    size_t len = 0, n = 0;
    int64_t malformed = 0;
    char *buf;
    bool ok;
    if (!opts || !opts->file || !out)
        return false;
    memset(out, 0, sizeof(*out));
    buf = ej_slurp(opts->file, SOAK_FILE_MAX, &len);
    if (!buf) {
        ej_cat(out, "soak-evidence: judge window_hours=%lld file=%s file_samples=0\n",
               (long long)opts->window_hours, opts->file);
        soak_set(out, "INSUFFICIENT", "no_evidence_file");
        soak_finish(out);
        return true;
    }
    samples = soak_parse(buf, &n, &malformed);
    ok = samples != NULL && soak_judge_samples(opts, samples, n, malformed, out);
    free(samples);
    free(buf);
    return ok;
}

bool zcl_soak_judge_defaults(struct zcl_soak_judge_opts *opts, char *path,
                             size_t cap, char *err, size_t err_cap)
{
    const char *dir = getenv("ZCL_SOAK_EVIDENCE_DIR");
    const char *home = getenv("HOME");
    int64_t now = 0;
    memset(opts, 0, sizeof(*opts));
    opts->window_hours = ZCL_SOAK_WINDOW_HOURS;
    if (ej_env_int("ZCL_SOAK_NOW", getenv("ZCL_SOAK_NOW"), &now, err, err_cap) < 0)
        return false;
    opts->now_unix = now;
    if (dir && dir[0])
        (void)snprintf(path, cap, "%s/evidence.jsonl", dir);
    else
        (void)snprintf(path, cap,
                       "%s/.local/state/zclassic23-soak-evidence/evidence.jsonl",
                       home && home[0] ? home : "/root");
    opts->file = path;
    return true;
}
