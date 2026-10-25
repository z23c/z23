/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The MVP C8 parity window judge. Reads parity.jsonl, the hourly
 *          ledger of our-vs-zclassicd block hash comparisons, and returns
 *          MET, NOT_MET or INSUFFICIENT over the trailing window anchored at
 *          the last sample.
 *
 * It reuses the C6 constants (hole threshold, window slack, 90 % reachability)
 * so both rows demand the same observation. Any `"match":false` in the window
 * is NOT_MET and names the first height and both hashes; every other
 * shortfall (short window, hole, thin samples, stale tail) is INSUFFICIENT,
 * never a pass. */

#include "native_evidence_judge_util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAR_FILE_MAX ((size_t)1 << 30)
#define PAR_HASH_MAX 80

struct par_stats {
    int64_t cnt, ok_cnt, hole_max, first_ts, prev_ts;
    bool have_mismatch;
    int64_t mismatch_height;
    char ours[PAR_HASH_MAX], oracle[PAR_HASH_MAX];
};

static void par_note_mismatch(const char *line, struct par_stats *st)
{
    struct ej_num h;
    if (st->have_mismatch)
        return;
    st->have_mismatch = true;
    h = ej_field_num(line, "height", false);
    st->mismatch_height = h.kind == EJ_NUM ? h.n : -1;
    if (!ej_field_str(line, "our_hash", st->ours, sizeof(st->ours)))
        (void)snprintf(st->ours, sizeof(st->ours), "null");
    if (!ej_field_str(line, "oracle_hash", st->oracle, sizeof(st->oracle)))
        (void)snprintf(st->oracle, sizeof(st->oracle), "null");
}

static void par_scan_line(const char *line, int64_t cutoff, struct par_stats *st)
{
    struct ej_num ts = ej_field_num(line, "ts", false);
    if (ts.kind != EJ_NUM || ts.n < cutoff)
        return;
    if (st->cnt == 0)
        st->first_ts = ts.n;
    else if (ts.n - st->prev_ts > st->hole_max)
        st->hole_max = ts.n - st->prev_ts;
    st->prev_ts = ts.n;
    st->cnt++;
    if (strstr(line, "\"ok\":true"))
        st->ok_cnt++;
    if (strstr(line, "\"match\":false"))
        par_note_mismatch(line, st);
}

/* The buffer holds NUL-split lines; walk them in order. */
static int64_t par_last_ts(const char *buf, size_t len)
{
    int64_t last = -1;
    for (size_t off = 0; off < len; off += strlen(buf + off) + 1) {
        struct ej_num ts = ej_field_num(buf + off, "ts", false);
        if (ts.kind == EJ_NUM && ts.n > last)
            last = ts.n;
    }
    return last;
}

static void par_set(struct zcl_judge_result *out, const char *v, const char *fmt,
                    ...) ZCL_PRINTF_LIKE(3, 4);

static void par_set(struct zcl_judge_result *out, const char *v, const char *fmt,
                    ...)
{
    char reason[ZCL_JUDGE_REASON_MAX];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(reason, sizeof(reason), fmt, args);
    va_end(args);
    ej_verdict(out, 0, v, reason);
}

static void par_ladder(const struct par_stats *st, int64_t need_sec, int64_t age,
                       const struct zcl_soak_judge_opts *o,
                       struct zcl_judge_result *out)
{
    int64_t covered = st->cnt > 0 ? st->prev_ts - st->first_ts : 0;
    if (st->have_mismatch)
        par_set(out, "NOT_MET", "parity_mismatch_height_%lld_ours_%s_oracle_%s",
                (long long)st->mismatch_height, st->ours, st->oracle);
    else if (st->cnt < 2)
        par_set(out, "INSUFFICIENT", "too_few_samples");
    else if (covered + ZCL_SOAK_WINDOW_SLACK_SEC < need_sec)
        par_set(out, "INSUFFICIENT", "window_short_%llds_lt_%llds_slack%ds",
                (long long)covered, (long long)need_sec,
                ZCL_SOAK_WINDOW_SLACK_SEC);
    else if (st->hole_max > ZCL_SOAK_HOLE_THRESHOLD_SEC)
        par_set(out, "INSUFFICIENT", "sampling_hole_%llds_gt_%ds",
                (long long)st->hole_max, ZCL_SOAK_HOLE_THRESHOLD_SEC);
    else if (st->ok_cnt * 100 < st->cnt * 90)
        par_set(out, "INSUFFICIENT", "oracle_coverage_thin_ok_%lld_of_%lld",
                (long long)st->ok_cnt, (long long)st->cnt);
    else if (!o->allow_stale && age > ZCL_SOAK_HOLE_THRESHOLD_SEC)
        par_set(out, "INSUFFICIENT", "stale_evidence_age_%llds", (long long)age);
    else
        par_set(out, "MET", "covered_%.1fh_hole_max_%llds_zero_mismatch",
                (double)covered / 3600.0, (long long)st->hole_max);
}

static void par_finish(struct zcl_judge_result *out)
{
    if (strcmp(out->verdict, "MET") == 0)
        out->exit_code = 0;
    else if (strcmp(out->verdict, "NOT_MET") == 0)
        out->exit_code = 1;
    else
        out->exit_code = 2;
    ej_cat(out, "parity-evidence: VERDICT=%s reason=%s\n", out->verdict,
           out->reason);
}

static void par_judge_buf(const struct zcl_soak_judge_opts *o, char *buf,
                          size_t len, struct zcl_judge_result *out)
{
    struct par_stats st;
    int64_t now = ej_now(o->now_unix), need = o->window_hours * 3600;
    int64_t last, cutoff;
    memset(&st, 0, sizeof(st));
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n')
            buf[i] = '\0';
    last = par_last_ts(buf, len);
    if (last < 0) {
        par_set(out, "INSUFFICIENT", "empty_log");
        par_finish(out);
        return;
    }
    cutoff = last - need - ZCL_SOAK_WINDOW_SLACK_SEC;
    for (size_t off = 0; off < len; off += strlen(buf + off) + 1)
        par_scan_line(buf + off, cutoff, &st);
    out->covered_hours = (double)(st.prev_ts - st.first_ts) / 3600.0;
    out->newest_age_sec = now - last;
    ej_cat(out,
           "parity-evidence: judge window_hours=%lld file=%s window_samples=%lld "
           "ok_samples=%lld max_sampling_hole_sec=%lld\n",
           (long long)o->window_hours, o->file, (long long)st.cnt,
           (long long)st.ok_cnt, (long long)st.hole_max);
    par_ladder(&st, need, now - last, o, out);
    par_finish(out);
}

bool zcl_parity_judge(const struct zcl_soak_judge_opts *opts,
                      struct zcl_judge_result *out)
{
    size_t len = 0;
    char *buf;
    if (!opts || !opts->file || !out)
        return false;
    memset(out, 0, sizeof(*out));
    buf = ej_slurp(opts->file, PAR_FILE_MAX, &len);
    if (!buf) {
        par_set(out, "INSUFFICIENT", "no_evidence_file");
        par_finish(out);
        return true;
    }
    par_judge_buf(opts, buf, len, out);
    free(buf);
    return true;
}
