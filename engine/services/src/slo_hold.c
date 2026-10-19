/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Trailing-window hold judge. Answers whether one instance satisfied the
 * hold bar continuously, reading only what the external prober recorded:
 * reachability, oracle gap, forward progress, zero pages, sample coverage and
 * freshness. A hole in the ledger is a hole in the proof, never a free pass. */
// one-result-type-ok:typed-report-struct — each entry point fills a report struct that names the failing condition; the bool only says whether the ledger I/O completed.

#include "services/slo_monitor.h"

#include "base/safe_alloc.h"

#include "services/evidence_ledger_row.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { HOLD_KNOWN = 3 };

struct hs {
    struct slo_stamp at;
    bool reach;
    struct slo_opt served, gap;
};

struct hold_data {
    const char *inst;
    struct hs *v;
    size_t n, cap;
    int64_t *pages;
    size_t np, pcap;
    bool oom;
};

struct reach_res {
    double pct;
    int64_t count, up, best_run, best_start;
    bool ok;
};

struct gap_res {
    struct slo_opt max;
    int64_t bad_ts, bad_val;
    bool bad, ok;
};

struct adv_res {
    bool ok;
    const char *kind;
    int64_t ts, val, prev, samples, buckets, span;
};

struct pages_res {
    int64_t count, worst;
    bool ok;
};

static const char *const k_known[HOLD_KNOWN] = { "canonical", "soak", "dev" };

bool slo_hold_instance_known(const char *name)
{
    for (size_t i = 0; name && i < HOLD_KNOWN; i++)
        if (strcmp(name, k_known[i]) == 0)
            return true;
    return false;
}

static void *grow(void *p, size_t *cap, size_t elem, bool *oom)
{
    size_t next = *cap ? *cap * 2 : 4096;
    void *q = zcl_realloc(p, next * elem, "slo_hold");
    if (!q) {
        *oom = true;
        return p;
    }
    *cap = next;
    return q;
}

static void ledger_row(const char *row, size_t len, void *ctx)
{
    struct hold_data *d = ctx;
    char name[SLO_NAME_MAX];
    int64_t ts;
    if (!evidence_row_flat_object_valid(row, len) ||
        !evidence_row_str(row, len, "instance", name, sizeof(name)) ||
        strcmp(name, d->inst) != 0 || !evidence_row_int(row, len, "ts", &ts))
        return;
    if (d->n == d->cap) {
        d->v = grow(d->v, &d->cap, sizeof(*d->v), &d->oom);
        if (d->n == d->cap)
            return;
    }
    struct hs *s = &d->v[d->n];
    memset(s, 0, sizeof(*s));
    s->at.ts = ts;
    s->at.seq = d->n++;
    (void)evidence_row_bool(row, len, "reachable", &s->reach);
    s->served.has = evidence_row_int(row, len, "served_height", &s->served.v);
    s->gap.has = evidence_row_int(row, len, "gap_vs_oracle", &s->gap.v);
}

static void pages_row(const char *row, size_t len, void *ctx)
{
    struct hold_data *d = ctx;
    char name[SLO_NAME_MAX];
    int64_t ts;
    if (!evidence_row_flat_object_valid(row, len) ||
        !evidence_row_int(row, len, "ts", &ts))
        return;
    if (evidence_row_str(row, len, "instance", name, sizeof(name)) &&
        strcmp(name, d->inst) != 0)
        return;
    if (d->np == d->pcap) {
        d->pages = grow(d->pages, &d->pcap, sizeof(*d->pages), &d->oom);
        if (d->np == d->pcap)
            return;
    }
    d->pages[d->np++] = ts;
}

static bool load_hold(const char *ledger, const char *pages,
                      struct hold_data *d)
{
    struct stat st;
    size_t tail = (size_t)256u << 20;
    if (pages && stat(pages, &st) == 0 && st.st_size > 0)
        (void)evidence_ledger_scan_tail(pages, tail, pages_row, d, NULL, NULL);
    if (stat(ledger, &st) == 0 && st.st_size > 0)
        (void)evidence_ledger_scan_tail(ledger, tail, ledger_row, d, NULL,
                                        NULL);
    if (d->n > 1)
        qsort(d->v, d->n, sizeof(*d->v), slo_stamp_cmp);
    return !d->oom;
}

static void say(struct slo_hold_report *r, const char *fmt, ...)
    ZCL_PRINTF_LIKE(2, 3);

static void say(struct slo_hold_report *r, const char *fmt, ...)
{
    if (r->nlines >= SLO_HOLD_LINES) {
        snprintf(r->lines[SLO_HOLD_LINES - 1], SLO_HOLD_LINE_LEN,
                 "slo-hold: report truncated at %u lines", SLO_HOLD_LINES);
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->lines[r->nlines++], SLO_HOLD_LINE_LEN, fmt, ap);
    va_end(ap);
}

static void verdict(struct slo_hold_report *r, const struct slo_hold_config *c,
                    int rc, const char *reason)
{
    r->rc = rc;
    r->proven = rc == 0;
    snprintf(r->verdict, sizeof(r->verdict), "%s",
             rc == 0 ? "HOLD_PROVEN" : "NOT_PROVEN");
    snprintf(r->reason, sizeof(r->reason), "%s", reason);
    if (rc == 0)
        say(r, "slo-hold: instance=%s window_hours=%lld VERDICT=HOLD_PROVEN",
            c->instance, (long long)c->window_hours);
    else
        say(r, "slo-hold: instance=%s window_hours=%lld VERDICT=NOT_PROVEN "
               "reason=%s",
            c->instance, (long long)c->window_hours, reason);
}

static void eval_reach(const struct hs *w, size_t n,
                       const struct slo_hold_config *c, struct reach_res *r)
{
    int64_t run_len = 0, run_start = 0;
    memset(r, 0, sizeof(*r));
    r->count = (int64_t)n;
    r->best_start = -1;
    for (size_t i = 0; i < n; i++) {
        if (!w[i].reach) {
            if (run_len++ == 0)
                run_start = w[i].at.ts;
            continue;
        }
        r->up++;
        if (run_len > 0 && w[i - 1].at.ts - run_start > r->best_run) {
            r->best_run = w[i - 1].at.ts - run_start;
            r->best_start = run_start;
        }
        run_len = 0;
    }
    if (run_len > 0 && w[n - 1].at.ts - run_start > r->best_run) {
        r->best_run = w[n - 1].at.ts - run_start;
        r->best_start = run_start;
    }
    r->pct = 100.0 * (double)r->up / (double)r->count;
    r->ok = r->pct >= c->reach_pct_min && r->best_run <= c->max_unreach_sec;
}

static void eval_gap(const struct hs *w, size_t n,
                     const struct slo_hold_config *c, struct gap_res *g)
{
    memset(g, 0, sizeof(*g));
    for (size_t i = 0; i < n; i++) {
        if (!w[i].reach || !w[i].gap.has)
            continue;
        int64_t v = w[i].gap.v;
        if (!g->max.has || v > g->max.v)
            g->max = (struct slo_opt){ true, v };
        if (v > c->gap_budget && (!g->bad || v > g->bad_val)) {
            g->bad = true;
            g->bad_val = v;
            g->bad_ts = w[i].at.ts;
        }
    }
    g->ok = !g->bad;
}

struct bucket_state {
    int64_t id, max, first_ts, prev_max;
    int64_t nth;
};

static void close_bucket(struct bucket_state *b, struct adv_res *a)
{
    if (b->nth >= 2 && a->ok && b->max <= b->prev_max) {
        a->ok = false;
        a->kind = "stall_no_advance_in_bucket";
        a->ts = b->first_ts;
        a->val = b->max;
        a->prev = b->prev_max;
    }
    b->prev_max = b->max;
}

static void bucket_add(struct bucket_state *b, struct adv_res *a,
                       const struct hs *s, int64_t width)
{
    int64_t id = s->at.ts / width;
    if (b->nth == 0 || id != b->id) {
        if (b->nth > 0)
            close_bucket(b, a);
        b->nth++;
        b->id = id;
        b->max = s->served.v;
        b->first_ts = s->at.ts;
        a->buckets++;
    } else if (s->served.v > b->max) {
        b->max = s->served.v;
    }
}

static void eval_advance(const struct hs *w, size_t n,
                         const struct slo_hold_config *c, struct adv_res *a)
{
    memset(a, 0, sizeof(*a));
    a->ok = true;
    const struct hs *first = NULL, *prev = NULL;
    for (size_t i = 0; i < n && a->ok; i++) {
        if (!w[i].reach || !w[i].served.has)
            continue;
        a->samples++;
        first = first ? first : &w[i];
        if (prev && w[i].served.v < prev->served.v) {
            a->ok = false;
            a->kind = "regressed";
            a->ts = w[i].at.ts;
            a->val = w[i].served.v;
            a->prev = prev->served.v;
        }
        prev = &w[i];
    }
    if (a->samples == 0) {
        a->ok = false;
        a->kind = "no_reachable_served_samples";
        return;
    }
    a->span = prev->served.v - first->served.v;
    if (!a->ok)
        return;
    struct bucket_state b = { 0 };
    for (size_t i = 0; i < n; i++)
        if (w[i].reach && w[i].served.has)
            bucket_add(&b, a, &w[i], c->bucket_sec);
    if (b.nth > 0)
        close_bucket(&b, a);
}

static void eval_pages(const struct hold_data *d, int64_t cutoff, int64_t last,
                       struct pages_res *p)
{
    memset(p, 0, sizeof(*p));
    for (size_t i = 0; i < d->np; i++) {
        if (d->pages[i] < cutoff || d->pages[i] > last)
            continue;
        if (p->count++ == 0 || d->pages[i] < p->worst)
            p->worst = d->pages[i];
    }
    p->ok = p->count == 0;
}

static void say_reach(struct slo_hold_report *r, const struct reach_res *x,
                      const struct slo_hold_config *c)
{
    if (x->ok) {
        say(r, "slo-hold: criterion=reachability met reachable_pct=%.2f "
               "samples=%lld reachable=%lld longest_unreachable_run_sec=%lld "
               "floor_pct=%g max_run_sec=%lld",
            x->pct, (long long)x->count, (long long)x->up,
            (long long)x->best_run, c->reach_pct_min,
            (long long)c->max_unreach_sec);
        return;
    }
    char start[24] = "-";
    if (x->best_start >= 0)
        snprintf(start, sizeof(start), "%lld", (long long)x->best_start);
    say(r, "slo-hold: criterion=reachability VIOLATED reachable_pct=%.2f "
           "samples=%lld reachable=%lld longest_unreachable_run_sec=%lld "
           "worst_run_start_ts=%s floor_pct=%g max_run_sec=%lld",
        x->pct, (long long)x->count, (long long)x->up, (long long)x->best_run,
        start, c->reach_pct_min, (long long)c->max_unreach_sec);
}

static void say_gap(struct slo_hold_report *r, const struct gap_res *g,
                    const struct slo_hold_config *c)
{
    if (!g->ok) {
        say(r, "slo-hold: criterion=gap_vs_oracle VIOLATED worst_ts=%lld "
               "gap_vs_oracle=%lld budget=%lld",
            (long long)g->bad_ts, (long long)g->bad_val,
            (long long)c->gap_budget);
        return;
    }
    char max[24] = "null";
    if (g->max.has)
        snprintf(max, sizeof(max), "%lld", (long long)g->max.v);
    say(r, "slo-hold: criterion=gap_vs_oracle met max_gap=%s budget=%lld", max,
        (long long)c->gap_budget);
}

static void say_adv(struct slo_hold_report *r, const struct adv_res *a,
                    const struct slo_hold_config *c)
{
    if (a->ok) {
        say(r, "slo-hold: criterion=served_advance met "
               "reachable_served_samples=%lld buckets=%lld span_advance=%lld "
               "bucket_sec=%lld",
            (long long)a->samples, (long long)a->buckets, (long long)a->span,
            (long long)c->bucket_sec);
        return;
    }
    char ts[24] = "-", val[24] = "-", prev[24] = "-";
    if (a->ts) {
        snprintf(ts, sizeof(ts), "%lld", (long long)a->ts);
        snprintf(val, sizeof(val), "%lld", (long long)a->val);
        snprintf(prev, sizeof(prev), "%lld", (long long)a->prev);
    }
    say(r, "slo-hold: criterion=served_advance VIOLATED kind=%s worst_ts=%s "
           "served=%s prev=%s bucket_sec=%lld",
        a->kind, ts, val, prev, (long long)c->bucket_sec);
}

static const char *first_violation(bool reach, bool gap, bool adv, bool pages,
                                   bool cov, bool fresh)
{
    if (!reach)
        return "reachability";
    if (!gap)
        return "gap_vs_oracle";
    if (!adv)
        return "served_advance";
    if (!pages)
        return "pages";
    if (!cov)
        return "coverage";
    return fresh ? "" : "freshness";
}

static void judge_window(const struct hold_data *d,
                         const struct slo_hold_config *c,
                         struct slo_hold_report *r)
{
    int64_t last = d->v[d->n - 1].at.ts, cutoff = last - c->window_hours * 3600;
    size_t i0 = 0;
    while (i0 + 1 < d->n && d->v[i0].at.ts < cutoff)
        i0++;
    const struct hs *w = d->v + i0;
    size_t n = d->n - i0;
    struct reach_res rr;
    struct gap_res gr;
    struct adv_res ar;
    struct pages_res pr;
    eval_reach(w, n, c, &rr);
    eval_gap(w, n, c, &gr);
    eval_advance(w, n, c, &ar);
    eval_pages(d, cutoff, last, &pr);
    int64_t expected = c->window_hours * 3600 / c->cadence_sec;
    double cov = expected > 0 ? 100.0 * (double)n / (double)expected : 0;
    int64_t age = c->now - last;
    bool cov_ok = cov >= c->cov_pct_min, fresh_ok = age <= c->max_age_sec;
    say_reach(r, &rr, c);
    say_gap(r, &gr, c);
    say_adv(r, &ar, c);
    if (pr.ok)
        say(r, "slo-hold: criterion=pages met pages_in_window=0");
    else
        say(r, "slo-hold: criterion=pages VIOLATED pages_in_window=%lld "
               "worst_ts=%lld", (long long)pr.count, (long long)pr.worst);
    say(r, "slo-hold: criterion=coverage %s samples=%lld expected=%lld "
           "coverage_pct=%.2f floor_pct=%g", cov_ok ? "met" : "VIOLATED",
        (long long)n, (long long)expected, cov, c->cov_pct_min);
    say(r, "slo-hold: criterion=freshness %s newest_ts=%lld newest_age_sec=%lld "
           "max_age_sec=%lld", fresh_ok ? "met" : "VIOLATED", (long long)last,
        (long long)age, (long long)c->max_age_sec);
    const char *why = first_violation(rr.ok, gr.ok, ar.ok, pr.ok, cov_ok,
                                      fresh_ok);
    verdict(r, c, why[0] ? 1 : 0, why);
}

static bool config_valid(const struct slo_hold_config *c)
{
    return c && slo_hold_instance_known(c->instance) && c->window_hours > 0 &&
           c->cadence_sec > 0 && c->bucket_sec > 0;
}

bool slo_hold_judge(const char *ledger_path, const char *pages_path,
                    const struct slo_hold_config *cfg,
                    struct slo_hold_report *out)
{
    if (!ledger_path || !out || !config_valid(cfg))
        return false;
    memset(out, 0, sizeof(*out));
    struct stat st;
    if (stat(ledger_path, &st) != 0 || st.st_size <= 0) {
        say(out, "slo-hold: instance=%s window_hours=%lld file=%s "
                 "file_samples=0", cfg->instance, (long long)cfg->window_hours,
            ledger_path);
        verdict(out, cfg, 4, "no_ledger_file");
        return true;
    }
    struct hold_data d = { .inst = cfg->instance };
    bool loaded = load_hold(ledger_path, pages_path, &d);
    if (loaded && d.n == 0) {
        say(out, "slo-hold: instance=%s window_hours=%lld probe_count=0",
            cfg->instance, (long long)cfg->window_hours);
        verdict(out, cfg, 3, "no_samples");
    } else if (loaded) {
        judge_window(&d, cfg, out);
    }
    free(d.v);
    free(d.pages);
    return loaded;
}

bool slo_hold_record(const struct slo_hold_config *cfg,
                     const struct slo_hold_report *report)
{
    char path[SLO_PATH_MAX], dir[SLO_PATH_MAX], line[SLO_LINE_MAX];
    if (!cfg || !report || !slo_monitor_dir(dir, sizeof(dir)) ||
        !slo_monitor_mkdir_p(dir) ||
        !slo_monitor_file("hold-ledger.jsonl", path, sizeof(path)))
        return false;
    struct slo_text t;
    slo_text_init(&t, line, sizeof(line));
    slo_text_addf(&t, "{\"ts\":%lld,\"instance\":", (long long)cfg->now);
    slo_json_escape(&t, cfg->instance);
    slo_text_addf(&t, ",\"window_hours\":%lld,\"gap_budget\":%lld,\"verdict\":",
                  (long long)cfg->window_hours, (long long)cfg->gap_budget);
    slo_json_escape(&t, report->verdict[0] ? report->verdict : "JUDGE_ERROR");
    slo_text_addf(&t, ",\"reason\":");
    slo_json_escape(&t, report->reason);
    slo_text_addf(&t, ",\"judge_rc\":%d}", report->rc);
    return !t.overflow && slo_monitor_append(path, line);
}
