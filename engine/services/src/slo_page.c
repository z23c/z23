/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * External SLO pager. Folds the prober ledger into four page conditions
 * (stale ledger, thin probe coverage, canonical unreachable, canonical
 * without a confirmed climb) and announces each active condition at most
 * once per renotify interval. Reads only what an outside client recorded. */
// one-result-type-ok:typed-report-struct — each entry point fills a report struct that names the failing condition; the bool only says whether the ledger I/O completed.

#include "services/slo_monitor.h"

#include "base/safe_alloc.h"

#include "services/evidence_ledger_row.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { PAGE_NAMES = 16, PAGE_MIN_SAMPLES = 3, PAGE_BLOCKER_MAX = 400 };

struct canon {
    struct slo_stamp at;
    bool reach;
    struct slo_opt served, oracle, gap;
};

struct page_data {
    struct canon *v;
    size_t n, cap;
    bool oom;
    char names[PAGE_NAMES][SLO_NAME_MAX];
    int64_t newest[PAGE_NAMES];
    size_t nnames;
};

static bool name_chars_ok(const char *s)
{
    if (!s[0])
        return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              (*s >= '0' && *s <= '9') || *s == '_'))
            return false;
    return true;
}

static void note_newest(struct page_data *d, const char *name, int64_t ts)
{
    for (size_t i = 0; i < d->nnames; i++)
        if (strcmp(d->names[i], name) == 0) {
            if (ts > d->newest[i])
                d->newest[i] = ts;
            return;
        }
    if (d->nnames < PAGE_NAMES) {
        snprintf(d->names[d->nnames], SLO_NAME_MAX, "%s", name);
        d->newest[d->nnames++] = ts;
    }
}

static void push_canon(struct page_data *d, const char *row, size_t len,
                       int64_t ts)
{
    if (d->n == d->cap) {
        size_t cap = d->cap ? d->cap * 2 : 4096;
        struct canon *grown = zcl_realloc(d->v, cap * sizeof(*grown), "slo_page");
        if (!grown) {
            d->oom = true;
            return;
        }
        d->v = grown;
        d->cap = cap;
    }
    struct canon *c = &d->v[d->n];
    memset(c, 0, sizeof(*c));
    c->at.ts = ts;
    c->at.seq = d->n++;
    (void)evidence_row_bool(row, len, "reachable", &c->reach);
    c->served.has = evidence_row_int(row, len, "served_height", &c->served.v);
    c->oracle.has = evidence_row_int(row, len, "oracle_height", &c->oracle.v);
    c->gap.has = evidence_row_int(row, len, "gap_vs_oracle", &c->gap.v);
}

static void page_row(const char *row, size_t len, void *ctx)
{
    struct page_data *d = ctx;
    char name[SLO_NAME_MAX];
    int64_t ts;
    if (!evidence_row_flat_object_valid(row, len) ||
        !evidence_row_int(row, len, "ts", &ts) ||
        !evidence_row_str(row, len, "instance", name, sizeof(name)) ||
        !name_chars_ok(name))
        return;
    note_newest(d, name, ts);
    if (strcmp(name, "canonical") == 0)
        push_canon(d, row, len, ts);
}

static bool load_ledger(const char *path, struct page_data *d)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0)
        return false;
    size_t tail = (size_t)st.st_size < (size_t)(256u << 20)
                      ? (size_t)st.st_size : (size_t)(256u << 20);
    if (!evidence_ledger_scan_tail(path, tail, page_row, d, NULL, NULL) ||
        d->oom)
        return false;
    if (d->n > 1)
        qsort(d->v, d->n, sizeof(*d->v), slo_stamp_cmp);
    return true;
}

static void add_cond(struct slo_page_eval *out, const char *id,
                     const struct page_data *d, const char *fmt, ...)
    ZCL_PRINTF_LIKE(4, 5);

static void add_cond(struct slo_page_eval *out, const char *id,
                     const struct page_data *d, const char *fmt, ...)
{
    if (out->ncond >= SLO_PAGE_COND_MAX)
        return;
    struct slo_page_cond *c = &out->cond[out->ncond++];
    snprintf(c->id, sizeof(c->id), "%s", id);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
    if (d && d->n > 0) {
        const struct canon *last = &d->v[d->n - 1];
        c->served = last->served;
        c->oracle = last->oracle;
        c->gap = last->gap;
    }
}

static bool live_has(const char *live, const char *name)
{
    size_t n = strlen(name);
    for (const char *p = live; *p;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == n && strncmp(p, name, n) == 0)
            return true;
        p += len + (comma ? 1 : 0);
    }
    return false;
}

static bool eval_stale(const struct page_data *d,
                       const struct slo_page_config *cfg,
                       struct slo_page_eval *out)
{
    const char *worst = NULL;
    int64_t worst_age = -1;
    for (size_t i = 0; i < d->nnames; i++) {
        if (cfg->live[0] && !live_has(cfg->live, d->names[i]))
            continue;
        int64_t age = cfg->now - d->newest[i];
        if (!worst || age > worst_age ||
            (age == worst_age && strcmp(d->names[i], worst) < 0)) {
            worst_age = age;
            worst = d->names[i];
        }
    }
    if (!worst || worst_age <= cfg->stale_sec)
        return false;
    add_cond(out, "stale_ledger", d,
             "instance=%s newest_sample_age=%llds exceeds stale threshold "
             "%llds (prober may be dead)",
             worst, (long long)worst_age, (long long)cfg->stale_sec);
    return true;
}

/* Returns the observed/expected sample ratio; 1 when the window is too short
 * to judge. Adds the condition when the ratio is below the floor. */
static double eval_coverage(const struct page_data *d,
                            const struct slo_page_config *cfg,
                            struct slo_page_eval *out, bool *fired)
{
    int64_t cutoff = cfg->now - cfg->cov_window_sec, seen = 0;
    for (size_t i = 0; i < d->n; i++)
        seen += d->v[i].at.ts >= cutoff;
    int64_t first = d->n ? d->v[0].at.ts : cfg->now;
    int64_t window = cfg->cov_window_sec;
    if (cfg->now - first < window)
        window = cfg->now - first;
    *fired = false;
    if (window < cfg->cov_cadence_sec * 3)
        return 1.0;
    double expected = (double)window / (double)cfg->cov_cadence_sec;
    double ratio = expected > 0 ? (double)seen / expected : 1.0;
    if (ratio < cfg->cov_min_ratio) {
        *fired = true;
        add_cond(out, "probe_coverage", d,
                 "probe coverage %d%% (%lld/%d expected canonical samples in "
                 "trailing %llds at %llds cadence) -- prober/timer likely "
                 "stalling (e.g. user-manager), independent of node health",
                 (int)(ratio * 100), (long long)seen, (int)expected,
                 (long long)window, (long long)cfg->cov_cadence_sec);
    }
    return ratio;
}

static bool eval_unreachable(const struct page_data *d,
                             const struct slo_page_config *cfg,
                             struct slo_page_eval *out)
{
    int64_t cutoff = cfg->now - cfg->unreach_sec, in_window = 0, up = 0;
    for (size_t i = 0; i < d->n; i++)
        if (d->v[i].at.ts >= cutoff) {
            in_window++;
            up += d->v[i].reach;
        }
    if (in_window < PAGE_MIN_SAMPLES || up != 0 || d->n == 0 ||
        d->v[d->n - 1].reach)
        return false;
    add_cond(out, "canonical_unreachable", d,
             "canonical unreachable: %lld samples in last %llds all "
             "reachable=false (newest sample age=%llds)",
             (long long)in_window, (long long)cfg->unreach_sec,
             (long long)(cfg->now - d->v[d->n - 1].at.ts));
    return true;
}

/* Index into the reachable subsequence of the newest corroborated climb,
 * or 0 (the oldest reachable sample) when the ledger holds none. */
static size_t confirmed_climb(const struct canon *const *r, size_t rn,
                              int64_t min_trailing)
{
    for (size_t i = rn - 1; i >= 1; i--)
        if (r[i]->served.v > r[i - 1]->served.v &&
            (int64_t)(rn - 1 - i) >= min_trailing)
            return i;
    return 0;
}

static bool eval_no_advance(const struct page_data *d,
                            const struct slo_page_config *cfg,
                            struct slo_page_eval *out)
{
    const struct canon **r = zcl_malloc((d->n ? d->n : 1) * sizeof(*r), "slo_page");
    size_t rn = 0;
    bool fired = false;
    if (!r)
        return false;
    for (size_t i = 0; i < d->n; i++)
        if (d->v[i].reach && d->v[i].served.has)
            r[rn++] = &d->v[i];
    if (rn > 0) {
        size_t adv = confirmed_climb(r, rn, cfg->adv_min_trailing);
        int64_t age = cfg->now - r[adv]->at.ts;
        int64_t trailing = (int64_t)(rn - 1 - adv);
        if (age > cfg->advance_sec && trailing >= cfg->adv_min_trailing) {
            fired = true;
            add_cond(out, "canonical_no_advance", d,
                     "canonical no net advance: served_height held at %lld "
                     "for %llds since last confirmed climb (to %lld) at "
                     "ts=%lld (advance_sec=%lld), %lld reachable samples "
                     "observed since with zero climb",
                     (long long)r[rn - 1]->served.v, (long long)age,
                     (long long)r[adv]->served.v, (long long)r[adv]->at.ts,
                     (long long)cfg->advance_sec, (long long)trailing);
        }
    }
    free(r);
    return fired;
}

static void fold_conditions(const struct page_data *d,
                            const struct slo_page_config *cfg,
                            struct slo_page_eval *out)
{
    struct slo_page_eval staged;
    memset(&staged, 0, sizeof(staged));
    bool stale = eval_stale(d, cfg, &staged);
    bool thin = false;
    double ratio = eval_coverage(d, cfg, &staged, &thin);
    bool dark = eval_unreachable(d, cfg, &staged);
    bool flat = eval_no_advance(d, cfg, &staged);
    /* Fixed announcement order: self-watchdog first. */
    static const char *const order[] = { "stale_ledger", "probe_coverage",
                                         "canonical_unreachable",
                                         "canonical_no_advance" };
    for (size_t o = 0; o < 4; o++)
        for (size_t i = 0; i < staged.ncond; i++)
            if (strcmp(staged.cond[i].id, order[o]) == 0)
                out->cond[out->ncond++] = staged.cond[i];
    if (d->n > 0)
        snprintf(out->summary, sizeof(out->summary),
                 "canonical_samples=%zu newest_canonical_age=%llds stale=%d "
                 "unreachable=%d no_advance=%d coverage_ratio=%.2f",
                 d->n, (long long)(cfg->now - d->v[d->n - 1].at.ts), stale,
                 dark, flat, ratio);
    else
        snprintf(out->summary, sizeof(out->summary),
                 "canonical_samples=0 newest_canonical_age=na stale=%d "
                 "unreachable=%d no_advance=%d coverage_ratio=%.2f",
                 stale, dark, flat, ratio);
}

bool slo_page_evaluate(const char *ledger_path,
                       const struct slo_page_config *cfg,
                       struct slo_page_eval *out)
{
    if (!ledger_path || !cfg || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct page_data d;
    memset(&d, 0, sizeof(d));
    bool loaded = load_ledger(ledger_path, &d);
    if (d.oom) {
        free(d.v);
        return false;
    }
    if (!loaded) {
        add_cond(out, "stale_ledger", NULL,
                 "ledger file missing or empty at %s (prober has written no "
                 "sample; it may be dead or never started)", ledger_path);
        snprintf(out->summary, sizeof(out->summary),
                 "canonical_samples=0 newest_canonical_age=na stale=1 "
                 "unreachable=0 no_advance=0 reason=no_ledger_file");
    } else {
        fold_conditions(&d, cfg, out);
    }
    free(d.v);
    return true;
}

static void page_line(struct slo_text *t, int64_t now,
                      const struct slo_page_cond *c, const char *detail)
{
    slo_text_addf(t, "{\"ts\":%lld,\"condition\":", (long long)now);
    slo_json_escape(t, c->id);
    slo_text_addf(t, ",\"detail\":");
    slo_json_escape(t, detail);
    slo_text_addf(t, ",\"served_height\":");
    slo_json_opt(t, c->served);
    slo_text_addf(t, ",\"oracle_height\":");
    slo_json_opt(t, c->oracle);
    slo_text_addf(t, ",\"gap_vs_oracle\":");
    slo_json_opt(t, c->gap);
    slo_text_addf(t, "}");
}

static bool recently_announced(const struct slo_page_config *cfg,
                               const struct slo_page_cond *c,
                               int64_t *since)
{
    char file[48], path[SLO_PATH_MAX], text[32];
    snprintf(file, sizeof(file), "%s.last", c->id);
    if (!slo_monitor_state_file("page-state", file, false, path,
                                sizeof(path)) ||
        !slo_monitor_read_line(path, text, sizeof(text)))
        return false;
    int64_t last = slo_parse_i64(text, 0);
    *since = cfg->now - (last > 0 ? last : 0);
    return *since < cfg->renotify_sec;
}

static void remember_announcement(const struct slo_page_config *cfg,
                                  const struct slo_page_cond *c)
{
    char file[48], path[SLO_PATH_MAX], text[32];
    snprintf(file, sizeof(file), "%s.last", c->id);
    if (!slo_monitor_state_file("page-state", file, true, path,
                                sizeof(path)))
        return;
    snprintf(text, sizeof(text), "%lld\n", (long long)cfg->now);
    (void)slo_monitor_write_atomic(path, text);
}

static void announce_one(const struct slo_page_config *cfg,
                         const struct slo_page_io *io,
                         const struct slo_page_cond *c,
                         struct slo_page_outcome *out)
{
    int64_t since = 0;
    if (recently_announced(cfg, c, &since)) {
        out->deduped++;
        SLO_NOTE(out, "WARN condition=%s ACTIVE but deduped (last announced "
                      "%llds ago < renotify %llds)",
                 c->id, (long long)since, (long long)cfg->renotify_sec);
        return;
    }
    char blocker[PAGE_BLOCKER_MAX + 1] = "", detail[1024], line[SLO_LINE_MAX];
    char pages[SLO_PATH_MAX];
    if (io && io->blocker)
        (void)io->blocker(io->ctx, blocker, sizeof(blocker));
    if (blocker[0])
        snprintf(detail, sizeof(detail), "%s | blocker=%s", c->detail, blocker);
    else
        snprintf(detail, sizeof(detail), "%s", c->detail);
    struct slo_text t;
    slo_text_init(&t, line, sizeof(line));
    page_line(&t, cfg->now, c, detail);
    if (t.overflow || !slo_monitor_file("pages.jsonl", pages, sizeof(pages)) ||
        !slo_monitor_append(pages, line))
        SLO_NOTE(out, "FAIL could not append the page record for %s", c->id);
    remember_announcement(cfg, c);
    if (cfg->wall && io && io->broadcast) {
        char msg[1200];
        snprintf(msg, sizeof(msg), "z23 SLO PAGE [%s]: %s", c->id, detail);
        io->broadcast(io->ctx, msg);
    }
    out->announced++;
    SLO_NOTE(out, "WARN PAGE condition=%s detail=%s", c->id, detail);
}

bool slo_page_announce(const struct slo_page_config *cfg,
                       const struct slo_page_io *io,
                       const struct slo_page_eval *eval,
                       struct slo_page_outcome *out)
{
    if (!cfg || !eval || !out)
        return false;
    memset(out, 0, sizeof(*out));
    char dir[SLO_PATH_MAX];
    if (eval->ncond > 0 &&
        (!slo_monitor_dir(dir, sizeof(dir)) || !slo_monitor_mkdir_p(dir)))
        return false;
    for (size_t i = 0; i < eval->ncond; i++)
        announce_one(cfg, io, &eval->cond[i], out);
    return true;
}
