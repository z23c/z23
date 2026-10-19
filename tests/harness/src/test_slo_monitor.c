/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression contract for the node SLO monitors (prober, pager, hold judge).
 * Every case runs over fixture ledgers in an isolated directory and fake
 * observers: no node, systemd unit or network is touched. */

#include "test/test_core.h"

#include "command/slo_monitor_io.h"
#include "services/slo_monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MON_CHECK(name_, expr_) do {                                     \
    printf("slo_monitor: %s... ", (name_));                              \
    if (expr_)                                                           \
        printf("OK\n");                                                  \
    else {                                                               \
        printf("FAIL\n");                                                \
        failures++;                                                      \
    }                                                                    \
} while (0)

static char g_dir[256];
static const int64_t BASE = 1700000000;

static bool fresh_dir(void)
{
    if (g_dir[0])
        (void)test_rm_rf_recursive(g_dir);
    if (!test_mkdtemp(g_dir, sizeof(g_dir), "slo_monitor"))
        return false;
    return setenv("ZCL_SLO_LEDGER_DIR", g_dir, 1) == 0;
}

static void path_of(const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", g_dir, name);
}

static char *slurp(const char *name)
{
    char path[512];
    path_of(name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    char *buf = calloc(1, 1u << 20);
    size_t got = buf ? fread(buf, 1, (1u << 20) - 1, f) : 0;
    if (buf)
        buf[got] = '\0';
    fclose(f);
    return buf;
}

static size_t count_lines(const char *name)
{
    char *text = slurp(name);
    size_t n = 0;
    for (const char *p = text; p && *p; p++)
        n += *p == '\n';
    free(text);
    return n;
}

static bool file_has(const char *name, const char *needle)
{
    char *text = slurp(name);
    bool found = text && strstr(text, needle);
    free(text);
    return found;
}

static bool exists(const char *name)
{
    char path[512];
    path_of(name, path, sizeof(path));
    return access(path, F_OK) == 0;
}

/* ---- ledger fixtures ---- */

static void put(const char *inst, int64_t ts, bool reach, int64_t served,
                int64_t oracle, int64_t gap)
{
    char path[512];
    path_of("uptime-ledger.jsonl", path, sizeof(path));
    FILE *f = fopen(path, "a");
    if (!f)
        return;
    char sv[24] = "null", orc[24] = "null", gp[24] = "null";
    if (served >= 0)
        snprintf(sv, sizeof(sv), "%lld", (long long)served);
    if (oracle >= 0)
        snprintf(orc, sizeof(orc), "%lld", (long long)oracle);
    if (gap >= 0)
        snprintf(gp, sizeof(gp), "%lld", (long long)gap);
    fprintf(f,
            "{\"ts\":%lld,\"instance\":\"%s\",\"rpcport\":1,\"datadir\":"
            "\"/x\",\"reachable\":%s,\"served_height\":%s,\"header_height\":"
            "%s,\"latency_ms\":1,\"oracle_height\":%s,\"max_height\":%s,"
            "\"gap_vs_max\":0,\"gap_vs_oracle\":%s,\"error_detail\":\"\"}\n",
            (long long)ts, inst, reach ? "true" : "false", sv, sv, orc, orc,
            gp);
    fclose(f);
}

struct shape {
    int64_t n, step, sv0, svstep, gap;
    int64_t down_lo, down_hi, breach_at, breach_gap;
};

static void emit(const char *inst, int64_t base, const struct shape *s)
{
    for (int64_t i = 0; i < s->n; i++) {
        int64_t ts = base + i * s->step;
        if (i >= s->down_lo && i <= s->down_hi) {
            put(inst, ts, false, -1, -1, -1);
            continue;
        }
        int64_t sv = s->sv0 + i * s->svstep;
        int64_t g = i == s->breach_at ? s->breach_gap : s->gap;
        put(inst, ts, true, sv, sv + g, g);
    }
}

static struct shape dense72(void)
{
    return (struct shape){ .n = 4320, .step = 60, .sv0 = 3000000,
                           .svstep = 1, .gap = 0, .down_lo = -1,
                           .down_hi = -1, .breach_at = -1 };
}

/* ---- pager ---- */

static struct slo_page_config page_cfg(int64_t now)
{
    return (struct slo_page_config){
        .now = now, .stale_sec = 300, .unreach_sec = 600,
        .advance_sec = 7200, .adv_min_trailing = 2, .cov_window_sec = 3600,
        .cov_cadence_sec = 60, .renotify_sec = 21600, .cov_min_ratio = 0.5,
        .live = "canonical,dev", .wall = false,
    };
}

struct page_fake {
    int blockers;
    int broadcasts;
};

static size_t fake_blocker(void *ctx, char *out, size_t cap)
{
    ((struct page_fake *)ctx)->blockers++;
    snprintf(out, cap, "{\"active_count\":1}");
    return strlen(out);
}

static void fake_broadcast(void *ctx, const char *text)
{
    (void)text;
    ((struct page_fake *)ctx)->broadcasts++;
}

/* Evaluate the fixture ledger and announce; returns the condition count. */
static size_t run_page(const struct slo_page_config *cfg,
                       struct slo_page_eval *eval,
                       struct slo_page_outcome *out, struct page_fake *fake)
{
    char ledger[512];
    struct slo_page_io io = { .ctx = fake, .blocker = fake_blocker,
                              .broadcast = fake_broadcast };
    path_of("uptime-ledger.jsonl", ledger, sizeof(ledger));
    if (!slo_page_evaluate(ledger, cfg, eval) ||
        !slo_page_announce(cfg, &io, eval, out))
        return (size_t)-1;
    return eval->ncond;
}

static bool has_cond(const struct slo_page_eval *e, const char *id)
{
    for (size_t i = 0; i < e->ncond; i++)
        if (strcmp(e->cond[i].id, id) == 0)
            return true;
    return false;
}

static void flat_run(int64_t base, int64_t n, int64_t step, int64_t served)
{
    for (int64_t k = 0; k < n; k++)
        put("canonical", base + k * step, true, served, 100, 100 - served);
}

static bool page_advancing_is_quiet(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    for (int k = 0; k < 8; k++)
        put("canonical", BASE + k * 500, true, 10 + k, 100, 90 - k);
    struct slo_page_config c = page_cfg(BASE + 7 * 500);
    c.stale_sec = 10000;
    c.advance_sec = 4000;
    c.cov_min_ratio = 0;
    return run_page(&c, &e, &o, &fake) == 0 && !exists("pages.jsonl") &&
           strstr(e.summary, "canonical_samples=8") != NULL;
}

static bool page_flat_dedups_then_renotifies(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    flat_run(BASE, 9, 500, 10);
    struct slo_page_config c = page_cfg(BASE + 9 * 500);
    c.stale_sec = 10000;
    c.advance_sec = 4000;
    c.renotify_sec = 100;
    c.cov_min_ratio = 0;
    bool first = run_page(&c, &e, &o, &fake) == 1 && o.announced == 1 &&
                 has_cond(&e, "canonical_no_advance") &&
                 count_lines("pages.jsonl") == 1 && fake.blockers == 1 &&
                 file_has("pages.jsonl", "| blocker={");
    bool dedup = run_page(&c, &e, &o, &fake) == 1 && o.deduped == 1 &&
                 o.announced == 0 && count_lines("pages.jsonl") == 1;
    c.now += 200;
    bool again = run_page(&c, &e, &o, &fake) == 1 && o.announced == 1 &&
                 count_lines("pages.jsonl") == 2;
    return first && dedup && again;
}

static bool page_wall_follows_config(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    flat_run(BASE, 9, 500, 10);
    struct slo_page_config c = page_cfg(BASE + 9 * 500);
    c.stale_sec = 10000;
    c.advance_sec = 4000;
    c.cov_min_ratio = 0;
    bool quiet = run_page(&c, &e, &o, &fake) == 1 && fake.broadcasts == 0;
    c.wall = true;
    c.renotify_sec = 0;
    return quiet && run_page(&c, &e, &o, &fake) == 1 && fake.broadcasts == 1;
}

static bool page_stale_and_retired(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    put("retired_lane", BASE, true, 5, 100, 95);
    put("canonical", BASE + 100000, true, 5, 100, 95);
    struct slo_page_config c = page_cfg(BASE + 100000);
    snprintf(c.live, sizeof(c.live), "canonical");
    c.cov_min_ratio = 0;
    bool retired_quiet = run_page(&c, &e, &o, &fake) == 0;
    snprintf(c.live, sizeof(c.live), "canonical,retired_lane");
    return retired_quiet && run_page(&c, &e, &o, &fake) == 1 &&
           has_cond(&e, "stale_ledger") &&
           strstr(e.cond[0].detail, "instance=retired_lane") != NULL;
}

static bool page_unreachable_and_missing(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    for (int k = 0; k < 4; k++)
        put("canonical", BASE + k * 60, false, -1, -1, -1);
    struct slo_page_config c = page_cfg(BASE + 180);
    bool dark = run_page(&c, &e, &o, &fake) == 1 &&
                has_cond(&e, "canonical_unreachable");
    if (!fresh_dir())
        return false;
    c = page_cfg(BASE);
    return dark && run_page(&c, &e, &o, &fake) == 1 &&
           has_cond(&e, "stale_ledger") &&
           strstr(e.summary, "reason=no_ledger_file") != NULL;
}

static bool page_probe_gap_cannot_mask_a_stall(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    for (int k = 0; k <= 46; k++)
        put("canonical", k * 300, true, 10, 100, 90);
    for (int k = 0; k < 7; k++)
        put("canonical", 21200 + k * 100, true, 10, 100, 90);
    struct slo_page_config c = page_cfg(21800);
    return run_page(&c, &e, &o, &fake) >= 1 &&
           has_cond(&e, "canonical_no_advance");
}

static bool page_coverage_degraded_and_nominal(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    for (int k = 0; k <= 18; k++)
        put("canonical", k * 200, true, 10, 100, 90);
    struct slo_page_config c = page_cfg(3600);
    bool thin = run_page(&c, &e, &o, &fake) == 1 &&
                has_cond(&e, "probe_coverage");
    if (!fresh_dir())
        return false;
    for (int k = 0; k <= 60; k++)
        put("canonical", k * 60, true, 10, 100, 90);
    return thin && run_page(&c, &e, &o, &fake) == 0 &&
           !exists("pages.jsonl");
}

static bool page_flat_boundary(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    struct slo_page_config c = page_cfg(3700);
    c.advance_sec = 3600;
    c.cov_min_ratio = 0;
    if (!fresh_dir())
        return false;
    flat_run(0, 38, 100, 10);
    bool over = run_page(&c, &e, &o, &fake) == 1;
    if (!fresh_dir())
        return false;
    flat_run(0, 36, 100, 10);
    c.now = 3500;
    return over && run_page(&c, &e, &o, &fake) == 0;
}

static bool page_uptick_needs_corroboration(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    flat_run(0, 37, 100, 10);
    put("canonical", 3700, true, 11, 100, 89);
    struct slo_page_config c = page_cfg(3700);
    c.advance_sec = 3600;
    c.cov_min_ratio = 0;
    return run_page(&c, &e, &o, &fake) == 1 &&
           has_cond(&e, "canonical_no_advance");
}

static bool page_recent_climb_ages_out(void)
{
    struct slo_page_eval e;
    struct slo_page_outcome o;
    struct page_fake fake = { 0 };
    if (!fresh_dir())
        return false;
    put("canonical", 0, true, 5, 100, 95);
    put("canonical", 100, true, 5, 100, 95);
    for (int k = 2; k < 5; k++)
        put("canonical", k * 100, true, 10, 100, 90);
    struct slo_page_config c = page_cfg(400);
    c.stale_sec = 100000;
    c.advance_sec = 1000;
    c.cov_min_ratio = 0;
    bool recent = run_page(&c, &e, &o, &fake) == 0 && !exists("pages.jsonl");
    c.now = 1300;
    return recent && run_page(&c, &e, &o, &fake) == 1 &&
           file_has("pages.jsonl", "\"served_height\":10");
}

/* ---- hold judge ---- */

static struct slo_hold_config hold_cfg(int64_t now)
{
    return (struct slo_hold_config){
        .instance = "canonical", .now = now, .window_hours = 72,
        .gap_budget = 3, .max_unreach_sec = 600, .cadence_sec = 60,
        .max_age_sec = 300, .bucket_sec = 900, .reach_pct_min = 99.5,
        .cov_pct_min = 90,
    };
}

static bool judge(const struct slo_hold_config *c, struct slo_hold_report *r)
{
    char ledger[512], pages[512];
    path_of("uptime-ledger.jsonl", ledger, sizeof(ledger));
    path_of("pages.jsonl", pages, sizeof(pages));
    return slo_hold_judge(ledger, pages, c, r);
}

static bool has_line(const struct slo_hold_report *r, const char *needle)
{
    for (size_t i = 0; i < r->nlines; i++)
        if (strstr(r->lines[i], needle))
            return true;
    return false;
}

static bool reason_is(const struct slo_hold_report *r, const char *why)
{
    return !r->proven && r->rc != 0 && strcmp(r->reason, why) == 0;
}

static int64_t dense_last(void)
{
    return BASE + 4319 * 60;
}

static bool hold_clean_window_proves(void)
{
    struct slo_hold_report r;
    struct shape s = dense72();
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    return judge(&c, &r) && r.proven && r.rc == 0 &&
           strcmp(r.verdict, "HOLD_PROVEN") == 0 &&
           has_line(&r, "criterion=reachability met reachable_pct=100.00");
}

static bool hold_gap_breach_fails(void)
{
    struct slo_hold_report r;
    struct shape s = dense72();
    s.breach_at = 2000;
    s.breach_gap = 4;
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    bool at_budget = judge(&c, &r) && reason_is(&r, "gap_vs_oracle") &&
                     has_line(&r, "gap_vs_oracle=4 budget=3");
    c.gap_budget = 4;
    return at_budget && judge(&c, &r) && r.proven;
}

static bool hold_long_outage_fails(void)
{
    struct slo_hold_report r;
    struct shape s = dense72();
    s.down_lo = 2000;
    s.down_hi = 2020;
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    return judge(&c, &r) && reason_is(&r, "reachability") &&
           has_line(&r, "longest_unreachable_run_sec=1200");
}

static bool hold_page_in_window_fails(void)
{
    struct slo_hold_report r;
    struct shape s = dense72();
    char pages[512];
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    path_of("pages.jsonl", pages, sizeof(pages));
    FILE *f = fopen(pages, "w");
    if (!f)
        return false;
    fprintf(f, "{\"ts\":%lld,\"instance\":\"canonical\",\"event\":\"page\"}\n"
               "{\"ts\":%lld,\"instance\":\"dev\",\"event\":\"page\"}\n",
            (long long)(BASE + 100000), (long long)(BASE + 100001));
    fclose(f);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    char want[96];
    snprintf(want, sizeof(want), "pages_in_window=1 worst_ts=%lld",
             (long long)(BASE + 100000));
    return judge(&c, &r) && reason_is(&r, "pages") && has_line(&r, want);
}

static bool hold_sparse_and_stale_fail(void)
{
    struct slo_hold_report r;
    struct shape sparse = { .n = 72, .step = 3600, .sv0 = 3000000,
                            .svstep = 240, .down_lo = -1, .down_hi = -1,
                            .breach_at = -1 };
    struct shape s = dense72();
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &sparse);
    struct slo_hold_config c = hold_cfg(BASE + 71 * 3600 + 30);
    bool thin = judge(&c, &r) && reason_is(&r, "coverage") &&
                has_line(&r, "criterion=coverage VIOLATED samples=72 "
                             "expected=4320");
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    c = hold_cfg(dense_last() + 3600);
    return thin && judge(&c, &r) && reason_is(&r, "freshness") &&
           has_line(&r, "newest_age_sec=3600");
}

static bool hold_missing_and_empty(void)
{
    struct slo_hold_report r;
    struct slo_hold_config c = hold_cfg(BASE);
    if (!fresh_dir())
        return false;
    bool missing = judge(&c, &r) && reason_is(&r, "no_ledger_file") &&
                   r.rc == 4;
    put("dev", BASE, true, 1, 1, 0);
    bool none = judge(&c, &r) && reason_is(&r, "no_samples") && r.rc == 3;
    snprintf(c.instance, sizeof(c.instance), "bogus");
    return missing && none && !judge(&c, &r);
}

static bool hold_stall_and_regress(void)
{
    struct slo_hold_report r;
    struct shape flat = dense72();
    flat.svstep = 0;
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &flat);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    bool stall = judge(&c, &r) && reason_is(&r, "served_advance") &&
                 has_line(&r, "kind=stall_no_advance_in_bucket");
    if (!fresh_dir())
        return false;
    struct shape s = dense72();
    s.n = 100;
    emit("canonical", BASE, &s);
    put("canonical", BASE + 100 * 60, true, 5, 5, 0);
    c = hold_cfg(BASE + 100 * 60 + 30);
    c.window_hours = 2;
    return stall && judge(&c, &r) && reason_is(&r, "served_advance") &&
           has_line(&r, "kind=regressed");
}

static bool hold_record_appends_verdict(void)
{
    struct slo_hold_report r;
    struct shape s = dense72();
    s.breach_at = 5;
    s.breach_gap = 9;
    if (!fresh_dir())
        return false;
    emit("canonical", BASE, &s);
    struct slo_hold_config c = hold_cfg(dense_last() + 30);
    return judge(&c, &r) && slo_hold_record(&c, &r) &&
           count_lines("hold-ledger.jsonl") == 1 &&
           file_has("hold-ledger.jsonl",
                    "\"instance\":\"canonical\",\"window_hours\":72,"
                    "\"gap_budget\":3,\"verdict\":\"NOT_PROVEN\","
                    "\"reason\":\"gap_vs_oracle\",\"judge_rc\":1}");
}

/* ---- prober ---- */

struct fake_node {
    bool up;
    int64_t served, header;
};

struct probe_fake {
    int64_t now;
    struct fake_node oracle, canonical, dev;
    int peers_calls, self_calls;
};

static void fake_chain(void *ctx, const struct slo_instance *at, bool oracle,
                       struct slo_chain_answer *out)
{
    struct probe_fake *f = ctx;
    const struct fake_node *n = oracle ? &f->oracle
        : strcmp(at->name, "canonical") == 0 ? &f->canonical : &f->dev;
    memset(out, 0, sizeof(*out));
    out->latency_ms = n->up ? 7 : 3;
    if (n->up) {
        out->served = (struct slo_opt){ true, n->served };
        out->header = (struct slo_opt){ true, n->header };
    } else {
        snprintf(out->detail, sizeof(out->detail), "connection refused");
    }
}

static struct slo_opt fake_peers(void *ctx, const struct slo_instance *at)
{
    (void)at;
    ((struct probe_fake *)ctx)->peers_calls++;
    return (struct slo_opt){ true, 8 };
}

static void fake_host(void *ctx, const struct slo_instance *at,
                      struct slo_host_facts *out)
{
    (void)ctx;
    (void)at;
    out->nrestarts = (struct slo_opt){ true, 2 };
    out->active_enter_ts = (struct slo_opt){ true, 1699990000 };
    out->rss_kb = (struct slo_opt){ true, 1000 };
    out->datadir_bytes = (struct slo_opt){ true, 5000 };
    snprintf(out->active_state, sizeof(out->active_state), "active");
}

static void fake_self(void *ctx, const struct slo_instance *at,
                      struct slo_self_report *out)
{
    (void)at;
    ((struct probe_fake *)ctx)->self_calls++;
    out->onion_enabled = (struct slo_opt){ true, 1 };
    out->blocker_count = (struct slo_opt){ true, 1 };
    out->state_ok = true;
    snprintf(out->onion_address, sizeof(out->onion_address), "abc.onion");
    snprintf(out->blocker_primary, sizeof(out->blocker_primary), "sync_stall");
}

static int64_t fake_now(void *ctx)
{
    return ((struct probe_fake *)ctx)->now;
}

static struct slo_probe_io probe_io(struct probe_fake *f)
{
    return (struct slo_probe_io){ .ctx = f, .now = fake_now,
        .chain = fake_chain, .peers = fake_peers, .host = fake_host,
        .self = fake_self };
}

static struct slo_probe_config probe_cfg(int64_t rotate, int64_t blind)
{
    struct slo_probe_config c = { .rotate_bytes = rotate,
                                  .blind_streak = blind, .ninst = 2 };
    c.oracle = (struct slo_instance){ .name = "oracle", .rpcport = 8232,
                                      .datadir = "/x/o" };
    c.inst[0] = (struct slo_instance){ .name = "canonical", .rpcport = 18232,
                                       .datadir = "/x/c", .unit = "u1" };
    c.inst[1] = (struct slo_instance){ .name = "dev", .rpcport = 18252,
                                       .datadir = "/x/d", .unit = "u2" };
    return c;
}

static struct probe_fake healthy(void)
{
    return (struct probe_fake){ .now = BASE,
        .oracle = { true, 100, 100 }, .canonical = { true, 98, 100 },
        .dev = { true, 100, 100 } };
}

static bool probe_row_format_is_stable(void)
{
    struct probe_fake f = healthy();
    struct slo_probe_io io = probe_io(&f);
    struct slo_probe_config c = probe_cfg(1 << 20, 3);
    struct slo_probe_result r;
    if (!fresh_dir())
        return false;
    bool ok = slo_probe_collect(&c, &io, &r) && r.samples == 2 &&
              !r.any_unreachable && r.max_height.v == 100 &&
              r.oracle_height.v == 100 && count_lines("uptime-ledger.jsonl") == 2;
    static const char want[] =
        "{\"ts\":1700000000,\"instance\":\"canonical\",\"rpcport\":18232,"
        "\"datadir\":\"/x/c\",\"reachable\":true,\"unreachable_streak\":0,"
        "\"served_height\":98,\"header_height\":100,\"latency_ms\":7,"
        "\"oracle_height\":100,\"max_height\":100,\"gap_vs_max\":2,"
        "\"gap_vs_oracle\":2,\"peer_count\":8,\"rss_kb\":1000,"
        "\"datadir_bytes\":5000,\"nrestarts\":2,\"active_enter_ts\":"
        "1699990000,\"unit_active_state\":\"active\",\"onion_enabled\":true,"
        "\"onion_address\":\"abc.onion\",\"blocker_count\":1,"
        "\"blocker_primary\":\"sync_stall\",\"node_state_ok\":true,"
        "\"error_detail\":\"\"}\n";
    char *text = slurp("uptime-ledger.jsonl");
    ok = ok && text && strncmp(text, want, sizeof(want) - 1) == 0;
    free(text);
    return ok && f.peers_calls == 2 && f.self_calls == 2;
}

static bool blind_row_present(void)
{
    return file_has("uptime-ledger.jsonl",
                    "\"unreachable_streak\":3,\"served_height\":null,"
                    "\"header_height\":null,\"latency_ms\":3,"
                    "\"oracle_height\":100,\"max_height\":100,"
                    "\"gap_vs_max\":null,\"gap_vs_oracle\":null,"
                    "\"peer_count\":null") &&
           file_has("uptime-ledger.jsonl",
                    "\"node_state_ok\":null,\"error_detail\":"
                    "\"connection refused\"}");
}

static bool probe_unreachable_is_data_with_streak(void)
{
    struct probe_fake f = healthy();
    struct slo_probe_io io = probe_io(&f);
    struct slo_probe_config c = probe_cfg(1 << 20, 3);
    struct slo_probe_result r;
    if (!fresh_dir())
        return false;
    f.dev.up = false;
    bool warn = slo_probe_collect(&c, &io, &r) && r.any_unreachable &&
                !r.any_blind && strstr(r.notes[0], "WARN instance=dev") &&
                f.peers_calls == 1 && f.self_calls == 1;
    f.now++;
    bool two = slo_probe_collect(&c, &io, &r) && !r.any_blind;
    f.now++;
    bool blind = slo_probe_collect(&c, &io, &r) && r.any_blind &&
                 strstr(r.notes[0], "BLIND instance=dev") &&
                 blind_row_present();
    f.dev.up = true;
    f.now++;
    bool reset = slo_probe_collect(&c, &io, &r) &&
                 file_has("uptime-ledger.jsonl", "\"instance\":\"dev\","
                          "\"rpcport\":18252,\"datadir\":\"/x/d\","
                          "\"reachable\":true,\"unreachable_streak\":0");
    return warn && two && blind && reset;
}

static bool probe_oracle_down_leaves_gap_null(void)
{
    struct probe_fake f = healthy();
    struct slo_probe_io io = probe_io(&f);
    struct slo_probe_config c = probe_cfg(1 << 20, 3);
    struct slo_probe_result r;
    if (!fresh_dir())
        return false;
    f.oracle.up = false;
    return slo_probe_collect(&c, &io, &r) && !r.oracle_height.has &&
           r.max_height.v == 100 &&
           file_has("uptime-ledger.jsonl",
                    "\"oracle_height\":null,\"max_height\":100,"
                    "\"gap_vs_max\":2,\"gap_vs_oracle\":null");
}

static bool probe_rotates_at_the_limit(void)
{
    struct probe_fake f = healthy();
    struct slo_probe_io io = probe_io(&f);
    struct slo_probe_config c = probe_cfg(1, 3);
    struct slo_probe_result r;
    if (!fresh_dir())
        return false;
    bool first = slo_probe_collect(&c, &io, &r) && !exists("uptime-ledger.jsonl.1");
    f.now++;
    bool second = slo_probe_collect(&c, &io, &r) &&
                  exists("uptime-ledger.jsonl.1") &&
                  strstr(r.notes[0], "rotated ledger") != NULL &&
                  count_lines("uptime-ledger.jsonl") == 2;
    f.now++;
    bool third = slo_probe_collect(&c, &io, &r) &&
                 exists("uptime-ledger.jsonl.2");
    return first && second && third;
}

static bool probe_ledger_write_failure_is_reported(void)
{
    struct probe_fake f = healthy();
    struct slo_probe_io io = probe_io(&f);
    struct slo_probe_config c = probe_cfg(1 << 20, 3);
    struct slo_probe_result r;
    char blocker[600];
    if (!fresh_dir())
        return false;
    snprintf(blocker, sizeof(blocker), "%s/file", g_dir);
    FILE *file = fopen(blocker, "w");
    if (!file)
        return false;
    fclose(file);
    snprintf(blocker, sizeof(blocker), "%s/file/sub", g_dir);
    setenv("ZCL_SLO_LEDGER_DIR", blocker, 1);
    return !slo_probe_collect(&c, &io, &r) && r.samples == 0;
}

/* ---- parsing and binding ---- */

static bool exec_arg_parsing(void)
{
    static const char show[] =
        "ExecStart={ path=/bin/z23 ; argv[]=/bin/z23 -datadir=/d/one "
        "-rpcport=18232 -tor ; ignore_errors=no ; start_time=[n/a] }\n";
    static const char twice[] =
        "ExecStart={ path=/bin/z23 ; argv[]=/bin/z23 -datadir=/a "
        "-datadir=/b ; ignore_errors=no }\n";
    char out[64];
    return slo_unit_exec_arg(show, "datadir", out, sizeof(out)) &&
           strcmp(out, "/d/one") == 0 &&
           slo_unit_exec_arg(show, "rpcport", out, sizeof(out)) &&
           strcmp(out, "18232") == 0 &&
           !slo_unit_exec_arg(show, "conf", out, sizeof(out)) &&
           !slo_unit_exec_arg(twice, "datadir", out, sizeof(out)) &&
           !slo_unit_exec_arg(show, "bad key", out, sizeof(out)) &&
           !slo_unit_exec_arg("", "datadir", out, sizeof(out));
}

static bool conf_rpcport_last_exact_wins(void)
{
    char path[512];
    if (!fresh_dir())
        return false;
    path_of("zclassic.conf", path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    fputs("rpcport=1111\n# rpcport=2222\nrpcportx=3333\n  rpcport = 8240  \n"
          "rpcport=notanumber\n", f);
    fclose(f);
    return slo_conf_rpcport(path) == 8240 &&
           slo_conf_rpcport("/definitely/not/here") == 0;
}

static bool chain_parsers(void)
{
    struct slo_chain_answer a;
    memset(&a, 0, sizeof(a));
    bool chain = slo_io_chain_parse(
        "{\"blocks\":123,\"headers\":125,\"chain\":\"main\"}", &a) &&
        a.served.v == 123 && a.header.v == 125;
    memset(&a, 0, sizeof(a));
    bool legacy = slo_io_chain_parse(
        "{\"result\":{\"blocks\":7,\"headers\":9},\"error\":null}", &a) &&
        a.served.v == 7;
    memset(&a, 0, sizeof(a));
    bool refused = !slo_io_chain_parse(
        "{\"error\":{\"code\":-32603,\"message\":\"refused\"}}", &a) &&
        !a.served.has && !slo_io_chain_parse("", &a) &&
        !slo_io_chain_parse("not json", &a);
    return chain && legacy && refused;
}

static bool scalar_parsers(void)
{
    struct slo_opt two = slo_io_peer_count("[{\"addr\":\"a\"},{\"addr\":\"b\"}]");
    struct slo_opt zero = slo_io_peer_count("[]");
    struct slo_opt bad = slo_io_peer_count("{\"error\":1}");
    int64_t v = 0;
    return two.has && two.v == 2 && zero.has && zero.v == 0 && !bad.has &&
           slo_io_epoch_parse("@1700000000", &v) && v == 1700000000 &&
           !slo_io_epoch_parse("n/a", &v) && !slo_io_epoch_parse("", &v) &&
           slo_io_rss_parse("Name:\tz23\nVmRSS:\t  2048 kB\n", &v) &&
           v == 2048 && !slo_io_rss_parse("Name:\tz23\n", &v);
}

static bool observer_parsers(void)
{
    return chain_parsers() && scalar_parsers();
}

static bool self_report_parsing(void)
{
    struct slo_self_report s;
    memset(&s, 0, sizeof(s));
    slo_io_self_parse(
        "{\"state\":{\"onion_enabled\":true,\"onion_address\":\"x.onion\"}}",
        "{\"state\":{\"active_count\":2,\"last_retired\":{\"id\":\"old\"},"
        "\"blockers\":[{\"id\":\"first\"},{\"id\":\"second\"}]}}", &s);
    bool good = s.state_ok && s.onion_enabled.has && s.onion_enabled.v == 1 &&
                strcmp(s.onion_address, "x.onion") == 0 &&
                s.blocker_count.v == 2 &&
                strcmp(s.blocker_primary, "first") == 0;
    memset(&s, 0, sizeof(s));
    slo_io_self_parse("{\"state\":{\"onion_enabled\":false}}",
                      "{\"error\":{\"code\":-1,\"message\":\"down\"}}", &s);
    return good && !s.state_ok && s.onion_enabled.has &&
           s.onion_enabled.v == 0 && !s.blocker_count.has;
}

int test_slo_monitor(void)
{
    int failures = 0;

    MON_CHECK("probe row format is byte-stable",
              probe_row_format_is_stable());
    MON_CHECK("unreachable node is data with a streak and BLIND note",
              probe_unreachable_is_data_with_streak());
    MON_CHECK("oracle outage leaves its gap null, never zero",
              probe_oracle_down_leaves_gap_null());
    MON_CHECK("ledger rotates at the limit and keeps two generations",
              probe_rotates_at_the_limit());
    MON_CHECK("unwritable ledger fails the cycle",
              probe_ledger_write_failure_is_reported());
    MON_CHECK("unit ExecStart arguments resolve exactly once",
              exec_arg_parsing());
    MON_CHECK("conf rpcport takes the last exact assignment",
              conf_rpcport_last_exact_wins());
    MON_CHECK("chain, peer, epoch and rss parsers", observer_parsers());
    MON_CHECK("node self-report parsing", self_report_parsing());

    MON_CHECK("pager: advancing canonical pages nothing",
              page_advancing_is_quiet());
    MON_CHECK("pager: flat canonical pages once, dedups, renotifies",
              page_flat_dedups_then_renotifies());
    MON_CHECK("pager: wall broadcast follows the config",
              page_wall_follows_config());
    MON_CHECK("pager: stale ledger pages unless the lane is retired",
              page_stale_and_retired());
    MON_CHECK("pager: dark canonical and missing ledger page",
              page_unreachable_and_missing());
    MON_CHECK("pager: a probe gap cannot mask a long stall",
              page_probe_gap_cannot_mask_a_stall());
    MON_CHECK("pager: thin sampling pages, nominal does not",
              page_coverage_degraded_and_nominal());
    MON_CHECK("pager: flat boundary over and under the advance window",
              page_flat_boundary());
    MON_CHECK("pager: an uncorroborated uptick does not clear a page",
              page_uptick_needs_corroboration());
    MON_CHECK("pager: a recent confirmed climb ages out into a page",
              page_recent_climb_ages_out());

    MON_CHECK("hold: a clean 72h window proves", hold_clean_window_proves());
    MON_CHECK("hold: one gap sample over budget fails",
              hold_gap_breach_fails());
    MON_CHECK("hold: a 20 minute outage fails on run length alone",
              hold_long_outage_fails());
    MON_CHECK("hold: a page in the window fails, other lanes do not count",
              hold_page_in_window_fails());
    MON_CHECK("hold: sparse coverage and a stale newest sample fail",
              hold_sparse_and_stale_fail());
    MON_CHECK("hold: missing ledger, no samples and unknown lane",
              hold_missing_and_empty());
    MON_CHECK("hold: a flat bucket and a height regression fail",
              hold_stall_and_regress());
    MON_CHECK("hold: record appends the verdict line",
              hold_record_appends_verdict());

    if (g_dir[0])
        (void)test_rm_rf_recursive(g_dir);
    return failures;
}
