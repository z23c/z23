/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the windowed tip-hash agreement judge
 * (tools/command/native_tip_agreement_judge.c).
 *
 * Every judge case of the retired shell harness
 * (tools/scripts/test_tip_agreement_evidence.sh, `--only judge`) runs here on
 * the same JSONL ledger fixtures: hand-built rows for the verdict ladder, and
 * rows the real recorder wrote (test_tip_agreement_judge_rows.h) for the
 * end-to-end cases. The clock is injected and the ledgers live in a temp
 * directory: no node, no datadir, no live state is read or written.
 *
 * The cases are data: each names the ledger it writes, the knob it moves, and
 * the verdict token and exit code it must produce. A case that must be
 * refused before judging expects an empty token and exit code 2. */

#include "test/test_core.h"

#include "command/native_evidence_judge.h"
#include "services/tip_agreement_watch.h"
#include "test_tip_agreement_judge_rows.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TJ_NOW INT64_C(2000000000)
#define TJ_HEIGHT 3197949
#define TJ_HASH "00000413d24a748e127ed332680da715e676b9a3d60c2f9d4b0dd592113a8a05"

enum tj_kind { TJ_END, TJ_ROW, TJ_LEGACY, TJ_TORN, TJ_RECORDED, TJ_LITERAL, TJ_MISSING };
enum tj_knob { TJK_NONE, TJK_WINDOW, TJK_MAXAGE, TJK_MAXDIS, TJK_MINAGREE,
               TJK_MINSPAN, TJK_MINPEERS };

/* n rows at ts = NOW - base - i*step for i = 1..n. */
struct tj_run {
    enum tj_kind kind;
    int n;
    int64_t base, step;
    const char *outcome;
    int peers, ctl, contested, unres;
    const char *text; /* TJ_RECORDED row body, or TJ_LITERAL file text */
};

struct tj_case {
    const char *name;
    struct tj_run run[4];
    enum tj_knob knob;
    int64_t value;
    const char *want;
    int rc;
};

#define AG "agrees"
#define CNA "could-not-ask"
#define DAY_AGO 172800
#define ROW(n, base, step, outcome, peers, ctl, contested, unres) \
    {TJ_ROW, n, base, step, outcome, peers, ctl, contested, unres, NULL}
#define GOOD(n, base, step) ROW(n, base, step, AG, 2, 2, 0, 0)
#define REC(text, base) {TJ_RECORDED, 8, base, 600, NULL, 0, 0, 0, 0, text}

static const struct tj_case g_cases[] = {
    {"8 agreeing samples in a fresh window", {GOOD(8, 0, 600)}, TJK_NONE, 0, "PASS", 0},
    {"an all-could-not-ask window is NO_EVIDENCE, never PASS",
     {ROW(20, 0, 600, CNA, 2, 2, 0, 0)}, TJK_NONE, 0, "NO_EVIDENCE", 1},
    {"a ledger whose newest sample is 2 days old is STALE",
     {GOOD(8, DAY_AGO, 600)}, TJK_NONE, 0, "STALE", 2},
    {"a missing ledger is STALE", {{.kind = TJ_MISSING}}, TJK_NONE, 0, "STALE", 2},
    {"a ledger with no parseable ts is STALE",
     {{.kind = TJ_LITERAL, .text = "not json\n{\"nope\":1}\n"}},
     TJK_NONE, 0, "STALE", 2},
    {"a far-future stamp cannot refresh a stale ledger",
     {GOOD(8, DAY_AGO, 600), ROW(1, -31536000, 0, AG, 2, 2, 0, 0)},
     TJK_NONE, 0, "STALE", 2},
    {"future samples cannot accrue agreement", {GOOD(6, -4200, 600)},
     TJK_NONE, 0, "STALE", 2},
    {"now is in the window but a second in the future is not",
     {GOOD(5, 0, 600), ROW(1, 0, 0, AG, 2, 2, 0, 0),
      ROW(1, -1, 0, AG, 2, 2, 0, 0)}, TJK_MINAGREE, 7,
     "THIN_EVIDENCE", 1},
    {"a single disagreement fails as DISAGREE",
     {GOOD(12, 0, 600), ROW(1, 300, 0, "disagrees", 2, 2, 0, 0)},
     TJK_NONE, 0, "DISAGREE", 1},
    {"3 agreeing samples is THIN_EVIDENCE", {GOOD(3, 0, 600)}, TJK_NONE, 0,
     "THIN_EVIDENCE", 1},
    {"a ledger written with a weakened control is THIN_EVIDENCE",
     {ROW(10, 0, 600, AG, 2, 1, 0, 0)}, TJK_NONE, 0, "THIN_EVIDENCE", 1},
    {"one single-witness agreeing sample is THIN_EVIDENCE",
     {GOOD(10, 0, 600), ROW(1, 60, 0, AG, 1, 2, 0, 0)}, TJK_NONE, 0,
     "THIN_EVIDENCE", 1},
    {"old agreement + fresh silence is NO_EVIDENCE (the window is graded)",
     {GOOD(10, 90000, 600), ROW(10, 0, 120, CNA, 2, 2, 0, 0)}, TJK_NONE, 0,
     "NO_EVIDENCE", 1},
    {"a could-not-ask LAST line does not sink a good window",
     {GOOD(10, 0, 600), ROW(1, 60, 0, CNA, 2, 2, 0, 0)}, TJK_NONE, 0, "PASS", 0},
    {"an unrecognised outcome is MALFORMED",
     {GOOD(10, 0, 600), ROW(1, 60, 0, "probably-fine", 2, 2, 0, 0)}, TJK_NONE, 0,
     "MALFORMED", 1},
    {"min_distinct_peers=1 is refused outright", {GOOD(8, 0, 600)}, TJK_MINPEERS, 1,
     "", 2},
    {"prober-written ledger judged end to end", {REC(TJR_AGREE, 0)}, TJK_NONE, 0,
     "PASS", 0},
    {"agreement carrying contesting remote hosts is DISAGREE",
     {ROW(10, 0, 600, AG, 3, 2, 2, 0)}, TJK_NONE, 0, "DISAGREE", 1},
    {"8 agreeing samples one second apart is THIN_EVIDENCE, not a day",
     {GOOD(8, 0, 1)}, TJK_NONE, 0, "THIN_EVIDENCE", 1},
    {"window_hours above the shipped 24 is refused", {GOOD(8, 0, 600)}, TJK_WINDOW,
     87600, "", 2},
    {"max_age_secs above the shipped 1800 is refused", {GOOD(8, 0, 600)}, TJK_MAXAGE,
     999999999, "", 2},
    {"max_disagree above the shipped 0 is refused", {GOOD(8, 0, 600)}, TJK_MAXDIS,
     1000, "", 2},
    {"min_agree below the shipped 6 is refused", {GOOD(8, 0, 600)}, TJK_MINAGREE, 1,
     "", 2},
    {"min_span_secs below the shipped 2700 is refused", {GOOD(8, 0, 600)}, TJK_MINSPAN,
     0, "", 2},
    {"tightening min_agree is accepted", {GOOD(8, 0, 600)}, TJK_MINAGREE, 8, "PASS", 0},
    {"tightening the window is accepted", {GOOD(8, 0, 600)}, TJK_WINDOW, 24, "PASS", 0},
    {"a pre-rival-scan ledger cannot pass (missing key is unknown, not zero)",
     {{.kind = TJ_LEGACY, .n = 10, .step = 600}}, TJK_NONE, 0, "NO_EVIDENCE", 1},
    {"a spliced (torn + overwritten) line is MALFORMED",
     {GOOD(10, 0, 600), {.kind = TJ_TORN, .n = 1, .base = 300}, GOOD(1, 60, 0)}, TJK_NONE, 0,
     "MALFORMED", 1},
    {"a window of unverifiable agreements is NO_EVIDENCE",
     {ROW(10, 0, 600, AG, 2, 2, 0, 1)}, TJK_NONE, 0, "NO_EVIDENCE", 1},
    {"thirteen qualifying clusters with omitted rival cannot accrue PASS",
     {REC(TJR_CAPPED, 0)}, TJK_NONE, 0, "NO_EVIDENCE", 1},
    {"one-witness sentinel does not prevent valid agreement accrual",
     {REC(TJR_SENTINEL, 0)}, TJK_NONE, 0, "PASS", 0},
    {"missing sentinel count cannot accrue PASS", {REC(TJR_NOCOUNT, 0)}, TJK_NONE, 0,
     "NO_EVIDENCE", 1},
    {"out-of-range sentinel count cannot accrue PASS", {REC(TJR_OVERSIZE, 0)},
     TJK_NONE, 0, "NO_EVIDENCE", 1},
    {"retained rank-12 rival is DISAGREE through recorder-written rows",
     {REC(TJR_RIVAL, 0)}, TJK_NONE, 0, "DISAGREE", 1},
    {"prober-written could-not-ask ledger is refused end to end", {REC(TJR_CNA, 0)},
     TJK_NONE, 0, "NO_EVIDENCE", 1},
};

static char g_root[512];
static struct zcl_judge_result g_res;

static void tj_row(FILE *f, int64_t ts, const struct tj_run *r)
{
    char peers[16];
    if (strcmp(r->outcome, CNA) == 0)
        (void)snprintf(peers, sizeof(peers), "null");
    else
        (void)snprintf(peers, sizeof(peers), "%d", r->peers);
    (void)fprintf(f,
        "{\"ts\":%lld,\"instance\":\"canonical\",\"rpcport\":18232,"
        "\"datadir\":\"/x\",\"window_secs\":900,\"min_distinct_peers\":%d,"
        "\"our_height\":%d,\"height\":%d,\"our_tip_hash\":\"%s\","
        "\"modal_remote_hash\":\"%s\",\"modal_remote_peers\":%s,"
        "\"modal_remote_groups\":2,\"disagreeing_peers\":%d,"
        "\"contested_peers\":%d,\"rival_heights_unresolved\":%d,"
        "\"heights_above_tip\":0,\"disagreeing_hashes\":[],\"peers_total\":21,"
        "\"peers_with_height\":20,\"peers_usable\":9,\"clusters_seen\":2,"
        "\"outcome\":\"%s\",\"reason\":\"fixture\",\"error_detail\":\"\"}\n",
        (long long)ts, r->ctl, TJ_HEIGHT, TJ_HEIGHT, TJ_HASH, TJ_HASH, peers,
        r->contested, r->contested, r->unres, r->outcome);
}

/* A row in the pre-rival-scan shape: it says "agrees" and carries no
 * contested_peers or rival_heights_unresolved key at all. */
static void tj_legacy(FILE *f, int64_t ts)
{
    (void)fprintf(f,
        "{\"ts\":%lld,\"min_distinct_peers\":2,\"modal_remote_peers\":2,"
        "\"disagreeing_peers\":0,\"outcome\":\"agrees\",\"reason\":\"legacy\"}\n",
        (long long)ts);
}

static void tj_write_run(FILE *f, const struct tj_run *r)
{
    for (int i = 1; i <= r->n; i++) {
        int64_t ts = TJ_NOW - r->base - (int64_t)i * r->step;
        if (r->kind == TJ_ROW)
            tj_row(f, ts, r);
        else if (r->kind == TJ_LEGACY)
            tj_legacy(f, ts);
        else if (r->kind == TJ_TORN)
            (void)fprintf(f, "{\"ts\":%lld,\"instance\":\"cano", (long long)ts);
        else if (r->kind == TJ_RECORDED)
            (void)fprintf(f, "{\"ts\":%lld,%s\n", (long long)ts, r->text);
    }
    if (r->kind == TJ_LITERAL)
        (void)fputs(r->text, f);
}

/* TJ_MISSING writes nothing and leaves the path absent. */
static bool tj_write_ledger(const struct tj_case *c, const char *path)
{
    FILE *f;
    bool ok;
    if (c->run[0].kind == TJ_MISSING)
        return true;
    f = fopen(path, "wb");
    if (!f)
        return false;
    for (int i = 0; i < 4 && c->run[i].kind != TJ_END; i++)
        tj_write_run(f, &c->run[i]);
    ok = ferror(f) == 0;
    return fclose(f) == 0 && ok;
}

static void tj_apply_knob(struct zcl_tip_judge_opts *o, enum tj_knob k, int64_t v)
{
    switch (k) {
    case TJK_WINDOW: o->window_hours = v; break;
    case TJK_MAXAGE: o->max_age_secs = v; break;
    case TJK_MAXDIS: o->max_disagree = v; break;
    case TJK_MINAGREE: o->min_agree = v; break;
    case TJK_MINSPAN: o->min_span_secs = v; break;
    case TJK_MINPEERS: o->min_distinct_peers = v; break;
    case TJK_NONE: break;
    }
}

/* The shipped contract with the injected clock, never the process env. */
static void tj_opts(struct zcl_tip_judge_opts *o, const char *path)
{
    memset(o, 0, sizeof(*o));
    o->file = path;
    o->window_hours = ZCL_TIP_DEF_WINDOW_HOURS;
    o->max_age_secs = ZCL_TIP_DEF_MAX_AGE_SECS;
    o->min_agree = ZCL_TIP_DEF_MIN_AGREE;
    o->min_distinct_peers = TIP_AGREEMENT_MIN_DISTINCT_PEERS;
    o->max_disagree = ZCL_TIP_DEF_MAX_DISAGREE;
    o->min_span_secs = ZCL_TIP_DEF_MIN_SPAN_SECS;
    o->now_unix = TJ_NOW;
    o->now_set = true;
}

/* The public report line names the verdict and counts, never the private
 * ledger: not its path, port, datadir or any row field. */
static bool tj_report_clean(const char *path)
{
    return strstr(g_res.text, path) == NULL && strstr(g_res.text, "rpcport") == NULL &&
           strstr(g_res.text, "datadir") == NULL && strstr(g_res.text, "/x") == NULL;
}

static bool tj_case_holds(const struct tj_case *c)
{
    struct zcl_tip_judge_opts o;
    char path[600], err[200], token[64];
    (void)snprintf(path, sizeof(path), "%s/case.jsonl", g_root);
    (void)remove(path);
    if (!tj_write_ledger(c, path))
        return false;
    tj_opts(&o, path);
    tj_apply_knob(&o, c->knob, c->value);
    if (!zcl_tip_judge_check(&o, err, sizeof(err)))
        return c->want[0] == '\0' && c->rc == 2;
    if (!zcl_tip_agreement_judge(&o, &g_res))
        return false;
    (void)snprintf(token, sizeof(token), "VERDICT=%s ", c->want);
    return strcmp(g_res.verdict, c->want) == 0 && g_res.exit_code == c->rc &&
           strstr(g_res.text, token) != NULL && tj_report_clean(path);
}

static int tj_run_cases(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(g_cases) / sizeof(g_cases[0]); i++) {
        TEST(g_cases[i].name) {
            ASSERT(tj_case_holds(&g_cases[i]));
            PASS();
        } _test_next:;
    }
    return failures;
}

/* The shipped values are the contract; the control comes from the watch. */
static int tj_case_contract(void)
{
    int failures = 0;
    struct zcl_tip_judge_opts o;
    char err[200];
    TEST("the shipped contract passes its own check and pins the watch control") {
        tj_opts(&o, "x");
        ASSERT(zcl_tip_judge_check(&o, err, sizeof(err)));
        ASSERT(o.min_distinct_peers == TIP_AGREEMENT_MIN_DISTINCT_PEERS);
        PASS();
    } _test_next:;
    return failures;
}

static int tj_case_negative(void)
{
    int failures = 0;
    struct zcl_tip_judge_opts o;
    char err[200];
    TEST("a negative knob is refused, not wrapped into a huge window") {
        tj_opts(&o, "x");
        o.window_hours = -1;
        ASSERT(!zcl_tip_judge_check(&o, err, sizeof(err)));
        PASS();
    } _test_next:;
    return failures;
}

static int tj_case_nul(void)
{
    int failures = 0;
    char path[600];
    struct zcl_tip_judge_opts o;
    TEST("a NUL cannot hide a subsequent disagreement") {
        (void)snprintf(path, sizeof(path), "%s/nul.jsonl", g_root);
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        struct tj_run agree = ROW(6, 0, 600, AG, 2, 2, 0, 0);
        struct tj_run disagree = ROW(1, 0, 0, "disagrees", 2, 2, 0, 0);
        tj_write_run(f, &agree);
        ASSERT(fputc(0, f) == 0);
        tj_row(f, TJ_NOW - 1, &disagree);
        ASSERT(fclose(f) == 0);
        tj_opts(&o, path);
        ASSERT(zcl_tip_agreement_judge(&o, &g_res));
        ASSERT(strcmp(g_res.verdict, "PASS") != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ZCL_PARITY_JUDGE_NOW is the hermetic clock seam; a malformed value is
 * refused, never read as an epoch. */
static int tj_case_env(void)
{
    int failures = 0;
    struct zcl_tip_judge_opts o;
    char err[200];
    TEST("ZCL_PARITY_JUDGE_NOW sets the clock; garbage is refused; unset is wall clock") {
        ASSERT(setenv("ZCL_PARITY_JUDGE_NOW", "2000000000", 1) == 0);
        ASSERT(zcl_tip_judge_defaults(&o, err, sizeof(err)));
        ASSERT(o.now_set && o.now_unix == TJ_NOW);
        ASSERT(setenv("ZCL_PARITY_JUDGE_NOW", "12x", 1) == 0);
        ASSERT(!zcl_tip_judge_defaults(&o, err, sizeof(err)));
        ASSERT(unsetenv("ZCL_PARITY_JUDGE_NOW") == 0);
        ASSERT(zcl_tip_judge_defaults(&o, err, sizeof(err)) && !o.now_set);
        PASS();
    } _test_next:;
    return failures;
}

int test_tip_agreement_judge(void);
int test_tip_agreement_judge(void)
{
    int failures = 0;
    test_make_tmpdir(g_root, sizeof(g_root), "tip_agreement_judge", "root");
    failures += tj_run_cases();
    failures += tj_case_contract();
    failures += tj_case_negative();
    failures += tj_case_nul();
    failures += tj_case_env();
    (void)test_rm_rf_recursive(g_root);
    if (failures == 0)
        printf("test_tip_agreement_judge: all passed\n");
    else
        printf("test_tip_agreement_judge: %d FAILED\n", failures);
    return failures;
}
