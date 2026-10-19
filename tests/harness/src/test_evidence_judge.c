/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the in-process evidence judges
 * (tools/command/native_soak_judge.c, native_stopwatch_judge.c).
 *
 * Fixture ledgers live in a temp directory and the clock is injected, so each
 * rung of the verdict ladders runs without a node or a host ledger. The cases
 * are the ones the retired judge scripts carried in their --selftest, plus a
 * parity case that runs the soak script on the same ledgers and requires the
 * identical report.
 */

#include "test/test_core.h"

#include "command/native_evidence_judge.h"

#include "util/spawn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EJT_NOW INT64_C(2000000000)
#define EJT_GOOD_TIP 3100000
#define EJT_BELOW_TIP 200
#define EJT_SOAK_BASE INT64_C(1700000000)
#define EJT_SHA_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define EJT_SHA_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static char g_root[512];

static bool ejt_write(const char *path, const char *text, const char *mode)
{
    FILE *f = fopen(path, mode);
    bool ok = f && fputs(text, f) >= 0;
    return f && fclose(f) == 0 && ok;
}

static void ejt_path(char *out, size_t cap, const char *name)
{
    (void)snprintf(out, cap, "%s/%s", g_root, name);
}

/* ── stopwatch ───────────────────────────────────────────────────────── */

static struct zcl_judge_result g_res;

static bool ejt_sw(const char *ledger, const char *slo, const char *expect)
{
    struct zcl_stopwatch_judge_opts o = {
        .history = ledger,
        .max_age_secs = 1000000,
        .expect_sha256 = expect,
        .slo_ledger = slo,
        .checkpoint_height = ZCL_STOPWATCH_CHECKPOINT_HEIGHT,
        .oracle_lag_budget = ZCL_STOPWATCH_ORACLE_LAG_BUDGET,
        .oracle_max_age_secs = ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS,
        .now_unix = EJT_NOW,
    };
    return zcl_stopwatch_judge(&o, &g_res);
}

static bool ejt_is(const char *verdict, int rc)
{
    return strcmp(g_res.verdict, verdict) == 0 && g_res.exit_code == rc;
}

static bool ejt_has(const char *needle)
{
    return strstr(g_res.text, needle) != NULL;
}

static void ejt_row(char *out, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void ejt_row(char *out, size_t cap, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(out, cap, fmt, args);
    va_end(args);
}

static int ejt_case_sw_passes(void)
{
    int failures = 0;
    char led[600], row[1024], none[600];
    ejt_path(led, sizeof(led), "sw_pass.jsonl");
    ejt_path(none, sizeof(none), "does-not-exist.jsonl");
    TEST("stopwatch: a modern or legacy pass passes; the SLO ledger may be "
         "missing, stale or within budget") {
        char slo[600];
        ejt_row(row, sizeof(row),
                "{\"ts\":%lld,\"verdict\":\"pass\",\"exit_code\":0,"
                "\"final_network_tip\":%d,\"artifact_dir\":\"/a/1\"}\n",
                (long long)EJT_NOW, EJT_GOOD_TIP);
        ASSERT(ejt_write(led, row, "wb"));
        ASSERT(ejt_sw(led, none, NULL) && ejt_is("PASS", 0));
        ASSERT(ejt_has("qualification=unbound ledger_available=false"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"exit_code\":0,"
            "\"artifact_dir\":\"/a/legacy\"}\n", "wb"));
        ASSERT(ejt_sw(led, none, NULL) && ejt_is("PASS", 0));
        ejt_path(slo, sizeof(slo), "slo_close.jsonl");
        ejt_row(row, sizeof(row), "{\"ts\":%lld,\"oracle_height\":%d}\n",
                (long long)EJT_NOW, 3100500);
        ASSERT(ejt_write(slo, row, "wb"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"final_network_tip\":"
            "3100000,\"artifact_dir\":\"/a/1\"}\n", "wb"));
        ASSERT(ejt_sw(led, slo, NULL) && ejt_is("PASS", 0));
        ASSERT(ejt_has("ledger_available=true"));
        ejt_path(slo, sizeof(slo), "slo_stale.jsonl");
        ejt_row(row, sizeof(row), "{\"ts\":%lld,\"oracle_height\":%d}\n",
                (long long)(EJT_NOW - 7200), 3200000);
        ASSERT(ejt_write(slo, row, "wb"));
        ASSERT(ejt_sw(led, slo, NULL) && ejt_is("PASS", 0));
        ASSERT(ejt_has("ledger_available=false"));
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_sw_fixture_gates(void)
{
    int failures = 0;
    char led[600], slo[600], row[1024];
    ejt_path(led, sizeof(led), "sw_gate.jsonl");
    ejt_path(slo, sizeof(slo), "slo_lead.jsonl");
    TEST("stopwatch: a below-checkpoint pass is THIN_FIXTURE, one lagging a "
         "fresh oracle is LAGGING_FIXTURE, and a non-pass is never upgraded") {
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"final_network_tip\":"
            "200,\"artifact_dir\":\"/a/thin\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("THIN_FIXTURE", 1));
        ejt_row(row, sizeof(row), "{\"ts\":%lld,\"oracle_height\":%d}\n",
                (long long)EJT_NOW, 3200000);
        ASSERT(ejt_write(slo, row, "wb"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"final_network_tip\":"
            "3100000,\"artifact_dir\":\"/a/1\"}\n", "wb"));
        ASSERT(ejt_sw(led, slo, NULL) && ejt_is("LAGGING_FIXTURE", 1));
        ASSERT(ejt_has("lags_oracle_3200000_by_100000_gt_budget_2000"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"seam\",\"exit_code\":3,"
            "\"final_network_tip\":200,\"artifact_dir\":\"/a/seam\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"readback-failed\",\"exit_code\":6,"
            "\"final_network_tip\":-1,\"artifact_dir\":\"/a/rb\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(ejt_has("last_run_verdict_readback-failed_age_0s class=unrecorded"));
        ASSERT(strcmp(g_res.artifact, "/a/rb") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_sw_qualify(void)
{
    int failures = 0;
    char led[600], art[600], proof[700], row[1400], gone[600];
    ejt_path(led, sizeof(led), "sw_q.jsonl");
    ejt_path(art, sizeof(art), "q_art");
    ejt_path(gone, sizeof(gone), "q_missing");
    (void)snprintf(proof, sizeof(proof), "%s/proof.json", art);
    TEST("stopwatch: qualification binds a pass to the executable it measured "
         "and to an artifact whose own proof says pass") {
        ASSERT(mkdir(art, 0700) == 0 || access(art, F_OK) == 0);
        ASSERT(ejt_write(proof, "{\"verdict\": \"pass\"}\n", "wb"));
        ejt_row(row, sizeof(row),
                "{\"ts\":2000000000,\"verdict\":\"pass\",\"final_network_tip\":"
                "3100000,\"node_bin_sha256\":\"%s\",\"artifact_dir\":\"%s\"}\n",
                EJT_SHA_A, art);
        ASSERT(ejt_write(led, row, "wb"));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_A) && ejt_is("PASS", 0));
        ASSERT(ejt_has("qualification=bound executable="));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_B) && ejt_is("WRONG_ARTIFACT", 1));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"artifact_dir\":\"/a/l\"}\n",
            "wb"));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_A) && ejt_is("UNBOUND", 1));
        ejt_row(row, sizeof(row),
                "{\"ts\":2000000000,\"verdict\":\"pass\",\"node_bin_sha256\":"
                "\"%s\",\"artifact_dir\":\"%s\"}\n", EJT_SHA_A, gone);
        ASSERT(ejt_write(led, row, "wb"));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_A) && ejt_is("INCOMPLETE", 1));
        ASSERT(ejt_write(proof, "{\"verdict\": \"stalled-named\"}\n", "wb"));
        ejt_row(row, sizeof(row),
                "{\"ts\":2000000000,\"verdict\":\"pass\",\"node_bin_sha256\":"
                "\"%s\",\"artifact_dir\":\"%s\"}\n", EJT_SHA_A, art);
        ASSERT(ejt_write(led, row, "wb"));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_A) && ejt_is("INCOMPLETE", 1));
        ejt_row(row, sizeof(row),
                "{\"ts\":%lld,\"verdict\":\"pass\",\"node_bin_sha256\":"
                "\"%s\",\"artifact_dir\":\"%s\"}\n",
                (long long)(EJT_NOW - 2000000), EJT_SHA_A, art);
        ASSERT(ejt_write(led, row, "wb"));
        ASSERT(ejt_sw(led, NULL, EJT_SHA_A) && ejt_is("STALE", 2));
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_sw_stale(void)
{
    int failures = 0;
    char led[600];
    ejt_path(led, sizeof(led), "sw_stale.jsonl");
    TEST("stopwatch: a missing, empty or ts-less ledger and a row past the "
         "window are STALE with the cause named") {
        ASSERT(ejt_sw("/nonexistent/ledger.jsonl", NULL, NULL));
        ASSERT(ejt_is("STALE", 2) && strcmp(g_res.reason, "no_evidence_file") == 0);
        ASSERT(ejt_write(led, "{\"ts\":2000000000,\"verdict\":\"pass\"}\n\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("STALE", 2));
        ASSERT(strcmp(g_res.reason, "empty_last_line") == 0);
        ASSERT(ejt_write(led, "{\"verdict\":\"pass\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("STALE", 2));
        ASSERT(strcmp(g_res.reason, "malformed_last_line_no_ts") == 0);
        ASSERT(ejt_write(led, "{\"ts\":2000000000}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("STALE", 2));
        ASSERT(strcmp(g_res.reason, "missing_verdict_field") == 0);
        ASSERT(ejt_write(led, "{\"ts\":1000000000,\"verdict\":\"pass\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("STALE", 2));
        ASSERT(strcmp(g_res.reason,
                      "last_sample_age_1000000000s_gt_1000000s") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static void ejt_skip_row(char *out, size_t cap, long long ts, const char *why,
                         const char *art)
{
    ejt_row(out, cap,
            "{\"ts\":%lld,\"verdict\":\"skip\",\"exit_code\":2,"
            "\"artifact_dir\":\"%s\",\"skip_reason\":\"%s\"}\n",
            ts, art, why);
}

static int ejt_case_sw_streaks(void)
{
    int failures = 0;
    char led[600], a[400], b[400];
    static const char dead[] = "serving peer not reachable: 127.0.0.1:39070";
    ejt_path(led, sizeof(led), "sw_streak.jsonl");
    TEST("stopwatch: the skip streak is reported, alarms only at its class "
         "threshold, and never moves the verdict") {
        ejt_skip_row(a, sizeof(a), EJT_NOW, dead, "/a/1");
        ASSERT(ejt_write(led, a, "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(ejt_has("SKIP_STREAK skip_streak=1") && !g_res.alarm[0]);
        ejt_skip_row(a, sizeof(a), EJT_NOW - 21600, dead, "/a/1");
        ejt_skip_row(b, sizeof(b), EJT_NOW, dead, "/a/2");
        ASSERT(ejt_write(led, a, "wb") && ejt_write(led, b, "ab"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(strstr(g_res.alarm, "ALARM class=fixture_absent skip_streak=2"));
        ASSERT(!strstr(g_res.alarm, "VERDICT"));
        ejt_skip_row(a, sizeof(a), EJT_NOW - 43200, dead, "/a/1");
        ejt_skip_row(b, sizeof(b), EJT_NOW - 21600, dead, "/a/2");
        ASSERT(ejt_write(led, a, "wb") && ejt_write(led, b, "ab"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"pass\",\"exit_code\":0,"
            "\"final_network_tip\":3100000,\"artifact_dir\":\"/a/p\"}\n", "ab"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("PASS", 0));
        ASSERT(ejt_has("SKIP_STREAK skip_streak=0") && !g_res.alarm[0]);
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_sw_skip_classes(void)
{
    int failures = 0;
    char led[600], a[400];
    ejt_path(led, sizeof(led), "sw_class.jsonl");
    TEST("stopwatch: benign skips never alarm, a config error alarms on the "
         "first, a legacy row is unclassified") {
        ASSERT(ejt_write(led, "", "wb"));
        for (int i = 0; i < 5; i++) {
            ejt_skip_row(a, sizeof(a), EJT_NOW,
                         "no valid --client-rpc / ZCL_ND_CLIENT_RPCPORT given",
                         "/a/b");
            ASSERT(ejt_write(led, a, "ab"));
        }
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(ejt_has("class=not_configured threshold=0") && !g_res.alarm[0]);
        ejt_skip_row(a, sizeof(a), EJT_NOW,
                     "node binary absent/not executable: /nope/zclassic23",
                     "/a/c");
        ASSERT(ejt_write(led, a, "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(strstr(g_res.alarm, "ALARM class=config_error skip_streak=1"));
        ASSERT(ejt_write(led,
            "{\"ts\":2000000000,\"verdict\":\"skip\",\"exit_code\":2,"
            "\"artifact_dir\":\"/a/l\"}\n", "wb"));
        ASSERT(ejt_sw(led, NULL, NULL) && ejt_is("FAIL", 1));
        ASSERT(ejt_has("class=unclassified threshold=2") && !g_res.alarm[0]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── soak ────────────────────────────────────────────────────────────── */

static bool ejt_soak_line(FILE *f, int64_t ts, int gap, int nr, int64_t aet,
                          int rss, const char *sha)
{
    return fprintf(f,
        "{\"ts\":%lld,\"soak_height\":%lld,\"zd_height\":%lld,\"gap\":%d,"
        "\"nrestarts\":%d,\"active_enter_ts\":%lld,\"rss_kb\":%d,"
        "\"binary_sha256\":\"%s\",\"security_review_required\":false,"
        "\"security_posture_ok\":true,\"window_eligible\":true,\"ok\":true}\n",
        (long long)ts, (long long)(3000000 + ts % 100000),
        (long long)(3000000 + ts % 100000 + gap), gap, nr, (long long)aet, rss,
        sha) > 0;
}

static bool ejt_soak_judge(const char *dir, int64_t hours, int64_t now,
                           bool allow_stale)
{
    char file[700];
    struct zcl_soak_judge_opts o = {.window_hours = hours, .allow_stale = allow_stale,
                                    .now_unix = now};
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    o.file = file;
    return zcl_soak_judge(&o, &g_res);
}

/* Writes `count` hourly samples from `base`, calling `edit` for each index to
 * let a case override the sample; the default is a healthy one. */
typedef bool (*ejt_edit)(FILE *f, int i, int64_t ts);

static bool ejt_healthy(FILE *f, int i, int64_t ts)
{
    (void)i;
    return ejt_soak_line(f, ts, 0, 1, EJT_SOAK_BASE - 500, 1500000, EJT_SHA_A);
}

static bool ejt_soak_ledger(const char *dir, int count, ejt_edit edit)
{
    char file[700];
    FILE *f;
    bool ok;
    (void)mkdir(dir, 0700);
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    f = fopen(file, "wb");
    ok = f != NULL;
    for (int i = 0; ok && i < count; i++)
        ok = edit(f, i, EJT_SOAK_BASE + (int64_t)i * 3600);
    return f && fclose(f) == 0 && ok;
}

static bool ejt_hole(FILE *f, int i, int64_t ts)
{
    return (i >= 50 && i <= 53) || ejt_healthy(f, i, ts);
}

static bool ejt_gap(FILE *f, int i, int64_t ts)
{
    int gap = (i >= 60 && i <= 69) ? 3 : 0;
    return ejt_soak_line(f, ts, gap, 1, EJT_SOAK_BASE - 500, 1500000, EJT_SHA_A);
}

static bool ejt_operator(FILE *f, int i, int64_t ts)
{
    return i < 100 ? ejt_soak_line(f, ts, 0, 2, EJT_SOAK_BASE - 500, 1500000, EJT_SHA_A)
                   : ejt_soak_line(f, ts, 0, 0, EJT_SOAK_BASE + 100 * 3600 - 30,
                                   1500000, EJT_SHA_A);
}

static bool ejt_recycle(FILE *f, int i, int64_t ts)
{
    return i < 80 ? ejt_soak_line(f, ts, 0, 1, EJT_SOAK_BASE - 500, 1500000, EJT_SHA_A)
                  : ejt_soak_line(f, ts, 0, 2, EJT_SOAK_BASE + 80 * 3600 - 100,
                                  1500000, EJT_SHA_A);
}

static bool ejt_ambiguous(FILE *f, int i, int64_t ts)
{
    return i < 100 ? ejt_soak_line(f, ts, 0, 5, EJT_SOAK_BASE - 500, 1500000, EJT_SHA_A)
                   : ejt_soak_line(f, ts, 0, 7, EJT_SOAK_BASE + 100 * 3600 - 30,
                                   1500000, EJT_SHA_A);
}

static bool ejt_swap(FILE *f, int i, int64_t ts)
{
    return ejt_soak_line(f, ts, 0, 1, EJT_SOAK_BASE - 500, 1500000,
                         i == 100 ? EJT_SHA_B : EJT_SHA_A);
}

static bool ejt_soak_down(FILE *f, int i, int64_t ts)
{
    if (i == 0 || i == 56 || i == 112 || i == 168)
        return ejt_healthy(f, i, ts);
    return fprintf(f,
        "{\"ts\":%lld,\"soak_height\":null,\"zd_height\":%lld,\"gap\":null,"
        "\"nrestarts\":1,\"active_enter_ts\":%lld,\"rss_kb\":null,"
        "\"mainpid\":null,\"ok\":false}\n",
        (long long)ts, (long long)(3000000 + ts % 100000),
        (long long)(EJT_SOAK_BASE - 500)) > 0;
}

static bool ejt_oracle_thin(FILE *f, int i, int64_t ts)
{
    if (i < 20 || i > 49)
        return ejt_healthy(f, i, ts);
    return fprintf(f,
        "{\"ts\":%lld,\"soak_height\":%lld,\"zd_height\":null,\"gap\":null,"
        "\"nrestarts\":1,\"active_enter_ts\":%lld,\"rss_kb\":1500000,"
        "\"mainpid\":777,\"ok\":false}\n",
        (long long)ts, (long long)(3000000 + ts % 100000),
        (long long)(EJT_SOAK_BASE - 500)) > 0;
}

static bool ejt_posture(FILE *f, int i, int64_t ts, const char *posture)
{
    if (i != 80)
        return ejt_healthy(f, i, ts);
    return fprintf(f,
        "{\"ts\":%lld,\"soak_height\":3000000,\"zd_height\":3000000,\"gap\":0,"
        "\"nrestarts\":1,\"active_enter_ts\":%lld,\"rss_kb\":1500000,%s"
        "\"ok\":true}\n",
        (long long)ts, (long long)(EJT_SOAK_BASE - 500), posture) > 0;
}

static bool ejt_review(FILE *f, int i, int64_t ts)
{
    return ejt_posture(f, i, ts,
        "\"security_review_required\":true,\"security_posture_ok\":false,"
        "\"window_eligible\":false,");
}

static bool ejt_unknown(FILE *f, int i, int64_t ts)
{
    return ejt_posture(f, i, ts, "");
}

static bool ejt_sec_gap(FILE *f, int i, int64_t ts)
{
    return ejt_posture(f, i, ts,
        "\"security_review_required\":false,\"security_posture_ok\":false,"
        "\"window_eligible\":false,");
}

static bool ejt_legacy(FILE *f, int i, int64_t ts)
{
    (void)i;
    return fprintf(f,
        "{\"ts\":%lld,\"soak_height\":3000000,\"zd_height\":3000000,\"gap\":0,"
        "\"nrestarts\":0,\"active_enter_ts\":%lld,\"rss_kb\":1500000,"
        "\"mainpid\":4242,\"security_review_required\":false,"
        "\"security_posture_ok\":true,\"window_eligible\":true,\"ok\":true}\n",
        (long long)ts, (long long)(EJT_SOAK_BASE - 500)) > 0;
}

#define EJT_FRESH (EJT_SOAK_BASE + 168 * 3600 + 60)

static bool ejt_soak_case(const char *name, int count, ejt_edit edit,
                          int64_t now, const char *verdict, const char *reason,
                          int rc)
{
    char dir[600];
    ejt_path(dir, sizeof(dir), name);
    return ejt_soak_ledger(dir, count, edit) &&
           ejt_soak_judge(dir, 168, now, false) && ejt_is(verdict, rc) &&
           strstr(g_res.reason, reason) != NULL;
}

static int ejt_case_soak_verdicts(void)
{
    int failures = 0;
    TEST("soak: a covered clean week is MET with one autonomous recycle "
         "reported; the ladder refuses every defect with its named reason") {
        ASSERT(ejt_soak_case("sk_green", 169, ejt_recycle, EJT_FRESH, "MET", "", 0));
        ASSERT(ejt_has("restarts_in_window=1 ambiguous_restarts=1 operator_interventions=0"));
        ASSERT(ejt_soak_case("sk_short", 12, ejt_healthy,
                             EJT_SOAK_BASE + 11 * 3600 + 60, "INSUFFICIENT",
                             "window_short_", 2));
        ASSERT(ejt_has("window_covered_hours=11.000"));
        ASSERT(ejt_soak_case("sk_hole", 169, ejt_hole, EJT_FRESH, "NOT_MET",
                             "sampling_hole_", 1));
        ASSERT(ejt_soak_case("sk_gap", 169, ejt_gap, EJT_FRESH, "NOT_MET",
                             "gap_nonzero_in_10_of_169_ok_samples", 1));
        ASSERT(ejt_soak_case("sk_op", 169, ejt_operator, EJT_FRESH, "NOT_MET",
                             "operator_intervention_detected", 1));
        ASSERT(ejt_soak_case("sk_down", 169, ejt_soak_down, EJT_FRESH, "NOT_MET",
                             "soak_unreachable_in_165_of_169_samples", 1));
        ASSERT(ejt_soak_case("sk_thin", 169, ejt_oracle_thin, EJT_FRESH,
                             "INSUFFICIENT", "oracle_coverage_thin_ok_139_of_169", 2));
        ASSERT(ejt_soak_case("sk_amb", 169, ejt_ambiguous, EJT_FRESH, "MET", "", 0));
        ASSERT(ejt_has("restarts_in_window=2 ambiguous_restarts=2 operator_interventions=0"));
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_soak_identity_posture(void)
{
    int failures = 0;
    TEST("soak: a posture or binary-identity gap can never earn MET") {
        ASSERT(ejt_soak_case("sk_rev", 169, ejt_review, EJT_FRESH, "NOT_MET",
                             "security_review_required_in_1_of_169_samples", 1));
        ASSERT(ejt_soak_case("sk_unk", 169, ejt_unknown, EJT_FRESH, "INSUFFICIENT",
                             "security_posture_unknown_in_1_of_169_samples", 2));
        ASSERT(ejt_soak_case("sk_sgap", 169, ejt_sec_gap, EJT_FRESH, "NOT_MET",
                             "security_posture_gap_in_1_of_169_samples", 1));
        ASSERT(ejt_soak_case("sk_swap", 169, ejt_swap, EJT_FRESH, "NOT_MET",
                             "binary_identity_changed", 1));
        ASSERT(ejt_soak_case("sk_leg", 169, ejt_legacy, EJT_FRESH, "INSUFFICIENT",
                             "binary_identity_unknown_in_169_of_169_samples", 2));
        PASS();
    } _test_next:;
    return failures;
}

static int ejt_case_soak_window_edges(void)
{
    int failures = 0;
    char dir[600];
    ejt_path(dir, sizeof(dir), "sk_edge");
    TEST("soak: the start slack covers timer jitter, a stale tail caps at "
         "INSUFFICIENT and allow_stale judges history") {
        ASSERT(ejt_soak_ledger(dir, 169, ejt_healthy));
        ASSERT(ejt_soak_judge(dir, 168, EJT_FRESH + 2592000, false));
        ASSERT(ejt_is("INSUFFICIENT", 2) &&
               strstr(g_res.reason, "stale_evidence_age_2592060s") != NULL);
        ASSERT(g_res.newest_age_sec > 168 * 3600);
        ASSERT(ejt_soak_judge(dir, 168, EJT_FRESH + 2592000, true));
        ASSERT(ejt_is("MET", 0));
        ASSERT(ejt_soak_judge("/nonexistent/soak", 168, EJT_FRESH, false));
        ASSERT(ejt_is("INSUFFICIENT", 2) &&
               strcmp(g_res.reason, "no_evidence_file") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── parity with the soak script ─────────────────────────────────────── */

static bool ejt_script_text(const char *dir, int64_t now, char *out, size_t cap)
{
    char dir_arg[700], now_arg[64];
    const char *argv[] = {"env",   now_arg, dir_arg, "bash",
                          "tools/scripts/soak_evidence.sh", "judge",
                          "--window-hours", "168", NULL};
    (void)snprintf(dir_arg, sizeof(dir_arg), "ZCL_SOAK_EVIDENCE_DIR=%s", dir);
    (void)snprintf(now_arg, sizeof(now_arg), "ZCL_SOAK_NOW=%lld", (long long)now);
    (void)zcl_spawn_capture(argv, out, cap, 20000);
    return out[0] != '\0';
}

static int ejt_case_soak_parity(void)
{
    static const struct {
        const char *name;
        int count;
        ejt_edit edit;
        int64_t now;
    } cases[] = {
        {"pr_green", 169, ejt_recycle, EJT_FRESH},
        {"pr_short", 12, ejt_healthy, EJT_SOAK_BASE + 11 * 3600 + 60},
        {"pr_hole", 169, ejt_hole, EJT_FRESH},
        {"pr_down", 169, ejt_soak_down, EJT_FRESH},
        {"pr_swap", 169, ejt_swap, EJT_FRESH},
        {"pr_amb", 169, ejt_ambiguous, EJT_FRESH},
        {"pr_stale", 169, ejt_healthy, EJT_FRESH + 2592000},
    };
    int failures = 0;
    TEST("soak: the C judge prints the same report as soak_evidence.sh judge "
         "on the same ledgers") {
        static char script[ZCL_JUDGE_TEXT_MAX];
        char dir[600];
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ejt_path(dir, sizeof(dir), cases[i].name);
            ASSERT(ejt_soak_ledger(dir, cases[i].count, cases[i].edit));
            ASSERT(ejt_script_text(dir, cases[i].now, script, sizeof(script)));
            ASSERT(ejt_soak_judge(dir, 168, cases[i].now, false));
            if (strcmp(script, g_res.text) != 0)
                printf("--- script\n%s--- c\n%s", script, g_res.text);
            ASSERT(strcmp(script, g_res.text) == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_evidence_judge(void);
int test_evidence_judge(void)
{
    int failures = 0;
    test_make_tmpdir(g_root, sizeof(g_root), "evidence_judge", "root");
    failures += ejt_case_sw_passes();
    failures += ejt_case_sw_fixture_gates();
    failures += ejt_case_sw_qualify();
    failures += ejt_case_sw_stale();
    failures += ejt_case_sw_streaks();
    failures += ejt_case_sw_skip_classes();
    failures += ejt_case_soak_verdicts();
    failures += ejt_case_soak_identity_posture();
    failures += ejt_case_soak_window_edges();
    failures += ejt_case_soak_parity();
    (void)test_rm_rf_recursive(g_root);
    if (failures == 0)
        printf("test_evidence_judge: all passed\n");
    else
        printf("test_evidence_judge: %d FAILED\n", failures);
    return failures;
}
