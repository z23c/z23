/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.stats (tools/command/native_dev_land_stats.c)
 * against a fixture outcomes ledger with known timestamps across two UTC
 * days. Every expected number below is computed by hand from the rows. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLS_PATH "dev.loop.land_stats"
#define DLS_D1 1794614400LL  /* 2026-11-14T00:00:00Z */
#define DLS_D2 1794700800LL  /* 2026-11-15T00:00:00Z */
#define DLS_NOW 1794744000LL /* 2026-11-15T12:00:00Z */

struct dls_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dls_run(struct dls_call *c, const char *ledger, long long hours)
{
    json_init(&c->input);
    json_set_object(&c->input);
    (void)json_push_kv_str(&c->input, "outcomes", ledger);
    (void)json_push_kv_int(&c->input, "now", DLS_NOW);
    if (hours > 0)
        (void)json_push_kv_int(&c->input, "hours", hours);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLS_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land_stats.v1");
    zcl_native_handle_dev_land_stats(&c->request, &c->reply);
}

static void dls_end(struct dls_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static int64_t dls_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -999999;
}

static const struct json_value *dls_sub(const struct dls_call *c, const char *key)
{
    return json_get(&c->reply.data, key);
}

static bool dls_flag(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static void dls_row(FILE *fp, const char *state, const char *phase,
                    const char *dim, long long start, long long end,
                    const char *terminal_key, const char *ts)
{
    (void)fprintf(fp,
                  "{\"seq\":1,\"ts\":\"%s\",\"state\":\"%s\",\"phase\":\"%s\","
                  "\"started\":%lld,\"%s\":%lld,\"dimension\":\"%s\","
                  "\"detail\":\"fixture\"}\n",
                  ts, state, phase, start, terminal_key, end, dim);
}

/* Two days. Day 1: landed 500 s and 800 s, failed prove/lint 600 s, failed
 * prove/test 1200 s, conflict 30 s, cancelled with started 0. Day 2: landed
 * 1000 s, 600 s (landed_at only) and 700 s, failed prove/lint 900 s, failed
 * prebuild 60 s, failed prove/test 120 s with only a ts to date it. One
 * landed row ended before the window and one line is not JSON. */
static void dls_fixture(const char *path)
{
    const char *tr = "terminal_recorded_at";
    FILE *fp = fopen(path, "wb");
    if (!fp)
        abort();
    dls_row(fp, "landed", "", "", DLS_D1 - 64800 - 900, DLS_D1 - 64800, tr,
            "2026-11-13T06:00:00Z");
    (void)fputs("this line is not json\n", fp);
    dls_row(fp, "landed", "", "", DLS_D1 + 3600, DLS_D1 + 4100, tr, "2026-11-14T01:08:20Z");
    dls_row(fp, "landed", "", "", DLS_D1 + 7200, DLS_D1 + 8000, tr, "2026-11-14T02:13:20Z");
    dls_row(fp, "failed", "prove", "lint", DLS_D1 + 10000, DLS_D1 + 10600, tr,
            "2026-11-14T02:56:40Z");
    dls_row(fp, "failed", "prove", "test", DLS_D1 + 12000, DLS_D1 + 13200, tr,
            "2026-11-14T03:40:00Z");
    dls_row(fp, "conflict", "rebase", "", DLS_D1 + 15000, DLS_D1 + 15030, tr,
            "2026-11-14T04:10:30Z");
    dls_row(fp, "cancelled", "", "", 0, DLS_D1 + 20000, tr, "2026-11-14T05:33:20Z");
    dls_row(fp, "landed", "", "", DLS_D2 + 3600, DLS_D2 + 4600, tr, "2026-11-15T01:16:40Z");
    dls_row(fp, "landed", "", "", DLS_D2 + 7200, DLS_D2 + 7800, "landed_at",
            "2026-11-15T02:10:00Z");
    dls_row(fp, "landed", "", "", DLS_D2 + 10000, DLS_D2 + 10700, tr, "2026-11-15T02:58:20Z");
    dls_row(fp, "failed", "prove", "lint", DLS_D2 + 12000, DLS_D2 + 12900, tr,
            "2026-11-15T03:35:00Z");
    dls_row(fp, "failed", "prebuild", "", DLS_D2 + 14000, DLS_D2 + 14060, tr,
            "2026-11-15T03:54:20Z");
    (void)fprintf(fp,
                  "{\"ts\":\"2026-11-15T10:00:00Z\",\"state\":\"failed\","
                  "\"phase\":\"prove\",\"started\":%lld,\"dimension\":\"test\"}\n",
                  DLS_D2 + 36000 - 120);
    (void)fclose(fp);
}

/* A ledger larger than the read cap: filler landed rows of about 1 KiB. */
static void dls_filler(const char *path, const char *ts, bool then_fixture,
                       const char *fixture_path)
{
    char pad[1001];
    FILE *fp = fopen(path, "wb");
    long long end = DLS_D1 - 10 * 86400;
    if (!fp)
        abort();
    memset(pad, 'x', sizeof(pad) - 1);
    pad[sizeof(pad) - 1] = '\0';
    for (int i = 0; i < 34 * 1024; i++)
        (void)fprintf(fp,
                      "{\"ts\":\"%s\",\"state\":\"other\",\"terminal_recorded_at\":%lld,"
                      "\"detail\":\"%s\"}\n",
                      ts, end, pad);
    if (then_fixture) {
        FILE *src = fopen(fixture_path, "rb");
        char buf[4096];
        size_t n;
        if (!src)
            abort();
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            (void)fwrite(buf, 1, n, fp);
        (void)fclose(src);
    }
    (void)fclose(fp);
}

static int dls_totals_case(const char *ledger)
{
    int failures = 0;
    struct dls_call c;
    TEST("land.stats: counts, failure rate, busy time and percentiles are exact") {
        const struct json_value *t, *days, *fb, *ld, *src;
        dls_run(&c, ledger, 48);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        t = dls_sub(&c, "totals");
        ASSERT_EQ(dls_int(t, "landed"), (int64_t)5);
        ASSERT_EQ(dls_int(t, "failed"), (int64_t)5);
        ASSERT_EQ(dls_int(t, "conflict"), (int64_t)1);
        ASSERT_EQ(dls_int(t, "cancelled"), (int64_t)1);
        ASSERT_EQ(dls_int(t, "failure_rate_permille"), (int64_t)500);
        ASSERT_EQ(dls_int(t, "busy_s"), (int64_t)(3130 + 3380));
        ASSERT_EQ(dls_int(t, "days_with_rows"), (int64_t)2);
        ASSERT_EQ(dls_int(t, "busy_permille_mean_of_days"), (int64_t)38);
        days = dls_sub(&c, "days");
        ASSERT_EQ((int)json_size(days), 2);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(days, 0), "day")), "2026-11-14");
        ASSERT_EQ(dls_int(json_at(days, 0), "busy_s"), (int64_t)3130);
        ASSERT_EQ(dls_int(json_at(days, 0), "busy_permille"), (int64_t)36);
        ASSERT_EQ(dls_int(json_at(days, 0), "landed"), (int64_t)2);
        ASSERT_EQ(dls_int(json_at(days, 0), "cancelled"), (int64_t)1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(days, 1), "day")), "2026-11-15");
        ASSERT_EQ(dls_int(json_at(days, 1), "busy_s"), (int64_t)3380);
        ASSERT_EQ(dls_int(json_at(days, 1), "busy_permille"), (int64_t)39);
        ASSERT_EQ(dls_int(json_at(days, 1), "failed"), (int64_t)3);
        fb = dls_sub(&c, "failures_by");
        ASSERT_EQ((int)json_size(fb), 3);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(fb, 0), "dimension")), "lint");
        ASSERT_EQ(dls_int(json_at(fb, 0), "rows"), (int64_t)2);
        ASSERT_EQ(dls_int(json_at(fb, 0), "slot_s"), (int64_t)1500);
        ASSERT_EQ(dls_int(json_at(fb, 0), "slot_min"), (int64_t)25);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(fb, 1), "dimension")), "test");
        ASSERT_EQ(dls_int(json_at(fb, 1), "rows"), (int64_t)2);
        ASSERT_EQ(dls_int(json_at(fb, 1), "slot_s"), (int64_t)1320);
        ASSERT_EQ(dls_int(json_at(fb, 1), "slot_min"), (int64_t)22);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(fb, 2), "phase")), "prebuild");
        ASSERT_EQ(dls_int(json_at(fb, 2), "slot_min"), (int64_t)1);
        ld = dls_sub(&c, "landed_duration");
        ASSERT_EQ(dls_int(ld, "n"), (int64_t)5);
        ASSERT_EQ(dls_int(ld, "median_s"), (int64_t)700);
        ASSERT_EQ(dls_int(ld, "p90_s"), (int64_t)1000);
        src = dls_sub(&c, "source");
        ASSERT_EQ(dls_int(src, "rows_skipped"), (int64_t)1);
        ASSERT(!dls_flag(src, "capped"));
        ASSERT(dls_flag(src, "window_covered"));
        ASSERT(strstr(json_get_str(dls_sub(&c, "screen")), "failure rate: 50.0%") != NULL);
        dls_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int dls_window_case(const char *ledger)
{
    int failures = 0;
    struct dls_call c;
    TEST("land.stats: a short window keeps only the newer day") {
        dls_run(&c, ledger, 12);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(dls_int(dls_sub(&c, "totals"), "landed"), (int64_t)3);
        ASSERT_EQ(dls_int(dls_sub(&c, "totals"), "failed"), (int64_t)3);
        ASSERT_EQ((int)json_size(dls_sub(&c, "days")), 1);
        dls_end(&c);
        PASS();
    }
    TEST("land.stats: hours out of range and a missing ledger are refused") {
        dls_run(&c, ledger, 721);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_FAILED);
        dls_end(&c);
        dls_run(&c, "test-tmp/dev_land_stats_absent/none.jsonl", 24);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_FAILED);
        dls_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int dls_cap_case(const char *dir, const char *fixture)
{
    int failures = 0;
    struct dls_call c;
    char big[600];
    TEST("land.stats: a ledger over the read cap is read from its tail and says so") {
        const struct json_value *src;
        (void)snprintf(big, sizeof(big), "%s/big.jsonl", dir);
        dls_filler(big, "2026-11-04T00:00:00Z", true, fixture);
        dls_run(&c, big, 48);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        src = dls_sub(&c, "source");
        ASSERT(dls_flag(src, "capped"));
        ASSERT(dls_int(src, "bytes_read") <= dls_int(src, "bytes_max"));
        ASSERT(dls_int(src, "bytes_total") > dls_int(src, "bytes_max"));
        ASSERT(dls_flag(src, "window_covered"));
        ASSERT_EQ(dls_int(dls_sub(&c, "totals"), "landed"), (int64_t)5);
        ASSERT_EQ(dls_int(dls_sub(&c, "totals"), "failed"), (int64_t)5);
        ASSERT(strstr(json_get_str(dls_sub(&c, "screen")), "capped:") != NULL);
        dls_end(&c);
        (void)remove(big);
        PASS();
    }
    TEST("land.stats: a cap that leaves the window uncovered is reported") {
        const struct json_value *src;
        (void)snprintf(big, sizeof(big), "%s/big.jsonl", dir);
        dls_filler(big, "2026-11-04T00:00:00Z", false, fixture);
        dls_run(&c, big, 24 * 30);
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        src = dls_sub(&c, "source");
        ASSERT(dls_flag(src, "capped"));
        ASSERT(!dls_flag(src, "window_covered"));
        ASSERT(strstr(json_get_str(dls_sub(&c, "screen")), "only partly covered") != NULL);
        dls_end(&c);
        (void)remove(big);
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_stats(void);
int test_dev_land_stats(void)
{
    int failures = 0;
    char dir[512], ledger[600];
    test_make_tmpdir(dir, sizeof(dir), "dev_land_stats", "rig");
    (void)snprintf(ledger, sizeof(ledger), "%s/outcomes.jsonl", dir);
    dls_fixture(ledger);
    failures += dls_totals_case(ledger);
    failures += dls_window_case(ledger);
    failures += dls_cap_case(dir, ledger);
    if (failures == 0)
        printf("test_dev_land_stats: all passed\n");
    else
        printf("test_dev_land_stats: %d FAILED\n", failures);
    return failures;
}
