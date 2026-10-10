/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.factory (tools/command/native_dev_factory.c):
 * one fixture per metric, written under a test tmpdir and handed to the leaf
 * through the ZCL_DEV_FACTORY_* path overrides. Every timestamp is relative
 * to the wall clock at the start of the test, so the window arithmetic is
 * exact whatever the date. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_dev_factory(void);
int test_dev_factory(void)
{
    printf("test_dev_factory: skipped on Windows\n");
    return 0;
}
#else
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#define DFX_HOUR 3600
#define DFX_NAME_40A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DFX_NAME_40B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DFX_NAME_40C "cccccccccccccccccccccccccccccccccccccccc"

struct dfx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dfx_begin(struct dfx_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "dev.agent.factory", NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_factory.v1");
}

static void dfx_end(struct dfx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void dfx_run(struct dfx_call *c, int64_t hours)
{
    dfx_begin(c);
    if (hours >= 0)
        (void)json_push_kv_int(&c->input, "hours", hours);
    zcl_native_handle_dev_factory(&c->request, &c->reply);
}

static bool dfx_ok(const struct dfx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* Walk a dotted path of object keys. */
static const struct json_value *dfx_at(const struct dfx_call *c,
                                       const char *path)
{
    char buf[256];
    const struct json_value *v = &c->reply.data;
    char *save = NULL;
    (void)snprintf(buf, sizeof(buf), "%s", path);
    for (char *k = strtok_r(buf, ".", &save); k && v;
         k = strtok_r(NULL, ".", &save))
        v = json_get(v, k);
    return v;
}

static double dfx_num(const struct dfx_call *c, const char *path)
{
    const struct json_value *v = dfx_at(c, path);
    if (v && v->type == JSON_INT)
        return (double)json_get_int(v);
    if (v && v->type == JSON_REAL)
        return json_get_real(v);
    return -12345.0;
}

static bool dfx_near(const struct dfx_call *c, const char *path, double want)
{
    double got = dfx_num(c, path);
    double d = got - want;
    return d < 0.01 && d > -0.01;
}

static bool dfx_str_is(const struct dfx_call *c, const char *path,
                       const char *want)
{
    const struct json_value *v = dfx_at(c, path);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static bool dfx_is_null(const struct dfx_call *c, const char *path)
{
    const struct json_value *v = dfx_at(c, path);
    return v && v->type == JSON_NULL;
}

static bool dfx_bool_is(const struct dfx_call *c, const char *path, bool want)
{
    const struct json_value *v = dfx_at(c, path);
    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}

static void dfx_write(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "dev_factory fixture: cannot write %s\n", path);
        abort();
    }
    (void)fputs(text, fp);
    (void)fclose(fp);
}

static void dfx_mkdirs(const char *path)
{
    char buf[1024];
    (void)snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(buf, 0700);
            *p = '/';
        }
    }
    (void)mkdir(buf, 0700);
}

static void dfx_age(const char *path, long age_s)
{
    struct timeval tv[2];
    gettimeofday(&tv[0], NULL);
    tv[0].tv_sec -= age_s;
    tv[1] = tv[0];
    (void)utimes(path, tv);
}

static void dfx_iso(long t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tmv;
    gmtime_r(&tt, &tmv);
    (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* One devbuild ledger row. */
static void dfx_job_line(char *out, size_t cap, const char *project, long q,
                         long started, long ended, double wait_s, double run_s,
                         double cpu_s, int rc, const char *tree,
                         const char *cmd, const char *cwd)
{
    (void)snprintf(out, cap,
                   "{\"project\":\"%s\",\"cwd\":\"%s\",\"queued\":%ld,"
                   "\"started\":%ld,\"ended\":%ld,\"wait_s\":%.1f,"
                   "\"run_s\":%.1f,\"cpu_s\":%.1f,\"rc\":%d,\"lane\":1,"
                   "\"mem_peak_mib\":10,\"tree\":\"%s\",\"cmd\":\"%s\"}\n",
                   project, cwd, q, started, ended, wait_s, run_s, cpu_s, rc,
                   tree, cmd);
}

static void dfx_jobs_fixture(const char *path, long now)
{
    char all[16384];
    char row[1024];
    size_t n = 0;
    const char *lane = "/srv/wt/feat";
    const char *lwt = "/srv/.local/state/z23/dev/land/wt/x/dev/land/wt";
#define DFX_ADD(...)                                                       \
    do {                                                                   \
        dfx_job_line(row, sizeof(row), __VA_ARGS__);                       \
        n += (size_t)snprintf(all + n, sizeof(all) - n, "%s", row);        \
    } while (0)
    /* land drive 1800 s and an overlapping land step: union is 2600 s */
    DFX_ADD("z23", now - 3700, now - 3600, now - 1800, 100, 1800, 900, 0, "t1",
            "z23-dev dev land drive", lwt);
    DFX_ADD("z23", now - 2500, now - 2400, now - 1000, 100, 1400, 700, 1, "t2",
            "z23-dev dev land step", lwt);
    /* lint twice, same tree/cmd/cwd: one duplicate, one failed */
    DFX_ADD("z23", now - 600, now - 500, now - 400, 10, 100, 10, 0, "tA",
            "make lint", lane);
    DFX_ADD("z23", now - 580, now - 500, now - 400, 30, 100, 10, 1, "tA",
            "make lint", lane);
    DFX_ADD("z23", now - 400, now - 300, now - 200, 10, 100, 50, 0, "tB",
            "make -j28 z23", lane);
    /* ends after now: run time is clipped to 100 s */
    DFX_ADD("z23", now - 150, now - 100, now + 500, 5, 600, 1, 0, "tC",
            "make t-fast-exact ONLY=x", lane);
    /* empty tree never counts as a duplicate */
    DFX_ADD("z23", now - 60, now - 50, now - 50, 0, 0, 0, 0, "", "ls", lane);
    DFX_ADD("z23", now - 60, now - 50, now - 50, 0, 0, 0, 0, "", "ls", lane);
    /* another project, and one queued before the 48 h window */
    DFX_ADD("other", now - 60, now - 50, now - 40, 0, 10, 1, 0, "tZ", "make",
            lane);
    DFX_ADD("z23", now - 49 * DFX_HOUR, now - 49 * DFX_HOUR + 5,
            now - 49 * DFX_HOUR + 50, 5, 45, 1, 0, "tY", "make old", lane);
    n += (size_t)snprintf(all + n, sizeof(all) - n, "this is not json\n");
#undef DFX_ADD
    dfx_write(path, all);
}

static void dfx_outcomes_fixture(const char *path, long now)
{
    char all[4096];
    char ts1[40], ts2[40], tsold[40];
    dfx_iso(now - DFX_HOUR, ts1, sizeof(ts1));
    dfx_iso(now - 2 * DFX_HOUR, ts2, sizeof(ts2));
    dfx_iso(now - 49 * DFX_HOUR, tsold, sizeof(tsold));
    (void)snprintf(
        all, sizeof(all),
        "{\"ts\":\"%s\",\"state\":\"landed\",\"seq\":1,\"detail\":\"ok\"}\n"
        "{\"ts\":\"%s\",\"state\":\"landed\",\"seq\":2,\"detail\":\"ok\"}\n"
        "{\"ts\":\"%s\",\"state\":\"failed\",\"seq\":3,\"detail\":\"boom\"}\n"
        "{\"ts\":\"%s\",\"state\":\"conflict\",\"seq\":4,\"detail\":\"boom\"}\n"
        "{\"ts\":\"%s\",\"state\":\"cancelled\",\"seq\":5,"
        "\"detail\":\"operator cancelled\"}\n"
        "{\"ts\":\"%s\",\"state\":\"failed\",\"seq\":6,\"detail\":\"too old\"}\n"
        "{broken\n",
        ts1, ts2, ts1, ts2, ts1, tsold);
    dfx_write(path, all);
}

static void dfx_attempt(const char *dir, const char *name, const char *phases,
                        const char *selection, long age_s)
{
    char path[1400];
    char sub[1400];
    (void)snprintf(sub, sizeof(sub), "%s/%s/logs", dir, name);
    dfx_mkdirs(sub);
    (void)snprintf(path, sizeof(path), "%s/%s/phases.txt", dir, name);
    dfx_write(path, phases);
    if (selection) {
        (void)snprintf(path, sizeof(path), "%s/%s/logs/a.test-selection.log",
                       dir, name);
        dfx_write(path, selection);
    }
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    dfx_age(path, age_s);
}

static void dfx_attempts_fixture(const char *dir)
{
    const char *real =
        "step=compile status=ok elapsed_ms=1000\n"
        "step=test status=ok elapsed_ms=120000\n"
        "lint_wall_ms=5000\n"
        "proof_cpu_children_ms=3600000\n"
        "queue_lock_wait_ms=7000\n";
    dfx_mkdirs(dir);
    dfx_attempt(dir, DFX_NAME_40A "-" DFX_NAME_40B ".s1", real,
                "test_selection=exact reason=none groups_selected=3\n", 60);
    dfx_attempt(dir, DFX_NAME_40A "-" DFX_NAME_40B ".s2", real,
                "test_selection=universal reason=header_change "
                "groups_selected=900\n", 120);
    dfx_attempt(dir, DFX_NAME_40C "-" DFX_NAME_40B ".s1",
                "queue_lock_wait_ms=2000\n", NULL, 30);
    dfx_attempt(dir, DFX_NAME_40C "-" DFX_NAME_40A ".s1", real, NULL,
                49 * DFX_HOUR);
}

/* Two cwds, a first and a second job each. cwd_a has a failed second run
 * whose verdict (written by the test) ends with it; cwd_b's failed second
 * run has no verdict. */
static void dfx_cold_fixture(const char *path, const char *cwd_a,
                             const char *cwd_b, long now)
{
    char all[4096], row[1024];
    size_t n = 0;
#define DFX_COLD(...)                                                      \
    do {                                                                   \
        dfx_job_line(row, sizeof(row), __VA_ARGS__);                       \
        n += (size_t)snprintf(all + n, sizeof(all) - n, "%s", row);        \
    } while (0)
    DFX_COLD("z23", now - 1000, now - 950, now - 50, 50, 900, 0, 0, "tA1",
             "make -j28 z23", cwd_a);
    DFX_COLD("z23", now - 500, now - 300, now, 200, 300, 0, 1, "tA2",
             "make -j28 z23", cwd_a);
    DFX_COLD("z23", now - 900, now - 800, now - 300, 100, 500, 0, 0, "tB1",
             "make t-fast-exact ONLY=x", cwd_b);
    DFX_COLD("z23", now - 400, now - 390, now - 190, 10, 200, 0, 1, "tB2",
             "make t-fast-exact ONLY=x", cwd_b);
#undef DFX_COLD
    dfx_write(path, all);
}

static void dfx_proc_fixture(const char *dir)
{
    char sub[1024], path[1100];
    (void)snprintf(sub, sizeof(sub), "%s/pressure", dir);
    dfx_mkdirs(sub);
    (void)snprintf(path, sizeof(path), "%s/memory", sub);
    dfx_write(path, "some avg10=1.50 avg60=2.50 avg300=3.50 total=99\n"
                    "full avg10=0.00 avg60=0.00 avg300=0.00 total=1\n");
    (void)snprintf(path, sizeof(path), "%s/cpu", sub);
    dfx_write(path, "some avg10=0.10 avg60=0.20 avg300=0.30 total=5\n");
}

static void dfx_env(const char *jobs, const char *land, const char *att,
                    const char *proc)
{
    (void)setenv("ZCL_DEV_FACTORY_JOBS", jobs, 1);
    (void)setenv("ZCL_DEV_FACTORY_LAND_DIR", land, 1);
    (void)setenv("ZCL_DEV_FACTORY_ATTEMPTS", att, 1);
    (void)setenv("ZCL_DEV_FACTORY_PROC", proc, 1);
}

static void dfx_unenv(void)
{
    (void)unsetenv("ZCL_DEV_FACTORY_JOBS");
    (void)unsetenv("ZCL_DEV_FACTORY_LAND_DIR");
    (void)unsetenv("ZCL_DEV_FACTORY_ATTEMPTS");
    (void)unsetenv("ZCL_DEV_FACTORY_PROC");
}

int test_dev_factory(void);
int test_dev_factory(void)
{
    int failures = 0;
    char base[512], jobs[640], land[640], att[640], proc[640], path[800];
    struct dfx_call c;
    long now = (long)time(NULL);

    test_make_tmpdir(base, sizeof(base), "dev_factory", "t");
    (void)snprintf(jobs, sizeof(jobs), "%s/jobs.jsonl", base);
    (void)snprintf(land, sizeof(land), "%s/land", base);
    (void)snprintf(att, sizeof(att), "%s/attempts", base);
    (void)snprintf(proc, sizeof(proc), "%s/proc", base);
    dfx_mkdirs(land);
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    dfx_jobs_fixture(jobs, now);
    dfx_outcomes_fixture(path, now);
    dfx_attempts_fixture(att);
    dfx_proc_fixture(proc);
    dfx_env(jobs, land, att, proc);

    TEST("factory: rejects hours outside 1..720") {
        dfx_run(&c, 0);
        ASSERT(!dfx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dfx_end(&c);
        dfx_run(&c, 721);
        ASSERT(!dfx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dfx_end(&c);
        PASS();
    }

    TEST("factory: job classes, percentiles and the window filter") {
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "hours"), 48);
        ASSERT_EQ((int)dfx_num(&c, "jobs.skipped_lines"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.total"), 8);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.land.n"), 2);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.land.failed"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.lint.n"), 2);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.lint.failed"), 1);
        ASSERT(dfx_near(&c, "jobs.classes.lint.wait_p50_s", 10));
        ASSERT(dfx_near(&c, "jobs.classes.lint.wait_p95_s", 30));
        ASSERT(dfx_near(&c, "jobs.classes.lint.run_p50_s", 100));
        ASSERT(dfx_near(&c, "jobs.classes.lint.run_sum_s", 200));
        ASSERT(dfx_near(&c, "jobs.classes.lint.cpu_sum_s", 20));
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.build.n"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.t_fast.n"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.other.n"), 2);
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.prepare.n"), 0);
        dfx_end(&c);
        PASS();
    }

    TEST("factory: duplicates, lander and lane busy, lane lint") {
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.duplicates"), 1);
        ASSERT(dfx_near(&c, "jobs.lander_busy_pct",
                        2600.0 * 100.0 / (48.0 * DFX_HOUR)));
        /* 1800 + 1400 + 100 + 100 + 100 + 100 (the t-fast job clipped) */
        ASSERT(dfx_near(&c, "jobs.lanes_busy_pct",
                        3600.0 * 100.0 / (3.0 * 48.0 * DFX_HOUR)));
        ASSERT_EQ((int)dfx_num(&c, "jobs.lane_lint.n"), 2);
        ASSERT_EQ((int)dfx_num(&c, "jobs.lane_lint.failed"), 1);
        dfx_end(&c);
        PASS();
    }

    TEST("factory: a shorter window drops the older jobs") {
        dfx_run(&c, 1);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.classes.land.n"), 1);
        dfx_end(&c);
        PASS();
    }

    TEST("factory: land outcomes counts and top non-landed details") {
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "land_outcomes.counts.landed"), 2);
        ASSERT_EQ((int)dfx_num(&c, "land_outcomes.counts.failed"), 1);
        ASSERT_EQ((int)dfx_num(&c, "land_outcomes.counts.conflict"), 1);
        ASSERT_EQ((int)dfx_num(&c, "land_outcomes.counts.cancelled"), 1);
        ASSERT_EQ((int)dfx_num(&c, "land_outcomes.skipped_lines"), 1);
        {
            const struct json_value *top =
                dfx_at(&c, "land_outcomes.top_non_landed");
            ASSERT(top && top->type == JSON_ARR);
            ASSERT_EQ((int)json_size(top), 2);
            ASSERT_STR_EQ(json_get_str(json_get(json_at(top, 0), "detail")),
                          "boom");
            ASSERT_EQ((int)json_get_int(json_get(json_at(top, 0), "n")), 2);
        }
        dfx_end(&c);
        PASS();
    }

    TEST("factory: attempts split short refusals from real proofs") {
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.attempts"), 3);
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.short_refusals"), 1);
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.real"), 2);
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.superseded"), 1);
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.lock_wait_ms.max"), 7000);
        ASSERT_EQ((int)dfx_num(&c, "proof_attempts.lock_wait_ms.sum"), 16000);
        dfx_end(&c);
        PASS();
    }

    TEST("factory: attempts group by exact and universal:reason") {
        const struct json_value *by;
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        by = dfx_at(&c, "proof_attempts.by_selection");
        ASSERT(by && by->type == JSON_ARR);
        ASSERT_EQ((int)json_size(by), 2);
        for (size_t i = 0; i < json_size(by); i++) {
            const struct json_value *row = json_at(by, i);
            const char *key = json_get_str(json_get(row, "key"));
            ASSERT(key != NULL);
            ASSERT_EQ((int)json_get_int(json_get(row, "n")), 1);
            ASSERT(strcmp(key, "exact") == 0 ||
                   strcmp(key, "universal:header_change") == 0);
            ASSERT(json_get_real(json_get(row, "avg_test_s")) > 119.99);
            ASSERT(json_get_real(json_get(row, "avg_test_s")) < 120.01);
            ASSERT(json_get_real(json_get(row, "avg_cpu_h")) > 0.99);
            ASSERT(json_get_real(json_get(row, "avg_cpu_h")) < 1.01);
        }
        dfx_end(&c);
        PASS();
    }

    TEST("factory: host pressure from the proc fixture, absent is null") {
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT(dfx_near(&c, "host.pressure.memory.avg10", 1.5));
        ASSERT(dfx_near(&c, "host.pressure.memory.avg60", 2.5));
        ASSERT(dfx_near(&c, "host.pressure.memory.avg300", 3.5));
        ASSERT(dfx_near(&c, "host.pressure.cpu.avg300", 0.3));
        ASSERT(dfx_is_null(&c, "host.pressure.io"));
        ASSERT(dfx_at(&c, "host.shm_used_bytes") != NULL);
        dfx_end(&c);
        PASS();
    }

    TEST("factory: absent sources report absent, not a failure") {
        char nowhere[700];
        (void)snprintf(nowhere, sizeof(nowhere), "%s/none", base);
        dfx_env(nowhere, nowhere, nowhere, nowhere);
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT(dfx_str_is(&c, "jobs.source", "absent"));
        ASSERT(dfx_str_is(&c, "land_outcomes.source", "absent"));
        ASSERT(dfx_str_is(&c, "proof_attempts.source", "absent"));
        ASSERT(dfx_is_null(&c, "host.pressure.memory"));
        dfx_end(&c);
        dfx_env(jobs, land, att, proc);
        PASS();
    }

    TEST("factory: an oversized ledger line is counted, never truncated") {
        char j2[700];
        FILE *fp;
        (void)snprintf(j2, sizeof(j2), "%s/jobs_big.jsonl", base);
        fp = fopen(j2, "w");
        ASSERT(fp != NULL);
        (void)fputs("{\"project\":\"z23\",\"cmd\":\"", fp);
        for (int i = 0; i < 1100000; i++)
            (void)fputc('x', fp);
        (void)fputs("\"}\n", fp);
        (void)fclose(fp);
        (void)setenv("ZCL_DEV_FACTORY_JOBS", j2, 1);
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.oversized_lines"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.total"), 0);
        dfx_end(&c);
        dfx_env(jobs, land, att, proc);
        PASS();
    }

    TEST("factory: cold-start proxy and failed runs named by a verdict") {
        char cwd_a[700], cwd_b[700], vdir[800], vpath[900], jobs_c[700];
        char vtext[256];
        (void)snprintf(cwd_a, sizeof(cwd_a), "%s/wt_a", base);
        (void)snprintf(cwd_b, sizeof(cwd_b), "%s/wt_b", base);
        (void)snprintf(jobs_c, sizeof(jobs_c), "%s/jobs_cold.jsonl", base);
        (void)snprintf(vdir, sizeof(vdir), "%s/build", cwd_a);
        (void)snprintf(vpath, sizeof(vpath), "%s/test-verdict.json", vdir);
        dfx_mkdirs(vdir);
        (void)snprintf(vtext, sizeof(vtext),
                       "{\"ended_unix\":%ld,\"failed_groups\":"
                       "[\"zcl_group_b\",\"zcl_group_a\"]}\n",
                       now);
        dfx_write(vpath, vtext);
        dfx_cold_fixture(jobs_c, cwd_a, cwd_b, now);
        (void)setenv("ZCL_DEV_FACTORY_JOBS", jobs_c, 1);
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.total"), 4);
        ASSERT_EQ((int)dfx_num(&c, "jobs.first_job_per_cwd.first.n"), 2);
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.first.run_p50_s", 500));
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.first.run_p95_s", 900));
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.first.run_sum_s", 1400));
        ASSERT_EQ((int)dfx_num(&c, "jobs.first_job_per_cwd.non_first.n"), 2);
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.non_first.run_p50_s", 200));
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.non_first.run_p95_s", 300));
        ASSERT(dfx_near(&c, "jobs.first_job_per_cwd.non_first.run_sum_s", 500));
        ASSERT_EQ((int)dfx_num(&c, "jobs.first_job_per_cwd.tracked_cwds"), 2);
        ASSERT(dfx_bool_is(&c, "jobs.first_job_per_cwd.cwd_cap_hit", false));
        /* build: 900 - 300 = 600; t_fast: 500 - 200 = 300 */
        ASSERT(dfx_near(&c, "jobs.cold_build_seconds_estimate", 900));
        ASSERT(dfx_str_is(&c, "jobs.cold_build_basis", "proxy"));
        ASSERT_EQ((int)dfx_num(&c, "jobs.cold_build_unbaselined_first_jobs"), 0);
        ASSERT_EQ((int)dfx_num(&c, "jobs.failed_runs_named"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.failed_runs_unnamed"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.failed_groups_overflow"), 0);
        {
            const struct json_value *g = dfx_at(&c, "jobs.failed_groups");
            ASSERT(g && g->type == JSON_ARR);
            ASSERT_EQ((int)json_size(g), 2);
            ASSERT_STR_EQ(json_get_str(json_get(json_at(g, 0), "group")),
                          "zcl_group_a");
            ASSERT_EQ((int)json_get_int(json_get(json_at(g, 0), "n")), 1);
            ASSERT_STR_EQ(json_get_str(json_get(json_at(g, 1), "group")),
                          "zcl_group_b");
        }
        dfx_end(&c);
        dfx_env(jobs, land, att, proc);
        PASS();
    }

    TEST("factory: first-seen cwd table caps at 4096 and says so") {
        char capf[700], row[1024];
        FILE *fp;
        (void)snprintf(capf, sizeof(capf), "%s/jobs_cap.jsonl", base);
        fp = fopen(capf, "w");
        ASSERT(fp != NULL);
        for (int i = 0; i < 4097; i++) {
            char cwd[64];
            (void)snprintf(cwd, sizeof(cwd), "/cap/wt%d", i);
            dfx_job_line(row, sizeof(row), "z23", now - 100, now - 90, now - 80,
                         10, 10, 0, 0, "tC", "make", cwd);
            (void)fputs(row, fp);
        }
        (void)fclose(fp);
        (void)setenv("ZCL_DEV_FACTORY_JOBS", capf, 1);
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.first_job_per_cwd.tracked_cwds"), 4096);
        ASSERT(dfx_bool_is(&c, "jobs.first_job_per_cwd.cwd_cap_hit", true));
        dfx_end(&c);
        dfx_env(jobs, land, att, proc);
        PASS();
    }

    TEST("factory: cold t-fast runs by cpu threshold, serial ones counted") {
        char cwd[700], jobs_k[700], all[4096], row[1024];
        size_t n = 0;
        FILE *fp;
        (void)snprintf(cwd, sizeof(cwd), "%s/wt_k", base);
        (void)snprintf(jobs_k, sizeof(jobs_k), "%s/jobs_k.jsonl", base);
        /* cold + -j (800 s), cold + serial (500 s), warm at the threshold
         * (100 s), warm serial (40 s), and a non-t-fast build (ignored). */
#define DFX_K(...)                                                         \
    do {                                                                   \
        dfx_job_line(row, sizeof(row), __VA_ARGS__);                       \
        n += (size_t)snprintf(all + n, sizeof(all) - n, "%s", row);        \
    } while (0)
        DFX_K("z23", now - 900, now - 890, now - 90, 10, 800, 700, 0, "tK1",
              "make -j28 t-fast-exact ONLY=a", cwd);
        DFX_K("z23", now - 800, now - 790, now - 300, 10, 500, 650, 1, "tK2",
              "make t-fast-exact ONLY=b", cwd);
        DFX_K("z23", now - 700, now - 695, now - 595, 5, 100, 600, 0, "tK3",
              "make -j28 t-fast ONLY=c", cwd);
        DFX_K("z23", now - 600, now - 599, now - 559, 1, 40, 30, 0, "tK4",
              "make t-fast-exact ONLY=d", cwd);
        DFX_K("z23", now - 500, now - 490, now - 10, 10, 900, 900, 0, "tK5",
              "make -j28 z23", cwd);
#undef DFX_K
        fp = fopen(jobs_k, "w");
        ASSERT(fp != NULL);
        (void)fputs(all, fp);
        (void)fclose(fp);
        (void)setenv("ZCL_DEV_FACTORY_JOBS", jobs_k, 1);
        dfx_run(&c, 48);
        ASSERT(dfx_ok(&c));
        ASSERT_EQ((int)dfx_num(&c, "jobs.cold_t_fast_n"), 2);
        ASSERT(dfx_near(&c, "jobs.cold_t_fast_run_s", 1300));
        ASSERT_EQ((int)dfx_num(&c, "jobs.cold_t_fast_without_j"), 1);
        ASSERT_EQ((int)dfx_num(&c, "jobs.warm_t_fast_n"), 2);
        ASSERT(dfx_near(&c, "jobs.cold_t_fast_cpu_threshold_s", 600));
        dfx_end(&c);
        dfx_env(jobs, land, att, proc);
        PASS();
    }

_test_next:;
    dfx_unenv();
    if (failures == 0)
        printf("test_dev_factory: all passed\n");
    else
        printf("test_dev_factory: %d FAILED\n", failures);
    return failures;
}
#endif
