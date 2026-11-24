/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: the red-main circuit breaker
 * (native_dev_land_red_breaker.c). The pure policy is checked on fixture
 * failure sets; the driver is driven step by step with the "red" proof stub,
 * which fails one test group on every pair whose tree lacks red-fix, so the
 * outcomes ledger the breaker reads is the one the driver itself wrote.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)

#include "command/native_dev_land_red_breaker.h"

#include <time.h>

#define DLRB_T_GROUP "test_red_fixture"

/* ── pure policy on fixture failure sets ─────────────────────────────── */

static void dlrb_t_fail(struct dlrb_fail *f, long long seq, const char *lane,
                        const char *paths)
{
    memset(f, 0, sizeof(*f));
    f->seq = seq;
    f->at = 1000 + seq;
    f->lane = dlrb_lane("/w/lanes", lane);
    dlrb_files_parse(&f->files, paths);
}

static int dlrb_t_trip_pure(void)
{
    int failures = 0;
    TEST("land red main: K disjoint failures from distinct lanes trip") {
        struct dlrb_fail cur, c[3];
        long long since = 0, since_at = 0;
        dlrb_t_fail(&cur, 9, "lane-c", "c.txt\n");
        dlrb_t_fail(&c[0], 8, "lane-b", "b.txt\n");
        dlrb_t_fail(&c[1], 7, "lane-a", "a.txt\nshared/a.h\n");
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)2);
        ASSERT_EQ(since, 7LL);
        ASSERT_EQ(since_at, 1007LL);
        /* One candidate short of K does not trip. */
        ASSERT_EQ(dlrb_trip_pick(c, 1, &cur, 2, &since, &since_at), (size_t)1);
        PASS();
    }
_test_next:;
    return failures;
}

static int dlrb_t_no_trip_pure(void)
{
    int failures = 0;
    TEST("land red main: same-lane repeats and overlapping files never count") {
        struct dlrb_fail cur, c[3];
        long long since = 0, since_at = 0;
        dlrb_t_fail(&cur, 9, "lane-a", "a3.txt\n");
        /* The failing lane's own earlier rows. */
        dlrb_t_fail(&c[0], 8, "lane-a", "a2.txt\n");
        dlrb_t_fail(&c[1], 7, "lane-a", "a1.txt\n");
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)0);
        /* Another lane repeating itself counts once. */
        dlrb_t_fail(&c[0], 8, "lane-b", "b2.txt\n");
        dlrb_t_fail(&c[1], 7, "lane-b", "b1.txt\n");
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)1);
        /* Distinct lanes touching the same file count once. */
        dlrb_t_fail(&c[0], 8, "lane-b", "same.c\n");
        dlrb_t_fail(&c[1], 7, "lane-c", "same.c\nother.c\n");
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)1);
        /* A candidate overlapping the failing row itself never counts. */
        dlrb_t_fail(&c[0], 8, "lane-b", "a3.txt\n");
        dlrb_t_fail(&c[1], 7, "lane-c", "c.txt\n");
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)1);
        /* An unreadable change set is never disjoint. */
        dlrb_t_fail(&c[0], 8, "lane-b", "b.txt\n");
        cur.files.known = false;
        ASSERT_EQ(dlrb_trip_pick(c, 2, &cur, 2, &since, &since_at), (size_t)0);
        PASS();
    }
_test_next:;
    return failures;
}

static void dlrb_t_parked_row(struct dl_row *r, long long seq,
                              const char *mark)
{
    memset(r, 0, sizeof(*r));
    r->seq = seq;
    (void)snprintf(r->state, sizeof(r->state), "queued");
    (void)snprintf(r->phase, sizeof(r->phase), DLRB_PHASE);
    (void)snprintf(r->red_main, sizeof(r->red_main), "%s", mark);
}

static int dlrb_t_age_pure(void)
{
    int failures = 0;
    struct dl_row *rows = calloc(3, sizeof(*rows));
    TEST("land red main: an episode ages out by time and by its maximum") {
        struct dlrb_policy p = { true, 2, 100, 1000 };
        struct dlrb_episode e[2];
        struct dlrb_mark m;
        char text[128];
        ASSERT(rows != NULL);
        dlrb_t_parked_row(&rows[0], 3, "parked:" DLRB_T_GROUP ":1:5000:5050");
        dlrb_t_parked_row(&rows[1], 4, "parked:" DLRB_T_GROUP ":2:5010:5090");
        dlrb_t_parked_row(&rows[2], 5, "parked:" DLRB_T_GROUP ":1:5000:5070");
        (void)snprintf(rows[2].phase, sizeof(rows[2].phase), "rebase");
        ASSERT_EQ(dlrb_episodes(rows, 3, e, 2), (size_t)1);
        ASSERT_STR_EQ(e[0].group, DLRB_T_GROUP);
        ASSERT_EQ(e[0].parked, (size_t)2); /* a released row is not parked */
        ASSERT_EQ(e[0].since, 1LL);
        ASSERT_EQ(e[0].newest_at, 5090LL);
        ASSERT(dlrb_episode_live(&e[0], &p, 5190));
        ASSERT(!dlrb_episode_live(&e[0], &p, 5191)); /* newest too old */
        p.age_s = 100000;
        ASSERT(dlrb_episode_live(&e[0], &p, 6000));
        ASSERT(!dlrb_episode_live(&e[0], &p, 6001)); /* episode maximum */
        /* The row field: a parsed mark round-trips; anything else is "". */
        ASSERT(dlrb_mark_parse(rows[0].red_main, &m) && !m.cleared);
        m.cleared = true;
        ASSERT(dlrb_mark_format(&m, text, sizeof(text)));
        ASSERT_STR_EQ(text, "cleared:" DLRB_T_GROUP ":1:5000:5050");
        ASSERT(dlrb_field_ok(""));
        ASSERT(!dlrb_field_ok("parked:" DLRB_T_GROUP ":1:5000"));
        ASSERT(!dlrb_field_ok("parked:bad-group:1:2:3"));
        ASSERT(!dlrb_field_ok("waived:" DLRB_T_GROUP ":1:2:3"));
        PASS();
    }
_test_next:;
    free(rows);
    return failures;
}

static int dlrb_t_only_group(void)
{
    int failures = 0;
    TEST("land red main: only a failure of the red group alone can park") {
        char dir[512], path[700];
        test_make_tmpdir(dir, sizeof(dir), "dev_land", "red_only_group");
        (void)snprintf(path, sizeof(path), "%s/runner.test.log", dir);
        /* The runner's tail: a load-flaky list, then the failed list. */
        ASSERT(dlx_write(path,
            "SOME TESTS FAILED - 1/1613 groups failed\n"
            "Load-flaky groups (counted as PASS):\n"
            "  - test_host_build\n"
            "Failed groups:\n"
            "  - " DLRB_T_GROUP ": exit code=1 log=./test-tmp/a.log\n"
            "      repro: make t-fast ONLY=" DLRB_T_GROUP "\n"));
        ASSERT(dlrb_log_only_group(path, DLRB_T_GROUP));
        ASSERT(!dlrb_log_only_group(path, "test_other"));
        ASSERT(dlx_write(path,
            "Failed groups:\n"
            "  - " DLRB_T_GROUP ": exit code=1 log=./test-tmp/a.log\n"
            "      repro: make t-fast ONLY=" DLRB_T_GROUP "\n"
            "  - test_own_change: exit code=1 log=./test-tmp/b.log\n"));
        ASSERT(!dlrb_log_only_group(path, DLRB_T_GROUP));
        ASSERT(dlx_write(path, "ALL TESTS PASSED\n"));
        ASSERT(!dlrb_log_only_group(path, DLRB_T_GROUP));
        (void)snprintf(path, sizeof(path), "%s/absent.test.log", dir);
        ASSERT(!dlrb_log_only_group(path, DLRB_T_GROUP));
        PASS();
    }
_test_next:;
    return failures;
}

/* ── the driver, step by step ────────────────────────────────────────── */

/* One branch off origin/main writing `path`. */
static bool dlrb_t_branch(struct dlx_rig *rig, const char *name,
                          const char *path, char tip[64])
{
    return dlx_qp_branch(rig, name, path, "row\n", NULL, NULL, tip);
}

static bool dlrb_t_submit(struct dlx_rig *rig, const char *tip,
                          const char *note, int64_t seq)
{
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    (void)json_push_kv_str(&c.input, "note", note);
    bool ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == seq;
    if (!ok)
        printf("[submit %s seq=%lld code=%s] ", note,
               (long long)dlx_int(&c, "seq"), dlx_err_code(&c));
    dlx_end(&c);
    return ok;
}

/* A step that must reply `state`; `parked` the parked_rows it reports
 * (-1: not checked). */
static bool dlrb_t_step(const char *state, int64_t parked)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (parked < 0 || dlx_int(&c, "parked_rows") == parked);
    if (!ok)
        printf("[step want=%s got=%s parked=%lld code=%s detail=%s] ", state,
               dlx_str(&c, "state"), (long long)dlx_int(&c, "parked_rows"),
               dlx_err_code(&c), dlx_str(&c, "detail"));
    dlx_end(&c);
    return ok;
}

/* A step that must reply `state` with `members` train members (0: none). */
static bool dlrb_t_step_members(const char *state, int64_t members)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              dlx_int(&c, "train_members") == (members ? members : -1);
    if (!ok) {
        char dir[1200], path[1400];
        static char log[65536];
        size_t n = 0;
        printf("[step want=%s/%lld got=%s/%lld code=%s detail=%s] ", state,
               (long long)members, dlx_str(&c, "state"),
               (long long)dlx_int(&c, "train_members"), dlx_err_code(&c),
               dlx_str(&c, "detail"));
        dlx_landdir(dir, sizeof(dir));
        (void)snprintf(path, sizeof(path), "%s/logs/land-%lld-a1.log", dir,
                       (long long)dlx_int(&c, "seq"));
        if (dlx_slurp(path, log, sizeof(log) - 1, &n)) {
            log[n] = '\0';
            for (char *line = strtok(log, "\n"); line; line = strtok(NULL, "\n"))
                if (strstr(line, "train"))
                    printf("[log %s] ", line);
        }
    }
    dlx_end(&c);
    return ok;
}

static bool dlrb_t_prove(const char *verdict, int64_t parked)
{
    return dlrb_t_step("started", -1) && dlrb_t_step(verdict, parked);
}

/* Step until the queue is empty (at most `cap` steps); `states` names every
 * reply, and no step may fail or park. */
static bool dlrb_t_drain(int cap, char *states, size_t states_cap)
{
    states[0] = '\0';
    for (int i = 0; i < cap; i++) {
        struct dlx_call c;
        dlx_begin(&c, "step");
        bool ok = dlx_run(&c) && dlx_ok(&c);
        const char *s = ok ? dlx_str(&c, "state") : dlx_err_code(&c);
        size_t used = strlen(states);
        (void)snprintf(states + used, states_cap - used, "%s%s",
                       used ? "," : "", s);
        bool empty = ok && strcmp(s, "empty") == 0;
        ok = ok && strcmp(s, "failed") != 0 && strcmp(s, "parked") != 0;
        dlx_end(&c);
        if (!ok || empty) {
            if (!ok)
                printf("[drain %s] ", states);
            return ok;
        }
    }
    printf("[drain did not empty: %s] ", states);
    return false;
}

static void dlrb_t_env(void)
{
    setenv("ZCL_LAND_PROOF_STUB", "red", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    setenv("ZCL_LAND_PROOF_STUB_RED_GROUP", DLRB_T_GROUP, 1);
}

static void dlrb_t_unenv(void)
{
    unsetenv("ZCL_LAND_PROOF_STUB_RED_GROUP");
    unsetenv("ZCL_LAND_RED_MAIN_NOW");
    unsetenv("ZCL_LAND_RED_MAIN");
    dlx_restore();
}

/* Status: the breaker's one entry, or none (`group` NULL). */
static bool dlrb_t_status(const char *group, int64_t since, int64_t parked)
{
    struct dlx_call c;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *arr = dlx_arr(&c, "main_red_breaker");
    bool ok = arr && arr->num_children == (group ? 1u : 0u);
    if (ok && group) {
        const struct json_value *e = &arr->children[0];
        ok = dlx_eq_str(dlx_jstr(e, "group"), group) &&
             json_get_int(json_get(e, "since_seq")) == since &&
             json_get_int(json_get(e, "parked")) == parked &&
             dlx_has(dlx_jstr(e, "line"), "main red on ");
    }
    dlx_end(&c);
    return ok;
}

/* Rows 1 and 2 (lanes one and two, disjoint files) fail the red group and
 * stay failed; row 3 (lane three) trips the breaker and is parked. */
static bool dlrb_t_trip(struct dlx_rig *rig, const char *tag)
{
    char t1[64], t2[64], t3[64], rig_tag[96];
    dlx_isolate(tag);
    dlrb_t_env();
    /* Its own directory: the isolate dir holds the fixture git identity. */
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    return dlx_rig_make(rig, rig_tag) &&
           dlrb_t_branch(rig, "r1", "f1.txt", t1) &&
           dlrb_t_branch(rig, "r2", "f2.txt", t2) &&
           dlrb_t_branch(rig, "r3", "f3.txt", t3) &&
           dlrb_t_submit(rig, t1, "lane-one", 1) &&
           dlrb_t_submit(rig, t2, "lane-two", 2) &&
           dlrb_t_submit(rig, t3, "lane-three", 3) &&
           dlrb_t_prove("failed", -1) && dlrb_t_prove("failed", -1) &&
           dlrb_t_prove("parked", 1);
}

/* The ledger text, for landed-row and marker checks. */
static bool dlrb_t_ledger(char *text, size_t cap)
{
    char dir[1200], path[1400];
    size_t n = 0;
    dlx_landdir(dir, sizeof(dir));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", dir);
    if (!dlx_slurp(path, text, cap - 1, &n))
        return false;
    text[n] = '\0';
    return true;
}

static size_t dlrb_t_count(const char *text, const char *frag)
{
    size_t n = 0;
    for (const char *p = text; (p = strstr(p, frag)) != NULL; p++)
        n++;
    return n;
}

static int dlrb_t_trip_and_park(void)
{
    int failures = 0;
    TEST("land red main: the third disjoint failure parks instead of failing") {
        struct dlx_rig rig;
        static char text[262144];
        ASSERT(dlrb_t_trip(&rig, "red_trip"));
        ASSERT(dlrb_t_status(DLRB_T_GROUP, 1, 1));
        ASSERT(dlrb_t_step("empty", -1)); /* a parked row is not picked */
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"failed\""), (size_t)2);
        ASSERT_EQ(dlrb_t_count(text, "\"seq\":3,"), (size_t)0);
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

static int dlrb_t_same_lane(void)
{
    int failures = 0;
    TEST("land red main: one lane failing its own change repeatedly never trips") {
        struct dlx_rig rig;
        char t1[64], t2[64], t3[64], t4[64];
        static char text[262144];
        dlx_isolate("red_same_lane");
        dlrb_t_env();
        ASSERT(dlx_rig_make(&rig, "red_same_lane_rig"));
        ASSERT(dlrb_t_branch(&rig, "s1", "f1.txt", t1));
        ASSERT(dlrb_t_branch(&rig, "s2", "f2.txt", t2));
        ASSERT(dlrb_t_branch(&rig, "s3", "f1.txt", t3));
        ASSERT(dlrb_t_branch(&rig, "s4", "f4.txt", t4));
        ASSERT(dlrb_t_submit(&rig, t1, "lane-a", 1));
        ASSERT(dlrb_t_submit(&rig, t2, "lane-a", 2));
        ASSERT(dlrb_t_submit(&rig, t3, "lane-b", 3)); /* overlaps row 1 */
        ASSERT(dlrb_t_submit(&rig, t4, "lane-a", 4));
        for (int i = 0; i < 4; i++)
            ASSERT(dlrb_t_prove("failed", -1));
        ASSERT(dlrb_t_status(NULL, 0, 0));
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"failed\""), (size_t)4);
        ASSERT_EQ(dlrb_t_count(text, "red_main"), (size_t)0);
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

static int dlrb_t_no_bisect_then_clear(void)
{
    int failures = 0;
    TEST("land red main: no halving of a train while red; the fix lands, clears and requeues") {
        struct dlx_rig rig;
        char t4[64], t5[64], t6[64], own[64], fix[64], states[512];
        static char text[262144];
        ASSERT(dlrb_t_trip(&rig, "red_clear"));
        /* A three-row train failing the red group is not halved (a split
         * would start a two-row train next): every member proves alone and
         * each is parked on its own failure. */
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlrb_t_branch(&rig, "r4", "f4.txt", t4));
        ASSERT(dlrb_t_branch(&rig, "r5", "f5.txt", t5));
        ASSERT(dlrb_t_branch(&rig, "r6", "f6.txt", t6));
        ASSERT(dlrb_t_submit(&rig, t4, "lane-four", 4));
        ASSERT(dlrb_t_submit(&rig, t5, "lane-five", 5));
        ASSERT(dlrb_t_submit(&rig, t6, "lane-six", 6));
        ASSERT(dlrb_t_step_members("started", 2));
        ASSERT(dlrb_t_step("rebased", -1));
        for (int i = 0; i < 3; i++) {
            ASSERT(dlrb_t_step_members("started", 0));
            ASSERT(dlrb_t_step("parked", 1));
        }
        ASSERT(dlrb_t_status(DLRB_T_GROUP, 1, 4));
        /* A row touching the group's own test is a likely fix: never parked. */
        ASSERT(dlrb_t_branch(&rig, "own", "tests/harness/src/" DLRB_T_GROUP ".c",
                             own));
        ASSERT(dlrb_t_submit(&rig, own, "lane-own", 7));
        ASSERT(dlrb_t_prove("failed", -1));
        /* The fix passes the group: it lands and every parked row requeues,
         * rebases onto the fixed main and lands under its own fresh proof. */
        ASSERT(dlrb_t_branch(&rig, "fix", "red-fix", fix));
        ASSERT(dlrb_t_submit(&rig, fix, "lane-fix", 8));
        ASSERT(dlrb_t_step("started", -1));
        ASSERT(dlrb_t_drain(32, states, sizeof(states)));
        ASSERT(dlrb_t_status(NULL, 0, 0));
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"landed\""), (size_t)5);
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"failed\""), (size_t)3);
        ASSERT(dlx_has(text, "\"red_main\":\"cleared:" DLRB_T_GROUP ":"));
        ASSERT_EQ(dlrb_t_count(text, "\"red_main\":\"parked:"), (size_t)0);
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

static int dlrb_t_age_out(void)
{
    int failures = 0;
    TEST("land red main: aged-out evidence releases parked rows for fresh proofs") {
        struct dlx_rig rig;
        char now[32];
        static char text[262144];
        ASSERT(dlrb_t_trip(&rig, "red_age"));
        /* Past the age bound: released, reproven, still red, parked again
         * (it remembers its episode) instead of failing. */
        (void)snprintf(now, sizeof(now), "%lld", (long long)time(NULL) + 7300);
        setenv("ZCL_LAND_RED_MAIN_NOW", now, 1);
        ASSERT(dlrb_t_prove("parked", 1));
        ASSERT(dlrb_t_status(DLRB_T_GROUP, 1, 1));
        /* Past the episode maximum: released and forgotten, so the stale
         * episode parks nothing more and the row fails on its own proof. */
        (void)snprintf(now, sizeof(now), "%lld", (long long)time(NULL) + 43300);
        setenv("ZCL_LAND_RED_MAIN_NOW", now, 1);
        ASSERT(dlrb_t_prove("failed", -1));
        ASSERT(dlrb_t_status(NULL, 0, 0));
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"failed\""), (size_t)3);
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

static int dlrb_t_off(void)
{
    int failures = 0;
    TEST("land red main: ZCL_LAND_RED_MAIN=0 fails the third row as before") {
        struct dlx_rig rig;
        char t1[64], t2[64], t3[64];
        dlx_isolate("red_off");
        dlrb_t_env();
        setenv("ZCL_LAND_RED_MAIN", "0", 1);
        ASSERT(dlx_rig_make(&rig, "red_off_rig"));
        ASSERT(dlrb_t_branch(&rig, "o1", "f1.txt", t1));
        ASSERT(dlrb_t_branch(&rig, "o2", "f2.txt", t2));
        ASSERT(dlrb_t_branch(&rig, "o3", "f3.txt", t3));
        ASSERT(dlrb_t_submit(&rig, t1, "lane-one", 1));
        ASSERT(dlrb_t_submit(&rig, t2, "lane-two", 2));
        ASSERT(dlrb_t_submit(&rig, t3, "lane-three", 3));
        for (int i = 0; i < 3; i++)
            ASSERT(dlrb_t_prove("failed", -1));
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

/* A retained attempt in the real layouts: the runner's banner and failed
 * list, under <root>/.cache/zcl-dev-proof/attempts/<attempt>/logs/. With the
 * stub out of the decision, this is the path production takes. */
static int dlrb_t_attempt_logs(void)
{
    int failures = 0;
    TEST("land red main: retained attempt logs decide the only failed group and the clear") {
        char dir[512], logs[900], path[1100];
        const char *l = "1111111111111111111111111111111111111111";
        const char *b = "2222222222222222222222222222222222222222";
        struct dl_row row;
        test_make_tmpdir(dir, sizeof(dir), "dev_land", "red_attempt_logs");
        (void)snprintf(logs, sizeof(logs),
                       "%s/.cache/zcl-dev-proof/attempts/%.40s-%.40s.7/logs",
                       dir, l, b);
        ASSERT(dlx_mkdir_p(logs));
        (void)snprintf(path, sizeof(path), "%s/%.40s-%.40s.test.log", logs, l, b);
        ASSERT(dlx_write(path,
            "\n==================== test_other (PASS, 1.0s) ====================\n"
            "\n==================== " DLRB_T_GROUP " (FAIL, 2.0s) ====================\n"
            "SOME TESTS FAILED - 1/9 groups failed\n"
            "Failed groups:\n"
            "  - " DLRB_T_GROUP ": exit code=1 log=./test-tmp/a.log\n"
            "      repro: make t-fast ONLY=" DLRB_T_GROUP "\n"));
        memset(&row, 0, sizeof(row));
        (void)snprintf(row.local, sizeof(row.local), "%s", l);
        (void)snprintf(row.base, sizeof(row.base), "%s", b);
        (void)snprintf(row.failed_proof.root, sizeof(row.failed_proof.root),
                       "%s", dir);
        (void)snprintf(row.failed_proof.attempt, sizeof(row.failed_proof.attempt),
                       "%.40s-%.40s.7", l, b);
        ASSERT(dlrb_failed_only(&row, DLRB_T_GROUP));
        ASSERT(!dlrb_failed_only(&row, "test_other"));
        /* The failed group did not pass; the other one did. */
        ASSERT(!dlrb_attempts_show(dir, l, b, DLRB_T_GROUP));
        ASSERT(dlrb_attempts_show(dir, l, b, "test_other"));
        ASSERT(!dlrb_attempts_show(dir, b, l, "test_other"));
        /* The pair's passing attempt: the red group passes. */
        ASSERT(dlx_write(path,
            "\n==================== " DLRB_T_GROUP " (PASS, 2.0s) ====================\n"
            "ALL TESTS PASSED\n"));
        ASSERT(dlrb_attempts_show(dir, l, b, DLRB_T_GROUP));
        ASSERT(!dlrb_failed_only(&row, DLRB_T_GROUP));
        /* A reaped attempt proves nothing. */
        (void)snprintf(path, sizeof(path), "%s/empty", dir);
        ASSERT(!dlrb_attempts_show(path, l, b, DLRB_T_GROUP));
        row.failed_proof.attempt[0] = '\0';
        ASSERT(!dlrb_failed_only(&row, DLRB_T_GROUP));
        PASS();
    }
_test_next:;
    return failures;
}

static int dlrb_t_cleared_list(void)
{
    int failures = 0;
    TEST("land red main: one cleared marker names several groups; a parked one never") {
        struct dlrb_mark m;
        char out[160];
        ASSERT(dlrb_mark_parse("cleared:test_a+test_b:3:100:200", &m));
        ASSERT(m.cleared && strcmp(m.group, "test_a+test_b") == 0);
        ASSERT(dlrb_mark_format(&m, out, sizeof(out)));
        ASSERT(strcmp(out, "cleared:test_a+test_b:3:100:200") == 0);
        ASSERT(!dlrb_mark_parse("parked:test_a+test_b:3:100:200", &m));
        m.cleared = false;
        ASSERT(!dlrb_mark_format(&m, out, sizeof(out)));
        PASS();
    }
_test_next:;
    return failures;
}

/* Rows one and two fail the red group, then the fix lands with nothing
 * parked, then a lane breaks the group by itself: main is green, so that
 * row fails on its own proof instead of being parked. */
static int dlrb_t_fix_before_trip(void)
{
    int failures = 0;
    TEST("land red main: a fix landing clears the evidence even with no row parked") {
        struct dlx_rig rig;
        char t1[64], t2[64], fix[64], brk[64], states[512];
        static char text[262144];
        dlx_isolate("red_fix_first");
        dlrb_t_env();
        ASSERT(dlx_rig_make(&rig, "red_fix_first_rig"));
        ASSERT(dlrb_t_branch(&rig, "p1", "f1.txt", t1));
        ASSERT(dlrb_t_branch(&rig, "p2", "f2.txt", t2));
        ASSERT(dlrb_t_branch(&rig, "pf", "red-fix", fix));
        ASSERT(dlrb_t_submit(&rig, t1, "lane-one", 1));
        ASSERT(dlrb_t_submit(&rig, t2, "lane-two", 2));
        ASSERT(dlrb_t_submit(&rig, fix, "lane-fix", 3));
        ASSERT(dlrb_t_prove("failed", -1) && dlrb_t_prove("failed", -1));
        ASSERT(dlrb_t_step("started", -1));
        ASSERT(dlrb_t_drain(32, states, sizeof(states)));
        ASSERT(dlrb_t_branch(&rig, "pb", "red-break", brk));
        ASSERT(dlrb_t_submit(&rig, brk, "lane-break", 4));
        ASSERT(dlrb_t_prove("failed", -1));
        ASSERT(dlrb_t_status(NULL, 0, 0));
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"failed\""), (size_t)3);
        ASSERT_EQ(dlrb_t_count(text, "\"red_main\":\"parked:"), (size_t)0);
        ASSERT(dlx_has(text, "\"red_main\":\"cleared:" DLRB_T_GROUP ":"));
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

/* A fix that skips the group runs no proof of it: nothing is cleared and
 * the parked row waits for the age-out. */
static int dlrb_t_skip_clears_nothing(void)
{
    int failures = 0;
    TEST("land red main: a landing that never ran the group does not clear it") {
        struct dlx_rig rig;
        char skip[64], states[512];
        static char text[262144];
        ASSERT(dlrb_t_trip(&rig, "red_skip"));
        ASSERT(dlrb_t_branch(&rig, "sk", "red-skip", skip));
        ASSERT(dlrb_t_submit(&rig, skip, "lane-skip", 4));
        ASSERT(dlrb_t_step("started", -1));
        ASSERT(dlrb_t_drain(32, states, sizeof(states)));
        ASSERT(dlrb_t_status(DLRB_T_GROUP, 1, 1));
        ASSERT(dlrb_t_ledger(text, sizeof(text)));
        ASSERT_EQ(dlrb_t_count(text, "\"state\":\"landed\""), (size_t)1);
        ASSERT_EQ(dlrb_t_count(text, "\"red_main\":\"cleared:"), (size_t)0);
        PASS();
    }
_test_next:;
    dlrb_t_unenv();
    return failures;
}

/* More than 8 distinct recent groups are all kept; past the real bound the
 * set says so, and a cleared list that cannot name a group refuses it. */
static int dlrb_t_many_groups(void)
{
    int failures = 0;
    TEST("land red main: 9 and more failing groups are never dropped silently") {
        static struct dlrb_groups gs;
        char name[DLRB_GROUP_MAX], list[DLRB_GROUP_MAX] = "";
        size_t added = 0;
        for (unsigned i = 0; i < 9; i++) {
            (void)snprintf(name, sizeof(name), "test_group_%u", i);
            dlrb_groups_add(&gs, name);
            dlrb_groups_add(&gs, name);
        }
        ASSERT_EQ(gs.n, (size_t)9);
        ASSERT(!gs.overflow);
        ASSERT(strcmp(gs.g[8], "test_group_8") == 0);
        for (unsigned i = 9; i < DLRB_RECENT_MAX + 3; i++) {
            (void)snprintf(name, sizeof(name), "test_group_%u", i);
            dlrb_groups_add(&gs, name);
        }
        ASSERT_EQ(gs.n, (size_t)DLRB_RECENT_MAX);
        ASSERT(gs.overflow);
        for (unsigned i = 0; i < 6; i++) {
            (void)snprintf(name, sizeof(name), "long_group_name_number_%u", i);
            if (dlrb_list_add(list, sizeof(list), name))
                added++;
        }
        ASSERT_EQ(added, (size_t)2);
        ASSERT(strcmp(list, "long_group_name_number_0+long_group_name_number_1") == 0);
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_red_breaker_cases(void)
{
    return dlrb_t_trip_pure() + dlrb_t_no_trip_pure() + dlrb_t_age_pure() +
           dlrb_t_only_group() + dlrb_t_trip_and_park() + dlrb_t_same_lane() +
           dlrb_t_no_bisect_then_clear() + dlrb_t_age_out() + dlrb_t_off() +
           dlrb_t_attempt_logs() + dlrb_t_cleared_list() +
           dlrb_t_fix_before_trip() + dlrb_t_skip_clears_nothing() +
           dlrb_t_many_groups();
}

#else

int test_dev_land_red_breaker_cases(void)
{
    return 0;
}

#endif
