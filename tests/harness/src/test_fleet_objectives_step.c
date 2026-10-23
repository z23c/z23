/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.objectives.step
 * (tools/command/native_fleet_objectives_step.c).
 *
 * Fixtures only: XDG_STATE_HOME points at a tmpdir that holds the land
 * queue, outcomes and the objectives snapshots, and the brief reads a
 * fixture repo, baseline and status brief, so no case reads the live land
 * state, a datadir or a node.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "engine/engine_prompt.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FST_NOWHERE "/nonexistent/z23-fst"
#define FST_OBJ "functions_over_complexity_cap"

struct fst_world {
    char root[512];
    char land[600];
    char brief[600];
    char baseline[600];
    char repo[600];
    char lintc[600];
    char snapshot[600];
    char saved_xdg[600];
    bool had_xdg;
};

static bool fst_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len = strlen(text);
    bool ok;
    if (!f)
        return false;
    ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool fst_mkdirs(const char *path)
{
    char tmp[700];
    (void)snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *c = tmp + 1; *c; c++) {
        if (*c != '/')
            continue;
        *c = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        *c = '/';
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

/* Three over-cap pin rows in three small repo files; rss_mb 100 is met, so
 * the top unmet objective is the complexity card (runner_ok), and 2200
 * makes the node row (product, not runner_ok) the top one. */
static bool fst_fixture(struct fst_world *w, int rss_mb)
{
    char text[200], file[700];
    (void)snprintf(w->brief, sizeof(w->brief), "%s/brief.json", w->root);
    (void)snprintf(w->baseline, sizeof(w->baseline), "%s/baseline.txt",
                   w->root);
    (void)snprintf(w->repo, sizeof(w->repo), "%s/repo", w->root);
    (void)snprintf(w->lintc, sizeof(w->lintc), "%s/lintc", w->root);
    (void)snprintf(w->snapshot, sizeof(w->snapshot), "%s/objectives.jsonl",
                   w->land);
    (void)snprintf(text, sizeof(text),
                   "{\"hstar\":1000,\"gap\":0,\"rss_mb\":%d,\"serving\":true}",
                   rss_mb);
    if (!fst_mkdirs(w->lintc) || !fst_mkdirs(w->repo) ||
        !fst_write(w->brief, text) ||
        !fst_write(w->baseline,
                   "apps/x.c:f:16\napps/y.c:g:17\napps/z.c:h:18\n"))
        return false;
    (void)snprintf(file, sizeof(file), "%s/apps", w->repo);
    if (!fst_mkdirs(file))
        return false;
    for (const char *n = "xyz"; *n; n++) {
        (void)snprintf(file, sizeof(file), "%s/apps/%c.c", w->repo, *n);
        if (!fst_write(file, "x\nx\nx\n"))
            return false;
    }
    return true;
}

static void fst_restore(struct fst_world *w)
{
    if (w->had_xdg)
        (void)setenv("XDG_STATE_HOME", w->saved_xdg, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

/* A fresh isolated state home with z23/dev/land and the brief fixture. */
static bool fst_world(struct fst_world *w, const char *tag, int rss_mb)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    char state[600];
    memset(w, 0, sizeof(*w));
    test_make_tmpdir(w->root, sizeof(w->root), "fleet_objectives_step", tag);
    (void)snprintf(state, sizeof(state), "%s/state", w->root);
    (void)snprintf(w->land, sizeof(w->land), "%s/z23/dev/land", state);
    w->had_xdg = xdg != NULL;
    if (xdg)
        (void)snprintf(w->saved_xdg, sizeof(w->saved_xdg), "%s", xdg);
    if (!fst_mkdirs(w->land))
        return false;
    (void)setenv("XDG_STATE_HOME", state, 1);
    return fst_fixture(w, rss_mb);
}

static void fst_file(const struct fst_world *w, const char *name,
                     const char *text)
{
    char path[700];
    (void)snprintf(path, sizeof(path), "%s/%s", w->land, name);
    (void)fst_write(path, text);
}

static void fst_cat(char *dst, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void fst_cat(char *dst, size_t cap, const char *fmt, ...)
{
    size_t used = strlen(dst);
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(dst + used, cap - used, fmt, ap);
    va_end(ap);
}

/* One land row (queue.jsonl or outcomes.jsonl). note may be "". */
static void fst_land_row(char *buf, size_t cap, int seq, const char *note,
                         const char *state)
{
    fst_cat(buf, cap,
            "{\"seq\":%d,\"ts\":\"2026-10-23T00:00:00Z\",\"tip\":\"%040x\","
            "\"note\":\"%s\",\"state\":\"%s\",\"attempt\":1,"
            "\"landed_at\":%d}\n",
            seq, seq, note, state, strcmp(state, "landed") == 0 ? 1 : 0);
}

/* One snapshot row: FST_OBJ at `value` (min objective, target 0). */
static void fst_snap_row(char *buf, size_t cap, int seq, int value)
{
    fst_cat(buf, cap,
            "{\"schema\":\"zcl.objectives_snapshot.v1\",\"ts\":%d,\"seq\":%d,"
            "\"tip\":\"tip%04d\",\"objectives\":[{\"id\":\"" FST_OBJ "\","
            "\"value\":%d,\"target\":0,\"direction\":\"min\",\"met\":false,"
            "\"reason\":\"\"}]}\n",
            1000 + seq, seq, seq, value);
}

struct fst_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static bool fst_run(struct fst_call *c, const struct fst_world *w, bool force)
{
    char why[192];
    json_init(&c->input);
    json_set_object(&c->input);
    (void)json_push_kv_str(&c->input, "snapshot", w->snapshot);
    (void)json_push_kv_str(&c->input, "brief", w->brief);
    (void)json_push_kv_str(&c->input, "lintc_dir", w->lintc);
    (void)json_push_kv_str(&c->input, "baseline", w->baseline);
    (void)json_push_kv_str(&c->input, "outcomes", FST_NOWHERE "/o.jsonl");
    (void)json_push_kv_str(&c->input, "attempts_dir", FST_NOWHERE "/a");
    (void)json_push_kv_str(&c->input, "repo", w->repo);
    if (force)
        (void)json_push_kv_bool(&c->input, "force", true);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.objectives.step", NULL);
    zcl_command_reply_init(&c->reply, "zcl.test.v1");
    if (!c->request.spec ||
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_objectives_step(&c->request, &c->reply);
    return true;
}

static void fst_end(struct fst_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const char *fst_str(const struct fst_call *c, const char *key)
{
    return json_get_str(json_get(&c->reply.data, key));
}

static const char *fst_next_str(const struct fst_call *c, const char *key)
{
    return json_get_str(json_get(json_get(&c->reply.data, "next"), key));
}

static const char *fst_verdict(const struct fst_call *c, size_t i)
{
    return json_get_str(
        json_get(json_at(json_get(&c->reply.data, "verdicts"), i), "verdict"));
}

/* Outcomes: a plain landing (seq 5), loop landings at 20 and 30. Snapshots:
 * 10 -> 5, 20 -> 7 (regressed), 30 -> 9 (regressed) unless improve30. */
static void fst_two_loop_landings(const struct fst_world *w, int value30)
{
    char o[4096] = "", s[4096] = "";
    fst_land_row(o, sizeof(o), 5, "plain work", "landed");
    fst_land_row(o, sizeof(o), 20, "loop:" FST_OBJ ": split one function",
                 "landed");
    fst_land_row(o, sizeof(o), 30, "loop:" FST_OBJ ": split another",
                 "landed");
    fst_snap_row(s, sizeof(s), 10, 5);
    fst_snap_row(s, sizeof(s), 20, 7);
    fst_snap_row(s, sizeof(s), 30, value30);
    fst_file(w, "outcomes.jsonl", o);
    fst_file(w, "queue.jsonl", "");
    fst_file(w, "objectives.jsonl", s);
}

static int fst_case_run(void)
{
    int failures = 0;
    struct fst_world w;
    struct fst_call c;
    TEST("step: no loop row and a runner_ok top objective is action run") {
        char o[1024] = "", s[1024] = "";
        ASSERT(fst_world(&w, "run", 100));
        fst_land_row(o, sizeof(o), 5, "plain work", "landed");
        fst_snap_row(s, sizeof(s), 5, 5);
        fst_file(&w, "outcomes.jsonl", o);
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", s);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        ASSERT(!json_get_bool(json_get(&c.reply.data, "paused")));
        ASSERT_STR_EQ(fst_next_str(&c, "objective"), FST_OBJ);
        ASSERT_STR_EQ(fst_next_str(&c, "note_prefix"),
                      "loop:" FST_OBJ ":");
        ASSERT_STR_EQ(fst_next_str(&c, "lane"),
                      "loop-functions-over-complexity-cap-6");
        ASSERT(json_get_bool(json_get(json_get(&c.reply.data, "next"),
                                      "runner_ok")));
        ASSERT(fst_next_str(&c, "level") != NULL);
        ASSERT(json_get(json_get(&c.reply.data, "next"), "brief") != NULL);
        ASSERT(strstr(fst_str(&c, "screen"), "loop step: run") != NULL);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
_test_next:;
    return failures;
}

static int fst_case_wait(void)
{
    int failures = 0;
    struct fst_world w;
    struct fst_call c;
    TEST("step: a queued loop row is action wait naming its seq") {
        char o[1024] = "", q[1024] = "", s[1024] = "";
        ASSERT(fst_world(&w, "wait", 100));
        fst_land_row(o, sizeof(o), 5, "plain work", "landed");
        fst_land_row(q, sizeof(q), 50, "loop:" FST_OBJ ": in flight",
                     "queued");
        fst_snap_row(s, sizeof(s), 5, 5);
        fst_file(&w, "outcomes.jsonl", o);
        fst_file(&w, "queue.jsonl", q);
        fst_file(&w, "objectives.jsonl", s);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "wait");
        ASSERT_EQ(json_get_int(json_get(json_get(&c.reply.data, "next"),
                                        "seq")), 50);
        ASSERT(strstr(fst_str(&c, "reason"), "seq 50") != NULL);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: a queued non-loop row does not make the loop wait") {
        char q[1024] = "";
        ASSERT(fst_world(&w, "wait_other", 100));
        fst_land_row(q, sizeof(q), 50, "someone else's work", "queued");
        fst_file(&w, "outcomes.jsonl", "");
        fst_file(&w, "queue.jsonl", q);
        fst_file(&w, "objectives.jsonl", "");
        ASSERT(fst_run(&c, &w, false));
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
_test_next:;
    return failures;
}

static int fst_case_paused(void)
{
    int failures = 0;
    struct fst_world w;
    struct fst_call c;
    TEST("step: two regressed loop landings pause the loop") {
        ASSERT(fst_world(&w, "paused", 100));
        fst_two_loop_landings(&w, 9);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "paused");
        ASSERT(json_get_bool(json_get(&c.reply.data, "paused")));
        ASSERT(!json_get_bool(json_get(&c.reply.data, "forced")));
        ASSERT_STR_EQ(fst_verdict(&c, 0), "regressed");
        ASSERT_STR_EQ(fst_verdict(&c, 1), "regressed");
        ASSERT_EQ(json_get_int(json_at(json_get(json_get(&c.reply.data,
                                                         "next"), "seqs"), 0)),
                  30);
        ASSERT_EQ(json_get_int(json_at(json_get(json_get(&c.reply.data,
                                                         "next"), "seqs"), 1)),
                  20);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(json_get(&c.reply.data,
                                                              "next"),
                                                    "objectives"), 0)),
                      FST_OBJ);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: force overrides the pause for one call and says so") {
        ASSERT(fst_world(&w, "force", 100));
        fst_two_loop_landings(&w, 9);
        ASSERT(fst_run(&c, &w, true));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        ASSERT(!json_get_bool(json_get(&c.reply.data, "paused")));
        ASSERT(json_get_bool(json_get(&c.reply.data, "forced")));
        ASSERT(strstr(fst_str(&c, "screen"), "overridden") != NULL);
        ASSERT_STR_EQ(fst_verdict(&c, 0), "regressed");
        fst_end(&c);
        /* Stateless: the next call without force pauses again. */
        ASSERT(fst_run(&c, &w, false));
        ASSERT_STR_EQ(fst_str(&c, "action"), "paused");
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: only the newest landing improved, so one regression does "
         "not pause") {
        ASSERT(fst_world(&w, "one_regress", 100));
        fst_two_loop_landings(&w, 3);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        ASSERT_STR_EQ(fst_verdict(&c, 0), "improved");
        ASSERT_STR_EQ(fst_verdict(&c, 1), "regressed");
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
_test_next:;
    return failures;
}

static int fst_case_none_and_skips(void)
{
    int failures = 0;
    struct fst_world w;
    struct fst_call c;
    TEST("step: a top objective that is not runner_ok falls through to the "
         "top runnable one and lists what it skipped") {
        const struct json_value *sk;
        ASSERT(fst_world(&w, "fall", 2200));
        fst_file(&w, "outcomes.jsonl", "");
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", "");
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        ASSERT_STR_EQ(fst_next_str(&c, "objective"), FST_OBJ);
        sk = json_get(&c.reply.data, "skipped");
        ASSERT_EQ(json_size(sk), 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(sk, 0), "objective")),
                      "node_rss_mb");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(sk, 0), "reason")),
                      "not runner_ok");
        ASSERT(strstr(fst_str(&c, "screen"),
                      "skipped node_rss_mb: not runner_ok") != NULL);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: no runner_ok objective unmet is action none, skipped named") {
        ASSERT(fst_world(&w, "none", 2200));
        ASSERT(fst_write(w.baseline, ""));
        fst_file(&w, "outcomes.jsonl", "");
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", "");
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fst_str(&c, "action"), "none");
        ASSERT(strstr(fst_str(&c, "reason"), "skipped node_rss_mb") != NULL);
        ASSERT_EQ(json_size(json_get(&c.reply.data, "skipped")), 1);
        ASSERT(json_get(&c.reply.data, "dispatch") == NULL);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: run carries a dispatch with a task engine_unit parses and an "
         "argv without --yes-dispatch") {
        const struct json_value *dp, *argv;
        const char *task;
        struct engine_contract ct;
        char why[ENGINE_CONTRACT_REASON_BYTES];
        bool has_task = false, has_nogroup = false;
        ASSERT(fst_world(&w, "dispatch", 100));
        fst_file(&w, "outcomes.jsonl", "");
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", "");
        ASSERT(fst_run(&c, &w, false));
        dp = json_get(&c.reply.data, "dispatch");
        ASSERT(dp != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(dp, "lane")),
                      "loop-functions-over-complexity-cap-1");
        ASSERT_STR_EQ(json_get_str(json_get(dp, "note_prefix")),
                      "loop:" FST_OBJ ":");
        ASSERT_STR_EQ(json_get_str(json_get(dp, "engine")), "claude-haiku");
        ASSERT_STR_EQ(json_get_str(json_get(dp, "group")), "--no-group");
        ASSERT(json_get_str(json_get(dp, "group_reason"))[0] != '\0');
        task = json_get_str(json_get(dp, "task_text"));
        ASSERT_STR_EQ(engine_prompt_kind_from_header(task), "fix-gate");
        ASSERT_EQ(engine_contract_check(task, strlen(task), &ct, why,
                                        sizeof(why)),
                  ENGINE_CONTRACT_LEGACY);
        ASSERT(strstr(task, "Acceptance: z23-dev fleet objectives") != NULL);
        ASSERT(strstr(task, "Target file: apps/") != NULL);
        argv = json_get(dp, "argv");
        ASSERT(json_size(argv) >= 6);
        for (size_t i = 0; i < json_size(argv); i++) {
            const char *a = json_get_str(json_at(argv, i));
            ASSERT(strcmp(a, "--yes-dispatch") != 0);
            has_task = has_task || strcmp(a, "--task") == 0;
            has_nogroup = has_nogroup || strcmp(a, "--no-group") == 0;
        }
        ASSERT(has_task && has_nogroup);
        ASSERT(strstr(fst_str(&c, "screen"), "--yes-dispatch") != NULL);
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: malformed lines in the outcomes and the snapshots are "
         "skipped") {
        char o[4096] = "", s[4096] = "";
        ASSERT(fst_world(&w, "malformed", 100));
        fst_cat(o, sizeof(o), "this is not json\n{\"seq\":\n");
        fst_land_row(o, sizeof(o), 20, "loop:" FST_OBJ ": ok", "landed");
        fst_cat(s, sizeof(s), "garbage\n");
        fst_snap_row(s, sizeof(s), 10, 5);
        fst_cat(s, sizeof(s), "{\"schema\":\"zcl.objectives_snapshot.v1\"}\n");
        fst_snap_row(s, sizeof(s), 20, 7);
        fst_file(&w, "outcomes.jsonl", o);
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", s);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_size(json_get(&c.reply.data, "verdicts")), 1);
        ASSERT_STR_EQ(fst_verdict(&c, 0), "regressed");
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
    TEST("step: a landing with no snapshot row is unmeasured, never "
         "regressed") {
        char o[2048] = "", s[2048] = "";
        ASSERT(fst_world(&w, "nosnap", 100));
        fst_land_row(o, sizeof(o), 20, "loop:" FST_OBJ ": a", "landed");
        fst_land_row(o, sizeof(o), 30, "loop:" FST_OBJ ": b", "landed");
        fst_snap_row(s, sizeof(s), 10, 5);
        fst_file(&w, "outcomes.jsonl", o);
        fst_file(&w, "queue.jsonl", "");
        fst_file(&w, "objectives.jsonl", s);
        ASSERT(fst_run(&c, &w, false));
        ASSERT_STR_EQ(fst_verdict(&c, 0), "unmeasured");
        ASSERT_STR_EQ(fst_verdict(&c, 1), "unmeasured");
        ASSERT_STR_EQ(fst_str(&c, "action"), "run");
        fst_end(&c);
        fst_restore(&w);
        PASS();
    }
_test_next:;
    return failures;
}

int test_fleet_objectives_step(void);
int test_fleet_objectives_step(void)
{
    int failures = 0;
    (void)setenv("ZCL_LAND_OBJECTIVES_DATADIR", FST_NOWHERE "/datadir", 1);
    failures += fst_case_run();
    failures += fst_case_wait();
    failures += fst_case_paused();
    failures += fst_case_none_and_skips();
    (void)unsetenv("ZCL_LAND_OBJECTIVES_DATADIR");
    if (failures == 0)
        printf("test_fleet_objectives_step: all passed\n");
    else
        printf("test_fleet_objectives_step: %d FAILED\n", failures);
    return failures;
}
