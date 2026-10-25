/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.loop.job.start / dev.loop.job.wait / dev.loop.job.exec
 * (tools/command/native_dev_job*.c) against an isolated state root and a
 * throwaway git repository. The fixture jobs are `make` targets (argv[0]
 * make is on the allowlist) that print and exit with a chosen status. The
 * detached child is replaced by a thread running the same exec core with
 * the test hooks; production admission (devbuild / host build) is not run. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_job.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_dev_job(void);
int test_dev_job(void)
{
    printf("test_dev_job: skipped on Windows\n");
    return 0;
}
#else
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DJ_MAX_THREADS 16

static char g_repo[1024];
static pthread_t g_threads[DJ_MAX_THREADS];
static int g_nthreads;
static bool g_no_child; /* launch succeeds but nothing runs: a lost job */

static void *dj_thread_main(void *arg)
{
    char *id = arg;
    (void)zcl_dev_job_exec_run(id);
    free(id);
    return NULL;
}

static bool dj_launch(const char *id)
{
    char *copy;
    if (g_no_child)
        return true;
    copy = strdup(id);
    if (!copy || g_nthreads >= DJ_MAX_THREADS)
        abort();
    if (pthread_create(&g_threads[g_nthreads], NULL, dj_thread_main, copy) != 0)
        abort();
    g_nthreads++;
    return true;
}

static void dj_join_all(void)
{
    for (int i = 0; i < g_nthreads; i++)
        (void)pthread_join(g_threads[i], NULL);
    g_nthreads = 0;
}

struct dj_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    int64_t elapsed_ms;
};

static void dj_begin(struct dj_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.dev_job.v1");
}

static void dj_end(struct dj_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Push argv: [argv0] or, for make, [make -f fx.mk <target>]. */
static void dj_push_argv(struct dj_call *c, const char *argv0,
                         const char *target)
{
    struct json_value arr, s;
    const char *items[4] = {argv0, "-f", "fx.mk", target};
    int count = strcmp(argv0, "make") == 0 ? 4 : 1;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        json_init(&s);
        json_set_str(&s, items[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(&c->input, "argv", &arr);
    json_free(&arr);
}

static void dj_start(struct dj_call *c, const char *cwd, const char *argv0,
                     const char *target, bool dedupe)
{
    int64_t t0;
    dj_begin(c);
    (void)json_push_kv_str(&c->input, "cwd", cwd);
    (void)json_push_kv_bool(&c->input, "dedupe", dedupe);
    dj_push_argv(c, argv0, target);
    t0 = platform_time_monotonic_ms();
    zcl_native_handle_dev_job_start(&c->request, &c->reply);
    c->elapsed_ms = platform_time_monotonic_ms() - t0;
}

static void dj_wait(struct dj_call *c, const char *id, const char *log,
                    int64_t timeout_s, int64_t tail_lines)
{
    int64_t t0;
    dj_begin(c);
    if (id)
        (void)json_push_kv_str(&c->input, "job_id", id);
    if (log)
        (void)json_push_kv_str(&c->input, "log", log);
    if (timeout_s > 0)
        (void)json_push_kv_int(&c->input, "timeout_s", timeout_s);
    if (tail_lines > 0)
        (void)json_push_kv_int(&c->input, "tail_lines", tail_lines);
    t0 = platform_time_monotonic_ms();
    zcl_native_handle_dev_job_wait(&c->request, &c->reply);
    c->elapsed_ms = platform_time_monotonic_ms() - t0;
}

static bool dj_ok(const struct dj_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dj_str(const struct dj_call *c, const char *key)
{
    const char *s = json_get_str(json_get(&c->reply.data, key));
    return s ? s : "";
}

static int64_t dj_int(const struct dj_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool dj_array_has(const struct dj_call *c, const char *key,
                         const char *needle)
{
    const struct json_value *a = json_get(&c->reply.data, key);
    for (size_t i = 0; a && i < json_size(a); i++) {
        const char *s = json_get_str(json_at(a, i));
        if (s && strstr(s, needle))
            return true;
    }
    return false;
}

static size_t dj_array_size(const struct dj_call *c, const char *key)
{
    const struct json_value *a = json_get(&c->reply.data, key);
    return a ? json_size(a) : 0;
}

static bool dj_array_lines_capped(const struct dj_call *c, const char *key)
{
    const struct json_value *a = json_get(&c->reply.data, key);
    for (size_t i = 0; a && i < json_size(a); i++) {
        const char *s = json_get_str(json_at(a, i));
        if (!s || strlen(s) > ZCL_DEV_JOB_LINE_MAX)
            return false;
    }
    return true;
}

static bool dj_error_is(const struct dj_call *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

/* ── fixtures ────────────────────────────────────────────────────────────── */

static void dj_git(const char *dir, const char *a, const char *b,
                   const char *c, const char *d, const char *e)
{
    const char *argv[] = {"git", "-c", "user.name=t", "-c",
                          "user.email=t@example.invalid", "-c",
                          "commit.gpgsign=false", a, b, c, d, e, NULL};
    char out[512];
    if (zcl_spawn_capture_in_dir_observed(argv, dir, out, sizeof(out), 20000,
                                          NULL) != 0) {
        fprintf(stderr, "dev_job fixture: git %s failed: %s\n", a, out);
        abort();
    }
}

static void dj_write_makefile(const char *dir)
{
    char path[1100];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/fx.mk", dir);
    f = fopen(path, "w");
    if (!f)
        abort();
    (void)fputs("ok:\n\t@echo hello-out\n\t@echo FAIL-in-name\n"
                "slow:\n\t@sleep 3\n\t@echo slow-done\n"
                "bad:\n\t@echo error: boom\n\t@exit 7 # make reports its own status 2\n"
                "big:\n\t@i=0; while [ $$i -lt 200 ]; do "
                "echo line-$$i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; "
                "i=$$((i+1)); done\n",
                f);
    (void)fclose(f);
}

static char g_saved_state[4096];
static bool g_had_state;

static void dj_isolate(void)
{
    char base[512], state[1024];
    const char *old = getenv("XDG_STATE_HOME");
    g_had_state = old != NULL;
    if (old)
        (void)snprintf(g_saved_state, sizeof(g_saved_state), "%s", old);
    test_make_tmpdir(base, sizeof(base), "dev_job", "rig");
    (void)snprintf(state, sizeof(state), "%s/state", base);
    (void)snprintf(g_repo, sizeof(g_repo), "%s/repo", base);
    if (mkdir(state, 0700) != 0 || mkdir(g_repo, 0700) != 0 ||
        setenv("XDG_STATE_HOME", state, 1) != 0) {
        fprintf(stderr, "dev_job fixture: cannot isolate\n");
        abort();
    }
    dj_git(g_repo, "init", "-q", NULL, NULL, NULL);
    dj_git(g_repo, "commit", "-q", "--allow-empty", "-m", "fixture");
    dj_write_makefile(g_repo);
}

static void dj_restore(void)
{
    if (g_had_state)
        (void)setenv("XDG_STATE_HOME", g_saved_state, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

/* A pid that is certainly dead: a forked child that exited and was reaped. */
static long dj_dead_pid(void)
{
    pid_t p = fork();
    if (p == 0)
        _exit(0);
    if (p < 0)
        abort();
    (void)waitpid(p, NULL, 0);
    return (long)p;
}

static void dj_write_pid(const char *id, long pid)
{
    char dir[4096], path[4200];
    FILE *f;
    if (!zcl_dev_job_dir(id, dir, sizeof(dir)))
        abort();
    (void)snprintf(path, sizeof(path), "%s/pid", dir);
    f = fopen(path, "w");
    if (!f)
        abort();
    (void)fprintf(f, "%ld\n", pid);
    (void)fclose(f);
}

int test_dev_job(void);
int test_dev_job(void)
{
    int failures = 0;
    struct dj_call c, w;
    char id[128], plain[600];
    static struct zcl_dev_job_hooks hooks = {
        .launch = dj_launch, .runner_direct = true};

    dj_isolate();
    hooks.primary_checkout = g_repo;
    zcl_dev_job_set_hooks(&hooks);

    TEST("dev.job: argv[0] outside the allowlist is refused") {
        dj_start(&c, g_repo, "sh", "ok", true);
        ASSERT(dj_error_is(&c, "ARGV_NOT_ALLOWED"));
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: a cwd that is not a registered worktree is refused") {
        test_make_tmpdir(plain, sizeof(plain), "dev_job", "plain");
        dj_start(&c, plain, "make", "ok", true);
        ASSERT(dj_error_is(&c, "CWD_NOT_WORKTREE"));
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: a scratch git repo that lists itself is refused as cwd") {
        char scratch[1024];
        test_make_tmpdir(scratch, sizeof(scratch), "dev_job", "scratch");
        dj_git(scratch, "init", "-q", NULL, NULL, NULL);
        dj_git(scratch, "commit", "-q", "--allow-empty", "-m", "scratch");
        dj_write_makefile(scratch);
        dj_start(&c, scratch, "make", "ok", true);
        ASSERT(dj_error_is(&c, "CWD_NOT_WORKTREE"));
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: start returns in under 1 s; wait 1 s reports running") {
        dj_start(&c, g_repo, "make", "slow", true);
        ASSERT(dj_ok(&c));
        ASSERT(c.elapsed_ms < 1000);
        ASSERT_STR_EQ(dj_str(&c, "state"), "started");
        (void)snprintf(id, sizeof(id), "%s", dj_str(&c, "job_id"));
        ASSERT(id[0] != '\0');
        dj_wait(&w, id, NULL, 1, 0);
        ASSERT(dj_ok(&w));
        ASSERT_STR_EQ(dj_str(&w, "state"), "running");
        ASSERT(w.elapsed_ms < 2500);
        dj_end(&w);
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: a duplicate start attaches to the running job") {
        dj_start(&c, g_repo, "make", "slow", true);
        ASSERT(dj_ok(&c));
        ASSERT_STR_EQ(dj_str(&c, "state"), "attached");
        ASSERT_STR_EQ(dj_str(&c, "job_id"), id);
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: wait after exit returns the exact rc and tail") {
        dj_wait(&w, id, NULL, 30, 0);
        ASSERT(dj_ok(&w));
        ASSERT_STR_EQ(dj_str(&w, "state"), "passed");
        ASSERT_EQ(dj_int(&w, "rc"), (int64_t)0);
        ASSERT(dj_array_has(&w, "tail", "slow-done"));
        dj_end(&w);
        PASS();
    }

    TEST("dev.job: timeout_s=9999 is clamped to 230 and reported") {
        dj_wait(&w, id, NULL, 9999, 0);
        ASSERT(dj_ok(&w));
        ASSERT_EQ(dj_int(&w, "timeout_s"), (int64_t)230);
        ASSERT(json_get_bool(json_get(&w.reply.data, "timeout_clamped")));
        dj_end(&w);
        PASS();
    }

    TEST("dev.job: a failing job reports failed, its rc and its error lines") {
        dj_start(&c, g_repo, "make", "bad", true);
        ASSERT(dj_ok(&c));
        (void)snprintf(id, sizeof(id), "%s", dj_str(&c, "job_id"));
        dj_wait(&w, id, NULL, 30, 0);
        ASSERT_STR_EQ(dj_str(&w, "state"), "failed");
        ASSERT_EQ(dj_int(&w, "rc"), (int64_t)2);
        ASSERT(dj_array_has(&w, "fail_lines", "error: boom"));
        dj_end(&w);
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: the tail never exceeds its line and byte caps") {
        dj_start(&c, g_repo, "make", "big", true);
        ASSERT(dj_ok(&c));
        (void)snprintf(id, sizeof(id), "%s", dj_str(&c, "job_id"));
        dj_wait(&w, id, NULL, 30, 9999);
        ASSERT_STR_EQ(dj_str(&w, "state"), "passed");
        ASSERT(dj_array_size(&w, "tail") <= ZCL_DEV_JOB_TAIL_MAX);
        ASSERT(dj_array_size(&w, "tail") >= 1);
        ASSERT(dj_array_lines_capped(&w, "tail"));
        ASSERT(dj_array_has(&w, "tail", "line-199-"));
        dj_end(&w);
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: a child that vanished with no rc line reports lost") {
        g_no_child = true;
        dj_start(&c, g_repo, "make", "ok", false);
        g_no_child = false;
        ASSERT(dj_ok(&c));
        (void)snprintf(id, sizeof(id), "%s", dj_str(&c, "job_id"));
        dj_write_pid(id, dj_dead_pid());
        dj_wait(&w, id, NULL, 5, 0);
        ASSERT_STR_EQ(dj_str(&w, "state"), "lost");
        dj_end(&w);
        dj_end(&c);
        PASS();
    }

    TEST("dev.job: wait follows an external log ending in an rc= line") {
        char log[1100], dir[1100];
        FILE *f;
        (void)snprintf(dir, sizeof(dir), "%s/build", g_repo);
        (void)mkdir(dir, 0700);
        (void)snprintf(dir, sizeof(dir), "%s/build/scratch", g_repo);
        (void)mkdir(dir, 0700);
        (void)snprintf(log, sizeof(log), "%s/ext.log", dir);
        f = fopen(log, "w");
        ASSERT(f != NULL);
        (void)fputs("gate output\nFAIL one\nrc=3\n", f);
        (void)fclose(f);
        dj_wait(&w, NULL, log, 5, 0);
        if (!dj_ok(&w))
            fprintf(stderr, "dev_job: external wait refused: %s: %s\n",
                    w.reply.error.code, w.reply.error.message);
        ASSERT_STR_EQ(dj_str(&w, "state"), "failed");
        ASSERT_EQ(dj_int(&w, "rc"), (int64_t)3);
        ASSERT(dj_array_has(&w, "fail_lines", "FAIL one"));
        dj_end(&w);
        f = fopen(log, "w");
        ASSERT(f != NULL);
        (void)fputs("still going\n", f);
        (void)fclose(f);
        dj_wait(&w, NULL, log, 1, 0);
        ASSERT_STR_EQ(dj_str(&w, "state"), "running");
        dj_end(&w);
        PASS();
    }

    TEST("dev.job: only a complete terminal decimal rc marker completes a log") {
        static const struct { const char *text; bool valid; int rc; } cases[] = {
            {"rc=0\n", true, 0}, {"output\nrc=3\n", true, 3},
            {"rc=0007\r\n", true, 7}, {"rc=\n", false, 0},
            {"rc=garbage\n", false, 0}, {"rc=0junk\n", false, 0},
            {"rc=999999999999999999999999999999\n", false, 0},
            {"rc=-1\n", true, -1}, {"rc=+0\n", true, 0},
            {"rc=-\n", false, 0}, {"rc=+\n", false, 0},
            {"rc= 0\n", false, 0}, {"rc=0", false, 0},
            {"rc=0\ncontinuing output\n", false, 0},
            {"rc=0\n\n", false, 0}, {"prefixrc=0\n", false, 0}
        };
        char log[1100];
        (void)snprintf(log, sizeof(log), "%s/build/scratch/markers.log", g_repo);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            FILE *f = fopen(log, "wb");
            int rc = -17;
            ASSERT(f != NULL);
            ASSERT(fputs(cases[i].text, f) >= 0);
            ASSERT_EQ(fclose(f), 0);
            ASSERT_EQ(zcl_dev_job_log_rc(log, &rc), cases[i].valid);
            ASSERT_EQ(rc, cases[i].valid ? cases[i].rc : -17);
        }
        FILE *f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT(fprintf(f, "rc=%d\n", INT_MAX) > 0);
        ASSERT_EQ(fclose(f), 0);
        int rc = -17;
        ASSERT(zcl_dev_job_log_rc(log, &rc));
        ASSERT_EQ(rc, INT_MAX);
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT(fprintf(f, "rc=%d\n", INT_MIN) > 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(zcl_dev_job_log_rc(log, &rc));
        ASSERT_EQ(rc, INT_MIN);
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT(fprintf(f, "rc=%llu\n", (unsigned long long)INT_MAX + 1ULL) > 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!zcl_dev_job_log_rc(log, &rc));
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT(fprintf(f, "rc=-%llu\n", (unsigned long long)(-(INT_MIN + 1)) + 2ULL) > 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!zcl_dev_job_log_rc(log, &rc));
        static const char binary[] = "rc=0\n\0hidden\nrc=0\n";
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT_EQ(fwrite(binary, 1, sizeof(binary) - 1, f), sizeof(binary) - 1);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!zcl_dev_job_log_rc(log, &rc));
        ASSERT(zcl_dev_job_read_tail(g_repo, 32, NULL) == NULL);
        /* The bounded tail must not invent a line boundary inside output. */
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        char padding[4096];
        memset(padding, 'x', sizeof(padding));
        for (int i = 0; i < 16; i++)
            ASSERT_EQ(fwrite(padding, 1, sizeof(padding), f), sizeof(padding));
        ASSERT(fputs("rc=0\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(!zcl_dev_job_log_rc(log, &rc));
        f = fopen(log, "ab");
        ASSERT(f != NULL);
        ASSERT(fputs("rc=0\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(zcl_dev_job_log_rc(log, &rc));
        ASSERT_EQ(rc, 0);
        f = fopen(log, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("rc=garbage\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        dj_wait(&w, NULL, log, 1, 0);
        ASSERT_STR_EQ(dj_str(&w, "state"), "running");
        dj_end(&w);
        PASS();
    }

    TEST("dev.job: wait refuses an external log outside the allowed roots") {
        char log[1100];
        FILE *f;
        (void)snprintf(log, sizeof(log), "%s/../outside.log", g_repo);
        f = fopen(log, "w");
        ASSERT(f != NULL);
        (void)fputs("rc=0\n", f);
        (void)fclose(f);
        dj_wait(&w, NULL, log, 5, 0);
        ASSERT(dj_error_is(&w, "LOG_NOT_ALLOWED"));
        dj_end(&w);
        PASS();
    }

_test_next:;
    dj_join_all();
    zcl_dev_job_set_hooks(NULL);
    dj_restore();
    return failures;
}
#endif
