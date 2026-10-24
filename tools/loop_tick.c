/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: z23-loop-tick, one hourly tick of the self-improving loop as a
 * typed C23 tool. It is the port of the ops bridge loop-tick.sh, step for step:
 *
 *   lock -> retire landed loop-* lanes and count *.HOLD -> `fleet objectives
 *   step` in the pristine base tree -> lane from origin/main (worktree-prime)
 *   -> z23-engine-unit (the model edits only) -> scope check against
 *   brief.owned -> complexity baseline regen (shrink-only) -> signed commit ->
 *   lint-land -> zgate agent-verify + lint -> read-only Haiku review ->
 *   prep -> `dev land submit` with the `loop:<objective>:` note prefix.
 *
 * A tool, not a node command leaf, for the reasons tools/engine_unit.c gives:
 * it launches programs and the always-running node must not. Every program it
 * starts goes through platform/modules/util zcl_spawn_capture*, which
 * execvp()s an argv directly: no shell, so nothing the step or the model wrote
 * can become a word in a command line. Every program path is an option whose
 * default is the bridge's value, so a test runs a whole tick against a temp
 * git repo with fake programs.
 *
 * Guards, in order: one tick at a time (flock on STATE/lock); at most
 * --max-held held loop lanes; the step's own in-flight and pause rules;
 * engine claude-haiku and lane names loop-* only; every changed path must be
 * owned; the baseline may only shrink; both gates rc=0; a non-author LAND.
 * Every guard failure after the lane exists writes STATE/<lane>.HOLD and
 * exits 0; the lead looks at the HOLD files. Output is one line per event on
 * stdout and in STATE/tick.log.
 *
 * Capture note: a program whose output lands in a log (devbuild, git add and
 * commit, lint, prep, the engine) runs through zcl_spawn_capture_merged_in_dir_
 * observed, so the log holds stderr too (compiler errors). A program whose
 * stdout is parsed (the step, zgate's log path, the review JSON, the submit
 * JSON, git status and rev-parse) stays stdout-only.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LT_GO (-1) /* a stage's "carry on" answer; any value >= 0 is the exit code */
enum {
    LT_PATH = 1024,
    LT_NAME = 160,
    LT_BUF = 4 << 20,
    LT_OWNED_MAX = 32,
    LT_SHOW_MAX = 90000,
    LT_BUILD_TIMEOUT_MS = 6 * 3600 * 1000,
    LT_SHORT_TIMEOUT_MS = 600 * 1000
};

/* X(id, flag, default). "~/" expands to $HOME, "@main/", "@lanes/" and
 * "@state/" to the option of that name. Dependencies precede dependents. */
#define LT_OPTS(X)                                                           \
    X(MAIN, "--main", "~/development/z23/main")                              \
    X(LANES, "--lanes", "~/development/lanes/z23")                           \
    X(STATE, "--state-dir", "~/.local/state/z23-loop")                       \
    X(BASE, "--base", "@lanes/loop-base")                                    \
    X(SCRATCH, "--scratch-dir", "~/.cache/development-scratch/z23/loop")     \
    X(DEV, "--dev", "@main/build/bin/z23-dev")                               \
    X(ENGINE_UNIT, "--engine-unit", "@main/build/bin/z23-engine-unit")       \
    X(ZGATE, "--zgate", "~/.local/lib/z23/tools/zgate")                      \
    X(RETIRE, "--retire-script",                                             \
      "~/development/z23/handoff/handoff-20261022-evening/retire.sh")        \
    X(GIT, "--git", "git")                                                   \
    X(SH, "--sh", "sh")                                                      \
    X(ENVP, "--env", "env")                                                  \
    X(DEVBUILD, "--devbuild", "devbuild")                                    \
    X(CLAUDE, "--claude", "claude")                                          \
    X(LINT_BIN, "--lint-bin", "build/bin/z23-lint")                          \
    X(SIGN, "--sign-flag", "-S")                                             \
    X(ALLOW_UNSIGNED, "--allow-unsigned", "0")                               \
    X(TRAILER, "--trailer",                                                  \
      "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>")            \
    X(MAX_HELD, "--max-held", "2")                                           \
    X(STEP_TIMEOUT, "--step-timeout-s", "300")                               \
    X(ENGINE_TIMEOUT, "--engine-timeout-s", "1800")                          \
    X(REVIEW_TIMEOUT, "--review-timeout-s", "1200")                          \
    X(GATE_WAIT, "--gate-wait-s", "7200")                                    \
    X(POLL, "--poll-ms", "30000")

enum lt_opt {
#define X(id, flag, dflt) LT_O_##id,
    LT_OPTS(X)
#undef X
        LT_O_COUNT
};

static const char *const k_flags[LT_O_COUNT] = {
#define X(id, flag, dflt) flag,
    LT_OPTS(X)
#undef X
};
static const char *const k_defaults[LT_O_COUNT] = {
#define X(id, flag, dflt) dflt,
    LT_OPTS(X)
#undef X
};

struct tick {
    const char *opt[LT_O_COUNT];
    char dflt[LT_O_COUNT][LT_PATH];
    char *buf; /* shared capture buffer, LT_BUF bytes */
    char log_path[LT_PATH];
    /* the step's decision */
    struct json_value root;
    char *raw;
    char lane[LT_NAME], objective[LT_NAME], prefix[LT_NAME], engine[LT_NAME];
    char target[LT_PATH], dir[LT_PATH], unit[LT_PATH];
    char owned[LT_PATH * 2], owned_store[LT_PATH * 2], pins[LT_PATH * 2], sha[96];
    const char *owned_v[LT_OWNED_MAX];
    size_t owned_n;
    long removed;
    char gatenote[160]; /* the land note's gate text, as the gates actually ran */
};

static const char *O(const struct tick *t, enum lt_opt o) { return t->opt[o]; }

static long oint(const struct tick *t, enum lt_opt o)
{
    return strtol(t->opt[o], NULL, 10);
}

static int oms(const struct tick *t, enum lt_opt o)
{
    const long s = oint(t, o);
    return (s > 0 && s < INT_MAX / 1000) ? (int)(s * 1000) : INT_MAX;
}

__attribute__((format(printf, 3, 4))) static bool
fmt(char *out, size_t cap, const char *f, ...)
{
    va_list ap;
    va_start(ap, f);
    const int n = vsnprintf(out, cap, f, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

/* ── files, logging ──────────────────────────────────────────────────── */

static bool write_file(const char *path, const char *data, size_t len,
                       const char *mode)
{
    FILE *f = fopen(path, mode);
    if (!f)
        return false;
    const bool ok = fwrite(data, 1, len, f) == len;
    return (fclose(f) == 0) && ok;
}

static bool mkdirs(const char *path)
{
    char tmp[LT_PATH];
    if (!fmt(tmp, sizeof(tmp), "%s", path))
        return false;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

static bool is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* Whole file into a fresh NUL-terminated heap block; NULL when absent. */
static char *read_file(const char *path, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *b = zcl_malloc(cap + 1, "loop_tick_file");
    if (!b) {
        (void)fclose(f);
        return NULL;
    }
    const size_t n = fread(b, 1, cap, f);
    (void)fclose(f);
    b[n] = '\0';
    return b;
}

static void say(const struct tick *t, const char *f, ...)
{
    char msg[2048], stamp[40];
    va_list ap;
    va_start(ap, f);
    (void)vsnprintf(msg, sizeof(msg), f, ap);
    va_end(ap);
    const time_t now = (time_t)(clock_now_wall_ms() / 1000);
    struct tm tm;
    gmtime_r(&now, &tm);
    (void)strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
    char line[2200];
    const int n = snprintf(line, sizeof(line), "%s %s\n", stamp, msg);
    if (n <= 0)
        return;
    const size_t len = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
    (void)fwrite(line, 1, len, stdout);
    (void)fflush(stdout);
    (void)write_file(t->log_path, line, len, "a");
}

/* The bridge's hold(): record why, say so, and end the tick with exit 0. */
__attribute__((format(printf, 3, 4))) static int
hold(const struct tick *t, const char *lane, const char *f, ...)
{
    char reason[1536], path[LT_PATH];
    va_list ap;
    va_start(ap, f);
    (void)vsnprintf(reason, sizeof(reason), f, ap);
    va_end(ap);
    if (fmt(path, sizeof(path), "%s/%s.HOLD", O(t, LT_O_STATE), lane)) {
        char body[1600];
        const int n = snprintf(body, sizeof(body), "%s\n", reason);
        if (n > 0 && !write_file(path, body, strlen(body), "w"))
            fprintf(stderr, "loop-tick: cannot write %s: %s\n", path,
                    strerror(errno));
    }
    say(t, "HOLD %s: %s", lane, reason);
    return 0;
}

static int skip(const struct tick *t, const char *reason)
{
    say(t, "skip: %s", reason);
    return 0;
}

/* ── running programs (argv only, no shell) ──────────────────────────── */

static int run(struct tick *t, const char *cwd, const char *const argv[],
               int timeout_ms)
{
    bool timed_out = false;
    t->buf[0] = '\0';
    const int rc = zcl_spawn_capture_in_dir_observed(
        argv, cwd, t->buf, LT_BUF, timeout_ms, &timed_out);
    return timed_out ? 124 : rc;
}

/* Stdout and stderr both land in the log; the exit status is the result. */
static int run_logged(struct tick *t, const char *cwd,
                      const char *const argv[], int timeout_ms,
                      const char *log)
{
    bool timed_out = false;
    t->buf[0] = '\0';
    const int rc = zcl_spawn_capture_merged_in_dir_observed(
        argv, cwd, t->buf, LT_BUF, timeout_ms, &timed_out);
    (void)write_file(log, t->buf, strlen(t->buf), "w");
    return timed_out ? 124 : rc;
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

static long count_lines(const char *text, bool (*keep)(const char *line))
{
    long n = 0;
    for (const char *p = text; *p;) {
        const char *nl = strchr(p, '\n');
        if (keep(p))
            n++;
        if (!nl)
            break;
        p = nl + 1;
    }
    return n;
}

static bool line_plus(const char *l) { return l[0] == '+'; }
static bool line_tracked(const char *l)
{
    return l[0] != '\0' && l[0] != '\n' && strncmp(l, "??", 2) != 0;
}

static long git_count(struct tick *t, const char *dir,
                      const char *const argv[], bool (*keep)(const char *))
{
    (void)run(t, dir, argv, LT_SHORT_TIMEOUT_MS);
    return count_lines(t->buf, keep);
}

/* ── step 0: retire landed loop lanes, count held ones ───────────────── */

static void lane_unlanded(struct tick *t, const char *dir, long *unl, long *dirty)
{
    const char *const cherry[] = { O(t, LT_O_GIT), "-C", dir, "cherry",
                                   "origin/main", "HEAD", NULL };
    const char *const status[] = { O(t, LT_O_GIT), "-C", dir, "status",
                                   "--porcelain", NULL };
    *unl = git_count(t, NULL, cherry, line_plus);
    *dirty = git_count(t, NULL, status, line_tracked);
}

static void retire_lane(struct tick *t, const char *name, const char *dir)
{
    char branch[LT_NAME + 8];
    const char *const retire[] = { O(t, LT_O_SH), O(t, LT_O_RETIRE), dir, NULL };
    const int rc = run(t, NULL, retire, LT_SHORT_TIMEOUT_MS);
    (void)write_file(t->log_path, t->buf, strlen(t->buf), "a");
    if (rc == 0 && fmt(branch, sizeof(branch), "lane/%s", name)) {
        const char *const del[] = { O(t, LT_O_GIT), "-C", O(t, LT_O_MAIN),
                                    "branch", "-D", branch, NULL };
        (void)run(t, NULL, del, LT_SHORT_TIMEOUT_MS);
    }
    say(t, "retired landed lane %s", name);
}

/* One loop-* directory: retire it when landed and clean, else count a HOLD. */
static bool lane_entry(struct tick *t, const char *name, long *held)
{
    char dir[LT_PATH], hold_path[LT_PATH];
    if (!fmt(dir, sizeof(dir), "%s/%s", O(t, LT_O_LANES), name) ||
        !fmt(hold_path, sizeof(hold_path), "%s/%s.HOLD", O(t, LT_O_STATE), name))
        return false;
    if (!is_dir(dir))
        return true;
    const char *base = strrchr(O(t, LT_O_BASE), '/');
    if (strcmp(name, base ? base + 1 : O(t, LT_O_BASE)) == 0)
        return true;
    long unl = 0, dirty = 0;
    lane_unlanded(t, dir, &unl, &dirty);
    const bool held_file = exists(hold_path);
    if (unl == 0 && dirty == 0 && !held_file)
        retire_lane(t, name, dir);
    else if (held_file)
        (*held)++;
    return true;
}

static int stage_housekeeping(struct tick *t)
{
    const char *const fetch[] = { O(t, LT_O_GIT), "-C", O(t, LT_O_MAIN),
                                  "fetch", "-q", "origin", "main", NULL };
    if (run(t, NULL, fetch, LT_SHORT_TIMEOUT_MS) != 0)
        return skip(t, "git fetch failed");
    long held = 0;
    DIR *d = opendir(O(t, LT_O_LANES));
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL)
            if (strncmp(e->d_name, "loop-", 5) == 0 &&
                !lane_entry(t, e->d_name, &held))
                break;
        (void)closedir(d);
    }
    if (held >= oint(t, LT_O_MAX_HELD)) {
        say(t, "stop: %ld held loop lanes need the lead (%s/*.HOLD)", held,
            O(t, LT_O_STATE));
        return 0;
    }
    return LT_GO;
}

/* ── step 1: ask the step what to do ─────────────────────────────────── */

static const struct json_value *jpath(const struct json_value *root,
                                      const char *path)
{
    char seg[LT_NAME];
    const struct json_value *v = root;
    while (v && *path) {
        const char *dot = strchr(path, '.');
        const size_t n = dot ? (size_t)(dot - path) : strlen(path);
        if (n == 0 || n >= sizeof(seg))
            return NULL;
        memcpy(seg, path, n);
        seg[n] = '\0';
        v = json_get(v, seg);
        path += n + (dot ? 1 : 0);
    }
    return v;
}

static const char *jstr(const struct json_value *root, const char *path)
{
    const struct json_value *v = jpath(root, path);
    return (v && v->type == JSON_STR && v->val.s) ? v->val.s : "";
}

static void run_free(struct tick *t)
{
    json_free(&t->root);
    free(t->raw);
    t->raw = NULL;
}

static bool step_collect(struct tick *t)
{
    t->raw = zcl_strdup(t->buf, "loop_tick_step");
    if (!t->raw)
        return false;
    json_init(&t->root);
    if (!json_read(&t->root, t->raw, strlen(t->raw)))
        json_set_null(&t->root);
    return true;
}

static int ensure_base(struct tick *t)
{
    if (!is_dir(O(t, LT_O_BASE))) {
        const char *const add[] = { O(t, LT_O_GIT), "-C", O(t, LT_O_MAIN),
                                    "worktree", "add", "-q", "--detach",
                                    O(t, LT_O_BASE), "origin/main", NULL };
        if (run(t, NULL, add, LT_SHORT_TIMEOUT_MS) != 0)
            return skip(t, "cannot create loop-base");
    }
    const char *const co[] = { O(t, LT_O_GIT), "-C", O(t, LT_O_BASE),
                               "checkout", "-q", "--detach", "origin/main",
                               NULL };
    if (run(t, NULL, co, LT_SHORT_TIMEOUT_MS) != 0)
        return skip(t, "loop-base checkout failed");
    return LT_GO;
}

/* The brief's owned array: NUL-separated in owned_store (owned_v points in),
 * space-joined in owned for messages and the review prompt. */
static void collect_owned(struct tick *t)
{
    const struct json_value *arr = jpath(&t->root, "data.next.brief.owned");
    size_t used = 0, joined = 0;
    t->owned[0] = '\0';
    t->owned_n = 0;
    for (size_t i = 0; arr && i < json_size(arr) && t->owned_n < LT_OWNED_MAX; i++) {
        const char *s = json_get_str(json_at(arr, i));
        const size_t n = s ? strlen(s) : 0;
        if (n == 0 || used + n + 1 > sizeof(t->owned_store) ||
            joined + n + 2 > sizeof(t->owned))
            continue;
        memcpy(t->owned_store + used, s, n + 1);
        t->owned_v[t->owned_n++] = t->owned_store + used;
        used += n + 1;
        joined += (size_t)snprintf(t->owned + joined, sizeof(t->owned) - joined,
                                   "%s%s", joined ? " " : "", s);
    }
}

/* "function(m) " per pin, as the bridge printed them. */
static void collect_pins(struct tick *t)
{
    const struct json_value *arr = jpath(&t->root, "data.next.brief.pins");
    size_t used = 0;
    t->pins[0] = '\0';
    for (size_t i = 0; arr && i < json_size(arr); i++) {
        const struct json_value *p = json_at(arr, i);
        const char *fn = json_get_str(json_get(p, "function"));
        if (!fn || !*fn || !json_get(p, "m"))
            continue;
        const int n = snprintf(t->pins + used, sizeof(t->pins) - used,
                               "%s(%lld) ", fn,
                               (long long)json_get_int(json_get(p, "m")));
        if (n < 0 || (size_t)n >= sizeof(t->pins) - used)
            break;
        used += (size_t)n;
    }
}

static void collect_decision(struct tick *t)
{
    (void)fmt(t->lane, sizeof(t->lane), "%s", jstr(&t->root, "data.dispatch.lane"));
    (void)fmt(t->prefix, sizeof(t->prefix), "%s",
              jstr(&t->root, "data.dispatch.note_prefix"));
    (void)fmt(t->engine, sizeof(t->engine), "%s",
              jstr(&t->root, "data.dispatch.engine"));
    (void)fmt(t->objective, sizeof(t->objective), "%s",
              jstr(&t->root, "data.next.objective"));
    (void)fmt(t->target, sizeof(t->target), "%s",
              jstr(&t->root, "data.next.brief.target_file"));
    collect_owned(t);
    collect_pins(t);
}

static bool unit_files(struct tick *t)
{
    char path[LT_PATH];
    const char *task = jstr(&t->root, "data.dispatch.task_text");
    char *line = NULL;
    if (!fmt(path, sizeof(path), "%s/step.json", t->unit) ||
        !write_file(path, t->raw, strlen(t->raw), "w") ||
        !fmt(path, sizeof(path), "%s/task.txt", t->unit))
        return false;
    const size_t n = strlen(task) + 2;
    line = zcl_malloc(n, "loop_tick_task");
    if (!line)
        return false;
    (void)snprintf(line, n, "%s\n", task);
    const bool ok = write_file(path, line, strlen(line), "w");
    free(line);
    return ok;
}

static int stage_step(struct tick *t)
{
    int rc = ensure_base(t);
    if (rc != LT_GO)
        return rc;
    const char *const step[] = { O(t, LT_O_DEV), "fleet", "objectives", "step",
                                 NULL };
    (void)run(t, O(t, LT_O_BASE), step, oms(t, LT_O_STEP_TIMEOUT));
    if (!step_collect(t))
        return skip(t, "cannot allocate the step document");
    const char *action = jstr(&t->root, "data.action");
    if (strcmp(action, "run") != 0) {
        const char *reason = jstr(&t->root, "data.reason");
        say(t, "step: %s \xe2\x80\x94 %s", *action ? action : "unreadable",
            *reason ? reason : "no reason");
        return 0;
    }
    collect_decision(t);
    if (strcmp(t->engine, "claude-haiku") != 0) {
        char msg[LT_NAME + 96];
        (void)fmt(msg, sizeof(msg),
                  "step chose engine '%s'; this tool runs claude-haiku only",
                  t->engine);
        return skip(t, msg);
    }
    if (strncmp(t->lane, "loop-", 5) != 0) {
        char msg[LT_NAME + 64];
        (void)fmt(msg, sizeof(msg), "unexpected lane name '%s'", t->lane);
        return skip(t, msg);
    }
    if (!*t->target || t->owned_n == 0)
        return skip(t, "step gave no target/owned paths");
    return LT_GO;
}

/* ── step 2: the lane, primed ────────────────────────────────────────── */

static int stage_lane(struct tick *t)
{
    char log[LT_PATH], branch[LT_NAME + 8];
    if (!fmt(t->dir, sizeof(t->dir), "%s/%s", O(t, LT_O_LANES), t->lane) ||
        !fmt(branch, sizeof(branch), "lane/%s", t->lane) ||
        !fmt(t->unit, sizeof(t->unit), "%s/%s", O(t, LT_O_SCRATCH), t->lane))
        return skip(t, "lane path too long");
    if (exists(t->dir)) {
        char msg[LT_NAME + 32];
        (void)fmt(msg, sizeof(msg), "%s already exists", t->lane);
        return skip(t, msg);
    }
    if (!mkdirs(t->unit) || !unit_files(t))
        return skip(t, "cannot write the unit scratch directory");
    say(t, "run %s: %s, %s, pins: %s", t->lane, t->objective, t->target,
        t->pins);
    const char *const add[] = { O(t, LT_O_GIT), "-C", O(t, LT_O_MAIN),
                                "worktree", "add", "-q", "-b", branch, t->dir,
                                "origin/main", NULL };
    if (run(t, NULL, add, LT_SHORT_TIMEOUT_MS) != 0)
        return skip(t, "worktree add failed");
    const char *const prime[] = { O(t, LT_O_DEVBUILD), "--wait", "make",
                                  "worktree-prime", "install-hooks", NULL };
    (void)fmt(log, sizeof(log), "%s/prime.log", t->unit);
    if (run_logged(t, t->dir, prime, LT_BUILD_TIMEOUT_MS, log) != 0)
        return hold(t, t->lane, "prime failed (%s)", log);
    return LT_GO;
}

/* ── steps 3-4: the model edits; the scope check ─────────────────────── */

static int stage_engine(struct tick *t)
{
    char task[LT_PATH], state[LT_PATH], log[LT_PATH], secs[24];
    (void)fmt(task, sizeof(task), "%s/task.txt", t->unit);
    (void)fmt(state, sizeof(state), "%s/eu", t->unit);
    (void)fmt(log, sizeof(log), "%s/engine.log", t->unit);
    (void)fmt(secs, sizeof(secs), "%ld", oint(t, LT_O_ENGINE_TIMEOUT));
    const char *const eu[] = { O(t, LT_O_ENGINE_UNIT), "--engine", "claude-haiku",
                               "--task", task, "--no-group", "--worktree",
                               t->dir, "--yes-dispatch", "--rounds", "1",
                               "--state-dir", state, "--timeout", secs, NULL };
    const int rc = run_logged(t, NULL, eu,
                              oms(t, LT_O_ENGINE_TIMEOUT) + LT_SHORT_TIMEOUT_MS,
                              log);
    say(t, "engine_unit rc=%d (%s)", rc, log);
    const char *const st[] = { O(t, LT_O_GIT), "status", "--porcelain", NULL };
    (void)run(t, t->dir, st, LT_SHORT_TIMEOUT_MS);
    if (!*t->buf)
        return hold(t, t->lane, "the engine changed nothing (rc=%d)", rc);
    return LT_GO;
}

static bool is_owned(const struct tick *t, const char *path)
{
    for (size_t i = 0; i < t->owned_n; i++)
        if (strcmp(path, t->owned_v[i]) == 0)
            return true;
    return false;
}

/* awk '{print $2}' over `git status --porcelain`: the path after the status. */
static bool porcelain_path(const char *line, char *out, size_t cap)
{
    const char *p = line + strspn(line, " ");
    p += strcspn(p, " \n");
    p += strspn(p, " ");
    const size_t n = strcspn(p, " \n");
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static int stage_scope(struct tick *t)
{
    char *status = zcl_strdup(t->buf, "loop_tick_status");
    if (!status)
        return hold(t, t->lane, "cannot allocate the scope check");
    char path[LT_PATH];
    int rc = LT_GO;
    for (char *p = status; *p && rc == LT_GO;) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (porcelain_path(p, path, sizeof(path)) && !is_owned(t, path))
            rc = hold(t, t->lane, "out-of-scope edit: %s", path);
        if (!nl)
            break;
        p = nl + 1;
    }
    free(status);
    return rc;
}

/* ── step 5: the complexity baseline may only shrink ─────────────────── */

static int stage_baseline(struct tick *t)
{
    if (strcmp(t->objective, "functions_over_complexity_cap") != 0)
        return LT_GO;
    char log[LT_PATH], binlog[LT_PATH];
    (void)fmt(log, sizeof(log), "%s/baseline.log", t->unit);
    (void)fmt(binlog, sizeof(binlog), "%s/lintbin.log", t->unit);
    const char *const bin[] = { O(t, LT_O_DEVBUILD), "--wait", "make",
                                "build/bin/z23-lint", NULL };
    const char *const regen[] = { O(t, LT_O_LINT_BIN), "check-cyclomatic-complexity",
                                  "--write-baseline", NULL };
    if (run_logged(t, t->dir, bin, LT_BUILD_TIMEOUT_MS, binlog) != 0 ||
        run_logged(t, t->dir, regen, LT_BUILD_TIMEOUT_MS, log) != 0)
        return hold(t, t->lane, "baseline regen failed (%s)", log);
    const char *const num[] = { O(t, LT_O_GIT), "diff", "--numstat", "--",
                                "tools/lint/cyclomatic_complexity_baseline.txt",
                                NULL };
    (void)run(t, t->dir, num, LT_SHORT_TIMEOUT_MS);
    long added = 0;
    t->removed = 0;
    (void)sscanf(t->buf, "%ld %ld", &added, &t->removed);
    if (added != 0)
        return hold(t, t->lane, "baseline grew by %ld rows", added);
    if (t->removed <= 0)
        return hold(t, t->lane, "no function left the baseline");
    return LT_GO;
}

/* ── step 6: the signed commit ───────────────────────────────────────── */

static bool write_message(struct tick *t, const char *path)
{
    const char *slash = strrchr(t->target, '/');
    const char *base = slash ? slash + 1 : t->target;
    char stem[LT_NAME];
    (void)fmt(stem, sizeof(stem), "%s", base);
    char *dot = strrchr(stem, '.');
    if (dot)
        *dot = '\0';
    char msg[4096];
    if (!fmt(msg, sizeof(msg),
             "refactor(%s): split %s functions under the complexity cap (loop)\n\n"
             "Self-improving loop unit for objective %s (lane %s): %ld\n"
             "function(s) in %s left the complexity baseline by behaviour-preserving\n"
             "extraction. Pins at dispatch: %s\n"
             "Edits by claude-haiku through z23-engine-unit (edit-only tools); the\n"
             "baseline was regenerated by z23-lint and only shrank; gates and a separate\n"
             "read-only Haiku review ran before submit.\n\n%s\n",
             stem, base, t->objective, t->lane, t->removed, t->target, t->pins,
             O(t, LT_O_TRAILER)))
        return false;
    return write_file(path, msg, strlen(msg), "w");
}

static int stage_commit(struct tick *t)
{
    char msgp[LT_PATH];
    const char *argv[LT_OWNED_MAX + 8];
    size_t n = 0;
    (void)fmt(msgp, sizeof(msgp), "%s/msg.txt", t->unit);
    if (!write_message(t, msgp))
        return hold(t, t->lane, "commit failed");
    argv[n++] = O(t, LT_O_GIT);
    argv[n++] = "add";
    argv[n++] = "-A";
    argv[n++] = "--";
    for (size_t i = 0; i < t->owned_n; i++)
        argv[n++] = t->owned_v[i];
    argv[n] = NULL;
    char alog[LT_PATH], clog[LT_PATH];
    (void)fmt(alog, sizeof(alog), "%s/add.log", t->unit);
    (void)fmt(clog, sizeof(clog), "%s/commit.log", t->unit);
    const bool added = run_logged(t, t->dir, argv, LT_SHORT_TIMEOUT_MS, alog) == 0;
    const char *const commit_sign[] = { O(t, LT_O_GIT), "commit", "-q",
                                        O(t, LT_O_SIGN), "-F", msgp, NULL };
    const char *const commit_plain[] = { O(t, LT_O_GIT), "commit", "-q", "-F",
                                         msgp, NULL };
    const char *const *commit = *O(t, LT_O_SIGN) ? commit_sign : commit_plain;
    if (!added || run_logged(t, t->dir, commit, LT_SHORT_TIMEOUT_MS, clog) != 0)
        return hold(t, t->lane, "commit failed (%s)", clog);
    const char *const head[] = { O(t, LT_O_GIT), "rev-parse", "HEAD", NULL };
    (void)run(t, t->dir, head, LT_SHORT_TIMEOUT_MS);
    trim(t->buf);
    (void)fmt(t->sha, sizeof(t->sha), "%s", t->buf);
    say(t, "committed %s", t->sha);
    return LT_GO;
}

/* ── step 7: quick check, then both gates ────────────────────────────── */

/* First whitespace-delimited token that ends in .log, from its first '/'. */
static bool first_log_path(const char *text, char *out, size_t cap)
{
    for (const char *p = text; *p;) {
        p += strspn(p, " \t\r\n");
        const size_t n = strcspn(p, " \t\r\n");
        const char *slash = memchr(p, '/', n);
        if (slash && n >= 4 && memcmp(p + n - 4, ".log", 4) == 0) {
            const size_t len = (size_t)(p + n - slash);
            if (len >= cap)
                return false;
            memcpy(out, slash, len);
            out[len] = '\0';
            return true;
        }
        p += n;
    }
    return false;
}

static bool start_gate(struct tick *t, const char *what, const char *extra,
                       char *log, size_t cap)
{
    const char *argv[] = { O(t, LT_O_ENVP), "-u", "CLAUDECODE", "-u",
                           "CLAUDE_CODE_ENTRYPOINT", O(t, LT_O_ZGATE),
                           "--detach", t->dir, what, extra, NULL };
    (void)run(t, NULL, argv, LT_SHORT_TIMEOUT_MS); /* a NULL extra ends argv */
    return first_log_path(t->buf, log, cap);
}

/* The last "rc=" line of a log, or false while there is none. */
static bool gate_rc(const char *log, char *out, size_t cap)
{
    char *text = read_file(log, 8 << 20);
    bool found = false;
    for (const char *p = text; p && *p;) {
        const char *nl = strchr(p, '\n');
        const size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (strncmp(p, "rc=", 3) == 0 && n < cap) {
            memcpy(out, p, n);
            out[n] = '\0';
            found = true;
        }
        p = nl ? nl + 1 : p + n;
    }
    free(text);
    return found;
}

static bool wait_gates(struct tick *t, const char *l1, const char *l2,
                       char *rc1, char *rc2, size_t cap)
{
    const long limit_ms = oint(t, LT_O_GATE_WAIT) * 1000;
    const long poll_ms = oint(t, LT_O_POLL) > 0 ? oint(t, LT_O_POLL) : 1000;
    for (long waited = 0;; waited += poll_ms) {
        if (gate_rc(l1, rc1, cap) && gate_rc(l2, rc2, cap))
            return true;
        if (waited >= limit_ms)
            return false;
        const struct timespec ts = { (time_t)(poll_ms / 1000),
                                     (long)(poll_ms % 1000) * 1000000L };
        (void)nanosleep(&ts, NULL);
    }
}

/* One rerun of agent-verify in the lane on r1, before a gate failure holds:
 * a single group failing on a loaded gate host is often load. The land note
 * then names both runs, so the lead reads what was actually proved. */
static int gate_rerun(struct tick *t, const char *rc1, const char *l1)
{
    char log[LT_PATH];
    (void)fmt(log, sizeof(log), "%s/av-rerun.log", t->unit);
    const char *const av[] = { O(t, LT_O_DEVBUILD), "--wait", "make",
                               "agent-verify", "ONLY=@changed", NULL };
    say(t, "agent-verify %s on the gate host; rerunning once on r1 (%s)", rc1, l1);
    if (run_logged(t, t->dir, av, LT_BUILD_TIMEOUT_MS, log) != 0)
        return hold(t, t->lane, "agent-verify %s (%s); the r1 rerun failed (%s)",
                    rc1, l1, log);
    say(t, "agent-verify rerun on r1 rc=0");
    (void)fmt(t->gatenote, sizeof(t->gatenote),
              "zgate agent-verify %s then r1 rerun rc=0, lint rc=0", rc1);
    return LT_GO;
}

static int stage_gates(struct tick *t)
{
    char log[LT_PATH], l1[LT_PATH], l2[LT_PATH], rc1[256], rc2[256];
    const char *const quick[] = { O(t, LT_O_DEVBUILD), "--wait", "make",
                                  "lint-land", "lint-preflight", NULL };
    (void)fmt(t->gatenote, sizeof(t->gatenote), "zgate agent-verify+lint rc=0");
    (void)fmt(log, sizeof(log), "%s/lintland.log", t->unit);
    if (run_logged(t, t->dir, quick, LT_BUILD_TIMEOUT_MS, log) != 0)
        return hold(t, t->lane, "lint-land failed (%s)", log);
    const bool a = start_gate(t, "agent-verify", "ONLY=@changed", l1, sizeof(l1));
    const bool b = start_gate(t, "lint", NULL, l2, sizeof(l2));
    if (!a || !b)
        return hold(t, t->lane, "zgate did not start");
    if (!wait_gates(t, l1, l2, rc1, rc2, sizeof(rc1)))
        return hold(t, t->lane, "gates did not finish in %ld h (%s %s)",
                    oint(t, LT_O_GATE_WAIT) / 3600, l1, l2);
    say(t, "gates: agent-verify %s / lint %s", rc1, rc2);
    if (strncmp(rc1, "rc=0", 4) != 0) {
        const int rr = gate_rerun(t, rc1, l1);
        if (rr != LT_GO)
            return rr;
    }
    if (strncmp(rc2, "rc=0", 4) != 0)
        return hold(t, t->lane, "lint %s (%s)", rc2, l2);
    return LT_GO;
}

static bool lane_at_sha(struct tick *t)
{
    const char *const head[] = { O(t, LT_O_GIT), "rev-parse", "HEAD", NULL };
    (void)run(t, t->dir, head, LT_SHORT_TIMEOUT_MS);
    trim(t->buf);
    return strcmp(t->buf, t->sha) == 0;
}

/* ── step 8: the non-author review ───────────────────────────────────── */

static bool build_review_prompt(struct tick *t, const char *path)
{
    const size_t cap = LT_SHOW_MAX + 6144;
    char *p = zcl_malloc(cap, "loop_tick_review_prompt");
    if (!p)
        return false;
    const char *const show[] = { O(t, LT_O_GIT), "show", "--stat", "--patch",
                                 "HEAD", NULL };
    (void)run(t, t->dir, show, LT_SHORT_TIMEOUT_MS);
    if (strlen(t->buf) > LT_SHOW_MAX)
        t->buf[LT_SHOW_MAX] = '\0'; /* head -c 90000 */
    const int n = snprintf(p, cap,
        "You are a NON-AUTHOR reviewer of one Z23 commit in the current git worktree. You can only read files (Read, Grep, Glob); you cannot run commands or edit anything.\n"
        "The commit claims a behaviour-preserving split of over-complexity functions in %s, and a baseline change that only deletes rows.\n"
        "Check, reading the code at HEAD and the diff below: (1) every extracted helper preserves the original behaviour exactly: same checks in the same order, same early returns and return values, same error/log text, same side effects and short-circuit order; (2) no lookalike duplicate helpers were added where an existing one fits; (3) no function in the diff obviously exceeds cyclomatic complexity 15; (4) only %s changed; (5) the baseline diff only deletes rows; (6) nothing weakens a test, assertion, threshold or refusal; (7) every allocation stays checked.\n"
        "End your reply with exactly one final line: 'VERDICT: LAND' or 'VERDICT: HOLD <reason with file:line>'.\n"
        "\n----- git show HEAD -----\n%s",
        t->target, t->owned, t->buf);
    const bool ok = n > 0 && (size_t)n < cap && write_file(path, p, (size_t)n, "w");
    free(p);
    return ok;
}

/* The last line holding "VERDICT: ", from there to the end of that line. */
static bool find_verdict(const char *review, char *out, size_t cap)
{
    bool found = false;
    for (const char *p = review; p && *p;) {
        const char *nl = strchr(p, '\n');
        const size_t n = nl ? (size_t)(nl - p) : strlen(p);
        const char *v = memmem(p, n, "VERDICT: ", 9);
        if (v) {
            const size_t len = (size_t)(p + n - v);
            if (len < cap) {
                memcpy(out, v, len);
                out[len] = '\0';
                found = true;
            }
        }
        p = nl ? nl + 1 : p + n;
    }
    return found;
}

static char *review_text(const struct tick *t)
{
    struct json_value doc;
    json_init(&doc);
    char *out = NULL;
    if (json_read(&doc, t->buf, strlen(t->buf))) {
        const char *r = json_get_str(json_get(&doc, "result"));
        out = r ? zcl_strdup(r, "loop_tick_review") : NULL;
    }
    json_free(&doc);
    return out;
}

static int stage_review(struct tick *t)
{
    char pp[LT_PATH], rj[LT_PATH], rt[LT_PATH], verdict[512] = "";
    (void)fmt(pp, sizeof(pp), "%s/review-prompt.txt", t->unit);
    (void)fmt(rj, sizeof(rj), "%s/review.json", t->unit);
    (void)fmt(rt, sizeof(rt), "%s/review.txt", t->unit);
    if (!build_review_prompt(t, pp))
        return hold(t, t->lane, "cannot build the review prompt (%s)", pp);
    char *prompt = read_file(pp, LT_SHOW_MAX + 6144);
    if (!prompt)
        return hold(t, t->lane, "cannot build the review prompt (%s)", pp);
    const char *const argv[] = { O(t, LT_O_CLAUDE), "-p", prompt, "--model",
                                 "claude-haiku-5-5", "--output-format", "json",
                                 "--no-session-persistence", "--setting-sources=",
                                 "--tools", "Read,Grep,Glob", NULL };
    /* stdout only: it is the review's JSON, parsed below */
    (void)run(t, t->dir, argv, oms(t, LT_O_REVIEW_TIMEOUT));
    (void)write_file(rj, t->buf, strlen(t->buf), "w");
    free(prompt);
    char *review = review_text(t);
    if (review) {
        (void)write_file(rt, review, strlen(review), "w");
        (void)write_file(rt, "\n", 1, "a");
    }
    const bool have = review && find_verdict(review, verdict, sizeof(verdict));
    free(review);
    say(t, "review: %s", have ? verdict : "none");
    if (!have || strncmp(verdict, "VERDICT: LAND", 13) != 0)
        return hold(t, t->lane, "review %s (%s)",
                    have ? verdict : "gave no verdict", rt);
    const char *const st[] = { O(t, LT_O_GIT), "status", "--porcelain", NULL };
    const bool at_sha = lane_at_sha(t);
    (void)run(t, t->dir, st, LT_SHORT_TIMEOUT_MS);
    if (!at_sha || count_lines(t->buf, line_tracked) != 0)
        return hold(t, t->lane, "the review changed the lane");
    return LT_GO;
}

/* ── step 9: prep and submit ─────────────────────────────────────────── */

static int stage_submit(struct tick *t)
{
    char log[LT_PATH], note[1024], flag_wt[LT_PATH + 16], flag_note[640];
    const char *slash = strrchr(t->target, '/');
    const char *base = slash ? slash + 1 : t->target;
    const char *const prep[] = { O(t, LT_O_DEVBUILD), "--wait", "make",
                                 "dev-bin", "build/bin/z23-lint",
                                 "docs-capability-inventory", NULL };
    (void)fmt(log, sizeof(log), "%s/prep.log", t->unit);
    if (run_logged(t, t->dir, prep, LT_BUILD_TIMEOUT_MS, log) != 0)
        return hold(t, t->lane, "prep failed (%s)", log);
    (void)fmt(note, sizeof(note),
              "%s split %ld over-cap function(s) in %s (%s) under the complexity cap; "
              "claude-haiku via z23-engine-unit, baseline only shrank, %s, "
              "read-only Haiku review LAND.",
              t->prefix, t->removed, base, t->pins, t->gatenote);
    (void)fmt(flag_wt, sizeof(flag_wt), "--worktree=%s", t->dir);
    (void)fmt(flag_note, sizeof(flag_note), "--note=%.500s", note);
    const char *const submit[] = { O(t, LT_O_DEV), "dev", "land", "submit",
                                   flag_wt, flag_note, NULL };
    (void)run(t, NULL, submit, LT_SHORT_TIMEOUT_MS);
    struct json_value doc;
    json_init(&doc);
    char seq[32] = "?";
    if (json_read(&doc, t->buf, strlen(t->buf)))
        (void)fmt(seq, sizeof(seq), "%lld",
                  (long long)json_get_int(jpath(&doc, "data.seq")));
    json_free(&doc);
    say(t, "submitted %s as #%s", t->lane, seq);
    return 0;
}

/* ── options, lock, main ─────────────────────────────────────────────── */

static bool expand_default(struct tick *t, enum lt_opt o)
{
    const char *d = k_defaults[o];
    const char *home = getenv("HOME");
    if (strncmp(d, "~/", 2) == 0)
        return fmt(t->dflt[o], LT_PATH, "%s/%s", home ? home : "", d + 2);
    static const struct { const char *tag; enum lt_opt opt; } tags[] = {
        { "@main/", LT_O_MAIN }, { "@lanes/", LT_O_LANES },
        { "@state/", LT_O_STATE }
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        const size_t n = strlen(tags[i].tag);
        if (strncmp(d, tags[i].tag, n) == 0)
            return fmt(t->dflt[o], LT_PATH, "%s/%s", O(t, tags[i].opt), d + n);
    }
    return fmt(t->dflt[o], LT_PATH, "%s", d);
}

static int parse_args(struct tick *t, int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        enum lt_opt o = LT_O_COUNT;
        for (int k = 0; k < LT_O_COUNT; k++)
            if (strcmp(argv[i], k_flags[k]) == 0)
                o = (enum lt_opt)k;
        if (o == LT_O_COUNT || i + 1 >= argc) {
            fprintf(stderr, "loop-tick: %s option '%s'\nusage: z23-loop-tick "
                    "[--<option> VALUE]... (see tools/loop_tick.c)\n",
                    o == LT_O_COUNT ? "unknown" : "missing value for", argv[i]);
            return 2;
        }
        t->opt[o] = argv[++i];
    }
    for (int k = 0; k < LT_O_COUNT; k++) {
        if (!t->opt[k] && !expand_default(t, (enum lt_opt)k)) {
            fprintf(stderr, "loop-tick: default for %s is too long\n", k_flags[k]);
            return 2;
        }
        if (!t->opt[k])
            t->opt[k] = t->dflt[k];
    }
    /* An unsigned commit lands only under the test-only option. */
    if (!*O(t, LT_O_SIGN) && strcmp(O(t, LT_O_ALLOW_UNSIGNED), "1") != 0) {
        fprintf(stderr, "loop-tick: refusing an empty --sign-flag: commits must be "
                "signed (--allow-unsigned 1 is for tests only)\n");
        return 2;
    }
    return LT_GO;
}

static int open_lock(const struct tick *t)
{
    char path[LT_PATH];
    if (!fmt(path, sizeof(path), "%s/lock", O(t, LT_O_STATE)))
        return -1;
    const int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return -2;
    }
    return fd;
}

static int tick_stages(struct tick *t)
{
    int (*const stages[])(struct tick *) = {
        stage_housekeeping, stage_step, stage_lane, stage_engine, stage_scope,
        stage_baseline, stage_commit, stage_gates, stage_review, stage_submit
    };
    int rc = LT_GO;
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]) && rc == LT_GO; i++) {
        rc = stages[i](t);
        if (rc == LT_GO && stages[i] == stage_gates && !lane_at_sha(t))
            rc = hold(t, t->lane, "lane moved during the gates");
    }
    return rc;
}

int main(int argc, char **argv)
{
    static struct tick t;
    int rc = parse_args(&t, argc, argv);
    if (rc != LT_GO)
        return rc;
    if (!mkdirs(O(&t, LT_O_STATE)) || !mkdirs(O(&t, LT_O_SCRATCH)) ||
        !fmt(t.log_path, sizeof(t.log_path), "%s/tick.log", O(&t, LT_O_STATE))) {
        fprintf(stderr, "loop-tick: cannot create the state or scratch directory\n");
        return 1;
    }
    const int lock = open_lock(&t);
    if (lock == -2)
        return skip(&t, "another tick is running");
    if (lock < 0) {
        fprintf(stderr, "loop-tick: cannot open the lock file: %s\n",
                strerror(errno));
        return 1;
    }
    t.buf = zcl_malloc(LT_BUF, "loop_tick_capture");
    if (!t.buf) {
        fprintf(stderr, "loop-tick: cannot allocate the capture buffer\n");
        return 1;
    }
    rc = tick_stages(&t);
    run_free(&t);
    free(t.buf);
    (void)close(lock);
    return rc == LT_GO ? 0 : rc;
}
