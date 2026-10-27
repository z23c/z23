/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_loop_tick: whole ticks of build/bin/z23-loop-tick against a temp git
 * repo (a bare origin, a main checkout, a lanes directory) with every external
 * program replaced by a small generated sh fake through the tool's options:
 * z23-dev (step and land submit), z23-engine-unit, zgate, devbuild, z23-lint,
 * the retire script. No real engine, gate host, model or land queue
 * is ever reached. The scripts are written at run time, so no shell file is
 * tracked.
 *
 * Scenarios: a clean run submits with the loop note; a scope violation, a
 * baseline that grows and a non-LAND review each write a HOLD (the first two
 * without a commit); the step actions wait, paused and none, and a non-haiku
 * engine, create no lane; a second instance exits on the lock; a landed lane
 * is retired; held lanes at --max-held stop the tick before the step. A failed
 * agent-verify is rerun once on r1 (a passing rerun submits with its note, a
 * failing one holds); the lint-land log keeps the stderr a build wrote; an
 * empty --sign-flag is refused unless --allow-unsigned 1 is given.
 *
 * Finish mode (--finish/--target/--credit): a committed one-commit lane is
 * adopted and submitted with the data-built land note; an out-of-scope
 * committed path, a grown baseline, no removed function, a dirty tracked tree,
 * two commits ahead and a HOLD review each exit 1 with the HOLD line; missing
 * --target exits 2; a held hourly-tick lock does not block a finish and a held
 * same-lane finish lock skips. Both modes build the land note with one bounded
 * builder: a long pins list is clipped (fixed tail intact), a note that cannot
 * fit 500 bytes HOLDs and is never submitted, and a submit without data.seq HOLDs.
 * The lane claim: a finish records the changed files with `dev agent claim`
 * before the gates, renews it while they wait, releases it after a submit and
 * after a HOLD, and a refused claim HOLDs before any gate runs. */

#include "test/test_core.h"

#include "util/spawn.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LT_CHECK(name, expr)                                                 \
    do {                                                                     \
        const bool lt_ok_ = (expr);                                          \
        if (!lt_ok_) failures++;                                             \
        printf("loop_tick: %s %s\n", lt_ok_ ? "OK  " : "FAIL", (name));      \
    } while (0)

static const char LT_BIN[] = "build/bin/z23-loop-tick";

struct lt_cfg {
    const char *edit;    /* file the fake engine appends to, or NULL */
    const char *lint;    /* "shrink" or "grow" */
    const char *verdict; /* the review's last line */
    const char *gate_rc; /* what the fake agent-verify gate prints (lint prints rc=0) */
    const char *rerun;   /* exit status of the r1 agent-verify rerun, NULL = 0 */
};

struct lt_env {
    char d[600]; /* absolute scenario directory */
};

static bool lt_wf(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool lt_script(const struct lt_env *e, const char *name, const char *fmt, ...)
{
    char path[900], body[4096], text[4300];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    (void)snprintf(path, sizeof(path), "%s/bin/%s", e->d, name);
    (void)snprintf(text, sizeof(text), "#!/bin/sh\n%s\n", body);
    return lt_wf(path, text) && chmod(path, 0755) == 0;
}

static bool lt_slurp(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(out, 1, cap - 1, f);
    (void)fclose(f);
    out[n] = '\0';
    return true;
}

struct lt_slow_slot {
    bool requested, published;
    int64_t due_ms;
    char log[900], result[32];
};

struct lt_slow_worker {
    pthread_t thread;
    atomic_bool stop;
    bool ok;
    const struct lt_env *env;
    struct lt_slow_slot slots[2];
};

static bool lt_slow_error(const char *operation, const char *path)
{
    fprintf(stderr, "loop_tick: slow_gate operation=%s path=%s error=%s\n",
            operation, path, strerror(errno));
    return false;
}

static bool lt_slow_name(const char *name)
{
    const size_t n = strlen(name);
    if (n <= 10 || strncmp(name, "zgate.", 6) != 0 ||
        strcmp(name + n - 4, ".log") != 0)
        return false;
    for (size_t i = 6; i < n - 4; i++)
        if (name[i] < '0' || name[i] > '9')
            return false;
    return true;
}

static bool lt_slow_line(FILE *f, char *out, size_t cap)
{
    if (!fgets(out, (int)cap, f))
        return false;
    const size_t n = strlen(out);
    if (n == 0 || out[n - 1] != '\n')
        return false;
    out[n - 1] = '\0';
    return true;
}

static bool lt_slow_result(const char *text)
{
    if (strncmp(text, "rc=", 3) != 0 || text[3] == '\0')
        return false;
    for (const char *p = text + 3; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

/* Atomic request publication prevents a partial request from being read. */
static int lt_slow_request(struct lt_slow_worker *worker, size_t index)
{
    const char *kind = index == 0 ? "agent-verify" : "lint";
    char request[900], name[64];
    (void)snprintf(request, sizeof(request), "%s/slow-request.%s", worker->env->d, kind);
    FILE *f = fopen(request, "rb");
    if (!f) {
        if (errno == ENOENT)
            return 0;
        (void)lt_slow_error("request-open", request);
        return -1;
    }
    struct lt_slow_slot *slot = &worker->slots[index];
    bool ok = lt_slow_line(f, name, sizeof(name)) &&
        lt_slow_line(f, slot->result, sizeof(slot->result)) &&
        fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0)
        ok = false;
    if (!ok || !lt_slow_name(name) || !lt_slow_result(slot->result)) {
        errno = EINVAL;
        (void)lt_slow_error("request-read", request);
        return -1;
    }
    (void)snprintf(slot->log, sizeof(slot->log), "%s/%s", worker->env->d, name);
    slot->due_ms = platform_time_monotonic_ms() + 1000;
    slot->requested = true;
    return 1;
}

static bool lt_slow_publish(struct lt_slow_slot *slot)
{
    char temp[920], text[40];
    (void)snprintf(temp, sizeof(temp), "%s.pending", slot->log);
    (void)snprintf(text, sizeof(text), "%s\n", slot->result);
    if (!lt_wf(temp, text))
        return lt_slow_error("log-write", temp);
    if (rename(temp, slot->log) != 0)
        return lt_slow_error("log-rename", slot->log);
    slot->published = true;
    return true;
}

static bool lt_slow_step(struct lt_slow_worker *worker, size_t index)
{
    struct lt_slow_slot *slot = &worker->slots[index];
    if (!slot->requested && lt_slow_request(worker, index) < 0)
        return false;
    if (slot->requested && !slot->published &&
        platform_time_monotonic_ms() >= slot->due_ms)
        return lt_slow_publish(slot);
    return true;
}

static void *lt_slow_run(void *argument)
{
    struct lt_slow_worker *worker = argument;
    while (!atomic_load_explicit(&worker->stop, memory_order_acquire)) {
        if (!lt_slow_step(worker, 0) || !lt_slow_step(worker, 1)) {
            worker->ok = false;
            break;
        }
        const struct timespec pause = { .tv_nsec = 20000000 };
        if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
            worker->ok = lt_slow_error("poll-sleep", worker->env->d);
            break;
        }
    }
    return NULL;
}

static bool lt_slow_start(struct lt_slow_worker *worker, const struct lt_env *env)
{
    *worker = (struct lt_slow_worker){ .ok = true, .env = env };
    atomic_init(&worker->stop, false);
    char marker[900];
    (void)snprintf(marker, sizeof(marker), "%s/slowgate", env->d);
    if (!lt_wf(marker, ""))
        return lt_slow_error("marker-write", marker);
    const int rc = pthread_create(&worker->thread, NULL, lt_slow_run, worker);
    if (rc != 0) {
        errno = rc;
        return lt_slow_error("thread-create", env->d);
    }
    return true;
}

static bool lt_slow_stop(struct lt_slow_worker *worker)
{
    atomic_store_explicit(&worker->stop, true, memory_order_release);
    const int rc = pthread_join(worker->thread, NULL);
    if (rc != 0) {
        errno = rc;
        (void)lt_slow_error("thread-join", worker->env->d);
        abort();
    }
    return worker->ok;
}

static bool lt_exists(const char *fmt, const char *d, const char *rel)
{
    char p[900];
    struct stat st;
    (void)snprintf(p, sizeof(p), fmt, d, rel);
    return stat(p, &st) == 0;
}

static bool lt_run(const char *const argv[], char *out, size_t cap, int *rc)
{
    char scratch[8192];
    const int r = zcl_spawn_capture(argv, out ? out : scratch,
                                    out ? cap : sizeof(scratch), 120000);
    if (rc)
        *rc = r;
    return r == 0;
}

__attribute__((sentinel)) static bool lt_git(const char *dir, ...)
{
    const char *argv[24] = { "git", "-C", dir };
    size_t n = 3;
    va_list ap;
    va_start(ap, dir);
    for (const char *a; n < 22 && (a = va_arg(ap, const char *)) != NULL;)
        argv[n++] = a;
    va_end(ap);
    argv[n] = NULL;
    return lt_run(argv, NULL, 0, NULL);
}

static bool lt_repo(const struct lt_env *e)
{
    char origin[700], main_[700], f[900];
    (void)snprintf(origin, sizeof(origin), "%s/origin.git", e->d);
    (void)snprintf(main_, sizeof(main_), "%s/main", e->d);
    const char *const mk[] = { "mkdir", "-p", main_, origin, NULL };
    char dirs[900];
    (void)snprintf(dirs, sizeof(dirs), "%s/main/tools/lint", e->d);
    const char *const mk2[] = { "mkdir", "-p", dirs, NULL };
    if (!lt_run(mk, NULL, 0, NULL) || !lt_run(mk2, NULL, 0, NULL))
        return false;
    (void)snprintf(f, sizeof(f), "%s/owned.c", main_);
    bool ok = lt_wf(f, "int owned;\n");
    (void)snprintf(f, sizeof(f), "%s/other.c", main_);
    ok = ok && lt_wf(f, "int other;\n");
    (void)snprintf(f, sizeof(f), "%s/tools/lint/cyclomatic_complexity_baseline.txt", main_);
    ok = ok && lt_wf(f, "a.c:f1:20\na.c:f2:21\na.c:f3:22\n");
    (void)snprintf(f, sizeof(f), "%s/tools/lint/card_baseline.txt", main_);
    ok = ok && lt_wf(f, "owned.c 3\nother.c 2\n");
    return ok && lt_git(origin, "init", "-q", "--bare", NULL) &&
           lt_git(main_, "init", "-q", NULL) &&
           lt_git(main_, "checkout", "-q", "-b", "main", NULL) &&
           lt_git(main_, "add", "-A", NULL) &&
           lt_git(main_, "-c", "user.name=fixture", "-c", "user.email=f@example.invalid",
                  "commit", "-q", "-m", "base", NULL) &&
           lt_git(main_, "remote", "add", "origin", origin, NULL) &&
           lt_git(main_, "push", "-q", "origin", "main", NULL) &&
           lt_git(main_, "fetch", "-q", "origin", "main", NULL);
}

/* The fake z23-lint --write-baseline body: "shrink" deletes the first row,
 * "grow" appends a new row, "lower" deletes the first row and lowers the
 * third row's score, "rise" raises the second row's score. */
static const char *lt_lint_body(const struct lt_env *e, const char *mode)
{
    static const char base[] = "tools/lint/cyclomatic_complexity_baseline.txt";
    static char lower[512], rise[512];
    if (strcmp(mode, "grow") == 0)
        return "echo f9:99 >> tools/lint/cyclomatic_complexity_baseline.txt";
    (void)snprintf(lower, sizeof(lower),
                   "f=%s\ntail -n +2 $f | sed 's/^a.c:f3:22$/a.c:f3:21/' > $f.new && mv $f.new $f",
                   base);
    (void)snprintf(rise, sizeof(rise),
                   "f=%s\nsed 's/^a.c:f2:21$/a.c:f2:25/' $f > $f.new && mv $f.new $f",
                   base);
    if (strcmp(mode, "verify") == 0) { /* a card's gate: log the words, pass unless verify.fail exists */
        static char verify[600];
        (void)snprintf(verify, sizeof(verify),
                       "echo \"$@\" >> '%s/verify_args.txt'\n[ -e '%s/verify.fail' ] && exit 1\nexit 0",
                       e->d, e->d);
        return verify;
    }
    if (strcmp(mode, "lower") == 0)
        return lower;
    if (strcmp(mode, "rise") == 0)
        return rise;
    return "f=tools/lint/cyclomatic_complexity_baseline.txt\n"
           "tail -n +2 $f > $f.new && mv $f.new $f";
}

static bool lt_fakes(const struct lt_env *e, const struct lt_cfg *c)
{
    char bindir[700];
    (void)snprintf(bindir, sizeof(bindir), "%s/bin", e->d);
    const char *const mk[] = { "mkdir", "-p", bindir, NULL };
    if (!lt_run(mk, NULL, 0, NULL))
        return false;
    const char *edit = c->edit ? c->edit : "";
    return lt_script(e, "dev",
               "case \"$1\" in\n fleet) echo \"$@\" >> '%s/step_args.txt'; cat '%s/step.json' ;;\n"
               " dev) if [ \"$2\" = agent ]; then\n"
               "  echo \"$@\" >> '%s/claims.txt'\n"
               "  [ -e '%s/claim.fail' ] && { echo '{\"ok\":false}'; exit 1; }\n"
               "  case \"$*\" in *release*) rm -f '%s/claim.live' ;; *) : > '%s/claim.live' ;; esac\n"
               "  echo '{\"ok\":true}'\n"
               " else echo \"$@\" > '%s/submit.txt'; echo '{\"data\":{\"seq\":7}}'; fi ;;\nesac",
               e->d, e->d, e->d, e->d, e->d, e->d, e->d) &&
           lt_script(e, "eu",
               "echo \"$@\" >> '%s/eu_args.txt'\n"
               "while [ $# -gt 0 ]; do\n"
               " case \"$1\" in --worktree) wt=$2 ;; --state-dir) sd=$2 ;; --kind) kind=$2 ;; esac\n"
               " shift\ndone\n"
               "if [ \"$kind\" = review ]; then\n"
               " if flock -n '%s/haiku.lock' true; then echo free > '%s/lockstate.txt';"
               " else echo held > '%s/lockstate.txt'; fi\n"
               " echo \"$wt\" >> '%s/review_wt.txt'\n"
               " mkdir -p \"$sd\" && printf 'reviewed\\n%%s\\n' '%s' > \"$sd/reply.txt\"\n"
               " exit 0\nfi\n"
               "[ -n '%s' ] || exit 0\ncd \"$wt\" && echo edit >> '%s'\n"
               "[ -e '%s/eu_extra.sh' ] && sh '%s/eu_extra.sh'\nexit 0",
               e->d, e->d, e->d, e->d, e->d, c->verdict, edit, edit, e->d, e->d) &&
           lt_script(e, "devbuild",
               "case \"$*\" in\n *lint-land*) echo lint-land-stderr-marker >&2 ;;\n"
               " *agent-verify*) exit %s ;;\nesac\nexit 0",
               c->rerun ? c->rerun : "0") &&
           lt_script(e, "lint", lt_lint_body(e, c->lint)) &&
           lt_script(e, "zgate",
               "d='%s'; l=\"$d\"/zgate.$$.log\n"
               "case \"$*\" in *agent-verify*) r='%s' ;; *) r='rc=0' ;; esac\n"
               "[ -e '%s/claim.live' ] && echo saw >> '%s/gate_saw_claim.txt'\n"
               "if [ -e \"$d/slowgate\" ]; then\n"
               " case \"$*\" in *agent-verify*) kind=agent-verify ;; *) kind=lint ;; esac\n"
               " req=\"$d/slow-request.$kind\"; tmp=\"$req.$$\"\n"
               " if ! printf '%%s\\n%%s\\n' \"zgate.$$.log\" \"$r\" > \"$tmp\" || ! mv \"$tmp\" \"$req\"; then\n"
               "  echo 'loop_tick: slow gate request publication failed' >&2; exit 1\n"
               " fi\n"
               "else echo \"$r\" > \"$l\"; fi\necho \"log: $l\"",
               e->d, c->gate_rc, e->d, e->d) &&
           lt_script(e, "precheck",
               "n=$(cat '%s/pre.count' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '%s/pre.count'\n"
               "echo \"$1\" >> '%s/pre.args'\n"
               "red=$(cat '%s/pre.red' 2>/dev/null || echo 0)\n"
               "if [ \"$n\" -le \"$red\" ]; then echo '1 new gate failure(s)'; echo '  check-fake-gate  failed'; exit 1; fi\n"
               "echo 'no new gate failures'",
               e->d, e->d, e->d, e->d) &&
           lt_script(e, "mainlint", "echo \"gate-output-marker for $1\"") &&
           lt_script(e, "retire",
               "echo \"$@\" >> '%s/retire.txt'\n"
               "git -C '%s/main' worktree remove --force \"$1\"", e->d, e->d);
}

/* The fixture step document: note prefix, target file and pins list given;
 * npins 0 is the one default pin fn_a(22), else npins padded pin names. */
static bool lt_step_doc(const struct lt_env *e, const char *action,
                        const char *engine, const char *prefix,
                        const char *target, int npins)
{
    static char pins[8192], doc[16384];
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/step.json", e->d);
    size_t used = 0;
    pins[0] = '\0';
    if (npins == 0)
        (void)snprintf(pins, sizeof(pins), "{\"function\":\"fn_a\",\"m\":22}");
    for (int i = 0; i < npins; i++)
        used += (size_t)snprintf(pins + used, sizeof(pins) - used,
                                 "%s{\"function\":\"pinned_function_%03d\",\"m\":22}",
                                 i ? "," : "", i);
    (void)snprintf(doc, sizeof(doc),
        "{\"data\":{\"action\":\"%s\",\"reason\":\"fixture reason\","
        "\"dispatch\":{\"lane\":\"loop-t1\",\"note_prefix\":\"%s\","
        "\"engine\":\"%s\",\"task_text\":\"do the unit\"},"
        "\"next\":{\"objective\":\"functions_over_complexity_cap\","
        "\"brief\":{\"target_file\":\"%s\","
        "\"owned\":[\"%s\",\"tools/lint/cyclomatic_complexity_baseline.txt\"],"
        "\"pins\":[%s]}}}}",
        action, prefix, engine, target, target, pins);
    return lt_wf(path, doc);
}

static bool lt_step_json(const struct lt_env *e, const char *action,
                         const char *engine)
{
    return lt_step_doc(e, action, engine, "loop:obj1:", "owned.c", 0);
}

static bool lt_setup(struct lt_env *e, const char *tag, const struct lt_cfg *c,
                     const char *action, const char *engine)
{
    char rel[512];
    test_make_tmpdir(rel, sizeof(rel), "loop_tick", tag);
    if (!test_abs_path(rel, e->d, sizeof(e->d)))
        return false;
    return lt_repo(e) && lt_fakes(e, c) && lt_step_json(e, action, engine);
}

/* One tool run with any number of extra argv words (NULL-terminated), last
 * one wins for a repeated option; returns the exit status, output in out. */
static int lt_tool(const struct lt_env *e, const char *const extra[], char *out,
                   size_t cap)
{
    char a[16][700], lock[700];
    (void)snprintf(lock, sizeof(lock), "%s/haiku.lock", e->d);
    const char *names[] = { "--main", "--lanes", "--state-dir", "--scratch-dir",
                            "--dev", "--engine-unit", "--zgate", "--retire-script",
                            "--devbuild", "--lint-bin", "--precheck-script",
                            "--main-lint" };
    const char *rels[] = { "main", "lanes", "state", "scratch", "bin/dev", "bin/eu",
                           "bin/zgate", "bin/retire", "bin/devbuild",
                           "bin/lint", "bin/precheck", "bin/mainlint" };
    const char *argv[64] = { "env", "GIT_AUTHOR_NAME=fixture",
        "GIT_AUTHOR_EMAIL=f@example.invalid", "GIT_COMMITTER_NAME=fixture",
        "GIT_COMMITTER_EMAIL=f@example.invalid", LT_BIN };
    size_t n = 6;
    for (size_t i = 0; i < 12; i++) {
        (void)snprintf(a[i], sizeof(a[i]), "%s/%s", e->d, rels[i]);
        argv[n++] = names[i];
        argv[n++] = a[i];
    }
    const char *const fixed[] = { "--sign-flag", "", "--allow-unsigned", "1",
        "--poll-ms", "50", "--gate-wait-s", "10", "--step-timeout-s", "30",
        "--engine-timeout-s", "30", "--review-timeout-s", "30" };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        argv[n++] = fixed[i];
    argv[n++] = "--haiku-lock";
    argv[n++] = lock;
    for (size_t i = 0; extra && extra[i] && n < 62; i++)
        argv[n++] = extra[i];
    argv[n] = NULL;
    /* merged: the refusal text is on stderr, the tool's own lines on stdout */
    char scratch[8192];
    bool timed_out = false;
    return zcl_spawn_capture_merged_observed(argv, out ? out : scratch,
                                             out ? cap : sizeof(scratch),
                                             120000, &timed_out);
}

/* One tick; returns the tool's exit status, output in out. */
static int lt_tick(const struct lt_env *e, const char *extra_flag,
                   const char *extra_value, char *out, size_t cap)
{
    const char *const extra[] = { extra_flag, extra_value, NULL };
    return lt_tool(e, extra, out, cap);
}

static bool lt_has(const char *path, const char *needle)
{
    static char text[1 << 16];
    return lt_slurp(path, text, sizeof(text)) && strstr(text, needle) != NULL;
}

static bool lt_file_has(const struct lt_env *e, const char *rel, const char *needle)
{
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/%s", e->d, rel);
    return lt_has(p, needle);
}

static int lt_commits_ahead(const struct lt_env *e)
{
    char lane[900], out[64] = "";
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-t1", e->d);
    const char *const argv[] = { "git", "-C", lane, "rev-list", "--count",
                                 "origin/main..HEAD", NULL };
    return lt_run(argv, out, sizeof(out), NULL) ? atoi(out) : -1;
}

static int lt_ahead(const struct lt_env *e, const char *name)
{
    char lane[900], out[64] = "";
    (void)snprintf(lane, sizeof(lane), "%s/lanes/%s", e->d, name);
    const char *const argv[] = { "git", "-C", lane, "rev-list", "--count",
                                 "origin/main..HEAD", NULL };
    return lt_run(argv, out, sizeof(out), NULL) ? atoi(out) : -1;
}

static int case_run_submits(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192];
    const bool ready = lt_setup(&e, "run", &c, "run", "claude-haiku");
    LT_CHECK("the run scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, out, sizeof(out));
    LT_CHECK("a clean tick exits 0", rc == 0);
    LT_CHECK("it submits with the loop:<objective>: note prefix",
             lt_file_has(&e, "submit.txt", "--note=loop:obj1: split 1 over-cap function(s) in owned.c (fn_a(22) )"));
    LT_CHECK("it submits the lane worktree",
             lt_file_has(&e, "submit.txt", "dev land submit --worktree="));
    LT_CHECK("it logs the submission with the sequence",
             lt_file_has(&e, "state/tick.log", "submitted loop-t1 as #7"));
    LT_CHECK("it logs both gate verdicts",
             lt_file_has(&e, "state/tick.log", "gates: agent-verify rc=0 / lint rc=0"));
    LT_CHECK("it logs a LAND review",
             lt_file_has(&e, "state/tick.log", "review: VERDICT: LAND"));
    LT_CHECK("the lint-land log keeps the stderr the build wrote",
             lt_file_has(&e, "scratch/loop-t1/lintland.log", "lint-land-stderr-marker"));
    LT_CHECK("it made exactly one commit in the lane", lt_commits_ahead(&e) == 1);
    LT_CHECK("the baseline lost its first row in the commit",
             lt_file_has(&e, "lanes/loop-t1/tools/lint/cyclomatic_complexity_baseline.txt", "a.c:f2:21") &&
             !lt_file_has(&e, "lanes/loop-t1/tools/lint/cyclomatic_complexity_baseline.txt", "a.c:f1:20"));
    LT_CHECK("no HOLD file was written", !lt_exists("%s/%s", e.d, "state/loop-t1.HOLD"));
    char lane[900], msg[4096] = "";
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-t1", e.d);
    const char *const show[] = { "git", "-C", lane, "log", "-1", "--format=%B", NULL };
    (void)lt_run(show, msg, sizeof(msg), NULL);
    LT_CHECK("the commit subject has the loop shape",
             strncmp(msg, "refactor(owned): split owned.c functions under the complexity cap (loop)", 70) == 0);
    LT_CHECK("the commit ends with the writer trailer",
             strstr(msg, "\n\nCo-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>") != NULL);
    return failures;
}

static int case_scope_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "other.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "scope", &c, "run", "claude-haiku");
    LT_CHECK("the scope scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a scope violation still exits 0", rc == 0);
    LT_CHECK("it writes the HOLD naming the path",
             lt_file_has(&e, "state/loop-t1.HOLD", "out-of-scope edit: other.c"));
    LT_CHECK("it logs the HOLD", lt_file_has(&e, "state/tick.log", "HOLD loop-t1: out-of-scope edit: other.c"));
    LT_CHECK("it does not commit", lt_commits_ahead(&e) == 0);
    LT_CHECK("it does not submit", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int case_baseline_growth_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "grow", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "grow", &c, "run", "claude-haiku");
    LT_CHECK("the growth scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a growing baseline exits 0", rc == 0);
    LT_CHECK("it holds on the grown rows",
             lt_file_has(&e, "state/loop-t1.HOLD", "baseline grew: 1 new or higher row(s)"));
    LT_CHECK("it does not commit", lt_commits_ahead(&e) == 0);
    LT_CHECK("it does not submit", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

/* The regen deletes one row AND lowers another row's score. numstat used to
 * read the lowered row as one added row and held the unit as growth. */
static int case_baseline_lower_commits(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "lower", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "lower", &c, "run", "claude-haiku");
    LT_CHECK("the lowered-score scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a lowered-score baseline exits 0", rc == 0);
    LT_CHECK("it does not hold for growth", !lt_exists("%s/%s", e.d, "state/loop-t1.HOLD"));
    LT_CHECK("it commits the unit", lt_commits_ahead(&e) == 1);
    LT_CHECK("the commit keeps the lowered score and drops the removed row",
             lt_file_has(&e, "lanes/loop-t1/tools/lint/cyclomatic_complexity_baseline.txt", "a.c:f3:21") &&
             !lt_file_has(&e, "lanes/loop-t1/tools/lint/cyclomatic_complexity_baseline.txt", "a.c:f1:20"));
    char lane[900], msg[4096] = "";
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-t1", e.d);
    const char *const show[] = { "git", "-C", lane, "log", "-1", "--format=%B", NULL };
    (void)lt_run(show, msg, sizeof(msg), NULL);
    LT_CHECK("the commit records one function left the baseline",
             strstr(msg, "(lane loop-t1): 1\nfunction(s) in owned.c left the complexity baseline") != NULL);
    return failures;
}

/* A row whose score rises is growth, even though its key stays. */
static int case_baseline_rise_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "rise", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "rise", &c, "run", "claude-haiku");
    LT_CHECK("the rising-score scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a rising-score baseline exits 0", rc == 0);
    LT_CHECK("it holds on the raised row",
             lt_file_has(&e, "state/loop-t1.HOLD", "baseline grew"));
    LT_CHECK("it does not commit", lt_commits_ahead(&e) == 0);
    LT_CHECK("it does not submit", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int case_review_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: HOLD owned.c:1 bad split", "rc=0", NULL };
    const bool ready = lt_setup(&e, "review", &c, "run", "claude-haiku");
    LT_CHECK("the review scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a HOLD review exits 0", rc == 0);
    LT_CHECK("it holds with the reviewer's reason",
             lt_file_has(&e, "state/loop-t1.HOLD", "review VERDICT: HOLD owned.c:1 bad split"));
    LT_CHECK("it does not submit", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int case_gate_failure_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=1", "1" };
    const bool ready = lt_setup(&e, "gate", &c, "run", "claude-haiku");
    LT_CHECK("the gate scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a failing gate holds", lt_file_has(&e, "state/loop-t1.HOLD", "agent-verify rc=1"));
    LT_CHECK("the failing r1 rerun is what holds it",
             lt_file_has(&e, "state/loop-t1.HOLD", "the r1 rerun failed"));
    LT_CHECK("it does not submit", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int case_rerun_pass(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=1", "0" };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "rerun", &c, "run", "claude-haiku");
    LT_CHECK("the rerun scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, out, sizeof(out));
    LT_CHECK("a failed agent-verify with a passing r1 rerun exits 0", rc == 0);
    LT_CHECK("it logs the passing r1 rerun",
             lt_file_has(&e, "state/tick.log", "agent-verify rerun on r1 rc=0"));
    LT_CHECK("it writes no HOLD", !lt_exists("%s/%s", e.d, "state/loop-t1.HOLD"));
    LT_CHECK("it submits", lt_file_has(&e, "submit.txt", "dev land submit --worktree="));
    LT_CHECK("it submits with the rerun gate note",
             lt_file_has(&e, "submit.txt", "zgate agent-verify rc=1 then r1 rerun rc=0, lint rc=0"));
    return failures;
}

static int case_unsigned_refused(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "unsigned", &c, "run", "claude-haiku");
    LT_CHECK("the unsigned scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, "--allow-unsigned", "0", out, sizeof(out));
    LT_CHECK("an empty --sign-flag without --allow-unsigned 1 exits 2", rc == 2);
    LT_CHECK("it names the refusal", strstr(out, "refusing an empty --sign-flag") != NULL);
    LT_CHECK("it creates no lane", !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    return failures;
}

static int case_no_lane_actions(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    static const char *const actions[] = { "wait", "paused", "none" };
    bool ready = lt_setup(&e, "wait", &c, "wait", "claude-haiku");
    LT_CHECK("the no-lane scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    for (size_t i = 0; i < 3; i++) {
        char want[64], name[96];
        ready = lt_step_json(&e, actions[i], "claude-haiku");
        const int rc = ready ? lt_tick(&e, NULL, NULL, NULL, 0) : -1;
        (void)snprintf(want, sizeof(want), "step: %s", actions[i]);
        (void)snprintf(name, sizeof(name), "action %s exits 0 and logs the step", actions[i]);
        LT_CHECK(name, rc == 0 && lt_file_has(&e, "state/tick.log", want));
    }
    LT_CHECK("no lane was created", !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    LT_CHECK("no unit scratch was created", !lt_exists("%s/scratch/%s", e.d, "loop-t1"));
    ready = lt_step_json(&e, "run", "codex-other");
    (void)lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a non-haiku engine is skipped",
             ready && lt_file_has(&e, "state/tick.log", "skip: step chose engine 'codex-other'"));
    LT_CHECK("it created no lane either", !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    return failures;
}

static int case_lock(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char lock[900], state[900];
    const bool ready = lt_setup(&e, "lock", &c, "run", "claude-haiku");
    LT_CHECK("the lock scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)snprintf(state, sizeof(state), "%s/state", e.d);
    (void)snprintf(lock, sizeof(lock), "%s/lock", state);
    const char *const mk[] = { "mkdir", "-p", state, NULL };
    (void)lt_run(mk, NULL, 0, NULL);
    const int fd = open(lock, O_CREAT | O_RDWR, 0600);
    LT_CHECK("the test holds the lock", fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a second instance exits 0", rc == 0);
    LT_CHECK("it says another tick is running",
             lt_file_has(&e, "state/tick.log", "skip: another tick is running"));
    LT_CHECK("it did nothing else", !lt_exists("%s/lanes/%s", e.d, "loop-t1") &&
                                    !lt_exists("%s/%s", e.d, "submit.txt"));
    if (fd >= 0)
        (void)close(fd);
    return failures;
}

static int case_retire_and_held(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char main_[700], lane[900], hold_a[900], hold_b[900], out[1024];
    const bool ready = lt_setup(&e, "retire", &c, "none", "claude-haiku");
    LT_CHECK("the retire scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)snprintf(main_, sizeof(main_), "%s/main", e.d);
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-old", e.d);
    char lanes[900];
    (void)snprintf(lanes, sizeof(lanes), "%s/lanes", e.d);
    const char *const mk[] = { "mkdir", "-p", lanes, NULL };
    (void)lt_run(mk, NULL, 0, NULL);
    LT_CHECK("a landed lane worktree exists",
             lt_git(main_, "worktree", "add", "-q", "-b", "lane/loop-old", lane,
                    "origin/main", NULL));
    (void)lt_tick(&e, NULL, NULL, out, sizeof(out));
    LT_CHECK("the landed lane was passed to the retire script",
             lt_file_has(&e, "retire.txt", "lanes/loop-old"));
    LT_CHECK("it logs the retirement",
             lt_file_has(&e, "state/tick.log", "retired landed lane loop-old"));
    LT_CHECK("it deleted the lane branch",
             !lt_git(main_, "rev-parse", "--verify", "-q", "lane/loop-old", NULL));

    /* Two held lanes stop the tick before the step runs. */
    char a[900], b[900];
    (void)snprintf(a, sizeof(a), "%s/lanes/loop-a", e.d);
    (void)snprintf(b, sizeof(b), "%s/lanes/loop-b", e.d);
    (void)snprintf(hold_a, sizeof(hold_a), "%s/state/loop-a.HOLD", e.d);
    (void)snprintf(hold_b, sizeof(hold_b), "%s/state/loop-b.HOLD", e.d);
    const bool held = lt_git(main_, "worktree", "add", "-q", "-b", "lane/loop-a", a, "origin/main", NULL) &&
                      lt_git(main_, "worktree", "add", "-q", "-b", "lane/loop-b", b, "origin/main", NULL) &&
                      lt_wf(hold_a, "x\n") && lt_wf(hold_b, "y\n");
    LT_CHECK("two held lanes are staged", held);
    (void)lt_step_json(&e, "run", "claude-haiku");
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("the held-lane stop exits 0", rc == 0);
    LT_CHECK("it stops and names the held count",
             lt_file_has(&e, "state/tick.log", "stop: 2 held loop lanes need the lead"));
    LT_CHECK("it never ran the step", !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    (void)lt_tick(&e, "--max-held", "3", NULL, 0);
    LT_CHECK("a larger --max-held lets the tick proceed to the lane",
             lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    return failures;
}

/* ── finish mode: an existing committed lane through the loop's stages ── */

static bool lt_commit(const char *dir, const char *msg)
{
    return lt_git(dir, "add", "-A", NULL) &&
           lt_git(dir, "-c", "user.name=fixture", "-c", "user.email=f@example.invalid",
                  "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg, NULL);
}

/* A lane worktree "fin1" off origin/main holding one commit of the given kind:
 * ok (target edit, first baseline row deleted), scope (also other.c), grow (a
 * new row), none (target edit only), dirty (ok plus an uncommitted tracked
 * edit), two (ok plus a second commit). */
static bool lt_make_lane_for(const struct lt_env *e, const char *kind,
                             const char *name, const char *file)
{
    char main_[700], lane[700], f[900], br[128];
    (void)snprintf(main_, sizeof(main_), "%s/main", e->d);
    (void)snprintf(lane, sizeof(lane), "%s/lanes/%s", e->d, name);
    (void)snprintf(br, sizeof(br), "lane/%s", name);
    if (!lt_git(main_, "worktree", "add", "-q", "-b", br, lane, "origin/main", NULL))
        return false;
    (void)snprintf(f, sizeof(f), "%s/%s", lane, file);
    bool ok = lt_wf(f, "int owned;\nint split;\n");
    if (strcmp(kind, "scope") == 0) {
        (void)snprintf(f, sizeof(f), "%s/other.c", lane);
        ok = ok && lt_wf(f, "int other;\nint stray;\n");
    }
    if (strcmp(kind, "space") == 0) {
        (void)snprintf(f, sizeof(f), "%s/owned.c extra", lane);
        ok = ok && lt_wf(f, "int stray;\n");
    }
    if (strcmp(kind, "none") != 0) {
        (void)snprintf(f, sizeof(f), "%s/tools/lint/cyclomatic_complexity_baseline.txt", lane);
        ok = ok && lt_wf(f, strcmp(kind, "grow") == 0
                                ? "a.c:f1:20\na.c:f2:21\na.c:f3:22\na.c:f9:30\n"
                                : "a.c:f2:21\na.c:f3:22\n");
    }
    ok = ok && lt_commit(lane, "split");
    if (strcmp(kind, "two") == 0) {
        (void)snprintf(f, sizeof(f), "%s/owned.c", lane);
        ok = ok && lt_wf(f, "int owned;\nint split;\nint more;\n") && lt_commit(lane, "more");
    }
    if (strcmp(kind, "dirty") == 0) {
        (void)snprintf(f, sizeof(f), "%s/owned.c", lane);
        ok = ok && lt_wf(f, "int owned;\nint dirty;\n");
    }
    return ok;
}

static bool lt_make_lane(const struct lt_env *e, const char *kind)
{
    return lt_make_lane_for(e, kind, "fin1", "owned.c");
}

static int lt_finish_for(const struct lt_env *e, const char *name, const char *target,
                         const char *const extra[], char *out, size_t cap)
{
    char lane[800];
    (void)snprintf(lane, sizeof(lane), "%s/lanes/%s", e->d, name);
    const char *argv[16] = { "--finish", lane, "--target", target };
    size_t n = 4;
    for (size_t i = 0; extra && extra[i] && n < 14; i++)
        argv[n++] = extra[i];
    argv[n] = NULL;
    return lt_tool(e, argv, out, cap);
}

static int lt_finish(const struct lt_env *e, const char *const extra[], char *out,
                     size_t cap)
{
    return lt_finish_for(e, "fin1", "owned.c", extra, out, cap);
}

static int case_finish_submits(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "finish", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the finish scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const char *const extra[] = { "--credit", "Mac sol 6.1 low via board post 1256ab1c", NULL };
    const int rc = lt_finish(&e, extra, out, sizeof(out));
    LT_CHECK("a clean finish exits 0", rc == 0);
    LT_CHECK("the last stdout line names the lane and the sequence",
             strstr(out, "finish fin1 submitted seq=7\n") != NULL);
    LT_CHECK("tick.log gets the same line",
             lt_file_has(&e, "state/tick.log", "finish fin1 submitted seq=7"));
    LT_CHECK("it submits the adopted lane worktree",
             lt_file_has(&e, "submit.txt", "dev land submit --worktree=") &&
             lt_file_has(&e, "submit.txt", "/lanes/fin1"));
    LT_CHECK("the land note is built from data and names the credit",
             lt_file_has(&e, "submit.txt",
                 "--note=fin1: split 1 over-cap function(s) in owned.c under the complexity cap; "
                 "Mac sol 6.1 low via board post 1256ab1c; baseline only shrank; "
                 "lint-land + zgate both rc=0; read-only Haiku review LAND (z23-loop-tick --finish)."));
    LT_CHECK("it made no commit of its own", lt_ahead(&e, "fin1") == 1);
    LT_CHECK("it wrote no HOLD", !lt_exists("%s/%s", e.d, "state/fin1.HOLD"));
    LT_CHECK("it ran no engine, step or housekeeping",
             !lt_exists("%s/scratch/%s", e.d, "loop-t1") && !lt_file_has(&e, "state/tick.log", "step:"));
    return failures;
}

struct lt_hold_case {
    const char *tag, *kind, *verdict, *want;
};

static int case_finish_holds(void)
{
    static const struct lt_hold_case cases[] = {
        { "fscope", "scope", "VERDICT: LAND", "finish fin1 HOLD out-of-scope edit: other.c" },
        { "fgrow", "grow", "VERDICT: LAND", "finish fin1 HOLD baseline grew: 1 new or higher row(s)" },
        { "fnone", "none", "VERDICT: LAND", "finish fin1 HOLD no function left the baseline" },
        { "fspace", "space", "VERDICT: LAND", "finish fin1 HOLD out-of-scope edit: owned.c extra" },
        { "fdirty", "dirty", "VERDICT: LAND", "finish fin1 HOLD tracked changes in the lane" },
        { "ftwo", "two", "VERDICT: LAND", "finish fin1 HOLD expected exactly one commit ahead of origin/main, found 2" },
        { "freview", "ok", "VERDICT: HOLD owned.c:1 bad split", "finish fin1 HOLD review VERDICT: HOLD owned.c:1 bad split" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct lt_env e;
        char out[8192] = "", name[160];
        const struct lt_cfg c = { NULL, "shrink", cases[i].verdict, "rc=0", NULL };
        const bool ready = lt_setup(&e, cases[i].tag, &c, "none", "claude-haiku") &&
                           lt_make_lane(&e, cases[i].kind);
        (void)snprintf(name, sizeof(name), "the %s fixtures are written", cases[i].tag);
        LT_CHECK(name, ready);
        if (!ready) {
            failures++;
            continue;
        }
        const int rc = lt_finish(&e, NULL, out, sizeof(out));
        (void)snprintf(name, sizeof(name), "%s: exits 1 with the HOLD line", cases[i].tag);
        LT_CHECK(name, rc == 1 && strstr(out, cases[i].want) != NULL);
        (void)snprintf(name, sizeof(name), "%s: submits nothing", cases[i].tag);
        LT_CHECK(name, !lt_exists("%s/%s", e.d, "submit.txt"));
        (void)snprintf(name, sizeof(name), "%s: leaves a HOLD file", cases[i].tag);
        LT_CHECK(name, lt_exists("%s/%s", e.d, "state/fin1.HOLD"));
    }
    return failures;
}

static int case_finish_usage(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[4096] = "";
    char lane[800];
    const bool ready = lt_setup(&e, "fusage", &c, "none", "claude-haiku");
    LT_CHECK("the usage scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)snprintf(lane, sizeof(lane), "%s/lanes/fin1", e.d);
    const char *const no_target[] = { "--finish", lane, NULL };
    const char *const no_finish[] = { "--target", "owned.c", NULL };
    const char *const rel_dir[] = { "--finish", "lanes/fin1", "--target", "owned.c", NULL };
    LT_CHECK("--finish without --target exits 2", lt_tool(&e, no_target, out, sizeof(out)) == 2);
    LT_CHECK("--target without --finish exits 2", lt_tool(&e, no_finish, out, sizeof(out)) == 2);
    LT_CHECK("a relative --finish directory exits 2", lt_tool(&e, rel_dir, out, sizeof(out)) == 2);
    return failures;
}

static int case_finish_locks(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "", state[900], lock[900];
    const bool ready = lt_setup(&e, "flock", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the finish lock scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)snprintf(state, sizeof(state), "%s/state", e.d);
    const char *const mk[] = { "mkdir", "-p", state, NULL };
    (void)lt_run(mk, NULL, 0, NULL);
    (void)snprintf(lock, sizeof(lock), "%s/lock", state);
    const int tick_fd = open(lock, O_CREAT | O_RDWR, 0600);
    LT_CHECK("the test holds the hourly tick lock",
             tick_fd >= 0 && flock(tick_fd, LOCK_EX | LOCK_NB) == 0);
    (void)snprintf(lock, sizeof(lock), "%s/finish-fin1.lock", state);
    const int fin_fd = open(lock, O_CREAT | O_RDWR, 0600);
    LT_CHECK("the test holds the fin1 finish lock",
             fin_fd >= 0 && flock(fin_fd, LOCK_EX | LOCK_NB) == 0);
    int rc = lt_finish(&e, NULL, out, sizeof(out));
    LT_CHECK("a held finish lock of the same lane skips with exit 1",
             rc == 1 && strstr(out, "finish fin1 HOLD already finishing") != NULL);
    LT_CHECK("the skipped finish submitted nothing", !lt_exists("%s/%s", e.d, "submit.txt"));
    if (fin_fd >= 0)
        (void)close(fin_fd);
    rc = lt_finish(&e, NULL, out, sizeof(out));
    LT_CHECK("a held hourly-tick lock does not block a finish",
             rc == 0 && strstr(out, "finish fin1 submitted seq=7\n") != NULL);
    LT_CHECK("with no credit the note says author unknown",
             lt_file_has(&e, "submit.txt", "complexity cap; author unknown; baseline only shrank"));
    if (tick_fd >= 0)
        (void)close(tick_fd);
    return failures;
}

/* ── repairs: rebase conflict, haiku lock, whole paths, long credit ───── */

/* A second commit on origin/main that edits owned.c against the lane's own
 * edit, so the finish rebase conflicts. */
static bool lt_push_conflict(const struct lt_env *e)
{
    char main_[700], f[900];
    (void)snprintf(main_, sizeof(main_), "%s/main", e->d);
    (void)snprintf(f, sizeof(f), "%s/owned.c", main_);
    return lt_wf(f, "int owned;\nint theirs;\n") && lt_commit(main_, "theirs") &&
           lt_git(main_, "push", "-q", "origin", "main", NULL);
}

static int case_finish_rebase_conflict(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "", lane[800], gitdir[900] = "", p[1100], tracked[256] = "x";
    const bool ready = lt_setup(&e, "frebase", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok") && lt_push_conflict(&e);
    LT_CHECK("the rebase conflict fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_finish(&e, NULL, out, sizeof(out));
    LT_CHECK("a conflicting lane exits 1 with a rebase conflict HOLD",
             rc == 1 && strstr(out, "finish fin1 HOLD rebase conflict") != NULL);
    (void)snprintf(lane, sizeof(lane), "%s/lanes/fin1", e.d);
    const char *const gd[] = { "git", "-C", lane, "rev-parse", "--absolute-git-dir", NULL };
    (void)lt_run(gd, gitdir, sizeof(gitdir), NULL);
    gitdir[strcspn(gitdir, "\n")] = '\0';
    (void)snprintf(p, sizeof(p), "%s/rebase-merge", gitdir);
    LT_CHECK("no rebase-merge directory is left", *gitdir && !lt_exists("%s%s", p, ""));
    (void)snprintf(p, sizeof(p), "%s/rebase-apply", gitdir);
    LT_CHECK("no rebase-apply directory is left", *gitdir && !lt_exists("%s%s", p, ""));
    const char *const st[] = { "git", "-C", lane, "status", "--porcelain", "-uno", NULL };
    (void)lt_run(st, tracked, sizeof(tracked), NULL);
    LT_CHECK("the tracked tree is clean after the abort", tracked[0] == '\0');
    LT_CHECK("the lane is still one commit ahead", lt_ahead(&e, "fin1") == 1);
    LT_CHECK("submit was never called", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}


static int case_haiku_lock_held(void)
{
    int failures = 0;
    struct lt_env e, f;
    const struct lt_cfg ct = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const struct lt_cfg cf = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "hlocktick", &ct, "run", "claude-haiku") &&
                       lt_setup(&f, "hlockfin", &cf, "none", "claude-haiku") &&
                       lt_make_lane(&f, "ok");
    LT_CHECK("the haiku lock fixtures are written", ready);
    if (!ready)
        return failures + 1;
    LT_CHECK("the tick submits", lt_tick(&e, NULL, NULL, out, sizeof(out)) == 0);
    LT_CHECK("tick mode holds the haiku lock while the model runs",
             lt_file_has(&e, "lockstate.txt", "held"));
    LT_CHECK("the finish submits", lt_finish(&f, NULL, out, sizeof(out)) == 0);
    LT_CHECK("finish mode holds the haiku lock while the model runs",
             lt_file_has(&f, "lockstate.txt", "held"));
    return failures;
}

static int case_finish_long_credit(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "", credit[400] = "x", want[800];
    const bool ready = lt_setup(&e, "fcredit", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the long credit fixtures are written", ready);
    if (!ready)
        return failures + 1;
    /* 1 + 3*60 = 181 bytes: byte 150 falls inside the 50th euro sign */
    for (int i = 0; i < 60; i++)
        (void)strcat(credit, "\xE2\x82\xAC");
    const char *const extra[] = { "--credit", credit, NULL };
    const int rc = lt_finish(&e, extra, out, sizeof(out));
    LT_CHECK("a long credit still submits", rc == 0);
    char kept[200] = "x";
    for (int i = 0; i < 49; i++)
        (void)strcat(kept, "\xE2\x82\xAC");
    (void)snprintf(want, sizeof(want), "complexity cap; %s; baseline only shrank;", kept);
    LT_CHECK("the credit is cut on a character boundary at 148 bytes",
             lt_file_has(&e, "submit.txt", want));
    LT_CHECK("the fixed review tail survives",
             lt_file_has(&e, "submit.txt",
                         "read-only Haiku review LAND (z23-loop-tick --finish)."));
    return failures;
}

/* The byte length of the --note= value the fake dev recorded, -1 if none. */
static long lt_note_len(const struct lt_env *e)
{
    static char text[1 << 14];
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/submit.txt", e->d);
    if (!lt_slurp(p, text, sizeof(text)))
        return -1;
    const char *note = strstr(text, "--note=");
    if (!note)
        return -1;
    note += strlen("--note=");
    const char *nl = strchr(note, '\n');
    return nl ? (long)(nl - note) : (long)strlen(note);
}

/* A new file on main, committed and pushed, so a lane cut from origin/main has it. */
static bool lt_main_file(const struct lt_env *e, const char *name)
{
    char main_[700], f[1100];
    (void)snprintf(main_, sizeof(main_), "%s/main", e->d);
    (void)snprintf(f, sizeof(f), "%s/%s", main_, name);
    return lt_wf(f, "int longname;\n") && lt_commit(main_, "add the long-named file") &&
           lt_git(main_, "push", "-q", "origin", "main", NULL) &&
           lt_git(main_, "fetch", "-q", "origin", "main", NULL);
}

static int case_tick_long_pins(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192];
    const bool ready = lt_setup(&e, "tlong", &c, "run", "claude-haiku") &&
                       lt_step_doc(&e, "run", "claude-haiku", "loop:obj1:", "owned.c", 80);
    LT_CHECK("the long-pins fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, out, sizeof(out));
    const long len = lt_note_len(&e);
    LT_CHECK("a tick with a long pins list still submits", rc == 0 && len > 0);
    LT_CHECK("the tick land note stays within 500 bytes", len > 0 && len <= 500);
    LT_CHECK("the pins list is clipped, not the fixed tail",
             lt_file_has(&e, "submit.txt", "pinned_function_000(22) ") &&
             !lt_file_has(&e, "submit.txt", "pinned_function_079"));
    LT_CHECK("the fixed tail survives intact in tick mode",
             lt_file_has(&e, "submit.txt",
                         ") under the complexity cap; claude-haiku via z23-engine-unit, "
                         "baseline only shrank, zgate agent-verify+lint rc=0, "
                         "read-only Haiku review LAND.\n"));
    LT_CHECK("no HOLD for a clipped note", !lt_exists("%s/%s", e.d, "state/loop-t1.HOLD"));
    return failures;
}

static int case_tick_note_cannot_fit(void)
{
    int failures = 0;
    struct lt_env e;
    char name[300], prefix[200];
    (void)snprintf(name, sizeof(name), "%0240d.c", 0);
    memset(name, 'x', 240);
    memset(prefix, 'p', 159);
    prefix[159] = '\0';
    const struct lt_cfg c = { name, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192];
    const bool ready = lt_setup(&e, "tfit", &c, "run", "claude-haiku") &&
                       lt_main_file(&e, name) &&
                       lt_step_doc(&e, "run", "claude-haiku", prefix, name, 0);
    LT_CHECK("the unfittable tick fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)lt_tick(&e, NULL, NULL, out, sizeof(out));
    LT_CHECK("a note that cannot fit holds with a reason",
             lt_file_has(&e, "state/loop-t1.HOLD", "the land note cannot fit 500 bytes"));
    LT_CHECK("a note that cannot fit is never submitted",
             !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int case_tick_no_sequence(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192];
    const bool ready = lt_setup(&e, "tseq", &c, "run", "claude-haiku") &&
                       lt_script(&e, "dev",
                           "case \"$1\" in\n fleet) cat '%s/step.json' ;;\n"
                           " dev) echo \"$@\" > '%s/submit.txt'; echo '{\"data\":{}}' ;;\nesac",
                           e.d, e.d);
    LT_CHECK("the no-sequence tick fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)lt_tick(&e, NULL, NULL, out, sizeof(out));
    LT_CHECK("a tick submit without data.seq holds",
             lt_file_has(&e, "state/loop-t1.HOLD", "submit gave no sequence"));
    LT_CHECK("it does not log a submission as #?",
             !lt_file_has(&e, "state/tick.log", "submitted loop-t1 as #?"));
    return failures;
}

static int case_finish_note_cannot_fit(void)
{
    int failures = 0;
    struct lt_env e;
    char lane[80], target[260];
    (void)snprintf(lane, sizeof(lane), "fin-%060d", 0);
    memset(lane + 4, 'x', 60);
    memset(target, 'y', 240);
    (void)snprintf(target + 240, sizeof(target) - 240, ".c");
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=1", "0" };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "ffit", &c, "none", "claude-haiku") &&
                       lt_make_lane_for(&e, "ok", lane, target);
    LT_CHECK("the unfittable finish fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_finish_for(&e, lane, target, NULL, out, sizeof(out));
    LT_CHECK("a finish whose note cannot fit exits 1 with the reason",
             rc == 1 && strstr(out, "HOLD the land note cannot fit 500 bytes") != NULL);
    LT_CHECK("it is never submitted", !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

static int lt_count(const struct lt_env *e, const char *rel, const char *needle)
{
    static char text[1 << 16];
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/%s", e->d, rel);
    int n = 0;
    if (!lt_slurp(p, text, sizeof(text)))
        return 0;
    for (const char *s = text; (s = strstr(s, needle)) != NULL; s += strlen(needle))
        n++;
    return n;
}

/* The finisher claims the lane's changed files before the gates, renews the
 * claim while they run, and releases it after a submit and after a HOLD. */
static int case_finish_claims(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "claim", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the claim scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    struct lt_slow_worker worker;
    const bool slow_ready = lt_slow_start(&worker, &e);
    LT_CHECK("the delayed gate worker starts", slow_ready);
    if (!slow_ready)
        return failures + 1;
    const char *const extra[] = { "--claim-renew-s", "0", NULL };
    const int rc = lt_finish(&e, extra, out, sizeof(out));
    LT_CHECK("the delayed gate worker stops cleanly", lt_slow_stop(&worker));
    if (rc != 0 || strstr(out, "submitted seq=7") == NULL) {
        size_t captured = strnlen(out, sizeof(out));
        fprintf(stderr,
            "loop_tick: phase=claim_finish rc=%d captured_bytes=%zu possibly_truncated=%d\n"
            "--- claim finish output begin ---\n%.*s\n--- claim finish output end ---\n",
            rc, captured, captured >= sizeof(out) - 1, (int)captured, out);
    }
    LT_CHECK("a finish with a claim submits", rc == 0 && strstr(out, "submitted seq=7") != NULL);
    LT_CHECK("the claim names the lane and its changed files",
             lt_file_has(&e, "claims.txt", "dev agent claim --input={\"story\":\"fin1\",\"files\":[") &&
             lt_file_has(&e, "claims.txt", "\"owned.c\""));
    LT_CHECK("a claim row exists while the gates run", lt_file_has(&e, "gate_saw_claim.txt", "saw"));
    LT_CHECK("the claim is renewed while the gates wait", lt_count(&e, "claims.txt", "\"story\":\"fin1\"") >= 2);
    LT_CHECK("the claim is released after the submit",
             lt_count(&e, "claims.txt", "{\"release\":true}") == 1 &&
             !lt_exists("%s/%s", e.d, "claim.live"));
    return failures;
}

static int case_claim_released_on_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: HOLD owned.c:1 bad split", "rc=0", NULL };
    char out[8192] = "";
    const bool ready = lt_setup(&e, "claimhold", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the claim HOLD fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_finish(&e, NULL, out, sizeof(out));
    LT_CHECK("a review HOLD exits 1", rc == 1 && strstr(out, "finish fin1 HOLD review") != NULL);
    LT_CHECK("the gates ran under a claim row", lt_file_has(&e, "gate_saw_claim.txt", "saw"));
    LT_CHECK("the claim is released after the HOLD",
             lt_count(&e, "claims.txt", "{\"release\":true}") == 1 &&
             !lt_exists("%s/%s", e.d, "claim.live"));
    return failures;
}

static int case_claim_refused_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { NULL, "shrink", "VERDICT: LAND", "rc=0", NULL };
    char out[8192] = "", fail[900];
    const bool ready = lt_setup(&e, "claimno", &c, "none", "claude-haiku") &&
                       lt_make_lane(&e, "ok");
    LT_CHECK("the claim refusal fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)snprintf(fail, sizeof(fail), "%s/claim.fail", e.d);
    (void)lt_wf(fail, "");
    const int rc = lt_finish(&e, NULL, out, sizeof(out));
    LT_CHECK("a refused claim HOLDs with a named reason",
             rc == 1 && strstr(out, "finish fin1 HOLD the lane claim was refused") != NULL);
    LT_CHECK("no gate ran and nothing was submitted",
             !lt_exists("%s/%s", e.d, "gate_saw_claim.txt") && !lt_exists("%s/%s", e.d, "submit.txt"));
    LT_CHECK("a refused claim leaves nothing to release", lt_count(&e, "claims.txt", "release") == 0);
    return failures;
}

/* ── ported from the ops bridge on 10-25: precheck, duplicate guard, cards ── */

static bool lt_mkdir(const struct lt_env *e, const char *rel)
{
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/%s", e->d, rel);
    const char *const mk[] = { "mkdir", "-p", p, NULL };
    return lt_run(mk, NULL, 0, NULL);
}

static bool lt_put(const struct lt_env *e, const char *rel, const char *text)
{
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/%s", e->d, rel);
    return lt_wf(p, text);
}

/* A red precheck gets ONE engine retry fed the gate's own output; a green
 * second run submits. */
static int case_precheck_retry(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "pre1", &c, "run", "claude-haiku") &&
                       lt_put(&e, "pre.red", "1");
    LT_CHECK("the precheck retry fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a red-then-green precheck exits 0", rc == 0);
    LT_CHECK("it names the red gate and the retry",
             lt_file_has(&e, "state/tick.log", "precheck red: check-fake-gate"));
    LT_CHECK("the precheck ran on the lane directory twice",
             lt_count(&e, "pre.args", "/lanes/loop-t1") == 2);
    LT_CHECK("the engine ran a second time",
             lt_file_has(&e, "state/tick.log", "engine_unit retry rc=0"));
    LT_CHECK("the retry task carries the original task and the gate's output",
             lt_file_has(&e, "scratch/loop-t1/task2.txt", "do the unit") &&
             lt_file_has(&e, "scratch/loop-t1/task2.txt", "== check-fake-gate") &&
             lt_file_has(&e, "scratch/loop-t1/task2.txt", "gate-output-marker for check-fake-gate"));
    LT_CHECK("it logs the green precheck", lt_file_has(&e, "state/tick.log", "precheck: no new gate failures"));
    LT_CHECK("it submits", lt_file_has(&e, "submit.txt", "dev land submit --worktree="));
    LT_CHECK("it made one commit", lt_commits_ahead(&e) == 1);
    return failures;
}

/* The attempt ids on the fake engine's recorded command lines, in call order:
 * each "--attempt-id " word must be followed by exactly 64 lowercase hex and a
 * space. Returns how many ids were read (at most max), or -1 on a malformed one. */
static int lt_attempt_ids(const struct lt_env *e, char ids[][65], int max)
{
    static char text[1 << 16];
    char p[900];
    (void)snprintf(p, sizeof(p), "%s/eu_args.txt", e->d);
    if (!lt_slurp(p, text, sizeof(text)))
        return 0;
    int n = 0;
    for (const char *s = text; (s = strstr(s, "--attempt-id ")) != NULL && n < max;) {
        s += strlen("--attempt-id ");
        size_t i = 0;
        while ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))
            i++;
        if (i != 64 || s[i] != ' ')
            return -1;
        memcpy(ids[n], s, 64);
        ids[n++][64] = '\0';
    }
    return n;
}

/* Every model call leaves a receipt: the writer rounds carry --kind build,
 * --model and a fresh 64-hex --attempt-id, and the review runs through
 * engine_unit as a --kind review unit in the lane worktree, never through a
 * direct claude spawn (the tool has no claude option). The fake engine writes
 * no receipt rows, so this asserts on its argv only. */
static int case_model_call_receipts(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "rcpt", &c, "run", "claude-haiku") &&
                       lt_put(&e, "pre.red", "1");
    LT_CHECK("the receipt fixtures are written", ready);
    if (!ready)
        return failures + 1;
    LT_CHECK("a tick with a writer retry and a review submits",
             lt_tick(&e, NULL, NULL, NULL, 0) == 0 && lt_exists("%s/%s", e.d, "submit.txt"));
    LT_CHECK("every writer round is kind build and the review is kind review once",
             lt_count(&e, "eu_args.txt", "--kind build ") == 2 &&
             lt_count(&e, "eu_args.txt", "--kind review ") == 1 &&
             lt_count(&e, "eu_args.txt", "--kind ") == 3);
    LT_CHECK("every engine call names the Haiku model",
             lt_count(&e, "eu_args.txt", "--model claude-haiku-5-5 ") == 3);
    char ids[4][65];
    const int n = lt_attempt_ids(&e, ids, 4);
    LT_CHECK("three engine calls (two writer rounds, one review) each carry a 64-hex attempt id",
             n == 3);
    LT_CHECK("the attempt ids differ per call",
             n == 3 && strcmp(ids[0], ids[1]) != 0 && strcmp(ids[0], ids[2]) != 0 &&
             strcmp(ids[1], ids[2]) != 0);
    LT_CHECK("the review ran once through engine_unit as a review unit",
             lt_count(&e, "eu_args.txt", "--kind review ") == 1 &&
             lt_file_has(&e, "lockstate.txt", "held"));
    LT_CHECK("the review ran in the lane worktree",
             lt_file_has(&e, "review_wt.txt", "/lanes/loop-t1") &&
             !lt_file_has(&e, "review_wt.txt", "review-wt"));
    return failures;
}

/* Still red after the one retry: HOLD, no commit, no third precheck. */
static int case_precheck_hold(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "pre2", &c, "run", "claude-haiku") &&
                       lt_put(&e, "pre.red", "9");
    LT_CHECK("the precheck hold fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a still-red precheck exits 0", rc == 0);
    LT_CHECK("it holds after one retry",
             lt_file_has(&e, "state/loop-t1.HOLD", "precheck still red after one retry: check-fake-gate"));
    LT_CHECK("it ran the precheck exactly twice", lt_file_has(&e, "pre.count", "2"));
    LT_CHECK("it does not commit or submit",
             lt_commits_ahead(&e) == 0 && !lt_exists("%s/%s", e.d, "submit.txt"));
    return failures;
}

/* A precheck that cannot run (rc 2) holds at once: no engine retry. */
static int case_precheck_setup_error(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "pre3", &c, "run", "claude-haiku") &&
                       lt_script(&e, "precheck", "exit 2");
    LT_CHECK("the precheck setup-error fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("it holds without a retry",
             lt_file_has(&e, "state/loop-t1.HOLD", "the precheck could not run (rc=2)") &&
             !lt_file_has(&e, "state/tick.log", "engine_unit retry"));
    return failures;
}

/* The step is told to skip files an open or held lane owns; a pick of such a
 * file anyway is skipped, a pick of another file proceeds. */
static int case_duplicate_target(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    char main_[700], lane[900];
    bool ready = lt_setup(&e, "dup", &c, "run", "claude-haiku");
    (void)snprintf(main_, sizeof(main_), "%s/main", e.d);
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-old", e.d);
    ready = ready && lt_mkdir(&e, "lanes") && lt_mkdir(&e, "state") &&
            lt_mkdir(&e, "scratch/loop-old") &&
            lt_git(main_, "worktree", "add", "-q", "-b", "lane/loop-old", lane, "origin/main", NULL) &&
            lt_put(&e, "state/loop-old.HOLD", "held\n") &&
            lt_put(&e, "scratch/loop-old/step.json",
                   "{\"data\":{\"next\":{\"brief\":{\"target_file\":\"owned.c\"}}}}");
    LT_CHECK("the duplicate-target fixtures are written", ready);
    if (!ready)
        return failures + 1;
    const int rc = lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("a duplicate target exits 0", rc == 0);
    LT_CHECK("the step was asked to exclude the held lane's target",
             lt_file_has(&e, "step_args.txt", "fleet objectives step --exclude=owned.c"));
    LT_CHECK("the same target is skipped, naming the owning lane",
             lt_file_has(&e, "state/tick.log", "skip: owned.c is already owned by open lane loop-old"));
    LT_CHECK("no lane was created", !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    ready = lt_step_doc(&e, "run", "claude-haiku", "loop:obj1:", "other.c", 0);
    (void)lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("another target gets its lane", ready && lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    return failures;
}

/* No open lane: the step gets no --exclude flag. */
static int case_no_exclude_without_lanes(void)
{
    int failures = 0;
    struct lt_env e;
    const struct lt_cfg c = { "owned.c", "shrink", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(&e, "noexcl", &c, "run", "claude-haiku");
    LT_CHECK("the no-exclude fixtures are written", ready);
    if (!ready)
        return failures + 1;
    (void)lt_tick(&e, NULL, NULL, NULL, 0);
    LT_CHECK("the step ran without --exclude",
             lt_file_has(&e, "step_args.txt", "fleet objectives step") &&
             !lt_file_has(&e, "step_args.txt", "--exclude"));
    return failures;
}

/* A kind=baseline_row card step document. */
static bool lt_card_doc(const struct lt_env *e, const char *row, const char *verify)
{
    static char doc[4096];
    (void)snprintf(doc, sizeof(doc),
        "{\"data\":{\"action\":\"run\",\"reason\":\"r\","
        "\"dispatch\":{\"lane\":\"loop-t1\",\"note_prefix\":\"loop:obj2:\","
        "\"engine\":\"claude-haiku\",\"task_text\":\"do the card\"},"
        "\"next\":{\"objective\":\"baseline_hardening_banned_str\","
        "\"brief\":{\"kind\":\"baseline_row\",\"target_file\":\"owned.c\","
        "\"owned\":[\"owned.c\",\"tools/lint/card_baseline.txt\"],"
        "\"baseline\":\"tools/lint/card_baseline.txt\",\"row\":\"%s\","
        "\"recipe\":\"use snprintf\",\"verify\":\"%s\","
        "\"review_focus\":\"no banned str remains\",\"level\":\"haiku\"}}}}",
        row, verify);
    return lt_put(e, "step.json", doc);
}

/* One card tick. extra is the fake engine's extra edit (sh, run in the lane),
 * verify_fail makes the card's gate exit 1. */
static bool lt_card_tick(struct lt_env *e, const char *tag, const char *row,
                         const char *verify, const char *extra, bool verify_fail)
{
    const struct lt_cfg c = { "owned.c", "verify", "VERDICT: LAND", "rc=0", NULL };
    const bool ready = lt_setup(e, tag, &c, "run", "claude-haiku") &&
                       lt_card_doc(e, row, verify) &&
                       (!extra || lt_put(e, "eu_extra.sh", extra)) &&
                       (!verify_fail || lt_put(e, "verify.fail", ""));
    if (ready)
        (void)lt_tick(e, NULL, NULL, NULL, 0);
    return ready;
}

#define LT_CARD_LOWER "sed 's/^owned.c 3$/owned.c 2/' tools/lint/card_baseline.txt > b.new && mv b.new tools/lint/card_baseline.txt"
#define LT_CARD_VERIFY "build/bin/z23-lint check-fake-card --flag=1"

static int case_card_submits(void)
{
    int failures = 0;
    struct lt_env e;
    const bool ready = lt_card_tick(&e, "card1", "owned.c 3", LT_CARD_VERIFY, LT_CARD_LOWER, false);
    LT_CHECK("the card scenario fixtures are written", ready);
    if (!ready)
        return failures + 1;
    LT_CHECK("it logs the card's row as the pins",
             lt_file_has(&e, "state/tick.log", "run loop-t1: baseline_hardening_banned_str, owned.c, pins: row: owned.c 3"));
    LT_CHECK("the card's gate ran with its own arguments",
             lt_file_has(&e, "verify_args.txt", "check-fake-card --flag=1"));
    LT_CHECK("it did not regenerate the complexity baseline",
             lt_file_has(&e, "lanes/loop-t1/tools/lint/cyclomatic_complexity_baseline.txt", "a.c:f1:20") &&
             !lt_file_has(&e, "verify_args.txt", "--write-baseline"));
    LT_CHECK("it wrote no HOLD", !lt_exists("%s/%s", e.d, "state/loop-t1.HOLD"));
    LT_CHECK("it made one commit", lt_commits_ahead(&e) == 1);
    LT_CHECK("the land note is built from the card",
             lt_file_has(&e, "submit.txt",
                         "--note=loop:obj2: shrank the card_baseline.txt row for owned.c (owned.c 3); "
                         "claude-haiku via z23-engine-unit, card gate rc=0, baseline only shrank, "
                         "zgate agent-verify+lint rc=0, read-only Haiku review LAND."));
    char lane[900], msg[4096] = "";
    (void)snprintf(lane, sizeof(lane), "%s/lanes/loop-t1", e.d);
    const char *const show[] = { "git", "-C", lane, "log", "-1", "--format=%B", NULL };
    (void)lt_run(show, msg, sizeof(msg), NULL);
    LT_CHECK("the commit message is the card's, not the complexity text",
             strncmp(msg, "lint(owned): shrink the card_baseline.txt row for owned.c (loop)", 62) == 0 &&
             strstr(msg, "Recipe:\nuse snprintf\nRow at dispatch: owned.c 3\n") != NULL &&
             strstr(msg, "complexity") == NULL);
    LT_CHECK("the review prompt carries the recipe and the review focus",
             lt_file_has(&e, "scratch/loop-t1/review-prompt.txt", "apply this recipe to owned.c: use snprintf") &&
             lt_file_has(&e, "scratch/loop-t1/review-prompt.txt", "(1) no banned str remains") &&
             !lt_file_has(&e, "scratch/loop-t1/review-prompt.txt", "over-complexity"));
    return failures;
}

static int case_card_holds(void)
{
    int failures = 0;
    struct lt_env e;
    bool ready = lt_card_tick(&e, "card2", "owned.c 3", LT_CARD_VERIFY, NULL, false);
    LT_CHECK("a card whose row stays holds",
             ready && lt_file_has(&e, "state/loop-t1.HOLD",
                                  "the card's row is still in tools/lint/card_baseline.txt unchanged"));
    LT_CHECK("it does not commit", lt_commits_ahead(&e) == 0);
    ready = lt_card_tick(&e, "card3", "owned.c 3", LT_CARD_VERIFY,
                         "sed 's/^owned.c 3$/owned.c 4/' tools/lint/card_baseline.txt > b.new && mv b.new tools/lint/card_baseline.txt",
                         false);
    LT_CHECK("a card baseline that grows holds",
             ready && lt_file_has(&e, "state/loop-t1.HOLD",
                                  "tools/lint/card_baseline.txt grew: 1 new or higher row(s)"));
    ready = lt_card_tick(&e, "card4", "owned.c 3", LT_CARD_VERIFY, LT_CARD_LOWER, true);
    LT_CHECK("a failing card gate holds",
             ready && lt_file_has(&e, "state/loop-t1.HOLD", "card verify failed: " LT_CARD_VERIFY));
    ready = lt_card_tick(&e, "card5", "ghost.c 7", LT_CARD_VERIFY, NULL, false);
    LT_CHECK("a baseline where nothing shrank holds",
             ready && lt_file_has(&e, "state/loop-t1.HOLD",
                                  "no row of tools/lint/card_baseline.txt shrank"));
    return failures;
}

static int case_card_refused(void)
{
    int failures = 0;
    struct lt_env e;
    bool ready = lt_card_tick(&e, "card6", "owned.c 3", "rm -rf build", NULL, false);
    LT_CHECK("a verify that is not a z23-lint gate is skipped",
             ready && lt_file_has(&e, "state/tick.log", "skip: card verify 'rm -rf build' is not a z23-lint gate") &&
             !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    ready = lt_card_tick(&e, "card7", "owned.c 3", "build/bin/z23-lint check-x;touch", NULL, false);
    LT_CHECK("a verify with unexpected characters is skipped",
             ready && lt_file_has(&e, "state/tick.log", "skip: card verify has unexpected characters") &&
             !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    ready = lt_card_tick(&e, "card8", "", LT_CARD_VERIFY, NULL, false);
    LT_CHECK("a card without a row is skipped",
             ready && lt_file_has(&e, "state/tick.log", "skip: baseline_row card lacks baseline/row/recipe") &&
             !lt_exists("%s/lanes/%s", e.d, "loop-t1"));
    return failures;
}

int test_loop_tick(void)
{
    int failures = 0;
    struct stat st;
    if (stat(LT_BIN, &st) != 0) {
        printf("loop_tick: FAIL (%s is a required test prerequisite)\n", LT_BIN);
        return 1;
    }
    failures += case_run_submits();
    failures += case_scope_hold();
    failures += case_baseline_growth_hold();
    failures += case_baseline_lower_commits();
    failures += case_baseline_rise_hold();
    failures += case_review_hold();
    failures += case_gate_failure_hold();
    failures += case_rerun_pass();
    failures += case_unsigned_refused();
    failures += case_no_lane_actions();
    failures += case_lock();
    failures += case_retire_and_held();
    failures += case_finish_submits();
    failures += case_finish_holds();
    failures += case_finish_usage();
    failures += case_finish_locks();
    failures += case_finish_rebase_conflict();
    failures += case_haiku_lock_held();
    failures += case_finish_long_credit();
    failures += case_tick_long_pins();
    failures += case_tick_note_cannot_fit();
    failures += case_tick_no_sequence();
    failures += case_finish_note_cannot_fit();
    failures += case_finish_claims();
    failures += case_claim_released_on_hold();
    failures += case_claim_refused_hold();
    failures += case_precheck_retry();
    failures += case_model_call_receipts();
    failures += case_precheck_hold();
    failures += case_precheck_setup_error();
    failures += case_duplicate_target();
    failures += case_no_exclude_without_lanes();
    failures += case_card_submits();
    failures += case_card_holds();
    failures += case_card_refused();
    return failures;
}
