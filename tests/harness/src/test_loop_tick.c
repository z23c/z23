/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_loop_tick: whole ticks of build/bin/z23-loop-tick against a temp git
 * repo (a bare origin, a main checkout, a lanes directory) with every external
 * program replaced by a small generated sh fake through the tool's options:
 * z23-dev (step and land submit), z23-engine-unit, zgate, devbuild, z23-lint,
 * claude and the retire script. No real engine, gate host, model or land queue
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
 * empty --sign-flag is refused unless --allow-unsigned 1 is given. */

#include "test/test_core.h"

#include "util/spawn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
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
static const char *lt_lint_body(const char *mode)
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
               "case \"$1\" in\n fleet) cat '%s/step.json' ;;\n"
               " dev) echo \"$@\" > '%s/submit.txt'; echo '{\"data\":{\"seq\":7}}' ;;\nesac",
               e->d, e->d) &&
           lt_script(e, "eu",
               "while [ $# -gt 0 ]; do [ \"$1\" = --worktree ] && wt=$2; shift; done\n"
               "[ -n '%s' ] || exit 0\ncd \"$wt\" && echo edit >> '%s'", edit, edit) &&
           lt_script(e, "devbuild",
               "case \"$*\" in\n *lint-land*) echo lint-land-stderr-marker >&2 ;;\n"
               " *agent-verify*) exit %s ;;\nesac\nexit 0",
               c->rerun ? c->rerun : "0") &&
           lt_script(e, "lint", lt_lint_body(c->lint)) &&
           lt_script(e, "zgate",
               "l='%s'/zgate.$$.log\n"
               "case \"$*\" in *agent-verify*) r='%s' ;; *) r='rc=0' ;; esac\n"
               "echo \"$r\" > \"$l\"\necho \"log: $l\"", e->d, c->gate_rc) &&
           lt_script(e, "claude",
               "printf '%%s\\n' '{\"result\":\"reviewed\\n%s\"}'", c->verdict) &&
           lt_script(e, "retire",
               "echo \"$@\" >> '%s/retire.txt'\n"
               "git -C '%s/main' worktree remove --force \"$1\"", e->d, e->d);
}

static bool lt_step_json(const struct lt_env *e, const char *action,
                         const char *engine)
{
    char path[900], doc[2048];
    (void)snprintf(path, sizeof(path), "%s/step.json", e->d);
    (void)snprintf(doc, sizeof(doc),
        "{\"data\":{\"action\":\"%s\",\"reason\":\"fixture reason\","
        "\"dispatch\":{\"lane\":\"loop-t1\",\"note_prefix\":\"loop:obj1:\","
        "\"engine\":\"%s\",\"task_text\":\"do the unit\"},"
        "\"next\":{\"objective\":\"functions_over_complexity_cap\","
        "\"brief\":{\"target_file\":\"owned.c\","
        "\"owned\":[\"owned.c\",\"tools/lint/cyclomatic_complexity_baseline.txt\"],"
        "\"pins\":[{\"function\":\"fn_a\",\"m\":22}]}}}}",
        action, engine);
    return lt_wf(path, doc);
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

/* One tick; returns the tool's exit status, output in out. */
static int lt_tick(const struct lt_env *e, const char *extra_flag,
                   const char *extra_value, char *out, size_t cap)
{
    char a[12][700];
    const char *names[] = { "--main", "--lanes", "--state-dir", "--scratch-dir",
                            "--dev", "--engine-unit", "--zgate", "--retire-script",
                            "--devbuild", "--claude", "--lint-bin" };
    const char *rels[] = { "main", "lanes", "state", "scratch", "bin/dev", "bin/eu",
                           "bin/zgate", "bin/retire", "bin/devbuild", "bin/claude",
                           "bin/lint" };
    const char *argv[48] = { "env", "GIT_AUTHOR_NAME=fixture",
        "GIT_AUTHOR_EMAIL=f@example.invalid", "GIT_COMMITTER_NAME=fixture",
        "GIT_COMMITTER_EMAIL=f@example.invalid", LT_BIN };
    size_t n = 6;
    for (size_t i = 0; i < 11; i++) {
        (void)snprintf(a[i], sizeof(a[i]), "%s/%s", e->d, rels[i]);
        argv[n++] = names[i];
        argv[n++] = a[i];
    }
    const char *const fixed[] = { "--sign-flag", "", "--allow-unsigned", "1",
        "--poll-ms", "50", "--gate-wait-s", "10", "--step-timeout-s", "30",
        "--engine-timeout-s", "30", "--review-timeout-s", "30" };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        argv[n++] = fixed[i];
    if (extra_flag) {
        argv[n++] = extra_flag;
        argv[n++] = extra_value;
    }
    argv[n] = NULL;
    /* merged: the refusal text is on stderr, the tool's own lines on stdout */
    char scratch[8192];
    bool timed_out = false;
    return zcl_spawn_capture_merged_observed(argv, out ? out : scratch,
                                             out ? cap : sizeof(scratch),
                                             120000, &timed_out);
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
    return failures;
}
