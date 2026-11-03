/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: prove the Muse executor without a model, a build, or a
 * network. A scripted MSP host stands in for `muse serve`, a shell
 * fixture stands in for the registered runner, and a real git worktree
 * stands in for the claimed workspace: struct-API validation, the
 * receipt-only restart pre-check, verdict mapping (completed is never
 * pass by itself; verbs are lowercase closed-vocabulary), receipt shape
 * the reaper reads, and the full result contract the result row needs.
 * A's queue files (locks, outcome rows) are never touched here: claim,
 * retry, and reap belong to A's loop. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "test/muse_fake_host.h"
#include "services/muse_run.h"
#include "services/muse_run_audit.h"
#include "services/muse_run_restore.h"
#include "command/native_devagent.h"
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MR_CHECK(label, expression) do { \
    bool ok = (expression); \
    printf("muse_run: %s... %s\n", label, ok ? "OK" : "FAIL"); \
    if (!ok) ++failures; \
} while (0)

#if defined(_WIN32)
int test_devagent_muse_run(void)
{
    printf("muse_run: POSIX-only worker (fork/git)... SKIP\n");
    return 0;
}
#else

struct mr_dirs {
    char root[4096];
    char run[4096];
    char wt[4096];
};

/* Exercise the production glue with an inert adapter; never launch a host. */
static int mr_glue_calls;
static char mr_glue_model[160];
static int mr_glue_run(const struct muse_run_task *task,
    struct muse_run_result *result, char err[MUSE_RUN_ERROR_MAX])
{
    (void)snprintf(mr_glue_model, sizeof(mr_glue_model), "%s", task->model);
    (void)result;
    (void)err;
    mr_glue_calls++;
    return 1;
}
#define muse_run_task(...) mr_glue_run(__VA_ARGS__)
#define zcl_devagent_worker_muse_executor mr_glue_executor
#include "../../../tools/command/native_devagent_muse_executor.c"
#undef zcl_devagent_worker_muse_executor
#undef muse_run_task

static bool mr_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f) return false;
    ok = fwrite(text, 1, strlen(text), f) == strlen(text);
    if (fclose(f) != 0) ok = false;
    if (ok && mode) (void)chmod(path, mode);
    return ok;
}

/* Exercise the owning writer with descriptor/close faults, without a clock. */
#include "platform/file_sync.h"
#include "platform/private_file.h"
#include "services/muse_run_evidence.h"
static int mr_evidence_fault, mr_evidence_order;
static int mr_evidence_sync(int fd)
{
    mr_evidence_order = 1;
    if (mr_evidence_fault == 1) { errno = EIO; return -1; }
    return platform_file_sync(fd);
}
static int mr_evidence_close(FILE *f)
{
    int rc = fclose(f);
    if (mr_evidence_order == 1) mr_evidence_order = 2;
    if (mr_evidence_fault == 2) { errno = ENOSPC; return EOF; }
    return rc;
}
static int mr_evidence_rename(const char *src, const char *dst)
{
    mr_evidence_order = mr_evidence_order == 2 ? 3 : 99;
    return rename(src, dst);
}
static bool mr_evidence_parent(const char *parent)
{
    if (mr_evidence_order != 3 || mr_evidence_fault == 3) return false;
    mr_evidence_order = 4;
    return platform_private_parent_flush(parent);
}
#define platform_file_sync mr_evidence_sync
#define fclose mr_evidence_close
#define rename mr_evidence_rename
#define platform_private_parent_flush mr_evidence_parent
#define muse_run_write_atomic mr_evidence_write
#define muse_run_write_receipt mr_evidence_receipt
#define muse_run_write_facts mr_evidence_facts
#define muse_run_write_blocked mr_evidence_blocked
#include "../../../contexts/commons/services/src/muse_run_evidence.c"
#undef muse_run_write_blocked
#undef muse_run_write_facts
#undef muse_run_write_receipt
#undef muse_run_write_atomic
#undef platform_private_parent_flush
#undef rename
#undef fclose
#undef platform_file_sync

/* Refuse exactly the fold temporary's close after releasing the real stream. */
static FILE *mr_fold_stream;
static bool mr_fold_refuse;
static int mr_fold_closes;
static FILE *mr_fold_open(const char *path, const char *mode)
{
    FILE *f = fopen(path, mode);
    const char *leaf = strrchr(path, '/');
    if (leaf && strcmp(leaf, "/.candidate.in") == 0) mr_fold_stream = f;
    return f;
}
static int mr_fold_close(FILE *f)
{
    bool target = f == mr_fold_stream;
    int rc = fclose(f);
    if (!target) return rc;
    mr_fold_stream = NULL;
    ++mr_fold_closes;
    if (mr_fold_refuse) { mr_fold_refuse = false; errno = ENOSPC; return EOF; }
    return rc;
}
#define fopen mr_fold_open
#define fclose mr_fold_close
#define muse_candidate_fold mr_fault_candidate_fold
#define muse_restore_workspace mr_fault_restore_workspace
#include "../../../contexts/commons/services/src/muse_run_restore.c"
#undef muse_restore_workspace
#undef muse_candidate_fold
#undef fclose
#undef fopen

static int mr_failures_evidence(int fault)
{
    const char *old = "{\"verdict\":\"fail\",\"seq\":7,\"name\":\"fixture\",\"attempt\":1,"
        "\"group\":\"g\",\"turn\":\"failed\",\"reason\":\"prior\",\"engine\":\"fixture\","
        "\"tokens\":0,\"files_changed\":0,\"workspace_restored\":true,\"workspace_blocked\":false}";
    const char *next = "{\"verdict\":\"pass\",\"seq\":7,\"name\":\"fixture\",\"attempt\":1,"
        "\"group\":\"g\",\"turn\":\"completed\",\"reason\":\"complete\",\"engine\":\"fixture\","
        "\"tokens\":8,\"files_changed\":1,\"workspace_restored\":true,\"workspace_blocked\":false}";
    char dir[4096], path[8192], bytes[512] = {0};
    int failures = 0;
    (void)mr_evidence_sync; (void)mr_evidence_parent;
    if (!test_mkdtemp(dir, sizeof(dir), "muse_evidence")) return 1;
    (void)snprintf(path, sizeof(path), "%s/receipt.json", dir);
    MR_CHECK("seed complete receipt", mr_write(path, old, 0));
    printf("muse_run: evidence fault=%d\n", fault);
    mr_evidence_fault = fault;
    mr_evidence_order = 0;
    MR_CHECK("durable replacement verdict", mr_evidence_write(path, next) == (fault == 0));
    MR_CHECK("flush/close/rename/parent order", mr_evidence_order == (fault == 0 ? 4 : fault == 3 ? 3 : 2));
    FILE *f = fopen(path, "rb");
    if (f) {  TEST_DISCARD(fread(bytes, 1, sizeof(bytes) - 1, f)); (void)fclose(f); }
    MR_CHECK("exact retained or installed bytes", strcmp(bytes, fault == 1 || fault == 2 ? old : next) == 0);
    mr_evidence_fault = 0;
    MR_CHECK("remove receipt", unlink(path) == 0);
    MR_CHECK("no staging leak", rmdir(dir) == 0);
    return failures;
}

static char *mr_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n < 0 || n > 1048576) {
        fclose(f);
        return NULL;
    }
    (void)fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static bool mr_mkdir_p(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) return false;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

static bool mr_git(const char *dir, const char *arg)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("git", "git", "-C", dir, arg, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool mr_git3(const char *dir, const char *a1, const char *a2,
    const char *a3)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("git", "git", "-C", dir, a1, a2, a3, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* The recipe the lane's committed Makefile runs for the gate build. The executor
 * rebuilds the gate target from the candidate tree before running the group; the
 * default recipe builds nothing and succeeds, and the build-refusal case swaps in
 * one that fails once the turn's file exists. No compiler runs. */
static const char *const mr_make_ok = "\t@:\n";
static const char *s_mr_make_recipe = NULL;

static bool mr_makefile(const struct mr_dirs *d)
{
    char path[8192], text[1024];
    if (snprintf(path, sizeof(path), "%s/Makefile", d->wt) >=
        (int)sizeof(path))
        return false;
    if (snprintf(text, sizeof(text), ".PHONY: test_parallel\n"
            "test_parallel:\n%s",
            s_mr_make_recipe ? s_mr_make_recipe : mr_make_ok) >=
        (int)sizeof(text))
        return false;
    return mr_write(path, text, 0);
}

/* One isolated lane: run dir plus a git worktree whose build output is
 * ignored and committed, mirroring prod primed worktrees. No queue dir:
 * the executor never reads A's claim state. */
static bool mr_lane(struct mr_dirs *d)
{
    char tmp[4096];
    if (!test_mkdtemp(tmp, sizeof(tmp), "muse_run")) return false;
    if (snprintf(d->root, sizeof(d->root), "%s", tmp) >=
        (int)sizeof(d->root))
        return false;
    if (snprintf(d->run, sizeof(d->run), "%s/run", tmp) >=
        (int)sizeof(d->run))
        return false;
    if (snprintf(d->wt, sizeof(d->wt), "%s/wt", tmp) >=
        (int)sizeof(d->wt))
        return false;
    if (!mr_mkdir_p(d->run) || !mr_mkdir_p(d->wt) ||
        !mr_git(d->wt, "init"))
        return false;
    {
        char ignore[8192];
        if (snprintf(ignore, sizeof(ignore), "%s/.gitignore", d->wt) >=
            (int)sizeof(ignore))
            return false;
        return mr_write(ignore, "build/\n", 0) && mr_makefile(d) &&
            mr_git3(d->wt, "config", "user.email", "t@t.t") &&
            mr_git3(d->wt, "config", "user.name", "t") &&
            mr_git3(d->wt, "add", "-A", ".") &&
            mr_git3(d->wt, "commit", "-m", "x");
    }
}

/* One composed file in the leaf format: the queue: header rides along
 * and must be tolerated, never consulted. */
static bool mr_task_file(const struct mr_dirs *d)
{
    char path[8192], task[8192];
    if (snprintf(path, sizeof(path), "%s/task.txt", d->run) >=
        (int)sizeof(path))
        return false;
    if (snprintf(task, sizeof(task),
            "kind: muse\nseq: 7\nname: u1\nattempt: 1\ngroup: task_document\n"
            "scope: src/\nworktree: %s\nrundir: %s\nqueue: /q\nmodel: \n"
            "=== BRIEF: /b.md ===\nDo the thing.\n",
            d->wt, d->run) >= (int)sizeof(task))
        return false;
    return mr_write(path, task, 0);
}

static bool mr_gate_script(const struct mr_dirs *d, const char *verdict,
    const char *headline, const char *marker)
{
    char dir[8192], path[8192], text[2048];
    if (snprintf(dir, sizeof(dir), "%s/build/bin", d->wt) >=
        (int)sizeof(dir))
        return false;
    if (!mr_mkdir_p(dir)) return false;
    if (snprintf(path, sizeof(path), "%s/test_parallel", dir) >=
        (int)sizeof(path))
        return false;
    if (snprintf(text, sizeof(text),
            "#!/bin/sh\nprintf '%%s\\n' '%s'\nprintf '%%s\\n' '%s'\n%s\n"
            "exit 0\n",
            verdict, headline,
            marker && marker[0] ? marker : ":") >= (int)sizeof(text))
        return false;
    return mr_write(path, text, 0755);
}

static const char *mr_verdict_pass =
    "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 groups_cached=0 "
    "groups_gated=1 groups_failed=0 self_skips=0 env_unobserved=0 "
    "toolkey=abc123";
static const char *mr_head_pass = "ALL TESTS PASSED";
static const char *mr_verdict_fail =
    "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 groups_cached=0 "
    "groups_gated=1 groups_failed=1 self_skips=0 env_unobserved=0 "
    "toolkey=abc123";
static const char *mr_head_fail = "ALL TESTS FAILED";

/* spawn_fake/close_fake live in the shared header; this file forks raw
 * transports, so reference them (as function pointers: -Werror=pedantic
 * forbids function-to-object pointer conversion) to keep -Wunused-function quiet. */
typedef void (*mr_any_fn)(void);
static const mr_any_fn mr_fake_lifecycle_refs[2] = {
    (mr_any_fn)spawn_fake, (mr_any_fn)close_fake
};

static bool mr_hex40(const char *s)
{
    if (!s) return false;
    for (int i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return s[40] == '\0';
}

/* What a case does to the workspace, and the scope the run declares.
 * `writes` is the path the TURN creates (the model's own output, measured
 * by the post-run scope audit); `baseline` is pre-existing dirt laid down
 * BEFORE the turn, which the executor must refuse without spending a
 * token. NULL fields take the lane defaults. */
struct mr_edit {
    const char *scope;      /* NULL = "src/" */
    const char *writes;     /* repo-relative; NULL = the turn writes nothing */
    const char *baseline;   /* repo-relative; NULL = a clean pre-state */
};

/* One in-scope edit made by the turn: the ordinary way a run earns a
 * non-empty diff now that baseline dirt cannot. */
static const struct mr_edit mr_edit_in_scope = { NULL, "src/sum.c", NULL };
/* The same gate-passing run, but the turn writes outside the scope. */
static const struct mr_edit mr_edit_outside = { NULL, "evil.txt", NULL };
/* The prefix trick: scope "docs/" must not admit the sibling "docsevil/". */
static const struct mr_edit mr_edit_prefix = { "docs/", "docsevil/x", NULL };
/* A two-prefix scope: the fix and its test live under different roots. */
static const struct mr_edit mr_edit_multi_in = { "docs/,src/", "src/sum.c",
    NULL };
/* Neither prefix of a two-prefix scope admits the turn's path. */
static const struct mr_edit mr_edit_multi_out = { "docs/,lib/", "src/sum.c",
    NULL };
/* Baseline dirt: the workspace is already changed before the turn. */
static const struct mr_edit mr_edit_baseline = { NULL, NULL, "edit.txt" };

/* Fill the struct task the way A's loop would: ref, worker, workspace,
 * scope, gate, model, prompt, rundir, budgets. */
static bool mr_task_for(const struct mr_dirs *d, struct muse_run_task *t,
    const char *worker, const char *model, const char *scope,
    const struct muse_run_budgets *budgets)
{
    memset(t, 0, sizeof(*t));
    t->ref.seq = 7;
    if (snprintf(t->ref.name, sizeof(t->ref.name), "u1") >=
        (int)sizeof(t->ref.name))
        return false;
    t->ref.attempt = 1;
    if (snprintf(t->worker, sizeof(t->worker), "%s",
            worker ? worker : "w1") >= (int)sizeof(t->worker))
        return false;
    if (snprintf(t->workspace, sizeof(t->workspace), "%s", d->wt) >=
        (int)sizeof(t->workspace))
        return false;
    if (snprintf(t->scope, sizeof(t->scope), "%s",
            scope ? scope : "src/") >= (int)sizeof(t->scope))
        return false;
    if (snprintf(t->gate, sizeof(t->gate), "task_document") >=
        (int)sizeof(t->gate))
        return false;
    if (snprintf(t->model, sizeof(t->model), "%s", model ? model : "") >=
        (int)sizeof(t->model))
        return false;
    t->prompt = "Do the thing.\n";
    if (snprintf(t->rundir, sizeof(t->rundir), "%s", d->run) >=
        (int)sizeof(t->rundir))
        return false;
    if (budgets) {
        t->budgets = *budgets;
    } else {
        t->budgets.turn_timeout_ms = 30000;
        t->budgets.gate_timeout_ms = 60000;
    }
    return true;
}

static int mr_failures_validate(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX];
    MR_CHECK("lane", mr_lane(&d));
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    /* Null surfaces refuse without touching anything. */
    err[0] = '\0';
    MR_CHECK("null task refuses", muse_run_task(NULL, &r, err) == 1);
    err[0] = '\0';
    MR_CHECK("null result refuses", muse_run_task(&t, NULL, err) == 1);
    /* Bad worker identity refuses: it rides the result row. */
    if (snprintf(t.worker, sizeof(t.worker), "not a worker") >=
        (int)sizeof(t.worker))
        MR_CHECK("worker overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("bad worker refuses", muse_run_task(&t, &r, err) == 1);
    }
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    /* Escaping scope refuses: the turn must stay inside the workspace. */
    if (snprintf(t.scope, sizeof(t.scope), "../out") >=
        (int)sizeof(t.scope))
        MR_CHECK("scope overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("escaping scope refuses", muse_run_task(&t, &r, err) == 1);
    }
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    if (snprintf(t.workspace, sizeof(t.workspace), "/nonexistent-wt") >=
        (int)sizeof(t.workspace))
        MR_CHECK("workspace overflow", false);
    else {
        err[0] = '\0';
        MR_CHECK("missing workspace refuses",
            muse_run_task(&t, &r, err) == 1);
    }
    return failures;
}

static int mr_failures_parse(void)
{
    int failures = 0;
    struct mr_dirs d;
    char err[MUSE_RUN_ERROR_MAX];
    MR_CHECK("lane", mr_lane(&d));
    /* Unknown kind. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write bad task",
            mr_write(path, "kind: file\nseq: 1\n", 0));
        err[0] = '\0';
        MR_CHECK("bad kind refused", muse_run_task_file(path, NULL, err)
            == 1);
    }
    /* Missing headers. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write short task",
            mr_write(path, "kind: muse\nseq: 1\n", 0));
        err[0] = '\0';
        MR_CHECK("short task refused",
            muse_run_task_file(path, NULL, err) == 1);
    }
    /* Empty brief. */
    {
        char path[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        MR_CHECK("write empty brief",
            mr_write(path,
                "kind: muse\nseq: 1\nname: u1\nattempt: 1\ngroup: g\n"
                "scope: src/\nworktree: /w\nrundir: /r\nqueue: /q\nmodel: \n"
                "=== BRIEF: /b.md ===\n", 0));
        err[0] = '\0';
        MR_CHECK("empty brief refused",
            muse_run_task_file(path, NULL, err) == 1);
    }
    /* A recorded ref short-circuits through the file path too: the queue: header
     * is tolerated and no host spawns. */
    {
        char path[8192], receipt[8192];
        (void)snprintf(path, sizeof(path), "%s/task.txt", d.run);
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        MR_CHECK("write task", mr_task_file(&d));
        MR_CHECK("seed receipt",
            mr_write(receipt,
                "{\"verdict\":\"pass\",\"seq\":7,\"name\":\"u1\","
                "\"attempt\":1}\n",
                0));
        err[0] = '\0';
        MR_CHECK("file short-circuits",
            muse_run_task_file(path, NULL, err) == 0);
    }
    return failures;
}

/* Forks the scripted host and hands the transport to the core under
 * test. The core owns the session afterwards, including close/reap. */
static bool mr_fork_fake(enum fake_mode mode, int ev_read, int *to_fd,
    int *from_fd, pid_t *child)
{
    int to_child[2], from_child[2];
    pid_t pid;
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return false;
    pid = fork();
    if (pid < 0) {
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        return false;
    }
    if (pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        close(ev_read);
        (void)dup2(to_child[0], STDIN_FILENO);
        (void)dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        fake_main(mode);
        _exit(0);
    }
    close(to_child[0]);
    close(from_child[1]);
    *to_fd = to_child[1];
    *from_fd = from_child[0];
    *child = pid;
    return true;
}

/* Arms the scripted turn's own write, and lays down any baseline dirt the
 * case asked for. The write path is absolute because the fake host runs
 * with its own working directory. */
static bool mr_arm_edit(const struct mr_dirs *d, const struct mr_edit *edit)
{
    char f[8192];
    s_fake_write_path[0] = '\0';
    if (!edit) return true;
    if (edit->writes &&
        snprintf(s_fake_write_path, sizeof(s_fake_write_path), "%s/%s",
            d->wt, edit->writes) >= (int)sizeof(s_fake_write_path))
        return false;
    if (!edit->baseline) return true;
    if (snprintf(f, sizeof(f), "%s/%s", d->wt, edit->baseline) >=
        (int)sizeof(f))
        return false;
    return mr_write(f, "changed\n", 0);
}

/* Runs one execute() case over the struct boundary. Worker/model NULL
 * take the lane defaults; budgets NULL takes the case defaults; edit NULL
 * leaves the workspace untouched by both the turn and the case. */
static int mr_execute(enum fake_mode mode, struct mr_dirs *d,
    const char *gate_verdict, const char *gate_headline,
    const char *gate_marker, const struct mr_edit *edit, const char *worker,
    const char *model, const struct muse_run_budgets *budgets,
    bool claimed, struct muse_run_result *res,
    char err[MUSE_RUN_ERROR_MAX], int *rc_out, char **evidence_out)
{
    int ev[2], to_fd = -1, from_fd = -1;
    pid_t child = -1;
    int rc;
    if (pipe(ev) != 0) return -1;
    s_evidence_fd = ev[1];
    if (!mr_lane(d)) {
        close(ev[0]); close(ev[1]);
        return -1;
    }
    {
        struct muse_run_task t;
        if (!mr_task_for(d, &t, worker, model,
                edit ? edit->scope : NULL, budgets)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        t.caller_holds_claim = claimed;
        if (gate_verdict &&
            !mr_gate_script(d, gate_verdict,
                gate_headline ? gate_headline : "", gate_marker)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        if (!mr_arm_edit(d, edit)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        if (!mr_fork_fake(mode, ev[0], &to_fd, &from_fd, &child)) {
            close(ev[0]); close(ev[1]);
            return -1;
        }
        rc = muse_run_task_on_transport(&t, child, to_fd, from_fd, res,
            err);
    }
    close(ev[1]);
    s_evidence_fd = -1;
    s_fake_write_path[0] = '\0';
    *evidence_out = read_evidence(ev[0]);
    close(ev[0]);
    if (rc_out) *rc_out = rc;
    return 0;
}

static int mr_failures_precheck(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX], receipt[8192];
    int ev[2];
    pid_t child = -1;
    int to_fd = -1, from_fd = -1;
    char *evidence = NULL;
    MR_CHECK("lane", mr_lane(&d));
    MR_CHECK("task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json", d.run);
    /* A receipt with a terminal verdict short-circuits: rc 0, no turn,
     * no rewrite. No queue files exist in this lane at all. */
    MR_CHECK("seed receipt",
        mr_write(receipt,
            "{\"verdict\":\"pass\",\"seq\":7,\"name\":\"u1\","
            "\"attempt\":1}\n",
            0));
    if (pipe(ev) != 0) {
        MR_CHECK("evidence pipe", false);
        return failures + 1;
    }
    s_evidence_fd = ev[1];
    if (!mr_fork_fake(FAKE_JOURNEY, ev[0], &to_fd, &from_fd, &child)) {
        MR_CHECK("fork fake", false);
        close(ev[0]); close(ev[1]);
        return failures + 1;
    }
    memset(&r, 0, sizeof(r));
    err[0] = '\0';
    MR_CHECK("recorded ref short-circuits",
        muse_run_task_on_transport(&t, child, to_fd, from_fd, &r, err)
        == 0);
    /* The short-circuit never touches the transport: close it so the host sees EOF and exits, then reap. */
    close(to_fd);
    close(from_fd);
    {
        int status = 0;
        (void)waitpid(child, &status, 0);
    }
    close(ev[1]);
    s_evidence_fd = -1;
    evidence = read_evidence(ev[0]);
    close(ev[0]);
    MR_CHECK("no turn started",
        evidence && !strstr(evidence, "turn-cmd:"));
    MR_CHECK("verdict carried", strcmp(r.verdict, "pass") == 0);
    MR_CHECK("rc zero", r.rc == 0);
    free(evidence);
    {
        char *rtext = mr_read(receipt);
        MR_CHECK("receipt untouched", rtext &&
            strstr(rtext, "\"verdict\":\"pass\""));
        free(rtext);
    }
    return failures;
}

/* No gate runner: refused, but the turn ran and was recorded. */
static int mr_exec_no_runner(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("refused run", mr_execute(FAKE_JOURNEY, &d, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("refused rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("refused receipt", rtext &&
            strstr(rtext, "\"verdict\":\"refused\"") &&
            strstr(rtext, "\"name\":\"u1\"") &&
            strstr(rtext, "\"attempt\":1"));
        free(rtext);
    }
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("facts carry turn+tokens", ftext &&
            strstr(ftext, "\"turn\"") &&
            strstr(ftext, "\"total\":15") &&
            strstr(ftext, "\"worker\":\"w1\"") &&
            strstr(ftext, "\"model_resolved\":\"m-test\""));
        free(ftext);
    }
    {
        char turns[8192];
        char *ttext = NULL;
        (void)snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl",
            d.run);
        ttext = mr_read(turns);
        MR_CHECK("admission recorded", ttext &&
            strstr(ttext, "\"turnId\""));
        free(ttext);
    }
    MR_CHECK("scope denied foreign paths", evidence &&
        evidence_has(evidence, "decide:c-deny") &&
        evidence_count(evidence, "decide:c-deny") == 2 &&
        evidence_count(evidence, "decide:c-allow") == 0);
    free(evidence);
    return failures;
}

/* Gate passes but nothing changed: failed, never pass. The engine
 * name rides the evidence, not the verdict. */
static int mr_exec_no_change(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("no-change run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, NULL, NULL, NULL, NULL,
        false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("no-change rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("no-change verdict", rtext &&
            strstr(rtext, "\"verdict\":\"failed\""));
        free(rtext);
    }
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("no-change engine named", ftext &&
            strstr(ftext, "\"engine\":\"NO-CHANGE\""));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* Completed turn, failing gate: failed. Completed is not pass. */
static int mr_exec_failing_gate(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("fail run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_fail,
        mr_head_fail, NULL, &mr_edit_in_scope, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("fail rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("fail verdict", rtext &&
            strstr(rtext, "\"verdict\":\"failed\""));
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* The named candidate artifact the gate checks for existence. */
static int mr_pass_candidate(const struct mr_dirs *d,
    const struct muse_run_result *r)
{
    int failures = 0;
    char cf[8192];
    size_t cn = strlen(r->candidate_file);
    bool named = cn > 15 &&
        strncmp(r->candidate_file, "candidate-", 10) == 0 &&
        strcmp(r->candidate_file + cn - 5, ".diff") == 0;
    MR_CHECK("pass candidate named", named);
    (void)snprintf(cf, sizeof(cf), "%s/%s", d->run,
        r->candidate_file);
    MR_CHECK("pass candidate on disk",
        named && access(cf, F_OK) == 0);
    return failures;
}

/* The two facts a pass also rests on: the pinned commit held still, and the
 * gate's process exited normally with status 0. */
static int mr_pass_measured_facts(const char *ftext)
{
    int failures = 0;
    MR_CHECK("pass head evidence", ftext &&
        strstr(ftext, "\"measured\":true"));
    MR_CHECK("pass spawn evidence", ftext &&
        strstr(ftext, "\"spawn\":\"exit=0\"") &&
        strstr(ftext, "\"exit\":0") &&
        strstr(ftext, "\"normal\":true"));
    return failures;
}

/* The facts file a passing run leaves behind. */
static int mr_pass_facts(const struct mr_dirs *d)
{
    int failures = 0;
    char facts[8192];
    char *ftext = NULL;
    (void)snprintf(facts, sizeof(facts), "%s/muse.json", d->run);
    ftext = mr_read(facts);
    MR_CHECK("pass evidence", ftext &&
        strstr(ftext, "\"verdict\":\"pass\"") &&
        strstr(ftext, "\"candidate\":\"") &&
        strstr(ftext, "\"verdict\":\"SUITE VERDICT") &&
        strstr(ftext, "\"build\":{\"target\":\"test_parallel\","
            "\"spawn\":\"exit=0\"") &&
        strstr(ftext, "\"runner_sha3\":\"") &&
        !strstr(ftext, "\"runner_sha3\":\"none\""));
    /* The changed paths are the proof the scope was respected: a clean measured
     * pre-state and the turn's in-scope path alone in the evidence. */
    MR_CHECK("pass scope audit", ftext &&
        strstr(ftext, "\"pre_measured\":true") &&
        strstr(ftext, "\"pre_clean\":true") &&
        strstr(ftext, "\"pre_count\":0") &&
        strstr(ftext, "\"changed_measured\":true") &&
        strstr(ftext, "\"changed_count\":1") &&
        strstr(ftext, "\"changed\":[\"src/sum.c\"]") &&
        strstr(ftext, "\"outside_count\":0") &&
        strstr(ftext, "\"outside\":[]"));
    failures += mr_pass_measured_facts(ftext);
    free(ftext);
    return failures;
}

/* (b) Baseline dirt: pre-existing edits could satisfy the non-empty diff a pass
 * requires, so fail closed BEFORE the model: no session, no turn, no tokens, and
 * the offending path named in the evidence. */
static int mr_exec_baseline_dirt(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("dirt run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_baseline, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("dirt not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("dirt refused", strcmp(r.verdict, "refused") == 0);
    /* No session/start and no turn/start ever reached the host. */
    MR_CHECK("dirt spends no tokens", evidence &&
        !strstr(evidence, "turn-cmd:") &&
        !strstr(evidence, "workspace:") && r.total_tokens == 0);
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("dirt evidence", ftext &&
            strstr(ftext, "\"pre_measured\":true") &&
            strstr(ftext, "\"pre_clean\":false") &&
            strstr(ftext, "\"pre_count\":1") &&
            strstr(ftext, "\"pre\":[\"edit.txt\"]"));
        free(ftext);
    }
    MR_CHECK("dirt reason names dirt",
        strstr(r.reason, "dirty before the turn") != NULL);
    free(evidence);
    return failures;
}

/* (c) The gate passes but the turn wrote outside the declared scope; only the
 * measured output catches it. */
static int mr_exec_outside_scope(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("outside run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_outside, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("outside not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("outside failed", strcmp(r.verdict, "failed") == 0);
    MR_CHECK("outside turned", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("outside path named", ftext &&
            strstr(ftext, "\"changed_measured\":true") &&
            strstr(ftext, "\"changed\":[\"evil.txt\"]") &&
            strstr(ftext, "\"outside_count\":1") &&
            strstr(ftext, "\"outside\":[\"evil.txt\"]"));
        free(ftext);
    }
    MR_CHECK("outside reason names scope",
        strstr(r.reason, "outside scope src/") != NULL);
    free(evidence);
    return failures;
}

/* (d) The scope-prefix trick: scope "docs/" must not admit the sibling
 * "docsevil/x" just because the name starts the same way. */
static int mr_exec_scope_prefix(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("prefix run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_prefix, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("prefix not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("prefix failed", strcmp(r.verdict, "failed") == 0);
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("prefix sibling outside", ftext &&
            strstr(ftext, "\"outside_count\":1") &&
            strstr(ftext, "\"outside\":[\"docsevil/x\"]") &&
            strstr(ftext, "\"changed\":[\"docsevil/x\"]"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* (d2) A SCOPE of several prefixes: any one admits a path, a path none admits
 * is outside. The grammar refuses an empty element, an absolute or ".." element,
 * and a fifth prefix. */
static int mr_exec_scope_multi(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    const char *one[MUSE_SCOPE_MAX_PREFIXES];
    char buf[MUSE_RUN_SCOPE_MAX];
    MR_CHECK("multi grammar", muse_scope_valid("a/,tests/x.c") &&
        !muse_scope_valid("a/,") && !muse_scope_valid(",a/") &&
        !muse_scope_valid("a/,/etc") && !muse_scope_valid("a/,x/../y") &&
        !muse_scope_valid("a,b,c,d,e") && muse_scope_valid("a,b,c,d"));
    MR_CHECK("multi split", muse_scope_prefixes("a/,tests/x.c", buf,
        sizeof(buf), one) == 2 && strcmp(one[0], "a/") == 0 &&
        strcmp(one[1], "tests/x.c") == 0);
    MR_CHECK("multi admits", muse_scope_admits("tests/x.c", "a/,tests/x.c") &&
        muse_scope_admits("a/b.c", "a/,tests/x.c") &&
        !muse_scope_admits("tests/x.cc", "a/,tests/x.c") &&
        !muse_scope_admits("ab/c", "a/,tests/x.c"));
    memset(&r, 0, sizeof(r));
    MR_CHECK("multi in run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_multi_in, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("multi in passes", rc == 0 && strcmp(r.verdict, "pass") == 0);
    free(evidence);
    evidence = NULL;
    memset(&r, 0, sizeof(r));
    MR_CHECK("multi out run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_multi_out, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("multi out failed", rc == 1 &&
        strcmp(r.verdict, "failed") == 0 &&
        strstr(r.reason, "outside scope docs/,lib/") != NULL);
    free(evidence);
    return failures;
}

/* The unmeasurable-workspace fixture: a directory whose `.git` is a FILE holding
 * garbage. Git exits non-zero and stops walking up to any enclosing repository,
 * so the enumeration is unmeasurable wherever the fixture lands. */
static bool mr_unmeasurable_ws(const struct mr_dirs *d, char *out,
    size_t cap)
{
    char gitfile[8192];
    if (snprintf(out, cap, "%s/bare", d->root) >= (int)cap) return false;
    if (!mr_mkdir_p(out)) return false;
    if (snprintf(gitfile, sizeof(gitfile), "%s/.git", out) >=
        (int)sizeof(gitfile))
        return false;
    return mr_write(gitfile, "not a gitfile\n", 0);
}

/* Runs one task over a transport this case owns, so the workspace can be
 * something the shared lane helper would never build. Returns the run's
 * rc, or -1 when the harness itself could not set the case up. */
static int mr_run_on_fake(struct muse_run_task *t,
    struct muse_run_result *r, char **evidence_out)
{
    char err[MUSE_RUN_ERROR_MAX] = {0};
    int ev[2], to_fd = -1, from_fd = -1;
    pid_t child = -1;
    int rc;
    *evidence_out = NULL;
    if (pipe(ev) != 0) return -1;
    s_evidence_fd = ev[1];
    if (!mr_fork_fake(FAKE_JOURNEY, ev[0], &to_fd, &from_fd, &child)) {
        s_evidence_fd = -1;
        close(ev[0]); close(ev[1]);
        return -1;
    }
    rc = muse_run_task_on_transport(t, child, to_fd, from_fd, r, err);
    close(to_fd);
    close(from_fd);
    {
        int status = 0;
        (void)waitpid(child, &status, 0);
    }
    close(ev[1]);
    s_evidence_fd = -1;
    *evidence_out = read_evidence(ev[0]);
    close(ev[0]);
    return rc;
}

/* (e) UNMEASURABLE porcelain: the run fails closed with a reason saying the
 * measurement failed, never a clean tree or "nothing outside scope". */
static int mr_exec_unmeasurable(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char *evidence = NULL;
    char bare[8192];
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("unmeasurable lane", mr_lane(&d));
    MR_CHECK("unmeasurable workspace",
        mr_unmeasurable_ws(&d, bare, sizeof(bare)));
    MR_CHECK("unmeasurable task",
        mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    if (snprintf(t.workspace, sizeof(t.workspace), "%s", bare) >=
        (int)sizeof(t.workspace)) {
        MR_CHECK("unmeasurable workspace fit", false);
        return failures;
    }
    rc = mr_run_on_fake(&t, &r, &evidence);
    MR_CHECK("unmeasurable not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("unmeasurable refused", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("unmeasurable no turn", evidence &&
        !strstr(evidence, "turn-cmd:"));
    /* The reason must say the measurement failed, and the counts stay -1, not 0. */
    MR_CHECK("unmeasurable reason",
        strstr(r.reason, "pre-state unmeasurable") != NULL);
    MR_CHECK("unmeasurable not clean", r.scope_pre_measured == false &&
        r.scope_pre_clean == false && r.scope_pre_count == -1 &&
        r.scope_changed_count == -1 && r.scope_outside_count == -1);
    {
        char facts[8192];
        char *ftext = NULL;
        (void)snprintf(facts, sizeof(facts), "%s/muse.json", d.run);
        ftext = mr_read(facts);
        MR_CHECK("unmeasurable evidence", ftext &&
            strstr(ftext, "\"pre_measured\":false") &&
            strstr(ftext, "\"pre_count\":-1") &&
            strstr(ftext, "\"changed_measured\":false") &&
            strstr(ftext, "\"outside_count\":-1"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* (e, second half) A porcelain capture that FILLS its bound: the capture helper
 * discards the overrun yet reports git's exit status, so a full buffer looks
 * complete and must refuse rather than audit a short change set. */
static int mr_exec_unmeasurable_bound(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char *evidence = NULL;
    char name[512];
    char path[8192];
    bool wrote = true;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("bound lane", mr_lane(&d));
    /* Enough untracked rows to overrun the 256 KiB porcelain bound (~1500
     * paths of ~200 bytes), each listed because the repository root is tracked. */
    memset(name, 'q', sizeof(name));
    name[200] = '\0';
    for (int i = 0; wrote && i < 1500; i++) {
        if (snprintf(path, sizeof(path), "%s/%04d%s", d.wt, i, name) >=
            (int)sizeof(path))
            wrote = false;
        else
            wrote = mr_write(path, "x\n", 0);
    }
    MR_CHECK("bound fixture", wrote);
    MR_CHECK("bound task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    rc = mr_run_on_fake(&t, &r, &evidence);
    MR_CHECK("bound not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("bound unmeasurable", r.scope_pre_measured == false &&
        r.scope_pre_count == -1 &&
        strstr(r.reason, "pre-state unmeasurable") != NULL);
    MR_CHECK("bound no turn", evidence &&
        !strstr(evidence, "turn-cmd:"));
    free(evidence);
    return failures;
}

/* The evidence file every case reads back. */
static char *mr_read_facts(const struct mr_dirs *d, char *path, size_t cap)
{
    if (snprintf(path, cap, "%s/muse.json", d->run) >= (int)cap)
        return NULL;
    return mr_read(path);
}

/* One more file committed into the lane, to rename or delete while the pre-state reads clean. */
static bool mr_seed_committed(const struct mr_dirs *d, const char *rel,
    const char *text)
{
    char p[8192], dir[8192];
    char *slash;
    if (snprintf(p, sizeof(p), "%s/%s", d->wt, rel) >= (int)sizeof(p))
        return false;
    (void)snprintf(dir, sizeof(dir), "%s", p);
    slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (!mr_mkdir_p(dir)) return false;
    }
    return mr_write(p, text, 0) && mr_git3(d->wt, "add", "-A", ".") &&
        mr_git3(d->wt, "commit", "-m", "seed");
}

/* Installs a core.fsmonitor hook: git runs it during the index refresh of every
 * `git status`, the one deterministic point where a fixture can act BETWEEN the
 * executor's git calls. The hook exits non-zero so git rescans everything and
 * the porcelain stays true. Hook and marker live inside .git, where no porcelain
 * row can name them. `trigger`, when given, holds the hook until that
 * workspace-relative path exists (acting after the turn). */
static bool mr_fsmonitor(const struct mr_dirs *d, const char *trigger,
    const char *body)
{
    char path[8192], text[4096], guard[8192];
    guard[0] = '\0';
    if (trigger && snprintf(guard, sizeof(guard),
            "if [ ! -e \"$W/%s\" ]; then exit 1; fi", trigger) >=
        (int)sizeof(guard))
        return false;
    if (snprintf(path, sizeof(path), "%s/.git/mon.sh", d->wt) >=
        (int)sizeof(path))
        return false;
    if (snprintf(text, sizeof(text),
            "#!/bin/sh\nG=$(dirname \"$0\")\nW=\"$G/..\"\n%s\n"
            "if [ -e \"$G/fired\" ]; then exit 1; fi\n: > \"$G/fired\"\n"
            "%s\nexit 1\n", guard, body) >= (int)sizeof(text))
        return false;
    return mr_write(path, text, 0755) &&
        mr_git3(d->wt, "config", "core.fsmonitor", path);
}

/* A `git` earlier on PATH that answers only THIS workspace's `status` with rows
 * the case chose and passes every other invocation through. Real git never
 * prints a malformed row, an absolute path or a "../" path, so the parser's
 * refusals need a shim. Each group runs in its own forked process, so the PATH
 * is private to the case. */
static bool mr_git_shim(const struct mr_dirs *d, const char *rows,
    const char *trigger)
{
    char dir[8192], rowsf[8192], path[8192];
    char *text, *newpath;
    const char *orig = getenv("PATH");
    bool ok;
    if (!orig || strchr(orig, '\'')) return false;
    if (snprintf(dir, sizeof(dir), "%s/shim", d->root) >= (int)sizeof(dir))
        return false;
    if (snprintf(rowsf, sizeof(rowsf), "%s/rows.txt", d->root) >=
        (int)sizeof(rowsf))
        return false;
    if (snprintf(path, sizeof(path), "%s/git", dir) >= (int)sizeof(path))
        return false;
    if (!mr_mkdir_p(dir) || !mr_write(rowsf, rows, 0)) return false;
    text = malloc(strlen(orig) + 32768);
    newpath = malloc(strlen(orig) + sizeof(dir) + 2);
    if (!text || !newpath) {
        free(text);
        free(newpath);
        return false;
    }
    (void)sprintf(text,
        "#!/bin/sh\nPATH='%s'\nexport PATH\n"
        "if [ \"$1\" = \"-C\" ] && [ \"$2\" = '%s' ] && "
        "[ \"$3\" = \"status\" ]; then\n"
        "  if [ -e '%s/%s' ]; then cat '%s'; fi\n  exit 0\nfi\n"
        "exec git \"$@\"\n",
        orig, d->wt, d->wt, trigger ? trigger : ".git", rowsf);
    (void)sprintf(newpath, "%s:%s", dir, orig);
    ok = mr_write(path, text, 0755) && setenv("PATH", newpath, 1) == 0;
    free(text);
    free(newpath);
    return ok;
}

/* Runs one case over a workspace the case itself prepared (the shared
 * mr_execute builds its lane and runs in one step). */
static int mr_run_prepared(struct mr_dirs *d, const char *scope,
    const char *writes, const struct muse_run_budgets *b,
    struct muse_run_result *r, char **evidence_out)
{
    struct muse_run_task t;
    int rc;
    if (!mr_task_for(d, &t, NULL, NULL, scope, b)) return -1;
    s_fake_write_path[0] = '\0';
    if (writes && snprintf(s_fake_write_path, sizeof(s_fake_write_path),
            "%s/%s", d->wt, writes) >= (int)sizeof(s_fake_write_path))
        return -1;
    rc = mr_run_on_fake(&t, r, evidence_out);
    s_fake_write_path[0] = '\0';
    return rc;
}

/* (f) The model COMMITTED its work: HEAD advances and the porcelain is spotless,
 * so a tree audit measures nothing. Only the pinned pre-turn HEAD catches it, and
 * the refusal must name HEAD. */
static int mr_exec_head_moved(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char body[8192];
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("moved lane", mr_lane(&d));
    MR_CHECK("moved gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    /* A real commit carrying the SAME tree: HEAD advances, the worktree stays
     * spotless. Built with commit-tree and update-ref because `git commit`
     * would want the index lock `git status` holds. */
    (void)snprintf(body, sizeof(body),
        "T=$(git --git-dir=\"$G\" rev-parse HEAD^{tree})\n"
        "C=$(git --git-dir=\"$G\" commit-tree \"$T\" -p HEAD -m moved)\n"
        "git --git-dir=\"$G\" update-ref HEAD \"$C\"");
    MR_CHECK("moved hook", mr_fsmonitor(&d, NULL, body));
    rc = mr_run_prepared(&d, NULL, NULL, NULL, &r, &evidence);
    MR_CHECK("moved not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("moved head unmeasured", r.head_measured == false);
    MR_CHECK("moved identities differ", mr_hex40(r.base) &&
        mr_hex40(r.head_observed) &&
        strcmp(r.base, r.head_observed) != 0);
    MR_CHECK("moved reason names head",
        strstr(r.reason, "HEAD moved during the turn") != NULL);
    /* The gate never ran: a moved HEAD is settled before it is asked. */
    MR_CHECK("moved gate not consulted", r.gate_normal == false &&
        r.gate_exit == -1);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("moved evidence", ftext &&
            strstr(ftext, "\"measured\":false") &&
            strstr(ftext, "\"normal\":false") &&
            strstr(ftext, "\"exit\":-1"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* (g) The pre-turn HEAD cannot be read: the pin anchors every later
 * measurement, so the run is refused before a token is spent. */
static int mr_exec_head_unborn(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_task t;
    struct muse_run_result r;
    char *evidence = NULL;
    char ws[8192];
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("unborn lane", mr_lane(&d));
    /* A repository with no commit yet: porcelain clean, `rev-parse HEAD` names nothing. */
    MR_CHECK("unborn workspace",
        snprintf(ws, sizeof(ws), "%s/unborn", d.root) <
        (int)sizeof(ws) && mr_mkdir_p(ws) && mr_git(ws, "init"));
    MR_CHECK("unborn task", mr_task_for(&d, &t, NULL, NULL, NULL, NULL));
    MR_CHECK("unborn workspace fit",
        snprintf(t.workspace, sizeof(t.workspace), "%s", ws) <
        (int)sizeof(t.workspace));
    rc = mr_run_on_fake(&t, &r, &evidence);
    MR_CHECK("unborn not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("unborn refused", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("unborn no turn", evidence && !strstr(evidence, "turn-cmd:"));
    MR_CHECK("unborn reason names head",
        strstr(r.reason, "HEAD unreadable before the turn") != NULL);
    MR_CHECK("unborn identities unread", strcmp(r.base, "none") == 0 &&
        strcmp(r.head_observed, "none") == 0 &&
        r.head_measured == false);
    free(evidence);
    return failures;
}

/* (h) A rename moving an in-scope file OUT of scope: both halves of the row are
 * judged, since reading only the source or only the destination misses half. */
static int mr_exec_rename_out(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("rename lane", mr_lane(&d));
    MR_CHECK("rename seed", mr_seed_committed(&d, "src/a.c", "orig\n"));
    MR_CHECK("rename gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("rename hook", mr_fsmonitor(&d, "src/turn.c",
        "git --git-dir=\"$G\" --work-tree=\"$W\" mv src/a.c evil.c"));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("rename not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("rename failed", strcmp(r.verdict, "failed") == 0);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("rename both halves judged", ftext &&
            strstr(ftext, "\"changed_measured\":true") &&
            strstr(ftext, "\"src/a.c\"") &&
            strstr(ftext, "\"outside_count\":1") &&
            strstr(ftext, "\"outside\":[\"evil.c\"]"));
        free(ftext);
    }
    MR_CHECK("rename reason names scope",
        strstr(r.reason, "outside scope src/") != NULL);
    free(evidence);
    return failures;
}

/* (i) A DELETE outside the declared scope is judged like any other path. */
static int mr_exec_delete_outside(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("delete lane", mr_lane(&d));
    MR_CHECK("delete seed", mr_seed_committed(&d, "outside.txt", "o\n"));
    MR_CHECK("delete gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("delete hook", mr_fsmonitor(&d, "src/turn.c",
        "rm -f \"$W/outside.txt\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("delete not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("delete failed", strcmp(r.verdict, "failed") == 0);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("delete path named", ftext &&
            strstr(ftext, "\"changed_measured\":true") &&
            strstr(ftext, "\"outside_count\":1") &&
            strstr(ftext, "\"outside\":[\"outside.txt\"]"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* One shim-fed case: the audited porcelain is exactly `rows`. `unmeasurable`
 * says whether the pass refuses as unmeasurable or the rows are readable but
 * out of scope. `why` is the EXACT reason the refusal must name. */
static int mr_rows_case(const char *label, const char *rows,
    bool unmeasurable, const char *why, const char *outside_json)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char facts[8192];
    char *ftext = NULL;
    char *saved_path = NULL;
    const char *orig = getenv("PATH");
    int rc = -1;
    memset(&r, 0, sizeof(r));
    printf("muse_run: rows case %s\n", label);
    saved_path = orig ? strdup(orig) : NULL;
    MR_CHECK("rows lane", mr_lane(&d));
    MR_CHECK("rows gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("rows shim", saved_path && mr_git_shim(&d, rows,
        "src/turn.c"));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    /* The shim is removed with the case that needed it. */
    if (saved_path) (void)setenv("PATH", saved_path, 1);
    free(saved_path);
    /* The gate script prints a PASSING verdict, so proving the refusal proves the audit refused. */
    MR_CHECK("rows not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    if (unmeasurable) {
        MR_CHECK("rows unmeasurable",
            r.scope_changed_measured == false &&
            r.scope_changed_count == -1 && r.scope_outside_count == -1 &&
            strstr(r.reason, "change set unmeasurable") != NULL);
        MR_CHECK("rows name the breakage",
            why && strstr(r.reason, why) != NULL);
    } else {
        MR_CHECK("rows outside", r.scope_changed_measured &&
            strcmp(r.verdict, "failed") == 0 &&
            strstr(r.reason, "outside scope") != NULL);
        ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("rows outside named", ftext && outside_json &&
            strstr(ftext, outside_json));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* (j) Rows the parser MUST NOT read: each is a refusal, never one lucky path. */
static int mr_exec_rows_malformed(void)
{
    int failures = 0;
    /* A status pair porcelain cannot print. */
    failures += mr_rows_case("bad status pair", "XY src/turn.c\n",
        true, "a status column that is not a porcelain v1 character", NULL);
    /* Two legal status characters but no separator space: a blind
     * three-character skip would have invented the path "rc/turn.c". */
    failures += mr_rows_case("no fixed separator", "MMsrc/turn.c\n",
        true, "no separating space after the two status columns", NULL);
    /* Unmodified in both columns, which this seam never prints. */
    failures += mr_rows_case("two blank columns", "   src/turn.c\n",
        true, "both status columns blank, which this seam never prints",
        NULL);
    /* A rename separator on a status that cannot carry one. */
    failures += mr_rows_case("arrow without rename",
        "M  src/turn.c -> src/other.c\n", true,
        "a \" -> \" separator on a status that never carries one", NULL);
    /* Shorter than the fixed prefix plus one path byte: the parser's first, independent check. */
    failures += mr_rows_case("row too short", "M\n", true,
        "a row too short to carry a status prefix and a path", NULL);
    /* '?' and '!' are only ever printed DOUBLED; one beside an ordinary status
     * byte passes the column and separator tests, so only the doubling rule
     * catches it, and each has its own rule. */
    failures += mr_rows_case("half untracked", "?M src/turn.c\n", true,
        "'?' in one status column only, never doubled", NULL);
    failures += mr_rows_case("half ignored", "!M src/turn.c\n", true,
        "'!' in one status column only, never doubled", NULL);
    /* C-quoting that does not parse (unterminated quote, unknown escape): no
     * best-effort path is claimed as measured. */
    failures += mr_rows_case("unterminated quote", "?? \"src/turn.c\n",
        true, "malformed quoting on a row's path", NULL);
    failures += mr_rows_case("bad escape", "?? \"src/\\qturn.c\"\n",
        true, "malformed quoting on a row's path", NULL);
    return failures;
}

/* (k) An R row that names only one path: the half the parser never saw is a
 * path it never judged, so it refuses. */
static int mr_exec_rows_rename_bare(void)
{
    return mr_rows_case("rename without separator", "R  src/turn.c\n",
        true, "a rename or copy row with no \" -> \" separator", NULL);
}

/* (l) An absolute path and a "../" path are outside the declared scope whatever
 * prefix they share with it. Real git never prints either, so the rows are handed in. */
static int mr_exec_rows_escaping_paths(void)
{
    int failures = 0;
    failures += mr_rows_case("absolute path", "?? /etc/passwd\n", false,
        NULL, "\"outside\":[\"/etc/passwd\"]");
    failures += mr_rows_case("dot dot path", "?? src/../../evil\n", false,
        NULL, "\"outside\":[\"src/../../evil\"]");
    return failures;
}

/* (m) The gate runner EXITS NON-ZERO while its captured log carries a passing
 * SUITE VERDICT line: the log is debris, not evidence, and the spawn status decides. */
static int mr_exec_gate_exit_nonzero(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("gate-exit run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, "exit 7", &mr_edit_in_scope, NULL,
        NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("gate-exit not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("gate-exit refused", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("gate-exit status carried", r.gate_normal == false &&
        r.gate_exit == 7);
    MR_CHECK("gate-exit reason names outcome",
        strstr(r.reason, "exit=7") != NULL);
    /* The passing line was captured and still did not decide anything. */
    MR_CHECK("gate-exit verdict line unread", r.gate_present == false &&
        r.gate_ran == -1 && r.gate_failed == -1);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("gate-exit evidence", ftext &&
            strstr(ftext, "\"spawn\":\"exit=7\"") &&
            strstr(ftext, "\"normal\":false"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* (m2) The candidate does not build while the prebuilt runner would still print
 * a passing verdict: the gate target is rebuilt from the candidate first, a
 * failed build refuses by name and the stale runner is never consulted. */
static int mr_exec_gate_build_fails(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    s_mr_make_recipe = "\t@echo 'make: warning: resetting jobserver mode' >&2\n"
        "\t@test ! -e src/sum.c || "
        "{ echo 'make: fixture preparation' >&2; "
        "echo 'src/sum.c:1: error: expected declaration' >&2; exit 2; }\n";
    MR_CHECK("build-fail run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, &mr_edit_in_scope, NULL,
        NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    s_mr_make_recipe = NULL;
    MR_CHECK("build-fail not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("build-fail refused", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("build-fail reason names the build",
        strstr(r.reason, "gate build failed: test_parallel exit=2") != NULL);
    /* The compiler's line goes to STDERR; the reason must quote it. */
    MR_CHECK("build-fail reason quotes the build's own stderr",
        strstr(r.reason, "error: expected declaration") != NULL);
    MR_CHECK("build-fail spawn named",
        strcmp(r.gate_spawn, "build exit=2") == 0 && r.gate_exit == 2);
    /* The stale runner printed a passing line and was never asked. */
    MR_CHECK("build-fail runner unconsulted", r.gate_normal == false &&
        r.gate_present == false && r.gate_ran == -1 &&
        r.gate_failed == -1);
    free(evidence);
    return failures;
}

/* One build-outcome case: the gate build runs `recipe` while the prebuilt runner
 * would print a passing verdict. Whatever the build did, the run is refused by
 * name, the runner is never consulted and no runner identity is published. */
static int mr_exec_build_refused(const char *label, const char *recipe,
    int gate_ms, const char *named)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 30000;
    b.gate_timeout_ms = gate_ms;
    s_mr_make_recipe = recipe;
    MR_CHECK(label, mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_in_scope, NULL, NULL, &b, false, &r,
        err, &rc, &evidence) == 0);
    s_mr_make_recipe = NULL;
    MR_CHECK(label, rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    MR_CHECK(label, strstr(r.reason, "gate build failed: test_parallel") &&
        strstr(r.reason, named) && strstr(r.build_spawn, named));
    MR_CHECK(label, r.gate_normal == false && r.gate_present == false &&
        r.gate_ran == -1 && strcmp(r.gate_runner, "none") == 0);
    free(evidence);
    return failures;
}

/* (m3) A build that overruns the gate deadline and (m4) a build whose make is
 * killed by a signal are named non-passes like a compile error. */
static int mr_exec_gate_build_outcomes(void)
{
    int failures = 0;
    failures += mr_exec_build_refused("build-timeout", "\t@sleep 30\n",
        400, "timeout");
    failures += mr_exec_build_refused("build-killed",
        "\t@kill -9 $$PPID; sleep 5\n", 60000, "exit=137");
    return failures;
}

/* (m5) The build REPLACES the runner: the prebuilt one says pass, the rebuilt
 * one says the group failed. The gate judges the rebuilt bytes, and the
 * evidence names them. */
static int mr_exec_gate_rebuilt_runner(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    s_mr_make_recipe = "\t@printf '#!/bin/sh\\necho \"%s\"\\n' "
        "'SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
        "groups_cached=0 groups_gated=1 groups_failed=1 self_skips=0 "
        "env_unobserved=0 toolkey=abc123' > build/bin/test_parallel\n";
    MR_CHECK("rebuilt run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_in_scope, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    s_mr_make_recipe = NULL;
    MR_CHECK("rebuilt runner judged", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "failed") == 0 && r.gate_normal &&
        r.gate_failed == 1);
    MR_CHECK("rebuilt build named", strcmp(r.build_spawn, "exit=0") == 0 &&
        r.build_ms >= 0 && strlen(r.gate_runner) == 64);
    free(evidence);
    return failures;
}

/* (n) The gate runner overruns its deadline with passing-looking output already
 * piped. A killed process proves nothing about the suite, so the deadline is a
 * named refusal of its own. */
static int mr_exec_gate_timeout(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 30000;
    b.gate_timeout_ms = 400;
    MR_CHECK("gate-timeout run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, "sleep 30", &mr_edit_in_scope,
        NULL, NULL, &b, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("gate-timeout not pass", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "pass") != 0);
    MR_CHECK("gate-timeout refused", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("gate-timeout named", r.gate_normal == false &&
        strstr(r.reason, "timeout") != NULL);
    MR_CHECK("gate-timeout verdict line unread", r.gate_present == false);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("gate-timeout evidence", ftext &&
            strstr(ftext, "\"spawn\":\"timeout\"") &&
            strstr(ftext, "\"normal\":false"));
        free(ftext);
    }
    free(evidence);
    return failures;
}

/* The pass binds the rebuilt runner's bytes beside the candidate. */
static int mr_pass_build(const struct muse_run_result *r)
{
    int failures = 0;
    MR_CHECK("pass build bound", strcmp(r->build_spawn, "exit=0") == 0 &&
        r->build_ms >= 0 && strlen(r->gate_runner) == 64 &&
        strspn(r->gate_runner, "0123456789abcdef") == 64);
    return failures;
}

/* Passing gate plus a real diff: pass, rc 0, full contract. */
static int mr_exec_pass(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("pass run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_in_scope, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("pass rc", rc == 0 && r.rc == 0);
    MR_CHECK("pass verdict", strcmp(r.verdict, "pass") == 0);
    MR_CHECK("pass terminal", strcmp(r.terminal, "completed") == 0);
    MR_CHECK("pass identity", mr_hex40(r.base) &&
        mr_hex40(r.candidate) && r.session[0] &&
        r.turn[0] && r.turn_command[0]);
    MR_CHECK("pass gate token",
        strcmp(r.gate_evidence, "task_document:1/0") == 0 &&
        r.gate_present && r.gate_ran == 1 && r.gate_failed == 0);
    /* Facts a pass rests on: the pinned commit held still, the gate exited normally. */
    MR_CHECK("pass head pinned", r.head_measured &&
        mr_hex40(r.head_observed) &&
        strcmp(r.base, r.head_observed) == 0);
    MR_CHECK("pass gate exited normally", r.gate_normal &&
        r.gate_exit == 0 && strcmp(r.gate_spawn, "exit=0") == 0);
    failures += mr_pass_build(&r);
    failures += mr_pass_candidate(&d, &r);
    MR_CHECK("pass tokens", r.total_tokens == 15 &&
        r.input_tokens == 10 && r.output_tokens == 5);
    failures += mr_pass_facts(&d);
    free(evidence);
    return failures;
}

/* Cancelled turn: cancelled without running the gate at all. */
static int mr_exec_cancelled(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("cancelled run", mr_execute(FAKE_CANCELLED, &d,
        mr_verdict_pass, mr_head_pass,
        "touch \"$0.marker\"", &mr_edit_in_scope, NULL, NULL, NULL,
        false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("cancelled rc", rc == 1 && r.rc == 1);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("cancelled verdict", rtext &&
            strstr(rtext, "\"verdict\":\"cancelled\""));
        free(rtext);
    }
    {
        char marker[8192];
        (void)snprintf(marker, sizeof(marker),
            "%s/build/bin/test_parallel.marker", d.wt);
        MR_CHECK("gate never ran", access(marker, F_OK) != 0);
    }
    free(evidence);
    return failures;
}

/* Unknown host notification mid-turn: ignored, the turn completes. */
static int mr_exec_unknown_frame(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("unknown frame run", mr_execute(FAKE_UNKNOWN, &d,
        mr_verdict_pass, mr_head_pass, NULL, &mr_edit_in_scope, NULL,
        NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("unknown frame pass", rc == 0 && r.rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    free(evidence);
    return failures;
}

/* Malformed frame mid-turn: fail closed, refused, gate never runs. */
static int mr_exec_garbage(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("garbage run", mr_execute(FAKE_GARBAGE, &d, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("garbage refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    {
        char receipt[8192];
        char *rtext = NULL;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
            d.run);
        rtext = mr_read(receipt);
        MR_CHECK("garbage receipt", rtext &&
            strstr(rtext, "\"verdict\":\"refused\""));
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* Host exits mid-turn with no terminal: refused, never pass. */
static int mr_exec_host_exit(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("host-exit run", mr_execute(FAKE_EXIT, &d, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("host-exit refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    /* The fake host _exit(0)s after accepting the turn; the reason must name that exit. */
    MR_CHECK("host-exit names the child status",
        strstr(r.reason, "serve stdout closed, child exit 0") != NULL);
    free(evidence);
    return failures;
}

/* Host abort()s after accept: the parent records the signal; a cgroup whose
 * memory.events max did not move is not called a memory.max charge failure. */
static int mr_exec_host_abort(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("host-abort run", mr_execute(FAKE_ABORT, &d, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("host-abort refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    {
        char expect[80];
        (void)snprintf(expect, sizeof(expect),
            "serve stdout closed, child signal %d", SIGABRT);
        MR_CHECK("host-abort names the signal",
            strstr(r.reason, expect) != NULL);
    }
    MR_CHECK("host-abort is not a memory.max charge without the counter",
        strstr(r.reason, "memory.max charge failed") == NULL);
    free(evidence);
    return failures;
}

static int mr_write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    size_t n;
    ssize_t w;
    if (fd < 0) return -1;
    n = strlen(text);
    w = write(fd, text, n);
    if (close(fd) != 0) return -1;
    return w == (ssize_t)n ? 0 : -1;
}

/* This process's cgroup v2 path under the unified mount ("/a/b"), or -1
 * when /proc/self/cgroup has no whole unified entry. */
static int mr_self_cgroup(char *rel, size_t cap)
{
    char line[4096];
    FILE *f = fopen("/proc/self/cgroup", "r");
    rel[0] = '\0';
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (strncmp(line, "0::", 3) != 0)
            continue;
        if (nl)
            *nl = '\0';
        if (!nl || snprintf(rel, cap, "%s", line + 3) >= (int)cap)
            rel[0] = '\0';
        break;
    }
    fclose(f);
    return rel[0] == '/' ? 0 : -1;
}

static int mr_delegates_memory(const char *cg)
{
    char stpath[1100], st[256];
    FILE *sf;
    int delegated = 0;
    if (snprintf(stpath, sizeof(stpath), "%s/cgroup.subtree_control", cg) >=
        (int)sizeof(stpath))
        return 0;
    sf = fopen(stpath, "r");
    if (!sf)
        return 0;
    if (fgets(st, sizeof(st), sf) && strstr(st, "memory"))
        delegated = 1;
    fclose(sf);
    return delegated;
}

/* What the memory.max leg found. ARMED: a child cgroup exists for the session.
 * UNOBSERVED: no ancestor both delegates memory and lets this uid create a
 * child. BROKEN: an ancestor refused for any other reason. */
enum { MR_MEMCG_BROKEN = -1, MR_MEMCG_ARMED = 0, MR_MEMCG_UNOBSERVED = 1 };

/* Where the walk looks and how it creates a child: the unified mount and
 * mkdir(2), or a fixture tree and a scripted mkdir. */
struct mr_memcg_walk {
    const char *mount;
    int (*make)(const char *path, mode_t mode);
    int pid;
    char *dir;
    size_t cap;
    char *why;
    size_t why_cap;
};

/* 0 armed, else the errno the child's creation failed with. */
static int mr_arm_child_cgroup(const struct mr_memcg_walk *w, const char *cg)
{
    char p[1100];
    if (snprintf(w->dir, w->cap, "%s/z23-memmax-%d", cg, w->pid) >=
        (int)w->cap)
        return ENAMETOOLONG;
    errno = 0;
    if (w->make(w->dir, 0755) != 0)
        return errno != 0 ? errno : EIO;
    if (snprintf(p, sizeof(p), "%s/memory.oom.group", w->dir) < (int)sizeof(p))
        (void)mr_write_text(p, "0\n");
    if (snprintf(p, sizeof(p), "%s/memory.swap.max", w->dir) < (int)sizeof(p))
        (void)mr_write_text(p, "0\n");
    return 0;
}

/* Step to the parent cgroup; false once the mount root was examined. */
static bool mr_cgroup_parent(char *cg, size_t floor)
{
    char *slash;
    if (strlen(cg) <= floor)
        return false;
    slash = strrchr(cg, '/');
    if (!slash || (size_t)(slash - cg) < floor)
        return false;
    *slash = '\0';
    return true;
}

struct mr_memcg_tally {
    int denied;
    int broken;
    char where[1100];
};

static int mr_memcg_verdict(const struct mr_memcg_walk *w, const char *self,
                            const struct mr_memcg_tally *t)
{
    if (t->broken != 0) {
        (void)snprintf(w->why, w->why_cap,
            "creating a child of memory-delegating %s failed: %s",
            t->where, strerror(t->broken));
        return MR_MEMCG_BROKEN;
    }
    (void)snprintf(w->why, w->why_cap,
        "cgroup %s has no memory-delegating ancestor this uid may create "
        "a child under (%d refused with a permission error); run it in a "
        "user-manager scope, e.g. under devbuild's development.slice",
        self, t->denied);
    return MR_MEMCG_UNOBSERVED;
}

/* Walk from `self` up to the mount root and arm a child under the nearest
 * ancestor that delegates memory and accepts one; every level is examined. */
static int mr_memcg_walk_run(const struct mr_memcg_walk *w, const char *self)
{
    char cg[1024];
    struct mr_memcg_tally t = {0};
    size_t floor = strlen(w->mount);
    if (snprintf(cg, sizeof(cg), "%s%s", w->mount, self) >= (int)sizeof(cg)) {
        (void)snprintf(w->why, w->why_cap, "cgroup path does not fit: %s",
                       self);
        return MR_MEMCG_BROKEN;
    }
    while (strlen(cg) > floor && cg[strlen(cg) - 1] == '/')
        cg[strlen(cg) - 1] = '\0';
    do {
        int e;
        if (!mr_delegates_memory(cg))
            continue;
        e = mr_arm_child_cgroup(w, cg);
        if (e == 0)
            return MR_MEMCG_ARMED;
        if (e == EACCES || e == EPERM || e == EROFS) {
            t.denied++;
        } else if (t.broken == 0) {
            t.broken = e;
            (void)snprintf(t.where, sizeof(t.where), "%s", cg);
        }
    } while (mr_cgroup_parent(cg, floor));
    return mr_memcg_verdict(w, self, &t);
}

/* The session under test joins the armed child cgroup. */
static int mr_memory_cgroup_open(char *dir, size_t cap, char *why,
                                 size_t why_cap)
{
    char self[1024];
    struct mr_memcg_walk w = {
        .mount = "/sys/fs/cgroup", .make = mkdir, .pid = (int)getpid(),
        .dir = dir, .cap = cap, .why = why, .why_cap = why_cap,
    };
    dir[0] = '\0';
    if (mr_self_cgroup(self, sizeof(self)) != 0) {
        (void)snprintf(why, why_cap,
                       "/proc/self/cgroup has no cgroup v2 unified entry");
        return MR_MEMCG_UNOBSERVED;
    }
    return mr_memcg_walk_run(&w, self);
}

static void mr_memory_cgroup_close(const char *dir)
{
    char line[512], rel[1024], self[1100], procs[1100];
    FILE *f;
    if (!dir || dir[0] == '\0') return;
    self[0] = '\0';
    if (mr_self_cgroup(rel, sizeof(rel)) == 0 &&
        snprintf(self, sizeof(self), "/sys/fs/cgroup%s/cgroup.procs", rel) >=
            (int)sizeof(self))
        self[0] = '\0';
    if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", dir) >=
        (int)sizeof(procs)) {
        (void)rmdir(dir);
        return;
    }
    f = fopen(procs, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (self[0] != '\0')
                (void)mr_write_text(self, line);
        }
        fclose(f);
    }
    (void)rmdir(dir);
}

/* ── The walk against a fixture tree shaped like a real hierarchy.
 * A scripted mkdir stands in for the delegation rule: only inside
 * user@1000.service may this uid create a child. */
static int g_mr_fake_mkdir_errno;

static int mr_fake_mkdir(const char *path, mode_t mode)
{
    if (g_mr_fake_mkdir_errno != 0) {
        errno = g_mr_fake_mkdir_errno;
        return -1;
    }
    if (!strstr(path, "/user@1000.service/")) {
        errno = EACCES;
        return -1;
    }
    return mkdir(path, mode);
}

#define MR_FX_USER "/user.slice/user-1000.slice"
#define MR_FX_DEV MR_FX_USER "/user@1000.service/development.slice"
#define MR_FX_SESSION MR_FX_USER "/session-52.scope"
#define MR_FX_SCOPE MR_FX_DEV "/run-u1.scope"
#define MR_FX_DEEP MR_FX_SCOPE "/a/b/c/d/e/f/g/h/i"

static bool mr_memcg_fixture(const char *mount)
{
    static const struct { const char *rel; const char *ctl; } rows[] = {
        {"", "cpu io memory pids\n"},
        {"/user.slice", "cpu memory pids\n"},
        {MR_FX_USER, "cpu memory pids\n"},
        {MR_FX_SESSION, "\n"},
        {MR_FX_USER "/user@1000.service", "cpu memory pids\n"},
        {MR_FX_DEV, "cpu memory pids\n"},
        {MR_FX_SCOPE, "\n"},
        {MR_FX_DEEP, "\n"},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char dir[1024], ctl[1100];
        if (snprintf(dir, sizeof(dir), "%s%s", mount, rows[i].rel) >=
                (int)sizeof(dir) ||
            snprintf(ctl, sizeof(ctl), "%s/cgroup.subtree_control", dir) >=
                (int)sizeof(ctl) ||
            !mr_mkdir_p(dir) || !mr_write(ctl, rows[i].ctl, 0))
            return false;
    }
    return true;
}

static int mr_memcg_walk_case(const char *mount, const char *self,
                              int fake_errno, char *dir, size_t cap,
                              char *why, size_t why_cap)
{
    struct mr_memcg_walk w = {
        .mount = mount, .make = mr_fake_mkdir, .pid = 4242,
        .dir = dir, .cap = cap, .why = why, .why_cap = why_cap,
    };
    g_mr_fake_mkdir_errno = fake_errno;
    dir[0] = '\0';
    why[0] = '\0';
    return mr_memcg_walk_run(&w, self);
}

static bool mr_memcg_armed_under_dev(const char *mount, const char *dir)
{
    char want[1100];
    struct stat st;
    return snprintf(want, sizeof(want), "%s%s/z23-memmax-4242", mount,
                    MR_FX_DEV) < (int)sizeof(want) &&
        strcmp(dir, want) == 0 && stat(dir, &st) == 0 && S_ISDIR(st.st_mode) &&
        rmdir(dir) == 0;
}

/* From a login session scope every memory-delegating ancestor is root-owned:
 * UNOBSERVED, not a failed delegated cgroup. Inside the user manager the walk
 * arms at the nearest delegating ancestor at any depth, and a non-permission
 * refusal stays a failure. */
static int mr_exec_memcg_walk(void)
{
    int failures = 0;
    char root[512], mount[600], dir[1100], why[512];
    if (!test_mkdtemp(root, sizeof(root), "muse_memcg") ||
        snprintf(mount, sizeof(mount), "%s/cg", root) >= (int)sizeof(mount) ||
        !mr_memcg_fixture(mount)) {
        MR_CHECK("memcg fixture", false);
        return 1;
    }
    MR_CHECK("memcg session scope is unobserved",
        mr_memcg_walk_case(mount, MR_FX_SESSION, 0, dir, sizeof(dir), why,
                           sizeof(why)) == MR_MEMCG_UNOBSERVED &&
        strstr(why, "session-52.scope") && strstr(why, "3 refused"));
    MR_CHECK("memcg user scope arms under development.slice",
        mr_memcg_walk_case(mount, MR_FX_SCOPE, 0, dir, sizeof(dir), why,
                           sizeof(why)) == MR_MEMCG_ARMED &&
        mr_memcg_armed_under_dev(mount, dir));
    MR_CHECK("memcg deep caller still reaches its delegating ancestor",
        mr_memcg_walk_case(mount, MR_FX_DEEP, 0, dir, sizeof(dir), why,
                           sizeof(why)) == MR_MEMCG_ARMED &&
        mr_memcg_armed_under_dev(mount, dir));
    MR_CHECK("memcg non-permission refusal is a failure",
        mr_memcg_walk_case(mount, MR_FX_SCOPE, EEXIST, dir, sizeof(dir), why,
                           sizeof(why)) == MR_MEMCG_BROKEN &&
        strstr(why, "development.slice") && strstr(why, strerror(EEXIST)));
    MR_CHECK("memcg permission-only refusal is unobserved",
        mr_memcg_walk_case(mount, MR_FX_SCOPE, EACCES, dir, sizeof(dir), why,
                           sizeof(why)) == MR_MEMCG_UNOBSERVED);
    test_rm_rf(root);
    return failures;
}

static int mr_cgroup_join(const char *dir)
{
    char path[700], pidb[32];
    if (snprintf(path, sizeof(path), "%s/cgroup.procs", dir) >=
        (int)sizeof(path))
        return -1;
    if (snprintf(pidb, sizeof(pidb), "%d\n", (int)getpid()) >=
        (int)sizeof(pidb))
        return -1;
    return mr_write_text(path, pidb);
}

static void mr_memory_max_child(int wr, const char *dir)
{
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX];
    char buf[512];
    char *evidence = NULL;
    int rc = -1;
    int n;
    if (mr_cgroup_join(dir) != 0)
        _exit(2);
    memset(&r, 0, sizeof(r));
    err[0] = '\0';
    if (mr_execute(FAKE_CHARGE, &d, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, false, &r, err, &rc, &evidence) != 0)
        _exit(3);
    free(evidence);
    n = snprintf(buf, sizeof(buf), "%d %s %s\n", rc, r.verdict, r.reason);
    if (n > 0)
         TEST_DISCARD(write(wr, buf, (size_t)n));
    _exit(0);
}

static void mr_wait_bounded(pid_t kid, int *st, int seconds)
{
    struct timespec deadline, now;
    (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += seconds;
    for (;;) {
        pid_t got = waitpid(kid, st, WNOHANG);
        if (got == kid || (got < 0 && errno != EINTR))
            return;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec &&
                now.tv_nsec >= deadline.tv_nsec)) {
            (void)kill(kid, SIGKILL);
            (void)waitpid(kid, st, 0);
            return;
        }
        {
            struct timespec rest = {.tv_sec = 0, .tv_nsec = 20000000L};
            (void)nanosleep(&rest, NULL);
        }
    }
}

static void mr_read_all(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t k = read(fd, buf + n, cap - 1 - n);
        if (k < 0 && errno == EINTR)
            continue;
        if (k <= 0)
            break;
        n += (size_t)k;
    }
    buf[n] = '\0';
}

/* The host shares a cgroup with the session and crosses memory.max: the run
 * refuses with the charge reason and the session parent survives to say so.
 * With no writable memory-delegating ancestor the leg reports UNOBSERVED
 * (never cached) instead of claiming a delegated cgroup failed. */
static int mr_exec_memory_max(void)
{
    int failures = 0;
    char dir[512];
    char buf[512];
    char why[512];
    int sp[2] = {-1, -1};
    pid_t kid;
    int st = 0;
    int opened = mr_memory_cgroup_open(dir, sizeof(dir), why, sizeof(why));
    if (opened == MR_MEMCG_UNOBSERVED) {
        printf("UNOBSERVED (memory.max leg not run: %s)\n", why);
        return 0;
    }
    if (opened != MR_MEMCG_ARMED) {
        printf("muse_run: memory cgroup: %s\n", why);
        MR_CHECK("memory cgroup delegated", false);
        return 1;
    }
    if (pipe(sp) != 0) {
        MR_CHECK("memory pipe", false);
        mr_memory_cgroup_close(dir);
        return 1;
    }
    kid = fork();
    if (kid < 0) {
        MR_CHECK("memory fork", false);
        close(sp[0]);
        close(sp[1]);
        mr_memory_cgroup_close(dir);
        return 1;
    }
    if (kid == 0) {
        close(sp[0]);
        mr_memory_max_child(sp[1], dir);
    }
    close(sp[1]);
    mr_wait_bounded(kid, &st, 90);
    mr_read_all(sp[0], buf, sizeof(buf));
    close(sp[0]);
    MR_CHECK("memory-max child finished",
        WIFEXITED(st) && WEXITSTATUS(st) == 0);
    MR_CHECK("memory-max refused", strstr(buf, "1 refused ") == buf);
    MR_CHECK("memory-max names the charge",
        strstr(buf, "memory.max charge failed, child signal ") != NULL);
    mr_memory_cgroup_close(dir);
    return failures;
}

struct mr_fresh {
    char root[512];
    char bin[576];
    char src[576];
    char muse[576];
    char poison[576];
    char marker[640];
    char probe[576];
    char saved_path[4096];
    char saved_data[512];
    char saved_tmp[512];
    int had_path;
    int had_data;
    int had_tmp;
};

static int mr_fresh_paths(struct mr_fresh *f)
{
    if (snprintf(f->bin, sizeof(f->bin), "%s/bin", f->root) >=
        (int)sizeof(f->bin))
        return -1;
    if (snprintf(f->src, sizeof(f->src), "%s/host.c", f->root) >=
        (int)sizeof(f->src))
        return -1;
    if (snprintf(f->muse, sizeof(f->muse), "%s/muse", f->bin) >=
        (int)sizeof(f->muse))
        return -1;
    if (snprintf(f->poison, sizeof(f->poison), "%s/poison", f->root) >=
        (int)sizeof(f->poison))
        return -1;
    if (snprintf(f->marker, sizeof(f->marker), "%s/muse/sessions/MARKER",
                 f->poison) >= (int)sizeof(f->marker))
        return -1;
    if (snprintf(f->probe, sizeof(f->probe), "%s/probe", f->root) >=
        (int)sizeof(f->probe))
        return -1;
    return 0;
}

static int mr_fresh_fixture(struct mr_fresh *f, const char *host_src)
{
    if (mr_fresh_paths(f) != 0)
        return -1;
    if (!mr_mkdir_p(f->bin) || !mr_write(f->src, host_src, 0))
        return -1;
    return 0;
}

static int mr_fresh_poison(const struct mr_fresh *f)
{
    char sessions[640];
    if (snprintf(sessions, sizeof(sessions), "%s/muse/sessions", f->poison) >=
        (int)sizeof(sessions))
        return -1;
    if (!mr_mkdir_p(sessions) || !mr_write(f->marker, "huge\n", 0))
        return -1;
    return 0;
}

/* 0 compiled, -1 fork failed, -2 the compiler failed. */
static int mr_fresh_compile(const struct mr_fresh *f)
{
    pid_t cc = fork();
    int st = 0;
    if (cc < 0)
        return -1;
    if (cc == 0) {
        execlp("cc", "cc", "-O2", "-o", f->muse, f->src, (char *)NULL);
        _exit(127);
    }
    if (waitpid(cc, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        return -2;
    return 0;
}

static int mr_save_env(const char *key, char *buf, size_t cap)
{
    const char *prev = getenv(key);
    buf[0] = '\0';
    if (prev && snprintf(buf, cap, "%s", prev) < (int)cap)
        return 1;
    return 0;
}

static int mr_fresh_env(const struct mr_fresh *f)
{
    if (setenv("PATH", f->bin, 1) != 0)
        return -1;
    if (setenv("XDG_DATA_HOME", f->poison, 1) != 0)
        return -1;
    if (setenv("MUSE_PROBE_FILE", f->probe, 1) != 0)
        return -1;
    if (setenv("TMPDIR", f->root, 1) != 0)
        return -1;
    return 0;
}

static void mr_trim_line(char *text)
{
    size_t n;
    if (!text)
        return;
    n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r'))
        text[--n] = '\0';
}

static int mr_fresh_recorded(char *seen, const char *poison, char **copied)
{
    int failures = 0;
    char path[700];
    if (seen)
        mr_trim_line(seen);
    MR_CHECK("fresh home recorded", seen && seen[0] &&
        strcmp(seen, poison) != 0 && strstr(seen, "z23-muse-") != NULL);
    if (seen && seen[0]) {
        if (snprintf(path, sizeof(path), "%s/muse/sessions/MARKER", seen) <
            (int)sizeof(path)) {
            *copied = mr_read(path);
            MR_CHECK("fresh home has no session history", *copied == NULL);
        } else {
            MR_CHECK("fresh home marker path", false);
        }
    }
    return failures;
}

static void mr_fresh_restore(const struct mr_fresh *f)
{
    unsetenv("MUSE_PROBE_FILE");
    if (f->had_tmp)
        (void)setenv("TMPDIR", f->saved_tmp, 1);
    else
        unsetenv("TMPDIR");
    if (f->had_path)
        (void)setenv("PATH", f->saved_path, 1);
    else
        unsetenv("PATH");
    if (f->had_data)
        (void)setenv("XDG_DATA_HOME", f->saved_data, 1);
    else
        unsetenv("XDG_DATA_HOME");
}

/* The serve child must not inherit the operator muse home. That tree's
 * session history is what pushes a turn through memory.max. */
static int mr_exec_fresh_muse_home(void)
{
    int failures = 0;
    struct mr_fresh home;
    int built;
    const char *host_src =
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "int main(void) {\n"
        "  const char *home = getenv(\"XDG_DATA_HOME\");\n"
        "  const char *outp = getenv(\"MUSE_PROBE_FILE\");\n"
        "  FILE *p; char line[8192];\n"
        "  if (outp && home) {\n"
        "    p = fopen(outp, \"w\");\n"
        "    if (p) { fputs(home, p); fputc('\\n', p); fclose(p); }\n"
        "  }\n"
        "  while (fgets(line, sizeof line, stdin)) {\n"
        "    if (strstr(line, \"\\\"method\\\":\\\"initialize\\\"\")) {\n"
        "      fputs(\"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1,"
        "\\\"result\\\":{\\\"ok\\\":true}}\\n\", stdout);\n"
        "      fflush(stdout);\n"
        "    }\n"
        "  }\n"
        "  return 0;\n}\n";
    struct muse_session *s = NULL;
    char err[MUSE_ERROR_MAX];
    char *seen = NULL;
    char *copied_text = NULL;
    memset(&home, 0, sizeof(home));
    err[0] = '\0';
    if (!test_mkdtemp(home.root, sizeof(home.root), "muse_home")) {
        MR_CHECK("fresh home root", false);
        return 1;
    }
    if (mr_fresh_fixture(&home, host_src) != 0) {
        MR_CHECK("fresh home fixture", false);
        return 1;
    }
    if (mr_fresh_poison(&home) != 0) {
        MR_CHECK("fresh home poison", false);
        return 1;
    }
    built = mr_fresh_compile(&home);
    if (built < 0) {
        MR_CHECK(built == -1 ? "fresh home cc fork" : "fresh home cc", false);
        return 1;
    }
    home.had_path = mr_save_env("PATH", home.saved_path, sizeof(home.saved_path));
    home.had_data = mr_save_env("XDG_DATA_HOME", home.saved_data,
                                sizeof(home.saved_data));
    home.had_tmp = mr_save_env("TMPDIR", home.saved_tmp, sizeof(home.saved_tmp));
    if (mr_fresh_env(&home) != 0) {
        MR_CHECK("fresh home env", false);
        goto restore;
    }
    s = muse_session_open(NULL, NULL, err);
    MR_CHECK("fresh home open", s != NULL);
    seen = mr_read(home.probe);
    failures += mr_fresh_recorded(seen, home.poison, &copied_text);
    if (s)
        muse_session_close(s);
restore:
    mr_fresh_restore(&home);
    free(seen);
    free(copied_text);
    return failures;
}

/* Silent host: the turn bound trips, the turn is cancelled first,
 * and the verdict is timeout. */
static int mr_exec_timeout(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 1500;
    b.gate_timeout_ms = 60000;
    MR_CHECK("timeout run", mr_execute(FAKE_HANG, &d, NULL,
        NULL, NULL, NULL, NULL, NULL, &b, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("timeout verdict", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "timeout") == 0);
    MR_CHECK("timeout cancels first", evidence &&
        evidence_has(evidence, "cancel:"));
    free(evidence);
    return failures;
}

/* Token cap below the first usage report: refused mid-turn, and
 * the turn is cancelled first like a timeout. */
static int mr_exec_token_cap(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    struct muse_run_budgets b;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    memset(&b, 0, sizeof(b));
    b.turn_timeout_ms = 30000;
    b.gate_timeout_ms = 60000;
    b.max_total_tokens = 10;
    MR_CHECK("cap run", mr_execute(FAKE_JOURNEY, &d, NULL,
        NULL, NULL, NULL, NULL, NULL, &b, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("cap refused", rc == 1 && r.rc == 1 &&
        strcmp(r.verdict, "refused") == 0);
    MR_CHECK("cap cancels first", evidence &&
        evidence_has(evidence, "cancel:"));
    /* The usage that tripped the cap is spend, recorded, never 0. */
    MR_CHECK("cap spend recorded", r.total_tokens > 10);
    free(evidence);
    return failures;
}

/* Model substitution: the run proceeds, both names are recorded. */
static int mr_exec_model_substitution(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    const char *saved = s_fake_model;
    memset(&r, 0, sizeof(r));
    s_fake_model = "m-other";
    MR_CHECK("mismatch run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, &mr_edit_in_scope, NULL,
        "m-want", NULL, false, &r, err, &rc, &evidence) == 0);
    MR_CHECK("mismatch proceeds", rc == 0 && r.rc == 0);
    MR_CHECK("mismatch visible",
        strcmp(r.model_requested, "m-want") == 0 &&
        strcmp(r.model_resolved, "m-other") == 0);
    MR_CHECK("mismatch selects", evidence &&
        evidence_has(evidence, "model:m-want"));
    s_fake_model = saved;
    free(evidence);
    return failures;
}

/* Claim-held callers skip the receipt pre-check: a seeded receipt
 * does not stop the turn, and no receipt is written beside it.
 * The candidate artifact and muse.json still land. */
static int mr_exec_claim_held(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    char receipt[8192], *seed = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("claimed run", mr_execute(FAKE_JOURNEY, &d,
        mr_verdict_pass, mr_head_pass, NULL, &mr_edit_in_scope, NULL,
        NULL, NULL, true, &r, err, &rc, &evidence) == 0);
    MR_CHECK("claimed proceeds", rc == 0 && r.rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    MR_CHECK("claimed turned", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
        d.run);
    seed = mr_read(receipt);
    MR_CHECK("claimed writes no receipt", seed == NULL);
    free(seed);
    {
        char cf[8192];
        (void)snprintf(cf, sizeof(cf), "%s/%s", d.run,
            r.candidate_file);
        MR_CHECK("claimed names artifact",
            r.candidate_file[0] && access(cf, F_OK) == 0);
    }
    free(evidence);
    return failures;
}

/* The claim-held turn itself, over a transport this case owns so the
 * seeded receipt can be read back byte-for-byte afterwards. */
static int mr_claim_seed_turn(struct mr_dirs *d, const char *receipt,
    const char *seed_text)
{
    int failures = 0;
    struct muse_run_result r;
    struct muse_run_task t;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int ev2[2], to_fd = -1, from_fd = -1;
    pid_t child = -1;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    if (pipe(ev2) != 0) {
        MR_CHECK("claimed pipe", false);
        return failures;
    }
    s_evidence_fd = ev2[1];
    if (!mr_task_for(d, &t, NULL, NULL, NULL, NULL)) {
        MR_CHECK("claimed task", false);
        close(ev2[0]); close(ev2[1]);
        return failures;
    }
    t.caller_holds_claim = true;
    if (!mr_fork_fake(FAKE_JOURNEY, ev2[0], &to_fd, &from_fd, &child)) {
        MR_CHECK("claimed fork", false);
        close(ev2[0]); close(ev2[1]);
        return failures;
    }
    err[0] = '\0';
    rc = muse_run_task_on_transport(&t, child, to_fd, from_fd, &r, err);
    close(to_fd);
    close(from_fd);
    {
        int status = 0;
        (void)waitpid(child, &status, 0);
    }
    close(ev2[1]);
    s_evidence_fd = -1;
    evidence = read_evidence(ev2[0]);
    close(ev2[0]);
    MR_CHECK("claimed seed ignored", rc == 0 &&
        strcmp(r.verdict, "pass") == 0);
    MR_CHECK("claimed seed turned", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    {
        char *rtext = mr_read(receipt);
        MR_CHECK("claimed seed intact", rtext &&
            strcmp(rtext, seed_text) == 0);
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* Claim-held with a seeded receipt: the turn still runs and the
 * seed is left byte-identical. */
static int mr_exec_claim_seed(void)
{
    int failures = 0;
    struct mr_dirs d;
    char receipt[8192];
    static const char seed_text[] =
        "{\"verdict\":\"failed\",\"seq\":7,\"name\":\"u1\","
        "\"attempt\":1}\n";
    MR_CHECK("claimed lane", mr_lane(&d));
    (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json",
        d.run);
    MR_CHECK("claimed seed", mr_write(receipt, seed_text, 0));
    MR_CHECK("claimed gate",
        mr_gate_script(&d, mr_verdict_pass, mr_head_pass, NULL));
    /* The TURN makes the in-scope change, not the fixture: a workspace
     * dirtied beforehand is baseline dirt and would be refused. */
    MR_CHECK("claimed arms turn edit",
        mr_arm_edit(&d, &mr_edit_in_scope));
    failures += mr_claim_seed_turn(&d, receipt, seed_text);
    s_fake_write_path[0] = '\0';
    return failures;
}

/* --- the workspace restore -------------------------------------------------
 * A run leaves the workspace at its pinned base once the candidate is verified
 * as a durable copy, so the next claimed task is not refused for this run's dirt. */

static bool mr_path_in(const char *dir, const char *rel, char *out,
    size_t cap)
{
    return snprintf(out, cap, "%s/%s", dir, rel) < (int)cap;
}

static bool mr_exists(const char *dir, const char *rel)
{
    char p[8192];
    return mr_path_in(dir, rel, p, sizeof(p)) && access(p, F_OK) == 0;
}

static bool mr_file_is(const char *dir, const char *rel, const char *text)
{
    char p[8192];
    char *got;
    bool same;
    if (!mr_path_in(dir, rel, p, sizeof(p))) return false;
    got = mr_read(p);
    same = got && strcmp(got, text) == 0;
    free(got);
    return same;
}

/* Clean at base: a measured empty porcelain and HEAD still the pin. */
static bool mr_at_base(const struct mr_dirs *d, const char *base)
{
    char head[64];
    return muse_files_changed(d->wt) == 0 &&
        muse_head_at(d->wt, head, sizeof(head)) && strcmp(head, base) == 0;
}

/* An ignored build output laid down before the run: never the run's to
 * touch, whatever the restore does. */
static bool mr_build_output(const struct mr_dirs *d)
{
    char p[8192];
    return mr_path_in(d->wt, "build/out.o", p, sizeof(p)) &&
        mr_write(p, "object\n", 0);
}

/* Puts the recorded change back from the evidence alone: the tracked
 * patch re-applied, and each untracked copy put back under its path. The
 * fold of the result must be the candidate the run named. */
static bool mr_reapply(const struct mr_dirs *d,
    const struct muse_run_result *r, const char *untracked_rel,
    const char *untracked_hash)
{
    char patch[8192], copy[8192], dst[8192], hex[64];
    char *fold = NULL, *text;
    bool same;
    (void)snprintf(patch, sizeof(patch), "%s/candidate-%s.tracked.patch",
        d->run, r->candidate);
    if (access(patch, F_OK) == 0 &&
        !mr_git3(d->wt, "apply", patch, NULL))
        return false;
    if (untracked_rel) {
        (void)snprintf(copy, sizeof(copy), "%s/candidate-%s.untracked/%s",
            d->run, r->candidate, untracked_hash);
        text = mr_read(copy);
        if (!text || !mr_path_in(d->wt, untracked_rel, dst, sizeof(dst)) ||
            !mr_write(dst, text, 0)) {
            free(text);
            return false;
        }
        free(text);
    }
    if (!muse_candidate_fold(d->wt, d->run, hex, sizeof(hex), &fold, NULL, 0))
        return false;
    same = strcmp(hex, r->candidate) == 0;
    free(fold);
    return same;
}

/* A passing run that modified a tracked file AND created an untracked
 * one: afterwards the workspace is clean at base, the ignored build
 * output is untouched, and the evidence alone reproduces the change. */
static int mr_exec_restore_pass(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char hash[64] = "";
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("restore lane", mr_lane(&d));
    MR_CHECK("restore seed", mr_seed_committed(&d, "src/sum.c", "orig\n"));
    MR_CHECK("restore gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("restore build output", mr_build_output(&d));
    MR_CHECK("restore tracked-edit hook", mr_fsmonitor(&d, "src/turn.c",
        "printf 'edited\\n' > \"$W/src/sum.c\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("restore pass", rc == 0 && strcmp(r.verdict, "pass") == 0);
    MR_CHECK("restore restored", r.workspace_restored &&
        strstr(r.workspace_restore, "restored to base") != NULL);
    MR_CHECK("restore clean at base", mr_at_base(&d, r.base));
    MR_CHECK("restore tracked back", mr_file_is(d.wt, "src/sum.c", "orig\n"));
    MR_CHECK("restore untracked removed", !mr_exists(d.wt, "src/turn.c"));
    MR_CHECK("restore ignored untouched",
        mr_file_is(d.wt, "build/out.o", "object\n"));
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("restore evidence", ftext &&
            strstr(ftext, "\"workspace\":{\"restored\":true") &&
            strstr(ftext, "\"verdict\":\"pass\""));
        free(ftext);
    }
    {
        char p[8192];
        (void)snprintf(p, sizeof(p), "%s/src/turn.c", d.wt);
        MR_CHECK("restore turn content hash", mr_write(p,
            "the turn wrote this\n", 0) &&
            muse_git_line(hash, sizeof(hash), d.wt, "hash-object", "--",
                "src/turn.c") && unlink(p) == 0);
    }
    MR_CHECK("restore candidate re-applies",
        mr_reapply(&d, &r, "src/turn.c", hash) &&
        mr_file_is(d.wt, "src/sum.c", "edited\n") &&
        mr_file_is(d.wt, "src/turn.c", "the turn wrote this\n"));
    free(evidence);
    return failures;
}

/* Drive the production restore directly, without the fake-turn fsmonitor.
 * Git's other commands may also refresh stat data: observe the explicit
 * refresh itself, not just whether the next intake happens to be clean. */
static bool mr_restore_seed_index(const struct mr_dirs *d, const char *path)
{
    char index_stat[1024] = "";
    struct stat seeded_stat;
    struct rcv_workspace w = {0};
    const struct timespec old_times[2] = {
        { .tv_sec = 946684800, .tv_nsec = 0 },
        { .tv_sec = 946684800, .tv_nsec = 0 }
    };
    /* Pin the cached baseline to an old second so restore's rewrite cannot
     * accidentally match it merely because the test ran in one second. */
    return utimensat(AT_FDCWD, path, old_times, 0) == 0 &&
        stat(path, &seeded_stat) == 0 && seeded_stat.st_mtime == 946684800 &&
        mr_git3(d->wt, "update-index", "--refresh", NULL) &&
        muse_git_line(index_stat, sizeof(index_stat), d->wt, "ls-files",
            "--debug", "src/sum.c") &&
        strstr(index_stat, "\n  mtime: 946684800:0\n") != NULL &&
        zcl_devagent_workspace_observe(d->wt, true, &w) && w.directory &&
        w.resolved && w.checkout && w.dirty == 0;
}

struct mr_restore_shim {
    char old_path[16384];
    bool installed;
};

static bool mr_restore_shell_literal(const char *s)
{
    return s && !strchr(s, '\'') && !strchr(s, '\n') && !strchr(s, '\r');
}

/* Pass through to the configured executable search path with no inherited
 * Git selectors. Only this fixture's explicit refresh writes the witness. */
static bool mr_restore_watch_refresh(const struct mr_dirs *d,
    struct mr_restore_shim *shim)
{
    const char *orig = getenv("PATH");
    char dir[8192], path[8192], marker[8192], next[24576], text[49152];
    if (!mr_restore_shell_literal(orig) ||
        !mr_restore_shell_literal(d->wt) ||
        !mr_restore_shell_literal(d->run))
        return false;
    int n = snprintf(shim->old_path, sizeof(shim->old_path), "%s", orig);
    if (n < 0 || (size_t)n >= sizeof(shim->old_path)) return false;
    if (!mr_path_in(d->root, "refresh-shim", dir, sizeof(dir)) ||
        !mr_path_in(dir, "git", path, sizeof(path)) ||
        !mr_path_in(d->run, "refresh.ok", marker, sizeof(marker)))
        return false;
    n = snprintf(next, sizeof(next), "%s:%s", dir, orig);
    if (n < 0 || (size_t)n >= sizeof(next)) return false;
    n = snprintf(text, sizeof(text),
        "#!/bin/sh\nunset ENV BASH_ENV\nPATH='%s'\nexport PATH\n"
        "if [ \"$1\" = '-C' ] && [ \"$2\" = '%s' ] && "
        "[ \"$3\" = 'update-index' ] && [ \"$4\" = '--refresh' ]; then\n"
        "  if [ -e '%s.refuse' ]; then exit 73; fi\n"
        "  env -i PATH=\"$PATH\" HOME=\"${HOME:-/}\" LC_ALL=C "
        "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git \"$@\" || "
        "exit \"$?\"\n"
        "  printf 'refreshed\\n' > '%s' || exit 74\n  exit 0\nfi\n"
        "exec env -i PATH=\"$PATH\" HOME=\"${HOME:-/}\" LC_ALL=C "
        "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git \"$@\"\n",
        orig, d->wt, marker, marker);
    if (n < 0 || (size_t)n >= sizeof(text)) return false;
    shim->installed = mr_mkdir_p(dir) && mr_write(path, text, 0755) &&
        setenv("PATH", next, 1) == 0;
    return shim->installed;
}

static int mr_restore_intake_checks(const struct mr_dirs *d, const char *path)
{
    int failures = 0;
    struct rcv_workspace w = {0};
    MR_CHECK("settle explicit refresh completed",
        mr_file_is(d->run, "refresh.ok", "refreshed\n"));
    MR_CHECK("settle content", mr_file_is(d->wt, "src/sum.c", "orig\n"));
    MR_CHECK("settle intake-clean",
        zcl_devagent_workspace_observe(d->wt, true, &w) && w.directory &&
        w.resolved && w.checkout && w.dirty == 0);
    /* A size change distinguishes real dirt without consulting a clock. */
    MR_CHECK("settle re-dirty", mr_write(path, "orig\nREAL DIRT\n", 0));
    memset(&w, 0, sizeof(w));
    MR_CHECK("settle dirt seen",
        zcl_devagent_workspace_observe(d->wt, true, &w) && w.dirty != 0);
    return failures;
}

static int mr_restore_refresh_refusal(const struct mr_dirs *d,
    const struct muse_restore_in *in, const char *path)
{
    int failures = 0;
    char marker[8192], reason[256] = "";
    bool half = true;
    bool ready = mr_path_in(d->run, "refresh.ok", marker, sizeof(marker)) &&
        (unlink(marker) == 0 || errno == ENOENT) &&
        mr_path_in(d->run, "refresh.ok.refuse", marker, sizeof(marker)) &&
        mr_write(marker, "refuse\n", 0) && mr_write(path, "orig\nTURN\n", 0);
    MR_CHECK("settle refresh-refusal fixture", ready);
    if (!ready) return failures;
    /* Recreate the same candidate bytes; the verified artifact is unchanged. */
    MR_CHECK("settle refresh failure refuses restore",
        !muse_restore_workspace(in, reason, sizeof(reason), &half));
    MR_CHECK("settle refresh refusal is named",
        strcmp(reason, "incomplete: the index stat cache could not be "
            "refreshed") == 0);
    MR_CHECK("settle refresh refusal is not half-undone", !half);
    MR_CHECK("settle refresh refusal keeps base bytes",
        mr_file_is(d->wt, "src/sum.c", "orig\n"));
    MR_CHECK("settle refused refresh has no success witness",
        !mr_exists(d->run, "refresh.ok"));
    return failures;
}

static int mr_exec_restore_settles_index(void)
{
    int failures = 0;
    struct mr_dirs d = {0};
    struct mr_restore_shim shim = {0};
    struct muse_restore_in in;
    char base[64] = "";
    char hex[64] = "";
    char *fold = NULL;
    char artifact[8192];
    char cf[128];
    char why[256] = "";
    char reason[256] = "";
    char path[8192];
    bool half = true;
    bool restored_ok;
    memset(&in, 0, sizeof(in));
    MR_CHECK("settle lane", mr_lane(&d));
    MR_CHECK("settle seed", mr_seed_committed(&d, "src/sum.c", "orig\n"));
    MR_CHECK("settle base", muse_head_at(d.wt, base, sizeof(base)));
    (void)snprintf(path, sizeof(path), "%s/src/sum.c", d.wt);
    MR_CHECK("settle cached baseline and pre-intake-clean",
        mr_restore_seed_index(&d, path));
    if (failures) goto cleanup;
    MR_CHECK("settle refresh witness installed", mr_restore_watch_refresh(&d,
        &shim));
    MR_CHECK("settle refresh witness starts absent",
        !mr_exists(d.run, "refresh.ok"));
    if (failures) goto cleanup;
    MR_CHECK("settle turn", mr_write(path, "orig\nTURN\n", 0));
    MR_CHECK("settle fold",
        muse_candidate_fold(d.wt, d.run, hex, sizeof(hex), &fold, why,
            sizeof(why)));
    (void)snprintf(artifact, sizeof(artifact), "%s/candidate-%s.diff",
        d.run, hex);
    (void)snprintf(cf, sizeof(cf), "candidate-%s.diff", hex);
    MR_CHECK("settle publish", fold && mr_write(artifact, fold, 0));
    free(fold);
    fold = NULL;
    in.workspace = d.wt;
    in.rundir = d.run;
    in.base = base;
    in.candidate = hex;
    in.candidate_file = cf;
    in.pre_clean = true;
    if (failures) goto cleanup;
    restored_ok = muse_restore_workspace(&in, reason, sizeof(reason), &half);
    MR_CHECK("settle restored", restored_ok && !half);
    failures += mr_restore_intake_checks(&d, path);
    failures += mr_restore_refresh_refusal(&d, &in, path);
cleanup:
    if (shim.installed)
        MR_CHECK("settle executable search path restored",
            setenv("PATH", shim.old_path, 1) == 0);
    if (d.root[0])
        MR_CHECK("settle fixture removed", test_rm_rf_recursive(d.root) == 0);
    return failures;
}

/* A judged-and-rejected run and a refused-after-the-turn run both leave
 * a verified candidate, so both are restored too. */
static int mr_exec_restore_rejected(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("rejected run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_fail,
        mr_head_fail, NULL, &mr_edit_in_scope, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("rejected failed", strcmp(r.verdict, "failed") == 0);
    MR_CHECK("rejected restored", r.workspace_restored &&
        mr_at_base(&d, r.base) && !mr_exists(d.wt, "src/sum.c"));
    free(evidence);
    evidence = NULL;
    memset(&r, 0, sizeof(r));
    MR_CHECK("refused run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, "exit 7", &mr_edit_in_scope, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("refused verdict", strcmp(r.verdict, "refused") == 0);
    MR_CHECK("refused restored", r.workspace_restored &&
        mr_at_base(&d, r.base) && !mr_exists(d.wt, "src/sum.c"));
    {
        char receipt[8192];
        char *rtext;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json", d.run);
        rtext = mr_read(receipt);
        MR_CHECK("refused receipt carries restore", rtext &&
            strstr(rtext, "\"workspace_restored\":true"));
        free(rtext);
    }
    free(evidence);
    return failures;
}

/* Baseline dirt is never this run's: it is refused before the turn and
 * left exactly where it was. */
static int mr_exec_restore_not_baseline(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char err[MUSE_RUN_ERROR_MAX] = {0};
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("baseline run", mr_execute(FAKE_JOURNEY, &d, mr_verdict_pass,
        mr_head_pass, NULL, &mr_edit_baseline, NULL, NULL, NULL, false,
        &r, err, &rc, &evidence) == 0);
    MR_CHECK("baseline kept", !r.workspace_restored &&
        strstr(r.workspace_restore, "not attempted") != NULL &&
        mr_file_is(d.wt, "edit.txt", "changed\n"));
    free(evidence);
    return failures;
}

/* A dirty lane plus the artifact its fold would publish, laid down by
 * hand so the restore can be handed a missing or damaged copy. */
static bool mr_dirty_candidate(struct mr_dirs *d, char *hex, size_t cap,
    char *base, size_t bcap, char *file, size_t fcap)
{
    char p[8192];
    char *fold = NULL;
    bool ok;
    if (!mr_lane(d) || !mr_seed_committed(d, "src/a.c", "orig\n") ||
        !muse_head_at(d->wt, base, bcap))
        return false;
    if (!mr_path_in(d->wt, "src/a.c", p, sizeof(p)) ||
        !mr_write(p, "edited\n", 0) ||
        !mr_path_in(d->wt, "src/b.c", p, sizeof(p)) ||
        !mr_write(p, "made\n", 0))
        return false;
    if (!muse_candidate_fold(d->wt, d->run, hex, cap, &fold, NULL, 0))
        return false;
    ok = snprintf(file, fcap, "candidate-%s.diff", hex) < (int)fcap &&
        mr_path_in(d->run, file, p, sizeof(p)) && mr_write(p, fold, 0);
    free(fold);
    return ok;
}

static bool mr_still_dirty(const struct mr_dirs *d)
{
    return mr_file_is(d->wt, "src/a.c", "edited\n") &&
        mr_file_is(d->wt, "src/b.c", "made\n");
}

static bool mr_restore_call_undone(const struct mr_dirs *d,
    const char *base, const char *hex, const char *file, bool pre_clean,
    char *why, size_t cap, bool *half_undone)
{
    struct muse_restore_in in;
    memset(&in, 0, sizeof(in));
    in.workspace = d->wt;
    in.rundir = d->run;
    in.base = base;
    in.candidate = hex;
    in.candidate_file = file;
    in.pre_clean = pre_clean;
    return muse_restore_workspace(&in, why, cap, half_undone);
}

/* Every refusal the cases below provoke is made BEFORE a byte is
 * touched, so none of them may ever report a half-undone workspace: a
 * half_undone flag here would itself be the failure. */
static bool mr_restore_call(const struct mr_dirs *d, const char *base,
    const char *hex, const char *file, bool pre_clean, char *why,
    size_t cap)
{
    bool half_undone = true;
    bool ok = mr_restore_call_undone(d, base, hex, file, pre_clean, why,
        cap, &half_undone);
    if (half_undone)
        (void)snprintf(why, cap, "%s",
            "HALF-UNDONE: a refusal reported a touched workspace");
    return ok && !half_undone;
}

/* A candidate that is missing, damaged, or no longer the workspace's
 * change is never restored from: the change stays, with the reason. */
static int mr_exec_restore_unverified(void)
{
    int failures = 0;
    struct mr_dirs d;
    char hex[64], base[64], file[192], p[8192], why[256];
    MR_CHECK("unverified lane", mr_dirty_candidate(&d, hex, sizeof(hex),
        base, sizeof(base), file, sizeof(file)));
    MR_CHECK("unverified pre-state gate",
        !mr_restore_call(&d, base, hex, file, false, why, sizeof(why)) &&
        strstr(why, "not attempted") && mr_still_dirty(&d));
    (void)mr_path_in(d.run, file, p, sizeof(p));
    MR_CHECK("corrupt artifact", mr_write(p, "diff --git a/x b/x\n", 0));
    MR_CHECK("corrupt refused",
        !mr_restore_call(&d, base, hex, file, true, why, sizeof(why)) &&
        strstr(why, "do not hash") && mr_still_dirty(&d));
    MR_CHECK("missing artifact", unlink(p) == 0);
    MR_CHECK("missing refused",
        !mr_restore_call(&d, base, hex, file, true, why, sizeof(why)) &&
        strstr(why, "missing") && mr_still_dirty(&d));
    MR_CHECK("stale lane", mr_dirty_candidate(&d, hex, sizeof(hex), base,
        sizeof(base), file, sizeof(file)));
    (void)mr_path_in(d.wt, "src/c.c", p, sizeof(p));
    MR_CHECK("stale extra write", mr_write(p, "later\n", 0));
    MR_CHECK("stale refused",
        !mr_restore_call(&d, base, hex, file, true, why, sizeof(why)) &&
        strstr(why, "no longer matches") && mr_still_dirty(&d) &&
        mr_exists(d.wt, "src/c.c"));
    MR_CHECK("stale cleared", unlink(p) == 0);
    MR_CHECK("verified restores",
        mr_restore_call(&d, base, hex, file, true, why, sizeof(why)) &&
        mr_at_base(&d, base) && mr_file_is(d.wt, "src/a.c", "orig\n") &&
        !mr_exists(d.wt, "src/b.c"));
    return failures;
}

/* Two claimed tasks in a row on one workspace: the second reaches the model turn. */
static int mr_exec_restore_twice(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("twice lane", mr_lane(&d));
    MR_CHECK("twice gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    rc = mr_run_prepared(&d, NULL, "src/one.c", NULL, &r, &evidence);
    MR_CHECK("twice first pass", rc == 0 && r.workspace_restored);
    free(evidence);
    evidence = NULL;
    MR_CHECK("twice second rundir",
        snprintf(d.run, sizeof(d.run), "%s/run2", d.root) <
        (int)sizeof(d.run) && mr_mkdir_p(d.run));
    memset(&r, 0, sizeof(r));
    rc = mr_run_prepared(&d, NULL, "src/two.c", NULL, &r, &evidence);
    MR_CHECK("twice second reached the turn", evidence &&
        evidence_has(evidence, "turn-cmd:") && r.scope_pre_clean &&
        r.total_tokens > 0);
    MR_CHECK("twice second pass", rc == 0 &&
        strcmp(r.verdict, "pass") == 0 && r.workspace_restored &&
        mr_at_base(&d, r.base));
    free(evidence);
    return failures;
}

/* --- the change set must be NAMED, or the run refuses by name -----------
 * A gate-passing turn whose tracked diff cannot be captured must not publish
 * a pass with no artifact. Reproduced with `diff.external` pointing at a
 * missing path: `git diff HEAD --` exits 128 with an empty capture while
 * status, rev-parse, hash-object and ls-files still exit 0. */
static bool mr_break_tracked_diff(const struct mr_dirs *d)
{
    return mr_git3(d->wt, "config", "diff.external",
        "/nonexistent/zcl-no-such-external-diff");
}

/* What a run that could not preserve its change must leave behind: the
 * change itself, untouched; the workspace named as blocked, because the
 * next claimed task cannot use it; and one line naming the blocker in
 * each place a reader looks. */
static int mr_unfoldable_evidence(const struct mr_dirs *d,
    const struct muse_run_result *r)
{
    int failures = 0;
    char path[8192];
    char *text;
    /* Nothing was preserved so nothing is undone, but the tree is off its base
     * and could not be put back: blocked, not half-undone (the change is intact). */
    MR_CHECK("unfoldable change untouched",
        !r->workspace_restored && r->workspace_blocked &&
        !r->half_undone);
    MR_CHECK("unfoldable edit still there",
        mr_file_is(d->wt, "src/sum.c", "edited\n") &&
        mr_exists(d->wt, "src/turn.c"));
    (void)snprintf(path, sizeof(path), "%s/workspace.blocked", d->run);
    text = mr_read(path);
    MR_CHECK("unfoldable marker written", text &&
        strstr(text, "candidate=none") &&
        strstr(text, "half_undone=false") &&
        strstr(text, "blocker=not attempted: the change set was never "
                     "named"));
    free(text);
    text = mr_read_facts(d, path, sizeof(path));
    MR_CHECK("unfoldable evidence", text &&
        strstr(text, "\"candidate\":\"none\"") &&
        strstr(text, "\"candidate_note\":\"the tracked diff") &&
        strstr(text, "\"half_undone\":false") &&
        strstr(text, "\"verdict\":\"refused\""));
    free(text);
    (void)snprintf(path, sizeof(path), "%s/receipt.json", d->run);
    text = mr_read(path);
    MR_CHECK("unfoldable receipt", text &&
        strstr(text, "\"verdict\":\"refused\"") &&
        strstr(text, "\"workspace_blocked\":true"));
    free(text);
    return failures;
}

/* A gate-passing turn whose change set cannot be folded is NOT a pass:
 * it is a named refusal, made before the gate build is spent, with the
 * change left exactly where the turn put it. */
static int mr_exec_candidate_unfoldable(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("unfoldable lane", mr_lane(&d));
    MR_CHECK("unfoldable seed", mr_seed_committed(&d, "src/sum.c",
        "orig\n"));
    MR_CHECK("unfoldable gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("unfoldable tracked edit", mr_fsmonitor(&d, "src/turn.c",
        "printf 'edited\\n' > \"$W/src/sum.c\""));
    MR_CHECK("unfoldable break diff", mr_break_tracked_diff(&d));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    /* The turn ran and the change is measured: not an early failure. */
    MR_CHECK("unfoldable turn ran", evidence &&
        evidence_has(evidence, "turn-cmd:") && r.files_changed == 2 &&
        r.scope_changed_measured && r.head_measured);
    MR_CHECK("unfoldable not pass",
        rc == 1 && r.rc == 1 && strcmp(r.verdict, "pass") != 0);
    MR_CHECK("unfoldable candidate unnamed",
        r.candidate_file[0] == '\0' && strcmp(r.candidate, "none") == 0);
    MR_CHECK("unfoldable blocker named", r.candidate_note[0] &&
        strstr(r.candidate_note, "tracked diff could not be captured") &&
        strstr(r.candidate_note, "exited 128"));
    MR_CHECK("unfoldable reason carries it",
        strstr(r.reason, "change set could not be preserved") != NULL);
    /* Refused BEFORE the gate build: a doomed run does not spend one. */
    MR_CHECK("unfoldable gate not built",
        strcmp(r.build_spawn, "none") == 0 && r.gate_normal == false);
    failures += mr_unfoldable_evidence(&d, &r);
    free(evidence);
    return failures;
}

/* The same turn with git healthy: one tracked file edited, the gate passes,
 * and the change is named and published. */
static int mr_exec_candidate_tracked(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char art[8192];
    char *atext = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("tracked lane", mr_lane(&d));
    MR_CHECK("tracked seed", mr_seed_committed(&d, "src/sum.c", "orig\n"));
    MR_CHECK("tracked gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    MR_CHECK("tracked edit hook", mr_fsmonitor(&d, "src/turn.c",
        "printf 'edited\\n' > \"$W/src/sum.c\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("tracked pass", rc == 0 && strcmp(r.verdict, "pass") == 0);
    MR_CHECK("tracked candidate named",
        mr_hex40(r.candidate) && r.candidate_file[0] &&
        r.candidate_note[0] == '\0');
    failures += mr_pass_candidate(&d, &r);
    (void)snprintf(art, sizeof(art), "%s/%s", d.run, r.candidate_file);
    atext = mr_read(art);
    MR_CHECK("tracked artifact holds the patch", atext &&
        strstr(atext, "diff --git a/src/sum.c b/src/sum.c") &&
        strstr(atext, "+edited") && strstr(atext, "?? src/turn.c "));
    free(atext);
    free(evidence);
    return failures;
}

/* A gate that FAILS still preserves the change and still puts the
 * workspace back: the next job is not charged for this one's dirt. */
static int mr_exec_restore_failed_gate(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char art[8192];
    char *atext = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("failgate lane", mr_lane(&d));
    MR_CHECK("failgate seed", mr_seed_committed(&d, "src/sum.c",
        "orig\n"));
    MR_CHECK("failgate gate", mr_gate_script(&d, mr_verdict_fail,
        mr_head_fail, NULL));
    MR_CHECK("failgate edit hook", mr_fsmonitor(&d, "src/turn.c",
        "printf 'edited\\n' > \"$W/src/sum.c\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("failgate failed", rc == 1 &&
        strcmp(r.verdict, "failed") == 0);
    /* Preserved FIRST: the artifact carries the whole change. */
    MR_CHECK("failgate candidate named",
        mr_hex40(r.candidate) && r.candidate_file[0]);
    (void)snprintf(art, sizeof(art), "%s/%s", d.run, r.candidate_file);
    atext = mr_read(art);
    MR_CHECK("failgate diff preserved", atext &&
        strstr(atext, "diff --git a/src/sum.c b/src/sum.c") &&
        strstr(atext, "+edited") && strstr(atext, "?? src/turn.c "));
    free(atext);
    /* Only THEN restored. */
    MR_CHECK("failgate clean at base", r.workspace_restored &&
        !r.workspace_blocked && mr_at_base(&d, r.base) &&
        mr_file_is(d.wt, "src/sum.c", "orig\n") &&
        !mr_exists(d.wt, "src/turn.c"));
    free(evidence);
    return failures;
}

/* The second half of the acceptance sequence: the next claimed task on
 * the recovered workspace measured a clean pre-state, reached its turn,
 * and passed with a change set of its own. */
static int mr_recover_second(const struct mr_dirs *d,
    const struct muse_run_result *r, const char *evidence, int rc,
    const char *first)
{
    int failures = 0;
    MR_CHECK("recover second pre-state clean", r->scope_pre_measured &&
        r->scope_pre_clean && r->scope_pre_count == 0);
    MR_CHECK("recover second reached the turn", evidence &&
        evidence_has(evidence, "turn-cmd:"));
    MR_CHECK("recover second pass", rc == 0 &&
        strcmp(r->verdict, "pass") == 0);
    MR_CHECK("recover second has its own change set",
        mr_hex40(r->candidate) && strcmp(r->candidate, first) != 0);
    MR_CHECK("recover second restored", r->workspace_restored &&
        !r->workspace_blocked && mr_at_base(d, r->base));
    return failures;
}

/* ACCEPTANCE SEQUENCE: a run whose gate fails, then the next claimed task on
 * the SAME workspace reaches its turn and passes, with no hand cleaning. */
static int mr_exec_recover_then_pass(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char first[64] = "";
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("recover lane", mr_lane(&d));
    MR_CHECK("recover seed", mr_seed_committed(&d, "src/sum.c", "orig\n"));
    MR_CHECK("recover failing gate", mr_gate_script(&d, mr_verdict_fail,
        mr_head_fail, NULL));
    MR_CHECK("recover edit hook", mr_fsmonitor(&d, "src/turn.c",
        "printf 'edited\\n' > \"$W/src/sum.c\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    MR_CHECK("recover first failed", rc == 1 &&
        strcmp(r.verdict, "failed") == 0);
    MR_CHECK("recover first preserved", mr_hex40(r.candidate) &&
        r.candidate_file[0]);
    MR_CHECK("recover first restored", r.workspace_restored &&
        !r.workspace_blocked && mr_at_base(&d, r.base));
    (void)snprintf(first, sizeof(first), "%s", r.candidate);
    free(evidence);
    evidence = NULL;
    /* The next claimed task: own run dir, same workspace, a passing gate. */
    MR_CHECK("recover second rundir",
        snprintf(d.run, sizeof(d.run), "%s/run2", d.root) <
        (int)sizeof(d.run) && mr_mkdir_p(d.run));
    MR_CHECK("recover passing gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    memset(&r, 0, sizeof(r));
    rc = mr_run_prepared(&d, NULL, "src/two.c", NULL, &r, &evidence);
    failures += mr_recover_second(&d, &r, evidence, rc, first);
    free(evidence);
    return failures;
}

/* A restore that CANNOT complete: the undo has already started when it
 * finds it cannot finish. It must say so as a blocker, leave the
 * blocker file an operator reads, and never report a clean workspace. */
static int mr_exec_restore_blocked(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct muse_run_result r;
    char *evidence = NULL;
    char dir[8192], blocked[8192];
    char *btext = NULL;
    int rc = -1;
    memset(&r, 0, sizeof(r));
    MR_CHECK("blocked lane", mr_lane(&d));
    MR_CHECK("blocked gate", mr_gate_script(&d, mr_verdict_pass,
        mr_head_pass, NULL));
    /* The turn's file lands under src/, which goes read-only once it exists: the
     * copy under the run dir succeeds (change preserved), then the undo cannot
     * remove it. Preserve first, restore second. */
    MR_CHECK("blocked hook", mr_fsmonitor(&d, "src/turn.c",
        "chmod 500 \"$W/src\""));
    rc = mr_run_prepared(&d, NULL, "src/turn.c", NULL, &r, &evidence);
    (void)snprintf(dir, sizeof(dir), "%s/src", d.wt);
    (void)chmod(dir, 0700);
    MR_CHECK("blocked preserved first", mr_hex40(r.candidate) &&
        r.candidate_file[0]);
    failures += mr_pass_candidate(&d, &r);
    MR_CHECK("blocked not restored", !r.workspace_restored);
    MR_CHECK("blocked says blocked",
        r.workspace_blocked && r.half_undone);
    MR_CHECK("blocked names the blocker",
        strstr(r.workspace_restore, "incomplete:") != NULL);
    MR_CHECK("blocked workspace not clean", !mr_at_base(&d, r.base) &&
        mr_exists(d.wt, "src/turn.c"));
    (void)snprintf(blocked, sizeof(blocked), "%s/workspace.blocked",
        d.run);
    btext = mr_read(blocked);
    MR_CHECK("blocked file written", btext &&
        strstr(btext, "workspace=") && strstr(btext, d.wt) &&
        strstr(btext, "half_undone=true") &&
        strstr(btext, "blocker=incomplete:") &&
        strstr(btext, r.candidate_file));
    free(btext);
    {
        char facts[8192];
        char *ftext = mr_read_facts(&d, facts, sizeof(facts));
        MR_CHECK("blocked evidence", ftext &&
            strstr(ftext, "\"blocked\":true"));
        free(ftext);
    }
    {
        char receipt[8192];
        char *rtext;
        (void)snprintf(receipt, sizeof(receipt), "%s/receipt.json", d.run);
        rtext = mr_read(receipt);
        MR_CHECK("blocked receipt", rtext &&
            strstr(rtext, "\"workspace_blocked\":true") &&
            strstr(rtext, "\"workspace_restored\":false"));
        free(rtext);
    }
    (void)rc;
    free(evidence);
    return failures;
}

static int mr_failures_restore(void)
{
    int failures = 0;
    failures += mr_exec_restore_pass();
    failures += mr_exec_restore_settles_index();
    failures += mr_exec_restore_rejected();
    failures += mr_exec_restore_not_baseline();
    failures += mr_exec_restore_unverified();
    failures += mr_exec_restore_twice();
    /* The change set is named before it is judged, or the run refuses. */
    failures += mr_exec_candidate_tracked();
    failures += mr_exec_candidate_unfoldable();
    /* Recovery: preserve, restore, and say so when it cannot finish. */
    failures += mr_exec_restore_failed_gate();
    failures += mr_exec_recover_then_pass();
    failures += mr_exec_restore_blocked();
    return failures;
}

static int mr_failures_execute(void)
{
    int failures = 0;
    failures += mr_exec_no_runner();
    failures += mr_exec_no_change();
    failures += mr_exec_failing_gate();
    failures += mr_exec_pass();
    failures += mr_exec_cancelled();
    failures += mr_exec_unknown_frame();
    failures += mr_exec_garbage();
    failures += mr_exec_host_exit();
    failures += mr_exec_host_abort();
    failures += mr_exec_memcg_walk();
    failures += mr_exec_memory_max();
    failures += mr_exec_fresh_muse_home();
    failures += mr_exec_timeout();
    failures += mr_exec_token_cap();
    failures += mr_exec_model_substitution();
    failures += mr_exec_claim_held();
    failures += mr_exec_claim_seed();
    /* The scope audit: the permission proven by measured output. */
    failures += mr_exec_baseline_dirt();
    failures += mr_exec_outside_scope();
    failures += mr_exec_scope_prefix();
    failures += mr_exec_scope_multi();
    failures += mr_exec_unmeasurable();
    failures += mr_exec_unmeasurable_bound();
    /* The pinned pre-turn commit: a clean audit of a tree a commit has
     * already emptied is evidence of nothing. */
    failures += mr_exec_head_moved();
    failures += mr_exec_head_unborn();
    /* Rows the audit must read in full, or refuse. */
    failures += mr_exec_rename_out();
    failures += mr_exec_delete_outside();
    failures += mr_exec_rows_malformed();
    failures += mr_exec_rows_rename_bare();
    failures += mr_exec_rows_escaping_paths();
    /* The gate's own process, not only the log it left behind. */
    failures += mr_exec_gate_exit_nonzero();
    failures += mr_exec_gate_build_fails();
    failures += mr_exec_gate_build_outcomes();
    failures += mr_exec_gate_rebuilt_runner();
    failures += mr_exec_gate_timeout();
    /* The workspace goes back to its base once the change is durable. */
    failures += mr_failures_restore();
    return failures;
}

/* The production glue refuses without a host whenever direction is
 * missing or unusable. These cases prove the refusal happens before
 * any model submission: no fake host is forked at all. */
static int mr_glue_job(struct wkr_job *job, const struct mr_dirs *d,
    const char *task)
{
    memset(job, 0, sizeof(*job));
    if (snprintf(job->rundir, sizeof(job->rundir), "%s", d->run) >=
        (int)sizeof(job->rundir))
        return -1;
    if (snprintf(job->name, sizeof(job->name), "u1") >=
        (int)sizeof(job->name))
        return -1;
    if (snprintf(job->kind, sizeof(job->kind), "leaf") >=
        (int)sizeof(job->kind))
        return -1;
    job->attempt = 1;
    job->seq = 7;
    if (snprintf(job->task, sizeof(job->task), "%s", task) >=
        (int)sizeof(job->task))
        return -1;
    job->token_cap = 200000;
    job->time_cap_s = 600;
    return 0;
}

static int mr_failures_glue(void)
{
    int failures = 0;
    struct mr_dirs d;
    struct wkr_job job;
    struct wkr_result res;
    char task[1024], model[161];
    MR_CHECK("glue lane", mr_lane(&d));
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue null job",
        zcl_devagent_worker_muse_executor(NULL, &res) == false);
    memset(&job, 0, sizeof(job));
    MR_CHECK("glue null res",
        zcl_devagent_worker_muse_executor(&job, NULL) == false);
    /* No muse direction at all: refused, reason names the header. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n\nJust do it.\n")
        == 0);
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue bare refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue bare verdict", strcmp(res.terminal, "refused") == 0 &&
        res.rc == 1);
    MR_CHECK("glue bare reason",
        strstr(res.evidence, "muse-workspace") != NULL);
    /* Unusable workspace: refused before any host. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /nonexistent-wt\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue workspace refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue workspace verdict", strcmp(res.terminal, "refused")
        == 0 && res.rc == 1);
    /* Missing rundir: refused before any host. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /tmp\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    if (snprintf(job.rundir, sizeof(job.rundir), "/nonexistent-run")
        >= (int)sizeof(job.rundir)) {
        MR_CHECK("glue rundir fit", false);
    } else {
        memset(&res, 0, sizeof(res));
        MR_CHECK("glue rundir refused",
            zcl_devagent_worker_muse_executor(&job, &res) == true);
        MR_CHECK("glue rundir verdict", strcmp(res.terminal, "refused")
            == 0 && res.rc == 1);
    }
    /* Zero token cap: refused, never unbounded. */
    MR_CHECK("glue task",
        mr_glue_job(&job, &d,
            "name=u1\nkind=leaf\nattempt=1\nmodel=\n"
            "muse-workspace: /tmp\nmuse-scope: src/\n"
            "muse-gate: g\n\nDo it.\n") == 0);
    job.token_cap = 0;
    memset(&res, 0, sizeof(res));
    MR_CHECK("glue cap refused",
        zcl_devagent_worker_muse_executor(&job, &res) == true);
    MR_CHECK("glue cap verdict", strcmp(res.terminal, "refused") == 0 &&
        res.rc == 1);
    memset(model, 'x', sizeof(model) - 1);
    model[sizeof(model) - 1] = '\0';
    (void)snprintf(task, sizeof(task),
        "muse-workspace: /tmp\nmuse-scope: src/\nmuse-gate: g\n"
        "muse-model: %s\n\nDo it.\n", model);
    MR_CHECK("glue oversized model task", mr_glue_job(&job, &d, task) == 0);
    (void)snprintf(job.model, sizeof(job.model), "fallback-model");
    mr_glue_calls = 0;
    MR_CHECK("glue oversized model refuses",
        mr_glue_executor(&job, &res) && strcmp(res.terminal, "refused") == 0 &&
        strstr(res.evidence, "model does not fit") != NULL);
    MR_CHECK("glue oversized model never runs", mr_glue_calls == 0);
    (void)snprintf(task, sizeof(task),
        "muse-workspace: /tmp\nmuse-scope: src/\nmuse-gate: g\n"
        "muse-model: chosen-model\n\nDo it.\n");
    MR_CHECK("glue chosen model task", mr_glue_job(&job, &d, task) == 0);
    (void)snprintf(job.model, sizeof(job.model), "fallback-model");
    mr_glue_calls = 0;
    (void)mr_glue_executor(&job, &res);
    MR_CHECK("glue chosen model forwarded", mr_glue_calls == 1 &&
        strcmp(mr_glue_model, "chosen-model") == 0);
    {
        char maximum[sizeof(((struct muse_run_task *)0)->model)];
        memset(maximum, 'm', sizeof(maximum) - 1);
        maximum[sizeof(maximum) - 1] = '\0';
        (void)snprintf(task, sizeof(task),
            "muse-workspace: /tmp\nmuse-scope: src/\nmuse-gate: g\n"
            "muse-model: %s\n\nDo it.\n", maximum);
        MR_CHECK("glue maximum model task", mr_glue_job(&job, &d, task) == 0);
        (void)snprintf(job.model, sizeof(job.model), "fallback-model");
        mr_glue_calls = 0;
        (void)mr_glue_executor(&job, &res);
        MR_CHECK("glue maximum model forwarded", mr_glue_calls == 1 &&
            strcmp(mr_glue_model, maximum) == 0);
    }
    (void)snprintf(task, sizeof(task),
        "muse-workspace: /tmp\nmuse-scope: src/\nmuse-gate: g\n"
        "muse-model: \n\nDo it.\n");
    MR_CHECK("glue empty model task", mr_glue_job(&job, &d, task) == 0);
    (void)snprintf(job.model, sizeof(job.model), "fallback-model");
    mr_glue_calls = 0;
    (void)mr_glue_executor(&job, &res);
    MR_CHECK("glue empty model falls back", mr_glue_calls == 1 &&
        strcmp(mr_glue_model, "fallback-model") == 0);
    (void)snprintf(task, sizeof(task),
        "muse-workspace: /tmp\nmuse-scope: src/\nmuse-gate: g\n\nDo it.\n");
    MR_CHECK("glue absent model task", mr_glue_job(&job, &d, task) == 0);
    (void)snprintf(job.model, sizeof(job.model), "fallback-model");
    mr_glue_calls = 0;
    (void)mr_glue_executor(&job, &res);
    MR_CHECK("glue absent model falls back", mr_glue_calls == 1 &&
        strcmp(mr_glue_model, "fallback-model") == 0);
    return failures;
}

static int mr_fold_close_success(const struct mr_dirs *d)
{
    char hex[64], why[MUSE_FOLD_NOTE_MAX], path[8192], identity[64];
    char *fold = NULL;
    int failures = 0;
    MR_CHECK("ordinary fold close succeeds", mr_fault_candidate_fold(d->wt, d->run,
        hex, sizeof(hex), &fold, why, sizeof(why)));
    MR_CHECK("ordinary fold complete", fold && strstr(fold, "+new") && why[0] == '\0');
    MR_CHECK("ordinary fold artifact identity", fold &&
        mr_path_in(d->run, "fold.diff", path, sizeof(path)) && mr_write(path, fold, 0) &&
        mrr_hash_file(path, identity, sizeof(identity)) && strcmp(hex, identity) == 0);
    (void)mrr_fold_failed(hex, sizeof(hex), &fold, fold, NULL, 0, "");
    return failures;
}

static int mr_fold_close_failure(void)
{
    struct mr_dirs d;
    char hex[64], why[MUSE_FOLD_NOTE_MAX], path[8192];
    char *fold = NULL;
    int failures = 0;
    if (!mr_lane(&d) || !mr_seed_committed(&d, "src/fold.c", "old\n") ||
        !mr_path_in(d.wt, "src/fold.c", path, sizeof(path)) ||
        !mr_write(path, "new\n", 0)) return 1;
    mr_fold_refuse = true;
    mr_fold_closes = 0;
    MR_CHECK("fold close refusal", !mr_fault_candidate_fold(d.wt, d.run,
        hex, sizeof(hex), &fold, why, sizeof(why)));
    MR_CHECK("fold close injected once", mr_fold_closes == 1 && !mr_fold_refuse);
    MR_CHECK("refused fold has no identity", strcmp(hex, "none") == 0 && fold == NULL);
    MR_CHECK("fold refusal names write/close", strstr(why, "close") != NULL);
    (void)mrr_fold_failed(hex, sizeof(hex), &fold, fold, NULL, 0, "");
    MR_CHECK("fold temporary path", mr_path_in(d.run, ".candidate.in", path, sizeof(path)));
    MR_CHECK("refused fold temporary removed", access(path, F_OK) != 0 && errno == ENOENT);
    return failures + mr_fold_close_success(&d);
}

int test_devagent_muse_run(void)
{
    int failures = 0;
    (void)mr_fake_lifecycle_refs;
    failures += mr_fold_close_failure();
    for (int fault = 0; fault < 4; ++fault) failures += mr_failures_evidence(fault);
    failures += mr_failures_validate();
    failures += mr_failures_parse();
    failures += mr_failures_precheck();
    failures += mr_failures_execute();
    failures += mr_failures_glue();
    if (failures == 0) printf("muse_run: all groups green\n");
    return failures;
}
#endif
