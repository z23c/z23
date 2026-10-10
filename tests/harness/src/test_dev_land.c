/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.land (tools/command/native_dev_land.c).
 *
 * Queue cases use isolated state and real git rigs, with the exact proof
 * replaced by ZCL_LAND_PROOF_STUB. Rebase, push, rows and locks use the
 * production paths. Watcher-admission cases separately use inert scheduler
 * fixtures to exercise structured arguments, refusal and a bounded timeout;
 * they cannot establish real watcher or proof readiness.
 *
 * The handler is called DIRECTLY, which is exactly what the CLI does after
 * input validation — and the input is additionally validated through the
 * real registry first, so a key the .def never declared is caught here
 * rather than passing in-process and failing from a shell.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_land_regen.h"
#include "command/native_dev_land_attestation.h"
#include "platform/logical_cpu.h"
#include "platform/state_root.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include "dev/dev_git_tree.h"
#include "dev/dev_proof.h"
#include "dev/dev_proof_signer.h"
#include "dev/dev_proof_budget.h"
#include "dev/devloop.h"
#include "base/bytes.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"

/* Hermetic seams from native_dev_land.c (ZCL_TESTING build): the idle-note
 * judgment dl_proof_read applies to a real proof status, and its bound. */
bool zcl_native_dev_land_test_idle_note(int64_t age_s, char *detail,
                                        size_t cap);
int64_t zcl_native_dev_land_test_idle_bound(void);
/* The drive's base probe (dl_base_observe) against one worktree's origin. */
int zcl_native_dev_land_test_base_observe(const char *wt, const char *base);
bool zcl_native_dev_land_test_chain_codec(const char *line, char *out, size_t cap);
int zcl_native_dev_land_test_chain_relation(const char *line,
    const char *const *lines, size_t count, const char *main, long long *waiting);
#if !defined(_WIN32)
/* dl_base_probe() watching an already-forked worker, as dl_drive_proof()
 * does, through the proof's own requester wait loop. */
int zcl_native_dev_land_test_watch_worker(const char *wt, const char *base,
                                          int worker_pid, int interval_ms,
                                          bool *superseded);
#endif
#if defined(__linux__)
void zcl_native_dev_land_test_watcher_launch(const char *wt,
    const char *scheduler, char *detail, size_t cap);
#endif
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_publication.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
void zcl_native_dev_land_test_pick_barrier(int ready_fd, int release_fd);
bool zcl_native_dev_land_test_producer_stale(const char *detail);
int zcl_native_dev_land_test_range_adds_source(const char *wt,
                                               const char *base,
                                               const char *local);
int zcl_native_dev_land_test_producer_reproof(const char *root,
                                              const char *local,
                                              const char *base,
                                              const char *make_program,
                                              char *why, size_t why_cap);
#endif

#define DLX_PATH "dev.land"

/* ── isolated state root ───────────────────────────────────────────────── */

static char g_dlx_state[1024];
static char g_dlx_saved_xdg[4096];
static bool g_dlx_had_xdg;

#if !defined(_WIN32)
/* The landing worktree now pushes through a real installed pre-push hook
 * (no more --no-verify), and dev.land arms that hook itself by running
 * `make install-hooks` in the landing worktree. The rigs below are a bare
 * origin plus a throwaway clone — not a checkout of this repository — so
 * there is no Makefile there to run. ZCL_LAND_HOOKS_STUB_DIR is dev.land's
 * test-only escape hatch for exactly that: it points at a fixture
 * directory holding a real executable `pre-push` script instead. A default
 * no-op (exit 0) hook is armed for every isolated test below so ordinary
 * cases behave as before; the one test that needs to prove the hook is
 * actually consulted installs a refusing one instead. */
static char g_dlx_hooks_ok[1024];

/* Forward declared: defined below alongside the rest of the git-rig
 * helpers (dlx_write in particular), which dlx_isolate() needs before that
 * point in the file. */
static bool dlx_hooks_dir(char *out, size_t cap, const char *tag,
                          int exit_code);
#endif

static void dlx_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "dev_land", tag);
    (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s/state", base);
    g_dlx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_dlx_had_xdg)
        (void)snprintf(g_dlx_saved_xdg, sizeof(g_dlx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_dlx_state, 1);
    unsetenv("ZCL_LAND_PROOF_STUB");
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    unsetenv("ZCL_LAND_HOOKS_STUB_DIR");
    unsetenv("ZCL_LAND_TEST_PICK_DELAY_MS");
    unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_PROOF");
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
    unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
    unsetenv("ZCL_LAND_WINDOW");
    unsetenv("ZCL_LAND_WINDOW_HOST");
    /* The vendor/tor submodule fixtures below add a real gitlink pointing
     * at a same-host bare repo; modern git's default transport allowlist
     * otherwise refuses a local `file://`-style remote reached through
     * `git submodule update --init`. This is a process-local env var, not
     * a persistent git config write. */
    setenv("GIT_ALLOW_PROTOCOL", "file:http:https:git:ssh", 1);
#if !defined(_WIN32)
    if (dlx_hooks_dir(g_dlx_hooks_ok, sizeof(g_dlx_hooks_ok), tag, 0))
        setenv("ZCL_LAND_HOOKS_STUB_DIR", g_dlx_hooks_ok, 1);
#endif
}

static void dlx_restore(void)
{
    if (g_dlx_had_xdg)
        setenv("XDG_STATE_HOME", g_dlx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
    unsetenv("ZCL_LAND_PROOF_STUB");
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    unsetenv("ZCL_LAND_HOOKS_STUB_DIR");
    unsetenv("ZCL_LAND_TEST_PICK_DELAY_MS");
    unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_PROOF");
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
    unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
    unsetenv("ZCL_LAND_WINDOW");
    unsetenv("ZCL_LAND_WINDOW_HOST");
    unsetenv("GIT_ALLOW_PROTOCOL");
}

static void dlx_landdir(char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/z23/dev/land", g_dlx_state);
}

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dlx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlx_begin(struct dlx_call *c, const char *action)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land.v1");
    if (action)
        (void)json_push_kv_str(&c->input, "action", action);
}

static bool dlx_run(struct dlx_call *c)
{
    char why[256];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_land(&c->request, &c->reply);
    return true;
}

static void dlx_end(struct dlx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Serialize the actual captured result without dispatching another push. */
static const struct zcl_command_reply *g_dlx_captured_reply;

static void dlx_captured_handler(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    (void)request;
    json_free(&reply->data);
    *reply = *g_dlx_captured_reply;
    json_init(&reply->data);
    json_copy(&reply->data, &g_dlx_captured_reply->data);
}

static bool dlx_refusal_serializes(const struct dlx_call *call)
{
    if (!call->request.spec) return false;
    struct zcl_command_spec spec = *call->request.spec;
    spec.handler = dlx_captured_handler;
    char wire[8192];
    enum zcl_command_exit code;
    g_dlx_captured_reply = &call->reply;
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        &spec, NULL, &call->input, false, DLX_PATH, NULL, 0, 0, NULL,
        wire, sizeof(wire), &code);
    g_dlx_captured_reply = NULL;
    struct json_value doc;
    json_init(&doc);
    bool ok = len > 0 && code == ZCL_COMMAND_EXIT_BLOCKED &&
        json_read(&doc, wire, len);
    const struct json_value *error = json_get(&doc, "error");
    const char *error_code = json_get_str(json_get(error, "code"));
    const char *action = json_get_str(json_get(error, "next_action"));
    ok = ok && error_code && strcmp(error_code, call->reply.error.code) == 0 &&
        action && strcmp(action, "z23-dev dev land step") == 0 &&
        json_get_bool(json_get(error, "retryable")) == call->reply.error.retryable &&
        json_get_bool(json_get(error, "mutated")) == call->reply.error.mutated;
    json_free(&doc);
    return ok;
}

static bool dlx_ok(const struct dlx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dlx_str(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dlx_int(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *dlx_arr(const struct dlx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *dlx_err_code(const struct dlx_call *c)
{
    return c->reply.error.code;
}

static const char *dlx_err_evidence(const struct dlx_call *c)
{
    return c->reply.error.evidence;
}

#if !defined(_WIN32)

/* ── a real git rig: a bare origin and a clone ─────────────────────────── */

static int dlx_git(const char *dir, const char *const *args)
{
    const char *argv[24];
    size_t n = 0;
    char sink[4096];
    argv[n++] = "git";
    if (dir) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    return zcl_spawn_capture(argv, sink, sizeof(sink), 60000);
}

static int dlx_git_out(const char *dir, const char *const *args, char *out,
                       size_t cap)
{
    const char *argv[24];
    size_t n = 0;
    int rc;
    argv[n++] = "git";
    if (dir) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    rc = zcl_spawn_capture(argv, out, cap, 60000);
    for (size_t i = strlen(out); i > 0; i--) {
        if (out[i - 1] == '\n' || out[i - 1] == '\r')
            out[i - 1] = '\0';
        else
            break;
    }
    return rc;
}

static bool dlx_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

#if !defined(_WIN32)
/* mkdir -p, for planting a fake dependency file several directories deep
 * (vendor/tor/src/ext/ed25519/donna/...) under a throwaway rig clone. */
static bool dlx_mkdir_p(const char *path)
{
    char buf[1200];
    size_t len = path ? strlen(path) : 0;
    char *p;
    if (!len || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0700) != 0 && errno != EEXIST)
                return false;
            *p = '/';
        }
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

/* Plant a fake proof-generation dependency (or its stand-in) at `rel`
 * under `root`, creating whatever directories `rel` needs. Content is
 * irrelevant: dl_wt_vendor_ensure()/dl_wt_hotswap_ensure() only ever check
 * for existence and copy bytes, they never open a vendored archive or
 * parse a fixture image. */
static bool dlx_write_dep(const char *root, const char *rel,
                          const char *body)
{
    char path[1400], dir[1400], *slash;
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", root, rel) >=
        sizeof(path))
        return false;
    (void)snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    return dlx_mkdir_p(dir) && dlx_write(path, body);
}
#endif

/* A fixture hooks directory holding one executable `pre-push` script that
 * exits `exit_code`. Pointed at through ZCL_LAND_HOOKS_STUB_DIR in place of
 * `make install-hooks`, which the throwaway rigs below have no Makefile
 * to run. */
static bool dlx_hooks_dir(char *out, size_t cap, const char *tag,
                          int exit_code)
{
    char path[1200], body[64];
    test_make_tmpdir(out, cap, "dev_land_hooks", tag);
    (void)snprintf(path, sizeof(path), "%s/pre-push", out);
    (void)snprintf(body, sizeof(body), "#!/bin/sh\nexit %d\n", exit_code);
    if (!dlx_write(path, body))
        return false;
    return chmod(path, 0755) == 0;
}

struct dlx_rig {
    char bare[600];
    char clone[600];
    char tip[64];
};

/* A commit in the clone whose parent is origin/main, pushed nowhere. */
static bool dlx_commit(const char *dir, const char *name, const char *body,
                       char out[64])
{
    char path[1200];
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", name, NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (!dlx_write(path, body))
        return false;
    if (dlx_git(dir, add) != 0)
        return false;
    if (dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

/* NOTE: tag must differ from every other fixture tag in the same TEST —
 * test_make_tmpdir wipes and recreates its path. */
static bool dlx_rig_make(struct dlx_rig *rig, const char *tag)
{
    char base[512];
    const char *init_bare[] = { "init", "--quiet", "--bare",
                                "--initial-branch=main", rig->bare, NULL };
    const char *clone[] = { "clone", "--quiet", rig->bare, rig->clone,
                            NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    char seed[64];
    test_make_tmpdir(base, sizeof(base), "dev_land", tag);
    (void)snprintf(rig->bare, sizeof(rig->bare), "%s/origin.git", base);
    (void)snprintf(rig->clone, sizeof(rig->clone), "%s/clone", base);
    if (dlx_git(NULL, init_bare) != 0)
        return false;
    if (dlx_git(NULL, clone) != 0)
        return false;
    /* A checkout marker set, so the leaf's checkout-root walk and its own
     * worktree bookkeeping behave the way they do in a real tree. */
    if (!dlx_commit(rig->clone, "seed.txt", "seed\n", seed))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    if (dlx_git(rig->clone, fetch) != 0)
        return false;
    if (!dlx_commit(rig->clone, "change.txt", "one\n", rig->tip))
        return false;
    return true;
}

static bool dlx_file_exists(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

/* An installed hook name: a symlink whose target is the one native hook
 * binary, exactly what install_git_hooks.sh lays down and the hooks
 * refresh relinks. */
static bool dlx_hook_link(const char *path)
{
    struct stat st;
    char target[256];
    ssize_t n;
    if (!path || lstat(path, &st) != 0 || !S_ISLNK(st.st_mode))
        return false;
    n = readlink(path, target, sizeof(target) - 1);
    if (n <= 0)
        return false;
    target[n] = '\0';
    return strcmp(target, "z23-git-hook") == 0;
}

/* The submitting checkout's own hook build, which every forced-deps
 * fixture must now carry: the hooks refresh shares the forced prerequisite
 * set with vendor and hotswap materialization. */
static bool dlx_plant_hook_bin(const char *dir)
{
    return dlx_write_dep(dir, "build/bin/z23-git-hook", "hook\n");
}

/* Whole-file slurp for a byte-identical before/after comparison. Bounded:
 * queue.jsonl in these tests is a handful of rows, never near this cap. */
static bool dlx_slurp(const char *path, char *out, size_t cap, size_t *len)
{
    FILE *f = path ? fopen(path, "rb") : NULL;
    size_t n;
    if (!f)
        return false;
    n = fread(out, 1, cap, f);
    if (ferror(f) || (size_t)ftell(f) == cap) {
        fclose(f);
        return false;
    }
    fclose(f);
    if (len)
        *len = n;
    return true;
}

#if !defined(_WIN32)
/* Take dev.land's own step.lock exactly the way dl_step_lock() does —
 * open(O_RDWR|O_CREAT|O_CLOEXEC) then flock(LOCK_EX|LOCK_NB) on
 * `<landdir>/step.lock` — so the test proves the production leaf refuses a
 * SECOND holder of the very same advisory lock it takes internally, not a
 * stand-in. dl_step_lock()/dl_lock_path() are file-static, so a test in a
 * separate translation unit reaches the lock the only way another process
 * driving the queue would: by name, with the same open+flock discipline. */
static int dlx_step_lock_take(const char *landdir)
{
    char path[1200];
    int fd;
    if ((size_t)snprintf(path, sizeof(path), "%s/step.lock", landdir) >=
        sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void dlx_step_lock_release(int fd)
{
    if (fd < 0)
        return;
    (void)flock(fd, LOCK_UN);
    close(fd);
}

/* 1 when another process holds step.lock, 0 when free, -1 when the file
 * is absent or unreadable. Does not create the lock file. */
static int dlx_step_held(const char *landdir)
{
    char path[1200];
    int fd;
    int err;
    if (!landdir ||
        (size_t)snprintf(path, sizeof(path), "%s/step.lock", landdir) >=
            sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        return 0;
    }
    err = errno;
    (void)close(fd);
    if (err == EWOULDBLOCK || err == EAGAIN)
        return 1;
    return -1;
}
#endif

/* ── vendor/tor submodule fixtures ────────────────────────────────────────
 *
 * A gitlink entry (mode 160000) plus a .gitmodules record it in, staged
 * directly through `update-index --cacheinfo` rather than a real
 * `submodule add`: the object the gitlink names never has to exist for
 * dl_wt_vendor_tor_is_submodule()'s `ls-tree` check to see a real
 * submodule entry, which is all the init-failure ordering test below
 * needs. */
static bool dlx_gitlink_commit(const char *dir, const char *path,
                               const char *sha, const char *url,
                               char out_tip[64])
{
    char cacheinfo[160], gm_path[1200], gm_body[512];
    const char *update_index[] = { "update-index", "--add", "--cacheinfo",
                                   cacheinfo, NULL };
    const char *add[] = { "add", ".gitmodules", NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", "add vendor/tor gitlink",
                             NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if ((size_t)snprintf(cacheinfo, sizeof(cacheinfo), "160000,%s,%s", sha,
                         path) >= sizeof(cacheinfo))
        return false;
    if (dlx_git(dir, update_index) != 0)
        return false;
    (void)snprintf(gm_path, sizeof(gm_path), "%s/.gitmodules", dir);
    (void)snprintf(gm_body, sizeof(gm_body),
                  "[submodule \"%s\"]\n\tpath = %s\n\turl = %s\n", path,
                  path, url);
    if (!dlx_write(gm_path, gm_body))
        return false;
    if (dlx_git(dir, add) != 0)
        return false;
    if (dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out_tip, 64) == 0 &&
          strlen(out_tip) == 40;
}

/* A tiny local bare repo with two commits (rev_a, rev_b), used as
 * vendor/tor's own upstream for the mismatch fixture below: a real
 * `submodule add`/checkout against a same-host repo, no network. */
struct dlx_subrepo {
    char bare[600];
    char rev_a[64];
    char rev_b[64];
};

static bool dlx_subrepo_make(struct dlx_subrepo *sub, const char *tag)
{
    char base[512], work[700];
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    test_make_tmpdir(base, sizeof(base), "dev_land_sub", tag);
    (void)snprintf(sub->bare, sizeof(sub->bare), "%s/sub.git", base);
    (void)snprintf(work, sizeof(work), "%s/subwork", base);
    {
        const char *init_bare[] = { "init", "--quiet", "--bare",
                                    "--initial-branch=main", sub->bare,
                                    NULL };
        if (dlx_git(NULL, init_bare) != 0)
            return false;
    }
    {
        const char *clone[] = { "clone", "--quiet", sub->bare, work, NULL };
        if (dlx_git(NULL, clone) != 0)
            return false;
    }
    if (!dlx_commit(work, "a.txt", "a\n", sub->rev_a))
        return false;
    if (dlx_git(work, push) != 0)
        return false;
    if (!dlx_commit(work, "b.txt", "b\n", sub->rev_b))
        return false;
    if (dlx_git(work, push) != 0)
        return false;
    return true;
}

/* A real `git submodule add` of `url` at `path` inside `dir`, committed as
 * the new tip. protocol.file.allow=always is needed on modern git for a
 * same-host bare repo used as a submodule remote. */
static bool dlx_submodule_add(const char *dir, const char *url,
                              const char *path, char out_tip[64])
{
    const char *add[] = { "-c", "protocol.file.allow=always", "submodule",
                          "add", "--quiet", url, path, NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", "add vendor/tor",
                             NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if (dlx_git(dir, add) != 0)
        return false;
    if (dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out_tip, 64) == 0 &&
          strlen(out_tip) == 40;
}

/* Detach the submodule working tree at `dir`/`path` onto `rev`, without
 * touching the superproject's own index/gitlink: the drift a stale
 * submitting checkout would show against the tip it is landing. */
static bool dlx_submodule_checkout(const char *dir, const char *path,
                                   const char *rev)
{
    char sub_dir[900];
    const char *checkout[] = { "checkout", "--quiet", "--detach", rev,
                               NULL };
    if ((size_t)snprintf(sub_dir, sizeof(sub_dir), "%s/%s", dir, path) >=
        sizeof(sub_dir))
        return false;
    return dlx_git(sub_dir, checkout) == 0;
}

static void dlx_submit(struct dlx_call *c, const struct dlx_rig *rig,
                       const char *tip)
{
    dlx_begin(c, "submit");
    (void)json_push_kv_str(&c->input, "tip", tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
}

static bool dlx_queue_has_one(void)
{
    struct dlx_call c;
    dlx_begin(&c, "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "queued");
    ok = ok && rows && rows->num_children == 1;
    dlx_end(&c);
    return ok;
}

static bool dlx_submit_expect(const struct dlx_rig *rig, const char *tip,
                              long long seq, bool deduplicated)
{
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    bool ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == seq &&
              json_get_bool(json_get(&c.reply.data, "deduplicated")) ==
                  deduplicated;
    dlx_end(&c);
    return ok;
}

static bool dlx_exact_submit_retry(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char later[64];
    bool ok = true;
    dlx_isolate("submit_duplicate");
    if (!dlx_rig_make(&rig, "submit_duplicate_rig")) {
        ok = false;
        goto done;
    }
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (!dlx_submit_expect(&rig, rig.tip, 1, false) ||
        !dlx_submit_expect(&rig, rig.tip, 1, true) ||
        !dlx_queue_has_one()) {
        ok = false;
        goto done;
    }
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == 1;
    dlx_end(&c);
    if (!ok)
        goto done;
    if (!dlx_submit_expect(&rig, rig.tip, 1, true) ||
        !dlx_commit(rig.clone, "later.txt", "later\n", later)) {
        ok = false;
        goto done;
    }
    ok = dlx_submit_expect(&rig, later, 2, false);
done:
    dlx_restore();
    return ok;
}

static bool dlx_queue_empty(void)
{
    struct dlx_call c;
    dlx_begin(&c, "status");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "queued");
    ok = ok && rows && rows->num_children == 0;
    dlx_end(&c);
    return ok;
}

/* A submit from a worktree mid-rebase names no finished stack. Measured
 * 2026-09-30 on the live queue: a submit issued while a rebase still
 * replayed queued an incomplete stack (the tip resolved, was signed, and
 * shared history), burned a full proof cycle on it, and failed only on
 * generated-docs freshness — the one check that happened to notice. A
 * submit made then must refuse by name instead. */
static bool dlx_exact_submit_mid_rebase_refused(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok = true;
    char moved[64];
    const char *checkout_base[] = { "checkout", "-q", "-B", "base",
                                    "origin/main", NULL };
    const char *push_moved[] = { "push", "--quiet", "origin",
                                 "HEAD:main", NULL };
    const char *checkout_tip[] = { "checkout", "-q", "-B", "work", NULL,
                                   NULL };
    const char *start_rebase[] = { "rebase", "origin/main", NULL };
    const char *abort_rebase[] = { "rebase", "--abort", NULL };
    dlx_isolate("submit_mid_rebase");
    if (!dlx_rig_make(&rig, "submit_mid_rebase_rig")) {
        ok = false;
        goto done;
    }
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    /* Move origin/main under the tip with a conflicting edit of the same
     * file, so rebasing the tip onto it stops on the conflict and leaves
     * the clone holding an unfinished rebase. */
    if (dlx_git(rig.clone, checkout_base) != 0 ||
        !dlx_commit(rig.clone, "change.txt", "two\n", moved) ||
        dlx_git(rig.clone, push_moved) != 0) {
        ok = false;
        goto done;
    }
    checkout_tip[4] = rig.tip;
    if (dlx_git(rig.clone, checkout_tip) != 0 ||
        dlx_git(rig.clone, start_rebase) == 0) {
        /* A clean rebase means the fixture stopped nowhere: the arm would
         * prove nothing. */
        ok = false;
        goto done;
    }
    char marker[700];
    struct stat marker_stat;
    (void)snprintf(marker, sizeof(marker), "%s/.git/rebase-merge", rig.clone);
    if (stat(marker, &marker_stat) != 0 || !S_ISDIR(marker_stat.st_mode)) {
        ok = false;
        goto done;
    }
    dlx_submit(&c, &rig, rig.tip);
    ok = dlx_run(&c) && !dlx_ok(&c) && c.reply.error.code[0] != '\0' &&
         strcmp(c.reply.error.code, "WORKTREE_BUSY") == 0;
    dlx_end(&c);
    ok = ok && dlx_queue_empty();
    (void)dlx_git(rig.clone, abort_rebase);
done:
    dlx_restore();
    return ok;
}

static bool dlx_submit_marker_refused(struct dlx_rig *rig, const char *mark)
{
    char rel[4096], path[8192];
    const char *args[] = { "rev-parse", "--git-path", mark, NULL };
    if (dlx_git_out(rig->clone, args, rel, sizeof(rel)) != 0)
        return false;
    int n = rel[0] == '/' ? snprintf(path, sizeof(path), "%s", rel)
                         : snprintf(path, sizeof(path), "%s/%s", rig->clone, rel);
    if (n < 0 || (size_t)n >= sizeof(path) || !dlx_write(path, "fixture\n"))
        return false;
    struct dlx_call c;
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && !dlx_ok(&c) && c.reply.error.code[0] != '\0' &&
        strcmp(c.reply.error.code, "WORKTREE_BUSY") == 0;
    dlx_end(&c);
    if (unlink(path) != 0)
        return false;
    ok = ok && dlx_queue_empty();
    return ok;
}

static bool dlx_submit_operation_markers_refused(void)
{
    struct dlx_rig rig;
    bool ok = false;
    dlx_isolate("submit_operation_markers");
    if (!dlx_rig_make(&rig, "submit_operation_markers_rig"))
        goto done;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    char linked[600];
    (void)snprintf(linked, sizeof(linked), "%s-linked", rig.clone);
    const char *add[] = { "worktree", "add", "--detach", linked, rig.tip, NULL };
    if (dlx_git(rig.clone, add) != 0)
        goto done;
    (void)snprintf(rig.clone, sizeof(rig.clone), "%s", linked);
    static const char *const marks[] = { "rebase-merge", "rebase-apply",
        "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "sequencer" };
    ok = true;
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (!dlx_submit_marker_refused(&rig, marks[i])) {
            ok = false;
            break;
        }
    }
done:
    dlx_restore();
    return ok;
}

static bool dlx_failed_admission_visible(const char *expected_tip)
{
    struct dlx_call c;
    dlx_begin(&c, "status");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *outcomes = dlx_arr(&c, "outcomes");
    ok = ok && outcomes && outcomes->num_children == 2;
    if (ok) {
        const struct json_value *failed = &outcomes->children[1];
        const char *tip = json_get_str(json_get(failed, "tip"));
        const char *state = json_get_str(json_get(failed, "state"));
        ok = tip && state && strcmp(tip, expected_tip) == 0 &&
            strcmp(state, "failed") == 0;
    }
    dlx_end(&c);
    return ok;
}

static bool dlx_missing_submitter(const struct dlx_rig *rig)
{
    struct dlx_call c;
    char moved[4096];
    char second_tip[64];
    /* An independent receiver must preserve the admission even when the
     * submitting checkout disappears. Cancelling another row rewrites the
     * queue and must not erase the unavailable request. */
    if (!dlx_commit(rig->clone, "second.txt", "second\n", second_tip))
        return false;
    dlx_submit(&c, rig, second_tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    long long second = dlx_int(&c, "seq");
    dlx_end(&c);
    if (!ok || second != 2 ||
        snprintf(moved, sizeof(moved), "%s-moved", rig->clone) >= (int)sizeof(moved) ||
        rename(rig->clone, moved) != 0)
        return false;
    dlx_begin(&c, "cancel");
    (void)json_push_kv_int(&c.input, "seq", second);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || !dlx_queue_has_one())
        return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
        strcmp(dlx_str(&c, "state"), "failed") == 0;
    dlx_end(&c);
    return ok && dlx_failed_admission_visible(rig->tip) && rename(moved, rig->clone) == 0;
}

/* Run only in a child: cwd and fixture environment cannot leak to other cases. */
static bool dlx_receiver_continuity(const struct dlx_rig *rig, const char *receiver)
{
    return chdir(receiver) == 0 && dlx_queue_has_one() && dlx_missing_submitter(rig);
}

static bool dlx_queue_outside_home(const char *root)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char receiver[4096];
    if (!getcwd(receiver, sizeof(receiver)) || chdir(root) != 0 ||
        !dlx_write_dep(root, "Makefile", "# fixture\n") ||
        !dlx_write_dep(root, "engine/composition/commands/root.def", "// fixture\n") ||
        !dlx_write_dep(root, "tools/dev/test_group_catalog.def", "// fixture\n"))
        return false;
    dlx_isolate("outside_home");
    if (!dlx_rig_make(&rig, "outside_home_rig"))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, &rig, rig.tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok && dlx_queue_has_one() && chdir("engine") == 0 && dlx_queue_has_one() &&
        dlx_receiver_continuity(&rig, receiver);
}

static bool dlx_outside_home(const char *path)
{
    const char *home = getenv("HOME");
    char canonical_home[4096], canonical_path[4096];
    if (!home || !home[0] ||
        !platform_directory_canonical_real(home, canonical_home, sizeof(canonical_home)) ||
        !platform_directory_canonical_real(path, canonical_path, sizeof(canonical_path)))
        return false;
    size_t n = strlen(canonical_home);
    if (n == 1 && canonical_home[0] == '/')
        return false;
    return strncmp(canonical_path, canonical_home, n) != 0 ||
        (canonical_path[n] != '/' && canonical_path[n] != '\0');
}

static bool dlx_queue_outside_home_child(void)
{
    char root[PLATFORM_TEMP_PATH_MAX];
    int status = 0;
    if (!platform_temp_directory_create("z23-land-outside-home-", root, sizeof(root)))
        return false;
    bool outside = dlx_outside_home(root);
    pid_t child = outside ? fork() : -1;
    if (child == 0)
        _exit(dlx_queue_outside_home(root) ? 0 : 1);
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    int cleanup = test_rm_rf_recursive(root);
    return outside && child > 0 && waited == child && cleanup == 0 &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* origin/main as the bare repo itself reports it. */
static bool dlx_origin_main(const struct dlx_rig *rig, char out[64])
{
    const char *args[] = { "rev-parse", "main", NULL };
    return dlx_git_out(rig->bare, args, out, 64) == 0 && strlen(out) == 40;
}

/* Commit whatever is in `dir`'s working tree under `msg`. Unlike
 * dlx_commit() this plants no file of its own: the caller has already
 * written the paths it wants recorded (docs/... through dlx_write_dep()),
 * which is what a generated-artifact conflict fixture needs. */
static bool dlx_commit_tree(const char *dir, const char *msg, char out[64])
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", msg, NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if (dlx_git(dir, add) != 0 || dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

/* Make an initialised submodule look UNINITIALISED, the way
 * dl_wt_submodule_ready() defines it: the .git marker inside the
 * submodule's working tree is gone. A real `git submodule deinit` would
 * also drop the working-tree files these cases still need present, so the
 * marker alone is the minimal, precise fixture. */
static bool dlx_submodule_uninit(const char *dir, const char *path)
{
    char marker[900];
    if ((size_t)snprintf(marker, sizeof(marker), "%s/%s/.git", dir, path) >=
        sizeof(marker))
        return false;
    return remove(marker) == 0;
}

/* Arm REAL commit signing in the rig, repo-wide, the way the maintainer
 * host arms it: an ssh key this fixture generates, an allowed-signers file
 * so `%G?` can actually verify what it produced, and commit.gpgsign on.
 * The landing worktree is a `git worktree add` off this clone and shares
 * its config, so a commit dev.land makes there is signed by AMBIENT config
 * alone — which is the property under test: the leaf passes no signing
 * flag of its own, exactly like dev.train's regenerate-docs commit. */
static bool dlx_sign_arm(const char *dir, const char *tag)
{
    char base[512], key[700], pub[720], allowed[760], line[1600];
    char pubtext[1024], sink[4096];
    const char *keygen[] = { "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                             "-C", "dev-land-fixture", "-f", key, NULL };
    const char *c_format[] = { "config", "gpg.format", "ssh", NULL };
    const char *c_key[] = { "config", "user.signingkey", pub, NULL };
    const char *c_sign[] = { "config", "commit.gpgsign", "true", NULL };
    const char *c_allow[] = { "config", "gpg.ssh.allowedSignersFile",
                              allowed, NULL };
    const char *c_name[] = { "config", "user.name", "land", NULL };
    const char *c_mail[] = { "config", "user.email", "land@z23.invalid",
                             NULL };
    FILE *f;
    test_make_tmpdir(base, sizeof(base), "dev_land_sign", tag);
    (void)snprintf(key, sizeof(key), "%s/k", base);
    (void)snprintf(pub, sizeof(pub), "%s/k.pub", base);
    (void)snprintf(allowed, sizeof(allowed), "%s/allowed_signers", base);
    if (zcl_spawn_capture(keygen, sink, sizeof(sink), 60000) != 0)
        return false;
    f = fopen(pub, "rb");
    if (!f)
        return false;
    if (!fgets(pubtext, sizeof(pubtext), f)) {
        (void)fclose(f);
        return false;
    }
    (void)fclose(f);
    (void)snprintf(line, sizeof(line), "land@z23.invalid %s", pubtext);
    if (!dlx_write(allowed, line))
        return false;
    return dlx_git(dir, c_format) == 0 && dlx_git(dir, c_key) == 0 &&
          dlx_git(dir, c_sign) == 0 && dlx_git(dir, c_allow) == 0 &&
          dlx_git(dir, c_name) == 0 && dlx_git(dir, c_mail) == 0;
}

/* Write the fixture artifacts, retaining every optional write refusal. */
static bool dlx_regen_files(struct dlx_rig *rig, const char *body,
                            const char *map_body, const char *third,
                            const char *extra)
{
    return dlx_write_dep(rig->clone, "docs/CAPABILITY_INVENTORY.jsonl", body) &&
           dlx_write_dep(rig->clone, "docs/CODEBASE_MAP.md", map_body) &&
           (!third || dlx_write_dep(rig->clone, third, body)) &&
           (!extra || dlx_write_dep(rig->clone, extra, body));
}

/* A rig whose origin and whose submitted tip regenerate the SAME generated
 * artifacts differently, so `git rebase origin/main` reports exactly those
 * paths as unmerged. `extra` (may be NULL) is one more path both sides
 * change, for the mixed-conflict case that must stay a plain conflict.
 * `out_tip` receives the tip to submit. */
static bool dlx_regen_conflict(struct dlx_rig *rig, const char *extra,
                               char out_tip[64])
{
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *branch[] = { "branch", "keep-tip", NULL };
    char basec[64], theirs[64];
    const char *reset[] = { "reset", "--quiet", "--hard", basec, NULL };
    /* A shared base both sides agree on, on origin/main. */
    if (!dlx_regen_files(rig, "base\n",
            "<!-- DOC-COUNTS-BEGIN -->\nbase\n<!-- DOC-COUNTS-END -->\n",
            "docs/API_REFERENCE.md", extra))
        return false;
    if (!dlx_commit_tree(rig->clone, "generated artifacts", basec))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    /* The submitted tip: its own real work, plus its regeneration of two
     * of the three artifacts. */
    if (!dlx_regen_files(rig, "mine\n",
            "<!-- DOC-COUNTS-BEGIN -->\nmine\n<!-- DOC-COUNTS-END -->\n",
            "mine.txt", extra))
        return false;
    if (!dlx_commit_tree(rig->clone, "the submitted work", out_tip))
        return false;
    /* Keep it reachable while the clone's own branch rewinds. */
    if (dlx_git(rig->clone, branch) != 0)
        return false;
    if (dlx_git(rig->clone, reset) != 0)
        return false;
    /* origin/main lands someone else's train, which regenerated the same
     * two artifacts from ITS code. */
    if (!dlx_regen_files(rig, "theirs\n",
            "<!-- DOC-COUNTS-BEGIN -->\ntheirs\n<!-- DOC-COUNTS-END -->\n",
            NULL, extra))
        return false;
    if (!dlx_commit_tree(rig->clone, "someone else's train", theirs))
        return false;
    return dlx_git(rig->clone, push) == 0;
}

/* Reproduce the host configuration that hid a generated-file conflict from
 * dev.land: rerere has a previous resolution and autoupdate stages it during
 * rebase. First teach rerere the exact conflict with a throwaway merge, then
 * verify a raw rebase leaves no unmerged path before giving the same tip to
 * the lander. The fixture changes only its isolated Git rig. */
static bool dlx_rerere_autoupdate_prime(struct dlx_rig *rig)
{
    char upstream[64], unmerged[512];
    const char *enable[] = { "config", "rerere.enabled", "true", NULL };
    const char *autoupdate[] = { "config", "rerere.autoupdate", "true", NULL };
    const char *merge[] = { "merge", "--no-ff", "keep-tip", NULL };
    const char *ours[] = { "checkout", "--ours", "--",
                           "docs/CAPABILITY_INVENTORY.jsonl",
                           "docs/CODEBASE_MAP.md", NULL };
    const char *rerere[] = { "rerere", NULL };
    const char *merge_abort[] = { "merge", "--abort", NULL };
    const char *checkout_tip[] = { "checkout", "--quiet", "keep-tip", NULL };
    const char *rebase[] = { "rebase", upstream, NULL };
    const char *diff_u[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    const char *rebase_abort[] = { "rebase", "--abort", NULL };
    const char *checkout_main[] = { "checkout", "--quiet", "main", NULL };

    if (!dlx_origin_main(rig, upstream) ||
        dlx_git(rig->clone, enable) != 0 ||
        dlx_git(rig->clone, autoupdate) != 0 ||
        dlx_git(rig->clone, merge) == 0 ||
        dlx_git(rig->clone, ours) != 0 ||
        dlx_git(rig->clone, rerere) != 0 ||
        dlx_git(rig->clone, merge_abort) != 0 ||
        dlx_git(rig->clone, checkout_tip) != 0)
        return false;
    bool stopped = dlx_git(rig->clone, rebase) != 0;
    bool staged = stopped &&
        dlx_git_out(rig->clone, diff_u, unmerged, sizeof(unmerged)) == 0 &&
        unmerged[0] == '\0';
    return dlx_git(rig->clone, rebase_abort) == 0 &&
           dlx_git(rig->clone, checkout_main) == 0 && staged;
}

/* The landing worktree's checkout directory, where the regeneration commit
 * this leaf makes has to be observable. */
static void dlx_land_wt(char *out, size_t cap)
{
    char land[1200];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(out, cap, "%s/wt", land);
}

/* `git add -A` then commit whatever is staged — dlx_commit() only ever
 * writes and commits ONE file; the docregen rig below needs a Makefile
 * plus three tracked doc files landing in a single seed commit. */
static bool dlx_commit_all(const char *dir, const char *name, char out[64])
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "-c", "user.name=land",
                             "-c", "user.email=land@z23.invalid",
                             "commit", "--quiet", "--no-verify",
                             "--no-gpg-sign", "-m", name, NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if (dlx_git(dir, add) != 0)
        return false;
    if (dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

/* A rig carrying a real (but trivial) Makefile with the three targets
 * native_dev_land_regen.c's regen phase runs after every successful
 * rebase (docs-capability-inventory, docs-executor-routing,
 * fix-doc-counts), plus the one tracked doc file each target owns. The
 * three `*_recipe` strings are literal tab-indented Makefile recipe lines
 * (e.g. "@:" for a no-op, or a shell one-liner that dirties or refuses),
 * exercised through the SAME code path as a real landing worktree: the
 * regen phase itself carries no test-only stub, it just finds this
 * Makefile absent everywhere else and present here (see
 * native_dev_land_regen.c's TEST SEAM comment). */
static bool dlx_rig_make_docregen(struct dlx_rig *rig, const char *tag,
                                  const char *cap_recipe,
                                  const char *routing_recipe,
                                  const char *counts_recipe)
{
    char base[512], makefile_body[1024], jobs[16];
    const char *init_bare[] = { "init", "--quiet", "--bare",
                                "--initial-branch=main", rig->bare, NULL };
    const char *clone[] = { "clone", "--quiet", rig->bare, rig->clone,
                            NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    char seed[64];
    if (!platform_build_jobs_arg(jobs))
        return false;
    test_make_tmpdir(base, sizeof(base), "dev_land", tag);
    (void)snprintf(rig->bare, sizeof(rig->bare), "%s/origin.git", base);
    (void)snprintf(rig->clone, sizeof(rig->clone), "%s/clone", base);
    if (dlx_git(NULL, init_bare) != 0)
        return false;
    if (dlx_git(NULL, clone) != 0)
        return false;
    /* The plan-refresh target the regen phase's dlrg_plan_refresh() runs
     * when it observed any artifact's stat identity change: a trivial
     * recipe that appends one marker line, so tests can tell how many
     * times (if any) it ran from the resulting line count, exactly the
     * observable this rig's fixed make-based mechanics give a test
     * without a real dev build. */
    if ((size_t)snprintf(makefile_body, sizeof(makefile_body),
                         "docs-capability-inventory:\n\t%s\n"
                         "docs-executor-routing:\n\t%s\n"
                         "fix-doc-counts:\n\t%s\n"
                         "build/dev-loop/restart.env:\n"
                         "\t@test '$(filter %s,$(MAKEFLAGS))' = '%s' || "
                         "{ echo 'FAIL restart plan build job count'; exit 1; }\n"
                         "\t@mkdir -p build/dev-loop\n"
                         "\t@printf 'plan\\n' >> build/dev-loop/"
                         "restart.env\n",
                         cap_recipe, routing_recipe, counts_recipe,
                         jobs, jobs) >=
            sizeof(makefile_body))
        return false;
    if (!dlx_write_dep(rig->clone, "Makefile", makefile_body))
        return false;
    if (!dlx_write_dep(rig->clone, "docs/CAPABILITY_INVENTORY.jsonl",
                       "orig\n") ||
        !dlx_write_dep(rig->clone, "docs/agent/EXECUTOR_HEURISTICS.md",
                       "orig\n") ||
        !dlx_write_dep(rig->clone, "docs/CODEBASE_MAP.md", "orig\n"))
        return false;
    if (!dlx_commit_all(rig->clone, "seed", seed))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    if (dlx_git(rig->clone, fetch) != 0)
        return false;
    if (!dlx_commit(rig->clone, "change.txt", "one\n", rig->tip))
        return false;
    return true;
}

static int test_dev_land_integrated_merge(bool signing_failure)
{
    int failures = 0;
    TEST("land: an integrated upstream merge preserves its resolved tree") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], observed[64], landwt[1300], prepared[64], tree[64], base[64];
        const char *checkout[] = { "checkout", "--quiet", "keep-tip", NULL };
        const char *merge[] = { "-c", "user.name=land", "-c",
            "user.email=land@z23.invalid", "merge", "--quiet",
            "-s", "ours", "-m", "resolved integration",
            "origin/main", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *remote[] = { "rev-parse", "main", NULL };
        const char *ancestor[] = { "merge-base", "--is-ancestor",
            "origin/main", "HEAD", NULL };
        const char *resolved[] = { "show", "HEAD:change.txt", NULL };
        const char *tree_args[] = { "rev-parse", "HEAD^{tree}", NULL };
        const char *base_args[] = { "rev-parse", "origin/main", NULL };
        const char *parent_args[] = { "show", "-s", "--format=%P", "HEAD", NULL };
        const char *signature_args[] = { "log", "-1", "--format=%G?", NULL };
        const char *message_args[] = { "log", "-1", "--format=%B", NULL };
        dlx_isolate(signing_failure ? "merge_signfail" : "integratedmerge");
        ASSERT(dlx_rig_make(&rig, signing_failure ? "merge_signfail_rig" : "integratedmerge_rig"));
        ASSERT(dlx_regen_conflict(&rig, "change.txt", tip));
        ASSERT(dlx_sign_arm(rig.clone, signing_failure ? "merge_signfail_key" : "integratedmerge_sign"));
        ASSERT(dlx_git(rig.clone, checkout) == 0);
        /* Both parents changed the same source. This fixture's explicit
         * resolution keeps the submitted version, then integrates main. */
        ASSERT(dlx_git(rig.clone, merge) == 0);
        ASSERT(dlx_git(rig.clone, ancestor) == 0);
        ASSERT(dlx_git_out(rig.clone, head, tip, sizeof(tip)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree_args, tree, sizeof(tree)) == 0);
        ASSERT(dlx_git_out(rig.clone, base_args, base, sizeof(base)) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        if (signing_failure) {
            const char *broken_signer[] = { "config", "gpg.ssh.program", "false", NULL };
            ASSERT(dlx_git(rig.clone, broken_signer) == 0);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        if (signing_failure) {
            ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
            ASSERT_STR_EQ(dlx_str(&c, "phase"), "rebase");
            ASSERT_STR_EQ(dlx_str(&c, "detail"),
                "cannot prepare a tree-preserving linear landing candidate");
            dlx_end(&c);
            ASSERT(dlx_git_out(rig.bare, remote, observed, sizeof(observed)) == 0);
            ASSERT_STR_EQ(observed, base);
            PASS();
            goto _test_next;
        }
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_STR_EQ(dlx_str(&c, "tip"), tip);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, head, prepared, sizeof(prepared)) == 0);
        ASSERT(strcmp(prepared, tip) != 0);
        ASSERT(dlx_git_out(landwt, tree_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, tree);
        ASSERT(dlx_git_out(landwt, parent_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, base);
        ASSERT(dlx_git_out(landwt, signature_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, "G");
        char message[512], expected[512];
        (void)snprintf(expected, sizeof(expected),
            "Prepare integrated candidate for linear publication\n\n"
            "Original-Candidate: %s\nIntegrated-Base: %s\nSource-Tree: %s",
            tip, base, tree);
        ASSERT(dlx_git_out(landwt, message_args, message, sizeof(message)) == 0);
        ASSERT_STR_EQ(message, expected);
        ASSERT(dlx_git_out(landwt, resolved, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, "mine");
        /* The signed integrated candidate is established. Permit this
         * fixture's stubbed proof through the unsigned publication seam. */
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, prepared);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The regen phase folds generated-doc drift after a clean rebase INTO the
 * candidate's own last commit: no "Regenerate ..." commit appears, the tip
 * keeps its subject and author, its tree carries the regenerated file, the
 * amend is signed by the same ambient configuration as every landing commit,
 * and the id the proof is bound to is exactly the id that gets pushed. */
static int test_dev_land_regen_commits_drift(void)
{
    int failures = 0;
    TEST("land: the regen phase folds generated-doc drift into the tip "
        "commit after a clean rebase, and proves and pushes that tip") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], out[512], head[64], base[64], parent[64];
        char intent[160];
        const char *log_subject[] = { "log", "-1", "--pretty=%s", NULL };
        const char *log_author[] = { "log", "-1", "--pretty=%an <%ae>",
                                     NULL };
        const char *log_sig[] = { "log", "-1", "--pretty=%G?", NULL };
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        const char *parent_args[] = { "rev-parse", "HEAD~1", NULL };
        const char *tip_parent[] = { "rev-parse", "keep-tip~1", NULL };
        const char *tip_author[] = { "log", "-1", "--pretty=%an <%ae>",
                                     "keep-tip", NULL };
        const char *keep[] = { "branch", "keep-tip", rig.tip, NULL };
        const char *inventory[] = { "show",
                                    "HEAD:docs/CAPABILITY_INVENTORY.jsonl",
                                    NULL };
        const char *remote[] = { "rev-parse", "main", NULL };
        dlx_isolate("regendocs_a");
        ASSERT(dlx_rig_make_docregen(
            &rig, "regendocs_a_rig",
            "@printf 'regen\\n' >> docs/CAPABILITY_INVENTORY.jsonl", "@:",
            "@:"));
        ASSERT(dlx_git(rig.clone, keep) == 0);
        ASSERT(dlx_sign_arm(rig.clone, "regendocs_a_key"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Past the regen phase and into the proof: a dirtied generated
         * artifact never became a terminal state. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        /* No new commit: the tip keeps its subject and author, sits on the
         * same parent the submitted tip had, and is a NEW id only because
         * its tree now carries the regenerated file. */
        ASSERT(dlx_git_out(landwt, log_subject, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "change.txt");
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) != 0);
        ASSERT(dlx_git_out(landwt, parent_args, parent, sizeof(parent)) ==
               0);
        ASSERT(dlx_git_out(rig.clone, tip_parent, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(parent, out);
        ASSERT_STR_EQ(parent, base);
        ASSERT(dlx_git_out(rig.clone, tip_author, out, sizeof(out)) == 0);
        {
            char author[512];
            ASSERT(dlx_git_out(landwt, log_author, author,
                               sizeof(author)) == 0);
            ASSERT_STR_EQ(author, out);
        }
        ASSERT(dlx_git_out(landwt, inventory, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "orig\nregen");
        /* Signed through the ambient commit.gpgsign configuration. */
        ASSERT(dlx_git_out(landwt, log_sig, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "G");
        /* The proof is bound to the AMENDED tip on the exact base. */
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        {
            const struct json_value *flight =
                json_get(&c.reply.data, "in_flight");
            ASSERT(flight != NULL);
            (void)snprintf(intent, sizeof(intent), "%s@%s", head, base);
            ASSERT_STR_EQ(json_get_str(json_get(flight, "proof_intent")),
                          intent);
        }
        dlx_end(&c);
        /* And the pushed id is exactly the proved one. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "tip_pushed"), head);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, head);
        dlx_restore();
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

/* The regen phase makes no commit when the doc generators change nothing. */
static int test_dev_land_regen_no_commit_when_clean(void)
{
    int failures = 0;
    TEST("land: the regen phase makes no commit when the doc generators "
        "change nothing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], subject[512], head[64];
        const char *log_subject[] = { "log", "-1", "--pretty=%s", NULL };
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("regendocs_b");
        ASSERT(dlx_rig_make_docregen(&rig, "regendocs_b_rig", "@:", "@:",
                                     "@:"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        /* No new commit: the tip is exactly the one submitted. */
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) == 0);
        ASSERT(dlx_git_out(landwt, log_subject, subject, sizeof(subject)) ==
              0);
        ASSERT(strcmp(subject, "change.txt") == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* A failing regen target fails the row by name, with no commit made. */
static int test_dev_land_regen_failure_fails_row(void)
{
    int failures = 0;
    TEST("land: a failing regen target fails the row by name, with no "
        "commit made") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("regendocs_c");
        ASSERT(dlx_rig_make_docregen(
            &rig, "regendocs_c_rig",
            "@echo 'PASS check-pipefail-status-pipe 5977 ms'; "
            "echo 'FAIL: synthetic regen failure' >&2; exit 1", "@:",
            "@:"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "regen") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "FAIL: synthetic regen failure") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* Each of the three regen targets appends "<make pid> <name>" to a marker
 * file. One make start costs a full Makefile parse, so all three must run
 * in ONE make invocation (one pid), in table order. */
#define DLX_MARK(name) "@mkdir -p build; echo \"$$PPID " name "\" >> build/regen-marks"
static int test_dev_land_regen_runs_all_targets_in_one_make(void)
{
    int failures = 0;
    TEST("land: the regen phase runs all three targets in one make "
        "invocation, in order") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], marks[1400], buf[4096], head[64];
        size_t len = 0;
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        int pid[3] = { 0, 0, 0 };
        char nm[3][64];
        dlx_isolate("regendocs_f");
        ASSERT(dlx_rig_make_docregen(&rig, "regendocs_f_rig",
                                     DLX_MARK("cap"), DLX_MARK("routing"),
                                     DLX_MARK("counts")));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        (void)snprintf(marks, sizeof(marks), "%s/build/regen-marks", landwt);
        ASSERT(dlx_slurp(marks, buf, sizeof(buf), &len));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        ASSERT(sscanf(buf, "%d %63s\n%d %63s\n%d %63s", &pid[0], nm[0],
                      &pid[1], nm[1], &pid[2], nm[2]) == 6);
        ASSERT(pid[0] > 0 && pid[0] == pid[1] && pid[1] == pid[2]);
        ASSERT(strcmp(nm[0], "cap") == 0);
        ASSERT(strcmp(nm[1], "routing") == 0);
        ASSERT(strcmp(nm[2], "counts") == 0);
        /* Unchanged commit behavior: nothing drifted, no regen commit. */
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* A failure in the middle target still fails the row by that target's own
 * line, stops before the later target, and commits nothing. */
static int test_dev_land_regen_middle_failure_names_line_and_stops(void)
{
    int failures = 0;
    TEST("land: a middle regen target failing names its line, skips the "
        "later target, and commits nothing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], marks[1400], buf[4096], head[64];
        size_t len = 0;
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("regendocs_g");
        ASSERT(dlx_rig_make_docregen(
            &rig, "regendocs_g_rig",
            "@printf 'regen\\n' >> docs/CAPABILITY_INVENTORY.jsonl",
            "@echo 'FAIL: routing table is hollow' >&2; exit 1",
            DLX_MARK("counts")));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "regen") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "FAIL: routing table is hollow") != NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        (void)snprintf(marks, sizeof(marks), "%s/build/regen-marks", landwt);
        /* make stopped at the failing goal: the counts recipe never ran. */
        ASSERT(!dlx_slurp(marks, buf, sizeof(buf), &len) || len == 0);
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* A generated artifact rewritten with IDENTICAL bytes (git sees no diff, so
 * no commit is made) still moves that file's mtime/ctime — exactly what the
 * source-mutation token the proof checks is built from. The regen phase
 * must re-seal build/dev-loop/restart.env in that case even though nothing
 * landed in git. */
static int test_dev_land_regen_refreshes_plan_on_identical_rewrite(void)
{
    int failures = 0;
    TEST("land: the regen phase re-seals the restart plan when a target "
        "rewrites an artifact with identical bytes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], head[64], planpath[1400], log[8192];
        size_t loglen = 0;
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("regendocs_d");
        /* Rewrites the file with the SAME content dlx_rig_make_docregen
         * seeded it with ("orig\n"): git diff --quiet sees nothing, but
         * the write still touches the inode's mtime/ctime. */
        ASSERT(dlx_rig_make_docregen(
            &rig, "regendocs_d_rig",
            "@printf 'orig\\n' > docs/CAPABILITY_INVENTORY.jsonl", "@:",
            "@:"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        (void)snprintf(landwt, sizeof(landwt), "%s",
                      dlx_str(&c, "log_path"));
        ASSERT(landwt[0] != '\0');
        ASSERT(dlx_slurp(landwt, log, sizeof(log), &loglen));
        log[loglen < sizeof(log) ? loglen : sizeof(log) - 1] = '\0';
        ASSERT(strstr(log, "regen: restart plan refreshed (1 artifact(s) "
                          "rewritten, 0 committed)") != NULL);
        dlx_end(&c);
        /* No git-visible change: no regen commit, HEAD is still the
         * submitted tip. */
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) == 0);
        /* The plan target ran exactly once: one marker line. */
        (void)snprintf(planpath, sizeof(planpath),
                      "%s/build/dev-loop/restart.env", landwt);
        ASSERT(dlx_slurp(planpath, log, sizeof(log), &loglen));
        log[loglen < sizeof(log) ? loglen : sizeof(log) - 1] = '\0';
        ASSERT(strcmp(log, "plan\n") == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* Exercise the proof-tools preparation adapter: a cold worktree triggers
 * exactly one docs-proof-tools build, a warm one builds nothing, and both
 * a make failure and a silent no-produce refuse by name. */
static int test_dev_land_proof_tools_preparation(void)
{
    int failures = 0;
    TEST("land: proof tools preparation builds the missing checker tools "
        "exactly once") {
        char root[1024], path[1200], body[128], why[512];
        size_t len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "proof_tools");
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@mkdir -p build/bin\n"
            "\t@cp prepared-tool build/bin/z23-lint\n"
            "\t@cp prepared-tool build/bin/z23-fleet-observe\n"
            "\t@cp prepared-tool build/bin/gen_capability_inventory\n"
            "\t@echo built >> build/proof-tools.log\n"));
        ASSERT(dlx_write_dep(root, "prepared-tool", "tool\n"));
        ASSERT(zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT((size_t)snprintf(path, sizeof(path),
                                "%s/build/proof-tools.log", root) <
               sizeof(path));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("built\n"));
        ASSERT(memcmp(body, "built\n", len) == 0);
        /* Warm: every tool present, so no second make runs. */
        ASSERT(zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("built\n"));
        /* A failed make preserves the make failure as the reason. */
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@echo 'FAIL: proof tools refused' >&2\n\t@exit 1\n"));
        (void)remove(path);
        (void)snprintf(path, sizeof(path), "%s/build/bin/z23-fleet-observe",
                       root);
        ASSERT(remove(path) == 0);
        ASSERT(!zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why, "proof tools refused") != NULL);
        /* A make that succeeds without producing a member refuses with the
         * exact dependency the proof would later name. */
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@mkdir -p build/bin\n"
            "\t@cp prepared-tool build/bin/z23-lint\n"
            "\t@cp prepared-tool build/bin/gen_capability_inventory\n"));
        ASSERT(!zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why,
                      "proof_generation_dependency_unavailable:"
                      "build/bin/z23-fleet-observe") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* Exercise the actual preparation adapter with an existing stale plan. */
static int test_dev_land_final_plan_preparation(void)
{
    int failures = 0;
    TEST("land: final preparation refreshes an existing plan and preserves make failures") {
        char root[1024], path[1200], body[128], why[512];
        size_t len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "final_plan");
        ASSERT(dlx_write_dep(root, "Makefile",
            ".PHONY: FORCE\nFORCE:\n"
            "build/dev-loop/restart.env: FORCE\n"
            "\t@mkdir -p build/dev-loop\n"
            "\t@cp prepared-input build/dev-loop/restart.env\n"));
        ASSERT(dlx_write_dep(root, "prepared-input", "generation-one\n"));
        ASSERT(zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT(dlx_write_dep(root, "prepared-input", "generation-two\n"));
        ASSERT(zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", root) < sizeof(path));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("generation-two\n"));
        ASSERT(memcmp(body, "generation-two\n", len) == 0);
        ASSERT(dlx_write_dep(root, "Makefile",
            ".PHONY: FORCE\nFORCE:\n"
            "build/dev-loop/restart.env: FORCE\n"
            "\t@echo 'FAIL: final preparation refused' >&2\n\t@exit 1\n"));
        ASSERT(!zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why, "final preparation refused") != NULL);
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("generation-two\n"));
        ASSERT(memcmp(body, "generation-two\n", len) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The earlier document phase need not refresh an untouched plan; final
 * preparation separately binds the plan after all prerequisites settle. */
static int test_dev_land_regen_leaves_plan_alone_when_untouched(void)
{
    int failures = 0;
    TEST("land: the regen phase leaves the restart plan alone when no "
        "artifact's stat identity changed") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], planpath[1400], log[8192];
        size_t loglen = 0;
        dlx_isolate("regendocs_e");
        ASSERT(dlx_rig_make_docregen(&rig, "regendocs_e_rig", "@:", "@:",
                                     "@:"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        (void)snprintf(landwt, sizeof(landwt), "%s",
                      dlx_str(&c, "log_path"));
        ASSERT(landwt[0] != '\0');
        ASSERT(dlx_slurp(landwt, log, sizeof(log), &loglen));
        log[loglen < sizeof(log) ? loglen : sizeof(log) - 1] = '\0';
        ASSERT(strstr(log, "regen: restart plan unchanged") != NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        (void)snprintf(planpath, sizeof(planpath),
                      "%s/build/dev-loop/restart.env", landwt);
        /* The plan target never ran: the marker file was never created. */
        ASSERT(!dlx_file_exists(planpath));
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static int test_dev_land_explicit_main(void)
{
    int failures = 0;
    TEST("land: observes main even when configured fetch excludes it") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], main_now[64];
        dlx_isolate("main_refspec");
        ASSERT(dlx_rig_make(&rig, "main_refspec_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                base, NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        const char *other[] = { "update-ref", "refs/heads/other", base, NULL };
        const char *cached[] = { "update-ref", "refs/remotes/origin/main",
                                base, NULL };
        const char *mapping[] = { "config", "--replace-all", "remote.origin.fetch",
                                 "refs/heads/other:refs/remotes/origin/other", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_git(rig.bare, other) == 0);
        ASSERT(dlx_git(rig.clone, cached) == 0);
        ASSERT(dlx_git(rig.clone, mapping) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT(strstr(dlx_str(&c, "detail"), "successor queued") != NULL);
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, stranger);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

static int test_dev_land_missing_main(void)
{
    int failures = 0;
    TEST("land: missing remote main blocks despite a cached tracking ref") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], main_now[64];
        dlx_isolate("missing_main");
        ASSERT(dlx_rig_make(&rig, "missing_main_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        const char *remove_main[] = { "update-ref", "-d", "refs/heads/main", NULL };
        const char *restore_main[] = { "update-ref", "refs/heads/main", base, NULL };
        ASSERT(dlx_git(rig.bare, remove_main) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(dlx_refusal_serializes(&c));
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(!dlx_origin_main(&rig, main_now));
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
        dlx_end(&c);
        ASSERT(dlx_git(rig.bare, restore_main) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

static int test_dev_land_initial_remote_missing(void)
{
    int failures = 0;
    TEST("land: unavailable remote before initial proof remains retryable") {
        struct dlx_rig rig;
        struct dlx_call c;
        char offline[700];
        dlx_isolate("initial_remote_missing");
        ASSERT(dlx_rig_make(&rig, "initial_remote_missing_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        (void)snprintf(offline, sizeof(offline), "%s.offline", rig.bare);
        ASSERT(rename(rig.bare, offline) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(rename(offline, rig.bare) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_EQ(dlx_int(&c, "attempt"), 1);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

static int test_dev_land_final_observation_missing(void)
{
    int failures = 0;
    TEST("land: second remote observation failure preserves the proven pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], main_now[64], upload_pack[700];
        char landdir[1200], queue_path[1240], calls_path[740], calls[16];
        char queue_before[16384], queue_after[16384];
        size_t before_len, after_len, calls_len;
        dlx_isolate("prepush_remote_missing");
        ASSERT(dlx_rig_make(&rig, "prepush_remote_missing_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack", rig.bare);
        ASSERT(dlx_write(upload_pack,
            "#!/bin/sh\n"
            "calls=${0}.calls\n"
            "count=0\n"
            "if test -f \"$calls\"; then read -r count < \"$calls\" || exit 70; fi\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$calls\" || exit 70\n"
            "test \"$count\" -ne 2 || exit 75\n"
            "exec git-upload-pack \"$@\"\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.uploadpack",
                                   upload_pack, NULL };
        const char *restore[] = { "config", "--unset", "remote.origin.uploadpack", NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(queue_path, sizeof(queue_path), "%s/queue.jsonl", landdir);
        ASSERT(dlx_slurp(queue_path, queue_before, sizeof(queue_before), &before_len));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        (void)snprintf(calls_path, sizeof(calls_path), "%s.calls", upload_pack);
        ASSERT(dlx_slurp(calls_path, calls, sizeof(calls), &calls_len));
        ASSERT_EQ(calls_len, 2);
        ASSERT(memcmp(calls, "2\n", 2) == 0);
        ASSERT(dlx_slurp(queue_path, queue_after, sizeof(queue_after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(queue_before, queue_after, before_len) == 0);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, base);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), base);
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "attempt"), 1);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

static int test_dev_land_lost_persistence(void)
{
    int failures = 0;
    TEST("land: a queue-commit failure after a real push is reported, "
        "not silently claimed, and the row self-heals") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], hook[1400], script[1600], before[64], after[64];
        dlx_isolate("persistfail");
        ASSERT(dlx_rig_make(&rig, "persistfail_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_landdir(landdir, sizeof(landdir));
        /* Lose the outcome write only after the exact push pair has been
         * durably prepared. Git's pre-push hook runs after that checkpoint. */
        ASSERT((size_t)snprintf(hook, sizeof(hook), "%s/pre-push",
                                g_dlx_hooks_ok) < sizeof(hook));
        ASSERT((size_t)snprintf(script, sizeof(script),
            "#!/bin/sh\nchmod 0500 '%s'\n", landdir) < sizeof(script));
        ASSERT(dlx_write(hook, script) && chmod(hook, 0755) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        ASSERT(strcmp(dlx_str(&c, "persist"), "failed") == 0);
        dlx_end(&c);
        /* The push already happened for real: origin/main moved even
         * though the queue could not record it. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT(chmod(landdir, 0700) == 0);
        /* A cached origin/main still contains the pushed commit when the
         * remote disappears. It cannot establish a fresh observation:
         * retain the inflight row, then reconcile after access returns. */
        char offline[700];
        (void)snprintf(offline, sizeof(offline), "%s.offline", rig.bare);
        ASSERT(rename(rig.bare, offline) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT(strcmp(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE") == 0);
        ASSERT(c.reply.error.retryable);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        ASSERT(rename(offline, rig.bare) == 0);
        /* Recoverable: a later step finds the tip is already an ancestor
         * of origin/main and records it landed without pushing again. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        ASSERT(dlx_str(&c, "persist")[0] == '\0');
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* A finished proof is separate from the landing verdict. Kill a step after
 * it observes PASS, before it can push or persist a phase change. The next
 * process must consume the same exact row and finish once. The test-only
 * proof stub supplies PASS; this tests landing recovery, not proof validity. */
static int test_dev_land_after_proof_restart(void)
{
    int failures = 0;
    TEST("land: death after proof PASS before verdict preserves the row for restart") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], landdir[1200], qpath[1400];
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        int child_status = 0;
        dlx_isolate("after_proof_restart");
        ASSERT(dlx_rig_make(&rig, "after_proof_restart_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "running", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "pass", 1) == 0);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            (void)setenv("ZCL_LAND_TEST_DIE_AFTER_PROOF", "1", 1);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(waitpid(child, &child_status, 0) == child);
        ASSERT(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 82);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(after, before, before_len) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_mail_outcome_found(const char *tip);

static int test_dev_land_terminal_replay(void)
{
    int failures = 0;
    TEST("land: failed outcome append keeps the pushed row reclaimable") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], qpath[1400], maildir[1400];
        char opath[1400], queue[8192], outcome[8192];
        char remote[64];
        size_t queue_len, outcome_len;
        dlx_isolate("outcome_append_failure");
        ASSERT(dlx_rig_make(&rig, "outcome_append_failure_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(maildir, sizeof(maildir), "%s/../mail", landdir) <
               (int)sizeof(maildir));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND", "1", 1);
        setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
        unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
        ASSERT(dlx_write(maildir, "not a mail directory"));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, outcome, sizeof(outcome), &outcome_len));
        ASSERT(outcome_len > 0);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        ASSERT(unlink(maildir) == 0 && mkdir(maildir, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        char again[8192];
        size_t again_len;
        ASSERT(dlx_slurp(opath, again, sizeof(again), &again_len));
        ASSERT_EQ(again_len, outcome_len);
        ASSERT(memcmp(again, outcome, outcome_len) == 0);
        ASSERT(dlx_mail_outcome_found(rig.tip));
        dlx_restore();
        PASS();
    }

    TEST("land: death after outcome append replays once without another push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], opath[1400], qpath[1400], before[8192];
        char after[8192], queue[8192], remote[64];
        size_t before_len, after_len, queue_len;
        int child_status = 0;
        dlx_isolate("outcome_replay_death");
        ASSERT(dlx_rig_make(&rig, "outcome_replay_death_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            (void)setenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME", "1", 1);
            (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(waitpid(child, &child_status, 0) == child);
        ASSERT(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 81);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(opath, before, sizeof(before), &before_len));
        ASSERT(before_len > 0);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "TERMINAL_REPLAY_PENDING");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        /* A terminal receipt for the same request but another proof base
         * cannot authorize replay or silently replace the candidate. */
        char bad_pair[sizeof(before)];
        ASSERT(before_len + 1 < sizeof(bad_pair));
        memcpy(bad_pair, before, before_len);
        bad_pair[before_len] = '\0';
        char *base = strstr(bad_pair, "\"base\":\"");
        ASSERT(base != NULL);
        base += strlen("\"base\":\"");
        ASSERT(strlen(base) >= 40);
        base[0] = base[0] == 'a' ? 'b' : 'a';
        ASSERT(dlx_write(opath, bad_pair));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        before[before_len] = '\0';
        ASSERT(dlx_write(opath, before));
        /* A second terminal claim for this exact request is not a
         * "latest wins" verdict. Preserve the queue and name the conflict. */
        char conflicting[sizeof(before) * 2];
        ASSERT(before_len * 2 + 1 < sizeof(conflicting));
        memcpy(conflicting, before, before_len);
        memcpy(conflicting + before_len, before, before_len);
        conflicting[before_len * 2] = '\0';
        char *state = strstr(conflicting + before_len, "\"state\":\"landed\"");
        ASSERT(state != NULL);
        memcpy(state + strlen("\"state\":\""), "failed", 6);
        ASSERT(dlx_write(opath, conflicting));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        before[before_len] = '\0';
        ASSERT(dlx_write(opath, before));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(after, before, before_len) == 0);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static pid_t dlx_wait_child(pid_t child, int *status)
{
    pid_t waited;
    do { waited = waitpid(child, status, 0); } while (waited < 0 && errno == EINTR);
    return waited;
}

/* A publisher killed mid-push by the remote's post-receive hook leaves its
 * Git descendants running: the orphaned `git push` still reads the remote's
 * report and then updates the landing worktree's refs/remotes/origin/main.
 * A recovery step that starts before they exit races that ref update — its
 * own fetch cannot lock the ref, and the lander correctly answers
 * REMOTE_OBSERVATION_UNAVAILABLE (retryable) — so the case would be judging
 * scheduling, not recovery. The publisher child calls setsid() first, so
 * every process it started stays in its session; after reaping it, wait
 * until that session has no member left: exactly when its work has ended.
 * The group watchdog bounds a descendant that never exits. */
static pid_t dlx_wait_publisher(pid_t publisher, int *status)
{
    pid_t waited = dlx_wait_child(publisher, status);
    while (waited == publisher &&
           zcl_devloop_process_session_members(publisher, 0) > 0) {
        struct timespec pause = { 0, 10 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: other processes' exit */
    }
    return waited;
}

static bool dlx_resume_after_death(void)
{
    struct dlx_call c;
    (void)alarm(30);
    for (unsigned retry = 0; retry < 100; ++retry) {
        dlx_begin(&c, "step");
        bool ran = dlx_run(&c);
        bool ok = ran && dlx_ok(&c) &&
            strcmp(dlx_str(&c, "state"), "landed") == 0;
        bool busy = ran && strcmp(dlx_err_code(&c), "STEP_BUSY") == 0;
        dlx_end(&c);
        if (!busy) return ok;
        struct timespec pause = { 0, 10 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: STEP_BUSY is another process's flock; no fake-clock seam reaches its release. */
    }
    return false;
}

/* ── land outcomes stay visible in agent mail ────────────────────────────
 *
 * The land leaf reports queued/phase/outcome rows through the mail leaf so
 * agents learn results by pulling. A raw append once wrote rows the mail
 * parser could not read (no to/body, kind outside the mail set, land-queue
 * seq colliding with the outbox seq space): every pull skipped them while
 * the global cursor stood still. This test drives a real submit and pulls
 * the outcome back by tip. */

struct dlx_mail_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlx_mail_begin(struct dlx_mail_call *m)
{
    json_init(&m->input);
    json_set_object(&m->input);
    memset(&m->request, 0, sizeof(m->request));
    m->request.input = &m->input;
    m->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "dev.agent.mail",
                                  NULL);
    zcl_command_reply_init(&m->reply, "zcl.agent_mail.v1");
}

static void dlx_mail_end(struct dlx_mail_call *m)
{
    zcl_command_reply_free(&m->reply);
    json_free(&m->input);
}

static bool dlx_mail_ok(const struct dlx_mail_call *m)
{
    return m->request.spec != NULL &&
        m->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool dlx_mail_post(const char *to, const char *kind, const char *body,
                          const char *ref, const char *from)
{
    struct dlx_mail_call m;
    bool ok;
    dlx_mail_begin(&m);
    ok = json_push_kv_str(&m.input, "action", "post") &&
         json_push_kv_str(&m.input, "to", to) &&
         json_push_kv_str(&m.input, "kind", kind) &&
         json_push_kv_str(&m.input, "body", body) &&
         json_push_kv_str(&m.input, "ref", ref) &&
         json_push_kv_str(&m.input, "from", from);
    if (ok)
        zcl_native_handle_dev_agent_mail(&m.request, &m.reply);
    ok = ok && dlx_mail_ok(&m);
    dlx_mail_end(&m);
    return ok;
}

static bool dlx_mail_str_eq(const struct json_value *obj, const char *key,
                            const char *want)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR && json_get_str(v) &&
        strcmp(json_get_str(v), want) == 0;
}

/* One pulled row is the wanted land note; records its seq. */
static bool dlx_mail_row_match(const struct json_value *row, const char *from,
                               const char *kind, const char *ref,
                               long long *seq)
{
    const struct json_value *v;
    if (!dlx_mail_str_eq(row, "from", from))
        return false;
    if (!dlx_mail_str_eq(row, "kind", kind))
        return false;
    if (!dlx_mail_str_eq(row, "ref", ref))
        return false;
    v = json_get(row, "seq");
    if (v && v->type == JSON_INT)
        *seq = json_get_int(v);
    return true;
}

/* One page's rows into the match accumulator. */
static void dlx_mail_page_scan(const struct json_value *rows, const char *from,
                               const char *kind, const char *ref,
                               long long *seq, bool *found)
{
    size_t n;
    if (!rows || rows->type != JSON_ARR)
        return;
    n = rows->num_children;
    for (size_t i = 0; i < n; i++) {
        if (dlx_mail_row_match(&rows->children[i], from, kind, ref, seq))
            *found = true;
    }
}

/* The token resuming the next page into *more. False when a further page
 * exists but its token does not fit: fail closed instead of re-reading
 * one page. */
static bool dlx_mail_advance(const struct zcl_command_reply *reply,
                             bool *more, char *since, size_t cap)
{
    const struct json_value *tok, *tr;
    tr = json_get(&reply->data, "truncated");
    *more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
    if (!*more)
        return true;
    tok = json_get(&reply->data, "next_since");
    if (!tok || tok->type != JSON_STR || !json_get_str(tok) ||
        strlen(json_get_str(tok)) >= cap)
        return false;
    (void)snprintf(since, cap, "%s", json_get_str(tok));
    return true;
}

/* One pull page at `since`: sums its skipped count, scans its rows, and
 * advances the cursor. */
struct dlx_mail_page {
    bool ok;
    bool more;
    long long skipped;
};

static void dlx_mail_page(struct dlx_mail_page *pg, const char *since,
                          const char *from, const char *kind, const char *ref,
                          long long *seq, bool *found, char *next, size_t cap)
{
    struct dlx_mail_call m;
    const struct json_value *rows, *sk;
    pg->ok = false;
    pg->more = false;
    pg->skipped = 0;
    dlx_mail_begin(&m);
    pg->ok = json_push_kv_str(&m.input, "action", "pull") &&
             json_push_kv_str(&m.input, "since", since);
    if (pg->ok)
        zcl_native_handle_dev_agent_mail(&m.request, &m.reply);
    pg->ok = pg->ok && dlx_mail_ok(&m);
    if (!pg->ok) {
        dlx_mail_end(&m);
        return;
    }
    sk = json_get(&m.reply.data, "skipped");
    if (sk && sk->type == JSON_INT)
        pg->skipped = json_get_int(sk);
    rows = json_get(&m.reply.data, "rows");
    dlx_mail_page_scan(rows, from, kind, ref, seq, found);
    pg->ok = dlx_mail_advance(&m.reply, &pg->more, next, cap);
    dlx_mail_end(&m);
}

/* Drain every pull page following next_since. Sets *found when one row
 * matches from/kind/ref, *seq to that row's seq, and *skipped to the summed
 * skipped count across pages. */
static bool dlx_mail_find(const char *from, const char *kind, const char *ref,
                          long long *seq, long long *skipped, bool *found)
{
    char since[4096] = "0";
    char next[4096] = "0";
    *found = false;
    *skipped = 0;
    for (int page = 0; page < 64; page++) {
        struct dlx_mail_page pg;
        dlx_mail_page(&pg, since, from, kind, ref, seq, found, next,
                      sizeof(next));
        if (!pg.ok)
            return false;
        *skipped += pg.skipped;
        if (!pg.more)
            return true;
        (void)snprintf(since, sizeof(since), "%s", next);
    }
    return false;
}

static bool dlx_mail_outcome_found(const char *tip)
{
    long long seq = -1, skipped = -1;
    bool found = false;
    return dlx_mail_find("dev.land", "note", tip, &seq, &skipped, &found) &&
           found && seq > 0 && skipped == 0;
}

static int test_dev_land_outcome_visible_in_mail(void)
{
    int failures = 0;
    TEST("land: a submitted outcome posts through the mail leaf and pulls back by tip") {
        struct dlx_rig rig;
        struct dlx_call c;
        long long seq = -1, skipped = -1;
        bool found = false;
        dlx_isolate("mailvisible");
        ASSERT(dlx_rig_make(&rig, "mailvisible_rig"));
        /* The mail dir pre-exists on every real host (receiver/steer
         * activity); establish it here through the mail leaf itself, the
         * way production does. */
        ASSERT(dlx_mail_post("*", "note", "seed", "seed", "test"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_mail_find("dev.land", "note", rig.tip, &seq, &skipped,
                             &found));
        ASSERT(found);
        /* Mail-allocated seq after the seed row, never the land queue's
         * own seq 1 colliding with the outbox seq space. */
        ASSERT_EQ(seq, 2);
        /* Nothing in the store is skipped as malformed: every row parses. */
        ASSERT_EQ(skipped, 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_publisher_death(void)
{
    int failures = 0;
    TEST("land: publisher death after remote mutation resumes without another push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hook[700], wrapper[700], marker[700];
        char received[32];
        size_t received_len;
        int status;
        dlx_isolate("publisher_death");
        ASSERT(dlx_rig_make(&rig, "publisher_death_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        pid_t publisher = fork();
        ASSERT(publisher >= 0);
        if (publisher == 0) {
            char script[256];
            /* post-receive runs only after the remote ref transaction.
             * Kill this publisher, not the test runner or Git descendants.
             * The hook exits immediately: no FIFO or sleeping orphan. Its
             * own session lets dlx_wait_publisher see its Git descendants
             * out. */
            (void)setsid();
            (void)alarm(30);
            (void)snprintf(script, sizeof(script),
                "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
            if (!dlx_write(hook, script) || chmod(hook, 0700) != 0)
                _exit(2);
            dlx_begin(&c, "step");
            (void)dlx_run(&c);
            _exit(3);
        }
        pid_t waited = dlx_wait_publisher(publisher, &status);
        ASSERT_EQ(waited, publisher);
        ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        /* Remove the injector before a new process takes the existing locks. */
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        const struct json_value *pending_outcomes = dlx_arr(&c, "outcomes");
        ASSERT(pending_outcomes);
        ASSERT_EQ(pending_outcomes->num_children, 0);
        dlx_end(&c);
        char land[1200], queue_path[1400], wire[8192];
        size_t wire_len;
        dlx_landdir(land, sizeof(land));
        (void)snprintf(queue_path, sizeof(queue_path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(queue_path, wire, sizeof(wire), &wire_len));
        struct json_value retained;
        json_init(&retained);
        ASSERT(json_read(&retained, wire, wire_len));
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "local")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "state")), "inflight");
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "tip_pushed")), "");
        ASSERT(json_get_int(json_get(&retained, "push_diagnostic_pending")) == 1);
        json_free(&retained);
        pid_t receiver = fork();
        ASSERT(receiver >= 0);
        if (receiver == 0)
            _exit(dlx_resume_after_death() ? 0 : 4);
        waited = dlx_wait_child(receiver, &status);
        ASSERT_EQ(waited, receiver);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "state")), "landed");
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "tip_pushed")), rig.tip);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Publisher holds the step lock and is killed before it claims. The queued
 * row stays eligible, status names drain_absent, and a different process
 * adopts through dev land step: one claim, one push, refetch matches.
 * Split so each function stays under the cyclomatic cap; the TEST below
 * is the one case. */
struct dlx_adopt_fix {
    struct dlx_rig rig;
    char before[64];
    char landdir[1200];
    char qpath[1400];
    char marker[700];
    char qsnap[8192];
    size_t qsnap_len;
};

static bool dlx_eq_str(const char *got, const char *want)
{
    if (!got || !want || strcmp(got, want) != 0) {
        printf("FAIL str got='%s' want='%s'\n",
               got ? got : "(nil)", want ? want : "(nil)");
        return false;
    }
    return true;
}

static bool dlx_eq_i64(int64_t got, int64_t want, const char *what)
{
    if (got != want) {
        printf("FAIL %s got=%lld want=%lld\n", what ? what : "int",
               (long long)got, (long long)want);
        return false;
    }
    return true;
}

static bool dlx_has(const char *s, const char *frag)
{
    if (!s || !frag || strstr(s, frag) == NULL) {
        printf("FAIL missing '%s'\n", frag ? frag : "(nil)");
        return false;
    }
    return true;
}

static const char *dlx_jstr(const struct json_value *obj, const char *key)
{
    const char *s = json_get_str(json_get(obj, key));
    return s ? s : "";
}

static bool dlx_alls(const bool *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!v[i])
            return false;
    }
    return true;
}

static void dlx_adopt_hold_child(const char *landdir)
{
    int fd;
    (void)alarm(30);
    fd = dlx_step_lock_take(landdir);
    if (fd < 0)
        _exit(2);
    for (;;)
        pause();
}

static bool dlx_wait_step_held(const char *landdir)
{
    for (int i = 0; i < 100; i++) {
        if (dlx_step_held(landdir) == 1)
            return true;
        struct timespec pause = { 0, 20 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: adoption child holds step.lock; no fake-clock seam reaches that flock. */
    }
    return false;
}

static bool dlx_child_ok(pid_t pid, int want)
{
    int status = 0;
    pid_t waited = dlx_wait_child(pid, &status);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == want;
}

static bool dlx_killed_ok(pid_t pid)
{
    int status = 0;
    if (kill(pid, SIGKILL) != 0)
        return false;
    if (dlx_wait_child(pid, &status) != pid)
        return false;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static bool dlx_adopt_submit(struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    memset(fx, 0, sizeof(*fx));
    if (!dlx_rig_make(&fx->rig, "drain_adopt_rig"))
        return false;
    if (!dlx_origin_main(&fx->rig, fx->before))
        return false;
    dlx_submit(&c, &fx->rig, fx->rig.tip);
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    dlx_end(&c);
    dlx_landdir(fx->landdir, sizeof(fx->landdir));
    if ((size_t)snprintf(fx->qpath, sizeof(fx->qpath), "%s/queue.jsonl",
                         fx->landdir) >= sizeof(fx->qpath))
        return false;
    if (!dlx_slurp(fx->qpath, fx->qsnap, sizeof(fx->qsnap), &fx->qsnap_len))
        return false;
    return fx->qsnap_len > 0;
}

static bool dlx_status_json(struct dlx_call *c)
{
    dlx_begin(c, "status");
    (void)json_push_kv_bool(&c->input, "json", true);
    if (!dlx_run(c) || !dlx_ok(c)) {
        dlx_end(c);
        return false;
    }
    return true;
}

static bool dlx_beat_active_status(void)
{
    struct dlx_call c;
    const struct json_value *steer;
    bool ok;
    if (!dlx_status_json(&c))
        return false;
    steer = json_get(&c.reply.data, "steer");
    ok = steer && steer->type == JSON_OBJ &&
         dlx_eq_str(dlx_str(&c, "incident"), "none") &&
         dlx_has(dlx_jstr(steer, "receiver_driver"), "beat_active") &&
         dlx_eq_str(dlx_jstr(steer, "lease"), "step.lock:held");
    dlx_end(&c);
    return ok;
}

static bool dlx_step_is_busy(void)
{
    struct dlx_call c;
    bool busy;
    dlx_begin(&c, "step");
    if (!dlx_run(&c)) {
        dlx_end(&c);
        return false;
    }
    busy = strcmp(dlx_err_code(&c), "STEP_BUSY") == 0;
    dlx_end(&c);
    return busy;
}

static bool dlx_adopt_while_held(struct dlx_adopt_fix *fx)
{
    pid_t pid = fork();
    char after[64];
    bool saw;
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_hold_child(fx->landdir);
        _exit(2);
    }
    saw = dlx_wait_step_held(fx->landdir) && dlx_step_is_busy() &&
          dlx_origin_main(&fx->rig, after) &&
          strcmp(after, fx->before) == 0 && dlx_beat_active_status();
    if (!dlx_killed_ok(pid))
        return false;
    return saw;
}

static bool dlx_queue_unchanged(const struct dlx_adopt_fix *fx)
{
    char after[8192];
    size_t n = 0;
    if (!dlx_slurp(fx->qpath, after, sizeof(after), &n))
        return false;
    return n == fx->qsnap_len && memcmp(after, fx->qsnap, n) == 0;
}

static bool dlx_steer_stalled(const struct dlx_call *c,
                              const struct dlx_adopt_fix *fx)
{
    const struct json_value *steer = json_get(&c->reply.data, "steer");
    const struct json_value *queued = dlx_arr(c, "queued");
    bool v[8];
    if (!steer || steer->type != JSON_OBJ)
        return false;
    v[0] = dlx_eq_str(dlx_str(c, "incident"), "drain_absent");
    v[1] = dlx_eq_str(dlx_jstr(steer, "candidate"), fx->rig.tip);
    v[2] = dlx_eq_i64(json_get_int(json_get(steer, "seq")), 1, "seq");
    v[3] = dlx_eq_str(dlx_jstr(steer, "phase"), "queued");
    v[4] = dlx_eq_str(dlx_jstr(steer, "owner"), "unclaimed");
    v[5] = dlx_eq_str(dlx_jstr(steer, "lease"), "none");
    v[6] = dlx_eq_str(dlx_jstr(steer, "proof_state"), "not_requested");
    v[7] = dlx_has(dlx_jstr(steer, "receiver_driver"), "no_active_drain");
    if (!dlx_alls(v, 8))
        return false;
    v[0] = dlx_eq_str(dlx_jstr(steer, "first_missing_transition"), "claim");
    v[1] = dlx_eq_str(dlx_jstr(steer, "wake_command"), "z23-dev dev land step");
    v[2] = dlx_has(dlx_jstr(steer, "remote_state"), "cached:");
    v[3] = queued && queued->num_children == 1;
    v[4] = json_get(&c->reply.data, "in_flight") == NULL;
    return dlx_alls(v, 5);
}

static bool dlx_screen_names_incident(void)
{
    struct dlx_call c;
    bool ok;
    dlx_begin(&c, "status");
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    ok = dlx_has(dlx_str(&c, "screen"), "incident: drain_absent") &&
         dlx_has(dlx_str(&c, "screen"),
                 "steer.wake_command: z23-dev dev land step");
    dlx_end(&c);
    return ok;
}

static bool dlx_adopt_incident(const struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    bool stalled;
    if (!dlx_queue_unchanged(fx))
        return false;
    if (!dlx_status_json(&c))
        return false;
    stalled = dlx_steer_stalled(&c, fx);
    dlx_end(&c);
    if (!stalled)
        return false;
    return dlx_screen_names_incident();
}

static bool dlx_arm_receive_count(struct dlx_adopt_fix *fx)
{
    char wrapper[700];
    const char *count_push[4];
    if ((size_t)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack",
                         fx->rig.bare) >= sizeof(wrapper))
        return false;
    if ((size_t)snprintf(fx->marker, sizeof(fx->marker),
                         "%s/hooks/receive-invocations", fx->rig.bare) >=
        sizeof(fx->marker))
        return false;
    if (!dlx_write(wrapper,
                   "#!/bin/sh\n"
                   "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
                   "exec git-receive-pack \"$@\"\n"))
        return false;
    if (chmod(wrapper, 0700) != 0)
        return false;
    count_push[0] = "config";
    count_push[1] = "remote.origin.receivepack";
    count_push[2] = wrapper;
    count_push[3] = NULL;
    return dlx_git(fx->rig.clone, count_push) == 0;
}

static void dlx_adopt_claim_child(void)
{
    struct dlx_call step;
    (void)alarm(60);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "started") != 0)
        _exit(4);
    _exit(0);
}

static bool dlx_one_claim_row(const struct dlx_adopt_fix *fx)
{
    char wire[8192];
    size_t n = 0;
    struct json_value row;
    bool ok;
    if (dlx_file_exists(fx->marker))
        return false;
    if (!dlx_slurp(fx->qpath, wire, sizeof(wire), &n))
        return false;
    json_init(&row);
    if (!json_read(&row, wire, n)) {
        json_free(&row);
        return false;
    }
    ok = dlx_eq_str(dlx_jstr(&row, "state"), "inflight") &&
         dlx_eq_str(dlx_jstr(&row, "phase"), "prove") &&
         dlx_eq_i64(json_get_int(json_get(&row, "attempt")), 1, "attempt") &&
         dlx_eq_str(dlx_jstr(&row, "tip"), fx->rig.tip);
    json_free(&row);
    return ok;
}

static bool dlx_inflight_only(const struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    const struct json_value *flight;
    const struct json_value *queued;
    bool ok;
    if (!dlx_status_json(&c))
        return false;
    flight = json_get(&c.reply.data, "in_flight");
    queued = dlx_arr(&c, "queued");
    ok = flight && flight->type == JSON_OBJ &&
         dlx_eq_str(dlx_jstr(flight, "tip"), fx->rig.tip) &&
         dlx_eq_str(dlx_str(&c, "incident"), "none") &&
         queued && queued->num_children == 0;
    dlx_end(&c);
    return ok;
}

static bool dlx_adopt_claim(struct dlx_adopt_fix *fx)
{
    pid_t pid;
    if (!dlx_arm_receive_count(fx))
        return false;
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_claim_child();
        _exit(4);
    }
    if (!dlx_child_ok(pid, 0))
        return false;
    if (!dlx_one_claim_row(fx))
        return false;
    return dlx_inflight_only(fx);
}

static void dlx_adopt_push_child(void)
{
    struct dlx_call step;
    (void)alarm(60);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "landed") != 0)
        _exit(5);
    dlx_end(&step);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "empty") != 0)
        _exit(6);
    _exit(0);
}

static bool dlx_receive_once(const struct dlx_adopt_fix *fx)
{
    char wire[64];
    size_t n = 0;
    if (!dlx_slurp(fx->marker, wire, sizeof(wire), &n))
        return false;
    return n == 8 && memcmp(wire, "invoked\n", 8) == 0;
}

static bool dlx_refetch_matches(const struct dlx_adopt_fix *fx)
{
    char after[64], fetched[64];
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *rev[] = { "rev-parse", "origin/main", NULL };
    if (!dlx_origin_main(&fx->rig, after))
        return false;
    if (strcmp(after, fx->rig.tip) != 0)
        return false;
    if (dlx_git(fx->rig.clone, fetch) != 0)
        return false;
    if (dlx_git_out(fx->rig.clone, rev, fetched, sizeof(fetched)) != 0)
        return false;
    return strcmp(fetched, fx->rig.tip) == 0 && strcmp(fetched, after) == 0;
}

static bool dlx_step_empty(void)
{
    struct dlx_call c;
    bool empty;
    dlx_begin(&c, "step");
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    empty = strcmp(dlx_str(&c, "state"), "empty") == 0;
    dlx_end(&c);
    return empty;
}

static bool dlx_adopt_push(struct dlx_adopt_fix *fx)
{
    pid_t pid;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_push_child();
        _exit(6);
    }
    if (!dlx_child_ok(pid, 0))
        return false;
    if (!dlx_receive_once(fx) || !dlx_refetch_matches(fx))
        return false;
    if (!dlx_step_empty())
        return false;
    return dlx_receive_once(fx);
}

static int test_dev_land_drain_adoption(void)
{
    int failures = 0;
    TEST("land: dead publisher leaves the queued row; one integrator adopts and pushes once") {
        struct dlx_adopt_fix fx;
        dlx_isolate("drain_adopt");
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_DRAIN_IDLE_SEC", "0", 1);
        ASSERT(dlx_adopt_submit(&fx));
        ASSERT(dlx_adopt_while_held(&fx));
        ASSERT(dlx_adopt_incident(&fx));
        ASSERT(dlx_adopt_claim(&fx));
        ASSERT(dlx_adopt_push(&fx));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_postpush_observation_missing(bool lost_ack)
{
    int failures = 0;
    TEST(lost_ack
        ? "land: final-attempt lost acknowledgement reconciles without duplicate push"
        : "land: successful push awaits independent observation and reconciles once") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], upload_pack[700], hook[700], marker[700];
        char receive_pack[700], invocations[700];
        char received[32];
        size_t received_len;
        dlx_isolate("postpush_observation_missing");
        ASSERT(dlx_rig_make(&rig, "postpush_observation_missing_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        if (lost_ack) {
            char land[1200], path[1400], wire[8192];
            size_t length;
            dlx_landdir(land, sizeof(land));
            (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
            ASSERT(dlx_slurp(path, wire, sizeof(wire), &length));
            wire[length] = '\0';
            char *attempt = strstr(wire, "\"attempt\":1");
            ASSERT(attempt != NULL);
            attempt[10] = '3';
            ASSERT(dlx_write(path, wire));
        }
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/received", rig.bare);
        ASSERT(dlx_write(hook,
            "#!/bin/sh\n"
            "printf 'received\\n' >> hooks/received || exit 73\n"));
        ASSERT(chmod(hook, 0700) == 0);
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack", rig.bare);
        ASSERT(dlx_write(upload_pack,
            "#!/bin/sh\n"
            "test ! -f \"$1/hooks/received\" || exit 75\n"
            "exec git-upload-pack \"$@\"\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        (void)snprintf(receive_pack, sizeof(receive_pack), "%s.receive-pack", rig.bare);
        (void)snprintf(invocations, sizeof(invocations), "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(receive_pack, lost_ack ?
            "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "git-receive-pack \"$@\" || exit $?\n"
            "exit 75\n" :
            "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(receive_pack, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.uploadpack",
                                   upload_pack, NULL };
        const char *count_push[] = { "config", "remote.origin.receivepack",
                                    receive_pack, NULL };
        const char *restore[] = { "config", "--unset", "remote.origin.uploadpack", NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        ASSERT(dlx_git(rig.clone, count_push) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        /* Establish the actual mutation before checking its reported state. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT_STR_EQ(after, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 9);
        ASSERT(memcmp(received, "received\n", 9) == 0);
        ASSERT(dlx_slurp(invocations, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), lost_ack ? 3 : 1);
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "attempt"), lost_ack ? 3 : 1);
        dlx_end(&c);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 9);
        ASSERT(memcmp(received, "received\n", 9) == 0);
        ASSERT(dlx_slurp(invocations, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_prepush_checkpoint(void)
{
    int failures = 0;
    TEST("land: push phase and exact pair are durable before pre-push runs") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], hook[1400], script[1800], base[64];
        dlx_isolate("prepush_checkpoint");
        ASSERT(dlx_rig_make(&rig, "prepush_checkpoint_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT((size_t)snprintf(hook, sizeof(hook), "%s/pre-push",
                                g_dlx_hooks_ok) < sizeof(hook));
        ASSERT((size_t)snprintf(script, sizeof(script),
            "#!/bin/sh\n"
            "grep -F '\"phase\":\"push\"' '%s/queue.jsonl' >/dev/null || exit 73\n"
            "grep -F '\"base\":\"%s\"' '%s/queue.jsonl' >/dev/null || exit 74\n"
            "exit 0\n", landdir, base, landdir) < sizeof(script));
        ASSERT(dlx_write(hook, script) && chmod(hook, 0755) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_prepush_persist_refusal(void)
{
    int failures = 0;
    TEST("land: failed pre-push persistence refuses remote mutation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], base[64], observed[64];
        dlx_isolate("prepush_persist_refusal");
        ASSERT(dlx_rig_make(&rig, "prepush_persist_refusal_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(chmod(landdir, 0500) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_INTENT_PERSIST_FAILED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        ASSERT(chmod(landdir, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_prepush_sync_refusal(void)
{
    int failures = 0;
    TEST("land: failed directory sync after checkpoint refuses push and retries") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], observed[64];
        dlx_isolate("prepush_sync_refusal");
        ASSERT(dlx_rig_make(&rig, "prepush_sync_refusal_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_TEST_DIR_SYNC_FAIL", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_INTENT_PERSIST_FAILED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
    dlx_restore();
    return failures;
}

static int test_dev_land_missing_publication_intent(void)
{
    int failures = 0;
    TEST("land: a proven pair without canonical intent cannot push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], observed[64];
        dlx_isolate("missing_publication_intent");
        ASSERT(dlx_rig_make(&rig, "missing_publication_intent_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── attach target: the blocked beat names its row; attach never targets
 * nothing ─────────────────────────────────────────────────────────────── */

/* Submit rig.tip and take the first beat under a running proof, then make
 * the proof PASS with unsigned publication forbidden: the row is a live
 * exact proven pair that still needs the operator's signed intent. */
static bool dlx_attach_proven_pair(struct dlx_rig *rig, const char *tag,
                                   char base[64])
{
    struct dlx_call c;
    char rig_tag[128];
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    if (!dlx_rig_make(rig, rig_tag) || !dlx_origin_main(rig, base))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
         strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    return ok;
}

static bool dlx_queue_bytes(char *out, size_t cap, size_t *len)
{
    char land[1200], path[1400];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, out, cap - 1, len))
        return false;
    out[*len] = '\0';
    return true;
}

/* Serialize the captured refusal through the real registry envelope and
 * return the wire error object's next_action and evidence plus the reason
 * of the first next[] entry: a failed envelope omits data, so these are
 * what a shell caller actually sees. */
static bool dlx_blocked_wire(const struct dlx_call *call, char *action,
                             char *evidence, char *reason, size_t cap)
{
    if (!call->request.spec) return false;
    struct zcl_command_spec spec = *call->request.spec;
    spec.handler = dlx_captured_handler;
    char wire[8192];
    enum zcl_command_exit code;
    g_dlx_captured_reply = &call->reply;
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        &spec, NULL, &call->input, false, DLX_PATH, NULL, 0, 0, NULL,
        wire, sizeof(wire), &code);
    g_dlx_captured_reply = NULL;
    struct json_value doc;
    json_init(&doc);
    bool ok = len > 0 && json_read(&doc, wire, len);
    const struct json_value *error = json_get(&doc, "error");
    const struct json_value *next = json_get(&doc, "next");
    const char *a = json_get_str(json_get(error, "next_action"));
    const char *e = json_get_str(json_get(error, "evidence"));
    const char *r = next && next->type == JSON_ARR && next->num_children > 0
        ? json_get_str(json_get(&next->children[0], "reason")) : NULL;
    ok = ok && a && e && r;
    if (ok) {
        (void)snprintf(action, cap, "%s", a);
        (void)snprintf(evidence, cap, "%s", e);
        (void)snprintf(reason, cap, "%s", r);
    }
    json_free(&doc);
    return ok;
}

/* The witness: after PASS, drive stops at PUBLICATION_INTENT_REQUIRED. The
 * reply must name the row, its exact pair, and the exact attach command, in
 * data and on the wire, so the operator cannot run `attach --seq=`. */
static int test_dev_land_blocked_names_attach_target(void)
{
    int failures = 0;
    TEST("land: a proven pair blocked on intent names seq, pair and attach --seq") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], action[256], evidence[256], reason[256];
        dlx_isolate("blocked_attach_target");
        ASSERT(dlx_attach_proven_pair(&rig, "blocked_attach_target", base));
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT(!c.reply.error.mutated);
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "base"), base);
        ASSERT(strlen(dlx_str(&c, "head_commit")) == 40);
        ASSERT_STR_EQ(dlx_str(&c, "next_command"),
                      "z23-dev dev land attach --seq=1");
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23-dev dev land attach --seq=1");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1 ") != NULL);
        ASSERT(strstr(dlx_err_evidence(&c), base) != NULL);
        ASSERT(dlx_blocked_wire(&c, action, evidence, reason,
                                sizeof(action)));
        ASSERT_STR_EQ(action, "z23-dev dev land attach --seq=1");
        ASSERT(strstr(evidence, "seq=1 ") != NULL);
        ASSERT(strstr(evidence, rig.tip) != NULL);
        ASSERT(strstr(reason, "z23-dev dev land attach --seq=1") != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23-dev dev land attach --seq=1");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        /* The named command, run as named, attaches and the pair lands. */
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_resolves_single_row(void)
{
    int failures = 0;
    TEST("land: attach without seq seals the one proven row lacking intent") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_resolves_single");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_resolves_single", base));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "target"), "resolved");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A deliberate signer action should consume the already passed proof and
 * publish under the same queue lock, without a second scheduled step. */
static int test_dev_land_attach_publish_one_window(void)
{
    int failures = 0;
    TEST("land: attach_publish seals and lands the exact proven pair in one beat") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_window");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_window", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(dlx_int(&c, "seq") == 1);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_exact_pair(void)
{
    int failures = 0;
    TEST("land: attach_publish refuses a reviewed pair that changed") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_exact_pair");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_exact_pair", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", base);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_CHANGED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_malformed_pair(void)
{
    int failures = 0;
    TEST("land: malformed present pair pins cannot become an unpinned push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_malformed_pair");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_malformed_pair", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_int(&c.input, "base", 0);
        (void)json_push_kv_int(&c.input, "head", 0);
        /* Exercise the handler too: a wire schema may reject earlier. */
        c.request.spec = NULL;
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "BAD_INPUT");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_wait_expires(void)
{
    int failures = 0;
    TEST("land: reviewed attach wait expires while proof is still pending") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_wait_expires");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_expires", base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_WAIT_EXPIRED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_wait_failure(void)
{
    int failures = 0;
    TEST("land: reviewed attach wait stops on a failed proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_wait_failure");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_failure", base));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_FAILED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_wait_busy(void)
{
    int failures = 0;
    int lockfd = -1;
    TEST("land: reviewed attach wait names an occupied step lock") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200];
        dlx_isolate("attach_publish_wait_busy");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_busy", base));
        dlx_landdir(land, sizeof(land));
        lockfd = dlx_step_lock_take(land);
        ASSERT(lockfd >= 0);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_STEP_WAIT_EXPIRED");
        dlx_end(&c);
        dlx_step_lock_release(lockfd);
        lockfd = -1;
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    if (lockfd >= 0) dlx_step_lock_release(lockfd);
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_moved_base(void)
{
    int failures = 0;
    TEST("land: attach_publish refuses a moved base without signing or pushing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64];
        dlx_isolate("attach_publish_moved_base");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_moved_base", base));
        const char *branch[] = {"checkout", "--quiet", "-B", "side", base,
                                NULL};
        const char *push[] = {"push", "--quiet", "origin", "HEAD:main", NULL};
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "EXPECTED_BASE_MISMATCH");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(flight, "base")), base);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_publish_push_checkpoint(void)
{
    int failures = 0;
    TEST("land: attach_publish never redispatches a prior push checkpoint") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400], row[8192];
        size_t used = 0;
        dlx_isolate("attach_publish_checkpoint");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_checkpoint", base));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, row, sizeof(row) - 1, &used));
        row[used] = '\0';
        char *phase = strstr(row, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        ASSERT(dlx_write(path, row));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_cancel_push_checkpoint(void)
{
    int failures = 0;
    TEST("land: cancel preserves a push checkpoint for reconciliation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400], row[8192];
        size_t used = 0;
        dlx_isolate("cancel_push_checkpoint");
        ASSERT(dlx_attach_proven_pair(&rig, "cancel_push_checkpoint", base));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, row, sizeof(row) - 1, &used));
        row[used] = '\0';
        char *phase = strstr(row, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        ASSERT(dlx_write(path, row));
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_target_none(void)
{
    int failures = 0;
    TEST("land: attach without seq and no proven row refuses and mutates nothing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_target_none");
        ASSERT(dlx_rig_make(&rig, "attach_target_none_rig"));
        /* Empty queue. */
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_NONE");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        /* A live row whose exact proof is still running is not a target. */
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_NONE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1") != NULL);
        const struct json_value *cands = dlx_arr(&c, "candidates");
        ASSERT(cands && cands->num_children == 0);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_explicit_unattachable(void)
{
    int failures = 0;
    TEST("land: attach with a seq that is not a proven pair names its state") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_explicit_unattachable");
        ASSERT(dlx_rig_make(&rig, "attach_explicit_unattachable_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_UNAVAILABLE");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1 state=queued") != NULL);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 9);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_UNAVAILABLE");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=9 not in the live queue")
               != NULL);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Model two live proven rows (a damaged or hand-edited queue): duplicate
 * the proven row under the next sequence number. */
static bool dlx_duplicate_proven_row(void)
{
    char land[1200], path[1400], wire[8192], twin[4096];
    size_t len = 0;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, wire, sizeof(wire) - 1, &len)) return false;
    wire[len] = '\0';
    char *eol = strchr(wire, '\n');
    if (!eol || eol[1] != '\0' || (size_t)(eol - wire) >= sizeof(twin))
        return false;
    memcpy(twin, wire, (size_t)(eol - wire));
    twin[eol - wire] = '\0';
    char *seq = strstr(twin, "\"seq\":1");
    if (!seq || (seq[7] >= '0' && seq[7] <= '9')) return false;
    seq[6] = '2';
    size_t used = strlen(wire);
    int n = snprintf(wire + used, sizeof(wire) - used, "%s\n", twin);
    return n > 0 && (size_t)n < sizeof(wire) - used && dlx_write(path, wire);
}

static int test_dev_land_attach_target_ambiguous(void)
{
    int failures = 0;
    TEST("land: attach without seq refuses two proven rows and lists both") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_target_ambiguous");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_target_ambiguous", base));
        ASSERT(dlx_duplicate_proven_row());
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_AMBIGUOUS");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "candidates=1,2") != NULL);
        const struct json_value *cands = dlx_arr(&c, "candidates");
        ASSERT(cands && cands->num_children == 2);
        ASSERT(json_get_int(&cands->children[0]) == 1);
        ASSERT(json_get_int(&cands->children[1]) == 2);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        /* An explicit seq still wins over the ambiguity. */
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        ASSERT_STR_EQ(dlx_str(&c, "target"), "explicit");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_attach_target_cases(void)
{
    int failures = 0;
    failures += test_dev_land_blocked_names_attach_target();
    failures += test_dev_land_attach_resolves_single_row();
    failures += test_dev_land_attach_publish_one_window();
    failures += test_dev_land_attach_publish_exact_pair();
    failures += test_dev_land_attach_publish_malformed_pair();
    failures += test_dev_land_attach_publish_wait_expires();
    failures += test_dev_land_attach_publish_wait_failure();
    failures += test_dev_land_attach_publish_wait_busy();
    failures += test_dev_land_attach_publish_moved_base();
    failures += test_dev_land_attach_publish_push_checkpoint();
    failures += test_dev_land_cancel_push_checkpoint();
    failures += test_dev_land_attach_target_none();
    failures += test_dev_land_attach_explicit_unattachable();
    failures += test_dev_land_attach_target_ambiguous();
    return failures;
}

/* Model a damaged local projection, while the proof stub deliberately admits
 * the pair. The real client must still enforce ancestry before dispatch. */
static bool dlx_replace_prepared_candidate(const char *ancestor)
{
    char land[1200], wt[1400], path[1400], wire[8192], divergent[64];
    size_t length;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, sizeof(wt), "%s/wt", land);
    const char *commit[] = { "-c", "user.name=land", "-c",
        "user.email=land@z23.invalid", "commit-tree", "HEAD^{tree}",
        "-p", ancestor, "-m", "divergent prepared candidate", NULL };
    if (dlx_git_out(wt, commit, divergent, sizeof(divergent)) != 0 ||
        strlen(divergent) != 40)
        return false;
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, wire, sizeof(wire), &length)) return false;
    wire[length] = '\0';
    char *local = strstr(wire, "\"local\":\"");
    if (!local || strlen(local + 9) < 41 || local[49] != '"') return false;
    memcpy(local + 9, divergent, 40);
    return dlx_write(path, wire);
}

static int test_dev_land_nonfastforward_client_guard(void)
{
    int failures = 0;
    TEST("land: expected-base comparison never authorizes non-fast-forward dispatch") {
        struct dlx_rig rig;
        struct dlx_call c;
        char ancestor[64], base[64], after[64], wrapper[700], marker[700];
        char first_log[1400];
        dlx_isolate("nonfastforward_client");
        ASSERT(dlx_rig_make(&rig, "nonfastforward_client_rig"));
        ASSERT(dlx_origin_main(&rig, ancestor));
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", rig.tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        (void)snprintf(first_log, sizeof(first_log), "%s", dlx_str(&c, "log_path"));
        dlx_end(&c);
        ASSERT(dlx_replace_prepared_candidate(ancestor));
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/push-invoked", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' > \"$1/hooks/push-invoked\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_file_exists(marker));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, base);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "attempt")), 2);
        char log[8192];
        size_t log_length;
        ASSERT(dlx_slurp(first_log, log, sizeof(log), &log_length));
        log[log_length] = '\0';
        ASSERT(strstr(log, "proven base is not an ancestor of candidate") != NULL);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_expected_base_race(void)
{
    int failures = 0;
    TEST("land: a fast-forward push still requires the proven remote base") {
        struct dlx_rig rig;
        struct dlx_call c;
        char ancestor[64], after[64], wrapper[700], marker[700], script[1800];
        dlx_isolate("expected_base_race");
        ASSERT(dlx_rig_make(&rig, "expected_base_race_rig"));
        ASSERT(dlx_origin_main(&rig, ancestor));
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, push) == 0);
        char base[64];
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", rig.tip));
        const char *protect[] = { "config", "receive.denyNonFastForwards", "true", NULL };
        ASSERT(dlx_git(rig.bare, protect) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/base-rewound", rig.bare);
        (void)snprintf(script, sizeof(script),
            "#!/bin/sh\n"
            "git -C \"$1\" update-ref refs/heads/main %s %s || exit 73\n"
            "printf 'rewound\\n' > \"$1/hooks/base-rewound\" || exit 74\n"
            "exec git-receive-pack \"$@\"\n", ancestor, base);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_file_exists(marker));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, ancestor);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "attempt")), 2);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_recovery_ignores_replace_refs(void)
{
    int failures = 0;
    TEST("land: restart cannot mistake a replaced remote commit for publication") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64], land[1200], wt[1400];
        char tree[64], forged[64], body[64];
        dlx_isolate("recovery_replace_ref");
        ASSERT(dlx_rig_make(&rig, "recovery_replace_ref_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);

        /* A competing integrator moves the real remote to a sibling tip.
         * A local replacement object lies about that tip's parent. This
         * simulates recovery after the persisted prove phase, not a push. */
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base, NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        const char *tree_args[] = { "rev-parse", "HEAD^{tree}", NULL };
        ASSERT(dlx_git_out(rig.clone, tree_args, tree, sizeof(tree)) == 0);
        const char *forge[] = { "-c", "user.name=land", "-c",
            "user.email=land@z23.invalid", "commit-tree", tree,
            "-p", rig.tip, "-m", "false local ancestry", NULL };
        ASSERT(dlx_git_out(wt, forge, forged, sizeof(forged)) == 0);
        const char *replace[] = { "replace", stranger, forged, NULL };
        ASSERT(dlx_git(wt, replace) == 0);
        const char *apparent[] = { "merge-base", "--is-ancestor",
            rig.tip, stranger, NULL };
        const char *actual[] = { "--no-replace-objects", "merge-base",
            "--is-ancestor", rig.tip, stranger, NULL };
        ASSERT(dlx_git(wt, apparent) == 0);
        ASSERT(dlx_git(wt, actual) == 1);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);

        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);

        /* Keep the misleading local ref in place. The persisted request
         * must still replay the candidate onto the real sibling and land
         * its bytes, not converge to an empty rebase of the fake history. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        const char *show[] = { "show", "main:change.txt", NULL };
        ASSERT(dlx_git_out(rig.bare, show, body, sizeof(body)) == 0);
        ASSERT_STR_EQ(body, "one");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_postpush_result_unconfirmed(void)
{
    int failures = 0;
    TEST("land: reachable remote must still contain the pushed candidate") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hook[700], marker[700], received[80];
        size_t received_len;
        dlx_isolate("postpush_result_unconfirmed");
        ASSERT(dlx_rig_make(&rig, "postpush_result_unconfirmed_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/received-tip", rig.bare);
        ASSERT(dlx_write(hook,
            "#!/bin/sh\n"
            "read -r old new ref || exit 73\n"
            "test \"$ref\" = refs/heads/main || exit 74\n"
            "printf '%s\\n' \"$new\" > hooks/received-tip || exit 75\n"
            "git update-ref \"$ref\" \"$old\" \"$new\"\n"));
        ASSERT(chmod(hook, 0700) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, strlen(rig.tip) + 1);
        ASSERT(memcmp(received, rig.tip, strlen(rig.tip)) == 0);
        ASSERT(received[received_len - 1] == '\n');
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_RESULT_UNCONFIRMED");
        ASSERT(dlx_refusal_serializes(&c));
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        dlx_end(&c);
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#endif /* !defined(_WIN32) */

#if !defined(_WIN32)
static int test_dev_land_vendor_dependencies(void)
{
    int failures = 0;
    TEST("land: the landing worktree gets the proof's vendored "
        "dependencies from the submitting checkout") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400], source[1400], exclude[1400];
        char abandoned[1500];
        char alias_dir[512], alias[700];
        char aaa_source[1400], aaa_target[1400], aaa_bytes[2][8] = {{0}};
        char second[64], third[64], bytes[3][8] = {{0}};
        struct stat st, source_st, landed_st, alias_st;
        FILE *file;
        dlx_isolate("depsok");
        ASSERT(dlx_rig_make(&rig, "depsok_rig"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        (void)snprintf(source, sizeof(source), "%s/vendor/lib/libfoo.a",
                       rig.clone);
        const struct timespec pinned[2] = {
            { .tv_sec = 1700000000, .tv_nsec = 123456789 },
            { .tv_sec = 1700000000, .tv_nsec = 123456789 },
        };
        ASSERT(chmod(source, 0640) == 0);
        ASSERT(utimensat(AT_FDCWD, source, pinned, 0) == 0);
        ASSERT(stat(source, &source_st) == 0 && S_ISREG(source_st.st_mode));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        /* Forces dl_wt_vendor_ensure()/dl_wt_hotswap_ensure() to run for
         * real even though ZCL_LAND_PROOF_STUB replaces the proof itself —
         * see dl_deps_test_force()'s comment in native_dev_land.c. The
         * hooks refresh shares the forced prerequisite set, so the
         * submitting checkout also carries a hook binary to install from. */
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        /* Every dependency the proof's own dependencies[] array names (the
         * vendor group, plus the Linux hotswap fixtures) is now present in
         * the landing worktree, materialized from the submitting checkout
         * rather than left for the proof to discover missing. */
        dlx_landdir(wt, sizeof(wt));
        const char *const required_inputs[] = {
            "vendor/sqlite3.c", "vendor/tor/.provenance", "vendor/tor/Makefile",
        };
        const char *const required_bytes[] = { "sqlite\n", "stamp\n", "CC=gcc\n" };
        for (size_t i = 0; i < 3; ++i) {
            char copied[16] = {0};
            (void)snprintf(source, sizeof(source), "%s/%s", rig.clone,
                           required_inputs[i]);
            (void)snprintf(check, sizeof(check), "%s/wt/%s", wt,
                           required_inputs[i]);
            ASSERT(stat(source, &source_st) == 0);
            ASSERT(stat(check, &landed_st) == 0);
            ASSERT(source_st.st_dev != landed_st.st_dev ||
                   source_st.st_ino != landed_st.st_ino);
            file = fopen(check, "rb");
            ASSERT(file != NULL);
            ASSERT(fread(copied, 1, sizeof(copied), file) ==
                   strlen(required_bytes[i]));
            ASSERT(fclose(file) == 0);
            ASSERT(strcmp(copied, required_bytes[i]) == 0);
        }
        (void)snprintf(source, sizeof(source), "%s/vendor/lib/libfoo.a",
                       rig.clone);
        ASSERT(stat(source, &source_st) == 0);
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a",
                       wt);
        ASSERT(stat(check, &st) == 0 && S_ISREG(st.st_mode));
        /* A landing generation must own its dependency inode. A hard link
         * lets later donor metadata or byte changes mutate sealed evidence. */
        ASSERT(st.st_dev != source_st.st_dev || st.st_ino != source_st.st_ino);
        ASSERT((st.st_mode & 07777) == (source_st.st_mode & 07777));
#if defined(__APPLE__)
        ASSERT(st.st_mtimespec.tv_sec == source_st.st_mtimespec.tv_sec);
        ASSERT(st.st_mtimespec.tv_nsec == source_st.st_mtimespec.tv_nsec);
#else
        ASSERT(st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
#endif
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/include/foo.h",
                       wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/build/hotswap/zcl_rollback_fixture_a.so", wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/build/hotswap/zcl_rollback_fixture_b.so", wt);
        ASSERT(stat(check, &st) == 0);

        /* An old generation may explain exactly two links: the submitting
         * dependency and the landing copy. Repair that known old shape. */
        (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude",
                       rig.clone);
        ASSERT(dlx_write(exclude, "vendor/\nbuild/\n"));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a", wt);
        ASSERT(unlink(check) == 0);
        ASSERT(link(source, check) == 0);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 2);
        /* A prior repair died before rename. The historical PID-only temp
         * name must not block this exact two-link recovery after PID reuse. */
        int abandoned_len = snprintf(abandoned, sizeof(abandoned),
                                     "%s.tmp.%ld", check, (long)getpid());
        ASSERT(abandoned_len > 0);
        ASSERT(abandoned_len < (int)sizeof(abandoned));
        ASSERT(dlx_write(abandoned, "abandoned\n"));
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        const char *const ignored[] = {
            "check-ignore", "-q", "vendor/lib/libfoo.a", NULL,
        };
        const char *const tracked[] = {
            "ls-files", "--error-unmatch", "vendor/lib/libfoo.a", NULL,
        };
        ASSERT(dlx_git(rig.clone, ignored) == 0);
        ASSERT(dlx_git(rig.clone, tracked) != 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 1);
        ASSERT(stat(check, &landed_st) == 0 && landed_st.st_nlink == 1);
        ASSERT(st.st_ino != landed_st.st_ino);
        ASSERT(stat(abandoned, &st) == 0 && st.st_nlink == 1);
        ASSERT(unlink(abandoned) == 0);
        ASSERT(st.st_dev != landed_st.st_dev || st.st_ino != landed_st.st_ino);
        ASSERT((landed_st.st_mode & 07777) == (source_st.st_mode & 07777));
#if defined(__APPLE__)
        ASSERT(landed_st.st_mtimespec.tv_sec == source_st.st_mtimespec.tv_sec);
        ASSERT(landed_st.st_mtimespec.tv_nsec ==
               source_st.st_mtimespec.tv_nsec);
#else
        ASSERT(landed_st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(landed_st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
#endif
        file = fopen(check, "rb");
        ASSERT(file != NULL);
        ASSERT(fread(bytes[0], 1, sizeof(bytes[0]), file) == 5);
        ASSERT(fclose(file) == 0);
        ASSERT(memcmp(bytes[0], "fake\n", 5) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);

        /* A third spelling has no unique explanation. Refuse atomically,
         * leaving every link and byte untouched for operator inspection. */
        test_make_tmpdir(alias_dir, sizeof(alias_dir), "dev_land",
                         "dependency_extra_alias");
        (void)snprintf(alias, sizeof(alias), "%s/libfoo.alias", alias_dir);
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libaaa.a", "aaa\n"));
        (void)snprintf(aaa_source, sizeof(aaa_source),
                       "%s/vendor/lib/libaaa.a", rig.clone);
        (void)snprintf(aaa_target, sizeof(aaa_target),
                       "%s/wt/vendor/lib/libaaa.a", wt);
        ASSERT(link(aaa_source, aaa_target) == 0);
        ASSERT(stat(aaa_source, &st) == 0 && st.st_nlink == 2);
        ASSERT(unlink(check) == 0);
        ASSERT(link(source, check) == 0);
        ASSERT(link(source, alias) == 0);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 3);
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", third));
        const char *const ignored_aaa[] = {
            "check-ignore", "-q", "vendor/lib/libaaa.a", NULL,
        };
        const char *const tracked_aaa[] = {
            "ls-files", "--error-unmatch", "vendor/lib/libaaa.a", NULL,
        };
        ASSERT(dlx_git(rig.clone, ignored_aaa) == 0);
        ASSERT(dlx_git(rig.clone, tracked_aaa) != 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, third);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unexplained_links:"
                      "vendor/lib/libfoo.a") != NULL);
        dlx_end(&c);
        const char *const aaa_paths[] = {aaa_source, aaa_target};
        for (size_t i = 0; i < 2; i++) {
            ASSERT(stat(aaa_paths[i], &alias_st) == 0);
            ASSERT(alias_st.st_nlink == 2);
            file = fopen(aaa_paths[i], "rb");
            ASSERT(file != NULL);
            ASSERT(fread(aaa_bytes[i], 1, sizeof(aaa_bytes[i]), file) == 4);
            ASSERT(fclose(file) == 0);
            ASSERT(memcmp(aaa_bytes[i], "aaa\n", 4) == 0);
        }
        const char *const linked_paths[] = {source, check, alias};
        for (size_t i = 0; i < 3; i++) {
            ASSERT(stat(linked_paths[i], &alias_st) == 0);
            ASSERT(alias_st.st_nlink == 3);
            file = fopen(linked_paths[i], "rb");
            ASSERT(file != NULL);
            ASSERT(fread(bytes[i], 1, sizeof(bytes[i]), file) == 5);
            ASSERT(fclose(file) == 0);
            ASSERT(memcmp(bytes[i], "fake\n", 5) == 0);
        }
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

#if !defined(_WIN32)
static int test_dev_land_missing_tor_makefile(void)
{
    int failures = 0;
    TEST("land: missing Tor Makefile refuses before requesting proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *const available[] = {
            "vendor/lib/libfoo.a", "vendor/include/foo.h",
            "vendor/sqlite3.c", "vendor/tor/libtor.a",
            "vendor/tor/.provenance",
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "build/hotswap/zcl_rollback_fixture_a.so",
            "build/hotswap/zcl_rollback_fixture_b.so",
        };
        dlx_isolate("tormakemissing");
        ASSERT(dlx_rig_make(&rig, "tormakemissing_rig"));
        for (size_t i = 0; i < sizeof(available) / sizeof(available[0]); ++i)
            ASSERT(dlx_write_dep(rig.clone, available[i], "fixture\n"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:"
                      "vendor/tor/Makefile ") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_dev_land(void);
#if !defined(_WIN32)
static bool dlx_tree_bytes(const char *path, const void *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool dlx_tree_types_make(struct dlx_rig *rig)
{
    if (!dlx_rig_make(rig, "tree_types")) return false;
    char path[1200];
    (void)snprintf(path, sizeof(path), "%s/space\tline\n.bin", rig->clone);
    static const unsigned char bytes[] = { 'A', 0, 'B' };
    if (!dlx_tree_bytes(path, bytes, sizeof(bytes))) return false;
    (void)snprintf(path, sizeof(path), "%s/run", rig->clone);
    if (!dlx_write(path, "") || chmod(path, 0755) != 0) return false;
    (void)snprintf(path, sizeof(path), "%s/link", rig->clone);
    if (symlink("../untrusted-target", path) != 0) return false;
    if (!dlx_commit(rig->clone, "marker", "types\n", rig->tip)) return false;
    char dependency[64];
    memcpy(dependency, rig->tip, sizeof(dependency));
    return dlx_gitlink_commit(rig->clone, "dependency", dependency, "unused", rig->tip);
}

static bool dlx_tree_types_match(const struct zcl_dev_git_tree *tree)
{
    bool executable = false, symlink_bytes = false, binary = false;
    unsigned char expected[32];
    static const unsigned char tagged[] = { 0x20, 'A', 0, 'B' };
    sha3_256(tagged, sizeof(tagged), expected);
    unsigned char link_hash[32];
    static const unsigned char link_bytes[] = "\x20../untrusted-target";
    sha3_256(link_bytes, sizeof(link_bytes) - 1, link_hash);
    for (size_t i = 0; i < tree->files.count; ++i) {
        const struct vcs_entry *entry = &tree->files.entries[i];
        if (!strcmp(entry->path, "run")) executable = entry->mode == 0100755u && entry->size == 0;
        if (!strcmp(entry->path, "link")) symlink_bytes = entry->mode == 0120000u &&
            entry->size == 19 && !memcmp(entry->blob, link_hash, 32);
        if (!strcmp(entry->path, "space\tline\n.bin")) binary = !memcmp(entry->blob, expected, 32);
    }
    return executable && symlink_bytes && binary;
}

static bool dlx_tree_closure_changes_with_gitlink(struct dlx_rig *rig,
    const uint8_t files_root[32], const uint8_t closure_root[32])
{
    char prior_tip[64];
    (void)snprintf(prior_tip, sizeof(prior_tip), "%s", rig->tip);
    if (!dlx_gitlink_commit(rig->clone, "dependency", prior_tip,
                            "unused", rig->tip))
        return false;
    struct zcl_dev_git_tree later = {0};
    struct zcl_result result = zcl_dev_git_tree_read(
        rig->clone, rig->tip, 10000, &later);
    bool ok = result.ok && later.gitlinks == 1 &&
        memcmp(files_root, later.file_manifest_root, 32) == 0 &&
        memcmp(closure_root, later.source_closure_root, 32) != 0 &&
        strcmp(later.links[0].oid, prior_tip) == 0;
    zcl_dev_git_tree_free(&later);
    return ok;
}

static bool dlx_tree_dependency_observation(struct dlx_rig *rig,
    const struct zcl_dev_git_tree *super)
{
    struct zcl_dev_git_tree dependency = {0};
    struct zcl_result result = zcl_dev_git_tree_read(
        rig->clone, super->links[0].oid, 10000, &dependency);
    if (!result.ok || dependency.gitlinks != 0) {
        zcl_dev_git_tree_free(&dependency);
        return false;
    }
    struct zcl_dev_git_dependency_input input = {
        .path = "dependency", .repo_locator = rig->clone,
    };
    memcpy(input.expected_source_closure_root,
           dependency.source_closure_root, 32);
    zcl_dev_git_tree_free(&dependency);
    struct zcl_dev_git_dependency_check check;
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (!result.ok || !check.complete || check.dependencies_verified != 1 ||
        memcmp(check.super_source_closure_root,
               super->source_closure_root, 32) != 0 ||
        !zcl_bytes_any_set(check.verified_dependency_root, 32))
        return false;
    input.expected_source_closure_root[0] ^= 1;
    memset(&check, 0xa5, sizeof(check));
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&check,
                                      sizeof(check))) return false;
    input.expected_source_closure_root[0] ^= 1;
    input.path = "other";
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&check,
                                      sizeof(check))) return false;
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        NULL, 0, 10000, &check);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&check, sizeof(check));
}

static bool dlx_tree_malformed_head(struct dlx_rig *rig, const char *a, const char *b,
                                   char head[64])
{
    char oid[64], tree_oid[64], path[1200];
    const char *lookup[] = { "rev-parse", "HEAD:change.txt", NULL };
    if (dlx_git_out(rig->clone, lookup, oid, sizeof(oid)) != 0) return false;
    unsigned char raw[1024], address[20]; size_t len = 0;
    for (size_t i = 0; i < sizeof(address); ++i) {
        unsigned value = 0;
        if (sscanf(oid + i * 2, "%2x", &value) != 1) return false;
        address[i] = (unsigned char)value;
    }
    const char *names[] = { a, b };
    for (size_t i = 0; i < 2; ++i) {
        int n = snprintf((char *)raw + len, sizeof(raw) - len, "100644 %s", names[i]);
        if (n < 0 || (size_t)n + 1 + sizeof(address) > sizeof(raw) - len) return false;
        len += (size_t)n + 1;
        memcpy(raw + len, address, sizeof(address)); len += sizeof(address);
    }
    (void)snprintf(path, sizeof(path), "%s/raw-tree", rig->clone);
    if (!dlx_tree_bytes(path, raw, len)) return false;
    const char *store[] = { "hash-object", "--literally", "-t", "tree", "-w", path, NULL };
    if (dlx_git_out(rig->clone, store, tree_oid, sizeof(tree_oid)) != 0) return false;
    const char *commit[] = { "-c", "user.name=tree", "-c", "user.email=tree@z23.invalid",
        "commit-tree", tree_oid, "-m", "malformed fixture", NULL };
    return dlx_git_out(rig->clone, commit, head, 64) == 0;
}

static int test_dev_land_tree_types(void)
{
    int failures = 0;
    TEST("land: tree observation preserves binary paths, modes and unresolved gitlinks") {
        struct dlx_rig rig;
        ASSERT(dlx_tree_types_make(&rig));
        char expected_link[64];
        const char *lookup[] = { "rev-parse", "HEAD:dependency", NULL };
        ASSERT(dlx_git_out(rig.clone, lookup, expected_link, sizeof(expected_link)) == 0);
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        bool matched = r.ok && tree.files.count == 7 && tree.gitlinks == 1 && tree.symlinks == 1;
        if (matched) matched = !strcmp(tree.links[0].path, "dependency") &&
            !strcmp(tree.links[0].oid, expected_link) && dlx_tree_types_match(&tree);
        uint8_t files_root[32], closure_root[32];
        if (matched) {
            memcpy(files_root, tree.file_manifest_root, 32);
            memcpy(closure_root, tree.source_closure_root, 32);
            matched = zcl_bytes_any_set(files_root, 32) &&
                      zcl_bytes_any_set(closure_root, 32);
        }
        if (matched) matched = dlx_tree_dependency_observation(&rig, &tree);
        zcl_dev_git_tree_free(&tree);
        ASSERT(matched);
        ASSERT(dlx_tree_closure_changes_with_gitlink(&rig,
            files_root, closure_root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_dev_land_tree_replacements(void)
{
    int failures = 0;
    TEST("land: exact tree ignores replacement refs and inherited repository override") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "tree_replacement"));
        char original[64], replacement[64];
        (void)snprintf(original, sizeof(original), "%s", rig.tip);
        ASSERT(dlx_commit(rig.clone, "later.txt", "replacement bytes\n", replacement));
        const char *replace[] = { "replace", original, replacement, NULL };
        ASSERT(dlx_git(rig.clone, replace) == 0);
        char saved[4096];
        const char *prior = getenv("GIT_DIR");
        bool had = prior != NULL;
        ASSERT(!prior || strlen(prior) < sizeof(saved));
        (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
        ASSERT(setenv("GIT_DIR", rig.bare, 1) == 0);
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, original, 10000, &tree);
        int restored = had ? setenv("GIT_DIR", saved, 1) : unsetenv("GIT_DIR");
        bool exact = r.ok && tree.files.count == 2;
        zcl_dev_git_tree_free(&tree);
        ASSERT(restored == 0);
        ASSERT(exact);
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_tree_promisor(struct dlx_rig *rig, char marker[1200], char oid[64])
{
    if (!dlx_rig_make(rig, "tree_promisor")) return false;
    char helper[1200], body[1600], remote[1300], object[1200];
    (void)snprintf(marker, 1200, "%s/fetch-marker", rig->clone);
    (void)snprintf(helper, sizeof(helper), "%s/fetch-helper", rig->clone);
    (void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf invoked > '%s'\nexit 1\n", marker);
    if (!dlx_write(helper, body) || chmod(helper, 0755) != 0) return false;
    (void)snprintf(remote, sizeof(remote), "ext::%s", helper);
    const char *promisor[] = { "config", "remote.trap.promisor", "true", NULL };
    const char *url[] = { "config", "remote.trap.url", remote, NULL };
    const char *partial[] = { "config", "extensions.partialClone", "trap", NULL };
    const char *lookup[] = { "rev-parse", "HEAD:change.txt", NULL };
    if (dlx_git(rig->clone, promisor) || dlx_git(rig->clone, url) ||
        dlx_git(rig->clone, partial) || dlx_git_out(rig->clone, lookup, oid, 64)) return false;
    (void)snprintf(object, sizeof(object), "%s/.git/objects/%.2s/%s", rig->clone, oid, oid + 2);
    return unlink(object) == 0;
}

static int test_dev_land_tree_missing(void)
{
    int failures = 0;
    TEST("land: missing promisor blob refuses without invoking its armed remote helper") {
        struct dlx_rig rig; char marker[1200], oid[64];
        ASSERT(dlx_tree_promisor(&rig, marker, oid));
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        bool refused = !r.ok && !tree.files.entries && !tree.links;
        zcl_dev_git_tree_free(&tree);
        ASSERT(refused);
        ASSERT(!dlx_file_exists(marker));
        const char *control[] = { "/usr/bin/env", "GIT_ALLOW_PROTOCOL=ext", "git", "-C", rig.clone,
            "-c", "protocol.ext.allow=always", "cat-file", "blob", oid, NULL };
        char sink[8];
        (void)zcl_spawn_capture(control, sink, sizeof(sink), 5000);
        ASSERT(dlx_file_exists(marker));
        PASS();
    } _test_next:;
    return failures;
}

static int test_dev_land_tree_malformed(void)
{
    int failures = 0;
    TEST("land: duplicate, ancestor-collision and traversal trees refuse") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "tree_malformed"));
        const char *first[] = { "same", "a", "../escape" };
        const char *second[] = { "same", "a/b", "valid" };
        for (size_t i = 0; i < 3; ++i) {
            char head[64];
            ASSERT(dlx_tree_malformed_head(&rig, first[i], second[i], head));
            struct zcl_dev_git_tree tree = {0};
            struct zcl_result r = zcl_dev_git_tree_read(rig.clone, head, 10000, &tree);
            bool refused = !r.ok && !tree.files.entries && !tree.links && tree.gitlinks == 0;
            zcl_dev_git_tree_free(&tree);
            ASSERT(refused);
        }
        PASS();
    } _test_next:;
    return failures;
}
#endif

static int test_dev_land_exact_tree(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: committed blob bytes retain canonical hashes despite dirty worktree") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "exact_tree"));
        char path[1200];
        (void)snprintf(path, sizeof(path), "%s/change.txt", rig.clone);
        ASSERT(dlx_write(path, "different worktree bytes\n"));
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        unsigned char expected[32];
        static const unsigned char tagged[] = { 0x20, 'o', 'n', 'e', '\n' };
        sha3_256(tagged, sizeof(tagged), expected);
        bool matched = r.ok && tree.files.count == 2;
        if (matched)
            matched = strcmp(tree.files.entries[0].path, "change.txt") == 0 &&
                tree.files.entries[0].size == 4 &&
                memcmp(tree.files.entries[0].blob, expected, 32) == 0;
        matched = matched && tree.gitlinks == 0 && tree.symlinks == 0;
        zcl_dev_git_tree_free(&tree);
        ASSERT(matched);
        PASS();
    } _test_next:;
#endif
    return failures;
}

#if !defined(_WIN32)
/* State threaded between the three phases below: one worktree fixture whose
 * committed content is bound by a single captured source_root across mode
 * refusal, bounded-admission refusal, and post-commit drift detection. Split
 * out of one TEST body (each phase kept its own assertions verbatim) only to
 * bring per-function cyclomatic complexity under the lint cap. */
struct dlx_source_binding_state {
    struct dlx_rig rig;
    char change_path[1200];
    char seed_path[1200];
    uint8_t source[32];
    uint8_t wrong_root[32];
    uint8_t publication_root[32];
    uint8_t attachment_root[32];
    uint8_t publisher_secret[32];
    uint8_t publisher_signer[32];
    char publication_head[80];
    char bundle_path[1200];
    size_t wire_len;
};

/* Fixture with two 0600 files, plus the mode-refusal check: an admission
 * comparator refuses unrepresentable file modes before it looks at content. */
static bool dlx_source_binding_setup_fixture(struct dlx_source_binding_state *st)
{
    if (!dlx_rig_make(&st->rig, "source_binding")) return false;
    char exclude[1200];
    (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude", st->rig.clone);
    if (!dlx_write(exclude, ".zvcs/\n")) return false;
    (void)snprintf(st->change_path, sizeof(st->change_path), "%s/change.txt", st->rig.clone);
    (void)snprintf(st->seed_path, sizeof(st->seed_path), "%s/seed.txt", st->rig.clone);
    if (chmod(st->change_path, 0600) != 0) return false;
    if (chmod(st->seed_path, 0600) != 0) return false;
    if (vcs_tree_capture_path(st->rig.clone, st->source) != 0) return false;
    struct zcl_dev_git_source_check mode_check = {0};
    struct zcl_result mode_result = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &mode_check);
    if (mode_result.ok) return false;
    if (!mode_check.observed) return false;
    if (mode_check.unrepresentable_modes != 2) return false;
    return true;
}

/* Representable modes admitted under an exact entry budget; stashes an
 * object addressed under a wrong root for the next phase's refusal checks. */
static bool dlx_source_binding_setup_admit(struct dlx_source_binding_state *st)
{
    if (chmod(st->change_path, 0644) != 0) return false;
    if (chmod(st->seed_path, 0644) != 0) return false;
    if (vcs_tree_capture_path(st->rig.clone, st->source) != 0) return false;
    struct vcs_manifest admitted = {0};
    if (!vcs_tree_load_bounded(st->rig.clone, st->source, 8u * 1024u * 1024u, 2, &admitted))
        return false;
    if (admitted.count != 2) { vcs_manifest_free(&admitted); return false; }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!vcs_manifest_serialize(&admitted, &wire, &wire_len)) {
        vcs_manifest_free(&admitted);
        return false;
    }
    memset(st->wrong_root, 0, sizeof(st->wrong_root));
    st->wrong_root[0] = 0xA5;
    bool put_ok = vcs_object_put_addressed(st->rig.clone, st->wrong_root, wire, wire_len);
    free(wire);
    vcs_manifest_free(&admitted);
    if (!put_ok) return false;
    st->wire_len = wire_len;
    return true;
}

static bool dlx_source_binding_setup(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_setup_fixture(st)) return false;
    if (!dlx_source_binding_setup_admit(st)) return false;
    return true;
}

static bool dlx_source_attachment_store(struct dlx_source_binding_state *st,
    const struct vcs_zcode_publication_v1 *intent,
    const uint8_t publication_root[32], uint8_t attachment_root[32])
{
    struct vcs_zcode_publication_attachment_v1 attachment = {
        .schema_version = 1, .created_unix = intent->created_unix + 1,
    };
    memcpy(attachment.publication_root, publication_root, 32);
    memcpy(attachment.expected_base, intent->expected_base, 32);
    memcpy(attachment.head_commit, intent->head_commit, 32);
    return zcl_hex_decode_lower(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            attachment.bundle_sha256, 32) &&
        vcs_zcode_publication_attachment_seal(&attachment,
            st->publisher_secret, st->publisher_signer) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_attachment_store_verified(st->rig.clone,
            &attachment, st->publisher_signer, attachment_root);
}

static bool dlx_source_publication_fixture(
    struct dlx_source_binding_state *st,
    struct vcs_zcode_publication_v1 *out_intent, char base[80])
{
    uint8_t seed[32] = {41};
    ed25519_keypair(st->publisher_signer, st->publisher_secret, seed);
    struct vcs_zcode_candidate_v1 candidate = {
        .schema_version = 1, .sequence = 1, .created_unix = 1000,
    };
    memset(candidate.task_root, 1, 32);
    memset(candidate.base_source_root, 2, 32);
    memset(candidate.patch_root, 3, 32);
    memcpy(candidate.candidate_source_root, st->source, 32);
    memset(candidate.adapter_policy_root, 4, 32);
    memcpy(candidate.author_pubkey, st->publisher_signer, 32);
    uint8_t candidate_root[32], candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_root(&candidate, candidate_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&candidate, candidate_wire) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(st->rig.clone, candidate_root,
                                  candidate_wire, sizeof(candidate_wire)))
        return false;
    if (!dlx_origin_main(&st->rig, base)) return false;
    struct vcs_zcode_publication_v1 intent = {
        .schema_version = 1,
        .git_object_format = VCS_ZCODE_PUBLICATION_GIT_OID_20,
        .target_ref = "refs/heads/main",
        .created_unix = 1001,
    };
    memcpy(intent.candidate_root, candidate_root, 32);
    memset(intent.proof_set_root, 5, 32);
    memset(intent.target_identity_root, 6, 32);
    memset(intent.authority_root, 7, 32);
    if (!zcl_hex_decode_lower(base, intent.expected_base, 20) ||
        !zcl_hex_decode_lower(st->rig.tip, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK)
        return false;
    if (!vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, st->publication_root))
        return false;
    (void)snprintf(st->bundle_path, sizeof(st->bundle_path),
                   "%s/.zvcs/test.bundle", st->rig.clone);
    if (!dlx_write(st->bundle_path, "abc")) return false;
    if (!dlx_source_attachment_store(st, &intent, st->publication_root,
                                     st->attachment_root))
        return false;
    (void)snprintf(st->publication_head, sizeof(st->publication_head), "%s",
                   st->rig.tip);
    *out_intent = intent;
    return true;
}

static bool dlx_source_publication_binding(struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    char base[80];
    if (!dlx_source_publication_fixture(st, &intent, base)) return false;
    struct zcl_dev_git_publication_check checked = {0};
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root,
        intent.target_ref, base, st->rig.tip, 1024, 10000, &checked);
    if (!result.ok || !checked.verified ||
        memcmp(checked.attachment_root, st->attachment_root, 32) != 0 ||
        memcmp(checked.source_root, st->source, 32) != 0 ||
        strcmp(checked.expected_base, base) != 0 ||
        strcmp(checked.head, st->rig.tip) != 0)
        return false;
    memset(&checked, 0xa5, sizeof(checked));
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, "refs/heads/other", base,
        st->rig.tip, 1024, 10000, &checked);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    uint8_t wrong_target[32];
    memcpy(wrong_target, intent.target_identity_root, 32);
    wrong_target[0] ^= 1;
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        wrong_target, intent.target_ref, base, st->rig.tip,
        1024, 10000, &checked);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, intent.target_ref,
        st->rig.tip, st->rig.tip, 1024, 10000, &checked);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_bundle_refusals(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    char base[80];
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent) ||
        !dlx_origin_main(&st->rig, base) ||
        !dlx_write(st->bundle_path, "abd"))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root, intent.target_ref,
        base, st->rig.tip, 1024, 10000, &checked);
    if (result.ok || strcmp(result.message,
            "git-publication: actual bundle digest mismatch") != 0 ||
        zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)) ||
        !dlx_write(st->bundle_path, "abc"))
        return false;
    result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root, intent.target_ref,
        base, st->rig.tip, 2, 10000, &checked);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_content_drift(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent))
        return false;
    char base[80];
    if (!dlx_origin_main(&st->rig, base)) return false;
    /* The new head descends from the base, but its committed content is no
     * longer the candidate's source. A freshly signed intent cannot hide it. */
    if (!zcl_hex_decode_lower(st->rig.tip, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK)
        return false;
    uint8_t drift_root[32];
    if (!vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, drift_root))
        return false;
    uint8_t drift_attachment_root[32];
    if (!dlx_source_attachment_store(st, &intent, drift_root,
                                     drift_attachment_root))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        drift_root, drift_attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root,
        intent.target_ref, base, st->rig.tip, 1024, 10000, &checked);
    if (result.ok || strcmp(result.message,
            "git-publication: committed source differs from candidate") != 0 ||
        zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    return true;
}

static bool dlx_source_publication_competing_base(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    uint8_t drift_root[32];
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent))
        return false;
    /* A competing base younger than the frozen head passes pair equality,
     * but fails the independent fast-forward ancestry check. */
    if (!zcl_hex_decode_lower(st->rig.tip, intent.expected_base, 20) ||
        !zcl_hex_decode_lower(st->publication_head, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK ||
        !vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, drift_root))
        return false;
    uint8_t drift_attachment_root[32];
    if (!dlx_source_attachment_store(st, &intent, drift_root,
                                     drift_attachment_root))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone, drift_root,
        drift_attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, intent.target_ref,
        st->rig.tip, st->publication_head, 1024, 10000, &checked);
    return !result.ok && strcmp(result.message,
        "git-publication: expected base is not an ancestor") == 0 &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_drift(struct dlx_source_binding_state *st)
{
    return dlx_source_publication_content_drift(st) &&
           dlx_source_publication_competing_base(st);
}

/* Bounded admission refuses a wrong structural root, an over-large declared
 * entry count, a truncated byte budget and a too-small entry budget, while
 * the exact root/byte-budget/entry-budget combination — and the unbounded
 * loader — both admit the same two entries. */
/* A wrong structural root and an over-large declared entry count are both
 * refused, each leaving the output manifest empty. */
static bool dlx_source_binding_bounds_refusals(struct dlx_source_binding_state *st)
{
    struct vcs_manifest admitted = {0};
    if (vcs_tree_load_bounded(st->rig.clone, st->wrong_root, st->wire_len, 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    uint8_t excessive[9] = {VCS_MANIFEST_VERSION, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff};
    uint8_t excessive_root[32] = {0xA6};
    if (!vcs_object_put_addressed(st->rig.clone, excessive_root, excessive, sizeof(excessive)))
        return false;
    if (vcs_tree_load_bounded(st->rig.clone, excessive_root, sizeof(excessive), 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    return true;
}

/* The exact root/byte-budget/entry-budget combination admits; a truncated
 * byte budget and a too-small entry budget both refuse; the unbounded
 * loader admits the same two entries. */
static bool dlx_source_binding_bounds_admits(struct dlx_source_binding_state *st)
{
    struct vcs_manifest admitted = {0};
    if (!vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len, 2, &admitted))
        return false;
    vcs_manifest_free(&admitted);
    if (vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len - 1, 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    if (vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len, 1, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    if (!vcs_tree_load(st->rig.clone, st->source, &admitted)) return false;
    if (admitted.count != 2) { vcs_manifest_free(&admitted); return false; }
    vcs_manifest_free(&admitted);
    return true;
}

static bool dlx_source_binding_bounds(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_bounds_refusals(st)) return false;
    if (!dlx_source_binding_bounds_admits(st)) return false;
    return true;
}

/* An exact match, then one committed edit at a time: a same-size content
 * change, an excluded extra, an unexpected extra, and a missing file — each
 * observed and reported by exactly the field it should set. */
/* The initial exact match: every field a complete match sets, and the
 * root/head the check reports back verbatim. */
static bool dlx_source_binding_drift_initial(struct dlx_source_binding_state *st)
{
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (!r.ok) return false;
    if (!check.observed) return false;
    if (!check.complete_content_matches) return false;
    if (check.matched != 2) return false;
    if (memcmp(check.source_root, st->source, 32) != 0) return false;
    if (strcmp(check.head, st->rig.tip) != 0) return false;
    return true;
}

/* A same-size content change is caught as `changed`, not silently accepted. */
static bool dlx_source_binding_drift_changed(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "change.txt", "two\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.changed != 1) return false;
    if (check.source_projection_matches) return false;
    if (check.complete_content_matches) return false;
    return true;
}

/* An excluded extra is classified as `excluded`: the projection still
 * matches (exclusions are outside its scope) but complete content does not. */
static bool dlx_source_binding_drift_excluded(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "change.txt", "one\n", st->rig.tip)) return false;
    if (!dlx_commit(st->rig.clone, "extra.log", "excluded\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.excluded != 1) return false;
    if (!check.source_projection_matches) return false;
    if (check.complete_content_matches) return false;
    return true;
}

/* An extra committed path the manifest never expected is `unexpected`,
 * distinct from the excluded one that is still committed alongside it. */
static bool dlx_source_binding_drift_unexpected(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "extra.txt", "unexpected\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.unexpected != 1) return false;
    if (check.excluded != 1) return false;
    return true;
}

/* A canonical file removed from the worktree is `missing`. */
static bool dlx_source_binding_drift_missing(struct dlx_source_binding_state *st)
{
    if (unlink(st->change_path) != 0) return false;
    if (!dlx_commit(st->rig.clone, "seed.txt", "seed\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.missing != 1) return false;
    return true;
}

static bool dlx_source_binding_drift(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_drift_initial(st)) return false;
    if (!dlx_source_binding_drift_changed(st)) return false;
    if (!dlx_source_binding_drift_excluded(st)) return false;
    if (!dlx_source_binding_drift_unexpected(st)) return false;
    if (!dlx_source_binding_drift_missing(st)) return false;
    return true;
}
#endif

static int test_dev_land_source_binding(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: canonical source root binds exact committed content, including same-size changes") {
        struct dlx_source_binding_state st = {0};
        ASSERT(dlx_source_binding_setup(&st));
        ASSERT(dlx_source_binding_bounds(&st));
        ASSERT(dlx_source_publication_binding(&st));
        ASSERT(dlx_source_publication_bundle_refusals(&st));
        ASSERT(dlx_source_binding_drift(&st));
        ASSERT(dlx_source_publication_drift(&st));
        PASS();
    } _test_next:;
#endif
    return failures;
}

static int test_dev_land_watcher_admission(void)
{
    int failures = 0;
#if defined(__linux__)
    TEST("land: scheduler refusal and successful exit never invent watcher readiness") {
        char root[512], scheduler[600], detail[256];
        test_make_tmpdir(root, sizeof(root), "dev_land", "watcher_admission");
        (void)snprintf(scheduler, sizeof(scheduler), "%s/scheduler", root);
        ASSERT(dlx_write(scheduler,
            "#!/bin/sh\n"
            "test \"$1\" = --wait || exit 64\n"
            "test \"$2\" = --project || exit 64\n"
            "test \"$3\" = z23 || exit 64\n"
            "test \"$5\" = dev || exit 64\n"
            "test \"$6\" = loop || exit 64\n"
            "test \"$7\" = ensure || exit 64\n"
            "printf '%s' \"$8\" > \"$0.input\"\n"
            "exit 75\n"));
        ASSERT(chmod(scheduler, 0700) == 0);
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        ASSERT(strstr(detail, "exit=75") != NULL);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        char input_path[640], input_text[1200] = {0};
        size_t input_len = 0;
        (void)snprintf(input_path, sizeof(input_path), "%s.input", scheduler);
        ASSERT(dlx_slurp(input_path, input_text, sizeof(input_text) - 1,
                         &input_len));
        ASSERT(input_len > 8 && memcmp(input_text, "--input=", 8) == 0);
        struct json_value routed;
        json_init(&routed);
        ASSERT(json_read(&routed, input_text + 8, input_len - 8));
        const char *routed_root = json_get_str(json_get(&routed, "root"));
        const char *routed_mode = json_get_str(json_get(&routed, "mode"));
        bool routed_ok = routed.num_children == 2 && routed_root && routed_mode &&
            strcmp(routed_root, root) == 0 && strcmp(routed_mode, "verify") == 0;
        json_free(&routed);
        ASSERT(routed_ok);
        ASSERT(dlx_write(scheduler, "#!/bin/sh\nexit 0\n"));
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        ASSERT(strstr(detail, "exit=0") != NULL);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        ASSERT(dlx_write(scheduler,
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$0.pid\"\nexec sleep 30\n"));
        int64_t started = platform_time_monotonic_ms();
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        int64_t elapsed = platform_time_monotonic_ms() - started;
        ASSERT(elapsed >= 9000 && elapsed < 20000);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        char pid_path[640], pid_text[32] = {0};
        size_t pid_len = 0;
        (void)snprintf(pid_path, sizeof(pid_path), "%s.pid", scheduler);
        ASSERT(dlx_slurp(pid_path, pid_text, sizeof(pid_text) - 1, &pid_len));
        char *end = NULL;
        long child = strtol(pid_text, &end, 10);
        ASSERT(pid_len > 0 && child > 1 && end && (*end == '\n' || *end == '\0'));
        errno = 0;
        ASSERT(kill((pid_t)child, 0) == -1 && errno == ESRCH);
        printf("watcher admission: timeout_ms=%lld child_reaped=yes\n",
               (long long)elapsed);
        PASS();
    } _test_next:;
#endif
    return failures;
}

static int test_dev_land_long_proof_root(void)
{
    int failures = 0;
    TEST("land: a long proof root remains a structured, worker-stealable action") {
        struct dlx_rig rig;
        struct dlx_call c;
        char parent[sizeof(g_dlx_state)], extended[sizeof(g_dlx_state)];
        char leaf[201];
        dlx_isolate("long_proof_root");
        (void)snprintf(parent, sizeof(parent), "%s", g_dlx_state);
        memset(leaf, 'p', sizeof(leaf) - 1);
        leaf[sizeof(leaf) - 1] = '\0';
        ASSERT(mkdir(parent, 0700) == 0);
        ASSERT(snprintf(extended, sizeof(extended), "%s/%s", parent, leaf) <
               (int)sizeof(extended));
        ASSERT(mkdir(extended, 0700) == 0);
        (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s", extended);
        ASSERT(setenv("XDG_STATE_HOME", g_dlx_state, 1) == 0);
        ASSERT(dlx_rig_make(&rig, "long_proof_root_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strstr(dlx_str(&c, "detail"), rig.tip) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "exceeds row detail") == NULL);
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        const struct json_value *action = json_get(flight, "proof_step");
        ASSERT(action != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(action, "command")), "dev.proof.step");
        ASSERT_STR_EQ(json_get_str(json_get(action, "local_commit")), rig.tip);
        ASSERT(strstr(json_get_str(json_get(action, "root")), leaf) != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(action, "remote_base")),
                      json_get_str(json_get(flight, "base")));
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* Codec cases deliberately exercise the production parser and encoder before
 * a submit interface can produce dependency authority. */
#define DLX_CHAIN_M "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DLX_CHAIN_A "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DLX_CHAIN_B "cccccccccccccccccccccccccccccccccccccccc"
#define DLX_CHAIN_ROW "\"seq\":3,\"tip\":\"" DLX_CHAIN_B "\",\"state\":\"queued\",\"attempt\":1"
#define DLX_CHAIN_FIELDS "\"predecessor_seq\":2,\"predecessor_local\":\"" DLX_CHAIN_A "\",\"predecessor_base\":\"" DLX_CHAIN_M "\",\"predecessor_tree\":\"" DLX_CHAIN_A "\",\"predecessor_intent\":\"" DLX_CHAIN_A "@" DLX_CHAIN_M "\""

static int test_dev_land_chain_codec(void)
{
    int failures = 0;
    TEST("land: dependency tuple round trips and malformed authority refuses") {
        char out[32768], again[32768];
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW "}", out, sizeof(out)));
        ASSERT(strstr(out, "predecessor_") == NULL);
        dlx_isolate("chain_codec_refusal");
        struct dlx_call call; dlx_begin(&call, "step"); ASSERT(dlx_run(&call) && dlx_ok(&call)); dlx_end(&call);
        char land[1024], queue[1200], history[1200], bytes[2048]; size_t len = 0;
        dlx_landdir(land, sizeof(land));
        (void)snprintf(queue, sizeof(queue), "%s/queue.jsonl", land);
        (void)snprintf(history, sizeof(history), "%s/outcomes.jsonl", land);
        static const char partial[] = "{" DLX_CHAIN_ROW ",\"predecessor_seq\":2}\n";
        static const char terminal[] = "{\"seq\":1,\"tip\":\"" DLX_CHAIN_M "\",\"state\":\"cancelled\",\"attempt\":1}\n";
        ASSERT(dlx_write(queue, partial)); ASSERT(dlx_write(history, terminal));
        static const char *actions[] = { "status", "step" };
        for (size_t i = 0; i < 2; ++i) {
            dlx_begin(&call, actions[i]);
            ASSERT(dlx_run(&call)); ASSERT_STR_EQ(dlx_err_code(&call), "QUEUE_READ_FAILED");
            ASSERT_STR_EQ(dlx_err_evidence(&call), "malformed_queue_record_1"); dlx_end(&call);
            ASSERT(dlx_slurp(queue, bytes, sizeof(bytes) - 1, &len)); bytes[len] = '\0'; ASSERT_STR_EQ(bytes, partial);
            ASSERT(dlx_slurp(history, bytes, sizeof(bytes) - 1, &len)); bytes[len] = '\0'; ASSERT_STR_EQ(bytes, terminal);
        }
        dlx_restore();
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW "," DLX_CHAIN_FIELDS "}", out, sizeof(out)));
        ASSERT(strstr(out, "\"predecessor_seq\":2") != NULL);
        ASSERT(strstr(out, DLX_CHAIN_A "@" DLX_CHAIN_M) != NULL);
        ASSERT(zcl_native_dev_land_test_chain_codec(out, again, sizeof(again)));
        ASSERT_STR_EQ(out, again);
        static const char *fields[] = { "predecessor_local", "predecessor_base", "predecessor_tree", "predecessor_intent", "predecessor_seq" };
        static const long long bad_sequences[] = { -1, 0, 3, 4 };
        for (size_t i = 0; i < 5; ++i) {
            for (int kind = 0; kind < 4; ++kind) {
                struct json_value doc; json_init(&doc);
                ASSERT(json_read(&doc, again, strlen(again)));
                struct json_value *v = NULL;
                for (size_t j = 0; j < doc.num_children; ++j)
                    if (strcmp(doc.keys[j], fields[i]) == 0) v = &doc.children[j];
                ASSERT(v != NULL);
                char oversized[256]; memset(oversized, 'a', sizeof(oversized) - 1); oversized[255] = '\0';
                if (i == 4) json_set_int(v, bad_sequences[kind]);
                else if (kind == 0) json_set_null(v);
                else if (kind == 1) json_set_int(v, 1);
                else json_set_str(v, kind == 2 ? "bad" : oversized);
                char line[2048]; size_t n = json_write(&doc, line, sizeof(line)); json_free(&doc);
                ASSERT(n > 0 && n < sizeof(line));
                ASSERT(!zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
            }
        }
        static const char *bad[] = {
            "\"predecessor_seq\":2", "\"predecessor_local\":\"" DLX_CHAIN_A "\"",
            DLX_CHAIN_FIELDS ",\"predecessor_seq\":2",
            DLX_CHAIN_FIELDS ",\"predecessor_local\":null",
            DLX_CHAIN_FIELDS ",\"predecessor_base\":0",
            DLX_CHAIN_FIELDS ",\"predecessor_tree\":\"bad\"",
            DLX_CHAIN_FIELDS ",\"predecessor_intent\":\"bad\"",
            "\"predecessor_seq\":-1", "\"predecessor_seq\":9223372036854775808",
            "\"predecessor_seq\":null", "\"predecessor_seq\":\"2\"",
            "\"predecessor_seq\":0,\"predecessor_local\":\"" DLX_CHAIN_A "\""
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            char line[2048];
            ASSERT(snprintf(line, sizeof(line), "{%s,%s}", DLX_CHAIN_ROW, bad[i]) < (int)sizeof(line));
            ASSERT(!zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
        }
        /* The current row boundary refuses containers before tuple parsing. */
        ASSERT(!zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW ",\"nested\":{" DLX_CHAIN_FIELDS "}}", out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_chain_row(char *out, size_t cap, long long seq,
    const char *repo, const char *local, const char *base, const char *state,
    long long predecessor, const char *pred_base, const char *pred_tree)
{
    char tree[64], dependency[512] = "";
    const char *args[] = { "--no-replace-objects", "show", "-s", "--format=%T", local, NULL };
    if (dlx_git_out(repo, args, tree, sizeof(tree)) != 0) return false;
    if (predecessor && snprintf(dependency, sizeof(dependency),
        ",\"predecessor_seq\":%lld,\"predecessor_local\":\"%s\",\"predecessor_base\":\"%s\","
        "\"predecessor_tree\":\"%s\",\"predecessor_intent\":\"%s@%s\"",
        predecessor, base, pred_base, pred_tree, base, pred_base) >= (int)sizeof(dependency)) return false;
    return snprintf(out, cap,
        "{\"seq\":%lld,\"tip\":\"%s\",\"state\":\"%s\",\"phase\":\"prove\",\"attempt\":1,"
        "\"worktree\":\"%s\",\"base\":\"%s\",\"local\":\"%s\",\"tree\":\"%s\",\"proof_intent\":\"%s@%s\"%s}",
        seq, local, state, repo, base, local, tree, local, base, dependency) < (int)cap;
}

static int test_dev_land_chain_relation(void)
{
    int failures = 0;
    TEST("land: only exact live dependency anchors wait; invalid identity never becomes current") {
        struct dlx_rig rig;
        char m[64], a[64], b[64], c[64], ta[64], tb[64];
        char ar[2048], br[2048], cr[2048], changed[2048];
        long long waiting = 0;
        dlx_isolate("chain_relation");
        ASSERT(dlx_rig_make(&rig, "chain_relation_rig"));
        ASSERT(dlx_origin_main(&rig, m));
        ASSERT(dlx_sign_arm(rig.clone, "chain_relation_sign"));
        const char *sign[] = { "commit", "--amend", "--no-edit", "--no-verify", "-S", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *tree[] = { "rev-parse", "HEAD^{tree}", NULL };
        ASSERT(dlx_git(rig.clone, sign) == 0);
        ASSERT(dlx_git_out(rig.clone, head, a, sizeof(a)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree, ta, sizeof(ta)) == 0);
        ASSERT(dlx_commit(rig.clone, "b.txt", "b\n", b));
        ASSERT(dlx_git(rig.clone, sign) == 0);
        ASSERT(dlx_git_out(rig.clone, head, b, sizeof(b)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree, tb, sizeof(tb)) == 0);
        ASSERT(dlx_commit(rig.clone, "c.txt", "c\n", c));
        ASSERT(dlx_chain_row(ar, sizeof(ar), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
        ASSERT(dlx_chain_row(br, sizeof(br), 2, rig.clone, b, a, "queued", 1, m, ta));
        ASSERT(dlx_chain_row(cr, sizeof(cr), 3, rig.clone, c, b, "queued", 2, a, tb));
        const char *rows[] = { ar, br };
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, m, &waiting) == 1);
        ASSERT(waiting == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, a, &waiting) == 0);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, c, &waiting) == 2);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, DLX_CHAIN_M, &waiting) == 2);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, m, &waiting) == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, a, &waiting) == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, b, &waiting) == 0);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, "", &waiting) == 3);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 0, a, &waiting) == 4);
        const char *duplicates[] = { ar, ar };
        ASSERT(zcl_native_dev_land_test_chain_relation(br, duplicates, 2, a, &waiting) == 4);
        static const char *states[] = { "failed", "cancelled", "fenced", "conflict", "landed" };
        for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
            ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, states[i], 0, NULL, NULL));
            const char *invalid[] = { changed };
            ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        }
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
        const char *invalid[] = { changed };
        static const char *pins[] = { "local", "base", "tree", "proof_intent" };
        for (size_t i = 0; i < 4; ++i) {
            ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
            char needle[64]; (void)snprintf(needle, sizeof(needle), "\"%s\":\"", pins[i]);
            char *pin = strstr(changed, needle); ASSERT(pin != NULL); pin += strlen(needle);
            *pin = *pin == '0' ? '1' : '0';
            ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        }
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "queued", 0, NULL, NULL));
        ASSERT(snprintf(changed, sizeof(changed), "{\"seq\":1,\"tip\":\"%s\",\"state\":\"queued\",\"attempt\":1}", a) < (int)sizeof(changed));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, rig.tip, m, "inflight", 0, NULL, NULL));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        char land[1024], history[1200]; dlx_landdir(land, sizeof(land));
        (void)snprintf(history, sizeof(history), "%s/outcomes.jsonl", land);
        static const char hidden_failed[] =
            "{\"seq\":99,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\0\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n";
        static const char hidden_duplicate[] =
            "{\"seq\":99,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\0\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\n";
        static const struct { const char *bytes; size_t length; } binary[] = {
            { hidden_failed, sizeof(hidden_failed) - 1 },
            { hidden_duplicate, sizeof(hidden_duplicate) - 1 }
        };
        int binary_relations[2];
        for (size_t i = 0; i < sizeof(binary) / sizeof(binary[0]); ++i) {
            FILE *file = fopen(history, "wb"); ASSERT(file != NULL);
            size_t written = fwrite(binary[i].bytes, 1, binary[i].length, file);
            int closed = fclose(file);
            ASSERT(written == binary[i].length && closed == 0);
            binary_relations[i] = zcl_native_dev_land_test_chain_relation(
                br, rows, 1, a, &waiting);
        }
        ASSERT(binary_relations[0] == 4);
        ASSERT(binary_relations[1] == 4);
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "landed", 0, NULL, NULL));
        size_t n = strlen(changed); ASSERT(n + 2 < sizeof(changed)); changed[n] = '\n'; changed[n + 1] = '\0';
        ASSERT(dlx_write(history, changed));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, a, &waiting) == 4);
        dlx_restore(); PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static int test_dev_land_malformed_queue_refusal(void)
{
    int failures = 0;
    TEST("land: a legacy row blocks status, submit and step without losing bytes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], qpath[1200], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("malformed_queue");
        ASSERT(dlx_rig_make(&rig, "malformed_queue_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        FILE *file = fopen(qpath, "ab");
        ASSERT(file != NULL);
        static const char legacy[] =
            "{\"seq\":2,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"queued\"}\n";
        ASSERT(fwrite(legacy, 1, sizeof(legacy) - 1, file) == sizeof(legacy) - 1);
        ASSERT(fclose(file) == 0);
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len);
        ASSERT(memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static int test_dev_land_malformed_priority_refusal(void)
{
    int failures = 0;
    TEST("land: malformed persisted priority refuses without losing the row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], qpath[1200], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("malformed_priority");
        ASSERT(dlx_rig_make(&rig, "malformed_priority_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_slurp(qpath, before, sizeof(before) - 1, &before_len));
        before[before_len] = '\0';
        char *priority = strstr(before, "\"priority_seq\":");
        ASSERT(priority != NULL);
        priority += strlen("\"priority_seq\":");
        ASSERT(*priority == '1');
        ASSERT(before_len + 2 < sizeof(before));
        memmove(priority + 3, priority + 1, strlen(priority + 1) + 1);
        priority[0] = '"';
        priority[1] = 'x';
        priority[2] = '"';
        before_len += 2;
        ASSERT(dlx_write(qpath, before));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
        dlx_end(&c);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len);
        ASSERT(memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_outcome_nul_refusal(void)
{
    int failures = 0;
    TEST("land: hidden terminal history refuses sequence assignment") {
        static const char history[] =
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n"
            "\0"
            "{\"seq\":2,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n";
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], opath[1200], qpath[1200], after[1024], queue[8192];
        size_t after_len = 0, queue_len = 0;
        dlx_isolate("outcome_nul");
        ASSERT(dlx_rig_make(&rig, "outcome_nul_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_write(qpath, ""));
        FILE *f = fopen(opath, "wb");
        ASSERT(f != NULL);
        bool wrote = fwrite(history, 1, sizeof(history) - 1, f) ==
                     sizeof(history) - 1;
        ASSERT(fclose(f) == 0 && wrote);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c),
                      "outcomes.jsonl unreadable, malformed, or exhausted");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, sizeof(history) - 1);
        ASSERT(memcmp(after, history, after_len) == 0);
        ASSERT(dlx_queue_bytes(queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        f = fopen(opath, "wb");
        ASSERT(f != NULL);
        const char *second = history + strlen(history) + 1;
        wrote = fwrite(history, 1, strlen(history), f) == strlen(history) &&
                fwrite(second, 1, strlen(second), f) == strlen(second);
        ASSERT(fclose(f) == 0 && wrote);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 3);
        dlx_end(&c);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_malformed_outcome_refusal(void)
{
    int failures = 0;
    TEST("land: a malformed terminal outcome is named, never hidden") {
        struct dlx_call c;
        char landdir[1024], opath[1200];
        dlx_isolate("malformed_outcome");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(dlx_write(opath,
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"landed\"}\n"));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_outcome_record_1");
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    failures += dlx_outcome_nul_refusal();
    return failures;
}

static int test_dev_land_missing_worker(void)
{
    int failures = 0;
    TEST("land: a dead proof worker leaves a resumable exact intent") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], logpath[1400], log[8192];
        size_t len = 0;
        dlx_isolate("proof_worker_dead");
        ASSERT(dlx_rig_make(&rig, "proof_worker_dead_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data,
                                                   "in_flight");
        ASSERT(flight != NULL);
        ASSERT(strlen(json_get_str(json_get(flight, "tree"))) == 40);
        ASSERT(strchr(json_get_str(json_get(flight, "proof_intent")), '@') !=
               NULL);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "missing", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "proving");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log",
                       landdir);
        ASSERT(dlx_slurp(logpath, log, sizeof(log) - 1, &len));
        log[len] = '\0';
        ASSERT(strstr(log, "proof worker missing; requeueing") != NULL);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

static bool dlx_pick_barrier_open(int ready[2], int release[2])
{
    if (pipe(ready) != 0 || pipe(release) != 0) return false;
    int fds[] = {ready[0], ready[1], release[0], release[1]};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
        if (fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) return false;
    return true;
}

static void dlx_pick_barrier_close(int ready[2], int release[2], pid_t child)
{
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; i++) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) (void)waitpid(child, NULL, 0);
}

static int dlx_competing_blocked(const struct dlx_rig *rig,
                                 const struct dlx_adopt_fix *count,
                                 const char *loser, const char *expected)
{
    int failures = 0;
    struct dlx_call c;
    char base[64], observed[64], before_wire[8192], after_wire[8192];
    size_t before_len, after_len;
    ASSERT(dlx_origin_main(rig, base));
    ASSERT(dlx_queue_bytes(before_wire, sizeof(before_wire), &before_len));
    struct json_value partial;
    json_init(&partial);
    ASSERT(json_read(&partial, before_wire, before_len));
    ASSERT_STR_EQ(json_get_str(json_get(&partial, "state")), expected);
    json_free(&partial);
    dlx_begin(&c, loser);
    ASSERT(dlx_run(&c) && !dlx_ok(&c));
    ASSERT_STR_EQ(dlx_err_code(&c), "STEP_BUSY");
    dlx_end(&c);
    ASSERT(dlx_queue_bytes(after_wire, sizeof(after_wire), &after_len));
    ASSERT_EQ(before_len, after_len);
    ASSERT(memcmp(before_wire, after_wire, before_len) == 0);
    ASSERT(dlx_origin_main(rig, observed));
    ASSERT_STR_EQ(observed, base);
    ASSERT(access(count->marker, F_OK) != 0 && errno == ENOENT);
    dlx_begin(&c, "status");
    ASSERT(dlx_run(&c) && dlx_ok(&c));
    const struct json_value *pending = dlx_arr(&c, "outcomes");
    ASSERT(pending && pending->num_children == 0);
    dlx_end(&c);
_test_next:;
    return failures;
}

static void dlx_competing_child(const char *winner, bool prepared,
                                int ready[2], int release[2])
{
    (void)alarm(60);
    (void)close(ready[0]);
    (void)close(release[1]);
    struct dlx_call other;
    dlx_begin(&other, winner);
    const char *expected = prepared || strcmp(winner, "drive") == 0
                           ? "landed" : "started";
    bool landed = dlx_run(&other) && dlx_ok(&other) &&
                  strcmp(dlx_str(&other, "state"), expected) == 0;
    dlx_end(&other);
    _exit(landed ? 0 : 1);
}

static int dlx_competing_beats(const struct dlx_rig *rig,
                              const struct dlx_adopt_fix *count,
                              const char *winner, const char *loser,
                              bool prepared, int ready, int release)
{
    int failures = 0;
    int beats = !prepared && strcmp(winner, "drive") == 0 ? 2 : 1;
    for (int beat = 0; beat < beats; beat++) {
        char marker = 0;
        ASSERT(read(ready, &marker, 1) == 1 && marker == 'R');
        ASSERT(dlx_competing_blocked(rig, count, loser,
                   !prepared && beat == 0 ? "queued" : "inflight") == 0);
        ASSERT(write(release, "G", 1) == 1);
    }
_test_next:;
    return failures;
}

static int test_dev_land_competing_publish(const char *winner, const char *loser,
                                           bool prepared)
{
    int failures = 0;
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    char label[160];
    (void)snprintf(label, sizeof(label),
                   "land: %s versus %s %s row is singleflight", winner, loser,
                   prepared ? "in-flight" : "queued");
    TEST(label) {
        struct dlx_rig rig;
        struct dlx_call c;
        int status = 0;
        dlx_isolate("passed_competitors");
        ASSERT(dlx_rig_make(&rig, "passed_competitors_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        if (prepared) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            dlx_end(&c);
        }
        struct dlx_adopt_fix count = {.rig = rig};
        ASSERT(dlx_arm_receive_count(&count));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_pick_barrier_open(ready, release));
        zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0)
            dlx_competing_child(winner, prepared, ready, release);
        ASSERT(close(ready[1]) == 0);
        ready[1] = -1;
        ASSERT(close(release[0]) == 0);
        release[0] = -1;
        ASSERT(dlx_competing_beats(&rig, &count, winner, loser, prepared,
                                   ready[0], release[1]) == 0);
        ASSERT(close(release[1]) == 0);
        release[1] = -1;
        ASSERT(waitpid(child, &status, 0) == child);
        child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        zcl_native_dev_land_test_pick_barrier(-1, -1);
        if (!prepared && strcmp(winner, "step") == 0) {
            dlx_begin(&c, "drive");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
            dlx_end(&c);
        }
        ASSERT(dlx_receive_once(&count));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "state")),
                      "landed");
        dlx_end(&c);
        PASS();
    }

_test_next:;
    dlx_pick_barrier_close(ready, release, child);
    dlx_restore();
    return failures;
}

static int test_dev_land_bounded_drive(void)
{
    int failures = 0;
    TEST("land: one bounded drive publishes a passing exact pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char main_tip[64];
        dlx_isolate("bounded_drive");
        ASSERT(dlx_rig_make(&rig, "bounded_drive_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        char pushed[64];
        (void)snprintf(pushed, sizeof(pushed), "%s",
                       dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_tip));
        ASSERT_STR_EQ(main_tip, pushed);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_pending_proof_move(void)
{
    int failures = 0;
    TEST("land: moving main requeues a still-running proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char stranger[64], main_now[64];
        dlx_isolate("move_pending");
        ASSERT(dlx_rig_make(&rig, "move_pending_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_git(rig.clone, back) == 0);
        ASSERT(dlx_git(rig.clone, fetch) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, stranger);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_main_moves_converge(void)
{
    int failures = test_dev_land_pending_proof_move();
    TEST("land: three proof-time main advances yield then converge") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64], original_ts[64], landed[64];
        char following[64];
        int i;
        dlx_isolate("moveforever");
        ASSERT(dlx_rig_make(&rig, "moveforever_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "following.txt", "following\n",
                          following));
        dlx_submit(&c, &rig, following);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *queued = dlx_arr(&c, "queued");
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(queued && queued->num_children == 1);
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_EQ(json_get_int(json_get(&outcomes->children[0], "seq")), 2);
        (void)snprintf(original_ts, sizeof(original_ts), "%s",
                       json_get_str(json_get(&queued->children[0], "ts")));
        dlx_end(&c);
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        for (i = 0; i < 3; i++) {
            char tag[32];
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
            dlx_end(&c);
            (void)snprintf(tag, sizeof(tag), "s%d.txt", i);
            ASSERT(dlx_git(side, branch) == 0);
            ASSERT(dlx_commit(side, tag, "elsewhere\n", stranger));
            ASSERT(dlx_git(side, push) == 0);
            ASSERT(dlx_git(side, back) == 0);
            ASSERT(dlx_git(side, fetch) == 0);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "state"),
                          i == 2 ? "queued" : "rebased");
            ASSERT_EQ(dlx_int(&c, "attempt"), i == 2 ? 1 : i + 2);
            if (i == 2) {
                ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
                ASSERT_EQ(dlx_int(&c, "seq"), 3);
            }
            dlx_end(&c);
            dlx_begin(&c, "status");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            queued = dlx_arr(&c, "queued");
            ASSERT(queued && queued->num_children == 1);
            ASSERT_STR_EQ(json_get_str(json_get(&queued->children[0], "ts")),
                          original_ts);
            dlx_end(&c);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        (void)snprintf(landed, sizeof(landed), "%s",
                       dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, stranger));
        ASSERT_STR_EQ(stranger, landed);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

static bool dlx_priority_snapshot(struct dlx_call *c, char ts[64])
{
    dlx_begin(c, "status");
    bool ok = dlx_run(c) && dlx_ok(c);
    if (ok) {
        const struct json_value *queued = dlx_arr(c, "queued");
        ok = queued && queued->num_children == 2;
        if (ok) {
            const char *value =
                json_get_str(json_get(&queued->children[0], "ts"));
            ok = value && snprintf(ts, 64, "%s", value) > 0;
        }
    }
    dlx_end(c);
    return ok;
}

static bool dlx_priority_successor_status(struct dlx_call *c,
                                           const char *original_ts)
{
    dlx_begin(c, "status");
    bool ok = dlx_run(c) && dlx_ok(c);
    if (ok) {
        const struct json_value *queued = dlx_arr(c, "queued");
        const struct json_value *steer = json_get(&c->reply.data, "steer");
        const char *ts = queued && queued->num_children == 2
            ? json_get_str(json_get(&queued->children[1], "ts")) : NULL;
        ok = queued && queued->num_children == 2 && steer &&
             json_get_int(json_get(&queued->children[0], "seq")) == 2 &&
             json_get_int(json_get(&queued->children[1], "seq")) == 3 &&
             json_get_int(json_get(&queued->children[0], "priority_seq")) == 2 &&
             json_get_int(json_get(&queued->children[1], "priority_seq")) == 1 &&
             ts && strcmp(ts, original_ts) == 0 &&
             json_get_int(json_get(steer, "seq")) == 3;
    }
    dlx_end(c);
    return ok;
}

static int test_dev_land_signed_intent(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed Git intent gates push and yields a remote receipt") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("signed_intent");
        ASSERT(dlx_rig_make(&rig, "signed_intent_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0],
                                          "acceptance_state")), "unknown");
        ASSERT(strlen(json_get_str(json_get(&outcomes->children[0],
                                          "remote_source"))) == 40);
        ASSERT(strlen(json_get_str(json_get(&outcomes->children[0],
                                          "remote_signature"))) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
/* Persist a signed remote observation, then lose only the terminal append.
 * The original pair remains inflight with its receipt for another driver. */
static bool dlx_receipt_prepare(struct dlx_rig *rig)
{
    struct dlx_call c;
    bool ok;
    if (!dlx_rig_make(rig, "receipt_pending_rig"))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static bool dlx_receipt_publisher_death(struct dlx_rig *rig)
{
    char hook[1400];
    int child_status = 0;
    (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig->bare);
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        char kill_script[256];
        (void)setsid();
        (void)alarm(30);
        (void)snprintf(kill_script, sizeof(kill_script),
                      "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
        if (!dlx_write(hook, kill_script) || chmod(hook, 0700) != 0)
            _exit(2);
        struct dlx_call child_call;
        dlx_begin(&child_call, "step");
        (void)dlx_run(&child_call);
        _exit(90);
    }
    bool ok = dlx_wait_publisher(child, &child_status) == child &&
         WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL;
    if (unlink(hook) != 0) ok = false;
    char remote[64];
    return ok && dlx_origin_main(rig, remote) && strcmp(remote, rig->tip) == 0;
}

static bool dlx_signed_receipt_pending(struct dlx_rig *rig, char *queue,
                                      size_t queue_cap, char *marker,
                                      size_t marker_cap, bool persist_receipt)
{
    struct dlx_call c;
    char land[1200], wt[1400], wrapper[1400], script[3000];
    bool ok;
    if (!dlx_receipt_prepare(rig)) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, sizeof(wt), "%s/wt", land);
    (void)snprintf(queue, queue_cap, "%s/queue.jsonl", land);
    (void)snprintf(marker, marker_cap, "%s/receive-count", land);
    (void)snprintf(wrapper, sizeof(wrapper), "%s/count-receive", land);
    (void)snprintf(script, sizeof(script),
        "#!/bin/sh\nprintf 'invoked\\n' >> '%s' || exit 73\n"
        "exec git-receive-pack \"$@\"\n", marker);
    if (!dlx_write(wrapper, script) || chmod(wrapper, 0700) != 0)
        return false;
    const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
    if (dlx_git(wt, intercept) != 0) return false;
    if (!persist_receipt) return dlx_receipt_publisher_death(rig);
    setenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND", "1", 1);
    setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
        strcmp(dlx_str(&c, "persist"), "failed") == 0;
    dlx_end(&c);
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    return ok;
}

static bool dlx_receipt_step(const char *error, const char *signer)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c);
    if (error)
        ok = ok && !dlx_ok(&c) && dlx_err_code(&c) &&
             strcmp(dlx_err_code(&c), error) == 0;
    else
        ok = ok && dlx_ok(&c) && strcmp(dlx_str(&c, "state"), "landed") == 0 &&
             (!signer || strcmp(dlx_str(&c, "remote_signer"), signer) == 0);
    dlx_end(&c);
    return ok;
}

static bool dlx_receipt_tamper_one(struct dlx_rig *rig, const char *queue,
                                  const char *original, size_t len,
                                  const char *field)
{
    char key[80], altered[8192], observed[8192], remote[64];
    size_t got;
    memcpy(altered, original, len + 1);
    (void)snprintf(key, sizeof(key), "\"%s\":\"", field);
    char *value = strstr(altered, key);
    if (!value) return false;
    value += strlen(key);
    if (!((*value >= '0' && *value <= '9') || (*value >= 'a' && *value <= 'f')))
        return false;
    *value = *value == '0' ? '1' : '0';
    return dlx_write(queue, altered) && dlx_receipt_step("REMOTE_RECEIPT_INVALID", NULL) &&
        dlx_slurp(queue, observed, sizeof(observed), &got) && got == len &&
        memcmp(altered, observed, len) == 0 &&
        dlx_origin_main(rig, remote) && strcmp(remote, rig->tip) == 0;
}

static bool dlx_receipt_tamper_cases(void)
{
    struct dlx_rig rig;
    char queue[1400], marker[1400], original[8192], count[32];
    size_t len, got;
    bool ok = false;
    dlx_isolate("receipt_tamper");
    if (!dlx_signed_receipt_pending(&rig, queue, sizeof(queue), marker, sizeof(marker), true) ||
        !dlx_slurp(queue, original, sizeof(original) - 1, &len))
        goto done;
    original[len] = 0;
    const char *fields[] = { "remote_signature", "remote_signer", "remote_source" };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!dlx_receipt_tamper_one(&rig, queue, original, len, fields[i]))
            goto done;
    }
    if (!dlx_write(queue, original) || !dlx_receipt_step(NULL, NULL))
        goto done;
    ok = dlx_slurp(marker, count, sizeof(count), &got) && got == 8 &&
         memcmp(count, "invoked\n", 8) == 0;
done:
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    dlx_restore();
    return ok;
}

static bool dlx_takeover_original_signer(const char *a_hex)
{
    char land[1200], path[1400], wire[8192];
    size_t len;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    struct json_value doc = {0};
    bool ok = dlx_slurp(path, wire, sizeof(wire), &len) &&
        json_read(&doc, wire, len) && doc.type == JSON_OBJ;
    const char *signer = json_get_str(json_get(&doc, "publication_signer"));
    ok = ok && signer && strcmp(signer, a_hex) == 0;
    json_free(&doc);
    return ok;
}

static bool dlx_takeover_landed(const char *a_hex, const char *b_hex)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
        strcmp(dlx_str(&c, "state"), "landed") == 0 &&
        strcmp(dlx_str(&c, "remote_signer"), b_hex) == 0;
    dlx_end(&c);
    return ok && dlx_takeover_original_signer(a_hex);
}

static bool dlx_takeover_trust(struct dlx_rig *rig, const char *queue,
                               const char *wire, size_t len,
                               const char *allow, const uint8_t a[32],
                               const uint8_t b[32])
{
    char observed[8192], remote[64], a_hex[65], b_hex[65], allow_text[80];
    size_t got;
    if (!dlx_receipt_step("PUBLICATION_INTENT_INVALID", NULL) ||
        !dlx_slurp(queue, observed, sizeof(observed), &got) || got != len ||
        memcmp(wire, observed, len) != 0 || !dlx_origin_main(rig, remote) ||
        strcmp(remote, rig->tip) != 0)
        return false;
    zcl_hex_encode(a, 32, a_hex);
    zcl_hex_encode(b, 32, b_hex);
    (void)snprintf(allow_text, sizeof(allow_text), "%s\n", a_hex);
    return dlx_write(allow, allow_text) && chmod(allow, 0600) == 0 &&
        dlx_takeover_landed(a_hex, b_hex);
}

static bool dlx_takeover_identity(uint8_t a[32], char *key, size_t key_cap,
                                  char *allow, size_t allow_cap)
{
    bool present = false;
    const char *why = NULL;
    return zcl_dev_proof_signer_public(a, &present, &why) && present &&
        zcl_dev_proof_signer_paths(key, key_cap, allow, allow_cap);
}

static bool dlx_receipt_receive_once(const char *marker)
{
    char count[32];
    size_t got;
    return dlx_slurp(marker, count, sizeof(count), &got) && got == 8 &&
        memcmp(count, "invoked\n", 8) == 0;
}

static bool dlx_receipt_different_signer(void)
{
    struct dlx_rig rig;
    char queue[1400], marker[1400], key[4096], allow[4096], backup[4160];
    char wire[8192];
    uint8_t a[32], b[32], signature[64];
    bool saved = false, ok = false;
    const char *why = NULL;
    size_t got, len;
    dlx_isolate("receipt_different_signer");
    if (!dlx_signed_receipt_pending(&rig, queue, sizeof(queue), marker, sizeof(marker), false) ||
        !dlx_slurp(queue, wire, sizeof(wire) - 1, &got))
        goto done;
    wire[got] = 0;
    len = got;
    if (!strstr(wire, "\"remote_signature\":\"\"") ||
        !dlx_takeover_identity(a, key, sizeof(key), allow, sizeof(allow)))
        goto done;
    if (snprintf(backup, sizeof(backup), "%s.fixture-saved", key) >= (int)sizeof(backup) ||
        rename(key, backup) != 0)
        goto done;
    saved = true;
    if (!zcl_dev_proof_signer_sign((const uint8_t *)"takeover", 8, b, signature, &why) ||
        memcmp(a, b, sizeof(a)) == 0 ||
        !dlx_takeover_trust(&rig, queue, wire, len, allow, a, b))
        goto done;
    /* B independently observes the remote and signs a new receipt while
     * trusting A's preserved publication intent; the push occurs once. */
    ok = dlx_receipt_receive_once(marker);
done:
    if (saved) {
        if (unlink(key) != 0 && errno != ENOENT)
            ok = false;
        if (rename(backup, key) != 0)
            ok = false;
    }
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    dlx_restore();
    return ok;
}
#endif

/* These cases enter dl_escape through its production caller dl_encode_row.
 * No queue, clock, filesystem fixture or publication authority is involved. */
static int dlx_row_utf8_refuses(const char *name, const char *text, bool detail)
{
    int failures = 0;
    TEST(name) {
        char out[8192], unchanged[8192];
        size_t len = 123;
        memset(out, 'X', sizeof(out));
        memcpy(unchanged, out, sizeof(out));
        ASSERT(!zcl_native_dev_land_test_encode_text(text, detail, out,
                                                     sizeof(out), &len));
        ASSERT_EQ(len, 123);
        ASSERT(memcmp(out, unchanged, sizeof(out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_row_text_roundtrips(const char *out, size_t len,
                                    const char *text, bool detail)
{
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, out, len);
    const char *decoded = json_get_str(json_get(&doc, detail ? "detail" : "note"));
    ok = ok && decoded && strcmp(decoded, text) == 0;
    json_free(&doc);
    return ok;
}

static bool dlx_row_empty_capacity(bool detail)
{
    char out[8192];
    size_t len = 0;
    if (!zcl_native_dev_land_test_encode_text("", detail, out, sizeof(out), &len))
        return false;
    if (len >= sizeof(out))
        return false;
    size_t exact = len + 1;
    if (!zcl_native_dev_land_test_encode_text("", detail, out, exact, &len))
        return false;
    size_t unchanged = len;
    if (zcl_native_dev_land_test_encode_text("", detail, out, exact - 1, &len) ||
        len != unchanged)
        return false;
    if (zcl_native_dev_land_test_encode_text("", detail, out, 0, &len) ||
        len != unchanged)
        return false;
    if (zcl_native_dev_land_test_encode_text("", detail, NULL, 1, &len))
        return false;
    return len == unchanged;
}

static int dlx_row_utf8_valid(bool detail)
{
    int failures = 0;
    TEST("land: row encoding preserves UTF-8 and JSON escapes with exact capacity") {
        static const char text[] =
            "\"\\\n\r\t\b\f\x01\x1f\x7f"
            "\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf"
            "\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf";
        static const char escaped[] =
            "\\\"\\\\\\n\\r\\t\\u0008\\u000c\\u0001\\u001f\x7f"
            "\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf"
            "\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf";
        char out[8192], exact[8192];
        size_t len = 0, got = 0;
        ASSERT(zcl_native_dev_land_test_encode_text(text, detail, out,
                                                    sizeof(out), &len));
        ASSERT(strstr(out, escaped) != NULL);
        ASSERT_EQ(len, strlen(out));
        ASSERT(dlx_row_text_roundtrips(out, len, text, detail));
        ASSERT(len + 1 < sizeof(exact));
        ASSERT(zcl_native_dev_land_test_encode_text(text, detail, exact,
                                                    len + 1, &got));
        ASSERT_EQ(got, len);
        ASSERT_STR_EQ(exact, out);
        got = 123;
        ASSERT(!zcl_native_dev_land_test_encode_text(text, detail, exact,
                                                     len, &got));
        ASSERT_EQ(got, 123);
        ASSERT(dlx_row_empty_capacity(detail));
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_row_utf8_dense_detail(void)
{
    int failures = 0;
    TEST("land: a full control-byte detail still fits its escaped row buffer") {
        char text[1024], out[8192], expected[1023 * 6 + 1];
        size_t len = 0;
        memset(text, '\x01', sizeof(text) - 1);
        text[sizeof(text) - 1] = '\0';
        for (size_t i = 0; i < sizeof(text) - 1; ++i)
            memcpy(expected + i * 6, "\\u0001", 6);
        expected[sizeof(expected) - 1] = '\0';
        ASSERT(zcl_native_dev_land_test_encode_text(text, true, out,
                                                    sizeof(out), &len));
        ASSERT(strstr(out, expected) != NULL);
        ASSERT_EQ(len, strlen(out));
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_row_utf8_cases(void)
{
    static const struct { const char *name; const char *text; } cases[] = {
        { "land: refuse stray continuation in a row", "a\x80" },
        { "land: refuse overlong two-byte UTF-8 in a row", "\xc0\xaf" },
        { "land: refuse C1 overlong UTF-8 in a row", "\xc1\xbf" },
        { "land: refuse overlong three-byte UTF-8 in a row", "\xe0\x80\xaf" },
        { "land: refuse overlong four-byte UTF-8 in a row", "\xf0\x80\x80\xaf" },
        { "land: refuse a UTF-16 surrogate in a row", "\xed\xa0\x80" },
        { "land: refuse a scalar above U+10FFFF in a row", "\xf4\x90\x80\x80" },
        { "land: refuse an illegal lead byte in a row", "\xff" },
        { "land: refuse F5 lead byte in a row", "\xf5\x80\x80\x80" },
        { "land: refuse an illegal lead after a prefix in a row", "prefix\xff" },
        { "land: refuse bad two-byte continuation in a row", "\xc2" "A" },
        { "land: refuse bad continuation in a row", "\xe2(\xa1" },
        { "land: refuse truncated two-byte UTF-8 in a row", "\xc2" },
        { "land: refuse truncated three-byte UTF-8 in a row", "\xe2\x82" },
        { "land: refuse truncated four-byte UTF-8 in a row", "\xf0\x9f\x92" }
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        failures += dlx_row_utf8_refuses(cases[i].name, cases[i].text, false);
        failures += dlx_row_utf8_refuses(cases[i].name, cases[i].text, true);
    }
    failures += dlx_row_utf8_valid(false);
    failures += dlx_row_utf8_valid(true);
    failures += dlx_row_utf8_dense_detail();
    return failures;
}

static int test_dev_land_receipt_adversarial(void)
{
    int failures = dlx_row_utf8_cases();
#if !defined(_WIN32)
    TEST("land: tampered persisted remote receipts refuse without redispatch") {
        ASSERT(dlx_receipt_tamper_cases());
        PASS();
    } _test_next:;
#endif
    return failures;
}

static int test_dev_land_signer_takeover(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: another signer resumes only with receiver-local trust") {
        ASSERT(dlx_receipt_different_signer());
        PASS();
    } _test_next:;
#endif
    return failures;
}

static int test_dev_land_signed_tamper(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: tampered signed intent refuses before remote mutation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400];
        char wire[8192];
        size_t len = 0;
        dlx_isolate("signed_tamper");
        ASSERT(dlx_rig_make(&rig, "signed_tamper_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, wire, sizeof(wire) - 1, &len));
        wire[len] = '\0';
        char *field = strstr(wire, "\"publication_signature\":\"");
        ASSERT(field != NULL);
        field += strlen("\"publication_signature\":\"");
        ASSERT(*field == '0' || (*field >= '1' && *field <= '9') ||
               (*field >= 'a' && *field <= 'f'));
        *field = *field == '0' ? '1' : '0';
        ASSERT(dlx_write(path, wire));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_INVALID");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_signed_stale(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed pair rejects a moved base and retains successor work") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64];
        dlx_isolate("signed_stale");
        ASSERT(dlx_rig_make(&rig, "signed_stale_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_signed_recovery(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed remote recovery records receipt without replaying push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char land[1200], wt[1400], wrapper[1400], marker[1400];
        char script[3000];
        dlx_isolate("signed_recovery");
        ASSERT(dlx_rig_make(&rig, "signed_recovery_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        (void)snprintf(wrapper, sizeof(wrapper), "%s/refuse-replay", land);
        (void)snprintf(marker, sizeof(marker), "%s/replay-attempted", land);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf 'attempted\\n' > '%s'\nexit 91\n",
                       marker);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        char update[128];
        (void)snprintf(update, sizeof(update), "%s:refs/heads/main", rig.tip);
        const char *remote_effect[] = { "fetch", "--quiet", rig.clone,
                                        update, NULL };
        ASSERT(dlx_git(rig.bare, remote_effect) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        ASSERT(!dlx_file_exists(marker));
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_new_source_precheck(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a range that adds a compiled source is told apart from one that edits a file or adds anything else") {
        struct dlx_rig rig;
        char base[64], edit[64], added[64], header[64];
        dlx_isolate("new_source_precheck");
        ASSERT(dlx_rig_make(&rig, "new_source_precheck_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *onto[] = { "checkout", "--quiet", "-B", "probe", base,
                               NULL };
        ASSERT(dlx_git(rig.clone, onto) == 0);
        ASSERT(dlx_commit(rig.clone, "notes.md", "prose\n", edit));
        ASSERT(dlx_commit(rig.clone, "module.h", "int f(void);\n", header));
        ASSERT(dlx_commit(rig.clone, "module.c", "int f(void){return 0;}\n",
                          added));
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          edit) == 0);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          header) == 0);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          added) == 1);
        /* The file exists on both sides: an edit, not an addition. */
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, added,
                                                          added) == 0);
        /* A pair git cannot name is never read as "nothing added". */
        ASSERT(zcl_native_dev_land_test_range_adds_source(
                   rig.clone, base,
                   "0123456789abcdef0123456789abcdef01234567") == -1);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, "main",
                                                          added) == -1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_drive_producer_reproof(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a drive whose binary is not the candidate's builds the producer in the landing worktree and proves with it") {
        char root[512], make_ok[1400], make_bad[1400], script[4000];
        char log[1400], seen[2048], want[1800], why[256] = "";
        size_t seen_len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "drive_producer_wt");
        ASSERT(zcl_native_dev_land_test_producer_stale(
            "proof_producer_source_mismatch"));
        ASSERT(zcl_native_dev_land_test_producer_stale(
            "failed exact proof: proof_producer_source_mismatch"));
        ASSERT(!zcl_native_dev_land_test_producer_stale("lint"));
        ASSERT(!zcl_native_dev_land_test_producer_stale(NULL));
        (void)snprintf(make_ok, sizeof(make_ok), "%s/fake-make", root);
        (void)snprintf(make_bad, sizeof(make_bad), "%s/fake-make-bad", root);
        (void)snprintf(log, sizeof(log), "%s/producer-argv", root);
        /* argv: -jN -C <root> dev-bin. The built "producer" records how it
         * was called. */
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\n"
                       "[ \"$2\" = -C ] && [ \"$4\" = dev-bin ] || exit 64\n"
                       "mkdir -p \"$3/build/bin\" || exit 65\n"
                       "printf '%%s\\n' '#!/bin/sh' "
                       "'printf \"%%s \" \"$@\" > \"%s\"' "
                       "'exit 7' > \"$3/build/bin/z23-dev\" || exit 66\n"
                       "chmod 700 \"$3/build/bin/z23-dev\"\n", log);
        ASSERT(dlx_write(make_ok, script));
        ASSERT(chmod(make_ok, 0700) == 0);
        ASSERT(dlx_write(make_bad,
                         "#!/bin/sh\necho 'boom: no rule' >&2\nexit 2\n"));
        ASSERT(chmod(make_bad, 0700) == 0);
        /* A build that fails names itself and runs no proof. */
        ASSERT(zcl_native_dev_land_test_producer_reproof(
                   root, "1111111111111111111111111111111111111111",
                   "2222222222222222222222222222222222222222", make_bad, why,
                   sizeof(why)) == -1);
        ASSERT(why[0] != '\0');
        ASSERT(!dlx_file_exists(log));
        /* A built producer is run on the exact pair and root; its verdict
         * (here a failing exit) is the proof's to settle, not the drive's. */
        ASSERT(zcl_native_dev_land_test_producer_reproof(
                   root, "1111111111111111111111111111111111111111",
                   "2222222222222222222222222222222222222222", make_ok, why,
                   sizeof(why)) == 1);
        ASSERT(dlx_slurp(log, seen, sizeof(seen) - 1, &seen_len));
        seen[seen_len] = '\0';
        (void)snprintf(want, sizeof(want),
                       "dev proof step --root=%s "
                       "--local_commit=1111111111111111111111111111111111111111 "
                       "--remote_base=2222222222222222222222222222222222222222 ",
                       root);
        ASSERT_STR_EQ(seen, want);
        PASS();
    }
_test_next:;
#endif
    return failures;
}

static int test_dev_land_signed_lost_ack(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a lost signed push is re-sent only while main is unmoved and attempts remain; a moved base requeues a successor") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], wt[1400];
        char wrapper[1400], marker[1400], script[3000], attempts[128];
        size_t attempts_len = 0;
        dlx_isolate("signed_lost_ack");
        ASSERT(dlx_rig_make(&rig, "signed_lost_ack_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
        (void)snprintf(marker, sizeof(marker), "%s/dispatch-count", land);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf 'attempted\\n' >> '%s'\nexit 91\n",
                       marker);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        ASSERT_STR_EQ(dlx_str(&c, "observed_remote_tip"), base);
        ASSERT_STR_EQ(dlx_str(&c, "head_commit"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "dispatch_state"), "unknown");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == strlen("attempted\n"));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *steer = json_get(&c.reply.data, "steer");
        const struct json_value *inflight =
            json_get(&c.reply.data, "in_flight");
        ASSERT(steer != NULL);
        ASSERT(inflight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "acceptance_state")),
                      "unknown");
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "dispatch_state")),
                      "unknown");
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "detail")),
                      "signed push outcome unknown; await independent remote receipt");
        ASSERT_STR_EQ(json_get_str(json_get(steer,
                                          "first_missing_transition")),
                      "remote_receipt");
        dlx_end(&c);
        /* Main is unmoved and the head is absent, so the dispatch did not
         * apply: each later step sends the same compare-and-swap again,
         * one per attempt the row has left, and then stops asking. */
        for (size_t sent = 2; sent <= 4; sent++) {
            size_t want = sent > 3 ? 3 : sent;
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
            ASSERT_STR_EQ(dlx_str(&c, "dispatch_state"), "unknown");
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, remote));
            ASSERT_STR_EQ(remote, base);
            ASSERT(dlx_slurp(marker, attempts, sizeof(attempts),
                             &attempts_len));
            ASSERT(attempts_len == want * strlen("attempted\n"));
        }
        char sibling[64];
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "side.txt", "other\n", sibling));
        char update_side[128];
        (void)snprintf(update_side, sizeof(update_side),
                       "%s:refs/heads/main", sibling);
        const char *fetch_side[] = { "fetch", "--quiet", rig.clone,
                                     update_side, NULL };
        ASSERT(dlx_git(rig.bare, fetch_side) == 0);
        /* Base moved and the head is provably absent from the fresh
         * observation: the exact signed pair can never fast-forward onto
         * the moved main, so the row requeues as a successor instead of
         * waiting forever on a receipt that can never arrive.  The exact
         * pair is not sent onto a moved base (the count stays at 3). */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT(dlx_int(&c, "predecessor_seq") == 1);
        dlx_end(&c);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == 3 * strlen("attempted\n"));
        /* Drive the successor to a real landing: lift the lose-ack
         * intercept, rebase+prove, attach the fresh pair, push. */
        const char *restore[] = { "config", "--unset",
                                  "remote.origin.receivepack", NULL };
        ASSERT(dlx_git(wt, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        dlx_end(&c);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT(strcmp(remote, base) != 0);
        ASSERT(strcmp(remote, sibling) != 0);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == 3 * strlen("attempted\n"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
static bool dlx_sibling(const struct dlx_rig *rig, const char *base,
                        const char *ref, char out[64]);

/* Attach a signed intent to a proven pair and make the next push lose its
 * acknowledgement. `marker` counts receive-pack dispatches. With `racer`,
 * a sibling of base wins remote main inside that lost dispatch. */
static bool dlx_signed_push_lossy(struct dlx_rig *rig, const char *tag,
                                  char base[64], char wt[1400],
                                  char marker[1400], char racer[64])
{
    struct dlx_call c;
    char land[1200], wrapper[1400], script[4000], extra[1600] = "";
    if (!dlx_attach_proven_pair(rig, tag, base))
        return false;
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (racer) {
        ok = ok && dlx_sibling(rig, base, "refs/heads/side", racer);
        (void)snprintf(extra, sizeof(extra),
                       "git --git-dir='%s' update-ref refs/heads/main %s %s "
                       "|| exit 92\n", rig->bare, racer, base);
    }
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, 1400, "%s/wt", land);
    (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
    (void)snprintf(marker, 1400, "%s/dispatch-count", land);
    (void)snprintf(script, sizeof(script),
                   "#!/bin/sh\nprintf 'attempted\\n' >> '%s'\n%sexit 91\n",
                   marker, extra);
    const char *intercept[] = { "config", "remote.origin.receivepack",
                                wrapper, NULL };
    return ok && dlx_write(wrapper, script) && chmod(wrapper, 0700) == 0 &&
           dlx_git(wt, intercept) == 0;
}

/* Commit a sibling of `base` in the clone and publish it on the bare
 * remote as `ref`. */
static bool dlx_sibling(const struct dlx_rig *rig, const char *base,
                        const char *ref, char out[64])
{
    char update[160];
    const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                             NULL };
    if (dlx_git(rig->clone, branch) != 0 ||
        !dlx_commit(rig->clone, "side.txt", "other\n", out))
        return false;
    (void)snprintf(update, sizeof(update), "%s:%s", out, ref);
    const char *fetch[] = { "fetch", "--quiet", rig->clone, update, NULL };
    return dlx_git(rig->bare, fetch) == 0;
}

static bool dlx_dispatched_once(const char *marker)
{
    char attempts[128];
    size_t len = 0;
    return dlx_slurp(marker, attempts, sizeof(attempts), &len) &&
           len == strlen("attempted\n");
}

/* The successor carries no publication and the land log names the settled
 * refusal against the observed sibling. */
static bool dlx_refused_successor(const struct dlx_call *c,
                                  const char *sibling)
{
    char queue[16384], log[65536], want[160];
    size_t qlen = 0, llen = 0;
    const char *log_path = dlx_str(c, "log_path");
    if (!dlx_queue_bytes(queue, sizeof(queue), &qlen) ||
        !strstr(queue, "\"publication_signature\":\"\"") ||
        !log_path || !dlx_slurp(log_path, log, sizeof(log) - 1, &llen))
        return false;
    log[llen] = '\0';
    (void)snprintf(want, sizeof(want),
                   "signed push refused: main moved to %s without head; "
                   "successor seq=1", sibling);
    return strstr(log, want) != NULL;
}
#endif

static int test_dev_land_signed_lost_race(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed push checkpoint settles as refused once main moves to a sibling") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], sibling[64];
        char upload_pack[1400];
        dlx_isolate("signed_lost_race");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_lost_race", base, wt,
                                     marker, NULL));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        ASSERT_STR_EQ(dlx_str(&c, "observed_remote_tip"), base);
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        /* Without a fresh observation the moved remote is not evidence. */
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack",
                       rig.bare);
        ASSERT(dlx_write(upload_pack, "#!/bin/sh\nexit 75\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        const char *blind[] = { "config", "remote.origin.uploadpack",
                                upload_pack, NULL };
        const char *see[] = { "config", "--unset", "remote.origin.uploadpack",
                              NULL };
        ASSERT(dlx_git(wt, blind) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(flight, "phase")), "push");
        dlx_end(&c);
        ASSERT(dlx_git(wt, see) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        ASSERT(dlx_refused_successor(&c, sibling));
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_signed_lost_ack_resend(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a lost signed push on a quiet main lands on the next step as the same row and pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400];
        dlx_isolate("signed_lost_ack_resend");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_lost_ack_resend", base,
                                     wt, marker, NULL));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        /* The remote answers again. Nothing else moved: no successor, no
         * second proof, no second signature — the next step is the push. */
        const char *restore[] = { "config", "--unset",
                                  "remote.origin.receivepack", NULL };
        ASSERT(dlx_git(wt, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip_pushed"), rig.tip);
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_dispatched_once(marker));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_signed_push_lost_race(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed push that loses the race while dispatching requeues as successor") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], sibling[64];
        dlx_isolate("signed_push_lost_race");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_push_lost_race", base, wt,
                                     marker, sibling));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        ASSERT(dlx_refused_successor(&c, sibling));
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_cancel_push_refused(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: cancel drops a push checkpoint settled as refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], sibling[64], wire[8192];
        size_t used = 0;
        dlx_isolate("cancel_push_refused");
        ASSERT(dlx_attach_proven_pair(&rig, "cancel_push_refused", base));
        ASSERT(dlx_queue_bytes(wire, sizeof(wire), &used));
        char *phase = strstr(wire, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        char land[1200], path[1400];
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_write(path, wire));
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_signed_publisher_death(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: publisher death after signed remote mutation recovers receipt") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], hook[1400], wrapper[1400], marker[1400];
        char received[32];
        size_t received_len = 0;
        int child_status = 0;
        dlx_isolate("signed_publisher_death");
        ASSERT(dlx_rig_make(&rig, "signed_publisher_death_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker),
                       "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        char land[1200], wt[1400];
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            char script[256];
            (void)setsid(); /* see dlx_wait_publisher */
            (void)alarm(30);
            (void)snprintf(script, sizeof(script),
                           "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
            if (!dlx_write(hook, script) || chmod(hook, 0700) != 0)
                _exit(2);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(dlx_wait_publisher(child, &child_status) == child);
        ASSERT(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
static int test_dev_land_rebase_regen_cases(void);
static int test_dev_land_queued_precheck_cases(void);
#endif

/* Submit the rig's tip and take the first step to a started proof. */
static bool dlx_started(struct dlx_rig *rig, const char *tag,
                        const char *rig_tag)
{
    struct dlx_call c;
    dlx_isolate(tag);
    if (!dlx_rig_make(rig, rig_tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool submitted = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    bool started = submitted && dlx_run(&c) && dlx_ok(&c) &&
                   strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    return started;
}

/* One step under `stub`; true when it answered `state` at `attempt`. */
static bool dlx_step_to(const char *stub, const char *state, int64_t attempt,
                        const char *detail_part)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", stub, 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (attempt <= 0 || dlx_int(&c, "attempt") == attempt) &&
              (!detail_part || strstr(dlx_str(&c, "detail"), detail_part));
    dlx_end(&c);
    return ok;
}

#if !defined(_WIN32)
/* ── the drive's base watch over a real proof step ───────────────────────
 *
 * The forked worker stands in for the proof worker around ONE real proof
 * step: the production step runner (own session; TERM, then KILL, of its
 * process group on cancel) runs `argv`, under the SIGTERM handler the real
 * worker inherits from its requester (a cancel request). The requester side
 * is the drive's own base probe (dl_base_probe) through the proof's own
 * wait loop, against a real bare origin. Only the step's command is a
 * stand-in for the proof. */
static void dlx_watch_worker_cancel(int signal_number)
{
    (void)signal_number;
    zcl_devloop_process_cancel_request();
}

static void dlx_watch_worker_run(const char *dir, const char *const argv[],
                                 int report_fd)
{
    struct sigaction action = {0};
    action.sa_handler = dlx_watch_worker_cancel;
    sigemptyset(&action.sa_mask);
    zcl_devloop_process_cancel_clear();
    char log[1200];
    struct zcl_dev_proof_step step;
    const struct zcl_dev_proof_budget budget =
        zcl_dev_proof_budget_make(600000, 600000);
    int64_t report[3] = { -1, -1, -1 };
    if (sigaction(SIGTERM, &action, NULL) == 0 &&
        snprintf(log, sizeof(log), "%s.step.log", dir) < (int)sizeof(log) &&
        zcl_dev_proof_step_start(&step, dir, log, argv, &budget)) {
        report[0] = step.child;
        if (write(report_fd, &report[0], sizeof(report[0])) !=
            (ssize_t)sizeof(report[0]))
            _exit(1);
        (void)zcl_dev_proof_steps_wait(&step, 1);
        report[1] = (int64_t)step.report.cause;
        report[2] = (int64_t)step.report.rc;
    } else if (write(report_fd, &report[0], sizeof(report[0])) !=
               (ssize_t)sizeof(report[0])) {
        _exit(1);
    }
    _exit(write(report_fd, &report[1], 2 * sizeof(report[1])) ==
                  (ssize_t)(2 * sizeof(report[1]))
              ? 0 : 1);
}

struct dlx_watched {
    int64_t step_child; /* the proof step's session leader */
    int64_t cause;      /* enum zcl_dev_proof_kill_cause of the step's end */
    int64_t rc;
    int waited;         /* what the drive's watched wait returned */
    bool superseded;
};

/* Start the worker, let `move` (when non-NULL) push a stranger commit to
 * origin main once the step is running, then watch the worker exactly as
 * a proving drive does until it exits. */
static bool dlx_watch_proof(const struct dlx_rig *rig, const char *base,
                            const char *const argv[], const char *move,
                            struct dlx_watched *out)
{
    int fds[2];
    char stranger[64];
    memset(out, 0, sizeof(*out));
    if (pipe(fds) != 0) return false;
    pid_t worker = fork();
    if (worker == 0) {
        (void)close(fds[0]);
        dlx_watch_worker_run(rig->bare, argv, fds[1]);
    }
    (void)close(fds[1]);
    bool ok = worker > 0 &&
        read(fds[0], &out->step_child, sizeof(out->step_child)) ==
            (ssize_t)sizeof(out->step_child) &&
        out->step_child > 0;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    if (ok && move)
        ok = dlx_commit(rig->clone, move, "elsewhere\n", stranger) &&
             dlx_git(rig->clone, push) == 0;
    if (worker > 0) {
        if (!ok) (void)kill(worker, SIGTERM);
        out->waited = zcl_native_dev_land_test_watch_worker(
            rig->clone, base, (int)worker, 20, &out->superseded);
    }
    int64_t tail[2] = { -1, -1 };
    ok = ok && read(fds[0], tail, sizeof(tail)) == (ssize_t)sizeof(tail);
    (void)close(fds[0]);
    out->cause = tail[0];
    out->rc = tail[1];
    return ok;
}

/* The step's session leader is gone, and nothing is left in its group. */
static bool dlx_step_group_gone(int64_t leader)
{
    errno = 0;
    bool leader_gone = kill((pid_t)leader, 0) != 0 && errno == ESRCH;
    errno = 0;
    bool group_gone = kill(-(pid_t)leader, 0) != 0 && errno == ESRCH;
    return leader_gone && group_gone;
}

static int test_dev_land_drive_base_watch(void)
{
    int failures = 0;
    TEST("land drive: main moving under a running proof cancels it as superseded and leaves no step process") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64];
        const char *never_ends[] = { "sleep", "120", NULL };
        dlx_isolate("watch_moved");
        ASSERT(dlx_rig_make(&rig, "watch_moved_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_watch_proof(&rig, base, never_ends, "stranger.txt", &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_CANCELLED);
        ASSERT_EQ(w.rc, 130);
        ASSERT(dlx_step_group_gone(w.step_child));
        dlx_restore();
        PASS();
    }
    TEST("land drive: an unreachable origin never cancels a running proof; it runs to its own end") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64], missing[1200];
        const char *short_step[] = { "sleep", "1", NULL };
        dlx_isolate("watch_unknown");
        ASSERT(dlx_rig_make(&rig, "watch_unknown_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        (void)snprintf(missing, sizeof(missing), "%s/absent", rig.bare);
        const char *unreachable[] = { "remote", "set-url", "origin", missing,
                                      NULL };
        ASSERT(dlx_git(rig.clone, unreachable) == 0);
        /* Even a base that is not the (unobservable) tip: only an
         * affirmative answer may cancel. */
        ASSERT(dlx_watch_proof(&rig, rig.tip, short_step, NULL, &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(!w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_NONE);
        ASSERT_EQ(w.rc, 0);
        ASSERT(dlx_step_group_gone(w.step_child));
        dlx_restore();
        PASS();
    }
    TEST("land drive: an unmoved main lets a running proof finish") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64];
        const char *short_step[] = { "sleep", "1", NULL };
        dlx_isolate("watch_current");
        ASSERT(dlx_rig_make(&rig, "watch_current_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_watch_proof(&rig, base, short_step, NULL, &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(!w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_NONE);
        ASSERT_EQ(w.rc, 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}
#endif

#if !defined(_WIN32)
/* The producer-recovery counter the proof stub's stand-in rebuild keeps. */
static long dlx_producer_runs(void)
{
    char path[1200];
    struct stat st;
    (void)snprintf(path, sizeof(path), "%s/producer-recovery-count",
                   g_dlx_state);
    return stat(path, &st) == 0 ? (long)st.st_size : 0;
}

/* One step under `stub`; true when it answered `state` with `dimension`. */
static bool dlx_step_dim(const char *stub, const char *state,
                         const char *dimension, const char *detail_part)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", stub, 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (!dimension || strcmp(dlx_str(&c, "dimension"),
                                    dimension) == 0) &&
              (!detail_part || strstr(dlx_str(&c, "detail"), detail_part));
    dlx_end(&c);
    return ok;
}

/* Stand in for a step that died between phases: rewrite the one row's phase
 * in the rig's queue file. Fails unless `"phase":"<from>"` occurs exactly once. */
static bool dlx_queue_phase(const char *from, const char *to)
{
    char landdir[1100], path[1200], key[64], buf[16384], out[16384];
    size_t len = 0;
    int n = snprintf(key, sizeof(key), "\"phase\":\"%s\"", from);
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (n < 0 || (size_t)n >= sizeof(key) ||
        !dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *hit = strstr(buf, key);
    if (!hit || strstr(hit + n, key))
        return false;
    int w = snprintf(out, sizeof(out), "%.*s\"phase\":\"%s\"%s",
                     (int)(hit - buf), buf, to, hit + n);
    return w > 0 && (size_t)w < sizeof(out) && dlx_write(path, out);
}

/* Stand in for a queued row whose producer recovery was spent: rewrite
 * `from` to `to` inside the one queue.jsonl line that holds `anchor`.
 * Fails unless `anchor` occurs exactly once in the file and `from` occurs
 * exactly once in that line. (Choice: the anchor is the row's tip, since
 * a second row carries the same field.) */
static bool dlx_queue_field_once(const char *anchor, const char *from,
                                 const char *to)
{
    char landdir[1100], path[1200], buf[16384], line[16384], out[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *hit = strstr(buf, anchor);
    if (!hit || strstr(hit + 1, anchor))
        return false;
    char *start = hit;
    while (start > buf && start[-1] != '\n')
        start--;
    char *end = strchr(hit, '\n');
    if (!end)
        end = buf + len;
    if ((size_t)(end - start) >= sizeof(line))
        return false;
    (void)snprintf(line, sizeof(line), "%.*s", (int)(end - start), start);
    char *f = strstr(line, from);
    if (!f || strstr(f + strlen(from), from))
        return false;
    int w = snprintf(out, sizeof(out), "%.*s%.*s%s%s%s",
                     (int)(start - buf), buf, (int)(f - line), line, to,
                     f + strlen(from), end);
    return w > 0 && (size_t)w < sizeof(out) && dlx_write(path, out);
}

/* Move origin/main with a commit from a side clone, as a stranger landing. */
static bool dlx_stranger_lands(const struct dlx_rig *rig)
{
    char stranger[64];
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *branch[] = { "checkout", "--quiet", "-B", "side",
                             "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
    return dlx_git(rig->clone, branch) == 0 &&
           dlx_commit(rig->clone, "stranger.txt", "elsewhere\n", stranger) &&
           dlx_git(rig->clone, push) == 0 &&
           dlx_git(rig->clone, back) == 0 &&
           dlx_git(rig->clone, fetch) == 0;
}

/* The shared setup of the dead-step cases: recover once, then kill the step. */
static bool dlx_recovered_dead(struct dlx_rig *rig, const char *tag,
                               const char *rig_tag)
{
    return dlx_started(rig, tag, rig_tag) &&
           dlx_step_dim("producer_stale", "proving", "", NULL) &&
           dlx_producer_runs() == 1 &&
           dlx_queue_phase("prove", "prebuild");
}
#endif

#if !defined(_WIN32)
/* Phase mail quieting. The lander posts one phase row per landing step; a
 * row identical to the last one posted for the same landing is not posted
 * again. These cases read the mail leaf's outbox raw and count rows. */
static bool dlx_pm_outbox_path(char *out, size_t cap)
{
    char landdir[1200], mail[1300];
    dlx_landdir(landdir, sizeof(landdir));
    return snprintf(mail, sizeof(mail), "%s/../mail", landdir) <
               (int)sizeof(mail) &&
           dlx_mkdir_p(mail) &&
           snprintf(out, cap, "%s/outbox.jsonl", mail) < (int)cap;
}

static int dlx_pm_count(const char *needle)
{
    char path[1400];
    static char text[1u << 20];
    size_t len = 0;
    int n = 0;
    if (!dlx_pm_outbox_path(path, sizeof(path)) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return 0;
    text[len] = '\0';
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

/* Occurrences of `needle` in the land log of the one submission, the same
 * logs/land-1-a1.log that dlx_beat_log_record reads. */
static int dlx_pm_log_count(const char *needle)
{
    char landdir[1200], path[1400];
    static char text[1u << 20];
    size_t len = 0;
    int n = 0;
    dlx_landdir(landdir, sizeof(landdir));
    int w = snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (w <= 0 || (size_t)w >= sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return 0;
    text[len] = '\0';
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

/* True while queue.jsonl still carries a "phase_mail" member, or cannot be
 * read (the caller then fails rather than passing on an unknown file). */
static bool dlx_pm_queue_has_phase_mail(void)
{
    char landdir[1100], path[1200], buf[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return true;
    buf[len] = '\0';
    return strstr(buf, "\"phase_mail\":") != NULL;
}

/* Isolated rig, mailbox present, one submission stepped once. */
static bool dlx_pm_start(struct dlx_rig *rig, const char *tag)
{
    struct dlx_call c;
    char path[1400];
    dlx_isolate(tag);
    if (!dlx_rig_make(rig, tag) || !dlx_pm_outbox_path(path, sizeof(path)))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok && dlx_step_dim("running", "started", NULL, NULL);
}

/* One step under the "running" stub that must succeed, whatever the state. */
static bool dlx_pm_step(void)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

/* Delete the `"phase_mail":N,` member from the queue file: an older row. */
static bool dlx_pm_strip_field(void)
{
    char landdir[1100], path[1200], buf[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *key = strstr(buf, "\"phase_mail\":");
    char *comma = key ? strchr(key, ',') : NULL;
    if (!comma)
        return false;
    memmove(key, comma + 1, strlen(comma + 1) + 1);
    return dlx_write(path, buf);
}

static int test_dev_land_phase_mail_quiet(void)
{
    int failures = 0;
    TEST("land: steps that change nothing post one phase row; a changed row posts a new one") {
        struct dlx_rig rig;
        int first, beats;
        ASSERT(dlx_pm_start(&rig, "pm_quiet"));
        first = dlx_pm_count("land=phase");
        ASSERT(first >= 1);
        beats = dlx_pm_log_count("beat=proof_status");
        ASSERT(dlx_pm_step());
        ASSERT(dlx_pm_step());
        /* Both steps ran the proof read and their commits succeeded (dlx_pm_step
         * requires an ok reply), so each wrote its proof_status beat. The
         * unchanged post count below is then suppression, not idle steps. */
        ASSERT(dlx_pm_log_count("beat=proof_status") >= beats + 2);
        ASSERT_EQ(dlx_pm_count("land=phase"), first);
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT(dlx_pm_count("land=phase") > first);
        dlx_restore();
        PASS();
    }
    TEST("land: a terminal row is posted after quiet phase rows") {
        struct dlx_rig rig;
        struct dlx_call c;
        ASSERT(dlx_pm_start(&rig, "pm_terminal"));
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=outcome"), 0);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT_EQ(dlx_pm_count("land=outcome\\nstate=cancelled"), 1);
        dlx_restore();
        PASS();
    }
    TEST("land: a queue row without the phase_mail field loads, steps and posts") {
        struct dlx_rig rig;
        int first;
        ASSERT(dlx_pm_start(&rig, "pm_oldrow"));
        first = dlx_pm_count("land=phase");
        ASSERT(dlx_pm_strip_field());
        ASSERT(!dlx_pm_queue_has_phase_mail());
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=phase"), first + 1);
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=phase"), first + 1);
        dlx_restore();
        PASS();
    }
    /* A plain behaviour test: the requeued successor's first phase row posts.
     * It does NOT discriminate the successor.phase_mail reset in
     * dl_requeue_successor; removing that reset leaves this test green. */
    TEST("land: a successor row's first phase row posts") {
        struct dlx_rig rig;
        char base[64], stranger[64];
        int first;
        ASSERT(dlx_started(&rig, "pm_successor", "pm_successor_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_step_to("cancelled", "rebased", 2, "successor queued"));
        first = dlx_pm_count("land=phase");
        ASSERT(dlx_pm_step());
        ASSERT(dlx_pm_count("land=phase") > first);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}
#endif

/* Pure digest judgments through zcl_dev_land_phase_digest, declared in
 * native_dev_land_attestation.h. Each test moves one input and says what
 * that must do to the digest. */
static long long dlx_pd(const char *detail, const char *tip)
{
    return zcl_dev_land_phase_digest("inflight", "prove", 1, "", "n", detail,
                                     "land-1-a1.log", tip);
}

static int test_dev_land_phase_digest(void)
{
    int failures = 0;
    static const char idle_901[] =
        "resident_proof_request_queued; proof_request_idle_age_s=901 "
        "(no worker has claimed the queued request)";
    static const char idle_12345[] =
        "resident_proof_request_queued; proof_request_idle_age_s=12345 "
        "(no worker has claimed the queued request)";
    TEST("land phase digest: a tip change moves the digest") {
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(idle_901, "bbbb"));
        PASS();
    }
    TEST("land phase digest: only the idle-age digits leave it unchanged; other detail moves it") {
        static const char renamed[] =
            "resident_proof_request_queued_x; proof_request_idle_age_s=901 "
            "(no worker has claimed the queued request)";
        static const char reworded[] =
            "resident_proof_request_queued; proof_request_idle_age_s=901 "
            "(no worker has claimed the queued request!)";
        ASSERT(dlx_pd(idle_901, "aaaa") == dlx_pd(idle_12345, "aaaa"));
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(renamed, "aaaa"));
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(reworded, "aaaa"));
        PASS();
    }
    TEST("land phase digest: an all-empty row is never 0, NULL reads as empty") {
        long long nulls = zcl_dev_land_phase_digest(NULL, NULL, 0, NULL, NULL,
                                                    NULL, NULL, NULL);
        long long empty = zcl_dev_land_phase_digest("", "", 0, "", "", "", "",
                                                    "");
        ASSERT(nulls != 0);
        ASSERT(empty != 0);
        ASSERT(nulls == empty);
        PASS();
    }
    TEST("land phase digest: adjacent fields keep their borders") {
        ASSERT(zcl_dev_land_phase_digest("ab", "c", 0, NULL, NULL, NULL, NULL,
                                         NULL) !=
               zcl_dev_land_phase_digest("a", "bc", 0, NULL, NULL, NULL, NULL,
                                         NULL));
        PASS();
    }
    TEST("land phase digest: the idle key with no digits, or twice, is stable") {
        static const char bare[] = "x; proof_request_idle_age_s= (none)";
        static const char twice_a[] =
            "proof_request_idle_age_s=1; proof_request_idle_age_s=22";
        static const char twice_b[] =
            "proof_request_idle_age_s=9; proof_request_idle_age_s=3";
        ASSERT(dlx_pd(bare, "t") != 0);
        ASSERT(dlx_pd(bare, "t") == dlx_pd(bare, "t"));
        ASSERT(dlx_pd(twice_a, "t") == dlx_pd(twice_b, "t"));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_step_producer_recovery(void)
{
    int failures = 0;
#if !defined(_WIN32)
    static const char *const stale = "proof_producer_source_mismatch";
    TEST("land step: a spent producer recovery is earned again when a dead step's rebase finds main moved") {
        struct dlx_rig rig;
        ASSERT(dlx_recovered_dead(&rig, "step_producer_moved", "step_producer_moved_rig"));
        ASSERT(dlx_stranger_lands(&rig));
        ASSERT(dlx_step_dim("running", "started", NULL, NULL));
        ASSERT(dlx_step_dim("producer_stale", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 2);
        dlx_restore();
        PASS();
    }
    TEST("land step: a dead step's rebase on an unmoved main does not hand out a second producer recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_recovered_dead(&rig, "step_producer_still", "step_producer_still_rig"));
        ASSERT(dlx_step_dim("running", "started", NULL, NULL));
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a producer-stale refusal is recovered once and the re-proved pair lands") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_once", "step_producer_once_rig"));
        ASSERT(dlx_step_dim("producer_stale_once", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_once", "landed", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a producer refusal that survives the one recovery settles failed and is not recovered again") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_twice", "step_producer_twice_rig"));
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale", "empty", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: any other proof failure settles as before and never recovers the producer") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_other", "step_producer_other_rig"));
        ASSERT(dlx_step_dim("fail", "failed", "lint", "proof stub: fail"));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict producer refusal is recovered once and the re-proved pair lands") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_once", "step_nv_once_rig"));
        ASSERT(dlx_step_dim("producer_stale_nv_once", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv_once", "landed", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict producer refusal that survives the one recovery settles failed, never pending") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_twice", "step_nv_twice_rig"));
        ASSERT(dlx_step_dim("producer_stale_nv", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv", "empty", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict status with another detail stays pending and never recovers the producer") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_other", "step_nv_other_rig"));
        ASSERT(dlx_step_dim("no_verdict_other", "proving", NULL,
                            "proof_producer_source_id_unavailable"));
        ASSERT(dlx_step_dim("no_verdict_other", "proving", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
    TEST("land step: a host-load retry mark is kept through a producer recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_hl", "step_producer_hl_rig"));
        ASSERT(dlx_step_dim("producer_host_load", "rebased", "host_load",
                            NULL));
        ASSERT(dlx_step_dim("running", "started", "host_load", NULL));
        ASSERT(dlx_step_dim("producer_stale_once", "proving", "host_load",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_once", "landed", "host_load",
                            NULL));
        dlx_restore();
        PASS();
    }
    TEST("land step: a host-load retry after the recovery does not earn a second recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_hl2", "step_producer_hl2_rig"));
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_host_load", "rebased", "host_load",
                            NULL));
        ASSERT(dlx_step_dim("running", "started", "host_load", NULL));
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a running status whose text mentions the stale producer is not a no-verdict and is left alone") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_text", "step_producer_text_rig"));
        ASSERT(dlx_step_dim("producer_stale_text", "proving", "",
                            "background_verification_running"));
        ASSERT(dlx_step_dim("producer_stale_text", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
_test_next:;
#endif
    return failures;
}

static int test_dev_land_interrupted_proof(void)
{
    int failures = 0;
    TEST("land: an interrupted proof re-runs the same pair instead of failing the candidate") {
        struct dlx_rig rig;
        char before[64], after[64];
        ASSERT(dlx_started(&rig, "interrupt_retry", "interrupt_retry_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        ASSERT(dlx_step_to("cancelled", "proving", 2,
                           "interrupted proof re-queued"));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        ASSERT(dlx_step_to("pass", "landed", 0, NULL));
        dlx_restore();
        PASS();
    }
    TEST("land: interruption retries are bounded, then the request settles as failed") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "interrupt_bound", "interrupt_bound_rig"));
        ASSERT(dlx_step_to("cancelled", "proving", 2, NULL));
        ASSERT(dlx_step_to("cancelled", "proving", 3, NULL));
        ASSERT(dlx_step_to("cancelled", "failed", 3,
                           "child_proof_cancelled_"));
        dlx_restore();
        PASS();
    }
    TEST("land: an interrupted proof whose base moved cuts the successor") {
        struct dlx_rig rig;
        char base[64], stranger[64];
        ASSERT(dlx_started(&rig, "interrupt_moved", "interrupt_moved_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_step_to("cancelled", "rebased", 2, "successor queued"));
        dlx_restore();
        PASS();
    }
    TEST("land: the base probe answers only from a well-formed remote tip") {
        struct dlx_rig rig;
        char base[64], missing[1200];
        dlx_isolate("base_probe");
        ASSERT(dlx_rig_make(&rig, "base_probe_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, base),
                  ZCL_DEV_PROOF_BASE_CURRENT);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, rig.tip),
                  ZCL_DEV_PROOF_BASE_SUPERSEDED);
        (void)snprintf(missing, sizeof(missing), "%s/absent", rig.bare);
        const char *unreachable[] = { "remote", "set-url", "origin", missing,
                                      NULL };
        ASSERT(dlx_git(rig.clone, unreachable) == 0);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, rig.tip),
                  ZCL_DEV_PROOF_BASE_UNKNOWN);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(missing, rig.tip),
                  ZCL_DEV_PROOF_BASE_UNKNOWN);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#if !defined(_WIN32)
/* ── a failed proof keeps what failed ─────────────────────────────────────
 *
 * A real attempt directory, a real stub child run as one proof dimension,
 * and the production failure settle and status reader: the only stand-in
 * is the child itself. Land seqs 163-167 failed with nothing but
 * `child_proof_failed_exit_N`; the first FAIL line has to survive into the
 * `.failed` record, the land outcome, and the attempt's evidence file,
 * while the record's first line stays the exact token every classifier
 * reads. */
struct dlx_evidence_case {
    const char *tag;
    enum zcl_dev_proof_dimension_id dimension;
    const char *script;         /* the stub child: its output and exit */
    const char *token;          /* the settled first line, unchanged */
    const char *land_dimension; /* the outcome's dimension */
    const char *detail;         /* what the outcome detail leads with */
    const char *absent;         /* noise the evidence must not carry */
};

static const char k_dlx_evidence_test_script[] =
    "printf '%s\\n' \\\n"
    " '==================== test_dev_land_noise (PASS, 0s) ====================' \\\n"
    " 'assert macros: FAIL names file:line and both values... OK' \\\n"
    " '==================== test_golden_dev_cycle (FAIL, 3s) ====================' \\\n"
    " 'golden dev cycle: a hot swap lands under a second... ' \\\n"
    " 'FAIL at tests/harness/src/test_golden_dev_cycle.c:367 (hotswap_ms < 1000.0)' \\\n"
    " 'SOME TESTS FAILED - 1/2 groups failed' \\\n"
    " 'Failed groups:' \\\n"
    " '  - test_golden_dev_cycle: exit code=1 log=./test-tmp/test_parallel_1_822.log'\n"
    "exit 1\n";

static const char k_dlx_evidence_compile_script[] =
    "root=$(pwd -P)\n"
    "echo \"cc -c $root/tools/dev/widget.c\"\n"
    "echo \"$root/tools/dev/widget.c:12:5: error: unknown type name 'widget_t'\"\n"
    "echo \"$root/tools/dev/widget.c:14:1: error: expected ';' before '}' token\"\n"
    "echo 'make: *** [Makefile:1: build-only] Error 1'\n"
    "exit 2\n";

/* The in-flight pair a `running` stub step left proving. */
static bool dlx_proving_pair(char local[64], char base[64])
{
    struct dlx_call c;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    (void)snprintf(local, 64, "%s", f ? dlx_jstr(f, "local") : "");
    (void)snprintf(base, 64, "%s", f ? dlx_jstr(f, "base") : "");
    dlx_end(&c);
    return local[0] != '\0' && base[0] != '\0';
}

/* Submit, start proving, then settle one stub child's failure as the
 * proof of exactly the in-flight pair in the landing worktree. */
static bool dlx_evidence_settle(const struct dlx_evidence_case *k,
                                char real_wt[PATH_MAX], char local[64],
                                char base[64])
{
    struct dlx_rig rig;
    struct dlx_call c;
    char tag[64], landwt[1300], landdir[1200], script[1300], why[256];
    (void)snprintf(tag, sizeof(tag), "%s_rig", k->tag);
    if (!dlx_rig_make(&rig, tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, &rig, rig.tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_land_wt(landwt, sizeof(landwt));
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(script, sizeof(script), "%s/stub-child.sh", landdir);
    const char *argv[] = { "/bin/sh", script, NULL };
    return ok && dlx_proving_pair(local, base) &&
           realpath(landwt, real_wt) != NULL &&
           dlx_write(script, k->script) &&
           zcl_dev_proof_test_settle_child(real_wt, local, base,
                                           k->dimension, argv, why,
                                           sizeof(why)) &&
           dlx_eq_str(why, k->token);
}

/* The evidence text: present, relative, and free of the named noise. */
static bool dlx_evidence_text_ok(const struct dlx_evidence_case *k,
                                 const char *text, const char *real_wt)
{
    if (!dlx_has(text, k->detail))
        return false;
    if (strstr(text, k->absent) || strstr(text, real_wt)) {
        printf("FAIL evidence carries '%s' or an absolute path: %s\n",
               k->absent, text);
        return false;
    }
    return true;
}

/* The pair's `.failed` record: the unchanged token, then the evidence. */
static bool dlx_evidence_record_ok(const struct dlx_evidence_case *k,
                                   const char *real_wt, const char *local,
                                   const char *base)
{
    char path[PATH_MAX + 200], record[4096];
    size_t len = 0, token_len = strlen(k->token);
    (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed",
                   real_wt, local, base);
    if (!dlx_slurp(path, record, sizeof(record) - 1, &len))
        return false;
    record[len] = '\0';
    if (strncmp(record, k->token, token_len) != 0 ||
        record[token_len] != '\n') {
        printf("FAIL record first line is not the bare token: %s\n", record);
        return false;
    }
    return dlx_evidence_text_ok(k, record + token_len, real_wt);
}

/* Consume the settled failure through the production status reader and
 * check the outcome row and the attempt's evidence file. */
static bool dlx_evidence_outcome_ok(const struct dlx_evidence_case *k,
                                    const char *real_wt)
{
    struct dlx_call c;
    char landdir[1200], path[1400], text[4096];
    size_t len = 0;
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              dlx_eq_str(dlx_str(&c, "state"), "failed") &&
              dlx_eq_str(dlx_str(&c, "dimension"), k->land_dimension) &&
              dlx_has(dlx_str(&c, "detail"), k->detail) &&
              strncmp(dlx_str(&c, "detail"), k->detail,
                      strlen(k->detail)) == 0;
    if (!ok)
        printf("FAIL outcome dimension='%s' detail='%s'\n",
               dlx_str(&c, "dimension"), dlx_str(&c, "detail"));
    dlx_end(&c);
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/logs/land-1-a1.evidence",
                   landdir);
    if (!ok || !dlx_slurp(path, text, sizeof(text) - 1, &len)) {
        if (ok)
            printf("FAIL no evidence file at %s\n", path);
        return false;
    }
    text[len] = '\0';
    return dlx_has(text, k->token) &&
           dlx_evidence_text_ok(k, text, real_wt);
}

static bool dlx_evidence_case_run(const struct dlx_evidence_case *k)
{
    char real_wt[PATH_MAX], local[64], base[64];
    dlx_isolate(k->tag);
    bool ok = dlx_evidence_settle(k, real_wt, local, base) &&
              dlx_evidence_record_ok(k, real_wt, local, base) &&
              dlx_evidence_outcome_ok(k, real_wt);
    dlx_restore();
    return ok;
}

static int test_dev_land_proof_evidence_test(void)
{
    int failures = 0;
    TEST("land: a failed test group names its FAIL line in the outcome") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_test",
            .dimension = ZCL_DEV_PROOF_TEST,
            .script = k_dlx_evidence_test_script,
            .token = "child_proof_failed_exit_1",
            .land_dimension = "test",
            .detail = "test test_golden_dev_cycle: FAIL at "
                      "tests/harness/src/test_golden_dev_cycle.c:367 "
                      "(hotswap_ms < 1000.0)",
            .absent = "assert macros",
        };
        ASSERT(dlx_evidence_case_run(&k));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_proof_evidence_compile(void)
{
    int failures = 0;
    TEST("land: a failed build names its first compiler error, relative") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_compile",
            .dimension = ZCL_DEV_PROOF_COMPILE,
            .script = k_dlx_evidence_compile_script,
            .token = "child_proof_failed_exit_2",
            .land_dimension = "compile",
            .detail = "compile: tools/dev/widget.c:12:5: error: unknown "
                      "type name 'widget_t'",
            .absent = "expected ';'",
        };
        ASSERT(dlx_evidence_case_run(&k));
        PASS();
    }
_test_next:;
    return failures;
}
#endif

#if !defined(_WIN32)
static int test_dev_land_status_observation(void)
{
    int failures = 0;
    char root[4096], land[8192], logs[8300];
    struct stat info;
    struct dlx_call call;
    bool opened = false;
    TEST("land: status observes absent and read-only state without setup") {
        dlx_isolate("observe_only");
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(!dlx_ok(&call));
        ASSERT(lstat(g_dlx_state, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(platform_state_root(root, sizeof(root)));
        ASSERT(snprintf(land, sizeof(land), "%s/land", root) > 0);
        ASSERT(snprintf(logs, sizeof(logs), "%s/logs", land) > 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(dlx_ok(&call));
        ASSERT(lstat(land, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(mkdir(land, 0500) == 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(dlx_ok(&call));
        ASSERT(stat(land, &info) == 0 && (info.st_mode & 0777) == 0500);
        ASSERT(lstat(logs, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(chmod(land, 0700) == 0);
        ASSERT(chmod(root, 0755) == 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(!dlx_ok(&call));
        ASSERT(stat(root, &info) == 0 && (info.st_mode & 0777) == 0755);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&call);
    dlx_restore();
    return failures;
}
#endif

#if !defined(_WIN32)
/* Real local bare receiver and independently signed, same-tree successor.
 * The proof stub hashes each distinct pair: equal trees do not share proof. */
static bool dlx_fence_prepare(struct dlx_rig *rig, const char *tag,
                               char base[64], char wt[1400], char successor[64])
{
    char marker[1400], tree[64];
    if (!dlx_signed_push_lossy(rig, tag, base, wt, marker, NULL)) return false;
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && !dlx_ok(&c) &&
        strcmp(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN") == 0;
    dlx_end(&c);
    const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
    const char *restore[] = { "config", "--unset", "remote.origin.receivepack", NULL };
    if (!ok || !dlx_sign_arm(rig->clone, tag) ||
        dlx_git(rig->clone, restore) != 0 ||
        dlx_git_out(rig->clone, lookup, tree, sizeof(tree)) != 0) return false;
    const char *create[] = { "commit-tree", "-S", tree, "-p", base,
                             "-m", "qualified fence successor", NULL };
    if (dlx_git_out(rig->clone, create, successor, 64) != 0) return false;
    const char *checkout[] = { "checkout", "--quiet", "-B", "fence-successor",
                               successor, NULL };
    const char *hooks[] = { "config", "--worktree", "core.hooksPath",
                            g_dlx_hooks_ok, NULL };
    setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    setenv("ZCL_LAND_TEST_FENCE_POLICY", "monotonic", 1);
    return dlx_git(rig->clone, checkout) == 0 && dlx_git(rig->clone, hooks) == 0;
}

static void dlx_fence_call(struct dlx_call *c, const struct dlx_rig *rig,
                           const char *base, const char *head, const char *tip)
{
    dlx_begin(c, "fence_replace");
    (void)json_push_kv_int(&c->input, "seq", 1);
    (void)json_push_kv_str(&c->input, "base", base);
    (void)json_push_kv_str(&c->input, "head", head);
    (void)json_push_kv_str(&c->input, "tip", tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
}

static bool dlx_fence_crash_step(const char *point)
{
    pid_t child = fork();
    if (child == 0) {
        setenv("ZCL_LAND_TEST_FENCE_CRASH", point, 1);
        struct dlx_call call;
        dlx_begin(&call, "step");
        (void)dlx_run(&call);
        dlx_end(&call);
        _exit(88);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 87;
}

struct dlx_fence_case {
    unsigned scenario; bool stop;
    struct dlx_rig rig; struct dlx_call c;
    char tag[64], base[64], wt[1400], successor[64], remote[64], land[1200];
    char before[32768], after[32768]; size_t before_len, after_len;
};

static int dlx_fence_case_admission(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced admission") {
            /* Historical old acceptance/reversion before current protection.
             * The fence must leave that history unknown rather than refused. */
            if (t->scenario == 2) {
                char ref[160];
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", t->rig.tip);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                const char *revert[] = { "update-ref", "refs/heads/main", t->base,
                                         t->rig.tip, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
                ASSERT(dlx_git(t->rig.bare, revert) == 0);
            }
            const char *deny_rewinds[] = { "config", "receive.denyNonFastForwards", "true", NULL };
            ASSERT(dlx_git(t->rig.bare, deny_rewinds) == 0);
            /* Missing policy and wrong pins leave original checkpoint exact. */
            setenv("ZCL_LAND_TEST_FENCE_POLICY", "unavailable", 1);
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_CONTRACT_UNAVAILABLE");
            dlx_end(&t->c);
            ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
            ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
            setenv("ZCL_LAND_TEST_FENCE_POLICY", "monotonic", 1);
            dlx_fence_call(&t->c, &t->rig, t->base, t->base, t->successor);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OLD_INTENT_CHANGED");
            dlx_end(&t->c);
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), "fence_armed");
            ASSERT(dlx_int(&t->c, "replacement_seq") == 2);
            dlx_end(&t->c);
            /* Idempotence allocates no second replacement or dispatch. */
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT(dlx_int(&t->c, "replacement_seq") == 2);
            dlx_end(&t->c);
            dlx_begin(&t->c, "cancel"); (void)json_push_kv_int(&t->c.input, "seq", 1);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_ACTIVE"); dlx_end(&t->c);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_lossy(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced lossy") {
            if (t->scenario == 7 || t->scenario == 8) {
                char wrapper[1400], marker[1400], script[3000], diagnostic[1400];
                dlx_landdir(t->land, sizeof(t->land));
                (void)snprintf(wrapper, sizeof(wrapper), "%s/reject-new", t->land);
                (void)snprintf(marker, sizeof(marker), "%s/new-attempts", t->land);
                (void)snprintf(script, sizeof(script),
                    "#!/bin/sh\nprintf 'sent\\n' >> '%s'\nprintf 'stderr-only-refusal\\033[31m\\n' >&2\nexit 91\n", marker);
                ASSERT(dlx_write(wrapper, script)); ASSERT(chmod(wrapper, 0700) == 0);
                const char *intercept[] = { "config", "--worktree", "remote.origin.receivepack", wrapper, NULL };
                ASSERT(dlx_git(t->rig.clone, intercept) == 0);
                if (t->scenario == 7) {
                    (void)snprintf(diagnostic, sizeof(diagnostic), "%s/logs/push-2-a1.diagnostic", t->land);
                    ASSERT(mkdir(diagnostic, 0700) == 0); /* Durable-storage refusal. */
                }
                for (unsigned beat = 0; beat < 4; ++beat) {
                    dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                    ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
                }
                size_t count = 0; char sends[128], transcript[4096];
                ASSERT(dlx_slurp(marker, sends, sizeof(sends), &count));
                ASSERT(count == strlen("sent\n") * (t->scenario == 7 ? 1 : 3));
                ASSERT(dlx_origin_main(&t->rig, t->remote)); ASSERT_STR_EQ(t->remote, t->base);
                if (t->scenario == 8) {
                    (void)snprintf(diagnostic, sizeof(diagnostic), "%s/logs/push-2-a1.diagnostic", t->land);
                    ASSERT(dlx_slurp(diagnostic, transcript, sizeof(transcript) - 1, &count));
                    transcript[count] = '\0';
                    ASSERT(strstr(transcript, "stderr-only-refusal?") != NULL);
                    ASSERT(strstr(transcript, "exit_observed=1") != NULL);
                    ASSERT(strstr(transcript, "END publication diagnostic") != NULL);
                }
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_both_heads(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced both_heads") {
            if (t->scenario == 9) {
                char tree[64], combined[64], ref[160];
                const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
                ASSERT(dlx_git_out(t->rig.clone, lookup, tree, sizeof(tree)) == 0);
                const char *merge[] = { "commit-tree", "-S", tree, "-p", t->rig.tip,
                                        "-p", t->successor, "-m", "contains both", NULL };
                ASSERT(dlx_git_out(t->rig.clone, merge, combined, sizeof(combined)) == 0);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", combined);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
                dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OBSERVATION_INCONSISTENT"); dlx_end(&t->c);
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_dispatch(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced dispatch") {
            if (t->scenario == 1) {
                char ref[160];
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", t->rig.tip);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
            } else if (t->scenario == 3) {
                ASSERT(dlx_fence_crash_step("before_dispatch"));
                dlx_begin(&t->c, "step");
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
                ASSERT(dlx_origin_main(&t->rig, t->remote)); ASSERT_STR_EQ(t->remote, t->base);
                /* A checkpointed send cannot be changed to another identity. */
                dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->base);
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_IDENTITY_FROZEN"); dlx_end(&t->c);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY");
                unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore(); t->stop = true; return failures;
            } else if (t->scenario == 4) {
                ASSERT(dlx_fence_crash_step("after_dispatch"));
            } else {
                dlx_begin(&t->c, "step");
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_rewind(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced rewind") {
            ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
            ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
            if (t->scenario == 5) ASSERT(dlx_fence_crash_step("paired"));
            if (t->scenario == 6) ASSERT(dlx_fence_crash_step("old_projection"));
            if (t->scenario == 10) {
                ASSERT(dlx_fence_crash_step("paired"));
                /* External administrative policy violation t->after observation:
                 * force a rewind through fixture update-ref, not receive-pack. */
                const char *rewind[] = { "update-ref", "refs/heads/main", t->base, t->successor, NULL };
                ASSERT(dlx_git(t->rig.bare, rewind) == 0);
                dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OBSERVATION_INCONSISTENT"); dlx_end(&t->c);
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_settlement(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced settlement") {
            dlx_begin(&t->c, "step");
            ASSERT(dlx_run(&t->c));
            if (!dlx_ok(&t->c)) printf("fence scenario=%u error=%s ", t->scenario, dlx_err_code(&t->c));
            ASSERT(dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), t->scenario == 1 ? "fenced" : "landed");
            dlx_end(&t->c);
            dlx_begin(&t->c, "status");
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            const struct json_value *outcomes = dlx_arr(&t->c, "outcomes");
            ASSERT(outcomes && outcomes->num_children == 2);
            const struct json_value *old = &outcomes->children[0];
            const struct json_value *next = &outcomes->children[1];
            ASSERT_STR_EQ(json_get_str(json_get(old, "state")), t->scenario == 1 ? "landed" : "fenced");
            ASSERT_STR_EQ(json_get_str(json_get(old, "historical_git_acceptance")),
                           t->scenario == 1 ? "verified" : "unknown");
            ASSERT_STR_EQ(json_get_str(json_get(old, "future_dispatch")),
                           t->scenario == 1 ? "complete" : "fenced");
            ASSERT_STR_EQ(json_get_str(json_get(next, "state")), t->scenario == 1 ? "fenced" : "landed");
            ASSERT(json_get_int(json_get(old, "fence_peer")) == 2);
            ASSERT(json_get_int(json_get(next, "fence_peer")) == 1);
            const struct json_value *winner = t->scenario == 1 ? old : next;
            ASSERT(strlen(json_get_str(json_get(winner, "remote_signature"))) == 128);
            ASSERT_STR_EQ(json_get_str(json_get(old, "tip")), t->rig.tip);
            ASSERT(json_get_int(json_get(old, "attempt")) == 1);
            dlx_end(&t->c);
            ASSERT(dlx_origin_main(&t->rig, t->remote));
            ASSERT_STR_EQ(t->remote, t->scenario == 1 ? t->rig.tip : t->successor);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_delayed(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced delayed") {
            /* A delayed competing exact-base CAS cannot undo the winner. */
            char lease[128], competing[128];
            (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", t->base);
            (void)snprintf(competing, sizeof(competing), "%s:refs/heads/main",
                           t->scenario == 1 ? t->successor : t->rig.tip);
            const char *delayed[] = { "push", lease, "origin", competing, NULL };
            const char *restore[] = { "config", "--worktree", "--unset", "remote.origin.receivepack", NULL };
            (void)dlx_git(t->wt, restore);
            ASSERT(dlx_git(t->scenario == 1 ? t->rig.clone : t->wt, delayed) != 0);
            ASSERT(dlx_origin_main(&t->rig, t->remote));
            ASSERT_STR_EQ(t->remote, t->scenario == 1 ? t->rig.tip : t->successor);
            dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), "empty"); dlx_end(&t->c);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_run(unsigned scenario)
{
    int failures = 0;
    struct dlx_fence_case t = {0};
    t.scenario = scenario;
    (void)snprintf(t.tag, sizeof(t.tag), "fence_%u", scenario);
    dlx_isolate(t.tag);
    TEST("land: compound same-tree fenced case") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        ASSERT(dlx_fence_case_admission(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_lossy(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_both_heads(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_dispatch(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_rewind(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_settlement(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_delayed(&t) == 0);
        if (t.stop) goto _test_next;
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_LAND_TEST_FENCE_CRASH");
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_cases(void)
{
    int failures = 0;
    for (unsigned scenario = 0; scenario < 11; ++scenario)
        failures += dlx_fence_case_run(scenario);
    return failures;
}

static void dlx_fence_race_child(unsigned old_wins, int ready[2], int release[2],
                                  struct dlx_rig *rig, const char *base, const char *wt)
{
    struct dlx_call call; char lease[128], ref[128];
                (void)close(ready[0]); (void)close(release[1]);
                if (old_wins) {
                    dlx_begin(&call, "step");
                    bool ok = dlx_run(&call) && !dlx_ok(&call) &&
                        strcmp(dlx_err_code(&call), "FENCE_PUSH_OUTCOME_UNKNOWN") == 0;
                    dlx_end(&call); _exit(ok ? 0 : 89);
                }
                char byte;
                if (write(ready[1], "R", 1) != 1 || read(release[0], &byte, 1) != 1 || byte != 'G')
                    _exit(90);
                (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", base);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", rig->tip);
                const char *push[] = { "push", lease, "origin", ref, NULL };
                _exit(dlx_git(wt, push) != 0 ? 0 : 91);
}

static int dlx_fence_race_parent(unsigned old_wins, struct dlx_rig *rig,
                                  struct dlx_call *call, const char *base, const char *wt, const char *tip)
{
    int failures = 0; char lease[128], ref[128];
    TEST("land: fenced race parent") {
            if (old_wins) {
                dlx_fence_call(call, rig, base, rig->tip, tip);
                ASSERT(dlx_run(call) && !dlx_ok(call));
                ASSERT_STR_EQ(dlx_err_code(call), "STEP_BUSY"); dlx_end(call);
                (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", base);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", rig->tip);
                const char *push[] = { "push", lease, "origin", ref, NULL };
                ASSERT(dlx_git(wt, push) == 0);
            } else {
                dlx_begin(call, "step"); ASSERT(dlx_run(call) && !dlx_ok(call));
                ASSERT_STR_EQ(dlx_err_code(call), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(call);
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_concurrent_case(unsigned old_wins)
{
    int failures = 0;
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    TEST("land: competing delayed exact-base CAS and concurrent replacement respect the single compound owner") {
            struct dlx_rig rig; struct dlx_call call;
            char base[64], wt[1400], tip[64], remote[64];
            dlx_isolate(old_wins ? "fence_old_race" : "fence_new_race");
            ASSERT(dlx_fence_prepare(&rig, old_wins ? "fence_old_race" : "fence_new_race", base, wt, tip));
            dlx_fence_call(&call, &rig, base, rig.tip, tip);
            ASSERT(dlx_run(&call) && dlx_ok(&call)); dlx_end(&call);
            ASSERT(dlx_pick_barrier_open(ready, release));
            if (old_wins) zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
            child = fork(); ASSERT(child >= 0);
            if (child == 0) dlx_fence_race_child(old_wins, ready, release, &rig, base, wt);
            (void)close(ready[1]); ready[1] = -1;
            (void)close(release[0]); release[0] = -1;
            char byte; ASSERT(read(ready[0], &byte, 1) == 1 && byte == 'R');
            zcl_native_dev_land_test_pick_barrier(-1, -1);
            ASSERT(dlx_fence_race_parent(old_wins, &rig, &call, base, wt, tip) == 0);
            ASSERT(write(release[1], "G", 1) == 1);
            (void)close(release[1]); release[1] = -1;
            int status = 0;
            ASSERT(waitpid(child, &status, 0) == child);
            child = -1; ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            (void)close(ready[0]); ready[0] = -1;
            dlx_begin(&call, "step"); ASSERT(dlx_run(&call) && dlx_ok(&call));
            ASSERT_STR_EQ(dlx_str(&call, "state"), old_wins ? "fenced" : "landed"); dlx_end(&call);
            ASSERT(dlx_origin_main(&rig, remote)); ASSERT_STR_EQ(remote, old_wins ? rig.tip : tip);
            unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
        PASS();
    } _test_next:;
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; ++i) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) { int status = 0; (void)waitpid(child, &status, 0); }
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}
static bool dlx_fence_expect(struct dlx_fence_case *t, const char *action, const char *code)
{
    if (strcmp(action, "fence_replace") == 0)
        dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
    else dlx_begin(&t->c, action);
    bool ok = dlx_run(&t->c) && !dlx_ok(&t->c) && strcmp(dlx_err_code(&t->c), code) == 0;
    if (!ok) printf("fence negative expected=%s actual=%s ", code, dlx_err_code(&t->c));
    dlx_end(&t->c);
    return ok;
}

static bool dlx_fence_same_queue(struct dlx_fence_case *t)
{
    return dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len) &&
        t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0;
}

static bool dlx_fence_bad_hook(struct dlx_fence_case *t)
{
    char hooks[1400];
    if (!dlx_hooks_dir(hooks, sizeof(hooks), "fence_unrelated_noop", 0)) return false;
    const char *set[] = { "config", "--worktree", "core.hooksPath", hooks, NULL };
    return dlx_git(t->rig.clone, set) == 0 &&
        dlx_fence_expect(t, "fence_replace", "FENCE_WORKTREE_INVALID");
}

/* All configuration changes are confined to fresh isolated throwaway rigs. */
static bool dlx_fence_receiver_config(struct dlx_fence_case *t, unsigned kind)
{
    char other[1400], key[1600];
    (void)snprintf(other, sizeof(other), "%s.other", t->rig.bare);
    const char *init[] = { "init", "--bare", "--quiet", other, NULL };
    if (dlx_git(NULL, init) != 0) return false;
    if (kind == 1) {
        const char *add[] = { "config", "--worktree", "--add", "remote.origin.url", other, NULL };
        return dlx_git(t->rig.clone, add) == 0;
    }
    if (kind == 2) {
        const char *first[] = { "config", "--worktree", "--add", "remote.origin.pushurl", t->rig.bare, NULL };
        const char *second[] = { "config", "--worktree", "--add", "remote.origin.pushurl", other, NULL };
        return dlx_git(t->rig.clone, first) == 0 && dlx_git(t->rig.clone, second) == 0;
    }
    if (kind == 3) {
        const char *single[] = { "config", "--worktree", "remote.origin.pushurl", other, NULL };
        return dlx_git(t->rig.clone, single) == 0;
    }
    if (kind == 6) {
        const char *first[] = { "config", "--worktree", "--add", "remote.origin.pushurl", t->rig.bare, NULL };
        const char *empty[] = { "config", "--worktree", "--add", "remote.origin.pushurl", "", NULL };
        return dlx_git(t->rig.clone, first) == 0 && dlx_git(t->rig.clone, empty) == 0;
    }
    if (kind == 5) {
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", other);
        const char *rewrite[] = { "config", "--worktree", key, t->rig.bare, NULL };
        return dlx_git(t->rig.clone, rewrite) == 0;
    }
    (void)snprintf(key, sizeof(key), "url.%s.pushInsteadOf", other);
    const char *rewrite[] = { "config", "--worktree", key, t->rig.bare, NULL };
    return dlx_git(t->rig.clone, rewrite) == 0;
}

static int dlx_fence_negative_receiver(unsigned kind, bool after_arm)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_receiver_%u_%u", kind, after_arm);
    dlx_isolate(t.tag);
    TEST("land: complete effective receiver set refuses before arming or dispatch") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        if (after_arm) {
            dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
            ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        }
        ASSERT(dlx_fence_receiver_config(&t, kind));
        ASSERT(dlx_fence_expect(&t, after_arm ? "step" : "fence_replace",
                               after_arm ? "FENCE_IDENTITY_INVALID" : "FENCE_NEW_PAIR_UNQUALIFIED"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        char other[1400]; (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *head[] = { "rev-parse", "--verify", "refs/heads/main", NULL };
        ASSERT(dlx_git(other, head) != 0);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static bool dlx_fence_stale_hook(struct dlx_fence_case *t)
{
    if (!dlx_write_dep(t->rig.clone, "build/bin/z23-git-hook", "current canonical fixture binary\n")) return false;
    char installed[1400];
    (void)snprintf(installed, sizeof(installed), "%s/z23-git-hook", g_dlx_hooks_ok);
    return dlx_write(installed, "stale installed fixture binary\n") &&
        dlx_fence_expect(t, "fence_replace", "FENCE_WORKTREE_INVALID");
}

static bool dlx_fence_signed_merge(struct dlx_fence_case *t)
{
    char tree[64], merge[64];
    const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
    if (dlx_git_out(t->rig.clone, lookup, tree, sizeof(tree)) != 0) return false;
    const char *make[] = { "commit-tree", "-S", tree, "-p", t->rig.tip, "-p", t->successor,
                           "-m", "signed merge rejected", NULL };
    if (dlx_git_out(t->rig.clone, make, merge, sizeof(merge)) != 0) return false;
    (void)snprintf(t->successor, sizeof(t->successor), "%s", merge);
    const char *checkout[] = { "checkout", "--quiet", "-B", "merge-proposal", merge, NULL };
    return dlx_git(t->rig.clone, checkout) == 0 &&
        dlx_fence_expect(t, "fence_replace", "FENCE_NEW_PAIR_UNQUALIFIED");
}

static int dlx_fence_negative_admission(unsigned kind)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_admission_%u", kind);
    dlx_isolate(t.tag);
    TEST("land: stale unrelated executable hook and signed merge are inadmissible") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        ASSERT(kind == 0 ? dlx_fence_bad_hook(&t) :
               kind == 1 ? dlx_fence_signed_merge(&t) : dlx_fence_stale_hook(&t));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static bool dlx_fence_conflicting_outcome(struct dlx_fence_case *t)
{
    char path[1400], content[65536]; size_t len = 0;
    dlx_landdir(t->land, sizeof(t->land));
    (void)snprintf(path, sizeof(path), "%s/fence.jsonl", t->land);
    if (!dlx_slurp(path, content, sizeof(content) - 1, &len)) return false;
    content[len] = '\0';
    char *row = strchr(content, '\n'); if (!row) return false;
    row = strchr(row + 1, '\n'); if (!row) return false; ++row;
    char *end = strchr(row, '\n'); if (!end) return false; *end = '\0';
    char *peer = strstr(row, "\"fence_peer\":2"); if (!peer) return false;
    peer[strlen("\"fence_peer\":")] = '9';
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", t->land);
    return dlx_write(path, row);
}

static int dlx_fence_negative_replay(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    dlx_isolate("fence_conflicting_outcome");
    TEST("land: contradictory prior terminal peer never replaces sealed paired outcome") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_conflicting_outcome", t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PUSH_OUTCOME_UNKNOWN"));
        ASSERT(dlx_fence_crash_step("paired"));
        ASSERT(dlx_fence_conflicting_outcome(&t));
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PROJECT_PENDING"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PROJECT_PENDING"));
        ASSERT(dlx_fence_same_queue(&t));
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_observer_rewrite(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    char config[1400], key[1600], other[1400];
    const char *prior = getenv("GIT_CONFIG_GLOBAL");
    char *saved = prior ? strdup(prior) : NULL;
    dlx_isolate("fence_observer_rewrite");
    TEST("land: observer-only rewrite cannot substitute the signed receiver") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_observer_rewrite", t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PUSH_OUTCOME_UNKNOWN"));
        dlx_landdir(t.land, sizeof(t.land));
        (void)snprintf(config, sizeof(config), "%s/observer.gitconfig", t.land);
        (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *init[] = { "init", "--bare", "--quiet", other, NULL };
        ASSERT(dlx_git(NULL, init) == 0);
        /* Global shorter-prefix rewrite applies only to the fresh observer;
         * the source checkout's longer identity mapping preserves its URL. */
        char prefix[1400]; (void)snprintf(prefix, sizeof(prefix), "%s", t.rig.bare);
        char *slash = strrchr(prefix, '/'); ASSERT(slash != NULL); slash[1] = '\0';
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", other);
        const char *global[] = { "config", "--file", config, key, prefix, NULL };
        ASSERT(dlx_git(NULL, global) == 0);
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", t.rig.bare);
        const char *local[] = { "config", key, t.rig.bare, NULL };
        ASSERT(dlx_git(t.rig.clone, local) == 0);
        setenv("GIT_CONFIG_GLOBAL", config, 1);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_WINNER_RECEIPT_UNAVAILABLE"));
        ASSERT(dlx_fence_same_queue(&t));
        PASS();
    } _test_next:;
    if (saved) setenv("GIT_CONFIG_GLOBAL", saved, 1); else unsetenv("GIT_CONFIG_GLOBAL");
    free(saved);
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_dispatch_receiver_race(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    int ready[2] = {-1, -1}, release[2] = {-1, -1}; pid_t child = -1;
    dlx_isolate("fence_dispatch_receiver_race");
    TEST("land: receiver changes after checkpoint still refuse before actual send") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_dispatch_receiver_race", t.base, t.wt, t.successor));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_pick_barrier_open(ready, release));
        zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
        child = fork(); ASSERT(child >= 0);
        if (child == 0) dlx_fence_race_child(1, ready, release, &t.rig, t.base, t.wt);
        (void)close(ready[1]); ready[1] = -1;
        (void)close(release[0]); release[0] = -1;
        char marker; ASSERT(read(ready[0], &marker, 1) == 1 && marker == 'R');
        zcl_native_dev_land_test_pick_barrier(-1, -1);
        ASSERT(dlx_fence_receiver_config(&t, 2));
        ASSERT(write(release[1], "G", 1) == 1);
        (void)close(release[1]); release[1] = -1;
        int status = 0; ASSERT(waitpid(child, &status, 0) == child); child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        char other[1400]; (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *head[] = { "rev-parse", "--verify", "refs/heads/main", NULL };
        ASSERT(dlx_git(other, head) != 0);
        PASS();
    } _test_next:;
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; ++i) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) { int status = 0; (void)waitpid(child, &status, 0); }
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_checkout_drift(bool dirty)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_checkout_drift_%u", dirty);
    dlx_isolate(t.tag);
    TEST("land: armed replacement checkout drift refuses new send") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        if (dirty) {
            const char *modify[] = { "config", "--worktree", "core.filemode", "true", NULL };
            ASSERT(dlx_git(t.rig.clone, modify) == 0);
            const char *remove[] = { "rm", "-r", "--cached", ".", NULL };
            ASSERT(dlx_git(t.rig.clone, remove) == 0);
        } else {
            const char *switch_head[] = { "checkout", "--detach", t.base, NULL };
            ASSERT(dlx_git(t.rig.clone, switch_head) == 0);
        }
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_WORKTREE_INVALID"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_negative_cases(void)
{
    int failures = dlx_fence_negative_admission(0) + dlx_fence_negative_admission(1) + dlx_fence_negative_admission(2) +
        dlx_fence_negative_replay() + dlx_fence_observer_rewrite() + dlx_fence_dispatch_receiver_race() +
        dlx_fence_checkout_drift(false) + dlx_fence_checkout_drift(true);
    for (unsigned kind = 1; kind <= 6; ++kind) {
        failures += dlx_fence_negative_receiver(kind, false);
        failures += dlx_fence_negative_receiver(kind, true);
    }
    return failures;
}

static int dlx_fence_concurrent(void)
{
    return dlx_fence_concurrent_case(0) + dlx_fence_concurrent_case(1);
}
#endif

static int dlx_attest_only_cases(void)
{
    int failures = 0;
    char land[2048], path[2304], wire[ZCL_LAND_ATTEST_CAP], before[2048], after[2048];
    size_t before_len = 0, after_len = 0;
    struct dlx_call c;
    const char *row = "{\"seq\":410,\"tip\":\"db648476e77c14308d77501ad85655e2444043b3\",\"state\":\"inflight\",\"attempt\":2,\"phase\":\"prove\",\"base\":\"3a93e60ebf922af3d119b9facc1d95803f42844b\",\"local\":\"db648476e77c14308d77501ad85655e2444043b3\",\"tree\":\"4514cfd63acc408be3d37023656a8e88bc1be2c6\"}\n";
    TEST("land attest-only: self capture roundtrip four BOOL cases and no mutation") {
        dlx_isolate("attest-only");
        dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_write(path, row));
        ASSERT(dlx_slurp(path, before, sizeof(before), &before_len));
        for (int i = 0; i < 4; ++i) {
            ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", (i & 1) ? "1" : "not-one", 1) == 0);
            ASSERT(setenv("ZCL_LAND_PROOF_STUB", (i & 2) ? "PRIVATE-FIXTURE-VALUE-NOT-OUTPUT" : "", 1) == 0);
            dlx_begin(&c, "attest_only");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "service_origin"), "UNKNOWN");
            ASSERT_EQ(json_get(&c.reply.data, "allow_unsigned_is_one")->val.b, !!(i & 1));
            ASSERT_EQ(json_get(&c.reply.data, "proof_stub_nonempty")->val.b, !!(i & 2));
            size_t n = json_write(&c.reply.data, wire, sizeof(wire));
            ASSERT(n > 0 && n < sizeof(wire));
            ASSERT(strstr(wire, "PRIVATE-FIXTURE") == NULL);
            bool enabled = true;
            const char *image = dlx_str(&c, "executable_sha256");
            const char *source = dlx_str(&c, "compiled_source_sha256");
            int64_t clock = dlx_int(&c, "observed_at_ms");
            ASSERT(zcl_dev_land_attestation_decode(wire, n, image, source, clock, &enabled));
            ASSERT_EQ(enabled, i == 3);
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, clock + 5001, &enabled));
            ASSERT(!enabled);
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, 0, &enabled));
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, source, "bad-source", clock, &enabled));
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, source, image, clock, &enabled));
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, NULL, source, clock, &enabled));
            ASSERT(!zcl_dev_land_attestation_decode(wire, n - 1, image, source, clock, &enabled));
            ASSERT(json_push_kv_str(&c.reply.data, "service_origin", "timer"));
            n = json_write(&c.reply.data, wire, sizeof(wire));
            ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, clock, &enabled));
            dlx_end(&c);
            ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
            ASSERT_EQ(before_len, after_len);
            ASSERT(memcmp(before, after, before_len) == 0);
        }
        const char *absent[] = {"step.lock", "queue.lock", "outcomes.jsonl", "logs", "wt"};
        for (size_t i = 0; i < sizeof(absent)/sizeof(absent[0]); ++i) {
            ASSERT(snprintf(path, sizeof(path), "%s/%s", land, absent[i]) < (int)sizeof(path));
            ASSERT(access(path, F_OK) != 0);
        }
        const char *markers[] = {"\"seq\":41", "\"base\":\"", "\"tree\":\"", "\"local\":\""};
        for (size_t i = 0; i < sizeof(markers)/sizeof(markers[0]); ++i) {
            char changed[2048];
            memcpy(changed, before, before_len + 1);
            char *at = strstr(changed, markers[i]);
            ASSERT(at != NULL);
            at += strlen(markers[i]);
            *at = *at == '1' ? '2' : '1';
            ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
            ASSERT(dlx_write(path, changed));
            dlx_begin(&c, "attest_only");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "ATTESTATION_UNKNOWN");
            dlx_end(&c);
            ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
            ASSERT_EQ(before_len, after_len);
            ASSERT(memcmp(changed, after, after_len) == 0);
        }
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_attest_bounded_wire_cases(void)
{
    int failures = 0;
    TEST("land attestation: malformed Unicode exact spans refuse before JSON") {
        const char *vectors[] = {"{\"x\":\"\\", "{\"x\":\"\\u", "{\"x\":\"\\u0",
            "{\"x\":\"\\u00", "{\"x\":\"\\u000", "{\"x\":\"\\uZZZZ\"}",
            "{\"x\":\"\\uD800\"}", "{\"x\":\"\\uDC00\"}",
            "{\"x\":\"\\uD800\\u", "{\"x\":\"\\u0000\"}"};
        char digest[65];
        memset(digest, 'a', 64);
        digest[64] = 0;
        for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); ++i) {
            size_t n = strlen(vectors[i]);
            char *span = malloc(n);
            ASSERT(span != NULL);
            memcpy(span, vectors[i], n);
            bool enabled = true;
            bool accepted = zcl_dev_land_attestation_decode(span, n, digest, digest, 1, &enabled);
            bool unchanged = memcmp(span, vectors[i], n) == 0;
            free(span);
            ASSERT(!accepted && !enabled && unchanged);
            unsigned char guarded[128];
            memset(guarded, 0xa5, sizeof(guarded));
            memcpy(guarded + 1, vectors[i], n);
            enabled = true;
            ASSERT(!zcl_dev_land_attestation_decode((char *)guarded + 1, n,
                digest, digest, 1, &enabled));
            ASSERT(!enabled && guarded[0] == 0xa5 && guarded[n + 1] == 0xa5);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static int dlx_beat_case(const char *beat, int64_t start, int64_t end,
                          const char *duration)
{
    int failures = 0;
    TEST("land beat timing: injected intervals retain exact identity") {
        char wire[768];
        struct zcl_land_beat b = { beat, "base", "candidate", "tree", 41, 2, start, end };
        ASSERT(zcl_dev_land_beat_format(&b, wire, sizeof(wire)));
        ASSERT(strstr(wire, "zcl.dev_land.beat.v1 seq=41 attempt=2") != NULL);
        ASSERT(strstr(wire, "base=base local=candidate tree=tree") != NULL);
        ASSERT(strstr(wire, beat) != NULL);
        ASSERT(strstr(wire, duration) != NULL);
        ASSERT(!zcl_dev_land_beat_format(&b, wire, 1));
        ASSERT_STR_EQ(wire, "");
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_beat_duration(const char *duration, size_t width)
{
    if (width == 7 && memcmp(duration, "unknown", 7) == 0) return true;
    if (width == 0 || width > 19) return false;
    for (size_t i = 0; i < width; i++)
        if (duration[i] < '0' || duration[i] > '9') return false;
    return true;
}

static bool dlx_beat_log_bytes(char *log, size_t len, const char *expected)
{
    const char *tag = "zcl.dev_land.beat.v1 ";
    size_t offset = 0, wanted = strlen(expected);
    bool found = false;
    if (memchr(log, 0, len)) return false;
    log[len] = '\0';
    while (offset < len) {
        char *record = log + offset;
        char *newline = memchr(record, '\n', len - offset);
        size_t width = newline ? (size_t)(newline - record) : len - offset;
        record[width] = '\0';
        bool is_beat = strncmp(record, tag, strlen(tag)) == 0;
        if (is_beat) {
            const char *duration = strstr(record, " elapsed_us=");
            if (!duration) return false;
            duration += strlen(" elapsed_us=");
            if (!dlx_beat_duration(duration, width - (size_t)(duration - record)))
                return false;
            if (width >= wanted && memcmp(record, expected, wanted) == 0)
                found = true;
        } else if (!newline) return false;
        offset += width;
        if (newline) offset++;
    }
    return found;
}

static bool dlx_beat_log_record(const char *prefix, const char *beat)
{
    char landdir[1200], path[1400], log[32768], expected[768];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    int n = snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    if (!dlx_slurp(path, log, sizeof(log) - 1, &len)) return false;
    n = snprintf(expected, sizeof(expected), "%s beat=%s elapsed_us=", prefix, beat);
    if (n <= 0 || (size_t)n >= sizeof(expected)) return false;
    return dlx_beat_log_bytes(log, len, expected);
}

static int dlx_beat_reader_case(const char *label, const char *wire,
                                size_t len, bool accepted)
{
    int failures = 0;
    TEST("land beat reader: bounded complete records") {
        char log[1024];
        printf("checking beat reader=%s\n", label);
        ASSERT(len < sizeof(log));
        memcpy(log, wire, len);
        log[len] = '\0';
        ASSERT(dlx_beat_log_bytes(log, len,
            "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=") == accepted);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_beat_reader_cases(void)
{
    static const struct { const char *label, *wire; size_t len; bool accepted; } cases[] = {
#define DLX_BEAT_READER(label, wire, accepted) { label, wire, sizeof(wire) - 1, accepted }
        DLX_BEAT_READER("newline", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n", true),
        DLX_BEAT_READER("EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1", true),
        DLX_BEAT_READER("unknown EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=unknown", true),
        DLX_BEAT_READER("NUL suffix", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n\0garbage", false),
        DLX_BEAT_READER("torn suffix", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\ntorn", false),
        DLX_BEAT_READER("torn beat", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2", false),
        DLX_BEAT_READER("trailing garbage", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1garbage\n", false),
        DLX_BEAT_READER("empty duration", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=\n", false),
        DLX_BEAT_READER("long duration", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=12345678901234567890\n", false),
        DLX_BEAT_READER("unknown garbage", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=unknown!\n", false),
        DLX_BEAT_READER("complete unrelated records", "ordinary\nzcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nother\n", true),
        DLX_BEAT_READER("unrelated beat EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2 beat=prepare elapsed_us=unknown", true),
        DLX_BEAT_READER("malformed unrelated beat", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2 beat=prepare elapsed_us=x\n", false),
        DLX_BEAT_READER("mid-record match", "other zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n", false),
        DLX_BEAT_READER("empty log", "", false),
#undef DLX_BEAT_READER
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += dlx_beat_reader_case(cases[i].label, cases[i].wire,
                                         cases[i].len, cases[i].accepted);
    return failures;
}

static bool dlx_beat_row_prefix(char *out, size_t cap)
{
    struct dlx_call c;
    if (out && cap) out[0] = '\0';
    if (!out || !cap) return false;
    dlx_begin(&c, "status");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *row = json_get(&c.reply.data, "in_flight");
    int n = 0;
    if (ok && row) {
        n = snprintf(out, cap,
            "zcl.dev_land.beat.v1 seq=1 attempt=1 base=%s local=%s tree=%s",
            dlx_jstr(row, "base"), dlx_jstr(row, "local"), dlx_jstr(row, "tree"));
        ok = strlen(dlx_jstr(row, "base")) == 40 &&
             strlen(dlx_jstr(row, "local")) == 40 &&
             strlen(dlx_jstr(row, "tree")) == 40;
    } else ok = false;
    dlx_end(&c);
    return ok && n > 0 && (size_t)n < cap;
}

static bool dlx_beat_fixture(struct dlx_rig *rig, char *prefix, size_t cap)
{
    struct dlx_call c;
    memset(rig, 0, sizeof(*rig));
    if (prefix && cap) prefix[0] = '\0';
    dlx_isolate("beat_log");
    if (!dlx_rig_make(rig, "beat_log_rig")) return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
         dlx_eq_str(dlx_str(&c, "state"), "started");
    dlx_end(&c);
    return ok && dlx_beat_row_prefix(prefix, cap);
}

static bool dlx_beat_publish(void)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              dlx_eq_str(dlx_str(&c, "state"), "attached");
    dlx_end(&c);
    if (!ok) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
         dlx_eq_str(dlx_str(&c, "state"), "landed");
    dlx_end(&c);
    return ok;
}

static int dlx_beat_production_case(const char *beat)
{
    int failures = 0;
    TEST("land beat logging: isolated production record retains row identity") {
        struct dlx_rig rig;
        char prefix[512];
        ASSERT(dlx_beat_fixture(&rig, prefix, sizeof(prefix)));
        if (strcmp(beat, "prepare") != 0) ASSERT(dlx_beat_publish());
        printf("checking production beat=%s\n", beat);
        ASSERT(dlx_beat_log_record(prefix, beat));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_beat_attach_case(void)
{
    int failures = 0;
    TEST("land beat logging: attach proof read records its exact row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], prefix[512], landdir[1200], path[1400];
        dlx_isolate("beat_attach");
        ASSERT(dlx_attach_proven_pair(&rig, "beat_attach", base));
        ASSERT(dlx_beat_row_prefix(prefix, sizeof(prefix)));
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir) < (int)sizeof(path));
        ASSERT(dlx_write(path, ""));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_FAILED");
        dlx_end(&c);
        ASSERT(dlx_beat_log_record(prefix, "proof_status"));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_beat_production_cases(void)
{
    return dlx_beat_attach_case() + dlx_beat_production_case("prepare") +
        dlx_beat_production_case("proof_status") +
        dlx_beat_production_case("push") +
        dlx_beat_production_case("fresh_observation");
}

static int dlx_beat_cases(void)
{
    return dlx_beat_case("push", 100, 900, "elapsed_us=800") +
        dlx_beat_case("fresh_observation", 100, 2100, "elapsed_us=2000") +
        dlx_beat_case("prepare", 0, 0, "elapsed_us=0") +
        dlx_beat_case("proof_status", 100, 99, "elapsed_us=unknown") +
        dlx_beat_case("push", -1, 100, "elapsed_us=unknown");
}

static int dlx_attest_refusal_cases(void)
{
    int failures = 0;
    struct dlx_call c;
    TEST("land attest-only: unavailable root refuses without creating state") {
        dlx_isolate("attest-missing-root");
        dlx_begin(&c, "attest_only");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTESTATION_UNKNOWN");
        ASSERT(access(g_dlx_state, F_OK) != 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures + dlx_beat_cases() + dlx_beat_production_cases() +
        dlx_beat_reader_cases();
}

static void dlx_join_bad_identity(int kind, struct zcl_land_launcher_capture *c,
                                  struct zcl_land_launcher_frame *f)
{
    switch (kind) {
    case 0: c->complete = false; break;
    case 1: c->frame_count = 0; break;
    case 2: c->frame_count = 2; break;
    case 3: c->frames = NULL; break;
    case 4: c->before.unit = "foreign.service"; break;
    case 5: c->after.descriptor_sha256 = f->identity.boot_id; break;
    case 6: f->identity.invocation_id = f->identity.boot_id; break;
    case 7: f->identity.boot_id = f->identity.invocation_id; break;
    case 8: c->after.manager_uid++; break;
    case 9: f->uid++; break;
    }
}

static void dlx_join_bad_frame(int kind, struct zcl_land_launcher_capture *c,
                               struct zcl_land_launcher_frame *f)
{
    switch (kind) {
    case 10: c->after.pid++; break;
    case 11: f->transport = "journal"; break;
    case 12: f->cursor = NULL; break;
    case 13: c->before.captured_at_ms = 4999; break;
    case 14: c->after.captured_at_ms = 10001; break;
    case 15: f->identity.captured_at_ms = 9999; break;
    case 16: f->journal_at_ms = 4999; break;
    case 17: f->length--; break;
    case 18: f->wire = "{}"; f->length = 2; break;
    case 19: f->identity.pid++; break;
    }
}

static int dlx_launcher_join_cases(void)
{
    int failures = 0;
    const char *wire = "{\"schema\":\"zcl.dev_land.self_attestation.v1\",\"seq\":410,\"candidate\":\"db648476e77c14308d77501ad85655e2444043b3\",\"base\":\"3a93e60ebf922af3d119b9facc1d95803f42844b\",\"tree\":\"4514cfd63acc408be3d37023656a8e88bc1be2c6\",\"unsealed\":true,\"executable_sha256\":\"d6810cf72e0c0ea08c05e89cb5cd20f37c9d8ecb6f069fc3c38f909bf26af564\",\"compiled_source_sha256\":\"6f0feb89be24e387e3b9cc67074c95172ddb78d9af093dda11dcf3e135bb5248\",\"observed_at_ms\":10000,\"allow_unsigned_is_one\":false,\"proof_stub_nonempty\":false,\"fixture_exception_enabled\":false,\"service_origin\":\"UNKNOWN\"}";
    struct zcl_land_launcher_identity expected = {
        .unit = "fixture-attest.service",
        .descriptor_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .invocation_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .boot_id = "cccccccccccccccccccccccccccccccc",
        .manager_uid = 1000, .pid = 123, .captured_at_ms = 10000
    };
    struct zcl_land_launcher_frame frame = {
        .identity = expected, .uid = 1000, .transport = "stdout",
        .cursor = "fixture-cursor", .wire = wire, .length = strlen(wire),
        .journal_at_ms = 10000
    };
    struct zcl_land_launcher_capture original = {
        .before = expected, .after = expected, .frames = &frame,
        .frame_count = 1, .complete = true
    };
    TEST("land launcher join: one exact frame and inclusive 5000ms fixture boundary") {
        bool enabled = true;
        ASSERT(zcl_dev_land_launcher_join(&expected, &original, 15000, &enabled));
        ASSERT(!enabled);
        ASSERT(!zcl_dev_land_launcher_join(&expected, &original, 15001, &enabled));
        ASSERT(!enabled);
        PASS();
    }
    TEST("land launcher join: missing stale foreign duplicate and truncated captures UNKNOWN") {
        for (int kind = 0; kind < 20; ++kind) {
            struct zcl_land_launcher_frame altered = frame;
            struct zcl_land_launcher_capture capture = original;
            capture.frames = &altered;
            dlx_join_bad_identity(kind, &capture, &altered);
            dlx_join_bad_frame(kind, &capture, &altered);
            bool enabled = true;
            ASSERT(!zcl_dev_land_launcher_join(&expected, &capture, 10000, &enabled));
            ASSERT(!enabled);
        }
        PASS();
    }
    TEST("land launcher join: image source and contradictory journal clocks UNKNOWN") {
        const char *markers[] = {"\"executable_sha256\":\"", "\"compiled_source_sha256\":\""};
        for (size_t i = 0; i < 4; ++i) {
            char changed[ZCL_LAND_ATTEST_CAP];
            ASSERT(strlen(wire) < sizeof(changed));
            memcpy(changed, wire, strlen(wire) + 1);
            struct zcl_land_launcher_frame altered = frame;
            struct zcl_land_launcher_capture capture = original;
            capture.frames = &altered;
            if (i < 2) {
                char *at = strstr(changed, markers[i]);
                ASSERT(at != NULL);
                at += strlen(markers[i]);
                *at = '0';
                altered.wire = changed;
            } else {
                altered.journal_at_ms = i == 2 ? 9999 : 10001;
            }
            bool enabled = true;
            ASSERT(!zcl_dev_land_launcher_join(&expected, &capture, 10001, &enabled));
            ASSERT(!enabled);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static bool dlx_hold_field_replace(const char *replacement)
{
    char body[16384], changed[16384], land[1200], path[1400];
    size_t len = 0;
    if (!dlx_queue_bytes(body, sizeof(body), &len)) return false;
    char *field = strstr(body, ",\"publication_hold\":");
    char *end = field ? strchr(field, '}') : NULL;
    if (!end) return false;
    int n = snprintf(changed, sizeof(changed), "%.*s%s%s",
                     (int)(field - body), body, replacement, end);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    return n > 0 && (size_t)n < sizeof(changed) && dlx_write(path, changed);
}

static int dlx_hold_legacy_case(void)
{
    int failures = 0;
    TEST("land: a legacy row without publication_hold retains normal publication") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64];
        dlx_isolate("hold_legacy");
        ASSERT(dlx_rig_make(&rig, "hold_legacy_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_hold_field_replace(""));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        /* Also remove the field from the reopened in-flight row. */
        ASSERT(dlx_hold_field_replace(""));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed"); dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(before, after) != 0);
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

/* Change the native fixture's one empty pushed-tip field, without adding
 * a duplicate key or changing any publication/signature field. */
static bool dlx_hold_pushed_fixture(const char *tip)
{
    static const char empty[] = "\"tip_pushed\":\"\"";
    char body[16384], changed[16384], land[1200], path[1400];
    size_t len = 0;
    if (!dlx_queue_bytes(body, sizeof(body), &len)) return false;
    char *field = strstr(body, empty);
    if (!field || strstr(field + sizeof(empty) - 1, "\"tip_pushed\":")) return false;
    int n = snprintf(changed, sizeof(changed), "%.*s\"tip_pushed\":\"%s\"%s",
                     (int)(field - body), body, tip,
                     field + sizeof(empty) - 1);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    return n > 0 && (size_t)n < sizeof(changed) && dlx_write(path, changed);
}

static int dlx_hold_pushed_case(void)
{
    int failures = 0;
    TEST("land: held row with a pushed tip refuses as contradictory without effects") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[16384], after[16384], origin[64], current[64];
        size_t first = 0, second = 0;
        dlx_isolate("hold_pushed");
        ASSERT(dlx_rig_make(&rig, "hold_pushed_rig"));
        ASSERT(dlx_origin_main(&rig, origin));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_hold_field_replace(",\"publication_hold\":true"));
        ASSERT(dlx_hold_pushed_fixture(rig.tip));
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        ASSERT(strstr(before, "\"phase\":\"\"") != NULL);
        ASSERT(strstr(before, "\"publication_signature\":\"\"") != NULL);
        ASSERT(strstr(before, "\"publication_bundle\":\"\"") != NULL);
        ASSERT(strstr(before, "\"push_diagnostic_pending\":0") != NULL);
        ASSERT(strstr(before, "\"fence_peer\":0") != NULL);
        const char *actions[] = {"status", "step", "hold", "release"};
        for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
            dlx_begin(&c, actions[i]);
            if (i >= 2) (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
            ASSERT(dlx_origin_main(&rig, current));
            ASSERT_STR_EQ(origin, current);
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

static int dlx_hold_malformed_case(void)
{
    int failures = 0;
    TEST("land: malformed or duplicate hold refuses without rewriting the queue") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[16384], after[16384], origin[64], current[64];
        size_t first = 0, second = 0;
        dlx_isolate("hold_malformed");
        ASSERT(dlx_rig_make(&rig, "hold_malformed_rig"));
        ASSERT(dlx_origin_main(&rig, origin));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        const char *bad[] = {",\"publication_hold\":\"true\"", ",\"publication_hold\":1",
            ",\"publication_hold\":null", ",\"publication_hold\":true,\"publication_hold\":false",
            ",\"publication_hold\":true,\"publication_hold\":true",
            ",\"publication_hold\":true,\"\\u0070ublication_hold\":true"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(dlx_hold_field_replace(bad[i]));
            ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
            ASSERT(dlx_origin_main(&rig, current));
            ASSERT_STR_EQ(origin, current);
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

static int dlx_hold_sealed_case(void)
{
    int failures = 0;
    TEST("land: hold and release refuse sealed and unknown sequences without changing bytes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], current[64], before[16384], after[16384];
        size_t first = 0, second = 0;
        dlx_isolate("hold_sealed");
        ASSERT(dlx_attach_proven_pair(&rig, "hold_sealed", base));
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        const char *actions[] = {"hold", "release"};
        for (size_t i = 0; i < 2; i++) {
            for (long long seq = 1; seq <= 2; seq++) {
                dlx_begin(&c, actions[i]);
                (void)json_push_kv_int(&c.input, "seq", seq);
                ASSERT(dlx_run(&c) && !dlx_ok(&c));
                ASSERT_STR_EQ(c.reply.error.code, seq == 1 ? "PUBLICATION_ALREADY_SEALED" : "UNKNOWN_SEQUENCE");
                dlx_end(&c);
                ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
                ASSERT(first == second && memcmp(before, after, first) == 0);
                ASSERT(dlx_origin_main(&rig, current));
                ASSERT_STR_EQ(current, base);
            }
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

static int dlx_hold_lock_case(void)
{
    int failures = 0;
    int lock = -1;
    TEST("land: hold and release serialize against the native step slot") {
        struct dlx_rig rig;
        struct dlx_call c;
        char land[1200], before[16384], after[16384];
        size_t first = 0, second = 0;
        dlx_isolate("hold_lock");
        ASSERT(dlx_rig_make(&rig, "hold_lock_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        const char *actions[] = {"hold", "release"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, actions[i]);
            (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "STEP_BUSY"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
        }
        PASS();
    }
_test_next:
    if (lock >= 0) { (void)flock(lock, LOCK_UN); (void)close(lock); }
    dlx_restore();
    return failures;
}

static int dlx_publication_hold_cases(void)
{
    int failures = 0;
    TEST("land: retained hold permits proof but refuses step/drive publication; release restores flow") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], landed[64];
        dlx_isolate("publication_hold");
        ASSERT(dlx_rig_make(&rig, "publication_hold_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get_bool(json_get(&c.reply.data, "publication_hold")));
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *queued = dlx_arr(&c, "queued");
        ASSERT(queued && queued->num_children == 1);
        ASSERT(json_get_bool(json_get(&queued->children[0], "publication_hold")));
        ASSERT(strstr(dlx_str(&c, "screen"), "publication HELD") != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        const char *beats[] = {"step", "drive"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, beats[i]);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT(strcmp(c.reply.error.code, "PUBLICATION_HELD") == 0);
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, after));
            ASSERT(strcmp(before, after) == 0);
        }
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT(json_get_bool(json_get(flight, "publication_hold")));
        ASSERT(strstr(dlx_str(&c, "screen"), "publication HELD") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "outcomes")->num_children, 0);
        dlx_end(&c);
        const char *attachments[] = {"attach", "attach_publish"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, attachments[i]);
            (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT(strcmp(c.reply.error.code, "PUBLICATION_HELD") == 0);
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, after));
            ASSERT(strcmp(before, after) == 0);
        }
        dlx_begin(&c, "release");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(!json_get_bool(json_get(&c.reply.data, "publication_hold")));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        (void)snprintf(landed, sizeof(landed), "%s", dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, landed) == 0 && strcmp(after, before) != 0);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT(strcmp(c.reply.error.code, "UNKNOWN_SEQUENCE") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

/* Reopen an otherwise-valid failed outcome through the actual native reader. */
static bool dlx_outcome_detail_matches(struct dlx_call *c, const char *expected)
{
    const struct json_value *outcomes = dlx_arr(c, "outcomes");
    if (!outcomes || outcomes->num_children != 1) return false;
    const char *observed = json_get_str(json_get(&outcomes->children[0], "detail"));
    return observed && strcmp(expected, observed) == 0;
}

static bool dlx_outcome_detail_wire(const char *wire, const char *expected)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char land[1200], queue[1400], outcome[1400], body[16384], changed[16384];
    size_t length = 0;
    dlx_isolate("escaped_outcome");
    bool ok = dlx_rig_make(&rig, "escaped_outcome_rig");
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (!ok) goto done;
    dlx_submit(&c, &rig, rig.tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || !dlx_queue_bytes(body, sizeof(body), &length)) {
        ok = false;
        goto done;
    }
    char *state = strstr(body, "\"state\":\"queued\"");
    char *field = strstr(body, "\"detail\":\"\"");
    if (!state || !field) { ok = false; goto done; }
    memcpy(state + strlen("\"state\":\""), "failed", 6);
    int n = snprintf(changed, sizeof(changed), "%.*s\"detail\":%s%s",
                     (int)(field - body), body, wire,
                     field + strlen("\"detail\":\"\""));
    dlx_landdir(land, sizeof(land));
    (void)snprintf(queue, sizeof(queue), "%s/queue.jsonl", land);
    (void)snprintf(outcome, sizeof(outcome), "%s/outcomes.jsonl", land);
    ok = n > 0 && (size_t)n < sizeof(changed) &&
         dlx_write(outcome, changed) && dlx_write(queue, "");
    if (!ok) goto done;
    dlx_begin(&c, "status");
    ok = dlx_run(&c) && dlx_ok(&c) && dlx_outcome_detail_matches(&c, expected);
    dlx_end(&c);
done:
    dlx_restore();
    return ok;
}

static int dlx_outcome_escape_cases(void)
{
    int failures = 0;
    TEST("land: status reopens escaped outcome diagnostics with exact identity") {
        const char *wire[] = {
            "\"repair\\ncommand\\tpath\\u0001suffix\"",
            "\"carriage\\rback\\bform\\f\"",
            "\"quote\\\"slash\\\\solidus\\/\"",
            "\"\\u00e9\\uD83D\\uDE00\"",
            "\"\""
        };
        const char *expected[] = {
            "repair\ncommand\tpath\001suffix",
            "carriage\rback\bform\f",
            "quote\"slash\\solidus/",
            "\xc3\xa9\xf0\x9f\x98\x80",
            ""
        };
        for (size_t i = 0; i < sizeof(wire) / sizeof(wire[0]); i++)
            ASSERT(dlx_outcome_detail_wire(wire[i], expected[i]));
        PASS();
    } _test_next:;
    return failures;
}

/* Independent review witnesses, one TEST per case: an early failure must not
 * hide the other baseline failures. These touch only private native rigs. */
static int dlx_string_refusal_case(unsigned index, const char *label,
                                  const char *needle, const char *replacement)
{
    int failures = 0;
    TEST(label) {
        struct dlx_rig rig; struct dlx_call c;
        char tag[64], rig_tag[64], land[1200], queue[1400], original[16384];
        char changed[16384], after[16384], base[80], remote[80];
        size_t length = 0, after_length = 0;
        ASSERT(snprintf(tag, sizeof(tag), "string_refusal_%u", index) < (int)sizeof(tag));
        dlx_isolate(tag);
        ASSERT(snprintf(rig_tag, sizeof(rig_tag), "string_refusal_rig_%u", index) < (int)sizeof(rig_tag));
        ASSERT(dlx_rig_make(&rig, rig_tag));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(original, sizeof(original), &length));
        dlx_landdir(land, sizeof(land));
        ASSERT(snprintf(queue, sizeof(queue), "%s/queue.jsonl", land) < (int)sizeof(queue));
        char *field = strstr(original, needle);
        ASSERT(field != NULL);
        int n = snprintf(changed, sizeof(changed), "%.*s%s%s",
            (int)(field - original), original, replacement, field + strlen(needle));
        ASSERT(n > 0 && (size_t)n < sizeof(changed));
        ASSERT(dlx_write(queue, changed));
        const char *actions[] = { "status", "submit", "step" };
        for (size_t j = 0; j < sizeof(actions) / sizeof(actions[0]); j++) {
            if (j == 1) dlx_submit(&c, &rig, rig.tip);
            else dlx_begin(&c, actions[j]);
            ASSERT(dlx_run(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
            ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
            dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &after_length));
            ASSERT(after_length == (size_t)n && memcmp(after, changed, after_length) == 0);
        }
        ASSERT(dlx_origin_main(&rig, remote)); ASSERT_STR_EQ(remote, base);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_optional_string_refusal_cases(void)
{
    static const struct { const char *label, *needle, *replacement; } cases[] = {
        { "land: single oversized phase refuses", "\"phase\":\"\"", "\"phase\":\"0123456789abcdef\"" },
        { "land: duplicate null phase refuses", "\"phase\":\"\"", "\"phase\":null,\"phase\":\"push\"" },
        { "land: nested phase refuses", "\"phase\":\"\"", "\"extra\":{\"phase\":\"push\"}" },
        { "land: wrong-type and nested phase refuse", "\"phase\":\"\"", "\"phase\":{},\"extra\":{\"phase\":\"push\"}" },
        { "land: unique oversized base refuses", "\"base\":\"\"", "\"base\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"" },
        { "land: displaced publication signature refuses", "\"phase\":\"\"", "\"phase\":\"\",\"extra\":{\"publication_signature\":\"aa\"}" },
        { "land: duplicate null detail refuses", "\"detail\":\"\"", "\"detail\":null,\"detail\":\"repair\"" },
        { "land: unique null phase refuses", "\"phase\":\"\"", "\"phase\":null" },
        { "land: decoded-equivalent duplicate keys refuse", "\"phase\":\"\"", "\"phase\":\"\",\"ph\\u0061se\":\"push\"" }
    };
    int failures = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += dlx_string_refusal_case(i, cases[i].label, cases[i].needle, cases[i].replacement);
    return failures;
}

/* Exercise the native serializer, not a parallel wire encoder. */
extern bool zcl_native_dev_land_test_encode_detail(const char *, bool, char *, size_t);

static bool dlx_native_detail_matches(struct dlx_call *c, const char *detail,
                                      bool terminal)
{
    const struct json_value *rows = dlx_arr(c, terminal ? "outcomes" : "queued");
    if (!rows || rows->num_children != 1) return false;
    if (!terminal) return true; /* Real row reader checked detail in the seam. */
    const char *observed = json_get_str(json_get(&rows->children[0], "detail"));
    return observed && strcmp(observed, detail) == 0;
}

static bool dlx_native_detail_roundtrip(const char *detail, bool terminal)
{
    struct dlx_call c;
    char land[1200], path[1400], body[16384];
    dlx_isolate("native_detail_boundary");
    dlx_landdir(land, sizeof(land));
    bool ok = dlx_mkdir_p(land) &&
        zcl_native_dev_land_test_encode_detail(detail, terminal, body, sizeof(body));
    int n = snprintf(path, sizeof(path), "%s/%s.jsonl", land,
                     terminal ? "outcomes" : "queue");
    ok = ok && n > 0 && (size_t)n < sizeof(path) && dlx_write(path, body);
    if (ok) {
        dlx_begin(&c, "status");
        ok = dlx_run(&c) && dlx_ok(&c);
        ok = ok && dlx_native_detail_matches(&c, detail, terminal);
        dlx_end(&c);
    }
    dlx_restore();
    return ok;
}

static int dlx_native_detail_boundary_case(unsigned kind)
{
    int failures = 0;
    TEST("land: maximum native detail survives queue and outcome decoding") {
        char detail[1024];
        for (size_t i = 0; i < sizeof(detail) - 1; i++)
            detail[i] = kind == 0 ? 'a' : kind == 1 ? '\001' :
                i == 1022 ? 'x' : i % 2 == 0 ? (char)0xc3 : (char)0xa9;
        detail[1023] = '\0';
        ASSERT(dlx_native_detail_roundtrip(detail, false));
        ASSERT(dlx_native_detail_roundtrip(detail, true));
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_extended_native_row(char *body, size_t cap, unsigned members)
{
    char native[16384];
    if (!zcl_native_dev_land_test_encode_detail("", false, native, sizeof(native)))
        return false;
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, native, strlen(native)) && doc.type == JSON_OBJ &&
              doc.num_children == 35;
    json_free(&doc);
    char *end = strrchr(native, '}');
    if (!ok || !end || members < 35) return false;
    size_t used = (size_t)(end - native);
    if (used >= cap) return false;
    memcpy(body, native, used);
    for (unsigned i = 35; i < members; i++) {
        int n = snprintf(body + used, cap - used, ",\"extension_%u\":0", i);
        if (n <= 0 || (size_t)n >= cap - used) return false;
        used += (size_t)n;
    }
    if (cap - used < 3) return false;
    memcpy(body + used, "}\n", 3);
    return true;
}

static int dlx_row_member_boundary_case(unsigned members, bool accepted)
{
    int failures = 0;
    TEST("land: row member bound accepts 64 and refuses larger inventories") {
        char body[100000], after[100000], land[1200], path[1400];
        size_t after_length = 0;
        struct dlx_call c;
        dlx_isolate("member_boundary");
        dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_extended_native_row(body, sizeof(body), members));
        ASSERT(dlx_write(path, body));
        dlx_begin(&c, "status"); ASSERT(dlx_run(&c));
        if (accepted) ASSERT(dlx_ok(&c));
        else ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_length));
        ASSERT(after_length == strlen(body) && memcmp(after, body, after_length) == 0);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_absent_optional_case(void)
{
    int failures = 0;
    TEST("land: absent optional fields remain valid legacy row fields") {
        struct dlx_call c;
        char land[1200], path[1400];
        dlx_isolate("absent_optional"); dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_write(path, "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                              "\"state\":\"queued\",\"attempt\":1}\n"));
        dlx_begin(&c, "status"); ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *rows = dlx_arr(&c, "queued");
        ASSERT(rows && rows->num_children == 1);
        dlx_end(&c); PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_string_compatibility_cases(void)
{
    int failures = dlx_absent_optional_case();
    for (unsigned i = 0; i < 3; i++) failures += dlx_native_detail_boundary_case(i);
    failures += dlx_row_member_boundary_case(64, true);
    failures += dlx_row_member_boundary_case(65, false);
    failures += dlx_row_member_boundary_case(4096, false);
    return failures;
}
static int dlx_case_registration(void)
{
    int failures = 0;
    TEST("land: the leaf is registered with its verb and row keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DLX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "action") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "tip") != NULL);
        ASSERT(spec->input_keys &&
               strstr(spec->input_keys, "worktree") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "note") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "seq") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "json") != NULL);
        ASSERT(spec->positional_keys &&
               strstr(spec->positional_keys, "action") != NULL);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_unknown_action(void)
{
    int failures = 0;
    TEST("land: an unknown action and a missing one are refused") {
        struct dlx_call c;
        dlx_isolate("route");
        dlx_begin(&c, "launch");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, NULL);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#if !defined(_WIN32)

static int dlx_case_unsigned_tip(void)
{
    int failures = 0;
    TEST("land: submit refuses an unsigned tip and an unknown one") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("refuse");
        ASSERT(dlx_rig_make(&rig, "refuse_rig"));
        /* The fixture commits are --no-gpg-sign, so this IS the unsigned
         * case, and the bypass is not set. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* A commit id nobody can resolve. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, "0123456789abcdef0123456789abcdef01234567");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Not a commit id at all. */
        dlx_submit(&c, &rig, "main");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Nothing was stored by any of the three. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(dlx_arr(&c, "queued") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_checkout_location(void)
{
    int failures = 0;
    TEST("land: queue survives outside HOME from checkout and nested cwd") {
        ASSERT(dlx_queue_outside_home_child());
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_submit_status(void)
{
    int failures = 0;
    TEST("land: submit queues the tip and status lists it, without waiting") {
        struct dlx_rig rig;
        struct dlx_call c;
        const struct json_value *rows;
        char full[64];
        time_t t0, t1;
        dlx_isolate("queue");
        ASSERT(dlx_rig_make(&rig, "queue_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        (void)snprintf(full, sizeof(full), "%s", rig.tip);
        t0 = time(NULL);
        dlx_submit(&c, &rig, full);
        (void)json_push_kv_str(&c.input, "note", "the first landing");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 1);
        ASSERT(strcmp(dlx_str(&c, "state"), "queued") == 0);
        ASSERT(strcmp(dlx_str(&c, "tip"), full) == 0);
        dlx_end(&c);
        t1 = time(NULL);
        /* Submit is a file append. It cannot have proved anything. */
        ASSERT((long long)(t1 - t0) < 20);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        rows = dlx_arr(&c, "queued");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        ASSERT(json_get_str(json_get(&rows->children[0], "tip")) &&
               strcmp(json_get_str(json_get(&rows->children[0], "tip")),
                      full) == 0);
        /* Nothing is in flight before a step runs. */
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_duplicate_submit(void)
{
    int failures = 0;
    TEST("land: retrying the exact tip in one checkout attaches to its live row") {
        ASSERT(dlx_exact_submit_retry());
        ASSERT(dlx_exact_submit_mid_rebase_refused());
        ASSERT(dlx_submit_operation_markers_refused());
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_empty_step(void)
{
    int failures = 0;
    TEST("land: a step over an empty queue is a no-op that returns at once") {
        struct dlx_call c;
        time_t t0, t1;
        dlx_isolate("empty");
        t0 = time(NULL);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        t1 = time(NULL);
        ASSERT((long long)(t1 - t0) < 10);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_step_lock(void)
{
    int failures = 0;
    TEST("land: a step finds its own lock already held and says STEP_BUSY, "
        "retryable, touching nothing; released, it proceeds") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200];
        char qpath[1400];
        char before[4096], after[4096];
        size_t before_len = 0, after_len = 0;
        int lockfd;

        dlx_isolate("stepbusy");
        ASSERT(dlx_rig_make(&rig, "stepbusy_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);

        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir);
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));

        /* Take the same step.lock dev.land's own dl_step_lock() takes,
         * through the identical open+flock(LOCK_EX|LOCK_NB) discipline. */
        lockfd = dlx_step_lock_take(landdir);
        ASSERT(lockfd >= 0);

        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT(strcmp(dlx_err_code(&c), "STEP_BUSY") == 0);
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "queue=") != NULL);
        {
#if defined(__linux__)
            char want[48];
            (void)snprintf(want, sizeof(want), "holder_pid=%d ",
                           (int)getpid());
            ASSERT(strstr(dlx_err_evidence(&c), want) != NULL);
#else
            /* The holder is read from /proc/locks, which only Linux has. */
            ASSERT(strstr(dlx_err_evidence(&c), "holder_pid=unknown") != NULL);
#endif
        }
        ASSERT(strstr(dlx_err_evidence(&c), landdir) != NULL);
        dlx_end(&c);

        /* Untouched: the queued row is still queued, never rebased. */
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT_EQ((long long)before_len, (long long)after_len);
        ASSERT(memcmp(before, after, before_len) == 0);

        /* Released, a step proceeds exactly as it would have. */
        dlx_step_lock_release(lockfd);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);

        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_starts_proof(void)
{
    int failures = 0;
    TEST("land: the step that asks for a proof returns before it finishes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], logpath[1400];
        dlx_isolate("start");
        ASSERT(dlx_rig_make(&rig, "start_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Asked for, not answered: the request is in flight and the verb
         * came back. A step that waited would still be inside the proof. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strcmp(dlx_str(&c, "phase"), "prove") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A second step while the proof is still pending changes nothing
         * and still returns. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        dlx_end(&c);
        /* The private landing worktree was created once and reused. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/wt/.git", landdir);
        ASSERT(dlx_file_exists(logpath));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_absent_watcher(void)
{
    int failures = 0;
    TEST("land: an absent resident watcher is named, twice, not hidden") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("watcher_absent");
        ASSERT(dlx_rig_make(&rig, "watcher_absent_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "watcher_absent", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strcmp(dlx_str(&c, "detail"),
                      "resident_proof_watcher_absent") == 0);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        ASSERT(strcmp(dlx_str(&c, "detail"),
                      "resident_proof_watcher_absent") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_unarmed_proof(void)
{
    int failures = 0;
    TEST("land: an unarmed proof has an exact worker-stealable step") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("manual_proof");
        ASSERT(dlx_rig_make(&rig, "manual_proof_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "manual", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "phase"), "prove") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "dev proof step") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), rig.tip) != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "dev proof step") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_stub_detail(void)
{
    int failures = 0;
    TEST("land: an unrelated stub value still reports its own detail") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("stub_running");
        ASSERT(dlx_rig_make(&rig, "stub_running_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "detail"), "proof stub: running") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_lands_proof(void)
{
    int failures = 0;
    TEST("land: a passing proof fast-forwards the real origin and lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], local[64];
        const struct json_value *outcomes;
        dlx_isolate("land");
        ASSERT(dlx_rig_make(&rig, "land_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The proof answers between steps, exactly as the real one does. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        (void)snprintf(local, sizeof(local), "%s", dlx_str(&c, "tip_pushed"));
        ASSERT(strlen(local) == 40);
        dlx_end(&c);
        /* The bare origin moved, and to exactly the commit that was proved. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT(strcmp(after, local) == 0);
        /* The outcome is durable and the queue is empty again. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "landed") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_hook_refusal(void)
{
    int failures = 0;
    TEST("land: pushes through the pre-push hook — a refusing hook wins") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hooks_dir[1024];
        bool done = false;
        int i;
        dlx_isolate("hookguard");
        ASSERT(dlx_rig_make(&rig, "hookguard_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        /* Arm a REAL pre-push hook in the landing worktree that always
         * refuses. dev.land no longer pushes with --no-verify (the fleet
         * rule this whole change exists to satisfy), so if that hook is
         * genuinely consulted the land can never succeed no matter how
         * many times the (stubbed) proof passes — proving the removal is
         * real and not merely cosmetic. */
        ASSERT(dlx_hooks_dir(hooks_dir, sizeof(hooks_dir), "hookguard_hooks",
                             1));
        setenv("ZCL_LAND_HOOKS_STUB_DIR", hooks_dir, 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        for (i = 0; i < 16 && !done; i++) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            if (strcmp(dlx_str(&c, "state"), "failed") == 0) {
                ASSERT(strcmp(dlx_str(&c, "dimension"), "push") == 0);
                done = true;
            }
            dlx_end(&c);
        }
        ASSERT(done);
        /* The refusing hook actually stopped it: the bare origin never
         * moved. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_proof_failure(void)
{
    int failures = 0;
    TEST("land: a failing proof records the dimension and a log path") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], logpath[4200];
        const struct json_value *outcomes;
        dlx_isolate("fail");
        ASSERT(dlx_rig_make(&rig, "fail_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *inflight = json_get(&c.reply.data, "in_flight");
        ASSERT(inflight != NULL);
        /* The published outcome must not mistake a passing gate's name
         * for the proof failure, even when it precedes the failure log. */
        char landdir[1200];
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log", landdir);
        ASSERT(dlx_write(logpath, "  PASS check-pipefail-status-pipe 5977 ms\n"));
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
        ASSERT_STR_EQ(dlx_str(&c, "detail"), "proof stub: fail");
        (void)snprintf(logpath, sizeof(logpath), "%s", dlx_str(&c,
                                                               "log_path"));
        ASSERT(logpath[0] != '\0');
        ASSERT(dlx_file_exists(logpath));
        dlx_end(&c);
        /* A red proof pushes nothing. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "failed") == 0);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "log_path")) &&
               json_get_str(json_get(&outcomes->children[0],
                                     "log_path"))[0] != '\0');
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_timing_detail(void)
{
    int failures = 0;
    TEST("land: a lint timing-table row never becomes a proof failure detail") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], logpath[4200];
        dlx_isolate("timingrow");
        ASSERT(dlx_rig_make(&rig, "timingrow_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        /* Plant the lint slowest-gates summary row in the attempt log: it
         * names gates with no PASS prefix, so a gate with "fail" in its
         * name matches the triage needles. The recorded outcome must
         * still name the proof's own typed failure, never that timing
         * row. */
        char landdir[1200];
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log", landdir);
        ASSERT(dlx_write(logpath,
                         "  slowest gates:\n    5977 ms  check-pipefail-status-pipe\n"));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
        ASSERT_STR_EQ(dlx_str(&c, "detail"), "proof stub: fail");
        dlx_end(&c);
        /* A red proof pushes nothing. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_moved_base(void)
{
    int failures = 0;
    TEST("land: a base that moved while proving re-rebases, never lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char stranger[64], main_now[64];
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600];
        dlx_isolate("moved");
        ASSERT(dlx_rig_make(&rig, "moved_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* A STRANGER lands on main while this request is proving. */
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        ASSERT(dlx_git(side, branch) == 0);
        ASSERT(dlx_commit(side, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(side, push) == 0);
        ASSERT(dlx_git(side, back) == 0);
        ASSERT(dlx_git(side, fetch) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* The receipt is about a base nobody is on. It rebases instead. */
        ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        /* main is still the stranger's commit: nothing was landed on a
         * stale receipt. */
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT(strcmp(main_now, stranger) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_cancel_request(void)
{
    int failures = 0;
    TEST("land: cancel drops one request by sequence number") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("cancel");
        ASSERT(dlx_rig_make(&rig, "cancel_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        /* A sequence number nobody submitted is refused, not invented. */
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 99);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "cancelled") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A cancelled request is a step's no-op, not a landing. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static size_t dlx_case_trim_row(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    return len;
}

static int dlx_case_concurrent_submit(void)
{
    int failures = 0;
    TEST("land: two concurrent exact submitters attach one complete row") {
        struct dlx_rig rig;
        char landdir[1200], qf[1400], line[8192];
        pid_t a, b;
        int sa = 0, sb = 0, nlines = 0;
        FILE *f;
        dlx_isolate("fork");
        ASSERT(dlx_rig_make(&rig, "fork_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        a = fork();
        ASSERT(a >= 0);
        if (a == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        b = fork();
        ASSERT(b >= 0);
        if (b == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)json_push_kv_str(&c.input, "note", "second");
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        while (waitpid(a, &sa, 0) < 0)
            ;
        while (waitpid(b, &sb, 0) < 0)
            ;
        ASSERT(WIFEXITED(sa) && WEXITSTATUS(sa) == 0);
        ASSERT(WIFEXITED(sb) && WEXITSTATUS(sb) == 0);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qf, sizeof(qf), "%s/queue.jsonl", landdir);
        f = fopen(qf, "r");
        ASSERT(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = dlx_case_trim_row(line);
                if (len == 0)
                    continue;
                nlines++;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                json_free(&v);
            }
            (void)fclose(f);
        }
        ASSERT_EQ((long long)nlines, 1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_dense_detail(void)
{
    int failures = 0;
    TEST("land: a control-byte-dense detail persists instead of "
        "un-committing the row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char stub[300], detail[300];
        size_t i;
        dlx_isolate("ctrlbytes");
        ASSERT(dlx_rig_make(&rig, "ctrlbytes_rig"));
        /* Dense control bytes, no NUL: dl_escape() would need to expand
         * every one of these into a 6-byte "\u00XX" sequence. Before
         * e_detail was sized for detail's true worst case, a value this
         * dense made dl_encode_row refuse and the "started" commit never
         * reached queue.jsonl at all — the reply would still have to
         * report something, but the row would never be durably marked
         * in flight. */
        for (i = 0; i < sizeof(stub) - 1; i++)
            stub[i] = (char)(1 + (i % 30)); /* 0x01..0x1e, never '\0' */
        stub[sizeof(stub) - 1] = '\0';
        setenv("ZCL_LAND_PROOF_STUB", stub, 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Committed for real, not silently dropped: the reply is the
         * normal "started" with no persist failure. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(dlx_str(&c, "persist")[0] == '\0');
        (void)snprintf(detail, sizeof(detail), "%s", dlx_str(&c, "detail"));
        dlx_end(&c);
        /* A second step reads the row back from queue.jsonl: the round
         * trip through dl_encode_row/dl_escape and back through
         * dl_parse_row survived. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_missing_hook(void)
{
    int failures = 0;
    TEST("land: a hooksPath naming no real pre-push cannot skip admission") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], mid[64], after[64], landdir[1200], wt[1400];
        char badhooks[1200], second[64];
        const char *cfg[4];
        dlx_isolate("hookslie");
        ASSERT(dlx_rig_make(&rig, "hookslie_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Land a first row all the way through: this creates the landing
         * worktree and arms it with the (test-only) good hook stub, and
         * frees dl_step's picker — it always prefers an inflight row, so
         * the second row below is only ever picked once nothing is
         * inflight any more. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, mid));
        ASSERT(strcmp(mid, before) != 0);
        /* Corrupt the landing worktree's own hooksPath to a directory
         * that carries no real, executable pre-push. Before this fix,
         * dl_wt_hooks_ready() treated any NONEMPTY core.hooksPath as
         * proof enough and never looked at the file it named. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(wt, sizeof(wt), "%s/wt", landdir);
        test_make_tmpdir(badhooks, sizeof(badhooks), "dev_land_badhooks",
                         "hookslie_bad");
        cfg[0] = "config"; cfg[1] = "--worktree"; cfg[2] = "core.hooksPath";
        cfg[3] = badhooks;
        {
            const char *args[] = { cfg[0], cfg[1], cfg[2], cfg[3], NULL };
            ASSERT(dlx_git(wt, args) == 0);
        }
        /* A second, independent tip. No test hook stub this time: a real
         * worktree with no Makefile to run `make install-hooks` in must
         * refuse the request rather than accept the broken config as
         * already armed and push straight through it. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        unsetenv("ZCL_LAND_HOOKS_STUB_DIR");
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree") == 0);
        dlx_end(&c);
        /* No second push happened: the broken hook config never got a
         * chance to wave one through. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, mid) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_cancel_race(void)
{
    int failures = 0;
    TEST("land: a cancel that beats a landing records exactly one outcome") {
        struct dlx_rig rig;
        struct dlx_call c, cancelc;
        char landdir[1200], opath[1400], line[8192];
        pid_t child;
        int st = 0;
        long long ntotal = 0, nlanded = 0, ncancelled = 0;
        FILE *f;
        dlx_isolate("racecancel");
        ASSERT(dlx_rig_make(&rig, "racecancel_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        /* ZCL_LAND_TEST_PICK_DELAY_MS makes the race deterministic: the
         * child pauses right after dl_step() picks this row (under the
         * slot lock only) and before it drives the pushing/committing
         * work below — exactly the published race window ("step loads
         * rows under only the slot lock, cancel deletes under the row
         * lock"). The parent's cancel (one flock and one small rewrite)
         * easily finishes inside that window. Whichever side had won
         * without the delay, exactly one outcome for this seq may ever
         * land in outcomes.jsonl — a cancelled row must never ALSO get a
         * second, later outcome appended on top of cancel's own. */
        setenv("ZCL_LAND_TEST_PICK_DELAY_MS", "200", 1);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(0);
        }
        /* Give the child time to run its own picker (dl_step reads the
         * queue under only the slot lock) before this cancel takes the
         * row lock and deletes — the published race window. Without this
         * the fork/schedule overhead alone lets cancel finish before the
         * child is even scheduled, which would race nothing. 30ms is
         * comfortably inside the child's own 200ms post-pick delay
         * (ZCL_LAND_TEST_PICK_DELAY_MS) below. */
        {
            struct timespec ts = { 0, 30 * 1000 * 1000L };
            (void)nanosleep(&ts, NULL);
        }
        dlx_begin(&cancelc, "cancel");
        (void)json_push_kv_int(&cancelc.input, "seq", 1);
        ASSERT(dlx_run(&cancelc));
        ASSERT(dlx_ok(&cancelc));
        ASSERT(strcmp(dlx_str(&cancelc, "state"), "cancelled") == 0);
        dlx_end(&cancelc);
        while (waitpid(child, &st, 0) < 0)
            ;
        ASSERT(WIFEXITED(st));
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir);
        f = fopen(opath, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = dlx_case_trim_row(line);
                const struct json_value *seqv, *statev;
                if (len == 0)
                    continue;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                seqv = json_get(&v, "seq");
                statev = json_get(&v, "state");
                if (seqv && seqv->type == JSON_INT && json_get_int(seqv) == 1) {
                    ntotal++;
                    if (statev && statev->type == JSON_STR) {
                        if (strcmp(json_get_str(statev), "landed") == 0)
                            nlanded++;
                        if (strcmp(json_get_str(statev), "cancelled") == 0)
                            ncancelled++;
                    }
                }
                json_free(&v);
            }
            (void)fclose(f);
        }
        /* Cancel won (guaranteed by the delay): exactly its own outcome,
         * never a second "landed" row appended after the fact. */
        ASSERT_EQ(ncancelled, 1);
        ASSERT_EQ(nlanded, 0);
        ASSERT_EQ(ntotal, 1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_aged_successor(void)
{
    int failures = 0;
    TEST("land: moving main keeps the aged successor ahead of newer work") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64], following[64], original_ts[64];
        bool done = false;
        int i;
        dlx_isolate("moveforever");
        ASSERT(dlx_rig_make(&rig, "moveforever_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "following.txt", "following\n",
                          following));
        dlx_submit(&c, &rig, following);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        ASSERT(dlx_priority_snapshot(&c, original_ts));
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        /* Every cycle: rebase onto the current tip and ask for the proof
         * ("started"), then a stranger lands on main again before the
         * next step reads the answer, so the receipt is always about a
         * base nobody is on. Before DL_ATTEMPT_MAX capped this specific
         * retry, one drive session could run forever. The bounded session
         * stops, while the original tip retains its claim priority under
         * the new sequence. */
        for (i = 0; i < 8 && !done; i++) {
            char tag[32];
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
            dlx_end(&c);
            (void)snprintf(tag, sizeof(tag), "s%d.txt", i);
            ASSERT(dlx_git(side, branch) == 0);
            ASSERT(dlx_commit(side, tag, "elsewhere\n", stranger));
            ASSERT(dlx_git(side, push) == 0);
            ASSERT(dlx_git(side, back) == 0);
            ASSERT(dlx_git(side, fetch) == 0);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            if (strcmp(dlx_str(&c, "state"), "queued") == 0) {
                ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
                ASSERT_EQ(dlx_int(&c, "seq"), 3);
                ASSERT(strcmp(dlx_str(&c, "tip"), rig.tip) == 0);
                done = true;
            } else {
                ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
            }
            dlx_end(&c);
        }
        ASSERT(done);
        ASSERT(dlx_priority_successor_status(&c, original_ts));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 3);
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_option_path(void)
{
    int failures = 0;
    TEST("land: a worktree that looks like a git option is refused at "
        "parse, never reaches git") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], mid[64], after[64], landdir[1200], qpath[1400];
        char line[8192], second[64];
        FILE *f;
        dlx_isolate("wtinj");
        ASSERT(dlx_rig_make(&rig, "wtinj_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Land a first row all the way through: this creates the landing
         * worktree, so the crafted row below hits the SAME "fetch the tip
         * from row->worktree" fallback a normal cross-worktree row would
         * (dl_wt_ensure short-circuits on an already-ready d->wt without
         * ever touching row->worktree again), rather than failing earlier
         * for an unrelated reason. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, mid));
        ASSERT(strcmp(mid, before) != 0);
        /* A hand-written row — the shape a foreign write to queue.jsonl
         * can take, never anything dl_submit itself produces — names a git
         * OPTION instead of a path, and a tip nothing here has ever seen.
         * Before the fix this string reached dl_already_landed()'s and
         * dl_rebase()'s fetch calls as a bare positional argument. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir);
        (void)snprintf(
            line, sizeof(line),
            "{\"seq\":99,\"ts\":\"2026-01-01T00:00:00Z\","
            "\"tip\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
            "\"worktree\":\"--upload-pack=/bin/false\",\"note\":\"\","
            "\"state\":\"queued\",\"phase\":\"\",\"attempt\":1,"
            "\"started\":0,\"base\":\"\",\"local\":\"\","
            "\"tip_pushed\":\"\",\"dimension\":\"\",\"log_path\":\"\","
            "\"detail\":\"\"}\n");
        f = fopen(qpath, "a");
        ASSERT(f != NULL);
        if (f) {
            size_t len = strlen(line);
            ASSERT(fwrite(line, 1, len, f) == len);
            ASSERT(fclose(f) == 0);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
        dlx_end(&c);
        /* Explicit fixture repair is required; a step never erases the
         * foreign row just because its path was unsafe. */
        ASSERT(dlx_write(qpath, ""));
        /* A normal, valid absolute worktree still lands: the parser
         * refuses only the shape it must, not every row that follows it. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, mid) != 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_dependency_links(void)
{
    int failures = 0;
    TEST("land: a dependency link whose only extra name sits in the "
        "leaf's own generation pool is repaired, not refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400], gendir[1400], genfile[1400];
        char second[64], exclude[1400];
        struct stat before_st, after_st, gen_st;
        dlx_isolate("gendeplink");
        ASSERT(dlx_rig_make(&rig, "gendeplink_rig"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        /* The landing worktree now owns its own independent copy of
         * vendor/lib/libfoo.a. Simulate the legacy state item A's fix
         * leaves behind: an older binary once linked a proof generation's
         * materialised copy straight from this exact file, so the two
         * still share an inode -- but the OTHER name lives under this
         * leaf's own disk generation pool (<land>/.z23p/<tag>/...), never
         * under a foreign path, so it is this code's own link to explain
         * and repair rather than a stranger's alias to refuse over. */
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a", wt);
        ASSERT(stat(check, &before_st) == 0 && before_st.st_nlink == 1);
        (void)snprintf(gendir, sizeof(gendir),
                       "%s/.z23p/0123456789abcdef0123456789abcdef/vendor/lib",
                       wt);
        ASSERT(dlx_mkdir_p(gendir));
        (void)snprintf(genfile, sizeof(genfile), "%s/libfoo.a", gendir);
        ASSERT(link(check, genfile) == 0);
        ASSERT(stat(check, &before_st) == 0 && before_st.st_nlink == 2);
        /* dlx_commit() runs `git add -A`; without excluding vendor/ and
         * build/ here the untracked dependency fixtures would be staged
         * and committed, and the landing worktree's later checkout of
         * that commit would overwrite `check` with a fresh blob before
         * this repair ever runs -- silently discarding the very hardlink
         * this test exists to exercise. */
        (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude",
                       rig.clone);
        ASSERT(dlx_write(exclude, "vendor/\nbuild/\n"));
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Repaired, not refused: the attempt proceeds past worktree_deps. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        ASSERT(stat(check, &after_st) == 0 && S_ISREG(after_st.st_mode));
        ASSERT(after_st.st_nlink == 1);
        ASSERT(before_st.st_dev != after_st.st_dev ||
              before_st.st_ino != after_st.st_ino);
        /* The generation pool's own copy is untouched: same inode as
         * before, now missing only the landing worktree's name. */
        ASSERT(stat(genfile, &gen_st) == 0 && S_ISREG(gen_st.st_mode));
        ASSERT(gen_st.st_nlink == 1);
        ASSERT(gen_st.st_dev == before_st.st_dev &&
              gen_st.st_ino == before_st.st_ino);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_missing_dependency(void)
{
    int failures = 0;
    TEST("land: a proof-generation dependency missing from the submitting "
        "checkout too refuses by name instead of proceeding") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("depsmissing");
        ASSERT(dlx_rig_make(&rig, "depsmissing_rig"));
        /* No vendor/lib at all in the submitting checkout: the landing
         * worktree cannot materialize what does not exist anywhere, so the
         * step must refuse by name rather than silently proceed to a proof
         * request the real dependencies[] check would only fail later. */
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:vendor/lib")
              != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "make vendor") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_tor_gitlink(void)
{
    int failures = 0;
    TEST("land: vendor/tor as a real submodule gitlink is initialised "
        "before any archive is materialized, and a failed init refuses by "
        "name without ever copying one") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400];
        dlx_isolate("subinitfail");
        ASSERT(dlx_rig_make(&rig, "subinitfail_rig"));
        /* vendor/tor recorded as a real gitlink (mode 160000) in the tip,
         * .gitmodules pointing at a URL nothing can ever clone. The
         * archive itself IS present in the submitting checkout — proving
         * the refusal comes from the failed submodule init, ahead of the
         * archive copy, and not from a missing source file. */
        /* update-index --cacheinfo requires the named object to exist in
         * THIS repo's own object database even for a gitlink (it does not
         * dereference it as a submodule commit) — the tip's own current
         * commit id is a convenient, always-present stand-in. */
        ASSERT(dlx_gitlink_commit(rig.clone, "vendor/tor", rig.tip,
                                  "/no/such/path/does-not-exist.git",
                                  rig.tip));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:vendor/tor")
              != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule init failed") !=
              NULL);
        /* Ordering: the archive that WAS available in the submitting
         * checkout must never have been copied, because the failed
         * submodule init refused before dl_wt_vendor_ensure() ever reached
         * the materialize step for it. */
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(!dlx_file_exists(check));
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_tor_head(void)
{
    int failures = 0;
    TEST("land: a submitting checkout whose vendor/tor HEAD differs from "
        "the tip's pinned gitlink refuses by name, naming both commits, "
        "instead of reusing the stale archive") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char wt[1200], check[1400];
        dlx_isolate("submismatch");
        ASSERT(dlx_rig_make(&rig, "submismatch_rig"));
        ASSERT(dlx_subrepo_make(&sub, "submismatch_sub"));
        /* A real submodule add: the tip's gitlink pins rev_b (the bare
         * repo's HEAD at add time). */
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        /* Now drift the SUBMITTING checkout's own submodule working tree
         * onto rev_a, without touching the superproject's committed
         * gitlink — exactly the staleness dl_wt_vendor_tor_pin_matches()
         * exists to catch: the tip still pins rev_b. */
        ASSERT(dlx_submodule_checkout(rig.clone, "vendor/tor", sub.rev_a));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:"
                      "vendor/tor/libtor.a") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule commit") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), sub.rev_a) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), sub.rev_b) != NULL);
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(!dlx_file_exists(check));
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_hook_drift(void)
{
    int failures = 0;
    TEST("land: a landing worktree whose installed native hooks drifted "
        "from the binary its own lint rebuilt is repaired before the proof "
        "is asked for, and missing hook names are relinked") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1200], bin[1400], installed[1400], link[1400], tip2[64];
        char bin_body[256] = {0}, installed_body[256] = {0};
        dlx_isolate("hooksrefresh");
        ASSERT(dlx_rig_make(&rig, "hooksrefresh_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Row 1 without forcing: the step only creates the landing
         * worktree. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* Land row 1 so the next step takes a fresh row through
         * dl_step_start. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        dlx_landdir(landwt, sizeof(landwt));
        (void)snprintf(landwt + strlen(landwt),
                       sizeof(landwt) - strlen(landwt), "/wt");
        /* The drift this repair exists for: the worktree's freshly linked
         * hook binary no longer matches the installed copy, and two of
         * the four hook names are gone. */
        (void)snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook",
                       landwt);
        (void)snprintf(installed, sizeof(installed),
                       "%s/build/githooks/z23-git-hook", landwt);
        ASSERT(dlx_write_dep(landwt, "build/bin/z23-git-hook",
                             "#!/bin/sh\nrebuilt today\n"));
        (void)snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook",
                       landwt);
        ASSERT(chmod(bin, 0755) == 0);
        ASSERT(dlx_write_dep(landwt, "build/githooks/z23-git-hook",
                             "old hook bytes\n"));
        /* Two of the four hook names are gone — the fixture worktree never
         * had install-hooks run, so at most stray files exist here. */
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-commit", landwt);
        (void)unlink(link);
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-merge", landwt);
        (void)unlink(link);
        /* Row 2 with dependency forcing on: vendor deps present in the
         * submitting checkout, so the step's only obstacle would be an
         * unrepaired hook drift. */
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        ASSERT(dlx_commit(rig.clone, "two.txt", "two\n", tip2));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, tip2);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The installed copy now matches the rebuilt binary byte for
         * byte, and both removed names are links to it again. */
        ASSERT(dlx_slurp(bin, bin_body, sizeof(bin_body), NULL));
        ASSERT(dlx_slurp(installed, installed_body,
                         sizeof(installed_body), NULL));
        ASSERT(strcmp(bin_body, installed_body) == 0);
        ASSERT(strcmp(installed_body, "#!/bin/sh\nrebuilt today\n") == 0);
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-commit", landwt);
        ASSERT(dlx_hook_link(link));
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-merge", landwt);
        ASSERT(dlx_hook_link(link));
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_idle_proof(void)
{
    int failures = 0;
    TEST("land: a queued proof request no worker claims past the idle "
        "bound is named, not read as an ordinary pending") {
        char detail[192];
        /* The 36-hour silent-resident shape in miniature: a pending detail
         * for a request whose age crosses the bound gains the named note,
         * a fresh one does not, and the bound follows its environment
         * override. The judgment is dl_proof_read's; the seam runs exactly
         * that function's helper without forking a resident in a rig. */
        setenv("ZCL_LAND_PROOF_IDLE_SEC", "900", 1);
        (void)snprintf(detail, sizeof(detail), "%s",
                       "resident_proof_request_queued");
        ASSERT(!zcl_native_dev_land_test_idle_note(899, detail,
                                                   sizeof(detail)));
        ASSERT(strcmp(detail, "resident_proof_request_queued") == 0);
        ASSERT(zcl_native_dev_land_test_idle_note(901, detail,
                                                  sizeof(detail)));
        ASSERT(strstr(detail, "resident_proof_request_queued;") != NULL);
        ASSERT(strstr(detail, "proof_request_idle_age_s=901") != NULL);
        ASSERT(strstr(detail, "no worker has claimed") != NULL);
        setenv("ZCL_LAND_PROOF_IDLE_SEC", "1", 1);
        ASSERT(zcl_native_dev_land_test_idle_bound() == 1);
        unsetenv("ZCL_LAND_PROOF_IDLE_SEC");
        ASSERT(zcl_native_dev_land_test_idle_bound() == 900);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_missing_hook_binary(void)
{
    int failures = 0;
    TEST("land: a landing worktree with no rebuilt hook binary at all "
        "fails the step by name instead of asking a proof for hooks it "
        "cannot vouch for") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("hooksmissing");
        ASSERT(dlx_rig_make(&rig, "hooksmissing_rig"));
        /* Neither the landing worktree nor the submitting checkout carries
         * a hook binary: the refresh must refuse by name rather than ask
         * a proof for hooks it cannot vouch for. */
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "landing_worktree_hook_binary_missing") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_quiet_hooks(void)
{
    int failures = 0;
    TEST("land: a step quiets the armed hooks' proof scheduling for its "
        "own transient checkouts, so a rebase's throwaway HEAD can never "
        "enqueue a doomed proof pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char hooks[1200], markdir[1400], marker[1440], script[1500];
        char body[64] = {0}, tip2[64];
        dlx_isolate("hookquiet");
        ASSERT(dlx_rig_make(&rig, "hookquiet_rig"));
        /* A post-checkout hook that records the guard env it inherited.
         * dl_tip_checkout fires it on every step that starts a row, which
         * is exactly the window the guard exists for. */
        test_make_tmpdir(markdir, sizeof(markdir), "dev_land", "hookmark");
        (void)snprintf(marker, sizeof(marker), "%s/marker", markdir);
        (void)snprintf(hooks, sizeof(hooks), "%s/post-checkout",
                       g_dlx_hooks_ok);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf '%%s' \"${ZCL_LAND_HOOK_QUIET:-"
                       "unset}\" > '%s'\n", marker);
        ASSERT(dlx_write(hooks, script));
        ASSERT(chmod(hooks, 0755) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* Row 2 drives another tip checkout through the armed hook. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "two.txt", "two\n", tip2));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, tip2);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The hook ran during the step and saw the guard set to exactly
         * "1". An absent marker means the hook never fired and this case
         * proved nothing; "unset" means the step leaked its transient
         * checkouts to the proof scheduler. */
        /* post-checkout is synchronous inside the step's own git calls, so
         * the marker exists by the time the step replies — assert the
         * outcome directly rather than poll toward a wall-clock deadline
         * (check-no-real-clock-test-deadline exists exactly for this). */
        char fired = dlx_slurp(marker, body, sizeof(body), NULL);
        ASSERT(fired);
        ASSERT(strcmp(body, "1") == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_uninitialised_tor(void)
{
    int failures = 0;
    TEST("land: an uninitialised vendor/tor in the SUBMITTING checkout "
        "refuses by name and by fix, never as a phantom pin mismatch") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char suffix[256];
        dlx_isolate("subuninit");
        ASSERT(dlx_rig_make(&rig, "subuninit_rig"));
        ASSERT(dlx_subrepo_make(&sub, "subuninit_sub"));
        /* The pin is CORRECT: the tip's gitlink and the submodule the
         * checkout holds are the same commit. The only defect is that the
         * checkout's vendor/tor is not checked out. */
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_submodule_uninit(rig.clone, "vendor/tor"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        /* The whole point: NOT "submodule commit <superproject sha> != tip
         * <pin>". A bare `git -C <checkout>/vendor/tor rev-parse HEAD`
         * walks up to the enclosing superproject and answers with a commit
         * that is not a submodule commit at all. */
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule commit") == NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:vendor/tor "
                      "(submodule uninitialised in ") != NULL);
        (void)snprintf(suffix, sizeof(suffix),
                       "; run git submodule update --init vendor/tor)");
        ASSERT(strstr(dlx_str(&c, "detail"), suffix) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), rig.clone) != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_current_tor(void)
{
    int failures = 0;
    TEST("land: a landing worktree already standing on the tip's vendor/tor "
        "pin with the archive in place never consults the submitting "
        "checkout again") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char wt[1200], check[1400], second[64];
        dlx_isolate("subtrust");
        ASSERT(dlx_rig_make(&rig, "subtrust_rig"));
        ASSERT(dlx_subrepo_make(&sub, "subtrust_sub"));
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Round one: an ordinary landing, which initialises the landing
         * worktree's own vendor/tor at the tip's pin and materializes
         * libtor.a beside it. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(dlx_file_exists(check));
        /* Round two: a new tip carrying the SAME gitlink, submitted from a
         * checkout whose vendor/tor is now uninitialised. Nothing over
         * there can answer for the pin any more — and nothing has to. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        ASSERT(dlx_submodule_uninit(rig.clone, "vendor/tor"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_generated_conflict(void)
{
    int failures = 0;
    TEST("land: a rebase conflict confined to the regenerated artifacts is "
        "resolved from the code and folded, signed, into the candidate's "
        "own commit, not refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], landwt[1300], subject[512], sig[64], base[64];
        const char *log_subject[] = { "log", "-1", "--pretty=%s", NULL };
        const char *log_sig[] = { "log", "-1", "--pretty=%G?", NULL };
        const char *parent_args[] = { "rev-parse", "HEAD~1", NULL };
        const char *inventory[] = { "show",
                                    "HEAD:docs/CAPABILITY_INVENTORY.jsonl",
                                    NULL };
        const char *map[] = { "show", "HEAD:docs/CODEBASE_MAP.md", NULL };
        const char *mine[] = { "show", "HEAD:mine.txt", NULL };
        dlx_isolate("regenauto");
        ASSERT(dlx_rig_make(&rig, "regenauto_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "regenauto_key"));
        ASSERT(dlx_regen_conflict(&rig, NULL, tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Past the rebase and into the proof: the conflict never became a
         * terminal state. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "rebase: regenerated "
                      "docs/CAPABILITY_INVENTORY.jsonl,"
                      "docs/CODEBASE_MAP.md") != NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, log_subject, subject, sizeof(subject)) ==
              0);
        /* No regeneration commit: the candidate's own commit, directly on
         * the new main, carries its subject and the regenerated files. */
        ASSERT_STR_EQ(subject, "the submitted work");
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_git_out(landwt, parent_args, subject, sizeof(subject)) ==
               0);
        ASSERT_STR_EQ(subject, base);
        ASSERT(dlx_git_out(landwt, inventory, subject, sizeof(subject)) ==
               0);
        ASSERT_STR_EQ(subject, "theirs\nregenerated by dev.land");
        ASSERT(dlx_git_out(landwt, map, subject, sizeof(subject)) == 0);
        ASSERT_STR_EQ(subject, "<!-- DOC-COUNTS-BEGIN -->\ntheirs\n<!-- DOC-COUNTS-END -->\nregenerated by dev.land");
        ASSERT(dlx_git_out(landwt, mine, subject, sizeof(subject)) == 0);
        ASSERT_STR_EQ(subject, "mine");
        /* Signed by AMBIENT config: dev.land passes no signing flag, and
         * main rejects an unsigned commit. */
        ASSERT(dlx_git_out(landwt, log_sig, sig, sizeof(sig)) == 0);
        ASSERT_STR_EQ(sig, "G");
        unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A conflict on one artifact must not leave a stale count bump that merged
 * cleanly in another: every generator runs before the gates. Both lanes
 * write the same stale CODEBASE_MAP bump; only the inventory conflicts.
 * The check-doc-counts stand-in refuses until fix-doc-counts has run. */
static int dlx_case_conflict_regens_clean_merged_artifact(void)
{
    int failures = 0;
    TEST("land: a conflict on one artifact still regenerates a cleanly "
        "merged stale one before the gates") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], base[64], landwt[1300], out[512];
        char mk[2048], mk2[3072], mkpath[700];
        size_t len = 0;
        const char *branch[] = { "branch", "keep-tip", NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *reset[] = { "reset", "--quiet", "--hard", base, NULL };
        const char *map[] = { "show", "HEAD:docs/CODEBASE_MAP.md", NULL };
        dlx_isolate("regenclean");
        ASSERT(dlx_rig_make_docregen(
            &rig, "regenclean_rig",
            "@printf 'regen\\n' > docs/CAPABILITY_INVENTORY.jsonl", "@:",
            "@printf 'fixed\\n' > docs/CODEBASE_MAP.md"));
        (void)snprintf(mkpath, sizeof(mkpath), "%s/Makefile", rig.clone);
        ASSERT(dlx_slurp(mkpath, mk, sizeof(mk) - 1, &len));
        mk[len] = '\0';
        ASSERT((size_t)snprintf(mk2, sizeof(mk2),
            "%sdocs-api-reference:\n\t@:\n"
            "check-generated-artifact-contradictions:\n\t@:\n"
            "check-doc-counts:\n\t@grep -q fixed docs/CODEBASE_MAP.md || "
            "{ echo 'FAIL: doc-count drift detected'; exit 1; }\n",
            mk) < sizeof(mk2));
        ASSERT(dlx_write_dep(rig.clone, "Makefile", mk2));
        ASSERT(dlx_write_dep(rig.clone, "docs/CAPABILITY_INVENTORY.jsonl",
                             "base\n"));
        ASSERT(dlx_commit_tree(rig.clone, "gates", base));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_write_dep(rig.clone, "docs/CAPABILITY_INVENTORY.jsonl",
                             "mine\n"));
        ASSERT(dlx_write_dep(rig.clone, "docs/CODEBASE_MAP.md", "bump\n"));
        ASSERT(dlx_commit_tree(rig.clone, "the submitted work", tip));
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_git(rig.clone, reset) == 0);
        ASSERT(dlx_write_dep(rig.clone, "docs/CAPABILITY_INVENTORY.jsonl",
                             "theirs\n"));
        ASSERT(dlx_write_dep(rig.clone, "docs/CODEBASE_MAP.md", "bump\n"));
        ASSERT(dlx_commit_tree(rig.clone, "someone else's train", out));
        ASSERT(dlx_git(rig.clone, push) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strstr(dlx_str(&c, "detail"), "refused after") == NULL);
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, map, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "fixed");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_rerere_conflict(void)
{
    int failures = 0;
    TEST("land: rerere autoupdate cannot hide a previously resolved "
        "generated-artifact conflict from the rebase classifier") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], landwt[1300], configured[16];
        const char *get_autoupdate[] = { "config", "--get",
                                         "rerere.autoupdate", NULL };
        dlx_isolate("regenrerere");
        ASSERT(dlx_rig_make(&rig, "regenrerere_rig"));
        ASSERT(dlx_regen_conflict(&rig, NULL, tip));
        ASSERT(dlx_rerere_autoupdate_prime(&rig));
        ASSERT(dlx_sign_arm(rig.clone, "regenrerere_key"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "rebase: regenerated docs/CAPABILITY_INVENTORY.jsonl,")
               != NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, get_autoupdate, configured,
                           sizeof(configured)) == 0);
        ASSERT(strcmp(configured, "true") == 0);
        unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_regen_gate(void)
{
    int failures = 0;
    TEST("land: a post-regeneration gate that still refuses fails the row "
        "by name instead of landing a tree the gates reject") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64];
        dlx_isolate("regengate");
        ASSERT(dlx_rig_make(&rig, "regengate_rig"));
        ASSERT(dlx_regen_conflict(&rig, NULL, tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        setenv("ZCL_LAND_REGEN_GATE_STUB_FAIL", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "rebase") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "check-generated-artifact-contradictions refused "
                      "after auto-resolving the rebase") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "ZCL_LAND_REGEN_GATE_STUB_FAIL") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
        unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int dlx_case_mixed_conflict(void)
{
    int failures = 0;
    TEST("land: one conflicted path outside the regenerated-artifact table "
        "keeps the whole conflict a conflict") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64];
        dlx_isolate("regenmixed");
        ASSERT(dlx_rig_make(&rig, "regenmixed_rig"));
        ASSERT(dlx_regen_conflict(&rig, "change.txt", tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "conflict") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "rebase") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "change.txt") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/CAPABILITY_INVENTORY.jsonl") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "docs/CODEBASE_MAP.md") !=
              NULL);
        /* No regeneration note anywhere: nothing was auto-resolved. */
        ASSERT(strstr(dlx_str(&c, "detail"), "rebase: regenerated") ==
              NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── LAND-WINDOW: deferral, announce, close ─────────────────────────────
 * The lander's window posts are off in test builds unless armed; the
 * fixture mail dir lives under the isolated state root. */

static void dlx_window_arm(const char *on)
{
    (void)setenv("ZCL_LAND_WINDOW", on, 1);
    (void)setenv("ZCL_LAND_WINDOW_HOST", "hosta", 1);
}

static bool dlx_window_maildir(char *out, size_t cap)
{
    char landdir[1200];
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(out, cap, "%s/../mail", landdir) >= (int)cap)
        return false;
    return dlx_mkdir_p(out);
}

static void dlx_window_clock(int64_t t, char iso[32], char hhmm[8])
{
    time_t tt = (time_t)t;
    struct tm tm;
    (void)gmtime_r(&tt, &tm);
    (void)strftime(iso, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
    (void)strftime(hhmm, 8, "%H:%MZ", &tm);
}

/* The peer inbox: hostb proving candidate aaaaaaaaaa on `base10`, announced
 * at `ts` and expected done at `done`, optionally released a minute later. */
static bool dlx_window_peer(const char *base10, int64_t ts, int64_t done,
                            bool released)
{
    char mail[1400], path[1500], iso[32], hhmm[8], dhhmm[8], riso[32];
    char rows[2048];
    if (!dlx_window_maildir(mail, sizeof(mail)))
        return false;
    dlx_window_clock(ts, iso, hhmm);
    dlx_window_clock(done, riso, dhhmm);
    dlx_window_clock(ts + 60, riso, hhmm);
    int n = snprintf(rows, sizeof(rows),
        "{\"seq\":1,\"ts\":\"%s\",\"from\":\"agent-b\",\"to\":\"*\","
        "\"kind\":\"note\",\"body\":\"LAND-WINDOW hostb, candidate "
        "aaaaaaaaaa on base %.10s, proving now, expected done %s.\","
        "\"ref\":\"astra-board-runs\"}\n",
        iso, base10, dhhmm);
    if (n <= 0 || (size_t)n >= sizeof(rows))
        return false;
    if (released &&
        snprintf(rows + n, sizeof(rows) - (size_t)n,
                 "{\"seq\":2,\"ts\":\"%s\",\"from\":\"agent-b\",\"to\":\"*\","
                 "\"kind\":\"note\",\"body\":\"RELEASED hostb, candidate "
                 "aaaaaaaaaa on base %.10s.\",\"ref\":\"astra-board-runs\"}\n",
                 riso, base10) >= (int)(sizeof(rows) - (size_t)n))
        return false;
    return snprintf(path, sizeof(path), "%s/inbox.peer.jsonl", mail) <
               (int)sizeof(path) &&
           dlx_write(path, rows);
}

static bool dlx_window_outbox_has(const char *needle)
{
    char mail[1400], path[1500];
    static char text[1u << 20];
    size_t len = 0;
    if (!dlx_window_maildir(mail, sizeof(mail)) ||
        snprintf(path, sizeof(path), "%s/outbox.jsonl", mail) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0'; /* dlx_slurp does not terminate */
    return strstr(text, needle) != NULL;
}

/* Isolated rig, armed lander window, a queued submission of the rig tip. */
static bool dlx_window_rig(struct dlx_rig *rig, const char *tag,
                           const char *on, char base[64])
{
    struct dlx_call c;
    char mail[1400];
    bool ok;
    dlx_isolate(tag);
    dlx_window_arm(on);
    if (!dlx_rig_make(rig, tag) || !dlx_origin_main(rig, base) ||
        !dlx_window_maildir(mail, sizeof(mail)))
        return false;
    (void)setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    (void)setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

/* Step once; "" state on a refusal, with the refusal code in `code`. */
static void dlx_window_step(char state[32], char code[64], char evidence[512])
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    state[0] = code[0] = evidence[0] = '\0';
    if (dlx_run(&c)) {
        if (dlx_ok(&c) && dlx_str(&c, "state"))
            (void)snprintf(state, 32, "%s", dlx_str(&c, "state"));
        else if (!dlx_ok(&c)) {
            (void)snprintf(code, 64, "%s", dlx_err_code(&c));
            (void)snprintf(evidence, 512, "%s", dlx_err_evidence(&c));
        }
    }
    dlx_end(&c);
}

static int test_dev_land_window_defer(void)
{
    int failures = 0;
    struct dlx_rig rig;
    char base[64], state[32], code[64], evidence[512], want[160];
    int64_t now = platform_time_wall_unix();

    TEST("land window: a foreign window on the same base defers the proof") {
        ASSERT(dlx_window_rig(&rig, "window_defer", "1", base));
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(code, "STEP_DEFERRED");
        ASSERT(strstr(evidence, "host=hostb") != NULL);
        ASSERT(strstr(evidence, "candidate=aaaaaaaaaa") != NULL);
        ASSERT(strstr(evidence, "seconds_left=") != NULL);
        ASSERT(!dlx_window_outbox_has("LAND-WINDOW hosta"));
        /* hostb released: the proof starts and hosta announces it */
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, true));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        (void)snprintf(want, sizeof(want), "on base %.10s, proving now, "
                       "expected done ", base);
        ASSERT(dlx_window_outbox_has("\"body\":\"LAND-WINDOW hosta, candidate "));
        ASSERT(dlx_window_outbox_has(want));
        /* the publish closes the window with LANDED */
        (void)setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "landed");
        ASSERT(dlx_window_outbox_has("\"body\":\"LANDED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        dlx_restore();
        PASS();
    }

    TEST("land window: a window on another base does not defer; a failure releases") {
        ASSERT(dlx_window_rig(&rig, "window_other_base", "1", base));
        ASSERT(dlx_window_peer("cccccccccc", now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        ASSERT(dlx_window_outbox_has("\"body\":\"LAND-WINDOW hosta, candidate "));
        (void)setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_window_step(state, code, evidence);
        ASSERT(state[0] != '\0' && strcmp(state, "landed") != 0);
        ASSERT(dlx_window_outbox_has("\"body\":\"RELEASED hosta, candidate "));
        dlx_restore();
        PASS();
    }

    TEST("land window: a window past expected-done + 10 min does not defer") {
        ASSERT(dlx_window_rig(&rig, "window_expired", "1", base));
        ASSERT(dlx_window_peer(base, now - 3000, now - 900, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        dlx_restore();
        PASS();
    }

    TEST("land window: ZCL_LAND_WINDOW=0 neither defers nor posts") {
        ASSERT(dlx_window_rig(&rig, "window_off", "0", base));
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        ASSERT(!dlx_window_outbox_has("LAND-WINDOW hosta"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The step that would have settled died right after its outcome append:
 * this host's window is still open in the sidecar while the row is
 * terminal. `proof` is the stub the dying step runs ("pass" -> landed,
 * "fail" -> a non-landed terminal). Returns the next step's state. */
static bool dlx_window_crash(const char *tag, const char *on,
                             const char *proof, char state[32],
                             char code[64], bool *sidecar)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char base[64], evidence[512], landdir[1200], side[1300];
    int child_status = 0;
    if (!dlx_window_rig(&rig, tag, on, base))
        return false;
    dlx_window_step(state, code, evidence);
    if (strcmp(state, "started") != 0)
        return false;
    (void)setenv("ZCL_LAND_PROOF_STUB", proof, 1);
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        (void)setenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME", "1", 1);
        (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
        dlx_begin(&c, "step");
        (void)dlx_run(&c);
        _exit(90);
    }
    if (dlx_wait_child(child, &child_status) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 81)
        return false;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(side, sizeof(side), "%s/window.state", landdir) >=
        (int)sizeof(side))
        return false;
    *sidecar = dlx_file_exists(side);
    dlx_window_step(state, code, evidence);
    *sidecar = *sidecar && dlx_file_exists(side);
    return true;
}

static int test_dev_land_window_replay(void)
{
    int failures = 0;
    char state[32], code[64], ref[32];
    bool sidecar;

    TEST("land window: a terminal replay closes the open window with LANDED") {
        /* reference: the same crash with the window off */
        ASSERT(dlx_window_crash("window_replay_off", "0", "pass", ref, code,
                                &sidecar));
        ASSERT_STR_EQ(ref, "landed");
        dlx_restore();
        ASSERT(dlx_window_crash("window_replay_landed", "1", "pass", state,
                                code, &sidecar));
        ASSERT_STR_EQ(state, ref);
        ASSERT_STR_EQ(code, "");
        ASSERT(dlx_window_outbox_has("\"body\":\"LANDED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        ASSERT(!sidecar);
        dlx_restore();
        PASS();
    }

    TEST("land window: a terminal replay of a failed row closes with RELEASED") {
        ASSERT(dlx_window_crash("window_replay_off2", "0", "fail", ref, code,
                                &sidecar));
        ASSERT(ref[0] != '\0' && strcmp(ref, "landed") != 0);
        dlx_restore();
        ASSERT(dlx_window_crash("window_replay_failed", "1", "fail", state,
                                code, &sidecar));
        ASSERT_STR_EQ(state, ref);
        ASSERT_STR_EQ(code, "");
        ASSERT(dlx_window_outbox_has("\"body\":\"RELEASED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"LANDED hosta"));
        ASSERT(!sidecar);
        dlx_restore();
        PASS();
    }

    TEST("land window: a row still proving keeps its window across a step") {
        struct dlx_rig rig;
        char base[64], evidence[512], landdir[1200], side[1300];
        ASSERT(dlx_window_rig(&rig, "window_replay_proving", "1", base));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        dlx_window_step(state, code, evidence); /* stub still running */
        ASSERT(strcmp(state, "started") == 0 || strcmp(state, "proving") == 0);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(side, sizeof(side), "%s/window.state", landdir) <
               (int)sizeof(side));
        ASSERT(dlx_file_exists(side));
        ASSERT(!dlx_window_outbox_has("\"body\":\"LANDED hosta"));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#endif /* !defined(_WIN32) */

int test_dev_land(void)
{
    /* Canonical registered group: private bare origin only, no live queue. */
    int failures = 0;
    failures += dlx_publication_hold_cases();
    failures += dlx_hold_legacy_case();
    failures += dlx_hold_pushed_case();
    failures += dlx_hold_malformed_case();
    failures += dlx_hold_sealed_case();
    failures += dlx_hold_lock_case();
    failures += dlx_launcher_join_cases();
    failures += dlx_attest_only_cases();
    failures += dlx_attest_bounded_wire_cases();
    failures += dlx_attest_refusal_cases();
    failures += test_dev_land_signed_intent();
#if !defined(_WIN32)
    failures += dlx_fence_cases();
    failures += dlx_fence_concurrent();
    failures += dlx_fence_negative_cases();
    failures += test_dev_land_status_observation();
#endif
    failures += test_dev_land_signed_tamper();
    failures += test_dev_land_receipt_adversarial();
    failures += test_dev_land_signer_takeover();
    failures += test_dev_land_signed_stale();
    failures += test_dev_land_signed_recovery();
    failures += test_dev_land_new_source_precheck();
    failures += test_dev_land_drive_producer_reproof();
    failures += test_dev_land_step_producer_recovery();
#if !defined(_WIN32)
    failures += test_dev_land_phase_mail_quiet();
#endif
    failures += test_dev_land_phase_digest();
    failures += test_dev_land_signed_lost_ack();
    failures += test_dev_land_signed_lost_race();
    failures += test_dev_land_signed_lost_ack_resend();
    failures += test_dev_land_signed_push_lost_race();
    failures += test_dev_land_cancel_push_refused();
    failures += test_dev_land_signed_publisher_death();
    failures += test_dev_land_watcher_admission();
    failures += test_dev_land_long_proof_root();
    failures += test_dev_land_malformed_queue_refusal();
    failures += test_dev_land_chain_codec();
    failures += test_dev_land_chain_relation();
    failures += test_dev_land_malformed_priority_refusal();
    failures += test_dev_land_malformed_outcome_refusal();
    failures += test_dev_land_exact_tree();
    failures += test_dev_land_source_binding();
#if !defined(_WIN32)
    failures += test_dev_land_tree_types();
    failures += test_dev_land_tree_malformed();
    failures += test_dev_land_tree_replacements();
    failures += test_dev_land_tree_missing();
    failures += test_dev_land_proof_evidence_test();
    failures += test_dev_land_proof_evidence_compile();
#endif

    failures += dlx_case_registration();

    failures += dlx_case_unknown_action();

#if !defined(_WIN32)

    failures += dlx_case_unsigned_tip();

    failures += dlx_case_checkout_location();

    failures += dlx_case_submit_status();

    failures += dlx_case_duplicate_submit();

    failures += dlx_case_empty_step();

    failures += dlx_case_step_lock();

    failures += dlx_case_starts_proof();

    failures += dlx_case_absent_watcher();

    failures += dlx_case_unarmed_proof();

    failures += test_dev_land_missing_worker();

    failures += test_dev_land_interrupted_proof();
#if !defined(_WIN32)
    failures += test_dev_land_drive_base_watch();
#endif

    failures += test_dev_land_competing_publish("step", "step", true);
    failures += test_dev_land_competing_publish("step", "drive", true);
    failures += test_dev_land_competing_publish("drive", "step", true);
    failures += test_dev_land_competing_publish("step", "drive", false);
    failures += test_dev_land_competing_publish("drive", "step", false);

    failures += test_dev_land_bounded_drive();

    failures += dlx_case_stub_detail();

    failures += dlx_case_lands_proof();

    failures += dlx_case_hook_refusal();

    failures += dlx_case_proof_failure();

    failures += dlx_case_timing_detail();

    failures += dlx_case_moved_base();

    failures += test_dev_land_explicit_main();

    failures += test_dev_land_missing_main();

    failures += test_dev_land_initial_remote_missing();

    failures += test_dev_land_final_observation_missing();

    failures += dlx_case_cancel_request();

    failures += dlx_case_concurrent_submit();

    failures += dlx_case_dense_detail();

    failures += test_dev_land_publisher_death();
    failures += test_dev_land_drain_adoption();
    failures += test_dev_land_postpush_observation_missing(false);
    failures += test_dev_land_postpush_observation_missing(true);
    failures += test_dev_land_prepush_checkpoint();
    failures += test_dev_land_prepush_persist_refusal();
    failures += test_dev_land_prepush_sync_refusal();
    failures += test_dev_land_missing_publication_intent();
    failures += test_dev_land_attach_target_cases();
    failures += test_dev_land_postpush_result_unconfirmed();
    failures += test_dev_land_expected_base_race();
    failures += test_dev_land_recovery_ignores_replace_refs();
    failures += test_dev_land_nonfastforward_client_guard();
    failures += test_dev_land_lost_persistence();
    failures += test_dev_land_after_proof_restart();
    failures += test_dev_land_terminal_replay();
    failures += test_dev_land_outcome_visible_in_mail();

    failures += dlx_case_missing_hook();

    failures += dlx_case_cancel_race();

    failures += dlx_case_aged_successor();
    failures += test_dev_land_main_moves_converge();

    failures += dlx_case_option_path();

    failures += test_dev_land_vendor_dependencies();

    failures += dlx_case_dependency_links();

    failures += dlx_case_missing_dependency();

    failures += test_dev_land_missing_tor_makefile();

    failures += dlx_case_tor_gitlink();

    failures += dlx_case_tor_head();

    failures += dlx_case_hook_drift();

    failures += dlx_case_idle_proof();

    failures += dlx_case_missing_hook_binary();

    failures += dlx_case_quiet_hooks();

    failures += dlx_case_uninitialised_tor();

    failures += dlx_case_current_tor();


    failures += dlx_case_generated_conflict();

    failures += dlx_case_rerere_conflict();

    failures += dlx_case_regen_gate();

    failures += dlx_case_conflict_regens_clean_merged_artifact();

    failures += dlx_case_mixed_conflict();

    failures += test_dev_land_integrated_merge(false);
    failures += test_dev_land_integrated_merge(true);
    failures += test_dev_land_regen_commits_drift();
    failures += test_dev_land_regen_no_commit_when_clean();
    failures += test_dev_land_regen_failure_fails_row();
    failures += test_dev_land_regen_runs_all_targets_in_one_make();
    failures += test_dev_land_regen_middle_failure_names_line_and_stops();
    failures += test_dev_land_regen_refreshes_plan_on_identical_rewrite();
    failures += test_dev_land_regen_leaves_plan_alone_when_untouched();
    failures += test_dev_land_proof_tools_preparation();
    failures += test_dev_land_final_plan_preparation();
    failures += test_dev_land_rebase_regen_cases();
    failures += test_dev_land_queued_precheck_cases();
    failures += dlx_outcome_escape_cases();
    failures += dlx_optional_string_refusal_cases();
    failures += dlx_string_compatibility_cases();
    failures += test_dev_land_window_defer();
    failures += test_dev_land_window_replay();

#endif /* !defined(_WIN32) */

    dlx_restore();
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}

/* ── rebase regeneration for tips that carry merges ───────────────────────
 *
 * The shape that stranded land queue row 30: a long-lived candidate that
 * merged origin/main into itself (resolving the inventory, and sometimes
 * real source, by hand), then main moved again before it landed. A plain
 * `git rebase` replays each non-merge commit and throws those resolutions
 * away, so a later replayed commit conflicts on real source and the
 * generated-artifact auto-resolve correctly declines. The cases below pin
 * the landing path that keeps the candidate's resolved tree instead, and
 * the ones that must still refuse. */
#if !defined(_WIN32)

struct dlx_mtip {
    char m1[64];  /* main after the train the candidate merged */
    char m2[64];  /* main after the train that raced it */
    char tip[64]; /* the submitted candidate tip */
};

/* A commit signed by the clone's AMBIENT signer (dlx_sign_arm): the lander
 * refuses to queue an unsigned tip outside the unsigned fixture seam. */
static bool dlx_mtip_commit(const char *dir, const char *msg, char out[64])
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "commit", "--quiet", "--no-verify", "-m", msg,
                             NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if (dlx_git(dir, add) != 0 || dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

static bool dlx_mtip_write2(const char *dir, const char *inv_body,
                            const char *path, const char *body)
{
    return dlx_write_dep(dir, "docs/CAPABILITY_INVENTORY.jsonl", inv_body) &&
           dlx_write_dep(dir, path, body);
}

static bool dlx_mtip_step(const char *dir, const char *inv_body,
                          const char *path, const char *body,
                          const char *msg, char out[64])
{
    return dlx_mtip_write2(dir, inv_body, path, body) &&
           dlx_mtip_commit(dir, msg, out);
}

/* base on main ; candidate c1 (a.txt, inventory) on branch cand ; main M1
 * (a.txt, inventory) pushed ; left on cand. */
static bool dlx_mtip_diverge(struct dlx_rig *rig, struct dlx_mtip *out)
{
    char scratch[64];
    const char *c = rig->clone;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *to_cand[] = { "checkout", "--quiet", "-b", "cand", NULL };
    const char *to_main[] = { "checkout", "--quiet", "main", NULL };
    const char *back[] = { "checkout", "--quiet", "cand", NULL };
    return dlx_mtip_step(c, "base\n", "a.txt", "base\n", "base", scratch) &&
           dlx_git(c, push) == 0 && dlx_git(c, to_cand) == 0 &&
           dlx_mtip_step(c, "mine1\n", "a.txt", "mine1\n", "candidate one",
                         scratch) &&
           dlx_git(c, to_main) == 0 &&
           dlx_mtip_step(c, "theirs1\n", "a.txt", "theirs1\n", "train one",
                         out->m1) &&
           dlx_git(c, push) == 0 && dlx_git(c, back) == 0;
}

/* ...then the candidate merges M1 resolving a.txt and the inventory by
 * hand ; candidate c2 (c.txt, inventory, and b.txt when `source_conflict`)
 * is the submitted tip ; main M2 (b.txt, inventory) is pushed. The
 * candidate's net change against M1 meets M2 only on the inventory unless
 * `source_conflict`. */
static bool dlx_mtip_rig(struct dlx_rig *rig, bool source_conflict,
                         struct dlx_mtip *out)
{
    char scratch[64];
    const char *c = rig->clone;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *to_main[] = { "checkout", "--quiet", "main", NULL };
    const char *merge[] = { "-c", "user.name=land", "-c",
                            "user.email=land@z23.invalid", "merge",
                            "--quiet", "--no-edit", "--no-gpg-sign", "main",
                            NULL };
    if (!dlx_mtip_diverge(rig, out))
        return false;
    /* Conflicts on a.txt and the inventory by construction; the hand
     * resolution is exactly what a per-commit replay throws away. */
    (void)dlx_git(c, merge);
    if (!dlx_mtip_step(c, "merged\n", "a.txt", "merged\n", "integrate main",
                       scratch))
        return false;
    if (source_conflict && !dlx_write_dep(c, "b.txt", "mine2\n"))
        return false;
    return dlx_mtip_step(c, "mine2\n", "c.txt", "mine2\n", "candidate two",
                         out->tip) &&
           dlx_git(c, to_main) == 0 &&
           dlx_mtip_step(c, "theirs2\n", "b.txt", "theirs2\n", "train two",
                         out->m2) &&
           dlx_git(c, push) == 0;
}

static bool dlx_land_log_has(const char *needle)
{
    char landdir[1200], path[1300], log[65536];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (!dlx_slurp(path, log, sizeof(log) - 1, &len))
        return false;
    log[len] = '\0';
    return strstr(log, needle) != NULL;
}

static int test_dev_land_merge_tip_regenerates(void)
{
    int failures = 0;
    TEST("land: a merge-bearing tip that main moved past keeps its resolved "
         "tree and auto-regenerates the inventory instead of conflicting") {
        struct dlx_rig rig;
        struct dlx_mtip m;
        struct dlx_call c;
        char landwt[1300], out[512], expect[256];
        const char *subject[] = { "log", "-1", "--format=%s", NULL };
        const char *sig_head[] = { "log", "-1", "--format=%G?", "HEAD",
                                   NULL };
        const char *parent[] = { "show", "-s", "--format=%P", "HEAD",
                                 NULL };
        const char *body[] = { "log", "-1", "--format=%B", "HEAD", NULL };
        const char *inv[] = { "show", "HEAD:docs/CAPABILITY_INVENTORY.jsonl",
                              NULL };
        const char *a_txt[] = { "show", "HEAD:a.txt", NULL };
        const char *b_txt[] = { "show", "HEAD:b.txt", NULL };
        const char *c_txt[] = { "show", "HEAD:c.txt", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *remote[] = { "rev-parse", "main", NULL };
        char prepared[64];
        dlx_isolate("mtipregen");
        ASSERT(dlx_rig_make(&rig, "mtipregen_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "mtipregen_key"));
        ASSERT(dlx_mtip_rig(&rig, false, &m));
        /* Production signing throughout the rebase step. */
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, m.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "rebase: regenerated docs/CAPABILITY_INVENTORY.jsonl")
               != NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, subject, out, sizeof(out)) == 0);
        /* The merge-bearing tip was cut into ONE linear commit first, and
         * the regenerated inventory is amended into THAT commit: its
         * subject is the linearization's, never a regeneration's. */
        ASSERT_STR_EQ(out, "Prepare candidate for linear publication");
        ASSERT(dlx_git_out(landwt, inv, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "theirs2\nregenerated by dev.land");
        /* The candidate's hand resolution survived; main's later train and
         * the candidate's later work are both present. */
        ASSERT(dlx_git_out(landwt, a_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "merged");
        ASSERT(dlx_git_out(landwt, b_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "theirs2");
        ASSERT(dlx_git_out(landwt, c_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "mine2");
        /* One single-parent candidate commit on the new main, signed by
         * the lander's signer, and nothing on top of it. */
        ASSERT(dlx_git_out(landwt, parent, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, m.m2);
        ASSERT(dlx_git_out(landwt, sig_head, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "G");
        ASSERT(dlx_git_out(landwt, body, out, sizeof(out)) == 0);
        (void)snprintf(expect, sizeof(expect), "Original-Candidate: %s",
                       m.tip);
        ASSERT(strstr(out, expect) != NULL);
        (void)snprintf(expect, sizeof(expect), "Original-Base: %s", m.m1);
        ASSERT(strstr(out, expect) != NULL);
        /* A replayed candidate's own source tree is not claimed. */
        ASSERT(strstr(out, "Source-Tree:") == NULL);
        ASSERT(dlx_land_log_has("rebase: regenerated "
                                "docs/CAPABILITY_INVENTORY.jsonl"));
        ASSERT(dlx_land_log_has("linearized merge-bearing candidate "));
        /* And it lands. */
        ASSERT(dlx_git_out(landwt, head, prepared, sizeof(prepared)) == 0);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, prepared);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_merge_tip_source_conflict(void)
{
    int failures = 0;
    TEST("land: a merge-bearing tip with a real source conflict beside the "
         "generated one is still a conflict") {
        struct dlx_rig rig;
        struct dlx_mtip m;
        struct dlx_call c;
        char out[64];
        const char *remote[] = { "rev-parse", "main", NULL };
        dlx_isolate("mtipsrc");
        ASSERT(dlx_rig_make(&rig, "mtipsrc_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "mtipsrc_key"));
        ASSERT(dlx_mtip_rig(&rig, true, &m));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, m.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT(strstr(dlx_str(&c, "detail"), "b.txt") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/CAPABILITY_INVENTORY.jsonl") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "rebase: regenerated") ==
               NULL);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, m.m2);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A linear two-commit tip whose FIRST replayed commit conflicts only on
 * the inventory and whose SECOND conflicts on real source: the conflict
 * outcome is unchanged (it names the original unmerged list), and the
 * attempt log now says why the auto-resolve stopped. Row 30's a2 log said
 * only "rebase conflict: docs/CAPABILITY_INVENTORY.jsonl". */
static int test_dev_land_late_conflict_named(void)
{
    int failures = 0;
    TEST("land: an auto-resolve that stops on a later replayed commit "
         "names the path that stopped it") {
        struct dlx_rig rig;
        struct dlx_call c;
        char scratch[64], tip[64];
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *to_cand[] = { "checkout", "--quiet", "-b", "cand",
                                  NULL };
        const char *to_main[] = { "checkout", "--quiet", "main", NULL };
        dlx_isolate("lateconf");
        ASSERT(dlx_rig_make(&rig, "lateconf_rig"));
        ASSERT(dlx_mtip_write2(rig.clone, "base\n", "a.txt", "base\n"));
        ASSERT(dlx_commit_tree(rig.clone, "base", scratch));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_git(rig.clone, to_cand) == 0);
        ASSERT(dlx_mtip_write2(rig.clone, "mine1\n", "x.txt", "mine1\n"));
        ASSERT(dlx_commit_tree(rig.clone, "candidate one", scratch));
        ASSERT(dlx_mtip_write2(rig.clone, "mine2\n", "a.txt", "mine2\n"));
        ASSERT(dlx_commit_tree(rig.clone, "candidate two", tip));
        ASSERT(dlx_git(rig.clone, to_main) == 0);
        ASSERT(dlx_mtip_write2(rig.clone, "theirs\n", "a.txt", "theirs\n"));
        ASSERT(dlx_commit_tree(rig.clone, "train", scratch));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_sign_arm(rig.clone, "lateconf_key"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT_STR_EQ(dlx_str(&c, "detail"),
                      "docs/CAPABILITY_INVENTORY.jsonl");
        dlx_end(&c);
        ASSERT(dlx_land_log_has("rebase auto-resolve stopped: a replayed "
                                "commit conflicted outside the regenerated "
                                "artifacts: "));
        ASSERT(dlx_land_log_has("a.txt"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The real generator (a make target in the rig's Makefile, no stub) exits
 * nonzero after the auto-resolve: the row fails in the rebase dimension
 * and names the artifact and the target, and nothing is pushed. */
static int test_dev_land_regen_generator_fails(void)
{
    int failures = 0;
    TEST("land: a regenerate command that fails after the auto-resolve "
         "refuses the row by name") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], before[64], out[64];
        const char *remote[] = { "rev-parse", "main", NULL };
        dlx_isolate("regengenfail");
        ASSERT(dlx_rig_make_docregen(&rig, "regengenfail_rig", "@false",
                                     "@:", "@:"));
        ASSERT(dlx_regen_conflict(&rig, NULL, tip));
        ASSERT(dlx_git_out(rig.bare, remote, before, sizeof(before)) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "regenerating docs/CAPABILITY_INVENTORY.jsonl "
                      "(docs-capability-inventory) failed after "
                      "auto-resolving the rebase") != NULL);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_rebase_regen_cases(void)
{
    int failures = 0;
    const char *block = "<!-- DOC-COUNTS-BEGIN -->\ntest_groups: 1253\nport_interfaces: 13\npersistence_adapters: 14\ncondition_registrations: 56\ncommand_bundles: 31\ncommand_roots: 13\ndumpstate_subsystems: 167\napp_shape_folders: 7\n<!-- DOC-COUNTS-END -->\n";
    for (int ordinal = 0; ordinal < 6; ordinal++) {
        int mode = ordinal == 0 ? 4 : ordinal == 5 ? 5 : ordinal - 1; /* mode 5: map above 64 KiB */
        TEST("land: count recovery preserves proposals and refuses invalid blocks") {
            struct dlx_rig rig;
            struct dlx_call c;
            char base[64], tip[64], upstream[64], wt[1300];
            static char a[90000], b[90000], p[90000], out[90000], pad[70001];
            const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
            const char *keep[] = { "branch", "keep-tip", NULL };
            const char *reset[] = { "reset", "--hard", base, NULL };
            const char *show[] = { "show", "keep-tip:docs/CODEBASE_MAP.md", NULL };
            const char *head[] = { "show", "HEAD:docs/CODEBASE_MAP.md", NULL };
            dlx_isolate("countsprose");
            ASSERT(dlx_rig_make(&rig, "countsprose_rig"));
            memset(pad, 'x', sizeof(pad) - 1); pad[sizeof(pad) - 2] = '\n'; pad[sizeof(pad) - 1] = '\0';
            snprintf(a, sizeof(a), "Action A.\n%s%s", mode == 5 ? pad : "", block);
            snprintf(b, sizeof(b), "Action B.\n%s%s", mode == 5 ? pad : "", block);
            snprintf(p, sizeof(p), "Action C.\n%s%s", mode == 5 ? pad : "", block);
            if (mode == 2) { strcpy(a, "Action A.\n"); strcpy(b, "Action B.\n"); strcpy(p, "Action C.\n"); }
            if (mode == 3) { strcat(a, block); strcat(b, block); strcat(p, block); }
            if (mode >= 4) {
                snprintf(b, sizeof(b), "Action A.\n%s%s", mode == 5 ? pad : "", block);
                strstr(b, "1253")[3] = '4';
                strstr(p, "1253")[3] = '5';
            }
            ASSERT(dlx_write_dep(rig.clone, "docs/CODEBASE_MAP.md", a)); ASSERT(dlx_commit_tree(rig.clone, "base", base));
            ASSERT(dlx_git(rig.clone, push) == 0);
            ASSERT(dlx_write_dep(rig.clone, "docs/CODEBASE_MAP.md", p));
            if (mode == 1) ASSERT(dlx_write_dep(rig.clone, "clean.txt", "clean\n"));
            ASSERT(dlx_commit_tree(rig.clone, "proposal", tip));
            ASSERT(dlx_git(rig.clone, keep) == 0);
            ASSERT(dlx_git(rig.clone, reset) == 0);
            ASSERT(dlx_write_dep(rig.clone, "docs/CODEBASE_MAP.md", b)); ASSERT(dlx_commit_tree(rig.clone, "upstream", upstream));
            ASSERT(dlx_git(rig.clone, push) == 0);
            setenv("ZCL_LAND_PROOF_STUB", "running", 1);
            setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
            setenv("ZCL_LAND_REGEN_MAKE_STUB", "1", 1);
            dlx_submit(&c, &rig, tip);
            ASSERT(dlx_run(&c)); ASSERT(dlx_ok(&c)); dlx_end(&c);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c)); ASSERT(dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "state"), mode >= 4 ? "started" : "conflict");
            if (mode >= 4)
                ASSERT(strstr(dlx_str(&c, "detail"),
                              "rebase: regenerated docs/CODEBASE_MAP.md") != NULL);
            dlx_end(&c);
            ASSERT(dlx_git_out(rig.clone, show, out, sizeof(out)) == 0);
            p[strlen(p) - 1] = '\0';
            ASSERT_STR_EQ(out, p);
            if (mode >= 4) { dlx_land_wt(wt, sizeof(wt)); ASSERT(dlx_git_out(wt, head, out, sizeof(out)) == 0); ASSERT(strstr(out, "Action C.\n") == out); }
            dlx_restore(); PASS();
        }
    }
    failures += test_dev_land_merge_tip_regenerates();
    failures += test_dev_land_merge_tip_source_conflict();
    failures += test_dev_land_late_conflict_named();
    failures += test_dev_land_regen_generator_fails();
_test_next:
    dlx_restore();
    return failures;
}


/* ── queued-row conflict precheck ─────────────────────────────────────────
 *
 * A row queued behind the in-flight proof used to learn that main had moved
 * into a conflicting state only when it reached the head of the queue (land
 * seqs 102/103: ~69 min queued, then `conflict/rebase` in under 5 s). Each
 * beat that leaves a row in flight now replays every queued row onto the
 * main it just observed, in the object store only, and ends a row that
 * cannot rebase as the same conflict outcome dl_rebase() would record. */

/* One commit on origin/main writing `path` = `body` on branch `branch`;
 * the clone goes back to its own main (the rig's tip A) afterwards. */
static bool dlx_qp_branch(struct dlx_rig *rig, const char *branch,
                          const char *path, const char *body,
                          const char *path2, const char *body2, char out[64])
{
    const char *to_branch[] = { "checkout", "--quiet", "-b", branch,
                                "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    if (dlx_git(rig->clone, to_branch) != 0 ||
        !dlx_write_dep(rig->clone, path, body))
        return false;
    if (path2 && !dlx_write_dep(rig->clone, path2, body2))
        return false;
    return dlx_commit_tree(rig->clone, branch, out) &&
           dlx_git(rig->clone, back) == 0;
}

/* A direct push to origin main that nobody queued: one commit on the
 * current origin/main writing `path` = `body`. `out` is the new main. */
static bool dlx_qp_push_main(struct dlx_rig *rig, const char *path,
                             const char *body, char out[64])
{
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *to_mover[] = { "checkout", "--quiet", "-B", "mover",
                               "origin/main", NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    return dlx_git(rig->clone, fetch) == 0 &&
           dlx_git(rig->clone, to_mover) == 0 &&
           dlx_write_dep(rig->clone, path, body) &&
           dlx_commit_tree(rig->clone, "direct push", out) &&
           dlx_git(rig->clone, push) == 0 &&
           dlx_git(rig->clone, back) == 0;
}

/* Submit `tip` and require it to take land seq `seq`. */
static bool dlx_qp_submit(struct dlx_rig *rig, const char *tip, int64_t seq)
{
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    bool ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == seq;
    dlx_end(&c);
    return ok;
}

/* Submit `a_tip` (seq 1, the row that goes in flight) then B (seq 2). */
static bool dlx_qp_start_a(struct dlx_rig *rig, const char *a_tip,
                           const char *b_tip)
{
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_qp_submit(rig, a_tip, 1) && dlx_qp_submit(rig, b_tip, 2);
}

/* Submit A (the rig tip) then B. */
static bool dlx_qp_start(struct dlx_rig *rig, const char *b_tip)
{
    return dlx_qp_start_a(rig, rig->tip, b_tip);
}

/* One step; `state` is what the reply must name, and `checked`,
 * `conflicts` and `uncertain` what the precheck must report (-1: not
 * asserted). */
static bool dlx_qp_beat_u(const char *state, int64_t checked,
                          int64_t conflicts, int64_t uncertain)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (checked < 0 || dlx_int(&c, "queued_prechecked") == checked) &&
              (conflicts < 0 ||
               dlx_int(&c, "queued_conflicts") == conflicts) &&
              (uncertain < 0 ||
               dlx_int(&c, "queued_uncertain") == uncertain);
    if (!ok)
        printf("[step state=%s prechecked=%lld conflicts=%lld "
               "uncertain=%lld detail=%s] ",
               dlx_str(&c, "state"),
               (long long)dlx_int(&c, "queued_prechecked"),
               (long long)dlx_int(&c, "queued_conflicts"),
               (long long)dlx_int(&c, "queued_uncertain"),
               dlx_str(&c, "detail"));
    dlx_end(&c);
    return ok;
}

static bool dlx_qp_beat(const char *state, int64_t checked,
                        int64_t conflicts)
{
    return dlx_qp_beat_u(state, checked, conflicts, -1);
}

/* Quiet string equality: these helpers scan every row, so a mismatch is
 * the normal case, not a failure worth printing. */
static bool dlx_qp_same(const char *got, const char *want)
{
    return got && want && strcmp(got, want) == 0;
}

/* True when `tip` is still a queued row at `attempt`. */
static bool dlx_qp_queued_has(const char *tip, int64_t attempt)
{
    struct dlx_call c;
    bool found = false;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *rows = dlx_arr(&c, "queued");
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        if (dlx_qp_same(dlx_jstr(r, "tip"), tip) &&
            json_get_int(json_get(r, "attempt")) == attempt)
            found = true;
    }
    dlx_end(&c);
    return found;
}

/* True when the last outcome for `tip` is `state` in the rebase dimension;
 * its detail is copied into `detail`. */
static bool dlx_qp_outcome(const char *tip, const char *state,
                           char *detail, size_t cap)
{
    struct dlx_call c;
    bool found = false;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *rows = dlx_arr(&c, "outcomes");
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        if (!dlx_qp_same(dlx_jstr(r, "tip"), tip))
            continue;
        found = dlx_qp_same(dlx_jstr(r, "state"), state) &&
                dlx_qp_same(dlx_jstr(r, "dimension"), "rebase");
        (void)snprintf(detail, cap, "%s", dlx_jstr(r, "detail"));
    }
    dlx_end(&c);
    return found;
}

/* The in-flight row: seq 1 (A), phase prove, proving on `base`, and the
 * landing worktree's checkout still at the prepared commit it proves. */
static bool dlx_qp_a_in_flight(const char *base)
{
    struct dlx_call c;
    char landwt[1300], head[64];
    const char *head_args[] = { "rev-parse", "HEAD", NULL };
    const char *porcelain[] = { "status", "--porcelain",
                                "--untracked-files=no", NULL };
    char dirty[256];
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    bool ok = f && json_get_int(json_get(f, "seq")) == 1 &&
              dlx_eq_str(dlx_jstr(f, "phase"), "prove") &&
              dlx_eq_str(dlx_jstr(f, "base"), base);
    char local[64];
    (void)snprintf(local, sizeof(local), "%s", ok ? dlx_jstr(f, "local") : "");
    dlx_end(&c);
    dlx_land_wt(landwt, sizeof(landwt));
    return ok && dlx_git_out(landwt, head_args, head, sizeof(head)) == 0 &&
           strcmp(head, local) == 0 &&
           dlx_git_out(landwt, porcelain, dirty, sizeof(dirty)) == 0 &&
           dirty[0] == '\0';
}

static bool dlx_qp_file_has(const char *path, const char *needle)
{
    static char text[262144];
    size_t len = 0;
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    return strstr(text, needle) != NULL;
}

/* The last line of `path` that holds `anchor`, copied into `line`. Choice:
 * outcomes.jsonl is read raw, since the status reply carries no base or mark. */
static bool dlx_qp_last_line(const char *path, const char *anchor,
                             char *line, size_t cap)
{
    static char text[262144];
    const char *hit = NULL, *p, *start, *end;
    size_t len = 0;
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    for (p = text; (p = strstr(p, anchor)) != NULL; p++)
        hit = p;
    if (!hit)
        return false;
    start = hit;
    while (start > text && start[-1] != '\n')
        start--;
    end = strchr(hit, '\n');
    if (!end)
        end = text + len;
    if ((size_t)(end - start) >= cap)
        return false;
    (void)snprintf(line, cap, "%.*s", (int)(end - start), start);
    return true;
}

static int test_dev_land_queued_conflict_detected(void)
{
    int failures = 0;
    TEST("land: a queued row main moved into conflict with ends as a "
         "conflict one beat later, while the in-flight row keeps proving") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512], landdir[1200], maildir[1400];
        char outbox[1500];
        dlx_isolate("qp_conflict");
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(maildir, sizeof(maildir), "%s/../mail", landdir) <
               (int)sizeof(maildir));
        ASSERT(dlx_mkdir_p(maildir));
        ASSERT(dlx_rig_make(&rig, "qp_conflict_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        /* A starts; B is mergeable onto the main A starts on. */
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Someone pushes straight to main, over the very line B edits. */
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        /* Existing behaviour: A's proof pair is for a base nobody is on
         * any more, so A is requeued and restarted on the new main. */
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        /* B learned now, not after A's proof. */
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, "seed.txt") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        ASSERT(!dlx_qp_queued_has(b, 1));
        /* A is in flight on the new main, and the landing checkout it
         * proves was never touched by the check. */
        ASSERT(dlx_qp_a_in_flight(m1));
        ASSERT(snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir) <
               (int)sizeof(outbox));
        ASSERT(dlx_qp_file_has(outbox, "state=conflict"));
        ASSERT(dlx_qp_file_has(outbox, "detected while queued"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A terminal conflict row records its base and its cleared mark together;
 * the cleared mark has no later effect because the row is terminal. */
static int test_dev_land_queued_conflict_mark_cleared(void)
{
    int failures = 0;
    TEST("land: a queued row that spent its producer recovery and is "
         "conflicted by a moved main is recorded on that main with the "
         "mark cleared") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512], landdir[1200], outcomes[1300];
        char anchor[128], base[128], line[4096];
        dlx_isolate("qp_mark");
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(dlx_rig_make(&rig, "qp_mark_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        /* Seed: B's producer recovery is spent before the precheck runs. */
        ASSERT(snprintf(anchor, sizeof(anchor), "\"tip\":\"%s\"", b) <
               (int)sizeof(anchor));
        ASSERT(dlx_queue_field_once(anchor, "\"producer_recovered\":0",
                                    "\"producer_recovered\":1"));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        /* The model's own verdict checks. */
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        ASSERT(!dlx_qp_queued_has(b, 1));
        /* The terminal row B lands in outcomes.jsonl: moved base, mark 0. */
        ASSERT(snprintf(outcomes, sizeof(outcomes), "%s/outcomes.jsonl",
                        landdir) < (int)sizeof(outcomes));
        ASSERT(dlx_qp_last_line(outcomes, anchor, line, sizeof(line)));
        ASSERT(strstr(line, "\"producer_recovered\":0") != NULL);
        ASSERT(snprintf(base, sizeof(base), "\"base\":\"%s\"", m1) <
               (int)sizeof(base));
        ASSERT(strstr(line, base) != NULL);
        ASSERT(strstr(line, "detected while queued") != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_regen_only_kept(void)
{
    int failures = 0;
    TEST("land: a queued row whose only conflict is a regenerated artifact "
         "stays queued for the rebase that settles it") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512];
        dlx_isolate("qp_regen");
        ASSERT(dlx_rig_make(&rig, "qp_regen_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "docs/CAPABILITY_INVENTORY.jsonl",
                             "mine\n", "b.txt", "mine\n", b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "docs/CAPABILITY_INVENTORY.jsonl",
                                "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        /* Checked against the new main, and NOT ended. */
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_qp_a_in_flight(m1));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_mergeable_lands(void)
{
    int failures = 0;
    TEST("land: a mergeable queued row is left queued by the check and "
         "later lands") {
        struct dlx_rig rig;
        char b[64], m1[64], remote[64];
        const char *show_b[] = { "show", "main:b.txt", NULL };
        const char *show_o[] = { "show", "main:other.txt", NULL };
        char out[64];
        dlx_isolate("qp_clean");
        ASSERT(dlx_rig_make(&rig, "qp_clean_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        /* Main moves before anything starts, so B's check is a real
         * replay onto a main B was not cut from. */
        ASSERT(dlx_qp_push_main(&rig, "other.txt", "theirs\n", m1));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_a_in_flight(m1));
        /* A lands, then B is rebased, proved and lands in order. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_qp_beat("landed", -1, -1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_beat("started", -1, -1));
        ASSERT(dlx_qp_beat("landed", -1, -1));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT(dlx_git_out(rig.bare, show_b, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "mine");
        ASSERT(dlx_git_out(rig.bare, show_o, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "theirs");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Lines of logs/precheck.log that name `needle`. */
static long dlx_qp_log_count(const char *needle)
{
    static char text[262144];
    char landdir[1200], path[1400];
    size_t len = 0;
    long n = 0;
    char *save = NULL;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(path, sizeof(path), "%s/logs/precheck.log", landdir) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return -1;
    text[len] = '\0';
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save))
        n += strstr(line, needle) != NULL;
    return n;
}

static int test_dev_land_queued_tool_failure_kept(void)
{
    int failures = 0;
    TEST("land: a precheck tool failure leaves the queued row queued and "
         "unmarked, and the next beat asks again") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512];
        dlx_isolate("qp_toolfail");
        ASSERT(dlx_rig_make(&rig, "qp_toolfail_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        /* The merge step itself fails: a real conflict, but no certainty
         * about it, so nothing is ended. */
        setenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL", "1", 1);
        ASSERT(dlx_qp_beat("started", 1, 0));
        unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT_EQ(dlx_qp_log_count("uncertain: merge-tree failed"), 1);
        ASSERT(dlx_qp_a_in_flight(m1));
        /* Main has not moved, yet the row is asked again: an uncertain
         * answer never marks it checked. */
        ASSERT(dlx_qp_beat("proving", 1, 1));
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_main_moves_twice(void)
{
    int failures = 0;
    TEST("land: a queued row is checked once per observed main: clean on the "
         "first new main, ended on the second, never rechecked between") {
        struct dlx_rig rig;
        char b[64], m1[64], m2[64], detail[512];
        dlx_isolate("qp_twice");
        ASSERT(dlx_rig_make(&rig, "qp_twice_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        /* First new main: clean for B. */
        ASSERT(dlx_qp_push_main(&rig, "other.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT_EQ(dlx_qp_log_count(m1), 1);
        /* Unchanged main: no recheck, however many beats. */
        ASSERT(dlx_qp_beat("proving", 0, 0));
        ASSERT(dlx_qp_beat("proving", 0, 0));
        ASSERT_EQ(dlx_qp_log_count(m1), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Second new main: over B's own line. */
        ASSERT(dlx_qp_push_main(&rig, "b.txt", "theirs\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        ASSERT_EQ(dlx_qp_log_count(m2), 1);
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, m2) != NULL);
        ASSERT(strstr(detail, "b.txt") != NULL);
        ASSERT(dlx_qp_a_in_flight(m2));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A branch `name` off origin/main with two commits, `p1` = `b1` then
 * `p2` = `b2`; the clone goes back to its own main afterwards. */
static bool dlx_qp_chain(struct dlx_rig *rig, const char *name,
                         const char *p1, const char *b1, const char *p2,
                         const char *b2, char out[64])
{
    char first[64];
    const char *to_branch[] = { "checkout", "--quiet", "-b", name,
                                "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    return dlx_git(rig->clone, to_branch) == 0 &&
           dlx_write_dep(rig->clone, p1, b1) &&
           dlx_commit_tree(rig->clone, "first", first) &&
           dlx_write_dep(rig->clone, p2, b2) &&
           dlx_commit_tree(rig->clone, "second", out) &&
           dlx_git(rig->clone, back) == 0;
}

/* A merge-bearing branch `name` off origin/main: it and a side branch both
 * add `path` with different bodies, and the merge resolves it by hand.
 * Replayed commit by commit, the side's commit conflicts with the branch's
 * own; the resolved tree does not. */
static bool dlx_qp_merge_row(struct dlx_rig *rig, const char *name,
                             const char *path, char out[64])
{
    char side[64], scratch[64];
    const char *c = rig->clone;
    (void)snprintf(side, sizeof(side), "%s-side", name);
    const char *to_branch[] = { "checkout", "--quiet", "-b", name,
                                "origin/main", NULL };
    const char *merge[] = { "-c", "user.name=land", "-c",
                            "user.email=land@z23.invalid", "merge",
                            "--quiet", "--no-ff", "--no-edit",
                            "--no-gpg-sign", side, NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    if (!dlx_qp_branch(rig, side, path, "side\n", NULL, NULL, scratch) ||
        dlx_git(c, to_branch) != 0 || !dlx_write_dep(c, path, "mine\n") ||
        !dlx_commit_tree(c, "mine", scratch))
        return false;
    /* The merge must stop on the add/add conflict it is built around. */
    if (dlx_git(c, merge) == 0)
        return false;
    return dlx_write_dep(c, path, "resolved\n") &&
           dlx_commit_tree(c, "resolve", out) && dlx_git(c, back) == 0;
}

/* Give queued row `seq` the landing priority `prio` in queue.jsonl, the
 * way a retried row keeps its original place ahead of later requests. */
static bool dlx_qp_prioritise(long long seq, long long prio)
{
    static char text[65536];
    char landdir[1200], qpath[1300], from[64], to[64];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) >=
            (int)sizeof(qpath) ||
        !dlx_slurp(qpath, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    (void)snprintf(from, sizeof(from), "\"seq\":%lld,\"priority_seq\":%lld,",
                   seq, seq);
    (void)snprintf(to, sizeof(to), "\"seq\":%lld,\"priority_seq\":%lld,",
                   seq, prio);
    char *at = strstr(text, from);
    if (!at || strlen(from) != strlen(to))
        return false;
    memcpy(at, to, strlen(to));
    return dlx_write(qpath, text);
}

/* True when the first precheck.log line naming `first` comes before the
 * first line naming `second`. */
static bool dlx_qp_log_before(const char *first, const char *second)
{
    static char text[262144];
    char landdir[1200], path[1400];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(path, sizeof(path), "%s/logs/precheck.log", landdir) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    const char *a = strstr(text, first), *b = strstr(text, second);
    return a && b && a < b;
}

static int test_dev_land_queued_union_attr_kept(void)
{
    int failures = 0;
    TEST("land: a queued row whose overlap main's own union merge attribute "
         "settles is not ended, whatever the landing checkout declares") {
        struct dlx_rig rig;
        char m1[64], m2[64], a[64], b[64], detail[512], landwt[1300];
        char attrs[1400];
        dlx_isolate("qp_union");
        ASSERT(dlx_rig_make(&rig, "qp_union_rig"));
        ASSERT(dlx_qp_push_main(&rig, "u.txt", "base\n", m1));
        ASSERT(dlx_qp_push_main(&rig, ".gitattributes", "u.txt merge=union\n",
                                m1));
        /* A, the row that goes in flight, drops the attribute, so the
         * landing checkout it proves declares no union merge. */
        ASSERT(dlx_qp_branch(&rig, "qp-a", ".gitattributes", "# none\n", NULL,
                             NULL, a));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "u.txt", "base\nb\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start_a(&rig, a, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        /* Main appends its own line where B appends: a conflict under the
         * default merge, clean under main's union attribute, which is
         * what a rebase onto main reads. */
        ASSERT(dlx_qp_push_main(&rig, "u.txt", "base\nm\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT_EQ(dlx_qp_log_count(m2), 1);
        /* The premise held: A proves on the new main with no union. */
        ASSERT(dlx_qp_a_in_flight(m2));
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(snprintf(attrs, sizeof(attrs), "%s/.gitattributes", landwt) <
               (int)sizeof(attrs));
        ASSERT(dlx_qp_file_has(attrs, "# none"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_uncertain_backoff(void)
{
    int failures = 0;
    TEST("land: a queued row that stays uncertain is asked three times per "
         "main, then left for its real rebase until main moves") {
        struct dlx_rig rig;
        char b[64], m1[64], m2[64], detail[512];
        dlx_isolate("qp_backoff");
        ASSERT(dlx_rig_make(&rig, "qp_backoff_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        setenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL", "1", 1);
        ASSERT(dlx_qp_beat_u("started", 1, 0, 1));
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 1));
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 1));
        /* Three strikes on this main: no fourth replay, and one line says
         * so. */
        ASSERT(dlx_qp_beat_u("proving", 0, 0, 0));
        unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
        ASSERT(dlx_qp_beat_u("proving", 0, 0, 0));
        ASSERT_EQ(dlx_qp_log_count("uncertain: merge-tree failed"), 3);
        ASSERT_EQ(dlx_qp_log_count("not rechecked until main moves"), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        /* A new main is a new question. */
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs2\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat_u("started", 1, 1, 0));
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, m2) != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_priority_order(void)
{
    int failures = 0;
    TEST("land: queued rows are checked in the order they will land, not "
         "the order they were written") {
        struct dlx_rig rig;
        char b[64], c[64];
        dlx_isolate("qp_order");
        ASSERT(dlx_rig_make(&rig, "qp_order_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_branch(&rig, "qp-c", "c.txt", "mine\n", NULL, NULL, c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        /* C keeps an earlier place in line than B (a retried row does). */
        ASSERT(dlx_qp_prioritise(3, 1));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_log_before("seq=3 ", "seq=2 "));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_deadline_left(void)
{
    int failures = 0;
    TEST("land: the precheck stops at its per-beat deadline and leaves the "
         "rows it did not reach unmarked for the next beat") {
        struct dlx_rig rig;
        struct dlx_call c;
        char b[64];
        dlx_isolate("qp_deadline");
        ASSERT(dlx_rig_make(&rig, "qp_deadline_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_start(&rig, b));
        setenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS", "0", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_EQ(dlx_int(&c, "queued_prechecked"), 0);
        ASSERT_EQ(dlx_int(&c, "queued_uncertain"), 0);
        ASSERT_EQ(dlx_int(&c, "queued_unchecked"), 1);
        dlx_end(&c);
        unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
        ASSERT_EQ(dlx_qp_log_count("deadline"), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Unmarked: the next beat, on the same main, reaches it. */
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 0));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_chain(void)
{
    int failures = 0;
    TEST("land: a multi-commit queued row is replayed commit on commit: a "
         "commit building on an earlier one is clean, a later commit over "
         "main's change is a conflict") {
        struct dlx_rig rig;
        char b[64], c[64], m1[64], detail[512];
        dlx_isolate("qp_chain");
        ASSERT(dlx_rig_make(&rig, "qp_chain_rig"));
        /* B's second commit edits the file its first commit adds. */
        ASSERT(dlx_qp_chain(&rig, "qp-b", "g.txt", "one\n", "g.txt", "two\n",
                            b));
        /* C's first commit is clean on any main; its second is not. */
        ASSERT(dlx_qp_chain(&rig, "qp-c", "h.txt", "h\n", "seed.txt",
                            "mine\n", c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 2, 1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_qp_outcome(c, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, "seed.txt") != NULL);
        ASSERT(strstr(detail, "h.txt") == NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_merge_tip(void)
{
    int failures = 0;
    TEST("land: a merge-bearing queued row is judged by its resolved tree, "
         "the way the rebase that linearises it replays it") {
        struct dlx_rig rig;
        char b[64], c[64], m1[64], detail[512];
        dlx_isolate("qp_mtip");
        ASSERT(dlx_rig_make(&rig, "qp_mtip_rig"));
        /* Commit by commit, B's two sides collide on f.txt; its merge
         * settled that, and main never touches f.txt. */
        ASSERT(dlx_qp_merge_row(&rig, "qp-b", "f.txt", b));
        /* C is shaped the same on g.txt, and main adds g.txt too. */
        ASSERT(dlx_qp_merge_row(&rig, "qp-c", "g.txt", c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_push_main(&rig, "g.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 2, 1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_qp_outcome(c, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "g.txt") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* (a) true conflict, (b) clean then lands, (c) regenerated artifacts only,
 * (d) tool failure, (e) main moving twice; then main's merge attributes,
 * the uncertain backoff, priority order, the beat deadline, multi-commit
 * chains and merge-bearing tips. */
static int test_dev_land_queued_precheck_cases(void)
{
    int failures = 0;
    failures += test_dev_land_queued_conflict_detected();
    failures += test_dev_land_queued_conflict_mark_cleared();
    failures += test_dev_land_queued_mergeable_lands();
    failures += test_dev_land_queued_regen_only_kept();
    failures += test_dev_land_queued_tool_failure_kept();
    failures += test_dev_land_queued_main_moves_twice();
    failures += test_dev_land_queued_union_attr_kept();
    failures += test_dev_land_queued_uncertain_backoff();
    failures += test_dev_land_queued_priority_order();
    failures += test_dev_land_queued_deadline_left();
    failures += test_dev_land_queued_chain();
    failures += test_dev_land_queued_merge_tip();
    return failures;
}

#endif /* !defined(_WIN32) */
