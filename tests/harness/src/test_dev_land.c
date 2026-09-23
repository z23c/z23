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

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_land_regen.h"
#include "platform/logical_cpu.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include "dev/dev_git_tree.h"
#include "sha3/sha3.h"

/* Hermetic seams from native_dev_land.c (ZCL_TESTING build): the idle-note
 * judgment dl_proof_read applies to a real proof status, and its bound. */
bool zcl_native_dev_land_test_idle_note(int64_t age_s, char *detail,
                                        size_t cap);
int64_t zcl_native_dev_land_test_idle_bound(void);
#if defined(__linux__)
void zcl_native_dev_land_test_watcher_launch(const char *wt,
    const char *scheduler, char *detail, size_t cap);
#endif
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

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
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_PROOF");
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
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
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_PROOF");
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
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
    /* An independent receiver must preserve the admission even when the
     * submitting checkout disappears. Cancelling another row rewrites the
     * queue and must not erase the unavailable request. */
    dlx_submit(&c, rig, rig->tip);
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
    if (!dlx_write_dep(rig->clone, "docs/CAPABILITY_INVENTORY.jsonl",
                       "base\n") ||
        !dlx_write_dep(rig->clone, "docs/API_REFERENCE.md", "base\n") ||
        !dlx_write_dep(rig->clone, "docs/CODEBASE_MAP.md", "base\n"))
        return false;
    if (extra && !dlx_write_dep(rig->clone, extra, "base\n"))
        return false;
    if (!dlx_commit_tree(rig->clone, "generated artifacts", basec))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    /* The submitted tip: its own real work, plus its regeneration of two
     * of the three artifacts. */
    if (!dlx_write_dep(rig->clone, "docs/CAPABILITY_INVENTORY.jsonl",
                       "mine\n") ||
        !dlx_write_dep(rig->clone, "docs/CODEBASE_MAP.md", "mine\n") ||
        !dlx_write_dep(rig->clone, "mine.txt", "mine\n"))
        return false;
    if (extra && !dlx_write_dep(rig->clone, extra, "mine\n"))
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
    if (!dlx_write_dep(rig->clone, "docs/CAPABILITY_INVENTORY.jsonl",
                       "theirs\n") ||
        !dlx_write_dep(rig->clone, "docs/CODEBASE_MAP.md", "theirs\n"))
        return false;
    if (extra && !dlx_write_dep(rig->clone, extra, "theirs\n"))
        return false;
    if (!dlx_commit_tree(rig->clone, "someone else's train", theirs))
        return false;
    return dlx_git(rig->clone, push) == 0;
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

/* The regen phase commits generated-doc drift after a clean rebase and
 * re-requests proof for the new tip. */
static int test_dev_land_regen_commits_drift(void)
{
    int failures = 0;
    TEST("land: the regen phase commits generated-doc drift after a clean "
        "rebase and re-requests proof for the new tip") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1300], subject[512], head[64];
        const char *log_subject[] = { "log", "-1", "--pretty=%s", NULL };
        const char *head_args[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("regendocs_a");
        ASSERT(dlx_rig_make_docregen(
            &rig, "regendocs_a_rig",
            "@printf 'regen\\n' >> docs/CAPABILITY_INVENTORY.jsonl", "@:",
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
        /* Past the regen phase and into the proof: a dirtied generated
         * artifact never became a terminal state. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, log_subject, subject, sizeof(subject)) ==
              0);
        ASSERT(strcmp(subject, "Regenerate generated docs after "
                              "change.txt") == 0);
        /* The proof is requested for the NEW tip, not the pre-regen one:
         * the regen commit sits on top of it. */
        ASSERT(dlx_git_out(landwt, head_args, head, sizeof(head)) == 0);
        ASSERT(strcmp(head, rig.tip) != 0);
        dlx_restore();
        PASS();
    } _test_next:;
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
        ASSERT(strstr(dlx_str(&c, "detail"), "while proving") != NULL);
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
        char landdir[1200], before[64], after[64];
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
        /* No write permission on the land dir itself: dl_rewrite_rows can
         * no longer create queue.jsonl.tmp, but logs/ and wt/ underneath
         * already exist and are untouched, so the rebase and the real
         * push still go through. */
        ASSERT(chmod(landdir, 0500) == 0);
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
             * The hook exits immediately: no FIFO or sleeping orphan. */
            (void)alarm(30);
            (void)snprintf(script, sizeof(script),
                "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
            if (!dlx_write(hook, script) || chmod(hook, 0700) != 0)
                _exit(2);
            dlx_begin(&c, "step");
            (void)dlx_run(&c);
            _exit(3);
        }
        pid_t waited = dlx_wait_child(publisher, &status);
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
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
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
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
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
        zcl_dev_git_tree_free(&tree);
        ASSERT(matched);
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
        ASSERT(dlx_source_binding_drift(&st));
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
    return failures;
}

int test_dev_land(void)
{
    int failures = 0;
    failures += test_dev_land_watcher_admission();
    failures += test_dev_land_long_proof_root();
    failures += test_dev_land_malformed_queue_refusal();
    failures += test_dev_land_malformed_outcome_refusal();
    failures += test_dev_land_exact_tree();
    failures += test_dev_land_source_binding();
#if !defined(_WIN32)
    failures += test_dev_land_tree_types();
    failures += test_dev_land_tree_malformed();
    failures += test_dev_land_tree_replacements();
    failures += test_dev_land_tree_missing();
#endif

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

#if !defined(_WIN32)

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

    TEST("land: queue survives outside HOME from checkout and nested cwd") {
        ASSERT(dlx_queue_outside_home_child());
        PASS();
    }

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

    failures += test_dev_land_explicit_main();

    failures += test_dev_land_missing_main();

    failures += test_dev_land_initial_remote_missing();

    failures += test_dev_land_final_observation_missing();

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

    TEST("land: two submitters at once never interleave a row") {
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
                size_t len = strlen(line);
                while (len > 0 &&
                       (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                if (len == 0)
                    continue;
                nlines++;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                json_free(&v);
            }
            (void)fclose(f);
        }
        ASSERT_EQ((long long)nlines, 2);
        dlx_restore();
        PASS();
    }

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

    failures += test_dev_land_publisher_death();
    failures += test_dev_land_drain_adoption();
    failures += test_dev_land_postpush_observation_missing(false);
    failures += test_dev_land_postpush_observation_missing(true);
    failures += test_dev_land_postpush_result_unconfirmed();
    failures += test_dev_land_expected_base_race();
    failures += test_dev_land_recovery_ignores_replace_refs();
    failures += test_dev_land_nonfastforward_client_guard();
    failures += test_dev_land_lost_persistence();
    failures += test_dev_land_after_proof_restart();
    failures += test_dev_land_terminal_replay();
    failures += test_dev_land_outcome_visible_in_mail();

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
                size_t len = strlen(line);
                const struct json_value *seqv, *statev;
                while (len > 0 &&
                       (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
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

    TEST("land: moving main yields a claimable successor behind other work") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64], following[64];
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
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        /* Every cycle: rebase onto the current tip and ask for the proof
         * ("started"), then a stranger lands on main again before the
         * next step reads the answer, so the receipt is always about a
         * base nobody is on. Before DL_ATTEMPT_MAX capped this specific
         * retry, this loop would run forever and starve the second row.
         * When the bounded attempt budget is exhausted, the original tip
         * must remain queued as a new sequence behind that row. */
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
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

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

    failures += test_dev_land_vendor_dependencies();

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

    failures += test_dev_land_missing_tor_makefile();

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


    TEST("land: a rebase conflict confined to the regenerated artifacts is "
        "resolved from the code and recorded as a signed regeneration "
        "commit, not refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], landwt[1300], subject[512], sig[64];
        const char *log_subject[] = { "log", "-1", "--pretty=%s", NULL };
        const char *log_sig[] = { "log", "-1", "--pretty=%G?", NULL };
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
        ASSERT(strncmp(subject,
                       "Regenerate the capability inventory and codebase "
                       "map after rebasing onto ",
                       strlen("Regenerate the capability inventory and "
                              "codebase map after rebasing onto ")) == 0);
        /* Signed by AMBIENT config: dev.land passes no signing flag, and
         * main rejects an unsigned commit. */
        ASSERT(dlx_git_out(landwt, log_sig, sig, sizeof(sig)) == 0);
        ASSERT(strcmp(sig, "N") != 0);
        unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
        dlx_restore();
        PASS();
    }

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

    failures += test_dev_land_integrated_merge(false);
    failures += test_dev_land_integrated_merge(true);
    failures += test_dev_land_regen_commits_drift();
    failures += test_dev_land_regen_no_commit_when_clean();
    failures += test_dev_land_regen_failure_fails_row();
    failures += test_dev_land_regen_refreshes_plan_on_identical_rewrite();
    failures += test_dev_land_regen_leaves_plan_alone_when_untouched();
    failures += test_dev_land_final_plan_preparation();

#endif /* !defined(_WIN32) */

_test_next:;
    dlx_restore();
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}
