/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: isolated state root, command call, git rigs and shared helpers.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"


/* ── isolated state root ───────────────────────────────────────────────── */

char g_dlx_state[1024];
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
char g_dlx_hooks_ok[1024];
#endif

void dlx_isolate(const char *tag)
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
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
    unsetenv("ZCL_LAND_WINDOW");
    unsetenv("ZCL_LAND_WINDOW_HOST");
    unsetenv("ZCL_LAND_TRAIN_WIDTH");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_TRAIN_BIND");
    /* The vendor/tor submodule fixtures below add a real gitlink pointing
     * at a same-host bare repo; modern git's default transport allowlist
     * otherwise refuses a local `file://`-style remote reached through
     * `git submodule update --init`. This is a process-local env var, not
     * a persistent git config write. */
    setenv("GIT_ALLOW_PROTOCOL", "file:http:https:git:ssh", 1);
    /* The lander refuses a push whose commits carry an identity other than
     * the configured user.email; the fixtures commit as land@z23.invalid, so
     * the global scope names that identity and a repo config can override it. */
    {
        char cfg[600];
        (void)snprintf(cfg, sizeof(cfg), "%s/gitconfig", base);
        FILE *f = fopen(cfg, "w");
        if (f) {
            /* Fixture repos are disposable and no case here tests power-loss
             * durability. Every git write otherwise fsyncs its objects and
             * refs (about 0.4 s per commit on this disk), which dominated the
             * run; core.fsync=none changes no ref, object or result. */
            (void)fputs("[user]\n\tname = land\n\temail = land@z23.invalid\n"
                        "[core]\n\tfsync = none\n", f);
            (void)fclose(f);
            setenv("GIT_CONFIG_GLOBAL", cfg, 1);
        }
    }
#if !defined(_WIN32)
    if (dlx_hooks_dir(g_dlx_hooks_ok, sizeof(g_dlx_hooks_ok), tag, 0))
        setenv("ZCL_LAND_HOOKS_STUB_DIR", g_dlx_hooks_ok, 1);
#endif
}

void dlx_restore(void)
{
    zcl_dev_land_precheck_test_now(0);
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
    unsetenv("ZCL_LAND_DRAIN_IDLE_SEC");
    unsetenv("ZCL_LAND_WINDOW");
    unsetenv("ZCL_LAND_WINDOW_HOST");
    unsetenv("ZCL_LAND_TRAIN_WIDTH");
    unsetenv("ZCL_LAND_TEST_DIE_AFTER_TRAIN_BIND");
    unsetenv("GIT_CONFIG_GLOBAL");
    unsetenv("GIT_ALLOW_PROTOCOL");
}

void dlx_landdir(char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/z23/dev/land", g_dlx_state);
}

/* ── one in-process invocation ─────────────────────────────────────────── */


/* A known verb resolves its registry leaf (dev.land.<verb>) and is validated
 * against that leaf's keys; an unknown or absent verb carries no leaf, and
 * the `action` input reaches the handler as an in-process caller sends it. */
void dlx_begin(struct dlx_call *c, const char *action)
{
    char path[64];
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    if (action && snprintf(path, sizeof(path), "%s.%s", DLX_PATH, action) <
                      (int)sizeof(path))
        c->request.spec =
            zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land.v1");
    if (action && !c->request.spec)
        (void)json_push_kv_str(&c->input, "action", action);
}

bool dlx_run(struct dlx_call *c)
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

void dlx_end(struct dlx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Serialize the actual captured result without dispatching another push. */
const struct zcl_command_reply *g_dlx_captured_reply;

void dlx_captured_handler(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    (void)request;
    json_free(&reply->data);
    *reply = *g_dlx_captured_reply;
    json_init(&reply->data);
    json_copy(&reply->data, &g_dlx_captured_reply->data);
}

bool dlx_refusal_serializes(const struct dlx_call *call)
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
        action && strcmp(action, "z23 dev land step") == 0 &&
        json_get_bool(json_get(error, "retryable")) == call->reply.error.retryable &&
        json_get_bool(json_get(error, "mutated")) == call->reply.error.mutated;
    json_free(&doc);
    return ok;
}

bool dlx_ok(const struct dlx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

const char *dlx_str(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

int64_t dlx_int(const struct dlx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

const struct json_value *dlx_arr(const struct dlx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

const char *dlx_err_code(const struct dlx_call *c)
{
    return c->reply.error.code;
}

const char *dlx_err_evidence(const struct dlx_call *c)
{
    return c->reply.error.evidence;
}

#if !defined(_WIN32)

/* ── a real git rig: a bare origin and a clone ─────────────────────────── */

int dlx_git(const char *dir, const char *const *args)
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

int dlx_git_out(const char *dir, const char *const *args, char *out,
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

bool dlx_write(const char *path, const char *text)
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
bool dlx_mkdir_p(const char *path)
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
bool dlx_write_dep(const char *root, const char *rel,
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
bool dlx_hooks_dir(char *out, size_t cap, const char *tag,
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


/* A commit in the clone whose parent is origin/main, pushed nowhere. */
bool dlx_commit(const char *dir, const char *name, const char *body,
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
bool dlx_rig_make(struct dlx_rig *rig, const char *tag)
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

bool dlx_file_exists(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

/* An installed hook name: a symlink whose target is the one native hook
 * binary, exactly what install_git_hooks.sh lays down and the hooks
 * refresh relinks. */
bool dlx_hook_link(const char *path)
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
bool dlx_plant_hook_bin(const char *dir)
{
    return dlx_write_dep(dir, "build/bin/z23-git-hook", "hook\n");
}

/* Whole-file slurp for a byte-identical before/after comparison. Bounded:
 * queue.jsonl in these tests is a handful of rows, never near this cap. */
bool dlx_slurp(const char *path, char *out, size_t cap, size_t *len)
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
int dlx_step_lock_take(const char *landdir)
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

void dlx_step_lock_release(int fd)
{
    if (fd < 0)
        return;
    (void)flock(fd, LOCK_UN);
    close(fd);
}

/* 1 when another process holds step.lock, 0 when free, -1 when the file
 * is absent or unreadable. Does not create the lock file. */
int dlx_step_held(const char *landdir)
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
bool dlx_gitlink_commit(const char *dir, const char *path,
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

bool dlx_subrepo_make(struct dlx_subrepo *sub, const char *tag)
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
bool dlx_submodule_add(const char *dir, const char *url,
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
bool dlx_submodule_checkout(const char *dir, const char *path,
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

void dlx_submit(struct dlx_call *c, const struct dlx_rig *rig,
                       const char *tip)
{
    dlx_begin(c, "submit");
    (void)json_push_kv_str(&c->input, "tip", tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
}

bool dlx_queue_has_one(void)
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

bool dlx_exact_submit_retry(void)
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

bool dlx_queue_empty(void)
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
bool dlx_exact_submit_mid_rebase_refused(void)
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
        strcmp(c.reply.error.code, "WORKTREE_BUSY") == 0 &&
        strcmp(c.reply.error.evidence, mark) == 0;
    dlx_end(&c);
    if (unlink(path) != 0)
        return false;
    ok = ok && dlx_queue_empty();
    return ok;
}

bool dlx_submit_operation_markers_refused(void)
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

bool dlx_marker_batch_clean(void)
{
    struct dlx_rig rig;
    bool ok = false;
    dlx_isolate("marker_batch_clean");
    if (!dlx_rig_make(&rig, "marker_batch_clean_rig")) goto done;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    struct dlx_call c;
    dlx_submit(&c, &rig, rig.tip);
    uint64_t before = zcl_spawn_thread_launch_count();
    bool ran = dlx_run(&c);
    uint64_t launched = zcl_spawn_thread_launch_count() - before;
    ok = ran && dlx_ok(&c) && launched == 4;
    printf("marker batch clean: launches=%llu expected=4\n", (unsigned long long)launched);
    dlx_end(&c);
    ok = ok && dlx_queue_has_one();
done:
    dlx_restore();
    return ok;
}

static bool dlx_marker_batch_bad_cases(struct dlx_rig *rig)
{
    static const struct { const char *text; int rc; } cases[] = {
        {"unsupported", 129}, {"", 0}, {"one\ntwo\nthree\nfour\nfive\n", 0},
        {"one\n\nthree\nfour\nfive\nsix\n", 0},
        {"one\ntwo\nthree\nfour\nfive\nsix\nextra\n", 0},
        {"one\ntwo\nthree\nfour\nfive\nsix", 0},
        {"one\ntwo\nthree\nfour\nfive\nsix \n", 0},
        {"one\ntwo\nthree\nfour\nfive\nsix\t\n", 0},
        {"one\ntwo\nthree\nfour\nfive\nsix\r\n", 0},
        {"one\ntwo\nthree\nfour\nfive\nsi\177x\n", 0},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        zcl_native_dev_land_test_marker_batch(cases[i].text, cases[i].rc);
        bool ok = dlx_submit_marker_refused(rig, "sequencer");
        zcl_native_dev_land_test_marker_batch(NULL, 0);
        if (!ok) return false;
    }
    return true;
}

static bool dlx_marker_batch_long_cases(struct dlx_rig *rig)
{
    char *text = zcl_malloc(6 * 4096 + 1, "land_marker_batch_fixture");
    if (!text) return false;
    memset(text, 'x', 4096);
    (void)snprintf(text + 4096, 6 * 4096 + 1 - 4096, "\ntwo\nthree\nfour\nfive\nsix\n");
    zcl_native_dev_land_test_marker_batch(text, 0);
    bool ok = dlx_submit_marker_refused(rig, "sequencer");
    memset(text, 'x', 6 * 4096);
    text[6 * 4096] = '\0';
    zcl_native_dev_land_test_marker_batch(text, 0);
    ok = dlx_submit_marker_refused(rig, "sequencer") && ok;
    zcl_native_dev_land_test_marker_batch(NULL, 0);
    free(text);
    return ok;
}

bool dlx_marker_batch_fallback(void)
{
    struct dlx_rig rig;
    bool ok = false;
    dlx_isolate("marker_batch_fallback");
    if (!dlx_rig_make(&rig, "marker_batch_fallback_rig")) goto done;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    ok = dlx_marker_batch_bad_cases(&rig) && dlx_marker_batch_long_cases(&rig);
done:
    zcl_native_dev_land_test_marker_batch(NULL, 0);
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

static bool dlx_disjoint_home(const char *base, char *root, size_t cap)
{
    char home[4096];
    if ((size_t)snprintf(home, sizeof(home), "%s/home", base) >= sizeof(home) ||
        (size_t)snprintf(root, cap, "%s/checkout", base) >= cap)
        return false;
    if (!dlx_mkdir_p(home) || !dlx_mkdir_p(root))
        return false;
    return setenv("HOME", home, 1) == 0 && dlx_outside_home(root);
}

/* Run only in a child. The temporary directory may lie anywhere, including
 * under the real home, so the case builds its own: HOME is a fresh sibling of
 * the checkout, which makes "the checkout is outside HOME" true by
 * construction. HOME is set before dlx_isolate() and the rig derive state. */
bool dlx_queue_outside_home(const char *base)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char receiver[4096], root[4096];
    if (!dlx_disjoint_home(base, root, sizeof(root)))
        return false;
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

bool dlx_run_in_child(bool (*body)(const char *base))
{
    char root[PLATFORM_TEMP_PATH_MAX];
    int status = 0;
    if (!platform_temp_directory_create("z23-land-outside-home-", root, sizeof(root)))
        return false;
    pid_t child = fork();
    if (child == 0)
        _exit(body(root) ? 0 : 1);
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    int cleanup = test_rm_rf_recursive(root);
    return child > 0 && waited == child && cleanup == 0 &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool dlx_plant_checkout_markers(const char *root)
{
    return dlx_write_dep(root, "Makefile", "# fixture\n") &&
        dlx_write_dep(root, "engine/composition/commands/root.def", "// fixture\n") &&
        dlx_write_dep(root, "tools/dev/test_group_catalog.def", "// fixture\n");
}

/* Submit with no worktree input, so the leaf discovers the checkout from cwd. */
static bool dlx_submit_discovered(const char *tip)
{
    struct dlx_call c;
    dlx_begin(&c, "submit");
    (void)json_push_kv_str(&c.input, "tip", tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static int dlx_queue_count(const char *needle)
{
    char landdir[1024], path[1100], rows[65536];
    int n = 0;
    dlx_landdir(landdir, sizeof(landdir));
    if ((size_t)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir) >= sizeof(path) ||
        !dlx_slurp(path, rows, sizeof(rows), NULL))
        return -1;
    for (const char *p = strstr(rows, needle); p; p = strstr(p + 1, needle))
        n++;
    return n;
}

/* Run only in a child. Checkout discovery from the checkout root must queue
 * the absolute checkout path; a relative answer is dropped by the row loader.
 * The nested-directory case is dlx_discovery_nested. */
bool dlx_discovery_checkout(const char *base)
{
    struct dlx_rig rig;
    char root[4096], canon[4096], needle[4200];
    if (!dlx_disjoint_home(base, root, sizeof(root)) || chdir(root) != 0)
        return false;
    dlx_isolate("discovery");
    if (!dlx_rig_make(&rig, "discovery_rig") ||
        !dlx_plant_checkout_markers(rig.clone) ||
        !platform_directory_canonical_real(rig.clone, canon, sizeof(canon)) ||
        (size_t)snprintf(needle, sizeof(needle), "\"worktree\":\"%s\"", canon) >=
            sizeof(needle) ||
        chdir(rig.clone) != 0)
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_submit_discovered(rig.tip) && dlx_queue_count(needle) == 1;
}

static bool dlx_submit_refused_no_checkout(const char *tip)
{
    struct dlx_call c;
    dlx_begin(&c, "submit");
    (void)json_push_kv_str(&c.input, "tip", tip);
    (void)dlx_run(&c);
    bool refused = strcmp(dlx_err_code(&c), "NO_CHECKOUT") == 0;
    dlx_end(&c);
    return refused;
}

/* Run only in a child. Submitted without a worktree from a directory below the
 * checkout root, the leaf walks up from the real working directory and queues
 * the absolute root; from a directory inside no checkout it refuses by name. */
bool dlx_discovery_nested(const char *base)
{
    struct dlx_rig rig;
    char root[4096], canon[4096], needle[4200], nowhere[4200];
    if (!dlx_disjoint_home(base, root, sizeof(root)) || chdir(root) != 0)
        return false;
    dlx_isolate("discovery_nested");
    if (!dlx_rig_make(&rig, "discovery_nested_rig") ||
        !dlx_plant_checkout_markers(rig.clone) ||
        !platform_directory_canonical_real(rig.clone, canon, sizeof(canon)) ||
        (size_t)snprintf(needle, sizeof(needle), "\"worktree\":\"%s\"", canon) >=
            sizeof(needle) ||
        (size_t)snprintf(nowhere, sizeof(nowhere), "%s/nowhere", base) >= sizeof(nowhere) ||
        !dlx_mkdir_p(nowhere))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (chdir(nowhere) != 0 || !dlx_submit_refused_no_checkout(rig.tip))
        return false;
    return chdir(rig.clone) == 0 && chdir("engine/composition") == 0 &&
        dlx_submit_discovered(rig.tip) && dlx_queue_count(needle) == 1;
}

/* Run only in a child. A proof tree outside HOME but beside the checkout is
 * steppable: the step policy admits a worktree under the checkout's parent. */
bool dlx_step_beside_checkout(const char *base)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char root[4096], proofs[4096];
    if (!dlx_disjoint_home(base, root, sizeof(root)) ||
        (size_t)snprintf(proofs, sizeof(proofs), "%s/proofs", base) >= sizeof(proofs) ||
        !dlx_mkdir_p(proofs) || chdir(proofs) != 0)
        return false;
    dlx_isolate("step_beside");
    if (!dlx_rig_make(&rig, "step_beside_rig") || !dlx_plant_checkout_markers(root))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, &rig, rig.tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || chdir(root) != 0)
        return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) && strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    return ok;
}

/* origin/main as the bare repo itself reports it. */
bool dlx_origin_main(const struct dlx_rig *rig, char out[64])
{
    const char *args[] = { "rev-parse", "main", NULL };
    return dlx_git_out(rig->bare, args, out, 64) == 0 && strlen(out) == 40;
}

/* Commit whatever is in `dir`'s working tree under `msg`. Unlike
 * dlx_commit() this plants no file of its own: the caller has already
 * written the paths it wants recorded (docs/... through dlx_write_dep()),
 * which is what a generated-artifact conflict fixture needs. */
bool dlx_commit_tree(const char *dir, const char *msg, char out[64])
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
bool dlx_submodule_uninit(const char *dir, const char *path)
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

 * flag of its own. */
bool dlx_sign_arm(const char *dir, const char *tag)
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
static bool dlx_generated_files(struct dlx_rig *rig, const char *body,
                            const char *map_body, const char *third,
                            const char *extra)
{
    return dlx_write_dep(rig->clone, "docs/agent/EXECUTOR_HEURISTICS.md", body) &&
           dlx_write_dep(rig->clone, "docs/dev/CODEBASE_MAP.md", map_body) &&
           (!third || dlx_write_dep(rig->clone, third, body)) &&
           (!extra || dlx_write_dep(rig->clone, extra, body));
}

/* A rig whose origin and whose submitted tip regenerate the SAME generated
 * artifacts differently, so `git rebase origin/main` reports exactly those
 * paths as unmerged. `extra` (may be NULL) is one more path both sides
 * change, for the mixed-conflict case that must stay a plain conflict.
 * `out_tip` receives the tip to submit. */
bool dlx_generated_conflict(struct dlx_rig *rig, const char *extra,
                               char out_tip[64])
{
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *branch[] = { "branch", "keep-tip", NULL };
    char basec[64], theirs[64];
    const char *reset[] = { "reset", "--quiet", "--hard", basec, NULL };
    /* A shared base both sides agree on, on origin/main. */
    if (!dlx_generated_files(rig, "base\n",
            "<!-- DOC-COUNTS-BEGIN -->\nbase\n<!-- DOC-COUNTS-END -->\n",
            "mine.txt", extra))
        return false;
    if (!dlx_commit_tree(rig->clone, "generated artifacts", basec))
        return false;
    if (dlx_git(rig->clone, push) != 0)
        return false;
    /* The submitted tip: its own real work, plus its regeneration of two
     * of the three artifacts. */
    if (!dlx_generated_files(rig, "mine\n",
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
    if (!dlx_generated_files(rig, "theirs\n",
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
bool dlx_rerere_autoupdate_prime(struct dlx_rig *rig)
{
    char upstream[64], unmerged[512];
    const char *enable[] = { "config", "rerere.enabled", "true", NULL };
    const char *autoupdate[] = { "config", "rerere.autoupdate", "true", NULL };
    const char *merge[] = { "merge", "--no-ff", "keep-tip", NULL };
    const char *ours[] = { "checkout", "--ours", "--",
                           "docs/agent/EXECUTOR_HEURISTICS.md",
                           "docs/dev/CODEBASE_MAP.md", NULL };
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
void dlx_land_wt(char *out, size_t cap)
{
    char land[1200];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(out, cap, "%s/wt", land);
}

#endif /* !defined(_WIN32) */
