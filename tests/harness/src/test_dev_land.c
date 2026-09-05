/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.land (tools/command/native_dev_land.c).
 *
 * THE PROPERTY THIS GROUP EXISTS FOR: nothing waits. Every case below runs
 * against an isolated XDG_STATE_HOME and a real git rig — a bare "origin"
 * plus a clone — so it proves the queue's behavior rather than the state of
 * this machine. The exact proof is the ONE thing replaced, by
 * ZCL_LAND_PROOF_STUB: a case that ran a real 15-minute proof would be a
 * test of the proof, not of the queue. Every rebase, push, row, and lock
 * exercised here is the production path.
 *
 * The handler is called DIRECTLY, which is exactly what the CLI does after
 * input validation — and the input is additionally validated through the
 * real registry first, so a key the .def never declared is caught here
 * rather than passing in-process and failing from a shell.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <errno.h>
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
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
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
    unsetenv("ZCL_LAND_REGEN_MAKE_STUB");
    unsetenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
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

#endif /* !defined(_WIN32) */

int test_dev_land(void);
int test_dev_land(void)
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
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
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

    TEST("land: a base that keeps moving is bounded, not infinite") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64];
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
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        /* Every cycle: rebase onto the current tip and ask for the proof
         * ("started"), then a stranger lands on main again before the
         * next step reads the answer, so the receipt is always about a
         * base nobody is on. Before DL_ATTEMPT_MAX capped this specific
         * retry, this loop would run forever and starve every other
         * queued row (this one is always picked first: dl_step prefers
         * "inflight" over "queued"). */
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
            if (strcmp(dlx_str(&c, "state"), "failed") == 0) {
                ASSERT(strcmp(dlx_str(&c, "dimension"), "rebase") == 0);
                done = true;
            } else {
                ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
            }
            dlx_end(&c);
        }
        ASSERT(done);
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
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
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

    TEST("land: the landing worktree gets the proof's vendored "
        "dependencies from the submitting checkout") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400];
        struct stat st;
        dlx_isolate("depsok");
        ASSERT(dlx_rig_make(&rig, "depsok_rig"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
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
         * see dl_deps_test_force()'s comment in native_dev_land.c. */
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
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a",
                       wt);
        ASSERT(stat(check, &st) == 0);
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

#endif /* !defined(_WIN32) */

_test_next:;
    dlx_restore();
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}
