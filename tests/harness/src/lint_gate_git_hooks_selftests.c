/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the git-hook installer and the receipt hooks it arms:
 * worktree scope, relative core.hooksPath, idempotence, the refresh step that
 * keeps an armed checkout current without arming an idle one, the quiet
 * post-commit contract, and the Makefile bootstrap goal filter. Every case
 * runs against real Git in a private repository under test-tmp/ with an
 * isolated environment; this checkout's configuration is never touched. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

#include <sys/file.h>

static int dip_join(char *out, size_t cap, const char *dir, const char *leaf)
{
    return snprintf(out, cap, "%s/%s", dir, leaf) >= (int)cap;
}

/* ── install_git_hooks.sh: worktree scope, relative hooksPath, idempotence ──
 * Real git in a private repository under test-tmp/. The installer runs as a
 * child whose ZCL_GIT_HOOK_* seams point at that repository, and every git
 * call runs with an isolated environment, so this checkout's configuration
 * is never read or written. */
#define HOOKS_BASE_PREFIX "test-tmp/_git_hooks_installer"
#define HOOKS_NATIVE_REL "build/bin/z23-git-hook"
#define HOOKS_SCRIPT_REL "tools/scripts/install_git_hooks.sh"
#define HOOKS_SHARED "sentinel-shared-hooks"
#define HOOKS_ARMED "build/githooks"
#define HOOKS_KV_CAP (PATH_MAX + 64)
#define HOOKS_ARGV_MAX 32
#define HOOKS_OUT_CAP 4096
#define HOOKS_ENV_MAX 12

struct hooks_env {
    char kv[10][HOOKS_KV_CAP];
    const char *vp[11];
};

struct hooks_fx {
    char base[PATH_MAX], src[PATH_MAX], bin[PATH_MAX], script[PATH_MAX];
    char repo[PATH_MAX], wt_a[PATH_MAX], wt_b[PATH_MAX], wt_c[PATH_MAX];
    char rig[PATH_MAX], rig_b[PATH_MAX];
    struct hooks_env genv, ienv;
    const char *extra_env; /* one more KEY=VALUE for hooks_git, or NULL */
    const char *bin_use;   /* hook binary override for hooks_env_build */
    char rebuilt[PATH_MAX];
};

static const char *const k_eff_hooks[] = {"config", "--get",
                                          "core.hooksPath", NULL};
static const char *const k_shared_hooks[] = {"config", "--local", "--get",
                                             "core.hooksPath", NULL};
static const char *const k_commit[] = {"commit", "-q", "--allow-empty",
                                       "-m", "probe", NULL};

static int hooks_kv(char *dst, const char *key, const char *val)
{
    int n = snprintf(dst, HOOKS_KV_CAP, "%s=%s", key, val);
    return (n < 0 || n >= (int)HOOKS_KV_CAP) ? -1 : 0;
}

/* Git-only environment when root is NULL; the installer adds its seams. */
static int hooks_env_build(struct hooks_env *e, const struct hooks_fx *fx,
                           const char *root)
{
    static const char *const fixed[][2] = {
        {"LC_ALL", "C"}, {"GIT_CONFIG_NOSYSTEM", "1"},
        {"GIT_CONFIG_GLOBAL", "/dev/null"}, {"GIT_TERMINAL_PROMPT", "0"},
    };
    const char *path = getenv("PATH");
    size_t n = 0, i;
    if (!path)
        path = "/usr/bin:/bin";
    if (hooks_kv(e->kv[n++], "PATH", path)
        || hooks_kv(e->kv[n++], "HOME", fx->base))
        return -1;
    for (i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
        if (hooks_kv(e->kv[n++], fixed[i][0], fixed[i][1]))
            return -1;
    if (root && (hooks_kv(e->kv[n++], "ZCL_GIT_HOOK_SOURCE_ROOT", fx->src)
                 || hooks_kv(e->kv[n++], "ZCL_GIT_HOOK_ROOT", root)
                 || hooks_kv(e->kv[n++], "ZCL_GIT_HOOK_NATIVE_BIN",
                         fx->bin_use ? fx->bin_use : fx->bin)
                 || hooks_kv(e->kv[n++], "ZCL_GIT_HOOK_HOST", "posix")))
        return -1;
    for (i = 0; i < n; i++)
        e->vp[i] = e->kv[i];
    e->vp[n] = NULL;
    return 0;
}

static int hooks_fx_base(struct hooks_fx *fx, const char *prefix)
{
    const char *root = repo_root();
    if (!root || repo_path_pid(fx->base, sizeof fx->base, prefix, "") != 0)
        return 1;
    if (snprintf(fx->src, sizeof fx->src, "%s", root) >= (int)sizeof fx->src)
        return 1;
    if (repo_path(fx->bin, sizeof fx->bin, HOOKS_NATIVE_REL) != 0
        || repo_path(fx->script, sizeof fx->script, HOOKS_SCRIPT_REL) != 0)
        return 1;
    (void)test_rm_rf_recursive(fx->base);
    if (mkdir(fx->base, 0755) != 0)
        return 1;
    return hooks_env_build(&fx->genv, fx, NULL);
}

extern char **environ;

/* fork+exec with an explicit environment, stdout and stderr captured into
 * out. The child swaps its own environ before execvp so PATH lookup uses the
 * isolated block. Returns the exit code, or -1 on harness error. */
static int hooks_spawn(const char *const argv[], const char *const envp[],
                       char *out, size_t cap)
{
    int pfd[2], status = 0;
    size_t used = 0;
    ssize_t got;
    pid_t pid;
    if (cap == 0 || pipe(pfd) != 0)
        return -1;
    pid = fork_with_retry();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pfd[0]);
        if (dup2(pfd[1], STDOUT_FILENO) < 0 || dup2(pfd[1], STDERR_FILENO) < 0)
            _exit(127);
        close(pfd[1]);
        environ = (char **)envp;
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    while (used + 1 < cap) {
        got = read(pfd[0], out + used, cap - 1 - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        used += (size_t)got;
    }
    out[used] = '\0';
    close(pfd[0]);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static struct hooks_fx *hooks_fx_new(void)
{
    return calloc(1, sizeof(struct hooks_fx));
}

static void hooks_fx_free(struct hooks_fx *fx)
{
    if (!fx)
        return;
    if (fx->base[0])
        (void)test_rm_rf_recursive(fx->base);
    free(fx);
}

/* Runs git with the fixed identity and signing off; returns the exit code,
 * or -1 on harness error, with combined output captured into out. */
static int hooks_git(const struct hooks_fx *fx, const char *dir,
                     const char *const args[], char *out, size_t cap)
{
    const char *argv[HOOKS_ARGV_MAX];
    const char *lead[] = {"git", "-C", dir, "-c", "commit.gpgsign=false",
                          "-c", "user.name=z23", "-c", "user.email=z23@invalid"};
    size_t n = 0, i;
    for (i = 0; i < sizeof lead / sizeof lead[0]; i++)
        argv[n++] = lead[i];
    for (i = 0; args[i]; i++) {
        if (n + 1 >= HOOKS_ARGV_MAX)
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (fx->extra_env) {
        const char *envp[HOOKS_ENV_MAX];
        for (n = 0; fx->genv.vp[n] && n + 2 < HOOKS_ENV_MAX; n++)
            envp[n] = fx->genv.vp[n];
        envp[n++] = fx->extra_env;
        envp[n] = NULL;
        return hooks_spawn(argv, envp, out, cap);
    }
    return hooks_spawn(argv, fx->genv.vp, out, cap);
}

static int hooks_git_ok(const struct hooks_fx *fx, const char *dir,
                        const char *const args[])
{
    char out[HOOKS_OUT_CAP];
    return hooks_git(fx, dir, args, out, sizeof out) == 0 ? 0 : 1;
}

/* Reads a config value (empty when unset) with its trailing newline cut. */
static int hooks_value(const struct hooks_fx *fx, const char *dir,
                       const char *const args[], char *value, size_t cap)
{
    size_t n;
    if (hooks_git(fx, dir, args, value, cap) < 0)
        return -1;
    n = strlen(value);
    while (n && (value[n - 1] == '\n' || value[n - 1] == '\r'))
        value[--n] = '\0';
    return 0;
}

static int hooks_expect(const struct hooks_fx *fx, const char *dir,
                        const char *const args[], const char *want,
                        const char *what)
{
    char got[PATH_MAX];
    got[0] = '\0';
    if (hooks_value(fx, dir, args, got, sizeof got) == 0
        && strcmp(got, want) == 0)
        return 0;
    fprintf(stderr, "installer selftest: %s: got '%s' want '%s'\n", what, got,
            want);
    return 1;
}

static int hooks_repo_seed(const struct hooks_fx *fx, const char *repo)
{
    const char *const init[] = {"init", "-q", repo, NULL};
    const char *const seed[] = {"commit", "-q", "--allow-empty", "-m", "seed",
                                NULL};
    if (hooks_git_ok(fx, fx->base, init))
        return 1;
    return hooks_git_ok(fx, repo, seed);
}

static int hooks_wt_add(const struct hooks_fx *fx, const char *repo,
                        const char *branch, const char *path)
{
    const char *const args[] = {"worktree", "add", "-q", "-b", branch, path,
                                NULL};
    return hooks_git_ok(fx, repo, args);
}

static int hooks_install(struct hooks_fx *fx, const char *target, char *out,
                         size_t cap)
{
    const char *argv[] = {fx->script, NULL};
    if (hooks_env_build(&fx->ienv, fx, target) != 0)
        return -1;
    return hooks_spawn(argv, fx->ienv.vp, out, cap);
}

static int hooks_hook_armed(const char *target)
{
    char pre[PATH_MAX];
    if (dip_join(pre, sizeof pre, target, HOOKS_ARMED "/pre-push"))
        return 1;
    return access(pre, X_OK) == 0 ? 0 : 1;
}

/* Installs into target and checks the report, the scope and that the
 * installed pre-push hook is executable. Returns 0 only when all hold. */
static int hooks_install_check(struct hooks_fx *fx, const char *target)
{
    char out[HOOKS_OUT_CAP];
    int rc = hooks_install(fx, target, out, sizeof out);
    if (rc != 0) {
        fprintf(stderr, "installer selftest: install in %s exited %d: %s\n",
                target, rc, out);
        return 1;
    }
    if (!strstr(out, "core.hooksPath  " HOOKS_ARMED)
        || !strstr(out, "config.worktree")) {
        fprintf(stderr, "installer selftest: report for %s omits the path or "
                        "scope it wrote\n", target);
        return 1;
    }
    return hooks_hook_armed(target);
}

static int hooks_wt_cfg(const struct hooks_fx *fx, const char *wt, char *path,
                        size_t cap)
{
    const char *const gdir_args[] = {"rev-parse", "--absolute-git-dir", NULL};
    char gdir[PATH_MAX];
    gdir[0] = '\0';
    if (hooks_value(fx, wt, gdir_args, gdir, sizeof gdir) != 0 || !gdir[0])
        return 1;
    return dip_join(path, cap, gdir, "config.worktree");
}

/* Byte-compares a file with a snapshot taken earlier; false when either is
 * missing. */
static int hooks_snap_same(const char *path, const char *before)
{
    char *now = NULL;
    int same = 0;
    if (before && read_entire_file(path, &now) == 0 && now
        && strcmp(now, before) == 0)
        same = 1;
    free(now);
    return same;
}

static int hooks_repo_fixture(struct hooks_fx *fx, const char *prefix)
{
    int bad = 0;
    bad |= hooks_fx_base(fx, prefix);
    bad |= dip_join(fx->repo, sizeof fx->repo, fx->base, "repo");
    bad |= dip_join(fx->wt_a, sizeof fx->wt_a, fx->base, "wt-a");
    bad |= dip_join(fx->wt_b, sizeof fx->wt_b, fx->base, "wt-b");
    bad |= dip_join(fx->wt_c, sizeof fx->wt_c, fx->base, "wt-c");
    if (bad)
        return 1;
    bad |= hooks_repo_seed(fx, fx->repo);
    {
        const char *const shared[] = {"config", "--local", "core.hooksPath",
                                      HOOKS_SHARED, NULL};
        bad |= hooks_git_ok(fx, fx->repo, shared);
    }
    bad |= hooks_wt_add(fx, fx->repo, "wt-a", fx->wt_a);
    bad |= hooks_wt_add(fx, fx->repo, "wt-b", fx->wt_b);
    bad |= hooks_wt_add(fx, fx->repo, "wt-c", fx->wt_c);
    return bad;
}

/* Arms wt-a, then wt-b. Neither install may change the other's worktree
 * scope: the snapshot of wt-a's config.worktree and its armed hook must
 * survive the install in wt-b, and the shared value must never move. An
 * installer that unset core.hooksPath unscoped, or wrote into another
 * worktree, fails here. */
static int hooks_disarm_check(struct hooks_fx *fx, const char *snap_path,
                              const char *snap)
{
    int bad = 0;
    bad |= hooks_expect(fx, fx->wt_a, k_eff_hooks, HOOKS_ARMED,
                        "wt-a after an install in wt-b");
    bad |= !hooks_snap_same(snap_path, snap);
    bad |= hooks_hook_armed(fx->wt_a);
    return bad;
}

static int hooks_scope_checks(struct hooks_fx *fx)
{
    char cfg_a[PATH_MAX], *snap = NULL;
    int bad = 0;
    if (hooks_wt_cfg(fx, fx->wt_a, cfg_a, sizeof cfg_a) != 0)
        return 1;
    bad |= hooks_install_check(fx, fx->wt_a);
    bad |= hooks_expect(fx, fx->wt_a, k_eff_hooks, HOOKS_ARMED,
                        "wt-a after its install");
    bad |= hooks_expect(fx, fx->repo, k_shared_hooks, HOOKS_SHARED,
                        "shared value after the wt-a install");
    (void)read_entire_file(cfg_a, &snap);
    bad |= hooks_install_check(fx, fx->wt_b);
    bad |= hooks_disarm_check(fx, cfg_a, snap);
    bad |= hooks_expect(fx, fx->wt_b, k_eff_hooks, HOOKS_ARMED,
                        "wt-b after its install");
    bad |= hooks_expect(fx, fx->repo, k_shared_hooks, HOOKS_SHARED,
                        "shared value after the wt-b install");
    bad |= hooks_expect(fx, fx->wt_c, k_eff_hooks, HOOKS_SHARED,
                        "never-installed wt-c");
    free(snap);
    return bad;
}

static int hooks_idempotent_checks(struct hooks_fx *fx)
{
    char cfg_a[PATH_MAX], out[HOOKS_OUT_CAP], *before = NULL;
    int bad = 0;
    if (hooks_wt_cfg(fx, fx->wt_a, cfg_a, sizeof cfg_a) != 0)
        return 1;
    bad |= hooks_install_check(fx, fx->wt_a);
    (void)read_entire_file(cfg_a, &before);
    bad |= hooks_install(fx, fx->wt_a, out, sizeof out) != 0;
    bad |= !hooks_snap_same(cfg_a, before);
    free(before);
    return bad;
}

/* Writes a marker pre-commit hook into wt, then makes one commit there so
 * Git runs whatever hooksPath resolves to in that worktree. */
static int hooks_mark_hook(const struct hooks_fx *fx, const char *wt,
                           const char *name)
{
    char build[PATH_MAX], dir[PATH_MAX], hook[PATH_MAX], body[PATH_MAX + 128];
    if (dip_join(build, sizeof build, wt, "build") != 0
        || dip_join(dir, sizeof dir, wt, "build/githooks") != 0
        || dip_join(hook, sizeof hook, dir, "pre-commit") != 0)
        return 1;
    if (mkdir(build, 0755) != 0 || mkdir(dir, 0755) != 0)
        return 1;
    if (snprintf(body, sizeof body,
                 "#!/bin/sh\nprintf %%s \"$PWD\" > \"%s/mark.%s\"\n",
                 fx->base, name) >= (int)sizeof body)
        return 1;
    if (write_file(hook, body) != 0 || chmod(hook, 0755) != 0)
        return 1;
    return hooks_git_ok(fx, wt, k_commit);
}

/* The marker written by the hook must name its own worktree, so each one
 * resolved the relative value against itself. */
static int hooks_mark_check(const struct hooks_fx *fx, const char *name)
{
    char path[PATH_MAX], *buf = NULL;
    size_t n = strlen(name), m;
    int ok = 0;
    if (snprintf(path, sizeof path, "%s/mark.%s", fx->base, name)
        >= (int)sizeof path)
        return 1;
    if (read_entire_file(path, &buf) == 0 && buf) {
        m = strlen(buf);
        ok = m > n && buf[m - n - 1] == '/' && strcmp(buf + m - n, name) == 0;
    }
    free(buf);
    return ok ? 0 : 1;
}

static int hooks_relative_checks(struct hooks_fx *fx)
{
    const char *const armed[] = {"config", "--local", "core.hooksPath",
                                 HOOKS_ARMED, NULL};
    int bad = 0;
    if (hooks_fx_base(fx, HOOKS_BASE_PREFIX "_relative") != 0)
        return 1;
    bad |= dip_join(fx->rig, sizeof fx->rig, fx->base, "rig");
    bad |= dip_join(fx->rig_b, sizeof fx->rig_b, fx->base, "rig-b");
    if (bad)
        return 1;
    bad |= hooks_repo_seed(fx, fx->rig);
    bad |= hooks_git_ok(fx, fx->rig, armed);
    bad |= hooks_wt_add(fx, fx->rig, "rig-b", fx->rig_b);
    bad |= hooks_mark_hook(fx, fx->rig, "rig");
    bad |= hooks_mark_hook(fx, fx->rig_b, "rig-b");
    bad |= hooks_mark_check(fx, "rig");
    bad |= hooks_mark_check(fx, "rig-b");
    return bad;
}

int t_git_hooks_installer_scope(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_repo_fixture(fx, HOOKS_BASE_PREFIX "_scope") : 1;
    TEST("[lint-gate] installer arms only its own worktree and keeps the "
         "shared hooksPath") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_scope_checks(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_installer_relative_hooks_path(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    TEST("[lint-gate] relative core.hooksPath resolves against each worktree") {
        ASSERT(fx != NULL);
        ASSERT(hooks_relative_checks(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_installer_idempotent(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_repo_fixture(fx, HOOKS_BASE_PREFIX "_idem") : 1;
    TEST("[lint-gate] a second installer run rewrites no worktree config") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_idempotent_checks(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

/* ── refresh: an armed checkout follows a rebuilt hook binary, an idle one
 * is never armed ───────────────────────────────────────────────────────── */
#define HOOKS_REFRESH_REL "tools/scripts/refresh_git_hooks_if_armed.sh"
#define HOOKS_INSTALLED_REL "build/githooks/z23-git-hook"
#define HOOKS_CHUNK 4096

static int hooks_same_bytes(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int same = fa && fb;
    while (same) {
        unsigned char ba[HOOKS_CHUNK], bb[HOOKS_CHUNK];
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0)
            same = 0;
        else if (na == 0)
            break;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return same;
}

/* A rebuild stand-in: the real hook bytes plus a trailing marker. */
static int hooks_rebuild_copy(struct hooks_fx *fx)
{
    unsigned char buf[HOOKS_CHUNK];
    FILE *in = fopen(fx->bin, "rb"), *out;
    size_t n;
    int bad = 0;
    if (dip_join(fx->rebuilt, sizeof fx->rebuilt, fx->base,
                 "z23-git-hook.rebuilt") != 0 || !in) {
        if (in)
            fclose(in);
        return 1;
    }
    out = fopen(fx->rebuilt, "wb");
    if (!out) {
        fclose(in);
        return 1;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        bad |= fwrite(buf, 1, n, out) != n;
    bad |= fputs("rebuilt\n", out) < 0;
    fclose(in);
    bad |= fclose(out) != 0;
    return bad | (chmod(fx->rebuilt, 0755) != 0); /* the refresh needs -x */
}

/* Runs the refresh step against root with the rebuilt binary as the hook
 * binary. Returns the script's exit code, or -1 on harness error. */
static int hooks_refresh(struct hooks_fx *fx, const char *root, char *out,
                         size_t cap)
{
    char script[PATH_MAX];
    const char *argv[] = {script, NULL};
    const char *saved = fx->bin_use;
    int rc;
    if (dip_join(script, sizeof script, fx->src, HOOKS_REFRESH_REL) != 0)
        return -1;
    fx->bin_use = fx->rebuilt;
    rc = hooks_env_build(&fx->ienv, fx, root) != 0
             ? -1
             : hooks_spawn(argv, fx->ienv.vp, out, cap);
    fx->bin_use = saved;
    return rc;
}

static int hooks_links_intact(const char *wt)
{
    static const char *const names[] = {"pre-push", "post-commit",
                                        "post-merge", "post-checkout"};
    char link[PATH_MAX], leaf[64], target[64];
    size_t i;
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        ssize_t n;
        if (snprintf(leaf, sizeof leaf, "build/githooks/%s", names[i])
                >= (int)sizeof leaf
            || dip_join(link, sizeof link, wt, leaf) != 0)
            return 1;
        n = readlink(link, target, sizeof target - 1);
        if (n < 0)
            return 1;
        target[n] = '\0';
        if (strcmp(target, "z23-git-hook") != 0)
            return 1;
    }
    return 0;
}

/* Reports which refresh check failed so a red run names its cause. */
static int hooks_note(int failed, const char *what)
{
    if (failed)
        fprintf(stderr, "refresh selftest: %s\n", what);
    return failed != 0;
}

static int hooks_refresh_armed(struct hooks_fx *fx)
{
    char inst_a[PATH_MAX], inst_b[PATH_MAX], out[HOOKS_OUT_CAP];
    int bad = 0;
    bad |= dip_join(inst_a, sizeof inst_a, fx->wt_a, HOOKS_INSTALLED_REL);
    bad |= dip_join(inst_b, sizeof inst_b, fx->wt_b, HOOKS_INSTALLED_REL);
    if (bad || hooks_rebuild_copy(fx) != 0)
        return 1;
    bad |= hooks_note(hooks_same_bytes(fx->rebuilt, inst_a), "fixture not stale");
    bad |= hooks_note(hooks_refresh(fx, fx->wt_a, out, sizeof out) != 0, "armed refresh exit");
    bad |= hooks_note(!hooks_same_bytes(fx->rebuilt, inst_a), "armed hook stale");
    bad |= hooks_note(hooks_links_intact(fx->wt_a), "links lost");
    bad |= hooks_expect(fx, fx->wt_a, k_eff_hooks, HOOKS_ARMED,
                        "wt-a core.hooksPath after refresh");
    bad |= hooks_note(hooks_same_bytes(fx->rebuilt, inst_b), "wt-b rewritten");
    return bad;
}

/* An idle checkout keeps its worktree scope byte for byte and gains no hook
 * files. */
static int hooks_refresh_idle(struct hooks_fx *fx, const char *idle,
                              int want_unset)
{
    static const char *const wt_get[] = {"config", "--worktree", "--get",
                                         "core.hooksPath", NULL};
    char before[HOOKS_OUT_CAP], after[HOOKS_OUT_CAP], out[HOOKS_OUT_CAP];
    char inst[PATH_MAX];
    int bad = 0;
    bad |= hooks_note(hooks_value(fx, idle, wt_get, before, sizeof before) < 0, "idle before");
    bad |= hooks_note(hooks_refresh(fx, idle, out, sizeof out) != 0, "idle refresh exit");
    bad |= hooks_value(fx, idle, wt_get, after, sizeof after) < 0;
    bad |= hooks_note(strcmp(before, after) != 0, "idle scope changed");
    bad |= hooks_note(want_unset && after[0] != 0, after);
    bad |= dip_join(inst, sizeof inst, idle, HOOKS_INSTALLED_REL);
    bad |= hooks_note(access(inst, F_OK) == 0, "idle got hook files");
    return bad;
}

static int hooks_refresh_checks(struct hooks_fx *fx)
{
    static const char *const unset[] = {"config", "--worktree", "--unset-all",
                                        "core.hooksPath", NULL};
    char wt_d[PATH_MAX];
    int bad = 0;
    bad |= dip_join(wt_d, sizeof wt_d, fx->base, "wt-d");
    bad |= hooks_note(hooks_install_check(fx, fx->wt_a), "install wt-a");
    bad |= hooks_note(hooks_install_check(fx, fx->wt_b), "install wt-b");
    bad |= hooks_note(hooks_wt_add(fx, fx->repo, "wt-d", wt_d), "add wt-d");
    if (bad)
        return 1;
    (void)hooks_git_ok(fx, wt_d, unset); /* wt-d has no scope value */
    bad |= hooks_refresh_armed(fx);
    bad |= hooks_refresh_idle(fx, fx->wt_c, 0);
    bad |= hooks_refresh_idle(fx, wt_d, 1);
    bad |= hooks_expect(fx, fx->repo, k_shared_hooks, HOOKS_SHARED,
                        "shared value after the refresh");
    return bad;
}

/* ── quiet post-commit: stale watcher residue and explicit suppression
 * launch nothing; a held ready lock launches exactly the attach-only call ── */
#define QUIET_LOCK ".cache/zcl-dev-watch.lock"
#define QUIET_MARK "proof-notify-marker"
#define QUIET_WANT "dev proof ensure --input={\"require_existing_watcher\":true}\n"
#define QUIET_READY "2 verify ready proofq1 1 " \
    "1111111111111111111111111111111111111111111111111111111111111111\n"
#define QUIET_WAIT_MS 10000
#define QUIET_POLL_MS 100
#define QUIET_SETTLE_MS 1000

static void hooks_pause_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static int hooks_quiet_fixture(struct hooks_fx *fx, const char *prefix)
{
    static const char *const init[] = {"config", "--local", "core.hooksPath",
                                       HOOKS_ARMED, NULL};
    char dir[PATH_MAX], file[PATH_MAX], body[PATH_MAX + 64];
    int bad = hooks_fx_base(fx, prefix);
    bad |= dip_join(fx->repo, sizeof fx->repo, fx->base, "quiet");
    if (bad || hooks_repo_seed(fx, fx->repo) != 0)
        return 1;
    bad |= dip_join(dir, sizeof dir, fx->repo, "build");
    bad |= mkdir(dir, 0755) != 0;
    bad |= dip_join(dir, sizeof dir, fx->repo, "build/githooks");
    bad |= mkdir(dir, 0755) != 0;
    bad |= dip_join(dir, sizeof dir, fx->repo, "build/bin");
    bad |= mkdir(dir, 0755) != 0;
    bad |= dip_join(dir, sizeof dir, fx->repo, ".cache");
    bad |= mkdir(dir, 0755) != 0;
    bad |= snprintf(body, sizeof body,
                    "#!/usr/bin/env bash\nexec '%s' --hook=post-commit\n",
                    fx->bin) >= (int)sizeof body;
    bad |= dip_join(file, sizeof file, fx->repo, "build/githooks/post-commit");
    bad |= write_file(file, body) != 0 || chmod(file, 0700) != 0;
    /* The fixture dev executable only records that it was invoked. */
    bad |= dip_join(file, sizeof file, fx->repo, "build/bin/z23-dev");
    bad |= write_file(file, "#!/usr/bin/env sh\n"
                            "printf '%s\\n' \"$*\" >> " QUIET_MARK "\n") != 0
           || chmod(file, 0700) != 0;
    return bad | hooks_git_ok(fx, fx->repo, init);
}

static int hooks_quiet_commit(const struct hooks_fx *fx, const char *msg)
{
    const char *const args[] = {"commit", "-q", "--allow-empty", "-m", msg,
                                NULL};
    return hooks_git_ok(fx, fx->repo, args);
}

/* 0 when no notification was recorded, 1 for exactly the attach-only call,
 * 2 for anything else. */
static int hooks_quiet_marker(const struct hooks_fx *fx)
{
    char path[PATH_MAX], *buf = NULL;
    int state = 0;
    if (dip_join(path, sizeof path, fx->repo, QUIET_MARK) != 0)
        return 2;
    if (read_entire_file(path, &buf) == 0 && buf)
        state = strcmp(buf, QUIET_WANT) == 0 ? 1 : 2;
    free(buf);
    return state;
}

/* Stale residue is not a live watcher, so an ordinary commit stays silent. */
static int hooks_quiet_residue(struct hooks_fx *fx)
{
    static const char *const kinds[] = {"empty", "dead", "malformed",
                                        "unreadable"};
    static const char *const bodies[] = {"", "999999 verify ready proofq1\n",
                                         "not a watcher receipt\n", NULL};
    char lock[PATH_MAX];
    size_t i;
    int bad = dip_join(lock, sizeof lock, fx->repo, QUIET_LOCK);
    for (i = 0; i < sizeof kinds / sizeof kinds[0] && !bad; i++) {
        if (bodies[i])
            bad |= write_file(lock, bodies[i]) != 0;
        else
            bad |= chmod(lock, 0) != 0;
        bad |= hooks_quiet_commit(fx, kinds[i]);
    }
    (void)chmod(lock, 0600);
    hooks_pause_ms(QUIET_SETTLE_MS);
    return bad | (hooks_quiet_marker(fx) != 0);
}

/* Holds the kernel lock with a complete ready record until closed. */
static int hooks_lock_hold(const struct hooks_fx *fx)
{
    char lock[PATH_MAX];
    int fd;
    if (dip_join(lock, sizeof lock, fx->repo, QUIET_LOCK) != 0)
        return -1;
    fd = open(lock, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0
        || write(fd, QUIET_READY, sizeof QUIET_READY - 1)
               != (ssize_t)(sizeof QUIET_READY - 1)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ZCL_LAND_HOOK_QUIET set to 1 or to the empty string suppresses the
 * notification even though a ready lock is held. */
static int hooks_quiet_suppressed(struct hooks_fx *fx)
{
    static const char *const values[] = {"ZCL_LAND_HOOK_QUIET=1",
                                         "ZCL_LAND_HOOK_QUIET="};
    size_t i;
    int bad = 0, fd = hooks_lock_hold(fx);
    if (fd < 0)
        return 1;
    for (i = 0; i < sizeof values / sizeof values[0]; i++) {
        fx->extra_env = values[i];
        bad |= hooks_quiet_commit(fx, "explicit-quiet");
    }
    fx->extra_env = NULL;
    hooks_pause_ms(QUIET_SETTLE_MS);
    bad |= hooks_quiet_marker(fx) != 0;
    close(fd);
    return bad;
}

static int hooks_quiet_held_ready(struct hooks_fx *fx)
{
    long waited = 0;
    int bad = 0, fd = hooks_lock_hold(fx);
    if (fd < 0)
        return 1;
    bad |= hooks_quiet_commit(fx, "held-ready");
    /* Git has returned, but the detached receiver need not have run yet. */
    while (hooks_quiet_marker(fx) != 1 && waited < QUIET_WAIT_MS) {
        hooks_pause_ms(QUIET_POLL_MS);
        waited += QUIET_POLL_MS;
    }
    hooks_pause_ms(QUIET_SETTLE_MS); /* a duplicate would break equality */
    bad |= hooks_quiet_marker(fx) != 1;
    close(fd);
    return bad;
}

/* ── bootstrap: dependency-free goals skip vendor and Tor, node goals do not */
#define BOOT_GUEST "build/gen/guest_kernel_data.c"
#define BOOT_TAIL \
    ".DEFAULT_GOAL := z23\n" \
    ".PHONY: git-hook git-hook-selftest install-hooks z23 unknown-goal " \
    "rvmachine-public-fixtures-testbin test-rvmachine-public-fixtures\n" \
    "git-hook git-hook-selftest install-hooks:\n\t@touch hook-ran\n" \
    BOOT_GUEST ":\n\t@touch guest-ran\n" \
    "rvmachine-public-fixtures-testbin test-rvmachine-public-fixtures:\n\t@touch fixture-ran\n" \
    "z23 unknown-goal:\n\t@touch node-ran\n" \
    "vendor-ready.mk: vendor-ready\n\t@touch vendor-ran\n\t@printf '# established\\n' > $@\n" \
    "tor-ready.mk:\n\t@touch tor-ran\n\t@printf '# established\\n' > $@\n"
#define BOOT_GOALS_MAX 3

struct hooks_goal_case {
    const char *goals[BOOT_GOALS_MAX];
    int node; /* the goals must reach vendor and Tor bootstrap */
    const char *ran;
};

static const char *const k_boot_marks[] = {
    "hook-ran", "node-ran", "vendor-ran", "vendor-ready.mk", "tor-ran",
    "tor-ready.mk", "guest-ran", "fixture-ran", "vendor-count", "audit-count"};

static int hooks_boot_scripts(const char *dir)
{
    char path[PATH_MAX]; int bad = 0;
    bad |= dip_join(path, sizeof path, dir, "tools"); bad |= mkdir(path, 0755) != 0;
    bad |= dip_join(path, sizeof path, dir, "tools/scripts"); bad |= mkdir(path, 0755) != 0;
    bad |= dip_join(path, sizeof path, dir, "tools/scripts/build_vendor.sh");
    bad |= write_file(path, "#!/bin/sh\necho run >> vendor-count\n[ -z \"$FAIL_VENDOR\" ]\n") != 0;
    bad |= chmod(path, 0700) != 0;
    bad |= dip_join(path, sizeof path, dir, "audit");
    bad |= write_file(path, "#!/bin/sh\necho run >> audit-count\n[ -z \"$FAIL_AUDIT\" ]\n") != 0;
    bad |= chmod(path, 0700) != 0;
    return bad;
}

/* Copies the real parse-time bootstrap blocks of the Makefile and adds
 * stub recipes that only drop marker files. */
static int hooks_boot_fixture(const char *dir)
{
    static const char *const marks[][2] = {
        {"\nZCL_WINDOWS_LAUNCHER_GOALS :=", "\n# Generated view headers"},
        {"\nZCL_TOR_SKIP_GOALS :=", "\n# The stub is reachable"},
        {"\n# Link/release/deploy front door:", "\n# Build the real embedded onion service"}};
    char mk_path[PATH_MAX], out_path[PATH_MAX], *mk = NULL;
    FILE *f;
    size_t i;
    int bad;
    if (repo_path(mk_path, sizeof mk_path, "Makefile") != 0
        || dip_join(out_path, sizeof out_path, dir, "Makefile") != 0
        || mkdir(dir, 0755) != 0 || read_entire_file(mk_path, &mk) != 0 || !mk)
    {
        free(mk);
        return 1;
    }
    f = fopen(out_path, "wb");
    bad = f == NULL;
    if (f) bad |= fputs("VENDOR_REPAIR_REQUESTED := $(filter vendor-ready deploy install,$(MAKECMDGOALS))\nDEP_AUDIT_BIN := ./audit\n", f) < 0;
    for (i = 0; f && i < 3; i++) {
        const char *s = strstr(mk, marks[i][0]);
        const char *e = s ? strstr(s, marks[i][1]) : NULL;
        bad |= !e || fwrite(s, 1, (size_t)(e - s), f) != (size_t)(e - s);
    }
    bad |= f && fputs(BOOT_TAIL, f) < 0;
    bad |= f && fclose(f) != 0;
    free(mk);
    return bad | hooks_boot_scripts(dir);
}

static int hooks_boot_has(const char *dir, const char *mark)
{
    char path[PATH_MAX];
    return dip_join(path, sizeof path, dir, mark) == 0
           && access(path, F_OK) == 0;
}

static int hooks_vendor_reset(const char *dir)
{
    char path[PATH_MAX];
    const char *marks[] = {"vendor-ready.mk", "tor-ready.mk", "vendor-count", "audit-count"};
    for (size_t i = 0; i < sizeof marks / sizeof marks[0]; ++i)
        if (dip_join(path, sizeof path, dir, marks[i]) || (unlink(path) && errno != ENOENT)) return 1;
    return 0;
}

static int hooks_vendor_count(const char *dir, const char *mark, const char *goal, int want)
{
    char path[PATH_MAX], *data = NULL;
    if (dip_join(path, sizeof path, dir, mark) || read_entire_file(path, &data)) return 1;
    size_t bytes = data ? strlen(data) : 0;
    int bad = !data || bytes != (size_t)want * 4;
    if (bad) fprintf(stderr, "vendor goal %s: expected %d %s, got %zu bytes\n", goal ? goal : "standalone", want, mark, bytes);
    free(data); return bad;
}

static int hooks_vendor_case(const struct hooks_fx *fx, const char *dir,
                             const char *goal, const char *failure, int want)
{
    const char *argv[] = {"make", "-s", "-C", dir, "VENDOR_MISSING_INPUTS=missing.a",
        "VENDOR_BOOTSTRAP_MK=vendor-ready.mk", "ZCL_TOR=full",
        "TOR_MISSING_ARCHIVES=missing-tor.a", "TOR_BOOTSTRAP_MK=tor-ready.mk",
        "vendor-ready", goal, failure, NULL};
    char out[HOOKS_OUT_CAP];
    if (hooks_vendor_reset(dir)) return 1;
    int rc = hooks_spawn(argv, fx->genv.vp, out, sizeof out);
    if (failure) return rc == 0;
    if (rc) return 1;
    int bad = hooks_vendor_count(dir, "vendor-count", goal, want);
    return bad | hooks_vendor_count(dir, "audit-count", goal, want);
}

static int hooks_boot_case(const struct hooks_fx *fx, const char *dir,
                           const struct hooks_goal_case *c)
{
    const char *argv[24] = {"make", "-s", "-C", dir,
                            "VENDOR_MISSING_INPUTS=missing.a",
                            "VENDOR_BOOTSTRAP_MK=vendor-ready.mk",
                            "ZCL_TOR=full", "TOR_MISSING_ARCHIVES=missing-tor.a",
                            "TOR_BOOTSTRAP_MK=tor-ready.mk"};
    char out[HOOKS_OUT_CAP], path[PATH_MAX];
    size_t n = 9, i;
    for (i = 0; i < sizeof k_boot_marks / sizeof k_boot_marks[0]; i++)
        if (dip_join(path, sizeof path, dir, k_boot_marks[i]) != 0
            || (unlink(path) != 0 && errno != ENOENT))
            return 1;
    for (i = 0; i < BOOT_GOALS_MAX && c->goals[i]; i++)
        argv[n++] = c->goals[i];
    argv[n] = NULL;
    if (hooks_spawn(argv, fx->genv.vp, out, sizeof out) != 0) {
        fprintf(stderr, "bootstrap probe failed: %s\n", out);
        return 1;
    }
    if (c->node)
        return !(hooks_boot_has(dir, c->ran)
                 && hooks_boot_has(dir, "vendor-ran")
                 && hooks_boot_has(dir, "tor-ran"));
    return !hooks_boot_has(dir, c->ran)
           || hooks_boot_has(dir, "vendor-ran")
           || hooks_boot_has(dir, "tor-ran");
}

static int hooks_boot_checks(struct hooks_fx *fx)
{
    static const struct hooks_goal_case cases[] = {
        {{"git-hook"}, 0, "hook-ran"},
        {{"git-hook-selftest"}, 0, "hook-ran"},
        {{"install-hooks"}, 0, "hook-ran"},
        {{"git-hook", "install-hooks"}, 0, "hook-ran"},
        {{"install-hooks", "z23"}, 1, "node-ran"},
        {{"unknown-goal"}, 1, "node-ran"},
        {{NULL}, 1, "node-ran"}, /* the default goal */
        {{BOOT_GUEST}, 0, "guest-ran"},
        {{BOOT_GUEST, "git-hook"}, 0, "guest-ran"},
        {{BOOT_GUEST, "z23"}, 1, "node-ran"},
        {{BOOT_GUEST, "Z23_GUEST_KERNEL=fixture-kernel"}, 1, "guest-ran"},
        {{BOOT_GUEST, "Z23_GUEST_KERNEL=$(UNDEFINED_KERNEL)"}, 1, "guest-ran"},
        {{"rvmachine-public-fixtures-testbin"}, 0, "fixture-ran"},
        {{"test-rvmachine-public-fixtures"}, 0, "fixture-ran"},
        {{"rvmachine-public-fixtures-testbin", "test-rvmachine-public-fixtures"}, 0, "fixture-ran"},
        {{"rvmachine-public-fixtures-testbin", "z23"}, 1, "node-ran"},
        {{"test-rvmachine-public-fixtures", "z23"}, 1, "node-ran"}};
    char dir[PATH_MAX];
    size_t i;
    int bad = hooks_fx_base(fx, HOOKS_BASE_PREFIX "_bootstrap");
    bad |= dip_join(dir, sizeof dir, fx->base, "bootstrap");
    if (bad || hooks_boot_fixture(dir) != 0)
        return 1;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (hooks_boot_case(fx, dir, &cases[i]) != 0) {
            fprintf(stderr, "bootstrap goal case %zu: wrong bootstrap\n", i);
            bad = 1;
        }
    }
    bad |= hooks_vendor_case(fx, dir, NULL, NULL, 1);
    bad |= hooks_vendor_case(fx, dir, "z23", NULL, 2);
    bad |= hooks_vendor_case(fx, dir, "MAKE_RESTARTS=1", NULL, 1);
    bad |= hooks_vendor_case(fx, dir, "FAIL_VENDOR=1", "FAIL_VENDOR=1", 0);
    bad |= hooks_vendor_case(fx, dir, "FAIL_AUDIT=1", "FAIL_AUDIT=1", 0);
    return bad;
}

int t_git_hooks_refresh_updates_armed_only(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_repo_fixture(fx, HOOKS_BASE_PREFIX "_refresh") : 1;
    TEST("[lint-gate] hook refresh updates an armed checkout and never arms "
         "an idle one") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_refresh_checks(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_quiet_stale_residue(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_quiet_fixture(fx, HOOKS_BASE_PREFIX "_residue") : 1;
    TEST("[lint-gate] post-commit launches no dev process from stale watcher "
         "residue") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_quiet_residue(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_quiet_env_suppresses(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_quiet_fixture(fx, HOOKS_BASE_PREFIX "_quiet") : 1;
    TEST("[lint-gate] ZCL_LAND_HOOK_QUIET (1 or empty) suppresses a ready "
         "notification") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_quiet_suppressed(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_quiet_held_ready_notifies(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    int setup = fx ? hooks_quiet_fixture(fx, HOOKS_BASE_PREFIX "_held") : 1;
    TEST("[lint-gate] a held ready lock notifies with the attach-only argv") {
        ASSERT(fx != NULL);
        ASSERT(setup == 0);
        ASSERT(hooks_quiet_held_ready(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

int t_git_hooks_bootstrap_goal_filter(void)
{
    int failures = 0;
    struct hooks_fx *fx = hooks_fx_new();
    TEST("[lint-gate] dependency-free goals skip vendor and Tor bootstrap, "
         "node and configured-kernel goals do not") {
        ASSERT(fx != NULL);
        ASSERT(hooks_boot_checks(fx) == 0);
        PASS();
    } _test_next:;
    hooks_fx_free(fx);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_git_hooks_unit;

#endif /* ZCL_TESTING */
