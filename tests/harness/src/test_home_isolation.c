/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_home_isolation — see test/test_home_isolation.h. */

#include "test/test_home_isolation.h"

#include "platform/environment_compat.h"
#include "platform/private_directory.h"
#include "util/util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

/* Every datadir variable the node reads at run time (flags.def, env_runtime). */
static const char *const k_datadir_vars[] = {
    "ZCL_DATADIR",
    "ZCL_ANCHOR_MINT_DATADIR",
    "ZCL_BENCH_LIVE_DATADIR",
    "ZCL_BENCH_SOURCE_DATADIR",
    "ZCL_CRASH_DATADIR",
    "ZCL_SLO_CANON_DATADIR",
    "ZCL_SLO_ORACLE_DATADIR",
};

struct iso_dirs {
    char home[PATH_MAX];
    char cfg[PATH_MAX];
    char data[PATH_MAX];
    char cache[PATH_MAX];
};

static void iso_unset(const char *name)
{
#if defined(_WIN32)
    (void)_putenv_s(name, "");
#else
    (void)unsetenv(name);
#endif
}

static bool iso_fail(char *err, size_t cap, const char *what, const char *path)
{
    if (err && cap)
        snprintf(err, cap, "%s %s: %s", what, path ? path : "",
                 strerror(errno));
    return false;
}

static bool iso_set(const char *name, const char *value)
{
    return platform_environment_set(name, value, 1) == 0;
}

static bool iso_subdir(char *out, size_t cap, const char *base,
                       const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", base, leaf);
    if (n < 0 || (size_t)n >= cap) {
        errno = ENAMETOOLONG;
        return false;
    }
    return platform_private_directory_ensure(out);
}

static bool real_home_opt_in(void)
{
    const char *v = getenv("ZCL_TEST_REAL_HOME");
    return v && strcmp(v, "1") == 0;
}

/* Record the canonical datadir BEFORE HOME moves. A nested runner keeps the
 * outermost answer: its own HOME is already a fixture. */
static bool iso_export_markers(char *err, size_t err_cap)
{
    const char *outer = getenv("ZCL_TEST_CANONICAL_DATADIR");
    if (!outer || !outer[0]) {
        char canonical[PATH_MAX];
        GetDefaultDataDir(canonical, sizeof(canonical));
        if (!iso_set("ZCL_TEST_CANONICAL_DATADIR", canonical))
            return iso_fail(err, err_cap, "cannot export canonical datadir",
                            canonical);
    }
    if (!iso_set("ZCL_TEST_HARNESS", "1"))
        return iso_fail(err, err_cap, "cannot export harness marker", "");
    return true;
}

static bool iso_make_dirs(struct iso_dirs *d, const char *root)
{
    char local[PATH_MAX];
    return iso_subdir(d->home, sizeof(d->home), root, "home") &&
           iso_subdir(d->cfg, sizeof(d->cfg), d->home, ".config") &&
           iso_subdir(local, sizeof(local), d->home, ".local") &&
           iso_subdir(d->data, sizeof(d->data), local, "share") &&
           iso_subdir(d->cache, sizeof(d->cache), d->home, ".cache");
}

/* Sapling parameters are read-only inputs, not a datadir: keep the
 * params-gated groups running by linking the real directory in. */
static bool iso_link_params(const char *real_home, const char *home)
{
#if defined(_WIN32)
    (void)real_home;
    (void)home;
    return true;
#else
    char src[PATH_MAX], dst[PATH_MAX];
    struct stat st;
    if (!real_home || !real_home[0]) return true;
    if (snprintf(src, sizeof(src), "%s/.zcash-params", real_home) < 0 ||
        snprintf(dst, sizeof(dst), "%s/.zcash-params", home) < 0)
        return false;
    if (stat(src, &st) != 0 || !S_ISDIR(st.st_mode)) return true;
    return symlink(src, dst) == 0 || errno == EEXIST;
#endif
}

/* A deterministic git identity: a test that drives git (commit, merge,
 * cherry-pick) used to find the operator's ~/.gitconfig; a private HOME has
 * none, and git refuses to commit without an identity. */
static bool iso_write_gitconfig(const char *home)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/.gitconfig", home) < 0) return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs("[user]\n\tname = Z23 Test\n"
                    "\temail = z23-test@example.invalid\n", f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool iso_switch_env(const struct iso_dirs *d)
{
    bool ok = iso_set("HOME", d->home) && iso_set("XDG_CONFIG_HOME", d->cfg) &&
              iso_set("XDG_DATA_HOME", d->data) &&
              iso_set("XDG_CACHE_HOME", d->cache);
#if defined(_WIN32)
    ok = ok && iso_set("USERPROFILE", d->home);
#endif
    for (size_t i = 0; i < sizeof(k_datadir_vars) / sizeof(k_datadir_vars[0]); ++i)
        iso_unset(k_datadir_vars[i]);
    return ok && iso_set("ZCL_TEST_PRIVATE_HOME", "1");
}

bool zcl_test_isolate_environment(const char *private_root,
                                  char *err, size_t err_cap)
{
    if (!private_root || !private_root[0]) {
        errno = EINVAL;
        return iso_fail(err, err_cap, "no private root", "");
    }

    /* HOME must survive a chdir: resolve the root to an absolute path. */
    char root_abs[PATH_MAX];
#if defined(_WIN32)
    bool resolved = _fullpath(root_abs, private_root, sizeof(root_abs)) != NULL;
#else
    bool resolved = realpath(private_root, root_abs) != NULL;
#endif
    if (!resolved)
        return iso_fail(err, err_cap, "cannot resolve private root",
                        private_root);

    if (!iso_export_markers(err, err_cap)) return false;

    if (real_home_opt_in()) {
        printf("test_home_isolation: ZCL_TEST_REAL_HOME=1 — HOME left real; "
               "the canonical-datadir writer guard still applies\n");
        return true;
    }

    const char *real_home = getenv("HOME");
    struct iso_dirs d;
    if (!iso_make_dirs(&d, root_abs))
        return iso_fail(err, err_cap, "cannot create private HOME", root_abs);
    if (!iso_link_params(real_home, d.home))
        return iso_fail(err, err_cap, "cannot link params into", d.home);
    if (!iso_write_gitconfig(d.home))
        return iso_fail(err, err_cap, "cannot write .gitconfig in", d.home);
    if (!iso_switch_env(&d))
        return iso_fail(err, err_cap, "cannot set private HOME", d.home);
    return true;
}

void zcl_test_isolate_or_exit(const char *runner, const char *private_root)
{
    char err[512];
    if (zcl_test_isolate_environment(private_root, err, sizeof(err)))
        return;
    fprintf(stderr, "%s: HOME isolation failed: %s\n",
            runner ? runner : "test", err);
    exit(2);
}

bool zcl_test_home_is_private(void)
{
    const char *v = getenv("ZCL_TEST_PRIVATE_HOME");
    return v && strcmp(v, "1") == 0 && !real_home_opt_in();
}

bool zcl_test_real_home_skip(const char *what)
{
    if (!zcl_test_home_is_private()) return false;
    printf("  SKIP: %s needs real HOME data, but this runner gave the test a "
           "private HOME; set ZCL_TEST_REAL_HOME=1 to opt in\n",
           what ? what : "test");
    return true;
}
