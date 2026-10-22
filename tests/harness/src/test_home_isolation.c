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
    if (platform_private_directory_ensure(out)) return true;
    return false;
}

static bool real_home_opt_in(void)
{
    const char *v = getenv("ZCL_TEST_REAL_HOME");
    return v && strcmp(v, "1") == 0;
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
    if (!_fullpath(root_abs, private_root, sizeof(root_abs)))
#else
    if (!realpath(private_root, root_abs))
#endif
        return iso_fail(err, err_cap, "cannot resolve private root",
                        private_root);
    private_root = root_abs;

    /* Record the canonical datadir BEFORE HOME moves. A nested runner keeps
     * the outermost answer: its own HOME is already a fixture. */
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

    if (real_home_opt_in()) {
        printf("test_home_isolation: ZCL_TEST_REAL_HOME=1 — HOME left real; "
               "the canonical-datadir writer guard still applies\n");
        return true;
    }

    const char *real_home = getenv("HOME");
    char home[PATH_MAX], cfg[PATH_MAX], local[PATH_MAX], data[PATH_MAX],
         cache[PATH_MAX];
    if (!iso_subdir(home, sizeof(home), private_root, "home"))
        return iso_fail(err, err_cap, "cannot create private HOME", private_root);
    if (!iso_subdir(cfg, sizeof(cfg), home, ".config") ||
        !iso_subdir(local, sizeof(local), home, ".local") ||
        !iso_subdir(data, sizeof(data), local, "share") ||
        !iso_subdir(cache, sizeof(cache), home, ".cache"))
        return iso_fail(err, err_cap, "cannot create private XDG dirs", home);

#if !defined(_WIN32)
    /* Sapling parameters are read-only inputs, not a datadir: keep the
     * params-gated groups running by linking the real directory in. */
    if (real_home && real_home[0]) {
        char src[PATH_MAX], dst[PATH_MAX];
        struct stat st;
        if (snprintf(src, sizeof(src), "%s/.zcash-params", real_home) > 0 &&
            snprintf(dst, sizeof(dst), "%s/.zcash-params", home) > 0 &&
            stat(src, &st) == 0 && S_ISDIR(st.st_mode) &&
            symlink(src, dst) != 0 && errno != EEXIST)
            return iso_fail(err, err_cap, "cannot link params", dst);
    }
#else
    (void)real_home;
#endif

    /* A deterministic git identity: a test that drives git (commit, merge,
     * cherry-pick) used to find the operator's ~/.gitconfig; a private HOME
     * has none, and git refuses to commit without an identity. */
    {
        char gitconfig[PATH_MAX];
        if (snprintf(gitconfig, sizeof(gitconfig), "%s/.gitconfig", home) > 0) {
            FILE *f = fopen(gitconfig, "w");
            bool ok = f && fputs("[user]\n\tname = Z23 Test\n"
                                 "\temail = z23-test@example.invalid\n", f) >= 0;
            if (f && fclose(f) != 0) ok = false;
            if (!ok) return iso_fail(err, err_cap, "cannot write", gitconfig);
        }
    }

    if (!iso_set("HOME", home) || !iso_set("XDG_CONFIG_HOME", cfg) ||
        !iso_set("XDG_DATA_HOME", data) || !iso_set("XDG_CACHE_HOME", cache))
        return iso_fail(err, err_cap, "cannot set private HOME", home);
#if defined(_WIN32)
    if (!iso_set("USERPROFILE", home))
        return iso_fail(err, err_cap, "cannot set private USERPROFILE", home);
#endif
    for (size_t i = 0; i < sizeof(k_datadir_vars) / sizeof(k_datadir_vars[0]); ++i)
        iso_unset(k_datadir_vars[i]);
    iso_set("ZCL_TEST_PRIVATE_HOME", "1");
    return true;
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
