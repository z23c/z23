/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the include path the core/ barrier pass resolves against
 * (gate_core_barrier.c). It mirrors ZCL_ALL_INCLUDES in the Makefile, in the
 * same order: a row with '*' expands by glob(3), sorted bytewise like
 * $(sort $(wildcard ...)); an "@<authority>" row expands to APP_DIRS x
 * {include,src}; absent directories are dropped, as APP_INCLUDES' $(wildcard)
 * does. Keep it in step with `make print-includes`; compare with
 * `z23-lint check-core-include-boundary --print-include-path`. A directory
 * missing here makes an include unresolved (reported), never silently clean.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <glob.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"

static const char *const k_cbp_rows[] = {
    "@engine", "@cognition", "@contexts/wallet", "@contexts/explorer",
    "@contexts/naming", "@contexts/messaging", "@contexts/market",
    "@contexts/commons", "@contexts/clips",
    "engine/composition/include",
    "cognition/modules/*/include", "contexts/*/modules/*/include",
    "core/modules/*/include", "engine/modules/*/include",
    "platform/modules/*/include",
    "core/consensus/include", "core/params/include", "core/math/include",
    "core/chainparams/include",
    "platform/ports/include",
    "contexts/wallet/domain/include", "platform/domain/encoding/include",
    "engine/application/consensus/include",
    "platform/adapters/outbound/persistence/include",
    "engine/reducer/conditions/include", "engine/reducer/conditions/src",
    "engine/reducer/jobs/include", "engine/reducer/jobs/src",
    "engine/reducer/services/include", "engine/reducer/services/src",
    "tools", "contexts/commons/packages/zutf8/include",
    "contexts/commons/packages/zjsonp/include",
    "contexts/commons/packages/zmap/include",
    "contexts/commons/packages/zbase64/include",
    "tools/mind", "tools/dev", "tests/harness/include", "vendor/include",
    "vendor/x11/include", "apps/skycombat/include",
    "apps/skycombat/specifications", "vendor/raylib/src",
    "contexts/commons/packages/zsha256/include", "apps/z23wallet/src",
};
static const char *const k_cbp_app_dirs[] = {
    "models", "controllers", "views", "services", "supervisors", "conditions",
    "jobs"
};

typedef int (*cbp_add_fn)(const char *dir, void *ctx);

static int cbp_is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int cbp_glob(const char *pat, cbp_add_fn add, void *ctx)
{
    glob_t g;
    int rc = glob(pat, 0, NULL, &g);
    if (rc == GLOB_NOMATCH)
        return 0;
    if (rc != 0)
        return die("z23-lint: core barrier: glob failed: %s\n", pat);
    for (size_t i = 0; rc == 0 && i < g.gl_pathc; i++)
        if (cbp_is_dir(g.gl_pathv[i]))
            rc = add(g.gl_pathv[i], ctx);
    globfree(&g);
    return rc;
}

static int cbp_app(const char *auth, cbp_add_fn add, void *ctx)
{
    static const char *const kind[] = { "include", "src" };
    char p[RS_PATH];
    int rc = 0;
    for (size_t d = 0; d < sizeof k_cbp_app_dirs / sizeof k_cbp_app_dirs[0];
         d++)
        for (int k = 0; rc == 0 && k < 2; k++) {
            if (ovf(snprintf(p, sizeof p, "%s/%s/%s", auth, k_cbp_app_dirs[d],
                             kind[k]), sizeof p))
                return 2;
            if (cbp_is_dir(p))
                rc = add(p, ctx);
        }
    return rc;
}

/* Headers `make vendor` installs under vendor/include (git-ignored, see
 * .gitignore): present only after a vendor build, so resolving them on disk
 * would make the verdict depend on build state. They always resolve to
 * vendor/include/<token>, an outside edge, whether installed or not. */
int core_barrier_vendor_installed(const char *tok)
{
    return strncmp(tok, "openssl/", 8) == 0 || strncmp(tok, "event2/", 7) == 0
           || strcmp(tok, "zlib.h") == 0 || strcmp(tok, "zconf.h") == 0;
}

int core_barrier_include_path(int (*add)(const char *dir, void *ctx),
                              void *ctx)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_cbp_rows / sizeof k_cbp_rows[0];
         i++) {
        const char *row = k_cbp_rows[i];
        if (row[0] == '@')
            rc = cbp_app(row + 1, add, ctx);
        else if (strchr(row, '*'))
            rc = cbp_glob(row, add, ctx);
        else if (cbp_is_dir(row))
            rc = add(row, ctx);
    }
    return rc;
}
