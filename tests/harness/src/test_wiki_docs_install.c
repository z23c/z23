/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Installed-binary docs resolution for the two install layouts: a copy of the
 * CLI at <prefix>/bin/z23 and at <prefix>/lib/z23/generations/<hex>/z23, each
 * with the documentation tree at <prefix>/share/z23/docs, run from a
 * directory outside any checkout with no source root configured. */

#include "test/test_core.h"

#include "json/json.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WI_EXE "build/bin/z23-dev"
#define WI_DEADLINE_MS 60000
#define WI_GEN "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static bool wi_mkpath(const char *base, const char *rel)
{
    char path[PATH_MAX + 128];
    size_t n = (size_t)snprintf(path, sizeof(path), "%s/%s", base, rel);
    for (size_t i = strlen(base) + 1; i <= n && n < sizeof(path); i++) {
        if (path[i] != '/' && path[i] != '\0')
            continue;
        char saved = path[i];
        path[i] = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return false;
        path[i] = saved;
    }
    return true;
}

static bool wi_copy(const char *src, const char *dst, mode_t mode)
{
    FILE *in = fopen(src, "rb"), *out = fopen(dst, "wb");
    char buf[65536];
    size_t got;
    bool ok = in && out;
    while (ok && (got = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, got, out) == got;
    if (in)
        fclose(in);
    ok = (out ? fclose(out) == 0 : false) && ok;
    return ok && chmod(dst, mode) == 0;
}

/* Lays out <prefix>/<exe_rel> (a copy of the CLI) and
 * <prefix>/share/z23/docs/README.md. */
static bool wi_install(const char *prefix, const char *exe_rel,
                       char *exe, size_t cap)
{
    char path[PATH_MAX + 192], dir[PATH_MAX + 192];
    snprintf(exe, cap, "%s/%s", prefix, exe_rel);
    snprintf(dir, sizeof(dir), "%s", exe_rel);
    *strrchr(dir, '/') = '\0';
    snprintf(path, sizeof(path), "%s/share/z23/docs/README.md", prefix);
    if (!wi_mkpath(prefix, dir) || !wi_mkpath(prefix, "share/z23/docs") ||
        !wi_copy(WI_EXE, exe, 0700))
        return false;
    FILE *fp = fopen(path, "wb");
    bool ok = fp && fputs("# Installed docs\n\nFound by path.\n", fp) >= 0;
    return (fp ? fclose(fp) == 0 : false) && ok;
}

static void wi_drop(const char *prefix, const char *exe_rel)
{
    char path[PATH_MAX + 192];
    snprintf(path, sizeof(path), "%s/share/z23/docs/README.md", prefix);
    TEST_DISCARD(unlink(path));
    snprintf(path, sizeof(path), "%s/%s", prefix, exe_rel);
    TEST_DISCARD(unlink(path));
    for (char *p = path + strlen(path); p > path + strlen(prefix); p--) {
        if (*p != '/')
            continue;
        *p = '\0';
        TEST_DISCARD(rmdir(path));
    }
    snprintf(path, sizeof(path), "%s/share/z23/docs", prefix);
    TEST_DISCARD(rmdir(path));
    snprintf(path, sizeof(path), "%s/share/z23", prefix);
    TEST_DISCARD(rmdir(path));
    snprintf(path, sizeof(path), "%s/share", prefix);
    TEST_DISCARD(rmdir(path));
    TEST_DISCARD(rmdir(prefix));
}

static bool wi_title(const char *exe, const char *cwd, char *title, size_t cap)
{
    char out[16384];
    const char *argv[] = { exe, "wiki", NULL };
    struct json_value reply;
    bool timed_out = false;
    TEST_DISCARD(unsetenv("ZCL_DEV_SOURCE_ROOT"));
    int rc = zcl_spawn_capture_in_dir_observed(argv, cwd, out, sizeof(out),
                                               WI_DEADLINE_MS, &timed_out);
    json_init(&reply);
    bool ok = rc == 0 && !timed_out && json_read(&reply, out, strlen(out));
    const char *t = ok ? json_get_str(json_get(json_get(&reply, "data"),
                                               "title")) : NULL;
    snprintf(title, cap, "%s", t ? t : "");
    json_free(&reply);
    return t != NULL;
}

static int wi_layout(const char *name, const char *exe_rel)
{
    int failures = 0;
    char base[PATH_MAX], prefix[PATH_MAX + 16], exe[PATH_MAX + 192];
    char title[256];
    bool made = false;
    TEST("wiki docs install: an installed layout finds <prefix>/share/z23/docs") {
        ASSERT(test_mkdtemp(base, sizeof(base), "wiki_docs_install") != NULL);
        made = true;
        snprintf(prefix, sizeof(prefix), "%s/%s", base, name);
        ASSERT(wi_mkpath(base, name));
        ASSERT(wi_install(prefix, exe_rel, exe, sizeof(exe)));
        ASSERT(wi_title(exe, base, title, sizeof(title)));
        ASSERT_STR_EQ(title, "Installed docs");
        PASS();
    } _test_next:;
    if (made) {
        wi_drop(prefix, exe_rel);
        TEST_DISCARD(rmdir(base));
    }
    return failures;
}

int test_wiki_docs_install(void)
{
    int failures = 0;
    failures += wi_layout("linux", "bin/z23");
    failures += wi_layout("macos", "lib/z23/generations/" WI_GEN "/z23");
    return failures;
}
