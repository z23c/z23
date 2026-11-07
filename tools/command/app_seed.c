/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: compose the self-contained staging tree an in-repo app is seeded
 *          from (see command/app_seed.h). Copies go through the one tree
 *          walker, zcl_tree_copy, which refuses symlinks. */

#include "command/app_seed.h"

#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "vcs/package_manifest.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define AS_PATH 4400

struct as_ctx {
    const char *repo;
    const char *dest;
    char app_dir[AS_PATH];
    struct app_seed_stage *out;
};

static bool as_fail(struct app_seed_stage *o, const char *code,
                    const char *fmt, ...)
{
    va_list ap;
    (void)snprintf(o->code, sizeof(o->code), "%s", code);
    va_start(ap, fmt);
    (void)vsnprintf(o->why, sizeof(o->why), fmt, ap);
    va_end(ap);
    return false;
}

static bool as_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

bool app_seed_name_valid(const char *app)
{
    size_t n = app ? strlen(app) : 0;
    if (n == 0 || n > APP_SEED_NAME_MAX ||
        !((app[0] >= 'a' && app[0] <= 'z') || (app[0] >= '0' && app[0] <= '9')))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = app[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
              c == '-'))
            return false;
    }
    return true;
}

/* ── the app's own files ─────────────────────────────────────────────── */

/* Root-level names that never enter the tree: the seed's own inputs and
 * the local stores no package root covers. */
static bool as_skipped(const char *name)
{
    static const char *const skip[] = {".", "..", APP_SEED_FRAGMENT,
                                       APP_SEED_DEF, "build", ".zvcs",
                                       ".codeindex"};
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++)
        if (strcmp(name, skip[i]) == 0)
            return true;
    return false;
}

static bool as_copy_entry(struct as_ctx *c, const char *name)
{
    char src[AS_PATH], dst[AS_PATH];
    struct stat st;
    if (!vcs_package_path_valid(name))
        return as_fail(c->out, "SEED_PATH_ESCAPE", "apps file '%s' is not a "
                       "canonical package path", name);
    if (!as_join(src, sizeof(src), c->app_dir, name) ||
        !as_join(dst, sizeof(dst), c->dest, name) || lstat(src, &st) != 0)
        return as_fail(c->out, "SEED_IO", "cannot read %s/%s", c->app_dir,
                       name);
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        return as_fail(c->out, "SEED_NOT_REGULAR", "%s is a symlink or "
                       "special file", src);
    struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    if (!r.ok)
        return as_fail(c->out, "SEED_NOT_REGULAR", "copying %s: %s", src,
                       r.message);
    return true;
}

/* Every top-level entry of apps/<app> but the skipped ones; the walker
 * copies each subtree and refuses any symlink in it. */
static bool as_copy_app(struct as_ctx *c)
{
    DIR *dh = opendir(c->app_dir);
    struct dirent *e;
    bool ok = dh != NULL;
    if (!ok)
        return as_fail(c->out, "SEED_IO", "cannot list %s", c->app_dir);
    while (ok && (e = readdir(dh)) != NULL)
        if (!as_skipped(e->d_name))
            ok = as_copy_entry(c, e->d_name);
    (void)closedir(dh);
    return ok;
}

/* app.mk becomes the tree's Makefile. */
static bool as_copy_fragment(struct as_ctx *c)
{
    char src[AS_PATH], dst[AS_PATH];
    struct stat st;
    if (!as_join(src, sizeof(src), c->app_dir, APP_SEED_FRAGMENT) ||
        lstat(src, &st) != 0 || !S_ISREG(st.st_mode))
        return as_fail(c->out, "NO_MAKE_FRAGMENT", "%s is not a regular file "
                       "with the print-app-closure and app targets", src);
    if (!as_join(dst, sizeof(dst), c->dest, APP_SEED_MAKEFILE) ||
        lstat(dst, &st) == 0)
        return as_fail(c->out, "SEED_COLLISION", "the app already carries a "
                       "Makefile; its make fragment is app.mk");
    struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    return r.ok || as_fail(c->out, "SEED_IO", "copying %s: %s", src,
                           r.message);
}

/* ── zcode-seed.def entries ──────────────────────────────────────────── */

/* Each component below the checkout is a plain directory and the last a
 * regular file: a symlink anywhere on the way is refused, never followed. */
static bool as_repo_file(struct as_ctx *c, const char *rel, char *abs,
                         size_t cap)
{
    char walk[AS_PATH];
    struct stat st;
    if (!as_join(abs, cap, c->repo, rel) ||
        !as_join(walk, sizeof(walk), c->repo, rel))
        return as_fail(c->out, "SEED_IO", "path too long: %s", rel);
    char *sep = walk + strlen(c->repo) + 1u;
    while ((sep = strchr(sep, '/')) != NULL) {
        *sep = '\0';
        if (lstat(walk, &st) != 0 || !S_ISDIR(st.st_mode))
            return as_fail(c->out, "SEED_NOT_REGULAR", "zcode-seed.def entry "
                           "'%s' passes through %s, which is not a plain "
                           "directory", rel, walk);
        *sep++ = '/';
    }
    if (lstat(abs, &st) != 0 || !S_ISREG(st.st_mode))
        return as_fail(c->out, "SEED_NOT_REGULAR", "zcode-seed.def entry '%s' "
                       "is not a regular file in the checkout", rel);
    return true;
}

static bool as_under_store(const char *tree)
{
    static const char *const stores[] = {"build/", ".zvcs/", ".codeindex/"};
    for (size_t i = 0; i < sizeof(stores) / sizeof(stores[0]); i++)
        if (strncmp(tree, stores[i], strlen(stores[i])) == 0)
            return true;
    return false;
}

static bool as_copy_mapped(struct as_ctx *c, const char *rel,
                           const char *tree)
{
    char src[AS_PATH], dst[AS_PATH], parent[AS_PATH];
    struct stat st;
    if (!vcs_package_path_valid(rel) || !vcs_package_path_valid(tree) ||
        as_under_store(tree))
        return as_fail(c->out, "SEED_PATH_ESCAPE", "zcode-seed.def entry "
                       "'%s %s' is not a canonical relative path pair inside "
                       "the checkout and the tree", rel, tree);
    if (!as_repo_file(c, rel, src, sizeof(src)))
        return false;
    if (!as_join(dst, sizeof(dst), c->dest, tree) || lstat(dst, &st) == 0)
        return as_fail(c->out, "SEED_COLLISION", "zcode-seed.def maps '%s' "
                       "onto '%s', which the tree already holds", rel, tree);
    (void)snprintf(parent, sizeof(parent), "%s", dst);
    char *slash = strrchr(parent, '/');
    if (slash)
        *slash = '\0';
    struct zcl_result r = zcl_mkdir_p(parent, 0755);
    if (r.ok)
        r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    if (!r.ok)
        return as_fail(c->out, "SEED_COLLISION", "zcode-seed.def entry '%s' "
                       "cannot be placed at '%s': %s", rel, tree, r.message);
    c->out->mapped++;
    return true;
}

/* One "<repo path> <tree path>" line; false with SEED_DEF_INVALID when it
 * is not exactly two fields. */
static bool as_line(struct as_ctx *c, char *line, size_t lineno)
{
    char *save = NULL;
    char *rel = strtok_r(line, " \t\r", &save);
    char *tree = rel ? strtok_r(NULL, " \t\r", &save) : NULL;
    if (!rel || rel[0] == '#')
        return true;
    if (!tree || strtok_r(NULL, " \t\r", &save) != NULL)
        return as_fail(c->out, "SEED_DEF_INVALID", "zcode-seed.def line %zu "
                       "is not '<repo path> <tree path>'", lineno);
    if (c->out->mapped >= APP_SEED_ENTRIES_MAX)
        return as_fail(c->out, "SEED_DEF_INVALID", "zcode-seed.def maps more "
                       "than %u files", APP_SEED_ENTRIES_MAX);
    return as_copy_mapped(c, rel, tree);
}

static bool as_copy_def(struct as_ctx *c)
{
    char path[AS_PATH];
    struct stat st;
    char *text = NULL;
    size_t len = 0;
    if (!as_join(path, sizeof(path), c->app_dir, APP_SEED_DEF))
        return as_fail(c->out, "SEED_IO", "path too long: %s", c->app_dir);
    if (lstat(path, &st) != 0)
        return true; /* an app with no host files */
    if (!S_ISREG(st.st_mode) ||
        !zcl_read_whole_file_text(path, APP_SEED_DEF_BYTES_MAX, &text, &len,
                                  "app.seed"))
        return as_fail(c->out, "SEED_DEF_INVALID", "%s is not a readable "
                       "regular file of at most %u bytes", path,
                       APP_SEED_DEF_BYTES_MAX);
    bool ok = true;
    size_t lineno = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); ok && line;
         line = strtok_r(NULL, "\n", &save))
        ok = as_line(c, line, ++lineno);
    free(text);
    return ok;
}

/* ── the stage ───────────────────────────────────────────────────────── */

/* apps and apps/<app> are plain directories of the checkout. */
static bool as_locate(struct as_ctx *c, const char *app)
{
    char apps[AS_PATH];
    struct stat st;
    if (!as_join(apps, sizeof(apps), c->repo, "apps") ||
        !as_join(c->app_dir, sizeof(c->app_dir), apps, app))
        return as_fail(c->out, "SEED_IO", "path too long: %s", c->repo);
    if (lstat(apps, &st) != 0 || !S_ISDIR(st.st_mode) ||
        lstat(c->app_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return as_fail(c->out, "APP_UNKNOWN", "%s is not an app directory "
                       "of the checkout", c->app_dir);
    return true;
}

bool app_seed_stage(const char *repo_root, const char *app, const char *dest,
                    struct app_seed_stage *out)
{
    struct as_ctx c = {.repo = repo_root, .dest = dest, .out = out};
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!repo_root || repo_root[0] != '/' || !dest || dest[0] != '/')
        return as_fail(out, "SEED_IO", "the checkout and the staging "
                       "directory must be absolute paths");
    if (!app_seed_name_valid(app))
        return as_fail(out, "BAD_APP", "app must be 1..%u of [a-z0-9_-], "
                       "starting with a letter or digit", APP_SEED_NAME_MAX);
    return as_locate(&c, app) && as_copy_app(&c) && as_copy_fragment(&c) &&
           as_copy_def(&c);
}
