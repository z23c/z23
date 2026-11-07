/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_seed — compose the self-contained staging tree an in-repo app is
 * seeded from, so the seeded package (and every copy or friend's received
 * copy of it) holds everything its build reads.
 *
 * The tree, from the source checkout <repo>:
 *   - every regular file under apps/<app>, at its path below apps/<app>,
 *     except zcode-seed.def, and except the root-level build/, .zvcs/ and
 *     .codeindex/ stores no package covers. apps/<app>/Makefile is the
 *     package entrypoint app.build runs (command/app_build_make.h:
 *     print-app-closure, and app with APP_OUT);
 *   - each repo file apps/<app>/zcode-seed.def maps, one entry per line:
 *         <repo path> <tree path>
 *     '#' starts a comment line and blank lines are ignored.
 *
 * Once staged, the tree's own `make print-app-closure` runs on it, confined
 * with nothing writable and bounded (app_build_closure_query), and every
 * input it names must be a regular file of the tree: the seed proves the
 * package holds its build's closure before anything is signed.
 *
 * Every path is a canonical package path (vcs_package_path_valid): relative,
 * no empty, '.' or '..' component. Each repo path is resolved component by
 * component with lstat, and anything that is not a plain directory or, at
 * the end, a regular file (a symlink above all) is refused, so no entry can
 * reach outside the checkout. A tree path may not collide with an app file,
 * the Makefile or another entry, and may not lie under a root-level store.
 *
 * Determinism: files are copied by the one tree walker (util/file_tree_ops.h:
 * symlinks refused, never followed) with their bytes and mode, and the
 * package root binds only bytes, paths and the executable bit git tracks,
 * so the same checkout gives the same package root on every host and in
 * every staging directory.
 */
#ifndef ZCL_TOOLS_COMMAND_APP_SEED_H
#define ZCL_TOOLS_COMMAND_APP_SEED_H

#include <stdbool.h>
#include <stddef.h>

#define APP_SEED_DEF "zcode-seed.def"
#define APP_SEED_MAKEFILE "Makefile"
#define APP_SEED_NAME_MAX 64u
#define APP_SEED_ENTRIES_MAX 1024u
#define APP_SEED_DEF_BYTES_MAX (256u << 10)

struct app_seed_stage {
    size_t mapped;   /* zcode-seed.def entries staged */
    size_t closure;  /* inputs the tree's print-app-closure names */
    bool unconfined; /* the closure query ran with no confinement */
    char code[40];  /* the refusal code when staging fails */
    char why[512];   /* what was refused, naming the path */
};

/* An app name: 1..APP_SEED_NAME_MAX of [a-z0-9_-], starting alphanumeric. */
bool app_seed_name_valid(const char *app);

/* Compose the tree for apps/<app> of the checkout at repo_root into dest,
 * an existing empty directory. False with out->code and out->why on
 * refusal: BAD_APP, APP_UNKNOWN, NO_PACKAGE_ENTRYPOINT (no Makefile),
 * SEED_DEF_INVALID, SEED_PATH_ESCAPE (not a canonical relative path, '..'
 * above all, or a tree path under a root-level store), SEED_NOT_REGULAR (a
 * symlink or special file), SEED_COLLISION, SEED_IO or NO_PACKAGE_TARGETS
 * (the staged Makefile has no print-app-closure, or names an input the tree
 * does not hold). dest may hold a partial tree
 * after a refusal; the caller removes it. */
bool app_seed_stage(const char *repo_root, const char *app, const char *dest,
                    struct app_seed_stage *out);

#endif /* ZCL_TOOLS_COMMAND_APP_SEED_H */
