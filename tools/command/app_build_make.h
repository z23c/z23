/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_build_make — the make fragment contract app.build runs a personal app
 * copy through, out of tree, under lab_exec's COMPILE confinement where the
 * host can apply it (Landlock, seccomp, no_new_privs, rlimits) and
 * unconfined elsewhere, saying so.
 *
 * A buildable copy carries a `Makefile` at its root with two targets:
 *   print-app-closure  prints every input file the build reads, one
 *                      copy-relative path per line (the per-copy twin of
 *                      the repository's print-game-closure);
 *   app                builds $(APP_OUT)/app, compiling with -MD so each
 *                      compile leaves a depfile under $(APP_OUT).
 * Both run as `make --no-print-directory -C <copy> ...` with the copy as
 * the working directory. APP_OUT is a fresh directory inside the copy's
 * persistent build directory, so $(APP_OUT)/.. is that build directory.
 * Under confinement the copy is read-only and only the build directory (and
 * /dev/null) is writable: a fragment that writes anywhere else fails.
 *
 * The declared closure. Each declared path must be a canonical package path
 * (vcs_package_path_valid) naming a regular file in the copy, outside the
 * root-level build/, .zvcs/ and .codeindex/ stores the package root does not
 * cover. Its root is vcs_build_input_closure_v1_root() of a closure whose
 * positive class is SHA3 over the sorted (path, file SHA3) list and whose
 * build-graph, harness and policy classes name this contract. It is the
 * DECLARED closure, not a per-compile zcl.action_preimage.v2 derivation:
 * make does not expose each compile's exact argv and environment. After a
 * build, every local depfile prerequisite must resolve to a declared regular
 * input inside the copy (app_build_depfiles_declared). Relative and
 * copy-prefixed escapes are refused. Existing externally absolute inputs
 * remain allowed; the env root does NOT bind arbitrary external header bytes.
 * Actual compiler-action capture and cache revalidation are still required
 * to close that separate evidence gap. */
#ifndef ZCL_TOOLS_COMMAND_APP_BUILD_MAKE_H
#define ZCL_TOOLS_COMMAND_APP_BUILD_MAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_BUILD_CLOSURE_MAX 2048u
#define APP_BUILD_TAIL_MAX 2048u
#define APP_BUILD_IMAGE_NAME "app"

struct app_build_closure {
    char **paths; /* sorted, unique, copy-relative */
    size_t count;
    uint8_t root[32];
};

void app_build_closure_free(struct app_build_closure *c);

struct app_toolchain;
struct app_build_make {
    const struct app_toolchain *kit; /* authenticated, sealed selected kit, or NULL */
    const char *copy_dir; /* canonical absolute copy directory */
    const char *work_dir; /* the copy's writable build directory */
    bool confine;         /* apply lab_exec confinement */
};

struct app_build_make_result {
    bool ok;
    bool unconfined; /* ran with no confinement applied */
    char tail[APP_BUILD_TAIL_MAX + 1u];
    char why[256];
};

/* True when this host confines a make fragment (lab_sandbox_available). */
bool app_build_make_confinable(void);

/* Run `make print-app-closure` (nothing writable) and root what it prints.
 * False with `why` on a failed query or an invalid, missing or oversized
 * declaration. */
bool app_build_closure_query(const struct app_build_make *m,
                             struct app_build_closure *out, char *why,
                             size_t why_cap);

/* Run `make app APP_OUT=<out_dir>`; out_dir lies inside m->work_dir. */
void app_build_make_run(const struct app_build_make *m, const char *out_dir,
                        struct app_build_make_result *r);

/* Every -MD depfile under out_dir names only declared copy inputs. False
 * with `why` naming the first undeclared input, or when there is none. */
bool app_build_depfiles_declared(const struct app_build_make *m,
                                 const char *out_dir,
                                 const struct app_build_closure *c, char *why,
                                 size_t why_cap);

#endif /* ZCL_TOOLS_COMMAND_APP_BUILD_MAKE_H */
