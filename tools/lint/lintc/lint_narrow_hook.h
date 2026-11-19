/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the shared narrowing hooks behind the per-file lint gates'
 * --changed-files support. Each gate keeps its own wrapper symbol (the
 * selftests and priv headers name them) and supplies a descriptor; the
 * duplicated repo-root / path-form / baseline-compare / collect / baseline-
 * row-filter bodies live once in fast_narrow.c.
 */
#ifndef LINT_NARROW_HOOK_H
#define LINT_NARROW_HOOK_H

#include "lintc.h"

/* Per-gate narrowing descriptor. PATH_FORM receives the repo root resolved
 * for the gate (NULL for the gates that never resolve one) and returns the
 * repo-relative form a changed path is compared in; NULL keeps the path
 * unchanged. EXTRA_KEEP is the optional gate veto: nonzero on a formed
 * changed path keeps the whole-tree run (NULL keeps every path). REPO_
 * RESOLVE overrides the default cic_repo_root resolution (cyc, whose
 * relative-path fallback must not fail the gate); NULL resolves
 * cic_repo_root and a failure refuses narrowing. COLLECT_SKIP is the
 * optional per-path scan filter applied by lint_narrow_collect after the
 * .c/.h suffix test (CTX is the collect context). COLLECT_STAT nonzero
 * makes the shared body lstat each surviving path (ENOENT is skipped,
 * any other stat error reports and returns 2, non-regular files are
 * dropped) before EMIT; zero leaves the stat to EMIT (ssr stats
 * root-prefixed paths). */
struct lint_narrow_gate {
    const char *gate;
    const char *const *sources;
    const char *(*path_form)(const char *path, const char *repo);
    int (*extra_keep)(const char *path);
    int (*repo_resolve)(const struct lint_changed *ch, char out[4096],
                        const char **repo);
    int (*collect_skip)(void *ctx, const char *path);
    int collect_stat;
};

/* The *_narrow_ok shape shared by bo/hcs/ssr/cyc/cph/wps: 0 (run
 * whole-tree) when the gate is not narrowing (--changed-files absent), the
 * repo root cannot be resolved, a changed path is vetoed by EXTRA_KEEP, or
 * a changed path forms to BASELINE (the gate's own inputs include the
 * baseline or source list the narrow run would trust); 1 (narrow) when the
 * changed set can steer the scan. BASELINE may be NULL (wps): the
 * baseline compare is skipped and only the veto decides. */
int lint_narrow_ok(const struct lint_changed *ch, const char *baseline,
                   const struct lint_narrow_gate *g);

/* The *_collect_changed shape shared by hcs/ssr: resolve the repo root
 * into REPO (failure keeps the existing 2 convention), then for each
 * changed path: form it, require the .c/.h suffix, drop paths COLLECT_SKIP
 * rejects, lstat (ENOENT is skipped, any other stat error reports and
 * returns 2), require a regular file, and hand the path to EMIT — a
 * nonzero EMIT return aborts the collect and is returned. Returns 0 when
 * every surviving path was emitted. */
int lint_narrow_collect(const struct lint_changed *ch, char repo[4096],
                        const struct lint_narrow_gate *g,
                        int (*emit)(void *ctx, const char *path), void *ctx);

/* The *_base_narrow shape shared by hcs/ssr/cyc/cph: keep the baseline
 * keys matched by any of CHANGED[0..N), compacting KEYS in place and
 * returning the kept count. KEYS elements are KEY_LEN-byte rows whose
 * first bytes are the NUL-terminated key handed to MATCH; KEY_LEN equal
 * to sizeof(const char *) reads KEYS as a pointer row instead (the key is
 * the pointer itself). Kept rows are moved down in place. MATCH NULL
 * means the exact strcmp(key, path) rows. */
int lint_narrow_filter_keys(const char *const *changed, int n,
                            const char *keys[], int nkeys, int key_len,
                            int (*match)(const char *key, const char *path));

/* The repo-relative path form shared by the narrowing gates: strip a
 * "./" prefix, report an exact match to the repo root as ".", strip a
 * repo-prefix directory, and return the path unchanged when it is not
 * inside REPO. The _opt variant tolerates a NULL repo (a failed repo
 * root a gate keeps narrowing under while every changed path stays
 * relative) and returns the stripped path unchanged. */
const char *lint_narrow_repo_form(const char *path, const char *repo);
const char *lint_narrow_repo_form_opt(const char *path, const char *repo);

/* The *_repo resolver shared by the gates that tolerate a failed repo
 * root: resolve cic_repo_root into OUT and hand it back through REPO;
 * when that fails, refuse (2) only if a changed path is absolute, else
 * pass NULL. */
int lint_narrow_repo_opt(const struct lint_changed *ch, char out[4096],
                         const char **repo);

/* True when PATH lives under one of the NROOTS repo-relative scan roots
 * (a "" or "." root means any relative path, "/" means everything). */
int lint_narrow_under_roots(const char *path, char roots[][RS_PATH],
                            int nroots, const char *repo);

/* True when PATH is exactly inside one of the NULL-terminated root
 * prefixes (root + '/'). */
int lint_narrow_roots_prefix(const char *path, const char *const *roots);

/* True when PATH ends exactly with SUFFIX (the db/hfs/zpr/wps *_suffix
 * shape). */
int lint_narrow_suffix(const char *path, const char *suffix);

/* The *_relevant shape shared by db/zpr: 1 when the gate must run
 * whole-tree (--changed-files absent or any changed path is kept by
 * RELEVANT), else 0. */
int lint_narrow_relevant(const struct lint_changed *ch,
                         int (*relevant)(const char *path));

/* The selftest GIT_* env fence shared by cyc/jvi: save the named
 * variables into VALUES (n slots, strdup'd; a failed strdup frees the
 * earlier slots and returns 1), unset every named variable (nonzero on
 * any unsetenv failure), and restore/free them (nonzero on any setenv or
 * unsetenv failure; a NULL slot restores by unsetting). */
int lint_narrow_env_save(const char *const *names, char *values[], int n);
int lint_narrow_env_clear(const char *const *names, int n);
int lint_narrow_env_restore(const char *const *names,
                            char *const values[], int n);

/* The selftest child wait shared by db/zpr: block on PID (EINTR retries),
 * die with "<WHAT> waitpid failed: <errno>" on any other failure, and
 * map the exit status to the shell convention (exit code, else 128+sig,
 * else 2). */
int lint_narrow_wait_pid(pid_t pid, const char *what);

#endif
