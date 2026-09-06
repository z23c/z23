/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-framework-shape
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded this gate into an
 * existing family are overridden by that ruling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* ── check-framework-shape (Gate #18, port of framework_shape_check.sh) ────
 * Every .c file directly under an app authority (engine, cognition,
 * contexts/<product-context>) is a violation; files under
 * <authority>/<shape>/src/ are in shape. Authority and shape sets come from
 * rs_init() (the repo_shape.sh derivation), never spelled out here.
 *
 * Baseline mapping: the shell gate loaded framework_shape_allowlist.txt with
 * gate_load_list_file() — a presence SET, not an exact-pin ratchet: a missing
 * file is an empty set, `#` starts a comment anywhere, whitespace is trimmed,
 * duplicates collapse silently, and an entry no scan observed is unused,
 * never stale. That is lint_base_load_set() semantics, so this gate uses the
 * set mode (as check-no-orphan-placement does) and never calls
 * lint_base_finish on it.
 *
 * The violation line's shape list below is a VERBATIM string from the shell
 * gate (its order differs from the Makefile's APP_DIRS); deriving it from
 * g_shapes would change the bytes, so it stays a literal.
 *
 * Deliberate parity quirk — the truncated scan: the shell gate ran its finds
 * inside `< <( for ...; do find ... 2>/dev/null; ... done | sort -u )` under
 * `set -euo pipefail`. The first `find` whose directory does not exist (e.g.
 * engine/views/src) exits 1, and errexit kills the producer subshell at that
 * point: every authority/shape after it in iteration order is NEVER scanned,
 * and the gate reports the truncated count (205, not 864, on the 2026-09-06
 * tree) with a clean exit. Byte parity with the shipped gate requires the
 * same stop-at-first-missing-dir scan, reproduced by FSC_HALT below. This is
 * a latent hollow-scan defect in the original; the port preserves it exactly
 * rather than repairing it silently. */

static const char k_fsc_allow[] = "tools/lint/framework_shape_allowlist.txt";
static struct lint_base g_fsc_allowed;

struct fsc_files { char **v; size_t n, cap; };

struct fsc_acc {
    FILE *err;
    const char *mode;
    int fail_mode;
    int scanned, viol, allow;
    char (*auth)[RS_PATH];
    int n_auth;
    char (*shapes)[RS_NAME];
    int n_shapes;
};

static const char *fsc_root(void)
{
    const char *e = getenv("ZCL_REPO_SHAPE_ROOT");
    return (e && e[0]) ? e : ".";
}

static int fsc_push(struct fsc_files *fs, const char *path)
{
    if (fs->n == fs->cap) {
        size_t nc = fs->cap ? fs->cap * 2 : 64;
        char **nv = realloc(fs->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        fs->v = nv;
        fs->cap = nc;
    }
    char *copy = strdup(path);
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    fs->v[fs->n++] = copy;
    return 0;
}

/* find <root>/<rel> -maxdepth 1 -type f -name '*.c' 2>/dev/null. Returns 0 on
 * success, 2 on a real error, and FSC_HALT when the dir is missing or
 * unreadable — the shell find exited 1 there and errexit killed the whole
 * producer subshell, so the scan STOPS here instead of skipping (see the
 * parity-quirk comment above). A file that vanishes mid-scan is skipped the
 * same way find skips it. */
#define FSC_HALT 3
static int fsc_collect_dir(const char *root, const char *rel,
                           struct fsc_files *fs)
{
    char dir[1024];
    if (ovf(snprintf(dir, sizeof dir, "%s/%s", root, rel), sizeof dir))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return FSC_HALT;
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *name = names[i]->d_name;
        size_t nl = strlen(name);
        if (nl >= 2 && name[nl - 2] == '.' && name[nl - 1] == 'c') {
            char full[1024], path[1024];
            struct stat st;
            if (ovf(snprintf(full, sizeof full, "%s/%s", dir, name),
                    sizeof full)
                || ovf(snprintf(path, sizeof path, "%s/%s", rel, name),
                       sizeof path))
                rc = 2;
            else if (lstat(full, &st) == 0 && S_ISREG(st.st_mode))
                rc = fsc_push(fs, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int fsc_collect(const char *root, const struct fsc_acc *a,
                       struct fsc_files *fs)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < a->n_auth; i++) {
        rc = fsc_collect_dir(root, a->auth[i], fs);
        for (int s = 0; rc == 0 && s < a->n_shapes; s++) {
            char rel[RS_PATH + RS_NAME + 8];
            if (ovf(snprintf(rel, sizeof rel, "%s/%s/src",
                             a->auth[i], a->shapes[s]), sizeof rel)) {
                rc = 2;
                break;
            }
            rc = fsc_collect_dir(root, rel, fs);
        }
    }
    return rc == FSC_HALT ? 0 : rc;
}

static int fsc_cmp(const void *a, const void *b)
{
    return strcoll(*(char *const *)a, *(char *const *)b);
}

/* sort -u under the ambient locale: LC_COLLATE is set by the caller before
 * this runs, and collation-equal lines collapse the way sort -u drops them. */
static void fsc_sort_uniq(struct fsc_files *fs)
{
    qsort(fs->v, fs->n, sizeof fs->v[0], fsc_cmp);
    size_t w = 0;
    for (size_t i = 0; i < fs->n; i++) {
        if (w > 0 && strcoll(fs->v[w - 1], fs->v[i]) == 0) {
            free(fs->v[i]);
            continue;
        }
        fs->v[w++] = fs->v[i];
    }
    fs->n = w;
}

/* is_known_shape_path(): 1 known, 0 not known, 2 on buffer overflow. */
static int fsc_known(const char *path, const struct fsc_acc *a)
{
    size_t pl = strlen(path);
    if (pl < 3 || path[pl - 2] != '.' || path[pl - 1] != 'c')
        return 0;
    for (int i = 0; i < a->n_auth; i++) {
        for (int s = 0; s < a->n_shapes; s++) {
            char pre[RS_PATH + RS_NAME + 8];
            if (ovf(snprintf(pre, sizeof pre, "%s/%s/src/",
                             a->auth[i], a->shapes[s]), sizeof pre))
                return 2;
            size_t n = strlen(pre);
            if (pl > n && strncmp(path, pre, n) == 0)
                return 1;
        }
    }
    return 0;
}

static int fsc_one(const char *path, struct fsc_acc *a)
{
    a->scanned++;
    int known = fsc_known(path, a);
    if (known == 2)
        return 2;
    if (known)
        return 0;
    if (!a->fail_mode && lint_base_observe(&g_fsc_allowed, path, 1) >= 0) {
        a->allow++;
        return 0;
    }
    a->viol++;
    return fprintf(a->err, "%s: not in a known shape folder (expected one of: "
                   "controllers, services, models, jobs, supervisors, "
                   "conditions, views)\n", path) < 0
               ? die("z23-lint: write failed\n", "")
               : 0;
}

static int fsc_finish(const struct fsc_acc *a, FILE *out)
{
    if (fprintf(out, "[framework_shape_check] scanned %d application-shape "
                ".c files\n", a->scanned) < 0
        || fprintf(out, "[framework_shape_check] %d violation(s) found "
                   "(mode: %s)\n", a->viol, a->mode) < 0)
        return die("z23-lint: write failed\n", "");
    if (a->allow > 0
        && fprintf(out, "[framework_shape_check] %d allowlisted violation(s) "
                   "ignored\n", a->allow) < 0)
        return die("z23-lint: write failed\n", "");
    if (fprintf(out, "[framework_shape_check] write to "
                "tools/lint/framework_shape_allowlist.txt to allowlist "
                "existing violations\n") < 0)
        return die("z23-lint: write failed\n", "");
    return (a->viol > 0
            && (a->fail_mode || strcmp(a->mode, "RATCHET") == 0)) ? 1 : 0;
}

static int fsc_check(const char *root, const char *mode,
                     const char *allow_path, char auth[][RS_PATH], int n_auth,
                     char shapes[][RS_NAME], int n_shapes,
                     FILE *out, FILE *err)
{
    struct fsc_files fs = { NULL, 0, 0 };
    struct fsc_acc a;
    memset(&a, 0, sizeof a);
    a.err = err;
    a.mode = mode;
    a.fail_mode = strcmp(mode, "FAIL") == 0;
    a.auth = auth;
    a.n_auth = n_auth;
    a.shapes = shapes;
    a.n_shapes = n_shapes;
    int rc = lint_base_load_set(&g_fsc_allowed, allow_path);
    if (rc == 0)
        rc = fsc_collect(root, &a, &fs);
    if (rc == 0) {
        (void)setlocale(LC_COLLATE, "");
        fsc_sort_uniq(&fs);
        for (size_t i = 0; rc == 0 && i < fs.n; i++)
            rc = fsc_one(fs.v[i], &a);
    }
    int fin_rc = rc == 0 ? fsc_finish(&a, out) : rc;
    for (size_t i = 0; i < fs.n; i++)
        free(fs.v[i]);
    free(fs.v);
    return fin_rc;
}

int check_framework_shape_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int rc = rs_init();
    if (rc)
        return rc;
    return fsc_check(fsc_root(), env_or("ZCL_LINT_MODE", "WARN"), k_fsc_allow,
                     g_auth, g_n_auth, g_shapes, g_n_shapes, stdout, stderr);
}

/* ── selftest ──────────────────────────────────────────────────────────── */

static int fsc_st_files(const char *root, int plant, const char *base_body,
                        char *bp, size_t bcap)
{
    char stray[4096];
    if (ovf(snprintf(stray, sizeof stray, "%s/eng/stray.c", root),
            sizeof stray)
        || ovf(snprintf(bp, bcap, "%s/allow.txt", root), bcap))
        return 1;
    if (plant) {
        if (csr_write(stray, "int fsc_st_stray;\n"))
            return 1;
    } else {
        (void)unlink(stray);
    }
    if (base_body)
        return csr_write(bp, base_body) != 0;
    (void)unlink(bp);
    return 0;
}

static int fsc_st_slurp(FILE *out, FILE *err, char *both, size_t cap)
{
    char bo[8192], be[8192];
    int rc = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be)
        | ovf(snprintf(both, cap, "%s%s", bo, be), cap);
    fclose(out);
    fclose(err);
    return rc;
}

static int fsc_st_case(const char *root, char auth[][RS_PATH], int n_auth,
                       char shapes[][RS_NAME], int n_shapes, int plant,
                       const char *base_body, const char *mode, int want_rc,
                       const char *needle)
{
    char bp[4096];
    if (fsc_st_files(root, plant, base_body, bp, sizeof bp))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = fsc_check(root, mode, bp, auth, n_auth, shapes, n_shapes,
                       out, err);
    char both[16384];
    if (fsc_st_slurp(out, err, both, sizeof both))
        return 1;
    if (rc != want_rc || (needle && !strstr(both, needle))) {
        fprintf(stderr, "check_framework_shape selftest: mode %s want rc %d "
                "needle '%s'; got rc %d and:\n%s\n",
                mode, want_rc, needle ? needle : "(none)", rc, both);
        return 1;
    }
    return 0;
}

int check_framework_shape_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-fsc-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    static char st_auth[2][RS_PATH];
    static char st_shapes[2][RS_NAME];
    memcpy(st_auth[0], "eng", 4);
    memcpy(st_auth[1], "ctx/x", 6);
    memcpy(st_shapes[0], "services", 9);
    memcpy(st_shapes[1], "models", 7);
    int bad = 0;
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/eng/services/src/ok.c", root), sizeof p)
        || csr_write(p, "int fsc_st_ok;\n")
        || ovf(snprintf(p, sizeof p, "%s/eng/models/src/m.c", root), sizeof p)
        || csr_write(p, "int fsc_st_m;\n")
        || ovf(snprintf(p, sizeof p, "%s/ctx/x/services/src/z.c", root),
               sizeof p)
        || csr_write(p, "int fsc_st_z;\n"))
        bad = 1;
    if (!bad) {
        /* a clean tree passes RATCHET and reports the scan count */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 0, NULL, "RATCHET",
                           0, "scanned 3 application-shape .c files\n"
                           "[framework_shape_check] 0 violation(s) found "
                           "(mode: RATCHET)");
        /* an off-shape file directly under an authority fails RATCHET */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1, NULL, "RATCHET",
                           1, "eng/stray.c: not in a known shape folder "
                           "(expected one of: controllers, services, models, "
                           "jobs, supervisors, conditions, views)");
        /* WARN reports the same violation but exits 0 */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1, NULL, "WARN", 0,
                           "1 violation(s) found (mode: WARN)\n");
        /* a set member is allowlisted, not failed */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1,
                           "eng/stray.c\n", "RATCHET", 0,
                           "1 allowlisted violation(s) ignored");
        /* FAIL mode ignores the set entirely */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1,
                           "eng/stray.c\n", "FAIL", 1,
                           "eng/stray.c: not in a known shape folder");
        /* set semantics: an entry nobody scanned is unused, never stale */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 0,
                           "eng/gone.c\n", "RATCHET", 0,
                           "0 violation(s) found");
        /* gate_load_list_file trims and takes `#` as a comment anywhere */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1,
                           "  eng/stray.c  # relocated soon\n", "RATCHET", 0,
                           "1 allowlisted violation(s) ignored");
        /* duplicate entries collapse silently */
        bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1,
                           "eng/stray.c\neng/stray.c\n", "RATCHET", 0,
                           "1 allowlisted violation(s) ignored");
        /* the shell parity quirk: the first missing dir kills the producer
         * subshell (errexit), so with eng/models/src gone the scan stops
         * after eng/services/src — eng/stray.c is seen (2 files), but
         * ctx/x/services/src/z.c never is */
        if (ovf(snprintf(p, sizeof p, "%s/eng/models/src", root), sizeof p)
            || rap_rm_rf(p))
            bad |= 1;
        else
            bad |= fsc_st_case(root, st_auth, 2, st_shapes, 2, 1, NULL,
                               "RATCHET", 1,
                               "scanned 2 application-shape .c files\n"
                               "[framework_shape_check] 1 violation(s) found "
                               "(mode: RATCHET)");
    }
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_framework_shape selftest: OK\n");
}
