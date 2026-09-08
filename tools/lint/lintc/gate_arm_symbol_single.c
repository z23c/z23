/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-arm-symbol-single
 * Four-file family under the 700-line ceiling: this file holds the root
 * list, file collection, the baseline ratchet, and the verdict;
 * gate_arm_symbol_single_analyzer.c holds the line-oriented function-
 * definition analyzer; gate_arm_symbol_single_coverage.c holds the
 * coverage oracle; gate_arm_symbol_single_selftest.c holds --selftest.
 *
 * Byte-parity C23 port of tools/lint/check_arm_symbol_single.sh (a
 * non-static function is DEFINED — has a body — only ONCE per translation
 * unit; since the C standard already forbids two unconditional definitions
 * of one external symbol, any hit is necessarily two disjoint preprocessor
 * arms). RATCHET: tools/lint/arm_symbol_single_baseline.txt, shrink-only.
 *
 * Scan-set deviation (deliberate, per the lane brief, not a shell-parity
 * choice): the shell scans via `find "$root" -name '*.c' -type f`, a plain
 * filesystem walk. This port instead walks the tracked git index
 * (lint_git_index_foreach) when ".git" is present, falling back to the
 * same filesystem walk when it is absent (an extracted archive with no
 * VCS metadata). On any tree this gate is actually run against — a git
 * worktree with no untracked stray .c files under its six scan roots, or a
 * `git archive` extraction whose only files ARE the tracked set — the two
 * approaches enumerate the identical file set; the git-index path is
 * simply spawn-free where `find` was a subprocess.
 *
 * The coverage oracle (an independent expectation the scan set is checked
 * against) is unchanged: gate_lib.sh's gate_require_git_coverage spawns
 * `git ls-files --cached -- <pathspec>...` for real, and so does this
 * port, via capture_cmd — a producer the original also ran, reproduced
 * command-for-command including the exact pathspec set and diagnostic
 * text. When ".git" is absent this call fails exactly as the shell's
 * would (not a git repository), and the port reproduces gate_git_oracle's
 * own UNPROVEN text for that failure byte-for-byte.
 *
 * The analyzer is a direct, line-oriented port of the shell's own awk
 * state machine (write_analyzer() in the original): brace-depth (bdepth)
 * and paren-depth (pdepth) tracking per file, comment/string/char-literal
 * stripping ahead of counting, and the same identifier-before-"("
 * classification (SCREAMING_SNAKE_CASE, __attribute__, __declspec are
 * "not a function name"; a leading `static` token on the signature line
 * or the line directly above marks internal linkage). Duplicate detection
 * is scoped per file (as in the shell, FNR==1 resets all state so no
 * bleed between files) and only among NON-static candidate names, since
 * "$file\t$name" is the count key both sides key on.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_arm_symbol_single_priv.h"

enum { ASY_LINE = 8192, ASY_NAME = 256, ASY_SIG = 4096 };
enum { ASY_MAXCAND = 4096 };
enum { ASY_MAXPAIR = 2048, ASY_PAIRKEY = ASY_PATH + ASY_NAME };

const char k_asy_gate[] = "check_arm_symbol_single";
static const char k_asy_baseline_default[] =
    "tools/lint/arm_symbol_single_baseline.txt";
const char *const k_asy_roots_default[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

struct asy_roots { char r[ASY_MAXROOTS][ASY_ROOT]; int n; };
struct asy_pairs { char k[ASY_MAXPAIR][ASY_PAIRKEY]; int n; };

/* ── root list: env override or the fixed default ─────────────────────── */

static int asy_split_roots(const char *s, struct asy_roots *out)
{
    out->n = 0;
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        size_t n = (size_t)(p - start);
        if (n == 0)
            continue;
        if (out->n >= ASY_MAXROOTS || n >= ASY_ROOT)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out->r[out->n], start, n);
        out->r[out->n][n] = '\0';
        out->n++;
    }
    return 0;
}

static int asy_default_roots(struct asy_roots *out)
{
    out->n = ASY_NROOTS_DEFAULT;
    for (int i = 0; i < ASY_NROOTS_DEFAULT; i++)
        snprintf(out->r[i], ASY_ROOT, "%s", k_asy_roots_default[i]);
    return 0;
}

/* ── file collection ───────────────────────────────────────────────────── */

static int asy_path_under_roots(const char *path, const struct asy_roots *rs)
{
    size_t pl = strlen(path);
    if (pl < 3 || path[pl - 1] != 'c' || path[pl - 2] != '.')
        return 0;
    for (int i = 0; i < rs->n; i++) {
        size_t rl = strlen(rs->r[i]);
        if (strncmp(path, rs->r[i], rl) == 0 && path[rl] == '/')
            return 1;
    }
    return 0;
}

int asy_files_add(struct asy_files *fs, const char *path)
{
    if (fs->n >= ASY_MAXFILES)
        return die("z23-lint: scan-set overflow\n", "");
    if (ovf(snprintf(fs->p[fs->n], ASY_PATH, "%s", path), ASY_PATH))
        return 2;
    fs->n++;
    return 0;
}

struct asy_idx_ctx { struct asy_files *fs; const struct asy_roots *rs; };

static int asy_on_idx(const char *path, int stage, void *ctx)
{
    (void)stage;
    struct asy_idx_ctx *c = ctx;
    if (!asy_path_under_roots(path, c->rs))
        return 0;
    return asy_files_add(c->fs, path);
}

/* `find "$root" -name '*.c' -type f` fallback: a plain recursive readdir,
 * dotfiles included (find's -name has no FNM_PERIOD), regular files only
 * (a symlinked .c file resolves through stat and is included, same as
 * find's default non-`-P` behavior). */
static int asy_walk(const char *dir, struct asy_files *fs)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char path[ASY_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/%s", dir, e->d_name),
                sizeof path)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            rc = asy_walk(path, fs);
            continue;
        }
        struct stat rst;
        if (stat(path, &rst) != 0 || !S_ISREG(rst.st_mode))
            continue;
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c") != 0)
            continue;
        rc = asy_files_add(fs, path);
    }
    closedir(d);
    return rc;
}

static int asy_collect(struct asy_files *fs, const struct asy_roots *rs)
{
    fs->n = 0;
    struct stat st;
    if (stat(".git", &st) == 0) {
        struct asy_idx_ctx c = { .fs = fs, .rs = rs };
        char bad[8] = {0};
        int rc = lint_git_index_foreach(asy_on_idx, &c, bad);
        if (rc) {
            fprintf(stderr,
                    "%s: UNPROVEN — git index%s%s could not be read.\n",
                    k_asy_gate, bad[0] ? " extension " : "", bad);
            return rc;
        }
        return 0;
    }
    int rc = 0;
    for (int i = 0; rc == 0 && i < rs->n; i++) {
        struct stat rst;
        if (stat(rs->r[i], &rst) != 0 || !S_ISDIR(rst.st_mode))
            continue;
        rc = asy_walk(rs->r[i], fs);
    }
    return rc;
}

static int asy_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

void asy_sort_files(struct asy_files *fs)
{
    qsort(fs->p, (size_t)fs->n, ASY_PATH, asy_path_cmp);
}

/* ── one file's scan: candidate collection then per-file dup detection ── */

struct asy_cand { char name[ASY_NAME]; int is_static; };

struct asy_file_scan {
    struct asy_cand c[ASY_MAXCAND];
    int n;
};

static int asy_file_emit(const char *file, void *ctx, const char *name,
                         int line, int is_static)
{
    (void)file;
    (void)line;
    struct asy_file_scan *fs = ctx;
    if (fs->n >= ASY_MAXCAND)
        return die("z23-lint: scan-set overflow\n", "");
    snprintf(fs->c[fs->n].name, ASY_NAME, "%s", name);
    fs->c[fs->n].is_static = is_static;
    fs->n++;
    return 0;
}

static int asy_pairs_add(struct asy_pairs *ps, const char *file,
                         const char *name)
{
    if (ps->n >= ASY_MAXPAIR)
        return die("z23-lint: scan-set overflow\n", "");
    if (ovf(snprintf(ps->k[ps->n], ASY_PAIRKEY, "%s\t%s", file, name),
            ASY_PAIRKEY))
        return 2;
    ps->n++;
    return 0;
}

static int asy_scan_one_file(const char *path, struct asy_pairs *found)
{
    struct asy_file_scan fs = { .n = 0 };
    int rc = asy_analyze_file(path, asy_file_emit, &fs);
    if (rc)
        return rc;
    for (int i = 0; i < fs.n; i++) {
        if (fs.c[i].is_static)
            continue;
        int count = 0;
        for (int j = 0; j < fs.n; j++)
            if (!fs.c[j].is_static && strcmp(fs.c[j].name, fs.c[i].name) == 0)
                count++;
        if (count < 2)
            continue;
        int already = 0;
        for (int j = 0; j < i; j++)
            if (!fs.c[j].is_static
                && strcmp(fs.c[j].name, fs.c[i].name) == 0) { already = 1; break; }
        if (already)
            continue;
        if (asy_pairs_add(found, path, fs.c[i].name))
            return 2;
    }
    return 0;
}

static int asy_pair_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* ── baseline: the generated-artifact preamble + <path>\t<function> set ── */

static const char *const k_asy_claims[] = {
    "# z23-generated-artifact: zcl.generated_artifact.v1",
    "# artifact-id: zcl.arm_symbol_single_baseline.v1",
    "# asserts: multi_arm_definition(path,symbol)",
    "# generated-by: tools/lint/check_arm_symbol_single.sh",
    "# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh",
};
enum { ASY_NCLAIMS = 5 };

static int asy_baseline_check_claims(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[%s] UNPROVEN — generated artifact absent or lacks: %s\n",
                k_asy_gate, k_asy_claims[0]);
        return 2;
    }
    int seen[ASY_NCLAIMS] = {0};
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (int i = 0; i < ASY_NCLAIMS; i++)
            if (strcmp(line, k_asy_claims[i]) == 0)
                seen[i] = 1;
    }
    free(line);
    fclose(f);
    for (int i = 0; i < ASY_NCLAIMS; i++) {
        if (!seen[i]) {
            fprintf(stderr,
                    "[%s] UNPROVEN — generated artifact absent or lacks: %s\n",
                    k_asy_gate, k_asy_claims[i]);
            return 2;
        }
    }
    return 0;
}

struct asy_base { char k[ASY_MAXPAIR][ASY_PAIRKEY]; int n; };

static int asy_base_load(struct asy_base *b, const char *path, int *count)
{
    b->n = 0;
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (!strchr(line, '\t'))
            continue;
        if (b->n >= ASY_MAXPAIR) {
            free(line);
            fclose(f);
            return die("z23-lint: baseline overflow\n", "");
        }
        snprintf(b->k[b->n], ASY_PAIRKEY, "%s", line);
        b->n++;
        (*count)++;
    }
    free(line);
    fclose(f);
    return 0;
}

/* ── the gate body, decomposed to stay under the complexity cap ─────────── */

struct asy_ctx {
    const char *mode;
    const char *baseline;
    const char *roots_env;
    int floor;
    int cov_on;
    int cov_allow;
};

static void asy_ctx_load(struct asy_ctx *c)
{
    c->mode = env_or("ZCL_LINT_MODE", "FAIL");
    c->baseline = env_or("ZCL_ARM_SYMBOL_BASELINE", k_asy_baseline_default);
    c->roots_env = getenv("ZCL_ARM_SYMBOL_SCAN_ROOTS");
    c->floor = atoi(env_or("ZCL_ARM_SYMBOL_FILE_FLOOR", "2500"));
    c->cov_on = strcmp(env_or("ZCL_ARM_SYMBOL_COVERAGE", "1"), "1") == 0;
    c->cov_allow = atoi(env_or("ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE", "0"));
}

/* Resolves roots, collects and sorts the scan set, enforces the hollow-scan
 * floor, and (if enabled) checks coverage. */
static int asy_gather(const struct asy_ctx *c, struct asy_files *scan_files)
{
    struct asy_roots roots;
    int rc = (c->roots_env && c->roots_env[0])
        ? asy_split_roots(c->roots_env, &roots) : asy_default_roots(&roots);
    if (rc)
        return rc;

    rc = asy_collect(scan_files, &roots);
    if (rc)
        return rc;
    asy_sort_files(scan_files);

    char hint[256];
    snprintf(hint, sizeof hint, "no production .c under: %s",
            c->roots_env && c->roots_env[0] ? c->roots_env
                : "core engine contexts cognition platform tools");
    rc = gate_require_scanned(scan_files->n, c->floor, k_asy_gate, hint);
    if (rc)
        return rc;

    if (c->cov_on)
        return asy_coverage(scan_files, c->cov_allow);
    return 0;
}

static int asy_scan_all(const struct asy_files *scan_files,
                        struct asy_pairs *found)
{
    found->n = 0;
    for (int i = 0; i < scan_files->n; i++) {
        int rc = asy_scan_one_file(scan_files->p[i], found);
        if (rc)
            return rc;
    }
    qsort(found->k, (size_t)found->n, ASY_PAIRKEY, asy_pair_cmp);
    return 0;
}

/* Splits found-vs-baseline into new violations and stale rows. */
static void asy_diff_baseline(const struct asy_pairs *found,
                              const struct asy_base *base,
                              char violations[][ASY_PAIRKEY], int *nv,
                              char stale[][ASY_PAIRKEY], int *ns)
{
    static char hit[ASY_MAXPAIR];
    memset(hit, 0, sizeof hit);
    *nv = 0;
    for (int i = 0; i < found->n; i++) {
        int bidx = -1;
        for (int j = 0; j < base->n; j++)
            if (strcmp(base->k[j], found->k[i]) == 0) { bidx = j; break; }
        if (bidx >= 0)
            hit[bidx] = 1;
        else if (*nv < ASY_MAXPAIR)
            snprintf(violations[(*nv)++], ASY_PAIRKEY, "%s", found->k[i]);
    }
    *ns = 0;
    for (int j = 0; j < base->n; j++)
        if (!hit[j] && *ns < ASY_MAXPAIR)
            snprintf(stale[(*ns)++], ASY_PAIRKEY, "%s", base->k[j]);
}

static int asy_write_baseline(const char *baseline,
                              const struct asy_pairs *found)
{
    FILE *f = fopen(baseline, "w");
    if (!f)
        return die("z23-lint: cannot write %s\n", baseline);
    for (int i = 0; i < ASY_NCLAIMS; i++)
        fprintf(f, "%s\n", k_asy_claims[i]);
    fputs("# check_arm_symbol_single baseline — <path>\\t<function> pairs where a non-static\n"
          "# function is DEFINED more than once in one translation unit\n"
          "# (necessarily in disjoint preprocessor arms — see the header\n"
          "# comment in tools/lint/check_arm_symbol_single.sh for the defect class and its\n"
          "# limits). One pair per line, tab-separated. THE LIST MAY ONLY\n"
          "# SHRINK.\n"
          "#\n"
          "# Fix a row by either (a) hoisting the function ABOVE the\n"
          "# preprocessor split as ONE definition, with the strictest\n"
          "# semantics of the arms it replaces, when the two bodies exist\n"
          "# only because it was copy-pasted into a platform split it\n"
          "# never needed (the file_service.c ROM-parser fix is the\n"
          "# reference case), or (b) marking both bodies 'static' when a\n"
          "# real per-arm implementation is intentional and has no\n"
          "# external caller relying on a single symbol. Adding a row is\n"
          "# not a fix.\n", f);
    for (int i = 0; i < found->n; i++)
        fprintf(f, "%s\n", found->k[i]);
    fclose(f);
    printf("[%s] baseline UPDATED: %s\n", k_asy_gate, baseline);
    return 0;
}

static void asy_report_violations(int nv, const char *baseline,
                                  char violations[][ASY_PAIRKEY])
{
    printf("\n[%s] %d new non-static duplicate definition(s) (not in %s):\n",
           k_asy_gate, nv, baseline);
    static char shown[ASY_MAXPAIR][ASY_PAIRKEY];
    for (int i = 0; i < nv; i++)
        snprintf(shown[i], ASY_PAIRKEY, "%.*s", ASY_PAIRKEY - 1,
                 violations[i]);
    qsort(shown, (size_t)nv, ASY_PAIRKEY, asy_pair_cmp);
    for (int i = 0; i < nv; i++) {
        char *tab = strchr(shown[i], '\t');
        if (tab)
            *tab = '\0';
        printf("  %s  ->  %s\n", shown[i], tab ? tab + 1 : "");
    }
    printf("\n  Either hoist the function above the platform/feature split as ONE\n"
           "  definition (strictest semantics of the arms it replaces), or mark\n"
           "  both bodies 'static' if a real per-arm implementation is\n"
           "  intentional. Adding a row to %s is NOT a fix.\n", baseline);
}

static void asy_report_stale(int ns, const char *baseline,
                             char stale[][ASY_PAIRKEY])
{
    printf("\n[%s] %d STALE baseline row(s) — no longer duplicated. Delete them from %s:\n",
           k_asy_gate, ns, baseline);
    static char shown2[ASY_MAXPAIR][ASY_PAIRKEY];
    for (int i = 0; i < ns; i++)
        snprintf(shown2[i], ASY_PAIRKEY, "%.*s", ASY_PAIRKEY - 1, stale[i]);
    qsort(shown2, (size_t)ns, ASY_PAIRKEY, asy_pair_cmp);
    for (int i = 0; i < ns; i++) {
        char *tab = strchr(shown2[i], '\t');
        if (tab)
            *tab = '\0';
        printf("  %s  ->  %s\n", shown2[i], tab ? tab + 1 : "");
    }
}

int asy_run(void)
{
    struct asy_ctx c;
    asy_ctx_load(&c);

    static struct asy_files scan_files;
    int rc = asy_gather(&c, &scan_files);
    if (rc)
        return rc;

    static struct asy_pairs found;
    rc = asy_scan_all(&scan_files, &found);
    if (rc)
        return rc;

    rc = asy_baseline_check_claims(c.baseline);
    if (rc)
        return rc;
    static struct asy_base base;
    int base_count = 0;
    rc = asy_base_load(&base, c.baseline, &base_count);
    if (rc)
        return rc;

    static char violations[ASY_MAXPAIR][ASY_PAIRKEY];
    static char stale[ASY_MAXPAIR][ASY_PAIRKEY];
    int nv, ns;
    asy_diff_baseline(&found, &base, violations, &nv, stale, &ns);

    if (strcmp(c.mode, "UPDATE") == 0)
        return asy_write_baseline(c.baseline, &found);

    int fail = 0;
    if (nv > 0) {
        asy_report_violations(nv, c.baseline, violations);
        fail = 1;
    }
    if (ns > 0) {
        asy_report_stale(ns, c.baseline, stale);
        fail = 1;
    }
    if (fail && strcmp(c.mode, "FAIL") == 0)
        return 1;
    printf("[%s] PASS (%d files scanned, %d duplicate pair(s), all %d baselined)\n",
          k_asy_gate, scan_files.n, found.n, base_count);
    return 0;
}

int check_arm_symbol_single_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return asy_run();
}
