/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-controller-private-headers
 * Second file of the check-controller-private-headers family (the 700-line
 * family ceiling split): the native collect (git index / find mirror), the
 * per-file include scan, and the private-header presence count. The gate
 * body (baseline loader, verdict, preflight, entry) and the family's
 * parity notes live in gate_controller_private_headers.c; the --selftest
 * probes live in gate_controller_private_headers_workers.c.
 */

/* ── collect_files and scan_external_edges, natively ───────────────────────
 * Byte-parity replacements for the shell gate's file enumeration and its
 * per-file grep|sed include extraction — spawn-free (verifier ruling on
 * 0a5eb681d).
 *
 * - "." mode: `git ls-files -- '*.c' '*.h'` is the runtime's native
 *   git-index reader (lint_git_index_foreach) — index order, byte-sorted
 *   by path then ascending stage, which is exactly the order ls-files
 *   prints (it walks the same sorted index and only filters). The
 *   pathspec glob with a star that crosses '/' is exactly the ".c"/".h"
 *   suffix test (cphs_index_add). A reader failure is silent and reads as
 *   an EMPTY list — the shell's mapfile also saw an empty list from a
 *   failed git, and the caller's "no C/H inputs" UNPROVEN follows on both
 *   sides; git's own fatal stderr line is the one lost byte stream (an
 *   environment defect, never a gate verdict). Unmerged entries emit once
 *   per stage, as ls-files prints them.
 * - find mode: `find "$SCAN_ROOT" -type f \( -name '*.c' -o -name '*.h'
 *   \) | sort` is cphs_walk plus a byte-order qsort. The walk is
 *   readdir-order depth-first (fts with no comparison function, which is
 *   what GNU find uses), symlinks are never followed (find -P, lstat — a
 *   symlinked ROOT therefore yields nothing, matching find on a symlink
 *   operand), a trailing-slash root joins without a doubled slash, and an
 *   unreadable directory or vanished entry reproduces find's own
 *   "find: '<path>': <strerror>" diagnostic and continues (the pipeline's
 *   rc never reached mapfile, even under pipefail). The `| sort` ran
 *   under the harness locale in the shell; BYTE order is the deliberate,
 *   deterministic replacement — the gate must report the same order on
 *   every node — and the A/B fixtures run with LC_ALL=C, under which the
 *   shell's sort is byte-wise anyway. find's path quoting in its
 *   diagnostics is locale-sensitive outside LC_ALL=C (findutils i18n
 *   quotes); the C-locale form is reproduced, which is the fixture locale.
 * - display_path strips the literal "$SCAN_ROOT/" prefix only when it
 *   truly prefixes the collected path; a trailing-slash scan root never
 *   matches (find prints no doubled slash), so the prefix stays —
 *   exactly like ${file#"$SCAN_ROOT"/}.
 * - is_test_path: the six bash case patterns via fnmatch without
 *   FNM_PATHNAME ('*' crosses '/', as in bash case).
 * - The per-file `grep -nE <ere> "$file" || true` piped through the sed
 *   extraction `s@^[0-9]+:<the same ERE with the path captured>@\1@p` is
 *   ONE capture-group ERE per line (cphs_scan_lines): every grep-matched
 *   line also matches the sed pattern, so group 1 is the include — the
 *   same glibc regexec resolved both sides. An open failure reproduces
 *   grep's own "grep: <file>: <strerror>" diagnostic and is swallowed
 *   like the shell's `|| true`. A file containing NUL is binary to grep:
 *   a match prints "grep: <path>: binary file matches" on grep's STDERR
 *   (an empirical probe of the real binary, matching the supervisor-domain
 *   port's finding) — never a stdout row, so the sed filter and this scan
 *   yield no edge either way. Detection here is whole-file; grep's is
 *   per-32-KiB-buffer, which differs only for a file whose NUL and match
 *   sit in different buffers — no such file exists in the tree.
 * - The exclusion predicates keep the original's exact anchoring: the
 *   composing-private-header skip is a *_internal/_private suffix case on
 *   the includer's extensionless basename; the owning-family skip applies
 *   only under a ".../controllers/src/..." path and matches base == owner
 *   or owner_* (cphs_exempt). owner = include leaf minus %_internal.h
 *   then %_private.h; base = basename minus ${base%.*} (from the LAST
 *   dot).
 * - Edge format is the shell's printf '%s:#include "%s"\n' — always the
 *   quoted form, even when the source line used angle brackets.
 * - The private-header presence check: with HEADER_ROOT, the shell's
 *   `find "$HEADER_ROOT" -maxdepth 1 -type f \( -name '*_internal.h' -o
 *   -name '*_private.h' \) -print` counted by lines is a native one-level
 *   readdir count (only the count is ever used; an unreadable root
 *   reproduces find's diagnostic and counts 0). Without it, the grep -E
 *   '(^|/)controllers/include/controllers/...' over the RAW collected
 *   paths stays an in-memory regexec (the (^|/) anchor sees the
 *   still-unstripped scan-root prefix).
 * - A newline inside a file name: the shell's mapfile counted LINES, the
 *   port counts FILES (index/walk entries). No such name exists in the
 *   tree. The shell was unbounded; the fixed pools fail closed with
 *   die().
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"

enum { CPHS_MAXF = 8192, CPHS_FPOOL = 1 << 20, CPHS_MAXE = 8192,
       CPHS_EPOOL = 1 << 20, CPHS_LINE = 8192 };

static char g_cphs_fpool[CPHS_FPOOL];   /* the collected file set */
static size_t g_cphs_fused;
static const char *g_cphs_files[CPHS_MAXF];
static int g_cphs_nfiles;
static char g_cphs_epool[CPHS_EPOOL];   /* the realized edges */
static size_t g_cphs_eused;
static const char *g_cphs_edges[CPHS_MAXE];
static int g_cphs_nedges;
static regex_t g_cphs_inc;  /* the grep+sed include matcher, one capture */
static regex_t g_cphs_priv; /* the private-header path grep */

/* ── small buffer utilities ────────────────────────────────────────────── */

static int cphs_pool(char *pool, size_t cap, size_t *used, const char *s,
                     const char **out)
{
    size_t n = strlen(s) + 1;
    if (*used + n > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = pool + *used;
    memcpy(dst, s, n);
    *used += n;
    *out = dst;
    return 0;
}

static int cphs_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int cphs_file_add(const char *path)
{
    if (g_cphs_nfiles >= CPHS_MAXF)
        return die("z23-lint: scan-set overflow\n", "");
    return cphs_pool(g_cphs_fpool, sizeof g_cphs_fpool, &g_cphs_fused, path,
                     &g_cphs_files[g_cphs_nfiles++]);
}

/* ── collect_files ─────────────────────────────────────────────────────── */

/* The "."-mode collector: one index entry per *.c or *.h path, in index
 * order — exactly the order ls-files prints. */
static int cphs_index_add(const char *path, int stage, void *ctx)
{
    (void)stage;
    (void)ctx;
    size_t n = strlen(path);
    if (n >= 2 && path[n - 2] == '.'
        && (path[n - 1] == 'c' || path[n - 1] == 'h'))
        return cphs_file_add(path);
    return 0;
}

/* find's own diagnostic, byte-for-byte (the C-locale quoting); the walk
 * continues, exactly like the shell's unmasked find inside the pipeline
 * (whose rc never reached mapfile, even under pipefail). */
static void cphs_walk_diag(const char *path, int errnum)
{
    fprintf(stderr, "find: '%s': %s\n", path, strerror(errnum));
}

static int cphs_walk(const char *root);

static int cphs_walk_entry(const char *root, const char *nm)
{
    size_t rl = strlen(root);
    char path[4096];
    int k = snprintf(path, sizeof path, "%s%s%s", root,
                     rl > 0 && root[rl - 1] == '/' ? "" : "/", nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", root);
    struct stat st;
    if (lstat(path, &st) != 0) {
        cphs_walk_diag(path, errno);
        return 0;
    }
    if (S_ISDIR(st.st_mode))
        return cphs_walk(path);
    size_t nl = strlen(nm);
    if (S_ISREG(st.st_mode) && nl >= 2 && nm[nl - 2] == '.'
        && (nm[nl - 1] == 'c' || nm[nl - 1] == 'h'))
        return cphs_file_add(path);
    return 0;
}

/* find <root> -type f \( -name '*.c' -o -name '*.h' \): readdir order,
 * depth-first; a directory that cannot be opened is find's diagnostic and
 * the walk continues with the next entry. */
static int cphs_walk(const char *root)
{
    DIR *d = opendir(root);
    if (!d) {
        cphs_walk_diag(root, errno);
        return 0;
    }
    int rc = 0;
    errno = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            rc = cphs_walk_entry(root, de->d_name);
        errno = 0;
    }
    if (errno != 0)
        cphs_walk_diag(root, errno);
    closedir(d);
    return rc;
}

int cphs_collect(const char *root)
{
    g_cphs_nfiles = 0;
    g_cphs_fused = 0;
    if (strcmp(root, ".") == 0) {
        (void)lint_git_index_foreach(cphs_index_add, NULL);
        return 0;
    }
    struct stat st;
    if (lstat(root, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    int rc = cphs_walk(root);
    if (rc == 0)
        qsort(g_cphs_files, (size_t)g_cphs_nfiles, sizeof g_cphs_files[0],
              cphs_ptr_cmp);
    return rc;
}

int cphs_nfiles(void)
{
    return g_cphs_nfiles;
}

/* display_path: see the file header for the trailing-slash case. */
static const char *cphs_display(const char *file, const char *root)
{
    if (strcmp(root, ".") == 0)
        return file;
    size_t rl = strlen(root);
    if (strncmp(file, root, rl) == 0 && file[rl] == '/')
        return file + rl + 1;
    return file;
}

/* is_test_path: the six bash case patterns; fnmatch without FNM_PATHNAME
 * lets '*' cross '/', like bash's case. */
static int cphs_is_test(const char *path)
{
    static const char *const pats[] = {
        "tests/*", "lib/test/*", "*/test/*", "*/tests/*",
        "*/test_*.c", "*/test_*.h",
    };
    for (size_t i = 0; i < sizeof pats / sizeof pats[0]; i++)
        if (fnmatch(pats[i], path, 0) == 0)
            return 1;
    return 0;
}

/* ── scan_external_edges ───────────────────────────────────────────────── */

/* owner = include leaf minus %_internal.h, then minus %_private.h. */
static int cphs_owner(const char *include, char *out, size_t cap)
{
    const char *leaf = strrchr(include, '/');
    leaf = leaf ? leaf + 1 : include;
    if (ovf(snprintf(out, cap, "%s", leaf), cap))
        return 2;
    size_t n = strlen(out);
    if (n >= 11 && strcmp(out + n - 11, "_internal.h") == 0)
        out[n -= 11] = '\0';
    if (n >= 10 && strcmp(out + n - 10, "_private.h") == 0)
        out[n - 10] = '\0';
    return 0;
}

/* base = display-path basename minus ${base%.*} (from the LAST dot). */
static int cphs_base(const char *path, char *out, size_t cap)
{
    const char *leaf = strrchr(path, '/');
    leaf = leaf ? leaf + 1 : path;
    if (ovf(snprintf(out, cap, "%s", leaf), cap))
        return 2;
    char *dot = strrchr(out, '.');
    if (dot)
        *dot = '\0';
    return 0;
}

/* The two exclusion predicates, anchoring preserved: a composing private
 * header (base ends _internal/_private), then — only under a path matching
 * the controllers/src/ shape — the owning family (base == owner or
 * owner_*). */
static int cphs_exempt(const char *path, const char *base, const char *owner)
{
    if (fnmatch("*_internal", base, 0) == 0
        || fnmatch("*_private", base, 0) == 0)
        return 1;
    if (fnmatch("*/controllers/src/*", path, 0) != 0)
        return 0;
    size_t bl = strlen(base), ol = strlen(owner);
    if (bl == ol && memcmp(base, owner, ol) == 0)
        return 1;
    return bl > ol && memcmp(base, owner, ol) == 0 && base[ol] == '_';
}

static int cphs_edge_add(const char *path, const char *include)
{
    if (g_cphs_nedges >= CPHS_MAXE)
        return die("z23-lint: scan-set overflow\n", "");
    char buf[CPHS_LINE];
    if (ovf(snprintf(buf, sizeof buf, "%s:#include \"%s\"", path, include),
            sizeof buf))
        return 2;
    return cphs_pool(g_cphs_epool, sizeof g_cphs_epool, &g_cphs_eused, buf,
                     &g_cphs_edges[g_cphs_nedges++]);
}

/* Pass 1: is this file binary to grep? A NUL anywhere flags it (grep's
 * per-buffer rule, exact for files under one 32 KiB buffer). Leaves the
 * stream rewound for pass 2. */
static int cphs_has_nul(FILE *f, int *out)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&line, &cap, f)) >= 0)
        found = memchr(line, '\0', (size_t)n) != NULL;
    free(line);
    rewind(f);
    *out = found;
    return 0;
}

/* Pass 2 for a binary file: grep matches the ERE against the raw buffer,
 * NULs included; testing each NUL-separated segment is exact because the
 * ERE itself contains no NUL. A match prints grep's stderr note — never a
 * stdout row, so the sed filter and this scan yield no edge either way. */
static int cphs_binary_note(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int matched = 0;
    while (!matched && (n = getline(&line, &cap, f)) >= 0) {
        const char *end = line + n;
        for (const char *seg = line; !matched && seg < end;
             seg += strlen(seg) + 1)
            matched = regexec(&g_cphs_inc, seg, 0, NULL, 0) == 0;
    }
    free(line);
    if (matched)
        fprintf(stderr, "grep: %s: binary file matches\n", path);
    return 0;
}

static int cphs_scan_lines(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int rc = 0;
    while (rc == 0 && (len = getline(&line, &cap, f)) >= 0) {
        regmatch_t m[2];
        if (regexec(&g_cphs_inc, line, 2, m, 0) != 0)
            continue;
        size_t il = (size_t)(m[1].rm_eo - m[1].rm_so);
        if (il >= 4096) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        char inc[4096], owner[4096], base[4096];
        memcpy(inc, line + m[1].rm_so, il);
        inc[il] = '\0';
        rc = cphs_owner(inc, owner, sizeof owner);
        if (rc == 0)
            rc = cphs_base(path, base, sizeof base);
        if (rc == 0 && !cphs_exempt(path, base, owner))
            rc = cphs_edge_add(path, inc);
    }
    return fin(f, line, path, rc);
}

static int cphs_scan_file(const char *file, const char *root)
{
    if (!*file)
        return 0;
    const char *path = cphs_display(file, root);
    if (cphs_is_test(path))
        return 0;
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "grep: %s: %s\n", file, strerror(errno));
        return 0;
    }
    int binary = 0;
    int rc = cphs_has_nul(f, &binary);
    if (rc == 0 && binary) {
        rc = cphs_binary_note(file, f);
        (void)fclose(f);
        return rc;
    }
    if (rc == 0)
        rc = cphs_scan_lines(path, f);
    return rc;
}

int cphs_scan_all(const char *root)
{
    g_cphs_nedges = 0;
    g_cphs_eused = 0;
    int rc = 0;
    for (int i = 0; rc == 0 && i < g_cphs_nfiles; i++)
        rc = cphs_scan_file(g_cphs_files[i], root);
    return rc;
}

/* Byte-order sort -u: the deliberate deterministic replacement for the
 * shell's locale-dependent sort -u (identical under LC_ALL=C). */
void cphs_sort_uniq(void)
{
    qsort(g_cphs_edges, (size_t)g_cphs_nedges, sizeof g_cphs_edges[0],
          cphs_ptr_cmp);
    int w = 0;
    for (int i = 0; i < g_cphs_nedges; i++) {
        if (w > 0 && strcmp(g_cphs_edges[w - 1], g_cphs_edges[i]) == 0)
            continue;
        g_cphs_edges[w++] = g_cphs_edges[i];
    }
    g_cphs_nedges = w;
}

const char *const *cphs_edges(int *out_n)
{
    *out_n = g_cphs_nedges;
    return g_cphs_edges;
}

/* ── the private-header presence check ─────────────────────────────────── */

/* find "$HEADER_ROOT" -maxdepth 1 -type f \( -name '*_internal.h' -o
 * -name '*_private.h' \) -print, counted by lines: a one-level readdir
 * count (only the count is used); an unreadable root reproduces find's
 * diagnostic and counts 0. */
static int cphs_priv_via_dir(const char *hroot, int *out)
{
    DIR *d = opendir(hroot);
    if (!d) {
        cphs_walk_diag(hroot, errno);
        *out = 0;
        return 0;
    }
    int n = 0;
    errno = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char path[4096];
        int k = snprintf(path, sizeof path, "%s/%s", hroot, de->d_name);
        if (k < 0 || (size_t)k >= sizeof path) {
            closedir(d);
            return die("z23-lint: path too long: %s\n", hroot);
        }
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISREG(st.st_mode))
            n += fnmatch("*_internal.h", de->d_name, 0) == 0
                 || fnmatch("*_private.h", de->d_name, 0) == 0;
        errno = 0;
    }
    if (errno != 0)
        cphs_walk_diag(hroot, errno);
    closedir(d);
    *out = n;
    return 0;
}

int cphs_count_private(const char *hroot, int *out)
{
    if (hroot[0])
        return cphs_priv_via_dir(hroot, out);
    int n = 0;
    for (int i = 0; i < g_cphs_nfiles; i++)
        n += regexec(&g_cphs_priv, g_cphs_files[i], 0, NULL, 0) == 0;
    *out = n;
    return 0;
}

/* ── pattern lifecycle ─────────────────────────────────────────────────── */

int cphs_comp(void)
{
    int cr = compile_pat(&g_cphs_inc, REG_EXTENDED,
                         "^[[:space:]]*#include[[:space:]]+[\"<](",
                         "controllers/[^\">]+_(internal|private)\\.h",
                         ")[\">]", "");
    if (cr)
        return cr;
    cr = compile_pat(&g_cphs_priv, REG_EXTENDED,
                     "(^|/)controllers/include/controllers/",
                     "[^/]+_(internal|private)\\.h$", "", "");
    if (cr)
        regfree(&g_cphs_inc);
    return cr;
}

void cphs_drop(void)
{
    regfree(&g_cphs_inc);
    regfree(&g_cphs_priv);
}
