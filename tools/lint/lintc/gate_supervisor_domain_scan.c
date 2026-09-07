/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-supervisor-domain
 * Third file of the check-supervisor-domain family (the 700-line family
 * ceiling split): the native main scan. gate_supervisor_domain.c holds
 * the find mirror, the git-oracle coverage check, and the gate entry;
 * gate_supervisor_domain_workers.c holds the boot-worker lock-in and the
 * gate's --selftest probes.
 */

/* ── the main scan, natively ─────────────────────────────────────────────
 * Byte-parity replacement for the shell gate's recursive ERE scan of the
 * roots — grep -rnE '(^|[^A-Za-z0-9_])supervisor_register<sp>*(' over the
 * scan roots with --include='*.c' plus the LINT_GREP_EXCLUDE_ARGS — the
 * one place the first cut of this port still borrowed the host grep.
 * — the one place the first cut of this port still borrowed the host grep.
 * The verifier's two objections are answered here: the GNU-only whitespace
 * escape is gone (the ERE below spells it [[:space:]], an identical match
 * set because every byte under the scan roots is ASCII), and no host grep
 * is involved at all (BSD grep on macOS differs).
 *
 * The GNU grep 3.11 behaviors this file reproduces, each pinned by an
 * empirical probe of the real binary:
 * - Traversal: fts with no comparison function, i.e. readdir order,
 *   depth-first, descending where the entries appear (verified identical
 *   to `find` order). Root operands are processed in argv order; a
 *   duplicated or overlapping root is scanned again.
 * - Root operands: stat (not lstat), so a symlinked root IS followed
 *   (FTS_COMFOLLOW) and reported under the operand's own name; symlinked
 *   entries found during traversal are skipped silently (FTS_PHYSICAL).
 * - The --include='*.c' and --exclude/--exclude-dir globs are basename
 *   fnmatch, and grep applies them even to explicit root operands (a root
 *   dir named "build" is pruned, a root file named "_xfixture.c" skipped).
 *   Trailing slashes are stripped before the basename check, as fts does.
 * - Output rows are "path:N:content" with the content bytes verbatim; an
 *   unterminated final line still terminates with a newline on output.
 * - A file containing NUL is binary to grep: a match prints
 *   "grep: <path>: binary file matches" on STDERR (never a stdout row)
 *   and does NOT set the exit-2 error. Detection here is whole-file;
 *   grep's is per-32-KiB-buffer, which differs only for a file whose NUL
 *   and match sit in different buffers — no such file exists in the tree
 *   (verified: no NUL-containing or invalid-UTF-8 *.c under the roots).
 * - Any open/read failure prints "grep: <path>: <strerror>" on stderr,
 *   the walk continues with the next entry, and the scan's exit becomes
 *   2 — the shell's FATAL block, whose branch exits before HITS is
 *   computed, so partial output is discarded exactly like the captured
 *   RAW was.
 * - The four `grep -v` filters are BRE regexec per kept row
 *   (sds_filter_hits); 'platform/modules/util/src/supervisor.c' keeps
 *   REGEX semantics (its dots match any character) rather than being
 *   repaired into a fixed string.
 *
 * Residual parity corners (none exercised by the tree or the A/B
 * fixtures): grep's binary verdict is locale-sensitive for non-UTF-8
 * bytes (this scan is byte-exact, i.e. the LC_ALL=C reading); a
 * > 32 KiB file with its NUL in a later buffer than its first match
 * reads as all-binary here where grep prints the early text rows; and
 * an lstat failure mid-traversal is treated as a scan error where
 * FTS_NOSTAT may never have stat(2)ed the entry. All three fail closed.
 * The shell was unbounded; the fixed 1 MiB RAW/HITS pools die() on
 * overflow (~8000 violations) — environment exhaustion, not a verdict.
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

static const char k_sds_name[] = "check_supervisor_domain";

enum { SDS_RAW = 1 << 20 };
static char g_sds_raw[SDS_RAW];   /* grep's captured stdout rows */
static size_t g_sds_raw_used;
static char g_sds_hits[SDS_RAW];  /* the filtered HITS */
static size_t g_sds_hits_used;
static int g_sds_nhits;
static int g_sds_err;             /* any scan error -> the exit-2 FATAL */
static regex_t g_sds_match;       /* the domain-registration ERE */
static int g_sds_prod;            /* ZCL_LINT_PRODUCTION_SCAN exclusions */

/* grep's own open/read diagnostic, byte-for-byte; also marks the scan
 * failed, which the caller turns into the FATAL exit 2 exactly like the
 * shell's grc >= 2 branch. */
static void sd_scan_diag(const char *path, int errnum)
{
    fprintf(stderr, "grep: %s: %s\n", path, strerror(errnum));
    g_sds_err = 1;
}

/* Basename for the exclusion globs, trailing slashes stripped (fts strips
 * them off root operands, so "core/" excludes and matches as "core"). */
static const char *sd_basename(const char *path)
{
    size_t n = strlen(path);
    while (n > 0 && path[n - 1] == '/')
        n--;
    const char *base = path;
    for (size_t i = 0; i < n; i++)
        if (path[i] == '/')
            base = path + i + 1;
    return base;
}

/* scan_exclusions.sh as grep's --exclude-dir globs: basenames, literals. */
static int sd_excluded_dir(const char *base)
{
    static const char *const dirs[] = {
        "planted", "build", "vendor", ".claude", "test-tmp",
    };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (strcmp(base, dirs[i]) == 0)
            return 1;
    return 0;
}

/* scan_exclusions.sh as grep's --exclude globs: basename fnmatch. */
static int sd_excluded_file(const char *base)
{
    return fnmatch("_*fixture*.c", base, 0) == 0
        || fnmatch("_*fixture*.h", base, 0) == 0;
}

/* One grep -n output row: "path:N:content\n", content bytes verbatim. */
static int sd_emit(const char *path, long lno, const char *line, size_t len)
{
    size_t left = sizeof g_sds_raw - g_sds_raw_used;
    int k = snprintf(g_sds_raw + g_sds_raw_used, left, "%s:%ld:", path, lno);
    if (k < 0 || (size_t)k >= left)
        return die("z23-lint: derived buffer overflow\n", "");
    g_sds_raw_used += (size_t)k;
    if (len + 2 > sizeof g_sds_raw - g_sds_raw_used)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(g_sds_raw + g_sds_raw_used, line, len);
    g_sds_raw_used += len;
    g_sds_raw[g_sds_raw_used++] = '\n';
    g_sds_raw[g_sds_raw_used] = '\0';
    return 0;
}

/* Pass 1: is this file binary to grep? A NUL anywhere flags it (grep's
 * per-buffer rule, exact for files under one 32 KiB buffer). Leaves the
 * stream rewound for pass 2. */
static int sd_has_nul(FILE *f, int *out)
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
 * ERE itself contains no NUL. A match prints grep's stderr note — never
 * a stdout row — and does not set the exit-2 error. */
static int sd_binary_note(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int matched = 0;
    while (!matched && (n = getline(&line, &cap, f)) >= 0) {
        const char *end = line + n;
        for (const char *seg = line; !matched && seg < end;
             seg += strlen(seg) + 1)
            matched = regexec(&g_sds_match, seg, 0, NULL, 0) == 0;
    }
    free(line);
    if (matched)
        fprintf(stderr, "grep: %s: binary file matches\n", path);
    return 0;
}

/* Pass 2 for a text file: one "path:N:content" row per matching line,
 * the ERE evaluated on the line without its newline. */
static int sd_text_lines(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    long lno = 0;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (regexec(&g_sds_match, line, 0, NULL, 0) == 0)
            rc = sd_emit(path, lno, line, (size_t)n);
    }
    free(line);
    return rc;
}

/* One file as grep sees it: an open failure is grep's diagnostic plus the
 * exit-2 FATAL (the walk continues); a read failure likewise. */
static int sd_scan_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        sd_scan_diag(path, errno);
        return 0;
    }
    int binary = 0;
    int rc = sd_has_nul(f, &binary);
    if (rc == 0)
        rc = binary ? sd_binary_note(path, f) : sd_text_lines(path, f);
    if (ferror(f))
        sd_scan_diag(path, errno);
    fclose(f);
    return rc;
}

static int sd_scan_dir(const char *dir);

static int sd_scan_child(const char *dir, const char *nm)
{
    size_t dl = strlen(dir);
    char path[4096];
    int k = snprintf(path, sizeof path, "%s%s%s", dir,
                     dl > 0 && dir[dl - 1] == '/' ? "" : "/", nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", dir);
    struct stat st;
    if (lstat(path, &st) != 0) {
        sd_scan_diag(path, errno);
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        if (g_sds_prod && sd_excluded_dir(nm))
            return 0;
        return sd_scan_dir(path);
    }
    if (!S_ISREG(st.st_mode) || fnmatch("*.c", nm, 0) != 0)
        return 0;
    if (g_sds_prod && sd_excluded_file(nm))
        return 0;
    return sd_scan_file(path);
}

/* grep -r traversal: readdir order, depth-first; a directory that cannot
 * be opened is grep's diagnostic plus the exit-2 FATAL, and the walk
 * continues with the next entry. */
static int sd_scan_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        sd_scan_diag(dir, errno);
        return 0;
    }
    int rc = 0;
    errno = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            rc = sd_scan_child(dir, de->d_name);
        errno = 0;
    }
    if (errno != 0)
        sd_scan_diag(dir, errno);
    closedir(d);
    return rc;
}

/* A root operand: stat (not lstat) so a symlinked root is followed
 * (FTS_COMFOLLOW), then the same include/exclude globbing as any other
 * entry — grep applies both even to explicit operands. A root that is
 * neither directory nor regular file is skipped silently. */
static int sd_scan_root(const char *root)
{
    struct stat st;
    if (stat(root, &st) != 0) {
        sd_scan_diag(root, errno);
        return 0;
    }
    const char *base = sd_basename(root);
    if (S_ISDIR(st.st_mode)) {
        if (g_sds_prod && sd_excluded_dir(base))
            return 0;
        return sd_scan_dir(root);
    }
    if (!S_ISREG(st.st_mode) || fnmatch("*.c", base, 0) != 0)
        return 0;
    if (g_sds_prod && sd_excluded_file(base))
        return 0;
    return sd_scan_file(root);
}

/* The four grep -v filters, as BRE (regcomp flags 0): the dots in
 * 'platform/modules/util/src/supervisor.c' match any character, exactly
 * like the shell. */
static int sds_drop_comp(regex_t *re)
{
    static const char *const pats[] = {
        "supervisor_register_in_domain",
        "platform/modules/util/src/supervisor.c",
        "tests/harness/include/test/",
        "// supervisor-root-ok:",
    };
    for (int i = 0; i < 4; i++) {
        int err = regcomp(&re[i], pats[i], 0);
        if (err) {
            int rc = reg_fail(&re[i], err);
            while (i > 0)
                regfree(&re[--i]);
            return rc;
        }
    }
    return 0;
}

static int sds_filter_hits(const regex_t *re)
{
    g_sds_hits_used = 0;
    g_sds_nhits = 0;
    for (const char *p = g_sds_raw; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        int drop = 0;
        for (int i = 0; i < 4 && !drop; i++)
            drop = regexec(&re[i], line, 0, NULL, 0) == 0;
        if (!drop) {
            if (g_sds_hits_used + n + 1 >= sizeof g_sds_hits)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(g_sds_hits + g_sds_hits_used, p, n);
            g_sds_hits_used += n;
            g_sds_hits[g_sds_hits_used++] = '\n';
            g_sds_nhits++;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

/* The FATAL block (any scan error) or the filtered violation report. */
static int sds_report(const char *mode)
{
    if (g_sds_err) {
        fprintf(stderr, "%s: FATAL — scan grep failed (exit 2); refusing\n"
                "  to report PASS off a broken scan.\n", k_sds_name);
        return 2;
    }
    regex_t drop[4];
    int rc = sds_drop_comp(drop);
    if (rc == 0)
        rc = sds_filter_hits(drop);
    for (int i = 0; i < 4; i++)
        regfree(&drop[i]);
    if (rc)
        return rc;
    if (g_sds_nhits > 0) {
        if (fwrite(g_sds_hits, 1, g_sds_hits_used, stdout) != g_sds_hits_used)
            return die("z23-lint: write failed\n", "");
        if (printf("[%s] %d violation(s) (mode: %s)\n", k_sds_name,
                   g_sds_nhits, mode) < 0)
            return die("z23-lint: write failed\n", "");
        if (strcmp(mode, "FAIL") == 0)
            return 1;
    }
    return 0;
}

/* The shell gate's RAW=$(grep ...); grc=$? — natively. */
int supervisor_domain_scan_run(const char *mode, const char *const *roots,
                               int nroots)
{
    g_sds_raw_used = 0;
    g_sds_raw[0] = '\0';
    g_sds_err = 0;
    g_sds_prod = lint_prod_scan();
    int err = regcomp(&g_sds_match,
                      "(^|[^A-Za-z0-9_])supervisor_register[[:space:]]*\\(",
                      REG_EXTENDED);
    int rc = err ? reg_fail(&g_sds_match, err) : 0;
    for (int i = 0; rc == 0 && i < nroots; i++)
        rc = sd_scan_root(roots[i]);
    regfree(&g_sds_match);
    if (rc)
        return rc;
    return sds_report(mode);
}
