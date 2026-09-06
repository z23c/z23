/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-file-purpose
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
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* ── check-file-purpose (Gate P1, port of check_file_purpose.sh) ───────────
 * Every indexed .c/.h under the codeindex roots (the five source authorities
 * plus tools/, exactly the shell gate's ZCL_SOURCE_AUTHORITIES + tools loop)
 * yields a non-empty DERIVABLE one-line purpose: a block or line comment
 * precedes the first code token, and within it some line is substantive
 * (not blank `*` fill, not a Copyright/license line) or is an explicit
 * `purpose:` override. This is the shell mirror of ci_file_purpose()
 * (cognition/modules/codeindex/src/codeindex_scan.c) reproduced state for
 * state; the extractor's stem-prefix-stripping cosmetics are irrelevant.
 *
 * Baseline mapping: the shell gate loaded file_purpose_baseline.txt with
 * gate_load_list_file() — a presence SET (a missing file is an empty set,
 * `#` starts a comment anywhere, whitespace is trimmed, duplicates collapse,
 * an entry no scan observed is unused, never stale). That is
 * lint_base_load_set() semantics, so this gate uses the set mode (as
 * check-framework-shape and check-no-orphan-placement do) and never calls
 * lint_base_finish on it.
 *
 * Modes (ZCL_LINT_MODE, default WARN): WARN reports and exits 0; RATCHET
 * fails only on violations not in the set; FAIL fails on any violation and
 * ignores the set. ZCL_FILE_PURPOSE_ROOT overrides the scan root (test
 * isolation only) and relaxes the hollow-scan floor from 1500 to 1.
 *
 * Parity notes:
 * - The shell exported LC_ALL=C, so `sort -u` was bytewise; the file list
 *   here is qsort/strcmp, never strcoll, and the case-folding in
 *   fp_ci_prefix is ASCII-only, matching awk tolower() under LC_ALL=C.
 * - find's -path patterns are fnmatch(,0) — `*` crosses `/`; reproduced
 *   with fnmatch(3) flags 0 against the same "$SCAN_ROOT/<auth>/..." path
 *   strings find saw.
 * - A file that cannot be opened mid-scan read as not-derivable under the
 *   shell too (awk exited nonzero, which `if file_is_derivable` treated as
 *   a violation); the shell also leaked awk's own error line to stderr in
 *   that pathological case, which this port does not reproduce.
 * - The shell's third gate_require_scanned (scanned == file count) is kept;
 *   in the port the loop runs over the collected vector so it can only fail
 *   if the walk logic itself is broken. */

static const char *const k_fp_auth[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
enum { FP_NAUTH = (int)(sizeof k_fp_auth / sizeof k_fp_auth[0]) };

static const char *const k_fp_excl[] = {
    "*/build/*",
    "*/modules/*/tests/*",
    "*/modules/*/examples/*",
    "*/modules/*/app/*",
    "*/contexts/commons/packages/*",
};

static const char k_fp_base[] = "tools/lint/file_purpose_baseline.txt";
static struct lint_base g_fp_allowed;

struct fp_files { char **v; size_t n, cap; };

struct fp_acc {
    FILE *err;
    const char *root;
    const char *mode;
    int fail_mode;
    int scanned, viol, allow;
};

/* ── file enumeration (find <dirs> -type f \( -name '*.c' -o -name '*.h' \)
 *    with the five -not -path filters, then LC_ALL=C sort -u) ──────────── */

static int fp_push(struct fp_files *fs, const char *path)
{
    if (fs->n == fs->cap) {
        size_t nc = fs->cap ? fs->cap * 2 : 256;
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

static void fp_free(struct fp_files *fs)
{
    for (size_t i = 0; i < fs->n; i++)
        free(fs->v[i]);
    free(fs->v);
}

static int fp_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* LC_ALL=C sort -u: bytewise order, exact-duplicate collapse. */
static void fp_sort_uniq(struct fp_files *fs)
{
    qsort(fs->v, fs->n, sizeof fs->v[0], fp_cmp);
    size_t w = 0;
    for (size_t i = 0; i < fs->n; i++) {
        if (w > 0 && strcmp(fs->v[w - 1], fs->v[i]) == 0) {
            free(fs->v[i]);
            continue;
        }
        fs->v[w++] = fs->v[i];
    }
    fs->n = w;
}

static int fp_suffix(const char *name)
{
    size_t n = strlen(name);
    return n >= 2 && name[n - 2] == '.'
        && (name[n - 1] == 'c' || name[n - 1] == 'h');
}

static int fp_excluded(const char *full)
{
    for (size_t i = 0; i < sizeof k_fp_excl / sizeof k_fp_excl[0]; i++)
        if (fnmatch(k_fp_excl[i], full, 0) == 0)
            return 1;
    return 0;
}

static int fp_walk_one(const char *dir, const char *rel, const char *name,
                       struct fp_files *fs)
{
    char full[4096], sub[4096];
    struct stat st;
    if (ovf(snprintf(full, sizeof full, "%s/%s", dir, name), sizeof full)
        || ovf(snprintf(sub, sizeof sub, "%s/%s", rel, name), sizeof sub))
        return 2;
    if (lstat(full, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode))
        return 1; /* sentinel: caller recurses (keeps this function flat) */
    if (S_ISREG(st.st_mode) && fp_suffix(name) && !fp_excluded(full))
        return fp_push(fs, sub);
    return 0;
}

/* find's default (-P): symlinks are never followed; unreadable dirs vanish
 * silently exactly as under the shell gate's `find ... 2>/dev/null`. */
static int fp_walk(const char *dir, const char *rel, struct fp_files *fs)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *name = names[i]->d_name;
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char full[4096], sub[4096];
            int one = fp_walk_one(dir, rel, name, fs);
            if (one == 1
                && (ovf(snprintf(full, sizeof full, "%s/%s", dir, name),
                        sizeof full)
                    || ovf(snprintf(sub, sizeof sub, "%s/%s", rel, name),
                           sizeof sub)))
                one = 2;
            if (one == 1)
                one = fp_walk(full, sub, fs);
            rc = one;
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* ── derivability (the awk mirror of ci_file_purpose, state for state) ──── */

struct fp_st { int started, block, incomment, verdict, done; };

/* awk: line=$0; sub(/^[ \t]+/,"",line); sub(/\r$/,"",line) — $0 carries no
 * newline, so drop getline's trailing '\n' first. */
static void fp_prep(char *line)
{
    size_t n = strlen(line);
    if (n && line[n - 1] == '\n')
        line[--n] = '\0';
    size_t i = 0;
    while (line[i] == ' ' || line[i] == '\t')
        i++;
    if (i)
        memmove(line, line + i, n - i + 1);
    n = strlen(line);
    if (n && line[n - 1] == '\r')
        line[n - 1] = '\0';
}

static int fp_fill(char c)
{
    return c == ' ' || c == '\t' || c == '*';
}

/* ASCII-only case-folded prefix test: awk tolower(substr(t,1,k))=="word"
 * under LC_ALL=C. A t shorter than the word never matches. */
static int fp_ci_prefix(const char *t, size_t tlen, const char *word)
{
    size_t wl = strlen(word);
    if (tlen < wl)
        return 0;
    for (size_t i = 0; i < wl; i++) {
        char c = t[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + 32);
        if (c != word[i])
            return 0;
    }
    return 1;
}

/* awk consider(): gsub(/\r/,""); strip leading/trailing [ \t*] fill; blank
 * is not substantive; `purpose:` (any case) is an explicit override; a
 * `copyright` line (any case) is skipped; anything else is substantive. */
static int fp_consider(char *b)
{
    size_t w = 0;
    for (size_t i = 0; b[i]; i++)
        if (b[i] != '\r')
            b[w++] = b[i];
    b[w] = '\0';
    size_t i = 0;
    while (fp_fill(b[i]))
        i++;
    size_t n = strlen(b);
    while (n > i && fp_fill(b[n - 1]))
        n--;
    if (n == i)
        return 0;
    if (fp_ci_prefix(b + i, n - i, "purpose:"))
        return 1;
    if (fp_ci_prefix(b + i, n - i, "copyright"))
        return 0;
    return 1;
}

/* First non-blank line: a block or line opener starts the comment run;
 * anything else is a code token before any comment (violation). */
static void fp_first(struct fp_st *s, char *line)
{
    if (!line[0])
        return;
    if (line[0] == '/' && line[1] == '*') {
        s->started = 1;
        s->block = 1;
        s->incomment = 1;
        char *close = strstr(line + 2, "*/");
        if (close) {
            *close = '\0';
            s->incomment = 0;
        }
        if (fp_consider(line + 2)) {
            s->verdict = 1;
            s->done = 1;
        }
        return;
    }
    if (line[0] == '/' && line[1] == '/') {
        s->started = 1;
        s->block = 0;
        if (fp_consider(line + 2)) {
            s->verdict = 1;
            s->done = 1;
        }
        return;
    }
    s->done = 1;
}

static void fp_block_line(struct fp_st *s, char *line)
{
    if (!s->incomment) {
        s->done = 1; /* block closed with nothing substantive found */
        return;
    }
    char *close = strstr(line, "*/");
    if (close)
        *close = '\0';
    if (fp_consider(line)) {
        s->verdict = 1;
        s->done = 1;
        return;
    }
    if (close)
        s->incomment = 0;
}

static void fp_slash_line(struct fp_st *s, char *line)
{
    if (line[0] == '/' && line[1] == '/') {
        if (fp_consider(line + 2)) {
            s->verdict = 1;
            s->done = 1;
        }
        return;
    }
    s->done = 1; /* end of the // run */
}

/* 1 derivable (PASS), 0 not derivable (violation). Reaching EOF, a code
 * token first, or a comment run that closes with nothing substantive all
 * leave verdict 0 — the awk END block's `exit 1`. An unreadable file is
 * not derivable (awk exited nonzero there too; see the parity notes). */
static int fp_derivable(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    struct fp_st s = { 0, 0, 0, 0, 0 };
    char *line = NULL;
    size_t cap = 0;
    while (!s.done && getline(&line, &cap, f) >= 0) {
        fp_prep(line);
        if (!s.started)
            fp_first(&s, line);
        else if (s.block)
            fp_block_line(&s, line);
        else
            fp_slash_line(&s, line);
    }
    free(line);
    (void)fclose(f);
    return s.verdict;
}

/* ── scan loop, summary, exit code ─────────────────────────────────────── */

static int fp_judge(const char *full, const char *key, struct fp_acc *a)
{
    a->scanned++;
    if (fp_derivable(full))
        return 0;
    if (!a->fail_mode && lint_base_observe(&g_fp_allowed, key, 1) >= 0) {
        a->allow++;
        return 0;
    }
    a->viol++;
    return fprintf(a->err, "%s: no derivable file purpose — add a top-of-file"
                   " comment line (or a '/* purpose: ... */' override)\n",
                   key) < 0
               ? die("z23-lint: write failed\n", "")
               : 0;
}

static int fp_finish(const struct fp_acc *a, FILE *out)
{
    if (fprintf(out, "[check_file_purpose] scanned %d source file(s) under "
                "%s\n", a->scanned, a->root) < 0
        || fprintf(out, "[check_file_purpose] %d violation(s) found (mode: "
                   "%s)\n", a->viol, a->mode) < 0)
        return die("z23-lint: write failed\n", "");
    if (a->allow > 0
        && fprintf(out, "[check_file_purpose] %d allowlisted violation(s) "
                   "ignored\n", a->allow) < 0)
        return die("z23-lint: write failed\n", "");
    if (a->viol > 0
        && fprintf(out, "[check_file_purpose] add the one-line purpose, or "
                   "(shrink-only) write to "
                   "tools/lint/file_purpose_baseline.txt\n") < 0)
        return die("z23-lint: write failed\n", "");
    return (a->viol > 0
            && (a->fail_mode || strcmp(a->mode, "RATCHET") == 0)) ? 1 : 0;
}

/* for authority in "${ZCL_SOURCE_AUTHORITIES[@]}" tools; keep only dirs
 * that exist ([[ -d ]] follows symlinks, so stat, not lstat). */
static int fp_collect_dirs(const char *root, char dirs[][4096],
                           const char **rels, int *n)
{
    *n = 0;
    for (int i = 0; i < FP_NAUTH; i++) {
        struct stat st;
        if (ovf(snprintf(dirs[*n], 4096, "%s/%s", root, k_fp_auth[i]), 4096))
            return 2;
        if (stat(dirs[*n], &st) == 0 && S_ISDIR(st.st_mode)) {
            rels[*n] = k_fp_auth[i];
            (*n)++;
        }
    }
    return 0;
}

static int fp_check(const char *root, const char *mode, const char *base_path,
                    int floor, FILE *out, FILE *err)
{
    char dirs[FP_NAUTH][4096];
    const char *rels[FP_NAUTH];
    int ndirs = 0;
    struct fp_files fs = { NULL, 0, 0 };
    struct fp_acc a;
    memset(&a, 0, sizeof a);
    a.err = err;
    a.root = root;
    a.mode = mode;
    a.fail_mode = strcmp(mode, "FAIL") == 0;
    char hint[4608];
    int rc = fp_collect_dirs(root, dirs, rels, &ndirs);
    if (rc == 0) {
        if (ovf(snprintf(hint, sizeof hint, "none of the codeindex root dirs "
                         "exist under %s — layout changed?", root),
                sizeof hint))
            rc = 2;
        else
            rc = gate_require_scanned(ndirs, 1, "check-file-purpose", hint);
    }
    for (int i = 0; rc == 0 && i < ndirs; i++)
        rc = fp_walk(dirs[i], rels[i], &fs);
    if (rc == 0) {
        fp_sort_uniq(&fs);
        rc = gate_require_scanned((int)fs.n, floor, "check-file-purpose",
                                  "the codeindex-root .c/.h scan came back "
                                  "too small — a scanned dir moved?");
    }
    if (rc == 0)
        rc = lint_base_load_set(&g_fp_allowed, base_path);
    for (size_t i = 0; rc == 0 && i < fs.n; i++) {
        char full[4096];
        if (ovf(snprintf(full, sizeof full, "%s/%s", root, fs.v[i]),
                sizeof full))
            rc = 2;
        else
            rc = fp_judge(full, fs.v[i], &a);
    }
    if (rc == 0)
        rc = gate_require_scanned(a.scanned, (int)fs.n, "check-file-purpose",
                                  "the per-file scan loop ran fewer "
                                  "iterations than the file list");
    int fin_rc = rc == 0 ? fp_finish(&a, out) : rc;
    fp_free(&fs);
    return fin_rc;
}

/* [[ -d "$SCAN_ROOT" ]] || FATAL exit 2, then the scan. */
static int fp_entry(const char *root, const char *mode, const char *base_path,
                    int floor, FILE *out, FILE *err)
{
    struct stat st;
    if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(err, "check_file_purpose: FATAL — missing scan root %s\n",
                root);
        return 2;
    }
    return fp_check(root, mode, base_path, floor, out, err);
}

int check_file_purpose_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *ov = getenv("ZCL_FILE_PURPOSE_ROOT");
    int isolated = ov && ov[0];
    return fp_entry(isolated ? ov : ".", env_or("ZCL_LINT_MODE", "WARN"),
                    k_fp_base, isolated ? 1 : 1500, stdout, stderr);
}

/* ── selftest ──────────────────────────────────────────────────────────── */

static int fp_st_case(const char *root, const char *mode,
                      const char *base_body, int want_rc, const char *needle)
{
    char bp[4096];
    if (ovf(snprintf(bp, sizeof bp, "%s/baseline.txt", root), sizeof bp))
        return 1;
    if (base_body) {
        if (csr_write(bp, base_body))
            return 1;
    } else {
        (void)unlink(bp);
    }
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = fp_entry(root, mode, bp, 1, out, err);
    char bo[8192], be[8192], both[16384];
    int src = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be)
        | ovf(snprintf(both, sizeof both, "%s%s", bo, be), sizeof both);
    fclose(out);
    fclose(err);
    if (src)
        return 1;
    if (rc != want_rc || (needle && !strstr(both, needle))) {
        fprintf(stderr, "check_file_purpose selftest: mode %s want rc %d "
                "needle '%s'; got rc %d and:\n%s\n",
                mode, want_rc, needle ? needle : "(none)", rc, both);
        return 1;
    }
    return 0;
}

/* The passing trio: a multi-line block with a `purpose:` override, a //
 * line comment, and a block whose second line is substantive. */
static int fp_st_tree(const char *root)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/services/src/ok.c", root),
            sizeof p)
        || csr_write(p, "/* Copyright 2026 Rhett Creighton - Apache License "
                        "2.0\n *\n * purpose: selftest fixture with an "
                        "explicit purpose override\n */\nint fp_st_ok;\n")
        || ovf(snprintf(p, sizeof p, "%s/engine/services/src/lc.c", root),
               sizeof p)
        || csr_write(p, "// selftest fixture whose purpose is a line "
                        "comment\nint fp_st_lc;\n")
        || ovf(snprintf(p, sizeof p, "%s/engine/services/src/blk.c", root),
               sizeof p)
        || csr_write(p, "/*\n * selftest fixture whose block comment carries "
                        "the purpose\n */\nint fp_st_blk;\n"))
        return 1;
    return 0;
}

static int fp_st_badpair(const char *root)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/services/src/bad.c", root),
            sizeof p)
        || csr_write(p, "int fp_st_bad;\n/* this comment comes after the "
                        "first code token */\n")
        || ovf(snprintf(p, sizeof p, "%s/engine/services/src/coponly.c",
                        root), sizeof p)
        || csr_write(p, "/* Copyright 2026 Rhett Creighton - Apache License "
                        "2.0 */\nint fp_st_cop;\n"))
        return 1;
    return 0;
}

static int fp_st_unplant(const char *root)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/engine/services/src/bad.c", root),
            sizeof p))
        return 1;
    (void)unlink(p);
    if (ovf(snprintf(p, sizeof p, "%s/engine/services/src/coponly.c", root),
            sizeof p))
        return 1;
    (void)unlink(p);
    return 0;
}

/* The run-level guard: a missing scan root is FATAL (exit 2), never a
 * quiet pass. */
static int fp_st_gone_root(const char *root)
{
    char gone[4096];
    if (ovf(snprintf(gone, sizeof gone, "%s/gone", root), sizeof gone))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = fp_entry(gone, "RATCHET", "x", 1, out, err);
    char be[8192];
    int src = csr_slurp(err, be, sizeof be);
    fclose(out);
    fclose(err);
    if (src || rc != 2 || !strstr(be, "FATAL — missing scan root"))
        return 1;
    return 0;
}

int check_file_purpose_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-fp-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    int bad = fp_st_tree(root);
    if (!bad) {
        /* a clean fixture tree passes RATCHET and reports the scan count */
        bad |= fp_st_case(root, "RATCHET", NULL, 0,
                          "scanned 3 source file(s) under");
        bad |= fp_st_case(root, "RATCHET", NULL, 0,
                          "0 violation(s) found (mode: RATCHET)");
        /* code-before-comment and copyright-only headers trip RATCHET */
        bad |= fp_st_badpair(root);
        bad |= fp_st_case(root, "RATCHET", NULL, 1,
                          "engine/services/src/bad.c: no derivable file "
                          "purpose");
        bad |= fp_st_case(root, "RATCHET", NULL, 1,
                          "2 violation(s) found (mode: RATCHET)");
        /* WARN reports the same violations but exits 0 */
        bad |= fp_st_case(root, "WARN", NULL, 0,
                          "2 violation(s) found (mode: WARN)");
        /* FAIL trips too, baseline or not */
        bad |= fp_st_case(root, "FAIL",
                          "engine/services/src/bad.c\n"
                          "engine/services/src/coponly.c\n", 1,
                          "2 violation(s) found (mode: FAIL)");
        /* set membership allowlists both under RATCHET */
        bad |= fp_st_case(root, "RATCHET",
                          "engine/services/src/bad.c\n"
                          "engine/services/src/coponly.c\n", 0,
                          "2 allowlisted violation(s) ignored");
        /* a partial set allowlists one and fails the other */
        bad |= fp_st_case(root, "RATCHET", "engine/services/src/bad.c\n", 1,
                          "1 violation(s) found (mode: RATCHET)\n"
                          "[check_file_purpose] 1 allowlisted violation(s) "
                          "ignored");
        bad |= fp_st_unplant(root);
        /* set semantics: an entry nobody scanned is unused, never stale */
        bad |= fp_st_case(root, "RATCHET", "engine/services/src/gone.c\n", 0,
                          "0 violation(s) found");
        /* gate_load_list_file trims and takes `#` as a comment anywhere */
        bad |= fp_st_badpair(root);
        bad |= fp_st_case(root, "RATCHET",
                          "  engine/services/src/bad.c  # relocated soon\n"
                          "engine/services/src/coponly.c\n", 0,
                          "2 allowlisted violation(s) ignored");
        bad |= fp_st_unplant(root);
        bad |= fp_st_gone_root(root);
        /* none of the authority dirs existing is a hollow scan: exit 2.
         * (gate_require_scanned writes to process stderr, so only the exit
         * code is asserted here, not the message bytes.) */
        char eng[4096];
        if (ovf(snprintf(eng, sizeof eng, "%s/engine", root), sizeof eng)
            || rap_rm_rf(eng))
            bad |= 1;
        else
            bad |= fp_st_case(root, "RATCHET", NULL, 2, NULL);
    }
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_file_purpose selftest: OK\n");
}
