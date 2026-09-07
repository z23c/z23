/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-source-identity-authority (port of
 * tools/lint/check_source_identity_authority.sh, now a shim). The JSON key
 * "source_id_sha256" answers two different questions in this tree — Q1
 * "what source tree was this BINARY built from?" (read through the
 * schema-anchored zcl_agentbuild_v2_top_source_id) vs Q2 "what source tree
 * is in THIS DIRECTORY right now?" (tools/dev/source-identity.sh
 * capture-record) — and a script that spells both the same way, or reads
 * one positionally, is how the two get confused. Shrink-only ratchet over
 * tools/lint/source_identity_authority_baseline.txt. Two classes counted
 * per scanned *.sh file (plus the Makefile): class R, a positional
 * agentbuild-response read (an inline grep/sed extraction of the key, or a
 * zcl_json_first_string/zcl_json_first_sha256/json_first_string_field call
 * on it) within WINDOW lines of the literal "agentbuild"; class P, a
 * plain `"source_id_sha256":` producer in a file that also runs
 * capture-record.
 *
 * First file of the check-source-identity-authority family (the 700-line
 * family ceiling split): the shared growable-list helpers, the regex
 * lifecycle, and the gate body. gate_source_identity_authority_scan.c
 * holds the find-mirror walk and the awk per-file counter;
 * gate_source_identity_authority_ratchet.c holds the baseline, the
 * evaluation and the report;
 * gate_source_identity_authority_selftest.c holds the planted-violation
 * selftest. The files share their internals through
 * gate_source_identity_authority_priv.h.
 *
 * Port notes (parity contract with the shell original):
 *  - The awk scan is reproduced exactly: the six-line "agentbuild nearby"
 *    window holds raw lines, a pure-comment line stores an empty slot, and
 *    the current line is stored BEFORE the class-R test (a line naming
 *    agentbuild is its own context). All needle tests are plain substring
 *    searches (awk index()), including the two regex-shaped SOURCE-TEXT
 *    needles and the grep|sed tool test.
 *  - find walks in readdir order; this port walks in scandir/alphasort
 *    order. Every multi-row output (violations, stale rows, the UPDATE
 *    baseline) goes through the same locale `sort` the shell used
 *    (setlocale(LC_COLLATE, "") + strcoll, byte tiebreak like GNU sort),
 *    so verdicts, counts and text are byte-identical either way.
 *  - gate_load_kv_file semantics: `#` cuts a comment anywhere, lines are
 *    whitespace-trimmed, the key is the text before the first SPACE and
 *    the value the text after the LAST one, later rows overwrite earlier
 *    ones, a missing baseline is an empty set.
 *  - An unreadable scanned file exits 2 naming the path (UNPROVEN); the
 *    shell's process substitution masked awk's error and reported off a
 *    partial scan. An unreadable DIRECTORY mid-walk likewise dies exit 2
 *    where find's 2>/dev/null skipped it silently. A missing scan root
 *    still reaches the scan-set floor exactly as the shell did.
 *  - Stored window lines and single-field copies are bounded (SIA_LINE);
 *    a longer line dies exit 2 (fail-closed) where the shell ran
 *    unbounded.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_source_identity_authority_priv.h"

static const char k_gate[] = "check_source_identity_authority";
static const char k_baseline_rel[] =
    "tools/lint/source_identity_authority_baseline.txt";

static int sia_compile(struct sia_rx *rx)
{
    int cr = reg_fail(&rx->excl, regcomp(&rx->excl,
        "(^|/)source_identity_lib\\.sh$|"
        "(^|/)check_source_identity_authority\\.sh$|"
        "(^|/)check_identity_parser_single\\.sh$", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->r1, regcomp(&rx->r1,
            "(^|[^A-Za-z0-9_])zcl_json_first_string[ \t]", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->r2, regcomp(&rx->r2,
            "(^|[^A-Za-z0-9_])zcl_json_first_sha256[ \t]", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->r3, regcomp(&rx->r3,
            "(^|[^A-Za-z0-9_])json_first_string_field[ \t]", REG_EXTENDED));
    return cr;
}

static void sia_drop(struct sia_rx *rx)
{
    regfree(&rx->excl);
    regfree(&rx->r1);
    regfree(&rx->r2);
    regfree(&rx->r3);
}

/* ── growable string list ─────────────────────────────────────────────── */

void sia_free(struct sia_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int sia_push(struct sia_list *l, char *s)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 32;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv) {
            free(s);
            return die("z23-lint: out of memory\n", "");
        }
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n++] = s;
    return 0;
}

int sia_add(struct sia_list *l, const char *s)
{
    size_t n = strlen(s);
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, s, n + 1);
    return sia_push(l, copy);
}

int sia_addf(struct sia_list *l, const char *fmt, const char *a,
             const char *b, const char *c)
{
    int need = snprintf(NULL, 0, fmt, a, b, c);
    if (need < 0)
        return die("z23-lint: write failed\n", "");
    char *s = malloc((size_t)need + 1); // raw-alloc-ok:lint-runtime
    if (!s)
        return die("z23-lint: out of memory\n", "");
    if (snprintf(s, (size_t)need + 1, fmt, a, b, c) != need) {
        free(s);
        return die("z23-lint: write failed\n", "");
    }
    return sia_push(l, s);
}

/* GNU sort under the ambient locale: strcoll, byte tiebreak. */
static int sia_coll(const void *a, const void *b)
{
    char *const *x = a;
    char *const *y = b;
    int c = strcoll(*x, *y);
    return c ? c : strcmp(*x, *y);
}

void sia_sort(struct sia_list *l)
{
    if (l->n)
        qsort(l->v, l->n, sizeof l->v[0], sia_coll);
}

/* ── the gate ─────────────────────────────────────────────────────────── */

static int sia_collect(struct sia_rx *rx, const char *scan_root,
                       const char *makefile, struct sia_list *files,
                       int *nfiles)
{
    int rc = sia_walk(rx, scan_root, files);
    struct stat st;
    if (rc == 0 && stat(makefile, &st) == 0 && S_ISREG(st.st_mode))
        rc = sia_add(files, makefile);
    *nfiles = (int)files->n;
    return rc;
}

static int sia_scan_all(struct sia_rx *rx, const struct sia_list *files,
                        struct sia_counts *counts)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < files->n; i++)
        rc = sia_scan_file(rx, files->v[i], counts);
    return rc;
}

/* gate_require_scanned's exact text, but to the gate's err stream so the
 * selftest's captured log sees it (the lib helper prints to real stderr). */
static int sia_require_scanned(int count, int floor, const char *hint,
                               FILE *err)
{
    if (count >= floor)
        return 0;
    fprintf(err, "%s: FATAL — scan set is '%d' (< floor %d).\n", k_gate,
            count, floor);
    fputs("  The scan producer (find/glob/grep) returned too little; a\n"
          "  scanned dir/file was likely renamed, moved, or deleted.\n"
          "  Refusing to report 'clean' off a hollow (empty) scan.\n", err);
    if (hint && hint[0])
        fprintf(err, "  %s\n", hint);
    return 2;
}

int sia_impl(FILE *out, FILE *err)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    const char *baseline = env_or("ZCL_SOURCE_AUTHORITY_BASELINE",
                                  k_baseline_rel);
    const char *scan_root = env_or("ZCL_SOURCE_AUTHORITY_SCAN_ROOT",
                                   "tools");
    const char *makefile = env_or("ZCL_SOURCE_AUTHORITY_MAKEFILE",
                                  "Makefile");
    const char *ceiling = env_or("ZCL_SOURCE_AUTHORITY_CEILING", "5");
    const char *floor = env_or("ZCL_SOURCE_AUTHORITY_FILE_FLOOR", "5");
    struct sia_rx rx;
    int rc = sia_compile(&rx);
    if (rc)
        return rc;
    struct sia_list files = { 0 };
    struct sia_counts counts = { 0 };
    struct sia_kvset base = { 0 };
    struct sia_eval e = { 0 };
    int nfiles = 0;
    rc = sia_collect(&rx, scan_root, makefile, &files, &nfiles);
    if (rc == 0) {
        char hint[8192];
        if (ovf(snprintf(hint, sizeof hint,
                         "no *.sh files found under %s (plus %s) — the "
                         "scan root moved", scan_root, makefile),
                sizeof hint))
            rc = 2;
        else
            rc = sia_require_scanned(nfiles, (int)strtol(floor, NULL, 10),
                                     hint, err);
    }
    if (rc == 0)
        rc = sia_scan_all(&rx, &files, &counts);
    if (rc == 0)
        rc = sia_base_load(baseline, &base);
    if (rc == 0)
        rc = sia_evaluate(&counts, &base, &e);
    if (rc == 0)
        rc = sia_finish(&e, &counts, baseline, ceiling, mode, nfiles,
                        (int)base.n, out);
    sia_free(&files);
    sia_counts_free(&counts);
    sia_kvset_free(&base);
    sia_eval_free(&e);
    sia_drop(&rx);
    return rc;
}

int check_source_identity_authority_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    (void)setlocale(LC_COLLATE, "");
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot chdir %s\n", root);
    return sia_impl(stdout, stderr);
}
