/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-outparam-init-before-return
 *
 * A function that hands back a struct the caller will free MUST initialize
 * that struct before the first thing that can fail; and a pointer published
 * into a module global must be unpublished before its storage is freed. Both
 * halves are one class: the thing a later reader will free or dereference is
 * left in a state its guard cannot see. Found live twice on 2026-08-26 —
 * compact_block_reconstruct() (remote, any peer, bce343876) and
 * sapling_init_params() (69518f2f3).
 *
 * THE BUG, LEG 1. compact_block_reconstruct() took `struct block *out_block`
 * and its first failure return sat ABOVE block_init(out_block); its caller
 * ran block_free(&out_block) on that outcome, so transaction_free() walked
 * whatever the caller's stack happened to hold. Two things hid it: LOG_FAIL
 * and every LOG_* macro expand to `return false`, so a line that reads like
 * logging is a control-flow exit; and a fresh stack reads back as zero, so a
 * one-shot replay frees nothing and exits clean (rebuild with
 * -ftrivial-auto-var-init=pattern to make it deterministic).
 *
 * WHAT IT CHECKS. For every function in every tracked .c file outside
 * vendor/ it extracts each parameter of the form `struct T *name` (non-const,
 * single pointer), finds the first `*_init(name)` / `memset(name, ...)` in the
 * body, and reports the pair when a `return` or `LOG_*(` that is DATA
 * dependent (not solely a NULL/empty-pointer guard) precedes it. It reports
 * only when `T_free` exists somewhere in the tree, and never for the type's
 * own T_init / T_free / T_reset. Every finding must be in the closed baseline
 * tools/lint/outparam_init_baseline.txt (`function|param|type`, each with a
 * reviewed reason); a baseline row the code no longer trips is STALE and
 * fails too.
 *
 * WHAT IT CANNOT CHECK. It is a line-order scanner over C text, not a
 * compiler: it does not follow control flow (`if (x) { init(out); } ...
 * return` reads as initialized), does not resolve macros, does not prove the
 * CALLER frees (that leg is the reviewer's, recorded per baseline row), only
 * sees `T_init(out)` / `memset(out, ...)` shapes, and ignores multi-declarator
 * declarations and `struct T **out` owner-outs. It is a RATCHET, not a prover.
 *
 * BRACE BALANCE IS PART OF THE CONTRACT. The scanner tracks `{`/`}` as text; a
 * file whose braces do not return to depth 0 (the `#if defined(_WIN32) if ..
 * { #else if .. { #endif .. }` shape) would hide its own later functions. The
 * depth is reset per file and every such file is a gate failure unless
 * tools/lint/outparam_scanner_imbalance_allow.txt pins it ("<path> <depth>").
 *
 * LEG 2. A published global freed without unpublishing: the publisher finder
 * derives every function that stores a caller pointer into a file-scope
 * variable (all tracked .c files); the publish/free analyzer then walks
 * production sources only (tests, fuzzers, examples excluded: harnesses hand
 * a stage module a main_state and free it at case teardown) and fails on any
 * publish-then-free with no unpublish between. Zero tolerance, no baseline.
 *
 * FAIL CLOSED. Unlike the awk pipeline this replaces (which sent every awk
 * error to /dev/null and ignored its exit status), an unreadable tracked
 * file, an unreadable git index, an overflowed table or an empty scan is a
 * non-zero exit with a message, never a clean pass.
 *
 * Mode: WARN | FAIL (ZCL_LINT_MODE, default FAIL). `--print-findings` lists
 * every in-scope finding with file and line numbers, in baseline-key order.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_outparam_init_priv.h"

#define OP_GATE "check-outparam-init-before-return"

enum {
    OP_MAXFILES = 16384,
    OP_MAXIMB = 256,
    OP_FREES_CAP = 16384,
    OP_SET_CAP = 8192
};

static const char k_op_baseline[] = "tools/lint/outparam_init_baseline.txt";
static const char k_op_allow[] = "tools/lint/outparam_scanner_imbalance_allow.txt";

static const char *const k_op_nonprod[] = {
    "tests/", "tools/fuzz/", "examples/", "contexts/commons/modules/vcs/tests/"
};

/* Tracked non-vendor .c and .h paths in index order; kind 'c' or 'h'. */
static char g_op_path[OP_MAXFILES][OP_PATH];
static char g_op_kind[OP_MAXFILES];
static int g_op_nfiles;

static char g_op_imb_file[OP_MAXIMB][OP_PATH];
static int g_op_imb_depth[OP_MAXIMB];
static int g_op_nimb;

static int op_index_cb(const char *path, int stage, void *ctx)
{
    size_t n = strlen(path);
    (void)stage;
    (void)ctx;
    if (n < 2 || path[n - 2] != '.' || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    if (strncmp(path, "vendor/", 7) == 0)
        return 0;
    if (g_op_nfiles > 0 && strcmp(g_op_path[g_op_nfiles - 1], path) == 0)
        return 0;
    if (g_op_nfiles >= OP_MAXFILES || n >= OP_PATH)
        return die("z23-lint: outparam-init: tracked file table overflow: %s\n", path);
    memcpy(g_op_path[g_op_nfiles], path, n + 1);
    g_op_kind[g_op_nfiles++] = path[n - 1];
    return 0;
}

static int op_collect(void)
{
    char bad[8] = { 0 };
    int rc;
    g_op_nfiles = 0;
    rc = lint_git_index_foreach(op_index_cb, NULL, bad);
    if (rc)
        fprintf(stderr, OP_GATE ": UNPROVEN — git index%s%s could not be read\n",
                bad[0] ? " extension " : "", bad);
    return rc;
}

static int op_count_kind(char kind)
{
    int n = 0;
    for (int i = 0; i < g_op_nfiles; i++)
        n += g_op_kind[i] == kind;
    return n;
}

static int op_is_prod(const char *path)
{
    for (size_t i = 0; i < sizeof k_op_nonprod / sizeof *k_op_nonprod; i++)
        if (strncmp(path, k_op_nonprod[i], strlen(k_op_nonprod[i])) == 0)
            return 0;
    return 1;
}

/* A maximal word of [a-z0-9_] ending in _free (a grep for the free-suffixed words). */
static int op_free_line(void *ctx, const char *line, size_t len)
{
    struct op_hset *frees = ctx;
    size_t i = 0;
    while (i < len) {
        size_t e = i;
        int lower = 1;
        if (!op_idc((unsigned char)line[i])) {
            i++;
            continue;
        }
        for (; e < len && op_idc((unsigned char)line[e]); e++)
            lower &= !(line[e] >= 'A' && line[e] <= 'Z');
        if (lower && e - i >= 6 && memcmp(line + e - 5, "_free", 5) == 0) {
            char w[OP_NAME];
            if (e - i >= sizeof w)
                return die("z23-lint: outparam-init: %s\n", "a *_free word longer than 127 bytes");
            memcpy(w, line + i, e - i);
            w[e - i] = '\0';
            if (op_hset_add(frees, w))
                return 2;
        }
        i = e;
    }
    return 0;
}

static int op_build_frees(struct op_hset *frees)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < g_op_nfiles; i++)
        rc = lc_each_line(g_op_path[i], op_free_line, frees, 0);
    return rc;
}

static int op_note_imbalance(const char *path, int depth)
{
    if (g_op_nimb >= OP_MAXIMB)
        return die("z23-lint: outparam-init: %s\n", "too many unbalanced files");
    if (ovf(snprintf(g_op_imb_file[g_op_nimb], OP_PATH, "%s", path), OP_PATH))
        return 2;
    g_op_imb_depth[g_op_nimb++] = depth;
    return 0;
}

/* Leg 1 over every tracked .c file. */
static int op_scan_all(struct op_fn *fn)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < g_op_nfiles; i++) {
        int depth = 0;
        if (g_op_kind[i] != 'c')
            continue;
        rc = op_fn_file(fn, g_op_path[i], &depth);
        if (rc == 0 && depth != 0)
            rc = op_note_imbalance(g_op_path[i], depth);
    }
    return rc;
}

static int op_set_line(void *ctx, const char *line, size_t len)
{
    struct op_hset *h = ctx;
    char buf[OP_NAME * 2];
    const char *hash = memchr(line, '#', len);
    size_t n = hash ? (size_t)(hash - line) : len;
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == ' ' || line[n - 1] == '\t'
                     || line[n - 1] == '\r'))
        n--;
    while (n > 0 && (*line == ' ' || *line == '\t')) {
        line++;
        n--;
    }
    if (n == 0)
        return 0;
    if (n >= sizeof buf)
        return die("z23-lint: outparam-init: %s\n", "list row too long");
    memcpy(buf, line, n);
    buf[n] = '\0';
    return op_hset_add(h, buf);
}

/* Presence-set list file (gate_load_list_file): `#` starts a comment, rows
 * are trimmed, a missing file is the empty set. count gets the rows read. */
static int op_load_set(const char *path, struct op_hset *h, int *count)
{
    int rc = lc_each_line(path, op_set_line, h, 1);
    *count = h->n;
    return rc == 1 ? 0 : rc;
}

static int op_imb_known(const struct op_hset *allow, int i)
{
    char key[OP_PATH + 16];
    if (ovf(snprintf(key, sizeof key, "%s %d", g_op_imb_file[i], g_op_imb_depth[i]),
            sizeof key))
        return 0;
    return op_hset_has(allow, key);
}

/* Fails the gate on every unbalanced file not pinned in the allow list; names
 * a pinned file that now balances. Returns 1 when the gate must fail. */
static int op_check_imbalance(const struct op_hset *allow)
{
    int bad = 0;
    for (int i = 0; i < g_op_nimb; i++)
        bad += !op_imb_known(allow, i);
    if (bad) {
        fprintf(stderr, OP_GATE ": %d file(s) the\n"
                "  scanner could not brace-balance, so their remaining functions were\n"
                "  NOT scanned:\n", bad);
        for (int i = 0; i < g_op_nimb; i++)
            if (!op_imb_known(allow, i))
                fprintf(stderr, "    scanner lost brace balance in %s: %d\n",
                        g_op_imb_file[i], g_op_imb_depth[i]);
        fputs("\n  This is almost always an '#if defined(X) if (..) { #else if (..) {\n"
              "  #endif ... }' shape: two openers, one closer. Give each branch its\n"
              "  own matched braces — duplicate the closing lines into both arms.\n"
              "  Only a file another in-flight lane owns belongs in\n", stderr);
        fprintf(stderr, "  %s, with its depth pinned and the removing lane named.\n", k_op_allow);
    }
    for (int i = 0; i < allow->n; i++) {
        int hit = 0;
        for (int k = 0; k < g_op_nimb && !hit; k++) {
            char key[OP_PATH + 16];
            hit = snprintf(key, sizeof key, "%s %d", g_op_imb_file[k], g_op_imb_depth[k]) > 0
                && strcmp(key, allow->nm[i]) == 0;
        }
        if (!hit)
            fprintf(stderr, OP_GATE ": note — '%s' in\n %s now balances; delete the entry.\n",
                    allow->nm[i], k_op_allow);
    }
    return bad > 0;
}

/* Publisher finder over every tracked .c file, then the publish/free analyzer
 * over the production ones. rc 0 or a fatal code; *failed set on a dangling
 * published pointer. */
static int op_leg2(struct op_pub *pub, struct op_hset *pubs, struct op_hset *objs,
                   long *scanned, int *failed)
{
    struct op_fn fn;
    int rc = 0, depth, nprod = 0;
    op_fn_init(&fn, OP_MODE_PUB, op_pubfind_emit, pub, objs);
    for (int i = 0; rc == 0 && i < g_op_nfiles; i++)
        if (g_op_kind[i] == 'c')
            rc = op_fn_file(&fn, g_op_path[i], &depth);
    op_fn_free(&fn);
    if (rc == 0)
        rc = gate_require_scanned(pubs->n, 20, OP_GATE,
            "expected >=20 publisher functions (a store of a caller pointer into a file-scope var); the derivation is empty");
    pub->known = pubs;
    op_fn_init(&fn, OP_MODE_FREE, op_pubfree_emit, pub, NULL);
    for (int i = 0; rc == 0 && i < g_op_nfiles; i++) {
        if (g_op_kind[i] != 'c' || !op_is_prod(g_op_path[i]))
            continue;
        nprod++;
        rc = op_fn_file(&fn, g_op_path[i], &depth);
    }
    op_fn_free(&fn);
    if (rc == 0)
        rc = gate_require_scanned(nprod, 1000, OP_GATE,
            "expected >=1000 production .c files after excluding harnesses");
    *scanned = pub->nfuncs;
    if (rc == 0)
        rc = gate_require_scanned((int)pub->nfuncs, 5000, OP_GATE,
            "the publish/free analyzer walked almost no function bodies");
    *failed = rc == 0 && pub->nhit > 0;
    return rc;
}

static void op_report_pubfree(const struct op_pub *pub)
{
    fprintf(stderr, OP_GATE ": %d PUBLISHED pointer(s) freed\n"
            "  without being unpublished first:\n", pub->nhit);
    for (int i = 0; i < pub->nhit; i++) {
        const struct op_pubhit *h = &pub->hit[i];
        fprintf(stderr, "    %s: %s() published %s via %s at publish=L%ld, freed at free=L%ld\n",
                h->file, h->fn, h->obj, h->setter, h->pub_line, h->free_line);
    }
    fputs("\n  Every reader's fail-closed guard asks only whether the published\n"
          "  pointer is NULL. That reading is true only while every failure path\n"
          "  actually produces NULL. Publish BELOW every fallible step, and\n"
          "  unpublish BEFORE freeing — see the invariant comment in\n"
          "  core/modules/sapling/src/params_init.c.\n", stderr);
}

/* Sorted unique finding keys (pointers into the finding table). */
static int op_unique_keys(const struct op_scan *s, const char **keys)
{
    int n = 0;
    for (int i = 0; i < s->nfind; i++)
        keys[n++] = s->find[i].key;
    qsort(keys, (size_t)n, sizeof *keys, lintc_strcmp_ptr);
    int u = 0;
    for (int i = 0; i < n; i++)
        if (u == 0 || strcmp(keys[u - 1], keys[i]) != 0)
            keys[u++] = keys[i];
    return u;
}

static void op_print_detail(const struct op_scan *s, const char *key, const char *lead)
{
    for (int i = 0; i < s->nfind; i++) {
        const struct op_finding *f = &s->find[i];
        if (strcmp(f->key, key) == 0)
            fprintf(stderr, "%s%s\texit=L%ld init=L%ld(%s)\n", lead, f->file,
                    f->exit_line, f->init_line, f->tag == 'm' ? "memset" : "init");
    }
}

/* --print-findings: every in-scope finding with its file and line numbers. */
static int op_print_findings(const struct op_scan *s)
{
    char **lines = calloc((size_t)s->nfind + 1, sizeof *lines); // raw-alloc-ok:lint-runtime
    int rc = 0;
    if (!lines)
        return die("z23-lint: outparam-init: out of memory\n", "");
    for (int i = 0; i < s->nfind && rc == 0; i++) {
        const struct op_finding *f = &s->find[i];
        char buf[OP_KEY + OP_PATH + 64];
        rc = ovf(snprintf(buf, sizeof buf, "%s\t%s\texit=L%ld init=L%ld(%s)", f->key, f->file,
                          f->exit_line, f->init_line, f->tag == 'm' ? "memset" : "init"),
                 sizeof buf);
        if (rc == 0 && !(lines[i] = strdup(buf))) // raw-alloc-ok:lint-runtime
            rc = die("z23-lint: outparam-init: out of memory\n", "");
    }
    if (rc == 0) {
        qsort(lines, (size_t)s->nfind, sizeof *lines, lintc_strcmp_ptr);
        for (int i = 0; i < s->nfind; i++)
            puts(lines[i]);
    }
    for (int i = 0; i < s->nfind; i++)
        free(lines[i]);
    free(lines);
    return rc;
}

/* NEW findings first and unconditionally: a stale-baseline complaint must
 * never pre-empt the report of an actual new violation. Returns the count. */
static int op_report_new(const struct op_scan *s, const char **keys, int nkeys,
                         const struct op_hset *base, int warn)
{
    int nnew = 0;
    for (int i = 0; i < nkeys; i++)
        nnew += !op_hset_has(base, keys[i]);
    if (nnew == 0)
        return 0;
    fprintf(stderr, OP_GATE ": %d NEW out-parameter(s) whose\n"
            "  initialization sits BELOW a failure return:\n", nnew);
    for (int i = 0; i < nkeys; i++) {
        const char *k = keys[i], *p1, *p2;
        if (op_hset_has(base, k))
            continue;
        p1 = strchr(k, '|');
        p2 = p1 ? strchr(p1 + 1, '|') : NULL;
        if (!p2)
            continue;
        fprintf(stderr, "    %.*s(): struct %s *%.*s\n", (int)(p1 - k), k, p2 + 1,
                (int)(p2 - p1 - 1), p1 + 1);
        op_print_detail(s, k, "        at ");
    }
    fputs("\n  Remember LOG_FAIL / LOG_ERR / LOG_RETURN EXPAND TO a return.\n"
          "  Fix by moving the *_init()/memset() ABOVE the first thing that can\n"
          "  fail, and state the post-condition in the header so the next caller\n"
          "  can rely on it — see core/modules/net/include/net/compact_blocks.h.\n"
          "  If the caller provably never frees on that path, add the key to\n", stderr);
    fprintf(stderr, "  %s with a one-line reviewed reason:\n", k_op_baseline);
    for (int i = 0; i < nkeys; i++)
        if (!op_hset_has(base, keys[i]))
            fprintf(stderr, "    %s\n", keys[i]);
    if (warn)
        fprintf(stderr, OP_GATE ": WARN (%d new)\n", nnew);
    return nnew;
}

/* A baseline row no code trips is a stale exception: the next function that
 * reuses the name would inherit a waiver nobody reviewed. */
static int op_report_stale(const struct op_hset *base, const struct op_hset *keyset)
{
    int nstale = 0;
    for (int i = 0; i < base->n; i++)
        nstale += !op_hset_has(keyset, base->nm[i]);
    if (nstale == 0)
        return 0;
    fprintf(stderr, OP_GATE ": %d STALE baseline entr(ies)\n"
            "  in %s — the code they name no longer trips this gate.\n"
            "  Delete them (and the reason comment above them):\n", nstale, k_op_baseline);
    for (int i = 0; i < base->n; i++)
        if (!op_hset_has(keyset, base->nm[i]))
            fprintf(stderr, "    %s\n", base->nm[i]);
    return nstale;
}

struct op_gate {
    struct op_hset frees, pubs, objs, allow, base, keyset;
    struct op_scan scan;
    struct op_pub pub;
    struct op_fn fn;
};

static void op_gate_free(struct op_gate *g)
{
    op_hset_free(&g->frees);
    op_hset_free(&g->pubs);
    op_hset_free(&g->objs);
    op_hset_free(&g->allow);
    op_hset_free(&g->base);
    op_hset_free(&g->keyset);
    op_scan_free(&g->scan);
    op_pub_free(&g->pub);
    op_fn_free(&g->fn);
}

static int op_gate_init(struct op_gate *g)
{
    memset(g, 0, sizeof *g);
    if (op_hset_init(&g->frees, OP_FREES_CAP) || op_hset_init(&g->pubs, OP_SET_CAP)
        || op_hset_init(&g->objs, OP_SET_CAP) || op_hset_init(&g->allow, 256)
        || op_hset_init(&g->base, OP_SET_CAP) || op_hset_init(&g->keyset, OP_SET_CAP)) {
        op_gate_free(g);
        return 2;
    }
    g->scan.frees = &g->frees;
    g->pub.found = &g->pubs;
    return 0;
}

/* Floors, collection, both legs. rc nonzero is a fatal 2. */
static int op_phase_scan(struct op_gate *g, int *imb_failed, int *pub_failed, long *pub_scanned)
{
    int rc = op_collect();
    if (rc == 0)
        rc = gate_require_scanned(op_count_kind('c'), 2000, OP_GATE,
            "expected thousands of tracked .c files; the git ls-files producer is empty");
    if (rc == 0)
        rc = op_build_frees(&g->frees);
    if (rc == 0)
        rc = gate_require_scanned(g->frees.n, 100, OP_GATE,
            "expected >=100 distinct *_free symbols; the derivation is empty");
    op_fn_init(&g->fn, OP_MODE_SCAN, op_scan_emit, &g->scan, NULL);
    if (rc == 0)
        rc = op_scan_all(&g->fn);
    if (rc == 0)
        rc = gate_require_scanned((int)g->scan.nfuncs, 10000, OP_GATE,
            "the analyzer walked almost no function bodies — its C parser is broken");
    if (rc == 0) {
        int dummy = 0;
        rc = op_load_set(k_op_allow, &g->allow, &dummy);
    }
    if (rc == 0)
        *imb_failed = op_check_imbalance(&g->allow);
    if (rc == 0)
        rc = op_leg2(&g->pub, &g->pubs, &g->objs, pub_scanned, pub_failed);
    return rc;
}

/* Baseline comparison; returns the gate exit code. */
static int op_phase_baseline(struct op_gate *g, int failed, long pub_scanned)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    int warn = strcmp(mode, "WARN") == 0, nbase = 0, nkeys, rc;
    const char **keys = calloc((size_t)g->scan.nfind + 1, sizeof *keys); // raw-alloc-ok:lint-runtime
    if (!keys)
        return die("z23-lint: outparam-init: out of memory\n", "");
    nkeys = op_unique_keys(&g->scan, keys);
    rc = gate_require_scanned(nkeys, 1, OP_GATE,
        "the in-scope filter matched nothing at all — the *_free derivation or the analyzer changed shape");
    for (int i = 0; rc == 0 && i < nkeys; i++)
        rc = op_hset_add(&g->keyset, keys[i]);
    if (rc == 0)
        rc = op_load_set(k_op_baseline, &g->base, &nbase);
    if (rc == 0)
        rc = gate_require_scanned(nbase, 1, OP_GATE, "tools/lint/outparam_init_baseline.txt is missing or empty");
    if (rc == 0) {
        failed |= op_report_new(&g->scan, keys, nkeys, &g->base, warn) > 0 && !warn;
        failed |= op_report_stale(&g->base, &g->keyset) > 0 && !warn;
        if (!failed)
            printf(OP_GATE ": clean — %ld function bodies scanned, %d in-scope out-param(s), "
                   "all %d reviewed; %ld production bodies (brace state reset per file) "
                   "checked for publish-before-free over %d publishers, 0 dangling\n",
                   g->scan.nfuncs, nkeys, nbase, pub_scanned, g->pubs.n);
        rc = failed ? 1 : 0;
    }
    free(keys);
    return rc;
}

int check_outparam_init_before_return_run(int argc, char **argv)
{
    static struct op_gate g;
    int rc, imb_failed = 0, pub_failed = 0;
    long pub_scanned = 0;
    int print = argc > 0 && strcmp(argv[0], "--print-findings") == 0;
    rc = op_gate_init(&g);
    if (rc)
        return rc;
    rc = op_phase_scan(&g, &imb_failed, &pub_failed, &pub_scanned);
    if (rc == 0 && pub_failed)
        op_report_pubfree(&g.pub);
    if (rc == 0 && print)
        rc = op_print_findings(&g.scan);
    else if (rc == 0)
        rc = op_phase_baseline(&g, imb_failed || pub_failed, pub_scanned);
    op_gate_free(&g);
    return rc;
}
