/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-no-new-borrowed-seed
 * Default landing spot for a FUTURE gate port: a shrink-only caller-baseline
 * ratchet (walk_src over production roots plus a comment-stripped baseline
 * file) joins this family. A filesystem-tree-walking gate that is not a
 * ratchet still joins gate_tree_walk.c; this file exists because
 * gate_tree_walk.c is already at the ~1500-line family cap.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum { NBS_MAX = 512, NBS_PATH = RS_PATH };

static const char k_nbs_def[] =
    "engine/modules/storage/src/coins_kv_boot_rebuild.c";
static const char k_nbs_base[] =
    "tools/lint/borrowed_seed_caller_baseline.txt";
static const char *const k_nbs_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

struct nbs_set { char n[NBS_MAX][NBS_PATH]; int count; };
struct nbs_acc { const char *sym; const char *def; struct nbs_set *callers; };

static void nbs_sym(char *buf, size_t cap)
{
    (void)snprintf(buf, cap, "%s%s", "coins_kv_seed_from_node_db", "(");
}

static int nbs_has(const struct nbs_set *s, const char *path)
{
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->n[i], path) == 0)
            return 1;
    }
    return 0;
}

static int nbs_add(struct nbs_set *s, const char *path)
{
    size_t n = strlen(path);
    if (nbs_has(s, path))
        return 0;
    if (s->count >= NBS_MAX || n >= NBS_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], path, n + 1);
    return 0;
}

static int nbs_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int nbs_load_list(const char *path, struct nbs_set *s)
{
    s->count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h)
            *h = '\0';
        while (*p && isspace((unsigned char)*p))
            p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1]))
            p[--n] = '\0';
        if (n)
            rc = nbs_add(s, p);
    }
    return fin(f, line, path, rc);
}

static int nbs_text_has_sym(const char *text, const char *sym)
{
    return text && sym && strstr(text, sym) != NULL;
}

static int nbs_file_has_sym(const char *path, const char *sym)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = strstr(line, sym) != NULL;
    (void)fin(f, line, path, 0);
    return found;
}

static int nbs_on_file(const char *path, void *ctx)
{
    struct nbs_acc *a = ctx;
    static const char pfx[] = "tests/harness/include/test/";
    if (strcmp(path, a->def) == 0)
        return 0;
    if (strncmp(path, pfx, sizeof pfx - 1) == 0)
        return 0;
    if (lint_path_is_excluded(path))
        return 0;
    if (!nbs_file_has_sym(path, a->sym))
        return 0;
    return nbs_add(a->callers, path);
}

static int nbs_hollow(FILE *out, const char *sym)
{
    if (fprintf(out,
                "check_no_new_borrowed_seed: FATAL — '%s' no longer found in %s.\n",
                sym, k_nbs_def) < 0
        || fputs("  - If the borrowed seed was DELETED (the sovereign cure landed), delete\n",
                 out) < 0
        || fprintf(out, "    this gate, its Makefile wiring, and %s.\n",
                   k_nbs_base) < 0
        || fputs("  - If it was RENAMED/MOVED, update DEF_FILE/SYMBOL here so the ratchet\n",
                 out) < 0
        || fputs("    keeps firing. A gate that matches nothing is a hollow gate.\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 2;
}

static int nbs_scan(FILE *out)
{
    char sym[64];
    nbs_sym(sym, sizeof sym);
    if (!nbs_file_has_sym(k_nbs_def, sym))
        return nbs_hollow(out, sym);
    struct nbs_set base = {0}, callers = {0}, newc = {0}, stale = {0};
    int rc = nbs_load_list(k_nbs_base, &base);
    if (rc)
        return rc;
    struct nbs_acc a = { .sym = sym, .def = k_nbs_def, .callers = &callers };
    for (size_t i = 0; rc == 0 && i < sizeof k_nbs_roots / sizeof k_nbs_roots[0]; i++)
        rc = walk_src(k_nbs_roots[i], 0, nbs_on_file, &a);
    if (rc)
        return rc;
    qsort(callers.n, (size_t)callers.count, NBS_PATH, nbs_cmp);
    for (int i = 0; i < callers.count; i++) {
        if (!nbs_has(&base, callers.n[i])) {
            rc = nbs_add(&newc, callers.n[i]);
            if (rc)
                return rc;
        }
    }
    for (int i = 0; i < base.count; i++) {
        if (!nbs_file_has_sym(base.n[i], sym)) {
            rc = nbs_add(&stale, base.n[i]);
            if (rc)
                return rc;
        }
    }
    if (newc.count == 0 && stale.count == 0) {
        if (fprintf(out,
                    "check_no_new_borrowed_seed: clean — %d grandfathered caller(s), no new ones\n",
                    base.count) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (newc.count) {
        if (fprintf(out,
                    "check_no_new_borrowed_seed: %d NEW caller(s) of the borrowed seed:\n",
                    newc.count) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < newc.count; i++) {
            if (fprintf(out, "  %s\n", newc.n[i]) < 0)
                return die("z23-lint: write failed\n", "");
        }
        if (fputc('\n', out) == EOF
            || fputs("Do NOT add a new coins_kv_seed_from_node_db caller — the borrow is being\n",
                     out) < 0
            || fputs("DELETED (the self-verified-tip cure). Self-derive the coin set (from the\n",
                     out) < 0
            || fputs("minted anchor snapshot / a from-genesis fold) instead. If a caller is\n",
                     out) < 0
            || fprintf(out,
                       "genuinely unavoidable for now, add its path to %s (last resort).\n",
                       k_nbs_base) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (stale.count) {
        if (fprintf(out,
                    "check_no_new_borrowed_seed: %d STALE baseline entry(ies) (no longer call it):\n",
                    stale.count) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < stale.count; i++) {
            if (fprintf(out, "  %s\n", stale.n[i]) < 0)
                return die("z23-lint: write failed\n", "");
        }
        if (fputc('\n', out) == EOF
            || fprintf(out,
                       "A caller was removed — good. Delete its line from %s so the\n",
                       k_nbs_base) < 0
            || fputs("ratchet reflects the smaller set.\n", out) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 1;
}

int check_no_new_borrowed_seed_run(int argc, char **argv)
{
    if (argc < 1 || !argv[0] || !argv[0][0])
        return nbs_scan(stdout);
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    if (chdir(argv[0]) != 0)
        return die("z23-lint: cannot scan %s\n", argv[0]);
    int rc = nbs_scan(stdout);
    if (chdir(cwd) != 0 && rc == 0)
        rc = die("z23-lint: getcwd failed\n", "");
    return rc;
}

static int nbs_st_excl(const char *path, int prod, int want)
{
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char saved[16];
    int had = 0;
    if (old) {
        if (ovf(snprintf(saved, sizeof saved, "%s", old), sizeof saved))
            return 1;
        had = 1;
    }
    int bad = 0;
    if (prod) {
        if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
            bad = 1;
    } else if (unsetenv("ZCL_LINT_PRODUCTION_SCAN") != 0)
        bad = 1;
    if (!bad)
        bad = lint_path_is_excluded(path) != want;
    if (had)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", saved, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    return bad;
}

int check_no_new_borrowed_seed_selftest(void)
{
    char sym[64];
    nbs_sym(sym, sizeof sym);
    char hit[128], miss[64];
    int bad = 0;
    if (ovf(snprintf(hit, sizeof hit, "int f%sint x) { return 0; }\n", sym),
            sizeof hit)
        || ovf(snprintf(miss, sizeof miss, "%s", "int g(void) { return 1; }\n"),
               sizeof miss))
        return 1;
    bad |= !nbs_text_has_sym(hit, sym);
    bad |= nbs_text_has_sym(miss, sym);
    static const char *const k_excl[] = {
        "tools/lint/fixtures/planted/x.c",
        "build/x.c",
        "vendor/x.c",
        "test-tmp/x.c",
        "engine/services/src/_xfixture.c"
    };
    for (size_t i = 0; i < sizeof k_excl / sizeof k_excl[0]; i++)
        bad |= nbs_st_excl(k_excl[i], 1, 1) | nbs_st_excl(k_excl[i], 0, 0);
    struct nbs_set base = {0}, callers = {0}, newc = {0}, stale = {0};
    bad |= nbs_add(&base, "in.c") || nbs_add(&base, "gone.c");
    bad |= nbs_add(&callers, "in.c") || nbs_add(&callers, "fresh.c");
    for (int i = 0; i < callers.count; i++) {
        if (!nbs_has(&base, callers.n[i]))
            bad |= nbs_add(&newc, callers.n[i]);
    }
    for (int i = 0; i < base.count; i++) {
        int exists = nbs_has(&callers, base.n[i]);
        if (!exists)
            bad |= nbs_add(&stale, base.n[i]);
    }
    bad |= newc.count != 1 || strcmp(newc.n[0], "fresh.c") != 0;
    bad |= stale.count != 1 || strcmp(stale.n[0], "gone.c") != 0;
    bad |= !nbs_has(&base, "in.c") || nbs_has(&base, "fresh.c");
    return st_ok(bad, "check_no_new_borrowed_seed selftest: OK\n");
}
