/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — guard-pairing pattern scans of the C23 lint
 * runtime (check-rpc-registrar, check-coins-lookup-nullcheck). Each gate
 * requires a risky bare call to be paired with, or replaced by, a
 * specific guard call.
 */

/*
 * Gates: check-rpc-registrar, check-coins-lookup-nullcheck
 * This family exists because gate_pattern_small.c and gate_ratchet_ports.c
 * are in concurrent flight (other lanes), and the remaining families are
 * each within ~350 lines of the 1500-line cap — too tight for two more
 * consumers. A future guard-pairing pattern scan joins this file while it
 * stays under the cap. Default landing spot otherwise: a filesystem-tree-
 * walking gate joins gate_tree_walk.c; a git-tracked-enumeration gate
 * joins whichever of gate_git_scan_a.c/gate_git_scan_b.c is smaller; a
 * proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static int pg_pref(const char *path, const char *pref)
{
    return strncmp(path, pref, strlen(pref)) == 0;
}

static int pg_ends(const char *path, const char *suf)
{
    size_t n = strlen(path), m = strlen(suf);
    return n >= m && memcmp(path + n - m, suf, m) == 0;
}

static int pg_is_ch(const char *path)
{
    return pg_ends(path, ".c") || pg_ends(path, ".h");
}

static int pg_copy(FILE *from, FILE *to)
{
    if (fseek(from, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, from)) >= 0) {
        if (fwrite(line, 1, (size_t)n, to) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(from);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int rpc_skip(const char *path)
{
    return strcmp(path, "engine/modules/rpc/src/server.c") == 0
        || strcmp(path, "engine/modules/rpc/include/rpc/server.h") == 0
        || pg_pref(path, "tests/harness/include/test/");
}

static int rpc_keep(const char *path)
{
    if (lint_path_is_excluded(path) || rpc_skip(path) || !pg_is_ch(path))
        return 0;
    return pg_pref(path, "lib/") || pg_pref(path, "app/")
        || pg_pref(path, "tools/") || pg_pref(path, "config/");
}

static int rpc_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "rpc_table_appe", "nd([^[:alnum:]_]|$)", "", "");
}

struct rpc_acc { regex_t *re; FILE *out; int hits; };

static int rpc_note(struct rpc_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(a->out, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

static int rpc_on_file(const char *path, void *ctx)
{
    return rpc_keep(path) ? rpc_note(ctx, path) : 0;
}

static int rpc_eval(FILE *out)
{
    regex_t re;
    int rc = rpc_comp(&re);
    if (rc)
        return rc;
    struct rpc_acc a = { .re = &re, .out = out };
    static const char *const roots[] = { "lib", "app", "tools", "config" };
    rc = each_zpath(k_ls_all, rpc_on_file, &a);
    if (rc != 0) {
        a.hits = 0;
        rc = 0;
        for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
            rc = walk_src(roots[i], 1, rpc_on_file, &a);
    }
    if (rc == 0 && a.hits) {
        if (fputs("\n"
                  "FAIL: rpc_table_appe" "nd() used outside engine/modules/rpc/src/server.c and tests/harness/include/test/.\n"
                  "      Use rpc_table_must_append() in every register_*_rpc_commands()\n"
                  "      callsite. See engine/modules/rpc/include/rpc/server.h for the contract.\n",
                  out) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            rc = 1;
    } else if (rc == 0) {
        if (fputs("  OK: all RPC registrar callsites use rpc_table_must_append\n",
                  out) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    regfree(&re);
    return rc;
}

int check_rpc_registrar_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return rpc_eval(stdout);
}

static int rpc_st_note(const char *text, int want_hits)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/z23-lint-rpc-note.c", td),
            sizeof path))
        return 1;
    if (csr_write(path, text))
        return 1;
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr) {
        (void)unlink(path);
        return 1;
    }
    FILE *out = tmpfile();
    if (!out) {
        regfree(&re);
        (void)unlink(path);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct rpc_acc a = { .re = &re, .out = out };
    int rc = rpc_note(&a, path);
    int bad = rc != 0 || a.hits != want_hits;
    fclose(out);
    regfree(&re);
    (void)unlink(path);
    return bad;
}

static int rpc_st_skip_scan(void)
{
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr)
        return 1;
    FILE *out = tmpfile();
    if (!out) {
        regfree(&re);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct rpc_acc a = { .re = &re, .out = out };
    int bad = rpc_on_file("engine/modules/rpc/src/server.c", &a) != 0
           || a.hits != 0
           || rpc_on_file("engine/modules/rpc/include/rpc/server.h", &a) != 0
           || a.hits != 0
           || rpc_on_file("tests/harness/include/test/x.h", &a) != 0
           || a.hits != 0;
    fclose(out);
    regfree(&re);
    return bad;
}

int check_rpc_registrar_selftest(void)
{
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr)
        return cr;
    const char *t = "check_rpc_registrar";
    int bad = want(t, &re, "    rpc_table_appe" "nd(&t, &c);", 1)
            | want(t, &re, "    rpc_table_must_append(&t, &c);", 0)
            | want(t, &re, "rpc_table_appe" "nd", 1)
            | want(t, &re, "rpc_table_appe" "nd_more(", 0);
    regfree(&re);
    bad |= !rpc_keep("lib/x.c") || !rpc_keep("app/x.h")
        || !rpc_keep("tools/x.c") || !rpc_keep("config/x.h")
        || rpc_keep("engine/modules/rpc/src/server.c")
        || rpc_keep("engine/modules/rpc/include/rpc/server.h")
        || rpc_keep("tests/harness/include/test/x.h")
        || rpc_keep("core/foo.c");
    bad |= rpc_st_skip_scan();
    bad |= rpc_st_note("    rpc_table_appe" "nd(&t, &c);\n", 1);
    bad |= rpc_st_note("    rpc_table_must_append(&t, &c);\n", 0);
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = rpc_eval(out);
    fclose(out);
    bad |= rc != 0;
    return st_ok(bad, "check_rpc_registrar selftest: OK\n");
}

static int cln_keep(const char *path, int env_mode)
{
    if (lint_path_is_excluded(path) || !pg_ends(path, ".c"))
        return 0;
    return env_mode || pg_pref(path, "engine/controllers/src/");
}

struct cln_acc {
    regex_t *lookup;
    regex_t *guard;
    FILE *miss;
    int nscan;
    int nhit;
    int nmiss;
    int env_mode;
};

static int cln_on_file(const char *path, void *ctx)
{
    struct cln_acc *a = ctx;
    if (!cln_keep(path, a->env_mode))
        return 0;
    a->nscan++;
    int nl = 0, ng = 0;
    int rc = scan_re(path, a->lookup, &nl, 0);
    if (rc)
        return rc;
    if (!nl)
        return 0;
    a->nhit++;
    rc = scan_re(path, a->guard, &ng, 0);
    if (rc)
        return rc;
    if (ng)
        return 0;
    a->nmiss++;
    if (fprintf(a->miss, "%s\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cln_report(struct cln_acc *a, const char *scan_dir, FILE *out)
{
    const char *dir = scan_dir ? scan_dir : "engine/controllers/src";
    char hint[4096];
    if (ovf(snprintf(hint, sizeof hint,
                     "no controller *.c files under '%s'", dir), sizeof hint))
        return 2;
    int rc = gate_require_scanned(a->nscan, 1, "check_coins_lookup_nullcheck",
                                  hint);
    if (rc)
        return rc;
    if (a->nmiss) {
        if (fputs("check_coins_lookup_nullcheck: missing rpc_require_chainstate_lookup_ready in:\n\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        rc = pg_copy(a->miss, out);
        return rc ? rc : 1;
    }
    rc = gate_require_scanned(a->nhit, 1, "check_coins_lookup_nullcheck",
            "no coins_view_cache_get_coins() call sites found; update this gate deliberately if the lookup API moved");
    if (rc)
        return rc;
    if (fprintf(out,
                "check_coins_lookup_nullcheck: clean — all controller coin lookups guarded (%d files)\n",
                a->nhit) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cln_eval(const char *scan_dir, FILE *out)
{
    regex_t lookup, guard;
    int rc = pair_comp(&lookup, REG_EXTENDED,
                       "coins_view_cache_get_coins[[:space:]]*\\(", "", "", "",
                       &guard, REG_EXTENDED,
                       "rpc_require_chainstate_lookup_ready[[:space:]]*\\(",
                       "", "", "");
    if (rc)
        return rc;
    FILE *miss = tmpfile();
    if (!miss) {
        drop2(&lookup, &guard);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct cln_acc a = {
        .lookup = &lookup, .guard = &guard, .miss = miss,
        .env_mode = scan_dir != NULL
    };
    if (scan_dir)
        rc = walk_src(scan_dir, 0, cln_on_file, &a);
    else {
        rc = each_zpath(k_ls_all, cln_on_file, &a);
        if (rc != 0) {
            a.nscan = 0;
            a.nhit = 0;
            a.nmiss = 0;
            a.env_mode = 1;
            if (psp_st_reset(a.miss))
                rc = die("z23-lint: fseek failed\n", "");
            else
                rc = walk_src("engine/controllers/src", 0, cln_on_file, &a);
        }
    }
    if (rc == 0)
        rc = cln_report(&a, scan_dir, out);
    fclose(miss);
    drop2(&lookup, &guard);
    return rc;
}

int check_coins_lookup_nullcheck_run(int argc, char **argv)
{
    const char *dir;
    (void)argc;
    (void)argv;
    dir = getenv("ZCL_COINS_LOOKUP_SCAN_DIR");
    return cln_eval((dir && dir[0]) ? dir : NULL, stdout);
}

static int cln_st_case(const char *root, const char *body, int want_rc)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/x.c", root), sizeof path))
        return 1;
    (void)unlink(path);
    if (body && csr_write(path, body))
        return 1;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = cln_eval(root, out);
    fclose(out);
    (void)unlink(path);
    return rc != want_rc;
}

int check_coins_lookup_nullcheck_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-cln.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = cln_st_case(tmp, NULL, 2);
    bad |= cln_st_case(tmp, "int x(void) { return 0; }\n", 2);
    bad |= cln_st_case(tmp,
                       "void f(void) { coins_view_cache_get_coins(c, id); }\n",
                       1);
    bad |= cln_st_case(tmp,
                       "void f(void) {\n"
                       "    rpc_require_chainstate_lookup_ready();\n"
                       "    coins_view_cache_get_coins(c, id);\n"
                       "}\n",
                       0);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_coins_lookup_nullcheck selftest: OK\n");
}
