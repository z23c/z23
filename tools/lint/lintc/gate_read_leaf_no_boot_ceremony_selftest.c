/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-read-leaf-no-boot-ceremony. Builds a
 * fixture tree (one .def leaf declaration, one corpus .c) under a
 * mkdtemp scratch dir and drives the analysis core directly (def parser,
 * function indexer, taint verdict) — no git needed. Cases: clean passes;
 * a direct banned call fails; an indirect call through a helper fails;
 * a banned name only inside a comment passes; a baseline entry
 * grandfathers a violation; a stale baseline entry fails; an unresolved
 * handler is noted, not gated; macro arity drift aborts LOUD.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_read_leaf_no_boot_ceremony_priv.h"

enum { X_PATH = 1024, X_TEXT = 4096 };

static struct rlb_readset x_rs;
static struct rlb_fnidx x_fi;
static struct rlb_fatalset x_fs;

struct x_case {
    const char *name;
    const char *handler;  /* handler body statement, or NULL for fx_missing */
    const char *helper;   /* helper body statement */
    const char *baseline; /* baseline text, or NULL for no baseline file */
    int want;
};

static const struct x_case k_cases[] = {
    { "clean fixture passes", "return 0;", "return 0;", NULL, 0 },
    { "direct node_db_open call fails", "return node_db_open(0);", "return 0;",
      NULL, 1 },
    { "indirect create_schema via helper fails", "return fx_helper();",
      "return create_schema(0);", NULL, 1 },
    { "banned token only in a comment passes",
      "return 0; /* node_db_open( is prose */", "return 0;", NULL, 0 },
    { "baseline entry grandfathers a violation", "return node_db_open(0);",
      "return 0;", "app.fixture node_db_open", 0 },
    { "stale baseline entry fails", "return 0;", "return 0;",
      "app.other create_schema", 1 },
    { "unresolved handler is noted, not gated", NULL, "return 0;", NULL, 0 },
};

static int x_root(char *out, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(out, cap, "%s/z23-lint-rlnbc.XXXXXX", td), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

static int x_write_def(const char *root, const char *handler, int zeros)
{
    char dir[X_PATH], path[X_PATH], text[X_TEXT];
    if (ovf(snprintf(dir, sizeof dir, "%s/defs", root), sizeof dir))
        return 2;
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/defs/leaves.def", root),
            sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "ZCL_COMMAND_READY_READ(\"app.fixture\"%s%s)\n",
                     zeros == 20 ? ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
                                 : ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0",
                     zeros == 20 ? handler : (zeros == 19 ? ",fx_handler" : "")),
            sizeof text))
        return 2;
    return csr_write(path, text);
}

static int x_write_src(const char *root, const char *handler_stmt,
                       const char *helper_stmt)
{
    char dir[X_PATH], path[X_PATH], text[X_TEXT];
    if (ovf(snprintf(dir, sizeof dir, "%s/src", root), sizeof dir))
        return 2;
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/src/fixture.c", root), sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "int fx_helper(void)\n"
                     "{\n"
                     "    %s\n"
                     "}\n"
                     "int fx_handler(void)\n"
                     "{\n"
                     "    %s\n"
                     "}\n",
                     helper_stmt, handler_stmt), sizeof text))
        return 2;
    return csr_write(path, text);
}

static int x_run_case(const char *root, const struct x_case *c)
{
    memset(&x_rs, 0, sizeof x_rs);
    x_fi.n = 0;
    x_fi.ndef = 0;
    x_fi.pool_n = 0;
    memset(&x_fs, 0, sizeof x_fs);
    int rc = x_write_def(root, c->handler ? ",fx_handler" : ",fx_missing", 20);
    if (rc)
        return rc;
    rc = x_write_src(root, c->handler ? c->handler : "return 0;", c->helper);
    if (rc)
        return rc;
    char base[X_PATH];
    const char *bpath;
    if (c->baseline) {
        if (ovf(snprintf(base, sizeof base, "%s/base.txt", root), sizeof base))
            return 2;
        rc = csr_write(base, c->baseline);
        if (rc)
            return rc;
        bpath = base;
    } else {
        if (ovf(snprintf(base, sizeof base, "%s/no-base.txt", root),
                sizeof base))
            return 2;
        bpath = base;
    }
    int nleaf = 0, ndefs = 0;
    rc = rlb_parse_defs(root, "defs", &x_rs, &nleaf, &ndefs, &x_fs);
    if (rc)
        return rc;
    if (x_fs.n)
        return rlb_def_fatal_report(&x_fs);
    const char *paths[] = { "src/fixture.c" };
    rc = rlb_index_paths(root, paths, 1, &x_fi);
    if (rc)
        return rc;
    char sinkp[X_PATH];
    if (ovf(snprintf(sinkp, sizeof sinkp, "%s/verdict.out", root), sizeof sinkp))
        return 2;
    FILE *sink = fopen(sinkp, "w");
    if (!sink)
        return die("z23-lint: cannot open selftest verdict sink\n", "");
    struct rlb_counts cnt;
    int got = rlb_verdict(&x_rs, &x_fi, bpath, bpath, &cnt, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr,
                "check-read-leaf-no-boot-ceremony selftest: %s: want rc=%d"
                " got rc=%d\n",
                c->name, c->want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

static int x_drift_case(const char *root)
{
    memset(&x_rs, 0, sizeof x_rs);
    memset(&x_fs, 0, sizeof x_fs);
    int rc = x_write_def(root, "", 19);
    if (rc)
        return rc;
    int nleaf = 0, ndefs = 0;
    rc = rlb_parse_defs(root, "defs", &x_rs, &nleaf, &ndefs, &x_fs);
    if (rc)
        return rc;
    if (x_fs.n == 0) {
        fprintf(stderr, "check-read-leaf-no-boot-ceremony selftest: arity"
                " drift was not reported\n");
        return 1;
    }
    printf("  selftest ok: arity drift aborts loud (rc=2)\n");
    return 0;
}

int check_read_leaf_no_boot_ceremony_selftest(void)
{
    char root[X_PATH];
    int rc = x_root(root, sizeof root);
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_cases / sizeof k_cases[0]; i++)
        bad |= x_run_case(root, &k_cases[i]) != 0;
    bad |= x_drift_case(root) != 0;
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check-read-leaf-no-boot-ceremony selftest\n", stderr);
    return st_ok(bad, "check-read-leaf-no-boot-ceremony selftest: OK\n");
}
