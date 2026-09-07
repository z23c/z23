/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-model-sql-literals (gate_model_sql_literals.c).
 * Plants each violation shape (SELECT/INSERT/UPDATE/DELETE literals, a split
 * literal, a stale baseline row, a regression) and each innocent shape
 * (lowercase identifier, continuation fragment, documentation comment, a
 * builder caller, the builder itself) in a scratch fixture tree, and proves
 * an empty scan set fails loud. Output is captured by redirecting the real
 * stdout/stderr file descriptors to a temp file around each sub-run;
 * fflush() runs before the descriptors are restored.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

int check_model_sql_literals_run(int argc, char **argv);

enum { MSLS_OUT = 65536 };

static int msls_capture(char *buf, size_t cap, int *rc)
{
    fflush(stdout);
    fflush(stderr);
    FILE *tf = tmpfile();
    if (!tf)
        return die("z23-lint: tmpfile failed\n", "");
    int tfd = fileno(tf);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0)
        return die("z23-lint: dup failed\n", "");
    dup2(tfd, STDOUT_FILENO);
    dup2(tfd, STDERR_FILENO);
    *rc = check_model_sql_literals_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    int sr = csr_slurp(tf, buf, cap);
    fclose(tf);
    return sr;
}

struct msls_env { const char *root; const char *base; };

static int msls_run(const struct msls_env *e, char *buf, size_t cap, int *rc)
{
    if (setenv("ZCL_MODEL_SQL_SCAN_ROOT", e->root, 1)
        || setenv("ZCL_MODEL_SQL_BASELINE", e->base, 1)
        || setenv("ZCL_MODEL_SQL_FILE_FLOOR", "1", 1)
        || setenv("ZCL_LINT_MODE", "FAIL", 1))
        return die("z23-lint: setenv failed\n", "");
    return msls_capture(buf, cap, rc);
}

/* want: 1 = expect a rejection (rc != 0), 0 = expect a PASS (rc == 0).
 * needle (may be NULL/empty) must appear in the captured output. */
static int msls_expect(const struct msls_env *e, const char *label, int want,
                       const char *needle, int *fails)
{
    static char buf[MSLS_OUT];
    int rc = 0;
    if (msls_run(e, buf, sizeof buf, &rc))
        return 2;
    int got = rc != 0;
    if (got != want) {
        fprintf(stderr,
               "check_model_sql_literals: SELFTEST FAILED — %s (rc=%d)\n",
               label, rc);
        (*fails)++;
        return 0;
    }
    if (needle && needle[0] && strstr(buf, needle) == NULL) {
        fprintf(stderr,
               "check_model_sql_literals: SELFTEST FAILED — %s (never named "
               "'%s')\n", label, needle);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok: %s\n", label);
    return 0;
}

static int msls_plant(const char *root, const char *name, const char *body)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/src/%s", root, name), sizeof path))
        return 2;
    return csr_write(path, body);
}

static int msls_unplant(const char *root, const char *name)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/src/%s", root, name), sizeof path))
        return 2;
    unlink(path);
    return 0;
}

static int msls_truncate(const char *base)
{ return csr_write(base, ""); }

static int msls_negative_controls(const struct msls_env *e, int *fails)
{
    int rc = msls_truncate(e->base);
    if (rc) return rc;
    if ((rc = msls_plant(e->root, "offender.c",
                         "static const char *k = \"SELECT id FROM peers "
                         "WHERE ip=?\";\n")))
        return rc;
    if ((rc = msls_expect(e, "an unbaselined SELECT literal is caught", 1,
                          "offender.c", fails)))
        return rc;
    if ((rc = msls_plant(e->root, "offender.c",
                         "bool save(void) { return exec(\"INSERT INTO peers "
                         "(ip) VALUES (?)\"); }\n")))
        return rc;
    if ((rc = msls_expect(e, "an INSERT literal is caught", 1, "offender.c",
                          fails)))
        return rc;
    if ((rc = msls_plant(e->root, "offender.c",
                         "bool bump(void) { return exec(\"UPDATE peers SET "
                         "a=a+1 WHERE ip=?\"); }\n")))
        return rc;
    if ((rc = msls_expect(e, "an UPDATE literal is caught", 1, "offender.c",
                          fails)))
        return rc;
    if ((rc = msls_plant(e->root, "offender.c",
                         "bool reap(void) { return exec(\"DELETE FROM peers "
                         "WHERE id<?\"); }\n")))
        return rc;
    return msls_expect(e, "a DELETE literal is caught", 1, "offender.c",
                       fails);
}

static int msls_split_literal(const struct msls_env *e, int *fails)
{
    int rc = msls_plant(e->root, "offender.c",
                        "static const char *k =\n"
                        "    \"SELECT a,b,c\"\n"
                        "    \" FROM peers WHERE ip=?\";\n");
    if (rc) return rc;
    return msls_expect(e, "a statement split across adjacent literals is "
                          "caught", 1, "offender.c", fails);
}

static int msls_ratchet(const struct msls_env *e, int *fails)
{
    int rc = msls_plant(e->root, "offender.c",
                        "static const char *k = \"SELECT id FROM peers\";\n");
    if (rc) return rc;
    char path[4096], row[4200];
    if (ovf(snprintf(path, sizeof path, "%s/src/offender.c", e->root),
            sizeof path)
        || ovf(snprintf(row, sizeof row, "%s\n", path), sizeof row))
        return 2;
    if ((rc = csr_write(e->base, row)))
        return rc;
    return msls_expect(e, "a baselined file is tolerated (ratchet, not a "
                          "hard ban)", 0, "", fails);
}

static int msls_stale(const struct msls_env *e, int *fails)
{
    int rc = msls_plant(e->root, "offender.c",
                        "static int clean(void) { return 0; }\n");
    if (rc) return rc;
    return msls_expect(e, "a baseline row whose file is now clean is caught "
                          "as STALE", 1, "STALE", fails);
}

static int msls_regression(const struct msls_env *e, int *fails)
{
    char path[4096], row[4200];
    if (ovf(snprintf(path, sizeof path, "%s/src/other.c", e->root),
            sizeof path)
        || ovf(snprintf(row, sizeof row, "%s\n", path), sizeof row))
        return 2;
    int rc = csr_write(e->base, row);
    if (rc) return rc;
    if ((rc = msls_plant(e->root, "other.c",
                         "static const char *k = \"SELECT 1 FROM peers\";\n")))
        return rc;
    if ((rc = msls_plant(e->root, "converted.c",
                         "static const char *k = \"SELECT id FROM peers "
                         "WHERE ip=?\";\n")))
        return rc;
    if ((rc = msls_expect(e, "a converted file that regresses to literal "
                             "SQL is caught", 1, "converted.c", fails)))
        return rc;
    return msls_unplant(e->root, "converted.c");
}

static int msls_positive_controls(const struct msls_env *e, int *fails)
{
    int rc = msls_truncate(e->base);
    if (rc) return rc;
    (void)msls_unplant(e->root, "offender.c");
    (void)msls_unplant(e->root, "other.c");
    if ((rc = msls_plant(e->root, "innocent.c",
                         "bool f(void) { return log(\"update_tree: invalid "
                         "args\"); }\n")))
        return rc;
    if ((rc = msls_expect(e, "a lowercase identifier that merely starts "
                             "with a keyword", 0, "", fails)))
        return rc;

    if ((rc = msls_plant(e->root, "innocent.c",
                         "static const char *k = \" FROM peers WHERE "
                         "ip=?\";\n")))
        return rc;
    if ((rc = msls_expect(e, "a continuation fragment with no opening "
                             "keyword", 0, "", fails)))
        return rc;

    if ((rc = msls_plant(e->root, "innocent.c",
                         "/* Example: AR_PREPARE(ndb, s, \"SELECT id FROM "
                         "peers\"); */\nbool f(void) { return true; }\n")))
        return rc;
    if ((rc = msls_expect(e, "a SELECT shown in a documentation comment, "
                             "not carried", 0, "", fails)))
        return rc;

    if ((rc = msls_plant(e->root, "innocent.c",
                         "/* static const char *k = \"SELECT id FROM "
                         "peers\"; */\n")))
        return rc;
    if ((rc = msls_expect(e, "a SQL example inside a C comment", 0, "",
                          fails)))
        return rc;
    return 0;
}

static int msls_comment_opener_and_builder(const struct msls_env *e,
                                           int *fails)
{
    int rc = msls_plant(e->root, "innocent.c",
                        "static const char *a = \"x /* y\";\n"
                        "static const char *k = \"SELECT id FROM peers\";\n");
    if (rc) return rc;
    if ((rc = msls_expect(e, "a comment opener inside a literal cannot "
                             "blind the scan", 1, "innocent.c", fails)))
        return rc;

    if ((rc = msls_plant(e->root, "innocent.c",
                         "void f(struct qb *q) { qb_select(q, QB_T_peers); "
                         "}\n")))
        return rc;
    if ((rc = msls_expect(e, "a file that uses the query builder", 0, "",
                          fails)))
        return rc;

    char qb[4096];
    if (ovf(snprintf(qb, sizeof qb, "%s/src/query_builder.c", e->root),
            sizeof qb))
        return 2;
    if ((rc = csr_write(qb, "void e(struct qb *q){ qb_puts(q, \"INSERT "
                            "INTO \"); }\n")))
        return rc;
    if ((rc = msls_expect(e, "the query builder itself is not flagged for "
                             "its own keywords", 0, "", fails)))
        return rc;
    unlink(qb);
    return 0;
}

static int msls_hollow_scan(const char *empty_root, const char *base,
                            int *fails)
{
    if (setenv("ZCL_MODEL_SQL_SCAN_ROOT", empty_root, 1)
        || setenv("ZCL_MODEL_SQL_BASELINE", base, 1)
        || setenv("ZCL_MODEL_SQL_FILE_FLOOR", "1", 1)
        || setenv("ZCL_LINT_MODE", "FAIL", 1))
        return die("z23-lint: setenv failed\n", "");
    static char buf[MSLS_OUT];
    int rc = 0;
    if (msls_capture(buf, sizeof buf, &rc))
        return 2;
    if (rc != 2) {
        fprintf(stderr, "check_model_sql_literals: SELFTEST FAILED — an "
               "empty scan set did not exit 2 (rc=%d)\n", rc);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok: an empty scan set fails LOUD (exit 2), never "
          "clean\n");
    return 0;
}

static int msls_mkdir(const char *path)
{
    return mkdir(path, 0700) != 0
        ? die("z23-lint: mkdir failed: %s\n", path) : 0;
}

static int msls_setup(const char *tmp, char *models, size_t mcap, char *base,
                      size_t bcap, char *empty, size_t ecap)
{
    if (ovf(snprintf(models, mcap, "%s/models", tmp), mcap)
        || ovf(snprintf(base, bcap, "%s/baseline.txt", tmp), bcap)
        || ovf(snprintf(empty, ecap, "%s/empty", tmp), ecap))
        return 2;
    int rc = msls_mkdir(models);
    if (rc) return rc;
    char srcdir[4200];
    if (ovf(snprintf(srcdir, sizeof srcdir, "%s/src", models), sizeof srcdir))
        return 2;
    rc = msls_mkdir(srcdir);
    if (rc) return rc;
    rc = msls_mkdir(empty);
    if (rc) return rc;
    return csr_write(base, "");
}

static int msls_run_cases(const struct msls_env *e, const char *empty,
                          const char *base, int *fails)
{
    int rc = msls_negative_controls(e, fails);
    if (rc == 0) rc = msls_split_literal(e, fails);
    if (rc == 0) rc = msls_ratchet(e, fails);
    if (rc == 0) rc = msls_stale(e, fails);
    if (rc == 0) rc = msls_regression(e, fails);
    if (rc == 0) rc = msls_positive_controls(e, fails);
    if (rc == 0) rc = msls_comment_opener_and_builder(e, fails);
    if (rc == 0) rc = msls_hollow_scan(empty, base, fails);
    return rc;
}

int check_model_sql_literals_selftest(void)
{
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl,
                     "build/z23-lint-msl-selftest.XXXXXX"), sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", tmpl);

    char models[4096], base[4096], empty[4096];
    int rc = msls_setup(tmp, models, sizeof models, base, sizeof base,
                        empty, sizeof empty);
    int fails = 0;
    if (rc == 0) {
        struct msls_env e = { .root = models, .base = base };
        rc = msls_run_cases(&e, empty, base, &fails);
    }

    unsetenv("ZCL_MODEL_SQL_SCAN_ROOT");
    unsetenv("ZCL_MODEL_SQL_BASELINE");
    unsetenv("ZCL_MODEL_SQL_FILE_FLOOR");
    unsetenv("ZCL_LINT_MODE");
    rap_rm_rf(tmp);
    if (rc)
        return rc;
    if (fails)
        return 1;
    return st_ok(0,
        "[check_model_sql_literals] SELFTEST PASS (SELECT/INSERT/UPDATE/"
        "DELETE/split literals fail; baselined tolerated; stale row and "
        "regression fail; lowercase token, continuation fragment, "
        "commented SQL, builder caller and the builder itself pass; "
        "hollow scan exits 2)\n");
}
