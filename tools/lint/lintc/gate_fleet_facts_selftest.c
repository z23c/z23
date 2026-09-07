/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-fleet-facts (gate_fleet_facts.c). Builds a
 * scratch fixture tree (no .git, so the ported term-tracked check exercises
 * its filesystem-fallback path) and drives check_fleet_facts_run() through
 * env-var overrides, the same knobs the shell original used. Output is
 * hushed by redirecting the real stdout/stderr file descriptors around each
 * sub-run; fflush() runs before the descriptors are restored.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

int check_fleet_facts_run(int argc, char **argv);

static int ffs_hushed(int argc, char **argv, int *rc)
{
    fflush(stdout);
    fflush(stderr);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0)
        return die("z23-lint: cannot open /dev/null\n", "");
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0)
        return die("z23-lint: dup failed\n", "");
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
    *rc = check_fleet_facts_run(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    return 0;
}

static const char k_head[] =
    "FLEET_RELATION(\"is_a\")\n"
    "FLEET_CONTEXT(\"doctrine\")\n"
    "FLEET_TERM(\"sonnet\")\n"
    "FLEET_TERM(\"executor\")\n";

static int ffs_write_stub(const char *stub, const char *extra_rows)
{
    char def[4096], doc[4096];
    if (ovf(snprintf(def, sizeof def, "%s/engine/composition/fleet_facts.def", stub),
            sizeof def)
        || ovf(snprintf(doc, sizeof doc, "%s/docs/agent/EXECUTOR_HEURISTICS.md", stub),
              sizeof doc))
        return 2;
    char body[8192];
    if (ovf(snprintf(body, sizeof body, "%s%s\n", k_head, extra_rows), sizeof body))
        return 2;
    if (csr_write(def, body)) return 2;
    if (access(doc, F_OK) != 0
        && csr_write(doc, "<!-- FLEET-FACTS-ROUTING-BEGIN -->\n"
                          "<!-- FLEET-FACTS-ROUTING-END -->\n"))
        return 2;
    return 0;
}

static int ffs_run_stub(const char *stub, const char *row)
{
    if (setenv("ZCL_FLEET_FACTS_ROOT", stub, 1)
        || setenv("ZCL_FLEET_FACTS_FLOOR", "1", 1))
        return die("z23-lint: setenv failed\n", "");
    if (ffs_write_stub(stub, row)) return 2;
    /* Rewrite the doc block from whatever the table says first, so the case
     * under test always exercises the row rules, never the doc mismatch. */
    int rc = 0;
    char *wd[] = { (char *)"--write-doc", NULL };
    return ffs_hushed(1, wd, &rc);
}

static int ffs_expect(const char *stub, const char *label, int want_pass,
                      const char *row, int *fails)
{
    if (ffs_run_stub(stub, row)) return 2;
    int rc = 0;
    if (ffs_hushed(0, NULL, &rc)) return 2;
    int got_pass = rc == 0;
    if (got_pass != want_pass) {
        fprintf(stderr, "check_fleet_facts: SELFTEST FAILED — %s (got rc=%d)\n",
               label, rc);
        (*fails)++;
    } else {
        printf("  selftest ok: %s\n", label);
    }
    return 0;
}

static int ffs_row_checks(const char *stub, int *fails)
{
    const char *good = "FLEET_FACT(\"sonnet\", \"is_a\", \"executor\", \"doctrine\", "
                       "\"DOCTRINE\", \"a\")\n";
    if (ffs_expect(stub, "a row whose term, relation and context are declared",
                   1, good, fails))
        return 2;
    if (ffs_expect(stub, "an object no term declares", 0,
                   "FLEET_FACT(\"sonnet\", \"is_a\", \"wizard\", \"doctrine\", "
                   "\"DOCTRINE\", \"a\")\n", fails))
        return 2;
    if (ffs_expect(stub, "a relation the table does not declare", 0,
                   "FLEET_FACT(\"sonnet\", \"eats\", \"executor\", \"doctrine\", "
                   "\"DOCTRINE\", \"a\")\n", fails))
        return 2;
    if (ffs_expect(stub, "a confidence of UNKNOWN", 0,
                   "FLEET_FACT(\"sonnet\", \"is_a\", \"executor\", \"doctrine\", "
                   "\"UNKNOWN\", \"a\")\n", fails))
        return 2;
    char dup[512];
    if (ovf(snprintf(dup, sizeof dup, "%s%s", good, good), sizeof dup)) return 2;
    if (ffs_expect(stub, "a duplicated row", 0, dup, fails)) return 2;
    if (ffs_expect(stub, "an empty why", 0,
                   "FLEET_FACT(\"sonnet\", \"is_a\", \"executor\", \"doctrine\", "
                   "\"DOCTRINE\", \"\")\n", fails))
        return 2;
    if (ffs_expect(stub, "a declared term no row uses", 0,
                   "FLEET_FACT(\"sonnet\", \"is_a\", \"sonnet\", \"doctrine\", "
                   "\"DOCTRINE\", \"a\")\n", fails))
        return 2;
    return 0;
}

static int ffs_missing_table(const char *stub, int *fails)
{
    if (setenv("ZCL_FLEET_FACTS_ROOT", stub, 1)
        || setenv("ZCL_FLEET_FACTS_DEF", "missing.def", 1)
        || setenv("ZCL_FLEET_FACTS_FLOOR", "1", 1))
        return die("z23-lint: setenv failed\n", "");
    int rc = 0;
    if (ffs_hushed(0, NULL, &rc)) return 2;
    unsetenv("ZCL_FLEET_FACTS_DEF");
    if (rc != 2) {
        fprintf(stderr,
               "check_fleet_facts: SELFTEST FAILED — a missing table did not "
               "exit 2 (rc=%d)\n", rc);
        (*fails)++;
    } else {
        printf("  selftest ok: a missing table exits 2\n");
    }
    return 0;
}

int check_fleet_facts_selftest(void)
{
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-ff.XXXXXX", env_or("TMPDIR", "/tmp")),
            sizeof tmpl))
        return 2;
    char *stub = mkdtemp(tmpl);
    if (!stub)
        return die("z23-lint: mkdir failed: %s\n", tmpl);
    int fails = 0, rc = 0;
    rc = ffs_row_checks(stub, &fails);
    if (rc == 0) rc = ffs_missing_table(stub, &fails);
    unsetenv("ZCL_FLEET_FACTS_ROOT");
    unsetenv("ZCL_FLEET_FACTS_FLOOR");
    rap_rm_rf(stub);
    if (rc) return rc;
    if (fails) return 1;
    printf("[check_fleet_facts] SELFTEST PASS (undeclared object, undeclared "
          "relation, UNKNOWN confidence, duplicate row, empty why and unused "
          "term all fail; a resolving row passes; a missing table exits 2)\n");
    return 0;
}
