/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-doc-accuracy (gate_doc_accuracy.c). Builds
 * a fixture tree under the scratch dir: a Makefile whose LINT_GATES lists
 * three gates, a DEFENSIVE_CODING.md with the marker block, and 60 filler
 * .md files so the prong-C scan-set floor holds. An empty .git directory
 * pins the find lane (git rev-parse fails there and prunes it), so the
 * selftest is deterministic regardless of what repo encloses the scratch
 * dir. Proves: clean pass, doc count mismatch, missing markers, stale
 * defensive-coding count, "3+ lint gates" with the exact count passing,
 * subset qualifier ("11 architecture gates") ignored, a missing Makefile
 * failing closed, and (in a second root without the fillers) a scan set
 * under the 50-file floor refused with rc 2.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_doc_accuracy_priv.h"

enum { DAS_PATH = 1024, DAS_TEXT = 4096, DAS_FILLERS = 60 };

static const char k_das_make[] =
    "LINT_GATES := check-alpha \\\n"
    "    check-beta \\\n"
    "    check-gamma\n"
    "lint: $(LINT_GATES)\n";

struct das_case {
    const char *name;
    const char *tokens; /* doc block tokens; NULL default (all three) */
    int markers;        /* 0 writes a doc with no marker block */
    const char *claim;  /* line written into docs/claims.md */
    int drop_make;      /* 1 deletes the fixture Makefile */
    int want;           /* expected return of da_check_root */
};

static const struct das_case k_das_cases[] = {
    { "clean fixture passes", NULL, 1, "", 0, 0 },
    { "doc count mismatch fails", "check-alpha\ncheck-beta", 1, "", 0, 1 },
    { "missing doc markers fails closed", NULL, 0, "", 0, 1 },
    { "stale defensive-coding count fails", NULL, 1,
      "We run 40 defensive-coding gates today.\n", 0, 1 },
    { "exact count with plus suffix passes", NULL, 1,
      "The repo has 3+ lint gates.\n", 0, 0 },
    { "subset qualifier ignored", NULL, 1,
      "11 architecture gates exist.\n", 0, 0 },
    /* The first match eats the "/"; the second search starts mid-line and must
     * not read its start as a line start (grep -o would not match it). */
    { "later match mid-line is not a line start", NULL, 1,
      "3 lint gates/40 lint gates\n", 0, 0 },
    { "missing Makefile fails closed", NULL, 1, "", 1, 1 },
};

static int das_write_make(const char *root)
{
    char path[DAS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    return csr_write(path, k_das_make);
}

static int das_write_doc(const char *root, const char *tokens, int markers)
{
    char path[DAS_PATH], text[DAS_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/docs/DEFENSIVE_CODING.md", root),
             sizeof path))
        return 2;
    int n;
    if (markers)
        n = snprintf(text, sizeof text, "# Defensive coding\n\n"
                     "<!-- LINT-GATES-BEGIN -->\n%s\n"
                     "<!-- LINT-GATES-END -->\n",
                     tokens ? tokens : "check-alpha\ncheck-beta\ncheck-gamma");
    else
        n = snprintf(text, sizeof text, "# Defensive coding\n"
                     "No marker block in this variant.\n");
    if (ovf(n, sizeof text))
        return 2;
    return csr_write(path, text);
}

static int das_write_claim(const char *root, const char *claim)
{
    char path[DAS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/docs/claims.md", root),
             sizeof path))
        return 2;
    return csr_write(path, claim[0] ? claim : "no claims here\n");
}

static int das_fillers(const char *root)
{
    for (int i = 0; i < DAS_FILLERS; i++) {
        char path[DAS_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/docs/fill/f%03d.md", root, i),
                 sizeof path))
            return 2;
        int rc = csr_write(path, "filler prose\n");
        if (rc)
            return rc;
    }
    return 0;
}

static int das_run_case(const char *root, const struct das_case *c)
{
    int rc = 0;
    char path[DAS_PATH];
    if (c->drop_make) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
            return 2;
        (void)unlink(path);
    } else {
        rc = das_write_make(root);
    }
    if (rc == 0)
        rc = das_write_doc(root, c->tokens, c->markers);
    if (rc == 0)
        rc = das_write_claim(root, c->claim);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = da_check_root(root, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr, "check_doc_accuracy selftest: %s: want rc=%d "
                "got rc=%d\n", c->name, c->want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

/* A scratch root with an empty .git (pins the find lane). */
static int das_root(char *root, const char *leaf)
{
    char gitdir[DAS_PATH];
    root[0] = '\0';
    int rc = lct_scratch_dir(root, DAS_PATH, leaf);
    if (rc) {
        root[0] = '\0'; /* nothing was created: callers skip cleanup */
        return rc;
    }
    if (ovf(snprintf(gitdir, sizeof gitdir, "%s/.git", root), sizeof gitdir))
        return 2;
    if (mkdir(gitdir, 0755) != 0) {
        fprintf(stderr, "check_doc_accuracy selftest: cannot mkdir %s\n",
                gitdir);
        return 2;
    }
    return 0;
}

/* Without the fillers the scan set is two docs: refused (rc 2), not clean. */
static int das_floor_case(void)
{
    static const struct das_case floor = {
        "scan set under the floor fails closed", NULL, 1, "", 0, 2 };
    char root[DAS_PATH] = "";
    int rc = das_root(root, "doc-accuracy-floor");
    if (rc == 0)
        rc = das_run_case(root, &floor);
    if (root[0])
        rap_rm_rf(root);
    return rc;
}

int check_doc_accuracy_selftest(void)
{
    char root[DAS_PATH] = "";
    int rc = das_root(root, "doc-accuracy");
    if (rc == 0)
        rc = das_fillers(root);
    if (rc) {
        if (root[0])
            rap_rm_rf(root);
        return rc;
    }
    int bad = 0;
    for (size_t i = 0; i < sizeof k_das_cases / sizeof k_das_cases[0]; i++)
        bad |= das_run_case(root, &k_das_cases[i]) != 0;
    if (root[0])
        rap_rm_rf(root);
    bad |= das_floor_case() != 0;
    if (bad)
        fputs("FAIL: check_doc_accuracy selftest\n", stderr);
    return st_ok(bad, "check_doc_accuracy selftest: OK\n");
}
