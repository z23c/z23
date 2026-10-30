/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest for check-fortify-masked-decls - writes scratch files
 * with a masked call, a guarded call and a commented-out call; checks verdicts. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

/* Exported by gate_fortify_masked_decls.c (opaque here). */
struct fmd_meas;
struct fmd_meas *fmd_meas_static(void);
int fmd_meas_create(const char *work, struct fmd_meas *m);
int fmd_meas_nmasked(const struct fmd_meas *m);
const char *fmd_meas_masked_first(const struct fmd_meas *m);
void fmd_meas_force_synthetic(struct fmd_meas *m);
void fmd_meas_masked_str(const struct fmd_meas *m, char *out, size_t cap);
int fmd_scan_file(const char *path, const struct fmd_meas *m, char *hits,
                  size_t cap);

enum { FMDS_PATH = 1024, FMDS_TEXT = 1024, FMDS_HITS = 512,
       FMDS_SET = 1024, FMDS_WHY = 256 };

static int fmds_fixture_root(char *out, size_t cap)
{
    return lint_mkdtemp(out, cap, "fmd-selftest");
}

static int fmds_write_cases(const char *root, const char *fn)
{
    char dir[FMDS_PATH], bad[FMDS_PATH], good[FMDS_PATH], com[FMDS_PATH];
    char t[FMDS_TEXT];
    if (ovf(snprintf(dir, sizeof dir, "%s/st", root), sizeof dir))
        return 2;
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    if (ovf(snprintf(bad, sizeof bad, "%s/st/bad.c", root), sizeof bad) ||
        ovf(snprintf(good, sizeof good, "%s/st/good.c", root), sizeof good) ||
        ovf(snprintf(com, sizeof com, "%s/st/comment.c", root),
            sizeof com))
        return 2;
    if (ovf(snprintf(t, sizeof t,
                     "#include <stdlib.h>\n"
                     "void f(void){ (void)%s(\"a\", 0); }\n", fn),
            sizeof t))
        return 2;
    rc = csr_write(bad, t);
    if (rc)
        return rc;
    if (ovf(snprintf(t, sizeof t,
                     "#if !defined(_DEFAULT_SOURCE)\n"
                     "#define _DEFAULT_SOURCE\n#endif\n"
                     "#include <stdlib.h>\n"
                     "void f(void){ (void)%s(\"a\", 0); }\n", fn),
            sizeof t))
        return 2;
    rc = csr_write(good, t);
    if (rc)
        return rc;
    if (ovf(snprintf(t, sizeof t,
                     "/* %s( is only named in prose here */\n"
                     "#include <stdlib.h>\nvoid f(void){}\n", fn),
            sizeof t))
        return 2;
    return csr_write(com, t);
}

/* Scans one fixture and expects a given verdict; on mismatch prints the
 * pre-formatted reason. Returns 0 as expected, 1 failed. */
static int fmds_check(const char *root, const char *leaf, int want,
                      const struct fmd_meas *m, const char *why)
{
    char path[FMDS_PATH], hits[FMDS_HITS];
    if (ovf(snprintf(path, sizeof path, "%s/st/%s", root, leaf),
            sizeof path)) {
        fprintf(stderr, "selftest: FAILED — %s\n", why);
        return 1;
    }
    if (fmd_scan_file(path, m, hits, sizeof hits) != want) {
        fprintf(stderr, "selftest: FAILED — %s\n", why);
        return 1;
    }
    return 0;
}

static int fmds_case_bad(const char *root, const struct fmd_meas *m,
                         const char *fn)
{
    char why[FMDS_WHY];
    snprintf(why, sizeof why, "unguarded caller of %s was not flagged", fn);
    return fmds_check(root, "bad.c", 1, m, why);
}

static int fmds_case_good(const char *root, const struct fmd_meas *m,
                          const char *fn)
{
    char why[FMDS_WHY];
    snprintf(why, sizeof why, "guarded caller of %s was flagged", fn);
    return fmds_check(root, "good.c", 0, m, why);
}

static int fmds_case_comment(const char *root, const struct fmd_meas *m,
                             const char *fn)
{
    char why[FMDS_WHY];
    snprintf(why, sizeof why, "a comment mentioning %s was flagged", fn);
    return fmds_check(root, "comment.c", 0, m, why);
}

int check_fortify_masked_decls_selftest(void)
{
    char root[FMDS_PATH];
    int rc = fmds_fixture_root(root, sizeof root);
    if (rc)
        return rc;
    struct fmd_meas *m = fmd_meas_static();
    rc = fmd_meas_create(root, m);
    if (rc) {
        rap_rm_rf(root);
        return die("z23-lint: check-fortify-masked-decls selftest cannot "
                   "measure the masked set\n", "");
    }
    if (fmd_meas_nmasked(m) == 0) {
        printf("check-fortify-masked-decls: selftest uses a synthetic masked "
               "name\n");
        fmd_meas_force_synthetic(m);
    }
    const char *fn = fmd_meas_masked_first(m);
    rc = fmds_write_cases(root, fn);
    if (rc) {
        rap_rm_rf(root);
        return rc;
    }
    int bad = fmds_case_bad(root, m, fn);
    if (!bad)
        bad = fmds_case_good(root, m, fn);
    if (!bad)
        bad = fmds_case_comment(root, m, fn);
    if (bad) {
        fputs("check-fortify-masked-decls: SELFTEST FAILED\n", stderr);
        rap_rm_rf(root);
        return 1;
    }
    char mset[FMDS_SET];
    fmd_meas_masked_str(m, mset, sizeof mset);
    printf("check-fortify-masked-decls: selftest PASSED (masked set measured "
           "as:%s)\n", mset);
    rap_rm_rf(root);
    return st_ok(0, "check-fortify-masked-decls selftest: OK\n");
}
