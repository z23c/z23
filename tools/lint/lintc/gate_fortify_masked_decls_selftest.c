/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-fortify-masked-decls
 * (gate_fortify_masked_decls.c). Measures the real masked set in a scratch
 * tree under $HOME/.local/state/zclassic23/scratch (never /tmp), falling
 * back to a synthetic masked name on hosts that truthfully measure none,
 * then proves the three --selftest cases of the shell original: an
 * unguarded caller of a masked function is flagged; a caller with the
 * feature-test guard before its first #include is not; a function named
 * only in a comment is not. Returns 0 only when every case answers as
 * expected.
 */
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
int fmd_meas_create(const char *work, struct fmd_meas **out);
void fmd_meas_free(struct fmd_meas *m);
int fmd_meas_nmasked(const struct fmd_meas *m);
const char *fmd_meas_masked_first(const struct fmd_meas *m);
void fmd_meas_force_synthetic(struct fmd_meas *m);
void fmd_meas_masked_str(const struct fmd_meas *m, char *out, size_t cap);
int fmd_scan_file(const char *path, const struct fmd_meas *m, char *hits,
                  size_t cap);

enum { FMDS_PATH = 1024, FMDS_TEXT = 1024, FMDS_HITS = 512,
       FMDS_SET = 1024 };

static int fmds_fixture_root(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place selftest scratch\n",
                   "");
    char base[FMDS_PATH];
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/fortify-masked-decls.XXXXXX", base), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
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

int check_fortify_masked_decls_selftest(void)
{
    char root[FMDS_PATH];
    int rc = fmds_fixture_root(root, sizeof root);
    if (rc)
        return rc;
    struct fmd_meas *m = NULL;
    rc = fmd_meas_create(root, &m);
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
        fmd_meas_free(m);
        rap_rm_rf(root);
        return rc;
    }
    int bad = 0;
    char path[FMDS_PATH], hits[FMDS_HITS];
    if (ovf(snprintf(path, sizeof path, "%s/st/bad.c", root), sizeof path))
        bad = 1;
    if (!bad && fmd_scan_file(path, m, hits, sizeof hits) != 1) {
        fprintf(stderr, "selftest: FAILED — unguarded caller of %s was not "
                "flagged\n", fn);
        bad = 1;
    }
    if (!bad && ovf(snprintf(path, sizeof path, "%s/st/good.c", root),
                    sizeof path))
        bad = 1;
    if (!bad && fmd_scan_file(path, m, hits, sizeof hits) != 0) {
        fprintf(stderr, "selftest: FAILED — guarded caller of %s was "
                "flagged\n", fn);
        bad = 1;
    }
    if (!bad && ovf(snprintf(path, sizeof path, "%s/st/comment.c", root),
                    sizeof path))
        bad = 1;
    if (!bad && fmd_scan_file(path, m, hits, sizeof hits) != 0) {
        fprintf(stderr, "selftest: FAILED — a comment mentioning %s was "
                "flagged\n", fn);
        bad = 1;
    }
    if (bad) {
        fputs("check-fortify-masked-decls: SELFTEST FAILED\n", stderr);
        fmd_meas_free(m);
        rap_rm_rf(root);
        return 1;
    }
    char mset[FMDS_SET];
    fmd_meas_masked_str(m, mset, sizeof mset);
    printf("check-fortify-masked-decls: selftest PASSED (masked set measured "
           "as:%s)\n", mset);
    fmd_meas_free(m);
    rap_rm_rf(root);
    return st_ok(0, "check-fortify-masked-decls selftest: OK\n");
}
