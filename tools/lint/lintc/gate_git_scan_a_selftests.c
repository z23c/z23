/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: planted-violation selftest for check-equihash-params, split out
 * of gate_git_scan_a.c to keep that file under the family line-count
 * ceiling. The two files share the gate's regex/scan internals through
 * gate_git_scan_a_priv.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_git_scan_a_priv.h"

static int eqp_build_paths(char *p_build, size_t bsz, char *p_skill, size_t ssz,
    char *p_disp, size_t dsz)
{
    if (ovf(snprintf(p_build, bsz, "build/x.%s", "md"), bsz)
        || ovf(snprintf(p_skill, ssz, ".claude/skills/w.%s", "md"), ssz)
        || ovf(snprintf(p_disp, dsz, "docs/PLANTED.%s", "md"), dsz))
        return 2;
    return 0;
}

static int eqp_path_filter_bad(const char *p_build, const char *p_skill)
{
    return eqp_keep_path(p_build) | eqp_keep_path("vendor/y.c")
        | eqp_keep_path(".claude/worktrees/z.h")
        | !eqp_keep_path(p_skill)
        | eqp_keep_path("docs/EQUIHASH_PARAMS.md")
        | eqp_keep_path("tools/equihash_params_fact.c")
        | eqp_keep_path("foo.py") | !eqp_keep_path("foo.def");
}

static int eqp_case_flat_claim(const char *work, const char *p_disp, regex_t *lit,
    regex_t *claim, regex_t *qual, int *bad)
{
    char planted[4096], line[96];
    if (ovf(snprintf(planted, sizeof planted, "%s/%s", work, p_disp), sizeof planted)
        || snprintf(line, sizeof line, "ZClassic is Equi%s 200,9 and always will be.\n",
                    "hash") >= (int)sizeof line || csr_write(planted, line))
        return 2;
    int nlines = 0, hits = 0;
    int rc = eqp_load(planted, &nlines);
    if (rc == 0) rc = eqp_scan_lines(p_disp, nlines, lit, claim, qual, NULL, &hits);
    if (rc || hits == 0) {
        fputs("check_equihash_params selftest: planted flat claim not detected\n", stderr);
        *bad = 1;
    }
    return 0;
}

static int eqp_case_qualified(const char *work, const char *p_disp, regex_t *lit,
    regex_t *claim, regex_t *qual, int *bad)
{
    char planted[4096];
    if (ovf(snprintf(planted, sizeof planted, "%s/%s", work, p_disp), sizeof planted))
        return 2;
    if (csr_write(planted,
                  "Mainnet is 192,7 from the Bubbles height; 200,9 applies before it.\n"))
        return 2;
    int nlines = 0, hits = 0;
    int rc = eqp_load(planted, &nlines);
    if (rc == 0) rc = eqp_scan_lines(p_disp, nlines, lit, claim, qual, NULL, &hits);
    if (rc || hits != 0) {
        fputs("check_equihash_params selftest: qualified sentence was reported\n", stderr);
        *bad = 1;
    }
    return 0;
}

int check_equihash_params_selftest(void)
{
    regex_t lit, claim, qual;
    int rc = eqp_comp(&lit, &claim, &qual);
    if (rc) return rc;
    char p_build[16], p_skill[32], p_disp[24];
    if (eqp_build_paths(p_build, sizeof p_build, p_skill, sizeof p_skill, p_disp, sizeof p_disp)) {
        drop3(&lit, &claim, &qual);
        return 2;
    }
    int bad = eqp_path_filter_bad(p_build, p_skill);
    if (bad) fputs("check_equihash_params selftest: path filter failed\n", stderr);

    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-eqparams-st.XXXXXX", td), sizeof tmpl)) {
        drop3(&lit, &claim, &qual);
        return 2;
    }
    char *work = mkdtemp(tmpl);
    if (!work) {
        drop3(&lit, &claim, &qual);
        return die("z23-lint: mkdir failed: %s\n", td);
    }

    int frc = eqp_case_flat_claim(work, p_disp, &lit, &claim, &qual, &bad);
    if (frc == 0)
        frc = eqp_case_qualified(work, p_disp, &lit, &claim, &qual, &bad);
    (void)rap_rm_rf(work);
    drop3(&lit, &claim, &qual);
    if (frc)
        return frc;
    return st_ok(bad, "check_equihash_params selftest: OK\n");
}
