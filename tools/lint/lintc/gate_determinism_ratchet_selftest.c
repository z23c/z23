/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-determinism-ratchet
 * (gate_determinism_ratchet.c). Each case plants ONE defect in a throwaway
 * REAL git fixture under $HOME/.local/state/zclassic23/scratch (never /tmp)
 * and asserts the gate rejects it AND names the offender; the last positive
 * controls assert a clean and a shrunk fixture pass, so an unconditionally
 * failing gate could not sneak through. Prong A needs a real git history,
 * so the fixture is a real git repo.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_determinism_ratchet_priv.h"

enum { DTS_PATH = 1024, DTS_TEXT = 4096, DTS_OUT = 8192 };

static const char k_dts_catalog[] =
    "ZCL_TEST_GROUP(alpha)\nZCL_TEST_GROUP(bravo)\nZCL_SPEC_GROUP(charlie)\n";
static const char k_dts_pert_hdr[] =
    "enum zcl_det_perturbation {\n"
    "    ZCL_DET_P_BASE,\n"
    "    ZCL_DET_P_CC_SET,\n"
    "    ZCL_DET_P_ENV_PAD,\n"
    "    ZCL_DET_P__COUNT\n"
    "};\n";
static const char k_dts_base[] =
    "# fixture baseline\n# count: 1\ntest_alpha NONDETERMINISTIC CC_SET\n";

static int dts_git(const char *d, char *const args[], size_t nargs)
{
    char *argv[16];
    size_t n = 0;
    argv[n++] = (char *)"git";
    argv[n++] = (char *)"-C";
    argv[n++] = (char *)d;
    for (size_t i = 0; i < nargs && n + 1 < sizeof argv / sizeof argv[0];
         i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    char scrap[256];
    int st;
    if (dtr_run("git", argv, scrap, sizeof scrap, &st) != 0 || st != 0)
        return die("z23-lint: git fixture command failed in %s\n", d);
    return 0;
}

static int dts_make_fixture(const char *d)
{
    char p[DTS_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/tools/lint", d), sizeof p))
        return 2;
    int rc = csr_mkdirs(p);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/tools/dev", d), sizeof p))
        return 2;
    rc = csr_mkdirs(p);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p,
                     "%s/engine/modules/determinism/include/determinism", d),
            sizeof p))
        return 2;
    rc = csr_mkdirs(p);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, k_dtr_catalog_rel), sizeof p))
        return 2;
    rc = csr_write(p, k_dts_catalog);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p,
                     "%s/engine/modules/determinism/include/determinism/"
                     "perturbation.h", d), sizeof p))
        return 2;
    rc = csr_write(p, k_dts_pert_hdr);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, k_dtr_baseline_rel), sizeof p))
        return 2;
    rc = csr_write(p, k_dts_base);
    if (rc)
        return rc;
    char *init[] = { (char *)"init", (char *)"-q" };
    rc = dts_git(d, init, 2);
    if (rc)
        return rc;
    char *add[] = { (char *)"-c", (char *)"user.email=fixture@example.invalid",
                    (char *)"-c", (char *)"user.name=fixture",
                    (char *)"add", (char *)"-A" };
    rc = dts_git(d, add, 6);
    if (rc)
        return rc;
    char *commit[] = { (char *)"-c",
                       (char *)"user.email=fixture@example.invalid",
                       (char *)"-c", (char *)"user.name=fixture",
                       (char *)"commit", (char *)"-q", (char *)"-m",
                       (char *)"fixture baseline" };
    return dts_git(d, commit, 8);
}

static int dts_write_baseline(const char *d, const char *const *lines,
                              int nlines)
{
    char p[DTS_PATH], text[DTS_TEXT];
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, k_dtr_baseline_rel), sizeof p))
        return 2;
    size_t len = 0;
    for (int i = 0; i < nlines; i++) {
        int w = snprintf(text + len, sizeof text - len, "%s\n", lines[i]);
        if (ovf(w, (int)(sizeof text - len)))
            return 2;
        len += (size_t)w;
    }
    return csr_write(p, text);
}

static void dts_show(const char *buf)
{
    const char *p = buf;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        printf("    %.*s\n", (int)n, p);
        if (!e)
            break;
        p = e + 1;
    }
}

struct dts_case {
    const char *tag;
    const char *label;
    const char *needle;
    const char *const *lines;
    int nlines;
    int drop_base;
    int empty_cat;
    int reject;
};

static const char *const k_a[] = { "# count: 2",
    "test_alpha NONDETERMINISTIC CC_SET",
    "test_bravo TIMING_SENSITIVE ENV_PAD" };
static const char *const k_b[] = { "# count: 1", "test_alpha" };
static const char *const k_c[] = { "# count: 1",
    "test_ghost NONDETERMINISTIC CC_SET" };
static const char *const k_d[] = { "# count: 1",
    "test_alpha NONDETERMINISTIC VIBES" };
static const char *const k_e[] = { "# count: 7",
    "test_alpha NONDETERMINISTIC CC_SET" };
static const char *const k_i[] = { "# count: 0" };
static const char *const k_j[] = { "# count: 1",
    "test_alpha FLAKY CC_SET" };
static const char *const k_k[] = { "# count: 1",
    "test_alpha NONDETERMINISTIC" };

static const struct dts_case k_cases[] = {
    { "a", "A: a baseline that grew is caught", "test_bravo", k_a, 3, 0, 0, 1 },
    { "b", "B: a row naming no perturbation is caught",
      "name no splitting perturbation", k_b, 2, 0, 0, 1 },
    { "c", "C: a row naming an unregistered group is caught", "test_ghost",
      k_c, 2, 0, 0, 1 },
    { "d", "D: a row naming an unknown perturbation is caught", "VIBES",
      k_d, 2, 0, 0, 1 },
    { "e", "E: a count header that disagrees with the rows is caught",
      "declares", k_e, 2, 0, 0, 1 },
    { "f", "F: a missing baseline fails closed",
      "no readable determinism baseline", NULL, 0, 1, 0, 1 },
    { "g", "G: an empty registry fails closed", "no registered groups",
      NULL, 0, 0, 1, 1 },
    { "h", "H: an unchanged, well-formed baseline passes", NULL, NULL, 0, 0,
      0, 0 },
    { "i", "I: shrinking the baseline to empty passes", NULL, k_i, 1, 0, 0, 0 },
    { "j", "J: a row naming an unrecorded class is caught", "FLAKY",
      k_j, 2, 0, 0, 1 },
    { "k", "K: a row with a class but no perturbation is caught",
      "name no splitting perturbation", k_k, 2, 0, 0, 1 },
};

static int dts_verdict(const struct dts_case *c, int rc, const char *out)
{
    if (c->reject) {
        if (rc == 0) {
            printf("SELFTEST FAIL: %s — expected rejection, got a PASS.\n",
                   c->label);
            dts_show(out);
            return 1;
        }
        if (c->needle && !strstr(out, c->needle)) {
            printf("SELFTEST FAIL: %s — rejected, but never named '%s'.\n"
                   "  A gate that fails without naming the offender is "
                   "unactionable.\n", c->label, c->needle);
            dts_show(out);
            return 1;
        }
    } else if (rc != 0) {
        printf("SELFTEST FAIL: %s — expected a PASS, got rejection.\n",
               c->label);
        dts_show(out);
        return 1;
    }
    printf("  selftest ok: %s\n", c->label);
    return 0;
}

static int dts_case(const char *root, const struct dts_case *c)
{
    char d[DTS_PATH], p[DTS_PATH];
    if (ovf(snprintf(d, sizeof d, "%s/%s", root, c->tag), sizeof d))
        return 2;
    int rc = dts_make_fixture(d);
    if (rc)
        return rc;
    if (c->nlines) {
        rc = dts_write_baseline(d, c->lines, c->nlines);
        if (rc)
            return rc;
    }
    if (c->drop_base || c->empty_cat) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", d, c->drop_base
                         ? k_dtr_baseline_rel : k_dtr_catalog_rel), sizeof p))
            return 2;
        if (c->drop_base) {
            if (unlink(p) != 0)
                return die("z23-lint: cannot remove fixture %s\n", p);
        } else {
            rc = csr_write(p, "");
            if (rc)
                return rc;
        }
    }
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = dtr_check_root(d, sink);
    static char out[DTS_OUT];
    rewind(sink);
    size_t m = fread(out, 1, sizeof out - 1, sink);
    out[m] = '\0';
    fclose(sink);
    return dts_verdict(c, got, out);
}

static int dts_scratch(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place selftest scratch\n",
                   "");
    char base[DTS_PATH];
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/determinism-ratchet-selftest.XXXXXX",
                     base), (int)cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

int check_determinism_ratchet_selftest(void)
{
    char root[DTS_PATH];
    int rc = dts_scratch(root, sizeof root);
    if (rc)
        return rc;
    printf("══ check-determinism-ratchet selftest ══\n");
    int bad = 0;
    for (size_t i = 0; i < sizeof k_cases / sizeof k_cases[0]; i++)
        bad |= dts_case(root, &k_cases[i]) != 0;
    rap_rm_rf(root);
    if (bad)
        printf("══ selftest: FAIL ══\n");
    else
        printf("══ selftest: PASS (11/11) ══\n");
    return bad ? 1 : 0;
}
