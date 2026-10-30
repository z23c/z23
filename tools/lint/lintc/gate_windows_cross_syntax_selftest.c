/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-windows-cross-syntax
 * (gate_windows_cross_syntax.c). Two halves, graded together because
 * everything else is hollow if a stale cached verdict can replay:
 *   1. the flag-set probes — a Windows-only undeclared identifier must
 *      trip, clean and test-compat TUs must pass, and a crashed compiler
 *      backend must classify as COMPILER_FAILURE;
 *   2. the per-TU result cache soundness proofs, ported from
 *      tu_cache_selftest in tools/lint/tu_result_cache.sh (deleted), over
 *      16 synthetic TUs plus one real TU with the gate's real compiler.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_windows_cross_syntax_priv.h"

enum { SFP = 1024, SFL = 4096 };

static const char k_stub_body[] =
    "#!/usr/bin/env bash\n"
    "set -uo pipefail\n"
    "if [ \"${1:-}\" = \"--version\" ]; then echo \"tu-cache stub compiler "
    "1.0\"; exit 0; fi\n"
    "src=\"${!#}\"\n"
    "echo x >> \"$ZCL_TU_STUB_RUNS\"\n"
    "case \"$src\" in\n"
    "    *u7.c)\n"
    "        printf '%s\\n' \"$src:1:1: error: stub planted rejection\" >&2\n"
    "        exit 1\n"
    "        ;;\n"
    "esac\n"
    "exit 0\n";

static int sf_fail(const char *msg)
{
    printf("FAIL: --self-test — tu-cache: %s\n", msg);
    return 1;
}

static int copy_one(const char *from, const char *to)
{
    FILE *i = fopen(from, "rb");
    if (!i) return -1;
    FILE *o = fopen(to, "wb");
    if (!o) { fclose(i); return -1; }
    static char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, i)) > 0) fwrite(buf, 1, n, o);
    fclose(i);
    fclose(o);
    return 0;
}

static int files_equal(const char *a, const char *b)
{
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    if (sa.st_size != sb.st_size) return 0;
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return 0; }
    static char ba[4096], bb[4096];
    int same = 1;
    for (;;) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0) { same = 0; break; }
        if (na == 0) break;
    }
    fclose(fa);
    fclose(fb);
    return same;
}

static int count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    static char line[SFL];
    int n = 0;
    while (fgets(line, sizeof line, f)) n++;
    fclose(f);
    return n;
}

/* dst = dir + leaf, failing closed (-1) when it does not fit. */
static int sjoin(char *dst, size_t cap, const char *dir, const char *leaf)
{
    return ovf(snprintf(dst, cap, "%s%s", dir, leaf), cap) ? -1 : 0;
}

static int flat_paths(const char *out_dir, const char *src, char *log,
                      size_t lcap, char *rc, size_t rcap)
{
    char k[SFP];
    size_t o = 0;
    for (const char *p = src; *p && o + 1 < sizeof k; p++)
        k[o++] = isalnum((unsigned char)*p) ? *p : '_';
    k[o] = '\0';
    if (ovf(snprintf(log, lcap, "%s/%s.log", out_dir, k), lcap) ||
        ovf(snprintf(rc, rcap, "%s/%s.rc", out_dir, k), rcap))
        return -1;
    return 0;
}

static int read_flags_nul(const char *flags_nul, char flags[][WCS_FLAGLEN],
                          int *nf, int max)
{
    FILE *ff = fopen(flags_nul, "rb");
    if (!ff) return -1;
    static char word[WCS_FLAGLEN];
    size_t w = 0;
    int c;
    *nf = 0;
    while ((c = fgetc(ff)) != EOF) {
        if (c == 0) {
            if (w && *nf < max) { word[w] = '\0';
                memcpy(flags[(*nf)++], word, w + 1); }
            w = 0;
        } else if (w + 1 < sizeof word) word[w++] = (char)c;
    }
    fclose(ff);
    return 0;
}

static int run_misses(const char *miss_list, const char *out_dir,
                      const char *cc, const char *flags_nul)
{
    static char flags[64][WCS_FLAGLEN];
    int nf = 0;
    if (read_flags_nul(flags_nul, flags, &nf, 64) != 0) return -1;
    FILE *mf = fopen(miss_list, "r");
    if (!mf) return -1;
    static char src[SFP];
    while (fgets(src, sizeof src, mf)) {
        size_t l = strlen(src);
        if (l && src[l - 1] == '\n') src[--l] = '\0';
        if (!l) continue;
        char log[SFP], rc[SFP];
        if (flat_paths(out_dir, src, log, sizeof log, rc, sizeof rc)) return -1;
        static char *cargv[70];
        int na = 0;
        cargv[na++] = (char *)cc;
        for (int i = 0; i < nf; i++) cargv[na++] = flags[i];
        cargv[na++] = src;
        cargv[na] = NULL;
        wcs_cache_compile(log, rc, cc, cargv, src);
    }
    fclose(mf);
    return 0;
}

/* One synthetic sweep: setup with a private cachedir, plan, compile the
 * misses serially with the stub. */
static int sweep_once(const char *base, const char *stub, const char *root,
                      const char *flags, const char *srclist, int check_on)
{
    char miss[SFP], cd[SFP], outdir[SFP];
    if (ovf(snprintf(miss, sizeof miss, "%s/miss.txt", base), sizeof miss) ||
        ovf(snprintf(cd, sizeof cd, "%s/cachedir", base), sizeof cd) ||
        ovf(snprintf(outdir, sizeof outdir, "%s/out", base), sizeof outdir))
        return -1;
    if (csr_mkdirs(outdir) != 0) return -1;
    wcs_cache_setup("tu-cache-selftest", stub, stub, flags, base, root, cd);
    if (check_on && !wcs_cache_on())
        return sf_fail("the cache refused to enable on a synthetic root");
    if (wcs_cache_plan(srclist, miss, outdir, 1) != 0) return -1;
    if (run_misses(miss, outdir, stub, flags) != 0) return -1;
    return 0;
}

static int sweep_expect(const char *base, const char *stub, const char *root,
                        const char *flags, const char *srclist, int eh,
                        int em, int es)
{
    if (sweep_once(base, stub, root, flags, srclist, 1) != 0) return -1;
    int h, m, s;
    wcs_cache_counts(&h, &m, &s);
    if (h != eh || m != em || s != es) {
        char msg[SFL];
        if (ovf(snprintf(msg, sizeof msg,
                         "a run over synthetic TUs reported '%d' hit / '%d' "
                         "miss / '%d' stored, wanted %d/%d/%d",
                         h, m, s, eh, em, es), sizeof msg))
            return -1;
        return sf_fail(msg);
    }
    return 0;
}

static int write_unit(const char *root, int i)
{
    char p[SFP], text[512];
    if (ovf(snprintf(p, sizeof p, "%s/src/u%d.c", root, i), sizeof p))
        return -1;
    if (ovf(snprintf(text, sizeof text,
                     "#include \"shared.h\"\nint unit_%d(void);\n", i),
             sizeof text))
        return -1;
    return csr_write(p, text);
}

static int bf_units(const char *root, const char *srclist)
{
    FILE *sl = fopen(srclist, "w");
    if (!sl) return -1;
    for (int i = 0; i < 16; i++) {
        char path[SFP];
        if (ovf(snprintf(path, sizeof path, "%s/src/u%d.c", root, i),
                sizeof path) || write_unit(root, i) != 0) {
            fclose(sl);
            return -1;
        }
        fprintf(sl, "%s\n", path);
    }
    fclose(sl);
    return 0;
}

static int bf_includes(const char *root)
{
    char p[SFP], u0[SFP], text[SFL];
    if (sjoin(p, sizeof p, root, "/src/shared.h")) return 2;
    if (csr_write(p, "#define TU_SELFTEST_SHARED 1\n") != 0) return -1;
    if (sjoin(u0, sizeof u0, root, "/src/u0.c")) return 2;
    if (ovf(snprintf(text, sizeof text,
                     "#include \"shared.h\"\nint unit_0(void);\n"
                     "#include \"bare.c\"\n#include \"nested/qualified.c\"\n"
                     "#include \"nested/regex[1].c\"\n"), sizeof text))
        return -1;
    if (csr_write(u0, text) != 0) return -1;
    const char *const inc[] = { "bare.c", "nested/qualified.c",
                                "nested/regex[1].c", NULL };
    for (int i = 0; inc[i]; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/src/%s", root, inc[i]), sizeof p))
            return -1;
        if (csr_write(p, "/* included body */\n") != 0) return -1;
    }
    return 0;
}

static int build_fixture(const char *base, const char *root, char *srclist)
{
    char p[SFP];
    if (csr_mkdirs(root) != 0 || csr_mkdirs(base) != 0) return -1;
    if (sjoin(p, sizeof p, root, "/src/nested")) return 2;
    if (csr_mkdirs(p) != 0) return -1;
    if (sjoin(srclist, SFP, base, "/srcs.txt")) return -1;
    if (bf_units(root, srclist) != 0) return -1;
    return bf_includes(root);
}

struct cold_art {
    char u7l[SFP * 2], u7r[SFP * 2], cl[SFP], cr[SFP];
};

/* Copy the cold run's u7 artifacts aside and prove the planted unit failed. */
static int record_cold(const char *base, const char *root, struct cold_art *a)
{
    char cold[SFP], u7p[SFP];
    if (sjoin(u7p, sizeof u7p, root, "/src/u7.c")) return 2;
    if (sjoin(cold, sizeof cold, base, "/cold-out")) return 2;
    csr_mkdirs(cold);
    if (flat_paths(cold, u7p, a->cl, sizeof a->cl, a->cr, sizeof a->cr)) return 2;
    char outd[SFP];
    if (sjoin(outd, sizeof outd, base, "/out")) return 2;
    if (flat_paths(outd, u7p, a->u7l, sizeof a->u7l, a->u7r, sizeof a->u7r))
        return 2;
    copy_one(a->u7l, a->cl);
    copy_one(a->u7r, a->cr);
    if (!files_equal(a->u7r, a->cr) || !files_equal(a->cl, a->u7l))
        return sf_fail("cold artifact copy failed");
    FILE *ck = fopen(a->cr, "r");
    static char ln[32];
    int ok = ck && fgets(ln, sizeof ln, ck) && strcmp(ln, "1\n") == 0;
    if (ck) fclose(ck);
    if (!ok)
        return sf_fail("the planted failing unit did not fail on the cold "
                       "run");
    return 0;
}

/* Editing any included C body must invalidate every TU. */
static int include_edit_loop(const char *base, const char *root,
                             const char *srclist, const char *stub,
                             const char *flags)
{
    static const char *const inc[] = { "bare.c", "nested/qualified.c",
                                       "nested/regex[1].c", NULL };
    char p[SFP];
    for (int i = 0; inc[i]; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/src/%s", root, inc[i]), sizeof p)) return 2;
        if (csr_write(p, "/* changed included body */\n") != 0) return 2;
        if (sweep_expect(base, stub, root, flags, srclist, 0, 16, 16) != 0)
            return 1;
    }
    return 0;
}

/* Cold sweep over the synthetic tree, then the artifacts recorded aside. */
static int cps_cold(const char *base, const char *root, const char *srclist,
                    const char *stub, const char *flags,
                    struct cold_art *a)
{
    char miss[SFP];
    int rc = sweep_expect(base, stub, root, flags, srclist, 0, 16, 16);
    if (rc) return rc;
    if (sjoin(miss, sizeof miss, base, "/miss.txt")) return 2;
    if (count_lines(miss) != 16)
        return sf_fail("checksum mode markers changed the cold compiler "
                       "source paths");
    return record_cold(base, root, a);
}

/* Warm sweeps: all 16 hit, no compiler launch, artifacts unchanged. */
static int cps_warm(const char *base, const char *root, const char *srclist,
                    const char *stub, const char *flags, const char *runs,
                    const struct cold_art *a)
{
    int before = count_lines(runs);
    int rc = sweep_expect(base, stub, root, flags, srclist, 16, 0, 0);
    if (rc) return rc;
    if (count_lines(runs) != before)
        return sf_fail("a warm run still invoked the compiler");
    if (!files_equal(a->u7l, a->cl) || !files_equal(a->u7r, a->cr))
        return sf_fail("a replayed artifact differs from the cold artifact");
    return sweep_expect(base, stub, root, flags, srclist, 16, 0, 0);
}

/* Source edits: the included bodies, shared.h, and one TU's body. */
static int cps_edits(const char *base, const char *root, const char *srclist,
                     const char *stub, const char *flags)
{
    char p[SFP], sh[SFP];
    if (sjoin(sh, sizeof sh, root, "/src/shared.h")) return 2;
    int rc = include_edit_loop(base, root, srclist, stub, flags);
    if (rc) return rc;
    if (csr_write(sh, "#define TU_SELFTEST_SHARED 2\n") != 0) return 2;
    rc = sweep_expect(base, stub, root, flags, srclist, 0, 16, 16);
    if (rc) return rc;
    if (sjoin(p, sizeof p, root, "/src/u3.c")) return 2;
    if (csr_write(p, "#include \"shared.h\"\nint unit_3(int);\n") != 0)
        return 2;
    rc = sweep_expect(base, stub, root, flags, srclist, 15, 1, 1);
    if (rc) return rc;
    if (csr_write(p, "#include \"shared.h\"\nint unit_3(void);\n") != 0)
        return 2;
    return sweep_expect(base, stub, root, flags, srclist, 16, 0, 0);
}

/* (1)-(6) over the synthetic tree; helper keeps the caller small. */
static int cache_proofs_synthetic(const char *base, const char *root,
                                  const char *srclist, const char *stub,
                                  const char *flags, const char *runs)
{
    static struct cold_art a;
    int rc = cps_cold(base, root, srclist, stub, flags, &a);
    if (rc) return rc;
    rc = cps_warm(base, root, srclist, stub, flags, runs, &a);
    if (rc) return rc;
    return cps_edits(base, root, srclist, stub, flags);
}

static int cache_proof_disabled(const char *base, const char *root,
                                const char *srclist, const char *stub,
                                const char *flags, const char *runs)
{
    char cdoff[SFP], miss[SFP], outdir[SFP];
    if (sjoin(cdoff, sizeof cdoff, base, "/cachedir-off")) return 2;
    if (sjoin(miss, sizeof miss, base, "/miss-off.txt")) return 2;
    if (sjoin(outdir, sizeof outdir, base, "/out")) return 2;
    setenv("ZCL_TU_CACHE_SELFTEST_FORCE", "0", 1);
    setenv("ZCL_LINT_TU_CACHE", "0", 1);
    wcs_cache_setup("tu-cache-selftest", stub, stub, flags, base, root, cdoff);
    setenv("ZCL_TU_CACHE_SELFTEST_FORCE", "1", 1);
    unsetenv("ZCL_LINT_TU_CACHE");
    if (wcs_cache_on())
        return sf_fail("ZCL_LINT_TU_CACHE=0 did not disable the cache");
    if (wcs_cache_plan(srclist, miss, outdir, 1) != 0) return 2;
    if (count_lines(miss) != 16)
        return sf_fail("a disabled cache did not send every TU to the "
                       "compiler");
    int before = count_lines(runs);
    char log[SFP], rc[SFP], src[SFP];
    char *cargv[4] = { (char *)stub, (char *)"-c", NULL, NULL };
    if (sjoin(src, sizeof src, root, "/src/u0.c")) return 2;
    cargv[2] = src;
    if (flat_paths(outdir, src, log, sizeof log, rc, sizeof rc)) return 2;
    wcs_cache_compile(log, rc, stub, cargv, src);
    if (count_lines(runs) == before)
        return sf_fail("a disabled cache did not invoke the compiler");
    struct stat st;
    if (stat(cdoff, &st) == 0)
        return sf_fail("a disabled cache still opened a cache directory");
    return 0;
}

struct cpr {
    char rdir[SFP], srclist[SFP], miss[SFP], outdir[SFP], cd[SFP];
    char coldl[SFP * 2], coldr[SFP * 2], log[SFP * 2], rc[SFP * 2];
};

static int cpr_paths(const char *base, struct cpr *s)
{
    if (sjoin(s->rdir, sizeof s->rdir, base, "/real") ||
        sjoin(s->srclist, sizeof s->srclist, s->rdir, "/srcs.txt") ||
        sjoin(s->miss, sizeof s->miss, s->rdir, "/miss.txt") ||
        sjoin(s->outdir, sizeof s->outdir, s->rdir, "/out") ||
        sjoin(s->cd, sizeof s->cd, s->rdir, "/cachedir"))
        return 2;
    return 0;
}

/* 0 when the real configuration enables the cache; a failure otherwise. */
static int cpr_enable(const char *gate_src, const char *cc,
                      const char *flags_nul, struct cpr *s)
{
    csr_mkdirs(s->outdir);
    wcs_cache_setup("check-windows-cross-syntax", gate_src, cc, flags_nul,
                    s->rdir, ".", s->cd);
    if (wcs_cache_on()) return 0;
    char why[SFL];
    if (ovf(snprintf(why, sizeof why,
                     "the real gate configuration disabled the cache (%s)",
                     wcs_cache_off_reason()), sizeof why))
        return 2;
    return sf_fail(why);
}

/* Compile the real TU cold through the cache and keep its artifacts. */
static int cpr_cold(const char *cc, const char *flags_nul,
                    const char *real_src, struct cpr *s)
{
    FILE *f = fopen(s->srclist, "w");
    if (!f) return 2;
    fprintf(f, "%s\n", real_src);
    fclose(f);
    if (wcs_cache_plan(s->srclist, s->miss, s->outdir, 1) != 0) return 2;
    if (count_lines(s->miss) != 1)
        return sf_fail("a fresh generation served the real source without "
                       "ever compiling it");
    if (flat_paths(s->outdir, real_src, s->log, sizeof s->log, s->rc,
                   sizeof s->rc))
        return 2;
    static char flags[256][WCS_FLAGLEN];
    int nf = 0;
    if (read_flags_nul(flags_nul, flags, &nf, 256) != 0) return 2;
    static char *cargv[WCS_ARGS];
    int na = 0;
    cargv[na++] = (char *)cc;
    for (int i = 0; i < nf; i++) cargv[na++] = flags[i];
    cargv[na++] = (char *)real_src;
    cargv[na] = NULL;
    wcs_cache_compile(s->log, s->rc, cc, cargv, real_src);
    if (sjoin(s->coldl, sizeof s->coldl, s->rdir, "/cold.log") ||
        sjoin(s->coldr, sizeof s->coldr, s->rdir, "/cold.rc"))
        return 2;
    copy_one(s->log, s->coldl);
    copy_one(s->rc, s->coldr);
    remove(s->log);
    remove(s->rc);
    return 0;
}

/* Replay from the stored result: no compile, byte-identical artifacts. */
static int cpr_replay(struct cpr *s)
{
    if (sjoin(s->miss, sizeof s->miss, s->rdir, "/miss2.txt"))
        return 2;
    if (wcs_cache_plan(s->srclist, s->miss, s->outdir, 1) != 0) return 2;
    if (count_lines(s->miss) != 0)
        return sf_fail("the real compiler's stored result did not replay");
    if (!files_equal(s->coldl, s->log))
        return sf_fail("the real compiler's replayed log differs from its "
                       "cold log");
    if (!files_equal(s->coldr, s->rc))
        return sf_fail("the real compiler's replayed status differs from "
                       "its cold status");
    return 0;
}

static int cache_proof_real(const char *gate_src, const char *cc,
                            const char *flags_nul, const char *base,
                            const char *real_src)
{
    static struct cpr s;
    int rc = cpr_paths(base, &s);
    if (rc) return rc;
    rc = cpr_enable(gate_src, cc, flags_nul, &s);
    if (rc) return rc;
    rc = cpr_cold(cc, flags_nul, real_src, &s);
    if (rc) return rc;
    return cpr_replay(&s);
}

static int cache_selftest(const char *cc, const char *flags_nul,
                          const char *scratch, const char *real_src)
{
    static char base[SFP], root[SFP], srclist[SFP], stub[SFP];
    static char flags[SFP], runs[SFP];
    struct stat st;
    if (stat(real_src, &st) != 0) {
        char why[SFL];
        if (ovf(snprintf(why, sizeof why,
                         "no real source was handed to the wiring proof "
                         "(got '%s'); the gate's scan set is empty or moved",
                         real_src), sizeof why))
            return 2;
        return sf_fail(why);
    }
    if (sjoin(base, sizeof base, scratch, "/tu-cache-selftest")) return 2;
    if (sjoin(root, sizeof root, base, "/root")) return 2;
    if (sjoin(stub, sizeof stub, base, "/stub_cc.sh")) return 2;
    if (sjoin(flags, sizeof flags, base, "/flags.nul")) return 2;
    if (sjoin(runs, sizeof runs, base, "/runs")) return 2;
    rap_rm_rf(base);
    if (build_fixture(base, root, srclist) != 0) return 2;
    if (csr_write(stub, k_stub_body) != 0) return 2;
    chmod(stub, 0755);
    setenv("ZCL_TU_STUB_RUNS", runs, 1);
    FILE *rf = fopen(runs, "w");
    if (!rf) return 2;
    fclose(rf);
    FILE *ff = fopen(flags, "wb");
    if (!ff) return 2;
    fprintf(ff, "-c%c", '\0');
    fclose(ff);
    setenv("ZCL_TU_CACHE_SELFTEST_FORCE", "1", 1);
    int rc = cache_proofs_synthetic(base, root, srclist, stub, flags, runs);
    if (rc == 0)
        rc = cache_proof_disabled(base, root, srclist, stub, flags, runs);
    if (rc == 0)
        rc = cache_proof_real(
            "tools/lint/lintc/gate_windows_cross_syntax.c", cc, flags_nul,
            base, real_src);
    unsetenv("ZCL_TU_STUB_RUNS");
    unsetenv("ZCL_TU_CACHE_SELFTEST_FORCE");
    rap_rm_rf(base);
    if (rc) return rc;
    printf("  OK: --self-test — tu-cache over 16 synthetic TUs at 4 "
           "workers:\n"
           "      two consecutive runs on an unchanged tree are 100%% hit "
           "and\n      byte-identical (a third too), header/included-C "
           "edits bust all 16, a\n      .c edit busts exactly 1 and "
           "reverting it hits again, a stored\n      FAIL replays as FAIL, "
           "ZCL_LINT_TU_CACHE=0 stores none, and\n"
           "      %s replays a real TU byte-for-byte\n", cc);
    return 0;
}

/* ── the flag-set probes (first phase of the script's self-test) ────── */

static int probe_files(char *violating, char *clean, char *compat,
                       size_t cap)
{
    if (ovf(snprintf(violating, cap, "%s/violating.c", g_wcs_work), cap) ||
        ovf(snprintf(clean, cap, "%s/clean.c", g_wcs_work), cap) ||
        ovf(snprintf(compat, cap, "%s/test_compat.c", g_wcs_work), cap))
        return 2;
    if (csr_write(violating,
                  "#if defined(_WIN32)\n"
                  "int zcl_gate_wincross_probe(void) { return "
                  "this_identifier_does_not_exist; }\n"
                  "#else\n"
                  "int zcl_gate_wincross_probe(void) { return 0; }\n"
                  "#endif\n") != 0)
        return 2;
    if (csr_write(clean, "int zcl_gate_wincross_clean(int a);\n"
                  "int zcl_gate_wincross_clean(int a) { return a + 1; }\n")
        != 0)
        return 2;
    return csr_write(compat,
                     "#include <fcntl.h>\n"
                     "#include <sys/stat.h>\n"
                     "int zcl_gate_wincross_test_compat(void)\n"
                     "{\n"
                     "zcl_win_suppress_abort_dialog();\n"
                     "return mkdir(\"fixture\", 0700) + O_CLOEXEC;\n"
                     "}\n");
}

static int build_argv(char *argv[], int max, const char *tail1,
                      const char *tail2, const char *src)
{
    int n = 0;
    argv[n++] = g_wcs_cc;
    for (int i = 0; i < g_wcs_nflag && n < max - 4; i++)
        argv[n++] = g_wcs_flag[i];
    if (tail1) argv[n++] = (char *)tail1;
    if (tail2) argv[n++] = (char *)tail2;
    argv[n++] = (char *)src;
    argv[n] = NULL;
    return 0;
}

/* A located diagnostic must keep its own class; a hollow classifier that
 * sends every diagnostic to COMPILER_FAILURE would turn real Windows syntax
 * errors and skippable missing headers into infrastructure failures. */
static int located_classifier_probes(void)
{
    static const struct { const char *log, *want; } k[] = {
        { "x.c:1:2: error: unknown type name 'foo'\n", "ERROR" },
        { "x.c:7: error: expected ';'\n", "ERROR" },
        { "x.c:3:10: fatal error: command/native_command.h: "
          "No such file or directory\n", "SKIP_GENERATED" },
        { "x.c:3:10: fatal error: openssl/evp.h: "
          "No such file or directory\n", "SKIP_OPENSSL" },
        { "x.c:3:10: fatal error: command/native_command.h: "
          "No such file or directory\n"
          "y.c:4:1: fatal error: openssl/evp.h: "
          "No such file or directory\n", "SKIP_HEADERS" },
        { "gcc: fatal error: no input files\n", "COMPILER_FAILURE" },
    };
    static char path[SFP];
    char kind[40];
    if (ovf(snprintf(path, sizeof path, "%s/located-compiler.log",
                     g_wcs_work), sizeof path))
        return 2;
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        if (csr_write(path, k[i].log) != 0) return 2;
        if (wcs_compile_kind(path, "1", kind, sizeof kind) != 0) return 2;
        if (strcmp(kind, k[i].want) != 0) {
            printf("FAIL: --self-test — located diagnostic probe %zu was "
                   "classified '%s', expected '%s'.\n", i, kind, k[i].want);
            return 1;
        }
    }
    return 0;
}

static int fake_classifier_probes(void)
{
    static char fake[SFP], mixed[SFP];
    char kind[40];
    if (ovf(snprintf(fake, sizeof fake, "%s/fake-compiler.log", g_wcs_work),
            sizeof fake) ||
        ovf(snprintf(mixed, sizeof mixed, "%s/mixed-compiler.log",
                     g_wcs_work), sizeof mixed))
        return 2;
    if (csr_write(fake, "gcc: fatal error: cannot execute 'cc1': "
                  "CreateProcess: No such file or directory\n") != 0)
        return 2;
    if (wcs_compile_kind(fake, "86", kind, sizeof kind) != 0) return 2;
    if (strcmp(kind, "COMPILER_FAILURE") != 0) {
        printf("FAIL: --self-test — a nonzero compiler with no conventional "
               "source diagnostic was classified '%s', not an "
               "infrastructure failure.\n", kind);
        return 1;
    }
    if (csr_write(mixed, "fixture.c:1:2: error: ordinary source rejection\n"
                  "cc1.exe: out of memory allocating 4096 bytes\n") != 0)
        return 2;
    if (wcs_compile_kind(mixed, "1", kind, sizeof kind) != 0) return 2;
    if (strcmp(kind, "COMPILER_FAILURE") != 0) {
        printf("FAIL: --self-test — a source diagnostic followed by a "
               "backend crash was classified '%s', not infrastructure "
               "failure.\n", kind);
        return 1;
    }
    return 0;
}

int wcs_selftest_phase(void)
{
    static char violating[SFP], clean[SFP], compat[SFP];
    static char *argv[WCS_ARGS];
    struct stat st;
    int have = wcs_have_cmd(g_wcs_cc);
    if (have < 0) return 2;
    if (!have) {
        if (env_or("ZCL_REQUIRE_MINGW", "0")[0] == '1') {
            fprintf(stderr, "  %s --self-test: FAIL — required compiler "
                    "'%s' is unavailable.\n", k_wcs_gate, g_wcs_cc);
            return 2;
        }
        printf("  %s --self-test: SKIP — '%s' is not installed;\n"
               "  cannot prove the gate trips without the compiler it "
               "gates.\n", k_wcs_gate, g_wcs_cc);
        return 0;
    }
    if (probe_files(violating, clean, compat, SFP) != 0) return 2;
    build_argv(argv, WCS_ARGS, NULL, NULL, violating);
    if (wcs_run_status(argv) == 0) {
        printf("FAIL: --self-test — mingw ACCEPTED a TU with an undeclared\n"
               "  identifier inside #if defined(_WIN32). The gate is "
               "hollow:\n  it would report clean on a real Windows-only "
               "syntax error.\n");
        return 1;
    }
    build_argv(argv, WCS_ARGS, NULL, NULL, clean);
    if (wcs_run_status(argv) != 0) {
        printf("FAIL: --self-test — mingw REJECTED a trivially clean TU.\n"
               "  The gate would false-fail every contributor.\n");
        return 1;
    }
    build_argv(argv, WCS_ARGS, "-include", "test/windows_compat.h", compat);
    if (wcs_run_status(argv) != 0) {
        printf("FAIL: --self-test — the native test-profile compatibility "
               "header did not compile a representative POSIX-style test "
               "TU.\n");
        return 1;
    }
    int rc = fake_classifier_probes();
    if (!rc) rc = located_classifier_probes();
    if (rc) return rc;
    printf("  OK: --self-test — flag set trips on a Windows-only undeclared "
           "identifier, passes clean and test-compat code, rejects a "
           "crashed compiler backend\n");
    (void)st;
    char flagsnul[SFP];
    if (ovf(snprintf(flagsnul, sizeof flagsnul, "%s/flags.nul", g_wcs_work),
            sizeof flagsnul))
        return 2;
    return cache_selftest(g_wcs_cc, flagsnul, g_wcs_work, g_wcs_src[0]);
}

int check_windows_cross_syntax_selftest(void)
{
    return wcs_begin(1);
}
