/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftests for the filesystem-tree-walking lint family
 * (check-sysinit-ordering, check-hotswap-dev-only,
 * check-no-new-coin-backfill-caller and the other tree-walk gates whose
 * run code stays in gate_tree_walk.c).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_tree_walk_priv.h"

/* Proves scan_hs_out's comment-stripping: a doc comment merely mentioning
 * "dlopen()" must not hit once stripped, though the same raw text does hit
 * the un-stripped regex. Kept out of check_hotswap_dev_only_selftest so
 * that function's own decision count stays under the complexity gate's
 * cap. */
static int hs_dev_comment_strip_ok(const regex_t *re)
{
    struct cstrip cs = { .in_block = 1 };
    char stripped[128];
    const char *doc = " * produce a dlopen()-able path that pins the bytes";
    int strip_ok = cstrip_line(&cs, doc, strlen(doc), stripped, sizeof stripped);
    return strip_ok && regexec(re, doc, 0, NULL, 0) == 0
                     && regexec(re, stripped, 0, NULL, 0) != 0;
}

static int hs_dev_make_fx(char *nested, size_t nsz, char *elseb, size_t esz,
                          char *inner, size_t isz, char *pfx, size_t psz,
                          char *d1, size_t d1sz, char *d2, size_t d2sz,
                          char *d3, size_t d3sz)
{
    return snprintf(nested, nsz,
                    "#ifdef ZCL_DEV_BUILD\n#if defined(__APPLE__)\ndl%s(\"dev\", 0);\n"
                    "#endif\n#endif\n", "open") >= (int)nsz
        || snprintf(elseb, esz,
                    "#ifdef ZCL_DEV_BUILD\ndl%s(\"dev\", 0);\n#else\ndl%s(\"release\", 0);\n"
                    "#endif\n", "open", "open") >= (int)esz
        || snprintf(inner, isz,
                    "#ifdef ZCL_DEV_BUILD\n#if 0\ndl%s(\"inner\", 0);\n#endif\n#endif\n",
                    "open") >= (int)isz
        || snprintf(pfx, psz, "%s\n%s\n%s\n",
                    "static void *vfs_dir_xdlopen(void);",
                    "static void *vfs_dir_xdlsym(void);",
                    "static void vfs_dir_xdlclose(void);") >= (int)psz
        || snprintf(d1, d1sz, "void *p = dl%s(\"fixture\", 0);", "open") >= (int)d1sz
        || snprintf(d2, d2sz, "p = dl%s (h, \"fixture\");", "sym") >= (int)d2sz
        || snprintf(d3, d3sz, "(void)dl%s(h);", "close") >= (int)d3sz;
}

static int hs_dev_pfx_hits(const regex_t *re, const char *pfx, int *rc)
{
    int pfx_hit = 0;
    const char *pl = pfx;
    while (*rc == 0 && *pl) {
        const char *nl = strchr(pl, '\n');
        size_t n = nl ? (size_t)(nl - pl) : strlen(pl);
        char line[160];
        if (n >= sizeof line) { *rc = 2; break; }
        memcpy(line, pl, n);
        line[n] = '\0';
        if (regexec(re, line, 0, NULL, 0) == 0) pfx_hit++;
        pl = nl ? nl + 1 : pl + n;
        if (!nl) break;
    }
    return pfx_hit;
}

static int hs_dev_direct_hits(const regex_t *re, const char *d1, const char *d2,
                              const char *d3)
{
    int direct = 0;
    if (regexec(re, d1, 0, NULL, 0) == 0) direct++;
    if (regexec(re, d2, 0, NULL, 0) == 0) direct++;
    if (regexec(re, d3, 0, NULL, 0) == 0) direct++;
    return direct;
}

int check_hotswap_dev_only_selftest(void)
{
    regex_t re;
    int cr = hs_dl_comp(&re);
    if (cr) return cr;
    char nested[160], elseb[160], inner[160], pfx[160], d1[64], d2[64], d3[48];
    char nbuf[256], ebuf[256], ibuf[256];
    size_t nused = 0, eused = 0, iused = 0;
    if (hs_dev_make_fx(nested, sizeof nested, elseb, sizeof elseb, inner,
                       sizeof inner, pfx, sizeof pfx, d1, sizeof d1, d2,
                       sizeof d2, d3, sizeof d3)) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int rc = hs_scan_text(nested, "-", &re, nbuf, sizeof nbuf, &nused);
    if (rc == 0) rc = hs_scan_text(elseb, "-", &re, ebuf, sizeof ebuf, &eused);
    if (rc == 0) rc = hs_scan_text(inner, "-", &re, ibuf, sizeof ibuf, &iused);
    int pfx_hit = hs_dev_pfx_hits(&re, pfx, &rc);
    int direct = 0;
    if (rc == 0)
        direct = hs_dev_direct_hits(&re, d1, d2, d3);
    int bad = rc != 0 || nused != 0 || eused == 0 || iused != 0 || pfx_hit != 0
            || direct != 3;
    bad |= require_scan_root("check-hotswap-dev-only", "config") == 0;
    bad |= !hs_dev_comment_strip_ok(&re);
    if (bad)
        fputs("FAIL: hot-swap dev-region scanner selftest\n", stderr);
    regfree(&re);
    return st_ok(bad, "check_hotswap_dev_only selftest: OK\n");
}


static int cbf_st_run(FILE *cap, int *rc)
{
    if (psp_st_reset(cap))
        return 1;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0)
        return 1;
    if (dup2(fileno(cap), STDOUT_FILENO) < 0) {
        close(saved);
        return 1;
    }
    *rc = check_no_new_coin_backfill_caller_run(0, NULL);
    fflush(stdout);
    (void)dup2(saved, STDOUT_FILENO);
    close(saved);
    return 0;
}

static int cbf_st_save_env(char *oldr, size_t rcap, int *had_root,
                           char *oldp, size_t pcap, int *had_prod)
{
    const char *old_root = getenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    const char *old_prod = getenv("ZCL_LINT_PRODUCTION_SCAN");
    *had_root = 0;
    *had_prod = 0;
    if (old_root) {
        if (ovf(snprintf(oldr, rcap, "%s", old_root), rcap))
            return 1;
        *had_root = 1;
    }
    if (old_prod) {
        if (ovf(snprintf(oldp, pcap, "%s", old_prod), pcap))
            return 1;
        *had_prod = 1;
    }
    return 0;
}

static void cbf_st_restore_env(int had_root, const char *oldr, int had_prod,
                               const char *oldp)
{
    if (had_root)
        (void)setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", oldr, 1);
    else
        (void)unsetenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    if (had_prod)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", oldp, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
}

static int cbf_st_expect(FILE *cap, char *ob, size_t obcap, int *rc, int want,
                         const char *need0, const char *need1)
{
    if (cbf_st_run(cap, rc))
        return 1;
    if (csr_slurp(cap, ob, obcap))
        return 1;
    if (*rc != want)
        return 1;
    if (need0 && strstr(ob, need0) == NULL)
        return 1;
    if (need1 && strstr(ob, need1) == NULL)
        return 1;
    return 0;
}

static int cbf_st_plant_clean(const char *root, const char *sym, char *defp,
                              size_t dcap, char *allp, size_t acap, char *probep,
                              size_t pcap, char *fx, size_t fcap, char *body,
                              size_t bcap)
{
    if (ovf(snprintf(defp, dcap, "%s/%s", root, k_cbf_def), dcap)
        || ovf(snprintf(allp, acap, "%s/%s", root, k_cbf_allow), acap)
        || ovf(snprintf(probep, pcap, "%s/core/probe.c", root), pcap)
        || ovf(snprintf(fx, fcap, "%s/engine/_xfixture.c", root), fcap)
        || ovf(snprintf(body, bcap, "void %svoid) {}\n", sym), bcap)
        || csr_write(defp, body)
        || ovf(snprintf(body, bcap, "void f(void) { %s); }\n", sym), bcap)
        || csr_write(allp, body)
        || setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root, 1) != 0)
        return 1;
    return 0;
}

static int cbf_st_plant_double(const char *allp, const char *sym, char *body,
                               size_t bcap)
{
    if (ovf(snprintf(body, bcap, "void f(void) { %s); %s); }\n", sym, sym),
            bcap)
        || csr_write(allp, body))
        return 1;
    return 0;
}

static int cbf_st_plant_probe(const char *allp, const char *probep,
                              const char *sym, char *body, size_t bcap)
{
    if (ovf(snprintf(body, bcap, "void f(void) { %s); }\n", sym), bcap)
        || csr_write(allp, body)
        || ovf(snprintf(body, bcap, "void g(void) { %s); }\n", sym), bcap)
        || csr_write(probep, body))
        return 1;
    return 0;
}

static int cbf_st_plant_fx(const char *defp, const char *fx, const char *sym,
                           char *body, size_t bcap)
{
    if (ovf(snprintf(body, bcap, "void %svoid) {}\n", sym), bcap)
        || csr_write(defp, body)
        || ovf(snprintf(body, bcap, "void x(void) { %s); }\n", sym), bcap)
        || csr_write(fx, body)
        || setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
        return 1;
    return 0;
}

int check_no_new_coin_backfill_caller_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-cbf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *cap = tmpfile();
    if (!cap) {
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char oldr[4096], oldp[64];
    int had_root = 0, had_prod = 0, bad = 0, rc = 0;
    if (cbf_st_save_env(oldr, sizeof oldr, &had_root, oldp, sizeof oldp, &had_prod))
        bad = 1;
    char sym[64], defp[4096], allp[4096], probep[4096], fx[4096], body[256], ob[8192];
    cbf_sym(sym, sizeof sym);
    if (cbf_st_plant_clean(root, sym, defp, sizeof defp, allp, sizeof allp,
                           probep, sizeof probep, fx, sizeof fx, body,
                           sizeof body))
        bad = 1;

    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 0,
                            "check_no_new_coin_backfill_caller: clean — one allowed production caller",
                            NULL);

    if (cbf_st_plant_double(allp, sym, body, sizeof body))
        bad = 1;
    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 1,
                            "expected exactly 1 call in", "found 2");

    if (cbf_st_plant_probe(allp, probep, sym, body, sizeof body))
        bad = 1;
    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 1,
                            "NEW production caller(s)", "core/probe.c:1");
    (void)unlink(probep);

    (void)unlink(defp);
    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 2, "FATAL", NULL);

    if (cbf_st_plant_fx(defp, fx, sym, body, sizeof body))
        bad = 1;
    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 0,
                            "check_no_new_coin_backfill_caller: clean — one allowed production caller",
                            NULL);
    (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    if (!bad)
        bad = cbf_st_expect(cap, ob, sizeof ob, &rc, 1,
                            "NEW production caller(s)", "engine/_xfixture.c:1");

    fclose(cap);
    cbf_st_restore_env(had_root, oldr, had_prod, oldp);
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_new_coin_backfill_caller selftest\n", stderr);
    return st_ok(bad, "check_no_new_coin_backfill_caller selftest: OK\n");
}
