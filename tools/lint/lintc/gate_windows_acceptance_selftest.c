/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-windows-acceptance
 * (gate_windows_acceptance.c). Ports all 13 cases of the deleted shell
 * script's self-test: a clean fixture (a REAL parse of the real catalog
 * and registry copied in) passes; a planted undeclared test_*.c in a
 * catalog tests directory is caught and named; removing it restores the
 * pass; the same file defining a registered group entry is accounted for;
 * an undeclared *_acceptance.c under tests/harness/src is caught; an
 * empty scan set, an unparseable catalog, an orphan _SOURCES row and an
 * active ID without sources all fail closed; and a stub make proves the
 * split modes clear MAKEFLAGS, name -j14 on a 28-processor grant, refuse
 * an unknown --row before make, link only the named row, and fail --global
 * when make cannot plan. A gate not proven able to go red is not evidence.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_windows_acceptance_priv.h"

static char waf_out[WA_TEXT];

static int waf_mkdirs(const char *dir)
{
    static char tmp[WA_PATH * 2];
    size_t n = strlen(dir);
    if (n >= sizeof tmp)
        return 1;
    memcpy(tmp, dir, n + 1);
    for (size_t i = 1; i < n; i++)
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    mkdir(tmp, 0755);
    return 0;
}

static int waf_write(const char *path, const char *text)
{
    static char dir[WA_PATH * 2];
    if (ovf(snprintf(dir, sizeof dir, "%s", path), sizeof dir))
        return 1;
    char *sl = strrchr(dir, '/');
    if (sl) {
        *sl = '\0';
        if (waf_mkdirs(dir))
            return 1;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return 1;
    fputs(text, f);
    return fclose(f) != 0;
}

static int waf_copy(const char *src, const char *dst)
{
    static char dir[WA_PATH * 2], chunk[1 << 16];
    if (ovf(snprintf(dir, sizeof dir, "%s", dst), sizeof dir))
        return 1;
    char *sl = strrchr(dir, '/');
    if (sl) {
        *sl = '\0';
        if (waf_mkdirs(dir))
            return 1;
    }
    FILE *a = fopen(src, "rb");
    if (!a)
        return 1;
    FILE *b = fopen(dst, "wb");
    if (!b) {
        fclose(a);
        return 1;
    }
    size_t r;
    while ((r = fread(chunk, 1, sizeof chunk, a)) > 0)
        if (fwrite(chunk, 1, r, b) != r) {
            fclose(a);
            fclose(b);
            return 1;
        }
    int bad = ferror(a) != 0;
    fclose(a);
    return fclose(b) != 0 || bad;
}

static int waf_read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 1;
    size_t got = fread(buf, 1, cap - 1, f);
    buf[got] = '\0';
    fclose(f);
    return 0;
}

static int waf_keeps(const char *p)
{
    size_t n = strlen(p);
    if (!strncmp(p, "tests/harness/src/", 18) && n >= 13 &&
        !strcmp(p + n - 13, "_acceptance.c"))
        return 1;
    return strstr(p, "/tests/") && n >= 2 && !strcmp(p + n - 2, ".c");
}

/* The fixture: the real catalog and registry copied in, every declared
 * source the reconcile could scan as an empty file, and every exempt
 * file. The reconcile only asks whether a path is accounted for. */
/* Copies the tree file rel from root into the fixture d. */
static int waf_copy_rel(const char *root, const char *d, const char *rel)
{
    char sp[WA_PATH * 2], dp[WA_PATH * 2];
    if (ovf(snprintf(sp, sizeof sp, "%s/%s", root, rel), sizeof sp))
        return 1;
    if (ovf(snprintf(dp, sizeof dp, "%s/%s", d, rel), sizeof dp))
        return 1;
    return waf_copy(sp, dp);
}

/* Creates the empty file rel under the fixture d. */
static int waf_touch_rel(const char *d, const char *rel)
{
    char dp[WA_PATH * 2];
    if (ovf(snprintf(dp, sizeof dp, "%s/%s", d, rel), sizeof dp))
        return 1;
    return waf_write(dp, "");
}

static int waf_make_fixture(const char *d)
{
    static char root[WA_PATH];
    static struct wa_names srcs, ex;
    if (wa_repo_root(root, sizeof root))
        return 1;
    if (waf_copy_rel(root, d, WA_CATALOG_REL) ||
        waf_copy_rel(root, d, WA_REGISTRY_REL))
        return 1;
    srcs.n = 0;
    if (wa_catalog_sources(root, &srcs))
        return 1;
    for (int i = 0; i < srcs.n; i++)
        if (waf_keeps(srcs.v[i]) && waf_touch_rel(d, srcs.v[i]))
            return 1;
    ex.n = 0;
    if (wa_exempt_paths(&ex))
        return 1;
    for (int i = 0; i < ex.n; i++)
        if (waf_touch_rel(d, ex.v[i]))
            return 1;
    return 0;
}

static int waf_reconcile(const char *root, char *out, size_t cap)
{
    FILE *f = tmpfile();
    if (!f)
        return -1;
    int rc = wa_reconcile_root(root, f);
    rewind(f);
    size_t got = fread(out, 1, cap - 1, f);
    out[got] = '\0';
    fclose(f);
    return rc;
}

static void waf_show(const char *text, const char *needle, const char *pfx,
                     int limit)
{
    size_t pos = 0;
    char line[WA_LINE];
    int shown = 0;
    while (shown < limit && wa_next_line(text, &pos, line, sizeof line) == 1) {
        if (needle && !strstr(line, needle))
            continue;
        printf("%s%s\n", pfx, line);
        shown++;
    }
}

static int waf_expect_red(const char *label, const char *needle,
                          const char *root)
{
    int rc = waf_reconcile(root, waf_out, sizeof waf_out);
    if (rc == 0) {
        printf("SELF-TEST FAIL: %s — expected a RED, got a PASS.\n", label);
        waf_show(waf_out, NULL, "    ", 2000);
        return 0;
    }
    if (!strstr(waf_out, needle)) {
        printf("SELF-TEST FAIL: %s — went red but never named '%s'.\n", label,
               needle);
        waf_show(waf_out, NULL, "    ", 2000);
        return 0;
    }
    printf("  self-test ok (RED): %s\n", label);
    waf_show(waf_out, needle, "      | ", 2);
    return 1;
}

static int waf_expect_green(const char *label, const char *root)
{
    int rc = waf_reconcile(root, waf_out, sizeof waf_out);
    if (rc != 0) {
        printf("SELF-TEST FAIL: %s — expected a PASS, got a RED.\n", label);
        waf_show(waf_out, NULL, "    ", 2000);
        return 0;
    }
    printf("  self-test ok (GREEN): %s\n", label);
    waf_show(waf_out, NULL, "      | ", 2000);
    return 1;
}

struct waf_env {
    char path[8192], mf[256], hj[64], cc[WA_PATH], rc[64];
    int p, m, h, c, r;
};

static void waf_grab(char *dst, size_t cap, int *has, const char *k)
{
    const char *v = getenv(k);
    *has = v && v[0] && strlen(v) < cap;
    if (*has)
        snprintf(dst, cap, "%s", v);
}

static void waf_env_save(struct waf_env *e)
{
    waf_grab(e->path, sizeof e->path, &e->p, "PATH");
    waf_grab(e->mf, sizeof e->mf, &e->m, "MAKEFLAGS");
    waf_grab(e->hj, sizeof e->hj, &e->h, "ZCL_HOST_JOBS");
    waf_grab(e->cc, sizeof e->cc, &e->c, "ZCL_WINDOWS_ACCEPTANCE_CC");
    waf_grab(e->rc, sizeof e->rc, &e->r, "STUB_MAKE_RC");
}

static void waf_env_restore(const struct waf_env *e)
{
    if (e->p) setenv("PATH", e->path, 1); else unsetenv("PATH");
    if (e->m) setenv("MAKEFLAGS", e->mf, 1); else unsetenv("MAKEFLAGS");
    if (e->h) setenv("ZCL_HOST_JOBS", e->hj, 1);
    else unsetenv("ZCL_HOST_JOBS");
    if (e->c) setenv("ZCL_WINDOWS_ACCEPTANCE_CC", e->cc, 1);
    else unsetenv("ZCL_WINDOWS_ACCEPTANCE_CC");
    if (e->r) setenv("STUB_MAKE_RC", e->rc, 1);
    else unsetenv("STUB_MAKE_RC");
}

static void waf_env_apply(const char *stub, const char *makeflags,
                          const char *host, const char *cc, const char *rc)
{
    static char p[8192];
    snprintf(p, sizeof p, "%s:%s", stub, env_or("PATH", "/usr/bin:/bin"));
    setenv("PATH", p, 1);
    if (makeflags) setenv("MAKEFLAGS", makeflags, 1);
    else unsetenv("MAKEFLAGS");
    if (host) setenv("ZCL_HOST_JOBS", host, 1);
    else unsetenv("ZCL_HOST_JOBS");
    if (cc) setenv("ZCL_WINDOWS_ACCEPTANCE_CC", cc, 1);
    else unsetenv("ZCL_WINDOWS_ACCEPTANCE_CC");
    if (rc) setenv("STUB_MAKE_RC", rc, 1);
    else unsetenv("STUB_MAKE_RC");
}

static int waf_stub(const char *stub, int with_rc)
{
    static char mk[WA_PATH * 2], txt[WA_PATH * 2];
    if (waf_mkdirs(stub))
        return 1;
    if (ovf(snprintf(mk, sizeof mk, "%s/make", stub), sizeof mk))
        return 1;
    if (ovf(snprintf(txt, sizeof txt,
                     "#!/bin/sh\n"
                     "printf \"%%s|%%s\\n\" \"${MAKEFLAGS-}\" \"$*\" > \"%s/argv\"\n"
                     "%s",
                     stub, with_rc ? "exit \"${STUB_MAKE_RC:-0}\"\n" : ""),
            sizeof txt))
        return 1;
    if (waf_write(mk, txt))
        return 1;
    return chmod(mk, 0755) != 0;
}

static int waf_cases_1_to_5(const char *fx)
{
    static char d[WA_PATH * 2], p[WA_PATH * 2];
    static const char planted[] =
        "platform/modules/platform/tests/test_planted_undeclared.c";
    static const char planted2[] =
        "tests/harness/src/planted_undeclared_acceptance.c";
    if (ovf(snprintf(d, sizeof d, "%s/clean", fx), sizeof d))
        return 0;
    if (waf_mkdirs(d) || waf_make_fixture(d))
        return 0;
    int bad = 0;
    bad |= !waf_expect_green(
        "1. a fixture with every declared program and nothing else passes", d);
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, planted), sizeof p))
        return 0;
    if (waf_write(p, "int main(void) { return 0; }\n"))
        return 0;
    bad |= !waf_expect_red(
        "2. a planted UNDECLARED program is caught and named", planted, d);
    unlink(p);
    bad |= !waf_expect_green(
        "3. removing the planted program restores the pass", d);
    if (waf_write(p, "int test_directory_watcher(void) { return 0; }\n"))
        return 0;
    bad |= !waf_expect_green(
        "4. the same file passes once it defines a registered group entry", d);
    unlink(p);
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, planted2), sizeof p))
        return 0;
    if (waf_write(p, "int main(void) { return 0; }\n"))
        return 0;
    bad |= !waf_expect_red(
        "5. an undeclared *_acceptance.c under tests/harness/src is caught",
        planted2, d);
    unlink(p);
    return !bad;
}

static int waf_is_test_c(const char *p)
{
    size_t n = strlen(p);
    return n >= 2 && !strcmp(p + n - 2, ".c") && strstr(p, "/tests/");
}

/* Like the script's find -type f -path under tests -name .c -delete:
 * recursive over the whole fixture, not just the catalog's program dirs. */
static int waf_mut_empty_walk(const char *dir, int depth)
{
    static char p[16][WA_PATH * 2];
    struct dirent *e;
    struct stat st;
    DIR *dp = opendir(dir);
    if (!dp || depth >= 16)
        return 1;
    while ((e = readdir(dp))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        if (ovf(snprintf(p[depth], sizeof p[depth], "%s/%s", dir, e->d_name),
                sizeof p[depth]) ||
            lstat(p[depth], &st) != 0)
            break;
        if (S_ISDIR(st.st_mode) && waf_mut_empty_walk(p[depth], depth + 1))
            break;
        if (S_ISREG(st.st_mode) && waf_is_test_c(p[depth]) &&
            remove(p[depth]) != 0)
            break;
    }
    int failed = e != NULL;
    closedir(dp);
    return failed;
}

static int waf_mut_empty(const char *d)
{
    return waf_mut_empty_walk(d, 0);
}

static int waf_mut_nocat(const char *d)
{
    static char p[WA_PATH * 2];
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, WA_CATALOG_REL), sizeof p))
        return 1;
    return waf_write(p, "# every row removed\n");
}

static int waf_is_rng_row(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    if (strncmp(s, "rng ", 4))
        return 0;
    s += 4;
    if (*s != '\\')
        return 0;
    s++;
    while (*s == ' ' || *s == '\t')
        s++;
    return *s == '\0';
}

static int waf_rewrite_cat(const char *d, int drop_rng, int add_missing)
{
    static char buf[WA_TEXT], out[WA_TEXT], p[WA_PATH * 2];
    if (wa_slurp_rel(d, WA_CATALOG_REL, buf, sizeof buf))
        return 1;
    size_t pos = 0, ow = 0;
    char line[WA_LINE];
    while (wa_next_line(buf, &pos, line, sizeof line) == 1) {
        size_t l = strlen(line);
        if (drop_rng && waf_is_rng_row(line))
            continue;
        if (ow + l + 2 > sizeof out)
            return 1;
        memcpy(out + ow, line, l);
        ow += l;
        out[ow++] = '\n';
        if (add_missing && !strncmp(line, "ZCL_WINDOWS_ACCEPTANCE_TESTS", 28)) {
            const char extra[] = "\tplanted_without_sources \\\n";
            if (ow + sizeof extra > sizeof out)
                return 1;
            memcpy(out + ow, extra, sizeof extra - 1);
            ow += sizeof extra - 1;
        }
    }
    out[ow] = '\0';
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, WA_CATALOG_REL), sizeof p))
        return 1;
    return waf_write(p, out);
}

static int waf_mut_orphan(const char *d)
{
    return waf_rewrite_cat(d, 1, 0);
}

static int waf_mut_missing(const char *d)
{
    return waf_rewrite_cat(d, 0, 1);
}

static int waf_case_red(const char *fx, const char *name, const char *label,
                        const char *needle, int (*mutate)(const char *))
{
    static char d[WA_PATH * 2];
    if (ovf(snprintf(d, sizeof d, "%s/%s", fx, name), sizeof d) ||
        waf_mkdirs(d) || waf_make_fixture(d) || mutate(d)) {
        printf("self-test FAIL: %s: fixture setup failed\n", label);
        return 0;
    }
    return waf_expect_red(label, needle, d);
}

static int waf_case_10(const char *fx)
{
    static char stub[WA_PATH * 2], avp[WA_PATH * 2], seen[WA_LINE];
    struct waf_env e;
    if (ovf(snprintf(stub, sizeof stub, "%s/stub-make", fx), sizeof stub))
        return 0;
    if (ovf(snprintf(avp, sizeof avp, "%s/argv", stub), sizeof avp))
        return 0;
    if (waf_stub(stub, 0))
        return 0;
    waf_env_save(&e);
    waf_env_apply(stub, "-j28 --jobserver-auth=fifo:/nonexistent", "28",
                  "true", NULL);
    (void)wa_compile_step_io(stdout, stderr, 1);
    waf_env_restore(&e);
    if (waf_read_file(avp, seen, sizeof seen))
        seen[0] = '\0';
    if (seen[0] == '|' && strstr(seen, " -j14 ")) {
        printf("  self-test ok (GREEN): 10. the cross-link runs -j14 on a 28-processor grant with MAKEFLAGS cleared\n");
        return 1;
    }
    printf("SELF-TEST FAIL: 10. the cross-link must clear MAKEFLAGS and name -j14; ran: %s\n",
           seen);
    return 0;
}

static int waf_stub_paths(const char *fx, const char *name, char *stub,
                          size_t scap, char *avp, size_t acap)
{
    if (ovf(snprintf(stub, scap, "%s/%s", fx, name), scap))
        return 1;
    if (ovf(snprintf(avp, acap, "%s/argv", stub), acap))
        return 1;
    return waf_stub(stub, 1);
}

static int waf_case_11(const char *fx)
{
    static char stub[WA_PATH * 2], avp[WA_PATH * 2];
    struct waf_env e;
    char *a1[] = { (char *)"--row=planted_not_a_row", NULL };
    if (waf_stub_paths(fx, "stub-split", stub, sizeof stub, avp, sizeof avp))
        return 0;
    unlink(avp);
    waf_env_save(&e);
    waf_env_apply(stub, NULL, NULL, "true", NULL);
    FILE *so = tmpfile(), *se = tmpfile();
    if (!so || !se)
        return 0;
    int rc = wa_rows_main_io(1, a1, so, se);
    fclose(so);
    fclose(se);
    waf_env_restore(&e);
    if (rc == 2 && access(avp, F_OK) != 0) {
        printf("  self-test ok (RED): 11. --row naming no catalog row refuses without running make\n");
        return 1;
    }
    printf("SELF-TEST FAIL: 11. --row naming no catalog row must refuse (2) before make; rc=%d\n",
           rc);
    return 0;
}

static int waf_case_12(const char *fx)
{
    static char stub[WA_PATH * 2], avp[WA_PATH * 2], root[WA_PATH];
    static char dir[WA_PATH], exp[WA_PATH * 2], seen[WA_LINE];
    struct waf_env e;
    char *a2[] = { (char *)"--row=rng", NULL };
    if (waf_stub_paths(fx, "stub-split", stub, sizeof stub, avp, sizeof avp))
        return 0;
    if (wa_repo_root(root, sizeof root))
        return 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/build/tests/windows-rows", root),
            sizeof dir))
        return 0;
    unlink(avp);
    waf_env_save(&e);
    waf_env_apply(stub, "-j28", "28", "true", NULL);
    FILE *so = tmpfile(), *se = tmpfile();
    if (!so || !se)
        return 0;
    int rc = wa_rows_main_io(1, a2, so, se);
    fclose(so);
    fclose(se);
    waf_env_restore(&e);
    if (waf_read_file(avp, seen, sizeof seen))
        seen[0] = '\0';
    if (ovf(snprintf(exp, sizeof exp, " ZCL_WINDOWS_ACCEPTANCE_DIR=%s %s/rng.exe",
                     dir, dir), sizeof exp))
        return 0;
    if (rc == 1 && strstr(seen, exp)) {
        printf("  self-test ok (RED): 12. --row=rng names only rng.exe and fails when no binary appears\n");
        return 1;
    }
    printf("SELF-TEST FAIL: 12. --row=rng must link only rng.exe and fail without it; rc=%d ran: %s\n",
           rc, seen);
    return 0;
}

static int waf_case_13(const char *fx)
{
    static char stub[WA_PATH * 2], avp[WA_PATH * 2], seen[WA_LINE];
    struct waf_env e;
    if (waf_stub_paths(fx, "stub-split", stub, sizeof stub, avp, sizeof avp))
        return 0;
    unlink(avp);
    waf_env_save(&e);
    waf_env_apply(stub, NULL, NULL, NULL, "2");
    FILE *so = tmpfile();
    if (!so)
        return 0;
    int rc = wa_global_main_io(so);
    fclose(so);
    waf_env_restore(&e);
    if (waf_read_file(avp, seen, sizeof seen))
        seen[0] = '\0';
    if (rc == 1 && strstr(seen, "-n ") &&
        strstr(seen, "windows-acceptance-compile")) {
        printf("  self-test ok (RED): 13. --global fails when make cannot plan the cross-link\n");
        return 1;
    }
    printf("SELF-TEST FAIL: 13. --global must fail when make cannot plan; rc=%d ran: %s\n",
           rc, seen);
    return 0;
}

int check_windows_acceptance_selftest(void)
{
    static char fx[WA_PATH];
    int rc0 = lint_mkdtemp(fx, sizeof fx, "windows-acceptance-selftest");
    if (rc0)
        return rc0;
    printf("══ check-windows-acceptance self-test ══\n");
    int bad = 0;
    bad |= !waf_cases_1_to_5(fx);
    bad |= !waf_case_red(fx, "empty", "6. an empty scan set fails closed",
                         "scan set came back EMPTY", waf_mut_empty);
    bad |= !waf_case_red(fx, "nocat",
                         "7. an unparseable catalog fails closed",
                         "no active acceptance IDs", waf_mut_nocat);
    bad |= !waf_case_red(fx, "orphan_sources",
                         "8. an inactive orphan _SOURCES row is caught",
                         "active acceptance IDs and _SOURCES IDs differ",
                         waf_mut_orphan);
    bad |= !waf_case_red(fx, "missing_sources",
                         "9. an active ID without _SOURCES is caught",
                         "active acceptance IDs and _SOURCES IDs differ",
                         waf_mut_missing);
    bad |= !waf_case_10(fx);
    bad |= !waf_case_11(fx);
    bad |= !waf_case_12(fx);
    bad |= !waf_case_13(fx);
    rap_rm_rf(fx);
    if (!bad)
        printf("══ self-test: PASS (13/13) — this gate is proven able to go red ══\n");
    else
        printf("══ self-test: FAIL ══\n");
    return bad;
}
