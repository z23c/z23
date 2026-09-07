/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — codeindex/doc-coverage lint gates of the C23 lint
 * runtime (check-codeindex-coverage).
 */

/*
 * Gates: check-codeindex-coverage, check-group-purpose
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs.
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


static int cic_digits(const char *s)
{
    if (!s || !s[0])
        return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return 0;
    }
    return 1;
}

static unsigned long cic_u32(const char *s)
{
    unsigned long v = 0;
    for (; *s; s++)
        v = v * 10UL + (unsigned long)(*s - '0');
    return v;
}

static int cic_prefix_sed(const char *output)
{
    const char *p = output ? output : "";
    do {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (fputs("  ", stderr) < 0
            || fwrite(p, 1, n, stderr) != n
            || fputc('\n', stderr) == EOF)
            return die("z23-lint: write failed\n", "");
        if (!nl)
            break;
        p = nl + 1;
    } while (*p);
    return 0;
}

static int cic_prefix_log(const char *buf)
{
    if (!buf || !buf[0])
        return 0;
    return cic_prefix_sed(buf);
}

static void cic_take_az(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    for (const char *p = buf; (p = strstr(p, key)) != NULL; ) {
        p += klen;
        size_t n = 0;
        while (p[n] >= 'A' && p[n] <= 'Z')
            n++;
        if (p[n] != '"')
            continue;
        if (n >= cap)
            n = cap - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        return;
    }
}

static void cic_take_num(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    for (const char *p = buf; (p = strstr(p, key)) != NULL; ) {
        p += klen;
        if (*p < '0' || *p > '9')
            continue;
        size_t n = 0;
        while (p[n] >= '0' && p[n] <= '9')
            n++;
        if (n >= cap)
            n = cap - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        return;
    }
}

static void cic_take_q(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = strstr(buf, key);
    if (!p)
        return;
    p += klen;
    size_t n = 0;
    while (p[n] && p[n] != '"')
        n++;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

static int cic_ceiling(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (line[0] == '#')
            continue;
        char *p = line;
        while (*p && isspace((unsigned char)*p))
            p++;
        if (*p == '\0')
            continue;
        size_t i = 0;
        while (p[i] && !isspace((unsigned char)p[i]))
            i++;
        if (i >= cap)
            i = cap - 1;
        memcpy(out, p, i);
        out[i] = '\0';
        break;
    }
    return fin(f, line, path, rc);
}

static int cic_cov_require(const char *bin, const char *baseline,
                           char *ceiling, size_t ceil_cap)
{
    if (access(bin, X_OK) != 0) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FATAL — missing executable %s\n",
                    bin) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    struct stat st;
    if (stat(baseline, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FATAL — missing baseline %s\n",
                    baseline) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (cic_ceiling(baseline, ceiling, ceil_cap))
        return 2;
    if (!cic_digits(ceiling)) {
        if (fputs("check-codeindex-coverage: FATAL — baseline must contain one nonnegative integer\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    return 0;
}

static int cic_cov_collect(char *cmd, size_t cmd_cap, char *ceiling,
                           size_t ceil_cap)
{
    char root[4096], bin_def[4096], base_def[4096];
    char qbin[8192];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(bin_def, sizeof bin_def, "%s/build/bin/z23-dev", root),
            sizeof bin_def)
        || ovf(snprintf(base_def, sizeof base_def,
                        "%s/tools/lint/codeindex_coverage_baseline.txt", root),
               sizeof base_def))
        return 2;
    const char *bin = env_or("ZCL_CODEINDEX_COVERAGE_BIN", bin_def);
    const char *baseline = env_or("ZCL_CODEINDEX_COVERAGE_BASELINE", base_def);
    const char *source_root = env_or("ZCL_CODEINDEX_COVERAGE_ROOT", root);
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = cic_cov_require(bin, baseline, ceiling, ceil_cap);
    if (rc)
        return rc;
    if (setenv("ZCL_DEV_SOURCE_ROOT", source_root, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    if (sh_single_quote(bin, qbin, sizeof qbin)
        || ovf(snprintf(cmd, cmd_cap, "%s code coverage 2>&1", qbin),
               cmd_cap))
        return 2;
    return 0;
}

static int cic_cov_check(const char *cmd, char *captured, size_t cap,
                         const char *ceiling, char *summary, size_t summary_cap)
{
    int code = 0;
    int rc = capture_cmd(cmd, captured, cap, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fputs("check-codeindex-coverage: FATAL — code coverage could not measure the tree\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 2;
    }
    char verdict[32], missing[32];
    cic_take_az(captured, "\"verdict\":\"", verdict, sizeof verdict);
    cic_take_num(captured, "\"missing_files\":", missing, sizeof missing);
    cic_take_q(captured, "\"summary\":\"", summary, summary_cap);
    if (!cic_digits(missing)) {
        if (fputs("check-codeindex-coverage: FATAL — malformed code coverage reply\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 2;
    }
    unsigned long miss_n = cic_u32(missing), ceil_n = cic_u32(ceiling);
    if (miss_n > ceil_n) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FAIL — %s; shrink-only ceiling=%s\n",
                    summary, ceiling) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 1;
    }
    if (strcmp(verdict, "GREEN") != 0 && miss_n == 0) {
        if (fputs("check-codeindex-coverage: FATAL — zero misses did not earn GREEN\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    return 0;
}

int check_codeindex_coverage_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char ceiling[64], cmd[8192];
    static char captured[256 * 1024];
    char summary[512];
    int rc = cic_cov_collect(cmd, sizeof cmd, ceiling, sizeof ceiling);
    if (rc)
        return rc;
    rc = cic_cov_check(cmd, captured, sizeof captured, ceiling, summary,
                       sizeof summary);
    if (rc)
        return rc;
    if (printf("check-codeindex-coverage: PASS — %s; shrink-only ceiling=%s\n",
               summary, ceiling) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cic_st_fail(const char *msg, const char *log)
{
    if (fprintf(stderr, "check-codeindex-coverage: SELFTEST FAILED — %s\n",
                msg) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = cic_prefix_log(log);
    return rc ? rc : 2;
}

struct cic_st {
    char tmpl[4096];
    char fixture[4096];
    char missp[4096];
    char basep[4096];
    char *logb;
    size_t logcap;
};

static int cic_st_mk_fixture(struct cic_st *st)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(st->tmpl, sizeof st->tmpl,
                     "%s/z23-codeindex-coverage.XXXXXX", td),
            sizeof st->tmpl))
        return 2;
    char *tmp = mkdtemp(st->tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char srcdir[4096], ac[4096];
    if (ovf(snprintf(st->fixture, sizeof st->fixture, "%s/repo", tmp),
            sizeof st->fixture)
        || ovf(snprintf(srcdir, sizeof srcdir, "%s/src", st->fixture),
               sizeof srcdir)
        || ovf(snprintf(ac, sizeof ac, "%s/a.c", srcdir), sizeof ac)
        || ovf(snprintf(st->missp, sizeof st->missp, "%s/missing.c", srcdir),
               sizeof st->missp)
        || ovf(snprintf(st->basep, sizeof st->basep, "%s/baseline", tmp),
               sizeof st->basep)
        || csr_write(ac, "int coverage_fixture(void) { return 23; }\n")
        || csr_write(st->basep, "0\n")) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    return 0;
}

static int cic_st_git_init(struct cic_st *st)
{
    char dump[256], gitcmd[8192];
    int code = 0;
    char *tmp = st->tmpl;
    const char *fixture = st->fixture;
    if (strchr(fixture, '\'')) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: path too long: %s\n", fixture);
    }
    if (ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' init -q", fixture),
            sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0
        || ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' add src/a.c",
                        fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    if (setenv("ZCL_CODEINDEX_COVERAGE_ROOT", fixture, 1) != 0
        || setenv("ZCL_CODEINDEX_COVERAGE_BASELINE", st->basep, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

static int cic_st_clean_green(struct cic_st *st)
{
    int code = 0, rc, bad = 0;
    rc = cic_invoke("check-codeindex-coverage", 1, st->logb, st->logcap, &code);
    if (rc) {
        (void)rap_rm_rf(st->tmpl);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("clean tracked source was not GREEN", st->logb);
        (void)rap_rm_rf(st->tmpl);
        return bad;
    }
    return 0;
}

static int cic_st_planted_red(struct cic_st *st)
{
    char dump[256], gitcmd[8192];
    int code = 0, rc, bad = 0;
    char *tmp = st->tmpl;
    const char *fixture = st->fixture;
    const char *missp = st->missp;
    if (csr_write(missp, "int planted_missing(void) { return 1; }\n")
        || ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' add src/missing.c",
                        fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    if (unlink(missp) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: cannot open %s\n", missp);
    }
    rc = cic_invoke("check-codeindex-coverage", 1, st->logb, st->logcap, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 1 || strstr(st->logb, "missing=1") == NULL) {
        bad = cic_st_fail("planted tracked omission was not named RED",
                          st->logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    return 0;
}

static int cic_st_restore_green(struct cic_st *st)
{
    char dump[256], gitcmd[8192];
    int code = 0, rc, bad = 0;
    char *tmp = st->tmpl;
    const char *fixture = st->fixture;
    if (ovf(snprintf(gitcmd, sizeof gitcmd,
                     "git -C '%s' rm -q --cached --ignore-unmatch src/missing.c",
                     fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    rc = cic_invoke("check-codeindex-coverage", 1, st->logb, st->logcap, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("removing the planted manifest row did not restore GREEN",
                          st->logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    return 0;
}

int check_codeindex_coverage_selftest(void)
{
    static char logb[256 * 1024];
    struct cic_st st;
    memset(&st, 0, sizeof st);
    st.logb = logb;
    st.logcap = sizeof logb;
    int rc = cic_st_mk_fixture(&st);
    if (rc)
        return rc;
    rc = cic_st_git_init(&st);
    if (rc)
        return rc;
    rc = cic_st_clean_green(&st);
    if (rc)
        return rc;
    rc = cic_st_planted_red(&st);
    if (rc)
        return rc;
    rc = cic_st_restore_green(&st);
    if (rc)
        return rc;
    (void)rap_rm_rf(st.tmpl);
    if (fputs("check-codeindex-coverage: SELFTEST PASS — clean and restored manifests are GREEN; one tracked missing file is RED\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

enum { GP_MAX = RS_MAX, GP_NAME = RS_NAME };

static const char k_gp_src[] =
    "cognition/modules/codeindex/src/codeindex_group.c";
static const char k_gp_mod[] =
    "module_group_is\\(group, \"%s\"\\)\\) return \"[^\"]";
static const char k_gp_rootp[] =
    "strcmp\\(group, \"%s\"\\) == 0\\) return \"[^\"]";
static const char k_gp_shapep[] =
    "group_ends_with\\(group, \"%s\"\\)\\) return \"[^\"]";
static const char k_gp_authp[] =
    "starts_seg\\(group, \"%s\"\\)\\) return \"[^\"]";
static const char k_gp_modroom[] =
    "group_ends_with\\(group, \"modules\"\\)\\) return \"[^\"]";
static const char *const k_gp_roots[] = {
    "root", "core", "engine", "contexts", "cognition", "platform", "tools", "tests"
};
static const char *const k_gp_auth[] = {
    "contexts", "core", "engine", "cognition", "platform"
};

static int gp_extract_line(char *line, int *inside, const char *needle,
                           char out[][GP_NAME], int max, int *n)
{
    if (!*inside && strstr(line, needle))
        *inside = 1;
    if (!*inside)
        return 0;
    for (char *p = line; ; ) {
        char *q = strchr(p, '"');
        if (!q)
            break;
        char *r = strchr(q + 1, '"');
        if (!r)
            break;
        size_t len = (size_t)(r - q - 1);
        if (*n >= max || len >= GP_NAME)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out[*n], q + 1, len);
        out[*n][len] = '\0';
        (*n)++;
        p = r + 1;
    }
    if (strstr(line, "};"))
        *inside = 0;
    return 0;
}

static int gp_extract_fp(FILE *f, const char *name, char out[][GP_NAME], int max,
                         int *n)
{
    char needle[128];
    if (ovf(snprintf(needle, sizeof needle, "static const char *const %s[]",
                     name), sizeof needle))
        return 2;
    char *line = NULL;
    size_t cap = 0;
    int inside = 0, rc = 0;
    *n = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = gp_extract_line(line, &inside, needle, out, max, n);
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", "extract");
    free(line);
    return rc;
}

static int gp_extract_mem(const char *text, const char *name,
                          char out[][GP_NAME], int max, int *n)
{
    FILE *t = tmpfile();
    if (!t)
        return die("z23-lint: tmpfile failed\n", "");
    if (fputs(text, t) < 0 || fseek(t, 0, SEEK_SET) != 0) {
        fclose(t);
        return die("z23-lint: write failed\n", "");
    }
    int rc = gp_extract_fp(t, name, out, max, n);
    if (fclose(t) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", "tmpfile");
    return rc;
}

static int gp_extract_path(const char *path, const char *name,
                           char out[][GP_NAME], int max, int *n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    int rc = gp_extract_fp(f, name, out, max, n);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int gp_set_differs(char items[][GP_NAME], int n, char table[][RS_NAME],
                          int tn)
{
    struct sr_set want = {0}, got = {0};
    for (int i = 0; i < tn; i++) {
        if (sr_add(&want, table[i]))
            return 1;
    }
    for (int i = 0; i < n; i++) {
        if (!sr_has(&want, items[i]))
            return 1;
        if (sr_add(&got, items[i]))
            return 1;
    }
    return got.count != want.count;
}

static int gp_file_has(const char *path, const char *fmt, const char *name,
                       int *has)
{
    char pat[256];
    if (ovf(snprintf(pat, sizeof pat, fmt, name), sizeof pat))
        return 2;
    regex_t re;
    int err = regcomp(&re, pat, REG_EXTENDED);
    if (err)
        return reg_fail(&re, err);
    int hits = 0;
    int rc = scan_re(path, &re, &hits, 0);
    regfree(&re);
    if (rc)
        return rc;
    *has = hits > 0;
    return 0;
}

static int gp_check_named(const char *src, const char *fmt, const char *name,
                          const char *kind, const char *tail, int *scanned,
                          int *fail)
{
    (*scanned)++;
    int has = 0;
    int rc = gp_file_has(src, fmt, name, &has);
    if (rc)
        return rc;
    if (!has) {
        fprintf(stderr, "check-group-purpose: %s '%s' %s\n", kind, name, tail);
        *fail = 1;
    }
    return 0;
}

static int gp_collect(const char **src_out)
{
    int rc = rs_init();
    if (rc)
        return rc;
    const char *src = env_or("ZCL_GROUP_PURPOSE_SRC", k_gp_src);
    *src_out = src;
    struct stat st;
    if (stat(src, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "check-group-purpose: missing %s\n", src);
        return 2;
    }
    char c_contexts[GP_MAX][GP_NAME];
    int n_ctx = 0;
    rc = gp_extract_path(src, "k_product_contexts", c_contexts, GP_MAX, &n_ctx);
    if (rc)
        return rc;
    rc = gate_require_scanned(n_ctx, g_n_ctx, "check-group-purpose",
                              "k_product_contexts[] is incomplete");
    if (rc)
        return rc;
    if (gp_set_differs(c_contexts, n_ctx, g_ctx, g_n_ctx)) {
        fputs("check-group-purpose: k_product_contexts[] differs from PRODUCT_CONTEXTS\n",
              stderr);
        return 1;
    }
    return 0;
}

static int gp_check_all(const char *src, int *scanned, int *fail)
{
    int rc;
    for (int i = 0; i < g_n_libs; i++) {
        rc = gp_check_named(src, k_gp_mod, g_libs[i], "module",
                            "has no non-empty purpose", scanned, fail);
        if (rc)
            return rc;
    }
    for (size_t i = 0; i < sizeof k_gp_roots / sizeof k_gp_roots[0]; i++) {
        rc = gp_check_named(src, k_gp_rootp, k_gp_roots[i], "root",
                            "has no non-empty purpose", scanned, fail);
        if (rc)
            return rc;
    }
    for (int i = 0; i < g_n_shapes; i++) {
        rc = gp_check_named(src, k_gp_shapep, g_shapes[i], "shape",
                            "has no non-empty purpose", scanned, fail);
        if (rc)
            return rc;
    }
    for (size_t i = 0; i < sizeof k_gp_auth / sizeof k_gp_auth[0]; i++) {
        rc = gp_check_named(src, k_gp_authp, k_gp_auth[i], "authority",
                            "lacks a room fallback", scanned, fail);
        if (rc)
            return rc;
    }
    {
        int has = 0;
        rc = gp_file_has(src, "%s", k_gp_modroom, &has);
        if (rc)
            return rc;
        if (!has) {
            fputs("check-group-purpose: module-room fallback is missing\n",
                  stderr);
            *fail = 1;
        }
    }
    return 0;
}

int check_group_purpose_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *src;
    int rc = gp_collect(&src);
    if (rc)
        return rc;
    int fail = 0, scanned = 0;
    rc = gp_check_all(src, &scanned, &fail);
    if (rc)
        return rc;
    rc = gate_require_scanned(scanned, g_n_libs + 20, "check-group-purpose",
                              "purpose scan was incomplete");
    if (rc)
        return rc;
    if (printf("[check_group_purpose] scanned %d architecture purpose contracts\n",
               scanned) < 0
        || printf("[check_group_purpose] %d violation(s) found\n", fail) < 0)
        return die("z23-lint: write failed\n", "");
    return fail;
}

static int gp_st_pat(const char *fmt, const char *name, const char *line,
                     int expect)
{
    char pat[256];
    if (ovf(snprintf(pat, sizeof pat, fmt, name), sizeof pat))
        return 1;
    regex_t re;
    int err = regcomp(&re, pat, REG_EXTENDED);
    if (err) {
        (void)reg_fail(&re, err);
        return 1;
    }
    int hit = regexec(&re, line, 0, NULL, 0) == 0;
    regfree(&re);
    return hit != expect;
}

int check_group_purpose_selftest(void)
{
    static const char k_fix[] =
        "prefix \"nope\"\n"
        "static const char *const k_product_contexts[] = {\n"
        "    \"a\", \"b\",\n"
        "};\n"
        "trailer \"c\"\n";
    char got[GP_MAX][GP_NAME];
    int n = 0, bad = 0;
    if (gp_extract_mem(k_fix, "k_product_contexts", got, GP_MAX, &n))
        return 1;
    bad |= n != 2 || strcmp(got[0], "a") != 0 || strcmp(got[1], "b") != 0;
    char match_t[][RS_NAME] = { "b", "a" };
    char miss_t[][RS_NAME] = { "a", "c" };
    bad |= gp_set_differs(got, n, match_t, 2);
    bad |= !gp_set_differs(got, n, miss_t, 2);
    bad |= gp_st_pat(k_gp_mod, "m",
                     "if (module_group_is(group, \"m\")) return \"non-empty\";", 1);
    bad |= gp_st_pat(k_gp_mod, "m",
                     "if (module_group_is(group, \"m\")) return \"\";", 0);
    bad |= gp_st_pat(k_gp_rootp, "core",
                     "if (strcmp(group, \"core\") == 0) return \"x\";", 1);
    bad |= gp_st_pat(k_gp_shapep, "models",
                     "if (group_ends_with(group, \"models\")) return \"x\";", 1);
    bad |= gp_st_pat(k_gp_authp, "engine",
                     "if (starts_seg(group, \"engine\")) return \"x\";", 1);
    return st_ok(bad, "check_group_purpose selftest: OK\n");
}
