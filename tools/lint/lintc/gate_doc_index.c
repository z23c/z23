/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/*
 * Gates: check-codeindex-coverage
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

int check_codeindex_coverage_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096], bin_def[4096], base_def[4096], ceiling[64];
    char qbin[8192], cmd[8192];
    static char captured[256 * 1024];
    char verdict[32], missing[32], summary[512];
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
    if (cic_ceiling(baseline, ceiling, sizeof ceiling))
        return 2;
    if (!cic_digits(ceiling)) {
        if (fputs("check-codeindex-coverage: FATAL — baseline must contain one nonnegative integer\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (setenv("ZCL_DEV_SOURCE_ROOT", source_root, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    if (sh_single_quote(bin, qbin, sizeof qbin)
        || ovf(snprintf(cmd, sizeof cmd, "%s code coverage 2>&1", qbin),
               sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, captured, sizeof captured, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fputs("check-codeindex-coverage: FATAL — code coverage could not measure the tree\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 2;
    }
    cic_take_az(captured, "\"verdict\":\"", verdict, sizeof verdict);
    cic_take_num(captured, "\"missing_files\":", missing, sizeof missing);
    cic_take_q(captured, "\"summary\":\"", summary, sizeof summary);
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

int check_codeindex_coverage_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-codeindex-coverage.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char fixture[4096], srcdir[4096], ac[4096], missp[4096], basep[4096];
    static char logb[256 * 1024];
    int code = 0, rc, bad = 0;
    if (ovf(snprintf(fixture, sizeof fixture, "%s/repo", tmp), sizeof fixture)
        || ovf(snprintf(srcdir, sizeof srcdir, "%s/src", fixture), sizeof srcdir)
        || ovf(snprintf(ac, sizeof ac, "%s/a.c", srcdir), sizeof ac)
        || ovf(snprintf(missp, sizeof missp, "%s/missing.c", srcdir),
               sizeof missp)
        || ovf(snprintf(basep, sizeof basep, "%s/baseline", tmp), sizeof basep)
        || csr_write(ac, "int coverage_fixture(void) { return 23; }\n")
        || csr_write(basep, "0\n")) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    char dump[256], gitcmd[8192];
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
        || setenv("ZCL_CODEINDEX_COVERAGE_BASELINE", basep, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("clean tracked source was not GREEN", logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
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
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 1 || strstr(logb, "missing=1") == NULL) {
        bad = cic_st_fail("planted tracked omission was not named RED", logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    if (ovf(snprintf(gitcmd, sizeof gitcmd,
                     "git -C '%s' rm -q --cached --ignore-unmatch src/missing.c",
                     fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("removing the planted manifest row did not restore GREEN",
                          logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    (void)rap_rm_rf(tmp);
    if (fputs("check-codeindex-coverage: SELFTEST PASS — clean and restored manifests are GREEN; one tracked missing file is RED\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
