/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — service result-type ratchet of the C23 lint
 * runtime (check-one-result-type). Tracked files via lint_git_index_foreach.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { ORT_MAX = 4096 };
struct ort_set { char p[ORT_MAX][RS_PATH]; int n; };

static const char k_ort_root[] = "engine/services/src";
static const char k_ort_base[] = "tools/scripts/one_result_type_baseline.txt";
static const char k_ort_res[] = "struct[[:space:]]+zcl_result";
static const char k_ort_ok[] =
    "//[[:space:]]*one-result-type-ok:[A-Za-z][A-Za-z0-9_-]*";

static int ort_is_c(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

static int ort_under(const char *path)
{
    size_t n = strlen(k_ort_root);
    if (strncmp(path, k_ort_root, n) != 0)
        return 0;
    return path[n] == '/' || path[n] == '\0';
}

static int ort_has(const struct ort_set *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int ort_add(struct ort_set *s, const char *path)
{
    size_t n;
    if (ort_has(s, path))
        return 0;
    n = strlen(path);
    if (s->n >= ORT_MAX || n >= RS_PATH)
        return die("z23-lint: one-result-type path set overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int ort_on_index(const char *path, void *ctx)
{
    if (!ort_is_c(path) || !ort_under(path) || lint_path_is_excluded(path))
        return 0;
    return ort_add(ctx, path);
}

static int ort_walk(const char *dir, struct ort_set *s)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, nm);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = ort_walk(path, s);
            else if (S_ISREG(st.st_mode) && ort_is_c(path)
                     && !lint_path_is_excluded(path))
                rc = ort_add(s, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int ort_collect(struct ort_set *s)
{
    int rc = lint_git_index_foreach(ort_on_index, s);
    if (rc)
        return rc;
    if (lint_prod_scan())
        return 0;
    return ort_walk(k_ort_root, s);
}

static int ort_scan_file(const char *path, const regex_t *res,
                         const regex_t *ok, int *uses, int *ovr)
{
    FILE *f = fopen(path, "r");
    char buf[8192];
    int rc = 0;
    *uses = 0;
    *ovr = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        if (regexec(res, buf, 0, NULL, 0) == 0)
            *uses = 1;
        if (regexec(ok, buf, 0, NULL, 0) == 0)
            *ovr = 1;
    }
    if (ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int ort_load_base(struct bln_set *b)
{
    FILE *f = fopen(k_ort_base, "r");
    char buf[BLN_ROW + 8];
    int rc = 0;
    b->count = 0;
    if (!f)
        return 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        char *p = buf;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[n] = '\0';
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#')
            continue;
        rc = bln_add(b, p);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", k_ort_base);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", k_ort_base);
    return rc;
}

static int ort_report(const struct bln_set *neu)
{
    int i;
    printf("\ncheck_one_result_type: %d NEW service file(s) not using "
           "struct zcl_result\n\n", neu->count);
    for (i = 0; i < neu->count; i++)
        printf("  %s\n", neu->n[i]);
    fputs("\nNew service functions must return struct zcl_result "
          "(util/result.h) so\nthe failure reason travels with the failure. "
          "Fix options:\n"
          "  1. Return struct zcl_result from the file's fallible functions\n"
          "     (ZCL_OK / ZCL_ERR(code, fmt, ...)).\n"
          "  2. If the file owns no fallible service surface, add a "
          "top-of-file\n     marker '// one-result-type-ok:<tag>' explaining "
          "why.\n"
          "  3. As a last resort, add the path to "
          "tools/scripts/one_result_type_baseline.txt\n"
          "     (a reviewable line; the baseline must only shrink).\n",
          stdout);
    return 1;
}

int check_one_result_type_run(int argc, char **argv)
{
    static struct ort_set set;
    struct bln_set base = {0}, neu = {0}, stale = {0};
    regex_t res, ok;
    int rc, i, uses, ovr;
    (void)argc;
    (void)argv;
    set.n = 0;
    rc = ort_collect(&set);
    if (rc)
        return rc;
    rc = gate_require_scanned(set.n, 1, "check-one-result-type",
                              "no *.c under engine/services/src");
    if (rc)
        return rc;
    rc = ort_load_base(&base);
    if (rc)
        return rc;
    rc = pair_comp(&res, REG_EXTENDED, k_ort_res, "", "", "",
                   &ok, REG_EXTENDED, k_ort_ok, "", "", "");
    if (rc)
        return rc;
    for (i = 0; rc == 0 && i < set.n; i++) {
        rc = ort_scan_file(set.p[i], &res, &ok, &uses, &ovr);
        if (rc)
            break;
        if (bln_has(&base, set.p[i])) {
            if (uses)
                rc = bln_add(&stale, set.p[i]);
            continue;
        }
        if (!uses && !ovr)
            rc = bln_add(&neu, set.p[i]);
    }
    drop2(&res, &ok);
    if (rc)
        return rc;
    if (neu.count) {
        return ort_report(&neu);
    }
    printf("check_one_result_type: clean — %d grandfathered service file(s), "
           "no new bare-result files\n", base.count);
    if (stale.count) {
        printf("  note: %d baselined file(s) now use zcl_result — delete "
               "their baseline line(s) to ratchet forward:\n", stale.count);
        for (i = 0; i < stale.count; i++)
            printf("    %s\n", stale.n[i]);
    }
    return 0;
}

static int ort_st_text(const char *text, int want_new)
{
    regex_t res, ok;
    int uses = 0, ovr = 0, rc;
    rc = pair_comp(&res, REG_EXTENDED, k_ort_res, "", "", "",
                   &ok, REG_EXTENDED, k_ort_ok, "", "", "");
    if (rc)
        return rc;
    {
        const char *p = text;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t n = nl ? (size_t)(nl - p) : strlen(p);
            char line[512];
            if (n >= sizeof line) {
                drop2(&res, &ok);
                return die("z23-lint: source line too long\n", "");
            }
            memcpy(line, p, n);
            line[n] = '\0';
            if (regexec(&res, line, 0, NULL, 0) == 0)
                uses = 1;
            if (regexec(&ok, line, 0, NULL, 0) == 0)
                ovr = 1;
            if (!nl)
                break;
            p = nl + 1;
        }
    }
    drop2(&res, &ok);
    {
        int got = (!uses && !ovr) ? 1 : 0;
        if (got != want_new) {
            fprintf(stderr, "check_one_result_type selftest: want %d got %d\n",
                    want_new, got);
            return 1;
        }
    }
    return 0;
}

static int ort_st_planted(void)
{
    return ort_st_text("bool e2_fixture(void){ return false; }\n", 1);
}

static int ort_st_clean(void)
{
    return ort_st_text("struct zcl_result e2_ok(void);\n", 0);
}

int check_one_result_type_selftest(void)
{
    return st_ok(ort_st_planted() | ort_st_clean(),
                 "check_one_result_type selftest: PASS — a planted bare-bool "
                 "service is named, a zcl_result file is clean\n");
}
