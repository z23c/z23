/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for land-preflight: grade the cold-proof dep table
 *          against this tree, or --selftest the grader on fixtures. */

#include "land_preflight.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#endif

static void lp_usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--root DIR] [--def FILE] [--makefile FILE]\n"
            "       %s --selftest\n"
            "Grades tools/dev/proof_dependencies.def rows that apply on this"
            " host: each row must be present in the tree or buildable by a"
            " make rule visible in the Makefile text (make is never run)."
            " Exits 1 when any row is MISSING.\n",
            argv0 ? argv0 : "land-preflight", argv0 ? argv0 : "land-preflight");
}

#if !defined(_WIN32)

static char *lp_fixture_dir(void)
{
    static char tmpl[512];
    const char *tmp = getenv("TMPDIR");
    if (!tmp || tmp[0] == '\0')
        tmp = ".";
    if (snprintf(tmpl, sizeof tmpl, "%s/land-preflight-selftest.XXXXXX", tmp)
        >= (int)sizeof tmpl)
        return NULL;
    return mkdtemp(tmpl);
}

static int lp_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    if (fputs(text, f) < 0 || fclose(f) != 0)
        return -1;
    return 0;
}

static int lp_rm_rf(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    if (!dir)
        return unlink(path);
    while ((ent = readdir(dir)) != NULL) {
        char child[1024];
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof child, "%s/%s", path, ent->d_name) >=
            (int)sizeof child) {
            (void)closedir(dir);
            return -1;
        }
        if (lp_rm_rf(child) != 0) {
            (void)closedir(dir);
            return -1;
        }
    }
    if (closedir(dir) != 0)
        return -1;
    return rmdir(path);
}

static int lp_mkdir_p(const char *path)
{
    char buf[1024];
    size_t n = strlen(path);
    if (n >= sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    return mkdir(buf, 0755) != 0 && errno != EEXIST ? -1 : 0;
}

static bool lp_contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* Table copy for the fixtures: one present row, one absent required row,
 * one absent optional row. Both absent rows' fix is "make vendor". */
static const char k_selftest_def[] =
    "ZCL_DEP(\"vendor/lib\", ZCL_DEP_ALL, ZCL_DEP_HOST_ANY, 0, ZCL_DEP_COPY)\n"
    "ZCL_DEP(\"vendor/absent_artifact.a\", ZCL_DEP_ALL, ZCL_DEP_HOST_ANY, 0,\n"
    "        ZCL_DEP_COPY)\n"
    "ZCL_DEP(\"vendor/optional_cache\", ZCL_DEP_PROOF, ZCL_DEP_HOST_ANY, 1,\n"
    "        ZCL_DEP_COPY)\n";

static const char k_selftest_mk_rule[] = "vendor:\n\t@true\n";

static int lp_selftest_prepare(const char *fx)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/tools/dev", fx);
    if (lp_mkdir_p(path) != 0)
        return -1;
    snprintf(path, sizeof path, "%s/vendor/lib", fx);
    if (lp_mkdir_p(path) != 0)
        return -1;
    snprintf(path, sizeof path, "%s/tools/dev/proof_dependencies.def", fx);
    if (lp_write(path, k_selftest_def) != 0)
        return -1;
    snprintf(path, sizeof path, "%s/vendor/lib/libplaceholder.a", fx);
    return lp_write(path, "placeholder\n");
}

static int lp_selftest_run(const char *fx, const char *mk_text,
                           char **out_buf, int *rc)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/Makefile", fx);
    if (lp_write(path, mk_text) != 0)
        return -1;
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    if (!mem)
        return -1;
    struct zcl_land_preflight_opts opts = {0};
    opts.root = fx;
    *rc = zcl_land_preflight_run(&opts, mem, mem);
    (void)fclose(mem);
    *out_buf = buf;
    return 0;
}

/* Warm half: the required row absent but the vendor rule reachable, a
 * present artifact, and an absent optional row must all grade OK. */
static bool lp_selftest_pass_ok(const char *fx, char **pass_out, int *pass_rc)
{
    if (lp_selftest_run(fx, k_selftest_mk_rule, pass_out, pass_rc) != 0)
        return false;
    return *pass_rc == 0 && *pass_out != NULL
        && lp_contains(*pass_out, "OK       vendor/lib")
        && lp_contains(*pass_out, "buildable: make vendor")
        && lp_contains(*pass_out, "OPTIONAL vendor/optional_cache");
}

/* Cold half: drop the vendor rule so the absent artifact has no reachable
 * make rule. The run must exit 1 naming the fix command. */
static bool lp_selftest_miss_ok(const char *fx, char **miss_out, int *miss_rc)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/Makefile", fx);
    (void)unlink(path);
    if (lp_selftest_run(fx, "all:\n\t@true\n", miss_out, miss_rc) != 0)
        return false;
    return *miss_rc == 1 && *miss_out != NULL
        && lp_contains(*miss_out, "MISSING  vendor/absent_artifact.a")
        && lp_contains(*miss_out, "fix: make vendor");
}

/* The simulated MISS must name the fix command and exit nonzero; adding the
 * fix's rule to the fixture makefile must flip the same run to green, so the
 * check discriminates absence from buildability. */
static int lp_selftest(void)
{
    char *fx = lp_fixture_dir();
    if (!fx)
        return 1;
    int status = 1;
    char path[1024];
    char *pass_out = NULL;
    char *miss_out = NULL;
    int pass_rc = -1;
    int miss_rc = -1;
    do {
        if (lp_selftest_prepare(fx) != 0)
            break;
        if (!lp_selftest_pass_ok(fx, &pass_out, &pass_rc))
            break;
        if (!lp_selftest_miss_ok(fx, &miss_out, &miss_rc))
            break;
        printf("land-preflight --selftest: PASS\n");
        status = 0;
    } while (0);
    if (status != 0)
        fprintf(stderr,
                "land-preflight --selftest: FAIL (pass_rc=%d miss_rc=%d"
                " pass_out=%s miss_out=%s)\n",
                pass_rc, miss_rc, pass_out ? pass_out : "(null)",
                miss_out ? miss_out : "(null)");
    free(pass_out);
    free(miss_out);
    snprintf(path, sizeof path, "%s", fx);
    (void)lp_rm_rf(path);
    return status;
}
#endif

int main(int argc, char **argv)
{
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    fprintf(stderr, "land-preflight: unavailable on Windows\n");
    return 1;
#else
    const char *argv0 = argc > 0 ? argv[0] : "land-preflight";
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return lp_selftest();
    struct zcl_land_preflight_opts opts = {0};
    for (int i = 1; i < argc; i++) {
        const char **slot = NULL;
        if (strcmp(argv[i], "--root") == 0)
            slot = &opts.root;
        else if (strcmp(argv[i], "--def") == 0)
            slot = &opts.def_path;
        else if (strcmp(argv[i], "--makefile") == 0)
            slot = &opts.makefile;
        else {
            lp_usage(argv0);
            return 2;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "land-preflight: %s needs a value\n", argv[i]);
            return 2;
        }
        *slot = argv[++i];
    }
    int rc = zcl_land_preflight_run(&opts, stdout, stderr);
    return rc < 0 ? 2 : rc;
#endif
}
