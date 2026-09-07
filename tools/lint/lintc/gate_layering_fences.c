/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — lib-layer and domain-purity include fences of
 * the C23 lint runtime (check-lib-layering, check-domain-purity).
 *
 * Native walk_src (no process spawn). Unreadable files are UNPROVEN
 * exit 2 and named. A domain scan that yields zero files refuses.
 * Missing production `lib/` matches the shell find-fail-open (clean
 * when the baseline is empty); selftests plant a `lib/` tree.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { LF_LINE = 8192, LF_TOK = 512, LF_HIT = 768, LF_MAX = 256 };

struct lf_acc {
    const regex_t *inc;
    const regex_t *ovr;
    int domain;
    int nfiles;
    int nhit;
    char hit[LF_MAX][LF_HIT];
    char unread[256];
};

static const char *const k_dom_allow[] = {
    "domain", "bloom", "chain", "coins", "consensus", "core", "crypto",
    "keys", "primitives", "script", "support", "util", "validation"
};

static int lf_test_path(const char *path)
{
    if (strncmp(path, "test/", 5) == 0)
        return 1;
    return strstr(path, "/test/") != NULL;
}

static void lf_trim(char *s)
{
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    char *b = s;
    while (*b && isspace((unsigned char)*b))
        b++;
    if (b != s)
        memmove(s, b, strlen(b) + 1);
}

static int lf_hdr(const char *line, char *out, size_t cap)
{
    const char *q = strchr(line, '"');
    if (!q)
        return 0;
    q++;
    const char *e = strchr(q, '"');
    if (!e)
        return 0;
    size_t n = (size_t)(e - q);
    if (n == 0 || n >= cap)
        return 0;
    memcpy(out, q, n);
    out[n] = '\0';
    return 1;
}

static int lf_token(const char *line, char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s", line), cap))
        return 0;
    char *c = strstr(out, "//");
    if (c)
        *c = '\0';
    c = strstr(out, "/*");
    if (c) {
        char *d = strstr(c, "*/");
        if (d)
            memmove(c, d + 2, strlen(d + 2) + 1);
        else
            *c = '\0';
    }
    lf_trim(out);
    return out[0] != '\0';
}

static int lf_allow(const char *hdr)
{
    const char *sl = strchr(hdr, '/');
    size_t n = sl ? (size_t)(sl - hdr) : strlen(hdr);
    for (size_t i = 0; i < sizeof k_dom_allow / sizeof k_dom_allow[0]; i++)
        if (strlen(k_dom_allow[i]) == n && memcmp(hdr, k_dom_allow[i], n) == 0)
            return 1;
    return 0;
}

static int lf_add(struct lf_acc *a, const char *row)
{
    if (a->nhit >= LF_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(a->hit[a->nhit], LF_HIT, "%s", row), LF_HIT))
        return 2;
    a->nhit++;
    return 0;
}

static int lf_line(struct lf_acc *a, const char *path, int lineno,
                   const char *line)
{
    if (regexec(a->inc, line, 0, NULL, 0) != 0)
        return 0;
    if (regexec(a->ovr, line, 0, NULL, 0) == 0)
        return 0;
    char hdr[LF_TOK], tok[LF_TOK], row[LF_HIT];
    if (!lf_hdr(line, hdr, sizeof hdr))
        return 0;
    if (a->domain) {
        if (lf_allow(hdr))
            return 0;
        if (ovf(snprintf(row, sizeof row, "%s:%d domain may not include %s",
                         path, lineno, hdr), sizeof row))
            return 2;
        return lf_add(a, row);
    }
    if (!lf_token(line, tok, sizeof tok))
        return 0;
    if (ovf(snprintf(row, sizeof row, "%s:%s", path, tok), sizeof row))
        return 2;
    return lf_add(a, row);
}

static int lf_file(const char *path, void *ctx)
{
    struct lf_acc *a = ctx;
    if (lf_test_path(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (ovf(snprintf(a->unread, sizeof a->unread, "%s", path),
                sizeof a->unread))
            return 2;
        return 2;
    }
    a->nfiles++;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = lf_line(a, path, lineno, line);
    }
    return fin(f, line, path, rc);
}

static int lf_walk(const char *gate, const char *root, struct lf_acc *a)
{
    struct stat st;
    if (stat(root, &st) != 0) {
        if (errno == ENOENT)
            return 0;
        return die("z23-lint: cannot stat %s\n", root);
    }
    if (!S_ISDIR(st.st_mode))
        return 0;
    (void)gate;
    return walk_src(root, 1, lf_file, a);
}

static int lf_base_count(const char *path, int *n)
{
    *n = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        lf_trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        (*n)++;
    }
    return fin(f, line, path, rc);
}

static int lf_comp(regex_t *inc, regex_t *ovr, int domain)
{
    const char *ip = domain
        ? "^[[:space:]]*#include[[:space:]]+\"[^\"]+/"
        : "^[[:space:]]*#include[[:space:]]+\""
          "(controllers|models|services|views|config)/";
    const char *op = domain
        ? "//[[:space:]]*domain-purity-ok:[A-Za-z][A-Za-z0-9_-]*"
        : "//[[:space:]]*lib-layer-ok:[A-Za-z][A-Za-z0-9_-]*";
    int e = reg_fail(inc, regcomp(inc, ip, REG_EXTENDED));
    if (e)
        return e;
    e = reg_fail(ovr, regcomp(ovr, op, REG_EXTENDED));
    if (e)
        regfree(inc);
    return e;
}

static int lf_lib_print(const struct lf_acc *a)
{
    printf("\ncheck_lib_layering: %d NEW violation(s) not in "
           "tools/scripts/lib_layering_baseline.txt\n\n", a->nhit);
    for (int i = 0; i < a->nhit; i++)
        printf("  %s\n", a->hit[i]);
    fputs("\nFix options (this is a HARD gate — baselining is NOT an option):\n"
          "  1. Delete the include if it's unused (the symbol may already "
          "come from elsewhere).\n"
          "  2. Replace with a forward declaration (struct fwd + extern fn "
          "decl).\n"
          "  3. Move the symbol down into lib/ where it can be referenced "
          "cleanly.\n"
          "  4. For a config/ include: declare a port in lib/ and register "
          "the\n"
          "     implementation from config/ (net/net_runtime_port.h,\n"
          "     storage/node_db_runtime.h are the two worked examples).\n"
          "  5. As a deliberate, reviewed exception only, add an override "
          "marker\n"
          "     '// lib-layer-ok:<tag>' to the include line.\n", stdout);
    return 1;
}

static int lf_dom_print(const struct lf_acc *a)
{
    printf("\ncheck_domain_purity: %d forbidden include(s) in domain/\n\n",
           a->nhit);
    for (int i = 0; i < a->nhit; i++)
        printf("FAIL: %s\n", a->hit[i]);
    fputs("\ndomain/ is the innermost layer. A domain/ file may only "
          "include:\n"
          "  - its own domain headers   #include \"domain/<sub>/<x>.h\"\n"
          "  - C / POSIX system headers #include <...>\n"
          "  - bare domain-local siblings (a quoted include with no slash)\n"
          "  - one of the 12 allowed lib subsystems:\n"
          "      bloom chain coins consensus core crypto keys\n"
          "      primitives script support util validation\n"
          "\nFix options (this is a HARD gate — there is no baseline):\n"
          "  1. Delete the include if it's unused.\n"
          "  2. Move the needed symbol down into domain/ (or one of the 12 "
          "libs).\n"
          "  3. Push the logic up into the app/ layer that should own it.\n"
          "  4. As a deliberate, reviewed exception only, add an override "
          "marker\n"
          "     '// domain-purity-ok:<tag>' to the include line.\n", stdout);
    return 1;
}

int check_lib_layering_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int nbase = 0, rc = lf_base_count("tools/scripts/lib_layering_baseline.txt",
                                      &nbase);
    if (rc)
        return rc;
    if (nbase != 0) {
        printf("\ncheck_lib_layering: tools/scripts/lib_layering_baseline.txt "
               "must stay EMPTY (HARD gate) — found\n"
               "  %d grandfathered entr(y/ies). Fix the lib/ include and\n"
               "  delete the line instead of baselining it.\n", nbase);
        return 1;
    }
    regex_t inc, ovr;
    rc = lf_comp(&inc, &ovr, 0);
    if (rc)
        return rc;
    struct lf_acc a = { .inc = &inc, .ovr = &ovr, .domain = 0 };
    rc = lf_walk("check-lib-layering", "lib", &a);
    drop2(&inc, &ovr);
    if (rc) {
        if (a.unread[0])
            fprintf(stderr, "check-lib-layering: UNPROVEN — cannot read %s\n",
                    a.unread);
        return rc;
    }
    if (a.nhit)
        return lf_lib_print(&a);
    fputs("check_lib_layering: clean — empty baseline (HARD), no lib/ → app/ "
          "or lib/ → config/ includes\n", stdout);
    return 0;
}

int check_domain_purity_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t inc, ovr;
    int rc = lf_comp(&inc, &ovr, 1);
    if (rc)
        return rc;
    struct lf_acc a = { .inc = &inc, .ovr = &ovr, .domain = 1 };
    char dirs[RS_MAX][RS_PATH];
    int nd = 0;
    rc = repo_shape_dirs("domain", "", dirs, RS_MAX, &nd);
    for (int i = 0; rc == 0 && i < nd; i++)
        rc = lf_walk("check-domain-purity", dirs[i], &a);
    drop2(&inc, &ovr);
    if (rc) {
        if (a.unread[0])
            fprintf(stderr, "check-domain-purity: UNPROVEN — cannot read %s\n",
                    a.unread);
        return rc;
    }
    rc = gate_require_scanned(a.nfiles, 1, "check-domain-purity",
                              "domain/ source set is empty");
    if (rc)
        return rc;
    if (a.nhit)
        return lf_dom_print(&a);
    fputs("check_domain_purity: clean — domain/ has no app/lib includes\n",
          stdout);
    return 0;
}

static int lf_st_want(const char *tag, int got, int want_rc)
{
    if (got == want_rc)
        return 0;
    fprintf(stderr, "%s selftest: want %d got %d\n", tag, want_rc, got);
    return 1;
}

static int lf_st_hush(int (*fn)(int, char **), int *out)
{
    fflush(stdout);
    fflush(stderr);
    int n = dup(1), e = dup(2), nfd = open("/dev/null", O_WRONLY);
    if (n < 0 || e < 0 || nfd < 0)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(nfd, 1) >= 0 && dup2(nfd, 2) >= 0) {
        close(nfd);
        rc = fn(0, NULL);
        fflush(stdout);
        fflush(stderr);
    } else {
        close(nfd);
    }
    (void)dup2(n, 1);
    (void)dup2(e, 2);
    close(n);
    close(e);
    *out = rc;
    return 0;
}

int check_lib_layering_selftest(void)
{
    char here[4096], tmp[64];
    if (!getcwd(here, sizeof here))
        return die("z23-lint: getcwd failed\n", "");
    if (ovf(snprintf(tmp, sizeof tmp, "z23-lf-%ld", (long)getpid()),
            sizeof tmp) || csr_mkdirs(tmp))
        return 2;
    int bad = 0, got = 0;
    if (chdir(tmp) != 0)
        bad = 1;
    if (!bad)
        bad |= csr_write("tools/scripts/lib_layering_baseline.txt",
                         "# empty\n");
    if (!bad)
        bad |= csr_write("lib/a.c",
                         "#include \"controllers/foo.h\"\n");
    if (!bad && lf_st_hush(check_lib_layering_run, &got) == 0)
        bad |= lf_st_want("lib-plant", got, 1);
    if (!bad)
        bad |= csr_write("lib/a.c",
                         "#include \"controllers/foo.h\" "
                         "// lib-layer-ok:selftest\n");
    if (!bad && lf_st_hush(check_lib_layering_run, &got) == 0)
        bad |= lf_st_want("lib-override", got, 0);
    if (chdir(here) != 0)
        bad = 1;
    (void)rap_rm_rf(tmp);
    if (bad)
        return 1;
    fputs("[check_lib_layering] SELFTEST PASS "
          "(planted controllers include is red; lib-layer-ok override is "
          "clean)\n", stdout);
    return 0;
}

int check_domain_purity_selftest(void)
{
    char tmp[64];
    if (ovf(snprintf(tmp, sizeof tmp, "z23-dp-%ld", (long)getpid()),
            sizeof tmp) || csr_mkdirs(tmp))
        return 2;
    char badp[256], okp[256];
    int bad = 0;
    if (ovf(snprintf(badp, sizeof badp, "%s/x.c", tmp), sizeof badp)
        || ovf(snprintf(okp, sizeof okp, "%s/y.c", tmp), sizeof okp))
        bad = 1;
    if (!bad)
        bad |= csr_write(badp, "#include \"controllers/foo.h\"\n");
    if (!bad)
        bad |= csr_write(okp, "#include \"domain/sub/x.h\"\n");
    regex_t inc, ovr;
    int compiled = 0;
    if (!bad) {
        bad |= lf_comp(&inc, &ovr, 1);
        compiled = !bad;
    }
    struct lf_acc a = { .inc = &inc, .ovr = &ovr, .domain = 1 };
    if (!bad)
        bad |= lf_file(badp, &a) ? 1 : lf_st_want("dom-plant", a.nhit > 0, 1);
    a.nhit = 0;
    if (!bad)
        bad |= lf_file(okp, &a) ? 1 : lf_st_want("dom-allow", a.nhit, 0);
    if (compiled)
        drop2(&inc, &ovr);
    (void)rap_rm_rf(tmp);
    if (bad)
        return 1;
    fputs("[check_domain_purity] SELFTEST PASS "
          "(planted controllers include is red; domain/ prefix is allowed)\n",
          stdout);
    return 0;
}
