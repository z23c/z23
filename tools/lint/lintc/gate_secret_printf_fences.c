/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — secret-printf static audit of the C23 lint
 * runtime (check-no-secret-printf). Production scan walks git-tracked
 * files via lint_git_index_foreach; full/dev scan walks the filesystem
 * directly.
 */
/*
ALLOWLIST_RE=(
'tools/wallet_dump\.c'
)
*/

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { NSP_MAX = 8192, NSP_HIT = 256, NSP_LINE = 8192 };
struct nsp_set { char p[NSP_MAX][RS_PATH]; int n; };
struct nsp_collect {
    const char (*roots)[RS_PATH];
    int nroots;
    struct nsp_set *set;
};

static const char *const k_nsp_def[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
static const char k_nsp_allow[] = "tools/wallet_dump.c";

static int nsp_is_src(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.'
        && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int nsp_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    if (strncmp(path, root, n) != 0)
        return 0;
    return path[n] == '/' || path[n] == '\0';
}

static int nsp_skip(const char *path)
{
    if (strncmp(path, "tests/harness", 13) == 0
        && (path[13] == '/' || path[13] == '\0'))
        return 1;
    if (strncmp(path, "vendor", 6) == 0
        && (path[6] == '/' || path[6] == '\0'))
        return 1;
    return lint_path_is_excluded(path);
}

static int nsp_in_roots(const char *path, const char (*roots)[RS_PATH], int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (nsp_under(path, roots[i]))
            return 1;
    return 0;
}

static int nsp_has(const struct nsp_set *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int nsp_add(struct nsp_set *s, const char *path)
{
    size_t n;
    if (nsp_has(s, path))
        return 0;
    n = strlen(path);
    if (s->n >= NSP_MAX || n >= RS_PATH)
        return die("z23-lint: secret-printf path set overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int nsp_on_index(const char *path, void *ctx)
{
    struct nsp_collect *c = ctx;
    if (!nsp_is_src(path) || nsp_skip(path))
        return 0;
    if (!nsp_in_roots(path, c->roots, c->nroots))
        return 0;
    return nsp_add(c->set, path);
}

static int nsp_walk(const char *dir, struct nsp_set *s)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0
            && strcmp(nm, "vendor") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, nm);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode) && !nsp_skip(path))
                rc = nsp_walk(path, s);
            else if (S_ISREG(st.st_mode) && nsp_is_src(path) && !nsp_skip(path))
                rc = nsp_add(s, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int nsp_split(char *buf, char out[][RS_PATH], int max, int *n)
{
    char *p = buf;
    *n = 0;
    while (*p) {
        char *s, save;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*n >= max)
            return die("z23-lint: secret-printf scan-dir overflow\n", "");
        s = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        save = *p;
        *p = '\0';
        if (ovf(snprintf(out[*n], RS_PATH, "%s", s), RS_PATH))
            return 2;
        (*n)++;
        if (!save)
            break;
        *p++ = save;
    }
    return 0;
}

static int nsp_fill_def(char out[][RS_PATH], int *n)
{
    size_t i;
    *n = 0;
    for (i = 0; i < sizeof k_nsp_def / sizeof k_nsp_def[0]; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s", k_nsp_def[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

/* Production scan: git-tracked files only, via the index (fast, no
 * directory traversal) -- an unread or refused index is UNPROVEN 2, same
 * as any other production-mode gate. Full/dev scan (the default, and what
 * every fixture and selftest exercises): walk the filesystem directly,
 * exactly like the original shell script always did. This gate's fixtures
 * run inside the make_lint_gates sandbox lane, a hardlink clone with .git
 * deliberately excluded -- so the full-scan path must never touch the git
 * index. */
static int nsp_collect(struct nsp_set *s, char roots[][RS_PATH], int nr,
                       int override)
{
    struct nsp_collect c = { .roots = roots, .nroots = nr, .set = s };
    int rc, i;
    s->n = 0;
    if (!override && lint_prod_scan())
        return lint_git_index_foreach(nsp_on_index, &c);
    rc = 0;
    for (i = 0; rc == 0 && i < nr; i++)
        rc = nsp_walk(roots[i], s);
    return rc;
}

static int nsp_allowed(const char *path)
{
    return strstr(path, k_nsp_allow) != NULL;
}

static int nsp_word_start(const char *line, const char *p)
{
    unsigned char c;
    if (p == line)
        return 1;
    c = (unsigned char)p[-1];
    return !isalnum(c) && c != '_';
}

static int nsp_is_secret(const char *p)
{
    static const char *const t[] = {
        "priv_key", "privkey", "privateKey", "spending_key", "spendingkey",
        "sk_data", "sk_bytes", "wif_str", "wif_data", "wif", "seed_phrase",
        "seed_words", "viewing_key", "viewingkey", "extfvk", "extspk",
        "xpriv", "xprv", "xpri", "xprvv"
    };
    size_t i, n;
    if (strncmp(p, "mnemonic", 8) == 0)
        return 1;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        n = strlen(t[i]);
        if (strncmp(p, t[i], n) != 0)
            continue;
        if (p[n] && (isalnum((unsigned char)p[n]) || p[n] == '_'))
            continue;
        return 1;
    }
    return 0;
}

static int nsp_args_hit(const char *args)
{
    const char *p = args;
    int in_str = 0;
    while (*p && *p != ')') {
        if (*p == '"')
            in_str = !in_str;
        else if (!in_str && nsp_word_start(args, p) && nsp_is_secret(p))
            return 1;
        p++;
    }
    return 0;
}

static const char *nsp_after_fmt(const char *p)
{
    while (*p && *p != '"')
        p++;
    if (*p != '"')
        return NULL;
    p++;
    while (*p && *p != '"')
        p++;
    if (*p != '"')
        return NULL;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    return *p == ',' ? p + 1 : NULL;
}

static int nsp_line_hit(const char *line)
{
    const char *p = line;
    while ((p = strstr(p, "printf")) != NULL) {
        const char *s = p, *q, *args;
        if (s > line && s[-1] == 'n')
            s--;
        if (s > line && (s[-1] == 'f' || s[-1] == 's'))
            s--;
        if (s > line && (isalnum((unsigned char)s[-1]) || s[-1] == '_')) {
            p += 6;
            continue;
        }
        q = p + 6;
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q != '(') {
            p += 6;
            continue;
        }
        args = nsp_after_fmt(q + 1);
        if (args && nsp_args_hit(args))
            return 1;
        p += 6;
    }
    return 0;
}

static int nsp_scan_file(const char *path, FILE *hits, int *nhit)
{
    FILE *f = fopen(path, "r");
    char buf[NSP_LINE];
    int rc = 0, lineno = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[n] = '\0';
        if (!nsp_line_hit(buf) || nsp_allowed(path))
            continue;
        if (*nhit >= NSP_HIT)
            return die("z23-lint: secret-printf hit overflow\n", "");
        if (fprintf(hits, "%s:%d:%s\n", path, lineno, buf) < 0)
            rc = die("z23-lint: write failed\n", "");
        (*nhit)++;
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int nsp_dump(FILE *hits)
{
    char buf[NSP_LINE];
    if (fseek(hits, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    while (fgets(buf, (int)sizeof buf, hits))
        if (fputs(buf, stdout) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

int check_no_secret_printf_run(int argc, char **argv)
{
    char roots[16][RS_PATH], ovbuf[4096];
    int nr = 0, override = 0, rc, i, nhit = 0;
    static struct nsp_set set;
    FILE *hits;
    const char *ov;
    (void)argc;
    (void)argv;
    ov = env_or("ZCL_SECRET_PRINTF_SCAN_DIRS", "");
    if (ov[0]) {
        if (ovf(snprintf(ovbuf, sizeof ovbuf, "%s", ov), sizeof ovbuf))
            return 2;
        rc = nsp_split(ovbuf, roots, 16, &nr);
        override = 1;
    } else {
        rc = nsp_fill_def(roots, &nr);
    }
    if (rc)
        return rc;
    rc = nsp_collect(&set, roots, nr, override);
    if (rc)
        return rc;
    rc = gate_require_scanned(set.n, 1, "check_no_secret_printf",
                              "no *.c/*.h under the scan dirs");
    if (rc)
        return rc;
    hits = tmpfile();
    if (!hits)
        return die("z23-lint: tmpfile failed\n", "");
    for (i = 0; rc == 0 && i < set.n; i++)
        rc = nsp_scan_file(set.p[i], hits, &nhit);
    if (rc) {
        fclose(hits);
        return rc;
    }
    if (nhit == 0) {
        fclose(hits);
        fputs("check_no_secret_printf: clean — no suspicious printf "
              "calls found\n", stdout);
        return 0;
    }
    fputs("check_no_secret_printf: SUSPICIOUS PRINTF CALLS FOUND\n\n", stdout);
    rc = nsp_dump(hits);
    fclose(hits);
    if (rc)
        return rc;
    fputs("\nIf any of these are false positives, add a regex to ALLOWLIST_RE "
          "in\ntools/scripts/check_no_secret_printf.sh (with a justification)."
          "\nIf they're real leaks, fix the call and run the script again.\n",
          stdout);
    return 1;
}

static int nsp_st_line(const char *line, int want)
{
    int got = nsp_line_hit(line);
    if (got != want) {
        fprintf(stderr, "check_no_secret_printf selftest: want %d got %d: %s\n",
                want, got, line);
        return 1;
    }
    return 0;
}

static int nsp_st_planted(void)
{
    char line[80];
    if (ovf(snprintf(line, sizeof line, "%s%s", "printf(\"%s\", ",
                     "priv_key);"), sizeof line))
        return 2;
    return nsp_st_line(line, 1);
}

static int nsp_st_clean(void)
{
    return nsp_st_line("printf(\"private: %f\", amount);", 0);
}

int check_no_secret_printf_selftest(void)
{
    return st_ok(nsp_st_planted() | nsp_st_clean(),
                 "check_no_secret_printf selftest: PASS — a planted secret "
                 "identifier argument is named, a benign amount print is "
                 "clean\n");
}
