/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-doc-accuracy (E11) — the documented lint-gate set
 * matches the Makefile (HARD). Ported from tools/scripts/check_doc_accuracy.sh
 * (deleted). Selftest: gate_doc_accuracy_selftest.c.
 *
 * Source of truth A: the LINT_GATES variable in Makefile (a backslash-
 * continued list), falling back to the historical literal 'lint:' target
 * line. Source of truth B: the check-* tokens inside the
 * LINT-GATES-BEGIN/END marker block of docs/DEFENSIVE_CODING.md. The gate
 * fails if the COUNT differs or the NAME SET differs; the doc is fixed to
 * match the Makefile, never the other way around.
 *
 * Prong C (repo-wide): derive the count from the Makefile, then scan EVERY
 * in-tree *.md (tracked, plus not-yet-added files git does not ignore; the
 * find fallback runs when the cwd is not the top of the git work tree) for
 * a count-shaped claim about the whole umbrella gate set — a number on a
 * non-alphanumeric boundary followed by "lint gates" / "defensive-coding
 * (lint) gates". Subset qualifiers ("11 architecture gates") are ignored.
 * A matched claim must equal the derived count EXACTLY, including "98+".
 *
 * Fail closed: unreadable files and failed git subprocesses are fatal
 * (exit 2), and a scan set under 50 .md files is refused outright.
 * No heap: fixed static arrays, overflow prints "<what> exceeds <N>" to
 * stderr and returns 2.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "util/str_suffix.h"
#include "gate_doc_accuracy_priv.h"

enum { DA_PATH = 1024, DA_GATE = 128, DA_MAXGATES = 512, DA_LINE = 1 << 18,
       DA_BLOCK = 1 << 16, DA_FILEBUF = 2 << 20, DA_GITOUT = 1 << 20,
       DA_MAXDOCS = 4096, DA_DOC = 512, DA_NUM = 32, DA_TXT = 256 };

static char g_file[DA_FILEBUF];
static char g_block[DA_BLOCK];
static char g_git[DA_GITOUT];
static char g_line[DA_LINE];
static char g_lint_line[DA_LINE];

struct da_set { char name[DA_MAXGATES][DA_GATE]; int n; };
struct da_docs { char path[DA_MAXDOCS][DA_DOC]; int n; };

/* ---------------------------------------------------------------- text */

static int da_line_next(const char **pp, const char *end, char *line,
                        size_t cap)
{
    if (*pp >= end)
        return 0;
    const char *s = *pp;
    const char *e = memchr(s, '\n', (size_t)(end - s));
    if (!e)
        e = end;
    size_t n = (size_t)(e - s);
    *pp = (e < end) ? e + 1 : end;
    if (n >= cap)
        return -1;
    memcpy(line, s, n);
    line[n] = '\0';
    if (n && line[n - 1] == '\r')
        line[n - 1] = '\0';
    return 1;
}

/* 0 read, 1 missing, 2 error/overflow. */
static int da_slurp(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f && errno == ENOENT)
        return 1;
    if (!f) {
        fprintf(stderr, "check_doc_accuracy: cannot open %s: %s\n", path,
                strerror(errno));
        return 2;
    }
    size_t r = fread(buf, 1, cap, f);
    if (r == cap && fgetc(f) != EOF) {
        fclose(f);
        fprintf(stderr, "check_doc_accuracy: %s exceeds %d bytes\n", path,
                DA_FILEBUF);
        return 2;
    }
    if (ferror(f)) {
        fclose(f);
        return 2;
    }
    fclose(f);
    *len = r;
    return 0;
}

static int da_has_nonspace(const char *s)
{
    for (; *s; s++)
        if (!isspace((unsigned char)*s))
            return 1;
    return 0;
}

/* ---------------------------------------------------------- gate sets */

static int da_set_add(struct da_set *s, const char *name, size_t len)
{
    char tmp[DA_GATE];
    if (len >= sizeof tmp) {
        fprintf(stderr, "check_doc_accuracy: gate name exceeds %d\n", DA_GATE);
        return 2;
    }
    memcpy(tmp, name, len);
    tmp[len] = '\0';
    int i = 0;
    while (i < s->n && strcmp(s->name[i], tmp) < 0)
        i++;
    if (i < s->n && strcmp(s->name[i], tmp) == 0)
        return 0;
    if (s->n >= DA_MAXGATES) {
        fprintf(stderr, "check_doc_accuracy: gate list exceeds %d\n",
                DA_MAXGATES);
        return 2;
    }
    memmove(s->name[i + 1], s->name[i], (size_t)(s->n - i) * DA_GATE);
    memcpy(s->name[i], tmp, len + 1);
    s->n++;
    return 0;
}

static int da_extract_tokens(const char *text, struct da_set *s)
{
    regex_t re;
    if (compile_pat(&re, REG_EXTENDED, "check-[a-z0-9-]+", "", "", ""))
        return 2;
    const char *p = text;
    regmatch_t m;
    int r;
    while ((r = regexec(&re, p, 1, &m, 0)) == 0) {
        if (da_set_add(s, p + m.rm_so, (size_t)(m.rm_eo - m.rm_so))) {
            regfree(&re);
            return 2;
        }
        p += m.rm_eo;
    }
    regfree(&re);
    return r == REG_NOMATCH ? 0 : 2;
}

static int da_starts_assign(const char *l)
{
    if (strncmp(l, "LINT_GATES", 10) != 0)
        return 0;
    size_t i = 10;
    while (l[i] == ' ' || l[i] == '\t')
        i++;
    return l[i] == ':' && l[i + 1] == '=';
}

static int da_ends_cont(const char *l)
{
    size_t n = strlen(l);
    while (n && (l[n - 1] == ' ' || l[n - 1] == '\t'))
        n--;
    return n > 0 && l[n - 1] == '\\';
}

static int da_is_lint_line(const char *l)
{
    return strncmp(l, "lint:", 5) == 0 && (l[5] == ' ' || l[5] == '\t');
}

/* Makefile scan state: the LINT_GATES block being copied, and the first
 * literal `lint:` line kept as the fallback source. */
struct da_mk { size_t blen; int inb, done, have_lint; };

static int da_mk_block_line(struct da_mk *m, const char *line)
{
    size_t ll = strlen(line);
    if (m->blen + ll + 2 > sizeof g_block) {
        fprintf(stderr, "check_doc_accuracy: LINT_GATES block "
                "exceeds %d\n", DA_BLOCK);
        return 2;
    }
    memcpy(g_block + m->blen, line, ll);
    m->blen += ll;
    g_block[m->blen++] = '\n';
    g_block[m->blen] = '\0';
    if (!da_ends_cont(line)) {
        m->inb = 0;
        m->done = 1;
    }
    return 0;
}

static int da_mk_line(struct da_mk *m, const char *line)
{
    if (!m->inb && !m->done && da_starts_assign(line))
        m->inb = 1;
    if (m->inb)
        return da_mk_block_line(m, line);
    if (!m->have_lint && da_is_lint_line(line)) {
        strcpy(g_lint_line, line);
        m->have_lint = 1;
    }
    return 0;
}

/* Returns 0 ok, 1 FAIL printed (exit 1), 2 fatal. */
static int da_make_gates(const char *root, struct da_set *g)
{
    char path[DA_PATH];
    char *const line = g_line;
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    size_t len;
    int rc = da_slurp(path, g_file, sizeof g_file, &len);
    if (rc == 1) {
        printf("FAIL: Makefile not found\n");
        return 1;
    }
    if (rc)
        return 2;
    struct da_mk m;
    memset(&m, 0, sizeof m);
    int r;
    const char *p = g_file, *end = g_file + len;
    while ((r = da_line_next(&p, end, line, DA_LINE)) == 1) {
        if (da_mk_line(&m, line))
            return 2;
    }
    if (r < 0) {
        fprintf(stderr, "check_doc_accuracy: Makefile line exceeds %d\n",
                DA_LINE);
        return 2;
    }
    const char *src = m.blen ? g_block
                             : (m.have_lint ? g_lint_line : NULL);
    if (!src) {
        printf("FAIL: could not find LINT_GATES or a literal 'lint:' target "
               "line in Makefile\n");
        return 1;
    }
    return da_extract_tokens(src, g);
}

static int da_doc_gates(const char *root, struct da_set *g, FILE *out)
{
    char path[DA_PATH];
    char *const line = g_line;
    if (ovf(snprintf(path, sizeof path, "%s/docs/DEFENSIVE_CODING.md", root),
             sizeof path))
        return 2;
    size_t len;
    int rc = da_slurp(path, g_file, sizeof g_file, &len);
    if (rc == 1) {
        fprintf(out, "FAIL: docs/DEFENSIVE_CODING.md not found\n");
        return 1;
    }
    if (rc)
        return 2;
    size_t blen = 0;
    int f = 0, r;
    const char *p = g_file, *end = g_file + len;
    while ((r = da_line_next(&p, end, line, DA_LINE)) == 1) {
        if (strstr(line, "<!-- LINT-GATES-BEGIN -->")) {
            f = 1;
            continue;
        }
        if (strstr(line, "<!-- LINT-GATES-END -->")) {
            f = 0;
            continue;
        }
        if (!f)
            continue;
        size_t ll = strlen(line);
        if (blen + ll + 2 > sizeof g_block) {
            fprintf(stderr, "check_doc_accuracy: doc block exceeds %d\n",
                    DA_BLOCK);
            return 2;
        }
        memcpy(g_block + blen, line, ll);
        blen += ll;
        g_block[blen++] = '\n';
    }
    if (r < 0) {
        fprintf(stderr, "check_doc_accuracy: doc line exceeds %d\n", DA_LINE);
        return 2;
    }
    g_block[blen] = '\0';
    if (!da_has_nonspace(g_block)) {
        fprintf(out, "FAIL: missing or empty <!-- LINT-GATES-BEGIN/END --> "
                "block in docs/DEFENSIVE_CODING.md\n"
                "      Add the canonical gate list so E11 can verify "
                "doc/Makefile parity.\n");
        return 1;
    }
    return da_extract_tokens(g_block, g);
}

/* Prints msg + the sorted names in a not in b. Returns 1 when nonempty. */
static int da_print_diff(const struct da_set *a, const struct da_set *b,
                         const char *msg, FILE *out)
{
    int i = 0, j = 0, any = 0;
    while (i < a->n && j < b->n) {
        int c = strcmp(a->name[i], b->name[j]);
        if (c == 0) {
            i++;
            j++;
        } else if (c < 0) {
            if (!any)
                fputs(msg, out);
            any = 1;
            fprintf(out, "    %s\n", a->name[i]);
            i++;
        } else {
            j++;
        }
    }
    for (; i < a->n; i++) {
        if (!any)
            fputs(msg, out);
        any = 1;
        fprintf(out, "    %s\n", a->name[i]);
    }
    return any;
}

static int da_compare_report(const struct da_set *mk, const struct da_set *dc,
                             FILE *out)
{
    int fail = 0;
    if (mk->n != dc->n) {
        fprintf(out, "FAIL: gate COUNT mismatch — Makefile LINT_GATES has %d "
                "check-* gates, docs/DEFENSIVE_CODING.md documents %d\n",
                mk->n, dc->n);
        fail = 1;
    }
    if (da_print_diff(mk, dc, "FAIL: gates in Makefile LINT_GATES but NOT "
                     "documented in docs/DEFENSIVE_CODING.md:\n", out))
        fail = 1;
    if (da_print_diff(dc, mk, "FAIL: gates documented in "
                     "docs/DEFENSIVE_CODING.md but NOT in Makefile "
                     "LINT_GATES:\n", out))
        fail = 1;
    return fail;
}

/* ------------------------------------------------------- doc listing */

static int da_doc_add(struct da_docs *d, const char *rel)
{
    if (strlen(rel) >= DA_DOC) {
        fprintf(stderr, "check_doc_accuracy: path exceeds %d: %s\n", DA_DOC,
                rel);
        return 2;
    }
    if (d->n >= DA_MAXDOCS) {
        fprintf(stderr, "check_doc_accuracy: .md file list exceeds %d\n",
                DA_MAXDOCS);
        return 2;
    }
    strcpy(d->path[d->n], rel);
    d->n++;
    return 0;
}

static int da_nul_add(struct da_docs *d, const char *buf, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\0')
            j++;
        if (j > i && da_doc_add(d, buf + i))
            return 2;
        i = j + 1;
    }
    return 0;
}

/* Reaps pid, retrying on EINTR only. Any other waitpid failure is a local
 * error: a child we cannot reap has no trustworthy exit status. */
static int da_reap(pid_t pid, int *st)
{
    int tmp = 0;
    int *dst = st ? st : &tmp;
    while (waitpid(pid, dst, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

/* Child side: cwd=root, stdout into the pipe, and stderr to /dev/null when
 * quiet (the script's `git rev-parse ... 2>/dev/null`). */
static void da_child(const char *root, char *const argv[], int out_fd,
                     int quiet)
{
    if (chdir(root) != 0)
        _exit(126);
    if (dup2(out_fd, STDOUT_FILENO) < 0)
        _exit(125);
    close(out_fd);
    if (quiet) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, STDERR_FILENO);
            close(nul);
        }
    }
    execvp(argv[0], argv);
    _exit(127);
}

/* Runs argv with cwd=root, captures stdout into out. Returns the child's
 * exit status (>=128 on abnormal end), or -1 on a local failure. */
static int da_capture(const char *root, char *const argv[], char *out,
                      size_t cap, size_t *len, int quiet)
{
    int fd[2];
    if (pipe(fd))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    if (pid == 0) {
        close(fd[0]);
        da_child(root, argv, fd[1], quiet);
    }
    close(fd[1]);
    size_t got = 0;
    char tmp[4096];
    ssize_t r;
    while ((r = read(fd[0], tmp, sizeof tmp)) > 0) {
        if (got + (size_t)r > cap) {
            close(fd[0]);
            (void)da_reap(pid, NULL);
            fprintf(stderr, "check_doc_accuracy: git output exceeds %d\n",
                    DA_GITOUT);
            return -1;
        }
        memcpy(out + got, tmp, (size_t)r);
        got += (size_t)r;
    }
    close(fd[0]);
    int st = 0;
    if (da_reap(pid, &st))
        return -1;
    *len = got;
    if (r < 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

/* 0: cwd is the git toplevel (git lane), 1: use find, 2: fatal. */
static int da_git_lane(const char *root)
{
    char *const av[] = { (char *)"git", (char *)"rev-parse",
                         (char *)"--show-toplevel", NULL };
    size_t len = 0;
    int code = da_capture(root, av, g_git, sizeof g_git, &len, 1);
    if (code != 0)
        return 1; /* not a repo from here, or git absent: find lane */
    while (len && (g_git[len - 1] == '\n' || g_git[len - 1] == '\r'))
        len--;
    g_git[len] = '\0';
    struct stat a, b;
    if (stat(g_git, &a) != 0 || stat(root, &b) != 0)
        return 1;
    return (a.st_dev == b.st_dev && a.st_ino == b.st_ino) ? 0 : 1;
}

static int da_pruned(const char *name)
{
    return strcmp(name, ".git") == 0 || strcmp(name, "vendor") == 0 ||
           strcmp(name, "build") == 0 || strcmp(name, "node_modules") == 0;
}

static int da_walk_dir(const char *root, const char *rel, struct da_docs *d);

static int da_walk_entry(const char *root, const char *rel, const char *name,
                         struct da_docs *d)
{
    char crel[DA_DOC], full[DA_PATH];
    int n = rel[0] ? snprintf(crel, sizeof crel, "%s/%s", rel, name)
                   : snprintf(crel, sizeof crel, "%s", name);
    if (ovf(n, sizeof crel))
        return 2;
    if (ovf(snprintf(full, sizeof full, "%s/%s", root, crel), sizeof full))
        return 2;
    struct stat st;
    if (lstat(full, &st) != 0) {
        fprintf(stderr, "check_doc_accuracy: cannot stat %s\n", full);
        return 2;
    }
    if (S_ISDIR(st.st_mode))
        return da_walk_dir(root, crel, d);
    if (S_ISREG(st.st_mode) && zcl_str_has_suffix(name, ".md"))
        return da_doc_add(d, crel);
    return 0;
}

static int da_walk_dir(const char *root, const char *rel, struct da_docs *d)
{
    char dirp[DA_PATH];
    int n = rel[0] ? snprintf(dirp, sizeof dirp, "%s/%s", root, rel)
                   : snprintf(dirp, sizeof dirp, "%s", root);
    if (ovf(n, sizeof dirp))
        return 2;
    DIR *dir = opendir(dirp);
    if (!dir) {
        fprintf(stderr, "check_doc_accuracy: cannot open %s\n", dirp);
        return 2;
    }
    struct dirent *de;
    int rc = 0;
    for (;;) {
        errno = 0;
        de = readdir(dir);
        if (!de)
            break;
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        if (da_pruned(de->d_name))
            continue;
        rc = da_walk_entry(root, rel, de->d_name, d);
        if (rc)
            break;
    }
    if (rc == 0 && errno != 0) {
        /* NULL with errno set is a failed read, not end-of-directory: the
         * scan set is incomplete, so refuse rather than report clean. */
        fprintf(stderr,
                "check_doc_accuracy: FATAL — readdir failed on %s; the "
                "scan set is incomplete.\n", dirp);
        rc = 2;
    }
    closedir(dir);
    return rc;
}

static int da_list_docs(const char *root, struct da_docs *d)
{
    int lane = da_git_lane(root);
    if (lane == 2)
        return 2;
    if (lane == 1)
        return da_walk_dir(root, "", d);
    static char *const av1[] = { (char *)"git", (char *)"ls-files",
                                 (char *)"-z", (char *)"--",
                                 (char *)"*.md", NULL };
    static char *const av2[] = { (char *)"git", (char *)"ls-files",
                                 (char *)"-z", (char *)"--others",
                                 (char *)"--exclude-standard",
                                 (char *)"--", (char *)"*.md", NULL };
    size_t len = 0;
    if (da_capture(root, av1, g_git, sizeof g_git, &len, 0) != 0) {
        fprintf(stderr, "check_doc_accuracy: git ls-files failed\n");
        return 2;
    }
    if (da_nul_add(d, g_git, len))
        return 2;
    if (da_capture(root, av2, g_git, sizeof g_git, &len, 0) != 0) {
        fprintf(stderr, "check_doc_accuracy: git ls-files failed\n");
        return 2;
    }
    return da_nul_add(d, g_git, len);
}

/* ------------------------------------------------------- prong C scan */

/* 0 clean, 1 claim failed, 2 regex error. */
static int da_claim_line(const char *line, const regex_t *re,
                         const char *mkstr, int make_count, const char *file,
                         long lineno, int *claims, FILE *out)
{
    const char *p = line;
    regmatch_t m;
    int fail = 0, r;
    /* A later search starts mid-line: ^ must not match there (grep -o keeps
     * the whole line as context), so every search past the first is NOTBOL. */
    while ((r = regexec(re, p, 1, &m, p == line ? 0 : REG_NOTBOL)) == 0) {
        const char *mt = p + m.rm_so;
        size_t span = (size_t)(m.rm_eo - m.rm_so);
        char num[DA_NUM], txt[DA_TXT];
        size_t i = 0, k = 0, tl = span;
        while (i < span && !isdigit((unsigned char)mt[i]))
            i++;
        while (i < span && isdigit((unsigned char)mt[i]) && k < DA_NUM - 1)
            num[k++] = mt[i++];
        num[k] = '\0';
        if (k > 0) {
            (*claims)++;
            if (strcmp(num, mkstr) != 0) {
                if (tl >= sizeof txt)
                    tl = sizeof txt - 1;
                memcpy(txt, mt, tl);
                txt[tl] = '\0';
                const char *t = txt;
                while (*t == ' ' || *t == '\t')
                    t++;
                fprintf(out, "FAIL: %s:%ld claims %s gates; Makefile "
                        "LINT_GATES has %d\n", file, lineno, num, make_count);
                fprintf(out, "      claim text: %s\n", t);
                fail = 1;
            }
        }
        p = mt + span;
        if (span == 0)
            p++;
    }
    if (r != REG_NOMATCH) {
        fprintf(stderr, "check_doc_accuracy: regexec failed on %s:%ld\n",
                file, lineno);
        return 2;
    }
    return fail;
}

/* 0 clean, 1 claim failed, 2 fatal. */
static int da_scan_file(const char *root, const char *rel, const regex_t *re,
                        const char *mkstr, int make_count, int *claims,
                        FILE *out)
{
    char path[DA_PATH];
    char *const line = g_line;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    size_t len;
    if (da_slurp(path, g_file, sizeof g_file, &len) != 0) {
        fprintf(stderr, "check_doc_accuracy: cannot read %s\n", rel);
        return 2;
    }
    const char *p = g_file, *end = g_file + len;
    long ln = 0;
    int r, fail = 0;
    while ((r = da_line_next(&p, end, line, DA_LINE)) == 1) {
        ln++;
        int c = da_claim_line(line, re, mkstr, make_count, rel, ln, claims,
                              out);
        if (c == 2)
            return 2;
        fail |= c;
    }
    if (r < 0) {
        fprintf(stderr, "check_doc_accuracy: line %ld of %s exceeds %d\n",
                ln + 1, rel, DA_LINE);
        return 2;
    }
    return fail;
}

static int da_scan_claims(const char *root, const struct da_docs *d,
                          int make_count, int *claims, FILE *out)
{
    regex_t re;
    if (compile_pat(&re, REG_EXTENDED | REG_ICASE,
                    "(^|[^[:alnum:]/_-])[0-9]+\\+?[[:space:]]+"
                    "(defensive[- ]coding([[:space:]]+lint)?|lint)"
                    "[[:space:]]+gates?([^a-zA-Z]|$)", "", "", ""))
        return 2;
    char mkstr[DA_NUM];
    if (ovf(snprintf(mkstr, sizeof mkstr, "%d", make_count), sizeof mkstr))
        return 2;
    int fail = 0;
    for (int i = 0; i < d->n; i++) {
        int rc = da_scan_file(root, d->path[i], &re, mkstr, make_count,
                              claims, out);
        if (rc == 2) {
            regfree(&re);
            return 2;
        }
        if (rc == 1)
            fail = 1;
    }
    regfree(&re);
    return fail;
}

/* ------------------------------------------------------------- driver */

int da_check_root(const char *root, FILE *out)
{
    static struct da_set mk, dc;
    static struct da_docs docs;
    memset(&mk, 0, sizeof mk);
    memset(&dc, 0, sizeof dc);
    memset(&docs, 0, sizeof docs);
    int rc = da_make_gates(root, &mk);
    if (rc)
        return rc;
    rc = da_doc_gates(root, &dc, out);
    if (rc)
        return rc;
    if (da_compare_report(&mk, &dc, out)) {
        fprintf(out, "\nFix: update the <!-- LINT-GATES-BEGIN/END --> block "
                "in docs/DEFENSIVE_CODING.md to\n"
                "     match the LINT_GATES list in Makefile. The Makefile "
                "is\n"
                "     authoritative for what actually runs.\n");
        return 1;
    }
    if (da_list_docs(root, &docs))
        return 2;
    if (docs.n < 50) {
        fprintf(stderr, "check_doc_accuracy: FATAL — scan set is %d .md "
                "file(s) (expected >=50).\n", docs.n);
        fputs("  list_docs came back (near-)empty, so this gate would report "
              "clean\n", stderr);
        fputs("  without inspecting anything. Refusing to pass off a dead "
              "scan.\n", stderr);
        return 2;
    }
    int claims = 0;
    rc = da_scan_claims(root, &docs, mk.n, &claims, out);
    if (rc == 2)
        return 2;
    if (rc == 1) {
        fprintf(out, "\nFix: do NOT re-pin the number — a corrected constant "
                "goes stale again\n"
                "     the next time a gate lands. Delete the count from the "
                "prose and\n"
                "     point at the derived source instead: `make lint` "
                "prints what it\n"
                "     ran, and the canonical gate list lives in the\n"
                "     <!-- LINT-GATES-BEGIN/END --> block of "
                "docs/DEFENSIVE_CODING.md.\n");
        return 1;
    }
    fprintf(out, "check_doc_accuracy: clean — %d gates; doc block agrees; "
            "%d prose gate-count claim(s) across in-tree .md verified\n",
            mk.n, claims);
    return 0;
}

int check_doc_accuracy_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    return da_check_root(root, stdout);
}
