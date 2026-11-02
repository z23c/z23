/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — git-tracked-enumeration lint gate of the C23 lint
 * runtime, half C (check-error-doc-refs).
 *
 * Gates: check-error-doc-refs
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_git_scan_a_priv.h"

static int edr_skip_path(const char *path)
{
    if (!strncmp(path, "tests/harness/", 14)) return 1;
    return !(c23_ends(path, ".c") || c23_ends(path, ".h"));
}

static int edr_word(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-';
}

static int edr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int edr_resolves(const char *tok)
{
    if (edr_exists(tok)) return 1;
    const char *base = strrchr(tok, '/');
    base = base ? base + 1 : tok;
    char p[4096];
    int n = snprintf(p, sizeof p, "docs/%s", base);
    if (ovf(n, sizeof p)) return 0;
    if (edr_exists(p)) return 1;
    n = snprintf(p, sizeof p, "docs/work/%s", base);
    if (ovf(n, sizeof p)) return 0;
    return edr_exists(p);
}

static int edr_tok_end_md(const char *tok)
{
    size_t n = strlen(tok);
    if (n < 3 || memcmp(tok + n - 3, ".md", 3) != 0) return 0;
    if (n == 3) return 0;
    if (n >= 4 && memcmp(tok + n - 4, "/.md", 4) == 0) return 0;
    return 1;
}

static int edr_lit_skip(const char *s, const char *e)
{
    for (const char *p = s; p < e; p++) {
        if (*p == '*') return 1;
        if (*p == '%' && (p + 1) < e) {
            char n = p[1];
            if (n == 's' || n == 'd' || n == 'l' || n == 'z') return 1;
        }
    }
    return 0;
}

static int edr_lit_has_md(const char *start, const char *end)
{
    int has_md = 0;
    for (const char *q = start; q < end; q++)
        if (q + 2 < end && q[0] == '.' && q[1] == 'm' && q[2] == 'd') has_md = 1;
    return has_md;
}

static int edr_lit_tokens(const char *file, int lineno, char *start, char *end, FILE *out,
                          int *violations)
{
    char *q = start;
    while (q < end) {
        while (q < end && !edr_word((unsigned char)*q)) q++;
        if (q >= end) break;
        char *tok = q;
        while (q < end && edr_word((unsigned char)*q)) q++;
        char saved = *q;
        *q = '\0';
        if (edr_tok_end_md(tok) && !edr_resolves(tok)) {
            (*violations)++;
            if (out && fprintf(out, "  %s:%d names a document that does not exist: %s\n",
                               file, lineno, tok) < 0) {
                *q = saved;
                return die("z23-lint: write failed\n", "");
            }
        }
        *q = saved;
    }
    return 0;
}

static int edr_line(const char *file, int lineno, char *line, FILE *out, int *violations)
{
    if (!strstr(line, ".md")) return 0;
    if (strstr(line, "// error-doc-ref-ok:")) return 0;
    for (char *p = line; *p; p++) {
        if (*p != '"') continue;
        char *start = p + 1;
        char *end = start;
        while (*end && *end != '"') end++;
        if (!*end) break;
        p = end;
        if (!edr_lit_has_md(start, end) || edr_lit_skip(start, end)) continue;
        int rc = edr_lit_tokens(file, lineno, start, end, out, violations);
        if (rc) return rc;
    }
    return 0;
}

static int edr_scan_file(const char *path, int *violations)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        rc = edr_line(path, lineno, line, stdout, violations);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}

static int edr_on_track(const char *path, void *ctx)
{
    int *violations = ctx;
    if (edr_skip_path(path)) return 0;
    return edr_scan_file(path, violations);
}

static int edr_fail(int n)
{
    if (printf("\ncheck_error_doc_refs: FAIL — %d operator-facing reference(s) to a missing document\n"
               "\n"
               "An error message that names a document the reader cannot open is worse\n"
               "than one that names nothing: it spends a round trip and it costs the\n"
               "error surface its credibility. Either write the document, or replace the\n"
               "reference with a command you have actually run.\n"
               "\n"
               "If the path is genuinely produced at runtime, append\n"
               "  // error-doc-ref-ok:<reason>\n"
               "to the line.\n", n) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_error_doc_refs_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int violations = 0;
    int rc = each_zpath(k_ls_all, edr_on_track, &violations);
    if (rc) return rc;
    if (violations) return edr_fail(violations);
    return fputs("check_error_doc_refs: clean — every document named in a C string literal exists\n",
                 stdout) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_error_doc_refs_selftest(void)
{
    char real[] = "const char *p = \"AGENTS.md\";";
    char miss[] = "const char *p = \"lintc11-no-such.md\";";
    char conv[] = "const char *p = \"lintc11-no-such-%s.md\";";
    char mark[] = "const char *p = \"lintc11-no-such.md\"; // error-doc-ref-ok:runtime";
    char docs[] = "const char *p = \"GETTING_STARTED.md\";";
    int v = 0, bad = 0;
    FILE *out = tmpfile();
    if (!out) return die("z23-lint: tmpfile failed\n", "");
    bad |= edr_line("tools/t.c", 1, real, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 3, miss, out, &v) != 0 || v != 1;
    v = 0;
    bad |= edr_line("tools/t.c", 4, conv, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 5, mark, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 6, docs, out, &v) != 0 || v != 0;
    bad |= !edr_skip_path("tests/harness/foo.c")
        || !edr_skip_path("tests/harness/include/test/x.h")
        || edr_skip_path("tools/t.c")
        || !edr_skip_path("docs/x." "md");
    fclose(out);
    if (bad)
        fputs("FAIL: check_error_doc_refs selftest\n", stderr);
    return st_ok(bad, "check_error_doc_refs selftest: OK\n");
}
