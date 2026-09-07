/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-no-snapshot-struct-memcmp
 * Port of tools/lint/check_no_snapshot_struct_memcmp.sh (now a shim).
 * struct platform_positioned_file_snapshot (platform/modules/platform/
 * include/platform/positioned_file.h) is 64 bytes wide but holds only 56
 * bytes of fields: two uint32_t nanosecond members sit in front of wider
 * int64_t/uint64_t members, so the compiler inserts 8 bytes of alignment
 * padding it never has to initialize. A raw memcmp()/bcmp() over the whole
 * object therefore reads those indeterminate bytes and can report an
 * UNCHANGED file as CHANGED. This exact defect landed three times (twenty
 * test groups red the second time, fixed in commit 44c45f255); the correct
 * comparison already exists as platform_positioned_file_snapshot_equal().
 *
 * This is a deliberately narrow TEXT scan, not a type checker: for every
 * .c/.h file under core/ engine/ contexts/ cognition/ platform/ tools/,
 * collect identifiers declared on ONE physical line as a plain (non-pointer)
 * `struct platform_positioned_file_snapshot <name>[, <name>...];` object,
 * then flag any memcmp()/bcmp() call ELSEWHERE IN THAT SAME FILE whose first
 * or second argument (leading-identifier, `&`-stripped) names one of those
 * identifiers. Every gap this cannot see (multi-line declarations/calls, a
 * helper function that does the memcmp elsewhere, a macro-wrapped memcmp, a
 * copy into a differently-typed buffer, a same-named-but-unrelated variable)
 * is a known, accepted false-negative -- see the shell original's retired
 * header comment for the full list; this port changes none of that scope.
 *
 * No ZCL_* env-var seam anywhere: the shell original reads none, and this
 * port adds none (confirmed: it needs no engine/composition/flags.def
 * registration).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum {
    HSW2_PATH = 320,
    HSW2_NAME = 96,
    HSW2_LINE_MAX = 4096,
    HSW2_MAX_NAMES = 256,
    HSW2_FILE_FLOOR = 3000,
    HSW2_DECL_FLOOR = 40,
    HSW2_VIOL_BUF = 65536,
};

static const char *const k_hsw2_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
static const char k_hsw2_gate[] = "check-no-snapshot-struct-memcmp";
static const char k_hsw2_struct[] = "platform_positioned_file_snapshot";

struct hsw2_re { regex_t decl, prefix, trail, use; };
struct hsw2_viol { char buf[HSW2_VIOL_BUF]; size_t len; int n; };

/* ── regex lifecycle ─────────────────────────────────────────────────────── */
static void hsw2_free(struct hsw2_re *re)
{
    regfree(&re->decl);
    regfree(&re->prefix);
    regfree(&re->trail);
    regfree(&re->use);
}

static int hsw2_compile(struct hsw2_re *re)
{
    static const char decl_pat[] =
        "^[[:space:]]*(static[[:space:]]+|const[[:space:]]+)*struct[[:space:]]+"
        "platform_positioned_file_snapshot[[:space:]]+[^*]*;[[:space:]]*$";
    static const char prefix_pat[] =
        "^[[:space:]]*(static[[:space:]]+|const[[:space:]]+)*struct[[:space:]]+"
        "platform_positioned_file_snapshot[[:space:]]+";
    static const char trail_pat[] = ";[[:space:]]*$";
    static const char use_pat[] = "(^|[^A-Za-z0-9_])(memcmp|bcmp)[[:space:]]*\\(";

    int err = reg_fail(&re->decl, regcomp(&re->decl, decl_pat, REG_EXTENDED | REG_NOSUB));
    if (err)
        return err;
    err = reg_fail(&re->prefix, regcomp(&re->prefix, prefix_pat, REG_EXTENDED));
    if (err) {
        regfree(&re->decl);
        return err;
    }
    err = reg_fail(&re->trail, regcomp(&re->trail, trail_pat, REG_EXTENDED));
    if (err) {
        drop2(&re->decl, &re->prefix);
        return err;
    }
    err = reg_fail(&re->use, regcomp(&re->use, use_pat, REG_EXTENDED));
    if (err) {
        drop3(&re->decl, &re->prefix, &re->trail);
        return err;
    }
    return 0;
}

/* ── violation accumulator ──────────────────────────────────────────────── */
static int hsw2_note(struct hsw2_viol *v, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(v->buf + v->len, sizeof v->buf - v->len, fmt, ap);
    va_end(ap);
    if (ovf(k, sizeof v->buf - v->len))
        return 2;
    v->len += (size_t)k;
    v->n++;
    return 0;
}

static int hsw2_print_prefixed(FILE *out, const char *buf, size_t len, const char *prefix)
{
    size_t i = 0;
    while (i < len) {
        if (fputs(prefix, out) == EOF)
            return die("z23-lint: write failed\n", "");
        size_t j = i;
        while (j < len && buf[j] != '\n')
            j++;
        size_t linelen = (j < len) ? j - i + 1 : j - i;
        if (fwrite(buf + i, 1, linelen, out) != linelen)
            return die("z23-lint: write failed\n", "");
        i += linelen;
    }
    return 0;
}

/* ── small string helpers ───────────────────────────────────────────────── */
static void hsw2_trim(char *s)
{
    size_t n = strlen(s);
    size_t start = 0;
    while (s[start] == ' ' || s[start] == '\t')
        start++;
    size_t end = n;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    size_t len = end - start;
    memmove(s, s + start, len);
    s[len] = '\0';
}

static void hsw2_strip_array_suffix(char *s)
{
    size_t n = strlen(s);
    if (n == 0 || s[n - 1] != ']')
        return;
    char *br = strchr(s, '[');
    if (br)
        *br = '\0';
}

static int hsw2_ident_ok(const char *s)
{
    if (!s[0] || !(isalpha((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    for (const char *p = s + 1; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_'))
            return 0;
    return 1;
}

static const char *hsw2_strip_amp(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '&') {
        s++;
        while (*s == ' ' || *s == '\t')
            s++;
    }
    return s;
}

static int hsw2_base_ident(const char *s, char *out, size_t cap)
{
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    size_t i = 1;
    while (s[i] && (isalnum((unsigned char)s[i]) || s[i] == '_'))
        i++;
    if (i >= cap)
        i = cap - 1;
    memcpy(out, s, i);
    out[i] = '\0';
    return 1;
}

/* ── per-file declared-name set (dedup, counted once per file) ─────────── */
static int hsw2_names_has(char names[][HSW2_NAME], int nnames, const char *s)
{
    for (int i = 0; i < nnames; i++)
        if (strcmp(names[i], s) == 0)
            return 1;
    return 0;
}

static int hsw2_names_add(char names[][HSW2_NAME], int *nnames, const char *name)
{
    if (hsw2_names_has(names, *nnames, name))
        return 0;
    if (*nnames >= HSW2_MAX_NAMES)
        return die("z23-lint: no-snapshot-struct-memcmp name-set overflow\n", "");
    if (ovf(snprintf(names[*nnames], HSW2_NAME, "%s", name), HSW2_NAME))
        return 2;
    (*nnames)++;
    return 0;
}

/* ── Phase A+B: declaration-line match then identifier extraction ──────── */
static int hsw2_split_and_collect(char *rest, char names[][HSW2_NAME], int *nnames)
{
    char *save = NULL;
    char *tok = strtok_r(rest, ",", &save);
    int rc = 0;
    while (rc == 0 && tok) {
        hsw2_trim(tok);
        hsw2_strip_array_suffix(tok);
        if (hsw2_ident_ok(tok))
            rc = hsw2_names_add(names, nnames, tok);
        tok = strtok_r(NULL, ",", &save);
    }
    return rc;
}

static int hsw2_extract_idents(const char *line, const struct hsw2_re *re,
                               char names[][HSW2_NAME], int *nnames)
{
    regmatch_t pm[1];
    if (regexec(&re->prefix, line, 1, pm, 0) != 0)
        return 0;
    size_t pstart = (size_t)pm[0].rm_eo;
    const char *tail = line + pstart;
    size_t restlen = strlen(tail);
    regmatch_t tm[1];
    if (regexec(&re->trail, tail, 1, tm, 0) == 0)
        restlen = (size_t)tm[0].rm_so;
    char rest[HSW2_LINE_MAX];
    if (restlen >= sizeof rest)
        restlen = sizeof rest - 1;
    memcpy(rest, tail, restlen);
    rest[restlen] = '\0';
    return hsw2_split_and_collect(rest, names, nnames);
}

static int hsw2_collect_decls(const char *path, const struct hsw2_re *re,
                              char names[][HSW2_NAME], int *nnames)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (regexec(&re->decl, line, 0, NULL, 0) != 0)
            continue;
        rc = hsw2_extract_idents(line, re, names, nnames);
    }
    return fin(f, line, path, rc);
}

/* ── Phase C: memcmp()/bcmp() scanner ───────────────────────────────────── */
static size_t hsw2_find_close(const char *s, size_t n, size_t openpos)
{
    int depth = 0;
    for (size_t i = openpos; i < n; i++) {
        char c = s[i];
        if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
            if (depth == 0)
                return i;
        }
    }
    return n;
}

/* Depth-aware (over ()[]{} only -- not string-literal-aware, matching the
 * shell's own SCAN_AWK asymmetry with Consumer 1's parser) top-level split;
 * returns 1 and fills `out` with the k-th (0-based) field if it exists. */
static int hsw2_arg_at(const char *args, size_t n, int k, char *out, size_t cap)
{
    int depth = 0;
    size_t start = 0;
    int idx = 0;
    for (size_t i = 0; i <= n; i++) {
        char c = (i < n) ? args[i] : ',';
        if (i < n && (c == '(' || c == '[' || c == '{'))
            depth++;
        else if (i < n && (c == ')' || c == ']' || c == '}'))
            depth--;
        if (c == ',' && depth == 0) {
            if (idx == k) {
                size_t len = i - start;
                if (len >= cap)
                    len = cap - 1;
                memcpy(out, args + start, len);
                out[len] = '\0';
                return 1;
            }
            idx++;
            start = i + 1;
        }
    }
    return 0;
}

static int hsw2_call_hit(const char *args, size_t alen, char names[][HSW2_NAME],
                         int nnames, char *hit, size_t hitcap)
{
    for (int k = 0; k < 2; k++) {
        char a[256];
        if (!hsw2_arg_at(args, alen, k, a, sizeof a))
            break;
        const char *p = hsw2_strip_amp(a);
        char base[HSW2_NAME];
        if (hsw2_base_ident(p, base, sizeof base)
            && hsw2_names_has(names, nnames, base)) {
            if (ovf(snprintf(hit, hitcap, "%s", base), hitcap))
                return -1;
            return 1;
        }
    }
    return 0;
}

static int hsw2_scan_line(const char *path, int lineno, const char *line,
                          char names[][HSW2_NAME], int nnames, const regex_t *use_re,
                          struct hsw2_viol *v)
{
    const char *rest = line;
    int rc = 0;
    while (rc == 0) {
        regmatch_t m[1];
        if (regexec(use_re, rest, 1, m, 0) != 0)
            break;
        size_t rlen = strlen(rest);
        size_t openpos = (size_t)m[0].rm_eo - 1;
        size_t close = hsw2_find_close(rest, rlen, openpos);
        if (close >= rlen) {
            rest = rest + openpos + 1;
            continue;
        }
        char hit[HSW2_NAME];
        int h = hsw2_call_hit(rest + openpos + 1, close - (openpos + 1), names, nnames,
                              hit, sizeof hit);
        if (h < 0)
            return 2;
        if (h > 0)
            rc = hsw2_note(v,
                "%s:%d: memcmp()/bcmp() compares a struct platform_positioned_file_snapshot "
                "object (`%s`) by raw bytes -- the struct has 8 bytes of "
                "never-initialized alignment padding, so this can report an "
                "unchanged file as CHANGED. Use platform_positioned_file_snapshot_equal() "
                "(platform/modules/platform/include/platform/positioned_file.h) instead.\n",
                path, lineno, hit);
        rest = rest + close + 1;
    }
    return rc;
}

static int hsw2_scan_memcmp(const char *path, char names[][HSW2_NAME], int nnames,
                            const regex_t *use_re, struct hsw2_viol *v)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = hsw2_scan_line(path, lineno, line, names, nnames, use_re, v);
    }
    return fin(f, line, path, rc);
}

/* ── walk orchestration ─────────────────────────────────────────────────── */
struct hsw2_ctx {
    const struct hsw2_re *re;
    struct hsw2_viol *v;
    int nfiles;
    int ndecl;
};

static int hsw2_visit(const char *path, void *ctx0)
{
    struct hsw2_ctx *ctx = ctx0;
    if (lint_path_is_excluded(path))
        return 0;
    ctx->nfiles++;
    char names[HSW2_MAX_NAMES][HSW2_NAME];
    int nnames = 0;
    int rc = hsw2_collect_decls(path, ctx->re, names, &nnames);
    if (rc || nnames == 0)
        return rc;
    ctx->ndecl += nnames;
    return hsw2_scan_memcmp(path, names, nnames, &ctx->re->use, ctx->v);
}

static int hsw2_scan_roots(const struct hsw2_re *re, const char *const *roots, int nroots,
                           int *nfiles, int *ndecl, struct hsw2_viol *v)
{
    struct hsw2_ctx ctx = { .re = re, .v = v, .nfiles = 0, .ndecl = 0 };
    int rc = 0;
    for (int i = 0; rc == 0 && i < nroots; i++)
        rc = walk_src_root(k_hsw2_gate, roots[i], 1, hsw2_visit, &ctx);
    *nfiles = ctx.nfiles;
    *ndecl = ctx.ndecl;
    return rc;
}

/* ── production verdict printers ────────────────────────────────────────── */
static int hsw2_fail(const struct hsw2_viol *v)
{
    if (fputc('\n', stderr) == EOF)
        return die("z23-lint: write failed\n", "");
    if (fprintf(stderr, "FAIL: raw memcmp()/bcmp() over a struct %s object.\n",
               k_hsw2_struct) < 0
        || fputs("  The struct carries 8 bytes of never-initialized alignment\n", stderr) == EOF
        || fputs("  padding (see platform/modules/platform/include/platform/positioned_file.h),\n",
                stderr) == EOF
        || fputs("  so comparing the whole object by raw bytes can report an\n", stderr) == EOF
        || fputs("  UNCHANGED file as changed. Use\n", stderr) == EOF
        || fputs("  platform_positioned_file_snapshot_equal() instead.\n", stderr) == EOF
        || fputc('\n', stderr) == EOF)
        return die("z23-lint: write failed\n", "");
    int rc = hsw2_print_prefixed(stderr, v->buf, v->len, "  ");
    return rc ? rc : 1;
}

static int hsw2_clean(int nfiles, int ndecl)
{
    return printf("  OK: %d file(s) scanned, %d struct %s object declaration(s), "
                 "0 memcmp/bcmp comparisons of them\n", nfiles, ndecl, k_hsw2_struct) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_snapshot_struct_memcmp_run(int argc, char **argv)
{
    if (argc >= 1 && strcmp(argv[0], "--self-test") == 0)
        return check_no_snapshot_struct_memcmp_selftest();
    (void)argv;
    if (puts("══ LINT: no raw memcmp/bcmp over a struct platform_positioned_file_snapshot ══") < 0)
        return die("z23-lint: write failed\n", "");
    struct hsw2_re re;
    int rc = hsw2_compile(&re);
    if (rc)
        return rc;
    int nfiles = 0, ndecl = 0;
    struct hsw2_viol v = {0};
    rc = hsw2_scan_roots(&re, k_hsw2_roots,
                         (int)(sizeof k_hsw2_roots / sizeof k_hsw2_roots[0]), &nfiles,
                         &ndecl, &v);
    hsw2_free(&re);
    if (rc)
        return rc;
    rc = gate_require_scanned(nfiles, HSW2_FILE_FLOOR, k_hsw2_gate,
                              "scanned 'core engine contexts cognition platform tools' "
                              "for *.c/*.h — a directory move or a broken find would "
                              "show up here");
    if (rc)
        return rc;
    rc = gate_require_scanned(ndecl, HSW2_DECL_FLOOR, k_hsw2_gate,
                              "parsed 'struct platform_positioned_file_snapshot "
                              "<name>[, <name>...];' declarations — if this "
                              "legitimately drops to zero because every site moved "
                              "to a different declaration shape, lower DECL_FLOOR by "
                              "hand with a comment explaining why; do not let a "
                              "silently-broken regex read as 'nothing to check'");
    if (rc)
        return rc;
    return v.n > 0 ? hsw2_fail(&v) : hsw2_clean(nfiles, ndecl);
}

/* ── selftest ────────────────────────────────────────────────────────────── */
static const char k_hsw2_violating_text[] =
    "#include \"platform/positioned_file.h\"\n"
    "#include <string.h>\n"
    "\n"
    "static bool probe_stable(struct platform_positioned_file *file)\n"
    "{\n"
    "    struct platform_positioned_file_snapshot before, after;\n"
    "    (void)platform_positioned_file_snapshot(file, &before);\n"
    "    (void)platform_positioned_file_snapshot(file, &after);\n"
    "    return memcmp(&before, &after, sizeof(before)) == 0;\n"
    "}\n";

static const char k_hsw2_clean_text[] =
    "#include \"platform/positioned_file.h\"\n"
    "#include <string.h>\n"
    "\n"
    "struct other_thing { int x; int y; };\n"
    "\n"
    "static int cmp_other(const struct other_thing *a, const struct other_thing *b)\n"
    "{\n"
    "    /* Unrelated memcmp, unrelated struct, names 'a'/'b' -- must NOT trip\n"
    "     * the gate just because the file also declares a snapshot pair below. */\n"
    "    return memcmp(a, b, sizeof(*a));\n"
    "}\n"
    "\n"
    "struct platform_positioned_file_snapshot before, after;\n"
    "\n"
    "static bool probe_stable_ok(void)\n"
    "{\n"
    "    /* The correct predicate -- field-wise, never memcmp. */\n"
    "    return platform_positioned_file_snapshot_equal(&before, &after);\n"
    "}\n";

static int hsw2_st_fixture(const char *work, const struct hsw2_re *re)
{
    char dir[HSW2_PATH], vp[HSW2_PATH], cp[HSW2_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/fixture", work), sizeof dir))
        return 2;
    if (csr_mkdirs(dir))
        return 2;
    if (ovf(snprintf(vp, sizeof vp, "%s/violating.c", dir), sizeof vp)
        || ovf(snprintf(cp, sizeof cp, "%s/clean.c", dir), sizeof cp))
        return 2;
    int rc = csr_write(vp, k_hsw2_violating_text);
    if (rc == 0)
        rc = csr_write(cp, k_hsw2_clean_text);
    if (rc)
        return rc;
    int nfiles = 0, ndecl = 0;
    struct hsw2_viol v = {0};
    const char *roots[1] = { dir };
    rc = hsw2_scan_roots(re, roots, 1, &nfiles, &ndecl, &v);
    if (rc)
        return rc;
    int bad = strstr(v.buf, "violating.c:9: memcmp()/bcmp() compares") == NULL
              || strstr(v.buf, "clean.c:") != NULL;
    if (bad) {
        fputs("FAIL: --self-test — the violating fixture (raw memcmp of\n", stderr);
        fputs("  two struct platform_positioned_file_snapshot objects,\n", stderr);
        fputs("  violating.c:9) was NOT flagged, or the clean fixture WAS. "
             "Gate is wrong.\n", stderr);
        hsw2_print_prefixed(stderr, v.buf, v.len, "    ");
        return 1;
    }
    return puts("  ok: --self-test fixture — trips on the violating file/line, "
               "silent on the clean one") < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int hsw2_st_real(const struct hsw2_re *re)
{
    int nfiles = 0, ndecl = 0;
    struct hsw2_viol v = {0};
    int rc = hsw2_scan_roots(re, k_hsw2_roots,
                             (int)(sizeof k_hsw2_roots / sizeof k_hsw2_roots[0]), &nfiles,
                             &ndecl, &v);
    if (rc)
        return rc;
    rc = gate_require_scanned(nfiles, HSW2_FILE_FLOOR, "check-no-snapshot-struct-memcmp --self-test",
                              "the real-tree leg of --self-test scanned too few files");
    if (rc)
        return rc;
    rc = gate_require_scanned(ndecl, HSW2_DECL_FLOOR, "check-no-snapshot-struct-memcmp --self-test",
                              "the real-tree leg of --self-test parsed too few declarations");
    if (rc)
        return rc;
    if (v.n > 0) {
        fputs("FAIL: --self-test — the REAL tree has a violation; the three\n", stderr);
        fputs("  known sites (fixed in 44c45f255) should be clean:\n", stderr);
        int wrc = hsw2_print_prefixed(stderr, v.buf, v.len, "    ");
        return wrc ? wrc : 1;
    }
    return printf("  ok: --self-test real tree — %d file(s), %d declaration(s), "
                 "0 violations\n", nfiles, ndecl) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_snapshot_struct_memcmp_selftest(void)
{
    struct hsw2_re re;
    int rc = hsw2_compile(&re);
    if (rc)
        return rc;
    const char *td = env_or("TMPDIR", "test-tmp");
    (void)csr_mkdirs("test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/no-snapshot-struct-memcmp-selftest.XXXXXX",
                     td), sizeof tmpl)) {
        hsw2_free(&re);
        return 2;
    }
    char *work = mkdtemp(tmpl);
    if (!work) {
        hsw2_free(&re);
        return die("z23-lint: mkdir failed: %s\n", td);
    }
    int f_rc = hsw2_st_fixture(work, &re);
    if (f_rc == 2) {
        (void)rap_rm_rf(work);
        hsw2_free(&re);
        return 2;
    }
    int cl = rap_rm_rf(work);
    int r_rc = hsw2_st_real(&re);
    hsw2_free(&re);
    if (r_rc == 2)
        return 2;
    if (f_rc || cl || r_rc)
        return 1;
    return st_ok(0, "  OK: check-no-snapshot-struct-memcmp --self-test\n");
}
