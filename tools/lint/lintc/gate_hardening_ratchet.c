/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-hardening-ratchet. One extensible,
 * shrink-only ratchet for the memory-safety rules on untrusted input
 * (docs/DEFENSIVE_CODING.md, "Hardening rules for untrusted input").
 * Every finding carries a RULE id; the baseline holds `RULE PATH COUNT`
 * rows; a file may never exceed its baselined count for a rule (a file or
 * rule with no row has baseline 0). Fewer than baseline PASSES with a
 * "can tighten" note, so cleanup lanes never coordinate on the baseline.
 * A later rule is one scanner function plus one row in k_rules.
 *
 * Rules today:
 *   banned-str   calls to strcpy, strcat, sprintf, vsprintf, gets
 *   local-reader a struct definition named *_reader, *_cursor or *_rd
 * Scope: git-tracked *.c and *.h, minus vendor/, tests/ and tools/lint/.
 * Escape: `// hardening-ok: <reason>` on the same line (reason required).
 *
 * Modes: (default) check | --write-baseline | --selftest (main.c).
 *
 * Gates: check-hardening-ratchet
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"

enum { HR_MAX = 8192, HR_PATH = 512, HR_LINES = 6, HR_RULES = 2,
       HR_FILE_FLOOR = 400 };

struct hr_row {
    int rule;
    char path[HR_PATH];
    int count;
    int line[HR_LINES];
};

struct hr_set {
    struct hr_row v[HR_MAX];
    int n;
};

typedef int (*hr_scan_fn)(const char *scrubbed, size_t n);
struct hr_rule { const char *name; hr_scan_fn scan; };

static const char k_baseline_default[] =
    "tools/lint/hardening_ratchet_baseline.txt";

static int hr_idc(int c)
{
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z');
}

static size_t hr_skip_ws(const char *s, size_t i, size_t n)
{
    while (i < n && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return i;
}

/* ── rule banned-str ───────────────────────────────────────────────────── */

static int hr_banned_word(const char *w, size_t len)
{
    static const char *const k_ban[] = { "strcpy", "strcat", "sprintf",
                                         "vsprintf", "gets" };
    for (size_t i = 0; i < sizeof k_ban / sizeof k_ban[0]; i++)
        if (strlen(k_ban[i]) == len && memcmp(k_ban[i], w, len) == 0)
            return 1;
    return 0;
}

static int hr_scan_banned(const char *s, size_t n)
{
    int hits = 0;
    size_t i = 0;
    while (i < n) {
        if (!hr_idc((unsigned char)s[i])) {
            i++;
            continue;
        }
        size_t b = i;
        while (i < n && hr_idc((unsigned char)s[i]))
            i++;
        size_t j = hr_skip_ws(s, i, n);
        if (j < n && s[j] == '(' && hr_banned_word(s + b, i - b))
            hits++;
    }
    return hits;
}

/* ── rule local-reader ─────────────────────────────────────────────────── */

static int hr_reader_name(const char *w, size_t len)
{
    static const char *const k_suf[] = { "_reader", "_cursor", "_rd" };
    for (size_t i = 0; i < sizeof k_suf / sizeof k_suf[0]; i++) {
        size_t k = strlen(k_suf[i]);
        if (len > k && memcmp(w + len - k, k_suf[i], k) == 0)
            return 1;
    }
    return 0;
}

/* `struct NAME {` (or NAME at end of line when the line starts the
 * definition: the brace is on the next line). */
static int hr_struct_def_at(const char *s, size_t n, size_t kw, size_t end)
{
    size_t i = hr_skip_ws(s, end, n), b = i;
    while (i < n && hr_idc((unsigned char)s[i]))
        i++;
    if (i == b || !hr_reader_name(s + b, i - b))
        return 0;
    i = hr_skip_ws(s, i, n);
    if (i < n)
        return s[i] == '{';
    size_t p = hr_skip_ws(s, 0, n);
    return p == kw || (p + 8 <= kw && memcmp(s + p, "typedef ", 8) == 0
                       && hr_skip_ws(s, p + 7, n) == kw);
}

/* Column-0 `} NAME;` closing a typedef'd struct. */
static int hr_typedef_close(const char *s, size_t n)
{
    if (n == 0 || s[0] != '}')
        return 0;
    size_t i = hr_skip_ws(s, 1, n), b = i;
    while (i < n && hr_idc((unsigned char)s[i]))
        i++;
    if (i == b || !hr_reader_name(s + b, i - b))
        return 0;
    i = hr_skip_ws(s, i, n);
    return i < n && s[i] == ';';
}

static int hr_scan_reader(const char *s, size_t n)
{
    int hits = hr_typedef_close(s, n);
    size_t i = 0;
    while (i < n) {
        if (!hr_idc((unsigned char)s[i])) {
            i++;
            continue;
        }
        size_t b = i;
        while (i < n && hr_idc((unsigned char)s[i]))
            i++;
        if (i - b == 6 && memcmp(s + b, "struct", 6) == 0
            && (b == 0 || !hr_idc((unsigned char)s[b - 1]))
            && hr_struct_def_at(s, n, b, i))
            hits++;
    }
    return hits;
}

static const struct hr_rule k_rules[HR_RULES] = {
    { "banned-str", hr_scan_banned },
    { "local-reader", hr_scan_reader },
};

static int hr_rule_id(const char *name)
{
    for (int i = 0; i < HR_RULES; i++)
        if (strcmp(k_rules[i].name, name) == 0)
            return i;
    return -1;
}

/* ── escape comment ────────────────────────────────────────────────────── */

/* A reason is non-blank once a trailing block-comment closer and
 * surrounding whitespace are dropped. */
static int hr_reason_ok(const char *r)
{
    size_t n = strlen(r);
    while (n && (r[n - 1] == ' ' || r[n - 1] == '\t' || r[n - 1] == '\r'))
        n--;
    if (n >= 2 && r[n - 2] == '*' && r[n - 1] == '/')
        n -= 2;
    for (size_t i = 0; i < n; i++)
        if (r[i] != ' ' && r[i] != '\t')
            return 1;
    return 0;
}

/* `hardening-ok:` inside a comment with a non-empty reason. */
static int hr_has_hatch(const char *line)
{
    const char *p = strstr(line, "hardening-ok:");
    if (!p)
        return 0;
    const char *c1 = strstr(line, "//"), *c2 = strstr(line, "/*");
    if ((!c1 || c1 > p) && (!c2 || c2 > p))
        return 0;
    return hr_reason_ok(p + strlen("hardening-ok:"));
}

/* ── set of (rule, path) counts ────────────────────────────────────────── */

static struct hr_row *hr_find(struct hr_set *s, int rule, const char *path)
{
    for (int i = 0; i < s->n; i++)
        if (s->v[i].rule == rule && strcmp(s->v[i].path, path) == 0)
            return &s->v[i];
    return NULL;
}

static struct hr_row *hr_get(struct hr_set *s, int rule, const char *path)
{
    struct hr_row *r = hr_find(s, rule, path);
    if (r)
        return r;
    if (s->n >= HR_MAX || strlen(path) >= HR_PATH) {
        die("z23-lint: check-hardening-ratchet: row table overflow\n", "");
        return NULL;
    }
    r = &s->v[s->n++];
    memset(r, 0, sizeof *r);
    r->rule = rule;
    memcpy(r->path, path, strlen(path) + 1);
    return r;
}

static int hr_note(struct hr_set *s, int rule, const char *path, int lineno,
                   int hits)
{
    struct hr_row *r = hr_get(s, rule, path);
    if (!r)
        return 2;
    for (int k = 0; k < hits; k++) {
        if (r->count < HR_LINES)
            r->line[r->count] = lineno;
        r->count++;
    }
    return 0;
}

/* Scan one in-memory line of a file; `st` carries block-comment state. */
static int hr_scan_line(struct hr_set *s, struct cstrip *st, const char *path,
                        const char *line, size_t n, int lineno)
{
    char scrubbed[CSTRIP_LINE_MAX];
    if (!cstrip_line(st, line, n, scrubbed, sizeof scrubbed))
        return 0;
    if (hr_has_hatch(line))
        return 0;
    for (int r = 0; r < HR_RULES; r++) {
        int hits = k_rules[r].scan(scrubbed, n);
        if (hits && hr_note(s, r, path, lineno, hits))
            return 2;
    }
    return 0;
}

/* Scan a whole text buffer (selftest entry point and file bodies). */
static int hr_scan_text(struct hr_set *s, const char *path, const char *text)
{
    struct cstrip st = { 0 };
    int lineno = 0, rc = 0;
    const char *p = text;
    while (rc == 0 && *p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        lineno++;
        if (n < CSTRIP_LINE_MAX) {
            char buf[CSTRIP_LINE_MAX];
            memcpy(buf, p, n);
            buf[n] = '\0';
            rc = hr_scan_line(s, &st, path, buf, n, lineno);
        }
        p = nl ? nl + 1 : p + n;
    }
    return rc;
}

static int hr_scan_file(struct hr_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: check-hardening-ratchet: cannot open %s\n",
                   path);
    struct cstrip st = { 0 };
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int lineno = 0, rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        size_t n = (size_t)nread;
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        lineno++;
        rc = hr_scan_line(s, &st, path, line, n, lineno);
    }
    return fin(f, line, path, rc);
}

/* ── tracked-file collection ───────────────────────────────────────────── */

static int hr_in_scope(const char *path)
{
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.' || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    if (strncmp(path, "vendor/", 7) == 0 || strncmp(path, "tests/", 6) == 0
        || strncmp(path, "tools/lint/", 11) == 0)
        return 0;
    return strstr(path, "/vendor/") == NULL;
}

struct hr_files { struct hr_set *set; int nfiles; };

static int hr_on_index(const char *path, int stage, void *vctx)
{
    struct hr_files *fc = vctx;
    (void)stage;
    if (!hr_in_scope(path))
        return 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    fc->nfiles++;
    return hr_scan_file(fc->set, path);
}

/* ── baseline ──────────────────────────────────────────────────────────── */

static int hr_base_line(struct hr_set *b, char *line)
{
    char rule[64], path[HR_PATH];
    int count;
    char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '#')
        return 0;
    if (sscanf(p, "%63s %511s %d", rule, path, &count) != 3 || count < 0)
        return die("z23-lint: check-hardening-ratchet: bad baseline row: %s\n",
                   p);
    int id = hr_rule_id(rule);
    if (id < 0)
        return die("z23-lint: check-hardening-ratchet: unknown rule: %s\n",
                   rule);
    if (hr_find(b, id, path))
        return die("z23-lint: check-hardening-ratchet: duplicate row: %s\n",
                   path);
    struct hr_row *r = hr_get(b, id, path);
    if (!r)
        return 2;
    r->count = count;
    return 0;
}

static int hr_base_load(struct hr_set *b, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* a missing baseline is an empty one */
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        size_t n = (size_t)nread;
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = hr_base_line(b, line);
    }
    return fin(f, line, path, rc);
}

static int hr_row_cmp(const void *a, const void *b)
{
    const struct hr_row *x = a, *y = b;
    int c = strcmp(k_rules[x->rule].name, k_rules[y->rule].name);
    return c ? c : strcmp(x->path, y->path);
}

static int hr_write_baseline(struct hr_set *live, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: check-hardening-ratchet: cannot write %s\n",
                   path);
    qsort(live->v, (size_t)live->n, sizeof live->v[0], hr_row_cmp);
    fputs("# check-hardening-ratchet baseline: `RULE PATH COUNT` rows, sorted.\n"
          "# COUNTS MAY ONLY SHRINK. A file or rule with no row has baseline 0.\n"
          "# Fewer findings than a row passes and prints a tighten note;\n"
          "# lower the number (or delete the row) when you clean a file up.\n"
          "# Adding a row or raising a number is not a fix; mark a justified\n"
          "# line in place with `// hardening-ok: <reason>` instead.\n"
          "# Rules: banned-str (strcpy strcat sprintf vsprintf gets),\n"
          "#        local-reader (struct *_reader, *_cursor, *_rd definitions).\n"
          "# core/ rows are counted and frozen like the rest of core/.\n"
          "# Regenerate: z23-lint check-hardening-ratchet --write-baseline\n",
          f);
    for (int i = 0; i < live->n; i++)
        fprintf(f, "%s %s %d\n", k_rules[live->v[i].rule].name,
                live->v[i].path, live->v[i].count);
    if (fclose(f) != 0)
        return die("z23-lint: check-hardening-ratchet: write failed %s\n",
                   path);
    return 0;
}

/* ── judgement ─────────────────────────────────────────────────────────── */

static void hr_print_over(const struct hr_row *l, int allowed, FILE *out)
{
    fprintf(out, "  %s %s: %d finding(s), baseline %d\n",
            k_rules[l->rule].name, l->path, l->count, allowed);
    for (int k = 0; k < l->count && k < HR_LINES; k++)
        fprintf(out, "      %s:%d\n", l->path, l->line[k]);
}

/* Compare live counts to the baseline; returns 1 on any file over its
 * baseline. Tighten notes go to `out`; they never fail. */
static int hr_judge(struct hr_set *live, struct hr_set *base, FILE *out)
{
    int over = 0, tighten = 0, total = 0;
    for (int i = 0; i < live->n; i++) {
        const struct hr_row *l = &live->v[i];
        const struct hr_row *b = hr_find(base, l->rule, l->path);
        int allowed = b ? b->count : 0;
        total += l->count;
        if (l->count > allowed) {
            if (!over)
                fputs("[check_hardening_ratchet] FAIL — over baseline:\n",
                      out);
            hr_print_over(l, allowed, out);
            over++;
        }
    }
    for (int i = 0; i < base->n; i++) {
        const struct hr_row *b = &base->v[i];
        const struct hr_row *l = hr_find(live, b->rule, b->path);
        int now = l ? l->count : 0;
        if (now < b->count) {
            fprintf(out, "can tighten: %s %s %d->%d\n",
                    k_rules[b->rule].name, b->path, b->count, now);
            tighten++;
        }
    }
    if (over) {
        fputs("  Use snprintf with a truncation check / a stream_read_* "
              "reader, or mark the line\n  // hardening-ok: <reason>. "
              "Raising a baseline number is NOT a fix.\n", out);
        return 1;
    }
    fprintf(out, "[check_hardening_ratchet] PASS (%d finding(s), %d row(s) "
            "can tighten)\n", total, tighten);
    return 0;
}

/* ── entry points ──────────────────────────────────────────────────────── */

int check_hardening_ratchet_run(int argc, char **argv)
{
    static struct hr_set live, base;
    struct hr_files fc = { &live, 0 };
    char bad[8] = { 0 };
    const char *bpath = k_baseline_default;
    int write = argc >= 1 && strcmp(argv[0], "--write-baseline") == 0;
    int rc = lint_git_index_foreach(hr_on_index, &fc, bad);
    if (rc)
        return rc;
    rc = gate_require_scanned(fc.nfiles, HR_FILE_FLOOR,
                              "check_hardening_ratchet",
                              "too few tracked .c/.h files scanned");
    if (rc)
        return rc;
    if (write) {
        rc = hr_write_baseline(&live, bpath);
        if (rc == 0)
            printf("[check_hardening_ratchet] baseline written: %s "
                   "(%d rows)\n", bpath, live.n);
        return rc;
    }
    rc = hr_base_load(&base, bpath);
    return rc ? rc : hr_judge(&live, &base, stdout);
}

/* ── selftest ──────────────────────────────────────────────────────────── */

static int hr_st_fails;

/* Scan `text` as file `path`, judge against baseline rows `brows`
 * ("RULE PATH COUNT\n" text), expect `want_rc`, and (optionally) that the
 * judgement output contains `want_out`. */
static void hr_st_case(const char *tag, const char *path, const char *text,
                       const char *brows, int want_rc, const char *want_out)
{
    static struct hr_set live, base;
    static char outbuf[8192];
    live.n = base.n = 0;
    int rc = hr_scan_text(&live, path, text);
    char *copy = strdup(brows); // raw-alloc-ok:lint-runtime
    for (char *l = copy ? strtok(copy, "\n") : NULL; l && rc == 0;
         l = strtok(NULL, "\n"))
        rc = hr_base_line(&base, l);
    free(copy);
    FILE *o = fmemopen(outbuf, sizeof outbuf - 1, "w");
    if (!o || rc) {
        printf("hardening-ratchet selftest FAIL: %s (setup rc=%d)\n", tag, rc);
        hr_st_fails++;
        if (o)
            fclose(o);
        return;
    }
    rc = hr_judge(&live, &base, o);
    fclose(o);
    int ok = rc == want_rc && (!want_out || strstr(outbuf, want_out));
    printf("hardening-ratchet selftest %s: %s\n", ok ? "ok" : "FAIL", tag);
    hr_st_fails += !ok;
}

static void hr_st_banned(void)
{
    hr_st_case("new strcpy in a new file fails", "new/a.c",
               "void f(char *d, char *s) { strcpy(d, s); }\n", "", 1,
               "banned-str new/a.c: 1");
    hr_st_case("strcat sprintf vsprintf gets all match", "new/b.c",
               "strcat(a,b);\nsprintf (a,b);\nvsprintf(a,b,c);\ngets(a);\n",
               "", 1, "4 finding(s), baseline 0");
    hr_st_case("snprintf strncpy my_strcpy_x strcpy_s do not match",
               "new/c.c",
               "snprintf(a,1,b);\nstrncpy(a,b,1);\nmy_strcpy_x(a);\n"
               "strcpy_s(a,b);\nvsnprintf(a,1,b,c);\nint gets_n = 1;\n",
               "", 0, "PASS");
    hr_st_case("strcpy in a line comment, block comment, string ignored",
               "new/d.c",
               "// strcpy(a,b);\n/* sprintf(a,b);\n   gets(a); */\n"
               "puts(\"strcpy(a,b)\");\nchar c = 'x';\n", "", 0, "PASS");
}

static void hr_st_escape(void)
{
    hr_st_case("hardening-ok with reason exempts", "new/e.c",
               "strcpy(d, s); // hardening-ok: fixed 4-byte literal\n", "",
               0, "PASS");
    hr_st_case("hardening-ok block form with reason exempts", "new/e2.c",
               "strcpy(d, s); /* hardening-ok: sized above */\n", "", 0,
               "PASS");
    hr_st_case("hardening-ok with empty reason does not", "new/f.c",
               "strcpy(d, s); // hardening-ok:\n", "", 1, "FAIL");
    hr_st_case("hardening-ok with blank block reason does not", "new/f2.c",
               "strcpy(d, s); /* hardening-ok: */\n", "", 1, "FAIL");
}

static void hr_st_baseline(void)
{
    hr_st_case("count equal to baseline passes", "old/g.c",
               "strcpy(a,b);\nstrcpy(a,b);\n", "banned-str old/g.c 2\n", 0,
               "PASS");
    hr_st_case("count above baseline fails", "old/g2.c",
               "strcpy(a,b);\nstrcpy(a,b);\n", "banned-str old/g2.c 1\n", 1,
               "2 finding(s), baseline 1");
    hr_st_case("count below baseline passes with tighten note", "old/h.c",
               "strcpy(a,b);\n", "banned-str old/h.c 3\n", 0,
               "can tighten: banned-str old/h.c 3->1");
    hr_st_case("fully cleaned file notes tighten to 0", "old/i.c",
               "int x;\n", "banned-str old/i.c 2\n", 0,
               "can tighten: banned-str old/i.c 2->0");
}

static void hr_st_reader(void)
{
    hr_st_case("new struct x_reader definition fails", "new/j.h",
               "struct x_reader {\n    int pos;\n};\n", "", 1,
               "local-reader new/j.h: 1");
    hr_st_case("struct x_cursor and x_rd definitions fail", "new/j2.h",
               "struct a_cursor {\n};\nstruct b_rd\n{\n};\n", "", 1,
               "2 finding(s)");
    hr_st_case("typedef closing } x_reader; fails", "new/j3.h",
               "typedef struct {\n    int p;\n} blob_reader;\n", "", 1,
               "local-reader new/j3.h: 1");
    hr_st_case("uses of struct x_reader do not count", "new/k.c",
               "struct x_reader *r;\nstatic struct x_reader mk(void);\n"
               "struct x_reader;\ntypedef struct x_reader x_reader_t;\n"
               "void f(struct x_reader *r, struct y_rd z);\n"
               "static struct x_reader\nmake(void);\n", "", 0, "PASS");
    hr_st_case("non-reader struct and comment mention do not count",
               "new/l.c",
               "struct reader_state {\n};\n// struct x_reader {\n", "", 0,
               "PASS");
    hr_st_case("reader baseline tracks per rule", "old/m.h",
               "struct q_reader {\n};\n", "banned-str old/m.h 1\n", 1,
               "local-reader old/m.h");
}

int check_hardening_ratchet_selftest(void)
{
    hr_st_fails = 0;
    hr_st_banned();
    hr_st_escape();
    hr_st_baseline();
    hr_st_reader();
    if (hr_st_fails) {
        printf("check_hardening_ratchet selftest: FAIL — %d case(s)\n",
               hr_st_fails);
        return 1;
    }
    puts("check_hardening_ratchet selftest: PASS");
    return 0;
}
