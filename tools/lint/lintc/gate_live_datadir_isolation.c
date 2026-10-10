/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: preserve the three source-only live-datadir isolation checks,
 * per-file shrink-only counts, scan floors and baseline analysis comments.
 * A counts matching lines, B checks direct getter/setter spelling per file,
 * C counts each derived leaf spelling per line; none proves call-graph safety.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_live_datadir_isolation_priv.h"

static const char k_gate[] = "check_live_datadir_isolation";
static struct ldi_scan scan;

static int ldi_find(struct ldi_rows *r, const char *path)
{
    for (int i = 0; i < r->n; i++)
        if (!strcmp(r->row[i].path, path)) return i;
    if (r->n == LDI_MAX || strlen(path) >= LDI_PATH)
        return -die("z23-lint: live-datadir row capacity exceeded: %s\n", path);
    int i = r->n++;
    memset(&r->row[i], 0, sizeof r->row[i]);
    strcpy(r->row[i].path, path);
    return i;
}

static int ldi_add(struct ldi_rows *r, const char *path, int count)
{
    int i = ldi_find(r, path);
    if (i < 0) return 2;
    if (r->row[i].count > INT_MAX - count)
        return die("z23-lint: live-datadir count overflow: %s\n", path);
    r->row[i].count += count;
    return 0;
}

static int ldi_number(const char *s, int *n)
{
    if (!s[0]) return 2;
    unsigned long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || v > (unsigned long)(INT_MAX - (*s - '0')) / 10)
            return 2;
        v = v * 10 + (unsigned)(*s - '0');
    }
    *n = (int)v;
    return 0;
}

static int ldi_env_number(const char *name, const char *fallback, int *n)
{
    const char *v = env_or(name, fallback);
    if (ldi_number(v, n))
        return die("z23-lint: invalid nonnegative integer for %s\n", name);
    return 0;
}

int ldi_patterns(struct ldi_scan *s)
{
    return pair_comp(&s->path, REG_EXTENDED, "(%s|\\$HOME|~)/\\.zclassic(-c23)?\"", "", "", "",
                     &s->get, REG_EXTENDED, "(^|[^[:alnum:]_])Get(Default)?DataDir[[:space:]]*\\(", "", "", "")
        || compile_pat(&s->set, REG_EXTENDED, "(^|[^[:alnum:]_])SetDataDir[[:space:]]*\\(", "", "", "");
}

int ldi_test_file(const char *path, void *ctx)
{
    struct ldi_scan *s = ctx;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0, get = 0, set = 0;
    s->tests++;
    while (getline(&line, &cap, f) >= 0) {
        if (!regexec(&s->path, line, 0, NULL, 0) && ldi_add(&s->a, path, 1)) { rc = 2; break; }
        get |= regexec(&s->get, line, 0, NULL, 0) == 0;
        set |= regexec(&s->set, line, 0, NULL, 0) == 0;
    }
    if (!rc && get && !set) {
        if (s->unpinned == LDI_MAX || strlen(path) >= LDI_PATH) return fin(f, line, path, die("z23-lint: unpinned caller capacity exceeded: %s\n", path));
        strcpy(s->b[s->unpinned], path);
        s->unpinned++;
    }
    return fin(f, line, path, rc);
}

/* Same textual normalization as the shell derivation, including escaped
 * quotes and whitespace; argument boundaries use the shared macro splitter. */
static int ldi_arg(const char *record, int arg, char *out, size_t cap)
{
    int off = 0, len = 0;
    if (lint_macro_arg(record, arg, &off, &len) < arg) { out[0] = '\0'; return 0; }
    size_t n = 0;
    for (int i = 0; i < len; i++) {
        char c = record[off + i];
        if (c == '\\' && i + 1 < len && record[off + i + 1] == '"') { i++; continue; }
        if (c == '"' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (n + 1 >= cap) return die("z23-lint: derived buffer overflow\n", "");
        out[n++] = c;
    }
    out[n] = '\0';
    return 0;
}

static int ldi_leaf(struct ldi_scan *s, const char *record)
{
    char name[LDI_PATH], keys[LDI_RECORD];
    if (ldi_arg(record, 1, name, sizeof name) || ldi_arg(record, 10, keys, sizeof keys)) return 2;
    char *save = NULL;
    for (char *p = strtok_r(keys, ",", &save); p; p = strtok_r(NULL, ",", &save))
        if (!strcmp(p, "datadir")) return ldi_add(&s->leaves, name, 0);
    return 0;
}

static int ldi_macro_start(const char *line, const char **rest)
{
    const char *p = line;
    if (strncmp(p, "ZCL_COMMAND_", 12)) return 0;
    p += 12;
    const char *start = p;
    while ((*p >= 'A' && *p <= 'Z') || *p == '_') p++;
    if (p == start || *p != '(') return 0;
    *rest = p + 1;
    return 1;
}

static int ldi_depth(const char *record)
{
    int depth = 0, quote = 0, escape = 0;
    for (const char *p = record; *p; p++) {
        if (escape) { escape = 0; continue; }
        if (quote) {
            if (*p == '\\') escape = 1;
            else if (*p == '"') quote = 0;
        } else if (*p == '"') quote = 1;
        else if (*p == '(') depth++;
        else if (*p == ')') depth--;
    }
    return depth;
}

/* awk sub removes the first same-line block comment, greedily. */
static void ldi_strip_inline_comment(const char *p)
{
    char *comment = strstr(p, "/*"), *last = NULL;
    if (!comment) return;
    for (char *q = comment; (q = strstr(q, "*/")); q += 2) last = q;
    if (!last) return;
    char *begin = comment;
    while (begin > p && (begin[-1] == ' ' || begin[-1] == '\t')) begin--;
    char *end = last + 2;
    while (*end == ' ' || *end == '\t') end++;
    *begin = ' ';
    memmove(begin + 1, end, strlen(end) + 1);
}
int ldi_derive(const char *path, void *ctx)
{
    struct ldi_scan *s = ctx;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char record[LDI_RECORD] = "", *line = NULL;
    size_t cap = 0, used = 0;
    int collecting = 0, rc = 0;
    s->defs++;
    while (getline(&line, &cap, f) >= 0) {
        const char *p = line;
        if (ldi_macro_start(line, &p)) {
            if (used && ldi_leaf(s, record)) { rc = 2; break; }
            collecting = 1; used = 0; record[0] = '\0';
        }
        if (!collecting) continue;
        ldi_strip_inline_comment(p);
        size_t n = strlen(p);
        if (used + n + 2 >= sizeof record) { rc = die("z23-lint: derived buffer overflow\n", ""); break; }
        record[used++] = ' '; memcpy(record + used, p, n + 1); used += n;
        if (ldi_depth(record) < 0) {
            char *end = strrchr(record, ')');
            if (end) *end = '\0';
            rc = ldi_leaf(s, record);
            used = 0; record[0] = '\0'; collecting = 0;
            if (rc) break;
        }
    }
    if (!rc && used) rc = ldi_leaf(s, record);
    return fin(f, line, path, rc);
}

static int ldi_doc_line(struct ldi_scan *s, const char *path, const char *line)
{
    for (int i = 0; i < s->leaves.n; i++) {
        char leaf[LDI_PATH];
        strcpy(leaf, s->leaves.row[i].path);
        for (char *q = leaf; *q; q++) if (*q == '.') *q = ' ';
        const char *names[] = { "z23", "z23-dev", "zclassic23" };
        for (size_t j = 0; j < sizeof names / sizeof names[0]; j++) {
            char needle[LDI_PATH + 16];
            int n = snprintf(needle, sizeof needle, "%s %s", names[j], leaf);
            if (ovf(n, sizeof needle)) return 2;
            if (strstr(line, needle) && ldi_add(&s->c, path, 1)) return 2;
        }
    }
    return 0;
}

int ldi_doc_file(const char *path, void *ctx)
{
    struct ldi_scan *s = ctx;
    if (!strcmp(path, "tools/lint/check_live_datadir_isolation.sh") ||
        (!strncmp(path, "tools/lint/live_datadir_", 23) && strstr(path, "_baseline.txt"))) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    const char *ext = strrchr(path, '.');
    while (getline(&line, &cap, f) >= 0) {
        const char *p = line;
        if (ext && !strcmp(ext, ".sh")) {
            while (isspace((unsigned char)*p)) p++;
            if (*p == '#') continue;
        }
        if (strstr(line, "datadir")) continue;
        rc = ldi_doc_line(s, path, line);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}
static int ldi_globs(const char *patterns, int (*fn)(const char *, void *), void *ctx)
{
    char *copy = strdup(patterns); // raw-alloc-ok:lint-runtime
    if (!copy) return die("z23-lint: out of memory\n", "");
    char *save = NULL;
    int rc = 0;
    for (char *p = strtok_r(copy, " \t\n", &save); p && !rc; p = strtok_r(NULL, " \t\n", &save)) {
        glob_t g = {0};
        int gr = glob(p, 0, NULL, &g);
        if (gr != 0 && gr != GLOB_NOMATCH) rc = die("z23-lint: glob failed: %s\n", p);
        for (size_t i = 0; !rc && i < g.gl_pathc; i++) rc = fn(g.gl_pathv[i], ctx);
        globfree(&g);
    }
    free(copy);
    return rc;
}

static int ldi_collect_doc(const char *path, void *ctx)
{
    struct ldi_scan *s = ctx;
    if (s->docs == LDI_MAX || strlen(path) >= LDI_PATH)
        return die("z23-lint: doc scan capacity exceeded: %s\n", path);
    strcpy(s->doc_paths[s->docs++], path);
    return 0;
}
static int ldi_defs(const char *dir, struct ldi_scan *s)
{
    char quoted[LDI_PATH * 4], cmd[LDI_PATH * 4 + 96];
    if (sh_single_quote(dir, quoted, sizeof quoted)) return 2;
    int n = snprintf(cmd, sizeof cmd, "find %s -type f -name '*.def' -print0", quoted);
    if (ovf(n, sizeof cmd) || each_zpath(cmd, ldi_derive, s)) return 2;
    return gate_require_scanned(s->defs, 1, k_gate, "no *.def under command definition scan root");
}

static int ldi_baseline_row(struct ldi_rows *rows, const char *path, char *line)
{
    char comment[2048] = "";
    char *hash = strchr(line, '#');
    if (hash) {
        if (strlen(hash) >= sizeof comment) return die("z23-lint: derived buffer overflow\n", "");
        strcpy(comment, hash); comment[strcspn(comment, "\n")] = '\0'; *hash = '\0';
    }
    char *p = line;
    while (isspace((unsigned char)*p)) p++;
    char *end = p + strlen(p);
    while (end > p && isspace((unsigned char)end[-1])) *--end = '\0';
    if (!*p) return 0;
    char *value = strrchr(p, ' '), *key_end = strchr(p, ' ');
    value = value ? value + 1 : p;
    int count = 0;
    if (ldi_number(value, &count)) {
        fprintf(stderr, "[%s] FATAL — baseline row '%s' has non-numeric count '%s' in %s\n", k_gate, p, value, path);
        return 2;
    }
    if (key_end) *key_end = '\0';
    int i = ldi_find(rows, p);
    if (i < 0) return 2;
    rows->row[i].base = count;
    rows->row[i].pinned = 1;
    if (*comment) strcpy(rows->row[i].comment, comment);
    return 0;
}

static int ldi_baseline(struct ldi_rows *rows, const char *path)
{
    struct stat st;
    if (stat(path, &st)) {
        if (errno == ENOENT) return 0;
        return die("z23-lint: cannot inspect %s\n", path);
    }
    if (!S_ISREG(st.st_mode)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (!n || line[n - 1] != '\n') continue; /* bash while read ignores final unterminated row. */
        rc = ldi_baseline_row(rows, path, line);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}
static int ldi_path_order(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int ldi_row_order(const void *a, const void *b)
{
    return strcmp(((const struct ldi_row *)a)->path, ((const struct ldi_row *)b)->path);
}

static int ldi_totals(struct ldi_rows *rows, const char *path,
                      int *total, int *base_sum, int *files, int *stale)
{
    int grown = 0;
    *total = 0; *base_sum = 0; *files = 0; *stale = 0;
    for (int i = 0; i < rows->n; i++) {
        const struct ldi_row *r = &rows->row[i];
        if (*total > INT_MAX - r->count || *base_sum > INT_MAX - r->base)
            return -die("z23-lint: baseline sum overflow: %s\n", path);
        *total += r->count; *base_sum += r->base; *files += r->count != 0;
        grown += r->count > r->base;
        *stale += !r->count && r->pinned;
    }
    return grown;
}

static void ldi_report_grown(const struct ldi_rows *rows, const char *path,
                             const char *prong, int ceiling, int base_sum, int grown)
{
    if (!strcmp(prong, "A"))
        printf("\n[%s] PRONG A — %d new/grown live-datadir path(s) in test sources:\n", k_gate, grown);
    else
        printf("\n[%s] PRONG C — %d new/grown copyable invocation(s) of a\n        datadir-taking leaf with no --datadir:\n", k_gate, grown);
    int ceiling_printed = 0;
    for (int i = 0; i < rows->n; i++) {
        const struct ldi_row *r = &rows->row[i];
        if (r->count > r->base && base_sum > ceiling && !ceiling_printed && strcmp(path, r->path) < 0) {
            printf("  %s — baseline sum %d exceeds ceiling %d\n", path, base_sum, ceiling);
            ceiling_printed = 1;
        }
        if (r->count > r->base)
            printf("  %s — %d %s, baseline allows %d\n", r->path, r->count,
                   !strcmp(prong, "A") ? "live-datadir path(s)" : "datadir-leaf invocation(s) with no --datadir", r->base);
    }
    if (base_sum > ceiling && !ceiling_printed) printf("  %s — baseline sum %d exceeds ceiling %d\n", path, base_sum, ceiling);
    if (!strcmp(prong, "A"))
        puts("  A test must never spell the operator's live datadir. Build the path\n  under a tmp root (test_make_tmpdir) and pin it with SetDataDir().");
    else
        puts("  A leaf that accepts `datadir` falls back to the process datadir when\n  none is given, which is the operator's live node. Show the datadir in\n  the example: --datadir=/tmp/<fixture> (or a \"datadir\" input key).");
    printf("  Raising a number in %s is not a fix; counts may only shrink.\n", path);
}

static int ldi_report(struct ldi_rows *rows, const char *path, const char *prong, int ceiling,
                      int *total, int *base_sum, int *files)
{
    qsort(rows->row, (size_t)rows->n, sizeof rows->row[0], ldi_row_order);
    int stale = 0;
    int grown = ldi_totals(rows, path, total, base_sum, files, &stale);
    if (grown < 0) return grown;
    grown += *base_sum > ceiling;
    if (!strcmp(env_or("ZCL_LINT_MODE", "FAIL"), "UPDATE")) return grown + stale;
    if (grown) ldi_report_grown(rows, path, prong, ceiling, *base_sum, grown);
    if (stale) {
        printf("\n[%s] PRONG %s — %d stale baseline row(s); delete them from %s:\n", k_gate, prong, stale, path);
        for (int i = 0; i < rows->n; i++) {
            const struct ldi_row *r = &rows->row[i];
            if (!r->count && r->pinned) printf("  %s (baseline says %d, actual 0)\n", r->path, r->base);
        }
    }
    return grown + stale;
}
static void ldi_report_b(const struct ldi_scan *s)
{
    if (!s->unpinned || !strcmp(env_or("ZCL_LINT_MODE", "FAIL"), "UPDATE")) return;
    printf("\n[%s] PRONG B — %d test file(s) resolve the datadir but never pin it:\n", k_gate, s->unpinned);
    for (int i = 0; i < s->unpinned; i++) printf("  %s\n", s->b[i]);
    puts("  GetDataDir()/GetDefaultDataDir() with no SetDataDir() resolves to\n"
         "  ~/.zclassic-c23. On a host running a node there, the test reads the\n"
         "  LIVE datadir and can pass off real, unrelated bytes — this host\n"
         "  cannot detect that by running the test. Pin it:\n"
         "    char dd[256]; test_make_tmpdir(dd, sizeof dd, \"<group>\", \"datadir\");\n"
         "    SetDataDir(dd);\n"
         "  This prong is HARD and has no baseline: today the count is zero.");
}
static int ldi_write(const struct ldi_rows *rows, const char *path, const char *prong)
{
    FILE *f = fopen(path, "w");
    if (!f) return die("z23-lint: cannot write %s\n", path);
    fprintf(f, "# %s — prong %s baseline.\n", k_gate, prong);
    if (!strcmp(prong, "A")) {
        fputs("# Test sources that construct the operator's EXACT live datadir\n"
              "# path (<x>/.zclassic or <x>/.zclassic-c23, no suffix).\n#\n"
              "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK.\n"
              "# The trailing comment on each row is hand analysis (whose $HOME\n"
              "# the path is built from); regeneration preserves it.\n", f);
    } else {
        fputs("# Tracked docs/scripts that show an invocation of a leaf which\n"
              "# ACCEPTS a datadir input, without naming one — so a reader who\n"
              "# copies the line points it at the live node.\n#\n"
              "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK.\n"
              "# Fix a row by adding --datadir=/tmp/<fixture> to the example.\n"
              "# Trailing per-row comments are hand analysis; regeneration keeps them.\n", f);
    }
    fprintf(f, "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/%s.sh\n", k_gate);
    for (int i = 0; i < rows->n; i++) {
        const struct ldi_row *r = &rows->row[i];
        if (!r->count) continue;
        fprintf(f, "%s %d%s%s\n", r->path, r->count, r->comment[0] ? "   " : "", r->comment);
    }
    int rc = ferror(f) ? die("z23-lint: write failed: %s\n", path) : 0;
    if (fclose(f) && !rc) rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}
struct ldi_options {
    const char *a, *c, *tests, *docs, *defs, *mode;
    int af, cf, lf, ac, cc;
};

static int ldi_options_load(struct ldi_options *o)
{
    o->a = env_or("ZCL_LDI_BASELINE_A", "tools/lint/live_datadir_test_paths_baseline.txt");
    o->c = env_or("ZCL_LDI_BASELINE_C", "tools/lint/live_datadir_examples_baseline.txt");
    o->tests = env_or("ZCL_LDI_TEST_GLOBS", "tests/harness/src/*.c tests/harness/src/*.h tests/harness/include/test/*.h");
    o->docs = env_or("ZCL_LDI_DOC_GLOBS", "");
    o->defs = env_or("ZCL_LDI_DEF_DIR", "engine/composition/commands");
    o->mode = env_or("ZCL_LINT_MODE", "FAIL");
    if (ldi_env_number("ZCL_LDI_TEST_FLOOR", "300", &o->af) || ldi_env_number("ZCL_LDI_DOC_FLOOR", "200", &o->cf)
        || ldi_env_number("ZCL_LDI_LEAF_FLOOR", "20", &o->lf) || ldi_env_number("ZCL_LDI_CEILING_A", "8", &o->ac)
        || ldi_env_number("ZCL_LDI_CEILING_C", "13", &o->cc)) return 2;
    return 0;
}

static int ldi_scan_inputs(const struct ldi_options *o)
{
    int rc = ldi_globs(o->tests, ldi_test_file, &scan);
    if (!rc) rc = gate_require_scanned(scan.tests, o->af, k_gate, "test scan set is empty — did tests/harness/src move?");
    if (!rc) rc = *o->docs ? ldi_globs(o->docs, ldi_collect_doc, &scan)
                           : each_zpath("git ls-files -z '*.md' '*.sh'", ldi_collect_doc, &scan);
    if (!rc) rc = gate_require_scanned(scan.docs, o->cf, k_gate, "doc/script scan set is empty — did git ls-files stop matching?");
    if (!rc) rc = ldi_defs(o->defs, &scan);
    if (!rc) rc = gate_require_scanned(scan.leaves.n, o->lf, k_gate, "no datadir-taking leaves derived — the .def macro arity or input_keys slot changed");
    for (int i = 0; !rc && i < scan.docs; i++) rc = ldi_doc_file(scan.doc_paths[i], &scan);
    drop3(&scan.path, &scan.get, &scan.set);
    if (!rc) rc = ldi_baseline(&scan.a, o->a) || ldi_baseline(&scan.c, o->c) ? 2 : 0;
    return rc;
}

int check_live_datadir_isolation_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    scan.a.n = 0; scan.c.n = 0; scan.leaves.n = 0;
    scan.tests = 0; scan.docs = 0; scan.defs = 0; scan.unpinned = 0;
    struct ldi_options o;
    if (ldi_options_load(&o) || ldi_patterns(&scan)) return 2;
    int rc = ldi_scan_inputs(&o);
    if (rc) return rc;
    int at, ab, an, ct, cb, cn;
    int av = ldi_report(&scan.a, o.a, "A", o.ac, &at, &ab, &an);
    qsort(scan.b, (size_t)scan.unpinned, sizeof scan.b[0], ldi_path_order);
    ldi_report_b(&scan);
    int cv = ldi_report(&scan.c, o.c, "C", o.cc, &ct, &cb, &cn);
    if (av < 0 || cv < 0) return 2;
    if (!strcmp(o.mode, "UPDATE")) {
        if (ldi_write(&scan.a, o.a, "A") || ldi_write(&scan.c, o.c, "C")) return 2;
        printf("[%s] baselines UPDATED: %s (%d), %s (%d)\n", k_gate, o.a, at, o.c, ct);
        return 0;
    }
    if ((av || cv || scan.unpinned) && !strcmp(o.mode, "FAIL")) return 1;
    printf("[%s] PASS (%d test file(s): prong A %d site(s) in %d file(s), all baselined (%d/%d); prong B %d unpinned GetDataDir caller(s), HARD; %d doc/script file(s) vs %d datadir-taking leaves: prong C %d site(s) in %d file(s), all baselined (%d/%d))\n", k_gate, scan.tests, at, an, ab, o.ac, scan.unpinned, scan.docs, scan.leaves.n, ct, cn, cb, o.cc);
    return 0;
}
