/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-no-bare-tmp-fixture. Forbids a NEW string
 * literal starting with the system temp directory (opening exactly
 * quote-slash-t-m-p-slash, or the bare four-letter form closed immediately)
 * inside tests/harness/, tools/lint/lintc/, engine/, or tools/command/:
 * those pile up as stale entries in the shared system scratch directory
 * across any run that aborts before its own cleanup runs, instead of living
 * under the repo's own test-tmp/ (see test_core.h's test_mkdtemp(),
 * test_mkstemp(), and test_fmt_tmpdir()).
 *
 * A file's live site count is pinned in a shrink-only baseline
 * (tools/lint/no_bare_tmp_fixture_baseline.txt, "<path> <count>" rows,
 * one per line): a file whose live count exceeds its pin FAILS as new/
 * grown, a pinned file with zero live sites FAILS as stale (delete its
 * row), and anything at or under its pin passes silently. Regenerate the
 * baseline after a deliberate sweep with
 *   build/bin/z23-lint check-no-bare-tmp-fixture --write-baseline
 *
 * The comment exemption is anchored at the match's own offset: each line is
 * passed through a stripper that blanks // and block comments in place but
 * leaves string literal BODIES untouched, so a mention in prose or a
 * commented-out line never counts, while a live literal always does — the
 * scan never has to guess.
 *
 * Tracked files via lint_git_index_foreach; .git probe first, filesystem
 * walk (walk_src) as the fallback when .git is absent — same idiom as
 * gate_no_new_repair_rung.c. Selftest sandboxes a throwaway fixture tree
 * under getenv("TMPDIR") else ./test-tmp (never /tmp itself: this gate
 * would be a hypocrite otherwise), forcing the filesystem-walk path so the
 * fixture never has to live inside a git index.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { NTF_MAX = 1024, NTF_LINEBUF = CSTRIP_LINE_MAX, NTF_KEEP_LINES = 4 };
enum { NTF_SCAN_FLOOR = 2800 };

static const char k_ntf_baseline[] = "tools/lint/no_bare_tmp_fixture_baseline.txt";
static const char k_ntf_self[] = "tools/lint/lintc/gate_no_bare_tmp_fixture.c";
static const char *const k_ntf_roots[] = {
    "tests/harness", "tools/lint/lintc", "engine", "tools/command"
};
enum { NTF_NROOT = (int)(sizeof k_ntf_roots / sizeof k_ntf_roots[0]) };

struct ntf_row {
    char path[RS_PATH];
    int count;
    int lines[NTF_KEEP_LINES];
    int nlines;
};
struct ntf_set { struct ntf_row v[NTF_MAX]; int n; };

/* ── the row set ──────────────────────────────────────────────────────── */

static int ntf_find(const struct ntf_set *s, const char *path)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i].path, path) == 0) return i;
    return -1;
}

static int ntf_bump(struct ntf_set *s, const char *path, int lineno)
{
    int i = ntf_find(s, path);
    if (i < 0) {
        if (s->n >= NTF_MAX)
            return die("z23-lint: no-bare-tmp-fixture overflow\n", "");
        if (ovf((int)strlen(path), sizeof s->v[0].path)) return 2;
        i = s->n++;
        memcpy(s->v[i].path, path, strlen(path) + 1);
        s->v[i].count = 0;
        s->v[i].nlines = 0;
    }
    s->v[i].count++;
    if (s->v[i].nlines < NTF_KEEP_LINES)
        s->v[i].lines[s->v[i].nlines++] = lineno;
    return 0;
}

static int ntf_under(const char *path, const char *const *roots, int nr)
{
    for (int i = 0; i < nr; i++) {
        size_t k = strlen(roots[i]);
        if (strncmp(path, roots[i], k) == 0
            && (path[k] == '/' || path[k] == '\0'))
            return 1;
    }
    return 0;
}

static int ntf_is_ch(const char *path)
{
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.') return 0;
    return path[n - 1] == 'c' || path[n - 1] == 'h';
}

/* ── comment-aware scan: strings kept intact, comments blanked ─────────── */

struct ntf_cs { int in_block; };

static size_t ntf_pass_literal(const char *line, size_t n, char *out,
                               size_t i, char q)
{
    out[i] = line[i];
    i++;
    while (i < n && line[i] != q) {
        if (line[i] == '\\' && i + 1 < n) {
            out[i] = line[i];
            out[i + 1] = line[i + 1];
            i += 2;
            continue;
        }
        out[i] = line[i];
        i++;
    }
    if (i < n) {
        out[i] = line[i];
        i++;
    }
    return i;
}

static size_t ntf_in_block(const char *line, size_t n, char *out, size_t i,
                           int *in_block)
{
    if (line[i] == '*' && i + 1 < n && line[i + 1] == '/') {
        out[i] = ' ';
        out[i + 1] = ' ';
        *in_block = 0;
        return i + 2;
    }
    out[i] = ' ';
    return i + 1;
}

/* Blank //-line-comments and block comments (state persists across calls
 * via *st, for one that spans lines) out of `line`, but leave "..."/'...'
 * literal BODIES untouched — the inverse of lib.c's cstrip_line, which
 * blanks literal bodies too and would hide the very sites this gate looks
 * for. */
static int ntf_strip(struct ntf_cs *st, const char *line, size_t n,
                     char *out, size_t cap)
{
    if (n >= cap) return 0;
    size_t i = 0;
    while (i < n) {
        if (st->in_block) {
            i = ntf_in_block(line, n, out, i, &st->in_block);
            continue;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '/') {
            while (i < n) { out[i] = ' '; i++; }
            break;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '*') {
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            st->in_block = 1;
            continue;
        }
        if (line[i] == '"' || line[i] == '\'') {
            i = ntf_pass_literal(line, n, out, i, line[i]);
            continue;
        }
        out[i] = line[i];
        i++;
    }
    out[n] = '\0';
    return 1;
}

/* A hit is a string literal that OPENS with the four bytes "tmp" right
 * after the leading quote and a slash, either continuing ("/tmp/...) or
 * closing immediately (exactly "/tmp"). Plain byte comparison — POSIX ERE
 * buys nothing a fixed 6-byte window does not already give for free. */
static int ntf_hit_at(const char *s)
{
    if (s[0] != '"' || s[1] != '/' || s[2] != 't' || s[3] != 'm'
        || s[4] != 'p')
        return 0;
    return s[5] == '/' || s[5] == '"';
}

static int ntf_count_hits(const char *line)
{
    int n = 0;
    for (const char *p = line; *p; p++)
        if (ntf_hit_at(p)) n++;
    return n;
}

/* ── one file ─────────────────────────────────────────────────────────── */

static int ntf_scan_file(const char *path, struct ntf_set *s)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr,
                "check-no-bare-tmp-fixture: UNPROVEN — cannot read %s\n",
                path);
        return 2;
    }
    struct ntf_cs cs = {0};
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    char stripped[NTF_LINEBUF];
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        const char *coded = ntf_strip(&cs, line, (size_t)n, stripped,
                                      sizeof stripped) ? stripped : line;
        int hits = ntf_count_hits(coded);
        for (int k = 0; k < hits && rc == 0; k++)
            rc = ntf_bump(s, path, lineno);
    }
    return fin(f, line, path, rc);
}

/* ── walking the tree (git index, or a filesystem walk fallback) ───────── */

struct ntf_walk_ctx {
    struct ntf_set *s;
    const char *const *roots;
    int nroots;
    const char *self;
    int considered;
};

static int ntf_visit(const char *path, void *ctxv)
{
    struct ntf_walk_ctx *c = ctxv;
    if (!ntf_is_ch(path) || lint_path_is_excluded(path)) return 0;
    if (c->self && c->self[0] && strcmp(path, c->self) == 0) return 0;
    if (c->nroots && !ntf_under(path, c->roots, c->nroots)) return 0;
    c->considered++;
    return ntf_scan_file(path, c->s);
}

static int ntf_on_idx(const char *path, int stage, void *ctx)
{
    (void)stage;
    return ntf_visit(path, ctx);
}

static int ntf_on_walk(const char *path, void *ctx)
{
    return ntf_visit(path, ctx);
}

static int ntf_collect(struct ntf_walk_ctx *c, int use_git)
{
    struct stat st;
    if (use_git && stat(".git", &st) == 0) {
        char bad[8] = {0};
        int rc = lint_git_index_foreach(ntf_on_idx, c, bad);
        if (rc)
            fprintf(stderr,
                    "check-no-bare-tmp-fixture: UNPROVEN — git index%s%s\n",
                    bad[0] ? " extension " : "", bad);
        return rc;
    }
    int rc = 0;
    for (int i = 0; rc == 0 && i < c->nroots; i++)
        rc = walk_src(c->roots[i], 1, ntf_on_walk, c);
    return rc;
}

/* ── the baseline ─────────────────────────────────────────────────────── */

/* Parse one already-newline-trimmed baseline line ("<path> <count>") into
 * *b. A blank or '#'-comment line is a silent no-op. Split out of
 * ntf_load_baseline() to keep that loop's own complexity low. */
static int ntf_load_line(struct ntf_set *b, char *buf)
{
    if (buf[0] == '\0' || buf[0] == '#') return 0;
    char *sp = strrchr(buf, ' ');
    if (!sp || sp == buf)
        return die("z23-lint: malformed no-bare-tmp-fixture baseline row: "
                   "%s\n", buf);
    *sp = '\0';
    char *end = NULL;
    long v = strtol(sp + 1, &end, 10);
    if (!end || *end != '\0' || v < 0)
        return die("z23-lint: malformed no-bare-tmp-fixture baseline "
                   "count: %s\n", buf);
    if (ntf_find(b, buf) >= 0)
        return die("z23-lint: duplicate no-bare-tmp-fixture baseline row: "
                   "%s\n", buf);
    if (b->n >= NTF_MAX || ovf((int)strlen(buf), sizeof b->v[0].path))
        return die("z23-lint: no-bare-tmp-fixture baseline overflow\n", "");
    int i = b->n++;
    memcpy(b->v[i].path, buf, strlen(buf) + 1);
    b->v[i].count = (int)v;
    b->v[i].nlines = 0;
    return 0;
}

static int ntf_load_baseline(struct ntf_set *b, const char *path)
{
    b->n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[512];
    int rc = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n') buf[--n] = '\0';
        rc = ntf_load_line(b, buf);
    }
    fclose(f);
    return rc;
}

static int ntf_compare(FILE *err, const struct ntf_set *base,
                       const struct ntf_set *found, const char *baseline_path)
{
    int bad = 0;
    for (int i = 0; i < found->n; i++) {
        const struct ntf_row *r = &found->v[i];
        int bi = ntf_find(base, r->path);
        int pinned = bi >= 0 ? base->v[bi].count : 0;
        if (r->count <= pinned) continue;
        fprintf(err, "check-no-bare-tmp-fixture: NEW/GROWN — %s now has %d "
                     "bare-tmp fixture site(s) (baseline %d)\n",
                r->path, r->count, pinned);
        for (int k = 0; k < r->nlines; k++)
            fprintf(err, "  %s:%d\n", r->path, r->lines[k]);
        bad = 1;
    }
    for (int i = 0; i < base->n; i++) {
        if (ntf_find(found, base->v[i].path) >= 0) continue;
        fprintf(err, "check-no-bare-tmp-fixture: STALE — %s is baselined at "
                     "%d but has 0 live sites; delete its row from %s\n",
                base->v[i].path, base->v[i].count, baseline_path);
        bad = 1;
    }
    return bad;
}

static int ntf_cmp_row(const void *a, const void *b)
{
    return strcmp(((const struct ntf_row *)a)->path,
                  ((const struct ntf_row *)b)->path);
}

/* ── run / --write-baseline ───────────────────────────────────────────── */

static int ntf_run_cfg(const char *const *roots, int nroots,
                       const char *baseline_path, const char *self,
                       int use_git, int floor, FILE *out, FILE *err)
{
    struct ntf_set base = {0}, found = {0};
    struct ntf_walk_ctx ctx = { .s = &found, .roots = roots, .nroots = nroots,
                               .self = self, .considered = 0 };
    int rc = ntf_load_baseline(&base, baseline_path);
    if (rc) return rc;
    rc = ntf_collect(&ctx, use_git);
    if (rc) return rc;
    rc = gate_require_scanned(ctx.considered, floor,
                              "check-no-bare-tmp-fixture",
                              "scanned far fewer .c/.h files than expected "
                              "under its roots");
    if (rc) return rc;
    if (ntf_compare(err, &base, &found, baseline_path)) {
        fputs("\nMove a new/grown bare \"/tmp fixture literal onto "
              "test_mkdtemp()/test_mkstemp()/test_fmt_tmpdir() (test_core.h) "
              "under test-tmp/, or pin a legitimate exception as a "
              "shrink-only row in ", out);
        fputs(baseline_path, out);
        fputs(".\n", out);
        return 1;
    }
    fprintf(out, "check-no-bare-tmp-fixture: clean — %d file(s) hold pinned "
                "bare-tmp fixture sites, no growth, none stale\n", base.n);
    return 0;
}

static int ntf_write_baseline(const char *const *roots, int nroots,
                              const char *self, const char *baseline_path,
                              int floor)
{
    struct ntf_set found = {0};
    struct ntf_walk_ctx ctx = { .s = &found, .roots = roots, .nroots = nroots,
                               .self = self, .considered = 0 };
    int rc = ntf_collect(&ctx, 1);
    if (rc) return rc;
    rc = gate_require_scanned(ctx.considered, floor,
                              "check-no-bare-tmp-fixture",
                              "scan collapsed before --write-baseline");
    if (rc) return rc;
    qsort(found.v, (size_t)found.n, sizeof found.v[0], ntf_cmp_row);
    FILE *f = fopen(baseline_path, "w");
    if (!f) return die("z23-lint: cannot write %s\n", baseline_path);
    fputs("# check-no-bare-tmp-fixture baseline — every file with a bare\n"
          "# \"/tmp fixture literal, pinned at its current count as\n"
          "# <path> <count>. GENERATED — never hand-edit; regenerate with:\n"
          "#   build/bin/z23-lint check-no-bare-tmp-fixture --write-baseline\n"
          "# Shrink-only ratchet: a count at or under its pin passes; a\n"
          "# grown count fails; a row whose file has 0 live sites fails as\n"
          "# STALE.\n", f);
    for (int i = 0; i < found.n; i++)
        fprintf(f, "%s %d\n", found.v[i].path, found.v[i].count);
    int bad = ferror(f);
    return fclose(f) != 0 || bad
               ? die("z23-lint: write failed: %s\n", baseline_path) : 0;
}

int check_no_bare_tmp_fixture_run(int argc, char **argv)
{
    if (argc >= 1 && strcmp(argv[0], "--write-baseline") == 0)
        return ntf_write_baseline(k_ntf_roots, NTF_NROOT, k_ntf_self,
                                  k_ntf_baseline, NTF_SCAN_FLOOR);
    return ntf_run_cfg(k_ntf_roots, NTF_NROOT, k_ntf_baseline, k_ntf_self, 1,
                       NTF_SCAN_FLOOR, stdout, stderr);
}

/* ── selftest ─────────────────────────────────────────────────────────── */

/* Build "<root>/case.c" and "<root>/baseline.txt" and write the given
 * bodies to them. Split out of ntf_st_case() to keep its own complexity
 * low. */
static int ntf_st_write(const char *root, const char *case_body,
                        const char *baseline_body, char *case_path,
                        size_t case_cap, char *base_path, size_t base_cap)
{
    if (ovf(snprintf(case_path, case_cap, "%s/case.c", root), case_cap))
        return 1;
    if (ovf(snprintf(base_path, base_cap, "%s/baseline.txt", root),
            base_cap))
        return 1;
    if (csr_write(case_path, case_body)) return 1;
    return csr_write(base_path, baseline_body) ? 1 : 0;
}

/* Run ntf_run_cfg() against the sandboxed root, capturing its stdout/stderr
 * into the caller's buffers and its return code into *rc_out. Split out of
 * ntf_st_case() to keep its own complexity low. */
static int ntf_st_capture(const char *root, const char *base_path,
                          char *obuf, size_t ocap, char *ebuf, size_t ecap,
                          int *rc_out)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return 1;
    }
    const char *roots[1] = { root };
    *rc_out = ntf_run_cfg(roots, 1, base_path, "", 0, 0, out, err);
    int bad = csr_slurp(out, obuf, ocap) || csr_slurp(err, ebuf, ecap);
    fclose(out);
    fclose(err);
    return bad ? 1 : 0;
}

static int ntf_st_case(const char *root, const char *case_body,
                       const char *baseline_body, int want_rc,
                       const char *needle)
{
    char case_path[4096], base_path[4096];
    if (ntf_st_write(root, case_body, baseline_body, case_path,
                     sizeof case_path, base_path, sizeof base_path))
        return 1;
    char obuf[4096], ebuf[4096];
    int rc = 0;
    if (ntf_st_capture(root, base_path, obuf, sizeof obuf, ebuf,
                       sizeof ebuf, &rc))
        return 1;
    int ok = rc == want_rc
             && (!needle || strstr(obuf, needle) || strstr(ebuf, needle));
    if (!ok)
        fprintf(stderr, "check_no_bare_tmp_fixture selftest: want rc %d "
                        "needle '%s'; got rc %d, stdout:\n%s\nstderr:\n%s\n",
                want_rc, needle ? needle : "(none)", rc, obuf, ebuf);
    return ok ? 0 : 1;
}

int check_no_bare_tmp_fixture_selftest(void)
{
    /* Every `make check-<gate>` recipe runs with ZCL_LINT_PRODUCTION_SCAN=1
     * (see the Makefile's `check-%:` pattern rule and
     * tools/lint/scan_exclusions.sh), which makes lint_path_is_excluded()
     * treat any path under test-tmp/ as noise to keep production scans
     * immune to OTHER processes' transient fixtures. This selftest's own
     * sandbox is deliberately rooted under test-tmp/ (never /tmp — see
     * test_mkdtemp() in tests/harness/include/test/test_core.h), so under
     * `make` that same exclusion would hide every fixture this selftest
     * plants from ntf_visit()'s lint_path_is_excluded() check, making
     * every case here read as "0 hits" regardless of content. Selftests
     * must see the unfiltered tree (precedent: gate_tree_walk_selftests.c,
     * gate_supervisor_domain_workers.c), so save and clear the var for the
     * duration of this scan and restore it on the way out. */
    const char *old_prod = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char old_prod_buf[64];
    int had_prod = 0;
    if (old_prod) {
        if (ovf(snprintf(old_prod_buf, sizeof old_prod_buf, "%s", old_prod),
                sizeof old_prod_buf))
            return 2;
        had_prod = 1;
    }
    (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    const char *td = env_or("TMPDIR", "test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-ntf-XXXXXX", td),
            sizeof tmpl))
        return 2;
    (void)mkdir(td, 0700);
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    char baseline1[4160];
    if (ovf(snprintf(baseline1, sizeof baseline1, "%s/case.c 1\n", root),
            sizeof baseline1))
        return 2;
    int bad = 0;
    /* clean tree: no literal at all, empty baseline */
    bad |= ntf_st_case(root, "int x;\n", "", 0, NULL);
    /* a freshly planted literal, unbaselined, fails naming file:line */
    bad |= ntf_st_case(root,
                       "char x[] = \"/tmp/planted_XXXXXX\";\n", "", 1,
                       "case.c:1");
    /* the identical text, but fenced inside a comment, passes */
    bad |= ntf_st_case(root,
                       "/* char x[] = \"/tmp/should_be_ignored\"; */\n", "",
                       0, NULL);
    /* a count that grew past its pin fails */
    bad |= ntf_st_case(root,
                       "char a[] = \"/tmp/one\";\n"
                       "char b[] = \"/tmp/two\";\n",
                       baseline1, 1, "NEW/GROWN");
    /* an exact pin at the live count passes */
    bad |= ntf_st_case(root, "char a[] = \"/tmp/one\";\n", baseline1, 0,
                       NULL);
    /* a stale row (file no longer has that many, or any, live sites) fails */
    bad |= ntf_st_case(root, "int x;\n", baseline1, 1, "STALE");
    /* an unreadable file is UNPROVEN, not silently skipped */
    {
        char case_path[4096];
        if (ovf(snprintf(case_path, sizeof case_path, "%s/case.c", root),
                sizeof case_path)) {
            bad = 1;
        } else if (csr_write(case_path, "int x;\n")
                  || chmod(case_path, 0) != 0) {
            bad = 1;
        } else {
            char base_path[4096];
            (void)snprintf(base_path, sizeof base_path, "%s/baseline.txt",
                           root);
            (void)csr_write(base_path, "");
            const char *roots[1] = { root };
            FILE *out = tmpfile(), *err = tmpfile();
            int rc = (out && err)
                         ? ntf_run_cfg(roots, 1, base_path, "", 0, 0, out, err)
                         : 1;
            if (out) fclose(out);
            if (err) fclose(err);
            if (rc != 2) {
                fprintf(stderr, "check_no_bare_tmp_fixture selftest: "
                                "unreadable file want rc 2 got %d\n", rc);
                bad = 1;
            }
            (void)chmod(case_path, 0600);
        }
    }
    (void)rap_rm_rf(root);
    if (had_prod)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", old_prod_buf, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    return st_ok(bad, "check_no_bare_tmp_fixture selftest: OK\n");
}
