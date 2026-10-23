/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-doc-no-false-deleted — doc-honesty ratchet. Ported from
 * tools/lint/gate_doc_no_false_deleted.sh (deleted). Selftest:
 * gate_doc_no_false_deleted_selftest.c.
 *
 * WHY: a doc that declares a code engine or path "deleted" / "removed" / "no
 * longer exists" while the code is still present and still live-called is a
 * lie a reader will act on. The gate turns that class of lie into a failure.
 * It also pins the binary size the docs cite to the real release binary.
 *
 * PART 1 — a claim row FIRES (fail) when some doc (flattened, so a claim that
 * wraps across lines still counts) makes the forbidden claim, the code path
 * still exists, and a live-caller file still calls the symbol. The claim
 * label is "<doc>:<first line naming the engine or a deleted state>".
 *
 * PART 2 — every "<N> MB" that CLAUDE.md, FRAMEWORK.md or the ADR cites must
 * be within 6 MB of the real build/bin/z23 (or build/bin/z23.exe) size. A
 * missing release binary skips this part with an INFO line.
 *
 * SHELL SEMANTICS MIRRORED
 *   - the doc list is `find docs -name '*.md'` plus CLAUDE.md, sorted and
 *     unique; find's own exit status is ignored, as the shell ignored it.
 *   - a doc is flattened by turning each newline into a space, then matched
 *     case-insensitively, as `tr '\n' ' '` followed by grep -Eiq did.
 *   - the binary size is the file's st_size (the shell read it with wc -c).
 *   - the cited numbers are the digit runs of "<N> MB" matches, sorted unique.
 *
 * DELIBERATE DIFFERENCES
 *   - a cited number longer than 18 digits fails closed (exit 2). The shell's
 *     arithmetic would wrap silently; no doc cites one.
 *   - a doc that cannot be read is fatal (exit 2), not a silent skip.
 *   - with no argument the root is the cwd (the shell fell back to its own
 *     script directory); the Makefile and run_lint pass ".".
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
#include <sys/stat.h>
#include <unistd.h>
#include "base/safe_alloc.h"
#include "lintc.h"
#include "gate_doc_no_false_deleted_priv.h"

static const char k_dfn_find_cmd[] = "find docs -name '*.md' -print0 2>/dev/null";
static const char k_dfn_hint_pat[] =
    "block-connect engine|no longer exists|has been (deleted|removed)";
static const char k_dfn_bin[] = "build/bin/z23";
static const char k_dfn_bin_exe[] = "build/bin/z23.exe";
static const char *const k_dfn_size_docs[] = {
    "docs/commons/FRAMEWORK.md", "docs/adr/0001-personal-sovereignty-stack.md",
    "CLAUDE.md"
};

enum { DFN_BAND_MB = 6, DFN_MB = 1048576, DFN_DOCS_MAX = 4096,
       DFN_PATH = 512, DFN_LABEL = 528, DFN_FLAT_MAX = 4194304,
       DFN_NUMS_MAX = 256, DFN_NUM_LEN = 19 };

/* One row: a forbidden claim, the code it names, and the callers that prove
 * the code is still live. */
struct dfn_row {
    const char *pattern;
    const char *code;
    const char *callers[2];
    int ncallers;
    const char *symbol;
};

static const struct dfn_row k_dfn_rows[] = {
    { "legacy[^.]*block-connect engine[^.]*\\b(deleted|removed|no longer exists)\\b",
      "core/modules/validation/src/connect_block.c",
      { "engine/composition/src/boot_index.c",
        "engine/controllers/src/sync_controller_blocks.c" },
      2, "connect_block" },
    { "connect_block[^.]*\\b(has been deleted|was deleted|is deleted|removed|no longer exists)\\b",
      "core/modules/validation/src/connect_block.c",
      { "engine/composition/src/boot_index.c" },
      1, "connect_block" },
};

struct dfn_docs { char *item[DFN_DOCS_MAX]; int n; };
struct dfn_flat { char *buf; size_t n; };
struct dfn_nums { char num[DFN_NUMS_MAX][DFN_NUM_LEN]; int n; };

struct dfn_state {
    struct dfn_docs docs;
    struct dfn_flat flat;
    regex_t hint;
    int hint_ok;
    int fail;
};

static int dfn_put(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int dfn_is_reg(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}

static void dfn_docs_free(struct dfn_docs *d)
{
    for (int i = 0; i < d->n; i++)
        free(d->item[i]);
    d->n = 0;
}

static int dfn_docs_add(struct dfn_docs *d, const char *path)
{
    size_t n = strlen(path);
    char *s;
    if (d->n >= DFN_DOCS_MAX || n >= DFN_PATH)
        return die("z23-lint: doc list overflow\n", "");
    s = zcl_malloc(n + 1, "dfn_doc");
    if (!s)
        return die("z23-lint: out of memory\n", "");
    memcpy(s, path, n + 1);
    d->item[d->n++] = s;
    return 0;
}

static int dfn_doc_cb(const char *path, void *ctx)
{
    return dfn_docs_add(ctx, path);
}

static int dfn_path_cmp(const void *a, const void *b)
{
    const char *x = *(char *const *)a;
    const char *y = *(char *const *)b;
    return strcmp(x, y);
}

/* Sorts the doc list and drops duplicates, leaving the unique sorted set. */
static void dfn_docs_sort_unique(struct dfn_docs *d)
{
    int o = 0;
    qsort(d->item, (size_t)d->n, sizeof d->item[0], dfn_path_cmp);
    for (int i = 0; i < d->n; i++) {
        if (o > 0 && strcmp(d->item[i], d->item[o - 1]) == 0) {
            free(d->item[i]);
            continue;
        }
        d->item[o++] = d->item[i];
    }
    d->n = o;
}

/* The doc set: CLAUDE.md plus every docs/ tree .md files, sorted and unique. Missing
 * entries are skipped later by the regular-file test, as the shell did. */
static int dfn_docs_collect(struct dfn_docs *d)
{
    if (dfn_docs_add(d, "CLAUDE.md"))
        return 2;
    if (each_zpath_st(k_dfn_find_cmd, 1, dfn_doc_cb, d))
        return 2;
    dfn_docs_sort_unique(d);
    return 0;
}

static int dfn_flat_cb(void *ctx, const char *line, size_t len)
{
    struct dfn_flat *f = ctx;
    size_t keep = len;
    int nl = keep > 0 && line[keep - 1] == '\n';
    if (nl)
        keep--;
    if (f->n + len + 1 > DFN_FLAT_MAX)
        return die("z23-lint: doc too large to scan\n", "");
    memcpy(f->buf + f->n, line, keep);
    f->n += keep;
    if (nl)
        f->buf[f->n++] = ' ';
    f->buf[f->n] = '\0';
    return 0;
}

/* Loads path into the flat buffer, newlines turned into spaces. */
static int dfn_flat_load(struct dfn_state *st, const char *path)
{
    st->flat.n = 0;
    st->flat.buf[0] = '\0';
    return lc_each_line(path, dfn_flat_cb, &st->flat, 0) ? 2 : 0;
}

struct dfn_scan { regex_t *re; long lineno; int hit; };

static int dfn_hint_cb(void *ctx, const char *line, size_t len)
{
    struct dfn_scan *s = ctx;
    int m;
    (void)len;
    s->lineno++;
    m = regexec(s->re, line, 0, NULL, 0);
    if (m == 0) {
        s->hit = 1;
        return 1;
    }
    return m == REG_NOMATCH ? 0 : 2;
}

/* Writes "<doc>:<line>" (or "<doc>" when no hint line exists) into hit. */
static int dfn_hit_label(struct dfn_state *st, const char *doc, char *hit,
                         size_t cap, int *found)
{
    struct dfn_scan s = { &st->hint, 0, 0 };
    int n;
    if (lc_each_line(doc, dfn_hint_cb, &s, 0))
        return 2;
    n = s.hit ? snprintf(hit, cap, "%s:%ld", doc, s.lineno)
              : snprintf(hit, cap, "%s", doc);
    *found = 1;
    return ovf(n, cap);
}

/* The first doc (sorted order) whose flattened text makes the claim. */
static int dfn_first_claim(struct dfn_state *st, const regex_t *re, char *hit,
                           size_t cap, int *found)
{
    *found = 0;
    for (int i = 0; i < st->docs.n; i++) {
        const char *d = st->docs.item[i];
        int m;
        if (!dfn_is_reg(d))
            continue;
        if (dfn_flat_load(st, d))
            return 2;
        m = regexec(re, st->flat.buf, 0, NULL, 0);
        if (m == 0)
            return dfn_hit_label(st, d, hit, cap, found);
        if (m != REG_NOMATCH)
            return 2;
    }
    return 0;
}

/* The first live caller that still names the symbol as a call. */
static int dfn_live_caller(const struct dfn_row *row, const char **live)
{
    regex_t re;
    int rc = 0;
    if (compile_pat(&re, REG_EXTENDED, "\\b", row->symbol, "\\b *\\(", ""))
        return 2;
    for (int i = 0; i < row->ncallers && rc == 0 && !*live; i++) {
        int hits = 0;
        if (!dfn_is_reg(row->callers[i]))
            continue;
        rc = scan_re(row->callers[i], &re, &hits, 0);
        if (rc == 0 && hits > 0)
            *live = row->callers[i];
    }
    regfree(&re);
    return rc;
}

static int dfn_false_claim(const struct dfn_row *row, const char *hit,
                           const char *live)
{
    if (dfn_put("FAIL: doc claims '%s' engine is deleted/removed (%s) but %s "
                "EXISTS and is live-called from %s.\n",
                row->symbol, hit, row->code, live))
        return 2;
    return dfn_put("      -> Either the doc lies (fix the doc) or the code is "
                   "truly dead (then delete %s).\n", row->code);
}

/* One row: fires only when the claim, the code and a live caller all hold. */
static int dfn_row_check(struct dfn_state *st, const struct dfn_row *row)
{
    regex_t re;
    char hit[DFN_LABEL];
    const char *live = NULL;
    int found = 0, rc;
    if (compile_pat(&re, REG_EXTENDED | REG_ICASE, row->pattern, "", "", ""))
        return 2;
    rc = dfn_first_claim(st, &re, hit, sizeof hit, &found);
    regfree(&re);
    if (rc || !found || !dfn_is_reg(row->code))
        return rc;
    rc = dfn_live_caller(row, &live);
    if (rc || !live)
        return rc;
    st->fail = 1;
    return dfn_false_claim(row, hit, live);
}

static int dfn_part1(struct dfn_state *st)
{
    for (size_t i = 0; i < sizeof k_dfn_rows / sizeof k_dfn_rows[0]; i++)
        if (dfn_row_check(st, &k_dfn_rows[i]))
            return 2;
    return 0;
}

/* ── Part 2: the cited binary size ─────────────────────────────────────── */

static int dfn_num_add(struct dfn_nums *s, const char *digits, size_t len)
{
    if (len == 0 || len >= DFN_NUM_LEN)
        return die("z23-lint: cited size is not a plain number\n", "");
    if (s->n >= DFN_NUMS_MAX)
        return die("z23-lint: too many cited sizes\n", "");
    memcpy(s->num[s->n], digits, len);
    s->num[s->n][len] = '\0';
    s->n++;
    return 0;
}

struct dfn_size_ctx { regex_t *re; struct dfn_nums *nums; };

/* Every "<N> MB" on the line; the digit run at the match start is N. */
static int dfn_size_cb(void *ctx, const char *line, size_t len)
{
    struct dfn_size_ctx *c = ctx;
    const char *p = line;
    regmatch_t m[1];
    int flags = 0, r = REG_NOMATCH;
    (void)len;
    while ((r = regexec(c->re, p, 1, m, flags)) == 0) {
        size_t d = 0;
        while (isdigit((unsigned char)p[m[0].rm_so + d]))
            d++;
        if (dfn_num_add(c->nums, p + m[0].rm_so, d))
            return 2;
        if (m[0].rm_eo <= 0) {
            r = REG_NOMATCH;
            break;
        }
        p += m[0].rm_eo;
        flags = REG_NOTBOL;
    }
    return r == REG_NOMATCH ? 0 : 2;
}

static int dfn_num_cmp(const void *a, const void *b)
{
    return strncmp((const char *)a, (const char *)b, DFN_NUM_LEN);
}

/* Sorts the cited numbers as strings and drops duplicates (sort -u). */
static void dfn_nums_sort_unique(struct dfn_nums *s)
{
    int o = 0;
    qsort(s->num, (size_t)s->n, DFN_NUM_LEN, dfn_num_cmp);
    for (int i = 0; i < s->n; i++) {
        if (o > 0 && strcmp(s->num[i], s->num[o - 1]) == 0)
            continue;
        if (o != i)
            memcpy(s->num[o], s->num[i], DFN_NUM_LEN);
        o++;
    }
    s->n = o;
}

/* Each cited number outside the band around the real size is a FAIL. */
static int dfn_size_check_doc(struct dfn_state *st, const char *doc,
                              const char *bin, long long real_mb)
{
    struct dfn_nums nums;
    regex_t re;
    struct dfn_size_ctx c;
    int rc;
    if (compile_pat(&re, REG_EXTENDED, "[0-9]+ ?MB", "", "", ""))
        return 2;
    nums.n = 0;
    c.re = &re;
    c.nums = &nums;
    rc = lc_each_line(doc, dfn_size_cb, &c, 0) ? 2 : 0;
    regfree(&re);
    if (rc)
        return rc;
    dfn_nums_sort_unique(&nums);
    for (int i = 0; i < nums.n; i++) {
        long long n = strtoll(nums.num[i], NULL, 10);
        long long diff = real_mb - n;
        if (diff < 0)
            diff = -diff;
        if (diff > DFN_BAND_MB) {
            st->fail = 1;
            if (dfn_put("FAIL: %s cites '%s MB' but real %s is %lld MB (band "
                        "±%d MB).\n", doc, nums.num[i], bin, real_mb,
                        DFN_BAND_MB))
                return 2;
        }
    }
    return 0;
}

static const char *dfn_release_bin(void)
{
    if (dfn_is_reg(k_dfn_bin))
        return k_dfn_bin;
    return dfn_is_reg(k_dfn_bin_exe) ? k_dfn_bin_exe : NULL;
}

static int dfn_part2(struct dfn_state *st)
{
    const char *bin = dfn_release_bin();
    struct stat sb;
    long long real_mb;
    if (!bin)
        return dfn_put("INFO: %s not built; skipping binary-size fact check "
                       "(build first to enforce).\n", k_dfn_bin);
    if (stat(bin, &sb) != 0)
        return 2;
    real_mb = (long long)sb.st_size / DFN_MB;
    for (size_t i = 0; i < sizeof k_dfn_size_docs / sizeof k_dfn_size_docs[0];
         i++) {
        const char *d = k_dfn_size_docs[i];
        if (!dfn_is_reg(d))
            continue;
        if (dfn_size_check_doc(st, d, bin, real_mb))
            return 2;
    }
    return 0;
}

/* ── Entry points ──────────────────────────────────────────────────────── */

static void dfn_state_free(struct dfn_state *st)
{
    dfn_docs_free(&st->docs);
    if (st->hint_ok)
        regfree(&st->hint);
    free(st->flat.buf);
}

static int dfn_state_init(struct dfn_state *st)
{
    memset(st, 0, sizeof *st);
    st->flat.buf = zcl_malloc(DFN_FLAT_MAX + 1, "dfn_flat");
    if (!st->flat.buf)
        return die("z23-lint: out of memory\n", "");
    if (compile_pat(&st->hint, REG_EXTENDED | REG_ICASE, k_dfn_hint_pat, "",
                    "", ""))
        return 2;
    st->hint_ok = 1;
    return dfn_docs_collect(&st->docs);
}

int dfn_check_tree(void)
{
    struct dfn_state st;
    int rc = dfn_state_init(&st);
    if (!rc)
        rc = dfn_part1(&st);
    if (!rc)
        rc = dfn_part2(&st);
    dfn_state_free(&st);
    if (rc)
        return rc;
    if (st.fail) {
        if (dfn_put("── gate_doc_no_false_deleted: FAIL ──\n"))
            return 2;
        return 1;
    }
    return dfn_put("── gate_doc_no_false_deleted: pass ──\n") ? 2 : 0;
}

int check_doc_no_false_deleted_run(int argc, char **argv)
{
    struct stat sb;
    const char *root = ".";
    if (argc > 0 && stat(argv[0], &sb) == 0 && S_ISDIR(sb.st_mode))
        root = argv[0];
    if (chdir(root) != 0)
        return dfn_put("FAIL: cannot cd into repo root '%s'\n", root) ? 2 : 1;
    return dfn_check_tree();
}
