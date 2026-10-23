/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-no-stale-pinned-facts — forbid hand-pinned numeric facts
 * that have a live source in the present-tense docs. Ported from
 * tools/lint/check_no_stale_pinned_facts.sh (deleted). Selftest:
 * gate_no_stale_pinned_facts_selftest.c.
 *
 * WHY: owner directive 2026-07-17: a numeric fact with a live source (the
 * built binary's size, the node's current H*) is derived or gated, never
 * hand-pinned into prose. A stale "~15 MB binary" claim survived long after
 * the real binary grew.
 *
 * WHAT IS SCANNED: CLAUDE.md, README.md and every git-tracked docs/ tree .md files
 * except docs/HANDOFF.md (the live-state page) and docs/work/archive/ tree
 * (frozen history). A listed file that is missing is dropped; fewer than 3
 * survivors (1 under the selftest override) is FATAL (exit 2), never a clean
 * pass off a hollow scan. A listed file that cannot be read is FATAL too.
 *
 * RULES
 *   (A) BINARY-SIZE CLAIM [HARD, never baseline-exempt]: "<N> MB" adjacent
 *       to the word binary, in either order, on one line.
 *   (B) LIVE-STATE HEIGHT PIN [RATCHET]: a live-state trigger ("H* =",
 *       "wedged at", "held at", "live tip", ...) and a height-shaped number
 *       (N,NNN or six or more digits). Keys in
 *       tools/lint/stale_pinned_facts_baseline.txt are "path|normalized
 *       text"; new keys fail, the baseline can only shrink.
 *   Per-line escape hatch: a trailing <!-- stale-ok: <reason> --> marker.
 *
 * ENV (kept from the shell gate, for the same callers):
 *   ZCL_STALE_FACTS_SCAN_FILES="a.md b.md"  override the scan set (floor 1)
 *   ZCL_STALE_FACTS_EMIT_BASELINE=1         print the height-pin keys, exit 0
 *
 * SHELL SEMANTICS MIRRORED
 *   - grep -E patterns, grep -i for triggers: the same regexes via regexec.
 *     The shell grepped the "path:lineno:text" output line for the height
 *     number; the number pattern cannot cross a ':', so it is checked on the
 *     path, the line number and the text separately (same answer).
 *   - scan set from `git ls-files` (popen, like the shell), sorted by strcmp
 *     (C byte order; the shell used sort -u under the caller's locale).
 *   - binary-size pass runs over all files before the height pass, so the
 *     report order matches the shell.
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
#include "gate_no_stale_pinned_facts_priv.h"

static const char k_snf_gate[] = "check-no-stale-pinned-facts";
static const char k_snf_baseline[] =
    "tools/lint/stale_pinned_facts_baseline.txt";
static const char k_snf_hint[] =
    "CLAUDE.md/README.md/docs missing — run from repo root inside the worktree?";
static const char k_snf_ls_cmd[] = "git ls-files -z docs/";

enum { SNF_MAX_FILES = 2048, SNF_PATH = 512, SNF_MAX_KEYS = 2048,
       SNF_TRIGS = 7 };

/* Regex table, indexed by the enum below. Each row is one grep -E pattern;
 * a rule matches a line when any row in its group does. The triggers are
 * case-insensitive (grep -i); everything else is case-sensitive. */
struct snf_pat { const char *pat; int icase; };
enum {
    SNF_R_FWD,   /* binary size: "<N> MB ... binary" */
    SNF_R_REV,   /* binary size: "binary ... <N> MB" */
    SNF_R_STALE, /* the stale-ok escape hatch */
    SNF_R_NUM0,  /* height-shaped number: N,NNN */
    SNF_R_NUM1,  /* height-shaped number: six or more digits */
    SNF_R_TRIG0, /* first of SNF_TRIGS live-state triggers */
    SNF_R_COUNT = SNF_R_TRIG0 + SNF_TRIGS
};
static const struct snf_pat k_snf_pat[SNF_R_COUNT] = {
    { "[0-9]+(\\.[0-9]+)?[[:space:]]*MB[[:space:]]+"
      "([-A-Za-z0-9,()$]+[[:space:]]+){0,4}[Bb]inar(y|ies)", 0 },
    { "[Bb]inar(y|ies)[^.]{0,25}[0-9]+(\\.[0-9]+)?[[:space:]]*MB", 0 },
    { "<!--[[:space:]]*stale-ok:[[:space:]]*[^[:space:]].*-->", 0 },
    { "[0-9]{1,3}(,[0-9]{3})+", 0 },
    { "[0-9]{6,}", 0 },
    { "(H\\\\?\\*[[:space:]]*=)", 1 },
    { "wedged[[:space:]]+at", 1 },
    { "held[[:space:]]+at", 1 },
    { "currently[[:space:]]+(wedged|held|at|stuck|pinned)", 1 },
    { "live[[:space:]]+tip", 1 },
    { "stuck[[:space:]]+at", 1 },
    { "pinned[[:space:]]+at", 1 },
};
_Static_assert(sizeof k_snf_pat / sizeof k_snf_pat[0] == SNF_R_COUNT,
               "snf pattern table and enum disagree");

struct snf_res { regex_t re[SNF_R_COUNT]; int nre; };

static void snf_free(struct snf_res *r)
{
    while (r->nre > 0)
        regfree(&r->re[--r->nre]);
}

static int snf_compile(struct snf_res *r)
{
    r->nre = 0;
    for (int i = 0; i < SNF_R_COUNT; i++) {
        int flags = REG_EXTENDED | (k_snf_pat[i].icase ? REG_ICASE : 0);
        if (compile_pat(&r->re[i], flags, k_snf_pat[i].pat, "", "", "")) {
            snf_free(r);
            return 2;
        }
        r->nre++;
    }
    return 0;
}

/* 1 when some regex in [first, first + count) matches s, 0 when none does,
 * -1 on a regexec failure other than no-match. */
static int snf_any(const struct snf_res *r, int first, int count,
                   const char *s)
{
    for (int i = first; i < first + count; i++) {
        int m = regexec(&r->re[i], s, 0, NULL, 0);
        if (m == 0)
            return 1;
        if (m != REG_NOMATCH)
            return -1;
    }
    return 0;
}

static int snf_out(FILE *f, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vfprintf(f, fmt, ap);
    va_end(ap);
    return n < 0 ? die("z23-lint: write failed\n", "") : 0;
}

/* Insertion sort in byte order (what qsort with strcmp gives). The count is
 * bounded by SNF_MAX_FILES or SNF_MAX_KEYS, so the quadratic cost is too. */
static void snf_sort_strs(char **arr, int n)
{
    for (int i = 1; i < n; i++) {
        char *v = arr[i];
        int j = i;
        while (j > 0 && strcmp(arr[j - 1], v) > 0) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = v;
    }
}

/* ── Scan-set discovery (run only) ─────────────────────────────────────── */

struct snf_list { char *item[SNF_MAX_FILES]; int n; };

static void snf_list_free(struct snf_list *l)
{
    for (int i = 0; i < l->n; i++)
        free(l->item[i]);
    l->n = 0;
}

static int snf_list_add(struct snf_list *l, const char *path)
{
    size_t n = strlen(path);
    char *s;
    if (l->n >= SNF_MAX_FILES || n >= SNF_PATH)
        return die("z23-lint: scan set overflow\n", "");
    s = zcl_malloc(n + 1, "snf_path");
    if (!s)
        return die("z23-lint: out of memory\n", "");
    memcpy(s, path, n + 1);
    l->item[l->n++] = s;
    return 0;
}

int snf_keep_path(const char *path)
{
    return strcmp(path, "docs/HANDOFF.md") != 0 &&
           strncmp(path, "docs/work/archive/", 18) != 0;
}

static int snf_git_cb(const char *path, void *ctx)
{
    size_t n = strlen(path);
    if (n < 3 || strcmp(path + n - 3, ".md") != 0)
        return 0;
    if (!snf_keep_path(path))
        return 0;
    return snf_list_add(ctx, path);
}

static void snf_sort_unique(struct snf_list *l)
{
    int o = 0;
    snf_sort_strs(l->item, l->n);
    for (int i = 0; i < l->n; i++) {
        if (o > 0 && strcmp(l->item[i], l->item[o - 1]) == 0) {
            free(l->item[i]);
            continue;
        }
        l->item[o++] = l->item[i];
    }
    l->n = o;
}

static int snf_discover(struct snf_list *l)
{
    if (snf_list_add(l, "CLAUDE.md") || snf_list_add(l, "README.md"))
        return 2;
    if (each_zpath(k_snf_ls_cmd, snf_git_cb, l))
        return 2;
    snf_sort_unique(l);
    return 0;
}

/* The override is split on whitespace in the caller's order, unsorted. */
static int snf_env_list(struct snf_list *l, const char *env)
{
    char *buf = zcl_malloc(strlen(env) + 1, "snf_env");
    char *save = NULL;
    int rc = 0;
    if (!buf)
        return die("z23-lint: out of memory\n", "");
    strcpy(buf, env);
    for (char *tok = strtok_r(buf, " \t\n", &save); tok;
         tok = strtok_r(NULL, " \t\n", &save)) {
        if (snf_list_add(l, tok)) {
            rc = 2;
            break;
        }
    }
    free(buf);
    return rc;
}

/* Drops the listed paths that are not regular files (the shell's
 * `[[ -f ]]` filter); the floor check then sees the survivors. */
static void snf_prune_missing(struct snf_list *l)
{
    int o = 0;
    for (int i = 0; i < l->n; i++) {
        struct stat st;
        if (stat(l->item[i], &st) == 0 && S_ISREG(st.st_mode))
            l->item[o++] = l->item[i];
        else
            free(l->item[i]);
    }
    l->n = o;
}

static int snf_gather(struct snf_list *l, int *floor)
{
    const char *env = getenv("ZCL_STALE_FACTS_SCAN_FILES");
    if (env && env[0]) {
        *floor = 1;
        if (snf_env_list(l, env))
            return 2;
    } else {
        *floor = 3;
        if (snf_discover(l))
            return 2;
    }
    snf_prune_missing(l);
    return 0;
}

/* ── String helpers ────────────────────────────────────────────────────── */

static char *snf_trim(char *s)
{
    char *e;
    while (*s && isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

/* A copy of one grep line: the trailing newline is not part of the text. */
static char *snf_text(const char *line, size_t len)
{
    char *t;
    if (len > 0 && line[len - 1] == '\n')
        len--;
    t = zcl_malloc(len + 1, "snf_text");
    if (!t)
        return NULL;
    memcpy(t, line, len);
    t[len] = '\0';
    return t;
}

/* "path|normalized text": the text is trimmed and every whitespace run
 * becomes one space (the shell's norm()). */
static char *snf_key(const char *path, const char *text)
{
    size_t pl = strlen(path), tl = strlen(text), o = pl;
    int sp = 1;
    char *k = zcl_malloc(pl + 1 + tl + 1, "snf_key");
    if (!k)
        return NULL;
    memcpy(k, path, pl);
    k[o++] = '|';
    for (size_t i = 0; i < tl; i++) {
        unsigned char c = (unsigned char)text[i];
        if (isspace(c)) {
            if (!sp)
                k[o++] = ' ';
            sp = 1;
            continue;
        }
        k[o++] = (char)c;
        sp = 0;
    }
    if (o > pl + 1 && k[o - 1] == ' ')
        o--;
    k[o] = '\0';
    return k;
}

/* ── Key sets (baseline rows and emitted keys) ─────────────────────────── */

struct snf_set { char *key[SNF_MAX_KEYS]; int n; };

static void snf_set_clear(struct snf_set *s)
{
    for (int i = 0; i < s->n; i++)
        free(s->key[i]);
    s->n = 0;
}

/* Takes ownership of owned; frees it on overflow. */
static int snf_set_add(struct snf_set *s, char *owned)
{
    if (s->n >= SNF_MAX_KEYS) {
        free(owned);
        return die("z23-lint: stale-pin key overflow\n", "");
    }
    s->key[s->n++] = owned;
    return 0;
}

static int snf_set_has(const struct snf_set *s, const char *k)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->key[i], k) == 0)
            return 1;
    return 0;
}

static int snf_base_line(void *ctx, const char *line, size_t len)
{
    char *s = zcl_malloc(len + 1, "snf_base"), *t;
    if (!s)
        return die("z23-lint: out of memory\n", "");
    memcpy(s, line, len);
    s[len] = '\0';
    t = snf_trim(s);
    if (*t == '\0' || *t == '#') {
        free(s);
        return 0;
    }
    if (t != s)
        memmove(s, t, strlen(t) + 1);
    return snf_set_add(ctx, s);
}

/* A missing baseline grandfathers nothing; any read failure is fatal. */
static int snf_load_base(struct snf_set *base, const char *path)
{
    return lc_each_line(path, snf_base_line, base, 1) == 2 ? 2 : 0;
}

static int snf_emit_keys(struct snf_set *keys, FILE *out)
{
    snf_sort_strs(keys->key, keys->n);
    for (int i = 0; i < keys->n; i++) {
        if (i > 0 && strcmp(keys->key[i], keys->key[i - 1]) == 0)
            continue;
        if (snf_out(out, "%s\n", keys->key[i]))
            return 2;
    }
    return 0;
}

/* ── Per-line rules ────────────────────────────────────────────────────── */

struct snf_pass {
    const struct snf_res *r;
    const struct snf_set *base; /* baseline rows (check mode) */
    struct snf_set *keys;       /* emitted keys (emit mode) */
    FILE *err;
    const char *path;
    long lineno;
    int height;                 /* 0: binary-size pass, 1: height pass */
    int emit;
    int bin, hgt, grand, skips;
};

/* One violation: a label line and the text with its leading space dropped. */
static int snf_report(const struct snf_pass *p, const char *label,
                      const char *text)
{
    const char *t = text;
    while (*t && isspace((unsigned char)*t))
        t++;
    return snf_out(p->err, "%s  %s:%ld\n    %s\n", label, p->path, p->lineno,
                   t);
}

static int snf_stale_ok(const struct snf_res *r, const char *text)
{
    return snf_any(r, SNF_R_STALE, 1, text);
}

static int snf_bin_line(struct snf_pass *p, const char *text)
{
    int m = snf_any(p->r, SNF_R_FWD, 2, text);
    if (m <= 0)
        return m < 0 ? 2 : 0;
    m = snf_stale_ok(p->r, text);
    if (m != 0) {
        if (m < 0)
            return 2;
        p->skips++;
        return 0;
    }
    p->bin++;
    return snf_report(p, "STALE BINARY-SIZE PIN", text);
}

/* The height number is checked on the text, the path and the line number.
 * The shell checked the whole "path:lineno:text" line, but the pattern cannot
 * cross the ':' separators, so a match lies wholly in one of the three. */
static int snf_height_num(const struct snf_pass *p, const char *text)
{
    char num[32];
    int m;
    if (ovf(snprintf(num, sizeof num, "%ld", p->lineno), sizeof num))
        return 2;
    m = snf_any(p->r, SNF_R_NUM0, 2, text);
    if (m != 0)
        return m;
    m = snf_any(p->r, SNF_R_NUM0, 2, p->path);
    if (m != 0)
        return m;
    return snf_any(p->r, SNF_R_NUM0, 2, num);
}

static int snf_pin_key(struct snf_pass *p, const char *text)
{
    char *key = snf_key(p->path, text);
    int hit;
    if (!key)
        return 2;
    if (p->emit)
        return snf_set_add(p->keys, key);
    hit = snf_set_has(p->base, key);
    free(key);
    if (hit) {
        p->grand++;
        return 0;
    }
    p->hgt++;
    return snf_report(p, "NEW LIVE-STATE HEIGHT PIN", text);
}

static int snf_height_line(struct snf_pass *p, const char *text)
{
    int m = snf_any(p->r, SNF_R_TRIG0, SNF_TRIGS, text);
    if (m <= 0)
        return m < 0 ? 2 : 0;
    m = snf_height_num(p, text);
    if (m <= 0)
        return m < 0 ? 2 : 0;
    m = snf_stale_ok(p->r, text);
    if (m != 0) {
        if (m < 0)
            return 2;
        p->skips++;
        return 0;
    }
    return snf_pin_key(p, text);
}

static int snf_line(void *ctx, const char *line, size_t len)
{
    struct snf_pass *p = ctx;
    char *text;
    int rc;
    p->lineno++;
    text = snf_text(line, len);
    if (!text)
        return die("z23-lint: out of memory\n", "");
    rc = p->height ? snf_height_line(p, text) : snf_bin_line(p, text);
    free(text);
    return rc;
}

static int snf_scan_file(struct snf_pass *p, const char *path)
{
    p->path = path;
    p->lineno = 0;
    return lc_each_line(path, snf_line, p, 0) ? 2 : 0;
}

static int snf_pass_all(struct snf_pass *p, char *const *files, int nfiles)
{
    for (int i = 0; i < nfiles; i++)
        if (snf_scan_file(p, files[i]))
            return 2;
    return 0;
}

/* ── Report ────────────────────────────────────────────────────────────── */

static int snf_fail_block(const struct snf_pass *p)
{
    if (snf_out(p->err, "\nFAIL: docs hand-pin a fact with a live source.\n"))
        return 2;
    if (p->bin > 0 &&
        snf_out(p->err,
                "  binary-size: use size-agnostic language (\"compact "
                "self-contained C23 binary\")\n"
                "               or quote the derived value from "
                "tools/scripts/binary_size.sh.\n"
                "               (NOT baseline-exemptible — this is the "
                "owner's named case.)\n"))
        return 2;
    if (p->hgt > 0 &&
        snf_out(p->err,
                "  height-pin:  live state lives in docs/agent/HANDOFF.md — "
                "point there, don't pin a height.\n"
                "               Verify the live H* (z23 dumpstate "
                "reducer_frontier) before writing.\n"
                "               A legitimately-constant/dated line may add "
                "a trailing\n"
                "               <!-- stale-ok: <reason> --> marker.\n"))
        return 2;
    return 0;
}

static int snf_summary(const struct snf_pass *p, int nfiles, FILE *out)
{
    int total = p->bin + p->hgt;
    if (snf_out(out, "[check_no_stale_pinned_facts] scanned %d doc(s); %d "
                     "violation(s) (binary-size=%d, height-pin=%d)\n",
                nfiles, total, p->bin, p->hgt))
        return 2;
    if (p->grand > 0 &&
        snf_out(out, "[check_no_stale_pinned_facts] %d grandfathered "
                     "height-pin(s) tolerated via baseline (shrink-only)\n",
                p->grand))
        return 2;
    if (p->skips > 0 &&
        snf_out(out, "[check_no_stale_pinned_facts] %d line(s) exempt via "
                     "<!-- stale-ok: … --> marker\n", p->skips))
        return 2;
    if (total == 0)
        return snf_out(out, "[check_no_stale_pinned_facts] clean — no stale "
                            "pinned binary-size or live-state height facts\n")
                   ? 2
                   : 0;
    if (snf_fail_block(p))
        return 2;
    return 1;
}

/* ── Entry points ──────────────────────────────────────────────────────── */

static int snf_run(struct snf_pass *p, char *const *files, int nfiles,
                   FILE *out)
{
    if (p->emit) {
        p->height = 1;
        if (snf_pass_all(p, files, nfiles))
            return 2;
        return snf_emit_keys(p->keys, out);
    }
    p->height = 0;
    if (snf_pass_all(p, files, nfiles))
        return 2;
    p->height = 1;
    if (snf_pass_all(p, files, nfiles))
        return 2;
    return snf_summary(p, nfiles, out);
}

int snf_check(char *const *files, int nfiles, const char *baseline, FILE *out,
              FILE *err, int emit)
{
    struct snf_res res;
    struct snf_set base, keys;
    struct snf_pass p;
    int rc;
    if (snf_compile(&res))
        return 2;
    memset(&base, 0, sizeof base);
    memset(&keys, 0, sizeof keys);
    memset(&p, 0, sizeof p);
    p.r = &res;
    p.base = &base;
    p.keys = &keys;
    p.err = err;
    p.emit = emit;
    rc = emit ? 0 : snf_load_base(&base, baseline);
    if (!rc)
        rc = snf_run(&p, files, nfiles, out);
    snf_set_clear(&base);
    snf_set_clear(&keys);
    snf_free(&res);
    return rc;
}

int check_no_stale_pinned_facts_run(int argc, char **argv)
{
    struct snf_list l;
    const char *emit = getenv("ZCL_STALE_FACTS_EMIT_BASELINE");
    int floor = 3, rc;
    if (argc > 0 && chdir(argv[0]) != 0)
        return die("z23-lint: cannot cd into repo root %s\n", argv[0]);
    l.n = 0;
    rc = snf_gather(&l, &floor);
    if (!rc)
        rc = gate_require_scanned(l.n, floor, k_snf_gate, k_snf_hint);
    if (!rc)
        rc = snf_check(l.item, l.n, k_snf_baseline, stdout, stderr,
                       emit && strcmp(emit, "1") == 0);
    snf_list_free(&l);
    return rc;
}
