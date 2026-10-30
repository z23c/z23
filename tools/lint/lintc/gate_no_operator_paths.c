/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-no-operator-paths — RATCHET (shrink-only) gate
 * enforcing that a committed file names no clearnet address, hostname,
 * operator username, or local filesystem path. Ported from
 * tools/lint/check_no_operator_paths.sh (deleted). Selftest:
 * gate_no_operator_paths_selftest.c. Baseline load, compare and report:
 * gate_no_operator_paths_report.c.
 *
 * THREE PRONGS:
 *   A  an absolute home path (universal, catches every operator);
 *   B  an account token exposed by prong A, as a standalone word;
 *   C  an explicit structured host identity (JSON host/hostname field).
 *
 * Prongs B and C are SOURCE-DERIVED (tokens come from tracked bytes,
 * never from the runner); generic, example, localhost, and onion values
 * are excluded deterministically. tools/lint/operator_paths_baseline.txt
 * records per-prong occurrence counts and may only shrink; it is not
 * scanned itself. This gate source never contains a literal absolute
 * home path, so it cannot flag itself.
 *
 * Exit: 0 clean, 1 violation, 2 the gate could not scan (loud).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_no_operator_paths_priv.h"

const char nop_gate_name[] = "check-no-operator-paths";
const char nop_baseline[] = "tools/lint/operator_paths_baseline.txt";
static const char k_root_a[] = "home";
static const char k_root_b[] = "Users";
static const char k_generic[] =
    " dev test build user you fred admin node home root local host runner "
    "ubuntu debian docker ci app main src lib bin tmp data work ";
static const char k_hint[] =
    "git ls-files returned almost nothing — wrong cwd, or not a checkout";

enum { NOP_FILES = 24000, NOP_PATH = 640, NOP_TOKN = 512, NOP_TOK = 160,
       NOP_PAT = 256, NOP_BUF = 8 << 20, NOP_OVR = 65536 };

static char g_files[NOP_FILES][NOP_PATH];
static size_t g_nfiles;
static char g_atok[NOP_TOKN][NOP_TOK];
static size_t g_natok;
static char g_htok[NOP_TOKN][NOP_TOK];
static size_t g_nhtok;
char nop_curk[NOP_ROWS][NOP_KEY];
int nop_curn[NOP_ROWS];
int nop_ncur;
static char g_buf[NOP_BUF];
static char g_ovr[NOP_OVR];
static regex_t g_re_abs, g_re_host;
static int g_re_ok;
static int g_err;

int nop_ovf(const char *what, int n)
{
    fprintf(stderr, "%s: %s exceeds %d\n", nop_gate_name, what, n);
    return 2;
}

/* ── token sets ─────────────────────────────────────────────────────────── */

static int nop_tok_add(char set[][NOP_TOK], size_t *n, const char *t)
{
    size_t len = strlen(t);
    for (size_t i = 0; i < *n; i++)
        if (strcmp(set[i], t) == 0)
            return 0;
    if (*n >= NOP_TOKN)
        return nop_ovf("identity token set", NOP_TOKN);
    if (len >= NOP_TOK)
        return nop_ovf("identity token length", NOP_TOK);
    memcpy(set[*n], t, len + 1);
    (*n)++;
    return 0;
}

static int nop_tok_usable(const char *t)
{
    if (strlen(t) < 3)
        return 0;
    char pat[NOP_TOK + 2];
    if (ovf(snprintf(pat, sizeof pat, " %s ", t), sizeof pat))
        return 0;
    return strstr(k_generic, pat) == NULL;
}

static int nop_ends(const char *t, const char *suf)
{
    size_t lt = strlen(t), ls = strlen(suf);
    return lt >= ls && strcmp(t + lt - ls, suf) == 0;
}

static int nop_host_usable(const char *t)
{
    if (!nop_tok_usable(t))
        return 0;
    if (strcmp(t, "localhost") == 0 || nop_ends(t, ".localhost")
        || nop_ends(t, ".onion"))
        return 0;
    if (strcmp(t, "example") == 0 || nop_ends(t, ".example")
        || strncmp(t, "example.", 8) == 0 || strstr(t, ".example."))
        return 0;
    return 1;
}

/* ── file reading ───────────────────────────────────────────────────────── */

/* Reads path into g_buf. Returns 0 ok, 1 binary (skip, as grep -I), 2 error. */
static int nop_read_file(const char *path, size_t *len, int *binary)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", nop_gate_name, path);
        return 2;
    }
    size_t n = fread(g_buf, 1, (size_t)NOP_BUF - 1, f);
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "%s: read error on %s\n", nop_gate_name, path);
        return 2;
    }
    if (n == (size_t)NOP_BUF - 1 && fgetc(f) != EOF) {
        fclose(f);
        return nop_ovf("file buffer", NOP_BUF);
    }
    fclose(f);
    g_buf[n] = '\0';
    *len = n;
    *binary = memchr(g_buf, '\0', n < 8000 ? n : 8000) != NULL;
    return 0;
}

typedef void (*nop_line_fn)(const char *line, void *ctx);

/* Splits buf into lines in place (newline -> NUL) and calls fn per line. */
static void nop_for_line(char *buf, size_t len, nop_line_fn fn, void *ctx)
{
    char *p = buf, *end = buf + len;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        if (nl)
            *nl = '\0';
        fn(p, ctx);
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* ── regex helpers (unanchored patterns only; offset regexec is exact) ──── */

static void nop_each_match(const regex_t *re, const char *line,
                           void (*fn)(const char *, size_t, void *), void *ctx)
{
    size_t len = strlen(line), off = 0;
    while (off <= len) {
        regmatch_t m;
        if (regexec(re, line + off, 1, &m, 0) != 0)
            break;
        size_t so = off + (size_t)m.rm_so, eo = off + (size_t)m.rm_eo;
        fn(line + so, eo - so, ctx);
        off = (eo > so) ? eo : eo + 1;
    }
}

/* ── pass 1: prong A counts plus token collection ───────────────────────── */

struct nop_p1 { long a; };

static void nop_abs_hit(const char *m, size_t n, void *ctx)
{
    struct nop_p1 *p = ctx;
    p->a++;
    size_t off = (n > 6 && strncmp(m, "/Users", 6) == 0) ? 7 : 6;
    if (n <= off || n - off >= NOP_TOK) {
        g_err = nop_ovf("prong A token length", NOP_TOK);
        return;
    }
    char tok[NOP_TOK];
    memcpy(tok, m + off, n - off);
    tok[n - off] = '\0';
    g_err |= nop_tok_add(g_atok, &g_natok, tok);
}

static void nop_host_hit(const char *m, size_t n, void *ctx)
{
    (void)ctx;
    if (n < 3 || m[n - 1] != '"')
        return;
    size_t e = n - 1, s = e;
    while (s > 0 && m[s - 1] != '"')
        s--;
    if (s == 0 || s >= e)
        return;
    if (e - s >= NOP_TOK) {
        g_err = nop_ovf("host token length", NOP_TOK);
        return;
    }
    char tok[NOP_TOK];
    memcpy(tok, m + s, e - s);
    tok[e - s] = '\0';
    g_err |= nop_tok_add(g_htok, &g_nhtok, tok);
}

static void nop_p1_line(const char *line, void *ctx)
{
    nop_each_match(&g_re_abs, line, nop_abs_hit, ctx);
    nop_each_match(&g_re_host, line, nop_host_hit, NULL);
}

/* ── occurrence counting (manual, replicating grep -o semantics) ────────── */

/* Standalone-word occurrences of tok in line, with grep -o semantics: the
 * leading and trailing boundary characters are consumed by a match, so a
 * single separator cannot serve two adjacent tokens. */
static long nop_word_count(const char *line, const char *tok)
{
    size_t tl = strlen(tok), len = strlen(line), s = 0;
    long n = 0;
    while (s + tl <= len) {
        const char *hit = strstr(line + s, tok);
        if (!hit)
            break;
        size_t pos = (size_t)(hit - line);
        int pre = (pos == 0 && s == 0)
            || (pos > 0 && pos - 1 >= s
                && !lintc_ident_char((unsigned char)line[pos - 1]));
        int post = (pos + tl == len)
            || !lintc_ident_char((unsigned char)line[pos + tl]);
        if (pre && post) {
            n++;
            s = (pos + tl < len) ? pos + tl + 1 : len;
        } else {
            s = pos + 1;
        }
    }
    return n;
}

static size_t nop_skip_ws(const char *line, size_t j, size_t len)
{
    while (j < len && isspace((unsigned char)line[j]))
        j++;
    return j;
}

/* Length of a "host" or "hostname" JSON key at p, or 0 when p starts none. */
static size_t nop_key_len(const char *p)
{
    if (strncmp(p, "\"hostname\"", 10) == 0)
        return 10;
    if (strncmp(p, "\"host\"", 6) == 0)
        return 6;
    return 0;
}

/* True when a quoted string equal to tok starts at line[j]. */
static int nop_quoted_is(const char *line, size_t len, size_t j,
                         const char *tok)
{
    size_t tl = strlen(tok);
    return j + 1 + tl <= len && line[j] == '"'
        && strncmp(line + j + 1, tok, tl) == 0 && line[j + 1 + tl] == '"';
}

/* Occurrences of a "host"/"hostname" JSON field whose value is exactly tok. */
static long nop_field_count(const char *line, const char *tok)
{
    size_t tl = strlen(tok), len = strlen(line), i = 0;
    long n = 0;
    while (i < len) {
        size_t fn = nop_key_len(line + i), j;
        if (fn == 0) {
            i++;
            continue;
        }
        j = nop_skip_ws(line, i + fn, len);
        if (j < len && line[j] == ':') {
            j = nop_skip_ws(line, j + 1, len);
            if (nop_quoted_is(line, len, j, tok)) {
                n++;
                i = j + tl + 2;
                continue;
            }
        }
        i += fn;
    }
    return n;
}

struct nop_tokcnt { const char *tok; long total; };

static void nop_word_line(const char *line, void *ctx)
{
    struct nop_tokcnt *c = ctx;
    c->total += nop_word_count(line, c->tok);
}

static void nop_field_line(const char *line, void *ctx)
{
    struct nop_tokcnt *c = ctx;
    c->total += nop_field_count(line, c->tok);
}

/* ── current-count table ────────────────────────────────────────────────── */

static int nop_cur_add(const char *prong, const char *path, int n)
{
    char key[NOP_KEY];
    size_t len;
    if (ovf(snprintf(key, sizeof key, "%s %s", prong, path), sizeof key))
        return 2;
    for (int i = 0; i < nop_ncur; i++)
        if (strcmp(nop_curk[i], key) == 0) {
            nop_curn[i] += n;
            return 0;
        }
    if (nop_ncur >= NOP_ROWS)
        return nop_ovf("row set", NOP_ROWS);
    len = strlen(key);
    memcpy(nop_curk[nop_ncur], key, len + 1);
    nop_curn[nop_ncur] = n;
    nop_ncur++;
    return 0;
}

/* ── scan-set construction ──────────────────────────────────────────────── */

static int nop_add_tracked(const char *line, int *total)
{
    size_t len = strlen(line);
    (*total)++;
    if (g_nfiles >= NOP_FILES)
        return nop_ovf("tracked file list", NOP_FILES);
    if (len >= NOP_PATH)
        return nop_ovf("tracked path length", NOP_PATH);
    memcpy(g_files[g_nfiles], line, len + 1);
    g_nfiles++;
    return 0;
}

/* A tracked gitlink (submodule) is a directory: it is counted as tracked
 * but not scanned, as grep -I skips it in the shell original. */
static int nop_ls_cb(const char *path, void *ctx)
{
    struct stat sb;
    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        (*(int *)ctx)++;
        return 0;
    }
    return nop_add_tracked(path, ctx);
}

static int nop_scan_override(const char *list)
{
    size_t len = strlen(list);
    if (len >= NOP_OVR)
        return nop_ovf("scan override list", NOP_OVR);
    memcpy(g_ovr, list, len + 1);
    char *p = g_ovr;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (*p) {
            struct stat sb;
            if (stat(p, &sb) == 0 && S_ISREG(sb.st_mode)) {
                int rc = nop_add_tracked(p, &(int){ 0 });
                if (rc)
                    return rc;
            }
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

/* ── the three prongs ───────────────────────────────────────────────────── */

static int nop_re_compile(void)
{
    char pat[NOP_PAT];
    int rc;
    if (ovf(snprintf(pat, sizeof pat, "/(%s|%s)/[A-Za-z0-9][A-Za-z0-9._-]*",
                     k_root_a, k_root_b), sizeof pat))
        return 2;
    rc = regcomp(&g_re_abs, pat, REG_EXTENDED);
    if (rc) {
        reg_fail(&g_re_abs, rc);
        return 2;
    }
    if (ovf(snprintf(pat, sizeof pat,
                     "\"(host|hostname)\"[[:space:]]*:[[:space:]]*"
                     "\"[A-Za-z0-9][A-Za-z0-9._-]*\""), sizeof pat))
        return 2;
    rc = regcomp(&g_re_host, pat, REG_EXTENDED);
    if (rc) {
        regfree(&g_re_abs);
        reg_fail(&g_re_host, rc);
        return 2;
    }
    g_re_ok = 1;
    return 0;
}

static int nop_pass1_file(const char *path)
{
    size_t len;
    int bin;
    int rc = nop_read_file(path, &len, &bin);
    if (rc)
        return rc;
    if (bin)
        return 0;
    struct nop_p1 p = { 0 };
    nop_for_line(g_buf, len, nop_p1_line, &p);
    if (g_err)
        return g_err;
    if (p.a > 0)
        return nop_cur_add("A", path, (int)p.a);
    return 0;
}

static int nop_pass1(int override)
{
    for (size_t i = 0; i < g_nfiles; i++) {
        if (!override && strcmp(g_files[i], nop_baseline) == 0)
            continue;
        int rc = nop_pass1_file(g_files[i]);
        if (rc)
            return rc;
    }
    return 0;
}

static int nop_count_token(const char *prong, const char *tok, int override)
{
    int host = prong[0] == 'C';
    for (size_t i = 0; i < g_nfiles; i++) {
        if (!override && strcmp(g_files[i], nop_baseline) == 0)
            continue;
        size_t len;
        int bin;
        int rc = nop_read_file(g_files[i], &len, &bin);
        if (rc)
            return rc;
        if (bin)
            continue;
        struct nop_tokcnt c = { tok, 0 };
        nop_for_line(g_buf, len, host ? nop_field_line : nop_word_line, &c);
        if (c.total > 0) {
            rc = nop_cur_add(prong, g_files[i], (int)c.total);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int nop_prong_counts(int override)
{
    for (size_t i = 0; i < g_natok; i++) {
        if (!nop_tok_usable(g_atok[i]))
            continue;
        int rc = nop_count_token("B", g_atok[i], override);
        if (rc)
            return rc;
    }
    for (size_t i = 0; i < g_nhtok; i++) {
        if (!nop_host_usable(g_htok[i]))
            continue;
        int rc = nop_count_token("C", g_htok[i], override);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── orchestration ──────────────────────────────────────────────────────── */

static int nop_scan_set(const struct nop_cfg *cfg, int *override, int *tracked)
{
    if (cfg->files) {
        *override = 1;
        for (size_t i = 0; i < cfg->nfiles; i++) {
            int rc = nop_add_tracked(cfg->files[i], tracked);
            if (rc)
                return rc;
        }
        return 0;
    }
    const char *ovr = getenv("ZCL_OPERATOR_PATHS_SCAN_FILES");
    if (ovr && ovr[0]) {
        *override = 1;
        return nop_scan_override(ovr);
    }
    return each_zpath("git ls-files -z", nop_ls_cb, tracked);
}

static int nop_seed_identities(const struct nop_cfg *cfg)
{
    const char *ti = cfg->test_identities
        ? cfg->test_identities
        : getenv("ZCL_OPERATOR_PATHS_TEST_IDENTITIES");
    if (!ti || !ti[0])
        return 0;
    return nop_tok_add(g_atok, &g_natok, ti);
}

static int nop_check_run(const struct nop_cfg *cfg, FILE *out)
{
    int override = 0, tracked = 0;
    int rc = nop_scan_set(cfg, &override, &tracked);
    if (rc)
        return rc;
    if (!override) {
        rc = gate_require_scanned(tracked, 100, nop_gate_name, k_hint);
        if (rc)
            return rc;
    }
    rc = nop_re_compile();
    if (rc)
        return rc;
    rc = nop_pass1(override);
    if (rc)
        return rc;
    if (override) {
        rc = nop_seed_identities(cfg);
        if (rc)
            return rc;
    }
    rc = nop_prong_counts(override);
    if (rc)
        return rc;
    if (cfg->update)
        return nop_update(out);
    if (!override) {
        rc = nop_load_baseline();
        if (rc)
            return rc;
    }
    return nop_report(out, override);
}

int nop_check(const struct nop_cfg *cfg, FILE *out)
{
    g_nfiles = 0;
    g_natok = 0;
    g_nhtok = 0;
    nop_ncur = 0;
    g_err = 0;
    int rc = nop_check_run(cfg, out);
    if (g_re_ok) {
        regfree(&g_re_abs);
        regfree(&g_re_host);
        g_re_ok = 0;
    }
    return rc;
}

int check_no_operator_paths_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct nop_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    const char *mode = getenv("ZCL_LINT_MODE");
    cfg.update = mode != NULL && strcmp(mode, "UPDATE") == 0;
    return nop_check(&cfg, stdout);
}
