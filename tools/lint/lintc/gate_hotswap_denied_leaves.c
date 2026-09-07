/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-hotswap-denied-leaves of the C23 lint
 * runtime. Port of tools/lint/check_hotswap_denied_leaves.sh (now a shim):
 * no command leaf named in engine/composition/hotswap_denied_leaves.def may
 * appear in ANY hot-swap manifest, nor in a ZCL_HOTSWAP_GEN /
 * ZCL_HOTSWAP_MODULE_GEN leaf table of a translation unit either manifest
 * can recompile. Fails CLOSED: a missing/unreadable/empty denylist, a
 * missing catalog or scan dir, zero manifests, or zero translation units is
 * exit 2, never a quiet pass. Selftest lives in the sibling file
 * gate_hotswap_denied_leaves_selftest.c (see lintc.h for both prototypes).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    HDL_LEAF = 128, HDL_REASON = 1024, HDL_PATH = 320, HDL_TOK = 200,
    HDL_LINE = 4096, HDL_ENTRIES = 128, HDL_MANIFESTS = 32, HDL_TUS = 64,
    HDL_TOKSET = 2048, HDL_GENLINES = 512,
};

FILE *g_hdl_out, *g_hdl_err;

/* Only defaults an UNSET stream to the real stdout/stderr — never clobbers
 * an override the selftest harness installed before calling run(), so one
 * entry point serves both the real gate and its in-process selftest. */
static void hdl_io_prod(void)
{
    if (!g_hdl_out) g_hdl_out = stdout;
    if (!g_hdl_err) g_hdl_err = stderr;
}

/* Bounded copy from a source buffer the compiler cannot statically bound
 * against `cap` (a parsed leaf/reason may be far larger than the fixed
 * field it lands in) — memcpy + explicit truncation, not snprintf("%s"),
 * so -Wformat-truncation has nothing to flag. */
static void hdl_bcpy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

struct hdl_entry { char leaf[HDL_LEAF]; char reason[HDL_REASON]; };
struct hdl_tokset { char tok[HDL_TOKSET][HDL_TOK]; int n; };

/* ── env-var overrides (ZCL_HOTSWAP_DENY_*), test isolation only ────────── */
static const char *hdl_denylist(void)
{ return env_or("ZCL_HOTSWAP_DENYLIST", "engine/composition/hotswap_denied_leaves.def"); }
static const char *hdl_scan_dir(void)
{ return env_or("ZCL_HOTSWAP_DENY_SCAN_DIR", "engine/composition"); }
static const char *hdl_catalog(void)
{ return env_or("ZCL_HOTSWAP_DENY_CATALOG", "engine/composition/commands"); }
static const char *hdl_tu_root(void)
{ return env_or("ZCL_HOTSWAP_DENY_TU_ROOT", "."); }

static int hdl_note(FILE *viol, int *nv, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vfprintf(viol, fmt, ap);
    va_end(ap);
    if (k < 0)
        return die("z23-lint: write failed\n", "");
    (*nv)++;
    return 0;
}

/* Quote-aware comment stripper, one line at a time; *in_block and *in_string
 * persist across calls for one file/stream (a block comment or a string
 * literal may span lines), reset to 0 at the start of each scan. Comment
 * text is dropped; string-literal bodies (including a `*` inside them) are
 * copied through untouched, exactly like the shell gate's awk stripper. */
/* One step inside an already-open block comment: blank it, clear *in_block
 * on the closing star-slash. Returns the new i. */
static size_t hdl_strip_block_step(int *in_block, const char *in, size_t n, size_t i)
{
    if (in[i] == '*' && i + 1 < n && in[i + 1] == '/') { *in_block = 0; return i + 2; }
    return i + 1;
}

/* One step inside an already-open "..." literal: copy the char through
 * (a backslash escape copies both bytes verbatim), clear *in_string on the
 * closing quote. Returns the new i. */
static size_t hdl_strip_string_step(int *in_string, const char *in, size_t n,
                                    size_t i, char *out, size_t cap, size_t *oi)
{
    char c = in[i];
    if (c == '\\' && i + 1 < n) {
        if (*oi + 2 < cap) { out[*oi] = c; out[*oi + 1] = in[i + 1]; *oi += 2; }
        return i + 2;
    }
    if (*oi + 1 < cap) out[(*oi)++] = c;
    if (c == '"') *in_string = 0;
    return i + 1;
}

/* One step outside any comment/string: recognizes a line comment (blanks
 * the rest of the line), a block-comment open, and a quote opening a
 * literal; anything else is copied through. Returns the new i, or n to
 * stop the line. */
static size_t hdl_strip_default_step(int *in_block, int *in_string, const char *in,
                                     size_t n, size_t i, char *out, size_t cap,
                                     size_t *oi)
{
    if (in[i] == '/' && i + 1 < n && in[i + 1] == '/') return n;
    if (in[i] == '/' && i + 1 < n && in[i + 1] == '*') { *in_block = 1; return i + 2; }
    if (in[i] == '"') {
        if (*oi + 1 < cap) out[(*oi)++] = in[i];
        *in_string = 1;
        return i + 1;
    }
    if (*oi + 1 < cap) out[(*oi)++] = in[i];
    return i + 1;
}

static void hdl_strip_line(int *in_block, int *in_string, const char *in,
                           char *out, size_t cap)
{
    size_t n = strlen(in), oi = 0, i = 0;
    while (i < n) {
        if (*in_block)
            i = hdl_strip_block_step(in_block, in, n, i);
        else if (*in_string)
            i = hdl_strip_string_step(in_string, in, n, i, out, cap, &oi);
        else
            i = hdl_strip_default_step(in_block, in_string, in, n, i, out, cap, &oi);
    }
    out[oi < cap ? oi : cap - 1] = '\0';
}

/* Every whitespace-separated word inside every "..." literal on `line`
 * (already comment-stripped) becomes one token in `ts`; a bare
 * "core.chain.block.get" argument and a space-separated leaf list
 * ("a b c") inside one literal are both covered. */
static int hdl_tok_add(struct hdl_tokset *ts, const char *tok)
{
    if (!tok[0]) return 0;
    for (int i = 0; i < ts->n; i++)
        if (strcmp(ts->tok[i], tok) == 0) return 0;
    if (ts->n >= HDL_TOKSET)
        return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(ts->tok[ts->n], HDL_TOK, "%s", tok), HDL_TOK))
        return 2;
    ts->n++;
    return 0;
}

static int hdl_tokenize_line(const char *line, struct hdl_tokset *ts)
{
    const char *p = line;
    while ((p = strchr(p, '"')) != NULL) {
        const char *close = strchr(p + 1, '"');
        if (!close) break;
        char lit[HDL_LINE];
        size_t len = (size_t)(close - (p + 1));
        if (len >= sizeof lit) len = sizeof lit - 1;
        memcpy(lit, p + 1, len);
        lit[len] = '\0';
        char *save = NULL;
        char *w = strtok_r(lit, " \t", &save);
        while (w) {
            int rc = hdl_tok_add(ts, w);
            if (rc) return rc;
            w = strtok_r(NULL, " \t", &save);
        }
        p = close + 1;
    }
    return 0;
}

static int hdl_tokset_has(const struct hdl_tokset *ts, const char *tok)
{
    for (int i = 0; i < ts->n; i++)
        if (strcmp(ts->tok[i], tok) == 0) return 1;
    return 0;
}

/* Scan-then-tokenize one file: strip comments line by line (state carried
 * across the whole file), collect every literal-body word into `ts`. */
static int hdl_scan_file_tokens(const char *path, struct hdl_tokset *ts)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        return 2;
    }
    int in_block = 0, in_string = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        char stripped[HDL_LINE];
        hdl_strip_line(&in_block, &in_string, line, stripped, sizeof stripped);
        rc = hdl_tokenize_line(stripped, ts);
    }
    if (rc == 0 && ferror(f)) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        rc = 2;
    }
    free(line);
    fclose(f);
    return rc;
}

/* ── parse the denylist ──────────────────────────────────────────────────
 * Whole-file, quote-aware, offset-driven scan for
 * HOTSWAP_DENIED_LEAF("leaf", "reason"...) invocations. A reason may be
 * split across as many adjacent string literals as it needs (they
 * concatenate) and may itself contain parentheses — only a ')' OUTSIDE a
 * quoted literal ends the invocation. */
static int hdl_load_denylist_buf(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        return 2;
    }
    int in_block = 0, in_string = 0;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    size_t used = 0;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &lcap, f)) >= 0) {
        char stripped[HDL_LINE];
        hdl_strip_line(&in_block, &in_string, line, stripped, sizeof stripped);
        size_t sl = strlen(stripped);
        if (used + sl + 2 >= cap) { rc = die("z23-lint: derived buffer overflow\n", ""); break; }
        memcpy(buf + used, stripped, sl);
        used += sl;
        buf[used++] = ' ';
    }
    if (rc == 0 && ferror(f)) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        rc = 2;
    }
    buf[used] = '\0';
    free(line);
    fclose(f);
    return rc;
}

static size_t hdl_read_qstring(const char *buf, size_t n, size_t i, char *out,
                               size_t outcap)
{
    size_t oi = 0;
    while (i < n) {
        char c = buf[i];
        if (c == '\\' && i + 1 < n) {
            if (oi + 1 < outcap) out[oi++] = buf[i + 1];
            i += 2;
            continue;
        }
        if (c == '"') { i++; break; }
        if (oi + 1 < outcap) out[oi++] = c;
        i++;
    }
    out[oi < outcap ? oi : outcap - 1] = '\0';
    return i;
}

static int hdl_parse_one_entry(const char *buf, size_t n, size_t *ip,
                               struct hdl_entry *e)
{
    size_t i = *ip;
    e->leaf[0] = '\0';
    e->reason[0] = '\0';
    int k = 0;
    while (i < n) {
        char c = buf[i];
        if (c == ')') { i++; break; }
        if (c == '"') {
            i++;
            char s[HDL_REASON];
            i = hdl_read_qstring(buf, n, i, s, sizeof s);
            if (k == 0)
                hdl_bcpy(e->leaf, sizeof e->leaf, s);
            else {
                size_t rl = strlen(e->reason);
                hdl_bcpy(e->reason + rl, sizeof e->reason - rl, s);
            }
            k++;
            continue;
        }
        i++;
    }
    *ip = i;
    return 0;
}

static int hdl_parse_denylist(const char *buf, struct hdl_entry *out, int *n)
{
    size_t len = strlen(buf);
    const char *needle = "HOTSWAP_DENIED_LEAF";
    size_t nl = strlen(needle);
    size_t i = 0;
    while (i < len) {
        const char *hit = strstr(buf + i, needle);
        if (!hit) break;
        size_t pos = (size_t)(hit - buf) + nl;
        while (pos < len && buf[pos] != '(') pos++;
        if (pos >= len) break;
        pos++;
        if (*n >= HDL_ENTRIES)
            return die("z23-lint: derived buffer overflow\n", "");
        int rc = hdl_parse_one_entry(buf, len, &pos, &out[*n]);
        if (rc) return rc;
        (*n)++;
        i = pos;
    }
    return 0;
}

static int hdl_leaf_name_valid(const char *leaf)
{
    if (!leaf[0]) return 0;
    for (const char *p = leaf; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.'))
            return 0;
    return 1;
}

/* grep -rqF "\"<leaf>\"," over CATALOG, every regular file recursively (the
 * original scans the whole tree, not just *.def, so README.md would count
 * too — it never matches, but parity means not assuming the extension). */
/* One regular file's contribution to the recursive grep -rqF scan: sets
 * *found and returns 0, or UNPROVEN-exit-2 naming the path on an open/read
 * failure. */
static int hdl_file_has_leaf(const char *path, const char *needle, int *found)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t rn;
    while (!*found && (rn = getline(&line, &cap, f)) >= 0)
        if (strstr(line, needle)) *found = 1;
    int rc = 0;
    if (!*found && ferror(f)) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
        rc = 2;
    }
    free(line);
    fclose(f);
    return rc;
}

static int hdl_dir_has_leaf(const char *dir, const char *needle, int *found)
{
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", dir);
        return 2;
    }
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && !*found && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char path[HDL_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/%s", dir, de->d_name), sizeof path)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (lstat(path, &st) != 0) {
            fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", path);
            rc = 2;
            break;
        }
        if (S_ISDIR(st.st_mode))
            rc = hdl_dir_has_leaf(path, needle, found);
        else if (S_ISREG(st.st_mode))
            rc = hdl_file_has_leaf(path, needle, found);
    }
    closedir(d);
    return rc;
}

static int hdl_catalog_declares(const char *catalog, const char *leaf, int *found)
{
    char needle[HDL_LEAF + 3];
    if (ovf(snprintf(needle, sizeof needle, "\"%s\",", leaf), sizeof needle))
        return 2;
    *found = 0;
    return hdl_dir_has_leaf(catalog, needle, found);
}

/* ── enumerate the hot-swap manifests: <scan_dir>/hotswap*.def plus
 * hotfork_capsules.def, direct children only, sorted, denylist excluded. */
static int hdl_manifest_name_matches(const char *name)
{
    if (strcmp(name, "hotfork_capsules.def") == 0) return 1;
    size_t nl = strlen(name);
    if (nl < 12) return 0;
    return strncmp(name, "hotswap", 7) == 0
        && strcmp(name + nl - 4, ".def") == 0;
}

static int hdl_cmp_str(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int hdl_enumerate_manifests(const char *scan_dir, const char *denylist,
                                   char names[][HDL_PATH], int *nm)
{
    DIR *d = opendir(scan_dir);
    if (!d) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", scan_dir);
        return 2;
    }
    char deny_base[HDL_PATH];
    const char *slash = strrchr(denylist, '/');
    snprintf(deny_base, sizeof deny_base, "%s", slash ? slash + 1 : denylist);
    char deny_dir[HDL_PATH];
    if (slash) {
        size_t dl = (size_t)(slash - denylist);
        if (dl >= sizeof deny_dir) dl = sizeof deny_dir - 1;
        memcpy(deny_dir, denylist, dl);
        deny_dir[dl] = '\0';
    } else {
        snprintf(deny_dir, sizeof deny_dir, ".");
    }
    int same_dir = strcmp(deny_dir, scan_dir) == 0;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d)) != NULL) {
        if (!hdl_manifest_name_matches(de->d_name)) continue;
        if (same_dir && strcmp(de->d_name, deny_base) == 0) continue;
        char path[HDL_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/%s", scan_dir, de->d_name), sizeof path)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (*nm >= HDL_MANIFESTS) { rc = die("z23-lint: derived buffer overflow\n", ""); break; }
        snprintf(names[*nm], HDL_PATH, "%s", path);
        (*nm)++;
    }
    closedir(d);
    if (rc == 0) qsort(names, (size_t)*nm, HDL_PATH, hdl_cmp_str);
    return rc;
}

/* ── the C-side leaf tables: TU list parsed from hotswap_eligible.def /
 * hotswap_swappable.def rows, then the body of every #ifdef ZCL_HOTSWAP_GEN
 * / #ifdef ZCL_HOTSWAP_MODULE_GEN block in each TU, nesting-aware. */
static int hdl_tus_add(char tus[][HDL_PATH], int *nt, const char *tu)
{
    for (int i = 0; i < *nt; i++)
        if (strcmp(tus[i], tu) == 0) return 0;
    if (*nt >= HDL_TUS) return die("z23-lint: derived buffer overflow\n", "");
    snprintf(tus[*nt], HDL_PATH, "%s", tu);
    (*nt)++;
    return 0;
}

static int hdl_collect_tus_from(const char *manifest_path, const char *base,
                                char tus[][HDL_PATH], int *nt)
{
    regex_t re;
    const char *pat = strcmp(base, "hotswap_eligible.def") == 0
        ? "^[[:space:]]*HOTSWAP_ELIGIBLE\\(\"([^\"]*)\"\\)"
        : "^[[:space:]]*HOTSWAP_SWAPPABLE\\(\"([^\"]*)\"";
    int cr = compile_pat(&re, REG_EXTENDED, pat, "", "", "");
    if (cr) return cr;
    FILE *f = fopen(manifest_path, "r");
    if (!f) {
        regfree(&re);
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", manifest_path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        regmatch_t m[2];
        if (regexec(&re, line, 2, m, 0) == 0) {
            char tu[HDL_PATH];
            size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
            if (len >= sizeof tu) len = sizeof tu - 1;
            memcpy(tu, line + m[1].rm_so, len);
            tu[len] = '\0';
            rc = hdl_tus_add(tus, nt, tu);
        }
    }
    if (rc == 0 && ferror(f)) rc = die("z23-lint: read failed: %s\n", manifest_path);
    free(line);
    fclose(f);
    regfree(&re);
    return rc;
}

/* Body of every #ifdef ZCL_HOTSWAP_GEN / #ifdef ZCL_HOTSWAP_MODULE_GEN
 * block, resident code outside those blocks excluded. */
static int hdl_gen_block_dir(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '#';
}

/* One #if/#ifdef/#ifndef or #endif directive line's effect on the
 * nesting-aware on/depth state that tracks whether we're inside a
 * ZCL_HOTSWAP_GEN / ZCL_HOTSWAP_MODULE_GEN block. */
static void hdl_gen_block_directive(const char *line, int *on, int *depth)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    p++; /* '#' */
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "if", 2) == 0) {
        if (!*on) {
            if (strstr(line, "ZCL_HOTSWAP_GEN") || strstr(line, "ZCL_HOTSWAP_MODULE_GEN")) {
                *on = 1; *depth = 1;
            }
        } else {
            (*depth)++;
        }
    } else if (strncmp(p, "endif", 5) == 0 && *on) {
        (*depth)--;
        if (*depth == 0) *on = 0;
    }
}

static int hdl_extract_gen_tokens(const char *tu_path, struct hdl_tokset *ts)
{
    FILE *f = fopen(tu_path, "r");
    if (!f) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: cannot open %s\n", tu_path);
        return 2;
    }
    int on = 0, depth = 0, in_block = 0, in_string = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (hdl_gen_block_dir(line)) {
            hdl_gen_block_directive(line, &on, &depth);
            continue;
        }
        if (!on) continue;
        char stripped[HDL_LINE];
        hdl_strip_line(&in_block, &in_string, line, stripped, sizeof stripped);
        rc = hdl_tokenize_line(stripped, ts);
    }
    if (rc == 0 && ferror(f)) rc = die("z23-lint: read failed: %s\n", tu_path);
    free(line);
    fclose(f);
    return rc;
}

/* ── run ──────────────────────────────────────────────────────────────── */

static int hdl_load_and_validate_entries(const char *denylist, const char *catalog,
                                         FILE *viol, int *nv,
                                         char leaves[][HDL_LEAF], int *nleaves)
{
    static char buf[1 << 17];
    int rc = hdl_load_denylist_buf(denylist, buf, sizeof buf);
    if (rc) return rc;
    static struct hdl_entry entries[HDL_ENTRIES];
    int n = 0;
    rc = hdl_parse_denylist(buf, entries, &n);
    if (rc) return rc;
    char hint[256];
    snprintf(hint, sizeof hint,
             "no HOTSWAP_DENIED_LEAF(\"leaf\", \"reason\") entries parsed from %s",
             denylist);
    rc = gate_require_scanned(n, 1, "check_hotswap_denied_leaves", hint);
    if (rc) return rc;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *leaf = entries[i].leaf;
        const char *reason = entries[i].reason;
        if (!hdl_leaf_name_valid(leaf)) {
            rc = hdl_note(viol, nv, "  denylist row '%s' has no valid dotted leaf\n", leaf);
            continue;
        }
        if (strlen(reason) < 20)
            rc = hdl_note(viol, nv,
                "  %s (denylist row carries no usable reason — the reason must "
                "live beside the name)\n", leaf);
        int declared = 0;
        if (rc == 0) rc = hdl_catalog_declares(catalog, leaf, &declared);
        if (rc == 0 && !declared)
            rc = hdl_note(viol, nv,
                "  %s (not declared in %s — a denial of a nonexistent leaf is "
                "hollow)\n", leaf, catalog);
        if (rc) continue;
        if (*nleaves >= HDL_ENTRIES) { rc = die("z23-lint: derived buffer overflow\n", ""); continue; }
        hdl_bcpy(leaves[*nleaves], HDL_LEAF, leaf);
        (*nleaves)++;
    }
    if (rc) return rc;
    return gate_require_scanned(*nleaves, 1, "check_hotswap_denied_leaves",
        "every denylist row failed to yield a leaf name");
}

static int hdl_scan_manifests(char names[][HDL_PATH], int nm,
                              char leaves[][HDL_LEAF], int nleaves,
                              FILE *viol, int *nv)
{
    int rc = 0;
    for (int i = 0; i < nm && rc == 0; i++) {
        struct hdl_tokset ts = {0};
        rc = hdl_scan_file_tokens(names[i], &ts);
        for (int j = 0; rc == 0 && j < nleaves; j++)
            if (hdl_tokset_has(&ts, leaves[j]))
                rc = hdl_note(viol, nv, "  %s names denied leaf '%s'\n", names[i], leaves[j]);
    }
    return rc;
}

static int hdl_scan_gen_tables(char tus[][HDL_PATH], int nt, const char *tu_root,
                               char leaves[][HDL_LEAF], int nleaves,
                               FILE *viol, int *nv)
{
    int rc = 0;
    for (int i = 0; i < nt && rc == 0; i++) {
        char tu_path[HDL_PATH * 2];
        if (ovf(snprintf(tu_path, sizeof tu_path, "%s/%s", tu_root, tus[i]), sizeof tu_path))
            return 2;
        struct stat st;
        if (stat(tu_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        struct hdl_tokset ts = {0};
        rc = hdl_extract_gen_tokens(tu_path, &ts);
        for (int j = 0; rc == 0 && j < nleaves; j++)
            if (hdl_tokset_has(&ts, leaves[j]))
                rc = hdl_note(viol, nv,
                    "  %s stages denied leaf '%s' in a ZCL_HOTSWAP_*_GEN leaf "
                    "table\n", tus[i], leaves[j]);
    }
    return rc;
}

/* Header line + the three fail-closed existence checks (denylist readable,
 * catalog and scan dir present). */
static int hdl_preflight(const char *denylist, const char *scan_dir, const char *catalog)
{
    if (fputs("══ LINT: hot-swap leaf denylist (never-swappable command leaves) ══\n",
              g_hdl_out) < 0)
        return die("z23-lint: write failed\n", "");

    if (access(denylist, R_OK) != 0) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: FATAL — denylist '%s' "
                "missing/unreadable.\n", denylist);
        fputs("  An absent denylist does NOT mean 'nothing is denied'. Refusing\n"
              "  to report 'clean' with no owner decision to enforce.\n", g_hdl_err);
        return 2;
    }
    struct stat cst, sst;
    if (stat(catalog, &cst) != 0 || !S_ISDIR(cst.st_mode)) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: FATAL — command catalog "
                "'%s' missing.\n", catalog);
        return 2;
    }
    if (stat(scan_dir, &sst) != 0 || !S_ISDIR(sst.st_mode)) {
        fprintf(g_hdl_err, "check_hotswap_denied_leaves: FATAL — scan dir '%s' "
                "missing.\n", scan_dir);
        return 2;
    }
    return 0;
}

/* The C-side TU list: every hotswap_eligible.def / hotswap_swappable.def
 * row among the enumerated manifests. */
static int hdl_collect_all_tus(char manifests[][HDL_PATH], int nm,
                               char tus[][HDL_PATH], int *nt)
{
    int rc = 0;
    for (int i = 0; i < nm && rc == 0; i++) {
        const char *slash = strrchr(manifests[i], '/');
        const char *base = slash ? slash + 1 : manifests[i];
        if (strcmp(base, "hotswap_eligible.def") == 0
            || strcmp(base, "hotswap_swappable.def") == 0)
            rc = hdl_collect_tus_from(manifests[i], base, tus, nt);
    }
    if (rc == 0)
        rc = gate_require_scanned(*nt, 1, "check_hotswap_denied_leaves",
            "no hot-swappable translation units parsed from the manifests");
    return rc;
}

/* Dump the accumulated violation lines to g_hdl_err and print the shared
 * FAIL explanation. `viol` is always closed on the way out. */
static int hdl_emit_violations(FILE *viol, const char *denylist)
{
    if (fseek(viol, 0, SEEK_SET) != 0) { fclose(viol); return die("z23-lint: fseek failed\n", ""); }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, viol)) >= 0)
        if (fwrite(line, 1, (size_t)n, g_hdl_err) != (size_t)n) {
            free(line); fclose(viol);
            return die("z23-lint: write failed\n", "");
        }
    free(line);
    fclose(viol);
    fputs("FAIL: a hot-swap manifest names a leaf the owner ruled never swappable.\n"
          "  These leaves render block/transaction bytes: a swapped generation\n"
          "  misreports the chain to every RPC reader without touching\n"
          "  validation. 'Read-only' is not the test on a rendering path.\n", g_hdl_err);
    fprintf(g_hdl_err, "  The rule and its per-leaf reason live in %s.\n", denylist);
    fputs("  Removing a row there is an OWNER decision, not a lane's.\n", g_hdl_err);
    return 1;
}

int check_hotswap_denied_leaves_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    hdl_io_prod();
    const char *denylist = hdl_denylist();
    const char *scan_dir = hdl_scan_dir();
    const char *catalog = hdl_catalog();
    const char *tu_root = hdl_tu_root();

    int rc = hdl_preflight(denylist, scan_dir, catalog);
    if (rc) return rc;

    FILE *viol = tmpfile();
    if (!viol) return die("z23-lint: tmpfile failed\n", "");
    int nv = 0;
    static char leaves[HDL_ENTRIES][HDL_LEAF];
    int nleaves = 0;
    rc = hdl_load_and_validate_entries(denylist, catalog, viol, &nv, leaves, &nleaves);
    if (rc) { fclose(viol); return rc; }

    static char manifests[HDL_MANIFESTS][HDL_PATH];
    int nm = 0;
    rc = hdl_enumerate_manifests(scan_dir, denylist, manifests, &nm);
    if (rc == 0) {
        char hint[256];
        snprintf(hint, sizeof hint,
                 "no hot-swap manifests found under %s — the scan producer emptied",
                 scan_dir);
        rc = gate_require_scanned(nm, 1, "check_hotswap_denied_leaves", hint);
    }
    if (rc) { fclose(viol); return rc; }

    rc = hdl_scan_manifests(manifests, nm, leaves, nleaves, viol, &nv);
    if (rc) { fclose(viol); return rc; }

    static char tus[HDL_TUS][HDL_PATH];
    int nt = 0;
    rc = hdl_collect_all_tus(manifests, nm, tus, &nt);
    if (rc) { fclose(viol); return rc; }

    rc = hdl_scan_gen_tables(tus, nt, tu_root, leaves, nleaves, viol, &nv);
    if (rc) { fclose(viol); return rc; }

    if (nv > 0)
        return hdl_emit_violations(viol, denylist);
    fclose(viol);
    if (fprintf(g_hdl_out, "  OK: %d denied leaf/leaves absent from %d hot-swap manifest(s)\n",
                nleaves, nm) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
