/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-no-runtime-abort. Byte-parity port of
 * tools/lint/check_no_runtime_abort.sh (at 89fca9905): a shrink-only,
 * per-file ratchet on RUNTIME assert()/abort() sites in network-reachable
 * code (assert() is LIVE in this build — -DNDEBUG is set only for the
 * vendored LevelDB compile). A site inside a comment or a string literal
 * does not count; `_Static_assert`/`static_assert` (compile-time) never
 * count; a site carrying `// abort-ok:<reason>` (>=6 char reason) is
 * annotated, not counted. Baseline rows may only shrink; a file with no
 * sites left must be deleted from the baseline (STALE).
 *
 * Gates: check-no-runtime-abort
 * Single-gate family (the port's _selftest.c sibling shares this subject
 * and is not reused by any other gate).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_runtime_abort_priv.h"

const char nra_gate_name[] = "check_no_runtime_abort";

/* Network-reachable roots only, not the whole tree — see the shell's own
 * rationale comment (a whole-tree scan drowns the signal in boot-only and
 * tooling code). Verbatim copy of SCAN_ROOTS_DEFAULT. */
static const char k_roots_default[] =
    "core/modules/crypto contexts/wallet/modules/keys core/modules/script "
    "core/modules/sapling core/modules/validation "
    "core/modules/net core/modules/sync contexts/wallet/modules/zid "
    "contexts/naming/modules/znam contexts/market/modules/zslp "
    "contexts/naming/modules/zdir engine/modules/storage core/modules/mining "
    "core/modules/core platform/modules/platform platform/modules/util "
    "engine/modules/rpc "
    "domain/encoding domain/wallet "
    "core/consensus core/math core/params core/chainparams";

/* ── generic string list (scan_files / violation / stale) ─────────────────
 * struct nra_list is declared in gate_no_runtime_abort_priv.h — shared with
 * gate_no_runtime_abort_report.c, which builds the violation/stale lists. */

int nra_push(struct nra_list *l, const char *s, size_t n)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, s, n);
    copy[n] = '\0';
    l->v[l->n++] = copy;
    return 0;
}

int nra_push_s(struct nra_list *l, const char *s)
{
    return nra_push(l, s, strlen(s));
}

void nra_free(struct nra_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* ── scan-root splitting (bash `read -r -a SCAN_ROOTS <<<`) ─────────────── */

static int nra_split_roots(const char *text, char out[][NRA_ROOT_LEN],
                           int max, int *n)
{
    *n = 0;
    const char *p = text;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t')
            e++;
        if (*n >= max)
            return die("z23-lint: too many scan roots\n", "");
        size_t n2 = (size_t)(e - p);
        if (n2 >= NRA_ROOT_LEN)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out[*n], p, n2);
        out[*n][n2] = '\0';
        (*n)++;
        p = e;
    }
    return 0;
}

/* ── scan-file collection: .c and .h files under each root, minus any
 * path under a "test" directory, minus the shared production-scan
 * exclusions (fixtures, build, vendor, .claude, test-tmp under
 * ZCL_LINT_PRODUCTION_SCAN=1). */

struct nra_collect_ctx { struct nra_list *files; };

static int nra_collect_one(const char *path, void *vctx)
{
    struct nra_collect_ctx *cc = vctx;
    if (strstr(path, "/test/"))
        return 0;
    if (lint_path_is_excluded(path))
        return 0;
    return nra_push_s(cc->files, path);
}

static int nra_collect_files(const struct nra_ctx *c, struct nra_list *files)
{
    struct nra_collect_ctx cc = { files };
    int rc = 0;
    for (int i = 0; rc == 0 && i < c->nroots; i++) {
        struct stat st;
        if (stat(c->roots[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue; /* a missing root is skipped, caught by the floor */
        rc = walk_src(c->roots[i], 1, nra_collect_one, &cc);
    }
    return rc;
}

/* ── per-site scan (the awk comment/string state machine + hatch check) ──
 * NRA_SITE/NRA_HATCH and struct nra_row/nra_rows are declared in
 * gate_no_runtime_abort_priv.h — the report side walks the rows to print
 * the per-site detail lines. */

static int nra_row_push(struct nra_rows *r, const struct nra_row *row)
{
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 64;
        struct nra_row *nv = realloc(r->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        r->v = nv;
        r->cap = nc;
    }
    r->v[r->n++] = *row;
    return 0;
}

static void nra_trim(char *s)
{
    size_t n = strlen(s);
    size_t start = 0;
    while (s[start] == ' ' || s[start] == '\t')
        start++;
    if (start)
        memmove(s, s + start, n - start + 1);
    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* The abort-ok escape hatch, either as a line comment or a block comment,
 * with a reason of >= 6 characters after trimming a trailing block-comment
 * closer and whitespace. Operates on the RAW (unscrubbed) line, matching
 * the awk's has_hatch($0). */
/* Nearest of a "//" line comment opener and a block-comment opener in s,
 * or NULL if neither is present. */
static const char *nra_nearest_comment(const char *s)
{
    const char *c1 = strstr(s, "//");
    const char *c2 = strstr(s, "/*");
    if (c1 && c2)
        return (c1 < c2) ? c1 : c2;
    return c1 ? c1 : c2;
}

/* Trim leading whitespace, a trailing block-comment closer plus any
 * whitespace around it, then any remaining trailing whitespace; return the
 * trimmed length. */
static size_t nra_hatch_trim_len(char *reason)
{
    char *t = reason;
    while (*t == ' ' || *t == '\t')
        t++;
    size_t n = strlen(t);
    while (n >= 2 && t[n - 2] == '*' && t[n - 1] == '/') {
        n -= 2;
        while (n && (t[n - 1] == ' ' || t[n - 1] == '\t'))
            n--;
    }
    while (n && (t[n - 1] == ' ' || t[n - 1] == '\t'))
        n--;
    return n;
}

static int nra_has_hatch(const char *s)
{
    const char *p = strstr(s, "abort-ok:");
    if (!p)
        return 0;
    const char *co = nra_nearest_comment(s);
    if (!co || co > p)
        return 0;
    char reason[512];
    const char *r = p + 9; /* strlen("abort-ok:") */
    if (ovf(snprintf(reason, sizeof reason, "%s", r), sizeof reason))
        return 0;
    return (int)nra_hatch_trim_len(reason) >= 6;
}

/* [^_[:alnum:]](assert|abort)[ \t]*\( with an equivalent start-of-string
 * alternative, on the comment/string-scrubbed line. */
static int nra_hit(const regex_t *re, const char *scrubbed)
{
    return regexec(re, scrubbed, 0, NULL, 0) == 0;
}

struct nra_scan_ctx {
    struct cstrip st;
    const regex_t *re;
    struct nra_rows *rows;
};

static int nra_scan_file(const char *path, void *vctx)
{
    struct nra_scan_ctx *sc = vctx;
    sc->st.in_block = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int lineno = 0, rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        lineno++;
        size_t n = (size_t)nread;
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        char scrubbed[CSTRIP_LINE_MAX];
        if (!cstrip_line(&sc->st, line, n, scrubbed, sizeof scrubbed))
            continue; /* a pathological over-long line: no match possible */
        if (!nra_hit(sc->re, scrubbed))
            continue;
        struct nra_row row;
        memset(&row, 0, sizeof row);
        row.kind = nra_has_hatch(line) ? NRA_HATCH : NRA_SITE;
        if (ovf(snprintf(row.path, sizeof row.path, "%s", path),
                sizeof row.path)) {
            rc = 2;
            break;
        }
        row.lineno = lineno;
        char trimmed[512];
        if (ovf(snprintf(trimmed, sizeof trimmed, "%s", line),
                sizeof trimmed)) {
            rc = 2;
            break;
        }
        nra_trim(trimmed);
        if (ovf(snprintf(row.text, sizeof row.text, "%s", trimmed),
                sizeof row.text)) {
            rc = 2;
            break;
        }
        rc = nra_row_push(sc->rows, &row);
    }
    return fin(f, line, path, rc);
}

static int nra_scan_sites(const struct nra_list *files, const regex_t *re,
                          struct nra_rows *rows)
{
    struct nra_scan_ctx sc = { { 0 }, re, rows };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < files->n; i++)
        rc = nra_scan_file(files->v[i], &sc);
    return rc;
}

/* ── baseline (gate_lib.sh gate_load_kv_file: "<path> <count>", # comment
 * and blank lines skipped, no trimming beyond that) ─────────────────────
 * struct nra_base_row/nra_baseline are declared in
 * gate_no_runtime_abort_priv.h — shared with the report side, which counts
 * observed sites per file into the same shape and ratchets it against
 * this loaded baseline. */

int nra_base_push(struct nra_baseline *b, const char *path, int n)
{
    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 64;
        struct nra_base_row *nv = realloc(b->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        b->v = nv;
        b->cap = nc;
    }
    struct nra_base_row *row = &b->v[b->n++];
    if (ovf(snprintf(row->path, sizeof row->path, "%s", path),
            sizeof row->path))
        return 2;
    row->allowed = n;
    row->used = 0;
    return 0;
}

struct nra_base_row *nra_base_find(struct nra_baseline *b,
                                   const char *path)
{
    for (size_t i = 0; i < b->n; i++)
        if (strcmp(b->v[i].path, path) == 0)
            return &b->v[i];
    return NULL;
}

static int nra_base_line(char *line, struct nra_baseline *b)
{
    char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '#')
        return 0;
    char *sp = strrchr(p, ' ');
    if (!sp)
        sp = strrchr(p, '\t');
    if (!sp)
        return 0; /* malformed row: no count column; skip like awk would */
    *sp = '\0';
    int n = atoi(sp + 1);
    if (nra_base_find(b, p))
        return die("z23-lint: duplicate baseline row: %s\n", p);
    return nra_base_push(b, p, n);
}

static int nra_base_load(const char *path, struct nra_baseline *b)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* gate_load_kv_file: a missing baseline is an empty set */
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        size_t n = (size_t)nread;
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = nra_base_line(line, b);
    }
    return fin(f, line, path, rc);
}

void nra_baseline_free(struct nra_baseline *b)
{
    free(b->v);
    b->v = NULL;
    b->n = b->cap = 0;
}

/* ── orchestration ────────────────────────────────────────────────────── */

static enum nra_mode nra_parse_mode(const char *s)
{
    if (strcmp(s, "WARN") == 0)
        return NRA_MODE_WARN;
    if (strcmp(s, "UPDATE") == 0)
        return NRA_MODE_UPDATE;
    return NRA_MODE_FAIL;
}

static int env_int_or(const char *name, int fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? atoi(e) : fallback;
}

int check_no_runtime_abort_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char roots_buf[NRA_ROOTS_MAX][NRA_ROOT_LEN];
    const char *root_ptrs[NRA_ROOTS_MAX];
    int nroots = 0;
    if (nra_split_roots(env_or("ZCL_NO_RUNTIME_ABORT_SCAN_ROOTS",
                               k_roots_default), roots_buf, NRA_ROOTS_MAX,
                        &nroots))
        return 2;
    for (int i = 0; i < nroots; i++)
        root_ptrs[i] = roots_buf[i];
    struct nra_ctx c = {
        .baseline = env_or("ZCL_NO_RUNTIME_ABORT_BASELINE",
                           "tools/lint/no_runtime_abort_baseline.txt"),
        .roots = root_ptrs,
        .nroots = nroots,
        .file_floor = env_int_or("ZCL_NO_RUNTIME_ABORT_FILE_FLOOR", 400),
        .site_floor = env_int_or("ZCL_NO_RUNTIME_ABORT_SITE_FLOOR", 15),
        .mode = nra_parse_mode(env_or("ZCL_LINT_MODE", "FAIL")),
    };
    return nra_run_gate(&c, stdout, stderr);
}

/* nra_write_update() and nra_report() (the PASS/FAIL/UPDATE report,
 * including the per-site detail lines under each violated file) live in
 * gate_no_runtime_abort_report.c — declared in gate_no_runtime_abort_priv.h. */
int nra_run_gate(const struct nra_ctx *c, FILE *out, FILE *err)
{
    (void)err; /* every diagnostic here — gate_require_scanned, die() — is
                * hardcoded to the process's real stderr, matching the
                * shell's own >&2 redirections; nothing in this gate needs
                * a redirectable stream. */
    regex_t re;
    int rc = reg_fail(&re, regcomp(&re,
        "(^|[^_[:alnum:]])(assert|abort)[ \t]*\\(", REG_EXTENDED));
    if (rc)
        return rc;

    struct nra_list files = { NULL, 0, 0 };
    rc = nra_collect_files(c, &files);
    if (rc == 0)
        rc = gate_require_scanned((int)files.n, c->file_floor, nra_gate_name,
            "no production .c/.h under the scan roots");

    struct nra_rows rows = { NULL, 0, 0 };
    if (rc == 0)
        rc = nra_scan_sites(&files, &re, &rows);
    if (rc == 0)
        rc = gate_require_scanned((int)rows.n, c->site_floor, nra_gate_name,
            "no assert(/abort( sites found at all — the scan or the matcher moved");

    if (rc == 0 && c->mode == NRA_MODE_UPDATE) {
        rc = nra_write_update(c, &rows, out);
    } else if (rc == 0) {
        struct nra_baseline base; memset(&base, 0, sizeof base);
        rc = nra_base_load(c->baseline, &base);
        if (rc == 0)
            rc = nra_report(c, &rows, &files, &base, out);
        nra_baseline_free(&base);
    }

    free(rows.v);
    nra_free(&files);
    regfree(&re);
    return rc;
}
