/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-raw-sqlite — no raw sqlite step primitive in
 * production code outside the AR_* wrappers (activerecord.h), no raw
 * node.db DML issued through sqlite3_exec, and no wallet projection DML
 * outside the owning models. Ported from tools/scripts/check_raw_sqlite.sh
 * (deleted). Selftest: gate_raw_sqlite_selftest.c.
 *
 * WHAT IS SCANNED (same scope as the shell original)
 * -------------------------------------------------
 *   A) core engine contexts cognition platform tools, *.c only, for the
 *      raw step call pattern, with the production-scan exclusions, minus
 *      vendor/test paths, AR_STEP_* macro bodies, safe_alloc, quoted
 *      occurrences, and per-line raw-sql-ok tags. Whole-file allowlist:
 *      tools/scripts/raw_sqlite_allowlist.txt (the ratchet; currently
 *      empty).
 *   B) The same roots, *.c and *.h, pruned of vendor/build/test dirs and
 *      the activerecord.h header itself, for multi-line raw node.db DML
 *      through sqlite3_exec(ndb->db, "...").
 *   C) The controllers/services rooms (repo shape) for wallet projection
 *      DML and destructive model calls from controllers.
 *
 * The principled kernel-store hatch (// raw-sql-ok:progress-kv-kernel-store
 * under the five physical authorities) is counted for visibility only; it
 * does not gate, exactly as in the shell original. Kernel counting skips
 * unreadable files silently because the original pipeline's rc was
 * swallowed; every other unreadable file or unreadable root is FATAL
 * (exit 2), never a skip or a pass.
 *
 * Exit 0 clean, 1 violations, 2 fatal/unproven. Same stdout/stderr lines.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_raw_sqlite_priv.h"

static const char k_crs_gate[] = "check_raw_sqlite";
static const char k_crs_allowlist[] = "tools/scripts/raw_sqlite_allowlist.txt";
const char *const k_crs_prod_roots[CRS_PROD_ROOTS] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
const char *const k_crs_kernel_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};

void crs_chomp(char *s)
{
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '\n')
        s[n - 1] = '\0';
}

/* True when a fgets result filled the buffer without a newline: the line
 * was truncated, which the shell scanners never did. Fail closed. */
int crs_overlong(const char *s)
{
    size_t n = strlen(s);
    return n == CRS_LINE - 1 && s[n - 1] != '\n';
}

int crs_ends_c(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && strcmp(path + n - 2, ".c") == 0;
}

int crs_ends_ch(const char *path)
{
    size_t n = strlen(path);
    return (n >= 2 && strcmp(path + n - 2, ".c") == 0) ||
           (n >= 2 && strcmp(path + n - 2, ".h") == 0);
}

int crs_viol_add(struct crs_viol *v, const char *fmt, ...)
{
    va_list ap;
    if (v->n >= CRS_ROWS) {
        v->overflow = 1;
        return 0;
    }
    va_start(ap, fmt);
    int n = vsnprintf(v->row[v->n], CRS_ROW, fmt, ap);
    va_end(ap);
    if (ovf(n, CRS_ROW))
        v->overflow = 1;
    else
        v->n++;
    return 0;
}

static int crs_is_noise_dir(const char *name)
{
    return strcmp(name, "vendor") == 0 || strcmp(name, "build") == 0 ||
           strcmp(name, "test") == 0;
}

/* Depth-first walk of dir (repo-relative). prune_noise skips vendor/build/
 * test directories whole, the find -prune of the exec scan. A nonzero
 * callback rc or an unreadable dir/file is CRS_FATAL: fail closed. */
static int crs_walk_entry(const char *dir, const char *name, int prune_noise,
                          crs_file_fn fn, void *ctx)
{
    char path[CRS_PATH];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return CRS_FATAL;
    if (stat(path, &st) != 0)
        return CRS_FATAL;
    if (S_ISDIR(st.st_mode)) {
        if (prune_noise && crs_is_noise_dir(name))
            return 0;
        return crs_walk(path, prune_noise, fn, ctx);
    }
    return S_ISREG(st.st_mode) ? fn(path, ctx) : 0;
}

int crs_walk(const char *dir, int prune_noise, crs_file_fn fn, void *ctx)
{
    DIR *d = opendir(dir);
    if (!d)
        return CRS_FATAL;
    struct dirent *e;
    int rc = 0;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) {
            if (errno != 0)
                rc = CRS_FATAL;
            break;
        }
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        rc = crs_walk_entry(dir, e->d_name, prune_noise, fn, ctx);
        if (rc != 0)
            break;
    }
    closedir(d);
    return rc;
}

/* ---- raw step scan -------------------------------------------------- */

static regex_t g_crs_step;
static regex_t g_crs_oktag;
static const char *const k_crs_drop[] = {
    "AR_STEP_ROW_READONLY", "AR_STEP_ROW", "AR_STEP_DONE", "AR_STEP_WRITE",
    "safe_alloc"
};

int crs_raw_init(void)
{
    int rc = compile_pat(&g_crs_step, REG_EXTENDED, "sqlite3_step",
                         "[[:space:]]*\\(", "", "");
    if (rc)
        return rc;
    return compile_pat(&g_crs_oktag, REG_EXTENDED, "// raw-sql-ok:",
                       "[A-Za-z][A-Za-z0-9_-]+", "", "");
}

/* regexec with only REG_NOMATCH as "no match": 1 match, 0 none, -1 after
 * a message for any other regexec error (fail closed, never a pass). */
int crs_rx(const regex_t *re, const char *s, regmatch_t *m, int flags)
{
    int r = regexec(re, s, m ? 1 : 0, m, flags);
    if (r == 0)
        return 1;
    if (r == REG_NOMATCH)
        return 0;
    fprintf(stderr, "%s: FATAL — regexec failed (%d)\n", k_crs_gate, r);
    return -1;
}

/* A call is wrapped only when its nearest enclosing unmatched "(" is
 * immediately preceded (spaces ignored) by a drop token: the call is an
 * argument of the wrapper. Scans back over the stripped text. */
static int crs_wrapped(const char *clean, size_t pos)
{
    int depth = 0;
    size_t i = pos;
    while (i > 0) {
        char ch = clean[--i];
        if (ch == ')')
            depth++;
        else if (ch == '(' && depth-- == 0)
            break;
    }
    if (depth >= 0)
        return 0;
    while (i > 0 && clean[i - 1] == ' ')
        i--;
    for (size_t k = 0; k < sizeof k_crs_drop / sizeof k_crs_drop[0]; k++) {
        size_t tl = strlen(k_crs_drop[k]);
        if (i >= tl && memcmp(clean + i - tl, k_crs_drop[k], tl) == 0)
            return 1;
    }
    return 0;
}

/* Judge EVERY step call on the comment- and literal-stripped line (the
 * shell dropped the whole line on any token or quote): 1 when some call
 * is not an argument of a wrapper, 0 when none is left, -1 on a regexec
 * failure. */
static int crs_line_flagged(const char *clean)
{
    size_t off = 0, len = strlen(clean);
    regmatch_t m;
    while (off < len) {
        int r = crs_rx(&g_crs_step, clean + off, &m, off ? REG_NOTBOL : 0);
        if (r <= 0)
            return r;
        if (!crs_wrapped(clean, off + (size_t)m.rm_so))
            return 1;
        off += (size_t)(m.rm_eo > 0 ? m.rm_eo : 1);
    }
    return 0;
}

static int crs_raw_hit(const char *path, long ln, const char *text,
                       const char *clean, struct crs_raw_ctx *c)
{
    char full[CRS_ROW];
    if (strstr(path, "vendor/") || strstr(path, "/test/"))
        return 0;
    int fl = crs_line_flagged(clean);
    if (fl <= 0)
        return fl < 0 ? CRS_FATAL : 0;
    int ok = crs_rx(&g_crs_oktag, text, NULL, 0);
    if (ok != 0)
        return ok < 0 ? CRS_FATAL : 0;
    if (ovf(snprintf(full, sizeof full, "%s:%ld:%s", path, ln, text),
            sizeof full)) {
        c->v->overflow = 1;
        return 0;
    }
    if (bln_has(c->allowed, path)) {
        (*c->allowed_total)++;
        return 0;
    }
    crs_viol_add(c->v, "%s", full);
    return 0;
}

int crs_raw_file(const char *path, void *ctx)
{
    struct crs_raw_ctx *c = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    if (!crs_ends_c(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return CRS_FATAL;
    char line[CRS_LINE], clean[CRS_LINE];
    struct cstrip st = { 0 };
    long ln = 0;
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        ln++;
        if (crs_overlong(line)) {
            rc = CRS_FATAL;
            break;
        }
        crs_chomp(line);
        if (!cstrip_line(&st, line, strlen(line), clean, sizeof clean))
            rc = CRS_FATAL;
        else
            rc = crs_raw_hit(path, ln, line, clean, c);
    }
    if (ferror(f))
        rc = CRS_FATAL;
    fclose(f);
    return rc;
}

static int crs_scan_raw_root(const char *root, void *ctx)
{
    int rc = crs_walk(root, 0, crs_raw_file, ctx);
    if (rc == CRS_FATAL) {
        fprintf(stderr,
                "%s: FATAL — grep exited 2 scanning physical authorities.\n"
                "  This is a real error (bad pattern / unreadable tree / non-GNU grep),\n"
                "  not 'no matches'. Refusing to pass hollow.\n", k_crs_gate);
        return 2;
    }
    return rc;
}

int crs_scan_raw(struct crs_viol *v, struct bln_set *allowed,
                 int *allowed_total)
{
    struct crs_raw_ctx c = { v, allowed, allowed_total };
    for (size_t i = 0; i < CRS_PROD_ROOTS;
         i++) {
        int rc = crs_scan_raw_root(k_crs_prod_roots[i], &c);
        if (rc)
            return rc;
    }
    return 0;
}

/* ---- principled kernel-store hatch count ---------------------------- */

struct crs_kernel_ctx { int total; };

static int crs_kernel_file(const char *path, void *ctx)
{
    if (!crs_ends_c(path))
        return 0;
    if (strstr(path, "vendor/") || strstr(path, "/test/"))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* the original pipeline swallowed producer errors here */
    char line[CRS_LINE];
    while (fgets(line, sizeof line, f))
        if (strstr(line, "// raw-sql-ok:progress-kv-kernel-store"))
            ((struct crs_kernel_ctx *)ctx)->total++;
    fclose(f);
    return 0;
}

int crs_scan_kernel(int *total)
{
    struct crs_kernel_ctx c = { 0 };
    for (size_t i = 0;
         i < sizeof k_crs_kernel_roots / sizeof k_crs_kernel_roots[0]; i++)
        (void)crs_walk(k_crs_kernel_roots[i], 0, crs_kernel_file, &c);
    *total = c.total;
    return 0;
}

/* ---- verdict --------------------------------------------------------- */

static int crs_verdict(struct crs_viol *v, const struct bln_set *allowed,
                       int allowed_total, int kernel_total)
{
    if (v->overflow) {
        fprintf(stderr, "%s: violation rows exceed %d\n", k_crs_gate,
                CRS_ROWS);
        return 2;
    }
    if (v->n > 0) {
        for (int i = 0; i < v->n; i++)
            printf("%s\n", v->row[i]);
        printf("\nFAIL: raw SQLite write primitive in production code\n");
        printf("  Use AR_STEP_ROW / AR_STEP_DONE / AR_STEP_ROW_READONLY (see\n");
        printf("  engine/models/include/models/activerecord.h), wrap in AR_BEGIN_SAVE /\n");
        printf("  AR_EXEC_BOOL, ar_exec_write_sql(), or — for unavoidable cases like schema bootstrap —\n");
        printf("  add a // raw-sql-ok:<tag> comment on the line (no space after the\n");
        printf("  colon). Kernel-store (consensus.db) sites use the canonical tag\n");
        printf("  // raw-sql-ok:progress-kv-kernel-store (see DEFENSIVE_CODING.md §1).\n");
        printf("  Allowlisted files (still pending sqlite3_step → AR migration) accounted for:\n");
        printf("    %d raw call sites across %d files\n", allowed_total,
               allowed->count);
        return 1;
    }
    if (allowed_total > 0) {
        printf("%s: clean outside allowlist\n", k_crs_gate);
        printf("  Allowlisted: %d raw call sites across %d files\n",
               allowed_total, allowed->count);
        printf("  (drives to zero as sqlite3_step → AR_BEGIN_SAVE migration lands)\n");
    } else {
        printf("%s: clean - no raw sqlite3_step in production code\n",
               k_crs_gate);
    }
    printf("  Principled kernel-store sites (consensus.db, correct-by-design,\n");
    printf("  below AR): %d // raw-sql-ok:progress-kv-kernel-store\n",
           kernel_total);
    return 0;
}

int check_raw_sqlite_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (excl_ensure() != 0)
        return 2;
    if (rs_init() != 0)
        return 2;
    if (crs_raw_init() != 0 || crs_exec_init() != 0)
        return 2;
    static struct crs_viol v;
    static struct bln_set allowed;
    memset(&allowed, 0, sizeof allowed);
    if (bln_load(&allowed, k_crs_allowlist) != 0)
        return 2;
    int allowed_total = 0;
    int rc = crs_scan_raw(&v, &allowed, &allowed_total);
    if (rc)
        return rc;
    int kernel_total = 0;
    crs_scan_kernel(&kernel_total);
    rc = crs_scan_exec(&v);
    if (rc)
        return rc;
    rc = crs_scan_context(&v);
    if (rc)
        return rc;
    return crs_verdict(&v, &allowed, allowed_total, kernel_total);
}
