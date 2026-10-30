/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: sha256 and the per-TRANSLATION-UNIT result cache for the
 * check-windows-cross-syntax gate, ported from tools/lint/tu_result_cache.sh
 * (deleted). Each entry is <cache>/<gate>/<salt>/<src>.<sha>: line 1 is
 * "<rc> <haslog>", the byte-exact compiler log follows. The salt folds the
 * gate identity, both gate source files, the compiler version line, the
 * flag list and the include-set digest of the whole tree, so a hit replays
 * exactly what a fresh compile would have written. Fail-safe, not
 * fail-open: every failure mode disables the cache with a reason; none can
 * turn a red gate green.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include "lintc.h"
#include "base/hex.h"
#include "zsha256/zsha256.h"
#include "gate_windows_cross_syntax_priv.h"

/* ── mkdir -p ───────────────────────────────────────────────────────── */

int wcs_mkdirs_p(const char *path)
{
    char tmp[WCS_PATH];
    size_t n = strlen(path);
    if (n >= sizeof tmp) return -1;
    memcpy(tmp, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* ── cache state ────────────────────────────────────────────────────── */

static int c_on;
static char c_reason[256];
static char c_dir[WCS_PATH];
static char c_stats[WCS_PATH];
static unsigned c_tmp_seq;

static void c_off(const char *reason)
{
    if (wcs_copy(c_reason, sizeof c_reason, reason))
        (void)wcs_copy(c_reason, sizeof c_reason, "cache disabled: reason "
                       "exceeds the state buffer");
    c_on = 0;
}

/* Formats a disable reason; a too-long reason still disables the cache. */
static void c_off_fmt(const char *fmt, const char *arg)
{
    char why[WCS_PATH + 128];
    if (ovf(snprintf(why, sizeof why, fmt, arg), sizeof why))
        c_off("cache disabled: reason exceeds the state buffer");
    else
        c_off(why);
}

int wcs_cache_on(void) { return c_on; }
const char *wcs_cache_off_reason(void) { return c_reason[0] ? c_reason : "not enabled"; }

static int env_eq(const char *name, const char *val)
{
    const char *v = getenv(name);
    return v && strcmp(v, val) == 0;
}

static int cc_version_line(const char *cc, const char *scratch, char *out,
                           size_t cap)
{
    char path[WCS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/ccver.txt", scratch),
            sizeof path))
        return -1;
    char *argv[3] = { (char *)cc, (char *)"--version", NULL };
    wcs_run_capture(path, "/dev/null", argv);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int ok = fgets(out, (int)cap, f) != NULL;
    fclose(f);
    if (ok) {
        size_t n = strlen(out);
        while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    }
    return ok && out[0] ? 0 : -1;
}

struct gen_ent { char name[256]; long mtime; };

static int gen_cmp(const void *a, const void *b)
{
    const struct gen_ent *x = a, *y = b;
    if (x->mtime != y->mtime) return x->mtime > y->mtime ? -1 : 1;
    return strcmp(x->name, y->name);
}

/* 0 on success; -1 when the table of generations is full (readdir would
 * otherwise stop early and leave stale generations unpruned). */
static int prune_generations(const char *gate_root, int keep)
{
    static struct gen_ent ents[128];
    DIR *d = opendir(gate_root);
    if (!d) return 0;
    if (keep < 1) keep = 1;
    int n = 0, rc = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char p[WCS_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", gate_root, de->d_name),
                sizeof p)) {
            rc = -1;
            break;
        }
        if (!lintc_is_dir(p)) continue;
        if (n >= 128) {
            fprintf(stderr, "%s: more than 128 cached generations under %s\n",
                    k_wcs_gate, gate_root);
            rc = -1;
            break;
        }
        struct stat st;
        if (stat(p, &st) != 0) continue;
        if (wcs_copy(ents[n].name, sizeof ents[0].name, de->d_name)) {
            rc = -1;
            break;
        }
        ents[n].mtime = (long)st.st_mtime;
        n++;
    }
    closedir(d);
    if (rc != 0) return -1;
    qsort(ents, (size_t)n, sizeof ents[0], gen_cmp);
    for (int i = keep; i < n; i++) {
        char p[WCS_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", gate_root, ents[i].name),
                sizeof p))
            return -1;
        rap_rm_rf(p);
    }
    return 0;
}

static int cache_gate_root(const char *gate, const char *cachedir, char *out,
                           size_t cap)
{
    const char *ov = getenv("ZCL_LINT_TU_CACHE_DIR");
    if (cachedir)
        return ovf(snprintf(out, cap, "%s/%s", cachedir, gate), cap);
    if (ov && ov[0])
        return ovf(snprintf(out, cap, "%s/%s", ov, gate), cap);
    return ovf(snprintf(out, cap, ".cache/lint-tu/%s", gate), cap);
}

static int generations_to_keep(void)
{
    int keep = 6;
    const char *kg = getenv("ZCL_LINT_TU_CACHE_GENERATIONS");
    if (kg && kg[0]) {
        keep = atoi(kg);
        if (keep < 1) keep = 1;
    }
    return keep;
}

static int cache_env_off(const char *cachedir)
{
    if ((!cachedir || !env_eq("ZCL_TU_CACHE_SELFTEST_FORCE", "1")) &&
        env_eq("ZCL_LINT_TU_CACHE", "0")) {
        c_off("ZCL_LINT_TU_CACHE=0");
        return 1;
    }
    return 0;
}

int wcs_cache_setup(const char *gate, const char *script_path,
                    const char *cc, const char *flags_nul,
                    const char *scratch, const char *root,
                    const char *cachedir)
{
    char ccid[WCS_LINE], dg[WCS_SHA], libsha[WCS_SHA], gsha[WCS_SHA];
    char fsha[WCS_SHA], salt[WCS_SHA], input[WCS_LINE * 2];
    char gate_root[WCS_PATH], dir[WCS_PATH];
    c_on = 0;
    c_dir[0] = c_stats[0] = '\0';
    if (cache_env_off(cachedir)) return 0;
    if (cc_version_line(cc, scratch, ccid, sizeof ccid) != 0) {
        c_off_fmt("'%s' printed no version line", cc);
        return 0;
    }
    if (wcs_include_digest(root, dg) != 0) {
        c_off_fmt("could not digest the include set under '%s'", root);
        return 0;
    }
    wcs_sha_file("tools/lint/lintc/gate_windows_cross_syntax_cache.c", libsha);
    wcs_sha_file(script_path, gsha);
    wcs_sha_file(flags_nul, fsha);
    if (ovf(snprintf(input, sizeof input,
                     "tu-result-cache/v2\n%s\n%s\n%s\n%s\n%s\n%s\n",
                     gate, libsha, gsha, ccid, fsha, dg), sizeof input)) {
        c_off("salt derivation produced no digest");
        return 0;
    }
    wcs_sha_str(input, strlen(input), salt);
    if (cache_gate_root(gate, cachedir, gate_root, sizeof gate_root))
        return 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/%s", gate_root, salt), sizeof dir))
        return 0;
    if (wcs_mkdirs_p(dir) != 0) {
        c_off_fmt("cannot create '%s'", dir);
        return 0;
    }
    utime(dir, NULL);
    if (prune_generations(gate_root, generations_to_keep()) != 0) {
        c_off("cache generations could not be pruned");
        return 2;
    }
    if (ovf(snprintf(c_stats, sizeof c_stats, "%s/tu-cache.events", scratch),
            sizeof c_stats))
        return 0;
    FILE *f = fopen(c_stats, "w");
    if (!f) {
        c_off_fmt("cannot write '%s'", c_stats);
        return 0;
    }
    fclose(f);
    if (wcs_copy(c_dir, sizeof c_dir, dir)) return 0;
    c_on = 1;
    return 0;
}

/* ── plan ───────────────────────────────────────────────────────────── */

static void flat_name(const char *src, char *out, size_t cap)
{
    size_t o = 0;
    for (const char *p = src; *p && o + 1 < cap; p++)
        out[o++] = isalnum((unsigned char)*p) ? *p : '_';
    out[o] = '\0';
}

int wcs_paths_for(const char *src, const char *out_dir, char *log,
                  size_t lcap, char *rc, size_t rcap)
{
    if (ovf(snprintf(log, lcap, "%s/%s.log", out_dir, src), lcap))
        return 2;
    if (ovf(snprintf(rc, rcap, "%s/%s.rc", out_dir, src), rcap))
        return 2;
    return 0;
}

static int entry_path(const char *src, const char *sha, char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/%s.%s", c_dir, src, sha), cap))
        return 2;
    return 0;
}

static void replay_entry(const char *ent, const char *log, const char *rc,
                         int erc, int haslog)
{
    FILE *o = fopen(rc, "w");
    if (o) { fprintf(o, "%d\n", erc); fclose(o); }
    o = fopen(log, "w");
    if (!o) return;
    if (haslog) {
        FILE *i = fopen(ent, "rb");
        static char buf[4096];
        int first = 1;
        size_t n;
        if (i) {
            while ((n = fread(buf, 1, sizeof buf, i)) > 0) {
                if (first) {
                    char *nl = memchr(buf, '\n', n);
                    if (nl) {
                        size_t off = (size_t)(nl - buf) + 1;
                        fwrite(buf + off, 1, n - off, o);
                        first = 0;
                    }
                } else {
                    fwrite(buf, 1, n, o);
                }
            }
            fclose(i);
        }
    }
    fclose(o);
}

static int entry_valid(const char *ent, int *erc, int *haslog)
{
    FILE *f = fopen(ent, "rb");
    if (!f) return 0;
    char line[64];
    int ok = fgets(line, sizeof line, f) != NULL;
    fclose(f);
    if (!ok) return 0;
    char *sp = strchr(line, ' ');
    if (!sp) return 0;
    *sp = '\0';
    const char *hl = sp + 1;
    if (!line[0]) return 0;
    for (const char *c = line; *c; c++)
        if (*c < '0' || *c > '9') return 0;
    *erc = atoi(line);
    if (!(hl[0] == '0' || hl[0] == '1') || hl[1] != '\n') return 0;
    *haslog = hl[0] - '0';
    return 1;
}

static int read_list_file(const char *path, char rows[][WCS_PATH], int max)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0;
    static char line[WCS_PATH + 8];
    while (n < max && fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n') line[--l] = '\0';
        if (!l) continue;
        memcpy(rows[n], line, l + 1);
        n++;
    }
    fclose(f);
    return n;
}

static int write_list_file(const char *path, char rows[][WCS_PATH], int n)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    for (int i = 0; i < n; i++)
        fprintf(f, "%s\n", rows[i]);
    fclose(f);
    return 0;
}

/* Hashes every row; returns how many were present on disk. */
static int plan_hash_rows(char rows[][WCS_PATH], int n, char shas[][WCS_SHA])
{
    int hashed = 0;
    for (int i = 0; i < n; i++) {
        wcs_sha_file(rows[i], shas[i]);
        if (strcmp(shas[i], "absent") != 0) hashed++;
    }
    return hashed;
}

/* Turns the cache off for this run (every row misses) and writes the list. */
static int plan_disable(char rows[][WCS_PATH], int n, const char *miss_list,
                        int hashed)
{
    char why[128];
    if (ovf(snprintf(why, sizeof why, "hashed %d of %d source(s)", hashed, n),
            sizeof why))
        c_off("cache disabled: hash count exceeds the state buffer");
    else
        c_off(why);
    return write_list_file(miss_list, rows, n) == 0 ? 0 : 2;
}

/* Replays one row on a hit (returns 0) or appends it to the miss list
 * (returns 1). Returns 2 on overflow or a bad copy. */
static int plan_row(const char *row, const char *sha, const char *out_dir,
                    int flat, char miss[][WCS_PATH], int *nmiss)
{
    char ent[WCS_PATH], log[WCS_PATH], rc[WCS_PATH], name[WCS_PATH];
    entry_path(row, sha, ent, sizeof ent);
    int erc = 0, haslog = 0;
    if (!entry_valid(ent, &erc, &haslog)) {
        if (*nmiss >= WCS_TUS || wcs_copy(miss[*nmiss], WCS_PATH, row)) {
            fprintf(stderr, "%s: miss list exceeds %d rows\n", k_wcs_gate,
                    WCS_TUS);
            return 2;
        }
        (*nmiss)++;
        return 1;
    }
    if (flat) flat_name(row, name, sizeof name);
    else if (wcs_copy(name, sizeof name, row)) return 2;
    wcs_paths_for(name, out_dir, log, sizeof log, rc, sizeof rc);
    replay_entry(ent, log, rc, erc, haslog);
    return 0;
}

/* Creates the cache directory that a miss will later store into. */
static int plan_mkdir_for(const char *path)
{
    char d[WCS_PATH], ent[WCS_PATH];
    const char *sl = strrchr(path, '/');
    if (!sl) return 0;
    if (ovf(snprintf(d, sizeof d, "%.*s", (int)(sl - path), path), sizeof d))
        return 2;
    entry_path(d, "x", ent, sizeof ent);
    char *pe = strrchr(ent, '/');
    if (pe) {
        *pe = '\0';
        if (wcs_mkdirs_p(ent) != 0) return 2;
    }
    return 0;
}

static int plan_replay(char rows[][WCS_PATH], int n, const char *miss_list,
                       const char *out_dir, int flat)
{
    static char shas[WCS_TUS][WCS_SHA];
    int hashed = plan_hash_rows(rows, n, shas);
    if (hashed != n) return plan_disable(rows, n, miss_list, hashed);
    static char miss[WCS_TUS][WCS_PATH];
    int nmiss = 0, hits = 0;
    for (int i = 0; i < n; i++) {
        int r = plan_row(rows[i], shas[i], out_dir, flat, miss, &nmiss);
        if (r == 2) return 2;
        if (r == 0) hits++;
    }
    for (int i = 0; i < nmiss; i++)
        if (plan_mkdir_for(miss[i]) != 0) return 2;
    if (write_list_file(miss_list, miss, nmiss) != 0) return 2;
    FILE *f = fopen(c_stats, "a");
    if (f) { fprintf(f, "H %d\nM %d\n", hits, nmiss); fclose(f); }
    return 0;
}

int wcs_cache_plan(const char *src_list, const char *miss_list,
                   const char *out_dir, int flat)
{
    static char rows[WCS_TUS][WCS_PATH];
    int n = read_list_file(src_list, rows, WCS_TUS);
    if (n < 0) return 2;
    if (!c_on) return write_list_file(miss_list, rows, n) == 0 ? 0 : 2;
    return plan_replay(rows, n, miss_list, out_dir, flat);
}

/* ── worker side ────────────────────────────────────────────────────── */

static void cache_event(const char *e)
{
    if (!c_stats[0]) return;
    FILE *f = fopen(c_stats, "a");
    if (f) { fprintf(f, "%s\n", e); fclose(f); }
}

static int cache_store(const char *src, int rc, const char *log)
{
    char sha[WCS_SHA], ent[WCS_PATH], tmp[WCS_PATH];
    wcs_sha_file(src, sha);
    if (strlen(sha) != 64) return 1;
    if (entry_path(src, sha, ent, sizeof ent) != 0) return 1;
    char *sl = strrchr(ent, '/');
    if (sl) { *sl = '\0'; wcs_mkdirs_p(ent); *sl = '/'; }
    struct stat st;
    int haslog = stat(log, &st) == 0 && st.st_size > 0;
    if (ovf(snprintf(tmp, sizeof tmp, "%s/.tmp.%d.%u", c_dir, (int)getpid(),
                     ++c_tmp_seq), sizeof tmp))
        return 1;
    FILE *o = fopen(tmp, "wb");
    if (!o) return 1;
    fprintf(o, "%d %d\n", rc, haslog);
    if (haslog) {
        FILE *i = fopen(log, "rb");
        static char buf[4096];
        size_t n;
        if (i) {
            while ((n = fread(buf, 1, sizeof buf, i)) > 0) fwrite(buf, 1, n, o);
            fclose(i);
        }
    }
    fclose(o);
    if (rename(tmp, ent) != 0) { remove(tmp); return 1; }
    return 0;
}

int wcs_cache_compile(const char *log, const char *rcf, const char *cc,
                      char *const cargv[], const char *src)
{
    int rc = wcs_run_capture(log, log, cargv);
    (void)cc;
    FILE *f = fopen(rcf, "w");
    if (f) { fprintf(f, "%d\n", rc); fclose(f); }
    if (c_on && cache_store(src, rc, log) == 0) cache_event("s");
    return 0;
}

int wcs_cache_counts(int *h, int *m, int *s)
{
    *h = *m = *s = 0;
    if (!c_stats[0]) return 0;
    FILE *f = fopen(c_stats, "r");
    if (!f) return 0;
    static char line[64];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "H ", 2) == 0) *h += atoi(line + 2);
        else if (strncmp(line, "M ", 2) == 0) *m += atoi(line + 2);
        else if (strcmp(line, "s\n") == 0) (*s)++;
    }
    fclose(f);
    return 0;
}

void wcs_cache_summary(void)
{
    if (!c_on) {
        printf("  tu-cache: 0 hit, 0 miss, 0 stored (off: %s)\n",
               wcs_cache_off_reason());
        return;
    }
    int h, m, s;
    wcs_cache_counts(&h, &m, &s);
    printf("  tu-cache: %d hit, %d miss, %d stored\n", h, m, s);
}
