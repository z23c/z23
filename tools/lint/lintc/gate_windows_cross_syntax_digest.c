/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: sha256 and the include-set digest that salts the
 * check-windows-cross-syntax result cache. Split out of
 * gate_windows_cross_syntax_cache.c to keep each file under 800 lines. The
 * digest walks the include roots and hashes every header or source the
 * windows compile can reach, so editing any of them changes the salt.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "lintc.h"
#include "base/hex.h"
#include "zsha256/zsha256.h"
#include "gate_windows_cross_syntax_priv.h"

/* ── sha256 ─────────────────────────────────────────────────────────── */

struct wcs_sha {
    zsha256_ctx c;
};

static void sha_init(struct wcs_sha *s) { zsha256_init(&s->c); }

static void sha_update(struct wcs_sha *s, const uint8_t *p, size_t n)
{
    zsha256_update(&s->c, p, n);
}

static void sha_final(struct wcs_sha *s, char out[WCS_SHA])
{
    uint8_t d[ZSHA256_DIGEST_LEN];
    zsha256_final(&s->c, d);
    zcl_hex_encode(d, sizeof d, out);
}

void wcs_sha_str(const char *d, size_t n, char out[WCS_SHA])
{
    struct wcs_sha s;
    sha_init(&s);
    sha_update(&s, (const uint8_t *)d, n);
    sha_final(&s, out);
}

/* -1 real error; 0 ok. A path that is not a regular file hashes as
 * "absent" with *enoent set when it vanished, mirroring the shell
 * original's [ -f ] test and its narrowly scoped TOCTOU tolerance. */
static int sha_file_ex(const char *path, char out[WCS_SHA], int *enoent)
{
    static char buf[65536];
    struct stat st;
    *enoent = 0;
    strcpy(out, "absent");
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        *enoent = (errno == ENOENT);
        return 0;
    }
    FILE *f = fopen(path, "rb");
    if (!f) { *enoent = (errno == ENOENT); return 0; }
    struct wcs_sha s;
    sha_init(&s);
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha_update(&s, (const uint8_t *)buf, n);
    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);
    sha_final(&s, out);
    return 0;
}

int wcs_sha_file(const char *path, char out[WCS_SHA])
{
    int en;
    return sha_file_ex(path, out, &en);
}


/* ── include-set digest ─────────────────────────────────────────────── */

enum { DG_MAX = 16384, DG_INCL = 512 };
static char dg_paths[DG_MAX][WCS_PATH];
static int dg_n;

static int dg_ext_ok(const char *p)
{
    size_t n = strlen(p);
    if (n < 2 || p[n - 1] != 'c' || p[n - 2] != '.') {
        if (n >= 2 && p[n - 1] == 'h' && p[n - 2] == '.') return 1;
        if (n >= 4 && strcmp(p + n - 4, ".inc") == 0) return 1;
        if (n >= 4 && strcmp(p + n - 4, ".def") == 0) return 1;
        return 0;
    }
    return 1;
}

static const char *const dg_pruned[] = { ".git", "build", "test-tmp",
    ".claude", ".cache", "vendor/tor", NULL };


/* Manual recursion, not nftw: nftw stops on FTW_SKIP_SUBTREE unless glibc's
 * FTW_ACTIONRETVAL is set, which is not portable. Unreadable directories are
 * skipped, as nftw reports them; depth is bounded and fails closed. */
static int dg_scan(const char *dir, int depth);

static int dg_entry(const char *p, int depth)
{
    struct stat st;
    if (lstat(p, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode)) {
        const char *rel = p[0] == '.' && p[1] == '/' ? p + 2 : p;
        return wcs_name_in(rel, dg_pruned) ? 0 : dg_scan(p, depth + 1);
    }
    if (S_ISREG(st.st_mode) && dg_ext_ok(p)) {
        if (dg_n >= DG_MAX) {
            fprintf(stderr, "%s: include-set digest exceeds %d files; the "
                    "cache key would be incomplete\n", k_wcs_gate, DG_MAX);
            return -1;
        }
        if (wcs_copy(dg_paths[dg_n], WCS_PATH, p)) {
            fprintf(stderr, "%s: digest path exceeds %d bytes\n", k_wcs_gate,
                    WCS_PATH);
            return -1;
        }
        dg_n++;
    }
    return 0;
}

static int dg_scan(const char *dir, int depth)
{
    if (depth > 64) return -1;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char p[WCS_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, de->d_name), sizeof p))
            rc = -1;
        else
            rc = dg_entry(p, depth);
    }
    closedir(d);
    return rc;
}

/* Collects basenames named by an include "...c" anywhere in the tree. */
/* Matches the script's regex #[[:space:]]*include[[:space:]]*"[^"]*\.c" at s
 * (s points at the '#'); on a match, name/len give the quoted path. */
static int dg_incl_name(const char *s, const char **name, size_t *len)
{
    const char *p = s + 1;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "include", 7) != 0) return 0;
    p += 7;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '"') return 0;
    const char *q = strchr(p + 1, '"');
    if (!q || q - (p + 1) < 2 || strncmp(q - 2, ".c", 2) != 0) return 0;
    *name = p + 1;
    *len = (size_t)(q - (p + 1));
    return 1;
}

/* Adds the basename of one included .c; -1 when the table or name is full. */
static int dg_incl_add(char incl[DG_INCL][256], int *nincl, const char *name,
                       size_t len)
{
    const char *bn = name, *end = name + len;
    for (const char *c = name; c < end; c++)
        if (*c == '/') bn = c + 1;
    char base[256];
    size_t bl = (size_t)(end - bn);
    if (bl >= sizeof base) {
        fprintf(stderr, "%s: included basename exceeds %d bytes\n", k_wcs_gate,
                (int)sizeof base - 1);
        return -1;
    }
    memcpy(base, bn, bl);
    base[bl] = '\0';
    for (int j = 0; j < *nincl; j++)
        if (strcmp(incl[j], base) == 0) return 0;
    if (*nincl >= DG_INCL) {
        fprintf(stderr, "%s: included .c basenames exceed %d; the cache key "
                "would be incomplete\n", k_wcs_gate, DG_INCL);
        return -1;
    }
    if (wcs_copy(incl[*nincl], 256, base)) return -1;
    (*nincl)++;
    return 0;
}

/* Collects basenames named by an include "...c" anywhere in the tree. */
static int dg_incl_scan(char incl[DG_INCL][256], int *nincl)
{
    static char line[WCS_SRCLINE];
    for (int i = 0; i < dg_n; i++) {
        if (!dg_ext_ok(dg_paths[i])) continue;
        FILE *f = fopen(dg_paths[i], "r");
        if (!f) continue;
        int rc = 0;
        while (rc == 0 && fgets(line, sizeof line, f)) {
            size_t raw = strlen(line);
            if (raw && line[raw - 1] != '\n' && !feof(f)) {
                fprintf(stderr, "%s: source line exceeds %d bytes in %s\n",
                        k_wcs_gate, WCS_SRCLINE, dg_paths[i]);
                rc = -1;
                break;
            }
            for (const char *h = strchr(line, '#'); h && rc == 0;
                 h = strchr(h + 1, '#')) {
                const char *name = NULL;
                size_t len = 0;
                if (dg_incl_name(h, &name, &len))
                    rc = dg_incl_add(incl, nincl, name, len);
            }
        }
        fclose(f);
        if (rc != 0) return -1;
    }
    return 0;
}

static int dg_is_header(const char *p)
{
    const char *dot = strrchr(p, '.');
    return dot && (!strcmp(dot, ".h") || !strcmp(dot, ".inc") ||
                   !strcmp(dot, ".def"));
}

static int dg_bad_path(const char *p)
{
    for (const char *c = p; *c; c++)
        if (*c == '\\' || isspace((unsigned char)*c)) return 1;
    return 0;
}

static int dg_cmp(const void *a, const void *b)
{
    const int *x = a, *y = b;
    return strcmp(dg_paths[*x], dg_paths[*y]);
}

static int dg_mark_keep(char incl[DG_INCL][256], int nincl, char *keep)
{
    int nkeep = 0;
    for (int i = 0; i < dg_n; i++) {
        int w = dg_is_header(dg_paths[i]);
        if (!w) {
            const char *bn = strrchr(dg_paths[i], '/');
            bn = bn ? bn + 1 : dg_paths[i];
            for (int j = 0; j < nincl && !w; j++)
                if (strcmp(incl[j], bn) == 0) w = 1;
        }
        keep[i] = (char)w;
        nkeep += w;
    }
    return nkeep;
}

static int dg_digest_ordered(const int *ord, int nord, char out[WCS_SHA])
{
    static char sha[WCS_SHA];
    struct wcs_sha s;
    sha_init(&s);
    for (int i = 0; i < nord; i++) {
        int en = 0;
        const char *p = dg_paths[ord[i]];
        if (sha_file_ex(p, sha, &en) != 0) {
            fprintf(stderr, "tu_cache_include_digest: sha256 reported an "
                    "error the vanished-path race does not explain:\n"
                    "  %s: %s\n", p, strerror(errno));
            return -1;
        }
        if (en) continue;
        sha_update(&s, (const uint8_t *)p, strlen(p));
        sha_update(&s, (const uint8_t *)"\t", 1);
        sha_update(&s, (const uint8_t *)sha, 64);
        sha_update(&s, (const uint8_t *)"\n", 1);
    }
    sha_final(&s, out);
    return 0;
}

int wcs_include_digest(const char *root, char out[WCS_SHA])
{
    static char incl[DG_INCL][256];
    static int ord[DG_MAX];
    static char keep[DG_MAX];
    int nincl = 0;
    dg_n = 0;
    if (dg_scan(root, 0) != 0 || dg_n == 0)
        return -1;
    for (int i = 0; i < dg_n; i++)
        if (dg_bad_path(dg_paths[i])) return -1;
    if (dg_incl_scan(incl, &nincl) != 0) return -1;
    if (dg_mark_keep(incl, nincl, keep) == 0) return -1;
    const char *prod = getenv("ZCL_LINT_PRODUCTION_SCAN");
    if (prod && strcmp(prod, "1") == 0 && excl_ensure() == 0)
        for (int i = 0; i < dg_n; i++)
            if (keep[i] && lint_path_is_excluded(dg_paths[i])) keep[i] = 0;
    int nord = 0;
    for (int i = 0; i < dg_n; i++)
        if (keep[i]) ord[nord++] = i;
    qsort(ord, (size_t)nord, sizeof(int), dg_cmp);
    return dg_digest_ordered(ord, nord, out);
}

