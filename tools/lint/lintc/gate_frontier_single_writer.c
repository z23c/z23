/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — one canonical writer per durable frontier
 * (check-frontier-single-writer). Tracked files via lint_git_index_foreach
 * after a .git probe; filesystem walk otherwise.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { FSW_MAX = 8192, FSW_LINE = 8192, FSW_KEY = RS_PATH + 64, FSW_HIT = 256,
       FSW_FR = 32 };

struct fsw_files { char p[FSW_MAX][RS_PATH]; int n; };
struct fsw_keys { char k[FSW_MAX][FSW_KEY]; int n; };
struct fsw_idx { struct fsw_files *s; const char (*roots)[RS_PATH]; int nr; };

static const char k_fsw_man[] = "tools/scripts/arch_frontier_owners.tsv";
static const char k_fsw_base[] = "tools/scripts/frontier_single_writer_baseline.tsv";

static int fsw_add(struct fsw_files *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= FSW_MAX || n >= RS_PATH)
        return die("z23-lint: frontier-single-writer overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int fsw_under(const char *path, const char (*roots)[RS_PATH], int nr)
{
    int i;
    for (i = 0; i < nr; i++) {
        size_t k = strlen(roots[i]);
        if (strncmp(path, roots[i], k) == 0
            && (path[k] == '/' || path[k] == '\0'))
            return 1;
    }
    return 0;
}

static int fsw_is_ch(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int fsw_skip(const char *path)
{
    return strstr(path, "/test/") != NULL || strstr(path, "/tests/") != NULL
        || strstr(path, "/include/") != NULL || strstr(path, "_test.") != NULL;
}

static int fsw_on_idx(const char *path, int stage, void *ctx)
{
    struct fsw_idx *c = ctx;
    (void)stage;
    if (!fsw_is_ch(path) || lint_path_is_excluded(path))
        return 0;
    if (!fsw_under(path, c->roots, c->nr))
        return 0;
    return fsw_add(c->s, path);
}

static int fsw_on_walk(const char *path, void *ctx)
{
    if (!fsw_is_ch(path) || lint_path_is_excluded(path))
        return 0;
    return fsw_add(ctx, path);
}

static int fsw_split(const char *s, char out[][RS_PATH], int max, int *n)
{
    char buf[4096], *p;
    *n = 0;
    if (ovf(snprintf(buf, sizeof buf, "%s", s), sizeof buf))
        return 2;
    p = buf;
    while (*p) {
        char *t, save;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*n >= max)
            return die("z23-lint: frontier-single-writer overflow\n", "");
        t = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        save = *p;
        *p = '\0';
        if (ovf(snprintf(out[*n], RS_PATH, "%s", t), RS_PATH))
            return 2;
        (*n)++;
        if (!save)
            break;
        *p++ = save;
    }
    return 0;
}

static int fsw_collect(struct fsw_files *s, const char (*roots)[RS_PATH], int nr)
{
    struct fsw_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc = 0, i;
    s->n = 0;
    for (i = 0; rc == 0 && i < nr; i++)
        rc = walk_src(roots[i], 1, fsw_on_walk, s);
    if (rc)
        return rc;
    if (stat(".git", &st) != 0)
        return 0;
    rc = lint_git_index_foreach(fsw_on_idx, &ix, bad);
    if (rc)
        fprintf(stderr, "check_frontier_single_writer: UNPROVEN — git "
                        "index%s%s\n", bad[0] ? " extension " : "", bad);
    return rc;
}

static int fsw_khas(const struct fsw_keys *s, const char *k)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->k[i], k) == 0)
            return 1;
    return 0;
}

static int fsw_kadd(struct fsw_keys *s, const char *k)
{
    size_t n;
    if (fsw_khas(s, k))
        return 0;
    n = strlen(k);
    if (s->n >= FSW_MAX || n >= FSW_KEY)
        return die("z23-lint: frontier-single-writer overflow\n", "");
    memcpy(s->k[s->n++], k, n + 1);
    return 0;
}

static void fsw_ere(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    const char *p = in;
    while (*p && n + 4 < cap) {
        if (p[0] == '\\' && (p[1] == '(' || p[1] == ')')) {
            out[n++] = '[';
            out[n++] = p[1];
            out[n++] = ']';
            p += 2;
        } else {
            out[n++] = *p++;
        }
    }
    out[n] = '\0';
}

static int fsw_unreadable(const char *path)
{
    fprintf(stderr, "check_frontier_single_writer: UNPROVEN — cannot read %s\n",
            path);
    return 2;
}

static int fsw_file_hits(const char *path, const regex_t *re, int *hit)
{
    FILE *f = fopen(path, "r");
    char buf[FSW_LINE];
    *hit = 0;
    if (!f)
        return fsw_unreadable(path);
    while (!*hit && fgets(buf, (int)sizeof buf, f))
        if (regexec(re, buf, 0, NULL, 0) == 0)
            *hit = 1;
    fclose(f);
    return 0;
}

static int fsw_base_of(const char *path, char *out, size_t cap)
{
    const char *s = strrchr(path, '/');
    s = s ? s + 1 : path;
    return ovf(snprintf(out, cap, "%s", s), cap) ? 2 : 0;
}

static int fsw_load_base(struct fsw_keys *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[FSW_LINE];
    b->n = 0;
    if (!f) {
        fprintf(stderr, "check_frontier_single_writer: FATAL — manifest or "
                        "baseline missing\n  manifest=%s baseline=%s\n",
                k_fsw_man, path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        char *tab, *tab2;
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        tab = strchr(buf, '\t');
        if (!tab) {
            fclose(f);
            fprintf(stderr, "check_frontier_single_writer: FATAL — malformed "
                            "baseline row: %s\n", buf);
            return 2;
        }
        tab2 = strchr(tab + 1, '\t');
        if (tab2) {
            fclose(f);
            fprintf(stderr, "check_frontier_single_writer: FATAL — malformed "
                            "baseline row: %s\n", buf);
            return 2;
        }
        if (fsw_khas(b, buf)) {
            fclose(f);
            fprintf(stderr, "check_frontier_single_writer: FATAL — duplicate "
                            "baseline row: %s\n", buf);
            return 2;
        }
        if (fsw_kadd(b, buf)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    return 0;
}

static int fsw_owners(const struct fsw_files *all, const char *owner,
                      char found[][RS_PATH], int *nf)
{
    int i;
    *nf = 0;
    for (i = 0; i < all->n; i++) {
        char base[RS_PATH];
        if (fsw_base_of(all->p[i], base, sizeof base))
            return 2;
        if (strcmp(base, owner) != 0)
            continue;
        if (*nf >= 8)
            return 2;
        snprintf(found[*nf], RS_PATH, "%s", all->p[i]);
        (*nf)++;
    }
    return 0;
}

static int fsw_malformed(const char *row)
{
    fprintf(stderr, "check_frontier_single_writer: FATAL — malformed "
                    "manifest row: %s\n", row);
    return 2;
}

static int fsw_require_roots(const char (*roots)[RS_PATH], int nr)
{
    int i;
    if (nr == 0) {
        fputs("check_frontier_single_writer: FATAL — empty scan-root set\n",
              stderr);
        return 2;
    }
    for (i = 0; i < nr; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "check_frontier_single_writer: FATAL — scan root "
                            "missing: %s\n", roots[i]);
            return 2;
        }
    }
    return 0;
}

struct fsw_row {
    char fr[64];
    char owner[RS_PATH];
    char *pat;
};

static int fsw_parse_row(char *buf, struct fsw_row *row)
{
    char *t1, *t2, *t3;
    t1 = strchr(buf, '\t');
    if (!t1)
        return fsw_malformed(buf);
    *t1 = '\0';
    t2 = strchr(t1 + 1, '\t');
    if (!t2)
        return fsw_malformed(buf);
    *t2 = '\0';
    t3 = strchr(t2 + 1, '\t');
    if (t3)
        return fsw_malformed(buf);
    snprintf(row->fr, sizeof row->fr, "%s", buf);
    snprintf(row->owner, sizeof row->owner, "%s", t1 + 1);
    row->pat = t2 + 1;
    return 0;
}

static int fsw_scan_file(const char *path, const struct fsw_row *row,
                         const regex_t *re, const struct fsw_keys *allowed,
                         struct fsw_keys *seen, char viol[][FSW_KEY], int *nv,
                         const char *owner_path)
{
    char base[RS_PATH], key[FSW_KEY];
    int hit = 0, rc;
    if (fsw_base_of(path, base, sizeof base))
        return 2;
    if (strcmp(base, row->owner) == 0 || fsw_skip(path))
        return 0;
    rc = fsw_file_hits(path, re, &hit);
    if (rc || !hit)
        return rc;
    if (ovf(snprintf(key, sizeof key, "%s\t%s", row->fr, path), sizeof key))
        return 2;
    if (fsw_khas(allowed, key))
        return fsw_kadd(seen, key);
    if (*nv < FSW_HIT
        && !ovf(snprintf(viol[*nv], FSW_KEY, "%s: %s (owner: %s)", row->fr,
                         path, owner_path), FSW_KEY))
        (*nv)++;
    return 0;
}

static int fsw_scan_row(const struct fsw_files *all, const struct fsw_row *row,
                        struct fsw_keys *fronts, struct fsw_keys *allowed,
                        struct fsw_keys *seen, char viol[][FSW_KEY], int *nv)
{
    char found[8][RS_PATH], ere[256];
    regex_t re;
    int nf = 0, j, rc;
    if (fsw_khas(fronts, row->fr)) {
        fprintf(stderr, "check_frontier_single_writer: FATAL — duplicate "
                        "frontier: %s\n", row->fr);
        return 2;
    }
    rc = fsw_kadd(fronts, row->fr);
    if (rc)
        return rc;
    rc = fsw_owners(all, row->owner, found, &nf);
    if (rc)
        return rc;
    if (nf != 1) {
        fprintf(stderr, "check_frontier_single_writer: FATAL — frontier %s "
                        "owner\n  expected exactly one %s, found %d\n",
                row->fr, row->owner, nf);
        return 2;
    }
    fsw_ere(row->pat, ere, sizeof ere);
    if (reg_fail(&re, regcomp(&re, ere, REG_EXTENDED)))
        return 2;
    for (j = 0; rc == 0 && j < all->n; j++)
        rc = fsw_scan_file(all->p[j], row, &re, allowed, seen, viol, nv,
                           found[0]);
    regfree(&re);
    return rc;
}

static int fsw_read_manifest(FILE *mf, const struct fsw_files *all,
                             struct fsw_keys *fronts, struct fsw_keys *allowed,
                             struct fsw_keys *seen, char viol[][FSW_KEY],
                             int *nv, int *nman)
{
    char buf[FSW_LINE];
    int rc = 0;
    fronts->n = 0;
    seen->n = 0;
    *nman = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, mf)) {
        struct fsw_row row;
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        rc = fsw_parse_row(buf, &row);
        if (rc)
            break;
        rc = fsw_scan_row(all, &row, fronts, allowed, seen, viol, nv);
        if (rc == 0)
            (*nman)++;
    }
    return rc;
}

static void fsw_stale(const struct fsw_keys *allowed,
                      const struct fsw_keys *fronts, const struct fsw_keys *seen,
                      char stale[][FSW_KEY], int *ns)
{
    int i;
    for (i = 0; i < allowed->n; i++) {
        char fr[64];
        const char *tab = strchr(allowed->k[i], '\t');
        size_t fl;
        if (!tab)
            continue;
        fl = (size_t)(tab - allowed->k[i]);
        if (fl >= sizeof fr)
            continue;
        memcpy(fr, allowed->k[i], fl);
        fr[fl] = '\0';
        if (!fsw_khas(fronts, fr)) {
            if (*ns < FSW_HIT)
                snprintf(stale[(*ns)++], FSW_KEY, "%s (frontier absent from "
                         "manifest)", allowed->k[i]);
        } else if (!fsw_khas(seen, allowed->k[i])) {
            if (*ns < FSW_HIT)
                snprintf(stale[(*ns)++], FSW_KEY, "%s (writer gone; shrink the "
                         "baseline)", allowed->k[i]);
        }
    }
}

static int fsw_report(int nman, int nallowed, char viol[][FSW_KEY], int nv,
                      char stale[][FSW_KEY], int ns)
{
    int i;
    if (!nv && !ns) {
        printf("check_frontier_single_writer: clean — %d frontier(s), %d "
               "reviewed debt writer(s), no new clones\n", nman, nallowed);
        return 0;
    }
    if (nv) {
        fputs("check_frontier_single_writer: FAIL — new non-owner writer(s)\n",
              stdout);
        for (i = 0; i < nv; i++)
            printf("  %s\n", viol[i]);
    }
    if (ns) {
        fputs("check_frontier_single_writer: FAIL — stale baseline row(s)\n",
              stdout);
        for (i = 0; i < ns; i++)
            printf("  %s\n", stale[i]);
    }
    fputs("Move writes behind the manifest owner; never baseline new debt.\n",
          stdout);
    return 1;
}

static int fsw_missing(const char *man, const char *bp)
{
    fprintf(stderr, "check_frontier_single_writer: FATAL — manifest or "
                    "baseline missing\n  manifest=%s baseline=%s\n", man, bp);
    return 2;
}

static int fsw_run(void)
{
    static struct fsw_files all;
    static struct fsw_keys allowed, seen, fronts;
    static char viol[FSW_HIT][FSW_KEY], stale[FSW_HIT][FSW_KEY];
    char roots[16][RS_PATH];
    const char *man = env_or("ZCL_FRONTIER_MANIFEST", k_fsw_man);
    const char *bp = env_or("ZCL_FRONTIER_BASELINE", k_fsw_base);
    const char *rt = env_or("ZCL_FRONTIER_SCAN_ROOTS",
                            "core engine contexts cognition platform");
    FILE *mf;
    int nr = 0, nv = 0, ns = 0, nman = 0, rc;
    rc = fsw_split(rt, roots, 16, &nr);
    if (rc)
        return rc;
    rc = fsw_require_roots(roots, nr);
    if (rc)
        return rc;
    if (access(man, R_OK) != 0 || access(bp, R_OK) != 0)
        return fsw_missing(man, bp);
    rc = fsw_load_base(&allowed, bp);
    if (rc)
        return rc;
    rc = fsw_collect(&all, roots, nr);
    if (rc)
        return rc;
    mf = fopen(man, "r");
    if (!mf)
        return fsw_missing(man, bp);
    rc = fsw_read_manifest(mf, &all, &fronts, &allowed, &seen, viol, &nv,
                           &nman);
    fclose(mf);
    if (rc)
        return rc;
    if (nman == 0) {
        fputs("check_frontier_single_writer: FATAL — manifest contains no "
              "frontiers\n", stderr);
        return 2;
    }
    fsw_stale(&allowed, &fronts, &seen, stale, &ns);
    return fsw_report(nman, allowed.n, viol, nv, stale, ns);
}

int check_frontier_single_writer_selftest(void)
{
    int rc = fsw_run();
    if (rc != 0) {
        fprintf(stderr, "check_frontier_single_writer selftest: FAIL — clean "
                        "tree rc=%d want=0\n", rc);
        return 1;
    }
    fputs("check_frontier_single_writer selftest: PASS — clean tree has no "
          "new cloned writers\n", stdout);
    return 0;
}

int check_frontier_single_writer_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return fsw_run();
}
