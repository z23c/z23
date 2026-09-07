/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — node.db utxos-mirror reader freeze
 * (check-no-utxos-mirror-read). Tracked files via lint_git_index_foreach
 * after a .git probe; filesystem walk otherwise.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { NUM_MAX = 4096, NUM_LINE = 8192, NUM_HIT = 256 };

struct num_files { char p[NUM_MAX][RS_PATH]; int n; };
struct num_idx { struct num_files *s; const char (*roots)[RS_PATH]; int nr; };

static const char k_num_base[] =
    "tools/scripts/check_no_utxos_mirror_read_baseline.txt";
static const char k_num_pat[] = "FROM utxos";

static int num_add(struct num_files *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= NUM_MAX || n >= RS_PATH)
        return die("z23-lint: no-utxos-mirror-read overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int num_has(const struct num_files *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int num_under(const char *path, const char (*roots)[RS_PATH], int nr)
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

static int num_is_ch(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int num_skip(const char *path)
{
    return strstr(path, "/test/") != NULL || strstr(path, "/tests/") != NULL
        || strstr(path, "/include/") != NULL || strstr(path, "_test.") != NULL;
}

static int num_on_idx(const char *path, int stage, void *ctx)
{
    struct num_idx *c = ctx;
    (void)stage;
    if (!num_is_ch(path) || num_skip(path) || lint_path_is_excluded(path))
        return 0;
    if (!num_under(path, c->roots, c->nr))
        return 0;
    return num_add(c->s, path);
}

static int num_on_walk(const char *path, void *ctx)
{
    if (!num_is_ch(path) || num_skip(path) || lint_path_is_excluded(path))
        return 0;
    return num_add(ctx, path);
}

static int num_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int num_fill_default(char out[][RS_PATH], int *n)
{
    const char *shapes[] = { "services", "jobs", "conditions" };
    const char *extra[] = {
        "engine/reducer/services", "engine/reducer/jobs",
        "engine/reducer/conditions", "engine/composition/src"
    };
    char rooms[RS_MAX][RS_PATH];
    int i, j, nr, rc;
    *n = 0;
    for (i = 0; i < 3; i++) {
        rc = repo_shape_room_dirs(shapes[i], rooms, RS_MAX, &nr);
        if (rc)
            return rc;
        for (j = 0; j < nr; j++) {
            if (*n >= RS_MAX)
                return die("z23-lint: no-utxos-mirror-read overflow\n", "");
            if (ovf(snprintf(out[*n], RS_PATH, "%s", rooms[j]), RS_PATH))
                return 2;
            (*n)++;
        }
    }
    for (i = 0; i < 4; i++) {
        if (*n >= RS_MAX)
            return die("z23-lint: no-utxos-mirror-read overflow\n", "");
        if (ovf(snprintf(out[*n], RS_PATH, "%s", extra[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

static int num_split(const char *s, char out[][RS_PATH], int max, int *n)
{
    char buf[8192], *p;
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
            return die("z23-lint: no-utxos-mirror-read overflow\n", "");
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

static int num_collect(struct num_files *s, const char (*roots)[RS_PATH], int nr)
{
    struct num_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc = 0, i;
    s->n = 0;
    for (i = 0; rc == 0 && i < nr; i++)
        rc = walk_src(roots[i], 1, num_on_walk, s);
    if (rc)
        return rc;
    if (stat(".git", &st) != 0)
        return 0;
    rc = lint_git_index_foreach(num_on_idx, &ix, bad);
    if (rc)
        fprintf(stderr, "check_no_utxos_mirror_read: UNPROVEN — git index%s%s\n",
                bad[0] ? " extension " : "", bad);
    return rc;
}

static int num_load_base(struct num_files *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[NUM_LINE];
    b->n = 0;
    if (!f) {
        fprintf(stderr, "check_no_utxos_mirror_read: FATAL — baseline missing: "
                        "%s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        if (num_has(b, buf)) {
            fclose(f);
            fprintf(stderr, "check_no_utxos_mirror_read: FATAL — duplicate "
                            "baseline row: %s\n", buf);
            return 2;
        }
        if (num_add(b, buf)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    return 0;
}

static int num_file_hits(const char *path, int *hit)
{
    FILE *f = fopen(path, "r");
    char buf[NUM_LINE];
    *hit = 0;
    if (!f) {
        fprintf(stderr, "check_no_utxos_mirror_read: UNPROVEN — cannot read "
                        "%s\n", path);
        return 2;
    }
    while (!*hit && fgets(buf, (int)sizeof buf, f))
        if (strstr(buf, k_num_pat))
            *hit = 1;
    fclose(f);
    return 0;
}

static int num_fill_roots(char roots[][RS_PATH], int *nr)
{
    char def[RS_MAX][RS_PATH];
    const char *ov = env_or("ZCL_NO_UTXOS_MIRROR_READ_SCAN_ROOTS", "");
    int nd = 0, rc;
    if (ov[0])
        return num_split(ov, roots, RS_MAX, nr);
    rc = num_fill_default(def, &nd);
    if (rc)
        return rc;
    memcpy(roots, def, (size_t)nd * RS_PATH);
    *nr = nd;
    return 0;
}

static int num_require_roots(const char (*roots)[RS_PATH], int nr)
{
    int i;
    if (nr == 0) {
        fputs("check_no_utxos_mirror_read: FATAL — empty scan-root set\n",
              stderr);
        return 2;
    }
    for (i = 0; i < nr; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "check_no_utxos_mirror_read: FATAL — scan root "
                            "missing: %s\n", roots[i]);
            return 2;
        }
    }
    return 0;
}

static int num_scan_hits(const struct num_files *all, struct num_files *hits)
{
    int i, rc;
    hits->n = 0;
    for (i = 0; i < all->n; i++) {
        int hit = 0;
        rc = num_file_hits(all->p[i], &hit);
        if (rc)
            return rc;
        if (hit && num_add(hits, all->p[i]))
            return 2;
    }
    qsort(hits->p, (size_t)hits->n, RS_PATH, num_cmp);
    return 0;
}

static int num_diff(const struct num_files *hits,
                    const struct num_files *allowed, struct num_files *nw,
                    struct num_files *stale)
{
    unsigned char seen[NUM_MAX];
    int i;
    memset(seen, 0, sizeof seen);
    nw->n = stale->n = 0;
    for (i = 0; i < hits->n; i++) {
        int k, found = 0;
        for (k = 0; k < allowed->n; k++)
            if (strcmp(allowed->p[k], hits->p[i]) == 0) {
                seen[k] = 1;
                found = 1;
                break;
            }
        if (!found && num_add(nw, hits->p[i]))
            return 2;
    }
    for (i = 0; i < allowed->n; i++)
        if (!seen[i] && num_add(stale, allowed->p[i]))
            return 2;
    qsort(nw->p, (size_t)nw->n, RS_PATH, num_cmp);
    qsort(stale->p, (size_t)stale->n, RS_PATH, num_cmp);
    return 0;
}

static int num_report(const struct num_files *allowed,
                      const struct num_files *nw,
                      const struct num_files *stale)
{
    int i;
    if (!nw->n && !stale->n) {
        printf("check_no_utxos_mirror_read: clean — %d reviewed reader(s), no "
               "new use\n", allowed->n);
        return 0;
    }
    if (nw->n) {
        fputs("check_no_utxos_mirror_read: FAIL — new reader(s) of the node.db "
              "utxos mirror\n", stdout);
        for (i = 0; i < nw->n; i++)
            printf("  %s\n", nw->p[i]);
    }
    if (stale->n) {
        fputs("check_no_utxos_mirror_read: FAIL — stale baseline row(s) "
              "(reader gone; shrink the baseline)\n", stdout);
        for (i = 0; i < stale->n; i++)
            printf("  %s\n", stale->p[i]);
    }
    fputs("Read the kernel coins store, not the node.db utxos mirror. "
          "Baselines\nshrink only.\n", stdout);
    return 1;
}

static int num_run(void)
{
    static struct num_files all, hits, allowed, nw, stale;
    char roots[RS_MAX][RS_PATH];
    const char *bp;
    int nr = 0, rc;
    bp = env_or("ZCL_NO_UTXOS_MIRROR_READ_BASELINE", k_num_base);
    rc = num_fill_roots(roots, &nr);
    if (rc)
        return rc;
    rc = num_require_roots(roots, nr);
    if (rc)
        return rc;
    if (access(bp, R_OK) != 0) {
        fprintf(stderr, "check_no_utxos_mirror_read: FATAL — baseline missing: "
                        "%s\n", bp);
        return 2;
    }
    rc = num_load_base(&allowed, bp);
    if (rc)
        return rc;
    rc = num_collect(&all, roots, nr);
    if (rc)
        return rc;
    rc = num_scan_hits(&all, &hits);
    if (rc)
        return rc;
    rc = num_diff(&hits, &allowed, &nw, &stale);
    if (rc)
        return rc;
    return num_report(&allowed, &nw, &stale);
}

int check_no_utxos_mirror_read_selftest(void)
{
    int rc = num_run();
    if (rc != 0) {
        fprintf(stderr, "check_no_utxos_mirror_read selftest: FAIL — clean "
                        "tree rc=%d want=0\n", rc);
        return 1;
    }
    fputs("check_no_utxos_mirror_read selftest: PASS — clean tree has no new "
          "utxos-mirror readers\n", stdout);
    return 0;
}

int check_no_utxos_mirror_read_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return num_run();
}
