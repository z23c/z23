/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: object-tree selection for the lib module link graph. Picks the
 * directory of compiled objects the graph is measured from (an explicit
 * --obj-dir, the newest epoch of --obj-root, or the first warm root of the
 * fixed preference list), lists its .o files and, for a root-selected tree,
 * drops objects whose source no longer exists. Ported from the selection
 * half of tools/dev/module-linkgraph.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "base/safe_alloc.h"
#include "gate_lib_module_order_graph.h"

/* Production tree first, then the release/fast/asan test trees and the dev
 * tree: a fixed order keeps the reported graph stable when several profiles
 * are warm. */
static const char *const k_lmg_roots[] = {
    "build/obj", "build/test-rel-obj", "build/test-obj", "build/test-asan-obj",
    "build/dev-obj",
};

struct lmg_list { char **p; size_t n, cap; };

static char *lmg_fmt2(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    char *s = zcl_malloc(la + lb + 2, "lmg_path");
    if (!s)
        return NULL;
    memcpy(s, a, la);
    s[la] = '/';
    memcpy(s + la + 1, b, lb + 1);
    return s;
}

/* root/p, or p alone when it is absolute. */
static char *lmg_join(const char *root, const char *p)
{
    if (p[0] == '/')
        return strdup(p);
    return lmg_fmt2(root, p);
}

static int lmg_push(struct lmg_list *l, char *s)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        char **np = zcl_realloc(l->p, nc * sizeof *np, "lmg_objs");
        if (!np) {
            free(s);
            return -1;
        }
        l->p = np;
        l->cap = nc;
    }
    l->p[l->n++] = s;
    return 0;
}

static int lmg_is_obj_name(const char *name)
{
    size_t n = strlen(name);
    return n >= 2 && strcmp(name + n - 2, ".o") == 0;
}

/* Recurses into dir collecting regular *.o files into l (symlinks are not
 * followed, like find -type f). stop_first ends the walk at the first hit.
 * 0 ok, -1 on allocation failure. */
static int lmg_walk(const char *dir, struct lmg_list *l, int stop_first)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char *path = lmg_fmt2(dir, e->d_name);
        if (!path) {
            rc = -1;
            break;
        }
        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
        } else if (S_ISDIR(st.st_mode)) {
            rc = lmg_walk(path, l, stop_first);
            free(path);
        } else if (S_ISREG(st.st_mode) && lmg_is_obj_name(e->d_name)) {
            rc = lmg_push(l, path);
        } else {
            free(path);
        }
        if (rc == 0 && stop_first && l->n > 0)
            break;
    }
    closedir(d);
    return rc;
}

static void lmg_list_free(struct lmg_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->p[i]);
    free(l->p);
    l->p = NULL;
    l->n = l->cap = 0;
}

/* True when dir holds at least one .o anywhere below it. */
static int lmg_has_obj(const char *dir)
{
    struct lmg_list l = { 0 };
    int rc = lmg_walk(dir, &l, 1);
    int found = l.n > 0;
    lmg_list_free(&l);
    return rc == 0 && found;
}

static int lmg_newer(const struct stat *a, const struct stat *b)
{
    if (a->st_mtim.tv_sec != b->st_mtim.tv_sec)
        return a->st_mtim.tv_sec > b->st_mtim.tv_sec;
    return a->st_mtim.tv_nsec > b->st_mtim.tv_nsec;
}

/* Name (malloc'd, joined) of the most recently modified directory under
 * root/epochs, or NULL when there is none. */
static char *lmg_newest_epoch(const char *epochs)
{
    DIR *d = opendir(epochs);
    if (!d)
        return NULL;
    char *best = NULL;
    struct stat bst = { 0 };
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char *path = lmg_fmt2(epochs, e->d_name);
        struct stat st;
        if (path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
            (!best || lmg_newer(&st, &bst))) {
            free(best);
            best = path;
            bst = st;
        } else {
            free(path);
        }
    }
    closedir(d);
    return best;
}

/* The tree to measure for one candidate root: its newest epoch holding an
 * object, else the root itself when any object sits below it. Returns the
 * relative directory (malloc'd) or NULL. */
static char *lmg_pick_root(const char *root, const char *cand)
{
    char *rj = lmg_join(root, cand);
    if (!rj)
        return NULL;
    char *res = NULL;
    char *ep = lmg_fmt2(rj, "epochs");
    char *newest = ep ? lmg_newest_epoch(ep) : NULL;
    if (newest && lmg_has_obj(newest)) {
        /* Keep the caller's spelling of the root: cand/epochs/<name>. */
        char *sub = lmg_fmt2(cand, "epochs");
        res = sub ? lmg_fmt2(sub, strrchr(newest, '/') + 1) : NULL;
        free(sub);
    } else if (lmg_has_obj(rj)) {
        res = strdup(cand);
    }
    free(newest);
    free(ep);
    free(rj);
    return res;
}

/* Sets o->dir_rel to the selected directory (explicit, or picked). 0 ok, or
 * LMG_NONE with the "no compiled objects" message. */
static int lmg_select(const struct lmg_req *req, struct lmg_objs *o, FILE *diag)
{
    if (req->obj_dir) {
        o->dir_rel = strdup(req->obj_dir);
        return o->dir_rel ? 0 : LMG_ERROR;
    }
    size_t n = req->obj_root ? 1 : sizeof k_lmg_roots / sizeof k_lmg_roots[0];
    for (size_t i = 0; i < n && !o->dir_rel; i++)
        o->dir_rel = lmg_pick_root(req->root,
                                   req->obj_root ? req->obj_root : k_lmg_roots[i]);
    if (o->dir_rel)
        return 0;
    if (diag) {
        if (req->obj_root)
            fprintf(diag, "module-linkgraph: no compiled objects under %s.\n",
                    req->obj_root);
        else
            fputs("module-linkgraph: no compiled objects found.\n", diag);
        fputs("  Run 'make build-only -j$(nproc)' first.\n", diag);
    }
    return LMG_NONE;
}

/* qsort order for an array of C strings. */
int lmg_cmp_strp(const void *a, const void *b)
{
    int r = strcmp(*(char *const *)a, *(char *const *)b);
    return (r > 0) - (r < 0);
}

/* A root-selected object keeps its place only while its source file exists:
 * a stale object whose .c moved would otherwise add a false edge forever. */
static int lmg_source_exists(const char *root, const char *dirj, const char *obj)
{
    size_t dl = strlen(dirj);
    const char *rel = obj + dl + 1;
    size_t rl = strlen(rel);
    char *src = zcl_malloc(rl + 1, "lmg_src");
    if (!src)
        return 0;
    memcpy(src, rel, rl - 1);
    src[rl - 1] = 'c';
    src[rl] = '\0';
    char *full = lmg_join(root, src);
    struct stat st;
    int ok = full && stat(full, &st) == 0 && S_ISREG(st.st_mode);
    free(full);
    free(src);
    return ok;
}

static void lmg_filter_sources(const struct lmg_req *req, struct lmg_objs *o)
{
    size_t w = 0;
    for (size_t i = 0; i < o->n; i++) {
        if (lmg_source_exists(req->root, o->dir, o->path[i]))
            o->path[w++] = o->path[i];
        else
            free(o->path[i]);
    }
    o->n = w;
}

int lmg_collect(const struct lmg_req *req, struct lmg_objs *o, FILE *diag)
{
    memset(o, 0, sizeof *o);
    int rc = lmg_select(req, o, diag);
    if (rc)
        return rc;
    size_t dl = strlen(o->dir_rel);
    while (dl > 1 && o->dir_rel[dl - 1] == '/')
        o->dir_rel[--dl] = '\0';
    o->dir = lmg_join(req->root, o->dir_rel);
    struct stat st;
    if (!o->dir)
        return LMG_ERROR;
    if (stat(o->dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (diag)
            fprintf(diag, "module-linkgraph: object dir not found: %s\n",
                    o->dir_rel);
        return LMG_NONE;
    }
    struct lmg_list l = { 0 };
    if (lmg_walk(o->dir, &l, 0) != 0) {
        lmg_list_free(&l);
        return LMG_ERROR;
    }
    o->path = l.p;
    o->n = l.n;
    if (req->obj_root)
        lmg_filter_sources(req, o);
    if (o->n == 0) {
        if (diag)
            fprintf(diag, "module-linkgraph: no .o files under %s\n"
                    "  Run 'make build-only -j$(nproc)' first.\n", o->dir_rel);
        return LMG_NONE;
    }
    qsort(o->path, o->n, sizeof *o->path, lmg_cmp_strp);
    return 0;
}

void lmg_objs_free(struct lmg_objs *o)
{
    for (size_t i = 0; i < o->n; i++)
        free(o->path[i]);
    free(o->path);
    free(o->dir);
    free(o->dir_rel);
    memset(o, 0, sizeof *o);
}
