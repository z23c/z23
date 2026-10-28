/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The facts-narrowed caller walk: callers of the seeds by name, kept only where a caller's manifest names the callee's canonical id, folded into the plan. */
#include "devloop_facts.h"

#include "devloop_facts_index.h"
#include "vcs/semantic_manifest.h"

#include "codeindex/codeindex.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The same bounds as the file-seeded walk (codeindex_impact.c): a caller
 * batch that fills, or the symbol cap, means the answer is not whole, and a
 * narrowing never keeps a partial answer. */
#define FX_BATCH 4096
#define FX_MAX_SYMS 50000
#define FX_KEY_MAX (ZCL_DEVLOOP_FACTS_ID_MAX + ZCL_DEVLOOP_FACTS_NAME_MAX + 2)

/* A set of fixed-width strings, insertion-ordered, open-addressed. */
struct fx_set {
    char *items;
    size_t width, len, cap;
    uint32_t *slots;
    size_t nslots;
};

static uint64_t fx_hash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

static const char *fx_at(const struct fx_set *s, size_t k)
{
    return s->items + k * s->width;
}

static bool fx_rehash(struct fx_set *s)
{
    size_t n = s->nslots ? s->nslots * 2 : 1024;
    uint32_t *slots = zcl_calloc(n, sizeof(*slots), "facts.set");
    if (slots == NULL)
        return false;
    for (size_t k = 0; k < s->len; k++) {
        size_t j = (size_t)fx_hash(fx_at(s, k)) & (n - 1);
        while (slots[j])
            j = (j + 1) & (n - 1);
        slots[j] = (uint32_t)(k + 1);
    }
    free(s->slots);
    s->slots = slots;
    s->nslots = n;
    return true;
}

static bool fx_push(struct fx_set *s, const char *key)
{
    if (s->len == s->cap) {
        size_t next = s->cap ? s->cap * 2 : 256;
        char *grown = zcl_realloc(s->items, next * s->width, "facts.set");
        if (grown == NULL)
            return false;
        s->items = grown;
        s->cap = next;
    }
    (void)snprintf(s->items + s->len * s->width, s->width, "%s", key);
    s->len++;
    return true;
}

/* Adds `key` (keys wider than the set are refused). */
static bool fx_add(struct fx_set *s, const char *key, bool *added)
{
    size_t j;
    *added = false;
    if (strlen(key) >= s->width)
        return false;
    if (s->len * 2 >= s->nslots && !fx_rehash(s))
        return false;
    j = (size_t)fx_hash(key) & (s->nslots - 1);
    for (; s->slots[j]; j = (j + 1) & (s->nslots - 1))
        if (strcmp(fx_at(s, s->slots[j] - 1), key) == 0)
            return true;
    if (!fx_push(s, key))
        return false;
    s->slots[j] = (uint32_t)s->len;
    *added = true;
    return true;
}

static void fx_set_free(struct fx_set *s)
{
    free(s->items);
    free(s->slots);
}

/* ---- caller manifests ---------------------------------------------------------- */

struct fx_manifest {
    char path[256];
    uint8_t *bytes;
    struct fxi *x; /* NULL: no usable manifest, keep callers by name */
};

struct fx_walk {
    struct codeindex *ci;
    const char *root, *facts_dir;
    /* Walk entries: key "<id>" or "#<name>" (unknown id), with the name to
     * query and the id to filter by, in insertion order. */
    struct fx_set keys, names, ids;
    struct fx_set *files;
    struct fx_manifest *cache;
    size_t ncache, capcache;
    struct ci_ref *buf;
};

static const struct fxi *fx_manifest_of(struct fx_walk *w, const char *path)
{
    struct fx_manifest *m;
    size_t len = 0;
    const char *why;
    if (w->facts_dir == NULL || strlen(path) >= sizeof(m->path))
        return NULL;
    for (size_t k = 0; k < w->ncache; k++)
        if (strcmp(w->cache[k].path, path) == 0)
            return w->cache[k].x;
    if (w->ncache == w->capcache) {
        size_t next = w->capcache ? w->capcache * 2 : 64;
        struct fx_manifest *g = zcl_realloc(w->cache, next * sizeof(*g),
                                            "facts.walk_cache");
        if (g == NULL)
            return NULL;
        w->cache = g;
        w->capcache = next;
    }
    m = &w->cache[w->ncache++];
    memset(m, 0, sizeof(*m));
    (void)snprintf(m->path, sizeof(m->path), "%s", path);
    if (zcl_devloop_facts_read(w->root, w->facts_dir, path, ".after.zsm",
                               VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &m->bytes,
                               &len))
        m->x = fxi_open(m->bytes, len, &why);
    return m->x;
}

/* The canonical id of function `name` that `path` defines, from its
 * manifest; "" when it has none or defines no such function. */
static void fx_enclosing_id(struct fx_walk *w, const char *path,
                            const char *name, char *out, size_t cap)
{
    const struct fxi *x = fx_manifest_of(w, path);
    char id[FX_KEY_MAX];
    size_t e;
    out[0] = '\0';
    if (x == NULL)
        return;
    (void)snprintf(id, sizeof(id), "f:%s:%s", path, name);
    if (!fxi_find(x, id, &e) || !fxi_main_function(x, e))
        (void)snprintf(id, sizeof(id), "f:%s", name);
    if (fxi_find(x, id, &e) && fxi_main_function(x, e) && strlen(id) < cap)
        memcpy(out, id, strlen(id) + 1);
}

static bool fx_entry(struct fx_walk *w, const char *name, const char *id)
{
    char key[FX_KEY_MAX];
    bool added;
    if (id[0] != '\0')
        (void)snprintf(key, sizeof(key), "%s", id);
    else
        (void)snprintf(key, sizeof(key), "#%s", name);
    if (!fx_add(&w->keys, key, &added))
        return false;
    return !added || (fx_push(&w->names, name) && fx_push(&w->ids, id));
}

/* A caller in `file` of the entry's function is real unless the file's
 * manifest is here and names none of the id's calls or addresses. */
static bool fx_is_caller(struct fx_walk *w, const char *file, const char *id)
{
    const struct fxi *x;
    if (id[0] == '\0' || file[0] == '\0')
        return true;
    x = fx_manifest_of(w, file);
    return x == NULL || fxi_refs_to(x, id, VCS_SEMANTIC_REF_V1_CALL) ||
           fxi_refs_to(x, id, VCS_SEMANTIC_REF_V1_ADDRESS);
}

enum fx_walk_rc { FX_WALK_OK, FX_WALK_BOUNDED, FX_WALK_ERROR };

static enum fx_walk_rc fx_expand(struct fx_walk *w, size_t k)
{
    char name[ZCL_DEVLOOP_FACTS_NAME_MAX], id[ZCL_DEVLOOP_FACTS_ID_MAX];
    int nc;
    bool added;
    (void)snprintf(name, sizeof(name), "%s", fx_at(&w->names, k));
    (void)snprintf(id, sizeof(id), "%s", fx_at(&w->ids, k));
    nc = codeindex_callers(w->ci, name, w->buf, FX_BATCH);
    if (nc < 0)
        return FX_WALK_ERROR;
    if (nc == FX_BATCH)
        return FX_WALK_BOUNDED;
    for (int i = 0; i < nc; i++) {
        const struct ci_ref *r = &w->buf[i];
        char enclosing_id[ZCL_DEVLOOP_FACTS_ID_MAX];
        if (!fx_is_caller(w, r->ref_file, id))
            continue;
        if (r->ref_file[0] && !fx_add(w->files, r->ref_file, &added))
            return FX_WALK_ERROR;
        if (zcl_devloop_plan_proof_owner(r->ref_file) || !r->enclosing[0])
            continue;
        if (w->keys.len >= FX_MAX_SYMS)
            return FX_WALK_BOUNDED;
        fx_enclosing_id(w, r->ref_file, r->enclosing, enclosing_id,
                        sizeof(enclosing_id));
        if (strlen(r->enclosing) >= ZCL_DEVLOOP_FACTS_NAME_MAX ||
            !fx_entry(w, r->enclosing, enclosing_id))
            return FX_WALK_ERROR;
    }
    return FX_WALK_OK;
}

/* Callers of the seeds, then callers of callers, CI_CLOSURE_DEFAULT_DEPTH
 * levels deep, exactly as codeindex_impact_closure_bounded() expands a
 * file's symbols, with the planner's proof-owner files as terminals. */
static enum fx_walk_rc fx_walk_run(struct fx_walk *w)
{
    enum fx_walk_rc rc = FX_WALK_OK;
    size_t lo = 0;
    for (int d = 0; rc == FX_WALK_OK && d < CI_CLOSURE_DEFAULT_DEPTH &&
                    lo < w->names.len;
         d++) {
        size_t hi = w->names.len;
        for (size_t k = lo; rc == FX_WALK_OK && k < hi; k++)
            rc = fx_expand(w, k);
        lo = hi;
    }
    return rc;
}

static int fx_path_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

/* Replace the plan's closure with the narrowed file set. */
static bool fx_fold(struct zcl_devloop_plan *plan, struct fx_set *files)
{
    if (files->len > 1)
        qsort(files->items, files->len, files->width, fx_path_cmp);
    plan->closure_attempted = true;
    plan->closure_snapshot = false;
    plan->closure_universal = plan->path_universal;
    zcl_devloop_capacity_reset_closure(plan);
    plan->closure_groups_len = 0;
    for (size_t k = 0; k < files->len; k++)
        if (!zcl_devloop_plan_fold_file(plan, fx_at(files, k),
                                        ZCL_DEVLOOP_DIM_SEMANTIC)) {
            zcl_devloop_capacity_note(plan, "facts", "group-cap", "batch");
            return false;
        }
    /* Feedback only, never proof: see zcl_devloop_plan_proof_admissible(). */
    plan->dims[ZCL_DEVLOOP_DIM_SEMANTIC].status = ZCL_DEVLOOP_DIM_INCOMPLETE;
    plan->dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason = "facts-narrowed";
    plan->dims[ZCL_DEVLOOP_DIM_INCLUDE].status =
        ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    plan->dims[ZCL_DEVLOOP_DIM_INCLUDE].reason = "";
    plan->closure_truncated = true;
    return true;
}


#if defined(ZCL_TESTING)
/* The reached set of the last walk that folded, for the fixture's check. */
static char *g_fx_test_reached;
static size_t g_fx_test_reached_len, g_fx_test_reached_width;
/* The fold the last walk started from. */
static char **g_fx_test_fold;
static size_t g_fx_test_nfold;

void zcl_devloop_test_reached_reset(void)
{
    free(g_fx_test_reached);
    g_fx_test_reached = NULL;
    g_fx_test_reached_len = g_fx_test_reached_width = 0;
    for (size_t k = 0; k < g_fx_test_nfold; k++)
        free(g_fx_test_fold[k]);
    free(g_fx_test_fold);
    g_fx_test_fold = NULL;
    g_fx_test_nfold = 0;
}

bool zcl_devloop_test_reached_has(const char *path)
{
    for (size_t k = 0; k < g_fx_test_reached_len; k++)
        if (strcmp(g_fx_test_reached + k * g_fx_test_reached_width, path) == 0)
            return true;
    return false;
}

bool zcl_devloop_test_folded_has(const char *path)
{
    for (size_t k = 0; k < g_fx_test_nfold; k++)
        if (strcmp(g_fx_test_fold[k], path) == 0)
            return true;
    return false;
}

static void fx_test_keep_reached(const struct fx_set *s)
{
    free(g_fx_test_reached);
    g_fx_test_reached = zcl_malloc(s->len * s->width + 1, "facts.test_reached");
    g_fx_test_reached_len = g_fx_test_reached_width = 0;
    if (g_fx_test_reached == NULL)
        return;
    memcpy(g_fx_test_reached, s->items, s->len * s->width);
    g_fx_test_reached_len = s->len;
    g_fx_test_reached_width = s->width;
}

static void fx_test_keep_fold(const char *const *fold, size_t nfold)
{
    zcl_devloop_test_reached_reset();
    g_fx_test_fold = zcl_calloc(nfold + 1, sizeof(*g_fx_test_fold),
                                "facts.test_fold");
    for (size_t k = 0; g_fx_test_fold != NULL && k < nfold; k++) {
        size_t n = strlen(fold[k]) + 1;
        char *copy = zcl_malloc(n, "facts.test_fold_path");
        if (copy == NULL)
            return;
        memcpy(copy, fold[k], n);
        g_fx_test_fold[g_fx_test_nfold++] = copy;
    }
}
#endif

static void fx_walk_free(struct fx_walk *w)
{
    for (size_t k = 0; k < w->ncache; k++) {
        fxi_free(w->cache[k].x);
        free(w->cache[k].bytes);
    }
    free(w->cache);
    free(w->buf);
    fx_set_free(&w->keys);
    fx_set_free(&w->names);
    fx_set_free(&w->ids);
}

static bool fx_walk_seed(struct fx_walk *w, const char *const *fold,
                         size_t nfold,
                         const struct zcl_devloop_facts_seed *seeds,
                         size_t nseeds)
{
    bool added, ok = w->buf != NULL;
    for (size_t k = 0; ok && k < nfold; k++)
        ok = fx_add(w->files, fold[k], &added);
    for (size_t k = 0; ok && k < nseeds; k++)
        ok = fx_entry(w, seeds[k].name, seeds[k].id);
    return ok;
}

bool zcl_devloop_facts_narrow(const char *root, const char *facts_dir,
                              const char *const *fold, size_t nfold,
                              const struct zcl_devloop_facts_seed *seeds,
                              size_t nseeds, struct zcl_devloop_plan *plan,
                              struct zcl_devloop_facts_verdict *v)
{
    struct fx_set reached = {.width = 256};
    struct fx_walk w = {
        .root = root, .facts_dir = facts_dir, .files = &reached,
        .keys = {.width = FX_KEY_MAX},
        .names = {.width = ZCL_DEVLOOP_FACTS_NAME_MAX},
        .ids = {.width = ZCL_DEVLOOP_FACTS_ID_MAX},
        .buf = zcl_malloc(sizeof(struct ci_ref) * FX_BATCH, "facts.refs")};
    enum fx_walk_rc rc = FX_WALK_ERROR;
    bool ok;
    /* The file-seeded closure's own index: codeindex_open() rebuilds it when
     * the sources moved past it, or refuses (a live resident owns the
     * rebuild) and the plan falls back. Never a stale snapshot. */
    w.ci = codeindex_open(root);
    if (w.ci == NULL) {
        v->reason = "no-code-index";
        fx_walk_free(&w);
        return false;
    }
#if defined(ZCL_TESTING)
    fx_test_keep_fold(fold, nfold);
#endif
    if (fx_walk_seed(&w, fold, nfold, seeds, nseeds))
        rc = fx_walk_run(&w);
    codeindex_close(w.ci);
    v->reason = rc == FX_WALK_OK      ? ""
                : rc == FX_WALK_BOUNDED ? "closure-bounded"
                                        : "closure-query-error";
    v->reached_files = reached.len;
    ok = rc == FX_WALK_OK && fx_fold(plan, &reached);
#if defined(ZCL_TESTING)
    if (ok)
        fx_test_keep_reached(&reached);
#endif
    if (rc == FX_WALK_OK && !ok)
        v->reason = "group-cap";
    fx_walk_free(&w);
    fx_set_free(&reached);
    return ok;
}
