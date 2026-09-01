/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_impact — the impact-closure query (F3, proof-DAG from symbol
 * closure). Given a set of changed FILES it computes the file-level blast
 * radius by walking the reverse-caller call graph:
 *
 *   changed files
 *     -> changed symbols   (ci_store_symbols_in_file: defs of a .c / decls of
 *                           a header)
 *     -> reverse-caller closure  (codeindex_callers: refs WHERE callee = sym;
 *                           each ref carries `enclosing` = the caller symbol,
 *                           and `ref_file` = the file the call sits in)
 *     -> impacted FILES    (every ref_file seen + the changed files themselves)
 *
 * Everything below the public query surface is REUSED — this TU adds only the
 * traversal + the two bounded string sets it needs, over existing store reads.
 * The result is deterministic (sorted, unique) and hard-capped: any bound hit
 * sets *truncated so a caller never silently builds a huge test plan from a
 * partial closure. */

#include "codeindex_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* ── bounds (all deliberately generous; the point is a hard ceiling, not a
 * tight budget — on a bounded change set none of these is reached) ── */

/* Per-query fan-out buffer: rows pulled from one callers()/symbols_in_file()
 * call. If a single symbol has MORE callers than this we cannot prove the
 * closure is complete, so we truncate. */
#define CI_CLOSURE_QUERY_BATCH 4096
/* Distinct symbols the traversal is allowed to visit. */
#define CI_CLOSURE_MAX_SYMS 50000
/* Distinct impacted files the traversal is allowed to collect. */
#define CI_CLOSURE_MAX_FILES 20000

/* ── a tiny open-addressing string set (owns its keys) ──────────────────
 * Used for dedup only; iteration order is never observed, so the final file
 * list is sorted separately for determinism. */
struct ci_strset {
    char  **slots;   /* NULL == empty */
    size_t  cap;     /* power of two */
    size_t  len;
};

static uint64_t ci_str_hash(const char *s)
{
    /* FNV-1a — deterministic, no external dep. */
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

static bool ci_strset_init(struct ci_strset *set, size_t cap)
{
    set->slots = zcl_calloc(cap, sizeof(*set->slots), "ci_strset");
    if (!set->slots)
        LOG_FAIL("codeindex", "ci_strset alloc (%zu slots)", cap);
    set->cap = cap;
    set->len = 0;
    return true;
}

static void ci_strset_free(struct ci_strset *set)
{
    if (!set || !set->slots)
        return;
    for (size_t i = 0; i < set->cap; i++)
        free(set->slots[i]);
    free(set->slots);
    set->slots = NULL;
    set->cap = set->len = 0;
}

static bool ci_strset_grow(struct ci_strset *set)
{
    size_t ncap = set->cap * 2;
    char **ns = zcl_calloc(ncap, sizeof(*ns), "ci_strset_grow");
    if (!ns)
        LOG_FAIL("codeindex", "ci_strset grow (%zu slots)", ncap);
    for (size_t i = 0; i < set->cap; i++) {
        char *k = set->slots[i];
        if (!k)
            continue;
        size_t j = (size_t)ci_str_hash(k) & (ncap - 1);
        while (ns[j])
            j = (j + 1) & (ncap - 1);
        ns[j] = k;
    }
    free(set->slots);
    set->slots = ns;
    set->cap = ncap;
    return true;
}

/* Add `s`. *added=true iff it was newly inserted (false on a dup). Returns
 * false only on a hard error (alloc). */
static bool ci_strset_add(struct ci_strset *set, const char *s, bool *added)
{
    if (added) *added = false;
    if (!s || !s[0])
        return true;  /* ignore empties (unattributed enclosing) — not an error */
    if (set->len * 10 >= set->cap * 7 && !ci_strset_grow(set))
        return false;
    size_t j = (size_t)ci_str_hash(s) & (set->cap - 1);
    while (set->slots[j]) {
        if (strcmp(set->slots[j], s) == 0)
            return true;  /* dup */
        j = (j + 1) & (set->cap - 1);
    }
    char *dup = zcl_strdup(s, "ci_strset_key");
    if (!dup)
        LOG_FAIL("codeindex", "ci_strset key dup");
    set->slots[j] = dup;
    set->len++;
    if (added) *added = true;
    return true;
}

/* ── a growable name list (traversal frontier + impacted-file accumulator) ── */
struct ci_strlist {
    char  **items;   /* owns each string */
    size_t  cap;
    size_t  len;
};

static bool ci_strlist_push(struct ci_strlist *l, const char *s)
{
    if (l->len == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 64;
        char **ni = zcl_realloc(l->items, ncap * sizeof(*ni), "ci_strlist");
        if (!ni)
            LOG_FAIL("codeindex", "ci_strlist grow");
        l->items = ni;
        l->cap = ncap;
    }
    char *dup = zcl_strdup(s, "ci_strlist_item");
    if (!dup)
        LOG_FAIL("codeindex", "ci_strlist item dup");
    l->items[l->len++] = dup;
    return true;
}

static void ci_strlist_free(struct ci_strlist *l)
{
    if (!l || !l->items)
        return;
    for (size_t i = 0; i < l->len; i++)
        free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->cap = l->len = 0;
}

static int ci_str_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ── traversal state (heap-owned; freed on every exit) ── */
struct ci_closure_ctx {
    struct ci_strset  seen_syms;   /* symbol names already queued/visited */
    struct ci_strset  seen_files;  /* impacted files already collected */
    struct ci_strlist files;       /* impacted files (unsorted; deduped) */
    struct ci_ref    *refbuf;      /* CI_CLOSURE_QUERY_BATCH rows */
    struct ci_symbol *symbuf;      /* CI_CLOSURE_QUERY_BATCH rows */
    char            (*incbuf)[256];/* CI_CLOSURE_QUERY_BATCH include rows (fwd) */
};

static void ci_closure_ctx_free(struct ci_closure_ctx *c)
{
    ci_strset_free(&c->seen_syms);
    ci_strset_free(&c->seen_files);
    ci_strlist_free(&c->files);
    free(c->refbuf);
    free(c->symbuf);
    free(c->incbuf);
}

/* Record an impacted file (dedup). *hit_cap=true if the file cap is exceeded. */
static bool ci_closure_add_file(struct ci_closure_ctx *c, const char *path,
                                bool *hit_cap)
{
    if (!path || !path[0])
        return true;
    bool added = false;
    if (!ci_strset_add(&c->seen_files, path, &added))
        return false;
    if (!added)
        return true;
    if (c->files.len >= CI_CLOSURE_MAX_FILES) {
        *hit_cap = true;
        return true;
    }
    return ci_strlist_push(&c->files, path);
}

/* Seed the frontier from a changed file's symbols and record the file itself. */
static bool ci_closure_seed_file(struct ci_closure_ctx *c, struct codeindex *ci,
                                 const char *file, struct ci_strlist *frontier,
                                 bool *truncated)
{
    if (!ci_closure_add_file(c, file, truncated))
        return false;

    int ns = codeindex_symbols_in_file(ci, file, c->symbuf,
                                        CI_CLOSURE_QUERY_BATCH);
    if (ns < 0)
        LOG_FAIL("codeindex", "symbols_in_file failed for %s", file);
    if (ns == CI_CLOSURE_QUERY_BATCH)
        *truncated = true;  /* a file with more symbols than we can enumerate */

    for (int i = 0; i < ns; i++) {
        if (c->seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
            *truncated = true;
            break;
        }
        bool added = false;
        if (!ci_strset_add(&c->seen_syms, c->symbuf[i].name, &added))
            return false;
        if (added && !ci_strlist_push(frontier, c->symbuf[i].name))
            return false;
    }
    return true;
}

/* Expand one symbol: pull its callers, record their files, queue new callers. */
static bool ci_closure_expand_symbol(struct ci_closure_ctx *c,
                                     struct codeindex *ci, const char *sym,
                                     struct ci_strlist *next, bool *truncated,
                                     codeindex_impact_terminal_fn terminal,
                                     void *terminal_user)
{
    int nc = codeindex_callers(ci, sym, c->refbuf, CI_CLOSURE_QUERY_BATCH);
    if (nc < 0)
        LOG_FAIL("codeindex", "callers failed for %s", sym);
    if (nc == CI_CLOSURE_QUERY_BATCH)
        *truncated = true;  /* more callers than one batch — closure incomplete */

    for (int i = 0; i < nc; i++) {
        if (!ci_closure_add_file(c, c->refbuf[i].ref_file, truncated))
            return false;
        if (terminal && terminal(c->refbuf[i].ref_file, terminal_user))
            continue;
        const char *caller = c->refbuf[i].enclosing;
        if (!caller[0])
            continue;  /* file-scope reference: file recorded, no symbol to walk */
        if (c->seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
            *truncated = true;
            continue;
        }
        bool added = false;
        if (!ci_strset_add(&c->seen_syms, caller, &added))
            return false;
        if (added && !ci_strlist_push(next, caller))
            return false;
    }
    return true;
}

struct ci_overlay_seed {
    struct ci_closure_ctx *closure;
    struct ci_strlist *frontier;
    bool *truncated;
    bool failed;
};

static void ci_overlay_sym(const struct ci_symbol *sym, void *user)
{
    struct ci_overlay_seed *seed = user;
    if (seed->failed || !sym || !sym->name[0]) return;
    if (seed->closure->seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
        *seed->truncated = true;
        return;
    }
    bool added = false;
    if (!ci_strset_add(&seed->closure->seen_syms, sym->name, &added) ||
        (added && !ci_strlist_push(seed->frontier, sym->name)))
        seed->failed = true;
}

static void ci_overlay_ignore_ref(const char *callee, const char *ref_file,
                                  int ref_line, const char *enclosing,
                                  void *user)
{
    (void)callee; (void)ref_file; (void)ref_line; (void)enclosing; (void)user;
}

static int impact_closure_impl(
    struct codeindex *ci, const char *overlay_root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated)
{
    if (truncated) *truncated = false;
    if (!ci || !ci->store || !changed_files || n_changed < 0 || !out ||
        cap <= 0 || !truncated)
        LOG_ERR("codeindex", "bad args to codeindex_impact_closure");

    int depth = max_depth > 0 ? max_depth : CI_CLOSURE_DEFAULT_DEPTH;

    struct ci_closure_ctx c = {0};
    int rc = -1;
    if (!ci_strset_init(&c.seen_syms, 1024) ||
        !ci_strset_init(&c.seen_files, 1024)) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "closure set init failed");
    }
    c.refbuf = zcl_malloc(sizeof(*c.refbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_closure_refbuf");
    c.symbuf = zcl_malloc(sizeof(*c.symbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_closure_symbuf");
    if (!c.refbuf || !c.symbuf) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "closure batch alloc failed");
    }

    struct ci_strlist frontier = {0};
    struct ci_strlist next = {0};

    for (int i = 0; i < n_changed; i++) {
        if (!ci_closure_seed_file(&c, ci, changed_files[i], &frontier,
                                  truncated))
            goto done;
        if (overlay_root) {
            struct ci_overlay_seed seed = {
                .closure = &c,
                .frontier = &frontier,
                .truncated = truncated,
            };
            uint8_t current_sha3[32];
            if (!ci_scan_file(overlay_root, changed_files[i], ci_overlay_sym,
                              ci_overlay_ignore_ref, &seed, current_sha3,
                              NULL) || seed.failed)
                goto done;
        }
    }

    for (int d = 0; d < depth && frontier.len > 0; d++) {
        /* Deterministic per-level expansion order. */
        qsort(frontier.items, frontier.len, sizeof(*frontier.items),
              ci_str_cmp);
        for (size_t i = 0; i < frontier.len; i++) {
            if (!ci_closure_expand_symbol(&c, ci, frontier.items[i], &next,
                                          truncated, terminal, terminal_user))
                goto done;
        }
        ci_strlist_free(&frontier);
        frontier = next;
        memset(&next, 0, sizeof(next));
    }

    /* Deterministic, unique output. */
    qsort(c.files.items, c.files.len, sizeof(*c.files.items), ci_str_cmp);
    int n = 0;
    for (size_t i = 0; i < c.files.len && n < cap; i++) {
        memset(out[n], 0, sizeof(out[n]));
        int w = snprintf(out[n], sizeof(out[n]), "%s", c.files.items[i]);
        /* A path longer than the caller's row lands as a SILENTLY DIFFERENT
         * path: the caller then hashes whatever the truncated prefix names, or
         * fails to open it. Either way the set it holds is not the set we
         * computed, so report truncation — testcache turns that into
         * UNCACHEABLE and the group runs. */
        if (w < 0 || (size_t)w >= sizeof(out[n]))
            *truncated = true;
        n++;
    }
    if ((size_t)n < c.files.len)
        *truncated = true;  /* caller's cap could not hold the full set */
    rc = n;

done:
    ci_strlist_free(&frontier);
    ci_strlist_free(&next);
    ci_closure_ctx_free(&c);
    if (rc < 0)
        LOG_ERR("codeindex", "closure traversal failed");
    return rc;
}

int codeindex_impact_closure(struct codeindex *ci,
                             const char (*changed_files)[256], int n_changed,
                             int max_depth,
                             char (*out)[256], int cap, bool *truncated)
{
    return impact_closure_impl(ci, NULL, changed_files, n_changed, max_depth,
                               NULL, NULL, out, cap, truncated);
}

int codeindex_impact_closure_overlay(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    char (*out)[256], int cap, bool *truncated)
{
    if (!root || !root[0]) {
        if (truncated) *truncated = false;
        LOG_ERR("codeindex", "overlay closure root is empty");
    }
    return impact_closure_impl(ci, root, changed_files, n_changed, max_depth,
                               NULL, NULL, out, cap, truncated);
}

int codeindex_impact_closure_with_terminal(
    struct codeindex *ci, const char (*changed_files)[256], int n_changed,
    int max_depth, codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated)
{
    if (!terminal) {
        if (truncated) *truncated = false;
        LOG_ERR("codeindex", "terminal closure callback is empty");
    }
    return impact_closure_impl(ci, NULL, changed_files, n_changed, max_depth,
                               terminal, terminal_user, out, cap, truncated);
}

int codeindex_impact_closure_overlay_with_terminal(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated)
{
    if (!root || !root[0] || !terminal) {
        if (truncated) *truncated = false;
        LOG_ERR("codeindex", "overlay terminal closure input is empty");
    }
    return impact_closure_impl(ci, root, changed_files, n_changed, max_depth,
                               terminal, terminal_user, out, cap, truncated);
}

/* ── reverse INCLUDE closure ────────────────────────────────────────────
 *
 * The dimension the call-graph walk above structurally cannot see. See
 * codeindex.h for the contract; the short version is that a depfile's
 * prerequisite list is already transitively flattened, so the reverse edge set
 * of one path IS its transitive dependent set over translation units — one
 * indexed equality probe, no traversal, no depth bound.
 *
 * The only thing that needs care is telling "nothing depends on this" apart
 * from "there is no include graph to ask". Those are the same empty array and
 * opposite facts, and conflating them is defect D4: a fresh clone would
 * answer every reverse-include question with a confident, complete-looking
 * zero. */
const char *codeindex_include_dim_label(enum codeindex_include_dim dim)
{
    switch (dim) {
    case CODEINDEX_INCLUDE_DIM_COMPLETE:    return "complete";
    case CODEINDEX_INCLUDE_DIM_TRUNCATED:   return "closure-truncated";
    case CODEINDEX_INCLUDE_DIM_UNAVAILABLE: return "no-include-graph";
    }
    return "unknown";
}

int codeindex_reverse_includes(struct codeindex *ci, const char *path,
                               char (*out)[256], int cap,
                               enum codeindex_include_dim *dim)
{
    if (dim) *dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    if (!ci || !ci->store || !path || !path[0] || !out || cap <= 0 ||
        cap > CI_CLOSURE_MAX_FILES || !dim)
        LOG_ERR("codeindex", "bad args to codeindex_reverse_includes");

    int64_t edges = ci_store_include_edge_count(ci->store);
    if (edges < 0)
        LOG_ERR("codeindex", "include edge count failed");
    if (edges == 0) {
        /* No depfiles were on disk when this index was built. Every reverse
         * question is UNANSWERED, not answered with zero. */
        *dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        return 0;
    }

    int n = ci_store_dependents_of_file(ci->store, path, out, cap);
    if (n < 0)
        LOG_ERR("codeindex", "dependents_of_file failed for %s", path);
    /* A result that exactly fills `cap` is ambiguous: complete-and-exact, or
     * clipped. Re-ask for one row more than the caller can hold; only that
     * distinguishes the two, and guessing would mint a false COMPLETE. */
    if (n == cap) {
        char (*wide)[256] = zcl_malloc(sizeof(*wide) * (size_t)cap + sizeof(*wide),
                                       "ci_revinc_probe");
        if (!wide)
            LOG_ERR("codeindex", "reverse-include probe alloc");
        int nw = ci_store_dependents_of_file(ci->store, path, wide, cap + 1);
        free(wide);
        if (nw < 0)
            LOG_ERR("codeindex", "reverse-include probe failed for %s", path);
        if (nw > cap) {
            *dim = CODEINDEX_INCLUDE_DIM_TRUNCATED;
            return n;
        }
    }
    *dim = CODEINDEX_INCLUDE_DIM_COMPLETE;
    return n;
}

/* ── forward (callee) input closure ─────────────────────────────────────
 *
 * The mirror of the reverse walk above: from a root SYMBOL, collect every
 * in-tree file whose bytes the symbol's behavior can transitively depend on.
 * Files are recorded at DISCOVERY time (not pop time) so a depth-bounded walk
 * never silently drops the last level's definition files — depth exhaustion
 * with a non-empty frontier is instead reported as *truncated.
 *
 * A generous depth ceiling: real call chains from a test entry point are far
 * shallower. Hitting it means the frontier never emptied within the ceiling,
 * which we report as truncated so the caller treats the group as uncacheable. */
#define CI_FWD_DEPTH_CEIL 256

/* Record `sym`'s definition file and that file's in-tree include closure.
 * A symbol that resolves to no in-tree definition (a libc/external call) has
 * no file to hash and is silently skipped — it cannot change under the tree.
 * *hit_cap is raised through ci_closure_add_file / an include fan-out overflow. */
static bool ci_fwd_record_symbol_file(struct ci_closure_ctx *c,
                                      struct codeindex *ci, const char *sym,
                                      bool *hit_cap)
{
    struct ci_symbol s;
    bool found = false;
    if (!codeindex_symbol(ci, sym, &s, &found))
        return false;
    if (!found || !s.def_path[0])
        return true;  /* external/undefined: nothing in-tree to hash */

    if (!ci_closure_add_file(c, s.def_path, hit_cap))
        return false;

    int ni = codeindex_includes_of_file(ci, s.def_path, c->incbuf,
                                        CI_CLOSURE_QUERY_BATCH);
    if (ni < 0)
        LOG_FAIL("codeindex", "includes_of_file failed for %s", s.def_path);
    if (ni == CI_CLOSURE_QUERY_BATCH)
        *hit_cap = true;  /* more includes than one batch — closure incomplete */
    for (int i = 0; i < ni; i++) {
        if (!ci_closure_add_file(c, c->incbuf[i], hit_cap))
            return false;
    }
    return true;
}

int codeindex_forward_closure(struct codeindex *ci, const char *root_symbol,
                              char (*out)[256], int cap,
                              bool *truncated, bool *root_found)
{
    if (truncated) *truncated = false;
    if (root_found) *root_found = false;
    if (!ci || !ci->store || !root_symbol || !out || cap <= 0 || !truncated)
        LOG_ERR("codeindex", "bad args to codeindex_forward_closure");

    struct ci_closure_ctx c = {0};
    int rc = -1;
    if (!ci_strset_init(&c.seen_syms, 1024) ||
        !ci_strset_init(&c.seen_files, 1024)) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "forward closure set init failed");
    }
    c.refbuf = zcl_malloc(sizeof(*c.refbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_fwd_refbuf");
    c.incbuf = zcl_malloc(sizeof(*c.incbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_fwd_incbuf");
    if (!c.refbuf || !c.incbuf) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "forward closure batch alloc failed");
    }

    /* The root must resolve to a known in-tree symbol; otherwise its inputs
     * cannot be bounded (the caller treats this as UNCACHEABLE). */
    struct ci_symbol rs;
    bool found = false;
    if (!codeindex_symbol(ci, root_symbol, &rs, &found)) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "root symbol lookup failed");
    }
    if (!found) {
        if (root_found) *root_found = false;
        ci_closure_ctx_free(&c);
        return 0;  /* empty closure, not an error */
    }
    if (root_found) *root_found = true;

    struct ci_strlist frontier = {0};
    struct ci_strlist next = {0};

    bool added = false;
    if (!ci_strset_add(&c.seen_syms, root_symbol, &added))
        goto done;
    if (!ci_fwd_record_symbol_file(&c, ci, root_symbol, truncated))
        goto done;
    if (!ci_strlist_push(&frontier, root_symbol))
        goto done;

    for (int d = 0; d < CI_FWD_DEPTH_CEIL && frontier.len > 0; d++) {
        qsort(frontier.items, frontier.len, sizeof(*frontier.items),
              ci_str_cmp);
        for (size_t i = 0; i < frontier.len; i++) {
            int nc = codeindex_callees(ci, frontier.items[i], c.refbuf,
                                       CI_CLOSURE_QUERY_BATCH);
            if (nc < 0) {
                ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR,
                    "[codeindex] %s:%d %s(): callees failed for %s\n",
                    __FILE__, __LINE__, __func__, frontier.items[i]);
                goto done;  /* rc stays -1; cleanup below runs */
            }
            if (nc == CI_CLOSURE_QUERY_BATCH)
                *truncated = true;  /* more callees than one batch */
            for (int j = 0; j < nc; j++) {
                const char *callee = c.refbuf[j].callee;
                if (!callee[0])
                    continue;
                if (c.seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
                    *truncated = true;
                    continue;
                }
                bool new_sym = false;
                if (!ci_strset_add(&c.seen_syms, callee, &new_sym))
                    goto done;
                if (!new_sym)
                    continue;
                /* Record the callee's file at DISCOVERY so depth bounding can
                 * never drop it. */
                if (!ci_fwd_record_symbol_file(&c, ci, callee, truncated))
                    goto done;
                if (!ci_strlist_push(&next, callee))
                    goto done;
            }
        }
        ci_strlist_free(&frontier);
        frontier = next;
        memset(&next, 0, sizeof(next));
    }
    if (frontier.len > 0)
        *truncated = true;  /* depth ceiling hit with the frontier non-empty */

    qsort(c.files.items, c.files.len, sizeof(*c.files.items), ci_str_cmp);
    int n = 0;
    for (size_t i = 0; i < c.files.len && n < cap; i++) {
        memset(out[n], 0, sizeof(out[n]));
        int w = snprintf(out[n], sizeof(out[n]), "%s", c.files.items[i]);
        /* A path longer than the caller's row lands as a SILENTLY DIFFERENT
         * path: the caller then hashes whatever the truncated prefix names, or
         * fails to open it. Either way the set it holds is not the set we
         * computed, so report truncation — testcache turns that into
         * UNCACHEABLE and the group runs. */
        if (w < 0 || (size_t)w >= sizeof(out[n]))
            *truncated = true;
        n++;
    }
    if ((size_t)n < c.files.len)
        *truncated = true;  /* caller's cap could not hold the full set */
    rc = n;

done:
    ci_strlist_free(&frontier);
    ci_strlist_free(&next);
    ci_closure_ctx_free(&c);
    if (rc < 0)
        LOG_ERR("codeindex", "forward closure traversal failed");
    return rc;
}
