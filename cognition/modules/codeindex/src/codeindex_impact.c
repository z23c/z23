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
 * The walk is LINKAGE-AWARE. A frontier entry is a symbol identity, not a bare
 * name: an external function is keyed by its name, but a static function
 * defined in a .c file is keyed by (name, defining file). Two TUs that each
 * define `static int helper(void)` are unrelated symbols; a name-only walk
 * treated every call to any `helper` as a caller of the changed one, and on the
 * real tree that turned a one-file test edit into 134 selected test groups.
 * A static's callers are the refs to its name that its own translation unit
 * can contain: refs in its file, in any header, and in any other .c whose
 * compiler depfile lists the static's file. A .c without a recorded depfile
 * is dropped only when it defines its own function of that name — its calls
 * bind there. Every case the index cannot prove stays on the name-only walk:
 * a static defined in a header (a `static inline` is defined in every
 * includer), an unresolved caller, a clipped include answer.
 *
 * Everything below the public query surface is REUSED — this TU adds only the
 * traversal + the two bounded string sets it needs, over existing store reads.
 * The result is deterministic (sorted, unique) and hard-capped: any bound hit
 * sets *truncated so a caller never silently builds a huge test plan from a
 * partial closure. */

#include "codeindex_priv.h"

#include "platform/file_metadata.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

const char *codeindex_impact_cause_label(enum ci_impact_cause_reason reason)
{
    static const char *const labels[] = {
        "none", "file_set_capacity", "queue_symbol_capacity",
        "seed_query_saturated", "seed_symbol_capacity", "caller_query_saturated",
        "caller_symbol_capacity", "output_path_capacity", "output_format_error",
        "output_row_capacity"
    };
    return (unsigned)reason < sizeof(labels) / sizeof(labels[0])
        ? labels[(unsigned)reason] : "unknown";
}
void codeindex_impact_cause_reset(struct ci_impact_cause *cause)
{
    if (cause)
        memset(cause, 0, sizeof(*cause));
}
#ifdef ZCL_TESTING
static bool ci_impact_cause_copy(char *out, size_t cap, const char *source)
{
    out[0] = '\0';
    if (!source)
        return false;
    size_t len = strlen(source), n = len < cap ? len : cap - 1;
    memcpy(out, source, n);
    out[n] = '\0';
    return len >= cap;
}
void codeindex_test_impact_cause_identity(struct ci_impact_cause *cause,
                                         const char *path, const char *node)
{
    codeindex_impact_cause_reset(cause);
    if (!cause)
        return;
    cause->path_known = path && path[0];
    cause->path_truncated = ci_impact_cause_copy(cause->path, sizeof(cause->path), path);
    cause->node_truncated = ci_impact_cause_copy(cause->node, sizeof(cause->node), node);
}
#endif

/* ── bounds (all deliberately generous; the point is a hard ceiling, not a
 * tight budget — on a bounded change set none of these is reached) ── */

/* Per-query fan-out buffer: rows pulled from one callers()/symbols_in_file()
 * call. If a single symbol has MORE callers than this we cannot prove the
 * closure is complete, so we truncate. */
#define CI_CLOSURE_QUERY_BATCH 4096
/* Distinct symbols the traversal is allowed to visit. */
#define CI_CLOSURE_MAX_SYMS 50000
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

/* qsort's base is declared nonnull; sorting 0 or 1 entries is a no-op. */
static void ci_strlist_sort(struct ci_strlist *l)
{
    if (l->len > 1) qsort(l->items, l->len, sizeof(*l->items), ci_str_cmp);
}

/* ── traversal state (heap-owned; freed on every exit) ── */
struct ci_closure_ctx {
    struct ci_strset  seen_syms;   /* symbol identity keys queued/visited */
    struct ci_strset  seen_sites;  /* (enclosing, file) pairs already resolved */
    struct ci_strset  seen_files;  /* impacted files already collected */
    struct ci_strlist files;       /* impacted files (unsorted; deduped) */
    struct ci_ref    *refbuf;      /* CI_CLOSURE_QUERY_BATCH rows */
    struct ci_symbol *symbuf;      /* CI_CLOSURE_QUERY_BATCH rows */
    char            (*incbuf)[256];/* CI_CLOSURE_QUERY_BATCH include rows (fwd) */
};

static void ci_closure_ctx_free(struct ci_closure_ctx *c)
{
    ci_strset_free(&c->seen_syms);
    ci_strset_free(&c->seen_sites);
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
    if (c->files.len >= CI_IMPACT_CLOSURE_MAX_FILES) {
        *hit_cap = true;
        return true;
    }
    return ci_strlist_push(&c->files, path);
}

/* ── linkage identity ──────────────────────────────────────────────────
 * A frontier key is "name" for a symbol walked by name (external linkage, or
 * anything whose linkage the index cannot prove file-local), and
 * "name@path" for a static function whose defining file is the .c `path`.
 * '@' never occurs in a C identifier, so the first '@' splits a key. */
#define CI_CLOSURE_KEY_MAX 400

static bool ci_path_is_c(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return n > 2 && strcmp(path + n - 2, ".c") == 0;
}

/* A header-defined static (`static inline` in a .h) is defined in EVERY
 * includer, so its callers live in files other than its own: it stays on the
 * name walk. Only a static whose own file is a .c translation unit is keyed
 * file-local. */
static bool ci_closure_key(const char *name, char kind, const char *def_path,
                           const char *decl_path, char key[CI_CLOSURE_KEY_MAX])
{
    const char *path = NULL;
    if (kind == 't')
        path = (def_path && def_path[0]) ? def_path : decl_path;
    int n = (path && ci_path_is_c(path))
        ? snprintf(key, CI_CLOSURE_KEY_MAX, "%s@%s", name, path)
        : snprintf(key, CI_CLOSURE_KEY_MAX, "%s", name);
    if (n < 0 || (size_t)n >= CI_CLOSURE_KEY_MAX)
        LOG_FAIL("codeindex", "closure key overflow for %s", name);
    return true;
}

/* Queue `key` unless it was already visited. */
static bool ci_closure_queue(struct ci_closure_ctx *c, const char *key,
                             struct ci_strlist *frontier, bool *truncated)
{
    if (c->seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
        *truncated = true;
        return true;
    }
    bool added = false;
    if (!ci_strset_add(&c->seen_syms, key, &added))
        return false;
    return !added || ci_strlist_push(frontier, key);
}

static bool ci_closure_queue_symbol(struct ci_closure_ctx *c,
                                    const struct ci_symbol *sym,
                                    struct ci_strlist *frontier,
                                    bool *truncated)
{
    char key[CI_CLOSURE_KEY_MAX];
    return ci_closure_key(sym->name, sym->kind, sym->def_path, sym->decl_path,
                          key) &&
           ci_closure_queue(c, key, frontier, truncated);
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
        if (!ci_closure_queue_symbol(c, &c->symbuf[i], frontier, truncated))
            return false;
    }
    return true;
}

/* Queue the function a reference sits in. Its identity comes from the one row
 * that defines `caller` in `file`; a caller the index cannot resolve to a
 * static definition there is walked by name. */
static bool ci_closure_queue_caller(struct ci_closure_ctx *c,
                                    struct codeindex *ci, const char *caller,
                                    const char *file, struct ci_strlist *next,
                                    bool *truncated)
{
    char site[CI_CLOSURE_KEY_MAX];
    int n = snprintf(site, sizeof(site), "%s@%s", caller, file);
    if (n < 0 || (size_t)n >= sizeof(site))
        LOG_FAIL("codeindex", "closure site overflow for %s", caller);
    bool added = false;
    if (!ci_strset_add(&c->seen_sites, site, &added))
        return false;
    if (!added)
        return true;  /* this (caller, file) pair was already resolved */

    struct ci_symbol s;
    bool found = false;
    if (!ci_store_symbol_by_name_path(ci->store, caller, file, &s, &found))
        LOG_FAIL("codeindex", "caller lookup failed for %s in %s", caller,
                 file);
    char key[CI_CLOSURE_KEY_MAX];
    if (!ci_closure_key(caller, found ? s.kind : 'T', file, "", key))
        return false;
    return ci_closure_queue(c, key, next, truncated);
}

/* Does `file` define its own function named `name`? A call in such a file
 * binds to that definition, never to another TU's static of the same name. */
static bool ci_file_defines_function(struct codeindex *ci, const char *name,
                                     const char *file, bool *defines)
{
    struct ci_symbol s;
    bool found = false;
    *defines = false;
    if (!ci_store_symbol_by_name_path(ci->store, name, file, &s, &found))
        LOG_FAIL("codeindex", "definition lookup failed for %s in %s", name,
                 file);
    *defines = found && (s.kind == 't' || s.kind == 'T');
    return true;
}

/* The static `name` defined in `path`: which of its name's refs can bind to
 * it? One per expansion; the per-file answer and the include answer are
 * cached because refs arrive ordered by file. */
struct ci_static_scope {
    const char *name;
    const char *path;
    char        last_file[256];
    bool        last_keep;
    bool        includers_loaded;
    bool        includers_unbounded;
    int         n_includers;
};

static bool ci_static_includer(struct ci_closure_ctx *c, struct codeindex *ci,
                               struct ci_static_scope *scope,
                               const char *file, bool *includes)
{
    *includes = false;
    if (!scope->includers_loaded) {
        enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int n = codeindex_reverse_includes(ci, scope->path, c->incbuf,
                                           CI_CLOSURE_QUERY_BATCH, &dim);
        if (n < 0)
            LOG_FAIL("codeindex", "reverse includes failed for %s",
                     scope->path);
        scope->includers_loaded = true;
        scope->n_includers = n;
        /* A clipped include answer cannot prove a file is NOT an includer. An
         * absent graph can: the definition check alone is sound without it. */
        scope->includers_unbounded = dim == CODEINDEX_INCLUDE_DIM_TRUNCATED;
    }
    if (scope->includers_unbounded) {
        *includes = true;
        return true;
    }
    for (int i = 0; i < scope->n_includers; i++)
        if (strcmp(c->incbuf[i], file) == 0) {
            *includes = true;
            break;
        }
    return true;
}

/* Can a call to `name` in `file` bind to the static `name` of scope->path?
 * Only when `file`'s translation unit contains scope->path. The compiler's
 * depfile for `file`, when the index holds one, lists that TU's every input,
 * so membership is exact. Without one, the only provable "no" is a file that
 * defines its own function of that name: its calls bind to that definition —
 * unless the include graph shows it also reads scope->path (an #ifdef twin). */
static bool ci_static_ref_binds(struct ci_closure_ctx *c, struct codeindex *ci,
                                struct ci_static_scope *scope,
                                const char *file, bool *keep)
{
    *keep = true;
    /* The static's own file, and every non-.c file (a header or .def
     * fragment is compiled inside some includer's TU), may bind to it. */
    if (strcmp(file, scope->path) == 0 || !ci_path_is_c(file))
        return true;
    if (strcmp(file, scope->last_file) == 0) {
        *keep = scope->last_keep;
        return true;
    }
    char probe[1][256];
    int recorded = codeindex_includes_of_file(ci, file, probe, 1);
    if (recorded < 0)
        LOG_FAIL("codeindex", "includes_of_file failed for %s", file);
    bool defines = false;
    if (recorded == 0 &&
        !ci_file_defines_function(ci, scope->name, file, &defines))
        return false;
    if ((recorded > 0 || defines) &&
        !ci_static_includer(c, ci, scope, file, keep))
        return false;
    snprintf(scope->last_file, sizeof(scope->last_file), "%s", file);
    scope->last_keep = *keep;
    return true;
}

/* Expand one symbol: pull its callers, record their files, queue new callers. */
static bool ci_closure_expand_symbol(struct ci_closure_ctx *c,
                                     struct codeindex *ci, const char *key,
                                     struct ci_strlist *next, bool *truncated,
                                     codeindex_impact_terminal_fn terminal,
                                     void *terminal_user)
{
    char name[CI_CLOSURE_KEY_MAX];
    snprintf(name, sizeof(name), "%s", key);
    char *at = strchr(name, '@');
    struct ci_static_scope scope = {0};
    if (at) {
        *at = '\0';
        scope.name = name;
        scope.path = at + 1;
    }
    /* The name's full ref set, filtered below for a static: the fan-out bound
     * therefore fires exactly where the name-only walk's did. */
    int nc = codeindex_callers(ci, name, c->refbuf, CI_CLOSURE_QUERY_BATCH);
    if (nc < 0)
        LOG_FAIL("codeindex", "callers failed for %s", name);
    if (nc == CI_CLOSURE_QUERY_BATCH)
        *truncated = true;  /* more callers than one batch — closure incomplete */

    for (int i = 0; i < nc; i++) {
        const struct ci_ref *ref = &c->refbuf[i];
        bool keep = true;
        if (scope.path && !ci_static_ref_binds(c, ci, &scope, ref->ref_file,
                                               &keep))
            return false;
        if (!keep)
            continue;  /* a same-named function of another TU */
        if (!ci_closure_add_file(c, ref->ref_file, truncated))
            return false;
        if (terminal && terminal(ref->ref_file, terminal_user))
            continue;
        if (!ref->enclosing[0])
            continue;  /* file-scope reference: file recorded, no symbol to walk */
        if (c->seen_syms.len >= CI_CLOSURE_MAX_SYMS) {
            *truncated = true;
            continue;
        }
        if (!ci_closure_queue_caller(c, ci, ref->enclosing, ref->ref_file,
                                     next, truncated))
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
    if (!ci_closure_queue_symbol(seed->closure, sym, seed->frontier,
                                 seed->truncated))
        seed->failed = true;
}

static void ci_overlay_ignore_ref(const char *callee, const char *ref_file,
                                  int ref_line, const char *enclosing,
                                  void *user)
{
    (void)callee; (void)ref_file; (void)ref_line; (void)enclosing; (void)user;
}

static bool ci_closure_seed_all(
    struct ci_closure_ctx *c, struct codeindex *ci, const char *overlay_root,
    const char (*changed_files)[256], int n_changed,
    struct ci_strlist *frontier, bool *truncated, bool stop_at_truncation)
{
    for (int i = 0; i < n_changed; i++) {
        if (stop_at_truncation && *truncated)
            break;
        if (!ci_closure_seed_file(c, ci, changed_files[i], frontier,
                                  truncated))
            return false;
        if (overlay_root) {
            struct ci_overlay_seed seed = {
                .closure = c,
                .frontier = frontier,
                .truncated = truncated,
            };
            uint8_t current_sha3[32];
            if (!ci_scan_file(overlay_root, changed_files[i], ci_overlay_sym,
                              ci_overlay_ignore_ref, &seed, current_sha3,
                              NULL) || seed.failed)
                return false;
        }
    }
    return true;
}

static int ci_closure_collect_output(struct ci_closure_ctx *c,
                                      char (*out)[256], int cap,
                                      bool *truncated)
{
    ci_strlist_sort(&c->files);
    int n = 0;
    for (size_t i = 0; i < c->files.len && n < cap; i++) {
        memset(out[n], 0, sizeof(out[n]));
        int w = snprintf(out[n], sizeof(out[n]), "%s", c->files.items[i]);
        /* A path longer than the caller's row lands as a SILENTLY DIFFERENT
         * path: the caller then hashes whatever the truncated prefix names, or
         * fails to open it. Either way the set it holds is not the set we
         * computed, so report truncation — testcache turns that into
         * UNCACHEABLE and the group runs. */
        if (w < 0 || (size_t)w >= sizeof(out[n]))
            *truncated = true;
        n++;
    }
    if ((size_t)n < c->files.len)
        *truncated = true;  /* caller's cap could not hold the full set */
    return n;
}

static int impact_closure_impl(
    struct codeindex *ci, const char *overlay_root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated, bool stop_at_truncation)
{
    if (truncated) *truncated = false;
    if (!ci || !ci->store || !changed_files || n_changed < 0 || !out ||
        cap <= 0 || !truncated)
        LOG_ERR("codeindex", "bad args to codeindex_impact_closure");

    int depth = max_depth > 0 ? max_depth : CI_CLOSURE_DEFAULT_DEPTH;

    struct ci_closure_ctx c = {0};
    int rc = -1;
    if (!ci_strset_init(&c.seen_syms, 1024) ||
        !ci_strset_init(&c.seen_sites, 1024) ||
        !ci_strset_init(&c.seen_files, 1024)) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "closure set init failed");
    }
    c.refbuf = zcl_malloc(sizeof(*c.refbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_closure_refbuf");
    c.symbuf = zcl_malloc(sizeof(*c.symbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_closure_symbuf");
    c.incbuf = zcl_malloc(sizeof(*c.incbuf) * CI_CLOSURE_QUERY_BATCH,
                          "ci_closure_incbuf");
    if (!c.refbuf || !c.symbuf || !c.incbuf) {
        ci_closure_ctx_free(&c);
        LOG_ERR("codeindex", "closure batch alloc failed");
    }

    struct ci_strlist frontier = {0};
    struct ci_strlist next = {0};

    if (!ci_closure_seed_all(&c, ci, overlay_root, changed_files, n_changed,
                             &frontier, truncated, stop_at_truncation))
        goto done;

    for (int d = 0; d < depth && frontier.len > 0; d++) {
        if (stop_at_truncation && *truncated)
            break;
        /* Deterministic per-level expansion order. */
        qsort(frontier.items, frontier.len, sizeof(*frontier.items),
              ci_str_cmp);
        for (size_t i = 0; i < frontier.len; i++) {
            if (!ci_closure_expand_symbol(&c, ci, frontier.items[i], &next,
                                          truncated, terminal, terminal_user))
                goto done;
            /* The caller has already decided a bounded closure means "run
             * everything", so paging the rest of a huge frontier cannot
             * change its answer — only its wall clock. Stop here. */
            if (stop_at_truncation && *truncated)
                break;
        }
        ci_strlist_free(&frontier);
        frontier = next;
        memset(&next, 0, sizeof(next));
    }

    /* Deterministic, unique output. */
    rc = ci_closure_collect_output(&c, out, cap, truncated);

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
                               NULL, NULL,
                               out, cap, truncated, false);
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
                               NULL, NULL,
                               out, cap, truncated, false);
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
                               terminal, terminal_user,
                               out, cap, truncated, false);
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
                               terminal, terminal_user,
                               out, cap, truncated, false);
}

int codeindex_impact_closure_bounded(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated, bool stop_at_truncation)
{
    if ((root && !root[0]) || !terminal) {
        if (truncated) *truncated = false;
        LOG_ERR("codeindex", "bounded closure input is empty");
    }
    return impact_closure_impl(ci, root, changed_files, n_changed, max_depth,
                               terminal, terminal_user,
                               out, cap, truncated, stop_at_truncation);
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
static enum codeindex_include_dim empty_include_dim(bool refused)
{
    return refused ? CODEINDEX_INCLUDE_DIM_TRUNCATED
                   : CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
}

static enum codeindex_include_dim filled_include_dim(bool refused)
{
    return refused ? CODEINDEX_INCLUDE_DIM_TRUNCATED
                   : CODEINDEX_INCLUDE_DIM_COMPLETE;
}

/* NULL when narrow include answers are trusted. Otherwise why they are not:
 * a label when the stored bit itself cannot be read, or "" when the bit is set
 * and the stored cause names the depfile rule behind it. */
static const char *include_narrow_refusal(const struct codeindex *ci)
{
    char bit[4];
    size_t len = 0;
    bool found = false;
    if (!ci || !ci->store)
        return "no_index_store";
    if (!ci_store_meta_get(ci->store, "include_narrow_unsafe", bit, sizeof bit,
                           &len, &found))
        return "include_meta_unreadable";
    if (!found || len != 1)
        return "include_meta_missing";
    return bit[0] == '1' ? "" : NULL;
}

static bool include_narrow_refused(const struct codeindex *ci)
{
    return include_narrow_refusal(ci) != NULL;
}

const char *codeindex_include_dim_label(enum codeindex_include_dim dim)
{
    switch (dim) {
    case CODEINDEX_INCLUDE_DIM_COMPLETE:    return "complete";
    case CODEINDEX_INCLUDE_DIM_TRUNCATED:   return "closure-truncated";
    case CODEINDEX_INCLUDE_DIM_UNAVAILABLE: return "no-include-graph";
    }
    return "unknown";
}

/* A set bit with no stored cause (or an unreadable one) still refuses; it
 * just cannot say why. */
static const char *include_stored_cause(const struct codeindex *ci,
                                        char *buf, size_t cap)
{
    size_t len = 0;
    bool found = false;
    if (!ci_store_meta_get(ci->store, "include_narrow_cause", buf, cap - 1,
                           &len, &found) ||
        !found || len == 0 || len >= cap)
        return "unrecorded";
    buf[len] = '\0';
    return buf;
}

bool codeindex_include_unsafe_cause(struct codeindex *ci, char *out,
                                    size_t cap)
{
    if (out && cap) out[0] = '\0';
    const char *refusal = include_narrow_refusal(ci);
    if (!refusal)
        return false;
    char stored[CODEINDEX_INCLUDE_UNSAFE_CAUSE_MAX];
    if (!refusal[0])
        refusal = include_stored_cause(ci, stored, sizeof stored);
    if (out && cap)
        (void)snprintf(out, cap, "%s", refusal);
    return true;
}

/* A deleted include input can disappear from an inactive quoted include and
 * from a fresh depfile graph at the same time. Its old readers are unknown. */
static bool include_input_missing(const struct codeindex *ci, const char *path)
{
    char full[CI_PATH_MAX];
    int n = snprintf(full, sizeof full, "%s/%s", ci->root, path);
    if (n < 0 || (size_t)n >= sizeof full)
        return true;
    return platform_file_shape_read(full) != PLATFORM_FILE_SHAPE_REGULAR;
}

static bool include_query_narrow_refused(const struct codeindex *ci,
                                         const char *path)
{
    return include_narrow_refused(ci) || include_input_missing(ci, path);
}

bool codeindex_include_query_unsafe_cause(struct codeindex *ci,
                                          const char *path, char *out,
                                          size_t cap)
{
    if (codeindex_include_unsafe_cause(ci, out, cap))
        return true;
    if (!ci || !path || !path[0] || !include_input_missing(ci, path))
        return false;
    if (out && cap)
        (void)snprintf(out, cap, "query_input_regular_file_unverified %s",
                       path);
    return true;
}

int codeindex_reverse_includes(struct codeindex *ci, const char *path,
                               char (*out)[256], int cap,
                               enum codeindex_include_dim *dim)
{
    if (dim) *dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    if (!ci || !ci->store || !path || !path[0] || !out || cap <= 0 ||
        cap > CI_IMPACT_CLOSURE_MAX_FILES || !dim)
        LOG_ERR("codeindex", "bad args to codeindex_reverse_includes");

    int64_t edges = ci_store_include_edge_count(ci->store);
    bool narrow_refused = include_query_narrow_refused(ci, path);
    if (edges < 0)
        LOG_ERR("codeindex", "include edge count failed");
    if (edges == 0) {
        /* No depfiles were on disk when this index was built. Every reverse
         * question is UNANSWERED, not answered with zero. A depfile that
         * existed but could not be trusted is closure-truncated instead. */
        *dim = empty_include_dim(narrow_refused);
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
    *dim = filled_include_dim(narrow_refused);
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

/* Record one definition file and that file's in-tree include closure. */
static bool ci_fwd_record_file(struct ci_closure_ctx *c, struct codeindex *ci,
                               const char *path, bool *hit_cap)
{
    if (!ci_closure_add_file(c, path, hit_cap))
        return false;

    int ni = codeindex_includes_of_file(ci, path, c->incbuf,
                                        CI_CLOSURE_QUERY_BATCH);
    if (ni < 0)
        LOG_FAIL("codeindex", "includes_of_file failed for %s", path);
    if (ni == CI_CLOSURE_QUERY_BATCH)
        *hit_cap = true;  /* more includes than one batch — closure incomplete */
    for (int i = 0; i < ni; i++) {
        if (!ci_closure_add_file(c, c->incbuf[i], hit_cap))
            return false;
    }
    return true;
}

/* Record EVERY definition row of `sym`, any kind, so a name defined in several
 * files (a static or macro in one, the real function in another) never loses
 * the file the call actually binds to: keeping an extra file only costs a
 * re-run, dropping a true dependency serves a stale PASS. A symbol with no
 * in-tree definition (a libc/external call) has no file to hash and is
 * silently skipped. *hit_cap is raised through ci_closure_add_file, an include
 * fan-out overflow, or a definition list that fills one batch. */
static bool ci_fwd_record_symbol_file(struct ci_closure_ctx *c,
                                      struct codeindex *ci, const char *sym,
                                      bool *hit_cap)
{
    if (!c->symbuf) {
        c->symbuf = zcl_malloc(sizeof(*c->symbuf) * CI_CLOSURE_QUERY_BATCH,
                               "ci_fwd_symbuf");
        if (!c->symbuf)
            LOG_FAIL("codeindex", "forward closure symbuf alloc failed");
    }
    int nd = ci_store_defs_by_name(ci->store, sym, c->symbuf,
                                   CI_CLOSURE_QUERY_BATCH);
    if (nd < 0)
        LOG_FAIL("codeindex", "definition rows failed for %s", sym);
    if (nd == CI_CLOSURE_QUERY_BATCH)
        *hit_cap = true;  /* more definitions than one batch */
    for (int i = 0; i < nd; i++) {
        const char *path = c->symbuf[i].def_path;
        if (!path[0] || (i > 0 && !strcmp(path, c->symbuf[i - 1].def_path)))
            continue;  /* undeclared-here, or this file was just recorded */
        if (!ci_fwd_record_file(c, ci, path, hit_cap))
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

    ci_strlist_sort(&c.files);
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
