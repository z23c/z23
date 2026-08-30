/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * territory_scorecard — compose one module's inventory out of registries that
 * already exist. Nothing here is stored; everything is a query.
 *
 *   what it owns      code index file rows for the group + stat() for size
 *   what it is for    the group row's purpose (ci_group_purpose)
 *   what proves it    the shared-rule router (ROUTED) and the test entry-point
 *                     call closure (REACHED) — two different facts, side by
 *                     side, never summed
 *   what it depends   compiler depfile include edges, forward and reverse,
 *   on                attributed to the owning territory by asking the index
 *                     which group each file belongs to
 *   where it is weak  the unreached public symbols and the unrouted files
 *
 * The classification of one public symbol is spelled out in full because a
 * scorecard that cannot be checked is a scorecard that will be believed when
 * it is wrong:
 *
 *   in the closure                     -> REACHED
 *   no reference anywhere in the tree  -> UNREACHED (dead public surface)
 *   any reference at FILE SCOPE        -> UNKNOWN (a dispatch-table entry;
 *                                        indirect calls are not call edges)
 *   references only from functions the
 *   closure does not contain           -> UNREACHED
 *   no closure available               -> UNKNOWN
 */

#include "territory/territory.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint64_t ts_now_us(void)
{
    int64_t ns = clock_now_monotonic_ns();
    return ns > 0 ? (uint64_t)ns / 1000ull : 0;
}

enum {
    TS_GROUPS_CAP     = 1024,   /* index group rows */
    TS_SYMS_PER_FILE  = 1024,   /* symbols read from one header */
    TS_REFS_PROBE     = 64,     /* refs sampled per public symbol */
    TS_INC_PER_FILE   = 2048,   /* forward include edges read per .c */
    TS_REVDEP_CAP     = 512,    /* reverse include dependents read per header */
    TS_REVDEP_BUDGET  = 8000,   /* total reverse-dependent rows examined */
    TS_PATHMEMO_SLOTS = 4096,   /* path -> owning group memo (power of two) */
    TS_HEADER_PROBE   = 65536,  /* header bytes read for the extern "C" probe */
};

/* ── path -> owning territory memo ──────────────────────────────────────
 *
 * The authority on which territory owns a path is the code index's own file
 * row, not a second copy of the path taxonomy in this file. That is one query
 * per path, and a hub module's dependency fan-out repeats the same few
 * hundred paths thousands of times, so the answers are memoized for the life
 * of one scorecard. */
struct ts_pathentry {
    char path[TERRITORY_PATH_MAX];
    char group[TERRITORY_GROUP_MAX];
};

struct ts_pathmemo {
    uint32_t *slot;               /* entry index + 1; 0 means empty */
    size_t    slots;              /* power of two */
    struct ts_pathentry *entry;
    size_t    len, cap;
    uint64_t  queries;            /* index lookups actually performed */
};

static uint64_t ts_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ull; }
    return h;
}

static bool ts_pathmemo_init(struct ts_pathmemo *m)
{
    m->slots = TS_PATHMEMO_SLOTS;
    m->cap = TS_PATHMEMO_SLOTS;
    m->slot = zcl_calloc(m->slots, sizeof(*m->slot), "ts_pathmemo_slots");
    m->entry = zcl_malloc(sizeof(*m->entry) * m->cap, "ts_pathmemo_entries");
    if (!m->slot || !m->entry) {
        free(m->slot); free(m->entry);
        memset(m, 0, sizeof(*m));
        LOG_FAIL("territory", "path memo (%zu slots)", (size_t)TS_PATHMEMO_SLOTS);
    }
    return true;
}

static void ts_pathmemo_free(struct ts_pathmemo *m)
{
    free(m->slot);
    free(m->entry);
    memset(m, 0, sizeof(*m));
}

/* The memo grows; it never fills. A fixed table that silently stopped caching
 * would degrade every later lookup to a full linear probe, which is how a
 * "fast" query turns into a slow one on exactly the hub modules that matter
 * most. */
static bool ts_pathmemo_grow(struct ts_pathmemo *m)
{
    size_t slots = m->slots * 2;
    size_t cap = m->cap * 2;
    uint32_t *slot = zcl_calloc(slots, sizeof(*slot), "ts_pathmemo_reslot");
    struct ts_pathentry *entry =
        zcl_realloc(m->entry, sizeof(*entry) * cap, "ts_pathmemo_regrow");
    if (!slot || !entry) {
        free(slot);
        if (entry) m->entry = entry;
        LOG_FAIL("territory", "path memo growth to %zu", slots);
    }
    m->entry = entry;
    m->cap = cap;
    for (size_t i = 0; i < m->slots; i++) {
        if (!m->slot[i]) continue;
        size_t j = (size_t)ts_hash(m->entry[m->slot[i] - 1].path) & (slots - 1);
        while (slot[j]) j = (j + 1) & (slots - 1);
        slot[j] = m->slot[i];
    }
    free(m->slot);
    m->slot = slot;
    m->slots = slots;
    return true;
}

/* Which territory owns `path`. The code index's own file row is the
 * authority; this file keeps no second copy of the path taxonomy. Writes ""
 * when the index does not know the file. Returns false only when the memo
 * could not grow, which the caller reports as truncation rather than dropping
 * the edge silently. */
static bool ts_group_of(struct ts_pathmemo *m, struct codeindex *ci,
                        const char *path, char out[TERRITORY_GROUP_MAX])
{
    out[0] = '\0';
    if (m->len * 10 >= m->slots * 7 && !ts_pathmemo_grow(m))
        return false;
    size_t i = (size_t)ts_hash(path) & (m->slots - 1);
    while (m->slot[i]) {
        struct ts_pathentry *e = &m->entry[m->slot[i] - 1];
        if (strcmp(e->path, path) == 0) {
            snprintf(out, TERRITORY_GROUP_MAX, "%s", e->group);
            return true;
        }
        i = (i + 1) & (m->slots - 1);
    }
    struct ci_file f;
    bool found = false;
    (void)codeindex_file(ci, path, &f, &found);
    m->queries++;
    struct ts_pathentry *e = &m->entry[m->len];
    snprintf(e->path, sizeof(e->path), "%s", path);
    snprintf(e->group, sizeof(e->group), "%s", found ? f.group : "");
    m->slot[i] = (uint32_t)(++m->len);
    snprintf(out, TERRITORY_GROUP_MAX, "%s", e->group);
    return true;
}

/* ── small tallies ──────────────────────────────────────────────────── */

static void ts_tally_group(struct territory_report *r, const char *name)
{
    for (int i = 0; i < r->group_count; i++)
        if (strcmp(r->groups[i].name, name) == 0) { r->groups[i].files++; return; }
    if (r->group_count >= TERRITORY_MAX_GROUPS) { r->groups_truncated = true; return; }
    snprintf(r->groups[r->group_count].name,
             sizeof(r->groups[r->group_count].name), "%s", name);
    r->groups[r->group_count].files = 1;
    r->group_count++;
}

static void ts_tally_neighbor(struct territory_neighbor *arr, int *count,
                              bool *trunc, const char *name)
{
    for (int i = 0; i < *count; i++)
        if (strcmp(arr[i].name, name) == 0) { arr[i].edges++; return; }
    if (*count >= TERRITORY_MAX_NEIGHBORS) { *trunc = true; return; }
    snprintf(arr[*count].name, sizeof(arr[*count].name), "%s", name);
    arr[*count].edges = 1;
    (*count)++;
}

static int ts_neighbor_cmp(const void *a, const void *b)
{
    const struct territory_neighbor *x = a, *y = b;
    if (x->edges != y->edges) return y->edges - x->edges;
    return strcmp(x->name, y->name);
}

static int ts_group_cmp(const void *a, const void *b)
{
    const struct territory_group_use *x = a, *y = b;
    if (x->files != y->files) return y->files - x->files;
    return strcmp(x->name, y->name);
}

/* A public header of territory `name` is any header under its include/ tree.
 * The include directory is the module's declared export surface — that is
 * what the build puts on the -I path for every other module. */
static bool ts_is_public_header(const char *path)
{
    const char *inc = strstr(path, "/include/");
    if (!inc) return false;
    size_t n = strlen(path);
    return n > 2 && path[n - 2] == '.' && path[n - 1] == 'h';
}

/* Does this header wrap its declarations in an `extern "C"` block? The code
 * index records a function declaration only at file scope, and that block's
 * brace puts every declaration inside it out of reach, so such a header
 * contributes no functions at all. This is a single bounded substring probe
 * over the header's own bytes — not a second scanner — and it exists so the
 * scorecard can COUNT the blind spot instead of quietly reporting a small
 * public surface as if it were the whole one.
 *
 * `buf` is caller-owned and TS_HEADER_PROBE + 1 bytes; the probe keeps no
 * automatic buffer of its own so it stays safe on a small worker stack. */
static bool ts_header_is_extern_c(const char *root, const char *rel, char *buf)
{
    char full[TERRITORY_PATH_MAX + 512];
    int w = snprintf(full, sizeof(full), "%s/%s",
                     (root && root[0]) ? root : ".", rel);
    if (w < 0 || (size_t)w >= sizeof(full)) return false;
    FILE *f = fopen(full, "rb");
    if (!f) return false;
    size_t n = fread(buf, 1, TS_HEADER_PROBE, f);
    fclose(f);
    buf[n] = '\0';
    /* A NUL inside the first block would truncate the search; a C header with
     * an embedded NUL is not a header this probe can speak about. */
    if (n > 0 && memchr(buf, '\0', n) != NULL) return false;
    return strstr(buf, "extern \"C\"") != NULL;
}

static bool ts_is_source(const char *path)
{
    size_t n = strlen(path);
    return n > 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

/* ── the reachability verdict for one public symbol ─────────────────── */

static void ts_classify(struct codeindex *ci,
                        const struct territory_reach_set *rs,
                        struct territory_symbol *out, struct ci_ref *refbuf)
{
    if (!rs) {
        out->verdict = TERRITORY_UNKNOWN;
        out->reason = TERRITORY_REASON_WALK_TRUNCATED;
        out->refs = -1;
        return;
    }
    if (territory_reach_contains(rs, out->name)) {
        out->verdict = TERRITORY_REACHED;
        out->reason = TERRITORY_REASON_IN_CLOSURE;
        out->refs = -1;
        return;
    }
    int n = codeindex_refs(ci, out->name, refbuf, TS_REFS_PROBE);
    if (n < 0) n = 0;
    out->refs = n;
    if (n == 0) {
        out->verdict = TERRITORY_UNREACHED;
        out->reason = TERRITORY_REASON_NO_REFS;
        return;
    }
    for (int i = 0; i < n; i++) {
        if (refbuf[i].enclosing[0] == '\0') {
            /* A reference with no enclosing function is an initializer or an
             * X-macro registry row: the symbol's ADDRESS is taken and called
             * through a pointer later. A source call graph has no edge for
             * that, so the honest answer is that it does not know. */
            out->verdict = TERRITORY_UNKNOWN;
            out->reason = TERRITORY_REASON_FILE_SCOPE_REF;
            return;
        }
    }
    out->verdict = TERRITORY_UNREACHED;
    out->reason = TERRITORY_REASON_COLD_CALLERS;
}

/* ── territory list ─────────────────────────────────────────────────── */

int territory_list(struct codeindex *ci, char (*out)[TERRITORY_NAME_MAX],
                   int cap)
{
    if (!ci || !out || cap <= 0)
        LOG_ERR("territory", "bad args to territory_list");
    struct ci_group *groups =
        zcl_malloc(sizeof(*groups) * TS_GROUPS_CAP, "ts_group_list");
    if (!groups) LOG_ERR("territory", "group buffer");
    int ng = codeindex_groups(ci, groups, TS_GROUPS_CAP);
    if (ng < 0) ng = 0;
    int n = 0;
    for (int i = 0; i < ng && n < cap; i++) {
        /* A "root" group is a container ("lib", "app") unless it also holds
         * files of its own — the repo root does. One rule, no exception list:
         * a territory is a declared non-container group, or any group that
         * directly owns at least one file. */
        if (strcmp(groups[i].kind, "root") == 0 &&
            codeindex_count_files_in_group(ci, groups[i].path, false) <= 0)
            continue;
        snprintf(out[n], TERRITORY_NAME_MAX, "%s", groups[i].path);
        n++;
    }
    free(groups);
    return n;
}

/* ── the scorecard ──────────────────────────────────────────────────── */

void territory_report_free(struct territory_report *r) { free(r); }

struct territory_report *territory_scorecard(
    struct codeindex *ci, const char *root, const char *name,
    const struct territory_reach_set *rs,
    const struct territory_router *router)
{
    if (!ci || !name || !name[0])
        LOG_NULL("territory", "scorecard needs an index and a territory name");

    struct territory_report *r = zcl_calloc(1, sizeof(*r), "territory_report");
    struct ci_group *groups =
        zcl_malloc(sizeof(*groups) * TS_GROUPS_CAP, "ts_groups");
    struct ci_file *files =
        zcl_malloc(sizeof(*files) * (TERRITORY_MAX_FILES + 1), "ts_files");
    struct ci_symbol *syms =
        zcl_malloc(sizeof(*syms) * TS_SYMS_PER_FILE, "ts_syms");
    struct ci_ref *refbuf = zcl_malloc(sizeof(*refbuf) * TS_REFS_PROBE,
                                       "ts_refs");
    char (*incs)[256] = zcl_malloc(sizeof(*incs) * TS_INC_PER_FILE, "ts_incs");
    char (*deps)[256] = zcl_malloc(sizeof(*deps) * TS_REVDEP_CAP, "ts_deps");
    char *probe = zcl_malloc(TS_HEADER_PROBE + 1, "ts_header_probe");
    struct ts_pathmemo memo = {0};
    if (!r || !groups || !files || !syms || !refbuf || !incs || !deps ||
        !probe || !ts_pathmemo_init(&memo)) {
        free(r); free(groups); free(files); free(syms); free(refbuf);
        free(incs); free(deps); free(probe); ts_pathmemo_free(&memo);
        LOG_NULL("territory", "scorecard buffers for %s", name);
    }

    snprintf(r->name, sizeof(r->name), "%s", name);

    int ng = codeindex_groups(ci, groups, TS_GROUPS_CAP);
    if (ng < 0) ng = 0;
    for (int i = 0; i < ng; i++) {
        if (strcmp(groups[i].path, name) != 0) continue;
        r->found = true;
        snprintf(r->kind, sizeof(r->kind), "%s", groups[i].kind);
        snprintf(r->purpose, sizeof(r->purpose), "%s", groups[i].purpose);
        break;
    }

    /* ── what it owns ──────────────────────────────────────────────── */
    int nf = codeindex_files_in_group(ci, name, files, TERRITORY_MAX_FILES + 1);
    if (nf < 0) nf = 0;
    if (nf > TERRITORY_MAX_FILES) { nf = TERRITORY_MAX_FILES; r->files_truncated = true; }
    r->file_count = nf;

    uint64_t phase0 = ts_now_us();
    char abs[TERRITORY_PATH_MAX + 512];
    for (int i = 0; i < nf; i++) {
        struct territory_file *tf = &r->files[i];
        snprintf(tf->path, sizeof(tf->path), "%s", files[i].path);
        tf->bytes = -1;
        int w = snprintf(abs, sizeof(abs), "%s/%s",
                         (root && root[0]) ? root : ".", files[i].path);
        if (w > 0 && (size_t)w < sizeof(abs)) {
            struct stat sb;
            if (stat(abs, &sb) == 0) {
                tf->bytes = (int64_t)sb.st_size;
                r->bytes += tf->bytes;
            }
        }
        if (ts_is_public_header(files[i].path)) r->header_count++;
        else if (ts_is_source(files[i].path)) r->source_count++;

        /* ── what proves it: ROUTED ─────────────────────────────────
         * The routing answer, verbatim from the same shared-rule resolver
         * `code tests` uses. It says which group to RUN, not which code
         * that group executes. */
        char routed[TERRITORY_MAX_GROUPS][TERRITORY_GROUP_MAX];
        size_t nr = 0;
        uint64_t rt0 = ts_now_us();
        if (router && router->route)
            nr = router->route(files[i].path, routed, TERRITORY_MAX_GROUPS,
                               router->user);
        r->routed_us += ts_now_us() - rt0;
        tf->routed = nr > 0;
        if (nr > 0) snprintf(tf->route, sizeof(tf->route), "%s", routed[0]);
        else r->files_unrouted++;
        for (size_t g = 0; g < nr; g++) ts_tally_group(r, routed[g]);
    }
    qsort(r->groups, (size_t)r->group_count, sizeof(*r->groups), ts_group_cmp);
    r->owns_us = ts_now_us() - phase0 - r->routed_us;

    /* ── what proves it: REACHED ───────────────────────────────────── */
    phase0 = ts_now_us();
    for (int i = 0; i < nf; i++) {
        if (!ts_is_public_header(files[i].path)) continue;
        int ns = codeindex_symbols_in_file(ci, files[i].path, syms,
                                           TS_SYMS_PER_FILE);
        if (ns < 0) ns = 0;
        if (ns == TS_SYMS_PER_FILE) r->symbols_truncated = true;
        int funcs_here = 0;
        for (int s = 0; s < ns; s++) {
            switch (syms[s].kind) {
            case 'S': case 'Y': case 'E': r->public_types++; continue;
            case 'M': r->public_macros++; continue;
            case 'T': break;
            default: continue;  /* 'D' data, 't' static: not a public call */
            }
            if (r->public_symbols >= TERRITORY_MAX_SYMBOLS) {
                r->symbols_truncated = true;
                continue;
            }
            struct territory_symbol *ts = &r->symbols[r->public_symbols];
            snprintf(ts->name, sizeof(ts->name), "%s", syms[s].name);
            snprintf(ts->header, sizeof(ts->header), "%s", files[i].path);
            ts->line = syms[s].decl_line;
            ts_classify(ci, rs, ts, refbuf);
            switch (ts->verdict) {
            case TERRITORY_REACHED:   r->reached++;   break;
            case TERRITORY_UNREACHED: r->unreached++; break;
            case TERRITORY_UNKNOWN:   r->unknown++;   break;
            }
            funcs_here++;
            r->public_symbols++;
        }
        /* A header the index attributed no function to is either genuinely
         * function-free (a constants or type header) or opaque to the
         * scanner. Count both, and separate them with the one probe that
         * distinguishes them. */
        if (funcs_here == 0) {
            r->headers_without_functions++;
            if (ts_header_is_extern_c(root, files[i].path, probe))
                r->headers_extern_c++;
        }
    }

    r->symbols_us = ts_now_us() - phase0;

    /* ── what it depends on ────────────────────────────────────────── */
    phase0 = ts_now_us();
    int64_t edges = codeindex_include_edge_count(ci);
    r->deps_available = edges > 0;
    if (r->deps_available) {
        for (int i = 0; i < nf; i++) {
            if (!codeindex_path_is_translation_unit(files[i].path)) continue;
            int ni = codeindex_includes_of_file(ci, files[i].path, incs,
                                                TS_INC_PER_FILE);
            if (ni < 0) ni = 0;
            if (ni == TS_INC_PER_FILE) r->deps_truncated = true;
            for (int d = 0; d < ni; d++) {
                char g[TERRITORY_GROUP_MAX];
                if (!ts_group_of(&memo, ci, incs[d], g)) {
                    r->deps_truncated = true;
                    break;
                }
                if (!g[0] || strcmp(g, name) == 0) continue;
                ts_tally_neighbor(r->deps_out, &r->deps_out_count,
                                  &r->deps_truncated, g);
            }
        }
        int budget = TS_REVDEP_BUDGET;
        for (int i = 0; i < nf && budget > 0; i++) {
            if (!ts_is_public_header(files[i].path)) continue;
            enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
            int nd = codeindex_reverse_includes(ci, files[i].path, deps,
                                                TS_REVDEP_CAP, &dim);
            if (nd < 0) nd = 0;
            if (dim != CODEINDEX_INCLUDE_DIM_COMPLETE) r->deps_truncated = true;
            for (int d = 0; d < nd && budget > 0; d++, budget--) {
                char g[TERRITORY_GROUP_MAX];
                if (!ts_group_of(&memo, ci, deps[d], g)) {
                    r->deps_truncated = true;
                    break;
                }
                if (!g[0] || strcmp(g, name) == 0) continue;
                ts_tally_neighbor(r->deps_in, &r->deps_in_count,
                                  &r->deps_truncated, g);
            }
            if (budget <= 0) r->deps_truncated = true;
        }
        qsort(r->deps_out, (size_t)r->deps_out_count, sizeof(*r->deps_out),
              ts_neighbor_cmp);
        qsort(r->deps_in, (size_t)r->deps_in_count, sizeof(*r->deps_in),
              ts_neighbor_cmp);
    }

    r->deps_us = ts_now_us() - phase0;
    r->index_lookups = memo.queries;

    ts_pathmemo_free(&memo);
    free(groups); free(files); free(syms); free(refbuf); free(incs);
    free(deps); free(probe);
    return r;
}
