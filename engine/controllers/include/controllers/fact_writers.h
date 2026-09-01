/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fact_writers — the writer census: for every durable NAMED SLOT in the node,
 * enumerate every place that writes it, and name the slots with more than one.
 *
 * ── Why ──
 * The recurring defect in this codebase is not duplicated text (measured: 0.65%
 * of production lines). It is one FACT with two independently writable homes
 * that then drift. A clone detector cannot see that and neither can a diff. The
 * doctrine's cure is "delete a copy, never add a reconciliation guard", but
 * until now nothing could tell you which facts have a second copy. This does.
 *
 * ── Ground truth ──
 * Nothing is authored. The slot names come from the tree's own key literals and
 * key macros; the writers come from call sites of the store's own declared
 * write API (via cognition/modules/codeindex refs) plus raw SQL mutations of the store's own
 * table. The only checked-in artifact is
 * controllers/fact_store_writers.def — a manifest of derivations, not of facts.
 * Re-running the census on a changed tree changes the answer; there is no copy
 * to keep fresh.
 *
 * ── What this cannot see (state it, do not paper over it) ──
 *  1. Slots not addressed by a string: a block header keyed by hash, a coin
 *     keyed by outpoint. Their writers cannot be attributed without authoring
 *     a taxonomy of "what counts as a header write", which would be a fact.
 *  2. A write whose key argument is a variable, a struct field, or a bound `?`
 *     SQL parameter. Counted in `sites_unresolved` per store and reported, so
 *     the blind spot has a number instead of being silently dropped.
 *  3. A write reached through a wrapper in ANOTHER file. A file-local wrapper is
 *     recovered (the function enclosing a bound-key mutation of a store table is
 *     that file's own write entry point, and its same-file call sites are
 *     attributed); a wrapper called across a translation unit is not.
 *  4. Everything under lib/test is excluded by construction: a fixture writing
 *     a slot is not a second production writer.
 */

#ifndef ZCL_CONTROLLERS_FACT_WRITERS_H
#define ZCL_CONTROLLERS_FACT_WRITERS_H

#include <stdbool.h>
#include <stddef.h>

struct codeindex;

enum {
    FACT_STORE_NAME_MAX  = 32,
    FACT_KEY_MAX         = 96,
    FACT_PATH_MAX        = 160,
    FACT_VIA_MAX         = 48,
    FACT_SITES_PER_FACT  = 12,   /* rendered writers per fact; overflow flagged */
    FACT_ROWS_MAX        = 768,  /* distinct (store,key) slots held */
    FACT_STORES_MAX      = 8,
};

/* How the write reaches the slot. */
enum fact_write_via {
    FACT_VIA_API = 0,   /* a declared write entry point of the store */
    FACT_VIA_RAW_SQL,   /* a mutation statement naming the store's table */
};

/* One writer of one slot. `via_name` is the API function, or the SQL verb. */
struct fact_writer_site {
    char path[FACT_PATH_MAX];
    int  line;
    char via_name[FACT_VIA_MAX];
    enum fact_write_via via;
};

/* One durable named slot and its writers. `writer_files` is the census's
 * headline: distinct FILES that write this slot. Two sites in one file are one
 * writer surface; two files are two independently writable homes. */
struct fact_row {
    char store[FACT_STORE_NAME_MAX];
    char key[FACT_KEY_MAX];
    int  writer_files;
    int  writer_sites;
    int  n_sites;                                   /* sites[] filled */
    bool sites_truncated;
    struct fact_writer_site sites[FACT_SITES_PER_FACT];
};

/* Per-store honesty counters. */
struct fact_store_stat {
    char store[FACT_STORE_NAME_MAX];
    int  facts;
    int  facts_multi_writer;
    int  sites_resolved;
    int  sites_unresolved;   /* write found, key not a literal — blind spot #2 */
};

struct fact_writers_report {
    int files_scanned;
    int facts_total;
    int facts_multi_writer;
    int sites_total;
    int sites_unresolved;
    int rows_dropped;        /* slots beyond FACT_ROWS_MAX */
    int n_rows;
    int n_stores;
    struct fact_store_stat stores[FACT_STORES_MAX];
    struct fact_row rows[FACT_ROWS_MAX];   /* sorted: writer_files desc, then
                                            * store, then key — deterministic */
};

/* Run the census over the checkout at `root`, using `ci` for call-site lookup.
 * Heap-allocated (the report is ~1 MB); free with fact_writers_report_free.
 * NULL on hard failure (context logged). Deterministic for a given tree. */
struct fact_writers_report *fact_writers_analyze(const char *root,
                                                 struct codeindex *ci);
void fact_writers_report_free(struct fact_writers_report *report);

/* Lookup one slot in a computed report. NULL when absent. `store` may be NULL
 * to match the first (highest writer count) store carrying `key`. */
const struct fact_row *fact_writers_find(const struct fact_writers_report *r,
                                         const char *store, const char *key);

/* How many FACT_WRITE_API rows the manifest carries. */
size_t fact_writers_api_row_count(void);
/* How many FACT_STORE rows the manifest carries. */
size_t fact_writers_store_row_count(void);

/* COVERAGE, the other direction: keyed-write declarations present in a
 * FACT_STORE row's api_headers that no FACT_WRITE_API row claims. A canonical
 * registry no row claims must fail, so test_fact_writers asserts this is 0.
 * Fills up to `cap` "<store> <fn>" strings; returns the count, -1 on error. */
int fact_writers_unclaimed_apis(const char *root, char (*out)[FACT_KEY_MAX],
                                int cap);

#endif /* ZCL_CONTROLLERS_FACT_WRITERS_H */
