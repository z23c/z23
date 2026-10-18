/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_build — the rebuild + staleness surface for the codeindex store.
 *
 * The build is a DETERMINISTIC full recompute: enumerate the source set in a
 * fixed sorted order, scan each file for symbols/refs, fold in include edges
 * from build depfiles, write the group hierarchy, all into a fresh unique
 * same-directory staging database, then atomically rename it over
 * <root>/.codeindex/index.kv and
 * stamp exact content roots plus metadata cache keys used to detect a changed
 * tree without rereading every byte on each warm open. "Recompute, never
 * repair."
 */

#ifndef ZCL_CODEINDEX_BUILD_H
#define ZCL_CODEINDEX_BUILD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct codeindex;

/* Fully rebuild the derived store from the source tree. Builds into a temp DB
 * and renames it into place, so a partial build never corrupts the live store.
 * Reopens the handle's store on success. Returns false on any hard error. */
bool codeindex_rebuild(struct codeindex *ci);

/* Compute whether the on-disk store is stale w.r.t. the current tree. Exact
 * roots are sealed at rebuild; warm checks compare path/inode/size/mtime/ctime
 * cache keys so a same-size edit with restored mtime still invalidates without
 * making every query O(total source bytes). Returns false on a hard error.
 * The stale output is optional; when supplied, it is true on refusal. */
bool codeindex_is_stale(struct codeindex *ci, bool *stale);


#ifdef ZCL_TESTING
/* Deterministic process-death boundaries for the crash-publication proof.
 * Test-only: production builds expose no fault-injection surface. */
enum codeindex_test_crash_point {
    CODEINDEX_TEST_CRASH_NONE = 0,
    CODEINDEX_TEST_CRASH_BEFORE_RENAME = 1,
    CODEINDEX_TEST_CRASH_AFTER_RENAME = 2,
};
void codeindex_test_set_crash_point(enum codeindex_test_crash_point point);

enum codeindex_test_stage_tamper {
    CODEINDEX_TEST_STAGE_TAMPER_NONE = 0,
    CODEINDEX_TEST_STAGE_TAMPER_SYMLINK = 1,
    CODEINDEX_TEST_STAGE_TAMPER_HARDLINK = 2,
};
/* Replace the staging name after its private inode is opened. The build must
 * reject publication without writing through the substituted name. */
void codeindex_test_set_stage_tamper(
    enum codeindex_test_stage_tamper tamper, const char *victim_path);

/* Remove the validated lock directory once, immediately before lock-file
 * creation, proving the opener reacquires a live directory capability. */
void codeindex_test_remove_lock_directory_once(void);

/* Warm-open proof: an unchanged metadata stamp must reuse the exact roots
 * sealed by the published generation without rereading source/depfile bytes. */
void codeindex_test_reset_exact_bytes_read(void);
uint64_t codeindex_test_exact_bytes_read(void);

/* Change-watched freshness memo proof: how many whole-tree freshness walks
 * codeindex_is_stale has run in this process, and a switch that makes arming
 * the change watch fail so the memo must fall back to walking every open. */
uint64_t codeindex_test_freshness_walks(void);
void codeindex_test_force_watch_failure(bool fail);
/* Test seams: a callback run after the verifying walk and before the memo is
 * sealed (mutate a depfile there), and a smaller depfile-key cap (0: default). */
void codeindex_test_set_bracket_hook(void (*hook)(const char *root));
void codeindex_test_set_dep_key_cap(size_t cap);
#endif

/* ── Canonical group taxonomy (mirrors the Makefile / shape layout) ──
 * These arrays are the SINGLE in-code mirror of the Makefile's LIB_MODULES
 * and the eight app/ shape folders. A parity test asserts they match. */
const char *const *ci_lib_modules(size_t *count);
const char *const *ci_app_shapes(size_t *count);

#endif /* ZCL_CODEINDEX_BUILD_H */
