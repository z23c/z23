/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_priv — private declarations shared across the cognition/modules/codeindex/
 * implementation translation units. NOT a public header: nothing outside
 * cognition/modules/codeindex/src/ includes this.
 *
 * Holds the store handle API (a dedicated derived SQLite store below the
 * AR layer, exactly like contexts/commons/modules/vcs's index.kv), the source enumerator, the C
 * scanner, the depfile parser, and the group taxonomy — the pieces the public
 * query/build surfaces are assembled from.
 */

#ifndef ZCL_CODEINDEX_PRIV_H
#define ZCL_CODEINDEX_PRIV_H

#include "codeindex/codeindex.h"

#include "crypto/sha3.h"
#include "platform/directory_transaction.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define CI_PATH_MAX 4096
#define CI_SYM_COLS \
    "name,kind,def_path,def_line,decl_path,decl_line," \
    "signature,doc,guard,\"group\",partial,row_sha3"

/* Derived-schema generation tag. Bump on ANY change to the derived table
 * layout or the meaning of a derived column (recompute, never repair). It is
 * written to meta as "ci_schema_version" during rebuild and gated in the
 * staleness check: a store whose key is absent or mismatched is stale and gets
 * a full deterministic rebuild on open. "cg1" = the call-graph generation that
 * added refs.enclosing. "rev1" = the reverse-include generation: it adds the
 * includes(dep_path) index AND admits `.def` registries into the scanned file
 * set, so a store built by the previous generation both lacks the index and
 * cannot report a .def's content hash. "cap1" = the capability generation:
 * files.purpose is stored at CI_FILE_PURPOSE_MAX instead of 160, so a store
 * built by "rev1" holds purposes that were truncated mid-sentence. The bytes
 * are still valid text, which is exactly why this needs a version bump rather
 * than a lazy repair — a capability search ranks on that text, and a stale
 * generation would rank on the cut version without any signal that it had.
 * "ret1" = the retrieval-integrity generation: every consumer-visible group,
 * file, symbol, and reference row is sealed by one canonical logical root.
 * "ret2" adds content-addressed per-file scan shards so a changed source can
 * replace only its own derived rows without weakening that logical seal. */
#define CI_SCHEMA_VERSION "ret2"
#define CI_STORE_FORMAT "zcl.codeindex.store.v5"
#define CI_RETRIEVAL_PROJECTION_META "retrieval_projection_root_sha3"

/* ── the public handle (defined here so every TU can reach the store) ── */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
struct ci_store;
struct ci_merkle;
struct ci_merkle_leaf;
struct codeindex {
    struct ci_store *store;
    struct ci_merkle *pending_merkle;
    bool              pending_merkle_snapshot_used;
    bool              pending_merkle_full_rescan;
    bool              pending_merkle_inventory_changed;
    char             root[CI_PATH_MAX];
};

static inline void ci_cpy(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

/* ── store: derived SQLite DB at <root>/.codeindex/index.kv ───────────
 * Raw sqlite3_step in the store carries `// raw-sql-ok:codeindex-derived`. */
/* Canonical generations are query-only. NULL also means "not published yet";
 * only the rebuild path may create a writable staging database. */
struct ci_store *ci_store_open(const char *root);
struct ci_store *ci_store_open_path(const char *dbpath);/* an explicit path (tmp build) */
void             ci_store_close(struct ci_store *s);
sqlite3         *ci_store_db(struct ci_store *s);
void             ci_store_lock(struct ci_store *s);
void             ci_store_unlock(struct ci_store *s);

/* Lazy-open refresh: coalesces concurrent stale opens under the cross-process
 * rebuild lock. Public codeindex_rebuild() remains a forced recompute. */
bool ci_codeindex_refresh(struct codeindex *ci);
bool ci_codeindex_source_view_is_stale(struct codeindex *ci, bool *stale);

/* single-writer transaction control */
bool ci_store_begin(struct ci_store *s);
bool ci_store_commit(struct ci_store *s);
bool ci_store_rollback(struct ci_store *s);

/* writes (require an open txn) */
bool ci_store_clear(struct ci_store *s);
bool ci_store_put_file(struct ci_store *s, const struct ci_file *f,
                       const uint8_t content_sha3[32], int64_t mtime,
                       int64_t *out_file_id);
bool ci_store_put_symbol(struct ci_store *s, const struct ci_symbol *sym);
bool ci_store_put_include(struct ci_store *s, int64_t file_id,
                          const char *dep_path);
bool ci_store_put_ref(struct ci_store *s, const char *callee,
                      const char *ref_file, int ref_line,
                      const char *enclosing);
bool ci_store_put_group(struct ci_store *s, const struct ci_group *g);
bool ci_store_meta_set(struct ci_store *s, const char *k, const void *v,
                       size_t vlen);
/* Serialize a committed in-memory store directly into an already-open private
 * regular-file capability. No pathname is opened or followed. */
bool ci_store_write_image_fd(struct ci_store *s, int fd);
/* Clone a validated immutable generation into a private staging descriptor,
 * then open that exact descriptor for derived-row replacement. POSIX only;
 * callers retain and publish the descriptor. */
bool ci_store_copy_image_fd(struct ci_store *s, int fd);
struct ci_store *ci_store_open_rw_fd(int fd);
/* Bind an already-validated private store descriptor (ownership/mode/nlink
 * checked by the caller) into a read-only immutable handle — the exact
 * binding discipline ci_store_open applies after its own checks. Takes
 * ownership of the descriptor. POSIX only. */
struct ci_store *ci_store_open_readonly_fd(int fd);
/* Serialize a committed in-memory store through one retained child file.
 * Used by the native Windows publisher, where an integer CRT descriptor is
 * not the directory-relative authority. */
bool ci_store_write_image_child(struct ci_store *s,
                                struct platform_directory_child *child);
#if defined(_WIN32)
bool ci_merkle_snapshot_image_load_windows(
    const char *root, const char *leaf, size_t maximum,
    unsigned char **image_out, size_t *length_out, bool *found);
bool ci_merkle_snapshot_image_save_windows(
    const char *root, const char *leaf, const unsigned char *image,
    size_t length);
bool ci_merkle_snapshot_image_forget_windows(const char *root,
                                             const char *leaf);
#endif

/* reads (self-locking; no open txn required) */
bool ci_store_meta_get(struct ci_store *s, const char *k, void *buf,
                       size_t cap, size_t *outlen, bool *found);
bool ci_store_symbol_by_name(struct ci_store *s, const char *name,
                             struct ci_symbol *out, bool *found);
bool ci_store_fill_symbol(sqlite3_stmt *stmt, struct ci_symbol *out);
bool ci_store_symbol_by_name_path(struct ci_store *s, const char *name,
                                  const char *def_path,
                                  struct ci_symbol *out, bool *found);
int  ci_store_find_symbols(struct ci_store *s, const char *q,
                           struct ci_symbol *out, int cap);
int  ci_store_search_text(struct ci_store *s, const char *q,
                          struct ci_search_hit *out, int cap);
int  ci_store_refs_by_callee(struct ci_store *s, const char *callee,
                             struct ci_ref *out, int cap);
/* Refs whose enclosing function is `enclosing` (the callee side of the call
 * graph), ordered by (ref_file, ref_line). Fills up to `cap`, returns count. */
int  ci_store_refs_by_enclosing(struct ci_store *s, const char *enclosing,
                                struct ci_ref *out, int cap);
int  ci_store_refs_by_callee_file(struct ci_store *s, const char *callee,
                                  const char *ref_file,
                                  struct ci_ref *out, int cap);
int  ci_store_refs_by_enclosing_file(struct ci_store *s,
                                     const char *enclosing,
                                     const char *ref_file,
                                     struct ci_ref *out, int cap);
bool ci_store_file_by_path(struct ci_store *s, const char *path,
                           struct ci_file *out, bool *found);
int  ci_store_list_groups(struct ci_store *s, struct ci_group *out, int cap);
int  ci_store_files_in_group(struct ci_store *s, const char *group,
                             struct ci_file *out, int cap);
int  ci_store_file_count(struct ci_store *s);
int  ci_store_files_page(struct ci_store *s, int offset,
                         struct ci_file *out, int cap);
int  ci_store_count_files_in_group(struct ci_store *s, const char *group,
                                   bool recursive);
bool ci_store_source_file_counts(struct ci_store *s,
                                 struct ci_source_file_counts *out);
int  ci_store_symbols_in_file(struct ci_store *s, const char *path,
                              struct ci_symbol *out, int cap);
int  ci_store_includes_of_file_page(struct ci_store *s, const char *path,
                                    int offset, char (*out)[256], int cap);
/* Reverse of the above: indexed files that list `dep_path` as a compiler
 * prerequisite, sorted by path. Returns the count (>=0), -1 on error. */
int  ci_store_dependents_of_file(struct ci_store *s, const char *dep_path,
                                 char (*out)[256], int cap);
/* Total include edges in the store. ZERO means the depfile graph was ABSENT
 * when the index was built — an availability fact, not an empty answer. */
int64_t ci_store_include_edge_count(struct ci_store *s);

/* Canonical per-symbol row hash used for verify-on-read. Deterministic over
 * all card fields. */
void ci_symbol_row_hash(const struct ci_symbol *sym, uint8_t out[32]);
/* Canonical logical root over every source-derived row consumed by retrieval.
 * The projector holds the immutable store handle's lock for one exact SQL
 * snapshot, rejects malformed types/widths, and touches out only on success. */
bool ci_store_retrieval_projection_root(struct ci_store *s, uint8_t out[32]);
/* Compare the recomputed logical root with the sealed meta record. Missing or
 * malformed records are valid observations of an invalid generation. */
bool ci_store_retrieval_projection_is_valid(struct ci_store *s, bool *valid);
bool ci_store_scan_shard_refresh(struct ci_store *s, const char *path);
bool ci_store_scan_shards_are_valid(struct ci_store *s, bool *valid);
bool ci_store_apply_pragmas(sqlite3 *db);
bool ci_store_ensure_schema(sqlite3 *db);

/* ── source enumeration ───────────────────────────────────────────────
 * Deterministic, sorted, repo-relative .c/.h and .def paths across the
 * maintained roots declared in codeindex/source_roots.def. cb returns false to
 * abort. */
typedef bool (*ci_enum_cb)(const char *relpath, const struct stat *st,
                           void *user);
bool ci_enumerate_sources(const char *root, ci_enum_cb cb, void *user);
/* True iff `relpath` names an X-macro registry (`*.def`): an include-graph node
 * that is hashed and filed but never handed to the C scanner. */
bool ci_path_is_registry(const char *relpath);
/* Fast freshness key for an exact source root already sealed in a generation.
 * It binds path + inode + size + mtime + ctime and never reads file bytes. */
bool ci_source_stat_root_sha3(const char *root, uint8_t out[32]);
/* Exact bytes and their metadata cache key from the same opened inodes. */
bool ci_source_roots_sha3(const char *root, uint8_t exact_out[32],
                          uint8_t stat_out[32]);

/* Shared deterministic store assembly. Platform publishers supply only the
 * retained staging/lock/replace transaction; scanning, metadata binding and
 * the in-memory SQLite generation stay identical on every host. */
void ci_source_root_init(struct sha3_256_ctx *sha);
void ci_source_root_add(struct sha3_256_ctx *sha, const char *relpath,
                        const uint8_t content_sha3[32]);
bool ci_build_store_memory(const char *root, int64_t build_start_ms,
                           struct ci_store **out_store,
                           uint8_t source_stat_out[32],
                           uint8_t dep_stat_out[32]);
bool ci_build_store_incremental(const char *root, struct ci_store *store,
                                const struct ci_merkle_leaf *changed,
                                int changed_count,
                                const uint8_t dep_stat[32],
                                const uint8_t merkle_root[32]);
int ci_store_diff_merkle_leaves(struct ci_store *store,
                                const struct ci_merkle_leaf *current,
                                int current_count,
                                struct ci_merkle_leaf *changed, int cap,
                                bool *inventory_same);

/* ── the publication ritual (codeindex_build.c, POSIX) ────────────────
 * The one cross-process discipline for placing a generation at
 * <root>/.codeindex/index.kv: owner-controlled directory capability,
 * exclusive rebuild.lock flock, unique private staging inode, atomic renameat,
 * fsync of file and directory. codeindex_fetch.c installs a verified fetched
 * image through the SAME ritual — a second copy would drift. */
struct ci_stage_identity {
    dev_t dev;
    ino_t ino;
};
bool ci_rebuild_lock_open(const char *root, char dir[CI_PATH_MAX],
                          int *out_dirfd, int *out_lockfd);
void ci_rebuild_lock_close(int dirfd, int lockfd);
bool ci_cleanup_orphan_stages(int dirfd);
bool ci_create_unique_stage(int dirfd, char name[128],
                            struct ci_stage_identity *identity, int *out_fd);
bool ci_remove_legacy_sidecars(int dirfd);

/* ── the C scanner (codeindex_scan.c) ─────────────────────────────────
 * Scan one in-tree file's text. Emits symbols and refs through callbacks.
 * relpath is repo-relative; is_header selects DEFINITION vs DECLARATION
 * handling for prototypes. Never aborts on messy input — degrades to
 * partial=true. `content_sha3` of the scanned bytes is returned in out_sha3.
 * `purpose_out` (may be NULL) receives the file's one-line self-description
 * derived from its leading block comment (§1.1 of docs/work/palace-design.md);
 * "" when no leading comment precedes the first code token. */
typedef void (*ci_sym_cb)(const struct ci_symbol *sym, void *user);
/* `enclosing` is the name of the function the call site sits inside — the
 * greatest function definition whose def_line <= ref_line in the same file (C
 * does not nest functions; best-effort). Empty string when unattributed. */
typedef void (*ci_ref_cb)(const char *callee, const char *ref_file,
                          int ref_line, const char *enclosing, void *user);
bool ci_scan_file(const char *root, const char *relpath,
                  ci_sym_cb on_sym, ci_ref_cb on_ref, void *user,
                  uint8_t out_sha3[32], char purpose_out[CI_FILE_PURPOSE_MAX]);

/* Pure text scanner (no file I/O) — the testable core. `src`/`len` is the raw
 * file text; the group is stamped into every emitted symbol. `purpose_out`
 * (may be NULL) receives the derived file purpose (see ci_scan_file). */
void ci_scan_text(const char *src, size_t len, const char *relpath,
                  bool is_header, const char *group,
                  ci_sym_cb on_sym, ci_ref_cb on_ref, void *user,
                  char purpose_out[CI_FILE_PURPOSE_MAX]);

/* ── depfile parsing (codeindex_deps.c) ───────────────────────────────
 * Parse one make depfile: yields (source_relpath, dep_relpath) edges for
 * in-tree prerequisites. */
typedef void (*ci_dep_cb)(const char *src_relpath, const char *dep_relpath,
                          void *user);
/* Deterministically scan sorted .d inputs below build/. `cb` may be NULL for a
 * digest-only freshness check. out_root binds the exact depfile bytes parsed,
 * including an explicit marker when build/ is absent. */
bool ci_deps_scan(const char *root, ci_dep_cb cb, void *user,
                  uint8_t out_root[32]);
bool ci_deps_scan_roots(const char *root, ci_dep_cb cb, void *user,
                        uint8_t exact_out[32], uint8_t stat_out[32]);
/* Metadata cache key for ci_deps_scan's exact root. Both functions read the
 * live compile epoch of each object root and nothing else; this path reads no
 * depfile content. */
bool ci_deps_stat_root_sha3(const char *root, uint8_t out_root[32]);

#ifdef ZCL_TESTING
void ci_test_note_exact_bytes(uint64_t bytes);
#else
#define ci_test_note_exact_bytes(...) ((void)0)
#endif

/* ── group taxonomy (codeindex_group.c) ───────────────────────────────*/
/* Map a repo-relative path to its group id (e.g. "core/modules/net", "app/services",
 * "core", "tools", "config"). Writes "" for an unclassified path. */
void ci_group_for_path(const char *relpath, char out[64]);
/* Human-readable one-liner for a known group ("" if none). */
const char *ci_group_purpose(const char *group);
/* Emit the full fixed hierarchy into an open store txn. */
bool ci_group_emit_all(struct ci_store *s);

#endif /* ZCL_CODEINDEX_PRIV_H */
