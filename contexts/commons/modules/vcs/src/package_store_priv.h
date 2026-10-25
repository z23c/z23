/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store_priv — private internals shared by the package_store
 * implementation units (package_store.c = public API/policy,
 * package_store_io.c = filesystem layout + crash recovery, package_store_fs.c
 * = filesystem primitives: mkdir, delete, durable writes, temp sweep). NOT a
 * public header: nothing outside contexts/commons/modules/vcs/src/ includes
 * this. */

#ifndef ZCL_VCS_PACKAGE_STORE_PRIV_H
#define ZCL_VCS_PACKAGE_STORE_PRIV_H

#include "vcs/package_store.h"

#include "vcs/package_manifest.h"

#include <pthread.h>
#include <stdatomic.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <wchar.h>
#include <windows.h>
#endif

#define STORE_PATH_MAX 4096u
#define STORE_TEMP_SUFFIX ".zstmp"
#define STORE_HOT_MANIFESTS 256u

/* One unique chunk hash of a package's manifest with its expected size.
 * Presence is derived (hash in the store's CAS set), never cached here. */
struct store_unique_chunk {
    uint8_t hash[32];
    uint64_t size;
};

struct store_package {
    uint8_t root[32];
    char root_hex[65];
    struct vcs_package_manifest manifest; /* parsed; owns heap members */
    uint8_t *manifest_wire;               /* canonical wire, for commit */
    size_t manifest_wire_len;
    uint32_t file_count; /* compact catalog metadata survives cooling */
    uint32_t total_chunks;
    bool manifest_loaded;
    uint64_t hot_clock;
    bool committed;    /* manifests/<hex> (vs staging/<hex>/manifest) */
    bool pinned;
    enum vcs_package_store_class class_;
    uint32_t replicas;
    uint64_t access_count;
    uint64_t last_access;   /* logical clock value of the last get */
    uint64_t total_bytes;   /* sum of manifest file sizes */
    struct store_unique_chunk *chunks; /* unique hashes, ascending */
    size_t chunk_count;
    uint64_t mutation_generation;
    uint64_t admission_generation; /* local admission order; unchanged by touches */
};

struct vcs_package_store {
    char root[STORE_PATH_MAX]; /* <datadir>/zcode */
    bool preexisting_root; /* root existed before this open created layout */
    int process_lock_fd;       /* recovery/CAS transaction serialization */
    uint64_t quota;
    uint64_t manifest_bytes_total;
    struct store_package *pkgs;
    size_t pkg_count;
    size_t pkg_cap;
    size_t *root_order; /* sorted indexes into pkgs; rebuilt from manifests */
    size_t hot_count;
    uint64_t hot_clock;
    uint64_t hot_loads;       /* manifests parsed again after release */
    uint64_t hot_trim_passes; /* catalog passes that released manifests */
    bool catalog_incomplete; /* committed manifest could not be replayed */
    uint8_t (*cas)[32]; /* present chunk hashes, ascending (bsearch) */
    size_t cas_count;
    size_t cas_cap;
    struct vcs_package_accept *accept;
    /* Slice 3 diagnostics: the last put_release acceptance outcome (set on
     * every put_release call, including rejections). */
    bool last_accept_set;
    enum vcs_package_accept_result last_accept;
    uint8_t last_accept_id[32];
    uint64_t logical_clock;
    uint64_t next_mutation_generation;
    uint64_t shared_generation; /* derived change detector on disk */
    uint64_t evictions_total;
    uint64_t gc_orphans_total;
    uint64_t quota_rejects_total;
    uint64_t releases_quarantined_total; /* moved aside by the last open */
    pthread_mutex_t lock;
};

/* Lock-held mutation epoch helpers. Epoch zero is never published. */
void store_package_touch(struct vcs_package_store *store,
                         struct store_package *pkg);
void store_packages_touch_hash(struct vcs_package_store *store,
                               const uint8_t hash[32]);

/* ── shared small helpers (package_store_io.c, package_store_fs.c) ── */

/* Set by vcs_package_store_set_deferred_sync; defined in package_store_io.c. */
extern _Atomic bool g_store_deferred_sync;

bool store_name_is_hex64(const char *name);
bool store_directory_exists(const char *path);

/* Win32 error and path helpers: defined in package_store_fs.c, used by the
 * no-follow probes and unlink in package_store_io.c. */
#if defined(_WIN32)
void store_set_errno(DWORD error);
bool store_wide_path(const char *path, wchar_t out[STORE_PATH_MAX]);
bool store_win32_real_directory(const wchar_t *path);
bool store_win32_delete_leaf(const wchar_t *path, DWORD attributes);
#endif

/* mkdir -p (every component); false on failure (logged by caller). */
bool store_mkdir_p(const char *path);

/* Recursive delete of a file or directory tree (pure C). */
bool store_rm_rf(const char *path);

/* Delete leftover temp files whose owner pid is gone, recursing under dir;
 * logs each swept file. Runs during open-time recovery (package_store_fs.c). */
void store_sweep_temps(struct vcs_package_store *store, const char *dir);

/* UTF-8 no-follow file presence/removal used by store policy paths. */
bool store_path_exists(const char *path);
bool store_unlink(const char *path);

/* Durable write: <path><STORE_TEMP_SUFFIX>.<pid>.<seq>, fsync, rename. */
bool store_atomic_write(const char *path, const uint8_t *data,
                        size_t data_len);

/* <store->root>/cas/sha3/<hh>/<64-hex> for a chunk hash. */
void store_cas_path(const struct vcs_package_store *store,
                    const uint8_t hash[32], char *out, size_t out_size);

/* CAS set: ascending-hash array; contains/insert/remove. */
bool store_cas_contains(const struct vcs_package_store *store,
                        const uint8_t hash[32]);
bool store_cas_insert(struct vcs_package_store *store,
                      const uint8_t hash[32]);
void store_cas_remove(struct vcs_package_store *store,
                      const uint8_t hash[32]);
bool store_chunk_write_verified(struct vcs_package_store *store,
                                const uint8_t hash[32],
                                const uint8_t *chunk, size_t chunk_len);
bool store_manifest_identity(const uint8_t *wire, size_t wire_len,
                             uint8_t root[32], uint64_t *total_bytes);
bool store_chunk_inputs_valid(struct vcs_package_store *store,
                              const uint8_t package_root[32],
                              const char *path, const uint8_t *chunk);
const struct vcs_package_file *store_resolve_file(
    const struct store_package *pkg, const char *path);
enum vcs_package_store_result store_chunk_hash_checked(
    const struct store_package *pkg, const char *path, uint32_t chunk_index,
    const uint8_t *chunk, size_t chunk_len, uint8_t hash[32]);

/* Create the layout, sweep temps, reload manifests (committed + staged),
 * GC unreferenced CAS objects, and commit CAS-complete staged packages.
 * Fills store->{pkgs,cas,gc_orphans_total}; false on hard I/O failure. */
bool store_open_recover(struct vcs_package_store *store);
/* Rebuild release acceptance from every present immutable envelope. The
 * caller owns the returned unpublished projection, or receives NULL on any
 * incomplete/corrupt history or resource failure. *quarantined
 * receives the count of provably invalid records moved aside. */
struct vcs_package_accept *store_replay_releases(const char *root,
                                                 uint64_t *quarantined);
bool store_process_lock(struct vcs_package_store *store);
void store_process_unlock(struct vcs_package_store *store);
bool store_generation_check(struct vcs_package_store *store);
bool store_generation_read(struct vcs_package_store *store, uint64_t *value);
void store_partial_catalog_free(struct vcs_package_store *store);
struct store_package *store_find(struct vcs_package_store *store,
                                const uint8_t root[32], size_t *index_out);
bool store_ensure_room(struct vcs_package_store *store,
                       enum vcs_package_store_pool pool, uint64_t incoming,
                       const uint8_t protect_root[32]);
uint64_t store_pool_budget(const struct vcs_package_store *store,
                           enum vcs_package_store_pool pool);
uint64_t store_pool_usage_locked(struct vcs_package_store *store,
                                  enum vcs_package_store_pool pool);
void store_pool_usages_locked(struct vcs_package_store *store,
                              uint64_t usage[4]);
enum vcs_package_store_result store_chunk_room(
    struct vcs_package_store *store, struct store_package *pkg,
    const uint8_t hash[32], const uint8_t package_root[32],
    bool *will_complete);
uint8_t *store_read_file(const char *path, size_t *out_len);
/* Caller holds the exact-root process lock; advance before recovery mutation. */
bool store_generation_advance(struct vcs_package_store *store);

/* With the exact-root process lock held, compare the open handle's catalog
 * with authoritative manifest, pin, and known CAS paths. A second handle or
 * an external deletion must refuse projection publication. */
enum vcs_package_store_page_result store_catalog_validate_disk(
    const struct vcs_package_store *store);
/* During a generation refresh, require every previously observed object to
 * remain intact while allowing another handle to have added new names. */
enum vcs_package_store_page_result store_catalog_validate_observed_disk(
    const struct vcs_package_store *store);
/* Validate one cached manifest and its present CAS refs before a no-op put. */
enum vcs_package_store_page_result store_catalog_validate_record_disk(
    const struct vcs_package_store *store, const struct store_package *pkg);
/* Caller holds the handle mutex; recheck and quarantine under process lock. */
enum vcs_package_store_result store_cas_quarantine_if_bad(
    struct vcs_package_store *store, const uint8_t hash[32],
    const struct vcs_package_file *file, uint32_t chunk_index,
    enum vcs_package_store_result observed);

/* Derived per-package state from the CAS set. */
void store_package_present(const struct vcs_package_store *store,
                           const struct store_package *pkg,
                           uint32_t *chunks_out, uint64_t *bytes_out);
bool store_package_complete(const struct vcs_package_store *store,
                            const struct store_package *pkg);

/* Commit one complete staged package: staging/<hex>/manifest ->
 * manifests/<hex>, staging dir removed. Package must be complete. */
bool store_package_commit(struct vcs_package_store *store,
                          struct store_package *pkg);

/* Count persisted release envelopes (64-hex names under releases/).
 * Best-effort for diagnostics: 0 when the directory is unreadable. */
uint32_t store_releases_count(const struct vcs_package_store *store);

/* Parse a manifest wire, verify its root equals expect_hex, build the
 * record (unique chunks, total bytes, pin marker), and append it to the
 * table. NULL on parse/root/allocation failure (logged). */
struct store_package *store_record_add(struct vcs_package_store *store,
                                       const uint8_t *wire, size_t wire_len,
                                       const char *expect_hex,
                                       bool committed);

/* The root/chunk catalog is rebuilt from manifests at open. Parsed manifest
 * trees and wire copies are an LRU hot cache capped independently of corpus
 * size. Caller holds store->lock (or the open-time process lock). */
bool store_package_materialize(struct vcs_package_store *store,
                               struct store_package *pkg);
void store_package_release_hot(struct vcs_package_store *store,
                               struct store_package *pkg);

#endif /* ZCL_VCS_PACKAGE_STORE_PRIV_H */
