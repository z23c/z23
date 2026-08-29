/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store_priv — private internals shared by the package_store
 * implementation units (package_store.c = public API/policy,
 * package_store_io.c = filesystem layout + crash recovery). NOT a public
 * header: nothing outside lib/vcs/src/ includes this. */

#ifndef ZCL_VCS_PACKAGE_STORE_PRIV_H
#define ZCL_VCS_PACKAGE_STORE_PRIV_H

#include "vcs/package_store.h"

#include "vcs/package_manifest.h"

#include <pthread.h>

#define STORE_PATH_MAX 4096u
#define STORE_TEMP_SUFFIX ".zstmp"

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
};

struct vcs_package_store {
    char root[STORE_PATH_MAX]; /* <datadir>/zcode */
    int process_lock_fd;       /* recovery/CAS transaction serialization */
    uint64_t quota;
    struct store_package *pkgs;
    size_t pkg_count;
    size_t pkg_cap;
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
    uint64_t evictions_total;
    uint64_t gc_orphans_total;
    uint64_t quota_rejects_total;
    pthread_mutex_t lock;
};

/* Lock-held mutation epoch helpers. Epoch zero is never published. */
void store_package_touch(struct vcs_package_store *store,
                         struct store_package *pkg);
void store_packages_touch_hash(struct vcs_package_store *store,
                               const uint8_t hash[32]);

/* ── shared small helpers (package_store_io.c) ────────────────────── */

bool store_name_is_hex64(const char *name);

/* mkdir -p (every component); false on failure (logged by caller). */
bool store_mkdir_p(const char *path);

/* Recursive delete of a file or directory tree (pure C). */
bool store_rm_rf(const char *path);

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

/* Create the layout, sweep temps, reload manifests (committed + staged),
 * GC unreferenced CAS objects, and commit CAS-complete staged packages.
 * Fills store->{pkgs,cas,gc_orphans_total}; false on hard I/O failure. */
bool store_open_recover(struct vcs_package_store *store);

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

#endif /* ZCL_VCS_PACKAGE_STORE_PRIV_H */
