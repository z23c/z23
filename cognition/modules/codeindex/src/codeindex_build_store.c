/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Assemble one deterministic codeindex generation in memory for a
 * platform publisher to commit through its retained directory capability. */

#include "codeindex_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ci_source_root_init(struct sha3_256_ctx *sha)
{
    /* v4 admits *.def registries into the exact indexed source universe. */
    static const char domain[] = "zcl.codeindex.source_root.v4";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
}

void ci_source_root_add(struct sha3_256_ctx *sha, const char *relpath,
                        const uint8_t content_sha3[32])
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    sha3_256_write(sha, content_sha3, 32);
}

struct idmap_ent { char path[256]; int64_t id; };
struct build_ctx {
    struct ci_store   *store;
    bool               err;
    struct idmap_ent  *ids;
    size_t             nids, cap_ids;
    struct sha3_256_ctx source_root;
};

static void on_sym_cb(const struct ci_symbol *sym, void *user)
{
    struct build_ctx *b = user;
    if (!b->err && !ci_store_put_symbol(b->store, sym)) b->err = true;
}

static void ignore_sym_cb(const struct ci_symbol *sym, void *user)
{
    (void)sym;
    (void)user;
}

static void ignore_ref_cb(const char *callee, const char *ref_file,
                          int ref_line, const char *enclosing, void *user)
{
    (void)callee;
    (void)ref_file;
    (void)ref_line;
    (void)enclosing;
    (void)user;
}

static void on_ref_cb(const char *callee, const char *ref_file, int ref_line,
                      const char *enclosing, void *user)
{
    struct build_ctx *b = user;
    if (!b->err && !ci_store_put_ref(b->store, callee, ref_file, ref_line,
                                     enclosing))
        b->err = true;
}

static bool idmap_push(struct build_ctx *b, const char *path, int64_t id)
{
    if (b->nids == b->cap_ids) {
        size_t ncap = b->cap_ids ? b->cap_ids * 2 : 512;
        void *next = zcl_realloc(b->ids, ncap * sizeof(*b->ids), "ci_idmap");
        if (!next) return false;
        b->ids = next;
        b->cap_ids = ncap;
    }
    (void)snprintf(b->ids[b->nids].path, sizeof(b->ids[b->nids].path),
                   "%s", path);
    b->ids[b->nids].id = id;
    b->nids++;
    return true;
}

static int idmap_cmp(const void *left, const void *right)
{
    return strcmp(((const struct idmap_ent *)left)->path,
                  ((const struct idmap_ent *)right)->path);
}

static int64_t idmap_find(const struct build_ctx *b, const char *path)
{
    size_t lo = 0, hi = b->nids;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(b->ids[mid].path, path);
        if (cmp == 0) return b->ids[mid].id;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

struct build_file_env { struct build_ctx *build; const char *root; };

static bool build_file_cb(const char *relpath, const struct stat *file_st,
                          void *user)
{
    struct build_file_env *env = user;
    struct build_ctx *b = env->build;
    if (b->err) return false;

    uint8_t sha[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    bool registry = ci_path_is_registry(relpath);
    if (!ci_scan_file(env->root, relpath,
                      registry ? ignore_sym_cb : on_sym_cb,
                      registry ? ignore_ref_cb : on_ref_cb, b, sha,
                      purpose)) {
        b->err = true;
        return false;
    }
    ci_source_root_add(&b->source_root, relpath, sha);

    struct ci_file file;
    memset(&file, 0, sizeof(file));
    (void)snprintf(file.path, sizeof(file.path), "%s", relpath);
    ci_group_for_path(relpath, file.group);
    (void)snprintf(file.purpose, sizeof(file.purpose), "%s", purpose);
#if defined(_WIN32)
    int64_t mtime_ns = (int64_t)file_st->st_mtime * INT64_C(1000000000);
#else
    int64_t mtime_ns = (int64_t)file_st->st_mtim.tv_sec * INT64_C(1000000000) +
                       (int64_t)file_st->st_mtim.tv_nsec;
#endif
    int64_t id = -1;
    if (!ci_store_put_file(b->store, &file, sha, mtime_ns, &id) ||
        !idmap_push(b, relpath, id)) {
        b->err = true;
        return false;
    }
    return true;
}

static void on_dep_cb(const char *source, const char *dependency, void *user)
{
    struct build_ctx *b = user;
    if (b->err) return;
    int64_t id = idmap_find(b, source);
    if (id >= 0 && !ci_store_put_include(b->store, id, dependency))
        b->err = true;
}

bool ci_build_store_memory(const char *root, struct ci_store **out_store,
                           uint8_t source_stat_out[32],
                           uint8_t dep_stat_out[32])
{
    if (!root || !out_store || !source_stat_out || !dep_stat_out)
        LOG_FAIL("codeindex", "null argument to memory store build");
    *out_store = NULL;

    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) LOG_FAIL("codeindex", "open in-memory staging store failed");
    struct build_ctx build;
    memset(&build, 0, sizeof(build));
    build.store = store;
    ci_source_root_init(&build.source_root);

    bool tx_open = ci_store_begin(store);
    bool ok = tx_open && ci_store_clear(store) && ci_group_emit_all(store);
    struct build_file_env env = { .build = &build, .root = root };
    if (ok && !ci_enumerate_sources(root, build_file_cb, &env)) ok = false;
    if (build.err) ok = false;
    if (ok) qsort(build.ids, build.nids, sizeof(build.ids[0]), idmap_cmp);

    uint8_t built_source_root[32], built_dep_root[32];
    if (ok) {
        sha3_256_finalize(&build.source_root, built_source_root);
        ok = ci_store_meta_set(store, "source_root_sha3", built_source_root,
                               sizeof(built_source_root));
    }
    if (ok)
        ok = ci_deps_scan(root, on_dep_cb, &build, built_dep_root) &&
             !build.err &&
             ci_store_meta_set(store, "dep_root_sha3", built_dep_root,
                               sizeof(built_dep_root));

    uint8_t current_source_root[32], current_dep_root[32];
    if (ok)
        ok = ci_source_roots_sha3(root, current_source_root, source_stat_out) &&
             memcmp(built_source_root, current_source_root, 32) == 0 &&
             ci_deps_scan_roots(root, NULL, NULL, current_dep_root,
                                dep_stat_out) &&
             memcmp(built_dep_root, current_dep_root, 32) == 0;
    if (ok)
        ok = ci_store_meta_set(store, "source_stat_root_sha3",
                               source_stat_out, 32) &&
             ci_store_meta_set(store, "dep_stat_root_sha3", dep_stat_out, 32) &&
             ci_store_meta_set(store, "store_format", CI_STORE_FORMAT,
                               sizeof(CI_STORE_FORMAT) - 1) &&
             ci_store_meta_set(store, "ci_schema_version", CI_SCHEMA_VERSION,
                               sizeof(CI_SCHEMA_VERSION) - 1);

    uint8_t retrieval_projection_root[32];
    if (ok)
        ok = ci_store_retrieval_projection_root(
                 store, retrieval_projection_root) &&
             ci_store_meta_set(store, CI_RETRIEVAL_PROJECTION_META,
                               retrieval_projection_root,
                               sizeof(retrieval_projection_root));

    if (!ok) {
        if (tx_open) (void)ci_store_rollback(store);
        ci_store_close(store);
        free(build.ids);
        LOG_FAIL("codeindex", "source scan or staging write failed");
    }
    if (!ci_store_commit(store)) {
        ci_store_close(store);
        free(build.ids);
        LOG_FAIL("codeindex", "commit staging store failed");
    }
    free(build.ids);
    *out_store = store;
    return true;
}
