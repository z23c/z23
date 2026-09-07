/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: package-scope store reads (READ-ONLY observer, slice 1b).
 * A package scope reads <store-root>/<label>/zcode directly: the committed
 * manifest, the release envelope naming that package root, the recipe
 * wire, and CAS chunks — every object is re-parsed and re-hashed on read
 * (chunk bytes must equal the hash committed at their manifest
 * coordinates), so a corrupted or tampered store fails the census closed.
 * The store is never opened through vcs_package_store_open: no recovery
 * sweep, GC, pin, or access-count mutation. See the PACKAGE SCOPES section
 * at the top of tools/corpus_census.c for the full evidence bindings.
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/package_build.h"
#include "vcs/package_recipe.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void package_ctx_free(struct package_ctx *ctx)
{
    if (!ctx) return;
    free(ctx->zcode_dir);
    vcs_package_manifest_free(&ctx->manifest);
    memset(ctx, 0, sizeof(*ctx));
}

/* Read one bounded regular file fully (allocates *out; caller frees). */
bool store_file_read(const char *path, size_t max_bytes, uint8_t **out,
                     size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR(CENSUS_LOG, "open %s: %s", path, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > max_bytes) {
        LOG_ERROR(CENSUS_LOG, "stat %s: not a regular file within %zu bytes",
                  path, max_bytes);
        close(fd);
        return false;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.store.file");
    if (!bytes) {
        close(fd);
        LOG_FAIL(CENSUS_LOG, "store file alloc %zu for %s", len, path);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, bytes + off, len - off);
        if (r <= 0) {
            LOG_ERROR(CENSUS_LOG, "read %s: %s", path,
                      r == 0 ? "short file" : strerror(errno));
            free(bytes);
            close(fd);
            return false;
        }
        off += (size_t)r;
    }
    close(fd);
    *out = bytes;
    *out_len = len;
    return true;
}

/* Load and re-root the committed manifest for the def's package root. */
static bool package_manifest_load(struct package_ctx *ctx,
                                  const uint8_t root[32])
{
    char hex[65];
    root_hex(root, hex);
    size_t plen = strlen(ctx->zcode_dir) + sizeof("/manifests/") + 64u;
    char *path = zcl_malloc(plen, "corpus.pkg.manifest");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "manifest path alloc");
    (void)snprintf(path, plen, "%s/manifests/%s", ctx->zcode_dir, hex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = store_file_read(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                              &wire, &wire_len);
    free(path);
    if (!ok) return false;
    if (!vcs_package_manifest_parse(wire, wire_len, &ctx->manifest)) {
        LOG_ERROR(CENSUS_LOG, "stored manifest %s fails the grammar", hex);
        free(wire);
        return false;
    }
    free(wire);
    uint8_t derived[32];
    if (!vcs_package_manifest_root(&ctx->manifest, derived))
        LOG_FAIL(CENSUS_LOG, "manifest root derivation failed");
    if (memcmp(derived, root, 32) != 0) {
        char dhex[65];
        root_hex(derived, dhex);
        LOG_ERROR(CENSUS_LOG,
                  "stored manifest root %s does not match the def root %s",
                  dhex, hex);
        vcs_package_manifest_free(&ctx->manifest);
        return false;
    }
    return true;
}

/* One releases/ directory entry: skip a non-hex-named entry, skip a
 * release that parses but names a different package root, else verify it
 * and bind it as ctx->release. *matched reports whether this entry bound
 * the release; the bool return is false only for a hard (fatal) error. */
static bool package_release_try_entry(struct package_ctx *ctx,
                                      const char *dirpath, size_t dlen,
                                      const char *d_name,
                                      const uint8_t root[32], bool *matched)
{
    *matched = false;
    size_t nlen = strlen(d_name);
    if (nlen != 64) return true;
    uint8_t id[32];
    if (!zcl_hex_decode_lower(d_name, id, 32)) return true;
    size_t plen = dlen + 1u + 64u;
    char *path = zcl_malloc(plen, "corpus.pkg.release");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "release path alloc");
    (void)snprintf(path, plen, "%s/%s", dirpath, d_name);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool read_ok = store_file_read(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                   &wire, &wire_len);
    free(path);
    if (!read_ok) return false;
    struct vcs_package_release release;
    enum vcs_package_release_error perr =
        vcs_package_release_parse(wire, wire_len, &release);
    free(wire);
    if (perr != VCS_PACKAGE_RELEASE_OK ||
        memcmp(release.package_root, root, 32) != 0)
        return true;
    if (vcs_package_release_verify(&release) != VCS_PACKAGE_RELEASE_OK) {
        LOG_ERROR(CENSUS_LOG, "release %s fails signature verification",
                  d_name);
        return false;
    }
    uint8_t computed_id[32];
    if (vcs_package_release_id(&release, computed_id) !=
            VCS_PACKAGE_RELEASE_OK ||
        memcmp(computed_id, id, 32) != 0) {
        LOG_ERROR(CENSUS_LOG,
                  "release file %s does not hash to its own id", d_name);
        return false;
    }
    ctx->release = release;
    memcpy(ctx->release_id, id, 32);
    *matched = true;
    return true;
}

/* Find the release envelope naming this package root under releases/:
 * exactly one signature-verified match, else fail closed. */
bool package_release_find(struct package_ctx *ctx, const uint8_t root[32])
{
    size_t dlen = strlen(ctx->zcode_dir) + sizeof("/releases");
    char *dirpath = zcl_malloc(dlen, "corpus.pkg.releases");
    if (!dirpath)
        LOG_FAIL(CENSUS_LOG, "releases path alloc");
    (void)snprintf(dirpath, dlen, "%s/releases", ctx->zcode_dir);
    DIR *dir = opendir(dirpath);
    if (!dir) {
        LOG_ERROR(CENSUS_LOG, "opendir %s: %s", dirpath, strerror(errno));
        free(dirpath);
        return false;
    }
    size_t found = 0;
    bool ok = true;
    struct dirent *ent;
    while (ok && (ent = readdir(dir)) != NULL) {
        bool matched = false;
        if (!package_release_try_entry(ctx, dirpath, dlen, ent->d_name, root,
                                       &matched)) {
            ok = false;
            break;
        }
        if (matched) found++;
    }
    closedir(dir);
    free(dirpath);
    if (!ok) return false;
    if (found != 1) {
        char hex[65];
        root_hex(root, hex);
        LOG_ERROR(CENSUS_LOG,
                  "package %s: %zu release envelopes name the root (want "
                  "exactly 1)", hex, found);
        return false;
    }
    zcl_hex_encode(ctx->release.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, ctx->publisher_hex);
    return true;
}

/* Read one package file's bytes back from the CAS, re-hashing every chunk
 * against its committed manifest coordinates (fail closed on any mismatch).
 * Over-cap content yields NULL bytes with the declared size, exactly like
 * file_load (the census core turns it into the OVERSIZE exclusion). */
bool package_file_load(const struct package_ctx *ctx, const char *path,
                       uint8_t **bytes_out, size_t *len_out,
                       uint64_t *declared_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    *declared_out = 0;
    const struct vcs_package_file *file = NULL;
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        if (strcmp(ctx->manifest.files[i].path, path) == 0) {
            file = &ctx->manifest.files[i];
            break;
        }
    }
    if (!file)
        LOG_FAIL(CENSUS_LOG, "package file %s not in the manifest", path);
    *declared_out = file->size;
    if (file->size > VCS_ZCODE_C23_MAX_FILE_BYTES)
        return true; /* oversize: no bytes, declared size only */
    size_t len = (size_t)file->size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.pkg.file");
    if (!bytes)
        LOG_FAIL(CENSUS_LOG, "package file alloc %zu for %s", len, path);
    size_t off = 0;
    for (uint32_t c = 0; c < file->chunk_count; c++) {
        const uint8_t *hash = file->chunk_hashes + (size_t)c * 32u;
        char hex[65];
        zcl_hex_encode(hash, 32, hex);
        size_t plen = strlen(ctx->zcode_dir) + sizeof("/cas/sha3//") + 66u;
        char *cpath = zcl_malloc(plen, "corpus.pkg.chunk");
        if (!cpath)
            LOG_FAIL(CENSUS_LOG, "chunk path alloc");
        (void)snprintf(cpath, plen, "%s/cas/sha3/%2.2s/%s", ctx->zcode_dir,
                       hex, hex);
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        bool ok = store_file_read(cpath, VCS_PACKAGE_CHUNK_BYTES, &chunk,
                                  &chunk_len);
        free(cpath);
        if (!ok) {
            free(bytes);
            LOG_FAIL(CENSUS_LOG,
                     "package %s: chunk %u of %s missing from the CAS",
                     ctx->release.name, c, path);
        }
        uint8_t actual[32];
        sha3_256(chunk, chunk_len, actual);
        bool last = c + 1u == file->chunk_count;
        size_t expect = last ? len - off : VCS_PACKAGE_CHUNK_BYTES;
        if (memcmp(actual, hash, 32) != 0 || chunk_len != expect ||
            chunk_len > len - off) {
            free(chunk);
            free(bytes);
            LOG_FAIL(CENSUS_LOG,
                     "package %s: chunk %u of %s fails hash/size "
                     "verification", ctx->release.name, c, path);
        }
        memcpy(bytes + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (off != len)
        LOG_FAIL(CENSUS_LOG, "package file %s reassembled to %zu of %zu",
                 path, off, len);
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

/* Load the manifest and release for one package scope (fail closed). Also
 * cross-checks the def spdx against the release envelope's license. */
bool package_ctx_load(struct package_ctx *ctx, const struct scope_def *def,
                      const char *store_root)
{
    memset(ctx, 0, sizeof(*ctx));
    /* The def carries a LABEL; the operator-local root that it hangs off is
     * a run-time coordinate (--store-root / $ZCL_CORPUS_STORE_ROOT / $HOME)
     * and is deliberately absent from every committed artifact. */
    if (!store_root || !*store_root) {
        LOG_ERROR(CENSUS_LOG,
                  "package scope %s needs a store root: pass --store-root "
                  "<dir> (or set ZCL_CORPUS_STORE_ROOT / HOME); the store "
                  "label '%s' resolves to <store-root>/%s",
                  def->name, def->store, def->store);
        return false;
    }
    size_t len = strlen(store_root) + 1u + strlen(def->store) +
                 sizeof("/zcode");
    ctx->zcode_dir = zcl_malloc(len, "corpus.pkg.zcode");
    if (!ctx->zcode_dir)
        LOG_FAIL(CENSUS_LOG, "zcode dir alloc");
    (void)snprintf(ctx->zcode_dir, len, "%s/%s/zcode", store_root,
                   def->store);
    if (!package_manifest_load(ctx, def->package_root) ||
        !package_release_find(ctx, def->package_root)) {
        package_ctx_free(ctx);
        return false;
    }
    if (strcmp(ctx->release.license, def->spdx) != 0) {
        LOG_ERROR(CENSUS_LOG,
                  "package %s: def spdx %s != release license %s",
                  def->name, def->spdx, ctx->release.license);
        package_ctx_free(ctx);
        return false;
    }
    return true;
}

/* The package-scope possession root (REPORT ONLY): the evidence root over
 * the sorted unique chunk hashes of the manifest. Every chunk was already
 * re-read and hash-verified during measurement, so a nonzero root here
 * means complete, verified CAS possession. */
bool package_possession_root(const struct package_ctx *ctx, uint8_t out[32])
{
    size_t total = 0;
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        if (!zcl_size_add(total, ctx->manifest.files[i].chunk_count,
                          &total))
            LOG_FAIL(CENSUS_LOG, "chunk count overflow");
    }
    struct buf wire = {0};
    bool ok = true;
    if (total) {
        uint8_t *hashes = zcl_malloc(total * 32u, "corpus.pkg.chunks");
        if (!hashes)
            LOG_FAIL(CENSUS_LOG, "chunk hashes alloc %zu", total);
        size_t n = 0;
        for (size_t i = 0; i < ctx->manifest.count; i++) {
            const struct vcs_package_file *f = &ctx->manifest.files[i];
            memcpy(hashes + n * 32u, f->chunk_hashes,
                   (size_t)f->chunk_count * 32u);
            n += f->chunk_count;
        }
        qsort(hashes, n, 32, cmp_bytes32);
        for (size_t i = 0; i < n; i++) {
            if (i && memcmp(hashes + i * 32u, hashes + (i - 1u) * 32u, 32) == 0)
                continue; /* dedup shared chunks */
            ok = buf_put(&wire, hashes + i * 32u, 32);
            if (!ok) break;
        }
        free(hashes);
    }
    if (ok)
        ok = evidence_root(k_domain_possession, wire.p, wire.len, out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "package possession root failed");
    return true;
}

/* Enumerate a package scope's files from the verified manifest: paths are
 * package-relative, already in canonical ascending order, and tests/ paths
 * carry the tests claim (same classification input as repo scopes). */
bool package_scope_enumerate(const struct package_ctx *ctx,
                             struct scope_files *sf)
{
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        const char *path = ctx->manifest.files[i].path;
        if (!scope_files_push(sf, path, strncmp(path, "tests/", 6) == 0))
            LOG_FAIL(CENSUS_LOG, "package enumeration push failed for %s",
                     path);
    }
    return true;
}

/* Package-scope recipe bind: the RECIPE bit is the release envelope's
 * recipe_root with the recipe wire present in the store and re-rooted
 * (fail closed on mismatch). The dependency closure comes from the
 * package's own zcode-package.json bytes. */
bool package_recipe_bind(const struct scope_def *def, struct scope_measure *m,
                         const struct package_ctx *pkg)
{
    char roothex[65];
    root_hex(pkg->release.recipe_root, roothex);
    size_t plen = strlen(pkg->zcode_dir) + sizeof("/recipes/") + 64u;
    char *path = zcl_malloc(plen, "corpus.pkg.recipe");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "recipe path alloc");
    (void)snprintf(path, plen, "%s/recipes/%s", pkg->zcode_dir, roothex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = store_file_read(path, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                              &wire, &wire_len);
    free(path);
    if (!ok) return false;
    struct vcs_package_recipe recipe;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_parse(wire, wire_len, &recipe);
    free(wire);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        LOG_ERROR(CENSUS_LOG, "package %s: stored recipe fails the grammar",
                  def->name);
        return false;
    }
    uint8_t derived[32];
    rerr = vcs_package_recipe_root(&recipe, derived);
    vcs_package_recipe_free(&recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        memcmp(derived, pkg->release.recipe_root, 32) != 0) {
        LOG_ERROR(CENSUS_LOG,
                  "package %s: stored recipe does not re-root to the "
                  "envelope's recipe_root", def->name);
        return false;
    }
    memcpy(m->recipe_root, pkg->release.recipe_root, 32);
    size_t rlen = strlen(roothex) + sizeof("recipes/");
    m->recipe_path = zcl_malloc(rlen, "corpus.recipe.bound");
    if (!m->recipe_path)
        LOG_FAIL(CENSUS_LOG, "recipe path alloc");
    (void)snprintf(m->recipe_path, rlen, "recipes/%s", roothex);
    m->recipe_is_package = true;
    uint8_t *meta = NULL;
    size_t meta_len = 0;
    uint64_t declared = 0;
    if (!package_file_load(pkg, "zcode-package.json", &meta, &meta_len,
                           &declared) ||
        !meta) {
        LOG_ERROR(CENSUS_LOG, "package %s: cannot read zcode-package.json",
                  def->name);
        free(meta);
        return false;
    }
    ok = dep_closure_bind(m, meta, meta_len, def->name,
                          "zcode-package.json");
    free(meta);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "package %s: dependency closure failed",
                 def->name);
    return true;
}
