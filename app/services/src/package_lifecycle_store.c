/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_lifecycle_store — the READ adapter of the ZCODE install lifecycle.
 * Everything that reads <datadir>/zcode from disk lives here: release
 * envelopes, manifests, recipes, the package's own dependency declaration,
 * and the VERIFIED gate that re-hashes every CAS chunk.
 *
 * Nothing here builds, installs, or executes. Nothing here trusts a name:
 * pkgl_release_for_name only SELECTS a root, and every later step keys on
 * the root. */

#include "package_lifecycle_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "vcs/package_publish.h"

#if !defined(_WIN32)
#include <dirent.h>
#endif
#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

/* ── context ────────────────────────────────────────────────────────── */

struct zcl_result pkgl_ctx_open(struct pkgl_ctx *ctx, const char *datadir)
{
    if (!ctx || !datadir || !datadir[0])
        return ZCL_ERR(-1, "package lifecycle needs a datadir");
    memset(ctx, 0, sizeof(*ctx));
    int n = snprintf(ctx->datadir, sizeof(ctx->datadir), "%s", datadir);
    if (n < 0 || (size_t)n >= sizeof(ctx->datadir))
        return ZCL_ERR(-1, "datadir path too long");
    n = snprintf(ctx->zcode_dir, sizeof(ctx->zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(ctx->zcode_dir))
        return ZCL_ERR(-1, "datadir path too long for <datadir>/zcode");
    ctx->releases = zcl_malloc(
        sizeof(*ctx->releases) * VCS_PACKAGE_PUBLISH_MAX_RELEASES,
        "pkgl.releases");
    if (!ctx->releases)
        return ZCL_ERR(-1, "cannot allocate the release table");
    size_t skipped = 0;
    if (!vcs_package_publish_load_releases(ctx->zcode_dir, ctx->releases,
                                           VCS_PACKAGE_PUBLISH_MAX_RELEASES,
                                           &ctx->release_count, &skipped)) {
        pkgl_ctx_close(ctx);
        return ZCL_ERR(-1, "cannot read %s/releases", ctx->zcode_dir);
    }
    return ZCL_OK;
}

void pkgl_ctx_close(struct pkgl_ctx *ctx)
{
    if (!ctx)
        return;
    free(ctx->releases);
    ctx->releases = NULL;
    ctx->release_count = 0;
}

struct zcl_result pkgl_join(const struct pkgl_ctx *ctx, const char *rel,
                            char *out, size_t cap)
{
    if (!ctx || !rel || !out)
        return ZCL_ERR(-1, "null argument joining a zcode path");
    int n = snprintf(out, cap, "%s/%s", ctx->zcode_dir, rel);
    if (n < 0 || (size_t)n >= cap)
        return ZCL_ERR(-1, "zcode path too long: %s", rel);
    return ZCL_OK;
}

/* ── release selection ──────────────────────────────────────────────── */

const struct vcs_package_release *pkgl_release_for_root(
    const struct pkgl_ctx *ctx, const uint8_t root[32])
{
    if (!ctx || !root)
        return NULL;
    /* Highest publisher_sequence wins when two envelopes name the same root:
     * the acceptance layer already forbids equivocation, so this is only a
     * deterministic tie-break, never a trust decision. */
    const struct vcs_package_release *best = NULL;
    for (size_t i = 0; i < ctx->release_count; i++) {
        const struct vcs_package_release *r = &ctx->releases[i];
        if (memcmp(r->package_root, root, 32) != 0)
            continue;
        if (!best || r->publisher_sequence > best->publisher_sequence)
            best = r;
    }
    return best;
}

/* Compare two semver core triples plus a coarse prerelease rule: a release
 * WITH a prerelease sorts below the same core WITHOUT one. Full semver
 * precedence over prerelease identifiers is not needed to SELECT a root and
 * would add a grammar this layer has no authority over. */
static int pkgl_semver_cmp(const char *a, const char *b)
{
    unsigned long av[3] = { 0, 0, 0 };
    unsigned long bv[3] = { 0, 0, 0 };
    if (sscanf(a, "%lu.%lu.%lu", &av[0], &av[1], &av[2]) != 3)
        return -1;  // raw-return-ok:comparator result (a sorts first), not an error
    if (sscanf(b, "%lu.%lu.%lu", &bv[0], &bv[1], &bv[2]) != 3)
        return 1;
    for (size_t i = 0; i < 3; i++) {
        if (av[i] != bv[i])
            return av[i] < bv[i] ? -1 : 1;
    }
    bool apre = strchr(a, '-') != NULL;
    bool bpre = strchr(b, '-') != NULL;
    if (apre != bpre)
        return apre ? -1 : 1;
    return strcmp(a, b);
}

const struct vcs_package_release *pkgl_release_for_name(
    const struct pkgl_ctx *ctx, const char *name)
{
    if (!ctx || !name || !name[0])
        return NULL;
    const struct vcs_package_release *best = NULL;
    for (size_t i = 0; i < ctx->release_count; i++) {
        const struct vcs_package_release *r = &ctx->releases[i];
        if (strcmp(r->name, name) != 0)
            continue;
        if (!best || pkgl_semver_cmp(r->semver, best->semver) > 0)
            best = r;
    }
    return best;
}

/* ── loaders ────────────────────────────────────────────────────────── */

struct zcl_result pkgl_load_manifest(const struct pkgl_ctx *ctx,
                                     const uint8_t root[32],
                                     struct vcs_package_manifest *out)
{
    if (!ctx || !root || !out)
        return ZCL_ERR(-1, "null argument loading a manifest");
    vcs_package_manifest_init(out);
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    char rel[80];
    (void)snprintf(rel, sizeof(rel), "manifests/%s", hex);
    char path[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_join(ctx, rel, path, sizeof(path)));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZCL_CHECK(pkgl_read_file(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                             &wire_len));
    bool ok = vcs_package_manifest_parse(wire, wire_len, out);
    free(wire);
    if (!ok)
        return ZCL_ERR(-1, "manifest %s does not parse", hex);
    return ZCL_OK;
}

struct zcl_result pkgl_load_recipe(const struct pkgl_ctx *ctx,
                                   const uint8_t recipe_root[32],
                                   struct vcs_package_recipe *out)
{
    if (!ctx || !recipe_root || !out)
        return ZCL_ERR(-1, "null argument loading a recipe");
    vcs_package_recipe_init(out);
    char hex[65];
    zcl_hex_encode(recipe_root, 32, hex);
    char rel[80];
    (void)snprintf(rel, sizeof(rel), "recipes/%s", hex);
    char path[PKGL_PATH_MAX];
    ZCL_CHECK(pkgl_join(ctx, rel, path, sizeof(path)));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZCL_CHECK(pkgl_read_file(path, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &wire,
                             &wire_len));
    enum vcs_package_recipe_error err =
        vcs_package_recipe_parse(wire, wire_len, out);
    free(wire);
    if (err != VCS_PACKAGE_RECIPE_OK)
        return ZCL_ERR(-1, "recipe %s: %s", hex,
                       vcs_package_recipe_error_string(err));
    return ZCL_OK;
}

/* Read one manifest file back out of the CAS by concatenating its committed
 * chunks, verifying each chunk's SHA3 at its exact coordinate. */
static struct zcl_result pkgl_read_member(const struct pkgl_ctx *ctx,
                                          const struct vcs_package_file *file,
                                          uint8_t **out, size_t *len_out)
{
    *out = NULL;
    *len_out = 0;
    if (file->size > VCS_PACKAGE_DEPS_META_MAX_BYTES)
        return ZCL_ERR(-1, "%s is %llu bytes, over the declaration cap",
                       file->path, (unsigned long long)file->size);
    uint8_t *buf = zcl_malloc(file->size ? (size_t)file->size : 1u,
                              "pkgl.member");
    if (!buf)
        return ZCL_ERR(-1, "cannot allocate %s", file->path);
    size_t off = 0;
    for (uint32_t c = 0; c < file->chunk_count; c++) {
        char hex[65];
        zcl_hex_encode(file->chunk_hashes + (size_t)c * 32u, 32, hex);
        char rel[96];
        (void)snprintf(rel, sizeof(rel), "cas/sha3/%.2s/%s", hex, hex);
        char path[PKGL_PATH_MAX];
        struct zcl_result jr = pkgl_join(ctx, rel, path, sizeof(path));
        if (!jr.ok) {
            free(buf);
            return jr;
        }
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        struct zcl_result rr =
            pkgl_read_file(path, VCS_PACKAGE_CHUNK_BYTES, &chunk, &chunk_len);
        if (!rr.ok) {
            free(buf);
            return rr;
        }
        if (!vcs_package_verify_chunk(file, c, chunk, chunk_len) ||
            off + chunk_len > (size_t)file->size) {
            free(chunk);
            free(buf);
            return ZCL_ERR(-1, "chunk %s#%u does not match its committed hash",
                           file->path, c);
        }
        memcpy(buf + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (off != (size_t)file->size) {
        free(buf);
        return ZCL_ERR(-1, "%s reassembled to %zu of %llu bytes", file->path,
                       off, (unsigned long long)file->size);
    }
    *out = buf;
    *len_out = off;
    return ZCL_OK;
}

struct zcl_result pkgl_load_declared_deps(const struct pkgl_ctx *ctx,
                                          const uint8_t root[32],
                                          struct vcs_package_deps *out)
{
    if (!ctx || !root || !out)
        return ZCL_ERR(-1, "null argument loading declared dependencies");
    vcs_package_deps_init(out);
    struct vcs_package_manifest manifest;
    ZCL_CHECK(pkgl_load_manifest(ctx, root, &manifest));
    const struct vcs_package_file *meta = NULL;
    for (size_t i = 0; i < manifest.count; i++)
        if (strcmp(manifest.files[i].path, VCS_PACKAGE_DEPS_META_PATH) == 0)
            meta = &manifest.files[i];
    if (!meta) {
        /* No declaration file: the package declares no dependencies. */
        vcs_package_manifest_free(&manifest);
        return ZCL_OK;
    }
    uint8_t *text = NULL;
    size_t text_len = 0;
    struct zcl_result rr = pkgl_read_member(ctx, meta, &text, &text_len);
    if (!rr.ok) {
        vcs_package_manifest_free(&manifest);
        return rr;
    }
    char detail[160];
    detail[0] = '\0';
    enum vcs_package_deps_error err =
        vcs_package_deps_parse_meta(text, text_len, out, detail,
                                    sizeof(detail));
    free(text);
    vcs_package_manifest_free(&manifest);
    if (err != VCS_PACKAGE_DEPS_OK)
        return ZCL_ERR(-1, "%s: %s%s%s", VCS_PACKAGE_DEPS_META_PATH,
                       vcs_package_deps_error_string(err),
                       detail[0] ? " " : "", detail);
    return ZCL_OK;
}

/* ── survey + verify ────────────────────────────────────────────────── */

/* Reassemble one package's full source tree from the CAS. Every chunk is
 * re-verified against the hash committed at its exact manifest coordinate
 * before its bytes land on disk (the same gate pkgl_read_member applies to
 * the declaration file), and the manifest must re-hash to the requested
 * root before anything is written — so a tampered store object can never
 * reach the tree a rebuild compiles. Files land read-only (0444), matching
 * the worker's own materialization discipline. */
struct zcl_result pkgl_materialize_package(const struct pkgl_ctx *ctx,
                                           const uint8_t root[32],
                                           const char *destination)
{
    if (!ctx || !root || !destination || !destination[0])
        return ZCL_ERR(-1, "null argument materializing a package");
#if defined(_WIN32)
    return ZCL_ERR(-1, "package materialization is disabled on Windows until "
                       "the sandbox and immutable staging lane qualify");
#else
    struct vcs_package_manifest manifest;
    ZCL_CHECK(pkgl_load_manifest(ctx, root, &manifest));
    uint8_t derived[32];
    if (!vcs_package_manifest_root(&manifest, derived) ||
        memcmp(derived, root, 32) != 0) {
        vcs_package_manifest_free(&manifest);
        return ZCL_ERR(-1, "the stored manifest does not re-hash to the "
                           "requested package root");
    }
    struct zcl_result res = pkgl_mkdir_p(destination);
    for (size_t i = 0; res.ok && i < manifest.count; i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        char dest[PKGL_PATH_MAX];
        int n = snprintf(dest, sizeof(dest), "%s/%s", destination, f->path);
        if (n <= 0 || (size_t)n >= sizeof(dest)) {
            res = ZCL_ERR(-1, "materialized path too long: %s", f->path);
            break;
        }
        char parent[PKGL_PATH_MAX];
        (void)snprintf(parent, sizeof(parent), "%s", dest);
        char *slash = strrchr(parent, '/');
        if (slash) {
            *slash = '\0';
            res = pkgl_mkdir_p(parent);
        }
        int fd = -1;
        if (res.ok) {
            fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0444);
            if (fd < 0)
                res = ZCL_ERR(-1, "open %s: %s", dest, strerror(errno));
        }
        uint64_t wrote = 0;
        for (uint32_t c = 0; res.ok && c < f->chunk_count; c++) {
            char hex[65];
            zcl_hex_encode(f->chunk_hashes + (size_t)c * 32u, 32, hex);
            char rel[96];
            (void)snprintf(rel, sizeof(rel), "cas/sha3/%.2s/%s", hex, hex);
            char path[PKGL_PATH_MAX];
            res = pkgl_join(ctx, rel, path, sizeof(path));
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            if (res.ok)
                res = pkgl_read_file(path, VCS_PACKAGE_CHUNK_BYTES, &chunk,
                                     &chunk_len);
            if (res.ok &&
                !vcs_package_verify_chunk(f, c, chunk, chunk_len))
                res = ZCL_ERR(-1, "chunk %s#%u does not match its committed "
                                  "hash", f->path, c);
            size_t off = 0;
            while (res.ok && off < chunk_len) {
                ssize_t w = write(fd, chunk + off, chunk_len - off);
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    res = ZCL_ERR(-1, "write %s: %s", dest, strerror(errno));
                    break;
                }
                off += (size_t)w;
            }
            wrote += off;
            free(chunk);
        }
        if (fd >= 0 && close(fd) != 0 && res.ok)
            res = ZCL_ERR(-1, "close %s: %s", dest, strerror(errno));
        if (res.ok && wrote != f->size)
            res = ZCL_ERR(-1, "%s materialized to %llu of %llu committed "
                              "bytes", f->path, (unsigned long long)wrote,
                          (unsigned long long)f->size);
    }
    vcs_package_manifest_free(&manifest);
    return res;
#endif
}

struct zcl_result pkgl_survey_package(const struct pkgl_ctx *ctx,
                                      const uint8_t root[32],
                                      bool *complete_out,
                                      uint64_t *bytes_out,
                                      uint32_t *chunks_out)
{
    if (!ctx || !root || !complete_out || !bytes_out || !chunks_out)
        return ZCL_ERR(-1, "null argument surveying a package");
    *complete_out = false;
    *bytes_out = 0;
    *chunks_out = 0;
    struct vcs_package_manifest manifest;
    ZCL_CHECK(pkgl_load_manifest(ctx, root, &manifest));
    bool complete = true;
    for (size_t i = 0; i < manifest.count; i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        *bytes_out += f->size;
        *chunks_out += f->chunk_count;
        for (uint32_t c = 0; c < f->chunk_count && complete; c++) {
            char hex[65];
            zcl_hex_encode(f->chunk_hashes + (size_t)c * 32u, 32, hex);
            char rel[96];
            (void)snprintf(rel, sizeof(rel), "cas/sha3/%.2s/%s", hex, hex);
            char path[PKGL_PATH_MAX];
            struct zcl_result jr = pkgl_join(ctx, rel, path, sizeof(path));
            if (!jr.ok) {
                vcs_package_manifest_free(&manifest);
                return jr;
            }
            bool present = false;
            struct zcl_result er = pkgl_exists(path, &present);
            if (!er.ok) {
                vcs_package_manifest_free(&manifest);
                return er;
            }
            if (!present)
                complete = false;
        }
    }
    vcs_package_manifest_free(&manifest);
    *complete_out = complete;
    return ZCL_OK;
}

// long-function-ok:one-verified-gate — the VERIFIED transition is one
// decision (envelope, manifest root, recipe binding, every chunk re-hashed);
// splitting it would let a caller reach a build having run only part of it.
struct zcl_result pkgl_verify_package(const struct pkgl_ctx *ctx,
                                      const uint8_t root[32], char *rule_out,
                                      size_t rule_cap)
{
    if (!ctx || !root)
        return ZCL_ERR(-1, "null argument verifying a package");
    if (rule_out && rule_cap)
        rule_out[0] = '\0';
    char hex[65];
    zcl_hex_encode(root, 32, hex);

    const struct vcs_package_release *release = pkgl_release_for_root(ctx, root);
    if (!release) {
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "release-missing");
        return ZCL_ERR(-1, "no release envelope names package root %s", hex);
    }
    enum vcs_package_release_error rerr = vcs_package_release_verify(release);
    if (rerr != VCS_PACKAGE_RELEASE_OK) {
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "release-verify");
        return ZCL_ERR(-1, "release for %s: %s", hex,
                       vcs_package_release_error_string(rerr));
    }

    struct vcs_package_manifest manifest;
    struct zcl_result mr = pkgl_load_manifest(ctx, root, &manifest);
    if (!mr.ok) {
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "manifest-missing");
        return mr;
    }
    uint8_t recomputed[32] = { 0 };
    if (!vcs_package_manifest_root(&manifest, recomputed) ||
        memcmp(recomputed, root, 32) != 0) {
        vcs_package_manifest_free(&manifest);
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "manifest-root-mismatch");
        return ZCL_ERR(-1, "manifest under %s does not hash to that root",
                       hex);
    }

    struct vcs_package_recipe recipe;
    struct zcl_result rr =
        pkgl_load_recipe(ctx, release->recipe_root, &recipe);
    if (!rr.ok) {
        vcs_package_manifest_free(&manifest);
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "recipe-missing");
        return rr;
    }
    uint8_t recipe_root[32] = { 0 };
    if (vcs_package_recipe_root(&recipe, recipe_root) !=
            VCS_PACKAGE_RECIPE_OK ||
        memcmp(recipe_root, release->recipe_root, 32) != 0) {
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "recipe-root-mismatch");
        return ZCL_ERR(-1, "recipe does not hash to the envelope's "
                           "recipe_root for %s", hex);
    }
    char membership[160];
    if (!vcs_package_recipe_files_in_manifest(&recipe, &manifest, membership,
                                              sizeof(membership))) {
        vcs_package_recipe_free(&recipe);
        vcs_package_manifest_free(&manifest);
        if (rule_out)
            (void)snprintf(rule_out, rule_cap, "recipe-path-not-in-manifest");
        return ZCL_ERR(-1, "%s", membership);
    }
    vcs_package_recipe_free(&recipe);

    /* Every chunk, re-hashed from the CAS bytes at its exact coordinates.
     * This is the gate a tampered store object cannot pass. */
    for (size_t i = 0; i < manifest.count; i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            char chex[65];
            zcl_hex_encode(f->chunk_hashes + (size_t)c * 32u, 32, chex);
            char rel[96];
            (void)snprintf(rel, sizeof(rel), "cas/sha3/%.2s/%s", chex, chex);
            char path[PKGL_PATH_MAX];
            struct zcl_result jr = pkgl_join(ctx, rel, path, sizeof(path));
            if (!jr.ok) {
                vcs_package_manifest_free(&manifest);
                return jr;
            }
            uint8_t *bytes = NULL;
            size_t bytes_len = 0;
            struct zcl_result br = pkgl_read_file(
                path, VCS_PACKAGE_CHUNK_BYTES, &bytes, &bytes_len);
            if (!br.ok) {
                vcs_package_manifest_free(&manifest);
                if (rule_out)
                    (void)snprintf(rule_out, rule_cap, "chunk-missing");
                return br;
            }
            bool good = vcs_package_verify_chunk(f, c, bytes, bytes_len);
            free(bytes);
            if (!good) {
                if (rule_out)
                    (void)snprintf(rule_out, rule_cap, "chunk-hash-mismatch");
                /* Format while f->path is still owned by manifest; the
                 * zcl_result copies the message into its fixed buffer. */
                struct zcl_result result = ZCL_ERR(
                    -1, "chunk %s#%u of %s does not match its committed "
                        "SHA3 — refusing to build tampered content",
                    f->path, c, hex);
                vcs_package_manifest_free(&manifest);
                return result;
            }
        }
    }
    vcs_package_manifest_free(&manifest);
    return ZCL_OK;
}

/* ── filesystem primitives ──────────────────────────────────────────── */

struct zcl_result pkgl_mkdir_p(const char *path)
{
    if (!path || !path[0])
        return ZCL_ERR(-1, "null directory path");
#if defined(_WIN32)
    return ZCL_ERR(-1, "package store directory mutation is disabled on Windows");
#else
    char buf[PKGL_PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(buf))
        return ZCL_ERR(-1, "directory path too long");
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return ZCL_ERR(-1, "mkdir %s: %s", buf, strerror(errno));
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return ZCL_ERR(-1, "mkdir %s: %s", buf, strerror(errno));
    return ZCL_OK;
#endif
}

struct zcl_result pkgl_rm_rf(const char *path)
{
    if (!path || !path[0])
        return ZCL_ERR(-1, "null path to remove");
#if defined(_WIN32)
    return ZCL_ERR(-1, "package store removal is disabled on Windows");
#else
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? ZCL_OK
                               : ZCL_ERR(-1, "lstat %s: %s", path,
                                         strerror(errno));
    if (!S_ISDIR(st.st_mode)) {
        if (unlink(path) != 0)
            return ZCL_ERR(-1, "unlink %s: %s", path, strerror(errno));
        return ZCL_OK;
    }
    DIR *dir = opendir(path);
    if (!dir)
        return ZCL_ERR(-1, "opendir %s: %s", path, strerror(errno));
    struct zcl_result res = ZCL_OK;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PKGL_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            res = ZCL_ERR(-1, "path too long under %s", path);
            continue;
        }
        struct zcl_result cr = pkgl_rm_rf(child);
        if (!cr.ok)
            res = cr;
    }
    closedir(dir);
    if (rmdir(path) != 0 && res.ok)
        res = ZCL_ERR(-1, "rmdir %s: %s", path, strerror(errno));
    return res;
#endif
}

struct zcl_result pkgl_read_file(const char *path, size_t cap, uint8_t **out,
                                 size_t *len_out)
{
    if (!path || !out || !len_out)
        return ZCL_ERR(-1, "null argument reading a file");
    *out = NULL;
    *len_out = 0;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    uint64_t file_size = 0;
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_size(&file, &file_size)) {
        platform_positioned_file_close(&file);
        return ZCL_ERR(-1, "%s: refused, missing, or not a regular file", path);
    }
    if (file_size > cap || file_size > SIZE_MAX) {
        platform_positioned_file_close(&file);
        return ZCL_ERR(-1, "%s: not a regular file within %zu bytes", path,
                       cap);
    }
    size_t len = (size_t)file_size;
    uint8_t *buf = zcl_malloc(len ? len : 1u, "pkgl.read_file");
    if (!buf)
        return ZCL_ERR(-1, "cannot allocate %zu bytes for %s", len, path);
    if (len > 0 && platform_positioned_file_read(&file, buf, len, 0) !=
                       (int64_t)len) {
        platform_positioned_file_close(&file);
        free(buf);
        return ZCL_ERR(-1, "short read on %s", path);
    }
    platform_positioned_file_close(&file);
    *out = buf;
    *len_out = len;
    return ZCL_OK;
}

struct zcl_result pkgl_write_atomic(const char *path, const uint8_t *data,
                                    size_t len)
{
    if (!path || (!data && len))
        return ZCL_ERR(-1, "null argument writing a file");
#if defined(_WIN32)
    return ZCL_ERR(-1, "package store writes are disabled on Windows");
#else
    char tmp[PKGL_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.zpltmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return ZCL_ERR(-1, "temp path too long for %s", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return ZCL_ERR(-1, "open %s: %s", tmp, strerror(errno));
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            close(fd);
            unlink(tmp);
            return ZCL_ERR(-1, "write %s: %s", tmp, strerror(e));
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        return ZCL_ERR(-1, "durable write of %s failed: %s", path,
                       strerror(e));
    }
    return ZCL_OK;
#endif
}

struct zcl_result pkgl_sha3_file(const char *path, uint8_t out[32],
                                 uint64_t *bytes_out)
{
    if (!path || !out || !bytes_out)
        return ZCL_ERR(-1, "null argument hashing a file");
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return ZCL_ERR(-1, "open %s: refused, missing, or not regular", path);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[65536];
    uint64_t total = 0;
    uint64_t offset = 0;
    int64_t got;
    while ((got = platform_positioned_file_read(&file, buf, sizeof(buf),
                                                 offset)) > 0) {
        sha3_256_write(&ctx, buf, got);
        total += (uint64_t)got;
        offset += (uint64_t)got;
    }
    platform_positioned_file_close(&file);
    if (got < 0)
        return ZCL_ERR(-1, "read error hashing %s", path);
    sha3_256_finalize(&ctx, out);
    *bytes_out = total;
    return ZCL_OK;
}

/* EXISTENCE OF ANY OBJECT, NOT REGULARITY OF A FILE. Most callers probe
 * installed/<root>, which is a DIRECTORY -- "is this package installed?" is
 * the single most common question asked here. platform_file_metadata_read()
 * deliberately answers REFUSED for everything that is not a regular file, so
 * routing this probe through it alone turns an installed package into a hard
 * lifecycle error and makes every plan over an installed root fail. Keep the
 * regular-file probe for the platforms that have nothing better, and use the
 * exact kind-agnostic lstat elsewhere. */
struct zcl_result pkgl_exists(const char *path, bool *out)
{
    if (!path || !out)
        return ZCL_ERR(-1, "null argument probing a path");
#if defined(_WIN32)
    struct platform_file_metadata metadata;
    enum platform_file_metadata_result result =
        platform_file_metadata_read(path, &metadata);
    *out = result != PLATFORM_FILE_METADATA_MISSING;
    return ZCL_OK;
#else
    struct stat st;
    if (lstat(path, &st) == 0) {
        *out = true;
        return ZCL_OK;
    }
    *out = false;
    if (errno == ENOENT || errno == ENOTDIR)
        return ZCL_OK;
    return ZCL_ERR(-1, "lstat %s: %s", path, strerror(errno));
#endif
}

struct zcl_result pkgl_installed_dir(const struct pkgl_ctx *ctx,
                                     const uint8_t root[32], char *out,
                                     size_t cap)
{
    if (!ctx || !root || !out)
        return ZCL_ERR(-1, "null argument building an install path");
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    char rel[96];
    (void)snprintf(rel, sizeof(rel), "installed/%s", hex);
    return pkgl_join(ctx, rel, out, cap);
}
