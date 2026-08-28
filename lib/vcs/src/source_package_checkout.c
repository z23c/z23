/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Git-free reconstruction of verified PROVEN source carriers. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "vcs/source_package_checkout.h"

#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs.h"
#include "vcs/zcode_accepted_work_bundle.h"
#include "vcs/zcode_lane.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define SOURCE_CHECKOUT_PATH_MAX 4400
#define SOURCE_CHECKOUT_AUTHORITY_MAX 4096u

struct source_checkout_loaded {
    struct vcs_package_manifest package;
    struct vcs_source_bundle_sharded source;
    uint8_t *license;
    size_t license_len;
    uint8_t *authority;
    size_t authority_len;
    uint8_t *offline[VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX];
    size_t offline_len[VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX];
    size_t offline_count;
};

const char *vcs_source_package_checkout_result_string(
    enum vcs_source_package_checkout_result result)
{
    switch (result) {
    case VCS_SOURCE_PACKAGE_CHECKOUT_OK: return "ok";
    case VCS_SOURCE_PACKAGE_CHECKOUT_NULL: return "null-argument";
    case VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE: return "package-incomplete";
    case VCS_SOURCE_PACKAGE_CHECKOUT_MANIFEST: return "package-manifest";
    case VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE: return "source-carrier-shape";
    case VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK: return "package-chunk";
    case VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE: return "source-verification";
    case VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION: return "destination";
    }
    return "unknown";
}

static void source_checkout_loaded_init(struct source_checkout_loaded *loaded)
{
    memset(loaded, 0, sizeof(*loaded));
    vcs_package_manifest_init(&loaded->package);
    vcs_source_bundle_sharded_init(&loaded->source);
}

static void source_checkout_loaded_free(struct source_checkout_loaded *loaded)
{
    if (!loaded) return;
    vcs_package_manifest_free(&loaded->package);
    vcs_source_bundle_sharded_free(&loaded->source);
    free(loaded->license);
    free(loaded->authority);
    for (size_t i = 0; i < VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX; i++)
        free(loaded->offline[i]);
    memset(loaded, 0, sizeof(*loaded));
}

static int source_checkout_file_index(
    const struct vcs_package_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->files[mid].path, path);
        if (cmp == 0) return (int)mid;
        if (cmp < 0) lo = mid + 1u; else hi = mid;
    }
    return -1;
}

static bool source_checkout_read_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *manifest, size_t index,
    uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    if (index >= manifest->count || manifest->files[index].size > SIZE_MAX)
        return false;
    const struct vcs_package_file *file = &manifest->files[index];
    size_t len = (size_t)file->size;
    uint8_t *bytes = len > 0
        ? zcl_malloc(len, "vcs.source_checkout.file") : NULL;
    if (len > 0 && !bytes) return false;
    size_t off = 0;
    for (uint32_t i = 0; i < file->chunk_count; i++) {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        enum vcs_package_store_result got = vcs_package_store_get_chunk_at(
            store, package_root, (uint32_t)index, i, &chunk, &chunk_len);
        bool ok = got == VCS_PACKAGE_STORE_OK &&
            vcs_package_verify_chunk(file, i, chunk, chunk_len) &&
            off <= len && chunk_len <= len - off;
        if (!ok) {
            free(chunk); free(bytes); return false;
        }
        memcpy(bytes + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (off != len) { free(bytes); return false; }
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

#if !defined(_WIN32)
static bool source_checkout_shard_index(const char *path, uint16_t *index_out)
{
    static const char prefix[] = "zclassic23-source/shard-";
    size_t prefix_len = sizeof(prefix) - 1u;
    if (!path || strlen(path) != prefix_len + 2u + 5u ||
        strncmp(path, prefix, prefix_len) != 0 ||
        strcmp(path + prefix_len + 2u, ".zvss") != 0)
        return false;
    unsigned value = 0;
    for (size_t i = 0; i < 2u; i++) {
        unsigned char c = (unsigned char)path[prefix_len + i];
        unsigned digit = c >= (unsigned char)'0' &&
                c <= (unsigned char)'9'
            ? (unsigned)(c - (unsigned char)'0')
            : c >= (unsigned char)'a' && c <= (unsigned char)'f'
                ? (unsigned)(c - (unsigned char)'a') + 10u : 16u;
        if (digit >= 16u) return false;
        value = value * 16u + digit;
    }
    char canonical[VCS_SOURCE_BUNDLE_SHARD_PATH_MAX];
    if (!vcs_source_bundle_shard_path(
            (uint16_t)value, canonical, sizeof(canonical)) ||
        strcmp(canonical, path) != 0)
        return false;
    *index_out = (uint16_t)value;
    return true;
}

static int source_checkout_offline_index(const char *path)
{
    for (size_t i = 0; i < vcs_source_package_offline_input_count(); i++)
        if (strcmp(path, vcs_source_package_offline_input_path(i)) == 0)
            return (int)i;
    return -1;
}
#endif

static enum vcs_source_package_checkout_result source_checkout_manifest(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct source_checkout_loaded *loaded)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &wire, &wire_len) != VCS_PACKAGE_STORE_OK)
        return VCS_SOURCE_PACKAGE_CHECKOUT_MANIFEST;
    bool parsed = vcs_package_manifest_parse(
        wire, wire_len, &loaded->package);
    free(wire);
    uint8_t checked[32];
    if (!parsed ||
        !vcs_package_manifest_root(&loaded->package, checked) ||
        memcmp(checked, package_root, 32) != 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_MANIFEST;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

#if !defined(_WIN32)
static enum vcs_source_package_checkout_result source_checkout_load_fixed(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32],
    struct source_checkout_loaded *loaded)
{
    const char *fixed[] = {
        VCS_SOURCE_PACKAGE_LICENSE_PATH,
        VCS_SOURCE_PACKAGE_MANIFEST_PATH,
        VCS_SOURCE_PACKAGE_LANE_PATH,
        VCS_SOURCE_PACKAGE_MARKER_PATH,
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (source_checkout_file_index(&loaded->package, fixed[i]) < 0)
            return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    int authority_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH);
    if (accepted_work_root && authority_index < 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    if (!accepted_work_root && authority_index >= 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    int manifest_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_MANIFEST_PATH);
    if (!source_checkout_read_file(
            store, package_root, &loaded->package, (size_t)manifest_index,
            &loaded->source.manifest_wire,
            &loaded->source.manifest_wire_len))
        return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    int license_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_LICENSE_PATH);
    if (!source_checkout_read_file(
            store, package_root, &loaded->package, (size_t)license_index,
            &loaded->license, &loaded->license_len))
        return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    if (!vcs_package_release_license_text_allowed(
            loaded->license, loaded->license_len))
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    int lane_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_LANE_PATH);
    const struct vcs_package_file *lane = &loaded->package.files[lane_index];
    if (lane->size != VCS_ZCODE_LANE_WIRE_BYTES ||
        lane->size > SOURCE_CHECKOUT_AUTHORITY_MAX)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    struct vcs_zcode_lane_receipt_v1 receipt;
    uint8_t lane_root[32];
    bool proven = source_checkout_read_file(
            store, package_root, &loaded->package, (size_t)lane_index,
            &lane_wire, &lane_wire_len) &&
        vcs_zcode_lane_receipt_parse(lane_wire, lane_wire_len, &receipt) ==
            VCS_ZCODE_DEV_OK && receipt.lane == VCS_ZCODE_LANE_PROVEN &&
        vcs_zcode_lane_receipt_id(&receipt, lane_root) == VCS_ZCODE_DEV_OK &&
        ((!accepted_work_root && expected_signer &&
          vcs_zcode_lane_receipt_verify(&receipt, expected_signer) ==
              VCS_ZCODE_DEV_OK) ||
         (accepted_work_root &&
          memcmp(lane_root, accepted_work_root, 32) == 0));
    free(lane_wire);
    if (!proven) return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    if (memcmp(receipt.source_root, source_root, 32) != 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    int marker_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_MARKER_PATH);
    uint8_t *marker = NULL;
    size_t marker_len = 0, expected_marker_len = 0;
    const uint8_t *expected_marker =
        vcs_source_package_transport_marker(&expected_marker_len);
    bool marker_ok = source_checkout_read_file(
            store, package_root, &loaded->package, (size_t)marker_index,
            &marker, &marker_len) && marker_len == expected_marker_len &&
        memcmp(marker, expected_marker, marker_len) == 0;
    free(marker);
    if (!marker_ok) return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    if (accepted_work_root &&
        !source_checkout_read_file(
            store, package_root, &loaded->package,
            (size_t)authority_index, &loaded->authority,
            &loaded->authority_len))
        return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_load_variable(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool has_authority, struct source_checkout_loaded *loaded)
{
    bool seen_shards[256] = {0};
    bool seen_offline[VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX] = {0};
    size_t offline_count = 0;
    size_t recognized = has_authority ? 5u : 4u;
    for (size_t i = 0; i < loaded->package.count; i++) {
        const char *path = loaded->package.files[i].path;
        uint16_t shard = 0;
        int offline = source_checkout_offline_index(path);
        if (source_checkout_shard_index(path, &shard)) {
            if (seen_shards[shard] ||
                loaded->source.shard_count >= 256u)
                return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
            seen_shards[shard] = true;
            struct vcs_source_bundle_shard *part =
                &loaded->source.shards[loaded->source.shard_count];
            part->index = shard;
            if (!source_checkout_read_file(
                    store, package_root, &loaded->package, i,
                    &part->wire, &part->wire_len))
                return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
            loaded->source.shard_count++;
            recognized++;
        } else if (offline >= 0) {
            if (seen_offline[offline] ||
                !source_checkout_read_file(
                    store, package_root, &loaded->package, i,
                    &loaded->offline[offline],
                    &loaded->offline_len[offline]))
                return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
            seen_offline[offline] = true;
            offline_count++;
            recognized++;
        }
    }
    size_t expected_offline = vcs_source_package_offline_input_count();
    if (offline_count != 0 && offline_count != expected_offline)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    for (size_t i = 0; offline_count > 0 && i < expected_offline; i++)
        if (!seen_offline[i]) return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    loaded->offline_count = offline_count;
    return recognized == loaded->package.count &&
           loaded->source.shard_count > 0
        ? VCS_SOURCE_PACKAGE_CHECKOUT_OK
        : VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
}

static bool source_checkout_empty_dir(const char *path)
{
#if defined(_WIN32)
    (void)path;
    return false;
#else
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool empty = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = false; break;
        }
    }
    return closedir(dir) == 0 && empty;
#endif
}

static bool source_checkout_write(const char *path, const uint8_t *bytes,
                                  size_t len)
{
#if defined(_WIN32)
    (void)path;
    (void)bytes;
    (void)len;
    return false;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool ok = off == len && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok) (void)unlink(path);
    return ok;
#endif
}

static bool source_checkout_write_offline(
    const char *destination, const struct source_checkout_loaded *loaded,
    uint64_t *bytes_out)
{
#if defined(_WIN32)
    (void)destination;
    (void)loaded;
    if (bytes_out) *bytes_out = 0;
    return false;
#else
    if (loaded->offline_count == 0) {
        *bytes_out = 0;
        return true;
    }
    if (loaded->offline_count != vcs_source_package_offline_input_count())
        return false;
    char cache[SOURCE_CHECKOUT_PATH_MAX];
    int n = snprintf(cache, sizeof(cache), "%s/vendor/.cache", destination);
    if (n <= 0 || (size_t)n >= sizeof(cache) ||
        !zcl_mkdir_p(cache, 0700).ok)
        return false;
    uint64_t total = 0;
    for (size_t i = 0; i < vcs_source_package_offline_input_count(); i++) {
        const char *relative = vcs_source_package_offline_input_path(i);
        char path[SOURCE_CHECKOUT_PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/%s", destination, relative);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            UINT64_MAX - total < loaded->offline_len[i] ||
            !source_checkout_write(
                path, loaded->offline[i], loaded->offline_len[i]))
            return false;
        total += loaded->offline_len[i];
    }
    *bytes_out = total;
    return true;
#endif
}

#endif /* !_WIN32: checkout publication helpers */

enum vcs_source_package_checkout_result
vcs_source_package_accepted_work_discover(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], uint8_t accepted_work_root[32])
{
    if (accepted_work_root)
        memset(accepted_work_root, 0, 32);
    if (!store || !package_root || !source_root || !accepted_work_root)
        return VCS_SOURCE_PACKAGE_CHECKOUT_NULL;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE;
    struct source_checkout_loaded loaded;
    source_checkout_loaded_init(&loaded);
    enum vcs_source_package_checkout_result result =
        source_checkout_manifest(store, package_root, &loaded);
    int lane_index = -1;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK) {
        lane_index = source_checkout_file_index(
            &loaded.package, VCS_SOURCE_PACKAGE_LANE_PATH);
        int authority_index = source_checkout_file_index(
            &loaded.package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH);
        if (lane_index < 0 || authority_index < 0 ||
            loaded.package.files[lane_index].size !=
                VCS_ZCODE_LANE_WIRE_BYTES ||
            loaded.package.files[authority_index].size == 0 ||
            loaded.package.files[authority_index].size >
                VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES)
            result = VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    }
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        !source_checkout_read_file(
            store, package_root, &loaded.package, (size_t)lane_index,
            &lane_wire, &lane_wire_len))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    struct vcs_zcode_lane_receipt_v1 receipt;
    uint8_t discovered[32];
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        (vcs_zcode_lane_receipt_parse(
             lane_wire, lane_wire_len, &receipt) != VCS_ZCODE_DEV_OK ||
         receipt.lane != VCS_ZCODE_LANE_PROVEN ||
         memcmp(receipt.source_root, source_root, 32) != 0 ||
         vcs_zcode_lane_receipt_id(&receipt, discovered) !=
             VCS_ZCODE_DEV_OK))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        memcpy(accepted_work_root, discovered, 32);
    free(lane_wire);
    source_checkout_loaded_free(&loaded);
    return result;
}

static enum vcs_source_package_checkout_result source_package_checkout_common(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32],
    const char *workspace,
    const char *destination,
    struct vcs_source_package_checkout_metrics *metrics)
{
    if (metrics) memset(metrics, 0, sizeof(*metrics));
    if (!store || !package_root || !source_root ||
        (!expected_signer && !accepted_work_root) ||
        (expected_signer && accepted_work_root) || !workspace || !destination)
        return VCS_SOURCE_PACKAGE_CHECKOUT_NULL;
#if defined(_WIN32)
    /* Publication is intentionally disabled until tree materialization is
     * backed by a retained directory-relative capability. Refuse before
     * probing either caller-supplied path or reading package-store state. */
    return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
#else
    if (!source_checkout_empty_dir(destination))
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE;
    struct source_checkout_loaded loaded;
    source_checkout_loaded_init(&loaded);
    enum vcs_source_package_checkout_result result =
        source_checkout_manifest(store, package_root, &loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_load_fixed(
            store, package_root, source_root, expected_signer,
            accepted_work_root, &loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_load_variable(
            store, package_root, accepted_work_root != NULL, &loaded);
    struct vcs_source_bundle_metrics source_metrics;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        vcs_source_bundle_sharded_verify(
            &loaded.source, source_root, &source_metrics) !=
            VCS_SOURCE_BUNDLE_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        vcs_source_bundle_sharded_import(
            &loaded.source, source_root, workspace, &source_metrics) !=
            VCS_SOURCE_BUNDLE_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    struct vcs_zcode_accepted_work_v1 accepted;
    uint32_t authority_objects = 0, work_receipts = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK && accepted_work_root &&
        vcs_zcode_accepted_work_bundle_import(
            workspace, accepted_work_root, source_root,
            loaded.authority, loaded.authority_len, &accepted,
            &authority_objects, &work_receipts) !=
                VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    uint64_t offline_bytes = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        vcs_tree_materialize(
            workspace, source_root, destination,
            VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        !source_checkout_write_offline(
            destination, &loaded, &offline_bytes))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK && metrics) {
        metrics->source = source_metrics;
        metrics->offline_input_bytes = offline_bytes;
        metrics->offline_input_files = (uint32_t)loaded.offline_count;
        metrics->source_shards = (uint32_t)loaded.source.shard_count;
        metrics->carrier_files = (uint32_t)loaded.package.count;
        metrics->authority_objects = authority_objects;
        metrics->work_receipts = work_receipts;
        if (accepted_work_root)
            memcpy(metrics->accepted_signer,
                   accepted.expected_signer, 32);
    }
    source_checkout_loaded_free(&loaded);
    return result;
#endif
}

enum vcs_source_package_checkout_result vcs_source_package_checkout(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const char *workspace, const char *destination,
    struct vcs_source_package_checkout_metrics *metrics)
{
    return source_package_checkout_common(
        store, package_root, source_root, expected_signer, NULL,
        workspace, destination, metrics);
}

enum vcs_source_package_checkout_result
vcs_source_package_checkout_accepted(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t accepted_work_root[32],
    const char *workspace, const char *destination,
    struct vcs_source_package_checkout_metrics *metrics)
{
    return source_package_checkout_common(
        store, package_root, source_root, NULL, accepted_work_root,
        workspace, destination, metrics);
}

#if !defined(_WIN32)
static enum vcs_source_package_checkout_result
source_package_identity_discover(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint8_t source_root[32], uint8_t accepted_work_root[32])
{
    memset(source_root, 0, 32);
    memset(accepted_work_root, 0, 32);
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE;
    struct source_checkout_loaded loaded;
    source_checkout_loaded_init(&loaded);
    enum vcs_source_package_checkout_result result =
        source_checkout_manifest(store, package_root, &loaded);
    int lane_index = result == VCS_SOURCE_PACKAGE_CHECKOUT_OK
        ? source_checkout_file_index(
              &loaded.package, VCS_SOURCE_PACKAGE_LANE_PATH) : -1;
    int authority_index = result == VCS_SOURCE_PACKAGE_CHECKOUT_OK
        ? source_checkout_file_index(
              &loaded.package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH) : -1;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        (lane_index < 0 || authority_index < 0 ||
         loaded.package.files[lane_index].size != VCS_ZCODE_LANE_WIRE_BYTES ||
         loaded.package.files[authority_index].size == 0 ||
         loaded.package.files[authority_index].size >
             VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        !source_checkout_read_file(
            store, package_root, &loaded.package, (size_t)lane_index,
            &lane_wire, &lane_wire_len))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    struct vcs_zcode_lane_receipt_v1 lane;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        (vcs_zcode_lane_receipt_parse(lane_wire, lane_wire_len, &lane) !=
             VCS_ZCODE_DEV_OK ||
         lane.lane != VCS_ZCODE_LANE_PROVEN ||
         vcs_zcode_lane_receipt_id(&lane, accepted_work_root) !=
             VCS_ZCODE_DEV_OK))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        memcpy(source_root, lane.source_root, 32);
    else {
        memset(source_root, 0, 32);
        memset(accepted_work_root, 0, 32);
    }
    free(lane_wire);
    source_checkout_loaded_free(&loaded);
    return result;
}
#endif

enum vcs_source_package_checkout_result
vcs_source_package_reconstruct_verify(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint8_t source_root_out[32], uint8_t accepted_work_root_out[32],
    struct vcs_source_package_checkout_metrics *metrics)
{
    if (source_root_out) memset(source_root_out, 0, 32);
    if (accepted_work_root_out) memset(accepted_work_root_out, 0, 32);
    if (metrics) memset(metrics, 0, sizeof(*metrics));
    if (!store || !package_root || !source_root_out ||
        !accepted_work_root_out)
        return VCS_SOURCE_PACKAGE_CHECKOUT_NULL;
#if defined(_WIN32)
    /* Reconstruction creates and recursively removes a workspace. Keep the
     * entire operation fail-closed until that transaction has a validated
     * directory capability and identity-bound cleanup. */
    return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
#else
    uint8_t source_root[32], accepted_work_root[32];
    enum vcs_source_package_checkout_result result =
        source_package_identity_discover(
            store, package_root, source_root, accepted_work_root);
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return result;

    char scratch[] = "/tmp/zcl-source-reconstruct.XXXXXX";
    if (!mkdtemp(scratch))
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    char workspace[SOURCE_CHECKOUT_PATH_MAX];
    char destination[SOURCE_CHECKOUT_PATH_MAX];
    int wn = snprintf(workspace, sizeof(workspace), "%s/zvcs", scratch);
    int dn = snprintf(destination, sizeof(destination), "%s/source", scratch);
    bool dirs = wn > 0 && (size_t)wn < sizeof(workspace) &&
        dn > 0 && (size_t)dn < sizeof(destination) &&
        zcl_mkdir_p(workspace, 0700).ok &&
        zcl_mkdir_p(destination, 0700).ok;
    struct vcs_source_package_checkout_metrics checked;
    if (dirs)
        result = vcs_source_package_checkout_accepted(
            store, package_root, source_root, accepted_work_root,
            workspace, destination, &checked);
    else
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    struct zcl_result removed = zcl_tree_remove(scratch);
    if (!removed.ok && result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return result;
    memcpy(source_root_out, source_root, 32);
    memcpy(accepted_work_root_out, accepted_work_root, 32);
    if (metrics) *metrics = checked;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
#endif
}
