/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Git-free reconstruction of verified PROVEN source carriers. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "vcs/source_package_checkout.h"

#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/temp_directory.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_accepted_work_bundle.h"
#include "vcs/zcode_lane.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
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

/* Parses the lane receipt, requires the PROVEN lane and derives its id. When
 * source_root is given it must match the receipt between those two checks,
 * so every caller fails on the same first check. */
static bool source_checkout_lane_receipt(
    const uint8_t *lane_wire, size_t lane_wire_len,
    const uint8_t *source_root, struct vcs_zcode_lane_receipt_v1 *receipt,
    uint8_t lane_root[32])
{
    if (vcs_zcode_lane_receipt_parse(lane_wire, lane_wire_len, receipt) !=
            VCS_ZCODE_DEV_OK ||
        receipt->lane != VCS_ZCODE_LANE_PROVEN)
        return false;
    if (source_root && memcmp(receipt->source_root, source_root, 32) != 0)
        return false;
    return vcs_zcode_lane_receipt_id(receipt, lane_root) == VCS_ZCODE_DEV_OK;
}

/* An accepted-work carrier is authorised by its lane root; otherwise the
 * expected signer must verify the receipt. */
static bool source_checkout_lane_authorised(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t lane_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32])
{
    if (accepted_work_root)
        return memcmp(lane_root, accepted_work_root, 32) == 0;
    return expected_signer &&
        vcs_zcode_lane_receipt_verify(receipt, expected_signer) ==
            VCS_ZCODE_DEV_OK;
}

/* Reads the lane carrier and proves it; the wire bytes are released here. */
static bool source_checkout_lane_proven(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *package, int lane_index,
    const uint8_t expected_signer[32], const uint8_t accepted_work_root[32],
    struct vcs_zcode_lane_receipt_v1 *receipt)
{
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    uint8_t lane_root[32];
    bool proven = source_checkout_read_file(
            store, package_root, package, (size_t)lane_index,
            &lane_wire, &lane_wire_len) &&
        source_checkout_lane_receipt(
            lane_wire, lane_wire_len, NULL, receipt, lane_root) &&
        source_checkout_lane_authorised(
            receipt, lane_root, expected_signer, accepted_work_root);
    free(lane_wire);
    return proven;
}

/* Every fixed carrier must be present, and the authority carrier exactly
 * when accepted work is being checked. */
static enum vcs_source_package_checkout_result source_checkout_fixed_shape(
    const struct vcs_package_manifest *package,
    const uint8_t accepted_work_root[32])
{
    const char *fixed[] = {
        VCS_SOURCE_PACKAGE_LICENSE_PATH,
        VCS_SOURCE_PACKAGE_MANIFEST_PATH,
        VCS_SOURCE_PACKAGE_LANE_PATH,
        VCS_SOURCE_PACKAGE_MARKER_PATH,
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (source_checkout_file_index(package, fixed[i]) < 0)
            return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    int authority_index = source_checkout_file_index(
        package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH);
    if (accepted_work_root && authority_index < 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    if (!accepted_work_root && authority_index >= 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_fixed_files(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct source_checkout_loaded *loaded)
{
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
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_fixed_lane(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32],
    struct source_checkout_loaded *loaded)
{
    int lane_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_LANE_PATH);
    const struct vcs_package_file *lane = &loaded->package.files[lane_index];
    if (lane->size != VCS_ZCODE_LANE_WIRE_BYTES ||
        lane->size > SOURCE_CHECKOUT_AUTHORITY_MAX)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    struct vcs_zcode_lane_receipt_v1 receipt;
    if (!source_checkout_lane_proven(
            store, package_root, &loaded->package, lane_index,
            expected_signer, accepted_work_root, &receipt))
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    if (memcmp(receipt.source_root, source_root, 32) != 0)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_fixed_marker(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct source_checkout_loaded *loaded)
{
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
    return marker_ok ? VCS_SOURCE_PACKAGE_CHECKOUT_OK
                     : VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
}

static enum vcs_source_package_checkout_result source_checkout_load_fixed(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32],
    struct source_checkout_loaded *loaded)
{
    enum vcs_source_package_checkout_result result =
        source_checkout_fixed_shape(&loaded->package, accepted_work_root);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_fixed_files(store, package_root, loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_fixed_lane(
            store, package_root, source_root, expected_signer,
            accepted_work_root, loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_fixed_marker(store, package_root, loaded);
    int authority_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK && accepted_work_root &&
        !source_checkout_read_file(
            store, package_root, &loaded->package,
            (size_t)authority_index, &loaded->authority,
            &loaded->authority_len))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    return result;
}

/* A shard carrier must claim its index first and must read cleanly. */
static enum vcs_source_package_checkout_result
source_checkout_load_shard_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct source_checkout_loaded *loaded, size_t index, uint16_t shard,
    bool seen_shards[256])
{
    if (seen_shards[shard] || loaded->source.shard_count >= 256u)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    seen_shards[shard] = true;
    struct vcs_source_bundle_shard *part =
        &loaded->source.shards[loaded->source.shard_count];
    part->index = shard;
    if (!source_checkout_read_file(
            store, package_root, &loaded->package, index,
            &part->wire, &part->wire_len))
        return VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    loaded->source.shard_count++;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

/* Offline inputs are all-or-nothing, and every carrier must be recognised. */
static enum vcs_source_package_checkout_result
source_checkout_load_variable_finish(
    struct source_checkout_loaded *loaded, size_t offline_count,
    size_t recognized,
    const bool seen_offline[VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX])
{
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
            enum vcs_source_package_checkout_result result =
                source_checkout_load_shard_file(
                    store, package_root, loaded, i, shard, seen_shards);
            if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
                return result;
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
    return source_checkout_load_variable_finish(
        loaded, offline_count, recognized, seen_offline);
}

#if defined(_WIN32)
struct source_checkout_windows_entry {
    char *name;
    DWORD attributes;
};

struct source_checkout_windows_entries {
    struct source_checkout_windows_entry *items;
    size_t count;
};

static bool source_checkout_windows_open_directory(
    const char *path, struct platform_directory_transaction *directory)
{
    uintptr_t validated = 0;
    wchar_t wide[32768];
    if (!path || !directory ||
        !platform_private_directory_open_validated(path, &validated) ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                            wide, 32768) <= 0) {
        if (validated != 0) platform_private_directory_close(validated);
        return false;
    }
    HANDLE capable = CreateFileW(
        wide, FILE_LIST_DIRECTORY | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
                  READ_CONTROL | DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION first = {0}, second = {0};
    bool ok = capable != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle((HANDLE)validated, &first) &&
        GetFileInformationByHandle(capable, &second) &&
        first.dwVolumeSerialNumber == second.dwVolumeSerialNumber &&
        first.nFileIndexHigh == second.nFileIndexHigh &&
        first.nFileIndexLow == second.nFileIndexLow &&
        (second.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (second.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    platform_private_directory_close(validated);
    if (!ok) {
        if (capable != INVALID_HANDLE_VALUE) CloseHandle(capable);
        return false;
    }
    platform_directory_transaction_close(directory);
    directory->native = (uintptr_t)capable;
    return true;
}

static void source_checkout_windows_entries_free(
    struct source_checkout_windows_entries *entries)
{
    if (!entries) return;
    for (size_t i = 0; i < entries->count; i++)
        free(entries->items[i].name);
    free(entries->items);
    memset(entries, 0, sizeof(*entries));
}

static bool source_checkout_windows_skip_name(const FILE_ID_BOTH_DIR_INFO *entry)
{
    size_t chars = entry->FileNameLength / sizeof(wchar_t);
    bool dot = chars == 1u && entry->FileName[0] == L'.';
    bool dotdot = chars == 2u && entry->FileName[0] == L'.' &&
        entry->FileName[1] == L'.';
    return dot || dotdot;
}

/* On failure the new name is freed and out is left for the caller to free. */
static bool source_checkout_windows_entry_append(
    struct source_checkout_windows_entries *out,
    const FILE_ID_BOTH_DIR_INFO *entry)
{
    size_t chars = entry->FileNameLength / sizeof(wchar_t);
    int needed = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, entry->FileName,
        (int)chars, NULL, 0, NULL, NULL);
    char *name = needed > 0
        ? zcl_malloc((size_t)needed + 1u,
                     "vcs.source_checkout.windows_name")
        : NULL;
    struct source_checkout_windows_entry *items = name
        ? zcl_realloc(
              out->items,
              (out->count + 1u) * sizeof(*out->items),
              "vcs.source_checkout.windows_entries")
        : NULL;
    /* realloc may have moved and freed the old block: adopt the new one
     * before the conversion can fail, or entries_free would free the old
     * pointer again and leak this one. */
    if (items)
        out->items = items;
    if (!items || WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, entry->FileName,
            (int)chars, name, needed, NULL, NULL) != needed) {
        free(name);
        return false;
    }
    name[needed] = '\0';
    out->items[out->count++] =
        (struct source_checkout_windows_entry){
            .name = name,
            .attributes = entry->FileAttributes,
        };
    return true;
}

static bool source_checkout_windows_entries_read(
    struct platform_directory_transaction *directory,
    struct source_checkout_windows_entries *out)
{
    if (!directory || !out) return false;
    memset(out, 0, sizeof(*out));
    BYTE buffer[16384];
    bool restart = true;
    for (;;) {
        FILE_INFO_BY_HANDLE_CLASS information_class = restart
            ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
        if (!GetFileInformationByHandleEx(
                (HANDLE)directory->native, information_class,
                buffer, sizeof(buffer))) {
            if (GetLastError() == ERROR_NO_MORE_FILES) return true;
            source_checkout_windows_entries_free(out);
            return false;
        }
        restart = false;
        FILE_ID_BOTH_DIR_INFO *entry = (FILE_ID_BOTH_DIR_INFO *)buffer;
        for (;;) {
            if (!source_checkout_windows_skip_name(entry) &&
                !source_checkout_windows_entry_append(out, entry)) {
                source_checkout_windows_entries_free(out);
                return false;
            }
            if (entry->NextEntryOffset == 0) break;
            entry = (FILE_ID_BOTH_DIR_INFO *)(
                (BYTE *)entry + entry->NextEntryOffset);
        }
    }
}

static bool source_checkout_windows_write_relative(
    struct platform_directory_transaction *directory, const char *relative,
    const uint8_t *bytes, size_t len)
{
    const char *slash = strchr(relative, '/');
    if (slash) {
        size_t component_len = (size_t)(slash - relative);
        char component[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
        if (component_len == 0 || component_len >= sizeof(component))
            return false;
        memcpy(component, relative, component_len);
        component[component_len] = '\0';
        struct platform_directory_transaction child;
        platform_directory_transaction_init(&child);
        bool ok = platform_directory_transaction_open_child(
                directory, component, true, &child) == PLATFORM_DIRECTORY_OK &&
            source_checkout_windows_write_relative(
                &child, slash + 1, bytes, len);
        platform_directory_transaction_close(&child);
        return ok;
    }
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    if (!platform_directory_child_create(directory, relative, &file))
        return false;
    bool ok = platform_directory_child_write_exact(&file, bytes, len, 0) &&
        platform_directory_child_flush(&file);
    platform_directory_child_close(&file);
    if (!ok)
        (void)platform_directory_child_unlink(directory, relative, true);
    return ok;
}

static bool source_checkout_windows_mark_directory_delete(
    struct platform_directory_transaction *directory)
{
    struct source_checkout_disposition {
        DWORD flags;
    } disposition = {.flags = 1u | 2u};
    return SetFileInformationByHandle(
               (HANDLE)directory->native, (FILE_INFO_BY_HANDLE_CLASS)21,
               &disposition, sizeof(disposition)) != 0;
}

static bool source_checkout_windows_remove_contents(
    struct platform_directory_transaction *directory, unsigned depth)
{
    if (depth >= 64u) return false;
    for (unsigned pass = 0; pass < 4u; pass++) {
        struct source_checkout_windows_entries entries;
        if (!source_checkout_windows_entries_read(directory, &entries))
            return false;
        if (entries.count == 0) {
            source_checkout_windows_entries_free(&entries);
            return true;
        }
        bool ok = true;
        for (size_t i = 0; ok && i < entries.count; i++) {
            const struct source_checkout_windows_entry *entry =
                &entries.items[i];
            if ((entry->attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                ok = false;
            } else if ((entry->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                struct platform_directory_transaction child;
                platform_directory_transaction_init(&child);
                ok = platform_directory_transaction_open_child(
                         directory, entry->name, false, &child) ==
                         PLATFORM_DIRECTORY_OK &&
                    source_checkout_windows_remove_contents(&child, depth + 1u) &&
                    source_checkout_windows_mark_directory_delete(&child);
                platform_directory_transaction_close(&child);
            } else {
                ok = platform_directory_child_unlink(
                    directory, entry->name, false);
            }
        }
        source_checkout_windows_entries_free(&entries);
        if (!ok) return false;
    }
    return false;
}

static bool source_checkout_windows_remove_tree(const char *path)
{
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    bool ok = source_checkout_windows_open_directory(path, &root) &&
        source_checkout_windows_remove_contents(&root, 0) &&
        source_checkout_windows_mark_directory_delete(&root);
    platform_directory_transaction_close(&root);
    return ok;
}
#endif

static bool source_checkout_empty_dir(const char *path)
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct source_checkout_windows_entries entries;
    platform_directory_transaction_init(&directory);
    bool ok = source_checkout_windows_open_directory(path, &directory) &&
        source_checkout_windows_entries_read(&directory, &entries);
    if (ok) {
        ok = entries.count == 0;
        source_checkout_windows_entries_free(&entries);
    }
    platform_directory_transaction_close(&directory);
    return ok;
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

#if !defined(_WIN32)
static bool source_checkout_write(const char *path, const uint8_t *bytes,
                                  size_t len)
{
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
}
#endif

#if defined(_WIN32)
static bool source_checkout_write_offline_files(
    const char *destination, const struct source_checkout_loaded *loaded,
    uint64_t *bytes_out)
{
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    bool ok = source_checkout_windows_open_directory(destination, &root);
    uint64_t total = 0;
    for (size_t i = 0;
         ok && i < vcs_source_package_offline_input_count(); i++) {
        if (UINT64_MAX - total < loaded->offline_len[i] ||
            !source_checkout_windows_write_relative(
                &root, vcs_source_package_offline_input_path(i),
                loaded->offline[i], loaded->offline_len[i]))
            ok = false;
        else
            total += loaded->offline_len[i];
    }
    platform_directory_transaction_close(&root);
    if (!ok) return false;
    *bytes_out = total;
    return true;
}
#else
static bool source_checkout_write_offline_files(
    const char *destination, const struct source_checkout_loaded *loaded,
    uint64_t *bytes_out)
{
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
}
#endif

static bool source_checkout_write_offline(
    const char *destination, const struct source_checkout_loaded *loaded,
    uint64_t *bytes_out)
{
    if (loaded->offline_count == 0) {
        *bytes_out = 0;
        return true;
    }
    if (loaded->offline_count != vcs_source_package_offline_input_count())
        return false;
    return source_checkout_write_offline_files(destination, loaded, bytes_out);
}

/* Parses the manifest, then requires the lane and authority carriers that
 * the discovery functions read. */
static enum vcs_source_package_checkout_result source_checkout_discover_manifest(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct source_checkout_loaded *loaded)
{
    enum vcs_source_package_checkout_result result =
        source_checkout_manifest(store, package_root, loaded);
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return result;
    int lane_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_LANE_PATH);
    int authority_index = source_checkout_file_index(
        &loaded->package, VCS_SOURCE_PACKAGE_AUTHORITY_PATH);
    if (lane_index < 0 || authority_index < 0 ||
        loaded->package.files[lane_index].size !=
            VCS_ZCODE_LANE_WIRE_BYTES ||
        loaded->package.files[authority_index].size == 0 ||
        loaded->package.files[authority_index].size >
            VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

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
        source_checkout_discover_manifest(store, package_root, &loaded);
    int lane_index = result == VCS_SOURCE_PACKAGE_CHECKOUT_OK
        ? source_checkout_file_index(
              &loaded.package, VCS_SOURCE_PACKAGE_LANE_PATH) : -1;
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
        !source_checkout_lane_receipt(
            lane_wire, lane_wire_len, source_root, &receipt, discovered))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        memcpy(accepted_work_root, discovered, 32);
    free(lane_wire);
    source_checkout_loaded_free(&loaded);
    return result;
}

static bool source_checkout_common_args_invalid(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32], const char *workspace,
    const char *destination)
{
    return !store || !package_root || !source_root ||
        (!expected_signer && !accepted_work_root) ||
        (expected_signer && accepted_work_root) || !workspace || !destination;
}

static enum vcs_source_package_checkout_result source_checkout_load_package(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t source_root[32], const uint8_t expected_signer[32],
    const uint8_t accepted_work_root[32],
    struct source_checkout_loaded *loaded)
{
    enum vcs_source_package_checkout_result result =
        source_checkout_manifest(store, package_root, loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_load_fixed(
            store, package_root, source_root, expected_signer,
            accepted_work_root, loaded);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_load_variable(
            store, package_root, accepted_work_root != NULL, loaded);
    return result;
}

static enum vcs_source_package_checkout_result source_checkout_verify_import(
    struct source_checkout_loaded *loaded, const uint8_t source_root[32],
    const char *workspace, struct vcs_source_bundle_metrics *source_metrics)
{
    if (vcs_source_bundle_sharded_verify(
            &loaded->source, source_root, source_metrics) !=
            VCS_SOURCE_BUNDLE_OK)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    if (vcs_source_bundle_sharded_import(
            &loaded->source, source_root, workspace, source_metrics) !=
            VCS_SOURCE_BUNDLE_OK)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_import_accepted(
    const char *workspace, const uint8_t accepted_work_root[32],
    const uint8_t source_root[32], struct source_checkout_loaded *loaded,
    struct vcs_zcode_accepted_work_v1 *accepted,
    uint32_t *authority_objects, uint32_t *work_receipts)
{
    if (!accepted_work_root)
        return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
    if (vcs_zcode_accepted_work_bundle_import(
            workspace, accepted_work_root, source_root,
            loaded->authority, loaded->authority_len, accepted,
            authority_objects, work_receipts) !=
                VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK)
        return VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static enum vcs_source_package_checkout_result source_checkout_materialize(
    const char *workspace, const uint8_t source_root[32],
    const char *destination, struct source_checkout_loaded *loaded,
    uint64_t *offline_bytes)
{
    if (vcs_tree_materialize(
            workspace, source_root, destination,
            VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK)
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (!source_checkout_write_offline(destination, loaded, offline_bytes))
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

static void source_checkout_fill_accepted_metrics(
    struct vcs_source_package_checkout_metrics *metrics,
    const struct vcs_zcode_accepted_work_v1 *accepted)
{
    memcpy(metrics->accepted_signer, accepted->expected_signer, 32);
    memcpy(metrics->task_root, accepted->task_root, 32);
    memcpy(metrics->candidate_root, accepted->candidate_root, 32);
    memcpy(metrics->proof_policy_root, accepted->proof_policy_root, 32);
    memcpy(metrics->toolchain_capsule_root,
           accepted->task.toolchain_capsule_root, 32);
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
    if (source_checkout_common_args_invalid(
            store, package_root, source_root, expected_signer,
            accepted_work_root, workspace, destination))
        return VCS_SOURCE_PACKAGE_CHECKOUT_NULL;
    if (!source_checkout_empty_dir(destination))
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE;
    struct source_checkout_loaded loaded;
    source_checkout_loaded_init(&loaded);
    enum vcs_source_package_checkout_result result =
        source_checkout_load_package(
            store, package_root, source_root, expected_signer,
            accepted_work_root, &loaded);
    struct vcs_source_bundle_metrics source_metrics;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_verify_import(
            &loaded, source_root, workspace, &source_metrics);
    struct vcs_zcode_accepted_work_v1 accepted;
    uint32_t authority_objects = 0, work_receipts = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_import_accepted(
            workspace, accepted_work_root, source_root, &loaded,
            &accepted, &authority_objects, &work_receipts);
    uint64_t offline_bytes = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = source_checkout_materialize(
            workspace, source_root, destination, &loaded, &offline_bytes);
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK && metrics) {
        metrics->source = source_metrics;
        metrics->offline_input_bytes = offline_bytes;
        metrics->offline_input_files = (uint32_t)loaded.offline_count;
        metrics->source_shards = (uint32_t)loaded.source.shard_count;
        metrics->carrier_files = (uint32_t)loaded.package.count;
        metrics->authority_objects = authority_objects;
        metrics->work_receipts = work_receipts;
        if (accepted_work_root)
            source_checkout_fill_accepted_metrics(metrics, &accepted);
    }
    source_checkout_loaded_free(&loaded);
    return result;
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
        source_checkout_discover_manifest(store, package_root, &loaded);
    int lane_index = result == VCS_SOURCE_PACKAGE_CHECKOUT_OK
        ? source_checkout_file_index(
              &loaded.package, VCS_SOURCE_PACKAGE_LANE_PATH) : -1;
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        !source_checkout_read_file(
            store, package_root, &loaded.package, (size_t)lane_index,
            &lane_wire, &lane_wire_len))
        result = VCS_SOURCE_PACKAGE_CHECKOUT_CHUNK;
    struct vcs_zcode_lane_receipt_v1 lane;
    if (result == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
        !source_checkout_lane_receipt(
            lane_wire, lane_wire_len, NULL, &lane, accepted_work_root))
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

#if defined(_WIN32)
static bool source_checkout_scratch_create(char *scratch, size_t capacity)
{
    return platform_temp_directory_create(
        "zcl-source-reconstruct-", scratch, capacity);
}
#else
static bool source_checkout_scratch_create(char *scratch, size_t capacity)
{
    static const char template_path[] = "/tmp/zcl-source-reconstruct.XXXXXX";
    if (capacity < sizeof(template_path))
        return false;
    memcpy(scratch, template_path, sizeof(template_path));
    return mkdtemp(scratch) != NULL;
}
#endif

#if defined(_WIN32)
static bool source_checkout_scratch_dirs(
    const char *scratch, const char *workspace, const char *destination)
{
    (void)workspace;
    (void)destination;
    struct platform_directory_transaction scratch_directory;
    struct platform_directory_transaction workspace_directory;
    struct platform_directory_transaction source_directory;
    platform_directory_transaction_init(&scratch_directory);
    platform_directory_transaction_init(&workspace_directory);
    platform_directory_transaction_init(&source_directory);
    bool dirs = source_checkout_windows_open_directory(
            scratch, &scratch_directory) &&
        platform_directory_transaction_open_child(
            &scratch_directory, "zvcs", true, &workspace_directory) ==
            PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(
            &scratch_directory, "source", true, &source_directory) ==
            PLATFORM_DIRECTORY_OK;
    platform_directory_transaction_close(&source_directory);
    platform_directory_transaction_close(&workspace_directory);
    platform_directory_transaction_close(&scratch_directory);
    return dirs;
}
#else
static bool source_checkout_scratch_dirs(
    const char *scratch, const char *workspace, const char *destination)
{
    (void)scratch;
    return zcl_mkdir_p(workspace, 0700).ok &&
        zcl_mkdir_p(destination, 0700).ok;
}
#endif

/* Builds the workspace and destination paths under scratch, then creates
 * both directories; the directories are made only when the paths fit. */
static bool source_checkout_scratch_ready(
    const char *scratch, char workspace[SOURCE_CHECKOUT_PATH_MAX],
    char destination[SOURCE_CHECKOUT_PATH_MAX])
{
    int wn = snprintf(workspace, SOURCE_CHECKOUT_PATH_MAX, "%s/zvcs", scratch);
    int dn = snprintf(destination, SOURCE_CHECKOUT_PATH_MAX, "%s/source",
                      scratch);
    bool paths = wn > 0 && (size_t)wn < SOURCE_CHECKOUT_PATH_MAX &&
        dn > 0 && (size_t)dn < SOURCE_CHECKOUT_PATH_MAX;
    return paths &&
        source_checkout_scratch_dirs(scratch, workspace, destination);
}

#if defined(_WIN32)
static bool source_checkout_scratch_remove(const char *scratch)
{
    return source_checkout_windows_remove_tree(scratch);
}
#else
static bool source_checkout_scratch_remove(const char *scratch)
{
    return zcl_tree_remove(scratch).ok;
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
    uint8_t source_root[32], accepted_work_root[32];
    enum vcs_source_package_checkout_result result =
        source_package_identity_discover(
            store, package_root, source_root, accepted_work_root);
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return result;
    char scratch[PLATFORM_TEMP_PATH_MAX];
    if (!source_checkout_scratch_create(scratch, sizeof(scratch)))
        return VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    char workspace[SOURCE_CHECKOUT_PATH_MAX];
    char destination[SOURCE_CHECKOUT_PATH_MAX];
    bool ready = source_checkout_scratch_ready(
        scratch, workspace, destination);
    struct vcs_source_package_checkout_metrics checked;
    if (ready)
        result = vcs_source_package_checkout_accepted(
            store, package_root, source_root, accepted_work_root,
            workspace, destination, &checked);
    else
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (!source_checkout_scratch_remove(scratch) &&
        result == VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        result = VCS_SOURCE_PACKAGE_CHECKOUT_DESTINATION;
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return result;
    memcpy(source_root_out, source_root, 32);
    memcpy(accepted_work_root_out, accepted_work_root, 32);
    if (metrics) *metrics = checked;
    return VCS_SOURCE_PACKAGE_CHECKOUT_OK;
}

const char *vcs_zcode_work_admit_result_string(
    enum vcs_zcode_work_admit_result result)
{
    switch (result) {
    case VCS_ZCODE_WORK_ADMIT_OK: return "ok";
    case VCS_ZCODE_WORK_ADMIT_NULL: return "null argument";
    case VCS_ZCODE_WORK_ADMIT_NOT_RECONSTRUCTIBLE:
        return "package does not reconstruct to a proven accepted work";
    case VCS_ZCODE_WORK_ADMIT_TASK_MISMATCH:
        return "package proves a different task than the expected root";
    }
    return "unknown";
}

enum vcs_zcode_work_admit_result vcs_zcode_work_solution_admit_metrics(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t expect_task_root[32], uint8_t source_root_out[32],
    uint8_t accepted_work_root_out[32],
    struct vcs_source_package_checkout_metrics *metrics_out)
{
    memset(source_root_out, 0, 32);
    memset(accepted_work_root_out, 0, 32);
    memset(metrics_out, 0, sizeof(*metrics_out));
    if (!store || !package_root)
        return VCS_ZCODE_WORK_ADMIT_NULL;
    uint8_t source_root[32], accepted_work_root[32];
    struct vcs_source_package_checkout_metrics metrics;
    if (vcs_source_package_reconstruct_verify(
            store, package_root, source_root, accepted_work_root,
            &metrics) != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return VCS_ZCODE_WORK_ADMIT_NOT_RECONSTRUCTIBLE;
    if (expect_task_root &&
        memcmp(metrics.task_root, expect_task_root, 32) != 0)
        return VCS_ZCODE_WORK_ADMIT_TASK_MISMATCH;
    memcpy(source_root_out, source_root, 32);
    memcpy(accepted_work_root_out, accepted_work_root, 32);
    *metrics_out = metrics;
    return VCS_ZCODE_WORK_ADMIT_OK;
}

enum vcs_zcode_work_admit_result vcs_zcode_work_solution_admit(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t expect_task_root[32], uint8_t task_root_out[32],
    uint8_t source_root_out[32], uint8_t accepted_work_root_out[32])
{
    if (task_root_out) memset(task_root_out, 0, 32);
    if (source_root_out) memset(source_root_out, 0, 32);
    if (accepted_work_root_out) memset(accepted_work_root_out, 0, 32);
    uint8_t source_root[32], accepted_work_root[32];
    struct vcs_source_package_checkout_metrics metrics;
    enum vcs_zcode_work_admit_result result =
        vcs_zcode_work_solution_admit_metrics(
            store, package_root, expect_task_root, source_root,
            accepted_work_root, &metrics);
    if (result != VCS_ZCODE_WORK_ADMIT_OK)
        return result;
    if (task_root_out) memcpy(task_root_out, metrics.task_root, 32);
    if (source_root_out) memcpy(source_root_out, source_root, 32);
    if (accepted_work_root_out)
        memcpy(accepted_work_root_out, accepted_work_root, 32);
    return VCS_ZCODE_WORK_ADMIT_OK;
}
