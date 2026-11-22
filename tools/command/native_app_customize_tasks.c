/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: read a bounded member of the exact currently kept Tasks package. */
#include "command/native_app_customize_tasks.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/positioned_file.h"
#include "vcs/package_manifest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACT_FILE_MAX (1024u * 1024u)
#define ACT_PATH_MAX 1200

bool ac_tasks_kept_read(const char *directory, struct package_resident_record *out)
{
    struct package_resident_store store = {0};
    if (!package_resident_store_open_app_readonly(&store, directory, "local/tasks").ok) return false;
    struct zcl_result read = package_resident_record_read(&store, out);
    struct zcl_result closed = package_resident_store_close(&store);
    return read.ok && closed.ok && out->generation > 0;
}

/* Open beneath the profile without following a component; bind bytes to the
 * actual open object and reject changes during read. */
static bool act_read(const char *directory, const char *relative, size_t cap,
                     uint8_t **out, size_t *size)
{
    *out = NULL; *size = 0;
    struct platform_positioned_file file; platform_positioned_file_init(&file);
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_open_beneath(&file, directory, relative)) return false;
    bool ok = platform_positioned_file_snapshot(&file, &before) && before.size > 0 && before.size <= cap;
    size_t n = ok ? (size_t)before.size : 0;
    uint8_t *bytes = ok ? zcl_malloc(n, "tasks-source-read") : NULL;
    if (!bytes) ok = false;
    size_t pos = 0;
    while (ok && pos < n) {
        int64_t got = platform_positioned_file_read(&file, bytes + pos, n - pos, pos);
        if (got <= 0 || (uint64_t)got > n - pos) ok = false;
        else pos += (size_t)got;
    }
    if (ok) ok = platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) { free(bytes); return false; }
    *out = bytes; *size = n; return true;
}

static bool act_manifest(const char *directory, const char *root,
                         struct vcs_package_manifest *manifest)
{
    char relative[ACT_PATH_MAX]; uint8_t expected[32], actual[32], *wire = NULL;
    size_t length = 0;
    int n = snprintf(relative, sizeof(relative), "zcode/manifests/%s", root);
    if (n <= 0 || (size_t)n >= sizeof(relative) || !zcl_hex_decode_lower(root, expected, 32) ||
        !act_read(directory, relative, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire, &length)) return false;
    bool ok = vcs_package_manifest_parse(wire, length, manifest);
    free(wire);
    if (ok) ok = vcs_package_manifest_root(manifest, actual) && !memcmp(actual, expected, sizeof(actual));
    if (!ok) vcs_package_manifest_free(manifest);
    return ok;
}

bool ac_tasks_manifest_read(const char *directory, const char *root, uint64_t generation,
                            struct package_resident_record *kept, struct vcs_package_manifest *manifest)
{
    if (!directory || !kept || !manifest || !ac_tasks_kept_read(directory, kept)) return false;
    if (root && (strcmp(root, kept->current.package_root) || (uint64_t)kept->generation != generation)) return false;
    vcs_package_manifest_init(manifest);
    return act_manifest(directory, kept->current.package_root, manifest);
}

static bool act_chunk(const char *directory, const struct vcs_package_file *entry,
                      struct ac_tasks_file *out)
{
    if (entry->size > ACT_FILE_MAX) return false;
    out->size = (size_t)entry->size; out->mode = entry->mode;
    if (!out->size) return true;
    if (entry->chunk_count != 1) return false;
    char hex[65], relative[ACT_PATH_MAX];
    zcl_hex_encode(entry->chunk_hashes, 32, hex);
    int n = snprintf(relative, sizeof(relative), "zcode/cas/sha3/%.2s/%s", hex, hex);
    size_t length = 0;
    if (n <= 0 || (size_t)n >= sizeof(relative) ||
        !act_read(directory, relative, ACT_FILE_MAX, &out->bytes, &length)) return false;
    if (length != out->size || !vcs_package_verify_chunk(entry, 0, out->bytes, length)) {
        free(out->bytes); out->bytes = NULL; return false;
    }
    return true;
}

bool ac_tasks_file_read(const char *directory, const char *root, uint64_t generation,
                        const char *path, struct ac_tasks_file *out)
{
    if (!directory || !root || !path || !out || !vcs_package_path_valid(path)) return false;
    memset(out, 0, sizeof(*out));
    if (!ac_tasks_kept_read(directory, &out->kept) || (uint64_t)out->kept.generation != generation ||
        strcmp(out->kept.current.package_root, root)) return false;
    struct vcs_package_manifest manifest; vcs_package_manifest_init(&manifest);
    if (!act_manifest(directory, root, &manifest)) return false;
    const struct vcs_package_file *entry = vcs_package_manifest_find(&manifest, path);
    bool ok = entry && act_chunk(directory, entry, out);
    vcs_package_manifest_free(&manifest);
    struct package_resident_record now = {0};
    if (ok) ok = ac_tasks_kept_read(directory, &now) && now.generation == out->kept.generation &&
        package_resident_identity_equal(&now.current, &out->kept.current);
    if (!ok) { free(out->bytes); out->bytes = NULL; out->size = 0; }
    return ok;
}
