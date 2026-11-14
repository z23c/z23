/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Bind installed compiler selection, authenticated tree and sealed bytes. */
#include "command/app_toolchain.h"
#include "command/app_installed_source_resolve.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/toolchain.h"
#include "sha3/sha3.h"
#include "vcs/source_bundle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define KIT_FILES 4096u
static bool kit_why(char *why, size_t cap, const char *text)
{
    if (why && cap) (void)snprintf(why, cap, "%s", text);
    return false;
}
void app_toolchain_free(struct app_toolchain *kit)
{
    if (!kit) return;
    if (kit->backing_owned) close(kit->backing_fd);
    free(kit->files); free(kit->bundle); vcs_manifest_free(&kit->manifest);
    memset(kit, 0, sizeof(*kit));
}
static bool kit_values(const struct json_value *doc, const char *values[6])
{
    static const char *const keys[] = {"schema", "bundle_file", "bundle_sha3", "tree_root", "target", "policy"};
    unsigned seen = 0;
    for (size_t i = 0; i < 6; ++i) {
        size_t j = 0; while (j < 6 && strcmp(keys[j], doc->keys[i])) ++j;
        if (j == 6 || (seen & (1u << j)) || doc->children[i].type != JSON_STR) return false;
        values[j] = json_get_str(&doc->children[i]); if (!values[j]) return false;
        seen |= 1u << j;
    }
    return seen == 63;
}
static bool kit_parse(const uint8_t *wire, size_t length, struct json_value *doc,
    const char *values[6])
{
    if (!wire || !length || length > 4096 || !json_read(doc, (const char *)wire, length) ||
        doc->type != JSON_OBJ || doc->num_children != 6) return false;
    char canonical[4097]; size_t n = json_write(doc, canonical, sizeof(canonical));
    if (n != length || n >= sizeof(canonical) || memcmp(wire, canonical, n)) return false;
    return kit_values(doc, values) && !strcmp(values[0], APP_TOOLCHAIN_SCHEMA) &&
        !strcmp(values[1], APP_TOOLCHAIN_BUNDLE) &&
        !strcmp(values[4], "linux-x86_64-v3") && !strcmp(values[5], APP_TOOLCHAIN_POLICY);
}
static bool kit_path(const char *path)
{
    if (strncmp(path, "rootfs/", 7) || !path[7]) return false;
    static const char *const reserved[] = {"source", "work", "proc", "dev", "tmp", ".old-root"};
    const char *rel = path + 7;
    for (size_t i = 0; i < sizeof(reserved)/sizeof(reserved[0]); ++i) {
        size_t n = strlen(reserved[i]);
        if (!strncmp(rel, reserved[i], n) && (!rel[n] || rel[n] == '/')) return false;
    }
    return true;
}
static bool kit_entry(void *context, const struct vcs_entry *entry,
    const uint8_t *bytes, size_t length)
{
    (void)bytes;
    struct app_toolchain *kit = context;
    return kit->manifest.count < KIT_FILES && kit_path(entry->path) &&
        S_ISREG(entry->mode) && !(entry->mode & 07000) && length == entry->size &&
        vcs_manifest_add(&kit->manifest, entry->path, entry->mode, entry->size, entry->blob);
}
static const struct vcs_entry *kit_find(const struct app_toolchain *kit, const char *path)
{
    for (size_t i = 0; i < kit->manifest.count; ++i)
        if (!strcmp(kit->manifest.entries[i].path + 7, path)) return &kit->manifest.entries[i];
    return NULL;
}
bool app_toolchain_member(const struct app_toolchain *kit, const char *path)
{
    return kit && kit->selected && path && path[0] == '/' && kit_find(kit, path + 1);
}
static bool kit_tools(const struct app_toolchain *kit)
{
    static const char *const tools[] = {"bin/sh", "usr/bin/make", "usr/bin/cc"};
    for (size_t i = 0; i < sizeof(tools)/sizeof(tools[0]); ++i) {
        const struct vcs_entry *e = kit_find(kit, tools[i]);
        if (!e || !(e->mode & 0111)) return false;
    }
    return true;
}
static void kit_environment(struct app_toolchain *kit)
{
    static const char domain[] = "zcl.app_build.kit_env.v1";
    struct sha3_256_ctx h; sha3_256_init(&h);
    sha3_256_write(&h, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&h, kit->tree, 32);
    sha3_256_write(&h, (const uint8_t *)kit->target, strlen(kit->target) + 1);
    sha3_256_write(&h, (const uint8_t *)APP_TOOLCHAIN_POLICY, sizeof(APP_TOOLCHAIN_POLICY));
    sha3_256_finalize(&h, kit->env);
}
bool app_toolchain_verify(struct app_toolchain *kit, const uint8_t *descriptor,
    size_t descriptor_size, const uint8_t *bundle, size_t bundle_size,
    char *why, size_t cap)
{
    if (!kit) return kit_why(why, cap, "Missing kit output.");
    app_toolchain_free(kit);
    struct json_value doc; json_init(&doc); const char *values[6] = {0};
    uint8_t actual[32];
    bool ok = kit_parse(descriptor, descriptor_size, &doc, values) &&
        zcl_hex_decode_lower(values[2], kit->bundle_hash, 32) &&
        zcl_hex_decode_lower(values[3], kit->tree, 32) && bundle &&
        bundle_size <= VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES;
    if (ok) {
        zcl_native_package_artifact_digest(actual, bundle, bundle_size);
        ok = !memcmp(actual, kit->bundle_hash, 32);
        (void)snprintf(kit->target, sizeof(kit->target), "%s", values[4]);
    }
    json_free(&doc);
    if (ok) ok = vcs_source_bundle_visit_verified(bundle, bundle_size, kit->tree,
        kit_entry, kit, NULL) == VCS_SOURCE_BUNDLE_OK && kit_tools(kit);
    if (ok) {
        kit->bundle = zcl_malloc(bundle_size, "app.toolchain.bundle");
        ok = kit->bundle != NULL;
    }
    if (!ok) { app_toolchain_free(kit); return kit_why(why, cap, "Kit descriptor, bundle, rootfs members or required executables invalid."); }
    memcpy(kit->bundle, bundle, bundle_size); kit->bundle_size = bundle_size;
    kit->selected = true; kit_environment(kit); return true;
}
static bool kit_read(const char *dir, const char *name, const char *hash,
    size_t maximum, struct app_installed_source_bytes *out)
{
    char path[4096]; int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    struct json_value in; json_init(&in); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "file", path) && json_push_kv_str(&in, "sha3", hash) &&
        zcl_native_package_artifact_read_file(&in, "file", "sha3", maximum, &out->bytes, &out->length);
    json_free(&in); return ok;
}
bool app_toolchain_artifact(struct app_toolchain *kit, const char *dir,
    const char *descriptor_sha3, char *why, size_t cap)
{
    char canonical[4096]; uint8_t digest[32];
    if (!dir || dir[0] != '/' || !descriptor_sha3 ||
        !zcl_hex_decode_lower(descriptor_sha3, digest, 32) ||
        !platform_directory_canonical_real(dir, canonical, sizeof(canonical)) || strcmp(dir, canonical))
        return kit_why(why, cap, "Provide canonical artifact_dir and independently supplied descriptor_sha3.");
    struct app_installed_source_bytes descriptor = {0}, bundle = {0};
    struct json_value doc; json_init(&doc); const char *values[6] = {0};
    bool ok = kit_read(dir, APP_TOOLCHAIN_DESCRIPTOR, descriptor_sha3, 4096, &descriptor) &&
        kit_parse(descriptor.bytes, descriptor.length, &doc, values) &&
        kit_read(dir, APP_TOOLCHAIN_BUNDLE, values[2], VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES, &bundle) &&
        app_toolchain_verify(kit, descriptor.bytes, descriptor.length, bundle.bytes, bundle.length, why, cap);
    json_free(&doc); free(descriptor.bytes); free(bundle.bytes);
    return ok || kit_why(why, cap, "Pinned compiler-kit artifacts refused.");
}
bool app_toolchain_resolve(struct app_toolchain *kit, char *why, size_t cap)
{
    app_toolchain_free(kit);
    struct app_installed_toolchain retained = {0};
    enum app_installed_toolchain_status state = app_installed_toolchain_resolve(&retained, why, cap);
    if (state == APP_INSTALLED_TOOLCHAIN_UNSELECTED) return true;
    bool ok = state == APP_INSTALLED_TOOLCHAIN_VERIFIED &&
        app_toolchain_verify(kit, retained.descriptor.bytes, retained.descriptor.length,
            retained.bundle.bytes, retained.bundle.length, why, cap);
    app_installed_toolchain_free(&retained);
    char target[64];
    if (ok) ok = platform_toolchain_canonical_target(target, sizeof(target)) && !strcmp(target, kit->target);
    if (!ok) { app_toolchain_free(kit); return kit_why(why, cap, "Selected compiler kit unavailable, invalid or for another target."); }
    return true;
}
static void kit_seal_clear(struct app_toolchain *kit)
{
    if (kit->backing_owned) close(kit->backing_fd);
    kit->backing_owned = false; kit->backing_fd = -1; kit->backing_size = 0;
    free(kit->files); kit->files = NULL; kit->file_count = 0;
}
static bool kit_seal_entry(void *context, const struct vcs_entry *entry,
    const uint8_t *bytes, size_t length)
{
    struct app_toolchain *kit = context; size_t i = kit->file_count;
    if (i >= kit->manifest.count || strcmp(entry->path, kit->manifest.entries[i].path) ||
        length > (256u << 20) - kit->backing_size || !S_ISREG(entry->mode) || (entry->mode & 07000)) return false;
    struct os_sandbox_kit_file *file = &kit->files[i];
    file->path = kit->manifest.entries[i].path + 7; file->fd = kit->backing_fd;
    file->slice = true; file->offset = kit->backing_size; file->length = length; file->mode = entry->mode;
    memcpy(file->blob, entry->blob, 32);
    if (!os_sandbox_kit_backing_append(kit->backing_fd, bytes, length).ok) return false;
    kit->backing_size += length; ++kit->file_count; return true;
}
bool app_toolchain_seal(struct app_toolchain *kit, char *why, size_t cap)
{
    if (!kit || !kit->selected) return true;
    if (kit->backing_owned && kit->file_count == kit->manifest.count) return true;
    kit_seal_clear(kit);
    kit->files = zcl_calloc(kit->manifest.count, sizeof(*kit->files), "app.toolchain.files");
    if (!kit->files) return kit_why(why, cap, "Cannot allocate sealed kit members.");
    if (!os_sandbox_kit_backing_create(&kit->backing_fd).ok) {
        kit_seal_clear(kit); return kit_why(why, cap, "Cannot create sealed kit backing.");
    }
    kit->backing_owned = true;
    bool ok = vcs_source_bundle_visit_verified(kit->bundle, kit->bundle_size, kit->tree,
        kit_seal_entry, kit, NULL) == VCS_SOURCE_BUNDLE_OK &&
        kit->file_count == kit->manifest.count && os_sandbox_kit_backing_seal(kit->backing_fd).ok;
    if (!ok) { kit_seal_clear(kit); return kit_why(why, cap, "Cannot construct and seal verified compiler kit backing."); }
    return true;
}
