/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verify pinned installed source assets without import or execution. */
#include "command/app_installed_source.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "vcs/source_bundle.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum ais_field {
    AIS_SCHEMA, AIS_APP, AIS_BUNDLE_FILE, AIS_BUNDLE_SHA, AIS_TREE,
    AIS_MANIFEST_FILE, AIS_MANIFEST_SHA, AIS_PACKAGE,
    AIS_RECIPE_FILE, AIS_RECIPE_SHA, AIS_RECIPE,
    AIS_RECORD_FILE, AIS_RECORD_SHA, AIS_RECORD, AIS_IMAGE, AIS_FIELDS
};
static const char *const ais_keys[AIS_FIELDS] = {
    "schema", "app", "bundle_file", "bundle_sha3", "tree_root",
    "manifest_file", "manifest_sha3", "package_root",
    "recipe_file", "recipe_sha3", "recipe_root",
    "record_file", "record_sha3", "record_id", "image_sha3"
};
struct ais_projection { const char *values[AIS_FIELDS]; };
void app_installed_source_init(struct app_installed_source *source)
{
    if (source) memset(source, 0, sizeof(*source));
}
void app_installed_source_free(struct app_installed_source *source)
{
    if (!source) return;
    free(source->projection.bytes); free(source->bundle.bytes);
    free(source->manifest.bytes); free(source->recipe.bytes); free(source->record.bytes);
    app_installed_source_init(source);
}
bool app_installed_source_message(char *why, size_t cap, const char *message)
{
    if (why && cap) (void)snprintf(why, cap, "%s", message);
    return false;
}
static bool ais_hex(const char *value, uint8_t bytes[32])
{
    return value && strlen(value) == 64 && zcl_hex_decode_lower(value, bytes, 32);
}
static bool ais_app(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (!n || n > APP_INSTALLED_SOURCE_APP_MAX) return false;
    for (size_t i = 0; i < n; ++i) {
        bool letter = name[i] >= 'a' && name[i] <= 'z';
        bool digit = name[i] >= '0' && name[i] <= '9';
        if (!letter && !digit && !(i && (name[i] == '_' || name[i] == '-'))) return false;
    }
    return true;
}
static bool ais_fields(const struct json_value *doc, struct ais_projection *p)
{
    if (doc->type != JSON_OBJ || doc->num_children != AIS_FIELDS) return false;
    uint32_t seen = 0;
    for (size_t i = 0; i < doc->num_children; ++i) {
        size_t field = 0;
        while (field < AIS_FIELDS && strcmp(doc->keys[i], ais_keys[field])) ++field;
        if (field == AIS_FIELDS || (seen & (1u << field))) return false;
        const struct json_value *v = &doc->children[i];
        if (v->type != JSON_STR || !json_get_str(v)) return false;
        p->values[field] = json_get_str(v);
        seen |= 1u << field;
    }
    return seen == (1u << AIS_FIELDS) - 1u;
}
static bool ais_values(const struct ais_projection *p)
{
    static const struct { enum ais_field field; const char *value; } fixed[] = {
        {AIS_SCHEMA, APP_INSTALLED_SOURCE_SCHEMA},
        {AIS_BUNDLE_FILE, APP_INSTALLED_SOURCE_BUNDLE},
        {AIS_MANIFEST_FILE, APP_INSTALLED_SOURCE_MANIFEST},
        {AIS_RECIPE_FILE, APP_INSTALLED_SOURCE_RECIPE},
        {AIS_RECORD_FILE, APP_INSTALLED_SOURCE_RECORD}
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i)
        if (strcmp(p->values[fixed[i].field], fixed[i].value)) return false;
    static const enum ais_field roots[] = {
        AIS_BUNDLE_SHA, AIS_TREE, AIS_MANIFEST_SHA, AIS_PACKAGE,
        AIS_RECIPE_SHA, AIS_RECIPE, AIS_RECORD_SHA, AIS_RECORD, AIS_IMAGE
    };
    uint8_t decoded[32];
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); ++i)
        if (!ais_hex(p->values[roots[i]], decoded)) return false;
    return ais_app(p->values[AIS_APP]);
}
static bool ais_parse(const struct app_installed_source_bytes *wire,
                      struct json_value *doc, struct ais_projection *p)
{
    if (!json_read(doc, (const char *)wire->bytes, wire->length)) return false;
    char canonical[APP_INSTALLED_SOURCE_PROJECTION_MAX + 1u];
    size_t length = json_write(doc, canonical, sizeof(canonical));
    if (!length || length >= sizeof(canonical) || length != wire->length ||
        memcmp(canonical, wire->bytes, length)) return false;
    return ais_fields(doc, p) && ais_values(p);
}
/* The ancestor ownership requirement is external. These checks reject
 * lexical aliases and a symlink/non-directory asset-directory leaf. */
static bool ais_locations(const char *dir, const char *image)
{
    char canonical[4096], absolute[4096];
    return dir && strlen(dir) > 1 && image &&
        platform_directory_probe_real(dir) == PLATFORM_DIRECTORY_PROBE_OK &&
        platform_directory_canonical_real(dir, canonical, sizeof(canonical)) &&
        !strcmp(canonical, dir) &&
        zcl_native_package_artifact_absolute(image, absolute, sizeof(absolute)) &&
        !strcmp(image, absolute);
}
static bool ais_read(const char *path, const char *digest, size_t maximum,
                     struct app_installed_source_bytes *out)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "file", path) &&
        json_push_kv_str(&input, "sha3", digest) &&
        zcl_native_package_artifact_read_file(&input, "file", "sha3",
                                              maximum, &out->bytes, &out->length);
    json_free(&input); return ok;
}
static bool ais_member(const char *dir, const char *name, const char *digest,
                        size_t maximum, struct app_installed_source_bytes *out)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    return n > 0 && (size_t)n < sizeof(path) && ais_read(path, digest, maximum, out);
}
static bool ais_assets(const char *dir, const struct ais_projection *p,
                        struct app_installed_source *out)
{
    return ais_member(dir, APP_INSTALLED_SOURCE_BUNDLE, p->values[AIS_BUNDLE_SHA],
                      (size_t)VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES, &out->bundle) &&
        ais_member(dir, APP_INSTALLED_SOURCE_MANIFEST, p->values[AIS_MANIFEST_SHA],
                   VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &out->manifest) &&
        ais_member(dir, APP_INSTALLED_SOURCE_RECIPE, p->values[AIS_RECIPE_SHA],
                   VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &out->recipe) &&
        ais_member(dir, APP_INSTALLED_SOURCE_RECORD, p->values[AIS_RECORD_SHA],
                   APP_IMAGE_BUILD_WIRE_BYTES, &out->record);
}
static bool ais_tree(const struct ais_projection *p, struct app_installed_source *out)
{
    return ais_hex(p->values[AIS_TREE], out->tree_root) &&
        vcs_source_bundle_verify(out->bundle.bytes, out->bundle.length,
                                 out->tree_root, NULL) == VCS_SOURCE_BUNDLE_OK;
}
static bool ais_package(const struct ais_projection *p, struct app_installed_source *out,
                         struct vcs_package_manifest *manifest)
{
    uint8_t expected[32];
    return ais_hex(p->values[AIS_PACKAGE], expected) &&
        vcs_package_manifest_parse(out->manifest.bytes, out->manifest.length, manifest) &&
        vcs_package_manifest_root(manifest, out->package_root) &&
        !memcmp(expected, out->package_root, 32);
}
static bool ais_recipe(const struct ais_projection *p, struct app_installed_source *out,
                        const struct vcs_package_manifest *manifest)
{
    struct vcs_package_recipe recipe; vcs_package_recipe_init(&recipe);
    uint8_t expected[32]; char detail[256];
    bool ok = ais_hex(p->values[AIS_RECIPE], expected) &&
        vcs_package_recipe_parse(out->recipe.bytes, out->recipe.length, &recipe) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(&recipe, out->recipe_root) == VCS_PACKAGE_RECIPE_OK &&
        !memcmp(expected, out->recipe_root, 32) &&
        vcs_package_recipe_files_in_manifest(&recipe, manifest, detail, sizeof(detail));
    vcs_package_recipe_free(&recipe); return ok;
}
static bool ais_metadata(const struct ais_projection *p, struct app_installed_source *out,
                          char *why, size_t cap)
{
    struct vcs_package_manifest manifest; vcs_package_manifest_init(&manifest);
    bool ok = ais_package(p, out, &manifest);
    if (!ok) app_installed_source_message(why, cap, "PACKAGE_INVALID: manifest wire or package root mismatch");
    else if (!(ok = ais_recipe(p, out, &manifest)))
        app_installed_source_message(why, cap, "RECIPE_INVALID: recipe wire, root or manifest membership mismatch");
    vcs_package_manifest_free(&manifest); return ok;
}
static bool ais_record(const struct ais_projection *p, struct app_installed_source *out)
{
    uint8_t expected[32], image[32];
    if (!ais_hex(p->values[AIS_RECORD], expected) || !ais_hex(p->values[AIS_IMAGE], image))
        return false;
    struct zcl_result decoded = app_image_build_decode(out->record.bytes, out->record.length, &out->build);
    if (!decoded.ok) return false;
    struct zcl_result rooted = app_image_build_id(&out->build, out->record_id);
    return rooted.ok && !memcmp(out->record_id, expected, 32) &&
        !memcmp(out->build.package_root, out->package_root, 32) &&
        !memcmp(out->build.image_sha3, image, 32) &&
        out->build.image_size <= APP_INSTALLED_SOURCE_IMAGE_MAX;
}
static bool ais_image(const char *path, const struct ais_projection *p,
                       const struct app_installed_source *out)
{
    struct app_installed_source_bytes image = {0};
    bool ok = ais_read(path, p->values[AIS_IMAGE], APP_INSTALLED_SOURCE_IMAGE_MAX, &image) &&
        image.length == out->build.image_size;
    free(image.bytes); return ok;
}
static bool ais_validate(const char *image, const struct ais_projection *p,
                          struct app_installed_source *out, char *why, size_t cap)
{
    if (!ais_tree(p, out))
        return app_installed_source_message(why, cap, "SOURCE_INVALID: source bundle failed bounded tree/blob verification");
    if (!ais_metadata(p, out, why, cap)) return false;
    if (!ais_record(p, out))
        return app_installed_source_message(why, cap, "RECORD_INVALID: build record id/package/image binding mismatch");
    if (!ais_image(image, p, out))
        return app_installed_source_message(why, cap, "IMAGE_INVALID: installed image read, digest or size mismatch");
    return true;
}
bool app_installed_source_load(const char *asset_dir,
    const char *expected_projection_sha3, const char *installed_image,
    struct app_installed_source *out, char *why, size_t why_cap)
{
    if (why && why_cap) why[0] = 0;
    if (!out) return app_installed_source_message(why, why_cap, "BAD_INPUT: initialized output required");
    app_installed_source_free(out);
    struct app_installed_source candidate; app_installed_source_init(&candidate);
    struct json_value doc; json_init(&doc);
    struct ais_projection p = {0};
    bool ok = ais_hex(expected_projection_sha3, candidate.projection_sha3) &&
        ais_locations(asset_dir, installed_image);
    if (!ok) app_installed_source_message(why, why_cap, "BAD_INPUT: independently pinned digest and canonical trusted paths required");
    else if (!(ok = ais_member(asset_dir, APP_INSTALLED_SOURCE_PROJECTION, expected_projection_sha3,
                               APP_INSTALLED_SOURCE_PROJECTION_MAX, &candidate.projection)))
        app_installed_source_message(why, why_cap, "PROJECTION_READ: missing, unsafe, unstable, oversized or digest-mismatched projection");
    else if (!(ok = ais_parse(&candidate.projection, &doc, &p)))
        app_installed_source_message(why, why_cap, "PROJECTION_INVALID: noncanonical JSON or unknown/duplicate/invalid fields");
    else if (!(ok = ais_assets(asset_dir, &p, &candidate)))
        app_installed_source_message(why, why_cap, "ASSET_READ: missing, unsafe, unstable, oversized or digest-mismatched member");
    else ok = ais_validate(installed_image, &p, &candidate, why, why_cap);
    if (ok) {
        memcpy(candidate.app, p.values[AIS_APP], strlen(p.values[AIS_APP]) + 1u);
        *out = candidate; app_installed_source_init(&candidate);
    }
    json_free(&doc); app_installed_source_free(&candidate);
    return ok;
}
