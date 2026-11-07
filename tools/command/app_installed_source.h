/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Load a caller-pinned inert installed-app source projection. */
#ifndef ZCL_APP_INSTALLED_SOURCE_H
#define ZCL_APP_INSTALLED_SOURCE_H
#include "command/app_image.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_INSTALLED_SOURCE_SCHEMA "zcl.app_installed_source.v1"
#define APP_INSTALLED_SOURCE_PROJECTION "installed-source.json"
#define APP_INSTALLED_SOURCE_BUNDLE "source.bundle"
#define APP_INSTALLED_SOURCE_MANIFEST "manifest.wire"
#define APP_INSTALLED_SOURCE_RECIPE "recipe.wire"
#define APP_INSTALLED_SOURCE_RECORD "app-build.wire"
#define APP_INSTALLED_SOURCE_PROJECTION_MAX 4096u
#define APP_INSTALLED_SOURCE_IMAGE_MAX (64u * 1024u * 1024u)
#define APP_INSTALLED_SOURCE_APP_MAX 32u

struct app_installed_source_bytes {
    uint8_t *bytes;
    size_t length;
};
struct app_installed_source {
    char app[APP_INSTALLED_SOURCE_APP_MAX + 1u];
    uint8_t projection_sha3[32], tree_root[32], package_root[32];
    uint8_t recipe_root[32], record_id[32];
    struct app_image_build build;
    struct app_installed_source_bytes projection, bundle, manifest, recipe, record;
};

/* Shared bounded diagnostic, including optional/zero-capacity buffers.
 * Returns false for refusal call sites; writing a message changes no state. */
bool app_installed_source_message(char *why, size_t cap, const char *message);

void app_installed_source_init(struct app_installed_source *source);
void app_installed_source_free(struct app_installed_source *source);
/* out must first be initialized; load frees any previous output, including on
 * refusal. On success it owns verified bytes until free. why may be NULL.
 *
 * asset_dir and installed_image must be absolute canonical paths with trusted,
 * stable installer-owned ancestors. That ownership is a CALLER prerequisite;
 * this loader does not derive authority from adjacency or directory contents.
 * expected_projection_sha3 is an independently authorized lowercase 64-hex
 * SHA3-256 of the exact projection bytes, never read from that asset directory.
 *
 * Flat projection: exactly schema, app, bundle_file, bundle_sha3, tree_root,
 * manifest_file, manifest_sha3, package_root, recipe_file, recipe_sha3,
 * recipe_root, record_file, record_sha3, record_id, image_sha3. All strings.
 * schema and four file values equal the constants above. app is 1..32 lowercase
 * letters/digits/_/-, starting alphanumeric. Roots/digests are exactly 64
 * lowercase hex. Canonical compact json_write encoding, no trailing bytes;
 * field order may vary. Duplicate/unknown keys and nested values are refused.
 *
 * No make, key creation, signing, import, materialization or filesystem writes.
 * Verifies bundle/tree, manifest/package, recipe/root/membership, build record
 * id/package/image and installed image bytes/size. Full source-to-package/recipe
 * derivation remains REQUIRED after owner consent/materialization and before
 * key creation or make. Existing codecs are not replaced by this projection.
 * The record's producer inode triple is provenance, NOT local launch authority.
 * Success is a point-in-time observation; recheck the independently pinned
 * binding at consent/use, and use retained bytes rather than reopening members.
 */
bool app_installed_source_load(const char *asset_dir,
    const char *expected_projection_sha3, const char *installed_image,
    struct app_installed_source *out, char *why, size_t why_cap);
/* Only after owner consent: reconstruct retained verified bytes in fresh
 * private scratch and independently derive the full package and recipe.
 * Never executes source, creates keys or publishes. Outputs are cleared on
 * entry. If scratch is nonempty, the caller owns and must remove that tree
 * even on failure; source_path is usable only on success. A failed cleanup
 * must retain/report scratch. Never pass an existing owned scratch output.
 * The input must be a successful load, still bound to the consented pin. */
bool app_installed_source_stage(const struct app_installed_source *source,
    char *scratch, size_t scratch_cap, char *source_path, size_t source_cap,
    char *why, size_t why_cap);
#endif
