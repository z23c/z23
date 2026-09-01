/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: closed content.v2 carrier for one signed reusable C23 package. */

#include "vcs/package_transport.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_content.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool transport_copy(uint8_t **out, size_t *out_len,
                           const uint8_t *wire, size_t wire_len,
                           const char *label)
{
    *out = NULL;
    *out_len = 0;
    if (!wire || wire_len == 0)
        return false;
    uint8_t *copy = zcl_malloc(wire_len, label);
    if (!copy)
        return false;
    memcpy(copy, wire, wire_len);
    *out = copy;
    *out_len = wire_len;
    return true;
}

static bool transport_source_path(const char *path, char out[256])
{
    int n = snprintf(out, 256, "%s%s",
                     VCS_PACKAGE_TRANSPORT_SOURCE_PREFIX, path);
    return n > 0 && n < 256 && vcs_package_path_valid(out);
}

static bool transport_add_sources(
    struct vcs_package_manifest *outer,
    const struct vcs_package_manifest *source)
{
    for (size_t i = 0; i < source->count; i++) {
        const struct vcs_package_file *file = &source->files[i];
        char path[256];
        if (!transport_source_path(file->path, path) ||
            !vcs_package_manifest_add(outer, path, file->mode, file->size,
                                      file->chunk_hashes,
                                      file->chunk_count))
            return false;
    }
    return true;
}

const char *vcs_package_transport_result_string(
    enum vcs_package_transport_result result)
{
    switch (result) {
    case VCS_PACKAGE_TRANSPORT_OK: return "ok";
    case VCS_PACKAGE_TRANSPORT_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_TRANSPORT_ERR_RELEASE: return "release";
    case VCS_PACKAGE_TRANSPORT_ERR_RECIPE: return "recipe";
    case VCS_PACKAGE_TRANSPORT_ERR_MANIFEST: return "manifest";
    case VCS_PACKAGE_TRANSPORT_ERR_BINDING: return "binding";
    case VCS_PACKAGE_TRANSPORT_ERR_PATH: return "path";
    case VCS_PACKAGE_TRANSPORT_ERR_ALLOC: return "allocation";
    case VCS_PACKAGE_TRANSPORT_ERR_SOURCE: return "source";
    case VCS_PACKAGE_TRANSPORT_ERR_STORE: return "store";
    }
    return "unknown";
}

void vcs_package_transport_init(struct vcs_package_transport *transport)
{
    if (!transport)
        return;
    memset(transport, 0, sizeof(*transport));
    vcs_package_manifest_init(&transport->source_manifest);
    vcs_package_manifest_init(&transport->transport_manifest);
}

void vcs_package_transport_free(struct vcs_package_transport *transport)
{
    if (!transport)
        return;
    vcs_package_manifest_free(&transport->source_manifest);
    vcs_package_manifest_free(&transport->transport_manifest);
    free(transport->release_wire);
    free(transport->recipe_wire);
    free(transport->package_manifest_wire);
    free(transport->transport_manifest_wire);
    memset(transport, 0, sizeof(*transport));
}

enum vcs_package_transport_result vcs_package_transport_build(
    const uint8_t *release_wire, size_t release_wire_len,
    const uint8_t *recipe_wire, size_t recipe_wire_len,
    const uint8_t *package_manifest_wire, size_t package_manifest_wire_len,
    struct vcs_package_transport *out)
{
    if (!release_wire || !recipe_wire || !package_manifest_wire || !out)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_NULL, "vcs.package.transport",
                   "null package transport input");
    vcs_package_transport_free(out);
    vcs_package_transport_init(out);
    if (vcs_package_release_parse(release_wire, release_wire_len,
                                  &out->release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&out->release) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&out->release, out->release_id) !=
            VCS_PACKAGE_RELEASE_OK)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_RELEASE,
                   "vcs.package.transport", "signed release rejected");

    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error recipe_error =
        vcs_package_recipe_parse(recipe_wire, recipe_wire_len, &recipe);
    uint8_t recipe_root[32];
    if (recipe_error != VCS_PACKAGE_RECIPE_OK ||
        vcs_package_recipe_root(&recipe, recipe_root) !=
            VCS_PACKAGE_RECIPE_OK) {
        vcs_package_recipe_free(&recipe);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_RECIPE,
                   "vcs.package.transport", "canonical recipe rejected");
    }
    if (!vcs_package_manifest_parse(package_manifest_wire,
                                    package_manifest_wire_len,
                                    &out->source_manifest) ||
        !vcs_package_manifest_root(&out->source_manifest,
                                   out->package_root)) {
        vcs_package_recipe_free(&recipe);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_MANIFEST,
                   "vcs.package.transport", "canonical manifest rejected");
    }
    struct vcs_package_publish_report report;
    vcs_package_publish_report_init(&report);
    vcs_package_publish_validate(&out->release, &out->source_manifest,
                                 &report);
    vcs_package_publish_validate_recipe(&out->release,
                                        &out->source_manifest,
                                        &recipe, &report);
    vcs_package_recipe_free(&recipe);
    if (memcmp(out->release.package_root, out->package_root, 32) != 0 ||
        memcmp(out->release.recipe_root, recipe_root, 32) != 0 ||
        report.failure_count != 0 || !report.recipe_ok)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_BINDING,
                   "vcs.package.transport",
                   "release/manifest/recipe binding rejected");
    memcpy(out->recipe_root, recipe_root, 32);

    if (!transport_copy(&out->release_wire, &out->release_wire_len,
                        release_wire, release_wire_len,
                        "vcs.package.transport.release") ||
        !transport_copy(&out->recipe_wire, &out->recipe_wire_len,
                        recipe_wire, recipe_wire_len,
                        "vcs.package.transport.recipe") ||
        !transport_copy(&out->package_manifest_wire,
                        &out->package_manifest_wire_len,
                        package_manifest_wire, package_manifest_wire_len,
                        "vcs.package.transport.manifest"))
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_ALLOC,
                   "vcs.package.transport", "carrier wire allocation");

    if (!vcs_package_content_add_file(
            &out->transport_manifest, VCS_PACKAGE_TRANSPORT_RELEASE_PATH,
            VCS_PACKAGE_MODE_FILE, release_wire, release_wire_len) ||
        !vcs_package_content_add_file(
            &out->transport_manifest, VCS_PACKAGE_TRANSPORT_RECIPE_PATH,
            VCS_PACKAGE_MODE_FILE, recipe_wire, recipe_wire_len) ||
        !vcs_package_content_add_file(
            &out->transport_manifest, VCS_PACKAGE_TRANSPORT_MANIFEST_PATH,
            VCS_PACKAGE_MODE_FILE, package_manifest_wire,
            package_manifest_wire_len))
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_MANIFEST,
                   "vcs.package.transport", "carrier metadata manifest");
    if (!transport_add_sources(&out->transport_manifest,
                               &out->source_manifest))
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_PATH,
                   "vcs.package.transport", "carrier source path");
    if (!vcs_package_manifest_serialize(
            &out->transport_manifest, &out->transport_manifest_wire,
            &out->transport_manifest_wire_len) ||
        !vcs_package_manifest_root(&out->transport_manifest,
                                   out->transport_root))
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_MANIFEST,
                   "vcs.package.transport", "carrier manifest root");
    return VCS_PACKAGE_TRANSPORT_OK;
}

enum vcs_package_transport_result vcs_package_transport_store(
    struct vcs_package_store *store,
    const struct vcs_package_transport *transport,
    const char *source_dir)
{
    if (!store || !transport || !source_dir)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_NULL, "vcs.package.transport",
                   "null carrier publication input");
    uint8_t root[32];
    if (vcs_package_store_put_manifest(
            store, transport->transport_manifest_wire,
            transport->transport_manifest_wire_len, root) !=
            VCS_PACKAGE_STORE_OK ||
        memcmp(root, transport->transport_root, 32) != 0)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE,
                   "vcs.package.transport", "store carrier manifest");
    enum vcs_package_transport_result result =
        vcs_package_content_put_file(
            store, root, VCS_PACKAGE_TRANSPORT_RELEASE_PATH,
            transport->release_wire, transport->release_wire_len) ==
                VCS_PACKAGE_STORE_OK
            ? VCS_PACKAGE_TRANSPORT_OK : VCS_PACKAGE_TRANSPORT_ERR_STORE;
    if (result == VCS_PACKAGE_TRANSPORT_OK)
        result = vcs_package_content_put_file(
                     store, root, VCS_PACKAGE_TRANSPORT_RECIPE_PATH,
                     transport->recipe_wire, transport->recipe_wire_len) ==
                         VCS_PACKAGE_STORE_OK
            ? VCS_PACKAGE_TRANSPORT_OK : VCS_PACKAGE_TRANSPORT_ERR_STORE;
    if (result == VCS_PACKAGE_TRANSPORT_OK)
        result = vcs_package_content_put_file(
                     store, root, VCS_PACKAGE_TRANSPORT_MANIFEST_PATH,
                     transport->package_manifest_wire,
                     transport->package_manifest_wire_len) ==
                         VCS_PACKAGE_STORE_OK
            ? VCS_PACKAGE_TRANSPORT_OK : VCS_PACKAGE_TRANSPORT_ERR_STORE;
    uint8_t *buffer = NULL;
    if (result == VCS_PACKAGE_TRANSPORT_OK &&
        transport->source_manifest.count != 0) {
        buffer = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES,
                            "vcs.package.transport.source_chunk");
        if (!buffer)
            result = VCS_PACKAGE_TRANSPORT_ERR_ALLOC;
    }
    for (size_t i = 0;
         result == VCS_PACKAGE_TRANSPORT_OK &&
             i < transport->source_manifest.count;
         i++) {
        const struct vcs_package_file *file =
            &transport->source_manifest.files[i];
        char outer_path[256];
        if (!transport_source_path(file->path, outer_path)) {
            result = VCS_PACKAGE_TRANSPORT_ERR_PATH;
            break;
        }
        for (uint32_t chunk = 0; chunk < file->chunk_count; chunk++) {
            size_t len = 0;
            enum vcs_package_publish_rule rule = VCS_PACKAGE_PUBLISH_OK;
            if (!vcs_package_publish_read_chunk(source_dir, file, chunk,
                                                buffer, &len, &rule)) {
                result = VCS_PACKAGE_TRANSPORT_ERR_SOURCE;
                break;
            }
            if (vcs_package_store_put_chunk(store, root, outer_path, chunk,
                                            buffer, len) !=
                VCS_PACKAGE_STORE_OK) {
                result = VCS_PACKAGE_TRANSPORT_ERR_STORE;
                break;
            }
        }
    }
    free(buffer);
    struct vcs_package_store_status status;
    if (result != VCS_PACKAGE_TRANSPORT_OK ||
        !vcs_package_store_package_status(store, root, &status) ||
        !status.complete)
        LOG_RETURN(result == VCS_PACKAGE_TRANSPORT_OK
                       ? VCS_PACKAGE_TRANSPORT_ERR_STORE : result,
                   "vcs.package.transport", "carrier publication failed");
    /* Reconstruct the inner package out of the carrier we just wrote, the
     * same step a consumer runs after fetching it. Without this a publisher
     * holds every byte of its own package while the store has no record of
     * the package root — so it could not answer for its own release, and a
     * dependent carrier could not prove the dependency is one this node can
     * hand over. It is a CAS-only reconstruction: no new bytes, no build,
     * no execution. */
    struct vcs_package_transport_import receipt;
    enum vcs_package_transport_result imported =
        vcs_package_transport_import(store, root, &receipt);
    if (imported != VCS_PACKAGE_TRANSPORT_OK)
        LOG_RETURN(imported, "vcs.package.transport",
                   "carrier stored but its inner package did not reconstruct");
    return VCS_PACKAGE_TRANSPORT_OK;
}

static bool transport_read_file(struct vcs_package_store *store,
                                const uint8_t root[32],
                                const struct vcs_package_manifest *manifest,
                                const char *path, uint8_t **bytes_out,
                                size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    size_t index = 0;
    while (index < manifest->count &&
           strcmp(manifest->files[index].path, path) != 0)
        index++;
    return index < manifest->count &&
        vcs_package_content_get_file_at(
            store, root, manifest, (uint32_t)index, bytes_out, len_out) ==
                VCS_PACKAGE_STORE_OK;
}

enum vcs_package_transport_result vcs_package_transport_import(
    struct vcs_package_store *store, const uint8_t transport_root[32],
    struct vcs_package_transport_import *receipt)
{
    if (!store || !transport_root || !receipt)
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_NULL, "vcs.package.transport",
                   "null carrier import input");
    memset(receipt, 0, sizeof(*receipt));
    uint8_t *outer_wire = NULL;
    size_t outer_wire_len = 0;
    struct vcs_package_manifest outer;
    vcs_package_manifest_init(&outer);
    uint8_t checked_root[32];
    if (vcs_package_store_get_manifest_wire(
            store, transport_root, &outer_wire, &outer_wire_len) !=
            VCS_PACKAGE_STORE_OK ||
        !vcs_package_manifest_parse(outer_wire, outer_wire_len, &outer) ||
        !vcs_package_manifest_root(&outer, checked_root) ||
        memcmp(checked_root, transport_root, 32) != 0) {
        free(outer_wire);
        vcs_package_manifest_free(&outer);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_MANIFEST,
                   "vcs.package.transport", "carrier root rejected");
    }
    uint8_t *release_wire = NULL, *recipe_wire = NULL, *manifest_wire = NULL;
    size_t release_len = 0, recipe_len = 0, manifest_len = 0;
    bool read = transport_read_file(
                    store, transport_root, &outer,
                    VCS_PACKAGE_TRANSPORT_RELEASE_PATH,
                    &release_wire, &release_len) &&
        transport_read_file(store, transport_root, &outer,
                            VCS_PACKAGE_TRANSPORT_RECIPE_PATH,
                            &recipe_wire, &recipe_len) &&
        transport_read_file(store, transport_root, &outer,
                            VCS_PACKAGE_TRANSPORT_MANIFEST_PATH,
                            &manifest_wire, &manifest_len);
    if (!read) {
        free(manifest_wire); free(recipe_wire); free(release_wire);
        free(outer_wire); vcs_package_manifest_free(&outer);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE,
                   "vcs.package.transport", "carrier metadata missing");
    }
    struct vcs_package_transport expected;
    vcs_package_transport_init(&expected);
    enum vcs_package_transport_result result = vcs_package_transport_build(
        release_wire, release_len, recipe_wire, recipe_len,
        manifest_wire, manifest_len, &expected);
    free(manifest_wire); free(recipe_wire); free(release_wire);
    if (result == VCS_PACKAGE_TRANSPORT_OK &&
        (memcmp(expected.transport_root, transport_root, 32) != 0 ||
         expected.transport_manifest_wire_len != outer_wire_len ||
         memcmp(expected.transport_manifest_wire, outer_wire,
                outer_wire_len) != 0))
        result = VCS_PACKAGE_TRANSPORT_ERR_BINDING;
    free(outer_wire);
    vcs_package_manifest_free(&outer);
    if (result != VCS_PACKAGE_TRANSPORT_OK) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(result, "vcs.package.transport",
                   "carrier closure mismatch");
    }
    uint8_t admitted_root[32], admitted_recipe[32];
    enum vcs_package_accept_result accept = VCS_PACKAGE_ACCEPT_INVALID;
    /* Five separate admissions, each with its own name. They used to share
     * one `||` chain and one message — "inner package admission" — so a
     * carrier refused because its publisher key does not own the namespace
     * logged exactly the same three words as one whose recipe bytes hash to
     * a recipe the release never named. The operator's next step differs for
     * every one of them, and the caller only ever sees the class ("store"),
     * so this log line is the whole diagnosis. The returned result is
     * deliberately unchanged: this names the failure, it does not reclassify
     * it. */
    enum vcs_package_store_result put = vcs_package_store_put_manifest(
        store, expected.package_manifest_wire,
        expected.package_manifest_wire_len, admitted_root);
    if (put != VCS_PACKAGE_STORE_OK) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE, "vcs.package.transport",
                   "carrier package manifest refused: %s",
                   vcs_package_store_result_string(put));
    }
    if (memcmp(admitted_root, expected.package_root, 32) != 0) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE, "vcs.package.transport",
                   "carrier package manifest hashes to a different package "
                   "root than the release names");
    }
    put = vcs_package_store_put_recipe(store, expected.recipe_wire,
                                       expected.recipe_wire_len,
                                       admitted_recipe);
    if (put != VCS_PACKAGE_STORE_OK) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE, "vcs.package.transport",
                   "carrier recipe refused: %s",
                   vcs_package_store_result_string(put));
    }
    if (memcmp(admitted_recipe, expected.recipe_root, 32) != 0) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE, "vcs.package.transport",
                   "carrier recipe hashes to a different recipe root than "
                   "the release names");
    }
    put = vcs_package_store_put_release(store, &expected.release, &accept);
    if (put != VCS_PACKAGE_STORE_OK) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE, "vcs.package.transport",
                   "carrier signed release refused: %s (acceptance: %s)",
                   vcs_package_store_result_string(put),
                   vcs_package_accept_result_string(accept));
    }
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(
            store, expected.package_root, &status) || !status.complete) {
        vcs_package_transport_free(&expected);
        LOG_RETURN(VCS_PACKAGE_TRANSPORT_ERR_STORE,
                   "vcs.package.transport", "inner CAS reconstruction");
    }
    memcpy(receipt->transport_root, expected.transport_root, 32);
    memcpy(receipt->package_root, expected.package_root, 32);
    memcpy(receipt->recipe_root, expected.recipe_root, 32);
    memcpy(receipt->release_id, expected.release_id, 32);
    receipt->source_bytes = status.total_bytes;
    receipt->source_chunks = status.total_chunks;
    receipt->cas_objects_reused = status.present_chunks;
    vcs_package_transport_free(&expected);
    return VCS_PACKAGE_TRANSPORT_OK;
}
