/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: closed content.v2 carrier for one signed reusable C23 package. */
#ifndef ZCL_VCS_PACKAGE_TRANSPORT_H
#define ZCL_VCS_PACKAGE_TRANSPORT_H

#include "vcs/package_manifest.h"
#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_TRANSPORT_VERSION 1u
#define VCS_PACKAGE_TRANSPORT_RELEASE_PATH \
    "zcode-package-transport/release.v1"
#define VCS_PACKAGE_TRANSPORT_RECIPE_PATH \
    "zcode-package-transport/recipe.v1"
#define VCS_PACKAGE_TRANSPORT_MANIFEST_PATH \
    "zcode-package-transport/manifest.v2"
#define VCS_PACKAGE_TRANSPORT_SOURCE_PREFIX \
    "zcode-package-transport/source/"

struct vcs_package_store;

enum vcs_package_transport_result {
    VCS_PACKAGE_TRANSPORT_OK = 0,
    VCS_PACKAGE_TRANSPORT_ERR_NULL,
    VCS_PACKAGE_TRANSPORT_ERR_RELEASE,
    VCS_PACKAGE_TRANSPORT_ERR_RECIPE,
    VCS_PACKAGE_TRANSPORT_ERR_MANIFEST,
    VCS_PACKAGE_TRANSPORT_ERR_BINDING,
    VCS_PACKAGE_TRANSPORT_ERR_PATH,
    VCS_PACKAGE_TRANSPORT_ERR_ALLOC,
    VCS_PACKAGE_TRANSPORT_ERR_SOURCE,
    VCS_PACKAGE_TRANSPORT_ERR_STORE,
};

/* A package transport is an ordinary content.v2 package. It deliberately
 * introduces no new CAS or network object: the existing package swarm sees
 * one manifest and immutable chunks. Source chunks retain their exact hashes,
 * so importing the inner package is a CAS-only reconstruction with no copy.
 * Build/test/install authority is outside this type. */
struct vcs_package_transport {
    struct vcs_package_manifest source_manifest;
    struct vcs_package_manifest transport_manifest;
    struct vcs_package_release release;
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t release_id[32];
    uint8_t transport_root[32];
    uint8_t *release_wire;
    size_t release_wire_len;
    uint8_t *recipe_wire;
    size_t recipe_wire_len;
    uint8_t *package_manifest_wire;
    size_t package_manifest_wire_len;
    uint8_t *transport_manifest_wire;
    size_t transport_manifest_wire_len;
};

struct vcs_package_transport_import {
    uint8_t transport_root[32];
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t release_id[32];
    uint64_t source_bytes;
    uint32_t source_chunks;
    uint32_t cas_objects_reused;
};

const char *vcs_package_transport_result_string(
    enum vcs_package_transport_result result);
void vcs_package_transport_init(struct vcs_package_transport *transport);
void vcs_package_transport_free(struct vcs_package_transport *transport);

/* Verify the signed author envelope, recipe, inner package manifest and all
 * bindings, then derive the deterministic outer content.v2 carrier. `out`
 * must first be initialized. No bytes are stored and no source files are
 * read. */
enum vcs_package_transport_result vcs_package_transport_build(
    const uint8_t *release_wire, size_t release_wire_len,
    const uint8_t *recipe_wire, size_t recipe_wire_len,
    const uint8_t *package_manifest_wire, size_t package_manifest_wire_len,
    struct vcs_package_transport *out);

/* Explicit publication step. Reads the exact source files under source_dir,
 * re-verifies their committed chunks, and stores the carrier in the existing
 * package CAS. This never announces, builds, tests, installs, or executes. */
enum vcs_package_transport_result vcs_package_transport_store(
    struct vcs_package_store *store,
    const struct vcs_package_transport *transport,
    const char *source_dir);

/* FETCH/STORE -> VERIFY reconstruction step. The carrier must already be
 * complete in store. This verifies its closure, admits the canonical inner
 * manifest/release/recipe, and proves the inner package is complete entirely
 * from already-verified CAS objects. It grants no build or execution power. */
enum vcs_package_transport_result vcs_package_transport_import(
    struct vcs_package_store *store, const uint8_t transport_root[32],
    struct vcs_package_transport_import *receipt);

#endif /* ZCL_VCS_PACKAGE_TRANSPORT_H */
