/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read-only derivation of a ZCODE package's signed release inputs. */
#ifndef ZCL_VCS_PACKAGE_PREPARE_H
#define ZCL_VCS_PACKAGE_PREPARE_H

#include "vcs/package_capsule.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum vcs_package_prepare_error {
    VCS_PACKAGE_PREPARE_OK = 0,
    VCS_PACKAGE_PREPARE_ERR_NULL,
    VCS_PACKAGE_PREPARE_ERR_PATH,
    VCS_PACKAGE_PREPARE_ERR_FILE_TYPE,
    VCS_PACKAGE_PREPARE_ERR_CHANGED,
    VCS_PACKAGE_PREPARE_ERR_IO,
    VCS_PACKAGE_PREPARE_ERR_ALLOC,
    VCS_PACKAGE_PREPARE_ERR_META,
    VCS_PACKAGE_PREPARE_ERR_MANIFEST,
    VCS_PACKAGE_PREPARE_ERR_RECIPE,
    VCS_PACKAGE_PREPARE_ERR_LOCK,
    VCS_PACKAGE_PREPARE_ERR_CAPSULE,
    VCS_PACKAGE_PREPARE_ERR_RELEASE,
};

struct vcs_package_prepare_options {
    const char *dir;
    uint8_t publisher_pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    uint64_t publisher_sequence;
    const char *reward_address; /* NULL means empty */
    const char *chain_id;       /* NULL means zclassic-main */
};

struct vcs_package_prepared {
    struct vcs_package_manifest manifest;
    struct vcs_package_recipe recipe;
    struct vcs_package_lock lock;
    struct vcs_package_capsule capsule;
    struct vcs_package_release release;
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t lock_root[32];
    uint8_t capsule_root[32];
    uint8_t signing_digest[32];
    uint8_t *manifest_wire;
    size_t manifest_wire_len;
    uint8_t *recipe_wire;
    size_t recipe_wire_len;
    uint8_t *lock_wire;
    size_t lock_wire_len;
    uint8_t *capsule_wire;
    size_t capsule_wire_len;
    uint8_t *release_body;
    size_t release_body_len;
};

const char *vcs_package_prepare_error_string(
    enum vcs_package_prepare_error error);
void vcs_package_prepared_init(struct vcs_package_prepared *prepared);
void vcs_package_prepared_free(struct vcs_package_prepared *prepared);

/* Opens the supplied directory without following symlinks, rejects every
 * non-regular/non-directory entry and any file that changes while read, then
 * derives all canonical wires. Root-level `.zvcs`, `.codeindex`, and `build`
 * directories are local control/output stores and do not enter the package
 * identity; a symlink or special file with those names is still refused. The
 * closed metadata may carry an optional strict, sorted `files` array; when
 * present, only those exact paths (which must include zcode-package.json)
 * enter the manifest and build recipe. This lets a real module expose a
 * package subset without copying source bytes. It creates and persists
 * nothing. */
enum vcs_package_prepare_error vcs_package_prepare(
    const struct vcs_package_prepare_options *options,
    struct vcs_package_prepared *out, char *detail, size_t detail_cap);

/* Read-only pre-initialization scan. It applies the exact same no-follow,
 * regular-file-only traversal as prepare(), and derives the existing recipe
 * layout without requiring zcode-package.json. Only out->manifest and
 * out->recipe are populated; callers release them with
 * vcs_package_prepared_free(). has_package_config reports whether the scan
 * observed the metadata file. No canonical object is persisted. */
enum vcs_package_prepare_error vcs_package_scan_layout(
    const char *dir, struct vcs_package_prepared *out,
    bool *has_package_config, char *detail, size_t detail_cap);

#endif /* ZCL_VCS_PACKAGE_PREPARE_H */
