/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_image — the zcl.app_build.v1 BUILD RECORD of one personal app copy.
 *
 * One record says which exact image a copy build produced and from what:
 *   package_root     the copy's package root (the saved source tree)
 *   closure_root     the input closure of the compile actions that built
 *                    it: each action's zcl.action_preimage.v2 derived from
 *                    the compiler's own -MD depfile (devloop_action_root.h),
 *                    split by vcs_action_preimage_v2_input_closure() and
 *                    rooted by vcs_build_input_closure_v1_root()
 *   env_root         vcs_toolchain_capsule_v1_root() of the captured
 *                    toolchain capsule (vcs_toolchain_capsule_v1_capture)
 *                    for host builds; selected compiler kits use SHA3-256 of
 *                    "zcl.app_build.kit_env.v1" NUL, full tree root, target NUL,
 *                    and "zcl.app_toolchain.linux_sealed.v1" NUL. The opaque
 *                    32-byte field and record/key codec remain unchanged.
 *   dependency_root  the pinned dependency set the build linked against
 *   image_sha3       SHA3-256 of the image bytes
 *   image triple     the positioned-file identity (volume, low, high,
 *                    size) captured over the image handle at record time
 * The last two are exactly the struct resident_launch_accepted that
 * resident_launch_prepare() needs to spawn that image and no other.
 *
 * This is NOT the ZCLBLD package_build receipt (vcs/package_build.h): that
 * wire carries no domain, so a record that could be mistaken for one could
 * be offered to install or reproduce. This wire begins with the literal
 * domain "zcl.app_build.v1"; ZCLBLD's magic is different, so the package
 * parser, install and reproduce all refuse it, and this decoder refuses a
 * ZCLBLD wire.
 *
 * Canonical wire (APP_IMAGE_BUILD_WIRE_BYTES, integers little-endian, one
 * legal encoding):
 *   [16 domain "zcl.app_build.v1"]
 *   [32 package_root][32 closure_root][32 env_root][32 dependency_root]
 *   [32 image_sha3]
 *   [8 image_volume][8 image_low][8 image_high][8 image_size]
 *   [32 record_id = SHA3-256("zcl.app_build.v1" 0x00 || bytes 0..207)]
 * Every root must be non-zero and image_size non-zero. Any other length,
 * domain, zero field or digest mismatch is refused with a reason.
 *
 * Store. A record lives at <store>/<key hex>.appbuild where key =
 * SHA3-256("zcl.app_build.key.v1" 0x00 || package_root || env_root ||
 * dependency_root): every input that exists BEFORE a build. Restoring an
 * earlier saved version brings back its package_root, so the same key finds
 * its record and the build is a cache hit. The closure is derived from the
 * compile, so it is bound in the record, not in the key. Saves validate,
 * encode, then write tmp -> fsync -> rename -> fsync(dir)
 * (authority_receipt_write_atomic). */
#ifndef ZCL_TOOLS_COMMAND_APP_IMAGE_H
#define ZCL_TOOLS_COMMAND_APP_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "base/result.h"
#include "platform/resident_launch.h"

struct zcl_action_root_request;
struct vcs_package_lock;

/* Shared build/open identity of the sorted directly declared dependencies. */
void app_image_dependency_root(const struct vcs_package_lock *lock, uint8_t out[32]);

#define APP_IMAGE_BUILD_DOMAIN "zcl.app_build.v1"
#define APP_IMAGE_BUILD_DOMAIN_BYTES 16u
#define APP_IMAGE_BUILD_KEY_DOMAIN "zcl.app_build.key.v1"
#define APP_IMAGE_BUILD_CLOSURE_SET_DOMAIN "zcl.app_build.closure_set.v1"
#define APP_IMAGE_BUILD_BODY_BYTES 208u
#define APP_IMAGE_BUILD_WIRE_BYTES 240u
#define APP_IMAGE_BUILD_FILE_SUFFIX ".appbuild"
/* Most compile actions one closure root folds. */
#define APP_IMAGE_BUILD_MAX_ACTIONS 256u

struct app_image_build {
    uint8_t package_root[32];
    uint8_t closure_root[32];
    uint8_t env_root[32];
    uint8_t dependency_root[32];
    uint8_t image_sha3[32];
    uint64_t image_volume, image_low, image_high, image_size;
};

/* Host-mode env_root only: capture the toolchain capsule and root it.
 * Build/current-environment lookup resolve installed kits separately. Exact
 * selected-image launch never requires the current compiler to be available. */
struct zcl_result app_image_env_root(uint8_t out[32]);

/* Hash the image at `image_path` and capture its positioned-file triple,
 * proving the handle's snapshot did not change while it was read. */
struct zcl_result app_image_capture(const char *image_path,
                                    struct app_image_build *rec);

struct zcl_result app_image_build_validate(const struct app_image_build *rec);
struct zcl_result app_image_build_encode(
    const struct app_image_build *rec,
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES]);
/* Strict decode: exact length, domain, non-zero fields and record id. */
struct zcl_result app_image_build_decode(const uint8_t *wire, size_t len,
                                         struct app_image_build *out);
/* record_id of a valid record (the digest the wire carries last). */
struct zcl_result app_image_build_id(const struct app_image_build *rec,
                                     uint8_t out[32]);

void app_image_build_key(const uint8_t package_root[32],
                         const uint8_t env_root[32],
                         const uint8_t dependency_root[32], uint8_t out[32]);

/* The acceptance resident_launch_prepare() checks the live image against. */
void app_image_build_accepted(const struct app_image_build *rec,
                              struct resident_launch_accepted *out);

/* Validate, encode and atomically write the record under its key into the
 * existing directory `store_dir`. `path_out` (optional) gets the final path. */
struct zcl_result app_image_build_save(const char *store_dir,
                                       const struct app_image_build *rec,
                                       char *path_out, size_t path_cap);

/* Find the record for (package_root, env_root, dependency_root). No record
 * is ok with *hit false; a present record that is malformed, truncated or
 * names other inputs is refused with a reason, never treated as a miss. */
struct zcl_result app_image_build_load(const char *store_dir,
                                       const uint8_t package_root[32],
                                       const uint8_t env_root[32],
                                       const uint8_t dependency_root[32],
                                       struct app_image_build *out, bool *hit);

/* resident_launch_prepare() of `image_path` against this record: refuses an
 * image whose bytes, size or identity triple differ from what was built. */
struct zcl_result app_image_build_prepare(const struct app_image_build *rec,
                                          const char *image_path,
                                          struct resident_launch *launch);

#endif /* ZCL_TOOLS_COMMAND_APP_IMAGE_H */
