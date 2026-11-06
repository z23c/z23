/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: share a personal package copy by one file, with no account and no
 * node — the .z23share file zcode.package.sign (or share with `output`)
 * writes, the verify and receive leaves that read it, and the receive trust
 * record a later build or open of the received copy reads.
 *
 * A share file is transport only. It carries the signed release envelope,
 * the canonical manifest and recipe wires that envelope binds, and the copy's
 * saved tree as an ordinary ZVCS source bundle (.zvsb wire). The signed
 * release stays the authority: the receiver re-derives the tree root from the
 * bundle, materializes it into private scratch and runs the same publication
 * validation zcode.package.publish.commit runs (signature, manifest root,
 * recipe root, every chunk) before anything is kept.
 *
 * Layout, little-endian:
 *   "Z23SHARE" | u32 version (1)
 *   | u32 len | release wire | u32 len | manifest wire | u32 len | recipe wire
 *   | 32-byte ZVCS tree root | u32 len | source bundle wire
 * and nothing after it.
 *
 * Receive trust record: the friend's one-time confirmation of a publisher
 * fingerprint and an exact package root, written only by the owner-only
 * zcode.package.bundle.receive confirm. It lives in the receiver's datadir,
 * never in the copy, keyed by (the copy's root commit, the release id):
 *   <datadir>/zcode/received/<copy_root hex>.<release_id hex>.trust
 * holding exactly these lines:
 *   zcl.zcode_package_receive_trust.v1
 *   copy_root <64 hex>
 *   release_id <64 hex>
 *   publisher <66 hex>
 *   package_root <64 hex>
 *   parent_release_root <64 hex | none>
 *   confirmed owner
 * The adopt check (zcl_package_copy_adopted) reads it through
 * zcl_package_receive_trust_read. */

#ifndef ZCL_NATIVE_ZCODE_PACKAGE_BUNDLE_H
#define ZCL_NATIVE_ZCODE_PACKAGE_BUNDLE_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PACKAGE_BUNDLE_MAGIC "Z23SHARE"
#define ZCL_PACKAGE_BUNDLE_VERSION 1u
#define ZCL_PACKAGE_BUNDLE_SUFFIX ".z23share"
#define ZCL_PACKAGE_RECEIVE_TRUST_DIR "zcode/received"
#define ZCL_PACKAGE_RECEIVE_TRUST_SCHEMA "zcl.zcode_package_receive_trust.v1"

struct zcl_package_receive_trust {
    uint8_t copy_root[32];
    uint8_t release_id[32];
    uint8_t publisher[33];
    uint8_t package_root[32];
    bool has_parent;
    uint8_t parent_release[32];
};

/* The wires one share file carries; borrowed, never freed here. */
struct zcl_package_bundle_wires {
    const uint8_t *release;
    size_t release_len;
    const uint8_t *manifest;
    size_t manifest_len;
    const uint8_t *recipe;
    size_t recipe_len;
};

/* Write one share file at output (exclusive create; an existing path is
 * refused): the wires plus the saved tree of the ZVCS store in copy_dir.
 * Fails the reply with SHARE_FILE_* and returns false on refusal. */
bool zcl_package_bundle_write(const char *output, const char *copy_dir,
                              const uint8_t tree[32],
                              const struct zcl_package_bundle_wires *wires,
                              struct zcl_command_reply *reply);

/* Read the receive trust record for (copy_root, release_id) under datadir.
 * True only when the record exists, parses exactly and names both keys. */
bool zcl_package_receive_trust_read(const char *datadir,
                                    const uint8_t copy_root[32],
                                    const uint8_t release_id[32],
                                    struct zcl_package_receive_trust *out);

#endif
