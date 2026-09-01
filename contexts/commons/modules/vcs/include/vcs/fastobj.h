/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fastobj — the shared authority for the zcl.fastobj.v1 translation-unit
 * object cache identity. tools/package_verify.c (the confined build
 * worker that populates the cache) and the fastobj carrier (which moves
 * cache entries between nodes as an ordinary content.v2 package) derive
 * the SAME key through this one implementation; a second copy of the
 * derivation anywhere would be a second source of truth.
 *
 * A fastobj key is an INPUT identity only. It names the compile action
 * (toolchain capsule root, target, profile, root-normalized compile
 * argv, preprocessed-unit SHA3-256) — never the object's admission. No
 * object is ever admitted on its key alone; the output anchor is a ZCLBLD
 * receipt's artifact hash (docs/work/WIRE_COMPILE_CACHE.md).
 */

#ifndef ZCL_VCS_FASTOBJ_H
#define ZCL_VCS_FASTOBJ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Hash domain and sidecar schema, frozen with the trailing 0x00 byte the
 * derivation hashes (sizeof the literal). */
#define VCS_FASTOBJ_DOMAIN "zcl.fastobj.v1"
#define VCS_FASTOBJ_SIDECAR_SCHEMA "zcl.fastobj.sidecar.v1"

/* Sidecar parse bound — mirrors the worker's PV_FASTOBJ_SIDECAR_CAP. */
#define VCS_FASTOBJ_SIDECAR_MAX_BYTES (256u * 1024u)

/* The cache key: SHA3-256 over the domain (with its NUL), the v1 toolchain
 * capsule root, the target and profile strings, each rendered compile
 * argv element, and the preprocessed-unit SHA3-256. argv must already be
 * root-normalized (@package/@build/@dep/<root> tokens) exactly as the
 * sidecar records it. Strings are hashed with the build_action.c
 * convention: u64 LE length, then the bytes. */
bool vcs_fastobj_key(const uint8_t capsule_root[32], const char *target,
                     const char *profile, const char *const *argv,
                     const uint8_t preproc_sha3[32], uint8_t out[32]);

/* The on-disk cache layout, one authority for producer and importer:
 *   <dir>/objects/<first 2 hex>/<remaining 62 hex>.o     cached object
 *   <dir>/objects/<first 2 hex>/<remaining 62 hex>.json  sidecar
 * key_hex is the 64 lowercase hex chars of the key. */
bool vcs_fastobj_cache_paths(const char *cache_dir, const char *key_hex,
                             char *obj_path, size_t obj_cap,
                             char *side_path, size_t side_cap);

/* Verify one sidecar document against its claimed key. Requires the
 * zcl.fastobj.sidecar.v1 schema, a complete key_components object
 * (capsule_root, target, profile, argv, preprocessed_sha3) whose derived
 * key equals key_hex, and a decodable object_sha3, returned in
 * object_sha3_out. This proves the entry sits under the path its own
 * declared inputs hash to; it does NOT prove the object bytes are honest
 * (compare SHA3-256 of the object against object_sha3_out for that) and
 * it is never an admission. */
bool vcs_fastobj_sidecar_verify(const uint8_t *side, size_t side_len,
                                const char *key_hex,
                                uint8_t object_sha3_out[32],
                                char *err, size_t err_cap);

#endif /* ZCL_VCS_FASTOBJ_H */
