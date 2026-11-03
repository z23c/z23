/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_fetch_manifest — the pure, I/O-free parse + content-bind of the "RMF"
 * per-chunk manifest blob. Split out of rom_fetch.c (which is at its
 * file-size limit) because it touches no socket or disk: the wire fetch
 * (rom_fetch_get_manifest) stays in rom_fetch.c and calls this. Trust is
 * unchanged: the digests are bound to the committed chunk_root before use. */

#include "net/rom_fetch.h"
#include "rom_fetch_internal.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include <string.h>

/* Manifest blob header: length shape, version 1, num_chunks bounds. */
static bool rf_manifest_hdr_ok(const uint8_t *blob, size_t len,
                               uint32_t out_cap, uint32_t *nc_out)
{
    if (len < 8u || len > ROM_SEED_MANIFEST_BLOB_MAX || ((len - 8u) % 32u) != 0u)
        return false;

    uint32_t version = zcl_read_u32_le(blob);
    uint32_t nc = zcl_read_u32_le(blob + 4);
    if (version != 1u)
        return false;
    if (nc == 0u || nc > ROM_SEED_MAX_CHUNKS || nc > out_cap ||
        (size_t)nc * 32u != (len - 8u))
        return false;
    *nc_out = nc;
    return true;
}

bool rom_fetch_parse_manifest_blob(const uint8_t *blob, size_t len,
                                   const uint8_t chunk_root[32],
                                   uint8_t (*out_chunk_sha3)[32],
                                   uint32_t out_cap, uint32_t *out_num_chunks)
{
    if (!blob || !chunk_root || !out_chunk_sha3 || out_cap == 0 ||
        !out_num_chunks)
        return false; /* raw-return-ok: predicate; NULL is "not a manifest" */
    *out_num_chunks = 0;

    uint32_t nc = 0;
    if (!rf_manifest_hdr_ok(blob, len, out_cap, &nc))
        return false;

    /* Content bind: fold the per-chunk digests exactly as the seeder derived
     * chunk_root (SHA3 over the concatenated per-chunk digests). A mismatch
     * means these digests are not the committed artifact's. */
    struct sha3_256_ctx root_ctx;
    sha3_256_init(&root_ctx);
    for (uint32_t i = 0; i < nc; i++)
        sha3_256_write(&root_ctx, blob + 8u + (size_t)i * 32u, 32);
    uint8_t computed_root[32];
    sha3_256_finalize(&root_ctx, computed_root);
    if (memcmp(computed_root, chunk_root, 32) != 0)
        return false;

    for (uint32_t i = 0; i < nc; i++)
        memcpy(out_chunk_sha3[i], blob + 8u + (size_t)i * 32u, 32);
    *out_num_chunks = nc;
    return true;
}
