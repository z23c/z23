/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Process-global swarm accessor and stable public result names. */

#include "vcs/package_swarm_node.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stddef.h>
#include <string.h>

bool vcs_swarm_bitmap_get(const uint8_t *map, uint32_t bit)
{
    return (map[bit / 8u] >> (bit % 8u)) & 1u;
}

void vcs_swarm_bitmap_set(uint8_t *map, uint32_t bit)
{
    map[bit / 8u] |= (uint8_t)(1u << (bit % 8u));
}

void vcs_swarm_derive_request_id32(const uint8_t key[33],
                                   uint64_t request_id,
                                   const uint8_t root[32], uint8_t out[32])
{
    static const char domain[] = "zcl.zcode_swarm_request.v1";
    struct sha3_256_ctx ctx;
    uint8_t id_le[8];
    zcl_write_u64_le(id_le, request_id);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&ctx, key, 33);
    sha3_256_write(&ctx, id_le, sizeof(id_le));
    sha3_256_write(&ctx, root, 32);
    sha3_256_finalize(&ctx, out);
}

bool vcs_swarm_provider_allowed(bool restricted, const uint64_t *allowed,
                                size_t count, uint64_t peer)
{
    if (!restricted)
        return true;
    for (size_t i = 0; i < count; i++)
        if (allowed[i] == peer)
            return true;
    return false;
}

size_t vcs_swarm_provider_set(uint64_t *out, size_t capacity,
                              const uint64_t *peers, size_t count)
{
    memset(out, 0, capacity * sizeof(*out));
    size_t used = 0;
    for (size_t i = 0; i < count && used < capacity; i++) {
        if (!peers[i])
            continue;
        size_t at = 0;
        while (at < used && out[at] < peers[i])
            at++;
        if (at < used && out[at] == peers[i])
            continue;
        memmove(&out[at + 1], &out[at], (used - at) * sizeof(*out));
        out[at] = peers[i];
        used++;
    }
    return used;
}

static struct vcs_swarm_engine *g_swarm_engine;

void vcs_swarm_engine_set_global(struct vcs_swarm_engine *engine)
{
    g_swarm_engine = engine;
}

struct vcs_swarm_engine *vcs_swarm_engine_global(void)
{
    return g_swarm_engine;
}

const char *vcs_swarm_fetch_result_string(enum vcs_swarm_fetch_result result)
{
    switch (result) {
    case VCS_SWARM_FETCH_OK: return "ok";
    case VCS_SWARM_FETCH_ALREADY_COMPLETE: return "already-complete";
    case VCS_SWARM_FETCH_NO_STORE: return "no-store";
    case VCS_SWARM_FETCH_FULL: return "download-table-full";
    case VCS_SWARM_FETCH_RECORD_IO: return "record-io";
    case VCS_SWARM_FETCH_BYTE_LIMIT: return "byte-limit";
    case VCS_SWARM_FETCH_BOUND_NOT_OWNED: return "bound-not-owned";
    case VCS_SWARM_FETCH_NO_PROVIDER: return "no-authenticated-provider";
    case VCS_SWARM_FETCH_BAD_INPUT: return "bad-input";
    }
    return "unknown";
}

const char *vcs_swarm_download_state_string(
    enum vcs_swarm_download_state state)
{
    switch (state) {
    case VCS_SWARM_DL_INACTIVE: return "inactive";
    case VCS_SWARM_DL_WANT_MANIFEST: return "want-manifest";
    case VCS_SWARM_DL_CHUNKS: return "downloading";
    case VCS_SWARM_DL_COMPLETE: return "complete";
    case VCS_SWARM_DL_FAILED: return "failed";
    }
    return "unknown";
}
