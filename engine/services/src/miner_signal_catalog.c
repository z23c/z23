/* purpose: Hash a canonical network-bound miner ballot catalog. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_catalog.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include <string.h>

static bool catalog_nonzero(const uint8_t bytes[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32; ++i) aggregate |= bytes[i];
    return aggregate != 0;
}

static struct zcl_result catalog_validate(const struct miner_signal_catalog *c, size_t slot)
{
    if (!c || !c->entries || c->count == 0 || c->count > 256 || slot >= c->count)
        return ZCL_ERR(-1, "Invalid catalog or selected slot");
    if (!catalog_nonzero(c->network_id) || !catalog_nonzero(c->genesis))
        return ZCL_ERR(-2, "Network and genesis identities must be nonzero");
    if (c->start < 1 || c->window < 1)
        return ZCL_ERR(-3, "Invalid catalog voting window");
    for (size_t i = 0; i < c->count; ++i) {
        if (i && memcmp(c->entries[i - 1].rule_revision, c->entries[i].rule_revision, 32) >= 0)
            return ZCL_ERR(-4, "Rule revisions must be strictly ascending");
        if (c->entries[i].activation <= (int64_t)c->start + c->window)
            return ZCL_ERR(-5, "Activation must follow a complete grace block");
    }
    return ZCL_OK;
}

static void catalog_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t bytes[4];
    zcl_write_u32_le(bytes, value);
    sha3_256_write(ctx, bytes, sizeof(bytes));
}

static void catalog_digest(const struct miner_signal_catalog *c, uint8_t out[32])
{
    static const uint8_t domain[] = "Z23-CATALOG-V1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain) - 1);
    sha3_256_write(&ctx, c->network_id, sizeof(c->network_id));
    sha3_256_write(&ctx, c->genesis, sizeof(c->genesis));
    catalog_u32(&ctx, (uint32_t)c->start);
    catalog_u32(&ctx, (uint32_t)c->window);
    catalog_u32(&ctx, (uint32_t)c->count);
    catalog_u32(&ctx, 95);
    catalog_u32(&ctx, 100);
    catalog_u32(&ctx, 1);
    for (size_t i = 0; i < c->count; ++i) {
        sha3_256_write(&ctx, c->entries[i].rule_revision, 32);
        catalog_u32(&ctx, (uint32_t)c->entries[i].activation);
    }
    sha3_256_finalize(&ctx, out);
}

struct zcl_result miner_signal_catalog_select(const struct miner_signal_catalog *c,
                                              size_t slot,
                                              struct miner_signal_schedule *out)
{
    if (!out) return ZCL_ERR(-6, "Missing output schedule");
    struct zcl_result valid = catalog_validate(c, slot);
    if (!valid.ok) return valid;
    struct miner_signal_schedule selected = {
        .start = c->start, .window = c->window,
        .activation = c->entries[slot].activation,
        .slots = (uint16_t)c->count, .slot = (uint16_t)slot
    };
    catalog_digest(c, selected.catalog);
    *out = selected;
    return ZCL_OK;
}
