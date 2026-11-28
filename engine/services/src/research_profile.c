/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Commit a research profile identity and refuse a foreign child. */

#include "services/research_profile.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static void profile_sha256d(const uint8_t *data, size_t len, uint8_t out[32])
{
    struct sha256_ctx ctx;
    uint8_t mid[32];
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, mid);
    sha256_init(&ctx);
    sha256_write(&ctx, mid, sizeof(mid));
    sha256_finalize(&ctx, out);
}

static void profile_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t bytes[4];
    zcl_write_u32_le(bytes, value);
    sha3_256_write(ctx, bytes, sizeof(bytes));
}

static int baseline_nonzero(const uint8_t baseline[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; ++i) acc |= baseline[i];
    return acc != 0;
}

static struct zcl_result spec_pointers(const struct research_profile_spec *spec)
{
    if (!spec || !spec->baseline || !spec->activations)
        return ZCL_ERR(-1, "Missing profile descriptor");
    if (!spec->genesis_wire || !spec->datadir || !spec->transport_domain)
        return ZCL_ERR(-1, "Missing profile descriptor");
    return ZCL_OK;
}

static struct zcl_result spec_local(const struct research_profile_spec *spec)
{
    if (!spec->datadir[0] || !spec->transport_domain[0])
        return ZCL_ERR(-2, "Missing local profile configuration");
    if (spec->rpc_port == 0) return ZCL_ERR(-2, "Missing local profile configuration");
    if (strlen(spec->datadir) >= 32) return ZCL_ERR(-8, "Datadir name is too long");
    return ZCL_OK;
}

static struct zcl_result spec_one_height(const struct research_profile_spec *spec, size_t i)
{
    if (spec->activations[i] <= (int64_t)spec->start + spec->window)
        return ZCL_ERR(-6, "Activation must follow the voting window");
    if (i > 0 && spec->activations[i] <= spec->activations[i - 1])
        return ZCL_ERR(-7, "Activation heights must increase");
    return ZCL_OK;
}

static struct zcl_result spec_schedule(const struct research_profile_spec *spec)
{
    if (spec->activation_count == 0 || spec->activation_count > 8)
        return ZCL_ERR(-3, "Invalid profile schedule");
    if (spec->start < 1 || spec->window < 1)
        return ZCL_ERR(-3, "Invalid profile schedule");
    for (size_t i = 0; i < spec->activation_count; ++i) {
        struct zcl_result height = spec_one_height(spec, i);
        if (!height.ok) return height;
    }
    return ZCL_OK;
}

static struct zcl_result spec_ok(const struct research_profile_spec *spec)
{
    struct zcl_result pointers = spec_pointers(spec);
    if (!pointers.ok) return pointers;
    struct zcl_result local = spec_local(spec);
    if (!local.ok) return local;
    if (spec->header_len == 0 || spec->header_len > spec->genesis_wire_len)
        return ZCL_ERR(-4, "Invalid genesis header span");
    if (!baseline_nonzero(spec->baseline))
        return ZCL_ERR(-5, "Baseline identity must be nonzero");
    return spec_schedule(spec);
}

static void profile_commit(const struct research_profile_spec *spec,
                           const uint8_t genesis_raw[32], uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)"Z23-PROFILE-V1", 14);
    sha3_256_write(&ctx, spec->baseline, 32);
    sha3_256_write(&ctx, genesis_raw, 32);
    profile_u32(&ctx, (uint32_t)spec->start);
    profile_u32(&ctx, (uint32_t)spec->window);
    profile_u32(&ctx, (uint32_t)spec->activation_count);
    for (size_t i = 0; i < spec->activation_count; ++i)
        profile_u32(&ctx, (uint32_t)spec->activations[i]);
    sha3_256_finalize(&ctx, out);
}

struct zcl_result research_profile_bind(const struct research_profile_spec *spec,
                                        struct research_profile_identity *out)
{
    struct zcl_result valid = spec_ok(spec);
    if (!valid.ok) return valid;
    if (!out) return ZCL_ERR(-9, "Missing profile identity output");
    struct research_profile_identity next = {0};
    profile_sha256d(spec->genesis_wire, spec->header_len, next.genesis_raw);
    uint8_t display[32];
    for (size_t i = 0; i < 32; ++i) display[i] = next.genesis_raw[31 - i];
    zcl_hex_encode(display, 32, next.genesis_display);
    uint8_t magic[32];
    sha3_256((const uint8_t *)spec->transport_domain, strlen(spec->transport_domain), magic);
    memcpy(next.message_start, magic, 4);
    next.rpc_port = spec->rpc_port;
    memcpy(next.datadir, spec->datadir, strlen(spec->datadir) + 1);
    profile_commit(spec, next.genesis_raw, next.commitment);
    int wrote = snprintf(next.state_dir, sizeof(next.state_dir),
                         "%s/%02x%02x%02x%02x%02x%02x%02x%02x", next.datadir,
                         next.commitment[0], next.commitment[1], next.commitment[2],
                         next.commitment[3], next.commitment[4], next.commitment[5],
                         next.commitment[6], next.commitment[7]);
    if (wrote < 0 || (size_t)wrote >= sizeof(next.state_dir))
        return ZCL_ERR(-10, "Profile state directory does not fit");
    *out = next;
    return ZCL_OK;
}

static int compact_target(uint32_t compact, uint8_t target[32])
{
    uint32_t exp = compact >> 24;
    uint32_t mant = compact & 0x007fffffu;
    memset(target, 0, 32);
    if ((compact & 0x00800000u) || mant == 0 || exp < 3 || exp > 32) return 0;
    int start = 32 - (int)exp;
    uint8_t be[3] = { (uint8_t)(mant >> 16), (uint8_t)(mant >> 8), (uint8_t)mant };
    for (int i = 0; i < 3; ++i) {
        int at = start + i;
        if (at >= 0 && at < 32) target[at] = be[i];
    }
    return 1;
}

static void child_hash(const struct research_profile_child *child, uint8_t out[32])
{
    uint8_t pre[72];
    memcpy(pre, child->prev, 32);
    memcpy(pre + 32, child->commitment, 32);
    memcpy(pre + 64, child->nonce, 8);
    profile_sha256d(pre, sizeof(pre), out);
}

struct zcl_result research_profile_accept_child(const struct research_profile_identity *parent,
                                                const struct research_profile_child *child,
                                                int *pow_ok)
{
    if (pow_ok) *pow_ok = 0;
    if (!parent || !child || !pow_ok)
        return ZCL_ERR(-11, "Missing profile child");
    uint8_t target[32], hash[32];
    if (!compact_target(child->compact_target, target))
        return ZCL_ERR(-12, "Invalid proof-of-work target");
    child_hash(child, hash);
    *pow_ok = memcmp(hash, target, 32) <= 0;
    if (!*pow_ok) return ZCL_ERR(-13, "Proof of work rejected");
    if (memcmp(child->prev, parent->genesis_raw, 32) != 0 ||
        memcmp(child->commitment, parent->commitment, 32) != 0)
        return ZCL_ERR(-14, "Cross-profile child refused");
    return ZCL_OK;
}

struct zcl_result research_profile_solve_child(const struct research_profile_identity *id,
                                               uint32_t compact_target,
                                               struct research_profile_child *out)
{
    if (!id || !out) return ZCL_ERR(-15, "Missing profile child output");
    struct research_profile_child child = {0};
    memcpy(child.prev, id->genesis_raw, 32);
    memcpy(child.commitment, id->commitment, 32);
    child.compact_target = compact_target;
    for (uint32_t n = 0; n < 1000000u; ++n) {
        int pow_ok = 0;
        zcl_write_u32_le(child.nonce, n);
        struct zcl_result accepted = research_profile_accept_child(id, &child, &pow_ok);
        if (accepted.ok) {
            *out = child;
            return ZCL_OK;
        }
        if (!pow_ok) continue;
        return accepted;
    }
    return ZCL_ERR(-16, "No proof of work within the search bound");
}
