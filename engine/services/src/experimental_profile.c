/* purpose: Inspect experimental offline regtest-shielded profile fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "base/serialize_le.h"
#include "base/hex.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "services/miner_signal_catalog.h"
#include "sha3/sha3.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "services/experimental_profile.h"

void experimental_profile_digest(const void *data, size_t size, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, size);
    sha3_256_finalize(&ctx, out);
}

static bool read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    if (!path || !buf || !cap || !len) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    *len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && feof(f);
    if (fclose(f)) ok = false;
    return ok;
}

static bool profile_fields_valid(const uint32_t f[8], size_t len, size_t offset)
{
    return f[0] && f[1] == 0x200f0f0f && f[2] == 48 && f[3] == 5 &&
        f[4] && f[4] <= INT32_MAX && f[5] && f[5] <= 256 && f[6] == 95 &&
        f[7] && f[7] <= 256 && len == offset + (size_t)f[7] * 36;
}

static bool parse_profile(const uint8_t *buf, size_t len, struct experimental_profile *out)
{
    if (!buf || !out) return false;
    static const char domain[] = "Z23-PROFILE-EXPERIMENT-1";
    static const char baseline[] = "regtest-shielded-baseline-fixture-1";
    static const char magic_domain[] = "Z23-PROFILE-MAGIC-EXPERIMENT-1";
    size_t off = sizeof(domain) - 1;
    uint8_t expected[32];
    experimental_profile_digest(baseline, sizeof(baseline) - 1, expected);
    if (len < off + 64 || memcmp(buf, domain, off) || memcmp(buf + off, expected, 32))
        return false;
    off += 32;
    uint32_t f[8];
    for (size_t i = 0; i < 8; i++, off += 4) f[i] = zcl_read_u32_le(buf + off);
    if (!profile_fields_valid(f, len, off)) return false;
    out->timestamp = f[0]; out->bits = f[1];
    out->catalog.start = (int32_t)f[4]; out->catalog.window = (int32_t)f[5];
    out->catalog.count = f[7];
    for (size_t i = 0; i < out->catalog.count; i++, off += 36) {
        uint32_t activation = zcl_read_u32_le(buf + off + 32);
        if (activation > INT32_MAX) return false;
        memcpy(out->catalog.entries[i].rule_revision, buf + off, 32);
        out->catalog.entries[i].activation = (int32_t)activation;
    }
    experimental_profile_digest(buf, len, out->digest);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)magic_domain, sizeof(magic_domain) - 1);
    sha3_256_write(&ctx, out->digest, 32);
    sha3_256_finalize(&ctx, out->magic);
    memcpy(out->catalog.network_id, out->digest, 32);
    return true;
}

static bool genesis_input(const struct transaction *tx, const uint8_t profile[32])
{
    return tx->vin && transaction_is_coinbase(tx) && tx->vin[0].sequence == UINT32_MAX &&
        tx->vin[0].script_sig.size == 33 && tx->vin[0].script_sig.data[0] == 32 &&
        !memcmp(tx->vin[0].script_sig.data + 1, profile, 32);
}

static bool genesis_transaction(const struct block *b, const uint8_t profile[32])
{
    if (b->num_vtx != 1 || !b->vtx) return false;
    const struct transaction *tx = &b->vtx[0];
    if (tx->overwintered || tx->version != 1 || !genesis_input(tx, profile) ||
        !tx->vout || tx->num_vout != 1 || tx->lock_time ||
        tx->vout[0].value != 0 || tx->vout[0].script_pub_key.size != 1 ||
        tx->vout[0].script_pub_key.data[0] != 0x6a) return false;
    struct uint256 txid;
    return transaction_hash_serialized(tx, &txid) && uint256_eq(&txid, &b->header.hashMerkleRoot);
}

static bool genesis_pow(const struct block_header *h, struct uint256 *hash)
{
    struct equihash_params params;
    equihash_params_init(&params, 48, 5);
    struct block_header prefix = *h;
    prefix.nSolutionSize = 0;
    struct byte_stream wire;
    stream_init(&wire, 0);
    bool ok = block_header_serialize(&prefix, &wire) && wire.size == 141 &&
              h->nSolutionSize == params.solution_width;
    struct blake2b_ctx state;
    if (ok) ok = equihash_initialise_state(&params, &state) == 0 &&
                 blake2b_update(&state, wire.data, 140) == 0 &&
                 equihash_is_valid_solution(&params, &state, h->nSolution, h->nSolutionSize);
    stream_free(&wire);
    if (!ok) return false;
    struct arith_uint256 target, value;
    bool negative = false, overflow = false;
    arith_uint256_set_compact(&target, h->nBits, &negative, &overflow);
    block_header_get_hash(h, hash);
    uint256_to_arith(&value, hash);
    return !negative && !overflow && !arith_uint256_is_zero(&target) &&
           arith_uint256_compare(&value, &target) <= 0;
}

static bool genesis_wire_shape(const uint8_t *bytes, size_t len)
{
    return len == EXPERIMENTAL_GENESIS_SIZE && bytes[140] == 36 && bytes[177] == 1 &&
        bytes[178] == 1 && !bytes[179] && !bytes[180] && !bytes[181] &&
        bytes[182] == 1 && bytes[219] == 33 && bytes[257] == 1;
}

static bool genesis_header_fields(const struct block_header *h, const struct experimental_profile *p)
{
    return h->nVersion == 4 && uint256_is_null(&h->hashPrevBlock) &&
        uint256_is_null(&h->hashFinalSaplingRoot) && h->nTime == p->timestamp &&
        h->nBits == p->bits;
}

static bool inspect_genesis(const uint8_t *bytes, size_t len, const struct experimental_profile *p,
                            struct uint256 *hash)
{
    /* Exact fixture length and one transaction prevent unbounded decoder allocations. */
    if (!bytes || !p || !hash || !genesis_wire_shape(bytes, len)) return false;
    struct byte_stream in, canonical;
    stream_init_from_data(&in, bytes, len);
    struct block b;
    block_init(&b);
    bool ok = block_deserialize(&b, &in) && stream_remaining(&in) == 0;
    stream_init(&canonical, 0);
    if (ok) ok = block_serialize(&b, &canonical) && canonical.size == len &&
                 !memcmp(canonical.data, bytes, len);
    if (ok) ok = genesis_header_fields(&b.header, p) && genesis_transaction(&b, p->digest) &&
                 genesis_pow(&b.header, hash);
    stream_free(&canonical);
    block_free(&b);
    return ok;
}


struct zcl_result experimental_profile_read_file(const char *path, uint8_t *buf,
                                                 size_t cap, size_t *len)
{
    return read_file(path, buf, cap, len) ? ZCL_OK : ZCL_ERR(-1, "Cannot read profile file");
}

struct zcl_result experimental_profile_parse(const uint8_t *buf, size_t len,
                                             struct experimental_profile *out)
{
    struct experimental_profile next = {0};
    if (!out || !parse_profile(buf, len, &next))
        return ZCL_ERR(-2, "Invalid profile manifest");
    *out = next;
    return ZCL_OK;
}

struct zcl_result experimental_profile_genesis(const uint8_t *bytes, size_t len,
    const struct experimental_profile *p, struct uint256 *hash)
{
    return inspect_genesis(bytes, len, p, hash) ? ZCL_OK : ZCL_ERR(-3, "Invalid profile genesis");
}

struct zcl_result experimental_profile_select(const struct experimental_profile *p, size_t slot,
                                              struct miner_signal_schedule *out)
{
    if (!p || !out) return ZCL_ERR(-1, "Missing profile or schedule");
    struct miner_signal_catalog c = {
        .start = p->catalog.start, .window = p->catalog.window,
        .count = p->catalog.count, .entries = p->catalog.entries
    };
    memcpy(c.network_id, p->catalog.network_id, 32);
    memcpy(c.genesis, p->catalog.genesis, 32);
    return miner_signal_catalog_select(&c, slot, out);
}

enum experimental_profile_status experimental_profile_inspect(
    const uint8_t *manifest, size_t mlen, const uint8_t *genesis, size_t glen,
    struct experimental_profile *out)
{
    if (!manifest || !genesis || !out) return EXPERIMENTAL_PROFILE_INVALID;
    struct experimental_profile next = {0};
    if (!parse_profile(manifest, mlen, &next) ||
        !experimental_profile_genesis(genesis, glen, &next, &next.genesis_hash).ok)
        return EXPERIMENTAL_PROFILE_INVALID;
    memcpy(next.catalog.genesis, next.genesis_hash.data, 32);
    struct miner_signal_schedule schedule;
    if (!experimental_profile_select(&next, 0, &schedule).ok)
        return EXPERIMENTAL_PROFILE_CATALOG_INVALID;
    memcpy(next.catalog.digest, schedule.catalog, 32);
    memcpy(next.genesis_wire, genesis, glen);
    next.genesis_size = glen;
    *out = next;
    return EXPERIMENTAL_PROFILE_OK;
}

enum experimental_profile_status experimental_profile_load(
    const uint8_t *manifest, size_t mlen, const uint8_t *genesis, size_t glen,
    const uint8_t expected[32], struct experimental_profile *out)
{
    if (!expected || !out) return EXPERIMENTAL_PROFILE_INVALID;
    struct experimental_profile next;
    enum experimental_profile_status status =
        experimental_profile_inspect(manifest, mlen, genesis, glen, &next);
    if (status != EXPERIMENTAL_PROFILE_OK) return status;
    if (memcmp(expected, next.catalog.digest, 32)) return EXPERIMENTAL_PROFILE_PIN_MISMATCH;
    *out = next;
    return EXPERIMENTAL_PROFILE_OK;
}
