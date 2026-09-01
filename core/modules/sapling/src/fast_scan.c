/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast Sapling commitment scanner. Skips scriptSig/scriptPubKey parsing
 * entirely — just reads varint lengths and jumps over them. This makes
 * scanning a block with 8000 inputs take microseconds instead of 100ms. */

#include "sapling/fast_scan.h"
#include "util/log_macros.h"
#include <inttypes.h>
#include <string.h>

/* The ~40 inner `return -1;` sites inside scan_tx() below are "malformed
 * transaction — stop parsing" signals. They fire once per bad tx the
 * wallet sees, and logging each would flood stderr during IBD on any
 * block that happens to have junk. All of them propagate up to
 * fast_scan_sapling_commitments() where we log once — see the LOG_ERR
 * calls in that function for the diagnostic entrypoints. */

/* Read Bitcoin compact size varint. Returns 0 on error. */
static int read_compact(const uint8_t *d, size_t len, size_t *pos, uint64_t *val)
{
    if (*pos >= len) return 0;
    uint8_t b = d[(*pos)++];
    if (b < 253) { *val = b; return 1; }
    if (b == 253) {
        if (*pos + 2 > len) return 0;
        *val = (uint64_t)d[*pos] | ((uint64_t)d[*pos+1] << 8);
        *pos += 2; return 1;
    }
    if (b == 254) {
        if (*pos + 4 > len) return 0;
        *val = (uint64_t)d[*pos] | ((uint64_t)d[*pos+1] << 8) |
               ((uint64_t)d[*pos+2] << 16) | ((uint64_t)d[*pos+3] << 24);
        *pos += 4; return 1;
    }
    if (*pos + 8 > len) return 0;
    memcpy(val, d + *pos, 8); *pos += 8; return 1;
}

static int skip(size_t *pos, size_t len, size_t n)
{
    if (*pos + n > len) return 0;
    *pos += n; return 1;
}

/* Scan one transaction for Sapling output commitments.
 * Returns number of cms extracted, -1 on error. */
static int scan_tx(const uint8_t *d, size_t len, size_t *pos,
                   uint8_t (*cms)[32], int max_cms, int *total)
{
    int found = 0;

    /* Header: version(4) — check overwintered bit and version */
    if (*pos + 4 > len) return -1;
    uint32_t header;
    memcpy(&header, d + *pos, 4); *pos += 4;
    int overwintered = (header >> 31) & 1;
    int version = (int)(header & 0x7FFFFFFF);

    uint32_t vgid = 0;
    if (overwintered) {
        if (*pos + 4 > len) return -1;
        memcpy(&vgid, d + *pos, 4); *pos += 4;
    }

    int is_sapling = (overwintered && version == 4 && vgid == 0x892F2085U);

    /* vin */
    uint64_t num_vin;
    if (!read_compact(d, len, pos, &num_vin)) return -1;
    for (uint64_t i = 0; i < num_vin; i++) {
        if (!skip(pos, len, 36)) return -1; /* prevout: hash(32) + n(4) */
        uint64_t script_len;
        if (!read_compact(d, len, pos, &script_len)) return -1;
        if (!skip(pos, len, (size_t)script_len)) return -1; /* scriptSig */
        if (!skip(pos, len, 4)) return -1; /* sequence */
    }

    /* vout */
    uint64_t num_vout;
    if (!read_compact(d, len, pos, &num_vout)) return -1;
    for (uint64_t i = 0; i < num_vout; i++) {
        if (!skip(pos, len, 8)) return -1; /* value */
        uint64_t script_len;
        if (!read_compact(d, len, pos, &script_len)) return -1;
        if (!skip(pos, len, (size_t)script_len)) return -1; /* scriptPubKey */
    }

    /* lock_time */
    if (!skip(pos, len, 4)) return -1;

    if (!is_sapling) {
        /* Pre-Sapling or Overwinter: skip JoinSplits if present */
        if (overwintered) {
            if (!skip(pos, len, 4)) return -1; /* expiry_height */
        }
        if (version >= 2) {
            uint64_t num_js;
            if (!read_compact(d, len, pos, &num_js)) return -1;
            for (uint64_t i = 0; i < num_js; i++) {
                if (!skip(pos, len, 8 + 8 + 32)) return -1; /* vpub_old + vpub_new + anchor */
                if (!skip(pos, len, 32 * 2)) return -1; /* nullifiers */
                if (!skip(pos, len, 32 * 2)) return -1; /* commitments */
                if (!skip(pos, len, 32)) return -1; /* ephemeral_key */
                if (!skip(pos, len, 32)) return -1; /* random_seed */
                if (!skip(pos, len, 32 * 2)) return -1; /* macs */
                /* proof size: groth=192, phgr=296 */
                int proof_size = (overwintered && version >= 4) ? 192 : 296;
                if (!skip(pos, len, (size_t)proof_size)) return -1;
                if (!skip(pos, len, 601 * 2)) return -1; /* ciphertexts */
            }
            if (num_js > 0) {
                if (!skip(pos, len, 32 + 64)) return -1; /* joinsplit_pubkey + sig */
            }
        }
        return 0;
    }

    /* Sapling v4 transaction */
    if (!skip(pos, len, 4)) return -1; /* expiry_height */
    if (!skip(pos, len, 8)) return -1; /* value_balance */

    /* Shielded spends */
    uint64_t num_spend;
    if (!read_compact(d, len, pos, &num_spend)) return -1;
    /* Each spend: cv(32) + anchor(32) + nullifier(32) + rk(32) + proof(192) + sig(64) */
    if (!skip(pos, len, (size_t)num_spend * (32+32+32+32+192+64))) return -1;

    /* Shielded outputs — THIS IS WHAT WE WANT */
    uint64_t num_output;
    if (!read_compact(d, len, pos, &num_output)) return -1;
    /* Each output: cv(32) + CM(32) + ephemeral_key(32) + enc_ciphertext(580) + out_ciphertext(80) + proof(192) */
    for (uint64_t i = 0; i < num_output; i++) {
        if (*pos + 32 + 32 > len) return -1;
        /* Skip cv(32), read cm(32) */
        *pos += 32; /* cv */
        if (*total < max_cms) {
            memcpy(cms[*total], d + *pos, 32);
            (*total)++;
            found++;
        }
        *pos += 32; /* cm */
        /* Skip rest: ephemeral_key(32) + enc(580) + out(80) + proof(192) */
        if (!skip(pos, len, 32 + 580 + 80 + 192)) return -1;
    }

    /* JoinSplits (still possible in v4) */
    uint64_t num_js;
    if (!read_compact(d, len, pos, &num_js)) return -1;
    for (uint64_t i = 0; i < num_js; i++) {
        if (!skip(pos, len, 8+8+32+32*2+32*2+32+32+32*2+192+601*2)) return -1;
    }
    if (num_js > 0)
        if (!skip(pos, len, 32 + 64)) return -1;

    /* Binding sig (if shielded spends or outputs) */
    if (num_spend > 0 || num_output > 0)
        if (!skip(pos, len, 64)) return -1;

    return found;
}

int fast_scan_sapling_commitments(const uint8_t *block_data, size_t block_len,
                                   uint8_t (*cms)[32], int max_cms)
{
    size_t pos = 0;

    /* Block header: version(4) + prev(32) + merkle(32) + sapling(32) +
     * time(4) + bits(4) + nonce(32) + solution(varint+data) */
    if (!skip(&pos, block_len, 4 + 32 + 32 + 32 + 4 + 4 + 32))
        LOG_ERR("fast_scan",
                "block header parse: truncated at fixed header (block_len=%zu)",
                block_len);
    uint64_t sol_size;
    if (!read_compact(block_data, block_len, &pos, &sol_size))
        LOG_ERR("fast_scan",
                "block header parse: bad solution-size compact at pos=%zu",
                pos);
    if (!skip(&pos, block_len, (size_t)sol_size))
        LOG_ERR("fast_scan",
                "block header parse: short solution body (sol_size=%" PRIu64 " pos=%zu len=%zu)",
                sol_size, pos, block_len);

    /* Number of transactions */
    uint64_t num_tx;
    if (!read_compact(block_data, block_len, &pos, &num_tx))
        LOG_ERR("fast_scan",
                "block parse: bad num_tx compact at pos=%zu", pos);

    int total = 0;
    for (uint64_t i = 0; i < num_tx; i++) {
        int r = scan_tx(block_data, block_len, &pos, cms, max_cms, &total);
        if (r < 0) {
            /* Bad tx inside block. Return partial success if we've found any
             * cms already, otherwise log so the caller's "no cms" isn't mute. */
            if (total > 0)
                return total;
            LOG_ERR("fast_scan",
                    "scan_tx returned -1 for tx index %" PRIu64 "/%" PRIu64 " at pos=%zu (block_len=%zu)",
                    i, num_tx, pos, block_len);
        }
    }
    return total;
}
