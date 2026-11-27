/* purpose: Create a bounded experimental offline test profile. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "common.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "platform/rename_compat.h"
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool number(const char *s, uint32_t max, uint32_t *out)
{
    if (!s || !*s) return false;
    uint64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        n = n * 10 + (unsigned)(*s - '0');
        if (n > max) return false;
    }
    *out = (uint32_t)n;
    return n != 0;
}

static bool manifest_from_args(int argc, char **argv, uint8_t *buf, size_t *len,
                               struct experimental_profile *p)
{
    static const char domain[] = "Z23-PROFILE-EXPERIMENT-1";
    static const char baseline[] = "regtest-shielded-baseline-fixture-1";
    if (argc < 7 || (argc - 5) % 2 || (argc - 5) / 2 > 256) return false;
    uint32_t timestamp, start, window;
    if (!number(argv[2], UINT32_MAX, &timestamp) ||
        !number(argv[3], INT32_MAX, &start) || !number(argv[4], 256, &window)) return false;
    size_t off = sizeof(domain) - 1;
    memcpy(buf, domain, off);
    experimental_profile_digest(baseline, sizeof(baseline) - 1, buf + off); off += 32;
    uint32_t fields[8] = { timestamp, 0x200f0f0f, 48, 5, start, window, 95,
                           (uint32_t)((argc - 5) / 2) };
    for (size_t i = 0; i < 8; i++, off += 4) zcl_write_u32_le(buf + off, fields[i]);
    for (size_t i = 0; i < fields[7]; i++, off += 36) {
        uint32_t activation;
        if (!zcl_hex_decode(argv[5 + 2 * i], buf + off, 32) ||
            !number(argv[6 + 2 * i], INT32_MAX, &activation)) return false;
        zcl_write_u32_le(buf + off + 32, activation);
    }
    *len = off;
    if (!experimental_profile_parse(buf, off, p).ok) return false;
    /* Validate ordering and schedule before doing the expensive solve. */
    p->catalog.genesis[0] = 1;
    struct miner_signal_schedule schedule;
    return experimental_profile_select(p, 0, &schedule).ok;
}

static bool try_nonce(struct block *b, uint32_t nonce, const struct equihash_params *ep)
{
    zcl_write_u32_le(b->header.nNonce.data, nonce);
    b->header.nSolutionSize = 0;
    struct byte_stream wire;
    stream_init(&wire, 0);
    bool ok = block_header_serialize(&b->header, &wire) && wire.size == 141;
    struct blake2b_ctx state;
    if (ok) ok = equihash_initialise_state(ep, &state) == 0 &&
                 blake2b_update(&state, wire.data, 140) == 0 &&
                 equihash_basic_solve(ep, &state, b->header.nSolution, sizeof(b->header.nSolution));
    stream_free(&wire);
    if (!ok) return false;
    b->header.nSolutionSize = ep->solution_width;
    struct arith_uint256 target, value;
    bool negative = false, overflow = false;
    arith_uint256_set_compact(&target, b->header.nBits, &negative, &overflow);
    struct uint256 hash;
    block_header_get_hash(&b->header, &hash);
    uint256_to_arith(&value, &hash);
    return !negative && !overflow && !arith_uint256_is_zero(&target) &&
           arith_uint256_compare(&value, &target) <= 0;
}

static bool generate_genesis(const struct experimental_profile *p, struct byte_stream *wire)
{
    struct tx_in input = {0};
    tx_in_init(&input);
    input.script_sig.size = 33; input.script_sig.data[0] = 32;
    memcpy(input.script_sig.data + 1, p->digest, 32);
    struct tx_out output = {0};
    output.script_pub_key.data[0] = 0x6a; output.script_pub_key.size = 1;
    struct transaction tx = { .version = 1, .vin = &input, .num_vin = 1,
                              .vout = &output, .num_vout = 1 };
    if (!transaction_hash_serialized(&tx, &tx.hash)) return false;
    struct block b = {0};
    block_header_init(&b.header);
    b.header.hashMerkleRoot = tx.hash; b.header.nTime = p->timestamp; b.header.nBits = p->bits;
    b.vtx = &tx; b.num_vtx = 1;
    struct equihash_params ep;
    equihash_params_init(&ep, 48, 5);
    for (uint32_t nonce = 0; nonce < 10000; nonce++)
        if (try_nonce(&b, nonce, &ep)) return block_serialize(&b, wire);
    return false;
}

static bool write_new(const char *path, const uint8_t *bytes, size_t size)
{
    FILE *f = fopen(path, "wbx");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, size, f) == size;
    if (fclose(f)) ok = false;
    return ok;
}

/* Create private staging in the destination's parent so publication cannot
 * cross filesystems. Ignore trailing slashes when locating the parent. */
static bool make_staging_dir(const char *dir, char *temp, size_t capacity)
{
    const char suffix[] = ".z23-profile.XXXXXX";
    size_t parent = strlen(dir);
    while (parent && dir[parent - 1] == '/') parent--;
    while (parent && dir[parent - 1] != '/') parent--;
    if (parent >= capacity || capacity - parent < sizeof(suffix)) return false;
    memcpy(temp, dir, parent);
    memcpy(temp + parent, suffix, sizeof(suffix));
    return mkdtemp(temp) != NULL;
}

static bool save_pair(const char *dir, const uint8_t *manifest, size_t mlen,
                      const uint8_t *genesis, size_t glen)
{
    char temp[4096], result[4096], mpath[4096], gpath[4096];
    if (!make_staging_dir(dir, temp, sizeof(temp))) return false;
    int a = snprintf(result, sizeof(result), "%s/result", temp);
    int b = snprintf(mpath, sizeof(mpath), "%s/result/manifest.bin", temp);
    int c = snprintf(gpath, sizeof(gpath), "%s/result/genesis.bin", temp);
    bool paths_ok = a >= 0 && (size_t)a < sizeof(result) &&
                    b >= 0 && (size_t)b < sizeof(mpath) &&
                    c >= 0 && (size_t)c < sizeof(gpath);
    bool made = paths_ok && mkdir(result, 0700) == 0;
    bool ok = made && write_new(mpath, manifest, mlen) && write_new(gpath, genesis, glen) &&
              platform_renameat_noreplace(AT_FDCWD, temp, AT_FDCWD, dir) == 0;
    if (!ok) {
        if (made) { (void)unlink(mpath); (void)unlink(gpath); (void)rmdir(result); }
        (void)rmdir(temp);
    }
    return ok;
}

int main(int argc, char **argv)
{
    uint8_t manifest[PROFILE_MAX]; size_t mlen = 0;
    struct experimental_profile p = {0};
    if (!manifest_from_args(argc, argv, manifest, &mlen, &p)) {
        fputs("usage: profile-create OUTPUT_DIR TIMESTAMP START WINDOW REVISION_HEX ACTIVATION [REVISION_HEX ACTIVATION ...]; revisions must be strictly sorted\n", stderr);
        return 1;
    }
    /* Avoid a solve for an occupied path. Publication repeats the exclusion
     * atomically, so concurrent creators can never replace each other. */
    struct stat st;
    if (!*argv[1] || lstat(argv[1], &st) == 0 || errno != ENOENT) {
        fputs("output path unavailable\n", stderr);
        return 1;
    }
    struct byte_stream genesis;
    stream_init(&genesis, 0);
    struct uint256 hash;
    bool ok = generate_genesis(&p, &genesis) &&
              experimental_profile_genesis(genesis.data, genesis.size, &p, &hash).ok;
    struct miner_signal_schedule selected;
    if (ok) {
        memcpy(p.catalog.genesis, hash.data, 32);
        ok = experimental_profile_select(&p, 0, &selected).ok;
    }
    if (ok) ok = save_pair(argv[1], manifest, mlen, genesis.data, genesis.size);
    stream_free(&genesis);
    if (!ok) { fputs("profile generation or exclusive output failed\n", stderr); return 1; }
    char hash_hex[65]; uint256_get_hex(&hash, hash_hex);
    fputs("profile=", stdout); profile_print_hex(p.digest, 32);
    printf(" genesis=%s catalog=", hash_hex); profile_print_hex(selected.catalog, 32);
    printf(" files=%s/result/{manifest.bin,genesis.bin}\n", argv[1]);
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "Profile files published at %s/result. Identity output write failed.\n", argv[1]);
        return 1;
    }
    return 0;
}
