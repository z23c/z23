/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * params_fetch.c — verify-first acquisition of the Zcash zk PROVING
 * parameters. See sapling/params_fetch.h for the trust argument; this file is
 * the machinery.
 *
 * The shape of the thing: a peer can give us a manifest and it can give us
 * chunks, and neither is believed. The manifest is folded into a Merkle root
 * and compared to a root compiled into this binary. Each chunk is hashed and
 * compared to its manifest leaf BEFORE it is written, so the worst a hostile
 * peer can do is waste our time — it cannot get one byte it authored into the
 * `.part` file. The assembled file is hashed end to end against the pinned
 * SHA-256 before the rename that makes it visible. Three independent checks,
 * all rooted in the same compiled-in constants.
 *
 * No allocation in this file is sized by a number that came off the wire.
 * Every buffer is sized from `zcl_param_pins`, which is a compile-time
 * constant, and a wire length is only ever compared against it.
 */

#include "sapling/params_fetch.h"
#include "params_fetch_internal.h"

#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── The trust root ─────────────────────────────────────────────────
 *
 * `bytes` and `sha256_hex` are the published outputs of the Zcash parameter
 * ceremonies. They are corroborated three ways: upstream zcash's own
 * zcutil/fetch-params.sh (which carried these exact SHA-256 strings through
 * v4.7.0), librustzcash's zcash_proofs crate (which pins the same byte
 * lengths as SAPLING_SPEND_BYTES / SAPLING_OUTPUT_BYTES / SPROUT_BYTES), and
 * this repository's own tools/scripts/zcash_params.sh and docs/PARAMS.md.
 * They are NOT derived from whatever happens to be on the machine that built
 * this binary.
 *
 * `chunk_root_hex` is the Merkle root over ZCL_PARAM_CHUNK_BYTES-sized chunks
 * of that same file. Nobody publishes it, and it does not need to be
 * published: it is a deterministic function of a file the SHA-256 above
 * already pins, so it inherits that corroboration exactly. test_params_fetch
 * recomputes it from the real files whenever they exist on the machine, which
 * is what keeps the derivation honest.
 *
 * `chunk_count` is ceil(bytes / ZCL_PARAM_CHUNK_BYTES), written out rather
 * than computed so a mismatch between the two is a compile-time-visible
 * inconsistency the tests can catch.
 */
const struct zcl_param_pin zcl_param_pins[ZCL_PARAM_FILE_COUNT] = {
    {
        .name           = "sapling-spend.params",
        .bytes          = 47958396ull,
        .sha256_hex     = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13",
        .chunk_root_hex = "7c6ef7174748125af00e5fa166a29e9c7cf7036b83ba52ed6597cabd2abc625e",
        .chunk_count    = 46u,
    },
    {
        .name           = "sapling-output.params",
        .bytes          = 3592860ull,
        .sha256_hex     = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4",
        .chunk_root_hex = "e7d6d68b05539acb7f9661c12da0c8a9bbed3ec77568f6b968d4f06128bf768c",
        .chunk_count    = 4u,
    },
    {
        .name           = "sprout-groth16.params",
        .bytes          = 725523612ull,
        .sha256_hex     = "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50",
        .chunk_root_hex = "05bb382b0af3304cf4deb335b013512176223cf309406244fb12d8578d034c4a",
        .chunk_count    = 692u,
    },
    {
        .name           = "sprout-verifying.key",
        .bytes          = 1449ull,
        .sha256_hex     = "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82",
        .chunk_root_hex = "8b0e130dc08d2ba3ce348dfed7c683b9c8c0cf18bcc4629b67fc5642b9cfe52b",
        .chunk_count    = 1u,
    },
};

/* ── Small helpers ──────────────────────────────────────────────────── */

bool zcl_pf_hex_to_32(const char *hex, uint8_t out[ZCL_PARAM_HASH_BYTES])
{
    if (!hex || strlen(hex) != ZCL_PARAM_HASH_BYTES * 2)
        return false;
    for (size_t i = 0; i < ZCL_PARAM_HASH_BYTES; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[i * 2 + k];
            unsigned d;
            if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a') + 10u;
            else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A') + 10u;
            else return false;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

/* Constant-time-ish 32-byte compare. These are public digests, so this is
 * hygiene rather than a defence against a timing oracle, but a verifier that
 * short-circuits on the first differing byte is a bad habit to publish. */
bool zcl_pf_digest_equal(const uint8_t a[ZCL_PARAM_HASH_BYTES],
                         const uint8_t b[ZCL_PARAM_HASH_BYTES])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < ZCL_PARAM_HASH_BYTES; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

bool zcl_pf_pin_valid(int file_idx)
{
    return file_idx >= 0 && file_idx < ZCL_PARAM_FILE_COUNT;
}

/* The chunk count the pin implies. Everything that sizes a buffer uses this,
 * never a wire value. */
uint32_t zcl_pf_derived_chunk_count(const struct zcl_param_pin *p)
{
    uint64_t n = (p->bytes + ZCL_PARAM_CHUNK_BYTES - 1) / ZCL_PARAM_CHUNK_BYTES;
    if (n == 0 || n > ZCL_PARAM_MAX_CHUNKS)
        return 0;
    return (uint32_t)n;
}

int zcl_param_pin_index(const char *name)
{
    if (!name)
        return -1;
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++)
        if (strcmp(name, zcl_param_pins[i].name) == 0)
            return i;
    return -1;
}

size_t zcl_param_chunk_len(int file_idx, uint32_t idx)
{
    if (!zcl_pf_pin_valid(file_idx))
        return 0;
    const struct zcl_param_pin *p = &zcl_param_pins[file_idx];
    uint32_t n = zcl_pf_derived_chunk_count(p);
    if (idx >= n)
        return 0;
    uint64_t off = (uint64_t)idx * ZCL_PARAM_CHUNK_BYTES;
    uint64_t rem = p->bytes - off;
    return rem < ZCL_PARAM_CHUNK_BYTES ? (size_t)rem : (size_t)ZCL_PARAM_CHUNK_BYTES;
}

/* ── Merkle ─────────────────────────────────────────────────────────── */

void zcl_param_leaf_hash(const uint8_t *chunk, size_t len,
                         uint8_t out[ZCL_PARAM_HASH_BYTES])
{
    const unsigned char tag = 0x00;
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, &tag, 1);
    if (chunk && len)
        sha256_write(&c, (const unsigned char *)chunk, len);
    sha256_finalize(&c, out);
}

static void interior_hash(const uint8_t *l, const uint8_t *r,
                          uint8_t out[ZCL_PARAM_HASH_BYTES])
{
    const unsigned char tag = 0x01;
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, &tag, 1);
    sha256_write(&c, (const unsigned char *)l, ZCL_PARAM_HASH_BYTES);
    sha256_write(&c, (const unsigned char *)r, ZCL_PARAM_HASH_BYTES);
    sha256_finalize(&c, out);
}

bool zcl_param_merkle_root(const uint8_t *leaves, uint32_t count,
                           uint8_t out[ZCL_PARAM_HASH_BYTES])
{
    if (!leaves || !out || count == 0 || count > ZCL_PARAM_MAX_CHUNKS)
        return false;
    if (count == 1) {
        memcpy(out, leaves, ZCL_PARAM_HASH_BYTES);
        return true;
    }

    /* count is bounded by ZCL_PARAM_MAX_CHUNKS, a compile-time constant, so
     * this allocation can never be steered by a peer. */
    uint8_t *level = zcl_malloc((size_t)count * ZCL_PARAM_HASH_BYTES,
                                "param_merkle_level");
    if (!level)
        return false;
    memcpy(level, leaves, (size_t)count * ZCL_PARAM_HASH_BYTES);

    uint32_t n = count;
    while (n > 1) {
        uint32_t w = 0;
        uint32_t i = 0;
        for (; i + 1 < n; i += 2, w++)
            interior_hash(level + (size_t)i * ZCL_PARAM_HASH_BYTES,
                          level + (size_t)(i + 1) * ZCL_PARAM_HASH_BYTES,
                          level + (size_t)w * ZCL_PARAM_HASH_BYTES);
        if (i < n) {
            /* Odd node is PROMOTED, never duplicated: duplicating the last
             * leaf is what lets two different leaf sequences share a root. */
            memmove(level + (size_t)w * ZCL_PARAM_HASH_BYTES,
                    level + (size_t)i * ZCL_PARAM_HASH_BYTES,
                    ZCL_PARAM_HASH_BYTES);
            w++;
        }
        n = w;
    }
    memcpy(out, level, ZCL_PARAM_HASH_BYTES);
    free(level);
    return true;
}

bool zcl_param_manifest_verify(int file_idx, const uint8_t *leaves,
                               uint32_t count)
{
    if (!zcl_pf_pin_valid(file_idx) || !leaves)
        return false;
    const struct zcl_param_pin *p = &zcl_param_pins[file_idx];

    /* The claimed count is checked against the pin BEFORE `leaves` is read at
     * all. A peer that says "this file has 4 billion chunks" gets refused
     * here, having caused no allocation and no read. */
    uint32_t want = zcl_pf_derived_chunk_count(p);
    if (want == 0 || count != want)
        return false;
    if (count != p->chunk_count)
        return false;

    uint8_t root[ZCL_PARAM_HASH_BYTES];
    if (!zcl_param_merkle_root(leaves, count, root))
        return false;

    uint8_t pinned[ZCL_PARAM_HASH_BYTES];
    if (!zcl_pf_hex_to_32(p->chunk_root_hex, pinned))
        LOG_FAIL("crypto.params",
                        "pinned chunk root for '%s' is malformed — this build "
                        "cannot fetch proving parameters", p->name);
    return zcl_pf_digest_equal(root, pinned);
}

/* ── Streaming recomputation from a real file ───────────────────────── */

bool zcl_param_pin_recompute_from_file(const char *path, uint64_t *out_bytes,
                                       uint8_t out_sha256[ZCL_PARAM_HASH_BYTES],
                                       uint8_t out_root[ZCL_PARAM_HASH_BYTES])
{
    if (!path)
        return false;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    bool ok = false;
    uint8_t *buf = zcl_malloc(ZCL_PARAM_CHUNK_BYTES, "param_recompute_chunk");
    uint8_t *leaves = zcl_malloc((size_t)ZCL_PARAM_MAX_CHUNKS * ZCL_PARAM_HASH_BYTES,
                                 "param_recompute_leaves");
    if (!buf || !leaves)
        goto done;

    struct sha256_ctx whole;
    sha256_init(&whole);
    uint64_t total = 0;
    uint32_t nleaves = 0;

    for (;;) {
        size_t filled = 0;
        while (filled < ZCL_PARAM_CHUNK_BYTES) {
            ssize_t r = read(fd, buf + filled, ZCL_PARAM_CHUNK_BYTES - filled);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                goto done;
            }
            if (r == 0)
                break;
            filled += (size_t)r;
        }
        if (filled == 0)
            break;
        total += filled;
        if (total > ZCL_PARAM_MAX_FILE_BYTES)
            goto done;
        if (nleaves >= ZCL_PARAM_MAX_CHUNKS)
            goto done;
        sha256_write(&whole, (const unsigned char *)buf, filled);
        zcl_param_leaf_hash(buf, filled,
                            leaves + (size_t)nleaves * ZCL_PARAM_HASH_BYTES);
        nleaves++;
        if (filled < ZCL_PARAM_CHUNK_BYTES)
            break;
    }
    if (nleaves == 0)
        goto done;

    if (out_bytes)
        *out_bytes = total;
    if (out_sha256)
        sha256_finalize(&whole, out_sha256);
    else {
        uint8_t scratch[ZCL_PARAM_HASH_BYTES];
        sha256_finalize(&whole, scratch);
    }
    if (out_root && !zcl_param_merkle_root(leaves, nleaves, out_root))
        goto done;
    ok = true;

done:
    free(buf);
    free(leaves);
    close(fd);
    return ok;
}

/* ── Installed-file verification ────────────────────────────────────── */

void zcl_pf_join_path(char *dst, size_t cap, const char *dir, const char *name,
                      const char *suffix)
{
    snprintf(dst, cap, "%s/%s%s", dir ? dir : ".", name, suffix ? suffix : "");
}

bool zcl_param_verify_installed(const char *dir, int file_idx)
{
    if (!zcl_pf_pin_valid(file_idx))
        return false;
    const struct zcl_param_pin *p = &zcl_param_pins[file_idx];

    char path[1200];
    zcl_pf_join_path(path, sizeof(path), dir, p->name, NULL);

    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    if ((uint64_t)st.st_size != p->bytes)
        return false;

    uint64_t bytes = 0;
    uint8_t got[ZCL_PARAM_HASH_BYTES], want[ZCL_PARAM_HASH_BYTES];
    if (!zcl_param_pin_recompute_from_file(path, &bytes, got, NULL))
        return false;
    if (bytes != p->bytes)
        return false;
    if (!zcl_pf_hex_to_32(p->sha256_hex, want))
        return false;
    return zcl_pf_digest_equal(got, want);
}

bool zcl_params_all_installed_verified(const char *dir)
{
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++)
        if (!zcl_param_verify_installed(dir, i))
            return false;
    return true;
}

