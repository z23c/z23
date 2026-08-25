/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Based on the BLAKE3 hash function designed by Jack O'Connor,
 * Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn
 * (https://blake3.io), implemented from the public specification.
 *
 * BLAKE3 is a MERKLE TREE by construction: the streaming state below is
 * that tree (one chunk state plus a chaining-value stack), which is why
 * this primitive exists — a transport layer can verify content in chunk
 * order, parallelize across chunks, and prune a peer whose subtree fails,
 * without any tree logic of its own.
 *
 * POSITIONING (docs/work/WIRE_COMPILE_CACHE.md): this is a TRANSFER-layer
 * hash for the package wire lane. It is NOT consensus (SHA-256d and
 * Equihash BLAKE2b stay consensus-only, byte-sealed under core/) and it is
 * NOT stored identity (content.v2 roots and receipts stay SHA3-256). A
 * BLAKE3 commitment is transport-local and disposable. */

#ifndef ZCL_CRYPTO_BLAKE3_H
#define ZCL_CRYPTO_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE3_OUT_LEN 32
#define BLAKE3_KEY_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024

/* blake3_hasher is ~2 KiB of caller-owned state; stack allocation is fine.
 * It is not safe to copy while mid-stream except as blake3_final does
 * internally (the chaining-value stack length is part of the tree shape). */
struct blake3_hasher {
    struct blake3_chunk_state {
        uint32_t cv[8];
        uint64_t chunk_counter;
        uint8_t buf[BLAKE3_BLOCK_LEN];
        uint8_t buf_len;
        uint8_t blocks_compressed;
        uint32_t flags;
    } chunk;
    uint32_t key[8];
    uint8_t cv_stack[54][BLAKE3_OUT_LEN];
    uint8_t cv_stack_len;
    uint32_t flags;
};

/* Standard hashing. */
void blake3_init(struct blake3_hasher *self);

/* Keyed hashing: the 32-byte key becomes the initial chaining value, so a
 * peer that does not know the key cannot produce a commitment it could not
 * have computed from content it holds. */
void blake3_init_keyed(struct blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN]);

/* Key derivation: the context string is hashed under the derive-key-context
 * domain to produce an internal key; the input that follows is hashed under
 * the derive-key-material domain. */
void blake3_init_derive_key(struct blake3_hasher *self, const void *context,
                            size_t context_len);

void blake3_update(struct blake3_hasher *self, const void *input,
                   size_t input_len);

/* Extended output: writes out_len bytes (out_len == 32 is the standard
 * digest; any length is valid — BLAKE3 is an XOF whose later bytes are
 * counter-mode extensions of the root node). Reads the hasher; the hasher
 * stays usable for further final calls but must not be updated after a
 * final without a re-init. out_len of zero writes nothing. */
void blake3_final(const struct blake3_hasher *self, void *out, size_t out_len);

/* One-shot derive-key convenience (init_derive_key + update + final). */
void blake3_derive_key(const void *context, size_t context_len,
                       const void *material, size_t material_len,
                       void *out, size_t out_len);

#endif /* ZCL_CRYPTO_BLAKE3_H */
