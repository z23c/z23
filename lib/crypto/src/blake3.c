/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * BLAKE3 — portable C23 implementation from the public specification
 * (https://blake3.io), pinned to the official test vectors in
 * lib/test/src/test_blake3_kat.c. Consensus and identity hashing do NOT use
 * this; see the positioning note in crypto/blake3.h.
 *
 * Structure: every chunk (1 KiB) hashes as a chain of 64-byte compressions
 * (CHUNK_START on the first, CHUNK_END on the last); chunk chaining values
 * combine pairwise into parents (PARENT flag); the root compression adds
 * ROOT and its counter-mode extension provides arbitrary output length. The
 * update loop folds a completed chunk into the CV stack only when the NEXT
 * byte arrives, so an input ending exactly on a chunk boundary finalizes
 * that chunk as the root's right-most node, never as an empty trailing
 * chunk. */

#include "crypto/blake3.h"
#include "base/serialize_le.h"

#include <string.h>

enum {
    CHUNK_START = 1u << 0,
    CHUNK_END = 1u << 1,
    PARENT = 1u << 2,
    ROOT = 1u << 3,
    KEYED_HASH = 1u << 4,
    DERIVE_KEY_CONTEXT = 1u << 5,
    DERIVE_KEY_MATERIAL = 1u << 6,
};

static const uint32_t blake3_iv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/* BLAKE3's own 7-row message schedule — NOT the BLAKE2s sigma (which cycles
 * 10 rows). Round r permutes the message words by row r; there are exactly
 * 7 rounds, so every row is used once. */
static const uint8_t blake3_msg_schedule[7][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    {  2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8 },
    {  3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1 },
    { 10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6 },
    { 12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4 },
    {  9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7 },
    { 11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13 },
};

static uint32_t rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static void g_mix(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
                  uint32_t mx, uint32_t my)
{
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void round_fn(uint32_t state[16], const uint32_t m[16], unsigned r)
{
    const uint8_t *s = blake3_msg_schedule[r];
    g_mix(state, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g_mix(state, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g_mix(state, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g_mix(state, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g_mix(state, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g_mix(state, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g_mix(state, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g_mix(state, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

/* The core compression: 7 rounds, then feed-forward. out16 receives all 16
 * output words; callers that only need the chaining value read the first 8. */
static void blake3_compress(const uint32_t cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint64_t counter, uint32_t block_len,
                            uint32_t flags, uint32_t out16[16])
{
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = zcl_read_u32_le(block + 4 * i);

    uint32_t state[16];
    for (int i = 0; i < 8; i++) {
        state[i] = cv[i];
        state[8 + i] = blake3_iv[i];
    }
    /* v[12..15] are not XORed with the IV (that is BLAKE2's shape): the
     * counter, block length, and flags REPLACE IV words 4..7. */
    state[12] = (uint32_t)(counter & 0xffffffffu);
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;

    for (unsigned r = 0; r < 7; r++)
        round_fn(state, m, r);

    /* Feed-forward: the second half XORs the ORIGINAL cv (v[12..15] have
     * been modified by the counter/block_len/flags words and are not part
     * of the output). */
    for (int i = 0; i < 8; i++) {
        out16[i] = state[i] ^ state[i + 8];
        out16[i + 8] = state[8 + i] ^ cv[i];
    }
}

/* ── chunk state ─────────────────────────────────────────────────────── */

static void chunk_state_init(struct blake3_chunk_state *self,
                             const uint32_t key[8], uint64_t counter,
                             uint32_t flags)
{
    memcpy(self->cv, key, sizeof(self->cv));
    self->chunk_counter = counter;
    self->buf_len = 0;
    self->blocks_compressed = 0;
    self->flags = flags;
    memset(self->buf, 0, sizeof(self->buf));
}

static size_t chunk_state_len(const struct blake3_chunk_state *self)
{
    return (size_t)self->blocks_compressed * BLAKE3_BLOCK_LEN +
           (size_t)self->buf_len;
}

static uint32_t chunk_state_start_flag(const struct blake3_chunk_state *self)
{
    return self->blocks_compressed == 0 ? CHUNK_START : 0;
}

static void chunk_state_update(struct blake3_chunk_state *self,
                               const uint8_t *input, size_t input_len)
{
    while (input_len > 0) {
        if (self->buf_len == BLAKE3_BLOCK_LEN) {
            uint32_t out16[16];
            blake3_compress(self->cv, self->buf, self->chunk_counter,
                            BLAKE3_BLOCK_LEN,
                            self->flags | chunk_state_start_flag(self), out16);
            memcpy(self->cv, out16, sizeof(self->cv));
            self->blocks_compressed++;
            self->buf_len = 0;
            memset(self->buf, 0, sizeof(self->buf));
        }
        size_t want = BLAKE3_BLOCK_LEN - self->buf_len;
        size_t take = want < input_len ? want : input_len;
        memcpy(self->buf + self->buf_len, input, take);
        self->buf_len = (uint8_t)(self->buf_len + take);
        input += take;
        input_len -= take;
    }
}

/* The chaining value of the chunk as it currently stands. */
static void chunk_state_cv(const struct blake3_chunk_state *self,
                           uint8_t out[BLAKE3_OUT_LEN])
{
    uint32_t out16[16];
    blake3_compress(self->cv, self->buf, self->chunk_counter, self->buf_len,
                    self->flags | chunk_state_start_flag(self) | CHUNK_END,
                    out16);
    for (int i = 0; i < 8; i++)
        zcl_write_u32_le(out + 4 * i, out16[i]);
}

/* ── hasher ──────────────────────────────────────────────────────────── */

static void hasher_reset(struct blake3_hasher *self, const uint32_t key[8],
                         uint32_t flags)
{
    memset(self, 0, sizeof(*self));
    memcpy(self->key, key, sizeof(self->key));
    self->flags = flags;
    chunk_state_init(&self->chunk, key, 0, flags);
}

static void parent_cv(const uint32_t key[8], const uint8_t left[BLAKE3_OUT_LEN],
                      const uint8_t right[BLAKE3_OUT_LEN], uint32_t flags,
                      uint8_t out[BLAKE3_OUT_LEN])
{
    uint8_t block[BLAKE3_BLOCK_LEN];
    uint32_t out16[16];
    memcpy(block, left, BLAKE3_OUT_LEN);
    memcpy(block + BLAKE3_OUT_LEN, right, BLAKE3_OUT_LEN);
    blake3_compress(key, block, 0, BLAKE3_BLOCK_LEN, flags | PARENT, out16);
    for (int i = 0; i < 8; i++)
        zcl_write_u32_le(out + 4 * i, out16[i]);
}

/* Fold one completed chunk CV into the stack. total_chunks is the number of
 * complete chunks so far INCLUDING the chunk this CV came from; its binary
 * trailing zeros say how many stack entries merge with it. */
static void hasher_push_cv(struct blake3_hasher *self,
                           uint8_t cv[BLAKE3_OUT_LEN], uint64_t total_chunks)
{
    while ((total_chunks & 1) == 0) {
        parent_cv(self->key, self->cv_stack[self->cv_stack_len - 1], cv,
                  self->flags, cv);
        self->cv_stack_len--;
        total_chunks >>= 1;
    }
    memcpy(self->cv_stack[self->cv_stack_len], cv, BLAKE3_OUT_LEN);
    self->cv_stack_len++;
}

void blake3_init(struct blake3_hasher *self)
{
    hasher_reset(self, blake3_iv, 0);
}

void blake3_init_keyed(struct blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN])
{
    uint32_t key_words[8];
    for (int i = 0; i < 8; i++)
        key_words[i] = zcl_read_u32_le(key + 4 * i);
    hasher_reset(self, key_words, KEYED_HASH);
}

void blake3_init_derive_key(struct blake3_hasher *self, const void *context,
                            size_t context_len)
{
    struct blake3_hasher scoped;
    uint8_t context_key[BLAKE3_OUT_LEN];
    uint32_t key_words[8];

    hasher_reset(&scoped, blake3_iv, DERIVE_KEY_CONTEXT);
    blake3_update(&scoped, context, context_len);
    blake3_final(&scoped, context_key, BLAKE3_OUT_LEN);
    for (int i = 0; i < 8; i++)
        key_words[i] = zcl_read_u32_le(context_key + 4 * i);
    hasher_reset(self, key_words, DERIVE_KEY_MATERIAL);
}

void blake3_update(struct blake3_hasher *self, const void *input,
                   size_t input_len)
{
    const uint8_t *p = (const uint8_t *)input;
    while (input_len > 0) {
        if (chunk_state_len(&self->chunk) == BLAKE3_CHUNK_LEN) {
            uint8_t cv[BLAKE3_OUT_LEN];
            uint64_t total_chunks = self->chunk.chunk_counter + 1;
            chunk_state_cv(&self->chunk, cv);
            hasher_push_cv(self, cv, total_chunks);
            chunk_state_init(&self->chunk, self->key,
                             self->chunk.chunk_counter + 1, self->flags);
        }
        size_t want = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
        size_t take = want < input_len ? want : input_len;
        chunk_state_update(&self->chunk, p, take);
        p += take;
        input_len -= take;
    }
}

void blake3_final(const struct blake3_hasher *self, void *out, size_t out_len)
{
    uint8_t *o = (uint8_t *)out;
    if (out_len == 0)
        return;

    uint32_t root_state[8];
    uint8_t root_block[BLAKE3_BLOCK_LEN];
    uint64_t root_counter;
    uint32_t root_block_len;
    uint32_t root_flags;

    if (self->cv_stack_len == 0) {
        /* Everything fits in one chunk: the root IS the chunk node. */
        memcpy(root_state, self->chunk.cv, sizeof(root_state));
        memcpy(root_block, self->chunk.buf, sizeof(root_block));
        root_counter = self->chunk.chunk_counter;
        root_block_len = self->chunk.buf_len;
        root_flags = self->chunk.flags | chunk_state_start_flag(&self->chunk) |
                     CHUNK_END;
    } else {
        /* Fold the CV stack down onto the current chunk's CV, keeping the
         * last parent's input block (left || right) — that block is the root
         * node's input, which the counter-mode extension below reuses for
         * every output block. */
        uint8_t cv[BLAKE3_OUT_LEN];
        chunk_state_cv(&self->chunk, cv);
        memcpy(root_block + BLAKE3_OUT_LEN, cv, BLAKE3_OUT_LEN);
        for (size_t i = self->cv_stack_len; i-- > 0;) {
            memcpy(root_block, self->cv_stack[i], BLAKE3_OUT_LEN);
            parent_cv(self->key, root_block, root_block + BLAKE3_OUT_LEN,
                      self->flags, cv);
            if (i > 0)
                memcpy(root_block + BLAKE3_OUT_LEN, cv, BLAKE3_OUT_LEN);
        }
        memcpy(root_state, self->key, sizeof(root_state));
        root_counter = 0;
        root_block_len = BLAKE3_BLOCK_LEN;
        root_flags = self->flags | PARENT;
    }

    /* Counter-mode extended output: every 64-byte output block re-compresses
     * the root node with an incremented counter field. Output block zero
     * uses the node's own counter, so its first 32 bytes are the standard
     * digest. */
    uint64_t out_block = root_counter;
    while (out_len > 0) {
        uint32_t out16[16];
        uint8_t bytes[BLAKE3_BLOCK_LEN];
        blake3_compress(root_state, root_block, out_block, root_block_len,
                        root_flags | ROOT, out16);
        for (int i = 0; i < 16; i++)
            zcl_write_u32_le(bytes + 4 * i, out16[i]);
        size_t take = out_len < BLAKE3_BLOCK_LEN ? out_len : BLAKE3_BLOCK_LEN;
        memcpy(o, bytes, take);
        o += take;
        out_len -= take;
        out_block++;
    }
}

void blake3_derive_key(const void *context, size_t context_len,
                       const void *material, size_t material_len,
                       void *out, size_t out_len)
{
    struct blake3_hasher hasher;
    blake3_init_derive_key(&hasher, context, context_len);
    blake3_update(&hasher, material, material_len);
    blake3_final(&hasher, out, out_len);
}
