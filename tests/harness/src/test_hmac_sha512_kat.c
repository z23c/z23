/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Known-answer and structural tests for core/modules/crypto/src/hmac_sha512.c
 * (hmac_sha512_init / hmac_sha512_write / hmac_sha512_finalize).
 *
 * HMAC-SHA512 is a pure, deterministic function: a fixed (key, message)
 * pair always produces one fixed 64-byte digest. Every assertion below
 * pins an exact byte-for-byte output, so any regression in the SHA-512
 * compression function, the ipad/opad key padding, the >128-byte key
 * pre-hash branch, or the stateful multi-write buffering changes a digest
 * and fails the test. The first three vectors are the canonical published
 * RFC 4231 test cases (HMAC-SHA-512), so they additionally pin the module
 * to the standard rather than merely to its own current behavior. */

#include "test/test_core.h"
#include "crypto/hmac_sha512.h"

/* Compute HMAC-SHA512(key, msg) into out[64] in one pass. */
static void hmac512_oneshot(const unsigned char *key, size_t keylen,
                            const unsigned char *msg, size_t msglen,
                            unsigned char out[HMAC_SHA512_OUTPUT_SIZE])
{
    struct hmac_sha512_ctx ctx;
    hmac_sha512_init(&ctx, key, keylen);
    hmac_sha512_write(&ctx, msg, msglen);
    hmac_sha512_finalize(&ctx, out);
}

/* Lowercase-hex-encode the 64-byte digest and compare against `expected`.
 * Returns true on exact match. Self-contained (does not borrow the shared
 * check_hex, which prints its own status line and would corrupt the
 * TEST_CASE "OK" output). */
static bool digest_is(const unsigned char digest[HMAC_SHA512_OUTPUT_SIZE],
                      const char *expected)
{
    char hex[2 * HMAC_SHA512_OUTPUT_SIZE + 1];
    for (int i = 0; i < HMAC_SHA512_OUTPUT_SIZE; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    return strcmp(hex, expected) == 0;
}

/* Behavior 1: RFC 4231 Test Case 2 — key="Jefe", msg="what do ya want
 * for nothing?". The canonical published HMAC-SHA-512 digest. Pins the
 * core algorithm (short-key ipad/opad path, single-block message) to the
 * standard. */
int test_hmac_sha512_kat_rfc4231_jefe(void)
{
    int failures = 0;

    TEST_CASE("hmac_sha512 RFC 4231 TC2 (key=Jefe)") {
        const unsigned char key[] = { 0x4a, 0x65, 0x66, 0x65 }; /* "Jefe" */
        const unsigned char msg[] = "what do ya want for nothing?";
        unsigned char out[HMAC_SHA512_OUTPUT_SIZE];

        hmac512_oneshot(key, sizeof(key), msg, sizeof(msg) - 1, out);

        ASSERT(digest_is(out,
            "164b7a7bfcf819e2e395fbe73b56e0a3"
            "87bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fd"
            "caeab1a34d4a6b4b636e070a38bce737"));
    } TEST_END

    return failures;
}

/* Behavior 2: key longer than the 128-byte block size. RFC 4231 Test
 * Case 6 — a 131-byte all-0xaa key with a single-block message. This
 * forces hmac_sha512_init's else-branch, which SHA-512-compresses the
 * oversized key down to 64 bytes (zero-padded to 128) before ipad/opad.
 * Pins the key-prehash path to the published vector. */
int test_hmac_sha512_kat_oversized_key(void)
{
    int failures = 0;

    TEST_CASE("hmac_sha512 RFC 4231 TC6 (131-byte key prehash)") {
        unsigned char key[131];
        memset(key, 0xaa, sizeof(key));
        const unsigned char msg[] =
            "Test Using Larger Than Block-Size Key - Hash Key First";
        unsigned char out[HMAC_SHA512_OUTPUT_SIZE];

        hmac512_oneshot(key, sizeof(key), msg, sizeof(msg) - 1, out);

        ASSERT(digest_is(out,
            "80b24263c7c1a3ebb71493c1dd7be8b4"
            "9b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e52"
            "95e64f73f63f0aec8b915a985d786598"));
    } TEST_END

    return failures;
}

/* Behavior 3: empty message determinism. HMAC-SHA512(key, "") must be
 * fully defined and stable — finalizing the inner SHA-512 over only the
 * ipad block (no application data) then the outer over that. Asserts the
 * fixed digest AND that calling hmac_sha512_write(.., 0) is equivalent to
 * not writing at all (the stateful path must not perturb the empty case). */
int test_hmac_sha512_empty_message(void)
{
    int failures = 0;

    TEST_CASE("hmac_sha512 empty message determinism") {
        const unsigned char key[] = { 0x6b, 0x65, 0x79 }; /* "key" */
        const unsigned char expected[] =
            "84fa5aa0279bbc473267d05a53ea0331"
            "0a987cecc4c1535ff29b6d76b8f1444a"
            "728df3aadb89d4a9a6709e1998f37356"
            "6e8f824a8ca93b1821f0b69bc2a2f65e";

        /* No write at all. */
        struct hmac_sha512_ctx ctx_a;
        unsigned char out_a[HMAC_SHA512_OUTPUT_SIZE];
        hmac_sha512_init(&ctx_a, key, sizeof(key));
        hmac_sha512_finalize(&ctx_a, out_a);
        ASSERT(digest_is(out_a, (const char *)expected));

        /* An explicit zero-length write must yield the identical digest. */
        struct hmac_sha512_ctx ctx_b;
        unsigned char out_b[HMAC_SHA512_OUTPUT_SIZE];
        hmac_sha512_init(&ctx_b, key, sizeof(key));
        hmac_sha512_write(&ctx_b, (const unsigned char *)"", 0);
        hmac_sha512_finalize(&ctx_b, out_b);
        ASSERT(memcmp(out_a, out_b, HMAC_SHA512_OUTPUT_SIZE) == 0);
    } TEST_END

    return failures;
}

/* Behavior 4 (PRIMARY, index 4): multi-block data across 2+ 128-byte
 * SHA-512 blocks, exercising stateful hmac_sha512_write correctness. A
 * 256-byte message (exactly two inner blocks plus the ipad prefix block)
 * fed two ways:
 *   (a) one 256-byte write, and
 *   (b) many small writes that straddle the internal 128-byte buffer
 *       boundary (60 + 68 + 1 + 127 = 256),
 * must produce the SAME fixed digest. This pins the running-buffer carry
 * logic in sha512_write (via hmac_sha512_write): a regression that mis-
 * counts a partial block or drops a chunk on a boundary changes the
 * digest or de-syncs the two paths. */
int test_hmac_sha512_multiblock_stateful_write(void)
{
    int failures = 0;

    TEST_CASE("hmac_sha512 multi-block stateful write") {
        const unsigned char key[] = { 0x6b }; /* "k" */
        unsigned char msg[256];
        memset(msg, 0x5a, sizeof(msg));
        const char *expected =
            "f25984fa211533c90028750118eb5b79"
            "3933f8e9cd7a3459b7bd1f0be59e1b0b"
            "e848cec88a5f8f358b2210c622300b48"
            "0f735e921ec8761e6b49de08f401e20d";

        /* (a) single contiguous write. */
        unsigned char out_single[HMAC_SHA512_OUTPUT_SIZE];
        hmac512_oneshot(key, sizeof(key), msg, sizeof(msg), out_single);
        ASSERT(digest_is(out_single, expected));

        /* (b) chunked writes crossing the 128-byte block boundary. */
        struct hmac_sha512_ctx ctx;
        unsigned char out_chunked[HMAC_SHA512_OUTPUT_SIZE];
        const size_t chunks[] = { 60, 68, 1, 127 }; /* sums to 256 */
        size_t off = 0;
        hmac_sha512_init(&ctx, key, sizeof(key));
        for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
            hmac_sha512_write(&ctx, msg + off, chunks[i]);
            off += chunks[i];
        }
        ASSERT(off == sizeof(msg));
        hmac_sha512_finalize(&ctx, out_chunked);

        /* Both paths must agree byte-for-byte. */
        ASSERT(memcmp(out_single, out_chunked, HMAC_SHA512_OUTPUT_SIZE) == 0);
    } TEST_END

    return failures;
}

/* Behavior 5: key length exactly 128 (the block-size boundary). This is
 * the largest key that still takes hmac_sha512_init's keylen<=128 branch
 * (memcpy then memset of 128-keylen == 0 trailing bytes). An off-by-one
 * at the boundary (e.g. routing 128 into the prehash branch, or writing
 * one byte past rkey) would change the padded key and thus the digest.
 * Pins the boundary to the exact module output, and asserts that the
 * 128-byte key does NOT collide with its 64-byte SHA-512 prehash (which
 * is what a >128 key of the same fill would reduce to). */
int test_hmac_sha512_key_len_128_boundary(void)
{
    int failures = 0;

    TEST_CASE("hmac_sha512 key_len==128 boundary") {
        unsigned char key128[128];
        memset(key128, 0x42, sizeof(key128));
        const unsigned char msg[] = { 0x61, 0x62, 0x63 }; /* "abc" */
        unsigned char out[HMAC_SHA512_OUTPUT_SIZE];

        hmac512_oneshot(key128, sizeof(key128), msg, sizeof(msg), out);

        ASSERT(digest_is(out,
            "f19859984a47cde96814ccd6353f8254"
            "6204fd314de0f995679fd8abcab6e861"
            "c20a84ce30e8b214c10302b7765d7b48"
            "1bf28fbbee62707ba9865dd53d51acbe"));

        /* A 129-byte key of the same fill takes the prehash branch and
         * must yield a DIFFERENT digest — confirming 128 used the direct
         * (non-prehash) padding path, not the >128 branch. */
        unsigned char key129[129];
        memset(key129, 0x42, sizeof(key129));
        unsigned char out129[HMAC_SHA512_OUTPUT_SIZE];
        hmac512_oneshot(key129, sizeof(key129), msg, sizeof(msg), out129);
        ASSERT(memcmp(out, out129, HMAC_SHA512_OUTPUT_SIZE) != 0);
    } TEST_END

    return failures;
}
