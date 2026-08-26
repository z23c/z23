/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_params_fetch.c — the adversary's half of the proving-parameter
 * transfer.
 *
 * The feature's whole claim is that a hostile peer cannot get one byte it
 * authored onto disk. These tests are written to try to make that false:
 * they flip a bit, truncate a stream, inflate a length field, lie about the
 * manifest, interrupt the transfer and resume it, and check that the file
 * that lands is byte-exact or does not land at all.
 *
 * The fast tests use small synthetic files with the real chunking, because
 * putting 777 MB in the suite would be an act of vandalism. The real-file
 * path is proved separately (it runs here only when ~/.zcash-params is
 * present) and its cost is reported in the lane notes.
 */

#include "sapling/params_fetch.h"
#include "crypto/sha256.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("  FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);      \
            failures++;                                                     \
        }                                                                   \
    } while (0)

/* ── A synthetic "pinned file" ──────────────────────────────────────
 *
 * The production pin table is a compile-time constant, so these tests cannot
 * add an entry to it. Instead they exercise the same primitives the session
 * uses — leaf hash, Merkle fold, per-chunk length derivation — over a
 * synthetic file, and separately drive a real session against the smallest
 * pinned file (sprout-verifying.key, 1449 bytes, one chunk) where a real
 * session is required.
 */

static char g_dir[512];

static bool make_scratch_dir(void)
{
    char tmpl[] = "/tmp/zcl_paramfetch_XXXXXX";
    char *d = mkdtemp(tmpl);
    if (!d)
        return false;
    snprintf(g_dir, sizeof(g_dir), "%s", d);
    return true;
}

static void rm_in_dir(const char *name)
{
    char p[900];
    snprintf(p, sizeof(p), "%s/%s", g_dir, name);
    unlink(p);
}

static void cleanup_scratch(void)
{
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++) {
        char n[600];
        snprintf(n, sizeof(n), "%s", zcl_param_pins[i].name);
        rm_in_dir(n);
        char part[700], state[700];
        snprintf(part, sizeof(part), "%s.part", n);
        snprintf(state, sizeof(state), "%s.zpart", n);
        rm_in_dir(part);
        rm_in_dir(state);
        snprintf(state, sizeof(state), "%s.zpart.new", n);
        rm_in_dir(state);
    }
    rmdir(g_dir);
}

/* Deterministic pseudo-random filler so a "correct" body is reproducible
 * across runs without shipping a blob. */
static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed)
{
    uint32_t x = seed ? seed : 1u;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)(x >> 24);
    }
}

/* Read the real pinned file `idx` if the machine has it, else NULL. */
static uint8_t *load_real_param(int idx, size_t *out_len)
{
    const char *home = getenv("HOME");
    if (!home)
        return NULL;
    char path[900];
    snprintf(path, sizeof(path), "%s/.zcash-params/%s", home,
             zcl_param_pins[idx].name);
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    size_t len = (size_t)zcl_param_pins[idx].bytes;
    uint8_t *buf = zcl_malloc(len, "test_real_param");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got != len) {
        free(buf);
        return NULL;
    }
    *out_len = len;
    return buf;
}

/* Build the manifest (leaf hashes) for an in-memory body under the real
 * chunking rules for pinned file `idx`. */
static uint8_t *build_manifest(int idx, const uint8_t *body, uint32_t *out_count)
{
    uint32_t n = zcl_param_pins[idx].chunk_count;
    uint8_t *man = zcl_malloc((size_t)n * ZCL_PARAM_HASH_BYTES, "test_manifest");
    if (!man)
        return NULL;
    for (uint32_t i = 0; i < n; i++) {
        size_t len = zcl_param_chunk_len(idx, i);
        zcl_param_leaf_hash(body + (size_t)i * ZCL_PARAM_CHUNK_BYTES, len,
                            man + (size_t)i * ZCL_PARAM_HASH_BYTES);
    }
    *out_count = n;
    return man;
}

/* ── 1. The pin table is internally consistent ─────────────────────── */

static int test_pins_consistent(void)
{
    int failures = 0;
    printf("  [pins] table consistency\n");

    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++) {
        const struct zcl_param_pin *p = &zcl_param_pins[i];
        CHECK(p->name && *p->name, "pin has a name");
        CHECK(p->bytes > 0 && p->bytes <= ZCL_PARAM_MAX_FILE_BYTES,
              "pinned length is inside the hard ceiling");
        CHECK(strlen(p->sha256_hex) == 64, "pinned sha256 is 64 hex chars");
        CHECK(strlen(p->chunk_root_hex) == 64, "pinned root is 64 hex chars");

        uint64_t want = (p->bytes + ZCL_PARAM_CHUNK_BYTES - 1) / ZCL_PARAM_CHUNK_BYTES;
        CHECK((uint64_t)p->chunk_count == want,
              "written chunk_count equals ceil(bytes/chunk)");
        CHECK(p->chunk_count <= ZCL_PARAM_MAX_CHUNKS,
              "chunk count is inside the hard cap");

        /* Chunk lengths must sum to exactly the pinned length: this is what
         * makes an out-of-range or short final chunk detectable. */
        uint64_t sum = 0;
        for (uint32_t c = 0; c < p->chunk_count; c++) {
            size_t l = zcl_param_chunk_len(i, c);
            CHECK(l > 0 && l <= ZCL_PARAM_CHUNK_BYTES, "chunk length in range");
            sum += l;
        }
        CHECK(sum == p->bytes, "chunk lengths sum to the pinned length");
        CHECK(zcl_param_chunk_len(i, p->chunk_count) == 0,
              "one past the last chunk has length 0");
        CHECK(zcl_param_chunk_len(i, UINT32_MAX) == 0,
              "UINT32_MAX chunk index has length 0");
    }

    CHECK(zcl_param_pin_index("sapling-spend.params") == 0, "name lookup works");
    CHECK(zcl_param_pin_index("../../etc/passwd") == -1,
          "a path-traversal name is not a pinned file");
    CHECK(zcl_param_pin_index("") == -1, "empty name is not a pinned file");
    CHECK(zcl_param_pin_index(NULL) == -1, "NULL name is not a pinned file");
    CHECK(zcl_param_chunk_len(-1, 0) == 0, "negative file index is refused");
    CHECK(zcl_param_chunk_len(ZCL_PARAM_FILE_COUNT, 0) == 0,
          "out-of-range file index is refused");
    return failures;
}

/* ── 2. Merkle behaviour ───────────────────────────────────────────── */

static int test_merkle(void)
{
    int failures = 0;
    printf("  [merkle] fold properties\n");

    uint8_t leaves[8 * ZCL_PARAM_HASH_BYTES];
    for (int i = 0; i < 8; i++)
        fill_pattern(leaves + i * ZCL_PARAM_HASH_BYTES, ZCL_PARAM_HASH_BYTES,
                     (uint32_t)(i + 1));

    uint8_t r1[32], r2[32];
    CHECK(zcl_param_merkle_root(leaves, 8, r1), "8-leaf fold succeeds");
    CHECK(zcl_param_merkle_root(leaves, 8, r2), "fold is repeatable");
    CHECK(memcmp(r1, r2, 32) == 0, "fold is deterministic");

    /* One flipped bit anywhere changes the root. */
    leaves[3 * ZCL_PARAM_HASH_BYTES + 7] ^= 0x01;
    CHECK(zcl_param_merkle_root(leaves, 8, r2), "fold after flip succeeds");
    CHECK(memcmp(r1, r2, 32) != 0, "a flipped leaf bit changes the root");
    leaves[3 * ZCL_PARAM_HASH_BYTES + 7] ^= 0x01;

    /* A different leaf COUNT must give a different root — this is the
     * property that makes duplicating an odd node unsafe and promoting it
     * safe. Fold 3 leaves and 4 leaves where the 4th duplicates the 3rd; a
     * duplicate-the-last-node tree would collide here. */
    uint8_t three[4 * ZCL_PARAM_HASH_BYTES];
    memcpy(three, leaves, 3 * ZCL_PARAM_HASH_BYTES);
    memcpy(three + 3 * ZCL_PARAM_HASH_BYTES, leaves + 2 * ZCL_PARAM_HASH_BYTES,
           ZCL_PARAM_HASH_BYTES);
    uint8_t r3[32], r4[32];
    CHECK(zcl_param_merkle_root(three, 3, r3), "3-leaf fold succeeds");
    CHECK(zcl_param_merkle_root(three, 4, r4), "4-leaf fold succeeds");
    CHECK(memcmp(r3, r4, 32) != 0,
          "promoting (not duplicating) the odd node keeps 3 and 4 leaves distinct");

    /* Single leaf is its own root. */
    uint8_t r5[32];
    CHECK(zcl_param_merkle_root(leaves, 1, r5), "1-leaf fold succeeds");
    CHECK(memcmp(r5, leaves, 32) == 0, "single leaf is the root");

    /* Bounds. */
    CHECK(!zcl_param_merkle_root(leaves, 0, r1), "zero leaves is refused");
    CHECK(!zcl_param_merkle_root(leaves, ZCL_PARAM_MAX_CHUNKS + 1, r1),
          "more than the cap is refused");
    CHECK(!zcl_param_merkle_root(NULL, 4, r1), "NULL leaves is refused");

    /* Leaf and interior hashes are domain-separated: a 32-byte "chunk" whose
     * bytes are two concatenated hashes must not hash like an interior node. */
    uint8_t pair[64];
    memcpy(pair, leaves, 64);
    uint8_t as_leaf[32];
    zcl_param_leaf_hash(pair, 64, as_leaf);
    uint8_t two[2 * ZCL_PARAM_HASH_BYTES];
    memcpy(two, leaves, 64);
    uint8_t as_node[32];
    CHECK(zcl_param_merkle_root(two, 2, as_node), "2-leaf fold succeeds");
    CHECK(memcmp(as_leaf, as_node, 32) != 0,
          "leaf and interior hashing are domain-separated");
    return failures;
}

/* ── 3. A lying manifest is rejected against the compiled-in root ───── */

static int test_manifest_rejection(void)
{
    int failures = 0;
    printf("  [manifest] hostile manifests\n");

    /* sprout-verifying.key: one chunk, so its pinned root IS its leaf hash.
     * Build the honest manifest from the real file if present; otherwise
     * assert only the refusal paths, which need no real bytes. */
    size_t len = 0;
    uint8_t *body = load_real_param(3, &len);

    if (body) {
        uint32_t n = 0;
        uint8_t *man = build_manifest(3, body, &n);
        CHECK(man != NULL, "manifest built");
        if (man) {
            CHECK(zcl_param_manifest_verify(3, man, n),
                  "the honest manifest folds to the compiled-in root");

            /* One flipped bit in one leaf: refused. */
            man[5] ^= 0x08;
            CHECK(!zcl_param_manifest_verify(3, man, n),
                  "a manifest with one flipped bit is refused");
            man[5] ^= 0x08;

            /* Right leaves, wrong count: refused before the fold. */
            CHECK(!zcl_param_manifest_verify(3, man, n + 1),
                  "a manifest claiming too many chunks is refused");
            CHECK(!zcl_param_manifest_verify(3, man, 0),
                  "a manifest claiming zero chunks is refused");
            CHECK(!zcl_param_manifest_verify(3, man, ZCL_PARAM_MAX_CHUNKS),
                  "a manifest claiming the cap is refused for a 1-chunk file");
            CHECK(!zcl_param_manifest_verify(3, man, UINT32_MAX),
                  "a manifest claiming UINT32_MAX chunks is refused");

            /* Right count, entirely fabricated leaves: refused. */
            uint8_t *fake = zcl_calloc(n, ZCL_PARAM_HASH_BYTES, "test_fake_man");
            if (fake) {
                fill_pattern(fake, (size_t)n * ZCL_PARAM_HASH_BYTES, 0xBADF00Du);
                CHECK(!zcl_param_manifest_verify(3, fake, n),
                      "a fabricated manifest of the right shape is refused");
                free(fake);
            }

            /* A manifest for the RIGHT file offered as another file: refused. */
            CHECK(!zcl_param_manifest_verify(1, man, n),
                  "a manifest offered under the wrong file index is refused");
            free(man);
        }
        free(body);
    } else {
        printf("    (real sprout-verifying.key absent — "
               "root-match assertions skipped, refusals still checked)\n");
    }

    /* These need no real bytes at all. */
    uint8_t junk[ZCL_PARAM_HASH_BYTES * 4];
    fill_pattern(junk, sizeof(junk), 7u);
    CHECK(!zcl_param_manifest_verify(-1, junk, 1), "bad file index refused");
    CHECK(!zcl_param_manifest_verify(ZCL_PARAM_FILE_COUNT, junk, 1),
          "out-of-range file index refused");
    CHECK(!zcl_param_manifest_verify(0, NULL, 46), "NULL leaves refused");
    return failures;
}

/* ── 4. Session: correct fetch, bad chunks, resume, atomic install ──── */

static int test_session_roundtrip(void)
{
    int failures = 0;
    printf("  [session] fetch / refuse / resume / install\n");

    /* Drive a real session over the smallest pinned file. Needs the real
     * bytes, because the session finalizes against the compiled-in SHA-256. */
    size_t len = 0;
    uint8_t *body = load_real_param(3, &len);
    if (!body) {
        printf("    (real sprout-verifying.key absent — session round-trip "
               "skipped; see the lane report)\n");
        return failures;
    }

    uint32_t n = 0;
    uint8_t *man = build_manifest(3, body, &n);
    if (!man) {
        free(body);
        CHECK(false, "manifest allocation");
        return failures;
    }

    struct zcl_param_fetch *s = zcl_param_fetch_open(g_dir, 3);
    CHECK(s != NULL, "session opens");
    if (!s) {
        free(man);
        free(body);
        return failures;
    }

    /* No manifest yet: a chunk is refused outright. */
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, len) ==
              ZCL_PARAM_CHUNK_NO_MANIFEST,
          "a chunk arriving before a manifest is refused");

    /* A lying manifest is refused, and leaves the session with no manifest —
     * so the fetcher never asks for a chunk against it. */
    uint8_t *fake = zcl_calloc(n, ZCL_PARAM_HASH_BYTES, "test_fake");
    CHECK(fake != NULL, "fake manifest allocation");
    if (fake) {
        fill_pattern(fake, (size_t)n * ZCL_PARAM_HASH_BYTES, 0x5EEDu);
        CHECK(!zcl_param_fetch_set_manifest(s, fake, n),
              "a manifest that does not match the compiled-in root is refused");
        CHECK(!zcl_param_fetch_has_manifest(s),
              "a refused manifest is not installed");
        free(fake);
    }

    CHECK(zcl_param_fetch_set_manifest(s, man, n), "the honest manifest is accepted");
    CHECK(zcl_param_fetch_has_manifest(s), "manifest is installed");
    CHECK(zcl_param_fetch_chunks_total(s) == n, "chunk total matches the pin");
    CHECK(zcl_param_fetch_next_needed(s) == 0, "chunk 0 is wanted first");

    /* An oversized length field is refused. The session compares it to the
     * pin-derived length before touching `data`, so nothing is allocated and
     * nothing is read past the buffer. */
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, len + 1) ==
              ZCL_PARAM_CHUNK_BAD_LENGTH,
          "an oversized length field is refused");
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, (size_t)ZCL_PARAM_CHUNK_BYTES) ==
              ZCL_PARAM_CHUNK_BAD_LENGTH,
          "a full-chunk length on a short final chunk is refused");
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, SIZE_MAX / 2) ==
              ZCL_PARAM_CHUNK_BAD_LENGTH,
          "an absurd length field is refused without allocating");

    /* A truncated stream is refused: same path, short instead of long. */
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, len - 1) ==
              ZCL_PARAM_CHUNK_BAD_LENGTH,
          "a truncated chunk is refused");
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, 0) ==
              ZCL_PARAM_CHUNK_BAD_LENGTH,
          "an empty chunk is refused");

    /* An out-of-range index is refused. */
    CHECK(zcl_param_fetch_accept_chunk(s, n, body, len) ==
              ZCL_PARAM_CHUNK_BAD_INDEX,
          "a chunk index past the end is refused");
    CHECK(zcl_param_fetch_accept_chunk(s, UINT32_MAX, body, len) ==
              ZCL_PARAM_CHUNK_BAD_INDEX,
          "UINT32_MAX chunk index is refused");

    /* One flipped bit in the payload is caught and that chunk is refused. */
    uint8_t *tampered = zcl_malloc(len, "test_tampered");
    CHECK(tampered != NULL, "tamper buffer");
    if (tampered) {
        memcpy(tampered, body, len);
        tampered[len / 2] ^= 0x01;
        CHECK(zcl_param_fetch_accept_chunk(s, 0, tampered, len) ==
                  ZCL_PARAM_CHUNK_BAD_HASH,
              "a single flipped bit in a chunk is caught");
        CHECK(zcl_param_fetch_chunks_have(s) == 0,
              "a refused chunk is not counted");
        CHECK(zcl_param_fetch_bytes_rejected(s) > 0,
              "refused bytes are charged to the peer");
        free(tampered);
    }

    /* Nothing above should have created the final file. */
    char final_path[900];
    snprintf(final_path, sizeof(final_path), "%s/%s", g_dir,
             zcl_param_pins[3].name);
    struct stat st;
    CHECK(stat(final_path, &st) != 0,
          "no partial file is visible while the transfer is incomplete");

    /* The honest chunk is accepted. */
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, len) == ZCL_PARAM_CHUNK_OK,
          "the correct chunk is accepted");
    CHECK(zcl_param_fetch_chunks_have(s) == 1, "chunk counted");
    CHECK(zcl_param_fetch_is_complete(s), "session reports complete");

    /* A duplicate is reported as such and charged, not silently re-written. */
    CHECK(zcl_param_fetch_accept_chunk(s, 0, body, len) ==
              ZCL_PARAM_CHUNK_DUPLICATE,
          "a duplicate chunk is refused as a duplicate");

    CHECK(zcl_param_fetch_finalize(s), "finalize installs the file");
    CHECK(stat(final_path, &st) == 0, "the final file now exists");
    CHECK((uint64_t)st.st_size == zcl_param_pins[3].bytes,
          "the installed file has the pinned length");
    CHECK(zcl_param_verify_installed(g_dir, 3),
          "the installed file verifies against the pinned SHA-256");

    /* Byte-exactness, read back off disk. */
    FILE *f = fopen(final_path, "rb");
    CHECK(f != NULL, "installed file opens");
    if (f) {
        uint8_t *back = zcl_malloc(len, "test_readback");
        if (back) {
            CHECK(fread(back, 1, len, f) == len, "installed file reads back fully");
            CHECK(memcmp(back, body, len) == 0,
                  "the reassembled file is byte-exact");
            free(back);
        }
        fclose(f);
    }

    zcl_param_fetch_close(s);

    /* The .part and state files are gone after a successful install. */
    char part[900];
    snprintf(part, sizeof(part), "%s/%s.part", g_dir, zcl_param_pins[3].name);
    CHECK(stat(part, &st) != 0, "the .part file is consumed by the rename");

    free(man);
    free(body);
    return failures;
}

/* ── 5. Interrupted transfer resumes rather than restarting ─────────── */

static int test_resume(void)
{
    int failures = 0;
    printf("  [resume] interrupted transfer\n");

    /* Use sapling-output.params: 4 chunks, small enough to keep in memory,
     * big enough that "resume" means something. */
    size_t len = 0;
    uint8_t *body = load_real_param(1, &len);
    if (!body) {
        printf("    (real sapling-output.params absent — resume test skipped; "
               "see the lane report)\n");
        return failures;
    }

    uint32_t n = 0;
    uint8_t *man = build_manifest(1, body, &n);
    if (!man) {
        free(body);
        CHECK(false, "manifest allocation");
        return failures;
    }
    CHECK(n == 4, "sapling-output.params is 4 chunks");

    /* First run: take two chunks, then "crash" (close without finalizing). */
    struct zcl_param_fetch *s = zcl_param_fetch_open(g_dir, 1);
    CHECK(s != NULL, "session opens");
    if (!s) {
        free(man);
        free(body);
        return failures;
    }
    CHECK(zcl_param_fetch_set_manifest(s, man, n), "manifest accepted");
    for (uint32_t i = 0; i < 2; i++) {
        size_t cl = zcl_param_chunk_len(1, i);
        CHECK(zcl_param_fetch_accept_chunk(
                  s, i, body + (size_t)i * ZCL_PARAM_CHUNK_BYTES, cl) ==
                  ZCL_PARAM_CHUNK_OK,
              "chunk accepted before the interruption");
    }
    CHECK(zcl_param_fetch_chunks_have(s) == 2, "two chunks held");
    CHECK(!zcl_param_fetch_is_complete(s), "not complete yet");
    zcl_param_fetch_close(s);

    /* Second run: the session must come back with those two chunks already
     * verified, and — crucially — with the manifest recovered from its own
     * state file AND re-checked against the compiled-in root, so no new
     * manifest fetch is needed to continue. */
    s = zcl_param_fetch_open(g_dir, 1);
    CHECK(s != NULL, "session reopens");
    if (!s) {
        free(man);
        free(body);
        return failures;
    }
    CHECK(zcl_param_fetch_has_manifest(s),
          "the manifest survives the interruption and re-verifies");
    CHECK(zcl_param_fetch_chunks_have(s) == 2,
          "resume keeps the chunks already verified — it does not restart");
    CHECK(zcl_param_fetch_next_needed(s) == 2,
          "resume asks for the first chunk it is actually missing");

    /* Finish it. */
    for (uint32_t i = 2; i < n; i++) {
        size_t cl = zcl_param_chunk_len(1, i);
        CHECK(zcl_param_fetch_accept_chunk(
                  s, i, body + (size_t)i * ZCL_PARAM_CHUNK_BYTES, cl) ==
                  ZCL_PARAM_CHUNK_OK,
              "chunk accepted after the resume");
    }
    CHECK(zcl_param_fetch_is_complete(s), "complete after resume");
    CHECK(zcl_param_fetch_finalize(s), "finalize after resume");
    CHECK(zcl_param_verify_installed(g_dir, 1),
          "the resumed file verifies against the pinned SHA-256");
    zcl_param_fetch_close(s);

    /* Byte-exact after a resume, not just hash-equal by luck. */
    char final_path[900];
    snprintf(final_path, sizeof(final_path), "%s/%s", g_dir,
             zcl_param_pins[1].name);
    FILE *f = fopen(final_path, "rb");
    CHECK(f != NULL, "resumed file opens");
    if (f) {
        uint8_t *back = zcl_malloc(len, "test_readback2");
        if (back) {
            CHECK(fread(back, 1, len, f) == len, "resumed file reads back fully");
            CHECK(memcmp(back, body, len) == 0,
                  "the resumed file is byte-exact");
            free(back);
        }
        fclose(f);
    }

    free(man);
    free(body);
    return failures;
}

/* ── 6. Resume refuses to believe a corrupted .part ─────────────────── */

static int test_resume_rejects_corrupt_part(void)
{
    int failures = 0;
    printf("  [resume] corrupted .part is not believed\n");

    size_t len = 0;
    uint8_t *body = load_real_param(1, &len);
    if (!body) {
        printf("    (real sapling-output.params absent — skipped)\n");
        return failures;
    }
    uint32_t n = 0;
    uint8_t *man = build_manifest(1, body, &n);
    if (!man) {
        free(body);
        return failures;
    }

    struct zcl_param_fetch *s = zcl_param_fetch_open(g_dir, 1);
    if (!s) {
        free(man);
        free(body);
        CHECK(false, "session opens");
        return failures;
    }
    CHECK(zcl_param_fetch_set_manifest(s, man, n), "manifest accepted");
    for (uint32_t i = 0; i < 3; i++)
        (void)zcl_param_fetch_accept_chunk(
            s, i, body + (size_t)i * ZCL_PARAM_CHUNK_BYTES,
            zcl_param_chunk_len(1, i));
    CHECK(zcl_param_fetch_chunks_have(s) == 3, "three chunks held");
    zcl_param_fetch_close(s);

    /* Corrupt chunk 1 in the .part behind the session's back — the shape an
     * unclean shutdown or a bad sector leaves. The state file still claims
     * the chunk is good. */
    char part[900];
    snprintf(part, sizeof(part), "%s/%s.part", g_dir, zcl_param_pins[1].name);
    int fd = open(part, O_RDWR);
    CHECK(fd >= 0, ".part opens for tampering");
    if (fd >= 0) {
        uint8_t bad = 0xFF;
        off_t at = (off_t)ZCL_PARAM_CHUNK_BYTES + 100;
        CHECK(pwrite(fd, &bad, 1, at) == 1, "tamper written");
        close(fd);
    }

    s = zcl_param_fetch_open(g_dir, 1);
    CHECK(s != NULL, "session reopens over the corrupted .part");
    if (s) {
        CHECK(zcl_param_fetch_chunks_have(s) == 2,
              "resume re-hashes and drops the corrupted chunk rather than "
              "trusting the state file");
        CHECK(zcl_param_fetch_next_needed(s) == 1,
              "the dropped chunk is the one re-requested");
        zcl_param_fetch_close(s);
    }

    /* Clean up so the later real-file test starts fresh. */
    unlink(part);
    char state[900];
    snprintf(state, sizeof(state), "%s/%s.zpart", g_dir, zcl_param_pins[1].name);
    unlink(state);

    free(man);
    free(body);
    return failures;
}

/* ── 7. Installed-verification refuses a wrong-length or wrong-content file */

static int test_verify_installed_refusals(void)
{
    int failures = 0;
    printf("  [verify] installed-file refusals\n");

    char path[900];
    snprintf(path, sizeof(path), "%s/%s", g_dir, zcl_param_pins[0].name);
    unlink(path);

    CHECK(!zcl_param_verify_installed(g_dir, 0),
          "an absent file does not verify");

    /* A file of the right NAME but the wrong length: refused on the stat,
     * before anything is hashed. */
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "decoy opens");
    if (f) {
        uint8_t junk[1024];
        fill_pattern(junk, sizeof(junk), 42u);
        fwrite(junk, 1, sizeof(junk), f);
        fclose(f);
    }
    CHECK(!zcl_param_verify_installed(g_dir, 0),
          "a short file under the right name does not verify");
    unlink(path);

    CHECK(!zcl_params_all_installed_verified(g_dir),
          "the all-files predicate is false when a file is missing");
    CHECK(!zcl_param_verify_installed(g_dir, -1), "bad index does not verify");
    CHECK(!zcl_param_verify_installed(g_dir, ZCL_PARAM_FILE_COUNT),
          "out-of-range index does not verify");
    return failures;
}

/* ── 8. Recomputation reproduces the pinned digests from the real files ── */

static int test_pins_match_real_files(void)
{
    int failures = 0;
    printf("  [pins] recomputation from the real parameter files\n");

    const char *home = getenv("HOME");
    int checked = 0;
    /* Recomputing every pin streams ~777 MB. The two small files are always
     * checked; the two large ones are checked when the stress gate is on,
     * which is the gate the lane is required to run. */
    const bool full = getenv("ZCL_STRESS_TESTS") != NULL;
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT && home; i++) {
        if (!full && zcl_param_pins[i].bytes > (16ull * 1024ull * 1024ull))
            continue;
        char path[900];
        snprintf(path, sizeof(path), "%s/.zcash-params/%s", home,
                 zcl_param_pins[i].name);
        struct stat st;
        if (stat(path, &st) != 0)
            continue;

        uint64_t bytes = 0;
        uint8_t sha[32], root[32];
        if (!zcl_param_pin_recompute_from_file(path, &bytes, sha, root)) {
            CHECK(false, "recomputation over a present real file succeeds");
            continue;
        }
        CHECK(bytes == zcl_param_pins[i].bytes,
              "the real file's length equals the pinned length");

        char hex[65];
        for (int k = 0; k < 32; k++)
            snprintf(hex + k * 2, 3, "%02x", sha[k]);
        CHECK(strcmp(hex, zcl_param_pins[i].sha256_hex) == 0,
              "the real file's SHA-256 equals the pinned digest");

        for (int k = 0; k < 32; k++)
            snprintf(hex + k * 2, 3, "%02x", root[k]);
        CHECK(strcmp(hex, zcl_param_pins[i].chunk_root_hex) == 0,
              "the real file's chunk root equals the pinned root");
        checked++;
    }
    if (checked == 0)
        printf("    (no real parameter files on this machine — "
               "pin recomputation not exercised)\n");
    else
        printf("    (%d of %d real files recomputed and matched%s)\n", checked,
               ZCL_PARAM_FILE_COUNT,
               full ? "" : " — set ZCL_STRESS_TESTS=1 for the large two");

    CHECK(!zcl_param_pin_recompute_from_file("/nonexistent/zcl/param", NULL,
                                             NULL, NULL),
          "recomputation over a missing path fails cleanly");
    CHECK(!zcl_param_pin_recompute_from_file(NULL, NULL, NULL, NULL),
          "recomputation over a NULL path fails cleanly");
    return failures;
}

/* ── 9. Serving is off until the local copy is verified ─────────────── */

static int test_serving_off_by_default(void)
{
    int failures = 0;
    printf("  [serve] off until the local copy verifies\n");

    /* g_dir has, at most, the two files the earlier tests installed. Whatever
     * is NOT there must not be servable. */
    char empty[600];
    snprintf(empty, sizeof(empty), "%s/empty", g_dir);
    (void)mkdir(empty, 0700);

    zcl_param_serve_shutdown();
    int armed = zcl_param_serve_prepare(empty);
    CHECK(armed == 0, "an empty directory arms nothing");
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++)
        CHECK(!zcl_param_serve_ready(i), "no file is servable from nothing");

    uint8_t out[64];
    size_t got = 0;
    uint32_t count = 0;
    CHECK(!zcl_param_serve_chunk(0, 0, out, sizeof(out), &got),
          "an unarmed chunk request serves nothing");
    CHECK(!zcl_param_serve_manifest(0, out, sizeof(out), &count),
          "an unarmed manifest request serves nothing");
    CHECK(!zcl_param_serve_ready(-1), "negative index is never servable");
    CHECK(!zcl_param_serve_ready(ZCL_PARAM_FILE_COUNT),
          "out-of-range index is never servable");

    rmdir(empty);
    zcl_param_serve_shutdown();
    return failures;
}

/* ── 10. Serve/fetch round trip through the serving API ─────────────── */

static int test_serve_roundtrip(void)
{
    int failures = 0;
    printf("  [serve] armed serving feeds a fetch\n");

    /* Arm serving from the scratch directory the earlier tests installed
     * into. Deliberately NOT the real ~/.zcash-params: arming streams every
     * file it finds, and making the fast suite read 777 MB to prove a
     * round-trip that 1449 bytes proves just as well would be vandalism. The
     * two files installed above (sprout-verifying.key and, if it ran,
     * sapling-output.params) are enough, and the two that are absent are
     * exactly the "must not serve what we do not have" case. */
    struct stat st;
    char probe[900];
    snprintf(probe, sizeof(probe), "%s/%s", g_dir, zcl_param_pins[3].name);
    if (stat(probe, &st) != 0) {
        printf("    (no installed file from the earlier tests — skipped)\n");
        return failures;
    }
    const char *src = g_dir;

    zcl_param_serve_shutdown();
    int armed = zcl_param_serve_prepare(src);
    CHECK(armed > 0, "serving arms from a verified parameter directory");
    CHECK(armed < ZCL_PARAM_FILE_COUNT,
          "a file we do not have is not armed for serving");
    CHECK(!zcl_param_serve_ready(2),
          "sprout-groth16.params is absent here and must not be servable");
    CHECK(zcl_param_serve_ready(3), "the smallest file is servable");

    uint32_t count = 0;
    static uint8_t man[ZCL_PARAM_MANIFEST_MAX_BYTES];
    CHECK(zcl_param_serve_manifest(3, man, sizeof(man), &count),
          "the served manifest is produced");
    CHECK(count == zcl_param_pins[3].chunk_count,
          "the served manifest has the pinned chunk count");
    CHECK(zcl_param_manifest_verify(3, man, count),
          "the served manifest folds to the compiled-in root");

    /* A too-small buffer is refused rather than overflowed. */
    uint8_t tiny[8];
    CHECK(!zcl_param_serve_manifest(3, tiny, sizeof(tiny), &count),
          "a manifest request with too small a buffer is refused");
    size_t got = 0;
    CHECK(!zcl_param_serve_chunk(3, 0, tiny, sizeof(tiny), &got),
          "a chunk request with too small a buffer is refused");
    CHECK(!zcl_param_serve_chunk(3, zcl_param_pins[3].chunk_count, man,
                                 sizeof(man), &got),
          "an out-of-range chunk index is refused");
    CHECK(!zcl_param_serve_chunk(3, UINT32_MAX, man, sizeof(man), &got),
          "UINT32_MAX chunk index is refused");

    /* Pull the file through a session using served bytes only. */
    char final_path[900];
    snprintf(final_path, sizeof(final_path), "%s/%s", g_dir,
             zcl_param_pins[3].name);
    unlink(final_path);

    struct zcl_param_fetch *s = zcl_param_fetch_open(g_dir, 3);
    CHECK(s != NULL, "session opens for the served pull");
    if (s) {
        CHECK(zcl_param_fetch_set_manifest(s, man, count),
              "the served manifest is accepted by the fetcher");
        uint8_t *buf = zcl_malloc(ZCL_PARAM_CHUNK_BYTES, "test_serve_pull");
        bool all_ok = buf != NULL;
        for (uint32_t i = 0; all_ok && i < count; i++) {
            size_t clen = 0;
            if (!zcl_param_serve_chunk(3, i, buf, ZCL_PARAM_CHUNK_BYTES, &clen)) {
                all_ok = false;
                break;
            }
            if (zcl_param_fetch_accept_chunk(s, i, buf, clen) !=
                ZCL_PARAM_CHUNK_OK)
                all_ok = false;
        }
        free(buf);
        CHECK(all_ok, "every served chunk verifies at the fetcher");
        CHECK(zcl_param_fetch_is_complete(s), "the served pull completes");
        CHECK(zcl_param_fetch_finalize(s), "the served pull installs");
        CHECK(zcl_param_verify_installed(g_dir, 3),
              "the served pull produces a file matching the pinned SHA-256");
        zcl_param_fetch_close(s);
    }

    zcl_param_serve_shutdown();
    return failures;
}

/* ── entry point ────────────────────────────────────────────────────── */

int test_params_fetch(void);
int test_params_fetch(void)
{
    int failures = 0;
    printf("\n=== params_fetch: proving parameters over the peer network ===\n");

    if (!make_scratch_dir()) {
        printf("  FAIL: cannot create scratch directory\n");
        return 1;
    }

    failures += test_pins_consistent();
    failures += test_merkle();
    failures += test_manifest_rejection();
    failures += test_session_roundtrip();
    failures += test_resume();
    failures += test_resume_rejects_corrupt_part();
    failures += test_verify_installed_refusals();
    failures += test_pins_match_real_files();
    failures += test_serving_off_by_default();
    failures += test_serve_roundtrip();

    cleanup_scratch();

    if (failures == 0)
        printf("=== params_fetch: all checks passed ===\n");
    else
        printf("=== params_fetch: %d FAILURES ===\n", failures);
    return failures;
}
