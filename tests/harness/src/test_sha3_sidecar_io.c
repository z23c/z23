/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for storage/sha3_sidecar_io.c — the shared body+sidecar
 * hashing / atomic-write / header-parse primitives behind
 * net/addrman_integrity (peers.dat) and block_index_sidecar_integrity
 * (block_index.bin).
 *
 * These functions are deterministic given their inputs and touch no
 * global/process state; every I/O side effect is confined to a private
 * temp directory this file creates and removes, so runs are fast and
 * order-independent. Despite having two live callers, the primitive
 * itself (engine/modules/storage/src/sha3_sidecar_io.c) had zero direct test
 * coverage before this file — grep for ssio_hash_body / ssio_write_sidecar
 * / ssio_read_sidecar across tests/harness/src turned up nothing but an
 * unrelated string match in test_make_lint_gates.c. */

#include "test/test_core.h"
#include "coins/undo.h"

#include "crypto/sha3.h"
#include "storage/sha3_sidecar_io.h"
#include "util/result.h"

#include <stdio.h>
#include <string.h>

#define SS_CHECK(name, expr) do {                                   \
    printf("sha3_sidecar_io: %s... ", (name));                      \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static bool write_file(const char *path, const void *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = (len == 0) || (fwrite(buf, 1, len, f) == len);
    fclose(f);
    return ok;
}

static void independent_sha3(const void *buf, size_t len, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, buf, len);
    sha3_256_finalize(&ctx, out);
}

/* ── ssio_hash_body ─────────────────────────────────────────────── */

static int case_hash_body(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "hash_body");

    struct ssio_spec spec = {
        .body_name = "body.dat",
        .sidecar_name = "body.dat.sha3",
        .magic = "TEST",
        .version = 1,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };

    char body_path[300];
    snprintf(body_path, sizeof(body_path), "%s/%s", dir, spec.body_name);

    /* Missing file: false, no crash. */
    uint8_t hash[32];
    uint64_t size = 0;
    SS_CHECK("missing body returns false",
             !ssio_hash_body(dir, &spec, hash, &size));

    /* Small known body: hash matches an independent SHA3-256 over the
     * same bytes computed without going through the streaming reader. */
    const char *small = "the quick brown fox jumps over the lazy dog";
    SS_CHECK("write small body fixture",
             write_file(body_path, small, strlen(small)));
    uint8_t expected[32];
    independent_sha3(small, strlen(small), expected);
    SS_CHECK("hash_body succeeds on small body",
             ssio_hash_body(dir, &spec, hash, &size));
    SS_CHECK("hash_body reports correct size", size == strlen(small));
    SS_CHECK("hash_body digest matches independent SHA3-256",
             memcmp(hash, expected, 32) == 0);

    /* Empty body: legal (zero-length file), size 0, digest of "". */
    SS_CHECK("write empty body fixture", write_file(body_path, "", 0));
    independent_sha3("", 0, expected);
    SS_CHECK("hash_body succeeds on empty body",
             ssio_hash_body(dir, &spec, hash, &size));
    SS_CHECK("hash_body reports size 0 for empty body", size == 0);
    SS_CHECK("hash_body(empty) matches independent SHA3-256(\"\")",
             memcmp(hash, expected, 32) == 0);

    /* Body larger than the internal 1 MiB streaming buffer: proves the
     * multi-chunk fread loop folds correctly across a buffer boundary,
     * not just a single-shot read. */
    {
        size_t big_len = (1u << 20) + 12345; /* > 1 MiB */
        uint8_t *big = zcl_malloc(big_len, "ssio_test_big");
        SS_CHECK("alloc big body fixture", big != NULL);
        if (big) {
            for (size_t i = 0; i < big_len; i++)
                big[i] = (uint8_t)(i * 2654435761u);
            SS_CHECK("write big body fixture",
                     write_file(body_path, big, big_len));
            independent_sha3(big, big_len, expected);
            SS_CHECK("hash_body succeeds on >1MiB body",
                     ssio_hash_body(dir, &spec, hash, &size));
            SS_CHECK("hash_body reports correct size for big body",
                     size == big_len);
            SS_CHECK("hash_body(big) matches independent SHA3-256",
                     memcmp(hash, expected, 32) == 0);
            free(big);
        }
    }

    /* out_size is optional — NULL must not crash. */
    SS_CHECK("hash_body tolerates NULL out_size",
             ssio_hash_body(dir, &spec, hash, NULL));

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── ssio_write_sidecar_raw + ssio_read_sidecar round trip ───────── */

static int case_sidecar_round_trip(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "sidecar_rt");

    struct ssio_spec spec = {
        .body_name = "peers.dat",
        .sidecar_name = "peers.dat.sha3",
        .magic = "ADIX",
        .version = 3,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };

    /* Missing sidecar: MISSING verdict, no crash. */
    struct ssio_sidecar_header hdr;
    SS_CHECK("read missing sidecar -> SSIO_READ_MISSING",
             ssio_read_sidecar(dir, &spec, &hdr) == SSIO_READ_MISSING);

    /* Round trip: write a raw sidecar for a known (size, hash) pair,
     * read it back, and confirm every field survives byte-for-byte. */
    uint8_t known_hash[32];
    for (int i = 0; i < 32; i++) known_hash[i] = (uint8_t)(i + 1);
    struct zcl_result wr =
        ssio_write_sidecar_raw(dir, &spec, 123456789ull, known_hash);
    SS_CHECK("write_sidecar_raw OK", wr.ok);

    struct ssio_sidecar_header got;
    memset(&got, 0, sizeof(got));
    enum ssio_read_verdict v = ssio_read_sidecar(dir, &spec, &got);
    SS_CHECK("read back written sidecar -> SSIO_READ_OK",
             v == SSIO_READ_OK);
    SS_CHECK("round-tripped magic matches", memcmp(got.magic, "ADIX", 4) == 0);
    SS_CHECK("round-tripped version matches", got.version == spec.version);
    SS_CHECK("round-tripped body_size matches", got.body_size == 123456789ull);
    SS_CHECK("round-tripped body_sha3 matches",
             memcmp(got.body_sha3, known_hash, 32) == 0);

    /* A second write overwrites the first (atomic tmp+rename, not append). */
    uint8_t known_hash2[32];
    for (int i = 0; i < 32; i++) known_hash2[i] = (uint8_t)(200 - i);
    struct zcl_result wr2 =
        ssio_write_sidecar_raw(dir, &spec, 42, known_hash2);
    SS_CHECK("second write_sidecar_raw OK", wr2.ok);
    v = ssio_read_sidecar(dir, &spec, &got);
    SS_CHECK("re-read after overwrite -> SSIO_READ_OK", v == SSIO_READ_OK);
    SS_CHECK("overwritten body_size wins", got.body_size == 42);
    SS_CHECK("overwritten body_sha3 wins",
             memcmp(got.body_sha3, known_hash2, 32) == 0);

    /* Wrong magic at read time (different spec, same file) -> BAD_MAGIC. */
    struct ssio_spec wrong_magic_spec = spec;
    wrong_magic_spec.magic = "ZZZZ";
    v = ssio_read_sidecar(dir, &wrong_magic_spec, &got);
    SS_CHECK("read with mismatched magic -> SSIO_READ_BAD_MAGIC",
             v == SSIO_READ_BAD_MAGIC);

    /* Wrong version at read time (same magic, different version) ->
     * UNSUPPORTED. */
    struct ssio_spec wrong_version_spec = spec;
    wrong_version_spec.version = spec.version + 1;
    v = ssio_read_sidecar(dir, &wrong_version_spec, &got);
    SS_CHECK("read with mismatched version -> SSIO_READ_UNSUPPORTED",
             v == SSIO_READ_UNSUPPORTED);

    /* Defensive: NULL datadir / NULL body_sha3 rejected without writing. */
    struct zcl_result wr_null_dir =
        ssio_write_sidecar_raw(NULL, &spec, 1, known_hash);
    SS_CHECK("write_sidecar_raw(NULL datadir) fails", !wr_null_dir.ok);
    struct zcl_result wr_null_hash =
        ssio_write_sidecar_raw(dir, &spec, 1, NULL);
    SS_CHECK("write_sidecar_raw(NULL body_sha3) fails", !wr_null_hash.ok);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── ssio_write_sidecar: the full hash-then-write pipeline ───────── */

static int case_write_sidecar_pipeline(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "write_pipeline");

    struct ssio_spec spec = {
        .body_name = "block_index.bin",
        .sidecar_name = "block_index.bin.sha3",
        .magic = "BIIX",
        .version = 2,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };

    char body_path[300];
    snprintf(body_path, sizeof(body_path), "%s/%s", dir, spec.body_name);

    /* No body on disk yet: stat() fails, ssio_write_sidecar reports error. */
    struct zcl_result wr_missing = ssio_write_sidecar(dir, &spec);
    SS_CHECK("write_sidecar fails when body is absent", !wr_missing.ok);

    /* Write a body, then let ssio_write_sidecar hash + persist the sidecar
     * in one call; the resulting sidecar must describe the ACTUAL body
     * bytes (cross-checked against ssio_hash_body run independently). */
    const char *body = "block index payload fixture bytes 0123456789";
    SS_CHECK("write body fixture",
             write_file(body_path, body, strlen(body)));

    uint8_t expected_hash[32];
    uint64_t expected_size = 0;
    SS_CHECK("independent hash_body succeeds",
             ssio_hash_body(dir, &spec, expected_hash, &expected_size));

    struct zcl_result wr = ssio_write_sidecar(dir, &spec);
    SS_CHECK("write_sidecar succeeds for a real body", wr.ok);

    struct ssio_sidecar_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    enum ssio_read_verdict v = ssio_read_sidecar(dir, &spec, &hdr);
    SS_CHECK("write_sidecar's own sidecar reads back OK",
             v == SSIO_READ_OK);
    SS_CHECK("write_sidecar's sidecar size matches the body",
             hdr.body_size == expected_size);
    SS_CHECK("write_sidecar's sidecar hash matches ssio_hash_body",
             memcmp(hdr.body_sha3, expected_hash, 32) == 0);
    SS_CHECK("write_sidecar's sidecar magic matches spec",
             memcmp(hdr.magic, spec.magic, 4) == 0);
    SS_CHECK("write_sidecar's sidecar version matches spec",
             hdr.version == spec.version);

    /* NULL datadir rejected up front. */
    struct zcl_result wr_null = ssio_write_sidecar(NULL, &spec);
    SS_CHECK("write_sidecar(NULL datadir) fails", !wr_null.ok);

    test_cleanup_tmpdir(dir);
    return failures;
}

int test_sha3_sidecar_io(void)
{
    printf("\n=== sha3_sidecar_io tests ===\n");
    int failures = 0;
    failures += case_hash_body();
    failures += case_sidecar_round_trip();
    failures += case_write_sidecar_pipeline();
    return failures;
}
