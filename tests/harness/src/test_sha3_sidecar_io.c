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
#include "event/event.h"
#include "platform/private_file.h"
#include "storage/sha3_sidecar_io.h"
#include "util/result.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

/* A failed create reports the exact cause: the destination directory is
 * absent, so the private create fails with ENOENT. */
static int case_write_sidecar_errno_reports_cause(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "errno_cause");

    struct ssio_spec spec = {
        .body_name = "block_index.bin",
        .sidecar_name = "block_index.bin.sha3",
        .magic = "BIIX",
        .version = 2,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };
    char missing[300];
    snprintf(missing, sizeof(missing), "%s/absent", dir);
    uint8_t sha[32] = {0};
    struct zcl_result wr = ssio_write_sidecar_raw(missing, &spec, 0, sha);
#if !defined(_WIN32)
    char want[64];
    snprintf(want, sizeof(want), "(errno %d)", ENOENT);
    SS_CHECK("write_sidecar create failure names private create and ENOENT",
             !wr.ok && strstr(wr.message, "private create") != NULL &&
             strstr(wr.message, want) != NULL);
#else
    SS_CHECK("write_sidecar create failure names private create and a cause",
             !wr.ok && strstr(wr.message, "private create") != NULL &&
             (strstr(wr.message, "(errno ") != NULL ||
              strstr(wr.message, "cause unavailable") != NULL));
#endif

    test_cleanup_tmpdir(dir);
    return failures;
}

#if !defined(_WIN32)
/* A non-empty directory squatting on the sidecar path makes the final
 * rename fail with EISDIR. The atomic-replace message (the Android symptom)
 * must carry that exact errno, and the staged .tmp must be removed. */
static int case_replace_failure_reports_errno_and_cleans_tmp(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "replace_eisdir");

    struct ssio_spec spec = {
        .body_name = "block_index.bin",
        .sidecar_name = "block_index.bin.sha3",
        .magic = "BIIX",
        .version = 2,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };
    char side[300];
    char tmp[310];
    snprintf(side, sizeof(side), "%s/block_index.bin.sha3", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", side);
    SS_CHECK("replace fixture: sidecar path is a directory",
             mkdir(side, 0700) == 0);
    char child[320];
    snprintf(child, sizeof(child), "%s/occupant", side);
    struct platform_private_file occupant;
    platform_private_file_init(&occupant);
    SS_CHECK("replace fixture: directory is non-empty",
             platform_private_file_create(child, &occupant));
    platform_private_file_close(&occupant);

    uint8_t sha[32] = {0};
    struct zcl_result wr = ssio_write_sidecar_raw(dir, &spec, 0, sha);
    char want[64];
    snprintf(want, sizeof(want), "(errno %d)", EISDIR);
    SS_CHECK("replace failure message names atomic replace",
             !wr.ok && strstr(wr.message, "atomic replace") != NULL);
    SS_CHECK("replace failure result code is -7", !wr.ok && wr.code == -7);
    SS_CHECK("replace failure message carries the exact EISDIR errno",
             !wr.ok && strstr(wr.message, want) != NULL);
    SS_CHECK("replace failure removes the staged .tmp file",
             platform_private_path_absent(tmp));

    test_rm_rf_recursive(dir);
    return failures;
}

#endif
#if !defined(_WIN32)
/* Replacing the staged path with a different file between create and
 * replace must be refused with ESTALE, and the destination must stay
 * absent. */
static int case_replace_identity_mismatch_is_estale(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "replace_estale");
    char staging[300];
    char dest[300];
    snprintf(staging, sizeof(staging), "%s/stage.bin", dir);
    snprintf(dest, sizeof(dest), "%s/dest.bin", dir);

    struct platform_private_file staged;
    platform_private_file_init(&staged);
    static const char other_bytes[] = "other-file";
    struct platform_private_file other;
    platform_private_file_init(&other);
    bool created = platform_private_file_create(staging, &staged);
    bool swapped = created &&
        platform_private_file_unlink_missing_ok(staging) &&
        platform_private_file_create(staging, &other) &&
        platform_private_file_write_at(&other, other_bytes,
                                       sizeof(other_bytes), 0) &&
        platform_private_file_flush(&other);
    platform_private_file_close(&other);
    errno = 0;
    bool replaced = swapped &&
        platform_private_file_replace(&staged, staging, dest);
    SS_CHECK("replace refuses a swapped staged path with ESTALE",
             swapped && !replaced && errno == ESTALE);
    SS_CHECK("replace leaves the destination absent after ESTALE",
             swapped && platform_private_path_absent(dest));
    platform_private_file_close(&staged);
    test_cleanup_tmpdir(dir);
    return failures;
}
#endif

#if !defined(_WIN32)

/* ── mutation-gap closers: embedded format, sidecar read refusals, error
 * codes, hash-body I/O error, quarantine ─────────────────────────────── */

static struct ssio_spec emb_spec(void)
{
    struct ssio_spec spec = {
        .body_name = "emb.dat",
        .sidecar_name = "emb.dat.sha3",
        .magic = "EMBD",
        .version = 7,
        .domain = "ssio_test",
        .malloc_label = "ssio_test_buf",
        .corrupt_event = 0,
    };
    return spec;
}

struct emb_payload {
    const uint8_t *bytes;
    size_t len;
    bool fail_after_write;
};

static bool emb_emit(FILE *f, void *ctx, uint64_t *out_size,
                     uint8_t out_sha3[32])
{
    const struct emb_payload *p = ctx;
    if (fwrite(p->bytes, 1, p->len, f) != p->len)
        return false;
    if (p->fail_after_write)
        return false;
    *out_size = p->len;
    independent_sha3(p->bytes, p->len, out_sha3);
    return true;
}

static void emb_fill(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(i * 31u + 7u);
}

static bool read_all(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    *len = fread(buf, 1, cap, f);
    fclose(f);
    return true;
}

/* Valid 1001-byte (odd) embedded file in <dir>/emb.dat. */
static bool emb_make(const char *dir, const struct ssio_spec *spec)
{
    uint8_t payload[1001];
    emb_fill(payload, sizeof(payload));
    struct emb_payload p = { payload, sizeof(payload), false };
    return ssio_write_embedded(dir, spec, emb_emit, &p).ok;
}

enum emb_tamper { EMB_FLIP, EMB_TRUNCATE, EMB_APPEND };

static enum ssio_read_verdict emb_tampered(const char *dir,
                                           const struct ssio_spec *spec,
                                           enum emb_tamper kind, size_t off)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/%s", dir, spec->body_name);
    uint8_t buf[1100];
    size_t len = 0;
    if (!emb_make(dir, spec) || !read_all(path, buf, sizeof(buf) - 1, &len))
        return SSIO_READ_UNREADABLE;
    if (kind == EMB_FLIP) buf[off] ^= 0x01;
    if (kind == EMB_TRUNCATE) len = off;
    if (kind == EMB_APPEND) buf[len++] = 0xAB;
    if (!write_file(path, buf, len))
        return SSIO_READ_UNREADABLE;
    return ssio_verify_embedded(dir, spec, NULL, NULL);
}

static int case_embedded_round_trip(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "emb_rt");
    struct ssio_spec spec = emb_spec();
    char body[300], side[300], tmp[310];
    snprintf(body, sizeof(body), "%s/emb.dat", dir);
    snprintf(side, sizeof(side), "%s/emb.dat.sha3", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", body);

    /* A legacy sidecar and a stale .tmp are present before the write. */
    SS_CHECK("emb: legacy sidecar fixture", write_file(side, "legacy", 6));
    SS_CHECK("emb: stale tmp fixture", write_file(tmp, "stale", 5));
    SS_CHECK("emb: write_embedded OK", emb_make(dir, &spec));
    SS_CHECK("emb: legacy sidecar removed",
             platform_private_path_absent(side));
    SS_CHECK("emb: tmp consumed by the rename",
             platform_private_path_absent(tmp));

    struct ssio_sidecar_header hdr;
    uint64_t off = 0;
    memset(&hdr, 0, sizeof(hdr));
    SS_CHECK("emb: verify OK",
             ssio_verify_embedded(dir, &spec, &hdr, &off) == SSIO_READ_OK);
    uint8_t payload[1001], want_sha[32];
    emb_fill(payload, sizeof(payload));
    independent_sha3(payload, sizeof(payload), want_sha);
    SS_CHECK("emb: header magic", memcmp(hdr.magic, "EMBD", 4) == 0);
    SS_CHECK("emb: header version", hdr.version == 7);
    SS_CHECK("emb: header size is the payload length", hdr.body_size == 1001);
    SS_CHECK("emb: header digest", memcmp(hdr.body_sha3, want_sha, 32) == 0);
    SS_CHECK("emb: payload offset is 48", off == 48);
    SS_CHECK("emb: verify tolerates NULL outputs",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_OK);

    uint8_t raw[1100];
    size_t raw_len = 0;
    SS_CHECK("emb: raw file read", read_all(body, raw, sizeof(raw), &raw_len));
    SS_CHECK("emb: file is header + payload", raw_len == 48 + 1001);
    struct ssio_sidecar_header exp;
    memset(&exp, 0, sizeof(exp));
    memcpy(exp.magic, "EMBD", 4);
    exp.version = 7;
    exp.body_size = 1001;
    memcpy(exp.body_sha3, want_sha, 32);
    SS_CHECK("emb: first 48 file bytes are exactly the expected header",
             raw_len >= 48 && memcmp(raw, &exp, 48) == 0);
    SS_CHECK("emb: payload follows the header at byte 48",
             raw_len >= 48 + 1001 && memcmp(raw + 48, payload, 1001) == 0);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_embedded_large_payload(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "emb_big");
    struct ssio_spec spec = emb_spec();
    size_t len = (1u << 20) + 7;
    uint8_t *big = zcl_malloc(len, "ssio_test_big_emb");
    SS_CHECK("emb big: alloc", big != NULL);
    if (big) {
        emb_fill(big, len);
        struct emb_payload p = { big, len, false };
        SS_CHECK("emb big: write OK",
                 ssio_write_embedded(dir, &spec, emb_emit, &p).ok);
        struct ssio_sidecar_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        SS_CHECK("emb big: verify OK across the 1 MiB window",
                 ssio_verify_embedded(dir, &spec, &hdr, NULL) ==
                     SSIO_READ_OK);
        SS_CHECK("emb big: header size", hdr.body_size == len);
        free(big);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

/* A torn, extended, corrupted or retargeted embedded file is never OK. */
static int case_embedded_tamper_is_stale(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "emb_tamper");
    struct ssio_spec spec = emb_spec();
    SS_CHECK("emb tamper: one byte short is STALE",
             emb_tampered(dir, &spec, EMB_TRUNCATE, 48 + 1000) ==
                 SSIO_READ_STALE);
    SS_CHECK("emb tamper: header only (empty payload) is STALE",
             emb_tampered(dir, &spec, EMB_TRUNCATE, 48) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: one byte long is STALE",
             emb_tampered(dir, &spec, EMB_APPEND, 0) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: first payload byte flipped is STALE",
             emb_tampered(dir, &spec, EMB_FLIP, 48) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: last payload byte flipped is STALE",
             emb_tampered(dir, &spec, EMB_FLIP, 48 + 1000) ==
                 SSIO_READ_STALE);
    SS_CHECK("emb tamper: first digest byte flipped is STALE",
             emb_tampered(dir, &spec, EMB_FLIP, 16) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: last digest byte flipped is STALE",
             emb_tampered(dir, &spec, EMB_FLIP, 47) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: declared size flipped is STALE",
             emb_tampered(dir, &spec, EMB_FLIP, 8) == SSIO_READ_STALE);
    SS_CHECK("emb tamper: last magic byte flipped is BAD_MAGIC",
             emb_tampered(dir, &spec, EMB_FLIP, 3) == SSIO_READ_BAD_MAGIC);
    SS_CHECK("emb tamper: first magic byte flipped is BAD_MAGIC",
             emb_tampered(dir, &spec, EMB_FLIP, 0) == SSIO_READ_BAD_MAGIC);
    SS_CHECK("emb tamper: version byte flipped is UNSUPPORTED",
             emb_tampered(dir, &spec, EMB_FLIP, 4) == SSIO_READ_UNSUPPORTED);

    SS_CHECK("emb tamper: fixture rebuilt", emb_make(dir, &spec));
    struct ssio_spec other_magic = spec;
    other_magic.magic = "XXXX";
    SS_CHECK("emb tamper: verify with another magic is BAD_MAGIC",
             ssio_verify_embedded(dir, &other_magic, NULL, NULL) ==
                 SSIO_READ_BAD_MAGIC);
    struct ssio_spec other_version = spec;
    other_version.version = 8;
    SS_CHECK("emb tamper: verify with another version is UNSUPPORTED",
             ssio_verify_embedded(dir, &other_version, NULL, NULL) ==
                 SSIO_READ_UNSUPPORTED);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Short files: under 4 bytes is legacy (BAD_MAGIC); exactly the magic, or a
 * magic plus a partial header, is torn embedded data (STALE). */
static int case_embedded_short_files(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "emb_short");
    struct ssio_spec spec = emb_spec();
    char body[300];
    snprintf(body, sizeof(body), "%s/emb.dat", dir);

    SS_CHECK("emb short: missing body is MISSING",
             ssio_verify_embedded(dir, &spec, NULL, NULL) ==
                 SSIO_READ_MISSING);
    write_file(body, "", 0);
    SS_CHECK("emb short: empty body is BAD_MAGIC (legacy)",
             ssio_verify_embedded(dir, &spec, NULL, NULL) ==
                 SSIO_READ_BAD_MAGIC);
    write_file(body, "EMB", 3);
    SS_CHECK("emb short: 3 bytes is BAD_MAGIC (legacy)",
             ssio_verify_embedded(dir, &spec, NULL, NULL) ==
                 SSIO_READ_BAD_MAGIC);
    write_file(body, "EMBD", 4);
    SS_CHECK("emb short: bare magic is STALE, not legacy",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_STALE);

    /* magic + a version that does NOT match, cut mid-header: truncated
     * outranks the version check. */
    uint8_t cut[20];
    memset(cut, 0, sizeof(cut));
    memcpy(cut, "EMBD", 4);
    cut[4] = 99;
    write_file(body, cut, sizeof(cut));
    SS_CHECK("emb short: truncated header with a bad version is STALE",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_STALE);
    cut[4] = 7;
    write_file(body, cut, sizeof(cut));
    SS_CHECK("emb short: truncated header with the right version is STALE",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_STALE);

    uint8_t full[48];
    memset(full, 0, sizeof(full));
    memcpy(full, "EMBD", 4);
    full[4] = 7;
    write_file(body, full, 47);
    SS_CHECK("emb short: 47-byte header is STALE",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_STALE);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* A datadir that is really a file makes every open fail with ENOTDIR: that
 * is UNREADABLE, never MISSING. */
static int case_unreadable_is_not_missing(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "unreadable");
    struct ssio_spec spec = emb_spec();
    char notdir[300];
    snprintf(notdir, sizeof(notdir), "%s/plainfile", dir);
    SS_CHECK("unreadable: plain file fixture",
             write_file(notdir, "x", 1));
    struct ssio_sidecar_header hdr;
    SS_CHECK("unreadable: embedded verify -> UNREADABLE",
             ssio_verify_embedded(notdir, &spec, NULL, NULL) ==
                 SSIO_READ_UNREADABLE);
    SS_CHECK("unreadable: sidecar read -> UNREADABLE",
             ssio_read_sidecar(notdir, &spec, &hdr) == SSIO_READ_UNREADABLE);
    test_cleanup_tmpdir(dir);
    return failures;
}

static struct ssio_sidecar_header side_hdr(uint32_t version)
{
    struct ssio_sidecar_header h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, "ADIX", 4);
    h.version = version;
    h.body_size = 5;
    return h;
}

/* A sidecar shorter than 48 bytes, or whose magic differs in any byte, is
 * never OK. */
static int case_sidecar_read_refusals(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "side_refuse");
    struct ssio_spec spec = {
        .body_name = "peers.dat", .sidecar_name = "peers.dat.sha3",
        .magic = "ADIX", .version = 3, .domain = "ssio_test",
        .malloc_label = "ssio_test_buf", .corrupt_event = 0,
    };
    char side[300];
    snprintf(side, sizeof(side), "%s/peers.dat.sha3", dir);
    struct ssio_sidecar_header good = side_hdr(3), got;

    write_file(side, "", 0);
    SS_CHECK("sidecar: empty file is STALE",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_STALE);
    write_file(side, &good, 20);
    SS_CHECK("sidecar: 20 bytes with valid magic+version is STALE",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_STALE);
    write_file(side, &good, 47);
    SS_CHECK("sidecar: 47 bytes is STALE",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_STALE);
    write_file(side, &good, 48);
    SS_CHECK("sidecar: exactly 48 bytes is OK",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_OK);

    struct ssio_sidecar_header bad = good;
    bad.magic[3] = 'Y';
    write_file(side, &bad, 48);
    SS_CHECK("sidecar: magic differing in the last byte is BAD_MAGIC",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_BAD_MAGIC);
    bad = good;
    bad.magic[0] = 'Z';
    write_file(side, &bad, 48);
    SS_CHECK("sidecar: magic differing in the first byte is BAD_MAGIC",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_BAD_MAGIC);
    bad = side_hdr(4);
    write_file(side, &bad, 48);
    SS_CHECK("sidecar: version 4 against spec 3 is UNSUPPORTED",
             ssio_read_sidecar(dir, &spec, &got) == SSIO_READ_UNSUPPORTED);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_error_codes_and_io_errors(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "codes");
    struct ssio_spec spec = emb_spec();
    uint8_t sha[32] = {0};
    char missing[300], body[300], stale[320];
    snprintf(missing, sizeof(missing), "%s/absent", dir);
    snprintf(body, sizeof(body), "%s/emb.dat", dir);
    snprintf(stale, sizeof(stale), "%s/emb.dat.sha3.tmp", dir);

    struct zcl_result r = ssio_write_sidecar_raw(NULL, &spec, 1, sha);
    SS_CHECK("codes: raw NULL datadir is -1", !r.ok && r.code == -1);
    r = ssio_write_sidecar_raw(dir, &spec, 1, NULL);
    SS_CHECK("codes: raw NULL sha is -1", !r.ok && r.code == -1);
    r = ssio_write_sidecar_raw(missing, &spec, 1, sha);
    SS_CHECK("codes: raw missing dir is -5", !r.ok && r.code == -5);
    r = ssio_write_sidecar(NULL, &spec);
    SS_CHECK("codes: pipeline NULL datadir is -1", !r.ok && r.code == -1);
    r = ssio_write_sidecar(dir, &spec);
    SS_CHECK("codes: pipeline missing body is -2", !r.ok && r.code == -2);

    /* A body path that is a directory stats fine but cannot be read. */
    SS_CHECK("codes: directory-as-body fixture", mkdir(body, 0700) == 0);
    uint8_t hash[32];
    uint64_t size = 12345;
    SS_CHECK("codes: hash_body on an unreadable body is false",
             !ssio_hash_body(dir, &spec, hash, &size));
    SS_CHECK("codes: failed hash_body leaves out_size untouched",
             size == 12345);
    r = ssio_write_sidecar(dir, &spec);
    SS_CHECK("codes: pipeline unreadable body is -3", !r.ok && r.code == -3);
    rmdir(body);

    /* A stale .tmp from a crashed earlier write does not block the next. */
    SS_CHECK("codes: stale sidecar tmp fixture", write_file(stale, "old", 3));
    r = ssio_write_sidecar_raw(dir, &spec, 9, sha);
    SS_CHECK("codes: raw write replaces a stale tmp", r.ok);
    SS_CHECK("codes: stale tmp gone after the write",
             platform_private_path_absent(stale));
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_embedded_write_failures(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "emb_fail");
    struct ssio_spec spec = emb_spec();
    uint8_t payload[64];
    emb_fill(payload, sizeof(payload));
    struct emb_payload good = { payload, sizeof(payload), false };
    struct emb_payload torn = { payload, sizeof(payload), true };
    char missing[300], body[300], tmp[310];
    snprintf(missing, sizeof(missing), "%s/absent", dir);
    snprintf(body, sizeof(body), "%s/emb.dat", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", body);

    struct zcl_result r = ssio_write_embedded(NULL, &spec, emb_emit, &good);
    SS_CHECK("emb fail: NULL datadir is -1", !r.ok && r.code == -1);
    r = ssio_write_embedded(dir, &spec, NULL, &good);
    SS_CHECK("emb fail: NULL emit is -1", !r.ok && r.code == -1);
    r = ssio_write_embedded(missing, &spec, emb_emit, &good);
    SS_CHECK("emb fail: missing datadir is -5", !r.ok && r.code == -5);

    SS_CHECK("emb fail: good body written", emb_make(dir, &spec));
    uint8_t before[1100], after[1100];
    size_t before_len = 0, after_len = 0;
    SS_CHECK("emb fail: body captured",
             read_all(body, before, sizeof(before), &before_len));
    r = ssio_write_embedded(dir, &spec, emb_emit, &torn);
    SS_CHECK("emb fail: a failed emit is -8", !r.ok && r.code == -8);
    SS_CHECK("emb fail: failed emit leaves no tmp",
             platform_private_path_absent(tmp));
    SS_CHECK("emb fail: failed emit leaves the old body byte-identical",
             read_all(body, after, sizeof(after), &after_len) &&
             after_len == before_len && memcmp(before, after, after_len) == 0);
    SS_CHECK("emb fail: old body still verifies",
             ssio_verify_embedded(dir, &spec, NULL, NULL) == SSIO_READ_OK);

    /* A non-empty directory squatting on the body path fails the rename. */
    unlink(body);
    char child[320];
    snprintf(child, sizeof(child), "%s/occupant", body);
    SS_CHECK("emb fail: directory squatter", mkdir(body, 0700) == 0 &&
             write_file(child, "x", 1));
    r = ssio_write_embedded(dir, &spec, emb_emit, &good);
    SS_CHECK("emb fail: a failed rename is -7", !r.ok && r.code == -7);
    SS_CHECK("emb fail: failed rename leaves no tmp",
             platform_private_path_absent(tmp));
    test_rm_rf_recursive(dir);
    return failures;
}

/* ── quarantine ────────────────────────────────────────────────────── */

struct q_seen {
    int count;
    uint32_t peer_id;
    char payload[160];
};

static void q_observer(enum event_type type, uint32_t peer_id,
                       const void *payload, uint32_t len, void *ctx)
{
    (void)type;
    struct q_seen *s = ctx;
    s->count++;
    s->peer_id = peer_id;
    size_t n = len < sizeof(s->payload) - 1 ? len : sizeof(s->payload) - 1;
    if (payload) memcpy(s->payload, payload, n);
    s->payload[n] = '\0';
}

/* Count entries in `dir` starting with `prefix`; copy the first one's tail
 * (after the prefix) into `suffix`. */
static int q_find(const char *dir, const char *prefix, char *suffix,
                  size_t cap)
{
    int found = 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) != 0) continue;
        if (found == 0) snprintf(suffix, cap, "%s", e->d_name + strlen(prefix));
        found++;
    }
    closedir(d);
    return found;
}

static int case_quarantine_renames_both(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssio", "quarantine");
    struct ssio_spec spec = {
        .body_name = "body.dat", .sidecar_name = "body.dat.sha3",
        .magic = "TEST", .version = 1, .domain = "ssio_test",
        .malloc_label = "ssio_test_buf", .corrupt_event = EV_ADDRMAN_CORRUPT,
    };
    struct q_seen seen;
    memset(&seen, 0, sizeof(seen));
    event_clear_observers(EV_ADDRMAN_CORRUPT);
    SS_CHECK("quarantine: observer registered",
             event_observe(EV_ADDRMAN_CORRUPT, q_observer, &seen));

    char body[300], side[300];
    snprintf(body, sizeof(body), "%s/body.dat", dir);
    snprintf(side, sizeof(side), "%s/body.dat.sha3", dir);
    SS_CHECK("quarantine: fixtures",
             write_file(body, "BODYBYTES", 9) && write_file(side, "SIDE", 4));
    ssio_quarantine(dir, &spec, "stale");
    SS_CHECK("quarantine: body moved aside", platform_private_path_absent(body));
    SS_CHECK("quarantine: sidecar moved aside",
             platform_private_path_absent(side));
    char ts_body[64] = "", ts_side[64] = "";
    SS_CHECK("quarantine: one body.corrupt.<ts>",
             q_find(dir, "body.dat.corrupt.", ts_body, sizeof(ts_body)) == 1);
    SS_CHECK("quarantine: one sidecar.corrupt.<ts>",
             q_find(dir, "body.dat.sha3.corrupt.", ts_side,
                    sizeof(ts_side)) == 1);
    SS_CHECK("quarantine: both carry the same non-empty timestamp",
             ts_body[0] != '\0' && strcmp(ts_body, ts_side) == 0);

    char moved[400], bytes[16] = "";
    size_t n = 0;
    snprintf(moved, sizeof(moved), "%s/body.dat.corrupt.%s", dir, ts_body);
    SS_CHECK("quarantine: body bytes preserved",
             read_all(moved, (uint8_t *)bytes, sizeof(bytes) - 1, &n) &&
             n == 9 && memcmp(bytes, "BODYBYTES", 9) == 0);
    char want[120];
    snprintf(want, sizeof(want), "verdict=stale ts=%s", ts_body);
    SS_CHECK("quarantine: exactly one event", seen.count == 1);
    SS_CHECK("quarantine: event carries verdict and ts", 
             strcmp(seen.payload, want) == 0);
    SS_CHECK("quarantine: event is not tied to a peer", seen.peer_id == 0);

    /* NULL datadir: nothing happens, nothing is emitted. */
    ssio_quarantine(NULL, &spec, "stale");
    SS_CHECK("quarantine: NULL datadir emits nothing", seen.count == 1);

    /* Only a body present: only the body moves. */
    struct ssio_spec solo = spec;
    solo.body_name = "solo.dat";
    solo.sidecar_name = "solo.dat.sha3";
    char solo_body[300];
    snprintf(solo_body, sizeof(solo_body), "%s/solo.dat", dir);
    SS_CHECK("quarantine: solo fixture", write_file(solo_body, "S", 1));
    ssio_quarantine(dir, &solo, "missing_sidecar");
    char tail[64] = "";
    SS_CHECK("quarantine: solo body moved",
             platform_private_path_absent(solo_body) &&
             q_find(dir, "solo.dat.corrupt.", tail, sizeof(tail)) == 1);
    SS_CHECK("quarantine: no sidecar file invented",
             q_find(dir, "solo.dat.sha3", tail, sizeof(tail)) == 0);
    SS_CHECK("quarantine: event still emitted for the solo call",
             seen.count == 2);

    event_clear_observers(EV_ADDRMAN_CORRUPT);
    test_cleanup_tmpdir(dir);
    return failures;
}

#endif /* !_WIN32 */

int test_sha3_sidecar_io(void)
{
    printf("\n=== sha3_sidecar_io tests ===\n");
    int failures = 0;
    failures += case_hash_body();
    failures += case_sidecar_round_trip();
    failures += case_write_sidecar_pipeline();
    failures += case_write_sidecar_errno_reports_cause();
#if !defined(_WIN32)
    failures += case_replace_failure_reports_errno_and_cleans_tmp();
#endif
#if !defined(_WIN32)
    failures += case_replace_identity_mismatch_is_estale();
    failures += case_embedded_round_trip();
    failures += case_embedded_large_payload();
    failures += case_embedded_tamper_is_stale();
    failures += case_embedded_short_files();
    failures += case_unreadable_is_not_missing();
    failures += case_sidecar_read_refusals();
    failures += case_error_codes_and_io_errors();
    failures += case_embedded_write_failures();
    failures += case_quarantine_renames_both();
#endif
    return failures;
}
