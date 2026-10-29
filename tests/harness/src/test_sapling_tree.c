/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling incremental-merkle-tree checkpoint round-trip.
 *
 * Covers the new sapling_tree_flush_checkpoint / sapling_tree_load_checkpoint
 * flat-file path that replaces the 2.6M-block replay on crash recovery.
 * Round-trip equivalence, delta-replay root equivalence, and corruption
 * fall-back are all here. */

#include "test/test_core.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "validation/main_state.h"

static void fill_hash(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx + i));
}

static void build_tree_with(size_t n, struct incremental_merkle_tree *t_out)
{
    sapling_tree_init(t_out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        fill_hash(&cm, 0xA5, i);
        incremental_tree_append(t_out, &cm);
    }
}

static bool trees_equal_by_root(const struct incremental_merkle_tree *a,
                                const struct incremental_merkle_tree *b)
{
    struct uint256 ra, rb;
    incremental_tree_root(a, &ra);
    incremental_tree_root(b, &rb);
    return memcmp(ra.data, rb.data, 32) == 0;
}

static int sapling_tree_round_trip_case(void)
{
    int failures = 0;
    char path[128];

    printf("sapling_tree checkpoint round-trip (flush then load) ... ");
    {
        strcpy(path, "/tmp/zcl_sapling_ckpt_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) {
            printf("FAIL (mkstemp)\n");
            failures++;
            goto done_round_trip;
        }
        close(fd);
        unlink(path); /* make_checkpoint writes fresh */

        struct incremental_merkle_tree src;
        build_tree_with(137, &src);

        bool ok_flush = sapling_tree_flush_checkpoint(&src, 512345, NULL, path);
        if (!ok_flush) {
            printf("FAIL (flush)\n");
            failures++;
            unlink(path);
            goto done_round_trip;
        }

        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        bool ok_load = sapling_tree_load_checkpoint(&dst, &got_h, NULL, path);
        if (!ok_load) {
            printf("FAIL (load)\n");
            failures++;
            unlink(path);
            goto done_round_trip;
        }
        if (got_h != 512345) {
            printf("FAIL (height mismatch: got %lld)\n", (long long)got_h);
            failures++;
            unlink(path);
            goto done_round_trip;
        }
        if (!trees_equal_by_root(&src, &dst)) {
            printf("FAIL (root mismatch)\n");
            failures++;
            unlink(path);
            goto done_round_trip;
        }
        if (incremental_tree_size(&dst) != incremental_tree_size(&src)) {
            printf("FAIL (size mismatch)\n");
            failures++;
            unlink(path);
            goto done_round_trip;
        }
        unlink(path);
        printf("OK\n");
done_round_trip:;
    }
    return failures;
}

static int sapling_tree_delta_replay_case(void)
{
    int failures = 0;
    char path[128];

    printf("sapling_tree checkpoint + delta-replay root equivalence ... ");
    {
        /* Build a 200-leaf chain. Checkpoint at 100, then replay 101..200
         * against the loaded checkpoint. Full-replay from 0..200 must
         * produce the same root. */
        strcpy(path, "/tmp/zcl_sapling_delta_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) {
            printf("FAIL (mkstemp)\n");
            failures++;
            goto done_delta;
        }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree at100;
        sapling_tree_init(&at100);
        for (size_t i = 0; i < 100; i++) {
            struct uint256 cm;
            fill_hash(&cm, 0x7C, i);
            incremental_tree_append(&at100, &cm);
        }

        if (!sapling_tree_flush_checkpoint(&at100, 100, NULL, path)) {
            printf("FAIL (flush at 100)\n");
            failures++;
            unlink(path);
            goto done_delta;
        }

        /* Full-replay reference */
        struct incremental_merkle_tree full;
        sapling_tree_init(&full);
        for (size_t i = 0; i < 200; i++) {
            struct uint256 cm;
            fill_hash(&cm, 0x7C, i);
            incremental_tree_append(&full, &cm);
        }

        /* Load checkpoint, delta-replay 100..199 */
        struct incremental_merkle_tree delta;
        sapling_tree_init(&delta);
        int64_t ckpt_h = 0;
        if (!sapling_tree_load_checkpoint(&delta, &ckpt_h, NULL, path)) {
            printf("FAIL (load)\n");
            failures++;
            unlink(path);
            goto done_delta;
        }
        if (ckpt_h != 100) {
            printf("FAIL (ckpt height)\n");
            failures++;
            unlink(path);
            goto done_delta;
        }
        for (size_t i = 100; i < 200; i++) {
            struct uint256 cm;
            fill_hash(&cm, 0x7C, i);
            incremental_tree_append(&delta, &cm);
        }

        bool eq = trees_equal_by_root(&full, &delta);
        if (!eq) {
            printf("FAIL (delta-replay root diverges from full-replay)\n");
            failures++;
            unlink(path);
            goto done_delta;
        }
        if (incremental_tree_size(&delta) != 200) {
            printf("FAIL (delta size != 200)\n");
            failures++;
            unlink(path);
            goto done_delta;
        }
        unlink(path);
        printf("OK\n");
done_delta:;
    }
    return failures;
}

static int sapling_tree_corruption_case(void)
{
    int failures = 0;
    char path[128];

    printf("sapling_tree checkpoint corruption detected on load ... ");
    {
        strcpy(path, "/tmp/zcl_sapling_corrupt_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) {
            printf("FAIL (mkstemp)\n");
            failures++;
            goto done_corrupt;
        }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree src;
        build_tree_with(50, &src);
        if (!sapling_tree_flush_checkpoint(&src, 777, NULL, path)) {
            printf("FAIL (flush)\n");
            failures++;
            unlink(path);
            goto done_corrupt;
        }

        /* Flip a bit in the middle of the file to trigger SHA3 tamper
         * detection on load. */
        FILE *f = fopen(path, "r+b");
        if (!f) {
            printf("FAIL (reopen)\n");
            failures++;
            unlink(path);
            goto done_corrupt;
        }
        fseek(f, 32, SEEK_SET); /* somewhere past the header */
        uint8_t b;
        size_t r = fread(&b, 1, 1, f);
        if (r != 1) {
            printf("FAIL (fread)\n");
            failures++;
            fclose(f);
            unlink(path);
            goto done_corrupt;
        }
        b ^= 0x01;
        fseek(f, 32, SEEK_SET);
        fwrite(&b, 1, 1, f);
        fclose(f);

        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        bool ok = sapling_tree_load_checkpoint(&dst, &got_h, NULL, path);
        if (ok) {
            printf("FAIL (tampered file loaded successfully)\n");
            failures++;
        } else {
            printf("OK\n");
        }
        unlink(path);
done_corrupt:;
    }
    return failures;
}

static int sapling_tree_missing_file_case(void)
{
    int failures = 0;

    printf("sapling_tree checkpoint missing file returns false ... ");
    {
        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        bool ok = sapling_tree_load_checkpoint(&dst, &got_h, NULL,
            "/tmp/zcl_sapling_definitely_does_not_exist_12345");
        if (ok) {
            printf("FAIL (loaded from missing file)\n");
            failures++;
        } else {
            printf("OK\n");
        }
    }
    return failures;
}

static int sapling_tree_load_speed_case(void)
{
    int failures = 0;
    char path[128];

    printf("sapling_tree checkpoint load is <1s for 10k leaves ... ");
    {
        /* The load path has to stay cheap enough that boot-to-ready
         * hits the target. Build a 10K-leaf tree (larger than
         * the real Sapling working set typically observed at the
         * commit boundary), flush, and assert load returns in <1s.
         * Full-replay takes minutes; 1s is a comfortable upper bound. */
        strcpy(path, "/tmp/zcl_sapling_speed_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) {
            printf("FAIL (mkstemp)\n");
            failures++;
            goto done_speed;
        }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree big;
        build_tree_with(10000, &big);
        if (!sapling_tree_flush_checkpoint(&big, 123456, NULL, path)) {
            printf("FAIL (flush)\n");
            failures++;
            unlink(path);
            goto done_speed;
        }

        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = 0;
        int64_t t0 = GetTimeMillis();
        bool ok = sapling_tree_load_checkpoint(&dst, &got_h, NULL, path);
        int64_t elapsed_ms = GetTimeMillis() - t0;
        unlink(path);

        if (!ok) {
            printf("FAIL (load)\n");
            failures++;
        } else if (elapsed_ms >= 1000) {
            printf("FAIL (load took %lld ms, expected <1000)\n",
                   (long long)elapsed_ms);
            failures++;
        } else if (!trees_equal_by_root(&big, &dst)) {
            printf("FAIL (root mismatch after fast load)\n");
            failures++;
        } else {
            printf("OK (%lld ms)\n", (long long)elapsed_ms);
        }
done_speed:;
    }
    return failures;
}

/* ---- Branch rows pinning sapling_tree_flush_checkpoint,
 * sapling_tree_load_checkpoint and incremental_witness_root as they behave
 * today. The expected bytes are the on-disk layout the source writes:
 * magic[0..3] version[4..7] height[8..15] root[16..47] blockhash[48..79]
 * treesize[80..83] bloblen[84..87] blob[88..] then a SHA3-256 trailer over
 * everything before it. */

#define CKT_HDR_SZ 88u
#define CKT_TRAILER_SZ 32u
#define CKT_MAX_BLOB (64u * 1024u)
#define CKT_OFF_VERSION 4u
#define CKT_OFF_HEIGHT 8u
#define CKT_OFF_ROOT 16u
#define CKT_OFF_BLOCKHASH 48u
#define CKT_OFF_TREESIZE 80u
#define CKT_OFF_BLOBLEN 84u
#define CKT_PATH_BUF 1024
#define CKT_ALT_BUF 1200

typedef void (*ckt_hdr_edit)(uint8_t hdr[CKT_HDR_SZ]);

struct ckt_ctx {
    char dir[CKT_PATH_BUF];
    char file[CKT_PATH_BUF];
    char alt[CKT_ALT_BUF];
};

static void ckt_report(const char *label, bool ok, int *failures)
{
    printf("%s ... %s\n", label, ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

static bool ckt_ctx_init(struct ckt_ctx *c, const char *tag)
{
    test_make_tmpdir(c->dir, sizeof(c->dir), "sapling_tree_rows", tag);
    int w1 = snprintf(c->file, sizeof(c->file), "%s/ckpt.dat", c->dir);
    int w2 = snprintf(c->alt, sizeof(c->alt), "%s/alt.dat", c->dir);
    return w1 > 0 && (size_t)w1 < sizeof(c->file) &&
           w2 > 0 && (size_t)w2 < sizeof(c->alt);
}

static uint32_t ckt_get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t ckt_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static void ckt_put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static bool ckt_absent(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return false;
    }
    return true;
}

/* Whole-file read into a fresh buffer; NULL on any failure. Caller frees. */
static uint8_t *ckt_slurp(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = NULL;
    long sz = -1;
    if (fseek(f, 0, SEEK_END) == 0)
        sz = ftell(f);
    if (sz >= 0 && fseek(f, 0, SEEK_SET) == 0) {
        buf = malloc((size_t)sz + 1);
        if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    if (buf)
        *len_out = (size_t)sz;
    return buf;
}

static bool ckt_write_bytes(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = (len == 0) || (fwrite(buf, 1, len, f) == len);
    return fclose(f) == 0 && ok;
}

static bool ckt_write_zeros(const char *path, size_t len)
{
    uint8_t *z = calloc(len ? len : 1, 1);
    if (!z)
        return false;
    bool ok = ckt_write_bytes(path, z, len);
    free(z);
    return ok;
}

/* Header + blob + fresh SHA3 trailer, so the integrity check passes and only
 * the field under test decides the load. */
static bool ckt_write_sealed(const char *path, const uint8_t hdr[CKT_HDR_SZ],
                             const uint8_t *blob, size_t blob_len)
{
    size_t body_sz = CKT_HDR_SZ + blob_len;
    uint8_t *file = malloc(body_sz + CKT_TRAILER_SZ);
    if (!file)
        return false;
    memcpy(file, hdr, CKT_HDR_SZ);
    if (blob_len)
        memcpy(file + CKT_HDR_SZ, blob, blob_len);
    zcl_sha3_256(file, body_sz, file + body_sz);
    bool ok = ckt_write_bytes(path, file, body_sz + CKT_TRAILER_SZ);
    free(file);
    return ok;
}

/* Split a flushed file into its 88-byte header and blob (trailer dropped). */
static bool ckt_read_parts(const char *path, uint8_t hdr[CKT_HDR_SZ],
                           uint8_t **blob, size_t *blob_len)
{
    size_t len = 0;
    uint8_t *buf = ckt_slurp(path, &len);
    if (!buf)
        return false;
    bool ok = len >= CKT_HDR_SZ + CKT_TRAILER_SZ;
    if (ok) {
        memcpy(hdr, buf, CKT_HDR_SZ);
        *blob_len = len - CKT_HDR_SZ - CKT_TRAILER_SZ;
        *blob = malloc(*blob_len + 1);
        ok = (*blob != NULL);
        if (ok)
            memcpy(*blob, buf + CKT_HDR_SZ, *blob_len);
    }
    free(buf);
    return ok;
}

/* Rewrite src as dst with `edit` applied to the header, and the blob replaced
 * by `blob` when replace_blob. Always resealed. */
static bool ckt_edit_write(const char *src, const char *dst, ckt_hdr_edit edit,
                           bool replace_blob, const uint8_t *blob,
                           size_t blob_len)
{
    uint8_t hdr[CKT_HDR_SZ];
    uint8_t *old_blob = NULL;
    size_t old_len = 0;
    if (!ckt_read_parts(src, hdr, &old_blob, &old_len))
        return false;
    edit(hdr);
    bool ok = replace_blob ? ckt_write_sealed(dst, hdr, blob, blob_len)
                           : ckt_write_sealed(dst, hdr, old_blob, old_len);
    free(old_blob);
    return ok;
}

/* Flip one byte of src (body byte 32, or the trailer's last byte) into dst,
 * without resealing. */
static bool ckt_flip_copy(const char *src, const char *dst, bool trailer)
{
    size_t len = 0;
    uint8_t *buf = ckt_slurp(src, &len);
    if (!buf || len <= CKT_HDR_SZ + CKT_TRAILER_SZ) {
        free(buf);
        return false;
    }
    buf[trailer ? len - 1 : 32] ^= 0x01;
    bool ok = ckt_write_bytes(dst, buf, len);
    free(buf);
    return ok;
}

static bool ckt_hash_is(const uint8_t *got, const uint8_t *want)
{
    static const uint8_t zeros[32] = {0};
    return memcmp(got, want ? want : zeros, 32) == 0;
}

/* A file on disk must be exactly what flush writes for (t, height, hash):
 * magic, version, height, root, blockhash (zeros when hash is NULL), treesize,
 * bloblen, and a SHA3 trailer over the body. */
static bool ckt_check_layout(const char *path,
                             const struct incremental_merkle_tree *t,
                             int64_t height, const uint8_t *hash)
{
    size_t len = 0;
    uint8_t *buf = ckt_slurp(path, &len);
    if (!buf)
        return false;
    if (len <= CKT_HDR_SZ + CKT_TRAILER_SZ) {
        free(buf);
        return false;
    }
    size_t body_sz = len - CKT_TRAILER_SZ;
    struct uint256 root;
    incremental_tree_root(t, &root);
    uint8_t trailer[CKT_TRAILER_SZ];
    zcl_sha3_256(buf, body_sz, trailer);
    bool ok = memcmp(buf, "SPLT", 4) == 0 &&
              ckt_get_u32(buf + CKT_OFF_VERSION) == 2u &&
              ckt_get_u64(buf + CKT_OFF_HEIGHT) == (uint64_t)height &&
              memcmp(buf + CKT_OFF_ROOT, root.data, 32) == 0 &&
              ckt_hash_is(buf + CKT_OFF_BLOCKHASH, hash) &&
              ckt_get_u32(buf + CKT_OFF_TREESIZE) ==
                  (uint32_t)incremental_tree_size(t) &&
              ckt_get_u32(buf + CKT_OFF_BLOBLEN) == body_sz - CKT_HDR_SZ &&
              memcmp(buf + body_sz, trailer, CKT_TRAILER_SZ) == 0;
    free(buf);
    return ok;
}

/* The loader refused the file and left the caller's 5-leaf tree untouched. */
static bool ckt_load_keeps_tree(const char *path)
{
    struct incremental_merkle_tree dst;
    build_tree_with(5, &dst);
    struct uint256 before, after;
    incremental_tree_root(&dst, &before);
    int64_t h = -1;
    bool loaded = sapling_tree_load_checkpoint(&dst, &h, NULL, path);
    incremental_tree_root(&dst, &after);
    return !loaded && incremental_tree_size(&dst) == 5 &&
           memcmp(before.data, after.data, 32) == 0;
}

static void ckt_ed_bad_magic(uint8_t hdr[CKT_HDR_SZ])
{
    hdr[0] = (uint8_t)'X';
}

static void ckt_ed_version_1(uint8_t hdr[CKT_HDR_SZ])
{
    ckt_put_u32(hdr + CKT_OFF_VERSION, 1u);
}

static void ckt_ed_root_flip(uint8_t hdr[CKT_HDR_SZ])
{
    hdr[CKT_OFF_ROOT] ^= 0x01;
}

static void ckt_ed_bloblen_plus_one(uint8_t hdr[CKT_HDR_SZ])
{
    ckt_put_u32(hdr + CKT_OFF_BLOBLEN,
                ckt_get_u32(hdr + CKT_OFF_BLOBLEN) + 1u);
}

static void ckt_ed_bloblen_over_max(uint8_t hdr[CKT_HDR_SZ])
{
    ckt_put_u32(hdr + CKT_OFF_BLOBLEN, CKT_MAX_BLOB + 1u);
}

static void ckt_ed_bloblen_three(uint8_t hdr[CKT_HDR_SZ])
{
    ckt_put_u32(hdr + CKT_OFF_BLOBLEN, 3u);
}

static void ckt_ed_noop(uint8_t hdr[CKT_HDR_SZ])
{
    (void)hdr;
}

static int ckt_row_flush_refusals(void)
{
    struct ckt_ctx c;
    struct incremental_merkle_tree t;
    int f = 0;
    if (!ckt_ctx_init(&c, "refusals")) {
        ckt_report("flush refusal fixture paths fit", false, &f);
        return f;
    }
    build_tree_with(3, &t);

    ckt_report("flush NULL tree refused, no file written",
               !sapling_tree_flush_checkpoint(NULL, 1, NULL, c.file) &&
                   ckt_absent(c.file),
               &f);
    ckt_report("flush NULL path refused",
               !sapling_tree_flush_checkpoint(&t, 1, NULL, NULL), &f);

    char missing[CKT_PATH_BUF + 64];
    int w = snprintf(missing, sizeof(missing), "%s/no_such_dir/ckpt.dat",
                     c.dir);
    ckt_report("flush into missing directory refused, no file written",
               w > 0 && (size_t)w < sizeof(missing) &&
                   !sapling_tree_flush_checkpoint(&t, 1, NULL, missing) &&
                   ckt_absent(missing),
               &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_flush_layout(void)
{
    struct ckt_ctx c;
    struct incremental_merkle_tree t;
    int f = 0;
    if (!ckt_ctx_init(&c, "layout")) {
        ckt_report("flush layout fixture paths fit", false, &f);
        return f;
    }
    build_tree_with(137, &t);

    bool ok_null = sapling_tree_flush_checkpoint(&t, 700000, NULL, c.file) &&
                   ckt_check_layout(c.file, &t, 700000, NULL);
    ckt_report("flush NULL block hash writes zero blockhash field", ok_null,
               &f);

    uint8_t hash[32];
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)(0x11 + i);
    bool ok_hash = sapling_tree_flush_checkpoint(&t, -7, hash, c.file) &&
                   ckt_check_layout(c.file, &t, -7, hash);
    ckt_report("flush copies block hash and writes negative height", ok_hash,
               &f);

    struct incremental_merkle_tree a, b;
    build_tree_with(10, &a);
    build_tree_with(20, &b);
    bool ok_first = sapling_tree_flush_checkpoint(&a, 10, NULL, c.file);
    bool ok_second = sapling_tree_flush_checkpoint(&b, 20, NULL, c.file) &&
                     ckt_check_layout(c.file, &b, 20, NULL);
    ckt_report("second flush replaces the first file atomically",
               ok_first && ok_second, &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_load_args_and_missing(void)
{
    struct ckt_ctx c;
    struct incremental_merkle_tree src, dst;
    int f = 0;
    if (!ckt_ctx_init(&c, "args")) {
        ckt_report("load args fixture paths fit", false, &f);
        return f;
    }
    build_tree_with(9, &src);
    sapling_tree_init(&dst);
    int64_t h = -1;
    bool flushed = sapling_tree_flush_checkpoint(&src, 42, NULL, c.file);

    ckt_report("load NULL tree refused",
               flushed && !sapling_tree_load_checkpoint(NULL, &h, NULL, c.file),
               &f);
    ckt_report("load NULL path refused",
               !sapling_tree_load_checkpoint(&dst, &h, NULL, NULL), &f);
    ckt_report("load missing file is a silent not-found",
               !sapling_tree_load_checkpoint(&dst, &h, NULL,
                                             "/nonexistent_dir_ckt/x.dat"),
               &f);
    ckt_report("load with NULL out-params succeeds",
               flushed &&
                   sapling_tree_load_checkpoint(&dst, NULL, NULL, c.file) &&
                   incremental_tree_size(&dst) == 9,
               &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_load_file_size(void)
{
    struct ckt_ctx c;
    int f = 0;
    if (!ckt_ctx_init(&c, "size")) {
        ckt_report("load size fixture paths fit", false, &f);
        return f;
    }
    ckt_report("load refuses a 10-byte file (below header+trailer)",
               ckt_write_zeros(c.alt, 10) && ckt_load_keeps_tree(c.alt), &f);
    ckt_report("load refuses 120 zero bytes (minimum size, bad trailer)",
               ckt_write_zeros(c.alt, CKT_HDR_SZ + CKT_TRAILER_SZ) &&
                   ckt_load_keeps_tree(c.alt),
               &f);
    ckt_report("load refuses one byte over header+max blob+trailer",
               ckt_write_zeros(c.alt, CKT_HDR_SZ + CKT_MAX_BLOB +
                                          CKT_TRAILER_SZ + 1) &&
                   ckt_load_keeps_tree(c.alt),
               &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_load_integrity(void)
{
    struct ckt_ctx c;
    struct incremental_merkle_tree src, dst;
    int f = 0;
    if (!ckt_ctx_init(&c, "integrity")) {
        ckt_report("load integrity fixture paths fit", false, &f);
        return f;
    }
    build_tree_with(40, &src);
    bool flushed = sapling_tree_flush_checkpoint(&src, 4242, NULL, c.file);
    ckt_report("flush writes the documented layout for a 40-leaf tree",
               flushed && ckt_check_layout(c.file, &src, 4242, NULL), &f);

    ckt_report("load refuses a flipped trailer byte",
               ckt_flip_copy(c.file, c.alt, true) && ckt_load_keeps_tree(c.alt),
               &f);
    ckt_report("load refuses a flipped body byte (SHA3 mismatch)",
               ckt_flip_copy(c.file, c.alt, false) &&
                   ckt_load_keeps_tree(c.alt),
               &f);

    build_tree_with(5, &dst);
    int64_t h = -1;
    ckt_report("control: resealed unmodified file loads",
               ckt_edit_write(c.file, c.alt, ckt_ed_noop, false, NULL, 0) &&
                   sapling_tree_load_checkpoint(&dst, &h, NULL, c.alt) &&
                   h == 4242 && incremental_tree_size(&dst) == 40,
               &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_load_resealed_headers(void)
{
    static const struct {
        const char *label;
        ckt_hdr_edit edit;
    } rows[] = {
        {"load refuses resealed bad magic", ckt_ed_bad_magic},
        {"load refuses resealed version 1", ckt_ed_version_1},
        {"load refuses resealed root mismatch", ckt_ed_root_flip},
        {"load refuses resealed bloblen one above real length",
         ckt_ed_bloblen_plus_one},
        {"load refuses resealed bloblen above max blob",
         ckt_ed_bloblen_over_max},
    };
    struct ckt_ctx c;
    int f = 0;
    if (!ckt_ctx_init(&c, "headers")) {
        ckt_report("load header fixture paths fit", false, &f);
        return f;
    }
    struct incremental_merkle_tree src;
    build_tree_with(40, &src);
    if (!sapling_tree_flush_checkpoint(&src, 4242, NULL, c.file)) {
        ckt_report("load header fixture flush", false, &f);
        return f;
    }
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        bool wrote = ckt_edit_write(c.file, c.alt, rows[i].edit, false,
                                    NULL, 0);
        ckt_report(rows[i].label, wrote && ckt_load_keeps_tree(c.alt), &f);
    }
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_load_blob_parse(void)
{
    /* Blob {disc_left=0, disc_right=0, compact_size 33} claims 33 parents, past
     * MAX_TREE_DEPTH (32), so deserialize refuses it. */
    static const uint8_t bad_blob[3] = {0x00, 0x00, 0x21};
    struct ckt_ctx c;
    struct incremental_merkle_tree src;
    int f = 0;
    if (!ckt_ctx_init(&c, "blob")) {
        ckt_report("load blob fixture paths fit", false, &f);
        return f;
    }
    build_tree_with(40, &src);
    if (!sapling_tree_flush_checkpoint(&src, 4242, NULL, c.file)) {
        ckt_report("load blob fixture flush", false, &f);
        return f;
    }
    ckt_report("load refuses a resealed blob with 33 parents (deserialize)",
               ckt_edit_write(c.file, c.alt, ckt_ed_bloblen_three, true,
                              bad_blob, sizeof(bad_blob)) &&
                   ckt_load_keeps_tree(c.alt),
               &f);
    test_rm_rf_recursive(c.dir);
    return f;
}

static int ckt_row_witness_root(void)
{
    /* Same positions and leaves as test_merkle_tree's witness-path case: a
     * witness started after leaf k and kept in sync must root at the tree. */
    static const size_t positions[] = {1,  2,  3,  4,  7,  8,
                                       15, 16, 31, 32, 63, 64};
    enum { N_POS = 12, N_LEAVES = 65 };
    int f = 0;
    struct incremental_merkle_tree t;
    struct incremental_witness w[N_POS];
    bool started[N_POS] = {false};
    sapling_tree_init(&t);
    for (size_t i = 0; i < N_LEAVES; i++) {
        struct uint256 cm;
        memset(cm.data, 0, sizeof(cm.data));
        cm.data[0] = (uint8_t)(i & 0xff);
        incremental_tree_append(&t, &cm);
        for (size_t j = 0; j < N_POS; j++) {
            if (started[j])
                incremental_witness_append(&w[j], &cm);
            if (i + 1 == positions[j]) {
                incremental_witness_init(&w[j], &t);
                started[j] = true;
            }
        }
    }
    struct uint256 tree_root;
    incremental_tree_root(&t, &tree_root);
    for (size_t j = 0; j < N_POS; j++) {
        struct uint256 wr;
        incremental_witness_root(&w[j], &wr);
        char label[96];
        (void)snprintf(label, sizeof(label),
                       "witness root equals tree root (start leaf %zu of 65)",
                       positions[j]);
        ckt_report(label, memcmp(wr.data, tree_root.data, 32) == 0, &f);
    }
    return f;
}

static int sapling_tree_branch_rows(void)
{
    int failures = 0;
    failures += ckt_row_flush_refusals();
    failures += ckt_row_flush_layout();
    failures += ckt_row_load_args_and_missing();
    failures += ckt_row_load_file_size();
    failures += ckt_row_load_integrity();
    failures += ckt_row_load_resealed_headers();
    failures += ckt_row_load_blob_parse();
    failures += ckt_row_witness_root();
    return failures;
}

int test_sapling_tree(void)
{
    int failures = 0;

    /* Each case uses its own temp path; tmpnam is deprecated but
     * we only need uniqueness within a single test run. Use mkstemp
     * for a proper fd then close+unlink so we can own the filename. */

    failures += sapling_tree_round_trip_case();
    failures += sapling_tree_delta_replay_case();
    failures += sapling_tree_corruption_case();
    failures += sapling_tree_missing_file_case();
    failures += sapling_tree_load_speed_case();
    failures += sapling_tree_branch_rows();

    return failures;
}
