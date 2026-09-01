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

int test_sapling_tree(void)
{
    int failures = 0;
    char path[128];

    /* Each case uses its own temp path; tmpnam is deprecated but
     * we only need uniqueness within a single test run. Use mkstemp
     * for a proper fd then close+unlink so we can own the filename. */

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
