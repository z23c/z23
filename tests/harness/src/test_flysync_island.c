/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_flysync_island — FlySync island start.
 *
 * Window walk (core/modules/net/src/checkpoint_header_fetch.c): a backward,
 * hash-pinned capture of a header window from an armed top hash. A forged or
 * out-of-order header is never captured; the window completes only along the
 * hashPrevBlock links; single-mode capture is untouched while no window is
 * armed and reports nothing while one is. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "net/checkpoint_header_fetch.h"
#include "primitives/block.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define FSI_CHECK(desc, cond)                                                \
    do {                                                                     \
        printf("flysync_island: %s... ", (desc));                            \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                               \
    } while (0)

/* A deterministic header with a non-empty solution; hash returned. */
static void fsi_build_header(struct block_header *h, int salt,
                             const struct uint256 *prev, struct uint256 *hash)
{
    block_header_init(h);
    if (prev)
        h->hashPrevBlock = *prev;
    h->hashMerkleRoot.data[0] = (uint8_t)salt;
    h->hashMerkleRoot.data[1] = 0x6d;
    h->nTime = 1760000000u + (uint32_t)salt;
    h->nBits = 0x1f07ffff;
    h->nNonce.data[0] = (uint8_t)salt;
    h->nNonce.data[2] = 0x33;
    h->nSolutionSize = 32;
    for (size_t i = 0; i < h->nSolutionSize; i++)
        h->nSolution[i] = (uint8_t)(salt * 7 + (int)i);
    block_header_get_hash(h, hash);
}

#define FSI_DEPTH 4

/* chain[0] is the top; chain[i].hashPrevBlock == hash(chain[i+1]). */
static void fsi_build_chain(struct block_header *chain, struct uint256 *hashes,
                            int n)
{
    struct uint256 below;
    memset(&below, 0x11, sizeof(below));
    for (int i = n - 1; i >= 0; i--) {
        fsi_build_header(&chain[i], 40 + i, &below, &hashes[i]);
        below = hashes[i];
    }
}

static int fsi_case_window_walk(void)
{
    int failures = 0;
    struct block_header chain[FSI_DEPTH];
    struct uint256 hashes[FSI_DEPTH];
    fsi_build_chain(chain, hashes, FSI_DEPTH);
    const int32_t top_h = 3200000;

    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_window(top_h, &hashes[0], FSI_DEPTH);
    FSI_CHECK("window arms", checkpoint_header_fetch_is_armed());

    struct block_header forged;
    struct uint256 forged_hash;
    fsi_build_header(&forged, 99, &hashes[1], &forged_hash);
    checkpoint_header_fetch_offer(&forged, &forged_hash);
    FSI_CHECK("forged header (not the pinned hash) is not captured",
              checkpoint_header_fetch_window_progress() == 0);

    checkpoint_header_fetch_offer(&chain[0], &hashes[0]);
    FSI_CHECK("top header captured",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[2], &hashes[2]);
    FSI_CHECK("out-of-order header is not captured",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[0], &hashes[0]);
    FSI_CHECK("re-delivered top is not captured twice",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[1], &hashes[1]);
    checkpoint_header_fetch_offer(&chain[2], &hashes[2]);
    FSI_CHECK("single-mode take sees nothing while a window walks",
              !checkpoint_header_fetch_has_capture());
    checkpoint_header_fetch_offer(&chain[3], &hashes[3]);
    FSI_CHECK("window complete after the linked walk",
              checkpoint_header_fetch_window_progress() == FSI_DEPTH);
    FSI_CHECK("single-mode has_capture stays false for a window",
              !checkpoint_header_fetch_has_capture());

    struct block_header got[CHECKPOINT_HEADER_FETCH_WINDOW_MAX];
    int32_t got_top = -1;
    FSI_CHECK("take refuses a too-small buffer",
              checkpoint_header_fetch_take_window(got, FSI_DEPTH - 1,
                                                  &got_top) == 0);
    int n = checkpoint_header_fetch_take_window(
        got, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &got_top);
    FSI_CHECK("take returns the whole window", n == FSI_DEPTH);
    FSI_CHECK("take reports the top height", got_top == top_h);
    bool order = n == FSI_DEPTH;
    for (int i = 0; order && i < FSI_DEPTH; i++) {
        struct uint256 h;
        block_header_get_hash(&got[i], &h);
        order = uint256_eq(&h, &hashes[i]);
    }
    FSI_CHECK("window is top-first and hash-linked", order);
    FSI_CHECK("take consumes once",
              checkpoint_header_fetch_take_window(
                  got, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &got_top) == 0);
    FSI_CHECK("take disarms the walk", !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_test_reset();
    return failures;
}

static int fsi_case_window_args_and_single_mode(void)
{
    int failures = 0;
    struct uint256 hash;
    struct block_header h;
    fsi_build_header(&h, 7, NULL, &hash);

    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_window(100, &hash, 0);
    FSI_CHECK("depth 0 does not arm", !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_arm_window(100, &hash,
                                       CHECKPOINT_HEADER_FETCH_WINDOW_MAX + 1);
    FSI_CHECK("depth above the max does not arm",
              !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_arm_window(2, &hash, 4);
    FSI_CHECK("a window below genesis does not arm",
              !checkpoint_header_fetch_is_armed());

    /* Single mode is exactly as before, and re-arming single cancels a window. */
    checkpoint_header_fetch_arm_window(100, &hash, 3);
    checkpoint_header_fetch_arm(100, &hash);
    checkpoint_header_fetch_offer(&h, &hash);
    FSI_CHECK("single-mode capture after a window is replaced",
              checkpoint_header_fetch_has_capture());
    FSI_CHECK("window progress reads 0 in single mode",
              checkpoint_header_fetch_window_progress() == 0);
    struct block_header taken;
    int32_t th = -1;
    FSI_CHECK("single-mode take works",
              checkpoint_header_fetch_take(&taken, &th) && th == 100);

    checkpoint_header_fetch_arm_window(100, &hash, 3);
    checkpoint_header_fetch_disarm();
    FSI_CHECK("disarm clears a window walk",
              !checkpoint_header_fetch_is_armed() &&
              checkpoint_header_fetch_window_progress() == 0);
    checkpoint_header_fetch_test_reset();
    return failures;
}

int test_flysync_island(void)
{
    int failures = 0;
    failures += fsi_case_window_walk();
    failures += fsi_case_window_args_and_single_mode();
    printf("flysync_island: %d failures\n", failures);
    return failures;
}
