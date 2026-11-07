/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixture of the flysync_island test group: test_flysync_island.c
 * (window, seed, exemptions, bounds, gate) and test_flysync_island_fallback.c
 * (fall-back detach, rejoin, island state). */

#ifndef ZCL_TEST_FLYSYNC_ISLAND_COMMON_H
#define ZCL_TEST_FLYSYNC_ISLAND_COMMON_H

#include "chain/checkpoints.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "services/island_anchor.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdio.h>

#define FSI_CHECK(desc, cond)                                                \
    do {                                                                     \
        printf("flysync_island: %s... ", (desc));                            \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                               \
    } while (0)

#define FSI_RUNG_H 3200000
#define FSI_W ISLAND_ANCHOR_WINDOW
#define FSI_BITS 0x1f07ffffu

struct fsi_island {
    struct block_header w[FSI_W];   /* w[0] is the rung, w[FSI_W-1] the root */
    struct uint256 hash[FSI_W];
    struct rom_state_rung rung;
    struct arith_uint256 rung_work;
};

struct fsi_node {
    char dir[256];
    struct main_state ms;
    struct fsi_island is;
    struct island_anchor a;
    struct block_index *rows[FSI_W];   /* ascending: rows[0] is the root */
};

/* test_flysync_island.c */
void fsi_build_island(struct fsi_island *is);
bool fsi_accept_all(const struct uint256 *hash, const struct block_header *hdr);
bool fsi_node_open(struct fsi_node *n, const char *tag);
void fsi_node_close(struct fsi_node *n);
struct block_index *fsi_top(struct fsi_node *n);
bool fsi_top_work_is_rung(struct fsi_node *n);
void fsi_reload_work(struct fsi_node *n);
bool fsi_node_seed(struct fsi_node *n);
void fsi_release_globals(void);
struct state_offer_v1;
void fsi_make_offer(struct state_offer_v1 *o, int32_t height, uint8_t tag);

/* test_flysync_island_fallback.c: run on the seeded island fixture, in order. */
int fsi_fallback_cases(struct fsi_node *n);
/* test_flysync_island_fallback.c: each case on its own fixture. */
int fsi_state_cases(void);

#endif /* ZCL_TEST_FLYSYNC_ISLAND_COMMON_H */
