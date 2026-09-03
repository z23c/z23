/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */

/* Native Windows scale proof for the block-swarm scheduler.  This deliberately
 * measures scheduler/state-machine cost, not network, disk, or consensus
 * validation throughput: the real-wire loopback group owns those boundaries.
 * A 3.2M-block chain maps to 50,000 independently verified 64-block pieces. */

#if defined(_WIN32)

#include "net/fast_sync.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCALE_BLOCKS UINT32_C(3200000)
#define SCALE_MAX_ELAPSED_US INT64_C(2000000)

int main(void)
{
    struct block_piece_manifest manifest;
    struct block_swarm swarm;
    uint64_t operations = 0;
    int64_t started_us;
    int64_t elapsed_us;

    memset(&manifest, 0, sizeof(manifest));
    manifest.start_height = 1;
    manifest.end_height = (int32_t)SCALE_BLOCKS;
    manifest.num_pieces =
        (SCALE_BLOCKS + BLOCKS_PER_PIECE - 1) / BLOCKS_PER_PIECE;
    manifest.piece_hashes = zcl_calloc(
        manifest.num_pieces, 32, "windows_block_swarm_scale_hashes");
    if (!manifest.piece_hashes) {
        fprintf(stderr, "block_swarm_scale: FAIL allocation\n");
        return 1;
    }

    if (!block_swarm_init(&swarm, &manifest, NULL)) {
        free(manifest.piece_hashes);
        fprintf(stderr, "block_swarm_scale: FAIL init\n");
        return 1;
    }
    free(manifest.piece_hashes);

    started_us = platform_time_monotonic_us();
    for (uint32_t expected = 0; expected < manifest.num_pieces; expected++) {
        int peer_id = 1 + (int)(expected % 8);
        uint32_t first_incomplete =
            block_swarm_first_incomplete_piece(&swarm);
        operations++;
        if (first_incomplete != expected) {
            fprintf(stderr,
                    "block_swarm_scale: FAIL window expected=%u got=%u\n",
                    expected, first_incomplete);
            block_swarm_free(&swarm);
            return 1;
        }
        int32_t assigned = block_swarm_assign_piece(
            &swarm, peer_id, NULL, 0);
        operations++;
        if (assigned != (int32_t)expected) {
            fprintf(stderr,
                    "block_swarm_scale: FAIL assignment expected=%u got=%d\n",
                    expected, assigned);
            block_swarm_free(&swarm);
            return 1;
        }

        /* Rewind a regular sample through the production retry path. */
        if ((expected & UINT32_C(4095)) == 0) {
            block_swarm_fail_piece(&swarm, expected);
            operations++;
            assigned = block_swarm_assign_piece(&swarm, peer_id, NULL, 0);
            operations++;
            if (assigned != (int32_t)expected) {
                fprintf(stderr,
                        "block_swarm_scale: FAIL retry expected=%u got=%d\n",
                        expected, assigned);
                block_swarm_free(&swarm);
                return 1;
            }
        }

        if (!block_swarm_receive_piece(&swarm, expected, peer_id)) {
            fprintf(stderr, "block_swarm_scale: FAIL receive piece=%u\n",
                    expected);
            block_swarm_free(&swarm);
            return 1;
        }
        operations++;
    }
    elapsed_us = platform_time_monotonic_us() - started_us;

    if (!block_swarm_is_complete(&swarm) ||
        block_swarm_progress(&swarm) != 100 || elapsed_us <= 0 ||
        elapsed_us > SCALE_MAX_ELAPSED_US) {
        fprintf(stderr,
                "block_swarm_scale: FAIL blocks=%" PRIu32
                " pieces=%" PRIu32 " operations=%" PRIu64
                " elapsed_us=%" PRId64 " budget_us=%" PRId64 "\n",
                SCALE_BLOCKS, manifest.num_pieces, operations, elapsed_us,
                SCALE_MAX_ELAPSED_US);
        block_swarm_free(&swarm);
        return 1;
    }

    printf("block_swarm_scale: PASS blocks=%" PRIu32
           " pieces=%" PRIu32 " operations=%" PRIu64
           " elapsed_us=%" PRId64 " pieces_per_second=%.0f\n",
           SCALE_BLOCKS, manifest.num_pieces, operations, elapsed_us,
           (double)manifest.num_pieces * 1000000.0 / (double)elapsed_us);
    block_swarm_free(&swarm);
    return 0;
}

#else
typedef int block_swarm_scale_windows_acceptance_not_built;
#endif
