/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for process_block_revalidate (Wave M).
 *
 * Coverage:
 *   - outcome name mapping (every enum value → stable string)
 *   - bad-args paths (NULL ms, negative height)
 *   - HEIGHT_NOT_FOUND when no pindex at the height
 *   - HEIGHT_NOT_FOUND when pindex exists but no BLOCK_FAILED_VALID
 *
 * What this file does NOT cover (operator-run integration is the right
 * place):
 *   - Full pipeline against a running zclassicd + quorum_oracle
 *   - Activation controller integration end-to-end
 *
 * The wedge scenario the function fixes — `BLOCK_FAILED_VALID` set on
 * a single block, two oracles agree on its hash, function clears and
 * activation re-runs — needs a real chainstate + LevelDB + zclassicd
 * to verify end-to-end. That's `make deploy` + observing
 * `z23 status` height advance, not a unit test.
 *
 * The unit-testable surface is the enum mapping + early-return paths +
 * the find_failed_pindex_at_height helper (verified through the
 * height-not-found contract). */

#include "test/test_core.h"

#include "chain/chain.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block_revalidate.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PBR_CHECK(name, expr) do { \
    printf("process_block_revalidate: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_process_block_revalidate(void)
{
    printf("\n=== process_block_revalidate tests ===\n");
    int failures = 0;

    /* ── 1. Outcome name mapping ─────────────────────────────────────── */
    PBR_CHECK("name(NOT_ATTEMPTED)",
              strcmp(reval_result_name(REVAL_NOT_ATTEMPTED),
                     "not_attempted") == 0);
    PBR_CHECK("name(NO_FAILURE)",
              strcmp(reval_result_name(REVAL_NO_FAILURE),
                     "no_failure") == 0);
    PBR_CHECK("name(HEIGHT_NOT_FOUND)",
              strcmp(reval_result_name(REVAL_HEIGHT_NOT_FOUND),
                     "height_not_found") == 0);
    PBR_CHECK("name(EVIDENCE_INSUFFICIENT)",
              strcmp(reval_result_name(REVAL_EVIDENCE_INSUFFICIENT),
                     "evidence_insufficient") == 0);
    PBR_CHECK("name(EVIDENCE_DISAGREES)",
              strcmp(reval_result_name(REVAL_EVIDENCE_DISAGREES),
                     "evidence_disagrees") == 0);
    PBR_CHECK("name(PERSIST_FAILED)",
              strcmp(reval_result_name(REVAL_PERSIST_FAILED),
                     "persist_failed") == 0);
    PBR_CHECK("name(CONNECT_FAILED)",
              strcmp(reval_result_name(REVAL_CONNECT_FAILED),
                     "connect_failed") == 0);
    PBR_CHECK("name(RECOVERED)",
              strcmp(reval_result_name(REVAL_RECOVERED),
                     "recovered") == 0);

    /* ── 2. Bad-args path ────────────────────────────────────────────── */
    struct uint256 dummy_hash;
    PBR_CHECK("NULL ms → NOT_ATTEMPTED",
              process_block_revalidate(3115060, NULL, &dummy_hash) ==
                  REVAL_NOT_ATTEMPTED);
    /* Build a minimal main_state so we can exercise the height-validation
     * path without a fully-loaded chainstate. */
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    PBR_CHECK("negative height → NOT_ATTEMPTED",
              process_block_revalidate(-1, &ms, &dummy_hash) ==
                  REVAL_NOT_ATTEMPTED);

    /* ── 3. HEIGHT_NOT_FOUND on empty block_map ──────────────────────── */
    /* Fresh main_state: block_map is empty; no pindex at any height. */
    memset(&dummy_hash, 0xCC, sizeof(dummy_hash));
    PBR_CHECK("empty block_map → HEIGHT_NOT_FOUND",
              process_block_revalidate(3115060, &ms, &dummy_hash) ==
                  REVAL_HEIGHT_NOT_FOUND);
    /* out_hash should be cleared (no pindex found). */
    {
        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        PBR_CHECK("out_hash zeroed on HEIGHT_NOT_FOUND",
                  memcmp(&dummy_hash, &zero, sizeof(zero)) == 0);
    }

    /* ── 4. HEIGHT_NOT_FOUND when pindex exists but isn't FAILED_VALID
     * (we only find entries WITH the bit set) ──────────────────────── */
    {
        /* Insert a synthetic pindex at height 100 with no failure bit. */
        struct block_index *pi = calloc(1, sizeof(*pi));
        struct uint256 h;
        memset(&h, 0xAB, sizeof(h));
        pi->nHeight = 100;
        pi->nStatus = BLOCK_VALID_SCRIPTS;  /* clean, no failure */
        struct uint256 *hp = malloc(sizeof(struct uint256));
        *hp = h;
        pi->phashBlock = hp;
        block_map_insert(&ms.map_block_index, &h, pi);

        PBR_CHECK("pindex without FAILED_VALID → HEIGHT_NOT_FOUND",
                  process_block_revalidate(100, &ms, &dummy_hash) ==
                      REVAL_HEIGHT_NOT_FOUND);

        free(pi);
        free(hp);
    }

    /* Note: we do NOT exercise the "pindex has FAILED_VALID, oracle
     * returns quorum, etc." paths here. Those require a fully-wired
     * quorum_oracle_service backed by a real zclassicd, plus the
     * activation controller, plus a block_tree_db handle. The acceptance
     * test is operator-run after make deploy:
     *
     *   # before
     *   $ z23 status | jq .height
     *   3115059
     *   $ zclassic23 blockers | jq .active_count
     *   0
     *
     *   # wait 900s (or one full coord_esc supervisor tick)
     *
     *   # after — chain should have advanced past 3,115,059 if zclassicd
     *   # at 127.0.0.1:8232 agreed with our pindex hash at h=3,115,060
     *   $ z23 status | jq .height
     *   3115060+
     */

    main_state_free(&ms);

    printf("process_block_revalidate: %d failures\n", failures);
    return failures;
}
