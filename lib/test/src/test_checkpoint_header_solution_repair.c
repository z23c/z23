/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_checkpoint_header_solution_repair — focused unit test for the trust core
 * of the checkpoint-header-solution cure
 * (checkpoint_header_solution_verify_and_persist): the fetch → HASH-PIN →
 * frozen-Equihash → durable-persist → mint-pass-record pipeline.
 *
 * Asserts the three trust cases from the design contract:
 *   (1) a WRONG-HASH header (does not hash to the compiled checkpoint hash) is
 *       REFUSED at the hash-pin and NOTHING is persisted.
 *   (2) a BAD-SOLUTION header (hashes to the expected hash but fails the frozen
 *       Equihash checker) is REFUSED and NOTHING is persisted — proven twice:
 *       once through the REAL block_row_verify default, once through the frozen
 *       verifier seam returning false.
 *   (3) a GOOD header (hash-pin OK + frozen verify OK) is PERSISTED hash-bound
 *       into header_solution_repair AND its pass record is minted, so
 *       validate_headers_stage_has_pass_record then passes.
 */

#include "test/test_core.h"

#include "conditions/checkpoint_header_solution_repair.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/stage_repair.h"
#include "jobs/validate_headers_stage.h"
#include "net/checkpoint_header_fetch.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define CHSR_CHECK(desc, cond)                                               \
    do {                                                                     \
        printf("checkpoint_header_solution_repair: %s... ", (desc));         \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                              \
    } while (0)

void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn,
                                                     void *user);

/* A pass validator so ensure_pass_record writes the durable row without a real
 * mined Equihash header (the frozen checker itself is proven in
 * test_domain_consensus_equihash; here we prove the persist + pass-record wire). */
static bool chsr_pass_validator(const struct block_index *bi,
                                const char *datadir, char *reason,
                                size_t reason_size, void *user)
{
    (void)bi; (void)datadir; (void)reason; (void)reason_size; (void)user;
    return true;
}

/* Frozen-verifier seam stubs. */
static bool frozen_ok(const struct uint256 *h, const struct block_header *hdr)
{
    (void)h; (void)hdr;
    return true;
}
static bool frozen_reject(const struct uint256 *h, const struct block_header *hdr)
{
    (void)h; (void)hdr;
    return false;
}

/* Build a deterministic non-genesis header with a non-empty solution and return
 * its real hash. */
static void build_header(struct block_header *h, int height, struct uint256 *out_hash)
{
    block_header_init(h);
    h->nVersion = 4;
    h->hashPrevBlock.data[0] = (uint8_t)(height - 1);
    h->hashPrevBlock.data[1] = 0x51;
    h->hashMerkleRoot.data[0] = (uint8_t)height;
    h->hashMerkleRoot.data[1] = 0x9E;
    h->hashFinalSaplingRoot.data[0] = (uint8_t)height;
    h->nTime = 1700000000u + (uint32_t)height;
    h->nBits = 0x1f07ffff;
    h->nNonce.data[0] = (uint8_t)height;
    h->nNonce.data[1] = 0x2C;
    h->nSolutionSize = 32;
    for (size_t i = 0; i < h->nSolutionSize; i++)
        h->nSolution[i] = (uint8_t)(height + (int)i);
    block_header_get_hash(h, out_hash);
}

/* Insert a block_index at `height` with hash `hash` and make it the header tip so
 * ensure_pass_record resolves it. */
static struct block_index *seed_index(struct main_state *ms, int height,
                                      const struct uint256 *hash)
{
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->pprev = NULL;
    ms->pindex_best_header = bi;
    return bi;
}

int test_checkpoint_header_solution_repair(void)
{
    printf("\n=== checkpoint_header_solution_repair tests ===\n");
    int failures = 0;
    const int H = 3056758;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chsr", "ok");
    CHSR_CHECK("progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);

    struct block_header good;
    struct uint256 good_hash;
    build_header(&good, H, &good_hash);
    CHSR_CHECK("seed checkpoint header index", seed_index(&ms, H, &good_hash) != NULL);

    /* (1) WRONG HASH → refused at hash-pin, nothing persisted. */
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_ok);
    {
        struct uint256 wrong = good_hash;
        wrong.data[3] ^= 0xFF; /* expected != the header's real hash */
        CHSR_CHECK("wrong-hash header REFUSED",
                   !checkpoint_header_solution_verify_and_persist(&ms, H, &wrong,
                                                                  &good));
        CHSR_CHECK("wrong-hash: nothing persisted",
                   !stage_repair_header_solution_available(progress_store_db(),
                                                           H, &wrong));
        CHSR_CHECK("wrong-hash: no pass record",
                   !validate_headers_stage_has_pass_record(H, &wrong));
    }

    /* (2a) BAD SOLUTION via the REAL frozen verifier (block_row_verify) → the
     * hash pin passes (expected == the header's own hash) but the frozen
     * Equihash/PoW check rejects it → refused, nothing persisted. */
    checkpoint_header_solution_set_frozen_verifier_for_test(NULL);
    CHSR_CHECK("bad-solution (real frozen verifier) REFUSED",
               !checkpoint_header_solution_verify_and_persist(&ms, H, &good_hash,
                                                              &good));
    CHSR_CHECK("bad-solution (real): nothing persisted",
               !stage_repair_header_solution_available(progress_store_db(), H,
                                                       &good_hash));
    CHSR_CHECK("bad-solution (real): no pass record",
               !validate_headers_stage_has_pass_record(H, &good_hash));

    /* (2b) BAD SOLUTION via the frozen-verify-failure branch (seam returns
     * false) → refused, nothing persisted. */
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_reject);
    CHSR_CHECK("bad-solution (frozen rejects) REFUSED",
               !checkpoint_header_solution_verify_and_persist(&ms, H, &good_hash,
                                                              &good));
    CHSR_CHECK("bad-solution (seam): nothing persisted",
               !stage_repair_header_solution_available(progress_store_db(), H,
                                                       &good_hash));

    /* (3) GOOD header (hash-pin OK + frozen verify OK) → persisted + pass record
     * minted. */
    validate_headers_ensure_set_validator_for_test(chsr_pass_validator, NULL);
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_ok);
    CHSR_CHECK("good header PERSISTED",
               checkpoint_header_solution_verify_and_persist(&ms, H, &good_hash,
                                                             &good));
    CHSR_CHECK("good header: repair row now available",
               stage_repair_header_solution_available(progress_store_db(), H,
                                                      &good_hash));
    CHSR_CHECK("good header: pass record now present",
               validate_headers_stage_has_pass_record(H, &good_hash));
    CHSR_CHECK("good header: checkpoint_header_solution_available true",
               checkpoint_header_solution_available(H, &good_hash));

    /* Idempotent: a second verify+persist of the same good header still OK. */
    CHSR_CHECK("good header: second persist idempotent",
               checkpoint_header_solution_verify_and_persist(&ms, H, &good_hash,
                                                             &good));

    /* Net capture: a new node must pin the checkpoint header as IBD headers
     * fly past. Offering before arm must not capture; arm then offer must. */
    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_offer(&good, &good_hash);
    CHSR_CHECK("offer before arm does not capture",
               !checkpoint_header_fetch_has_capture());
    checkpoint_header_fetch_arm(H, &good_hash);
    checkpoint_header_fetch_offer(&good, &good_hash);
    CHSR_CHECK("arm then offer captures hash-pinned header",
               checkpoint_header_fetch_has_capture());
    {
        struct block_header taken;
        int32_t taken_h = -1;
        memset(&taken, 0, sizeof(taken));
        CHSR_CHECK("take consumes the capture",
                   checkpoint_header_fetch_take(&taken, &taken_h));
        CHSR_CHECK("taken height matches", taken_h == H);
        CHSR_CHECK("capture slot empty after take",
                   !checkpoint_header_fetch_has_capture());
    }
    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_compiled();
    CHSR_CHECK("arm_compiled arms the compiled checkpoint",
               checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_offer(&good, &good_hash);
    CHSR_CHECK("arm_compiled does not capture a non-checkpoint hash",
               !checkpoint_header_fetch_has_capture());
    checkpoint_header_fetch_test_reset();

    validate_headers_ensure_set_validator_for_test(NULL, NULL);
    checkpoint_header_solution_set_frozen_verifier_for_test(NULL);
    main_state_free(&ms);
    progress_store_close();
    test_rm_rf_recursive(dir);

    printf("checkpoint_header_solution_repair: %d failures\n", failures);
    return failures;
}
