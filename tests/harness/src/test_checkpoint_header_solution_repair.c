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
#include "chain/checkpoints.h"
#include "core/uint256.h"
#include "event/event.h"
#include "framework/condition.h"
#include "jobs/stage_repair.h"
#include "jobs/validate_headers_stage.h"
#include "net/checkpoint_header_fetch.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* ── Lifecycle cases: the registered condition's detect / remedy / witness /
 * urgent hooks on an isolated fixture datadir. The compiled SHA3 checkpoint is
 * replaced by an override at CHSR_FX_H whose hash is the real hash of a
 * deterministic header, so the hash-pin and the staged-bundle target agree. ── */

#define CHSR_FX_H 5000
#define CHSR_NO_PEER_ID "checkpoint_header_solution_no_peer"

static struct sha3_utxo_checkpoint g_chsr_cp; /* borrowed by the override seam */

static bool chsr_reject_validator(const struct block_index *bi,
                                  const char *datadir, char *reason,
                                  size_t reason_size, void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (reason && reason_size)
        snprintf(reason, reason_size, "fixture rejects");
    return false;
}

struct chsr_fx {
    struct main_state ms;
    struct block_header hdr;
    struct uint256 hash;
    char dir[256];
    bool ok;
};

static void chsr_fx_open(struct chsr_fx *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    event_log_init();
    (void)blocker_module_init();
    blocker_reset_for_testing();
    condition_engine_reset_for_testing();
    checkpoint_header_solution_repair_test_reset();
    checkpoint_header_fetch_test_reset();

    build_header(&fx->hdr, CHSR_FX_H, &fx->hash);
    memset(&g_chsr_cp, 0, sizeof(g_chsr_cp));
    g_chsr_cp.height = CHSR_FX_H;
    memcpy(g_chsr_cp.block_hash, fx->hash.data, 32);
    checkpoints_set_sha3_override_for_test(&g_chsr_cp);

    test_make_tmpdir(fx->dir, sizeof(fx->dir), "chsr", tag);
    main_state_init(&fx->ms);
    char bundles[320];
    snprintf(bundles, sizeof(bundles), "%s/bundles", fx->dir);
    bool staged = mkdir(bundles, 0700) == 0;
    snprintf(bundles, sizeof(bundles),
             "%s/bundles/consensus-state-bundle-%d.sqlite", fx->dir,
             CHSR_FX_H);
    FILE *f = fopen(bundles, "w");
    if (f) fclose(f);
    fx->ok = staged && f && progress_store_open(fx->dir) &&
             seed_index(&fx->ms, CHSR_FX_H, &fx->hash) != NULL;

    checkpoint_header_solution_repair_test_set_main_state(&fx->ms);
    checkpoint_header_solution_repair_test_set_datadir(fx->dir);
    checkpoint_header_solution_repair_test_set_peer_count(1);
    validate_headers_ensure_set_validator_for_test(chsr_pass_validator, NULL);
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_ok);
}

static void chsr_fx_close(struct chsr_fx *fx)
{
    validate_headers_ensure_set_validator_for_test(NULL, NULL);
    checkpoint_header_solution_repair_test_reset();
    checkpoint_header_fetch_test_reset();
    checkpoints_reset_sha3_override_for_test();
    condition_engine_reset_for_testing();
    blocker_clear(CHSR_NO_PEER_ID);
    main_state_free(&fx->ms);
    progress_store_close();
    test_rm_rf_recursive(fx->dir);
}

static bool chsr_durable(const struct chsr_fx *fx)
{
    return stage_repair_header_solution_available(progress_store_db(),
                                                  CHSR_FX_H, &fx->hash);
}

static int chsr_case_registration(void)
{
    int failures = 0;
    struct condition_runtime_snapshot snap;
    condition_engine_reset_for_testing();
    register_checkpoint_header_solution_repair();
    memset(&snap, 0, sizeof(snap));
    CHSR_CHECK("registered",
               condition_engine_get_registered_snapshot(
                   "checkpoint_header_solution_repair", &snap) &&
                   snap.registered);
    CHSR_CHECK("cadence 5s poll / 30s backoff / 5 attempts / 30s witness",
               snap.poll_secs == 5 && snap.backoff_secs == 30 &&
                   snap.max_attempts == 5 && snap.witness_window_secs == 30);
    CHSR_CHECK("WARN, cooldown 300s re-armed forever (0 max rearms)",
               snap.severity == COND_WARN && snap.cooldown_secs == 300 &&
                   snap.cooldown_max_rearms == 0);
    condition_engine_reset_for_testing();
    return failures;
}

/* detect() fires only when every precondition holds; each case below removes
 * exactly one from the firing baseline. */
static int chsr_case_detect(void)
{
    int failures = 0;
    struct chsr_fx fx;
    chsr_fx_open(&fx, "detect");
    CHSR_CHECK("detect: fixture ready", fx.ok);
    CHSR_CHECK("detect: fires with header chain + staged bundle + no solution",
               checkpoint_header_solution_repair_test_detect());

    struct main_state below;
    main_state_init(&below);
    struct uint256 other = fx.hash;
    other.data[9] ^= 0xFF;
    seed_index(&below, CHSR_FX_H - 1, &other);
    checkpoint_header_solution_repair_test_set_main_state(&below);
    CHSR_CHECK("detect: quiet while the header chain is below the checkpoint",
               !checkpoint_header_solution_repair_test_detect());
    main_state_free(&below);

    main_state_init(&below);
    seed_index(&below, CHSR_FX_H, &other);
    checkpoint_header_solution_repair_test_set_main_state(&below);
    CHSR_CHECK("detect: quiet when the checkpoint height carries another hash",
               !checkpoint_header_solution_repair_test_detect());
    main_state_free(&below);

    checkpoint_header_solution_repair_test_set_main_state(NULL);
    CHSR_CHECK("detect: quiet with no main state wired",
               !checkpoint_header_solution_repair_test_detect());
    CHSR_CHECK("remedy: skips with no main state wired",
               checkpoint_header_solution_repair_test_remedy() ==
                       (int)COND_REMEDY_SKIP &&
                   !checkpoint_header_fetch_is_armed());
    checkpoint_header_solution_repair_test_set_main_state(&fx.ms);

    char bundle[320];
    snprintf(bundle, sizeof(bundle),
             "%s/bundles/consensus-state-bundle-%d.sqlite", fx.dir,
             CHSR_FX_H);
    CHSR_CHECK("detect: remove staged bundle", unlink(bundle) == 0);
    CHSR_CHECK("detect: quiet with no staged bundle",
               !checkpoint_header_solution_repair_test_detect());
    FILE *f = fopen(bundle, "w");
    if (f) fclose(f);
    CHSR_CHECK("detect: fires again once the bundle is back",
               checkpoint_header_solution_repair_test_detect());

    CHSR_CHECK("detect: persist the solution",
               checkpoint_header_solution_verify_and_persist(
                   &fx.ms, CHSR_FX_H, &fx.hash, &fx.hdr));
    CHSR_CHECK("detect: quiet once the solution is durable",
               !checkpoint_header_solution_repair_test_detect());
    chsr_fx_close(&fx);
    return failures;
}

/* remedy(): arms the bounded fetch and names the no-peer blocker, refuses a
 * capture that does not verify, and persists one that does. */
static int chsr_case_remedy_arm(void)
{
    int failures = 0;
    struct chsr_fx fx;
    chsr_fx_open(&fx, "arm");

    checkpoint_header_solution_repair_test_set_peer_count(0);
    CHSR_CHECK("remedy: nothing captured, no peer -> skip",
               checkpoint_header_solution_repair_test_remedy() ==
                   (int)COND_REMEDY_SKIP);
    CHSR_CHECK("remedy: fetch armed and no-peer blocker named",
               checkpoint_header_fetch_is_armed() &&
                   blocker_exists(CHSR_NO_PEER_ID));
    checkpoint_header_solution_repair_test_set_peer_count(2);
    CHSR_CHECK("remedy: nothing captured, peers -> skip",
               checkpoint_header_solution_repair_test_remedy() ==
                   (int)COND_REMEDY_SKIP);
    CHSR_CHECK("remedy: with peers the blocker is cleared, still armed",
               checkpoint_header_fetch_is_armed() &&
                   !blocker_exists(CHSR_NO_PEER_ID));

    /* A capture armed for another height is refused and the fetch re-armed. */
    checkpoint_header_fetch_arm(CHSR_FX_H + 7, &fx.hash);
    checkpoint_header_fetch_offer(&fx.hdr, &fx.hash);
    CHSR_CHECK("remedy: wrong-height capture present",
               checkpoint_header_fetch_has_capture());
    CHSR_CHECK("remedy: wrong-height capture refused (skip)",
               checkpoint_header_solution_repair_test_remedy() ==
                   (int)COND_REMEDY_SKIP);
    CHSR_CHECK("remedy: wrong-height capture persisted nothing, re-armed",
               !chsr_durable(&fx) && checkpoint_header_fetch_is_armed() &&
                   !checkpoint_header_fetch_has_capture());

    /* A capture whose solution fails the frozen verifier is refused. */
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_reject);
    checkpoint_header_fetch_arm(CHSR_FX_H, &fx.hash);
    checkpoint_header_fetch_offer(&fx.hdr, &fx.hash);
    CHSR_CHECK("remedy: bad-solution capture refused (skip)",
               checkpoint_header_solution_repair_test_remedy() ==
                   (int)COND_REMEDY_SKIP);
    CHSR_CHECK("remedy: bad-solution capture persisted nothing, re-armed",
               !chsr_durable(&fx) && checkpoint_header_fetch_is_armed());

    /* A verifying capture is persisted; the fetch disarms and the blocker
     * (re-raised below) clears. */
    checkpoint_header_solution_set_frozen_verifier_for_test(frozen_ok);
    checkpoint_header_solution_repair_test_set_peer_count(0);
    (void)checkpoint_header_solution_repair_test_remedy();
    CHSR_CHECK("remedy: blocker raised before the good capture",
               blocker_exists(CHSR_NO_PEER_ID));
    checkpoint_header_fetch_offer(&fx.hdr, &fx.hash);
    CHSR_CHECK("remedy: good capture persisted (ok)",
               checkpoint_header_solution_repair_test_remedy() ==
                   (int)COND_REMEDY_OK);
    CHSR_CHECK("remedy: durable, disarmed, blocker cleared",
               chsr_durable(&fx) && !checkpoint_header_fetch_is_armed() &&
                   !blocker_exists(CHSR_NO_PEER_ID));
    CHSR_CHECK("remedy: pass record minted",
               validate_headers_stage_has_pass_record(CHSR_FX_H, &fx.hash));
    chsr_fx_close(&fx);
    return failures;
}

/* Through the engine: a capture that lands inside the 30s backoff is consumed
 * on the next tick because urgent() reports it, and the witness then clears. */
static int chsr_case_engine(void)
{
    int failures = 0;
    struct chsr_fx fx;
    struct condition_runtime_snapshot s0, s1, s2;
    chsr_fx_open(&fx, "engine");

    register_checkpoint_header_solution_repair();
    memset(&s0, 0, sizeof(s0));
    (void)condition_engine_get_registered_snapshot(
        "checkpoint_header_solution_repair", &s0);
    condition_engine_tick();
    memset(&s1, 0, sizeof(s1));
    (void)condition_engine_get_registered_snapshot(
        "checkpoint_header_solution_repair", &s1);
    CHSR_CHECK("engine: detect fired, first remedy armed the fetch",
               s1.currently_active && s1.attempts == 1 &&
                   checkpoint_header_fetch_is_armed() && !chsr_durable(&fx));

    checkpoint_header_fetch_offer(&fx.hdr, &fx.hash);
    CHSR_CHECK("engine: capture landed", checkpoint_header_fetch_has_capture());
    condition_engine_tick(); /* well inside backoff: only urgent() makes it due */
    memset(&s2, 0, sizeof(s2));
    (void)condition_engine_get_registered_snapshot(
        "checkpoint_header_solution_repair", &s2);
    CHSR_CHECK("engine: urgent capture consumed, witnessed clear",
               s2.cleared_count == s0.cleared_count + 1 &&
                   !s2.currently_active && chsr_durable(&fx));
    CHSR_CHECK("engine: fetch disarmed after the clear",
               !checkpoint_header_fetch_is_armed());
    chsr_fx_close(&fx);
    return failures;
}

static int chsr_case_persist_edges(void)
{
    int failures = 0;
    struct chsr_fx fx;
    chsr_fx_open(&fx, "edges");
    struct main_state *ms = &fx.ms;

    CHSR_CHECK("persist: NULL main state refused",
               !checkpoint_header_solution_verify_and_persist(
                   NULL, CHSR_FX_H, &fx.hash, &fx.hdr));
    CHSR_CHECK("persist: negative height refused",
               !checkpoint_header_solution_verify_and_persist(
                   ms, -1, &fx.hash, &fx.hdr));
    CHSR_CHECK("persist: NULL hash refused",
               !checkpoint_header_solution_verify_and_persist(
                   ms, CHSR_FX_H, NULL, &fx.hdr));
    CHSR_CHECK("persist: NULL header refused",
               !checkpoint_header_solution_verify_and_persist(
                   ms, CHSR_FX_H, &fx.hash, NULL));
    CHSR_CHECK("available: negative height false",
               !checkpoint_header_solution_available(-1, &fx.hash));
    CHSR_CHECK("available: NULL hash false",
               !checkpoint_header_solution_available(CHSR_FX_H, NULL));
    CHSR_CHECK("available: nothing durable yet",
               !checkpoint_header_solution_available(CHSR_FX_H, &fx.hash));

    /* Fail-open pass record: the durable repair row alone is enough. */
    validate_headers_ensure_set_validator_for_test(chsr_reject_validator,
                                                   NULL);
    CHSR_CHECK("persist: ok even when the pass record cannot be minted",
               checkpoint_header_solution_verify_and_persist(
                   ms, CHSR_FX_H, &fx.hash, &fx.hdr));
    CHSR_CHECK("persist: repair row durable, no pass record",
               chsr_durable(&fx) &&
                   !validate_headers_stage_has_pass_record(CHSR_FX_H,
                                                           &fx.hash));
    CHSR_CHECK("available: true from the repair row alone",
               checkpoint_header_solution_available(CHSR_FX_H, &fx.hash));

    /* A closed progress store can neither persist nor report availability. */
    progress_store_close();
    CHSR_CHECK("persist: closed store refused",
               !checkpoint_header_solution_verify_and_persist(
                   ms, CHSR_FX_H, &fx.hash, &fx.hdr));
    CHSR_CHECK("available: closed store false",
               !checkpoint_header_solution_available(CHSR_FX_H, &fx.hash));
    (void)progress_store_open(fx.dir);
    chsr_fx_close(&fx);
    return failures;
}

static int chsr_lifecycle_cases(void)
{
    int failures = 0;
    failures += chsr_case_registration();
    failures += chsr_case_detect();
    failures += chsr_case_remedy_arm();
    failures += chsr_case_engine();
    failures += chsr_case_persist_edges();
    return failures;
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

    failures += chsr_lifecycle_cases();

    printf("checkpoint_header_solution_repair: %d failures\n", failures);
    return failures;
}
