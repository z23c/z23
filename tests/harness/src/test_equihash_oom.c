/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Allocation-failure coverage for the Equihash verifier and the generic
 * Wagner solver (core/modules/crypto/src/equihash.c).
 *
 * equihash_is_valid_solution() runs on every inbound block header before it
 * is trusted, and its seven allocations each have a hand-rolled multi-pointer
 * unwind; equihash_basic_solve() adds an `oom` flag threading out of a
 * doubly-nested loop.
 *
 * zcl_alloc_fault_fail_nth (base/safe_alloc.h) makes the Nth checked
 * allocation with an exact label return NULL once. Each case asserts both
 * halves: true without injection, false with it, and the hook fired.
 *
 * N > 1 drives the partial-unwind cases: failing the fifth eh_row_data makes
 * the batch-of-8 unwind free four built rows; failing the second eh_row_xor
 * makes the merge unwind free one merged row.
 *
 * Reach: only the 8-wide row loop is covered. num_indices is 2^K with K in
 * {5, 7, 9}, always a multiple of 8, so the 4-wide and scalar arms are
 * unreachable for node-supplied parameters. K < 3 reaches them, but the
 * solver and verifier disagree there (solution_width truncates), so no
 * "true without injection" baseline exists; those arms are left uncovered.
 *
 * Characterization (no injection): the refusals that return before any work
 * (wrong length, NULL arguments, short output buffer), the PoW rejects a
 * well-formed encoding reaches (out-of-order and non-distinct leaf indices),
 * and the solver's exact output bytes. Still uncovered: the verifier's
 * collision-mismatch and non-zero-final-XOR rejects (both need a hand-computed
 * index set), and the verifier's index-count mismatch (unreachable once the
 * length check passes). The solver's "no full collision" return is reached
 * only when the first witness nonce is above 0.
 */

#include "test/test_core.h"

#include "base/safe_alloc.h"

#include <pthread.h>
#include <stdint.h>
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "mining/miner.h"
#include "net/msg_internal.h"
#include "primitives/block.h"
#include "services/block_row_verify.h"
#include "validation/check_block.h"

/* (N=96, K=5) witness from the Zcash reference suite (same vector as
 * test_domain_consensus_equihash.c), for the BLAKE2b state seeded by the
 * fixed input string + nonce {1, 0, ...}. */
static const eh_index kValidIndices_96_5[32] = {
    2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041,
    32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
    15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
    23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568
};

#define EHO_CHECK(name, expr) do { \
    printf("equihash_oom: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── (96,5) verifier fixture ─────────────────────────────────────── */

static struct equihash_params g_p965;
static unsigned char g_soln965[68];
static size_t g_soln965_len;

static void eho_state_965(struct blake2b_ctx *st)
{
    equihash_initialise_state(&g_p965, st);
    const char *input = "Equihash is an asymmetric PoW based on the "
                        "Generalised Birthday problem.";
    blake2b_update(st, (const unsigned char *)input, strlen(input));
    unsigned char nonce[32] = {0};
    nonce[0] = 1;
    blake2b_update(st, nonce, 32);
}

static bool eho_verify_965(void)
{
    struct blake2b_ctx st;
    eho_state_965(&st);
    return equihash_is_valid_solution(&g_p965, &st, g_soln965, g_soln965_len);
}

/* Arm the Nth allocation carrying `label`, run the verifier, and require
 * that the hook fired AND the verifier rejected. Always disarms. */
static bool eho_verify_rejects(const char *label, unsigned n)
{
    zcl_alloc_fault_fail_nth(label, n);
    bool valid = eho_verify_965();
    bool fired = (zcl_alloc_fault_armed_label() == NULL);
    zcl_alloc_fault_clear();
    if (!fired)
        printf("\n  (injection on '%s' n=%u never fired)\n", label, n);
    return fired && !valid;
}

/* ── (48,5) solver fixture ───────────────────────────────────────── */

static struct equihash_params g_p485;
static int g_solve_nonce = -1;

static void eho_state_485(struct blake2b_ctx *st, int nonce)
{
    equihash_initialise_state(&g_p485, st);
    blake2b_update(st, (const unsigned char *)"zcl-equihash-oom", 16);
    unsigned char n32[32] = {0};
    n32[0] = (unsigned char)nonce;
    blake2b_update(st, n32, 32);
}

static bool eho_solve_485(int nonce, unsigned char *out, size_t out_len)
{
    struct blake2b_ctx st;
    eho_state_485(&st, nonce);
    return equihash_basic_solve(&g_p485, &st, out, out_len);
}

static bool eho_solve_rejects(const char *label, unsigned n)
{
    unsigned char out[256];
    zcl_alloc_fault_fail_nth(label, n);
    bool solved = eho_solve_485(g_solve_nonce, out, sizeof(out));
    bool fired = (zcl_alloc_fault_armed_label() == NULL);
    zcl_alloc_fault_clear();
    if (!fired)
        printf("\n  (injection on '%s' n=%u never fired)\n", label, n);
    return fired && !solved;
}

/* ── The seven verifier labels, first allocation each ─────────────── */

static int eho_verifier_labels(void)
{
    int failures = 0;
    printf("\n--- verifier: every allocation label rejects on OOM ---\n");

    EHO_CHECK("(96,5) reference witness verifies with no injection",
              eho_verify_965());

    /* eh_get_indices_from_minimal's scratch: the caller must still free
     * the index array it allocated one line earlier. */
    EHO_CHECK("eh_expand_indices OOM -> reject",
              eho_verify_rejects("eh_expand_indices", 1));
    EHO_CHECK("equihash_indices OOM -> reject",
              eho_verify_rejects("equihash_indices", 1));
    EHO_CHECK("equihash_rows OOM -> reject (frees indices)",
              eho_verify_rejects("equihash_rows", 1));
    EHO_CHECK("equihash_tmp_hash OOM -> reject (frees indices + rows)",
              eho_verify_rejects("equihash_tmp_hash", 1));
    EHO_CHECK("eh_row_data OOM -> reject (frees indices + rows + hashes)",
              eho_verify_rejects("eh_row_data", 1));
    EHO_CHECK("equihash_collision_rows OOM -> reject (frees the row table)",
              eho_verify_rejects("equihash_collision_rows", 1));
    EHO_CHECK("eh_row_xor OOM -> reject (frees both row tables)",
              eho_verify_rejects("eh_row_xor", 1));

    EHO_CHECK("(96,5) reference witness still verifies after every injection",
              eho_verify_965());
    return failures;
}

/* ── The partial unwinds: fail late, with siblings already built ──── */

static int eho_verifier_partial_unwinds(void)
{
    int failures = 0;
    printf("\n--- verifier: partial-row unwinds (Nth allocation fails) ---\n");

    /* num_indices is 32 for K=5, so the 8-wide loop builds all rows: n=5
     * fails mid-batch, n=8 on the first batch's last slot, n=32 on the last
     * row of the last batch (three partial-free counts). */
    EHO_CHECK("eh_row_data #5 OOM -> reject (unwinds 4 built rows)",
              eho_verify_rejects("eh_row_data", 5));
    EHO_CHECK("eh_row_data #8 OOM -> reject (unwinds 7 built rows)",
              eho_verify_rejects("eh_row_data", 8));
    EHO_CHECK("eh_row_data #32 OOM -> reject (unwinds 31 built rows)",
              eho_verify_rejects("eh_row_data", 32));

    /* The collision table is allocated once per round (K=5): n=2 and n=5
     * fail in a later round, freeing a merged row table. */
    EHO_CHECK("equihash_collision_rows #2 OOM -> reject (round 2)",
              eho_verify_rejects("equihash_collision_rows", 2));
    EHO_CHECK("equihash_collision_rows #5 OOM -> reject (final round)",
              eho_verify_rejects("equihash_collision_rows", 5));

    /* 16 + 8 + 4 + 2 + 1 = 31 merges over five rounds: n=2 leaves one merged
     * row to unwind in round 1, n=18 in round 2, n=31 is the final merge. */
    EHO_CHECK("eh_row_xor #2 OOM -> reject (unwinds 1 merged row, round 1)",
              eho_verify_rejects("eh_row_xor", 2));
    EHO_CHECK("eh_row_xor #18 OOM -> reject (unwinds 1 merged row, round 2)",
              eho_verify_rejects("eh_row_xor", 18));
    EHO_CHECK("eh_row_xor #31 OOM -> reject (final round's only merge)",
              eho_verify_rejects("eh_row_xor", 31));

    EHO_CHECK("(96,5) reference witness still verifies after every injection",
              eho_verify_965());
    return failures;
}

/* ── The solver's labels, including its cross-loop oom flag ───────── */

static int eho_solver_labels(void)
{
    int failures = 0;
    printf("\n--- solver: every allocation label gives up cleanly ---\n");

    EHO_CHECK("(48,5) solver finds a witness with no injection",
              g_solve_nonce >= 0);
    if (g_solve_nonce < 0)
        return failures;   /* nothing below can mean anything */

    {
        unsigned char out[256];
        struct blake2b_ctx st;
        bool ok = eho_solve_485(g_solve_nonce, out, sizeof(out));
        eho_state_485(&st, g_solve_nonce);
        EHO_CHECK("(48,5) solver witness verifies",
                  ok && equihash_is_valid_solution(&g_p485, &st, out,
                                                   g_p485.solution_width));
    }

    EHO_CHECK("eh_solve_rows OOM -> give up",
              eho_solve_rejects("eh_solve_rows", 1));
    EHO_CHECK("eh_solve_tmp_hash OOM -> give up (frees the row table)",
              eho_solve_rejects("eh_solve_tmp_hash", 1));
    EHO_CHECK("eh_row_data OOM -> give up (frees the leaf rows built so far)",
              eho_solve_rejects("eh_row_data", 1));
    EHO_CHECK("eh_row_data #5 OOM -> give up (unwinds 4 leaf rows)",
              eho_solve_rejects("eh_row_data", 5));
    EHO_CHECK("eh_solve_round_rows OOM -> give up (round 1)",
              eho_solve_rejects("eh_solve_round_rows", 1));
    EHO_CHECK("eh_solve_round_rows #2 OOM -> give up (round 2)",
              eho_solve_rejects("eh_solve_round_rows", 2));
    EHO_CHECK("eh_solve_round_rows #5 OOM -> give up (final round)",
              eho_solve_rejects("eh_solve_round_rows", 5));
    /* The two that set `oom` deep inside the run/pair double loop and
     * have to carry it out through both levels without leaking Xc. */
    EHO_CHECK("eh_row_xor OOM -> oom flag exits both loops",
              eho_solve_rejects("eh_row_xor", 1));
    EHO_CHECK("eh_row_xor #5 OOM -> oom flag exits both loops (4 rows merged)",
              eho_solve_rejects("eh_row_xor", 5));
    EHO_CHECK("eh_solve_round_grow OOM -> oom flag exits both loops",
              eho_solve_rejects("eh_solve_round_grow", 1));
    EHO_CHECK("eh_solve_round_grow #2 OOM -> oom flag exits both loops",
              eho_solve_rejects("eh_solve_round_grow", 2));
    /* Reached only in the final round, on a real full collision. */
    EHO_CHECK("eh_solve_indices OOM -> give up on the winning pair",
              eho_solve_rejects("eh_solve_indices", 1));

    {
        unsigned char out[256];
        EHO_CHECK("(48,5) solver still finds the witness after every injection",
                  eho_solve_485(g_solve_nonce, out, sizeof(out)));
    }
    return failures;
}

/* ── Characterization: refusals and PoW rejects off the OOM path ──── */

static bool eho_verify_965_bytes(const unsigned char *soln, size_t len)
{
    struct blake2b_ctx st;
    eho_state_965(&st);
    return equihash_is_valid_solution(&g_p965, &st, soln, len);
}

static int eho_verifier_refusals(void)
{
    int failures = 0;
    unsigned char zeros[69] = {0};
    printf("\n--- verifier: length refusals return before any work ---\n");

    EHO_CHECK("(96,5) solution_width is 68 bytes",
              g_p965.solution_width == 68 && g_soln965_len == 68);
    EHO_CHECK("one byte short of solution_width -> false",
              !eho_verify_965_bytes(g_soln965, g_p965.solution_width - 1));
    EHO_CHECK("one byte over solution_width -> false",
              !eho_verify_965_bytes(zeros, g_p965.solution_width + 1));
    EHO_CHECK("empty solution -> false",
              !eho_verify_965_bytes(g_soln965, 0));
    return failures;
}

static int eho_verifier_pow_rejects(void)
{
    int failures = 0;
    unsigned char zeros[68] = {0};
    unsigned char minimal[68];
    eh_index idx[32];
    printf("\n--- verifier: well-formed encodings that break the PoW rules ---\n");

    /* Every index decodes to 0: rows 0 and 1 are identical, so they collide,
     * but their indices are equal, so the distinct-indices check rejects. */
    EHO_CHECK("all-zero solution of exact width -> false (non-distinct)",
              !eho_verify_965_bytes(zeros, sizeof(zeros)));

    /* Swapping the first leaf pair keeps its collision but puts the larger
     * index first, so the order check rejects. */
    memcpy(idx, kValidIndices_96_5, sizeof(idx));
    idx[0] = kValidIndices_96_5[1];
    idx[1] = kValidIndices_96_5[0];
    size_t n = eh_get_minimal_from_indices(idx, 32,
                                           g_p965.collision_bit_length,
                                           minimal, sizeof(minimal));
    EHO_CHECK("swapped leaf pair encodes to solution_width",
              n == g_p965.solution_width);
    EHO_CHECK("swapped leaf pair (indices out of order) -> false",
              !eho_verify_965_bytes(minimal, n));

    /* A duplicated leaf index collides with itself and fails distinctness. */
    memcpy(idx, kValidIndices_96_5, sizeof(idx));
    idx[1] = idx[0];
    n = eh_get_minimal_from_indices(idx, 32,
                                    g_p965.collision_bit_length,
                                    minimal, sizeof(minimal));
    EHO_CHECK("duplicated leaf index encodes to solution_width",
              n == g_p965.solution_width);
    EHO_CHECK("duplicated leaf index (non-distinct) -> false",
              !eho_verify_965_bytes(minimal, n));
    return failures;
}

static int eho_solver_refusals(void)
{
    int failures = 0;
    unsigned char out[256];
    struct blake2b_ctx st;
    printf("\n--- solver: refusals return before any work ---\n");

    eho_state_485(&st, 0);
    EHO_CHECK("NULL params -> false",
              !equihash_basic_solve(NULL, &st, out, sizeof(out)));
    EHO_CHECK("NULL base_state -> false",
              !equihash_basic_solve(&g_p485, NULL, out, sizeof(out)));
    EHO_CHECK("NULL soln_out -> false",
              !equihash_basic_solve(&g_p485, &st, NULL, sizeof(out)));
    EHO_CHECK("buffer one byte short of solution_width -> false",
              !equihash_basic_solve(&g_p485, &st, out,
                                    g_p485.solution_width - 1));
    EHO_CHECK("zero-length buffer -> false",
              !equihash_basic_solve(&g_p485, &st, out, 0));
    return failures;
}

static int eho_solver_output_bytes(void)
{
    int failures = 0;
    unsigned char ref[256];
    unsigned char exact[64];
    unsigned char wide[64];
    printf("\n--- solver: output bytes are fixed by the witness ---\n");

    if (g_solve_nonce < 0) {
        EHO_CHECK("(48,5) witness nonce known for byte pinning", false);
        return failures;
    }

    bool ref_ok = eho_solve_485(g_solve_nonce, ref, sizeof(ref));
    EHO_CHECK("(48,5) reference solve succeeds", ref_ok);

    /* An exact-width buffer solves and writes exactly solution_width bytes;
     * the byte past the output length is never touched. */
    memset(exact, 0xA5, sizeof(exact));
    struct blake2b_ctx st;
    eho_state_485(&st, g_solve_nonce);
    bool exact_ok = equihash_basic_solve(&g_p485, &st, exact,
                                         g_p485.solution_width);
    EHO_CHECK("exact-width buffer solves", exact_ok);
    EHO_CHECK("exact-width bytes match the reference solve",
              memcmp(exact, ref, g_p485.solution_width) == 0);
    EHO_CHECK("byte past exact-width output is untouched",
              exact[g_p485.solution_width] == 0xA5);

    /* A wider buffer yields the same leading bytes and the same
     * solution_width-byte encoding. */
    memset(wide, 0xA5, sizeof(wide));
    eho_state_485(&st, g_solve_nonce);
    bool wide_ok = equihash_basic_solve(&g_p485, &st, wide, sizeof(wide));
    EHO_CHECK("wide buffer solves", wide_ok);
    EHO_CHECK("wide-buffer bytes match the reference solve",
              memcmp(wide, ref, g_p485.solution_width) == 0);
    EHO_CHECK("byte past solution_width in wide buffer is untouched",
              wide[g_p485.solution_width] == 0xA5);

    /* Nonces the entry loop tried before the first witness returned false,
     * and a rerun returns false again. */
    bool all_false = true;
    for (int nonce = 0; nonce < g_solve_nonce; nonce++) {
        unsigned char o[256];
        if (eho_solve_485(nonce, o, sizeof(o)))
            all_false = false;
    }
    EHO_CHECK("nonces before the first witness give up (false)", all_false);
    return failures;
}

/* ── The injector's own contract ──────────────────────────────────── */

static int eho_injector_contract(void)
{
    int failures = 0;
    printf("\n--- fault injector: Nth-allocation contract ---\n");

    /* One allocation per call carries "equihash_indices": arming the SECOND
     * lets the first call through and fires on the next; an ignored skip
     * credit would reject the first. */
    zcl_alloc_fault_fail_nth("equihash_indices", 2);
    bool first = eho_verify_965();
    bool still_armed = (zcl_alloc_fault_armed_label() != NULL);
    bool second = eho_verify_965();
    bool fired = (zcl_alloc_fault_armed_label() == NULL);
    zcl_alloc_fault_clear();

    EHO_CHECK("n=2 lets the first matching allocation through", first);
    EHO_CHECK("n=2 stays armed after the first call", still_armed);
    EHO_CHECK("n=2 fires on the second call", fired && !second);

    /* And a label nothing allocates never fires and never disturbs the
     * call it was armed across. */
    zcl_alloc_fault_fail_nth("equihash_no_such_label", 1);
    bool unaffected = eho_verify_965();
    bool untouched = (zcl_alloc_fault_armed_label() != NULL);
    zcl_alloc_fault_clear();
    EHO_CHECK("an unmatched label neither fires nor perturbs the verifier",
              unaffected && untouched);
    return failures;
}

/* ── The callers: a failed allocation is not a verdict on a header ── */

static const char *const kEhoVerifierAllocLabels[] = {
    "eh_expand_indices", "equihash_indices", "equihash_rows",
    "equihash_tmp_hash", "eh_row_data", "equihash_collision_rows",
    "eh_row_xor",
};

/* A regtest (48,5) header with a real solution. */
static bool eho_mine_header(struct block_header *out,
                            const struct chain_params *cp)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.hashMerkleRoot.data[0] = 0x51;
    blk.header.nTime = 1600000000u;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk.header.nBits = arith_uint256_get_compact(&pow_limit, false);
    bool ok = mine_block_pow(&blk, 1, cp, 0);
    if (ok)
        *out = blk.header;
    block_free(&blk);
    return ok;
}

/* The same header with a broken solution and PoW that still passes. */
static bool eho_break_solution(struct block_header *h,
                               const struct chain_params *cp)
{
    h->nSolution[0] ^= 0xFF;
    for (uint32_t i = 0; i < 100000; i++) {
        memcpy(h->nNonce.data, &i, sizeof(i));
        struct uint256 hash;
        block_header_get_hash(h, &hash);
        if (CheckProofOfWork(hash, h->nBits, &cp->consensus))
            return true;
    }
    return false;
}

static bool eho_row_verdict_is(const struct block_header *h,
                               const struct chain_params *cp,
                               enum block_row_verify_result want)
{
    struct uint256 hash;
    block_header_get_hash(h, &hash);
    return block_row_verify(hash.data, h->nBits, h, cp, true) == want;
}

/* Every allocation in the verifier failing: a local error with no DoS score that
 * P2P intake keeps retryable, from both header checks. A broken solution can be
 * rejected before a later allocation is reached, which is then still its verdict,
 * so `expect_all` is true only for a valid header, which reaches them all. */
static bool eho_alloc_failure_is_local(const struct block_header *h,
                                       const struct chain_params *cp,
                                       const char *unreached_label)
{
    bool all_local = true;
    for (size_t i = 0; i < sizeof(kEhoVerifierAllocLabels) /
                           sizeof(kEhoVerifierAllocLabels[0]); i++) {
        const char *label = kEhoVerifierAllocLabels[i];
        struct validation_state state;
        validation_state_init(&state);
        int dos = -1;
        zcl_alloc_fault_fail_nth(label, 1);
        bool accepted = check_block_header(h, &state, cp, true);
        bool header_fired = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        bool header_local = !accepted &&
                            validation_state_is_error(&state) &&
                            !validation_state_get_dos(&state, &dos) &&
                            msg_block_validation_is_retryable(&state);

        zcl_alloc_fault_fail_nth(label, 1);
        bool row_local =
            eho_row_verdict_is(h, cp, BLOCK_ROW_VERIFY_LOCAL_FAILURE);
        bool row_fired = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();

        /* A label fires, or it is the one this header is known not to reach. */
        bool unreached = unreached_label &&
                         strcmp(label, unreached_label) == 0;
        bool label_ok = (header_fired ? header_local : unreached) &&
                        (row_fired ? row_local : unreached);
        if (!label_ok) {
            printf("\n  (label '%s': header_fired=%d header_local=%d "
                   "row_fired=%d row_local=%d)\n",
                   label, header_fired, header_local, row_fired, row_local);
            all_local = false;
        }
    }
    return all_local;
}

static int eho_caller_verdicts(void)
{
    int failures = 0;
    printf("\n--- callers: allocation failure is a local error, not a verdict ---\n");

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    struct block_header good;
    block_header_init(&good);
    bool mined = eho_mine_header(&good, cp);
    EHO_CHECK("regtest header with a real solution mined", mined);
    if (!mined) {
        chain_params_select(CHAIN_MAIN);
        return failures;
    }

    struct validation_state state;
    validation_state_init(&state);
    EHO_CHECK("valid header passes check_block_header",
              check_block_header(&good, &state, cp, true));
    EHO_CHECK("valid header passes block_row_verify",
              eho_row_verdict_is(&good, cp, BLOCK_ROW_VERIFY_OK));
    EHO_CHECK("valid header: each failed allocation is local",
              eho_alloc_failure_is_local(&good, cp, NULL));
    validation_state_init(&state);
    EHO_CHECK("valid header still passes once memory is back",
              check_block_header(&good, &state, cp, true) &&
              eho_row_verdict_is(&good, cp, BLOCK_ROW_VERIFY_OK));

    struct block_header bad = good;
    EHO_CHECK("broken solution with passing PoW built",
              eho_break_solution(&bad, cp));
    int dos = 0;
    validation_state_init(&state);
    bool bad_rejected = !check_block_header(&bad, &state, cp, true);
    EHO_CHECK("invalid solution is rejected with DoS 100",
              bad_rejected && validation_state_get_dos(&state, &dos) &&
              dos == 100 &&
              strcmp(state.reject_reason, "invalid-solution") == 0);
    EHO_CHECK("invalid solution is BAD_EQUIHASH from block_row_verify",
              eho_row_verdict_is(&bad, cp, BLOCK_ROW_VERIFY_BAD_EQUIHASH));
    EHO_CHECK("invalid header: each failed allocation is local",
              eho_alloc_failure_is_local(&bad, cp, "eh_row_xor"));
    validation_state_init(&state);
    dos = 0;
    bad_rejected = !check_block_header(&bad, &state, cp, true);
    EHO_CHECK("invalid solution is the same verdict once memory is back",
              bad_rejected && validation_state_get_dos(&state, &dos) &&
              dos == 100 &&
              eho_row_verdict_is(&bad, cp, BLOCK_ROW_VERIFY_BAD_EQUIHASH));

    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── The failure count: real NULL returns, per thread ──────────
 *
 * Injected failures are not the production path. These requests are ones no
 * allocator can satisfy, so each checked allocator's own NULL branch runs. */

static volatile size_t g_eho_impossible_size = SIZE_MAX / 2;

static void *eho_count_on_worker(void *arg)
{
    uint64_t before = zcl_alloc_failure_count();
    void *p = zcl_malloc(g_eho_impossible_size, "eho_worker_impossible");
    *(uint64_t *)arg = zcl_alloc_failure_count() - before;
    free(p);
    return NULL;
}

/* AddressSanitizer aborts on a request this size unless told to return NULL. */
#if defined(__SANITIZE_ADDRESS__)
#define EHO_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define EHO_UNDER_ASAN 1
#endif
#endif

static int eho_failure_count_contract(void)
{
    int failures = 0;
    printf("\n--- failure count: real NULL returns, per thread ---\n");
#ifdef EHO_UNDER_ASAN
    printf("  (AddressSanitizer build: impossible-size requests not made)\n");
    return failures;
#endif

    uint64_t before = zcl_alloc_failure_count();
    void *ok_block = zcl_malloc(16, "eho_possible");
    EHO_CHECK("a successful allocation moves nothing",
              ok_block && zcl_alloc_failure_count() == before);

    void *p = zcl_malloc(g_eho_impossible_size, "eho_impossible");
    EHO_CHECK("zcl_malloc NULL counts one",
              !p && zcl_alloc_failure_count() == before + 1);
    p = zcl_calloc(g_eho_impossible_size, 4, "eho_impossible");
    EHO_CHECK("zcl_calloc NULL counts one",
              !p && zcl_alloc_failure_count() == before + 2);
    p = zcl_realloc(ok_block, g_eho_impossible_size, "eho_impossible");
    EHO_CHECK("zcl_realloc NULL counts one and keeps the block",
              !p && ok_block && zcl_alloc_failure_count() == before + 3);
    free(ok_block);

    uint64_t worker_moved = 0;
    uint64_t caller_before = zcl_alloc_failure_count();
    pthread_t th;
    bool started = pthread_create(&th, NULL, eho_count_on_worker,
                                  &worker_moved) == 0;
    if (started)
        pthread_join(th, NULL);
    EHO_CHECK("a worker counts its own failure", started && worker_moved == 1);
    EHO_CHECK("a worker's failure does not move the caller's count",
              zcl_alloc_failure_count() == caller_before);
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_equihash_oom(void)
{
    int failures = 0;
    printf("\n=== Equihash allocation-failure tests ===\n");

    equihash_params_init(&g_p965, 96, 5);
    g_soln965_len = eh_get_minimal_from_indices(kValidIndices_96_5, 32,
                                                g_p965.collision_bit_length,
                                                g_soln965, sizeof(g_soln965));

    equihash_params_init(&g_p485, 48, 5);
    for (int nonce = 0; nonce < 64 && g_solve_nonce < 0; nonce++) {
        unsigned char out[256];
        if (eho_solve_485(nonce, out, sizeof(out)))
            g_solve_nonce = nonce;
    }

    EHO_CHECK("(96,5) solution packs to the expected width",
              g_soln965_len == g_p965.solution_width);

    failures += eho_verifier_labels();
    failures += eho_verifier_partial_unwinds();
    failures += eho_solver_labels();
    failures += eho_verifier_refusals();
    failures += eho_verifier_pow_rejects();
    failures += eho_solver_refusals();
    failures += eho_solver_output_bytes();
    failures += eho_injector_contract();
    failures += eho_caller_verdicts();
    failures += eho_failure_count_contract();

    zcl_alloc_fault_clear();
    return failures;
}
