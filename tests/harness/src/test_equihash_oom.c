/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Allocation-failure coverage for the Equihash proof-of-work verifier
 * and the generic Wagner solver beside it (core/modules/crypto/src/equihash.c).
 *
 * WHY THIS EXISTS. equihash_is_valid_solution() runs on every inbound
 * block header, from any peer, before the header is trusted for
 * anything. It allocates seven distinct times per call — the index
 * array, the expanded-index scratch inside eh_get_indices_from_minimal,
 * the row table, the batched hash scratch, one buffer per row, the
 * per-round collision table, and one buffer per merged row — and every
 * failure branch is a hand-rolled multi-pointer unwind. Nothing proved
 * any of those unwinds ran, and an unwind that frees the wrong count of
 * partially-built rows is a double-free or a wild free on the header
 * path. equihash_basic_solve() has the same shape plus an `oom` flag
 * that has to thread out of a doubly-nested loop without leaking the
 * round table it was half-way through filling.
 *
 * HOW. zcl_alloc_fault_fail_nth (base/safe_alloc.h) makes the Nth
 * checked allocation carrying an exact label return NULL once. Every
 * case below asserts BOTH halves: the same call returns true with no
 * injection and false with it, and the hook reports that it actually
 * fired. Asserting only "did not crash" would pass just as happily if
 * the injection never landed.
 *
 * N > 1 is the point of the partial cases. Failing the FIRST allocation
 * of a label runs the sibling-freeing loops zero times; failing the
 * fifth eh_row_data is what makes the batch-of-8 unwind free four
 * already-built rows, and failing the second eh_row_xor is what makes
 * the merge unwind free one already-merged row out of a half-filled
 * collision table.
 *
 * REACH NOTE (why only the 8-wide row loop is covered). The row build
 * has three arms — 8-wide, 4-wide, then scalar — selected purely by
 * num_indices, which is 2^K. equihash_solution_params accepts exactly
 * four solution lengths, giving K in {5, 7, 9}, so num_indices is
 * always a multiple of 8 and the 4-wide and scalar arms are unreachable
 * for every parameter set the node can be handed. Parameter sets with
 * K < 3 do reach them, but equihash_basic_solve and
 * equihash_is_valid_solution disagree there (the solver emits a
 * solution the verifier rejects, because solution_width truncates when
 * 2^K * (collision_bit_length + 1) is not a whole number of bytes), so
 * there is no "true without injection" baseline to test against. Those
 * two arms are therefore left uncovered on purpose rather than covered
 * by a test that cannot fail. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"

/* (N=96, K=5) witness from the Zcash reference suite — the same vector
 * test_domain_consensus_equihash.c pins, for the BLAKE2b state seeded
 * by the fixed input string + nonce {1, 0, ...}. */
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
 * that the hook fired AND the verifier rejected. Disarms unconditionally
 * so one failing case cannot poison the next. */
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

    /* num_indices is 32 for K=5, so the 8-wide loop builds all of them.
     * n=5 fails mid-batch (four rows already built), n=8 fails on the
     * last slot of the first batch, n=32 on the very last row of the
     * last batch — three different partial-free counts. */
    EHO_CHECK("eh_row_data #5 OOM -> reject (unwinds 4 built rows)",
              eho_verify_rejects("eh_row_data", 5));
    EHO_CHECK("eh_row_data #8 OOM -> reject (unwinds 7 built rows)",
              eho_verify_rejects("eh_row_data", 8));
    EHO_CHECK("eh_row_data #32 OOM -> reject (unwinds 31 built rows)",
              eho_verify_rejects("eh_row_data", 32));

    /* The collision table is allocated once per round; K=5 rounds. n=2
     * and n=5 fail in a later round, where hash_len and len_indices have
     * already shifted and the row table being freed is a merged one. */
    EHO_CHECK("equihash_collision_rows #2 OOM -> reject (round 2)",
              eho_verify_rejects("equihash_collision_rows", 2));
    EHO_CHECK("equihash_collision_rows #5 OOM -> reject (final round)",
              eho_verify_rejects("equihash_collision_rows", 5));

    /* 16 + 8 + 4 + 2 + 1 = 31 merges across the five rounds. n=2 leaves
     * one merged row to unwind in round 1; n=18 leaves one in round 2;
     * n=31 is the single merge of the final round. */
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

/* ── The injector's own contract ──────────────────────────────────── */

static int eho_injector_contract(void)
{
    int failures = 0;
    printf("\n--- fault injector: Nth-allocation contract ---\n");

    /* Exactly one allocation per call carries "equihash_indices", so
     * arming the SECOND one must let the first call through untouched
     * and stay armed, then fire on the next call. If the skip credit
     * were ignored, the first call would already reject. */
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
    failures += eho_injector_contract();

    zcl_alloc_fault_clear();
    return failures;
}
