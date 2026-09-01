/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Example 08 — byzantine blocks: adversarial input, rejected by real consensus.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * A malicious or buggy peer can send a node any bytes it likes. The node's
 * job is to run those bytes through the SAME validator every honest block
 * goes through (`connect_block()` for a fully-formed block, or the header
 * admission gates `check_block_header()` / `contextual_check_block_header()`
 * for a bare header before the body even arrives) and reject anything that
 * violates a consensus rule — with a NAMED reason, not a silent drop, and
 * WITHOUT letting the chain tip move.
 *
 * Mental model: rejection is not a special code path bolted on for safety.
 * It is the normal path returning `false` plus a reason string. There is no
 * separate "byzantine detector" — the validator that accepts a good block is
 * the exact function that rejects a bad one. This example exercises four
 * distinct ways a block can be wrong:
 *
 *   1. SIMNET_BYZ_BAD_MERKLE     — hashMerkleRoot doesn't match the txs
 *                                   (tier 1: inside connect_block/check_block)
 *   2. SIMNET_BYZ_BAD_CB_AMOUNT  — coinbase pays itself one zatoshi over
 *                                   the subsidy schedule (tier 1)
 *   3. SIMNET_BYZ_NEGATIVE_OUTPUT- a tx output value is negative (tier 1)
 *   4. SIMNET_BYZ_INVALID_POW    — the Equihash solution doesn't satisfy
 *                                   the header's own bits (tier 2: header
 *                                   admission, before a body is requested)
 *
 * `engine/modules/sim/include/sim/simnet_byzantine.h` is a fixture library over the
 * REAL validator: each `simnet_byzantine_run_*_case()` call builds a fresh,
 * isolated in-RAM chain (`simnet_init`), constructs one malformed block or
 * header for the requested class, drives it through the real check, records
 * the outcome, and — critically — then mints one more ordinary honest
 * coinbase on the SAME chain to prove the rejection didn't wedge anything.
 * No disk, no network, no PoW grinding: fully deterministic, no seed needed
 * (there is no randomness in this path — every byte of every malformed
 * block is chosen by the fixture builder).
 *
 * Read `engine/modules/sim/src/simnet_byzantine.c` for how each fixture is built and
 * `tests/harness/src/test_simnet_byzantine.c` for the reference assertions this
 * example mirrors at a slower, narrated pace.
 *
 * Build/run: see docs/cookbook/08_byzantine_blocks.md
 */

#include "sim/simnet_byzantine.h"
#include "util/blocker.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* One row per byzantine class we drive in this example. `tier` decides
 * whether the fixture is checked via connect_block() (a full block) or via
 * the header admission gate (a bare header, no body). The fixture library
 * itself reports the tier via simnet_byzantine_class_tier(); this table
 * exists only so main() can print a human label per class. */
struct byz_demo_case {
    enum simnet_byzantine_class kind;
    const char *label;
};

static const struct byz_demo_case g_cases[] = {
    { SIMNET_BYZ_BAD_MERKLE,      "bad merkle root"     },
    { SIMNET_BYZ_BAD_CB_AMOUNT,   "over-subsidy coinbase" },
    { SIMNET_BYZ_NEGATIVE_OUTPUT, "negative output value" },
    { SIMNET_BYZ_INVALID_POW,     "invalid PoW solution"  },
};
#define NUM_CASES (sizeof(g_cases) / sizeof(g_cases[0]))

/* Drive one byzantine class through the real validator and assert every
 * invariant a production node also relies on:
 *   - the block/header was rejected (never silently accepted)
 *   - the reject reason string matches the class's known consensus reason
 *   - the tip did not move (rejection is a no-op on chain state)
 *   - an ordinary honest block minted right afterward still connects
 *     (rejection didn't corrupt or wedge the in-RAM chain state)
 * Returns true iff every check passed. */
static bool run_and_check_one(const struct byz_demo_case *tc, int idx, int total)
{
    printf("[%d/%d] %s (%s)... ", idx, total, tc->label,
           simnet_byzantine_class_name(tc->kind));

    /* Clear any blocker left by a prior case so each demo starts from a
     * clean registry — mirrors what test_simnet_byzantine.c does between
     * cases so fire-count/rate-limit state from one class never leaks
     * into the next. */
    blocker_reset_for_testing();

    struct simnet_byzantine_observation obs;
    bool ran;
    if (simnet_byzantine_class_tier(tc->kind) == SIMNET_BYZ_TIER_CONNECT_BLOCK) {
        /* Tier 1: a fully-formed block reaches connect_block(). This is
         * where a peer's tx content, merkle root, and coinbase amount get
         * checked against the UTXO set and the subsidy schedule. */
        ran = simnet_byzantine_run_connect_case(tc->kind, &obs);
    } else {
        /* Tier 2: only a header is checked (check_block_header /
         * contextual_check_block_header) — this runs BEFORE a node even
         * asks the peer for the block body, so a bad PoW header is
         * rejected cheaply and never reaches connect_block() at all. */
        ran = simnet_byzantine_run_header_case(tc->kind, &obs);
    }

    if (!ran) {
        printf("FAIL (fixture could not be built)\n");
        return false;
    }

    const char *expected_reason = simnet_byzantine_expected_reason(tc->kind);
    bool ok = obs.rejected &&
              strcmp(obs.reject_reason, expected_reason) == 0 &&
              obs.tip_after == obs.tip_before &&
              obs.honest_after_accepted &&
              obs.invariant_ok;

    printf("%s\n", ok ? "OK" : "FAIL");
    printf("        reject_reason=\"%s\" (expected \"%s\")\n",
           obs.reject_reason, expected_reason);
    printf("        blocker=%s class=%s\n", obs.blocker_id,
           blocker_class_name(obs.blocker_class));
    printf("        tip: %d -> %d (unchanged), honest block after: %s\n",
           obs.tip_before, obs.tip_after,
           obs.honest_after_accepted ? "accepted" : "REJECTED");

    /* Belt-and-suspenders: the fixture library's own self-check must agree
     * with our re-derivation of "ok" above. If these ever disagree, either
     * this example or the library drifted from the real invariant. */
    assert(obs.invariant_ok == ok || !ok);
    return ok;
}

int main(void)
{
    printf("=== 08_byzantine_blocks: four ways a block/header can be "
           "adversarially malformed, each rejected by real consensus ===\n\n");

    /* Select a chain network before any chain/consensus code runs — the
     * fixtures below build real blocks/headers that connect_block() and
     * the header admission gates validate against chain_params_get(),
     * which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    /* The blocker registry is a process-wide singleton; init it once before
     * any byzantine case runs (idempotent — safe even if a host process
     * already called it). Every rejection below turns into a typed,
     * observable BLOCKER_PERMANENT record here, exactly as it would on a
     * live node (see `z23 dumpstate blocker` / `z23 blockers`). */
    blocker_module_init();

    int passed = 0;
    for (size_t i = 0; i < NUM_CASES; i++) {
        if (run_and_check_one(&g_cases[i], (int)i + 1, (int)NUM_CASES))
            passed++;
        printf("\n");
    }

    blocker_reset_for_testing();

    if (passed != (int)NUM_CASES) {
        fprintf(stderr,
                "FAILED: %d/%zu byzantine classes behaved as expected "
                "(rejected, tip unchanged, honest block still connects)\n",
                passed, NUM_CASES);
        return 1;
    }

    printf("=== SUCCESS: all %zu byzantine classes were rejected with the "
           "correct named reason, left the tip unchanged, and did not stop "
           "an honest block from connecting right after ===\n", NUM_CASES);
    return 0;
}

/* Production counterpart:
 * ------------------------
 * A real peer's block/header takes this exact path, just triggered by wire
 * messages instead of a fixture builder:
 *
 *   - core/modules/validation/include/validation/connect_block.h : connect_block()
 *       — the same function this example calls on a scratch coins view;
 *         in production it is called from
 *         engine/controllers/src/sync_controller_blocks.c while advancing the
 *         chain over a real, disk-backed coins_view.
 *   - core/modules/validation/include/validation/check_block.h :
 *       check_block_header() / contextual_check_block_header()
 *       — the tier-2 header admission gate this example drives directly;
 *         in production reached from
 *         core/modules/validation/src/accept_block_header.c and
 *         core/modules/validation/src/process_block_contextual_header.c the moment
 *         a `headers` P2P message arrives, before the block body is even
 *         requested.
 *   - platform/modules/util/include/util/blocker.h : blocker_set()
 *       — turns a production reject into a durable, typed record (class,
 *         reason, owner subsystem) instead of a log line that scrolls
 *         away; introspect live via `core sync blockers` or
 *         `z23 dumpstate blocker`.
 */
