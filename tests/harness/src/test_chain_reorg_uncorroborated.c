/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the eclipse-resistant best-header SWITCH corroboration policy
 * (net/header_corroboration.h). Synthetic block-index branches + synthetic
 * address groups; no network, no main_state — the gate walks pprev/pskip only.
 *
 * Coverage:
 *   - corroborated switch proceeds (ALLOW once a 2nd distinct group serves it)
 *   - un-corroborated deep switch HOLDS, then proceeds on 2nd-group announce
 *   - single-peer plain EXTENSION is never gated
 *   - shallow switch (<= MIN_SWITCH_DEPTH) is never gated
 *   - checkpoint-covered fork is exempt even un-corroborated
 *   - -nocorroborate (disabled) never holds
 *   - note()/groups() distinct-group counting + dedup
 *   - a held switch auto-clears when the branch is abandoned/absorbed
 */

#include "test/test_core.h"

#include "net/header_corroboration.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CR_CHECK(name, expr) do { \
    printf("chain_reorg_uncorroborated: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Synthetic block-index pool ──────────────────────────────────────── */

#define CR_POOL 64
static struct block_index cr_nodes[CR_POOL];
static struct uint256     cr_hashes[CR_POOL];
static int                cr_used;

static void cr_pool_reset(void)
{
    memset(cr_nodes, 0, sizeof(cr_nodes));
    memset(cr_hashes, 0, sizeof(cr_hashes));
    cr_used = 0;
}

static struct block_index *cr_mk(int height, uint64_t work,
                                 struct block_index *prev, uint8_t seed)
{
    if (cr_used >= CR_POOL)
        return NULL;
    int i = cr_used++;
    struct block_index *bi = &cr_nodes[i];
    struct uint256 *hp = &cr_hashes[i];
    block_index_init(bi);
    memset(hp, seed, sizeof(*hp));
    hp->data[0] = (uint8_t)height;
    hp->data[1] = seed;
    hp->data[2] = (uint8_t)i;
    bi->nHeight = height;
    bi->hashBlock = *hp;
    bi->phashBlock = &bi->hashBlock;
    bi->pprev = prev;
    arith_uint256_set_u64(&bi->nChainWork, work);
    block_index_build_skip(bi);
    return bi;
}

/* Distinct synthetic address groups. */
static const unsigned char GROUP_A[] = {0xA1, 0xA2, 0xA3};
static const unsigned char GROUP_B[] = {0xB1, 0xB2, 0xB3};
static const unsigned char GROUP_C[] = {0xC1, 0xC2, 0xC3};

/* Build a main chain g..c[len-1] and a fork branch off c[fork_idx] of `flen`
 * blocks with per-block work `fwork_step`. Returns current tip and cand tip. */
static void cr_build(struct block_index **out_current,
                     struct block_index **out_cand,
                     int main_len, int fork_idx,
                     int flen, uint64_t fwork_step)
{
    struct block_index *chain[CR_POOL];
    struct block_index *prev = NULL;
    for (int h = 0; h < main_len; h++) {
        chain[h] = cr_mk(h, (uint64_t)(h + 1) * 10ULL, prev, 0x10);
        prev = chain[h];
    }
    *out_current = chain[main_len - 1];

    struct block_index *fp = chain[fork_idx];
    struct block_index *fprev = fp;
    uint64_t fw = fp->nChainWork.pn[0]; /* small values fit low word */
    struct block_index *ftip = fp;
    for (int k = 0; k < flen; k++) {
        fw += fwork_step;
        ftip = cr_mk(fp->nHeight + 1 + k, fw, fprev, 0x20);
        fprev = ftip;
    }
    *out_cand = ftip;
}

/* ── Tests ───────────────────────────────────────────────────────────── */

static int test_note_and_groups(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    struct uint256 h;
    memset(&h, 0x55, sizeof(h));

    CR_CHECK("unknown hash has 0 groups",
             header_corroboration_groups(&h) == 0);
    header_corroboration_note(&h, GROUP_A, sizeof(GROUP_A));
    CR_CHECK("1 group after first note",
             header_corroboration_groups(&h) == 1);
    header_corroboration_note(&h, GROUP_A, sizeof(GROUP_A));
    CR_CHECK("same group de-duped (still 1)",
             header_corroboration_groups(&h) == 1);
    header_corroboration_note(&h, GROUP_B, sizeof(GROUP_B));
    CR_CHECK("distinct group -> 2 (corroborated)",
             header_corroboration_groups(&h) == 2);
    header_corroboration_note(&h, GROUP_C, sizeof(GROUP_C));
    CR_CHECK("third distinct group -> 3",
             header_corroboration_groups(&h) == 3);
    return failures;
}

static int test_extension_never_gated(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    /* main chain of 10, candidate is a direct child of the tip (extension). */
    struct block_index *chain[16];
    struct block_index *prev = NULL;
    for (int h = 0; h < 10; h++) {
        chain[h] = cr_mk(h, (uint64_t)(h + 1) * 10ULL, prev, 0x10);
        prev = chain[h];
    }
    struct block_index *current = chain[9];
    struct block_index *child = cr_mk(10, 110, current, 0x10);

    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, child, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("plain extension -> ALLOW", g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("extension raises no hold", !header_corroboration_hold_active());
    return failures;
}

static int test_shallow_switch_not_gated(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    /* fork off h8 (depth = 9-8 = 1 <= MIN_SWITCH_DEPTH), higher work. */
    struct block_index *current, *cand;
    cr_build(&current, &cand, 10, 8, 3, 40);
    CR_CHECK("shallow switch is strictly better",
             arith_uint256_compare(&cand->nChainWork,
                                   &current->nChainWork) > 0);
    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("shallow switch -> ALLOW (never gated)",
             g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("shallow switch raises no hold",
             !header_corroboration_hold_active());
    return failures;
}

static int test_deep_switch_holds_then_proceeds(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    /* fork off h3 (depth = 9-3 = 6... need > 6): use main_len=11 -> depth 7. */
    struct block_index *current, *cand;
    cr_build(&current, &cand, 11, 3, 9, 15);
    CR_CHECK("deep switch is strictly better",
             arith_uint256_compare(&cand->nChainWork,
                                   &current->nChainWork) > 0);

    /* Only GROUP_A has served the branch tip -> un-corroborated. */
    header_corroboration_note(cand->phashBlock, GROUP_A, sizeof(GROUP_A));
    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("deep un-corroborated switch -> HOLD",
             g == HEADER_CORROBORATION_HOLD);
    CR_CHECK("hold is active", header_corroboration_hold_active());

    struct header_corroboration_hold snap;
    bool got = header_corroboration_hold_get(&snap);
    CR_CHECK("hold snapshot available", got);
    CR_CHECK("hold fork height correct", got && snap.fork_height == 3);
    CR_CHECK("hold switch depth > K",
             got && snap.switch_depth > HEADER_CORROBORATION_MIN_SWITCH_DEPTH);
    CR_CHECK("hold names the peer",
             got && strcmp(snap.peer_name, "peerA") == 0);

    /* A second distinct group serves the same branch tip -> corroborated. */
    header_corroboration_note(cand->phashBlock, GROUP_B, sizeof(GROUP_B));
    g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_B, sizeof(GROUP_B), "peerB");
    CR_CHECK("corroborated switch -> ALLOW", g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("hold cleared on corroboration",
             !header_corroboration_hold_active());
    return failures;
}

static int test_corroboration_on_ancestor(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    struct block_index *current, *cand;
    cr_build(&current, &cand, 11, 3, 9, 15);

    /* Corroborate an ANCESTOR of the tip (above the fork), not the tip. */
    struct block_index *anc = cand->pprev->pprev; /* two below tip */
    header_corroboration_note(anc->phashBlock, GROUP_A, sizeof(GROUP_A));
    header_corroboration_note(anc->phashBlock, GROUP_B, sizeof(GROUP_B));

    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_B, sizeof(GROUP_B), "peerB");
    CR_CHECK("ancestor-above-fork corroboration -> ALLOW",
             g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("no hold when ancestor corroborated",
             !header_corroboration_hold_active());
    return failures;
}

static int test_checkpoint_exempt(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    struct block_index *current, *cand;
    cr_build(&current, &cand, 11, 3, 9, 15);

    /* fork at h3; checkpoint_last_height >= 3 exempts it even un-corroborated. */
    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 5, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("checkpoint-covered fork -> ALLOW (exempt)",
             g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("checkpoint-covered fork raises no hold",
             !header_corroboration_hold_active());
    return failures;
}

static int test_disabled_never_holds(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    header_corroboration_set_enabled(false);
    struct block_index *current, *cand;
    cr_build(&current, &cand, 11, 3, 9, 15);
    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("disabled -> ALLOW", g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("disabled raises no hold", !header_corroboration_hold_active());
    header_corroboration_set_enabled(true);
    return failures;
}

static int test_hold_abandoned_on_advance(void)
{
    int failures = 0;
    header_corroboration_test_reset();
    cr_pool_reset();

    struct block_index *current, *cand;
    cr_build(&current, &cand, 11, 3, 9, 15);
    header_corroboration_note(cand->phashBlock, GROUP_A, sizeof(GROUP_A));
    enum header_corroboration_gate g = header_corroboration_gate_switch(
        current, cand, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("switch held", g == HEADER_CORROBORATION_HOLD &&
             header_corroboration_hold_active());

    /* The honest chain advances past the candidate's work: a new best header
     * that outweighs the held candidate. The next gate call must clear the
     * now-moot hold. */
    struct block_index *stronger = cr_mk(20, 1000000, NULL, 0x30);
    g = header_corroboration_gate_switch(
        stronger, cand, 0, GROUP_A, sizeof(GROUP_A), "peerA");
    CR_CHECK("moot switch -> ALLOW", g == HEADER_CORROBORATION_ALLOW);
    CR_CHECK("abandoned hold cleared", !header_corroboration_hold_active());
    return failures;
}

int test_chain_reorg_uncorroborated(void)
{
    printf("\n=== header corroboration (eclipse resistance) tests ===\n");
    int failures = 0;
    failures += test_note_and_groups();
    failures += test_extension_never_gated();
    failures += test_shallow_switch_not_gated();
    failures += test_deep_switch_holds_then_proceeds();
    failures += test_corroboration_on_ancestor();
    failures += test_checkpoint_exempt();
    failures += test_disabled_never_holds();
    failures += test_hold_abandoned_on_advance();
    /* Leave the policy enabled for any later group sharing the process. */
    header_corroboration_set_enabled(true);
    printf("chain_reorg_uncorroborated: %d failures\n", failures);
    return failures;
}
