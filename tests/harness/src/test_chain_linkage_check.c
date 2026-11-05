/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack check 1 + the HOLD latch
 * (core/modules/validation/src/chain_linkage_check.c):
 *
 *   - healthy +1 advance passes, no blocker (non-fire);
 *   - label splice (pprev height != h-1) REFUSES the move, registers
 *     chain.linkage_violation, latches the HOLD — process alive (the
 *     crash-only contract);
 *   - HOLD refuses moves at/past the divergence, allows rewinds below;
 *   - clear releases the hold + blocker, moves pass again;
 *   - depth-10 reorg (rewind + reconnect) never fires (non-fire);
 *   - genesis install and >+1 jumps are scoped out of pointer identity
 *     but the label check still applies (non-fire on healthy labels). */

#include "test/test_core.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define CLC_CHECK(name, expr) do {                  \
    printf("chain_linkage_check: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static struct block_index *clc_insert(struct main_state *ms,
                                      struct uint256 *hash, int h,
                                      struct block_index *prev, uint8_t salt)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[2] = salt;

    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi) return NULL;
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    pi->nTx = 1;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    pi->pprev = prev;
    return pi;
}

/* Heights 0..count-1, each linked to the previous, then walked as +1
 * window advances. ok short-circuits only the advance loop. */
static bool clc_insert_and_advance_heights(struct main_state *ms,
                                           struct uint256 *hash,
                                           struct block_index **out,
                                           int count, uint8_t salt)
{
    struct block_index *prev = NULL;
    bool ok = true;
    for (int i = 0; i < count; i++) {
        out[i] = clc_insert(ms, &hash[i], i, prev, salt);
        ok = ok && out[i] != NULL;
        prev = out[i];
    }
    for (int i = 0; i < count && ok; i++)
        ok = active_chain_move_window_tip(&ms->chain_active, out[i]);
    return ok;
}

/* The refused move always runs. Later queries short-circuit on ok. */
static bool clc_label_splice_hold_latched(struct main_state *ms,
                                          struct block_index *spliced,
                                          struct block_index *kept_tip,
                                          bool ok)
{
    bool refused = !active_chain_move_window_tip(&ms->chain_active, spliced);
    ok = ok && refused;
    ok = ok && chain_linkage_hold_active();
    ok = ok && chain_linkage_hold_refuse_from() == 11;
    ok = ok && blocker_exists("chain.linkage_violation");
    ok = ok && blocker_class_for("chain.linkage_violation") ==
                   BLOCKER_PERMANENT;
    ok = ok && chain_linkage_violations_total() == 1;
    /* Crash-only: window tip unchanged, process obviously alive. */
    ok = ok && active_chain_tip(&ms->chain_active) == kept_tip;
    return ok;
}

/* 1. Healthy chain: genesis install + sequential +1 advances pass,
 * no blocker, no hold. */
static int clc_healthy_genesis_advances(void)
{
    struct main_state ms; main_state_init(&ms);
    static struct uint256 h[16];
    struct block_index *b[16];
    int failures = 0;
    bool ok = clc_insert_and_advance_heights(&ms, h, b, 12, 0x11);
    ok = ok && !chain_linkage_hold_active();
    ok = ok && !blocker_exists("chain.linkage_violation");
    ok = ok && chain_linkage_violations_total() == 0;
    CLC_CHECK("healthy genesis + 11 sequential advances pass", ok);
    main_state_free(&ms);
    return failures;
}

/* 2. Label splice fires at block 1: a block whose pprev height label
 * is 7 below (the +6/+7 splice boundary shape) is REFUSED. */
static int clc_label_splice_hold_and_clear(void)
{
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct main_state ms; main_state_init(&ms);
    static struct uint256 h[16];
    struct block_index *b[16];
    int failures = 0;
    bool ok = clc_insert_and_advance_heights(&ms, h, b, 5, 0x22);
    /* The spliced block: built on b[4] (h=4) but LABELED h=11. */
    b[5] = clc_insert(&ms, &h[5], 11, b[4], 0x22);
    ok = ok && b[5] != NULL;
    ok = clc_label_splice_hold_latched(&ms, b[5], b[4], ok);
    CLC_CHECK("label splice refused at block 1 + HOLD + blocker", ok);

    /* 3. HOLD semantics on the same state: a rewind BELOW the
     * divergence passes; a healthy-looking move AT/PAST it refuses. */
    bool rewind_ok = active_chain_move_window_tip(&ms.chain_active, b[2]);
    uint64_t refusals_before = chain_linkage_hold_refusals_total();
    /* healthy-labeled block at 11 building correctly would still be
     * refused by the hold (refuse_from=11): build labels 3..11. */
    struct block_index *p = b[2];
    static struct uint256 h2[16];
    struct block_index *c = NULL;
    for (int i = 3; i <= 11; i++) {
        c = clc_insert(&ms, &h2[i], i, p, 0x33);
        p = c;
    }
    bool held = !active_chain_move_window_tip(&ms.chain_active, c);
    bool ok2 = rewind_ok && held &&
               chain_linkage_hold_refusals_total() > refusals_before;
    CLC_CHECK("HOLD: rewind below passes, move at/past refuses", ok2);

    /* 4. Clear releases hold + blocker; the held move now passes. */
    chain_linkage_hold_clear("linkage");
    bool ok3 = !chain_linkage_hold_active() &&
               !blocker_exists("chain.linkage_violation") &&
               active_chain_move_window_tip(&ms.chain_active, c);
    CLC_CHECK("clear releases hold + blocker; move passes", ok3);
    main_state_free(&ms);
    return failures;
}

/* 5. Depth-10 reorg: rewind to the fork then reconnect a heavier
 * branch block-by-block — never fires (non-fire proof). */
static int clc_depth10_reorg_reconnect(void)
{
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct main_state ms; main_state_init(&ms);
    static struct uint256 h[40];
    struct block_index *a[20], *bb[20];
    int failures = 0;
    /* branch A: 0..14 */
    bool ok = clc_insert_and_advance_heights(&ms, h, a, 15, 0x44);
    /* branch B forks at height 4 (depth-10 reorg), extends to 16 */
    struct block_index *prev = a[4];
    for (int i = 5; i <= 16; i++) {
        bb[i] = clc_insert(&ms, &h[20 + i], i, prev, 0x55);
        ok = ok && bb[i] != NULL;
        prev = bb[i];
    }
    /* rewind to the fork point, then reconnect B one by one */
    ok = ok && active_chain_move_window_tip(&ms.chain_active, a[4]);
    for (int i = 5; i <= 16 && ok; i++)
        ok = active_chain_move_window_tip(&ms.chain_active, bb[i]);
    ok = ok && !chain_linkage_hold_active();
    ok = ok && !blocker_exists("chain.linkage_violation");
    ok = ok && active_chain_tip(&ms.chain_active) == bb[16];
    CLC_CHECK("depth-10 reorg rewind+reconnect never fires", ok);
    main_state_free(&ms);
    return failures;
}

/* 6. Cold-import shape: a jump far past the window (> +1) with
 * healthy labels passes (scoped out of pointer identity). */
static int clc_seed_jump_healthy_labels(void)
{
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct main_state ms; main_state_init(&ms);
    static struct uint256 h[40];
    struct block_index *prev = NULL, *bi = NULL;
    bool ok = true;
    int failures = 0;
    for (int i = 0; i < 30; i++) {
        bi = clc_insert(&ms, &h[i], i, prev, 0x66);
        ok = ok && bi != NULL;
        prev = bi;
    }
    /* window empty (height -1): seed-jump straight to 29 */
    ok = ok && active_chain_move_window_tip(&ms.chain_active, bi);
    ok = ok && !chain_linkage_hold_active();
    ok = ok && !blocker_exists("chain.linkage_violation");
    CLC_CHECK("seed jump (> +1, healthy labels) passes", ok);
    main_state_free(&ms);
    return failures;
}

/* 7. +1 advance whose pprev is NOT the window tip object (a
 * single-move 1-block fork switch) is ALLOWED — fill_window rewrites
 * the window from the pprev walk — but COUNTED as a diagnostic.
 * Refusing it would false-HOLD routine network reorgs. */
static int clc_offtip_fork_switch_counted(void)
{
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct main_state ms; main_state_init(&ms);
    static struct uint256 h[8];
    struct block_index *b0, *b1, *b1x, *b2;
    int failures = 0;
    b0 = clc_insert(&ms, &h[0], 0, NULL, 0x77);
    b1 = clc_insert(&ms, &h[1], 1, b0, 0x77);
    b1x = clc_insert(&ms, &h[2], 1, b0, 0x78); /* sibling at h=1 */
    bool ok = b0 && b1 && b1x;
    ok = ok && active_chain_move_window_tip(&ms.chain_active, b0);
    ok = ok && active_chain_move_window_tip(&ms.chain_active, b1);
    /* b2 builds on the SIBLING b1x, not the window tip b1 */
    b2 = clc_insert(&ms, &h[3], 2, b1x, 0x78);
    ok = ok && b2 != NULL;
    uint64_t before = chain_linkage_offtip_switches_total();
    ok = ok && active_chain_move_window_tip(&ms.chain_active, b2);
    ok = ok && chain_linkage_offtip_switches_total() == before + 1;
    ok = ok && !blocker_exists("chain.linkage_violation");
    ok = ok && !chain_linkage_hold_active();
    /* The window was rewritten onto the new branch. */
    ok = ok && active_chain_at(&ms.chain_active, 1) == b1x;
    ok = ok && active_chain_tip(&ms.chain_active) == b2;
    CLC_CHECK("+1 fork switch allowed + counted (no false HOLD)", ok);
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    main_state_free(&ms);
    return failures;
}

/* ── Mutation-gap tests: hold-slot bookkeeping, snapshot, clear, reset ── */

struct clc_ev_capture {
    int      count;
    uint32_t last_peer;
};

static void clc_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)type; (void)payload; (void)payload_len;
    struct clc_ev_capture *cap = ctx;
    cap->count++;
    cap->last_peer = peer_id;
}

static bool clc_snapshot_ids_are(const char *want)
{
    char ids[64];
    memset(ids, 'Z', sizeof(ids));
    chain_linkage_hold_snapshot(NULL, NULL, ids, (int)sizeof(ids), NULL, 0);
    return strcmp(ids, want) == 0;
}

static struct block_index clc_bare(int h, struct block_index *prev)
{
    struct block_index bi;
    memset(&bi, 0, sizeof(bi));
    bi.nHeight = h;
    bi.pprev = prev;
    return bi;
}

/* hold_set argument validation: a one-character id and height 0 are legal. */
static int clc_hold_set_validation(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set(NULL, 5, "r");
    chain_linkage_hold_set("", 5, "r");
    chain_linkage_hold_set("a", -1, "r");
    CLC_CHECK("hold_set refuses NULL id, empty id, negative height",
              !chain_linkage_hold_active());
    CLC_CHECK("refuse_from is -1 while no hold is latched",
              chain_linkage_hold_refuse_from() == -1);
    chain_linkage_hold_set("a", 0, "r");
    CLC_CHECK("one-character id at height 0 latches",
              chain_linkage_hold_active() &&
              chain_linkage_hold_refuse_from() == 0);
    chain_linkage_hold_set("b", 5, "r");
    CLC_CHECK("minimum stays 0 when a higher hold joins",
              chain_linkage_hold_refuse_from() == 0);
    chain_linkage_reset_for_testing();
    return failures;
}

/* Lower-boundary rule and slot reuse. */
static int clc_hold_lower_boundary(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 9, "ra");
    CLC_CHECK("single hold at 9 publishes 9",
              chain_linkage_hold_refuse_from() == 9);
    chain_linkage_hold_set("a", 5, "ra");
    CLC_CHECK("re-set lowers the boundary",
              chain_linkage_hold_refuse_from() == 5);
    chain_linkage_hold_set("a", 20, "ra");
    CLC_CHECK("re-set never loosens the boundary",
              chain_linkage_hold_refuse_from() == 5);
    CLC_CHECK("re-set reuses the same slot", clc_snapshot_ids_are("a"));
    chain_linkage_reset_for_testing();
    return failures;
}

/* Slot allocation for distinct ids, exhaustion, reuse after clear. */
static int clc_hold_slot_exhaustion(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 9, "ra");
    chain_linkage_hold_set("b", 3, "rb");
    chain_linkage_hold_set("c", 8, "rc");
    CLC_CHECK("distinct ids keep distinct slots, minimum is 3",
              clc_snapshot_ids_are("a,b,c") &&
              chain_linkage_hold_refuse_from() == 3);
    chain_linkage_hold_set("d", 7, "rd");
    chain_linkage_hold_set("e", 1, "re");
    CLC_CHECK("fifth id is not latched once all slots are held",
              clc_snapshot_ids_are("a,b,c,d") &&
              chain_linkage_hold_refuse_from() == 3);
    chain_linkage_hold_clear("b");
    chain_linkage_hold_set("e", 6, "re");
    CLC_CHECK("a cleared slot is reused", clc_snapshot_ids_are("a,e,c,d"));
    chain_linkage_reset_for_testing();
    return failures;
}

static int clc_hold_clear_selective(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 4, "ra");
    chain_linkage_hold_set("b", 6, "rb");
    chain_linkage_hold_clear(NULL);
    chain_linkage_hold_clear("");
    CLC_CHECK("clear(NULL) and clear(\"\") change nothing",
              clc_snapshot_ids_are("a,b"));
    chain_linkage_hold_clear("a");
    CLC_CHECK("clear of a one-character id leaves the other hold",
              clc_snapshot_ids_are("b") && chain_linkage_hold_active() &&
              chain_linkage_hold_refuse_from() == 6);
    chain_linkage_hold_clear("b");
    CLC_CHECK("clearing the last hold deactivates",
              !chain_linkage_hold_active());
    chain_linkage_reset_for_testing();
    return failures;
}

static int clc_hold_raise_blocker_ids(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    chain_linkage_hold_raise("a", "q", 4, "why");
    CLC_CHECK("one-character blocker id is registered",
              blocker_exists("q"));
    chain_linkage_hold_clear("a");
    CLC_CHECK("clear releases a one-character blocker id",
              !blocker_exists("q") && !chain_linkage_hold_active());
    chain_linkage_hold_raise("a", NULL, 4, "why");
    chain_linkage_hold_raise("b", "", 4, "why");
    CLC_CHECK("raise without a blocker id latches only the hold",
              clc_snapshot_ids_are("a,b"));
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    return failures;
}

/* Exhausted slots: raise of a fifth id must not crash. */
static int clc_hold_raise_exhausted(void)
{
    int failures = 0;
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    chain_linkage_hold_set("a", 1, "r");
    chain_linkage_hold_set("b", 2, "r");
    chain_linkage_hold_set("c", 3, "r");
    chain_linkage_hold_set("d", 4, "r");
    chain_linkage_hold_raise("e", "qe", 5, "why");
    CLC_CHECK("raise on exhausted slots leaves holds as they were",
              clc_snapshot_ids_are("a,b,c,d"));
    blocker_clear("qe");
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    return failures;
}

/* Operator page: once per fresh blocker write, with peer id 0. */
static int clc_hold_raise_pages_once(void)
{
    int failures = 0;
    struct clc_ev_capture cap = { .count = 0, .last_peer = 99 };
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    blocker_set_clock_for_testing(5000000); /* frozen: second set is a dup */
    bool reg = event_observe(EV_OPERATOR_NEEDED, clc_ev_observer, &cap);
    CLC_CHECK("operator observer registers", reg);
    chain_linkage_hold_raise("a", "q", 7, "why");
    CLC_CHECK("fresh blocker pages exactly once with peer 0",
              cap.count == 1 && cap.last_peer == 0);
    chain_linkage_hold_raise("a", "q", 7, "why");
    CLC_CHECK("rate-limited duplicate does not page again", cap.count == 1);
    event_clear_observers(EV_OPERATOR_NEEDED);
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    return failures;
}

static int clc_snapshot_text(void)
{
    int failures = 0;
    bool act = false;
    int rf = -7;
    char ids[64], rsn[64];
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 9, "x");
    chain_linkage_hold_set("b", 4, "yy");
    memset(ids, 'Z', sizeof(ids)); ids[63] = '\0';
    memset(rsn, 'Z', sizeof(rsn)); rsn[63] = '\0';
    chain_linkage_hold_snapshot(&act, &rf, ids, 64, rsn, 64);
    CLC_CHECK("snapshot reports active and minimum", act && rf == 4);
    CLC_CHECK("snapshot lists ids in slot order", strcmp(ids, "a,b") == 0);
    CLC_CHECK("snapshot reason is the first held slot's",
              strcmp(rsn, "x") == 0);
    chain_linkage_reset_for_testing();
    chain_linkage_hold_snapshot(&act, &rf, ids, 64, rsn, 64);
    CLC_CHECK("empty snapshot: inactive, -1, empty strings",
              !act && rf == -1 && ids[0] == '\0' && rsn[0] == '\0');
    return failures;
}

static int clc_snapshot_capacities(void)
{
    int failures = 0;
    char ids[64], rsn[64];
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 9, "x");
    memset(ids, 'Z', sizeof(ids)); memset(rsn, 'Z', sizeof(rsn));
    chain_linkage_hold_snapshot(NULL, NULL, ids, 1, rsn, 1);
    CLC_CHECK("capacity 1 yields empty strings, writes nothing beyond",
              ids[0] == '\0' && rsn[0] == '\0' &&
              ids[1] == 'Z' && rsn[1] == 'Z');
    memset(ids, 'Z', sizeof(ids)); ids[10] = '\0';
    memset(rsn, 'Z', sizeof(rsn)); rsn[10] = '\0';
    chain_linkage_hold_snapshot(NULL, NULL, ids, 0, rsn, 0);
    CLC_CHECK("capacity 0 leaves both buffers untouched",
              strlen(ids) == 10 && strlen(rsn) == 10);
    chain_linkage_hold_snapshot(NULL, NULL, NULL, 5, NULL, 5);
    chain_linkage_hold_snapshot(NULL, NULL, ids, 5, NULL, 5);
    chain_linkage_hold_snapshot(NULL, NULL, NULL, 5, rsn, 5);
    CLC_CHECK("NULL out buffers with a capacity do not crash", true);
    chain_linkage_reset_for_testing();
    return failures;
}

/* Violation reason text. */
static int clc_violation_reason(void)
{
    int failures = 0;
    struct main_state ms; main_state_init(&ms);
    struct block_index p = clc_bare(4, NULL);
    struct block_index spliced = clc_bare(11, &p);
    char rsn[CHAIN_HOLD_REASON_MAX];
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    bool refused = !chain_linkage_check_advance(&ms.chain_active, &spliced);
    chain_linkage_hold_snapshot(NULL, NULL, NULL, 0, rsn, (int)sizeof(rsn));
    CLC_CHECK("splice refused", refused);
    CLC_CHECK("violation reason names heights and the expected one",
              strcmp(rsn, "label splice at connect: h=11 pprev_h=4 "
                          "(expected 10)") == 0);
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    main_state_free(&ms);
    return failures;
}

/* Exact-once refusal accounting around the hold boundary. */
static int clc_hold_refusal_accounting(void)
{
    int failures = 0;
    struct main_state ms; main_state_init(&ms);
    struct block_index below = clc_bare(4, NULL);
    struct block_index at = clc_bare(5, NULL);
    struct block_index past = clc_bare(9, NULL);
    struct block_index genesis = clc_bare(0, NULL);
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 5, "r");
    bool pass = chain_linkage_check_advance(&ms.chain_active, &below);
    CLC_CHECK("move below the hold passes, uncounted",
              pass && chain_linkage_hold_refusals_total() == 0);
    bool r1 = !chain_linkage_check_advance(&ms.chain_active, &at);
    CLC_CHECK("move at the hold refuses, counted once",
              r1 && chain_linkage_hold_refusals_total() == 1);
    bool r2 = !chain_linkage_check_advance(&ms.chain_active, &past);
    CLC_CHECK("move past the hold refuses, counted once more",
              r2 && chain_linkage_hold_refusals_total() == 2);
    chain_linkage_reset_for_testing();
    chain_linkage_hold_set("a", 0, "r");
    CLC_CHECK("hold at height 0 refuses genesis",
              !chain_linkage_check_advance(&ms.chain_active, &genesis));
    chain_linkage_reset_for_testing();
    main_state_free(&ms);
    return failures;
}

/* Off-tip diagnostic: only for a strict +1 move of a window that holds
 * at least the genesis block. */
static int clc_offtip_diagnostic_scope(void)
{
    int failures = 0;
    struct main_state ms; main_state_init(&ms);
    static struct uint256 hh;
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct block_index g0 = clc_bare(0, NULL);
    CLC_CHECK("empty window: genesis install passes",
              chain_linkage_check_advance(&ms.chain_active, &g0));
    struct block_index *real = clc_insert(&ms, &hh, 0, NULL, 0x91);
    bool seated = real && active_chain_move_window_tip(&ms.chain_active, real);
    CLC_CHECK("window seated at height 0, nothing counted yet",
              seated && chain_linkage_offtip_switches_total() == 0);
    struct block_index h1ok = clc_bare(1, real);
    bool on_tip = chain_linkage_check_advance(&ms.chain_active, &h1ok);
    CLC_CHECK("+1 move on the window tip is not counted",
              on_tip && chain_linkage_offtip_switches_total() == 0);
    struct block_index h1 = clc_bare(1, &g0);
    bool off_tip = chain_linkage_check_advance(&ms.chain_active, &h1);
    CLC_CHECK("+1 move off the tip at window height 0 is counted",
              off_tip && chain_linkage_offtip_switches_total() == 1);
    struct block_index h2 = clc_bare(2, &h1ok);
    bool jump = chain_linkage_check_advance(&ms.chain_active, &h2);
    CLC_CHECK("a +2 jump off the tip is allowed and not counted",
              jump && chain_linkage_offtip_switches_total() == 1);
    chain_linkage_reset_for_testing();
    main_state_free(&ms);
    return failures;
}

static int clc_reset_clears_everything(void)
{
    int failures = 0;
    struct main_state ms; main_state_init(&ms);
    chain_linkage_reset_for_testing();
    blocker_reset_for_testing();
    struct block_index p = clc_bare(0, NULL);
    struct block_index spliced = clc_bare(5, &p);
    struct block_index past = clc_bare(6, &spliced);
    bool a = !chain_linkage_check_advance(&ms.chain_active, &spliced);
    bool b = !chain_linkage_check_advance(&ms.chain_active, &past);
    chain_linkage_hold_raise("z", "q", 8, "why");
    CLC_CHECK("setup: violation and refusal counted",
              a && b && chain_linkage_violations_total() == 1 &&
              chain_linkage_hold_refusals_total() == 1);
    CLC_CHECK("setup: both blockers registered",
              blocker_exists("chain.linkage_violation") &&
              blocker_exists("q"));
    chain_linkage_reset_for_testing();
    CLC_CHECK("reset deactivates the hold and clears every slot",
              !chain_linkage_hold_active() && clc_snapshot_ids_are(""));
    CLC_CHECK("reset releases both blockers",
              !blocker_exists("chain.linkage_violation") &&
              !blocker_exists("q"));
    CLC_CHECK("reset zeroes the violation and refusal counters",
              chain_linkage_violations_total() == 0 &&
              chain_linkage_hold_refusals_total() == 0);
    blocker_reset_for_testing();
    main_state_free(&ms);
    return failures;
}

static int clc_reset_clears_offtip_counter(void)
{
    int failures = 0;
    struct main_state ms; main_state_init(&ms);
    static struct uint256 hh;
    chain_linkage_reset_for_testing();
    struct block_index g0 = clc_bare(0, NULL);
    struct block_index *real = clc_insert(&ms, &hh, 0, NULL, 0x92);
    bool seated = real && active_chain_move_window_tip(&ms.chain_active, real);
    struct block_index h1 = clc_bare(1, &g0);
    bool moved = chain_linkage_check_advance(&ms.chain_active, &h1);
    CLC_CHECK("setup: off-tip switch counted",
              seated && moved && chain_linkage_offtip_switches_total() == 1);
    chain_linkage_reset_for_testing();
    CLC_CHECK("reset zeroes the off-tip counter",
              chain_linkage_offtip_switches_total() == 0);
    main_state_free(&ms);
    return failures;
}

static int clc_mutation_gap_tests(void)
{
    int failures = 0;
    failures += clc_hold_set_validation();
    failures += clc_hold_lower_boundary();
    failures += clc_hold_slot_exhaustion();
    failures += clc_hold_clear_selective();
    failures += clc_hold_raise_blocker_ids();
    failures += clc_hold_raise_exhausted();
    failures += clc_hold_raise_pages_once();
    failures += clc_snapshot_text();
    failures += clc_snapshot_capacities();
    failures += clc_violation_reason();
    failures += clc_hold_refusal_accounting();
    failures += clc_offtip_diagnostic_scope();
    failures += clc_reset_clears_everything();
    failures += clc_reset_clears_offtip_counter();
    return failures;
}

int test_chain_linkage_check(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== chain_linkage_check tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();

    failures += clc_healthy_genesis_advances();
    failures += clc_label_splice_hold_and_clear();
    failures += clc_depth10_reorg_reconnect();
    failures += clc_seed_jump_healthy_labels();
    failures += clc_offtip_fork_switch_counted();
    failures += clc_mutation_gap_tests();
    return failures;
}
