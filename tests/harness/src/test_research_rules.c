/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/research_rules.h"
#include "base/hex.h"
#include "primitives/block.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test-only instrumentation, not part of the service API. */
size_t research_rules_test_hashes(bool reset);

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "research rules line %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

enum { CHAIN_LENGTH = 401 };
struct fixture {
    struct miner_signal_catalog_pin pin;
    struct research_rules_binding binding;
    struct block_index *index;
    struct block *blocks;
    int calls, fail, fail_above, substitute;
};

static bool pin_init(struct fixture *f, int start, int window, int cap, int freeze, int count)
{
    struct miner_signal_catalog_pin *p = &f->pin;
    *p = (struct miner_signal_catalog_pin){ .start = start, .window = window, .count = (size_t)count };
    if (!zcl_hex_decode("0470426015683b2d25ae8014a684975fa4841720b848c22457ee8f510a1ab718",
                        p->network_id, 32)) return false;
    f->binding.params = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD)->chain;
    f->binding.pin = p;
    memcpy(p->genesis, f->binding.params->consensus.hashGenesisBlock.data, 32);
    memcpy(p->entries[0].rule_revision, research_rule_revision[0], 32);
    p->entries[0].activation = cap;
    if (count > 1) {
        memcpy(p->entries[1].rule_revision, research_rule_revision[1], 32);
        p->entries[1].activation = freeze;
    }
    struct miner_signal_catalog c = { .start = start, .window = window,
                                      .count = p->count, .entries = p->entries };
    memcpy(c.network_id, p->network_id, 32);
    memcpy(c.genesis, p->genesis, 32);
    struct miner_signal_schedule schedule;
    if (!miner_signal_catalog_select(&c, 0, &schedule).ok) return false;
    memcpy(p->digest, schedule.catalog, 32);
    return true;
}

static bool fixture_blocks(struct fixture *f, int cap_votes, int freeze_votes)
{
    f->index = calloc(CHAIN_LENGTH, sizeof(*f->index));
    f->blocks = calloc(CHAIN_LENGTH, sizeof(*f->blocks));
    if (!f->index || !f->blocks) return false;
    for (int h = 0; h < CHAIN_LENGTH; ++h) {
        struct block *b = &f->blocks[h];
        block_init(b);
        b->vtx = calloc(1, sizeof(*b->vtx));
        if (!b->vtx) return false;
        b->num_vtx = 1;
        transaction_init(b->vtx);
        if (!transaction_alloc(b->vtx, 1, 1)) return false;
        outpoint_set_null(&b->vtx[0].vin[0].prevout);
        b->vtx[0].vout[0].value = 0;
        uint8_t bits[32] = {0};
        int relative = h - f->pin.start;
        if (relative >= 0 && relative < cap_votes) bits[0] |= 1;
        if (relative >= 0 && relative < freeze_votes && f->pin.count > 1) bits[0] |= 2;
        struct script *script = &b->vtx[0].vout[0].script_pub_key;
        miner_signal_ballot_script(f->pin.digest, bits, script->data);
        script->size = MINER_SIGNAL_SCRIPT_BYTES;
        transaction_compute_hash(b->vtx);
        b->header.hashMerkleRoot = b->vtx[0].hash;
        b->header.nTime = (uint32_t)h;
        if (h) b->header.hashPrevBlock = f->index[h-1].hashBlock;
        struct block_index *bi = &f->index[h];
        bi->nHeight = h;
        bi->pprev = h ? &f->index[h-1] : NULL;
        bi->phashBlock = &bi->hashBlock;
        block_get_hash(b, &bi->hashBlock);
    }
    return true;
}

static void fixture_free(struct fixture *f)
{
    if (f->blocks) for (int h = 0; h < CHAIN_LENGTH; ++h) block_free(&f->blocks[h]);
    free(f->blocks);
    free(f->index);
}

static bool read_block(void *ctx, const struct block_index *bi, struct block *out)
{
    struct fixture *f = ctx;
    ++f->calls;
    if (f->fail) return false;
    int h = bi->nHeight;
    if (f->fail_above && h >= f->fail_above) return false;
    if (f->substitute == h) ++h;
    return block_clone(out, &f->blocks[h]);
}

static int expect_state(struct fixture *f, int parent, bool cap, bool freeze)
{
    struct research_rules_state state = {0};
    CHECK(research_rules_for_parent(&f->binding, &f->index[parent], read_block, f, &state).ok);
    CHECK(state.active[0] == cap && state.active[1] == freeze);
    return 0;
}

static int tracker_check(struct fixture *f)
{
    struct research_rules_tracker *t = research_rules_tracker_create(&f->binding);
    CHECK(t);
    struct research_rules_state a, b;
    CHECK(research_rules_tracker_state(t, &a).code == RESEARCH_RULES_INVALID);
    CHECK(research_rules_tracker_connect(t, &f->index[103], &f->blocks[103]).code == RESEARCH_RULES_INVALID);
    for (int h = 0; h <= 130; ++h) {
        CHECK(research_rules_tracker_connect(t, &f->index[h], &f->blocks[h]).ok);
        CHECK(research_rules_tracker_state(t, &a).ok);
        CHECK(research_rules_for_parent(&f->binding, &f->index[h], read_block, f, &b).ok);
        CHECK(a.active[0] == b.active[0] && a.active[1] == b.active[1]);
        if (h == 102) {
            CHECK(research_rules_tracker_connect(t, &f->index[104], &f->blocks[104]).code == RESEARCH_RULES_INVALID);
            struct block_index wrong = f->index[103];
            wrong.pprev = &f->index[101];
            CHECK(research_rules_tracker_connect(t, &wrong, &f->blocks[103]).code == RESEARCH_RULES_INVALID);
            struct block_index fake_parent = f->index[102];
            fake_parent.phashBlock = &f->index[101].hashBlock;
            wrong.pprev = &fake_parent;
            CHECK(research_rules_tracker_connect(t, &wrong, &f->blocks[103]).code == RESEARCH_RULES_INVALID);
            struct block tampered;
            CHECK(block_clone(&tampered, &f->blocks[103]));
            tampered.vtx[0].vout[0].script_pub_key.data[39] ^= 1;
            CHECK(research_rules_tracker_connect(t, &f->index[103], &tampered).code == RESEARCH_RULES_UNAVAILABLE);
            transaction_compute_hash(tampered.vtx);
            tampered.header.hashMerkleRoot = tampered.vtx[0].hash;
            CHECK(research_rules_tracker_connect(t, &f->index[103], &tampered).code == RESEARCH_RULES_UNAVAILABLE);
            block_free(&tampered);
            CHECK(research_rules_tracker_state(t, &b).ok);
            CHECK(a.active[0] == b.active[0] && a.active[1] == b.active[1]);
        }
    }
    research_rules_tracker_destroy(t);
    t = research_rules_tracker_create(NULL);
    CHECK(t && research_rules_tracker_connect(t, &f->index[130], &f->blocks[130]).ok);
    CHECK(research_rules_tracker_state(t, &a).ok && !a.active[0] && !a.active[1]);
    research_rules_tracker_destroy(t);
    return 0;
}

static int tracker_cost_check(struct fixture *f)
{
    struct research_rules_tracker *t = research_rules_tracker_create(NULL);
    CHECK(t);
    (void)research_rules_test_hashes(true);
    for (int h = 0; h <= 30; ++h) {
        struct research_rules_state a, b;
        CHECK(research_rules_tracker_connect(t, &f->index[h], &f->blocks[h]).ok);
        CHECK(research_rules_test_hashes(true) == 0);
        CHECK(research_rules_tracker_state(t, &a).ok);
        CHECK(research_rules_for_parent(NULL, &f->index[h], read_block, f, &b).ok);
        CHECK(a.active[0] == b.active[0] && a.active[1] == b.active[1]);
    }
    research_rules_tracker_destroy(t);
    t = research_rules_tracker_create(&f->binding);
    CHECK(t);
    for (int h = 0; h <= 30; ++h) {
        struct research_rules_state a, b;
        (void)research_rules_test_hashes(true);
        CHECK(research_rules_tracker_connect(t, &f->index[h], &f->blocks[h]).ok);
        size_t hashes = research_rules_test_hashes(true);
        CHECK((h >= f->pin.start - 1 && h < f->pin.start + f->pin.window) ?
              hashes > 0 : hashes == 0);
        CHECK(research_rules_tracker_state(t, &a).ok);
        CHECK(research_rules_for_parent(&f->binding, &f->index[h], read_block, f, &b).ok);
        CHECK(a.active[0] == b.active[0] && a.active[1] == b.active[1]);
    }
    research_rules_tracker_destroy(t);
    return 0;
}

static int failure_checks(struct fixture *f)
{
    struct research_rules_state state = { .active = {true, true} };
    f->fail = 1;
    CHECK(research_rules_for_parent(&f->binding, &f->index[124], read_block, f, &state).code == RESEARCH_RULES_UNAVAILABLE);
    CHECK(state.active[0] && state.active[1]);
    f->fail = 0;
    f->substitute = 103;
    CHECK(research_rules_for_parent(&f->binding, &f->index[124], read_block, f, &state).code == RESEARCH_RULES_UNAVAILABLE);
    CHECK(state.active[0] && state.active[1]);
    f->substitute = 0;
    f->blocks[103].vtx[0].vout[0].script_pub_key.data[39] ^= 1;
    CHECK(research_rules_for_parent(&f->binding, &f->index[124], read_block, f, &state).code == RESEARCH_RULES_UNAVAILABLE);
    CHECK(state.active[0] && state.active[1]);
    transaction_compute_hash(f->blocks[103].vtx);
    f->blocks[103].header.hashMerkleRoot = f->blocks[103].vtx[0].hash;
    CHECK(research_rules_for_parent(&f->binding, &f->index[124], read_block, f, &state).code == RESEARCH_RULES_UNAVAILABLE);
    CHECK(state.active[0] && state.active[1]);
    f->index[110].nHeight--;
    CHECK(research_rules_for_parent(&f->binding, &f->index[124], read_block, f, &state).code == RESEARCH_RULES_INVALID);
    f->index[110].nHeight++;
    return 0;
}

static int deposit_checks(void)
{
    struct block b = {0};
    struct transaction tx[3] = {0};
    struct tx_in in = {0};
    outpoint_set_null(&in.prevout);
    tx[0].vin = &in; tx[0].num_vin = 1; tx[0].value_balance = -1;
    b.vtx = tx; b.num_vtx = 3;
    CHECK(research_rules_deposit_violation(NULL) == SIZE_MAX);
    b.vtx = NULL;
    CHECK(research_rules_deposit_violation(&b) == SIZE_MAX);
    b.vtx = tx;
    CHECK(research_rules_deposit_violation(&b) == 0);
    b.num_vtx = 0;
    CHECK(research_rules_deposit_violation(&b) == SIZE_MAX);
    b.num_vtx = 3;
    tx[1].value_balance = -1;
    CHECK(research_rules_deposit_violation(&b) == 2);
    tx[1].value_balance = 1; tx[2].value_balance = -1;
    CHECK(research_rules_deposit_violation(&b) == 3);
    tx[2].value_balance = 0;
    CHECK(research_rules_deposit_violation(&b) == 0);
    return 0;
}

static void rehash_from(struct fixture *f, int start)
{
    for (int h = start; h < CHAIN_LENGTH; ++h) {
        struct block *b = &f->blocks[h];
        transaction_compute_hash(b->vtx);
        b->header.hashMerkleRoot = b->vtx[0].hash;
        if (h) b->header.hashPrevBlock = f->index[h-1].hashBlock;
        block_get_hash(b, &f->index[h].hashBlock);
    }
}

static int replay_range(struct research_rules_tracker *tracker, struct fixture *f, int first, int last)
{
    for (int h = first; h <= last; ++h) {
        struct research_rules_state tracked, resolved;
        CHECK(research_rules_tracker_connect(tracker, &f->index[h], &f->blocks[h]).ok);
        CHECK(research_rules_tracker_state(tracker, &tracked).ok);
        CHECK(research_rules_for_parent(&f->binding, &f->index[h], read_block, f, &resolved).ok);
        CHECK(tracked.active[0] == resolved.active[0] && tracked.active[1] == resolved.active[1]);
    }
    return 0;
}

static int reorg_check(struct fixture *original, struct fixture *sibling)
{
    struct research_rules_tracker *tracker = research_rules_tracker_create(&original->binding);
    CHECK(tracker);
    CHECK(replay_range(tracker, original, 0, 20) == 0);
    struct research_rules_state state;
    CHECK(research_rules_tracker_state(tracker, &state).ok && state.active[0]);
    CHECK(research_rules_tracker_connect(tracker, &sibling->index[13],
                                         &sibling->blocks[13]).code == RESEARCH_RULES_INVALID);
    research_rules_tracker_destroy(tracker);
    tracker = research_rules_tracker_create(&original->binding);
    CHECK(tracker);
    CHECK(replay_range(tracker, original, 0, 12) == 0);
    CHECK(replay_range(tracker, sibling, 13, 30) == 0);
    CHECK(research_rules_tracker_state(tracker, &state).ok && !state.active[0]);
    research_rules_tracker_destroy(tracker);
    return 0;
}

static int unknown_tracker_check(struct fixture *f, int slot, bool locked)
{
    struct research_rules_tracker *t = research_rules_tracker_create(&f->binding);
    CHECK(t);
    for (int h = 0; h <= 30; ++h) {
        struct research_rules_state a = { .active = {true, true} }, b = a;
        CHECK(research_rules_tracker_connect(t, &f->index[h], &f->blocks[h]).ok);
        struct zcl_result x = research_rules_tracker_state(t, &a);
        struct zcl_result y = research_rules_for_parent(&f->binding, &f->index[h], read_block, f, &b);
        CHECK(x.code == y.code);
        if (locked && h >= f->pin.start + f->pin.window - 1) {
            char name[32];
            snprintf(name, sizeof(name), "slot %d", slot);
            CHECK(x.code == RESEARCH_RULES_UNAVAILABLE && strstr(x.message, name));
            CHECK(strstr(y.message, name));
            CHECK(a.active[0] && a.active[1] && b.active[0] && b.active[1]);
        } else {
            CHECK(x.ok && y.ok);
            CHECK(a.active[0] == b.active[0] && a.active[1] == b.active[1]);
        }
    }
    research_rules_tracker_destroy(t);
    return 0;
}

static int other_rounds(void)
{
    struct fixture f = {0};
    CHECK(pin_init(&f, 103, 20, 125, 126, 2));
    CHECK(fixture_blocks(&f, 18, 19));
    CHECK(expect_state(&f, 124, false, false) == 0);
    CHECK(expect_state(&f, 125, false, true) == 0);
    CHECK(expect_state(&f, 399, false, true) == 0);
    fixture_free(&f);
    f = (struct fixture){0};
    CHECK(pin_init(&f, 10, 4, 16, 17, 2));
    CHECK(fixture_blocks(&f, 4, 3));
    CHECK(tracker_cost_check(&f) == 0);
    CHECK(expect_state(&f, 15, true, false) == 0);
    CHECK(expect_state(&f, 399, true, false) == 0);
    /* Votes outside the window cannot make the three-vote rule qualify. */
    f.blocks[9].vtx[0].vout[0].script_pub_key.data[39] |= 2;
    f.blocks[14].vtx[0].vout[0].script_pub_key.data[39] |= 2;
    rehash_from(&f, 9);
    CHECK(expect_state(&f, 399, true, false) == 0);
    /* Two simultaneous branches share the window parent through height 12. */
    struct fixture sibling = {0};
    CHECK(pin_init(&sibling, 10, 4, 16, 17, 2));
    CHECK(fixture_blocks(&sibling, 4, 3));
    sibling.blocks[9].vtx[0].vout[0].script_pub_key.data[39] |= 2;
    sibling.blocks[14].vtx[0].vout[0].script_pub_key.data[39] |= 2;
    sibling.blocks[13].vtx[0].vout[0].script_pub_key.data[39] &= (uint8_t)~1u;
    rehash_from(&sibling, 9);
    sibling.index[13].pprev = &f.index[12];
    CHECK(expect_state(&f, 15, true, false) == 0);
    CHECK(expect_state(&sibling, 15, false, false) == 0);
    CHECK(expect_state(&sibling, 399, false, false) == 0);
    CHECK(reorg_check(&f, &sibling) == 0);
    fixture_free(&sibling);
    fixture_free(&f);
    f = (struct fixture){0};
    CHECK(pin_init(&f, 10, 4, 16, 17, 1));
    CHECK(fixture_blocks(&f, 4, 4));
    CHECK(expect_state(&f, 399, true, false) == 0);
    fixture_free(&f);
    f = (struct fixture){0};
    CHECK(pin_init(&f, 10, 4, 16, 17, 1));
    memset(f.pin.entries[0].rule_revision, 0x11, 32);
    struct miner_signal_catalog c = { .start = 10, .window = 4, .count = 1, .entries = f.pin.entries };
    memcpy(c.network_id, f.pin.network_id, 32);
    memcpy(c.genesis, f.pin.genesis, 32);
    struct miner_signal_schedule schedule;
    CHECK(miner_signal_catalog_select(&c, 0, &schedule).ok);
    memcpy(f.pin.digest, schedule.catalog, 32);
    CHECK(fixture_blocks(&f, 3, 0));
    CHECK(expect_state(&f, 399, false, false) == 0 && f.calls > 0);
    CHECK(unknown_tracker_check(&f, 0, false) == 0);
    f.blocks[13].vtx[0].vout[0].script_pub_key.data[39] |= 1;
    rehash_from(&f, 13);
    CHECK(unknown_tracker_check(&f, 0, true) == 0);
    fixture_free(&f);
    f = (struct fixture){0};
    CHECK(pin_init(&f, 10, 4, 16, 17, 2));
    memset(f.pin.entries[1].rule_revision, 0xee, 32);
    c = (struct miner_signal_catalog){ .start = 10, .window = 4, .count = 2, .entries = f.pin.entries };
    memcpy(c.network_id, f.pin.network_id, 32);
    memcpy(c.genesis, f.pin.genesis, 32);
    CHECK(miner_signal_catalog_select(&c, 0, &schedule).ok);
    memcpy(f.pin.digest, schedule.catalog, 32);
    CHECK(fixture_blocks(&f, 4, 3));
    CHECK(expect_state(&f, 399, true, false) == 0);
    CHECK(unknown_tracker_check(&f, 1, false) == 0);
    f.blocks[13].vtx[0].vout[0].script_pub_key.data[39] |= 2;
    rehash_from(&f, 13);
    CHECK(unknown_tracker_check(&f, 1, true) == 0);
    fixture_free(&f);
    return 0;
}

int test_research_rules(void)
{
    struct fixture f = {0};
    CHECK(pin_init(&f, 103, 20, 125, 126, 2));
    CHECK(fixture_blocks(&f, 19, 18));
    struct research_rules_state s = { .active = {true, true} };
    CHECK(research_rules_for_parent(NULL, &f.index[124], read_block, &f, &s).ok);
    CHECK(!s.active[0] && !s.active[1] && !f.calls);
    CHECK(research_rules_for_parent(&f.binding, NULL, read_block, &f, &s).ok && !f.calls);
    CHECK(expect_state(&f, 123, false, false) == 0 && !f.calls);
    CHECK(expect_state(&f, 124, true, false) == 0);
    CHECK(expect_state(&f, 125, true, false) == 0);
    CHECK(expect_state(&f, 126, true, false) == 0);
    CHECK(expect_state(&f, 399, true, false) == 0);
    /* Ancestors above the window are linked by the index, never read. */
    f.fail_above = f.pin.start + f.pin.window;
    CHECK(expect_state(&f, 399, true, false) == 0);
    f.fail_above = 0;
    CHECK(tracker_check(&f) == 0);
    CHECK(failure_checks(&f) == 0);
    CHECK(deposit_checks() == 0);
    CHECK(other_rounds() == 0);
    struct chain_params wrong = *f.binding.params;
    wrong.consensus.hashGenesisBlock.data[0] ^= 1;
    struct research_rules_binding bad = { &wrong, &f.pin };
    CHECK(research_rules_for_parent(&bad, &f.index[124], read_block, &f, &s).code == RESEARCH_RULES_INVALID);
    CHECK(!research_rules_tracker_create(&bad));
    CHECK(!research_rules_install(NULL, &f.pin));
    CHECK(!research_rules_install(f.binding.params, NULL));
    CHECK(!research_rules_install(&wrong, &f.pin));
    f.pin.genesis[0] ^= 1;
    CHECK(research_rules_for_parent(&f.binding, &f.index[124], read_block, &f, &s).code == RESEARCH_RULES_INVALID);
    CHECK(!research_rules_install(f.binding.params, &f.pin));
    f.pin.genesis[0] ^= 1;
    CHECK(research_rules_install(f.binding.params, &f.pin));
    CHECK(research_rules_binding()->params == f.binding.params && research_rules_binding()->pin == &f.pin);
    CHECK(!research_rules_install(f.binding.params, &f.pin));
    fixture_free(&f);
    return 0;
}
