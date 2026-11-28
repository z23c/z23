/* purpose: Resolve authenticated research ballots on a candidate branch. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
// one-result-type-ok:boot-binding-decision — the frozen bool API reports only
// whether a boot-time binding is accepted; fallible resolution returns zcl_result.
#include "services/research_rules.h"
#include "domain/consensus/check_block.h"
#include "primitives/block.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

const uint8_t research_rule_revision[RESEARCH_RULE_COUNT][32] = {
    {0x67,0x68,0xea,0xfc,0x3e,0x43,0xa9,0x46,0xac,0x94,0x5b,0xde,0xc8,0x39,0xf5,0xcd,
     0xc7,0x51,0xe6,0xbe,0x73,0x57,0x0b,0x53,0xb6,0x10,0x1b,0x65,0x61,0x6f,0xa2,0x86},
    {0xdd,0x9a,0x28,0x17,0x9a,0xf6,0x8e,0x0e,0x8b,0x65,0x83,0x1c,0xca,0x98,0xd7,0x3c,
     0x39,0x8d,0xa0,0x3a,0xe6,0x6c,0xc0,0xe5,0x0f,0x0f,0x81,0x09,0x04,0xa6,0x64,0xe8}
};

/* Installed once by single-threaded boot, before any readers exist. */
static struct research_rules_binding installed;

static bool binding_valid(const struct research_rules_binding *b)
{
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    return b && b->params && b->pin && d && d->chain &&
        uint256_eq(&b->params->consensus.hashGenesisBlock, &d->chain->consensus.hashGenesisBlock) &&
        memcmp(b->pin->genesis, b->params->consensus.hashGenesisBlock.data, 32) == 0;
}

bool research_rules_install(const struct chain_params *params, const struct miner_signal_catalog_pin *pin)
{
    struct research_rules_binding b = { params, pin };
    if (installed.params || !binding_valid(&b)) return false;
    installed = b;
    return true;
}

const struct research_rules_binding *research_rules_binding(void)
{
    return installed.params ? &installed : NULL;
}

size_t research_rules_deposit_violation(const struct block *block)
{
    /* Fail closed on a block that cannot be walked: a valid block always
     * carries at least its coinbase. */
    if (!block || !block->num_vtx || !block->vtx) return SIZE_MAX;
    for (size_t i = 1; i < block->num_vtx; ++i) {
        const struct transaction *tx = &block->vtx[i];
        if (tx->value_balance < 0 && !(tx->vin && transaction_is_coinbase(tx))) return i + 1;
    }
    return 0;
}

struct rule_round {
    size_t count;
    int rule[256];
    struct miner_signal_schedule schedule[256];
    struct miner_signal_tally tally[256];
};

static int revision_rule(const uint8_t revision[32])
{
    for (size_t i = 0; i < RESEARCH_RULE_COUNT; ++i)
        if (!memcmp(revision, research_rule_revision[i], 32)) return (int)i;
    return -1; // raw-return-ok:unknown-rule-sentinel
}

static struct zcl_result round_prepare(const struct research_rules_binding *b, struct rule_round *r)
{
    if (!binding_valid(b)) return ZCL_ERR(RESEARCH_RULES_INVALID, "Invalid research binding");
    if (b->pin->count == 0 || b->pin->count > 256)
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Invalid research catalog count");
    for (size_t i = 0; i < b->pin->count; ++i) {
        if (!miner_signal_catalog_pin_select(b->pin, i, &r->schedule[i]).ok)
            return ZCL_ERR(RESEARCH_RULES_INVALID, "Invalid research catalog pin or schedule");
        r->rule[i] = revision_rule(b->pin->entries[i].rule_revision);
        /* catalog_validate already requires activation > start + window. */
        if (r->rule[i] >= 0 && r->schedule[i].activation <
            (int64_t)r->schedule[i].start + r->schedule[i].window)
            return ZCL_ERR(RESEARCH_RULES_INVALID, "Known rule activates before its window ends");
    }
    r->count = b->pin->count;
    return ZCL_OK;
}

#ifdef ZCL_TESTING
static size_t test_hashes;
size_t research_rules_test_hashes(bool reset);
size_t research_rules_test_hashes(bool reset)
{
    size_t n = test_hashes;
    if (reset) test_hashes = 0;
    return n;
}
#endif

static bool body_authenticated(const struct block_index *bi, const struct block *blk)
{
    if (!bi || !bi->phashBlock || !blk || blk->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        (blk->num_vtx && !blk->vtx) ||
        blk->header.nSolutionSize > MAX_SOLUTION_SIZE) return false;
    struct uint256 hash;
    block_get_hash(blk, &hash);
    if (!uint256_eq(&hash, bi->phashBlock)) return false;
    /* The consensus Merkle helper consumes cached txids; bind them to bytes. */
    for (size_t i = 0; i < blk->num_vtx; ++i) {
#ifdef ZCL_TESTING
        ++test_hashes;
#endif
        if (!transaction_hash_serialized(&blk->vtx[i], &hash)) {
            LOG_ERROR("research_rules", "Cannot hash transaction %zu", i);
            return false;
        }
        if (!uint256_eq(&hash, &blk->vtx[i].hash)) return false;
    }
    return domain_consensus_check_block_merkle_root(blk, NULL, 0, NULL).ok;
}

static struct zcl_result round_begin(struct rule_round *r, int32_t height, const struct uint256 *hash)
{
    for (size_t i = 0; i < r->count; ++i)
        if (!miner_signal_begin(&r->schedule[i], height, hash, &r->tally[i]).ok)
            return ZCL_ERR(RESEARCH_RULES_INVALID, "Cannot initialize research tally");
    return ZCL_OK;
}

static struct zcl_result round_connect(struct rule_round *r, const struct block_index *bi,
                                       const struct block *blk)
{
    if (!blk->num_vtx || !blk->vtx || !blk->vtx[0].vin ||
        !transaction_is_coinbase(&blk->vtx[0]))
        return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Missing window coinbase");
    for (size_t i = 0; i < r->count; ++i)
        if (!miner_signal_connect(&r->tally[i], bi->nHeight, &blk->header.hashPrevBlock,
                                  bi->phashBlock, &blk->vtx[0], &r->tally[i]).ok)
            return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Cannot tally window coinbase");
    return ZCL_OK;
}

static struct zcl_result round_state(const struct rule_round *r, int32_t height,
                                     struct research_rules_state *out)
{
    struct research_rules_state next = {0};
    for (size_t i = 0; i < r->count; ++i) {
        int64_t check_height = r->rule[i] >= 0 ? r->schedule[i].activation :
            (int64_t)r->schedule[i].start + r->schedule[i].window;
        if (height < check_height) continue;
        enum miner_signal_phase phase;
        if (!miner_signal_phase_at(&r->tally[i], height, &phase).ok)
            return ZCL_ERR(RESEARCH_RULES_INVALID, "Incomplete research tally");
        if (r->rule[i] < 0) {
            if (phase == MINER_SIGNAL_LOCKED_IN || phase == MINER_SIGNAL_ACTIVE)
                return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Unknown research catalog slot %zu locked in", i);
        } else {
            next.active[r->rule[i]] = phase == MINER_SIGNAL_ACTIVE;
        }
    }
    *out = next;
    return ZCL_OK;
}

static struct zcl_result collect_window(const struct block_index *parent, int32_t start,
    int32_t window, const struct block_index **entries, const struct block_index **base)
{
    const struct block_index *p = parent;
    while (p && p->nHeight > start - 1) {
        if (!p->pprev || (int64_t)p->pprev->nHeight != (int64_t)p->nHeight - 1)
            return ZCL_ERR(RESEARCH_RULES_INVALID, "Discontinuous research ancestry");
        int64_t offset = (int64_t)p->nHeight - start;
        if (offset >= 0 && offset < window) entries[offset] = p;
        p = p->pprev;
    }
    if (!p || p->nHeight != start - 1 || !p->phashBlock)
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Missing research window parent");
    *base = p;
    return ZCL_OK;
}

static struct zcl_result tally_window(struct rule_round *round, const struct block_index **entries,
    int32_t window, research_rules_read_fn read, void *ctx)
{
    for (int32_t i = 0; i < window; ++i) {
        const struct block_index *p = entries[i];
        if (!p) return ZCL_ERR(RESEARCH_RULES_INVALID, "Research window incomplete");
        struct block blk;
        block_init(&blk);
        bool ok = read(ctx, p, &blk) && body_authenticated(p, &blk) && p->pprev &&
                  p->pprev->phashBlock &&
                  uint256_eq(&blk.header.hashPrevBlock, p->pprev->phashBlock);
        struct zcl_result result = ok ? round_connect(round, p, &blk) :
            ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Research window body unavailable or unauthenticated");
        block_free(&blk);
        if (!result.ok) return result;
    }
    return ZCL_OK;
}

static bool round_needed(const struct rule_round *round, int32_t height)
{
    for (size_t i = 0; i < round->count; ++i) {
        int64_t threshold = round->rule[i] >= 0 ? round->schedule[i].activation :
            (int64_t)round->schedule[i].start + round->schedule[i].window;
        if (height >= threshold) return true;
    }
    return false;
}

struct zcl_result research_rules_for_parent(const struct research_rules_binding *binding,
    const struct block_index *parent, research_rules_read_fn read, void *ctx,
    struct research_rules_state *out)
{
    if (!out) return ZCL_ERR(RESEARCH_RULES_INVALID, "Missing research state output");
    struct research_rules_state inactive = {0};
    if (!binding || !parent) { *out = inactive; return ZCL_OK; }
    struct rule_round round = {0};
    struct zcl_result result = round_prepare(binding, &round);
    if (!result.ok) return result;
    if (parent->nHeight < 0 || parent->nHeight == INT32_MAX)
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Invalid candidate height");
    int32_t height = parent->nHeight + 1;
    if (!round_needed(&round, height)) { *out = inactive; return ZCL_OK; }
    if (!read) return ZCL_ERR(RESEARCH_RULES_INVALID, "Missing research block reader");
    int32_t window = binding->pin->window;
    if ((size_t)window > SIZE_MAX / sizeof(struct block_index *))
        return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Research window exceeds address space");
    const struct block_index **entries = zcl_malloc((size_t)window * sizeof(*entries), "research window");
    if (!entries) return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Cannot allocate research window");
    memset(entries, 0, (size_t)window * sizeof(*entries));
    const struct block_index *base = NULL;
    result = collect_window(parent, binding->pin->start, window, entries, &base);
    if (result.ok) result = round_begin(&round, base->nHeight, base->phashBlock);
    if (result.ok) result = tally_window(&round, entries, window, read, ctx);
    free(entries);
    if (!result.ok) return result;
    return round_state(&round, height, out);
}

struct research_rules_tracker {
    struct rule_round round;
    int32_t start, window, height;
    struct uint256 hash;
    bool connected, bound;
};

struct research_rules_tracker *research_rules_tracker_create(const struct research_rules_binding *binding)
{
    struct research_rules_tracker *t = zcl_malloc(sizeof(*t), "research rules tracker");
    if (!t) return NULL;
    *t = (struct research_rules_tracker){0};
    if (binding) {
        if (!round_prepare(binding, &t->round).ok) { free(t); return NULL; }
        t->start = binding->pin->start;
        t->window = binding->pin->window;
        t->bound = true;
    }
    return t;
}

void research_rules_tracker_destroy(struct research_rules_tracker *tracker)
{
    free(tracker);
}

static bool tracker_ordered(const struct research_rules_tracker *t,
                            const struct block_index *bi, const struct block *blk)
{
    if (!t->connected) return !t->bound || bi->nHeight <= t->start - 1;
    return (int64_t)bi->nHeight == (int64_t)t->height + 1 &&
        bi->pprev && bi->pprev->phashBlock && bi->pprev->nHeight == t->height &&
        uint256_eq(bi->pprev->phashBlock, &t->hash) &&
        uint256_eq(&blk->header.hashPrevBlock, &t->hash);
}

static bool tracker_input_valid(const struct research_rules_tracker *t,
                                const struct block_index *bi, const struct block *blk)
{
    return t && bi && blk && bi->phashBlock && bi->nHeight >= 0 && bi->nHeight < INT32_MAX;
}

struct zcl_result research_rules_tracker_connect(struct research_rules_tracker *t,
    const struct block_index *bi, const struct block *blk)
{
    if (!tracker_input_valid(t, bi, blk))
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Invalid tracker input");
    if (!tracker_ordered(t, bi, blk))
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Tracker block is out of order");
    if (t->bound && bi->nHeight >= t->start - 1 &&
        (int64_t)bi->nHeight < (int64_t)t->start + t->window &&
        !body_authenticated(bi, blk))
        return ZCL_ERR(RESEARCH_RULES_UNAVAILABLE, "Tracker body unavailable or unauthenticated");
    struct research_rules_tracker next = *t;
    if (next.bound && bi->nHeight == next.start - 1) {
        struct zcl_result r = round_begin(&next.round, bi->nHeight, bi->phashBlock);
        if (!r.ok) return r;
    }
    if (next.bound && bi->nHeight >= next.start &&
        (int64_t)bi->nHeight < (int64_t)next.start + next.window) {
        struct zcl_result r = round_connect(&next.round, bi, blk);
        if (!r.ok) return r;
    }
    next.connected = true;
    next.height = bi->nHeight;
    next.hash = *bi->phashBlock;
    *t = next;
    return ZCL_OK;
}

struct zcl_result research_rules_tracker_state(const struct research_rules_tracker *t,
                                                struct research_rules_state *out)
{
    if (!t || !out || !t->connected)
        return ZCL_ERR(RESEARCH_RULES_INVALID, "Tracker has no connected parent");
    return round_state(&t->round, t->height + 1, out);
}
