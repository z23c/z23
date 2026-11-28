/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/research_rules_gate.h"
#include "base/hex.h"
#include "services/research_block_size.h"
#include "primitives/block.h"
#include "util/safe_alloc.h"
#include "storage/disk_block_io.h"
#include "platform/directory_compat.h"
#include "test/test_core.h"
#include "test/test_block_map.h"
#include "services/chain_activation_service.h"
#include "validation/main_state.h"
#include "consensus/validation.h"
#include "util/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct gate_fixture {
    struct miner_signal_catalog_pin pin;
    struct research_rules_binding binding;
    struct block_index index[126];
    struct block *blocks;
};

static int expect_gate(const char *name, struct research_gate_decision d,
                       enum research_gate_verdict verdict, const char *rule,
                       size_t offender)
{
    if (d.verdict == verdict && d.offender == offender &&
        ((!rule && !d.rule) || (rule && d.rule && !strcmp(rule, d.rule)))) return 0;
    fprintf(stderr, "research gate %s: verdict=%d rule=%s detail=%s offender=%zu active=%d,%d\n",
            name, d.verdict, d.rule ? d.rule : "(none)", d.detail, d.offender,
            d.rules.active[0], d.rules.active[1]);
    return 1;
}

static bool gate_fixture_init(struct gate_fixture *f, const char *dir)
{
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d) return false;
    f->pin = (struct miner_signal_catalog_pin){ .start = 103, .window = 20, .count = 2 };
    f->binding = (struct research_rules_binding){ d->chain, &f->pin };
    memcpy(f->pin.genesis, d->chain->consensus.hashGenesisBlock.data, 32);
    if (!zcl_hex_decode("0470426015683b2d25ae8014a684975fa4841720b848c22457ee8f510a1ab718",
                        f->pin.network_id, 32)) return false;
    memcpy(f->pin.entries[0].rule_revision, research_rule_revision[0], 32);
    memcpy(f->pin.entries[1].rule_revision, research_rule_revision[1], 32);
    f->pin.entries[0].activation = 125;
    f->pin.entries[1].activation = 126;
    struct miner_signal_catalog c = { .start = 103, .window = 20, .count = 2,
                                      .entries = f->pin.entries };
    memcpy(c.network_id, f->pin.network_id, 32);
    memcpy(c.genesis, f->pin.genesis, 32);
    struct miner_signal_schedule schedule;
    if (!miner_signal_catalog_select(&c, 0, &schedule).ok) return false;
    memcpy(f->pin.digest, schedule.catalog, 32);
    f->blocks = calloc(126, sizeof(*f->blocks));
    if (!f->blocks) return false;
    for (int h = 0; h < 126; ++h) {
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
        if (h >= 103 && h < 122) bits[0] = 3;
        struct script *s = &b->vtx[0].vout[0].script_pub_key;
        miner_signal_ballot_script(f->pin.digest, bits, s->data);
        s->size = MINER_SIGNAL_SCRIPT_BYTES;
        transaction_compute_hash(b->vtx);
        b->header.hashMerkleRoot = b->vtx[0].hash;
        b->header.nTime = (uint32_t)h;
        if (h) b->header.hashPrevBlock = f->index[h - 1].hashBlock;
        struct block_index *bi = &f->index[h];
        bi->nHeight = h;
        bi->pprev = h ? &f->index[h - 1] : NULL;
        bi->phashBlock = &bi->hashBlock;
        block_get_hash(b, &bi->hashBlock);
        if (h >= 102 && h <= 122) {
            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            if (!write_block_to_disk(b, &pos, dir, d->chain->pchMessageStart)) return false;
            block_index_disk_pos_store(bi, pos.nFile, pos.nPos);
            (void)block_index_status_fetch_or(bi, BLOCK_HAVE_DATA);
        }
    }
    return true;
}

static int ceiling_test(void)
{
    const struct chain_research_descriptor *research =
        chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    const struct chain_params *ordinary = chain_params_get();
    struct block b;
    block_init(&b);
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(*b.vtx));
    if (!research || !ordinary || !b.vtx) { block_free(&b); return 1; }
    transaction_init(b.vtx);
    if (!transaction_alloc(b.vtx, 0, 251)) { block_free(&b); return 1; }
    for (size_t i = 0; i < 249; ++i) {
        b.vtx[0].vout[i].script_pub_key.size = 8000;
        memset(b.vtx[0].vout[i].script_pub_key.data, 0x51, 8000);
    }
    struct byte_stream stream;
    stream_init(&stream, 0);
    bool ok = block_serialize(&b, &stream);
    size_t base = stream.size;
    stream_free(&stream);
    if (!ok || base >= 2000000 || 2000001 - base >= MAX_SCRIPT_SIZE) {
        block_free(&b);
        return 1;
    }
    struct script *s = &b.vtx[0].vout[249].script_pub_key;
    s->size = 2000000 - base - 2;
    memset(s->data, 0x51, s->size + 1);
    bool exact = research_block_size_check_ceiling(research->chain, &b) == RESEARCH_BLOCK_SIZE_OK;
    ++s->size;
    bool over = research_block_size_check_ceiling(research->chain, &b) == RESEARCH_BLOCK_SIZE_EXCEEDED;
    zcl_alloc_fault_fail_next("research block size");
    bool unchanged = research_block_size_check_ceiling(ordinary, &b) == RESEARCH_BLOCK_SIZE_OK &&
                     zcl_alloc_fault_armed_label() != NULL;
    zcl_alloc_fault_clear();
    block_free(&b);
    return exact && over && unchanged ? 0 : 1;
}

static int unwalkable_size_test(void)
{
    struct block b;
    block_init(&b);
    b.num_vtx = 1;
    bool missing = research_block_size_measure(&b, RESEARCH_BLOCK_SIZE_LIMIT) ==
                   RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    bool null = research_block_size_measure(NULL, RESEARCH_BLOCK_SIZE_LIMIT) ==
                RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    return missing && null ? 0 : 1;
}

/* A rejected input that consumed a window slot or tally could shift activation.
 * Compare a tracker that sees bad inputs with one that never sees them. */
static int tracker_retry_test(struct gate_fixture *f)
{
    struct research_rules_tracker *a = research_rules_tracker_create(&f->binding);
    struct research_rules_tracker *b = research_rules_tracker_create(&f->binding);
    bool ok = a && b;
    bool activated = false;
    for (int h = 102; ok && h < 126; ++h) {
        if (h == 103) {
            struct block bad = f->blocks[h];
            bad.header.nTime++;
            ok = research_rules_tracker_connect(a, &f->index[h], &bad).code ==
                 RESEARCH_RULES_UNAVAILABLE;
            bad = f->blocks[h];
            memset(&bad.header.hashPrevBlock, 0, sizeof bad.header.hashPrevBlock);
            ok = ok && research_rules_tracker_connect(a, &f->index[h], &bad).code ==
                 RESEARCH_RULES_INVALID;
        }
        ok = ok && research_rules_tracker_connect(a, &f->index[h], &f->blocks[h]).ok &&
             research_rules_tracker_connect(b, &f->index[h], &f->blocks[h]).ok;
        struct research_rules_state sa = {0}, sb = {0};
        ok = ok && research_rules_tracker_state(a, &sa).ok &&
             research_rules_tracker_state(b, &sb).ok;
        for (size_t i = 0; ok && i < RESEARCH_RULE_COUNT; ++i)
            ok = sa.active[i] == sb.active[i];
        if (sa.active[RESEARCH_RULE_BLOCK_CAP]) activated = true;
    }
    research_rules_tracker_destroy(a);
    research_rules_tracker_destroy(b);
    if (!ok || !activated) fprintf(stderr, "research gate: tracker retry mismatch\n");
    return ok && activated ? 0 : 1;
}

static int reducer_hold_test(struct gate_fixture *f, struct block *candidate, const char *dir)
{
    struct main_state ms;
    main_state_init(&ms);
    const struct research_rules_binding *installed = research_rules_binding();
    bool setup = SetDataDir(dir) &&
                  test_block_map_insert(&ms.map_block_index, f->index[125].phashBlock,
                                        &f->index[125]) &&
                  (installed ? installed->params == f->binding.params &&
                               installed->pin == f->binding.pin
                             : research_rules_install(f->binding.params, f->binding.pin));
    candidate->header.hashPrevBlock = *f->index[125].phashBlock;
    struct chain_activation_controller ctl = { .ms = &ms, .params = f->binding.params };
    struct validation_state state;
    unsigned before = block_index_status_load(&f->index[125]);
    size_t entries = ms.map_block_index.size;
    bool admitted = setup && reducer_stage_p2p_block_for_catchup(&ctl, candidate, &state);
    bool held = setup && !admitted && state.mode == MODE_ERROR &&
                !strcmp(state.reject_reason, "p2p-block-intake-unavailable") &&
                before == block_index_status_load(&f->index[125]) &&
                entries == ms.map_block_index.size;
    admitted = setup && reducer_ingest_block(&ctl, candidate, REDUCER_SRC_P2P, false, &state);
    held = held && !admitted && state.mode == MODE_ERROR &&
           !strcmp(state.reject_reason, "p2p-block-intake-unavailable") &&
           before == block_index_status_load(&f->index[125]) &&
           entries == ms.map_block_index.size;
    admitted = setup && reducer_ingest_block(&ctl, candidate, REDUCER_SRC_COMPACT, false, &state);
    held = held && !admitted && state.mode == MODE_ERROR &&
           !strcmp(state.reject_reason, "p2p-block-intake-unavailable");
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    bool restored = write_block_to_disk(&f->blocks[103], &pos, dir,
                                        f->binding.params->pchMessageStart);
    if (restored) {
        block_index_disk_pos_store(&f->index[103], pos.nFile, pos.nPos);
        admitted = reducer_stage_p2p_block_for_catchup(&ctl, candidate, &state);
        restored = admitted || strcmp(state.reject_reason, "p2p-block-intake-unavailable");
    }
    main_state_free(&ms);
    SetDataDir("");
    ClearDataDirCache();
    if (!held || !restored) fprintf(stderr, "research gate: reducer hold/retry failed\n");
    return held && restored ? 0 : 1;
}

static int reducer_hold_selected(struct gate_fixture *f, struct block *candidate, const char *dir)
{
    if (!chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return 1;
    return reducer_hold_test(f, candidate, dir);
}

static int activation_test(void)
{
    int failures = 0;
    char raw[PATH_MAX], dir[PATH_MAX];
    test_make_tmpdir(raw, sizeof raw, "research_gate", "blocks");
    if (!platform_directory_canonical_real(raw, dir, sizeof dir)) return 1;
    static struct gate_fixture f;
    memset(&f, 0, sizeof f);
    bool selected = chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD);
    bool ok = selected && gate_fixture_init(&f, dir);
    if (ok) failures += tracker_retry_test(&f);
    struct block b;
    block_init(&b);
    b.num_vtx = 2;
    b.vtx = calloc(2, sizeof(*b.vtx));
    if (!ok || !b.vtx) { failures++; goto done; }
    transaction_init(&b.vtx[0]);
    transaction_init(&b.vtx[1]);
    if (!transaction_alloc(&b.vtx[0], 1, 25)) { failures++; goto done; }
    outpoint_set_null(&b.vtx[0].vin[0].prevout);
    for (size_t i = 0; i < 24; ++i) {
        b.vtx[0].vout[i].script_pub_key.size = 8000;
        memset(b.vtx[0].vout[i].script_pub_key.data, 0x51, 8000);
    }
    struct byte_stream stream;
    stream_init(&stream, 0);
    ok = block_serialize(&b, &stream);
    size_t base = stream.size;
    stream_free(&stream);
    if (!ok || base >= 200000 || 200001 - base >= MAX_SCRIPT_SIZE) {
        failures++; goto done;
    }
    struct script *s = &b.vtx[0].vout[24].script_pub_key;
    s->size = 200001 - base - 2;
    memset(s->data, 0x51, s->size);
    struct research_gate_decision unbound = research_rules_gate_for(NULL, NULL, &b, NULL, NULL);
    failures += expect_gate("unbound oversized", unbound, RESEARCH_GATE_PASS, NULL, 0);
    struct research_gate_decision d = research_rules_gate_for(&f.binding, f.binding.params, &b,
                                                              &f.index[123], dir);
    failures += expect_gate("inactive cap", d, RESEARCH_GATE_PASS, NULL, 0);
    d = research_rules_gate_for(&f.binding, f.binding.params, &b, &f.index[124], dir);
    failures += expect_gate("active cap", d, RESEARCH_GATE_REJECT, "research-block-size-limit", 0);
    --s->size;
    d = research_rules_gate_for(&f.binding, f.binding.params, &b, &f.index[124], dir);
    failures += expect_gate("inclusive cap", d, RESEARCH_GATE_PASS, NULL, 0);
    b.vtx[1].value_balance = -1;
    d = research_rules_gate_for(&f.binding, f.binding.params, &b, &f.index[125], dir);
    failures += expect_gate("deposit freeze", d, RESEARCH_GATE_REJECT, "research-deposit-freeze", 2);
    b.vtx[1].value_balance = 1;
    d = research_rules_gate_for(&f.binding, f.binding.params, &b, &f.index[125], dir);
    failures += expect_gate("withdrawal", d, RESEARCH_GATE_PASS, NULL, 0);
    block_index_disk_pos_store(&f.index[103], -1, 0);
    d = research_rules_gate_for(&f.binding, f.binding.params, &b, &f.index[125], dir);
    failures += expect_gate("missing body", d, RESEARCH_GATE_HOLD, "research-rules-unavailable", 0);
    if (d.rules.active[0] || d.rules.active[1]) failures++;
    struct research_rules_binding invalid = { chain_params_get(), &f.pin };
    chain_params_select(CHAIN_MAIN);
    invalid.params = chain_params_get();
    d = research_rules_gate_for(&invalid, invalid.params, &b, &f.index[125], dir);
    failures += expect_gate("invalid binding", d, RESEARCH_GATE_HOLD, "research-rules-unavailable", 0);
    failures += reducer_hold_selected(&f, &b, raw);
done:
    block_free(&b);
    if (f.blocks) {
        for (int h = 0; h < 126; ++h) block_free(&f.blocks[h]);
        free(f.blocks);
        f.blocks = NULL;
    }
    chain_params_select(CHAIN_MAIN);
    (void)test_rm_rf_recursive(raw);
    if (failures) fprintf(stderr, "research rules gate: activation fixture failures=%d\n", failures);
    return failures;
}

int test_research_rules_gate(void)
{
    struct block b;
    block_init(&b);
    struct research_gate_decision d = research_rules_gate_for(NULL, NULL, &b, NULL, NULL);
    block_free(&b);
    if (d.verdict != RESEARCH_GATE_PASS || d.rules.active[0] || d.rules.active[1] ||
        d.rule || d.offender) {
        fprintf(stderr, "research rules gate: unbound pass failed\n");
        return 1;
    }
    int failures = unwalkable_size_test() + ceiling_test();
    failures += activation_test();
    const struct research_rules_binding *installed = research_rules_binding();
    const struct miner_signal_catalog_pin *pin = installed ? installed->pin : NULL;
    failures += activation_test();
    installed = research_rules_binding();
    if (!installed || installed->pin != pin || !pin ||
        pin->start != 103 || pin->window != 20)
        failures++;
    return failures;
}
