/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/research_rules_gate.h"
#include "base/hex.h"
#include "services/research_block_size.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_decode.h"
#include "util/safe_alloc.h"
#include "storage/disk_block_io.h"
#include "platform/directory_compat.h"
#include "test/test_core.h"
#include "test/test_block_map.h"
#include "services/chain_activation_service.h"
#include "services/replay_verify_service.h"
#include "ports/block_log_port.h"
#include "validation/main_state.h"
#include "consensus/validation.h"
#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "net/download.h"
#include "net/peer_scoring.h"
#include "util/util.h"
#include <stdatomic.h>
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
        struct block *b = &f->blocks[h]; block_init(b);
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
            struct disk_block_pos pos; disk_block_pos_init(&pos);
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
    struct block b; block_init(&b);
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(*b.vtx));
    if (!research || !ordinary || !b.vtx) { block_free(&b); return 1; }
    transaction_init(b.vtx);
    if (!transaction_alloc(b.vtx, 0, 251)) { block_free(&b); return 1; }
    for (size_t i = 0; i < 249; ++i) {
        b.vtx[0].vout[i].script_pub_key.size = 8000;
        memset(b.vtx[0].vout[i].script_pub_key.data, 0x51, 8000);
    }
    struct byte_stream stream; stream_init(&stream, 0);
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
static bool checked_reward_size(void)
{
    uint8_t wire[9313];
    FILE *f = fopen("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", "rb");
    if (!f) return false;
    bool read = fread(wire, 1, sizeof wire, f) == sizeof wire && fgetc(f) == EOF && !ferror(f);
    fclose(f);
    if (!read) return false;
    struct byte_stream input;
    stream_init_from_data(&input, wire, sizeof wire);
    struct transaction reward;
    struct block b;
    block_init(&b);
    bool decoded = transaction_v6_decode_prefix(&reward, &input, sizeof wire);
    b.vtx = &reward;
    b.num_vtx = 1;
    /* 140 fixed header bytes, empty solution CompactSize, one tx CompactSize. */
    size_t exactly = 142 + sizeof wire;
    bool ok = decoded && !stream_remaining(&input) &&
        research_block_size_measure(&b, exactly) == RESEARCH_BLOCK_SIZE_OK &&
        research_block_size_measure(&b, exactly - 1) == RESEARCH_BLOCK_SIZE_EXCEEDED;
    reward.ironwood_value_balance ^= 1;
    ok = ok && research_block_size_measure(&b, exactly) == RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    transaction_free(&reward);
    return ok;
}
static int unwalkable_size_test(void)
{
    struct block b; block_init(&b);
    b.num_vtx = 1;
    bool missing = research_block_size_measure(&b, RESEARCH_BLOCK_SIZE_LIMIT) ==
                   RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    bool null = research_block_size_measure(NULL, RESEARCH_BLOCK_SIZE_LIMIT) ==
                RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    return missing && null ? 0 : 1;
}
static bool tracker_bad_inputs(struct gate_fixture *f, struct research_rules_tracker *a, int h)
{
    struct block bad = f->blocks[h];
    bad.header.nTime++;
    if (research_rules_tracker_connect(a, &f->index[h], &bad).code !=
        RESEARCH_RULES_UNAVAILABLE) {
        fprintf(stderr, "research gate: bad hash was not held\n");
        return false;
    }
    bad = f->blocks[h];
    memset(&bad.header.hashPrevBlock, 0, sizeof bad.header.hashPrevBlock);
    if (research_rules_tracker_connect(a, &f->index[h], &bad).code != RESEARCH_RULES_INVALID) {
        fprintf(stderr, "research gate: bad linkage was not rejected\n");
        return false;
    }
    return true;
}
static bool tracker_compare_step(struct gate_fixture *f, struct research_rules_tracker *a,
                                 struct research_rules_tracker *b, int h, bool *activated)
{
    if (!research_rules_tracker_connect(a, &f->index[h], &f->blocks[h]).ok) return false;
    if (!research_rules_tracker_connect(b, &f->index[h], &f->blocks[h]).ok) return false;
    struct research_rules_state sa = {0}, sb = {0};
    if (!research_rules_tracker_state(a, &sa).ok) return false;
    if (!research_rules_tracker_state(b, &sb).ok) return false;
    for (size_t i = 0; i < RESEARCH_RULE_COUNT; ++i)
        if (sa.active[i] != sb.active[i]) return false;
    if (sa.active[RESEARCH_RULE_BLOCK_CAP]) *activated = true;
    return true;
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
        if (h == 103) ok = tracker_bad_inputs(f, a, h);
        if (ok) ok = tracker_compare_step(f, a, b, h, &activated);
    }
    research_rules_tracker_destroy(a);
    research_rules_tracker_destroy(b);
    if (!ok || !activated) fprintf(stderr, "research gate: tracker retry mismatch\n");
    return ok && activated ? 0 : 1;
}
static bool reducer_hold_result(bool admitted, const struct validation_state *state)
{
    if (admitted) return false;
    if (state->mode != MODE_ERROR) return false;
    return !strcmp(state->reject_reason, "p2p-block-intake-unavailable");
}
static bool reducer_hold_paths(struct gate_fixture *f, struct main_state *ms,
                               struct chain_activation_controller *ctl, struct block *candidate)
{
    struct validation_state state;
    unsigned before = block_index_status_load(&f->index[125]);
    size_t entries = ms->map_block_index.size;
    bool admitted = reducer_stage_p2p_block_for_catchup(ctl, candidate, &state);
    if (!reducer_hold_result(admitted, &state)) return false;
    if (before != block_index_status_load(&f->index[125])) return false;
    if (entries != ms->map_block_index.size) return false;
    admitted = reducer_ingest_block(ctl, candidate, REDUCER_SRC_P2P, false, &state);
    if (!reducer_hold_result(admitted, &state)) return false;
    if (before != block_index_status_load(&f->index[125])) return false;
    if (entries != ms->map_block_index.size) return false;
    admitted = reducer_ingest_block(ctl, candidate, REDUCER_SRC_COMPACT, false, &state);
    return reducer_hold_result(admitted, &state);
}
static bool reducer_write_window(struct gate_fixture *f, const char *dir)
{
    struct disk_block_pos pos; disk_block_pos_init(&pos);
    if (!write_block_to_disk(&f->blocks[103], &pos, dir, f->binding.params->pchMessageStart))
        return false;
    block_index_disk_pos_store(&f->index[103], pos.nFile, pos.nPos);
    return true;
}
static bool reducer_restore_window(struct gate_fixture *f, struct chain_activation_controller *ctl,
                                   struct block *candidate, const char *dir)
{
    if (!reducer_write_window(f, dir)) return false;
    struct validation_state state;
    bool admitted = reducer_stage_p2p_block_for_catchup(ctl, candidate, &state);
    return admitted || strcmp(state.reject_reason, "p2p-block-intake-unavailable");
}
struct hold_message_context {
    struct chain_activation_controller *ctl;
    struct validation_state verdict;
    bool admitted;
    int calls;
};
static bool hold_message_submit(struct block *block, struct validation_state *state, void *ctx)
{
    struct hold_message_context *hold = ctx;
    bool accepted = reducer_stage_p2p_block_for_catchup(hold->ctl, block, state);
    hold->admitted = accepted;
    hold->verdict = *state;
    hold->calls++;
    return accepted;
}
static bool reducer_hold_message(struct gate_fixture *f, struct main_state *ms,
                                 struct chain_activation_controller *ctl,
                                 struct hold_message_context *result, bool expect_hold)
{
    struct block block = f->blocks[125];
    block.header.hashPrevBlock = *f->index[125].phashBlock;
    struct uint256 hash; block_get_hash(&block, &hash);
    block_clear_seen(&hash);
    struct byte_stream stream; stream_init(&stream, 256);
    bool ok = block_serialize(&block, &stream);
    struct download_manager *dm = get_download_mgr();
    dl_init(dm);
    peer_scoring_init();
    struct p2p_node node = {0};
    node.id = 42;
    atomic_init(&node.misbehavior, 0);
    struct hold_message_context hold = { .ctl = ctl };
    struct msg_processor mp = { .main_state = ms, .block_submit = hold_message_submit,
                                .block_submit_ctx = &hold };
    if (ok) ok = dl_mark_requested(dm, &hash, 126, node.id);
    if (ok) ok = process_block_msg(&mp, &node, &stream);
    if (hold.calls != 1) ok = false;
    if (expect_hold && !reducer_hold_result(hold.admitted, &hold.verdict)) ok = false;
    if (expect_hold && atomic_load(&node.misbehavior) != 0) ok = false;
    if (expect_hold && block_already_seen(&hash)) ok = false;
    if (result) *result = hold;
    dl_free(dm);
    stream_free(&stream);
    if (!ok) fprintf(stderr, "research gate: held message scored or not retryable\n");
    return ok;
}
static bool reducer_fixture_setup(struct gate_fixture *f, struct main_state *ms,
                                  struct chain_activation_controller *ctl, const char *dir,
                                  bool window_body_present)
{
    main_state_init(ms);
    *ctl = (struct chain_activation_controller){ .ms = ms, .params = f->binding.params };
    if (!window_body_present) block_index_disk_pos_store(&f->index[103], -1, 0);
    if (window_body_present && !reducer_write_window(f, dir)) return false;
    if (!SetDataDir(dir)) return false;
    if (!test_block_map_insert(&ms->map_block_index, f->index[125].phashBlock, &f->index[125]))
        return false;
    const struct research_rules_binding *installed = research_rules_binding();
    if (!installed) return research_rules_install(f->binding.params, f->binding.pin);
    return installed->params == f->binding.params && installed->pin == f->binding.pin;
}
static bool compare_verdict(const char *path, bool retry, struct validation_state *a,
                            bool control, struct validation_state *b)
{
    fprintf(stderr, "research gate %s: retry=%d mode=%d reason=%s control=%d mode=%d reason=%s\n",
            path, retry, a->mode, a->reject_reason, control, b->mode, b->reject_reason);
    return retry == control && a->mode == b->mode && !strcmp(a->reject_reason, b->reject_reason);
}
enum probe_path { PROBE_CATCHUP, PROBE_P2P, PROBE_COMPACT, PROBE_MESSAGE, PROBE_COUNT };
static const char *const probe_names[] = { "catchup", "p2p", "compact", "message" };
static bool reducer_probe_call(struct gate_fixture *f, struct main_state *ms,
                               struct chain_activation_controller *ctl, struct block *candidate,
                               enum probe_path path, bool expect_hold,
                               struct hold_message_context *result)
{
    if (path == PROBE_MESSAGE)
        return reducer_hold_message(f, ms, ctl, result, expect_hold);
    if (path == PROBE_CATCHUP)
        result->admitted = reducer_stage_p2p_block_for_catchup(ctl, candidate, &result->verdict);
    else
        result->admitted = reducer_ingest_block(ctl, candidate,
            path == PROBE_P2P ? REDUCER_SRC_P2P : REDUCER_SRC_COMPACT, false, &result->verdict);
    return !expect_hold || reducer_hold_result(result->admitted, &result->verdict);
}
/* Every invocation owns a new map and ancestry. The held intake must leave
 * that state unchanged; both measured intakes therefore have no prior intake. */
static void reducer_clone_fixture(struct gate_fixture *dst, struct gate_fixture *src)
{
    *dst = *src;
    for (int h = 0; h < 126; ++h) {
        dst->index[h].pprev = h ? &dst->index[h - 1] : NULL;
        dst->index[h].phashBlock = &dst->index[h].hashBlock;
    }
}
static bool reducer_probe(struct gate_fixture *f, struct block *candidate, const char *dir,
                          enum probe_path path, bool hold, struct hold_message_context *first,
                          struct hold_message_context *result)
{
    static struct gate_fixture local;
    reducer_clone_fixture(&local, f);
    *first = (struct hold_message_context){0};
    struct main_state ms; struct chain_activation_controller ctl;
    bool ok = reducer_fixture_setup(&local, &ms, &ctl, dir, !hold);
    unsigned before = block_index_status_load(&local.index[125]);
    size_t entries = ms.map_block_index.size;
    if (ok && hold) ok = reducer_probe_call(&local, &ms, &ctl, candidate, path, true, first);
    if (ok && hold) ok = before == block_index_status_load(&local.index[125]);
    if (ok && hold) ok = entries == ms.map_block_index.size;
    if (ok && hold) ok = reducer_write_window(&local, dir);
    if (ok) ok = reducer_probe_call(&local, &ms, &ctl, candidate, path, false, result);
    main_state_free(&ms);
    return ok;
}
static bool reducer_compare_paths(struct gate_fixture *f, struct block *candidate, const char *dir)
{
    for (enum probe_path path = PROBE_CATCHUP; path < PROBE_COUNT; ++path) {
        struct hold_message_context first = {0}, unused = {0}, retry = {0}, control = {0};
        if (!reducer_probe(f, candidate, dir, path, true, &first, &retry)) return false;
        if (!reducer_probe(f, candidate, dir, path, false, &unused, &control)) return false;
        if (!reducer_hold_result(first.admitted, &first.verdict)) {
            fprintf(stderr, "research gate %s: first probe was not held\n", probe_names[path]);
            return false;
        }
        if (reducer_hold_result(unused.admitted, &unused.verdict)) {
            fprintf(stderr, "research gate %s: control was held before measurement\n", probe_names[path]);
            return false;
        }
        if (reducer_hold_result(control.admitted, &control.verdict)) {
            fprintf(stderr, "research gate %s: control was held\n", probe_names[path]);
            return false;
        }
        if (!compare_verdict(probe_names[path], retry.admitted, &retry.verdict,
                             control.admitted, &control.verdict)) return false;
    }
    return true;
}
static bool reducer_cumulative_holds(struct gate_fixture *f, struct main_state *ms,
                                     struct chain_activation_controller *ctl,
                                     struct block *candidate)
{
    unsigned before = block_index_status_load(&f->index[125]);
    size_t entries = ms->map_block_index.size;
    for (enum probe_path path = PROBE_CATCHUP; path < PROBE_COUNT; ++path) {
        struct hold_message_context first = {0};
        if (!reducer_probe_call(f, ms, ctl, candidate, path, true, &first)) return false;
        if (!reducer_hold_result(first.admitted, &first.verdict)) return false;
        if (before != block_index_status_load(&f->index[125])) return false;
        if (entries != ms->map_block_index.size) return false;
    }
    return true;
}
static bool reducer_cumulative_retries(struct gate_fixture *f, struct main_state *ms,
                                       struct chain_activation_controller *ctl,
                                       struct block *candidate, const char *dir)
{
    for (enum probe_path path = PROBE_CATCHUP; path < PROBE_COUNT; ++path) {
        struct hold_message_context retry = {0}, control = {0}, unused = {0};
        if (!reducer_probe_call(f, ms, ctl, candidate, path, false, &retry)) return false;
        if (!reducer_probe(f, candidate, dir, path, false, &unused, &control)) return false;
        if (reducer_hold_result(unused.admitted, &unused.verdict)) return false;
        if (reducer_hold_result(control.admitted, &control.verdict)) return false;
        if (!compare_verdict(probe_names[path], retry.admitted, &retry.verdict,
                             control.admitted, &control.verdict)) return false;
    }
    return true;
}
static bool reducer_cumulative_sequence(struct gate_fixture *f, struct block *candidate,
                                        const char *dir)
{
    static struct gate_fixture local;
    reducer_clone_fixture(&local, f);
    struct main_state ms; struct chain_activation_controller ctl;
    bool ok = reducer_fixture_setup(&local, &ms, &ctl, dir, false);
    if (ok) ok = reducer_cumulative_holds(&local, &ms, &ctl, candidate);
    if (ok) ok = reducer_write_window(&local, dir);
    if (ok) ok = reducer_cumulative_retries(&local, &ms, &ctl, candidate, dir);
    main_state_free(&ms);
    return ok;
}
static int reducer_results(bool held, bool message_held, bool restored, bool compared)
{
    if (!held || !message_held || !restored || !compared)
        fprintf(stderr, "research gate: reducer hold/retry failed\n");
    return held && message_held && restored && compared ? 0 : 1;
}
static int reducer_hold_test(struct gate_fixture *f, struct block *candidate, const char *dir)
{
    struct main_state ms; struct chain_activation_controller ctl;
    bool setup = reducer_fixture_setup(f, &ms, &ctl, dir, false);
    candidate->header.hashPrevBlock = *f->index[125].phashBlock;
    bool held = setup && reducer_hold_paths(f, &ms, &ctl, candidate);
    struct block message_candidate = f->blocks[125];
    message_candidate.header.hashPrevBlock = *f->index[125].phashBlock;
    held = held && reducer_hold_paths(f, &ms, &ctl, &message_candidate);
    bool message_held = setup && reducer_hold_message(f, &ms, &ctl, NULL, true);
    bool restored = reducer_restore_window(f, &ctl, candidate, dir);
    bool compared = restored && reducer_compare_paths(f, candidate, dir);
    compared = compared && reducer_compare_paths(f, &message_candidate, dir);
    compared = compared && reducer_cumulative_sequence(f, candidate, dir);
    main_state_free(&ms);
    SetDataDir(""); ClearDataDirCache();
    return reducer_results(held, message_held, restored, compared);
}
static int reducer_hold_selected(struct gate_fixture *f, struct block *candidate, const char *dir)
{
    if (!chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD)) return 1;
    return reducer_hold_test(f, candidate, dir);
}
struct replay_gate_fixture {
    struct gate_fixture *gate;
    int visited;
};
static uint32_t replay_gate_tip(void *ctx)
{
    (void)ctx;
    return 1;
}
static struct zcl_result replay_gate_iter(void *ctx, uint32_t start, block_log_iter_fn cb,
                                         void *user)
{
    struct replay_gate_fixture *f = ctx;
    for (uint32_t h = start; h < 2; ++h) {
        struct byte_stream stream; stream_init(&stream, 256);
        if (!block_serialize(&f->gate->blocks[h], &stream)) {
            stream_free(&stream);
            return ZCL_ERR(-1, "fixture block serialization failed");
        }
        struct block_hash hash;
        memcpy(hash.bytes, f->gate->index[h].hashBlock.data, sizeof hash.bytes);
        f->visited++;
        bool more = cb(h, &hash, stream.data, stream.size, user);
        stream_free(&stream);
        if (!more) break;
    }
    return ZCL_OK;
}
/* A bound replay stops at the PoW failure before visiting its successor. */
static int replay_pow_stop_test(struct gate_fixture *f)
{
    struct replay_gate_fixture fixture = { .gate = f };
    struct block_log_port port = { .self = &fixture, .tip_height = replay_gate_tip,
                                   .iter_from = replay_gate_iter };
    struct replay_verify_report report;
    struct zcl_result result = replay_verify_run_port(&port, 0, 0, &report);
    bool ok = result.code == -8;
    if (report.pow_failures != 1) ok = false;
    if (report.blocks_checked != 1) ok = false;
    if (fixture.visited != 1) ok = false;
    if (!report.first_fail_reason || strcmp(report.first_fail_reason, "pow")) ok = false;
    if (!ok) fprintf(stderr, "research gate: bound replay did not stop at PoW failure\n");
    return ok ? 0 : 1;
}
static bool activation_candidate_init(struct block *b)
{
    block_init(b);
    b->num_vtx = 2;
    b->vtx = calloc(2, sizeof(*b->vtx));
    if (!b->vtx) return false;
    transaction_init(&b->vtx[0]);
    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[0], 1, 25)) return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    for (size_t i = 0; i < 24; ++i) {
        b->vtx[0].vout[i].script_pub_key.size = 8000;
        memset(b->vtx[0].vout[i].script_pub_key.data, 0x51, 8000);
    }
    struct byte_stream stream; stream_init(&stream, 0);
    bool ok = block_serialize(b, &stream);
    size_t base = stream.size;
    stream_free(&stream);
    if (!ok || base >= 200000 || 200001 - base >= MAX_SCRIPT_SIZE) return false;
    struct script *s = &b->vtx[0].vout[24].script_pub_key;
    s->size = 200001 - base - 2;
    memset(s->data, 0x51, s->size);
    return true;
}
static int activation_test(void)
{
    int failures = 0;
    char raw[PATH_MAX], dir[PATH_MAX];
    test_make_tmpdir(raw, sizeof raw, "research_gate", "blocks");
    if (!platform_directory_canonical_real(raw, dir, sizeof dir)) return 1;
    static struct gate_fixture f; memset(&f, 0, sizeof f);
    bool selected = chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD);
    bool ok = selected && gate_fixture_init(&f, dir);
    if (ok) failures += tracker_retry_test(&f);
    struct block b;
    bool candidate_ready = activation_candidate_init(&b);
    if (!ok || !candidate_ready) { failures++; goto done; }
    struct script *s = &b.vtx[0].vout[24].script_pub_key;
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
    failures += replay_pow_stop_test(&f);
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
    struct block b; block_init(&b);
    struct research_gate_decision d = research_rules_gate_for(NULL, NULL, &b, NULL, NULL);
    block_free(&b);
    if (d.verdict != RESEARCH_GATE_PASS || d.rules.active[0] || d.rules.active[1] ||
        d.rule || d.offender) {
        fprintf(stderr, "research rules gate: unbound pass failed\n");
        return 1;
    }
    int failures = unwalkable_size_test() + ceiling_test() + !checked_reward_size();
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
