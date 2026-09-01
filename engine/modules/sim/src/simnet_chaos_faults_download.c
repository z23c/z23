/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: chaos faults (j)-(m) — the download/peer-behaviour half of the
 * sync fault matrix: a header reorg landing mid artifact download, a
 * slow-loris seeder that never finishes a chunk, an invalid tail block after
 * a valid bundle, and a peer disconnect mid body-download whose resume must
 * not refetch what BLOCK_HAVE_DATA already covers.
 *
 * Split out of simnet_chaos_faults.c along the file-size ceiling seam. The
 * ROM fixture helpers these faults share live in simnet_chaos_faults_rom.c;
 * see sim/simnet_chaos_faults.h for the per-fault contract, and
 * simnet_chaos_faults_internal.h for the symbols that cross the seam.
 */

#include "simnet_chaos_faults_internal.h"

#include "sim/simnet_chaos_faults.h"
#include "platform/file_sync.h"

#include "test/test_helpers.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "coins/coins_view.h"
#include "conditions/segment_corruption.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_rederive_range.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_row_itag.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "net/download.h"
#include "net/file_service.h"
#include "net/rom_fetch.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"
#include "sim/simnet.h"
#include "sim/simnet_byzantine.h"
#include "storage/chain_segment.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "sync/sync_planner.h"
#include "sync/sync_reduce.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "validation/main_state.h"
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ══════════════════════════════════════════════════════════════════════
 * (j) header reorg during an artifact download — the PURE kernel, no IO
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_reorg_during_artifact_download(uint64_t seed,
                                                struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "PEER_LOST fired mid-RECEIVING (the reorged-anchor signal)");

    uint64_t sid = 1000ull + (seed % 1000ull);
    struct sync_kernel_state st;
    memset(&st, 0, sizeof(st));
    st.session_id.value = sid;
    st.phase = SYNC_PHASE_IDLE;
    uint32_t evn = 0;

    struct sync_event e;
#define SFM_STEP(kind_) do {                                               \
        memset(&e, 0, sizeof(e));                                          \
        e.session_id.value = sid;                                          \
        e.kind = (kind_);                                                  \
        struct sync_transition d = sync_reduce(st, e);                     \
        st.phase = d.next_state.phase;                                     \
        evn++;                                                             \
    } while (0)

    /* Legitimate negotiation with a couple chunks already in flight. */
    SFM_STEP(SYNC_EVENT_START);
    SFM_STEP(SYNC_EVENT_OFFER_RECEIVED);
    SFM_STEP(SYNC_EVENT_OFFER_ACCEPTED);
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    bool receiving_before = (st.phase == SYNC_PHASE_RECEIVING);
    snprintf(out->state_before, sizeof(out->state_before),
             "phase=%s (mid-download, chunks already in flight)",
             sync_phase_name(st.phase));

    /* THE FAULT: PEER_LOST — the kernel's typed stand-in for "the anchor
     * this session was chasing was reorged out from under it" (no separate
     * REORG event exists in the catalog; see sim/simnet_chaos_faults.h (j)). */
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = SYNC_EVENT_PEER_LOST;
    struct sync_transition fault_decision = sync_reduce(st, e);
    st.phase = fault_decision.next_state.phase;
    evn++;

    bool failed_named = fault_decision.next_state.phase == SYNC_PHASE_FAILED &&
                        fault_decision.has_blocker &&
                        fault_decision.blocker == SYNC_BLOCKER_PEER_LOST &&
                        fault_decision.action_count == 1 &&
                        fault_decision.actions[0] == SYNC_ACTION_FAIL;

    /* NEVER installed: further progress on the SAME (now-stale-anchor)
     * session — even a PASSING proof — must never reach STAGE_BUNDLE. */
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    SFM_STEP(SYNC_EVENT_RECEIVE_COMPLETE);
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = SYNC_EVENT_PROOF_VERIFIED;
    e.proof_ok = true;
    struct sync_transition final_decision = sync_reduce(st, e);
    st.phase = final_decision.next_state.phase;
    evn++;
#undef SFM_STEP

    bool never_reactivated = st.phase == SYNC_PHASE_FAILED;
    bool never_staged = true;
    for (int i = 0; i < final_decision.action_count; i++)
        if (final_decision.actions[i] == SYNC_ACTION_STAGE_BUNDLE)
            never_staged = false;

    const char *blocker_str = fault_decision.has_blocker &&
                              fault_decision.blocker == SYNC_BLOCKER_PEER_LOST
        ? "peer_lost" : "none";
    snprintf(out->state_after, sizeof(out->state_after),
             "phase=%s blocker=%s never_staged=%d never_reactivated=%d",
             sync_phase_name(st.phase), blocker_str, never_staged,
             never_reactivated);
    out->event_number = evn;
    snprintf(out->phase, sizeof(out->phase), "%s",
             sync_phase_name(SYNC_PHASE_RECEIVING));
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_reorg_during_artifact_download(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = receiving_before;
    out->base.recovered = failed_named && never_staged && never_reactivated;
    /* FAILED + a typed blocker IS this fault's intended outcome — the pure
     * kernel does not itself page an operator (that is the condition
     * engine's job, exercised by faults (e)/(k)); no page is expected here. */
    out->base.operator_paged = false;
    sfm_note(out, "reorg mid-download: PEER_LOST -> phase=%s blocker=%s "
             "never_staged=%d never_reactivated=%d", sync_phase_name(st.phase),
             blocker_str, never_staged, never_reactivated);
    return true;
}
/* ══════════════════════════════════════════════════════════════════════
 * (k) slow-loris seeder — bounded stall, never a silent hang
 * ══════════════════════════════════════════════════════════════════════ */

/* Guarded exactly like (d)/(e) above: supervisor_reset_for_testing /
 * supervisor_sweep_once_for_testing are ZCL_TESTING-only, and this file also
 * compiles into the production zclassic23 binary (engine/modules/sim is a LIB_MODULE
 * linked into every target) which builds WITHOUT ZCL_TESTING. Reuses the
 * `chaos_sleep_ms` helper defined above (d)'s block — still in scope here,
 * same translation unit. */
#ifdef ZCL_TESTING
bool chaos_fault_slow_loris_seeder(uint64_t seed,
                                   struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "seeder accepted the connection, then sent nothing");

    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);

    static struct liveness_contract c;
    liveness_contract_init(&c, "chaos.rom_fetch_wait");
    atomic_store(&c.deadline_secs, 1);
    supervisor_domain_t *domain = supervisor_create_domain("chaos");
    supervisor_child_id id = domain
        ? supervisor_register_in_domain(domain, &c)
        : SUPERVISOR_INVALID_ID;
    if (id == SUPERVISOR_INVALID_ID) {
        sfm_note(out, "supervisor_register_in_domain failed");
        return false;
    }

    /* This child is a fault INJECTION: the case backdates its heartbeat
     * on purpose so the supervisor declares it stalled. It has no work
     * units to report and never will, so it is exempt rather than armed
     * -- arming it would mean asserting progress the fixture exists to
     * withhold. Test-only: the whole block is inside ZCL_TESTING. */
    supervisor_set_progress_exempt(
        id, "synthetic stall fixture: no work units by construction");

    /* THE FAULT: the seeder accepted the connection (the client would be
     * blocked in a real recv() on the socket) but never sends a byte —
     * modeled at the same supervisor liveness primitive every bounded-stall
     * class in this codebase surfaces through (mirrors
     * chaos_fault_freeze_reducer_drive exactly, a distinct domain/contract);
     * see sim/simnet_chaos_faults.h (k) for why this stays off rom_fetch.c's
     * real multi-second I/O timeouts. */
    atomic_store(&c.last_tick_us, atomic_load(&c.last_tick_us) - 5000000);

    bool started = supervisor_start();
    chaos_sleep_ms(80);

    bool stall_fired = atomic_load(&c.stall_fires) >= 1u;
    bool stall_named = atomic_load(&c.stall_reason) ==
                       SUPERVISOR_STALL_TIME_DEADLINE;
    snprintf(out->state_before, sizeof(out->state_before),
             "stall_fires=%u reason=%s", atomic_load(&c.stall_fires),
             supervisor_stall_reason_name(atomic_load(&c.stall_reason)));

    /* Recovery: the connection is abandoned and retried elsewhere — a fresh
     * heartbeat proves the stall was BOUNDED, never a permanent hang. */
    atomic_store(&c.last_tick_us, 0);
    supervisor_progress(id, 1);
    uint32_t ticks_before = atomic_load(&c.ticks_run);
    atomic_store(&c.deadline_secs, 60);
    supervisor_sweep_once_for_testing();
    chaos_sleep_ms(40);
    uint32_t ticks_after = atomic_load(&c.ticks_run);

    supervisor_stop();

    snprintf(out->state_after, sizeof(out->state_after),
             "ticks %u->%u (resumed=%d)", ticks_before, ticks_after,
             ticks_after >= ticks_before);
    out->event_number = 1;
    snprintf(out->phase, sizeof(out->phase), "stalled");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_slow_loris_seeder(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = started && stall_fired;
    out->base.recovered = stall_named && ticks_after >= ticks_before;
    out->base.operator_paged = false;
    sfm_note(out, "slow-loris seeder: stall_fires=%u reason=%s ticks %u->%u",
             atomic_load(&c.stall_fires),
             supervisor_stall_reason_name(atomic_load(&c.stall_reason)),
             ticks_before, ticks_after);

    supervisor_reset_for_testing();
    return true;
}
#else
bool chaos_fault_slow_loris_seeder(uint64_t seed,
                                   struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    sfm_note(out, "unavailable: built without ZCL_TESTING");
    return false;
}
#endif /* ZCL_TESTING */

/* ══════════════════════════════════════════════════════════════════════
 * (l) a valid multi-block "bundle" followed by one invalid TAIL block
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_invalid_tail_block(uint64_t seed,
                                    struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "malformed tail block right after a valid bundle prefix");

    struct simnet sim;
    if (!simnet_init(&sim)) {
        sfm_note(out, "simnet_init failed");
        return false;
    }

    /* "The bundle": a few legitimately minted, connected blocks — the
     * trusted prefix a checkpoint/artifact install would have left. */
    const int prefix_blocks = 1 + (int)(seed % 3); /* deterministic, 1..3 */
    bool prefix_ok = true;
    for (int i = 0; i < prefix_blocks && prefix_ok; i++)
        prefix_ok = simnet_mint_coinbase(&sim, NULL);
    int bundle_height = simnet_tip_height(&sim);
    snprintf(out->state_before, sizeof(out->state_before),
             "bundle-installed prefix at height %d (%d valid block(s))",
             bundle_height, prefix_blocks);
    if (!prefix_ok) {
        sfm_note(out, "prefix minting failed (harness defect)");
        simnet_free(&sim);
        return false;
    }

    /* THE TAIL BLOCK: one malformed block right after the bundle's last
     * height, built + connected through the REAL Byzantine-fixture path
     * (sim/simnet_byzantine.h) — the same connect_block(...,just_check=false)
     * on a scratch coins view that path documents, reused here so the
     * malformed-block construction is never reinvented. */
    struct simnet_byzantine_block_case c;
    bool built = simnet_byzantine_build_bad_merkle(&sim, &c);
    if (!built) {
        sfm_note(out, "malformed tail-block build failed (harness defect)");
        simnet_free(&sim);
        return false;
    }

    struct coins_view parent_view;
    coins_view_cache_as_view(&parent_view, &sim.view);
    struct coins_view_cache scratch;
    coins_view_cache_init(&scratch, &parent_view);

    struct uint256 block_hash;
    block_header_get_hash(&c.block.header, &block_hash);
    struct block_index idx;
    block_index_init(&idx);
    idx.hashBlock = block_hash;
    idx.phashBlock = &idx.hashBlock;
    idx.pprev = &sim.tip;
    idx.nHeight = c.height;
    idx.nVersion = c.block.header.nVersion;
    idx.nTime = c.block.header.nTime;
    idx.nBits = c.block.header.nBits;
    idx.hashMerkleRoot = c.block.header.hashMerkleRoot;

    struct validation_state vs;
    validation_state_init(&vs);
    bool tail_accepted = connect_block(&c.block, &vs, &idx, &scratch,
                                       &sim.params, false);
    coins_view_cache_free(&scratch);

    bool tip_unmoved = simnet_tip_height(&sim) == bundle_height;
    bool tail_rejected = !tail_accepted && vs.reject_reason[0] != '\0';

    /* Recovery: an HONEST block at the same next height still connects
     * cleanly right after — the rejected tail never wedges the chain. */
    bool honest_after = simnet_mint_coinbase(&sim, NULL);
    bool honest_advanced = honest_after &&
        simnet_tip_height(&sim) == bundle_height + 1;
    int final_height = simnet_tip_height(&sim);

    simnet_byzantine_block_case_free(&c);
    simnet_free(&sim);

    snprintf(out->state_after, sizeof(out->state_after),
             "tail_accepted=%d reject=%.100s tip_unmoved=%d honest_advanced=%d",
             tail_accepted, vs.reject_reason, tip_unmoved, honest_advanced);
    out->event_number = (uint32_t)(prefix_blocks + 1); /* +1 for the tail */
    snprintf(out->phase, sizeof(out->phase), "connect_block");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_invalid_tail_block(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = true;
    out->base.hstar_before = bundle_height;
    out->base.hstar_after = final_height;
    out->base.recovered = tail_rejected && tip_unmoved && honest_advanced;
    out->base.operator_paged = false;
    sfm_note(out, "invalid tail block after valid bundle: prefix_h=%d "
             "tail_rejected=%d tip_unmoved=%d honest_advanced=%d",
             bundle_height, tail_rejected, tip_unmoved, honest_advanced);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (m) P2P body-download disruption/resume — BLOCK_HAVE_DATA no-refetch
 * ══════════════════════════════════════════════════════════════════════ */

/* Deterministic 32-byte hash for the (m) fixture. Tag byte 0xD0 keeps it
 * disjoint from chaos_synth_hash's 0xC5 (a)-(f) tag and synth_chain_bf's
 * 0xB4 (tests/harness/src/test_body_fetch_stage.c) so a shared debugging
 * session never confuses the three synthetic-chain families. */
static void bdr_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[31] = 0xD0;
}

bool chaos_fault_peer_disconnect_mid_body_download(
    int32_t chain_len, struct body_download_resume_result *out)
{
    struct body_download_resume_result empty = {0};
    if (!out) return false;
    *out = empty;
    out->base.hstar_before = -1;
    out->base.hstar_after = -1;

    if (chain_len < 8) {
        chaos_note(&out->base, "harness defect: chain_len must be >= 8 "
                   "(got %d)", chain_len);
        return false;
    }

    int32_t n = chain_len;  /* heights 0..n inclusive, n+1 entries */
    struct block_index *chain = zcl_calloc((size_t)n + 1, sizeof(*chain),
                                           "bdr_chain");
    struct uint256 *hashes = zcl_calloc((size_t)n + 1, sizeof(*hashes),
                                        "bdr_hashes");
    if (!chain || !hashes) {
        free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: OOM building %d-height "
                   "chain", n);
        return false;
    }
    for (int32_t h = 0; h <= n; h++) {
        block_index_init(&chain[h]);
        bdr_hash(hashes[h].data, h);
        chain[h].phashBlock = &hashes[h];
        chain[h].nHeight = h;
        chain[h].nVersion = 4;
        if (h > 0) chain[h].pprev = &chain[h - 1];
    }

    /* Fixed, deterministic proportions of the chain:
     *   [1, baseline]              — already durably persisted (HAVE_DATA)
     *                                 before this run even starts.
     *   (baseline, batch_end]      — the doomed peer's assigned window.
     *   (baseline, completed_kill] — the part of that window that actually
     *                                 completed (real forward progress)
     *                                 before the peer died mid-transfer.
     *   (completed_kill, batch_end]— interrupted in-flight at the kill.
     *   (batch_end, n]             — never even assigned yet. */
    int32_t baseline = n / 4;
    int32_t batch_end = n / 2;
    int32_t completed_kill = baseline + (batch_end - baseline) / 3;

    for (int32_t h = 1; h <= baseline; h++)
        chain[h].nStatus |= BLOCK_HAVE_DATA;

    struct download_manager dm;
    dl_init(&dm);
    if (!dm.slots) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: dl_init allocation failed");
        return false;
    }

    const uint32_t PEER_A = 1001, PEER_B = 2002;
    struct block_index *candidate = &chain[n];
    struct block_index *tip0 = &chain[baseline];

    /* ── Phase 1: the FIRST header-driven scan, at the durable baseline —
     * exactly what msg_headers.c runs the moment headers up to `candidate`
     * are admitted. ────────────────────────────────────────────────── */
    enum { BDR_MAX_COLLECT = 4096 };
    struct uint256 need_hashes[BDR_MAX_COLLECT];
    int32_t need_heights[BDR_MAX_COLLECT];
    struct sync_needed_blocks needed;
    syncsvc_collect_needed_blocks(&needed, candidate, tip0, baseline,
                                  need_hashes, need_heights, BDR_MAX_COLLECT);
    if (!needed.chains_from_tip || needed.count == 0) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: initial collect found "
                   "chains_from_tip=%d count=%zu (want true, >0)",
                   needed.chains_from_tip, needed.count);
        return false;
    }
    dl_queue_blocks(&dm, need_hashes, need_heights, needed.count);

    struct uint256 out_hashes[BDR_MAX_COLLECT];
    size_t want = (size_t)(batch_end - baseline);
    size_t assigned = dl_assign_to_peer(&dm, PEER_A, out_hashes, want);
    if (assigned != want) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: peer A got %zu of %zu "
                   "requested", assigned, want);
        return false;
    }

    /* dl_assign_to_peer hands back heights in ascending order (the queue is
     * height-sorted), so the first `completed_count` entries are exactly
     * heights (baseline, baseline+completed_count]. */
    int32_t completed_count = completed_kill - baseline;
    for (int32_t i = 0; i < completed_count; i++) {
        int32_t h = baseline + 1 + i;
        uint32_t got_peer = dl_mark_received(&dm, &out_hashes[i]);
        if (got_peer != PEER_A) {
            dl_free(&dm); free(chain); free(hashes);
            chaos_note(&out->base, "harness defect: mark_received(h=%d) "
                       "peer=%u want=%u", h, got_peer, PEER_A);
            return false;
        }
        chain[h].nStatus |= BLOCK_HAVE_DATA;
    }
    int32_t our_height = completed_kill;   /* genuine forward progress */

    /* ── Phase 2: DISRUPTION — the peer dies mid-transfer. Everything it
     * held in-flight but never delivered goes back to the pending queue;
     * a received/persisted height cannot be among them (dl_mark_received
     * already removed it from the in-flight table). ──────────────────── */
    size_t requeued = dl_peer_disconnected(&dm, PEER_A);

    /* ── Phase 3: reconnect — re-run the SAME production decision fresh
     * against the post-disruption block_index. The core assertion this
     * fault exists to prove: no height <= our_height (already durable)
     * ever reappears, from EITHER the fresh collect pass or the download
     * manager's own in-flight table. ─────────────────────────────────── */
    struct block_index *tip1 = &chain[our_height];
    struct sync_needed_blocks needed2;
    int64_t t_disconnect_us = platform_time_monotonic_us();
    syncsvc_collect_needed_blocks(&needed2, candidate, tip1, our_height,
                                  need_hashes, need_heights, BDR_MAX_COLLECT);

    uint64_t duplicate_persisted = 0;
    for (size_t i = 0; i < needed2.count; i++)
        if (need_heights[i] <= our_height)
            duplicate_persisted++;
    for (int32_t h = 1; h <= our_height; h++) {
        struct uint256 hh;
        bdr_hash(hh.data, h);
        if (dl_is_in_flight(&dm, &hh))
            duplicate_persisted++;
    }
    dl_queue_blocks(&dm, need_hashes, need_heights, needed2.count);

    /* Deliberately small first reconnect window (a fresh, unscored peer) so
     * the steady-state re-collect/re-assign loop below actually runs more
     * than once — a stronger regression proof than a single giant batch. */
    size_t reconnect_assign = dl_assign_to_peer(&dm, PEER_B, out_hashes, 8);
    int64_t t_assigned_us = platform_time_monotonic_us();
    out->reconnect_decision_us = t_assigned_us - t_disconnect_us;

    if (reconnect_assign == 0) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: peer B got 0 blocks on "
                   "reconnect (requeued=%zu queued2=%zu)",
                   requeued, needed2.count);
        return false;
    }

    /* ── Phase 4: drive the resumed peer to tip, re-collecting/re-
     * assigning as its window empties — the real steady-state tick
     * (gap_fill_service / block_sync_service). A small per-block sleep
     * models a real LAN body round-trip so resume_latency_us reports a
     * representative figure instead of a meaningless sub-microsecond
     * in-process one. ────────────────────────────────────────────────── */
    int64_t t_first_progress_us = 0;
    bool measured_first = false;
    int32_t cur_height = our_height;
    size_t batch_off = 0, batch_len = reconnect_assign;
    int guard = 0;
    while (cur_height < n && guard++ < 4 * (n + 1)) {
        if (batch_off >= batch_len) {
            struct sync_needed_blocks more;
            struct block_index *tipN = &chain[cur_height];
            syncsvc_collect_needed_blocks(&more, candidate, tipN, cur_height,
                                          need_hashes, need_heights,
                                          BDR_MAX_COLLECT);
            for (size_t i = 0; i < more.count; i++)
                if (need_heights[i] <= our_height)
                    duplicate_persisted++;
            dl_queue_blocks(&dm, need_hashes, need_heights, more.count);
            batch_len = dl_assign_to_peer(&dm, PEER_B, out_hashes,
                                          BDR_MAX_COLLECT);
            batch_off = 0;
            if (batch_len == 0) break;   /* nothing assignable; real stall */
        }

        struct uint256 *hh = &out_hashes[batch_off++];
        platform_sleep_ms(2);   /* simulated LAN body-transfer latency */
        uint32_t got_peer = dl_mark_received(&dm, hh);
        if (got_peer != PEER_B) {
            dl_free(&dm); free(chain); free(hashes);
            chaos_note(&out->base, "harness defect: post-resume "
                       "mark_received peer=%u want=%u at h=%d",
                       got_peer, PEER_B, cur_height + 1);
            return false;
        }
        if (!measured_first) {
            t_first_progress_us = platform_time_monotonic_us();
            measured_first = true;
        }
        cur_height++;
        chain[cur_height].nStatus |= BLOCK_HAVE_DATA;
        dl_add_bytes_received(&dm, 512);
    }

    uint64_t requested_total = 0;
    dl_get_stats(&dm, &requested_total, NULL, NULL, NULL, NULL);

    out->chain_len = n;
    out->persisted_at_disruption = our_height;
    out->final_height = cur_height;
    out->requested_total = requested_total;
    out->duplicate_persisted_requests = duplicate_persisted;
    out->resume_latency_us = measured_first
        ? t_first_progress_us - t_assigned_us : -1;

    out->base.ok = true;
    out->base.recovered = (cur_height == n) && (duplicate_persisted == 0);
    /* This path never touches the blocker/condition/event escalation
     * surface — a stalled body fetch is body_fetch_missing_have_data's
     * typed blocker, not an operator page. */
    out->base.operator_paged = false;
    chaos_note(&out->base,
               "chain=%d baseline=%d disrupted_at=%d final=%d requeued=%zu "
               "requested_total=%llu duplicates=%llu "
               "reconnect_decision_us=%lld resume_latency_us=%lld",
               n, baseline, our_height, cur_height, requeued,
               (unsigned long long)requested_total,
               (unsigned long long)duplicate_persisted,
               (long long)out->reconnect_decision_us,
               (long long)out->resume_latency_us);

    dl_free(&dm);
    free(chain);
    free(hashes);
    return true;
}
