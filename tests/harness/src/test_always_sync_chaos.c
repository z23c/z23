/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The always-sync G-TIP chaos regression gate.
 *
 * MISSION: the node must ALWAYS fold to the network tip and never silently
 * stall; a stall is always a NAMED, SELF-HEALED blocker at a known height,
 * never an operator page for a recoverable cause. This table-driven test
 * drives the six reusable fault injectors in sim/simnet_chaos_faults.h and
 * asserts the mission property on each: the fixture recovers, and no
 * EV_OPERATOR_NEEDED (or equivalent named escalation) fires for what should
 * have been a recoverable cause.
 *
 * The G-TIP case (fault a, "full block index + empty active-chain window")
 * gets TWO rows instead of one:
 *
 *   - a BOUNDED gap, inside BLOCK_INDEX_LOADER_SEED_MAX_GAP — this repair is
 *     already landed production code (engine/services/src/block_index_loader_
 *     rebuild.c); this row is an unconditional regression gate.
 *   - a LIVE-WEDGE-SCALE gap, beyond BLOCK_INDEX_LOADER_SEED_MAX_GAP — this
 *     is the documented, still-open Pillar-0 limit (docs/HANDOFF.md). Until
 *     recovery lands, the row requires an explicit contained refusal with no
 *     operator page; it flips to the recovery assertion when the injector
 *     reports `ok=true`.
 *
 * See engine/modules/sim/include/sim/simnet_chaos_faults.h for what each fault
 * reproduces and engine/services/include/services/block_index_loader.h for
 * BLOCK_INDEX_LOADER_SEED_MAX_GAP.
 *
 * Fault (m) (lane G4, wf/disruption-resume) extends the corpus with the
 * ordinary P2P block-body download/resume path: a peer disconnects mid-
 * transfer and reconnects, and the on-disk BLOCK_HAVE_DATA contract must
 * hold — never re-request a block already durably persisted, always reach
 * tip. Distinct from the (g)-(l) matrix's rom_journal/artifact-download
 * subsystem below.
 */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "sim/simnet_chaos_faults.h"

#include <stdio.h>
#include <string.h>

#define ASC_CHECK(name, expr) do {                                          \
    printf("always_sync_chaos: %s... ", (name));                           \
    if (expr) { printf("OK\n"); }                                          \
    else { printf("FAIL\n"); failures++; }                                 \
} while (0)

/* Common assertion every fault must satisfy: the harness fixture built
 * cleanly (`ok`) and no operator page fired for what is, by construction,
 * a recoverable synthetic fault. `recovered` is asserted separately per row
 * below since fault (a)'s live-wedge-scale row deliberately SKIPs it. */
static bool asc_never_pages(const struct chaos_fault_result *r)
{
    return r->ok && !r->operator_paged;
}

/* Same assertion, for the (g)-(l) sync/ROM-artifact fault matrix's richer
 * `sync_fault_capsule` (base chaos_fault_result + replay/seed fields). */
static bool asc_never_pages_capsule(const struct sync_fault_capsule *c)
{
    return c->base.ok && !c->base.operator_paged;
}

int test_always_sync_chaos(void)
{
    printf("\n=== always_sync_chaos (G-TIP fault-injection harness) ===\n");
    int failures = 0;
    struct chaos_fault_result r;

    /* ── (a-1) G-TIP: bounded gap — the landed regression floor ────────── */
    {
        const int gap = 200; /* well inside BLOCK_INDEX_LOADER_SEED_MAX_GAP */
        bool harness_ok = chaos_fault_empty_active_chain_window(gap, &r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("gtip bounded: harness fixture built", harness_ok);
        ASC_CHECK("gtip bounded: never pages operator", asc_never_pages(&r));
        ASC_CHECK("gtip bounded: active_chain_tip INSTALLED + H* CLIMBS",
                  r.ok && r.recovered && r.hstar_after == gap);
    }

    /* ── (a-2) G-TIP: live-wedge-scale gap — REFUSE-or-RECOVER ──────────
     * A gap comfortably beyond MAX_GAP, at the SAME scale relationship the
     * documented live limit has to the cap (a multiple of it), kept cheap
     * for a unit test. Until recovery lands, refusal must remain contained
     * and must not page the operator. The moment the genesis-root branch
     * resolves an over-cap gap, `r.ok` flips true and the recovery assertion
     * becomes the hard gate with no test edit. */
    {
        const int gap = BLOCK_INDEX_LOADER_SEED_MAX_GAP + 10000;
        bool harness_ok = chaos_fault_empty_active_chain_window(gap, &r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("gtip live-wedge-scale: harness fixture built", harness_ok);
        if (!r.ok) {
            ASC_CHECK("gtip live-wedge-scale: contained refusal, no operator "
                      "page", !r.recovered && !r.operator_paged);
        } else {
            ASC_CHECK("gtip live-wedge-scale: never pages operator",
                      !r.operator_paged);
            ASC_CHECK("gtip live-wedge-scale: active_chain_tip INSTALLED + "
                      "H* CLIMBS (Pillar-0 fix landed — now a hard gate)",
                      r.recovered && r.hstar_after == gap);
        }
    }

    /* ── (b) kill/restart mid-fold ───────────────────────────────────── */
    {
        bool harness_ok = chaos_fault_kill_restart_mid_fold(&r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("kill/restart: harness fixture built", harness_ok);
        ASC_CHECK("kill/restart: never pages operator", asc_never_pages(&r));
        ASC_CHECK("kill/restart: H* resumes identically, nothing lost",
                  r.recovered);
    }

    /* ── (c) corrupt a sealed chain_segment ─────────────────────────── */
    {
        bool harness_ok = chaos_fault_corrupt_sealed_segment(&r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("segment corruption: harness fixture built", harness_ok);
        ASC_CHECK("segment corruption: never pages operator",
                  asc_never_pages(&r));
        ASC_CHECK("segment corruption: detect+repair returns to SERVING",
                  r.recovered);
    }

    /* ── (d) freeze the reducer drive ───────────────────────────────── */
    {
        bool harness_ok = chaos_fault_freeze_reducer_drive(&r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("reducer-drive freeze: harness fixture built", harness_ok);
        ASC_CHECK("reducer-drive freeze: never pages operator",
                  asc_never_pages(&r));
        ASC_CHECK("reducer-drive freeze: named stall, then resumes ticking",
                  r.recovered);
    }

    /* ── (e) stall a single stage ────────────────────────────────────── */
    {
        bool harness_ok = chaos_fault_stall_single_stage(&r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("single-stage stall: harness fixture built", harness_ok);
        ASC_CHECK("single-stage stall: never pages operator (recoverable "
                  "cause, retry budget held)", asc_never_pages(&r));
        ASC_CHECK("single-stage stall: self-heals, blocker clears",
                  r.recovered);
    }

    /* ── (f) kill/restart mid-RECOVERY (inside an open rewind window) ──
     * Unlike (b) — a kill BEFORE any repair action started — this kills
     * AFTER stage_rederive_range() has committed a rewind (cursors
     * lowered, stale rows deleted, coins inverse-rewound to the hole) but
     * BEFORE the drive re-folds the range forward. */
    {
        bool harness_ok = chaos_fault_kill_restart_mid_recovery(&r);
        printf("  note: %s\n", r.note);
        ASC_CHECK("kill mid-recovery: harness fixture built", harness_ok);
        ASC_CHECK("kill mid-recovery: never pages operator",
                  asc_never_pages(&r));
        ASC_CHECK("kill mid-recovery: H* + coins frontier survive the kill "
                  "identically, next pass converges", r.recovered);
    }

    /* ── (g)-(l): the sync/ROM-artifact fault matrix (lane G3) ──────────
     * Six more named injectors over core/modules/net/rom_fetch.c, rom_journal.c and
     * the pure core/modules/sync/src/sync_reduce.c kernel — see
     * sim/simnet_chaos_faults.h for each fault's exact contract. Every
     * fixed seed below is chosen once so a failure replays deterministically
     * via the printed replay_command. */
    struct sync_fault_capsule sc;

    /* ── (g) two peers, same chunk index, different bytes ────────────── */
    {
        bool harness_ok = chaos_fault_conflicting_chunk_peers(0xC11C0DE1ull,
                                                               &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("conflicting chunk peers: harness fixture built",
                  harness_ok);
        ASC_CHECK("conflicting chunk peers: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("conflicting chunk peers: bad peer named+rejected, good "
                  "chunk kept", sc.base.recovered);
    }

    /* ── (h) ENOSPC (write failure) during a journal bitmap commit ───── */
    {
        bool harness_ok = chaos_fault_journal_commit_enospc(0xE7057Aull, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("journal commit ENOSPC: harness fixture built", harness_ok);
        ASC_CHECK("journal commit ENOSPC: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("journal commit ENOSPC: failed mark rolls back cleanly, "
                  "retry converges", sc.base.recovered);
    }

    /* ── (i) kill at the two documented resume boundaries ────────────── */
    {
        bool harness_ok = chaos_fault_kill_resume_boundary(0xB0117A1ull,
                                                            false, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("kill before bitmap commit: harness fixture built",
                  harness_ok);
        ASC_CHECK("kill before bitmap commit: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("kill before bitmap commit: <=1 chunk redone, resume "
                  "converges", sc.base.recovered);
    }
    {
        bool harness_ok = chaos_fault_kill_resume_boundary(0xB0117A2ull,
                                                            true, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("kill after bitmap commit: harness fixture built",
                  harness_ok);
        ASC_CHECK("kill after bitmap commit: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("kill after bitmap commit: 0 chunks redone, rename "
                  "converges", sc.base.recovered);
    }

    /* ── (j) header reorg during an artifact download — pure kernel ──── */
    {
        bool harness_ok = chaos_fault_reorg_during_artifact_download(
            0x8EAD0000ull, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("reorg during download: harness fixture built", harness_ok);
        ASC_CHECK("reorg during download: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("reorg during download: FAILED+named, never installs",
                  sc.base.recovered);
    }

    /* ── (k) slow-loris seeder: bounded stall, never a silent hang ───── */
    {
        bool harness_ok = chaos_fault_slow_loris_seeder(0x510C0Full, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("slow-loris seeder: harness fixture built", harness_ok);
        ASC_CHECK("slow-loris seeder: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("slow-loris seeder: named stall, then resumes ticking",
                  sc.base.recovered);
    }

    /* ── (l) valid bundle prefix + one invalid TAIL block ─────────────── */
    {
        bool harness_ok = chaos_fault_invalid_tail_block(0x7A11B10Cull, &sc);
        printf("  note: %s\n", sc.base.note);
        ASC_CHECK("invalid tail block: harness fixture built", harness_ok);
        ASC_CHECK("invalid tail block: never pages operator",
                  asc_never_pages_capsule(&sc));
        ASC_CHECK("invalid tail block: rejected independently, chain never "
                  "wedged", sc.base.recovered);
    }

    /* ── (m) peer disconnect mid body-download, then resume — lane G4 ──
     * (wf/disruption-resume). Distinct subsystem from (i): this is the
     * ordinary P2P block-BODY download path (core/modules/net/src/download.c +
     * the real syncsvc_collect_needed_blocks() planner msg_headers.c
     * calls on every accepted header batch), not the rom_journal
     * snapshot/artifact chunk resume. Proves the on-disk BLOCK_HAVE_DATA
     * contract: a block already durably persisted before the peer died
     * is NEVER re-requested after reconnect, and the node still reaches
     * tip. See sim/simnet_chaos_faults.h for the full fixture narrative
     * and struct body_download_resume_result for the measured fields. */
    {
        struct body_download_resume_result r2;
        bool harness_ok = chaos_fault_peer_disconnect_mid_body_download(
            40, &r2);
        printf("  note: %s\n", r2.base.note);
        ASC_CHECK("body-download resume: harness fixture built", harness_ok);
        ASC_CHECK("body-download resume: never pages operator",
                  asc_never_pages(&r2.base));
        ASC_CHECK("body-download resume: zero re-requests of already-"
                  "persisted (HAVE_DATA) blocks",
                  r2.base.ok && r2.duplicate_persisted_requests == 0);
        ASC_CHECK("body-download resume: reaches tip after reconnect",
                  r2.base.ok && r2.final_height == r2.chain_len);
        ASC_CHECK("body-download resume: recovered verdict",
                  r2.base.recovered);
        printf("  measured: reconnect_decision_us=%lld "
               "resume_latency_us=%lld (persisted_at_disruption=%d/%d)\n",
               (long long)r2.reconnect_decision_us,
               (long long)r2.resume_latency_us,
               r2.persisted_at_disruption, r2.chain_len);
    }

    if (failures == 0)
        printf("=== always_sync_chaos: ALL PASS ===\n\n");
    else
        printf("always_sync_chaos: failures=%d\n", failures);
    return failures;
}
