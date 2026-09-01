/* 10_wire_adversaries.c — deterministic in-memory P2P wire under attack.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * z23's `simnet_wire` harness (engine/modules/sim/src/simnet_wire.c) drives the
 * REAL message processor (core/modules/net/src/msgprocessor.c) and the REAL p2p_node
 * framing/receive-reassembly code against synthetic byte sources — no
 * sockets, no threads, no wall clock. A "tick" is one scheduling quantum:
 * each tick, every connected peer may emit bytes, those bytes are pumped
 * into the node-under-test (the NUT), the NUT's queued replies are drained
 * back out, and a permanent-blocker monitor runs. Because everything is
 * driven by a fixed seed and a tick counter (never gettimeofday), the same
 * seed always reproduces the same byte-for-byte run — this is what makes
 * "flood 10,000 peers for an hour" a sub-second, replayable unit test
 * instead of a flaky integration test.
 *
 * This example puts TWO peers on the wire against one NUT:
 *   - peer 0: HONEST — completes the version/verack handshake and will
 *     round-trip ping/pong on request. Per simnet_wire.c, egress from the
 *     NUT is pinned to peer slot 0, so peer 0 is the only link whose
 *     closure is externally observable (a ping/pong test).
 *   - peer 1: FLOOD — an adversary that pushes as many bytes as the ring
 *     buffer will hold, forcing the NUT's receive-message backpressure path
 *     to reject rather than grow unbounded.
 *
 * Mental model for the middle act: "the node's only real peer connection
 * drops while an attacker's connection stays up." We close peer 0's link
 * (simnet_wire_partition_peer(..., closed=true)) — modeling a network
 * partition, not a clean disconnect — while peer 1 keeps flooding. The
 * no-silent-halt invariant this file proves is that a real chain-processing
 * component (the blocker registry) shows no unexpected PERMANENT blocker
 * during the outage — the node is quiescent, not stuck. We then heal the
 * link and prove liveness returns with a fresh ping/pong round trip.
 *
 * NOTE ON TEST-ONLY DEPENDENCIES: `blocker_reset_for_testing()` (declared
 * unconditionally in util/blocker.h, no ZCL_TESTING guard) clears the
 * process-global blocker registry. It is not gated behind ZCL_TESTING, but
 * it exists to give a fresh baseline before creating a wire — the harness
 * tests always call it for the same reason. Safe to call once at start.
 *
 * Build: this file is intended to compile with -DZCL_TESTING (see the repo
 * Makefile's LIB_INCLUDES) because it links against the same engine/modules/sim +
 * core/modules/net object files the test binary uses; no individual symbol used
 * here is itself #ifdef ZCL_TESTING-gated.
 */

#include "net/net.h"
#include "sim/simnet_wire.h"
#include "util/blocker.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Fixed seed: every run of this program produces the identical tick
 * sequence, byte content, and final fingerprint. Change the seed and you
 * get a different (still fully deterministic) run. */
#define WIRE_SEED   0x10ADEE5A0000A11EULL
#define PING_BEFORE 0x0000000042454630ULL /* "BEF0" */
#define PING_AFTER  0x0000000041465452ULL /* "AFTR" */

static void print_stats(const char *label, const struct simnet_wire_stats *st)
{
    printf("    [%s] peers_open=%zu handshake=%d pong=%d "
           "no_perm_blocker=%d monitor_failed=%d fp=0x%016" PRIx64 "\n",
           label, st->peers_open, st->handshake_complete ? 1 : 0,
           st->pong_received ? 1 : 0, st->no_unexpected_permanent_blocker ? 1 : 0,
           st->monitor_failed ? 1 : 0, st->fingerprint);
}

int main(void)
{
    printf("=== 10_wire_adversaries: honest peer + flooding adversary, "
           "partition with no silent halt, then heal ===\n\n");

    /* Select a chain network before any wire/net code runs — simnet_wire
     * reads its parameters (e.g. block-relay message shaping) through
     * chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    /* Clean process-global blocker state before the first wire run — see
     * the file header note on why this call is safe outside the test
     * binary. */
    blocker_reset_for_testing();

    printf("[1/6] building a 2-peer scenario: peer 0 honest, peer 1 FLOOD "
           "(seed=0x%016" PRIx64 ")...\n", (uint64_t)WIRE_SEED);
    struct wire_scenario_peer peers[] = {
        { SIMNET_WIRE_PEER_FLOOD, 1 },
    };
    struct wire_scenario scenario = {
        .master_seed = WIRE_SEED,
        .peers = peers,
        .peer_kind_count = sizeof(peers) / sizeof(peers[0]),
        .honest_peer_count = 1, /* honest peers are assigned slots first,
                                  * so peer 0 = honest, peer 1 = FLOOD */
    };
    struct simnet_wire *wire = simnet_wire_create_scenario(&scenario);
    if (!wire) {
        fprintf(stderr, "FAIL: simnet_wire_create_scenario returned NULL\n");
        return 1;
    }

    printf("[2/6] baseline: draining handshake + attacker traffic, then "
           "round-tripping a ping on the honest link...\n");
    bool ok = simnet_wire_run(wire, 512, 0) &&
              simnet_wire_peer_handshake_complete(wire, 0) &&
              simnet_wire_peer_send_ping(wire, 0, PING_BEFORE) &&
              simnet_wire_run(wire, 512, 128) &&
              simnet_wire_peer_pong_received(wire, 0, PING_BEFORE);
    if (!ok) {
        fprintf(stderr, "FAIL: baseline handshake/ping/pong did not "
                        "complete while the FLOOD peer was live\n");
        simnet_wire_free(wire);
        return 1;
    }
    printf("    OK: honest peer handshook and got its pong back despite "
           "concurrent flood traffic.\n");

    printf("[3/6] partitioning peer 0's link (closed=true) — the node's "
           "only real connection just went dark...\n");
    ok = simnet_wire_partition_peer(wire, 0, true);
    if (!ok) {
        fprintf(stderr, "FAIL: simnet_wire_partition_peer(close) failed\n");
        simnet_wire_free(wire);
        return 1;
    }

    printf("[4/6] running 256 ticks with the link down (attacker still "
           "flooding on slot 1)...\n");
    ok = simnet_wire_run(wire, 256, 0);
    if (!ok) {
        fprintf(stderr, "FAIL: simnet_wire_run failed during the outage\n");
        simnet_wire_free(wire);
        return 1;
    }

    struct simnet_wire_stats mid;
    memset(&mid, 0, sizeof(mid));
    if (!simnet_wire_get_stats(wire, &mid)) {
        fprintf(stderr, "FAIL: simnet_wire_get_stats failed mid-outage\n");
        simnet_wire_free(wire);
        return 1;
    }
    print_stats("mid-outage", &mid);
    /* The no-silent-halt invariant: a real partition must not trip a
     * PERMANENT blocker (that would mean the node quietly wedged instead
     * of naming the outage). Only the attacker's link remains open. */
    if (!mid.no_unexpected_permanent_blocker || mid.monitor_failed ||
        mid.peers_open != 1) {
        fprintf(stderr, "FAIL: outage state wrong (expected "
                        "no_unexpected_permanent_blocker=1, "
                        "monitor_failed=0, peers_open=1; got %d/%d/%zu)\n",
                mid.no_unexpected_permanent_blocker ? 1 : 0,
                mid.monitor_failed ? 1 : 0, mid.peers_open);
        simnet_wire_free(wire);
        return 1;
    }
    printf("    OK: no permanent blocker fired; the outage is visible as "
           "peers_open==1, not a silent halt.\n");

    printf("[5/6] healing the link (closed=false)...\n");
    ok = simnet_wire_partition_peer(wire, 0, false);
    if (!ok) {
        fprintf(stderr, "FAIL: simnet_wire_partition_peer(reopen) failed\n");
        simnet_wire_free(wire);
        return 1;
    }

    printf("[6/6] proving recovery with a fresh ping/pong round trip...\n");
    ok = simnet_wire_run(wire, 256, 0) &&
         simnet_wire_peer_send_ping(wire, 0, PING_AFTER) &&
         simnet_wire_run(wire, 512, 128) &&
         simnet_wire_peer_pong_received(wire, 0, PING_AFTER);
    if (!ok) {
        fprintf(stderr, "FAIL: post-heal ping/pong did not complete\n");
        simnet_wire_free(wire);
        return 1;
    }

    struct simnet_wire_stats final_st;
    memset(&final_st, 0, sizeof(final_st));
    if (!simnet_wire_get_stats(wire, &final_st)) {
        fprintf(stderr, "FAIL: simnet_wire_get_stats failed at the end\n");
        simnet_wire_free(wire);
        return 1;
    }
    print_stats("post-heal", &final_st);

    ok = final_st.no_unexpected_permanent_blocker &&
         !final_st.monitor_failed &&
         final_st.peers_open == 2 && /* both links open again */
         final_st.pong_received &&
         final_st.max_recv_msg_count <= MAX_RECV_MESSAGES;
    if (!ok) {
        fprintf(stderr, "FAIL: post-heal invariants did not hold\n");
        simnet_wire_free(wire);
        return 1;
    }

    printf("=== SUCCESS: partition -> no silent halt -> heal -> recovery, "
           "all deterministic (fingerprint=0x%016" PRIx64 ", ticks=%" PRIu64
           ", backpressure_rejects=%" PRIu64 ") ===\n",
           final_st.fingerprint, final_st.ticks,
           final_st.backpressure_reject_events);

    /* A same-seed re-run of this whole program (nothing here reads the
     * wall clock or /dev/urandom) reproduces this exact fingerprint —
     * that determinism is what lets a wire-adversary bug be pinned to one
     * 64-bit seed instead of a flaky retry loop. */

    simnet_wire_free(wire);
    return 0;
}

/* Production counterpart:
 * -----------------------
 * The real (non-simulated) equivalent of this file's two acts:
 *
 *   - Real handshake + framing + backpressure: core/modules/net/src/msgprocessor.c
 *     (dispatch table) and core/modules/net/src/net.c (p2p_node receive/send,
 *     MAX_RECV_MESSAGES enforcement) — this IS the code simnet_wire drives
 *     directly, over real sockets instead of a synthetic byte source.
 *
 *   - Real per-peer disconnect/reconnect + no-silent-halt liveness:
 *     engine/services/src/sync_monitor.c and platform/modules/util/src/supervisor.c (the
 *     supervisor liveness tree — see CLAUDE.md "Adding state
 *     introspection" and `z23 dumpstate supervisor`) are what detect
 *     and surface a stalled or partitioned peer set on a live node, instead
 *     of this file's direct simnet_wire_get_stats() polling.
 *
 *   - Typed blocker registry used for the no-silent-halt check:
 *     platform/modules/util/include/util/blocker.h / platform/modules/util/src/blocker.c — the same
 *     PERMANENT/TRANSIENT blocker classes a live node reports via
 *     `z23 dumpstate blocker`.
 */
