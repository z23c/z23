/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_wire IBD / header-sync adversarial scenarios.
 *
 * These build on the simnet_wire multi-link substrate (a single real
 * p2p_node — the node-under-test, NUT — fed by N independent byte-ring
 * links) to exercise the *receive-side* header-sync path, process_headers()
 * in core/modules/net/src/msg_headers.c, which msg_process_messages() dispatches for
 * every inbound `headers` frame. Each scenario rides on a REAL net predicate
 * and asserts the two node-liveness invariants the whole wire harness is
 * built around: no silent halt (no unexpected PERMANENT blocker) and
 * consensus unchanged (the NUT's active tip + UTXO commitment never move off
 * the baseline while an adversary streams garbage).
 *
 * SUBSTRATE SCOPE — read before extending. The current simnet_wire substrate
 * has hard limits that bound which "IBD" behaviours are expressible here,
 * and these tests are written to ride only on what is genuinely driven,
 * never to fake node behaviour:
 *   1. There is ONE p2p_node (the NUT). Every wire_peer slot is a byte-ring
 *      ingress source into that single node; there is no independent
 *      p2p_node per peer. Peer-scoring/misbehaviour therefore accumulates on
 *      the ONE node, so "ban the attacker while honest peers are untouched"
 *      is NOT expressible — banning is per-node and there is one node.
 *   2. Egress is pinned to peer slot 0 (simnet_wire_drain_nut_send), so only
 *      slot 0 is a bidirectionally-handshaken peer; slots 1..N are
 *      ingress-only adversarial byte sources. process_headers() has
 *      requires_handshake=true and gates on node->version, which the slot-0
 *      handshake sets — so a headers frame injected on ANY slot is dispatched
 *      once slot 0 has completed its handshake.
 *   3. The harness drives msg_process_messages() only, NOT msg_send_messages()
 *      — so the NUT never issues getheaders and the outbound HEADER-STALL
 *      eviction (msgprocessor.c) never runs. Active-tip advance also needs
 *      block-connect + a real coins view the NUT does not have here. So
 *      "converge on the most-work chain" and "evict a stalling/withholding
 *      peer" are NOT expressible on this substrate; they need substrate work
 *      (per-peer p2p_nodes + a driven send loop + a connectable coins view)
 *      and are reported as findings by this lane rather than faked.
 *
 * What IS driven and asserted below: the inbound process_headers() DoS /
 * robustness guards — the count>2000 flood guard and the
 * block_header_deserialize() malformed-header reject — plus the honest slot-0
 * link continuing to round-trip a ping/pong through the garbage (the node is
 * not wedged by an ingress attacker). All deterministic under the seed tape;
 * a same-seed second run must reproduce the FNV fingerprint exactly.
 */

#include "test/test_core.h"

#include "core/serialize.h"
#include "net/net.h"
#include "sim/simnet_wire.h"
#include "util/blocker.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SWI_CHECK(name, expr) do {         \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool swi_monitors_ok(const struct simnet_wire_stats *st)
{
    return st &&
           st->recv_queue_bounded &&
           st->no_unexpected_permanent_blocker &&
           st->memory_plateau_ok &&
           st->consensus_unchanged &&
           !st->monitor_failed;
}

/* Drive peer 0 through a full version/verack handshake so node->version is
 * set (the gate process_headers() checks) and the NUT is ready to dispatch a
 * subsequent `headers` frame from any slot. Returns true iff the handshake
 * completed with the node still connected. */
static bool swi_handshake_peer0(struct simnet_wire *wire)
{
    return simnet_wire_start_honest_peer(wire, 0) &&
           simnet_wire_run(wire, 1024, 64) &&
           simnet_wire_peer_handshake_complete(wire, 0);
}

/* Build a `headers` payload declaring `count` headers followed by
 * `body_len` raw bytes of (deliberately truncated / garbage) header data.
 * count alone (body_len==0) trips the count>2000 flood guard; count==1 with a
 * too-short body trips the per-header block_header_deserialize() reject. */
static bool swi_build_headers_payload(uint64_t count, const uint8_t *body,
                                      size_t body_len, struct byte_stream *out)
{
    stream_init(out, 16 + body_len);
    if (!stream_write_compact_size(out, count))
        return false;
    if (body_len > 0 && !stream_write_bytes(out, body, body_len))
        return false;
    return true;
}

/* SCENARIO 1 — headers-count flood guard (real: msg_count_exceeds in
 * process_headers(), the "headers count > 2000" DoS guard). An ingress peer
 * completes the slot-0 handshake, then announces a `headers` message that
 * claims 2001 headers. process_headers() rejects the count before parsing a
 * single header: EV_PEER_MISBEHAVE + PEER_OFFENCE_FLOOD + node->disconnect.
 * We assert the guard fires (misbehave observed, node disconnected) WITHOUT a
 * silent halt and WITHOUT touching consensus — the NUT's tip/coins never move
 * off baseline because no header was ever admitted. */
static bool swi_run_count_flood(uint64_t seed, uint64_t *out_fp,
                                struct simnet_wire_stats *out_stats)
{
    blocker_reset_for_testing();
    struct simnet_wire *wire = simnet_wire_create(1, seed);
    if (!wire)
        return false;

    bool ok = swi_handshake_peer0(wire);

    struct byte_stream payload;
    if (ok) {
        ok = swi_build_headers_payload(2001, NULL, 0, &payload);
        if (ok) {
            ok = simnet_wire_inject_message(wire, 0, "headers", payload.data,
                                            payload.size) &&
                 simnet_wire_run(wire, 1024, 0);
            stream_free(&payload);
        }
    }

    struct simnet_wire_stats st;
    memset(&st, 0, sizeof(st));
    if (simnet_wire_get_stats(wire, &st)) {
        if (out_stats)
            *out_stats = st;
        if (out_fp)
            *out_fp = st.fingerprint;
    }
    ok = ok &&
         swi_monitors_ok(&st) &&
         st.peer_misbehave_events > 0 &&   /* count>2000 guard fired */
         st.nut_disconnected &&            /* guard sets node->disconnect */
         st.consensus_unchanged &&         /* no header admitted */
         st.max_recv_msg_count <= MAX_RECV_MESSAGES;

    simnet_wire_free(wire);
    return ok;
}

/* SCENARIO 2 — malformed header body, node survives (real:
 * block_header_deserialize() failure inside process_headers(), which emits
 * EV_HEADERS_REJECTED + PEER_OFFENCE_FLOOD but does NOT disconnect — a single
 * FLOOD offence is 20 points, well under the 100-point ban threshold). The
 * peer announces 1 header then supplies a too-short body so the deserialize
 * fails on the first header. Crucially the node is NOT wedged or dropped: we
 * prove it still serves the SAME peer by round-tripping a fresh ping/pong
 * AFTER the malformed headers. Consensus stays at baseline throughout. */
static bool swi_run_malformed_body(uint64_t seed, uint64_t *out_fp,
                                   struct simnet_wire_stats *out_stats)
{
    blocker_reset_for_testing();
    struct simnet_wire *wire = simnet_wire_create(1, seed);
    if (!wire)
        return false;

    bool ok = swi_handshake_peer0(wire);

    /* 8 bytes is far short of a full block header (fixed fields + Equihash
     * solution), so block_header_deserialize() fails on header[0]. */
    static const uint8_t truncated[8] = {
        0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
    };
    struct byte_stream payload;
    if (ok) {
        ok = swi_build_headers_payload(1, truncated, sizeof(truncated),
                                       &payload);
        if (ok) {
            ok = simnet_wire_inject_message(wire, 0, "headers", payload.data,
                                            payload.size) &&
                 simnet_wire_run(wire, 1024, 0);
            stream_free(&payload);
        }
    }

    /* The node must still be alive on the honest link: prove it answers a
     * fresh ping. A wedged/disconnected node would fail this. */
    const uint64_t recovery_nonce = 0x49424452454356ULL;
    ok = ok &&
         !simnet_wire_node(wire)->disconnect &&
         simnet_wire_peer_send_ping(wire, 0, recovery_nonce) &&
         simnet_wire_run(wire, 1024, 128) &&
         simnet_wire_peer_pong_received(wire, 0, recovery_nonce);

    struct simnet_wire_stats st;
    memset(&st, 0, sizeof(st));
    if (simnet_wire_get_stats(wire, &st)) {
        if (out_stats)
            *out_stats = st;
        if (out_fp)
            *out_fp = st.fingerprint;
    }
    ok = ok &&
         swi_monitors_ok(&st) &&
         st.peer_misbehave_events > 0 &&   /* malformed-header FLOOD offence */
         !st.nut_disconnected &&           /* 20 pts < 100-pt ban threshold */
         st.consensus_unchanged &&
         st.pong_received &&               /* honest link still serves */
         st.max_recv_msg_count <= MAX_RECV_MESSAGES;

    simnet_wire_free(wire);
    return ok;
}

/* SCENARIO 3 (garbage header STREAM from a second, independently-handshaken
 * attacker peer) was removed: the merged Step-D2 substrate gives each peer its
 * OWN p2p_node, so an attacker on slot 1 must complete its own version/verack
 * handshake before its `headers` frames are dispatched — injecting pre-handshake
 * hits the "received headers before version" guard and is dropped without FLOOD
 * scoring. The corrected multi-peer form (handshake slot 1, then stream garbage,
 * then assert per-peer scoring + honest slot-0 untouched) is future work. */

int test_simnet_wire_ibd(void)
{
    printf("\n=== simnet_wire IBD / header-sync adversarial ===\n");
    int failures = 0;

    {
        uint64_t fp_a = 0;
        uint64_t fp_b = 0;
        struct simnet_wire_stats st;
        memset(&st, 0, sizeof(st));
        bool a = swi_run_count_flood(0x571A0000000f1b01ULL, &fp_a, &st);
        bool b = swi_run_count_flood(0x571A0000000f1b01ULL, &fp_b, NULL);
        SWI_CHECK("ibd count-flood: headers count>2000 guard misbehaves + "
                  "disconnects, no silent halt", a);
        SWI_CHECK("ibd count-flood: same-seed fingerprint deterministic",
                  a && b && fp_a == fp_b);
        printf("[ibd count-flood] fp=0x%016" PRIx64
               " misbehave=%" PRIu64 " disconnected=%d consensus_ok=%d\n",
               fp_a, st.peer_misbehave_events, st.nut_disconnected ? 1 : 0,
               st.consensus_unchanged ? 1 : 0);
    }

    {
        uint64_t fp_a = 0;
        uint64_t fp_b = 0;
        struct simnet_wire_stats st;
        memset(&st, 0, sizeof(st));
        bool a = swi_run_malformed_body(0x571A0000000f1b02ULL, &fp_a, &st);
        bool b = swi_run_malformed_body(0x571A0000000f1b02ULL, &fp_b, NULL);
        SWI_CHECK("ibd malformed-header: deserialize reject scores peer, node "
                  "survives + still serves honest link", a);
        SWI_CHECK("ibd malformed-header: same-seed fingerprint deterministic",
                  a && b && fp_a == fp_b);
        printf("[ibd malformed-header] fp=0x%016" PRIx64
               " misbehave=%" PRIu64 " disconnected=%d pong=%d\n",
               fp_a, st.peer_misbehave_events, st.nut_disconnected ? 1 : 0,
               st.pong_received ? 1 : 0);
    }

    printf("=== simnet_wire IBD: %d failures ===\n", failures);
    return failures;
}
