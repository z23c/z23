/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_swarm scenario checks, adversarial first: malicious peers
 * serving WRONG-HASH chunks or wrong chunk coordinates (named,
 * no-credit, never reaches the CAS); unrequested DATA and duplicate-
 * response replay; the honest CANCELLED/peer-drop race; announce-only
 * earning nothing, the announce inventory bound, and the announce-
 * flood rate limit; and the ordinary C23 library shelf announce walk.
 *
 * Split out of test_zcode_swarm.c (which keeps the includes, the
 * fixture helpers shared across siblings, and the group entry point)
 * so no family member crosses the 1,500-line ceiling. */

#include "test/test_core.h"

#include "test/public_shape_fixture.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "command/native_command.h"
#include "config/boot_zcode_dht.h"
#include "vcs/blob_store.h"
#include "vcs/package_prepare.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_release.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_transport.h"
#include "vcs/service_receipt.h"

#include <secp256k1.h>

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "vcs/package_accept.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "test/test_zcode_swarm_priv.h"

static int swarm_case_invalid_wrong_manifest(struct sw_node *n,
                                              struct sw_pkg *p,
                                              uint64_t bad,
                                              const uint8_t *key)
{
    int failures = 0;
    /* Wrong-hash manifest from the malicious peer: named invalid,
     * INVALID_CHUNK offence, UNVERIFIED no-credit, nothing stored. */
    vcs_swarm_engine_tick(n->engine, SW_DAY, 2);
    struct vcs_package_swarm_object wants[8];
    SW_CHECK("manifest want issued", sw_drain_wants(n, bad, wants, 8) == 1);
    uint8_t corrupted[4096];
    memcpy(corrupted, p->wire, p->wire_len);
    corrupted[p->wire_len - 1] ^= 0xff; /* root no longer reproduces */
    struct vcs_swarm_frame_result res =
        sw_answer(n, bad, &wants[0], corrupted, p->wire_len, UINT32_MAX);
    SW_CHECK("wrong manifest named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA &&
             res.rule != NULL && strcmp(res.rule, "invalid-chunk") == 0);
    struct vcs_service_key_totals totals;
    SW_CHECK("wrong manifest: invalid offence + unverified no-credit",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] == 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_UNVERIFIED] == 1 &&
             totals.verified_bytes_downloaded == 0);
    struct vcs_swarm_download_status dst;
    SW_CHECK("still want-manifest",
             vcs_swarm_engine_download_status(n->engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_WANT_MANIFEST);
    return failures;
}

static int swarm_case_invalid_honest_takeover(struct sw_node *n,
                                               struct sw_pkg *p,
                                               uint64_t bad, uint64_t honest,
                                               const uint8_t *key2)
{
    int failures = 0;
    /* The malicious peer is manifest-failed; a fresh honest peer serves
     * the manifest. */
    SW_CHECK("honest peer add",
             vcs_swarm_engine_peer_add(n->engine, honest, key2));
    sw_announce(n->engine, honest, p);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 3);
    struct vcs_package_swarm_object wants[8];
    SW_CHECK("honest peer gets no stale frames",
             sw_drain_wants(n, bad, wants, 8) == 0);
    SW_CHECK("manifest want to honest peer",
             sw_drain_wants(n, honest, wants, 8) == 1);
    struct vcs_swarm_frame_result res =
        sw_answer(n, honest, &wants[0], p->wire, p->wire_len, UINT32_MAX);
    SW_CHECK("honest manifest accepted", res.penalty == VCS_SWARM_PENALTY_NONE);
    struct vcs_swarm_download_status dst;
    SW_CHECK("now downloading chunks",
             vcs_swarm_engine_download_status(n->engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS);
    return failures;
}

static int swarm_case_invalid_chunk_answers(
    struct sw_node *n, struct sw_pkg *p, uint64_t bad, uint64_t honest,
    const uint8_t *key, struct vcs_package_swarm_object *honest_want0)
{
    int failures = 0;
    /* Chunk WANTs spread deterministically: slot 0 (bad) holds chunks 0
     * and 2, slot 1 (honest) chunk 1. Answer bad's chunk 0 with a wrong
     * hash and chunk 2 with wrong coordinates; answer NOTHING honest
     * yet, so the CAS must stay empty and credit at the manifest only. */
    vcs_swarm_engine_tick(n->engine, SW_DAY, 4);
    struct vcs_package_swarm_object bad_wants[8], honest_wants[8];
    size_t nb = sw_drain_wants(n, bad, bad_wants, 8);
    size_t nh = sw_drain_wants(n, honest, honest_wants, 8);
    SW_CHECK("bad peer holds two chunk wants", nb == 2);
    SW_CHECK("honest peer holds one chunk want", nh == 1);
    *honest_want0 = honest_wants[0];
    uint8_t wrong[SW_MAX_FILE];
    size_t len0 = 0;
    const uint8_t *bytes0 = sw_chunk_bytes(p, bad_wants[0].file_index,
                                           &len0);
    memcpy(wrong, bytes0, len0);
    wrong[0] ^= 0xff;
    struct vcs_swarm_frame_result res =
        sw_answer(n, bad, &bad_wants[0], wrong, len0, UINT32_MAX);
    SW_CHECK("wrong-hash chunk named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA);
    uint32_t other = (bad_wants[1].file_index + 1u) % (uint32_t)p->count;
    size_t len2 = 0;
    const uint8_t *bytes2 = sw_chunk_bytes(p, other, &len2);
    res = sw_answer(n, bad, &bad_wants[1], bytes2, len2, other);
    SW_CHECK("wrong-coords chunk named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA);
    struct vcs_service_key_totals totals;
    SW_CHECK("invalid chunks: offences accumulate, no credit",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] == 3 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_INVALID_CHUNK] >= 2 &&
             totals.verified_bytes_downloaded == 0);
    bool any_present = false;
    for (uint32_t fi = 0; fi < p->count; fi++)
        any_present |= vcs_package_store_chunk_present(n->store, p->root, fi,
                                                       0);
    SW_CHECK("invalid bytes never stored", !any_present);
    return failures;
}

static int swarm_case_invalid_finish_honest(
    struct sw_node *n, struct sw_pkg *p, uint64_t honest,
    const struct vcs_package_swarm_object *honest_want0, const uint8_t *key)
{
    int failures = 0;
    /* The honest peer finishes: its held chunk plus the two reassigned
     * ones (the bad peer is failed for both). */
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { honest };
    /* Answer the already-held honest want first. */
    size_t lenh = 0;
    const uint8_t *bytesh = sw_chunk_bytes(p, honest_want0->file_index,
                                           &lenh);
    struct vcs_swarm_frame_result res =
        sw_answer(n, honest, honest_want0, bytesh, lenh, UINT32_MAX);
    SW_CHECK("held honest chunk accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("completes via honest peer",
             sw_drive_complete(n, peers, 1, p, &max_inflight));
    SW_CHECK("in-flight bound honored", max_inflight > 0 &&
             max_inflight <= VCS_SWARM_PEER_INFLIGHT_MAX);
    struct vcs_package_store_status sst;
    SW_CHECK("store complete",
             vcs_package_store_package_status(n->store, p->root, &sst) &&
             sst.complete);
    struct vcs_service_key_totals totals;
    SW_CHECK("malicious peer earned nothing",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == 0);
    return failures;
}

int t_swarm_invalid_data(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33], key2[33];
    sw_key(7, key);
    sw_key(8, key2);
    if (!sw_node_open(&n, "invalid", sw_score_contributor) ||
        !sw_make_package(&p, 3, 11))
        return 1;
    const uint64_t bad = 1001, honest = 1002;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, bad, key));
    sw_announce(n.engine, bad, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);

    failures += swarm_case_invalid_wrong_manifest(&n, &p, bad, key);
    failures += swarm_case_invalid_honest_takeover(&n, &p, bad, honest,
                                                    key2);

    struct vcs_package_swarm_object honest_want0;
    failures += swarm_case_invalid_chunk_answers(&n, &p, bad, honest, key,
                                                 &honest_want0);
    failures += swarm_case_invalid_finish_honest(&n, &p, honest,
                                                 &honest_want0, key);

    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 3-4: unrequested bytes, replays, cancel races ────────────────── */

int t_swarm_unsolicited_and_replay(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(9, key);
    if (!sw_node_open(&n, "unsolicited", sw_score_contributor) ||
        !sw_make_package(&p, 2, 21))
        return 1;
    const uint64_t peer = 2001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));

    /* DATA for a root with no download at all: UNREQUESTED. */
    struct vcs_package_swarm_message data;
    memset(&data, 0, sizeof(data));
    data.type = VCS_PACKAGE_SWARM_DATA;
    data.body.data.object.request_id = 4242;
    memcpy(data.body.data.object.package_root, p.root, 32);
    data.body.data.object.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    data.body.data.object.file_index = 0;
    data.body.data.object.chunk_index = 0;
    memcpy(data.body.data.object.expected_hash,
           p.manifest.files[0].chunk_hashes, 32);
    size_t len = 0;
    data.body.data.bytes = sw_chunk_bytes(&p, 0, &len);
    data.body.data.bytes_len = (uint32_t)len;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t frame_len = 0;
    SW_CHECK("unsolicited data serializes",
             vcs_package_swarm_serialize(&data, frame, sizeof(frame),
                                         &frame_len));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, frame_len, SW_DAY, 1);
    SW_CHECK("unrequested bytes named",
             res.penalty == VCS_SWARM_PENALTY_UNREQUESTED_DATA &&
             res.rule != NULL && strcmp(res.rule, "unrequested-bytes") == 0);
    struct vcs_service_key_totals totals;
    SW_CHECK("unrequested offence recorded",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_UNREQUESTED_BYTES] == 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_UNREQUESTED] == 1 &&
             totals.verified_bytes_downloaded == 0);

    /* Honest fetch; duplicate replay of one chunk DATA: the first copy
     * earns, the replay is a DUPLICATE_REQUEST offence, no double
     * credit. */
    sw_announce(n.engine, peer, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, false, 2, &st); /* manifest */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);
    memset(&st, 0, sizeof(st));
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, true, 3, &st);  /* dup chunks */
    SW_CHECK("replay named duplicate-request",
             st.last.penalty == VCS_SWARM_PENALTY_REPLAYED_DATA &&
             st.last.rule != NULL &&
             strcmp(st.last.rule, "duplicate-request") == 0);
    SW_CHECK("replay offence recorded",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_DUPLICATE_REQUEST] >= 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_DUPLICATE_REQUEST]
                 >= 1);
    uint64_t earned = 0;
    for (size_t i = 0; i < p.count; i++)
        earned += p.lens[i];
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { peer };
    SW_CHECK("completes despite replays",
             sw_drive_complete(&n, peers, 1, &p, &max_inflight));
    SW_CHECK("verified bytes counted once per chunk",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded ==
                 earned + p.wire_len);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

int t_swarm_cancel_race(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(10, key);
    if (!sw_node_open(&n, "cancelrace", sw_score_contributor) ||
        !sw_make_package(&p, 4, 31))
        return 1;
    const uint64_t peer = 3001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, false, 2, &st); /* manifest */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);            /* chunk wants */
    /* Cancel with chunk WANTs outstanding: CANCEL frames must appear. */
    SW_CHECK("cancel accepted",
             vcs_swarm_engine_cancel(n.engine, p.root, 3));
    memset(&st, 0, sizeof(st));
    /* Drain WITHOUT answering (manifest pump consumed already-answered
     * wants; remaining outbound = WANTs + CANCELs). */
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    uint32_t cancels = 0, wants = 0;
    uint64_t cancelled_id = 0;
    while (vcs_swarm_engine_next_outbound(n.engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg))
            continue;
        if (msg.type == VCS_PACKAGE_SWARM_CANCEL) {
            cancels++;
            cancelled_id = msg.body.cancel.request_id;
        } else if (msg.type == VCS_PACKAGE_SWARM_WANT) {
            wants++;
            /* Capture one outstanding WANT to answer AFTER the cancel. */
            cancelled_id = msg.body.want.request_id;
        }
    }
    SW_CHECK("cancel frames queued", cancels > 0);
    (void)wants;
    /* Late DATA for the cancelled id: the honest race — no credit and
     * NO offence. */
    struct vcs_package_swarm_message late;
    memset(&late, 0, sizeof(late));
    late.type = VCS_PACKAGE_SWARM_DATA;
    late.body.data.object.request_id = cancelled_id;
    memcpy(late.body.data.object.package_root, p.root, 32);
    late.body.data.object.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    late.body.data.object.file_index = 0;
    late.body.data.object.chunk_index = 0;
    memcpy(late.body.data.object.expected_hash,
           p.manifest.files[0].chunk_hashes, 32);
    size_t len = 0;
    late.body.data.bytes = sw_chunk_bytes(&p, 0, &len);
    late.body.data.bytes_len = (uint32_t)len;
    uint8_t dframe[8 + 96 + SW_MAX_FILE];
    size_t dlen = 0;
    SW_CHECK("late data serializes",
             vcs_package_swarm_serialize(&late, dframe, sizeof(dframe),
                                         &dlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, dframe, dlen, SW_DAY, 4);
    SW_CHECK("late cancelled data: no penalty",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    struct vcs_service_key_totals totals;
    /* The manifest was honestly served pre-cancel (credited); the late
     * cancelled DATA adds NO offence and NO further credit. */
    SW_CHECK("late cancelled data: no offence, no credit",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offence_total == 0 &&
             totals.verified_bytes_downloaded == p.wire_len);
    /* The cancelled download is a named terminal state; re-fetch starts
     * clean. */
    struct vcs_swarm_download_status dst;
    SW_CHECK("cancelled download named",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_FAILED && dst.rule != NULL &&
             strcmp(dst.rule, "operator-cancelled") == 0);
    SW_CHECK("re-fetch after cancel",
             vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY, 5) ==
                 VCS_SWARM_FETCH_OK);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 4b: peer-drop straggler races ────────────────────────────────── */
/* A mid-transfer disconnect frees the peer's outstanding wants with no
 * CANCEL frame (the route is gone). When the same node id reconnects,
 * frames it had already queued before the drop must read as the
 * cancelled honest race peer_drop tombstones — never as unrequested
 * bytes with a disconnect. */
int t_swarm_drop_race(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(11, key);
    if (!sw_node_open(&n, "droprace", sw_score_contributor) ||
        !sw_make_package(&p, 4, 33))
        return 1;
    const uint64_t peer = 3501;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, false, 2, &st); /* manifest */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);            /* chunk wants */
    /* Capture one still-outstanding chunk WANT, unanswered. */
    uint64_t stranded_id = 0;
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    while (vcs_swarm_engine_next_outbound(n.engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg))
            continue;
        if (msg.type == VCS_PACKAGE_SWARM_WANT)
            stranded_id = msg.body.want.request_id;
    }
    SW_CHECK("chunk want was outstanding", stranded_id != 0);

    /* Drop mid-transfer; the same node reconnects under its id and key.
     * Its straggler now matches no outstanding req, so the only thing
     * standing between it and an UNREQUESTED offence is the cancelled
     * tombstone peer_drop writes. */
    vcs_swarm_engine_peer_drop(n.engine, peer);
    SW_CHECK("reconnect re-registers",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    /* A reconnecting node re-advertises: the fresh slot carries no ads,
     * and the scheduler pulls only from known advertisers. */
    sw_announce(n.engine, peer, &p);

    struct vcs_package_swarm_message late;
    memset(&late, 0, sizeof(late));
    late.type = VCS_PACKAGE_SWARM_DATA;
    late.body.data.object.request_id = stranded_id;
    memcpy(late.body.data.object.package_root, p.root, 32);
    late.body.data.object.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    late.body.data.object.file_index = 0;
    late.body.data.object.chunk_index = 0;
    memcpy(late.body.data.object.expected_hash,
           p.manifest.files[0].chunk_hashes, 32);
    size_t len = 0;
    late.body.data.bytes = sw_chunk_bytes(&p, 0, &len);
    late.body.data.bytes_len = (uint32_t)len;
    uint8_t dframe[8 + 96 + SW_MAX_FILE];
    size_t dlen = 0;
    SW_CHECK("straggler data serializes",
             vcs_package_swarm_serialize(&late, dframe, sizeof(dframe),
                                         &dlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, dframe, dlen, SW_DAY, 4);
    SW_CHECK("dropped-peer straggler: no penalty",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    struct vcs_service_key_totals totals;
    /* The manifest was honestly served pre-drop (credited); the
     * straggler adds NO offence and NO further credit — no-credit still
     * books once, as for any cancelled-id arrival. */
    SW_CHECK("dropped-peer straggler: no offence, no credit",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_UNREQUESTED_BYTES] == 0 &&
             totals.offence_total == 0 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_UNREQUESTED] ==
                 1 &&
             totals.verified_bytes_downloaded == p.wire_len);

    /* The download itself survived the drop and finishes through the
     * reconnected peer (req_finish also balanced in-flight accounting). */
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { peer };
    SW_CHECK("completes via reconnected peer",
             sw_drive_complete(&n, peers, 1, &p, &max_inflight));
    SW_CHECK("in-flight bound honored", max_inflight > 0 &&
             max_inflight <= VCS_SWARM_PEER_INFLIGHT_MAX);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 5: announcements never earn; announce flood named ────────────── */

static int swarm_case_announce_fill_inventory(
    struct sw_node *n, struct sw_pkg *p, uint64_t peer, const uint8_t *key,
    const uint8_t *frame, size_t frame_len,
    struct vcs_swarm_peer_info infos[4])
{
    int failures = 0;
    (void)key;
    /* NEW_USER announce rate is the unique-root serving-set inventory
     * bound (VCS_POLICY_FREE_ANNOUNCE_PER_HOUR/hour). Keep-alive repeats
     * of a root already in peer->ads[] do not consume it. */
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n->engine, peer, frame, frame_len, SW_DAY, 1);
    SW_CHECK("new-user first unique announce accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("new-user announce recorded",
             vcs_swarm_engine_peers_for(n->engine, p->root, infos, 4) == 1);
    res = vcs_swarm_engine_handle_frame(n->engine, peer, frame, frame_len,
                                        SW_DAY, 1);
    SW_CHECK("keep-alive of the same root accepted, no flood",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    bool minted = true;
    uint32_t extra_accepted = 0;
    for (uint32_t i = 1; i < VCS_POLICY_FREE_ANNOUNCE_PER_HOUR; i++) {
        struct sw_pkg extra;
        /* count>=2 so seed changes the root (LICENSE-only packages share
         * one root). */
        if (!sw_make_package(&extra, 2, (uint8_t)(50u + i))) {
            minted = false;
            break;
        }
        uint8_t extra_frame[128];
        size_t extra_len = sw_announce_frame(&extra, extra_frame);
        res = vcs_swarm_engine_handle_frame(n->engine, peer, extra_frame,
                                            extra_len, SW_DAY, 1);
        if (res.penalty == VCS_SWARM_PENALTY_NONE)
            extra_accepted++;
        sw_free_package(&extra);
    }
    SW_CHECK("new-user unique announces fill the inventory bound",
             minted &&
             extra_accepted == VCS_POLICY_FREE_ANNOUNCE_PER_HOUR - 1);
    return failures;
}

static int swarm_case_announce_over_bound(
    struct sw_node *n, struct sw_pkg *p, uint64_t peer, const uint8_t *key,
    struct vcs_swarm_peer_info infos[4], struct sw_pkg *over, bool *built)
{
    int failures = 0;
    *built = sw_make_package(
        over, 2, (uint8_t)(50u + VCS_POLICY_FREE_ANNOUNCE_PER_HOUR));
    if (!*built)
        return failures;
    uint8_t over_frame[128];
    size_t over_len = sw_announce_frame(over, over_frame);
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n->engine, peer, over_frame, over_len, SW_DAY, 1);
    SW_CHECK("new-user distinct root over inventory bound flood named",
             res.penalty == VCS_SWARM_PENALTY_ANNOUNCE_FLOOD &&
             res.rule != NULL &&
             strcmp(res.rule, "announce-rate-limit") == 0);
    struct vcs_service_key_totals totals;
    /* Unique accepts + one keep-alive + one flood unique; no credit. */
    SW_CHECK("announce: one flood offence, no ratio movement",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD] == 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_ANNOUNCEMENT] ==
                 VCS_POLICY_FREE_ANNOUNCE_PER_HOUR + 2 &&
             totals.verified_bytes_downloaded == 0 &&
             totals.verified_bytes_uploaded == 0);
    SW_CHECK("first unique root still advertised after keep-alive",
             vcs_swarm_engine_peers_for(n->engine, p->root, infos, 4) == 1);
    SW_CHECK("flooded distinct root was not added to the serving set",
             vcs_swarm_engine_peers_for(n->engine, over->root, infos, 4) ==
                 0);
    return failures;
}

static int swarm_case_announce_contributor(const uint8_t *frame,
                                            size_t frame_len,
                                            struct sw_pkg *p,
                                            struct vcs_swarm_peer_info
                                                infos[4],
                                            struct sw_node *n2, bool *opened)
{
    int failures = 0;
    /* An earned contributor may announce; it STILL earns nothing. */
    uint8_t key2[33];
    sw_key(13, key2);
    *opened = sw_node_open(n2, "announce2", sw_score_contributor);
    if (!*opened)
        return failures;
    const uint64_t peer2 = 4002;
    SW_CHECK("peer2 add", vcs_swarm_engine_peer_add(n2->engine, peer2,
                                                    key2));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n2->engine, peer2, frame, frame_len, SW_DAY, 1);
    SW_CHECK("contributor announce accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("contributor announce recorded",
             vcs_swarm_engine_peers_for(n2->engine, p->root, infos, 4) == 1);
    struct vcs_service_key_totals totals;
    SW_CHECK("contributor announce earns nothing",
             vcs_service_key_totals(n2->book, key2, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == 0 &&
             totals.verified_bytes_uploaded == 0 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_ANNOUNCEMENT] == 1 &&
             totals.offence_total == 0);
    return failures;
}

int t_swarm_announce_policy(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    if (!sw_node_open(&n, "announce", NULL /* score 0: NEW_USER */) ||
        !sw_make_package(&p, 1, 41))
        return 1;
    uint8_t key[33];
    sw_key(12, key);
    const uint64_t peer = 4001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    uint8_t frame[128];
    size_t frame_len = sw_announce_frame(&p, frame);
    struct vcs_swarm_peer_info infos[4];

    failures += swarm_case_announce_fill_inventory(&n, &p, peer, key, frame,
                                                    frame_len, infos);

    struct sw_pkg over;
    bool over_built = false;
    failures += swarm_case_announce_over_bound(&n, &p, peer, key, infos,
                                               &over, &over_built);
    if (!over_built) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }
    sw_free_package(&over);

    struct sw_node n2;
    bool n2_opened = false;
    failures += swarm_case_announce_contributor(frame, frame_len, &p, infos,
                                                &n2, &n2_opened);
    if (!n2_opened) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }

    sw_free_package(&p);
    sw_node_close(&n);
    sw_node_close(&n2);
    test_rm_rf_recursive(n.datadir);
    test_rm_rf_recursive(n2.datadir);
    return failures;
}

/* Prepare, sign, store, pin, and import one in-tree package as a public
 * transport carrier. Distinct `seed` values pick distinct publisher keys
 * so each title keeps its own sequence-1 release. */
static bool sw_seed_prepare_signed(const char *source_dir, uint8_t seed,
                                   uint64_t sequence,
                                   struct vcs_package_prepared *prepared)
{
    struct privkey sk;
    struct pubkey pk;
    if (!sw_keypair(seed, &sk, &pk))
        return false;
    struct vcs_package_prepare_options options = {
        .dir = source_dir,
        .publisher_sequence = sequence,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    vcs_package_prepared_init(prepared);
    char detail[160] = {0};
    if (vcs_package_prepare(&options, prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        fprintf(stderr, "zcode_swarm shelf prepare %s: %s\n", source_dir,
                detail);
        vcs_package_prepared_free(prepared);
        return false;
    }
    struct uint256 digest;
    memcpy(digest.data, prepared->signing_digest, 32);
    uint8_t compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &digest, compact)) {
        vcs_package_prepared_free(prepared);
        return false;
    }
    memcpy(prepared->release.signature, compact + 1,
           VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool sw_seed_store_transport(struct sw_node *n,
                                    const char *source_dir,
                                    struct vcs_package_prepared *prepared,
                                    uint8_t transport_root[32])
{
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_transport transport;
    vcs_package_transport_init(&transport);
    bool ok =
        vcs_package_release_verify(&prepared->release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_serialize(&prepared->release, &release_wire,
                                      &release_wire_len) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_transport_build(
            release_wire, release_wire_len, prepared->recipe_wire,
            prepared->recipe_wire_len, prepared->manifest_wire,
            prepared->manifest_wire_len, &transport) ==
            VCS_PACKAGE_TRANSPORT_OK &&
        vcs_package_transport_store(n->store, &transport, source_dir) ==
            VCS_PACKAGE_TRANSPORT_OK &&
        vcs_package_store_pin(n->store, transport.transport_root, true) ==
            VCS_PACKAGE_STORE_OK;
    if (ok)
        memcpy(transport_root, transport.transport_root, 32);
    free(release_wire);
    vcs_package_transport_free(&transport);
    vcs_package_prepared_free(prepared);
    return ok;
}

static bool sw_seed_import_and_classify(struct sw_node *n,
                                        const char *source_dir,
                                        uint8_t transport_root[32])
{
    struct vcs_package_store_status st;
    if (!vcs_package_store_package_status(n->store, transport_root, &st) ||
        !st.complete || !st.pinned)
        return false;
    struct vcs_package_transport_import imported;
    memset(&imported, 0, sizeof(imported));
    if (vcs_swarm_engine_import_transport(n->engine, transport_root,
                                          &imported) !=
        VCS_PACKAGE_TRANSPORT_OK)
        return false;
    struct vcs_package_public_verdict shape;
    vcs_package_public_shape_classify(n->store, transport_root, &shape);
    if (shape.shape == VCS_PACKAGE_PUBLIC_REFUSED) {
        fprintf(stderr, "zcode_swarm shelf public_shape %s: %s (%s)\n",
                source_dir, shape.rule ? shape.rule : "?",
                shape.dependency_rule ? shape.dependency_rule : "-");
        return false;
    }
    return true;
}

static bool sw_seed_in_tree_package(struct sw_node *n, const char *source_dir,
                                    uint8_t seed, uint64_t sequence,
                                    uint8_t transport_root[32])
{
    if (!n || !source_dir || !transport_root || !n->store || !n->engine)
        return false;
    struct vcs_package_prepared prepared;
    if (!sw_seed_prepare_signed(source_dir, seed, sequence, &prepared))
        return false;
    if (!sw_seed_store_transport(n, source_dir, &prepared, transport_root))
        return false;
    return sw_seed_import_and_classify(n, source_dir, transport_root);
}

static size_t sw_drain_announces(struct sw_node *n, uint64_t peer,
                                 uint8_t frames[][VCS_SWARM_OUTBOUND_FRAME_MAX],
                                 size_t *lens, size_t max)
{
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0, count = 0;
    while (vcs_swarm_engine_next_outbound(n->engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg) ||
            msg.type != VCS_PACKAGE_SWARM_ANNOUNCE)
            continue;
        if (count < max) {
            memcpy(frames[count], frame, frame_len);
            lens[count] = frame_len;
            count++;
        }
    }
    return count;
}

static bool sw_announce_names_root(const uint8_t *frame, size_t len,
                                   const uint8_t root[32])
{
    struct vcs_package_swarm_message msg;
    return vcs_package_swarm_parse(frame, len, &msg) &&
           msg.type == VCS_PACKAGE_SWARM_ANNOUNCE &&
           memcmp(msg.body.announce.package_root, root, 32) == 0;
}

/* Independent in-tree titles, not the Arena set (zprng/zdogfight/
 * zdogace/zdogview). zutf8 before zjson so the seeder holds the
 * declared dependency when public-shape classifies the dependent. */
static const char *const k_c23_shelf[] = {
    "contexts/commons/packages/zhex",   "contexts/commons/packages/zstr", "contexts/commons/packages/zbuf",  "contexts/commons/packages/zsha256",
    "contexts/commons/packages/zring",  "contexts/commons/packages/zmap", "contexts/commons/packages/zvec",  "contexts/commons/packages/zutf8",
    "contexts/commons/packages/zjson",
};
enum { SW_SHELF_N = (int)(sizeof(k_c23_shelf) / sizeof(k_c23_shelf[0])) };

static int shelf_case_seed_titles(struct sw_node *seeder,
                                   uint8_t roots[SW_SHELF_N][32],
                                   bool *seeded)
{
    int failures = 0;
    *seeded = true;
    for (size_t i = 0; i < SW_SHELF_N; i++) {
        if (!sw_seed_in_tree_package(seeder, k_c23_shelf[i],
                                     (uint8_t)(0x61u + i), i + 1u,
                                     roots[i])) {
            fprintf(stderr, "zcode_swarm shelf: failed %s\n",
                    k_c23_shelf[i]);
            *seeded = false;
            break;
        }
    }
    SW_CHECK("ordinary C23 shelf has at least eight titles",
             SW_SHELF_N >= 8);
    SW_CHECK("ordinary C23 shelf prepared and imported", *seeded);
    if (!*seeded)
        return failures;
    bool unique_roots = true;
    for (size_t i = 0; i < SW_SHELF_N; i++)
        for (size_t j = i + 1u; j < SW_SHELF_N; j++)
            if (memcmp(roots[i], roots[j], 32) == 0)
                unique_roots = false;
    SW_CHECK("shelf titles derive distinct transport roots", unique_roots);
    return failures;
}

static int shelf_case_seeder_announces(
    struct sw_node *seeder, uint64_t seed_peer, const uint8_t *seed_key,
    const uint8_t roots[SW_SHELF_N][32],
    uint8_t frames[VCS_SWARM_MAX_LOCAL_ANNOUNCES]
                  [VCS_SWARM_OUTBOUND_FRAME_MAX],
    size_t lens[VCS_SWARM_MAX_LOCAL_ANNOUNCES], size_t *drained)
{
    int failures = 0;
    SW_CHECK("seeder peer add",
             vcs_swarm_engine_peer_add(seeder->engine, seed_peer, seed_key));
    size_t queued = vcs_swarm_engine_announce_to(seeder->engine, seed_peer);
    SW_CHECK("announce_to queues the public-serveable shelf",
             queued >= SW_SHELF_N && queued <= VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    memset(frames, 0,
           sizeof(uint8_t) * VCS_SWARM_MAX_LOCAL_ANNOUNCES *
               VCS_SWARM_OUTBOUND_FRAME_MAX);
    memset(lens, 0, sizeof(size_t) * VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    *drained = sw_drain_announces(seeder, seed_peer, frames, lens,
                                  VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    SW_CHECK("queued announces drain", *drained == queued);
    bool all_seeded = true;
    for (size_t i = 0; i < SW_SHELF_N; i++) {
        bool found = false;
        for (size_t j = 0; j < *drained; j++)
            if (sw_announce_names_root(frames[j], lens[j], roots[i]))
                found = true;
        if (!found)
            all_seeded = false;
    }
    SW_CHECK("every seeded transport root was announced", all_seeded);
    SW_CHECK("re-announce is already-announced keep-alive, not a flood",
             vcs_swarm_engine_announce_to(seeder->engine, seed_peer) == 0);
    return failures;
}

static int shelf_case_learner_learns(
    struct sw_node *learner, uint64_t learn_peer, const uint8_t *learn_key,
    const uint8_t roots[SW_SHELF_N][32],
    uint8_t frames[VCS_SWARM_MAX_LOCAL_ANNOUNCES]
                  [VCS_SWARM_OUTBOUND_FRAME_MAX],
    const size_t lens[VCS_SWARM_MAX_LOCAL_ANNOUNCES], size_t drained)
{
    int failures = 0;
    SW_CHECK("learner peer add",
             vcs_swarm_engine_peer_add(learner->engine, learn_peer,
                                       learn_key));
    bool learned = true;
    uint32_t unique_accepted = 0;
    for (size_t i = 0; i < drained; i++) {
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            learner->engine, learn_peer, frames[i], lens[i], SW_DAY, 1);
        if (res.penalty != VCS_SWARM_PENALTY_NONE) {
            learned = false;
            break;
        }
        unique_accepted++;
    }
    SW_CHECK("NEW_USER learns the shelf unique roots without flood",
             learned && unique_accepted == drained &&
             unique_accepted <= VCS_POLICY_FREE_ANNOUNCE_PER_HOUR);
    struct vcs_swarm_peer_info infos[4];
    bool advertised = true;
    for (size_t i = 0; i < SW_SHELF_N; i++)
        if (vcs_swarm_engine_peers_for(learner->engine, roots[i], infos,
                                       4) != 1)
            advertised = false;
    SW_CHECK("NEW_USER recorded each shelf transport root", advertised);
    bool keep_alive = true;
    for (size_t i = 0; i < drained; i++) {
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            learner->engine, learn_peer, frames[i], lens[i], SW_DAY, 2);
        if (res.penalty != VCS_SWARM_PENALTY_NONE)
            keep_alive = false;
    }
    struct vcs_service_key_totals totals;
    SW_CHECK("keep-alive repeats of heard roots are not ANNOUNCE_FLOOD",
             keep_alive &&
             vcs_service_key_totals(learner->book, learn_key, SW_DAY,
                                    &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD] == 0);
    SW_CHECK("unique-flood bound is still the serving-set size",
             VCS_POLICY_FREE_ANNOUNCE_PER_HOUR ==
                 VCS_SWARM_MAX_LOCAL_ANNOUNCES &&
             SW_SHELF_N < VCS_POLICY_FREE_ANNOUNCE_PER_HOUR);
    return failures;
}

int t_swarm_c23_shelf_announce(void)
{
    int failures = 0;
    struct sw_node seeder, learner;
    if (!sw_node_open(&seeder, "shelf-seed", sw_score_contributor) ||
        !sw_node_open(&learner, "shelf-learn", NULL /* NEW_USER */))
        return 1;
    uint8_t roots[SW_SHELF_N][32];
    memset(roots, 0, sizeof(roots));
    bool seeded = false;
    failures += shelf_case_seed_titles(&seeder, roots, &seeded);
    if (!seeded) {
        sw_node_close(&seeder);
        sw_node_close(&learner);
        test_rm_rf_recursive(seeder.datadir);
        test_rm_rf_recursive(learner.datadir);
        return failures + 1;
    }

    uint8_t seed_key[33], learn_key[33];
    sw_key(0x71, seed_key);
    sw_key(0x72, learn_key);
    const uint64_t seed_peer = 5101, learn_peer = 5102;
    uint8_t frames[VCS_SWARM_MAX_LOCAL_ANNOUNCES][VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t lens[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    size_t drained = 0;
    failures += shelf_case_seeder_announces(&seeder, seed_peer, seed_key,
                                            roots, frames, lens, &drained);
    failures += shelf_case_learner_learns(&learner, learn_peer, learn_key,
                                          roots, frames, lens, drained);

    sw_node_close(&seeder);
    sw_node_close(&learner);
    test_rm_rf_recursive(seeder.datadir);
    test_rm_rf_recursive(learner.datadir);
    return failures;
}

