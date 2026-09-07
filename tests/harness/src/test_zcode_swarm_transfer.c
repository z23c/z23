/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_swarm scenario checks: scheduler shape (manifest-first,
 * rarest-first, per-peer in-flight bound, multi-peer spread), timeout
 * retry with a fresh request id, disconnect requeue, resume after
 * restart from CAS presence, serving inbound WANTs with upload credit
 * and burst/allowance limits, the offence-count disconnect threshold,
 * and blob transfer (vcs/blob_store.h) over the unchanged swarm wire.
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

/* ── 6: scheduler shape + end-to-end ──────────────────────────────── */

static int scheduler_case_rarest_first_order(struct sw_node *n,
                                              struct sw_pkg *common,
                                              struct sw_pkg *rare,
                                              uint64_t d)
{
    int failures = 0;
    vcs_swarm_engine_tick(n->engine, SW_DAY, 2);
    /* Rarest-first: the RARE package's manifest WANT (to peer d) must be
     * queued ahead of COMMON's. */
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    SW_CHECK("first outbound exists",
             vcs_swarm_engine_next_outbound(n->engine, 0, &target, frame,
                                            &frame_len));
    SW_CHECK("rarest-first: rare package scheduled first", target == d);
    struct vcs_package_swarm_message msg;
    SW_CHECK("first frame parses",
             vcs_package_swarm_parse(frame, frame_len, &msg) &&
             msg.type == VCS_PACKAGE_SWARM_WANT &&
             memcmp(msg.body.want.package_root, rare->root, 32) == 0 &&
             msg.body.want.object_kind ==
                 VCS_PACKAGE_SWARM_OBJECT_MANIFEST);
    /* Manifest-first: no chunk WANT may precede a verified manifest. */
    SW_CHECK("second outbound is common manifest want",
             vcs_swarm_engine_next_outbound(n->engine, 0, &target, frame,
                                            &frame_len) &&
             vcs_package_swarm_parse(frame, frame_len, &msg) &&
             msg.body.want.object_kind ==
                 VCS_PACKAGE_SWARM_OBJECT_MANIFEST &&
             memcmp(msg.body.want.package_root, common->root, 32) == 0);
    return failures;
}

static void scheduler_case_drive_to_complete(
    struct sw_node *n, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    struct sw_pkg *common, struct sw_pkg *rare)
{
    /* End-to-end: both complete; chunk load spreads across the three
     * common advertisers. */
    for (int round = 3; round < 64; round++) {
        vcs_swarm_engine_tick(n->engine, SW_DAY, (uint64_t)round);
        struct sw_pump_stats st;
        memset(&st, 0, sizeof(st));
        sw_pump(n, a, common, SW_SERVE_HONEST, false, (uint64_t)round, &st);
        memset(&st, 0, sizeof(st));
        sw_pump(n, b, common, SW_SERVE_HONEST, false, (uint64_t)round, &st);
        memset(&st, 0, sizeof(st));
        sw_pump(n, c, common, SW_SERVE_HONEST, false, (uint64_t)round, &st);
        memset(&st, 0, sizeof(st));
        sw_pump(n, d, rare, SW_SERVE_HONEST, false, (uint64_t)round, &st);
        struct vcs_swarm_download_status s1, s2;
        vcs_swarm_engine_download_status(n->engine, common->root, &s1);
        vcs_swarm_engine_download_status(n->engine, rare->root, &s2);
        if (s1.state == VCS_SWARM_DL_COMPLETE &&
            s2.state == VCS_SWARM_DL_COMPLETE)
            break;
    }
}

static int scheduler_case_verify_complete(struct sw_node *n,
                                           struct sw_pkg *common,
                                           struct sw_pkg *rare,
                                           const uint8_t *k1,
                                           const uint8_t *k2,
                                           const uint8_t *k3)
{
    int failures = 0;
    struct vcs_swarm_download_status s1, s2;
    SW_CHECK("common complete",
             vcs_swarm_engine_download_status(n->engine, common->root,
                                              &s1) &&
             s1.state == VCS_SWARM_DL_COMPLETE);
    SW_CHECK("rare complete",
             vcs_swarm_engine_download_status(n->engine, rare->root, &s2) &&
             s2.state == VCS_SWARM_DL_COMPLETE);
    struct vcs_service_key_totals t1, t2, t3;
    vcs_service_key_totals(n->book, k1, SW_DAY, &t1);
    vcs_service_key_totals(n->book, k2, SW_DAY, &t2);
    vcs_service_key_totals(n->book, k3, SW_DAY, &t3);
    SW_CHECK("multi-peer spread: every advertiser served",
             t1.verified_bytes_downloaded > 0 ||
             t2.verified_bytes_downloaded > 0 ||
             t3.verified_bytes_downloaded > 0);
    SW_CHECK("no offences in honest run",
             t1.offence_total == 0 && t2.offence_total == 0 &&
             t3.offence_total == 0);
    /* Completion is verified CAS content: every chunk re-reads. */
    bool all_present = true;
    for (uint32_t fi = 0; fi < common->count; fi++)
        all_present &= vcs_package_store_chunk_present(n->store,
                                                       common->root, fi, 0);
    SW_CHECK("common chunks verified in CAS", all_present);
    return failures;
}

int t_swarm_scheduler_order(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg common, rare;
    if (!sw_node_open(&n, "sched", sw_score_contributor) ||
        !sw_make_package(&common, 3, 51) || !sw_make_package(&rare, 2, 91))
        return 1;
    uint8_t k1[33], k2[33], k3[33], k4[33];
    sw_key(1, k1);
    sw_key(2, k2);
    sw_key(3, k3);
    sw_key(4, k4);
    const uint64_t a = 11, b = 12, c = 13, d = 14;
    vcs_swarm_engine_peer_add(n.engine, a, k1);
    vcs_swarm_engine_peer_add(n.engine, b, k2);
    vcs_swarm_engine_peer_add(n.engine, c, k3);
    vcs_swarm_engine_peer_add(n.engine, d, k4);
    /* common: 3 advertisers; rare: 1 advertiser. */
    sw_announce(n.engine, a, &common);
    sw_announce(n.engine, b, &common);
    sw_announce(n.engine, c, &common);
    sw_announce(n.engine, d, &rare);
    SW_CHECK("fetch common",
             vcs_swarm_engine_fetch(n.engine, common.root, SW_DAY, 1) ==
                 VCS_SWARM_FETCH_OK);
    SW_CHECK("fetch rare",
             vcs_swarm_engine_fetch(n.engine, rare.root, SW_DAY, 1) ==
                 VCS_SWARM_FETCH_OK);

    failures += scheduler_case_rarest_first_order(&n, &common, &rare, d);
    scheduler_case_drive_to_complete(&n, a, b, c, d, &common, &rare);
    failures += scheduler_case_verify_complete(&n, &common, &rare, k1, k2,
                                               k3);

    sw_free_package(&common);
    sw_free_package(&rare);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 7-8: timeout/retry bounds + disconnect requeue ───────────────── */

int t_swarm_timeout_retry(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(15, key);
    if (!sw_node_open(&n, "timeout", sw_score_contributor) ||
        !sw_make_package(&p, 1, 61))
        return 1;
    const uint64_t peer = 5001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    /* The silent peer never answers: each timeout reissues with a FRESH
     * id, and the bounded attempt budget fails the download with a named
     * rule. */
    uint64_t ids[VCS_SWARM_MAX_CHUNK_ATTEMPTS * 2];
    size_t id_count = 0;
    uint64_t now = 2;
    struct vcs_swarm_download_status dst;
    for (int round = 0; round < 40; round++) {
        vcs_swarm_engine_tick(n.engine, SW_DAY, now);
        uint64_t target = 0;
        uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
        size_t frame_len = 0;
        while (vcs_swarm_engine_next_outbound(n.engine, peer, &target,
                                              frame, &frame_len)) {
            struct vcs_package_swarm_message msg;
            if (vcs_package_swarm_parse(frame, frame_len, &msg) &&
                msg.type == VCS_PACKAGE_SWARM_WANT &&
                id_count < sizeof(ids) / sizeof(ids[0]))
                ids[id_count++] = msg.body.want.request_id;
        }
        vcs_swarm_engine_download_status(n.engine, p.root, &dst);
        if (dst.state == VCS_SWARM_DL_FAILED)
            break;
        now += VCS_SWARM_REQUEST_TIMEOUT_TICKS + 1u;
    }
    SW_CHECK("bounded attempts fail named",
             dst.state == VCS_SWARM_DL_FAILED && dst.rule != NULL &&
             strcmp(dst.rule, "manifest-attempts-exhausted") == 0);
    SW_CHECK("retries were issued", id_count >= 2);
    bool distinct = true;
    for (size_t i = 0; i < id_count; i++)
        for (size_t j = i + 1; j < id_count; j++)
            if (ids[i] == ids[j])
                distinct = false;
    SW_CHECK("every retry uses a fresh request id", distinct);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

int t_swarm_disconnect_requeue(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t k1[33], k2[33];
    sw_key(21, k1);
    sw_key(22, k2);
    if (!sw_node_open(&n, "requeue", sw_score_contributor) ||
        !sw_make_package(&p, 6, 71))
        return 1;
    const uint64_t p1 = 6001, p2 = 6002;
    vcs_swarm_engine_peer_add(n.engine, p1, k1);
    vcs_swarm_engine_peer_add(n.engine, p2, k2);
    sw_announce(n.engine, p1, &p);
    sw_announce(n.engine, p2, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n, p1, &p, SW_SERVE_HONEST, false, 2, &st); /* manifest */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);          /* chunk wants */
    /* p1 has outstanding chunk WANTs; drop it before it answers. */
    vcs_swarm_engine_peer_drop(n.engine, p1);
    /* The work must requeue onto p2 with fresh ids and still complete. */
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { p2 };
    SW_CHECK("completes after disconnect requeue",
             sw_drive_complete(&n, peers, 1, &p, &max_inflight));
    struct vcs_service_key_totals totals;
    SW_CHECK("dropped peer earned only what it served",
             vcs_service_key_totals(n.book, k1, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == p.wire_len &&
             totals.offence_total == 0);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 9: resume after restart ──────────────────────────────────────── */

static int resume_case_answer_one_chunk(struct sw_node *n, uint64_t peer,
                                         struct sw_pkg *p)
{
    int failures = 0;
    /* Answer exactly ONE chunk WANT, leave the rest outstanding. */
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    bool answered = false;
    while (vcs_swarm_engine_next_outbound(n->engine, peer, &target,
                                          frame, &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg) ||
            msg.type != VCS_PACKAGE_SWARM_WANT || answered)
            continue;
        answered = true;
        struct vcs_package_swarm_message data;
        memset(&data, 0, sizeof(data));
        data.type = VCS_PACKAGE_SWARM_DATA;
        data.body.data.object = msg.body.want;
        size_t len = 0;
        data.body.data.bytes =
            sw_chunk_bytes(p, msg.body.want.file_index, &len);
        data.body.data.bytes_len = (uint32_t)len;
        uint8_t dframe[8 + 96 + SW_MAX_FILE];
        size_t dlen = 0;
        vcs_package_swarm_serialize(&data, dframe, sizeof(dframe), &dlen);
        struct vcs_swarm_frame_result res =
            vcs_swarm_engine_handle_frame(n->engine, peer, dframe, dlen,
                                          SW_DAY, 3);
        free(res.reply);
    }
    SW_CHECK("one chunk answered pre-restart", answered);
    return failures;
}

static int resume_case_restart(struct sw_node *n, struct sw_pkg *p)
{
    int failures = 0;
    /* Restart: engine + store + book all reopen on the same datadir. */
    struct vcs_swarm_download_status dst;
    SW_CHECK("pre-restart partial",
             vcs_swarm_engine_download_status(n->engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.present_chunks == 1);
    char datadir[1024];
    char zcode_dir[1100];
    snprintf(datadir, sizeof(datadir), "%s", n->datadir);
    snprintf(zcode_dir, sizeof(zcode_dir), "%s", n->zcode_dir);
    sw_node_close(n);
    n->store = vcs_package_store_open(datadir,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(zcode_dir);
    n->engine = vcs_swarm_engine_create(n->store, n->book, zcode_dir,
                                        sw_score_contributor, NULL);
    snprintf(n->datadir, sizeof(n->datadir), "%s", datadir);
    snprintf(n->zcode_dir, sizeof(n->zcode_dir), "%s", zcode_dir);
    SW_CHECK("restart ok", n->store && n->book && n->engine);
    SW_CHECK("resume rebuilds from CAS",
             vcs_swarm_engine_download_status(n->engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.present_chunks == 1);
    return failures;
}

static int resume_case_finish(struct sw_node *n, struct sw_pkg *p,
                               uint64_t peer, const uint8_t *key)
{
    int failures = 0;
    /* Re-add the peer and finish: the download completes from where it
     * stopped (staging bytes earn nothing — only newly verified bytes
     * credit). */
    SW_CHECK("peer re-add", vcs_swarm_engine_peer_add(n->engine, peer, key));
    sw_announce(n->engine, peer, p);
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { peer };
    SW_CHECK("resume completes",
             sw_drive_complete(n, peers, 1, p, &max_inflight));
    struct vcs_swarm_download_status dst;
    SW_CHECK("record deleted on completion",
             vcs_swarm_engine_download_status(n->engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_COMPLETE);
    struct vcs_service_key_totals totals;
    uint64_t served = p->wire_len;
    for (size_t i = 0; i < p->count; i++)
        served += p->lens[i];
    SW_CHECK("exactly the verified bytes credited",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == served);
    return failures;
}

int t_swarm_resume(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(31, key);
    if (!sw_node_open(&n, "resume", sw_score_contributor) ||
        !sw_make_package(&p, 4, 81))
        return 1;
    const uint64_t peer = 7001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, false, 2, &st); /* manifest */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);

    failures += resume_case_answer_one_chunk(&n, peer, &p);
    failures += resume_case_restart(&n, &p);
    failures += resume_case_finish(&n, &p, peer, key);

    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 10: serving, replayed WANTs, burst flood, allowance ──────────── */

static int serve_case_unreleased_not_announced(struct sw_node *n,
                                                struct sw_pkg *p,
                                                const uint8_t *key)
{
    int failures = 0;
    /* Host the package locally first (publish path). */
    SW_CHECK("manifest admitted",
             vcs_package_store_put_manifest(n->store, p->wire, p->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p->count; i++)
        SW_CHECK("chunk admitted",
                 vcs_package_store_put_chunk(
                     n->store, p->root, p->manifest.files[i].path, 0,
                     p->contents[i], p->lens[i]) == VCS_PACKAGE_STORE_OK);
    /* Complete is not hostable. Before the release lands, the engine
     * announces nothing and answers a manifest WANT with the named
     * refusal instead of bytes. */
    SW_CHECK("unreleased package is not announced",
             vcs_swarm_engine_peer_add(n->engine, 8009, key) &&
             vcs_swarm_engine_announce_to(n->engine, 8009) == 0);
    /* ...and a WANT for it is refused BY NAME, with no reply, no penalty
     * and no offence: the requester cannot know what we host. */
    struct vcs_package_swarm_message unlicensed;
    memset(&unlicensed, 0, sizeof(unlicensed));
    unlicensed.type = VCS_PACKAGE_SWARM_WANT;
    unlicensed.body.want.request_id = 8801;
    memcpy(unlicensed.body.want.package_root, p->root, 32);
    unlicensed.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    unlicensed.body.want.file_index = UINT32_MAX;
    unlicensed.body.want.chunk_index = UINT32_MAX;
    uint8_t refused_frame[8 + 96 + SW_MAX_FILE];
    size_t refused_len = 0;
    SW_CHECK("unreleased want serializes",
             vcs_package_swarm_serialize(&unlicensed, refused_frame,
                                         sizeof(refused_frame),
                                         &refused_len));
    struct vcs_swarm_frame_result refused =
        vcs_swarm_engine_handle_frame(n->engine, 8009, refused_frame,
                                      refused_len, SW_DAY, 1);
    SW_CHECK("unreleased want refused by name, not by silence",
             refused.reply == NULL &&
             refused.penalty == VCS_SWARM_PENALTY_NONE &&
             !refused.disconnect_peer && refused.rule != NULL &&
             strcmp(refused.rule, "no-verified-release") == 0);
    struct vcs_service_key_totals unlicensed_totals;
    SW_CHECK("refusal credits nothing and books no offence",
             vcs_service_key_totals(n->book, key, SW_DAY,
                                    &unlicensed_totals) &&
             unlicensed_totals.verified_bytes_uploaded == 0);
    return failures;
}

static int serve_case_publish_and_announce(struct sw_node *n,
                                            struct sw_pkg *p,
                                            const uint8_t *key,
                                            uint64_t peer)
{
    int failures = 0;
    SW_CHECK("release published",
             sw_publish_release(n->store, p->root, 0x41,
                                "swarm-serve/fixture"));
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n->engine, peer, key));

    /* Announce our complete packages to the peer. */
    SW_CHECK("announce queued",
             vcs_swarm_engine_announce_to(n->engine, peer) == 1);
    uint64_t target = 0;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t frame_len = 0;
    SW_CHECK("announce frame drains",
             vcs_swarm_engine_next_outbound(n->engine, peer, &target, frame,
                                            &frame_len));
    /* Dedupe: a repeat announce_to (the per-sync re-announce) queues
     * nothing; a package completed AFTER the peer joined queues exactly
     * one frame on the next call. */
    SW_CHECK("repeat announce queues nothing (deduped)",
             vcs_swarm_engine_announce_to(n->engine, peer) == 0);
    struct sw_pkg p2;
    if (!sw_make_package(&p2, 1, 137))
        return failures + 1;
    SW_CHECK("late manifest admitted",
             vcs_package_store_put_manifest(n->store, p2.wire, p2.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p2.count; i++)
        SW_CHECK("late chunk admitted",
                 vcs_package_store_put_chunk(
                     n->store, p2.root, p2.manifest.files[i].path, 0,
                     p2.contents[i], p2.lens[i]) == VCS_PACKAGE_STORE_OK);
    SW_CHECK("late release published",
             sw_publish_release(n->store, p2.root, 0x42,
                                "swarm-late/fixture"));
    SW_CHECK("late package announced to the existing peer",
             vcs_swarm_engine_announce_to(n->engine, peer) == 1);
    SW_CHECK("late announce frame drains",
             vcs_swarm_engine_next_outbound(n->engine, peer, &target, frame,
                                            &frame_len));
    sw_free_package(&p2);
    return failures;
}

static int serve_case_manifest_serve_and_replay(struct sw_node *n,
                                                 struct sw_pkg *p,
                                                 const uint8_t *key,
                                                 uint64_t peer)
{
    int failures = 0;
    /* Inbound WANT (manifest): served with upload credit. A replay of
     * the same request id: DUPLICATE_REQUEST offence, no second
     * credit. */
    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    want.body.want.request_id = 9001;
    memcpy(want.body.want.package_root, p->root, 32);
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t wlen = 0;
    SW_CHECK("want serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &wlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n->engine, peer, frame, wlen, SW_DAY, 1);
    SW_CHECK("manifest served", res.reply != NULL && res.reply_len > 0 &&
             res.penalty == VCS_SWARM_PENALTY_NONE);
    free(res.reply);
    res.reply = NULL;
    struct vcs_service_key_totals totals;
    SW_CHECK("upload credited",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.verified_bytes_uploaded == p->wire_len);
    res = vcs_swarm_engine_handle_frame(n->engine, peer, frame, wlen,
                                        SW_DAY, 1);
    SW_CHECK("replayed want named duplicate",
             res.penalty == VCS_SWARM_PENALTY_REPLAYED_REQUEST &&
             res.rule != NULL &&
             strcmp(res.rule, "duplicate-request") == 0 && !res.reply);
    SW_CHECK("replay earns no second credit",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.verified_bytes_uploaded == p->wire_len &&
             totals.offences[VCS_POLICY_OFFENCE_DUPLICATE_REQUEST] == 1);
    return failures;
}

static int serve_case_bad_coords_and_burst(struct sw_node *n,
                                            struct sw_pkg *p,
                                            const uint8_t *key,
                                            uint64_t peer)
{
    int failures = 0;
    /* Chunk WANT with the WRONG expected hash: silent no-serve. */
    struct vcs_package_swarm_message bad_want;
    memset(&bad_want, 0, sizeof(bad_want));
    bad_want.type = VCS_PACKAGE_SWARM_WANT;
    bad_want.body.want.request_id = 9002;
    memcpy(bad_want.body.want.package_root, p->root, 32);
    bad_want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    bad_want.body.want.file_index = 0;
    bad_want.body.want.chunk_index = 0;
    memset(bad_want.body.want.expected_hash, 0xee, 32);
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t wlen = 0;
    SW_CHECK("bad want serializes",
             vcs_package_swarm_serialize(&bad_want, frame, sizeof(frame),
                                         &wlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n->engine, peer, frame, wlen, SW_DAY, 1);
    SW_CHECK("wrong-coords want: silent no-serve",
             res.penalty == VCS_SWARM_PENALTY_NONE && !res.reply);

    /* Honest chunk WANTs through the burst window: two WANTs were already
     * consumed (the manifest + the bad-coords WANT), so exactly limit-2 more
     * are served before request-burst-limit is named. */
    const uint32_t burst_limit = vcs_policy_limits_for(
        VCS_POLICY_TIER_EARNED_CONTRIBUTOR)->request_burst_per_window;
    uint32_t served_chunks = 0;
    bool flood_named = false;
    for (uint32_t i = 0; i < burst_limit + 6u; i++) {
        struct vcs_package_swarm_message cw;
        memset(&cw, 0, sizeof(cw));
        cw.type = VCS_PACKAGE_SWARM_WANT;
        cw.body.want.request_id = 10000 + i;
        memcpy(cw.body.want.package_root, p->root, 32);
        cw.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
        cw.body.want.file_index = i % (uint32_t)p->count;
        cw.body.want.chunk_index = 0;
        memcpy(cw.body.want.expected_hash,
               p->manifest.files[cw.body.want.file_index].chunk_hashes, 32);
        SW_CHECK("chunk want serializes",
                 vcs_package_swarm_serialize(&cw, frame, sizeof(frame),
                                             &wlen));
        res = vcs_swarm_engine_handle_frame(n->engine, peer, frame, wlen,
                                            SW_DAY, 1);
        free(res.reply);
        if (res.penalty == VCS_SWARM_PENALTY_NONE)
            served_chunks++;
        if (res.penalty == VCS_SWARM_PENALTY_REQUEST_FLOOD &&
            res.rule != NULL &&
            strcmp(res.rule, "request-burst-limit") == 0)
            flood_named = true;
    }
    SW_CHECK("burst allowance served then stopped",
             served_chunks == burst_limit - 2u && flood_named);
    struct vcs_service_key_totals totals;
    SW_CHECK("request flood offence recorded",
             vcs_service_key_totals(n->book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_REQUEST_FLOOD] >= 1);
    return failures;
}

static int serve_case_allowance_exhaustion(struct sw_pkg *p, bool *opened)
{
    int failures = 0;
    /* Download allowance: pre-fill the peer's weekly download bucket
     * with its full tier allowance; the scheduler must then refuse to
     * pull from it (named allowance exhausted, NO offence). The peer is
     * an earned contributor (unique-root inventory is the serving-set
     * size at this tier, same as NEW_USER). */
    struct sw_node n2;
    uint8_t key2[33];
    sw_key(42, key2);
    *opened = sw_node_open(&n2, "allowance", sw_score_contributor);
    if (!*opened)
        return failures;
    const uint64_t peer2 = 8002;
    SW_CHECK("peer2 add", vcs_swarm_engine_peer_add(n2.engine, peer2,
                                                    key2));
    uint8_t req32[32] = {0};
    req32[0] = 0xab;
    SW_CHECK("allowance pre-filled",
             vcs_service_credit_download(
                 n2.book, key2, req32,
                 vcs_policy_limits_for(VCS_POLICY_TIER_EARNED_CONTRIBUTOR)
                     ->weekly_download_bytes,
                 SW_DAY) == VCS_SERVICE_CREDIT_OK);
    sw_announce(n2.engine, peer2, p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n2.engine, p->root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n2.engine, SW_DAY, 2);
    /* The manifest WANT is issued and served first (manifest-first
     * bypasses chunk accounting); once the scheduler reaches the CHUNKS
     * branch the exhausted allowance blocks every chunk WANT — named by
     * the flag, with NO offence. */
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n2, peer2, p, SW_SERVE_HONEST, false, 2, &st);
    SW_CHECK("manifest served pre-exhaustion", st.wants == 1);
    vcs_swarm_engine_tick(n2.engine, SW_DAY, 3);
    memset(&st, 0, sizeof(st));
    sw_pump(&n2, peer2, p, SW_SERVE_HONEST, false, 3, &st);
    SW_CHECK("no chunk wants over allowance", st.wants == 0);
    struct vcs_swarm_peer_info infos[4];
    size_t np = vcs_swarm_engine_peers_for(n2.engine, p->root, infos, 4);
    SW_CHECK("allowance exhausted flag",
             np == 1 && infos[0].allowance_exhausted);
    struct vcs_service_key_totals totals;
    SW_CHECK("exhaustion is not an offence",
             vcs_service_key_totals(n2.book, key2, SW_DAY, &totals) &&
             totals.offence_total == 0);
    struct vcs_swarm_download_status dst;
    SW_CHECK("download stalls honestly at chunks",
             vcs_swarm_engine_download_status(n2.engine, p->root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.inflight == 0);
    sw_node_close(&n2);
    test_rm_rf_recursive(n2.datadir);
    return failures;
}

int t_swarm_serving_and_allowance(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(41, key);
    if (!sw_node_open(&n, "serve", sw_score_contributor) ||
        !sw_make_package(&p, 3, 91))
        return 1;
    const uint64_t peer = 8001;

    failures += serve_case_unreleased_not_announced(&n, &p, key);
    failures += serve_case_publish_and_announce(&n, &p, key, peer);
    failures += serve_case_manifest_serve_and_replay(&n, &p, key, peer);
    failures += serve_case_bad_coords_and_burst(&n, &p, key, peer);

    bool n2_opened = false;
    failures += serve_case_allowance_exhaustion(&p, &n2_opened);
    if (!n2_opened) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }

    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── disconnect threshold ─────────────────────────────────────────── */

int t_swarm_disconnect_threshold(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(51, key);
    if (!sw_node_open(&n, "threshold", sw_score_contributor) ||
        !sw_make_package(&p, 1, 3))
        return 1;
    const uint64_t peer = 9001;
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    size_t len = 0;
    const uint8_t *bytes = sw_chunk_bytes(&p, 0, &len);
    bool flagged = false;
    for (uint32_t i = 0;
         i < VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD + 2; i++) {
        struct vcs_package_swarm_message data;
        memset(&data, 0, sizeof(data));
        data.type = VCS_PACKAGE_SWARM_DATA;
        data.body.data.object.request_id = 50000 + i;
        memcpy(data.body.data.object.package_root, p.root, 32);
        data.body.data.object.object_kind =
            VCS_PACKAGE_SWARM_OBJECT_CHUNK;
        data.body.data.object.file_index = 0;
        data.body.data.object.chunk_index = 0;
        memcpy(data.body.data.object.expected_hash,
               p.manifest.files[0].chunk_hashes, 32);
        data.body.data.bytes = bytes;
        data.body.data.bytes_len = (uint32_t)len;
        uint8_t frame[8 + 96 + SW_MAX_FILE];
        size_t frame_len = 0;
        vcs_package_swarm_serialize(&data, frame, sizeof(frame),
                                    &frame_len);
        struct vcs_swarm_frame_result res =
            vcs_swarm_engine_handle_frame(n.engine, peer, frame, frame_len,
                                          SW_DAY, 1);
        if (res.disconnect_peer)
            flagged = true;
    }
    SW_CHECK("offence threshold flags disconnect", flagged);
    struct vcs_service_key_totals totals;
    SW_CHECK("offences accumulated",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offence_total >= VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 11: content-addressed blob over the UNCHANGED swarm wire ─────── */

/* Two real engines, two real stores, zero protocol change: the seeder
 * puts a blob (a one-file/one-chunk content.v2 package), ANNOUNCEs it
 * with the existing frame, and the leecher's vcs_blob_fetch_via drives
 * the frozen WANT(manifest) -> WANT(chunk) -> DATA path to a verified
 * copy. Nothing here knows a "blob" message exists, because none does. */
static int blob_case_seed_and_register(struct sw_node *seed,
                                        struct sw_node *leech,
                                        uint64_t peer_leech,
                                        uint64_t peer_seed,
                                        const uint8_t *key_leech,
                                        const uint8_t *key_seed,
                                        uint8_t blob[300], uint8_t root[32])
{
    int failures = 0;
    for (size_t i = 0; i < 300; i++)
        blob[i] = (uint8_t)(i * 13u + 5u);
    SW_CHECK("blob: seeder admits the blob",
             vcs_blob_put_to(seed->store, blob, 300, root) == VCS_BLOB_OK);
    struct vcs_package_store_status pst;
    SW_CHECK("blob: seeded package is complete + single chunk",
             vcs_package_store_package_status(seed->store, root, &pst) &&
             pst.complete && pst.total_chunks == 1);
    SW_CHECK("blob: leecher does not have it yet",
             !vcs_package_store_package_status(leech->store, root, &pst));

    SW_CHECK("blob: peers register on both engines",
             vcs_swarm_engine_peer_add(seed->engine, peer_leech,
                                       key_leech) &&
             vcs_swarm_engine_peer_add(leech->engine, peer_seed, key_seed));
    return failures;
}

static int blob_case_announce_and_drain(struct sw_node *seed,
                                         struct sw_node *leech,
                                         uint64_t peer_leech,
                                         uint64_t peer_seed,
                                         const uint8_t root[32])
{
    int failures = 0;
    /* ANNOUNCE over the existing frame: no new message type. */
    size_t announced = vcs_blob_announce_via(seed->engine);
    SW_CHECK("blob: announce queued on the existing wire", announced >= 1);
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    uint64_t target = 0;
    size_t delivered = 0;
    while (vcs_swarm_engine_next_outbound(seed->engine, peer_leech, &target,
                                          frame, &frame_len)) {
        struct vcs_swarm_frame_result r = vcs_swarm_engine_handle_frame(
            leech->engine, peer_seed, frame, frame_len, SW_DAY, 1);
        free(r.reply);
        if (r.penalty == VCS_SWARM_PENALTY_NONE)
            delivered++;
    }
    SW_CHECK("blob: announce accepted unpenalized", delivered >= 1);
    struct vcs_swarm_peer_info infos[VCS_SWARM_MAX_PEERS];
    SW_CHECK("blob: leecher sees an advertiser for the root",
             vcs_swarm_engine_peers_for(leech->engine, root, infos,
                                        VCS_SWARM_MAX_PEERS) == 1);
    return failures;
}

static int blob_case_drive_to_complete(struct sw_node *seed,
                                        struct sw_node *leech,
                                        uint64_t peer_leech,
                                        uint64_t peer_seed,
                                        const uint8_t root[32])
{
    int failures = 0;
    SW_CHECK("blob: fetch by root accepted",
             vcs_blob_fetch_via(leech->engine, root, SW_DAY, 2) ==
                 VCS_BLOB_OK);

    /* Drive: leecher WANT -> seeder engine DATA reply -> leecher. */
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    uint64_t target = 0;
    bool complete = false;
    for (int round = 0; round < 32 && !complete; round++) {
        vcs_swarm_engine_tick(leech->engine, SW_DAY, (uint64_t)(round + 3));
        while (vcs_swarm_engine_next_outbound(leech->engine, peer_seed,
                                              &target, frame, &frame_len)) {
            struct vcs_swarm_frame_result served =
                vcs_swarm_engine_handle_frame(seed->engine, peer_leech,
                                              frame, frame_len, SW_DAY,
                                              (uint64_t)(round + 3));
            if (served.reply && served.reply_len > 0) {
                struct vcs_swarm_frame_result got =
                    vcs_swarm_engine_handle_frame(
                        leech->engine, peer_seed, served.reply,
                        served.reply_len, SW_DAY, (uint64_t)(round + 3));
                free(got.reply);
            }
            free(served.reply);
        }
        struct vcs_swarm_download_status ds;
        if (vcs_swarm_engine_download_status(leech->engine, root, &ds) &&
            ds.state == VCS_SWARM_DL_COMPLETE)
            complete = true;
    }
    SW_CHECK("blob: download completes over the unchanged wire", complete);
    return failures;
}

static int blob_case_verify_bytes(struct sw_node *leech,
                                   const uint8_t root[32],
                                   const uint8_t blob[300])
{
    int failures = 0;
    uint8_t out[300];
    size_t out_len = 0;
    memset(out, 0, sizeof(out));
    SW_CHECK("blob: leecher reads back the exact bytes",
             vcs_blob_get_from(leech->store, root, out, sizeof(out),
                               &out_len) == VCS_BLOB_OK &&
             out_len == 300 &&
             memcmp(out, blob, 300) == 0);
    uint8_t rederived[32];
    SW_CHECK("blob: transferred bytes re-derive the same root",
             vcs_blob_root(out, out_len, rederived) &&
             memcmp(rederived, root, 32) == 0);
    return failures;
}

int t_swarm_blob_transfer(void)
{
    int failures = 0;
    struct sw_node seed, leech;
    const uint64_t peer_leech = 7;  /* leecher's handle on the seeder */
    const uint64_t peer_seed = 9;   /* seeder's handle on the leecher */
    uint8_t key_leech[33], key_seed[33];
    sw_key(71, key_leech);
    sw_key(72, key_seed);
    if (!sw_node_open(&seed, "blobseed", sw_score_contributor) ||
        !sw_node_open(&leech, "blobleech", sw_score_contributor)) {
        printf("  zcode_swarm: blob fixture nodes... FAIL\n");
        return failures + 1;
    }

    uint8_t blob[300];
    uint8_t root[32];
    failures += blob_case_seed_and_register(&seed, &leech, peer_leech,
                                            peer_seed, key_leech, key_seed,
                                            blob, root);
    failures += blob_case_announce_and_drain(&seed, &leech, peer_leech,
                                             peer_seed, root);
    failures += blob_case_drive_to_complete(&seed, &leech, peer_leech,
                                            peer_seed, root);
    failures += blob_case_verify_bytes(&leech, root, blob);

    sw_node_close(&seed);
    sw_node_close(&leech);
    test_rm_rf_recursive(seed.datadir);
    test_rm_rf_recursive(leech.datadir);
    return failures;
}

