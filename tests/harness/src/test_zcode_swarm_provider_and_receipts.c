/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_swarm scenario checks: provider-directed downloads (no WANT to
 * an unauthenticated advertiser, restart-preserved restriction), the
 * bounded-provider/legacy-record/event-driven-schedule paths, dual-
 * signed receipt exchange and receipt session, and a DHT-recovered
 * provider evidence peer offer.
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

static int provider_case_empty_refusal(struct sw_node *n, struct sw_pkg *p)
{
    int failures = 0;
    struct vcs_zcode_dht_provider_route route = {
        .authenticated_count = 0,
        .reachability_pending = 2,
        .policy_denied = 3,
    };
    struct json_value route_json;
    json_init(&route_json);
    boot_zcode_dht_provider_route_test_render(
        &route_json, &route, VCS_SWARM_FETCH_NO_PROVIDER);
    SW_CHECK("provider: empty authenticated route is named fail-closed JSON",
             !json_get_bool_or(&route_json, "ok", true) &&
             strcmp(json_get_str(json_get(&route_json, "code")),
                    "FETCH_REFUSED") == 0 &&
             strcmp(json_get_str(json_get(&route_json, "fetch_result")),
                    "no-authenticated-provider") == 0 &&
             json_get_int(json_get(&route_json,
                                   "authenticated_providers")) == 0 &&
             json_get_int(json_get(&route_json,
                                   "reachability_pending")) == 2);
    json_free(&route_json);
    const uint64_t zero_peers[2] = {0, 0};
    SW_CHECK("provider: empty directed fetch is refused before registration",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 1,
                                         NULL, 0) ==
                 VCS_SWARM_FETCH_NO_PROVIDER);
    SW_CHECK("provider: zero-only bounded fetch has the same exact refusal",
             vcs_swarm_engine_fetch_from_bounded(
                 n->engine, p->root, SW_DAY, 1, zero_peers, 2, 4096) ==
                 VCS_SWARM_FETCH_NO_PROVIDER);
    struct vcs_swarm_download_status empty_status;
    SW_CHECK("provider: refusal creates no active or resumable download",
             vcs_swarm_engine_download_status(n->engine, p->root,
                                              &empty_status) &&
             empty_status.state == VCS_SWARM_DL_INACTIVE);
    vcs_swarm_engine_free(n->engine);
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    SW_CHECK("provider: refusal leaves no record to reload",
             n->engine != NULL &&
             vcs_swarm_engine_download_status(n->engine, p->root,
                                              &empty_status) &&
             empty_status.state == VCS_SWARM_DL_INACTIVE);
    return failures;
}

static int provider_case_exact_bind(struct sw_node *n, struct sw_pkg *p,
                                     uint64_t bad, uint64_t honest,
                                     const uint8_t *bad_key,
                                     const uint8_t *honest_key)
{
    int failures = 0;
    SW_CHECK("provider: both advertisers register",
             vcs_swarm_engine_peer_add(n->engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n->engine, honest, honest_key));
    sw_announce(n->engine, bad, p);
    SW_CHECK("provider: restricted fetch accepts an exact unannounced peer",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 1,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 2);
    struct vcs_package_swarm_object wants[2];
    SW_CHECK("provider: unlisted advertiser receives no WANT",
             sw_drain_wants(n, bad, wants, 2) == 0);
    SW_CHECK("provider: exact authenticated provider needs no broadcast ad",
             sw_drain_wants(n, honest, wants, 2) == 1);
    return failures;
}

static int provider_case_restart_resume(struct sw_node *n, struct sw_pkg *p,
                                         uint64_t bad, uint64_t honest,
                                         const uint8_t *bad_key,
                                         const uint8_t *honest_key)
{
    int failures = 0;
    vcs_swarm_engine_free(n->engine);
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    SW_CHECK("provider: restricted intent resumes", n->engine != NULL);
    SW_CHECK("provider: peers re-register",
             vcs_swarm_engine_peer_add(n->engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n->engine, honest, honest_key));
    sw_announce(n->engine, bad, p);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 3);
    struct vcs_package_swarm_object wants[2];
    SW_CHECK("provider: restart does not widen before fresh binding",
             sw_drain_wants(n, bad, wants, 2) == 0 &&
             sw_drain_wants(n, honest, wants, 2) == 0);
    SW_CHECK("provider: fresh authenticated binding resumes",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 4,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 4);
    SW_CHECK("provider: refreshed allowlist remains exclusive",
             sw_drain_wants(n, bad, wants, 2) == 0 &&
             sw_drain_wants(n, honest, wants, 2) == 1);
    return failures;
}

static int provider_case_cancel(struct sw_node *n, struct sw_pkg *p)
{
    int failures = 0;
    struct json_value cancel_input;
    json_init(&cancel_input);
    json_set_object(&cancel_input);
    char root_hex[65];
    zcl_hex_encode(p->root, 32, root_hex);
    json_push_kv_str(&cancel_input, "blob_root", root_hex);
    json_push_kv_str(&cancel_input, "datadir", n->datadir);
    json_push_kv_bool(&cancel_input, "cancel", true);
    json_push_kv_int(&cancel_input, "now_unix", 5);
    struct zcl_command_request cancel_request;
    memset(&cancel_request, 0, sizeof(cancel_request));
    cancel_request.input = &cancel_input;
    struct zcl_command_reply cancel_reply;
    zcl_command_reply_init(&cancel_reply, "zcl.zcode_science_fetch.v1");
    vcs_swarm_engine_set_global(n->engine);
    zcl_native_handle_zcode_science_fetch(&cancel_request, &cancel_reply);
    vcs_swarm_engine_set_global(NULL);
    SW_CHECK("provider: native restricted fetch cancel succeeds",
             json_get_bool_or(&cancel_reply.data, "canceled", false) &&
             !json_get_bool_or(&cancel_reply.data, "restriction_widened",
                               true));
    zcl_command_reply_free(&cancel_reply);
    json_free(&cancel_input);
    return failures;
}

static int provider_case_post_cancel_restart(struct sw_node *n,
                                              struct sw_pkg *p, uint64_t bad,
                                              uint64_t honest,
                                              const uint8_t *bad_key,
                                              const uint8_t *honest_key)
{
    int failures = 0;
    vcs_swarm_engine_free(n->engine);
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    SW_CHECK("provider: engine restarts after cancellation",
             n->engine != NULL);
    SW_CHECK("provider: canceled peers re-register",
             vcs_swarm_engine_peer_add(n->engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n->engine, honest, honest_key));
    sw_announce(n->engine, bad, p);
    sw_announce(n->engine, honest, p);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 6);
    struct vcs_package_swarm_object wants[2];
    struct vcs_swarm_download_status canceled_status;
    SW_CHECK("provider: canceled resumable state stays deleted on restart",
             vcs_swarm_engine_download_status(n->engine, p->root,
                                              &canceled_status) &&
             canceled_status.state == VCS_SWARM_DL_INACTIVE &&
             sw_drain_wants(n, bad, wants, 2) == 0 &&
             sw_drain_wants(n, honest, wants, 2) == 0);
    SW_CHECK("provider: explicit rebind after cancel remains restricted",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 7,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 7);
    SW_CHECK("provider: cancel never broadens the restarted fetch",
             sw_drain_wants(n, bad, wants, 2) == 0 &&
             sw_drain_wants(n, honest, wants, 2) == 1);
    return failures;
}

int t_swarm_provider_restricted(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t bad_key[33], honest_key[33];
    sw_key(91, bad_key);
    sw_key(92, honest_key);
    const uint64_t bad = 901, honest = 902;
    if (!sw_node_open(&n, "provider", sw_score_contributor) ||
        !sw_make_package(&p, 1, 29))
        return 1;

    failures += provider_case_empty_refusal(&n, &p);
    failures += provider_case_exact_bind(&n, &p, bad, honest, bad_key,
                                         honest_key);
    failures += provider_case_restart_resume(&n, &p, bad, honest, bad_key,
                                             honest_key);
    failures += provider_case_cancel(&n, &p);
    failures += provider_case_post_cancel_restart(&n, &p, bad, honest,
                                                  bad_key, honest_key);

    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

static int bound_case_ordinary_first(struct sw_node *n, struct sw_pkg *p,
                                      uint64_t peer, uint64_t bound)
{
    int failures = 0;
    SW_CHECK("provider bound: ordinary shared work starts",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 1,
                                         &peer, 1) == VCS_SWARM_FETCH_OK);
    SW_CHECK("provider bound: late scout cannot tighten shared work",
             vcs_swarm_engine_fetch_from_bounded(
                 n->engine, p->root, SW_DAY, 1, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_BOUND_NOT_OWNED);
    struct vcs_swarm_download_status status;
    SW_CHECK("provider bound: shared work remains unbounded and active",
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.state == VCS_SWARM_DL_WANT_MANIFEST &&
             status.maximum_package_bytes == 0);
    SW_CHECK("provider bound: ordinary work cancels cleanly",
             vcs_swarm_engine_cancel(n->engine, p->root, 1));
    return failures;
}

static int bound_case_start_and_restart(struct sw_node *n, struct sw_pkg *p,
                                         uint64_t peer, uint64_t bound)
{
    int failures = 0;
    struct vcs_swarm_download_status status;
    SW_CHECK("provider bound: bounded intent starts",
             vcs_swarm_engine_fetch_from_bounded(
                 n->engine, p->root, SW_DAY, 2, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_OK);
    SW_CHECK("provider bound: ceiling is visible before restart",
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == bound);
    vcs_swarm_engine_free(n->engine);
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    SW_CHECK("provider bound: engine restarts", n->engine != NULL);
    SW_CHECK("provider bound: ceiling survives restart",
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == bound);
    return failures;
}

static int bound_case_oversized_manifest_fails(struct sw_node *n,
                                                struct sw_pkg *p,
                                                uint64_t peer,
                                                const uint8_t *key,
                                                uint64_t bound)
{
    int failures = 0;
    SW_CHECK("provider bound: peer rebinds",
             vcs_swarm_engine_peer_add(n->engine, peer, key));
    sw_announce(n->engine, peer, p);
    SW_CHECK("provider bound: compatible bounded rebind accepted",
             vcs_swarm_engine_fetch_from_bounded(
                 n->engine, p->root, SW_DAY, 3, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n->engine, SW_DAY, 3);
    struct sw_pump_stats pump = {0};
    sw_pump(n, peer, p, SW_SERVE_HONEST, false, 3, &pump);
    struct vcs_swarm_download_status status;
    SW_CHECK("provider bound: oversized manifest fails before chunks",
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.state == VCS_SWARM_DL_FAILED && status.rule &&
             strcmp(status.rule, "maximum-package-bytes-exceeded") == 0 &&
             status.present_chunks == 0 && status.fetched_bytes == 0);
    struct vcs_package_store_status stored;
    SW_CHECK("provider bound: oversized manifest never enters package store",
             !vcs_package_store_package_status(n->store, p->root, &stored));
    return failures;
}

static int bound_case_lift_authority(struct sw_node *n, struct sw_pkg *p,
                                      uint64_t peer, uint64_t bound)
{
    int failures = 0;
    struct vcs_swarm_download_status status;
    SW_CHECK("provider bound: failed scout intent retries as ordinary work",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 4,
                                         &peer, 1) == VCS_SWARM_FETCH_OK &&
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == 0);

    /* Bound-lift authority: only unrestricted demand may lift a scout
     * ceiling. fetch_from carries no bound of its own, so before the
     * !restricted guard a restricted rebind silently un-bound — and
     * persisted — a live ceiling. */
    SW_CHECK("provider bound: operator cancel frees the ordinary slot",
             vcs_swarm_engine_cancel(n->engine, p->root, 1));
    SW_CHECK("provider bound: bounded scout re-arms on the freed slot",
             vcs_swarm_engine_fetch_from_bounded(
                 n->engine, p->root, SW_DAY, 5, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_OK &&
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.state == VCS_SWARM_DL_WANT_MANIFEST &&
             status.maximum_package_bytes == bound);
    SW_CHECK("provider bound: restricted rebind cannot lift the ceiling",
             vcs_swarm_engine_fetch_from(n->engine, p->root, SW_DAY, 5,
                                         &peer, 1) ==
                 VCS_SWARM_FETCH_OK &&
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == bound);
    vcs_swarm_engine_free(n->engine);
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    SW_CHECK("provider bound: engine restarts", n->engine != NULL);
    SW_CHECK("provider bound: refused lift left no widening on disk",
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == bound);
    SW_CHECK("provider bound: ordinary demand lifts the scout ceiling",
             vcs_swarm_engine_fetch(n->engine, p->root, SW_DAY, 6) ==
                 VCS_SWARM_FETCH_OK &&
             vcs_swarm_engine_download_status(n->engine, p->root, &status) &&
             status.maximum_package_bytes == 0);
    return failures;
}

int t_swarm_bounded_provider(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(93, key);
    const uint64_t peer = 903;
    const uint64_t bound = 1;
    if (!sw_node_open(&n, "provider_bound", sw_score_contributor) ||
        !sw_make_package(&p, 1, 30))
        return 1;
    SW_CHECK("provider bound: advertiser registers",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);

    failures += bound_case_ordinary_first(&n, &p, peer, bound);
    failures += bound_case_start_and_restart(&n, &p, peer, bound);
    failures += bound_case_oversized_manifest_fails(&n, &p, peer, key,
                                                    bound);
    failures += bound_case_lift_authority(&n, &p, peer, bound);

    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

int t_swarm_legacy_record(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(94, key);
    const uint64_t peer = 904;
    if (!sw_node_open(&n, "provider_v2", sw_score_contributor) ||
        !sw_make_package(&p, 1, 31))
        return 1;
    vcs_swarm_engine_free(n.engine);
    n.engine = NULL;
    char dir[4096], path[4096], root_hex[65];
    zcl_hex_encode(p.root, 32, root_hex);
    int dir_len = snprintf(dir, sizeof(dir), "%s/downloads", n.zcode_dir);
    int path_len = snprintf(path, sizeof(path), "%s/%s", dir, root_hex);
    SW_CHECK("provider v2: download directory path fits",
             dir_len > 0 && (size_t)dir_len < sizeof(dir) &&
             path_len > 0 && (size_t)path_len < sizeof(path));
    SW_CHECK("provider v2: download directory created",
             mkdir(dir, 0700) == 0);
    uint8_t wire[51] = {'Z', 'S', 'W', 'D', 'L', 'R', 0x0d, 0x0a};
    zcl_write_u16_le(wire + 8, 2);
    memcpy(wire + 10, p.root, 32);
    zcl_write_u64_le(wire + 42, (uint64_t)SW_DAY);
    wire[50] = 0;
    FILE *record = fopen(path, "wb");
    bool wrote = false;
    if (record) {
        wrote = fwrite(wire, 1, sizeof(wire), record) == sizeof(wire);
        if (fclose(record) != 0)
            wrote = false;
    }
    SW_CHECK("provider v2: legacy record fixture written", wrote);
    n.engine = vcs_swarm_engine_create(n.store, n.book, n.zcode_dir,
                                       sw_score_contributor, NULL);
    struct vcs_swarm_download_status status;
    SW_CHECK("provider v2: legacy intent resumes unbounded",
             n.engine && vcs_swarm_engine_download_status(
                             n.engine, p.root, &status) &&
             status.state == VCS_SWARM_DL_WANT_MANIFEST &&
             status.maximum_package_bytes == 0);
    SW_CHECK("provider v2: peer registers after migration",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 1);
    struct vcs_package_swarm_object wants[1];
    SW_CHECK("provider v2: legacy unbounded intent remains schedulable",
             sw_drain_wants(&n, peer, wants, 1) == 1);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

int t_swarm_event_driven_schedule(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(95, key);
    const uint64_t peer = 905;
    if (!sw_node_open(&n, "event_schedule", sw_score_contributor) ||
        !sw_make_package(&p, 4, 32))
        return 1;
    SW_CHECK("event schedule: peer registers",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("event schedule: fetch registers",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 7,
                                         &peer, 1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_schedule_ready(n.engine, SW_DAY, 7);
    struct vcs_package_swarm_object wants[SW_MAX_FILES];
    SW_CHECK("event schedule: manifest want needs no clock tick",
             sw_drain_wants(&n, peer, wants, SW_MAX_FILES) == 1 &&
             wants[0].object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST);
    struct vcs_swarm_frame_result res = sw_answer(
        &n, peer, &wants[0], p.wire, p.wire_len, UINT32_MAX);
    SW_CHECK("event schedule: manifest accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    free(res.reply);
    vcs_swarm_engine_schedule_ready(n.engine, SW_DAY, 7);
    size_t chunks = sw_drain_wants(&n, peer, wants, SW_MAX_FILES);
    bool all_chunks = chunks == p.count;
    for (size_t i = 0; i < chunks; i++)
        all_chunks = all_chunks &&
            wants[i].object_kind == VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    SW_CHECK("event schedule: chunk wants need no clock tick", all_chunks);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

struct receipt_exchange_ctx {
    struct sw_node *n;
    struct sw_pkg *p;
    uint64_t peer;
    secp256k1_context *ctx;
    uint8_t up_sec[32];
    uint8_t down_sec[32];
    uint8_t other_sec[32];
    uint8_t up_pub[33];
    uint8_t down_pub[33];
    uint8_t other_pub[33];
    struct vcs_swarm_transfer xfer;
    struct vcs_swarm_transfer leecher_xfer;
    struct vcs_service_receipt draft;
    struct vcs_service_receipt leecher_draft;
    uint8_t wire[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    struct vcs_service_book *leecher_book;
};

static int receipt_case_admit_and_serve(struct receipt_exchange_ctx *rc,
                                         const uint8_t *session_key)
{
    int failures = 0;
    struct sw_node *n = rc->n;
    struct sw_pkg *p = rc->p;
    SW_CHECK("receipt: manifest admitted",
             vcs_package_store_put_manifest(n->store, p->wire, p->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p->count; i++)
        SW_CHECK("receipt: chunk admitted",
                 vcs_package_store_put_chunk(
                     n->store, p->root, p->manifest.files[i].path, 0,
                     p->contents[i], p->lens[i]) == VCS_PACKAGE_STORE_OK);
    SW_CHECK("receipt: release published",
             sw_publish_release(n->store, p->root, 0x61,
                                "swarm-receipt/fx"));
    rc->peer = 9101;
    SW_CHECK("receipt: peer add",
             vcs_swarm_engine_peer_add(n->engine, rc->peer, session_key));

    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    want.body.want.request_id = 91001;
    memcpy(want.body.want.package_root, p->root, 32);
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t wlen = 0;
    SW_CHECK("receipt: want serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &wlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n->engine, rc->peer, frame, wlen, SW_DAY, 1);
    SW_CHECK("receipt: manifest served",
             res.reply != NULL && res.penalty == VCS_SWARM_PENALTY_NONE);
    free(res.reply);

    memset(&rc->xfer, 0, sizeof(rc->xfer));
    SW_CHECK("receipt: snapshot after serve",
             vcs_swarm_engine_transfer_snapshot(n->engine, rc->peer,
                                                &rc->xfer) &&
             memcmp(rc->xfer.package_root, p->root, 32) == 0 &&
             rc->xfer.served == p->wire_len && rc->xfer.fetched == 0);
    return failures;
}

static int receipt_case_keys(struct receipt_exchange_ctx *rc)
{
    int failures = 0;
    rc->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY);
    memset(rc->up_sec, 0, sizeof(rc->up_sec));
    memset(rc->down_sec, 0, sizeof(rc->down_sec));
    memset(rc->other_sec, 0, sizeof(rc->other_sec));
    rc->up_sec[31] = 0x81;
    rc->down_sec[31] = 0x82;
    rc->other_sec[31] = 0x83;
    secp256k1_pubkey parsed;
    size_t plen = 33;
    bool keys =
        secp256k1_ec_pubkey_create(rc->ctx, &parsed, rc->up_sec) == 1 &&
        secp256k1_ec_pubkey_serialize(rc->ctx, rc->up_pub, &plen, &parsed,
                                      SECP256K1_EC_COMPRESSED) == 1 &&
        secp256k1_ec_pubkey_create(rc->ctx, &parsed, rc->down_sec) == 1 &&
        secp256k1_ec_pubkey_serialize(rc->ctx, rc->down_pub, &plen, &parsed,
                                      SECP256K1_EC_COMPRESSED) == 1 &&
        secp256k1_ec_pubkey_create(rc->ctx, &parsed, rc->other_sec) == 1 &&
        secp256k1_ec_pubkey_serialize(rc->ctx, rc->other_pub, &plen, &parsed,
                                      SECP256K1_EC_COMPRESSED) == 1;
    SW_CHECK("receipt: secp keys", keys);
    return failures;
}

static int receipt_case_draft(struct receipt_exchange_ctx *rc)
{
    int failures = 0;
    struct sw_pkg *p = rc->p;
    enum vcs_service_receipt_role role = VCS_SERVICE_RECEIPT_DOWNLOADER;
    SW_CHECK("receipt: seeder drafts as uploader",
             vcs_swarm_receipt_draft(&rc->xfer, rc->up_pub, rc->down_pub,
                                     SW_DAY, SW_DAY, &rc->draft, &role) &&
             role == VCS_SERVICE_RECEIPT_UPLOADER &&
             rc->draft.verified_bytes == p->wire_len);
    rc->leecher_xfer = rc->xfer;
    rc->leecher_xfer.served = 0;
    rc->leecher_xfer.fetched = rc->xfer.served;
    enum vcs_service_receipt_role leecher_role =
        VCS_SERVICE_RECEIPT_UPLOADER;
    SW_CHECK("receipt: leecher drafts matching body",
             vcs_swarm_receipt_draft(&rc->leecher_xfer, rc->down_pub,
                                     rc->up_pub, SW_DAY, SW_DAY,
                                     &rc->leecher_draft, &leecher_role) &&
             leecher_role == VCS_SERVICE_RECEIPT_DOWNLOADER &&
             memcmp(rc->leecher_draft.session_nonce,
                    rc->draft.session_nonce, 32) == 0 &&
             memcmp(rc->leecher_draft.uploader_pubkey,
                    rc->draft.uploader_pubkey, 33) == 0);
    return failures;
}

static int receipt_case_sign_and_accept(struct receipt_exchange_ctx *rc)
{
    int failures = 0;
    struct sw_node *n = rc->n;
    SW_CHECK("receipt: both ends sign",
             vcs_service_receipt_sign(&rc->draft,
                                      VCS_SERVICE_RECEIPT_UPLOADER, rc->ctx,
                                      rc->up_sec) == VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_sign(&rc->draft,
                                      VCS_SERVICE_RECEIPT_DOWNLOADER,
                                      rc->ctx, rc->down_sec) ==
                 VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_serialize(&rc->draft, rc->wire,
                                           sizeof(rc->wire)) ==
                 VCS_SERVICE_RECEIPT_OK);

    char leecher_dir[1200];
    snprintf(leecher_dir, sizeof(leecher_dir), "%s/leecher-zcode",
             n->datadir);
    rc->leecher_book = vcs_service_book_load(leecher_dir);
    SW_CHECK("receipt: leecher book", rc->leecher_book != NULL);
    SW_CHECK("receipt: seeder accepts matching serve",
             vcs_swarm_receipt_accept(n->book, &rc->xfer, rc->up_pub,
                                      SW_DAY, rc->wire,
                                      sizeof(rc->wire)) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("receipt: leecher accepts matching fetch",
             rc->leecher_book &&
             vcs_swarm_receipt_accept(rc->leecher_book, &rc->leecher_xfer,
                                      rc->down_pub, SW_DAY, rc->wire,
                                      sizeof(rc->wire)) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("receipt: replay is duplicate",
             vcs_swarm_receipt_accept(n->book, &rc->xfer, rc->up_pub,
                                      SW_DAY, rc->wire,
                                      sizeof(rc->wire)) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    SW_CHECK("receipt: stranger refused",
             vcs_swarm_receipt_accept(n->book, &rc->xfer, rc->other_pub,
                                      SW_DAY, rc->wire,
                                      sizeof(rc->wire)) ==
                 VCS_SWARM_RECEIPT_NOT_PARTY);
    struct vcs_swarm_transfer lied = rc->xfer;
    lied.served = 1;
    SW_CHECK("receipt: inflated bytes refused",
             vcs_swarm_receipt_accept(n->book, &lied, rc->up_pub, SW_DAY,
                                      rc->wire, sizeof(rc->wire)) ==
                 VCS_SWARM_RECEIPT_BYTES_MISMATCH);
    SW_CHECK("receipt: named statuses",
             strcmp(vcs_swarm_receipt_status_string(
                        VCS_SWARM_RECEIPT_BYTES_MISMATCH),
                    "bytes-mismatch") == 0);
    return failures;
}

int t_swarm_receipt_exchange(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t session_key[33];
    sw_key(61, session_key);
    if (!sw_node_open(&n, "receipt", sw_score_contributor) ||
        !sw_make_package(&p, 2, 101))
        return 1;

    struct receipt_exchange_ctx rc;
    memset(&rc, 0, sizeof(rc));
    rc.n = &n;
    rc.p = &p;

    failures += receipt_case_admit_and_serve(&rc, session_key);
    failures += receipt_case_keys(&rc);
    failures += receipt_case_draft(&rc);
    failures += receipt_case_sign_and_accept(&rc);

    if (rc.leecher_book)
        vcs_service_book_free(rc.leecher_book);
    secp256k1_context_destroy(rc.ctx);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

static bool sw_secp_pair(secp256k1_context *ctx, uint8_t last,
                         uint8_t sec[32], uint8_t pub[33])
{
    memset(sec, 0, 32);
    sec[31] = last;
    secp256k1_pubkey parsed;
    size_t plen = 33;
    return secp256k1_ec_pubkey_create(ctx, &parsed, sec) == 1 &&
           secp256k1_ec_pubkey_serialize(ctx, pub, &plen, &parsed,
                                         SECP256K1_EC_COMPRESSED) == 1;
}

struct receipt_session_ctx {
    secp256k1_context *ctx;
    uint8_t up_sec[32], down_sec[32], other_sec[32];
    uint8_t up_pub[33], down_pub[33], other_pub[33];
    struct vcs_swarm_receipt_session *up;
    struct vcs_swarm_receipt_session *down;
    struct vcs_swarm_receipt_session *stranger;
    uint64_t peer;
    struct vcs_swarm_transfer seed_x, leech_x;
    uint8_t offer[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    uint8_t *reply;
    size_t reply_len;
};

static int session_case_setup_keys_and_identity(struct receipt_session_ctx *rc)
{
    int failures = 0;
    rc->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY);
    SW_CHECK("session: secp keys",
             rc->ctx && sw_secp_pair(rc->ctx, 0x91, rc->up_sec, rc->up_pub) &&
             sw_secp_pair(rc->ctx, 0x92, rc->down_sec, rc->down_pub) &&
             sw_secp_pair(rc->ctx, 0x93, rc->other_sec, rc->other_pub) &&
             memcmp(rc->up_pub, rc->other_pub, 33) != 0);
    rc->up = vcs_swarm_receipt_session_open_secret(rc->up_sec);
    rc->down = vcs_swarm_receipt_session_open_secret(rc->down_sec);
    rc->stranger = vcs_swarm_receipt_session_open_secret(rc->other_sec);
    uint8_t got[33];
    SW_CHECK("session: open secrets",
             rc->up && rc->down && rc->stranger &&
             vcs_swarm_receipt_session_local_pub(rc->up, got) &&
             memcmp(got, rc->up_pub, 33) == 0 &&
             vcs_swarm_receipt_session_local_pub(rc->down, got) &&
             memcmp(got, rc->down_pub, 33) == 0);

    uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
    size_t ilen = 0;
    rc->peer = 77;
    SW_CHECK("session: seeder identity once",
             vcs_swarm_receipt_identity_take(rc->up, rc->peer, ident,
                                             sizeof(ident), &ilen) &&
             ilen == VCS_SWARM_RECEIPT_IDENTITY_BYTES);
    SW_CHECK("session: seeder identity not resent",
             !vcs_swarm_receipt_identity_take(rc->up, rc->peer, ident,
                                              sizeof(ident), &ilen));
    SW_CHECK("session: leecher notes seeder",
             vcs_swarm_receipt_identity_note(rc->down, rc->peer, ident,
                                             ilen));
    SW_CHECK("session: leecher identity",
             vcs_swarm_receipt_identity_take(rc->down, rc->peer, ident,
                                             sizeof(ident), &ilen));
    SW_CHECK("session: seeder notes leecher",
             vcs_swarm_receipt_identity_note(rc->up, rc->peer, ident, ilen));
    return failures;
}

static int session_case_offer_and_complete(struct receipt_session_ctx *rc,
                                            struct sw_node *seeder,
                                            struct sw_node *leecher)
{
    int failures = 0;
    memset(&rc->seed_x, 0, sizeof(rc->seed_x));
    memset(&rc->leech_x, 0, sizeof(rc->leech_x));
    memset(rc->seed_x.package_root, 0x44, 32);
    memcpy(rc->leech_x.package_root, rc->seed_x.package_root, 32);
    rc->seed_x.served = 4096;
    rc->leech_x.fetched = 4096;

    SW_CHECK("session: seeder offers",
             vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                             SW_DAY, rc->offer));
    SW_CHECK("session: second identical offer withheld",
             !vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                              SW_DAY, rc->offer));
    rc->reply = NULL;
    rc->reply_len = 0;
    SW_CHECK("session: leecher completes",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &rc->leech_x, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), &rc->reply, &rc->reply_len) ==
                 VCS_SWARM_RECEIPT_OK &&
             rc->reply && rc->reply_len == VCS_SERVICE_RECEIPT_WIRE_BYTES);
    SW_CHECK("session: seeder accepts completed",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("session: both settled",
             vcs_swarm_receipt_session_settled(rc->up, rc->peer) &&
             vcs_swarm_receipt_session_settled(rc->down, rc->peer));
    return failures;
}

static int session_case_replay_and_refusals(struct receipt_session_ctx *rc,
                                             struct sw_node *seeder,
                                             struct sw_node *leecher)
{
    int failures = 0;
    SW_CHECK("session: replay is duplicate",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    struct vcs_swarm_transfer grown = rc->leech_x;
    grown.fetched = rc->leech_x.fetched + 1;
    SW_CHECK("session: superseded offer is stale",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &grown, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), NULL, NULL) ==
                 VCS_SWARM_RECEIPT_STALE);
    SW_CHECK("session: stranger refused",
             vcs_swarm_receipt_session_handle(
                 rc->stranger, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_NOT_PARTY);
    uint8_t tamper[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    memcpy(tamper, rc->offer, sizeof(tamper));
    tamper[40] ^= 0xff;
    enum vcs_swarm_receipt_status tst = vcs_swarm_receipt_session_handle(
        rc->down, leecher->book, &rc->leech_x, 78, SW_DAY, tamper,
        sizeof(tamper), NULL, NULL);
    SW_CHECK("session: tampered offer refused",
             tst == VCS_SWARM_RECEIPT_UNVERIFIED ||
             tst == VCS_SWARM_RECEIPT_NOT_PARTY);
    free(rc->reply);
    return failures;
}

static int session_case_persist(struct sw_node *seeder)
{
    int failures = 0;
    struct vcs_swarm_receipt_session *persisted =
        vcs_swarm_receipt_session_open(seeder->zcode_dir);
    uint8_t pub_a[33], pub_b[33];
    SW_CHECK("session: persist open",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_a));
    vcs_swarm_receipt_session_free(persisted);
    persisted = vcs_swarm_receipt_session_open(seeder->zcode_dir);
    SW_CHECK("session: persist reload",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_b) &&
             memcmp(pub_a, pub_b, 33) == 0);
    vcs_swarm_receipt_session_free(persisted);
    return failures;
}

int t_swarm_receipt_session(void)
{
    int failures = 0;
    struct sw_node seeder, leecher;
    if (!sw_node_open(&seeder, "rcpt-s", sw_score_contributor) ||
        !sw_node_open(&leecher, "rcpt-l", sw_score_contributor))
        return 1;

    struct receipt_session_ctx rc;
    memset(&rc, 0, sizeof(rc));

    failures += session_case_setup_keys_and_identity(&rc);
    failures += session_case_offer_and_complete(&rc, &seeder, &leecher);
    failures += session_case_replay_and_refusals(&rc, &seeder, &leecher);
    failures += session_case_persist(&seeder);

    vcs_swarm_receipt_session_free(rc.up);
    vcs_swarm_receipt_session_free(rc.down);
    vcs_swarm_receipt_session_free(rc.stranger);
    if (rc.ctx)
        secp256k1_context_destroy(rc.ctx);
    sw_node_close(&seeder);
    sw_node_close(&leecher);
    test_rm_rf_recursive(seeder.datadir);
    test_rm_rf_recursive(leecher.datadir);
    return failures;
}

/* DHT-recovered provider evidence applied as a peer offer — the seam the
 * automatic discovery fallback will use. Pins: refusal for unknown peers,
 * zero-advertiser stall broken by exactly one scheduled WANT, idempotent
 * re-offer consuming no inventory, and the bounded ad table refusing (not
 * overflowing) when full. */
int t_swarm_peer_offer(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(77, key);
    if (!sw_node_open(&n, "offer", sw_score_contributor) ||
        !sw_make_package(&p, 2, 91))
        return 1;
    const uint64_t pid = 7701;
    const uint64_t evidence_expiry = 50;

    SW_CHECK("unknown peer refused",
             !vcs_swarm_engine_peer_offer(n.engine, pid, p.root,
                                          evidence_expiry, 1));
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, pid, key));

    /* No announce anywhere: with zero advertisers nothing may queue. */
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct vcs_package_swarm_object quiet[2];
    SW_CHECK("stalled before evidence",
             sw_drain_wants(&n, pid, quiet, 2) == 0);

    /* The discovery fallback's work list names exactly this root while
     * nothing advertises it. */
    uint8_t stalled[4][32];
    SW_CHECK("stall work list names the root",
             vcs_swarm_engine_unadvertised_roots(n.engine, stalled, 4) == 1 &&
             memcmp(stalled[0], p.root, 32) == 0);

    /* Locally verified DHT-style evidence becomes an offer; the event
     * edge wakes scheduling and the manifest WANT goes to this peer. */
    SW_CHECK("offer accepted",
             vcs_swarm_engine_peer_offer(n.engine, pid, p.root,
                                         evidence_expiry, 3));
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);
    struct vcs_package_swarm_object wants[2];
    SW_CHECK("want after offer", sw_drain_wants(&n, pid, wants, 2) == 1);

    /* Advertised again: the root leaves the work list. */
    SW_CHECK("work list drains once advertised",
             vcs_swarm_engine_unadvertised_roots(n.engine, stalled, 4) == 0);

    /* Idempotent: still true, consumes no further ad inventory. */
    SW_CHECK("idempotent offer",
             vcs_swarm_engine_peer_offer(n.engine, pid, p.root,
                                         evidence_expiry, 4));

    /* The signed window is scheduler authority, not descriptive metadata.
     * At expiry the peer stops advertising and the unfinished download
     * returns to the discovery work list. */
    vcs_swarm_engine_tick(n.engine, SW_DAY, evidence_expiry);
    SW_CHECK("expired evidence unscheduled",
             vcs_swarm_engine_unadvertised_roots(n.engine, stalled, 4) == 1 &&
             memcmp(stalled[0], p.root, 32) == 0);
    SW_CHECK("already-expired evidence refused",
             !vcs_swarm_engine_peer_offer(n.engine, pid, p.root,
                                          evidence_expiry, evidence_expiry));
    SW_CHECK("renewed evidence accepted",
             vcs_swarm_engine_peer_offer(n.engine, pid, p.root, 100, 51));

    /* Distinct roots fill the remaining slots exactly; the next one is
     * refused by name instead of writing past ads[]. */
    uint8_t junk[32];
    memcpy(junk, p.root, 32);
    unsigned filled = 0;
    while (filled < VCS_SWARM_MAX_PEER_ADS + 4) {
        junk[31] = (uint8_t)(0x40 + filled);
        junk[15] = (uint8_t)(filled << 2);
        if (!vcs_swarm_engine_peer_offer(n.engine, pid, junk, 100, 51))
            break;
        filled++;
    }
    SW_CHECK("fill bounded at capacity minus held root",
             filled == VCS_SWARM_MAX_PEER_ADS - 1);
    return failures;
}

