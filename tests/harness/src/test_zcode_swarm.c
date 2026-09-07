/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_swarm — the slice-12 swarm engine gate
 * (contexts/commons/modules/vcs/package_swarm_node.*), adversarial first:
 *
 *   1. Malicious peer serving WRONG-HASH chunks: named INVALID_DATA,
 *      INVALID_CHUNK offence in the service book, no credit, and the
 *      chunk never reaches the CAS (verify-before-store); a wrong
 *      manifest is refused the same way (UNVERIFIED no-credit).
 *   2. Wrong chunk coordinates (valid request id, wrong file/chunk
 *      index): named invalid, no credit, nothing stored.
 *   3. Unrequested DATA (unknown request id / unknown root): named
 *      UNREQUESTED_DATA, UNREQUESTED_BYTES offence, no credit; the
 *      offence-count disconnect threshold flips disconnect_peer.
 *   4. Duplicate response replay (DATA twice for one fulfilled id):
 *      the first copy earns, the replay is a DUPLICATE_REQUEST offence
 *      with no credit. Late DATA for a CANCELLED id is the honest race:
 *      no credit, NO offence — and peer_drop tombstones a disconnected
 *      peer's wants the same way, so its straggler after reconnect is
 *      also the honest race.
 *   5. Announce-only peers earn nothing (no-credit ANNOUNCEMENT on every
 *      announce); keep-alive repeats of a root already advertised do not
 *      consume the unique-root inventory bound; a new-user (zero-score)
 *      peer gets VCS_POLICY_FREE_ANNOUNCE_PER_HOUR distinct roots per
 *      hour and the next distinct root is ANNOUNCE_FLOOD naming
 *      announce-rate-limit.
 *   6. Scheduler shape: manifest-first; rarest-first across downloads
 *      (fewest advertisers first); per-peer in-flight bound honored;
 *      multi-peer spread; end-to-end verified completion into the CAS.
 *   7. Timeout → retry with a FRESH request id, bounded attempts →
 *      named manifest-attempts-exhausted failure.
 *   8. Cancel: CANCEL frames queued; disconnect requeue moves in-flight
 *      work to surviving peers with fresh ids.
 *   9. Resume: restart mid-download rebuilds the have-bitmap from CAS
 *      presence (staging bytes earn nothing) and completes; the record
 *      file is deleted on completion.
 *  10. Serving: inbound WANTs are answered from the store with upload
 *      credit per request id; a replayed WANT id is a DUPLICATE_REQUEST
 *      offence with no second credit; over-burst WANTs name
 *      request-burst-limit (REQUEST_FLOOD); the per-tier weekly
 *      download allowance (free allowance honored) throttles our own
 *      pulling without offence.
 *  11. Blob transfer (vcs/blob_store.h) with ZERO protocol change: a
 *      one-file/one-chunk content.v2 package announces, is wanted, and
 *      transfers between two real engines over the frozen 'zpkgswm'
 *      codec, and the received bytes re-derive the same root.
 *  12. Provider-directed downloads issue no WANT to an unauthenticated
 *      advertiser; restart preserves the restriction with an empty transient
 *      allowlist until fresh authenticated peer handles are supplied.
 *  13. An ordinary C23 library shelf (independent in-tree packages, not
 *      the Arena set) is prepared, stored, and imported; announce_to
 *      queues those complete public-serveable roots up to
 *      VCS_SWARM_MAX_LOCAL_ANNOUNCES; a repeat is already-announced
 *      keep-alive; a NEW_USER learns that many unique roots without
 *      ANNOUNCE_FLOOD. The 65th distinct root still floods in
 *      t_swarm_announce_policy.
 *
 * Every engine runs over a real store + real service book on ./test-tmp
 * datadirs; peers are driven through vcs_swarm_engine_handle_frame with
 * hand-built codec frames. */

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


bool sw_make_package(struct sw_pkg *p, size_t count, uint8_t seed)
{
    static const char *const k_paths[SW_MAX_FILES] = {
        "LICENSE", "examples/ex.c", "include/a.h", "include/b.h",
        "include/c.h", "include/d.h", "src/a.c", "src/b.c", "src/c.c",
        "src/d.c", "tests/t1.c", "tests/t2.c",
    };
    memset(p, 0, sizeof(*p));
    if (count == 0 || count > SW_MAX_FILES)
        return false;
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < count; i++) {
        size_t len;
        if (strcmp(k_paths[i], "LICENSE") == 0) {
            /* Real MIT text: the hosting rule reads these bytes and holds
             * them against the envelope's SPDX identifier, so a fixture
             * that shipped noise here would be refused — correctly. */
            len = strlen(TEST_LICENSE_TEXT_MIT);
            if (len > SW_MAX_FILE)
                return false;
            memcpy(p->contents[i], TEST_LICENSE_TEXT_MIT, len);
        } else {
            len = 40u + i * 31u + seed;
            for (size_t j = 0; j < len; j++)
                p->contents[i][j] = (uint8_t)(seed + i * 7u + j * 3u);
        }
        p->lens[i] = len;
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(p->contents[i], len, hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, k_paths[i],
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1))
            return false;
    }
    p->count = count;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    return vcs_package_manifest_root(&p->manifest, p->root);
}

void sw_free_package(struct sw_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* The file index of manifest path position i (manifest is path-sorted;
 * the fixture inserts in sorted order, so i IS the file index). Chunk
 * bytes for (file_index, chunk_index=0). */
const uint8_t *sw_chunk_bytes(const struct sw_pkg *p,
                                     uint32_t file_index, size_t *len)
{
    *len = p->lens[file_index];
    return p->contents[file_index];
}

/* ── public-hosting fixture: the release that makes a package hostable ──
 *
 * The engine refuses to announce or serve a root that is not a recognized
 * public shape (vcs/package_public_shape.h). sw_make_package builds the
 * released-package shape — a top-level LICENSE plus sources — so the one
 * thing these fixtures still need is the signed envelope that names the
 * exact root and carries an allowlisted SPDX identifier. Every serving
 * fixture below publishes one; the tests that prove REFUSAL deliberately
 * do not. */
bool sw_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

bool sw_reward_address(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    return encode_destination(&dest, pk, pk_len, sc, sc_len, out, out_size);
}

/* Sign a release naming `root` and persist it. `seed` picks the publisher
 * key: one key may name only one package root per sequence, so distinct
 * fixture packages need distinct seeds. */
bool sw_publish_release(struct vcs_package_store *store,
                               const uint8_t root[32], uint8_t seed,
                               const char *name)
{
    struct privkey sk;
    struct pubkey pk;
    struct vcs_package_release r;
    memset(&r, 0, sizeof(r));
    if (!sw_keypair(seed, &sk, &pk))
        return false;
    r.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r.name, sizeof(r.name), "%s", name);
    snprintf(r.semver, sizeof(r.semver), "1.0.0");
    memcpy(r.package_root, root, 32);
    for (int i = 0; i < 32; i++)
        r.recipe_root[i] = (uint8_t)(0x50 + i);
    memcpy(r.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r.publisher_sequence = 1u;
    if (!sw_reward_address(r.reward_address, sizeof(r.reward_address)))
        return false;
    snprintf(r.license, sizeof(r.license), "MIT");
    if (!vcs_package_accept_chain_id(r.chain_id, sizeof(r.chain_id)))
        return false;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(r.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    return vcs_package_store_put_release(store, &r, &ar) ==
               VCS_PACKAGE_STORE_OK &&
           (ar == VCS_PACKAGE_ACCEPT_OK || ar == VCS_PACKAGE_ACCEPT_DUPLICATE);
}

/* ── fixture node: store + book + engine over one datadir ─────────── */


uint64_t sw_score_contributor(const uint8_t contributor[33],
                                     void *ctx)
{
    (void)contributor;
    (void)ctx;
    return SW_CONTRIBUTOR_SCORE;
}

/* This suite opens ~25 real store+book datadirs (one or two per subtest,
 * see the file banner). Each open/close round-trips through real
 * durable-write barriers (package_store's process lock file, the service
 * book's save path); on a journaled disk shared with concurrent lanes
 * those fsyncs can queue behind someone else's journal commit. The engine
 * logic under test never inspects *where* the datadir lives, only that
 * writes there are real and durable, so route it through tmpfs (/dev/shm)
 * where available — same file semantics, no journal to queue behind —
 * and fall back to the shared ./test-tmp path (test_make_tmpdir) where
 * /dev/shm doesn't exist (e.g. macOS). */
#if !defined(_WIN32)
static const char *sw_test_tmp_root(void)
{
    static int cached = -1; /* -1 unknown, 0 = shared test-tmp, 1 = shm */
    if (cached < 0)
        cached = (access("/dev/shm", W_OK) == 0) ? 1 : 0;
    return cached ? "/dev/shm/zcode_swarm-test-tmp" : NULL;
}
#endif

void sw_make_tmpdir(char *buf, size_t n, const char *tag)
{
#if !defined(_WIN32)
    const char *root = sw_test_tmp_root();
    if (root) {
        int wrote = snprintf(buf, n, "%s_%d_%s", root, (int)getpid(), tag);
        if (wrote > 0 && (size_t)wrote < n) {
            test_rm_rf_recursive(buf);
            (void)mkdir(buf, 0700);
            return;
        }
    }
#endif
    test_make_tmpdir(buf, n, "zcode_swarm", tag);
}

bool sw_node_open(struct sw_node *n, const char *tag,
                         vcs_swarm_score_fn score_fn)
{
    sw_make_tmpdir(n->datadir, sizeof(n->datadir), tag);
    snprintf(n->zcode_dir, sizeof(n->zcode_dir), "%s/zcode", n->datadir);
    n->store = vcs_package_store_open(
        n->datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(n->zcode_dir);
    if (!n->store || !n->book)
        return false;
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        score_fn, NULL);
    return n->engine != NULL;
}

void sw_node_close(struct sw_node *n)
{
    vcs_swarm_engine_free(n->engine);
    vcs_service_book_free(n->book);
    vcs_package_store_close(n->store);
    n->engine = NULL;
    n->book = NULL;
    n->store = NULL;
}

void sw_key(uint8_t seed, uint8_t out[33])
{
    memset(out, 0, 33);
    out[0] = 0x02;
    out[32] = seed;
    out[1] = (uint8_t)(seed ^ 0x5a);
}

/* ── frame builders ─────────────────────────────────────────────────── */

size_t sw_announce_frame(const struct sw_pkg *p, uint8_t *out)
{
    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    memcpy(msg.body.announce.package_root, p->root, 32);
    msg.body.announce.manifest_bytes = (uint32_t)p->wire_len;
    msg.body.announce.file_count = (uint32_t)p->count;
    uint64_t total = 0;
    for (size_t i = 0; i < p->count; i++)
        total += p->lens[i];
    msg.body.announce.total_bytes = total;
    msg.body.announce.total_chunks = (uint32_t)p->count;
    size_t len = 0;
    if (!vcs_package_swarm_serialize(&msg, out, 128, &len))
        return 0;
    return len;
}

void sw_announce(struct vcs_swarm_engine *e, uint64_t peer,
                        const struct sw_pkg *p)
{
    uint8_t frame[128];
    size_t len = sw_announce_frame(p, frame);
    vcs_swarm_engine_handle_frame(e, peer, frame, len, SW_DAY, 1);
}



/* Drain every outbound frame for `peer`; answer WANTs with DATA per
 * `mode` fed straight back into handle_frame. duplicate_last: after an
 * honest DATA, immediately replay the same frame a second time. The
 * per-peer in-flight peak is sampled AFTER draining (every issued WANT
 * still outstanding) and BEFORE answering. */
static void sw_pump_drain_outbound(struct sw_node *n, uint64_t peer,
                                   struct vcs_package_swarm_message
                                       wants[SWARM_PUMP_MAX_WANTS],
                                   size_t *want_count,
                                   struct sw_pump_stats *st)
{
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    while (vcs_swarm_engine_next_outbound(n->engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg)) {
            st->last.penalty = VCS_SWARM_PENALTY_MALFORMED;
            continue;
        }
        if (msg.type == VCS_PACKAGE_SWARM_ANNOUNCE) {
            st->announces++;
            continue;
        }
        if (msg.type == VCS_PACKAGE_SWARM_CANCEL) {
            st->cancels++;
            continue;
        }
        if (msg.type != VCS_PACKAGE_SWARM_WANT || *want_count >=
                SWARM_PUMP_MAX_WANTS)
            continue;
        wants[(*want_count)++] = msg;
        st->wants++;
    }
}

static void sw_pump_track_inflight(struct sw_node *n, uint64_t peer,
                                   const struct sw_pkg *p,
                                   struct sw_pump_stats *st)
{
    struct vcs_swarm_peer_info infos[VCS_SWARM_MAX_PEERS];
    size_t np = vcs_swarm_engine_peers_for(n->engine, p->root, infos,
                                           VCS_SWARM_MAX_PEERS);
    for (size_t i = 0; i < np; i++)
        if (infos[i].peer == peer && infos[i].inflight > st->max_inflight)
            st->max_inflight = infos[i].inflight;
}

static void sw_pump_serve_wants(
    struct sw_node *n, uint64_t peer, const struct sw_pkg *p,
    enum sw_serve_mode mode, bool duplicate_last, uint64_t now,
    const struct vcs_package_swarm_message *wants, size_t want_count,
    struct sw_pump_stats *st)
{
    for (size_t w = 0; w < want_count; w++) {
        struct vcs_package_swarm_message data;
        memset(&data, 0, sizeof(data));
        data.type = VCS_PACKAGE_SWARM_DATA;
        data.body.data.object = wants[w].body.want;
        uint8_t wrong[SW_MAX_FILE];
        if (wants[w].body.want.object_kind ==
            VCS_PACKAGE_SWARM_OBJECT_MANIFEST) {
            data.body.data.bytes = p->wire;
            data.body.data.bytes_len = (uint32_t)p->wire_len;
        } else {
            uint32_t fi = wants[w].body.want.file_index;
            if (mode == SW_SERVE_WRONG_COORDS && p->count > 1)
                fi = (fi + 1u) % (uint32_t)p->count;
            size_t len = 0;
            const uint8_t *bytes = sw_chunk_bytes(p, fi, &len);
            if (mode == SW_SERVE_WRONG_HASH) {
                memcpy(wrong, bytes, len);
                wrong[0] ^= 0xff;
                bytes = wrong;
            }
            data.body.data.object.file_index = fi;
            data.body.data.bytes = bytes;
            data.body.data.bytes_len = (uint32_t)len;
        }
        uint8_t dframe[8 + 96 + 4096];
        size_t dlen = 0;
        if (!vcs_package_swarm_serialize(&data, dframe, sizeof(dframe),
                                         &dlen)) {
            st->last.penalty = VCS_SWARM_PENALTY_MALFORMED;
            continue;
        }
        st->replies++;
        st->last = vcs_swarm_engine_handle_frame(n->engine, peer, dframe,
                                                 dlen, SW_DAY, now);
        free(st->last.reply);
        st->last.reply = NULL;
        if (duplicate_last) {
            struct vcs_swarm_frame_result dup =
                vcs_swarm_engine_handle_frame(n->engine, peer, dframe, dlen,
                                              SW_DAY, now);
            free(dup.reply);
            st->last.penalty = dup.penalty;
            st->last.rule = dup.rule;
        }
    }
}

void sw_pump(struct sw_node *n, uint64_t peer, const struct sw_pkg *p,
                    enum sw_serve_mode mode, bool duplicate_last,
                    uint64_t now, struct sw_pump_stats *st)
{
    memset(&st->last, 0, sizeof(st->last));
    struct vcs_package_swarm_message wants[SWARM_PUMP_MAX_WANTS];
    size_t want_count = 0;
    sw_pump_drain_outbound(n, peer, wants, &want_count, st);
    sw_pump_track_inflight(n, peer, p, st);
    if (mode == SW_SERVE_SILENT)
        return;
    sw_pump_serve_wants(n, peer, p, mode, duplicate_last, now, wants,
                        want_count, st);
}

/* Fetch + drive to completion between one downloader node and N serving
 * peers (all honest). Returns false unless the store ends COMPLETE. */
bool sw_drive_complete(struct sw_node *n, const uint64_t *peers,
                              size_t peer_count, const struct sw_pkg *p,
                              uint32_t *max_inflight)
{
    for (int round = 0; round < 64; round++) {
        vcs_swarm_engine_tick(n->engine, SW_DAY, (uint64_t)(round + 2));
        for (size_t i = 0; i < peer_count; i++) {
            struct sw_pump_stats st;
            memset(&st, 0, sizeof(st));
            sw_pump(n, peers[i], p, SW_SERVE_HONEST, false,
                    (uint64_t)(round + 2), &st);
            if (st.max_inflight > *max_inflight)
                *max_inflight = st.max_inflight;
        }
        struct vcs_swarm_download_status st;
        if (!vcs_swarm_engine_download_status(n->engine, p->root, &st))
            return false;
        if (st.state == VCS_SWARM_DL_COMPLETE)
            return true;
    }
    return false;
}

/* ── 1-2: invalid chunks and coordinates never reach the CAS ──────── */

/* Drain every outbound WANT for `peer` into wants[] (parsed). Returns
 * the count; other frame types are counted in *cancels when non-NULL. */
size_t sw_drain_wants(struct sw_node *n, uint64_t peer,
                             struct vcs_package_swarm_object *wants,
                             size_t max)
{
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0, count = 0;
    while (vcs_swarm_engine_next_outbound(n->engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg) ||
            msg.type != VCS_PACKAGE_SWARM_WANT || count >= max)
            continue;
        wants[count++] = msg.body.want;
    }
    return count;
}

/* Hand-answer one WANT with caller-supplied bytes (or a coordinate
 * override) and return the engine's verdict. */
struct vcs_swarm_frame_result sw_answer(
    struct sw_node *n, uint64_t peer,
    const struct vcs_package_swarm_object *want, const uint8_t *bytes,
    size_t bytes_len, uint32_t file_index_override)
{
    struct vcs_package_swarm_message data;
    memset(&data, 0, sizeof(data));
    data.type = VCS_PACKAGE_SWARM_DATA;
    data.body.data.object = *want;
    if (file_index_override != UINT32_MAX)
        data.body.data.object.file_index = file_index_override;
    data.body.data.bytes = bytes;
    data.body.data.bytes_len = (uint32_t)bytes_len;
    uint8_t dframe[8 + 96 + 4096];
    size_t dlen = 0;
    struct vcs_swarm_frame_result res;
    memset(&res, 0, sizeof(res));
    if (!vcs_package_swarm_serialize(&data, dframe, sizeof(dframe),
                                     &dlen)) {
        res.penalty = VCS_SWARM_PENALTY_MALFORMED;
        return res;
    }
    res = vcs_swarm_engine_handle_frame(n->engine, peer, dframe, dlen,
                                        SW_DAY, 90);
    free(res.reply);
    res.reply = NULL;
    return res;
}


int test_zcode_swarm(void)
{
    int failures = 0;
    failures += t_swarm_invalid_data();
    failures += t_swarm_unsolicited_and_replay();
    failures += t_swarm_cancel_race();
    failures += t_swarm_drop_race();
    failures += t_swarm_announce_policy();
    failures += t_swarm_c23_shelf_announce();
    failures += t_swarm_scheduler_order();
    failures += t_swarm_timeout_retry();
    failures += t_swarm_disconnect_requeue();
    failures += t_swarm_resume();
    failures += t_swarm_serving_and_allowance();
    failures += t_swarm_receipt_exchange();
    failures += t_swarm_receipt_session();
    failures += t_swarm_disconnect_threshold();
    failures += t_swarm_blob_transfer();
    failures += t_swarm_provider_restricted();
    failures += t_swarm_bounded_provider();
    failures += t_swarm_legacy_record();
    failures += t_swarm_event_driven_schedule();
    failures += t_swarm_peer_offer();
    return failures;
}
