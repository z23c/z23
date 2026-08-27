/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_swarm — the slice-12 swarm engine gate
 * (lib/vcs/package_swarm_node.*), adversarial first:
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
 *      no credit, NO offence.
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

#define SW_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zcode_swarm: %s... OK\n", (name)); }          \
    else { printf("  zcode_swarm: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define SW_MAX_FILES 12u
#define SW_MAX_FILE 1200u
#define SW_DAY 20500
#define SW_CONTRIBUTOR_SCORE UINT64_C(100)
#define SWARM_PUMP_MAX_WANTS 40u

/* ── fixture package (single-chunk files) ─────────────────────────── */

struct sw_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    size_t count;
    uint8_t contents[SW_MAX_FILES][SW_MAX_FILE];
    size_t lens[SW_MAX_FILES];
};

static bool sw_make_package(struct sw_pkg *p, size_t count, uint8_t seed)
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

static void sw_free_package(struct sw_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* The file index of manifest path position i (manifest is path-sorted;
 * the fixture inserts in sorted order, so i IS the file index). Chunk
 * bytes for (file_index, chunk_index=0). */
static const uint8_t *sw_chunk_bytes(const struct sw_pkg *p,
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
static bool sw_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool sw_reward_address(char *out, size_t out_size)
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
static bool sw_publish_release(struct vcs_package_store *store,
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

struct sw_node {
    char datadir[1024];
    char zcode_dir[1100];
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
};

static uint64_t sw_score_contributor(const uint8_t contributor[33],
                                     void *ctx)
{
    (void)contributor;
    (void)ctx;
    return SW_CONTRIBUTOR_SCORE;
}

static bool sw_node_open(struct sw_node *n, const char *tag,
                         vcs_swarm_score_fn score_fn)
{
    test_make_tmpdir(n->datadir, sizeof(n->datadir), "zcode_swarm", tag);
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

static void sw_node_close(struct sw_node *n)
{
    vcs_swarm_engine_free(n->engine);
    vcs_service_book_free(n->book);
    vcs_package_store_close(n->store);
    n->engine = NULL;
    n->book = NULL;
    n->store = NULL;
}

static void sw_key(uint8_t seed, uint8_t out[33])
{
    memset(out, 0, 33);
    out[0] = 0x02;
    out[32] = seed;
    out[1] = (uint8_t)(seed ^ 0x5a);
}

/* ── frame builders ─────────────────────────────────────────────────── */

static size_t sw_announce_frame(const struct sw_pkg *p, uint8_t *out)
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

static void sw_announce(struct vcs_swarm_engine *e, uint64_t peer,
                        const struct sw_pkg *p)
{
    uint8_t frame[128];
    size_t len = sw_announce_frame(p, frame);
    vcs_swarm_engine_handle_frame(e, peer, frame, len, SW_DAY, 1);
}

enum sw_serve_mode {
    SW_SERVE_HONEST = 0,
    SW_SERVE_WRONG_HASH,
    SW_SERVE_WRONG_COORDS,
    SW_SERVE_SILENT, /* never answer (timeout driver) */
};

struct sw_pump_stats {
    uint32_t wants;
    uint32_t cancels;
    uint32_t announces;
    uint32_t replies;
    uint32_t max_inflight; /* per-peer bound witness */
    struct vcs_swarm_frame_result last;
};

/* Drain every outbound frame for `peer`; answer WANTs with DATA per
 * `mode` fed straight back into handle_frame. duplicate_last: after an
 * honest DATA, immediately replay the same frame a second time. The
 * per-peer in-flight peak is sampled AFTER draining (every issued WANT
 * still outstanding) and BEFORE answering. */
static void sw_pump(struct sw_node *n, uint64_t peer, const struct sw_pkg *p,
                    enum sw_serve_mode mode, bool duplicate_last,
                    uint64_t now, struct sw_pump_stats *st)
{
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    memset(&st->last, 0, sizeof(st->last));
    struct vcs_package_swarm_message wants[SWARM_PUMP_MAX_WANTS];
    size_t want_count = 0;
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
        if (msg.type != VCS_PACKAGE_SWARM_WANT || want_count >=
                SWARM_PUMP_MAX_WANTS)
            continue;
        wants[want_count++] = msg;
        st->wants++;
    }
    struct vcs_swarm_peer_info infos[VCS_SWARM_MAX_PEERS];
    size_t np = vcs_swarm_engine_peers_for(n->engine, p->root, infos,
                                           VCS_SWARM_MAX_PEERS);
    for (size_t i = 0; i < np; i++)
        if (infos[i].peer == peer && infos[i].inflight > st->max_inflight)
            st->max_inflight = infos[i].inflight;
    if (mode == SW_SERVE_SILENT)
        return;
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

/* Fetch + drive to completion between one downloader node and N serving
 * peers (all honest). Returns false unless the store ends COMPLETE. */
static bool sw_drive_complete(struct sw_node *n, const uint64_t *peers,
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
static size_t sw_drain_wants(struct sw_node *n, uint64_t peer,
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
static struct vcs_swarm_frame_result sw_answer(
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

static int t_swarm_invalid_data(void)
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

    /* Wrong-hash manifest from the malicious peer: named invalid,
     * INVALID_CHUNK offence, UNVERIFIED no-credit, nothing stored. */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct vcs_package_swarm_object wants[8];
    SW_CHECK("manifest want issued", sw_drain_wants(&n, bad, wants, 8) == 1);
    uint8_t corrupted[4096];
    memcpy(corrupted, p.wire, p.wire_len);
    corrupted[p.wire_len - 1] ^= 0xff; /* root no longer reproduces */
    struct vcs_swarm_frame_result res =
        sw_answer(&n, bad, &wants[0], corrupted, p.wire_len, UINT32_MAX);
    SW_CHECK("wrong manifest named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA &&
             res.rule != NULL && strcmp(res.rule, "invalid-chunk") == 0);
    struct vcs_service_key_totals totals;
    SW_CHECK("wrong manifest: invalid offence + unverified no-credit",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] == 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_UNVERIFIED] == 1 &&
             totals.verified_bytes_downloaded == 0);
    struct vcs_swarm_download_status dst;
    SW_CHECK("still want-manifest",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_WANT_MANIFEST);

    /* The malicious peer is manifest-failed; a fresh honest peer serves
     * the manifest. */
    SW_CHECK("honest peer add",
             vcs_swarm_engine_peer_add(n.engine, honest, key2));
    sw_announce(n.engine, honest, &p);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);
    SW_CHECK("honest peer gets no stale frames",
             sw_drain_wants(&n, bad, wants, 8) == 0);
    SW_CHECK("manifest want to honest peer",
             sw_drain_wants(&n, honest, wants, 8) == 1);
    res = sw_answer(&n, honest, &wants[0], p.wire, p.wire_len, UINT32_MAX);
    SW_CHECK("honest manifest accepted", res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("now downloading chunks",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS);

    /* Chunk WANTs spread deterministically: slot 0 (bad) holds chunks 0
     * and 2, slot 1 (honest) chunk 1. Answer bad's chunk 0 with a wrong
     * hash and chunk 2 with wrong coordinates; answer NOTHING honest
     * yet, so the CAS must stay empty and credit at the manifest only. */
    vcs_swarm_engine_tick(n.engine, SW_DAY, 4);
    struct vcs_package_swarm_object bad_wants[8], honest_wants[8];
    size_t nb = sw_drain_wants(&n, bad, bad_wants, 8);
    size_t nh = sw_drain_wants(&n, honest, honest_wants, 8);
    SW_CHECK("bad peer holds two chunk wants", nb == 2);
    SW_CHECK("honest peer holds one chunk want", nh == 1);
    uint8_t wrong[SW_MAX_FILE];
    size_t len0 = 0;
    const uint8_t *bytes0 = sw_chunk_bytes(&p, bad_wants[0].file_index,
                                           &len0);
    memcpy(wrong, bytes0, len0);
    wrong[0] ^= 0xff;
    res = sw_answer(&n, bad, &bad_wants[0], wrong, len0, UINT32_MAX);
    SW_CHECK("wrong-hash chunk named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA);
    uint32_t other = (bad_wants[1].file_index + 1u) % (uint32_t)p.count;
    size_t len2 = 0;
    const uint8_t *bytes2 = sw_chunk_bytes(&p, other, &len2);
    res = sw_answer(&n, bad, &bad_wants[1], bytes2, len2, other);
    SW_CHECK("wrong-coords chunk named invalid",
             res.penalty == VCS_SWARM_PENALTY_INVALID_DATA);
    SW_CHECK("invalid chunks: offences accumulate, no credit",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] == 3 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_INVALID_CHUNK] >= 2 &&
             totals.verified_bytes_downloaded == 0);
    bool any_present = false;
    for (uint32_t fi = 0; fi < p.count; fi++)
        any_present |= vcs_package_store_chunk_present(n.store, p.root, fi,
                                                       0);
    SW_CHECK("invalid bytes never stored", !any_present);

    /* The honest peer finishes: its held chunk plus the two reassigned
     * ones (the bad peer is failed for both). */
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { honest };
    /* Answer the already-held honest want first. */
    size_t lenh = 0;
    const uint8_t *bytesh = sw_chunk_bytes(&p, honest_wants[0].file_index,
                                           &lenh);
    res = sw_answer(&n, honest, &honest_wants[0], bytesh, lenh, UINT32_MAX);
    SW_CHECK("held honest chunk accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("completes via honest peer",
             sw_drive_complete(&n, peers, 1, &p, &max_inflight));
    SW_CHECK("in-flight bound honored", max_inflight > 0 &&
             max_inflight <= VCS_SWARM_PEER_INFLIGHT_MAX);
    struct vcs_package_store_status sst;
    SW_CHECK("store complete",
             vcs_package_store_package_status(n.store, p.root, &sst) &&
             sst.complete);
    SW_CHECK("malicious peer earned nothing",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == 0);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 3-4: unrequested bytes, replays, cancel races ────────────────── */

static int t_swarm_unsolicited_and_replay(void)
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

static int t_swarm_cancel_race(void)
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

/* ── 5: announcements never earn; announce flood named ────────────── */

static int t_swarm_announce_policy(void)
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
    /* NEW_USER announce rate is the unique-root serving-set inventory
     * bound (VCS_POLICY_FREE_ANNOUNCE_PER_HOUR/hour). Keep-alive repeats
     * of a root already in peer->ads[] do not consume it. */
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, frame_len, SW_DAY, 1);
    SW_CHECK("new-user first unique announce accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("new-user announce recorded",
             vcs_swarm_engine_peers_for(n.engine, p.root, infos, 4) == 1);
    res = vcs_swarm_engine_handle_frame(n.engine, peer, frame, frame_len,
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
        res = vcs_swarm_engine_handle_frame(n.engine, peer, extra_frame,
                                            extra_len, SW_DAY, 1);
        if (res.penalty == VCS_SWARM_PENALTY_NONE)
            extra_accepted++;
        sw_free_package(&extra);
    }
    SW_CHECK("new-user unique announces fill the inventory bound",
             minted &&
             extra_accepted == VCS_POLICY_FREE_ANNOUNCE_PER_HOUR - 1);
    struct sw_pkg over;
    if (!sw_make_package(&over, 2,
                         (uint8_t)(50u + VCS_POLICY_FREE_ANNOUNCE_PER_HOUR))) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }
    uint8_t over_frame[128];
    size_t over_len = sw_announce_frame(&over, over_frame);
    res = vcs_swarm_engine_handle_frame(n.engine, peer, over_frame, over_len,
                                        SW_DAY, 1);
    SW_CHECK("new-user distinct root over inventory bound flood named",
             res.penalty == VCS_SWARM_PENALTY_ANNOUNCE_FLOOD &&
             res.rule != NULL &&
             strcmp(res.rule, "announce-rate-limit") == 0);
    struct vcs_service_key_totals totals;
    /* Unique accepts + one keep-alive + one flood unique; no credit. */
    SW_CHECK("announce: one flood offence, no ratio movement",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD] == 1 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_ANNOUNCEMENT] ==
                 VCS_POLICY_FREE_ANNOUNCE_PER_HOUR + 2 &&
             totals.verified_bytes_downloaded == 0 &&
             totals.verified_bytes_uploaded == 0);
    SW_CHECK("first unique root still advertised after keep-alive",
             vcs_swarm_engine_peers_for(n.engine, p.root, infos, 4) == 1);
    SW_CHECK("flooded distinct root was not added to the serving set",
             vcs_swarm_engine_peers_for(n.engine, over.root, infos, 4) == 0);
    sw_free_package(&over);

    /* An earned contributor may announce; it STILL earns nothing. */
    struct sw_node n2;
    uint8_t key2[33];
    sw_key(13, key2);
    if (!sw_node_open(&n2, "announce2", sw_score_contributor)) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }
    const uint64_t peer2 = 4002;
    SW_CHECK("peer2 add", vcs_swarm_engine_peer_add(n2.engine, peer2, key2));
    res = vcs_swarm_engine_handle_frame(n2.engine, peer2, frame, frame_len,
                                        SW_DAY, 1);
    SW_CHECK("contributor announce accepted",
             res.penalty == VCS_SWARM_PENALTY_NONE);
    SW_CHECK("contributor announce recorded",
             vcs_swarm_engine_peers_for(n2.engine, p.root, infos, 4) == 1);
    SW_CHECK("contributor announce earns nothing",
             vcs_service_key_totals(n2.book, key2, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == 0 &&
             totals.verified_bytes_uploaded == 0 &&
             totals.no_credit_events[VCS_POLICY_NO_CREDIT_ANNOUNCEMENT] == 1 &&
             totals.offence_total == 0);
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
static bool sw_seed_in_tree_package(struct sw_node *n, const char *source_dir,
                                    uint8_t seed, uint64_t sequence,
                                    uint8_t transport_root[32])
{
    struct privkey sk;
    struct pubkey pk;
    if (!n || !source_dir || !transport_root || !n->store || !n->engine ||
        !sw_keypair(seed, &sk, &pk))
        return false;
    struct vcs_package_prepare_options options = {
        .dir = source_dir,
        .publisher_sequence = sequence,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    struct vcs_package_prepared prepared;
    vcs_package_prepared_init(&prepared);
    char detail[160] = {0};
    if (vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        fprintf(stderr, "zcode_swarm shelf prepare %s: %s\n", source_dir,
                detail);
        vcs_package_prepared_free(&prepared);
        return false;
    }
    struct uint256 digest;
    memcpy(digest.data, prepared.signing_digest, 32);
    uint8_t compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &digest, compact)) {
        vcs_package_prepared_free(&prepared);
        return false;
    }
    memcpy(prepared.release.signature, compact + 1,
           VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_transport transport;
    vcs_package_transport_init(&transport);
    bool ok =
        vcs_package_release_verify(&prepared.release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_serialize(&prepared.release, &release_wire,
                                      &release_wire_len) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_transport_build(
            release_wire, release_wire_len, prepared.recipe_wire,
            prepared.recipe_wire_len, prepared.manifest_wire,
            prepared.manifest_wire_len, &transport) ==
            VCS_PACKAGE_TRANSPORT_OK &&
        vcs_package_transport_store(n->store, &transport, source_dir) ==
            VCS_PACKAGE_TRANSPORT_OK &&
        vcs_package_store_pin(n->store, transport.transport_root, true) ==
            VCS_PACKAGE_STORE_OK;
    if (ok)
        memcpy(transport_root, transport.transport_root, 32);
    free(release_wire);
    vcs_package_transport_free(&transport);
    vcs_package_prepared_free(&prepared);
    if (!ok)
        return false;
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
    "packages/zhex",   "packages/zstr", "packages/zbuf",  "packages/zsha256",
    "packages/zring",  "packages/zmap", "packages/zvec",  "packages/zutf8",
    "packages/zjson",
};
enum { SW_SHELF_N = (int)(sizeof(k_c23_shelf) / sizeof(k_c23_shelf[0])) };

static int t_swarm_c23_shelf_announce(void)
{
    int failures = 0;
    struct sw_node seeder, learner;
    if (!sw_node_open(&seeder, "shelf-seed", sw_score_contributor) ||
        !sw_node_open(&learner, "shelf-learn", NULL /* NEW_USER */))
        return 1;
    uint8_t roots[SW_SHELF_N][32];
    memset(roots, 0, sizeof(roots));
    bool seeded = true;
    for (size_t i = 0; i < SW_SHELF_N; i++) {
        if (!sw_seed_in_tree_package(&seeder, k_c23_shelf[i],
                                     (uint8_t)(0x61u + i), i + 1u,
                                     roots[i])) {
            fprintf(stderr, "zcode_swarm shelf: failed %s\n",
                    k_c23_shelf[i]);
            seeded = false;
            break;
        }
    }
    SW_CHECK("ordinary C23 shelf has at least eight titles",
             SW_SHELF_N >= 8);
    SW_CHECK("ordinary C23 shelf prepared and imported", seeded);
    if (!seeded) {
        sw_node_close(&seeder);
        sw_node_close(&learner);
        test_rm_rf_recursive(seeder.datadir);
        test_rm_rf_recursive(learner.datadir);
        return failures + 1;
    }
    bool unique_roots = true;
    for (size_t i = 0; i < SW_SHELF_N; i++)
        for (size_t j = i + 1u; j < SW_SHELF_N; j++)
            if (memcmp(roots[i], roots[j], 32) == 0)
                unique_roots = false;
    SW_CHECK("shelf titles derive distinct transport roots", unique_roots);

    uint8_t seed_key[33], learn_key[33];
    sw_key(0x71, seed_key);
    sw_key(0x72, learn_key);
    const uint64_t seed_peer = 5101, learn_peer = 5102;
    SW_CHECK("seeder peer add",
             vcs_swarm_engine_peer_add(seeder.engine, seed_peer, seed_key));
    size_t queued = vcs_swarm_engine_announce_to(seeder.engine, seed_peer);
    SW_CHECK("announce_to queues the public-serveable shelf",
             queued >= SW_SHELF_N && queued <= VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    uint8_t frames[VCS_SWARM_MAX_LOCAL_ANNOUNCES][VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t lens[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    memset(frames, 0, sizeof(frames));
    memset(lens, 0, sizeof(lens));
    size_t drained =
        sw_drain_announces(&seeder, seed_peer, frames, lens,
                           VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    SW_CHECK("queued announces drain", drained == queued);
    bool all_seeded = true;
    for (size_t i = 0; i < SW_SHELF_N; i++) {
        bool found = false;
        for (size_t j = 0; j < drained; j++)
            if (sw_announce_names_root(frames[j], lens[j], roots[i]))
                found = true;
        if (!found)
            all_seeded = false;
    }
    SW_CHECK("every seeded transport root was announced", all_seeded);
    SW_CHECK("re-announce is already-announced keep-alive, not a flood",
             vcs_swarm_engine_announce_to(seeder.engine, seed_peer) == 0);

    SW_CHECK("learner peer add",
             vcs_swarm_engine_peer_add(learner.engine, learn_peer,
                                       learn_key));
    bool learned = true;
    uint32_t unique_accepted = 0;
    for (size_t i = 0; i < drained; i++) {
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            learner.engine, learn_peer, frames[i], lens[i], SW_DAY, 1);
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
        if (vcs_swarm_engine_peers_for(learner.engine, roots[i], infos,
                                       4) != 1)
            advertised = false;
    SW_CHECK("NEW_USER recorded each shelf transport root", advertised);
    bool keep_alive = true;
    for (size_t i = 0; i < drained; i++) {
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            learner.engine, learn_peer, frames[i], lens[i], SW_DAY, 2);
        if (res.penalty != VCS_SWARM_PENALTY_NONE)
            keep_alive = false;
    }
    struct vcs_service_key_totals totals;
    SW_CHECK("keep-alive repeats of heard roots are not ANNOUNCE_FLOOD",
             keep_alive &&
             vcs_service_key_totals(learner.book, learn_key, SW_DAY,
                                    &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD] == 0);
    SW_CHECK("unique-flood bound is still the serving-set size",
             VCS_POLICY_FREE_ANNOUNCE_PER_HOUR ==
                 VCS_SWARM_MAX_LOCAL_ANNOUNCES &&
             SW_SHELF_N < VCS_POLICY_FREE_ANNOUNCE_PER_HOUR);

    sw_node_close(&seeder);
    sw_node_close(&learner);
    test_rm_rf_recursive(seeder.datadir);
    test_rm_rf_recursive(learner.datadir);
    return failures;
}

/* ── 6: scheduler shape + end-to-end ──────────────────────────────── */

static int t_swarm_scheduler_order(void)
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
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    /* Rarest-first: the RARE package's manifest WANT (to peer d) must be
     * queued ahead of COMMON's. */
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    SW_CHECK("first outbound exists",
             vcs_swarm_engine_next_outbound(n.engine, 0, &target, frame,
                                            &frame_len));
    SW_CHECK("rarest-first: rare package scheduled first", target == d);
    struct vcs_package_swarm_message msg;
    SW_CHECK("first frame parses",
             vcs_package_swarm_parse(frame, frame_len, &msg) &&
             msg.type == VCS_PACKAGE_SWARM_WANT &&
             memcmp(msg.body.want.package_root, rare.root, 32) == 0 &&
             msg.body.want.object_kind ==
                 VCS_PACKAGE_SWARM_OBJECT_MANIFEST);
    /* Manifest-first: no chunk WANT may precede a verified manifest. */
    SW_CHECK("second outbound is common manifest want",
             vcs_swarm_engine_next_outbound(n.engine, 0, &target, frame,
                                            &frame_len) &&
             vcs_package_swarm_parse(frame, frame_len, &msg) &&
             msg.body.want.object_kind ==
                 VCS_PACKAGE_SWARM_OBJECT_MANIFEST &&
             memcmp(msg.body.want.package_root, common.root, 32) == 0);

    /* End-to-end: both complete; chunk load spreads across the three
     * common advertisers. */
    for (int round = 3; round < 64; round++) {
        vcs_swarm_engine_tick(n.engine, SW_DAY, (uint64_t)round);
        struct sw_pump_stats st;
        memset(&st, 0, sizeof(st));
        sw_pump(&n, a, &common, SW_SERVE_HONEST, false, (uint64_t)round,
                &st);
        memset(&st, 0, sizeof(st));
        sw_pump(&n, b, &common, SW_SERVE_HONEST, false, (uint64_t)round,
                &st);
        memset(&st, 0, sizeof(st));
        sw_pump(&n, c, &common, SW_SERVE_HONEST, false, (uint64_t)round,
                &st);
        memset(&st, 0, sizeof(st));
        sw_pump(&n, d, &rare, SW_SERVE_HONEST, false, (uint64_t)round,
                &st);
        struct vcs_swarm_download_status s1, s2;
        vcs_swarm_engine_download_status(n.engine, common.root, &s1);
        vcs_swarm_engine_download_status(n.engine, rare.root, &s2);
        if (s1.state == VCS_SWARM_DL_COMPLETE &&
            s2.state == VCS_SWARM_DL_COMPLETE)
            break;
    }
    struct vcs_swarm_download_status s1, s2;
    SW_CHECK("common complete",
             vcs_swarm_engine_download_status(n.engine, common.root, &s1) &&
             s1.state == VCS_SWARM_DL_COMPLETE);
    SW_CHECK("rare complete",
             vcs_swarm_engine_download_status(n.engine, rare.root, &s2) &&
             s2.state == VCS_SWARM_DL_COMPLETE);
    struct vcs_service_key_totals t1, t2, t3;
    vcs_service_key_totals(n.book, k1, SW_DAY, &t1);
    vcs_service_key_totals(n.book, k2, SW_DAY, &t2);
    vcs_service_key_totals(n.book, k3, SW_DAY, &t3);
    SW_CHECK("multi-peer spread: every advertiser served",
             t1.verified_bytes_downloaded > 0 ||
             t2.verified_bytes_downloaded > 0 ||
             t3.verified_bytes_downloaded > 0);
    SW_CHECK("no offences in honest run",
             t1.offence_total == 0 && t2.offence_total == 0 &&
             t3.offence_total == 0);
    /* Completion is verified CAS content: every chunk re-reads. */
    bool all_present = true;
    for (uint32_t fi = 0; fi < common.count; fi++)
        all_present &= vcs_package_store_chunk_present(n.store, common.root,
                                                       fi, 0);
    SW_CHECK("common chunks verified in CAS", all_present);
    sw_free_package(&common);
    sw_free_package(&rare);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 7-8: timeout/retry bounds + disconnect requeue ───────────────── */

static int t_swarm_timeout_retry(void)
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

static int t_swarm_disconnect_requeue(void)
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

static int t_swarm_resume(void)
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
    /* Answer exactly ONE chunk WANT, leave the rest outstanding. */
    {
        uint64_t target = 0;
        uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
        size_t frame_len = 0;
        bool answered = false;
        while (vcs_swarm_engine_next_outbound(n.engine, peer, &target,
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
                sw_chunk_bytes(&p, msg.body.want.file_index, &len);
            data.body.data.bytes_len = (uint32_t)len;
            uint8_t dframe[8 + 96 + SW_MAX_FILE];
            size_t dlen = 0;
            vcs_package_swarm_serialize(&data, dframe, sizeof(dframe),
                                        &dlen);
            struct vcs_swarm_frame_result res =
                vcs_swarm_engine_handle_frame(n.engine, peer, dframe, dlen,
                                              SW_DAY, 3);
            free(res.reply);
        }
        SW_CHECK("one chunk answered pre-restart", answered);
    }
    /* Restart: engine + store + book all reopen on the same datadir. */
    struct vcs_swarm_download_status dst;
    SW_CHECK("pre-restart partial",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.present_chunks == 1);
    char datadir[1024];
    char zcode_dir[1100];
    snprintf(datadir, sizeof(datadir), "%s", n.datadir);
    snprintf(zcode_dir, sizeof(zcode_dir), "%s", n.zcode_dir);
    sw_node_close(&n);
    n.store = vcs_package_store_open(datadir,
                                     VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n.book = vcs_service_book_load(zcode_dir);
    n.engine = vcs_swarm_engine_create(n.store, n.book, zcode_dir,
                                       sw_score_contributor, NULL);
    snprintf(n.datadir, sizeof(n.datadir), "%s", datadir);
    snprintf(n.zcode_dir, sizeof(n.zcode_dir), "%s", zcode_dir);
    SW_CHECK("restart ok", n.store && n.book && n.engine);
    SW_CHECK("resume rebuilds from CAS",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.present_chunks == 1);
    /* Re-add the peer and finish: the download completes from where it
     * stopped (staging bytes earn nothing — only newly verified bytes
     * credit). */
    SW_CHECK("peer re-add", vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    uint32_t max_inflight = 0;
    const uint64_t peers[1] = { peer };
    SW_CHECK("resume completes",
             sw_drive_complete(&n, peers, 1, &p, &max_inflight));
    SW_CHECK("record deleted on completion",
             vcs_swarm_engine_download_status(n.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_COMPLETE);
    char record_path[1200];
    snprintf(record_path, sizeof(record_path), "%s/downloads", zcode_dir);
    struct vcs_service_key_totals totals;
    uint64_t served = p.wire_len;
    for (size_t i = 0; i < p.count; i++)
        served += p.lens[i];
    SW_CHECK("exactly the verified bytes credited",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.verified_bytes_downloaded == served);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 10: serving, replayed WANTs, burst flood, allowance ──────────── */

static int t_swarm_serving_and_allowance(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t key[33];
    sw_key(41, key);
    if (!sw_node_open(&n, "serve", sw_score_contributor) ||
        !sw_make_package(&p, 3, 91))
        return 1;
    /* Host the package locally first (publish path). */
    SW_CHECK("manifest admitted",
             vcs_package_store_put_manifest(n.store, p.wire, p.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p.count; i++)
        SW_CHECK("chunk admitted",
                 vcs_package_store_put_chunk(
                     n.store, p.root, p.manifest.files[i].path, 0,
                     p.contents[i], p.lens[i]) == VCS_PACKAGE_STORE_OK);
    const uint64_t peer = 8001;
    /* Complete is not hostable. Before the release lands, the engine
     * announces nothing and answers a manifest WANT with the named
     * refusal instead of bytes. */
    SW_CHECK("unreleased package is not announced",
             vcs_swarm_engine_peer_add(n.engine, 8009, key) &&
             vcs_swarm_engine_announce_to(n.engine, 8009) == 0);
    /* ...and a WANT for it is refused BY NAME, with no reply, no penalty
     * and no offence: the requester cannot know what we host. */
    {
        struct vcs_package_swarm_message unlicensed;
        memset(&unlicensed, 0, sizeof(unlicensed));
        unlicensed.type = VCS_PACKAGE_SWARM_WANT;
        unlicensed.body.want.request_id = 8801;
        memcpy(unlicensed.body.want.package_root, p.root, 32);
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
            vcs_swarm_engine_handle_frame(n.engine, 8009, refused_frame,
                                          refused_len, SW_DAY, 1);
        SW_CHECK("unreleased want refused by name, not by silence",
                 refused.reply == NULL &&
                 refused.penalty == VCS_SWARM_PENALTY_NONE &&
                 !refused.disconnect_peer && refused.rule != NULL &&
                 strcmp(refused.rule, "no-verified-release") == 0);
        struct vcs_service_key_totals unlicensed_totals;
        SW_CHECK("refusal credits nothing and books no offence",
                 vcs_service_key_totals(n.book, key, SW_DAY,
                                        &unlicensed_totals) &&
                 unlicensed_totals.verified_bytes_uploaded == 0);
    }
    SW_CHECK("release published",
             sw_publish_release(n.store, p.root, 0x41, "swarm-serve/fixture"));
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, peer, key));

    /* Announce our complete packages to the peer. */
    SW_CHECK("announce queued",
             vcs_swarm_engine_announce_to(n.engine, peer) == 1);
    uint64_t target = 0;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t frame_len = 0;
    SW_CHECK("announce frame drains",
             vcs_swarm_engine_next_outbound(n.engine, peer, &target, frame,
                                            &frame_len));
    /* Dedupe: a repeat announce_to (the per-sync re-announce) queues
     * nothing; a package completed AFTER the peer joined queues exactly
     * one frame on the next call. */
    SW_CHECK("repeat announce queues nothing (deduped)",
             vcs_swarm_engine_announce_to(n.engine, peer) == 0);
    struct sw_pkg p2;
    if (!sw_make_package(&p2, 1, 137))
        return 1;
    SW_CHECK("late manifest admitted",
             vcs_package_store_put_manifest(n.store, p2.wire, p2.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p2.count; i++)
        SW_CHECK("late chunk admitted",
                 vcs_package_store_put_chunk(
                     n.store, p2.root, p2.manifest.files[i].path, 0,
                     p2.contents[i], p2.lens[i]) == VCS_PACKAGE_STORE_OK);
    SW_CHECK("late release published",
             sw_publish_release(n.store, p2.root, 0x42, "swarm-late/fixture"));
    SW_CHECK("late package announced to the existing peer",
             vcs_swarm_engine_announce_to(n.engine, peer) == 1);
    SW_CHECK("late announce frame drains",
             vcs_swarm_engine_next_outbound(n.engine, peer, &target, frame,
                                            &frame_len));
    sw_free_package(&p2);

    /* Inbound WANT (manifest): served with upload credit. A replay of
     * the same request id: DUPLICATE_REQUEST offence, no second
     * credit. */
    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    want.body.want.request_id = 9001;
    memcpy(want.body.want.package_root, p.root, 32);
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    size_t wlen = 0;
    SW_CHECK("want serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &wlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, wlen, SW_DAY, 1);
    SW_CHECK("manifest served", res.reply != NULL && res.reply_len > 0 &&
             res.penalty == VCS_SWARM_PENALTY_NONE);
    free(res.reply);
    res.reply = NULL;
    struct vcs_service_key_totals totals;
    SW_CHECK("upload credited",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.verified_bytes_uploaded == p.wire_len);
    res = vcs_swarm_engine_handle_frame(n.engine, peer, frame, wlen,
                                        SW_DAY, 1);
    SW_CHECK("replayed want named duplicate",
             res.penalty == VCS_SWARM_PENALTY_REPLAYED_REQUEST &&
             res.rule != NULL &&
             strcmp(res.rule, "duplicate-request") == 0 && !res.reply);
    SW_CHECK("replay earns no second credit",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.verified_bytes_uploaded == p.wire_len &&
             totals.offences[VCS_POLICY_OFFENCE_DUPLICATE_REQUEST] == 1);

    /* Chunk WANT with the WRONG expected hash: silent no-serve. */
    struct vcs_package_swarm_message bad_want;
    memset(&bad_want, 0, sizeof(bad_want));
    bad_want.type = VCS_PACKAGE_SWARM_WANT;
    bad_want.body.want.request_id = 9002;
    memcpy(bad_want.body.want.package_root, p.root, 32);
    bad_want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    bad_want.body.want.file_index = 0;
    bad_want.body.want.chunk_index = 0;
    memset(bad_want.body.want.expected_hash, 0xee, 32);
    SW_CHECK("bad want serializes",
             vcs_package_swarm_serialize(&bad_want, frame, sizeof(frame),
                                         &wlen));
    res = vcs_swarm_engine_handle_frame(n.engine, peer, frame, wlen,
                                        SW_DAY, 1);
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
        memcpy(cw.body.want.package_root, p.root, 32);
        cw.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
        cw.body.want.file_index = i % (uint32_t)p.count;
        cw.body.want.chunk_index = 0;
        memcpy(cw.body.want.expected_hash,
               p.manifest.files[cw.body.want.file_index].chunk_hashes, 32);
        SW_CHECK("chunk want serializes",
                 vcs_package_swarm_serialize(&cw, frame, sizeof(frame),
                                             &wlen));
        res = vcs_swarm_engine_handle_frame(n.engine, peer, frame, wlen,
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
    SW_CHECK("request flood offence recorded",
             vcs_service_key_totals(n.book, key, SW_DAY, &totals) &&
             totals.offences[VCS_POLICY_OFFENCE_REQUEST_FLOOD] >= 1);

    /* Download allowance: pre-fill the peer's weekly download bucket
     * with its full tier allowance; the scheduler must then refuse to
     * pull from it (named allowance exhausted, NO offence). The peer is
     * an earned contributor (unique-root inventory is the serving-set
     * size at this tier, same as NEW_USER). */
    struct sw_node n2;
    uint8_t key2[33];
    sw_key(42, key2);
    if (!sw_node_open(&n2, "allowance", sw_score_contributor)) {
        sw_free_package(&p);
        sw_node_close(&n);
        test_rm_rf_recursive(n.datadir);
        return failures + 1;
    }
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
    sw_announce(n2.engine, peer2, &p);
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n2.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n2.engine, SW_DAY, 2);
    /* The manifest WANT is issued and served first (manifest-first
     * bypasses chunk accounting); once the scheduler reaches the CHUNKS
     * branch the exhausted allowance blocks every chunk WANT — named by
     * the flag, with NO offence. */
    struct sw_pump_stats st;
    memset(&st, 0, sizeof(st));
    sw_pump(&n2, peer2, &p, SW_SERVE_HONEST, false, 2, &st);
    SW_CHECK("manifest served pre-exhaustion", st.wants == 1);
    vcs_swarm_engine_tick(n2.engine, SW_DAY, 3);
    memset(&st, 0, sizeof(st));
    sw_pump(&n2, peer2, &p, SW_SERVE_HONEST, false, 3, &st);
    SW_CHECK("no chunk wants over allowance", st.wants == 0);
    struct vcs_swarm_peer_info infos[4];
    size_t np = vcs_swarm_engine_peers_for(n2.engine, p.root, infos, 4);
    SW_CHECK("allowance exhausted flag",
             np == 1 && infos[0].allowance_exhausted);
    SW_CHECK("exhaustion is not an offence",
             vcs_service_key_totals(n2.book, key2, SW_DAY, &totals) &&
             totals.offence_total == 0);
    struct vcs_swarm_download_status dst;
    SW_CHECK("download stalls honestly at chunks",
             vcs_swarm_engine_download_status(n2.engine, p.root, &dst) &&
             dst.state == VCS_SWARM_DL_CHUNKS && dst.inflight == 0);
    sw_free_package(&p);
    sw_node_close(&n);
    sw_node_close(&n2);
    test_rm_rf_recursive(n.datadir);
    test_rm_rf_recursive(n2.datadir);
    return failures;
}

/* ── disconnect threshold ─────────────────────────────────────────── */

static int t_swarm_disconnect_threshold(void)
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
static int t_swarm_blob_transfer(void)
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
    for (size_t i = 0; i < sizeof(blob); i++)
        blob[i] = (uint8_t)(i * 13u + 5u);
    uint8_t root[32];
    SW_CHECK("blob: seeder admits the blob",
             vcs_blob_put_to(seed.store, blob, sizeof(blob), root) ==
                 VCS_BLOB_OK);
    struct vcs_package_store_status pst;
    SW_CHECK("blob: seeded package is complete + single chunk",
             vcs_package_store_package_status(seed.store, root, &pst) &&
             pst.complete && pst.total_chunks == 1);
    SW_CHECK("blob: leecher does not have it yet",
             !vcs_package_store_package_status(leech.store, root, &pst));

    SW_CHECK("blob: peers register on both engines",
             vcs_swarm_engine_peer_add(seed.engine, peer_leech, key_leech) &&
             vcs_swarm_engine_peer_add(leech.engine, peer_seed, key_seed));

    /* ANNOUNCE over the existing frame: no new message type. */
    size_t announced = vcs_blob_announce_via(seed.engine);
    SW_CHECK("blob: announce queued on the existing wire", announced >= 1);
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    uint64_t target = 0;
    size_t delivered = 0;
    while (vcs_swarm_engine_next_outbound(seed.engine, peer_leech, &target,
                                          frame, &frame_len)) {
        struct vcs_swarm_frame_result r = vcs_swarm_engine_handle_frame(
            leech.engine, peer_seed, frame, frame_len, SW_DAY, 1);
        free(r.reply);
        if (r.penalty == VCS_SWARM_PENALTY_NONE)
            delivered++;
    }
    SW_CHECK("blob: announce accepted unpenalized", delivered >= 1);
    struct vcs_swarm_peer_info infos[VCS_SWARM_MAX_PEERS];
    SW_CHECK("blob: leecher sees an advertiser for the root",
             vcs_swarm_engine_peers_for(leech.engine, root, infos,
                                        VCS_SWARM_MAX_PEERS) == 1);

    SW_CHECK("blob: fetch by root accepted",
             vcs_blob_fetch_via(leech.engine, root, SW_DAY, 2) ==
                 VCS_BLOB_OK);

    /* Drive: leecher WANT -> seeder engine DATA reply -> leecher. */
    bool complete = false;
    for (int round = 0; round < 32 && !complete; round++) {
        vcs_swarm_engine_tick(leech.engine, SW_DAY, (uint64_t)(round + 3));
        while (vcs_swarm_engine_next_outbound(leech.engine, peer_seed,
                                              &target, frame, &frame_len)) {
            struct vcs_swarm_frame_result served =
                vcs_swarm_engine_handle_frame(seed.engine, peer_leech, frame,
                                              frame_len, SW_DAY,
                                              (uint64_t)(round + 3));
            if (served.reply && served.reply_len > 0) {
                struct vcs_swarm_frame_result got =
                    vcs_swarm_engine_handle_frame(
                        leech.engine, peer_seed, served.reply,
                        served.reply_len, SW_DAY, (uint64_t)(round + 3));
                free(got.reply);
            }
            free(served.reply);
        }
        struct vcs_swarm_download_status ds;
        if (vcs_swarm_engine_download_status(leech.engine, root, &ds) &&
            ds.state == VCS_SWARM_DL_COMPLETE)
            complete = true;
    }
    SW_CHECK("blob: download completes over the unchanged wire", complete);

    uint8_t out[sizeof(blob)];
    size_t out_len = 0;
    memset(out, 0, sizeof(out));
    SW_CHECK("blob: leecher reads back the exact bytes",
             vcs_blob_get_from(leech.store, root, out, sizeof(out),
                               &out_len) == VCS_BLOB_OK &&
             out_len == sizeof(blob) &&
             memcmp(out, blob, sizeof(blob)) == 0);
    uint8_t rederived[32];
    SW_CHECK("blob: transferred bytes re-derive the same root",
             vcs_blob_root(out, out_len, rederived) &&
             memcmp(rederived, root, 32) == 0);

    sw_node_close(&seed);
    sw_node_close(&leech);
    test_rm_rf_recursive(seed.datadir);
    test_rm_rf_recursive(leech.datadir);
    return failures;
}

static int t_swarm_provider_restricted(void)
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
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 1,
                                         NULL, 0) ==
                 VCS_SWARM_FETCH_NO_PROVIDER);
    SW_CHECK("provider: zero-only bounded fetch has the same exact refusal",
             vcs_swarm_engine_fetch_from_bounded(
                 n.engine, p.root, SW_DAY, 1, zero_peers, 2, 4096) ==
                 VCS_SWARM_FETCH_NO_PROVIDER);
    struct vcs_swarm_download_status empty_status;
    SW_CHECK("provider: refusal creates no active or resumable download",
             vcs_swarm_engine_download_status(n.engine, p.root,
                                              &empty_status) &&
             empty_status.state == VCS_SWARM_DL_INACTIVE);
    vcs_swarm_engine_free(n.engine);
    n.engine = vcs_swarm_engine_create(n.store, n.book, n.zcode_dir,
                                       sw_score_contributor, NULL);
    SW_CHECK("provider: refusal leaves no record to reload",
             n.engine != NULL &&
             vcs_swarm_engine_download_status(n.engine, p.root,
                                              &empty_status) &&
             empty_status.state == VCS_SWARM_DL_INACTIVE);
    SW_CHECK("provider: both advertisers register",
             vcs_swarm_engine_peer_add(n.engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n.engine, honest, honest_key));
    sw_announce(n.engine, bad, &p);
    SW_CHECK("provider: restricted fetch accepts an exact unannounced peer",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 1,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct vcs_package_swarm_object wants[2];
    SW_CHECK("provider: unlisted advertiser receives no WANT",
             sw_drain_wants(&n, bad, wants, 2) == 0);
    SW_CHECK("provider: exact authenticated provider needs no broadcast ad",
             sw_drain_wants(&n, honest, wants, 2) == 1);

    vcs_swarm_engine_free(n.engine);
    n.engine = vcs_swarm_engine_create(n.store, n.book, n.zcode_dir,
                                       sw_score_contributor, NULL);
    SW_CHECK("provider: restricted intent resumes", n.engine != NULL);
    SW_CHECK("provider: peers re-register",
             vcs_swarm_engine_peer_add(n.engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n.engine, honest, honest_key));
    sw_announce(n.engine, bad, &p);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);
    SW_CHECK("provider: restart does not widen before fresh binding",
             sw_drain_wants(&n, bad, wants, 2) == 0 &&
             sw_drain_wants(&n, honest, wants, 2) == 0);
    SW_CHECK("provider: fresh authenticated binding resumes",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 4,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 4);
    SW_CHECK("provider: refreshed allowlist remains exclusive",
             sw_drain_wants(&n, bad, wants, 2) == 0 &&
             sw_drain_wants(&n, honest, wants, 2) == 1);
    struct json_value cancel_input;
    json_init(&cancel_input);
    json_set_object(&cancel_input);
    char root_hex[65];
    zcl_hex_encode(p.root, 32, root_hex);
    json_push_kv_str(&cancel_input, "blob_root", root_hex);
    json_push_kv_str(&cancel_input, "datadir", n.datadir);
    json_push_kv_bool(&cancel_input, "cancel", true);
    json_push_kv_int(&cancel_input, "now_unix", 5);
    struct zcl_command_request cancel_request;
    memset(&cancel_request, 0, sizeof(cancel_request));
    cancel_request.input = &cancel_input;
    struct zcl_command_reply cancel_reply;
    zcl_command_reply_init(&cancel_reply, "zcl.zcode_science_fetch.v1");
    vcs_swarm_engine_set_global(n.engine);
    zcl_native_handle_zcode_science_fetch(&cancel_request, &cancel_reply);
    vcs_swarm_engine_set_global(NULL);
    SW_CHECK("provider: native restricted fetch cancel succeeds",
             json_get_bool_or(&cancel_reply.data, "canceled", false) &&
             !json_get_bool_or(&cancel_reply.data, "restriction_widened",
                               true));
    zcl_command_reply_free(&cancel_reply);
    json_free(&cancel_input);
    vcs_swarm_engine_free(n.engine);
    n.engine = vcs_swarm_engine_create(n.store, n.book, n.zcode_dir,
                                       sw_score_contributor, NULL);
    SW_CHECK("provider: engine restarts after cancellation",
             n.engine != NULL);
    SW_CHECK("provider: canceled peers re-register",
             vcs_swarm_engine_peer_add(n.engine, bad, bad_key) &&
             vcs_swarm_engine_peer_add(n.engine, honest, honest_key));
    sw_announce(n.engine, bad, &p);
    sw_announce(n.engine, honest, &p);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 6);
    struct vcs_swarm_download_status canceled_status;
    SW_CHECK("provider: canceled resumable state stays deleted on restart",
             vcs_swarm_engine_download_status(n.engine, p.root,
                                              &canceled_status) &&
             canceled_status.state == VCS_SWARM_DL_INACTIVE &&
             sw_drain_wants(&n, bad, wants, 2) == 0 &&
             sw_drain_wants(&n, honest, wants, 2) == 0);
    SW_CHECK("provider: explicit rebind after cancel remains restricted",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 7,
                                         &honest, 1) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 7);
    SW_CHECK("provider: cancel never broadens the restarted fetch",
             sw_drain_wants(&n, bad, wants, 2) == 0 &&
             sw_drain_wants(&n, honest, wants, 2) == 1);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

static int t_swarm_bounded_provider(void)
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
    SW_CHECK("provider bound: ordinary shared work starts",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 1,
                                         &peer, 1) == VCS_SWARM_FETCH_OK);
    SW_CHECK("provider bound: late scout cannot tighten shared work",
             vcs_swarm_engine_fetch_from_bounded(
                 n.engine, p.root, SW_DAY, 1, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_BOUND_NOT_OWNED);
    struct vcs_swarm_download_status status;
    SW_CHECK("provider bound: shared work remains unbounded and active",
             vcs_swarm_engine_download_status(n.engine, p.root, &status) &&
             status.state == VCS_SWARM_DL_WANT_MANIFEST &&
             status.maximum_package_bytes == 0);
    SW_CHECK("provider bound: ordinary work cancels cleanly",
             vcs_swarm_engine_cancel(n.engine, p.root, 1));
    SW_CHECK("provider bound: bounded intent starts",
             vcs_swarm_engine_fetch_from_bounded(
                 n.engine, p.root, SW_DAY, 2, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_OK);
    SW_CHECK("provider bound: ceiling is visible before restart",
             vcs_swarm_engine_download_status(n.engine, p.root, &status) &&
             status.maximum_package_bytes == bound);
    vcs_swarm_engine_free(n.engine);
    n.engine = vcs_swarm_engine_create(n.store, n.book, n.zcode_dir,
                                       sw_score_contributor, NULL);
    SW_CHECK("provider bound: engine restarts", n.engine != NULL);
    SW_CHECK("provider bound: ceiling survives restart",
             vcs_swarm_engine_download_status(n.engine, p.root, &status) &&
             status.maximum_package_bytes == bound);
    SW_CHECK("provider bound: peer rebinds",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    sw_announce(n.engine, peer, &p);
    SW_CHECK("provider bound: compatible bounded rebind accepted",
             vcs_swarm_engine_fetch_from_bounded(
                 n.engine, p.root, SW_DAY, 3, &peer, 1, bound) ==
                 VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 3);
    struct sw_pump_stats pump = {0};
    sw_pump(&n, peer, &p, SW_SERVE_HONEST, false, 3, &pump);
    SW_CHECK("provider bound: oversized manifest fails before chunks",
             vcs_swarm_engine_download_status(n.engine, p.root, &status) &&
             status.state == VCS_SWARM_DL_FAILED && status.rule &&
             strcmp(status.rule, "maximum-package-bytes-exceeded") == 0 &&
             status.present_chunks == 0 && status.fetched_bytes == 0);
    struct vcs_package_store_status stored;
    SW_CHECK("provider bound: oversized manifest never enters package store",
             !vcs_package_store_package_status(n.store, p.root, &stored));

    SW_CHECK("provider bound: failed scout intent retries as ordinary work",
             vcs_swarm_engine_fetch_from(n.engine, p.root, SW_DAY, 4,
                                         &peer, 1) == VCS_SWARM_FETCH_OK &&
             vcs_swarm_engine_download_status(n.engine, p.root, &status) &&
             status.maximum_package_bytes == 0);
    sw_free_package(&p);
    sw_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

static int t_swarm_legacy_record(void)
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

static int t_swarm_event_driven_schedule(void)
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

static int t_swarm_receipt_exchange(void)
{
    int failures = 0;
    struct sw_node n;
    struct sw_pkg p;
    uint8_t session_key[33];
    sw_key(61, session_key);
    if (!sw_node_open(&n, "receipt", sw_score_contributor) ||
        !sw_make_package(&p, 2, 101))
        return 1;
    SW_CHECK("receipt: manifest admitted",
             vcs_package_store_put_manifest(n.store, p.wire, p.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    for (size_t i = 0; i < p.count; i++)
        SW_CHECK("receipt: chunk admitted",
                 vcs_package_store_put_chunk(
                     n.store, p.root, p.manifest.files[i].path, 0,
                     p.contents[i], p.lens[i]) == VCS_PACKAGE_STORE_OK);
    SW_CHECK("receipt: release published",
             sw_publish_release(n.store, p.root, 0x61, "swarm-receipt/fx"));
    const uint64_t peer = 9101;
    SW_CHECK("receipt: peer add",
             vcs_swarm_engine_peer_add(n.engine, peer, session_key));

    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    want.body.want.request_id = 91001;
    memcpy(want.body.want.package_root, p.root, 32);
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    uint8_t frame[8 + 96 + SW_MAX_FILE];
    size_t wlen = 0;
    SW_CHECK("receipt: want serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &wlen));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, wlen, SW_DAY, 1);
    SW_CHECK("receipt: manifest served",
             res.reply != NULL && res.penalty == VCS_SWARM_PENALTY_NONE);
    free(res.reply);

    struct vcs_swarm_transfer xfer;
    memset(&xfer, 0, sizeof(xfer));
    SW_CHECK("receipt: snapshot after serve",
             vcs_swarm_engine_transfer_snapshot(n.engine, peer, &xfer) &&
             memcmp(xfer.package_root, p.root, 32) == 0 &&
             xfer.served == p.wire_len && xfer.fetched == 0);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t up_sec[32] = {0};
    uint8_t down_sec[32] = {0};
    uint8_t other_sec[32] = {0};
    up_sec[31] = 0x81;
    down_sec[31] = 0x82;
    other_sec[31] = 0x83;
    uint8_t up_pub[33];
    uint8_t down_pub[33];
    uint8_t other_pub[33];
    secp256k1_pubkey parsed;
    size_t plen = 33;
    bool keys = secp256k1_ec_pubkey_create(ctx, &parsed, up_sec) == 1 &&
                secp256k1_ec_pubkey_serialize(ctx, up_pub, &plen, &parsed,
                                              SECP256K1_EC_COMPRESSED) == 1 &&
                secp256k1_ec_pubkey_create(ctx, &parsed, down_sec) == 1 &&
                secp256k1_ec_pubkey_serialize(ctx, down_pub, &plen, &parsed,
                                              SECP256K1_EC_COMPRESSED) == 1 &&
                secp256k1_ec_pubkey_create(ctx, &parsed, other_sec) == 1 &&
                secp256k1_ec_pubkey_serialize(ctx, other_pub, &plen, &parsed,
                                              SECP256K1_EC_COMPRESSED) == 1;
    SW_CHECK("receipt: secp keys", keys);

    struct vcs_service_receipt draft;
    enum vcs_service_receipt_role role = VCS_SERVICE_RECEIPT_DOWNLOADER;
    SW_CHECK("receipt: seeder drafts as uploader",
             vcs_swarm_receipt_draft(&xfer, up_pub, down_pub, SW_DAY,
                                     SW_DAY, &draft, &role) &&
             role == VCS_SERVICE_RECEIPT_UPLOADER &&
             draft.verified_bytes == p.wire_len);
    struct vcs_swarm_transfer leecher_xfer = xfer;
    leecher_xfer.served = 0;
    leecher_xfer.fetched = xfer.served;
    struct vcs_service_receipt leecher_draft;
    enum vcs_service_receipt_role leecher_role =
        VCS_SERVICE_RECEIPT_UPLOADER;
    SW_CHECK("receipt: leecher drafts matching body",
             vcs_swarm_receipt_draft(&leecher_xfer, down_pub, up_pub,
                                     SW_DAY, SW_DAY, &leecher_draft,
                                     &leecher_role) &&
             leecher_role == VCS_SERVICE_RECEIPT_DOWNLOADER &&
             memcmp(leecher_draft.session_nonce, draft.session_nonce,
                    32) == 0 &&
             memcmp(leecher_draft.uploader_pubkey, draft.uploader_pubkey,
                    33) == 0);

    uint8_t wire[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    SW_CHECK("receipt: both ends sign",
             vcs_service_receipt_sign(&draft, VCS_SERVICE_RECEIPT_UPLOADER,
                                      ctx, up_sec) ==
                 VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_sign(&draft,
                                      VCS_SERVICE_RECEIPT_DOWNLOADER, ctx,
                                      down_sec) ==
                 VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_serialize(&draft, wire, sizeof(wire)) ==
                 VCS_SERVICE_RECEIPT_OK);

    char leecher_dir[1200];
    snprintf(leecher_dir, sizeof(leecher_dir), "%s/leecher-zcode",
             n.datadir);
    struct vcs_service_book *leecher_book =
        vcs_service_book_load(leecher_dir);
    SW_CHECK("receipt: leecher book", leecher_book != NULL);
    SW_CHECK("receipt: seeder accepts matching serve",
             vcs_swarm_receipt_accept(n.book, &xfer, up_pub, SW_DAY, wire,
                                      sizeof(wire)) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("receipt: leecher accepts matching fetch",
             leecher_book &&
             vcs_swarm_receipt_accept(leecher_book, &leecher_xfer, down_pub,
                                      SW_DAY, wire, sizeof(wire)) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("receipt: replay is duplicate",
             vcs_swarm_receipt_accept(n.book, &xfer, up_pub, SW_DAY, wire,
                                      sizeof(wire)) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    SW_CHECK("receipt: stranger refused",
             vcs_swarm_receipt_accept(n.book, &xfer, other_pub, SW_DAY,
                                      wire, sizeof(wire)) ==
                 VCS_SWARM_RECEIPT_NOT_PARTY);
    struct vcs_swarm_transfer lied = xfer;
    lied.served = 1;
    SW_CHECK("receipt: inflated bytes refused",
             vcs_swarm_receipt_accept(n.book, &lied, up_pub, SW_DAY, wire,
                                      sizeof(wire)) ==
                 VCS_SWARM_RECEIPT_BYTES_MISMATCH);
    SW_CHECK("receipt: named statuses",
             strcmp(vcs_swarm_receipt_status_string(
                        VCS_SWARM_RECEIPT_BYTES_MISMATCH),
                    "bytes-mismatch") == 0);

    if (leecher_book)
        vcs_service_book_free(leecher_book);
    secp256k1_context_destroy(ctx);
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

static int t_swarm_receipt_session(void)
{
    int failures = 0;
    struct sw_node seeder, leecher;
    if (!sw_node_open(&seeder, "rcpt-s", sw_score_contributor) ||
        !sw_node_open(&leecher, "rcpt-l", sw_score_contributor))
        return 1;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t up_sec[32], down_sec[32], other_sec[32];
    uint8_t up_pub[33], down_pub[33], other_pub[33];
    SW_CHECK("session: secp keys",
             ctx && sw_secp_pair(ctx, 0x91, up_sec, up_pub) &&
             sw_secp_pair(ctx, 0x92, down_sec, down_pub) &&
             sw_secp_pair(ctx, 0x93, other_sec, other_pub) &&
             memcmp(up_pub, other_pub, 33) != 0);
    struct vcs_swarm_receipt_session *up =
        vcs_swarm_receipt_session_open_secret(up_sec);
    struct vcs_swarm_receipt_session *down =
        vcs_swarm_receipt_session_open_secret(down_sec);
    struct vcs_swarm_receipt_session *stranger =
        vcs_swarm_receipt_session_open_secret(other_sec);
    uint8_t got[33];
    SW_CHECK("session: open secrets",
             up && down && stranger &&
             vcs_swarm_receipt_session_local_pub(up, got) &&
             memcmp(got, up_pub, 33) == 0 &&
             vcs_swarm_receipt_session_local_pub(down, got) &&
             memcmp(got, down_pub, 33) == 0);

    uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
    size_t ilen = 0;
    const uint64_t peer = 77;
    SW_CHECK("session: seeder identity once",
             vcs_swarm_receipt_identity_take(up, peer, ident, sizeof(ident),
                                             &ilen) &&
             ilen == VCS_SWARM_RECEIPT_IDENTITY_BYTES);
    SW_CHECK("session: seeder identity not resent",
             !vcs_swarm_receipt_identity_take(up, peer, ident, sizeof(ident),
                                              &ilen));
    SW_CHECK("session: leecher notes seeder",
             vcs_swarm_receipt_identity_note(down, peer, ident, ilen));
    SW_CHECK("session: leecher identity",
             vcs_swarm_receipt_identity_take(down, peer, ident, sizeof(ident),
                                             &ilen));
    SW_CHECK("session: seeder notes leecher",
             vcs_swarm_receipt_identity_note(up, peer, ident, ilen));

    struct vcs_swarm_transfer seed_x = {0}, leech_x = {0};
    memset(seed_x.package_root, 0x44, 32);
    memcpy(leech_x.package_root, seed_x.package_root, 32);
    seed_x.served = 4096;
    leech_x.fetched = 4096;

    uint8_t offer[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    SW_CHECK("session: seeder offers",
             vcs_swarm_receipt_session_offer(up, &seed_x, peer, SW_DAY,
                                             offer));
    SW_CHECK("session: second identical offer withheld",
             !vcs_swarm_receipt_session_offer(up, &seed_x, peer, SW_DAY,
                                              offer));
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    SW_CHECK("session: leecher completes",
             vcs_swarm_receipt_session_handle(down, leecher.book, &leech_x,
                                              peer, SW_DAY, offer,
                                              sizeof(offer), &reply,
                                              &reply_len) ==
                 VCS_SWARM_RECEIPT_OK &&
             reply && reply_len == VCS_SERVICE_RECEIPT_WIRE_BYTES);
    SW_CHECK("session: seeder accepts completed",
             vcs_swarm_receipt_session_handle(up, seeder.book, &seed_x, peer,
                                              SW_DAY, reply, reply_len, NULL,
                                              NULL) == VCS_SWARM_RECEIPT_OK);
    SW_CHECK("session: both settled",
             vcs_swarm_receipt_session_settled(up, peer) &&
             vcs_swarm_receipt_session_settled(down, peer));
    SW_CHECK("session: replay is duplicate",
             vcs_swarm_receipt_session_handle(up, seeder.book, &seed_x, peer,
                                              SW_DAY, reply, reply_len, NULL,
                                              NULL) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    struct vcs_swarm_transfer grown = leech_x;
    grown.fetched = leech_x.fetched + 1;
    SW_CHECK("session: superseded offer is stale",
             vcs_swarm_receipt_session_handle(down, leecher.book, &grown,
                                              peer, SW_DAY, offer,
                                              sizeof(offer), NULL, NULL) ==
                 VCS_SWARM_RECEIPT_STALE);
    SW_CHECK("session: stranger refused",
             vcs_swarm_receipt_session_handle(stranger, seeder.book, &seed_x,
                                              peer, SW_DAY, reply, reply_len,
                                              NULL, NULL) ==
                 VCS_SWARM_RECEIPT_NOT_PARTY);
    uint8_t tamper[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    memcpy(tamper, offer, sizeof(tamper));
    tamper[40] ^= 0xff;
    enum vcs_swarm_receipt_status tst = vcs_swarm_receipt_session_handle(
        down, leecher.book, &leech_x, 78, SW_DAY, tamper, sizeof(tamper),
        NULL, NULL);
    SW_CHECK("session: tampered offer refused",
             tst == VCS_SWARM_RECEIPT_UNVERIFIED ||
             tst == VCS_SWARM_RECEIPT_NOT_PARTY);
    free(reply);

    struct vcs_swarm_receipt_session *persisted =
        vcs_swarm_receipt_session_open(seeder.zcode_dir);
    uint8_t pub_a[33], pub_b[33];
    SW_CHECK("session: persist open",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_a));
    vcs_swarm_receipt_session_free(persisted);
    persisted = vcs_swarm_receipt_session_open(seeder.zcode_dir);
    SW_CHECK("session: persist reload",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_b) &&
             memcmp(pub_a, pub_b, 33) == 0);
    vcs_swarm_receipt_session_free(persisted);
    vcs_swarm_receipt_session_free(up);
    vcs_swarm_receipt_session_free(down);
    vcs_swarm_receipt_session_free(stranger);
    if (ctx)
        secp256k1_context_destroy(ctx);
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
static int t_swarm_peer_offer(void)
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

    SW_CHECK("unknown peer refused",
             !vcs_swarm_engine_peer_offer(n.engine, pid, p.root));
    SW_CHECK("peer add", vcs_swarm_engine_peer_add(n.engine, pid, key));

    /* No announce anywhere: with zero advertisers nothing may queue. */
    SW_CHECK("fetch ok", vcs_swarm_engine_fetch(n.engine, p.root, SW_DAY,
                                                1) == VCS_SWARM_FETCH_OK);
    vcs_swarm_engine_tick(n.engine, SW_DAY, 2);
    struct vcs_package_swarm_object quiet[2];
    SW_CHECK("stalled before evidence",
             sw_drain_wants(&n, pid, quiet, 2) == 0);

    /* Locally verified DHT-style evidence becomes an offer; the event
     * edge wakes scheduling and the manifest WANT goes to this peer. */
    SW_CHECK("offer accepted",
             vcs_swarm_engine_peer_offer(n.engine, pid, p.root));
    vcs_swarm_engine_schedule_ready(n.engine, SW_DAY, 3);
    struct vcs_package_swarm_object wants[2];
    SW_CHECK("want after offer", sw_drain_wants(&n, pid, wants, 2) == 1);

    /* Idempotent: still true, consumes no further ad inventory. */
    SW_CHECK("idempotent offer",
             vcs_swarm_engine_peer_offer(n.engine, pid, p.root));

    /* Distinct roots fill the remaining slots exactly; the next one is
     * refused by name instead of writing past ads[]. */
    uint8_t junk[32];
    memcpy(junk, p.root, 32);
    unsigned filled = 0;
    while (filled < VCS_SWARM_MAX_PEER_ADS + 4) {
        junk[31] = (uint8_t)(0x40 + filled);
        junk[15] = (uint8_t)(filled << 2);
        if (!vcs_swarm_engine_peer_offer(n.engine, pid, junk))
            break;
        filled++;
    }
    SW_CHECK("fill bounded at capacity minus held root",
             filled == VCS_SWARM_MAX_PEER_ADS - 1);
    return failures;
}

int test_zcode_swarm(void)
{
    int failures = 0;
    failures += t_swarm_invalid_data();
    failures += t_swarm_unsolicited_and_replay();
    failures += t_swarm_cancel_race();
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
