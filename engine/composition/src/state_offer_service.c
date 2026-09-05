/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Build this node's state offers and fetch the one it chooses.
 *
 * See config/state_offer_service.h for the contract, and note the one rule this
 * file exists to keep: it adds no verification and removes none. Every byte it
 * lands goes through the ROM path's per-chunk and whole-file digest checks, and
 * every bundle it installs goes through the installer's checkpoint and
 * Sapling-root re-derivation, exactly as an operator-seeded bundle does. */

// supervisor-ok:bounded-offer-fetch — the one thread here is a single joined
// download, not a resident service: it is started only when the store has
// chosen an offer, at most one exists at a time, the next tick joins it before
// starting another, and shutdown joins it too. It has no loop to wedge in — it
// runs the ROM fetch path once and returns — and the transport's own connect
// and receive windows bound a silent peer. Its progress is visible while it
// runs through the state_offer status row (chunks and bytes landed), so a slow
// or stalled transfer is observable rather than a quiet gap.

#include "config/state_offer_service.h"

#include "config/consensus_state_install_runtime.h"
#include "config/consensus_state_snapshot_install.h"
#include "config/state_offer_store.h"
#include "conditions/stale_offers_only.h"

#include "platform/time_compat.h"

#include "chain/mmb.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "net/msgprocessor.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "net/netaddr.h"
#include "net/state_offer.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/log_macros.h"
#include "vcs/zcode_dht_identity.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define SOSVC_SUBSYS "state_offer"

/* Rebuild the artifact snapshot at most this often. Opening a bundle's SQLite
 * manifest is not something to do once per handshake, and the set of artifacts
 * a node holds changes on the exporter's cadence, not on a peer's. */
#define SOSVC_SNAPSHOT_TTL_S 300

/* One artifact this node holds and could offer. Everything except the tip and
 * the signature is stable for the life of the file, so it is cached. */
struct sosvc_artifact {
    bool used;
    int32_t bundle_height;
    uint8_t header_hash[32];
    uint8_t content_digest[32];
    uint8_t chunk_root[32];
    uint8_t producer_receipt_id[32];
    uint64_t content_bytes;
    uint32_t num_chunks;
    uint32_t chunk_size;
    uint8_t filename[STATE_OFFER_NAME_MAX];
    uint16_t filename_len;
};

static char g_datadir[1024];
static struct node_db *g_ndb;
static bool g_have_identity;
static uint8_t g_online_seed[32];

static struct sosvc_artifact g_artifacts[STATE_OFFER_MAX_PER_PEER];
static uint32_t g_artifact_count;
static int64_t g_snapshot_unix;
static bool g_snapshot_valid;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_fetch_thread;
static bool g_fetch_running;
static bool g_fetch_started;
static bool g_fallback_raised;
static struct state_offer_record g_fetch_target;

static int64_t sosvc_now_unix(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static int64_t sosvc_now_ms(void)
{
    return platform_time_monotonic_ms();
}

/* This node's MMB peaks digest at its own tip — the accumulator a phase-2
 * sampling proof samples from. Read from the same durable state key the
 * snapshot offer path already reads (engine/services/src/snapshot_offer.c), so
 * there is one answer to "what is our MMB root" and not two. */
static bool sosvc_mmb_peaks_digest(uint8_t out[32])
{
    uint8_t buf[MMB_SERIALIZED_MAX];
    size_t len = 0;
    struct mmb m;

    if (!g_ndb || !g_ndb->open)
        return false;
    memset(buf, 0, sizeof(buf));
    if (!node_db_state_get(g_ndb, "mmb_state", buf, sizeof(buf), &len) ||
        len < 13 || !mmb_deserialize(&m, buf, len) || m.num_leaves == 0)
        return false;
    mmb_root(&m, out);
    for (size_t i = 0; i < 32; i++)
        if (out[i] != 0)
            return true;
    return false;
}

/* Read the height, block hash and mint identity out of one bundle file. This is
 * the only reason the producer touches disk, and why the result is cached. */
static bool sosvc_read_manifest(const char *path, int32_t *out_height,
                                uint8_t out_block_hash[32],
                                uint8_t out_receipt_id[32])
{
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct zcl_result r =
        consensus_state_artifact_evidence_open(path, -1, &evidence);
    if (!r.ok || !evidence) {
        if (evidence)
            consensus_state_artifact_evidence_free(evidence);
        return false;
    }
    struct consensus_state_bundle_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    bool ok = consensus_state_artifact_evidence_manifest_copy(evidence,
                                                              &manifest);
    consensus_state_artifact_evidence_free(evidence);
    if (!ok || manifest.height <= 0)
        return false;
    *out_height = manifest.height;
    memcpy(out_block_hash, manifest.block_hash, 32);
    /* The mint's logical artifact digest: stable for the bundle, distinct
     * across mints, and the natural dedup key for the same bundle offered by
     * several peers. */
    memcpy(out_receipt_id, manifest.artifact_digest, 32);
    return true;
}

/* Snapshot what this node holds and could offer. Caller holds g_lock. */
static void sosvc_refresh_snapshot_locked(void)
{
    struct rom_artifact artifacts[ROM_SEED_MAX_ARTIFACTS];
    memset(artifacts, 0, sizeof(artifacts));
    memset(g_artifacts, 0, sizeof(g_artifacts));
    g_artifact_count = 0;
    g_snapshot_unix = sosvc_now_unix();
    g_snapshot_valid = true;

    int n = rom_seed_list(artifacts, ROM_SEED_MAX_ARTIFACTS);
    if (n <= 0)
        return;

    for (int i = 0; i < n && g_artifact_count < STATE_OFFER_MAX_PER_PEER; i++) {
        const struct rom_artifact *a = &artifacts[i];
        if (!a->used || a->kind != ROM_ARTIFACT_CONSENSUS_BUNDLE)
            continue;
        if (a->chunk_size != ROM_SEED_CHUNK_SIZE || a->num_chunks == 0)
            continue;
        if (a->filename[0] == '\0' ||
            strlen(a->filename) >= STATE_OFFER_NAME_MAX)
            continue;

        char path[1024];
        if (snprintf(path, sizeof(path), "%s/bundles/%s", g_datadir,
                     a->filename) >= (int)sizeof(path))
            continue;
        int32_t height = 0;
        uint8_t block_hash[32], receipt_id[32];
        if (!sosvc_read_manifest(path, &height, block_hash, receipt_id)) {
            LOG_INFO(SOSVC_SUBSYS,
                     "holding '%s' but its manifest does not open — not "
                     "offered (a bundle we cannot describe is one we must not "
                     "advertise)", a->filename);
            continue;
        }

        struct sosvc_artifact *s = &g_artifacts[g_artifact_count];
        s->used = true;
        s->bundle_height = height;
        memcpy(s->header_hash, block_hash, 32);
        memcpy(s->content_digest, a->whole_sha3, 32);
        memcpy(s->chunk_root, a->chunk_root, 32);
        memcpy(s->producer_receipt_id, receipt_id, 32);
        s->content_bytes = a->size_bytes;
        s->num_chunks = a->num_chunks;
        s->chunk_size = a->chunk_size;
        s->filename_len = (uint16_t)strlen(a->filename);
        memcpy(s->filename, a->filename, s->filename_len);
        g_artifact_count++;
    }
    LOG_INFO(SOSVC_SUBSYS, "offerable bundles: %u of %d registered artifacts",
             g_artifact_count, n);
}

/* The provider net calls at the "zfileaddr" send site. */
static uint32_t sosvc_provide(struct state_offer_batch_v1 *out, void *ctx)
{
    (void)ctx;
    if (!out || !g_have_identity)
        return 0;

    int32_t tip = reducer_frontier_external_tip_height();
    if (tip <= 0)
        return 0;
    uint8_t peaks[32];
    if (!sosvc_mmb_peaks_digest(peaks))
        return 0; /* nothing to anchor a work proof to — say nothing */

    pthread_mutex_lock(&g_lock);
    if (!g_snapshot_valid ||
        sosvc_now_unix() - g_snapshot_unix >= SOSVC_SNAPSHOT_TTL_S)
        sosvc_refresh_snapshot_locked();

    out->version = STATE_OFFER_VERSION;
    out->flags = STATE_OFFER_FLAGS_NONE;
    out->offerer_tip_height = tip;
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_artifact_count && count < STATE_OFFER_MAX_PER_PEER;
         i++) {
        const struct sosvc_artifact *s = &g_artifacts[i];
        /* THE freshness rule, decided by the same function the parser and the
         * consumer call. A stale bundle is not offered at all — a stale offer
         * is worse than none, because it teaches the asker a wrong height. */
        if (!state_offer_height_is_fresh(s->bundle_height, tip))
            continue;

        struct state_offer_v1 *o = &out->offers[count];
        memset(o, 0, sizeof(*o));
        o->version = STATE_OFFER_VERSION;
        o->flags = STATE_OFFER_FLAGS_NONE;
        o->bundle_height = s->bundle_height;
        o->offerer_tip_height = tip;
        o->chunk_size = s->chunk_size;
        o->num_chunks = s->num_chunks;
        o->kind = (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE;
        memcpy(o->header_hash, s->header_hash, 32);
        memcpy(o->content_digest, s->content_digest, 32);
        memcpy(o->chunk_tree_root, s->chunk_root, 32);
        memcpy(o->mmb_peaks_digest, peaks, 32);
        memcpy(o->producer_receipt_id, s->producer_receipt_id, 32);
        o->content_bytes = s->content_bytes;
        o->issued_unix = (uint64_t)sosvc_now_unix();
        memcpy(o->filename, s->filename, sizeof(o->filename));
        o->filename_len = s->filename_len;
        /* Signed with the tip of the moment: the freshness claim is part of
         * what we sign, so we cannot be quoted later as having vouched for a
         * staleness we did not. */
        if (state_offer_v1_sign(o, g_online_seed) != STATE_OFFER_OK) {
            memset(o, 0, sizeof(*o));
            continue;
        }
        count++;
    }
    pthread_mutex_unlock(&g_lock);
    return count;
}

/* The sink net calls for each verified offer that arrives. */
static void sosvc_record(const struct state_offer_v1 *offer,
                         const uint8_t ip[16], uint16_t file_service_port,
                         int64_t peer_id, int64_t now_unix, void *ctx)
{
    (void)now_unix;
    (void)ctx;
    enum state_offer_store_result r = state_offer_store_record(
        offer, ip, file_service_port, peer_id, sosvc_now_ms());
    if (r != STATE_OFFER_STORE_KEPT && r != STATE_OFFER_STORE_KEPT_REPLACED)
        LOG_INFO(SOSVC_SUBSYS, "offer from peer %lld not retained (%s)",
                 (long long)peer_id, state_offer_store_result_string(r));
}

static bool sosvc_progress(uint32_t chunks_done, uint32_t num_chunks,
                           uint64_t bytes_done, void *ctx)
{
    const struct state_offer_v1 *offer = ctx;
    state_offer_store_note_fetch_progress(
        chunks_done, num_chunks, bytes_done,
        offer ? offer->content_bytes : 0);
    return true;
}

/* One download, on its own thread. Every check below already existed; this
 * function only chooses the arguments. */
static void *sosvc_fetch_main(void *arg)
{
    (void)arg;
    struct state_offer_record target = g_fetch_target;
    const struct state_offer_v1 *offer = &target.offer;

    char host[NET_ADDR_STR_MAX + 1];
    struct net_addr a;
    net_addr_init(&a);
    memcpy(a.ip, target.peer_ip, sizeof(a.ip));
    if (net_addr_to_string(&a, host, sizeof(host)) <= 0 || !host[0]) {
        LOG_WARN(SOSVC_SUBSYS, "chosen offer has no printable endpoint");
        state_offer_store_note_bad(offer->content_digest, target.peer_id);
        g_fetch_running = false;
        return NULL;
    }

    struct rom_fetch_manifest m;
    memset(&m, 0, sizeof(m));
    if (!state_offer_v1_filename(offer, m.filename, sizeof(m.filename))) {
        state_offer_store_note_bad(offer->content_digest, target.peer_id);
        g_fetch_running = false;
        return NULL;
    }
    m.used = true;
    m.size_bytes = offer->content_bytes;
    m.chunk_size = offer->chunk_size;
    m.num_chunks = offer->num_chunks;
    memcpy(m.chunk_root, offer->chunk_tree_root, 32);
    memcpy(m.whole_sha3, offer->content_digest, 32);
    m.kind = ROM_ARTIFACT_CONSENSUS_BUNDLE;
    m.height = offer->bundle_height;
    /* The existing sanity gate on the manifest we just built from a peer's
     * claim. If it refuses, the peer described something the fetch path would
     * never accept, and the dial is not worth making. */
    if (!rom_fetch_manifest_sane(&m)) {
        LOG_WARN(SOSVC_SUBSYS,
                 "chosen offer describes an artifact the fetch path refuses — "
                 "not dialled");
        state_offer_store_note_bad(offer->content_digest, target.peer_id);
        g_fetch_running = false;
        return NULL;
    }

    char out_dir[1024];
    if (snprintf(out_dir, sizeof(out_dir), "%s/bundles", g_datadir) >=
        (int)sizeof(out_dir)) {
        g_fetch_running = false;
        return NULL;
    }

    LOG_INFO(SOSVC_SUBSYS,
             "fetching offered bundle at height %ld (%llu bytes, %u chunks) "
             "from %s:%u — every chunk is verified against the offer's own "
             "chunk root before it is written",
             (long)offer->bundle_height,
             (unsigned long long)offer->content_bytes, offer->num_chunks, host,
             (unsigned)target.file_service_port);

    /* Per-chunk manifest, BOUND to the chunk root the offer committed to. A
     * seeder that cannot serve it is not an offence — it is the legacy reply,
     * and a bundle we cannot verify chunk by chunk is one we do not take in
     * phase 1a. */
    static uint8_t chunk_sha3[ROM_SEED_MAX_CHUNKS][32];
    uint32_t num_chunks = 0;
    bool ok = rom_fetch_get_manifest(host, target.file_service_port,
                                     m.chunk_root, chunk_sha3,
                                     ROM_SEED_MAX_CHUNKS, &num_chunks) &&
              num_chunks == m.num_chunks;
    if (ok)
        ok = rom_fetch_download_verified(host, target.file_service_port, &m,
                                         chunk_sha3, num_chunks, out_dir,
                                         sosvc_progress,
                                         (void *)&target.offer);
    if (!ok) {
        /* The bytes did not verify, or never arrived. rom_fetch has already
         * discarded them; the store refuses this digest for the rest of the
         * run and strikes the offerer, and the next offer is chosen. */
        LOG_WARN(SOSVC_SUBSYS,
                 "offered bundle at height %ld did not verify — discarded, "
                 "peer struck, trying the next offer",
                 (long)offer->bundle_height);
        state_offer_store_note_bad(offer->content_digest, target.peer_id);
        g_fetch_running = false;
        return NULL;
    }

    char landed[1200];
    if (snprintf(landed, sizeof(landed), "%s/%s", out_dir, m.filename) >=
        (int)sizeof(landed)) {
        g_fetch_running = false;
        return NULL;
    }
    /* Hand it to the UNCHANGED install path. Checkpoint re-derivation and
     * Sapling-root re-derivation decide whether this state is admissible; this
     * module has no opinion and no override. */
    if (boot_install_bundle_request(g_datadir, landed) != 0)
        LOG_WARN(SOSVC_SUBSYS,
                 "bundle landed at '%s' but the install request could not be "
                 "armed — the file is staged and the autodetect path will "
                 "still find it", landed);
    else
        LOG_INFO(SOSVC_SUBSYS,
                 "offered bundle at height %ld landed and armed for install — "
                 "no operator flag, no catalog, no configured file service",
                 (long)offer->bundle_height);
    g_fetch_running = false;
    return NULL;
}

void state_offer_service_wire(struct msg_processor *mp)
{
    if (!mp)
        return;
    msg_processor_set_state_offer_record(mp, sosvc_record, NULL);
}

void state_offer_service_start(const char *datadir, struct node_db *ndb)
{
    if (!datadir)
        return;
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir);
    g_ndb = ndb;
    g_snapshot_valid = false;
    g_artifact_count = 0;
    g_fetch_started = false;
    g_fetch_running = false;
    g_fallback_raised = false;

    uint8_t pubkey[32];
    char err[160];
    err[0] = '\0';
    g_have_identity = vcs_zcode_dht_online_key_load(datadir, g_online_seed,
                                                    pubkey, err, sizeof(err));
    if (!g_have_identity)
        LOG_INFO(SOSVC_SUBSYS,
                 "no online identity (%s) — this node consumes state offers "
                 "but makes none; nothing is silently provisioned",
                 err[0] ? err : "not present");

    state_offer_set_provider(sosvc_provide, NULL);
}

void state_offer_service_shutdown(void)
{
    state_offer_set_provider(NULL, NULL);
    if (g_fetch_started) {
        pthread_join(g_fetch_thread, NULL);
        g_fetch_started = false;
    }
    g_have_identity = false;
    memset(g_online_seed, 0, sizeof(g_online_seed));
    g_snapshot_valid = false;
    g_ndb = NULL;
}

void state_offer_service_tick(void)
{
    int64_t now_ms = sosvc_now_ms();
    state_offer_store_note_first_peer(now_ms);

    if (g_fetch_running)
        return;
    /* A finished thread is joined before another can start, so exactly one
     * download exists at a time and none is ever abandoned. */
    if (g_fetch_started) {
        pthread_join(g_fetch_thread, NULL);
        g_fetch_started = false;
    }

    struct state_offer_record chosen;
    enum state_offer_decision decision =
        state_offer_store_decide(now_ms, &chosen);
    if (decision == STATE_OFFER_DECIDE_FALL_BACK && !g_fallback_raised) {
        /* Raised ONCE, the moment the wait closes: the node is folding forward
         * from whatever it has, and an operator is entitled to read why and
         * how stale their peers were rather than infer it from a silent
         * genesis fold. The condition owns the clear. */
        g_fallback_raised = true;
        struct state_offer_store_status st;
        state_offer_store_status_get(&st);
        struct stale_offers_only_facts f = {
            .newest_height_seen = st.newest_height_seen,
            .peers_offering = st.peers_offering,
            .offers_seen = st.offers_seen,
            .baseline_hstar = reducer_frontier_provable_tip_cached(),
        };
        stale_offers_only_raise(&f);
    }
    if (decision != STATE_OFFER_DECIDE_FETCH)
        return;

    g_fetch_target = chosen;
    state_offer_store_note_fetching(chosen.offer.content_digest);
    g_fetch_running = true;
    if (pthread_create(&g_fetch_thread, NULL, sosvc_fetch_main, NULL) != 0) {
        g_fetch_running = false;
        LOG_WARN(SOSVC_SUBSYS, "could not start the offer fetch thread");
        return;
    }
    g_fetch_started = true;
}

#ifdef ZCL_TESTING
void state_offer_service_test_invalidate(void)
{
    pthread_mutex_lock(&g_lock);
    g_snapshot_valid = false;
    pthread_mutex_unlock(&g_lock);
}
#endif
