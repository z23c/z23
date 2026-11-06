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
#include "config/boot_consensus_bundle_marker.h"
#include "storage/progress_store.h"
#include "config/state_offer_peer.h"
#include "config/state_offer_link_session.h"
#include "config/state_offer_link_receive.h"
#include "conditions/stale_offers_only.h"

#include "platform/time_compat.h"

#include "base/cleanse.h"
#include "chain/mmb.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "models/database.h"
#include "net/msgprocessor.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "net/netaddr.h"
#include "net/state_offer.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/log_macros.h"
#include "util/path_leaf.h"
#include "util/thread_registry.h"
#include "vcs/zcode_dht_identity.h"

#include <errno.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
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
static uint32_t g_identity_gap_warn_count;
static bool g_identity_gap_logged;

static struct sosvc_artifact g_artifacts[STATE_OFFER_MAX_PER_PEER];
static uint32_t g_artifact_count;
static int g_snapshot_registry_count;
static int64_t g_snapshot_unix;
static bool g_snapshot_valid;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_fetch_thread;
static _Atomic bool g_fetch_running;
static bool g_fetch_started;
static bool g_fetch_staged;
static bool g_fallback_raised;
static struct state_offer_record g_fetch_target;
static _Atomic bool g_fetch_stopping;
static enum sol_receive_result g_fetch_result;
static struct { uint32_t done, total; uint64_t bytes, size; bool dirty; } g_fetch_progress;

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

#ifdef ZCL_TESTING
static _Atomic uint32_t g_test_opens;
static state_offer_service_test_reader_fn g_test_reader;
#endif

/* Read the height, block hash and mint identity out of one bundle file. This is
 * the only reason the producer touches disk, and why the result is cached. */
static bool sosvc_read_manifest(const char *path, int32_t *out_height,
                                uint8_t out_block_hash[32],
                                uint8_t out_receipt_id[32])
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_opens, 1);
    if (g_test_reader)
        return g_test_reader(path, out_height, out_block_hash, out_receipt_id);
#endif
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

/* Compose the absolute path rom_seed's own read path resolves for a
 * registered artifact: `g_datadir` + "/" + `filename`. `filename` already
 * carries any "bundles/" prefix rom_seed_register stored it under — a
 * root-scan artifact is a bare basename, while the bundles/ subdir scan and
 * every reseed caller (boot_bundle_fetch.c, bundle_exporter.c) register it as
 * "ROM_SEED_BUNDLES_SUBDIR/<name>" (see net/rom_seed.h) — so no second
 * "bundles/" belongs here; rom_seed_read_chunk (net/rom_seed.c) and
 * platform_positioned_file_open_beneath() resolve the SAME `datadir` + "/" +
 * `filename` shape, and this is the one place in this file that repeats it,
 * so the two paths cannot re-drift. */
static bool sosvc_artifact_path(char *out, size_t out_sz, const char *filename)
{
    int n = snprintf(out, out_sz, "%s/%s", g_datadir, filename);
    return n > 0 && (size_t)n < out_sz;
}
/* The part of stat() that says "this is still the same file, unmodified". */
struct sosvc_file_id {
    uint64_t dev;
    uint64_t ino;
    int64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
};

static bool sosvc_file_id_read(const char *path, struct sosvc_file_id *id)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    id->dev = (uint64_t)st.st_dev;
    id->ino = (uint64_t)st.st_ino;
    id->size = (int64_t)st.st_size;
    id->mtime_sec = (int64_t)st.st_mtime;
#ifdef _WIN32
    id->mtime_nsec = 0;
#else
    id->mtime_nsec = (int64_t)st.st_mtim.tv_nsec;
#endif
    return true;
}


/* One artifact whose bundle manifest this file already opened and validated.
 * The key is everything that can change while the answer stays the same:
 * the catalog identity rom_seed hashed at registration (filename, whole-file
 * SHA3, size, chunk root) plus the file's own stat identity, so a replaced or
 * rewritten file misses and is validated again. Only successful opens are
 * cached; a failed open is retried on every refresh (it logs, and it is the
 * rare case). Touched only by the single refresher (g_refreshing), never under
 * g_lock. */
struct sosvc_manifest_cache {
    bool used;
    char filename[ROM_SEED_NAME_MAX];
    uint8_t whole_sha3[32];
    uint8_t chunk_root[32];
    uint64_t size_bytes;
    struct sosvc_file_id id;
    int32_t height;
    uint8_t block_hash[32];
    uint8_t receipt_id[32];
};

static struct sosvc_manifest_cache g_mcache[STATE_OFFER_MAX_PER_PEER];
static struct sosvc_manifest_cache g_mcache_next[STATE_OFFER_MAX_PER_PEER];
static struct sosvc_artifact g_build[STATE_OFFER_MAX_PER_PEER];
static bool g_refreshing;

static bool sosvc_cache_key_matches(const struct sosvc_manifest_cache *c,
                                    const struct rom_artifact *a,
                                    const struct sosvc_file_id *id)
{
    return c->used && strcmp(c->filename, a->filename) == 0 &&
           memcmp(c->whole_sha3, a->whole_sha3, 32) == 0 &&
           memcmp(c->chunk_root, a->chunk_root, 32) == 0 &&
           c->size_bytes == a->size_bytes && c->id.dev == id->dev &&
           c->id.ino == id->ino && c->id.size == id->size &&
           c->id.mtime_sec == id->mtime_sec &&
           c->id.mtime_nsec == id->mtime_nsec;
}

static const struct sosvc_manifest_cache *
sosvc_cache_find(const struct rom_artifact *a, const struct sosvc_file_id *id)
{
    for (size_t i = 0; i < STATE_OFFER_MAX_PER_PEER; i++)
        if (sosvc_cache_key_matches(&g_mcache[i], a, id))
            return &g_mcache[i];
    return NULL;
}

/* Is this registered artifact something the offer path could ever describe? */

static bool sosvc_artifact_eligible(const struct rom_artifact *a)
{
    return a->used && a->kind == ROM_ARTIFACT_CONSENSUS_BUNDLE &&
           a->chunk_size == ROM_SEED_CHUNK_SIZE && a->num_chunks != 0 &&
           zcl_path_leaf(a->filename)[0] != '\0' &&
           strlen(zcl_path_leaf(a->filename)) < STATE_OFFER_NAME_MAX;
}

enum sosvc_resolve { SOSVC_RESOLVE_FAILED, SOSVC_RESOLVE_CACHED,
                     SOSVC_RESOLVE_OPENED, SOSVC_RESOLVE_ABORT };

/* Height, block hash and receipt id of one artifact: from the cache when the
 * key still matches, else by opening and validating the bundle. The open is
 * skipped (ABORT) once shutdown has been asked for, so shutdown never waits on
 * a fresh validation. On a cache hit or an open, `*next` is the entry to carry
 * into the next cache generation. */
static enum sosvc_resolve sosvc_resolve_manifest(
    const struct rom_artifact *a, const char *path,
    struct sosvc_manifest_cache *next)
{
    struct sosvc_file_id id;
    bool have_stat = sosvc_file_id_read(path, &id);
    const struct sosvc_manifest_cache *hit =
        have_stat ? sosvc_cache_find(a, &id) : NULL;
    if (hit) {
        *next = *hit;
        return SOSVC_RESOLVE_CACHED;
    }
    if (thread_registry_shutdown_requested())
        return SOSVC_RESOLVE_ABORT;
    memset(next, 0, sizeof(*next));
    if (!sosvc_read_manifest(path, &next->height, next->block_hash,
                             next->receipt_id))
        return SOSVC_RESOLVE_FAILED;
    next->used = have_stat;
    snprintf(next->filename, sizeof(next->filename), "%s", a->filename);
    memcpy(next->whole_sha3, a->whole_sha3, 32);
    memcpy(next->chunk_root, a->chunk_root, 32);
    next->size_bytes = a->size_bytes;
    if (have_stat)
        next->id = id;
    return SOSVC_RESOLVE_OPENED;
}

static void sosvc_fill_artifact(struct sosvc_artifact *s,
                                const struct rom_artifact *a,
                                const struct sosvc_manifest_cache *m)
{
    memset(s, 0, sizeof(*s));
    s->used = true;
    s->bundle_height = m->height;
    memcpy(s->header_hash, m->block_hash, 32);
    memcpy(s->content_digest, a->whole_sha3, 32);
    memcpy(s->chunk_root, a->chunk_root, 32);
    memcpy(s->producer_receipt_id, m->receipt_id, 32);
    s->content_bytes = a->size_bytes;
    s->num_chunks = a->num_chunks;
    s->chunk_size = a->chunk_size;
    const char *name = zcl_path_leaf(a->filename);
    s->filename_len = (uint16_t)strlen(name);
    memcpy(s->filename, name, s->filename_len);
}

struct sosvc_refresh_tally {
    uint32_t built;
    uint32_t opened;
    uint32_t cached;
    bool aborted;
};

/* Build the offerable set into g_build / g_mcache_next. Takes no lock and may
 * open bundles; only the one refresher (g_refreshing) runs it. */
static int sosvc_build_snapshot(struct sosvc_refresh_tally *t)
{
    static struct rom_artifact artifacts[ROM_SEED_MAX_ARTIFACTS];
    memset(artifacts, 0, sizeof(artifacts));
    memset(g_build, 0, sizeof(g_build));
    memset(g_mcache_next, 0, sizeof(g_mcache_next));
    int n = rom_seed_list(artifacts, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < n && t->built < STATE_OFFER_MAX_PER_PEER; i++) {
        const struct rom_artifact *a = &artifacts[i];
        char path[1024];
        if (!sosvc_artifact_eligible(a) ||
            !sosvc_artifact_path(path, sizeof(path), a->filename))
            continue;
        struct sosvc_manifest_cache *next = &g_mcache_next[t->built];
        enum sosvc_resolve r = sosvc_resolve_manifest(a, path, next);
        if (r == SOSVC_RESOLVE_ABORT) {
            t->aborted = true;
            break;
        }
        if (r == SOSVC_RESOLVE_FAILED) {
            /* Named, once per refresh (this loop runs on the snapshot TTL,
             * never per peer) — say the exact path tried so a missing or
             * unreadable bundle is diagnosable from this one line. */
            LOG_INFO(SOSVC_SUBSYS,
                     "holding '%s' but '%s' does not open as a bundle "
                     "manifest — not offered (a bundle we cannot describe is "
                     "one we must not advertise)", a->filename, path);
            continue;
        }
        sosvc_fill_artifact(&g_build[t->built], a, next);
        t->built++;
        if (r == SOSVC_RESOLVE_CACHED)
            t->cached++;
        else
            t->opened++;
    }
    return n;
}

/* Count changes refresh promptly; same-count replacement waits for the TTL. Caller holds g_lock. */
static bool sosvc_refresh_due_locked(int registry_count)
{
    return !g_snapshot_valid || registry_count != g_snapshot_registry_count ||
           sosvc_now_unix() - g_snapshot_unix >= SOSVC_SNAPSHOT_TTL_S;
}

/* Rebuild the snapshot WITHOUT holding g_lock while bundles are opened, then
 * take it only to swap the result in. `force` ignores the TTL (test hook). If
 * another refresh is already running this returns at once and the caller keeps
 * using the current snapshot. Called from the peer-link tick only (and the
 * test hook): sosvc_provide, on the same message thread, never refreshes. */
static void sosvc_refresh_snapshot(bool force)
{
    int registry_count = rom_seed_count();
    pthread_mutex_lock(&g_lock);
    if (g_refreshing || (!force && !sosvc_refresh_due_locked(registry_count))) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    g_refreshing = true;
    pthread_mutex_unlock(&g_lock);

    int64_t t0 = sosvc_now_ms();
    struct sosvc_refresh_tally t = {0};
    int n = sosvc_build_snapshot(&t);

    pthread_mutex_lock(&g_lock);
    if (!t.aborted) {
        memcpy(g_artifacts, g_build, sizeof(g_artifacts));
        g_artifact_count = t.built;
        g_snapshot_unix = sosvc_now_unix();
        g_snapshot_valid = true;
        g_snapshot_registry_count = n;
        memcpy(g_mcache, g_mcache_next, sizeof(g_mcache));
    }
    g_refreshing = false;
    pthread_mutex_unlock(&g_lock);
    if (!t.aborted)
        LOG_INFO(SOSVC_SUBSYS,
                 "offerable bundles: %u of %d registered artifacts "
                 "(opened=%u cached=%u, %lld ms)", t.built, n, t.opened,
                 t.cached, (long long)(sosvc_now_ms() - t0));
}

/* Does this node hold something it would actually offer at `tip`? Caller holds
 * g_lock. The SAME rule the producer filters with, called from the same header,
 * so "we may sign" and "we may offer" can never drift apart. */
static bool sosvc_has_offerable_artifact_locked(int32_t tip)
{
    for (uint32_t i = 0; i < g_artifact_count; i++)
        if (state_offer_height_is_fresh(g_artifacts[i].bundle_height, tip))
            return true;
    return false;
}

/* One WARN per gap: the first failed mint of an offerable-without-identity gap
 * logs; the retries on later ticks stay quiet until the gap closes. */
static bool sosvc_identity_gap_open(void)
{
    pthread_mutex_lock(&g_lock);
    bool first = !g_identity_gap_logged;
    g_identity_gap_logged = true;
    if (first)
        g_identity_gap_warn_count++;
    pthread_mutex_unlock(&g_lock);
    return first;
}

/* THE GAP THIS CLOSES. A node that registers and serves a 513 MB consensus
 * bundle still appended NO offer batch to its "zfileaddr" messages, because
 * state_offer_service_start() LOADS the durable online identity and nothing in
 * boot ever CREATES it: the only vcs_zcode_dht_online_key_load_or_create()
 * caller is the fleet board (engine/composition/src/boot_fleet_board.c), lazily,
 * on the first board post. On a plain hosted node the key file is absent, so
 * sosvc_provide returned 0 for the life of the process and a stranger heard
 * nothing but a port. Every hosted node served the bundle; nobody could find it.
 *
 * FAIL CLOSED, AND ONLY FOR SOMETHING WE HOLD. The key is minted only once this
 * node actually holds a bundle it would offer — a registered ROM artifact whose
 * manifest opens and whose height passes state_offer_height_is_fresh() against
 * our own tip (which exempts the compiled checkpoint height by design,
 * core/modules/net/src/state_offer.c). A node with nothing to offer mints
 * nothing and writes no file, exactly as before.
 *
 * WHAT IS AND IS NOT PROVISIONED. This is the node's OWN durable Ed25519 online
 * identity — the same key file, created by the same function, that the fleet
 * board already creates on demand. No new key, no new key file, no second
 * identity. It authenticates the offer on the wire; it grants nothing. Trust
 * still binds where it always did: the RMF per-chunk digests, the whole-file
 * SHA3, and the installer's CHECKPOINT_ROM re-derivation against the compiled
 * checkpoint.
 *
 * WHERE IT RUNS. On the peer-link tick, not the offer send path. The tick is
 * also the ONLY place the artifact snapshot is refreshed (every
 * SOSVC_SNAPSHOT_TTL_S, and cheaply: an unchanged bundle is a cache hit, see
 * sosvc_refresh_snapshot), so the send path never opens a bundle. */
static void sosvc_ensure_offering_identity(int32_t tip)
{
    if (!g_datadir[0] || tip <= 0)
        return;
    sosvc_refresh_snapshot(false);

    pthread_mutex_lock(&g_lock);
    bool have = g_have_identity;
    bool offerable = !have && sosvc_has_offerable_artifact_locked(tip);
    bool cleared = g_identity_gap_logged && !offerable;
    if (cleared)
        g_identity_gap_logged = false;
    pthread_mutex_unlock(&g_lock);
    if (cleared)
        LOG_INFO(SOSVC_SUBSYS,
                 "offer identity gap closed: no offerable bundle is held without "
                 "an online identity any more");
    if (have || !offerable)
        return; /* nothing to advertise — mint nothing, write nothing */

    uint8_t seed[32], pubkey[32];
    char err[160];
    err[0] = '\0';
    if (!vcs_zcode_dht_online_key_load_or_create(g_datadir, seed, pubkey, err,
                                                 sizeof(err))) {
        bool first = sosvc_identity_gap_open();
        if (first)
            LOG_WARN(SOSVC_SUBSYS,
                     "holding an offerable bundle but this node has no online "
                     "identity to sign an offer with (%s) — peers will hear our "
                     "file-service port and no state offer",
                     err[0] ? err : "unknown reason");
        memory_cleanse(seed, sizeof(seed));
        return;
    }

    pthread_mutex_lock(&g_lock);
    memcpy(g_online_seed, seed, sizeof(g_online_seed));
    g_have_identity = true;
    g_identity_gap_logged = false;
    pthread_mutex_unlock(&g_lock);
    memory_cleanse(seed, sizeof(seed));
    LOG_INFO(SOSVC_SUBSYS,
             "online identity ready — this node now advertises the consensus "
             "bundle it holds in its zfileaddr handshakes, so a fresh peer can "
             "find a state source with no operator flag");
}

bool state_offer_service_advertising(void)
{
    int32_t tip = reducer_frontier_external_tip_height();
    /* Reads the CACHED snapshot only — a status caller must never drive the
     * disk scan that opens bundle manifests. */
    pthread_mutex_lock(&g_lock);
    bool advertising = g_have_identity && tip > 0 && g_snapshot_valid &&
                       sosvc_has_offerable_artifact_locked(tip);
    pthread_mutex_unlock(&g_lock);
    return advertising;
}

/* Compose the batch from the CURRENT snapshot. It never refreshes it and never
 * opens a bundle: the snapshot is rebuilt on the peer-link tick, which runs on
 * the same message thread as the send site, so one more refresh trigger here
 * would only add a second place that could stall that thread. An expired TTL
 * means the offers are built from a snapshot at most one tick older than it
 * would otherwise be, and every offer is signed with the tip of the moment. */
static uint32_t sosvc_provide_from_snapshot(struct state_offer_batch_v1 *out,
                                            int32_t tip,
                                            const uint8_t peaks[32])
{
    pthread_mutex_lock(&g_lock);
    /* Read the identity flag under the same lock the tick sets it under: the
     * offering identity is minted on the peer-link tick (see
     * sosvc_ensure_offering_identity), so this net-thread reader must not see
     * `have identity` before the seed it signs with. */
    if (!g_have_identity) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
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

/* The provider net calls at the "zfileaddr" send site. */
static uint32_t sosvc_provide(struct state_offer_batch_v1 *out, void *ctx)
{
    (void)ctx;
    if (!out)
        return 0;

    int32_t tip = reducer_frontier_external_tip_height();
    if (tip <= 0)
        return 0;
    uint8_t peaks[32];
    if (!sosvc_mmb_peaks_digest(peaks))
        return 0; /* nothing to anchor a work proof to — say nothing */
    return sosvc_provide_from_snapshot(out, tip, peaks);
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
    pthread_mutex_lock(&g_lock);
    g_fetch_progress.done = chunks_done;
    g_fetch_progress.total = num_chunks;
    g_fetch_progress.bytes = bytes_done;
    g_fetch_progress.size = offer ? offer->content_bytes : 0;
    g_fetch_progress.dirty = true;
    pthread_mutex_unlock(&g_lock);
    return !atomic_load(&g_fetch_stopping);
}
static bool sosvc_manifest(const struct state_offer_v1 *o, struct rom_fetch_manifest *m)
{
    memset(m, 0, sizeof(*m));
    if (!state_offer_v1_filename(o, m->filename, sizeof(m->filename))) return false;
    m->used = true; m->size_bytes = o->content_bytes; m->chunk_size = o->chunk_size;
    m->num_chunks = o->num_chunks; m->kind = ROM_ARTIFACT_CONSENSUS_BUNDLE;
    m->height = o->bundle_height;
    memcpy(m->chunk_root, o->chunk_tree_root, 32);
    memcpy(m->whole_sha3, o->content_digest, 32);
    return rom_fetch_manifest_sane(m);
}
static bool sosvc_bundles(char *out, size_t cap)
{
    if (snprintf(out, cap, "%s/bundles", g_datadir) >= (int)cap) return false;
#if defined(_WIN32)
    return true; /* Preserve the existing pathname-based IP fetch on Windows. */
#else
    if (mkdir(out, 0700) && errno != EEXIST) return false;
    struct stat st;
    return !lstat(out, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 0022);
#endif
}
static enum sol_receive_result sosvc_fetch_ip(const struct state_offer_record *target,
    const struct rom_fetch_manifest *m, const char *out_dir, char *landed, size_t cap)
{
    char host[NET_ADDR_STR_MAX + 1]; struct net_addr a;
    net_addr_init(&a); memcpy(a.ip, target->peer_ip, sizeof(a.ip));
    if (net_addr_to_string(&a, host, sizeof(host)) <= 0 || !host[0]) return SOL_RECEIVE_UNAVAILABLE;
    static uint8_t hashes[ROM_SEED_MAX_CHUNKS][32]; uint32_t count = 0;
    if (!rom_fetch_get_manifest(host, target->file_service_port, m->chunk_root,
                                hashes, ROM_SEED_MAX_CHUNKS, &count) || count != m->num_chunks)
        return SOL_RECEIVE_UNAVAILABLE;
    if (!rom_fetch_download_verified(host, target->file_service_port, m, hashes, count,
                                      out_dir, sosvc_progress, (void *)&target->offer))
        return atomic_load(&g_fetch_stopping) ? SOL_RECEIVE_CANCELLED : SOL_RECEIVE_UNAVAILABLE;
    return snprintf(landed, cap, "%s/%s", out_dir, m->filename) < (int)cap ? SOL_RECEIVE_OK : SOL_RECEIVE_LOCAL_IO;
}
static enum sol_receive_result sosvc_fetch_link(const struct state_offer_record *target,
    const struct rom_fetch_manifest *m, const char *out_dir, char *landed, size_t cap)
{
    if (target->peer_id < 0 || target->peer_id == INT64_MAX) return SOL_RECEIVE_UNAVAILABLE;
    uint64_t peer = (uint64_t)target->peer_id + 1;
    pthread_mutex_lock(&g_lock);
    bool started = !atomic_load(&g_fetch_stopping) && state_offer_peer_begin(peer);
    pthread_mutex_unlock(&g_lock);
    if (!started) return SOL_RECEIVE_UNAVAILABLE;
    enum sol_receive_result r = state_offer_link_receive(m, out_dir, sol_client_read, &peer,
        sosvc_progress, (void *)&target->offer, landed, cap);
    state_offer_peer_end(peer);
    return r;
}
static void *sosvc_fetch_main(void *arg)
{
    (void)arg;
    struct state_offer_record target = g_fetch_target;
    struct rom_fetch_manifest m; char out_dir[1024], landed[1200];
    enum sol_receive_result r = SOL_RECEIVE_BAD_DATA;
    if (sosvc_manifest(&target.offer, &m)) {
        r = SOL_RECEIVE_LOCAL_IO;
        if (sosvc_bundles(out_dir, sizeof(out_dir)))
            r = target.peer_link ? sosvc_fetch_link(&target, &m, out_dir, landed, sizeof(landed)) :
                sosvc_fetch_ip(&target, &m, out_dir, landed, sizeof(landed));
    }
    if (r == SOL_RECEIVE_OK && !atomic_load(&g_fetch_stopping)) {
        if (boot_install_bundle_request(g_datadir, landed) <= 0) {
            LOG_WARN(SOSVC_SUBSYS, "verified bundle staged but install request could not be armed");
            r = SOL_RECEIVE_LOCAL_IO;
        }
    }
    g_fetch_result = r;
    atomic_store(&g_fetch_running, false);
    return NULL;
}
static void sosvc_drain_progress(void)
{
    pthread_mutex_lock(&g_lock);
    uint32_t done = g_fetch_progress.done, total = g_fetch_progress.total;
    uint64_t bytes = g_fetch_progress.bytes, size = g_fetch_progress.size;
    bool dirty = g_fetch_progress.dirty;
    g_fetch_progress.dirty = false;
    pthread_mutex_unlock(&g_lock);
    if (dirty) state_offer_store_note_fetch_progress(done, total, bytes, size);
}
static const char *sosvc_receive_name(enum sol_receive_result r)
{
    static const char *const names[] = {"ok", "unavailable", "bad-data", "cancelled", "local-io"};
    return (unsigned)r < sizeof(names) / sizeof(names[0]) ? names[r] : "unknown";
}
/* One line per fetch start and end: run F fell back with no trace of either. */
static void sosvc_log_fetch(const char *what, const struct state_offer_record *t, const char *result)
{
    LOG_INFO(SOSVC_SUBSYS, "bundle fetch %s: h=%d peer %lld over %s%s%s", what,
             (int)t->offer.bundle_height, (long long)t->peer_id,
             t->peer_link ? "peer link" : "file service", result ? " result=" : "",
             result ? result : "");
}
static void sosvc_finish_fetch(void)
{
    pthread_join(g_fetch_thread, NULL);
    g_fetch_started = false;
    sosvc_log_fetch("ended", &g_fetch_target, sosvc_receive_name(g_fetch_result));
    if (g_fetch_result == SOL_RECEIVE_OK) g_fetch_staged = true;
    if (g_fetch_result == SOL_RECEIVE_BAD_DATA) {
        if (g_fetch_target.peer_link)
            state_offer_store_note_link_bad(g_fetch_target.offer.content_digest, g_fetch_target.peer_id);
        else state_offer_store_note_bad(g_fetch_target.offer.content_digest, g_fetch_target.peer_id);
    } else if (g_fetch_result != SOL_RECEIVE_OK) {
        if (g_fetch_target.peer_link)
            state_offer_store_note_link_retry(g_fetch_target.offer.content_digest, g_fetch_target.peer_id, sosvc_now_ms());
        else state_offer_store_note_retry(g_fetch_target.offer.content_digest, sosvc_now_ms());
    }
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
    memset(g_mcache, 0, sizeof(g_mcache));
    g_refreshing = false;
    g_artifact_count = 0;
    g_fetch_started = false;
    g_fetch_staged = false;
    g_fetch_running = false;
    g_fallback_raised = false;
    atomic_store(&g_fetch_stopping, false);
    g_fetch_result = SOL_RECEIVE_UNAVAILABLE;
    memset(&g_fetch_progress, 0, sizeof(g_fetch_progress));
    if (!state_offer_peer_start(datadir))
        LOG_WARN(SOSVC_SUBSYS, "peer-link service could not start");

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
    pthread_mutex_lock(&g_lock);
    atomic_store(&g_fetch_stopping, true);
    sol_client_shutdown();
    pthread_mutex_unlock(&g_lock);
    state_offer_peer_shutdown();
    if (g_fetch_started) {
        pthread_join(g_fetch_thread, NULL);
        g_fetch_started = false;
    }
    pthread_mutex_lock(&g_lock);
    g_identity_gap_logged = false;
    pthread_mutex_unlock(&g_lock);
    g_have_identity = false;
    memset(g_online_seed, 0, sizeof(g_online_seed));
    g_snapshot_valid = false;
    g_ndb = NULL;
}

/* What this node already holds. Height is reducer_frontier_external_tip_height
 * (published H* once warm, else the durable tip_finalize witness read from the
 * progress store at boot), NOT active_chain_height (a lookahead number that is
 * 0 until headers load). That getter returns 0 both for a fresh datadir and
 * when it cannot read, so an unreadable progress store with H* unpublished is
 * reported UNKNOWN and fails towards not fetching. */
/* The last chosen offer's partial download still has its journal in bundles/
 * (the next fetch resumes from it) and link bytes arrived inside the progress
 * window: a source is still delivering. Owner tick only (reads the target). */
static bool sosvc_resume_progressing(void)
{
    int64_t last = sol_client_last_progress_ms();
    if (last == INT64_MIN ||
        platform_time_monotonic_ms() - last >= STATE_OFFER_FETCH_PROGRESS_WINDOW_MS)
        return false;
    char name[ROM_FETCH_NAME_MAX], path[1400];
    struct stat st;
    return g_datadir[0] && g_fetch_target.offer.bundle_height > 0 &&
           state_offer_v1_filename(&g_fetch_target.offer, name, sizeof(name)) &&
           snprintf(path, sizeof(path), "%s/bundles/%s.part.journal", g_datadir, name) <
               (int)sizeof(path) &&
           stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void sosvc_local_need(struct state_offer_need *need)
{
    need->resume_progressing = sosvc_resume_progressing();
    need->marker_present =
        g_datadir[0] && boot_consensus_bundle_marker_exists(g_datadir);
    int32_t h = reducer_frontier_external_tip_height();
    need->height_known = h > 0 || reducer_frontier_provable_tip_is_published() ||
                         progress_store_db() != NULL;
    need->local_height = h > 0 ? h : 0;
    /* A from-genesis or from-anchor refold (refold_in_progress is set by both)
     * is deliberately self-derived and sits at a low height for hours with no
     * marker; it must never take an offered bundle. Report it as unknown so it
     * takes the existing fail-towards-not-fetching path. */
    if (refold_in_progress())
        need->height_known = false;
}

void state_offer_service_tick(void)
{
    int64_t now_ms = sosvc_now_ms();
    sosvc_drain_progress();
    state_offer_store_note_first_peer(now_ms);
    /* Producer side: make sure a node that HOLDS a bundle can actually say so.
     * It also refreshes the artifact snapshot every SOSVC_SNAPSHOT_TTL_S (a
     * cache hit for an unchanged bundle); the identity itself is set once. */
    sosvc_ensure_offering_identity(reducer_frontier_external_tip_height());

    if (g_fetch_running)
        return;
    /* A finished thread is joined before another can start, so exactly one
     * download exists at a time and none is ever abandoned. */
    if (g_fetch_started) sosvc_finish_fetch();
    if (g_fetch_staged) return;

    struct state_offer_record chosen;
    struct state_offer_need need;
    sosvc_local_need(&need);
    enum state_offer_decision decision =
        state_offer_store_decide_for(now_ms, &chosen, &need);
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
            .rung_only = state_offer_store_height_filter_active(),
        };
        stale_offers_only_raise(&f);
    }
    if (decision != STATE_OFFER_DECIDE_FETCH)
        return;

    g_fetch_target = chosen;
    if (chosen.peer_link) state_offer_store_note_link_fetching(chosen.offer.content_digest, chosen.peer_id);
    else state_offer_store_note_fetching(chosen.offer.content_digest);
    g_fetch_running = true;
    if (pthread_create(&g_fetch_thread, NULL, sosvc_fetch_main, NULL) != 0) {
        g_fetch_running = false;
        if (chosen.peer_link) state_offer_store_note_link_retry(chosen.offer.content_digest, chosen.peer_id, now_ms);
        else state_offer_store_note_retry(chosen.offer.content_digest, now_ms);
        LOG_WARN(SOSVC_SUBSYS, "could not start the offer fetch thread");
        return;
    }
    g_fetch_started = true;
    sosvc_log_fetch("started", &chosen, NULL);
}

#ifdef ZCL_TESTING
void state_offer_service_test_local_need(struct state_offer_need *need)
{
    sosvc_local_need(need);
}

void state_offer_service_test_set_staged(bool staged) { g_fetch_staged = staged; }
bool state_offer_service_test_fetch_running_is_atomic(void)
{
    return _Generic(&g_fetch_running, _Atomic bool *: true, default: false);
}

void state_offer_service_test_invalidate(void)
{
    pthread_mutex_lock(&g_lock);
    g_snapshot_valid = false;
    pthread_mutex_unlock(&g_lock);
}

void state_offer_service_test_hold_artifact(int32_t bundle_height)
{
    pthread_mutex_lock(&g_lock);
    g_snapshot_valid = true;
    g_snapshot_unix = sosvc_now_unix();
    if (g_artifact_count < STATE_OFFER_MAX_PER_PEER) {
        struct sosvc_artifact *s = &g_artifacts[g_artifact_count];
        memset(s, 0, sizeof(*s));
        s->used = true;
        s->bundle_height = bundle_height;
        g_artifact_count++;
    }
    pthread_mutex_unlock(&g_lock);
}

void state_offer_service_test_ensure_identity(int32_t tip)
{
    sosvc_ensure_offering_identity(tip);
}

uint32_t state_offer_service_test_identity_gap_warns(void)
{
    pthread_mutex_lock(&g_lock);
    uint32_t warns = g_identity_gap_warn_count;
    pthread_mutex_unlock(&g_lock);
    return warns;
}

bool state_offer_service_test_have_identity(void)
{
    pthread_mutex_lock(&g_lock);
    bool have = g_have_identity;
    pthread_mutex_unlock(&g_lock);
    return have;
}

uint32_t state_offer_service_test_refresh_and_count(void)
{
    sosvc_refresh_snapshot(true);
    pthread_mutex_lock(&g_lock);
    uint32_t n = g_artifact_count;
    pthread_mutex_unlock(&g_lock);
    return n;
}

void state_offer_service_test_set_manifest_reader(
    state_offer_service_test_reader_fn fn)
{
    g_test_reader = fn;
}

uint32_t state_offer_service_test_manifest_opens(void)
{
    return atomic_load(&g_test_opens);
}

void state_offer_service_test_expire_ttl(void)
{
    pthread_mutex_lock(&g_lock);
    g_snapshot_unix = 0;
    pthread_mutex_unlock(&g_lock);
}

uint32_t state_offer_service_test_provide(struct state_offer_batch_v1 *out,
                                          int32_t tip)
{
    uint8_t peaks[32];
    memset(peaks, 0x5a, sizeof(peaks));
    return out ? sosvc_provide_from_snapshot(out, tip, peaks) : 0;
}

bool state_offer_service_test_compose_path(const char *filename, char *out,
                                           size_t out_sz)
{
    return sosvc_artifact_path(out, out_sz, filename);
}

void state_offer_service_test_set_fetch_running(bool running)
{
    g_fetch_running = running;
}

bool state_offer_service_test_fetch_running(void)
{
    return g_fetch_running;
}
#endif
