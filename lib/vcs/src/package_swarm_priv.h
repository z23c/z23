/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_priv — engine internals shared by package_swarm_node.c
 * (scheduler, serve, accounting) and package_swarm_complete.c
 * (COMPLETE + immediate ANNOUNCE). Not a public header. */

#ifndef ZCL_VCS_PACKAGE_SWARM_PRIV_H
#define ZCL_VCS_PACKAGE_SWARM_PRIV_H

#include "vcs/package_swarm_node.h"

#include "vcs/package_manifest.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"

#include "package_store_priv.h"

#include <pthread.h>
#include <string.h>

#define SWARM_DL_INFLIGHT_MAX 32u

struct swarm_req {
    bool used;
    uint32_t global_chunk; /* SWARM_MANIFEST_CHUNK for the manifest */
    uint64_t peer;
    uint64_t deadline;
    struct vcs_package_swarm_object want; /* the exact outstanding WANT */
};

struct swarm_tombstone {
    uint64_t id;
    bool fulfilled; /* fulfilled: replay offence; cancelled: quiet drop */
};

struct swarm_download {
    bool used;
    uint8_t root[32];
    char root_hex[65];
    enum vcs_swarm_download_state state;
    const char *rule; /* static; the named failure when FAILED */
    struct vcs_package_manifest manifest; /* valid when loaded */
    bool manifest_loaded;
    uint32_t total_chunks;   /* flattened coordinate count */
    uint32_t *file_of;       /* global chunk -> manifest file index */
    uint32_t *chunk_of;      /* global chunk -> in-file chunk index */
    uint8_t *have;           /* verified-present bitmap */
    uint64_t *peer_failed;   /* per-chunk bitmask of failed peer slots */
    uint32_t *chunk_attempts;
    uint32_t have_count;
    uint64_t manifest_failed_mask; /* peer slots that served a bad manifest */
    uint32_t manifest_attempts;
    struct swarm_req reqs[SWARM_DL_INFLIGHT_MAX];
    struct swarm_tombstone tombs[VCS_SWARM_TOMBSTONES_PER_DL];
    size_t tomb_pos;
    size_t tomb_count;
    uint64_t fetched_bytes;
    uint64_t requested_bytes;
    uint64_t transferred_bytes;
    uint64_t reused_bytes;
    uint32_t requested_objects;
    uint32_t transferred_objects;
    uint32_t reused_objects;
    uint64_t maximum_package_bytes; /* zero means unbounded */
    int64_t created_day;
    bool provider_restricted;
    uint64_t provider_peers[VCS_SWARM_PROVIDER_MAX];
    size_t provider_count;
};

struct swarm_peer {
    bool used;
    uint64_t id;
    uint8_t key[33];
    enum vcs_policy_tier tier;
    uint8_t ads[VCS_SWARM_MAX_PEER_ADS][32];
    /* Zero means a live-session ANNOUNCE. A nonzero value is the exact
     * signed-evidence expiry for an offer injected by peer_offer(). */
    uint64_t ad_expires_at[VCS_SWARM_MAX_PEER_ADS];
    size_t ad_count;
    /* Roots WE already announced TO this peer (dedupe: repeat announce_to
     * calls queue only newly complete roots, so the transport glue can
     * call it on every membership sync without flooding the peer). */
    uint8_t announced[VCS_SWARM_MAX_LOCAL_ANNOUNCES][32];
    size_t announced_count;
    uint32_t inflight;
    uint64_t burst_start;
    uint32_t burst_count;
    uint64_t announce_start;
    uint32_t announce_count;
    uint64_t seen[VCS_SWARM_SEEN_IDS_PER_PEER];
    size_t seen_pos;
    size_t seen_count;
    uint64_t verified_served;
    uint64_t verified_from;
    bool allowance_exhausted;
    int64_t allowance_week;
    /* Dominant verified transfer with this peer, for dual-signed
     * receipts. One root: the first credited package this session. */
    uint8_t xfer_root[32];
    uint64_t xfer_served;
    uint64_t xfer_fetched;
};

struct swarm_outbound {
    uint64_t peer;
    uint8_t len;
    uint8_t bytes[VCS_SWARM_OUTBOUND_FRAME_MAX];
};

/* Direct-mapped public-hosting verdict cache. One announce sweep touches
 * at most VCS_SWARM_MAX_LOCAL_ANNOUNCES roots, so a table that size keeps a
 * full sweep off the verifier while a hot serve root stays resident.
 * Collisions simply reclassify. */
#define VCS_SWARM_PUBLIC_CACHE_SLOTS VCS_SWARM_MAX_LOCAL_ANNOUNCES
struct swarm_public_entry {
    uint8_t root[32];
    uint64_t generation; /* this package's own mutation generation */
    uint64_t epoch;      /* store-wide, only meaningful when dep_scoped */
    enum vcs_package_public_shape shape;
    const char *rule;
    bool dep_scoped;
    bool used;
};

struct vcs_swarm_engine {
    pthread_mutex_t lock;
    struct vcs_package_store *store; /* borrowed */
    struct vcs_service_book *book;   /* borrowed */
    char zcode_dir[STORE_PATH_MAX];
    bool persist;
    vcs_swarm_score_fn score_fn;
    void *score_ctx;
    struct swarm_peer peers[VCS_SWARM_MAX_PEERS];
    struct swarm_download dls[VCS_SWARM_MAX_DOWNLOADS];
    uint64_t next_request_id;
    struct swarm_outbound outq[VCS_SWARM_OUTBOUND_MAX];
    size_t outq_pos;
    size_t outq_count;
    uint64_t last_tick;
    bool ticked;
    /* Single-entry serve cache: the last manifest parsed for serving
     * inbound chunk WANTs, and the public-hosting verdict for that same
     * root. Both are keyed by the store's mutation generation, so a
     * package that completes, gains bytes, or is evicted is reclassified
     * rather than served off a stale decision. */
    uint8_t serve_root[32];
    struct vcs_package_manifest serve_manifest;
    bool serve_loaded;
    struct swarm_public_entry public_cache[VCS_SWARM_PUBLIC_CACHE_SLOTS];
};

static inline bool vcs_swarm_peer_was_announced(const struct swarm_peer *peer,
                                                const uint8_t root[32])
{
    for (size_t i = 0; i < peer->announced_count; i++)
        if (memcmp(peer->announced[i], root, 32) == 0)
            return true;
    return false;
}

/* Lock held. Implemented in package_swarm_node.c. */
bool peer_advertises(const struct swarm_peer *peer, const uint8_t root[32]);
uint32_t advertisers_of(const struct vcs_swarm_engine *engine,
                        const struct swarm_download *dl);
bool vcs_swarm_queue_frame(struct vcs_swarm_engine *engine, uint64_t peer,
                           const struct vcs_package_swarm_message *message);
bool vcs_swarm_public_serveable(struct vcs_swarm_engine *engine,
                                const uint8_t root[32], const char **rule_out);
void vcs_swarm_cancel_outstanding(struct vcs_swarm_engine *engine,
                                  struct swarm_download *dl);
void vcs_swarm_record_delete_dl(struct vcs_swarm_engine *engine,
                                const struct swarm_download *dl);

/* Lock held. Implemented in package_swarm_complete.c. */
void vcs_swarm_complete_download(struct vcs_swarm_engine *engine,
                                 struct swarm_download *dl);

#endif /* ZCL_VCS_PACKAGE_SWARM_PRIV_H */
