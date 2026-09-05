/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The only net-to-fleet-board adapter; see config/boot_fleet_board.h. */

#include "config/boot_fleet_board.h"

#include "config/boot_internal.h"
#include "models/fleet_board_post.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <string.h>

static zcl_mutex_t s_lock;
static bool s_lock_init;
static struct boot_svc_ctx *s_svc;      /* borrowed; set by wire() */

/* Per-peer rate-limit slots. A fixed table rather than a growing map: the
 * board must never let a peer buy memory by connecting. A full table refuses
 * new identities until a slot has been inactive through both protection
 * periods; evicting a live slot would reset its receive and announce budgets,
 * letting identity churn move unbounded work onto chain threads. */
struct fleet_board_peer_slot {
    int64_t peer_id;
    int64_t window_start;
    int64_t last_announce;
    int64_t last_activity;
    int64_t inventory_before_seq;
    uint32_t frames;
    bool used;
};
static struct fleet_board_peer_slot s_peers[FLEET_BOARD_PEER_SLOTS];
static int64_t s_receive_window_start;
static uint32_t s_receive_frames;

/* Identity is loaded once and cached: the seed is the node's own durable
 * host key and re-reading it per post would put a file open on the wire
 * path. */
static uint8_t s_seed[32];
static uint8_t s_pubkey[32];
static bool s_identity_ready;

static void fleet_board_lock(void)
{
    if (!s_lock_init) {
        zcl_mutex_init(&s_lock);
        s_lock_init = true;
    }
    zcl_mutex_lock(&s_lock);
}

void boot_fleet_board_wire(struct boot_svc_ctx *svc)
{
    fleet_board_lock();
    s_svc = svc;
    memset(s_peers, 0, sizeof(s_peers));
    s_receive_window_start = 0;
    s_receive_frames = 0;
    zcl_mutex_unlock(&s_lock);
}

void boot_fleet_board_shutdown(void)
{
    fleet_board_lock();
    s_svc = NULL;
    memset(s_peers, 0, sizeof(s_peers));
    s_receive_window_start = 0;
    s_receive_frames = 0;
    memset(s_seed, 0, sizeof(s_seed));
    memset(s_pubkey, 0, sizeof(s_pubkey));
    s_identity_ready = false;
    zcl_mutex_unlock(&s_lock);
}

bool boot_fleet_board_identity(uint8_t seed_out[32], uint8_t pubkey_out[32],
                               char *why, size_t why_capacity)
{
    if (!seed_out || !pubkey_out)
        return false;
    if (why && why_capacity)
        why[0] = '\0';
    fleet_board_lock();
    if (s_identity_ready) {
        memcpy(seed_out, s_seed, sizeof(s_seed));
        memcpy(pubkey_out, s_pubkey, sizeof(s_pubkey));
        zcl_mutex_unlock(&s_lock);
        return true;
    }
    const char *datadir = s_svc ? s_svc->datadir : NULL;
    zcl_mutex_unlock(&s_lock);

    if (!datadir || !datadir[0]) {
        if (why && why_capacity)
            (void)snprintf(why, why_capacity,
                           "no datadir: the board signs with the node's own "
                           "host identity, which lives in the datadir");
        return false;
    }
    uint8_t seed[32], pubkey[32];
    char err[256] = {0};
    /* The board shares the node's ONE durable online identity rather than
     * minting a board-only key: a reader who can tie a post to a node is the
     * whole value of signing it. */
    if (!vcs_zcode_dht_online_key_load_or_create(datadir, seed, pubkey, err,
                                                 sizeof(err))) {
        if (why && why_capacity)
            (void)snprintf(why, why_capacity, "host identity unavailable: %s",
                           err[0] ? err : "unknown reason");
        return false;
    }
    fleet_board_lock();
    memcpy(s_seed, seed, sizeof(s_seed));
    memcpy(s_pubkey, pubkey, sizeof(s_pubkey));
    s_identity_ready = true;
    memcpy(seed_out, seed, sizeof(seed));
    memcpy(pubkey_out, pubkey, sizeof(pubkey));
    zcl_mutex_unlock(&s_lock);
    return true;
}

bool boot_fleet_board_public_identity(uint8_t pubkey_out[32])
{
    if (!pubkey_out)
        return false;
    fleet_board_lock();
    bool ready = s_identity_ready;
    if (ready)
        memcpy(pubkey_out, s_pubkey, sizeof(s_pubkey));
    zcl_mutex_unlock(&s_lock);
    return ready;
}

/* Caller holds the lock. */
static struct fleet_board_peer_slot *fleet_board_slot(int64_t peer_id,
                                                      int64_t now)
{
    struct fleet_board_peer_slot *free_slot = NULL;
    struct fleet_board_peer_slot *stale_slot = NULL;
    for (size_t i = 0; i < FLEET_BOARD_PEER_SLOTS; i++) {
        if (s_peers[i].used && s_peers[i].peer_id == peer_id)
            return &s_peers[i];
        if (!s_peers[i].used && !free_slot)
            free_slot = &s_peers[i];
        if (s_peers[i].used && !stale_slot &&
            now - s_peers[i].last_activity >=
                FLEET_BOARD_SLOT_PROTECT_SECONDS)
            stale_slot = &s_peers[i];
    }
    if (!free_slot && !stale_slot)
        return NULL;
    struct fleet_board_peer_slot *slot = free_slot ? free_slot : stale_slot;
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->peer_id = peer_id;
    slot->window_start = now;
    slot->last_activity = now;
    return slot;
}

/* True when this peer is inside its frame budget for the current window. */
static bool fleet_board_admit(int64_t peer_id, int64_t now)
{
    fleet_board_lock();
    struct fleet_board_peer_slot *slot = fleet_board_slot(peer_id, now);
    if (!slot) {
        zcl_mutex_unlock(&s_lock);
        return false;
    }
    slot->last_activity = now;
    if (now - slot->window_start >= FLEET_BOARD_PEER_WINDOW_SECONDS) {
        slot->window_start = now;
        slot->frames = 0;
    }
    if (now - s_receive_window_start >= FLEET_BOARD_PEER_WINDOW_SECONDS) {
        s_receive_window_start = now;
        s_receive_frames = 0;
    }
    bool ok = slot->frames < FLEET_BOARD_PEER_FRAMES_PER_WINDOW &&
              s_receive_frames < FLEET_BOARD_RECEIVE_FRAMES_PER_WINDOW;
    if (ok) {
        slot->frames++;
        s_receive_frames++;
    }
    zcl_mutex_unlock(&s_lock);
    return ok;
}

static bool fleet_board_announce_due(int64_t peer_id, int64_t now)
{
    fleet_board_lock();
    struct fleet_board_peer_slot *slot = fleet_board_slot(peer_id, now);
    if (slot)
        slot->last_activity = now;
    bool due = slot && now - slot->last_announce >=
                           FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS;
    if (due)
        slot->last_announce = now;
    zcl_mutex_unlock(&s_lock);
    return due;
}

/* Commit an inventory page only if this is still the same peer and page.
 * Sending happens without the board lock, so a reclaimed slot must never
 * inherit a former peer's progress. Caller may reset only after a verified
 * empty page; a non-empty page advances only after its frame was sent. */
static bool fleet_board_inventory_cursor_commit(int64_t peer_id,
                                                int64_t before_seq,
                                                int64_t last_seq,
                                                bool end_page)
{
    fleet_board_lock();
    struct fleet_board_peer_slot *slot = NULL;
    for (size_t i = 0; i < FLEET_BOARD_PEER_SLOTS; i++)
        if (s_peers[i].used && s_peers[i].peer_id == peer_id) {
            slot = &s_peers[i];
            break;
        }
    bool committed = slot && slot->inventory_before_seq == before_seq &&
                     (end_page || last_seq > 0);
    if (committed)
        slot->inventory_before_seq = end_page ? 0 : last_seq;
    zcl_mutex_unlock(&s_lock);
    return committed;
}

static bool fleet_board_inventory_cursor_read(int64_t peer_id,
                                              int64_t *before_seq)
{
    if (!before_seq)
        return false;
    fleet_board_lock();
    bool found = false;
    for (size_t i = 0; i < FLEET_BOARD_PEER_SLOTS; i++)
        if (s_peers[i].used && s_peers[i].peer_id == peer_id) {
            *before_seq = s_peers[i].inventory_before_seq;
            found = true;
            break;
        }
    zcl_mutex_unlock(&s_lock);
    return found;
}

#ifdef ZCL_TESTING
bool boot_fleet_board_admit_for_testing(int64_t peer_id, int64_t now)
{
    return fleet_board_admit(peer_id, now);
}

bool boot_fleet_board_announce_due_for_testing(int64_t peer_id, int64_t now)
{
    return fleet_board_announce_due(peer_id, now);
}

int64_t boot_fleet_board_inventory_cursor_for_testing(int64_t peer_id)
{
    int64_t before_seq = -1;
    return fleet_board_inventory_cursor_read(peer_id, &before_seq)
        ? before_seq : -1;
}

bool boot_fleet_board_inventory_cursor_commit_for_testing(
    int64_t peer_id, int64_t before_seq, int64_t last_seq, bool end_page)
{
    return fleet_board_inventory_cursor_commit(peer_id, before_seq, last_seq,
                                               end_page);
}
#endif

static struct node_db *fleet_board_db(void)
{
    fleet_board_lock();
    struct node_db *ndb = s_svc ? s_svc->node_db : NULL;
    zcl_mutex_unlock(&s_lock);
    return ndb && ndb->open ? ndb : NULL;
}

static bool fleet_board_send(struct msg_processor *mp, struct p2p_node *node,
                             const uint8_t *frame, size_t frame_len)
{
    if (!mp || !mp->params || !node || !frame || !frame_len)
        return false;
    if (!p2p_node_begin_message(node, "zpkgswm", mp->params->pchMessageStart)) {
        LOG_WARN("net.fleet_board", "begin_message failed for peer %lld",
                 (long long)node->id);
        return false;
    }
    p2p_node_write_message_data(node, frame, frame_len);
    if (!p2p_node_end_message(node)) {
        LOG_WARN("net.fleet_board", "end_message failed for peer %lld",
                 (long long)node->id);
        return false;
    }
    return true;
}

static void fleet_board_offend(struct msg_processor *mp, struct p2p_node *node,
                               enum fleet_board_result why)
{
    if (!mp || !mp->net_mgr || !node)
        return;
    char context[96];
    (void)snprintf(context, sizeof(context), "fleet board: %s",
                   fleet_board_result_string(why));
    peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                        context);
}

/* Decode has already established that the bytes are a well-formed post. A
 * local quota or storage failure says nothing about the sending peer, so it
 * must be dropped without turning our full board into their offence. */
static bool fleet_board_ingest_refused_locally(enum fleet_board_result result)
{
    return result == FLEET_BOARD_ERR_CAPACITY ||
           result == FLEET_BOARD_ERR_ARGS;
}

/* Announce this node's newest ids to one peer. */
static void fleet_board_announce_to(struct msg_processor *mp,
                                    struct p2p_node *node, int64_t now)
{
    struct node_db *ndb = fleet_board_db();
    if (!ndb)
        return;
    int64_t before_seq = 0;
    if (!fleet_board_inventory_cursor_read(node->id, &before_seq))
        return;
    uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
    int64_t last_seq = 0;
    int n = db_fleet_board_ids_before(ndb, now, before_seq, ids,
                                      FLEET_BOARD_FRAME_IDS_MAX, &last_seq);
    if (n < 0)
        return;
    if (n == 0) {
        (void)fleet_board_inventory_cursor_commit(node->id, before_seq, 0,
                                                  true);
        return;
    }
    uint8_t frame[FLEET_BOARD_FRAME_MAX];
    size_t frame_len = 0;
    if (fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids, (size_t)n,
                                     frame, sizeof(frame),
                                     &frame_len) != FLEET_BOARD_OK)
        return;
    if (fleet_board_send(mp, node, frame, frame_len))
        (void)fleet_board_inventory_cursor_commit(node->id, before_seq,
                                                  last_seq, false);
}

void boot_fleet_board_tick(struct msg_processor *mp, struct p2p_node *node,
                           void *ctx)
{
    (void)ctx;
    if (!mp || !node)
        return;
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool due = fleet_board_announce_due(node->id, now);
    if (due)
        fleet_board_announce_to(mp, node, now);
}

/* INV: ask back for every announced id this node does not hold. */
static void fleet_board_handle_inv(struct msg_processor *mp,
                                   struct p2p_node *node,
                                   const uint8_t (*ids)[32], size_t count,
                                   struct node_db *ndb)
{
    uint8_t wanted[FLEET_BOARD_FRAME_IDS_MAX][32];
    size_t n_wanted = 0;
    for (size_t i = 0; i < count && n_wanted < FLEET_BOARD_FRAME_IDS_MAX; i++) {
        if (!db_fleet_board_have(ndb, ids[i])) {
            memcpy(wanted[n_wanted], ids[i], 32);
            n_wanted++;
        }
    }
    if (!n_wanted)
        return;
    uint8_t frame[FLEET_BOARD_FRAME_MAX];
    size_t frame_len = 0;
    if (fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_GET, wanted, n_wanted,
                                     frame, sizeof(frame),
                                     &frame_len) != FLEET_BOARD_OK)
        return;
    (void)fleet_board_send(mp, node, frame, frame_len);
}

/* GET: serve every requested id this node holds, one post per frame. Serving
 * is bounded by the id ceiling the request frame itself carries. */
static void fleet_board_handle_get(struct msg_processor *mp,
                                   struct p2p_node *node,
                                   const uint8_t (*ids)[32], size_t count,
                                   struct node_db *ndb)
{
    for (size_t i = 0; i < count; i++) {
        struct db_fleet_board_post row;
        if (!db_fleet_board_post_find(ndb, ids[i], &row))
            continue;
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t frame_len = 0;
        if (fleet_board_frame_encode_post(&row.post, frame, sizeof(frame),
                                          &frame_len) != FLEET_BOARD_OK)
            continue;
        if (!fleet_board_send(mp, node, frame, frame_len))
            return;
    }
}

bool boot_fleet_board_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            void *ctx)
{
    (void)ctx;
    if (!fleet_board_frame_is_board(payload, payload_len))
        return false;
    if (!mp || !node)
        return true;

    int64_t now = (int64_t)platform_time_wall_time_t();
    /* Over the per-peer ceiling is a drop, never an offence: a peer that
     * talks too much has not lied, and scoring it would punish a node whose
     * board is simply busier than ours. */
    if (!fleet_board_admit(node->id, now))
        return true;

    struct node_db *ndb = fleet_board_db();
    if (!ndb)
        return true;    /* store not open: the board is quiet, not broken */

    uint8_t type = fleet_board_frame_type(payload, payload_len);
    if (type == FLEET_BOARD_FRAME_INV || type == FLEET_BOARD_FRAME_GET) {
        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        size_t count = 0;
        uint8_t decoded_type = 0;
        enum fleet_board_result r = fleet_board_frame_decode_ids(
            payload, payload_len, &decoded_type, ids,
            FLEET_BOARD_FRAME_IDS_MAX, &count);
        if (r != FLEET_BOARD_OK) {
            fleet_board_offend(mp, node, r);
            return true;
        }
        if (decoded_type == FLEET_BOARD_FRAME_INV)
            fleet_board_handle_inv(mp, node, ids, count, ndb);
        else
            fleet_board_handle_get(mp, node, ids, count, ndb);
        return true;
    }

    if (type == FLEET_BOARD_FRAME_POST) {
        struct fleet_board_post post;
        enum fleet_board_result r =
            fleet_board_frame_decode_post(payload, payload_len, &post);
        if (r != FLEET_BOARD_OK) {
            fleet_board_offend(mp, node, r);
            return true;
        }
        bool stored = false;
        r = db_fleet_board_post_ingest(ndb, &post, now, &stored);
        if (r != FLEET_BOARD_OK) {
            /* An expired post is stale, not forged: peers legitimately relay
             * one whose ttl ran out in flight. Capacity and storage refusal
             * are local receiver state. All other errors remain sender-owned
             * payload failures and keep their scoring consequence. */
            if (fleet_board_ingest_refused_locally(r))
                LOG_WARN("net.fleet_board", "dropped post from peer %lld: %s",
                         (long long)node->id, fleet_board_result_string(r));
            else if (r != FLEET_BOARD_ERR_EXPIRED)
                fleet_board_offend(mp, node, r);
            return true;
        }
        if (stored) {
            char id_hex[65];
            fleet_board_id_to_hex(post.id, id_hex);
            LOG_INFO("net.fleet_board", "stored %s post %.16s from peer %lld",
                     fleet_board_kind_name(post.kind), id_hex,
                     (long long)node->id);
        }
        return true;
    }

    fleet_board_offend(mp, node, FLEET_BOARD_ERR_KIND);
    return true;
}

void boot_fleet_board_announce(const uint8_t id[32])
{
    if (!id)
        return;
    fleet_board_lock();
    struct msg_processor *mp = s_svc ? s_svc->msg_processor : NULL;
    zcl_mutex_unlock(&s_lock);
    if (!mp)
        return;
    uint8_t ids[1][32];
    memcpy(ids[0], id, 32);
    uint8_t frame[FLEET_BOARD_FRAME_MAX];
    size_t frame_len = 0;
    if (fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids, 1, frame,
                                     sizeof(frame),
                                     &frame_len) != FLEET_BOARD_OK)
        return;
    /* One inventory line to every peer. Peers that already hold the id say
     * nothing; the rest ask for it. */
    msg_processor_flood_message(mp, "zpkgswm", frame, frame_len);
}

enum fleet_board_result boot_fleet_board_publish(
    struct fleet_board_post *post, int64_t now)
{
    if (!post)
        return FLEET_BOARD_ERR_ARGS;
    struct node_db *ndb = fleet_board_db();
    if (!ndb)
        return FLEET_BOARD_ERR_ARGS;

    uint8_t seed[32], pubkey[32];
    char why[256];
    if (!boot_fleet_board_identity(seed, pubkey, why, sizeof(why))) {
        LOG_WARN("fleet.board", "cannot sign a post: %s", why);
        return FLEET_BOARD_ERR_SIGNATURE;
    }
    enum fleet_board_result r = fleet_board_post_sign(post, seed, pubkey);
    memset(seed, 0, sizeof(seed));
    if (r != FLEET_BOARD_OK)
        return r;

    bool stored = false;
    r = db_fleet_board_post_ingest(ndb, post, now, &stored);
    if (r != FLEET_BOARD_OK)
        return r;
    /* Announced only after it is durable: a post the fleet can ask for but
     * this node cannot serve is a promise nobody can keep. */
    boot_fleet_board_announce(post->id);
    return FLEET_BOARD_OK;
}
