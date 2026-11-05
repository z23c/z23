/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "board" mesh stream service — FLEET-scope board posts pulled
 * between PAIRED peers (see config/boot_fleet_board.h). It is the fleet
 * ledger's pull lane (boot_fleet_ledger.c) applied to the board: one
 * registration serves both halves and the stream lane only ever copies
 * bytes. The answering half reads one page when a stream opens, through
 * the arrival index and capped at FLEET_BOARD_FLEET_ANSWER_POSTS_MAX row
 * reads and signature checks, so a pull cannot hold the frame loop for
 * longer than that however large the store is. Every pulled post is
 * verified and stored on this lane's own tick with no lock held.
 */

// one-result-type-ok:closed-security-verdict — the callbacks return the
// stream primitive's bounded refusal enum; no diagnostic text crosses the
// wire. Failure logging happens here, with the refusal named.

#include "config/boot_fleet_board.h"
#include "config/boot_fleet_roster.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "boot_fleet_board_cursor_internal.h"
#include "boot_fleet_board_roster_internal.h"
#include "boot_mesh_status_internal.h"

#include "net/msgprocessor.h"
#include "net/noise_transport.h"
#include "util/fleet_role_check.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/random_secret.h"
#include "models/fleet_board_post.h"
#include "models/mesh_pairing.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What one pull asked for: a forward page from the peer's cursor, or one
 * page of a sweep back over rows a refusal left unsettled. */
struct board_ask {
    uint8_t peer_box_id[32];
    int64_t after;
    bool sweep;
    /* A roster pull: the answer starts with a proof bound to this session. */
    bool roster;
    uint8_t transcript[32];
    uint64_t generation;
};

/* The asking half's per-stream state: what we asked, and what came back. */
struct board_pull_state {
    struct board_ask ask;
    size_t len;
    uint8_t rows[FLEET_BOARD_FLEET_ANSWER_MAX];
};

/* The answering half's per-stream state: one bounded answer, read once at
 * open. */
struct board_serve_state {
    size_t len;
    size_t sent;
    bool roster;            /* admitted by the roster, not by a pairing row */
    uint8_t roster_key[32]; /* the board key that proved itself at open */
    uint8_t rows[FLEET_BOARD_FLEET_ANSWER_MAX];
};

/* An answer waiting for the tick to verify and store it. */
struct board_inbox_slot {
    bool used;
    bool roster_only; /* set at drain: take only sealed roster rows from it */
    struct board_ask ask;
    size_t len;
    uint8_t *rows;
};

static zcl_mutex_t g_lock;
static zcl_once_t g_lock_once = ZCL_ONCE_INIT;
static struct boot_svc_ctx *g_svc; /* borrowed; set by wire() */
static struct board_inbox_slot g_inbox[FLEET_BOARD_FLEET_INBOX_MAX];
static struct board_cursor g_cursors[FLEET_BOARD_FLEET_PEERS_MAX];
static bool g_cursors_loaded;
static struct liveness_contract g_contract;
static supervisor_child_id g_child = SUPERVISOR_INVALID_ID;
static int64_t g_last_pull;
static int64_t g_last_roster_publish;
static _Atomic uint64_t g_delegation_refused;
static _Atomic uint64_t g_role_refused;
static _Atomic uint64_t g_inbox_full;
static _Atomic uint64_t g_stored;
static _Atomic uint64_t g_deferred;
static _Atomic uint64_t g_answer_refused;
/* This process's answer epoch: drawn once, the first time it answers, and
 * never reset while the process lives — the same lifetime as the store's
 * arrival high-water mark, which is exactly what it names. Lane lock. */
static uint8_t g_epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
static bool g_epoch_ready;

#ifdef ZCL_TESTING
/* See boot_fleet_board_fleet_test_bind / _bind_authority. */
static struct node_db *g_test_db;
static bool g_test_authority;
static struct vcs_zcode_dht_delegation g_test_delegation;
static uint8_t g_test_genesis[32];
static int64_t g_test_now;
static char g_test_cursor_dir[512];
static int64_t g_test_last_after;
#endif

static void board_lock_init(void)
{
    zcl_mutex_init(&g_lock);
}

static void board_lock(void)
{
    (void)zcl_once_call(&g_lock_once, board_lock_init);
    zcl_mutex_lock(&g_lock);
}

static void board_unlock(void)
{
    zcl_mutex_unlock(&g_lock);
}

/* The board store this box serves from and commits into. */
static struct node_db *board_db(void)
{
    board_lock();
    struct node_db *ndb = g_svc ? g_svc->node_db : NULL;
#ifdef ZCL_TESTING
    if (g_test_db)
        ndb = g_test_db;
#endif
    board_unlock();
    return ndb && ndb->open ? ndb : NULL;
}

/* ── the frames ──────────────────────────────────────────────────────── */

static size_t pull_encode(int64_t after,
                          uint8_t out[FLEET_BOARD_FLEET_PULL_BYTES])
{
    out[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_PULL;
    out[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    zcl_write_u64_be(out + 2, (uint64_t)after);
    return FLEET_BOARD_FLEET_PULL_BYTES;
}

static bool pull_decode(const uint8_t *in, size_t len, int64_t *after_out)
{
    if (!in || len != FLEET_BOARD_FLEET_PULL_BYTES ||
        in[0] != (uint8_t)FLEET_BOARD_FLEET_MSG_PULL ||
        in[1] != (uint8_t)FLEET_BOARD_FLEET_VERSION)
        return false;
    uint64_t after = zcl_read_u64_be(in + 2);
    if (after > (uint64_t)INT64_MAX)
        return false;
    *after_out = (int64_t)after;
    return true;
}

/* This process's answer epoch, drawn on first use. False only when the
 * system could not supply random bytes; nothing is answered then. */
static bool board_epoch(uint8_t out[FLEET_BOARD_FLEET_EPOCH_BYTES])
{
    board_lock();
    if (!g_epoch_ready)
        g_epoch_ready = zcl_random_secret_bytes(g_epoch, sizeof g_epoch,
                                                "fleet_board_epoch");
    bool ready = g_epoch_ready;
    if (ready)
        memcpy(out, g_epoch, sizeof g_epoch);
    board_unlock();
    return ready;
}

/* The answer head: which process answered, and how far its page reached. */
struct board_answer_head {
    uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
    int64_t scanned;
};

static void answer_head_encode(
    const uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES], int64_t scanned,
    uint8_t *out)
{
    out[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_ANSWER;
    out[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    memcpy(out + 2, epoch, FLEET_BOARD_FLEET_EPOCH_BYTES);
    zcl_write_u64_be(out + 2 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)scanned);
}

static bool answer_head_decode(const uint8_t *in, size_t len,
                               struct board_answer_head *out)
{
    if (!in || len < FLEET_BOARD_FLEET_ANSWER_HEAD ||
        in[0] != (uint8_t)FLEET_BOARD_FLEET_MSG_ANSWER ||
        in[1] != (uint8_t)FLEET_BOARD_FLEET_VERSION)
        return false;
    memcpy(out->epoch, in + 2, FLEET_BOARD_FLEET_EPOCH_BYTES);
    uint64_t scanned = zcl_read_u64_be(in + 2 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    if (scanned > (uint64_t)INT64_MAX)
        return false;
    out->scanned = (int64_t)scanned;
    return true;
}

/* ── who may ask ─────────────────────────────────────────────────────── */

/* The composition roots this decision reads, named so the test group can
 * stand in for the DHT lookup it cannot host (boot_fleet_ledger.c has the
 * same three, for the same reason). */
static bool board_peer_delegation(const struct db_mesh_pairing *row,
                                  struct vcs_zcode_dht_delegation *out)
{
#ifdef ZCL_TESTING
    if (g_test_authority) {
        if (memcmp(row->peer_noise_pubkey,
                   g_test_delegation.noise_static_pubkey, 32) != 0)
            return false;
        *out = g_test_delegation;
        return true;
    }
#endif
    return boot_mesh_peer_delegation(row, out);
}

static bool board_network_genesis(uint8_t out[32])
{
#ifdef ZCL_TESTING
    if (g_test_authority) {
        memcpy(out, g_test_genesis, 32);
        return true;
    }
#endif
    return boot_zcode_dht_network_genesis(out);
}

static int64_t board_now(void)
{
#ifdef ZCL_TESTING
    if (g_test_authority)
        return g_test_now;
#endif
    return (int64_t)platform_time_wall_time_t();
}

/* The pairing row's own window cannot say whether the peer's master
 * identity is still ACTIVE on chain, so that is asked separately. A
 * refusal is counted and named, never the peer. */
static bool board_delegation_current(
    struct node_db *ndb, const struct db_mesh_pairing *row,
    const struct vcs_zcode_dht_delegation *peer,
    const uint8_t session_noise_static[32], int64_t now)
{
    uint8_t network_genesis[32];
    enum mesh_pairing_reason reason = MESH_PAIRING_BAD_ARGUMENT;
    if (board_network_genesis(network_genesis))
        reason = mesh_pairing_service_authorize_status(
            ndb, network_genesis, row->pairing_id, peer,
            session_noise_static, now);
    if (reason == MESH_PAIRING_OK)
        return true;
    atomic_fetch_add_explicit(&g_delegation_refused, 1, memory_order_relaxed);
    LOG_WARN("fleet.board", "fleet pull refused: delegation %s",
             mesh_pairing_reason_token(reason));
    return false;
}

/* The pairing row for one Noise static: bounded, and fail-closed on an
 * unreadable list. */
static bool board_pairing_for_peer(struct node_db *ndb,
                                   const uint8_t peer_noise_static[32],
                                   struct db_mesh_pairing *out)
{
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_pairing");
    if (!rows)
        return false;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_BOARD_FLEET_PEERS_MAX);
    bool found = false;
    for (int i = 0; i < count && !found; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_noise_static, 32) != 0)
            continue;
        *out = rows[i];
        found = true;
    }
    free(rows);
    return found;
}

/* A paired, current peer still reads fleet-private posts only when the
 * key it signs with holds a role granting the board's read leaf here. */
static bool board_peer_may_read(const uint8_t signer[32])
{
    char why[ZCL_FLEET_ROLE_WHY_MAX];
    if (zcl_fleet_role_allows(signer, FLEET_BOARD_FLEET_READ_LEAF, NULL, why,
                              sizeof why))
        return true;
    atomic_fetch_add_explicit(&g_role_refused, 1, memory_order_relaxed);
    LOG_WARN("fleet.board", "fleet pull refused: %s", why);
    return false;
}

/* ZRC 0012 step 2: is this peer's board key on the fleet roster? The roster
 * is read from the board store this box serves from. Unarmed (no fleet root,
 * or no sealed row yet) admits, exactly as before this step; an armed roster
 * admits members only; an unverifiable one admits nobody. */
static bool board_roster_admits(const uint8_t online_pubkey[32])
{
    struct node_db *store = board_db();
    if (!store)
        return false;
    int64_t now = board_now();
    bool ok = boot_fleet_roster_admits_peer(store, online_pubkey, now);
    uint64_t skipped = 0;
    if (!ok && boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_PEER_REFUSED,
                                         now, &skipped))
        LOG_WARN("fleet.board", "fleet pull refused: not on the fleet roster "
                 "(%llu more since the last line)",
                 (unsigned long long)skipped);
    return ok;
}

/* Everything the answering half proves about a peer that is already
 * through the primitive's Noise and capability gates, before any post is
 * read. */
static bool board_accept_authorized(const uint8_t peer_noise_static[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return false;
    struct db_mesh_pairing row;
    struct vcs_zcode_dht_delegation peer;
    if (!board_pairing_for_peer(ndb, peer_noise_static, &row) ||
        !board_peer_delegation(&row, &peer)) {
        atomic_fetch_add_explicit(&g_delegation_refused, 1,
                                  memory_order_relaxed);
        LOG_WARN("fleet.board", "fleet pull refused: delegation_unresolved");
        return false;
    }
    return board_delegation_current(ndb, &row, &peer, peer_noise_static,
                                    board_now()) &&
           board_peer_may_read(peer.online_pubkey) &&
           board_roster_admits(peer.online_pubkey);
}

/* ── the answer ──────────────────────────────────────────────────────── */

struct board_answer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    unsigned count;
};

/* Append one record, or stop the page when it would not fit: the next
 * pull starts at exactly this row, so nothing is skipped. */
static bool board_answer_visit(const struct db_fleet_board_post *row,
                               void *ctx)
{
    struct board_answer *a = ctx;
    const size_t head = FLEET_BOARD_FLEET_RECORD_HEAD;
    if (a->count >= FLEET_BOARD_FLEET_ANSWER_POSTS_MAX ||
        a->cap - a->len <= head)
        return false;
    uint8_t *at = a->buf + a->len;
    size_t wire_len = 0;
    if (fleet_board_post_encode(&row->post, at + head, a->cap - a->len - head,
                                &wire_len) != FLEET_BOARD_OK)
        return false;
    zcl_write_u64_be(at, (uint64_t)row->arrival);
    memcpy(at + 8, row->post.id, 32);
    zcl_write_u32_be(at + 40, (uint32_t)wire_len);
    a->len += head + wire_len;
    a->count++;
    return true;
}

/* ── the service callbacks ───────────────────────────────────────────── */

/* Read one bounded page into a new serve state: once, at open. `proof` (a
 * roster stream's answering proof, with the key that was admitted) goes first
 * on the wire. */
static enum mesh_stream_refusal board_serve_compose(struct mesh_stream *st,
                                                    struct node_db *ndb,
                                                    int64_t after,
                                                    const uint8_t *proof,
                                                    const uint8_t *key)
{
    uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
    if (!ndb || !board_epoch(epoch))
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    struct board_serve_state *s =
        zcl_calloc(1, sizeof *s, "fleet_board_serve");
    if (!s)
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    const size_t skip = proof ? FLEET_BOARD_ROSTER_PROOF_BYTES : 0;
    const size_t head = skip + FLEET_BOARD_FLEET_ANSWER_HEAD;
    struct board_answer a = { s->rows + head, sizeof s->rows - head, 0, 0 };
    int64_t scanned = after;
    if (db_fleet_board_fleet_after(ndb, board_now(), after,
                                   FLEET_BOARD_FLEET_ANSWER_POSTS_MAX,
                                   board_answer_visit, &a, &scanned) < 0) {
        free(s);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    if (proof) {
        memcpy(s->rows, proof, skip);
        memcpy(s->roster_key, key, 32);
        s->roster = true;
    }
    answer_head_encode(epoch, scanned, s->rows + skip);
    s->len = head + a.len;
    st->service_state = s;
    return MESH_STREAM_OK;
}

/* An inbound OPEN. The primitive has proven the Noise session and a
 * pairing row granting the capability; this lane proves the delegation is
 * current and the peer holds the read role, and only then reads the page
 * once, here. The tick rechecks authority before emitting the cached page. */
static enum mesh_stream_refusal board_service_open(struct mesh_stream *st,
                                                   const uint8_t *payload,
                                                   size_t len, uint8_t *reply,
                                                   size_t reply_cap,
                                                   size_t *reply_len,
                                                   void *ctx)
{
    (void)ctx;
    (void)reply;
    (void)reply_cap;
    if (reply_len)
        *reply_len = 0;
    int64_t after = 0;
    if (!pull_decode(payload, len, &after))
        return MESH_STREAM_REFUSED_MALFORMED;
    if (!board_accept_authorized(st->peer_static))
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    return board_serve_compose(st, board_db(), after, NULL, NULL);
}

/* What one roster proof is bound to on this network. */
static bool board_roster_bind(const uint8_t transcript[32], uint64_t generation,
                              int64_t after,
                              struct fleet_board_roster_bind *out)
{
    memcpy(out->transcript_hash, transcript, 32);
    out->connection_generation = generation;
    out->after = after;
    return board_network_genesis(out->network_genesis);
}

/* An inbound roster OPEN. The primitive demands only the Noise session here
 * (capability 0): this is the whole decision, and every refusal is the one an
 * unpaired peer already gets. */
static enum mesh_stream_refusal board_roster_open(struct mesh_stream *st,
                                                  const uint8_t *payload,
                                                  size_t len, uint8_t *reply,
                                                  size_t reply_cap,
                                                  size_t *reply_len, void *ctx)
{
    (void)ctx;
    (void)reply;
    (void)reply_cap;
    if (reply_len)
        *reply_len = 0;
    int64_t after = 0;
    if (len != FLEET_BOARD_ROSTER_PULL_BYTES ||
        !pull_decode(payload, FLEET_BOARD_FLEET_PULL_BYTES, &after))
        return MESH_STREAM_REFUSED_MALFORMED;
    const uint8_t *proof = payload + FLEET_BOARD_FLEET_PULL_BYTES;
    struct node_db *pairings = app_runtime_node_db();
    struct node_db *store = board_db();
    struct fleet_board_roster_bind bind;
    if (!pairings || !app_runtime_node_db_handle_open(pairings) || !store ||
        !board_roster_bind(st->transcript_hash, st->connection_generation,
                           after, &bind))
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    if (!fleet_board_roster_admit(pairings, store, &bind, st->peer_static,
                                  proof, board_now()) ||
        !board_peer_may_read(proof))
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    uint8_t answer_proof[FLEET_BOARD_ROSTER_PROOF_BYTES];
    if (!fleet_board_roster_proof_make(FLEET_BOARD_ROSTER_SIDE_ANSWER, &bind,
                                       answer_proof))
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    fleet_board_roster_learn(st->peer_static, proof);
    return board_serve_compose(st, store, after, answer_proof, proof);
}

/* The tick's recheck before the cached page leaves. The signature bound the
 * key to this session at open and the stream cannot leave that session, so
 * only the key's standing is asked again. */
static bool board_serve_authorized(const struct mesh_stream *st,
                                   const struct board_serve_state *s)
{
    if (!s->roster)
        return board_accept_authorized(st->peer_static);
    struct node_db *pairings = app_runtime_node_db();
    return pairings && app_runtime_node_db_handle_open(pairings) &&
           fleet_board_roster_standing(pairings, board_db(), st->peer_static,
                                       s->roster_key, board_now()) &&
           board_peer_may_read(s->roster_key);
}

/* The asking half receives the answer: bytes are copied and credit is
 * given back; nothing is verified and nothing is written here. */
static void board_service_data(struct mesh_stream *st, const uint8_t *payload,
                               size_t len, void *ctx)
{
    (void)ctx;
    if (!st->local_initiator)
        return;
    struct board_pull_state *p = st->service_state;
    if (!p || !payload || len == 0)
        return;
    if (p->len + len > sizeof p->rows) {
        /* More than one answer's worth: the peer is off protocol, so the
         * stream ends rather than the buffer growing. */
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        return;
    }
    memcpy(p->rows + p->len, payload, len);
    p->len += len;
    (void)mesh_stream_grant(st, (uint32_t)len);
}

/* The answering half's drain: one answer inside the credit it holds, then
 * the stream is done. A pull with nothing new costs one answer head. */
static void board_service_tick(struct mesh_stream *st, int64_t now, void *ctx)
{
    (void)now;
    (void)ctx;
    if (st->local_initiator)
        return;
    struct board_serve_state *s = st->service_state;
    size_t remaining = s ? s->len - s->sent : 0;
    if (remaining == 0) {
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        return;
    }
    if (st->send_credit < remaining)
        return; /* wait for the window; never split an answer */
    if (!board_serve_authorized(st, s)) {
        mesh_stream_close(st, MESH_STREAM_REFUSED_PEER_UNPAIRED, NULL, 0);
        return;
    }
    if (mesh_stream_send(st, s->rows + s->sent, remaining))
        s->sent += remaining;
}

/* Take a free inbox slot for one finished answer. Lane lock held. */
static struct board_inbox_slot *board_inbox_claim(void)
{
    for (size_t i = 0; i < FLEET_BOARD_FLEET_INBOX_MAX; i++)
        if (!g_inbox[i].used)
            return &g_inbox[i];
    return NULL;
}

/* The stream ended. A finished answer moves into the inbox by pointer; an
 * answer that did not finish has no standing and is asked for again. */
static void board_service_close(struct mesh_stream *st,
                                enum mesh_stream_refusal reason,
                                const uint8_t *payload, size_t len, void *ctx)
{
    (void)payload;
    (void)len;
    (void)ctx;
    struct board_pull_state *p = st->service_state;
    if (!st->local_initiator || !p || p->len == 0 ||
        (reason != MESH_STREAM_CLOSED_BY_SERVICE && reason != MESH_STREAM_OK))
        return;
    uint8_t *rows = zcl_malloc(p->len, "fleet_board_inbox");
    if (!rows)
        return;
    memcpy(rows, p->rows, p->len);
    board_lock();
    struct board_inbox_slot *slot = board_inbox_claim();
    if (slot) {
        slot->used = true;
        slot->ask = p->ask;
        slot->len = p->len;
        slot->rows = rows;
    }
    board_unlock();
    if (!slot) {
        free(rows);
        atomic_fetch_add_explicit(&g_inbox_full, 1, memory_order_relaxed);
        LOG_WARN("fleet.board",
                 "fleet answer deferred: inbox full (%u slots)",
                 (unsigned)FLEET_BOARD_FLEET_INBOX_MAX);
    }
}

static void board_service_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    free(st->service_state);
    st->service_state = NULL;
}

bool boot_fleet_board_fleet_register_service(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof(service));
    service.name = FLEET_BOARD_FLEET_SERVICE_NAME;
    /* The grant the fleet ledger and a mesh status read already use: a
     * pairing record is insert-only, so demanding a new bit would leave
     * this service dead on every pairing the fleet already committed. The
     * read role checked in on_open is what narrows it. */
    service.required_pairing_capability = MESH_PAIRING_CAP_STATUS_READ;
    service.on_open = board_service_open;
    service.on_data = board_service_data;
    service.on_close = board_service_close;
    service.on_tick = board_service_tick;
    service.on_release = board_service_release;
    if (!mesh_stream_service_register(&service))
        return false;
    /* The same lane for a machine on the fleet roster, with no pairing row.
     * Capability 0: board_roster_open owns the decision. */
    mesh_stream_service_unregister(FLEET_BOARD_ROSTER_SERVICE_NAME);
    service.name = FLEET_BOARD_ROSTER_SERVICE_NAME;
    service.required_pairing_capability = 0;
    service.on_open = board_roster_open;
    return mesh_stream_service_register(&service);
}

/* ── per-peer cursors ────────────────────────────────────────────────── */

/* Lane lock held. NULL when the table is full: that peer is then always
 * asked from the beginning, which dedupe by id keeps correct. */
static struct board_cursor *board_cursor_slot(const uint8_t box_id[32],
                                              bool create)
{
    struct board_cursor *free_slot = NULL;
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX; i++) {
        if (g_cursors[i].used &&
            memcmp(g_cursors[i].peer_box_id, box_id, 32) == 0)
            return &g_cursors[i];
        if (!g_cursors[i].used && !free_slot)
            free_slot = &g_cursors[i];
    }
    if (!create || !free_slot)
        return NULL;
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->used = true;
    memcpy(free_slot->peer_box_id, box_id, 32);
    return free_slot;
}

static bool board_cursor_file(char *out, size_t cap)
{
#ifdef ZCL_TESTING
    if (g_test_cursor_dir[0]) {
        int n = snprintf(out, cap, "%s/fleet-board-cursors", g_test_cursor_dir);
        return n > 0 && (size_t)n < cap;
    }
#endif
    struct node_db *ndb = board_db();
    const char *slash = ndb ? strrchr(ndb->path, '/') : NULL;
    if (!ndb || ndb->path[0] == '\0' || ndb->path[0] == ':' || !slash ||
        slash == ndb->path)
        return false;
    int n = snprintf(out, cap, "%.*s/fleet-board-cursors",
                     (int)(slash - ndb->path), ndb->path);
    return n > 0 && (size_t)n < cap;
}

/* Fill an empty in-memory table from the cursor file once per process.
 * A missing file is a box that has never pulled. A later forget (a test
 * bind, or shutdown) clears the flag so the next pull reads again. */
static void board_cursors_load(void)
{
    char path[1200];
    struct board_cursor snap[FLEET_BOARD_FLEET_PEERS_MAX];
    size_t n = 0;
    bool loaded = false;
    board_lock();
    loaded = g_cursors_loaded;
    board_unlock();
    if (loaded)
        return;
    if (board_cursor_file(path, sizeof path))
        n = board_cursor_read(path, snap, FLEET_BOARD_FLEET_PEERS_MAX);
    board_lock();
    if (!g_cursors_loaded) {
        for (size_t i = 0; i < n && i < FLEET_BOARD_FLEET_PEERS_MAX; i++)
            g_cursors[i] = snap[i];
        g_cursors_loaded = true;
    }
    board_unlock();
}

/* Choose the next pull toward one peer. While anything is waiting on a
 * sweep, pulls alternate: a forward page, then a sweep page, so new posts
 * keep flowing while refused ones are offered again. A sweep starts at the
 * lowest refused arrival and ends where `next` stood when it started. */
static void board_plan_pull(struct board_ask *ask)
{
    ask->after = 0;
    ask->sweep = false;
    board_cursors_load();
    board_lock();
    struct board_cursor *c = board_cursor_slot(ask->peer_box_id, true);
    if (c) {
        bool pending = c->sweep_active || c->carry_min > 0;
        if (pending && c->sweep_turn && !c->sweep_active) {
            c->sweep_active = true;
            c->sweep_pos = c->carry_min - 1;
            c->sweep_end = c->next;
            c->carry_min = 0;
        }
        ask->sweep = pending && c->sweep_turn;
        ask->after = ask->sweep ? c->sweep_pos : c->next;
        c->sweep_turn = pending && !ask->sweep;
    }
    board_unlock();
#ifdef ZCL_TESTING
    g_test_last_after = ask->after;
#endif
}

/* Copy one peer's cursor out, so the store is written with no lock held.
 * False when the table has no room for this peer. */
static bool board_cursor_load(const uint8_t box_id[32],
                              struct board_cursor *out)
{
    board_lock();
    const struct board_cursor *c = board_cursor_slot(box_id, true);
    if (c)
        *out = *c;
    board_unlock();
    return c != NULL;
}

/* Only the lane tick touches a cursor — planning a pull and draining an
 * answer both run there — so the copy it loaded is still the cursor it
 * stores back. */
static void board_cursor_store(const struct board_cursor *in)
{
    struct board_cursor snap[FLEET_BOARD_FLEET_PEERS_MAX];
    size_t n = 0;
    board_lock();
    struct board_cursor *c = board_cursor_slot(in->peer_box_id, false);
    if (c)
        *c = *in;
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX; i++) {
        if (g_cursors[i].used)
            snap[n++] = g_cursors[i];
    }
    g_cursors_loaded = true;
    board_unlock();
    char path[1200];
    if (board_cursor_file(path, sizeof path))
        board_cursor_write(path, snap, n);
}

/* Is this answer's numbering the one the cursor holds? A different epoch
 * means the peer's process restarted, and a restart may reuse an arrival
 * number whose row was reclaimed, so everything the cursor says is void
 * and the peer is read again from the beginning. An answer to a forward
 * pull from 0 needs no numbering to be trusted; anything else waits for
 * the next pull. */
static bool board_cursor_epoch(struct board_cursor *c,
                               const struct board_answer_head *h,
                               const struct board_ask *ask)
{
    if (c->epoch_known &&
        memcmp(c->epoch, h->epoch, FLEET_BOARD_FLEET_EPOCH_BYTES) == 0)
        return true;
    uint8_t box_id[32];
    memcpy(box_id, c->peer_box_id, 32);
    memset(c, 0, sizeof *c);
    c->used = true;
    memcpy(c->peer_box_id, box_id, 32);
    memcpy(c->epoch, h->epoch, FLEET_BOARD_FLEET_EPOCH_BYTES);
    c->epoch_known = true;
    return !ask->sweep && ask->after == 0;
}

/* Is this answer to the question the cursor is waiting on? An answer to
 * any other question is stale and moves nothing. */
static bool board_answer_current(const struct board_cursor *c,
                                 const struct board_ask *ask)
{
    if (ask->sweep)
        return c->sweep_active && ask->after == c->sweep_pos;
    return ask->after == c->next;
}

/* ── the commit, on this lane's tick ─────────────────────────────────── */

struct board_record {
    int64_t arrival;
    uint8_t id[32];
    const uint8_t *wire;
    size_t wire_len;
    bool roster_only; /* the answer's: this box is not armed yet */
};

/* The next framed record, or false at the end or at a frame that does not
 * add up. */
static bool board_record_next(const uint8_t *buf, size_t len, size_t *off,
                              struct board_record *rec)
{
    const size_t head = FLEET_BOARD_FLEET_RECORD_HEAD;
    if (*off >= len || len - *off < head)
        return false;
    const uint8_t *at = buf + *off;
    uint64_t arrival = zcl_read_u64_be(at);
    uint32_t wire_len = zcl_read_u32_be(at + 40);
    if (arrival > (uint64_t)INT64_MAX || wire_len == 0 ||
        wire_len > len - *off - head)
        return false;
    rec->arrival = (int64_t)arrival;
    memcpy(rec->id, at + 8, 32);
    rec->wire = at + head;
    rec->wire_len = wire_len;
    *off += head + wire_len;
    return true;
}

/* The whole answer adds up before any of it is used: every record framed,
 * arrivals strictly rising from where the pull asked, none past the point
 * the page says it reached. One bad frame voids the answer; nothing in it
 * is guessed at and no cursor moves. */
static bool board_answer_valid(const uint8_t *buf, size_t len,
                               const struct board_answer_head *h,
                               int64_t asked_after)
{
    if (h->scanned < asked_after)
        return false;
    size_t off = FLEET_BOARD_FLEET_ANSWER_HEAD;
    int64_t prev = asked_after;
    struct board_record rec;
    while (board_record_next(buf, len, &off, &rec)) {
        if (rec.arrival <= prev || rec.arrival > h->scanned)
            return false;
        prev = rec.arrival;
    }
    return off == len;
}

/* A refusal that says nothing final about the post: this box has not
 * granted the author a role yet, its clock is behind the author's, the
 * author's quota or this store is full right now, or the store could not
 * write. Every one of these can clear, so the row is offered again. */
static bool board_refusal_retryable(enum fleet_board_result r)
{
    switch (r) {
    case FLEET_BOARD_ERR_ROLE:
    case FLEET_BOARD_ERR_FUTURE:
    case FLEET_BOARD_ERR_QUOTA:
    case FLEET_BOARD_ERR_WIKI_QUOTA:
    case FLEET_BOARD_ERR_CAPACITY:
    case FLEET_BOARD_ERR_BUSY:
    case FLEET_BOARD_ERR_STORAGE:
    case FLEET_BOARD_ERR_ARGS:
        return true;
    default:
        return false;
    }
}

/* Decode, prove it is the record the header named and that it is
 * fleet-scoped, then hand it to the one ingest every post goes through. */
static enum fleet_board_result board_record_ingest(
    struct node_db *ndb, const struct board_record *rec,
    struct fleet_board_post *post, int64_t now, bool *stored)
{
    *stored = false;
    enum fleet_board_result r =
        fleet_board_post_decode(rec->wire, rec->wire_len, post);
    if (r != FLEET_BOARD_OK)
        return r;
    if (memcmp(post->id, rec->id, 32) != 0)
        return FLEET_BOARD_ERR_ID;
    if (post->scope != FLEET_BOARD_SCOPE_FLEET)
        return FLEET_BOARD_ERR_SCOPE;
    /* From a roster answer, a box not armed yet takes sealed roster rows and
     * offers the rest again once those rows have armed it. */
    if (rec->roster_only && !boot_fleet_roster_is_row(post))
        return FLEET_BOARD_ERR_ROLE;
    /* ZRC 0012 step 2: an armed roster takes fleet posts from its members
     * only, and a roster row only when its seal verifies. A non-member
     * author is this box's own decision, not the peer's fault, so it is the
     * retryable role refusal: the post is offered again once the roster row
     * that names its author arrives. An unsealed roster row is final. */
    r = boot_fleet_roster_screen_post(ndb, post, now);
    if (r != FLEET_BOARD_OK)
        return r;
    r = db_fleet_board_post_ingest(ndb, post, now, stored);
    if (r == FLEET_BOARD_OK && *stored && boot_fleet_roster_is_row(post))
        boot_fleet_roster_invalidate();
    return r;
}

/* Offer one record. A refusal that can clear lowers `carry_min` so a later
 * sweep offers the row again; every other refusal is final and named.
 * None names the post's text: that is the fleet's own. */
static bool board_offer(struct node_db *ndb, const struct board_record *rec,
                        struct fleet_board_post *post, int64_t now,
                        struct board_cursor *c)
{
    bool stored = false;
    enum fleet_board_result r = board_record_ingest(ndb, rec, post, now,
                                                    &stored);
    if (board_refusal_retryable(r)) {
        if (c && (c->carry_min == 0 || rec->arrival < c->carry_min))
            c->carry_min = rec->arrival;
        atomic_fetch_add_explicit(&g_deferred, 1, memory_order_relaxed);
        uint64_t skipped = 0;
        if (boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_DEFERRED, now,
                                      &skipped))
            LOG_WARN("fleet.board", "fleet post deferred: %s (%llu more "
                     "since the last line)", fleet_board_result_string(r),
                     (unsigned long long)skipped);
    } else if (r != FLEET_BOARD_OK && r != FLEET_BOARD_ERR_EXPIRED) {
        /* An expired post is stale, not wrong. */
        LOG_WARN("fleet.board", "fleet post refused: %s",
                 fleet_board_result_string(r));
    }
    return stored;
}

/* Offer every record of a valid answer that this box does not already
 * hold (a held row is settled). A sweep offers only rows inside its range:
 * rows above it belong to forward pulls. */
static size_t board_offer_all(struct node_db *ndb,
                              const struct board_inbox_slot *slot,
                              struct fleet_board_post *post, int64_t now,
                              struct board_cursor *c)
{
    size_t off = FLEET_BOARD_FLEET_ANSWER_HEAD;
    size_t stored = 0;
    struct board_record rec;
    while (board_record_next(slot->rows, slot->len, &off, &rec)) {
        if ((slot->ask.sweep && rec.arrival > c->sweep_end) ||
            db_fleet_board_have(ndb, rec.id))
            continue;
        rec.roster_only = slot->roster_only;
        if (board_offer(ndb, &rec, post, now, c))
            stored++;
    }
    return stored;
}

/* Where the cursor stands once a whole answer has been offered. A forward
 * page settles everything up to the point it reached. A sweep moves on, or
 * ends once it reaches the end of its range or the peer has nothing more. */
static void board_cursor_settle(struct board_cursor *c,
                                const struct board_ask *ask,
                                const struct board_answer_head *h)
{
    if (!ask->sweep) {
        c->next = h->scanned;
        return;
    }
    if (h->scanned >= c->sweep_end || h->scanned == ask->after)
        c->sweep_active = false;
    else
        c->sweep_pos = h->scanned;
}

static size_t board_drain_slot(struct node_db *ndb,
                               const struct board_inbox_slot *slot,
                               struct fleet_board_post *post, int64_t now)
{
    struct board_answer_head h;
    if (!answer_head_decode(slot->rows, slot->len, &h) ||
        !board_answer_valid(slot->rows, slot->len, &h, slot->ask.after)) {
        atomic_fetch_add_explicit(&g_answer_refused, 1, memory_order_relaxed);
        LOG_WARN("fleet.board", "fleet answer refused: malformed");
        return 0;
    }
    struct board_cursor c;
    if (!board_cursor_load(slot->ask.peer_box_id, &c)) {
        /* No room to remember this peer: take what arrived, remember
         * nothing, and ask from the beginning again next time. */
        return slot->ask.sweep ? 0 : board_offer_all(ndb, slot, post, now,
                                                     NULL);
    }
    size_t stored = 0;
    if (board_cursor_epoch(&c, &h, &slot->ask) &&
        board_answer_current(&c, &slot->ask)) {
        stored = board_offer_all(ndb, slot, post, now, &c);
        board_cursor_settle(&c, &slot->ask, &h);
    }
    board_cursor_store(&c);
    return stored;
}

/* A roster answer proves who answered before any row of it is looked at, and
 * leaves a plain answer behind. A refused one is dropped whole and moves no
 * cursor. */
static bool board_answer_open(struct node_db *ndb,
                              struct board_inbox_slot *slot, int64_t now)
{
    struct fleet_board_roster_bind bind;
    if (!slot->ask.roster)
        return true;
    if (board_roster_bind(slot->ask.transcript, slot->ask.generation,
                          slot->ask.after, &bind) &&
        fleet_board_roster_answer_open(ndb, &bind, slot->rows, &slot->len, now,
                                       &slot->roster_only))
        return true;
    atomic_fetch_add_explicit(&g_answer_refused, 1, memory_order_relaxed);
    return false;
}

static size_t board_drain_inbox(struct node_db *ndb, int64_t now)
{
    struct fleet_board_post *post =
        zcl_calloc(1, sizeof *post, "fleet_board_drain");
    if (!post)
        return 0;
    size_t stored = 0;
    for (size_t i = 0; i < FLEET_BOARD_FLEET_INBOX_MAX; i++) {
        board_lock();
        struct board_inbox_slot slot = g_inbox[i];
        memset(&g_inbox[i], 0, sizeof g_inbox[i]);
        board_unlock();
        if (!slot.used)
            continue;
        if (ndb && board_answer_open(ndb, &slot, now))
            stored += board_drain_slot(ndb, &slot, post, now);
        free(slot.rows);
    }
    free(post);
    atomic_fetch_add_explicit(&g_stored, stored, memory_order_relaxed);
    return stored;
}

/* ── the pull lane ───────────────────────────────────────────────────── */

struct board_live_probe {
    uint8_t peer_static[32];
    bool found;
};

static bool board_live_visitor(struct mesh_stream *st, void *ctx)
{
    struct board_live_probe *probe = ctx;
    if (st->local_initiator && !st->ended &&
        memcmp(st->peer_static, probe->peer_static, 32) == 0) {
        probe->found = true;
        return false;
    }
    return true;
}

/* Open one pull stream, which owns `p` from here on when it opens. */
static bool board_stream_open(const char *service,
                              const uint8_t peer_noise[32],
                              const uint8_t *frame, size_t frame_len,
                              struct board_pull_state *p)
{
    uint64_t stream_id = 0;
    enum mesh_stream_refusal refusal = mesh_stream_open(
        service, peer_noise, 0, frame, frame_len, p, &stream_id);
    if (refusal == MESH_STREAM_OK)
        return true;
    if (refusal != MESH_STREAM_REFUSED_PEER_NOT_CONNECTED)
        LOG_WARN("fleet.board", "fleet pull not opened: %s",
                 mesh_stream_refusal_string(refusal));
    free(p);
    return false;
}

/* The one PULL this protocol has, toward a peer the caller has already
 * verified. The lane and the loopback test both enter here. */
static bool board_open_pull(const uint8_t peer_noise[32],
                            const uint8_t peer_box_id[32])
{
    struct board_pull_state *p =
        zcl_calloc(1, sizeof *p, "fleet_board_pull");
    if (!p)
        return false;
    memcpy(p->ask.peer_box_id, peer_box_id, 32);
    board_plan_pull(&p->ask);
    uint8_t frame[FLEET_BOARD_FLEET_PULL_BYTES];
    size_t frame_len = pull_encode(p->ask.after, frame);
    return board_stream_open(FLEET_BOARD_FLEET_SERVICE_NAME, peer_noise, frame,
                             frame_len, p);
}

/* The roster pull: the same page question, plus this box's board key proving
 * itself on the session it is asked over. The peer's Noise static is its
 * cursor key, because its board key is not known until it answers. */
static bool board_open_roster_pull(struct boot_svc_ctx *svc,
                                   const uint8_t peer_noise[32])
{
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof snap);
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return false;
    struct p2p_node *node = boot_mesh_find_session_peer(
        svc->msg_processor->net_mgr, peer_noise, &snap);
    if (!node)
        return false;
    p2p_node_release(node);
    struct board_pull_state *p =
        zcl_calloc(1, sizeof *p, "fleet_board_roster_pull");
    if (!p)
        return false;
    memcpy(p->ask.peer_box_id, peer_noise, 32);
    board_plan_pull(&p->ask);
    p->ask.roster = true;
    memcpy(p->ask.transcript, snap.transcript_hash, 32);
    p->ask.generation = snap.connection_generation;
    uint8_t frame[FLEET_BOARD_ROSTER_PULL_BYTES];
    size_t frame_len = pull_encode(p->ask.after, frame);
    struct fleet_board_roster_bind bind;
    if (!board_roster_bind(snap.transcript_hash, snap.connection_generation,
                           p->ask.after, &bind) ||
        !fleet_board_roster_proof_make(FLEET_BOARD_ROSTER_SIDE_ASK, &bind,
                                       frame + frame_len)) {
        free(p);
        return false;
    }
    frame_len += FLEET_BOARD_ROSTER_PROOF_BYTES;
    return board_stream_open(FLEET_BOARD_ROSTER_SERVICE_NAME, peer_noise, frame,
                             frame_len, p);
}

/* Is this paired row a peer due a pull right now? The same questions the
 * answering half asks, so a stale peer is neither asked nor answered. */
static bool board_peer_due(struct node_db *ndb,
                           const struct db_mesh_pairing *row, int64_t now,
                           struct vcs_zcode_dht_delegation *peer)
{
    if (!mesh_pairing_allows(row, MESH_PAIRING_CAP_STATUS_READ, now) ||
        !board_peer_delegation(row, peer) ||
        !board_delegation_current(ndb, row, peer, row->peer_noise_pubkey,
                                  now) ||
        !board_roster_admits(peer->online_pubkey))
        return false;
    struct board_live_probe probe;
    memset(&probe, 0, sizeof probe);
    memcpy(probe.peer_static, row->peer_noise_pubkey, 32);
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, board_live_visitor,
                      &probe);
    return !probe.found;
}

static void board_pull_paired_peers(int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return;
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_pairings");
    if (!rows)
        return;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_BOARD_FLEET_PEERS_MAX);
    for (int i = 0; i < count; i++) {
        struct vcs_zcode_dht_delegation peer;
        if (board_peer_due(ndb, &rows[i], now, &peer))
            (void)board_open_pull(rows[i].peer_noise_pubkey,
                                  peer.doc.master_pubkey);
    }
    free(rows);
}

/* The roster half of the lane: the sessions the roster names, with no pairing
 * row and no pull already under way. Returns how many pulls opened. */
static size_t board_pull_roster_peers(struct boot_svc_ctx *svc,
                                      struct node_db *store, int64_t now)
{
    struct node_db *pairings = app_runtime_node_db();
    if (!pairings || !app_runtime_node_db_handle_open(pairings))
        return 0;
    uint8_t (*targets)[32] = zcl_calloc(FLEET_BOARD_FLEET_PEERS_MAX,
                                        sizeof *targets, "fleet_board_targets");
    if (!targets)
        return 0;
    size_t n = fleet_board_roster_targets(svc, pairings, store, now, targets,
                                          FLEET_BOARD_FLEET_PEERS_MAX);
    size_t opened = 0;
    for (size_t i = 0; i < n; i++) {
        struct board_live_probe probe;
        memset(&probe, 0, sizeof probe);
        memcpy(probe.peer_static, targets[i], 32);
        mesh_stream_visit(FLEET_BOARD_ROSTER_SERVICE_NAME, board_live_visitor,
                          &probe);
        if (!probe.found && board_open_roster_pull(svc, targets[i]))
            opened++;
    }
    free(targets);
    return opened;
}

/* The manager's half of ZRC 0012 step 2: once per period, put this box's own
 * sealed machine roster onto the board as roster rows. A box that is not the
 * fleet root's own box writes nothing. */
static void board_publish_roster_due(struct node_db *ndb, int64_t now)
{
    board_lock();
    bool due = g_last_roster_publish == 0 ||
               now - g_last_roster_publish >= BOOT_FLEET_ROSTER_PUBLISH_PERIOD_S;
    if (due)
        g_last_roster_publish = now;
    board_unlock();
    if (due)
        (void)boot_fleet_roster_publish(ndb, now);
}

static void board_tick(struct liveness_contract *contract)
{
    (void)contract;
    board_lock();
    struct boot_svc_ctx *svc = g_svc;
    bool wired = svc != NULL;
    int64_t last = g_last_pull;
    board_unlock();
    struct node_db *ndb = board_db();
    if (!wired || !ndb) {
        supervisor_progress_idle(g_child);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    (void)board_drain_inbox(ndb, now);
    if (now <= 0 ||
        (last != 0 && now - last < FLEET_BOARD_FLEET_PULL_INTERVAL_S)) {
        supervisor_progress_idle(g_child);
        return;
    }
    board_lock();
    g_last_pull = now;
    board_unlock();
    board_publish_roster_due(ndb, now);
    board_pull_paired_peers(now);
    (void)board_pull_roster_peers(svc, ndb, now);
}

void boot_fleet_board_fleet_counts(struct boot_fleet_board_fleet_counts *out)
{
    if (!out)
        return;
    out->delegation_refused =
        atomic_load_explicit(&g_delegation_refused, memory_order_relaxed);
    out->role_refused =
        atomic_load_explicit(&g_role_refused, memory_order_relaxed);
    out->inbox_full =
        atomic_load_explicit(&g_inbox_full, memory_order_relaxed);
    out->stored = atomic_load_explicit(&g_stored, memory_order_relaxed);
    out->deferred = atomic_load_explicit(&g_deferred, memory_order_relaxed);
    out->answer_refused =
        atomic_load_explicit(&g_answer_refused, memory_order_relaxed);
    out->roster_refused = fleet_board_roster_refused_count();
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

/* Lane lock held. */
static void board_forget_locked(void)
{
    for (size_t i = 0; i < FLEET_BOARD_FLEET_INBOX_MAX; i++)
        free(g_inbox[i].rows);
    memset(g_inbox, 0, sizeof g_inbox);
    memset(g_cursors, 0, sizeof g_cursors);
    g_cursors_loaded = false;
    g_last_pull = 0;
    g_last_roster_publish = 0;
    fleet_board_roster_forget();
}

void boot_fleet_board_fleet_wire(struct boot_svc_ctx *svc)
{
    if (!svc) {
        LOG_ERROR("fleet.board", "fleet carriage wire: no context");
        return;
    }
    board_lock();
    bool already = g_svc != NULL;
    if (!already) {
        g_svc = svc;
        board_forget_locked();
    }
    board_unlock();
    if (already) {
        LOG_ERROR("fleet.board", "fleet carriage wire: already wired");
        return;
    }
    if (!boot_fleet_board_fleet_register_service()) {
        LOG_ERROR("fleet.board", "board stream service refused");
        return;
    }
    liveness_contract_init(&g_contract, "fleet.board_pull");
    g_contract.on_tick = board_tick;
    supervisor_domains_init();
    g_child = supervisor_register_in_domain(g_net_sup, &g_contract);
    if (g_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR("fleet.board", "fleet pull supervisor register failed");
        return;
    }
    supervisor_set_period(g_child, 1);
    g_contract.period_us = 1000000;
    supervisor_set_deadline(g_child, 120);
    supervisor_set_progress_exempt(g_child,
                                   "paired peers may have nothing new to say");
}

void boot_fleet_board_fleet_shutdown(void)
{
    mesh_stream_service_unregister(FLEET_BOARD_FLEET_SERVICE_NAME);
    mesh_stream_service_unregister(FLEET_BOARD_ROSTER_SERVICE_NAME);
    board_lock();
    supervisor_child_id child = g_child;
    g_child = SUPERVISOR_INVALID_ID;
    g_svc = NULL;
    board_forget_locked();
    board_unlock();
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
}

#ifdef ZCL_TESTING
void boot_fleet_board_fleet_test_bind(struct node_db *serve_db)
{
    board_lock();
    g_test_db = serve_db;
    board_forget_locked();
    board_unlock();
}

bool boot_fleet_board_fleet_test_pull(const uint8_t peer_noise[32],
                                      const uint8_t peer_box_id[32])
{
    return board_open_pull(peer_noise, peer_box_id);
}

void boot_fleet_board_fleet_test_pull_paired(int64_t now)
{
    if (now > 0)
        board_pull_paired_peers(now);
}

bool boot_fleet_board_fleet_test_pull_roster(struct boot_svc_ctx *svc,
                                             const uint8_t peer_noise[32])
{
    return board_open_roster_pull(svc, peer_noise);
}

size_t boot_fleet_board_fleet_test_pull_roster_lane(struct boot_svc_ctx *svc,
                                                    struct node_db *store,
                                                    int64_t now)
{
    return board_pull_roster_peers(svc, store, now);
}

/* The answering drain, run once from inside the lane lock — which is
 * exactly where and how the shared stream pump runs it. */
static bool board_serve_visitor(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    if (!st->local_initiator && !st->ended)
        board_service_tick(st, board_now(), NULL);
    return true;
}

void boot_fleet_board_fleet_test_serve(void)
{
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, board_serve_visitor,
                      NULL);
    mesh_stream_visit(FLEET_BOARD_ROSTER_SERVICE_NAME, board_serve_visitor,
                      NULL);
}

size_t boot_fleet_board_fleet_test_drain_into(struct node_db *ndb)
{
    return ndb && ndb->open ? board_drain_inbox(ndb, board_now()) : 0;
}

void boot_fleet_board_fleet_test_bind_authority(
    const struct vcs_zcode_dht_delegation *peer_delegation,
    const uint8_t network_genesis[32], int64_t now)
{
    board_lock();
    g_test_authority = peer_delegation && network_genesis && now > 0;
    memset(&g_test_delegation, 0, sizeof g_test_delegation);
    memset(g_test_genesis, 0, sizeof g_test_genesis);
    g_test_now = 0;
    if (g_test_authority) {
        g_test_delegation = *peer_delegation;
        memcpy(g_test_genesis, network_genesis, 32);
        g_test_now = now;
    }
    board_unlock();
}

/* The answering process as if it had restarted: the next answer carries a
 * fresh epoch. */
void boot_fleet_board_fleet_test_new_epoch(void)
{
    board_lock();
    g_epoch_ready = false;
    board_unlock();
}

void boot_fleet_board_fleet_test_cursor_dir(const char *dir)
{
    board_lock();
    g_test_cursor_dir[0] = '\0';
    if (dir && dir[0])
        (void)snprintf(g_test_cursor_dir, sizeof g_test_cursor_dir, "%s", dir);
    board_unlock();
}

void boot_fleet_board_fleet_test_restart_cursors(void)
{
    board_lock();
    memset(g_cursors, 0, sizeof g_cursors);
    g_cursors_loaded = false;
    board_unlock();
}

int64_t boot_fleet_board_fleet_test_last_after(void)
{
    return g_test_last_after;
}
#endif
