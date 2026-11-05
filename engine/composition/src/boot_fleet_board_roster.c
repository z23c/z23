/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet-scope board carriage between machines the owner sealed onto
 * the fleet roster, with no pairing row and no coin spent. See
 * config/boot_fleet_board.h for the contract.
 *
 * A Noise session proves a static key and a roster line names a board signing
 * key, so neither says the other is on the roster. The bridge is one Ed25519
 * signature by the board signing key over this exact session, carried in the
 * pull and in its answer. Membership is asked first, from the cached roster
 * and with no signature check, so a stranger costs a memcmp.
 *
 * No secret passes through here but the seed one signature needs; it is
 * cleansed before the call returns. Refusals log a token, never a key.
 */

#include "boot_fleet_board_roster_internal.h"

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "config/boot_fleet_board.h"
#include "config/boot_fleet_roster.h"
#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "crypto/ed25519.h"
#include "models/fleet_board_post.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/noise_transport.h"
#include "services/p2p_node_noise.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exactly 32 bytes on the wire, trailing zeros included. */
static const uint8_t PROOF_DOMAIN[32] = "z23-fleet-board-roster-proof-v1";

enum {
    /* domain, side, genesis, transcript, generation, after, key */
    PROOF_MESSAGE_BYTES = 32 + 1 + 32 + 32 + 8 + 8 + 32,
    /* The roster's onions are read at most this often (seconds): each line
     * costs signature checks, and a line changes when an operator acts. */
    ONIONS_REUSE_S = 120,
};

struct learned_peer {
    bool used;
    uint8_t noise[32];
    uint8_t key[32];
};

struct onion_set {
    bool valid;
    int64_t built_at;
    size_t n;
    struct net_addr addr[BOOT_FLEET_ROSTER_MAX];
};

static zcl_mutex_t g_lock; /* guards g_learned, g_learned_next and g_onions */
static zcl_once_t g_lock_once = ZCL_ONCE_INIT;
static struct learned_peer g_learned[FLEET_BOARD_FLEET_PEERS_MAX];
static size_t g_learned_next;
static struct onion_set g_onions;
/* The head row to lead an answer with, found on the lane tick. No index leads
 * with the agent, so looking for it costs a walk of the store, which the frame
 * loop must not pay on every OPEN. Guarded by g_lock. */
static struct {
    bool have;
    int64_t built_at;
    int64_t arrival;
    uint8_t id[32];
} g_pin;
static _Atomic uint64_t g_refused;

#ifdef ZCL_TESTING
/* Both halves share one process in the loopback test, so each side signs as
 * the box it stands in for. */
static bool g_test_identity_set[3];
static uint8_t g_test_seed[3][32];
static uint8_t g_test_pub[3][32];
#endif

static void roster_lock_init(void)
{
    zcl_mutex_init(&g_lock);
}

static void roster_lock(void)
{
    (void)zcl_once_call(&g_lock_once, roster_lock_init);
    zcl_mutex_lock(&g_lock);
}

static void roster_unlock(void)
{
    zcl_mutex_unlock(&g_lock);
}

/* One rate-limited line per kind, and every refusal counted. */
static void roster_refuse(const char *token, int64_t now)
{
    uint64_t skipped = 0;
    atomic_fetch_add_explicit(&g_refused, 1, memory_order_relaxed);
    if (boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_PEER_REFUSED, now,
                                  &skipped))
        LOG_WARN("fleet.board", "fleet roster carriage refused: %s (%llu more "
                 "since the last line)", token, (unsigned long long)skipped);
}

uint64_t fleet_board_roster_refused_count(void)
{
    return atomic_load_explicit(&g_refused, memory_order_relaxed);
}

/* ── the proof ───────────────────────────────────────────────────────── */

static void proof_message(enum fleet_board_roster_side side,
                          const struct fleet_board_roster_bind *bind,
                          const uint8_t key[32],
                          uint8_t out[PROOF_MESSAGE_BYTES])
{
    uint8_t *at = out;
    memcpy(at, PROOF_DOMAIN, 32);
    at += 32;
    *at++ = (uint8_t)side;
    memcpy(at, bind->network_genesis, 32);
    at += 32;
    memcpy(at, bind->transcript_hash, 32);
    at += 32;
    zcl_write_u64_be(at, bind->connection_generation);
    at += 8;
    zcl_write_u64_be(at, (uint64_t)bind->after);
    at += 8;
    memcpy(at, key, 32);
}

static bool proof_identity(enum fleet_board_roster_side side, uint8_t seed[32],
                           uint8_t pub[32])
{
    char why[160];
    (void)side; /* only the test seam tells the two sides apart */
#ifdef ZCL_TESTING
    if (g_test_identity_set[side]) {
        memcpy(seed, g_test_seed[side], 32);
        memcpy(pub, g_test_pub[side], 32);
        return true;
    }
#endif
    if (boot_fleet_board_identity(seed, pub, why, sizeof why))
        return true;
    LOG_WARN("fleet.board", "cannot prove roster membership: %s", why);
    return false;
}

bool fleet_board_roster_proof_make(enum fleet_board_roster_side side,
                                   const struct fleet_board_roster_bind *bind,
                                   uint8_t *out)
{
    uint8_t seed[32], pub[32], message[PROOF_MESSAGE_BYTES];
    if (!bind || !out || !proof_identity(side, seed, pub))
        return false;
    proof_message(side, bind, pub, message);
    memcpy(out, pub, 32);
    ed25519_sign(out + 32, message, sizeof message, seed, pub);
    memory_cleanse(seed, sizeof seed);
    return true;
}

bool fleet_board_roster_proof_check(enum fleet_board_roster_side side,
                                    const struct fleet_board_roster_bind *bind,
                                    const uint8_t *proof)
{
    uint8_t message[PROOF_MESSAGE_BYTES];
    if (!bind || !proof)
        return false;
    proof_message(side, bind, proof, message);
    return ed25519_verify(proof + 32, message, sizeof message, proof);
}

/* ── the two halves' decisions ───────────────────────────────────────── */

/* Fail closed: an unreadable list reads as a row, so the roster path stands
 * aside and the peer gets what it gets today. */
static bool pairing_row_held(struct node_db *pairings,
                             const uint8_t peer_noise[32])
{
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_roster_rows");
    if (!rows)
        return true;
    int count = db_mesh_pairing_list_after_checked(
        pairings, rows, FLEET_BOARD_FLEET_PEERS_MAX, 0);
    bool held = count < 0;
    for (int i = 0; i < count && !held; i++)
        held = memcmp(rows[i].peer_noise_pubkey, peer_noise, 32) == 0;
    free(rows);
    return held;
}

bool fleet_board_roster_standing(struct node_db *pairings,
                                 struct node_db *store,
                                 const uint8_t peer_noise[32],
                                 const uint8_t key[32], int64_t now)
{
    if (!pairings || !store || !peer_noise || !key)
        return false;
    if (pairing_row_held(pairings, peer_noise)) {
        roster_refuse("peer_has_pairing_row", now);
        return false;
    }
    if (!boot_fleet_roster_carries_peer(store, key, now)) {
        roster_refuse("not_a_member_of_an_armed_roster", now);
        return false;
    }
    return true;
}

bool fleet_board_roster_admit(struct node_db *pairings, struct node_db *store,
                              const struct fleet_board_roster_bind *bind,
                              const uint8_t peer_noise[32],
                              const uint8_t *proof, int64_t now)
{
    if (!proof ||
        !fleet_board_roster_standing(pairings, store, peer_noise, proof, now))
        return false;
    if (fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK, bind,
                                       proof))
        return true;
    roster_refuse("asking_proof_invalid", now);
    return false;
}

bool fleet_board_roster_answer_open(struct node_db *ndb,
                                    const struct fleet_board_roster_bind *bind,
                                    uint8_t *rows, size_t *len, int64_t now,
                                    bool *roster_only)
{
    if (*len < FLEET_BOARD_ROSTER_PROOF_BYTES) {
        roster_refuse("answer_carries_no_proof", now);
        return false;
    }
    enum boot_fleet_roster_verdict v = boot_fleet_roster_check(ndb, rows, now);
    bool bootstrap = v == BOOT_FLEET_ROSTER_UNARMED &&
                     boot_fleet_roster_carriage_open(ndb);
    if (v != BOOT_FLEET_ROSTER_MEMBER && !bootstrap) {
        roster_refuse("answering_peer_not_a_member", now);
        return false;
    }
    if (!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ANSWER, bind,
                                        rows)) {
        roster_refuse("answering_proof_invalid", now);
        return false;
    }
    *len -= FLEET_BOARD_ROSTER_PROOF_BYTES;
    memmove(rows, rows + FLEET_BOARD_ROSTER_PROOF_BYTES, *len);
    *roster_only = bootstrap;
    return true;
}

/* ── who to ask ──────────────────────────────────────────────────────── */

void fleet_board_roster_learn(const uint8_t peer_noise[32],
                              const uint8_t key[32])
{
    roster_lock();
    struct learned_peer *slot = &g_learned[g_learned_next];
    bool known = false;
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX && !known; i++) {
        if (g_learned[i].used &&
            memcmp(g_learned[i].noise, peer_noise, 32) == 0) {
            slot = &g_learned[i];
            known = true;
        }
    }
    if (!known)
        g_learned_next = (g_learned_next + 1) % FLEET_BOARD_FLEET_PEERS_MAX;
    slot->used = true;
    memcpy(slot->noise, peer_noise, 32);
    memcpy(slot->key, key, 32);
    roster_unlock();
}

void fleet_board_roster_forget(void)
{
    roster_lock();
    memset(g_learned, 0, sizeof g_learned);
    memset(&g_onions, 0, sizeof g_onions);
    memset(&g_pin, 0, sizeof g_pin);
    g_learned_next = 0;
    roster_unlock();
}

void fleet_board_roster_pin_refresh(struct node_db *store, int64_t now)
{
    struct db_fleet_board_post *row =
        zcl_calloc(1, sizeof *row, "fleet_board_pin");
    if (!row)
        return;
    bool have = boot_fleet_roster_newest_head_row(store, now, row);
    roster_lock();
    g_pin.have = have;
    g_pin.built_at = now;
    g_pin.arrival = have ? row->arrival : 0;
    memcpy(g_pin.id, row->post.id, 32);
    roster_unlock();
    free(row);
}

bool fleet_board_roster_pinned_head(struct node_db *store, int64_t after,
                                    struct db_fleet_board_post *out)
{
    uint8_t id[32];
    roster_lock();
    bool due = g_pin.have && g_pin.arrival > after;
    memcpy(id, g_pin.id, 32);
    roster_unlock();
    return due && db_fleet_board_post_find(store, id, out) &&
           boot_fleet_roster_is_head_row(&out->post);
}

static void pin_refresh_due(struct node_db *store, int64_t now)
{
    roster_lock();
    bool fresh = g_pin.built_at != 0 && now >= g_pin.built_at &&
                 now - g_pin.built_at < ONIONS_REUSE_S;
    roster_unlock();
    if (!fresh)
        fleet_board_roster_pin_refresh(store, now);
}

/* A peer that proved a member key here, and whose key still is one. */
static bool learned_member(struct node_db *store, const uint8_t noise[32],
                           int64_t now)
{
    uint8_t key[32];
    bool known = false;
    roster_lock();
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX && !known; i++) {
        if (g_learned[i].used && memcmp(g_learned[i].noise, noise, 32) == 0) {
            memcpy(key, g_learned[i].key, 32);
            known = true;
        }
    }
    roster_unlock();
    return known &&
           boot_fleet_roster_check(store, key, now) == BOOT_FLEET_ROSTER_MEMBER;
}

static void onion_visit(const struct boot_fleet_roster_machine *m, void *user)
{
    struct onion_set *set = user;
    char host[BOOT_FLEET_ROSTER_ONION_MAX];
    if (m->self || !m->onion[0] || set->n >= BOOT_FLEET_ROSTER_MAX)
        return;
    (void)snprintf(host, sizeof host, "%s", m->onion);
    char *port = strchr(host, ':');
    if (port)
        *port = '\0';
    if (net_addr_from_onion(host, &set->addr[set->n]))
        set->n++;
}

/* The onion each OTHER machine's sealed line claims, read at most once per
 * ONIONS_REUSE_S. An address this box dials is the machine's own signed
 * claim; the answering proof is what tests it. */
static void onions_refresh(struct node_db *store, int64_t now)
{
    roster_lock();
    bool fresh = g_onions.valid && now >= g_onions.built_at &&
                 now - g_onions.built_at < ONIONS_REUSE_S;
    roster_unlock();
    if (fresh)
        return;
    struct onion_set *set = zcl_calloc(1, sizeof *set, "fleet_board_onions");
    if (!set)
        return;
    (void)boot_fleet_roster_each_machine(store, now, onion_visit, set);
    set->valid = true;
    set->built_at = now;
    roster_lock();
    g_onions = *set;
    roster_unlock();
    free(set);
}

static bool onion_claimed(const struct p2p_node *node)
{
    bool claimed = false;
    roster_lock();
    for (size_t i = 0; i < g_onions.n && !claimed; i++)
        claimed = net_addr_eq(&node->addr.svc.addr, &g_onions.addr[i]);
    roster_unlock();
    return claimed;
}

static bool target_listed(const uint8_t (*out)[32], size_t n,
                          const uint8_t noise[32])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(out[i], noise, 32) == 0)
            return true;
    return false;
}

/* Is this node an established session this lane may ask? */
static bool target_judge(struct p2p_node *node, struct node_db *pairings,
                         struct node_db *store, int64_t now,
                         uint8_t noise[32])
{
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof snap);
    if (!p2p_node_noise_snapshot(node, &snap) || !snap.established)
        return false;
    memcpy(noise, snap.remote_static, 32);
    return (onion_claimed(node) || learned_member(store, noise, now)) &&
           !pairing_row_held(pairings, noise);
}

size_t fleet_board_roster_targets(struct boot_svc_ctx *svc,
                                  struct node_db *pairings,
                                  struct node_db *store, int64_t now,
                                  uint8_t (*out)[32], size_t cap)
{
    struct p2p_node *nodes[FLEET_BOARD_FLEET_PEERS_MAX];
    size_t count = 0, n = 0;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr ||
        !pairings || !store || !out ||
        !boot_fleet_roster_carriage_open(store))
        return 0;
    onions_refresh(store, now);
    pin_refresh_due(store, now);
    struct net_manager *nm = svc->msg_processor->net_mgr;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes && count < FLEET_BOARD_FLEET_PEERS_MAX;
         i++) {
        if (!boot_zcode_dht_peer_ready(nm->nodes[i]))
            continue;
        nodes[count++] = nm->nodes[i];
        p2p_node_add_ref(nm->nodes[i]);
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    for (size_t i = 0; i < count; i++) {
        uint8_t noise[32];
        if (n < cap && target_judge(nodes[i], pairings, store, now, noise) &&
            !target_listed(out, n, noise))
            memcpy(out[n++], noise, 32);
        p2p_node_release(nodes[i]);
    }
    return n;
}

#ifdef ZCL_TESTING
void boot_fleet_board_fleet_test_roster_identity(int side, const uint8_t *seed,
                                                 const uint8_t *pub)
{
    if (side != (int)FLEET_BOARD_ROSTER_SIDE_ASK &&
        side != (int)FLEET_BOARD_ROSTER_SIDE_ANSWER)
        return;
    g_test_identity_set[side] = seed && pub;
    if (seed && pub) {
        memcpy(g_test_seed[side], seed, 32);
        memcpy(g_test_pub[side], pub, 32);
    }
}
#endif
