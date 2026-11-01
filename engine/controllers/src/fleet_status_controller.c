/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * core.wallet.fleet.status. See controllers/fleet_status_controller.h.
 *
 * Membership and the machine list come from the verified roster
 * (config/boot_fleet_roster.h); connections come from the connection
 * manager; each machine's best block comes from the cache in
 * controllers/fleet_tip.h. No wallet state is read or returned, and nothing
 * here waits on the network. */

#include "controllers/fleet_status_controller.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "platform/clock.h"
#include "config/runtime.h"
#include "controllers/blockchain_controller.h"
#include "controllers/fleet_tip.h"
#include "controllers/network_controller.h"
#include "controllers/strong_params.h"
#include "json/json.h"
#include "models/database.h"
#include "net/connman.h"
#include "util/fleet_roster_check.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_STATUS_PEERS_MAX 1024u

/* ── the roster half ─────────────────────────────────────────────────── */

static struct fleet_status_machine *machine_for_box(struct fleet_status *s,
                                                     const uint8_t box[32])
{
    for (size_t i = 0; i < s->machine_count; i++)
        if (memcmp(s->machines[i].box, box, 32) == 0)
            return &s->machines[i];
    return NULL;
}

static void machine_set(struct fleet_status_machine *d,
                        const struct boot_fleet_roster_machine *m)
{
    memcpy(d->box, m->box, sizeof d->box);
    memcpy(d->onion, m->onion, sizeof d->onion);
    memcpy(d->name, m->name, sizeof d->name);
    d->enrolled_at = m->enrolled_at;
}

/* One verified line. A box admitted again has several rows under one key, and
 * the newest enrolment is the machine: an onion the operator retired names
 * nobody. At equal times the earlier row stays, unless it names no onion. */
static void collect_visit(const struct boot_fleet_roster_machine *m,
                          void *user)
{
    struct fleet_status *s = user;
    struct fleet_status_machine *known;
    if (m->self)
        return;
    known = machine_for_box(s, m->box);
    if (known) {
        if (m->enrolled_at > known->enrolled_at ||
            (m->enrolled_at == known->enrolled_at && !known->onion[0] &&
             m->onion[0]))
            machine_set(known, m);
        return;
    }
    if (s->machine_count >= BOOT_FLEET_ROSTER_MAX)
        return;
    machine_set(&s->machines[s->machine_count++], m);
}

void fleet_status_collect(struct node_db *ndb, int64_t now,
                          struct fleet_status *out)
{
    uint8_t root[32];
    bool present = false;
    memset(out, 0, sizeof *out);
    if (zcl_fleet_roster_root(root, &present, NULL)) {
        out->member = present;
    } else {
        /* A recorded root that cannot be read is unverifiable, never absent:
         * the roster and the refusals stored against it cannot be told. */
        out->member = true;
        out->unverifiable = true;
    }
    memory_cleanse(root, sizeof root);
    if (out->member)
        (void)boot_fleet_roster_each_machine(ndb, now, collect_visit, out);
    out->verdict = out->member ? FLEET_STATUS_NONE_CONNECTED
                               : FLEET_STATUS_NOT_MEMBER;
}

/* ── the connection half ─────────────────────────────────────────────── */

bool fleet_status_onion_key(const char *addr, char *out, size_t cap)
{
    static const char suffix[] = ".onion";
    const size_t slen = sizeof suffix - 1;
    size_t n = 0;
    if (!addr || !out || !cap)
        return false;
    while (addr[n] && addr[n] != ':')
        n++;
    if (n <= slen || n >= cap)
        return false;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)tolower((unsigned char)addr[i]);
    out[n] = '\0';
    return strcmp(out + n - slen, suffix) == 0;
}

/* The index of the machine whose sealed onion is this outbound connection's
 * host, or -1. */
static int machine_index_for_peer(const struct fleet_status *s,
                                  const char *addr_name, bool inbound)
{
    char host[256], claim[BOOT_FLEET_ROSTER_ONION_MAX];
    if (inbound || !fleet_status_onion_key(addr_name, host, sizeof host))
        return -1; // raw-return-ok:not a roster machine
    for (size_t i = 0; i < s->machine_count; i++)
        if (fleet_status_onion_key(s->machines[i].onion, claim,
                                   sizeof claim) &&
            strcmp(host, claim) == 0)
            return (int)i;
    return -1; // raw-return-ok:not a roster machine
}

/* ── the comparison ──────────────────────────────────────────────────── */

/* A machine above this node's tip, by the block it names at the height this
 * node asked about. Without an answer for a height this node holds, nothing
 * is learned. */
static enum fleet_status_agreement classify_above(
    const struct fleet_tip *t, const struct fleet_status_local *local)
{
    char ours[FLEET_TIP_HASH_HEX + 1];
    if (!t->has_at || t->at_height <= 0 || t->at_height > local->tip ||
        !local->hash_at ||
        !local->hash_at(t->at_height, ours, local->ctx))
        return FLEET_STATUS_UNKNOWN;
    return strcmp(ours, t->at_hash) == 0 ? FLEET_STATUS_PHONE_BEHIND
                                         : FLEET_STATUS_MACHINE_DISAGREES;
}

/* How a check of a machine relates to `local`'s chain. */
static enum fleet_status_agreement fleet_status_classify(
    const struct fleet_tip *t, const struct fleet_status_local *local)
{
    char ours[FLEET_TIP_HASH_HEX + 1];
    if (!local || local->tip <= 0 || t->height < 0)
        return FLEET_STATUS_UNKNOWN;
    if (t->height > local->tip)
        return classify_above(t, local);
    if (!local->hash_at || !local->hash_at(t->height, ours, local->ctx))
        return FLEET_STATUS_UNKNOWN;
    if (strcmp(ours, t->hash) != 0)
        return FLEET_STATUS_MACHINE_DISAGREES;
    if (t->height == local->tip)
        return FLEET_STATUS_AGREES;
    /* Further down it may share only an old ancestor and has checked none of
     * the top blocks of this node: unknown, never agreement. */
    return local->tip - t->height <= FLEET_STATUS_AGREE_DEPTH
               ? FLEET_STATUS_MACHINE_BEHIND
               : FLEET_STATUS_UNKNOWN;
}

/* Does a disagreement hold a send back? Only from a machine at or above
 * this node's tip: one below it is reported but cannot. */
static bool disagreement_refuses(const struct fleet_tip *t,
                                 const struct fleet_status_local *local)
{
    return local && t->height >= local->tip;
}

/* ── the standing refusal ────────────────────────────────────────────── */

/* The refusal key of a machine: its box key as lowercase hex. */
static void box_key(const uint8_t box[32], char out[FLEET_TIP_REFUSAL_KEY_MAX])
{
    zcl_hex_encode(box, 32, out);
}

/* The node_state name of the standing refusal of the machine `key`. */
static bool refusal_name(const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "fleet_refusal.%s", key);
    return n > 0 && (size_t)n < cap;
}

/* The refused height stored in `ndb` for `key`, 0 when none. */
static int64_t refusal_load(struct node_db *ndb, const char *key)
{
    char name[FLEET_TIP_REFUSAL_KEY_MAX + 16];
    int64_t height = 0;
    if (!ndb || !refusal_name(key, name, sizeof name) ||
        !node_db_state_get_int(ndb, name, &height) || height <= 0)
        return 0;
    return height;
}

/* Write the refused height of `key` to `ndb`; 0 deletes it. A failed write
 * leaves the in-memory refusal standing. */
static void refusal_store(struct node_db *ndb, const char *key, int64_t height)
{
    char name[FLEET_TIP_REFUSAL_KEY_MAX + 16];
    bool ok;
    if (!ndb || !refusal_name(key, name, sizeof name))
        return;
    ok = height > 0 ? node_db_state_set_int(ndb, name, height)
                    : node_db_state_delete(ndb, name);
    if (!ok)
        LOG_WARN("fleet.status", "standing send refusal not stored: height=%lld",
                 (long long)height);
}

/* The height a check speaks for: the block a machine above the tip named, or
 * the machine's own best block. */
static int64_t checked_height(const struct fleet_tip *t,
                              enum fleet_status_agreement a)
{
    return a == FLEET_STATUS_PHONE_BEHIND ? t->at_height : t->height;
}

void fleet_status_note_check(struct node_db *ndb, const uint8_t box[32],
                             const struct fleet_tip *t,
                             const struct fleet_status_local *local)
{
    char key[FLEET_TIP_REFUSAL_KEY_MAX];
    enum fleet_status_agreement a = fleet_status_classify(t, local);
    box_key(box, key);
    fleet_tip_cache_raise_refusal(key, refusal_load(ndb, key));
    switch (a) {
    case FLEET_STATUS_AGREES:
    case FLEET_STATUS_PHONE_BEHIND:
    case FLEET_STATUS_MACHINE_BEHIND: {
        int64_t held = fleet_tip_cache_refusal(key);
        if (held > 0 && checked_height(t, a) >= held) {
            fleet_tip_cache_clear_refusal(key);
            refusal_store(ndb, key, 0);
        }
        break;
    }
    case FLEET_STATUS_MACHINE_DISAGREES:
        if (disagreement_refuses(t, local)) {
            fleet_tip_cache_raise_refusal(key, local->tip);
            refusal_store(ndb, key, fleet_tip_cache_refusal(key));
        }
        break;
    case FLEET_STATUS_UNKNOWN:
        break;
    }
}

void fleet_status_load_refusals(struct node_db *ndb,
                                const struct fleet_status *s)
{
    for (size_t i = 0; s && i < s->machine_count; i++) {
        char key[FLEET_TIP_REFUSAL_KEY_MAX];
        int64_t stored, held;
        box_key(s->machines[i].box, key);
        stored = refusal_load(ndb, key);
        fleet_tip_cache_raise_refusal(key, stored);
        held = fleet_tip_cache_refusal(key);
        if (held > 0 && held != stored)
            refusal_store(ndb, key, held);
    }
}

/* The agreement of one connected machine from its cached check at `now`. */
static void judge(struct fleet_status_machine *m,
                  const struct fleet_status_local *local, int64_t now)
{
    char key[BOOT_FLEET_ROSTER_ONION_MAX];
    struct fleet_tip t;
    bool fresh;
    if (!fleet_status_onion_key(m->onion, key, sizeof key) ||
        !fleet_tip_cache_get(key, &t))
        return;
    fresh = now >= t.fetched_at && now - t.fetched_at <= FLEET_TIP_MAX_AGE_SECS;
    if (!fresh)
        return;
    m->agreement = fleet_status_classify(&t, local);
    m->refusing = m->agreement == FLEET_STATUS_MACHINE_DISAGREES &&
                  disagreement_refuses(&t, local);
    m->tip_height = t.height;
    if (local && t.height >= 0 && t.height < local->tip)
        m->depth = local->tip - t.height;
}

/* A standing refusal shows as a disagreement of its machine however old its
 * check is and whether or not the machine is connected. */
static void standing(struct fleet_status_machine *m)
{
    char key[FLEET_TIP_REFUSAL_KEY_MAX], onion[BOOT_FLEET_ROSTER_ONION_MAX];
    struct fleet_tip t;
    box_key(m->box, key);
    if (fleet_tip_cache_refusal(key) <= 0)
        return;
    m->agreement = FLEET_STATUS_MACHINE_DISAGREES;
    m->refusing = true;
    if (m->tip_height == 0 && fleet_status_onion_key(m->onion, onion, sizeof onion) &&
        fleet_tip_cache_get(onion, &t))
        m->tip_height = t.height;
}

static bool settles_agreement(const struct fleet_status_machine *m)
{
    return m->agreement == FLEET_STATUS_AGREES ||
           m->agreement == FLEET_STATUS_MACHINE_BEHIND;
}

static enum fleet_status_verdict verdict_of(const struct fleet_status *s)
{
    bool settled = false;
    if (!s->member)
        return FLEET_STATUS_NOT_MEMBER;
    for (size_t i = 0; i < s->machine_count; i++)
        if (s->machines[i].agreement == FLEET_STATUS_MACHINE_DISAGREES)
            return FLEET_STATUS_DISAGREE;
    if (s->connected_count == 0)
        return FLEET_STATUS_NONE_CONNECTED;
    for (size_t i = 0; i < s->machine_count; i++)
        settled = settled || settles_agreement(&s->machines[i]);
    return settled ? FLEET_STATUS_AGREE : FLEET_STATUS_UNCHECKED;
}

static bool refusal_of(const struct fleet_status *s)
{
    for (size_t i = 0; i < s->machine_count; i++)
        if (s->machines[i].refusing)
            return true;
    return false;
}

void fleet_status_apply(struct fleet_status *s,
                        const struct fleet_status_peer *peers, size_t n,
                        const struct fleet_status_local *local, int64_t now)
{
    s->local_tip = local ? local->tip : 0;
    s->connected_count = 0;
    for (size_t i = 0; i < s->machine_count; i++) {
        s->machines[i].connected = false;
        s->machines[i].agreement = FLEET_STATUS_UNKNOWN;
        s->machines[i].tip_height = 0;
        s->machines[i].depth = 0;
        s->machines[i].refusing = false;
    }
    for (size_t i = 0; s->member && peers && i < n; i++) {
        int at = machine_index_for_peer(s, peers[i].host, peers[i].inbound);
        struct fleet_status_machine *m = at < 0 ? NULL : &s->machines[at];
        if (!m || m->connected)
            continue;
        m->connected = true;
        judge(m, local, now);
        s->connected_count++;
    }
    for (size_t i = 0; i < s->machine_count; i++)
        standing(&s->machines[i]);
    s->verdict = verdict_of(s);
    s->refuses_send = refusal_of(s);
    if (s->unverifiable) {
        s->verdict = FLEET_STATUS_UNCHECKED;
        s->refuses_send = true;
    }
}

bool fleet_status_peer_on_roster(const struct fleet_status *s,
                                 const char *addr_name, bool inbound)
{
    return s && s->member &&
           machine_index_for_peer(s, addr_name, inbound) >= 0;
}

const char *fleet_status_verdict_name(enum fleet_status_verdict v)
{
    switch (v) {
    case FLEET_STATUS_NOT_MEMBER: return "not_member";
    case FLEET_STATUS_NONE_CONNECTED: return "none_connected";
    case FLEET_STATUS_UNCHECKED: return "unchecked";
    case FLEET_STATUS_AGREE: return "agree";
    case FLEET_STATUS_DISAGREE: return "disagree";
    }
    return "none_connected";
}

const char *fleet_status_agreement_name(enum fleet_status_agreement a)
{
    switch (a) {
    case FLEET_STATUS_AGREES: return "agrees";
    case FLEET_STATUS_PHONE_BEHIND: return "phone_behind";
    case FLEET_STATUS_MACHINE_BEHIND: return "machine_behind";
    case FLEET_STATUS_MACHINE_DISAGREES: return "disagree";
    case FLEET_STATUS_UNKNOWN: break;
    }
    return "unknown";
}

/* ── the reply ───────────────────────────────────────────────────────── */

void fleet_status_render(const struct fleet_status *s, struct json_value *out)
{
    struct json_value list;
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.fleet_status.v1");
    json_push_kv_bool(out, "member", s->member);
    json_push_kv_str(out, "verdict", fleet_status_verdict_name(s->verdict));
    json_push_kv_bool(out, "refuses_send", s->refuses_send);
    json_push_kv_int(out, "machines_total", (int64_t)s->machine_count);
    json_push_kv_int(out, "machines_connected", (int64_t)s->connected_count);
    json_push_kv_int(out, "local_tip", s->local_tip > 0 ? s->local_tip : 0);
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < s->machine_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "name", s->machines[i].name);
        json_push_kv_bool(&row, "connected", s->machines[i].connected);
        json_push_kv_str(&row, "agreement",
                         fleet_status_agreement_name(s->machines[i].agreement));
        json_push_kv_int(&row, "depth", s->machines[i].depth);
        json_push_back(&list, &row);
        json_free(&row);
    }
    json_push_kv(out, "machines", &list);
    json_free(&list);
}

/* ── the running node ────────────────────────────────────────────────── */

size_t fleet_status_peers_snapshot(struct connman *cm,
                                   struct fleet_status_peer *peers,
                                   size_t cap)
{
    size_t n = 0;
    if (!cm || !peers)
        return 0;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes && n < cap; i++) {
        const struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->disconnect ||
            node->state < PEER_HANDSHAKE_COMPLETE)
            continue;
        (void)snprintf(peers[n].host, sizeof peers[n].host, "%s",
                       node->addr_name);
        peers[n].inbound = node->inbound;
        n++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return n;
}

static bool node_hash_at(int64_t height, char hex[65], void *ctx)
{
    (void)ctx;
    return rpc_blockchain_provable_hash_at(height, hex);
}

void fleet_status_node_local(struct fleet_status_local *local)
{
    memset(local, 0, sizeof *local);
    local->hash_at = node_hash_at;
    local->tip = rpc_blockchain_provable_tip_height();
}

bool fleet_status_build(struct node_db *ndb, struct connman *cm,
                        const struct fleet_status_local *local,
                        int64_t wall_now, int64_t mono_now,
                        struct fleet_status *out)
{
    struct fleet_status_peer *peers = zcl_calloc(
        FLEET_STATUS_PEERS_MAX, sizeof *peers, "fleet_status_peers");
    size_t n;
    if (!peers)
        return false;
    fleet_status_collect(ndb, wall_now, out);
    fleet_status_load_refusals(ndb, out);
    n = fleet_status_peers_snapshot(cm, peers, FLEET_STATUS_PEERS_MAX);
    fleet_status_apply(out, peers, n, local, mono_now);
    free(peers);
    return true;
}

bool fleet_status_current(struct fleet_status *out)
{
    struct fleet_status_local local;
    fleet_status_node_local(&local);
    return fleet_status_build(app_runtime_node_db(), rpc_net_get_connman(),
                              &local, clock_now_wall_ms() / 1000,
                              fleet_tip_now_secs(), out);
}

bool fleet_status_rpc(const struct json_value *params, bool help,
                      struct json_value *result)
{
    struct fleet_status *s;
    (void)params;
    RPC_HELP(help, result,
        "fleetstatus\n"
        "Fleet membership, roster machines connected over onion and whether "
        "their best block is this node's block at that height. Reads a cache "
        "and never waits on the network. Returns no wallet data.");
    s = zcl_calloc(1, sizeof *s, "fleet_status");
    if (!s || !fleet_status_current(s)) {
        free(s);
        json_set_str(result, "out of memory");
        return false;
    }
    fleet_status_render(s, result);
    free(s);
    return true;
}
