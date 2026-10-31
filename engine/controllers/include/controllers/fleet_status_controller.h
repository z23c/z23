/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: core.wallet.fleet.status. Whether this node is a fleet member, how
 *          many other roster machines exist, how many are connected over
 *          onion, and whether each connected machine's best block is the
 *          block this node holds at that height. It reads no wallet and
 *          returns none.
 *
 * A machine is "connected" when this node holds an OUTBOUND, handshaken
 * connection whose host is the .onion the machine's verified roster line
 * names. A v3 onion host is its own key, so reaching it proves the peer holds
 * the key the operator sealed into the line; a clearnet address, or an
 * inbound stream (which Tor delivers from loopback and so names nobody),
 * never counts. A box admitted twice counts once, under its newest line, so
 * an onion the operator retired names nobody.
 *
 * Agreement compares block hashes, never heights alone. The best block of a
 * machine comes from fleet_tip.h, a cache refreshed in the background; this
 * file never touches the network. A version message's starting_height is
 * written once at connect and is never used.
 *
 * A machine above this node's tip is asked for its block at this node's tip
 * height; naming another block there is a disagreement, naming this node's
 * block is only the phone being behind. A send refusal, once raised by a
 * check, outlives that check's age, the machine's connection and a restart of
 * the node: it is kept in node_state and counts for every roster machine,
 * connected or not, until a later check from that machine lands on this
 * node's chain at a height at or above the refused one. Failing to learn is
 * never agreement. */

#ifndef ZCL_CONTROLLERS_FLEET_STATUS_CONTROLLER_H
#define ZCL_CONTROLLERS_FLEET_STATUS_CONTROLLER_H

#include "config/boot_fleet_roster.h"
#include "controllers/fleet_tip.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct node_db;
struct connman;

/* How one connected machine's best block relates to this node's chain.
 *   agrees          its hash is this node's block at its height, which is
 *                   this node's tip.
 *   phone_behind    its height is above this node's tip and it names this
 *                   node's block at this node's tip height. Not a
 *                   disagreement: the ordinary sync path catches up. Above
 *                   the tip with no answer for that height is unknown, and
 *                   naming another block there is disagree.
 *   machine_behind  its hash is this node's block at a lower height, at most
 *                   FLEET_STATUS_AGREE_DEPTH blocks down. Not a disagreement.
 *   disagree        its height is at or below this node's tip and its hash
 *                   is not this node's block there. The chain lookup is exact
 *                   at any depth, so a recent reorg race and a machine stuck
 *                   on an old fork both report this; refuses_send narrows it.
 *   unknown         not connected, or no check within
 *                   FLEET_TIP_MAX_AGE_SECS and no standing refusal, or a machine
 *                   behind by more than FLEET_STATUS_AGREE_DEPTH (the
 *                   row's depth says by how much). Never agreement. */
#define FLEET_STATUS_AGREE_DEPTH 6
enum fleet_status_agreement {
    FLEET_STATUS_UNKNOWN = 0,
    FLEET_STATUS_AGREES,
    FLEET_STATUS_PHONE_BEHIND,
    FLEET_STATUS_MACHINE_BEHIND,
    FLEET_STATUS_MACHINE_DISAGREES,
};

/* not_member: no fleet root. none_connected: no roster machine connected.
 * unchecked: some are connected and none has a fresh check that settles it.
 * agree: at least one fresh check agrees or is behind on this chain within
 * FLEET_STATUS_AGREE_DEPTH blocks of the tip, and none disagrees.
 * disagree: some connected machine disagrees. */
enum fleet_status_verdict {
    FLEET_STATUS_NOT_MEMBER = 0,
    FLEET_STATUS_NONE_CONNECTED,
    FLEET_STATUS_UNCHECKED,
    FLEET_STATUS_AGREE,
    FLEET_STATUS_DISAGREE,
};

/* One connection as the status needs it. `host` is addr_name as the node
 * holds it, "<host>" or "<host>:<port>". */
struct fleet_status_peer {
    char host[256];
    bool inbound;
};

struct fleet_status_machine {
    char name[32];
    char onion[BOOT_FLEET_ROSTER_ONION_MAX];
    uint8_t box[32];
    int64_t enrolled_at;
    int64_t tip_height; /* height of the check behind `agreement`, or 0 */
    int64_t depth;      /* blocks the fresh check is below this node's tip, else 0 */
    bool connected;
    bool refusing;      /* holds a send back; see refuses_send */
    enum fleet_status_agreement agreement;
};

struct fleet_status {
    bool member;
    size_t machine_count;   /* other machines on the verified roster */
    size_t connected_count; /* of those, connected over onion */
    int64_t local_tip;      /* this node's provable tip height, <= 0 unknown */
    bool refuses_send;      /* a roster machine at or above the tip named
                               another block there and no later check has
                               landed on this chain */
    enum fleet_status_verdict verdict;
    struct fleet_status_machine machines[BOOT_FLEET_ROSTER_MAX];
};

/* This node's chain as the comparison needs it: its tip, and the hash of its
 * block at a height (false when it holds none). */
struct fleet_status_local {
    int64_t tip;
    bool (*hash_at)(int64_t height, char hex[65], void *ctx);
    void *ctx;
};

/* Settle the standing send refusal of the machine `key` after a successful
 * check. A disagreement at or above `local`'s tip raises it at `local`'s tip
 * height; a check that agrees, is behind on this chain or names this node's
 * block clears it only when the height it speaks for reaches the refused
 * height; any other check changes nothing. The refusal is written to `ndb`
 * (NULL: memory only). */
void fleet_status_note_check(struct node_db *ndb, const char *key,
                             const struct fleet_tip *t,
                             const struct fleet_status_local *local);

/* Reload the refusals stored in `ndb` for the machines of `s` into the
 * cache; a stored refusal is only ever added, never cleared. */
void fleet_status_load_refusals(struct node_db *ndb,
                                const struct fleet_status *s);

/* `local` over the running node's chain. */
void fleet_status_node_local(struct fleet_status_local *local);

/* Fill `out` with membership and the verified, unrevoked, other machines of
 * this box's roster, one per box key (the newest enrolment wins). Nothing is
 * connected yet. */
void fleet_status_collect(struct node_db *ndb, int64_t now,
                          struct fleet_status *out);

/* Match `peers` against the collected machines and set connected, agreement,
 * refuses_send, the counts and the verdict from the cached checks at the
 * time `now` on the fleet_tip_now_secs() clock. */
void fleet_status_apply(struct fleet_status *s,
                        const struct fleet_status_peer *peers, size_t n,
                        const struct fleet_status_local *local, int64_t now);

/* The connections of `cm` that completed their handshake and are not being
 * disconnected, the same filter connman_handshaked_peer_count uses. Returns
 * how many were written, at most `cap`. */
size_t fleet_status_peers_snapshot(struct connman *cm,
                                   struct fleet_status_peer *peers,
                                   size_t cap);

/* Collect from `ndb`, snapshot the connections of `cm` and apply, at the wall
 * time `wall_now` (roster) and `mono_now` on the fleet_tip_now_secs() clock
 * (cache ages).
 * False when memory is short. */
bool fleet_status_build(struct node_db *ndb, struct connman *cm,
                        const struct fleet_status_local *local,
                        int64_t wall_now, int64_t mono_now,
                        struct fleet_status *out);

/* fleet_status_build() over the running node. */
bool fleet_status_current(struct fleet_status *out);

/* Is a connection with this address and direction a roster machine reached
 * over onion in `s`? The one question the private relay asks. */
bool fleet_status_peer_on_roster(const struct fleet_status *s,
                                 const char *addr_name, bool inbound);

/* The lowercase "<host>.onion" of "<host>[:port]" into `out`; false when it
 * is not an onion address. This is the cache key of a machine. */
bool fleet_status_onion_key(const char *addr, char *out, size_t cap);

const char *fleet_status_verdict_name(enum fleet_status_verdict v);
const char *fleet_status_agreement_name(enum fleet_status_agreement a);

/* Render `s` as the zcl.fleet_status.v1 object. */
void fleet_status_render(const struct fleet_status *s,
                         struct json_value *out);

/* Backing RPC for the typed core.wallet.fleet.status contract. */
bool fleet_status_rpc(const struct json_value *params, bool help,
                      struct json_value *result);

#endif /* ZCL_CONTROLLERS_FLEET_STATUS_CONTROLLER_H */
