/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed peer-offence scoring layered on top of peer_misbehaving().
 * See core/modules/net/include/net/peer_scoring.h for design notes. */

#include "platform/time_compat.h"
#include "net/peer_scoring.h"
#include "net/net.h"
#include "event/event.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PEER_SCORING_DEFAULT_THRESHOLD 100
#define PEER_SCORING_DEFAULT_BAN_HOURS 24
#define PEER_SCORING_DEFAULT_DECAY     1   /* points per minute */
#define PEER_SCORING_DEFAULT_MAX_INBOUND_PER_IP 3
#define PEER_SCORING_DEFAULT_LAST_PEER_BAN_SECS 600
#define PEER_SCORING_DEFAULT_LOOPBACK_INBOUND_MAX 24

static _Atomic int g_ban_threshold   = PEER_SCORING_DEFAULT_THRESHOLD;
static _Atomic int g_ban_hours       = PEER_SCORING_DEFAULT_BAN_HOURS;
static _Atomic int g_decay_per_min   = PEER_SCORING_DEFAULT_DECAY;
static _Atomic int g_max_inbound_per_ip =
    PEER_SCORING_DEFAULT_MAX_INBOUND_PER_IP;
static _Atomic int g_last_peer_ban_secs =
    PEER_SCORING_DEFAULT_LAST_PEER_BAN_SECS;

static int read_env_int(const char *name, int fallback, int min, int max)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v || parsed < (long)min || parsed > (long)max)
        return fallback;
    return (int)parsed;
}

void peer_scoring_init(void)
{
    /* Threshold range [1, 1_000_000] — an operator who sets 0 would get
     * instant-ban behaviour which is almost certainly a mistake, so we
     * fall back to the default instead of honouring it. */
    int threshold = read_env_int("ZCL_PEER_BAN_THRESHOLD",
                                 PEER_SCORING_DEFAULT_THRESHOLD,
                                 1, 1000000);
    int hours = read_env_int("ZCL_PEER_BAN_HOURS",
                             PEER_SCORING_DEFAULT_BAN_HOURS,
                             1, 24 * 365);
    /* Decay can legitimately be 0 (operator wants sticky scores). */
    int decay = read_env_int("ZCL_PEER_SCORE_DECAY_PER_MIN",
                             PEER_SCORING_DEFAULT_DECAY,
                             0, 10000);

    /* Per-IP inbound admission cap. Was a bare `3` literal in
     * accept_connection() with no override, which makes a legitimately
     * multi-node source (one host running several nodes, or any NAT'd
     * network) undiagnosably unreachable past the third socket: the server
     * closes at accept() with zero bytes exchanged, so the client only ever
     * sees "remote-close, state=connecting". Range [1, 4096] — 0 would
     * refuse every inbound peer, which is what -listen=0 is for. */
    int max_inbound_per_ip = read_env_int("ZCL_PEER_MAX_INBOUND_PER_IP",
                                          PEER_SCORING_DEFAULT_MAX_INBOUND_PER_IP,
                                          1, 4096);
    /* Bounded ban applied instead of the full ban_hours when the ban would
     * leave the node with no connected peer at all — see peer_misbehaving()
     * in net.c. Range [60, 24h]: shorter than a minute is not a ban, and the
     * ceiling is the normal default so this knob can never make the
     * last-peer case HARSHER than the ordinary case. */
    int last_peer_ban_secs = read_env_int("ZCL_PEER_LAST_PEER_BAN_SECS",
                                          PEER_SCORING_DEFAULT_LAST_PEER_BAN_SECS,
                                          60, 24 * 60 * 60);

    atomic_store(&g_ban_threshold, threshold);
    atomic_store(&g_ban_hours, hours);
    atomic_store(&g_decay_per_min, decay);
    atomic_store(&g_max_inbound_per_ip, max_inbound_per_ip);
    atomic_store(&g_last_peer_ban_secs, last_peer_ban_secs);
}

int peer_scoring_ban_threshold(void)
{
    return atomic_load(&g_ban_threshold);
}

int peer_scoring_ban_hours(void)
{
    return atomic_load(&g_ban_hours);
}

int peer_scoring_decay_rate(void)
{
    return atomic_load(&g_decay_per_min);
}

int peer_scoring_max_inbound_per_ip(void)
{
    return atomic_load(&g_max_inbound_per_ip);
}

/* See net/peer_scoring.h. Read straight from the environment rather than
 * from a cached atomic: this is consulted once per accept(), it is not on
 * any hot path, and reading it here keeps the hard floor and the operator
 * knob in one place where a test can exercise both without booting a node.
 */
int peer_scoring_max_inbound_loopback(int max_inbound)
{
    if (max_inbound <= 0)
        return 0;

    int configured = read_env_int("ZCL_NET_LOOPBACK_INBOUND_MAX",
                                  PEER_SCORING_DEFAULT_LOOPBACK_INBOUND_MAX,
                                  0, 4096);

    /* Hard floor: three quarters of inbound capacity is permanently
     * reserved for non-loopback peers, whatever the operator asks for.
     * This is what stops a local flood from owning every slot in the
     * post-restart race. */
    int ceiling = max_inbound - (3 * max_inbound) / 4;
    if (ceiling < 0)
        ceiling = 0;
    return configured < ceiling ? configured : ceiling;
}

int peer_scoring_last_peer_ban_secs(void)
{
    return atomic_load(&g_last_peer_ban_secs);
}

int64_t peer_scoring_now_ms(void)
{
    struct timespec ts;
    if (platform_time_realtime_timespec(&ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

/* DoS-policy surface: one row per offence carries both the weight and the
 * display name, indexed by the enum value itself. Single source of truth —
 * previously peer_offence_weight() and peer_offence_name() each carried
 * their own parallel switch over the same case list; changing a weight or a
 * name now only touches one line instead of two. */
struct peer_offence_info {
    int weight;
    const char *name;
};

static const struct peer_offence_info g_peer_offence_info[PEER_OFFENCE_COUNT_] = {
    [PEER_OFFENCE_NONE]               = { 0,   "none" },
    [PEER_OFFENCE_TIMEOUT]            = { 5,   "timeout" },
    [PEER_OFFENCE_INVALID_MESSAGE]    = { 10,  "invalid_message" },
    [PEER_OFFENCE_UNREQUESTED]        = { 10,  "unrequested" },
    [PEER_OFFENCE_OFFER_REJECTED]     = { 10,  "offer_rejected" },
    [PEER_OFFENCE_FLOOD]              = { 20,  "flood" },
    [PEER_OFFENCE_INVALID_PAYLOAD]    = { 20,  "invalid_payload" },
    [PEER_OFFENCE_INVALID_HEADER]     = { 50,  "invalid_header" },
    [PEER_OFFENCE_INVALID_CHUNK]      = { 50,  "invalid_chunk" },
    [PEER_OFFENCE_INVALID_BLOCK]      = { 100, "invalid_block" },
    [PEER_OFFENCE_INVALID_PROOF]      = { 100, "invalid_proof" },
    [PEER_OFFENCE_PROTOCOL_VIOLATION] = { 100, "protocol_violation" },
};

int peer_offence_weight(enum peer_offence offence)
{
    if (offence < 0 || offence >= PEER_OFFENCE_COUNT_)
        return 0;
    return g_peer_offence_info[offence].weight;
}

const char *peer_offence_name(enum peer_offence offence)
{
    if (offence < 0 || offence >= PEER_OFFENCE_COUNT_)
        return "unknown";
    return g_peer_offence_info[offence].name;
}

void peer_scoring_record(struct net_manager *nm, struct p2p_node *node,
                         enum peer_offence offence, const char *context)
{
    if (!node || offence == PEER_OFFENCE_NONE)
        return;

    char reason[192];
    const char *name = peer_offence_name(offence);
    if (context && *context) {
        snprintf(reason, sizeof(reason), "%s: %s", name, context);
    } else {
        snprintf(reason, sizeof(reason), "%s", name);
    }

    /* peer_misbehaving() handles the is_trusted_peer() guard, the score
     * accumulation, the EV_PEER_MISBEHAVE event, the auto-ban at the
     * configured threshold (see peer_misbehaving() in net.c which now
     * reads peer_scoring_ban_threshold()), the EV_PEER_BANNED event, and
     * the disconnect flag. All we add here is the typed name prefix. */
    peer_misbehaving(nm, node, peer_offence_weight(offence), reason);
}

bool peer_scoring_should_ban(const struct p2p_node *node)
{
    if (!node) return false;
    /* Cast away const for atomic_load — p2p_node's misbehavior field is
     * _Atomic int, and the atomic load does not mutate observable state. */
    int score = atomic_load((_Atomic int *)&((struct p2p_node *)node)->misbehavior);
    return score >= peer_scoring_ban_threshold();
}

int peer_scoring_decay(struct p2p_node *node, int64_t now_ms)
{
    if (!node) return 0;

    int decay_per_min = peer_scoring_decay_rate();
    int score = atomic_load(&node->misbehavior);

    /* Score of 0 can't decay further. */
    if (score <= 0) {
        atomic_store(&node->peer_score_last_good_ms, (int_least64_t)now_ms);
        return 0;
    }

    /* Decay disabled — leave the score alone but keep tracking the
     * good-interaction timestamp so a later re-enable works correctly. */
    if (decay_per_min <= 0) {
        atomic_store(&node->peer_score_last_good_ms, (int_least64_t)now_ms);
        return score;
    }

    int_least64_t last_good = atomic_load(&node->peer_score_last_good_ms);
    if (last_good == 0) {
        /* First decay call — anchor the timer instead of awarding decay
         * back to the UNIX epoch. */
        atomic_store(&node->peer_score_last_good_ms, (int_least64_t)now_ms);
        return score;
    }

    int64_t delta_ms = now_ms - (int64_t)last_good;
    if (delta_ms <= 0) {
        /* Clock skew or same-millisecond call — no decay but still update
         * the anchor to the latest observation. */
        atomic_store(&node->peer_score_last_good_ms, (int_least64_t)now_ms);
        return score;
    }

    int minutes = (int)(delta_ms / 60000);
    if (minutes <= 0)
        return score; /* sub-minute — don't advance last_good so fractions accumulate */

    int decay = minutes * decay_per_min;
    int new_score = score - decay;
    if (new_score < 0) new_score = 0;
    atomic_store(&node->misbehavior, new_score);
    atomic_store(&node->peer_score_last_good_ms, (int_least64_t)now_ms);
    return new_score;
}

void peer_scoring_on_good_interaction(struct p2p_node *node, int64_t now_ms)
{
    if (!node) return;
    (void)peer_scoring_decay(node, now_ms);
}

void peer_scoring_reset(struct p2p_node *node)
{
    if (!node) return;
    atomic_store(&node->misbehavior, 0);
    atomic_store(&node->peer_score_last_good_ms,
                 (int_least64_t)peer_scoring_now_ms());
}
