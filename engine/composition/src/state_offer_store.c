/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded, clockless record and choice of peer state offers.
 *
 * See config/state_offer_store.h for the contract. Everything here is a fixed
 * array and a comparison; there is no allocation, no IO and no clock, so the
 * decision a node's first boot depends on is one a test can drive exactly. */

#include "config/state_offer_store.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define SOS_SUBSYS "state_offer"

struct sos_bad {
    bool used;
    uint8_t digest[32];
    int64_t peer_id;
};

struct sos_peer_strike {
    bool used;
    int64_t peer_id;
    uint32_t strikes;
};

static struct state_offer_record g_offers[STATE_OFFER_STORE_MAX];
static bool g_offer_used[STATE_OFFER_STORE_MAX];
static bool g_offer_fetching[STATE_OFFER_STORE_MAX];
static struct sos_bad g_bad[STATE_OFFER_STORE_BAD_MAX];
static struct sos_peer_strike g_strikes[STATE_OFFER_STORE_BAD_MAX];

static bool g_wait_armed;
static int64_t g_wait_started_ms;
static uint32_t g_offers_seen;
static uint32_t g_offers_rejected;
static int32_t g_newest_height_seen;
static int32_t g_chosen_height;
static uint8_t g_chosen_digest[32];
static bool g_fallback_named;
static char g_fallback_reason[128];
static enum state_offer_decision g_last_decision = STATE_OFFER_DECIDE_WAIT;
static uint64_t g_fetch_bytes_done, g_fetch_bytes_total;
static uint32_t g_fetch_chunks_done, g_fetch_chunks_total;

const char *state_offer_store_result_string(enum state_offer_store_result r)
{
    switch (r) {
    case STATE_OFFER_STORE_KEPT: return "kept";
    case STATE_OFFER_STORE_KEPT_REPLACED: return "kept-replaced";
    case STATE_OFFER_STORE_DROPPED_INVALID: return "dropped-invalid";
    case STATE_OFFER_STORE_DROPPED_UNSIGNED: return "dropped-unsigned";
    case STATE_OFFER_STORE_DROPPED_KIND: return "dropped-kind";
    case STATE_OFFER_STORE_DROPPED_BAD: return "dropped-bad";
    case STATE_OFFER_STORE_DROPPED_ENDPOINT: return "dropped-endpoint";
    case STATE_OFFER_STORE_DROPPED_FULL: return "dropped-full";
    }
    return "unknown";
}

const char *state_offer_decision_string(enum state_offer_decision d)
{
    switch (d) {
    case STATE_OFFER_DECIDE_WAIT: return "wait";
    case STATE_OFFER_DECIDE_FETCH: return "fetch";
    case STATE_OFFER_DECIDE_FALL_BACK: return "fall-back";
    }
    return "unknown";
}

void state_offer_store_reset(void)
{
    memset(g_offers, 0, sizeof(g_offers));
    memset(g_offer_used, 0, sizeof(g_offer_used));
    memset(g_offer_fetching, 0, sizeof(g_offer_fetching));
    memset(g_bad, 0, sizeof(g_bad));
    memset(g_strikes, 0, sizeof(g_strikes));
    g_wait_armed = false;
    g_wait_started_ms = 0;
    g_offers_seen = 0;
    g_offers_rejected = 0;
    g_newest_height_seen = 0;
    g_chosen_height = 0;
    memset(g_chosen_digest, 0, sizeof(g_chosen_digest));
    g_fallback_named = false;
    g_fallback_reason[0] = '\0';
    g_last_decision = STATE_OFFER_DECIDE_WAIT;
    g_fetch_bytes_done = g_fetch_bytes_total = 0;
    g_fetch_chunks_done = g_fetch_chunks_total = 0;
}

void state_offer_store_note_first_peer(int64_t now_ms)
{
    if (g_wait_armed)
        return; /* the window measures from the FIRST peer, not the last */
    g_wait_armed = true;
    g_wait_started_ms = now_ms;
    LOG_INFO(SOS_SUBSYS,
             "first peer connected — waiting up to %llds for a state offer "
             "while headers keep flowing; a peer that offers nothing costs "
             "this node nothing but the wait",
             (long long)(STATE_OFFER_WAIT_MS / 1000));
}

bool state_offer_store_wait_armed(void)
{
    return g_wait_armed;
}

static bool digest_eq(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

bool state_offer_store_digest_is_bad(const uint8_t content_digest[32])
{
    if (!content_digest)
        return false;
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (g_bad[i].used && digest_eq(g_bad[i].digest, content_digest))
            return true;
    return false;
}

uint32_t state_offer_store_peer_strikes(int64_t peer_id)
{
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (g_strikes[i].used && g_strikes[i].peer_id == peer_id)
            return g_strikes[i].strikes;
    return 0;
}

static void strike_peer(int64_t peer_id)
{
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (g_strikes[i].used && g_strikes[i].peer_id == peer_id) {
            g_strikes[i].strikes++;
            return;
        }
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (!g_strikes[i].used) {
            g_strikes[i].used = true;
            g_strikes[i].peer_id = peer_id;
            g_strikes[i].strikes = 1;
            return;
        }
    /* Table full: the strike is still real, it just cannot be attributed to a
     * seventeenth distinct peer in one run. Say so rather than silently
     * dropping it, and never evict an existing strike to make room — that
     * would let a flood of fresh identities launder an earlier one. */
    LOG_WARN(SOS_SUBSYS,
             "peer strike table full (%u peers) — strike for peer %lld "
             "recorded in the reject count but not attributed",
             (unsigned)STATE_OFFER_STORE_BAD_MAX, (long long)peer_id);
}

/* An offer with no dialable endpoint is not actionable, whatever else it says.
 * An onion peer's connection address is all-zero here (its identity lives in a
 * field this path does not carry) and the RMF transport dials by name with no
 * SOCKS route, so such an offer is dropped rather than kept as a promise that
 * cannot be cashed. That is a phase-1a limit of the file-service dial, not of
 * the offer — phase 1b's peer-link stream removes it. */
static bool endpoint_dialable(const uint8_t peer_ip[16], uint16_t port)
{
    if (port == 0)
        return false;
    for (size_t i = 0; i < 16; i++)
        if (peer_ip[i] != 0)
            return true;
    return false;
}

static size_t find_by_digest(const uint8_t digest[32])
{
    for (size_t i = 0; i < STATE_OFFER_STORE_MAX; i++)
        if (g_offer_used[i] && digest_eq(g_offers[i].offer.content_digest,
                                         digest))
            return i;
    return STATE_OFFER_STORE_MAX;
}

/* The weakest slot to evict: the LOWEST bundle height, breaking ties toward the
 * oldest. A newcomer takes it only if it is strictly better, so a peer cannot
 * evict a good offer by repeating a worse one. */
static size_t weakest_slot(void)
{
    size_t worst = STATE_OFFER_STORE_MAX;
    for (size_t i = 0; i < STATE_OFFER_STORE_MAX; i++) {
        if (!g_offer_used[i])
            return i;
        if (worst == STATE_OFFER_STORE_MAX)
            worst = i;
        else if (g_offers[i].offer.bundle_height <
                     g_offers[worst].offer.bundle_height ||
                 (g_offers[i].offer.bundle_height ==
                      g_offers[worst].offer.bundle_height &&
                  g_offers[i].heard_ms < g_offers[worst].heard_ms))
            worst = i;
    }
    return worst;
}

enum state_offer_store_result state_offer_store_record(
    const struct state_offer_v1 *offer, const uint8_t peer_ip[16],
    uint16_t file_service_port, int64_t peer_id, int64_t now_ms)
{
    if (!offer || !peer_ip)
        return STATE_OFFER_STORE_DROPPED_INVALID;
    /* Re-checked here even though the net layer already checked: this module is
     * reachable from a test and from a future caller, and a store that trusted
     * its caller to have validated would be one refactor away from holding a
     * row nobody checked. */
    if (state_offer_v1_validate(offer) != STATE_OFFER_OK)
        return STATE_OFFER_STORE_DROPPED_INVALID;
    if (state_offer_v1_verify(offer) != STATE_OFFER_OK)
        return STATE_OFFER_STORE_DROPPED_UNSIGNED;

    g_offers_seen++;
    if (offer->bundle_height > g_newest_height_seen)
        g_newest_height_seen = offer->bundle_height;

    /* Phase 1a installs a consensus state bundle. A header seed is a real and
     * useful artifact, but it is not a state source, so it is counted (it still
     * teaches us the newest height a peer has) and not retained for choice. */
    if (offer->kind != (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE)
        return STATE_OFFER_STORE_DROPPED_KIND;
    if (state_offer_store_digest_is_bad(offer->content_digest))
        return STATE_OFFER_STORE_DROPPED_BAD;
    if (!endpoint_dialable(peer_ip, file_service_port))
        return STATE_OFFER_STORE_DROPPED_ENDPOINT;

    size_t existing = find_by_digest(offer->content_digest);
    if (existing < STATE_OFFER_STORE_MAX) {
        /* The same bundle from a second peer (or the same peer again) refreshes
         * the endpoint rather than consuming a second slot: ZRC-0011 dedups on
         * content, and one bundle held by several peers is one bundle. */
        memcpy(g_offers[existing].peer_ip, peer_ip, 16);
        g_offers[existing].file_service_port = file_service_port;
        g_offers[existing].peer_id = peer_id;
        return STATE_OFFER_STORE_KEPT_REPLACED;
    }

    size_t slot = weakest_slot();
    if (slot >= STATE_OFFER_STORE_MAX)
        return STATE_OFFER_STORE_DROPPED_FULL;
    if (g_offer_used[slot] &&
        offer->bundle_height <= g_offers[slot].offer.bundle_height)
        return STATE_OFFER_STORE_DROPPED_FULL;

    memset(&g_offers[slot], 0, sizeof(g_offers[slot]));
    g_offers[slot].offer = *offer;
    memcpy(g_offers[slot].peer_ip, peer_ip, 16);
    g_offers[slot].file_service_port = file_service_port;
    g_offers[slot].peer_id = peer_id;
    g_offers[slot].heard_ms = now_ms;
    g_offer_used[slot] = true;
    g_offer_fetching[slot] = false;
    return STATE_OFFER_STORE_KEPT;
}

void state_offer_store_note_bad(const uint8_t content_digest[32],
                                int64_t peer_id)
{
    if (!content_digest)
        return;
    g_offers_rejected++;
    strike_peer(peer_id);

    size_t slot = find_by_digest(content_digest);
    if (slot < STATE_OFFER_STORE_MAX) {
        g_offer_used[slot] = false;
        g_offer_fetching[slot] = false;
        memset(&g_offers[slot], 0, sizeof(g_offers[slot]));
    }
    if (digest_eq(g_chosen_digest, content_digest)) {
        g_chosen_height = 0;
        memset(g_chosen_digest, 0, sizeof(g_chosen_digest));
    }
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (g_bad[i].used && digest_eq(g_bad[i].digest, content_digest))
            return;
    for (size_t i = 0; i < STATE_OFFER_STORE_BAD_MAX; i++)
        if (!g_bad[i].used) {
            g_bad[i].used = true;
            memcpy(g_bad[i].digest, content_digest, 32);
            g_bad[i].peer_id = peer_id;
            LOG_WARN(SOS_SUBSYS,
                     "offered bundle failed verification — digest refused for "
                     "the rest of this run, peer %lld struck, no address ban "
                     "(one shared loopback source fronts every onion peer); "
                     "trying the next offer",
                     (long long)peer_id);
            return;
        }
    /* Full: the newest refusal replaces the oldest. Forgetting a digest costs
     * at most one repeated bounded fetch that fails the same way. */
    memcpy(g_bad[0].digest, content_digest, 32);
    g_bad[0].peer_id = peer_id;
}

void state_offer_store_note_fetching(const uint8_t content_digest[32])
{
    if (!content_digest)
        return;
    size_t slot = find_by_digest(content_digest);
    if (slot < STATE_OFFER_STORE_MAX)
        g_offer_fetching[slot] = true;
}

int32_t state_offer_store_newest_height_seen(void)
{
    return g_newest_height_seen;
}

enum state_offer_decision state_offer_store_decide(
    int64_t now_ms, struct state_offer_record *out)
{
    /* Newest first. Every retained offer already cleared the freshness rule
     * against its OWN offerer's tip at parse time, so "newest" here is a
     * preference among acceptable offers, never a way past the rule. */
    size_t best = STATE_OFFER_STORE_MAX;
    for (size_t i = 0; i < STATE_OFFER_STORE_MAX; i++) {
        if (!g_offer_used[i] || g_offer_fetching[i])
            continue;
        if (best == STATE_OFFER_STORE_MAX ||
            g_offers[i].offer.bundle_height >
                g_offers[best].offer.bundle_height ||
            (g_offers[i].offer.bundle_height ==
                 g_offers[best].offer.bundle_height &&
             g_offers[i].heard_ms < g_offers[best].heard_ms))
            best = i;
    }
    if (best < STATE_OFFER_STORE_MAX) {
        if (out)
            *out = g_offers[best];
        g_chosen_height = g_offers[best].offer.bundle_height;
        memcpy(g_chosen_digest, g_offers[best].offer.content_digest, 32);
        g_last_decision = STATE_OFFER_DECIDE_FETCH;
        return STATE_OFFER_DECIDE_FETCH;
    }

    /* Nothing acceptable. The window only runs once a peer exists to answer. */
    if (!g_wait_armed) {
        g_last_decision = STATE_OFFER_DECIDE_WAIT;
        return STATE_OFFER_DECIDE_WAIT;
    }
    if (now_ms - g_wait_started_ms < STATE_OFFER_WAIT_MS) {
        g_last_decision = STATE_OFFER_DECIDE_WAIT;
        return STATE_OFFER_DECIDE_WAIT;
    }

    if (!g_fallback_named) {
        g_fallback_named = true;
        if (g_newest_height_seen > 0)
            snprintf(g_fallback_reason, sizeof(g_fallback_reason),
                     "no acceptable offer within %llds of the first peer; the "
                     "newest height any peer offered was %ld",
                     (long long)(STATE_OFFER_WAIT_MS / 1000),
                     (long)g_newest_height_seen);
        else
            snprintf(g_fallback_reason, sizeof(g_fallback_reason),
                     "no peer offered any state within %llds of the first peer",
                     (long long)(STATE_OFFER_WAIT_MS / 1000));
        LOG_WARN(SOS_SUBSYS, "%s — folding forward from local state",
                 g_fallback_reason);
    }
    g_last_decision = STATE_OFFER_DECIDE_FALL_BACK;
    return STATE_OFFER_DECIDE_FALL_BACK;
}

void state_offer_store_note_fetch_progress(uint32_t chunks_done,
                                           uint32_t chunks_total,
                                           uint64_t bytes_done,
                                           uint64_t bytes_total)
{
    g_fetch_chunks_done = chunks_done;
    g_fetch_chunks_total = chunks_total;
    g_fetch_bytes_done = bytes_done;
    g_fetch_bytes_total = bytes_total;
}

void state_offer_store_status_get(struct state_offer_store_status *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->wait_armed = g_wait_armed;
    out->wait_started_ms = g_wait_started_ms;
    out->offers_seen = g_offers_seen;
    out->offers_rejected = g_offers_rejected;
    out->newest_height_seen = g_newest_height_seen;
    out->chosen_height = g_chosen_height;
    memcpy(out->chosen_digest, g_chosen_digest, 32);
    out->fetch_bytes_done = g_fetch_bytes_done;
    out->fetch_bytes_total = g_fetch_bytes_total;
    out->fetch_chunks_done = g_fetch_chunks_done;
    out->fetch_chunks_total = g_fetch_chunks_total;
    out->last_decision = g_last_decision;
    snprintf(out->fallback_reason, sizeof(out->fallback_reason), "%s",
             g_fallback_reason);

    int64_t seen_peers[STATE_OFFER_STORE_MAX];
    uint32_t npeers = 0;
    for (size_t i = 0; i < STATE_OFFER_STORE_MAX; i++) {
        if (!g_offer_used[i])
            continue;
        out->offers_retained++;
        bool dup = false;
        for (uint32_t j = 0; j < npeers; j++)
            if (seen_peers[j] == g_offers[i].peer_id) { dup = true; break; }
        if (!dup)
            seen_peers[npeers++] = g_offers[i].peer_id;
    }
    out->peers_offering = npeers;
}
