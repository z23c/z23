/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-node community content moderation for the marketplace.
 *
 * Three layers stay separate:
 *   1. Protocol validity — the signed offer wire. Never filtered here.
 *      Moderation NEVER reaches block or transaction acceptance: a
 *      consensus-affecting content rule is a chain-split mechanism and
 *      is forbidden. A node may refuse to SERVE; it always VALIDATES.
 *   2. Local hosting policy — the node still STORES every valid offer
 *      it ingested and moderation never deletes. What it will hand to
 *      another party is gated: see the two legs below.
 *   3. View filtering — this module: each node applies its OWN local
 *      listing-visibility policy to its own listing surfaces
 *      (zmarket_list / app market list / GET /api/market).
 *
 * TWO LEGS, TWO SEPARATE SETTINGS, TWO DIFFERENT DEFAULTS. They protect
 * different things and are deliberately not one switch:
 *
 *   SERVE — handing over the actual content bytes. The default profile
 *   general-audience.v1 requires the node's own reviewed_ok mark. This
 *   is the protection: a node hosts what its operator signed off on.
 *
 *   RELAY — forwarding a POINTER to somebody else's content (an offer
 *   announcement carrying a filename). The default is relay-all.v1:
 *   relay everything valid. Gating relay by default would collapse
 *   offer gossip to one hop from the seller on every node until a human
 *   acted, which breaks permissionless discovery for honest sellers and
 *   concentrates reach on whoever has operators awake. That is a
 *   centralization pressure, and it is refused. An operator who wants
 *   strict relay opts in to relay-reviewed-only.v1.
 *
 * ONE RULE COVERS BOTH LEGS AND BOTH FAILURE MODES:
 *
 *   Readable and unconfigured  -> that leg's documented DEFAULT
 *                                 (serve: reviewed_ok required;
 *                                  relay: allow all).
 *   Unreadable or unaskable    -> that leg's STRICT side
 *                                 (serve: hide; relay: refuse).
 *
 * The second half is why a corrupt, forged, world-readable, truncated,
 * or empty policy file can never silently re-open a gate an operator
 * deliberately closed: an ABSENT file means "never configured" and
 * yields the defaults, while a PRESENT-BUT-UNREADABLE file means the
 * operator wrote something we cannot read, so every leg takes its
 * strict side. The same reasoning covers an unwired injection port —
 * a node that cannot ask its own policy is not a node with no policy.
 *
 * There are no network-wide bans and no deletion authority anywhere:
 * the policy decides only what THIS node lists, serves, and relays, and
 * binds no other node. It persists per datadir at market/moderation.v1
 * (mode 0600, atomic rename). Profiles and relay rules are immutable
 * and named — operators pick one; they never edit one.
 *
 * review_state is local-only metadata on file_offers rows
 * (unreviewed / reviewed_ok / sensitive). It is set by the node's own
 * curation action (zmarket_review_set), never gossiped, and never part
 * of the signed wire. */

#ifndef ZCL_SERVICES_MARKET_MODERATION_SERVICE_H
#define ZCL_SERVICES_MARKET_MODERATION_SERVICE_H

#include "base/result.h"
#include "models/review_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MARKET_MODERATION_POLICY_FILE "market/moderation.v1"
#define MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1 "general-audience.v1"
#define MARKET_MODERATION_PROFILE_OPEN_VIEW "open-view"

enum market_moderation_profile {
    MARKET_MODERATION_PROFILE_DEFAULT = 0, /* general-audience.v1 */
    MARKET_MODERATION_PROFILE_OPEN = 1,
    MARKET_MODERATION_PROFILE_COUNT = 2
};

const char *market_moderation_profile_string(
    enum market_moderation_profile profile);
/* -1 when the name is not a known immutable profile. */
int market_moderation_profile_from_string(const char *name);

static inline bool market_moderation_profile_valid(int profile)
{
    return profile >= 0 && profile < MARKET_MODERATION_PROFILE_COUNT;
}


/* ── The RELAY leg: a separate setting with its own default ──────────
 * Never derived from the profile. An operator reading the node's
 * posture sees two independently-valued rules, and "strict relay" is a
 * value they can see, never the absence of one. */
#define MARKET_MODERATION_RELAY_ALL_V1 "relay-all.v1"
#define MARKET_MODERATION_RELAY_REVIEWED_ONLY_V1 "relay-reviewed-only.v1"

enum market_moderation_relay_rule {
    /* Boot default: forward every valid offer announcement. Keeps
     * permissionless discovery working for a seller whose node nobody
     * has reviewed yet. */
    MARKET_MODERATION_RELAY_ALL = 0,
    /* Explicit operator opt-in: rebroadcast only offers this node
     * itself marked reviewed_ok. Refusals stay counted. */
    MARKET_MODERATION_RELAY_REVIEWED_ONLY = 1,
    MARKET_MODERATION_RELAY_RULE_COUNT = 2
};

const char *market_moderation_relay_rule_string(
    enum market_moderation_relay_rule rule);
/* -1 when the name is not a known immutable relay rule. */
int market_moderation_relay_rule_from_string(const char *name);

static inline bool market_moderation_relay_rule_valid(int rule)
{
    return rule >= 0 && rule < MARKET_MODERATION_RELAY_RULE_COUNT;
}
/* Per-datadir policy persistence — both legs, one file, one read.
 *
 * ABSENT file  -> ok_out=true, profile=general-audience.v1,
 *                 relay=relay-all.v1. The documented first-boot state:
 *                 never configured, so each leg gets its DEFAULT.
 * PRESENT but unreadable/corrupt/world-readable/empty/oversize
 *              -> ok_out=false, profile=general-audience.v1 AND
 *                 relay=relay-reviewed-only.v1. The operator wrote
 *                 something we cannot read, so EVERY leg takes its
 *                 STRICT side. This is the only reason relay's strict
 *                 value ever appears without an explicit opt-in, and it
 *                 is what stops a corrupt file from re-opening a gate
 *                 the operator deliberately closed.
 *
 * relay_out may be NULL when a caller only wants the profile. Save
 * writes both rules 0600 via tmp+rename and fsyncs the directory. */
enum market_moderation_profile market_moderation_profile_load(
    const char *datadir, enum market_moderation_relay_rule *relay_out,
    bool *ok_out, char *error, size_t error_capacity);
struct zcl_result market_moderation_profile_save(
    const char *datadir, enum market_moderation_profile profile,
    enum market_moderation_relay_rule relay_rule);

struct node_db;

/* Node-process context: registered once at boot (rpc_market_set_state)
 * so the listing filter, the status surface, and the dumpstate dumper
 * share the live profile and the review-state store. */
void market_moderation_set_context(struct node_db *ndb,
                                   const char *datadir);
/* True when a bound, open review store is reachable. A pre-flight for
 * surfaces that want to say "the store is not open" instead of a
 * per-operation failure; the gates never need it, because they already
 * answer their leg's strict side when the store is absent. */
bool market_moderation_store_ready(void);
enum market_moderation_profile market_moderation_active_profile(void);
/* Set + persist the active profile. Rewrites the policy file with the
 * relay rule unchanged — setting one leg never moves the other. */
struct zcl_result market_moderation_set_active_profile(
    enum market_moderation_profile profile);
enum market_moderation_relay_rule market_moderation_active_relay_rule(void);
/* Set + persist the active relay rule, profile unchanged. */
struct zcl_result market_moderation_set_active_relay_rule(
    enum market_moderation_relay_rule rule);

/* Review-state store access through the context db. get answers
 * MARKET_REVIEW_UNREVIEWED when the db is absent or the offer row is
 * missing (an offer known only to the gossip cache is unreviewed). */
int market_moderation_review_state_for_root(const uint8_t root_hash[32]);
struct zcl_result market_moderation_review_counts(
    int64_t counts[MARKET_REVIEW_STATE_COUNT]);
/* The node's own curation action: mark one signed offer by offer_id.
 * Fails when the state is invalid or no signed offer carries that id. */
struct zcl_result market_moderation_set_review_state(
    const uint8_t offer_id[32], enum market_review_state state);
/* Plan/commit write: succeeds only when the persisted mark still equals
 * `expected`. Code MARKET_MODERATION_REVIEW_STALE means another writer won. */
#define MARKET_MODERATION_REVIEW_STALE (-5)
struct zcl_result market_moderation_compare_set_review_state(
    const uint8_t offer_id[32], enum market_review_state expected,
    enum market_review_state state);
/* Same answer as _for_root, addressed by the signed offer id a delivery
 * request carries. MARKET_REVIEW_UNREVIEWED when the db is absent, the
 * id matches no signed offer, or the mark is unreadable. */
int market_moderation_review_state_for_offer_id(const uint8_t offer_id[32]);

/* ── The serving gate (SERVE leg) ────────────────────────────────────
 * A node serves a moderated, general-audience view BY DEFAULT, and its
 * operator signs off on what it hands out. These two calls are the ONE
 * gate every content-serving surface asks. They answer through the same
 * immutable profile and the same view-service decide() the listing
 * surfaces already use — there is no second policy engine, no second
 * profile format, and no second store.
 *
 * FAIL CLOSED BY CONSTRUCTION. false ("do not serve") is the answer for
 * every one of: a NULL id, an unbound node context, a closed database,
 * an offer id no signed offer carries, an unreadable review mark, an
 * out-of-range active profile, a view service that refuses to decide,
 * and an unreviewed or sensitive mark under the default profile. There
 * is no input for which an error yields "serve".
 *
 * BOUNDARY. false means only "this node does not hand these bytes to
 * another party". It never deletes anything, it is a purely local
 * decision that binds no other node, and it is never consulted by block
 * or transaction validation — moderation must never touch consensus. */
bool market_moderation_may_serve_root(const uint8_t root_hash[32]);
bool market_moderation_may_serve_offer_id(const uint8_t offer_id[32]);

/* ── The relay gate (RELAY leg) ──────────────────────────────────────
 * May this node rebroadcast somebody else's offer announcement? A
 * SEPARATE question from may_serve with a SEPARATE setting and the
 * opposite default: under the boot default relay-all.v1 this answers
 * true for every well-formed id, because refusing to forward a pointer
 * would shrink an honest seller's reach to this node's own peers.
 *
 * Under the operator's explicit relay-reviewed-only.v1 opt-in it asks
 * exactly the same profile + decide() the serve leg asks, so a strict
 * relay is fail-closed in every class the serve leg is: an unbound
 * context, a closed db, an unknown root, and an unreadable mark all
 * answer false rather than forwarding.
 *
 * A NULL id answers false under BOTH rules — that is malformed input
 * being rejected, not a policy decision. */
bool market_moderation_may_relay_root(const uint8_t root_hash[32]);

struct json_value;
/* See AGENTS.md "Adding state introspection". Reentrant-safe. */
bool market_moderation_dump_state_json(struct json_value *out,
                                       const char *key);

#endif /* ZCL_SERVICES_MARKET_MODERATION_SERVICE_H */
