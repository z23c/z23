/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The node's own moderation posture, as RPC.
 *
 * Split out of file_market_controller.c because this is a policy surface,
 * not a marketplace one: the rest of that controller lists offers, sells
 * files, and moves money, while everything here reads or writes the two
 * rules in <datadir>/market/moderation.v1 and the local review marks that
 * feed them. They share a node_db and nothing else.
 *
 * TWO LEGS, TWO COMMANDS. serve (the profile) decides what this node hands
 * out and defaults to reviewed_ok only; relay decides whether it forwards
 * other people's offer announcements and defaults to forwarding all of
 * them. They are set by separate commands whose plan tokens are
 * domain-separated, so neither can move the other by accident. The
 * reasoning for the split defaults lives in
 * app/services/include/services/market_moderation_service.h.
 *
 * Nothing here deletes, bans, binds another node, or reaches block or
 * transaction acceptance. */

#include "controllers/file_market_controller.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "net/file_market.h"
#include "rpc/server.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

static bool rpc_zmarket_moderation_status(const struct json_value *params,
                                          bool help,
                                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_moderation_status\n"
            "\nThe node's own marketplace listing-visibility posture: active\n"
            "profile, available immutable profiles, and local review_state\n"
            "counts, and the TWO independently-valued rules:\n"
            "  serve_rule  what this node hands out. Default\n"
            "              general-audience.v1: reviewed_ok only.\n"
            "  relay_rule  whether it forwards other people's offer\n"
            "              announcements. Default relay-all.v1: yes.\n"
            "They are separate settings with separate defaults and are set\n"
            "by separate commands; neither moves the other. Never a\n"
            "deletion and never a ban — a hidden offer stays stored, keeps\n"
            "its signed wire, and stays reachable from any node that does\n"
            "host it — and neither rule affects block or transaction\n"
            "acceptance.\n");
        return true;
    }
    (void)params;

    enum market_moderation_profile active =
        market_moderation_active_profile();
    enum market_moderation_relay_rule active_relay =
        market_moderation_active_relay_rule();
    json_set_object(result);
    json_push_kv_str(result, "active_profile",
                     market_moderation_profile_string(active));
    /* The two legs, named side by side and separately valued, so an
     * operator never has to infer a strict relay from the absence of a
     * key or from what the serve rule happens to be. */
    json_push_kv_str(result, "serve_rule",
                     market_moderation_profile_string(active));
    json_push_kv_str(result, "relay_rule",
                     market_moderation_relay_rule_string(active_relay));
    json_push_kv_bool(result, "relay_gated",
                      active_relay ==
                          MARKET_MODERATION_RELAY_REVIEWED_ONLY);
    struct json_value profiles;
    json_init(&profiles);
    json_set_array(&profiles);
    for (int i = 0; i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        struct json_value p;
        json_init(&p);
        json_set_str(&p, market_moderation_profile_string(
                             (enum market_moderation_profile)i));
        json_push_back(&profiles, &p);
        json_free(&p);
    }
    json_push_kv(result, "available_profiles", &profiles);
    json_free(&profiles);
    json_init(&profiles);
    json_set_array(&profiles);
    for (int i = 0; i < MARKET_MODERATION_RELAY_RULE_COUNT; i++) {
        struct json_value r;
        json_init(&r);
        json_set_str(&r, market_moderation_relay_rule_string(
                             (enum market_moderation_relay_rule)i));
        json_push_back(&profiles, &r);
        json_free(&r);
    }
    json_push_kv(result, "available_relay_rules", &profiles);
    json_free(&profiles);

    int64_t counts[MARKET_REVIEW_STATE_COUNT] = {0, 0, 0};
    struct zcl_result counted = market_moderation_review_counts(counts);
    struct json_value by_state;
    json_init(&by_state);
    json_set_object(&by_state);
    for (int i = 0; i < MARKET_REVIEW_STATE_COUNT; i++)
        json_push_kv_int(&by_state,
                         market_review_state_string(
                             (enum market_review_state)i),
                         counted.ok ? counts[i] : 0);
    json_push_kv(result, "review_counts", &by_state);
    json_free(&by_state);
    json_push_kv_bool(result, "review_counts_live", counted.ok);
    json_push_kv_int(result, "offers_cached", file_market_count());
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    /* False since the profile started deciding what this node HANDS OUT,
     * not only what it lists: chunk delivery, offer re-gossip, and the
     * registered-content index all ask it now. Reporting it as
     * view-filtering-only would advertise a narrower effect than the
     * node actually has. What is still untouched: ingest, storage,
     * deletion (there is none), the signed wire, and consensus. */
    json_push_kv_bool(result, "view_filter_only", false);
    return true;
}

static bool rpc_zmarket_moderation_profile_show(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "zmarket_moderation_profile_show \"profile\"\n"
            "\nDescribe one immutable named listing-visibility profile:\n"
            "what it shows, what it hides, and whether it is active here.\n"
            "\nArguments:\n"
            "1. profile   (string, required) \"general-audience.v1\" or "
            "\"open-view\"\n");
        return true;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const char *name =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    int profile = market_moderation_profile_from_string(name);
    if (profile < 0) {
        json_set_str(result,
            "unknown market moderation profile — available: "
            "general-audience.v1, open-view");
        return false;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct market_moderation_view_service_v1 *service = zcl_hotswap_service_acquire(MARKET_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service) service = market_moderation_view_service_builtin();
    struct market_moderation_profile_result_v1 rendered;
    if (!service->render_profile(profile, &rendered) || !rendered.valid) {
        zcl_hotswap_service_release(&lease);
        json_set_str(result, "market moderation profile rendering failed");
        return false;
    }
    json_set_object(result);
    json_push_kv_str(result, "profile", rendered.profile);
    json_push_kv_bool(result, "immutable", true);
    json_push_kv_bool(result, "active", (int)market_moderation_active_profile() == profile);
    json_push_kv_str(result, "shows", rendered.shows);
    json_push_kv_str(result, "hides", rendered.hides);
    /* A profile describes the SERVE leg only. Naming the leg here, and
     * naming the relay rule that is in force beside it, stops a reader
     * from taking "hides X" as a statement about relay too. */
    json_push_kv_str(result, "leg", "serve");
    json_push_kv_str(result, "active_relay_rule",
                     market_moderation_relay_rule_string(
                         market_moderation_active_relay_rule()));
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    zcl_hotswap_service_release(&lease);
    return true;
}

/* Plan tokens are domain-separated per leg so a token minted to move the
 * serve profile can never commit a relay change, or the reverse. */
static void market_plan_token(const char *domain, size_t domain_len,
                              const char *active_name,
                              const char *target_name, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, (const uint8_t *)active_name,
                   strlen(active_name) + 1u);
    sha3_256_write(&sha, (const uint8_t *)target_name,
                   strlen(target_name) + 1u);
    sha3_256_finalize(&sha, out);
}

static void market_profile_plan_token(const char *active_name,
                                      const char *target_name,
                                      uint8_t out[32])
{
    static const char domain[] = "zcl.market.moderation.plan.v1";
    market_plan_token(domain, sizeof(domain), active_name, target_name, out);
}

static void market_relay_plan_token(const char *active_name,
                                    const char *target_name,
                                    uint8_t out[32])
{
    static const char domain[] = "zcl.market.moderation.relay.plan.v1";
    market_plan_token(domain, sizeof(domain), active_name, target_name, out);
}

/* The per-offer REVIEW mark's plan token: unlike the two posture legs
 * there is no single "current value", so the token binds offer identity,
 * the mark as it stands at plan time, and the target. Moving the mark
 * between plan and commit therefore stales the token exactly the way a
 * moved profile stales a posture token. */
static void market_review_plan_token(const char *offer_hex,
                                     const char *current_name,
                                     const char *target_name, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.market.review.plan.v1";
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, (const uint8_t *)offer_hex, strlen(offer_hex) + 1u);
    sha3_256_write(&sha, (const uint8_t *)current_name,
                   strlen(current_name) + 1u);
    sha3_256_write(&sha, (const uint8_t *)target_name,
                   strlen(target_name) + 1u);
    sha3_256_finalize(&sha, out);
}

static bool rpc_zmarket_moderation_profile_set(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_moderation_profile_set \"profile\" \"mode\" "
            "[\"plan_token\"]\n"
            "\nSet the node's own listing-visibility profile, persisted to\n"
            "<datadir>/market/moderation.v1. Exact two-step: mode \"plan\"\n"
            "mints a plan_token bound to the current active profile and the\n"
            "target; mode \"commit\" requires that token (STALE_PLAN if the\n"
            "active profile moved in between). Local view filtering only.\n"
            "\nArguments:\n"
            "1. profile   (string, required) \"general-audience.v1\" or "
            "\"open-view\"\n"
            "2. mode      (string, required) \"plan\" or \"commit\"\n"
            "3. plan_token (string, required for commit) 64-hex plan token\n");
        return true;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    const char *name =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    const char *mode =
        arg1 && arg1->type == JSON_STR ? json_get_str(arg1) : NULL;
    int profile = market_moderation_profile_from_string(name);
    if (profile < 0) {
        json_set_str(result,
            "unknown market moderation profile — available: "
            "general-audience.v1, open-view");
        return false;
    }
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        json_set_str(result, "mode must be \"plan\" or \"commit\"");
        return false;
    }

    const char *active_name = market_moderation_profile_string(
        market_moderation_active_profile());
    uint8_t token[32];
    market_profile_plan_token(active_name, name, token);

    bool committed = false;
    if (strcmp(mode, "commit") == 0) {
        const struct json_value *arg2 = json_at(params, 2);
        const char *hex =
            arg2 && arg2->type == JSON_STR ? json_get_str(arg2) : NULL;
        uint8_t supplied[32], difference = 0;
        if (!hex || strlen(hex) != 64 ||
            !zcl_hex_decode_lower(hex, supplied, 32)) {
            json_set_str(result,
                "INVALID_PLAN_TOKEN: commit requires the canonical 64-hex "
                "plan_token minted by mode \"plan\"");
            return false;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            json_set_str(result,
                "STALE_PLAN: the active moderation profile moved after the "
                "plan was minted — re-plan and commit again");
            return false;
        }
        struct zcl_result set = market_moderation_set_active_profile(
            (enum market_moderation_profile)profile);
        if (!set.ok) {
            char message[300];
            snprintf(message, sizeof(message), "POLICY_REFUSED: %s",
                     set.message[0] ? set.message : "profile save failed");
            json_set_str(result, message);
            return false;
        }
        committed = true;
    }

    char token_hex[65];
    zcl_hex_encode(token, 32, token_hex);
    json_set_object(result);
    json_push_kv_str(result, "mode", mode);
    json_push_kv_bool(result, "committed", committed);
    json_push_kv_str(result, "plan_token", token_hex);
    json_push_kv_str(result, "profile", name);
    json_push_kv_str(result, "previous_profile", active_name);
    json_push_kv_str(result, "relay_rule",
                     market_moderation_relay_rule_string(
                         market_moderation_active_relay_rule()));
    json_push_kv_bool(result, "relay_rule_unchanged", true);
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    return true;
}

/* The RELAY leg's own setter. Deliberately a separate command from
 * profile_set rather than a flag on it: the two legs have different
 * defaults and protect different things, and an operator changing what
 * this node HOSTS should never move what it FORWARDS as a side effect. */
static bool rpc_zmarket_moderation_relay_set(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zmarket_moderation_relay_set \"relay_rule\" \"mode\" "
            "[\"plan_token\"]\n"
            "\nSet the node's own RELAY rule — whether it forwards other\n"
            "people's offer announcements — persisted to\n"
            "<datadir>/market/moderation.v1 alongside, and independent of,\n"
            "the serve profile. Same exact two-step as profile_set: mode\n"
            "\"plan\" mints a plan_token bound to the current rule and the\n"
            "target; \"commit\" requires that token (STALE_PLAN if the rule\n"
            "moved in between). Plan tokens are not interchangeable\n"
            "between the setters.\n"
            "\nBoot default is relay-all.v1: forward every valid offer.\n"
            "Relaying passes on a POINTER, not content — gating it by\n"
            "default would cut an honest seller's reach to one hop and hand\n"
            "discovery to whoever has operators awake. relay-reviewed-only\n"
            ".v1 is the opt-in that forwards only offers this node marked\n"
            "reviewed_ok; refusals are counted in offer_relay_hidden_by_\n"
            "profile, never silently dropped.\n"
            "\nArguments:\n"
            "1. relay_rule (string, required) \"relay-all.v1\" or "
            "\"relay-reviewed-only.v1\"\n"
            "2. mode       (string, required) \"plan\" or \"commit\"\n"
            "3. plan_token (string, required for commit) 64-hex plan token\n");
        return true;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    const char *name =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    const char *mode =
        arg1 && arg1->type == JSON_STR ? json_get_str(arg1) : NULL;
    int rule = market_moderation_relay_rule_from_string(name);
    if (rule < 0) {
        json_set_str(result,
            "unknown market moderation relay rule — available: "
            "relay-all.v1, relay-reviewed-only.v1");
        return false;
    }
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        json_set_str(result, "mode must be \"plan\" or \"commit\"");
        return false;
    }

    const char *active_name = market_moderation_relay_rule_string(
        market_moderation_active_relay_rule());
    uint8_t token[32];
    market_relay_plan_token(active_name, name, token);

    bool committed = false;
    if (strcmp(mode, "commit") == 0) {
        const struct json_value *arg2 = json_at(params, 2);
        const char *hex =
            arg2 && arg2->type == JSON_STR ? json_get_str(arg2) : NULL;
        uint8_t supplied[32], difference = 0;
        if (!hex || strlen(hex) != 64 ||
            !zcl_hex_decode_lower(hex, supplied, 32)) {
            json_set_str(result,
                "INVALID_PLAN_TOKEN: commit requires the canonical 64-hex "
                "plan_token minted by mode \"plan\"");
            return false;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            json_set_str(result,
                "STALE_PLAN: the active relay rule moved after the plan was "
                "minted — re-plan and commit again");
            return false;
        }
        struct zcl_result set = market_moderation_set_active_relay_rule(
            (enum market_moderation_relay_rule)rule);
        if (!set.ok) {
            char message[300];
            snprintf(message, sizeof(message), "POLICY_REFUSED: %s",
                     set.message[0] ? set.message : "relay rule save failed");
            json_set_str(result, message);
            return false;
        }
        committed = true;
    }

    char token_hex[65];
    zcl_hex_encode(token, 32, token_hex);
    json_set_object(result);
    json_push_kv_str(result, "mode", mode);
    json_push_kv_bool(result, "committed", committed);
    json_push_kv_str(result, "plan_token", token_hex);
    json_push_kv_str(result, "relay_rule", name);
    json_push_kv_str(result, "previous_relay_rule", active_name);
    json_push_kv_str(result, "profile",
                     market_moderation_profile_string(
                         market_moderation_active_profile()));
    json_push_kv_bool(result, "profile_unchanged", true);
    json_push_kv_str(result, "policy_file", MARKET_MODERATION_POLICY_FILE);
    return true;
}

static bool rpc_zmarket_review_set(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "zmarket_review_set \"offer_id\" \"review_state\" \"mode\" "
            "[\"plan_token\"]\n"
            "\nThe node's OWN curation mark on one signed offer: sets the\n"
            "local-only review_state (unreviewed / reviewed_ok / sensitive).\n"
            "Never gossiped, never in the signed wire, never a deletion —\n"
            "the offer stays stored either way. This is how this node signs\n"
            "off: under the boot-default general-audience.v1 profile only a\n"
            "reviewed_ok offer is listed and served from here. Relay is a\n"
            "separate rule and forwards everything by default, so this mark\n"
            "does not affect relay unless the operator opted in to\n"
            "relay-reviewed-only.v1. One audit log line is written per mark.\n"
            "\nSame exact two-step as the posture setters: mode \"plan\"\n"
            "mints a plan_token bound to this offer's current mark and the\n"
            "target; mode \"commit\" requires that token (STALE_PLAN if the\n"
            "mark moved in between). Plan tokens are not interchangeable\n"
            "between the legs.\n"
            "\nArguments:\n"
            "1. offer_id     (string, required) 64-hex signed offer id\n"
            "2. review_state (string, required) unreviewed | reviewed_ok | "
            "sensitive\n"
            "3. mode         (string, required) \"plan\" or \"commit\"\n"
            "4. plan_token   (string, required for commit) 64-hex plan token\n");
        return true;
    }
    /* Asked through the service rather than a controller-owned handle:
     * the review store belongs to the moderation service, and this file
     * deliberately holds no database of its own. */
    if (!market_moderation_store_ready()) {
        json_set_str(result,
            "NODE_UNAVAILABLE: the market store is not open on this node");
        return false;
    }
    const struct json_value *arg0 = json_at(params, 0);
    const struct json_value *arg1 = json_at(params, 1);
    const struct json_value *arg2 = json_at(params, 2);
    const char *id_hex =
        arg0 && arg0->type == JSON_STR ? json_get_str(arg0) : NULL;
    const char *state_text =
        arg1 && arg1->type == JSON_STR ? json_get_str(arg1) : NULL;
    const char *mode =
        arg2 && arg2->type == JSON_STR ? json_get_str(arg2) : NULL;
    uint8_t offer_id[32];
    if (!id_hex || strlen(id_hex) != 64 ||
        !zcl_hex_decode_lower(id_hex, offer_id, 32)) {
        json_set_str(result,
            "INVALID_OFFER_ID: offer_id must be the 64-hex signed offer id");
        return false;
    }
    int state = market_review_state_from_string(state_text);
    if (state < 0) {
        json_set_str(result,
            "INVALID_REVIEW_STATE: use unreviewed, reviewed_ok, or "
            "sensitive");
        return false;
    }
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        json_set_str(result, "mode must be \"plan\" or \"commit\"");
        return false;
    }

    /* Read the mark BEFORE any write, through the service, so the plan
     * token can bind what it replaces and the audit line can name it. An
     * id no signed offer carries reads as unreviewed here and is refused
     * by the write below — which is the one authority on whether the
     * offer exists, so the two can never disagree about it. */
    enum market_review_state previous =
        (enum market_review_state)
            market_moderation_review_state_for_offer_id(offer_id);
    const char *previous_name = market_review_state_string(previous);

    uint8_t token[32];
    market_review_plan_token(id_hex, previous_name,
                             market_review_state_string(
                                 (enum market_review_state)state),
                             token);

    bool committed = false;
    if (strcmp(mode, "commit") == 0) {
        const struct json_value *arg3 = json_at(params, 3);
        const char *hex =
            arg3 && arg3->type == JSON_STR ? json_get_str(arg3) : NULL;
        uint8_t supplied[32], difference = 0;
        if (!hex || strlen(hex) != 64 ||
            !zcl_hex_decode_lower(hex, supplied, 32)) {
            json_set_str(result,
                "INVALID_PLAN_TOKEN: commit requires the canonical 64-hex "
                "plan_token minted by mode \"plan\"");
            return false;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            json_set_str(result,
                "STALE_PLAN: the review mark moved after the plan was minted "
                "— re-plan and commit again");
            return false;
        }
        struct zcl_result marked = market_moderation_set_review_state(
            offer_id, (enum market_review_state)state);
        if (!marked.ok) {
            char message[300];
            snprintf(message, sizeof(message), "REVIEW_REFUSED: %s",
                     marked.message[0] ? marked.message
                                       : "the mark could not persist");
            json_set_str(result, message);
            return false;
        }
        committed = true;
        /* Local curation audit trail: one line per mark, node.log only. */
        LOG_INFO("market",
                 "moderation review set: offer_id=%s review_state=%s "
                 "previous=%s",
                 id_hex,
                 market_review_state_string(
                     (enum market_review_state)state),
                 previous_name);
    }

    char token_hex[65];
    zcl_hex_encode(token, 32, token_hex);
    json_set_object(result);
    json_push_kv_str(result, "mode", mode);
    json_push_kv_bool(result, "committed", committed);
    json_push_kv_str(result, "plan_token", token_hex);
    json_push_kv_str(result, "status", committed ? "marked" : "planned");
    json_push_kv_str(result, "offer_id", id_hex);
    json_push_kv_str(result, "review_state",
                     market_review_state_string(
                         (enum market_review_state)state));
    json_push_kv_str(result, "previous_review_state", previous_name);
    json_push_kv_bool(result, "local_only", true);
    json_push_kv_bool(result, "gossiped", false);
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

/* Called from register_market_rpc_commands so the market RPC table stays
 * the one place a reader looks for market command names. */
void register_market_moderation_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "market", "zmarket_moderation_status",
          rpc_zmarket_moderation_status, true },
        { "market", "zmarket_moderation_profile_show",
          rpc_zmarket_moderation_profile_show, true },
        { "market", "zmarket_moderation_profile_set",
          rpc_zmarket_moderation_profile_set, false },
        { "market", "zmarket_moderation_relay_set",
          rpc_zmarket_moderation_relay_set, false },
        { "market", "zmarket_review_set", rpc_zmarket_review_set, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
