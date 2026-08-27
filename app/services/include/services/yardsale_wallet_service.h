/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the yardsale WALLET GLUE — wallet-backed seller arm and
 * wallet-backed buy behind exact, expiring plan/commit commands.
 *
 * Stage 4 shipped the ceremony brain (controllers/yardsale_controller.h)
 * and the onion form flow; what only C tests could do was arm the seller
 * profile and begin a buy. This service is the operator path:
 *
 *   yardsale_wallet_seller_arm — plan: verify the named token outpoint is
 *     a confirmed, spendable, P2PKH wallet coin holding EXACTLY the sign's
 *     token_amount of the sign's token_id (SLP overlay classification, the
 *     assembler's exact-coin precondition), derive the ZCL receive +
 *     change addresses from the wallet, and persist an exact expiring plan
 *     (yardsale_plans, models/yardsale_plan.h) binding the canonical
 *     seller terms. commit (confirm:true): re-verify the coin is still
 *     there, fetch the owning key from the wallet, and configure the
 *     process-memory seller profile (yardsale_seller_profile_configure).
 *   yardsale_wallet_seller_disarm — clear the profile (cleanses the key).
 *   yardsale_wallet_seller_status — configured? terms digest, outpoint,
 *     addresses, deadline. NEVER the key.
 *   yardsale_wallet_buy — plan: select confirmed ordinary wallet ZCL
 *     inputs covering the sign's zcl_amount + the wallet fee (ordinary
 *     selection, which never touches SLP-reserved coins), derive the token
 *     receive + change addresses, persist the exact plan. commit: fetch
 *     one wallet key per input and yardsale_buyer_begin(), which floods
 *     zswapaccept; completion lands via the existing partial-ingest path.
 *
 * Idempotency: request_hash = SHA3(domain | kind | request fields) is the
 * durable identity; plan_root = SHA3(plan-domain | request_hash). The
 * same request always names the same plan — re-planning returns it
 * unchanged, re-committing returns the stored result, and neither double
 * arms nor double registers a pending buy. Plans expire after
 * YARDSALE_WALLET_PLAN_TTL_SECS; an expired plan refuses commit and never
 * arms/buys.
 *
 * KEY HYGIENE: keys are fetched from the wallet at commit time only, used
 * in stack copies cleansed with memory_cleanse, and NEVER written to the
 * plan row, the DB, or the logs. The plan payload is the canonical accept
 * serialization plus the sign root — outpoints, addresses, and deadlines
 * only. Every refusal names its rule; no path half-arms or half-begins. */

#ifndef ZCL_SERVICES_YARDSALE_WALLET_SERVICE_H
#define ZCL_SERVICES_YARDSALE_WALLET_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wallet;
struct node_db;
struct json_value;
struct zswap_seller_accept;
struct zswap_buyer_accept;
struct zswap_quote_v1;
struct privkey;

#define YARDSALE_WALLET_PLAN_TTL_SECS 600LL

enum yardsale_wallet_status {
    YARDSALE_WALLET_OK = 0,
    YARDSALE_WALLET_ERR_ARGS,            /* caller passed nonsense */
    YARDSALE_WALLET_ERR_DB,              /* node.db unavailable / save failed */
    YARDSALE_WALLET_ERR_AD_UNKNOWN,      /* no live sign with that root */
    YARDSALE_WALLET_ERR_INPUT_NOT_OWNED, /* outpoint not a confirmed spendable wallet coin */
    YARDSALE_WALLET_ERR_TOKEN_MISMATCH,  /* coin holds the wrong token or amount */
    YARDSALE_WALLET_ERR_SCRIPT_TYPE,     /* a coin's script is not P2PKH */
    YARDSALE_WALLET_ERR_KEY_MISSING,     /* the wallet holds no key for the coin */
    YARDSALE_WALLET_ERR_ADDRESS,         /* receive/change derivation failed */
    YARDSALE_WALLET_ERR_FEE,             /* the wallet fee is not a positive amount */
    YARDSALE_WALLET_ERR_INSUFFICIENT,    /* confirmed balance cannot cover price + fee */
    YARDSALE_WALLET_ERR_INPUT_CONFLICT,  /* a planned input is no longer spendable */
    YARDSALE_WALLET_ERR_PLAN_NOT_FOUND,  /* commit without a plan */
    YARDSALE_WALLET_ERR_PLAN_EXPIRED,    /* commit after the plan lifetime */
    YARDSALE_WALLET_ERR_CEREMONY,        /* yardsale_buyer_begin refused */
    YARDSALE_WALLET_ERR_INTERNAL         /* allocation / impossible state */
};

/* Stable machine token for a status, e.g. "INSUFFICIENT_CONFIRMED_FUNDS".
 * Never NULL. */
const char *yardsale_wallet_status_code(int status);

/* Seller arm: plan (confirm=false) or commit (confirm=true). token_txid is
 * node-internal byte order. Fills `out` with the result body on every
 * path — ok:false + code + message on a refusal. */
enum yardsale_wallet_status yardsale_wallet_seller_arm(
    struct wallet *w, struct node_db *ndb,
    const uint8_t token_txid[32], uint32_t token_vout,
    const uint8_t ad_root[32], bool confirm, int64_t now_unix,
    struct json_value *out);

/* Clear the seller profile, cleansing the retained key. Idempotent:
 * disarming an unarmed node is a clean no-op that says so. */
enum yardsale_wallet_status yardsale_wallet_seller_disarm(
    struct json_value *out);

/* Configured? terms digest, token outpoint, addresses, deadline — never
 * the key. */
enum yardsale_wallet_status yardsale_wallet_seller_status(
    int64_t now_unix, struct json_value *out);

/* Buy the live sign ad_root: plan (confirm=false) or commit
 * (confirm=true). Fills `out` on every path; an insufficient-balance plan
 * refusal names required/available/shortfall sats. */
enum yardsale_wallet_status yardsale_wallet_buy(
    struct wallet *w, struct node_db *ndb,
    const uint8_t ad_root[32], bool confirm, int64_t now_unix,
    struct json_value *out);

/* ── ceremony port ─────────────────────────────────────────────────── */

/* The service never includes controllers/ (shape-direction gate): the
 * seller-profile side effects and the buyer ceremony ride this port,
 * wired by the RPC controller at registration (and by tests directly).
 * buyer_begin / buyer_error_string carry enum yardsale_error as int so
 * this header never names the controller's enum. An unwired port makes
 * arm/buy commit a loud ERR_INTERNAL refusal and status/disarm a truthful
 * "unconfigured" — never a silent no-op. */
struct yardsale_wallet_ceremony_port {
    void (*seller_profile_configure)(const struct zswap_seller_accept *terms,
                                     const struct privkey *key);
    void (*seller_profile_clear)(void);
    bool (*seller_profile_configured)(void);
    bool (*seller_profile_snapshot)(struct zswap_seller_accept *terms_out);
    int (*pending_count)(int64_t now_unix);
    int (*buyer_begin)(const struct zswap_quote_v1 *ad,
                       const struct zswap_buyer_accept *buyer,
                       const struct privkey *input_keys, size_t num_keys,
                       int64_t now_unix, uint8_t *wire_out, size_t wire_cap,
                       size_t *wire_len);
    const char *(*buyer_error_string)(int error_code);
    /* How a begun buy ended, keyed by quote_root: -1 unknown, 0
     * in-flight, 1 completed, 2 failed (the controller's outcome enum,
     * carried as int so this header never names it). NULL keeps the
     * conservative answer: a committed replay stays committed. */
    int (*buy_outcome)(const uint8_t quote_root[32]);
};

/* Set once at composition time (RPC registration / test setup); NULL
 * unwires. Not thread-safe by design — call before commands run. */
void yardsale_wallet_set_ceremony_port(
    const struct yardsale_wallet_ceremony_port *port);

#endif /* ZCL_SERVICES_YARDSALE_WALLET_SERVICE_H */
