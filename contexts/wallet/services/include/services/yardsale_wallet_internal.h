/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: internal shared helpers between the two halves of the yardsale
 * wallet service (yardsale_wallet_service.c — seller arm/disarm/status —
 * and yardsale_wallet_service_buy.c — the buy). Not a public API; the
 * public entry points stay in services/yardsale_wallet_service.h. */

#ifndef ZCL_SERVICES_YARDSALE_WALLET_INTERNAL_H
#define ZCL_SERVICES_YARDSALE_WALLET_INTERNAL_H

#include "base/result.h"
#include "models/yardsale_plan.h"
#include "wallet/wallet.h"
#include "zswap/zswap_assembly.h"
#include "zswap/zswap_yardsale.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

#define YW_COIN_CAP 4096
#define YW_PAYLOAD_RAW_MAX (YARDSALE_PLAN_PAYLOAD_HEX_MAX / 2)

/* Every refusal: logged, and the body always names the rule that fired. */
enum yardsale_wallet_status yw_fail(struct json_value *out,
                                    enum yardsale_wallet_status status,
                                    const char *message);

/* Canonical payload parse (the zswap_assembly.c layout, LE ints):
 * payload = ad_root(32) || canonical accept; strict, trailing bytes
 * rejected, validation re-run, buyer inputs must be in canonical sorted
 * order. */
struct zcl_result yw_parse_seller_payload(const uint8_t *raw, size_t len,
                                          uint8_t ad_root[32],
                                          struct zswap_seller_accept *out);
struct zcl_result yw_parse_buyer_payload(const uint8_t *raw, size_t len,
                                         uint8_t ad_root[32],
                                         struct zswap_buyer_accept *out);
struct zcl_result yw_payload_decode(const char *hex, uint8_t *raw,
                                    size_t raw_cap, size_t *raw_len);

void yw_script_key_id(const uint8_t *script, struct key_id *out);

/* Find one outpoint among the wallet's confirmed coins; include_slp must
 * be true for the seller's token input (ordinary selection reserves it)
 * and false for the buyer's ZCL inputs. .ok = found confirmed-spendable. */
struct zcl_result yw_find_coin(struct wallet *w, const uint8_t txid[32],
                               uint32_t vout, bool include_slp,
                               struct coin_entry *coin, bool *seen);
int64_t yw_available_ordinary(struct wallet *w);

/* The remembered sign for root, live inside its validity window.
 * .ok = the sign is live. */
struct zcl_result yw_live_ad(const uint8_t ad_root[32], int64_t now_unix,
                             struct zswap_yardsale_ad *out);

/* The wired ceremony port, or NULL before
 * yardsale_wallet_set_ceremony_port() runs. */
const struct yardsale_wallet_ceremony_port *yw_ceremony_port(void);

/* sha3 over the canonical terms bytes — the status "terms digest". */
void yw_terms_digest(const uint8_t *bytes, size_t len, char out[65]);

void yw_render_plan_head(struct json_value *out, const char *kind,
                         const char plan_root_hex[65],
                         const char request_hex[65], int64_t expires_unix);
void yw_render_seller_terms(struct json_value *out,
                            const struct zswap_seller_accept *terms,
                            const struct zswap_yardsale_ad *ad);
void yw_render_buyer_terms(struct json_value *out,
                           const struct zswap_buyer_accept *buyer,
                           const struct zswap_yardsale_ad *ad);

/* Plan row plumbing: deterministic request/plan identity, store/refresh,
 * and state transitions. */
struct yw_plan {
    char request_hex[65];
    char plan_root_hex[65];
    struct db_yardsale_plan row;
    bool exists;
};

void yw_plan_identity(struct yw_plan *p, const char *kind,
                      const uint8_t *a, size_t a_len,
                      const uint8_t *b, size_t b_len);
struct zcl_result yw_plan_store(struct yw_plan *p, struct node_db *ndb,
                                const char *kind, const char *payload_hex,
                                int64_t now_unix);
struct zcl_result yw_plan_mark(struct yw_plan *p, struct node_db *ndb,
                               const char *state, const char *result);

#endif /* ZCL_SERVICES_YARDSALE_WALLET_INTERNAL_H */
