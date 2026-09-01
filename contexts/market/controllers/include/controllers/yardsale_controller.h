/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Yardsale MVC controller — the ceremony brain of the yardsale
 * app (contexts/commons/apps/yardsale/app.def).
 *
 * The yardsale is for-sale-by-owner, always: sellers pin signed, expiring
 * ads (zswap_quote.v1) into the gossip yardsale (zswap/zswap_yardsale.h),
 * and a buyer settles DIRECTLY with the seller through the two-message
 * ceremony (zswap/zswap_ceremony.h). This controller is the seam between
 * the transports and that pure ceremony core:
 *
 *   SELLER side — a zswap_accept.v1 wire arrives (P2P zswapaccept gossip,
 *   or a POST to the /yardsale/accept web endpoint). The controller finds
 *   the named ad in the local yardsale, and — only when the operator has
 *   configured a seller profile (terms + the key owning the token input) —
 *   re-verifies the assembled transaction pays the exact ad terms and
 *   partial-signs it (zswap_ceremony_seller_build_partial), producing the
 *   zswap_partial.v1 answer. A node with no profile configured never signs
 *   anything; it just relays.
 *
 *   BUYER side — yardsale_buyer_begin() encodes the accept, registers a
 *   pending buy (the ad, the accept data, and one privkey per buyer input),
 *   and floods zswapaccept. When the seller's zswap_partial.v1 comes back
 *   (P2P zswappartial gossip), the controller re-verifies every term
 *   against the signed ad byte-for-byte, inserts the seller's signature,
 *   signs the buyer's own inputs, and hands the fully-signed transaction
 *   to the broadcast port (default: the same mempool-accept + relay flow
 *   as sendrawtransaction).
 *
 * Gossip hygiene mirrors the zswapquote idiom: a bounded dedup ring on the
 * wire content hash (every node forwards a given wire at most once) and a
 * per-peer fresh-wire clamp, so ceremony gossip cannot loop or flood. All
 * state is static and bounded; one mutex, brief critical sections, crypto
 * verification OUTSIDE the lock (the zswap_yardsale.c idiom).
 *
 * This is NOT a matching engine: the controller never pairs buyers with
 * sellers — it carries two wires between two parties who already chose
 * each other off a signed sign.
 */

#ifndef ZCL_CONTROLLERS_YARDSALE_CONTROLLER_H
#define ZCL_CONTROLLERS_YARDSALE_CONTROLLER_H

#include "base/result.h"
#include "keys/key.h"
#include "primitives/transaction.h"
#include "zswap/zswap_ceremony.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum yardsale_error {
    YARDSALE_OK = 0,
    YARDSALE_ERR_NULL,
    YARDSALE_ERR_AD_UNKNOWN,     /* quote_root matches no remembered sign */
    YARDSALE_ERR_NOT_CONFIGURED, /* seller profile or flood port unwired */
    YARDSALE_ERR_PENDING_FULL,   /* the pending-buy table is at capacity */
    YARDSALE_ERR_NO_PENDING,     /* no pending buy for this quote_root */
    YARDSALE_ERR_KEY_COUNT,      /* input_keys != buyer->num_inputs */
    /* Ceremony failures are reported as YARDSALE_ERR_CEREMONY_BASE +
     * enum zswap_ceremony_error, so the exact Stage-3 named error survives
     * the journey through the controller. */
    YARDSALE_ERR_CEREMONY_BASE = 100,
};

const char *yardsale_error_string(int error);

/* ── Ports (composition root wires; tests inject) ────────────────── */

/* Broadcast port: receives the completed, fully-signed swap transaction.
 * Boot wires the same accept_to_mempool + connman relay flow used by
 * sendrawtransaction. Unwired, the controller refuses before buyer signing;
 * transaction-controller private state is never a fallback. */
typedef bool (*yardsale_broadcast_fn)(const struct transaction *tx,
                                      void *ctx);
void yardsale_ceremony_set_broadcast(yardsale_broadcast_fn fn, void *ctx);

/* Chain-content port: fetch a CONFIRMED transaction body by txid (internal
 * byte order) so the buyer can re-classify the seller's claimed token
 * input before signing — the ad's token leg is a claim, and only this
 * port checks it against the chain and strict token ledger the buyer actually
 * has. Implemented by the prevout service over node.db + the active chain;
 * controller tests inject a contract-equivalent fake and service tests call
 * the production implementation directly. The result type carries why a body
 * is not confirmed here (E2: services return struct zcl_result, never bare
 * bool). Fail-closed: while unwired, every partial ingest is refused (nothing
 * is signed or broadcast). */
typedef struct zcl_result (*yardsale_prevout_fetch_fn)(
    void *ctx, const uint8_t txid[32], uint32_t vout,
    const uint8_t token_id[32], uint64_t token_amount,
    struct transaction *tx_out);
void yardsale_ceremony_set_prevout_fetch(yardsale_prevout_fetch_fn fn,
                                         void *ctx);

/* Outbound gossip port: flood one ceremony wire to every fast-sync peer.
 * Wired at boot to the msg_processor flood; an unwired port makes
 * yardsale_buyer_begin return YARDSALE_ERR_NOT_CONFIGURED. */
typedef void (*yardsale_flood_fn)(const char *command,
                                  const uint8_t *wire, size_t wire_len,
                                  void *ctx);
void yardsale_ceremony_set_flood(yardsale_flood_fn fn, void *ctx);

/* The consensus branch id the ceremony signs under (both parties must
 * agree). Boot derives (active tip + 1) at the composition root; tests pin
 * the fixture branch. Unwired, signing refuses. */
typedef uint32_t (*yardsale_branch_id_fn)(void *ctx);
void yardsale_ceremony_set_branch_id_source(yardsale_branch_id_fn fn,
                                            void *ctx);

/* ── Seller side ─────────────────────────────────────────────────── */

/* The operator's standing seller terms: the token input being sold, the
 * ZCL receive + change addresses, and the key that owns the token input.
 * One profile per node — a seller with several signs out re-configures or
 * leaves the answering to a dedicated node. Configured state is process
 * memory only; the key copy is cleansed by
 * yardsale_seller_profile_clear(). */
void yardsale_seller_profile_configure(
    const struct zswap_seller_accept *terms, const struct privkey *key);
void yardsale_seller_profile_clear(void);
bool yardsale_seller_profile_configured(void);

/* Snapshot the configured seller terms (no key material — the terms are
 * the outpoint, addresses, and deadline only). Returns false when no
 * profile is configured. Backs yardsale.seller.status. */
bool yardsale_seller_profile_snapshot(struct zswap_seller_accept *terms_out);

/* Handle one zswap_accept.v1 wire as the seller: strict-decode, look the
 * ad up in the local yardsale cache (an accept for a sign we never saw is
 * YARDSALE_ERR_AD_UNKNOWN), and — with a configured profile — verify the
 * assembled transaction pays the exact ad terms and partial-sign the token
 * input. On success *out carries the exact zswap_partial.v1 wire. */
enum yardsale_error yardsale_seller_handle_accept_wire(
    const uint8_t *wire, size_t wire_len, int64_t now_unix,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* ── Buyer side ──────────────────────────────────────────────────── */

/* Begin a buy: validate the ad is live at now_unix and the accept data is
 * structurally sound, encode the zswap_accept.v1 wire into wire_out,
 * register the pending buy (ad + accept + one privkey per buyer input,
 * parallel to buyer->inputs[] in the caller's order — the completion maps
 * them back onto the canonically sorted vin by outpoint), and flood
 * zswapaccept through the flood port. num_keys must equal
 * buyer->num_inputs (v1: one key per input — a wallet-backed multi-key
 * buy is a later slice). */
enum yardsale_error yardsale_buyer_begin(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct privkey *input_keys, size_t num_keys,
    int64_t now_unix,
    uint8_t *wire_out, size_t wire_cap, size_t *wire_len);

/* ── P2P ingress (wired into the msg_processor dispatch at boot) ──── */

/* The int return carries enum zswap_ceremony_wire_result
 * (zswap/zswap_ceremony.h): DROP consumed/refused the wire, RELAY forwards
 * it once, RESPOND floods respond back (the seller's partial). */
int yardsale_ceremony_accept_ingest(const uint8_t *wire, size_t wire_len,
                                    int64_t peer_id, int64_t now_unix,
                                    uint8_t *respond, size_t respond_cap,
                                    size_t *respond_len);
int yardsale_ceremony_partial_ingest(const uint8_t *wire, size_t wire_len,
                                     int64_t peer_id, int64_t now_unix);

/* Count of live pending buys (diagnostics/tests). */
int yardsale_pending_count(int64_t now_unix);

/* Test hook: drop every pending buy (cleansing keys), the relay dedup
 * ring, and the per-peer clamp. Does NOT clear the seller profile. */
void yardsale_ceremony_reset(void);

#endif /* ZCL_CONTROLLERS_YARDSALE_CONTROLLER_H */
