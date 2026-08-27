/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * yardsale_prevout_service — the confirmed-prevout fetch behind the buyer's
 * chain-content port (yardsale_ceremony_set_prevout_fetch). Before a buyer
 * signs a swap he re-reads the seller's claimed token input from confirmed
 * chain state: the ad's token leg is a claim, and this service is what turns
 * that claim into something checked (zswap_assembly.h's "classify the
 * seller's token input via slp_classify_tx_output before accepting").
 *
 * Shape: one pure read over the canonical confirmed lookup path — the
 * node.db locator row is only a HINT; the row's height must name the
 * active chain's block and the on-disk body must hash back to both that
 * block and the requested txid, so a stale or hostile locator row can
 * never substitute a different body. Never serves mempool transactions:
 * callers treat false as "not confirmed here". */

#ifndef ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H
#define ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct node_db;
struct transaction;

/* The confirmed-chain view a fetch reads: the active chain for tip
 * verification, the canonical node database for the finalized
 * (txid -> height / tx_index / block_hash) locator row, and the datadir
 * for the verified block body. The boot composition root fills one for
 * the node's lifetime; tests build their own or fake the port entirely. */
struct yardsale_prevout_view {
    struct main_state *state;
    struct node_db *node_db;
    const char *datadir;
};

/* Fetch a CONFIRMED transaction body by txid (internal little-endian
 * byte order — the same order as transaction.hash). Signature matches
 * yardsale_prevout_fetch_fn so it wires straight into the ceremony port;
 * ctx is a struct yardsale_prevout_view *. On success *tx_out receives a
 * private copy the caller owns (transaction_free). */
bool yardsale_prevout_fetch_confirmed(void *ctx, const uint8_t txid[32],
                                      struct transaction *tx_out);

#endif /* ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H */
