/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Current, identity-bound custody snapshot from existing wallet authorities. */

#ifndef ZCL_SERVICES_WALLET_MONEY_SERVICE_H
#define ZCL_SERVICES_WALLET_MONEY_SERVICE_H

#include "base/result.h"
#include "models/wallet_identity.h"
#include "sync/sync_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct main_state;
struct node_db;

#define WALLET_MONEY_REASON_MAX 160

enum wallet_money_freshness {
    WALLET_MONEY_FRESHNESS_UNKNOWN = 0,
    WALLET_MONEY_FRESHNESS_STALE,
    WALLET_MONEY_FRESHNESS_CURRENT,
};

struct wallet_money_snapshot {
    struct wallet_identity_row identity;
    char wallet_scope[5];
    char status[16];                 /* CURRENT | UNKNOWN | STALE | CONFLICTED */
    bool complete;
    char reason[WALLET_MONEY_REASON_MAX + 1];

    int64_t confirmed_zat;
    int64_t transparent_spendable_zat;
    int64_t shielded_spendable_zat;
    int64_t pending_zat;
    int64_t encumbered_zat;
    int64_t intent_reserved_zat;
    int64_t lifetime_lab_spent_zat;
    int64_t agent_available_zat;

    int32_t tip_height;
    int32_t network_tip_height;
    uint8_t tip_hash[32];
    int64_t observed_at;
    uint8_t snapshot_root[32];
};

/* Pure fail-closed classification shared by snapshot construction and tests.
 * `network_tip` is the maximum of active-chain, best-header, and observed-peer
 * height. CURRENT requires a published H*, an exact authoritative coins tip
 * at that target, H* exactly at the coins tip,
 * at least one live peer, and a live block-catch-up state. It deliberately
 * does not require SYNC_AT_TIP: that global verdict also proves complete
 * historical block-body custody, which a valid bundle-seeded wallet may not
 * possess. */
enum wallet_money_freshness wallet_money_freshness_classify(
    bool hstar_published, int32_t hstar, int32_t money_tip,
    int32_t network_tip, size_t peer_count, enum sync_state state);

/* Explicit custody scopes accepted by the wallet-local money authority.
 * `test` is an isolated, pre-funded lab wallet: it is not part of the
 * dev/prod portfolio and its own confirmed balance is its hard envelope. */
bool wallet_money_scope_valid(const char *wallet_scope);
const char *wallet_money_scope_expected_lane(const char *wallet_scope);
const char *wallet_money_scope_for_lane(const char *operator_lane);

/* Compose identity + vault readers + intent reservations + chain tip. No
 * independent balance arithmetic is stored; every call re-reads authorities. */
struct zcl_result wallet_money_snapshot_build(
    struct node_db *ndb, struct main_state *main_state,
    const char *wallet_scope, struct wallet_money_snapshot *out);

/* Build for the wallet identity already bound to this node.  The persisted
 * operator lane is the authority for the scope: canonical -> prod, dev ->
 * dev, test -> test.  Callers must not guess a scope or probe several scopes
 * to discover which wallet they reached. */
struct zcl_result wallet_money_snapshot_build_current(
    struct node_db *ndb, struct main_state *main_state,
    struct wallet_money_snapshot *out);

/* Purely derive the exact money document after adding one durable intent
 * reservation.  This is valid only for a complete CURRENT snapshot and never
 * reads or writes storage.  The caller must bind the insert atomically to the
 * input snapshot's intent_reserved_zat before publishing the derived root. */
bool wallet_money_snapshot_after_reservation(
    const struct wallet_money_snapshot *before, int64_t reservation_zat,
    struct wallet_money_snapshot *after);

struct zcl_result wallet_money_snapshot_to_json(
    const struct wallet_money_snapshot *snapshot, struct json_value *out);

/* Apply the development allocation to a caller's explicit owner-reviewed
 * reserve floor. Non-development scopes retain their normal availability. */
int64_t wallet_money_agent_available_for_floor(
    const struct wallet_money_snapshot *snapshot, int64_t reserve_floor_zat);

#endif
