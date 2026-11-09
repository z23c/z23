/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable, local owner-consented hosting intent. No publish or key access. */
#ifndef ZCL_MODELS_APP_HOST_INTENT_H
#define ZCL_MODELS_APP_HOST_INTENT_H

#include "models/activerecord.h"
#include "session/fleet_board_proto.h"
#include "vcs/package_release.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_HOST_ENDPOINT_MAX 72u
#define APP_HOST_WIRE_MAX (FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES)
#define APP_HOST_RETRY_MAX 31u
#define APP_HOST_REPLACEMENT_MAX 1u
#define APP_HOST_DUE_MAX 16u

enum app_host_result {
    APP_HOST_OK, APP_HOST_NOT_FOUND, APP_HOST_STALE, APP_HOST_CONFLICT,
    APP_HOST_INVALID, APP_HOST_CORRUPT, APP_HOST_BUSY, APP_HOST_STORAGE
};

/* The caller is the node coordinator: it must verify the original carrier
 * and obtain explicit owner consent before enable. This struct is data, not
 * a proof of consent, custody, or authentication. */
struct app_host_binding {
    uint8_t local_host[FLEET_BOARD_PUBKEY_BYTES];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char publisher[67];
    char release_root[65]; /* offer.root: signed release's package_root, not release_id */
    char carrier_root[65], sha256[65];
    int64_t size;
    bool recurring;
};

struct db_app_host_intent {
    struct app_host_binding binding;
    bool enabled;
    int64_t generation, due_at, renewal_slot;
    uint32_t retry_count, replacement_count;
    char slot_endpoint[APP_HOST_ENDPOINT_MAX + 1u];
    uint8_t slot_post_id[FLEET_BOARD_ID_BYTES];
    bool pending;
    uint8_t pending_wire[APP_HOST_WIRE_MAX];
    size_t pending_wire_len;
    uint8_t pending_id[FLEET_BOARD_ID_BYTES];
    uint64_t pending_created_at;
    int64_t pending_generation;
};

struct node_db;
struct ar_callbacks *db_app_host_intent_callbacks(void);
bool db_app_host_intent_validate(const struct db_app_host_intent *row,
                                 struct ar_errors *errors);
/* FOUND is APP_HOST_OK. Lookup never returns a partially decoded row. */
enum app_host_result db_app_host_intent_find(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    struct db_app_host_intent *out);
/* Deterministic due order for the current resident identity; old identities
 * cannot starve this bounded batch. Corrupt/failed reads return no rows. */
enum app_host_result db_app_host_intent_due(struct node_db *db, const uint8_t local_host[32], int64_t now,
    struct db_app_host_intent *out, size_t capacity, size_t *count, bool *more);
/* Owner-local rows ordered by (host, carrier), including rotated identities.
 * A cursor is either entirely absent or an exclusive canonical bound. Pages reflect
 * live state, not a cross-request snapshot. Failure returns no partial rows. */
enum app_host_result db_app_host_intent_list(struct node_db *db,
    const uint8_t after_host[32], const char *after_carrier,
    struct db_app_host_intent *out, size_t capacity, size_t *count, bool *more);
/* expected_generation=0 creates a new intent; reenable uses the disabled
 * row's exact generation and immutable binding. A successful consent change
 * increments generation, never past INT64_MAX. */
enum app_host_result db_app_host_intent_enable(struct node_db *db,
    const struct app_host_binding *binding, int64_t expected_generation,
    int64_t due_at);
/* A new slot reserves once; within an existing slot at most one changed
 * endpoint is accepted. Exact retry is idempotent. The supplied bytes must be
 * an exact valid signed local public apps offer matching the immutable binding. */
enum app_host_result db_app_host_intent_reserve(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation, int64_t slot, int64_t now, const char *endpoint,
    const uint8_t *wire, size_t wire_len);
/* Reconcile only the matching pending id; caller decides timing/backoff.
 * retry_count is bounded and must never control permanent enablement. */
enum app_host_result db_app_host_intent_reconcile(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation, const uint8_t pending_id[32],
    int64_t due_at, uint32_t retry_count);
/* A failed attempt keeps the exact pending post for a later retry. A NULL id
 * requires no pending post and supports failure before first reservation. */
enum app_host_result db_app_host_intent_defer(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation, const uint8_t pending_id[32],
    int64_t due_at, uint32_t retry_count);
/* Atomically replace a pending post after the coordinator has authoritatively
 * established that its exact ID is absent from the board (or cannot still be
 * live). Unknown/unreadable board state is not absence. Within the same
 * slot this consumes its replacement budget; a later current slot starts a
 * new budget. This model cannot prove absence. */
enum app_host_result db_app_host_intent_replace_absent(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation, const uint8_t old_pending_id[32], int64_t now,
    const char *endpoint, const uint8_t *wire, size_t wire_len);
/* Expiry is computed from the retained signed post and supplied wall time;
 * the old slot and replacement budget remain durable. */
enum app_host_result db_app_host_intent_retire_expired(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation, const uint8_t pending_id[32], int64_t now);
enum app_host_result db_app_host_intent_disable(struct node_db *db,
    const uint8_t local_host[32], const char *carrier_root,
    int64_t expected_generation);
#endif
