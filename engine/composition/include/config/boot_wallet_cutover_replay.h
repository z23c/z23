/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: startup coordination of checkpoint wallet replay phases. */
#ifndef Z23_BOOT_WALLET_CUTOVER_REPLAY_H
#define Z23_BOOT_WALLET_CUTOVER_REPLAY_H
#include <stdint.h>
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "controllers/wallet_rescan_controller.h"
struct db_service;
struct wallet_rpc_context;
struct main_state;
struct transparent_replay_filter;
enum boot_cutover_replay_phase {
    BOOT_CUTOVER_TRANSPARENT, BOOT_CUTOVER_DISCOVER,
    BOOT_CUTOVER_WITNESS, BOOT_CUTOVER_SPENDS, BOOT_CUTOVER_DONE,
    BOOT_CUTOVER_INVALIDATED
};
enum boot_cutover_replay_status {
    BOOT_CUTOVER_PROGRESS, BOOT_CUTOVER_COMPLETE, BOOT_CUTOVER_RETRY,
    BOOT_CUTOVER_STALE, BOOT_CUTOVER_INVALID, BOOT_CUTOVER_BUSY
};
/* Caller serializes calls and keeps chain mutation quiescent from initialization
 * through final publication. State is not durable authority or readiness. */
struct boot_cutover_replay {
    struct wallet_rpc_context *ctx;
    struct db_service *service;
    struct transparent_replay_filter *transparent_filter;
    bool transparent_filter_attempted;
    bool sapling_load_ok;
    bool shielded_empty;
    bool full_empty;
    bool pending_complete;
    bool checkpoint_resume;
    int pending_end;
    int64_t auth_deadline_ms;  /* Zero when startup authentication was not required. */
    struct main_state *canonical_state;
    char archive_datadir[4096];
    struct wallet_cutover_binding binding;
    struct wallet_readiness readiness;
    struct wallet_witness_endpoint endpoint;
    enum boot_cutover_replay_phase phase;
    int floor, next;
    uint8_t identity[32], key_digest[32];
};
bool boot_cutover_replay_init(struct boot_cutover_replay *replay,
    struct wallet_rpc_context *ctx, struct db_service *service,
    const struct wallet_cutover_binding *binding, int floor,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32]);
/* Caller authenticates and holds the immutable archive and both chain views
 * quiescent through publication. Wallet and database remain in ctx. */
bool boot_cutover_replay_init_archive(struct boot_cutover_replay *replay,
    struct wallet_rpc_context *ctx, struct db_service *service,
    const struct wallet_cutover_binding *binding, int floor,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32],
    struct main_state *canonical_state, const char *archive_datadir);

/* Only a checked empty wallet may complete without historical bodies. */
bool boot_cutover_replay_complete_full_empty(struct boot_cutover_replay *replay);

/* Clear after every successful or partially run init, and before reinitializing. */
void boot_cutover_replay_clear(struct boot_cutover_replay *replay);

/* Caller must hold both distinct chain locks. */
bool boot_cutover_replay_archive_chains_current(const struct boot_cutover_replay *replay);
/* Caller holds chain, wallet, keystore and Sapling locks. */
bool boot_cutover_replay_current_locked(const struct boot_cutover_replay *replay);
/* A stale result invalidates all phases; caller must reload before retrying. */
enum boot_cutover_replay_status boot_cutover_replay_step(struct boot_cutover_replay *replay);
#endif
