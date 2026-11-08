/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Borrowed boot resources for pending wallet startup. */
#ifndef Z23_BOOT_CUTOVER_STARTUP_INTERNAL_H
#define Z23_BOOT_CUTOVER_STARTUP_INTERNAL_H
#include "base/result.h"
#include <stdbool.h>
#include <stddef.h>
struct app_context;
struct boot_svc_ctx;
struct main_state;
struct node_db;
struct wallet;
struct wallet_sqlite;
struct coins_view_kv;
struct coins_view_cache;
struct coins_view_sqlite;
struct block_tree_db;
struct db_service;
struct chain_params;
struct block_index;
struct wallet_cutover_binding;
struct consensus_state_publication_decision_record;
struct consensus_state_bundle_manifest;
struct sqlite3;
bool boot_cutover_journal_durable(struct sqlite3 *db);
bool boot_cutover_set_sync(struct node_db *node, int level);
bool boot_cutover_raise_sync(struct node_db *node, int previous);
bool icb_wallet_old_authority_locked(struct sqlite3 *db,
    const struct consensus_state_publication_decision_record *decision,
    struct wallet_cutover_binding *binding);
bool boot_bound_wallet_fence(struct node_db *node, struct main_state *main,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest,
    const unsigned char whole[32], const unsigned char history_root[32],
    struct wallet_cutover_binding *binding);
struct boot_old_height_entry;
/* Caller preallocates entries and holds main-chain, progress and wallet locks
 * through prepare, callbacks and commit, with a validated complete active map. */
struct boot_old_height_map {
    struct main_state *main;
    struct block_index *tip;
    struct block_index *frontier;
    struct boot_old_height_entry *entries;
    size_t count;
    int reference_height;
    unsigned char reference_hash[32];
    bool ready;
};
bool boot_old_height_allocate(struct boot_old_height_map *map);
bool boot_old_height_prepare_locked(struct boot_old_height_map *map,
    struct main_state *main, const struct wallet *wallet, const struct wallet_cutover_binding *binding);
bool boot_old_height_resolve(void *opaque, const unsigned char hash[32], int *height);
bool boot_old_height_reference(void *opaque, int height, const unsigned char hash[32]);
void boot_old_height_free(struct boot_old_height_map *map);
struct boot_cutover_env {
    struct main_state *state;
    struct node_db *node;
    struct wallet *wallet;
    struct wallet_sqlite *wallet_db;
    bool sapling_load_ok;
    struct coins_view_kv *coins_view;
    struct coins_view_cache *coins_tip;
    struct coins_view_sqlite *coins_sqlite;
    struct block_tree_db *block_tree;
    bool *block_tree_open;
    struct db_service *db_service;
    bool (*gate_index)(struct app_context *ctx, bool replay_pending);
    void (*build_svc)(struct app_context *ctx, struct boot_svc_ctx *svc);
};
enum boot_cutover_preflight_kind { BOOT_CUTOVER_NONE, BOOT_CUTOVER_COMMITTED, BOOT_CUTOVER_OLD_RETRY };
struct wallet_cutover_binding;
bool boot_cutover_preflight_classify(struct boot_cutover_env *env, const char *datadir,
    enum boot_cutover_preflight_kind *kind, struct wallet_cutover_binding *binding);
bool boot_cutover_preflight(struct boot_cutover_env *env, const char *datadir, bool *pending);
bool boot_bound_old_cold_retry(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding);
bool boot_cutover_retry_old(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding);
bool boot_cutover_verify_committed(struct boot_cutover_env *env, const char *datadir,
    const struct wallet_cutover_binding *expected);
bool boot_cutover_verify_committed_stop(struct boot_cutover_env *env, const char *datadir,
    const struct wallet_cutover_binding *expected);
bool boot_cutover_load_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip);
bool boot_cutover_load_completed_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, const struct wallet_cutover_binding *binding);
bool boot_cutover_load_old_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding,
    struct block_index **tip);
enum boot_pending_replay_result { BOOT_PENDING_FAILED, BOOT_PENDING_STOPPED, BOOT_PENDING_COMPLETE };
/* Caller passes an initialized empty capability and retains it on COMPLETE.
 * The request is compared before and after acquisition, including attempts.
 * The caller must still recheck the request at any later mutation boundary. */
struct chain_activation_controller;
struct boot_bound_bundle_observation;
struct wallet_history_capability;
enum boot_pending_replay_result boot_bound_history_acquire_observed(const char *datadir,
    const struct boot_bound_bundle_observation *expected, bool allow_terminal,
    struct wallet_history_capability *capability);
#ifdef ZCL_TESTING
void boot_bound_history_test_after_acquire(void (*hook)(const char *, void *), void *context);
#endif
enum boot_busy_result { BOOT_BUSY_RETRY, BOOT_BUSY_STOPPED, BOOT_BUSY_FAILED };
enum boot_pending_replay_result boot_cutover_replay(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params);
enum boot_pending_replay_result boot_cutover_replay_and_retire(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params, const struct wallet_cutover_binding *binding);
#ifdef ZCL_TESTING
struct boot_cutover_replay;
bool boot_test_pending_publish(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct boot_cutover_replay *replay);
#endif
#ifdef ZCL_TESTING
void boot_test_completed_before_proof(void (*hook)(struct boot_cutover_env *, struct app_context *, void *), void *context);
void boot_test_run_completed_before_proof(struct boot_cutover_env *env, struct app_context *ctx);
#endif
bool boot_bound_observation_equal(const struct boot_bound_bundle_observation *a,
    const struct boot_bound_bundle_observation *b);
bool boot_bound_request_matches_completed(const struct boot_bound_bundle_observation *request,
    const struct wallet_cutover_binding *binding);
bool boot_cutover_publish_completed(struct boot_cutover_env *env, struct app_context *ctx, bool required);
bool boot_cutover_publish_readiness(struct boot_cutover_env *env, struct app_context *ctx);
enum boot_bound_fresh_result { BOOT_BOUND_FRESH_FAILED, BOOT_BOUND_FRESH_STOPPED, BOOT_BOUND_FRESH_INSTALLED };
enum boot_bound_dispatch_result { BOOT_BOUND_DISPATCH_UNARMED, BOOT_BOUND_DISPATCH_FAILED,
    BOOT_BOUND_DISPATCH_INSTALLED, BOOT_BOUND_DISPATCH_COMPLETED };
enum boot_bound_dispatch_result boot_bound_dispatch(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, struct wallet_cutover_binding *binding,
    struct chain_activation_controller *activation);
bool boot_bound_memory_bind(struct boot_cutover_env *env);
bool boot_cutover_mode_supported(const struct app_context *ctx);
struct zcl_result boot_sandbox_enter(const struct app_context *ctx, const char *fallback_datadir);
#endif
