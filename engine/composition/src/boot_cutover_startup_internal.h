/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Borrowed boot resources for pending wallet startup. */
#ifndef Z23_BOOT_CUTOVER_STARTUP_INTERNAL_H
#define Z23_BOOT_CUTOVER_STARTUP_INTERNAL_H
#include "base/result.h"
#include <stdbool.h>
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
bool boot_cutover_retry_old(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding);
bool boot_cutover_verify_committed(struct boot_cutover_env *env, const char *datadir,
    const struct wallet_cutover_binding *expected);
bool boot_cutover_verify_committed_stop(struct boot_cutover_env *env, const char *datadir,
    const struct wallet_cutover_binding *expected);
bool boot_cutover_load_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip);
bool boot_cutover_load_old_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding,
    struct block_index **tip);
enum boot_pending_replay_result { BOOT_PENDING_FAILED, BOOT_PENDING_STOPPED, BOOT_PENDING_COMPLETE };
enum boot_busy_result { BOOT_BUSY_RETRY, BOOT_BUSY_STOPPED, BOOT_BUSY_FAILED };
enum boot_pending_replay_result boot_cutover_replay(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params);
#ifdef ZCL_TESTING
struct boot_cutover_replay;
bool boot_test_pending_publish(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct boot_cutover_replay *replay);
#endif
bool boot_cutover_publish_readiness(struct boot_cutover_env *env, struct app_context *ctx);
bool boot_cutover_mode_supported(const struct app_context *ctx);
struct zcl_result boot_sandbox_enter(const struct app_context *ctx, const char *fallback_datadir);
#endif
