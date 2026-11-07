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
    struct coins_view_kv *coins_view;
    struct coins_view_cache *coins_tip;
    struct coins_view_sqlite *coins_sqlite;
    struct block_tree_db *block_tree;
    bool *block_tree_open;
    struct db_service *db_service;
    bool (*gate_index)(struct app_context *ctx, bool replay_pending);
    void (*build_svc)(struct app_context *ctx, struct boot_svc_ctx *svc);
};
bool boot_cutover_preflight(struct boot_cutover_env *env, const char *datadir, bool *pending);
bool boot_cutover_load_chain(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip);
bool boot_cutover_replay(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params);
bool boot_cutover_publish_readiness(struct boot_cutover_env *env, struct app_context *ctx);
bool boot_cutover_mode_supported(const struct app_context *ctx);
struct zcl_result boot_sandbox_enter(const struct app_context *ctx, const char *fallback_datadir);
#endif
