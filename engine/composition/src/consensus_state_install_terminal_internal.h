/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal terminal preparation context and guarded install bridge. */
#ifndef ZCL_CONSENSUS_STATE_INSTALL_TERMINAL_INTERNAL_H
#define ZCL_CONSENSUS_STATE_INSTALL_TERMINAL_INTERNAL_H
#include "primitives/block.h"
#include "services/island_anchor.h"
#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>
struct main_state;
struct node_db;
struct wallet_sqlite;
struct wallet;
struct consensus_state_bundle_manifest;
struct consensus_state_install_runtime_result;
struct icb_terminal_context {
    struct main_state *archive;
    uintptr_t history_handle;
    bool history_open;
    bool prepared;
    struct block_header window[ISLAND_ANCHOR_WINDOW];
};
struct zcl_result icb_terminal_prepare(struct icb_terminal_context *terminal,
    const char *datadir, struct main_state *ms,
    const struct consensus_state_bundle_manifest *manifest);
struct zcl_result icb_install_wallet_guarded(struct node_db *ndb, struct main_state *ms,
    const char *bundle_path, const char *datadir, struct wallet_sqlite *ws,
    struct wallet *wallet, struct icb_terminal_context *terminal,
    struct consensus_state_install_runtime_result *out);
#endif
