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
struct wallet_cutover_binding;
struct node_db;
struct wallet_sqlite;
struct wallet;
struct consensus_state_bundle_manifest;
struct consensus_state_install_runtime_result;
struct wallet_history_capability;
struct boot_bound_bundle_observation;
struct consensus_state_artifact_evidence;
struct bound_history_preflight;
enum bound_history_header_error {
    BOUND_HISTORY_HEADER_INVALID = -1, BOUND_HISTORY_HEADER_UNAVAILABLE = -2,
    BOUND_HISTORY_HEADER_CORRUPT = -3, BOUND_HISTORY_HEADER_CANCELLED = -5
};
/* On refusal, out is unchanged. Object, artifact and capability remain held. */
struct zcl_result bound_history_preflight_read_header(struct bound_history_preflight *p,
    int32_t height, const uint8_t hash[32], struct block_header *out);
struct zcl_result bound_history_preflight_open(struct bound_history_preflight **out,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, int32_t old_height, const uint8_t old_hash[32]);
struct zcl_result bound_history_preflight_recheck(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, const struct block_index *staged_old_tip);
struct zcl_result bound_history_preflight_prepare(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, struct main_state *ms);
/* Borrowed handoff: caller retains p, its original evidence and its leased
 * history capability until return, then closes p exactly once. */
struct zcl_result bound_history_preflight_install(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, struct consensus_state_install_runtime_result *out);
#ifdef ZCL_TESTING
void bound_history_preflight_test_reset_archive_opens(void);
unsigned bound_history_preflight_test_archive_opens(void);
#endif
struct icb_terminal_context *bound_history_preflight_terminal(struct bound_history_preflight *p);
struct zcl_result bound_history_preflight_install_old_retry(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out);
void bound_history_preflight_close(struct bound_history_preflight **p);
struct icb_terminal_context {
    struct bound_history_preflight *preflight_owner;
    struct main_state *archive;
    struct block_index *bridge_window[ISLAND_ANCHOR_WINDOW];
    uintptr_t history_handle;
    bool history_open;
    bool prepared;
    const struct wallet_history_capability *history_capability;
    const struct boot_bound_bundle_observation *observation;
    struct block_header window[ISLAND_ANCHOR_WINDOW];
};
bool icb_terminal_archive_has_frontier(const struct icb_terminal_context *terminal,
    const struct block_index *old_tip);
bool icb_terminal_link_window(struct icb_terminal_context *terminal,
    struct block_index *top, struct block_index *old_tip);
#ifdef ZCL_TESTING
struct zcl_result icb_terminal_select_window_test(struct icb_terminal_context *,
    struct main_state *, const struct consensus_state_bundle_manifest *);
#endif
void icb_terminal_unlink_window(struct icb_terminal_context *terminal);
struct zcl_result icb_terminal_prepare(struct icb_terminal_context *terminal,
    const char *datadir, struct main_state *ms,
    const struct consensus_state_bundle_manifest *manifest);
struct zcl_result icb_install_wallet_guarded(struct node_db *ndb, struct main_state *ms,
    const char *bundle_path, const char *datadir, struct wallet_sqlite *ws,
    struct wallet *wallet, const uint8_t *whole, const uint8_t *logical,
    struct icb_terminal_context *terminal,
    struct consensus_state_install_runtime_result *out);
struct zcl_result icb_install_wallet_old_retry(struct node_db *ndb, struct main_state *ms,
    const char *bundle_path, const char *datadir, struct wallet_sqlite *ws,
    struct wallet *wallet, const struct wallet_cutover_binding *expected,
    struct icb_terminal_context *terminal, const uint8_t *whole, const uint8_t *logical,
    struct consensus_state_install_runtime_result *out);
#endif
