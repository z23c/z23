/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare immutable history production and serving admission. */
#ifndef ZCL_CONFIG_WALLET_HISTORY_PROVIDER_H
#define ZCL_CONFIG_WALLET_HISTORY_PROVIDER_H
#include "net/file_service_generation.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct main_state;
struct boot_svc_ctx;
struct wallet_history_provider_budget {
    const char *private_parent;
    size_t max_rows;
    uint64_t max_bytes, min_free_bytes;
};
enum wallet_history_provider_config_result {
    WALLET_HISTORY_PROVIDER_DISABLED,
    WALLET_HISTORY_PROVIDER_CONFIGURED,
    WALLET_HISTORY_PROVIDER_INVALID,
};
enum wallet_history_provider_config_result wallet_history_provider_parse_budget(
    const char *parent, const char *rows, const char *bytes, const char *free_bytes,
    struct wallet_history_provider_budget *out);
enum wallet_history_provider_config_result wallet_history_provider_read_budget(
    struct wallet_history_provider_budget *out);
struct wallet_history_provider_request {
    struct main_state *main;
    const char *source_datadir, *private_parent, *staging_leaf, *destination_leaf;
    const char *snapshot_path;
    uint8_t snapshot_digest[32], endpoint_hash[32];
    int32_t endpoint_height;
    size_t max_rows;
    uint64_t max_bytes, min_free_bytes;
    bool (*cancelled)(void *context);
    void *cancel_context;
};
/* Caller initializes out, owns typed storage/capacity admission and output.
 * Refusal leaves exporter evidence in place. Success returns one owned generation. */
bool wallet_history_provider_prepare(const struct wallet_history_provider_request *request,
                                     struct fs_history_generation *out);
bool wallet_history_provider_recheck(const struct wallet_history_provider_request *request);
/* Called on an existing joined worker, never on a frontend startup thread. */
bool wallet_history_provider_prepare_and_start(
    const struct wallet_history_provider_request *request,
    uint16_t port, const char *bind_address);
bool wallet_history_provider_run_selected(struct main_state *main,
    const char *datadir, const struct wallet_history_provider_budget *budget,
    uint16_t port, const char *bind_address);
bool wallet_history_provider_offer_allowed(const uint8_t digest[32],
                                           int32_t height, const uint8_t hash[32]);
void wallet_history_provider_boot(struct boot_svc_ctx *svc, int64_t *checkpoint,
                                  void (*beat)(int64_t *));
#ifdef ZCL_TESTING
bool wallet_history_provider_served_covers_for_test(int32_t served, int32_t requested);
#endif
#endif
