/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Define the node's consent-bound recurring app-host coordinator. */
#ifndef ZCL_BOOT_APP_HOST_H
#define ZCL_BOOT_APP_HOST_H
#include "vcs/app_offer.h"
#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct vcs_package_store;
struct boot_app_host_plan {
    struct zcl_app_offer offer;
    const char *post_id, *post_host, *receive_plan, *datadir, *token;
    const char *expected_plan;
};
enum boot_app_host_result {
    BOOT_APP_HOST_OK, BOOT_APP_HOST_INVALID, BOOT_APP_HOST_UNAVAILABLE,
    BOOT_APP_HOST_STALE, BOOT_APP_HOST_BUSY, BOOT_APP_HOST_STORAGE
};
enum boot_app_host_result boot_app_host_enable(
    struct node_db *db, struct vcs_package_store *store,
    const struct boot_app_host_plan *plan, int64_t now,
    uint8_t local_host_out[32], int64_t *generation_out);
enum boot_app_host_result boot_app_host_tick(
    struct node_db *db, struct vcs_package_store *store, int64_t now);
enum boot_app_host_result boot_app_host_stop(
    struct node_db *db, const uint8_t local_host[32], const char *carrier,
    int64_t expected_generation);

/* Recheck an exact pinned carrier and its signed original release. The
 * returned generation must be rechecked before authorizing publication. */
bool boot_app_host_verify_carrier(struct vcs_package_store *store,
                                  const struct zcl_app_offer *offer,
                                  uint64_t *generation);
bool boot_app_host_endpoint(char host[static 63],
                            char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u]);

#ifdef ZCL_TESTING
struct fleet_board_post;
struct db_fleet_board_post;
struct boot_app_host_test_hooks {
    void *context;
    bool (*identity)(void *context, uint8_t host[32], bool create);
    bool (*datadir)(void *context, const char *datadir);
    bool (*endpoint)(void *context, char host[63], char endpoint[ZCL_APP_OFFER_ONION_MAX + 1u]);
    bool (*sign)(void *context, struct fleet_board_post *post);
    void (*announce)(void *context, const uint8_t id[32]);
    void (*before_guard)(void *context);
    bool (*after_ingest)(void *context, const uint8_t id[32]);
    int (*lookup)(void *context, struct node_db *db, const uint8_t id[32],
                  struct db_fleet_board_post *out);
};
void boot_app_host_set_test_hooks(const struct boot_app_host_test_hooks *hooks);
#endif
#endif
