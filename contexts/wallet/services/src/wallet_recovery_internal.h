/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared internal primitives for offline wallet creation and recovery. */
#ifndef Z23_WALLET_RECOVERY_INTERNAL_H
#define Z23_WALLET_RECOVERY_INTERNAL_H
#include "services/wallet_recovery_service.h"
#include "services/wallet_restore_service.h"
#include "models/database.h"
#include "wallet/wallet_sqlite.h"
struct wallet;
/* The selected scan floor and its block hash. */
struct wrc_floor { int height; uint8_t hash[32]; };
/* Handles held from writer-lock acquisition through cleanup. */
struct wrc_run {
    struct node_db ndb;
    sqlite3 *ro_db;
    struct wallet_restore_datadir_lock wlock;
    struct wallet_sqlite ws;
    bool have_db, ro_open, have_ws;
};
void wrc_reset(struct wallet_recovery_report *out, const char *datadir);
struct zcl_result wrc_at_rest_gate(const char *passphrase);
struct zcl_result wrc_rebuild_keys(struct wallet *w, struct node_db *chain,
    bool shielded_only, struct wallet_recovery_report *out);
/* A seed row, transparent key, Sapling key or note constitutes a wallet. */
static inline bool wrc_wallet_present(const struct wallet_recovery_report *out)
{
    return out->keys_before > 0 || out->seed_present_before ||
           out->sapling_keys_before > 0 || out->notes_before > 0;
}
struct zcl_result wrc_load_passphrase(const struct wallet_recovery_request *req, bool *loaded);
void wrc_birthday_floor(const char *datadir, struct node_db *ndb, struct wrc_floor *floor);
void wrc_settle_birthday(const struct wallet_recovery_request *req, struct node_db *ndb,
    struct wallet *w, bool seeded, struct wallet_recovery_report *out);
struct zcl_result wrc_check_request(const struct wallet_recovery_request *req);
void wrc_run_release(struct wrc_run *run);
struct zcl_result wrc_phrase_to_addresses(const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out);
struct zcl_result wrc_take_writer_lock(const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *run);
struct zcl_result wrc_open_existing_target_ro(const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *run);
struct zcl_result wrc_read_existing_wallet_facts(struct wallet_recovery_report *out, struct wrc_run *run);
struct zcl_result wrc_swap_to_write_handle(struct wallet_recovery_report *out, struct wrc_run *run);
struct zcl_result wrc_inspect_and_open_target(const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *run, bool *seeded, bool strict_creation);
struct zcl_result wrc_creation_wallet_free_r(sqlite3 *db);
struct zcl_result wrc_creation_no_auxiliary_keys_r(sqlite3 *db);
#endif
