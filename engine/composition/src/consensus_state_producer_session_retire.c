/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Offline operator retirement of a foreign producer start session. */

#include "config/consensus_state_producer_receipt.h"
#include "consensus_state_producer_receipt_internal.h"

#include "base/hex.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* Audit key: the binary digest of the last session this operator retired, so
 * the act stays attributable in progress.kv after the row is gone. */
static const char k_retired_binary_meta_key[] =
    "consensus_state.producer_session_retired_binary_digest";

static bool set_err(char *err, size_t err_size, const char *msg)
{
    if (err && err_size)
        snprintf(err, err_size, "%s", msg);
    return false; /* raw-return-ok:bounded policy reason returned to caller */
}

static bool exec_checked(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    if (error) {
        LOG_WARN(PRODUCER_RECEIPT_SUBSYS, "exec failed: %s", error);
        sqlite3_free(error);
    }
    return ok;
}

enum consensus_state_producer_session_retire_result
consensus_state_producer_session_retire(
    sqlite3 *pdb, struct consensus_state_producer_session_retired *out,
    char *err, size_t err_size)
{
    if (err && err_size)
        err[0] = '\0';
    if (out) {
        memset(out, 0, sizeof(*out));
        out->validation_profile = -1;
    }
    if (!pdb) {
        set_err(err, err_size, "producer session retire: NULL store");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }

    uint8_t running_binary[32];
    if (!producer_running_binary_digest(running_binary)) {
        set_err(err, err_size, "producer session retire: running executable "
                               "digest failed");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }

    progress_store_tx_lock();
    if (!exec_checked(pdb, "BEGIN IMMEDIATE")) {
        progress_store_tx_unlock();
        set_err(err, err_size,
                "producer session retire: cannot open transaction");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }

    struct producer_session stored;
    if (!producer_session_load(pdb, &stored)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        set_err(err, err_size, "producer session retire: session read failed");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }
    if (!stored.present) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT;
    }

    /* Judge with build identity alone: recompute the current claim at the
     * stored session's profile so a profile difference alone never makes a
     * same-build session look foreign (the profile is not an input to the
     * source-epoch digest). A legacy v1 session never matches (begin() is
     * inspection-only for v1), so retirement is also the v1 escape path. */
    struct consensus_state_source_receipt current;
    uint8_t current_epoch[32];
    if (!producer_current_v2_claim(stored.claim.validation_profile, &current,
                                   current_epoch)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        set_err(err, err_size,
                "producer session retire: build has no exact 64-hex SHA-256 "
                "source identity; an unstamped build cannot judge a session");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }
    if (producer_session_matches_current(&stored, &current, current_epoch,
                                         running_binary)) {
        (void)exec_checked(pdb, "ROLLBACK");
        progress_store_tx_unlock();
        set_err(err, err_size,
                "producer session retire: stored session matches this "
                "running build; nothing to retire");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_CURRENT;
    }

    bool ok = exec_checked(
                  pdb, "DELETE FROM consensus_state_producer_session") &&
              progress_meta_table_ensure(pdb) &&
              progress_meta_set_in_tx(pdb, k_retired_binary_meta_key,
                                      stored.running_binary_digest, 32) &&
              exec_checked(pdb, "COMMIT");
    if (!ok)
        (void)exec_checked(pdb, "ROLLBACK");
    progress_store_tx_unlock();
    if (!ok) {
        set_err(err, err_size,
                "producer session retire: durable retire write failed");
        return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR;
    }

    if (out) {
        zcl_hex_encode(stored.running_binary_digest, 32,
                       out->running_binary_digest);
        zcl_hex_encode(stored.claim.source_tree_root, 32,
                       out->source_tree_root);
        zcl_hex_encode(stored.source_epoch_digest, 32,
                       out->source_epoch_digest);
        out->validation_profile = stored.claim.validation_profile;
        out->started_us = stored.started_us;
    }
    return CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_RETIRED;
}
