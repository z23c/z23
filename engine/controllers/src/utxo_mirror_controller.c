/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handler for `ops.recovery.utxo_mirror`: the operator repair for the
 * node.db `utxos` projection. It rebuilds the mirror wholesale from one
 * coins_kv snapshot, verifies the staged rows against that snapshot's SHA3
 * commitment, and commits only on a match (clearing a sticky quarantine).
 * It never writes coins_kv. Parse -> authorize (registry, OPERATOR) -> call
 * one service -> render. */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "json/json.h"
#include "services/utxo_mirror_sync_service.h"

void zcl_native_handle_utxo_mirror_rebuild(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    if (!svc) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "MIRROR_ABSENT",
                               "handle", false, false,
                               "the utxo mirror service is not running", "");
        return;
    }
    int64_t rows = utxo_mirror_rebuild_now(svc);
    if (rows < 0) {
        const char *code = rows == UTXO_MIRROR_REBUILD_VERIFY_MISMATCH
                               ? "VERIFY_MISMATCH"
                               : rows == UTXO_MIRROR_REBUILD_STOPPED
                                     ? "STOPPED" : "REBUILD_FAILED";
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, code, "handle",
                               false, false,
                               "the rebuild rolled back; the previous mirror "
                               "is unchanged", code);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_int(&reply->data, "rows_written", rows);
    (void)json_push_kv_int(&reply->data, "mirror_height",
                           atomic_load(&svc->last_mirror_height));
    (void)json_push_kv_bool(&reply->data, "quarantined",
                            atomic_load(&svc->mirror_health) ==
                                UTXO_MIRROR_QUARANTINED);
}
