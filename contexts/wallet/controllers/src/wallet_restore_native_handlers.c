/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for the two OFFLINE wallet-recovery leaves —
 * `core.wallet.restore` and `core.wallet.backup.decrypt`.
 *
 * These are the odd ones out in the wallet command surface: every other
 * wallet leaf proxies a JSON-RPC call to a RUNNING node, and these two
 * must work when there is no running node at all. That is the whole point.
 * A user restoring onto a rebuilt machine has a backup file and an empty
 * datadir; asking them to start a node first would ask them to boot the
 * very wallet they are trying to put back. So both handlers call the
 * service directly, in-process, and `core.wallet.restore` REFUSES if a
 * node is holding the target datadir (the pidfile flock is the
 * single-writer lock — see docs/WALLET_PERSISTENCE_RECOVERY.md).
 *
 * Both carry ZCL_COMMAND_CONFIRM_PLAN_COMMIT, and the plan half is not
 * cosmetic:
 *   - restore's plan runs the FULL merge inside a transaction and rolls it
 *     back, so the counts it shows are exactly what the commit will do;
 *   - decrypt's plan names the plaintext file it would write without
 *     writing it, because that file contains every private key in the
 *     clear.
 *
 * Bound in engine/composition/commands/core.def.
 */

#include "controllers/wallet_native_handlers.h"

#include "controllers/agent_controller.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "rpc/rpc_timeout.h"
#include "services/wallet_backup_service.h"
#include "services/wallet_restore_service.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WRN_TAG "native.wallet.restore"


/* Deterministic non-secret token binding a plan preview to its parameters,
 * mirroring wnh_plan_token in wallet_native_handlers.c. */
static void wrn_plan_token(char out[17], const char *a, const char *b)
{
    uint64_t h = 1469598103934665603ULL;
    const char *parts[2] = { a, b };
    for (int i = 0; i < 2; i++) {
        for (const char *p = parts[i]; p && *p; p++) {
            h ^= (unsigned char)*p;
            h *= 1099511628211ULL;
        }
        h ^= 0x1f;
        h *= 1099511628211ULL;
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* The datadir a restore targets when the caller names none: the runtime's
 * own context datadir, else the stock $HOME/.zclassic-c23. Always echoed
 * back in the plan so the operator confirms the path before the commit. */
static void wrn_default_datadir(char *out, size_t cap)
{
    const char *ctx = agent_runtime_context_datadir();
    if (ctx && ctx[0]) {
        snprintf(out, cap, "%s", ctx);
        return;
    }
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.zclassic-c23", home && home[0] ? home : ".");
}

/* One per-table row of the restore report. */
static void wrn_push_table(struct json_value *arr,
                           const struct wallet_restore_table_report *t)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "table", t->table);
    (void)json_push_kv_bool(&row, "in_backup", t->in_backup);
    (void)json_push_kv_int(&row, "rows_in_backup", t->rows_in_backup);
    (void)json_push_kv_int(&row, "manifest_row_count", t->manifest_row_count);
    (void)json_push_kv_int(&row, "rows_before", t->rows_before);
    (void)json_push_kv_int(&row, "rows_inserted", t->rows_inserted);
    (void)json_push_kv_int(&row, "rows_collided", t->rows_collided);
    (void)json_push_kv_int(&row, "rows_rejected", t->rows_rejected);
    (void)json_push_kv_int(&row, "rows_after", t->rows_after);
    (void)json_push_back(arr, &row);
    json_free(&row);
}

/* Render a completed report (dry run or committed) onto the reply. */
static void wrn_push_report(struct zcl_command_reply *reply,
                            const struct wallet_restore_report *rep)
{
    (void)json_push_kv_str(&reply->data, "backup_path", rep->backup_path);
    (void)json_push_kv_str(&reply->data, "target_db", rep->target_db);
    (void)json_push_kv_bool(&reply->data, "dry_run", rep->dry_run);
    (void)json_push_kv_bool(&reply->data, "source_was_encrypted",
                            rep->source_was_encrypted);
    (void)json_push_kv_bool(&reply->data, "target_created",
                            rep->target_created);
    (void)json_push_kv_str(&reply->data, "collision_policy", "keep-existing");
    (void)json_push_kv_int(&reply->data, "tables_in_backup",
                           rep->tables_in_backup);
    (void)json_push_kv_int(&reply->data, "total_rows_in_backup",
                           rep->total_rows_in_backup);
    (void)json_push_kv_int(&reply->data, "total_inserted",
                           rep->total_inserted);
    (void)json_push_kv_int(&reply->data, "total_collided",
                           rep->total_collided);
    (void)json_push_kv_int(&reply->data, "total_rejected",
                           rep->total_rejected);
    (void)json_push_kv_int(&reply->data, "manifest_mismatches",
                           rep->manifest_mismatches);
    (void)json_push_kv_str(&reply->data, "warnings",
                           rep->warnings[0] ? rep->warnings : "none");

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < rep->n_tables; i++)
        wrn_push_table(&arr, &rep->tables[i]);
    (void)json_push_kv(&reply->data, "tables", &arr);
    json_free(&arr);
}

void zcl_native_handle_wallet_restore(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *from = json_get_str(json_get(request->input, "from"));
    if (!from || !from[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_FROM",
                 "from is required: the path of the backup file to restore",
                 "core.wallet.restore");
        return;
    }
    char datadir[1024];
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && dd[0])
        snprintf(datadir, sizeof(datadir), "%s", dd);
    else
        wrn_default_datadir(datadir, sizeof(datadir));

    const char *password = json_get_str(json_get(request->input, "password"));
    bool confirm = json_get_bool_or(request->input, "confirm", false);

    char token[17];
    wrn_plan_token(token, from, datadir);

    struct wallet_restore_request req = {
        .backup_path = from,
        .datadir     = datadir,
        .password    = password,
        .dry_run     = !confirm,
    };
    struct wallet_restore_report rep;
    struct zcl_result r = wallet_restore_run(&req, &rep);

    if (!r.ok) {
        /* A refusal still reports what it learned about the file, so the
         * operator's next move is informed rather than guessed. */
        bool blocked = r.code == -34;   /* datadir held by a running node */
        wrn_push_report(reply, &rep);
        wnh_fail(reply,
                 blocked ? ZCL_COMMAND_EXIT_BLOCKED : ZCL_COMMAND_EXIT_FAILED,
                 blocked ? "DATADIR_LOCKED" : "RESTORE_REFUSED",
                 r.message, from);
        return;
    }

    wrn_push_report(reply, &rep);
    (void)json_push_kv_str(
        &reply->data, "next_steps",
        "run 'core wallet rescan' to rebuild transparent history, then "
        "'core wallet rescan-witnesses' before spending a shielded note");

    if (!confirm) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "from", from);
        (void)json_push_kv_str(&ci, "datadir", datadir);
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[640];
        size_t n = json_write(&ci, commit, sizeof(commit));
        if (n == 0 || n >= sizeof(commit))
            (void)snprintf(commit, sizeof(commit), "{\"confirm\":true}");
        json_free(&ci);
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", "restore");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_str(&reply->data, "plan_token", token);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "the counts above are a rehearsal that was rolled back; re-run "
            "this command with commit_input to write them");
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        reply->error.mutated = false;
        return;
    }

    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
}

void zcl_native_handle_wallet_backup_decrypt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *from = json_get_str(json_get(request->input, "from"));
    const char *to = json_get_str(json_get(request->input, "to"));
    if (!from || !from[0] || !to || !to[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                 "both from (encrypted backup) and to (output file) are "
                 "required", "core.wallet.backup.decrypt");
        return;
    }
    const char *password = json_get_str(json_get(request->input, "password"));
    if (!password || !password[0])
        password = getenv("WALLET_BACKUP_PASSWORD");
    bool confirm = json_get_bool_or(request->input, "confirm", false);

    char token[17];
    wrn_plan_token(token, from, to);

    if (!confirm) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "from", from);
        (void)json_push_kv_str(&ci, "to", to);
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[640];
        size_t n = json_write(&ci, commit, sizeof(commit));
        if (n == 0 || n >= sizeof(commit))
            (void)snprintf(commit, sizeof(commit), "{\"confirm\":true}");
        json_free(&ci);
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", "backup-decrypt");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_str(&reply->data, "from", from);
        (void)json_push_kv_str(&reply->data, "to", to);
        (void)json_push_kv_bool(&reply->data, "password_available",
                                password && password[0]);
        (void)json_push_kv_str(
            &reply->data, "warning",
            "commit writes every wallet key to this path in the clear");
        (void)json_push_kv_str(&reply->data, "plan_token", token);
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        reply->error.mutated = false;
        return;
    }

    if (!password || !password[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PASSWORD",
                 "set WALLET_BACKUP_PASSWORD or pass password: the backup is "
                 "encrypted under it", from);
        return;
    }

    struct zcl_result r = wallet_backup_decrypt_file(from, to, password);
    if (!r.ok) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "DECRYPT_FAILED", r.message,
                 from);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "from", from);
    (void)json_push_kv_str(&reply->data, "to", to);
    (void)json_push_kv_bool(&reply->data, "decrypted", true);
    (void)json_push_kv_str(
        &reply->data, "next_steps",
        "restore it with 'core wallet restore --from=<to>'; the file holds "
        "every private key in the clear until you delete it");
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
}

/* ── Rescan family ──────────────────────────────────────────────────────
 * Moved here 2026-07-29 from wallet_native_handlers.c, which crossed its
 * 800-line ceiling when the restore and store lanes landed together. This
 * file already owns wallet recovery (restore, backup decrypt), and a rescan
 * is the step that makes a restored wallet usable, so the family belongs
 * together. wnh_fail/wnh_call_rpc moved to the shared header rather than
 * being copied — wrn_fail was already a byte-for-byte duplicate of wnh_fail
 * and is now deleted rather than joined by a third copy. */
void zcl_native_handle_wallet_rescan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *sh = json_get(request->input, "start_height");
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    if (sh && sh->type == JSON_INT) {
        if (json_get_int(sh) < 0) {
            rpc_arg_builder_free(&p);
            wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_START_HEIGHT",
                     "start_height must be a non-negative integer",
                     "core.wallet.rescan");
            return;
        }
        rpc_arg_builder_push_int(&p, json_get_int(sh));
    }
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode rescanblockchain params",
                 "core.wallet.rescan");
        return;
    }
    struct json_value body;
    bool ok = wnh_call_rpc(reply, "rescanblockchain", params, &body);
    free(params);
    if (!ok)
        return;

    /* The scan is synchronous (see core.def: MODE_JOB is aspirational —
     * rpc_rescanblockchain blocks until the scan completes), so by the time
     * we are here it has FINISHED. Report what it actually covered and
     * found; never an unconditional "started". */
    const struct json_value *cov = json_get(&body, "coverage_ok");
    const struct json_value *blk = json_get(&body, "blocker");
    bool coverage_ok = !cov || cov->type != JSON_BOOL || json_get_bool(cov);

    if (!coverage_ok) {
        /* A rescan that could not read the blocks it was asked to scan is a
         * failure, not a success with a small number in it. Surface the
         * counts alongside the typed name so an agent can act without a
         * second call. */
        const char *code = (blk && blk->type == JSON_STR)
                             ? json_get_str(blk) : "RESCAN_INCOMPLETE_COVERAGE";
        char msg[384];
        const struct json_value *scanned = json_get(&body, "blocks_scanned");
        const struct json_value *indexed = json_get(&body, "blocks_indexed");
        const struct json_value *missing = json_get(&body, "blocks_missing_data");
        snprintf(msg, sizeof(msg),
                 "rescan read %lld of %lld indexed blocks (%lld have no block "
                 "body on this node); the result does NOT mean the wallet is "
                 "empty — this node cannot see those blocks' transactions",
                 scanned ? (long long)json_get_int(scanned) : 0LL,
                 indexed ? (long long)json_get_int(indexed) : 0LL,
                 missing ? (long long)json_get_int(missing) : 0LL);
        (void)json_push_kv(&reply->data, "result", &body);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, msg,
                 "core.wallet.rescan");
        /* AFTER wnh_fail: zcl_command_reply_fail() overwrites `mutated`.
         * A failed rescan still wrote — it advanced best_block_height and
         * folded in whatever the blocks it COULD read contained. */
        reply->error.mutated = true;
        json_free(&body);
        return;
    }

    (void)json_push_kv(&reply->data, "result", &body);
    (void)json_push_kv_bool(&reply->data, "completed", true);
    reply->error.mutated = true;
    json_free(&body);
}

/* core.wallet.rescan-witnesses — rebuild the Sapling Merkle witnesses for
 * every unspent note (rpc_rescanwitnesses, engine/controllers/src/
 * wallet_rescan_controller_witness.c). This existed as an RPC with no typed
 * command and no mention in any document, which made it invisible at the
 * one moment it matters: a restored shielded note has rows but no witness,
 * and a note without a witness cannot be spent. The RPC verifies its final
 * tree root against the block header before saving and refuses to persist a
 * diverged tree, so a failure here is a real answer, not a silent one. */
void zcl_native_handle_wallet_rescan_witnesses(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value body;
    if (!wnh_call_rpc_deadline(reply, "rescanwitnesses", NULL,
                               RPC_PROOF_BUILD_TIMEOUT_MS, &body))
        return;
    /* A legacy RPC actor can refuse with a bare string. The HTTP client
     * extracts the JSON-RPC error value, so that shape is indistinguishable
     * from a successful string unless this object-only command validates its
     * own result contract. Never report completed=true for a refusal. */
    if (body.type != JSON_OBJ) {
        const char *message = body.type == JSON_STR
            ? json_get_str(&body) : NULL;
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "WITNESS_RESCAN_FAILED", "repair", false, false,
            message && message[0]
                ? message : "witness rescan returned an invalid result",
            "fix the named prerequisite, then rerun core wallet rescan-witnesses");
        json_free(&body);
        return;
    }
    (void)json_push_kv(&reply->data, "result", &body);
    (void)json_push_kv_bool(&reply->data, "completed", true);
    reply->error.mutated = true;
    json_free(&body);
}
