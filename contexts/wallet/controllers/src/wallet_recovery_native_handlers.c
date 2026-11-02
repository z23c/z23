/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for the recovery-phrase leaves —
 * `core.wallet.recovery.status` and `core.wallet.recovery.restore`.
 *
 * Like the two backup-file recovery leaves next door, these run OFFLINE:
 * they call wallet_recovery_service directly, in-process, against a datadir
 * on disk. A user typing their twelve words into a rebuilt machine has no
 * node to talk to yet.
 *
 * `status` is a READ leaf and is held to the read contract by construction:
 * it opens <datadir>/node.db through zcl_native_node_db_open_readonly()
 * (SQLITE_OPEN_READONLY + PRAGMA query_only=ON) and hands the handle to the
 * service, which no longer opens anything. It must never call
 * node_db_open(): that is the datadir BOOT CEREMONY — READWRITE|CREATE,
 * create_schema(), node_db_migrate(), and on a failed quick_check a
 * rename() of the operator's node.db to node.db.corrupt-<ts> followed by a
 * fresh empty one — and `datadir` defaults to the LIVE datadir, so the
 * documented invocation of a read command destroyed the wallet it was
 * asked about. Gated by check-read-leaf-no-boot-ceremony (z23-lint) and
 * proven on disk by tests/harness/src/test_read_leaf_no_datadir_write.c.
 * `restore` is a COMMAND and writes on purpose; it is not held to this.
 *
 * There is deliberately NO leaf that prints an existing wallet's phrase.
 * That is not a gap. The node keeps only the 32-byte seed the words derive,
 * and a seed cannot be turned back into words — so no such command could
 * exist without storing the phrase, and storing the phrase would make one
 * read of node.db the loss of every coin in it. The words are shown once,
 * when the wallet is created, and the help text says so.
 *
 * The phrase never leaves this file's stack: it is read out of the request
 * (or ZCL_RECOVERY_PHRASE), handed to the service, and never pushed onto a
 * reply, into a plan echo, or into a log line. The commit_input a plan
 * hands back deliberately omits it, so the phrase is not sitting in a
 * response body waiting to be pasted into a chat log.
 *
 * Bound in engine/composition/commands/core.def.
 */

#include "controllers/wallet_native_handlers.h"

#include "chain/chainparams.h"
#include "controllers/agent_controller.h"
#include "base/hex.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "models/database.h"                   /* struct node_db (RO shim) */
#include "services/wallet_create_service.h"
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "util/boot_phase.h"

#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define WRP_TAG "native.wallet.recovery"

/* Address encoding reads chain_params_get(), which aborts if nothing ever
 * called chain_params_select(). A one-shot CLI process never boots, so it
 * has to select for itself — the same thing native_offline_query.c does.
 *
 * Guarded on the boot stage, which the unconditional call next door is not:
 * inside a RUNNING node boot has already selected the node's own network,
 * and re-selecting mainnet under a testnet or regtest node would switch the
 * whole process's consensus parameters out from under it. BOOT_STAGE_INIT
 * means no boot happened in this process, so there is no selection to
 * clobber. Mainnet-only, as the offline recovery story targets mainnet
 * datadirs; a testnet datadir needs a network hint this leaf does not
 * accept yet. */
static void wrp_select_chain_params_if_standalone(void)
{
    if (boot_stage_current() == BOOT_STAGE_INIT)
        chain_params_select(CHAIN_MAIN);
}

/* The datadir a recovery targets when the caller names none: the runtime's
 * own context datadir, else the stock $HOME/.zclassic-c23. Always echoed
 * back so the operator confirms the path before the commit. */
static void wrp_default_datadir(char *out, size_t cap)
{
    const char *ctx = agent_runtime_context_datadir();
    if (ctx && ctx[0]) {
        snprintf(out, cap, "%s", ctx);
        return;
    }
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.zclassic-c23", home && home[0] ? home : ".");
}

/* Every public field of a report. Nothing here is secret: addresses are
 * meant to be shown, and the phrase is not in the report at all. */
static void wrp_push_report(struct zcl_command_reply *reply,
                            const struct wallet_recovery_report *rep)
{
    (void)json_push_kv_str(&reply->data, "datadir", rep->datadir);
    (void)json_push_kv_str(&reply->data, "target_db", rep->target_db);
    (void)json_push_kv_int(&reply->data, "keys_before", rep->keys_before);
    (void)json_push_kv_int(&reply->data, "keys_after", rep->keys_after);
    (void)json_push_kv_bool(&reply->data, "wallet_already_present",
                            rep->keys_before > 0 || rep->seed_present_before);
    if (rep->first_address[0])
        (void)json_push_kv_str(&reply->data, "first_address",
                               rep->first_address);
    if (rep->first_shielded_address[0])
        (void)json_push_kv_str(&reply->data, "first_shielded_address",
                               rep->first_shielded_address);
}

/* What kind of seed the target wallet holds, in one word, so a caller never
 * has to infer "locked" from a false. */
static const char *wrp_seed_state_name(enum wallet_seed_state s)
{
    switch (s) {
    case WALLET_SEED_ABSENT:     return "none";
    case WALLET_SEED_PLAINTEXT:  return "present";
    case WALLET_SEED_UNLOCKED:   return "present-encrypted-unlocked";
    case WALLET_SEED_LOCKED:     return "present-encrypted-locked";
    case WALLET_SEED_MALFORMED:  return "present-unusable";
    case WALLET_SEED_UNREADABLE: return "unreadable";
    }
    return "unknown";
}

/* How far the rebuild reached. Printed on both the plan and the commit, so
 * "recovered" is never a bare true with no scope attached. */
static void wrp_push_scan(struct zcl_command_reply *reply,
                          const struct wallet_recovery_report *rep)
{
    (void)json_push_kv_int(&reply->data, "receiving_addresses_rebuilt",
                           rep->receiving_keys);
    (void)json_push_kv_int(&reply->data, "change_addresses_rebuilt",
                           rep->change_keys);
    (void)json_push_kv_int(&reply->data, "shielded_addresses_rebuilt",
                           rep->shielded_children);
    (void)json_push_kv_bool(&reply->data, "chain_history_consulted",
                            rep->chain_history_consulted);
    if (rep->chain_history_consulted)
        (void)json_push_kv_int(&reply->data, "addresses_with_history_found",
                               (int64_t)rep->receiving_keys_used +
                               (int64_t)rep->change_keys_used);
    else
        (void)json_push_kv_str(&reply->data, "address_coverage",
            "this datadir has no chain to check against, so the rebuild "
            "derived the standard lookahead rather than following your "
            "history. That covers every address a wallet hands out before "
            "it has been used a lot. If you gave out more addresses than "
            "that, recover into a datadir that has already synced and the "
            "scan will follow them");
    if (rep->transparent_scan_truncated)
        (void)json_push_kv_str(&reply->data, "coverage_warning",
            "the address scan stopped at its safety ceiling with your "
            "history still running past it: addresses beyond that point "
            "were NOT rebuilt. Coins on them are not lost — the seed still "
            "derives them — but this datadir does not hold their keys yet");
}

void zcl_native_handle_wallet_recovery_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    wrp_select_chain_params_if_standalone();
    char datadir[1024];
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && strlen(dd) >= sizeof(datadir)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                 "datadir is too long to use without changing its path",
                 "core.wallet.recovery.status");
        return;
    }
    if (dd && dd[0])
        snprintf(datadir, sizeof(datadir), "%s", dd);
    else
        wrp_default_datadir(datadir, sizeof(datadir));

    struct wallet_recovery_report rep;
    struct zcl_result pre = wallet_recovery_status_preflight(datadir, &rep);
    if (!pre.ok) {
        bool held = pre.code == -61;
        wrp_push_report(reply, &rep);
        wnh_fail(reply,
                 held ? ZCL_COMMAND_EXIT_BLOCKED : ZCL_COMMAND_EXIT_FAILED,
                 held ? "DATADIR_LOCKED" : "BAD_DATADIR", pre.message,
                 datadir);
        return;
    }

    /* READ leaf. The `datadir` input defaults to the operator's LIVE one,
     * so this open is SQLITE_OPEN_READONLY + PRAGMA query_only=ON and
     * nothing else — never node_db_open(), which is READWRITE|CREATE and
     * would create_schema(), migrate, and on a failed quick_check rename
     * the user's node.db aside to node.db.corrupt-<ts> and answer "ok".
     * Every status EXCEPT OK is refused with its own named reason, and
     * ABSENT is refused separately from UNREADABLE: "you have not made a
     * wallet yet" and "I could not read your wallet" are opposite answers
     * to the question this leaf is asked, and collapsing them would tell
     * an operator with an unreadable wallet that they never had one. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    char ndb_path[1200];
    enum zcl_node_db_ro_status ro_st = zcl_native_node_db_open_readonly(
        datadir, &db, &ndb, ndb_path, sizeof(ndb_path));
    if (ro_st == ZCL_NODE_DB_RO_ABSENT) {
        wrp_push_report(reply, &rep);
        (void)json_push_kv_str(&reply->data, "what_to_do",
            "nothing here is broken — this datadir has no wallet database "
            "yet. One is created, with its twelve words shown once, the "
            "first time the node starts on it. Check --datadir if you "
            "expected a wallet at this path");
        wnh_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "NO_NODE_DB",
                 "there is no node.db at this datadir, so there is no wallet "
                 "to answer about — this is the normal state of a datadir "
                 "the node has never booted on, not a fault", ndb_path);
        return;
    }
    if (ro_st != ZCL_NODE_DB_RO_OK) {
        wrp_push_report(reply, &rep);
        /* Fills the reply with NODE_DB_UNREADABLE / MISSING_DATADIR /
         * DATADIR_PATH_TOO_LONG and returns false; never "ok": true. */
        (void)zcl_native_node_db_require_readonly(
            datadir, reply,
            "whether this wallet can be rebuilt from its recovery phrase",
            &db, &ndb);
        return;
    }

    struct zcl_result r = wallet_recovery_status(datadir, &ndb, &rep);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!r.ok) {
        wrp_push_report(reply, &rep);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NO_WALLET", r.message,
                 datadir);
        return;
    }

    wrp_push_report(reply, &rep);
    (void)json_push_kv_bool(&reply->data, "recoverable_from_phrase",
                            rep.seed_installed);
    (void)json_push_kv_str(&reply->data, "seed_state",
                           wrp_seed_state_name(rep.seed_state_before));

    /* LOCKED is answered on its own, BEFORE the recoverable/not fork.
     * An encrypted wallet that does have a phrase-backed seed used to fall
     * through to the "created before recovery phrases" branch below and be
     * told its money could only come back from a file — the error path and
     * the empty result returning the same value, the defect family this
     * tree keeps paying for. "Locked, unlock and ask again" and "there is
     * no phrase for this wallet" are opposite answers and now read that
     * way. */
    if (rep.seed_state_before == WALLET_SEED_LOCKED) {
        (void)json_push_kv_str(&reply->data, "meaning",
            "this wallet IS seed-backed — the seed is right there in "
            "node.db — but it is encrypted and could not be decrypted "
            "here, so whether your twelve words rebuild it cannot be "
            "checked yet. This is not the same as having no recovery "
            "phrase");
        (void)json_push_kv_str(&reply->data, "what_to_do",
            "unlock the wallet and ask again: set ZCL_WALLET_PASSPHRASE to "
            "the passphrase you encrypted it with and re-run this command. "
            "Do not treat this as 'no phrase' and do not recover over this "
            "datadir");
        wnh_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "WALLET_LOCKED",
                 "the wallet seed at this datadir is encrypted and could "
                 "not be decrypted, so this command cannot say whether your "
                 "recovery phrase rebuilds it — unlock it and ask again",
                 datadir);
        return;
    }
    if (rep.seed_state_before == WALLET_SEED_MALFORMED) {
        (void)json_push_kv_str(&reply->data, "meaning",
            "there is a seed row in this wallet, but it is not a usable "
            "seed. That is damage, not the absence of a recovery phrase");
        (void)json_push_kv_str(&reply->data, "what_to_do",
            "do not recover over this datadir. Take a copy of it first, "
            "then rebuild into a NEW empty datadir — from your twelve words "
            "('core wallet recovery restore') or from a wallet backup file");
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "WALLET_SEED_UNUSABLE",
                 "the wallet seed stored at this datadir is not a usable "
                 "seed", datadir);
        return;
    }

    if (rep.seed_installed) {
        (void)json_push_kv_str(&reply->data, "meaning",
            "this wallet's keys all descend from its recovery phrase, so the "
            "twelve words you wrote down when it was created bring it back "
            "on any machine");
        (void)json_push_kv_str(&reply->data, "phrase_shown_again",
            "never — the node stores only the key material the words derive, "
            "and the words cannot be worked back out of it. If you did not "
            "write them down, take a file backup now (core wallet backup "
            "now) and treat that file as the only copy");
    } else {
        (void)json_push_kv_str(&reply->data, "meaning",
            "this wallet was created before recovery phrases. Its keys are "
            "independently random, so no phrase can rebuild them and there "
            "is no phrase to show you");
        (void)json_push_kv_str(&reply->data, "what_to_do",
            "back it up as a file: 'core wallet backup now', and keep that "
            "file somewhere the machine's disk failing cannot take with it. "
            "To move to a phrase-backed wallet, recover a NEW empty datadir "
            "from a new phrase and send your coins there");
    }
    reply->error.mutated = false;
}

/* Restore has no default: it installs spending keys and must preserve the
 * caller's explicit target byte-for-byte before any filesystem operation. */
static bool wrp_restore_datadir(const struct json_value *input,
                                char *datadir, size_t datadir_cap,
                                struct zcl_command_reply *reply,
                                const char *leaf)
{
    const char *dd = json_get_str(json_get(input, "datadir"));
    if (!dd || !dd[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                 "datadir is required and has no default here. This command "
                 "writes a whole wallet — spending keys and the master seed "
                 "they all descend from — and it will not guess where. Name "
                 "an EMPTY directory to recover into, e.g. "
                 "--input='{\"datadir\":\"/srv/zcl-recovered\"}'. It is "
                 "deliberately NOT your running node's datadir: recover "
                 "beside it, then move what you need",
                 leaf);
        return false;
    }
    if (strlen(dd) >= datadir_cap) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                 "datadir is too long to use without changing its path",
                 leaf);
        return false;
    }
    (void)snprintf(datadir, datadir_cap, "%s", dd);
    return true;
}

/* The birthday a create reply named: {"height":N,"hash":"<64 hex>"}. Absent is
 * fine; a present one that is not that shape is refused before anything is
 * written, because a caller that sends it expects it to be used. */
static bool wrp_parse_birthday(const struct json_value *input,
                               struct wallet_recovery_request *req,
                               struct zcl_command_reply *reply)
{
    const struct json_value *b = json_get(input, "birthday");
    if (!b)
        return true;
    const struct json_value *h = json_get(b, "height");
    const char *hex = json_get_str(json_get(b, "hash"));
    int64_t height = h ? json_get_int(h) : 0;
    if (height <= 0 || !hex || !zcl_hex_decode(hex, req->birthday_hash, 32)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_BIRTHDAY",
                 "birthday must be {\"height\": a positive number, \"hash\": "
                 "64 hex characters}, exactly as a wallet create reply "
                 "gave them. Nothing was written",
                 "core.wallet.recovery.restore");
        return false;
    }
    req->has_birthday = true;
    req->birthday_height = height;
    return true;
}

/* The passphrase arrives only on standard input, the way create takes it. */
static bool wrp_restore_passphrase(const struct json_value *input,
                                   const char **pass,
                                   struct zcl_command_reply *reply)
{
    const struct json_value *p = json_get(input, "passphrase");
    *pass = p ? json_get_str(p) : NULL;
    if (!p || zcl_native_input_was_stdin())
        return true;
    wnh_fail(reply, ZCL_COMMAND_EXIT_DENIED, "STDIN_REQUIRED",
             "the passphrase is accepted only through --input=-; it is never "
             "taken from arguments or the environment",
             "core.wallet.recovery.restore");
    return false;
}

/* What the restore did with the birthday and what it cannot show. The app
 * shows history_below_seed_hidden next to the balance. */
static void wrp_push_history(struct zcl_command_reply *reply,
                             const struct wallet_recovery_report *rep)
{
    (void)json_push_kv_bool(&reply->data, "birthday_recorded",
                            rep->birthday_recorded);
    (void)json_push_kv_bool(&reply->data, "birthday_rejected",
                            rep->birthday_rejected);
    (void)json_push_kv_int(&reply->data, "seed_floor_height",
                           rep->seed_floor_height);
    (void)json_push_kv_bool(&reply->data, "history_below_seed_hidden",
                            rep->history_below_seed_hidden);
    if (rep->history_below_seed_hidden)
        (void)json_push_kv_str(&reply->data, "history_warning",
            "this node was seeded from a snapshot and holds no blocks below "
            "its seed height, and these words carry no birthday. Funds "
            "received below the seed height are not visible here. A phrase "
            "created just now has none; an older phrase may");
}

/* Lower-case hex of a 32-byte hash. */
static void wrp_hash_hex(const uint8_t hash[32], char hex[65])
{
    for (size_t i = 0; i < 32; i++)
        (void)snprintf(hex + 2 * i, 3, "%02x", hash[i]);
}

/* The birthday as the caller gave it, for the commit input a plan returns. */
static void wrp_push_birthday_input(struct json_value *obj,
                                    const struct wallet_recovery_request *req)
{
    char hex[65];
    wrp_hash_hex(req->birthday_hash, hex);
    struct json_value b;
    json_init(&b);
    json_set_object(&b);
    (void)json_push_kv_int(&b, "height", req->birthday_height);
    (void)json_push_kv_str(&b, "hash", hex);
    (void)json_push_kv(obj, "birthday", &b);
    json_free(&b);
}

/* The reply code for a refused recovery. The names are separate because they
 * are separate operator moves: "your database is damaged and I did not touch
 * it" differs from "decide how these keys are stored first". None is a generic
 * failure and none ever reports ok. */
static const char *wrp_failure_code(int code, enum zcl_command_exit *ex)
{
    static const struct {
        int code;
        const char *name;
        enum zcl_command_exit exit;
    } map[] = {
        { -60, "INVALID_PHRASE", ZCL_COMMAND_EXIT_INVALID },
        { -61, "DATADIR_LOCKED", ZCL_COMMAND_EXIT_BLOCKED },
        { -62, "WALLET_ALREADY_PRESENT", ZCL_COMMAND_EXIT_BLOCKED },
        { -66, "NODE_DB_UNREADABLE", ZCL_COMMAND_EXIT_BLOCKED },
        { -67, "WALLET_AT_REST_UNDECIDED", ZCL_COMMAND_EXIT_BLOCKED },
        { -68, "PASSPHRASE_TOO_SHORT", ZCL_COMMAND_EXIT_INVALID },
    };
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (map[i].code == code) {
            *ex = map[i].exit;
            return map[i].name;
        }
    }
    *ex = ZCL_COMMAND_EXIT_FAILED;
    return "RECOVERY_REFUSED";
}

static void wrp_restore_body(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    wrp_select_chain_params_if_standalone();
    /* argv is world-readable on this machine; the env var is the quieter
     * way in and the help text names it. */
    const char *phrase = json_get_str(json_get(request->input, "phrase"));
    if (!phrase || !phrase[0])
        phrase = getenv("ZCL_RECOVERY_PHRASE");
    if (!phrase || !phrase[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PHRASE",
                 "phrase is required: the words you wrote down when this "
                 "wallet was created. Pass it as the phrase input, or set "
                 "ZCL_RECOVERY_PHRASE so it stays out of your shell history",
                 "core.wallet.recovery.restore");
        return;
    }

    char datadir[1024];
    if (!wrp_restore_datadir(request->input, datadir, sizeof(datadir), reply,
                             "core.wallet.recovery.restore"))
        return;

    bool confirm = json_get_bool_or(request->input, "confirm", false);

    struct wallet_recovery_request req = {
        .phrase  = phrase,
        .datadir = datadir,
        .dry_run = !confirm,
        .shielded_only = json_get_bool_or(request->input, "shielded_only",
                                          false),
    };
    if (!wrp_restore_passphrase(request->input, &req.passphrase, reply) ||
        !wrp_parse_birthday(request->input, &req, reply))
        return;
    struct wallet_recovery_report rep;
    struct zcl_result r = wallet_recovery_run(&req, &rep);

    if (!r.ok) {
        wrp_push_report(reply, &rep);
        enum zcl_command_exit ex;
        const char *code = wrp_failure_code(r.code, &ex);
        /* r.message describes the shape of the failure and never quotes
         * the phrase; the evidence field carries the datadir, not the
         * words. */
        wnh_fail(reply, ex, code, r.message, datadir);
        return;
    }

    wrp_push_report(reply, &rep);
    wrp_push_scan(reply, &rep);
    wrp_push_history(reply, &rep);
    /* Once, from the service: a commit's result, or a plan's forecast under
     * the same decision the commit uses. */
    (void)json_push_kv_bool(&reply->data, "encrypted_at_rest",
                            rep.encrypted_at_rest);
    if (!confirm && rep.commit_refused_at_rest)
        (void)json_push_kv_str(&reply->data, "commit_would_refuse",
                               "WALLET_AT_REST_UNDECIDED");
    /* Said on every plan and every commit, because the failure it prevents
     * is silent: a phrase from other wallet software validates here, opens
     * a different empty wallet, and reports success. */
    (void)json_push_kv_str(
        &reply->data, "phrase_compatibility",
        "these words work with THIS NODE ONLY. They are ordinary BIP39 "
        "words, but this node builds its key from the first 32 bytes of the "
        "standard 64-byte result while other wallets use all 64. A phrase "
        "written down here restores nothing in other wallet software, and a "
        "phrase from other software restores a different, EMPTY wallet "
        "here — with no error, which is why it is worth saying out loud. "
        "Keep the words labelled 'zclassic23'");
    (void)json_push_kv_str(
        &reply->data, "next_steps",
        "start the node on this datadir, then run 'core wallet rescan' to "
        "find your transparent history and 'core wallet rescan-witnesses' "
        "before spending a shielded note — the keys came back from the "
        "phrase, but balances and history are chain state and have to be "
        "read back off the chain");

    if (!confirm) {
        /* The commit input carries the datadir and the confirm flag ONLY.
         * Putting the phrase in a response body is how a wallet ends up in
         * a paste buffer. */
        struct json_value commit_value;
        json_init(&commit_value);
        json_set_object(&commit_value);
        (void)json_push_kv_str(&commit_value, "phrase", "<your words>");
        (void)json_push_kv_str(&commit_value, "datadir", datadir);
        (void)json_push_kv_bool(&commit_value, "confirm", true);
        if (req.shielded_only)
            (void)json_push_kv_bool(&commit_value, "shielded_only", true);
        if (req.has_birthday)
            wrp_push_birthday_input(&commit_value, &req);
        char commit[7000];
        if (json_write(&commit_value, commit, sizeof(commit)) == 0)
            snprintf(commit, sizeof(commit), "{\"error\":\"input too long\"}");
        json_free(&commit_value);
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", "recovery-restore");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        /* This sentence is a promise, and the service now keeps it: the
         * plan path creates no datadir and no node.db, and reads an
         * existing target through a read-only handle only. */
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "the addresses above are what these words open — check the first "
            "one against what you remember, then re-run with confirm true to "
            "write the wallet. Nothing has been written yet: no directory, "
            "no database, no file anywhere");
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        (void)json_push_kv_str(&reply->data, "phrase_in_commit_input",
            "no — retype your own words; they are deliberately not echoed "
            "back to you here");
        reply->error.mutated = false;
        return;
    }

    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "recovered", rep.seed_installed);
    reply->error.mutated = true;
}

/* ── core.wallet.create ────────────────────────────────────────────────
 *
 * A new wallet in an EMPTY datadir. The passphrase arrives only on standard
 * input (`--input=-`), the way the other custody leaves take theirs, so it is
 * never in argv or the environment. The 24-word phrase leaves in this reply
 * and nowhere else: the service stores, logs and journals nothing, the
 * registry keeps only latency for a reply, and this handler pushes the phrase
 * after every other field so a failure path cannot carry it. */

/* A create that committed but whose reply never arrived cannot be repeated
 * here: the phrase was shown once and is stored nowhere. The caller holds the
 * way back, so the refusal says what it is (the reply caps this at 255). */
#define WRP_CREATE_LOST_REPLY_HINT                                          \
    "If an earlier create here lost its reply, no command can show that "   \
    "phrase again. Delete a datadir made only for that attempt and never "  \
    "started, then create in a new one. Restore a used wallet from its "    \
    "written phrase into a new datadir."
_Static_assert(sizeof(WRP_CREATE_LOST_REPLY_HINT) <= 256,
               "next_action holds 255 bytes");

static const char *wrp_create_failure_code(int code, enum zcl_command_exit *ex)
{
    *ex = ZCL_COMMAND_EXIT_BLOCKED;
    switch (code) {
    case -61: return "DATADIR_LOCKED";
    case -62: return "WALLET_ALREADY_PRESENT";
    case -66: return "NODE_DB_UNREADABLE";
    case -68: *ex = ZCL_COMMAND_EXIT_INVALID; return "PASSPHRASE_TOO_SHORT";
    default:  *ex = ZCL_COMMAND_EXIT_FAILED; return "CREATE_FAILED";
    }
}

static void wrp_push_created(struct zcl_command_reply *reply,
                             const struct wallet_create_report *rep)
{
    const struct wallet_recovery_report *rec = &rep->recovery;
    (void)json_push_kv_str(&reply->data, "datadir", rec->datadir);
    (void)json_push_kv_str(&reply->data, "first_shielded_address",
                           rec->first_shielded_address);
    (void)json_push_kv_bool(&reply->data, "encrypted_at_rest", true);
    (void)json_push_kv_int(&reply->data, "transparent_addresses",
                           (int64_t)rec->keys_after);
    (void)json_push_kv_bool(&reply->data, "birthday_recorded",
                            rec->birthday_recorded);
    if (rec->birthday_recorded) {
        (void)json_push_kv_int(&reply->data, "birthday_height",
                               rec->birthday_height);
        char hex[65];
        wrp_hash_hex(rec->birthday_hash, hex);
        (void)json_push_kv_str(&reply->data, "birthday_hash", hex);
    }
    (void)json_push_kv_str(&reply->data, "phrase_shown_again",
        "never. The phrase is not stored anywhere and no command can print "
        "it again. Write it down now: it is the only backup");
    (void)json_push_kv_str(&reply->data, "phrase_compatibility",
        "these words work with this node only; other wallet software reads "
        "the same words as a different, empty wallet");
}

/* A crash must not write the phrase or the passphrase to a core file. The
 * process is one-shot and this does not make its memory secret; it closes the
 * one path that outlives it. */
static void wrp_disable_core_dumps(void)
{
#ifndef _WIN32
    struct rlimit none = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &none);
#endif
#ifdef __linux__
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* Everything the datadir open prints to standard output is moved to standard
 * error for the length of the call, so standard output holds the reply
 * document and nothing else: a strict parser must not fail after the wallet is
 * committed, because a lost reply cannot be repeated. Returns the saved
 * descriptor, or -1 when standard output could not be moved. */
static int wrp_stdout_to_stderr(void)
{
    (void)fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved >= 0 && dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
        (void)close(saved);
        saved = -1;
    }
    return saved;
}

/* False when standard output could not be put back: it still points at the log
 * stream, and the reply document, which carries the phrase, must not follow. */
static bool wrp_stdout_restore(int saved)
{
    (void)fflush(stdout);
    bool ok = dup2(saved, STDOUT_FILENO) >= 0;
    (void)close(saved);
    return ok;
}

static void wrp_create_body(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    wrp_select_chain_params_if_standalone();
    if (!zcl_native_input_was_stdin()) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_DENIED, "STDIN_REQUIRED",
                 "the passphrase is accepted only through --input=-; it is "
                 "never taken from arguments or the environment",
                 "core.wallet.create");
        return;
    }
    char datadir[1024];
    if (!wrp_restore_datadir(request->input, datadir, sizeof(datadir),
                             reply, "core.wallet.create"))
        return;
    const char *passphrase =
        json_get_str(json_get(request->input, "passphrase"));

    struct wallet_create_request req = { .datadir = datadir,
                                         .passphrase = passphrase };
    struct wallet_create_report rep;
    struct zcl_result r = wallet_create_run(&req, &rep);
    if (!r.ok) {
        enum zcl_command_exit ex;
        const char *code = wrp_create_failure_code(r.code, &ex);
        wnh_fail(reply, ex, code,
                 r.code == -62 ? "this datadir already holds a wallet. "
                                 "Nothing was written" : r.message, datadir);
        if (r.code == -62)
            (void)snprintf(reply->error.next_action,
                           sizeof(reply->error.next_action), "%s",
                           WRP_CREATE_LOST_REPLY_HINT);
        wallet_create_report_cleanse(&rep);
        return;
    }
    wrp_push_created(reply, &rep);
    (void)json_push_kv_str(&reply->data, "phrase", rep.phrase);
    wallet_create_report_cleanse(&rep);
    reply->error.mutated = true;
}

/* The restore reply carries what the app reads (birthday, history_below_seed_
 * hidden, encrypted_at_rest), so standard output holds only that document, as
 * for create: the log lines of opening the datadir go to standard error. If
 * standard output cannot be put back the reply is withheld, and a restore that
 * had written the wallet says so. */
void zcl_native_handle_wallet_recovery_restore(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    int saved = wrp_stdout_to_stderr();
    wrp_restore_body(request, reply);
    if (saved >= 0 && !wrp_stdout_restore(saved)) {
        bool written = reply->error.mutated;
        json_free(&reply->data);
        json_init(&reply->data);
        json_set_object(&reply->data);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "STDOUT_RESTORE_FAILED",
                 written ? "standard output could not be restored, so the "
                           "reply was withheld. The wallet WAS written; read "
                           "its state with core wallet recovery status"
                         : "standard output could not be restored, so the "
                           "reply was withheld. Nothing was written",
                 "core.wallet.recovery.restore");
        reply->error.mutated = written;
    }
}

void zcl_native_handle_wallet_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    wrp_disable_core_dumps();
    int saved = wrp_stdout_to_stderr();
    if (saved < 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "STDOUT_UNAVAILABLE",
                 "standard output could not be kept clear of log lines, so "
                 "the reply could not be delivered whole. Nothing was written",
                 "core.wallet.create");
        return;
    }
    wrp_create_body(request, reply);
    /* Only a body that committed carries a phrase; a refusal is left as it is. */
    if (!wrp_stdout_restore(saved) && reply->error.mutated) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_set_object(&reply->data);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "STDOUT_RESTORE_FAILED",
                 "standard output could not be restored, so the reply was "
                 "withheld rather than written to the log stream. If a "
                 "wallet was made its phrase is lost: delete the datadir",
                 "core.wallet.create");
        reply->error.mutated = true;
    }
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only RECOVERY POSTURE. The restore path itself is withheld. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "core.wallet.recovery.status"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(wallet_recovery)
ZCL_HOTSWAP_LEAF("core.wallet.recovery.status", zcl_native_handle_wallet_recovery_status)
ZCL_HOTSWAP_LEAVES_END(wallet_recovery)
#endif
