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
 * asked about. Gated by tools/lint/check_read_leaf_no_boot_ceremony.sh and
 * proven on disk by lib/test/src/test_read_leaf_no_datadir_write.c.
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
 * Bound in config/commands/core.def.
 */

#include "controllers/wallet_native_handlers.h"

#include "chain/chainparams.h"
#include "controllers/agent_controller.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "models/database.h"                   /* struct node_db (RO shim) */
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void zcl_native_handle_wallet_recovery_restore(
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

    /* NO DEFAULT DATADIR ON THIS LEAF. `status` may fall back to the
     * runtime's datadir because it only reads; this one installs spending
     * keys and a master seed, and its fallback was the OPERATOR'S LIVE
     * DATADIR. "Recovery" is precisely the word a person types when
     * something is already wrong, and the cost of guessing the target
     * wrong is a second wallet written into the live node. An explicit
     * path is also the only thing a plan and its later commit can be
     * checked to agree on. So: name it, or nothing happens. */
    char datadir[1024];
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (!dd || !dd[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                 "datadir is required and has no default here. This command "
                 "writes a whole wallet — spending keys and the master seed "
                 "they all descend from — and it will not guess where. Name "
                 "an EMPTY directory to recover into, e.g. "
                 "--input='{\"datadir\":\"/srv/zcl-recovered\"}'. It is "
                 "deliberately NOT your running node's datadir: recover "
                 "beside it, then move what you need",
                 "core.wallet.recovery.restore");
        return;
    }
    snprintf(datadir, sizeof(datadir), "%s", dd);

    bool confirm = json_get_bool_or(request->input, "confirm", false);

    struct wallet_recovery_request req = {
        .phrase  = phrase,
        .datadir = datadir,
        .dry_run = !confirm,
    };
    struct wallet_recovery_report rep;
    struct zcl_result r = wallet_recovery_run(&req, &rep);

    if (!r.ok) {
        wrp_push_report(reply, &rep);
        const char *code = "RECOVERY_REFUSED";
        enum zcl_command_exit ex = ZCL_COMMAND_EXIT_FAILED;
        if (r.code == -60) { code = "INVALID_PHRASE"; ex = ZCL_COMMAND_EXIT_INVALID; }
        else if (r.code == -61) { code = "DATADIR_LOCKED"; ex = ZCL_COMMAND_EXIT_BLOCKED; }
        else if (r.code == -62) { code = "WALLET_ALREADY_PRESENT"; ex = ZCL_COMMAND_EXIT_BLOCKED; }
        /* Separate names because they are separate operator moves: one says
         * "your database is damaged and I did not touch it", the other says
         * "decide how these keys are stored first". Neither is a generic
         * failure and neither ever reports ok. */
        else if (r.code == -66) { code = "NODE_DB_UNREADABLE"; ex = ZCL_COMMAND_EXIT_BLOCKED; }
        else if (r.code == -67) { code = "WALLET_AT_REST_UNDECIDED"; ex = ZCL_COMMAND_EXIT_BLOCKED; }
        /* r.message describes the shape of the failure and never quotes
         * the phrase; the evidence field carries the datadir, not the
         * words. */
        wnh_fail(reply, ex, code, r.message, datadir);
        return;
    }

    wrp_push_report(reply, &rep);
    wrp_push_scan(reply, &rep);
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
