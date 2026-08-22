/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `core zdir` tree — the operator's way to put a
 * node on the on-chain directory, and to take it back off.
 *
 * This is the surface that closes the gap zdir/zdir.h named: the ZDIR codec
 * and the onion_directory fold were both wired, but nothing composed,
 * funded, signed or broadcast a record, so on a network where no other tool
 * writes ZDIR records the projection read empty forever.
 *
 * Writes (register/deregister) require an explicit dev/prod custody scope and
 * dispatch zdir_intent in two phases. Planning atomically reserves the exact
 * inputs plus maximum fee; commit publishes only the stored signed bytes.
 * Public receipts whitelist custody/status fields and omit hostnames, keys,
 * owners, addresses, and raw bytes. No boot path, timer, or background
 * service reaches this file.
 *
 * Pre-flight reads run against <datadir>/node.db READONLY BEFORE either
 * plan — the core.storage.query.offline pattern — so a refusal is named and
 * free rather than a spent fee: deregister needs an existing, still-active
 * row, and any mutation of a row that records no owner is refused outright
 * because the fold would refuse it too.
 *
 * NO TRANSFER LEAF. ZDIR command byte 3 is reserved for TRANSFER and
 * zdir_parse deliberately rejects it, because a parsed-but-unhandled
 * command would be a silent stub. Handing a hostname to another operator is
 * expressed as `core zdir deregister` by the current owner followed by
 * `core zdir register` from the new one. */

#include "command/native_command.h"

#include "base/log_macros.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/onion_directory.h"
#include "net/onion_peer_merge.h"
#include "zdir/zdir.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── small helpers ────────────────────────────────────────────────── */

static const char *zdc_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Explicit input.datadir wins, else the CLI's --datadir. */
static const char *zdc_datadir(const struct zcl_command_request *request)
{
    const char *dd = zdc_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* The read-only open is zcl_native_node_db_{open,require}_readonly
 * (command/native_command.h). This wrapper exists only for the register
 * pre-flight, where an ABSENT node.db is NOT an error: a first
 * registration from a host with no folded chain is legitimate. That
 * licence covers ABSENT alone — an UNREADABLE node.db is a failure to
 * look, and skipping the pre-flight on it would spend a fee against a row
 * that was never actually checked. Returns the handle, or NULL with
 * *fatal_out set when the caller must refuse instead of proceeding. */
static sqlite3 *zdc_open_db_preflight(const char *datadir,
                                      struct node_db *ndb_out,
                                      bool *fatal_out)
{
    sqlite3 *db = NULL;
    *fatal_out = false;
    enum zcl_node_db_ro_status st =
        zcl_native_node_db_open_readonly(datadir, &db, ndb_out, NULL, 0);
    if (st == ZCL_NODE_DB_RO_OK)
        return db;
    if (st != ZCL_NODE_DB_RO_ABSENT)
        *fatal_out = true;
    return NULL;  // raw-return-ok:optional-preflight-open
}

/* Exactly 64 hex chars decoding to a non-zero 32-byte key. */
static bool zdc_parse_key(const char *hex, uint8_t out[ZDIR_PUBKEY_LEN])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex))
        return false;
    if (ParseHex(hex, out, ZDIR_PUBKEY_LEN) != ZDIR_PUBKEY_LEN)
        return false;
    for (int i = 0; i < ZDIR_PUBKEY_LEN; i++)
        if (out[i])
            return true;
    return false;   /* all-zero is the unset sentinel, never a usable key */
}

/* Read --hostname, holding it to the ONE v3 onion rule the node has
 * (onion_hostname_valid). Fails the reply with a named code and returns
 * NULL when it is absent or not a v3 onion. */
static const char *zdc_require_hostname(const struct json_value *input,
                                        struct zcl_command_reply *reply,
                                        const char *path)
{
    const char *hostname = zdc_input_str(input, "hostname");
    if (!hostname || !hostname[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_HOSTNAME",
                               "normalize", false, false,
                               "give --hostname=<56 base32 chars>.onion — the "
                               "exact Tor v3 hostname this node serves", path);
        return NULL;
    }
    if (!onion_hostname_valid(hostname)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_HOSTNAME",
                               "normalize", false, false,
                               "hostname must be a Tor v3 onion: exactly 56 "
                               "base32 characters followed by \".onion\" — v2 "
                               "onions and bare hostnames are refused",
                               hostname);
        return NULL;
    }
    return hostname;
}

#define ZDC_LIST_CAP 32
#define ZDC_TAG "native.zdir"

void zcl_native_handle_core_zdir_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input || request->input->type != JSON_OBJ ||
        request->input->num_children != 0) {
        LOG_ERROR(ZDC_TAG, "BAD_ZDIR_GUIDE_INPUT: zdir guide accepts no "
                          "input keys");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "BAD_ZDIR_GUIDE_INPUT", "validate", false,
                               false, "zdir guide accepts no input keys",
                               "core.zdir.guide");
        return;
    }
    bool ok = json_push_kv_str(
            &reply->data, "mission",
            "Find Z23 nodes from the chain you already verify.") &&
        json_push_kv_str(&reply->data, "list_command",
                         "z23 core zdir list") &&
        json_push_kv_str(&reply->data, "announce_command",
                         "z23 core zdir register") &&
        json_push_kv_str(
            &reply->data, "never",
            "Do not hardcode hosts. Directory authorities are the chain.");
    if (!ok) {
        LOG_ERROR(ZDC_TAG, "ZDIR_GUIDE_OUTPUT: the directory guide could "
                          "not be rendered");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ZDIR_GUIDE_OUTPUT",
                               "render", false, false,
                               "the directory guide could not be rendered",
                               "core.zdir.guide");
    }
}

void zcl_native_handle_core_zdir_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.zdir.list";
    const char *datadir = zdc_datadir(request);
    sqlite3 *db = NULL;
    struct node_db ndb;
    enum zcl_node_db_ro_status st =
        zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0);
    if (st != ZCL_NODE_DB_RO_OK && st != ZCL_NODE_DB_RO_ABSENT &&
        st != ZCL_NODE_DB_RO_NO_DATADIR) {
        LOG_ERROR(ZDC_TAG, "NODE_DB_UNREADABLE: onion_directory could not "
                          "be opened read-only");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NODE_DB_UNREADABLE",
                               "execute", false, false,
                               "the onion directory could not be read",
                               path);
        return;
    }

    int offset = 0;
    if (request->cursor && request->cursor[0]) {
        char *end = NULL;
        unsigned long long c = strtoull(request->cursor, &end, 10);
        if (end && !*end && c <= 100000)
            offset = (int)c;
    }

    struct db_onion_directory rows[ZDC_LIST_CAP];
    int n = 0;
    int64_t active = 0;
    bool folded = (st == ZCL_NODE_DB_RO_OK);
    if (folded) {
        n = db_onion_directory_list_active(&ndb, rows, ZDC_LIST_CAP,
                                           offset);
        active = db_onion_directory_count_by_status(
            &ndb, ONION_DIRECTORY_STATUS_ACTIVE);
        zcl_native_node_db_close_readonly(&db, &ndb);
    }

    struct json_value items;
    json_init(&items);
    json_set_array(&items);
    for (int i = 0; i < n; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "hostname", rows[i].hostname);
        (void)json_push_kv_int(&row, "height", rows[i].height);
        (void)json_push_back(&items, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "items", &items);
    json_free(&items);
    (void)json_push_kv_int(&reply->data, "count", n);
    (void)json_push_kv_int(&reply->data, "active", active);
    (void)json_push_kv_bool(&reply->data, "folded", folded);
    if (folded && offset + n < active) {
        char cont[80];
        snprintf(cont, sizeof(cont), "z23 core zdir list --cursor=%d",
                 offset + n);
        (void)json_push_kv_str(&reply->data, "continue", cont);
    }
    (void)json_push_kv_str(&reply->data, "next_action",
                           folded && n > 0 ? "z23 core network onion status"
                                           : "z23 core zdir guide");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.zdir.register ───────────────────────────────────────────── */

void zcl_native_handle_core_zdir_register(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.zdir.register";
    if (json_get_bool_or(request->input, "confirm", false)) {
        zcl_native_overlay_intent_run(
            request, reply, "zdir_intent", "register", false);
        return;
    }

    const char *hostname = zdc_require_hostname(request->input, reply, path);
    if (!hostname)
        return;

    const char *pubkey_hex = zdc_input_str(request->input, "pubkey");
    bool have_key = pubkey_hex && pubkey_hex[0];
    uint8_t key[ZDIR_PUBKEY_LEN];
    if (have_key && !zdc_parse_key(pubkey_hex, key)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY_HEX",
                               "normalize", false, false,
                               "pubkey must be exactly 64 hex characters and "
                               "not all-zero — omit it entirely to register "
                               "the hostname unbound", pubkey_hex);
        return;
    }

    /* Pre-flight: a hostname whose row records no owner can never be
     * mutated by anyone, so re-registering it would spend a fee on a record
     * the fold refuses. A missing node.db is not an error — a first
     * registration from a host with no folded chain is legitimate. */
    const char *datadir = zdc_datadir(request);
    char owner[ONION_DIRECTORY_ADDRESS_MAX] = "";
    bool known = false;
    if (datadir) {
        struct node_db ndb;
        bool db_fatal = false;
        sqlite3 *db = zdc_open_db_preflight(datadir, &ndb, &db_fatal);
        if (db_fatal) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "NODE_DB_UNREADABLE", "execute", true, false,
                "node.db is present at this datadir but would not open "
                "read-only, so the ownership pre-flight could not run — "
                "refusing rather than spending a fee on an unchecked "
                "registration; check permissions, or pass a readable datadir",
                datadir);
            return;
        }
        if (db) {
            struct db_onion_directory prev;
            memset(&prev, 0, sizeof(prev));
            known = db_onion_directory_find(&ndb, hostname, &prev);
            if (known) {
                snprintf(owner, sizeof(owner), "%s", prev.owner_address);
            }
            zcl_native_node_db_close_readonly(&db, &ndb);
            if (known && owner[0] == '\0') {
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_FAILED, "NOT_OWNER", "execute", false,
                    false,
                    "this hostname already has a directory row that records "
                    "no owner address, so no signer can ever prove ownership "
                    "of it — the row is permanently immutable by design and "
                    "a re-registration would be refused by every node",
                    hostname);
                return;
            }
        }
    }

    zcl_native_overlay_intent_run(
        request, reply, "zdir_intent", "register", true);
}

/* ── core.zdir.deregister ─────────────────────────────────────────── */

void zcl_native_handle_core_zdir_deregister(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *path = "core.zdir.deregister";
    if (json_get_bool_or(request->input, "confirm", false)) {
        zcl_native_overlay_intent_run(
            request, reply, "zdir_intent", "deregister", false);
        return;
    }

    const char *hostname = zdc_require_hostname(request->input, reply, path);
    if (!hostname)
        return;

    const char *datadir = zdc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default — "
                               "deregister must read the directory row first "
                               "to know who owns it", path);
        return;
    }
    /* Required, not optional: deregister must read the row to learn who
     * owns it, so an unreadable node.db must not fall through to
     * NOT_REGISTERED — that would claim the hostname has no row when the
     * truth is that no row was ever read. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the onion directory row",
                                             &db, &ndb))
        return;
    struct db_onion_directory prev;
    memset(&prev, 0, sizeof(prev));
    bool found = db_onion_directory_find(&ndb, hostname, &prev);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!found) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NOT_REGISTERED",
                               "execute", false, false,
                               "this hostname has no directory row on the "
                               "chain this node has folded — there is "
                               "nothing to retire", hostname);
        return;
    }
    if (strcmp(prev.status, ONION_DIRECTORY_STATUS_RETIRED) == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ALREADY_RETIRED",
                               "execute", false, false,
                               "this hostname is already retired — "
                               "deregistering it again would spend a fee to "
                               "say nothing", hostname);
        return;
    }
    if (prev.owner_address[0] == '\0') {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NOT_OWNER",
                               "execute", false, false,
                               "the directory row records no owner address, "
                               "so no signer can ever prove ownership of it "
                               "— this hostname is permanently immutable by "
                               "design", hostname);
        return;
    }

    zcl_native_overlay_intent_run(
        request, reply, "zdir_intent", "deregister", true);
}
