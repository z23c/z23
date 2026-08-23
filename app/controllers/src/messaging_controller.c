/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Messaging RPC controller.
 *
 * Commands:
 *   msg_send   — send P2P message to a connected peer
 *   msg_inbox  — list messages (all or unread only)
 *   msg_read   — mark message as read, return content */

#include "platform/time_compat.h"
#include "net/zmsg.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/connman.h"
#include "controllers/network_controller.h"
#include "sapling/params_init.h"     /* sapling_params_loaded (diagnostics) */
#include "sapling/sapling_prover.h"  /* prover readiness = can we send on-chain */
#include "chain/chainparams.h"
#include "models/znam.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "rpc/server.h"
#include "models/database.h"
#include "crypto/sha3.h"
#include "core/serialize.h"
#include "views/format_helpers.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "util/log_macros.h"

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_msg_ndb = NULL;
static struct connman *g_msg_connman = NULL;

void rpc_msg_set_state(struct node_db *ndb, struct connman *cm)
{
    g_msg_ndb = ndb;
    g_msg_connman = cm;
}

/* z_sendmany RPC handler (app/controllers/src/wallet_shielded_send.c). The
 * on-chain ZMSG send composes this exact machinery (coin selection, Sapling
 * output proof, binding sig, relay) rather than duplicating proof construction
 * — declared here to avoid pulling the heavy wallet-internal header. */
bool rpc_z_sendmany(const struct json_value *params, bool help,
                    struct json_value *result);

/* ── Helpers ────────────────────────────────────────────────────── */

static void msg_to_json(const struct zmsg_message *msg, struct json_value *obj)
{
    json_set_object(obj);
    char hex[65];
    HexStr(msg->msg_id, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "msg_id", hex);
    json_push_kv_str(obj, "direction",
                     msg->direction == ZMSG_OUTBOUND ? "outbound" : "inbound");
    json_push_kv_str(obj, "channel",
                     msg->channel == ZMSG_CHANNEL_P2P ? "p2p" : "onchain");
    json_push_kv_str(obj, "sender", msg->sender);
    json_push_kv_str(obj, "recipient", msg->recipient);
    json_push_kv_str(obj, "body", msg->body);
    json_push_kv_int(obj, "timestamp", msg->timestamp);
    json_push_kv_bool(obj, "read", msg->read);
}

/* ── msg_send (on-chain channel) ────────────────────────────────── */

/* Build + broadcast a shielded tx carrying the message in the Sapling memo,
 * by composing z_sendmany. Fails CLOSED (clear error body) when the Sapling
 * prover params are not loaded or the funding address / recipient is bad. */
static bool msg_send_onchain(const char *to_addr, const char *body,
                             const char *from_addr, const char *reply_hex,
                             struct json_value *result)
{
    /* On-chain ZMSG rides a shielded transaction, so it needs BOTH the params
     * on disk and a proving backend in the build. Checking only the params
     * would report ready on a build with no proving backend (params load fine
     * there; only proving is absent) and then fail deep in the stack with a
     * vaguer message. */
    if (!zclassic_sapling_prover_is_ready()) {
        char err[320];
        snprintf(err, sizeof(err),
                 "On-chain ZMSG unavailable: cannot build a shielded "
                 "transaction (backend=%s, status=%s)",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        json_set_str(result, err);
        LOG_FAIL("zmsg",
                 "msg_send onchain: prover not ready: backend=%s status=%s "
                 "params_loaded=%d",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status(),
                 (int)sapling_params_loaded());
    }
    if (!to_addr || strncmp(to_addr, "zs1", 3) != 0) {
        json_set_str(result,
            "On-chain ZMSG requires a shielded (zs1...) recipient address");
        LOG_FAIL("zmsg", "msg_send onchain: recipient is not a z-address");
    }
    if (!from_addr || !from_addr[0]) {
        json_set_str(result,
            "On-chain ZMSG requires a from_address (4th arg) to fund the "
            "dust output");
        LOG_FAIL("zmsg", "msg_send onchain: missing from_address");
    }
    size_t blen = body ? strlen(body) : 0;
    if (blen == 0 || blen > ZMSG_MEMO_MAX_PAYLOAD) {
        json_set_str(result,
            "Message empty or exceeds on-chain ZMSG payload max (474 bytes)");
        LOG_FAIL("zmsg", "msg_send onchain: body len=%zu out of range", blen);
    }

    uint8_t reply_to[32];
    bool has_reply = false;
    if (reply_hex && reply_hex[0]) {
        if (!zcl_is_hex_string(reply_hex, 64)) {
            json_set_str(result, "Invalid reply_to (64-char hex msg_id)");
            LOG_FAIL("zmsg", "msg_send onchain: bad reply_to hex");
        }
        (void)ParseHex(reply_hex, reply_to, 32);
        has_reply = true;
    }

    uint8_t memo[ZMSG_MEMO_LEN];
    if (!zmsg_memo_encode(memo, (const uint8_t *)body, blen,
                          has_reply ? reply_to : NULL)) {
        json_set_str(result, "Failed to encode ZMSG memo");
        LOG_FAIL("zmsg", "msg_send onchain: memo encode failed");
    }
    char memohex[ZMSG_MEMO_LEN * 2 + 1];
    HexStr(memo, ZMSG_MEMO_LEN, false, memohex, sizeof(memohex));

    /* Compose z_sendmany: ["<from>", [{address,amount,memo_hex}]]. */
    struct json_value zparams = {0};
    json_set_array(&zparams);
    struct json_value jfrom = {0};
    json_set_str(&jfrom, from_addr);
    json_push_back(&zparams, &jfrom);
    json_free(&jfrom);
    struct json_value jarr = {0};
    json_set_array(&jarr);
    struct json_value jrec = {0};
    json_set_object(&jrec);
    json_push_kv_str(&jrec, "address", to_addr);
    json_push_kv_int(&jrec, "amount", ZMSG_ONCHAIN_DUST_ZAT);
    json_push_kv_str(&jrec, "memo_hex", memohex);
    json_push_back(&jarr, &jrec);
    json_free(&jrec);
    json_push_back(&zparams, &jarr);
    json_free(&jarr);

    struct json_value sub = {0};
    bool ok = rpc_z_sendmany(&zparams, false, &sub);
    json_free(&zparams);
    if (!ok) {
        const char *emsg = json_get_str(&sub);
        char buf[256];
        snprintf(buf, sizeof(buf), "on-chain ZMSG send failed: %s",
                 emsg ? emsg : "(no detail)");
        json_set_str(result, buf);
        json_free(&sub);
        LOG_FAIL("zmsg", "msg_send onchain: z_sendmany rejected");
    }
    const char *txid_hex = json_get_str(&sub);   /* success => txid string */

    /* Store our outbound copy. */
    struct zmsg_message m;
    memset(&m, 0, sizeof(m));
    m.direction = ZMSG_OUTBOUND;
    m.channel = ZMSG_CHANNEL_ONCHAIN;
    m.timestamp = (int64_t)platform_time_wall_time_t();
    snprintf(m.sender, sizeof(m.sender), "self");
    snprintf(m.recipient, sizeof(m.recipient), "%s", to_addr);
    snprintf(m.body, sizeof(m.body), "%s", body);
    if (txid_hex && zcl_is_hex_string(txid_hex, 64))
        (void)ParseHex(txid_hex, m.txid, 32);
    zmsg_compute_id(&m, m.msg_id);
    zmsg_store_add(&m);
    if (g_msg_ndb)
        db_zmsg_save(g_msg_ndb, &m);

    json_set_object(result);
    char idhex[65];
    HexStr(m.msg_id, 32, false, idhex, sizeof(idhex));
    json_push_kv_str(result, "msg_id", idhex);
    json_push_kv_str(result, "channel", "onchain");
    json_push_kv_str(result, "recipient", to_addr);
    if (txid_hex)
        json_push_kv_str(result, "txid", txid_hex);
    json_push_kv_str(result, "status", "sent");
    json_free(&sub);
    printf("zmsg: sent on-chain message to %s\n", to_addr);
    return true;
}

/* ── msg_send ───────────────────────────────────────────────────── */

static bool rpc_msg_send(const struct json_value *params, bool help,
                         struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "msg_send recipient \"message\" [channel] [from_address] [reply_to]\n"
            "\nSend a message. Two channels:\n"
            "  p2p (default) — instant, free, to a connected peer\n"
            "  onchain       — permanent, shielded Sapling memo transaction\n"
            "\nArguments:\n"
            "1. recipient    (p2p: number peer ID | onchain: zs1... address)\n"
            "2. message      (string) Message text (onchain max 474 bytes)\n"
            "3. channel      (string, optional) \"p2p\" (default) or \"onchain\"\n"
            "4. from_address (string) onchain only: funding z/t address (required)\n"
            "5. reply_to     (string, optional) onchain only: 64-hex parent msg_id\n"
            "\nResult: message ID and delivery/broadcast status.\n");
        return true;
    }

    /* Channel selection — P2P is the default (backward compatible). */
    const char *channel_str = json_size(params) >= 3
                                  ? json_get_str(json_at(params, 2)) : NULL;
    if (channel_str && strcmp(channel_str, "onchain") == 0) {
        const char *to_addr = json_get_str(json_at(params, 0));
        const char *body = json_get_str(json_at(params, 1));
        const char *from_addr = json_size(params) >= 4
                                    ? json_get_str(json_at(params, 3)) : NULL;
        const char *reply_hex = json_size(params) >= 5
                                    ? json_get_str(json_at(params, 4)) : NULL;
        return msg_send_onchain(to_addr, body, from_addr, reply_hex, result);
    }
    if (channel_str && strcmp(channel_str, "p2p") != 0) {
        json_set_str(result, "Invalid channel (expected \"p2p\" or \"onchain\")");
        LOG_FAIL("zmsg", "msg_send: invalid channel '%s'", channel_str);
    }

    int64_t peer_id = json_get_int(json_at(params, 0));
    const char *body = json_get_str(json_at(params, 1));

    if (!body || !body[0]) {
        json_set_str(result, "Empty message");
        return false;
    }

    if (!g_msg_connman) {
        json_set_str(result, "Network not available");
        return false;
    }

    /* Find the peer */
    struct p2p_node *target = NULL;
    zcl_mutex_lock(&g_msg_connman->manager.cs_nodes);
    for (size_t i = 0; i < g_msg_connman->manager.num_nodes; i++) {
        struct p2p_node *node = g_msg_connman->manager.nodes[i];
        if (node->id == peer_id && !node->disconnect) {
            target = node;
            break;
        }
    }

    if (!target) {
        zcl_mutex_unlock(&g_msg_connman->manager.cs_nodes);
        json_set_str(result, "Peer not found or disconnected");
        return false;
    }

    /* Build the message */
    struct zmsg_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.direction = ZMSG_OUTBOUND;
    msg.channel = ZMSG_CHANNEL_P2P;
    msg.timestamp = (int64_t)platform_time_wall_time_t();
    snprintf(msg.sender, sizeof(msg.sender), "self");
    snprintf(msg.recipient, sizeof(msg.recipient), "peer:%lld",
             (long long)peer_id);
    snprintf(msg.body, sizeof(msg.body), "%s", body);

    /* Compute msg_id */
    zmsg_compute_id(&msg, msg.msg_id);

    /* Serialize and send */
    struct byte_stream os;
    stream_init(&os, 512);
    zmsg_serialize(&msg, &os);

    p2p_node_begin_message(target, MSG_ZMSG,
                           g_msg_connman->params->pchMessageStart);
    p2p_node_write_message_data(target, os.data, os.size);
    p2p_node_end_message(target);
    stream_free(&os);

    zcl_mutex_unlock(&g_msg_connman->manager.cs_nodes);

    /* Store locally */
    zmsg_store_add(&msg);
    if (g_msg_ndb)
        db_zmsg_save(g_msg_ndb, &msg);

    /* Return result */
    json_set_object(result);
    char hex[65];
    HexStr(msg.msg_id, 32, false, hex, sizeof(hex));
    json_push_kv_str(result, "msg_id", hex);
    json_push_kv_int(result, "peer_id", peer_id);
    json_push_kv_str(result, "status", "sent");

    LOG_INFO("zmsg", "event=message_sent msg_id=%s peer_id=%lld "
             "body_bytes=%zu",
             hex, (long long)peer_id, strlen(msg.body));
    return true;
}

/* ── msg_inbox ──────────────────────────────────────────────────── */

static bool rpc_msg_inbox(const struct json_value *params, bool help,
                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "msg_inbox [unread_only=false]\n"
            "\nList messages in the inbox.\n"
            "\nArguments:\n"
            "1. unread_only (bool, optional) Only show unread messages\n");
        return true;
    }

    bool unread_only = false;
    if (params && json_size(params) > 0) {
        const struct json_value *arg0 = json_at(params, 0);
        if (arg0) unread_only = json_get_int(arg0) != 0;
    }

    json_set_array(result);

    struct zmsg_message msgs[50];
    int count = 0;

    /* Try SQLite first, fall back to in-memory store */
    if (g_msg_ndb)
        count = db_zmsg_list(g_msg_ndb, msgs, 50, unread_only);
    if (count == 0)
        count = zmsg_store_list(msgs, 50, unread_only);

    for (int i = 0; i < count; i++) {
        struct json_value e = {0};
        msg_to_json(&msgs[i], &e);
        json_push_back(result, &e);
        json_free(&e);
    }

    return true;
}

/* ── msg_read ───────────────────────────────────────────────────── */

static bool rpc_msg_read(const struct json_value *params, bool help,
                         struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "msg_read \"msg_id\"\n"
            "\nMark a message as read and return its content.\n"
            "\nArguments:\n"
            "1. msg_id (string) 64-char hex message ID\n");
        return true;
    }

    const char *hex = json_get_str(json_at(params, 0));
    if (!zcl_is_hex_string(hex, 64)) {
        json_set_str(result, "Invalid msg_id (64-char hex)");
        return false;
    }

    uint8_t msg_id[32];
    (void)ParseHex(hex, msg_id, 32);  /* hex already validated by zcl_is_hex_string */

    zmsg_store_mark_read(msg_id);
    if (g_msg_ndb)
        db_zmsg_mark_read(g_msg_ndb, msg_id);

    json_set_object(result);
    json_push_kv_str(result, "msg_id", hex);
    json_push_kv_str(result, "status", "read");
    return true;
}

/* ── msg_send_named ─────────────────────────────────────────────── */

static bool rpc_msg_send_named(const struct json_value *params, bool help,
                               struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "msg_send_named \"name\" \"message\"\n"
            "\nSend a message using a ZCL Name. Resolves the name first.\n"
            "\nArguments:\n"
            "1. name    (string) ZCL Name to resolve (e.g. \"alice\")\n"
            "2. message (string) Message text\n"
            "\nThe name is resolved to find the recipient's address/onion.\n"
            "The message is stored locally with the resolved identity.\n");
        return true;
    }

    const char *name = json_get_str(json_at(params, 0));
    const char *body = json_get_str(json_at(params, 1));

    if (!name || !name[0] || !body || !body[0]) {
        json_set_str(result, "name and message required");
        return false;
    }

    /* Resolve the ZCL Name */
    struct znam_entry entry;
    if (!g_msg_ndb || !db_znam_find(g_msg_ndb, name, &entry)) {
        json_set_str(result, "Name not found");
        return false;
    }

    /* Build and store the message */
    struct zmsg_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.direction = ZMSG_OUTBOUND;
    msg.channel = ZMSG_CHANNEL_P2P;
    msg.timestamp = (int64_t)platform_time_wall_time_t();
    snprintf(msg.sender, sizeof(msg.sender), "self");
    snprintf(msg.recipient, sizeof(msg.recipient), "%s (%s)",
             name, entry.target_value);
    snprintf(msg.body, sizeof(msg.body), "%s", body);
    zmsg_compute_id(&msg, msg.msg_id);

    zmsg_store_add(&msg);
    if (g_msg_ndb)
        db_zmsg_save(g_msg_ndb, &msg);

    json_set_object(result);
    char hex[65];
    HexStr(msg.msg_id, 32, false, hex, sizeof(hex));
    json_push_kv_str(result, "msg_id", hex);
    json_push_kv_str(result, "resolved_name", name);
    json_push_kv_str(result, "resolved_to", entry.target_value);

    const char *type = "unknown";
    if (entry.target_type == ZNAM_TYPE_ONION) type = "onion";
    else if (entry.target_type == ZNAM_TYPE_ZADDR) type = "z-address";
    else if (entry.target_type == ZNAM_TYPE_TADDR) type = "t-address";
    json_push_kv_str(result, "target_type", type);
    json_push_kv_str(result, "status", "queued");
    json_push_kv_str(result, "note",
        "Message stored. Delivery will occur when peer is connected.");

    printf("zmsg: message to '%s' -> %s (%s)\n",
           name, entry.target_value, type);
    return true;
}

/* ── REST API ───────────────────────────────────────────────────── */

bool api_msg_inbox(struct json_value *result)
{
    return rpc_msg_inbox(NULL, false, result);
}

/* ── Diagnostics: `ops state --subsystem=messaging` ──────────────────
 *
 * See CLAUDE.md "Adding state introspection". Reports the two ZMSG channels'
 * live readiness (off-chain P2P is always available but plaintext on the wire;
 * the on-chain Sapling-memo channel needs the prover params loaded), whether
 * the controller is wired to a node_db + connman, ZMSG wire counters owned by
 * the message processor, and the in-memory inbox store occupancy. No SQLite
 * scan — these are atomic loads plus one bounded store-mutex acquire, so this
 * is safe on the health-rollup hot path. */
bool messaging_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    bool db_open = g_msg_ndb != NULL;
    bool net_up = g_msg_connman != NULL;
    struct msg_processor *mp = rpc_net_get_msg_processor();
    struct msg_zmsg_stats transport;
    msg_processor_get_zmsg_stats(mp, &transport);
    /* READY means a shielded tx can actually be built: params on disk AND a
     * proving backend compiled into this binary. Reporting only the former
     * advertised a channel that cannot send on a build with no proving
     * backend. */
    bool onchain_ready = zclassic_sapling_prover_is_ready();

    json_push_kv_bool(out, "controller_wired", db_open && net_up);
    json_push_kv_bool(out, "db_open", db_open);
    json_push_kv_bool(out, "network_available", net_up);
    json_push_kv_bool(out, "p2p_channel_available", true);
    json_push_kv_bool(out, "transport_telemetry_wired", mp != NULL);
    json_push_kv_int(out, "frames_received",
                     (int64_t)transport.frames_received);
    json_push_kv_int(out, "messages_accepted",
                     (int64_t)transport.messages_accepted);
    json_push_kv_int(out, "duplicates", (int64_t)transport.duplicates);
    json_push_kv_int(out, "acknowledgements_received",
                     (int64_t)transport.acknowledgements_received);
    json_push_kv_int(out, "last_received_unix",
                     transport.last_received_unix);
    json_push_kv_int(out, "last_ack_unix", transport.last_ack_unix);
    json_push_kv_bool(out, "onchain_channel_ready", onchain_ready);
    json_push_kv_bool(out, "sapling_params_loaded", sapling_params_loaded());
    json_push_kv_str(out, "onchain_prover_backend",
                     zclassic_sapling_prover_backend());
    json_push_kv_str(out, "onchain_prover_status",
                     zclassic_sapling_prover_status());
    json_push_kv_int(out, "inbox_store_count", (int64_t)zmsg_store_count());
    json_push_kv_int(out, "inbox_store_cap", (int64_t)ZMSG_MAX_STORED);
    json_push_kv_int(out, "onchain_memo_max_bytes",
                     (int64_t)ZMSG_MEMO_MAX_PAYLOAD);

    diag_push_health(out, true,
                     onchain_ready
                         ? "messaging ready (p2p + on-chain)"
                         : "messaging ready (p2p only; on-chain send needs "
                           "a Sapling proving backend)");
    return true;
}

/* ── Registration ───────────────────────────────────────────────── */

void register_msg_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "messaging", "msg_send",       rpc_msg_send,       true },
        { "messaging", "msg_send_named", rpc_msg_send_named, true },
        { "messaging", "msg_inbox",      rpc_msg_inbox,      true },
        { "messaging", "msg_read",       rpc_msg_read,       true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
