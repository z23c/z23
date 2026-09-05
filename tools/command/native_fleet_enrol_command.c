/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet invite`, `fleet join`, `fleet admit`, `fleet machines` — the CLI
 * half of one-paste fleet enrolment.
 *
 * These four leaves are deliberately NODE-FREE. The box being enrolled has
 * just cloned and built; it has no datadir, no running node and no RPC
 * cookie, so a leaf that asked a node anything would refuse on exactly the
 * machine the owner is trying to add. Everything they need is an Ed25519
 * key under the state root and a pasted string, so that is all they use.
 * Contrast `fleet board *` next door, which is RPC-only on purpose: a board
 * that only one process can see is a notebook. A roster only one machine
 * can see is correct — it is that machine's own record of what its owner
 * admitted.
 *
 * Bound by engine/composition/commands/fleet_enrol.def. The record formats,
 * the refusal tokens and the trust argument live in tools/dev/fleet_enrol.h;
 * this file is the adapter and holds no policy of its own.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"

#include <stdio.h>
#include <string.h>

/* One pasted token or receipt, plus the command word around it. */
#define FE_LINE_MAX (FLEET_ENROL_MACHINE_TEXT_MAX + 64)

static void fe_fail(struct zcl_command_reply *reply, const char *code,
                    const char *stage, const char *message, const char *why)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false, false,
                           message, why ? why : FLEET_ENROL_WHY_ARGUMENTS);
}

static int64_t fe_now(void) { return clock_now_wall_ms() / 1000; }

/* Load this box's key, failing the reply by name when it cannot. */
static bool fe_key(struct zcl_command_reply *reply, bool create,
                   uint8_t seed[FLEET_ENROL_SEED_BYTES],
                   uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES], bool *present)
{
    const char *why = NULL;
    if (fleet_enrol_key_load(seed, pubkey, create, present, &why))
        return true;
    fe_fail(reply, "FLEET_KEY_UNAVAILABLE", "resolve",
            "this box cannot read or create its own fleet key. It lives "
            "under the owner-private state root; set HOME or XDG_STATE_HOME "
            "and check the directory is yours alone.", why);
    return false;
}

/* ── fleet invite ───────────────────────────────────────────────────────── */

static void fe_invite(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char line[FE_LINE_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct fleet_invite invite;
    const struct json_value *in = request ? request->input : NULL;
    const char *name = json_get_str(json_get(in, "name"));
    const char *relay = json_get_str(json_get(in, "relay"));
    const struct json_value *ttl_in = json_get(in, "ttl_hours");
    int64_t ttl = ttl_in ? json_get_int(ttl_in) : FLEET_ENROL_TTL_HOURS_DEFAULT;
    const char *why = NULL;
    bool present = false;
    if (!fleet_enrol_name_valid(name)) {
        fe_fail(reply, "FLEET_NAME_INVALID", "normalize",
                "--name is required and is how you will refer to this "
                "computer from now on: 2 to 24 characters of a-z, 0-9 and "
                "interior dashes, starting and ending with a letter or "
                "digit. Pick something you would say out loud.",
                FLEET_ENROL_WHY_NAME_INVALID);
        return;
    }
    if (!fe_key(reply, true, seed, pubkey, &present))
        return;
    if (!fleet_invite_mint(name, ttl, relay ? relay : "", seed, pubkey,
                           fe_now(), token, sizeof(token), &invite, &why)) {
        fe_fail(reply, "FLEET_INVITE_REFUSED", "execute",
                "this invite was not minted. --ttl-hours is 1 to 168 and "
                "--relay is a host or host:port.", why);
        return;
    }
    zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)snprintf(line, sizeof(line), "z23 fleet join %s", token);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.invite.v1");
    (void)json_push_kv_str(&reply->data, "name", invite.name);
    (void)json_push_kv_int(&reply->data, "expires_at", invite.expires_unix);
    (void)json_push_kv_str(&reply->data, "operator_pubkey", hex);
    (void)json_push_kv_str(&reply->data, "token", token);
    /* The one line the owner pastes. Everything else in this reply is
     * explanation; this field is the product. */
    (void)json_push_kv_str(&reply->data, "join_command", line);
    (void)json_push_kv_str(&reply->data, "paste_to",
                           "the AI agent on the computer being added, after "
                           "it has cloned and built this repository");
}

/* ── fleet join ─────────────────────────────────────────────────────────── */

static void fe_join_facts(struct json_value *out,
                          const struct fleet_box_facts *facts)
{
    struct json_value self;
    json_init(&self);
    json_set_object(&self);
    (void)json_push_kv_str(&self, "hostname", facts->hostname);
    (void)json_push_kv_str(&self, "os", facts->os);
    (void)json_push_kv_str(&self, "os_version", facts->os_version);
    (void)json_push_kv_str(&self, "arch", facts->arch);
    (void)json_push_kv_int(&self, "cores", (int64_t)facts->cores);
    (void)json_push_kv_int(&self, "ram_mb", (int64_t)facts->ram_mb);
    (void)json_push_kv_int(&self, "disk_free_mb", (int64_t)facts->disk_free_mb);
    (void)json_push_kv_str(&self, "toolchain", facts->toolchain);
    (void)json_push_kv_str(&self, "git_head", facts->git_head);
    (void)json_push_kv(out, "self_reported", &self);
    json_free(&self);
}

static void fe_join(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    char line[FE_LINE_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    char ssh[FLEET_ENROL_SSH_MAX + 1];
    struct fleet_invite invite;
    struct fleet_box_facts facts;
    size_t invite_len = 0;
    const char *token = json_get_str(json_get(request ? request->input : NULL,
                                              "token"));
    const char *why = NULL;
    bool present = false;
    if (!fleet_invite_parse(token, &invite, invite_wire, sizeof(invite_wire),
                            &invite_len, &why)) {
        fe_fail(reply, "FLEET_INVITE_INVALID", "normalize",
                "this is not a token this fleet's operator signed. Copy the "
                "whole single line the manager printed, with no line break "
                "in the middle of it.", why);
        return;
    }
    if (invite.expires_unix <= fe_now()) {
        fe_fail(reply, "FLEET_INVITE_EXPIRED", "normalize",
                "this invite has expired. Ask the manager for a fresh one "
                "with `z23 fleet invite`.", FLEET_ENROL_WHY_INVITE_EXPIRED);
        return;
    }
    if (!fe_key(reply, true, seed, pubkey, &present))
        return;
    /* Trust on paste: the owner carried this public key here, so this box
     * records it as ITS operator. Nothing else on this machine gets to
     * decide that, and re-joining with a different owner's invite replaces
     * it deliberately. */
    if (!fleet_enrol_operator_write(invite.operator_pubkey, &why)) {
        fe_fail(reply, "FLEET_OPERATOR_UNWRITABLE", "execute",
                "this box verified the invite but could not record which "
                "operator key it now trusts.", why);
        return;
    }
    fleet_enrol_facts_collect(&facts);
    fleet_enrol_ssh_pubkey(ssh, sizeof(ssh));
    if (!fleet_receipt_mint(invite_wire, invite_len, &facts, ssh, seed, pubkey,
                            receipt, sizeof(receipt), &why)) {
        fe_fail(reply, "FLEET_RECEIPT_REFUSED", "execute",
                "this box could not sign its enrolment receipt.", why);
        return;
    }
    zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)snprintf(line, sizeof(line), "z23 fleet admit %s", receipt);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.join.v1");
    (void)json_push_kv_str(&reply->data, "name", invite.name);
    (void)json_push_kv_str(&reply->data, "box_pubkey", hex);
    (void)json_push_kv_str(&reply->data, "relay", invite.relay);
    (void)json_push_kv_bool(&reply->data, "bridge_key_present", ssh[0] != '\0');
    (void)json_push_kv_str(&reply->data, "receipt", receipt);
    (void)json_push_kv_str(&reply->data, "admit_command", line);
    (void)json_push_kv_str(&reply->data, "paste_to",
                           "the manager computer that printed the invite");
    fe_join_facts(&reply->data, &facts);
    /* The native path this lane does not build. Naming it as a typed field
     * is the honest form of "not yet": it says what comes next and does not
     * pretend the mesh pairing already happened. */
    (void)json_push_kv_str(&reply->data, "next_step",
                           ssh[0] ? "run the admit command on the manager, "
                                    "then pair natively with `ops mesh pair "
                                    "plan` once this box runs a node"
                                  : "no ~/.ssh/z23_fleet.pub on this box, so "
                                    "the admit will record the machine "
                                    "without an ssh bridge");
}

/* ── fleet admit ────────────────────────────────────────────────────────── */

/* Everything the roster must agree to before one line is appended. Split
 * out so the admission decisions read as a list, and so no path can reach
 * the append having skipped one. */
static bool fe_admit_checks(struct zcl_command_reply *reply,
                            const struct fleet_receipt *receipt,
                            const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                            struct fleet_roster_scan *scan, uint16_t *port)
{
    const char *why = NULL;
    bool spent = false;
    if (memcmp(receipt->invite.operator_pubkey, pubkey,
               FLEET_ENROL_PUBKEY_BYTES) != 0) {
        fe_fail(reply, "FLEET_INVITE_NOT_OURS", "authorize",
                "this receipt carries an invite some other key minted. Only "
                "invites this box signed are honoured here.",
                FLEET_ENROL_WHY_INVITE_NOT_OURS);
        return false;
    }
    if (receipt->invite.expires_unix <= fe_now()) {
        fe_fail(reply, "FLEET_INVITE_EXPIRED", "authorize",
                "the invite behind this receipt has expired. Mint a fresh "
                "invite and have the box join again.",
                FLEET_ENROL_WHY_INVITE_EXPIRED);
        return false;
    }
    if (!fleet_nonce_seen(receipt->invite.nonce, &spent, &why)) {
        fe_fail(reply, "FLEET_ROSTER_UNREADABLE", "resolve",
                "this box cannot read its record of spent invites, so it "
                "cannot rule out a replay and will not admit.", why);
        return false;
    }
    if (spent) {
        fe_fail(reply, "FLEET_INVITE_REPLAYED", "authorize",
                "this invite has already been used. One invite enrols one "
                "box, once.", FLEET_ENROL_WHY_INVITE_REPLAYED);
        return false;
    }
    if (!fleet_roster_scan(pubkey, receipt->invite.name, receipt->box_pubkey,
                           scan, &why)) {
        fe_fail(reply, "FLEET_ROSTER_UNREADABLE", "resolve",
                "this box cannot read its machine roster and will not append "
                "to a file it could not check.", why);
        return false;
    }
    if (scan->name_taken) {
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "another computer is already called \"%s\" in this "
                       "fleet, and one name means one machine. Mint the "
                       "invite under a different --name.",
                       receipt->invite.name);
        fe_fail(reply, "FLEET_NAME_TAKEN", "authorize", message,
                FLEET_ENROL_WHY_NAME_TAKEN);
        return false;
    }
    /* A box re-enrolling keeps the port it already has, so re-running admit
     * after a lost reply changes nothing. */
    *port = scan->same_box ? scan->existing_port : scan->next_port;
    if (*port < FLEET_ENROL_PORT_FIRST || *port > FLEET_ENROL_PORT_LAST) {
        fe_fail(reply, "FLEET_ROSTER_FULL", "authorize",
                "every relay port in the assignable range is taken. Retire a "
                "machine before adding another.", FLEET_ENROL_WHY_ROSTER_FULL);
        return false;
    }
    return true;
}

static void fe_admit_bridge(struct zcl_command_reply *reply,
                            const struct fleet_receipt *receipt, uint16_t port,
                            bool wanted)
{
    char line[FLEET_ENROL_SSH_MAX + 256];
    const char *why = NULL;
    bool added = false;
    if (!wanted || !receipt->ssh_pubkey[0]) {
        (void)json_push_kv_bool(&reply->data, "bridge_line_added", false);
        (void)json_push_kv_str(&reply->data, "bridge",
                               receipt->ssh_pubkey[0]
                                   ? "not requested"
                                   : "the box carried no ~/.ssh/z23_fleet.pub");
        return;
    }
    if (!fleet_bridge_line(receipt->ssh_pubkey, port, receipt->invite.name,
                           line, sizeof(line)) ||
        !fleet_bridge_authorize(line, receipt->invite.name, &added, &why)) {
        /* The machine row is already durable. A bridge that could not be
         * written is reported as such, not rolled back: the enrolment
         * happened, and the operator can add the line by hand. */
        (void)json_push_kv_bool(&reply->data, "bridge_line_added", false);
        (void)json_push_kv_str(&reply->data, "bridge",
                               why ? why : FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        (void)zcl_command_reply_add_next(
            reply, "fleet.machines", "{}",
            "the machine is enrolled; the ssh bridge line was not written");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "bridge_line_added", added);
    (void)json_push_kv_str(&reply->data, "bridge",
                           added ? "one restricted port-forwarding line added "
                                   "to ~/.ssh/authorized_keys"
                                 : "a line for this box was already present");
}

static void fe_admit(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char sealed[FLEET_ENROL_MACHINE_TEXT_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct fleet_receipt receipt;
    struct fleet_roster_scan scan = {0};
    const struct json_value *in = request ? request->input : NULL;
    const char *text = json_get_str(json_get(in, "receipt"));
    const char *bridge = json_get_str(json_get(in, "bridge"));
    size_t receipt_len = 0;
    int64_t now = fe_now();
    uint16_t port = 0;
    const char *why = NULL;
    bool present = false;
    if (!fleet_receipt_parse(text, &receipt, receipt_wire,
                             sizeof(receipt_wire), &receipt_len, &why)) {
        fe_fail(reply, "FLEET_RECEIPT_INVALID", "normalize",
                "this is not a receipt a box signed against an invite. Copy "
                "the whole single line the joining computer printed.", why);
        return;
    }
    if (!fe_key(reply, false, seed, pubkey, &present))
        return;
    if (!present) {
        fe_fail(reply, "FLEET_NOT_A_MANAGER", "authorize",
                "this box has never minted an invite, so it holds no key "
                "that could have signed the one in this receipt. Run "
                "`z23 fleet invite` on the manager instead.",
                FLEET_ENROL_WHY_INVITE_NOT_OURS);
        return;
    }
    if (!fe_admit_checks(reply, &receipt, pubkey, &scan, &port))
        return;
    if (!fleet_machine_mint(receipt_wire, receipt_len, now, port, seed, pubkey,
                            sealed, sizeof(sealed), &why) ||
        !fleet_roster_append(sealed, &why)) {
        fe_fail(reply, "FLEET_ROSTER_UNWRITABLE", "execute",
                "this box could not append the machine row, so nothing was "
                "enrolled and the invite is still usable.", why);
        return;
    }
    /* Only now is the invite spent. Burning it earlier would let a failed
     * append cost the owner an invite they would then have to re-mint. */
    if (!fleet_nonce_spend(receipt.invite.nonce, &why))
        (void)json_push_kv_str(&reply->data, "replay_guard_warning", why);
    zcl_hex_encode(receipt.box_pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.admit.v1");
    (void)json_push_kv_str(&reply->data, "name", receipt.invite.name);
    (void)json_push_kv_str(&reply->data, "box_pubkey", hex);
    (void)json_push_kv_int(&reply->data, "relay_port", port);
    (void)json_push_kv_int(&reply->data, "enrolled_at", now);
    (void)json_push_kv_bool(&reply->data, "re_enrolled", scan.same_box);
    fe_admit_bridge(reply, &receipt, port,
                    !(bridge && strcmp(bridge, "no") == 0));
    (void)zcl_command_reply_add_next(reply, "fleet.machines", "{}",
                                     "see the machine this fleet now holds");
}

/* ── fleet machines ─────────────────────────────────────────────────────── */

struct fe_list {
    struct json_value *array;
    uint32_t rendered;
    uint32_t dropped;
};

static void fe_list_row(const struct fleet_machine *machine, void *user)
{
    struct fe_list *list = user;
    struct json_value row;
    /* The roster cannot hold more rows than the closed relay-port range has
     * ports, so this cap can only ever bind on a file somebody grew by
     * hand. It is still counted rather than silently dropped: a fleet map
     * that quietly omits a machine is worse than one that says it did. */
    if (list->rendered >= (uint32_t)FLEET_ENROL_ROSTER_MAX) {
        list->dropped++;
        return;
    }
    json_init(&row);
    fleet_machine_render(machine, &row);
    if (json_push_back(list->array, &row)) list->rendered++;
    else list->dropped++;
    json_free(&row);
}

static void fe_machines(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own[FLEET_ENROL_PUBKEY_BYTES];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct json_value array;
    struct fe_list list = { &array, 0, 0 };
    struct fleet_roster_scan scan = {0};
    const char *why = NULL;
    bool joined = false, own_present = false;
    (void)request;
    /* Whose roster is this? On a box that joined a fleet, the operator is
     * the key the owner pasted; on the manager, it is this box's own key.
     * A box that has done neither has no roster, which is a state, not an
     * error. */
    if (!fleet_enrol_operator_read(operator_pubkey, &joined, &why)) {
        fe_fail(reply, "FLEET_OPERATOR_UNREADABLE", "resolve",
                "this box has a recorded fleet operator key it cannot read.",
                why);
        return;
    }
    if (!joined) {
        if (!fleet_enrol_key_load(seed, own, false, &own_present, &why)) {
            fe_fail(reply, "FLEET_KEY_UNAVAILABLE", "resolve",
                    "this box cannot read its own fleet key.", why);
            return;
        }
        memcpy(operator_pubkey, own, FLEET_ENROL_PUBKEY_BYTES);
    }
    json_init(&array);
    json_set_array(&array);
    if (!fleet_roster_each(operator_pubkey, fe_list_row, &list, &scan, &why)) {
        json_free(&array);
        fe_fail(reply, "FLEET_ROSTER_UNREADABLE", "resolve",
                "this box cannot read its machine roster.", why);
        return;
    }
    zcl_hex_encode(operator_pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.machines.v1");
    (void)json_push_kv_str(&reply->data, "operator_pubkey",
                           joined || own_present ? hex : "");
    (void)json_push_kv_bool(&reply->data, "joined", joined);
    (void)json_push_kv_int(&reply->data, "total", (int64_t)scan.rows);
    (void)json_push_kv_int(&reply->data, "returned", (int64_t)list.rendered);
    (void)json_push_kv_bool(&reply->data, "truncated", list.dropped != 0);
    /* Counted, never rendered: a line this operator key did not seal is
     * somebody else's row or a corrupted one, and either way it is not
     * evidence about this fleet. */
    (void)json_push_kv_int(&reply->data, "unverifiable",
                           (int64_t)scan.unverifiable);
    (void)json_push_kv(&reply->data, "machines", &array);
    json_free(&array);
    if (scan.rows == 0)
        (void)zcl_command_reply_add_next(
            reply, "fleet.invite", "{\"name\":\"<box>\"}",
            "no machine has enrolled here yet; mint an invite to add one");
}

void zcl_native_fleet_enrol_dispatch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *path = request && request->spec ? request->spec->path : NULL;
    if (path && strcmp(path, "fleet.invite") == 0)
        fe_invite(request, reply);
    else if (path && strcmp(path, "fleet.join") == 0)
        fe_join(request, reply);
    else if (path && strcmp(path, "fleet.admit") == 0)
        fe_admit(request, reply);
    else if (path && strcmp(path, "fleet.machines") == 0)
        fe_machines(request, reply);
    else
        fe_fail(reply, "FLEET_COMMAND_INVALID", "dispatch",
                "fleet enrolment dispatch requires an exact leaf path", "");
}
