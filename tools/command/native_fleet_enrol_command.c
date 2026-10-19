/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet invite`, `fleet join`, `fleet admit`, `fleet import`, `fleet
 * machines` — the CLI half of one-paste fleet enrolment.
 *
 * These five leaves are deliberately NODE-FREE. The box being enrolled has
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

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "fleet_enrol.h"
#include "fleet_roles.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "platform/clock.h"
#include "vcs/zcode_dht_identity.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* One pasted token or receipt, plus the command word around it. */
#define FE_LINE_MAX (FLEET_ENROL_MACHINE_TEXT_MAX + 64)

static void fe_fail_mut(struct zcl_command_reply *reply, const char *code,
                        const char *stage, const char *message,
                        const char *why, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false,
                           mutated, message,
                           why ? why : FLEET_ENROL_WHY_ARGUMENTS);
}

static void fe_fail(struct zcl_command_reply *reply, const char *code,
                    const char *stage, const char *message, const char *why)
{
    fe_fail_mut(reply, code, stage, message, why, false);
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

/* ── the fleet root as a ZID anchor (ZRC 0012 step 1) ───────────────────── */

/* The datadir whose zid_identities projection answers "is this operator key
 * anchored?". An explicit `datadir` input wins; else only a datadir the CLI
 * was GIVEN (--datadir). The default datadir is never opened for this: these
 * leaves are node-free, and a fleet command quietly reading the operator's
 * live node.db is not something they promise. NULL means nobody looked. */
static const char *fe_anchor_datadir(const struct zcl_command_request *request)
{
    const char *dd = request ? json_get_str(json_get(request->input, "datadir"))
                             : NULL;
    if (dd && dd[0])
        return dd;
    return zcl_native_command_datadir_is_explicit()
               ? zcl_native_command_datadir() : NULL;
}

static enum fleet_anchor_state fe_anchor_state_of(const struct zid_identity *r)
{
    if (strcmp(r->status, ZID_IDENTITY_STATUS_ACTIVE) == 0)
        return FLEET_ANCHOR_ACTIVE;
    if (strcmp(r->status, ZID_IDENTITY_STATUS_ROTATED) == 0)
        return FLEET_ANCHOR_ROTATED;
    if (strcmp(r->status, ZID_IDENTITY_STATUS_REVOKED) == 0)
        return FLEET_ANCHOR_REVOKED;
    return FLEET_ANCHOR_UNREADABLE; /* a status this build does not know */
}

/* One READ-ONLY lookup (never CREATE, never READWRITE): an absent node.db is
 * "unchecked" — this host has no folded chain, which is a state, not an
 * error — while a node.db that exists and cannot be read is "unreadable",
 * which a required anchor must NOT treat as "no anchor was needed". */
static void fe_anchor_lookup(const struct zcl_command_request *request,
                             const uint8_t key[FLEET_ENROL_PUBKEY_BYTES],
                             struct fleet_anchor_fact *out)
{
    const char *datadir = fe_anchor_datadir(request);
    struct sqlite3 *db = NULL;
    struct node_db ndb;
    struct zid_identity row;
    enum zcl_node_db_ro_status st;
    memset(out, 0, sizeof(*out));
    out->state = FLEET_ANCHOR_UNCHECKED;
    if (!datadir)
        return;
    st = zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0);
    if (st == ZCL_NODE_DB_RO_ABSENT || st == ZCL_NODE_DB_RO_NO_DATADIR)
        return;
    if (st != ZCL_NODE_DB_RO_OK) {
        out->state = FLEET_ANCHOR_UNREADABLE;
        return;
    }
    if (!db_zid_identity_find(&ndb, key, &row)) {
        out->state = FLEET_ANCHOR_NOT_ANCHORED;
    } else {
        out->state = fe_anchor_state_of(&row);
        out->anchor_height = row.anchor_height;
        out->has_successor = row.has_successor;
        if (row.has_successor)
            memcpy(out->successor, row.successor_pubkey,
                   FLEET_ENROL_PUBKEY_BYTES);
    }
    zcl_native_node_db_close_readonly(&db, &ndb);
}

/* --require_anchor is a STRING input, like --bridge: the catalog types a
 * bare key as a string and boolean keys are a closed table. Absent, "no",
 * "false" and "0" leave the anchor optional; ANY other value requires it, so
 * a typo fails closed rather than quietly turning the requirement off. */
static bool fe_anchor_required(const struct zcl_command_request *request)
{
    const char *v = request ? json_get_str(json_get(request->input,
                                                    "require_anchor"))
                            : NULL;
    if (!v || !v[0])
        return false;
    return strcmp(v, "no") != 0 && strcmp(v, "false") != 0 &&
           strcmp(v, "0") != 0;
}

/* The reported anchor state: its own object, never merged into what the
 * operator seal attests. `refusal` is what a REQUIRED anchor would answer,
 * so a reader sees the verdict even when nothing was required. */
static void fe_anchor_render(struct zcl_command_reply *reply,
                             const struct fleet_anchor_fact *fact,
                             bool required)
{
    struct json_value obj;
    const char *refusal = fleet_root_anchor_refusal(fact, true);
    char hex[FLEET_ENROL_PUBKEY_HEX];
    json_init(&obj);
    json_set_object(&obj);
    (void)json_push_kv_str(&obj, "state", fleet_anchor_state_name(fact->state));
    (void)json_push_kv_bool(&obj, "required", required);
    (void)json_push_kv_str(&obj, "would_refuse_as", refusal ? refusal : "");
    (void)json_push_kv_int(&obj, "anchor_height", fact->anchor_height);
    if (fact->has_successor)
        zcl_hex_encode(fact->successor, FLEET_ENROL_PUBKEY_BYTES, hex);
    else
        hex[0] = '\0';
    (void)json_push_kv_str(&obj, "successor", hex);
    (void)json_push_kv(&reply->data, "operator_anchor", &obj);
    json_free(&obj);
}

static void fe_anchor_refuse(struct zcl_command_reply *reply,
                             const char *token)
{
    fe_fail(reply, "FLEET_ROOT_NOT_ANCHORED", "authorize",
            "--require_anchor=yes was given and the operator key is not an active "
            "ZID anchor in the node.db read. Anchor it with `z23 core "
            "identity anchor`, or drop --require_anchor.", token);
}

/* Read the root's anchor state BEFORE anything is checked or spent, so a
 * refusal under --require_anchor leaves the invite usable. False means the
 * reply is already failed; true leaves the fact for the caller to render. */
static bool fe_anchor_gate(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           const uint8_t key[FLEET_ENROL_PUBKEY_BYTES],
                           struct fleet_anchor_fact *fact)
{
    const char *refusal = NULL;
    fe_anchor_lookup(request, key, fact);
    refusal = fleet_root_anchor_refusal(fact, fe_anchor_required(request));
    if (refusal)
        fe_anchor_refuse(reply, refusal);
    return refusal == NULL;
}

/* ── fleet invite ───────────────────────────────────────────────────────── */

static void fe_invite(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char line[FE_LINE_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    /* Every fleet record this file declares is zero-initialised, without
     * exception and whether or not the callee is known to fill it. The
     * exception is what cost us: this struct was raw stack, the mint left
     * `nonce` untouched, the stack happened to be zeros, and every invite
     * this manager ever minted carried the same all-zero nonce — so the
     * second `fleet admit` was a replay and the fleet could hold exactly
     * one machine. A blanket rule is cheaper to keep true than a
     * per-callee argument about who initialises what. */
    struct fleet_invite invite = {0};
    struct fleet_anchor_fact anchor = {0};
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
                "this invite was not minted. --ttl_hours is 1 to 168 and "
                "--relay is a host or host:port.", why);
        return;
    }
    zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)snprintf(line, sizeof(line), "z23 fleet join %s", token);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.invite.v1");
    (void)json_push_kv_str(&reply->data, "name", invite.name);
    (void)json_push_kv_int(&reply->data, "expires_at", invite.expires_unix);
    (void)json_push_kv_str(&reply->data, "operator_pubkey", hex);
    fe_anchor_lookup(request, pubkey, &anchor);
    fe_anchor_render(reply, &anchor, false);
    (void)json_push_kv_str(&reply->data, "token", token);
    /* The one line the owner pastes. Everything else in this reply is
     * explanation; this field is the product. */
    (void)json_push_kv_str(&reply->data, "join_command", line);
    (void)json_push_kv_str(&reply->data, "paste_to",
                           "the AI agent on the computer being added, after "
                           "it has cloned and built this repository");
}

/* ── fleet join ─────────────────────────────────────────────────────────── */

static void fe_join_facts(struct json_value *out, const char *onion,
                          const struct fleet_box_facts *facts)
{
    struct json_value self;
    json_init(&self);
    json_set_object(&self);
    (void)json_push_kv_str(&self, "onion", onion);
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

/* The key this box will SIGN board posts and ledger rows with, when it
 * already has one: the node's DHT online key, in its datadir. LOAD
 * ONLY. `fleet join` runs on a box that may never have started a node,
 * and minting a durable node identity as a side effect of joining is a
 * decision this leaf has no business making. A box with no key yet
 * names none, and the reply says what to do about that. */
static const struct fleet_signing_key *fe_signing_key(
    struct fleet_signing_key *out)
{
    const char *datadir = zcl_native_command_datadir();
    char err[160];
    memset(out, 0, sizeof(*out));
    if (!datadir ||
        !vcs_zcode_dht_online_key_load(datadir, out->seed, out->pubkey, err,
                                       sizeof(err)))
        return NULL;
    return out;
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
    struct fleet_invite invite = {0};
    struct fleet_box_facts facts = {0};
    struct fleet_signing_key signing;
    const struct fleet_signing_key *signer = NULL;
    size_t invite_len = 0;
    const char *token = json_get_str(json_get(request ? request->input : NULL,
                                              "token"));
    /* Self-reported and optional. The owner (or the agent on this box) says
     * where this machine will answer; this lane does not run a node and has
     * nothing to read the address off, and inventing one would be worse than
     * an empty column. */
    const char *onion = json_get_str(json_get(request ? request->input : NULL,
                                              "onion"));
    const char *why = NULL;
    bool present = false;
    if (!onion) onion = "";
    if (!fleet_enrol_onion_valid(onion)) {
        fe_fail(reply, "FLEET_ONION_INVALID", "normalize",
                "--onion must be this box's v3 onion hostname: 56 lowercase "
                "letters and digits 2-7, then .onion, with an optional :port. "
                "Leave it off if this box has no persistent onion yet.",
                FLEET_ENROL_WHY_ONION_INVALID);
        return;
    }
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
    /* Loaded here, at the last moment before it is used, so no refusal
     * path above leaves a private seed sitting in this frame. */
    signer = fe_signing_key(&signing);
    if (!fleet_receipt_mint(invite_wire, invite_len, onion, &facts, ssh, seed,
                            pubkey, signer, receipt, sizeof(receipt), &why)) {
        fe_fail(reply, "FLEET_RECEIPT_REFUSED", "execute",
                "this box could not sign its enrolment receipt.", why);
        return;
    }
    memset(&signing, 0, sizeof(signing)); /* the seed leaves no trace */
    zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)snprintf(line, sizeof(line), "z23 fleet admit %s", receipt);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.join.v1");
    (void)json_push_kv_str(&reply->data, "name", invite.name);
    (void)json_push_kv_str(&reply->data, "box_pubkey", hex);
    (void)json_push_kv_str(&reply->data, "relay", invite.relay);
    (void)json_push_kv_bool(&reply->data, "bridge_key_present", ssh[0] != '\0');
    /* Typed, because the operator needs to know whether admitting this
     * receipt will cover the key this box signs with. */
    (void)json_push_kv_bool(&reply->data, "signing_key_named",
                            signer != NULL);
    (void)json_push_kv_str(
        &reply->data, "signing_key",
        signer ? "named in this receipt, so admitting it grants a role to "
                 "the key this box will post and replicate with"
               : "this box has not started a node yet, so this receipt "
                 "names none; run `z23 fleet join` again after the first "
                 "node start and admit that receipt too");
    (void)json_push_kv_str(&reply->data, "receipt", receipt);
    (void)json_push_kv_str(&reply->data, "admit_command", line);
    (void)json_push_kv_str(&reply->data, "paste_to",
                           "the manager computer that printed the invite");
    fe_join_facts(&reply->data, onion, &facts);
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

/* All-zero: the receipt named no signing key. A key of all zeroes is
 * not a key — ed25519 refuses the identity point — so this cannot
 * collide with a real one. */
static const uint8_t k_fe_no_key[FLEET_ENROL_PUBKEY_BYTES] = {0};

/* Admitting a machine IS the operator's decision to trust it, so the role
 * that decision implies is minted here rather than left as a second command
 * the owner has to remember. Idempotent: re-admitting a box that already
 * holds `worker` writes no second row.
 *
 * A refusal is reported, never fatal. `fleet admit` is deliberately
 * node-free — the box being admitted has no datadir yet and neither may the
 * manager — so a manager with no operator identity still enrols the machine
 * and says plainly that the grant is outstanding. */

static void fe_admit_role(struct zcl_command_reply *reply,
                          const struct fleet_receipt *receipt,
                          int64_t now)
{
    const char *why = NULL;
    const char *datadir = zcl_native_command_datadir();
    bool granted = datadir &&
                   zcl_fleet_roles_grant_worker(datadir,
                                                receipt->box_pubkey,
                                                now, &why);
    (void)json_push_kv_bool(&reply->data, "worker_role_granted", granted);
    if (!granted)
        (void)json_push_kv_str(&reply->data, "worker_role_why",
                               why ? why : "this box has no datadir to keep a "
                                           "role store in");
    /* And the key the box will actually SIGN with, when its receipt
     * names one. That is the key its board posts and ledger rows
     * carry, so without this the roster would hold a role for a key
     * that never signs anything. */
    bool named = memcmp(receipt->signer_pubkey, k_fe_no_key,
                        sizeof(k_fe_no_key)) != 0;
    why = NULL;
    bool signing_granted =
        named && datadir &&
        zcl_fleet_roles_grant_worker(datadir, receipt->signer_pubkey, now,
                                     &why);
    (void)json_push_kv_bool(&reply->data, "signing_key_role_granted",
                            signing_granted);
    if (!signing_granted)
        (void)json_push_kv_str(
            &reply->data, "signing_key_why",
            named ? (why ? why : "the grant row could not be written")
                  : "this receipt names no signing key: the box had not "
                    "started a node when it joined. Run `z23 fleet join` "
                    "there again after its first node start and admit the "
                    "new receipt, or the rows it signs are refused.");
}

static void fe_admit(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char sealed[FLEET_ENROL_MACHINE_TEXT_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct fleet_anchor_fact anchor = {0};
    struct fleet_receipt receipt = {0};
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
    if (!fe_anchor_gate(request, reply, pubkey, &anchor))
        return;
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
    /* Echoed so the operator sees the locator the box claimed at the moment
     * they admitted it, and can notice a surprise before it is a roster row
     * somebody else reads. Still self-reported: nothing here dialled it. */
    (void)json_push_kv_str(&reply->data, "self_reported_onion", receipt.onion);
    (void)json_push_kv_str(&reply->data, "box_pubkey", hex);
    (void)json_push_kv_int(&reply->data, "relay_port", port);
    (void)json_push_kv_int(&reply->data, "enrolled_at", now);
    (void)json_push_kv_bool(&reply->data, "re_enrolled", scan.same_box);
    fe_anchor_render(reply, &anchor, fe_anchor_required(request));
    fe_admit_role(reply, &receipt, now);
    fe_admit_bridge(reply, &receipt, port,
                    !(bridge && strcmp(bridge, "no") == 0));
    (void)zcl_command_reply_add_next(reply, "fleet.machines", "{}",
                                     "see the machine this fleet now holds");
}

/* ── fleet import ───────────────────────────────────────────────────────── */

/* The operator key this box trusts: the one `fleet join` recorded, or, on
 * the manager, its own. A box that has neither trusts nobody yet and has no
 * key a line could be checked against. */
static bool fe_import_operator(struct zcl_command_reply *reply,
                               uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES])
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES];
    const char *why = NULL;
    bool joined = false, own = false;
    if (!fleet_enrol_operator_read(operator_pubkey, &joined, &why)) {
        fe_fail(reply, "FLEET_OPERATOR_UNREADABLE", "resolve",
                "this box has a recorded fleet operator key it cannot read.",
                why);
        return false;
    }
    if (joined)
        return true;
    if (!fe_key(reply, false, seed, operator_pubkey, &own))
        return false;
    memset(seed, 0, sizeof(seed)); /* only the public half is needed */
    if (own)
        return true;
    fe_fail(reply, "FLEET_OPERATOR_UNKNOWN", "resolve",
            "this box trusts no fleet operator key yet, so no roster line "
            "can be checked here. Run `z23 fleet join <token>` first.",
            FLEET_ENROL_WHY_OPERATOR_UNKNOWN);
    return false;
}

/* The anchor verdict for an imported line. A line the operator key did not
 * seal is NOT decided here: it falls through to fleet_roster_import, which
 * refuses it under its own long-standing token. Only a line that IS sealed
 * by the operator can be refused for the operator's anchor. */
static bool fe_import_gate(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                           const char *line, struct fleet_anchor_fact *fact)
{
    struct fleet_machine seen = {0};
    const char *why = NULL;
    fe_anchor_lookup(request, operator_pubkey, fact);
    if (!line || fleet_root_line_verify(line, operator_pubkey, fact,
                                        fe_anchor_required(request), &seen,
                                        &why))
        return true;
    if (strcmp(why, FLEET_ENROL_WHY_ROSTER_SIGNATURE) == 0 ||
        strcmp(why, FLEET_ENROL_WHY_ARGUMENTS) == 0)
        return true;
    fe_anchor_refuse(reply, why);
    return false;
}

/* confirm_operator_change is a STRING input like --require_anchor, but it
 * fails the other way round: ONLY an exact "yes" re-pins, so a typo can
 * never quietly accept a changed fleet root. */
static bool fe_confirm_change(const struct zcl_command_request *request)
{
    const char *v = request ? json_get_str(json_get(request->input,
                                                    "confirm_operator_change"))
                            : NULL;
    return v && strcmp(v, "yes") == 0;
}

/* Why an import was refused, as the code and the one sentence an owner or
 * an agent acts on. An unlisted reason keeps the long-standing code. */
static const struct {
    const char *why;
    const char *code;
    const char *message;
} fe_import_refusals[] = {
    { FLEET_ENROL_WHY_HEAD_STALE, "FLEET_HEAD_STALE",
      "this roster head has a lower sequence than the one this box already "
      "holds. Importing it would un-revoke boxes; paste the newest head." },
    { FLEET_ENROL_WHY_HEAD_CONFLICT, "FLEET_HEAD_CONFLICT",
      "this box holds a different roster head with the same sequence. Two "
      "heads at one sequence mean the operator signed twice; mint a higher "
      "sequence." },
    { FLEET_ENROL_WHY_ROOT_CHANGED, "FLEET_ROOT_CHANGED",
      "this line is sealed by an operator key other than the one this box "
      "pinned or trusts. Re-run with confirm_operator_change=yes only if "
      "you meant to move this box to a new fleet root." },
    { FLEET_ENROL_WHY_BOX_REVOKED, "FLEET_BOX_REVOKED",
      "the roster head revokes this machine's box key, so its row is not "
      "imported." },
    { FLEET_ENROL_WHY_HEAD_UNREADABLE, "FLEET_HEAD_UNREADABLE",
      "this box holds a roster head it cannot trust (unreadable, corrupt or "
      "not sealed by its operator). It fails closed: import a good head, or "
      "remove the file by hand if you know it is stale." },
    { FLEET_ENROL_WHY_HEAD_TORN, "FLEET_HEAD_TORN",
      "the roster head on this box does not match its sequence record (a "
      "crash mid-import, or a damaged file), so it admits nobody. Paste the "
      "same head again, or a newer one, to repair it." },
    { FLEET_ENROL_WHY_HEAD_HWM, "FLEET_HEAD_HWM_UNREADABLE",
      "the sequence record beside the roster head is missing or unreadable. "
      "This box will not guess it was zero: repair or remove the head by "
      "hand, then import the newest head." },
    { FLEET_ENROL_WHY_STATE_LOCK, "FLEET_STATE_LOCKED",
      "another import holds the fleet state lock; nothing was changed. Try "
      "again." },
    { FLEET_ENROL_WHY_IMPORT_PARTIAL, "FLEET_IMPORT_PARTIAL",
      "the import changed some fleet state and then failed. The operator pin "
      "or sequence record moved but the head or row did not finish; read "
      "the state, then repeat the same import to complete it." },
    { FLEET_ENROL_WHY_PIN_UNREADABLE, "FLEET_OPERATOR_PIN_UNREADABLE",
      "the recorded operator pin cannot be read, so this box will not guess "
      "which fleet root it pinned." },
};

static void fe_import_refuse(struct zcl_command_reply *reply, const char *why)
{
    for (size_t i = 0; why && i < sizeof(fe_import_refusals) /
                                      sizeof(fe_import_refusals[0]); ++i) {
        if (strcmp(why, fe_import_refusals[i].why) != 0)
            continue;
        fe_fail_mut(reply, fe_import_refusals[i].code, "authorize",
                fe_import_refusals[i].message, why,
                strcmp(why, FLEET_ENROL_WHY_IMPORT_PARTIAL) == 0);
        return;
    }
    fe_fail(reply, "FLEET_IMPORT_REFUSED", "authorize",
            "this roster line was not added. It must be one whole line "
            "from the manager's roster, sealed by the operator key this "
            "box trusts, for a machine whose name no other box here "
            "already has.", why);
}

/* A head the operator key sealed is held to --require_anchor like a row; a
 * head it did not seal falls through to fleet_head_import's own refusal. */
static bool fe_import_head_gate(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                const char *line, struct fleet_head *head,
                                struct fleet_anchor_fact *anchor)
{
    if (!fleet_head_parse(line, head, NULL) ||
        memcmp(head->operator_pubkey, operator_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) != 0)
        return true;
    return fe_anchor_gate(request, reply, operator_pubkey, anchor);
}

static void fe_import_head(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                           const char *line)
{
    struct fleet_head *head = zcl_malloc(sizeof(*head), "fleet-import-head");
    struct fleet_anchor_fact anchor = {0};
    const char *why = NULL;
    bool replaced = false;
    if (!head) {
        fe_fail(reply, "FLEET_HEAD_UNREADABLE", "resolve",
                "this box could not allocate room to read the head.",
                FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return;
    }
    bool ok = fe_import_head_gate(request, reply, operator_pubkey, line, head,
                                  &anchor);
    if (ok && !fleet_head_import(line, operator_pubkey,
                                 fe_confirm_change(request), head, &replaced,
                                 &why)) {
        fe_import_refuse(reply, why);
        ok = false;
    }
    if (ok) {
        (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.import.v1");
        (void)json_push_kv_str(&reply->data, "kind", "head");
        (void)json_push_kv_int(&reply->data, "seq", (int64_t)head->seq);
        (void)json_push_kv_int(&reply->data, "issued_at", head->issued_at);
        (void)json_push_kv_int(&reply->data, "revoked_count",
                               (int64_t)head->n_revoked);
        /* False when this exact head was already held: importing it twice
         * is a no-op. */
        (void)json_push_kv_bool(&reply->data, "replaced", replaced);
        fe_anchor_render(reply, &anchor, fe_anchor_required(request));
    }
    free(head);
}

static void fe_import(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply)
{
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct fleet_machine machine = {0};
    const struct json_value *in = request ? request->input : NULL;
    const char *line = json_get_str(json_get(in, "line"));
    const char *why = NULL;
    bool appended = false;
    struct fleet_anchor_fact anchor = {0};
    if (!fe_import_operator(reply, operator_pubkey))
        return;
    if (fleet_head_is_line(line)) {
        fe_import_head(request, reply, operator_pubkey, line);
        return;
    }
    if (!fe_import_gate(request, reply, operator_pubkey, line, &anchor))
        return;
    if (!fleet_roster_import_pinned(line, operator_pubkey,
                                    fe_confirm_change(request), &machine,
                                    &appended, &why)) {
        fe_import_refuse(reply, why);
        return;
    }
    zcl_hex_encode(machine.receipt.box_pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.import.v1");
    (void)json_push_kv_str(&reply->data, "name", machine.receipt.invite.name);
    (void)json_push_kv_str(&reply->data, "box_pubkey", hex);
    (void)json_push_kv_int(&reply->data, "relay_port", machine.relay_port);
    (void)json_push_kv_int(&reply->data, "enrolled_at", machine.enrolled_at);
    /* False when this exact box was already on the roster: importing the
     * same line twice is a no-op, never a second row. */
    (void)json_push_kv_bool(&reply->data, "appended", appended);
    fe_anchor_render(reply, &anchor, fe_anchor_required(request));
    (void)zcl_command_reply_add_next(reply, "fleet.machines", "{}",
                                     "see the roster this box now holds");
}

/* ── fleet roster head ──────────────────────────────────────────────────── */

/* `fleet import` takes its line as an input string bounded at 4096
 * characters; a head longer than that could be minted but never pasted, so
 * it is refused here, by name, where the owner can still act on it. */
#define FE_HEAD_PASTE_MAX 4096u

struct fe_head_mint {
    uint8_t keys[FLEET_ENROL_HEAD_REVOKED_MAX][FLEET_ENROL_PUBKEY_BYTES];
    size_t count;
    char text[FLEET_ENROL_HEAD_TEXT_MAX];
};

/* --revoke is a comma-separated list of 64-hex box public keys; absent means
 * none (a head that revokes nobody still advances the sequence). One bad
 * entry refuses the whole list rather than minting a partial revocation. */
static bool fe_head_keys(struct zcl_command_reply *reply, const char *csv,
                         struct fe_head_mint *m)
{
    char token[FLEET_ENROL_PUBKEY_HEX];
    while (csv && *csv) {
        const char *end = strchr(csv, ',');
        size_t len = end ? (size_t)(end - csv) : strlen(csv);
        if (len != FLEET_ENROL_PUBKEY_HEX - 1u ||
            m->count >= (size_t)FLEET_ENROL_HEAD_REVOKED_MAX) {
            fe_fail(reply, "FLEET_HEAD_INVALID", "normalize",
                    "--revoke is a comma-separated list of at most 256 "
                    "box public keys, each exactly 64 lowercase hex digits "
                    "(the box_pubkey `fleet machines` prints).",
                    FLEET_ENROL_WHY_HEAD_INVALID);
            return false;
        }
        memcpy(token, csv, len);
        token[len] = '\0';
        if (!zcl_hex_decode_lower(token, m->keys[m->count++],
                                  FLEET_ENROL_PUBKEY_BYTES)) {
            fe_fail(reply, "FLEET_HEAD_INVALID", "normalize",
                    "a --revoke entry is not 64 lowercase hex digits.",
                    FLEET_ENROL_WHY_HEAD_INVALID);
            return false;
        }
        csv = end ? end + 1 : NULL;
    }
    return true;
}

static bool fe_head_seq(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply, uint64_t *seq)
{
    const struct json_value *v = request ? json_get(request->input, "seq")
                                         : NULL;
    if (v && v->type == JSON_INT && json_get_int(v) >= 1) {
        *seq = (uint64_t)json_get_int(v);
        return true;
    }
    fe_fail(reply, "FLEET_HEAD_INVALID", "normalize",
            "--seq is required and is a whole number of at least 1. Use a "
            "number higher than the last head you minted; boxes refuse a "
            "lower one.", FLEET_ENROL_WHY_HEAD_INVALID);
    return false;
}

/* Every revoked box also revokes EVERY signer key this operator's roster
 * rows have bound to it: the relay gate sees only the signer. A box whose
 * row this operator does not hold cannot be revoked. */
#define FE_SIGNERS_PER_BOX 16u

static bool fe_head_add_signers(struct zcl_command_reply *reply,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                struct fe_head_mint *m)
{
    const size_t boxes = m->count;
    for (size_t i = 0; i < boxes; ++i) {
        uint8_t signers[FE_SIGNERS_PER_BOX][FLEET_ENROL_PUBKEY_BYTES];
        const char *why = NULL;
        size_t n = 0;
        bool found = false;
        if (!fleet_roster_signers_of_box(operator_pubkey, m->keys[i], signers,
                                         FE_SIGNERS_PER_BOX, &n, &found,
                                         &why)) {
            fe_fail(reply, "FLEET_HEAD_INVALID", "resolve",
                    "this box could not read its roster to find the signer "
                    "keys of a box being revoked.", why);
            return false;
        }
        if (!found) {
            fe_fail(reply, "FLEET_REVOKE_BOX_UNKNOWN", "resolve",
                    "a box named in --revoke has no row in this operator's "
                    "roster, so its signer key cannot be revoked with it. "
                    "Import or admit its row on this box first.",
                    FLEET_ENROL_WHY_REVOKE_UNKNOWN);
            return false;
        }
        if (m->count + n > (size_t)FLEET_ENROL_HEAD_REVOKED_MAX) {
            fe_fail(reply, "FLEET_HEAD_INVALID", "normalize",
                    "revoking these boxes and their signer keys needs more "
                    "than 256 entries; revoke fewer boxes per head.",
                    FLEET_ENROL_WHY_HEAD_INVALID);
            return false;
        }
        for (size_t k = 0; k < n; ++k)
            memcpy(m->keys[m->count++], signers[k], FLEET_ENROL_PUBKEY_BYTES);
    }
    return true;
}

static void fe_roster_head(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], pubkey[FLEET_ENROL_PUBKEY_BYTES];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct fe_head_mint *m = zcl_calloc(1, sizeof(*m), "fleet-head-mint");
    const char *csv = request ? json_get_str(json_get(request->input,
                                                      "revoke")) : NULL;
    const char *why = NULL;
    uint64_t seq = 0;
    bool present = false, ok;
    if (!m) {
        fe_fail(reply, "FLEET_HEAD_INVALID", "execute",
                "this box could not allocate room to mint a head.",
                FLEET_ENROL_WHY_HEAD_INVALID);
        return;
    }
    ok = fe_head_seq(request, reply, &seq) && fe_head_keys(reply, csv, m) &&
         fe_key(reply, false, seed, pubkey, &present);
    if (ok && !present) {
        fe_fail(reply, "FLEET_OPERATOR_UNKNOWN", "resolve",
                "this box has no fleet key, so it is not an operator. Run "
                "`z23 fleet invite` on the manager first.",
                FLEET_ENROL_WHY_OPERATOR_UNKNOWN);
        ok = false;
    }
    ok = ok && fe_head_add_signers(reply, pubkey, m);
    if (ok && !fleet_head_mint(seq, fe_now(), &m->keys[0][0], m->count, seed,
                               pubkey, m->text, sizeof(m->text), &why)) {
        fe_fail(reply, "FLEET_HEAD_INVALID", "execute",
                "this head was not minted.", why);
        ok = false;
    }
    memory_cleanse(seed, sizeof(seed));
    if (ok && strlen(m->text) > FE_HEAD_PASTE_MAX) {
        fe_fail(reply, "FLEET_HEAD_TOO_LARGE", "execute",
                "this head is longer than `fleet import` accepts in one "
                "line. Revoke fewer boxes per head.",
                FLEET_ENROL_WHY_HEAD_TOO_LARGE);
        ok = false;
    }
    if (ok) {
        zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
        (void)json_push_kv_str(&reply->data, "schema",
                               "zcl.fleet.roster.head.v1");
        (void)json_push_kv_str(&reply->data, "operator_pubkey", hex);
        (void)json_push_kv_int(&reply->data, "seq", (int64_t)seq);
        (void)json_push_kv_int(&reply->data, "revoked_count",
                               (int64_t)m->count);
        (void)json_push_kv_str(&reply->data, "head", m->text);
        (void)zcl_command_reply_add_next(
            reply, "fleet.import", "{\"line\":\"<head>\"}",
            "paste this head into fleet.import on every box, this one included");
    }
    free(m);
}

/* ── fleet machines ─────────────────────────────────────────────────────── */

/* One reply renders at most one roster page. A larger `limit` is clamped
 * to that cap; the rows after it stay reachable at `next_offset`. */
#define FE_PAGE_INDEX_MAX 1000000u

struct fe_page {
    uint32_t offset;
    uint32_t limit;
};

struct fe_list {
    struct json_value *array;
    uint32_t skip;
    uint32_t limit;
    uint32_t rendered;
    uint32_t dropped;
    bool more;
    bool stopped;
};

static bool fe_u32_key(const struct json_value *in, const char *key,
                       bool *present, uint32_t *out,
                       struct zcl_command_reply *reply)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    int64_t n = 0;
    *present = v != NULL;
    *out = 0;
    if (!v)
        return true;
    if (v->type != JSON_INT) {
        fe_fail(reply, "FLEET_PAGE_INVALID", "validate",
                "offset and limit are whole numbers.", key);
        return false;
    }
    n = json_get_int(v);
    if (n < 0) {
        fe_fail(reply, "FLEET_PAGE_INVALID", "validate",
                "offset and limit are zero or greater.", key);
        return false;
    }
    *out = n > (int64_t)FE_PAGE_INDEX_MAX ? FE_PAGE_INDEX_MAX : (uint32_t)n;
    return true;
}

static bool fe_machines_page(const struct zcl_command_request *request,
                             struct fe_page *page,
                             struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    bool saw_offset = false, saw_limit = false;
    uint32_t limit = 0;
    page->offset = 0;
    page->limit = (uint32_t)FLEET_ENROL_ROSTER_MAX;
    if (!fe_u32_key(in, "offset", &saw_offset, &page->offset, reply) ||
        !fe_u32_key(in, "limit", &saw_limit, &limit, reply))
        return false;
    (void)saw_offset;
    if (!saw_limit)
        return true;
    if (limit < 1) {
        fe_fail(reply, "FLEET_PAGE_INVALID", "validate",
                "limit is at least 1.", "limit");
        return false;
    }
    if (limit > (uint32_t)FLEET_ENROL_ROSTER_MAX)
        limit = (uint32_t)FLEET_ENROL_ROSTER_MAX;
    page->limit = limit;
    return true;
}

static void fe_list_row(const struct fleet_machine *machine, void *user)
{
    struct fe_list *list = user;
    struct json_value row;
    if (list->stopped)
        return;
    /* `offset` counts verified rows only. Unverifiable lines never reach
     * this callback, so they do not consume a page slot. */
    if (list->skip > 0) {
        list->skip--;
        return;
    }
    if (list->rendered >= list->limit) {
        list->more = true;
        list->stopped = true;
        return;
    }
    json_init(&row);
    fleet_machine_render(machine, &row);
    if (json_push_back(list->array, &row))
        list->rendered++;
    else {
        list->dropped++;
        list->more = true;
        list->stopped = true;
    }
    json_free(&row);
}

static int64_t fe_next_offset(uint32_t offset, uint32_t rendered, bool more)
{
    uint64_t sum = (uint64_t)offset + rendered;
    if (!more || sum > (uint64_t)INT64_MAX)
        return -1;
    return (int64_t)sum;
}

/* Reported, never enforced: this is a read leaf, and an enrolment made
 * before the operator anchored its key must still list. A box that has
 * neither joined nor minted holds no operator key to look up. It takes no
 * `datadir` INPUT on purpose: only a datadir the CLI was given (--datadir)
 * is opened, read-only, because a READ leaf that declares `datadir` must be
 * exercised by tests/harness/src/test_read_leaf_no_datadir_write.c. */
static void fe_machines_anchor(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                               bool known)
{
    struct fleet_anchor_fact anchor = {0};
    if (!known)
        return;
    fe_anchor_lookup(request, operator_pubkey, &anchor);
    fe_anchor_render(reply, &anchor, false);
}

static void fe_machines(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own[FLEET_ENROL_PUBKEY_BYTES];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    struct json_value array;
    struct fe_page page = {0};
    struct fe_list list = { &array, 0, 0, 0, 0, false, false };
    struct fleet_roster_scan scan = {0};
    const char *why = NULL;
    bool joined = false, own_present = false, more = false;
    if (!fe_machines_page(request, &page, reply))
        return;
    list.skip = page.offset;
    list.limit = page.limit;
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
    more = list.more || list.dropped != 0;
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet.machines.v1");
    (void)json_push_kv_str(&reply->data, "operator_pubkey",
                           joined || own_present ? hex : "");
    (void)json_push_kv_bool(&reply->data, "joined", joined);
    (void)json_push_kv_int(&reply->data, "total", (int64_t)scan.rows);
    (void)json_push_kv_int(&reply->data, "offset", (int64_t)page.offset);
    (void)json_push_kv_int(&reply->data, "limit", (int64_t)page.limit);
    (void)json_push_kv_int(&reply->data, "returned", (int64_t)list.rendered);
    (void)json_push_kv_int(&reply->data, "next_offset",
                           fe_next_offset(page.offset, list.rendered, more));
    (void)json_push_kv_bool(&reply->data, "truncated", more);
    /* Counted, never rendered: a line this operator key did not seal is
     * somebody else's row or a corrupted one, and either way it is not
     * evidence about this fleet. */
    (void)json_push_kv_int(&reply->data, "unverifiable",
                           (int64_t)scan.unverifiable);
    fe_machines_anchor(request, reply, operator_pubkey, joined || own_present);
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
    static const struct {
        const char *path;
        void (*run)(const struct zcl_command_request *,
                    struct zcl_command_reply *);
    } leaves[] = {
        { "fleet.invite", fe_invite },
        { "fleet.join", fe_join },
        { "fleet.roster.head", fe_roster_head },
        { "fleet.import", fe_import },
        { "fleet.admit", fe_admit },
        { "fleet.machines", fe_machines },
    };
    const char *path = request && request->spec ? request->spec->path : NULL;
    for (size_t i = 0; path && i < sizeof(leaves) / sizeof(leaves[0]); ++i) {
        if (strcmp(path, leaves[i].path) == 0) {
            leaves[i].run(request, reply);
            return;
        }
    }
    fe_fail(reply, "FLEET_COMMAND_INVALID", "dispatch",
            "fleet enrolment dispatch requires an exact leaf path", "");
}
