/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet roster revoke`: stop admitting one machine on this box, in one step.
 *
 * The revocation authority is the operator-sealed roster head (tools/dev/
 * fleet_enrol.h); `fleet roster head` mints one and `fleet import` stores it,
 * and the relay gate already reads it (config/boot_fleet_roster.h). This leaf
 * adds no second list. It reads the head this box holds, adds the box and
 * every signer key its roster rows name, seals the result at the next
 * sequence with the operator key and imports it here.
 *
 * So the revocation lasts because the head file lasts, a running node picks it
 * up on its next roster rebuild (at most BOOT_FLEET_ROSTER_TTL_S later), and
 * nothing is rewritten: roster rows and stored board posts stay readable. Only
 * the box holding the operator key can seal a head, so a member box is refused
 * and pointed at `fleet import`. Nothing here sends the head anywhere. */

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRR_SCHEMA "zcl.fleet.roster.revoke.v1"
#define FRR_SIGNERS_MAX 16u
#define FRR_LEFT_STANDING                                                     \
    "the machine's ssh bridge line, mesh pairing and role rows are untouched; " \
    "other boxes keep admitting it until they import this head"

struct frr_plan {
    uint8_t seed[FLEET_ENROL_SEED_BYTES];
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t box[FLEET_ENROL_PUBKEY_BYTES];
    char name[FLEET_ENROL_NAME_MAX + 1];
    uint64_t next_seq;
    size_t added;
    size_t count;
    uint8_t keys[FLEET_ENROL_HEAD_REVOKED_MAX][FLEET_ENROL_PUBKEY_BYTES];
    char text[FLEET_ENROL_HEAD_TEXT_MAX];
    struct fleet_head head;
};

static void frr_fail_mut(struct zcl_command_reply *reply, const char *code,
                         const char *stage, const char *message,
                         const char *why, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false,
                           mutated, message,
                           why ? why : FLEET_ENROL_WHY_ARGUMENTS);
}

static void frr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *stage, const char *message, const char *why)
{
    frr_fail_mut(reply, code, stage, message, why, false);
}

static bool frr_box_read(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, struct frr_plan *plan)
{
    const char *hex = request ? json_get_str(json_get(request->input,
                                                      "box_pubkey"))
                              : NULL;
    if (hex && strlen(hex) == FLEET_ENROL_PUBKEY_HEX - 1u &&
        zcl_hex_decode_lower(hex, plan->box, FLEET_ENROL_PUBKEY_BYTES))
        return true;
    frr_fail(reply, "FLEET_HEAD_INVALID", "normalize",
             "box_pubkey must be exactly 64 lowercase hex digits: the "
             "box_pubkey `fleet machines` prints.",
             FLEET_ENROL_WHY_HEAD_INVALID);
    return false;
}

/* Only the key this box trusts as its fleet's operator can seal a head this
 * box will accept. A member holds a key of its own, which is not that key. */
static bool frr_operator_load(struct zcl_command_reply *reply,
                              struct frr_plan *plan)
{
    uint8_t trusted[FLEET_ENROL_PUBKEY_BYTES];
    const char *why = NULL;
    bool present = false, joined = false;
    if (!fleet_enrol_key_load(plan->seed, plan->operator_pubkey, false,
                              &present, &why) ||
        !fleet_enrol_operator_read(trusted, &joined, &why)) {
        frr_fail(reply, "FLEET_KEY_UNAVAILABLE", "resolve",
                 "this box cannot read its fleet key or the operator key it "
                 "trusts. Both live under the owner-private state root; check "
                 "the directory is yours alone.", why);
        return false;
    }
    if (present && (!joined || memcmp(trusted, plan->operator_pubkey,
                                      FLEET_ENROL_PUBKEY_BYTES) == 0))
        return true;
    frr_fail(reply, "FLEET_REVOKE_NOT_OPERATOR", "authorize",
             "this box does not hold its fleet's operator key, so it cannot "
             "seal a revocation. Run this on the manager and paste the head "
             "it prints into `fleet import` here.",
             FLEET_ENROL_WHY_OPERATOR_UNKNOWN);
    return false;
}

/* A head that cannot be trusted is never "nothing revoked yet": building on it
 * could drop revocations it holds. */
static bool frr_head_read(struct zcl_command_reply *reply,
                          struct frr_plan *plan)
{
    const char *why = NULL;
    if (fleet_head_load(plan->operator_pubkey, &plan->head, &why) !=
        FLEET_HEAD_BAD)
        return true;
    frr_fail(reply, "FLEET_HEAD_UNREADABLE", "resolve",
             "this box holds a roster head it cannot trust, so it will not "
             "build a new one on it. Import the newest good head with `fleet "
             "import` first.", why ? why : FLEET_ENROL_WHY_HEAD_UNREADABLE);
    return false;
}

static void frr_add_key(struct frr_plan *plan,
                        const uint8_t key[FLEET_ENROL_PUBKEY_BYTES],
                        bool *overflow)
{
    for (size_t i = 0; i < plan->count; i++)
        if (memcmp(plan->keys[i], key, FLEET_ENROL_PUBKEY_BYTES) == 0)
            return;
    if (plan->count >= (size_t)FLEET_ENROL_HEAD_REVOKED_MAX) {
        *overflow = true;
        return;
    }
    memcpy(plan->keys[plan->count++], key, FLEET_ENROL_PUBKEY_BYTES);
    plan->added++;
}

/* The name that leads every reply, read from the same rows. */
static void frr_name_visit(const struct fleet_machine *machine, void *user)
{
    struct frr_plan *plan = user;
    if (memcmp(machine->receipt.box_pubkey, plan->box,
               FLEET_ENROL_PUBKEY_BYTES) == 0)
        (void)snprintf(plan->name, sizeof(plan->name), "%s",
                       machine->receipt.invite.name);
}

/* The held set plus this box and every signer key its rows name: the relay
 * gate sees only the signer. A box with no row here has nothing to revoke. */
static bool frr_keys_build(struct zcl_command_reply *reply,
                           struct frr_plan *plan)
{
    uint8_t signers[FRR_SIGNERS_MAX][FLEET_ENROL_PUBKEY_BYTES];
    struct fleet_roster_scan scan = {0};
    const char *why = NULL;
    size_t n = 0;
    bool found = false, overflow = false;
    if (!fleet_roster_signers_of_box(plan->operator_pubkey, plan->box, signers,
                                     FRR_SIGNERS_MAX, &n, &found, &why) ||
        !fleet_roster_each(plan->operator_pubkey, frr_name_visit, plan, &scan,
                           &why)) {
        frr_fail(reply, "FLEET_ROSTER_UNREADABLE", "resolve",
                 "this box could not read its roster to find the machine and "
                 "its signer keys, so nothing changed.", why);
        return false;
    }
    if (!found) {
        frr_fail(reply, "FLEET_REVOKE_BOX_UNKNOWN", "resolve",
                 "no machine with this box public key is on this operator's "
                 "roster, so there is nothing to revoke and nothing changed. "
                 "`fleet machines` lists every box_pubkey.",
                 FLEET_ENROL_WHY_REVOKE_UNKNOWN);
        return false;
    }
    plan->count = plan->head.n_revoked;
    memcpy(plan->keys, plan->head.revoked,
           plan->count * FLEET_ENROL_PUBKEY_BYTES);
    frr_add_key(plan, plan->box, &overflow);
    for (size_t i = 0; i < n; i++)
        frr_add_key(plan, signers[i], &overflow);
    if (overflow) {
        frr_fail(reply, "FLEET_HEAD_TOO_LARGE", "resolve",
                 "this head would revoke more than 256 keys, and a longer one "
                 "cannot be sealed. Nothing changed.",
                 FLEET_ENROL_WHY_HEAD_TOO_LARGE);
        return false;
    }
    plan->next_seq = plan->head.seq + 1u;
    return true;
}

/* The exact word, as `fleet import` takes confirm_operator_change: a typo can
 * never stop a machine. The refusal says what the word would do. */
static bool frr_confirmed(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply,
                          const struct frr_plan *plan)
{
    const char *word = request ? json_get_str(json_get(request->input,
                                                       "confirm_revoke"))
                               : NULL;
    char message[240];
    if (word && strcmp(word, "yes") == 0)
        return true;
    (void)snprintf(message, sizeof(message),
                   "\"%s\" is not revoked yet. This would add %zu key(s) to "
                   "this box's roster head at sequence %llu. Run again with "
                   "confirm_revoke=yes.", plan->name, plan->added,
                   (unsigned long long)plan->next_seq);
    frr_fail(reply, "FLEET_REVOKE_UNCONFIRMED", "authorize", message,
             FLEET_ENROL_WHY_ARGUMENTS);
    return false;
}

/* The head is sealed for pasting too, so it is held to the bound `fleet
 * import` takes. A store failure after a leaf moved is reported as mutated. */
static bool frr_seal_and_store(struct zcl_command_reply *reply,
                               struct frr_plan *plan)
{
    const char *why = NULL;
    bool replaced = false;
    if (!fleet_head_mint(plan->next_seq, clock_now_wall_ms() / 1000,
                         &plan->keys[0][0], plan->count, plan->seed,
                         plan->operator_pubkey, plan->text, sizeof(plan->text),
                         &why)) {
        frr_fail(reply, "FLEET_HEAD_INVALID", "execute",
                 "this revocation could not be sealed, so nothing changed.",
                 why);
        return false;
    }
    if (strlen(plan->text) > FLEET_ENROL_HEAD_PASTE_MAX) {
        frr_fail(reply, "FLEET_HEAD_TOO_LARGE", "execute",
                 "this head is longer than `fleet import` accepts in one "
                 "line, so nothing changed.", FLEET_ENROL_WHY_HEAD_TOO_LARGE);
        return false;
    }
    if (fleet_head_import(plan->text, plan->operator_pubkey, false, &plan->head,
                          &replaced, &why))
        return true;
    frr_fail_mut(reply, "FLEET_REVOKE_NOT_STORED", "execute",
                 "this box did not store the new roster head, so the machine "
                 "is not revoked. Another head may have landed first; read "
                 "the evidence and run this again.", why,
                 why && strcmp(why, FLEET_ENROL_WHY_IMPORT_PARTIAL) == 0);
    return false;
}

static void frr_render(struct zcl_command_reply *reply,
                       const struct frr_plan *plan, bool already)
{
    char box[FLEET_ENROL_PUBKEY_HEX], op[FLEET_ENROL_PUBKEY_HEX];
    zcl_hex_encode(plan->box, FLEET_ENROL_PUBKEY_BYTES, box);
    zcl_hex_encode(plan->operator_pubkey, FLEET_ENROL_PUBKEY_BYTES, op);
    (void)json_push_kv_str(&reply->data, "schema", FRR_SCHEMA);
    (void)json_push_kv_str(&reply->data, "name", plan->name);
    (void)json_push_kv_str(&reply->data, "box_pubkey", box);
    (void)json_push_kv_str(&reply->data, "operator_pubkey", op);
    (void)json_push_kv_bool(&reply->data, "already_revoked", already);
    (void)json_push_kv_int(&reply->data, "seq", (int64_t)plan->head.seq);
    (void)json_push_kv_int(&reply->data, "revoked_count",
                           (int64_t)plan->head.n_revoked);
    (void)json_push_kv_str(&reply->data, "left_standing", FRR_LEFT_STANDING);
    if (already)
        return;
    (void)json_push_kv_str(&reply->data, "head", plan->text);
    (void)zcl_command_reply_add_next(
        reply, "fleet.import", "{\"line\":\"<head>\"}",
        "paste this head into fleet.import on any other box that should "
        "stop admitting this machine");
}

static void frr_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, struct frr_plan *plan)
{
    if (!frr_box_read(request, reply, plan) ||
        !frr_operator_load(reply, plan) || !frr_head_read(reply, plan) ||
        !frr_keys_build(reply, plan))
        return;
    /* Everything is already in the head: no new sequence, nothing to confirm,
     * so running this twice is one revocation. */
    if (plan->added == 0) {
        frr_render(reply, plan, true);
        return;
    }
    if (frr_confirmed(request, reply, plan) && frr_seal_and_store(reply, plan))
        frr_render(reply, plan, false);
}

void zcl_native_handle_fleet_roster_revoke(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct frr_plan *plan = zcl_calloc(1, sizeof(*plan), "fleet-roster-revoke");
    if (!plan) {
        frr_fail(reply, "FLEET_HEAD_UNREADABLE", "execute",
                 "this box could not allocate room to build a roster head, so "
                 "nothing changed.", FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return;
    }
    frr_run(request, reply, plan);
    memory_cleanse(plan->seed, sizeof(plan->seed));
    free(plan);
}
