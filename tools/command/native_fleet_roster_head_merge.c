/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Carry the revocations a box already holds into the head that
 *          `fleet roster head` mints, and say which ones the operator
 *          explicitly dropped.
 *
 * `fleet import` accepts any higher sequence, so a head that names only the
 * newest revocation would silently un-revoke every earlier one fleet-wide.
 * The mint therefore starts from the held head's set (the same read
 * `fleet roster revoke` builds on) and removes a key only when the operator
 * names it in drop_revoked. Dropping a box also drops the signer keys its
 * roster rows bound to it, because revoking it added them, except a signer
 * that another box which stays revoked also names.
 *
 * Nothing here opens a file: the held head and the roster rows come through
 * the fleet store. */

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdlib.h>
#include <string.h>

#define FRM_SIGNERS_MAX 16u
#define FRM_KEY FLEET_ENROL_PUBKEY_BYTES
#define FRM_SET_MAX ((size_t)FLEET_ENROL_HEAD_REVOKED_MAX)

static bool frm_has(const uint8_t (*set)[FRM_KEY], size_t n,
                    const uint8_t key[FRM_KEY])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(set[i], key, FRM_KEY) == 0)
            return true;
    return false;
}

static bool frm_push(uint8_t (*set)[FRM_KEY], size_t *n,
                     const uint8_t key[FRM_KEY])
{
    if (frm_has((const uint8_t (*)[FRM_KEY])set, *n, key))
        return true;
    if (*n >= FRM_SET_MAX)
        return false;
    memcpy(set[(*n)++], key, FRM_KEY);
    return true;
}

/* The csv of boxes to drop. `drop` takes the boxes themselves; `sig` takes the
 * signer keys their rows name, which stay revoked if another box that stays
 * revoked names the same key (a signer key is self-named in a receipt, signed
 * by that key, and nothing makes it unique to one box). */
static enum fleet_head_merge_status frm_drop_set(
    const uint8_t op[FRM_KEY], const char *csv, uint8_t (*drop)[FRM_KEY],
    size_t *n, uint8_t (*sig)[FRM_KEY], size_t *n_sig, const char **why)
{
    char token[FLEET_ENROL_PUBKEY_HEX];
    while (csv && *csv) {
        const char *end = strchr(csv, ',');
        size_t len = end ? (size_t)(end - csv) : strlen(csv);
        uint8_t key[FRM_KEY], signers[FRM_SIGNERS_MAX][FRM_KEY];
        size_t found_n = 0;
        bool found = false;
        if (len != FLEET_ENROL_PUBKEY_HEX - 1u)
            return FLEET_HEAD_MERGE_DROP_INVALID;
        memcpy(token, csv, len);
        token[len] = '\0';
        if (!zcl_hex_decode_lower(token, key, FRM_KEY))
            return FLEET_HEAD_MERGE_DROP_INVALID;
        if (!fleet_roster_signers_of_box(op, key, signers, FRM_SIGNERS_MAX,
                                         &found_n, &found, why))
            return FLEET_HEAD_MERGE_ROSTER;
        if (!frm_push(drop, n, key))
            return FLEET_HEAD_MERGE_TOO_LARGE;
        for (size_t i = 0; found && i < found_n; i++)
            if (!frm_push(sig, n_sig, signers[i]))
                return FLEET_HEAD_MERGE_TOO_LARGE;
        csv = end ? end + 1 : NULL;
    }
    return FLEET_HEAD_MERGE_OK;
}

/* True when a key in keys[0..n), other than `signer`, is a box whose rows
 * name `signer`. */
static enum fleet_head_merge_status frm_signer_shared(
    const uint8_t op[FRM_KEY], const uint8_t (*keys)[FRM_KEY], size_t n,
    const uint8_t signer[FRM_KEY], bool *shared, const char **why)
{
    *shared = false;
    for (size_t i = 0; i < n && !*shared; i++) {
        uint8_t signers[FRM_SIGNERS_MAX][FRM_KEY];
        size_t found_n = 0;
        bool found = false;
        if (memcmp(keys[i], signer, FRM_KEY) == 0)
            continue;
        if (!fleet_roster_signers_of_box(op, keys[i], signers, FRM_SIGNERS_MAX,
                                         &found_n, &found, why))
            return FLEET_HEAD_MERGE_ROSTER;
        *shared = frm_has((const uint8_t (*)[FRM_KEY])signers, found_n,
                          signer);
    }
    return FLEET_HEAD_MERGE_OK;
}

/* Each signer of a dropped box leaves the head unless a box that stays
 * revoked names it too. */
static enum fleet_head_merge_status frm_settle_signers(
    const uint8_t op[FRM_KEY], const uint8_t (*sig)[FRM_KEY], size_t n_sig,
    uint8_t (*keys)[FRM_KEY], size_t *count, uint8_t (*dropped)[FRM_KEY],
    size_t *n_dropped, const char **why)
{
    for (size_t i = 0; i < n_sig; i++) {
        bool shared = false;
        enum fleet_head_merge_status st = frm_signer_shared(
            op, (const uint8_t (*)[FRM_KEY])keys, *count, sig[i], &shared,
            why);
        if (st != FLEET_HEAD_MERGE_OK)
            return st;
        if (!frm_push(shared ? keys : dropped, shared ? count : n_dropped,
                      sig[i]))
            return FLEET_HEAD_MERGE_TOO_LARGE;
    }
    return FLEET_HEAD_MERGE_OK;
}

enum fleet_head_merge_status fleet_roster_head_merge_held(
    const uint8_t op[FRM_KEY], const char *drop_csv, uint8_t (*keys)[FRM_KEY],
    size_t *count, uint8_t (*dropped)[FRM_KEY], size_t *n_dropped,
    const char **why)
{
    struct fleet_head head;
    uint8_t drop[FLEET_ENROL_HEAD_REVOKED_MAX][FRM_KEY];
    uint8_t sig[FLEET_ENROL_HEAD_REVOKED_MAX][FRM_KEY];
    uint8_t held_sig[FLEET_ENROL_HEAD_REVOKED_MAX][FRM_KEY];
    size_t n_drop = 0, n_sig = 0, n_held_sig = 0;
    enum fleet_head_merge_status st;
    *n_dropped = 0;
    st = frm_drop_set(op, drop_csv, drop, &n_drop, sig, &n_sig, why);
    if (st != FLEET_HEAD_MERGE_OK)
        return st;
    if (fleet_head_load(op, &head, why) == FLEET_HEAD_BAD)
        return FLEET_HEAD_MERGE_HEAD_BAD;
    for (size_t i = 0; i < head.n_revoked; i++) {
        const uint8_t *key = head.revoked[i];
        bool is_sig = frm_has((const uint8_t (*)[FRM_KEY])sig, n_sig, key);
        if (frm_has((const uint8_t (*)[FRM_KEY])keys, *count, key))
            continue;
        if (frm_has((const uint8_t (*)[FRM_KEY])drop, n_drop, key))
            (void)frm_push(dropped, n_dropped, key);
        else if (is_sig)
            (void)frm_push(held_sig, &n_held_sig, key);
        else if (!frm_push(keys, count, key))
            return FLEET_HEAD_MERGE_TOO_LARGE;
    }
    return frm_settle_signers(op, (const uint8_t (*)[FRM_KEY])held_sig,
                              n_held_sig, keys, count, dropped, n_dropped, why);
}

void fleet_roster_head_merge_fail(struct zcl_command_reply *reply,
                                  enum fleet_head_merge_status status,
                                  const char *why)
{
    const char *code = "FLEET_HEAD_INVALID", *stage = "normalize", *msg;
    switch (status) {
    case FLEET_HEAD_MERGE_HEAD_BAD:
        code = "FLEET_HEAD_UNREADABLE";
        stage = "resolve";
        msg = "this box holds a roster head it cannot trust, so it will not "
              "build a new one on it. Import the newest good head with "
              "`fleet import` first.";
        why = why ? why : FLEET_ENROL_WHY_HEAD_UNREADABLE;
        break;
    case FLEET_HEAD_MERGE_TOO_LARGE:
        code = "FLEET_HEAD_TOO_LARGE";
        msg = "the revocations this box already holds plus these need more "
              "than 256 entries; drop some with --drop_revoked.";
        why = FLEET_ENROL_WHY_HEAD_TOO_LARGE;
        break;
    case FLEET_HEAD_MERGE_ROSTER:
        stage = "resolve";
        msg = "this box could not read its roster to find the signer keys "
              "of a box named in --drop_revoked.";
        break;
    default:
        msg = "--drop_revoked is a comma-separated list of box public keys, "
              "each exactly 64 lowercase hex digits.";
        why = FLEET_ENROL_WHY_HEAD_INVALID;
        break;
    }
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false, false,
                           msg, why ? why : FLEET_ENROL_WHY_ARGUMENTS);
}

/* The keys the operator chose to let back, as the same csv the switch takes,
 * so the reply shows exactly what the new head no longer revokes. */
void fleet_roster_head_render_dropped(struct zcl_command_reply *reply,
                                      const uint8_t (*dropped)[FRM_KEY],
                                      size_t n_dropped)
{
    const size_t hex_len = FLEET_ENROL_PUBKEY_HEX;
    char *text = zcl_calloc(n_dropped + 1u, hex_len, "fleet-head-dropped");
    size_t at = 0;
    for (size_t i = 0; text && i < n_dropped; ++i) {
        if (i)
            text[at++] = ',';
        zcl_hex_encode(dropped[i], FRM_KEY, text + at);
        at += hex_len - 1u;
    }
    (void)json_push_kv_str(&reply->data, "dropped", text ? text : "");
    free(text);
}
