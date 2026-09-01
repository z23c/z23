/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The two on-chain feeds of the zid_identities projection — see
 * models/explorer_index.h for the declarations and
 * docs/spec/sovereign-identity-layer.md for the wire formats:
 *
 *   1. explorer_index_apply_znam_zid_text — the NAME CONVENTION. A ZNAM
 *      SET_TEXT with key "zid" whose value is a 64-hex ed25519 master pubkey
 *      anchors that key under the name. source "znam_text".
 *   2. explorer_index_apply_zid_overlay — the DEDICATED `ZID\0` OP_RETURN
 *      overlay: ANCHOR / ROTATE / REVOKE. source "zid_overlay".
 *
 * OWNERSHIP, stated once. A row's owner_address is the t-address of the
 * anchoring tx's first-input P2PKH signer. Every mutation of an EXISTING row
 * (rotate, revoke, re-anchor) requires that the row carry a NON-EMPTY recorded
 * owner AND that the current signer equal it. So an ANCHOR published from a
 * non-P2PKH first input records owner_address "" and is thereafter permanently
 * immutable — a deliberate fail-closed choice, mirroring the owner checks
 * apply_znam already runs on UPDATE/TRANSFER/SET_RECORD/SET_TEXT.
 *
 * Every refusal is a LOG_WARN + no-op. Nothing here is ever fatal, nothing
 * here gates block acceptance, and the whole table is rebuildable from block
 * history. Writes are INSERT OR REPLACE keyed on master_pubkey, so a re-walk
 * of the same block rewrites identical rows.
 *
 * node.db ONLY.
 *
 * ar-validate-skip:zid-apply — every write goes through db_zid_identity_save
 * (engine/models/src/zid_identity.c), which runs the validates_* lifecycle; this
 * TU only decodes + authorizes and owns no model record. */

#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/zid_identity.h"
#include "primitives/transaction.h"
#include "encoding/utilstrencodings.h"
#include "zid/zid_anchor.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static bool zid_key_is_zero(const uint8_t key[32])
{
    for (int i = 0; i < 32; i++)
        if (key[i]) return false;
    return true;
}

/* Decode EXACTLY 64 hex characters into 32 bytes. Anything shorter, longer,
 * non-hex, or all-zero is refused — a value that is not a usable ed25519
 * master key is simply not an identity, not an error. */
static bool zid_hex64_to_key(const char *hex, uint8_t out[32])
{
    if (!hex || !out) return false;
    if (strlen(hex) != 64 || !IsHex(hex)) return false;
    if (ParseHex(hex, out, 32) != 32) return false;
    return !zid_key_is_zero(out);
}

/* True iff `signer` is a non-empty string equal to the row's recorded owner.
 * A row with no recorded owner can never be mutated (fail-closed). */
static bool zid_owner_matches(const struct zid_identity *row,
                              const char *signer)
{
    return row->owner_address[0] != '\0' && signer && signer[0] != '\0' &&
           strcmp(row->owner_address, signer) == 0;
}

static void zid_fill_active(struct zid_identity *row, const uint8_t key[32],
                            const uint8_t txid[32], int height,
                            const char *source, const char *name,
                            const char *owner)
{
    memset(row, 0, sizeof(*row));
    memcpy(row->master_pubkey, key, 32);
    memcpy(row->anchor_txid, txid, 32);
    row->anchor_height = height;
    row->updated_height = height;
    snprintf(row->status, sizeof(row->status), "%s",
             ZID_IDENTITY_STATUS_ACTIVE);
    snprintf(row->source, sizeof(row->source), "%s", source);
    if (name) snprintf(row->name, sizeof(row->name), "%s", name);
    if (owner) snprintf(row->owner_address, sizeof(row->owner_address), "%s",
                        owner);
}

/* Mark `row` rotated toward `successor`. anchor_txid / anchor_height stay put
 * — they record the ANCHOR, not the rotation; only updated_height moves. That
 * is also what keeps find_by_name idempotent: the successor row always carries
 * the strictly higher anchor_height, so it keeps winning the lookup. */
static void zid_mark_rotated(struct zid_identity *row,
                             const uint8_t successor[32], int height)
{
    snprintf(row->status, sizeof(row->status), "%s",
             ZID_IDENTITY_STATUS_ROTATED);
    memcpy(row->successor_pubkey, successor, 32);
    row->has_successor = true;
    row->updated_height = height;
}

static void zid_mark_revoked(struct zid_identity *row, int height)
{
    snprintf(row->status, sizeof(row->status), "%s",
             ZID_IDENTITY_STATUS_REVOKED);
    memset(row->successor_pubkey, 0, 32);
    row->has_successor = false;   /* validator: successor present iff rotated */
    row->updated_height = height;
}

/* Save a row and publish the change. EVERY save in this TU writes a status —
 * a fresh ACTIVE anchor, a ROTATED supersession, or a REVOKED retirement — so
 * routing them all through here is what makes "the chain changed its mind"
 * observable at all.
 *
 * The publish is a monotonic counter bump (models/zid_identity.h), and that is
 * the WHOLE mechanism on purpose. A callback or subscriber list would run some
 * other subsystem's work on this thread, and this thread is the block fold;
 * the consumer that needed this signal is precisely the one that must never
 * do a node.db read on a thread it does not own. A poller costs the fold two
 * atomic stores and cannot block it. */
static bool zid_save_and_publish(struct node_db *ndb,
                                 const struct zid_identity *row, int height)
{
    if (!db_zid_identity_save(ndb, row))
        return false;  // raw-return-ok:every caller logs the failure with the command that hit it -- a line here would double every save failure
    zid_identity_note_status_change(height);
    return true;
}

/* A key already claimed by a DIFFERENT signer may not be overwritten. Without
 * this, INSERT OR REPLACE would let anyone rotate their own key onto someone
 * else's row and take it over. A replay passes (same signer, same row). */
static bool zid_target_free(struct node_db *ndb, const uint8_t key[32],
                            const char *signer)
{
    struct zid_identity claimed;
    if (!db_zid_identity_find(ndb, key, &claimed))
        return true;                       /* unclaimed */
    if (claimed.owner_address[0] == '\0')
        return true;                       /* claimed by nobody in particular */
    return signer && signer[0] && strcmp(claimed.owner_address, signer) == 0;
}

/* ── Feed 2: the dedicated `ZID\0` overlay ─────────────────────────── */

static bool zid_apply_anchor(struct node_db *ndb,
                             const struct zid_anchor_message *msg,
                             const uint8_t txid[32], const char *owner,
                             int height)
{
    struct zid_identity prev;
    if (db_zid_identity_find(ndb, msg->pubkey, &prev)) {
        /* A dead or superseded key is never resurrected by a fresh ANCHOR. */
        if (strcmp(prev.status, ZID_IDENTITY_STATUS_ACTIVE) != 0) {
            LOG_WARN("zid", "zid ANCHOR: key is already '%s' at h=%d — refused",
                     prev.status, height);
            return false;
        }
        if (prev.owner_address[0] != '\0' && !zid_owner_matches(&prev, owner)) {
            LOG_WARN("zid", "zid ANCHOR: key owned by another signer at h=%d"
                     " — refused", height);
            return false;
        }
    }

    struct zid_identity row;
    zid_fill_active(&row, msg->pubkey, txid, height,
                    ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, owner);
    if (!zid_save_and_publish(ndb, &row, height)) {
        LOG_WARN("zid", "zid ANCHOR: save failed at h=%d", height);
        return false;
    }
    return true;
}

static bool zid_apply_rotate(struct node_db *ndb,
                             const struct zid_anchor_message *msg,
                             const uint8_t txid[32], const char *owner,
                             int height)
{
    struct zid_identity prev;
    if (!db_zid_identity_find(ndb, msg->old_pubkey, &prev)) {
        LOG_WARN("zid", "zid ROTATE: old key is not anchored at h=%d", height);
        return false;
    }
    if (strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) == 0) {
        LOG_WARN("zid", "zid ROTATE: old key is revoked at h=%d — refused",
                 height);
        return false;
    }
    if (!zid_owner_matches(&prev, owner)) {
        LOG_WARN("zid", "zid ROTATE: signer is not the recorded owner at h=%d"
                 " — refused", height);
        return false;
    }
    if (!zid_target_free(ndb, msg->pubkey, owner)) {
        LOG_WARN("zid", "zid ROTATE: target key already claimed at h=%d"
                 " — refused", height);
        return false;
    }

    zid_mark_rotated(&prev, msg->pubkey, height);
    if (!zid_save_and_publish(ndb, &prev, height)) {
        LOG_WARN("zid", "zid ROTATE: old-key save failed at h=%d", height);
        return false;
    }

    struct zid_identity row;
    zid_fill_active(&row, msg->pubkey, txid, height,
                    ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, owner);
    if (!zid_save_and_publish(ndb, &row, height)) {
        LOG_WARN("zid", "zid ROTATE: new-key save failed at h=%d", height);
        return false;
    }
    return true;
}

static bool zid_apply_revoke(struct node_db *ndb,
                             const struct zid_anchor_message *msg,
                             const char *owner, int height)
{
    struct zid_identity prev;
    if (!db_zid_identity_find(ndb, msg->pubkey, &prev)) {
        LOG_WARN("zid", "zid REVOKE: key is not anchored at h=%d", height);
        return false;
    }
    if (!zid_owner_matches(&prev, owner)) {
        LOG_WARN("zid", "zid REVOKE: signer is not the recorded owner at h=%d"
                 " — refused", height);
        return false;
    }

    zid_mark_revoked(&prev, height);
    if (!zid_save_and_publish(ndb, &prev, height)) {
        LOG_WARN("zid", "zid REVOKE: save failed at h=%d", height);
        return false;
    }
    return true;
}

bool explorer_index_apply_zid_overlay(struct node_db *ndb,
                                      const struct transaction *tx,
                                      const uint8_t *script, size_t script_len,
                                      int height)
{
    if (!ndb || !tx || !script)
        LOG_FAIL("zid", "explorer_index_apply_zid_overlay: invalid args"
                 " (ndb=%p tx=%p)", (void *)ndb, (const void *)tx);

    /* The lokad matched but the body did not. Not logged: the input is
     * attacker-controlled chain data (anyone can pay for an OP_RETURN with a
     * valid lokad and a garbage body), so a line per miss is an unbounded,
     * externally driven log flood during sync. */
    struct zid_anchor_message msg;
    if (!zid_anchor_parse(script, script_len, &msg))
        return false;  // raw-return-ok:lokad matched, body malformed -- attacker-payable chain data, so logging would storm

    char owner[64] = "";
    (void)explorer_index_owner_address(ndb, tx, owner, sizeof(owner));

    switch (msg.command) {
    case ZID_ANCHOR_CMD_ANCHOR:
        return zid_apply_anchor(ndb, &msg, tx->hash.data, owner, height);
    case ZID_ANCHOR_CMD_ROTATE:
        return zid_apply_rotate(ndb, &msg, tx->hash.data, owner, height);
    case ZID_ANCHOR_CMD_REVOKE:
        return zid_apply_revoke(ndb, &msg, owner, height);
    case ZID_ANCHOR_CMD_INVALID:
    default:
        return false;
    }
}

/* ── Feed 1: the ZNAM "zid" text convention ────────────────────────── */

void explorer_index_apply_znam_zid_text(struct node_db *ndb,
                                        const struct transaction *tx,
                                        const char *name, const char *key,
                                        const char *value, const char *owner,
                                        int height)
{
    if (!ndb || !tx || !name || !key || !value) {
        LOG_WARN("zid", "znam zid text: invalid args at h=%d", height);
        return;
    }
    if (strcmp(key, "zid") != 0)
        return;                             /* an ordinary text record */

    struct zid_identity prev;
    const bool prev_found = db_zid_identity_find_by_name(ndb, name, &prev);

    /* ZNAM stores an empty text value rather than deleting the record; the
     * identity reading of that is "this name no longer asserts a key". */
    if (value[0] == '\0') {
        if (!prev_found)
            return;                         /* nothing to revoke */
        if (!zid_owner_matches(&prev, owner)) {
            LOG_WARN("zid", "znam zid text: revoke by non-owner of '%s' at"
                     " h=%d — refused", name, height);
            return;
        }
        zid_mark_revoked(&prev, height);
        if (!zid_save_and_publish(ndb, &prev, height))
            LOG_WARN("zid", "znam zid text: revoke save failed at h=%d",
                     height);
        return;
    }

    uint8_t key32[32];
    if (!zid_hex64_to_key(value, key32))
        return;   /* not 64 hex chars → a plain text record, not an identity */

    const bool same_key = prev_found &&
                          memcmp(prev.master_pubkey, key32, 32) == 0;

    if (prev_found && !zid_owner_matches(&prev, owner)) {
        /* The name changed hands (ZNAM TRANSFER) or the row was anchored by
         * an unresolvable signer. Fail closed: the standing identity is not
         * silently reassigned. */
        LOG_WARN("zid", "znam zid text: '%s' is anchored by another owner at"
                 " h=%d — refused", name, height);
        return;
    }
    if (!zid_target_free(ndb, key32, owner)) {
        LOG_WARN("zid", "znam zid text: key already claimed by another owner"
                 " at h=%d — refused", height);
        return;
    }

    /* A NEW key from the same owner rotates the standing one. A revoked row
     * stays revoked — it is dead, not superseded. */
    if (prev_found && !same_key &&
        strcmp(prev.status, ZID_IDENTITY_STATUS_REVOKED) != 0) {
        zid_mark_rotated(&prev, key32, height);
        if (!zid_save_and_publish(ndb, &prev, height))
            LOG_WARN("zid", "znam zid text: rotate save failed at h=%d",
                     height);
    }

    struct zid_identity row;
    zid_fill_active(&row, key32, tx->hash.data, height,
                    ZID_IDENTITY_SOURCE_ZNAM_TEXT, name, owner);
    if (!zid_save_and_publish(ndb, &row, height))
        LOG_WARN("zid", "znam zid text: anchor save failed at h=%d", height);
}
