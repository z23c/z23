/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The chain feed of the onion_directory projection — the REAL replacement for
 * blog_discover_onion_peers' wallet scrape.
 *
 * The old "ZSLP chain scan" read db_wallet_tx_recent_raw(): it could only ever
 * see transactions already in the LOCAL WALLET table, so a node with an empty
 * wallet discovered nothing and no node ever saw another node's announcement.
 * This is the projection that actually folds out of block history: every
 * confirmed `ZDIR` OP_RETURN is dispatched here by the overlay registry
 * (explorer_index_overlays.c) during the same genesis-ascending walk that
 * builds znam_names / zanc_anchors / zid_identities.
 *
 * PURE FOLD. No network call, no clock read, no RNG — the only inputs are the
 * transaction, the script bytes, the confirming height, and rows this same
 * fold already wrote. Re-walking a block rewrites identical rows (INSERT OR
 * REPLACE keyed on hostname), so the table is rebuildable from block history
 * and nothing else.
 *
 * OWNERSHIP, stated once. A row's owner_address is the t-address of the
 * REGISTERing tx's first-input P2PKH signer, the same rule apply_znam and the
 * zid feeds use. Every mutation of an EXISTING row (re-register, deregister)
 * requires the row to carry a NON-EMPTY recorded owner AND the current signer
 * to equal it. A REGISTER published from a non-P2PKH first input records
 * owner_address "" and is thereafter permanently immutable — the same
 * deliberate fail-closed choice explorer_index_zid.c documents.
 *
 * WHAT THIS CANNOT DO. A row is a HINT ABOUT WHERE TO LOOK, never proof of who
 * is there. The projection only ever ADDS candidates to peer discovery
 * alongside DNS seeds, fixed seeds, addrman and the signed-descriptor source;
 * it has no path to exclude a peer or narrow a source, so the worst a squatted
 * or poisoned record achieves is one wasted connection attempt. Hostnames are
 * held to onion_hostname_valid (core/modules/net) at parse, here, and again in the
 * model validator before a byte is stored.
 *
 * Every refusal is a LOG_WARN + no-op. Nothing here is ever fatal and nothing
 * here gates block acceptance.
 *
 * node.db ONLY.
 *
 * ar-validate-skip:zdir-apply — every write goes through
 * db_onion_directory_save (engine/models/src/onion_directory.c), which runs the
 * validates_* lifecycle; this TU only decodes + authorizes and owns no model
 * record. */

#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/onion_directory.h"
#include "primitives/transaction.h"
#include "net/onion_peer_merge.h"
#include "zdir/zdir.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* True iff `signer` is a non-empty string equal to the row's recorded owner.
 * A row with no recorded owner can never be mutated (fail-closed). */
static bool zdir_owner_matches(const struct db_onion_directory *row,
                               const char *signer)
{
    return row->owner_address[0] != '\0' && signer && signer[0] != '\0' &&
           strcmp(row->owner_address, signer) == 0;
}

static void zdir_fill_row(struct db_onion_directory *row,
                          const struct zdir_message *msg,
                          const uint8_t txid[32], int first_height,
                          int height, const char *owner)
{
    memset(row, 0, sizeof(*row));
    snprintf(row->hostname, sizeof(row->hostname), "%s", msg->hostname);
    memcpy(row->txid, txid, 32);
    row->height = first_height;
    row->updated_height = height;
    snprintf(row->status, sizeof(row->status), "%s",
             ONION_DIRECTORY_STATUS_ACTIVE);
    if (msg->has_pubkey) {
        memcpy(row->master_pubkey, msg->pubkey, 32);
        row->has_pubkey = true;
    }
    if (owner)
        snprintf(row->owner_address, sizeof(row->owner_address), "%s", owner);
}

/* REGISTER — first-come-first-served on the hostname, then owner-locked.
 * A re-register by the recorded owner refreshes the record (txid, key
 * binding, and status back to active after a deregister) but never moves
 * `height`: that is the seniority signal, and letting a re-register reset it
 * would make seniority free to fake. */
static bool zdir_apply_register(struct node_db *ndb,
                                const struct zdir_message *msg,
                                const uint8_t txid[32], const char *owner,
                                int height)
{
    struct db_onion_directory prev;
    int first_height = height;
    if (db_onion_directory_find(ndb, msg->hostname, &prev)) {
        if (!zdir_owner_matches(&prev, owner)) {
            LOG_WARN("zdir", "zdir REGISTER: '%s' is held by another signer at"
                     " h=%d — refused", msg->hostname, height);
            return false;
        }
        first_height = prev.height;
    }

    struct db_onion_directory row;
    zdir_fill_row(&row, msg, txid, first_height, height, owner);
    if (!db_onion_directory_save(ndb, &row)) {
        LOG_WARN("zdir", "zdir REGISTER: save failed at h=%d", height);
        return false;
    }
    return true;
}

/* DEREGISTER — the recorded owner retires the hostname. The row stays (its
 * seniority and history are the record), it just stops being dialed. */
static bool zdir_apply_deregister(struct node_db *ndb,
                                  const struct zdir_message *msg,
                                  const char *owner, int height)
{
    struct db_onion_directory prev;
    if (!db_onion_directory_find(ndb, msg->hostname, &prev)) {
        LOG_WARN("zdir", "zdir DEREGISTER: '%s' is not registered at h=%d",
                 msg->hostname, height);
        return false;
    }
    if (!zdir_owner_matches(&prev, owner)) {
        LOG_WARN("zdir", "zdir DEREGISTER: signer is not the recorded owner"
                 " at h=%d — refused", height);
        return false;
    }

    snprintf(prev.status, sizeof(prev.status), "%s",
             ONION_DIRECTORY_STATUS_RETIRED);
    prev.updated_height = height;
    if (!db_onion_directory_save(ndb, &prev)) {
        LOG_WARN("zdir", "zdir DEREGISTER: save failed at h=%d", height);
        return false;
    }
    return true;
}

bool explorer_index_apply_zdir_overlay(struct node_db *ndb,
                                       const struct transaction *tx,
                                       const uint8_t *script,
                                       size_t script_len, int height)
{
    if (!ndb || !tx || !script)
        LOG_FAIL("zdir", "explorer_index_apply_zdir_overlay: invalid args"
                 " (ndb=%p tx=%p)", (void *)ndb, (const void *)tx);

    /* The lokad matched but the body did not. Not logged: the input is
     * attacker-controlled chain data (anyone can pay for an OP_RETURN with a
     * valid lokad and a garbage body), so a line per miss is an unbounded,
     * externally driven log flood during sync. */
    struct zdir_message msg;
    if (!zdir_parse(script, script_len, &msg))
        return false;  // raw-return-ok:lokad matched, body malformed -- attacker-payable chain data, so logging would storm

    /* zdir_parse already applied the v3 rule. Re-applied here because this
     * function is also the seam a future feed would call, and a hostname that
     * reaches the table is dialed: the rule is cheap and the failure is
     * silent, so it is checked at every boundary rather than assumed. */
    if (!onion_hostname_valid(msg.hostname))
        LOG_RETURN(false, "zdir", "zdir apply: hostname failed the v3 rule at"
                   " h=%d — refused", height);

    char owner[64] = "";
    (void)explorer_index_owner_address(ndb, tx, owner, sizeof(owner));

    switch (msg.command) {
    case ZDIR_CMD_REGISTER:
        return zdir_apply_register(ndb, &msg, tx->hash.data, owner, height);
    case ZDIR_CMD_DEREGISTER:
        return zdir_apply_deregister(ndb, &msg, owner, height);
    case ZDIR_CMD_INVALID:
    default:
        /* Unreachable: zdir_parse rejects every command byte it does not
         * handle. Present so a future command added to the codec cannot be
         * silently half-projected here. */
        LOG_RETURN(false, "zdir", "zdir apply: unhandled command %u at h=%d",
                   (unsigned)msg.command, height);
    }
}
