/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The OP_RETURN overlay registry + the ZNAM/ZANC apply callbacks — split out
 * of explorer_index.c to keep that TU under the E1 ceiling.
 *
 * This is the ONE dispatcher for on-chain overlays. explorer_index.c used to
 * hand-roll an if-chain (slp_parse → ... → znam_parse → ... → zanc_parse → ...)
 * that every new overlay had to be threaded into. It now calls
 * overlay_ingest(explorer_index_overlays(), ...) exactly once per OP_RETURN,
 * and adding an overlay is a registration in build_registry() below.
 *
 * Each apply callback receives the RAW SCRIPT BYTES and re-parses with its own
 * codec. That is the registry's stated contract (overlay/overlay_projection.h):
 * it keeps engine/modules/overlay decoupled from any single subsystem's headers, at the
 * cost of one extra pure parse over <= 223 bytes on the OP_RETURN path only.
 *
 * Behaviour is identical to the if-chain it replaced: the four lokads are
 * mutually exclusive, so at most one could ever have matched, and the registry
 * makes that structural instead of incidental. Every failure is logged and
 * skipped — an overlay never gates block acceptance.
 *
 * node.db ONLY.
 *
 * ar-validate-skip:overlay-dispatch — every write here goes through
 * db_znam_save / db_znam_addr_save / db_znam_text_save (contexts/naming/models/src/znam.c),
 * db_zanc_save (zanc.c), db_zid_identity_save (zid_identity.c) or
 * explorer_index_apply_slp, each of which runs the validates_* lifecycle; this
 * TU only decodes + dispatches and owns no model record. */

#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/znam.h"
#include "models/zanc.h"
#include "models/zslp_ledger.h"
#include "primitives/transaction.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "overlay/overlay_projection.h"
#include "zslp/slp.h"
#include "znam/znam.h"
#include "zanc/zanc.h"
#include "zid/zid_anchor.h"
#include "zdir/zdir.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* ── Owner derivation ──────────────────────────────────────────────── */

bool explorer_index_owner_address(struct node_db *ndb,
                                  const struct transaction *tx,
                                  char *out, size_t outsize)
{
    if (!ndb || !tx || !out || outsize == 0)
        LOG_FAIL("explorer", "explorer_index_owner_address: invalid args");

    if (tx->num_vin == 0 || outpoint_is_null(&tx->vin[0].prevout))
        return false;
    uint8_t addr20[20];
    if (!db_tx_output_addr(ndb, tx->vin[0].prevout.hash.data,
                           tx->vin[0].prevout.n, addr20))
        return false;

    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, addr20, 20);

    const struct chain_params *cp = chain_params_get();
    if (!cp)
        return false;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len,
                              out, outsize);
}

/* ── ZNAM ──────────────────────────────────────────────────────────── */

/* Apply one parsed ZNAM op into the node.db registry tables (path A).
 * Stateful commands (REGISTER FCFS, UPDATE, TRANSFER, RENEW, SET_RECORD,
 * SET_TEXT) are correct only under the genesis-ascending walk the catchup
 * driver guarantees. Every mutation of an existing name (UPDATE, TRANSFER,
 * SET_RECORD, SET_TEXT) is authorized against the current owner — the first
 * input's P2PKH signer — so only the owner can change a name's records.
 * RENEW is permissionless and only extends expiry_height. Failures are
 * logged and skipped — never fatal. */
static void apply_znam(struct node_db *ndb, const struct transaction *tx,
                       const struct znam_message *zm, int height)
{
    if (!znam_validate_name(zm->name))
        return;

    char owner[64] = "";
    bool have_owner = explorer_index_owner_address(ndb, tx, owner,
                                                   sizeof(owner));

    switch (zm->command) {
    case ZNAM_CMD_REGISTER: {
        if (!have_owner)
            return;   /* owner unresolvable → reject (non-P2PKH input) */
        struct znam_entry existing;
        if (db_znam_find(ndb, zm->name, &existing))
            return;   /* FCFS: name already taken */
        struct znam_entry e;
        memset(&e, 0, sizeof(e));
        snprintf(e.name, sizeof(e.name), "%s", zm->name);
        snprintf(e.owner_address, sizeof(e.owner_address), "%s", owner);
        e.target_type = zm->target_type;
        snprintf(e.target_value, sizeof(e.target_value), "%s",
                 zm->target_value);
        memcpy(e.reg_txid, tx->hash.data, 32);
        e.reg_height = height;
        memcpy(e.last_update_txid, tx->hash.data, 32);
        e.expiry_height = height + ZNAM_REGISTRATION_TERM_BLOCKS;
        if (!db_znam_save(ndb, &e))
            LOG_WARN("explorer", "apply_znam: REGISTER %s save failed",
                     zm->name);
        break;
    }
    case ZNAM_CMD_UPDATE: {
        struct znam_entry e;
        if (!db_znam_find(ndb, zm->name, &e))
            return;   /* name must exist */
        if (!have_owner || strcmp(e.owner_address, owner) != 0)
            return;   /* owner auth */
        e.target_type = zm->target_type;
        snprintf(e.target_value, sizeof(e.target_value), "%s",
                 zm->target_value);
        memcpy(e.last_update_txid, tx->hash.data, 32);
        if (!db_znam_save(ndb, &e))
            LOG_WARN("explorer", "apply_znam: UPDATE %s save failed",
                     zm->name);
        break;
    }
    case ZNAM_CMD_TRANSFER: {
        struct znam_entry e;
        if (!db_znam_find(ndb, zm->name, &e))
            return;
        if (!have_owner || strcmp(e.owner_address, owner) != 0)
            return;   /* only current owner may transfer */
        snprintf(e.owner_address, sizeof(e.owner_address), "%s",
                 zm->new_owner);
        memcpy(e.last_update_txid, tx->hash.data, 32);
        if (!db_znam_save(ndb, &e))
            LOG_WARN("explorer", "apply_znam: TRANSFER %s save failed",
                     zm->name);
        break;
    }
    case ZNAM_CMD_SET_RECORD: {
        /* Records resolve the identity, so only the current owner may set
         * them — same auth as UPDATE/TRANSFER. Without this guard anyone
         * could post a coin address under any name (identity spoofing). */
        struct znam_entry e;
        if (!db_znam_find(ndb, zm->name, &e))
            return;   /* name must exist */
        if (!have_owner || strcmp(e.owner_address, owner) != 0)
            return;   /* only the current owner may set records */
        if (!db_znam_addr_save(ndb, zm->name, zm->target_type,
                               zm->target_value))
            LOG_WARN("explorer", "apply_znam: SET_RECORD %s save failed",
                     zm->name);
        break;
    }
    case ZNAM_CMD_SET_TEXT: {
        /* Same owner authorization as SET_RECORD — text records (onion,
         * pubkey, url, ...) are identity-bearing. */
        struct znam_entry e;
        if (!db_znam_find(ndb, zm->name, &e))
            return;   /* name must exist */
        if (!have_owner || strcmp(e.owner_address, owner) != 0)
            return;   /* only the current owner may set text records */
        if (!db_znam_text_save(ndb, zm->name, zm->text_key, zm->text_value))
            LOG_WARN("explorer", "apply_znam: SET_TEXT %s save failed",
                     zm->name);
        /* Sovereign-identity feed 1: text key "zid" carries a 64-hex ed25519
         * master pubkey. Runs AFTER the owner check above, so a non-owner
         * never reaches it. Any other key, or a value that is not 64 hex
         * chars, projects nothing. */
        explorer_index_apply_znam_zid_text(ndb, tx, zm->name, zm->text_key,
                                           zm->text_value, owner, height);
        break;
    }
    case ZNAM_CMD_RENEW: {
        /* Extend the registration term. Renewal is permissionless
         * (ENS-style): extending expiry can only benefit the owner, so no
         * owner check — anyone may keep a name alive. Extend from the later
         * of the current expiry or the anchor height, by one term. */
        struct znam_entry e;
        if (!db_znam_find(ndb, zm->name, &e))
            return;   /* name must exist */
        int32_t base = e.expiry_height > height ? e.expiry_height : height;
        e.expiry_height = base + ZNAM_REGISTRATION_TERM_BLOCKS;
        memcpy(e.last_update_txid, tx->hash.data, 32);
        if (!db_znam_save(ndb, &e))
            LOG_WARN("explorer", "apply_znam: RENEW %s save failed",
                     zm->name);
        break;
    }
    case ZNAM_CMD_INVALID:
    default:
        break;
    }
}

/* ── ZANC ──────────────────────────────────────────────────────────── */

/* Project one parsed ZANC anchor into zanc_anchors (rebuildable, never
 * authoritative). Anchoring is permissionless — no owner check. Idempotent:
 * INSERT OR REPLACE keyed on txid, so re-processing a block is a no-op.
 * Failures are logged and skipped, never fatal. */
static void apply_zanc(struct node_db *ndb, const struct transaction *tx,
                       const struct zanc_message *zm, int height)
{
    struct zanc_anchor a;
    memset(&a, 0, sizeof(a));
    memcpy(a.txid, tx->hash.data, 32);
    a.height = height;
    a.hash_type = zm->hash_type;
    memcpy(a.digest, zm->digest, ZANC_DIGEST_LEN);
    memcpy(a.label, zm->label, zm->label_len);
    a.label[zm->label_len] = '\0';
    if (!db_zanc_save(ndb, &a))
        LOG_WARN("explorer", "apply_zanc: anchor save failed at h=%d", height);
}

/* ── Registry descriptors ──────────────────────────────────────────── */

/* Each thunk re-parses the raw script with its overlay's own codec, then
 * projects. A parse miss returns false with no side effects: the lokad
 * matched but the body did not, which is a malformed overlay op, not an
 * error condition of the node.
 *
 * Those misses are deliberately NOT logged. The input is attacker-controlled
 * chain data — anyone can pay for an OP_RETURN carrying a valid lokad and a
 * garbage body — so a log line per miss is an unbounded, externally driven
 * log flood during sync. Hence the raw-return-ok markers below. */

static bool ov_apply_zslp(struct node_db *ndb, const struct transaction *tx,
                          const uint8_t *script, size_t script_len,
                          int height, void *ctx)
{
    (void)ctx;
    struct slp_message m;
    if (!slp_parse(script, script_len, &m))
        return false;  // raw-return-ok:lokad matched, body malformed -- attacker-payable chain data, so logging would storm
    explorer_index_apply_slp(ndb, tx, &m, height);
    /* Debit-correct per-outpoint ledger (rows only; the backfill service owns
     * the cursor/digest). See models/zslp_ledger.h. */
    (void)zslp_ledger_apply_slp_live(ndb, tx, &m, height);
    return true;
}

static bool ov_apply_znam(struct node_db *ndb, const struct transaction *tx,
                          const uint8_t *script, size_t script_len,
                          int height, void *ctx)
{
    (void)ctx;
    struct znam_message m;
    if (!znam_parse(script, script_len, &m))
        return false;  // raw-return-ok:lokad matched, body malformed -- attacker-payable chain data, so logging would storm
    apply_znam(ndb, tx, &m, height);
    return true;
}

static bool ov_apply_zanc(struct node_db *ndb, const struct transaction *tx,
                          const uint8_t *script, size_t script_len,
                          int height, void *ctx)
{
    (void)ctx;
    struct zanc_message m;
    if (!zanc_parse(script, script_len, &m))
        return false;  // raw-return-ok:lokad matched, body malformed -- attacker-payable chain data, so logging would storm
    apply_zanc(ndb, tx, &m, height);
    return true;
}

static bool ov_apply_zid(struct node_db *ndb, const struct transaction *tx,
                         const uint8_t *script, size_t script_len,
                         int height, void *ctx)
{
    (void)ctx;
    return explorer_index_apply_zid_overlay(ndb, tx, script, script_len,
                                            height);
}

static bool ov_apply_zdir(struct node_db *ndb, const struct transaction *tx,
                          const uint8_t *script, size_t script_len,
                          int height, void *ctx)
{
    (void)ctx;
    return explorer_index_apply_zdir_overlay(ndb, tx, script, script_len,
                                             height);
}

/* ── The registry ──────────────────────────────────────────────────── */

static struct overlay_registry g_overlays;
static pthread_once_t g_overlays_once = PTHREAD_ONCE_INIT;

static void register_one(const char lokad[OVERLAY_LOKAD_LEN], const char *name,
                         overlay_apply_fn apply)
{
    struct overlay_descriptor d;
    memset(&d, 0, sizeof(d));
    memcpy(d.lokad, lokad, OVERLAY_LOKAD_LEN);
    d.name = name;
    d.apply = apply;
    d.ctx = NULL;
    if (!overlay_registry_add(&g_overlays, &d))
        LOG_WARN("explorer", "explorer_index_overlays: '%s' failed to register",
                 name);
}

/* THE place an overlay is added. One line per on-chain protocol; the
 * dispatcher itself never changes. */
static void build_registry(void)
{
    overlay_registry_init(&g_overlays);
    register_one(SLP_LOKAD_BYTES, "zslp", ov_apply_zslp);
    register_one(ZNAM_LOKAD_BYTES, "znam", ov_apply_znam);
    register_one(ZANC_LOKAD_BYTES, "zanc", ov_apply_zanc);
    register_one(ZID_ANCHOR_LOKAD_BYTES, "zid", ov_apply_zid);
    register_one(ZDIR_LOKAD_BYTES, "zdir", ov_apply_zdir);
}

const struct overlay_registry *explorer_index_overlays(void)
{
    pthread_once(&g_overlays_once, build_registry);
    if (overlay_registry_count(&g_overlays) == 0)
        LOG_NULL("explorer", "explorer_index_overlays: registry is empty");
    return &g_overlays;
}
