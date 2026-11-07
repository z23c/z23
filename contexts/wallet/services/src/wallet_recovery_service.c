/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_recovery_service — implementation.
 * See services/wallet_recovery_service.h. */

#include "services/wallet_recovery_service.h"
#include "wallet_recovery_internal.h"
#include "services/wallet_create_service.h"
#include "core/random.h"

#include "chain/chainparams.h"
#include "chain/checkpoints.h"                 /* pinned blocks */
#include "command/native_command.h"            /* the ONE read-only db open */
#include "config/boot_shutdown_marker.h"       /* verified-clean binding */
#include "keys/key.h"                          /* ecc_start_once */
#include "models/database.h"
#include "models/block.h"                       /* active tip for the birthday */
#include "models/utxo.h"                /* gap-scan history oracle */
#include "models/wallet_key.h"
#include "sapling/sapling.h"
#include "util/ar_step_readonly.h"
#include "models/wallet_tx.h"                    /* note count */
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "services/block_index_loader.h"       /* the best header */
#include "services/wallet_restore_service.h"   /* datadir single-writer proof */
#include "services/wallet_create_service.h"    /* the passphrase minimum */
#include "support/cleanse.h"
#include "core/utiltime.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/bip44.h"
#include "wallet/mnemonic.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"            /* the at-rest creation policy */
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define WRC_TAG "wallet_recovery"

/* ── helpers ─────────────────────────────────────────────────────── */

void wrc_reset(struct wallet_recovery_report *out, const char *datadir)
{
    memset(out, 0, sizeof(*out));
    if (datadir && datadir[0]) {
        snprintf(out->datadir, sizeof(out->datadir), "%s", datadir);
        snprintf(out->target_db, sizeof(out->target_db), "%s/node.db",
                 datadir);
    }
}

/* Count the words in a phrase without copying it anywhere. */
static int wrc_word_count(const char *phrase)
{
    int n = 0;
    bool in_word = false;
    for (const char *p = phrase; *p; p++) {
        bool sp = (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r');
        if (!sp && !in_word) { n++; in_word = true; }
        else if (sp) in_word = false;
    }
    return n;
}

/* Make the datadir if it is not there. A directory that does not exist
 * cannot be held by a node, so this cannot race the lock proof. */
static struct zcl_result wrc_ensure_datadir(const char *datadir,
                                            struct wallet_recovery_report *out)
{
    bool absent = platform_private_path_absent(datadir);
    if (!platform_private_directory_ensure(datadir))
        return ZCL_ERR(-63,
                       "cannot create or validate private datadir %s",
                       datadir);
    out->datadir_created = absent;
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result wallet_recovery_test_ensure_datadir(
    const char *datadir, struct wallet_recovery_report *out)
{
    if (!out)
        return ZCL_ERR(-63, "wallet recovery datadir test: report is NULL");
    memset(out, 0, sizeof(*out));
    return wrc_ensure_datadir(datadir, out);
}
#endif

/* ── at-rest policy: the SAME one boot obeys ──────────────────────────
 *
 * BOOT refuses to mint a spendable wallet whose private keys land on disk
 * in the clear unless the operator said so (wallet_at_rest_boot_decision,
 * engine/composition/src/app_context.c). This command installs exactly that — 240-odd
 * spending keys AND the master seed every future key descends from — and
 * used to write them plaintext with no passphrase, no opt-in and no
 * warning. One command in the tree enforcing the policy while another
 * ignores it means the policy is decoration, and the one that ignores it is
 * the one a person reaches for after losing a machine.
 *
 * So the same env-driven policy decides here. The lane/mint context boot
 * folds in does NOT apply: this is a one-shot offline CLI invocation, not a
 * declared unattended lane, and there is nobody to wedge. */
static enum wallet_at_rest_policy wrc_at_rest_decision(const char *passphrase)
{
    /* A passphrase handed in by the caller (wallet creation reads it from
     * standard input) decides the question: the keys are encrypted. */
    if (passphrase && passphrase[0])
        return WALLET_AT_REST_ENCRYPTED;
    return wallet_at_rest_creation_policy();
}

struct zcl_result wrc_at_rest_gate(const char *passphrase)
{
    switch (wrc_at_rest_decision(passphrase)) {
    case WALLET_AT_REST_ENCRYPTED:
        /* wallet_sqlite_flush_r wraps every key and the seed in a WKS1
         * envelope under this passphrase. Nothing further to do. */
        return ZCL_OK;
    case WALLET_AT_REST_PLAINTEXT_OPTIN:
        LOG_WARN(WRC_TAG,
            "recovering into a PLAINTEXT wallet: the spending keys and the "
            "master seed the phrase derives will be written to node.db "
            "unencrypted, and anyone who can read that file can spend every "
            "coin the phrase controls. Proceeding because "
            "ZCL_ALLOW_PLAINTEXT_WALLET is set");
        return ZCL_OK;
    case WALLET_AT_REST_REFUSE:
    default:
        return ZCL_ERR(-67,
            "refusing to write this wallet's spending keys and master seed "
            "to disk unencrypted. Recovering installs the whole wallet the "
            "phrase controls, so it obeys the same rule the node obeys when "
            "it creates one: set ZCL_WALLET_PASSPHRASE to encrypt the keys "
            "at rest (recommended), or set ZCL_ALLOW_PLAINTEXT_WALLET=1 to "
            "say plaintext is what you want here. Nothing was written");
    }
}

/* Keys at rest are not a world-readable file, whatever the umask says.
 * node_db_open creates node.db 0644 through SQLite, and -wal/-shm alongside
 * it; on this path that file holds spending keys. Best-effort and never
 * fatal — a tightened mode that could not be applied is worth a line in the
 * log, not the loss of a recovery that otherwise worked. */
static void wrc_tighten_modes(const char *db_path)
{
    static const char *const suffix[] = { "", "-wal", "-shm" };
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
        char p[1300];
        int n = snprintf(p, sizeof(p), "%s%s", db_path, suffix[i]);
        if (n <= 0 || (size_t)n >= sizeof(p))
            continue;
        struct stat st;
        if (stat(p, &st) != 0)
            continue;              /* -wal/-shm may legitimately be absent */
        if (chmod(p, 0600) != 0)
            LOG_WARN(WRC_TAG, "could not restrict %s to 0600: %s", p,
                     strerror(errno));
    }
}

/* ── "has this address been used?" — the gap scan's oracle ───────────
 *
 * Answered from the chain THIS datadir already holds. A restore into a
 * datadir that has synced can therefore walk past the standard lookahead
 * and rebuild every address the user actually handed out. A restore into
 * an empty datadir has nothing to consult, gets a NULL oracle, and derives
 * the floor — which is stated in the report rather than glossed as full
 * coverage. See wallet_derive_gap_limited in wallet/wallet.h. */
static bool wrc_address_used(const struct key_id *id, void *ctx)
{
    struct node_db *ndb = (struct node_db *)ctx;
    if (!id || !ndb || !ndb->open)
        return false;
    return db_address_has_chain_history(ndb, id->id.data);
}

/* Rebuild the key material the phrase determines, into an already-rooted
 * wallet. `chain` may be NULL (no history oracle available). */
static struct zcl_result wrc_rebuild_transparent(
    struct wallet *w, struct node_db *chain,
    struct wallet_recovery_report *out)
{
    struct wallet_gap_scan scan;
    if (!wallet_derive_gap_limited(w, chain ? wrc_address_used : NULL,
                                   chain, &scan))
        return ZCL_ERR(-64, "could not derive the address keys from the "
                            "phrase");

    out->receiving_keys = scan.external_derived;
    out->change_keys = scan.internal_derived;
    out->receiving_keys_used = scan.external_used;
    out->change_keys_used = scan.internal_used;
    out->chain_history_consulted = scan.oracle_consulted;
    out->transparent_scan_truncated = scan.ceiling_hit;
    return ZCL_OK;
}

struct zcl_result wrc_rebuild_keys(struct wallet *w,
                                          struct node_db *chain,
                                          bool shielded_only,
                                          struct wallet_recovery_report *out)
{
    if (!shielded_only) {
        struct zcl_result tr = wrc_rebuild_transparent(w, chain, out);
        if (!tr.ok)
            return tr;
    }

    /* The shielded side: a fixed lookahead, not a scan — there is no cheap
     * offline oracle for shielded use. See WALLET_RECOVERY_SHIELDED_LOOKAHEAD. */
    for (uint32_t i = 0; i < (uint32_t)WALLET_RECOVERY_SHIELDED_LOOKAHEAD; i++) {
        uint8_t div[ZC_DIVERSIFIER_SIZE];
        uint8_t pk_d[32];
        if (!sapling_keystore_new_address(&w->sapling_keys, div, pk_d))
            return ZCL_ERR(-64, "could not derive shielded address %u of %d",
                           i, WALLET_RECOVERY_SHIELDED_LOOKAHEAD);
        out->shielded_children = i + 1;
    }

    out->keys_minted = (int)w->keystore.num_keys;
    return ZCL_OK;
}

/* Derive and encode the two public addresses the phrase's seed reproduces.
 * Pure derivation; writes nothing. */
static bool wrc_fill_addresses(const uint8_t seed[32],
                               struct wallet_recovery_report *out)
{
    /* Offline entry point: nothing has booted, so the process-wide signing
     * context every key derivation needs may not exist yet. */
    if (!ecc_start_once())
        LOG_FAIL(WRC_TAG, "no secp256k1 signing context; cannot derive keys");

    if (!wallet_seed_address_at(seed, 0, BIP44_EXTERNAL, 0,
                                out->first_address,
                                sizeof(out->first_address)))
        LOG_FAIL(WRC_TAG, "could not derive the first receiving address");

    /* The shielded side: same seed, ZIP32 tree, first account. A scratch
     * keystore keeps this out of any wallet the caller owns. */
    struct sapling_keystore *sks =
        zcl_malloc(sizeof(*sks), "wallet_recovery.sapling_probe");
    if (!sks)
        LOG_FAIL(WRC_TAG, "out of memory deriving the shielded address");
    sapling_keystore_init(sks);
    bool ok = sapling_keystore_set_seed(sks, seed);
    uint8_t div[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    ok = ok && sapling_keystore_new_address(sks, div, pk_d);
    if (ok) {
        const struct chain_params *cp = chain_params_get();
        ok = sapling_encode_payment_address(
                div, pk_d, cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                out->first_shielded_address,
                sizeof(out->first_shielded_address));
    }
    sapling_keystore_free(sks);
    free(sks);
    if (!ok)
        LOG_FAIL(WRC_TAG, "could not derive the first shielded address");
    return true;
}

static bool wrc_persisted_columns_valid(sqlite3_stmt *s)
{
    return sqlite3_column_bytes(s, 0) == 32 &&
           sqlite3_column_bytes(s, 1) == (int)wks_envelope_size(sizeof(struct zip32_xsk)) &&
           sqlite3_column_bytes(s, 2) == (int)sizeof(struct zip32_xfvk) &&
           sqlite3_column_bytes(s, 3) == 11 && sqlite3_column_bytes(s, 4) == 32;
}

/* Refuse an unsafe selected account rather than choosing a different one. */
static bool wrc_persisted_row_address(struct wallet_sqlite *ws, sqlite3_stmt *s,
                                      struct wallet_recovery_report *out)
{
    if (!wrc_persisted_columns_valid(s))
        return false; // raw-return-ok:invalid-row
    const uint8_t *ivk = sqlite3_column_blob(s, 0);
    const uint8_t *xsk = sqlite3_column_blob(s, 1);
    const void *fv = sqlite3_column_blob(s, 2);
    const uint8_t *div = sqlite3_column_blob(s, 3);
    const uint8_t *pk = sqlite3_column_blob(s, 4);
    if (!ivk || !xsk || !fv || !div || !pk ||
        !wks_envelope_iterations(xsk, (size_t)sqlite3_column_bytes(s, 1)))
        return false;
    struct sapling_key_entry acct = {0};
    uint8_t derived_ivk[32], derived_pk[32];
    memcpy(&acct.xfvk, fv, sizeof(acct.xfvk));
    sapling_crh_ivk(acct.xfvk.fvk.ak, acct.xfvk.fvk.nk, derived_ivk);
    if (memcmp(ivk, derived_ivk, 32) ||
        !sapling_ivk_to_pkd(ivk, div, derived_pk) || memcmp(pk, derived_pk, 32)) {
        memory_cleanse(&acct, sizeof(acct));
        return false;
    }
    memcpy(acct.ivk, ivk, 32);
    memcpy(acct.diversifier, div, ZC_DIVERSIFIER_SIZE);
    memcpy(acct.pk_d, pk, 32);
    acct.used = true;
    uint8_t current_div[ZC_DIVERSIFIER_SIZE], current_pk[32];
    enum wallet_diversifier_current current =
        wallet_sqlite_diversifier_current(ws, &acct, current_div, current_pk);
    if (current == WALLET_DIVERSIFIER_ABSENT) {
        memcpy(current_div, acct.diversifier, sizeof(current_div));
        memcpy(current_pk, acct.pk_d, sizeof(current_pk));
    }
    const struct chain_params *cp = chain_params_get();
    bool ok = current != WALLET_DIVERSIFIER_INVALID && cp &&
        sapling_encode_payment_address(current_div, current_pk,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            out->persisted_shielded_address, sizeof(out->persisted_shielded_address));
    memory_cleanse(&acct, sizeof(acct));
    return ok;
}

/* SQL ordering agrees with the live uint32 and bytewise account ordering. */
static bool wrc_account_order_row_valid(sqlite3_stmt *s)
{
    sqlite3_int64 index = sqlite3_column_int64(s, 1);
    return sqlite3_column_type(s, 0) == SQLITE_BLOB &&
           sqlite3_column_bytes(s, 0) == 32 &&
           sqlite3_column_type(s, 1) == SQLITE_INTEGER &&
           index >= 0 && (uint64_t)index <= UINT32_MAX;
}

static bool wrc_account_order_valid(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ivk,child_index FROM wallet_sapling_keys LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return false;
    }
    if (sqlite3_bind_int(s, 1, MAX_SAPLING_KEYS + 1) != SQLITE_OK) {
        sqlite3_finalize(s);
        return false;
    }
    size_t count = 0;
    int rc;
    bool ok = true;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        if (++count > MAX_SAPLING_KEYS || !wrc_account_order_row_valid(s)) {
            ok = false;
            break;
        }
    }
    ok = ok && rc == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static void wrc_persisted_address(struct wallet_sqlite *ws,
                                  struct wallet_recovery_report *out)
{
    if (!wrc_account_order_valid(ws->db)) {
        out->persisted_address_unavailable = true;
        return;
    }
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT ivk,xsk,xfvk,diversifier,pk_d FROM wallet_sapling_keys "
                      "ORDER BY child_index,ivk LIMIT 1";
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        out->persisted_address_unavailable = true;
        return;
    }
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW)
        out->persisted_address_unavailable = !wrc_persisted_row_address(ws, s, out);
    else if (rc != SQLITE_DONE)
        out->persisted_address_unavailable = true;
    sqlite3_finalize(s);
}

/* ── status ──────────────────────────────────────────────────────── */

struct zcl_result wallet_recovery_status_preflight(
    const char *datadir, struct wallet_recovery_report *out)
{
    if (!out)
        return ZCL_ERR(-63, "report is NULL");
    wrc_reset(out, datadir);
    if (!datadir || !datadir[0])
        return ZCL_ERR(-63, "datadir path is empty");

    /* Single-writer proof BEFORE anything opens the datadir. The read
     * itself cannot write any more — the caller opens node.db READ-ONLY —
     * but a node that is mid-migration is rewriting the very wallet tables
     * this answer is derived from, and the leaf aims at the operator's
     * running node when the caller names no datadir, which is exactly when
     * that would happen. */
    struct zcl_result lock_r = wallet_restore_datadir_free(datadir);
    if (!lock_r.ok) {
        LOG_WARN(WRC_TAG, "refusing to inspect a held datadir: %s",
                 lock_r.message);
        return ZCL_ERR(-61, "%s", lock_r.message);
    }
    return ZCL_OK;
}

static struct zcl_result wrc_status_check_seed(
    struct wallet_sqlite *ws, const uint8_t seed[32],
    struct wallet_recovery_report *out)
{
    struct wallet *w = zcl_malloc(sizeof(*w), "wallet_recovery.status");
    if (!w) {
        return ZCL_ERR(-63, "out of memory loading the wallet");
    }
    wallet_init(w);
    /* A read failure here would leave an empty keystore, and an empty
     * keystore makes wallet_hd_adopt_seed say yes unconditionally —
     * i.e. it would report a legacy wallet as phrase-recoverable. Fail
     * the question instead of answering it wrong. */
    struct zcl_result kr = wallet_sqlite_read_keys_r(ws, w);
    if (!kr.ok) {
        wallet_free(w);
        free(w);
        return ZCL_ERR(-63, "cannot read this wallet's keys, so whether "
                       "a phrase would bring them back is unknown: %s",
                       kr.message);
    }
    out->seed_installed = wallet_hd_adopt_seed(w, seed);
    if (out->seed_installed)
        (void)wallet_seed_address_at(seed, 0, BIP44_EXTERNAL, 0,
                                     out->first_address,
                                     sizeof(out->first_address));
    wallet_free(w);
    free(w);
    return ZCL_OK;
}

struct zcl_result wallet_recovery_status(const char *datadir,
                                         struct node_db *ndb,
                                         struct wallet_recovery_report *out)
{
    if (!out)
        return ZCL_ERR(-63, "report is NULL");
    if (!out->target_db[0])
        wrc_reset(out, datadir);
    if (!datadir || !datadir[0])
        return ZCL_ERR(-63, "datadir path is empty");
    /* The handle is the caller's, opened READ-ONLY. Nothing here opens,
     * creates, migrates or closes a database — that is the whole point of
     * taking it as a parameter rather than a path. */
    if (!ndb || !ndb->open || !ndb->db)
        return ZCL_ERR(-63, "no open node.db to read at %s", out->target_db);

    /* Offline entry point — the derivation below needs a signing context. */
    if (!ecc_start_once())
        return ZCL_ERR(-63, "no secp256k1 signing context; cannot check "
                            "whether this wallet descends from its seed");

    struct wallet_sqlite ws;
    {
        struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb->db);
        if (!wr.ok)
            return ZCL_ERR(-63, "cannot open the wallet tables in %s: %s",
                           out->target_db, wr.message);
    }

    if (out->inspect_persisted_address)
        wrc_persisted_address(&ws, out);

    out->keys_before = db_wallet_key_count(ndb);
    out->keys_after = out->keys_before;

    uint8_t seed[32];
    memset(seed, 0, sizeof(seed));
    /* Three different facts, three different answers. "No seed row" and "a
     * seed row I cannot decrypt" used to be the same false here, and that
     * told the owner of an encrypted, phrase-backed wallet that their
     * wallet predates recovery phrases and their money could only come back
     * from a file. It can come back from their words; they have to unlock
     * it first. The caller renders LOCKED as its own answer. */
    out->seed_state_before = wallet_sqlite_sapling_seed_state(&ws, seed);
    out->seed_present_before =
        wallet_seed_state_row_present(out->seed_state_before);
    bool seed_readable = (out->seed_state_before == WALLET_SEED_PLAINTEXT ||
                          out->seed_state_before == WALLET_SEED_UNLOCKED);

    struct zcl_result result = ZCL_OK;
    if (seed_readable)
        result = wrc_status_check_seed(&ws, seed, out);
    memory_cleanse(seed, sizeof(seed));

    /* The wallet_sqlite statement set is ours; the node_db handle under it
     * is the caller's and stays open. */
    wallet_sqlite_close(&ws);
    return result;
}

/* ── target inspection and creation extras ───────────────────────── */

/* Everything besides the transparent keys and the seed that makes a target
 * a wallet: Sapling spending keys and received notes. */
static void wrc_count_shielded_rows(struct node_db *ndb,
                                    struct wallet_recovery_report *out)
{
    out->sapling_keys_before = db_sapling_key_count(ndb);
    out->notes_before = db_sapling_note_count_all(ndb);
}

/* Register the caller's passphrase (or the creation-policy environment one)
 * for the flush that follows, so the seed and keys are wrapped as they are
 * written. Sets *loaded when the lock module now holds a passphrase. */
struct zcl_result wrc_load_passphrase(
    const struct wallet_recovery_request *req, bool *loaded)
{
    const char *pass = req->passphrase;
    *loaded = false;
    if (!pass || !pass[0]) {
        if (wallet_at_rest_creation_policy() != WALLET_AT_REST_ENCRYPTED)
            return ZCL_OK;
        pass = getenv("ZCL_WALLET_PASSPHRASE");
    }
    struct zcl_result ur = wallet_lock_unlock(NULL, NULL, pass);
    if (!ur.ok)
        return ZCL_ERR(-65, "could not load the recovery encryption key: %s",
                       ur.message);
    *loaded = true;
    return ZCL_OK;
}

static bool wrc_release_floor_usable(void);

/* A restored wallet claims no scanned-through height until it is read; a
 * created one has its birthday instead. */
static void wrc_mark_unread(const struct wallet_recovery_request *req,
                            struct wallet *w, bool birthday_honoured)
{
    if ((req->record_birthday && !req->birthday_at_local_tip) ||
        birthday_honoured)
        return;
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    w->scan_retry.since = GetTime();
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             req->birthday_at_local_tip && wrc_release_floor_usable()
                 ? WALLET_BIRTHDAY_PENDING : WALLET_RESTORE_BLOCKER_UNREAD);
}

static void wrc_floor_offer(struct wrc_floor *f, int height,
                            const uint8_t hash[32])
{
    if (height <= f->height)
        return;
    f->height = height;
    memcpy(f->hash, hash, sizeof(f->hash));
}

static bool wrc_floor_cb(int height, const struct db_block *row, void *ctx)
{
    (void)height;
    *(struct db_block *)ctx = *row;
    return false;
}

/* (a) The connected row at `height`. The ordered range probe reads through a
 * plain handle, so this serves the read-only handle as well as the write one. */
static void wrc_offer_row(struct node_db *ndb, int height, struct wrc_floor *f)
{
    struct db_block row;
    memset(&row, 0, sizeof(row));
    if (height <= 0 || !ndb || !ndb->open)
        return;
    (void)db_block_scan_height_range_probe(ndb, height, height, wrc_floor_cb,
                                           &row);
    if (row.height == height)
        wrc_floor_offer(f, height, row.hash);
}

/* (c) The best header's ancestor at `height`. */
static void wrc_offer_header(struct block_index_flat_cursor *headers,
                             int height, struct wrc_floor *f)
{
    uint8_t hash[32];
    if (headers && height > 0 &&
        block_index_flat_cursor_best_ancestor(headers, height, hash).ok)
        wrc_floor_offer(f, height, hash);
}

/* (b) The anchor's height, or 0 on a network that ships none: the network
 * rule reducer_frontier_floor() applies to the same compiled checkpoint. */
static int wrc_shipped_anchor(uint8_t hash[32])
{
    const struct chain_params *p = chain_params_get();
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!p || strcmp(p->strNetworkID, "main") != 0 || !cp || cp->height <= 0)
        return 0;
    memcpy(hash, cp->block_hash, 32);
    return cp->height;
}

/* The pinned blocks at or below `top`: every header checkpoint of this
 * network and the anchor. */
static void wrc_offer_pinned(int top, int anchor, const uint8_t anchor_hash[32],
                             struct wrc_floor *f)
{
    const struct checkpoint_data *cps = &chain_params_get()->checkpointData;
    for (int i = 0; i < cps->nEntries; i++)
        if (cps->entries[i].height <= top)
            wrc_floor_offer(f, cps->entries[i].height,
                            cps->entries[i].hash.data);
    if (anchor <= top)
        wrc_floor_offer(f, anchor, anchor_hash);
}

static void wrc_release_floor(struct wrc_floor *f)
{
    uint8_t anchor_hash[32] = {0};
    int anchor = wrc_shipped_anchor(anchor_hash);
    memset(f, 0, sizeof(*f));
    wrc_floor_offer(f, anchor, anchor_hash);
}

static bool wrc_release_floor_usable(void)
{
    struct wrc_floor f;
    wrc_release_floor(&f);
    return f.height > 0 && f.height <= INT_MAX - WALLET_BIRTHDAY_MARGIN;
}

static int wrc_max(int a, int b) { return a > b ? a : b; }
static int wrc_min(int a, int b) { return a < b ? a : b; }

/* (c) The best header's height, or 0. Opening block_index.bin hashes the
 * whole file and finding the best header reads every row, so it is read only
 * while (a) is below (b) + WALLET_BIRTHDAY_MARGIN. From there on the connected
 * row WALLET_BIRTHDAY_MARGIN below (a), or else the anchor, is a floor no lower
 * than the anchor, and a synced node's birthday is its own tip. */
static int wrc_best_header(const char *datadir, int tip, int anchor,
                           struct block_index_flat_cursor **headers)
{
    int32_t best = 0;
    if (tip >= anchor + WALLET_BIRTHDAY_MARGIN ||
        !block_index_flat_cursor_open(datadir, headers).ok ||
        !block_index_flat_cursor_best(*headers, &best).ok)
        return 0;
    return best;
}

/* The birthday of a phrase made now. Nothing can pay it in a block mined
 * before it, so its first scan may start at any block that already exists.
 * Three heights are each at or below the real chain tip:
 *   (a) the highest connected block (status >= 3) in node.db, which this node
 *       validated;
 *   (b) the SHA3 UTXO anchor this release ships (mainnet only), the
 *       height the reducer never folds below and a bundle install must match,
 *       mined before this binary was built;
 *   (c) the best header in block_index.bin, the accepted header with the
 *       most chain work: a peer that sends headers past the real tip must
 *       mine them, and a chain of them outweighs the real chain only for one
 *       that out-mined it.
 * A height a peer only claims is never used. P is the highest of the three,
 * with (c) read only while (a) is below (b) + WALLET_BIRTHDAY_MARGIN
 * (wrc_best_header). The floor block is the highest block at or below P - WALLET_BIRTHDAY_MARGIN
 * whose hash is known: a connected row, an ancestor of the best header, or a
 * block this release pins (a header checkpoint or the anchor). The stored
 * birthday is the floor plus the margin, so it is never above P, and a
 * reorganisation shorter than the margin cannot replace the floor. Rows above
 * a rewound tip keep their status; that is safe because boot checks the floor
 * block, not the birthday, against the active chain. With no floor above
 * genesis the wallet records no birthday and scans from genesis. */
void wrc_birthday_floor(const char *datadir, struct node_db *ndb,
                               struct wrc_floor *f)
{
    uint8_t anchor_hash[32] = {0};
    struct block_index_flat_cursor *headers = NULL;
    int tip = ndb && ndb->open ? db_block_max_height(ndb) : 0;
    int anchor = wrc_shipped_anchor(anchor_hash);
    int best = wrc_best_header(datadir, tip, anchor, &headers);
    int top = wrc_max(wrc_max(tip, anchor), best) - WALLET_BIRTHDAY_MARGIN;
    memset(f, 0, sizeof(*f));
    if (top > 0) {
        wrc_offer_row(ndb, wrc_min(tip, top), f);
        wrc_offer_header(headers, wrc_min(best, top), f);
        wrc_offer_pinned(top, anchor, anchor_hash, f);
    }
    block_index_flat_cursor_close(headers);
}

static void wrc_record_birthday(const struct wallet_recovery_request *req,
                                struct node_db *ndb, struct wallet *w, bool local_creation,
                                struct wallet_recovery_report *out)
{
    struct wrc_floor f;
    if (!req->record_birthday)
        return;
    if (req->birthday_at_local_tip) {
        wrc_release_floor(&f);
    } else {
        wrc_birthday_floor(req->datadir, ndb, &f);
    }
    int64_t birthday = (int64_t)f.height + WALLET_BIRTHDAY_MARGIN;
    uint8_t identity[32];
    bool valid = f.height > 0 && f.height <= INT_MAX - WALLET_BIRTHDAY_MARGIN;
    out->birthday_recorded = valid && (local_creation
        ? (wallet_scan_identity(w, identity) && db_wallet_birthday_set_created(ndb, birthday, f.hash, identity))
        : db_wallet_birthday_set(ndb, birthday, f.hash));
    out->birthday_height = out->birthday_recorded ? birthday : 0;
    if (out->birthday_recorded)
        memcpy(out->birthday_hash, f.hash, sizeof(f.hash));
}

/* The highest checkpoint compiled into this binary on mainnet: the sha3 UTXO
 * checkpoint, the ROM keystone or a baked ROM rung. 0 elsewhere. A mint by this
 * binary cannot hold funds below any of them. */
static int wrc_highest_compiled(uint8_t hash[32])
{
    int height = wrc_shipped_anchor(hash);
    const struct rom_state_checkpoint *ks = get_rom_state_checkpoint();
    if (height <= 0)
        return 0;
    if (ks && ks->height > height) {
        height = ks->height;
        memcpy(hash, ks->block_hash, 32);
    }
    for (size_t i = 0; i < get_rom_state_rung_count(); i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height > height) {
            height = r->cp.height;
            memcpy(hash, r->cp.block_hash, 32);
        }
    }
    return height;
}

bool wallet_recovery_record_fresh_birthday(const char *datadir,
                                           struct node_db *ndb,
                                           int64_t *birthday_out)
{
    struct wrc_floor f;
    if (birthday_out)
        *birthday_out = 0;
    if (!ndb || !ndb->open) {
        LOG_WARN(WRC_TAG, "fresh birthday not recorded: node.db is not open");
        return false;
    }
    wrc_birthday_floor(datadir ? datadir : "", ndb, &f);
    /* Keys drawn by this running binary postdate every checkpoint compiled
     * into it, so the highest of them is a floor too, whichever is higher. */
    struct wrc_floor release;
    memset(&release, 0, sizeof(release));
    release.height = wrc_highest_compiled(release.hash);
    wrc_floor_offer(&f, release.height, release.hash);
    if (f.height <= 0 || f.height > INT_MAX - WALLET_BIRTHDAY_MARGIN)
        return false;
    int64_t birthday = (int64_t)f.height + WALLET_BIRTHDAY_MARGIN;
    if (!db_wallet_birthday_set_if_absent(ndb, birthday, f.hash)) {
        LOG_WARN(WRC_TAG, "fresh birthday %lld could not be stored",
                 (long long)birthday);
        return false;
    }
    if (birthday_out)
        *birthday_out = birthday;
    return true;
}

/* True when the caller's birthday names a block this datadir holds: the block
 * WALLET_BIRTHDAY_MARGIN below the height must exist, connected, with the
 * given hash. This is the test wallet_birthday_check applies to the active
 * chain at boot, made against the stored chain rows because an offline
 * restore has no in-memory chain; boot repeats it and marks the wallet unread
 * from 0 if the chain has since moved. Chain membership does not show the
 * phrase is new: the caller vouches for that. */
static bool wrc_birthday_verified(const struct wallet_recovery_request *req,
                                  struct node_db *ndb)
{
    struct db_block floor_block;
    if (!req->has_birthday || !ndb || !ndb->open ||
        req->birthday_height <= WALLET_BIRTHDAY_MARGIN ||
        req->birthday_height > INT_MAX)
        return false;
    return db_block_find_by_height(
               ndb, (int)req->birthday_height - WALLET_BIRTHDAY_MARGIN,
               &floor_block) &&
           memcmp(floor_block.hash, req->birthday_hash,
                  sizeof(floor_block.hash)) == 0;
}

/* Store a verified birthday for a restored wallet. False leaves the wallet
 * without one, and the caller marks it unread. */
static bool wrc_honour_birthday(const struct wallet_recovery_request *req,
                                struct node_db *ndb,
                                struct wallet_recovery_report *out)
{
    if (!wrc_birthday_verified(req, ndb) ||
        !db_wallet_birthday_set(ndb, req->birthday_height,
                                req->birthday_hash))
        return false;
    out->birthday_recorded = true;
    out->birthday_height = req->birthday_height;
    memcpy(out->birthday_hash, req->birthday_hash, sizeof(out->birthday_hash));
    return true;
}

struct wrc_lowest {
    int height;
    bool found;
};

static bool wrc_lowest_cb(int height, const struct db_block *row, void *ctx)
{
    (void)row;
    struct wrc_lowest *low = ctx;
    low->height = height;
    low->found = true;
    return false;
}

/* What this datadir cannot show of the phrase's history. A datadir seeded
 * from a snapshot holds no connected block below its seed height, so coins
 * received there stay unseen unless a verified birthday shows the phrase is
 * newer than the seed. The seed height is the lowest connected block the
 * datadir holds; a datadir with no block is not seeded yet, and its wallet is
 * marked unread. A read that fails counts as seeded. */
static bool wrc_seeded(struct node_db *ndb, struct wallet_recovery_report *out)
{
    struct wrc_lowest low = { 0, false };
    out->seed_floor_height = 0;
    if (!ndb || !ndb->open)
        return false;
    bool done = db_block_scan_height_range_probe(ndb, 0, INT_MAX - 1,
                                                 wrc_lowest_cb, &low);
    if (!done && !low.found)
        return true;
    out->seed_floor_height = low.found ? low.height : 0;
    return out->seed_floor_height > 0;
}

/* Facts the plan and the commit both report about history and the birthday. */
static void wrc_report_history(const struct wallet_recovery_request *req,
                               struct wallet_recovery_report *out,
                               bool seeded, bool birthday_ok)
{
    out->history_below_seed_hidden =
        seeded && !req->record_birthday && !birthday_ok;
    out->birthday_rejected = req->has_birthday && !birthday_ok;
}

/* Read the history facts before any write handle exists, so the plan reports
 * what the commit will do. Returns whether the datadir is seeded. */
static bool wrc_assess_history(const struct wallet_recovery_request *req,
                               struct node_db *ndb,
                               struct wallet_recovery_report *out)
{
    bool seeded = wrc_seeded(ndb, out);
    wrc_report_history(req, out, seeded, wrc_birthday_verified(req, ndb));
    return seeded;
}

/* A restored wallet has read none of the chain. Boot defers a long range, so
 * the wallet must say so: a verified birthday is stored, and without one a
 * pending retry from height 0 keeps the wallet reading incomplete until a
 * rescan reads the range. Creation has its own birthday. */
void wrc_settle_birthday(const struct wallet_recovery_request *req,
                                struct node_db *ndb, struct wallet *w,
                                bool seeded,
                                struct wallet_recovery_report *out)
{
    bool honoured = wrc_honour_birthday(req, ndb, out);
    wrc_mark_unread(req, w, honoured);
    wrc_report_history(req, out, seeded, honoured);
}

/* Create and restore unlock and then force-lock the process-wide wallet lock
 * to write their datadir, which would lock or re-key a wallet this process
 * serves. -70 when boot has marked one. */
struct zcl_result wallet_recovery_refuse_live_process(void)
{
    if (!wallet_lock_has_live_wallet())
        return ZCL_OK;
    return ZCL_ERR(-70,
        "this process already serves a wallet. Creating or restoring one "
        "unlocks and then locks the whole process, which would lock or "
        "re-key that wallet: run it in its own process. Nothing was "
        "written");
}

/* The request's own shape, refused before anything is read or written. */
struct zcl_result wrc_check_request(
    const struct wallet_recovery_request *req)
{
    if (!req->dry_run) {
        struct zcl_result live = wallet_recovery_refuse_live_process();
        if (!live.ok)
            return live;
    }
    if (!req->datadir || !req->datadir[0])
        return ZCL_ERR(-63, "datadir path is empty");
    if (!req->phrase || !req->phrase[0])
        return ZCL_ERR(-60, "a recovery phrase is required");
    if (req->passphrase &&
        strlen(req->passphrase) < (size_t)WALLET_CREATE_MIN_PASSPHRASE)
        return ZCL_ERR(-68,
            "the passphrase is shorter than %d bytes. The wallet is encrypted "
            "from its first write, so it is refused rather than written with "
            "a weak one. Nothing was written",
            WALLET_CREATE_MIN_PASSPHRASE);
    if (req->birthday_at_local_tip && req->has_birthday)
        return ZCL_ERR(-71,
            "a birthday was named and birthday_at_local_tip was also set. "
            "They are two sources for one value, so neither is used. Send "
            "one. Nothing was written");
    return ZCL_OK;
}

/* ── recover ─────────────────────────────────────────────────────── */

/* Mark a release-new phrase for the pinned birthday path and new-phrase scan. */
static const struct wallet_recovery_request *
wrc_with_tip_birthday(const struct wallet_recovery_request *req,
                      struct wallet_recovery_request *scratch)
{
    if (!req->birthday_at_local_tip)
        return req;
    *scratch = *req;
    scratch->record_birthday = true;
    return scratch;
}

/* What the inspected target allows, before any write handle exists: -62 when
 * it already holds a wallet, on a plan as on a commit. */
static struct zcl_result wrc_target_gate(const struct wallet_recovery_report *out)
{
    if (wrc_wallet_present(out)) {
        LOG_WARN(WRC_TAG, "refusing recovery: %s already holds a wallet "
                 "(%lld keys, seed_state=%d)", out->target_db,
                 (long long)out->keys_before, (int)out->seed_state_before);
        return ZCL_ERR(-62,
            "%s already holds a wallet (%lld keys). Recovering here would "
            "leave a wallet whose keys came from two different seeds and no "
            "way to tell them apart. Recover into an empty datadir instead, "
            "then move what you need",
            out->datadir, (long long)out->keys_before);
    }
    return ZCL_OK;
}

/* Close whatever the run still holds, handles first, the lock last. */
void wrc_run_release(struct wrc_run *st)
{
    if (st->have_ws) wallet_sqlite_close(&st->ws);
    if (st->ro_open) zcl_native_node_db_close_readonly(&st->ro_db, &st->ndb);
    else if (st->have_db) node_db_close(&st->ndb);
    /* Last: the lock outlives every handle it protects. */
    wallet_restore_datadir_release(&st->wlock);
}

/* From the phrase alone: shape check, seed, addresses. */
struct zcl_result wrc_phrase_to_addresses(
    const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out)
{
    out->word_count = wrc_word_count(req->phrase);
    /* Refuse on shape, and describe the shape — never the words. */
    if (!mnemonic_validate(req->phrase)) {
        LOG_WARN(WRC_TAG, "refusing recovery: phrase failed BIP39 validation "
                 "(%d words)", out->word_count);
        return ZCL_ERR(-60,
            "that is not a valid recovery phrase (%d words read). A phrase is "
            "12, 15, 18, 21 or 24 words from the BIP39 word list, in the "
            "order they were written down, and its last word is a checksum — "
            "so a single mistyped or reordered word fails here rather than "
            "silently opening an empty wallet",
            out->word_count);
    }
    out->phrase_valid = true;

    uint8_t seed[32];
    if (!mnemonic_to_wallet_seed(req->phrase, NULL, seed)) {
        memory_cleanse(seed, sizeof(seed));
        return ZCL_ERR(-64, "could not derive the wallet seed from the phrase");
    }

    /* The addresses come from the phrase alone: a dry run can show the user
     * exactly which wallet these words open before anything is written. */
    if (!wrc_fill_addresses(seed, out)) {
        memory_cleanse(seed, sizeof(seed));
        return ZCL_ERR(-64, "could not derive addresses from the phrase");
    }
    memory_cleanse(seed, sizeof(seed));
    return ZCL_OK;
}

/* The two refusals that must land before any directory is created. */
static struct zcl_result wrc_pre_directory_gates(
    const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out)
{
    /* Single-writer proof BEFORE anything opens the datadir, on both paths.
     * A datadir that does not exist yet cannot be held, so this is safe to
     * run before the directory is created. */
    struct zcl_result lock_r = wallet_restore_datadir_free(req->datadir);
    if (!lock_r.ok) {
        LOG_WARN(WRC_TAG, "refusing recovery: %s", lock_r.message);
        return ZCL_ERR(-61, "%s", lock_r.message);
    }

    /* The at-rest decision, before a directory is created — a refusal that
     * arrives after the datadir exists has already changed the disk. */
    if (req->dry_run) {
        /* A plan writes nothing, so it does not refuse; it says what the
         * commit would do under these inputs and this policy. */
        enum wallet_at_rest_policy d = wrc_at_rest_decision(req->passphrase);
        out->encrypted_at_rest = d == WALLET_AT_REST_ENCRYPTED;
        out->commit_refused_at_rest = d == WALLET_AT_REST_REFUSE;
    } else {
        struct zcl_result pr = wrc_at_rest_gate(req->passphrase);
        if (!pr.ok) {
            LOG_WARN(WRC_TAG, "refusing recovery: %s", pr.message);
            return pr;
        }
    }
    return ZCL_OK;
}

/* The writer's lock; a plan takes none. */
struct zcl_result wrc_take_writer_lock(
    const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *st)
{
    /* ── the WRITER's lock, held from here to the flush ──────────────
     *
     * wallet_restore_datadir_free() above answered "is a node holding
     * this?" and let go. That is not enough for a writer: two recoveries
     * into the same empty datadir both read "no wallet here" and both
     * wrote, leaving 480 keys from two different seeds under one seed row.
     * The exclusive lock below spans the check AND the write, so the second
     * caller is refused by name instead of racing.
     *
     * A plan takes no lock: it writes nothing, so there is nothing to
     * serialize, and taking one would mean a preview could block a real
     * recovery. */
    memset(&st->wlock, 0, sizeof(st->wlock));
    st->wlock.fd = -1;
    if (!req->dry_run) {
        struct zcl_result dr = wrc_ensure_datadir(req->datadir, out);
        if (!dr.ok)
            return dr;
        struct zcl_result hr =
            wallet_restore_datadir_hold(req->datadir, &st->wlock);
        if (!hr.ok) {
            LOG_WARN(WRC_TAG, "refusing recovery: %s", hr.message);
            return ZCL_ERR(-61, "%s", hr.message);
        }
    }
    return ZCL_OK;
}

/* Open an existing target read-only and prove it intact. */
struct zcl_result wrc_open_existing_target_ro(
    const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *st)
{
    /* The node's own last clean shutdown, bound to this exact file identity,
     * proves node.db intact as it stands now. The writer's lock serializes
     * recovery runs only and a node never takes it; a node that starts after
     * this read holds node.db's owner lease while it runs, so the commit's
     * write open is refused (-63) instead of writing under it. A plan opens
     * no write handle for that lease to refuse, so it always runs the check.
     * Read before any handle opens the file. */
    bool verified_clean = !req->dry_run &&
        boot_shutdown_marker_peek_verified_clean(req->datadir, out->target_db);
    char ro_path[1200];
    enum zcl_node_db_ro_status ro = zcl_native_node_db_open_readonly(
        req->datadir, &st->ro_db, &st->ndb, ro_path, sizeof(ro_path));
    if (ro != ZCL_NODE_DB_RO_OK) {
        wallet_restore_datadir_release(&st->wlock);
        LOG_WARN(WRC_TAG, "refusing recovery: node.db at %s did not open "
                 "read-only (status=%d)", out->target_db, (int)ro);
        return ZCL_ERR(-66,
            "there is a node.db at %s and it would not open for reading, "
            "so this cannot tell whether recovering here would write "
            "over a wallet. It has NOT been touched, renamed or "
            "replaced. Take a copy of that datadir, then recover into a "
            "NEW empty one", out->target_db);
    }
    st->have_db = true;
    st->ro_open = true;

    /* The deeper read the boot open would do. Running it HERE, on the
     * read-only handle, is what turns "damaged database" into a refusal
     * instead of a quarantine; the write open below neither repeats it nor
     * renames anything aside. Only paid when a node.db already exists
     * without a verified-clean binding. */
    if (!verified_clean &&
        !node_db_quick_check_ok(st->ro_db, out->target_db)) {
        zcl_native_node_db_close_readonly(&st->ro_db, &st->ndb);
        wallet_restore_datadir_release(&st->wlock);
        LOG_WARN(WRC_TAG, "refusing recovery: quick_check failed on %s",
                 out->target_db);
        return ZCL_ERR(-66,
            "the node.db at %s is damaged (its integrity check failed), "
            "so this cannot tell whether recovering here would write "
            "over a wallet. It has NOT been touched, renamed or "
            "replaced. Take a copy of that datadir, then recover into a "
            "NEW empty one", out->target_db);
    }
    return ZCL_OK;
}

/* Read the existing wallet's key and seed facts through the open handle. */
struct zcl_result wrc_read_existing_wallet_facts(
    struct wallet_recovery_report *out, struct wrc_run *st)
{
    struct zcl_result wr = wallet_sqlite_open_r(&st->ws, st->ndb.db);
    if (!wr.ok) {
        zcl_native_node_db_close_readonly(&st->ro_db, &st->ndb);
        wallet_restore_datadir_release(&st->wlock);
        return ZCL_ERR(-63, "cannot open the wallet tables in %s: %s",
                       out->target_db, wr.message);
    }
    st->have_ws = true;

    out->keys_before = db_wallet_key_count(&st->ndb);
    out->keys_after = out->keys_before;
    /* The ROW question, not the readability one. A LOCKED seed is a
     * seed: recovering over it would put a second seed on a wallet
     * whose first one is merely shut, and the owner would have no way
     * to tell which keys came from which. */
    out->seed_state_before = wallet_sqlite_sapling_seed_state(&st->ws, NULL);
    out->seed_present_before =
        wallet_seed_state_row_present(out->seed_state_before);
    wrc_count_shielded_rows(&st->ndb, out);
    return ZCL_OK;
}

/* Swap the read-only handle for the real write handle. */
struct zcl_result wrc_swap_to_write_handle(
    struct wallet_recovery_report *out, struct wrc_run *st)
{
    if (st->have_ws) { wallet_sqlite_close(&st->ws); st->have_ws = false; }
    if (st->ro_open) {
        zcl_native_node_db_close_readonly(&st->ro_db, &st->ndb);
        st->ro_open = false;
        st->have_db = false;
    }
    /* An existing target was proven intact before this point, by its
     * clean-shutdown binding or by the read-only check, so it gets the
     * runtime open: no second full read of the file and no boot repair that
     * could rename it aside. Only a target this run creates gets the boot
     * open. */
    bool opened = out->target_created
        ? node_db_open(&st->ndb, out->target_db)
        : node_db_open_runtime(&st->ndb, out->target_db,
                               "wallet_recovery.restore");
    if (!opened) {
        wallet_restore_datadir_release(&st->wlock);
        return ZCL_ERR(-63, "cannot open target database %s",
                       out->target_db);
    }
    st->have_db = true;
    /* Before a single key lands in it. */
    wrc_tighten_modes(out->target_db);
    struct zcl_result wr = wallet_sqlite_open_r(&st->ws, st->ndb.db);
    if (!wr.ok) {
        node_db_close(&st->ndb);
        wallet_restore_datadir_release(&st->wlock);
        return ZCL_ERR(-63, "cannot open the wallet tables in %s: %s",
                       out->target_db, wr.message);
    }
    st->have_ws = true;
    return ZCL_OK;
}

/* The chain the gap scan asks, or NULL to derive the floor without reading
 * it. A shielded-only rebuild derives no transparent key, so nothing would
 * use the answer. A phrase made just now (drawn by a create, or restored
 * with birthday_at_local_tip) has no history to find, so its keys are the
 * floor; asking would read the chain once per derived address for an answer
 * already known. An open node.db is not by itself a chain: a freshly created
 * one has the tables and no rows, and every address probe against it
 * answers false for a reason that has nothing to do with the address. Ask
 * only when there is something to ask, so "no history found" is never
 * printed for "nothing to look in". out->history_skip records which reason
 * held, so the reply states it rather than "no chain" for every one. */
static struct node_db *wrc_history_oracle(
    const struct wallet_recovery_request *req, struct wrc_run *st,
    struct wallet_recovery_report *out)
{
    out->history_skip =
        req->shielded_only     ? WALLET_RECOVERY_HISTORY_SHIELDED_ONLY
        : req->record_birthday ? WALLET_RECOVERY_HISTORY_NEW_PHRASE
                               : WALLET_RECOVERY_HISTORY_NO_CHAIN;
    if (out->history_skip != WALLET_RECOVERY_HISTORY_NO_CHAIN || !st->have_db)
        return NULL;
    return db_address_index_populated(&st->ndb) ? &st->ndb : NULL;
}

/* Root the wallet on the phrase, rebuild its keys and, on a commit, flush. */
static struct zcl_result wrc_rebuild_and_flush(
    const struct wallet_recovery_request *req, struct wrc_run *st,
    struct wallet *w, bool seeded, bool local_creation, bool *recovery_pass_loaded,
    struct wallet_recovery_report *out)
{
    struct zcl_result rc = ZCL_OK;
    if (!wallet_init_from_recovery_phrase(w, req->phrase))
        return ZCL_ERR(-64, "could not root the wallet on the recovery phrase");
    /* Same scan on both paths, against the same chain, so the plan's
     * numbers are the commit's numbers. */
    rc = wrc_rebuild_keys(w, wrc_history_oracle(req, st, out),
                          req->shielded_only, out);
    if (!rc.ok)
        return rc;

    if (req->dry_run) {
        out->keys_after = out->keys_before;
        return rc;
    }

    wrc_settle_birthday(req, &st->ndb, w, seeded, out);

    /* Creation policy may accept a one-shot environment passphrase, but that
     * variable must never auto-unlock the live wallet. Load it only across
     * this offline flush, then scrub and force-lock before returning. */
    rc = wrc_load_passphrase(req, recovery_pass_loaded);
    if (!rc.ok)
        return rc;
    out->encrypted_at_rest = *recovery_pass_loaded;

    /* One writer: the encryption-aware wallet_sqlite layer, in one
     * transaction, exactly as boot flushes a freshly minted keypool. */
    struct zcl_result fr = wallet_sqlite_flush_r(&st->ws, w);
    if (!fr.ok)
        return ZCL_ERR(-65, "could not save the recovered wallet: %s",
                       fr.message);
    out->keys_after = db_wallet_key_count(&st->ndb);
    out->seed_installed = true;
    wrc_record_birthday(req, &st->ndb, w, local_creation, out);
    node_db_wal_checkpoint(&st->ndb);
    /* Again after the write: the checkpoint can recreate -wal/-shm, and
     * those hold the same key bytes as the database they front. */
    wrc_tighten_modes(out->target_db);
    return rc;
}


/* Inspect the target read-only and settle every refusal that precedes a
 * write handle; on a commit, swap in the write handle. On failure the run's
 * handles and lock are already released. */
struct zcl_result wrc_inspect_and_open_target(
    const struct wallet_recovery_request *req,
    struct wallet_recovery_report *out, struct wrc_run *st, bool *seeded, bool strict_creation)
{
    /* ── inspect the target, READ-ONLY, on both paths ─────────────────
     *
     * The plan half of this was already right and the commit half was not.
     * The commit called node_db_open() — the datadir BOOT CEREMONY:
     * READWRITE|CREATE, then PRAGMA quick_check and, on failure,
     * db_quarantine_files(), which rename()s the user's node.db,
     * node.db-wal and node.db-shm aside to node.db.corrupt-<ts> and puts a
     * fresh empty database in their place. The "this datadir already holds
     * a wallet" refusal then read that NEW EMPTY database, saw zero keys,
     * and recovered over the top — answering ok:true, keys_before:0,
     * wallet_already_present:false, with no mention of the rename. A
     * damaged node.db is exactly the state a person reaches for a recovery
     * command in.
     *
     * So BOTH paths now read an existing target through the read-only
     * handle (SQLITE_OPEN_READONLY + PRAGMA query_only=ON, no CREATE, no
     * migrate, no quarantine) and refuse on anything but OK. Nothing opens
     * for write until the target is proven readable AND wallet-free. */
    if (!out->target_created) {
        struct zcl_result ror = wrc_open_existing_target_ro(req, out, st);
        if (!ror.ok)
            return ror;
    }

    if (st->have_db) {
        struct zcl_result fr = wrc_read_existing_wallet_facts(out, st);
        if (!fr.ok)
            return fr;
    }

    if (st->have_db) {
        struct wallet_create_pending pending;
        enum wallet_birthday_proof_status ps = db_wallet_create_pending_get(&st->ndb, &pending);
        if (ps != WALLET_BIRTHDAY_PROOF_ABSENT &&
            !(ps == WALLET_BIRTHDAY_PROOF_FOUND && pending.committed)) {
            wrc_run_release(st);
            return ZCL_ERR(-62, "unfinished or unreadable wallet creation preparation");
        }
    }
    *seeded = wrc_assess_history(req, &st->ndb, out);

    /* Never write a second seed over a wallet that already has keys. */
    struct zcl_result gate = wrc_target_gate(out);
    if (!gate.ok) {
        wrc_run_release(st);
        return gate;
    }

    if (strict_creation && st->have_db && (!wrc_creation_wallet_free_r(st->ndb.db).ok ||
        !wrc_creation_no_auxiliary_keys_r(st->ndb.db).ok)) {
        wrc_run_release(st);
        return ZCL_ERR(-62, "creation target is not verifiably wallet-free");
    }

    /* Proven readable AND wallet-free. Only NOW may a write handle exist:
     * swap the read-only handle for the real one, which is allowed to
     * create the database when there is none. */
    if (!req->dry_run)
        return wrc_swap_to_write_handle(out, st);
    return ZCL_OK;
}

static struct zcl_result wallet_recovery_run_internal(const struct wallet_recovery_request *req,
                                      struct wallet_recovery_report *out, bool local_creation)
{
    if (!out)
        return ZCL_ERR(-60, "report is NULL");
    if (!req)
        return ZCL_ERR(-60, "request is NULL");
    wrc_reset(out, req->datadir);
    out->dry_run = req->dry_run;

    struct zcl_result shape = wrc_check_request(req);
    if (!shape.ok)
        return shape;
    struct wallet_recovery_request tip_req;
    req = wrc_with_tip_birthday(req, &tip_req);

    struct zcl_result addr_r = wrc_phrase_to_addresses(req, out);
    if (!addr_r.ok)
        return addr_r;

    struct zcl_result gates_r = wrc_pre_directory_gates(req, out);
    if (!gates_r.ok)
        return gates_r;

    struct wrc_run st;
    memset(&st, 0, sizeof(st));
    struct zcl_result lock_r = wrc_take_writer_lock(req, out, &st);
    if (!lock_r.ok)
        return lock_r;

    struct stat sb;
    /* Stat AFTER the lock: a competing writer that got there first has
     * already created node.db by now, and this is the read that sees it. */
    out->target_created = stat(out->target_db, &sb) != 0;

    bool seeded = false;
    struct zcl_result open_r = wrc_inspect_and_open_target(req, out, &st,
                                                           &seeded, local_creation);
    if (!open_r.ok)
        return open_r;

    /* Build the wallet the phrase describes. struct wallet is far too big
     * for the stack. */
    struct wallet *w = zcl_malloc(sizeof(*w), "wallet_recovery.wallet");
    if (!w) {
        wrc_run_release(&st);
        return ZCL_ERR(-64, "out of memory building the recovered wallet");
    }
    wallet_init(w);
    /* This wallet is a scratch built for another datadir, never the running
     * node's: the process-wide lock belongs to that wallet and must not
     * refuse the keys written here. */
    w->sapling_keys.follows_wallet_lock = false;

    bool recovery_pass_loaded = false;
    struct zcl_result rc = wrc_rebuild_and_flush(req, &st, w, seeded, local_creation,
                                                 &recovery_pass_loaded, out);

    if (recovery_pass_loaded)
        wallet_lock_lock(w);
    wallet_free(w);
    free(w);
    wrc_run_release(&st);
    return rc;
}

struct zcl_result wallet_recovery_run(const struct wallet_recovery_request *req, struct wallet_recovery_report *out)
{
    return wallet_recovery_run_internal(req, out, false);
}

struct zcl_result wallet_recovery_create_fresh(const struct wallet_recovery_request *req, struct wallet_recovery_report *out, char *phrase, size_t cap)
{
    if (!req || !phrase) return ZCL_ERR(-69, "invalid fresh wallet request");
    struct zcl_result generated = wallet_create_phrase(phrase, cap);
    if (!generated.ok) return generated;
    struct wallet_recovery_request fresh = *req;
    fresh.phrase = phrase; fresh.record_birthday = true; fresh.birthday_at_local_tip = false; fresh.has_birthday = false;
    return wallet_recovery_run_internal(&fresh, out, true);
}
