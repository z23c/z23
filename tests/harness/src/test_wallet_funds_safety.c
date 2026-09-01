/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_funds_safety — regression gates for the wallet funds-safety
 * fixes on branch sticky/wallet-fixes. Each block proves, at the model layer
 * (hermetic /tmp node.db), the exact defect the fix closes:
 *
 *  - MEDIUM: getbalance counted immature coinbase as spendable.
 *  - MEDIUM/LOW: z_getbalance ignored minconf in the SQLite path.
 *  - MEDIUM: transparent z_sendmany coin selection ignored the from-address.
 *  - HIGH: witness/list paths capped at 256 notes by value (notes beyond #256
 *    unspendable / invisible) — proven via the dynamic load helper.
 *  - HIGH: z_sendmany shielded never marked notes spent at broadcast, so a
 *    second send re-selected the same notes — proven via the selection query
 *    after a nullifier mark-spent.
 */

#include "test/test_core.h"

#include "models/database.h"
#include "models/wallet_tx.h"
#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/sync_controller.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define WFS_CHECK(name, expr) do {                       \
    printf("wallet_funds_safety: %s... ", (name));       \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* Save a block header at `height` so db_wallet_chain_tip_height() (MAX(height)
 * FROM blocks) reflects a known tip. */
static bool wfs_save_block(struct node_db *ndb, int height)
{
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, (uint8_t)(0x40 + (height & 0x0f)), 32);
    memset(blk.prev_hash, 0x0b, 32);
    memset(blk.merkle_root, 0x0c, 32);
    memset(blk.chain_work, 0x0d, 32);
    blk.height = height;
    blk.time = 12345;
    blk.bits = 0x1d00ffffU;
    blk.status = 3;
    static uint8_t sol[] = {0x01, 0x02};
    blk.solution = sol;
    blk.solution_len = sizeof(sol);
    return db_block_save(ndb, &blk);
}

static bool wfs_save_utxo(struct node_db *ndb, uint8_t txid_seed,
                          const uint8_t addr_hash[20], int64_t value,
                          int height, bool is_coinbase)
{
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memset(u.txid, txid_seed, 32);
    u.vout = 0;
    memcpy(u.address_hash, addr_hash, 20);
    u.value = value;
    u.height = height;
    u.is_coinbase = is_coinbase;
    u.script = (uint8_t *)"\x76\xa9\x14\x00\x88\xac";
    u.script_len = 6;
    return db_wallet_utxo_save(ndb, &u);
}

/* Persist a sapling note via the production sync path. nf_seed sets a distinct
 * nullifier so notes can be individually mark-spent. */
static bool wfs_save_note(struct node_db *ndb, uint8_t txid_seed,
                          const uint8_t ivk[32], int64_t value,
                          int block_height, uint8_t nf_seed)
{
    uint8_t txid[32], rcm[32], div[11], pk_d[32], cm[32], nf[32], memo[512];
    memset(txid, txid_seed, 32);
    memset(rcm, 0x05, 32);
    memset(div, 0x07, 11);
    memset(pk_d, 0x08, 32);
    memset(cm, txid_seed, 32);   /* distinct cm per note */
    memset(nf, nf_seed, 32);
    memset(memo, 0xF6, 512);
    return node_db_sync_sapling_note(ndb, txid, 0, value, rcm, memo, 512,
                                     ivk, div, pk_d, cm, nf, block_height);
}

static bool wfs_make_view_note(const char *address, uint8_t seed,
                               struct db_sapling_note *out)
{
    uint8_t div_full[32];

    if (!address || !address[0] || !out)
        return false;
    memset(out, 0, sizeof(*out));
    memset(out->txid, seed, 32);
    out->output_index = seed;
    out->value = 5000 + seed;
    out->block_height = 200;
    snprintf(out->address, sizeof(out->address), "%s", address);
    snprintf(out->source, sizeof(out->source), "%s",
             DB_SAPLING_NOTE_SOURCE_VIEW);
    wv_sapling_placeholder_fields_for_test(out->txid, (int)out->output_index,
                                           out->rcm, out->ivk, div_full,
                                           out->pk_d, out->cm,
                                           out->nullifier);
    memcpy(out->diversifier, div_full, sizeof(out->diversifier));
    return true;
}

int test_wallet_funds_safety(void);
int test_wallet_funds_safety(void)
{
    printf("\n=== wallet funds-safety regression gates ===\n");
    int failures = 0;

    char dbdir[256], dbpath[320];
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet_funds_safety", "main");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, dbpath);
    WFS_CHECK("node.db opened", opened);
    if (!opened) {
        (void)test_rm_rf_recursive(dbdir);
        return failures + 1;
    }

    /* ── MEDIUM: immature coinbase excluded from SPENDABLE balance ──────── */
    {
        bool ok = wfs_save_block(&ndb, 200);  /* tip = 200; maturity cut = 100 */
        uint8_t addr_a[20]; memset(addr_a, 0xA1, 20);
        /* mature coinbase (height 50, 150 deep) — spendable */
        ok = ok && wfs_save_utxo(&ndb, 0x10, addr_a, 1000, 50, true);
        /* immature coinbase (height 150, 50 deep < 100) — NOT spendable */
        ok = ok && wfs_save_utxo(&ndb, 0x11, addr_a, 2000, 150, true);
        /* normal output (height 199) — spendable */
        ok = ok && wfs_save_utxo(&ndb, 0x12, addr_a, 4000, 199, false);
        WFS_CHECK("seeded coinbase + normal UTXOs", ok);

        int64_t raw = db_wallet_utxo_balance(&ndb);
        int64_t spend = db_wallet_utxo_spendable_balance(&ndb, NULL);
        /* raw = all unspent = 1000+2000+4000 = 7000 (diagnostic total) */
        WFS_CHECK("raw balance includes immature coinbase (7000)", raw == 7000);
        /* spendable EXCLUDES the immature 2000 coinbase → 5000 */
        WFS_CHECK("spendable balance excludes immature coinbase (5000)",
                  spend == 5000);
        WFS_CHECK("spendable < raw while a coinbase is immature", spend < raw);
    }

    /* ── MEDIUM: transparent coin selection honors the from-address ─────── */
    {
        uint8_t addr_small[20]; memset(addr_small, 0xB1, 20);  /* 5 ZCL on A */
        uint8_t addr_big[20];   memset(addr_big,   0xB2, 20);  /* 100 on B  */
        bool ok = wfs_save_utxo(&ndb, 0x20, addr_small, 500000000LL, 199, false);
        ok = ok && wfs_save_utxo(&ndb, 0x21, addr_big, 10000000000LL, 199, false);
        WFS_CHECK("seeded two addresses (A small, B big)", ok);

        /* Send target 1 ZCL + fee from addr_small. The OLD global selector
         * would pick B's 100-ZCL coin first (value DESC) and then find no A
         * coins after post-filter. The address-scoped selector picks A's. */
        struct db_wallet_utxo sel[16];
        int n = db_wallet_utxo_select_coins_for_address(&ndb,
            100000000LL + 1000, 200, addr_small, sel, 16);
        int64_t sum = 0;
        bool only_a = (n > 0);
        for (int i = 0; i < n; i++) {
            sum += sel[i].value;
            if (memcmp(sel[i].address_hash, addr_small, 20) != 0)
                only_a = false;
        }
        WFS_CHECK("from-address selection returns A's coin (funded)",
                  n == 1 && only_a && sum == 500000000LL);
        for (int i = 0; i < n; i++) db_wallet_utxo_free(&sel[i]);

        /* And selection from the big address returns B's coin, not A's. */
        struct db_wallet_utxo selb[16];
        int nb = db_wallet_utxo_select_coins_for_address(&ndb,
            100000000LL + 1000, 200, addr_big, selb, 16);
        bool only_b = (nb == 1) &&
            memcmp(selb[0].address_hash, addr_big, 20) == 0;
        WFS_CHECK("from-address selection isolates the big address", only_b);
        for (int i = 0; i < nb; i++) db_wallet_utxo_free(&selb[i]);
    }

    /* ── MEDIUM/LOW: z_getbalance per-ivk SQLite balance honors minconf ─── */
    {
        uint8_t ivk_m[32]; memset(ivk_m, 0x31, 32);
        /* tip is 200 (from the earlier block save). Two notes for this ivk:
         * one deeply confirmed (h=100 → 101 confs) and one fresh (h=200 →
         * 1 conf). */
        bool ok = wfs_save_note(&ndb, 0x32, ivk_m, 3000, 100, 0x91);
        ok = ok && wfs_save_note(&ndb, 0x33, ivk_m, 7000, 200, 0x92);
        WFS_CHECK("seeded two shielded notes (deep + fresh)", ok);

        int tip = db_wallet_chain_tip_height(&ndb);
        WFS_CHECK("chain tip height resolves to 200", tip == 200);

        int64_t all_conf = db_sapling_note_balance_for_ivk(&ndb, ivk_m);
        int64_t mc1 = db_sapling_note_balance_for_ivk_minconf(&ndb, ivk_m, tip, 1);
        int64_t mc6 = db_sapling_note_balance_for_ivk_minconf(&ndb, ivk_m, tip, 6);
        WFS_CHECK("unfiltered ivk balance == 10000", all_conf == 10000);
        WFS_CHECK("minconf=1 counts both notes (10000)", mc1 == 10000);
        /* minconf=6 excludes the 1-conf fresh note → only the deep 3000 */
        WFS_CHECK("minconf=6 excludes the fresh 1-conf note (3000)",
                  mc6 == 3000);
    }

    /* ── HIGH: dynamic note load returns ALL notes (no 256-by-value cap) ── */
    {
        uint8_t ivk_big[32]; memset(ivk_big, 0x41, 32);
        const int N = 300;  /* > 256 */
        /* Unique (txid,cm,nf) per note; ascending value so the LOWEST-value
         * notes are exactly the ones a value-DESC top-256 cap would drop. */
        bool ok = true;
        for (int i = 0; i < N && ok; i++) {
            uint8_t txid[32], rcm[32], div[11], pk_d[32], cm[32], nf[32], memo[512];
            /* 4-byte little-endian counter embedded in txid/cm/nf to keep
             * them unique across 300 notes. */
            memset(txid, 0, 32); memset(cm, 0, 32); memset(nf, 0, 32);
            txid[0] = (uint8_t)i; txid[1] = (uint8_t)(i >> 8); txid[2] = 0x77;
            cm[0]   = (uint8_t)i; cm[1]   = (uint8_t)(i >> 8); cm[2]   = 0x78;
            nf[0]   = (uint8_t)i; nf[1]   = (uint8_t)(i >> 8); nf[2]   = 0x79;
            memset(rcm, 0x05, 32); memset(div, 0x07, 11);
            memset(pk_d, 0x08, 32); memset(memo, 0xF6, 512);
            ok = node_db_sync_sapling_note(&ndb, txid, 0, 1000 + i, rcm, memo,
                                           512, ivk_big, div, pk_d, cm, nf, 200);
        }
        WFS_CHECK("seeded 300 unspent notes for one ivk", ok);

        /* The fixed-cap load truncates at 256. */
        struct db_sapling_note capped[256];
        int n_capped = db_sapling_note_list_unspent(&ndb, capped, 256);
        WFS_CHECK("fixed-cap list truncates at 256 (the OLD behavior)",
                  n_capped == 256);

        int count = db_sapling_note_count_unspent(&ndb);
        WFS_CHECK("count_unspent sees all notes (>= 300)", count >= 300);

        /* The dynamic load returns every note. */
        struct db_sapling_note *all = NULL;
        int n_all = db_sapling_note_list_unspent_alloc(&ndb, &all);
        WFS_CHECK("dynamic list returns >= 300 notes (no value cap)",
                  n_all >= 300 && all != NULL);
        /* Confirm the lowest-value notes (rank > 256) are present. */
        bool found_smallest = false;
        for (int i = 0; i < n_all; i++)
            if (all[i].value == 1000) { found_smallest = true; break; }
        WFS_CHECK("smallest-value note (would be dropped by top-256) IS present",
                  found_smallest);
        free(all);
    }

    /* ── HIGH: marking a note spent excludes it from the SEND selection ─── */
    {
        uint8_t ivk_s[32]; memset(ivk_s, 0x61, 32);
        uint8_t nf_a[32]; memset(nf_a, 0xDA, 32);
        /* one spendable note for this ivk */
        bool ok = true;
        {
            uint8_t txid[32], rcm[32], div[11], pk_d[32], cm[32], memo[512];
            memset(txid, 0x62, 32); memset(rcm, 0x05, 32); memset(div, 0x07, 11);
            memset(pk_d, 0x08, 32); memset(cm, 0x63, 32); memset(memo, 0xF6, 512);
            ok = node_db_sync_sapling_note(&ndb, txid, 0, 9000, rcm, memo, 512,
                                           ivk_s, div, pk_d, cm, nf_a, 200);
        }
        WFS_CHECK("seeded a single spendable note for the send ivk", ok);

        struct db_sapling_note before[16];
        int n_before = db_sapling_note_list_unspent_for_ivk(&ndb, ivk_s, before, 16);
        WFS_CHECK("note is selectable BEFORE broadcast (1 note)", n_before == 1);

        /* Simulate the at-broadcast mark-spent the fix adds to z_sendmany. */
        uint8_t spending_txid[32]; memset(spending_txid, 0xEE, 32);
        enum db_mark_spent_result r =
            node_db_sync_sapling_spend(&ndb, nf_a, spending_txid);
        WFS_CHECK("mark-spent at broadcast succeeds (OK)", r == DB_MARK_SPENT_OK);

        struct db_sapling_note after[16];
        int n_after = db_sapling_note_list_unspent_for_ivk(&ndb, ivk_s, after, 16);
        /* The SECOND z_sendmany would now find zero notes — no double-spend of
         * the user's own note. */
        WFS_CHECK("note is NOT re-selected after broadcast (0 notes)",
                  n_after == 0);
    }

    /* ── HIGH: multi-note reservation is all-or-nothing ─────────────────── */
    {
        uint8_t ivk_b[32]; memset(ivk_b, 0x81, sizeof(ivk_b));
        uint8_t nf_0[32]; memset(nf_0, 0x82, sizeof(nf_0));
        uint8_t nf_1[32]; memset(nf_1, 0x83, sizeof(nf_1));
        bool ok = wfs_save_note(&ndb, 0x84, ivk_b, 4000, 200, 0x82);
        ok = ok && wfs_save_note(&ndb, 0x85, ivk_b, 5000, 200, 0x83);
        WFS_CHECK("seeded two notes for atomic reservation", ok);

        struct transaction tx;
        transaction_init(&tx);
        tx.v_shielded_spend = zcl_calloc(2, sizeof(*tx.v_shielded_spend),
                                         "wallet_funds_safety.batch_spends");
        tx.num_shielded_spend = tx.v_shielded_spend ? 2 : 0;
        memset(tx.hash.data, 0x86, sizeof(tx.hash.data));
        if (tx.v_shielded_spend) {
            memcpy(tx.v_shielded_spend[0].nullifier.data, nf_0, 32);
            memset(tx.v_shielded_spend[1].nullifier.data, 0xFF, 32);
        }

        WFS_CHECK("reservation probe identifies an available note",
            db_sapling_note_reservation_probe(&ndb, nf_0, tx.hash.data) ==
                DB_NOTE_RESERVATION_AVAILABLE);
        uint8_t missing_nf[32]; memset(missing_nf, 0xFE, sizeof(missing_nf));
        WFS_CHECK("reservation probe identifies a stale nullifier",
            db_sapling_note_reservation_probe(
                &ndb, missing_nf, tx.hash.data) ==
                DB_NOTE_RESERVATION_MISSING);

        bool reserved = tx.num_shielded_spend == 2 &&
            node_db_sync_wallet_sapling_spends(&ndb, &tx);
        WFS_CHECK("reservation rejects when any selected note is missing",
                  !reserved);
        struct db_sapling_note after_failed[4];
        int n_after_failed = db_sapling_note_list_unspent_for_ivk(
            &ndb, ivk_b, after_failed, 4);
        WFS_CHECK("failed reservation rolls back the earlier note update",
                  n_after_failed == 2);

        if (tx.v_shielded_spend)
            memcpy(tx.v_shielded_spend[1].nullifier.data, nf_1, 32);
        reserved = tx.num_shielded_spend == 2 &&
            node_db_sync_wallet_sapling_spends(&ndb, &tx);
        WFS_CHECK("reservation commits when every selected note exists",
                  reserved);
        struct db_sapling_note after_success[4];
        int n_after_success = db_sapling_note_list_unspent_for_ivk(
            &ndb, ivk_b, after_success, 4);
        WFS_CHECK("successful reservation hides both notes from reselection",
                  n_after_success == 0);

        /* Restart retry is idempotent, but a different transaction must not
         * steal the first transaction's durable note reservation. */
        WFS_CHECK("same transaction can replay its note reservation",
                  node_db_sync_wallet_sapling_spends(&ndb, &tx));
        WFS_CHECK("reservation probe recognizes the same transaction",
            db_sapling_note_reservation_probe(&ndb, nf_0, tx.hash.data) ==
                DB_NOTE_RESERVATION_SAME_TX);
        memset(tx.hash.data, 0x87, sizeof(tx.hash.data));
        WFS_CHECK("reservation probe identifies a conflicting transaction",
            db_sapling_note_reservation_probe(&ndb, nf_0, tx.hash.data) ==
                DB_NOTE_RESERVATION_CONFLICT);
        WFS_CHECK("conflicting transaction cannot replace note reservation",
                  !node_db_sync_wallet_sapling_spends(&ndb, &tx));
        memset(tx.hash.data, 0x86, sizeof(tx.hash.data));
        WFS_CHECK("expired transaction releases its exact note reservations",
                  db_sapling_note_release_reservation(&ndb, tx.hash.data));
        WFS_CHECK("released notes return to spendable selection",
            db_sapling_note_list_unspent_for_ivk(
                &ndb, ivk_b, after_success, 4) == 2);
        transaction_free(&tx);
    }

    /* Canonical block evidence must supersede an unconfirmed transaction's
     * reservation. Rolling back the loser afterward cannot resurrect the
     * mined note. */
    {
        uint8_t ivk_c[32]; memset(ivk_c, 0x88, sizeof(ivk_c));
        uint8_t nf_c[32]; memset(nf_c, 0x89, sizeof(nf_c));
        bool ok = wfs_save_note(&ndb, 0x8a, ivk_c, 6000, 200, 0x89);
        struct transaction losing;
        struct transaction mined;
        transaction_init(&losing);
        transaction_init(&mined);
        losing.v_shielded_spend = zcl_calloc(
            1, sizeof(*losing.v_shielded_spend),
            "wallet_funds_safety.losing_spend");
        mined.v_shielded_spend = zcl_calloc(
            1, sizeof(*mined.v_shielded_spend),
            "wallet_funds_safety.mined_spend");
        losing.num_shielded_spend = losing.v_shielded_spend ? 1 : 0;
        mined.num_shielded_spend = mined.v_shielded_spend ? 1 : 0;
        memset(losing.hash.data, 0x8b, sizeof(losing.hash.data));
        memset(mined.hash.data, 0x8c, sizeof(mined.hash.data));
        if (losing.v_shielded_spend)
            memcpy(losing.v_shielded_spend[0].nullifier.data, nf_c, 32);
        if (mined.v_shielded_spend)
            memcpy(mined.v_shielded_spend[0].nullifier.data, nf_c, 32);
        ok = ok && losing.num_shielded_spend == 1 &&
            mined.num_shielded_spend == 1 &&
            node_db_sync_wallet_sapling_spends(&ndb, &losing);
        WFS_CHECK("unconfirmed shielded transaction reserves its note", ok);
        ok = ok && node_db_sync_confirmed_sapling_spends(&ndb, &mined);
        WFS_CHECK("canonical shielded spend supersedes losing reservation", ok);
        ok = ok && db_sapling_note_release_reservation(
            &ndb, losing.hash.data);
        struct db_sapling_note should_be_empty[1];
        WFS_CHECK("losing rollback cannot resurrect canonically spent note",
            ok && db_sapling_note_reservation_probe(
                &ndb, nf_c, mined.hash.data) ==
                DB_NOTE_RESERVATION_SAME_TX &&
            db_sapling_note_list_unspent_for_ivk(
                &ndb, ivk_c, should_be_empty, 1) == 0);
        transaction_free(&losing);
        transaction_free(&mined);
    }

    /* Durable compensation deletes an unrelayed wallet transaction through
     * the same serialized node.db write lane used in production. */
    {
        struct db_wallet_tx txrow;
        uint8_t raw_tx = 0;
        memset(&txrow, 0, sizeof(txrow));
        memset(txrow.txid, 0x91, sizeof(txrow.txid));
        txrow.raw_tx = &raw_tx;
        txrow.raw_tx_len = sizeof(raw_tx);
        txrow.time_received = 1713000000;
        txrow.from_me = true;
        bool ok = db_wallet_tx_save(&ndb, &txrow);
        WFS_CHECK("seeded an unrelayed wallet row for compensation", ok);
        WFS_CHECK("serialized compensation deletes the durable wallet row",
                  ok && node_db_sync_wallet_tx_delete(&ndb, txrow.txid));
        struct db_wallet_tx absent;
        memset(&absent, 0, sizeof(absent));
        WFS_CHECK("compensated wallet row is absent",
                  !db_wallet_tx_find(&ndb, txrow.txid, &absent));
    }

    /* ── P3/qw11: zclassicd view notes are marked inert and non-clobbering ─ */
    {
        struct wallet *w = zcl_calloc(1, sizeof(*w),
                                      "wallet_funds_safety.wallet");
        bool ok = (w != NULL);
        if (w)
            wallet_init(w);
        uint8_t seed[32]; memset(seed, 0xA7, sizeof(seed));
        ok = ok && sapling_keystore_set_seed(&w->sapling_keys, seed);
        uint8_t d0[ZC_DIVERSIFIER_SIZE], pkd0[32];
        uint8_t d1[ZC_DIVERSIFIER_SIZE], pkd1[32];
        ok = ok && sapling_keystore_new_address(&w->sapling_keys, d0, pkd0);
        ok = ok && sapling_keystore_new_address(&w->sapling_keys, d1, pkd1);
        WFS_CHECK("derived two real sapling keys for view-note inertness", ok);

        const struct sapling_key_entry *key0 =
            ok ? &w->sapling_keys.keys[0] : NULL;
        const struct sapling_key_entry *key1 =
            ok ? &w->sapling_keys.keys[1] : NULL;
        const struct chain_params *cp = chain_params_get();
        char addr0[128] = "";
        char addr1[128] = "";
        ok = ok && cp &&
             sapling_encode_payment_address(key0->diversifier, key0->pk_d,
                 cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                 addr0, sizeof(addr0)) &&
             sapling_encode_payment_address(key1->diversifier, key1->pk_d,
                 cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                 addr1, sizeof(addr1));
        WFS_CHECK("encoded real sapling addresses for view-note inertness", ok);

        struct db_sapling_note view_notes[2];
        ok = ok && wfs_make_view_note(addr0, 0x71, &view_notes[0]);
        ok = ok && wfs_make_view_note(addr1, 0x72, &view_notes[1]);
        WFS_CHECK("built two zclassicd view-only placeholder notes", ok);
        WFS_CHECK("placeholder ivk differs from real keystore ivk",
                  ok && memcmp(view_notes[0].ivk, key0->ivk, 32) != 0 &&
                  memcmp(view_notes[1].ivk, key1->ivk, 32) != 0);

        ok = ok && wfs_save_note(&ndb, 0x70, key0->ivk, 1234, 200, 0xE1);
        WFS_CHECK("seeded one durable local catchup note", ok);
        int64_t before_local = ok
            ? db_sapling_note_balance_for_ivk(&ndb, key0->ivk)
            : 0;

        ok = ok && db_sapling_note_replace_view_rows(&ndb, view_notes, 2);
        WFS_CHECK("view-only replace writes placeholders through model API", ok);
        WFS_CHECK("view-only replace preserves local catchup note",
                  ok && before_local == 1234 &&
                  db_sapling_note_balance_for_ivk(&ndb, key0->ivk) == 1234);
        WFS_CHECK("view-only rows are discoverable by address marker",
                  ok &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr0) == 1 &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr1) == 1);

        ok = ok && db_sapling_note_replace_view_rows(&ndb, NULL, 0);
        WFS_CHECK("empty view refresh clears view rows but preserves local note",
                  ok &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr0) == 0 &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr1) == 0 &&
                  db_sapling_note_balance_for_ivk(&ndb, key0->ivk) == 1234);
        ok = ok && db_sapling_note_replace_view_rows(&ndb, view_notes, 2);
        WFS_CHECK("view-only replace restores placeholders after empty refresh",
                  ok &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr0) == 1 &&
                  db_sapling_note_count_unspent_view_for_address(&ndb, addr1) == 1);

        struct db_sapling_note real_sel[4];
        struct db_sapling_note view_sel[4];
        int n_real = ok
            ? db_sapling_note_list_unspent_for_ivk(&ndb, key0->ivk,
                                                   real_sel, 4)
            : -1;
        int n_view = ok
            ? db_sapling_note_list_unspent_for_ivk(&ndb, view_notes[0].ivk,
                                                   view_sel, 4)
            : -1;
        WFS_CHECK("real ivk selection sees local note but not view placeholder",
                  ok && n_real == 1 && real_sel[0].value == 1234 &&
                  strcmp(real_sel[0].source, DB_SAPLING_NOTE_SOURCE_LOCAL) == 0 &&
                  n_view == 1 &&
                  strcmp(view_sel[0].source, DB_SAPLING_NOTE_SOURCE_VIEW) == 0);

        struct wallet_rpc_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.wallet = w;
        ctx.node_db = &ndb;
        struct json_value result;
        json_init(&result);
        bool sent = false;
        if (ok && cp && key1) {
            sent = z_sendmany_shielded(&ctx, cp, key1, 1,
                                       NULL, NULL, 0,
                                       NULL, NULL, NULL, NULL, NULL, 0,
                                       NULL, &result);
        } else {
            json_set_str(&result, "setup failed");
        }
        WFS_CHECK("view-only spend attempt returns explicit message",
                  !sent &&
                  strcmp(json_get_str(&result),
                         "view-only balance synced from zclassicd") == 0);
        json_free(&result);
        if (w) {
            wallet_free(w);
            free(w);
        }
    }

    /* Trial decryption deliberately stores a position-0 placeholder
     * nullifier. Block-connect witness creation must replace it in the live
     * wallet by stable note identity, or immediate shielded change spends
     * cannot be marked/reserved without a later deep rescan. */
    {
        struct wallet *w = zcl_calloc(1, sizeof(*w),
                                      "wfs_nullifier_refresh_wallet");
        bool ok = w != NULL;
        if (w) {
            wallet_init(w);
            w->sapling_notes = zcl_calloc(
                1, sizeof(*w->sapling_notes), "wfs_nullifier_refresh_note");
            ok = ok && w->sapling_notes != NULL;
        }
        uint8_t txid[32], old_nf[32], real_nf[32];
        memset(txid, 0x41, sizeof(txid));
        memset(old_nf, 0x42, sizeof(old_nf));
        memset(real_nf, 0x43, sizeof(real_nf));
        if (ok) {
            w->num_sapling_notes = 1;
            w->sapling_notes_cap = 1;
            w->sapling_notes[0].used = true;
            w->sapling_notes[0].output_index = 7;
            memcpy(w->sapling_notes[0].txid.data, txid, sizeof(txid));
            memcpy(w->sapling_notes[0].nf, old_nf, sizeof(old_nf));
        }
        bool refreshed = ok && sync_wallet_note_nullifier_refresh_for_test(
            w, txid, 7, real_nf);
        bool wrong_output_refused = ok &&
            !sync_wallet_note_nullifier_refresh_for_test(
                w, txid, 8, old_nf);
        WFS_CHECK("witness creation replaces the live nullifier placeholder",
                  refreshed && wrong_output_refused &&
                  memcmp(w->sapling_notes[0].nf,
                         real_nf, sizeof(real_nf)) == 0);
        if (w) {
            wallet_free(w);
            free(w);
        }
    }

    node_db_close(&ndb);
    (void)test_rm_rf_recursive(dbdir);

    if (failures == 0)
        printf("wallet_funds_safety: OK (all funds-safety gates pass)\n");
    else
        printf("=== wallet_funds_safety: %d failure(s) ===\n", failures);
    return failures;
}
