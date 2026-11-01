/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_diversified_receive: the wallet hands out fresh ZIP-32 diversified
 * addresses of its one account, finds every note sent to any of them with the
 * account's incoming viewing key, and never issues an address twice.
 *
 * Every fixture is a recovered wallet in a private temporary datadir, built
 * from a fixed throwaway phrase through the shipped recovery service. Nothing
 * touches a running node, a canonical datadir, a real wallet or real funds.
 * Notes are real Sapling note encryptions with a zero proof; trial decryption
 * does not read the proof. The proof-bearing spend is covered by the
 * params-gated group simnet_wallet_diversified_send. */

#include "test/test_core.h"
#include "test/test_sync_probe_vfs.h"
#include "chain/chainparams.h"
#include "config/boot_wallet_phrase.h"
#include "config/command_catalog.h"
#include "controllers/sync_controller.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_shielded_controller.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_frontier_schema.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "sapling/constants.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/note_encryption.h"
#include "sapling/params_init.h"
#include "sapling/sapling_prover.h"
#include "sapling/sapling.h"
#include "sapling/zip32.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "sim/simnet.h"
#include "sim/simnet_sapling.h"
#include "services/agent_spend_policy.h"
#include "services/wallet_recovery_service.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "wallet/mnemonic.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WDR_PASS "wdr-fixture-passphrase"
#define WDR_UNIT ((uint64_t)100000000)
#define WDR_PAYERS 3

struct wdr {
    char dir[256];
    struct node_db ndb;
    struct wallet_sqlite ws;
    struct wallet *w;
    struct rpc_table *tbl;
    bool db_open;
    bool ws_open;
};

/* ── Fixture ─────────────────────────────────────────────────────── */

static bool wdr_phrase(char *out, size_t size)
{
    uint8_t entropy[16];
    memset(entropy, 0x2a, sizeof(entropy));
    return mnemonic_from_entropy(entropy, sizeof(entropy), out, size);
}

static void wdr_register(struct wdr *f)
{
    f->tbl = zcl_calloc(1, sizeof(*f->tbl), "wdr_rpc_table");
    if (!f->tbl)
        return;
    rpc_table_init(f->tbl);
    register_wallet_rpc_commands(f->tbl);
    char status[32];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
}

/* Load the wallet stored in f->dir, as a process start does. */
static bool wdr_boot(struct wdr *f)
{
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", f->dir);
    memset(&f->ndb, 0, sizeof(f->ndb));
    if (!node_db_open(&f->ndb, dbpath))
        return false;
    f->db_open = true;
    if (!wallet_sqlite_open_r(&f->ws, f->ndb.db).ok)
        return false;
    f->ws_open = true;
    f->w = zcl_calloc(1, sizeof(*f->w), "wdr_wallet");
    if (!f->w)
        return false;
    wallet_init(f->w);
    bool ok = wallet_sqlite_read_keys_r(&f->ws, f->w).ok;
    ok = wallet_sqlite_read_sapling_keys(&f->ws, f->w) && ok;
    rpc_wallet_set_state(f->w, NULL, f->dir, &f->ws, NULL, NULL);
    wallet_rpc_context_set_node_db(&f->ndb);
    return ok;
}

static void wdr_close(struct wdr *f)
{
    if (f->w) {
        wallet_free(f->w);
        free(f->w);
        f->w = NULL;
    }
    if (f->ws_open)
        wallet_sqlite_close(&f->ws);
    f->ws_open = false;
    wallet_rpc_context_set_node_db(NULL);
    if (f->db_open)
        node_db_close(&f->ndb);
    f->db_open = false;
}

/* Restore the fixed phrase into a new private datadir and boot it. */
static bool wdr_restore(struct wdr *f)
{
    memset(f, 0, sizeof(*f));
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    int n = snprintf(f->dir, sizeof(f->dir), "%s/test-tmp/wdr_XXXXXX", cwd);
    if (n <= 0 || (size_t)n >= sizeof(f->dir) ||
        !test_mkdtemp(f->dir, sizeof(f->dir), "wdr"))
        return false;
    char phrase[BOOT_WALLET_PHRASE_CAP];
    if (!wdr_phrase(phrase, sizeof(phrase)))
        return false;
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    struct wallet_recovery_request req = {
        .phrase = phrase, .datadir = f->dir, .dry_run = false };
    struct wallet_recovery_report rep;
    struct zcl_result r = wallet_recovery_run(&req, &rep);
    memory_cleanse(phrase, sizeof(phrase));
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    if (!r.ok)
        return false;
    wdr_register(f);
    return f->tbl && wdr_boot(f);
}

static void wdr_teardown(struct wdr *f)
{
    wdr_close(f);
    free(f->tbl);
    f->tbl = NULL;
    if (f->dir[0])
        (void)test_rm_rf_recursive(f->dir);
    f->dir[0] = '\0';
}

/* ── Calls ───────────────────────────────────────────────────────── */

/* z_getreceiveaddress: true with the address in `out`, or false with the
 * refusal text in `out`. */
static bool wdr_receive_text(struct wdr *f, char *out, size_t size)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(f->tbl, "z_getreceiveaddress", &params,
                                &result);
    const char *s = json_get_str(&result);
    if (ok && s && strncmp(s, "zs1", 3) == 0) {
        snprintf(out, size, "%s", s);
    } else {
        ok = false;
        snprintf(out, size, "%s", s ? s : "");
    }
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool wdr_receive(struct wdr *f, char *out, size_t size)
{
    char text[256];
    if (!wdr_receive_text(f, text, sizeof(text)))
        return false;
    snprintf(out, size, "%s", text);
    return true;
}

static bool wdr_account(struct wdr *f, struct sapling_key_entry *acct)
{
    return sapling_keystore_copy_account(&f->w->sapling_keys, acct);
}

static bool wdr_encode(const uint8_t d[11], const uint8_t pk_d[32], char *out,
                       size_t size)
{
    const struct chain_params *cp = chain_params_get();
    return sapling_encode_payment_address(
        d, pk_d, cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], out, size);
}

/* The address the n-th receive (n = 0 is the first) returns when the random
 * start index is `start`: derived here from the diversifier key alone, the
 * (n+1)-th valid diversifier index counting from `start`. */
static bool wdr_expected_from(const struct sapling_key_entry *acct,
                              uint64_t start, unsigned n, char *out,
                              size_t size)
{
    uint8_t j[11] = {0};
    uint8_t d[11], pk_d[32];
    for (int b = 0; b < 8; b++)
        j[b] = (uint8_t)(start >> (8 * b));
    for (unsigned k = 0; k <= n; k++) {
        if (k > 0) {
            for (int b = 0; b < 11 && ++j[b] == 0; b++) {}
        }
        if (!zip32_diversifier(acct->xfvk.dk, j, d))
            return false;
    }
    return sapling_ivk_to_pkd(acct->ivk, d, pk_d) &&
           wdr_encode(d, pk_d, out, size);
}

/* The default address, derived the same way: index 0. */
static bool wdr_default(const struct sapling_key_entry *acct, char *out,
                        size_t size)
{
    return wdr_expected_from(acct, 0, 0, out, size);
}

/* The default payment key of an unrelated seed: no wallet address shares its
 * pk_d. */
static bool wdr_foreign(uint8_t d[11], uint8_t pk_d[32])
{
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    struct zip32_xsk xsk;
    struct zip32_xfvk xfvk;
    zip32_xsk_master(&xsk, seed, sizeof(seed));
    zip32_xsk_to_xfvk(&xfvk, &xsk);
    bool ok = zip32_xfvk_address(&xfvk, d, pk_d);
    memory_cleanse(&xsk, sizeof(xsk));
    return ok;
}

/* A fixed random source: the starting index is WDR_START_MIN + g_wdr_draw. */
#define WDR_START_MIN ((uint64_t)1 << 40)
static uint64_t g_wdr_draw;
static bool g_wdr_rng_fails;

static bool wdr_rng(uint8_t *buf, size_t n)
{
    if (g_wdr_rng_fails)
        return false;
    for (size_t i = 0; i < n; i++)
        buf[i] = i < 8 ? (uint8_t)(g_wdr_draw >> (8 * i)) : 0;
    return true;
}

static uint64_t wdr_use_start(uint64_t draw)
{
    g_wdr_draw = draw;
    g_wdr_rng_fails = false;
    wallet_sqlite_diversifier_set_rng_for_test(wdr_rng);
    return WDR_START_MIN + draw;
}

static void wdr_use_system_rng(void)
{
    g_wdr_rng_fails = false;
    wallet_sqlite_diversifier_set_rng_for_test(NULL);
}

/* The stored next index for the account; false when none is recorded. */
static bool wdr_stored_next(struct wdr *f, const struct sapling_key_entry *acct,
                            uint64_t *next)
{
    sqlite3_stmt *s = NULL;
    bool have = false;
    if (sqlite3_prepare_v2(f->ndb.db,
            "SELECT next_index FROM wallet_sapling_diversifier WHERE ivk=?",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, acct->ivk, 32, SQLITE_STATIC);
    if (sqlite3_step(s) == SQLITE_ROW) {
        *next = (uint64_t)sqlite3_column_int64(s, 0);
        have = true;
    }
    sqlite3_finalize(s);
    return have;
}

/* ── Notes ───────────────────────────────────────────────────────── */

static bool wdr_build_tx(struct transaction *tx, const char *address,
                         uint64_t value)
{
    transaction_init(tx);
    uint8_t d[11], pk_d[32];
    if (!sapling_decode_payment_address(address, d, pk_d))
        return false;
    uint8_t ovk[32];
    memset(ovk, 0x5a, sizeof(ovk));
    uint8_t cv[32], cm[32], epk[32];
    uint8_t enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    uint8_t out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    uint8_t proof[GROTH_PROOF_SIZE];
    memset(proof, 0, sizeof(proof));
    if (!sapling_build_output_description(ovk, d, pk_d, value, NULL, cv, cm,
                                          epk, enc, out, proof, NULL))
        return false;
    tx->version = 4;
    tx->overwintered = true;
    tx->value_balance = -(int64_t)value;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "wdr_output");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;
    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, cv, 32);
    memcpy(od->cm.data, cm, 32);
    memcpy(od->ephemeral_key.data, epk, 32);
    memcpy(od->enc_ciphertext, enc, sizeof(enc));
    memcpy(od->out_ciphertext, out, sizeof(out));
    memcpy(od->zkproof, proof, sizeof(proof));
    return true;
}

/* Scan one transaction into the wallet and store each note found the way the
 * sync layer does. Returns the number of notes found. */
static int wdr_scan(struct wdr *f, const struct transaction *tx,
                    const struct uint256 *txid, int height)
{
    size_t before = f->w->num_sapling_notes;
    int found = wallet_try_sapling_decrypt(f->w, tx, txid);
    for (size_t i = before; i < f->w->num_sapling_notes; i++) {
        const struct sapling_received_note *n = &f->w->sapling_notes[i];
        if (!node_db_sync_sapling_note(&f->ndb, n->txid.data,
                n->output_index, (int64_t)n->value, n->rcm, n->memo, 512,
                n->ivk, n->diversifier, n->pk_d, n->cm, n->nf, height))
            return -1;
    }
    return found;
}

/* A payment of `value` to `address`, scanned as a block at height 100. */
static int wdr_deliver(struct wdr *f, const char *address, uint64_t value,
                       uint8_t tag)
{
    struct transaction tx;
    if (!wdr_build_tx(&tx, address, value))
        return -1;
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = tag;
    int found = wdr_scan(f, &tx, &txid, 100);
    transaction_free(&tx);
    return found;
}

static uint64_t wdr_total(const struct wdr *f)
{
    uint64_t total = 0;
    for (size_t i = 0; i < f->w->num_sapling_notes; i++)
        if (f->w->sapling_notes[i].used && !f->w->sapling_notes[i].spent)
            total += f->w->sapling_notes[i].value;
    return total;
}

/* True when a stored note was received on `address`, with its own
 * diversifier and pk_d, under the account's viewing key. */
static bool wdr_note_on(const struct wdr *f, const struct sapling_key_entry *acct,
                        const char *address, uint64_t value)
{
    uint8_t d[11], pk_d[32];
    if (!sapling_decode_payment_address(address, d, pk_d))
        return false;
    for (size_t i = 0; i < f->w->num_sapling_notes; i++) {
        const struct sapling_received_note *n = &f->w->sapling_notes[i];
        if (n->value == value && memcmp(n->diversifier, d, 11) == 0 &&
            memcmp(n->pk_d, pk_d, 32) == 0 &&
            memcmp(n->ivk, acct->ivk, 32) == 0)
            return true;
    }
    return false;
}

/* ── Tests ───────────────────────────────────────────────────────── */

/* The unspent notes the database holds for the account, as a restarted
 * process reads them: count and total, with each on its own diversifier. */
static bool wdr_db_notes(struct wdr *f, const struct sapling_key_entry *acct,
                         const char got[WDR_PAYERS][128], int *count,
                         uint64_t *total)
{
    struct db_sapling_note rows[16];
    int n = db_sapling_note_list_unspent_for_ivk(&f->ndb, acct->ivk, rows, 16);
    if (n < 0)
        return false;
    *count = n;
    *total = 0;
    int matched = 0;
    for (int i = 0; i < n; i++) {
        *total += (uint64_t)rows[i].value;
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            uint8_t d[11], pk_d[32];
            if (sapling_decode_payment_address(got[k], d, pk_d) &&
                memcmp(rows[i].diversifier, d, 11) == 0 &&
                memcmp(rows[i].pk_d, pk_d, 32) == 0)
                matched++;
        }
    }
    return matched == WDR_PAYERS;
}

/* Three receives, three payments, a restart that still holds the notes, then
 * a restore that finds all three with no list and never reissues one. */
static int test_receive_find_and_restore(void)
{
    int failures = 0;
    struct wdr f, g;
    memset(&f, 0, sizeof(f));
    memset(&g, 0, sizeof(g));
    TEST("wallet_diversified_receive: three addresses, three notes, restore") {
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        char def[128], got[WDR_PAYERS][128], want[128];
        ASSERT(wdr_default(&acct, def, sizeof(def)));
        ASSERT(wdr_encode(acct.diversifier, acct.pk_d, want, sizeof(want)));
        ASSERT_STR_EQ(def, want);

        /* Nothing is issued yet, so there is no latest address. */
        uint8_t ld[11], lpk[32];
        ASSERT(!wallet_sqlite_diversifier_latest(&f.ws, &acct, ld, lpk));

        uint64_t start = wdr_use_start(0x123456789ULL);
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            ASSERT(wdr_receive(&f, got[k], sizeof(got[k])));
            ASSERT(wdr_expected_from(&acct, start, k, want, sizeof(want)));
            ASSERT_STR_EQ(got[k], want);
            ASSERT(strcmp(got[k], def) != 0);
            for (unsigned j = 0; j < k; j++)
                ASSERT(strcmp(got[k], got[j]) != 0);
        }

        /* The latest query returns the last address issued and issues nothing. */
        for (int again = 0; again < 2; again++) {
            char latest[128];
            ASSERT(wallet_sqlite_diversifier_latest(&f.ws, &acct, ld, lpk));
            ASSERT(wdr_encode(ld, lpk, latest, sizeof(latest)));
            ASSERT_STR_EQ(latest, got[WDR_PAYERS - 1]);
        }

        uint64_t sum = 0;
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            uint64_t value = (k + 1) * WDR_UNIT;
            sum += value;
            ASSERT_EQ(wdr_deliver(&f, got[k], value, (uint8_t)(k + 1)), 1);
        }
        ASSERT(wdr_total(&f) == sum);
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(wdr_note_on(&f, &acct, got[k], (k + 1) * WDR_UNIT));

        /* A payment to the default address is found too and does not move
         * the issued index backwards. */
        ASSERT_EQ(wdr_deliver(&f, def, 7 * WDR_UNIT, 9), 1);
        char fourth[128];
        ASSERT(wdr_receive(&f, fourth, sizeof(fourth)));
        ASSERT(wdr_expected_from(&acct, start, WDR_PAYERS, want,
                                 sizeof(want)));
        ASSERT_STR_EQ(fourth, want);

        /* A restart: the database still holds all four notes, each on its
         * own diversifier, and the next address continues the sequence. */
        wdr_close(&f);
        ASSERT(wdr_boot(&f));
        int count = 0;
        uint64_t db_total = 0;
        ASSERT(wdr_db_notes(&f, &acct, (const char (*)[128])got, &count,
                            &db_total));
        ASSERT_EQ(count, WDR_PAYERS + 1);
        ASSERT(db_total == sum + 7 * WDR_UNIT);
        ASSERT(wdr_receive(&f, fourth, sizeof(fourth)));
        ASSERT(wdr_expected_from(&acct, start, WDR_PAYERS + 1, want,
                                 sizeof(want)));
        ASSERT_STR_EQ(fourth, want);

        /* Restore the same phrase into a new datadir: no index, no address
         * list, no chain history read. It draws a new random start, so the
         * first address it issues is none of the three already paid. */
        ASSERT(wdr_restore(&g));
        struct sapling_key_entry acct2;
        ASSERT(wdr_account(&g, &acct2));
        ASSERT(memcmp(acct.ivk, acct2.ivk, 32) == 0);
        uint64_t start2 = wdr_use_start(0x7edcba987ULL);
        char first_after[128];
        ASSERT(wdr_receive(&g, first_after, sizeof(first_after)));
        ASSERT(wdr_expected_from(&acct2, start2, 0, want, sizeof(want)));
        ASSERT_STR_EQ(first_after, want);
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(strcmp(first_after, got[k]) != 0);

        /* The scan then finds every note with no list. */
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT_EQ(wdr_deliver(&g, got[k], (k + 1) * WDR_UNIT,
                                  (uint8_t)(k + 1)), 1);
        ASSERT(wdr_total(&g) == sum);
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(wdr_note_on(&g, &acct2, got[k], (k + 1) * WDR_UNIT));
        char next[128];
        ASSERT(wdr_receive(&g, next, sizeof(next)));
        ASSERT(wdr_expected_from(&acct2, start2, 1, want, sizeof(want)));
        ASSERT_STR_EQ(next, want);
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(strcmp(next, got[k]) != 0);
        memory_cleanse(&acct, sizeof(acct));
        memory_cleanse(&acct2, sizeof(acct2));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    wdr_teardown(&g);
    return failures;
}

/* A call that fails after the index is recorded burns that index; the next
 * call, in a new process, returns a new address and never the burnt one. */
static int test_crash_after_index_write(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: index survives a failure and a restart") {
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        char first[128], burnt[128], again[128], want[128];
        uint64_t start = wdr_use_start(0x2468ace0ULL);
        ASSERT(wdr_receive(&f, first, sizeof(first)));
        ASSERT(wdr_expected_from(&acct, start, 0, want, sizeof(want)));
        ASSERT_STR_EQ(first, want);

        wallet_receive_fault_after_reserve_for_test(true);
        bool failed = !wdr_receive(&f, burnt, sizeof(burnt));
        wallet_receive_fault_after_reserve_for_test(false);
        ASSERT(failed);

        /* New process: reopen the database and reload the wallet. */
        wdr_close(&f);
        ASSERT(wdr_boot(&f));
        ASSERT(wdr_receive(&f, again, sizeof(again)));
        ASSERT(wdr_expected_from(&acct, start, 2, want, sizeof(want)));
        ASSERT_STR_EQ(again, want);
        ASSERT(wdr_expected_from(&acct, start, 1, want, sizeof(want)));
        ASSERT(strcmp(again, want) != 0);
        ASSERT(strcmp(again, first) != 0);
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    return failures;
}

static bool wdr_secrets_absent(const struct wallet *w)
{
    const struct sapling_keystore *sks = &w->sapling_keys;
    static const uint8_t zero[sizeof(struct zip32_xsk)];
    if (sks->has_seed)
        return false;
    for (size_t i = 0; i < 32; i++)
        if (sks->seed[i])
            return false;
    for (size_t i = 0; i < sks->num_keys; i++)
        if (memcmp(&sks->keys[i].xsk, zero, sizeof(zero)) != 0)
            return false;
    return true;
}

/* Receive works while the wallet is locked, in-process and after a locked
 * boot, and reads or writes no secret. */
static int test_receive_while_locked(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    const char *old = getenv("ZCL_WALLET_KDF_ITERS");
    char saved[32] = "";
    if (old)
        snprintf(saved, sizeof(saved), "%s", old);
    TEST("wallet_diversified_receive: works while the wallet is locked") {
        char iters[16];
        snprintf(iters, sizeof(iters), "%u", (unsigned)WKS_MIN_ITERS);
        setenv("ZCL_WALLET_KDF_ITERS", iters, 1);
        wallet_lock_reset_for_test();
        ASSERT(wallet_lock_unlock(NULL, NULL, WDR_PASS).ok);
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        char a[128], b[128], want[128];
        uint64_t start = wdr_use_start(0x13572468ULL);

        wallet_lock_lock(f.w);
        ASSERT(!wallet_lock_is_unlocked());
        ASSERT(wdr_secrets_absent(f.w));
        ASSERT(wdr_receive(&f, a, sizeof(a)));
        ASSERT(wdr_expected_from(&acct, start, 0, want, sizeof(want)));
        ASSERT_STR_EQ(a, want);
        ASSERT(wdr_secrets_absent(f.w));

        /* A locked boot: no passphrase, rows sealed. */
        wdr_close(&f);
        wallet_lock_reset_for_test();
        ASSERT(wdr_boot(&f));
        ASSERT(!wallet_lock_is_unlocked());
        ASSERT(wdr_secrets_absent(f.w));
        ASSERT(wdr_receive(&f, b, sizeof(b)));
        ASSERT(wdr_expected_from(&acct, start, 1, want, sizeof(want)));
        ASSERT_STR_EQ(b, want);
        ASSERT(wdr_secrets_absent(f.w));
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    wallet_lock_reset_for_test();
    if (old)
        setenv("ZCL_WALLET_KDF_ITERS", saved, 1);
    else
        unsetenv("ZCL_WALLET_KDF_ITERS");
    return failures;
}

/* The leaf is owner-only wallet authority and an agent session is refused. */
static int test_agent_session_refused(void)
{
    int failures = 0;
    TEST("wallet_diversified_receive: an agent session is refused") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            reg, "core.wallet.shielded.receive", NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->effect == ZCL_COMMAND_EFFECT_MUTATE);
        ASSERT(spec->risk == ZCL_COMMAND_RISK_WALLET);
        ASSERT(spec->authority == ZCL_COMMAND_AUTH_OWNER);

        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        struct agent_spend_policy_decision d;
        agent_spend_policy_evaluate("wdr-session-0123456789", spec, &in, false,
                                    &d);
        ASSERT(!d.allowed);
        agent_spend_policy_evaluate("wdr-session-0123456789", spec, &in, true,
                                    &d);
        ASSERT(!d.allowed);
        agent_spend_policy_evaluate(NULL, spec, &in, true, &d);
        ASSERT(d.allowed);
        json_free(&in);
        PASS();
    } _test_next:;
    return failures;
}

static char g_wdr_stub_reply[256];

static char *wdr_stub_rpc(const char *method, const char *params_json)
{
    (void)params_json;
    if (method && strcmp(method, "z_getreceiveaddress") == 0)
        return strdup(g_wdr_stub_reply);
    return strdup("null");
}

/* The leaf answers {"address":"zs1..."} and nothing else; a refusal from the
 * node is a failure, never an address. */
static int test_native_reply_shape(void)
{
    int failures = 0;
    TEST("wallet_diversified_receive: leaf reply is exactly {address}") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            reg, "core.wallet.shielded.receive", NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->availability == ZCL_COMMAND_READY);
        uint8_t d[11] = {0}, pk_d[32] = {0};
        char addr[128];
        ASSERT(wdr_encode(d, pk_d, addr, sizeof(addr)));
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        struct zcl_command_request req = {
            .spec = spec, .input = &in, .view = "normal",
        };
        struct zcl_command_reply reply;

        node_rpc_client_set_test_hook(wdr_stub_rpc);
        snprintf(g_wdr_stub_reply, sizeof(g_wdr_stub_reply), "\"%s\"", addr);
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_wallet_shielded_receive(&req, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ((int)reply.data.num_children, 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "address")), addr);
        ASSERT(reply.error.mutated);
        zcl_command_reply_free(&reply);

        snprintf(g_wdr_stub_reply, sizeof(g_wdr_stub_reply),
                 "\"Error: failed to record the address index\"");
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_wallet_shielded_receive(&req, &reply);
        ASSERT(reply.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get(&reply.data, "address") == NULL);
        zcl_command_reply_free(&reply);
        node_rpc_client_set_test_hook(NULL);
        json_free(&in);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static bool wdr_file_contains(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    bool found = false;
    char buf[8192];
    size_t keep = strlen(needle);
    size_t n;
    while (!found && (n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
        buf[n] = '\0';
        found = strstr(buf, needle) != NULL;
        if (!found && n == sizeof(buf) - 1 && keep > 1)
            (void)fseek(fp, -(long)(keep - 1), SEEK_CUR);
    }
    fclose(fp);
    return found;
}

/* No issued address reaches stdout or stderr, on success or on failure. */
static int test_no_address_in_logs(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    int saved_out = -1, saved_err = -1;
    TEST("wallet_diversified_receive: no address in a log") {
        ASSERT(wdr_restore(&f));
        char path[400];
        snprintf(path, sizeof(path), "%s/capture.log", f.dir);
        fflush(stdout);
        fflush(stderr);
        saved_out = dup(STDOUT_FILENO);
        saved_err = dup(STDERR_FILENO);
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        ASSERT(saved_out >= 0 && saved_err >= 0 && fd >= 0);
        ASSERT(dup2(fd, STDOUT_FILENO) >= 0 && dup2(fd, STDERR_FILENO) >= 0);
        close(fd);

        char a[128], b[128], c[128];
        bool ok_a = wdr_receive(&f, a, sizeof(a));
        bool ok_b = wdr_receive(&f, b, sizeof(b));
        wallet_receive_fault_after_reserve_for_test(true);
        bool failed = !wdr_receive(&f, c, sizeof(c));
        wallet_receive_fault_after_reserve_for_test(false);

        fflush(stdout);
        fflush(stderr);
        dup2(saved_out, STDOUT_FILENO);
        dup2(saved_err, STDERR_FILENO);
        close(saved_out);
        close(saved_err);
        saved_out = saved_err = -1;

        ASSERT(ok_a && ok_b && failed);
        /* The harness can see a log line at all: the failure path logs. */
        ASSERT(wdr_file_contains(path, "z_getreceiveaddress"));
        ASSERT(!wdr_file_contains(path, a));
        ASSERT(!wdr_file_contains(path, b));
        ASSERT(!wdr_file_contains(path, "zs1"));
        PASS();
    } _test_next:;
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    wdr_teardown(&f);
    return failures;
}

/* ── Randomness, durability, exhaustion, concurrency, recognition ───── */

/* A wallet with no record draws its start from the system CSPRNG: far above
 * any sequential run, different for two restores, recorded at once. */
static int test_random_start(void)
{
    int failures = 0;
    struct wdr f, g;
    memset(&f, 0, sizeof(f));
    memset(&g, 0, sizeof(g));
    TEST("wallet_diversified_receive: a wallet with no record starts at random") {
        wdr_use_system_rng();
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        uint64_t next = 0;
        ASSERT(!wdr_stored_next(&f, &acct, &next));
        char a[128], b[128], a2[128];
        ASSERT(wdr_receive(&f, a, sizeof(a)));
        ASSERT(wdr_stored_next(&f, &acct, &next));
        ASSERT(next > WDR_START_MIN);
        ASSERT(next < WALLET_DIVERSIFIER_INDEX_MAX);

        /* The RPC state follows the most recent restore. */
        ASSERT(wdr_restore(&g));
        ASSERT(wdr_receive(&g, b, sizeof(b)));
        ASSERT(strcmp(a, b) != 0);
        uint64_t next_g = 0;
        ASSERT(wdr_stored_next(&g, &acct, &next_g));
        ASSERT(next_g > WDR_START_MIN);
        ASSERT(next_g != next);
        ASSERT(wdr_receive(&g, a2, sizeof(a2)));
        ASSERT(strcmp(b, a2) != 0);
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_teardown(&f);
    wdr_teardown(&g);
    return failures;
}

/* When the CSPRNG fails no address is issued and nothing is recorded. */
static int test_random_failure_refuses(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: no address when randomness fails") {
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        uint64_t start = wdr_use_start(0x99ULL);
        g_wdr_rng_fails = true;
        char a[128] = "", want[128];
        ASSERT(!wdr_receive(&f, a, sizeof(a)));
        ASSERT_STR_EQ(a, "");
        uint64_t next = 0;
        ASSERT(!wdr_stored_next(&f, &acct, &next));
        uint8_t ld[11], lpk[32];
        ASSERT(!wallet_sqlite_diversifier_latest(&f.ws, &acct, ld, lpk));
        g_wdr_rng_fails = false;
        ASSERT(wdr_receive(&f, a, sizeof(a)));
        ASSERT(wdr_expected_from(&acct, start, 0, want, sizeof(want)));
        ASSERT_STR_EQ(a, want);
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    return failures;
}

static int wdr_sync_level(struct wdr *f)
{
    sqlite3_stmt *s = NULL;
    int level = -1;
    if (sqlite3_prepare_v2(f->ndb.db, "PRAGMA synchronous", -1, &s, NULL) ==
            SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
        level = sqlite3_column_int(s, 0);
    if (s)
        sqlite3_finalize(s);
    return level;
}

/* The index reaches the disk before the address leaves: the receive itself
 * syncs the write-ahead log, the connection's mode is put back afterwards,
 * and when the sync fails no address is returned. In bulk-sync mode, which
 * does not sync, no address is issued at all. */
static int test_index_synced_before_return(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    bool vfs_on = false;
    TEST("wallet_diversified_receive: the index is synced before the address") {
        ASSERT(spv_install());
        vfs_on = true;
        ASSERT(wdr_restore(&f));
        wdr_use_start(0x5151ULL);
        char warm[128], a[128], c[128], d[128];
        int normal = wdr_sync_level(&f);
        ASSERT_EQ(normal, 1);

        /* The first write after a log reset syncs the log header whatever the
         * mode, so one receive goes first and only the next is counted. */
        ASSERT(sqlite3_exec(f.ndb.db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL,
                            NULL, NULL) == SQLITE_OK);
        ASSERT(wdr_receive(&f, warm, sizeof(warm)));
        spv_reset();
        ASSERT(wdr_receive(&f, a, sizeof(a)));
        ASSERT(spv_count(SPV_SYNC_WAL) > 0);
        ASSERT_EQ(wdr_sync_level(&f), normal);

        /* While the node is catching up the connection does not sync, so no
         * index may be issued: the refusal says why and consumes nothing. */
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        uint64_t before = 0, after = 0;
        ASSERT(wdr_stored_next(&f, &acct, &before));
        ASSERT(node_db_ibd_turbo_mode(&f.ndb));
        int bulk = wdr_sync_level(&f);
        ASSERT_EQ(bulk, 0);
        char why[256];
        ASSERT(!wdr_receive_text(&f, why, sizeof(why)));
        ASSERT(strstr(why, "catching up") != NULL);
        ASSERT(wdr_stored_next(&f, &acct, &after));
        ASSERT_EQ(after, before);
        ASSERT_EQ(wdr_sync_level(&f), bulk);
        memory_cleanse(&acct, sizeof(acct));
        ASSERT(node_db_normal_mode(&f.ndb));
        ASSERT_EQ(wdr_sync_level(&f), normal);

        spv_fail_wal_sync(true);
        c[0] = '\0';
        bool failed = !wdr_receive(&f, c, sizeof(c));
        spv_fail_wal_sync(false);
        ASSERT(failed);
        ASSERT_STR_EQ(c, "");
        ASSERT_EQ(wdr_sync_level(&f), normal);

        ASSERT(wdr_receive(&f, d, sizeof(d)));
        ASSERT(strcmp(d, a) != 0);
        PASS();
    } _test_next:;
    spv_fail_wal_sync(false);
    wdr_use_system_rng();
    wdr_teardown(&f);
    if (vfs_on)
        spv_uninstall();
    return failures;
}

/* Entering bulk mode syncs the database before the log is first truncated,
 * so a receive-index row that was only in the log is on disk when the
 * connection stops syncing. */
static int test_bulk_entry_syncs_first(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    bool vfs_on = false;
    TEST("wallet_diversified_receive: bulk entry syncs the database first") {
        ASSERT(spv_install());
        vfs_on = true;
        ASSERT(wdr_restore(&f));
        wdr_use_start(0x7272ULL);
        char a[128];
        ASSERT(wdr_receive(&f, a, sizeof(a)));
        spv_reset();
        ASSERT(node_db_ibd_turbo_mode(&f.ndb));
        ASSERT_EQ(wdr_sync_level(&f), 0);
        ASSERT(spv_count(SPV_SYNC_DB) > 0);
        ASSERT(spv_count(SPV_TRUNC_WAL) > 0);
        ASSERT(spv_first(SPV_SYNC_DB) < spv_first(SPV_TRUNC_WAL));
        ASSERT(node_db_normal_mode(&f.ndb));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    if (vfs_on)
        spv_uninstall();
    return failures;
}

#define WDR_THREADS 2
#define WDR_PER_THREAD 20

struct wdr_worker {
    struct wdr *f;
    const struct sapling_key_entry *acct;
    uint8_t d[WDR_PER_THREAD][11];
    int done;
};

static void *wdr_worker_run(void *arg)
{
    struct wdr_worker *w = arg;
    for (int i = 0; i < WDR_PER_THREAD; i++) {
        uint8_t pk_d[32];
        if (!wallet_sqlite_diversifier_reserve(&w->f->ws, w->acct, w->d[i],
                                               pk_d))
            return NULL;
        w->done++;
    }
    return NULL;
}

/* Two callers at once never share an address. */
static int test_concurrent_receives(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: concurrent receives differ") {
        ASSERT(wdr_restore(&f));
        wdr_use_start(0x777ULL);
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        struct wdr_worker w[WDR_THREADS];
        pthread_t th[WDR_THREADS];
        memset(w, 0, sizeof(w));
        for (int t = 0; t < WDR_THREADS; t++) {
            w[t].f = &f;
            w[t].acct = &acct;
            ASSERT_EQ(pthread_create(&th[t], NULL, wdr_worker_run, &w[t]), 0);
        }
        for (int t = 0; t < WDR_THREADS; t++)
            pthread_join(th[t], NULL);
        for (int t = 0; t < WDR_THREADS; t++)
            ASSERT_EQ(w[t].done, WDR_PER_THREAD);
        for (int a = 0; a < WDR_THREADS * WDR_PER_THREAD; a++)
            for (int b = a + 1; b < WDR_THREADS * WDR_PER_THREAD; b++)
                ASSERT(memcmp(w[a / WDR_PER_THREAD].d[a % WDR_PER_THREAD],
                              w[b / WDR_PER_THREAD].d[b % WDR_PER_THREAD],
                              11) != 0);
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    return failures;
}

/* Past the last issuable index the leaf refuses; it never wraps or repeats. */
static int test_index_exhaustion(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: the index space ends in a refusal") {
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        sqlite3_stmt *s = NULL;
        ASSERT(sqlite3_prepare_v2(f.ndb.db,
            "INSERT OR REPLACE INTO wallet_sapling_diversifier"
            "(ivk,next_index) VALUES(?,?)", -1, &s, NULL) == SQLITE_OK);
        sqlite3_bind_blob(s, 1, acct.ivk, 32, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2,
                           (sqlite3_int64)(WALLET_DIVERSIFIER_INDEX_MAX - 40));
        ASSERT(sqlite3_step(s) == SQLITE_DONE);
        sqlite3_finalize(s);

        char seen[64][128];
        int issued = 0;
        bool refused = false;
        for (int i = 0; i < 64; i++) {
            char a[128];
            if (wdr_receive(&f, a, sizeof(a))) {
                ASSERT(!refused);
                for (int j = 0; j < issued; j++)
                    ASSERT(strcmp(seen[j], a) != 0);
                snprintf(seen[issued++], sizeof(seen[0]), "%s", a);
            } else {
                refused = true;
            }
        }
        ASSERT(issued >= 1);
        ASSERT(refused);
        uint64_t next = 0;
        ASSERT(wdr_stored_next(&f, &acct, &next));
        ASSERT(next < WALLET_DIVERSIFIER_INDEX_MAX);
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_teardown(&f);
    return failures;
}

/* z_getbalance of `address` as text; minconf < 0 leaves the argument out, so
 * the handler's default applies. */
static bool wdr_balance(struct wdr *f, const char *address, int minconf,
                        char *out, size_t size)
{
    struct json_value params, arg, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&arg);
    json_set_str(&arg, address);
    bool ok = json_push_back(&params, &arg);
    json_free(&arg);
    if (ok && minconf >= 0) {
        json_init(&arg);
        json_set_int(&arg, minconf);
        ok = json_push_back(&params, &arg);
        json_free(&arg);
    }
    json_init(&result);
    ok = ok && rpc_table_execute(f->tbl, "z_getbalance", &params, &result);
    snprintf(out, size, "%s",
             json_get_str(&result) ? json_get_str(&result) : "");
    json_free(&params);
    json_free(&result);
    return ok;
}

/* The balance of an issued address is what was paid to that address and is
 * still unspent: the funded one reports its notes, an issued but unpaid one,
 * the default and an address that only borrows a wallet diversifier report
 * nothing, at the default minconf and at zero. */
static int test_issued_address_balance(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: balance is held at the issued address") {
        ASSERT(wdr_restore(&f));
        struct sapling_key_entry acct;
        ASSERT(wdr_account(&f, &acct));
        wdr_use_start(0xabcdefULL);
        char x[128], y[128], def[128], stolen[128];
        ASSERT(wdr_receive(&f, x, sizeof(x)));
        ASSERT(wdr_receive(&f, y, sizeof(y)));
        ASSERT(wdr_default(&acct, def, sizeof(def)));

        /* The foreign key under the diversifier of a funded address: the wallet
         * does not own it, so it holds nothing. */
        uint8_t xd[11], xpk[32], fd[11], fpk[32];
        ASSERT(sapling_decode_payment_address(x, xd, xpk));
        ASSERT(wdr_foreign(fd, fpk));
        ASSERT(wdr_encode(xd, fpk, stolen, sizeof(stolen)));

        /* Notes sit at height 100; the tip is later, so minconf 1 counts them. */
        f.w->best_block_height = 200;
        ASSERT_EQ(wdr_deliver(&f, x, 3 * WDR_UNIT, 1), 1);
        ASSERT_EQ(wdr_deliver(&f, x, 2 * WDR_UNIT, 2), 1);
        const struct sapling_received_note *spent =
            &f.w->sapling_notes[f.w->num_sapling_notes - 1];
        ASSERT_EQ(spent->value, 2 * WDR_UNIT);
        uint8_t by[32];
        memset(by, 0x77, sizeof(by));
        ASSERT_EQ(db_sapling_note_mark_spent(&f.ndb, spent->nf, by),
                  DB_MARK_SPENT_OK);

        const char *const addr[4] = { x, y, def, stolen };
        const char *const want[4] = { "3.00000000", "0.00000000",
                                      "0.00000000", "0.00000000" };
        for (int mc = -1; mc <= 0; mc++) {
            for (int which = 0; which < 4; which++) {
                char got[32];
                ASSERT(wdr_balance(&f, addr[which], mc, got, sizeof(got)));
                ASSERT_STR_EQ(got, want[which]);
            }
        }
        memory_cleanse(&acct, sizeof(acct));
        PASS();
    } _test_next:;
    wdr_use_system_rng();
    wdr_teardown(&f);
    return failures;
}

static char g_wdr_send_params[1024];

static char *wdr_stub_send(const char *method, const char *params_json)
{
    if (method && strcmp(method, "getwalletinfo") == 0)
        return strdup("{\"paytxfee\":\"0.00010000\"}");
    if (method && strcmp(method, "z_sendmany") == 0) {
        snprintf(g_wdr_send_params, sizeof(g_wdr_send_params), "%s",
                 params_json ? params_json : "");
        return strdup("\"00112233445566778899aabbccddeeff"
                      "00112233445566778899aabbccddeeff\"");
    }
    return strdup("null");
}

/* The native send leaf passes the whole-account from form through to the
 * node's send unchanged. */
static int test_native_send_from_account(void)
{
    int failures = 0;
    TEST("wallet_diversified_receive: native send accepts from=account") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            reg, "core.wallet.shielded.send", NULL);
        ASSERT(spec != NULL);
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "wallet_scope", "dev"));
        ASSERT(json_push_kv_str(&in, "from", "account"));
        ASSERT(json_push_kv_str(&in, "to", "zs1payee"));
        ASSERT(json_push_kv_str(&in, "amount", "1.00000000"));
        ASSERT(json_push_kv_bool(&in, "confirm", true));
        struct zcl_command_request req = {
            .spec = spec, .input = &in, .view = "normal",
        };
        struct zcl_command_reply reply;
        node_rpc_client_set_test_hook(wdr_stub_send);
        g_wdr_send_params[0] = '\0';
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_wallet_shielded_send(&req, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "from")), "account");
        ASSERT(strncmp(g_wdr_send_params, "[\"account\",", 11) == 0);
        zcl_command_reply_free(&reply);
        node_rpc_client_set_test_hook(NULL);
        json_free(&in);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* The measured cost of a synced receive, printed with the run's evidence. */
static int test_receive_cost(void)
{
    int failures = 0;
    struct wdr f;
    memset(&f, 0, sizeof(f));
    TEST("wallet_diversified_receive: cost of a synced receive") {
        ASSERT(wdr_restore(&f));
        enum { N = 40 };
        char a[128];
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < N; i++)
            ASSERT(wdr_receive(&f, a, sizeof(a)));
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
        printf("(%d receives, %.2f ms each) ", N, ms / N);
        PASS();
    } _test_next:;
    wdr_teardown(&f);
    return failures;
}


int test_wallet_diversified_receive(void)
{
    int failures = 0;
    failures += test_receive_find_and_restore();
    failures += test_crash_after_index_write();
    failures += test_receive_while_locked();
    failures += test_agent_session_refused();
    failures += test_native_reply_shape();
    failures += test_no_address_in_logs();
    failures += test_random_start();
    failures += test_random_failure_refuses();
    failures += test_index_synced_before_return();
    failures += test_bulk_entry_syncs_first();
    failures += test_concurrent_receives();
    failures += test_index_exhaustion();
    failures += test_issued_address_balance();
    failures += test_native_send_from_account();
    failures += test_receive_cost();
    return failures;
}

/* ── Whole-account spend with the production prover ──────────────────
 *
 * Group simnet_wallet_diversified_send. A payer outside the wallet shields
 * three coinbases to three fresh diversified addresses with the production
 * Groth16 prover; the wallet finds the notes, maintains their witnesses with
 * the production block path, and builds one `account` send that spends all
 * three. The real consensus verifier accepts it and the simulated chain
 * confirms it. Skips when the Sapling parameters are absent. */

#define WDS_FEE ((int64_t)10000)
#define WDS_SAPLING_H 100
/* Height label the wallet signs and tracks witnesses at: above the global
 * chain parameters' Sapling activation, so its sighash branch id matches
 * the simulated chain's Sapling epoch. */
#define WDS_WALLET_H 500000

/* The production witness maintainer (engine/controllers/src/
 * sync_controller_blocks.c). */
bool advance_wallet_witnesses(struct node_db *ndb, const struct block *blk,
                              struct incremental_merkle_tree *tree,
                              int height, struct wallet *wallet);

static bool wds_params(void)
{
    const char *home = getenv("HOME");
    char dir[512], probe[640];
    snprintf(dir, sizeof(dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    snprintf(probe, sizeof(probe), "%s/sapling-output.params", dir);
    FILE *fp = fopen(probe, "rb");
    if (!fp) {
        printf("  UNOBSERVED (~/.zcash-params absent; production prover leg "
               "did not run)\n");
        return false;
    }
    fclose(fp);
    if (!sapling_init_params(dir) || !zclassic_sapling_prover_is_ready()) {
        printf("  UNOBSERVED (production prover not ready; status=%s)\n",
               zclassic_sapling_prover_status());
        return false;
    }
    return true;
}

/* The minimal self-derived progress projection a running node has; the
 * production spend path is sovereignty-gated on it. */
static bool wds_trust(const char *dir, int tip_height)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db) ||
        !reducer_frontier_ensure_schema(db) ||
        !nullifier_kv_initialize_history(db, 0))
        return false;
    reducer_frontier_provable_tip_set(tip_height);
    struct uint256 txid;
    uint256_set_null(&txid);
    txid.data[0] = 0x51;
    txid.data[31] = 0x77;
    const unsigned char script[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    if (!coins_kv_add(db, txid.data, 0, 1234, tip_height, true, script,
                      sizeof(script)))
        return false;
    uint8_t migrated = 1;
    uint8_t tip_hash[32];
    memset(tip_hash, 0x50, sizeof(tip_hash));
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                  SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(db, tip_height + 1) &&
              progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                      &migrated, sizeof(migrated));
    sqlite3_stmt *st = NULL;
    ok = ok && sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,validated_at) VALUES(?1,?2,1,0)",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int(st, 1, tip_height);
        sqlite3_bind_blob(st, 2, tip_hash, sizeof(tip_hash), SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    if (st)
        sqlite3_finalize(st);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    else
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return ok && coins_kv_mark_self_folded(db);
}

static bool wds_sighash(struct transaction *tx,
                        const struct consensus_params *cp, int height,
                        struct uint256 *out)
{
    uint32_t branch = consensus_current_epoch_branch_id(height, cp);
    struct sighash_type ht;
    ht.raw = 1; /* SIGHASH_ALL */
    struct script empty;
    empty.size = 0;
    uint256_set_null(out);
    return signature_hash(&empty, tx, NOT_AN_INPUT, ht, 0, branch, NULL, out);
}

static bool wds_verify(const struct transaction *tx,
                       const struct consensus_params *cp, int height)
{
    struct validation_state st;
    validation_state_init(&st);
    return contextual_check_transaction(tx, &st, cp, height, 100);
}

/* The payer: shield one coinbase to `address` with the production prover.
 * `copy_out` receives an independent copy for the wallet's scan; the chain
 * mints the original. */
static bool wds_pay(struct simnet *s,
                    const struct uint256 *coinbase, const char *address,
                    int64_t value, struct transaction *copy_out)
{
    transaction_init(copy_out);
    uint8_t d[11], pk_d[32];
    if (!sapling_decode_payment_address(address, d, pk_d))
        return false;
    void *pctx = zclassic_sapling_proving_ctx_init();
    if (!pctx)
        return false;
    const struct consensus_params *cp = &s->params.consensus;
    int height = simnet_tip_height(s) + 1;
    struct transaction tz;
    transaction_init(&tz);
    tz.overwintered = true;
    tz.version = SAPLING_TX_VERSION;
    tz.version_group_id = SAPLING_VERSION_GROUP_ID;
    if (!transaction_alloc(&tz, 1, 0))
        return false;
    tz.vin[0].prevout.hash = *coinbase;
    tz.vin[0].prevout.n = 0;
    tz.vin[0].sequence = 0xFFFFFFFF;
    uint8_t ss[2] = {0x00, 0x00};
    script_set(&tz.vin[0].script_sig, ss, sizeof(ss));
    tz.value_balance = -value;
    tz.v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                      "wds_out");
    if (!tz.v_shielded_output)
        return false;
    tz.num_shielded_output = 1;
    uint8_t ovk[32];
    memset(ovk, 0x6b, sizeof(ovk));
    struct output_description *od = &tz.v_shielded_output[0];
    struct uint256 sighash;
    bool ok = sapling_build_output_with_ctx(
                  pctx, ovk, d, pk_d, (uint64_t)value, NULL, od->cv.data,
                  od->cm.data, od->ephemeral_key.data, od->enc_ciphertext,
                  od->out_ciphertext, od->zkproof) &&
              wds_sighash(&tz, cp, height, &sighash) &&
              zclassic_sapling_binding_sig(pctx, tz.value_balance,
                                           sighash.data, tz.binding_sig);
    transaction_compute_hash(&tz);
    ok = ok && wds_verify(&tz, cp, height);
    ok = ok && transaction_copy(copy_out, &tz);
    transaction_compute_hash(copy_out);
    ok = ok && simnet_mint_txs(s, &tz, 1);
    zclassic_sapling_proving_ctx_free(pctx);
    free(tz.v_shielded_output);
    return ok;
}

/* Recover the diversifier and value an output description carries for
 * `ivk`, as the recipient does. */
static bool wds_decrypt(const struct output_description *od,
                        const uint8_t ivk[32], uint8_t d_out[11],
                        uint64_t *value_out)
{
    uint8_t dh[32], key[32], pt[ZC_SAPLING_ENCPLAINTEXT_SIZE];
    bool ok = sapling_ka_agree(od->ephemeral_key.data, ivk, dh) &&
              sapling_kdf(key, dh, od->ephemeral_key.data) &&
              sapling_note_decrypt(key, od->enc_ciphertext,
                                   ZC_SAPLING_ENCCIPHERTEXT_SIZE, pt);
    if (ok) {
        memcpy(d_out, pt + 1, 11);
        uint64_t v = 0;
        for (int i = 0; i < 8; i++)
            v |= (uint64_t)pt[12 + i] << (8 * i);
        *value_out = v;
    }
    memory_cleanse(dh, sizeof(dh));
    memory_cleanse(key, sizeof(key));
    memory_cleanse(pt, sizeof(pt));
    return ok;
}

/* True when `tx` has a spend whose nullifier is `nf`. */
static bool wds_spends(const struct transaction *tx, const uint8_t nf[32])
{
    for (size_t i = 0; i < tx->num_shielded_spend; i++)
        if (memcmp(tx->v_shielded_spend[i].nullifier.data, nf, 32) == 0)
            return true;
    return false;
}

/* The nullifier the account key gives a stored note at tree position
 * `position`, computed with the note's own diversifier and pk_d. */
static bool wds_nf(const struct sapling_key_entry *key, const char *address,
                   const uint8_t rcm[32], uint64_t value, uint64_t position,
                   uint8_t nf[32])
{
    uint8_t d[11], pk_d[32];
    return sapling_decode_payment_address(address, d, pk_d) &&
           sapling_compute_nf(d, pk_d, value, rcm, key->xfvk.fvk.ak,
                              key->xfvk.fvk.nk, position, nf);
}

/* Build, without committing, a send of `amount` to `payee` from `from`
 * ("account" or an address). The refusal, if any, is copied to `why`. */
static bool wds_prepare_why(const char *from, const char *payee,
                            const char *amount, struct wallet_tx *out,
                            char *why, size_t why_size)
{
    struct json_value params, recips, rcp, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&rcp);
    json_set_str(&rcp, from);
    bool ok = json_push_back(&params, &rcp);
    json_free(&rcp);
    json_init(&recips);
    json_set_array(&recips);
    json_init(&rcp);
    json_set_object(&rcp);
    ok = ok && json_push_kv_str(&rcp, "address", payee) &&
         json_push_kv_str(&rcp, "amount", amount) &&
         json_push_back(&recips, &rcp) && json_push_back(&params, &recips);
    json_free(&rcp);
    json_free(&recips);
    json_init(&result);
    ok = ok && z_sendmany_prepare(&params, out, &result);
    if (why && why_size)
        snprintf(why, why_size, "%s",
                 !ok && json_get_str(&result) ? json_get_str(&result) : "");
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool wds_prepare(const char *from, const char *payee,
                        const char *amount, struct wallet_tx *out)
{
    char why[160];
    bool ok = wds_prepare_why(from, payee, amount, out, why, sizeof(why));
    if (!ok)
        printf("(z_sendmany_prepare: %s) ", why);
    return ok;
}

/* What the wallet recorded for one note before the process restarted. */
struct wds_note {
    uint8_t rcm[32];
    uint64_t value;
};

/* Every check after the three notes are in the wallet: build the `account`
 * send, then verify and confirm it. */
static int wds_spend_all(struct wdr *f, struct simnet *s,
                         const char addrs[WDR_PAYERS][128],
                         const struct wds_note snap[WDR_PAYERS])
{
    int failures = 0;
    TEST("simnet_wallet_diversified_send: one account send spends all three") {
        const struct consensus_params *cp = &s->params.consensus;
        struct sapling_key_entry acct;
        ASSERT(wdr_account(f, &acct));
        const struct sapling_key_entry *key =
            sapling_keystore_find_by_ivk(&f->w->sapling_keys, acct.ivk);
        ASSERT(key != NULL);

        /* A payee from an unrelated seed. */
        uint8_t seed[32];
        memset(seed, 0x11, sizeof(seed));
        struct zip32_xsk pxsk;
        struct zip32_xfvk pxfvk;
        zip32_xsk_master(&pxsk, seed, sizeof(seed));
        zip32_xsk_to_xfvk(&pxfvk, &pxsk);
        uint8_t pd[11], ppk[32], pivk[32];
        ASSERT(zip32_xfvk_address(&pxfvk, pd, ppk));
        sapling_crh_ivk(pxfvk.fvk.ak, pxfvk.fvk.nk, pivk);
        char payee[128];
        ASSERT(wdr_encode(pd, ppk, payee, sizeof(payee)));

        /* An address of an unrelated seed is foreign: a send from it is
         * refused, however its key relates to the wallet's. */
        {
            struct wallet_tx foreign;
            char why[160];
            ASSERT(!wds_prepare_why(payee, addrs[0], "0.10000000", &foreign,
                                    why, sizeof(why)));
            ASSERT(strstr(why, "not in wallet") != NULL);
        }

        /* A send from one issued address builds, spends the account's notes
         * and the verifier accepts it: the address is owned, not foreign. */
        {
            struct wallet_tx single;
            ASSERT(wds_prepare(addrs[0], payee, "0.50000000", &single));
            ASSERT(single.tx.num_shielded_spend >= 1);
            ASSERT(wds_verify(&single.tx, cp,
                              simnet_tip_height(s) + 1));

            /* From the default address the same notes are spent. */
            char defaddr[128];
            struct wallet_tx from_default;
            ASSERT(wdr_default(&acct, defaddr, sizeof(defaddr)));
            ASSERT(wds_prepare(defaddr, payee, "0.50000000", &from_default));
            ASSERT(from_default.tx.num_shielded_spend >= 1);
            ASSERT(wds_verify(&from_default.tx, cp,
                              simnet_tip_height(s) + 1));
        }

        /* 5.5 ZCL exceeds any two of the notes (1+2+3 ZCL less fees). */
        const int64_t amount = 550000000;
        struct wallet_tx prepared;
        ASSERT(wds_prepare("account", payee, "5.50000000", &prepared));
        struct transaction *tx = &prepared.tx;

        ASSERT_EQ((int)tx->num_shielded_spend, WDR_PAYERS);
        ASSERT_EQ((int)tx->num_shielded_output, 2);
        int64_t total = 0;
        for (unsigned i = 0; i < WDR_PAYERS; i++)
            total += (int64_t)snap[i].value;
        ASSERT_EQ(tx->value_balance, f->w->default_fee);

        /* Each spend's nullifier is the one the note's own diversifier gives. */
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            uint8_t nf[32];
            ASSERT(wds_nf(key, addrs[k], snap[k].rcm, snap[k].value, k, nf));
            ASSERT(wds_spends(tx, nf));
        }
        for (size_t a = 0; a < tx->num_shielded_spend; a++)
            for (size_t b = a + 1; b < tx->num_shielded_spend; b++)
                ASSERT(memcmp(tx->v_shielded_spend[a].nullifier.data,
                              tx->v_shielded_spend[b].nullifier.data,
                              32) != 0);

        /* The payee gets the amount; change goes to the account default. */
        bool paid = false, changed = false;
        for (size_t o = 0; o < tx->num_shielded_output; o++) {
            uint8_t d[11];
            uint64_t v = 0;
            if (wds_decrypt(&tx->v_shielded_output[o], pivk, d, &v)) {
                paid = v == (uint64_t)amount && memcmp(d, pd, 11) == 0;
            } else if (wds_decrypt(&tx->v_shielded_output[o], acct.ivk, d,
                                   &v)) {
                changed = memcmp(d, acct.diversifier, 11) == 0 &&
                          v == (uint64_t)(total - amount -
                                          f->w->default_fee);
            }
        }
        ASSERT(paid);
        ASSERT(changed);

        /* The anchor is the chain's tree root, the verifier accepts the
         * proofs and signatures, and the chain confirms the transaction. */
        struct uint256 root;
        ASSERT(simnet_sapling_tree_root(s, &root));
        for (size_t i = 0; i < tx->num_shielded_spend; i++)
            ASSERT(memcmp(tx->v_shielded_spend[i].anchor.data, root.data,
                          32) == 0);
        int height = simnet_tip_height(s) + 1;
        ASSERT(wds_verify(tx, cp, height));
        struct transaction mint;
        transaction_init(&mint);
        ASSERT(transaction_copy(&mint, tx));
        transaction_compute_hash(&mint);
        ASSERT(simnet_mint_txs(s, &mint, 1));
        ASSERT_EQ(simnet_tip_height(s), height);
        ASSERT_EQ((int)simnet_sapling_tree_size(s), WDR_PAYERS + 2);
        free(mint.v_shielded_spend);
        free(mint.v_shielded_output);
        transaction_free(tx);
        memory_cleanse(&acct, sizeof(acct));
        memory_cleanse(&pxsk, sizeof(pxsk));
        PASS();
    } _test_next:;
    return failures;
}

int test_simnet_wallet_diversified_send(void)
{
    printf("\n=== wallet diversified receive: whole-account send "
           "(production prover) ===\n");
    if (!wds_params())
        return 0;
    int saved_defer = atomic_load(&g_deferred_proof_validation_below_height);
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    int failures = 0;
    struct wdr f;
    struct simnet s;
    struct incremental_merkle_tree tree;
    struct main_state ms;
    bool sim_open = false, ms_open = false, trusted = false;
    memset(&f, 0, sizeof(f));
    memset(&s, 0, sizeof(s));
    TEST("simnet_wallet_diversified_send: three payers, three notes found") {
        ASSERT(wdr_restore(&f));
        char addrs[WDR_PAYERS][128];
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(wdr_receive(&f, addrs[k], sizeof(addrs[k])));

        ASSERT(simnet_init(&s));
        sim_open = true;
        simnet_activate_sapling_at(&s, WDS_SAPLING_H);
        ASSERT(simnet_enable_sapling_tree(&s));
        simnet_enable_contextual_check(&s, false);
        struct script fund;
        script_init(&fund);
        uint8_t pk[3] = {0x76, 0xa9, 0x14};
        script_set(&fund, pk, sizeof(pk));
        struct uint256 coinbase[WDR_PAYERS];
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            ASSERT(simnet_mint_coinbase_to(
                &s, &fund, (int64_t)(k + 1) * 100000000, &coinbase[k]));
        ASSERT(simnet_mint_to_height(
            &s, WDS_SAPLING_H + WDR_PAYERS - 1 + COINBASE_MATURITY));

        sapling_tree_init(&tree);
        int height = 0;
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            struct transaction seen;
            ASSERT(wds_pay(&s, &coinbase[k], addrs[k],
                           (int64_t)(k + 1) * 100000000 - WDS_FEE, &seen));
            height = WDS_WALLET_H + (int)k;
            ASSERT_EQ(wdr_scan(&f, &seen, &seen.hash, height), 1);
            struct block blk;
            memset(&blk, 0, sizeof(blk));
            blk.vtx = &seen;
            blk.num_vtx = 1;
            ASSERT(node_db_begin_immediate(&f.ndb));
            ASSERT(advance_wallet_witnesses(&f.ndb, &blk, &tree, height,
                                            f.w));
            ASSERT(node_db_commit(&f.ndb));
            transaction_free(&seen);
        }
        ASSERT_EQ((int)simnet_sapling_tree_size(&s), WDR_PAYERS);
        uint64_t sum = 0;
        for (unsigned k = 0; k < WDR_PAYERS; k++)
            sum += (k + 1) * (uint64_t)100000000 - (uint64_t)WDS_FEE;
        ASSERT(wdr_total(&f) == sum);
        struct wds_note snap[WDR_PAYERS];
        ASSERT_EQ((int)f.w->num_sapling_notes, WDR_PAYERS);
        for (unsigned k = 0; k < WDR_PAYERS; k++) {
            memcpy(snap[k].rcm, f.w->sapling_notes[k].rcm, 32);
            snap[k].value = f.w->sapling_notes[k].value;
        }

        /* A restart: the spend reads the notes from the database, not from
         * the process that found them. */
        wdr_close(&f);
        ASSERT(wdr_boot(&f));
        ASSERT_EQ((int)f.w->num_sapling_notes, 0);

        ASSERT(wds_trust(f.dir, height));
        trusted = true;
        main_state_init(&ms);
        ms_open = true;
        f.w->best_block_height = height;
        rpc_wallet_set_state(f.w, &ms, f.dir, &f.ws, NULL, NULL);
        wallet_rpc_context_set_node_db(&f.ndb);
        PASS();
        failures += wds_spend_all(&f, &s, (const char (*)[128])addrs, snap);
    } _test_next:;
    if (ms_open)
        main_state_free(&ms);
    if (trusted) {
        progress_store_close();
        reducer_frontier_provable_tip_reset();
    }
    if (sim_open)
        simnet_free(&s);
    wdr_teardown(&f);
    atomic_store(&g_deferred_proof_validation_below_height, saved_defer);
    return failures;
}
