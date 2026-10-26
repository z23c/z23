/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #5, the BUYING half: a program buys from a store.
 *
 * The selling half is proven by test_store_e2e_gate.c. This group proves the
 * other side — services/store_buyer.h — and, more importantly, proves the
 * three things a buyer must never get wrong:
 *
 *   1. A payment that names a DIFFERENT order does not unlock this one.
 *      The merchant's matcher is memo-bound and this asserts the buyer
 *      inherits that, rather than quietly accepting "money arrived at the
 *      right address" as proof of purchase.
 *   2. Bytes that do not hash to the product's content hash are refused
 *      and NOTHING is written — not the target, not a partial, not a
 *      leftover temporary.
 *   3. A memo padded the old way (0xF6, the "no memo" sentinel) is NOT
 *      credited. That is the regression this group exists to hold: the
 *      plain-text memo path used to pad with 0xF6, which made a buyer who
 *      followed the payment page literally uncreditable, and it is
 *      invisible in every test that constructs its own memo bytes.
 *
 * Plus the refusals a caller must be able to tell apart: mainnet on the
 * spend, no Sapling proving backend, and payment not yet confirmed.
 *
 * Deterministic and in-process: one temporary datadir, a seeded merchant
 * wallet, hand-written confirmed notes. No network, no clock dependence
 * beyond the store's own proof-of-work challenge timestamp. */

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See platform/modules/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/runtime.h"
#include "controllers/store_controller.h"
#include "controllers/store_buyer_controller.h"
#include "json/json.h"
#include "rpc/server.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/zslp_controller.h"
#include "crypto/sha3.h"
#include "models/block.h"
#include "models/store.h"
#include "models/store_blob.h"
#include "models/store_purchase.h"
#include "models/wallet_tx.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "controllers/sync_controller.h"
#include "sapling/constants.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "services/store_buyer.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

/* The mainnet-format transparent address the seeded demo catalog and the
 * existing store gate both use. The test chain is CHAIN_MAIN (selected by
 * the runner before every group), so this is the address form the store's
 * validator accepts. */
#define TSB_CUSTOMER "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"

/* The payload a buyer must receive byte for byte. Embeds a NUL and
 * non-ASCII bytes so a pass proves the whole path is binary-safe. */
static const uint8_t TSB_BLOB[] = {
    'Z','C','L','2','3',' ','B','U','Y','E','R',' ',
    'P','A','Y','L','O','A','D', 0x00, 0xC0, 0xFF, 0xEE, 0x01
};

/* A different payload, used to make the store serve something the purchase
 * did not agree to buy. */
static const uint8_t TSB_SWAPPED[] = {
    'S','W','A','P','P','E','D', 0x00, 0xBA, 0xAD
};

static struct wallet *tsb_merchant;
static struct app_runtime_context tsb_runtime;

/* Wire a seeded merchant wallet as the current runtime so the order-create
 * path can mint a REAL, recoverable Sapling payment address (the placeholder
 * fallback was removed on purpose — an order can no longer bind to a
 * synthetic address). Heap-allocated: struct wallet is far too large for the
 * stack. */
static bool tsb_wire_merchant(void)
{
    tsb_merchant = zcl_calloc(1, sizeof(struct wallet), "tsb_merchant_wallet");
    if (!tsb_merchant)
        return false;
    wallet_init(tsb_merchant);
    uint8_t seed[32];
    memset(seed, 0x5B, sizeof(seed));
    if (!sapling_keystore_set_seed(&tsb_merchant->sapling_keys, seed)) {
        wallet_free(tsb_merchant);
        free(tsb_merchant);
        tsb_merchant = NULL;
        return false;
    }
    memset(&tsb_runtime, 0, sizeof(tsb_runtime));
    tsb_runtime.wallet = tsb_merchant;
    app_runtime_set_current(&tsb_runtime);
    return true;
}

static void tsb_unwire_merchant(void)
{
    app_runtime_set_current(NULL);
    if (tsb_merchant) {
        wallet_free(tsb_merchant);
        free(tsb_merchant);
        tsb_merchant = NULL;
    }
}

static bool tsb_open(const char *datadir, struct node_db *ndb)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/node.db", datadir);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path);
}

/* A tip block so the payment scan has a confirmation depth to measure. */
static bool tsb_seed_tip(struct node_db *ndb, int height)
{
    struct db_block blk;
    static uint8_t solution[] = { 0x51, 0x52 };

    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0x11, sizeof(blk.hash));
    memset(blk.prev_hash, 0x22, sizeof(blk.prev_hash));
    memset(blk.merkle_root, 0x33, sizeof(blk.merkle_root));
    memset(blk.chain_work, 0x44, sizeof(blk.chain_work));
    blk.height = height;
    blk.time = 123456789u;
    blk.bits = 0x1d00ffffu;
    blk.status = 3;
    blk.solution = solution;
    blk.solution_len = sizeof(solution);
    return db_block_save(ndb, &blk);
}

/* Persist a confirmed note at `address` carrying `memo_text`, padded with
 * `pad`. `pad` is the whole point of this helper: 0x00 is what a text memo
 * looks like on the wire, and 0xF6 is what it used to look like — the
 * merchant's matcher requires the byte after the order token to be NUL or
 * ';', so the two pads are the difference between paid and not paid. */
static bool tsb_seed_note(struct node_db *ndb, const char *address,
                          const char *memo_text, uint8_t pad,
                          int64_t value, int block_height, uint8_t tag)
{
    struct db_sapling_note note;

    memset(&note, 0, sizeof(note));
    memset(note.txid, tag, sizeof(note.txid));
    memset(note.rcm, 0x62, sizeof(note.rcm));
    memset(note.ivk, 0x63, sizeof(note.ivk));
    memset(note.diversifier, 0x64, sizeof(note.diversifier));
    memset(note.pk_d, 0x65, sizeof(note.pk_d));
    memset(note.cm, tag, sizeof(note.cm));
    memset(note.nullifier, tag, sizeof(note.nullifier));
    note.output_index = 0;
    note.value = value;
    note.block_height = block_height;
    (void)snprintf(note.address, sizeof(note.address), "%s", address);

    memset(note.memo, pad, sizeof(note.memo));
    size_t n = strlen(memo_text);
    if (n > sizeof(note.memo))
        n = sizeof(note.memo);
    memcpy(note.memo, memo_text, n);
    note.memo_len = ZC_MEMO_SIZE;
    return db_sapling_note_save(ndb, &note);
}

/* Store `data` and stamp it onto product `id`, so the token-gated download
 * serves real bytes. */
static bool tsb_attach_blob(struct node_db *ndb, int64_t product_id,
                            const uint8_t *data, size_t len)
{
    uint8_t hash[32];
    if (!db_store_blob_put(ndb, data, len, "engine/application/octet-stream",
                           "payload.bin", hash))
        return false;
    return db_store_product_save_content(ndb, product_id, hash);
}

/* Make a fixture datadir under test-tmp.
 *
 * The absolute spelling matters here: the handlers write through
 * platform_private_path_resolve, which realpath()s the destination's parent
 * and refuses any pathname that does not start at the root ("destination
 * parent is not a safe real directory"). test_make_tmpdir now hands back an
 * absolute path, so this is a straight pass-through; it used to prepend the
 * working directory itself, which after that change produced a doubled
 * prefix and a datadir that did not exist. */
static void tsb_tmpdir(char *dir, size_t dir_size, const char *tag)
{
    test_make_tmpdir(dir, dir_size, "store_buyer", tag);
}

static bool tsb_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Read a whole file into `buf`; returns the byte count, or -1. */
static long tsb_read_file(const char *path, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return (long)n;
}

/* One pure case: prints its verdict, returns the failure count. */
static int tsb_report(const char *what, bool ok)
{
    printf("store_buyer: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* A remote seller's payment address must match the kind ordered. */
static bool tsb_remote_addr_kind(void)
{
    bool ok;
    chain_params_select(CHAIN_MAIN);
    ok = store_buyer_remote_addr_matches("zs1abcdefghijklmnop", false) &&
         !store_buyer_remote_addr_matches("zs1abcdefghijklmnop", true) &&
         store_buyer_remote_addr_matches(TSB_CUSTOMER, true) &&
         !store_buyer_remote_addr_matches(TSB_CUSTOMER, false) &&
         !store_buyer_remote_addr_matches("", false) &&
         !store_buyer_remote_addr_matches("", true) &&
         !store_buyer_remote_addr_matches("garbage", true) &&
         !store_buyer_remote_addr_matches("zregtestsapling1abcdef", false);
    return ok;
}

/* A seller that claims a file must prove it with a hash, and quote a
 * price in money range, before the buyer pays. */
static bool tsb_parse_product_cases(void)
{
    static const struct { const char *json; bool ok; bool has; } c[] = {
        { "{\"id\":7,\"price_zatoshi\":5,\"has_content\":true,\"content_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\"}", true, true },
        { "{\"id\":7,\"price_zatoshi\":5,\"has_content\":false}", true, false },
        { "{\"id\":7,\"price_zatoshi\":5,\"has_content\":true}", false, false },
        { "{\"id\":7,\"price_zatoshi\":5,\"has_content\":true,\"content_hash\":\"00\"}", false, false },
        { "{\"id\":7,\"price_zatoshi\":5,\"has_content\":true,\"content_hash\":\"zz00000000000000000000000000000000000000000000000000000000000001\"}", false, false },
        { "{\"id\":7,\"price_zatoshi\":0,\"has_content\":false}", false, false },
        { "{\"id\":7,\"price_zatoshi\":-5,\"has_content\":false}", false, false },
        { "{\"id\":7,\"price_zatoshi\":2100000000000001,\"has_content\":false}", false, false },
        { "{\"id\":8,\"price_zatoshi\":5,\"has_content\":false}", false, false },
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        char name[64], tok[64];
        int64_t price = 0;
        bool has = false;
        uint8_t hash[32];
        bool got = store_buyer_parse_product_json(c[i].json, 7, name,
            sizeof(name), tok, sizeof(tok), &price, &has, hash);
        if (got != c[i].ok || (got && has != c[i].has)) {
            printf("case %zu: got=%d has=%d\n", i, got, has);
            return false;
        }
    }
    return true;
}

/* A seller-supplied challenge is bounded and parsed strictly before the
 * buyer spends any work on it. */
static bool tsb_pow_params_bounded(void)
{
    static const struct { const char *ts, *bits; bool ok; } cases[] = {
        { "1700000000", "26", true },  { "1700000000", "1", true },
        { "1700000000", "27", false }, { "1700000000", "64", false },
        { "1700000000", "0", false },  { "1700000000", "-1", false },
        { "1700000000", "", false },   { "1700000000", "12x", false },
        { "abc", "12", false },        { "", "12", false },
        { "99999999999999999999", "12", false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int64_t ts = 0;
        int bits = 0;
        bool got = store_buyer_pow_params(cases[i].ts, cases[i].bits, &ts,
                                          &bits);
        if (got != cases[i].ok) {
            printf("FAIL (ts=\"%s\" bits=\"%s\")\n", cases[i].ts,
                   cases[i].bits);
            return false;
        }
        if (got && (ts != 1700000000 || bits != atoi(cases[i].bits))) {
            printf("FAIL (parsed %lld/%d)\n", (long long)ts, bits);
            return false;
        }
    }
    return true;
}

/* Only a true retry of an unpaid order may refresh a row whose remote order
 * id comes back again. */
static bool tsb_remote_reuse_guarded(void)
{
    struct db_store_purchase row;
    uint8_t hash[32], other[32];
    memset(&row, 0, sizeof(row));
    memset(hash, 0x5a, sizeof(hash));
    memset(other, 0xa5, sizeof(other));
    row.id = 3;
    row.product_id = 7;
    row.amount_zatoshi = 50000;
    row.has_content_hash = true;
    memcpy(row.content_hash, hash, sizeof(hash));
    row.stage = STORE_PURCHASE_CREATED;
    if (!store_buyer_remote_reuse_ok(&row, 7, 50000, true, hash))
        return false; /* same unpaid order retried */
    if (store_buyer_remote_reuse_ok(&row, 8, 50000, true, hash) ||
        store_buyer_remote_reuse_ok(&row, 7, 50001, true, hash) ||
        store_buyer_remote_reuse_ok(&row, 7, 50000, true, other) ||
        store_buyer_remote_reuse_ok(&row, 7, 50000, false, NULL))
        return false; /* a different purchase under the same id */
    row.stage = STORE_PURCHASE_PAID;
    return !store_buyer_remote_reuse_ok(&row, 7, 50000, true, hash);
}

/* Re-read a purchase and report whether the merchant has credited it. */
static bool tsb_credited(const char *datadir, int64_t purchase_id,
                         int64_t want_zatoshi)
{
    struct store_buyer_state state;
    store_process_payments(datadir);
    if (!store_buyer_refresh(datadir, purchase_id, &state).ok)
        return false;
    printf("[confirmed=%lld stage=%d] ", (long long)state.confirmed_zatoshi,
           (int)state.purchase.stage);
    return state.confirmed_zatoshi >= want_zatoshi &&
           state.purchase.stage == STORE_PURCHASE_PAID &&
           state.ready_to_collect;
}

/* The witnessed failure: a buyer pays P-1, then 1 zat, both to the order's
 * one-time address and both carrying the order's memo. The matcher sums
 * memo-bound notes, so the order must stay uncredited after the first note
 * and be credited after the second. Anything else strands the buyer's money
 * with no goods and no refusal. */
static bool tsb_split_payment_credited(const char *datadir,
                                       int64_t product_id)
{
    struct store_buyer_order split;
    struct node_db ndb;
    char split_out[640];
    (void)snprintf(split_out, sizeof(split_out), "%s/split.bin", datadir);
    if (!store_buyer_order(datadir, product_id, TSB_CUSTOMER, split_out,
                           false, &split).ok || split.amount_zatoshi < 2)
        return false;

    bool ok = tsb_open(datadir, &ndb);
    ok = ok && tsb_seed_note(&ndb, split.payment_addr, split.memo, 0x00,
                             split.amount_zatoshi - 1, 97, 0x75);
    if (ndb.open)
        node_db_close(&ndb);
    if (!ok || tsb_credited(datadir, split.purchase_id, 1)) {
        printf("(underpaid P-1 was credited) ");
        return false;
    }

    ok = tsb_open(datadir, &ndb);
    ok = ok && tsb_seed_note(&ndb, split.payment_addr, split.memo, 0x00,
                             1, 97, 0x76);
    if (ndb.open)
        node_db_close(&ndb);
    return ok && tsb_credited(datadir, split.purchase_id,
                              split.amount_zatoshi);
}

/* Pay `value` to `addr` with the order memo as a REAL Sapling output (the
 * production payer builder), then let the merchant wallet trial-decrypt it
 * and persist the recovered note through the live sync writer — the same
 * calls the tip-finalize block scan makes. No hand-filled note fields. */
static bool tsb_pay_real_note(const char *datadir, const char *addr,
                              const char *memo_text, uint64_t value,
                              uint8_t tag)
{
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32], ovk[32], memo[ZC_MEMO_SIZE];
    uint8_t cv[32], cm[32], epk[32], proof[GROTH_PROOF_SIZE];
    uint8_t enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    uint8_t out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    struct transaction tx;
    struct uint256 txid;
    struct node_db ndb;
    size_t before = tsb_merchant->num_sapling_notes;

    memset(ovk, 0x5a, sizeof(ovk));
    memset(memo, 0x00, sizeof(memo));
    memcpy(memo, memo_text, strlen(memo_text));
    memset(proof, 0, sizeof(proof));
    if (!sapling_decode_payment_address(addr, d, pk_d) ||
        !sapling_build_output_description(ovk, d, pk_d, value, memo, cv, cm,
                                          epk, enc, out, proof, NULL))
        return false;
    transaction_init(&tx);
    tx.version = 4;
    tx.overwintered = true;
    tx.value_balance = -(int64_t)value;
    tx.v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                      "tsb_output_desc");
    if (!tx.v_shielded_output)
        return false;
    tx.num_shielded_output = 1;
    memcpy(tx.v_shielded_output[0].cv.data, cv, 32);
    memcpy(tx.v_shielded_output[0].cm.data, cm, 32);
    memcpy(tx.v_shielded_output[0].ephemeral_key.data, epk, 32);
    memcpy(tx.v_shielded_output[0].enc_ciphertext, enc, sizeof(enc));
    memcpy(tx.v_shielded_output[0].out_ciphertext, out, sizeof(out));
    memset(&txid, tag, sizeof(txid));

    bool ok = wallet_try_sapling_decrypt(tsb_merchant, &tx, &txid) == 1 &&
              tsb_merchant->num_sapling_notes == before + 1 &&
              tsb_open(datadir, &ndb);
    if (ok) {
        const struct sapling_received_note *rn =
            &tsb_merchant->sapling_notes[before];
        ok = node_db_sync_sapling_note(&ndb, txid.data, rn->output_index,
                                       (int64_t)rn->value, rn->rcm, rn->memo,
                                       ZC_MEMO_SIZE, rn->ivk, rn->diversifier,
                                       rn->pk_d, rn->cm, rn->nf, 97);
        node_db_close(&ndb);
    }
    transaction_free(&tx);
    return ok;
}

/* The same split payment as tsb_split_payment_credited, but every note comes
 * out of real note encryption and the merchant wallet's trial decrypt, so a
 * 1-zat note, the memo decode and the address derivation are all the
 * production ones. */
static bool tsb_split_real_notes_credited(const char *datadir,
                                          int64_t product_id)
{
    struct store_buyer_order split;
    char split_out[640];
    (void)snprintf(split_out, sizeof(split_out), "%s/split_real.bin",
                   datadir);
    if (!store_buyer_order(datadir, product_id, TSB_CUSTOMER, split_out,
                           false, &split).ok || split.amount_zatoshi < 2)
        return false;
    if (!tsb_pay_real_note(datadir, split.payment_addr, split.memo,
                           (uint64_t)split.amount_zatoshi - 1, 0x77) ||
        tsb_credited(datadir, split.purchase_id, 1)) {
        printf("(P-1 note not ingested, or credited while underpaid) ");
        return false;
    }
    if (!tsb_pay_real_note(datadir, split.payment_addr, split.memo, 1,
                           0x78)) {
        printf("(1-zat note not ingested) ");
        return false;
    }
    return tsb_credited(datadir, split.purchase_id, split.amount_zatoshi);
}

/* A fully paid order must be credited however many NEWER unpaid orders sit
 * in the pending pool. The pool admits STORE_ORDER_MAX_PENDING_GLOBAL rows,
 * so a reconcile that only looks at a fixed page of them strands every paid
 * order outside that page: confirmed money, no goods, no refusal. */
static bool tsb_paid_order_behind_full_page(const char *datadir,
                                            int64_t product_id)
{
    struct store_buyer_order target;
    struct node_db ndb;
    char target_out[640];
    (void)snprintf(target_out, sizeof(target_out), "%s/crowded.bin",
                   datadir);
    if (!store_buyer_order(datadir, product_id, TSB_CUSTOMER, target_out,
                           false, &target).ok)
        return false;

    bool ok = tsb_open(datadir, &ndb);
    ok = ok && tsb_seed_note(&ndb, target.payment_addr, target.memo, 0x00,
                             target.amount_zatoshi, 97, 0x79);
    /* 64 newer unpaid orders for the same product, still inside the scan
     * window (the order-create gate would admit up to 200 per product). */
    int64_t newer = (int64_t)platform_time_wall_time_t() + 1;
    for (int i = 0; ok && i < 64; i++) {
        struct db_store_order filler;
        memset(&filler, 0, sizeof(filler));
        filler.product_id = product_id;
        (void)snprintf(filler.customer_addr, sizeof(filler.customer_addr),
                       "%s", TSB_CUSTOMER);
        (void)snprintf(filler.payment_addr, sizeof(filler.payment_addr),
                       "%s", target.payment_addr);
        filler.amount_zatoshi = target.amount_zatoshi;
        filler.status = STORE_ORDER_PENDING;
        filler.created_at = newer;
        ok = db_store_order_save(&ndb, &filler);
    }
    if (ndb.open)
        node_db_close(&ndb);
    return ok && tsb_credited(datadir, target.purchase_id,
                              target.amount_zatoshi);
}

/* Push an order's created_at back past the pending lifetime, so the payment
 * pass would delete it if it judged the order unpaid. */
static bool tsb_age_order(struct node_db *ndb, int64_t order_id)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "UPDATE orders SET created_at = created_at - ? WHERE id = ?",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(s, 1, (int64_t)STORE_ORDER_PENDING_EXPIRE_SECS + 600);
    sqlite3_bind_int64(s, 2, order_id);
    bool ok = sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(ndb->db) == 1;
    sqlite3_finalize(s);
    return ok;
}

/* -1 when the order row is gone (pruned), -2 when the ledger cannot be
 * opened, else the order's status. */
static int tsb_order_status(const char *datadir, int64_t order_id)
{
    struct db_store_order_view view;
    struct node_db ndb;
    if (!tsb_open(datadir, &ndb))
        return -2;
    memset(&view, 0, sizeof(view));
    int status = db_store_order_find_view(&ndb, order_id, &view)
        ? view.status : -1;
    node_db_close(&ndb);
    return status;
}

/* One payment pass on the merchant ledger with the wallet's scanned-through
 * height. The seeded tip is 100, so the confirmation ceiling is 97. */
static bool tsb_payment_pass(const char *datadir, int64_t scanned_height)
{
    struct node_db ndb;
    if (!tsb_open(datadir, &ndb))
        return false;
    store_process_payments_with_db(&ndb, datadir, scanned_height);
    node_db_close(&ndb);
    return true;
}

static bool tsb_place_aged_order(const char *datadir, int64_t product_id,
                                 const char *tag, struct store_buyer_order *o)
{
    struct node_db ndb;
    char out[640];
    (void)snprintf(out, sizeof(out), "%s/%s.bin", datadir, tag);
    if (!store_buyer_order(datadir, product_id, TSB_CUSTOMER, out, false,
                           o).ok)
        return false;
    bool ok = tsb_open(datadir, &ndb) && tsb_age_order(&ndb, o->order_id);
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* A confirmed, memo-bound note paying `o` in full at `height`: what the
 * wallet persists once it has read that block. */
static bool tsb_pay_order(const char *datadir,
                          const struct store_buyer_order *o, int height,
                          uint8_t tag)
{
    struct node_db ndb;
    bool ok = tsb_open(datadir, &ndb) &&
              tsb_seed_note(&ndb, o->payment_addr, o->memo, 0x00,
                            o->amount_zatoshi, height, tag);
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* While the wallet has not read every block through the confirmation
 * ceiling, an order with no visible payment is not knowably unpaid: the pass
 * must keep it pending, however old, and still credit a payment it can see.
 * Once the scan covers the ceiling, the pass credits the order whose payment
 * the scan just surfaced — even though it is past the pending lifetime — and
 * prunes only the order that is still unpaid. */
static bool tsb_scan_coverage_gates_prune(const char *datadir,
                                          int64_t product_id)
{
    struct store_buyer_order unread = {0}, unpaid = {0}, visible = {0};
    /* Block 97 was read and pays `visible`; block 91 (holding `unread`'s
     * payment) was not, so the wallet has read through 90 only. */
    bool ok = tsb_place_aged_order(datadir, product_id, "unread", &unread) &&
              tsb_place_aged_order(datadir, product_id, "unpaid", &unpaid) &&
              tsb_place_aged_order(datadir, product_id, "visible", &visible) &&
              tsb_pay_order(datadir, &visible, 97, 0x7a) &&
              tsb_payment_pass(datadir, 90);
    int unread_st = tsb_order_status(datadir, unread.order_id);
    int unpaid_st = tsb_order_status(datadir, unpaid.order_id);
    int visible_st = tsb_order_status(datadir, visible.order_id);
    printf("[incomplete: unread=%d unpaid=%d visible=%d] ", unread_st,
           unpaid_st, visible_st);
    if (!ok || unread_st != STORE_ORDER_PENDING ||
        unpaid_st != STORE_ORDER_PENDING || visible_st != STORE_ORDER_SENT)
        return false;

    /* The catch-up reads block 91: `unread`'s payment appears. */
    ok = tsb_pay_order(datadir, &unread, 91, 0x7b) &&
         tsb_payment_pass(datadir, 100);
    unread_st = tsb_order_status(datadir, unread.order_id);
    unpaid_st = tsb_order_status(datadir, unpaid.order_id);
    printf("[complete: unread=%d unpaid=%d] ", unread_st, unpaid_st);
    return ok && unread_st == STORE_ORDER_SENT && unpaid_st == -1;
}

/* Set the product's token id, returning the previous one in `old` when given.
 * An unusable id makes the mint refuse, as projection lag does. */
static bool tsb_swap_token(const char *datadir, int64_t product_id,
                           const char *token, char *old, size_t old_size)
{
    struct node_db ndb;
    sqlite3_stmt *s = NULL;
    bool ok = tsb_open(datadir, &ndb);
    if (ok && old) {
        ok = sqlite3_prepare_v2(ndb.db,
                 "SELECT token_id FROM products WHERE id = ?", -1, &s,
                 NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_int64(s, 1, product_id);
            ok = sqlite3_step(s) == SQLITE_ROW;
            if (ok)
                (void)snprintf(old, old_size, "%s",
                               (const char *)sqlite3_column_text(s, 0));
            sqlite3_finalize(s);
        }
    }
    if (ok) {
        ok = sqlite3_prepare_v2(ndb.db,
                 "UPDATE products SET token_id = ? WHERE id = ?", -1, &s,
                 NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_text(s, 1, token, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s, 2, product_id);
            ok = sqlite3_step(s) == SQLITE_DONE;
            sqlite3_finalize(s);
        }
    }
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

static bool tsb_seed_tip_at(const char *datadir, int height)
{
    struct node_db ndb;
    bool ok = tsb_open(datadir, &ndb) && tsb_seed_tip(&ndb, height);
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* A payment the pass cannot credit yet is not an abandoned order: the aged
 * order that is paid but shallower than the confirmation depth, and the one
 * whose mint fails, stay pending. The order with no payment at all is still
 * pruned once the scan covers the range. */
static bool tsb_prune_keeps_paid_orders(const char *datadir,
                                        int64_t product_id)
{
    struct store_buyer_order shallow = {0}, minting = {0}, unpaid = {0};
    char good_token[STORE_PRODUCT_TOKEN_MAX + 1] = "";
    bool ok = tsb_place_aged_order(datadir, product_id, "shallow", &shallow) &&
              tsb_place_aged_order(datadir, product_id, "minting", &minting) &&
              tsb_place_aged_order(datadir, product_id, "unpaid2", &unpaid) &&
              tsb_pay_order(datadir, &shallow, 100, 0x7c) &&
              tsb_pay_order(datadir, &minting, 90, 0x7d) &&
              tsb_swap_token(datadir, product_id, "not-a-token", good_token,
                             sizeof(good_token)) &&
              tsb_payment_pass(datadir, 100);
    int shallow_st = tsb_order_status(datadir, shallow.order_id);
    int minting_st = tsb_order_status(datadir, minting.order_id);
    int unpaid_st = tsb_order_status(datadir, unpaid.order_id);
    printf("[shallow=%d minting=%d unpaid=%d] ", shallow_st, minting_st,
           unpaid_st);
    if (!ok || shallow_st != STORE_ORDER_PENDING ||
        minting_st != STORE_ORDER_PENDING || unpaid_st != -1)
        return false;

    /* The mint recovers and the shallow payment matures: both are credited. */
    ok = tsb_swap_token(datadir, product_id, good_token, NULL, 0) &&
         tsb_seed_tip_at(datadir, 103) && tsb_payment_pass(datadir, 103);
    shallow_st = tsb_order_status(datadir, shallow.order_id);
    minting_st = tsb_order_status(datadir, minting.order_id);
    printf("[after: shallow=%d minting=%d] ", shallow_st, minting_st);
    return ok && shallow_st == STORE_ORDER_SENT &&
           minting_st == STORE_ORDER_SENT;
}

/* Point an order at a product row that does not exist. */
static bool tsb_orphan_order(const char *datadir, int64_t order_id)
{
    struct node_db ndb;
    sqlite3_stmt *s = NULL;
    bool ok = tsb_open(datadir, &ndb) &&
              sqlite3_prepare_v2(ndb.db,
                  "UPDATE orders SET product_id = 999999 WHERE id = ?", -1,
                  &s, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int64(s, 1, order_id);
        ok = sqlite3_step(s) == SQLITE_DONE;
        sqlite3_finalize(s);
    }
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* An order whose product row is gone cannot be minted. The expired one with
 * no payment is pruned; the one with a visible payment stays pending and is
 * logged for a refund. */
static bool tsb_orphan_orders(const char *datadir, int64_t product_id)
{
    struct store_buyer_order unpaid = {0}, paid = {0};
    bool ok = tsb_place_aged_order(datadir, product_id, "orphan-unpaid",
                                   &unpaid) &&
              tsb_place_aged_order(datadir, product_id, "orphan-paid",
                                   &paid) &&
              tsb_pay_order(datadir, &paid, 90, 0x7e) &&
              tsb_orphan_order(datadir, unpaid.order_id) &&
              tsb_orphan_order(datadir, paid.order_id) &&
              tsb_payment_pass(datadir, 100);
    int unpaid_st = tsb_order_status(datadir, unpaid.order_id);
    int paid_st = tsb_order_status(datadir, paid.order_id);
    printf("[orphan unpaid=%d paid=%d] ", unpaid_st, paid_st);
    return ok && unpaid_st == -1 && paid_st == STORE_ORDER_PENDING;
}

/* With a stored tip below the 3-block ceiling, a scanned height of -1 must
 * not count as covering, so nothing is pruned. */
static bool tsb_low_tip_prunes_nothing(void)
{
    char dir[512];
    struct node_db ndb;
    struct store_buyer_order o = {0};
    int64_t product_id = 0;
    struct store_buyer_offer offers[8];
    size_t n = 0;
    char out[640];

    tsb_tmpdir(dir, sizeof(dir), "lowtip");
    (void)snprintf(out, sizeof(out), "%s/lowtip.bin", dir);
    bool ok = store_buyer_catalog(dir, offers, 8, &n).ok && n > 0;
    if (ok)
        product_id = offers[0].product_id;
    ok = ok && tsb_open(dir, &ndb) && tsb_seed_tip(&ndb, 2);
    if (ndb.open)
        node_db_close(&ndb);
    ok = ok && tsb_place_aged_order(dir, product_id, "lowtip", &o) &&
         tsb_payment_pass(dir, -1);
    int st = tsb_order_status(dir, o.order_id);
    printf("[status=%d] ", st);
    return ok && st == STORE_ORDER_PENDING;
}

static bool tsb_rpc_catalog_unwired(const struct rpc_command *command)
{
    struct json_value params = {0}, result = {0};
    bool called = command->actor(&params, false, &result);
    const struct json_value *ok = json_get(&result, "ok");
    const char *code = json_get_str(json_get(&result, "code"));
    const char *detail = json_get_str(json_get(&result, "detail"));
    bool refused = called && ok && !json_get_bool(ok) && code && detail &&
        strcmp(code, "NODE_DB_UNAVAILABLE") == 0 &&
        strcmp(detail, "no data directory wired") == 0;
    json_free(&result);
    return refused;
}

static bool tsb_rpc_catalog_contains(const struct rpc_command *command, int64_t product_id)
{
    struct json_value params = {0}, result = {0};
    bool called = command->actor(&params, false, &result);
    const struct json_value *products = json_get(&result, "products");
    bool found = false;
    for (size_t i = 0; i < json_size(products); i++) {
        const struct json_value *row = json_at(products, i);
        if (json_get_int(json_get(row, "product_id")) == product_id)
            found = true;
    }
    bool listed = called && json_get_bool(json_get(&result, "ok")) && found;
    json_free(&result);
    return listed;
}

static int tsb_rpc_datadir_copy(const char *datadir, int64_t product_id)
{
    struct rpc_table table;
    rpc_table_init(&table);
    register_store_buyer_rpc_commands(&table);
    const struct rpc_command *command = rpc_table_find(&table, "storebuy_catalog");
    rpc_store_buyer_set_state(NULL);
    if (!command || !command->actor)
        return 1;
    bool before = tsb_rpc_catalog_unwired(command);
    char mutable_path[1024];
    snprintf(mutable_path, sizeof(mutable_path), "%s", datadir);
    rpc_store_buyer_set_state(mutable_path);
    memset(mutable_path, 0, sizeof(mutable_path));
    bool copied = tsb_rpc_catalog_contains(command, product_id);
    rpc_store_buyer_set_state(NULL);
    bool after = tsb_rpc_catalog_unwired(command);
    if (!before || !copied || !after)
        fprintf(stderr, "store_buyer: RPC datadir copy failed before=%d copied=%d after=%d\n",
            before, copied, after);
    return !(before && copied && after);
}

/* ── 1. Sapling address routing follows the active chain ─────────── */
static int tsb_zaddr_prefix_follows_chain(void)
{
    printf("store_buyer: z-address prefix follows the active chain... ");
    bool ok = true;
    chain_params_select(CHAIN_MAIN);
    ok = ok && wallet_addr_is_sapling("zs1abcdefghijklmnop");
    ok = ok && !wallet_addr_is_sapling("zregtestsapling1abcdef");
    ok = ok && !wallet_addr_is_sapling(TSB_CUSTOMER);
    chain_params_select(CHAIN_REGTEST);
    ok = ok && wallet_addr_is_sapling("zregtestsapling1abcdef");
    /* The old literal test accepted this on every chain; on regtest a
     * "zs1..." string is not a local address and must not be routed to
     * the shielded branch. */
    ok = ok && !wallet_addr_is_sapling("zs1abcdefghijklmnop");
    chain_params_select(CHAIN_TESTNET);
    ok = ok && wallet_addr_is_sapling("ztestsapling1abcdef");
    ok = ok && !wallet_addr_is_sapling("zs1abcdefghijklmnop");
    /* The bech32 separator is required, so an HRP that is a prefix of a
     * longer word cannot be mistaken for one of ours. */
    ok = ok && !wallet_addr_is_sapling("ztestsaplingfoo");
    ok = ok && !wallet_addr_is_sapling(NULL);
    chain_params_select(CHAIN_MAIN);
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    return 0;
}

/* ── 2. A catalog is visible, and product 1 gets a file ──────────── */
static int tsb_catalog_with_downloadable_file(const char *datadir,
                                              int64_t *product_id)
{
    printf("store_buyer: catalog lists products with a downloadable file... ");
    struct store_buyer_offer offers[8];
    size_t n = 0;
    struct node_db ndb;
    bool ok = store_buyer_catalog(datadir, offers, 8, &n).ok;
    ok = ok && n > 0;
    if (ok)
        *product_id = offers[0].product_id;
    /* No file attached yet, so the buyer is told so honestly. */
    ok = ok && !offers[0].has_content;

    if (ok && tsb_open(datadir, &ndb)) {
        ok = tsb_attach_blob(&ndb, *product_id, TSB_BLOB, sizeof(TSB_BLOB));
        ok = ok && tsb_seed_tip(&ndb, 100);
        node_db_close(&ndb);
    } else {
        ok = false;
    }
    /* ...and now it says there is one. */
    if (ok) {
        n = 0;
        ok = store_buyer_catalog(datadir, offers, 8, &n).ok;
        ok = ok && n > 0 && offers[0].has_content;
    }
    if (ok) {
        printf("OK (product %lld)\n", (long long)*product_id);
    } else {
        printf("FAIL\n");
        return 1;
    }
    return 0;
}

/* Order, confirm the memo token is the order id, and seed its payment. */
static const char *tsb_place_memo_and_pay(const char *datadir,
                                          int64_t product_id,
                                          const char *out_path,
                                          struct store_buyer_order *paid)
{
    const char *step = "order";
    bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                out_path, false, paid).ok;
    ok = ok && paid->purchase_id > 0 && paid->order_id > 0;
    ok = ok && paid->payment_addr[0] != '\0';
    if (ok) {
        /* The memo the buyer records must be exactly the token the
         * merchant's matcher looks for — not "something like" it. */
        char want[64];
        (void)snprintf(want, sizeof(want), "ZCL23ORDER:%lld",
                       (long long)paid->order_id);
        step = "memo format";
        ok = strcmp(paid->memo, want) == 0;
    }
    if (ok) {
        step = "seed payment";
        struct node_db ndb;
        ok = tsb_open(datadir, &ndb);
        if (ok) {
            ok = tsb_seed_note(&ndb, paid->payment_addr, paid->memo, 0x00,
                               paid->amount_zatoshi, 97, 0x71);
            node_db_close(&ndb);
        }
    }
    return ok ? NULL : step;
}

/* Merchant credits the seeded note, then the buyer collects the file. */
static const char *tsb_credit_and_collect_paid(
    const char *datadir, const struct store_buyer_order *paid)
{
    const char *step = "merchant credits the order";
    store_process_payments(datadir);
    struct store_buyer_state state;
    bool ok = store_buyer_refresh(datadir, paid->purchase_id, &state).ok;
    ok = ok && state.confirmed_zatoshi >= paid->amount_zatoshi;
    ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
    ok = ok && state.ready_to_collect;
    if (ok) {
        step = "collect";
        struct store_buyer_delivery got;
        ok = store_buyer_collect(datadir, paid->purchase_id, NULL, &got).ok;
        ok = ok && got.hash_verified;
        ok = ok && got.bytes == (int64_t)sizeof(TSB_BLOB);
    }
    return ok ? NULL : step;
}

/* The file on disk is the blob, the temporary is gone, and the row is
 * delivered. */
static const char *tsb_verify_bought_file_delivered(
    const char *datadir, const char *out_path, const char *part_path,
    const struct store_buyer_order *paid)
{
    const char *step = "bytes on disk";
    bool ok;
    {
        uint8_t buf[256];
        long n = tsb_read_file(out_path, buf, sizeof(buf));
        ok = n == (long)sizeof(TSB_BLOB) &&
             memcmp(buf, TSB_BLOB, sizeof(TSB_BLOB)) == 0;
        /* Atomic write: no temporary is left behind. */
        ok = ok && !tsb_file_exists(part_path);
    }
    if (ok) {
        step = "stage is delivered";
        struct db_store_purchase rows[8];
        size_t n = 0;
        ok = store_buyer_list(datadir, rows, 8, &n).ok;
        ok = ok && n >= 1;
        ok = ok && rows[0].id == paid->purchase_id;
        ok = ok && rows[0].stage == STORE_PURCHASE_DELIVERED;
    }
    return ok ? NULL : step;
}

/* ── 3. Happy path: order, pay, collect, verify ──────────────────── */
static int tsb_confirmed_payment_verified_file(
    const char *datadir, int64_t product_id, const char *out_path,
    const char *part_path, struct store_buyer_order *paid)
{
    printf("store_buyer: order -> confirmed payment -> verified file... ");
    memset(paid, 0, sizeof(*paid));
    const char *step = tsb_place_memo_and_pay(datadir, product_id, out_path,
                                              paid);
    if (!step)
        step = tsb_credit_and_collect_paid(datadir, paid);
    if (!step)
        step = tsb_verify_bought_file_delivered(datadir, out_path, part_path,
                                                paid);
    if (!step) {
        printf("OK (purchase %lld, %zu bytes)\n",
               (long long)paid->purchase_id, sizeof(TSB_BLOB));
        return 0;
    }
    printf("FAIL (%s)\n", step);
    return 1;
}

/* ── 4. A payment naming a DIFFERENT order does not unlock this one ─ */
static int tsb_wrong_memo_does_not_unlock(
    const char *datadir, int64_t product_id,
    const struct store_buyer_order *paid, struct store_buyer_order *unpaid)
{
    printf("store_buyer: a wrong-order memo does not unlock a purchase... ");
    memset(unpaid, 0, sizeof(*unpaid));
    const char *step = "order";
    char decoy_out[640];
    (void)snprintf(decoy_out, sizeof(decoy_out), "%s/decoy.bin", datadir);
    bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                decoy_out, false, unpaid).ok;
    ok = ok && unpaid->purchase_id != paid->purchase_id;
    if (ok) {
        /* Full value arrives at THIS order's one-time address, but the
         * memo names the earlier order. An address-and-amount matcher
         * would call that paid; the memo-bound one must not. */
        step = "seed a decoy payment";
        struct node_db ndb;
        ok = tsb_open(datadir, &ndb);
        if (ok) {
            ok = tsb_seed_note(&ndb, unpaid->payment_addr, paid->memo, 0x00,
                               unpaid->amount_zatoshi, 97, 0x72);
            node_db_close(&ndb);
        }
    }
    if (ok) {
        step = "not credited";
        store_process_payments(datadir);
        struct store_buyer_state state;
        ok = store_buyer_refresh(datadir, unpaid->purchase_id, &state).ok;
        ok = ok && state.confirmed_zatoshi == 0;
        ok = ok && state.purchase.stage != STORE_PURCHASE_PAID;
        ok = ok && !state.ready_to_collect;
    }
    if (ok) {
        step = "collect refuses by name";
        struct store_buyer_delivery got;
        ok = store_buyer_collect(datadir, unpaid->purchase_id, NULL,
                                 &got).code
            == STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED;
        ok = ok && !tsb_file_exists(decoy_out);
    }
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (%s)\n", step);
        return 1;
    }
    return 0;
}

/* ── 5. Mainnet refuses the spend; a test chain names the real reason ─ */
static int tsb_mainnet_refuses_spend(const char *datadir,
                                     int64_t purchase_id)
{
    printf("store_buyer: mainnet refuses the payment step... ");
    struct store_buyer_payment pay;
    chain_params_select(CHAIN_MAIN);
    bool ok = store_buyer_prepare_payment(datadir, purchase_id,
                                          TSB_CUSTOMER, &pay).code
        == STORE_BUYER_ERR_MAINNET_REFUSED;
    /* Nothing may be handed back when the answer is a refusal. */
    ok = ok && pay.to_addr[0] == '\0' && pay.memo_hex[0] == '\0';
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    return 0;
}

static int tsb_missing_prover_refuses_pay(const char *datadir,
                                          int64_t purchase_id)
{
    printf("store_buyer: a build with no proving backend refuses to pay... ");
    struct store_buyer_payment pay;
    chain_params_select(CHAIN_REGTEST);
    struct zcl_result r =
        store_buyer_prepare_payment(datadir, purchase_id, TSB_CUSTOMER, &pay);
    bool ok;
    if (!zclassic_sapling_prover_is_ready()) {
        /* An unavailable native prover must refuse here rather than fail
         * later inside coin selection—or, worse, quietly do nothing. */
        ok = (r.code == STORE_BUYER_ERR_PROVER_UNAVAILABLE);
        ok = ok && pay.memo_hex[0] == '\0';
    } else {
        /* A prover-linked build gets past that check; the next honest
         * refusal is the empty wallet, never PROVER_UNAVAILABLE. */
        ok = (r.code != STORE_BUYER_ERR_PROVER_UNAVAILABLE);
    }
    chain_params_select(CHAIN_MAIN);
    if (ok) {
        printf("OK (%s)\n", store_buyer_status_code(r.code));
    } else {
        printf("FAIL (got %s)\n", store_buyer_status_code(r.code));
        return 1;
    }
    return 0;
}

/* ── 6. The old 0xF6 memo padding is not creditable ──────────────── */
static int tsb_old_f6_memo_uncredited(const char *datadir,
                                      int64_t product_id)
{
    printf("store_buyer: a memo padded the old way is not credited... ");
    const char *step = "order";
    struct store_buyer_order stale;
    char stale_out[640];
    (void)snprintf(stale_out, sizeof(stale_out), "%s/stale.bin", datadir);
    bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                stale_out, false, &stale).ok;
    if (ok) {
        /* Exactly the right token for exactly the right order, at the
         * right address, for the right amount — padded with 0xF6, which
         * is what the plain-text memo path used to emit. The merchant
         * requires NUL or ';' after the token, so this is money that
         * arrives and is never credited. That was a real, silent way to
         * lose a buyer's payment. */
        step = "seed a 0xF6-padded payment";
        struct node_db ndb;
        ok = tsb_open(datadir, &ndb);
        if (ok) {
            ok = tsb_seed_note(&ndb, stale.payment_addr, stale.memo, 0xF6,
                               stale.amount_zatoshi, 97, 0x73);
            node_db_close(&ndb);
        }
    }
    if (ok) {
        step = "not credited";
        store_process_payments(datadir);
        struct store_buyer_state state;
        ok = store_buyer_refresh(datadir, stale.purchase_id, &state).ok;
        ok = ok && state.confirmed_zatoshi == 0;
        ok = ok && state.purchase.stage != STORE_PURCHASE_PAID;
    }
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (%s)\n", step);
        return 1;
    }
    return 0;
}

/* Place the swapped-payload order and pay it with its own memo. */
static const char *tsb_order_and_pay_swapped(const char *datadir,
                                             int64_t product_id,
                                             const char *swap_out,
                                             struct store_buyer_order *swapped)
{
    const char *step = "order";
    bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                swap_out, false, swapped).ok;
    if (ok) {
        step = "pay it";
        struct node_db ndb;
        ok = tsb_open(datadir, &ndb);
        if (ok) {
            ok = tsb_seed_note(&ndb, swapped->payment_addr, swapped->memo,
                               0x00, swapped->amount_zatoshi, 97, 0x74);
            node_db_close(&ndb);
        }
    }
    return ok ? NULL : step;
}

/* Credit that payment, then serve a different payload than ordered. */
static const char *tsb_credit_and_swap_payload(
    const char *datadir, int64_t product_id,
    const struct store_buyer_order *swapped)
{
    const char *step = "credited";
    store_process_payments(datadir);
    struct store_buyer_state state;
    bool ok = store_buyer_refresh(datadir, swapped->purchase_id, &state).ok;
    ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
    if (ok) {
        /* The merchant now serves a DIFFERENT payload than the one this
         * purchase agreed to buy. The buyer recorded the content hash at
         * order time, so it can tell — this covers a swapped payload,
         * not merely a corrupted transfer. */
        step = "merchant swaps the payload";
        struct node_db ndb;
        ok = tsb_open(datadir, &ndb);
        if (ok) {
            ok = tsb_attach_blob(&ndb, product_id, TSB_SWAPPED,
                                 sizeof(TSB_SWAPPED));
            node_db_close(&ndb);
        }
    }
    return ok ? NULL : step;
}

/* Collect names the hash mismatch and leaves neither file nor temporary. */
static const char *tsb_refuse_hash_mismatch_unwritten(
    const char *datadir, const char *swap_out, const char *swap_part,
    const struct store_buyer_order *swapped)
{
    const char *step = "refused by name";
    struct store_buyer_delivery got;
    bool ok = store_buyer_collect(datadir, swapped->purchase_id, NULL,
                                  &got).code == STORE_BUYER_ERR_HASH_MISMATCH;
    if (ok) {
        step = "nothing written";
        ok = !tsb_file_exists(swap_out) && !tsb_file_exists(swap_part);
    }
    return ok ? NULL : step;
}

static const char *tsb_prior_delivery_intact(const char *out_path)
{
    /* The earlier, correct purchase keeps its file: a later refusal
     * must not damage what a buyer already owns. */
    uint8_t buf[256];
    long n = tsb_read_file(out_path, buf, sizeof(buf));
    bool ok = n == (long)sizeof(TSB_BLOB) &&
              memcmp(buf, TSB_BLOB, sizeof(TSB_BLOB)) == 0;
    return ok ? NULL : "already-delivered file untouched";
}

static const char *tsb_swapped_failure_recorded(
    const char *datadir, const struct store_buyer_order *swapped)
{
    struct db_store_purchase rows[8];
    size_t n = 0;
    bool ok = store_buyer_list(datadir, rows, 8, &n).ok;
    bool found = false;
    for (size_t i = 0; ok && i < n; i++) {
        if (rows[i].id != swapped->purchase_id)
            continue;
        found = true;
        ok = rows[i].stage == STORE_PURCHASE_FAILED;
        ok = ok && strstr(rows[i].last_error, "HASH_MISMATCH") != NULL;
    }
    ok = ok && found;
    return ok ? NULL : "the refusal is recorded on the purchase";
}

static const char *tsb_hash_mismatch_reason_survives(
    const char *datadir, const struct store_buyer_order *swapped)
{
    /* A status call must not erase why it stopped. The stage may go
     * back to `paid` (the merchant WAS paid, so a retry is owed), but
     * the reason has to survive or the operator is told a purchase is
     * fine when its file was wrong. */
    struct store_buyer_state state;
    bool ok = store_buyer_refresh(datadir, swapped->purchase_id, &state).ok;
    ok = ok && strstr(state.purchase.last_error, "HASH_MISMATCH");
    ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
    return ok ? NULL : "the reason survives a status call";
}

/* ── 7. Wrong bytes are refused, and nothing is written ──────────── */
static int tsb_hash_mismatch_writes_nothing(const char *datadir,
                                            int64_t product_id,
                                            const char *out_path)
{
    printf("store_buyer: a content-hash mismatch writes nothing... ");
    struct store_buyer_order swapped;
    char swap_out[640];
    char swap_part[384];
    (void)snprintf(swap_out, sizeof(swap_out), "%s/swapped.bin", datadir);
    (void)snprintf(swap_part, sizeof(swap_part), "%s.part", swap_out);

    const char *step = tsb_order_and_pay_swapped(datadir, product_id,
                                                 swap_out, &swapped);
    if (!step)
        step = tsb_credit_and_swap_payload(datadir, product_id, &swapped);
    if (!step)
        step = tsb_refuse_hash_mismatch_unwritten(datadir, swap_out,
                                                  swap_part, &swapped);
    if (!step)
        step = tsb_prior_delivery_intact(out_path);
    if (!step)
        step = tsb_swapped_failure_recorded(datadir, &swapped);
    if (!step)
        step = tsb_hash_mismatch_reason_survives(datadir, &swapped);
    if (!step) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (%s)\n", step);
    return 1;
}

/* ── 8. Unknown ids are refused distinguishably ──────────────────── */
static int tsb_unknown_ids_are_named(const char *datadir,
                                     const char *out_path)
{
    printf("store_buyer: unknown product and purchase ids are named... ");
    struct store_buyer_order o;
    struct store_buyer_state s;
    bool ok = store_buyer_order(datadir, 999999, TSB_CUSTOMER, out_path,
                                false,
                                &o).code == STORE_BUYER_ERR_UNKNOWN_PRODUCT;
    ok = ok && store_buyer_refresh(datadir, 999999, &s).code == STORE_BUYER_ERR_UNKNOWN_PURCHASE;
    ok = ok && strcmp(store_buyer_status_code(
                          STORE_BUYER_ERR_UNKNOWN_PRODUCT),
                      "UNKNOWN_PRODUCT") == 0;
    ok = ok && strcmp(store_buyer_status_code(
                          STORE_BUYER_ERR_HASH_MISMATCH),
                      "HASH_MISMATCH") == 0;
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    return 0;
}

int test_store_buyer(void)
{
    int failures = 0;
    char datadir[512];
    char out_path[640];
    char part_path[704];

    printf("\n=== store buyer (MVP #5, buying side) ===\n");

    /* Under ./test-tmp/, not the repository root: this group keeps its
     * datadir on failure for post-mortem, and a kept directory in the root
     * is exactly what check-no-stray-root-files exists to catch. */
    tsb_tmpdir(datadir, sizeof(datadir), "main");
    (void)snprintf(out_path, sizeof(out_path), "%s/bought.bin", datadir);
    (void)snprintf(part_path, sizeof(part_path), "%s.part", out_path);

    failures += tsb_zaddr_prefix_follows_chain();

    if (!tsb_wire_merchant()) {
        printf("store_buyer: FAIL (could not seed a merchant wallet)\n");
        return failures + 1;
    }

    int64_t product_id = 0;
    failures += tsb_catalog_with_downloadable_file(datadir, &product_id);
    failures += tsb_rpc_datadir_copy(datadir, product_id);

    struct store_buyer_order paid_order;
    failures += tsb_confirmed_payment_verified_file(datadir, product_id,
                                                    out_path, part_path,
                                                    &paid_order);

    struct store_buyer_order unpaid;
    memset(&unpaid, 0, sizeof(unpaid));
    failures += tsb_wrong_memo_does_not_unlock(datadir, product_id,
                                               &paid_order, &unpaid);
    failures += tsb_mainnet_refuses_spend(datadir, unpaid.purchase_id);
    failures += tsb_missing_prover_refuses_pay(datadir, unpaid.purchase_id);
    failures += tsb_old_f6_memo_uncredited(datadir, product_id);
    failures += tsb_hash_mismatch_writes_nothing(datadir, product_id,
                                                 out_path);

    /* ── 7b. A payment split across two memo-bound notes is credited ─── */
    failures += tsb_report("a payment split P-1 + 1 is credited once whole",
                           tsb_split_payment_credited(datadir, product_id));
    failures += tsb_report("real decrypted notes P-1 + 1 are credited whole",
                           tsb_split_real_notes_credited(datadir,
                                                         product_id));
    failures += tsb_report("a paid order behind 64 newer unpaid is credited",
                           tsb_paid_order_behind_full_page(datadir,
                                                           product_id));
    failures += tsb_report("an incomplete wallet scan never prunes an order "
                           "as unpaid",
                           tsb_scan_coverage_gates_prune(datadir,
                                                         product_id));
    failures += tsb_report("an expired order with a visible payment survives "
                           "the prune and is credited once it can be",
                           tsb_prune_keeps_paid_orders(datadir, product_id));
    failures += tsb_report("an expired orphan order is pruned unless a payment "
                           "is visible",
                           tsb_orphan_orders(datadir, product_id));
    failures += tsb_report("a stored tip below 3 prunes nothing",
                           tsb_low_tip_prunes_nothing());

    failures += tsb_unknown_ids_are_named(datadir, out_path);

    /* ── 9. A seller's proof-of-work ask is bounded before solving ───── */
    failures += tsb_report("seller pow bits are bounded and strict",
                           tsb_pow_params_bounded());

    /* ── 10. A reused remote order id cannot rewrite a purchase ──────── */
    failures += tsb_report("reused remote order id only refreshes a retry",
                           tsb_remote_reuse_guarded());
    failures += tsb_report("seller product JSON must prove a file it claims",
                           tsb_parse_product_cases());
    failures += tsb_report("a shielded order refuses a transparent address",
                           tsb_remote_addr_kind());

    tsb_unwire_merchant();
    chain_params_select(CHAIN_MAIN);

    if (failures == 0) {
        failures += !fixture_rm_ok(datadir);
    } else {
        printf("store_buyer: debug datadir kept: %s\n", datadir);
    }
    return failures;
}
