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

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/runtime.h"
#include "controllers/store_controller.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/zslp_controller.h"
#include "crypto/sha3.h"
#include "models/block.h"
#include "models/store.h"
#include "models/store_blob.h"
#include "models/store_purchase.h"
#include "models/wallet_tx.h"
#include "sapling/constants.h"
#include "sapling/sapling_prover.h"
#include "services/store_buyer.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    if (!db_store_blob_put(ndb, data, len, "application/octet-stream",
                           "payload.bin", hash))
        return false;
    return db_store_product_save_content(ndb, product_id, hash);
}

/* Make a fixture datadir under ./test-tmp and hand it back as an ABSOLUTE
 * path.
 *
 * test_make_tmpdir spells the directory relative to the working directory
 * ("./test-tmp/store_buyer_<pid>_<tag>"). store_buyer_collect writes the
 * delivered payload through sb_write_atomic -> platform_private_path_resolve,
 * which realpath()s the destination's parent and refuses any pathname that
 * does not start at the root ("destination parent is not a safe real
 * directory"). A relative output path is rejected before a byte is written,
 * so the fixture must anchor the same in-tree directory at the working
 * directory. */
static void tsb_tmpdir(char *dir, size_t dir_size, const char *tag)
{
    char rel[192];
    test_make_tmpdir(rel, sizeof(rel), "store_buyer", tag);

    const char *leaf = rel;
    if (leaf[0] == '.' && leaf[1] == '/')
        leaf += 2;

    char cwd[256];
    if (!getcwd(cwd, sizeof(cwd))) {
        (void)snprintf(dir, dir_size, "%s", rel);  /* write fails loudly */
        return;
    }
    (void)snprintf(dir, dir_size, "%s/%s", cwd, leaf);
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

int test_store_buyer(void)
{
    int failures = 0;
    char datadir[512];
    char out_path[640];
    char part_path[704];
    struct node_db ndb;

    printf("\n=== store buyer (MVP #5, buying side) ===\n");

    /* Under ./test-tmp/, not the repository root: this group keeps its
     * datadir on failure for post-mortem, and a kept directory in the root
     * is exactly what check-no-stray-root-files exists to catch. */
    tsb_tmpdir(datadir, sizeof(datadir), "main");
    (void)snprintf(out_path, sizeof(out_path), "%s/bought.bin", datadir);
    (void)snprintf(part_path, sizeof(part_path), "%s.part", out_path);

    /* ── 1. Sapling address routing follows the active chain ─────────── */
    printf("store_buyer: z-address prefix follows the active chain... ");
    {
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
            failures++;
        }
    }

    if (!tsb_wire_merchant()) {
        printf("store_buyer: FAIL (could not seed a merchant wallet)\n");
        return failures + 1;
    }

    /* ── 2. A catalog is visible, and product 1 gets a file ──────────── */
    printf("store_buyer: catalog lists products with a downloadable file... ");
    int64_t product_id = 0;
    {
        struct store_buyer_offer offers[8];
        size_t n = 0;
        bool ok = store_buyer_catalog(datadir, offers, 8, &n).ok;
        ok = ok && n > 0;
        if (ok)
            product_id = offers[0].product_id;
        /* No file attached yet, so the buyer is told so honestly. */
        ok = ok && !offers[0].has_content;

        if (ok && tsb_open(datadir, &ndb)) {
            ok = tsb_attach_blob(&ndb, product_id, TSB_BLOB, sizeof(TSB_BLOB));
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
            printf("OK (product %lld)\n", (long long)product_id);
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    /* ── 3. Happy path: order, pay, collect, verify ──────────────────── */
    printf("store_buyer: order -> confirmed payment -> verified file... ");
    struct store_buyer_order paid_order;
    memset(&paid_order, 0, sizeof(paid_order));
    {
        const char *step = "order";
        bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                    out_path, false, &paid_order).ok;
        ok = ok && paid_order.purchase_id > 0 && paid_order.order_id > 0;
        ok = ok && paid_order.payment_addr[0] != '\0';
        if (ok) {
            /* The memo the buyer records must be exactly the token the
             * merchant's matcher looks for — not "something like" it. */
            char want[64];
            (void)snprintf(want, sizeof(want), "ZCL23ORDER:%lld",
                           (long long)paid_order.order_id);
            step = "memo format";
            ok = strcmp(paid_order.memo, want) == 0;
        }
        if (ok) {
            step = "seed payment";
            ok = tsb_open(datadir, &ndb);
            if (ok) {
                ok = tsb_seed_note(&ndb, paid_order.payment_addr,
                                   paid_order.memo, 0x00,
                                   paid_order.amount_zatoshi, 97, 0x71);
                node_db_close(&ndb);
            }
        }
        if (ok) {
            step = "merchant credits the order";
            store_process_payments(datadir);
            struct store_buyer_state state;
            ok = store_buyer_refresh(datadir, paid_order.purchase_id,
                                     &state).ok;
            ok = ok && state.confirmed_zatoshi >= paid_order.amount_zatoshi;
            ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
            ok = ok && state.ready_to_collect;
        }
        if (ok) {
            step = "collect";
            struct store_buyer_delivery got;
            ok = store_buyer_collect(datadir, paid_order.purchase_id, NULL,
                                     &got).ok;
            ok = ok && got.hash_verified;
            ok = ok && got.bytes == (int64_t)sizeof(TSB_BLOB);
        }
        if (ok) {
            step = "bytes on disk";
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
            ok = ok && rows[0].id == paid_order.purchase_id;
            ok = ok && rows[0].stage == STORE_PURCHASE_DELIVERED;
        }
        if (ok) {
            printf("OK (purchase %lld, %zu bytes)\n",
                   (long long)paid_order.purchase_id, sizeof(TSB_BLOB));
        } else {
            printf("FAIL (%s)\n", step);
            failures++;
        }
    }

    /* ── 4. A payment naming a DIFFERENT order does not unlock this one ─ */
    printf("store_buyer: a wrong-order memo does not unlock a purchase... ");
    struct store_buyer_order unpaid;
    memset(&unpaid, 0, sizeof(unpaid));
    {
        const char *step = "order";
        char decoy_out[640];
        (void)snprintf(decoy_out, sizeof(decoy_out), "%s/decoy.bin", datadir);
        bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                    decoy_out, false, &unpaid).ok;
        ok = ok && unpaid.purchase_id != paid_order.purchase_id;
        if (ok) {
            /* Full value arrives at THIS order's one-time address, but the
             * memo names the earlier order. An address-and-amount matcher
             * would call that paid; the memo-bound one must not. */
            step = "seed a decoy payment";
            ok = tsb_open(datadir, &ndb);
            if (ok) {
                ok = tsb_seed_note(&ndb, unpaid.payment_addr,
                                   paid_order.memo, 0x00,
                                   unpaid.amount_zatoshi, 97, 0x72);
                node_db_close(&ndb);
            }
        }
        if (ok) {
            step = "not credited";
            store_process_payments(datadir);
            struct store_buyer_state state;
            ok = store_buyer_refresh(datadir, unpaid.purchase_id,
                                     &state).ok;
            ok = ok && state.confirmed_zatoshi == 0;
            ok = ok && state.purchase.stage != STORE_PURCHASE_PAID;
            ok = ok && !state.ready_to_collect;
        }
        if (ok) {
            step = "collect refuses by name";
            struct store_buyer_delivery got;
            ok = store_buyer_collect(datadir, unpaid.purchase_id, NULL,
                                     &got).code == STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED;
            ok = ok && !tsb_file_exists(decoy_out);
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL (%s)\n", step);
            failures++;
        }
    }

    /* ── 5. Mainnet refuses the spend; a test chain names the real reason ─ */
    printf("store_buyer: mainnet refuses the payment step... ");
    {
        struct store_buyer_payment pay;
        chain_params_select(CHAIN_MAIN);
        bool ok = store_buyer_prepare_payment(datadir, unpaid.purchase_id,
                                              TSB_CUSTOMER, &pay).code == STORE_BUYER_ERR_MAINNET_REFUSED;
        /* Nothing may be handed back when the answer is a refusal. */
        ok = ok && pay.to_addr[0] == '\0' && pay.memo_hex[0] == '\0';
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("store_buyer: a build with no proving backend refuses to pay... ");
    {
        struct store_buyer_payment pay;
        chain_params_select(CHAIN_REGTEST);
        struct zcl_result r =
            store_buyer_prepare_payment(datadir, unpaid.purchase_id,
                                        TSB_CUSTOMER, &pay);
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
            failures++;
        }
    }

    /* ── 6. The old 0xF6 memo padding is not creditable ──────────────── */
    printf("store_buyer: a memo padded the old way is not credited... ");
    {
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
            ok = store_buyer_refresh(datadir, stale.purchase_id,
                                     &state).ok;
            ok = ok && state.confirmed_zatoshi == 0;
            ok = ok && state.purchase.stage != STORE_PURCHASE_PAID;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL (%s)\n", step);
            failures++;
        }
    }

    /* ── 7. Wrong bytes are refused, and nothing is written ──────────── */
    printf("store_buyer: a content-hash mismatch writes nothing... ");
    {
        const char *step = "order";
        struct store_buyer_order swapped;
        char swap_out[640];
        char swap_part[384];
        (void)snprintf(swap_out, sizeof(swap_out), "%s/swapped.bin", datadir);
        (void)snprintf(swap_part, sizeof(swap_part), "%s.part", swap_out);

        bool ok = store_buyer_order(datadir, product_id, TSB_CUSTOMER,
                                    swap_out, false, &swapped).ok;
        if (ok) {
            step = "pay it";
            ok = tsb_open(datadir, &ndb);
            if (ok) {
                ok = tsb_seed_note(&ndb, swapped.payment_addr, swapped.memo,
                                   0x00, swapped.amount_zatoshi, 97, 0x74);
                node_db_close(&ndb);
            }
        }
        if (ok) {
            step = "credited";
            store_process_payments(datadir);
            struct store_buyer_state state;
            ok = store_buyer_refresh(datadir, swapped.purchase_id,
                                     &state).ok;
            ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
        }
        if (ok) {
            /* The merchant now serves a DIFFERENT payload than the one this
             * purchase agreed to buy. The buyer recorded the content hash at
             * order time, so it can tell — this covers a swapped payload,
             * not merely a corrupted transfer. */
            step = "merchant swaps the payload";
            ok = tsb_open(datadir, &ndb);
            if (ok) {
                ok = tsb_attach_blob(&ndb, product_id, TSB_SWAPPED,
                                     sizeof(TSB_SWAPPED));
                node_db_close(&ndb);
            }
        }
        if (ok) {
            step = "refused by name";
            struct store_buyer_delivery got;
            ok = store_buyer_collect(datadir, swapped.purchase_id, NULL,
                                     &got).code == STORE_BUYER_ERR_HASH_MISMATCH;
        }
        if (ok) {
            step = "nothing written";
            ok = !tsb_file_exists(swap_out) && !tsb_file_exists(swap_part);
        }
        if (ok) {
            step = "already-delivered file untouched";
            /* The earlier, correct purchase keeps its file: a later refusal
             * must not damage what a buyer already owns. */
            uint8_t buf[256];
            long n = tsb_read_file(out_path, buf, sizeof(buf));
            ok = n == (long)sizeof(TSB_BLOB) &&
                 memcmp(buf, TSB_BLOB, sizeof(TSB_BLOB)) == 0;
        }
        if (ok) {
            step = "the refusal is recorded on the purchase";
            struct db_store_purchase rows[8];
            size_t n = 0;
            ok = store_buyer_list(datadir, rows, 8, &n).ok;
            bool found = false;
            for (size_t i = 0; ok && i < n; i++) {
                if (rows[i].id != swapped.purchase_id)
                    continue;
                found = true;
                ok = rows[i].stage == STORE_PURCHASE_FAILED;
                ok = ok && strstr(rows[i].last_error, "HASH_MISMATCH") != NULL;
            }
            ok = ok && found;
        }
        if (ok) {
            /* A status call must not erase why it stopped. The stage may go
             * back to `paid` (the merchant WAS paid, so a retry is owed), but
             * the reason has to survive or the operator is told a purchase is
             * fine when its file was wrong. */
            step = "the reason survives a status call";
            struct store_buyer_state state;
            ok = store_buyer_refresh(datadir, swapped.purchase_id,
                                     &state).ok;
            ok = ok && strstr(state.purchase.last_error, "HASH_MISMATCH");
            ok = ok && state.purchase.stage == STORE_PURCHASE_PAID;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL (%s)\n", step);
            failures++;
        }
    }

    /* ── 8. Unknown ids are refused distinguishably ──────────────────── */
    printf("store_buyer: unknown product and purchase ids are named... ");
    {
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
            failures++;
        }
    }

    tsb_unwire_merchant();
    chain_params_select(CHAIN_MAIN);

    if (failures == 0) {
        char cmd[640];
        (void)snprintf(cmd, sizeof(cmd), "rm -rf %s", datadir);
        (void)system(cmd);
    } else {
        printf("store_buyer: debug datadir kept: %s\n", datadir);
    }
    return failures;
}
