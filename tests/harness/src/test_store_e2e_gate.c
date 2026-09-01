/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #5 CI gate: store end-to-end.
 *
 * This gate proves the shipped store flow survives the persistence boundary:
 *   1. browse the seeded store catalog and fetch a CSRF token
 *   2. create an order through the HTTP controller path
 *   3. persist a confirmed Sapling note for that order's payment address
 *   4. run store payment reconciliation
 *   5. reopen through fresh controller/model calls and assert:
 *      - order status advanced to TOKENS SENT
 *      - token balance was credited exactly once
 *      - token-gated access succeeds after reconciliation
 */

#include "test/test_core.h"
#include "controllers/store_controller.h"
#include "controllers/zslp_controller.h"
#include "models/block.h"
#include "models/store.h"
#include "models/store_blob.h"
#include "models/wallet_tx.h"
#include "crypto/sha3.h"

/* For the SHIELDED gate (test_store_e2e_shielded): a real Sapling output
 * built by the production payer path, ivk-decrypted by a merchant wallet. */
#include "core/uint256.h"
#include "consensus/upgrades.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"
#include "sapling/fr.h"
#include "sapling/sapling.h"
#include "script/sighashtype.h"
#include "sim/simnet.h"
#include "sim/simnet_sapling.h"
#include "support/cleanse.h"
#include "validation/main_constants.h"
#include "validation/sighash.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "config/runtime.h"
#include "net/puzzle.h"

#include <unistd.h>

/* Wire a seeded merchant wallet as the current runtime so the order-create
 * controller path (serve_create_order → zslp_generate_payment_address →
 * app_runtime_wallet) can mint a REAL, recoverable Sapling z-address. The
 * placeholder fallback was removed, so an order can no longer bind to a
 * synthetic address; without a seeded keystore the create would be refused
 * with a 503.
 *
 * The wallet is HEAP-allocated (struct wallet is far too large for the
 * stack — it would overflow an 8 MB default stack). `rt` is caller-owned and
 * must outlive the order create. On success returns the seeded wallet (the
 * caller owns it: app_runtime_set_current(NULL) + wallet_free + free); on
 * failure returns NULL and leaves the runtime untouched. */
static struct wallet *p11_wire_merchant_runtime(struct app_runtime_context *rt,
                                                uint8_t seed_byte)
{
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet),
                                  "p11_merchant_runtime_wallet");
    if (!w)
        LOG_NULL("store_e2e", "p11_wire_merchant_runtime: wallet alloc failed");
    wallet_init(w);
    uint8_t seed[32];
    memset(seed, seed_byte, sizeof(seed));
    if (!sapling_keystore_set_seed(&w->sapling_keys, seed)) {
        wallet_free(w);
        free(w);
        LOG_NULL("store_e2e", "p11_wire_merchant_runtime: set_seed failed");
    }
    memset(rt, 0, sizeof(*rt));
    rt->wallet = w;
    app_runtime_set_current(rt);
    return w;
}

/* The exact payload the buyer must receive on gated download. It embeds a
 * NUL byte (and non-ASCII bytes) so a passing assertion proves the
 * response path is binary-safe — not %.*s-truncated at the first NUL. */
static const uint8_t P11_5_BLOB[] = {
    'Z','C','L','2','3',' ','S','E','C','R','E','T',' ',
    'P','A','Y','L','O','A','D', 0x00, 0xDE, 0xAD, 0xBE, 0xEF
};

/* Store P11_5_BLOB and stamp it onto an existing product so a token-gated
 * download serves the real bytes. Returns false on any DB error. */
static bool p11_5_attach_blob_to_product(struct node_db *ndb,
                                         int64_t product_id)
{
    uint8_t hash[32];
    if (!db_store_blob_put(ndb, P11_5_BLOB, sizeof(P11_5_BLOB),
                           "engine/application/octet-stream", "secret.bin", hash))
        return false;
    return db_store_product_save_content(ndb, product_id, hash);
}

static void p11_5_setup_datadir(char *datadir, size_t datadir_size)
{
    test_make_tmpdir(datadir, datadir_size, "store_e2e", "gate");
}

static void p11_5_cleanup_datadir(const char *datadir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", datadir ? datadir : "");
    (void)system(cmd);
}

static bool p11_5_fetch_csrf_token(const char *datadir,
                                   int64_t product_id,
                                   char *out,
                                   size_t out_size)
{
    uint8_t page[16384];
    char path[64];
    const char *needle = "name='csrf_token' value='";
    const char *p;
    const char *end;
    size_t n;
    size_t token_len;

    if (!datadir || !out || out_size == 0)
        return false;

    snprintf(path, sizeof(path), "/store/product/%lld", (long long)product_id);
    n = store_handle_request("GET", path, NULL, 0,
                             page, sizeof(page), datadir);
    if (n == 0)
        return false;

    page[(n < sizeof(page)) ? n : (sizeof(page) - 1)] = '\0';
    p = strstr((const char *)page, needle);
    if (!p)
        return false;
    p += strlen(needle);
    end = strchr(p, '\'');
    if (!end)
        return false;

    token_len = (size_t)(end - p);
    if (token_len >= out_size)
        return false;

    memcpy(out, p, token_len);
    out[token_len] = '\0';
    return true;
}

/* Order-gate internals: defined in engine/controllers/src/store_controller_pow.c,
 * declared in the controller's private store_controller_internal.h. Forward
 * declared here, matching the pattern the store view already uses. */
void store_pow_reset_state(void);

/* Read one data-pow-* attribute value out of an already-fetched page. */
static bool p11_5_scrape_attr(const char *page, const char *attr,
                              char *out, size_t out_size)
{
    char needle[48];
    const char *p, *end;
    size_t len;

    snprintf(needle, sizeof(needle), "%s='", attr);
    p = strstr(page, needle);
    if (!p)
        return false;
    p += strlen(needle);
    end = strchr(p, '\'');
    if (!end)
        return false;
    len = (size_t)(end - p);
    if (len >= out_size)
        return false;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* Fetch the LIVE order-form puzzle challenge (serve_product_detail's
 * data-pow-seed / data-pow-token / data-pow-ts / data-pow-bits attributes)
 * and solve it via puzzle_solve — the same primitive
 * store_pow_verify_and_claim() checks with — so this gate's order-create
 * exercises the REAL gate, not a bypass. Formats the pow_ts / pow_nonce
 * values a real client would submit. One page fetch: each render is a
 * real challenge issuance, so the four attributes must come from one.
 *
 * The gate is reset first so the difficulty this gate has to solve does not
 * depend on how much order traffic earlier cases generated — the ramp is
 * proven in tests/harness/src/test_puzzle.c, not here. The challenge is issued
 * after the reset and solved at whatever difficulty it names. */
static bool p11_5_solve_store_pow(const char *datadir,
                                  int64_t product_id,
                                  char *pow_ts_out, size_t ts_max,
                                  char *pow_nonce_out, size_t nonce_max)
{
    uint8_t page[16384];
    char path[64];
    char seed_hex[65], token_hex[65], ts_str[32], bits_str[16];
    uint8_t seed[32], token[32];
    uint64_t nonce = 0;
    int64_t ts;
    int bits;
    size_t n;

    if (!datadir || !pow_ts_out || !pow_nonce_out)
        return false;

    store_pow_reset_state();
    snprintf(path, sizeof(path), "/store/product/%lld", (long long)product_id);
    n = store_handle_request("GET", path, NULL, 0,
                             page, sizeof(page), datadir);
    if (n == 0)
        return false;
    page[(n < sizeof(page)) ? n : (sizeof(page) - 1)] = '\0';

    if (!p11_5_scrape_attr((const char *)page, "data-pow-seed",
                           seed_hex, sizeof(seed_hex)) ||
        !p11_5_scrape_attr((const char *)page, "data-pow-token",
                           token_hex, sizeof(token_hex)) ||
        !p11_5_scrape_attr((const char *)page, "data-pow-ts",
                           ts_str, sizeof(ts_str)) ||
        !p11_5_scrape_attr((const char *)page, "data-pow-bits",
                           bits_str, sizeof(bits_str)))
        return false;
    if (strlen(seed_hex) != 64 || strlen(token_hex) != 64)
        return false;

    for (int i = 0; i < 32; i++) {
        char b[3] = { seed_hex[i * 2], seed_hex[i * 2 + 1], '\0' };
        seed[i] = (uint8_t)strtoul(b, NULL, 16);
        b[0] = token_hex[i * 2]; b[1] = token_hex[i * 2 + 1];
        token[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    ts = strtoll(ts_str, NULL, 10);
    bits = (int)strtol(bits_str, NULL, 10);
    if (bits <= 0)
        return false;
    /* Random start, matching the browser solver: a search from zero is a
     * pure function of (seed, token, ts), so two solves for one product in
     * one wall second would return the same nonce and the gate's
     * single-use ring would refuse the second. */
    if (!puzzle_solve_random(seed, token, ts, bits, &nonce))
        return false;
    snprintf(pow_ts_out, ts_max, "%lld", (long long)ts);
    snprintf(pow_nonce_out, nonce_max, "%llu", (unsigned long long)nonce);
    return true;
}

static bool p11_5_seed_tip_block(struct node_db *ndb, int height)
{
    struct db_block blk;
    static uint8_t solution[] = {0x51, 0x52};

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

static bool p11_5_seed_confirmed_note(struct node_db *ndb,
                                      const char *address,
                                      int64_t order_id,
                                      int64_t value,
                                      int block_height)
{
    struct db_sapling_note note;

    memset(&note, 0, sizeof(note));
    memset(note.txid, 0x61, sizeof(note.txid));
    memset(note.rcm, 0x62, sizeof(note.rcm));
    memset(note.ivk, 0x63, sizeof(note.ivk));
    memset(note.diversifier, 0x64, sizeof(note.diversifier));
    memset(note.pk_d, 0x65, sizeof(note.pk_d));
    memset(note.cm, 0x66, sizeof(note.cm));
    memset(note.nullifier, 0x67, sizeof(note.nullifier));
    note.output_index = 0;
    note.value = value;
    note.block_height = block_height;
    snprintf(note.address, sizeof(note.address), "%s", address);
    /* Carry the order-binding memo a real payer is now instructed to place
     * (store payment page) — so this gate exercises the LIVE memo-bound
     * reconcile (db_store_received_payment_for_memo), not the legacy
     * address-only finder. A 512-byte zero-padded memo with the token at
     * the head, mirroring a recovered Sapling note. */
    snprintf((char *)note.memo, sizeof(note.memo),
             "ZCL23ORDER:%lld", (long long)order_id);
    note.memo_len = ZC_MEMO_SIZE;
    return db_sapling_note_save(ndb, &note);
}

int test_store_e2e_gate(void)
{
    int failures = 0;

    printf("\n=== store e2e (MVP #5) ===\n");
    printf("store_e2e order -> confirmed payment -> token access... ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 to run deterministic gate)\n");
        return 0;
    }

    {
        char datadir[256];
        char dbpath[320];
        char csrf[64] = "";
        char body[256];
        uint8_t resp[16384];
        struct node_db ndb;
        struct db_store_order_summary summaries[8];
        struct db_store_order_view order;
        size_t n = 0;
        bool ok = true;
        int order_count;
        uint64_t bal;
        const char *fail_step = "setup";

        p11_5_setup_datadir(datadir, sizeof(datadir));
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
        memset(&ndb, 0, sizeof(ndb));
        memset(&order, 0, sizeof(order));

        /* Seeded merchant runtime so the order-create path mints a real
         * recoverable z-address (the placeholder fallback is gone).
         * Heap-allocated: struct wallet is too large for the stack. */
        struct app_runtime_context merchant_rt;
        struct wallet *merchant_w = p11_wire_merchant_runtime(&merchant_rt, 0x11);
        if (ok) fail_step = "wire merchant runtime";
        ok = merchant_w != NULL;

        if (ok) fail_step = "fetch csrf";
        ok = ok && p11_5_fetch_csrf_token(datadir, 1, csrf, sizeof(csrf));
        char pow_ts[32] = "", pow_nonce[32] = "";
        if (ok) fail_step = "solve pow";
        ok = ok && p11_5_solve_store_pow(datadir, 1, pow_ts, sizeof(pow_ts),
                                         pow_nonce, sizeof(pow_nonce));
        if (ok) {
            fail_step = "create order";
            snprintf(body, sizeof(body),
                     "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                     "&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
                     csrf, pow_ts, pow_nonce);
            n = store_handle_request("POST", "/store/orders",
                                     (const uint8_t *)body, strlen(body),
                                     resp, sizeof(resp), datadir);
            ok = n > 0;
            ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL;
            ok = ok && strstr((char *)resp, "Order #") != NULL;
        }

        if (ok) fail_step = "open after create";
        ok = ok && node_db_open(&ndb, dbpath);
        if (ok) {
            order_count = db_store_order_list_recent(&ndb, summaries,
                                                     sizeof(summaries) / sizeof(summaries[0]));
            if (ok) fail_step = "list recent";
            ok = order_count == 1;
            if (ok) fail_step = "load order";
            ok = ok && db_store_order_find_view(&ndb, summaries[0].id, &order);
            if (ok) fail_step = "pending status";
            ok = ok && order.status == STORE_ORDER_PENDING;
            if (ok) fail_step = "payment addr present";
            ok = ok && order.payment_addr[0] != '\0';
            if (ok) fail_step = "seed tip block";
            ok = ok && p11_5_seed_tip_block(&ndb, 100);
            if (ok) fail_step = "seed confirmed note";
            ok = ok && p11_5_seed_confirmed_note(&ndb, order.payment_addr,
                                                 summaries[0].id,
                                                 order.amount_zatoshi, 97);
            /* Attach the real file payload to product #1 (the seeded
             * ZCL23ACCESS product the order purchased) so the token-gated
             * download serves bytes instead of the HTML access page. */
            if (ok) fail_step = "attach product blob";
            ok = ok && p11_5_attach_blob_to_product(&ndb, 1);
            node_db_close(&ndb);
        }

        if (ok) fail_step = "process payments";
        if (ok)
            store_process_payments(datadir);

        memset(&ndb, 0, sizeof(ndb));
        if (ok) fail_step = "reopen after reconcile";
        ok = ok && node_db_open(&ndb, dbpath);
        if (ok) {
            memset(&order, 0, sizeof(order));
            if (ok) fail_step = "reload order";
            ok = db_store_order_find_view(&ndb, summaries[0].id, &order);
            if (ok) fail_step = "sent status";
            ok = ok && order.status == STORE_ORDER_SENT;
            if (ok) fail_step = "credited balance";
            bal = zslp_balance(datadir, "ZCL23ACCESS",
                               "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
            ok = ok && (bal == 10);
            node_db_close(&ndb);
        }

        if (ok) {
            fail_step = "status page";
            n = store_handle_request("GET", "/store/orders/1", NULL, 0,
                                     resp, sizeof(resp), datadir);
            ok = n > 0;
            ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL;
            ok = ok && strstr((char *)resp, "Tokens Sent") != NULL;
            ok = ok && strstr((char *)resp, order.payment_addr) != NULL;
        }

        if (ok) fail_step = "dedupe reconcile";
        if (ok)
            store_process_payments(datadir);

        if (ok) fail_step = "dedupe balance";
        bal = zslp_balance(datadir, "ZCL23ACCESS",
                           "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
        ok = ok && (bal == 10);

        if (ok) {
            fail_step = "token access serves real bytes";
            n = store_handle_request("GET",
                                     "/store/access?addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&token=ZCL23ACCESS",
                                     NULL, 0, resp, sizeof(resp), datadir);
            ok = n > 0;
            ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL;
            ok = ok && strstr((char *)resp,
                              "Content-Type: engine/application/octet-stream") != NULL;

            /* Locate the body after the header terminator. */
            const uint8_t *hdr_end = NULL;
            if (ok) {
                for (size_t i = 0; i + 4 <= n; i++) {
                    if (memcmp(resp + i, "\r\n\r\n", 4) == 0) {
                        hdr_end = resp + i + 4;
                        break;
                    }
                }
                ok = (hdr_end != NULL);
            }
            /* Buyer must receive the exact blob bytes, NUL included. */
            if (ok) {
                size_t body_len = n - (size_t)(hdr_end - resp);
                ok = (body_len == sizeof(P11_5_BLOB)) &&
                     (memcmp(hdr_end, P11_5_BLOB, sizeof(P11_5_BLOB)) == 0);
            }
            /* Defence-in-depth: served bytes re-hash to the stored hash. */
            if (ok) {
                uint8_t got_hash[32], want_hash[32];
                zcl_sha3_256(hdr_end, sizeof(P11_5_BLOB), got_hash);
                zcl_sha3_256(P11_5_BLOB, sizeof(P11_5_BLOB), want_hash);
                ok = (memcmp(got_hash, want_hash, 32) == 0);
            }
        }

        /* Regression (C5 collect wedge, second half): the canonical token
         * key is a 64-hex-char txid. A token[64] route buffer truncated it
         * to 63 chars (store_parse_query_field caps at out_max-1), the
         * validator rejected the prefix as a truncated-txid look-alike, and
         * the gate answered 400 to EVERY full-txid request — only the
         * 11-char ticker form below ever worked. Assert a full-txid request
         * now REACHES the gate: honest 403 balance denial, never the 400
         * "Invalid access request" parse failure. */
        if (ok) {
            fail_step = "full-txid token reaches the gate";
            n = store_handle_request("GET",
                "/store/access?addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&token=44A568A771FE2BE73B7181483387EC331501DBCE329615139"
                "AA1254FFECC7135",
                NULL, 0, resp, sizeof(resp), datadir);
            ok = n > 0;
            ok = ok && strstr((char *)resp, "Invalid access request") == NULL;
            ok = ok && strstr((char *)resp, "403 Forbidden") != NULL;
            ok = ok && strstr((char *)resp, "Access Denied") != NULL;
        }

        if (ok) {
            printf("OK (order=%lld payment=%s balance=10)\n",
                   (long long)summaries[0].id, order.payment_addr);
            p11_5_cleanup_datadir(datadir);
        } else {
            printf("FAIL (%s; debug datadir: %s)\n", fail_step, datadir);
            failures++;
        }

        app_runtime_set_current(NULL);
        if (merchant_w) {
            wallet_free(merchant_w);
            free(merchant_w);
        }
    }

    return failures;
}

/* ── MVP #5 SHIELDED gate: real ivk-decrypt + memo-bound credit ──────────────
 *
 * The gate above proves the store PLUMBING but fabricates the payment (a note
 * with a placeholder ivk = memset(0x63), matched by address string). This gate
 * proves the cryptographic heart C5 actually claims ("buyer pays SHIELDED"):
 * a REAL Sapling output is encrypted to a merchant wallet's address carrying an
 * order-binding memo, the merchant wallet's ivk-DECRYPTS it (the production
 * receive path wallet_try_sapling_decrypt — params-free, see
 * test_shielded_receive_slice), and the order is credited ONLY via the recovered
 * memo (db_store_received_payment_for_memo). It is non-gameable: the persisted
 * note's value+memo come from the AEAD decrypt (not fabricated), and a real
 * payment whose memo names a DIFFERENT order does NOT credit this order — which
 * the legacy address+amount finder (db_store_received_payment) wrongly would. */

/* Build a single-output shielded tx paying (to_d,to_pk_d) `value`, with memo
 * "ZCL23ORDER:<order_id>". Uses the production payer path
 * (sapling_build_output_description) — proof degrades to zero with no params,
 * so the cv/cm/epk/enc_ciphertext are real AEAD over the recipient's PUBLIC
 * address material. Mirrors test_shielded_receive_slice's builder. */
static bool p11_6_build_paid_output_tx(struct transaction *tx,
                                       const uint8_t to_d[11],
                                       const uint8_t to_pk_d[32],
                                       uint64_t value,
                                       int64_t order_id,
                                       uint8_t output_rcv[32])
{
    uint8_t ovk[32];
    memset(ovk, 0x5a, 32);

    uint8_t memo[ZC_MEMO_SIZE];
    memset(memo, 0, sizeof(memo));
    snprintf((char *)memo, sizeof(memo), "ZCL23ORDER:%lld", (long long)order_id);

    uint8_t od_cv[32], od_cm[32], od_epk[32];
    uint8_t od_enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    uint8_t od_out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    uint8_t od_proof[GROTH_PROOF_SIZE];
    memset(od_cv, 0, sizeof(od_cv));
    memset(od_cm, 0, sizeof(od_cm));
    memset(od_epk, 0, sizeof(od_epk));
    memset(od_enc, 0, sizeof(od_enc));
    memset(od_out, 0, sizeof(od_out));
    memset(od_proof, 0, sizeof(od_proof));

    if (!sapling_build_output_description(ovk, to_d, to_pk_d, value, memo,
                                          od_cv, od_cm, od_epk,
                                          od_enc, od_out, od_proof,
                                          output_rcv))
        return false;

    transaction_init(tx);
    tx->version = SAPLING_TX_VERSION;
    tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->value_balance = -(int64_t)value;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "p11_6_output_desc");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;

    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, od_cv, 32);
    memcpy(od->cm.data, od_cm, 32);
    memcpy(od->ephemeral_key.data, od_epk, 32);
    memcpy(od->enc_ciphertext, od_enc, ZC_SAPLING_ENCCIPHERTEXT_SIZE);
    memcpy(od->out_ciphertext, od_out, ZC_SAPLING_OUTCIPHERTEXT_SIZE);
    memcpy(od->zkproof, od_proof, GROTH_PROOF_SIZE);
    return true;
}

static bool p11_6_bind_transparent_input(
    struct transaction *tx, const struct uint256 *funding_txid,
    const uint8_t output_rcv[32], uint32_t branch_id)
{
    if (!tx || !funding_txid || !output_rcv ||
        !transaction_alloc(tx, 1, 0))
        return false;
    tx->vin[0].prevout.hash = *funding_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    {
        static const uint8_t placeholder_sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, placeholder_sig,
                   sizeof(placeholder_sig));
    }

    struct precomputed_tx_data txdata;
    precompute_tx_data(tx, &txdata);
    struct script empty;
    script_init(&empty);
    struct sighash_type hash_type = {.raw = SIGHASH_ALL};
    struct uint256 sighash;
    if (!signature_hash(&empty, tx, NOT_AN_INPUT, hash_type, 0,
                        branch_id, &txdata, &sighash))
        return false;

    struct fs rcv, neg, bsk;
    fs_zero(&bsk);
    if (!fs_from_bytes(&rcv, output_rcv))
        return false;
    fs_neg(&neg, &rcv);
    fs_add(&bsk, &bsk, &neg);
    uint8_t bsk_bytes[32];
    fs_to_bytes(bsk_bytes, &bsk);
    bool bound = sapling_create_binding_sig(
        bsk_bytes, sighash.data, tx->binding_sig);
    memory_cleanse(bsk_bytes, sizeof(bsk_bytes));
    memory_cleanse(&bsk, sizeof(bsk));
    if (bound)
        transaction_compute_hash(tx);
    return bound;
}

/* Persist `rn` (a note RECOVERED by ivk-decrypt) into wallet_sapling_notes at
 * `pay_addr`, confirmed at `block_height`. Every consensus-relevant field comes
 * from the decrypt; only address (string column) and block height are set here. */
static bool p11_6_persist_recovered_note(struct node_db *ndb,
                                         const struct sapling_received_note *rn,
                                         const struct uint256 *txid,
                                         const char *pay_addr,
                                         int block_height)
{
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    memcpy(note.txid, txid->data, 32);
    note.output_index = rn->output_index;
    note.value = (int64_t)rn->value;
    memcpy(note.rcm, rn->rcm, 32);
    memcpy(note.memo, rn->memo, ZC_MEMO_SIZE);
    note.memo_len = ZC_MEMO_SIZE;
    memcpy(note.ivk, rn->ivk, 32);
    memcpy(note.diversifier, rn->diversifier, 11);
    memcpy(note.pk_d, rn->pk_d, 32);
    memcpy(note.cm, rn->cm, 32);
    memcpy(note.nullifier, rn->nf, 32);
    note.block_height = block_height;
    snprintf(note.address, sizeof(note.address), "%s", pay_addr);
    return db_sapling_note_save(ndb, &note);
}

int test_store_e2e_shielded(void);
int test_store_e2e_shielded(void)
{
    int failures = 0;

    printf("\n=== store e2e SHIELDED (MVP #5: real ivk-decrypt + memo-bound) ===\n");
    printf("store_e2e_shielded order -> REAL sapling note ivk-decrypt -> "
           "memo-bound credit... ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 to run deterministic gate)\n");
        return 0;
    }

    char datadir[256];
    char dbpath[320];
    char csrf[64] = "";
    char body[256];
    uint8_t resp[16384];
    struct node_db ndb;
    struct db_store_order_summary summaries[8];
    struct db_store_order_view order;
    struct wallet *w = NULL;
    struct transaction tx, tx2;
    bool tx_built = false, tx2_built = false;
    struct simnet sim;
    bool sim_ready = false;
    int payment_height = 0;
    bool ok = true;
    size_t n = 0;
    int order_count = 0;
    int64_t order_id = 0, amount = 0;
    int64_t other_order = 0;
    const char *fail_step = "setup";
    uint8_t to_d[ZC_DIVERSIFIER_SIZE];
    uint8_t to_pk_d[32];

    test_make_tmpdir(datadir, sizeof(datadir), "store_e2e", "shielded");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    memset(&ndb, 0, sizeof(ndb));
    memset(&order, 0, sizeof(order));

    /* Seeded merchant runtime so the order-create controller path can mint a
     * real recoverable z-address (the placeholder fallback is gone). This is
     * a separate keystore from the decrypt wallet `w` built below; the gate's
     * crypto binding is via the memo, not the minted address value.
     * Heap-allocated: struct wallet is too large for the stack. */
    struct app_runtime_context merchant_rt;
    struct wallet *merchant_w = p11_wire_merchant_runtime(&merchant_rt, 0x11);
    if (ok) fail_step = "wire merchant runtime";
    ok = merchant_w != NULL;

    /* (1) Create an order through the HTTP controller (same as the gate). */
    if (ok) fail_step = "fetch csrf";
    ok = ok && p11_5_fetch_csrf_token(datadir, 1, csrf, sizeof(csrf));
    char pow_ts[32] = "", pow_nonce[32] = "";
    if (ok) fail_step = "solve pow";
    ok = ok && p11_5_solve_store_pow(datadir, 1, pow_ts, sizeof(pow_ts),
                                     pow_nonce, sizeof(pow_nonce));
    if (ok) {
        fail_step = "create order";
        snprintf(body, sizeof(body),
                 "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                 "&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
                 csrf, pow_ts, pow_nonce);
        n = store_handle_request("POST", "/store/orders",
                                 (const uint8_t *)body, strlen(body),
                                 resp, sizeof(resp), datadir);
        ok = n > 0 && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
             strstr((char *)resp, "Order #") != NULL;
    }
    ok = ok && node_db_open(&ndb, dbpath);
    if (ok) {
        order_count = db_store_order_list_recent(&ndb, summaries,
                                                 sizeof(summaries) / sizeof(summaries[0]));
        fail_step = "list recent";
        ok = order_count == 1;
        fail_step = "load order";
        ok = ok && db_store_order_find_view(&ndb, summaries[0].id, &order);
        fail_step = "payment addr present";
        ok = ok && order.payment_addr[0] != '\0';
        if (ok) {
            order_id = summaries[0].id;
            amount = order.amount_zatoshi;
            other_order = order_id + 777;
        }
        fail_step = "order has positive amount";
        ok = ok && amount > 0;
    }

    /* (2) Merchant wallet derives the address whose ivk will decrypt payments. */
    if (ok) {
        w = zcl_calloc(1, sizeof(struct wallet), "p11_6_wallet");
        fail_step = "merchant wallet alloc";
        ok = w != NULL;
    }
    if (ok) {
        wallet_init(w);
        uint8_t seed[32];
        memset(seed, 0x11, 32);
        fail_step = "merchant sapling seed";
        ok = sapling_keystore_set_seed(&w->sapling_keys, seed);
        fail_step = "merchant sapling address";
        ok = ok && sapling_keystore_new_address(&w->sapling_keys, to_d, to_pk_d);
    }

    /* A real isolated transparent input funds the shielded order payment.
     * Proof verification remains at the same deferred boundary used by the
     * Sapling simnet harness, while note encryption, binding signature,
     * commitment-tree application, and connect_block are all production. */
    struct uint256 funding_txid;
    int payment_target = 0;
    if (ok) {
        fail_step = "shielded simnet initialize";
        ok = simnet_init(&sim);
        sim_ready = ok;
    }
    if (ok) {
        enum { P11_SAPLING_HEIGHT = 100 };
        simnet_activate_sapling_at(&sim, P11_SAPLING_HEIGHT);
        fail_step = "enable shielded commitment tree";
        ok = simnet_enable_sapling_tree(&sim);
        simnet_enable_contextual_check(&sim, false);
        struct script funding_script;
        script_init(&funding_script);
        static const uint8_t p2pkh_prefix[] = {0x76, 0xa9, 0x14};
        script_set(&funding_script, p2pkh_prefix, sizeof(p2pkh_prefix));
        int funding_height = simnet_tip_height(&sim) + 1;
        fail_step = "mint and mature shielded payment funding";
        ok = ok && simnet_mint_coinbase_to(
            &sim, &funding_script, amount + 10000, &funding_txid);
        ok = ok && simnet_mint_to_height(
            &sim, funding_height + COINBASE_MATURITY);
        payment_target = simnet_tip_height(&sim) + 1;
    }

    /* (3) REAL payment: build a Sapling output to the merchant carrying the
     * order memo, ivk-DECRYPT it, and persist the RECOVERED note. */
    uint8_t payment_rcv[32] = {0};
    if (ok) {
        tx_built = p11_6_build_paid_output_tx(&tx, to_d, to_pk_d,
                                              (uint64_t)amount, order_id,
                                              payment_rcv);
        fail_step = "build paid output (params-free)";
        ok = tx_built;
    }
    if (ok) {
        uint32_t branch_id = consensus_current_epoch_branch_id(
            payment_target, &sim.params.consensus);
        fail_step = "bind transparent funding input to shielded output";
        ok = p11_6_bind_transparent_input(
            &tx, &funding_txid, payment_rcv, branch_id);
    }
    struct uint256 txid;
    txid = tx_built ? tx.hash : (struct uint256){0};
    if (ok) {
        int found = wallet_try_sapling_decrypt(w, &tx, &txid);
        fail_step = "merchant ivk-decrypts the paying note";
        ok = found == 1 && w->num_sapling_notes == 1;
    }
    if (ok) {
        struct output_description *shielded_owned = tx.v_shielded_output;
        fail_step = "exact memo-bound payment passes connect_block";
        ok = simnet_mint_txs(&sim, &tx, 1);
        free(shielded_owned);
        tx_built = false; /* simnet consumed the ordinary tx allocations */
        payment_height = simnet_tip_height(&sim);
        ok = ok && payment_height == payment_target &&
             simnet_sapling_tree_size(&sim) == 1 &&
             !simnet_coin_value(&sim, &funding_txid, 0, NULL);
    }
    if (ok) {
        fail_step = "seed three-confirmation projection tip";
        ok = p11_5_seed_tip_block(&ndb, payment_height + 3);
    }
    if (ok) {
        const struct sapling_received_note *rn = &w->sapling_notes[0];
        char expect[64];
        int el = snprintf(expect, sizeof(expect), "ZCL23ORDER:%lld",
                          (long long)order_id);
        fail_step = "recovered value == order amount";
        ok = rn->value == (uint64_t)amount;
        fail_step = "recovered memo binds the order";
        ok = ok && el > 0 && (size_t)el < sizeof(expect) &&
             memcmp(rn->memo, expect, (size_t)el) == 0 && rn->memo[el] == '\0';
        fail_step = "persist recovered note";
        ok = ok && p11_6_persist_recovered_note(&ndb, rn, &txid,
                                                order.payment_addr,
                                                payment_height);
    }

    /* (4) The memo-bound finder credits this order; the legacy finder agrees
     * (one note, one order — they cannot diverge yet). */
    if (ok) {
        fail_step = "memo-bound finder credits the order";
        ok = db_store_received_payment_for_memo(&ndb, order.payment_addr,
                                                order_id,
                                                payment_height) == amount;
        fail_step = "legacy address+amount finder also sees the note";
        ok = ok && db_store_received_payment(
            &ndb, order.payment_addr, payment_height) == amount;
    }

    /* (5) NEGATIVE: a REAL payment to the SAME address whose memo names a
     * DIFFERENT order must NOT credit this order — yet the legacy address+amount
     * finder wrongly counts both. This is the hole the memo bind closes. */
    if (ok) {
        tx2_built = p11_6_build_paid_output_tx(&tx2, to_d, to_pk_d,
                                               (uint64_t)amount, other_order,
                                               NULL);
        fail_step = "build other-order payment";
        ok = tx2_built;
    }
    struct uint256 txid2;
    memset(&txid2, 0, sizeof(txid2));
    txid2.data[0] = 0x5D;
    txid2.data[1] = (uint8_t)(other_order & 0xff);
    if (ok) {
        int found2 = wallet_try_sapling_decrypt(w, &tx2, &txid2);
        fail_step = "second payment ivk-decrypts";
        ok = found2 == 1 && w->num_sapling_notes == 2;
    }
    if (ok) {
        fail_step = "persist second recovered note";
        ok = p11_6_persist_recovered_note(&ndb, &w->sapling_notes[1], &txid2,
                                          order.payment_addr,
                                          payment_height);
    }
    if (ok) {
        fail_step = "memo finder still credits ONLY this order's amount";
        ok = db_store_received_payment_for_memo(&ndb, order.payment_addr,
                                                order_id,
                                                payment_height) == amount;
        fail_step = "memo finder credits the OTHER order separately";
        ok = ok && db_store_received_payment_for_memo(&ndb, order.payment_addr,
                                                      other_order,
                                                      payment_height) == amount;
        fail_step = "legacy finder over-counts both (the closed hole)";
        ok = ok && db_store_received_payment(
            &ndb, order.payment_addr, payment_height) == amount * 2;
    }

    if (ndb.open)
        node_db_close(&ndb);
    if (tx_built)
        transaction_free(&tx);
    if (tx2_built)
        transaction_free(&tx2);
    if (sim_ready)
        simnet_free(&sim);
    if (w) {
        wallet_free(w);
        free(w);
    }

    app_runtime_set_current(NULL);
    if (merchant_w) {
        wallet_free(merchant_w);
        free(merchant_w);
    }

    if (ok) {
        printf("OK (order=%lld payment=%s amount=%lld, ivk-decrypted, memo-bound)\n",
               (long long)order_id, order.payment_addr, (long long)amount);
        p11_5_cleanup_datadir(datadir);
    } else {
        printf("FAIL (%s; debug datadir: %s)\n", fail_step, datadir);
        failures++;
    }

    return failures;
}
