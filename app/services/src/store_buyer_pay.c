/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BUYER service, part 2 of 2: paying a placed order, polling the
 * merchant's verdict on it, and collecting the bytes. Browsing and ordering
 * live in store_buyer.c. See services/store_buyer.h for what this is.
 *
 * The two upward includes below are the shape of the thing on purpose: a
 * buyer is a CLIENT of the store's request handler and of the node's spend
 * guard. Reaching around either — writing the order row directly, or paying
 * without asking the guard — is exactly what this service must not do. */

#include "services/store_buyer_internal.h"

#include "controllers/store_controller.h" // shape-layer-ok:buyer-is-a-store-client
#include "controllers/sovereignty_controller.h" // shape-layer-ok:buyer-asks-the-spend-guard
#include "controllers/wallet_shielded_controller.h" // shape-layer-ok:buyer-classifies-an-address
#include "chain/chainparams.h"
#include "config/runtime.h"
#include "crypto/sha3.h"
#include "models/store.h"
#include "platform/private_file.h"
#include "sapling/sapling_prover.h"
#include "util/safe_alloc.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── shared preconditions ───────────────────────────────────────────── */

/* Refuse mainnet. A scripted buyer that mints orders and submits shielded
 * sends is a development and proof surface, and the cost of it running
 * against the real chain is real value leaving a wallet with no human in the
 * loop. This is checked before any payment is prepared — and since
 * store_buyer_prepare_payment is the only path from this service to
 * z_sendmany, there is nothing to route around. Browsing, ordering and
 * collecting move no value and are deliberately not gated: gating them would
 * only stop an operator seeing their own store. */
static bool sb_network_allows_spend(void)
{
    const struct chain_params *cp = chain_params_get();
    return cp && strcmp(cp->strNetworkID, "main") != 0;
}

/* Whether a refusal means "stuck" (retrying cannot change the answer without
 * an operator changing something first) or "not yet".
 *
 * Static on purpose, and deliberately not in the header: a "not yet" must
 * NEVER bury the row in FAILED. A purchase that is paid but not collected —
 * no prover, no funds, guard closed, merchant has not credited yet — is
 * still resumable, and losing its stage is the exact outcome this service
 * exists to prevent. */
static bool sb_status_is_terminal(int why)
{
    switch ((enum store_buyer_status)why) {
    case STORE_BUYER_ERR_HASH_MISMATCH:
    case STORE_BUYER_ERR_DELIVERY_FAILED:
    case STORE_BUYER_ERR_UNKNOWN_PRODUCT:
        return true;
    default:
        return false;
    }
}

/* A purchase records the address under the chain that minted the order. Test
 * and recovery callers can inspect that durable row after selecting another
 * chain, so the active-HRP router alone is not enough for preflight: it would
 * mistake a real mainnet Sapling address for transparent on regtest and skip
 * the proving-backend refusal. Decoding validates the Bech32 payload while
 * deliberately ignoring HRP; here that is the wanted, read-only historical
 * classification. The actual send still uses wallet_addr_is_sapling() against
 * the active chain and therefore cannot route a cross-chain address to spend. */
static bool sb_purchase_addr_is_sapling(const char *addr)
{
    uint8_t diversifier[11], pk_d[32];
    return wallet_addr_is_sapling(addr) ||
           sapling_decode_payment_address(addr, diversifier, pk_d);
}

/* ── pay ────────────────────────────────────────────────────────────── */

struct zcl_result store_buyer_prepare_payment(const char *datadir,
                                              int64_t purchase_id,
                                              const char *from_addr,
                                              struct store_buyer_payment *out)
{
    struct node_db ndb;
    struct db_store_purchase purchase;
    struct zcl_result r;

    if (!datadir || !from_addr || !from_addr[0] || !out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    memset(out, 0, sizeof(*out));
    if (!sb_network_allows_spend())
        return SB_FAIL(STORE_BUYER_ERR_MAINNET_REFUSED);

    r = sb_open_db(datadir, &ndb, "store_buyer.prepare_payment");
    if (!r.ok)
        return r;
    r = sb_load_purchase(&ndb, purchase_id, &purchase);
    node_db_close(&ndb);
    if (!r.ok)
        return r;

    if (purchase.stage == STORE_PURCHASE_PAYING ||
        purchase.stage == STORE_PURCHASE_PAID ||
        purchase.stage == STORE_PURCHASE_DELIVERED)
        return SB_FAILF(STORE_BUYER_ERR_ALREADY_PAID,
                        "purchase %lld is already at stage %s",
                        (long long)purchase_id,
                        store_purchase_stage_name(purchase.stage));

    /* No proving backend ⇒ no shielded output can be built at all. Refuse
     * here, loudly and by name, rather than letting the send fail hundreds
     * of lines later inside coin selection — and never silently no-op.
     *
     * Only a SHIELDED order address needs it. A transparent order is paid by
     * an ordinary signed t->t spend with no zk-proof anywhere in it, so
     * demanding a prover for one would refuse a payment this build can
     * actually make. The order's address type is the merchant's choice, not
     * the buyer's, so this asks the address rather than a flag. */
    if (sb_purchase_addr_is_sapling(purchase.payment_addr) &&
        !zclassic_sapling_prover_is_ready()) {
        LOG_WARN(SB_TAG, "pay: refusing purchase %lld — no Sapling proving "
                 "backend (backend=%s status=%s); native C23 proving remains "
                 "disabled until its full self-test passes",
                 (long long)purchase_id, zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        return SB_FAILF(STORE_BUYER_ERR_PROVER_UNAVAILABLE,
                        "no Sapling proving backend (backend=%s status=%s); "
                        "native C23 Spend, Output, and binding proofs must "
                        "pass the full self-test",
                        zclassic_sapling_prover_backend(),
                        zclassic_sapling_prover_status());
    }

    /* The node's own spend guard. Never weakened here: if it refuses, the
     * purchase stays unpaid and says so. */
    {
        char reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", reason, sizeof(reason))) {
            LOG_WARN(SB_TAG, "pay: refusing purchase %lld — spend guard: %s",
                     (long long)purchase_id, reason);
            return SB_FAILF(STORE_BUYER_ERR_SPEND_REFUSED,
                            "the node refuses to spend from this tip: %s",
                            reason[0] ? reason : "(no reason given)");
        }
    }

    /* Whole-wallet floor. Coin selection is z_sendmany's job; this only
     * refuses the case where no selection could possibly succeed. */
    {
        const struct wallet *w = app_runtime_wallet();
        if (w) {
            /* Which balance pool the FUNDING address draws on (t->z and z->z
             * are both allowed; this only picks the floor to check). */
            int64_t pool = wallet_addr_is_sapling(from_addr)
                               ? wallet_get_sapling_balance(w)
                               : wallet_get_balance(w);
            if (pool < purchase.amount_zatoshi) {
                LOG_WARN(SB_TAG, "pay: refusing purchase %lld — wallet holds "
                         "%lld zatoshi, order needs %lld",
                         (long long)purchase_id, (long long)pool,
                         (long long)purchase.amount_zatoshi);
                return SB_FAILF(STORE_BUYER_ERR_INSUFFICIENT_FUNDS,
                                "wallet holds %lld zatoshi, order %lld needs "
                                "%lld", (long long)pool,
                                (long long)purchase.order_id,
                                (long long)purchase.amount_zatoshi);
            }
        }
    }

    (void)snprintf(out->from_addr, sizeof(out->from_addr), "%s", from_addr);
    (void)snprintf(out->to_addr, sizeof(out->to_addr), "%s",
                   purchase.payment_addr);
    out->amount_zatoshi = purchase.amount_zatoshi;

    /* Hex-encode the memo and append an explicit 00 terminator. The
     * merchant credits an order only when the byte after
     * "ZCL23ORDER:<id>" is NUL or ';' — a memo that merely starts with the
     * token and runs into padding is not credited. Emitting the terminator
     * here means the buyer never depends on which padding byte the sender
     * happens to use. */
    {
        size_t memo_len = strlen(purchase.memo);
        size_t need = memo_len * 2 + 2 + 1;
        if (need > sizeof(out->memo_hex))
            return SB_FAILF(STORE_BUYER_ERR_INTERNAL,
                            "memo for purchase %lld does not fit the hex "
                            "buffer (%zu bytes needed, %zu available)",
                            (long long)purchase_id, need,
                            sizeof(out->memo_hex));
        for (size_t i = 0; i < memo_len; i++)
            (void)snprintf(out->memo_hex + i * 2, 3, "%02x",
                           (unsigned char)purchase.memo[i]);
        (void)snprintf(out->memo_hex + memo_len * 2, 3, "00");
    }
    return ZCL_OK;
}

struct zcl_result store_buyer_record_payment(const char *datadir,
                                             int64_t purchase_id,
                                             const char *operation_id)
{
    struct node_db ndb;
    struct db_store_purchase purchase;
    struct zcl_result r;
    bool ok;

    if (!datadir)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    r = sb_open_db(datadir, &ndb, "store_buyer.record_payment");
    if (!r.ok)
        return r;
    r = sb_load_purchase(&ndb, purchase_id, &purchase);
    if (!r.ok) {
        node_db_close(&ndb);
        return r;
    }
    purchase.stage = STORE_PURCHASE_PAYING;
    purchase.last_error[0] = '\0';
    (void)snprintf(purchase.operation_id, sizeof(purchase.operation_id), "%s",
                   operation_id ? operation_id : "");
    ok = db_store_purchase_save(&ndb, &purchase);
    node_db_close(&ndb);
    if (!ok) {
        LOG_WARN(SB_TAG, "pay: payment submitted for purchase %lld but the "
                 "row would not persist — operation id %s",
                 (long long)purchase_id,
                 operation_id && operation_id[0] ? operation_id : "(none)");
        return SB_FAILF(STORE_BUYER_ERR_DB,
                        "payment for purchase %lld was submitted but the "
                        "purchase row would not persist — operation id %s",
                        (long long)purchase_id,
                        operation_id && operation_id[0] ? operation_id
                                                        : "(none)");
    }
    return ZCL_OK;
}

struct zcl_result store_buyer_fail(const char *datadir, int64_t purchase_id,
                                   int why, const char *detail)
{
    struct node_db ndb;
    struct db_store_purchase purchase;
    struct zcl_result r;
    bool ok;

    if (!datadir)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    r = sb_open_db(datadir, &ndb, "store_buyer.fail");
    if (!r.ok)
        return r;
    r = sb_load_purchase(&ndb, purchase_id, &purchase);
    if (!r.ok) {
        node_db_close(&ndb);
        return r;
    }
    (void)snprintf(purchase.last_error, sizeof(purchase.last_error), "%s: %s",
                   store_buyer_status_code(why),
                   detail && detail[0] ? detail
                                       : store_buyer_status_message(why));
    if (sb_status_is_terminal(why))
        purchase.stage = STORE_PURCHASE_FAILED;
    ok = db_store_purchase_save(&ndb, &purchase);
    node_db_close(&ndb);
    if (!ok)
        return SB_FAILF(STORE_BUYER_ERR_DB,
                        "could not record the failure reason on purchase %lld",
                        (long long)purchase_id);
    return ZCL_OK;
}

/* ── poll ───────────────────────────────────────────────────────────── */

struct zcl_result store_buyer_refresh(const char *datadir,
                                      int64_t purchase_id,
                                      struct store_buyer_state *out)
{
    struct node_db ndb;
    struct db_store_purchase purchase;
    struct db_store_order_view order_view;
    struct zcl_result r;

    if (!datadir || !out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    memset(out, 0, sizeof(*out));
    r = sb_open_db(datadir, &ndb, "store_buyer.refresh");
    if (!r.ok)
        return r;
    r = sb_load_purchase(&ndb, purchase_id, &purchase);
    if (!r.ok) {
        node_db_close(&ndb);
        return r;
    }

    out->tip_height = db_store_chain_tip_height(&ndb);
    out->merchant_order_found =
        db_store_order_find_view(&ndb, purchase.order_id, &order_view);
    if (out->merchant_order_found)
        out->merchant_order_status = order_view.status;

    /* The SAME reconcile the merchant's payment processor uses — one function,
     * so a buyer can never believe an order paid that the merchant will never
     * credit. It picks the memo bind or the address bind from the order
     * address type; there is deliberately no second payment finder here.
     * Confirmation depth mirrors the merchant's (tip - 3). */
    out->confirmed_zatoshi = store_confirmed_payment(
        &ndb, purchase.payment_addr, purchase.order_id, out->tip_height - 3);

    /* Advance the stage on the merchant's verdict, never on our own opinion
     * of the payment: STORE_ORDER_SENT means the merchant credited the order
     * AND minted the access tokens, which is exactly the precondition the
     * gated download checks. */
    if (purchase.stage != STORE_PURCHASE_DELIVERED &&
        out->merchant_order_found &&
        order_view.status == STORE_ORDER_SENT) {
        if (purchase.stage != STORE_PURCHASE_PAID) {
            /* Advance the stage, but NEVER clear last_error. A collect that
             * refused — a hash mismatch, an unwritable path — parks the row
             * at FAILED with the reason on it, and the merchant's verdict is
             * still SENT, so this is exactly the path that would erase it.
             * The stage going back to `paid` is right (the merchant WAS paid,
             * so a retry is owed); telling the operator the purchase is fine
             * when its bytes were wrong is not. */
            purchase.stage = STORE_PURCHASE_PAID;
            if (order_view.payment_txid[0])
                (void)snprintf(purchase.operation_id,
                               sizeof(purchase.operation_id), "%s",
                               order_view.payment_txid);
            (void)db_store_purchase_save(&ndb, &purchase);
        }
    }

    out->purchase = purchase;
    out->ready_to_collect = (purchase.stage == STORE_PURCHASE_PAID);
    node_db_close(&ndb);
    return ZCL_OK;
}

struct zcl_result store_buyer_list(const char *datadir,
                                   struct db_store_purchase *out,
                                   size_t max, size_t *n_out)
{
    struct node_db ndb;
    struct zcl_result r;
    int count;

    if (n_out)
        *n_out = 0;
    if (!datadir || !out || max == 0 || !n_out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    r = sb_open_db(datadir, &ndb, "store_buyer.list");
    if (!r.ok)
        return r;
    count = db_store_purchase_list(&ndb, out, max);
    node_db_close(&ndb);
    *n_out = (size_t)(count > 0 ? count : 0);
    return ZCL_OK;
}

/* ── collect ────────────────────────────────────────────────────────── */

/* Locate the body of an HTTP response already in memory. Returns NULL when
 * the response carries no header terminator (which is itself a refusal —
 * we never guess where a body starts). */
static const uint8_t *sb_http_body(const uint8_t *resp, size_t n,
                                   size_t *body_len)
{
    for (size_t i = 0; i + 4 <= n; i++) {
        if (memcmp(resp + i, "\r\n\r\n", 4) == 0) {
            *body_len = n - (i + 4);
            return resp + i + 4;
        }
    }
    return NULL;
}

/* Write `len` bytes to `path` atomically: a sibling temporary in the same
 * directory, fsync, rename. A caller that dies mid-write leaves the target
 * either absent or complete — never a truncated file that hashes to nothing
 * and looks like a delivered purchase. On any failure the temporary is
 * removed, so a failed collect leaves no debris either. */
static bool sb_write_atomic(const char *path, const uint8_t *data, size_t len)
{
    errno = 0;
    char installed[STORE_PURCHASE_PATH_MAX + 1];
    char parent[STORE_PURCHASE_PATH_MAX + 1];
    if (!platform_private_destination_resolve(
            path, installed, sizeof(installed), parent, sizeof(parent))) {
        errno = EINVAL;
        return false;
    }

    char tmp[STORE_PURCHASE_PATH_MAX + 16];
    int n = snprintf(tmp, sizeof(tmp), "%s.part", installed);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return false;
    }

    if (!platform_private_file_unlink_missing_ok(tmp)) {
        if (errno == 0) errno = EIO;
        return false;
    }

    struct platform_private_file staging;
    platform_private_file_init(&staging);
    if (!platform_private_file_create(tmp, &staging)) {
        if (errno == 0) errno = EIO;
        return false;
    }

    if ((len != 0 &&
         !platform_private_file_write_at(&staging, data, len, 0)) ||
        !platform_private_file_flush(&staging)) {
        int saved_errno = errno ? errno : EIO;
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        errno = saved_errno;
        return false;
    }
    if (!platform_private_file_replace(&staging, tmp, installed)) {
        int saved_errno = errno ? errno : EIO;
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        errno = saved_errno;
        return false;
    }
    if (!platform_private_parent_flush(parent)) {
        if (errno == 0) errno = EIO;
        return false;
    }
    return true;
}

struct zcl_result store_buyer_collect(const char *datadir,
                                      int64_t purchase_id,
                                      const char *output_path,
                                      struct store_buyer_delivery *out)
{
    struct node_db ndb;
    struct db_store_purchase purchase;
    struct zcl_result r;
    uint8_t *resp = NULL;
    uint8_t got[32];
    const uint8_t *body;
    size_t body_len = 0;
    size_t n;
    char path[512];
    char target[STORE_PURCHASE_PATH_MAX + 1];
    const char *want_path;

    if (!datadir || !out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    memset(out, 0, sizeof(*out));

    /* Re-poll the merchant first. This is what makes a collect a RESUME: a
     * node that paid, then restarted, comes back with the row still at
     * "paying" — the credit happened while it was gone. Asking the merchant
     * before refusing means the operator does not have to know to run a
     * status call first. */
    {
        struct store_buyer_state state;
        r = store_buyer_refresh(datadir, purchase_id, &state);
        if (!r.ok)
            return r;
    }

    r = sb_open_db(datadir, &ndb, "store_buyer.collect");
    if (!r.ok)
        return r;
    r = sb_load_purchase(&ndb, purchase_id, &purchase);
    node_db_close(&ndb);
    if (!r.ok)
        return r;

    if (purchase.stage != STORE_PURCHASE_PAID &&
        purchase.stage != STORE_PURCHASE_DELIVERED)
        return SB_FAILF(STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED,
                        "purchase %lld is at stage %s; the merchant has not "
                        "credited order %lld yet", (long long)purchase_id,
                        store_purchase_stage_name(purchase.stage),
                        (long long)purchase.order_id);

    want_path = (output_path && output_path[0]) ? output_path
                                                : purchase.output_path;
    if (!want_path || !want_path[0])
        return SB_FAILF(STORE_BUYER_ERR_ARGS,
                        "purchase %lld has no output path, and none was "
                        "supplied", (long long)purchase_id);
    if (strlen(want_path) > STORE_PURCHASE_PATH_MAX)
        return SB_FAILF(STORE_BUYER_ERR_ARGS,
                        "output path is %zu bytes, the limit is %d",
                        strlen(want_path), STORE_PURCHASE_PATH_MAX);
    (void)snprintf(target, sizeof(target), "%s", want_path);

    /* A product with no attached payload has nothing to verify and nothing
     * to write; the store answers with an HTML access page. Refusing here
     * is the honest answer — there is no file to deliver. */
    if (!purchase.has_content_hash) {
        LOG_WARN(SB_TAG, "collect: purchase %lld is for a product with no "
                 "file payload; there is nothing to download",
                 (long long)purchase_id);
        return SB_FAILF(STORE_BUYER_ERR_DELIVERY_FAILED,
                        "purchase %lld is for a product with no file payload",
                        (long long)purchase_id);
    }

    resp = zcl_malloc(SB_RESP_MAX, "store_buyer_collect_resp");
    if (!resp)
        return SB_FAILF(STORE_BUYER_ERR_INTERNAL,
                        "could not allocate the %d-byte response buffer",
                        (int)SB_RESP_MAX);

    (void)snprintf(path, sizeof(path), "/store/access?addr=%s&token=%s",
                   purchase.customer_addr, purchase.token_id);
    n = store_handle_request("GET", path, NULL, 0, resp, SB_RESP_MAX, datadir);
    if (n == 0 || !strstr((const char *)resp, "HTTP/1.1 200 OK")) {
        free(resp);
        LOG_WARN(SB_TAG, "collect: token gate did not serve purchase %lld "
                 "(token=%s addr=%s)", (long long)purchase_id,
                 purchase.token_id, purchase.customer_addr);
        return SB_FAILF(STORE_BUYER_ERR_DELIVERY_FAILED,
                        "the token gate did not serve purchase %lld "
                        "(token=%s addr=%s)", (long long)purchase_id,
                        purchase.token_id, purchase.customer_addr);
    }

    body = sb_http_body(resp, n, &body_len);
    if (!body || body_len == 0) {
        free(resp);
        LOG_WARN(SB_TAG, "collect: purchase %lld got a response with no body",
                 (long long)purchase_id);
        return SB_FAILF(STORE_BUYER_ERR_DELIVERY_FAILED,
                        "the store answered purchase %lld with no body",
                        (long long)purchase_id);
    }

    /* Verify BEFORE writing. The hash is the product's content hash recorded
     * when the order was placed, so this also catches a merchant that swapped
     * the payload after the sale — not just a corrupted transfer. */
    zcl_sha3_256(body, body_len, got);
    if (memcmp(got, purchase.content_hash, sizeof(got)) != 0) {
        free(resp);
        LOG_WARN(SB_TAG, "collect: purchase %lld delivered %zu bytes whose "
                 "SHA3-256 does not match the product content hash — "
                 "nothing written", (long long)purchase_id, body_len);
        ZCL_IGNORE_RESULT(store_buyer_fail(datadir, purchase_id,
                                       STORE_BUYER_ERR_HASH_MISMATCH, NULL),
                      "the mismatch is already the returned failure; a row "
                      "that will not take the note must not mask it");
        return SB_FAILF(STORE_BUYER_ERR_HASH_MISMATCH,
                        "purchase %lld delivered %zu bytes whose SHA3-256 is "
                        "not the product content hash; nothing was written",
                        (long long)purchase_id, body_len);
    }

    if (!sb_write_atomic(target, body, body_len)) {
        int werr = errno;
        free(resp);
        LOG_WARN(SB_TAG, "collect: purchase %lld verified %zu bytes but they "
                 "could not be written to %s (%s)", (long long)purchase_id,
                 body_len, target, strerror(werr));
        ZCL_IGNORE_RESULT(store_buyer_fail(datadir, purchase_id,
                                       STORE_BUYER_ERR_WRITE_FAILED, target),
                      "the write failure is already the returned failure; a "
                      "row that will not take the note must not mask it");
        return SB_FAILF(STORE_BUYER_ERR_WRITE_FAILED,
                        "verified %zu bytes for purchase %lld could not be "
                        "written to %s (%s)", body_len,
                        (long long)purchase_id, target, strerror(werr));
    }
    free(resp);

    r = sb_open_db(datadir, &ndb, "store_buyer.collect_record");
    if (!r.ok)
        return r;
    if (sb_load_purchase(&ndb, purchase_id, &purchase).ok) {
        purchase.stage = STORE_PURCHASE_DELIVERED;
        purchase.last_error[0] = '\0';
        (void)snprintf(purchase.output_path, sizeof(purchase.output_path),
                       "%s", target);
        (void)db_store_purchase_save(&ndb, &purchase);
    }
    node_db_close(&ndb);

    (void)snprintf(out->output_path, sizeof(out->output_path), "%s", target);
    out->bytes = (int64_t)body_len;
    memcpy(out->content_hash, got, sizeof(out->content_hash));
    out->hash_verified = true;
    return ZCL_OK;
}
