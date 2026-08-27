/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Simple Ledger Protocol (SLP) parser and builder. */

#include "test/test_core.h"
#include "zslp/slp.h"
#include "wallet/wallet.h"
#include "script/standard.h"
#include "services/zslp_command_service.h"

static bool test_slp_coin_reserved(const struct transaction *tx,
                                   uint32_t vout, void *ctx)
{
    (void)ctx;
    struct slp_output_metadata meta;
    return slp_classify_tx_output(tx, vout, &meta);
}

int test_slp(void)
{
    int failures = 0;

    /* ── Parse valid GENESIS ─────────────────────────────── */

    printf("slp_parse valid GENESIS... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "ZCL", "ZClassic Token", "https://zclassic.org", NULL,
            8, 0, 1000000);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && msg.token_type == SLP_TOKEN_TYPE_1;
        ok = ok && strcmp(msg.ticker, "ZCL") == 0;
        ok = ok && strcmp(msg.name, "ZClassic Token") == 0;
        ok = ok && strcmp(msg.document_url, "https://zclassic.org") == 0;
        ok = ok && !msg.has_document_hash;
        ok = ok && msg.decimals == 8;
        ok = ok && msg.mint_baton_vout == 0;
        ok = ok && msg.initial_quantity == 1000000;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse GENESIS with document hash... ");
    {
        uint8_t hash[32];
        memset(hash, 0xAB, 32);
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "TEST", "Test Token", "https://example.com", hash,
            4, 2, 5000);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && msg.has_document_hash;
        ok = ok && memcmp(msg.document_hash, hash, 32) == 0;
        ok = ok && msg.decimals == 4;
        ok = ok && msg.mint_baton_vout == 2;
        ok = ok && msg.initial_quantity == 5000;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Parse valid MINT ────────────────────────────────── */

    printf("slp_parse valid MINT... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0xCC, 32);
        uint8_t buf[256];
        size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 2, 999999);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_MINT;
        ok = ok && msg.token_type == SLP_TOKEN_TYPE_1;
        ok = ok && memcmp(msg.token_id.data, token_id.data, 32) == 0;
        ok = ok && msg.mint_baton_vout == 2;
        ok = ok && msg.additional_quantity == 999999;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse MINT no baton... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0xDD, 32);
        uint8_t buf[256];
        size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 0, 42);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_MINT;
        ok = ok && msg.mint_baton_vout == 0;
        ok = ok && msg.additional_quantity == 42;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Parse valid SEND ────────────────────────────────── */

    printf("slp_parse valid SEND 1 output... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0xEE, 32);
        uint64_t qty[] = { 100 };
        uint8_t buf[256];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 1);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_SEND;
        ok = ok && msg.num_outputs == 1;
        ok = ok && msg.output_quantities[0] == 100;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse valid SEND multiple outputs... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0xFF, 32);
        uint64_t qty[] = { 10, 20, 30, 40, 50 };
        uint8_t buf[512];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 5);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_SEND;
        ok = ok && msg.num_outputs == 5;
        for (int i = 0; i < 5 && ok; i++)
            ok = ok && msg.output_quantities[i] == qty[i];
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── NULL / empty / too-short scripts ────────────────── */

    printf("slp_parse NULL script... ");
    {
        struct slp_message msg;
        bool ok = !slp_parse(NULL, 0, &msg);
        ok = ok && msg.type == SLP_TX_INVALID;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse NULL output message... ");
    {
        uint8_t buf[] = { 0x6a };
        bool ok = !slp_parse(buf, sizeof(buf), NULL);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse empty script... ");
    {
        uint8_t buf[1] = { 0 };
        struct slp_message msg;
        bool ok = !slp_parse(buf, 0, &msg);
        ok = ok && msg.type == SLP_TX_INVALID;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse too-short script (just OP_RETURN)... ");
    {
        uint8_t buf[] = { 0x6a };
        struct slp_message msg;
        bool ok = !slp_parse(buf, 1, &msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_parse script not starting with OP_RETURN... ");
    {
        uint8_t buf[] = { 0x00, 0x04, 'S', 'L', 'P', 0x00 };
        struct slp_message msg;
        bool ok = !slp_parse(buf, sizeof(buf), &msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Invalid lokad_id ────────────────────────────────── */

    printf("slp_parse invalid lokad_id... ");
    {
        /* Build a valid script then corrupt the lokad_id */
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "X", "X", "", NULL, 0, 0, 1);
        /* lokad_id is at offset 2 (after OP_RETURN + push opcode) */
        buf[2] = 'X'; /* corrupt first byte of "SLP\0" */
        struct slp_message msg;
        bool ok = !slp_parse(buf, len, &msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Wrong token_type ────────────────────────────────── */

    printf("slp_parse wrong token_type... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "X", "X", "", NULL, 0, 0, 1);
        /* token_type is pushed after lokad_id.
         * lokad_id: OP_RETURN(1) + push(1) + 4 bytes = offset 6
         * token_type: push(1) + 1 byte at offset 7 */
        buf[7] = 2; /* change token_type from 1 to 2 */
        struct slp_message msg;
        bool ok = !slp_parse(buf, len, &msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Build + parse round-trips ───────────────────────── */

    printf("slp_build_genesis round-trip... ");
    {
        uint8_t hash[32];
        for (int i = 0; i < 32; i++) hash[i] = (uint8_t)i;
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "MYTOKEN", "My Token Name", "https://mytoken.org", hash,
            6, 3, UINT64_C(1000000000000));
        bool ok = len > 0;
        struct slp_message msg;
        ok = ok && slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && strcmp(msg.ticker, "MYTOKEN") == 0;
        ok = ok && strcmp(msg.name, "My Token Name") == 0;
        ok = ok && strcmp(msg.document_url, "https://mytoken.org") == 0;
        ok = ok && msg.has_document_hash;
        ok = ok && memcmp(msg.document_hash, hash, 32) == 0;
        ok = ok && msg.decimals == 6;
        ok = ok && msg.mint_baton_vout == 3;
        ok = ok && msg.initial_quantity == UINT64_C(1000000000000);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_mint round-trip... ");
    {
        struct uint256 token_id;
        for (int i = 0; i < 32; i++) token_id.data[i] = (uint8_t)(0x10 + i);
        uint8_t buf[256];
        size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 4, UINT64_C(9999999999));
        bool ok = len > 0;
        struct slp_message msg;
        ok = ok && slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_MINT;
        ok = ok && memcmp(msg.token_id.data, token_id.data, 32) == 0;
        ok = ok && msg.mint_baton_vout == 4;
        ok = ok && msg.additional_quantity == UINT64_C(9999999999);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_send round-trip... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0x55, 32);
        uint64_t qty[] = { 100, 200, 300 };
        uint8_t buf[512];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 3);
        bool ok = len > 0;
        struct slp_message msg;
        ok = ok && slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_SEND;
        ok = ok && msg.num_outputs == 3;
        ok = ok && msg.output_quantities[0] == 100;
        ok = ok && msg.output_quantities[1] == 200;
        ok = ok && msg.output_quantities[2] == 300;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Edge cases: ticker lengths ──────────────────────── */

    printf("slp_build_genesis empty ticker... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "", "No Ticker", "", NULL, 0, 0, 1);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && msg.ticker[0] == '\0'; /* empty ticker */
        ok = ok && msg.initial_quantity == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_genesis NULL ticker... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            NULL, "Null Ticker", "", NULL, 0, 0, 1);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && msg.ticker[0] == '\0';
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_genesis max-length ticker (63 chars)... ");
    {
        char long_ticker[64];
        memset(long_ticker, 'Z', 63);
        long_ticker[63] = '\0';
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            long_ticker, "Long", "", NULL, 0, 0, 1);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_GENESIS;
        ok = ok && strcmp(msg.ticker, long_ticker) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Edge cases: decimals ────────────────────────────── */

    printf("slp_build_genesis 0 decimals... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "NDC", "No Decimals Coin", "", NULL, 0, 0, 100);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.decimals == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_genesis 8 decimals... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "BTC", "Bitcoin Clone", "", NULL, 8, 0, 2100000000000000ULL);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.decimals == 8;
        ok = ok && msg.initial_quantity == 2100000000000000ULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Edge cases: SEND outputs ────────────────────────── */

    printf("slp_build_send 0 outputs (should fail)... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0x11, 32);
        uint64_t qty[] = { 0 };
        uint8_t buf[256];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 0);
        bool ok = (len == 0); /* builder should reject 0 outputs */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_send 19 outputs (max)... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0x22, 32);
        uint64_t qty[19];
        for (int i = 0; i < 19; i++) qty[i] = (uint64_t)(i + 1) * 100;
        uint8_t buf[1024];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 19);
        bool ok = len > 0;
        struct slp_message msg;
        ok = ok && slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_SEND;
        ok = ok && msg.num_outputs == 19;
        for (int i = 0; i < 19 && ok; i++)
            ok = ok && msg.output_quantities[i] == qty[i];
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_send 20 outputs (over max, should fail)... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0x33, 32);
        uint64_t qty[20];
        for (int i = 0; i < 20; i++) qty[i] = 1;
        uint8_t buf[1024];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 20);
        bool ok = (len == 0); /* builder should reject >19 outputs */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Large quantity (UINT64_MAX) ─────────────────────── */

    printf("slp_build_genesis max quantity (UINT64_MAX)... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "MAX", "Max Supply", "", NULL, 0, 0, UINT64_MAX);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.initial_quantity == UINT64_MAX;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("slp_build_mint max quantity (UINT64_MAX)... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0xAA, 32);
        uint8_t buf[256];
        size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 0, UINT64_MAX);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.additional_quantity == UINT64_MAX;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Zero quantity ───────────────────────────────────── */

    printf("slp_build_genesis zero quantity... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "ZERO", "Zero Token", "", NULL, 0, 0, 0);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.initial_quantity == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Truncated GENESIS (cut off at decimals field) ───── */

    printf("slp_parse truncated GENESIS... ");
    {
        uint8_t buf[512];
        size_t len = slp_build_genesis(buf, sizeof(buf),
            "X", "X", "", NULL, 0, 0, 1);
        /* Truncate to remove the last field (initial_quantity) */
        struct slp_message msg;
        bool ok = !slp_parse(buf, len - 10, &msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── SEND with zero-value quantities ─────────────────── */

    printf("slp_build_send with zero quantities... ");
    {
        struct uint256 token_id;
        memset(token_id.data, 0x44, 32);
        uint64_t qty[] = { 0, 0, 0 };
        uint8_t buf[512];
        size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 3);
        struct slp_message msg;
        bool ok = slp_parse(buf, len, &msg);
        ok = ok && msg.type == SLP_TX_SEND;
        ok = ok && msg.num_outputs == 3;
        ok = ok && msg.output_quantities[0] == 0;
        ok = ok && msg.output_quantities[1] == 0;
        ok = ok && msg.output_quantities[2] == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Wallet custody classification ───────────────────── */

    printf("slp output classifier normalizes token id byte order... ");
    {
        struct transaction genesis;
        transaction_init(&genesis);
        bool ok = transaction_alloc(&genesis, 0, 3);
        uint8_t script[256];
        size_t len = slp_build_genesis(script, sizeof(script), "SAFE",
                                       "Safe Token", "", NULL, 0, 2, 1000);
        genesis.vout[0].script_pub_key.size = len;
        memcpy(genesis.vout[0].script_pub_key.data, script, len);
        transaction_compute_hash(&genesis);
        struct slp_output_metadata token, baton;
        ok = ok && slp_classify_tx_output(&genesis, 1, &token);
        ok = ok && token.role == SLP_OUTPUT_TOKEN && token.amount == 1000;
        ok = ok && memcmp(token.token_id, genesis.hash.data, 32) == 0;
        ok = ok && slp_classify_tx_output(&genesis, 2, &baton);
        ok = ok && baton.role == SLP_OUTPUT_MINT_BATON;

        struct uint256 wire;
        for (int i = 0; i < 32; i++)
            wire.data[i] = genesis.hash.data[31 - i];
        uint64_t quantities[2] = { 400, 600 };
        struct transaction send;
        transaction_init(&send);
        ok = ok && transaction_alloc(&send, 0, 3);
        len = slp_build_send(script, sizeof(script), &wire, quantities, 2);
        send.vout[0].script_pub_key.size = len;
        memcpy(send.vout[0].script_pub_key.data, script, len);
        struct slp_output_metadata change;
        ok = ok && slp_classify_tx_output(&send, 2, &change);
        ok = ok && change.role == SLP_OUTPUT_TOKEN && change.amount == 600;
        ok = ok && memcmp(change.token_id, genesis.hash.data, 32) == 0;
        transaction_free(&send);
        transaction_free(&genesis);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("ordinary wallet coin selection reserves token and baton dust... ");
    {
        wallet_set_coin_reservation_probe(test_slp_coin_reserved, NULL);
        struct wallet w;
        uint8_t seed[32];
        memset(seed, 0x5a, sizeof(seed));
        wallet_init(&w);
        bool ok = wallet_init_hd(&w, seed, sizeof(seed));
        char address[128];
        struct key_id kid = {0};
        ok = ok && wallet_get_new_address_with_key_id(
                       &w, address, sizeof(address), &kid);
        ok = ok && wallet_top_up_key_pool(&w, 4);
        wallet_key_pool_mark_persisted_through(
            &w, wallet_key_pool_generation_ceiling(&w));
        struct tx_destination owner = { .type = DEST_KEY_ID, .id.key = kid };

        struct wallet_tx asset;
        memset(&asset, 0, sizeof(asset));
        transaction_init(&asset.tx);
        ok = ok && transaction_alloc(&asset.tx, 0, 3);
        uint8_t script[256];
        size_t len = slp_build_genesis(script, sizeof(script), "SAFE",
                                       "Safe Token", "", NULL, 0, 2, 1000);
        asset.tx.vout[0].script_pub_key.size = len;
        memcpy(asset.tx.vout[0].script_pub_key.data, script, len);
        for (int i = 1; i <= 2; i++) {
            asset.tx.vout[i].value = 546;
            script_for_destination(&asset.tx.vout[i].script_pub_key, &owner);
        }
        transaction_compute_hash(&asset.tx);
        struct uint256 token_id = asset.tx.hash;
        asset.confirms = 10;
        ok = ok && wallet_add_to_wallet(&w, &asset);
        transaction_free(&asset.tx);

        struct wallet_tx funding;
        memset(&funding, 0, sizeof(funding));
        transaction_init(&funding.tx);
        ok = ok && transaction_alloc(&funding.tx, 0, 1);
        funding.tx.vout[0].value = 100000;
        script_for_destination(&funding.tx.vout[0].script_pub_key, &owner);
        transaction_compute_hash(&funding.tx);
        funding.confirms = 10;
        ok = ok && wallet_add_to_wallet(&w, &funding);
        transaction_free(&funding.tx);

        struct coin_entry ordinary[8], asset_aware[8];
        size_t ordinary_count = 0, asset_count = 0;
        wallet_available_coins(&w, ordinary, &ordinary_count, 8, true, false);
        wallet_available_coins_ex(&w, asset_aware, &asset_count, 8, true,
                                  false, true);
        ok = ok && ordinary_count == 1 && asset_count == 3;

        struct wallet_tx send_tx;
        int64_t fee_paid = 0;
        const char *tx_error = NULL;
        struct zcl_result send_built = zslp_command_build_token_send_tx(
            &w, token_id.data, address, 400, &send_tx, &fee_paid, &tx_error);
        ok = ok && send_built.ok && send_tx.tx.num_vin == 2 &&
             send_tx.tx.num_vout == 4 && fee_paid == wallet_default_fee(&w);
        bool spent_token = false, spent_baton = false;
        for (size_t i = 0; send_built.ok && i < send_tx.tx.num_vin; i++) {
            if (uint256_eq(&send_tx.tx.vin[i].prevout.hash, &token_id) &&
                send_tx.tx.vin[i].prevout.n == 1)
                spent_token = true;
            if (uint256_eq(&send_tx.tx.vin[i].prevout.hash, &token_id) &&
                send_tx.tx.vin[i].prevout.n == 2)
                spent_baton = true;
        }
        struct slp_output_metadata sent, returned;
        ok = ok && spent_token && !spent_baton;
        ok = ok && slp_classify_tx_output(&send_tx.tx, 1, &sent) &&
             sent.amount == 400;
        ok = ok && slp_classify_tx_output(&send_tx.tx, 2, &returned) &&
             returned.amount == 600;
        if (send_built.ok)
            transaction_free(&send_tx.tx);

        struct wallet_tx mint_tx;
        tx_error = NULL;
        struct zcl_result mint_built = zslp_command_build_token_mint_tx(
            &w, token_id.data, address, 250, &mint_tx, &fee_paid, &tx_error);
        bool mint_spent_baton = false;
        for (size_t i = 0; mint_built.ok && i < mint_tx.tx.num_vin; i++) {
            if (uint256_eq(&mint_tx.tx.vin[i].prevout.hash, &token_id) &&
                mint_tx.tx.vin[i].prevout.n == 2)
                mint_spent_baton = true;
        }
        struct slp_output_metadata minted, next_baton;
        ok = ok && mint_built.ok && mint_spent_baton;
        ok = ok && slp_classify_tx_output(&mint_tx.tx, 1, &minted) &&
             minted.amount == 250;
        ok = ok && slp_classify_tx_output(&mint_tx.tx, 2, &next_baton) &&
             next_baton.role == SLP_OUTPUT_MINT_BATON;
        if (mint_built.ok)
            transaction_free(&mint_tx.tx);

        struct wallet_tx burn_tx;
        tx_error = NULL;
        struct zcl_result burn_built = zslp_command_build_token_burn_tx(
            &w, token_id.data, 400, &burn_tx, &fee_paid, &tx_error);
        bool burn_spent_token = false, burn_spent_baton = false;
        for (size_t i = 0; burn_built.ok && i < burn_tx.tx.num_vin; i++) {
            if (uint256_eq(&burn_tx.tx.vin[i].prevout.hash, &token_id) &&
                burn_tx.tx.vin[i].prevout.n == 1)
                burn_spent_token = true;
            if (uint256_eq(&burn_tx.tx.vin[i].prevout.hash, &token_id) &&
                burn_tx.tx.vin[i].prevout.n == 2)
                burn_spent_baton = true;
        }
        struct slp_output_metadata burn_change;
        ok = ok && burn_built.ok && burn_spent_token && !burn_spent_baton;
        ok = ok && slp_classify_tx_output(&burn_tx.tx, 1, &burn_change) &&
             burn_change.amount == 600 &&
             memcmp(burn_change.token_id, token_id.data, 32) == 0;
        if (burn_built.ok)
            transaction_free(&burn_tx.tx);
        wallet_free(&w);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
