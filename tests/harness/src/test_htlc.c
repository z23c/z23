/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for HTLC (Hash Time-Locked Contracts) — atomic swap infrastructure. */

#include "test/test_core.h"
#include "script/htlc.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/swap_contract.h"

int test_htlc(void)
{
    int failures = 0;

    printf("\n=== HTLC / Atomic Swap Tests ===\n");

    /* ── Chain parsing ────────────────────────────────────────── */

    printf("swap_parse_chain: zcl... ");
    if (swap_parse_chain("zcl") == SWAP_CHAIN_ZCL) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: zclassic... ");
    if (swap_parse_chain("zclassic") == SWAP_CHAIN_ZCL) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: btc... ");
    if (swap_parse_chain("btc") == SWAP_CHAIN_BTC) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: bitcoin... ");
    if (swap_parse_chain("bitcoin") == SWAP_CHAIN_BTC) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: ltc... ");
    if (swap_parse_chain("ltc") == SWAP_CHAIN_LTC) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: litecoin... ");
    if (swap_parse_chain("litecoin") == SWAP_CHAIN_LTC) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: doge... ");
    if (swap_parse_chain("doge") == SWAP_CHAIN_DOGE) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: dogecoin... ");
    if (swap_parse_chain("dogecoin") == SWAP_CHAIN_DOGE) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: null... ");
    if (swap_parse_chain(NULL) == -1) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("swap_parse_chain: invalid... ");
    if (swap_parse_chain("eth") == -1) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* ── Chain params ─────────────────────────────────────────── */

    printf("swap_get_chain_params: ZCL has 2-byte prefix... ");
    {
        const struct swap_chain_params *p = swap_get_chain_params(SWAP_CHAIN_ZCL);
        if (p && p->prefix_len == 2 && strcmp(p->ticker, "ZCL") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("swap_get_chain_params: BTC has 1-byte prefix... ");
    {
        const struct swap_chain_params *p = swap_get_chain_params(SWAP_CHAIN_BTC);
        if (p && p->prefix_len == 1 && strcmp(p->ticker, "BTC") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("swap_get_chain_params: invalid returns NULL... ");
    if (swap_get_chain_params(99) == NULL) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* ── HTLC script builder ──────────────────────────────────── */

    printf("htlc_build_script: produces 97-byte script... ");
    {
        struct htlc_params params;
        memset(&params, 0, sizeof(params));
        memset(params.secret_hash, 0xAA, 32);
        memset(params.recipient_pkh, 0xBB, 20);
        memset(params.refunder_pkh, 0xCC, 20);
        params.locktime = 1000000;

        uint8_t script[128];
        size_t len = htlc_build_script(&params, script, sizeof(script));
        if (len == 97) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("htlc_build_script: correct opcode structure... ");
    {
        struct htlc_params params;
        memset(&params, 0, sizeof(params));
        memset(params.secret_hash, 0x11, 32);
        memset(params.recipient_pkh, 0x22, 20);
        memset(params.refunder_pkh, 0x33, 20);
        params.locktime = 500;

        uint8_t script[128];
        size_t len = htlc_build_script(&params, script, sizeof(script));

        /* Check key opcodes */
        bool ok = (len == 97) &&
                  (script[0] == 0x63) &&            /* OP_IF */
                  (script[1] == 0x82) &&            /* OP_SIZE */
                  (script[5] == 0xa8) &&            /* OP_SHA256 */
                  (script[6] == 0x20) &&            /* OP_DATA_32 */
                  (memcmp(script + 7, params.secret_hash, 32) == 0) &&
                  (script[39] == 0x88) &&           /* OP_EQUALVERIFY */
                  (script[40] == 0x76) &&           /* OP_DUP */
                  (script[41] == 0xa9) &&           /* OP_HASH160 */
                  (script[42] == 0x14) &&           /* OP_DATA_20 */
                  (memcmp(script + 43, params.recipient_pkh, 20) == 0) &&
                  (script[63] == 0x67) &&           /* OP_ELSE */
                  (script[64] == 0x04) &&           /* OP_DATA_4 */
                  (script[69] == 0xb1) &&           /* OP_CLTV */
                  (script[70] == 0x75) &&           /* OP_DROP */
                  (script[94] == 0x68) &&           /* OP_ENDIF */
                  (script[95] == 0x88) &&           /* OP_EQUALVERIFY */
                  (script[96] == 0xac);             /* OP_CHECKSIG */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("htlc_build_script: locktime encoding (LE)... ");
    {
        struct htlc_params params = {0};
        params.locktime = 0x12345678;
        memset(params.secret_hash, 0, 32);
        memset(params.recipient_pkh, 0, 20);
        memset(params.refunder_pkh, 0, 20);

        uint8_t script[128];
        htlc_build_script(&params, script, sizeof(script));

        /* Locktime at offset 65 (after OP_DATA_4 at 64) */
        if (script[65] == 0x78 && script[66] == 0x56 &&
            script[67] == 0x34 && script[68] == 0x12) {
            printf("OK\n");
        } else {
            printf("FAIL (got %02x%02x%02x%02x)\n",
                   script[65], script[66], script[67], script[68]);
            failures++;
        }
    }

    printf("htlc_build_script: buffer too small... ");
    {
        struct htlc_params params = {0};
        uint8_t small[50];
        size_t len = htlc_build_script(&params, small, sizeof(small));
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Secret generation + extraction ───────────────────────── */

    printf("htlc_generate_secret: produces valid secret+hash... ");
    {
        uint8_t secret[32], secret_hash[32];
        htlc_generate_secret(secret, secret_hash);

        /* Verify: SHA256(secret) == secret_hash */
        uint8_t verify[32];
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_write(&ctx, secret, 32);
        sha256_finalize(&ctx, verify);

        if (memcmp(verify, secret_hash, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("htlc_extract_secret: extracts 3rd push... ");
    {
        /* Build a mock redeem scriptSig:
         * <72-byte sig> <33-byte pubkey> <32-byte secret> OP_1 <97-byte contract> */
        uint8_t scriptsig[300];
        size_t off = 0;

        /* Push 1: fake signature (72 bytes) */
        scriptsig[off++] = 72;
        memset(scriptsig + off, 0xAA, 72);
        off += 72;

        /* Push 2: fake pubkey (33 bytes) */
        scriptsig[off++] = 33;
        memset(scriptsig + off, 0xBB, 33);
        off += 33;

        /* Push 3: secret (32 bytes) */
        scriptsig[off++] = 32;
        uint8_t expected_secret[32];
        memset(expected_secret, 0x42, 32);
        memcpy(scriptsig + off, expected_secret, 32);
        off += 32;

        /* OP_1 */
        scriptsig[off++] = 0x51;

        /* Push 4: fake contract (97 bytes) */
        scriptsig[off++] = 0x4c; /* OP_PUSHDATA1 */
        scriptsig[off++] = 97;
        memset(scriptsig + off, 0xCC, 97);
        off += 97;

        uint8_t out_secret[32];
        bool ok = htlc_extract_secret(scriptsig, off, out_secret);
        if (ok && memcmp(out_secret, expected_secret, 32) == 0)
            printf("OK\n");
        else { printf("FAIL (ok=%d)\n", ok); failures++; }
    }

    printf("htlc_extract_secret: fails on empty... ");
    {
        uint8_t out[32];
        if (!htlc_extract_secret(NULL, 0, out)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Redeem/Refund ScriptSig builders ─────────────────────── */

    printf("htlc_build_redeem_scriptsig: builds valid scriptsig... ");
    {
        uint8_t sig[72], pubkey[33], secret[32], contract[97];
        memset(sig, 0xAA, 72);
        memset(pubkey, 0xBB, 33);
        memset(secret, 0xCC, 32);
        memset(contract, 0xDD, 97);

        uint8_t out[512];
        size_t len = htlc_build_redeem_scriptsig(out, sizeof(out),
                                                  sig, 72,
                                                  pubkey, 33,
                                                  secret,
                                                  contract, 97);
        if (len > 0) {
            /* Verify we can extract the secret back */
            uint8_t extracted[32];
            bool ok = htlc_extract_secret(out, len, extracted);
            if (ok && memcmp(extracted, secret, 32) == 0)
                printf("OK (len=%zu)\n", len);
            else { printf("FAIL (extract)\n"); failures++; }
        } else { printf("FAIL (len=0)\n"); failures++; }
    }

    printf("htlc_build_refund_scriptsig: builds valid scriptsig... ");
    {
        uint8_t sig[72], pubkey[33], contract[97];
        memset(sig, 0xAA, 72);
        memset(pubkey, 0xBB, 33);
        memset(contract, 0xDD, 97);

        uint8_t out[512];
        size_t len = htlc_build_refund_scriptsig(out, sizeof(out),
                                                  sig, 72,
                                                  pubkey, 33,
                                                  contract, 97);
        if (len > 0) printf("OK (len=%zu)\n", len);
        else { printf("FAIL\n"); failures++; }
    }

    printf("htlc_build_redeem_scriptsig: too small buffer... ");
    {
        uint8_t sig[72], pubkey[33], secret[32], contract[97];
        uint8_t small[10];
        size_t len = htlc_build_redeem_scriptsig(small, sizeof(small),
                                                  sig, 72, pubkey, 33,
                                                  secret, contract, 97);
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Swap ID computation ──────────────────────────────────── */

    printf("swap_compute_id: deterministic... ");
    {
        uint8_t hash[32];
        memset(hash, 0x55, 32);
        char id1[65], id2[65];
        swap_compute_id("addr1", "addr2", hash, id1);
        swap_compute_id("addr1", "addr2", hash, id2);
        if (strcmp(id1, id2) == 0 && strlen(id1) == 64)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("swap_compute_id: different inputs, different IDs... ");
    {
        uint8_t hash[32];
        memset(hash, 0x55, 32);
        char id1[65], id2[65];
        swap_compute_id("addr1", "addr2", hash, id1);
        swap_compute_id("addr3", "addr2", hash, id2);
        if (strcmp(id1, id2) != 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── P2SH address generation ──────────────────────────────── */

    printf("htlc_p2sh_address: ZCL address... ");
    {
        struct htlc_params params = {0};
        memset(params.secret_hash, 0xAA, 32);
        memset(params.recipient_pkh, 0xBB, 20);
        memset(params.refunder_pkh, 0xCC, 20);
        params.locktime = 100000;

        uint8_t script[128];
        size_t slen = htlc_build_script(&params, script, sizeof(script));

        char addr[64] = {0};
        bool ok = htlc_p2sh_address(script, slen, SWAP_CHAIN_ZCL,
                                    addr, sizeof(addr));
        if (ok && strlen(addr) > 0 && addr[0] == 't')
            printf("OK (%s)\n", addr);
        else { printf("FAIL (ok=%d addr=%s)\n", ok, addr); failures++; }
    }

    printf("htlc_p2sh_address: invalid chain returns false... ");
    {
        uint8_t script[97] = {0};
        char addr[64];
        if (!htlc_p2sh_address(script, 97, 99, addr, sizeof(addr)))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── SQLite persistence ───────────────────────────────────── */

    printf("htlc DB save+find+list+update roundtrip... ");
    {
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        if (rc != SQLITE_OK) { printf("FAIL (open)\n"); failures++; }
        else {
            sqlite3_exec(db,
                "CREATE TABLE zswp_contracts("
                "swap_id TEXT PRIMARY KEY, role INTEGER, state INTEGER,"
                "chain INTEGER, secret_hash BLOB, secret BLOB,"
                "amount INTEGER, locktime INTEGER,"
                "my_address TEXT, counter_address TEXT,"
                "funding_txid BLOB, funding_vout INTEGER,"
                "redeem_script BLOB, redeem_script_len INTEGER,"
                "p2sh_address TEXT, created_at INTEGER)",
                NULL, NULL, NULL);

            struct node_db ndb = { .db = db, .open = true };

            struct swap_contract swap = {0};
            snprintf(swap.swap_id, sizeof(swap.swap_id), "abc123def456");
            swap.role = SWAP_INITIATOR;
            swap.state = SWAP_PENDING;
            swap.chain = SWAP_CHAIN_ZCL;
            memset(swap.secret_hash, 0xAA, 32);
            swap.has_secret = false;
            swap.amount = 100000000;
            swap.locktime = 960;
            snprintf(swap.my_address, sizeof(swap.my_address), "t1me");
            snprintf(swap.counter_address, sizeof(swap.counter_address), "t1them");
            swap.redeem_script_len = 3;
            swap.redeem_script[0] = 0x51; /* OP_TRUE */
            snprintf(swap.p2sh_address, sizeof(swap.p2sh_address),
                     "t3contract");
            swap.created_at = 1700000000;

            bool save_ok = db_swap_save(&ndb, &swap);

            struct swap_contract found = {0};
            bool find_ok = db_swap_find(&ndb, "abc123def456", &found);

            struct swap_contract list[10];
            int count = db_swap_list(&ndb, list, 10, -1);
            int count_pending = db_swap_list(&ndb, list, 10, SWAP_PENDING);
            int count_funded = db_swap_list(&ndb, list, 10, SWAP_FUNDED);

            bool update_ok = db_swap_update_state(&ndb, "abc123def456",
                                                  SWAP_FUNDED, NULL);
            struct swap_contract after = {0};
            db_swap_find(&ndb, "abc123def456", &after);

            /* Update with secret */
            uint8_t secret[32];
            memset(secret, 0xBB, 32);
            bool update2 = db_swap_update_state(&ndb, "abc123def456",
                                                SWAP_REDEEMED, secret);
            struct swap_contract redeemed = {0};
            db_swap_find(&ndb, "abc123def456", &redeemed);

            if (save_ok && find_ok &&
                strcmp(found.swap_id, "abc123def456") == 0 &&
                found.role == SWAP_INITIATOR &&
                found.state == SWAP_PENDING &&
                found.amount == 100000000 &&
                count == 1 && count_pending == 1 && count_funded == 0 &&
                update_ok && after.state == SWAP_FUNDED &&
                update2 && redeemed.state == SWAP_REDEEMED &&
                redeemed.has_secret) {
                printf("OK\n");
            } else {
                printf("FAIL\n");
                failures++;
            }

            /* Null guards */
            printf("htlc DB null guards... ");
            if (!db_swap_save(NULL, &swap) &&
                !db_swap_find(NULL, "x", &found) &&
                db_swap_list(NULL, list, 10, -1) == 0) {
                printf("OK\n");
            } else { printf("FAIL\n"); failures++; }

            /* Find non-existent */
            printf("htlc DB find non-existent... ");
            if (!db_swap_find(&ndb, "nonexistent", &found))
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            sqlite3_close(db);
        }
    }

    /* ── Cross-chain P2SH addresses ─────────────────────────────── */

    printf("htlc_p2sh_address: BTC address starts with '3'... ");
    {
        struct htlc_params params = {0};
        memset(params.secret_hash, 0xAA, 32);
        memset(params.recipient_pkh, 0xBB, 20);
        memset(params.refunder_pkh, 0xCC, 20);
        params.locktime = 100000;

        uint8_t script[128];
        size_t slen = htlc_build_script(&params, script, sizeof(script));

        char addr[64] = {0};
        bool ok = htlc_p2sh_address(script, slen, SWAP_CHAIN_BTC,
                                    addr, sizeof(addr));
        if (ok && strlen(addr) > 0 && addr[0] == '3')
            printf("OK (%s)\n", addr);
        else { printf("FAIL (ok=%d addr=%s)\n", ok, addr); failures++; }
    }

    printf("htlc_p2sh_address: LTC address... ");
    {
        struct htlc_params params = {0};
        memset(params.secret_hash, 0xAA, 32);
        memset(params.recipient_pkh, 0xBB, 20);
        memset(params.refunder_pkh, 0xCC, 20);
        params.locktime = 100000;

        uint8_t script[128];
        size_t slen = htlc_build_script(&params, script, sizeof(script));

        char addr[64] = {0};
        bool ok = htlc_p2sh_address(script, slen, SWAP_CHAIN_LTC,
                                    addr, sizeof(addr));
        if (ok && strlen(addr) > 0)
            printf("OK (%s)\n", addr);
        else { printf("FAIL\n"); failures++; }
    }

    printf("htlc_p2sh_address: DOGE address... ");
    {
        struct htlc_params params = {0};
        memset(params.secret_hash, 0xAA, 32);
        memset(params.recipient_pkh, 0xBB, 20);
        memset(params.refunder_pkh, 0xCC, 20);
        params.locktime = 100000;

        uint8_t script[128];
        size_t slen = htlc_build_script(&params, script, sizeof(script));

        char addr[64] = {0};
        bool ok = htlc_p2sh_address(script, slen, SWAP_CHAIN_DOGE,
                                    addr, sizeof(addr));
        if (ok && strlen(addr) > 0)
            printf("OK (%s)\n", addr);
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Same contract → same P2SH across rebuilds ────────────── */

    printf("htlc_p2sh_address: deterministic output... ");
    {
        struct htlc_params params = {0};
        memset(params.secret_hash, 0xDE, 32);
        memset(params.recipient_pkh, 0xAD, 20);
        memset(params.refunder_pkh, 0xBE, 20);
        params.locktime = 500000;

        uint8_t s1[128], s2[128];
        size_t l1 = htlc_build_script(&params, s1, sizeof(s1));
        size_t l2 = htlc_build_script(&params, s2, sizeof(s2));

        char a1[64] = {0}, a2[64] = {0};
        htlc_p2sh_address(s1, l1, SWAP_CHAIN_ZCL, a1, sizeof(a1));
        htlc_p2sh_address(s2, l2, SWAP_CHAIN_ZCL, a2, sizeof(a2));

        if (l1 == l2 && memcmp(s1, s2, l1) == 0 && strcmp(a1, a2) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Full swap simulation: initiate → participate → redeem → extract ── */

    printf("htlc full swap: end-to-end secret exchange... ");
    {
        /* Initiator generates secret */
        uint8_t secret[32], secret_hash[32];
        htlc_generate_secret(secret, secret_hash);

        /* Both sides use the same secret_hash */
        struct htlc_params init_params = {0};
        memcpy(init_params.secret_hash, secret_hash, 32);
        memset(init_params.recipient_pkh, 0x11, 20); /* participant claims */
        memset(init_params.refunder_pkh, 0x22, 20);  /* initiator refunds */
        init_params.locktime = 960; /* initiator: ~20 hours */

        struct htlc_params part_params = {0};
        memcpy(part_params.secret_hash, secret_hash, 32);
        memset(part_params.recipient_pkh, 0x22, 20); /* initiator claims */
        memset(part_params.refunder_pkh, 0x11, 20);  /* participant refunds */
        part_params.locktime = 384; /* participant: ~8 hours */

        uint8_t init_script[128], part_script[128];
        size_t init_len = htlc_build_script(&init_params, init_script, sizeof(init_script));
        size_t part_len = htlc_build_script(&part_params, part_script, sizeof(part_script));

        /* Both produce 97-byte dcrdex-compatible scripts */
        bool ok = (init_len == 97 && part_len == 97);

        /* Same secret_hash at offset 7 in both */
        ok = ok && memcmp(init_script + 7, secret_hash, 32) == 0;
        ok = ok && memcmp(part_script + 7, secret_hash, 32) == 0;

        /* Initiator redeems participant's contract (reveals secret) */
        uint8_t fake_sig[72], fake_pk[33];
        memset(fake_sig, 0xAA, 72);
        memset(fake_pk, 0xBB, 33);

        uint8_t redeem_sig[512];
        size_t redeem_len = htlc_build_redeem_scriptsig(
            redeem_sig, sizeof(redeem_sig),
            fake_sig, 72, fake_pk, 33,
            secret, part_script, part_len);
        ok = ok && (redeem_len > 0);

        /* Participant extracts secret from initiator's redeem tx */
        uint8_t extracted[32];
        bool extracted_ok = htlc_extract_secret(redeem_sig, redeem_len, extracted);
        ok = ok && extracted_ok && memcmp(extracted, secret, 32) == 0;

        /* Participant can now verify: SHA256(extracted) == secret_hash */
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_write(&ctx, extracted, 32);
        uint8_t verify_hash[32];
        sha256_finalize(&ctx, verify_hash);
        ok = ok && memcmp(verify_hash, secret_hash, 32) == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("\n%d HTLC test(s) failed\n", failures);
    return failures;
}
