/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for multisig P2SH support — script building, keystore,
 * address encoding, and P2SH-wrapped multisig signing. */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "script/script_flags.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"
#include "wallet/keystore.h"
#include "keys/key_io.h"
#include "util/safe_alloc.h"

int test_multisig(void)
{
    int failures = 0;

    /* ================================================================
     * 1. script_for_multisig: 2-of-3 builds correct script
     * ================================================================ */
    printf("multisig: script_for_multisig 2-of-3 layout... ");
    {
        struct privkey k1, k2, k3;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        privkey_make_new(&k3, true);
        struct pubkey p1, p2, p3;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);
        privkey_get_pubkey(&k3, &p3);

        struct pubkey pks[3] = { p1, p2, p3 };
        struct script s;
        script_for_multisig(&s, 2, pks, 3);

        /* OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG */
        bool ok = (s.data[0] == OP_2) &&
                  (s.data[s.size - 2] == OP_3) &&
                  (s.data[s.size - 1] == OP_CHECKMULTISIG) &&
                  (s.size == 105); /* 1 + (1+33)*3 + 1 + 1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 2. script_for_multisig: 1-of-1 minimum case
     * ================================================================ */
    printf("multisig: script_for_multisig 1-of-1... ");
    {
        struct privkey k1;
        privkey_make_new(&k1, true);
        struct pubkey p1;
        privkey_get_pubkey(&k1, &p1);

        struct pubkey pks[1] = { p1 };
        struct script s;
        script_for_multisig(&s, 1, pks, 1);

        bool ok = (s.data[0] == OP_1) &&
                  (s.data[s.size - 2] == OP_1) &&
                  (s.data[s.size - 1] == OP_CHECKMULTISIG) &&
                  (s.size == 37); /* 1 + (1+33) + 1 + 1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 3. script_solver recognizes multisig as TX_MULTISIG
     * ================================================================ */
    printf("multisig: script_solver detects TX_MULTISIG... ");
    {
        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script s;
        script_for_multisig(&s, 1, pks, 2);

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = script_solver(&s, &type, solutions, solution_sizes,
                                &num_solutions);
        ok = ok && (type == TX_MULTISIG);
        /* solutions: [0]=nrequired, [1..n]=pubkeys, [n+1]=nkeys */
        ok = ok && (num_solutions == 4);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 4. P2SH wrapping: hash160 + address encoding roundtrip
     * ================================================================ */
    printf("multisig: P2SH address roundtrip... ");
    {
        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script redeem;
        script_for_multisig(&redeem, 2, pks, 2);

        struct script_id sid;
        script_id_from_script(&sid, &redeem);

        /* Build P2SH script and verify solver */
        struct script p2sh;
        script_for_p2sh(&p2sh, &sid);
        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        bool ok = script_solver(&p2sh, &type, solutions, solution_sizes,
                                &num_solutions);
        ok = ok && (type == TX_SCRIPTHASH);
        ok = ok && (memcmp(solutions[0], sid.hash.data, 20) == 0);

        /* Encode + decode destination */
        const struct chain_params *cp = chain_params_get();
        size_t pk_pfx_len, sc_pfx_len;
        const unsigned char *pk_pfx = chain_params_base58_prefix(
            cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
        const unsigned char *sc_pfx = chain_params_base58_prefix(
            cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        dest.id.script = sid;
        char addr[128];
        encode_destination(&dest, pk_pfx, pk_pfx_len,
                           sc_pfx, sc_pfx_len, addr, sizeof(addr));

        /* ZCL P2SH mainnet starts with "t3" */
        ok = ok && (addr[0] == 't') && (addr[1] == '3');

        /* Decode back */
        struct tx_destination dest2;
        ok = ok && decode_destination(addr, pk_pfx, pk_pfx_len,
                                      sc_pfx, sc_pfx_len, &dest2);
        ok = ok && (dest2.type == DEST_SCRIPT_ID);
        ok = ok && (memcmp(dest2.id.script.hash.data, sid.hash.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 5. Keystore: add and retrieve redeem script
     * ================================================================ */
    printf("multisig: keystore add/get/have cscript... ");
    {
        struct basic_keystore *ks = zcl_malloc(sizeof(*ks), "test_ks");

        keystore_init(ks);

        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script redeem;
        script_for_multisig(&redeem, 2, pks, 2);

        bool ok = keystore_add_cscript(ks, &redeem);

        struct script_id sid;
        script_id_from_script(&sid, &redeem);
        ok = ok && keystore_have_cscript(ks, &sid.hash);

        struct script retrieved;
        ok = ok && keystore_get_cscript(ks, &sid.hash, &retrieved);
        ok = ok && (retrieved.size == redeem.size);
        ok = ok && (memcmp(retrieved.data, redeem.data, redeem.size) == 0);

        /* Unknown script should not be found */
        struct uint160 fake;
        memset(fake.data, 0xff, 20);
        ok = ok && !keystore_have_cscript(ks, &fake);

        keystore_free(ks);
        free(ks);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 6. P2SH-wrapped 2-of-2 multisig signing
     * ================================================================ */
    printf("multisig: P2SH 2-of-2 sign produces valid scriptSig... ");
    {
        struct basic_keystore *ks = zcl_malloc(sizeof(*ks), "test_ks");
        keystore_init(ks);

        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        keystore_add_key(ks, &k1);
        keystore_add_key(ks, &k2);

        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script redeem;
        script_for_multisig(&redeem, 2, pks, 2);
        keystore_add_cscript(ks, &redeem);

        struct script_id sid;
        script_id_from_script(&sid, &redeem);

        /* Create a minimal transaction */
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 4;
        tx.version_group_id = 0x892F2085; /* Sapling */
        struct tx_in vin;
        memset(&vin, 0, sizeof(vin));
        vin.sequence = 0xffffffff;
        tx.vin = &vin;
        tx.num_vin = 1;
        struct tx_out vout;
        memset(&vout, 0, sizeof(vout));
        vout.value = 100000000;
        struct key_id dummy_kid;
        memset(&dummy_kid, 0, sizeof(dummy_kid));
        script_for_p2pkh(&vout.script_pub_key, &dummy_kid);
        tx.vout = &vout;
        tx.num_vout = 1;

        /* Compute sighash over the redeem script */
        struct sighash_type ht;
        ht.raw = SIGHASH_ALL;
        struct precomputed_tx_data txdata;
        precompute_tx_data(&tx, &txdata);

        struct uint256 sighash;
        bool ok = signature_hash(&redeem, &tx, 0, ht, 100000000,
                                 0x76b809bb, &txdata, &sighash);

        /* Build scriptSig: OP_0 <sig1> <sig2> <redeemScript> */
        struct script *ss = &tx.vin[0].script_sig;
        ss->size = 0;
        ss->data[ss->size++] = OP_0;

        for (int i = 0; i < 2 && ok; i++) {
            struct privkey *key = (i == 0) ? &k1 : &k2;
            unsigned char sig[SIGNATURE_SIZE + 1];
            size_t siglen = 0;
            ok = ok && privkey_sign(key, &sighash, sig, &siglen);
            sig[siglen++] = 0x01; /* SIGHASH_ALL */
            ss->data[ss->size++] = (unsigned char)siglen;
            memcpy(&ss->data[ss->size], sig, siglen);
            ss->size += siglen;
        }

        /* Append redeem script */
        ss->data[ss->size++] = (unsigned char)redeem.size;
        memcpy(&ss->data[ss->size], redeem.data, redeem.size);
        ss->size += redeem.size;

        ok = ok && (ss->data[0] == OP_0);
        ok = ok && (memcmp(&ss->data[ss->size - redeem.size],
                           redeem.data, redeem.size) == 0);
        ok = ok && (ss->size > 100);

        /* Prove the completed input against the production consensus script
         * interpreter, not just by inspecting its byte layout. */
        struct script p2sh;
        script_for_p2sh(&p2sh, &sid);
        struct tx_sig_checker checker_ctx;
        tx_sig_checker_init(&checker_ctx, &tx, 0, 100000000,
                            0x76b809bb, &txdata);
        struct sig_checker checker = tx_make_sig_checker(&checker_ctx);
        ScriptError script_error = SCRIPT_ERR_OK;
        ok = ok && verify_script(ss, &p2sh,
                                 SCRIPT_VERIFY_P2SH |
                                 SCRIPT_VERIFY_STRICTENC,
                                 &checker, 0x76b809bb, &script_error);

        /* A signature-byte mutation must be rejected by the same checker. */
        struct script tampered = *ss;
        if (tampered.size > 10)
            tampered.data[10] ^= 0x01;
        script_error = SCRIPT_ERR_OK;
        ok = ok && !verify_script(&tampered, &p2sh,
                                  SCRIPT_VERIFY_P2SH |
                                  SCRIPT_VERIFY_STRICTENC,
                                  &checker, 0x76b809bb, &script_error);

        keystore_free(ks);
        free(ks);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 7. 1-of-2 only needs one key
     * ================================================================ */
    printf("multisig: 1-of-2 signs with one key... ");
    {
        struct basic_keystore *ks = zcl_malloc(sizeof(*ks), "test_ks");
        keystore_init(ks);

        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        keystore_add_key(ks, &k1);
        /* k2 NOT added to keystore */

        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script redeem;
        script_for_multisig(&redeem, 1, pks, 2);
        keystore_add_cscript(ks, &redeem);

        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 4;
        tx.version_group_id = 0x892F2085;
        struct tx_in vin;
        memset(&vin, 0, sizeof(vin));
        vin.sequence = 0xffffffff;
        tx.vin = &vin;
        tx.num_vin = 1;
        struct tx_out vout;
        memset(&vout, 0, sizeof(vout));
        vout.value = 50000000;
        struct key_id dummy_kid;
        memset(&dummy_kid, 0, sizeof(dummy_kid));
        script_for_p2pkh(&vout.script_pub_key, &dummy_kid);
        tx.vout = &vout;
        tx.num_vout = 1;

        struct sighash_type ht;
        ht.raw = SIGHASH_ALL;
        struct precomputed_tx_data txdata;
        precompute_tx_data(&tx, &txdata);

        struct uint256 sighash;
        bool ok = signature_hash(&redeem, &tx, 0, ht, 50000000,
                                 0x76b809bb, &txdata, &sighash);

        struct script *ss = &tx.vin[0].script_sig;
        ss->size = 0;
        ss->data[ss->size++] = OP_0;

        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        ok = ok && privkey_sign(&k1, &sighash, sig, &siglen);
        sig[siglen++] = 0x01;
        ss->data[ss->size++] = (unsigned char)siglen;
        memcpy(&ss->data[ss->size], sig, siglen);
        ss->size += siglen;

        ss->data[ss->size++] = (unsigned char)redeem.size;
        memcpy(&ss->data[ss->size], redeem.data, redeem.size);
        ss->size += redeem.size;

        ok = ok && (ss->data[0] == OP_0);
        ok = ok && (ss->size < 180);

        keystore_free(ks);
        free(ks);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 8. Deterministic: same keys produce same script and address
     * ================================================================ */
    printf("multisig: deterministic script from same keys... ");
    {
        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks[2] = { p1, p2 };
        struct script s1, s2;
        script_for_multisig(&s1, 2, pks, 2);
        script_for_multisig(&s2, 2, pks, 2);

        bool ok = (s1.size == s2.size) &&
                  (memcmp(s1.data, s2.data, s1.size) == 0);

        struct script_id sid1, sid2;
        script_id_from_script(&sid1, &s1);
        script_id_from_script(&sid2, &s2);
        ok = ok && (memcmp(sid1.hash.data, sid2.hash.data, 20) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 9. Key order matters: different order → different script
     * ================================================================ */
    printf("multisig: key order changes script hash... ");
    {
        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct pubkey p1, p2;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);

        struct pubkey pks_ab[2] = { p1, p2 };
        struct pubkey pks_ba[2] = { p2, p1 };
        struct script s_ab, s_ba;
        script_for_multisig(&s_ab, 2, pks_ab, 2);
        script_for_multisig(&s_ba, 2, pks_ba, 2);

        bool ok = (s_ab.size == s_ba.size) &&
                  (memcmp(s_ab.data, s_ba.data, s_ab.size) != 0);

        struct script_id sid_ab, sid_ba;
        script_id_from_script(&sid_ab, &s_ab);
        script_id_from_script(&sid_ba, &s_ba);
        ok = ok && (memcmp(sid_ab.hash.data, sid_ba.hash.data, 20) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 10. 3-of-3: solver extracts correct nrequired
     * ================================================================ */
    printf("multisig: 3-of-3 solver nrequired... ");
    {
        struct privkey k1, k2, k3;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        privkey_make_new(&k3, true);
        struct pubkey p1, p2, p3;
        privkey_get_pubkey(&k1, &p1);
        privkey_get_pubkey(&k2, &p2);
        privkey_get_pubkey(&k3, &p3);

        struct pubkey pks[3] = { p1, p2, p3 };
        struct script redeem;
        script_for_multisig(&redeem, 3, pks, 3);

        bool ok = (redeem.data[0] == OP_3) &&
                  (redeem.data[redeem.size - 2] == OP_3);

        enum txnouttype type;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions;
        ok = ok && script_solver(&redeem, &type, solutions, solution_sizes,
                                 &num_solutions);
        ok = ok && (type == TX_MULTISIG);
        /* solver stores m as raw integer, not opcode */
        ok = ok && (solutions[0][0] == 3);
        ok = ok && (num_solutions == 5); /* m + 3 keys + n */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
