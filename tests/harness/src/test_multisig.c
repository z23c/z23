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

/* Generates two fresh random keys and writes out their pubkeys. */
static void generate_two_random_pubkeys(struct pubkey *p1,
                                        struct pubkey *p2)
{
    struct privkey k1, k2;
    privkey_make_new(&k1, true);
    privkey_make_new(&k2, true);
    privkey_get_pubkey(&k1, p1);
    privkey_get_pubkey(&k2, p2);
}

/* Builds an m-of-n (n <= 3) multisig script from fresh keys and checks
 * its <OP_m> <pubkeys> <OP_n> OP_CHECKMULTISIG layout and total size. */
static bool multisig_script_layout_matches(int required, int total,
                                           int m_op, int n_op,
                                           size_t expected_size)
{
    struct privkey keys[3];
    struct pubkey pks[3];
    for (int i = 0; i < total; i++) {
        privkey_make_new(&keys[i], true);
        privkey_get_pubkey(&keys[i], &pks[i]);
    }

    struct script s;
    script_for_multisig(&s, required, pks, total);

    bool ok = (s.data[0] == m_op) &&
              (s.data[s.size - 2] == n_op) &&
              (s.data[s.size - 1] == OP_CHECKMULTISIG) &&
              (s.size == expected_size);
    return ok;
}

/* Checks script_solver classifies a 1-of-2 redeem script as TX_MULTISIG
 * with the expected number of solutions. */
static bool multisig_script_solver_detects_multisig_type(void)
{
    struct pubkey p1, p2;
    generate_two_random_pubkeys(&p1, &p2);

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
    return ok;
}

/* Wraps a 2-of-2 redeem script in P2SH and checks the script id
 * survives the base58 address encode/decode roundtrip. */
static bool p2sh_address_roundtrip_preserves_script_id(void)
{
    struct pubkey p1, p2;
    generate_two_random_pubkeys(&p1, &p2);

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
    return ok;
}

/* Checks a keystore can add, retrieve and refuse redeem scripts. */
static bool keystore_roundtrips_redeem_script(void)
{
    struct basic_keystore *ks = zcl_malloc(sizeof(*ks), "test_ks");

    keystore_init(ks);

    struct pubkey p1, p2;
    generate_two_random_pubkeys(&p1, &p2);

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
    return ok;
}

/* Allocates and initializes a keystore and generates two fresh keys. */
static struct basic_keystore *new_keystore_with_two_keys(struct privkey *k1,
                                                         struct privkey *k2)
{
    struct basic_keystore *ks = zcl_malloc(sizeof(*ks), "test_ks");
    keystore_init(ks);
    privkey_make_new(k1, true);
    privkey_make_new(k2, true);
    return ks;
}

/* Builds the minimal one-input/one-output Sapling tx the signing
 * tests spend. */
static void build_one_in_one_out_test_tx(struct transaction *tx,
                                         struct tx_in *vin,
                                         struct tx_out *vout,
                                         long long value)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 4;
    tx->version_group_id = 0x892F2085; /* Sapling */
    memset(vin, 0, sizeof(*vin));
    vin->sequence = 0xffffffff;
    tx->vin = vin;
    tx->num_vin = 1;
    memset(vout, 0, sizeof(*vout));
    vout->value = value;
    struct key_id dummy_kid;
    memset(&dummy_kid, 0, sizeof(dummy_kid));
    script_for_p2pkh(&vout->script_pub_key, &dummy_kid);
    tx->vout = vout;
    tx->num_vout = 1;
}

/* Precomputes txdata and returns the signature hash over the redeem
 * script for input 0. */
static bool compute_redeem_script_sighash(struct script *redeem,
                                          struct transaction *tx,
                                          long long amount,
                                          struct precomputed_tx_data *txdata,
                                          struct uint256 *sighash)
{
    struct sighash_type ht;
    ht.raw = SIGHASH_ALL;
    precompute_tx_data(tx, txdata);
    return signature_hash(redeem, tx, 0, ht, amount,
                          0x76b809bb, txdata, sighash);
}

/* Signs the sighash and appends <siglen> <sig + hashtype> to the
 * scriptSig under construction. */
static bool append_multisig_signature(struct script *ss,
                                      struct privkey *key,
                                      struct uint256 *sighash)
{
    unsigned char sig[SIGNATURE_SIZE + 1];
    size_t siglen = 0;
    bool signed_ok = privkey_sign(key, sighash, sig, &siglen);
    sig[siglen++] = 0x01; /* SIGHASH_ALL */
    ss->data[ss->size++] = (unsigned char)siglen;
    memcpy(&ss->data[ss->size], sig, siglen);
    ss->size += siglen;
    return signed_ok;
}

/* Appends <len> <redeemScript> to the scriptSig under construction. */
static void append_redeem_script_to_script_sig(struct script *ss,
                                               struct script *redeem)
{
    ss->data[ss->size++] = (unsigned char)redeem->size;
    memcpy(&ss->data[ss->size], redeem->data, redeem->size);
    ss->size += redeem->size;
}

/* Runs the consensus interpreter on the scriptSig, then checks a
 * mutated copy of it is rejected. */
static bool p2sh_script_sig_passes_interpreter(struct script *ss,
                                               struct script *p2sh,
                                               struct sig_checker *checker)
{
    ScriptError script_error = SCRIPT_ERR_OK;
    bool ok = verify_script(ss, p2sh,
                            SCRIPT_VERIFY_P2SH |
                            SCRIPT_VERIFY_STRICTENC,
                            checker, 0x76b809bb, &script_error);

    /* A signature-byte mutation must be rejected by the same checker. */
    struct script tampered = *ss;
    if (tampered.size > 10)
        tampered.data[10] ^= 0x01;
    script_error = SCRIPT_ERR_OK;
    ok = ok && !verify_script(&tampered, p2sh,
                              SCRIPT_VERIFY_P2SH |
                              SCRIPT_VERIFY_STRICTENC,
                              checker, 0x76b809bb, &script_error);
    return ok;
}

/* P2SH-wrapped 2-of-2: signs with both keys and proves the completed
 * scriptSig against the consensus interpreter. */
static bool p2sh_two_of_two_signs_valid_script_sig(void)
{
    struct privkey k1, k2;
    struct basic_keystore *ks = new_keystore_with_two_keys(&k1, &k2);
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
    struct tx_in vin;
    struct tx_out vout;
    build_one_in_one_out_test_tx(&tx, &vin, &vout, 100000000);

    /* Compute sighash over the redeem script */
    struct precomputed_tx_data txdata;
    struct uint256 sighash;
    bool ok = compute_redeem_script_sighash(&redeem, &tx, 100000000,
                                            &txdata, &sighash);

    /* Build scriptSig: OP_0 <sig1> <sig2> <redeemScript> */
    struct script *ss = &tx.vin[0].script_sig;
    ss->size = 0;
    ss->data[ss->size++] = OP_0;

    for (int i = 0; i < 2 && ok; i++) {
        struct privkey *key = (i == 0) ? &k1 : &k2;
        ok = ok && append_multisig_signature(ss, key, &sighash);
    }

    /* Append redeem script */
    append_redeem_script_to_script_sig(ss, &redeem);

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

    ok = ok && p2sh_script_sig_passes_interpreter(ss, &p2sh, &checker);

    keystore_free(ks);
    free(ks);
    return ok;
}

/* 1-of-2: signs a P2SH multisig input with a single key. */
static bool one_of_two_multisig_signs_with_single_key(void)
{
    struct privkey k1, k2;
    struct basic_keystore *ks = new_keystore_with_two_keys(&k1, &k2);
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
    struct tx_in vin;
    struct tx_out vout;
    build_one_in_one_out_test_tx(&tx, &vin, &vout, 50000000);

    struct precomputed_tx_data txdata;
    struct uint256 sighash;
    bool ok = compute_redeem_script_sighash(&redeem, &tx, 50000000,
                                            &txdata, &sighash);

    struct script *ss = &tx.vin[0].script_sig;
    ss->size = 0;
    ss->data[ss->size++] = OP_0;

    ok = ok && append_multisig_signature(ss, &k1, &sighash);

    append_redeem_script_to_script_sig(ss, &redeem);

    ok = ok && (ss->data[0] == OP_0);
    ok = ok && (ss->size < 180);

    keystore_free(ks);
    free(ks);
    return ok;
}

/* Builds 2-of-2 redeem scripts from two pubkey orderings and checks
 * the scripts and their script ids compare as the caller expects. */
static bool multisig_scripts_compare_as_expected(struct pubkey *pks_a,
                                                 struct pubkey *pks_b,
                                                 bool expect_equal)
{
    struct script s_a, s_b;
    script_for_multisig(&s_a, 2, pks_a, 2);
    script_for_multisig(&s_b, 2, pks_b, 2);

    bool ok = (s_a.size == s_b.size);
    if (expect_equal)
        ok = ok && (memcmp(s_a.data, s_b.data, s_a.size) == 0);
    else
        ok = ok && (memcmp(s_a.data, s_b.data, s_a.size) != 0);

    struct script_id sid_a, sid_b;
    script_id_from_script(&sid_a, &s_a);
    script_id_from_script(&sid_b, &s_b);
    if (expect_equal)
        ok = ok && (memcmp(sid_a.hash.data, sid_b.hash.data, 20) == 0);
    else
        ok = ok && (memcmp(sid_a.hash.data, sid_b.hash.data, 20) != 0);
    return ok;
}

/* Checks a 3-of-3 redeem script layout and its solver solutions. */
static bool three_of_three_solver_extracts_nrequired(void)
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
    return ok;
}

int test_multisig(void)
{
    int failures = 0;

    /* ================================================================
     * 1. script_for_multisig: 2-of-3 builds correct script
     * ================================================================ */
    printf("multisig: script_for_multisig 2-of-3 layout... ");
    {
        /* OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG */
        bool ok = multisig_script_layout_matches(2, 3, OP_2, OP_3,
                                                 105); /* 1 + (1+33)*3 + 1 + 1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 2. script_for_multisig: 1-of-1 minimum case
     * ================================================================ */
    printf("multisig: script_for_multisig 1-of-1... ");
    {
        bool ok = multisig_script_layout_matches(1, 1, OP_1, OP_1,
                                                 37); /* 1 + (1+33) + 1 + 1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 3. script_solver recognizes multisig as TX_MULTISIG
     * ================================================================ */
    printf("multisig: script_solver detects TX_MULTISIG... ");
    {
        bool ok = multisig_script_solver_detects_multisig_type();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 4. P2SH wrapping: hash160 + address encoding roundtrip
     * ================================================================ */
    printf("multisig: P2SH address roundtrip... ");
    {
        bool ok = p2sh_address_roundtrip_preserves_script_id();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 5. Keystore: add and retrieve redeem script
     * ================================================================ */
    printf("multisig: keystore add/get/have cscript... ");
    {
        bool ok = keystore_roundtrips_redeem_script();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 6. P2SH-wrapped 2-of-2 multisig signing
     * ================================================================ */
    printf("multisig: P2SH 2-of-2 sign produces valid scriptSig... ");
    {
        bool ok = p2sh_two_of_two_signs_valid_script_sig();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 7. 1-of-2 only needs one key
     * ================================================================ */
    printf("multisig: 1-of-2 signs with one key... ");
    {
        bool ok = one_of_two_multisig_signs_with_single_key();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 8. Deterministic: same keys produce same script and address
     * ================================================================ */
    printf("multisig: deterministic script from same keys... ");
    {
        struct pubkey p1, p2;
        generate_two_random_pubkeys(&p1, &p2);

        struct pubkey pks[2] = { p1, p2 };
        bool ok = multisig_scripts_compare_as_expected(pks, pks, true);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 9. Key order matters: different order → different script
     * ================================================================ */
    printf("multisig: key order changes script hash... ");
    {
        struct pubkey p1, p2;
        generate_two_random_pubkeys(&p1, &p2);

        struct pubkey pks_ab[2] = { p1, p2 };
        struct pubkey pks_ba[2] = { p2, p1 };
        bool ok = multisig_scripts_compare_as_expected(pks_ab, pks_ba,
                                                       false);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 10. 3-of-3: solver extracts correct nrequired
     * ================================================================ */
    printf("multisig: 3-of-3 solver nrequired... ");
    {
        bool ok = three_of_three_solver_extracts_nrequired();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
