/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical-mainnet evidence for transaction wire eras and output-script
 * classes.  Every fixture below is public chain data fetched read-only from
 * the operator's zclassicd oracle.  No wallet, key, address binding, endpoint,
 * or datadir material is present.
 *
 * ZClassic mainnet activated Overwinter and Sapling at the same height
 * (476969).  Consequently an Overwinter-v3 transaction has no height at which
 * it is mainnet-valid: before activation it is premature; at activation it is
 * rejected because Sapling v4 is required.  That absence is a consensus fact,
 * not a missing fixture.
 */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"

#include <string.h>

struct wire_evidence_case {
    const char *label;
    const char *raw_hex;
    const char *txid;
    int height;
    size_t output_index;
    enum txnouttype expected_type;
};

static const struct wire_evidence_case k_cases[] = {
    {
        "height-1 v1 P2PK coinbase",
        "0100000001000000000000000000000000000000000000000000000000000000"
        "0000000000ffffffff03510101ffffffff01807c814a00000000232102e26fa6c7"
        "08e0f65d4d56a2a49f4e71e0924a83f0a4c50430ecb996733923cf61ac000000"
        "00",
        "13e63618e0f7dd61ecbb3ee0607489ead19a10317c2311e50a72585643256f56",
        1, 0, TX_PUBKEY,
    },
    {
        "height-122001 v1 nonstandard coinbase",
        "0100000001000000000000000000000000000000000000000000000000000000"
        "0000000000ffffffff050391dc0100ffffffff01807c814a000000003f76a9148f"
        "1baca4c8101fc922dbe7e71906ba99b874b0dd88ac20f641541a30f91ea4ac209"
        "1af21573dbd03464ee045121049fc3fdb4b0c00000003f8da01b400000000",
        "c6b58ab4533eafd151b998c8b232d3910417ead11e916d04f7a633afc171e1cc",
        122001, 0, TX_NONSTANDARD,
    },
    {
        "height-255001 v1 P2SH payment",
        "010000000111ece7425f614ac71cf7a5dcecdf0dca58689e30afec4113f0146637"
        "751b5be0010000006b483045022100a6ca0cce9c1c035190db95a7602bc25553cb"
        "4cd7ec7dc46488b7cca01af9ff9902201892962be6da93ab19f9fb142dd6f30259"
        "226a14cfddcc4687fd7df540a9867d01210325eba70602dc0a03382b32278bc308"
        "9654f5f7175de0af70d0f7bbcf076e0490ffffffff02401ac8050000000017a914"
        "4761fe5dd794d2beda5b63d04cc96d8004029ada87c8060400000000001976a914"
        "ad1938e840e9203d503f4817686259f11619302488ac00000000",
        "b18c3f28d2d4867920a126d09f90e619f3e64e41cd31a7c9f9653b9adce60c83",
        255001, 0, TX_SCRIPTHASH,
    },
    {
        "height-3139216 v4 P2PKH coinbase",
        "0400008085202f8901000000000000000000000000000000000000000000000000"
        "0000000000000000ffffffff220390e62f04995e256a088e27ab4e000000002f"
        "7a706f6f6c2e63612f8e27ab4e2f00ffffffff01e40b5402000000001976a9144a"
        "440303eb700db2ed916471a063404e72f498d888ac000000000000000000000000"
        "00000000000000",
        "1765e9c9b0dbcbd9c9a968ea4f3c9c4b60d447d86c2583aa186e9a107c2e7c91",
        3139216, 0, TX_PUBKEYHASH,
    },
    {
        "height-3139216 v4 nulldata ZSLP transaction",
        "0400008085202f8901d839883da8a5a8dd18d5da638ff52cea7e0aa632b2eeaef1"
        "d7514a7bde0dcace000000006a47304402203266b749d3751272dfb12f4cd07ba0"
        "f1a4f8c68ad452afc4bb89ca538e565dea02206b5aeed6b84ca2be8ed7c1af149"
        "df5efe77b1889078fecb8dcfa4e4f3417f41e012103865d1685a99393c8f6a8aa"
        "0919164e88d5d3730c1634642fe02b17c9879b3342feffffff0300000000000000"
        "00546a04534c500001010747454e455349534c0011416c667265645f452e5f4e65"
        "756d616e6e4c0020b53519eb69b90922c9b80195103f0c2a28b1b5bb3f21f77a"
        "c4488274658b56c501004c0008000000000000000122020000000000001976a914"
        "aaab99c59845da48a1d71f49313555e4672d108588accc3e0f00000000001976a9"
        "148d0173a0b97cedc5da8ba9882c335017933ce3de88ac85e62f00b8e62f000000"
        "000000000000000000",
        "34ed27f1291a95c0f829c089522227bc30e4c215ac62b4e20a434179e36bd754",
        3139216, 0, TX_NULL_DATA,
    },
};

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex(const char *hex, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    size_t n = hex ? strlen(hex) : 0;
    if (!hex || !out || !out_len || (n & 1U) != 0 || n / 2 > cap)
        return false;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return true;
}

#define WIRE_CHECK(label, expression) do {          \
    printf("%s... ", (label));                      \
    if ((expression)) printf("OK\n");              \
    else { printf("FAIL\n"); failures++; }         \
} while (0)

int test_transaction_wire_evidence(void)
{
    printf("\n=== Canonical transaction wire/script evidence ===\n");
    int failures = 0;
    bool all_fixtures = true;
    bool saw_types[TX_NULL_DATA + 1] = {false};

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *params = chain_params_get();
    WIRE_CHECK("mainnet chain parameters are available", params != NULL);
    if (!params)
        return failures;

    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        const struct wire_evidence_case *fixture = &k_cases[i];
        uint8_t raw[512];
        size_t raw_len = 0;
        bool ok = decode_hex(fixture->raw_hex, raw, sizeof(raw), &raw_len);

        struct byte_stream input;
        stream_init_from_data(&input, raw, raw_len);
        struct transaction tx;
        transaction_init(&tx);
        ok = ok && transaction_deserialize(&tx, &input) &&
             stream_remaining(&input) == 0;

        char txid[65] = {0};
        if (ok)
            uint256_get_hex(&tx.hash, txid);
        ok = ok && strcmp(txid, fixture->txid) == 0 &&
             fixture->output_index < tx.num_vout;

        struct byte_stream output;
        stream_init(&output, raw_len + 16);
        ok = ok && transaction_serialize(&tx, &output) &&
             output.size == raw_len && memcmp(output.data, raw, raw_len) == 0;

        enum txnouttype type = TX_NONSTANDARD;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        size_t num_solutions = 0;
        bool standard = false;
        if (ok) {
            standard = script_solver(
                &tx.vout[fixture->output_index].script_pub_key, &type,
                solutions, solution_sizes, &num_solutions);
            ok = type == fixture->expected_type &&
                 (fixture->expected_type == TX_NONSTANDARD ? !standard
                                                            : standard);
        }

        struct validation_state structural;
        validation_state_init(&structural);
        ok = ok && check_transaction(&tx, &structural);

        struct validation_state contextual;
        validation_state_init(&contextual);
        ok = ok && contextual_check_transaction(
            &tx, &contextual, &params->consensus, fixture->height, 100);

        printf("canonical %s: exact wire, txid, class, and context... ",
               fixture->label);
        if (ok) {
            printf("OK\n");
            saw_types[fixture->expected_type] = true;
        } else {
            printf("FAIL\n");
            failures++;
            all_fixtures = false;
        }
        stream_free(&output);
        transaction_free(&tx);
    }

    WIRE_CHECK("canonical fixtures cover five observed script classes",
               all_fixtures && saw_types[TX_NONSTANDARD] &&
               saw_types[TX_PUBKEY] && saw_types[TX_PUBKEYHASH] &&
               saw_types[TX_SCRIPTHASH] && saw_types[TX_NULL_DATA] &&
               !saw_types[TX_MULTISIG]);

    WIRE_CHECK("mainnet Overwinter and Sapling activate together",
               params->consensus.vUpgrades[UPGRADE_OVERWINTER]
                       .nActivationHeight == 476969 &&
               params->consensus.vUpgrades[UPGRADE_SAPLING]
                       .nActivationHeight == 476969);

    /* Reuse a structurally valid canonical transaction and change only the
     * wire-era discriminator.  There is no mainnet height between these two
     * checks: v3 is premature immediately before activation and its group id
     * is invalid as soon as Sapling activates. */
    uint8_t v1_raw[128];
    size_t v1_len = 0;
    struct transaction v3;
    transaction_init(&v3);
    struct byte_stream v1_stream;
    bool v3_ready = decode_hex(k_cases[0].raw_hex, v1_raw, sizeof(v1_raw),
                               &v1_len);
    stream_init_from_data(&v1_stream, v1_raw, v1_len);
    v3_ready = v3_ready && transaction_deserialize(&v3, &v1_stream);
    v3.overwintered = true;
    v3.version = OVERWINTER_TX_VERSION;
    v3.version_group_id = OVERWINTER_VERSION_GROUP_ID;
    v3.expiry_height = 476969;

    struct validation_state before_activation;
    validation_state_init(&before_activation);
    bool rejects_before = v3_ready && !contextual_check_transaction(
        &v3, &before_activation, &params->consensus, 476968, 100) &&
        strcmp(before_activation.reject_reason,
               "tx-overwinter-not-active") == 0;
    WIRE_CHECK("v3 is rejected immediately before mainnet activation",
               rejects_before);

    struct validation_state at_activation;
    validation_state_init(&at_activation);
    bool rejects_at = v3_ready && !contextual_check_transaction(
        &v3, &at_activation, &params->consensus, 476969, 100) &&
        strcmp(at_activation.reject_reason,
               "bad-sapling-tx-version-group-id") == 0;
    WIRE_CHECK("v3 is rejected when Sapling activates on mainnet",
               rejects_at);
    transaction_free(&v3);

    printf("Transaction wire evidence: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
