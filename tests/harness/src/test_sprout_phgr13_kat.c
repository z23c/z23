/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Real Sprout PHGR13 proof KAT. Fixture source:
 * mainnet height 241, tx index 1, JoinSplit 0
 * txid 55c6c3a289d295954936076b697cc1e2a713c99dd268934f7ab6518f825148fd.
 *
 * This pins the consensus verifier's positive direction with no runtime
 * dependency on ~/.zcash-params or a node datadir.
 */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "sapling/bn254.h"
#include "sapling/params_vk_embedded.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"

#include <stdatomic.h>
#include <string.h>

extern const unsigned char g_fixture_tx_sprout_241[];
extern const size_t g_fixture_tx_sprout_241_len;

static const char k_vk_hex[] =
    "30075339600b17fb80cf0ccec8ef6c3b2fed8a11aa4902c53d8856170ffadd521b85c345f6a506f0d6e3b27f125faa49"
    "a9ef9d3db3ff2689d3347a442ee9eaff1731a578e3ee9e163bcbca51997cb2e2fb49f104ce0518d1ce2beded61e21306"
    "02dc24a1fac18d113c34055788b5ee6f6a11ba97ae0cb9459c16fc2ecc3218cc23303a8e887bbdfc498bb14cdb64cc6b"
    "607de4e1d5c26a75ca18132c223ddf7cd600da8f088769a26dbea6dc96d87a41afb71684ae7b038e6f0f939d59bf8dfa"
    "5228302d7c24407946a26a8c6f389e0ee14bd11ce97fccf1ab4a5b824e342b47327f2556e118981fbef18bc7cfd7f30f"
    "f567e8c9e64919dd75da16137ee89e9a87cd057a88077eb0d929a3d3a8f73f0b15138556ce6af8c9ba5b1b94f5de91ac"
    "1c9d00d77fe86aac855315f14601cbf65dbc88b1f0c349a89eb418eac9ebce8356212430c263c1c65e2a8f1d62326aef"
    "2fac469c8f6a3d423a1a7ff1013268c55ec48613ca3016259922434a2f2bc4855dc1bc423691052b476dd2acf0af46fa"
    "d1056a167cd78237ce5012a500c9243f285ac4fb8c347ab9db60cfcbf6deabb83aa8f61b9e91a8d44778294921f8e426"
    "3c14969d1226478c12e2399ce233aca9590ce103305d9ce6c7c60b5d10b0f1dc68ab00df0086514f50efbcdc6c9fe052"
    "3df384620fc636ed65d8ae3534026221fe882025fdc30491603063a906fad626215fce481e308abcb09f02b5039f386f"
    "4faeaa36f137881c362616febe860d6323dbbf86fd104075d97b500a79e320dd75ecc0b2c58b3475427acb54e11b74ba"
    "d90fed9b5b2dbcd2bbcd6c65ea7f489761c3c763e148279836f52043bcea1f69326d15b16309933f3ebe86893b45ee53"
    "0766dfd7ed0d34a471b76287cfce9e1b5f2bb3338e0530cb9c2c785bc6e595fab2f88e7bb28b64f9ec2e0740f85cae3e"
    "1c9e8dc8c2e222bac9484d6613a0acaf0d26696722e54e43461b87088a8f25337917b8f6fa47183fabc36fbf9c331ca6"
    "49a7e557ab9de807d4bfee81bcb1585e0007593bd4df2cea513db61df64c97ea4ab6a83b45fa633de421828969873299"
    "3f1dc41ecc062f30e1928e0bfee09197fd8822f6452babbbe23ece7d6662fa5a23911a28e45cca1dd32c956023379db3"
    "ff21bc3c960bcf57440d3fe0fe5ce4b84009bd6a3003621d390a390a300a310a320a330a340a350a360a370a380a390a"
    "30be3d3fc2b40b9013c1544902b487723032d643a294eae373d59f405178a23a1ff91cd0e4a8a0144c7dc9a99799b327"
    "3139469a8101c8c36011d42348675de1233082e4103de3b168c115ccbdf6b44426815c86587fb47ee75c418df1cab6fc"
    "c0088273e916a5f231c0abacf93a37de1c8cf3bbc373582f3dc0ddfc0d6a53ed32163047c206ca41f1c41a9ad27f5dca"
    "528c8df3cd6f34e2112d6c32b007334ee6dc1d7da438c99b616a2c5f35a39009229451c1fedbb3f932bec95b152ad3ce"
    "38740930ee7ed49f60a26d721ad55445f1a7c9c446055540b45b0e8e15f5d65a51e0c608ee442b59c0e7fcfffdd53c4d"
    "4fed0a69f8606278bc3d540e1ce1532c44a9a0233018df0778474b896bb3ca3dabd2fd5442bc0883123f57a36a2bcc89"
    "da98e805224befdd33f88789f70c695c861a102ddf7906e712bcd42bac0173964626e22a1d30a241be018dbe94b98166"
    "e8e660d2302b07000d006e16e20a53b72e9e6205462c432d6ba7258ae294bf8ffa5805fb27d58a1860e86cb91a1586de"
    "13a40a99d428304b674de60d25337258d2a26a3ca1848052acbe3a6a6a93103d881eab4d574a0ae2771d4dc7beb6df50"
    "8ccb5cdc0e4e72a43aff58446cef9665cd1abdd8a9b91e3082c8e21275fc3bf834f7ef333dda94c72949661ff54ee623"
    "0db3c16299a2d317bcefd810863d9c148a581d3e8adfa2cd4522934f7d42a7646f6b2c12ea6b152c300116b062e10223"
    "9a95afc4adb4937ffb825c6fb97ffd496285252208b7cce323dc38d4c7ee26ea33b048858606f070a95cde20ac251424"
    "d67e4d6382b1be0012";

static const uint64_t k_vpub_old = 1249990000ULL;
static const uint64_t k_vpub_new = 0ULL;

static const char k_proof_hex[] =
    "03285153c3029f3e5955395ca617498d8ae3db7d2c5904103f71b4d67ccc1e408a021e63826bac468e89a96f47d4878a"
    "775af18971b5b94167e3772402b735cac47b0a0521402661d91c8d7bd00ac04da33e6604c5d578f9d6317ecb0618d4f7"
    "a6755e94fca74453a74a328b09dc11831210442ed7ef2ebabcde71187f92f6be87455503201c1713b784fa09e5657a67"
    "a917515a9e833ab65c9a773e8f96993b4777de850309af0cb0a057a18c17e956d5db9066c2d38c4b885e3931f1f9cf8a"
    "1b380a7688032ec70722fff9ecd43afc06ee53a580cf6d139844f1bc7c6b0a1e762e64509417020ed0097f4ea82d6b1f"
    "ba4eb831743f1dfe220e48d26a356d2ba19345850cbb0a0312f3b2990da9df24195260c531b4b17c726cb9a2f03503ea"
    "16044cf9306e201f";
static const char k_anchor_hex[] =
    "d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259";
static const char k_hsig_hex[] =
    "ce79461df91ca43c3da7e715e43845fc7054b4cf8fc1291f72015bebc56e31cd";
static const char k_mac1_hex[] =
    "b65e0e165f5daef5311098467772c00486739c420f1c47d7ecf490cb5b1df051";
static const char k_mac2_hex[] =
    "957b152d1ce122fdbe75debbde06b3fb26264e2414939c62fb715a6bec723d4a";
static const char k_nf1_hex[] =
    "c2f4f6342207af5ffa181fb1d1b6bac3496f2ae476b55a4a1da0d7ff2584d34b";
static const char k_nf2_hex[] =
    "99fe254e53c66639a81140a64e277dfe3eaf251e302122794e3dc30d6e563b3b";
static const char k_cm1_hex[] =
    "869e92d09df2362aed6cb367554d94fa9ec2dd40211aef204e4a963fbb56bc04";
static const char k_cm2_hex[] =
    "dfee184b5cb8a50461ca21f0f409fd4a1b17d3139a367af95367556a9acf77e0";

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex_exact(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex || !out || strlen(hex) != out_len * 2)
        return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

#define KAT_CHECK(name, expr) do {             \
    printf("%s... ", (name));                  \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

int test_sprout_phgr13_kat(void)
{
    printf("\n=== Sprout PHGR13 real-proof KAT ===\n");
    int failures = 0;

    static struct ppzksnark_vk fixture_vk;
    static bool fixture_vk_loaded = false;

    uint8_t vk_bytes[1449];
    uint8_t proof[296], anchor[32], hsig[32], mac1[32], mac2[32];
    uint8_t nf1[32], nf2[32], cm1[32], cm2[32];

    bool decoded = decode_hex_exact(k_vk_hex, vk_bytes, sizeof(vk_bytes)) &&
                   decode_hex_exact(k_proof_hex, proof, sizeof(proof)) &&
                   decode_hex_exact(k_anchor_hex, anchor, sizeof(anchor)) &&
                   decode_hex_exact(k_hsig_hex, hsig, sizeof(hsig)) &&
                   decode_hex_exact(k_mac1_hex, mac1, sizeof(mac1)) &&
                   decode_hex_exact(k_mac2_hex, mac2, sizeof(mac2)) &&
                   decode_hex_exact(k_nf1_hex, nf1, sizeof(nf1)) &&
                   decode_hex_exact(k_nf2_hex, nf2, sizeof(nf2)) &&
                   decode_hex_exact(k_cm1_hex, cm1, sizeof(cm1)) &&
                   decode_hex_exact(k_cm2_hex, cm2, sizeof(cm2));
    KAT_CHECK("fixture hex decodes to exact byte lengths", decoded);
    if (!decoded)
        return failures;

    if (!fixture_vk_loaded) {
        fixture_vk_loaded = ppzksnark_vk_read(&fixture_vk, vk_bytes,
                                              sizeof(vk_bytes));
    }
    KAT_CHECK("embedded sprout-verifying.key parses", fixture_vk_loaded);
    KAT_CHECK("embedded PHGR13 VK has ic_len == 10",
              fixture_vk_loaded && fixture_vk.ic_len == 10);
    if (!fixture_vk_loaded)
        return failures;

    sprout_phgr_set_vk(&fixture_vk);

    KAT_CHECK("real PHGR13 proof verifies",
              sprout_verify_phgr13(proof, anchor, hsig, mac1, mac2,
                                   nf1, nf2, cm1, cm2,
                                   k_vpub_old, k_vpub_new));

    uint8_t bad_proof[296];
    memcpy(bad_proof, proof, sizeof(bad_proof));
    bad_proof[17] ^= 0x01;
    KAT_CHECK("flipped proof byte rejects",
              !sprout_verify_phgr13(bad_proof, anchor, hsig, mac1, mac2,
                                    nf1, nf2, cm1, cm2,
                                    k_vpub_old, k_vpub_new));

    uint8_t bad_nf1[32];
    memcpy(bad_nf1, nf1, sizeof(bad_nf1));
    bad_nf1[3] ^= 0x01;
    KAT_CHECK("flipped nullifier rejects",
              !sprout_verify_phgr13(proof, anchor, hsig, mac1, mac2,
                                    bad_nf1, nf2, cm1, cm2,
                                    k_vpub_old, k_vpub_new));

    /* Full canonical transaction: parser, structural rules, JoinSplit
     * Ed25519 signature, hSig derivation, and PHGR13 proof all run through the
     * production consensus entrypoints. Anchor membership and the transparent
     * input script require the preceding mainnet chain state and are therefore
     * deliberately outside this context-only fixture. */
    struct byte_stream stream;
    stream_init_from_data(&stream, g_fixture_tx_sprout_241,
                          g_fixture_tx_sprout_241_len);
    struct transaction tx;
    transaction_init(&tx);
    bool parsed = transaction_deserialize(&tx, &stream);
    KAT_CHECK("canonical height-241 transaction deserializes", parsed);
    if (parsed) {
        char txid[65];
        uint256_get_hex(&tx.hash, txid);
        KAT_CHECK("canonical transaction identity and complete wire are pinned",
                  g_fixture_tx_sprout_241_len == 2022 &&
                  stream_remaining(&stream) == 0 &&
                  strcmp(txid,
                         "55c6c3a289d295954936076b697cc1e2a713c99d"
                         "d268934f7ab6518f825148fd") == 0 &&
                  tx.num_joinsplit == 1 && tx.v_joinsplit != NULL);
        KAT_CHECK("canonical JoinSplit public inputs match the proof KAT",
                  tx.v_joinsplit &&
                  tx.v_joinsplit[0].vpub_old == k_vpub_old &&
                  tx.v_joinsplit[0].vpub_new == k_vpub_new &&
                  memcmp(tx.v_joinsplit[0].anchor.data, anchor, 32) == 0 &&
                  memcmp(tx.v_joinsplit[0].nullifiers[0].data, nf1, 32) == 0 &&
                  memcmp(tx.v_joinsplit[0].nullifiers[1].data, nf2, 32) == 0 &&
                  memcmp(tx.v_joinsplit[0].commitments[0].data, cm1, 32) == 0 &&
                  memcmp(tx.v_joinsplit[0].commitments[1].data, cm2, 32) == 0);
        struct validation_state structural;
        validation_state_init(&structural);
        KAT_CHECK("canonical Sprout transaction passes structural consensus",
                  check_transaction(&tx, &structural));

        /* contextual_check_transaction() now asks whether this process can
         * verify a shielded proof AT ALL before it tries: on a NULL VK it sets
         * local_fault and returns false with DoS 0, so an honest peer is not
         * charged for our missing keys. That gate reads sapling_params_loaded(),
         * which hand-publishing one PHGR13 fixture key does not set — so this
         * KAT was asserting against a process state no real node is ever in,
         * and read "the canonical proof fails consensus" when the truth was
         * "this process holds no verifying keys". Install the compiled-in set,
         * then re-pin the fixture key so the proof under test is still checked
         * against THIS file's VK. */
        (void)sapling_install_embedded_vks();
        sprout_phgr_set_vk(&fixture_vk);
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        int saved_defer = atomic_exchange(
            &g_deferred_proof_validation_below_height, -1);
        struct validation_state contextual;
        validation_state_init(&contextual);
        bool consensus_ok = params && contextual_check_transaction(
            &tx, &contextual, &params->consensus, 241, 100);
        atomic_store(&g_deferred_proof_validation_below_height, saved_defer);
        KAT_CHECK("canonical JoinSplit signature and proof pass contextual consensus",
                  consensus_ok);
        transaction_free(&tx);
    }

    printf("Sprout PHGR13 real-proof KAT: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
