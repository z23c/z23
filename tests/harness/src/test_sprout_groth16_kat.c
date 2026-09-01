/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Real post-Sapling Sprout Groth16 proof KAT. Fixture source:
 * ZClassic mainnet height 476970, tx index 1, JoinSplit 0,
 * block 000000002ef6ebe979c451adfa9508121d216ac861ee12576015b5cae8d3733c,
 * txid 6eb069da34331871a55314ec3b92fcf50d8fabe914d16c46d686be853c8a3047.
 *
 * The embedded verification key is the 1,828-byte public VK prefix of the
 * canonical sprout-groth16.params file (868 fixed bytes + 10 IC points).
 * No proving material, wallet data, or private key is present.
 */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "sapling/bls12_381.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sprout.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"

#include <stdatomic.h>
#include <string.h>

static const char k_tx_hex_0[] =
    "0400008085202f890e1cd1d9052affaefe627346cd54d7ba2a4d0f54825c4ad981edb95b8f25775029000000006b4830"
    "4502210098c961251b7a5a16a5573ad8dd2c1deffbf252d6ec74e8ce27e7d355884d325b02204331f58849b79df7afc3"
    "fe74dc8eba646e344e760ee75ec7c0c28712defc3b1e01210297152abe74cd2eb0bb7622b7273895344974d641dca0bf"
    "f159f7bb906bb93942ffffffff2377935ff7be32d02662b554c9f68781cfa69bb0d4bfadef21fbc6069e6f3c80000000"
    "006a473044022039b06d0c5496b526e7e3c0eec1406f24d55e613d94f8753e3fe0308be028d2c802202e7ca9d52bdbaa"
    "fae8ef41dad3f8d5795768a6050676ab9665c6c8ad097379b401210297152abe74cd2eb0bb7622b7273895344974d641"
    "dca0bff159f7bb906bb93942ffffffff2bcceebd3b01e7d0ce6902dc59b9771340efe6ed750f776289b2e9d64587a086"
    "000000006a47304402204a2fcccc5e372cc08ade62d8cedece2a4a9636806352ab2f036d151163a24b030220649f846b"
    "6014b942dc91448d0455d4bc67566354bea92cf0d9345758cd3089f301210297152abe74cd2eb0bb7622b72738953449"
    "74d641dca0bff159f7bb906bb93942ffffffff2ff8e06bf043b3c4d649e46215d6fce633652bf8a417e302cfecf903d7"
    "02fda9000000006b48304502210090ecf34cfe7f1167c4b654a4a514b5274a2b679df09db5483836439e991decd50220"
    "59e16bcdb08592f69d50a1ca43e61982470f5f89cc9194d0665bd372e927b6cf01210297152abe74cd2eb0bb7622b727"
    "3895344974d641dca0bff159f7bb906bb93942ffffffff37654cad5f6ba5d891886b4f42cd1bb89aca012a9f554f6aa9"
    "c66d107cfa1462000000006a473044022071a13cc603276fa6120a80371df40ac4d618673440a87b87e325b95fafbe8b"
    "570220514fcef6cee11f84fc05de2a2e5a598168681a5e63e2076940d659a4a433c29901210297152abe74cd2eb0bb76"
    "22b7273895344974d641dca0bff159f7bb906bb93942ffffffff4f37c9d9cc9801cc373a822f520cd6ec8dd570604e91"
    "f4eed91f0cc5b7c01c0a000000006b483045022100aff56d4bfef02391ab8304708b01ebbd62e767503f7b92bfaeb880"
    "9bbce395c80220324770f6fa44f8fb4fbf176837862bad2058393bf2869bc6fbe77949ba0ff7f901210297152abe74cd"
    "2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffffff5e7e2fd7ff103bee38be6748b55d081fb666"
    "dfe72d11f21d1af339f0fdee617e000000006b4830450221008eab1db40643bbb853204ecbeda5c67846665318a0c853"
    "fbf69f80bfacb4a65a0220454e6085c23c6568eb4edcdf4fae439450d7c3793c80ffa107d1e6a2de9212230121029715"
    "2abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffffff67847d3fd7814537a11036daebd5"
    "e209d8a15d80b0dae8bc750ce304fe5036fd000000006b483045022100ea1f17e4ca8d5796505865f0869bfb01629e13"
    "44b3e951ff40aad190868deb1d02200b0b2e559f38eed70d5b76b1bedabe3d26c64dc7337c00523cf00662926a630b01"
    "210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffffff7987dbe8297cd403d3e5"
    "39caa634c2ac4a51323aa466d9d0b6b55d6b7cf76aa9000000006b483045022100e7d875f19086240b642ac18deb1b73"
    "3d870966a1789d5971c02daa05df9ecb42022008cd8b8816255ede1594535d07564975190857f7f1b8303b8dc5989c62"
    "89c88b01210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffffff983957174859"
    "ee635f05f856cef4c6318722ab6d206e3fa999762d3da061e3ac000000006a47304402206f69ef7ad8413b1cc4b66fd0"
    "eeb7334e872a47ef74d00b87cc43cf2177e94f3102207066f764f2908eb56edc6165a702e63ea3fc7b5ed84f63b6ae62"
    "1cb40218a8a601210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffffffbcfa71"
    "f8a3172cf92461d7ff481c913e9ffbc91e42a7ecab1ccffa244273f0a8000000006b483045022100b15774e9461c59ee"
    "cb99ca7cf7bd2ef542d1c32895f7f6742c1930b818a57f2b022020c5326283f5a7ac2b68546acf4a30f6a8f4d48ce722"
    "82766ade509a94bc88ff01210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb93942ffffff"
    "ffbf1a2adacc4fb07e1b8ddb973543b9233fe43a867a8df0ea0dab04f60e44d2df000000006b483045022100aa3e1095"
    "d4f7718cd61bcb7e59e867a6b13e464197d4567261b753d5b5fa467e02203ffac4203610c1b7d839d565033e5e7336bc"
    "e4bbe39725925807e356c16e867b01210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb906bb939"
    "42ffffffffd4a229804a4512952797df086e357195aa45eb54dff1a2372b84838583dc171a000000006b483045022100"
    "c26143650361a814c2debfe3bffe8eba4218adb34600b0ec1c045672e51b56fb02202bf40385f0b13766f3f43e12bfa5"
    "80b64308900ef5997f0b513a44105bd50b3901210297152abe74cd2eb0bb7622b7273895344974d641dca0bff159f7bb";

static const char k_tx_hex_1[] =
    "906bb93942ffffffffd7e94a5720b4a660e6ee789410b1fbef22ce26a9bdce13371e757a6abc903003000000006a4730"
    "4402206d5bd106e1ff2ef1d261b78aa5bbe8db4ff7826b3340816a15e92e1704d9f44f0220713feb2c775d1cce8c60c0"
    "7870655551c71b14d686c2d20621cf162da3be25bc01210297152abe74cd2eb0bb7622b7273895344974d641dca0bff1"
    "59f7bb906bb93942ffffffff00000000003e470700000000000000000000000197b51813040000000000000000000000"
    "fb3a59d34477c18e0d90d1f481613bcbbddb87ab6b5951e85ce60a0faee1688c8a882422937a424f149e348ddb887fdd"
    "4e4a3441eca3ae82b8e590a9aa813e4db64714ff501ec38f491286fcb2a0953e15ac4d956b29caa09b79c96f2094e9cb"
    "1c4ae37713057cb4139f19149c50bf2ca60fd46509792641e77578130c0297fd79a90ff6e0a293c8a5d9bfe618bc2f35"
    "f9508263c8975dee5a18df168d7acf084e4eb9eb885504e63d6037f7ee2fbab5223bf71f93069e4a98c45878a197e403"
    "2a587f780e543094f39950115035ae93574b7126b8daede92debc0caef344acd5cb69c48c7855744fddb28f0909a89a9"
    "ef7d604509e6dd6f41bab7b4fd407f37d301b77a2423808dfe53538f6fa328b41214474db22b948cbded6e04986fe8b5"
    "80c6555e6b7bf4098c53ee727dd055bd769d1080a535fc8991655632128df1e6aab613ddb9b5c53adb42d3b5b8d662f5"
    "b607a1155a3a6487cbd15de351794a472f68f0b23688051a25cf0fc3ce4ccc5d1b1d4f0ed39d42f0310fbc01f424ce49"
    "0eb60fcda47a7209d80103fd5f09cb4b659802ee3211d4bcb9d51dc7c49fea8251be60ae2890b8bec31e82012f9992fa"
    "80ded9b62a98db0ecff758934714c2755cac67ba641ba0c2c565c2e19ffbb6b370a932ee7f381ed36050b89598831887"
    "f4ccb4af563447cb180ee66645dda0b859602e860035db0c2b274866fd8f50beb40ccb248717745134bfb34567a491fa"
    "659f94e2184451cf69fa389096636d33c166431dbfa4652542164f8218d76f48e7801a601b8d52b0329e366aeaeef02e"
    "f3fd67f3dfa634e0f477e361356f5207714166cda62ab2f7d2b9e9ac5d8efc3e48b6807873ced87e70cce0cd6d5865ab"
    "1f786a0f44b47174edbf8624646d09f33f827dd8bfedf6f8abed03b9aa7b2d952c64f89e8382d1518e552d6cd0744435"
    "5613ec3db7efdc6927249016c312ff943085860e2cfc530fd81784df3dc264cfc78d5bd791bc4a1a366fc65372829e70"
    "961be89b2dd071a05917a5bf58451c19ea3861c55e06ddbd8d965894d77e36e96da3ddad49321f92ffe97d074a1b8c2c"
    "913facc13c27f1a1fbddb0aca5fb437f8b5c4dc3d000d26a472ab5a01bb7fd68fc8e783792c81b1422ceb2ad707eb188"
    "8a82a56d9e8efc6cc938f2a6344a3e5fdcd8f146a36d410048875d2c19c50616c99fa66f62374dec1dddf5a20bbf9606"
    "91db1861aaae3fd06b8466ec62fe1a2f3486659d3e4faed54dd5566df460931d9f92850bb5c80ad55d50274c9411033a"
    "006483407293dc232a73dfda43026d6ddd0095d3a0ebd569df3c897a816f4c0d55feb96b28768f181703b8fdea33486b"
    "43da1bf65dbb71622b501bce21098b11c35a09cfa2e568d238a73a8f88b1ba340abc45da930362189f5071b1c2c56224"
    "fa3ac860da51df8727630b331fb2d6723e361327622441fa8bd10ae78840b55ac2b1f11fecc828e0441876e318f33924"
    "d846607e8bb44a2938bd2d6ff9ea81d18147ae013f59d3461f03fa545e2a8033a6104b60486dd1e6b02139c3556d150e"
    "49999082d13d9f3440fedfbb17955a82c4bf4c9b8f75a248865eb31df780e22d6b08069c9df4c5c69d3e2a7458e946f5"
    "fc90272032519f4f70c176c33d263d15da82886d8d861b171b95cf2ca91a3ed05292abd6fe68fd9684e3dc4b7e347b3d"
    "5b2a9630441c2b581687578b07559c8d2572199aaf98f5dcc0da570a5fe0e88737b4c0d63b712ca7b1f7cf6247d9acb9"
    "90e77be784676c9cf134bb3230ac14da79676b09f3254e0a2304962d45c2d8e63825f64d719c72d51c5a58082432ac4c"
    "3b2386db55868acef310e253dbb8466df09d94653f85e7d99c83cf3d2847156ed25bc605ad09cdd4ae96fd001ac4a385"
    "72327866cce6149856cb911cb753b3e678555c77685444d60e116cfd8569a8fd8abfcc13d9a3c717e628470ed42a6088"
    "0cb4506b0c32d9d90287f6fddd85efd6956c028c423c8e627cb3dbd26b87e4c48166cef7c9722ce68ff09b7aa7d23fab"
    "35ec1d4a0878e898547c9135e97d9c9ba8941c2605ab796a5e6bf6bcc34d2269015f19b056d7fad6e97a6516b4318205"
    "85ff13785f743a0a283a455499dad09cb47791b03ab7ab5313d00f7bca247e9514c0a4a709ae5d3df307a4ff29d5e499"
    "22265cbed53dd127cf2cc44793eff06b1373923b83225e2b75efd447a86b5cfc06503171bc37b2592c29169a36b71e30"
    "f3480e664b0fbd0cf53686589e471bfefc1941ef6d3f406008fdf21a0b16698e57e83bf950ba0c8ac939d864812e9fc8"
    "75b6371a5f316109208d6275d7fcea20a640c17947aceb341ec185620dc55ea3543d9f0fadcad7a23eda7854d3275c0c"
    "aad88c3e4d3aa842265b0040e670327c7b269cf7042af50b640d463356339c3c0d2eeb023744980a1f0b589a33a66c61"
    "e81f1cb1f324733487f0cfab5b7800de8fe041f4512e39b38d406bb84e8f1907336e01b51147cf08658b3c56885c1831"
    "4303";

static const char k_vk_hex[] =
    "0db882cf5db3e8567f16b4db1772d4d1f5a3fe8d62f0df2eb8a5cfa50806702afde8fc25335eb5ec859c2818b2610b2e"
    "19ab445dac720bb1f2b0cd3336f7a1acc62bf1b3a321826264dc7e469281e23b218394d598689da04e136878ff9a7897"
    "014a78a8d17180a37c4ca8fb231f264ab89bd14863777fc1ffe901fd92444365d18f78237612ac38e39f419c32f08245"
    "15219ec45c26c1fad530514ed891a0d0043acedf348922102e95b3e6d07e0afa94c58aa41480631fc1ca36e55aae51fd"
    "0a416b8187450b28f025c421e3ff14d38f9abd9af2f1046b914b53ab37e9aebba683cb25284e5c22fa341129985250a1"
    "03547de5d005df48265f7cb258162253d56fbc682d106a1ecb07666ebf7524a364e512c37aa62f82d6e7dd4ed8838478"
    "104376a98072766c29959358e9cde6a4985618f65ea257e8f288974f4aedde52e5dac2fb7ae5d30eab7cd828a2c8b15f"
    "15b16f139f2c33ef33d63befe404e696c97077d17ea42f4ff9d82ec456aaf43914a3d07968111a3a348f157e64c0278a"
    "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
    "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
    "163a172acc0b2c767845cfbd68b1d833c0339ac63cf9e3ed1118da02b49e4c52f519fa66132d905a832db41dd6016922"
    "15d8a41d6a57d05dd805a02eb757a3368bd5d1ff128a6fb12a0476bc197b0e8b6ccfb87ac654ed63d38c6892eea8a30d"
    "0b1463b9bac462399c6f68c288f3b011ece2f6373b93e3fadb54dc942d507bcda05a890d560ae31b2fe6335c9a20545d"
    "0cc178cc2059a2ed2310ef82009f8ccd9626461349826dba59d3c472c4e714e8627415b0e721423979b63f92d487b472"
    "02fd41281149bc3ac44efacb4cb9a5e08f94a501df13839b119340db136ae7b429286f7badb76ec1ad5cb6a82aba8013"
    "03d215102021c0b077499892e9e395ce26379b791f3aa24332244af952bd63d8b88d3f65b13e72189d2aec114a95eabe"
    "0000000a0d97f9bc23442f2ad8102c99be160c76f4acbbe094c83dac8842ea5852ee8906c69e5c591086aa4c45f29c75"
    "bc53dd460174af2943249b84206d65c7541c826b3c51ef10f8ef866d7c456c8aecb52e5ff49befe4f03a8c29e3c5d18a"
    "de6f41fd0e0c186c0a4b6a5439c155f0470f5e858a69103593ed0cea4924ee402b5fffac8c6cce307265ef0a7fd3f3d9"
    "43dd40a201ab5bdc58bd06f03b6e506c4505fb0e60c425b648c7e9b770c338aa47dfe68b512a601266adcacb026bf92b"
    "0ad545ef019e822cf432de2712476848e4973be485f2dab7b7b2c61806132cd823a008b6c3040aa64566fa7e4a36a082"
    "c11626990a5a402a52d7c9a4a583b534b78436fcc9e54b31ad0d228a12e4a7fd4846f7f1daf4e9de5cb4a81cc5edda80"
    "942be9f401378546aae41ca23490479020f4c606830d3d52e1202ca591bfe697b570347096e21bd63406cba5513155c2"
    "8e03f3dc0ddd3f9c14a6e4ae0a4b8db973b7f913fb5b419fc8e3c1e829b1468e6e389df38ada375f86285a30519c107d"
    "6b5bfb600c46d90dc5a2cda86f764b71d965e7ede02b7f3ae750484d8abda3adee364ffda5929a24029fcfc012957720"
    "eaf4f1960ff515e37dc31c9db3adde517d7fb0ce3f1dd151611529715994d98485f2cae57f36a0e7a472c891b059f596"
    "59bbc04b0a96b78180f7191125f5e064a22abff870275163a66f9805e741d8b578ec52df3cf18bb548a9b9477e7c257d"
    "8f3b7b69153d0c6dd9a29d335e9d04843413c90f04908f6a7458a73d3839962872e294c9e57c1e8c440b36a110b7e3a8"
    "9783caa917ae7a0bf88c71915691a2a39bd4286a4b7413af95dbcb9243dd3d5e2c10d5631485d6f6950e667cad9ae32d"
    "d2bd6128103707248c026256835c920c2b063a365940ee1d5ae499679dea872eb4aa3e276fbc8ecb7c2954e32311e8ff"
    "14c20859055d14d652bc8eda7f6b2e8cd4684c8af8a5e56fdfd00cd790b718b535f3b0717c065c4cb678105448b5fecf"
    "77d003030c8347c8764d2a7595e87632ab7ece577dff40d78235f96b38b5e200b8c945eceb153b28c0436732360e3872"
    "4d8f2f9801abb94269630f88638f72caac370308512a1d00743c4e3eb73992fca590c811580bee7d53bf375627b02bac"
    "a5c8f82e02ca79f2de40bcf0dffa4c2e6f89aff5c59c9f0cad78a0e31b3c2846143ecdb726bddc76dcd3ecd9fa140e42"
    "985801b918d405db3a6c7fd359c38632a917587ad836cc9f1dc13040b55e0751afe6e1c2369b33c96ac61f1fb1e25bf2"
    "021b630819808298f2d82910dce519ebf1db6fbd6f9f965d8e075d65b5025dc13a7d92f73e15a6bbbaa1134c494ac8de"
    "335110bb";

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

int test_sprout_groth16_kat(void)
{
    enum {
        TX_BYTES = 3890,
        TX_HEX_0_BYTES = 1920,
        VK_BYTES = 1828,
        MAINNET_HEIGHT = 476970
    };
    printf("\n=== Sprout Groth16 real-proof KAT ===\n");
    int failures = 0;
    uint8_t tx_bytes[TX_BYTES], vk_bytes[VK_BYTES];
    bool decoded = decode_hex_exact(k_tx_hex_0, tx_bytes,
                                    TX_HEX_0_BYTES) &&
                   decode_hex_exact(k_tx_hex_1,
                                    tx_bytes + TX_HEX_0_BYTES,
                                    sizeof(tx_bytes) - TX_HEX_0_BYTES) &&
                   decode_hex_exact(k_vk_hex, vk_bytes, sizeof(vk_bytes));
    KAT_CHECK("canonical transaction and public VK decode exactly", decoded);
    if (!decoded)
        return failures;

    static struct groth16_vk fixture_vk;
    static bool fixture_vk_loaded = false;
    if (!fixture_vk_loaded)
        fixture_vk_loaded = groth16_vk_read_raw(&fixture_vk, vk_bytes,
                                                sizeof(vk_bytes));
    KAT_CHECK("embedded Sprout Groth16 VK parses",
              fixture_vk_loaded && fixture_vk.ic_len == 10);
    if (!fixture_vk_loaded)
        return failures;
    bool verification_set_ready = sapling_params_loaded() ||
                                  sapling_install_embedded_vks();
    KAT_CHECK("hash-pinned shielded verification set is published",
              verification_set_ready);
    if (!verification_set_ready)
        return failures;
    /* The contextual verifier now correctly requires the complete published
     * key set. Override only its Sprout member with this independently decoded
     * canonical fixture after satisfying that production precondition. */
    sprout_set_vk(&fixture_vk);

    struct byte_stream stream;
    stream_init_from_data(&stream, tx_bytes, sizeof(tx_bytes));
    struct transaction tx;
    transaction_init(&tx);
    bool parsed = transaction_deserialize(&tx, &stream);
    KAT_CHECK("canonical height-476970 transaction deserializes", parsed);
    if (!parsed)
        return failures;

    char txid[65];
    uint256_get_hex(&tx.hash, txid);
    KAT_CHECK("canonical v4 JoinSplit identity and wire are pinned",
              stream_remaining(&stream) == 0 &&
              strcmp(txid,
                     "6eb069da34331871a55314ec3b92fcf50d8fabe914d16c46d"
                     "686be853c8a3047") == 0 &&
              tx.overwintered && tx.version == SAPLING_TX_VERSION &&
              tx.version_group_id == SAPLING_VERSION_GROUP_ID &&
              tx.expiry_height == 476990 && tx.num_vin == 14 &&
              tx.num_vout == 0 && tx.num_joinsplit == 1 &&
              tx.v_joinsplit && tx.v_joinsplit[0].use_groth &&
              tx.num_shielded_spend == 0 && tx.num_shielded_output == 0);

    struct byte_stream encoded;
    stream_init(&encoded, sizeof(tx_bytes));
    bool roundtrip = transaction_serialize(&tx, &encoded) &&
                     encoded.size == sizeof(tx_bytes) &&
                     memcmp(encoded.data, tx_bytes, sizeof(tx_bytes)) == 0;
    KAT_CHECK("canonical v4 transaction reserializes byte-identically",
              roundtrip);
    stream_free(&encoded);

    struct validation_state structural;
    validation_state_init(&structural);
    KAT_CHECK("canonical v4 JoinSplit passes structural consensus",
              check_transaction(&tx, &structural));

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *params = chain_params_get();
    int saved_defer = atomic_exchange(
        &g_deferred_proof_validation_below_height, -1);
    struct validation_state contextual;
    validation_state_init(&contextual);
    bool consensus_ok = params && contextual_check_transaction(
        &tx, &contextual, &params->consensus, MAINNET_HEIGHT, 100);
    atomic_store(&g_deferred_proof_validation_below_height, saved_defer);
    KAT_CHECK("canonical JoinSplit signature and Groth16 proof verify",
              consensus_ok);

    struct js_description *js = &tx.v_joinsplit[0];
    uint8_t h_sig[32];
    sprout_h_sig(js->random_seed.data, js->nullifiers[0].data,
                 js->nullifiers[1].data, tx.joinsplit_pubkey.data, h_sig);
    KAT_CHECK("canonical Groth16 proof verifies directly",
              sprout_verify_groth16(
                  js->proof, js->anchor.data, h_sig, js->macs[0].data,
                  js->macs[1].data, js->nullifiers[0].data,
                  js->nullifiers[1].data, js->commitments[0].data,
                  js->commitments[1].data, js->vpub_old, js->vpub_new));

    uint8_t bad_proof[GROTH_PROOF_SIZE];
    memcpy(bad_proof, js->proof, sizeof(bad_proof));
    bad_proof[17] ^= 0x01;
    KAT_CHECK("flipped Groth16 proof byte rejects",
              !sprout_verify_groth16(
                  bad_proof, js->anchor.data, h_sig, js->macs[0].data,
                  js->macs[1].data, js->nullifiers[0].data,
                  js->nullifiers[1].data, js->commitments[0].data,
                  js->commitments[1].data, js->vpub_old, js->vpub_new));

    uint8_t bad_nullifier[32];
    memcpy(bad_nullifier, js->nullifiers[0].data, sizeof(bad_nullifier));
    bad_nullifier[3] ^= 0x01;
    KAT_CHECK("flipped public input rejects",
              !sprout_verify_groth16(
                  js->proof, js->anchor.data, h_sig, js->macs[0].data,
                  js->macs[1].data, bad_nullifier,
                  js->nullifiers[1].data, js->commitments[0].data,
                  js->commitments[1].data, js->vpub_old, js->vpub_new));

    transaction_free(&tx);
    printf("Sprout Groth16 real-proof KAT: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
