/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * BLAKE3 known-answer test against the OFFICIAL vectors
 * (BLAKE3-team/BLAKE3, test_vectors/test_vectors.json): every input is the
 * repeating 251-byte pattern 0,1,...,250,0,1,...; the keyed key is the
 * 32-byte ASCII "whats the Elvish word for friend"; the derive_key context
 * is "BLAKE3 2019-12-27 16:29:52 test vectors context".
 *
 * Why vectors and not parity: BLAKE3 has no second in-tree implementation to
 * differential against. The transport lane (docs/work/WIRE_COMPILE_CACHE.md)
 * will verify package transfers chunk-by-chunk with this code, so the tree
 * logic — chunk boundaries (1023/1024/1025), tree shapes (2048/2049, 3072,
 * 31744), the counter-mode XOF extension, keyed and derive-key domains — is
 * guilty until proven byte-identical to the designers' published answers.
 *
 * Legs:
 *   1. Standard 32-byte digests for ALL published input lengths, in all
 *      three modes (hash, keyed_hash, derive_key).
 *   2. Extended 131-byte outputs (XOF) for tree-shape-discriminating
 *      lengths: empty (single root compression), 1024/1025 (chunk
 *      boundary), 2048 (exactly two chunks — the root must be the parent
 *      of two chunk CVs, not a parent over an empty trailing chunk), and
 *      102400 (deep tree) for hash; empty and 1025 for keyed and
 *      derive_key.
 *   3. Streaming differential: the same input hashed through irregular
 *      update sizes (including zero-length updates) must equal the one-shot
 *      digest, for lengths that cross chunk and block boundaries.
 *   4. Final-is-repeatable: a second blake3_final call on the same hasher
 *      (131 bytes after 32) must extend, not change, the digest.
 *   5. Teeth: the hex comparator must catch a planted one-nibble mismatch —
 *      a hollow comparator passing every vector is worse than no test.
 */

#include "crypto/blake3.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KAT_MAX_INPUT 102400
#define EXT_LEN       131

static const uint8_t kat_key[] =
    "whats the Elvish word for friend";
static_assert(sizeof(kat_key) == BLAKE3_KEY_LEN + 1u,
              "official BLAKE3 test-vector key must be exactly 32 bytes");
static const char kat_context[] =
    "BLAKE3 2019-12-27 16:29:52 test vectors context";

struct kat_row {
    size_t input_len;
    const char *hash;       /* first 32 bytes, 64 hex */
    const char *keyed_hash;
    const char *derive_key;
};

/* Official vectors, standard 32-byte outputs. */
static const struct kat_row kat_rows[] = {
    { 0,
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
      "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
      "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d" },
    { 1,
      "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
      "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
      "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c" },
    { 2,
      "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
      "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
      "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6" },
    { 3,
      "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
      "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
      "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797" },
    { 4,
      "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
      "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070",
      "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060" },
    { 5,
      "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2",
      "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461",
      "1f24eda69dbcb752847ec3ebb5dd42836d86e58500c7c98d906ecd82ed9ae47f" },
    { 6,
      "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844",
      "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6d",
      "be96b30b37919fe4379dfbe752ae77b4f7e2ab92f7ff27435f76f2f065f6a5f4" },
    { 7,
      "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe",
      "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a",
      "dc3b6485f9d94935329442916b0d059685ba815a1fa2a14107217453a7fc9f0e" },
    { 8,
      "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
      "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600",
      "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940" },
    { 63,
      "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
      "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
      "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3" },
    { 64,
      "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
      "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
      "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e" },
    { 65,
      "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
      "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
      "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8" },
    { 127,
      "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
      "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818",
      "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3" },
    { 128,
      "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
      "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec",
      "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225" },
    { 129,
      "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
      "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f",
      "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1" },
    { 1023,
      "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
      "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
      "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5" },
    { 1024,
      "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
      "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
      "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706" },
    { 1025,
      "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
      "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
      "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb" },
    { 2048,
      "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
      "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
      "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23" },
    { 2049,
      "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
      "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
      "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273" },
    { 3072,
      "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
      "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770",
      "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b" },
    { 3073,
      "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
      "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a",
      "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081" },
    { 4096,
      "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
      "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0",
      "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9" },
    { 4097,
      "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
      "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc",
      "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8" },
    { 5120,
      "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833",
      "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20",
      "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f60" },
    { 5121,
      "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff",
      "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024",
      "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c34" },
    { 6144,
      "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205",
      "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1d",
      "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a15" },
    { 6145,
      "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f",
      "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539",
      "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5" },
    { 7168,
      "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a",
      "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fc",
      "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae2237" },
    { 7169,
      "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817",
      "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa511",
      "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d9" },
    { 8192,
      "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
      "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
      "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d" },
    { 8193,
      "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
      "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5",
      "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1" },
    { 16384,
      "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
      "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d",
      "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1" },
    { 31744,
      "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
      "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
      "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e" },
    { 102400,
      "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
      "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
      "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6" },
};

enum kat_mode { KAT_HASH = 0, KAT_KEYED = 1, KAT_DERIVE = 2 };

struct kat_ext {
    size_t input_len;
    enum kat_mode mode;
    const char *hex;        /* full 131-byte output, 262 hex */
};

/* Official extended outputs. The empty-hash row doubles as the XOF
 * discriminator: bytes 32..63 come from counter 1 of the root node, which
 * no standard-digest vector pins. */
static const struct kat_ext kat_ext[] = {
    { 0, KAT_HASH,
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d" },
    { 1024, KAT_HASH,
      "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e" },
    { 1025, KAT_HASH,
      "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a" },
    { 2048, KAT_HASH,
      "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9" },
    { 102400, KAT_HASH,
      "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e" },
    { 0, KAT_KEYED,
      "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f" },
    { 1025, KAT_KEYED,
      "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930" },
    { 0, KAT_DERIVE,
      "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0" },
    { 1025, KAT_DERIVE,
      "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f462118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8217cca46defa2751e7f3ad" },
};

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Returns 0 when the first hex_len/2 bytes of got match the hex string. */
static int check_hex(const uint8_t *got, size_t bytes, const char *hex,
                     const char *what)
{
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            printf("\n  FAIL %s: vector hex is malformed at byte %zu\n",
                   what, i);
            return 1;
        }
        if (got[i] != (uint8_t)((hi << 4) | lo)) {
            printf("\n  FAIL %s at byte %zu\n    want ", what, i);
            for (size_t j = 0; j < 16 && j < bytes; j++) {
                int whi = hex_nibble(hex[2 * j]);
                int wlo = hex_nibble(hex[2 * j + 1]);
                printf("%02x", (uint8_t)((whi << 4) | wlo));
            }
            printf("...\n    got  ");
            for (size_t j = 0; j < 16 && j < bytes; j++)
                printf("%02x", got[j]);
            printf("...\n");
            return 1;
        }
    }
    return 0;
}

static void kat_input(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(i % 251);
}

static void kat_digest(enum kat_mode mode, const uint8_t *input,
                       size_t len, uint8_t *out, size_t out_len)
{
    struct blake3_hasher h;
    switch (mode) {
    case KAT_HASH:
        blake3_init(&h);
        break;
    case KAT_KEYED:
        blake3_init_keyed(&h, kat_key);
        break;
    default:
        blake3_init_derive_key(&h, kat_context, sizeof(kat_context) - 1);
        break;
    }
    blake3_update(&h, input, len);
    blake3_final(&h, out, out_len);
}

int test_blake3_kat(void)
{
    static uint8_t input[KAT_MAX_INPUT];
    uint8_t out[EXT_LEN];
    int failures = 0;
    int checks = 0;

    printf("\n=== BLAKE3 official known-answer vectors ===\n");
    kat_input(input, sizeof(input));

    /* Leg 1: standard digests, all lengths, all modes. */
    for (size_t r = 0; r < sizeof(kat_rows) / sizeof(kat_rows[0]); r++) {
        const struct kat_row *row = &kat_rows[r];
        static const char *const names[3] = { "hash", "keyed", "derive" };
        for (int mode = KAT_HASH; mode <= KAT_DERIVE; mode++) {
            const char *want = mode == KAT_HASH ? row->hash :
                               mode == KAT_KEYED ? row->keyed_hash :
                                                   row->derive_key;
            char what[64];
            snprintf(what, sizeof(what), "len=%zu %s", row->input_len,
                     names[mode]);
            kat_digest((enum kat_mode)mode, input, row->input_len, out,
                       BLAKE3_OUT_LEN);
            checks++;
            failures += check_hex(out, BLAKE3_OUT_LEN, want, what);
        }
    }
    printf("standard digests: %d vectors\n", checks);

    /* Leg 2: extended (XOF) outputs. */
    for (size_t e = 0; e < sizeof(kat_ext) / sizeof(kat_ext[0]); e++) {
        const struct kat_ext *row = &kat_ext[e];
        char what[64];
        snprintf(what, sizeof(what), "ext len=%zu mode=%d", row->input_len,
                 (int)row->mode);
        kat_digest(row->mode, input, row->input_len, out, EXT_LEN);
        failures += check_hex(out, EXT_LEN, row->hex, what);
    }
    printf("extended outputs: %zu vectors\n",
           sizeof(kat_ext) / sizeof(kat_ext[0]));

    /* Leg 3: streaming differential — same input, irregular update sizes
     * (1..13 bytes, with zero-length updates interleaved) must give the
     * one-shot digest. Lengths cross block (1025), chunk (3073), and many
     * chunk (102400) boundaries. */
    {
        static const size_t stream_lens[] = { 1025, 3073, KAT_MAX_INPUT };
        for (size_t s = 0; s < sizeof(stream_lens) / sizeof(stream_lens[0]);
             s++) {
            size_t len = stream_lens[s];
            size_t off = 0;
            unsigned step = 0;
            struct blake3_hasher h;
            blake3_init(&h);
            while (off < len) {
                size_t take = 1 + (step * 7 + step * step) % 13;
                if (take > len - off)
                    take = len - off;
                blake3_update(&h, input + off, take);
                off += take;
                blake3_update(&h, input, 0); /* zero-length is a no-op */
                step++;
            }
            blake3_final(&h, out, BLAKE3_OUT_LEN);
            for (size_t r = 0; r < sizeof(kat_rows) / sizeof(kat_rows[0]);
                 r++) {
                if (kat_rows[r].input_len == len) {
                    char what[64];
                    snprintf(what, sizeof(what), "stream len=%zu", len);
                    failures += check_hex(out, BLAKE3_OUT_LEN,
                                          kat_rows[r].hash, what);
                    break;
                }
            }
        }
        printf("streaming differential: %zu irregular-update runs\n",
               sizeof(stream_lens) / sizeof(stream_lens[0]));
    }

    /* Leg 4: blake3_final may be called again on the same hasher; the
     * longer read must extend (start with) the shorter one. */
    {
        struct blake3_hasher h;
        uint8_t short_out[BLAKE3_OUT_LEN];
        uint8_t long_out[EXT_LEN];
        blake3_init(&h);
        blake3_update(&h, input, 2048);
        blake3_final(&h, short_out, sizeof(short_out));
        blake3_final(&h, long_out, sizeof(long_out));
        if (memcmp(short_out, long_out, sizeof(short_out)) != 0) {
            printf("  FAIL: second blake3_final changed the digest prefix\n");
            failures++;
        }
        for (size_t e = 0; e < sizeof(kat_ext) / sizeof(kat_ext[0]); e++) {
            if (kat_ext[e].input_len == 2048 && kat_ext[e].mode == KAT_HASH) {
                failures += check_hex(long_out, EXT_LEN, kat_ext[e].hex,
                                      "re-final ext len=2048");
                break;
            }
        }
        printf("repeatable final: checked\n");
    }

    /* Leg 5: teeth — the comparator must catch a planted mismatch. */
    {
        uint8_t zero[BLAKE3_OUT_LEN] = { 0 };
        if (check_hex(zero, BLAKE3_OUT_LEN, kat_rows[0].hash, "teeth") == 0) {
            printf("  FAIL: comparator passed a planted mismatch\n");
            failures++;
        }
    }

    printf("\n%d BLAKE3 KAT check-group(s) %s\n", failures,
           failures ? "FAILED" : "ok");
    return failures;
}
