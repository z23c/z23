/* purpose: Check bounded Halo2 multiopening commitment folding. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen_commitment.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "multiopen commitment line %d: %s\n", __LINE__, #x); return 1; } } while (0)
struct trace_point { unsigned group; bool derived; const char *hex; };

static const struct trace_point one_points[] = {
    {0, false, "80ae49576822ed6f71a100543ca52367f34e94548a13127cdf495923a9f7ef36"},
    {0, true, "47180081f6977aee33f98f789b28549a2ddd85de94150c20104f3d2e6bb3c2b5"},
    {0, false, "3f45b4fbeb4b815cab5d86a9f309eb2ce415de91a894cd7762c7fa3ab73aab0a"},
    {0, false, "d5f7b96e2d92669f317319aab59dac9d9cd3fcc0959dd9990d650f8ee27d9e0f"},
    {0, false, "ab03d4acac61ee9c08f67318c71607e3697dd23f0fbd4ce4eaa17516b410d2a1"},
    {0, false, "def3700320f5106ea7263935ec53df1bdad7564f7c1901a8ed2fe6c87f51fd29"},
    {0, false, "7b1f2cf9e12b9198f4c9685cfa182b48b77ea485d292854cde5663259e335e96"},
    {0, false, "4b19d31e2ef49d21b0e47b144d3ba11afb72b2533dece818c40749e9ed500f32"},
    {0, false, "89abb3e18fb46bf85806a56a363be1aa35a589cbb9c40f7a7b7277231a0fb915"},
    {0, false, "83afa01d50cee483688ab128d511b3ddb543b34aa9fb3637409df049974813aa"},
    {0, false, "1f8f8b27a88a7f61461a6728de8db4717167ec91229653f281d1ca2b8723aeb7"},
    {0, false, "fc7ba6886b0875aa238b26fc83a6bdd0172172374544b10d5204d288c95a549b"},
    {0, false, "3fcd2c2eddade9e0c6dd7923e32905bf878e3ab3c21b53fa77a509ef22556a3a"},
    {0, false, "0adf9adf06d1c3482a22d4e6b6e59504f2782b2fe0bbe7a16ed87da91f8d1f9f"},
    {0, false, "60ef63525a077f9c6d17036e4980f1e0c68c8140c3c7ebc42df6432f38efe10b"},
    {0, false, "41ac9b609189a61654987f0f58427e417e30c2431b50e40144f2bafc1109e08c"},
    {0, false, "07007f4f7f22ce991acd1c728adef96220325320c59a9d6637d9ed7001bbf6b5"},
    {0, false, "ad087d3b84930454a9b5b4be2a07caa9a3d9090276c3590f494741bae92047a9"},
    {0, false, "fabfb8292267f0870b020e48260b1bb29f75f1af7003c5a25ed34054e0f63336"},
    {0, false, "614043557e9f244b17cb65d3f8232ec635c45e369df947273ecac32d4601502c"},
    {0, false, "1cb3d4733e48ab32c057d158dffc349d886bd6431d73148ccca1dcb93d9e7c19"},
    {0, false, "9cc89112dcc0187fbbef98bf359ee1706d1302469fec9e8308c2e1b0166d4f39"},
    {0, false, "e64b8d3d3f65094044ac83237642347712b31f4662f420c1afccff3c785d351e"},
    {0, false, "9e8730ff31518103d40850247a2fea287f2ba820d89cc5d2c8b40e3c1aad7409"},
    {0, false, "54bf2477bcf2a887ff6ffdf9e1aa2684ed38bc717d2d7e0101cd18e4bf9f4b8d"},
    {0, false, "b13c74abd05080f0c28916da7de77afefff4474fc84273ace30de333ccb5a43f"},
    {0, false, "5b30587393dbe88d432da5081d9fa88fdca57307322e51474c490fe6f7dbb115"},
    {0, false, "046a4aad80e901741ce633aed2d7e786c6ea4b1dd94f8ef92af297d9b53819ab"},
    {0, false, "50f58796f1fb67caee37bf34c7b822135573608d090be9c022ce4ada76bdd093"},
    {0, false, "be957f735e09c4b686c53ccc51a9ff3503649c731308f3194aec63420e7f771f"},
    {0, false, "293f71d44d15a495ec29e3f068dee74c57b101beeaddda26adf285decb83c202"},
    {0, false, "8277f11d60ea21d1727ae58ab7dcbf682d96be74f728f08b5e79de318a354b83"},
    {0, false, "df915e6bd4a8582bb9ad9bc3dbe896f8974a9e551f1335d0b3e4a58aecd4002d"},
    {0, false, "31710e7665f2144934bc1cb884b8ae50a4f96bfb308b66ec5d1ca9d60d684837"},
    {0, false, "57ebb3c46480257fa82eb4f8a7d55587bd8d959dd3550312989f6754857e72be"},
    {0, false, "d30ff26e02c957f704a23a24c68575f54ccb40fc416a7d7dd8bbebc9cbb7ad82"},
    {0, false, "799cc094f089ed63c070450de174b7968f3b07eef15e2a0370dca9582ff3d00a"},
    {0, false, "7671dfef8018371692daf7e243771911c533cd7641ca1cbdd710b0a03f8d0a30"},
    {0, false, "6294a5a2da45b05bebb4cbe4941d2ac4ea85e80b03010fd3212739fa1c393492"},
    {0, false, "02baa1b62438a2fb00c879d2bae7cd91f9609d608ea2c12c698170bd456a8231"},
    {0, false, "811f406858c39edbfca3d0ebf1102909d6bda9671807c00c4b1749aca2185e02"},
    {0, false, "cb2a25d15f573c6c81314e842a8b6a119c6d89a71cc0ed7df056d53200aa47af"},
    {0, false, "344eb7e778a98021af08b89b3ab03eaa0b3aee515acb23ba04acb74b52c4c910"},
    {0, false, "7e82b18cd880164b19ccca22da0d676a9d083f26200acf10c16529fc4ea7bea7"},
    {0, false, "31527f386166255433e1b09e2d591bb157ff9e3a84c1c35b858828ad2c86f505"},
    {0, false, "461bb12ee8a697133757404f0dcaf8d42966bdc31542101f478b2815a009dba0"},
    {0, false, "51cb2f4be52c9941ea6fd96d5d413cae9689de5a99596b358699453f1cc9afa5"},
    {4, false, "4d0bfdc407ec1e5df6479a495d5d8f981670948a8ff1a2d7a2987c3f84a072b0"},
    {1, false, "a8a7d4cca1df67c2a4a0de3a1e7990a57e209d03186ffa1cb0c36ff952646c2b"},
    {0, false, "d13f05fcf095b005971946faaca873f57789a299e476ebbe7ad674968c89b6b4"},
    {4, false, "20c0c7b464f8ef69be0624088d959f90bce556f6a9510b62b1edd449a494f61d"},
    {1, false, "65e60cb69bff83791739ec986c3e35ac34ae14b83528520cdd0ea44be3569f02"},
    {0, false, "bd9c3a560cfa4e2394440dead39d260ddd84a382be818922ab4981a5f657e829"},
    {4, false, "6a4a8e6d86f89c467138628459dcbdebd9d90d12bfc26ada32663d9b3dda282e"},
    {1, false, "aeabd7ff39ef5d8133b144f03754bd55fc370ab263fed3a630083f9747adc7a8"},
    {1, false, "23b74f5ddcb8ad599309fc18db781328f886c9531754f719899cc86434651206"},
    {3, false, "4b984c6271a04a337f681e9053742a9688f7597a9f14f3973c4763c5714b2db1"},
    {3, false, "ae6dc6ca186a05e4c5017435b0cc39ac13b1fd865d7714082d8e0ecc85ec1915"},
    {2, false, "5af1a05f0a8adfb2dba3bc76ec51c367c509b15ae8761c1fbf51bb184e294386"},
    {2, false, "e1db86236f4faefd7dfb590bfc439731a3482eb0e8df726a8716e72ee75d0401"},
    {2, false, "e3bcd4814ee23ff9112842e5822ec07e4ba683af0cbc029690069eb0c45e2585"},
    {2, false, "decf1615ffcee243fd95d33754d9f25e5094e2307a3c5e70ba8b6c23ded21eb6"},
    {1, false, "39066aa7282337ebdf4899946e62d890986b11621e60e71d12dcbb8a3c3cdd15"},
    {1, false, "032a3c77b525a8aa133167b1b2e07dff37fe218722e225b0f204cd05fa950022"},
    {1, false, "385d6aa162e863bd1cee7019b92ba8f610e54e1f45011c3a8b4562ce8ee09387"},
    {1, false, "2573e5856dca33403c0a88ac0f50f977a8d97601253f10657f5677a6b08a7d98"},
    {2, false, "0fa0b472d10f271ae572373baf69514034ddab917436499a2b31d81db7f50984"},
    {1, false, "97b46d53675018cd87223fc9e694dc109807618f171dae09393b705e7a1c0815"},
    {0, false, "b5c8febce59fe6cf37ce714e2b0c2eaaab93b767a3b33f4b35bcd4aee3c9cb1f"},
};

static const struct trace_point two_points[] = {
    {0, false, "f68bad636ddecfb8dd4bfc391c653ba6e2d679bd0243c41d370fc41f4c9704a2"},
    {0, true, "66dbf726bd8ed700235cb72710cfadd0f6f4d5080a63b71c0f714b075e22c706"},
    {0, false, "3f45b4fbeb4b815cab5d86a9f309eb2ce415de91a894cd7762c7fa3ab73aab0a"},
    {0, false, "d5f7b96e2d92669f317319aab59dac9d9cd3fcc0959dd9990d650f8ee27d9e0f"},
    {0, false, "ab03d4acac61ee9c08f67318c71607e3697dd23f0fbd4ce4eaa17516b410d2a1"},
    {0, false, "def3700320f5106ea7263935ec53df1bdad7564f7c1901a8ed2fe6c87f51fd29"},
    {0, false, "7b1f2cf9e12b9198f4c9685cfa182b48b77ea485d292854cde5663259e335e96"},
    {0, false, "4b19d31e2ef49d21b0e47b144d3ba11afb72b2533dece818c40749e9ed500f32"},
    {0, false, "89abb3e18fb46bf85806a56a363be1aa35a589cbb9c40f7a7b7277231a0fb915"},
    {0, false, "83afa01d50cee483688ab128d511b3ddb543b34aa9fb3637409df049974813aa"},
    {0, false, "1f8f8b27a88a7f61461a6728de8db4717167ec91229653f281d1ca2b8723aeb7"},
    {0, false, "fc7ba6886b0875aa238b26fc83a6bdd0172172374544b10d5204d288c95a549b"},
    {0, false, "3fcd2c2eddade9e0c6dd7923e32905bf878e3ab3c21b53fa77a509ef22556a3a"},
    {0, false, "0adf9adf06d1c3482a22d4e6b6e59504f2782b2fe0bbe7a16ed87da91f8d1f9f"},
    {0, false, "60ef63525a077f9c6d17036e4980f1e0c68c8140c3c7ebc42df6432f38efe10b"},
    {0, false, "41ac9b609189a61654987f0f58427e417e30c2431b50e40144f2bafc1109e08c"},
    {0, false, "07007f4f7f22ce991acd1c728adef96220325320c59a9d6637d9ed7001bbf6b5"},
    {0, false, "ad087d3b84930454a9b5b4be2a07caa9a3d9090276c3590f494741bae92047a9"},
    {0, false, "fabfb8292267f0870b020e48260b1bb29f75f1af7003c5a25ed34054e0f63336"},
    {0, false, "614043557e9f244b17cb65d3f8232ec635c45e369df947273ecac32d4601502c"},
    {0, false, "1cb3d4733e48ab32c057d158dffc349d886bd6431d73148ccca1dcb93d9e7c19"},
    {0, false, "9cc89112dcc0187fbbef98bf359ee1706d1302469fec9e8308c2e1b0166d4f39"},
    {0, false, "e64b8d3d3f65094044ac83237642347712b31f4662f420c1afccff3c785d351e"},
    {0, false, "9e8730ff31518103d40850247a2fea287f2ba820d89cc5d2c8b40e3c1aad7409"},
    {0, false, "54bf2477bcf2a887ff6ffdf9e1aa2684ed38bc717d2d7e0101cd18e4bf9f4b8d"},
    {0, false, "b13c74abd05080f0c28916da7de77afefff4474fc84273ace30de333ccb5a43f"},
    {0, false, "5b30587393dbe88d432da5081d9fa88fdca57307322e51474c490fe6f7dbb115"},
    {0, false, "046a4aad80e901741ce633aed2d7e786c6ea4b1dd94f8ef92af297d9b53819ab"},
    {0, false, "50f58796f1fb67caee37bf34c7b822135573608d090be9c022ce4ada76bdd093"},
    {0, false, "be957f735e09c4b686c53ccc51a9ff3503649c731308f3194aec63420e7f771f"},
    {0, false, "293f71d44d15a495ec29e3f068dee74c57b101beeaddda26adf285decb83c202"},
    {0, false, "8277f11d60ea21d1727ae58ab7dcbf682d96be74f728f08b5e79de318a354b83"},
    {0, false, "df915e6bd4a8582bb9ad9bc3dbe896f8974a9e551f1335d0b3e4a58aecd4002d"},
    {0, false, "31710e7665f2144934bc1cb884b8ae50a4f96bfb308b66ec5d1ca9d60d684837"},
    {0, false, "57ebb3c46480257fa82eb4f8a7d55587bd8d959dd3550312989f6754857e72be"},
    {0, false, "d30ff26e02c957f704a23a24c68575f54ccb40fc416a7d7dd8bbebc9cbb7ad82"},
    {0, false, "799cc094f089ed63c070450de174b7968f3b07eef15e2a0370dca9582ff3d00a"},
    {0, false, "7671dfef8018371692daf7e243771911c533cd7641ca1cbdd710b0a03f8d0a30"},
    {0, false, "6294a5a2da45b05bebb4cbe4941d2ac4ea85e80b03010fd3212739fa1c393492"},
    {0, false, "02baa1b62438a2fb00c879d2bae7cd91f9609d608ea2c12c698170bd456a8231"},
    {0, false, "811f406858c39edbfca3d0ebf1102909d6bda9671807c00c4b1749aca2185e02"},
    {0, false, "cb2a25d15f573c6c81314e842a8b6a119c6d89a71cc0ed7df056d53200aa47af"},
    {0, false, "344eb7e778a98021af08b89b3ab03eaa0b3aee515acb23ba04acb74b52c4c910"},
    {0, false, "7e82b18cd880164b19ccca22da0d676a9d083f26200acf10c16529fc4ea7bea7"},
    {0, false, "31527f386166255433e1b09e2d591bb157ff9e3a84c1c35b858828ad2c86f505"},
    {0, false, "461bb12ee8a697133757404f0dcaf8d42966bdc31542101f478b2815a009dba0"},
    {0, false, "814adb9b6782795b2514905f755a50415483740ed8232712aaaa08f478343b23"},
    {4, false, "40fcb3844bf77f2d3933e499bdac4f6190e4ef4861e8231fda2c22d399d0ca98"},
    {1, false, "e92746c614cd5795590464b068002a7458ffc8e01efa29563fc7203a9177b416"},
    {0, false, "cee66b08b5fb7d7937d3123f9c3246e5e504052e0d3f9545112cdcde6f565728"},
    {4, false, "6a694c9c0f1532641311fbff10c778183a9d9a627868ded9a081dfbb5bd3dfbb"},
    {1, false, "ea4ae559c0f4cc2f8154d639b23708b4756a8c3b9b29f91ea022235b8dbbb3a7"},
    {0, false, "3d19f6cd92e90a935539e05263c98b3cf966aa829c8aec24f893c5a0af795180"},
    {4, false, "e34f346936b490a74b63e8ff08a653fe7e31eb1cec800dc2bf35da2478b1990c"},
    {1, false, "5b773fcad2387349a5b7b545d1374f5863437b23b3a5592e1fb910b8ce60b191"},
    {1, false, "2cf906ff6cb56ea12794b6d78b873a0d403c4c8f72556c944ba13a3710b346b9"},
    {3, false, "f7cb521e71fcdc8b8d39c946903e30cccb1d8d006b6182960a54815addefb439"},
    {3, false, "9f766e9c25f99052994536f375e4e586235957c5e2135d62403c7cc47707a304"},
    {2, false, "21c3ef5a0d57b0a4cc132b67d492f313488a4151290f1fae2bac14317d225f9f"},
    {2, false, "857f4163353a503ee3a10c13d8767b3c8deec49e08560f0794e14483f913bb8f"},
    {2, false, "9cfbbc9c16a1368173ff011939a12011008288e3e99c245fca853609b42fc917"},
    {2, false, "036de6a23cabe4e154d3e5136a1c2be398241319692d3856ef5183a841209022"},
    {1, false, "7e1f40aa8d4b2c66b7e552cd0c56e788a70f711f21f32fc018234f4d9a0c6d2a"},
    {1, false, "3d62545328ae2b359cbf9a6f569342d42fb8623680a7275739229e7900d93d81"},
    {1, false, "4910e20c5e84cd679148408dc3b084400f5535c9e8fdb82b87872ee0c9f1728c"},
    {1, false, "7493dad173c1265b3fbf4e7354459795d8d6465095a1a41d730b1c493ff1b132"},
    {2, false, "f538000fb7cd9a152dc1c7a173d5faa341420468d4255c046ad1851c6b463c92"},
    {1, false, "03c23e27e592ee0dda5bbcc916341187f8ea4eb52e2660b56a6e2e29973a2a9e"},
    {0, false, "273cf53ff47191c5a7a25ba8e3a8df751b1b4933500b3653ff54ccd8b94f95a0"},
    {0, false, "8655dcb663fc4aa23d2be0dabbdc101a49e4bc5817bc4ed15db7ce160f14519a"},
    {4, false, "dc341fde2ed69112932418420745a37a3118505bd524ca97d930222e2941a72d"},
    {1, false, "4bde6f61b160577aa713155e5e03a1ded7bd02e03907feacae18ffce5c459b1b"},
    {0, false, "e2c647ed3736614382904319ced8978471ffb5b750a064f5cbde4c2db36cbbaa"},
    {4, false, "8d6f142fad920f18b9e4e826d3ca6f03020a257e7f5b48c3a16678e7c3fd881d"},
    {1, false, "1ef4791ebfd83fc56acead31384289696bcdf073ef2118062afdb3aeae35f90b"},
    {0, false, "889def6b5e6990a110a2ea79bd5951f42bfce328d3bb2ee7f0ecdb91bd4add00"},
    {4, false, "ed10fc133fdeea38b49e2a901ef65197919bb0f3525236b82870b32506fd131a"},
    {1, false, "0cf81b505429265eba39b02f82a5b3f35be2286d630d7e6dda669b9db8768638"},
    {1, false, "76b469013b259f79b944f033ce9cb5219bd99a191f20d5ed8967c05777044aab"},
    {3, false, "824128af5f0cab4c0df025206851336dc17927df9041d8cd79739efe8336720f"},
    {3, false, "53a82d454ec7bb79a2f78b7773a144dbd7d5dbb20bf376e7fa114e5f58e575be"},
    {2, false, "a2f71b7f380020730d95739e1a646079181cab6ac5f8297419b89e1c35098ead"},
    {2, false, "0c4e36c413e06c02e2397a1c578897bd972c210fe376195f1ab08aac0f976ea8"},
    {2, false, "f93b1133d493de969e7b56696996103014699ff657694e3492c56f59282da688"},
    {2, false, "9cb0c854023ffb6c51a91cdaa1c34552838da323d1ef38b786620486968003b2"},
    {1, false, "ce58c89cc008806c75feb145cf4b22b2ac04a08d99c20df9a36d62fb190d33a2"},
    {1, false, "db216b8279cb17eaa51fc4be1c6d5e64b2d6174a6c1361db7894899aab7f47b3"},
    {1, false, "24459dcd01c0cb3edb0e7b3066f179f3d0cec8d151506d101503ebe00b0be42e"},
    {1, false, "2d6cb183b8bc43acfa896e0dd07879ab2045c2741a789998bc0751381fc23e3d"},
    {2, false, "e45606fc8f661fdbb2bc32245e29987c873134c671c0bbd0ecff2428939643a9"},
    {1, false, "f6d7f77c4cd712e22589eac67f76eee2ba311103bc71a7d113766dd6daeef90d"},
    {0, false, "e55fe4c155c0e04e28e3a39aaa06ec5a77c27eea1aab0c529391e7b2a12fb9a0"},
};

static int extended_map(struct ironwood_multiopen_commitment *items, size_t count,
                        const uint8_t q[32], const uint8_t x4[32])
{
    uint8_t zero[32] = {0}, first[32], extended[32];
    CHECK(count == 69);
    CHECK(ironwood_multiopen_commitment_fold(items, count, q, zero, x4, first).ok);
    memcpy(items + count, items, count * sizeof *items);
    CHECK(ironwood_multiopen_commitment_fold(items, 2 * count, q, zero, x4, extended).ok);
    CHECK(!memcmp(first, extended, 32));
    return 0;
}

/* The H entries are independently folded from the eight source-derived terms;
 * all other points and their order are from the instrumented upstream maps. */
static int actual_trace(const struct trace_point *rows, size_t count, const char *q_hex,
                        const char *x1_hex, const char *x4_hex, const char *expected_hex)
{
    struct ironwood_multiopen_commitment items[2 * (sizeof two_points / sizeof two_points[0])] = {0};
    uint8_t q[32], x1[32], x4[32], expected[32], out[32], saved[32];
    CHECK(count * 2 <= sizeof items / sizeof items[0]);
    for (size_t i = 0; i < count; ++i) {
        items[i].group = rows[i].group;
        items[i].kind = rows[i].derived ? IRONWOOD_MULTIOPEN_DERIVED_POINT : IRONWOOD_MULTIOPEN_PROOF_POINT;
        CHECK(zcl_hex_decode(rows[i].hex, items[i].point, 32));
    }
    CHECK(zcl_hex_decode(q_hex, q, 32) && zcl_hex_decode(x1_hex, x1, 32));
    CHECK(zcl_hex_decode(x4_hex, x4, 32) && zcl_hex_decode(expected_hex, expected, 32));
    CHECK(ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(!memcmp(out, expected, 32));
    memcpy(saved, out, 32);
    if (count == 69) CHECK(extended_map(items, count, q, x4) == 0);
    memcpy(items[0].point, items[2].point, 32);
    CHECK(ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(memcmp(out, saved, 32));
    memset(items[1].point, 0, 32);
    items[1].kind = IRONWOOD_MULTIOPEN_DERIVED_POINT;
    CHECK(ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    items[1].kind = IRONWOOD_MULTIOPEN_PROOF_POINT;
    memcpy(out, saved, 32);
    CHECK(!ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(!memcmp(out, saved, 32));
    items[1].kind = IRONWOOD_MULTIOPEN_DERIVED_POINT;
    uint8_t last = x1[31], saved_q[32];
    memcpy(saved_q, q, 32);
    x1[31] = 0xff;
    CHECK(!ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(!memcmp(out, saved, 32));
    x1[31] = last;
    memset(q, 0, 32);
    CHECK(!ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(!memcmp(out, saved, 32));
    memcpy(q, saved_q, 32);
    items[0].group = IRONWOOD_MULTIOPEN_GROUPS;
    CHECK(!ironwood_multiopen_commitment_fold(items, count, q, x1, x4, out).ok);
    CHECK(!memcmp(out, saved, 32));
    return 0;
}
int test_ironwood_multiopen_commitment(void)
{
    CHECK(actual_trace(one_points, sizeof one_points / sizeof one_points[0],
        "2bd99f2ffbcfcdaaee62e36e65e835264b869dc138f52e2d8b53d55e028f39b6",
        "ef07195d8f747d47ec405d09dfa70d2d4a9dc3ada36823cf344b1c224e41fd2e",
        "556696aa887a119ff3ab4cf91a293237d41692a8782927b24a9290990989f413",
        "3169e22cbe2c35665fd334b3b5040345f14f0a71abd908fe67273c34cf8ca106") == 0);
    CHECK(actual_trace(two_points, sizeof two_points / sizeof two_points[0],
        "7331705c594af19cf8d52dc6dde3d40f85b1143a6a44b749019ec98a2b86e8b4",
        "b708924eba8cb1cb9ae8ae04b2bd522acfd0e50589df5960475db3e327e78b0d",
        "646752d2e0197d9492cd388d75084df1cce5af8091929221b70fc08661a8982b",
        "27b1808550d8ce556c79250ae26b071cdde04cd880f7c272b1ba012aa56cdca9") == 0);
    return 0;
}
