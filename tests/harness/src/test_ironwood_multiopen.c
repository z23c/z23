/* purpose: Check bounded Halo2 multiopening interpolation and refusal. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "multiopen line %d: %s\n", __LINE__, #x); return 1; } } while (0)

static int actual_traces(void);
int test_ironwood_multiopen(void)
{
    struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS] = {0};
    uint8_t x2[32] = {1}, x3[32] = {2}, x4[32] = {1}, out[32], expected[32] = {11};
    for (size_t i = 0; i < IRONWOOD_MULTIOPEN_SETS; ++i) sets[i].count = 1;
    sets[0].count = 2;
    sets[0].points[1][0] = 1;
    sets[0].evaluations[0][0] = 1;
    sets[0].evaluations[1][0] = 3;
    sets[0].u[0] = 9;
    CHECK(ironwood_multiopen_value(sets, x2, x3, x4, out).ok);
    CHECK(!memcmp(out, expected, sizeof out));
    uint8_t before[32];
    memcpy(before, out, sizeof out);
    sets[0].points[1][0] = 0;
    CHECK(!ironwood_multiopen_value(sets, x2, x3, x4, out).ok);
    CHECK(!memcmp(out, before, sizeof out));
    sets[0].points[1][0] = 2;
    CHECK(!ironwood_multiopen_value(sets, x2, x3, x4, out).ok);
    CHECK(!memcmp(out, before, sizeof out));
    sets[0].points[1][0] = 1;
    sets[0].evaluations[0][31] = 0xff;
    CHECK(!ironwood_multiopen_value(sets, x2, x3, x4, out).ok);
    CHECK(!memcmp(out, before, sizeof out));
    CHECK(actual_traces() == 0);
    return 0;
}

static const char *const one_trace[] = {
    "MX25c3d784b586f90040dbed73554256ab1e622134f4c3fd642152c5250fd0b3814",
    "MP03fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
    "MP13fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
    "MP1383f8db8f79db61a2ace945e5036e9198e39df80bfd8edb0945a6a1ad40cdf12",
    "MP23fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
    "MP2383f8db8f79db61a2ace945e5036e9198e39df80bfd8edb0945a6a1ad40cdf12",
    "MP2a06f894dfac6e0a1eecfb3014f26c02e117c7d8cf93a250de56b288b72654d05",
    "MP33fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
    "MP3383f8db8f79db61a2ace945e5036e9198e39df80bfd8edb0945a6a1ad40cdf12",
    "MP33b4ff0b7c7088561750b1a4d51164031a50927db50ff2e552de4c41a242fb71d",
    "MP43fafa948dc173285045f363b178d2d420f41f8cfc98c533e9cc080d6038f870a",
    "MP4a06f894dfac6e0a1eecfb3014f26c02e117c7d8cf93a250de56b288b72654d05",
    "MX3c677ec13fc49602ac75e6da7a17acc4f6e42ac6c39adb8eb7e0bb244070b9c1f",
    "MX4556696aa887a119ff3ab4cf91a293237d41692a8782927b24a9290990989f413",
    "MUfb514179216fe170e53b8b13641797cc66fdaa78c7b96c576aad02e9e640c73c",
    "MU294459471788f187e4c9e71b3a6a27aeaef46133fca0562203dd418726ee7423",
    "MU45e7529fb9a4889d4dbba5fe5088cdcf619804b05ebca99ccf29ab5dd582ef03",
    "MUdf7e650c05399239f2e67cc238d71e4b4ce2b5ea22989957b4ec9e536b1dd714",
    "MU163fc8d2e6276d661e0c91c827721597da96ed6b4c4f02831a8557d983486f14",
    "MV3842e7cc6ad2391040cc392021452cb1fdb9ee44ed59db05feda39ad0075d428",
    "Q0a32845b67373103283a8272e420513640560b94b8a171a29bbf4eacf656af126",
    "Q19cffd0ff109e45abbc0e7f2dc8728ca47f7934ad7fdea989fffa2ff006df5327",
    "Q18a99c48bdfd90843cf2f5919c8ec364ea9a6d2a741df1820427b165347a9b505",
    "Q214d6cf8443e5b73dcaf7efd197bb92086dbafd1db42242188d85950b56c5b61e",
    "Q29481b5c2b97516afcd0ed306c05a7e94c618287042f8d17d9c81f009672f0904",
    "Q2542889760605133b404e683e61dcac8d6f80d23fc778cc211ce0759040c96829",
    "Q34a4aa78ec2bd3629837092281a2bde7f14e1b9438d8c527ae9fff7023ff3691b",
    "Q33671dc1f1cfb1d7f01c76faa9c781a348c2e1e45a5f5cfa5c48f6c2f3d418220",
    "Q344161e72f3a83e5bc439896f69aff0b8b9add79e6dbe524daeeaf974f0e2f03a",
    "Q4be0d89cc6a9dc942b84956a779e5e3bbc70543a32d2f4cc158c3eccf6cd1c320",
    "Q4e15b3e57126db3766a4b007307913817789eaa806295fdbd611f802f5b01f417",
    NULL
};

static const char *const two_trace[] = {
    "MX28cba29a60657dad74eea387da51591fd3556a07ed062eba23fe747ab314ac011",
    "MP0a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a",
    "MP1a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a",
    "MP1893b9fd6cff86be2ef7b215179aaa642fbf78be626159d981ac12b756e951011",
    "MP2a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a",
    "MP2893b9fd6cff86be2ef7b215179aaa642fbf78be626159d981ac12b756e951011",
    "MP22eebf319da7477307f5217f7b8dad391fbdfb2a796c464e16e45d805c1efc109",
    "MP3a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a",
    "MP3893b9fd6cff86be2ef7b215179aaa642fbf78be626159d981ac12b756e951011",
    "MP3e76746309665379bfe2cc9d737c04f4d0c8f346348bb12ec9b37c29dacb2413b",
    "MP4a1c6c0c3c9fc964d3d54bbb9e586a2a3c1e6489881715ed10540fdf622c29d3a",
    "MP42eebf319da7477307f5217f7b8dad391fbdfb2a796c464e16e45d805c1efc109",
    "MX3c36e19788ada21a630c8efe3ef84c7e70ad4735eb990b1fdd6d63497a8944117",
    "MX4646752d2e0197d9492cd388d75084df1cce5af8091929221b70fc08661a8982b",
    "MU8ac601d31d1ecfe376061662539037bdfeaad7966a132faef6c30e0b23eb2c25",
    "MU6cedb0d24a31cca5be2480ada9a1ca9c0caef0ad987e126c733ef2e6321fb91f",
    "MU0ce92f7ce6e519883e7457836085041483770b4c3458e2fff22418254140b20a",
    "MU2c1a519e12c96c46713a43c342d6ec6761e610db7120f118fa073c5c9d164c37",
    "MU0549a2afd024579d027f30fd8273b232973eddff4e81cdec2aa8efe1b4a1de22",
    "MV34247345d2f931cdd394eece6af6b051fc6c49c03d5461a827c5dd63c8955d3e",
    "Q05bdbcc63540d82a64a6f75b7c1df2f879008291914e567fd939cdff0c79ddb37",
    "Q1a16f13a902e5606dfc0b55ee5550de2d9f9a854dd3c43d1805ff7357b8a51510",
    "Q1a5b17b8b6eed7b5213b34a2d35e29a25f67444cb40d5cf83deb9ec4ca02ac500",
    "Q258117d72a0415110a6a535786b03a427087463907dc6d66fa433d4ed7d03982f",
    "Q2885ba7125143be272e2f91676fab770f7e693dd523d393d1612483c0ec1d5339",
    "Q2221959264620fd765d902ea1741dc193fa976beebf15754ce6937542dcaac536",
    "Q306a49273f36897068be8ecdfdb0ffe21f7e96a9d79395edafd4f912b65479837",
    "Q319f0bde9360a4f5ce575d8b6d45caa49f90aab3a20664b0e36f1c4ad1b203b28",
    "Q38099e8419bc535e48d4c29996b6630adacc956a59e111999481270928e045601",
    "Q4107fe04579e67ef3ef07f813e208b350a1c818e580db8edc5832d95e657c351e",
    "Q4534a71ee172fa52b82e57530378b6bd65ff3daad9a3e533180e89729eca64710",
    NULL
};

/* Q rows are independently compressed with x1 from the upstream commitment
 * map. P and U rows and challenges come from the instrumented upstream proof. */
static int actual_trace(const char *const *rows)
{
    struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS] = {0};
    size_t evals[IRONWOOD_MULTIOPEN_SETS] = {0}, u = 0;
    uint8_t x[3][32] = {0}, expected[32] = {0}, out[32];
    bool have[3] = {false}, havev = false;
    for (size_t i = 0; rows[i]; ++i) {
        const char *r = rows[i];
        if (r[0] == 'Q') {
            size_t n = (size_t)(r[1] - '0');
            CHECK(n < IRONWOOD_MULTIOPEN_SETS && evals[n] < IRONWOOD_MULTIOPEN_POINTS);
            CHECK(zcl_hex_decode(r + 2, sets[n].evaluations[evals[n]++], 32));
        } else if (r[1] == 'P') {
            size_t n = (size_t)(r[2] - '0');
            CHECK(n < IRONWOOD_MULTIOPEN_SETS && sets[n].count < IRONWOOD_MULTIOPEN_POINTS);
            CHECK(zcl_hex_decode(r + 3, sets[n].points[sets[n].count++], 32));
        } else if (r[1] == 'U') {
            CHECK(u < IRONWOOD_MULTIOPEN_SETS);
            CHECK(zcl_hex_decode(r + 2, sets[u++].u, 32));
        } else if (r[1] == 'V') {
            CHECK(!havev); havev = true;
            CHECK(zcl_hex_decode(r + 2, expected, 32));
        }
        else if (r[1] == 'X') {
            CHECK(r[2] >= '2' && r[2] <= '4');
            size_t n = (size_t)(r[2] - '2');
            CHECK(!have[n]); have[n] = true;
            CHECK(zcl_hex_decode(r + 3, x[n], 32));
        } else CHECK(false);
    }
    CHECK(u == IRONWOOD_MULTIOPEN_SETS && have[0] && have[1] && have[2] && havev);
    for (size_t i = 0; i < IRONWOOD_MULTIOPEN_SETS; ++i) CHECK(evals[i] == sets[i].count);
    CHECK(ironwood_multiopen_value(sets, x[0], x[1], x[2], out).ok);
    CHECK(!memcmp(out, expected, 32));
    return 0;
}
static int actual_traces(void)
{
    CHECK(actual_trace(one_trace) == 0);
    CHECK(actual_trace(two_trace) == 0);
    return 0;
}
