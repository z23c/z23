/* purpose: Check Halo2 transcript framing against upstream proof traces. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_halo2_transcript.h"
#include "base/hex.h"
#include "codec/cursor.h"
#include <stdio.h>
#include <string.h>

struct trace_row { char kind; const char *hex; };
/* Orchard 0.16 post-NU6.3 unrestricted fixture, upstream transcript matched
 * independently in ironwood-halo2-transcript.TFDApwHb/replay3.log. */
static const struct trace_row trace[] = {
    {'S', "99b4fa5429bf1f72bbba9c1620e201206287d2cc6373012d5bb99fedb7f72205"},
    {'P', "5d1ec738bb0307c047eeb2a9af2ffa180a4022574dbc6165133c04e78d8eb811e276a6b4792ec294ba6ece7a07e8aa756e53ec63faceb6c6a691e17b31b5c736"},
    {'P', "c6745fecdb4524cf488ed68632bfd9b18dc4256945f9797b94a8aa33b681202f57014505d14e7f47b195cc13c67f5094ae3bd7eafb1b836331889b84021f5813"},
    {'P', "02a4ba47102bd561b4378ae4bc5528705ba8d33a89052b72b9d714d23fb5391604658c549fedeb44f1f581e8936c5773658a4e77d58a4661c009dcb547426a08"},
    {'P', "6f824347092dea1c585397cf736c1d83619abee14cb38d753eaf9fd517ae7b0b199bfdcdb27bba46e692c1c141f99c76eaf3fc9867c166936868728479ce0626"},
    {'P', "a17bdb3b78f98b7c13551669733778647d1df967c26ce7f167fb88324fd7da3fc332d2dceaeb96a94066c03337e309113fa13390c4e1ba63e2f78f802245ee15"},
    {'P', "ddb96cb66b279c7d6924672669d5f11e24630ba05a45431c5cc278a4ed428422e1de2b900b0c69bd7d63b098672a305413a6bf7cf018301716574180aab7a21d"},
    {'P', "a63b55f60e58ea477944584a5324247de02de88acb236772f916266537f9152a9ec7b5ea22b46774a4b214a708a4fb72d465bd0141f0fa2cf9d09752722daa3e"},
    {'P', "3aa69a54a3f2c10942068462ddf9e87fef9888a5696b97fbb838dcaf052f863522127b58b566e5940b1eed042f23ceeb6fcb449cef5a7dfebf867c96d33a5413"},
    {'P', "a9d9e3934fa8f7098ff1e87d7f7a9211f3c2fc10fe72a45e9719aff590e8d71ee25d756fa4468a1847b849d1430e2e87f77a13d89fe59fe13cb14f39bbf66730"},
    {'P', "b3563828a7ce9bdfc0a5f2c48ea85ed8bf424db4a4e9fa54d0b404493c2ffd0f2798856127d371e9f0ffa3b007b7701829b78af32a8789b1ac456c4354a8610a"},
    {'P', "dfa638392a53e06269265937dc72f44c57f34d48999e924186e3899730d83b3305d2c52ca84920d815f61a04fbc38309ace298803960c6f7c4317bd94a245e07"},
    {'C', "7b5abe121c57bcef35e123a98f6db34fc91c9a1884d7f51171a446461f18fa518e297ab3cfc1d729ea016432c791c1e2c46a7e0f00aa07a857a224f2bc53c927"},
    {'P', "82efc51ae2aca9d44244a3e4285982db282a932fa68a2e0a34c646a05e049b17caf0022256e49ff22f4b975ca380875cbf844ef782e28b50b91cb9fe481beb20"},
    {'P', "15d8cffe7359be9b2dc405ec618c189e3bcf65fff5513edff1723ea9597c1121d9dac86edab9a679f044d9c1d12ad23803fcbbeeabdb5fab4cdd4b78c8361021"},
    {'P', "fddafeec96644470b6bf7513ab2557dcaa0fdfdbdf672bba45b4bb7f33604f10a32805eb3c6497db8d130372dd7d6da9c908562db6e5c6163679e41d7fab7e3a"},
    {'P', "7b7b25959fa6c711b9b891719d5473c8e1a02c0c0ff06ef7c6c5d9692890701518f8acf8586e40c8ec5909f502cb9ccb3a90c260eae44ac4e8c40f9fb38a5201"},
    {'P', "9f81805d12c91e2ec5e0f1778f53d185fde3431c485c474743da550f623b67276b8b35bbd3eda451dab810ae704f033eed1ceb3149623f58e7183622610dbd3a"},
    {'P', "604044c8d1906f4309463c4b93872612345605e2c80967b80c96c384c21a6809ad7c5ef767c25d88c63822c84a229a6ef31d4debaabb48e62f4f05763cb2d207"},
    {'C', "a09c11c2e91c6dc9a9f795bcd1c22188574cdf0f0ce367360a76ec763599071028ce68446f4bb788539b33e3ff1cd467968472df6966c0a76de16746e69c8dfb"},
};
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "transcript line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int scalar_reader_refusal(const uint8_t *input, size_t length, bool initialized)
{
    struct ironwood_halo2_transcript t = {0};
    struct zcl_codec_reader r;
    uint8_t out[32], saved[32];
    if (initialized) CHECK(ironwood_halo2_transcript_init(&t).ok);
    zcl_codec_reader_init(&r, input, length);
    struct ironwood_halo2_transcript before = t;
    struct zcl_codec_reader prior = r;
    memset(out, 0xa5, sizeof out);
    memcpy(saved, out, sizeof out);
    CHECK(!ironwood_halo2_read_scalar(&t, &r, out, sizeof out).ok);
    CHECK(!memcmp(&t, &before, sizeof t));
    CHECK(!memcmp(&r, &prior, sizeof r));
    CHECK(!memcmp(out, saved, sizeof out));
    return 0;
}

static int scalar_reader_sequence(void)
{
    /* First INPUT_S in the retained Orchard restricted proof trace. */
    static const char corpus[] = "d76829e6e44d3e45b056b3dbcb2b36e5deeabc4940dc6d47d9dea7beb51c9009";
    uint8_t wire[64] = {0}, out[32], a[64], b[64];
    struct ironwood_halo2_transcript t, expected;
    struct zcl_codec_reader r;
    CHECK(zcl_hex_decode(corpus, wire, 32));
    CHECK(ironwood_halo2_transcript_init(&t).ok);
    CHECK(ironwood_halo2_transcript_init(&expected).ok);
    zcl_codec_reader_init(&r, wire, sizeof wire);
    CHECK(ironwood_halo2_read_scalar(&t, &r, out, sizeof out).ok);
    CHECK(r.position == 32 && !memcmp(out, wire, 32));
    CHECK(ironwood_halo2_read_scalar(&t, &r, out, sizeof out).ok);
    CHECK(r.position == 64 && !memcmp(out, wire + 32, 32));
    CHECK(ironwood_halo2_transcript_scalar(&expected, wire, 32).ok);
    CHECK(ironwood_halo2_transcript_scalar(&expected, wire + 32, 32).ok);
    CHECK(ironwood_halo2_transcript_challenge(&t, a, sizeof a).ok);
    CHECK(ironwood_halo2_transcript_challenge(&expected, b, sizeof b).ok);
    CHECK(!memcmp(a, b, sizeof a));
    CHECK(scalar_reader_refusal(wire, 31, true) == 0);
    CHECK(scalar_reader_refusal(wire, 32, false) == 0);
    return 0;
}

static int scalar_reader_boundaries(void)
{
    static const char modulus[] = "01000000ed302d991bf94c09fc98462200000000000000000000000000000040";
    uint8_t wire[32], out[32];
    struct ironwood_halo2_transcript t;
    struct zcl_codec_reader r;
    CHECK(ironwood_halo2_transcript_init(&t).ok);
    CHECK(zcl_hex_decode(modulus, wire, 32));
    CHECK(scalar_reader_refusal(wire, 32, true) == 0);
    ++wire[0];
    CHECK(scalar_reader_refusal(wire, 32, true) == 0);
    wire[0] -= 2;
    zcl_codec_reader_init(&r, wire, 32);
    CHECK(ironwood_halo2_read_scalar(&t, &r, out, sizeof out).ok);
    CHECK(r.position == 32 && !memcmp(out, wire, 32));
    memset(wire, 0xff, 32);
    CHECK(scalar_reader_refusal(wire, 32, true) == 0);
    return 0;
}
static int reduction_checks(void)
{
    /* Fp modulus from pasta_curves 0.5.1; the zero-extended modulus and
     * its immediate neighbours are important little-endian boundaries. */
    static const char modulus[] = "01000000ed302d991bf94c09fc98462200000000000000000000000000000040";
    uint8_t wide[64] = {0}, out[32], expected[32], saved[32];
    CHECK(zcl_hex_decode(modulus, wide, 32));
    CHECK(ironwood_halo2_vesta_scalar(wide, 64, out, 32).ok);
    memset(expected, 0, sizeof expected);
    CHECK(!memcmp(out, expected, 32));
    --wide[0];
    CHECK(ironwood_halo2_vesta_scalar(wide, 64, out, 32).ok);
    CHECK(!memcmp(out, wide, 32));
    wide[0] += 2;
    CHECK(ironwood_halo2_vesta_scalar(wide, 64, out, 32).ok);
    expected[0] = 1;
    CHECK(!memcmp(out, expected, 32));
    memset(out, 0xa5, sizeof out);
    memcpy(saved, out, sizeof out);
    CHECK(!ironwood_halo2_vesta_scalar(wide, 63, out, 32).ok);
    CHECK(!ironwood_halo2_vesta_scalar(NULL, 64, out, 32).ok);
    CHECK(!ironwood_halo2_vesta_scalar(wide, 64, out, 31).ok);
    CHECK(!memcmp(out, saved, sizeof out));
    CHECK(ironwood_halo2_vesta_scalar(wide, 64, wide, 32).ok);
    CHECK(!memcmp(wide, expected, 32));
    return 0;
}
int test_ironwood_halo2_transcript(void)
{
    static const char *reduced[] = {
        "e94f2b398553e648c8b66098b1f34044c36d84e8d55e1f0bf062df0d2cce732b",
        "3e5eacc9e7be31c058a0bc9863c5fb90fd469c0d9d6c5ae514b19af153dcd613"
    };
    struct ironwood_halo2_transcript t = {0};
    uint8_t bytes[64], expected[64], untouched[64], scalar[32], scalar_expected[32];
    size_t challenge_count = 0;
    CHECK(reduction_checks() == 0);
    CHECK(scalar_reader_sequence() == 0);
    CHECK(scalar_reader_boundaries() == 0);
    CHECK(!ironwood_halo2_transcript_challenge(&t, bytes, 64).ok);
    CHECK(!ironwood_halo2_transcript_init(NULL).ok);
    CHECK(ironwood_halo2_transcript_init(&t).ok);
    for (size_t i = 0; i < sizeof trace / sizeof trace[0]; ++i) {
        size_t n = trace[i].kind == 'S' ? 32 : 64;
        CHECK(zcl_hex_decode(trace[i].hex, expected, n));
        if (trace[i].kind == 'S')
            CHECK(ironwood_halo2_transcript_scalar(&t, expected, n).ok);
        else if (trace[i].kind == 'P')
            CHECK(ironwood_halo2_transcript_point(&t, expected, n).ok);
        else {
            struct ironwood_halo2_transcript before = t;
            memset(bytes, 0xa5, sizeof bytes);
            memcpy(untouched, bytes, sizeof bytes);
            CHECK(!ironwood_halo2_transcript_challenge(&t, bytes, 63).ok);
            CHECK(!memcmp(&before, &t, sizeof t) && !memcmp(bytes, untouched, sizeof bytes));
            CHECK(!ironwood_halo2_transcript_scalar(&t, NULL, 32).ok);
            CHECK(!ironwood_halo2_transcript_point(&t, expected, 63).ok);
            CHECK(!memcmp(&before, &t, sizeof t));
            CHECK(ironwood_halo2_transcript_challenge(&t, bytes, 64).ok);
            CHECK(!memcmp(bytes, expected, 64));
            CHECK(challenge_count < sizeof reduced / sizeof reduced[0]);
            CHECK(zcl_hex_decode(reduced[challenge_count++], scalar_expected, 32));
            CHECK(ironwood_halo2_vesta_scalar(bytes, 64, scalar, 32).ok);
            CHECK(!memcmp(scalar, scalar_expected, 32));
        }
    }
    CHECK(challenge_count == sizeof reduced / sizeof reduced[0]);
    return 0;
}
