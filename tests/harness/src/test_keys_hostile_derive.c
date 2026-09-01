/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hostile-input hardening tests for the key-derivation and address-codec
 * decoders — BIP32 derivation, xpub serialization, the Base58/Base58Check
 * codec, and Sapling witness deserialization all sit on paths that carry
 * externally-supplied bytes (watch-only xpub import, RPC address arguments,
 * explorer URL segments, stored witness blobs). Every one of them used to
 * hold a live assert(): -DNDEBUG is NOT set for the node, so an assert on a
 * hostile input aborted the whole process instead of returning an error.
 *
 * Contract under test:
 *   - pubkey_derive is total: an empty parent, an uncompressed parent, or a
 *     hardened child index returns false rather than aborting;
 *   - ext_pubkey_encode / hd_serialize_xpub return false on a key the
 *     fixed-width BIP32 body cannot hold, instead of asserting;
 *   - hd_deserialize_xpub rejects its whole boundary corpus (wrong version,
 *     truncated, wrong length, degenerate all-'1', over-long) cleanly;
 *   - the Base58 codec is total in both directions — a short output buffer,
 *     an out-of-alphabet byte, or embedded whitespace all fail as a return
 *     value, and a legitimate payload still round-trips byte for byte;
 *   - incremental_witness_deserialize refuses an out-of-range depth before
 *     it can write past the fixed parents[]/has_parent[] arrays;
 *   - equihash_params_supported admits all four consensus parameter sets and
 *     refuses every (N,K) outside the bit-packers' width assumptions, so a
 *     future chain-params entry cannot reach them unchecked.
 *
 * As in test_key_hostile_wif.c, REACHING THE END OF THIS FUNCTION AT ALL is
 * the no-abort proof: every call below is an input that previously tripped a
 * live assert(), so a regression does not show up as a failed check — it
 * shows up as the test binary dying before it prints its summary.
 */

#include "test/test_core.h"

#include "crypto/equihash.h"
#include "domain/encoding/base58.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "sapling/constants.h"
#include "sapling/incremental_merkle_tree.h"
#include "wallet/hd_keychain.h"
#include "core/serialize.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define KHD_CHECK(name, expr) do {                      \
    printf("keys_hostile_derive: %s... ", (name));      \
    if (expr) printf("OK\n");                           \
    else { printf("FAIL\n"); failures++; }              \
} while (0)

/* Mainnet BIP32 xpub version prefix (0x0488B21E). */
static const unsigned char KHD_XPUB_VERSION[4] = { 0x04, 0x88, 0xB2, 0x1E };

int test_keys_hostile_derive(void)
{
    printf("\n=== hostile key-derivation / address-codec tests ===\n");
    int failures = 0;

    /* A real compressed parent key, so the derivation checks below fail for
     * the reason under test and not because the key is nonsense. */
    struct privkey parent_priv;
    privkey_init(&parent_priv);
    privkey_make_new(&parent_priv, true);
    struct pubkey parent_pub;
    bool have_parent = privkey_get_pubkey(&parent_priv, &parent_pub);
    KHD_CHECK("fixture: compressed parent public key derived",
              have_parent && parent_pub.size == COMPRESSED_PUBLIC_KEY_SIZE);

    struct uint256 cc;
    memset(&cc, 0x5A, sizeof(cc));

    /* ── 1. pubkey_derive totality ─────────────────────────────────── */
    {
        struct pubkey child;
        struct uint256 cc_child;

        /* Hardened index: bit 31 set. Only a PRIVATE key can derive a
         * hardened child, so this is a caller error that a watch-only wallet
         * can reach with an attacker-chosen path. */
        KHD_CHECK("hardened index rejected (no abort)",
                  !pubkey_derive(&parent_pub, &child, &cc_child,
                                 0x80000000u, &cc));
        KHD_CHECK("largest hardened index rejected (no abort)",
                  !pubkey_derive(&parent_pub, &child, &cc_child,
                                 0xFFFFFFFFu, &cc));

        /* Empty parent: pubkey_is_valid() is false. */
        struct pubkey empty;
        pubkey_init(&empty);
        KHD_CHECK("empty parent key rejected (no abort)",
                  !pubkey_derive(&empty, &child, &cc_child, 0, &cc));

        /* Uncompressed 65-byte parent: BIP32 hashes the 33-byte compressed
         * form, so an uncompressed parent has no defined derivation. */
        struct pubkey uncompressed = parent_pub;
        KHD_CHECK("fixture: parent decompresses to 65 bytes",
                  pubkey_decompress(&uncompressed) &&
                  uncompressed.size == PUBLIC_KEY_SIZE);
        KHD_CHECK("uncompressed parent key rejected (no abort)",
                  !pubkey_derive(&uncompressed, &child, &cc_child, 0, &cc));

        /* The boundary just below hardened must still work. */
        KHD_CHECK("index 0x7FFFFFFF (last non-hardened) still derives",
                  pubkey_derive(&parent_pub, &child, &cc_child,
                                0x7FFFFFFFu, &cc));
    }

    /* ── 2. ext_pubkey_encode / hd_serialize_xpub on a bad key ─────── */
    {
        struct ext_pubkey epk;
        memset(&epk, 0, sizeof(epk));
        epk.nDepth = 1;
        epk.nChild = 7;
        epk.chaincode = cc;
        epk.pubkey = parent_pub;

        unsigned char code[BIP32_EXTKEY_SIZE];
        KHD_CHECK("compressed ext_pubkey encodes",
                  ext_pubkey_encode(&epk, code));

        char xpub[HD_XKEY_STRING_SIZE];
        KHD_CHECK("compressed ext_pubkey serializes to an xpub string",
                  hd_serialize_xpub(&epk, KHD_XPUB_VERSION,
                                    xpub, sizeof(xpub)));

        /* Round-trip proves the encoder still produces what the decoder
         * accepts — the guard must not have changed the happy path. */
        struct ext_pubkey back;
        memset(&back, 0, sizeof(back));
        bool round = hd_deserialize_xpub(xpub, KHD_XPUB_VERSION, &back);
        KHD_CHECK("xpub round-trips (depth, index, chaincode, key)",
                  round && back.nDepth == 1 && back.nChild == 7 &&
                  memcmp(back.chaincode.data, cc.data, 32) == 0 &&
                  back.pubkey.size == COMPRESSED_PUBLIC_KEY_SIZE &&
                  memcmp(back.pubkey.vch, parent_pub.vch,
                         COMPRESSED_PUBLIC_KEY_SIZE) == 0);

        /* Uncompressed key: no room in the 74-byte body. Used to assert. */
        struct ext_pubkey bad = epk;
        KHD_CHECK("fixture: uncompressed ext_pubkey built",
                  pubkey_decompress(&bad.pubkey) &&
                  bad.pubkey.size == PUBLIC_KEY_SIZE);
        KHD_CHECK("uncompressed ext_pubkey_encode returns false (no abort)",
                  !ext_pubkey_encode(&bad, code));
        KHD_CHECK("uncompressed hd_serialize_xpub returns false (no abort)",
                  !hd_serialize_xpub(&bad, KHD_XPUB_VERSION,
                                     xpub, sizeof(xpub)));

        /* Empty key: size 0, also unencodable. */
        struct ext_pubkey none = epk;
        pubkey_init(&none.pubkey);
        KHD_CHECK("empty ext_pubkey_encode returns false (no abort)",
                  !ext_pubkey_encode(&none, code));
    }

    /* ── 3. hd_deserialize_xpub boundary corpus ────────────────────── */
    {
        struct ext_pubkey out;
        static const unsigned char wrong_version[4] = {
            0x04, 0x88, 0xAD, 0xE4 /* xprv prefix, not xpub */
        };

        struct ext_pubkey epk;
        memset(&epk, 0, sizeof(epk));
        epk.pubkey = parent_pub;
        char xpub[HD_XKEY_STRING_SIZE];
        bool built = hd_serialize_xpub(&epk, KHD_XPUB_VERSION,
                                       xpub, sizeof(xpub));
        KHD_CHECK("fixture: xpub string built", built);

        KHD_CHECK("wrong version prefix rejected",
                  !hd_deserialize_xpub(xpub, wrong_version, &out));

        /* Truncated: lop off the tail, which also breaks the checksum. */
        char truncated[HD_XKEY_STRING_SIZE];
        memcpy(truncated, xpub, sizeof(truncated));
        size_t xlen = strlen(truncated);
        KHD_CHECK("fixture: xpub is long enough to truncate", xlen > 20);
        truncated[xlen - 10] = '\0';
        KHD_CHECK("truncated xpub rejected",
                  !hd_deserialize_xpub(truncated, KHD_XPUB_VERSION, &out));

        /* Wrong decoded length but a VALID checksum — this gets past
         * base58check_decode and must be caught by the length check. */
        {
            unsigned char shortpayload[20];
            memcpy(shortpayload, KHD_XPUB_VERSION, 4);
            memset(shortpayload + 4, 0x11, sizeof(shortpayload) - 4);
            char shortstr[HD_XKEY_STRING_SIZE];
            size_t written = 0;
            bool ok = domain_encoding_base58check_encode(
                shortpayload, sizeof(shortpayload),
                shortstr, sizeof(shortstr), &written);
            KHD_CHECK("fixture: short-but-valid-checksum xpub built", ok);
            KHD_CHECK("valid checksum, wrong length rejected",
                      !hd_deserialize_xpub(shortstr, KHD_XPUB_VERSION, &out));
        }

        /* Degenerate all-'1' string: decodes to a run of leading zero bytes,
         * so the length/version checks are the only thing standing there. */
        {
            char ones[200];
            memset(ones, '1', sizeof(ones) - 1);
            ones[sizeof(ones) - 1] = '\0';
            KHD_CHECK("all-'1' string rejected",
                      !hd_deserialize_xpub(ones, KHD_XPUB_VERSION, &out));
        }
        KHD_CHECK("empty string rejected",
                  !hd_deserialize_xpub("", KHD_XPUB_VERSION, &out));
        KHD_CHECK("single '1' rejected",
                  !hd_deserialize_xpub("1", KHD_XPUB_VERSION, &out));

        /* Over-long blob: past the decoder's 1023-char stack-VLA cap, which
         * is the bound that keeps an attacker-sized string off the stack. */
        {
            static char huge[4096];
            memset(huge, 'z', sizeof(huge) - 1);
            huge[sizeof(huge) - 1] = '\0';
            KHD_CHECK("over-long blob rejected (VLA cap holds)",
                      !hd_deserialize_xpub(huge, KHD_XPUB_VERSION, &out));
        }
    }

    /* ── 4. Base58 codec totality ──────────────────────────────────── */
    {
        const unsigned char payload[] = {
            0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55,
            0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B,
            0xEE,
        };
        char enc[128];
        size_t enc_len = 0;
        KHD_CHECK("base58 encode of a real address payload",
                  domain_encoding_base58_encode(payload, sizeof(payload),
                                                enc, sizeof(enc), &enc_len) &&
                  enc_len == strlen(enc));

        /* Round-trip identity. */
        {
            unsigned char dec[128];
            size_t dec_len = 0;
            bool ok = domain_encoding_base58_decode(enc, dec, sizeof(dec),
                                                    &dec_len);
            KHD_CHECK("base58 round-trip is byte-identical",
                      ok && dec_len == sizeof(payload) &&
                      memcmp(dec, payload, sizeof(payload)) == 0);
        }

        /* Output buffer exactly one byte short (the encoder needs room for
         * the NUL as well as the digits). */
        {
            char tight[128];
            size_t need = enc_len + 1; /* digits + NUL */
            size_t out_len = 0;
            KHD_CHECK("base58 encode fails when out_size is one byte short",
                      !domain_encoding_base58_encode(payload, sizeof(payload),
                                                     tight, need - 1,
                                                     &out_len));
            KHD_CHECK("base58 encode succeeds at exactly the needed size",
                      domain_encoding_base58_encode(payload, sizeof(payload),
                                                    tight, need, &out_len));
            KHD_CHECK("base58 encode into a zero-size buffer fails",
                      !domain_encoding_base58_encode(payload, sizeof(payload),
                                                     tight, 0, &out_len));
        }

        /* Decode output buffer one byte short. */
        {
            unsigned char dec[128];
            size_t dec_len = 0;
            KHD_CHECK("base58 decode fails when out_size is one byte short",
                      !domain_encoding_base58_decode(enc, dec,
                                                     sizeof(payload) - 1,
                                                     &dec_len));
        }

        /* Out-of-alphabet characters: '0', 'O', 'I', 'l' are the four
         * deliberately-excluded look-alikes, plus a non-ASCII byte. */
        {
            unsigned char dec[128];
            size_t dec_len = 0;
            KHD_CHECK("base58 decode rejects '0'",
                      !domain_encoding_base58_decode("1230", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects 'O'",
                      !domain_encoding_base58_decode("123O", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects 'I'",
                      !domain_encoding_base58_decode("123I", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects 'l'",
                      !domain_encoding_base58_decode("123l", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects a high-bit byte",
                      !domain_encoding_base58_decode("123\xC3\xA9", dec,
                                                     sizeof(dec), &dec_len));
        }

        /* Whitespace: leading/trailing tolerated, embedded rejected. */
        {
            unsigned char dec[128];
            size_t dec_len = 0;
            KHD_CHECK("base58 decode rejects embedded whitespace",
                      !domain_encoding_base58_decode("12 34", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects an embedded tab",
                      !domain_encoding_base58_decode("12\t34", dec,
                                                     sizeof(dec), &dec_len));
            KHD_CHECK("base58 decode rejects an embedded NUL-free newline",
                      !domain_encoding_base58_decode("12\n34", dec,
                                                     sizeof(dec), &dec_len));
        }

        /* Length caps on both sides of the stack VLA. */
        {
            static char longstr[2048];
            memset(longstr, 'z', sizeof(longstr) - 1);
            longstr[sizeof(longstr) - 1] = '\0';
            unsigned char dec[128];
            size_t dec_len = 0;
            KHD_CHECK("base58 decode refuses a >1023-char string",
                      !domain_encoding_base58_decode(longstr, dec,
                                                     sizeof(dec), &dec_len));

            static unsigned char bigpayload[2048];
            memset(bigpayload, 0xAB, sizeof(bigpayload));
            char bigout[8192];
            size_t big_len = 0;
            KHD_CHECK("base58 encode refuses a >1 KB payload",
                      !domain_encoding_base58_encode(bigpayload,
                                                     sizeof(bigpayload),
                                                     bigout, sizeof(bigout),
                                                     &big_len));
            KHD_CHECK("base58check encode refuses a >1 KB payload",
                      !domain_encoding_base58check_encode(
                          bigpayload, sizeof(bigpayload),
                          bigout, sizeof(bigout), &big_len));
        }

        /* base58check: a flipped digit must fail the checksum, not abort. */
        {
            char chk[128];
            size_t chk_len = 0;
            bool built = domain_encoding_base58check_encode(
                payload, sizeof(payload), chk, sizeof(chk), &chk_len);
            KHD_CHECK("fixture: base58check string built",
                      built && chk_len > 4);
            unsigned char dec[128];
            size_t dec_len = 0;
            KHD_CHECK("base58check round-trips",
                      domain_encoding_base58check_decode(chk, dec,
                                                         sizeof(dec),
                                                         &dec_len) &&
                      dec_len == sizeof(payload) &&
                      memcmp(dec, payload, sizeof(payload)) == 0);
            chk[chk_len - 1] = (chk[chk_len - 1] == 'z') ? 'y' : 'z';
            KHD_CHECK("base58check rejects a flipped checksum digit",
                      !domain_encoding_base58check_decode(chk, dec,
                                                          sizeof(dec),
                                                          &dec_len));
        }
    }

    /* ── 5. Sapling witness deserialize: depth bound ───────────────── */
    {
        /* incremental_witness_deserialize writes `depth` straight into
         * w->tree.depth / w->cursor.depth without going through tree_init,
         * so tree_init's depth assert never runs on this path. An
         * out-of-range depth overruns the fixed parents[]/has_parent[]
         * arrays during the root fold. The stream contents are irrelevant:
         * the guard must fire before a single byte is read. */
        unsigned char blob[64];
        memset(blob, 0, sizeof(blob));

        struct incremental_witness w;
        memset(&w, 0, sizeof(w));

        struct byte_stream s;
        stream_init_from_data(&s, blob, sizeof(blob));
        KHD_CHECK("witness deserialize refuses depth = 0",
                  !incremental_witness_deserialize(
                      &w, &s, 0,
                      sha256_compress_combine, sha256_compress_uncommitted));
        stream_free(&s);

        stream_init_from_data(&s, blob, sizeof(blob));
        KHD_CHECK("witness deserialize refuses depth = MAX_TREE_DEPTH + 1",
                  !incremental_witness_deserialize(
                      &w, &s, MAX_TREE_DEPTH + 1,
                      sha256_compress_combine, sha256_compress_uncommitted));
        stream_free(&s);

        stream_init_from_data(&s, blob, sizeof(blob));
        KHD_CHECK("witness deserialize refuses a wildly out-of-range depth",
                  !incremental_witness_deserialize(
                      &w, &s, (size_t)1 << 40,
                      sha256_compress_combine, sha256_compress_uncommitted));
        stream_free(&s);

        /* An in-range depth must still be ACCEPTED — the guard must not
         * have narrowed what already works. A real serialized witness is
         * round-tripped here so the check is end-to-end, not just the
         * bounds test's mirror image. */
        struct incremental_merkle_tree t;
        sprout_tree_init(&t); /* SHA256 combine: no Sapling params needed */
        struct uint256 leaf;
        memset(&leaf, 0x11, sizeof(leaf));
        incremental_tree_append(&t, &leaf);

        struct incremental_witness ok_w;
        incremental_witness_init(&ok_w, &t);
        struct byte_stream ok_s;
        stream_init(&ok_s, 4096);
        bool serialized = incremental_witness_serialize(&ok_w, &ok_s);

        struct incremental_witness reloaded;
        struct byte_stream rs;
        stream_init_from_data(&rs, ok_s.data, ok_s.size);
        KHD_CHECK("witness deserialize still accepts an in-range depth",
                  serialized &&
                  incremental_witness_deserialize(
                      &reloaded, &rs, INCREMENTAL_MERKLE_TREE_DEPTH,
                      t.combine, t.uncommitted));
        stream_free(&rs);
        stream_free(&ok_s);
    }

    /* ── 6. Equihash parameter admissibility ───────────────────────── */
    {
        /* The Equihash bit-packers assert on their width assumptions and
         * those asserts are live in release builds. Block verification
         * cannot reach them with a bad (N,K) — equihash_solution_params
         * admits only the four sets below — but a future chain-params entry
         * read at a mining/config seam could. This predicate is what the
         * mining seams call to refuse one. */
        KHD_CHECK("equihash (200,9) mainnet parameters supported",
                  equihash_params_supported(200, 9));
        KHD_CHECK("equihash (192,7) parameters supported",
                  equihash_params_supported(192, 7));
        KHD_CHECK("equihash (96,5) parameters supported",
                  equihash_params_supported(96, 5));
        KHD_CHECK("equihash (48,5) regtest parameters supported",
                  equihash_params_supported(48, 5));

        /* collision_bit_length = N/(K+1) below the packers' 8-bit floor. */
        KHD_CHECK("equihash (48,11) refused (collision bits < 8)",
                  !equihash_params_supported(48, 11));
        /* collision_bit_length above the 24-bit ceiling that
         * 8*sizeof(uint32_t) >= 7 + (bits+1) imposes. */
        KHD_CHECK("equihash (200,7) refused (collision bits > 24)",
                  !equihash_params_supported(200, 7));
        KHD_CHECK("equihash (256,3) refused (collision bits > 24)",
                  !equihash_params_supported(256, 3));
        /* Degenerate inputs must not divide by zero or shift out of range. */
        KHD_CHECK("equihash (0,0) refused", !equihash_params_supported(0, 0));
        KHD_CHECK("equihash (200,0) refused",
                  !equihash_params_supported(200, 0));
        KHD_CHECK("equihash K=64 refused (1 << K out of range)",
                  !equihash_params_supported(200, 64));
        KHD_CHECK("equihash N > 512 refused (no index per hash output)",
                  !equihash_params_supported(1024, 9));
        KHD_CHECK("equihash N=UINT_MAX refused",
                  !equihash_params_supported(0xFFFFFFFFu, 9));
    }

    return failures;
}
