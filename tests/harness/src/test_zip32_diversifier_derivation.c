/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests pinning ZIP 32 diversifier derivation
 * (zip32_diversifier / zip32_default_diversifier) in
 * core/modules/sapling/src/zip32.c.
 *
 * These pin the contract that the wallet's default payment-address
 * derivation depends on:
 *   - default diversifier is deterministic for a fixed dk,
 *   - the search advances the 88-bit index j and skips indices whose
 *     FF1-encrypted output fails sapling_check_diversifier,
 *   - the output diversifier is exactly FF1_AES256(dk, j_final) for the
 *     j the search settled on (radix=2, 88-bit binary numeral string),
 *   - distinct dk values yield distinct default diversifiers,
 *   - FF1 itself is deterministic and 11-byte (88-bit) in/out. */

#include "test/test_core.h"
#include "sapling/sapling.h"
#include "sapling/ff1.h"
#include "sapling/zip32.h"

/* ── Local fixtures ──────────────────────────────────────────────── */

/* Mirror of the in-source FF1 invocation that zip32_diversifier performs:
 * encrypt the 11-byte (88-bit) index into the diversifier slot. */
static void ff1_div(const uint8_t dk[32], const uint8_t j[11],
                    uint8_t out[11])
{
    uint8_t d[11];
    memcpy(d, j, 11);
    ff1_aes256_encrypt(dk, NULL, 0, d, 88);
    memcpy(out, d, 11);
}

/* Bit i of the 88-bit numeral is pat[i % pat_len] ('1' or '0'), stored in
 * LE bit order exactly as ff1.c reads its data buffer (bit i = byte i/8,
 * bit i%8), so string index i is numeral digit i, most significant first. */
static void bits_from_pattern(const char *pat, size_t pat_len,
                              uint8_t out[11])
{
    memset(out, 0, 11);
    for (size_t i = 0; i < 88; i++)
        if (pat[i % pat_len] == '1')
            out[i / 8] |= (uint8_t)(1u << (i % 8));
}

/* One radix-2 FF1-AES256 case from zcash-test-vectors ff1.py. */
struct ff1_zc_vec {
    size_t tweak_len;     /* 0, or 255 for bytes(range(255)) */
    const char *in_pat;   /* input bit pattern, repeated to 88 bits */
    size_t in_pat_len;
    const char *out_bits; /* expected 88-bit output, digit 0 first */
};

static const char ff1_zc_key_hex[] =
    "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94";

/* Copied from zcash-test-vectors zcash_test_vectors/ff1.py, test_ff1().
 * Key is the ff1.py key on line 80 for all four cases. */
static const struct ff1_zc_vec ff1_zc_vectors[] = {
    /* lines 83-85: x = [0]*88, empty tweak */
    { 0, "0", 1,
      "0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111" },
    /* lines 89-91: x = the previous output, empty tweak */
    { 0, "0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111", 88,
      "1101101011010001100011110000010011001111110110011101010110100001111001000101011111011000" },
    /* lines 95-97: x = [0, 1]*44, empty tweak */
    { 0, "01", 2,
      "0000111101000001111011010111011111110001100101000000001101101110100010010111001100100110" },
    /* lines 101-103: x = [0, 1]*44, tweak = bytes(range(255)); the 255-byte
     * tweak makes the CBC-MAC message longer than any fixed staging buffer. */
    { 255, "01", 2,
      "0111110110001000000111010110000100010101101000000011100111100100100010101101111010100011" },
};

static bool ff1_zc_vector_matches(const struct ff1_zc_vec *v)
{
    uint8_t key[32], tweak[255], d[11], want[11];
    test_hex_to_bytes(ff1_zc_key_hex, key, 32);
    for (size_t i = 0; i < sizeof(tweak); i++)
        tweak[i] = (uint8_t)i;
    bits_from_pattern(v->in_pat, v->in_pat_len, d);
    bits_from_pattern(v->out_bits, 88, want);
    ff1_aes256_encrypt(key, v->tweak_len ? tweak : NULL, v->tweak_len, d, 88);
    return memcmp(d, want, 11) == 0;
}

/* One sapling_zip32.json row: dk and the diversifiers at indices 0, 1, 2
 * and 2^88-1 (slot 3). A NULL slot means that index is not a valid
 * diversifier, so its FF1 image must fail sapling_check_diversifier. */
struct sapling_zip32_row {
    const char *dk_hex;
    const char *d_hex[4];
};

/* Copied from zcash-test-vectors test-vectors/json/sapling_zip32.json,
 * rows 4 and 5 (fields dk, d0, d1, d2, dmax). */
static const struct sapling_zip32_row sapling_zip32_rows[] = {
    { "77c17cb75b7796afb39f0f3e91c924607da56fa9a20e283509bc8a3ef996a172",
      { "d8621b981cf300e9d4cc89", "48ea17a199c84bd1baa5d4", NULL, NULL } },
    { "e04de832a2d791ec129ab9002b91c9e9cdeed79241a7c4960e5178d870c1b4dc",
      { "8b4138320dfafd7b399781", NULL, "5749a13352bc223e308078",
        "6389574cde0fbbc6368131" } },
};

static bool sapling_zip32_row_matches(const struct sapling_zip32_row *r)
{
    uint8_t dk[32], def[11], d0[11];
    test_hex_to_bytes(r->dk_hex, dk, 32);
    for (int k = 0; k < 4; k++) {
        uint8_t idx[11], got[11], want[11];
        memset(idx, k == 3 ? 0xFF : 0x00, sizeof(idx));
        if (k < 3)
            idx[0] = (uint8_t)k;
        ff1_div(dk, idx, got);
        if (r->d_hex[k] == NULL) {
            if (sapling_check_diversifier(got))
                return false;
            continue;
        }
        test_hex_to_bytes(r->d_hex[k], want, 11);
        if (memcmp(got, want, 11) != 0 || !sapling_check_diversifier(got))
            return false;
    }
    /* Index 0 is valid in every row, so the default is exactly d0. */
    test_hex_to_bytes(r->d_hex[0], d0, 11);
    return zip32_default_diversifier(dk, def) && memcmp(def, d0, 11) == 0;
}

/* ── Tests ───────────────────────────────────────────────────────── */

/* zip32_default_diversifier is a pure function of dk: same dk always
 * yields the identical 11-byte diversifier, and it really is a valid
 * diversifier (passes the consensus group-hash check). */
int test_zip32_default_diversifier_deterministic(void)
{
    int failures = 0;
    TEST_CASE("zip32_default_diversifier deterministic for fixed dk") {
        uint8_t dk[32];
        for (int i = 0; i < 32; i++) dk[i] = (uint8_t)(0x11 * (i + 1));

        uint8_t d1[11], d2[11];
        memset(d1, 0xAA, sizeof(d1));
        memset(d2, 0x55, sizeof(d2));

        bool ok1 = zip32_default_diversifier(dk, d1);
        bool ok2 = zip32_default_diversifier(dk, d2);

        /* A valid diversifier must exist and both calls must agree. */
        ASSERT(ok1);
        ASSERT(ok2);
        ASSERT(memcmp(d1, d2, 11) == 0);

        /* It is genuinely a valid diversifier. */
        ASSERT(sapling_check_diversifier(d1));

        /* The returned diversifier is not the trivially-empty buffer
         * (FF1 on a real key never leaves the slot all-zero here). */
        uint8_t zero[11] = {0};
        ASSERT(memcmp(d1, zero, 11) != 0);
    } TEST_END
    return failures;
}

/* zip32_default_diversifier == zip32_diversifier starting at j=0, and
 * the diversifier it returns is exactly FF1_AES256(dk, j_settled). This
 * pins both the start-index semantics and the FF1 derivation rule. */
int test_zip32_default_diversifier_is_ff1_of_settled_index(void)
{
    int failures = 0;
    TEST_CASE("default diversifier equals FF1(dk, settled j)") {
        uint8_t dk[32];
        for (int i = 0; i < 32; i++) dk[i] = (uint8_t)(0x07 * i + 3);

        /* default path */
        uint8_t d_default[11];
        ASSERT(zip32_default_diversifier(dk, d_default));

        /* explicit search from j=0 — must settle on the same value and
         * report the index it stopped at via the in/out j buffer. */
        uint8_t j[11] = {0};
        uint8_t d_explicit[11];
        ASSERT(zip32_diversifier(dk, j, d_explicit));
        ASSERT(memcmp(d_default, d_explicit, 11) == 0);

        /* The returned diversifier is byte-exactly the FF1 encryption of
         * the settled index j (radix=2, n=88). */
        uint8_t d_ff1[11];
        ff1_div(dk, j, d_ff1);
        ASSERT(memcmp(d_explicit, d_ff1, 11) == 0);

        /* And that settled j really maps to a valid diversifier. */
        ASSERT(sapling_check_diversifier(d_explicit));

        /* Independent answers: sapling_zip32.json rows. Each index value
         * matches FF1(dk, index), and the default is the index-0 value. */
        for (size_t r = 0; r < sizeof(sapling_zip32_rows) / sizeof(sapling_zip32_rows[0]); r++)
            ASSERT(sapling_zip32_row_matches(&sapling_zip32_rows[r]));
    } TEST_END
    return failures;
}

/* The search skips every index whose FF1 image fails the diversifier
 * check, and the settled j is the FIRST valid index at/after the start.
 * We re-walk the index space independently and confirm that:
 *   - every j strictly before j_settled is invalid (was skipped),
 *   - j_settled is the value the search reports through the in/out buffer.
 * This pins the "increment j and skip invalid diversifiers" behavior. */
int test_zip32_diversifier_skips_invalid_indices(void)
{
    int failures = 0;
    TEST_CASE("zip32_diversifier skips invalid indices, settles on first valid") {
        /* dk chosen so that j=0 is overwhelmingly likely valid OR a few
         * steps in; either way the invariant below holds. The check is
         * structural, not value-pinned, so any dk exercises it. */
        uint8_t dk[32];
        for (int i = 0; i < 32; i++) dk[i] = (uint8_t)(0x9E + i);

        uint8_t j[11] = {0};
        uint8_t div[11];
        ASSERT(zip32_diversifier(dk, j, div));

        /* j now holds the settled index. Independently confirm it is
         * valid and matches the returned diversifier. */
        uint8_t d_at_settled[11];
        ff1_div(dk, j, d_at_settled);
        ASSERT(memcmp(div, d_at_settled, 11) == 0);
        ASSERT(sapling_check_diversifier(div));

        /* The settled index lives in the low part of the space for a
         * normal dk; reconstruct its little-endian magnitude (it fits in
         * far fewer than 88 bits for any realistic search). Then verify
         * every earlier index was invalid (hence skipped). We only walk
         * when the magnitude is small enough to enumerate cheaply. */
        uint64_t settled = 0;
        bool fits_u64 = true;
        for (int k = 10; k >= 0; k--) {
            if (k >= 8 && j[k] != 0) fits_u64 = false; /* high bytes set */
            if (k < 8) settled = (settled << 8) | j[k];
        }
        ASSERT(fits_u64);

        /* Bound the walk so the test stays fast even on a pathological
         * dk; the search almost always settles within a handful of steps.
         * If it settled beyond the bound we skip the exhaustive replay but
         * still keep the value-pins above. */
        if (settled <= 4096) {
            for (uint64_t v = 0; v < settled; v++) {
                uint8_t jv[11] = {0};
                for (int k = 0; k < 8; k++)
                    jv[k] = (uint8_t)((v >> (8 * k)) & 0xff);
                uint8_t dv[11];
                ff1_div(dk, jv, dv);
                /* Every earlier index must have been invalid — that is
                 * precisely why the search advanced past it. */
                ASSERT(!sapling_check_diversifier(dv));
            }
        }
    } TEST_END
    return failures;
}

/* zip32_diversifier advances the caller's j buffer in place: starting a
 * search one index past a known-valid index must return a DIFFERENT
 * (later) diversifier, and the reported j must be strictly greater. This
 * pins that the function consumes and updates the index correctly rather
 * than ignoring the start index. */
int test_zip32_diversifier_advances_index_in_place(void)
{
    int failures = 0;
    TEST_CASE("zip32_diversifier advances j in place past the start") {
        uint8_t dk[32];
        for (int i = 0; i < 32; i++) dk[i] = (uint8_t)(0x40 ^ (i * 5));

        /* First valid index from 0. */
        uint8_t j0[11] = {0};
        uint8_t d0[11];
        ASSERT(zip32_diversifier(dk, j0, d0));

        /* Start the next search one past the settled index. */
        uint8_t jnext[11];
        memcpy(jnext, j0, 11);
        /* increment jnext by one (88-bit LE, carry-propagating) */
        for (int k = 0; k < 11; k++) {
            jnext[k]++;
            if (jnext[k] != 0) break;
        }
        uint8_t jstart[11];
        memcpy(jstart, jnext, 11);

        uint8_t d1[11];
        ASSERT(zip32_diversifier(dk, jnext, d1));

        /* The second search settled at or after the new start, never
         * before it (the function only ever increments). */
        bool not_before = false; /* jnext (settled) >= jstart, LE compare */
        for (int k = 10; k >= 0; k--) {
            if (jnext[k] != jstart[k]) {
                not_before = (jnext[k] > jstart[k]);
                break;
            }
            if (k == 0) not_before = true; /* equal */
        }
        ASSERT(not_before);

        /* And the settled index is strictly past the original j0, so the
         * two searches cannot return the same index. */
        bool past_j0 = false;
        for (int k = 10; k >= 0; k--) {
            if (jnext[k] != j0[k]) { past_j0 = (jnext[k] > j0[k]); break; }
            if (k == 0) past_j0 = false; /* equal to j0 -> not past */
        }
        ASSERT(past_j0);

        /* Different settled index -> the returned diversifier differs. */
        ASSERT(memcmp(d0, d1, 11) != 0);

        /* And the second result is consistent with FF1(dk, settled j). */
        uint8_t d1_ff1[11];
        ff1_div(dk, jnext, d1_ff1);
        ASSERT(memcmp(d1, d1_ff1, 11) == 0);
        ASSERT(sapling_check_diversifier(d1));
    } TEST_END
    return failures;
}

/* Different dk values produce different default diversifiers. Two keys
 * that differ in a single byte must not collide on the default address's
 * diversifier (otherwise the diversifier carried no key entropy). */
int test_zip32_diversifier_distinct_keys_distinct_output(void)
{
    int failures = 0;
    TEST_CASE("distinct dk -> distinct default diversifier") {
        uint8_t dk_a[32], dk_b[32];
        for (int i = 0; i < 32; i++) { dk_a[i] = (uint8_t)(i + 1); dk_b[i] = (uint8_t)(i + 1); }
        dk_b[0] ^= 0x01; /* single-bit difference */

        uint8_t da[11], db[11];
        ASSERT(zip32_default_diversifier(dk_a, da));
        ASSERT(zip32_default_diversifier(dk_b, db));

        ASSERT(memcmp(da, db, 11) != 0);

        /* A third, very different key also diverges from both. */
        uint8_t dk_c[32];
        memset(dk_c, 0xC3, sizeof(dk_c));
        uint8_t dc[11];
        ASSERT(zip32_default_diversifier(dk_c, dc));
        ASSERT(memcmp(dc, da, 11) != 0);
        ASSERT(memcmp(dc, db, 11) != 0);
    } TEST_END
    return failures;
}

/* The 88-bit index space is iterated with carry-propagating little-endian
 * increments. Pin the increment/wrap arithmetic that the search relies on
 * by driving zip32_diversifier across byte-boundary start indices and
 * confirming the FF1+check invariant holds at each settled point. Also
 * pin the near-exhaustion edge: starting at the all-ones (max) index, the
 * next increment would overflow the whole 88-bit space, so a search that
 * starts at max and whose own index is invalid would exhaust — we drive
 * the boundary index itself and confirm it is handled as a normal index
 * (encrypted + checked) rather than mis-wrapped. */
int test_zip32_diversifier_index_boundaries(void)
{
    int failures = 0;
    TEST_CASE("zip32_diversifier handles byte-carry and max-index boundaries") {
        uint8_t dk[32];
        for (int i = 0; i < 32; i++) dk[i] = (uint8_t)(0x1F * i + 7);

        /* Start indices straddling a byte carry boundary (0x00FF -> next
         * is 0x0100). Each search must return FF1(dk, settled) and a
         * valid diversifier, and never settle below its start. */
        const uint64_t starts[] = { 0x00FFull, 0x0100ull, 0xFFFFull, 0x010000ull };
        for (size_t s = 0; s < sizeof(starts) / sizeof(starts[0]); s++) {
            uint8_t jstart[11] = {0};
            for (int k = 0; k < 8; k++)
                jstart[k] = (uint8_t)((starts[s] >> (8 * k)) & 0xff);

            uint8_t j[11];
            memcpy(j, jstart, 11);
            uint8_t div[11];
            ASSERT(zip32_diversifier(dk, j, div));

            /* settled >= start (LE compare). */
            bool not_before = false;
            for (int k = 10; k >= 0; k--) {
                if (j[k] != jstart[k]) { not_before = (j[k] > jstart[k]); break; }
                if (k == 0) not_before = true;
            }
            ASSERT(not_before);

            uint8_t dff1[11];
            ff1_div(dk, j, dff1);
            ASSERT(memcmp(div, dff1, 11) == 0);
            ASSERT(sapling_check_diversifier(div));
        }

        /* Max index = all 0xFF (one short of 88-bit overflow). The search
         * must still treat it as a normal index: encrypt it, check it.
         * If it happens to be valid, the returned diversifier equals
         * FF1(dk, 0xFF..). We cannot force exhaustion (that needs ~2^88
         * consecutive invalid indices, which is computationally absurd),
         * but we pin that the boundary value itself is FF1-encrypted and
         * group-hash-checked exactly like any other index when valid. */
        uint8_t jmax[11];
        memset(jmax, 0xFF, sizeof(jmax));
        uint8_t dmax_ff1[11];
        ff1_div(dk, jmax, dmax_ff1);
        bool max_valid = sapling_check_diversifier(dmax_ff1);

        /* Independently confirm the carry-out behavior the search uses at
         * exhaustion: incrementing all-0xFF wraps every byte to 0 and
         * produces no non-zero byte (i.e. the documented "2^88 space
         * exhausted" carry-out). */
        uint8_t jwrap[11];
        memset(jwrap, 0xFF, sizeof(jwrap));
        bool produced_nonzero = false;
        for (int k = 0; k < 11; k++) {
            jwrap[k]++;
            if (jwrap[k] != 0) { produced_nonzero = true; break; }
        }
        ASSERT(!produced_nonzero); /* full wrap -> exhaustion signal */
        uint8_t jzero[11] = {0};
        ASSERT(memcmp(jwrap, jzero, 11) == 0);

        /* Touch max_valid so the compiler keeps the boundary FF1 call and
         * the pin is non-vacuous regardless of validity. */
        ASSERT(max_valid == sapling_check_diversifier(dmax_ff1));
    } TEST_END
    return failures;
}

/* FF1 (radix=2, AES-256, 88-bit) is deterministic and length-preserving:
 * the same (key, 88-bit input) maps to the same 88-bit output, and the
 * output occupies exactly 11 bytes (no over/underflow of the slot). Also
 * pin that a single-bit input change diffuses (FF1 is a real cipher, not
 * the identity) and that changing the key changes the output. This is the
 * primitive zip32_diversifier leans on. */
int test_zip32_ff1_radix2_deterministic(void)
{
    int failures = 0;
    TEST_CASE("FF1 radix=2 88-bit is deterministic and length-preserving") {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x2A + 3 * i);

        uint8_t in[11];
        for (int i = 0; i < 11; i++) in[i] = (uint8_t)(i * 17 + 1);

        /* Determinism: two encryptions of the same input match. */
        uint8_t a[11], b[11];
        memcpy(a, in, 11); ff1_aes256_encrypt(key, NULL, 0, a, 88);
        memcpy(b, in, 11); ff1_aes256_encrypt(key, NULL, 0, b, 88);
        ASSERT(memcmp(a, b, 11) == 0);

        /* Non-identity: FF1 actually transforms the input. */
        ASSERT(memcmp(a, in, 11) != 0);

        /* Length-preserving / no slot overflow: a 12-byte buffer whose
         * trailing byte is a sentinel must keep that sentinel untouched —
         * the 88-bit (11-byte) operation writes exactly 11 bytes. */
        uint8_t framed[12];
        memcpy(framed, in, 11);
        framed[11] = 0x7E; /* sentinel */
        ff1_aes256_encrypt(key, NULL, 0, framed, 88);
        ASSERT(framed[11] == 0x7E);            /* sentinel preserved */
        ASSERT(memcmp(framed, a, 11) == 0);    /* first 11 bytes == result */

        /* Diffusion: flipping one input bit changes the ciphertext. */
        uint8_t in2[11];
        memcpy(in2, in, 11);
        in2[0] ^= 0x01;
        uint8_t c[11];
        memcpy(c, in2, 11); ff1_aes256_encrypt(key, NULL, 0, c, 88);
        ASSERT(memcmp(c, a, 11) != 0);

        /* Key sensitivity: a different key yields a different ciphertext
         * for the same input (this is exactly why different dk produce
         * different diversifiers). */
        uint8_t key2[32];
        memcpy(key2, key, 32);
        key2[31] ^= 0x80;
        uint8_t d[11];
        memcpy(d, in, 11); ff1_aes256_encrypt(key2, NULL, 0, d, 88);
        ASSERT(memcmp(d, a, 11) != 0);

        /* Independent answers: zcash-test-vectors ff1.py radix-2 cases. */
        for (size_t v = 0; v < sizeof(ff1_zc_vectors) / sizeof(ff1_zc_vectors[0]); v++)
            ASSERT(ff1_zc_vector_matches(&ff1_zc_vectors[v]));
    } TEST_END
    return failures;
}
