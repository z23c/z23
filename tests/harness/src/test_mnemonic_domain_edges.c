/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boundary and refusal cases for contexts/wallet/domain/src/mnemonic.c,
 * written against the mutation sweep's survivors. They run from
 * test_mnemonic(), the group the sweep measures that file with.
 *
 * Phrases are the published BIP-39 vectors (trezor/python-mnemonic, entropy
 * 7f.., 80.., ff..); nothing here is a real wallet phrase.
 */

#include "domain/wallet/mnemonic.h"
#include "crypto/pbkdf2_sha512.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MDE_CHECK(name, expr) do {                                    \
    printf("mnemonic_domain_edges: %s... ", (name));                  \
    if ((expr)) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

#define MDE_GUARD 0x55
#define MDE_ERR(r, c) (!(r).ok && (r).code == DOMAIN_WALLET_MNEMONIC_ERR_##c)

#define ZOO4 "zoo zoo zoo zoo "
#define LEGAL8 "legal winner thank year wave sausage worth useful "
#define LETTER8 "letter advice cage absurd amount doctor acoustic avoid "

struct mde_vec {
    uint8_t fill;
    size_t len;
    const char *phrase;
};

static const struct mde_vec mde_vecs[] = {
    { 0x7f, 16, LEGAL8 "legal winner thank yellow" },
    { 0x80, 16, LETTER8 "letter advice cage above" },
    { 0xff, 16, ZOO4 ZOO4 "zoo zoo zoo wrong" },
    { 0x7f, 24, LEGAL8 LEGAL8 "legal will" },
    { 0x80, 24, LETTER8 LETTER8 "letter always" },
    { 0xff, 24, ZOO4 ZOO4 ZOO4 ZOO4 "zoo when" },
    { 0x7f, 32, LEGAL8 LEGAL8 "legal winner thank year wave sausage worth title" },
    { 0x80, 32, LETTER8 LETTER8 "letter advice cage absurd amount doctor acoustic bless" },
    { 0xff, 32, ZOO4 ZOO4 ZOO4 ZOO4 ZOO4 "zoo zoo zoo vote" },
};

static int mde_count_words(const char *phrase)
{
    int n = 1;
    for (const char *p = phrase; *p; p++)
        if (*p == ' ')
            n++;
    return n;
}

/* Replace the last word with the word whose index differs in one bit. */
static bool mde_flip_last_word(const char *phrase, int bit,
                               char *out, size_t cap)
{
    const char *sp = strrchr(phrase, ' ');
    if (!sp)
        return false;
    int idx = domain_wallet_mnemonic_wordlist_find(sp + 1);
    if (idx < 0)
        return false;
    const char *w = domain_wallet_mnemonic_wordlist_get(idx ^ (1 << bit));
    int head = (int)(sp - phrase) + 1;
    if (!w)
        return false;
    return snprintf(out, cap, "%.*s%s", head, phrase, w) < (int)cap;
}

/* ── the two ends of the wordlist ─────────────────────────────── */

static int mde_wordlist_ends(void)
{
    int failures = 0;
    MDE_CHECK("find(abandon) is the first index",
              domain_wallet_mnemonic_wordlist_find("abandon") == 0);
    MDE_CHECK("find(zoo) is the last index",
              domain_wallet_mnemonic_wordlist_find("zoo") == 2047);
    MDE_CHECK("find(zoo2) past the end is -1",
              domain_wallet_mnemonic_wordlist_find("zoo2") == -1);
    MDE_CHECK("find(NULL) is -1",
              domain_wallet_mnemonic_wordlist_find(NULL) == -1);
    const char *last = domain_wallet_mnemonic_wordlist_get(2047);
    MDE_CHECK("get(2047) is zoo", last && strcmp(last, "zoo") == 0);
    MDE_CHECK("get(2048) is NULL",
              domain_wallet_mnemonic_wordlist_get(2048) == NULL);
    MDE_CHECK("get(-1) is NULL",
              domain_wallet_mnemonic_wordlist_get(-1) == NULL);
    return failures;
}

/* ── entropy length and word count tables ─────────────────────── */

static size_t mde_words_for_entropy(size_t len)
{
    return (len >= 16 && len <= 32 && len % 4 == 0) ? (len - 16) / 4 * 3 + 12
                                                     : 0;
}

/* One entropy length: accepted with the right word count, or refused. */
static bool mde_entropy_len_case(size_t n)
{
    uint8_t entropy[48] = {0};
    char buf[512];
    size_t w = 77;
    size_t want_words = mde_words_for_entropy(n);
    struct zcl_result r = domain_wallet_mnemonic_from_entropy(
            entropy, n, buf, sizeof(buf), &w);
    if (want_words == 0)
        return MDE_ERR(r, ENTROPY_LEN) && w == 77;
    return r.ok && (size_t)mde_count_words(buf) == want_words &&
           w == strlen(buf);
}

/* One word count: the entropy length that carries it, or 0. */
static bool mde_word_count_case(size_t n)
{
    size_t want = 0;
    for (size_t e = 16; e <= 32; e += 4)
        if (mde_words_for_entropy(e) == n)
            want = e;
    return domain_wallet_mnemonic_entropy_bytes_for_words((int)n) == want;
}

static int mde_length_tables(void)
{
    int failures = 0;
    bool words_ok = true, bytes_ok = true;
    for (size_t n = 0; n <= 40; n++) {
        words_ok = words_ok && mde_entropy_len_case(n);
        bytes_ok = bytes_ok && mde_word_count_case(n);
    }
    MDE_CHECK("from_entropy accepts exactly 16/20/24/28/32 bytes", words_ok);
    MDE_CHECK("entropy_bytes_for_words is exact for 0..40", bytes_ok);
    MDE_CHECK("entropy_bytes_for_words(-1) is 0",
              domain_wallet_mnemonic_entropy_bytes_for_words(-1) == 0);
    MDE_CHECK("entropy_bytes_for_words(65) is 0",
              domain_wallet_mnemonic_entropy_bytes_for_words(65) == 0);
    return failures;
}

/* ── from_entropy: never writes past phrase_size ──────────────── */

static bool mde_tail_clean(const char *buf, size_t size, size_t cap)
{
    for (size_t i = size; i < cap; i++)
        if (buf[i] != MDE_GUARD)
            return false;
    return true;
}

static bool mde_exact_size_case(const uint8_t *entropy, size_t len,
                                size_t phrase_len, size_t size)
{
    char buf[160];
    size_t w = 4242;
    memset(buf, MDE_GUARD, sizeof(buf));
    struct zcl_result r = domain_wallet_mnemonic_from_entropy(
            entropy, len, buf, size, &w);
    if (!mde_tail_clean(buf, size, sizeof(buf)))
        return false;
    if (size >= phrase_len + 1)
        return r.ok && w == phrase_len && strlen(buf) == phrase_len;
    return MDE_ERR(r, BUF_TOO_SMALL) && w == 4242;
}

static bool mde_exact_size_sweep(const uint8_t *entropy, size_t len,
                                 size_t phrase_len)
{
    bool ok = true;
    for (size_t size = 1; size <= phrase_len + 2; size++)
        ok = ok && mde_exact_size_case(entropy, len, phrase_len, size);
    return ok;
}

static int mde_from_entropy_exact_sizes(void)
{
    int failures = 0;
    uint8_t zeros[16] = {0};
    uint8_t ones[16];
    memset(ones, 0xff, sizeof(ones));
    /* 11 x "abandon" + "about" and 11 x "zoo" + "wrong". */
    MDE_CHECK("from_entropy sizes around the 12-word abandon phrase",
              mde_exact_size_sweep(zeros, 16, 11 * 8 + 5));
    MDE_CHECK("from_entropy sizes around the 12-word zoo phrase",
              mde_exact_size_sweep(ones, 16, 11 * 4 + 5));
    return failures;
}

/* ── normalize ────────────────────────────────────────────────── */

static int mde_normalize_args(void)
{
    int failures = 0;
    char out[16];
    size_t n = 99;

    struct zcl_result r = domain_wallet_mnemonic_normalize(NULL, out,
                                                           sizeof(out), &n);
    MDE_CHECK("normalize null phrase reports zero written",
              MDE_ERR(r, NULL_PHRASE) && n == 0);
    n = 99;
    r = domain_wallet_mnemonic_normalize("a", NULL, 8, &n);
    MDE_CHECK("normalize null out is NULL_BUF, zero written",
              MDE_ERR(r, NULL_BUF) && n == 0);
    r = domain_wallet_mnemonic_normalize("a", out, 0, NULL);
    MDE_CHECK("normalize zero out_size is NULL_BUF", MDE_ERR(r, NULL_BUF));
    return failures;
}

static int mde_normalize_non_ascii(void)
{
    int failures = 0;
    char out[16];
    size_t n = 99;
    struct zcl_result r;

    memset(out, 'X', sizeof(out));
    n = 99;
    r = domain_wallet_mnemonic_normalize("a\x80", out, sizeof(out), &n);
    MDE_CHECK("normalize refuses byte 0x80, empties out, zero written",
              MDE_ERR(r, NON_ASCII) && out[0] == '\0' && n == 0);
    memset(out, 'X', sizeof(out));
    r = domain_wallet_mnemonic_normalize("\xff", out, sizeof(out), NULL);
    MDE_CHECK("normalize refuses byte 0xff, empties out",
              MDE_ERR(r, NON_ASCII) && out[0] == '\0');
    memset(out, 'X', sizeof(out));
    r = domain_wallet_mnemonic_normalize("a\x7f", out, sizeof(out), &n);
    MDE_CHECK("normalize keeps 0x7f, the last ASCII byte",
              r.ok && n == 2 && out[0] == 'a' && out[1] == '\x7f');
    return failures;
}

static int mde_normalize_leading_and_one_byte(void)
{
    int failures = 0;
    char out[16];
    size_t n = 99;
    struct zcl_result r = domain_wallet_mnemonic_normalize(" \t a  b", out,
                                                           sizeof(out), &n);
    MDE_CHECK("normalize drops leading whitespace, no leading space",
              r.ok && strcmp(out, "a b") == 0 && n == 3);
    memset(out, 'X', sizeof(out));
    r = domain_wallet_mnemonic_normalize("", out, 1, &n);
    MDE_CHECK("normalize empty phrase fits out_size 1",
              r.ok && out[0] == '\0' && n == 0);
    r = domain_wallet_mnemonic_normalize("  \n ", out, 1, &n);
    MDE_CHECK("normalize blank phrase fits out_size 1",
              r.ok && out[0] == '\0' && n == 0);
    memset(out, 'X', sizeof(out));
    r = domain_wallet_mnemonic_normalize("a", out, 1, &n);
    MDE_CHECK("normalize one byte does not fit out_size 1",
              MDE_ERR(r, BUF_TOO_SMALL) && out[0] == '\0' && out[1] == 'X');
    return failures;
}

static bool mde_normalize_case(const char *phrase, const char *want,
                               size_t size)
{
    size_t need = strlen(want) + 1;
    char buf[16];
    size_t n = 0;
    memset(buf, MDE_GUARD, sizeof(buf));
    struct zcl_result r = domain_wallet_mnemonic_normalize(phrase, buf,
                                                           size, &n);
    if (!mde_tail_clean(buf, size, sizeof(buf)))
        return false;
    if (size >= need)
        return r.ok && strcmp(buf, want) == 0 && n == need - 1;
    return MDE_ERR(r, BUF_TOO_SMALL) && buf[0] == '\0';
}

static bool mde_normalize_sweep(const char *phrase, const char *want)
{
    bool ok = true;
    for (size_t size = 1; size <= strlen(want) + 2; size++)
        ok = ok && mde_normalize_case(phrase, want, size);
    return ok;
}

static int mde_normalize_sizes(void)
{
    int failures = 0;
    MDE_CHECK("normalize size sweep, one word", mde_normalize_sweep("abc", "abc"));
    MDE_CHECK("normalize size sweep, two words",
              mde_normalize_sweep("ab  c", "ab c"));
    return failures;
}

/* ── decode: published vectors, checksum and count refusals ───── */

static bool mde_checksum_bit_flips(const char *phrase)
{
    int cs_bits = mde_count_words(phrase) / 3;
    bool ok = true;
    for (int bit = 0; bit < cs_bits; bit++) {
        char bad[512];
        uint8_t e[32];
        size_t el = 99;
        memset(e, 0xEE, sizeof(e));
        if (!mde_flip_last_word(phrase, bit, bad, sizeof(bad))) {
            ok = false;
            continue;
        }
        struct zcl_result v = domain_wallet_mnemonic_validate(bad);
        struct zcl_result d = domain_wallet_mnemonic_to_entropy(
                bad, e, sizeof(e), &el);
        ok = ok && MDE_ERR(v, CHECKSUM) && MDE_ERR(d, CHECKSUM) &&
             el == 0 && e[0] == 0xEE && e[31] == 0xEE;
    }
    return ok;
}

static bool mde_decodes_to(const char *phrase, uint8_t fill, size_t len)
{
    uint8_t e[32];
    size_t el = 0;
    memset(e, 0xEE, sizeof(e));
    struct zcl_result r = domain_wallet_mnemonic_to_entropy(phrase, e,
                                                            sizeof(e), &el);
    bool ok = r.ok && el == len;
    for (size_t i = 0; i < sizeof(e); i++)
        ok = ok && e[i] == (i < len ? fill : 0xEE);
    return ok && domain_wallet_mnemonic_validate(phrase).ok;
}

static bool mde_encodes_to(const char *phrase, uint8_t fill, size_t len)
{
    uint8_t entropy[32];
    char out[512];
    size_t w = 0;
    memset(entropy, fill, sizeof(entropy));
    struct zcl_result r = domain_wallet_mnemonic_from_entropy(
            entropy, len, out, sizeof(out), &w);
    return r.ok && strcmp(out, phrase) == 0 && w == strlen(phrase);
}

static int mde_published_vectors(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(mde_vecs) / sizeof(mde_vecs[0]); i++) {
        const struct mde_vec *v = &mde_vecs[i];
        MDE_CHECK("vector: entropy encodes to the published phrase",
                  mde_encodes_to(v->phrase, v->fill, v->len));
        MDE_CHECK("vector: phrase decodes to the published entropy",
                  mde_decodes_to(v->phrase, v->fill, v->len));
        MDE_CHECK("vector: every checksum bit is checked",
                  mde_checksum_bit_flips(v->phrase));
    }
    return failures;
}

/* 15 and 21 words have no published vector; the phrase is built here and
 * must round-trip and refuse a flipped checksum bit. */
static int mde_fifteen_and_twenty_one_words(void)
{
    int failures = 0;
    static const struct { size_t len; int words; } cases[] = {
        { 20, 15 }, { 28, 21 },
    };
    for (size_t i = 0; i < 2; i++) {
        uint8_t entropy[32];
        char phrase[512];
        size_t w = 0;
        memset(entropy, 0x7f, sizeof(entropy));
        struct zcl_result r = domain_wallet_mnemonic_from_entropy(
                entropy, cases[i].len, phrase, sizeof(phrase), &w);
        bool built = r.ok && mde_count_words(phrase) == cases[i].words;
        MDE_CHECK("generated 15/21-word phrase has the right word count",
                  built);
        MDE_CHECK("generated 15/21-word phrase decodes to its entropy",
                  built && mde_decodes_to(phrase, 0x7f, cases[i].len));
        MDE_CHECK("generated 15/21-word phrase checks every checksum bit",
                  built && mde_checksum_bit_flips(phrase));
    }
    return failures;
}

static int mde_word_count_refusals(void)
{
    int failures = 0;
    bool ok = true;
    for (int n = 1; n <= 30; n++) {
        char phrase[512] = "";
        for (int i = 0; i < n; i++)
            strcat(phrase, i ? " abandon" : "abandon");
        bool valid_count = n == 12 || n == 15 || n == 18 || n == 21 || n == 24;
        struct zcl_result r = domain_wallet_mnemonic_validate(phrase);
        ok = ok && (valid_count ? MDE_ERR(r, CHECKSUM)
                                : MDE_ERR(r, BAD_WORD_COUNT));
    }
    MDE_CHECK("1..30 words: only 12/15/18/21/24 reach the checksum", ok);
    return failures;
}

static int mde_unknown_word_reports(void)
{
    int failures = 0;
    struct zcl_result r = domain_wallet_mnemonic_validate(
            "abandon abandon zzzsecretzzz abandon abandon abandon "
            "abandon abandon abandon abandon abandon about");
    MDE_CHECK("unknown word names its position, 3",
              MDE_ERR(r, UNKNOWN_WORD) && strstr(r.message, "word 3 is not"));
    MDE_CHECK("unknown word message never carries the word",
              strstr(r.message, "zzzsecret") == NULL);

    /* The 25th word is refused for the count before it is looked up. */
    char phrase[512] = "";
    for (int i = 0; i < 24; i++)
        strcat(phrase, "abandon ");
    strcat(phrase, "zzzsecretzzz");
    r = domain_wallet_mnemonic_validate(phrase);
    MDE_CHECK("a 25th unknown word is BAD_WORD_COUNT, not UNKNOWN_WORD",
              MDE_ERR(r, BAD_WORD_COUNT));
    return failures;
}

static int mde_overlong_and_non_ascii(void)
{
    int failures = 0;
    char big[700] = "";
    for (int i = 0; i < 80; i++)
        strcat(big, "abandon ");
    uint8_t e[32];
    size_t el = 0;
    uint8_t seed[64];

    MDE_CHECK("validate: over-long phrase is PHRASE_LEN",
              MDE_ERR(domain_wallet_mnemonic_validate(big), PHRASE_LEN));
    struct zcl_result r = domain_wallet_mnemonic_to_entropy(big, e, sizeof(e), &el);
    MDE_CHECK("to_entropy: over-long phrase is PHRASE_LEN",
              MDE_ERR(r, PHRASE_LEN));
    r = domain_wallet_mnemonic_to_seed(big, "", seed, sizeof(seed));
    MDE_CHECK("to_seed: over-long phrase is PHRASE_LEN",
              MDE_ERR(r, PHRASE_LEN));

    r = domain_wallet_mnemonic_to_entropy("abandon \xc3\xa1", e, sizeof(e), &el);
    MDE_CHECK("to_entropy: non-ASCII is NON_ASCII, not PHRASE_LEN",
              MDE_ERR(r, NON_ASCII));
    r = domain_wallet_mnemonic_to_seed("abandon \xc3\xa1", "", seed, sizeof(seed));
    MDE_CHECK("to_seed: non-ASCII is NON_ASCII, not PHRASE_LEN",
              MDE_ERR(r, NON_ASCII));
    return failures;
}

static int mde_to_entropy_edges(void)
{
    int failures = 0;
    const char *phrase = mde_vecs[0].phrase;
    uint8_t e[40];
    size_t el = 99;
    struct zcl_result r = domain_wallet_mnemonic_to_entropy(phrase, e, 31, &el);
    MDE_CHECK("to_entropy capacity 31 is BUF_TOO_SMALL",
              MDE_ERR(r, BUF_TOO_SMALL));
    el = 99;
    r = domain_wallet_mnemonic_to_entropy(phrase, e, 32, &el);
    MDE_CHECK("to_entropy capacity exactly 32 is enough", r.ok && el == 16);
    el = 99;
    r = domain_wallet_mnemonic_to_entropy("abandon abandon", e, sizeof(e), &el);
    MDE_CHECK("to_entropy failure leaves a zero length", !r.ok && el == 0);
    return failures;
}

/* ── to_seed ──────────────────────────────────────────────────── */

static bool mde_seed_matches_pbkdf2(const char *phrase, const char *pass)
{
    char salt[400];
    uint8_t want[64], got[64];
    snprintf(salt, sizeof(salt), "mnemonic%s", pass);
    pbkdf2_hmac_sha512((const uint8_t *)phrase, strlen(phrase),
                       (const uint8_t *)salt, strlen(salt), 2048, want, 64);
    struct zcl_result r = domain_wallet_mnemonic_to_seed(phrase, pass, got,
                                                         sizeof(got));
    return r.ok && memcmp(want, got, sizeof(got)) == 0;
}

static int mde_to_seed_passphrase_bounds(void)
{
    int failures = 0;
    char pass[300];
    memset(pass, 'p', sizeof(pass));
    const char *phrase = mde_vecs[0].phrase;
    uint8_t seed[64];

    pass[248] = '\0';
    MDE_CHECK("to_seed: a 248-byte passphrase (salt 256) is accepted",
              mde_seed_matches_pbkdf2(phrase, pass));
    pass[248] = 'p';
    pass[249] = '\0';
    struct zcl_result r = domain_wallet_mnemonic_to_seed(phrase, pass, seed,
                                                         sizeof(seed));
    MDE_CHECK("to_seed: a 249-byte passphrase is PHRASE_LEN",
              MDE_ERR(r, PHRASE_LEN));
    MDE_CHECK("to_seed: a short passphrase reaches the salt",
              mde_seed_matches_pbkdf2(phrase, "TREZOR"));
    return failures;
}

int test_mnemonic_domain_edges(void)
{
    int failures = 0;
    failures += mde_wordlist_ends();
    failures += mde_length_tables();
    failures += mde_from_entropy_exact_sizes();
    failures += mde_normalize_args();
    failures += mde_normalize_non_ascii();
    failures += mde_normalize_leading_and_one_byte();
    failures += mde_normalize_sizes();
    failures += mde_published_vectors();
    failures += mde_fifteen_and_twenty_one_words();
    failures += mde_word_count_refusals();
    failures += mde_unknown_word_reports();
    failures += mde_overlong_and_non_ascii();
    failures += mde_to_entropy_edges();
    failures += mde_to_seed_passphrase_bounds();
    return failures;
}
