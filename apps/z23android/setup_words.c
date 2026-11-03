/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "setup_words.h"
#include "base/cleanse.h"
#include "zsha256/zsha256.h"
#include <string.h>

static bool space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }
static bool letter(char c) { return lower(c) >= 'a' && lower(c) <= 'z'; }
static bool count_valid(size_t n) { return n >= 12 && n <= ZAPP_WORDS_MAX && n % 3 == 0; }

/* Copies the next word of text into out and returns the text after it; NULL when there is none or the word is not 1 to
 * 8 letters. */
static const char *next_word(const char *text, char *out, bool *bad)
{
    size_t n = 0;
    while (space(*text)) ++text;
    if (!*text) return NULL;
    for (; *text && !space(*text); ++text) {
        if (!letter(*text) || n == ZAPP_WORD_LETTERS) { *bad = true; return NULL; }
        out[n++] = lower(*text);
    }
    out[n] = 0;
    return text;
}
bool zapp_words_parse(const char *text, struct zapp_words *out)
{
    char word[ZAPP_WORD_LETTERS + 1] = "";
    bool bad = false;
    memset(out, 0, sizeof(*out));
    if (!text) return false;
    while (!bad && out->count <= ZAPP_WORDS_MAX) {
        text = next_word(text, word, &bad);
        if (!text) break;
        if (out->count < ZAPP_WORDS_MAX) memcpy(out->word[out->count], word, sizeof(word));
        ++out->count;
    }
    memory_cleanse(word, sizeof(word));
    if (bad || !count_valid(out->count)) { zapp_words_cleanse(out); return false; }
    return true;
}
/* The index of word in the BIP39 list, or -1. The list is sorted. */
static long index_of(const char *word)
{
    size_t lo = 0, hi = ZAPP_WORDLIST_SIZE;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int order = strcmp(word, zapp_wordlist[mid]);
        if (order == 0) return (long)mid;
        if (order < 0) hi = mid;
        else lo = mid + 1;
    }
    return -1;
}
enum zapp_words_problem zapp_words_check(const struct zapp_words *words, size_t *position)
{
    uint8_t bits[ZAPP_WORDS_MAX * 11 / 8 + 1] = {0};
    uint8_t digest[ZSHA256_DIGEST_LEN];
    if (!count_valid(words->count)) return ZAPP_WORDS_CHECKSUM;
    for (size_t i = 0; i < words->count; ++i) {
        long index = index_of(words->word[i]);
        if (index < 0) {
            *position = i;
            memory_cleanse(bits, sizeof(bits));
            return ZAPP_WORDS_OFF_LIST;
        }
        for (size_t b = 0; b < 11; ++b)
            if ((index >> (10 - b)) & 1) bits[(i * 11 + b) / 8] |= (uint8_t)(0x80u >> ((i * 11 + b) % 8));
    }
    /* Each word holds 11 bits: ENT bits of entropy followed by ENT / 32 bits of the SHA-256 of the entropy. */
    size_t total = words->count * 11, entropy = total * 32 / 33, checksum = total - entropy;
    zsha256(bits, entropy / 8, digest);
    bool ok = (bits[entropy / 8] >> (8 - checksum)) == (digest[0] >> (8 - checksum));
    memory_cleanse(bits, sizeof(bits));
    memory_cleanse(digest, sizeof(digest));
    return ok ? ZAPP_WORDS_OK : ZAPP_WORDS_CHECKSUM;
}
bool zapp_words_join(const struct zapp_words *words, char *out, size_t cap)
{
    size_t used = 0;
    if (cap) out[0] = 0;
    for (size_t i = 0; i < words->count; ++i) {
        size_t n = strlen(words->word[i]);
        if (used + n + (i ? 1 : 0) + 1 > cap) { if (cap) memory_cleanse(out, cap); if (cap) out[0] = 0; return false; }
        if (i) out[used++] = ' ';
        memcpy(out + used, words->word[i], n);
        used += n;
    }
    if (cap) out[used] = 0;
    return cap != 0;
}
/* One position below count, without modulo bias. */
static bool one_position(size_t count, bool (*random)(void *, uint8_t *, size_t), void *ctx, size_t *out)
{
    uint8_t byte;
    unsigned limit = 256u - 256u % (unsigned)count;
    do {
        if (!random(ctx, &byte, 1)) return false;
    } while (byte >= limit);
    *out = byte % count;
    return true;
}
bool zapp_words_pick(size_t count, bool (*random)(void *ctx, uint8_t *out, size_t len), void *ctx, size_t n, size_t *positions)
{
    bool taken[ZAPP_WORDS_MAX] = {false};
    if (!random || !count_valid(count) || n > count) return false;
    for (size_t i = 0; i < n; ++i) {
        size_t at;
        do {
            if (!one_position(count, random, ctx, &at)) return false;
        } while (taken[at]);
        taken[at] = true;
    }
    size_t used = 0;
    for (size_t i = 0; i < count && used < n; ++i) if (taken[i]) positions[used++] = i;
    return true;
}
bool zapp_words_match(const struct zapp_words *words, const size_t *positions, const char *const *answers, size_t n)
{
    bool all = n > 0;
    for (size_t i = 0; i < n; ++i) {
        char given[ZAPP_WORD_LETTERS + 1];
        bool bad = false;
        const char *rest = answers[i] ? next_word(answers[i], given, &bad) : NULL;
        bool one = rest && positions[i] < words->count;
        while (one && space(*rest)) ++rest;
        one = one && !*rest && !strcmp(given, words->word[positions[i]]);
        all = all && one;
        memory_cleanse(given, sizeof(given));
    }
    return all;
}
void zapp_words_cleanse(struct zapp_words *words)
{
    memory_cleanse(words, sizeof(*words));
}
/* Fills the next empty slot of out with a word of the wordlist that differs from right and from every word already in out. */
static bool decoy(bool (*random)(void *, uint8_t *, size_t), void *ctx, char out[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1], const char *right)
{
    for (unsigned tries = 0; tries < 64; ++tries) {
        uint8_t bytes[2];
        if (!random(ctx, bytes, sizeof(bytes))) return false;
        const char *word = zapp_wordlist[(bytes[0] << 8 | bytes[1]) % ZAPP_WORDLIST_SIZE];
        bool fresh = strcmp(word, right) != 0;
        for (size_t i = 0; fresh && i < ZAPP_WORD_CHOICES; ++i) fresh = strcmp(word, out[i]) != 0;
        if (!fresh) continue;
        for (size_t i = 0; i < ZAPP_WORD_CHOICES; ++i) {
            if (out[i][0]) continue;
            memcpy(out[i], word, strlen(word) + 1);
            return true;
        }
    }
    return false;
}
bool zapp_words_choices(const char *right, bool (*random)(void *ctx, uint8_t *out, size_t len), void *ctx,
                        char out[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1])
{
    size_t slot, length = right ? strlen(right) : 0;
    memset(out, 0, ZAPP_WORD_CHOICES * (ZAPP_WORD_LETTERS + 1));
    if (!random || length < 1 || length > ZAPP_WORD_LETTERS) return false;
    bool ok = one_position(ZAPP_WORD_CHOICES, random, ctx, &slot);
    if (ok) memcpy(out[slot], right, length + 1);
    for (size_t i = 1; ok && i < ZAPP_WORD_CHOICES; ++i) ok = decoy(random, ctx, out, right);
    if (!ok) memset(out, 0, ZAPP_WORD_CHOICES * (ZAPP_WORD_LETTERS + 1));
    return ok;
}
