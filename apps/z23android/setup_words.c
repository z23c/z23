/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "setup_words.h"
#include "base/cleanse.h"
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
