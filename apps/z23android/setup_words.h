/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SETUP_WORDS_H
#define ZAPP_SETUP_WORDS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The recovery words as the setup screens handle them: parsed from the node's reply or from what the owner typed,
 * shown once, asked back in part, and wiped. Nothing here writes a word anywhere. */
#define ZAPP_WORDS_MAX 24u
#define ZAPP_WORD_LETTERS 8u    /* The longest BIP39 word. */
#define ZAPP_WORDS_ASKED 3u

struct zapp_words {
    size_t count;
    char word[ZAPP_WORDS_MAX][ZAPP_WORD_LETTERS + 1];
};

/* Splits text on white space into lower-case words. True only for 12, 15, 18, 21 or 24 words of letters, each of 1 to 8
 * letters; out is zero on every other result. Whether the words are on the list and their checksum holds is the node's to
 * say. */
bool zapp_words_parse(const char *text, struct zapp_words *out);
/* The words joined by single spaces. False, with an empty string, when cap is too small. */
bool zapp_words_join(const struct zapp_words *words, char *out, size_t cap);
/* n distinct positions below count, in increasing order, drawn without bias from random. False when random fails or
 * n > count. */
bool zapp_words_pick(size_t count, bool (*random)(void *ctx, uint8_t *out, size_t len), void *ctx, size_t n, size_t *positions);
/* Whether every answer is the word at its position, ignoring case and the white space around it. */
bool zapp_words_match(const struct zapp_words *words, const size_t *positions, const char *const *answers, size_t n);

#define ZAPP_WORDLIST_SIZE 2048u
#define ZAPP_WORD_CHOICES 4u
/* The BIP39 English wordlist, sorted. */
extern const char *const zapp_wordlist[ZAPP_WORDLIST_SIZE];
/* The words to pick from for one asked word: right and ZAPP_WORD_CHOICES - 1 decoys drawn from the wordlist, all different, with
 * right in a slot drawn from random. False, with out empty, when random fails or right is not 1 to 8 letters. */
bool zapp_words_choices(const char *right, bool (*random)(void *ctx, uint8_t *out, size_t len), void *ctx,
                        char out[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1]);
void zapp_words_cleanse(struct zapp_words *words);

#endif
