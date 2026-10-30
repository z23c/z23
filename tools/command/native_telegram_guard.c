/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: best-effort wallet secret detection for outbound Telegram text:
 * extended keys, Sapling secrets and viewing keys, WIF keys and BIP-39 phrases. */
#include "command/native_telegram.h"
#include "domain/encoding/base58.h"
#include "domain/wallet/mnemonic.h"
#include <ctype.h>
#include <string.h>

#define TG_B58_RUN_MAX 160u
#define TG_PHRASE_MIN_WORDS 12u

static bool tg_b58_byte(char c)
{
    return c != '\0' && strchr("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", c) != NULL;
}

/* Sapling bech32 spending keys and viewing keys, main and test networks. */
static bool tg_sapling_text(const char *text)
{
    static const char *const marks[] = {
        "secret-extended-key-", "zxviews", "zxview", "zviews", "zivk", "zxprv",
    };
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (tg_icontains(text, marks[i]))
            return true;
    }
    return false;
}

/* BIP-32 version bytes: xprv, xpub, tprv, tpub. */
static bool tg_extended_version(const unsigned char *p)
{
    static const unsigned char versions[][4] = {
        {0x04, 0x88, 0xAD, 0xE4}, {0x04, 0x88, 0xB2, 0x1E},
        {0x04, 0x35, 0x83, 0x94}, {0x04, 0x35, 0x87, 0xCF},
    };
    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        if (!memcmp(p, versions[i], 4))
            return true;
    }
    return false;
}

/* One base58 run: a checksummed extended key or a checksummed WIF key. */
static bool tg_base58_secret(const char *run, size_t len)
{
    unsigned char payload[128];
    size_t out = 0;
    bool wif_shape = (len == 51 || len == 52) && strchr("5KL", run[0]) != NULL;
    if (len >= 100 && (!strncmp(run, "xprv", 4) || !strncmp(run, "tprv", 4)))
        return true;
    if (len < 50 || len >= TG_B58_RUN_MAX)
        return false;
    char copy[TG_B58_RUN_MAX];
    memcpy(copy, run, len);
    copy[len] = '\0';
    if (!domain_encoding_base58check_decode(copy, payload, sizeof(payload), &out))
        return false;
    if (out == 78 && tg_extended_version(payload))
        return true;
    return wif_shape && (out == 33 || out == 34);
}

static bool tg_has_base58_secret(const char *text)
{
    for (size_t i = 0; text[i];) {
        size_t n = 0;
        while (tg_b58_byte(text[i + n]))
            n++;
        if (n && (i == 0 || !isalnum((unsigned char)text[i - 1])) && tg_base58_secret(text + i, n))
            return true;
        i += n ? n : 1;
    }
    return false;
}

/* Length of the lowercase word at text, or 0 when it is not a BIP-39 word. */
static size_t tg_phrase_word(const char *text)
{
    char word[16];
    size_t n = 0;
    while (text[n] >= 'a' && text[n] <= 'z' && n < sizeof(word) - 1) {
        word[n] = text[n];
        n++;
    }
    word[n] = '\0';
    if (n < 3 || isalpha((unsigned char)text[n]))
        return 0;
    return domain_wallet_mnemonic_wordlist_find(word) >= 0 ? n : 0;
}

/* Twelve or more consecutive BIP-39 words separated by blanks. */
static bool tg_has_phrase(const char *text)
{
    size_t run = 0;
    for (const char *p = text; *p;) {
        size_t n = (p == text || !isalnum((unsigned char)p[-1])) ? tg_phrase_word(p) : 0;
        if (n == 0) {
            run = 0;
            p++;
            continue;
        }
        p += n;
        run++;
        if (run >= TG_PHRASE_MIN_WORDS)
            return true;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
    }
    return false;
}

const char *tg_wallet_secret_refusal(const char *text)
{
    if (tg_sapling_text(text))
        return "text mentions a Sapling spending or viewing key";
    if (tg_has_base58_secret(text))
        return "text contains an extended key or WIF private key";
    if (tg_has_phrase(text))
        return "text contains a BIP-39 recovery phrase";
    return NULL;
}
