/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PAYMENT_CODE_H
#define ZAPP_PAYMENT_CODE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Reads the text of one QR code as a payment request: a bare address, or one ZIP 321 payment,
 * zclassic:<address>?amount=&memo=&label=&message=. Pure: no I/O, no allocation, no floating point.
 * An address is checked for its length, charset and network prefix only, never its checksum. The
 * node validates the address with validateaddress before any payment is built from it. */

#define ZAPP_PAY_INPUT_MAX 4096
#define ZAPP_PAY_MEMO_MAX 512
#define ZAPP_PAY_TEXT_MAX 256
#define ZAPP_PAY_ADDRESS_MAX 96
#define ZAPP_PAY_MAX_ZAT 2100000000000000ULL /* 21000000 ZCL in zatoshi */

enum zapp_pay_network { ZAPP_PAY_MAINNET, ZAPP_PAY_TESTNET, ZAPP_PAY_REGTEST };
enum zapp_pay_kind { ZAPP_PAY_PRIVATE, ZAPP_PAY_PUBLIC };

enum zapp_pay_refusal {
    ZAPP_PAY_OK = 0,
    ZAPP_PAY_REFUSE_INPUT_TOO_LONG,    /* more than ZAPP_PAY_INPUT_MAX bytes */
    ZAPP_PAY_REFUSE_EMBEDDED_NUL,      /* a NUL byte in the input, or one decoded from a label or message */
    ZAPP_PAY_REFUSE_MALFORMED,         /* anything else, including empty input and bad parameter syntax */
    ZAPP_PAY_REFUSE_BAD_ADDRESS,       /* not the length, prefix or charset of a Sapling or transparent address */
    ZAPP_PAY_REFUSE_WRONG_NETWORK,     /* a well-formed address of another network */
    ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED,  /* a req- parameter, in any letter case; none is known here */
    ZAPP_PAY_REFUSE_MULTIPLE,          /* a second payment: an address parameter, or any indexed name such as amount.1 */
    ZAPP_PAY_REFUSE_DUPLICATE,         /* the same parameter name twice, known or not */
    ZAPP_PAY_REFUSE_AMOUNT_FORMAT,     /* empty, signed, with an exponent, not decimal, or no digit before the point */
    ZAPP_PAY_REFUSE_AMOUNT_PRECISION,  /* more than 8 decimal places */
    ZAPP_PAY_REFUSE_AMOUNT_RANGE,      /* above 21000000 ZCL */
    ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC,    /* a memo with a transparent address */
    ZAPP_PAY_REFUSE_MEMO_ENCODING,     /* not base64url, or padding or trailing bits not canonical */
    ZAPP_PAY_REFUSE_MEMO_TOO_LONG,     /* more than ZAPP_PAY_MEMO_MAX bytes once decoded */
    ZAPP_PAY_REFUSE_PERCENT,           /* a % not followed by two hex digits */
    ZAPP_PAY_REFUSE_LABEL_INVALID,     /* not UTF-8, a control character, or a bidi control */
    ZAPP_PAY_REFUSE_LABEL_TOO_LONG,    /* more than ZAPP_PAY_TEXT_MAX bytes once decoded */
    ZAPP_PAY_REFUSE_MESSAGE_INVALID,   /* not UTF-8, a control character, or a bidi control */
    ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG,  /* more than ZAPP_PAY_TEXT_MAX bytes once decoded */
};

struct zapp_payment {
    char address[ZAPP_PAY_ADDRESS_MAX];  /* as written, NUL-terminated */
    enum zapp_pay_kind kind;
    bool has_amount;
    uint64_t amount_zat;                 /* valid when has_amount */
    size_t memo_len;                     /* 0 when there is no memo */
    uint8_t memo[ZAPP_PAY_MEMO_MAX];     /* decoded bytes, not text */
    char label[ZAPP_PAY_TEXT_MAX + 1];   /* decoded and NUL-terminated; "" when absent */
    char message[ZAPP_PAY_TEXT_MAX + 1]; /* decoded and NUL-terminated; "" when absent */
};

/* Whether a code point changes how text reads without showing: controls, soft hyphen, direction marks and isolates, zero width
 * characters, line and paragraph separators, the byte order mark, the noncharacters U+FDD0..U+FDEF and U+nFFFE and U+nFFFF of
 * every plane, and tag characters. The label and message of a payment code are refused when they hold one, and the screens write
 * one out as <U+XXXX> instead of drawing it: one table. */
bool zapp_pay_cp_hidden(uint32_t cp);

/* Parses text[0..len) for network. On ZAPP_PAY_OK, out holds the payment. On any refusal out is
 * zeroed, so a refused code is never partly honoured. Parameters other than amount, memo, label and
 * message are ignored unless their name starts with req- (any case), which is refused. */
enum zapp_pay_refusal zapp_payment_parse(const char *text, size_t len, enum zapp_pay_network network,
                                         struct zapp_payment *out);

/* The text a Receive screen shows: the bare address when has_amount is false, otherwise
 * zclassic:<address>?amount=<decimal> with the amount in ZCL and trailing zeros dropped. address
 * must be letters and digits only. An amount above ZAPP_PAY_MAX_ZAT is refused, so every code built
 * here parses back. Returns false when out is too small (cap counts the NUL) or an input is refused. */
bool zapp_payment_receive_code(const char *address, bool has_amount, uint64_t amount_zat,
                               char *out, size_t cap);

/* Room for any code zapp_payment_receive_code makes: scheme, address, amount parameter and NUL. */
#define ZAPP_RECEIVE_CODE_MAX 160

/* Writes zat as ZCL: whole amounts without a point, otherwise up to 8 decimals with trailing zeros
 * dropped ("1.5", "0.00000001"). False, with out empty, when cap is too small. */
bool zapp_zat_format(uint64_t zat, char *out, size_t cap);

/* Reads an amount typed in ZCL: digits, then optionally a point and 1 to 8 digits, with surrounding
 * spaces allowed. The same rules as the amount parameter of a payment code, so false for anything
 * else, including a value above the supply limit; *zat is then left unchanged. */
bool zapp_zat_parse(const char *text, uint64_t *zat);

#endif
