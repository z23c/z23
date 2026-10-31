/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "payment_code.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                                          \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            fprintf(stderr, "payment_code_test: %s:%d: failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                                         \
        }                                                                                    \
    } while (0)

/* Fixtures hold no key material. Only the length and charset of each address form are real. */
#define Q10 "qqqqqqqqqq"
#define Q75 Q10 Q10 Q10 Q10 Q10 Q10 Q10 "qqqqq"
#define A10 "aaaaaaaaaa"
#define A33 A10 A10 A10 "aaa"
#define ZS_ADDR "zs1" Q75
#define ZTS_ADDR "ztestsapling1" Q75
#define ZRS_ADDR "zregtestsapling1" Q75
#define T1_ADDR "t1" A33
#define T3_ADDR "t3" A33
#define TM_ADDR "tm" A33
#define T2_ADDR "t2" A33
#define URI_PREFIX "zclassic:"
#define MAIN ZAPP_PAY_MAINNET
#define TEST ZAPP_PAY_TESTNET
#define REGTEST ZAPP_PAY_REGTEST
#define PRIVATE_KIND ZAPP_PAY_PRIVATE
#define PUBLIC_KIND ZAPP_PAY_PUBLIC

_Static_assert(sizeof(ZS_ADDR) == 79, "a Sapling mainnet address is 78 characters");
_Static_assert(sizeof(ZTS_ADDR) == 89, "a Sapling testnet address is 88 characters");
_Static_assert(sizeof(ZRS_ADDR) == 92, "a Sapling regtest address is 91 characters");
_Static_assert(sizeof(T1_ADDR) == 36, "a transparent address is 35 characters");

struct refusal_case {
    const char *text;
    enum zapp_pay_network net;
    enum zapp_pay_refusal want;
};
#define REFUSE(t, n, w) { (t), (n), (w) }

struct accept_case {
    const char *text;
    enum zapp_pay_network net;
    const char *address;
    enum zapp_pay_kind kind;
    bool has_amount;
    uint64_t zat;
    const char *memo;
    size_t memo_len;
    const char *label;
    const char *message;
};
#define NO_TEXT .label = "", .message = ""
#define BARE_CASE(a, n, k) { .text = (a), .net = (n), .address = (a), .kind = (k), NO_TEXT }

static const struct accept_case ACCEPTED[] = {
    BARE_CASE(ZS_ADDR, MAIN, PRIVATE_KIND),
    BARE_CASE(T1_ADDR, MAIN, PUBLIC_KIND),
    BARE_CASE(T3_ADDR, MAIN, PUBLIC_KIND),
    BARE_CASE(ZTS_ADDR, TEST, PRIVATE_KIND),
    BARE_CASE(TM_ADDR, TEST, PUBLIC_KIND),
    BARE_CASE(T2_ADDR, TEST, PUBLIC_KIND),
    BARE_CASE(ZRS_ADDR, REGTEST, PRIVATE_KIND),
    BARE_CASE(TM_ADDR, REGTEST, PUBLIC_KIND),
    BARE_CASE(T2_ADDR, REGTEST, PUBLIC_KIND),
    { .text = URI_PREFIX ZS_ADDR, .net = MAIN, .address = ZS_ADDR, .kind = PRIVATE_KIND, NO_TEXT },
    { .text = "ZCLASSIC:" ZS_ADDR "?amount=0.00000001", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 1, NO_TEXT },
    { .text = "Zclassic:" T1_ADDR "?amount=21000000", .net = MAIN, .address = T1_ADDR,
      .kind = PUBLIC_KIND, .has_amount = true, .zat = 2100000000000000ULL, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=21000000.00000000", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 2100000000000000ULL, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=0", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 0, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=0.00000000", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 0, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=1.50", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 150000000, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=0001.5", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 150000000, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=1.10000000", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 110000000, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?amount=1&memo=aGVsbG8", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .has_amount = true, .zat = 100000000, .memo = "hello", .memo_len = 5,
      NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?memo=aGVsbG8%3D", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .memo = "hello", .memo_len = 5, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?memo=QQ", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .memo = "A", .memo_len = 1, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?memo=", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?label=Coffee%20shop&message=Thank%20you", .net = MAIN,
      .address = ZS_ADDR, .kind = PRIVATE_KIND, .label = "Coffee shop", .message = "Thank you" },
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%82%AC", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x82\xac", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?x-foo=1&bar=2&label=ok", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "ok", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?reqx=1", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?a_b-c=1", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?label=%C2%A0", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xc2\xa0", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=a+b", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "a+b", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%41%42", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "AB", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%e2%82%ac", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x82\xac", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?memo=aGVsbG8&message=%F0%9F%98%80", .net = MAIN,
      .address = ZS_ADDR, .kind = PRIVATE_KIND, .memo = "hello", .memo_len = 5,
      .label = "", .message = "\xf0\x9f\x98\x80" },
    /* Code points either side of the bidi control ranges are valid text and stay accepted. */
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%80%A9", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x80\xa9", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%80%AF", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x80\xaf", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%81%A5", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x81\xa5", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%81%AA", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x81\xaa", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?message=%E2%80%A8", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "", .message = "\xe2\x80\xa8" },
    /* Neighbours of the new marks stay accepted: U+200D, U+2010 and U+061B. */
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%80%8D", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x80\x8d", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?label=%E2%80%90", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "\xe2\x80\x90", .message = "" },
    { .text = URI_PREFIX ZS_ADDR "?message=%D8%9B", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, .label = "", .message = "\xd8\x9b" },
    /* Only the exact lower-case name is an amount: Amount= and AMOUNT= are ignored. */
    { .text = URI_PREFIX ZS_ADDR "?Amount=1", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, NO_TEXT },
    { .text = URI_PREFIX ZS_ADDR "?AMOUNT=1", .net = MAIN, .address = ZS_ADDR,
      .kind = PRIVATE_KIND, NO_TEXT },
    { .text = URI_PREFIX T1_ADDR "?amount=1", .net = MAIN, .address = T1_ADDR,
      .kind = PUBLIC_KIND, .has_amount = true, .zat = 100000000, NO_TEXT },
    { .text = URI_PREFIX TM_ADDR "?amount=1", .net = TEST, .address = TM_ADDR,
      .kind = PUBLIC_KIND, .has_amount = true, .zat = 100000000, NO_TEXT },
};

static const struct refusal_case REFUSED[] = {
    REFUSE("", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE(" " ZS_ADDR, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE(ZS_ADDR " ", MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE("zs1", MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE("zs1?amount=1", MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE("bitcoin:" ZS_ADDR, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE(ZS_ADDR, TEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(ZS_ADDR, REGTEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(ZTS_ADDR, MAIN, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(ZTS_ADDR, REGTEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(ZRS_ADDR, MAIN, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(ZRS_ADDR, TEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(TM_ADDR, MAIN, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(T2_ADDR, MAIN, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(T1_ADDR, TEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(T1_ADDR, REGTEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(T3_ADDR, TEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(URI_PREFIX TM_ADDR, MAIN, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1", TEST, ZAPP_PAY_REFUSE_WRONG_NETWORK),
    /* amount: shape */
    REFUSE(URI_PREFIX ZS_ADDR "?amount=", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=-1", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=+1", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1e3", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1E8", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=.", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1.", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=.5", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1.2.3", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1+", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1%20", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1,5", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=0x10", MAIN, ZAPP_PAY_REFUSE_AMOUNT_FORMAT),
    /* amount: precision, then range */
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1.000000000", MAIN, ZAPP_PAY_REFUSE_AMOUNT_PRECISION),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=0.123456789", MAIN, ZAPP_PAY_REFUSE_AMOUNT_PRECISION),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1.5000000000", MAIN, ZAPP_PAY_REFUSE_AMOUNT_PRECISION),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=21000000.00000001", MAIN, ZAPP_PAY_REFUSE_AMOUNT_RANGE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=21000000.1", MAIN, ZAPP_PAY_REFUSE_AMOUNT_RANGE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=21000001", MAIN, ZAPP_PAY_REFUSE_AMOUNT_RANGE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=22000000", MAIN, ZAPP_PAY_REFUSE_AMOUNT_RANGE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=99999999999999999999999999", MAIN, ZAPP_PAY_REFUSE_AMOUNT_RANGE),
    /* parameter names */
    REFUSE(URI_PREFIX ZS_ADDR "?req-foo=1", MAIN, ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED),
    REFUSE(URI_PREFIX ZS_ADDR "?REQ-foo=1", MAIN, ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1&req-x=1", MAIN, ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED),
    REFUSE(URI_PREFIX ZS_ADDR "?amount.1=1", MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount.0=1", MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?label.1=x", MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?message.2=x", MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?address.1=x", MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?address=" ZS_ADDR, MAIN, ZAPP_PAY_REFUSE_MULTIPLE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1&amount=2", MAIN, ZAPP_PAY_REFUSE_DUPLICATE),
    REFUSE(URI_PREFIX ZS_ADDR "?label=a&label=b", MAIN, ZAPP_PAY_REFUSE_DUPLICATE),
    REFUSE(URI_PREFIX ZS_ADDR "?message=a&message=b", MAIN, ZAPP_PAY_REFUSE_DUPLICATE),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=QQ&memo=QQ", MAIN, ZAPP_PAY_REFUSE_DUPLICATE),
    REFUSE(URI_PREFIX ZS_ADDR "?x=1&x=2", MAIN, ZAPP_PAY_REFUSE_DUPLICATE),
    REFUSE(URI_PREFIX ZS_ADDR "?amount", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?amount=1&", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?&amount=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?&&", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?a b=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?a%20b=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?x", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    /* memo: public address, then encoding */
    REFUSE(URI_PREFIX T1_ADDR "?memo=aGVsbG8", MAIN, ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC),
    REFUSE(URI_PREFIX T1_ADDR "?memo=", MAIN, ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC),
    REFUSE(URI_PREFIX TM_ADDR "?memo=QQ", TEST, ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=aGVsbG8*", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=a", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=aGVsbG=", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=QR", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=a+c", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=a/c", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=a%20", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=QQ==QQ", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo======", MAIN, ZAPP_PAY_REFUSE_MEMO_ENCODING),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=aGVs%G8", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=aGVs%", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?memo=aGVs%4", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    /* label and message: percent, then content */
    REFUSE(URI_PREFIX ZS_ADDR "?label=%", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%4", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%ZZ", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%G1", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%2", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%", MAIN, ZAPP_PAY_REFUSE_PERCENT),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%FF", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%C0%80", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%ED%A0%80", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%F4%90%80%80", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%82", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%07", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%1B", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%7F", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%0A", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%C2%85", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%00", MAIN, ZAPP_PAY_REFUSE_EMBEDDED_NUL),
    REFUSE(URI_PREFIX ZS_ADDR "?label=a%00b", MAIN, ZAPP_PAY_REFUSE_EMBEDDED_NUL),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%00", MAIN, ZAPP_PAY_REFUSE_EMBEDDED_NUL),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%FF", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%0D", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%C2%9F", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    /* direction marks: U+200E, U+200F and U+061C, refused as label or message */
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%80%8E", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%80%8F", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%D8%9C", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=\xe2\x80\x8f", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=\xd8\x9c", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%E2%80%8E", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%D8%9C", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    /* bidi controls: U+202A..U+202E and U+2066..U+2069, each boundary, refused as label or message */
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%80%AA", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%80%AE", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%81%A6", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=%E2%81%A9", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=a%E2%80%AEb", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?label=\xe2\x80\xae", MAIN, ZAPP_PAY_REFUSE_LABEL_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%E2%80%AA", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=%E2%81%A9", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    REFUSE(URI_PREFIX ZS_ADDR "?message=\xe2\x81\xa6", MAIN, ZAPP_PAY_REFUSE_MESSAGE_INVALID),
    /* a %-encoded parameter name is not decoded, so it is malformed, never req- or amount */
    REFUSE(URI_PREFIX ZS_ADDR "?%72eq-x=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    REFUSE(URI_PREFIX ZS_ADDR "?am%6Funt=1", MAIN, ZAPP_PAY_REFUSE_MALFORMED),
    /* a % in the address is not decoded: the address is 78 characters with a bad character */
    REFUSE(URI_PREFIX "zs1" Q10 Q10 Q10 Q10 Q10 Q10 Q10 "qqqq%", MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE(URI_PREFIX "zs1" Q10 Q10 Q10 Q10 Q10 Q10 Q10 "qqqq%?amount=1", MAIN,
           ZAPP_PAY_REFUSE_BAD_ADDRESS),
    REFUSE(URI_PREFIX "zs1" Q10 Q10 Q10 Q10 Q10 Q10 Q10 "qq%41", MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS),
    /* req- in mixed case with a duplicate: req- is checked first, so it is UNKNOWN_REQUIRED */
    REFUSE(URI_PREFIX ZS_ADDR "?Req-x=1&Req-x=2", MAIN, ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED),
    REFUSE(URI_PREFIX ZS_ADDR "?req-x=1&REQ-X=2", MAIN, ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED),
};

static size_t bounded_len(const char *s, size_t cap)
{
    size_t i = 0;
    while (i < cap && s[i] != '\0')
        i++;
    return i;
}

static bool is_zeroed(const struct zapp_payment *p)
{
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < sizeof *p; i++) {
        if (b[i] != 0)
            return false;
    }
    return true;
}

static enum zapp_pay_refusal parse_case(const char *text, enum zapp_pay_network net, struct zapp_payment *p)
{
    memset(p, 0xA5, sizeof *p);
    return zapp_payment_parse(text, strlen(text), net, p);
}

static void expect_refusal(const char *text, enum zapp_pay_network net, enum zapp_pay_refusal want)
{
    struct zapp_payment p;
    enum zapp_pay_refusal got = parse_case(text, net, &p);
    if (got != want)
        fprintf(stderr, "payment_code_test: \"%s\" gave %d, want %d\n", text, (int)got, (int)want);
    CHECK(got == want);
    CHECK(is_zeroed(&p));
}

static void expect_accept(const struct accept_case *c)
{
    struct zapp_payment p;
    enum zapp_pay_refusal got = parse_case(c->text, c->net, &p);
    if (got != ZAPP_PAY_OK)
        fprintf(stderr, "payment_code_test: \"%s\" refused with %d\n", c->text, (int)got);
    CHECK(got == ZAPP_PAY_OK);
    CHECK(strcmp(p.address, c->address) == 0);
    CHECK(p.kind == c->kind);
    CHECK(p.has_amount == c->has_amount);
    CHECK(!c->has_amount || p.amount_zat == c->zat);
    CHECK(p.memo_len == c->memo_len);
    CHECK(c->memo_len == 0 || memcmp(p.memo, c->memo, c->memo_len) == 0);
    CHECK(strcmp(p.label, c->label) == 0);
    CHECK(strcmp(p.message, c->message) == 0);
}

static void check_invariants(const struct zapp_payment *p, enum zapp_pay_refusal got)
{
    CHECK((int)got >= 0 && (int)got <= (int)ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG);
    if (got != ZAPP_PAY_OK) {
        CHECK(is_zeroed(p));
        return;
    }
    CHECK(bounded_len(p->address, sizeof p->address) < sizeof p->address);
    CHECK(p->memo_len <= ZAPP_PAY_MEMO_MAX);
    CHECK(bounded_len(p->label, sizeof p->label) < sizeof p->label);
    CHECK(bounded_len(p->message, sizeof p->message) < sizeof p->message);
    CHECK(!p->has_amount || p->amount_zat <= ZAPP_PAY_MAX_ZAT);
}

static void with_length(char *out, size_t cap, const char *prefix, char fill, size_t total)
{
    size_t p = strlen(prefix);
    CHECK(total < cap && p <= total);
    memcpy(out, prefix, p);
    memset(out + p, fill, total - p);
    out[total] = '\0';
}

/* Test-side encoder, unpadded base64url, so the decoder is checked against an independent writer. */
static size_t b64_encode_for_test(const uint8_t *in, size_t n, char *out)
{
    static const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        size_t k = n - i < 3 ? n - i : 3;
        uint32_t v = (uint32_t)in[i] << 16;
        if (k > 1)
            v |= (uint32_t)in[i + 1] << 8;
        if (k > 2)
            v |= (uint32_t)in[i + 2];
        for (size_t j = 0; j <= k; j++)
            out[o++] = ALPHA[(v >> (18 - 6 * j)) & 63u];
    }
    out[o] = '\0';
    return o;
}

static void run_accepts(void)
{
    for (size_t i = 0; i < sizeof ACCEPTED / sizeof ACCEPTED[0]; i++)
        expect_accept(&ACCEPTED[i]);
}

static void run_refusals(void)
{
    for (size_t i = 0; i < sizeof REFUSED / sizeof REFUSED[0]; i++)
        expect_refusal(REFUSED[i].text, REFUSED[i].net, REFUSED[i].want);
}

/* Lengths and charsets just outside each address form. */
static void run_bad_shapes(void)
{
    char buf[128];
    with_length(buf, sizeof buf, "zs1", 'q', 77);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", 'q', 79);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", 'b', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", 'i', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", 'o', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", '1', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zs1", 'Q', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "ZS1", 'q', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "ztestsapling1", 'q', 87);
    expect_refusal(buf, TEST, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zregtestsapling1", 'q', 90);
    expect_refusal(buf, REGTEST, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", 'a', 34);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", 'a', 36);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", '0', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", 'O', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", 'I', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t1", 'l', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "T1", 'a', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "t4", 'a', 35);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
    with_length(buf, sizeof buf, "zz1", 'q', 78);
    expect_refusal(buf, MAIN, ZAPP_PAY_REFUSE_BAD_ADDRESS);
}

static void run_memo_limits(void)
{
    static uint8_t raw[ZAPP_PAY_INPUT_MAX];
    static char b64[ZAPP_PAY_INPUT_MAX];
    static char text[8192];
    struct zapp_payment p;
    memset(raw, 'A', sizeof raw);
    size_t n = b64_encode_for_test(raw, ZAPP_PAY_MEMO_MAX, b64);
    CHECK(n == 683);
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?memo=%s", b64);
    CHECK(parse_case(text, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(p.memo_len == ZAPP_PAY_MEMO_MAX && memcmp(p.memo, raw, ZAPP_PAY_MEMO_MAX) == 0);
    b64_encode_for_test(raw, ZAPP_PAY_MEMO_MAX + 1, b64);
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?memo=%s", b64);
    expect_refusal(text, MAIN, ZAPP_PAY_REFUSE_MEMO_TOO_LONG);
    b64_encode_for_test(raw, 3000, b64);
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?memo=%s", b64);
    expect_refusal(text, MAIN, ZAPP_PAY_REFUSE_MEMO_TOO_LONG);
}

static void run_text_limits(void)
{
    static char text[8192];
    static char body[ZAPP_PAY_TEXT_MAX + 2];
    struct zapp_payment p;
    memset(body, 'a', ZAPP_PAY_TEXT_MAX);
    body[ZAPP_PAY_TEXT_MAX] = '\0';
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?label=%s", body);
    CHECK(parse_case(text, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(strlen(p.label) == ZAPP_PAY_TEXT_MAX);
    body[ZAPP_PAY_TEXT_MAX] = 'a';
    body[ZAPP_PAY_TEXT_MAX + 1] = '\0';
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?label=%s", body);
    expect_refusal(text, MAIN, ZAPP_PAY_REFUSE_LABEL_TOO_LONG);
    body[ZAPP_PAY_TEXT_MAX] = '\0';
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?message=%s", body);
    CHECK(parse_case(text, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(strlen(p.message) == ZAPP_PAY_TEXT_MAX);
    body[ZAPP_PAY_TEXT_MAX] = 'a';
    body[ZAPP_PAY_TEXT_MAX + 1] = '\0';
    snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?message=%s", body);
    expect_refusal(text, MAIN, ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG);
}

/* 85 euro signs are 255 bytes; one more ASCII byte is 256, which fits, and two more do not. */
static void run_multibyte_text_limit(void)
{
    static char text[8192];
    struct zapp_payment p;
    size_t n = (size_t)snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?label=");
    for (int i = 0; i < 85; i++) {
        memcpy(text + n, "%E2%82%AC", 9);
        n += 9;
    }
    text[n] = 'a';
    text[n + 1] = '\0';
    CHECK(parse_case(text, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(strlen(p.label) == ZAPP_PAY_TEXT_MAX);
    text[n + 1] = 'a';
    text[n + 2] = '\0';
    expect_refusal(text, MAIN, ZAPP_PAY_REFUSE_LABEL_TOO_LONG);
}

static void run_input_bounds(void)
{
    static char text[ZAPP_PAY_INPUT_MAX + 16];
    static const char head_nul[] = "\0" ZS_ADDR;
    static const char tail_nul[] = URI_PREFIX ZS_ADDR "?label=a\0" "b";
    struct zapp_payment p;
    memset(text, 'a', sizeof text);
    memcpy(text, URI_PREFIX ZS_ADDR "?x=", strlen(URI_PREFIX ZS_ADDR "?x="));
    CHECK(zapp_payment_parse(text, ZAPP_PAY_INPUT_MAX, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(!p.has_amount);
    CHECK(zapp_payment_parse(text, ZAPP_PAY_INPUT_MAX + 1, MAIN, &p) == ZAPP_PAY_REFUSE_INPUT_TOO_LONG);
    CHECK(is_zeroed(&p));
    CHECK(zapp_payment_parse(head_nul, sizeof head_nul - 1, MAIN, &p) == ZAPP_PAY_REFUSE_EMBEDDED_NUL);
    CHECK(is_zeroed(&p));
    CHECK(zapp_payment_parse(tail_nul, sizeof tail_nul - 1, MAIN, &p) == ZAPP_PAY_REFUSE_EMBEDDED_NUL);
    CHECK(is_zeroed(&p));
    CHECK(zapp_payment_parse("", 0, MAIN, &p) == ZAPP_PAY_REFUSE_MALFORMED);
    CHECK(zapp_payment_parse(NULL, 0, MAIN, &p) == ZAPP_PAY_REFUSE_MALFORMED);
}

static bool is_hex_char(char c)
{
    return c != '\0' && strchr("0123456789abcdefABCDEF", c) != NULL;
}

static bool is_b64_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/* Every byte after a % in a label: hex digits decode, anything else is a bad percent sign. */
static void fuzz_percent_bytes(void)
{
    char text[128];
    struct zapp_payment p;
    for (int c = 1; c < 256; c++) {
        snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?label=%%%c1", c);
        enum zapp_pay_refusal got = parse_case(text, MAIN, &p);
        if (is_hex_char((char)c))
            CHECK(got != ZAPP_PAY_REFUSE_PERCENT);
        else
            CHECK(got == ZAPP_PAY_REFUSE_PERCENT);
        check_invariants(&p, got);
    }
}

/* Every byte after a three-character memo: base64url and = decode, & ends the query early,
 * % is a bad escape, and anything else is a bad base64url character. */
static void fuzz_base64_bytes(void)
{
    char text[128];
    struct zapp_payment p;
    for (int c = 1; c < 256; c++) {
        snprintf(text, sizeof text, URI_PREFIX ZS_ADDR "?memo=QQQ%c", c);
        enum zapp_pay_refusal got = parse_case(text, MAIN, &p);
        if (c == '%')
            CHECK(got == ZAPP_PAY_REFUSE_PERCENT);
        else if (c == '&')
            CHECK(got == ZAPP_PAY_REFUSE_MALFORMED);
        else if (is_b64_char((char)c) || c == '=')
            CHECK(got == ZAPP_PAY_OK);
        else
            CHECK(got == ZAPP_PAY_REFUSE_MEMO_ENCODING);
        check_invariants(&p, got);
    }
}

static uint32_t next_rand(uint32_t *state)
{
    *state = *state * 1664525u + 1013904223u;
    return *state >> 16;
}

static void fuzz_random(const char *alpha, const char *head, uint32_t seed, int rounds)
{
    static char text[512];
    size_t alen = strlen(alpha);
    size_t hlen = strlen(head);
    uint32_t state = seed;
    for (int r = 0; r < rounds; r++) {
        memcpy(text, head, hlen);
        size_t n = hlen;
        size_t tail = next_rand(&state) % 120u;
        for (size_t i = 0; i < tail; i++)
            text[n++] = alpha[next_rand(&state) % alen];
        text[n] = '\0';
        struct zapp_payment p;
        enum zapp_pay_refusal got = parse_case(text, MAIN, &p);
        check_invariants(&p, got);
    }
}

static void run_fuzz(void)
{
    fuzz_percent_bytes();
    fuzz_base64_bytes();
    fuzz_random("zclassic:?&=%.-_+/ 0123456789aAbBzZamountmemolabelmessagereq-\x7f\x80\xc2\xa0\xff",
                "", 0x2026u, 20000);
    fuzz_random("qQaA0-_=%&?+/*", URI_PREFIX ZS_ADDR "?memo=", 0x0c23u, 20000);
}

static void run_receive_code(void)
{
    char out[160];
    struct zapp_payment p;
    CHECK(zapp_payment_receive_code(ZS_ADDR, false, 0, out, sizeof out));
    CHECK(strcmp(out, ZS_ADDR) == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 1, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=0.00000001") == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 100000000, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=1") == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 150000000, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=1.5") == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 100000001, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=1.00000001") == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 0, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=0") == 0);
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, ZAPP_PAY_MAX_ZAT, out, sizeof out));
    CHECK(strcmp(out, URI_PREFIX ZS_ADDR "?amount=21000000") == 0);
    CHECK(!zapp_payment_receive_code(ZS_ADDR, true, ZAPP_PAY_MAX_ZAT + 1, out, sizeof out));
    CHECK(!zapp_payment_receive_code(NULL, false, 0, out, sizeof out));
    CHECK(!zapp_payment_receive_code("", false, 0, out, sizeof out));
    CHECK(!zapp_payment_receive_code("zs1?amount=1", false, 0, out, sizeof out));
    CHECK(!zapp_payment_receive_code(ZS_ADDR, false, 0, out, 0));
    char exact[sizeof ZS_ADDR];
    char short_buf[sizeof ZS_ADDR - 1];
    CHECK(zapp_payment_receive_code(ZS_ADDR, false, 0, exact, sizeof exact));
    CHECK(!zapp_payment_receive_code(ZS_ADDR, false, 0, short_buf, sizeof short_buf));
    CHECK(zapp_payment_receive_code(ZS_ADDR, true, 150000000, out, sizeof out));
    CHECK(parse_case(out, MAIN, &p) == ZAPP_PAY_OK);
    CHECK(p.has_amount && p.amount_zat == 150000000);
}

int main(void)
{
    run_accepts();
    run_refusals();
    run_bad_shapes();
    run_memo_limits();
    run_text_limits();
    run_multibyte_text_limit();
    run_input_bounds();
    run_fuzz();
    run_receive_code();
    puts("payment_code_test: ok");
    return 0;
}
