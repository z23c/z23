/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "payment_notice.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void no_amount_or_address(const char *text)
{
    for (const char *c = text; *c; ++c) assert(!isdigit((unsigned char)*c));
    assert(!strstr(text, "ZCL") && !strstr(text, "zs1") && !strstr(text, "t1"));
}

int main(void)
{
    static const char *const titles[] = {"Payment sent", "Payment not sent", "Payment status unknown"};
    for (int r = ZAPP_PAYMENT_SENT; r <= ZAPP_PAYMENT_UNKNOWN; ++r) {
        struct zapp_payment_notice n = zapp_payment_notice_of((enum zapp_payment_result)r);
        assert(!strcmp(n.title, titles[r]));
        no_amount_or_address(n.title);
        no_amount_or_address(n.text);
    }
    assert(!strcmp(zapp_payment_notice_of(ZAPP_PAYMENT_NOT_SENT).text, "Your coins were not spent."));
    assert(!strstr(zapp_payment_notice_of(ZAPP_PAYMENT_UNKNOWN).title, "not sent"));
    /* The public version is one fixed title: it cannot reveal the outcome, the amount or the address. */
    assert(!strcmp(ZAPP_PAYMENT_PUBLIC_TITLE, "Z23 payment update"));
    no_amount_or_address(&ZAPP_PAYMENT_PUBLIC_TITLE[3]);   /* past the product name */
    for (int r = ZAPP_PAYMENT_SENT; r <= ZAPP_PAYMENT_UNKNOWN; ++r)
        assert(strcmp(ZAPP_PAYMENT_PUBLIC_TITLE, zapp_payment_notice_of((enum zapp_payment_result)r).title) != 0);
    puts("payment_notice_test: ok");
    return 0;
}
