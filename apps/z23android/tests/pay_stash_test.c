/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "pay_stash.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void payment_code(char *out, size_t cap, const char *tail)
{
    char addr[ZAPP_PAY_ADDRESS_MAX];
    memcpy(addr, "zs1", 3);
    memset(addr + 3, 'q', 75);
    addr[78] = 0;
    snprintf(out, cap, "zclassic:%s%s", addr, tail);
}
static bool all_zero(const void *p, size_t n)
{
    const unsigned char *b = p;
    for (size_t i = 0; i < n; ++i) if (b[i]) return false;
    return true;
}

int main(void)
{
    char code[512];
    struct zapp_payment p;
    payment_code(code, sizeof(code), "?amount=1.25&memo=aGk");
    /* A payment code is held from the classifying scan until the shell takes it, once. */
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    assert(zapp_pay_stash_take(&p) && p.has_amount && p.amount_zat == 125000000ull && p.memo_len == 2);
    assert(!zapp_pay_stash_take(&p) && all_zero(&p, sizeof(p)));
    /* A refused or any other kind holds nothing and empties the slot. */
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    assert(!zapp_pay_stash_offer(code, ZAPP_SCAN_PAY_REFUSED));
    assert(!zapp_pay_stash_take(&p));
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    assert(!zapp_pay_stash_offer(code, ZAPP_SCAN_TEXT));
    assert(!zapp_pay_stash_take(&p));
    /* A payload the parser refuses is not held even if the kind says pay. */
    assert(!zapp_pay_stash_offer("zclassic:nonsense", ZAPP_SCAN_PAY) && !zapp_pay_stash_take(&p));
    assert(!zapp_pay_stash_offer(NULL, ZAPP_SCAN_PAY));
    /* A new scan empties what an earlier one left. */
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    zapp_pay_stash_clear();
    assert(!zapp_pay_stash_take(&p));
    /* The second payment replaces the first. */
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    payment_code(code, sizeof(code), "?amount=2");
    assert(zapp_pay_stash_offer(code, ZAPP_SCAN_PAY));
    assert(zapp_pay_stash_take(&p) && p.amount_zat == 200000000ull);
    puts("pay_stash_test: ok");
    return 0;
}
