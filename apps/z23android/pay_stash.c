/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "pay_stash.h"
#include "base/cleanse.h"
#include <pthread.h>
#include <string.h>

static struct {
    pthread_mutex_t lock;
    struct zapp_payment pay;
    bool held;
} slot = {.lock = PTHREAD_MUTEX_INITIALIZER};

void zapp_pay_stash_clear(void)
{
    pthread_mutex_lock(&slot.lock);
    memory_cleanse(&slot.pay, sizeof(slot.pay));
    slot.held = false;
    pthread_mutex_unlock(&slot.lock);
}

bool zapp_pay_stash_offer(const char *payload, enum zapp_scan_kind kind)
{
    struct zapp_payment pay;
    zapp_pay_stash_clear();
    if (kind != ZAPP_SCAN_PAY || !payload) return false;
    if (zapp_scan_payment(payload, &pay) != ZAPP_PAY_OK) {
        memory_cleanse(&pay, sizeof(pay));
        return false;
    }
    pthread_mutex_lock(&slot.lock);
    slot.pay = pay;
    slot.held = true;
    pthread_mutex_unlock(&slot.lock);
    memory_cleanse(&pay, sizeof(pay));
    return true;
}

bool zapp_pay_stash_take(struct zapp_payment *out)
{
    pthread_mutex_lock(&slot.lock);
    bool held = slot.held;
    if (held) *out = slot.pay;
    else memset(out, 0, sizeof(*out));
    memory_cleanse(&slot.pay, sizeof(slot.pay));
    slot.held = false;
    pthread_mutex_unlock(&slot.lock);
    return held;
}
