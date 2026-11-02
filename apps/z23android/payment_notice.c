/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "payment_notice.h"

struct zapp_payment_notice zapp_payment_notice_of(enum zapp_payment_result result)
{
    switch (result) {
    case ZAPP_PAYMENT_SENT: return (struct zapp_payment_notice){"Payment sent", "It has left the phone. History shows it."};
    case ZAPP_PAYMENT_NOT_SENT: return (struct zapp_payment_notice){"Payment not sent", "Your coins were not spent."};
    case ZAPP_PAYMENT_UNKNOWN: break;
    }
    return (struct zapp_payment_notice){"Payment status unknown", "It may have been sent. Check History before paying again."};
}
