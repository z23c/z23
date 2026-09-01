/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private, same-island buyer-want UX vocabulary. */

#ifndef ZCL_SHOP_WANT_VIEW_INTERNAL_H
#define ZCL_SHOP_WANT_VIEW_INTERNAL_H

#define SHOP_WANT_NEXT_OPEN \
    "review the signed criteria and contact the buyer; fulfillment, " \
    "acceptance, and ZCL settlement are separate follow-ups — this ad " \
    "moves no value"
#define SHOP_WANT_NEXT_EXPIRED \
    "ask the buyer to post a fresh signed want; this expired ad remains " \
    "evidence and moves no value"
#define SHOP_WANT_NEXT_CANCELLED \
    "no fulfillment action: the buyer cancelled this local board entry; " \
    "the signed ad remains evidence and moves no value"

#endif /* ZCL_SHOP_WANT_VIEW_INTERNAL_H */
