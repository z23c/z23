/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Regression for the checkout lock and the Makefile recipes that
 *          take it. */

#ifndef ZCL_CHECKOUT_LOCK_SELFTEST_H
#define ZCL_CHECKOUT_LOCK_SELFTEST_H

/* repo is the checkout whose Makefile and build/bin/checkout-lock are
 * checked. Returns 0 after the PASS line. A failed check returns 1. */
int zcl_checkout_lock_selftest(const char *repo);

#endif
