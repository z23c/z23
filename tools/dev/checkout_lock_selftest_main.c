/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the checkout-lock regression. */

#include "checkout_lock_selftest.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "checkout-lock-selftest: FAIL: cannot locate the checkout\n");
        return 1;
    }
    return zcl_checkout_lock_selftest(root);
}
