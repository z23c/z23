/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the C23 Commons stranger-journey installer. */

#include "c23_commons_beta.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "c23-commons-beta: cannot locate the checkout\n");
        return 1;
    }
    return zcl_c23_commons_beta(root);
}
