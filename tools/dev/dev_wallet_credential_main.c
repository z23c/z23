/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the dev-wallet credential tool. */

#include "dev_wallet_credential.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    const char *action = "status";
    if (argc >= 2)
        action = argv[1];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "dev-wallet-credential: checkout root is unavailable\n");
        return 1;
    }
    return zcl_dev_wallet_credential(argv[0], action, root);
}
