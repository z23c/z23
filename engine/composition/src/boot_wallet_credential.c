/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_wallet_credential — register one systemd wallet secret before WKS1
 * persistence reads, with a named fatal refusal for malformed credentials. */

#include "config/boot_internal.h"

#include "wallet/wallet_lock.h"

#include <stdio.h>
#include <stdlib.h>

void boot_wallet_credential_register_or_die(void)
{
    struct zcl_result result = wallet_lock_register_boot_credential();
    if (result.ok)
        return;

    fprintf(stderr, "FATAL boot: wallet credential refused (code=%d): %s\n",
            result.code, result.message);
    exit(1);
}
