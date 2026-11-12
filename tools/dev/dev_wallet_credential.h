/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Provision or report the encrypted dev-wallet boot credential. */

#ifndef ZCL_DEV_WALLET_CREDENTIAL_H
#define ZCL_DEV_WALLET_CREDENTIAL_H

/* action is "setup", "status", or NULL (status). repo is the checkout
 * the credential directory must not sit inside. 0 when status was
 * reported or setup finished. 1 when setup is refused or the action
 * is unknown. Secret bytes are never printed. */
int zcl_dev_wallet_credential(const char *argv0, const char *action,
                              const char *repo);

#endif
