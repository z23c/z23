/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Create Service — a brand-new wallet in an empty datadir.
 *
 * A 24-word BIP39 phrase is drawn from the system random source and derives
 * the wallet seed through mnemonic_to_wallet_seed, exactly as a restore does,
 * so restoring the phrase in another datadir reproduces the same shielded
 * addresses. The seed and the Sapling keys are written under a caller-held
 * passphrase through the WKS1 and WKD1 envelopes, so nothing is ever on disk
 * in the clear. No transparent key is minted. The chain tip the datadir holds
 * is stored as the wallet birthday, and scans start there.
 *
 * The phrase is returned once, in the report, to the caller. It is not
 * stored, logged or journaled by this service. Whoever receives the report
 * owns the buffer and calls wallet_create_report_cleanse.
 *
 * Creation never overwrites or merges: a datadir that holds any seed, key or
 * note is refused, as is a datadir a node is holding. It writes through
 * wallet_recovery_run, so it shares that service's lock, read-only target
 * inspection and refusals.
 */

#ifndef ZCL_SERVICES_WALLET_CREATE_SERVICE_H
#define ZCL_SERVICES_WALLET_CREATE_SERVICE_H

#include "services/wallet_recovery_service.h"
#include "util/result.h"
#include "wallet/mnemonic.h"

#include <stddef.h>

/* Shortest passphrase accepted, in bytes. */
#define WALLET_CREATE_MIN_PASSPHRASE 12

struct wallet_create_request {
    const char *datadir;      /* target datadir; required */
    const char *passphrase;   /* at-rest passphrase; required, never stored */
};

struct wallet_create_report {
    struct wallet_recovery_report recovery;   /* public facts only */
    char phrase[MNEMONIC_MAX_PHRASE_SIZE];    /* set only on success */
};

/* Create a wallet in `req->datadir`. Returns ZCL_OK on success; on refusal
 * the code is
 *   -68 passphrase missing or shorter than WALLET_CREATE_MIN_PASSPHRASE
 *   -69 the system random source or phrase generation failed
 * or one of wallet_recovery_run's codes (-61 datadir held, -62 a wallet is
 * already there, -63/-65/-66 storage). `out->phrase` is empty on every
 * failure. */
struct zcl_result wallet_create_run(const struct wallet_create_request *req,
                                    struct wallet_create_report *out);

/* Draw a new 24-word recovery phrase into `out` (at least
 * MNEMONIC_MAX_PHRASE_SIZE bytes) from the system random source. Touches no
 * file or database and takes no lock; the one generator create uses. Returns
 * ZCL_OK, or -69 with `out` emptied. The caller cleanses `out`. */
struct zcl_result wallet_create_phrase(char *out, size_t cap);

/* Overwrite the phrase buffer. */
void wallet_create_report_cleanse(struct wallet_create_report *rep);

#endif /* ZCL_SERVICES_WALLET_CREATE_SERVICE_H */
