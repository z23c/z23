/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Declare the wallet recovery coverage verdict and comparison interface.
 */
#ifndef Z23_WALLET_RECOVERY_COVERAGE_H
#define Z23_WALLET_RECOVERY_COVERAGE_H
#include <stdint.h>
struct wallet_sqlite;
struct wallet;
enum wrc_coverage { WRC_COVERAGE_UNKNOWN, WRC_COVERAGE_COMPLETE, WRC_COVERAGE_INCOMPLETE };
/* old must be a freshly initialized empty wallet owned by the caller;
 * its contents may be replaced with the rebuilt wallet. The caller owns and
 * must close the connection if SQLite cannot release the read transaction.
 * Compares persisted wallet material with the actual offline empty-target
 * rebuild. UNKNOWN includes read failures and unverifiable stored rows. */
enum wrc_coverage wrc_recovery_coverage(struct wallet_sqlite *ws, struct wallet *old,
                                        const uint8_t seed[32]);
#endif
