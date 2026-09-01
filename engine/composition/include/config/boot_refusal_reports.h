/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The typed refusal reports app_init's boot steps emit.
 *
 * These live outside engine/composition/src/boot.c on purpose. Each one is a block of
 * operator-facing prose — message, measured evidence, and verified next
 * commands — attached to a decision made elsewhere. Keeping the prose in its
 * own translation unit lets the decision sites stay short enough to read, and
 * lets the wording be reviewed as text rather than buried mid-function.
 *
 * Every function here renders through config/boot_error.h, so a pre-registry
 * refusal reaches an operator or agent in the same {code, phase, message,
 * evidence, next[]} shape a dispatched command would produce. The caller
 * decides; these functions only explain. None of them exits — the caller owns
 * the return/exit. */

#ifndef ZCL_CONFIG_BOOT_REFUSAL_REPORTS_H
#define ZCL_CONFIG_BOOT_REFUSAL_REPORTS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct zcl_result;

/* BOOT_DATADIR_CREATE_FAILED — the datadir did not exist and the node's
 * single-level mkdir also failed. `mkdir_errno` is errno as captured at the
 * failing call. */
void boot_report_datadir_create_failed(const char *datadir, int mkdir_errno);

/* BOOT_WALLET_PERSISTENCE_OPEN_FAILED — STATE D of the wallet boot state
 * machine: wallet_keys has rows but the persistence layer would not open.
 * `open_result` carries the WSQL_* code, message and source file:line. */
void boot_report_wallet_persistence_open_failed(
    const char *datadir, const struct zcl_result *open_result,
    long long wallet_key_rows);

/* BOOT_WALLET_CANARY_FAILED — STATE E: the wallet opened but its
 * write-then-read self-test failed while user keys are on disk. */
void boot_report_wallet_canary_failed(const char *datadir, int canary_code,
                                      const char *canary_message,
                                      long long wallet_key_rows);

/* BOOT_WALLET_KEYSTORE_COUNT_MISMATCH — STATE F: fewer keys loaded into the
 * keystore than there are rows on disk, so the next flush would delete the
 * difference. */
void boot_report_wallet_keystore_count_mismatch(const char *datadir,
                                                long long wallet_key_rows,
                                                size_t loaded_keys);

/* BOOT_WALLET_PLAINTEXT_SCRUB_FAILED — STATE G: wrapping legacy plaintext
 * secret rows into WKS1 envelopes failed, so an encrypted wallet would
 * keep plaintext key material at rest. */
void boot_report_wallet_scrub_failed(const char *datadir,
                                     const struct zcl_result *scrub_result);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_REFUSAL_REPORTS_H */
