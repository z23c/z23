/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet lock/unlock — the at-rest key-availability gate.
 *
 * wallet_keystore.{h,c} is the crypto primitive (WKS1 envelope); the
 * wallet_sqlite read/write paths wrap transparent keys under a WKD1 wallet
 * DEK and Sapling/HD secrets in WKS1 before they hit node.db. This module
 * owns the *runtime* half of that story: whether the
 * passphrase is currently available, so a wallet can be LOCKED (keys not
 * decryptable / not resident in RAM) and UNLOCKED (passphrase supplied) at
 * runtime — the standard `walletlock` / `walletpassphrase` posture.
 *
 * Effective-passphrase resolution (what the persistence layer decrypts with):
 *
 *   1. force-locked        -> NULL           (explicit `lock`, wins over env)
 *   2. runtime passphrase  -> that value     (explicit `unlock`)
 *   3. otherwise           -> NULL           (locked / no passphrase)
 *
 * Environment auto-unlock is deliberately unsupported. Interactive wallets
 * start locked and secret input enters through the bounded native stdin unlock
 * surface. A headless service may make one explicit boot-time exception by
 * provisioning systemd's `wallet-passphrase` credential; boot registers that
 * credential before persistence reads any encrypted rows. A plaintext wallet
 * (no at-rest encryption in use) is considered unlocked because there is
 * nothing to decrypt.
 *
 * Consensus-neutral: this is wallet-local key handling.  It changes no tx
 * bytes, no proof, and no consensus check — a tx signed by an unlocked
 * wallet is byte-identical to today's. */

#ifndef ZCL_WALLET_LOCK_H
#define ZCL_WALLET_LOCK_H

#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wallet;
struct wallet_sqlite;
struct json_value;

/* Typed error codes for the lock surface (negative, distinct from the
 * wallet_sqlite WSQL_* range). */
enum wallet_lock_err {
    WLK_OK              = 0,
    WLK_NULL_ARG        = -200,
    WLK_EMPTY_PASS      = -201,
    WLK_PASS_TOO_LONG   = -202,
    WLK_WRONG_PASS      = -203,   /* passphrase did not decrypt on-disk keys */
    WLK_LOCKED          = -204,   /* spend attempted on a locked wallet */
    WLK_TIMEOUT_RANGE   = -205,
    WLK_TIMER_FAIL      = -206,
    WLK_CREDENTIAL_IO   = -207,
    WLK_CREDENTIAL_MODE = -208,
};

/* The passphrase the persistence layer must decrypt/encrypt with, per the
 * resolution order above.  Reentrant.  The returned pointer is owned by the
 * module and stays valid until the next lock/unlock call; copy it if you must
 * hold it across one.  Returns NULL when locked or when no passphrase is set. */
const char *wallet_lock_effective_passphrase(void);

/* Copy the active passphrase while holding the lock. Prefer this for an
 * operation that must remain safe if the auto-lock timer fires concurrently.
 * The caller must cleanse `out` after use. */
bool wallet_lock_copy_passphrase(char *out, size_t out_size);

/* Record that the wallet uses at-rest encryption — the persistence layer
 * calls this the first time it encrypts or detects a WKS1/WKD1 envelope, so the
 * lock subsystem can tell an encrypted wallet (lockable) from a plaintext
 * one (nothing to lock).  Idempotent, thread-safe. */
void wallet_lock_note_encrypted_at_rest(void);
bool wallet_lock_encrypted_at_rest(void);

/* True when spending keys are accessible: a plaintext wallet is always
 * unlocked; an encrypted wallet is unlocked only while an effective
 * passphrase is available. */
bool wallet_lock_is_unlocked(void);

/* Spend-authority gate, consulted at every spend entry IN ADDITION TO the
 * sync-trust WALLET_SPEND capability: a locked wallet cannot spend even when
 * trust permits.  Returns ZCL_OK when unlocked; a WLK_LOCKED error otherwise. */
struct zcl_result wallet_lock_spend_guard(void);

/* Runtime unlock.  Cache `passphrase` in a secured buffer, clear the
 * force-lock, and — when both `w` and `ws` are non-NULL — reload the keystore
 * from `ws` into `w` so decrypted keys become resident.  If on-disk key rows
 * exist but none decrypt under `passphrase`, NO state is committed: the module
 * re-locks, scrubs the attempted passphrase, and returns WLK_WRONG_PASS.
 * `w`/`ws` may be NULL (register-only unlock, e.g. before the keystore is
 * wired, or in unit tests).  Rejects NULL/empty/over-long passphrases. */
struct zcl_result wallet_lock_unlock(struct wallet *w, struct wallet_sqlite *ws,
                                     const char *passphrase);

/* Register the systemd `wallet-passphrase` credential before boot reads
 * encrypted rows. Missing CREDENTIALS_DIRECTORY or a missing named credential
 * is a clean no-op. Present credentials must be regular, private, bounded
 * files; contents are read once, registered through wallet_lock_unlock(NULL,
 * NULL, ...), cleansed, and never logged. Environment passphrases are not
 * consulted here. */
struct zcl_result wallet_lock_register_boot_credential(void);

/* Arm automatic lock after a successful unlock. `timeout_seconds` is bounded
 * to 1..3600; expiry scrubs the cached passphrase and resident private keys.
 * Re-arming supersedes the older timer. */
struct zcl_result wallet_lock_arm_timeout(struct wallet *w,
                                          uint32_t timeout_seconds);

/* Runtime lock.  Secure-erase the cached passphrase, set the force-lock, and
 * wipe decrypted private keys from `w`'s in-RAM keystore (`w` may be NULL).
 * Never touches disk; idempotent. */
void wallet_lock_lock(struct wallet *w);

/* Render {locked, unlocked, encrypted_at_rest, source} into `out` (which the
 * caller has already json_set_object'd).  Never echoes the passphrase. */
void wallet_lock_status_json(struct json_value *out);

/* Test-only: scrub the cached passphrase and reset every process-global lock
 * flag to a clean start.  The lock state is a single process-wide singleton;
 * this lets unit tests run deterministically regardless of ordering.  Not for
 * production call sites. */
void wallet_lock_reset_for_test(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_WALLET_LOCK_H */
