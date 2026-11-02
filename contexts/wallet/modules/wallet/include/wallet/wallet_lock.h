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
    WLK_STORE_UNREADABLE = -209,  /* stored rows could not be read; unchanged */
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

/* Record that this process serves a wallet of its own (boot calls it once the
 * node's wallet is open). Create and restore unlock and then force-lock the
 * process-wide lock to write a different datadir; they refuse when this is
 * set, so they cannot lock or re-key a running wallet. Idempotent. */
void wallet_lock_note_live_wallet(void);
bool wallet_lock_has_live_wallet(void);

/* True when spending keys are accessible: a plaintext wallet is always
 * unlocked; an encrypted wallet is unlocked only while an effective
 * passphrase is available. */
bool wallet_lock_is_unlocked(void);

/* True iff the wallet is encrypted at rest and no passphrase is loaded. Same
 * truth as !wallet_lock_is_unlocked() but without the test seam, so internal
 * checks do not consume an armed seam count. */
bool wallet_lock_is_locked(void);

/* Spend-authority gate, consulted at every spend entry IN ADDITION TO the
 * sync-trust WALLET_SPEND capability: a locked wallet cannot spend even when
 * trust permits.  Returns ZCL_OK when unlocked; a WLK_LOCKED error otherwise. */
struct zcl_result wallet_lock_spend_guard(void);

/* Runtime unlock.  When both `w` and `ws` are non-NULL, first test
 * `passphrase` against the sealed rows on disk; if sealed rows exist and none
 * opens, return WLK_WRONG_PASS having changed nothing (live keys, cached
 * passphrase and lock state included).  A right passphrase is established by
 * the rows that do open: a damaged row is reported per key and never blocks
 * the others.  Then cache the passphrase, clear the force-lock, reload the
 * keystores into the existing entries (idempotent), restore the Sapling seed
 * and the HD master, and adopt the stored seed when it governs the keys (an
 * unlock after a locked boot).  A read error returns WLK_STORE_UNREADABLE and
 * leaves the wallet in its prior state.  Lock and unlock are serialised by one
 * transition mutex.  `w`/`ws` may be NULL (register-only unlock, e.g. before
 * the keystore is wired, or in unit tests).  Rejects NULL/empty/over-long
 * passphrases. */
struct zcl_result wallet_lock_unlock(struct wallet *w, struct wallet_sqlite *ws,
                                     const char *passphrase);

/* Reload every stored key row into the live keystores and restore the HD
 * master, under the same transition mutex as lock and unlock, so a lock can
 * neither land inside the reload nor be undone by it. Use this instead of
 * reading the key rows directly from outside this module. */
struct zcl_result wallet_lock_reload_keys(struct wallet *w,
                                          struct wallet_sqlite *ws);

/* Register the systemd `wallet-passphrase` credential before boot reads
 * encrypted rows. Missing CREDENTIALS_DIRECTORY or a missing named credential
 * is a clean no-op. Present credentials must be regular, private, bounded
 * files; contents are read once, registered through wallet_lock_unlock(NULL,
 * NULL, ...), cleansed, and never logged. Environment passphrases are not
 * consulted here. */
struct zcl_result wallet_lock_register_boot_credential(void);

/* The auto-lock duration range, in seconds, inclusive. */
#define WALLET_LOCK_TIMEOUT_MIN_SECONDS 1
#define WALLET_LOCK_TIMEOUT_MAX_SECONDS 3600

/* True iff `timeout_seconds` is inside the auto-lock range. Pure: callers use
 * it to refuse a request before any key is decrypted. */
bool wallet_lock_timeout_valid(int64_t timeout_seconds);

/* Arm automatic lock after a successful unlock. `timeout_seconds` is bounded
 * to 1..3600; expiry scrubs the cached passphrase and resident private keys.
 * Re-arming supersedes the older timer. */
struct zcl_result wallet_lock_arm_timeout(struct wallet *w,
                                          uint32_t timeout_seconds);

/* Runtime lock.  Secure-erase the cached passphrase, set the force-lock, and
 * cleanse the secret material held by `w` (`w` may be NULL): transparent
 * private keys always; for an encrypted wallet also the Sapling seed, master
 * key and every spending key, and the HD master key.  Viewing keys,
 * diversifiers, pk_d and the address list stay resident, so a locked wallet
 * keeps scanning incoming notes.  Unlock restores the secrets into the
 * existing entries.  Never touches disk; idempotent. */
void wallet_lock_lock(struct wallet *w);

/* Render {locked, unlocked, encrypted_at_rest, source} into `out` (which the
 * caller has already json_set_object'd).  Never echoes the passphrase. */
void wallet_lock_status_json(struct json_value *out);

/* Test-only: scrub the cached passphrase and reset every process-global lock
 * flag to a clean start.  The lock state is a single process-wide singleton;
 * this lets unit tests run deterministically regardless of ordering.  Not for
 * production call sites. */
void wallet_lock_reset_for_test(void);

#ifdef ZCL_TESTING
/* Test-only: after `n` further wallet_lock_is_unlocked() calls, the wallet is
 * forced locked. 0 (the production state) disables it; reset by
 * wallet_lock_reset_for_test(). Not for production call sites. */
void wallet_lock_flip_after_unlock_checks_for_test(uint32_t n);
/* Test-only: how many times wallet_lock_unlock() has been entered since the
 * last wallet_lock_reset_for_test(). Lets a test prove a refusal happened
 * before the unlock path (and so before any key was decrypted). */
uint32_t wallet_lock_unlock_entries_for_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_WALLET_LOCK_H */
