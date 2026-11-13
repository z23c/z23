/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet lock/unlock — implementation.  See wallet_lock.h for the model. */

#include "wallet/wallet_lock.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_sqlite_key_crypto.h"
#include "wallet/keystore.h"

#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "platform/private_file.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "json/json.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Bound the cached passphrase so it lives in a fixed, cleansable buffer
 * (no heap copy of the secret to chase). 512 bytes is far past any real
 * passphrase and still fits the WKS PBKDF2 input. */
#define WLK_MAX_PASS 512

/* g_transition serialises every lock, unlock and key reload, so a lock can never
 * land between an unlock's publication of the passphrase and its reload, and a
 * wipe can never finish after a later unlock. The passphrase check itself runs
 * before the mutex, so a slow wrong attempt never holds off a lock. Lock order
 * is fixed:
 *
 *   g_transition  ->  wallet / keystore mutexes  ->  g_mu
 *
 * Persistence code holding wallet or keystore mutexes calls back into this
 * module, but only for functions that take g_mu alone. No function that
 * takes g_transition (lock, unlock, the timer) may be called with a wallet,
 * keystore or g_mu mutex held. */
static pthread_mutex_t g_transition = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* All fields guarded by g_mu. */
static char  g_runtime_pass[WLK_MAX_PASS + 1];
static bool  g_have_runtime_pass;   /* an unlock cached a passphrase */
static bool  g_force_locked;        /* an explicit lock — wins over env */
static bool  g_unlock_loading;       /* an unlock published the passphrase and is
                                       still reading the key rows back */
static bool  g_encrypted_at_rest;   /* the wallet uses WKS1 at-rest wrapping */
static bool  g_live_wallet;         /* this process serves a wallet of its own */
static uint64_t g_timeout_generation;
#ifdef ZCL_TESTING
static _Thread_local void (*g_unlock_observer)(char);
void wallet_lock_test_unlock_observer(void (*observer)(char))
{
    g_unlock_observer = observer;
}
static void wlk_observe(char stage)
{
    if (g_unlock_observer) g_unlock_observer(stage);
}
#else
#define wlk_observe(stage) ((void)0)
#endif

#ifdef ZCL_TESTING
/* Test-only seam, compiled out of production. When nonzero, the nth
 * wallet_lock_is_unlocked() call after arming reports unlocked and then
 * forces the wallet locked. */
static uint32_t g_flip_after_unlock_checks;
/* Counts wallet_lock_unlock() entries; read only by tests. */
static uint32_t g_unlock_entries;
#endif

struct wallet_lock_timer {
    struct wallet *wallet;
    uint32_t timeout_seconds;
    uint64_t generation;
};

/* Resolve the effective passphrase under g_mu already held. Returns a
 * pointer into g_runtime_pass, the env value, or NULL. */
static const char *effective_pass_locked(void)
{
    if (g_force_locked)
        return NULL;
    if (g_have_runtime_pass)
        return g_runtime_pass;
    return NULL;
}

static bool wallet_lock_apply_locked(void)
{
    memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
    g_have_runtime_pass = false;
    g_force_locked = true;
    g_timeout_generation++;
    return g_encrypted_at_rest;
}

/* Make secret memory non-resident. Runs after g_mu is released: it takes the
 * keystore and wallet mutexes, and persistence code holding those calls back
 * into this module. An encrypted wallet keeps only viewing material; a
 * plaintext wallet has no passphrase to restore from, so its Sapling keys
 * stay as they were.
 *
 * The transparent seal runs under w->cs, the mutex a key mint holds from its
 * lock check through keystore_add_key. A mint therefore either finishes
 * before the seal and is sealed by it, or starts after the lock was published
 * and refuses; it can never add a key the seal has already passed. The order
 * is wallet -> keystore, as in every mint and flush. */
static void wallet_lock_wipe_memory(struct wallet *w, bool encrypted)
{
    if (!w)
        return;
    zcl_mutex_lock(&w->cs);
    keystore_seal_private_keys(&w->keystore);
    zcl_mutex_unlock(&w->cs);
    if (!encrypted)
        return;
    sapling_keystore_wipe_secrets(&w->sapling_keys);
    wallet_hd_wipe_master(w);
}

#ifdef ZCL_TESTING
static void (*g_timer_blocked_hook)(void *);
static void *g_timer_blocked_ctx;
void wallet_lock_timer_test_blocked_hook(void (*hook)(void *), void *ctx)
{
    g_timer_blocked_hook = hook; g_timer_blocked_ctx = ctx;
}
static void wlk_timer_transition_lock(void)
{
    if (g_timer_blocked_hook) {
        if (pthread_mutex_trylock(&g_transition) == 0) return;
        g_timer_blocked_hook(g_timer_blocked_ctx);
    }
    pthread_mutex_lock(&g_transition);
}
#else
static void wlk_timer_transition_lock(void) { pthread_mutex_lock(&g_transition); }
#endif


static void *wallet_lock_timer_main(void *opaque)
{
    struct wallet_lock_timer *timer = opaque;
    uint32_t remaining = timer->timeout_seconds;
    while (remaining > 0 && !thread_registry_shutdown_requested()) {
        struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };
        while (nanosleep(&req, &req) != 0) { /* retry interrupted sleep */ }
        remaining--;
        pthread_mutex_lock(&g_mu);
        bool current = timer->generation == g_timeout_generation;
        pthread_mutex_unlock(&g_mu);
        if (!current)
            break;
    }
    bool locked_now = false;
    bool encrypted = false;
    wlk_timer_transition_lock();
    pthread_mutex_lock(&g_mu);
    if (!thread_registry_shutdown_requested() && remaining == 0 &&
        timer->generation == g_timeout_generation) {
        encrypted = wallet_lock_apply_locked();
        locked_now = true;
    }
    pthread_mutex_unlock(&g_mu);
    if (locked_now) {
        wallet_lock_wipe_memory(timer->wallet, encrypted);
        wallet_sqlite_key_crypto_reset();
    }
    pthread_mutex_unlock(&g_transition);
    free(timer);
    return NULL;
}

const char *wallet_lock_effective_passphrase(void)
{
    pthread_mutex_lock(&g_mu);
    const char *p = effective_pass_locked();
    pthread_mutex_unlock(&g_mu);
    return p;
}

bool wallet_lock_copy_passphrase(char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return false; // raw-return-ok:copy predicate rejects absent output
    pthread_mutex_lock(&g_mu);
    const char *p = effective_pass_locked();
    size_t n = p ? strlen(p) : 0;
    bool ok = p && n + 1 <= out_size;
    if (ok)
        memcpy(out, p, n + 1);
    else
        out[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    return ok;
}

void wallet_lock_note_encrypted_at_rest(void)
{
    pthread_mutex_lock(&g_mu);
    g_encrypted_at_rest = true;
    pthread_mutex_unlock(&g_mu);
}

void wallet_lock_note_live_wallet(void)
{
    pthread_mutex_lock(&g_mu);
    g_live_wallet = true;
    pthread_mutex_unlock(&g_mu);
}

bool wallet_lock_has_live_wallet(void)
{
    pthread_mutex_lock(&g_mu);
    bool v = g_live_wallet;
    pthread_mutex_unlock(&g_mu);
    return v;
}

bool wallet_lock_encrypted_at_rest(void)
{
    pthread_mutex_lock(&g_mu);
    bool v = g_encrypted_at_rest;
    pthread_mutex_unlock(&g_mu);
    return v;
}

bool wallet_lock_is_locked(void)
{
    pthread_mutex_lock(&g_mu);
    bool locked = g_encrypted_at_rest &&
                  (effective_pass_locked() == NULL || g_unlock_loading);
    pthread_mutex_unlock(&g_mu);
    return locked;
}

bool wallet_lock_is_unlocked(void)
{
    pthread_mutex_lock(&g_mu);
    /* A plaintext wallet has nothing to unlock — always "unlocked". An
     * encrypted wallet is unlocked only while an effective passphrase is
     * available. It is also not
     * unlocked while an unlock is still reading its keys back: the passphrase
     * is live for that read, but no key is loaded yet. */
    bool unlocked = !g_encrypted_at_rest ||
                    (effective_pass_locked() != NULL && !g_unlock_loading);
#ifdef ZCL_TESTING
    if (g_flip_after_unlock_checks && --g_flip_after_unlock_checks == 0) {
        memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
        g_have_runtime_pass = false;
        g_force_locked = true;
    }
#endif
    pthread_mutex_unlock(&g_mu);
    return unlocked;
}

struct zcl_result wallet_lock_spend_guard(void)
{
    if (wallet_lock_is_unlocked())
        return ZCL_OK;
    return ZCL_ERR(WLK_LOCKED,
        "wallet is locked — private keys are encrypted at rest and no "
        "passphrase is loaded; unlock before spending");
}

/* Publish `passphrase` as the live passphrase and report the state it
 * replaced, so a failed reload can put it back. g_transition is held. */
struct wlk_prev {
    bool have;
    bool force;
    char pass[WLK_MAX_PASS + 1];
};

static void wlk_publish(const char *passphrase, size_t plen,
                        struct wlk_prev *prev)
{
    pthread_mutex_lock(&g_mu);
    prev->have = g_have_runtime_pass;
    prev->force = g_force_locked;
    memcpy(prev->pass, g_runtime_pass, sizeof(prev->pass));
    memcpy(g_runtime_pass, passphrase, plen);
    g_runtime_pass[plen] = '\0';
    g_have_runtime_pass = true;
    g_force_locked = false;
    g_unlock_loading = true;
    pthread_mutex_unlock(&g_mu);
}

/* The unlock read every key class back: the wallet now reports unlocked. */
static void wlk_loaded(void)
{
    pthread_mutex_lock(&g_mu);
    g_unlock_loading = false;
    pthread_mutex_unlock(&g_mu);
}

/* Undo wlk_publish. A wallet that was locked before is sealed again. */
static void wlk_rollback(struct wallet *w, struct wlk_prev *prev)
{
    pthread_mutex_lock(&g_mu);
    memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
    memcpy(g_runtime_pass, prev->pass, sizeof(prev->pass));
    g_have_runtime_pass = prev->have;
    g_force_locked = prev->force;
    g_unlock_loading = false;
    bool encrypted = g_encrypted_at_rest;
    pthread_mutex_unlock(&g_mu);
    if (!prev->have)
        wallet_lock_wipe_memory(w, encrypted);
    wallet_sqlite_key_crypto_reset();
    memory_cleanse(prev, sizeof(*prev));
}

/* Restore the HD master from the Sapling seed. An unlock after a locked boot
 * has no master yet: adopt the seed when it governs the stored keys, exactly
 * as a passphrase boot does. */
static void wlk_restore_hd(struct wallet *w)
{
    uint8_t seed[32];
    if (!sapling_keystore_copy_seed(&w->sapling_keys, seed))
        return;
    (void)wallet_hd_restore_master(w, seed);
    if (!wallet_has_hd(w))
        (void)wallet_hd_adopt_seed(w, seed);
    memory_cleanse(seed, sizeof(seed));
}

/* Prove the passphrase against the sealed rows before any live key or lock
 * state changes: a wrong attempt must leave no trace. Takes no lock of this
 * module, so a slow attempt (rows x KDF) never holds off a lock. */
static struct zcl_result wlk_check_passphrase(struct wallet_sqlite *ws,
                                              const char *passphrase)
{
    enum wallet_passphrase_check chk =
        wallet_sqlite_check_passphrase(ws, passphrase);
    if (chk == WALLET_PASS_WRONG)
        return ZCL_ERR(WLK_WRONG_PASS,
            "unlock: passphrase did not decrypt any sealed on-disk row");
    if (chk == WALLET_PASS_UNREADABLE)
        return ZCL_ERR(WLK_STORE_UNREADABLE,
            "unlock: stored key rows could not be read; wallet unchanged");
    return ZCL_OK;
}

/* Reload every key row into the live keystores and restore the HD master.
 * g_transition is held. */
static bool wlk_reload(struct wallet *w, struct wallet_sqlite *ws)
{
    struct zcl_result rr = wallet_sqlite_read_keys_r(ws, w);
    bool sapling_ok = wallet_sqlite_read_sapling_keys(ws, w);
    if (!rr.ok || !sapling_ok)
        return false;
    wlk_observe('K');
    wlk_restore_hd(w);
    wlk_observe('H');
    return true;
}

static struct zcl_result wlk_unlock_locked(struct wallet *w,
                                           struct wallet_sqlite *ws,
                                           const char *passphrase, size_t plen)
{
    wallet_sqlite_key_crypto_reset();
    struct wlk_prev prev;
    wlk_publish(passphrase, plen, &prev);

    if (!wlk_reload(w, ws)) {
        wlk_rollback(w, &prev);
        return ZCL_ERR(WLK_STORE_UNREADABLE,
            "unlock: stored keys could not be read; wallet stays locked");
    }
    wlk_loaded();
    memory_cleanse(&prev, sizeof(prev));
    return ZCL_OK;
}

struct zcl_result wallet_lock_reload_keys(struct wallet *w,
                                          struct wallet_sqlite *ws)
{
    if (!w || !ws)
        return ZCL_ERR(WLK_NULL_ARG, "reload: wallet or store is NULL");
    pthread_mutex_lock(&g_transition);
    bool ok = wlk_reload(w, ws);
    pthread_mutex_unlock(&g_transition);
    if (!ok)
        return ZCL_ERR(WLK_STORE_UNREADABLE,
            "reload: stored keys could not be read");
    return ZCL_OK;
}

struct zcl_result wallet_lock_unlock(struct wallet *w, struct wallet_sqlite *ws,
                                     const char *passphrase)
{
#ifdef ZCL_TESTING
    pthread_mutex_lock(&g_mu);
    g_unlock_entries++;
    pthread_mutex_unlock(&g_mu);
#endif
    if (!passphrase)
        return ZCL_ERR(WLK_NULL_ARG, "unlock: passphrase is NULL");
    size_t plen = strlen(passphrase);
    if (plen == 0)
        return ZCL_ERR(WLK_EMPTY_PASS, "unlock: passphrase is empty");
    if (plen > WLK_MAX_PASS)
        return ZCL_ERR(WLK_PASS_TOO_LONG,
                       "unlock: passphrase exceeds %d bytes", WLK_MAX_PASS);

    if (w && ws) {
        struct zcl_result c = wlk_check_passphrase(ws, passphrase);
        if (!c.ok)
            return c;
        wlk_observe('C');
    }
    pthread_mutex_lock(&g_transition);
    wlk_observe('L');
    struct zcl_result r;
    if (!w || !ws) {
        /* Register-only unlock (no keystore wired / unit test): accept. */
        struct wlk_prev prev;
        wlk_publish(passphrase, plen, &prev);
        wlk_loaded();
        memory_cleanse(&prev, sizeof(prev));
        r = ZCL_OK;
    } else {
        r = wlk_unlock_locked(w, ws, passphrase, plen);
    }
    pthread_mutex_unlock(&g_transition);
    return r;
}

/* Format the boot credential path into path; false when it would not fit. */
static bool boot_credential_path(char *path, size_t path_size, const char *dir)
{
    int n = snprintf(path, path_size, "%s/wallet-passphrase", dir);
    return n >= 0 && (size_t)n < path_size;
}

/* Fill before and report whether the open credential is a private bounded
 * file: statable, current-user-only, non-empty and within WLK_MAX_PASS. */
static bool boot_credential_snapshot_valid(
    struct platform_positioned_file *credential,
    struct platform_positioned_file_snapshot *before)
{
    if (!platform_positioned_file_snapshot(credential, before))
        return false;
    if (!platform_positioned_file_is_current_user_only(credential))
        return false;
    if (before->size == 0 || before->size > WLK_MAX_PASS)
        return false;
    return true;
}

/* Read exactly need bytes of the credential into secret; short on error. */
static size_t boot_credential_read_secret(
    struct platform_positioned_file *credential, char *secret, size_t need)
{
    size_t off = 0;
    while (off < need) {
        int64_t got = platform_positioned_file_read(
            credential, secret + off, need - off, off);
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    return off;
}

struct zcl_result wallet_lock_register_boot_credential(void)
{
    const char *dir = getenv("CREDENTIALS_DIRECTORY");
    if (!dir || !dir[0])
        return ZCL_OK;

    char path[1024];
    if (!boot_credential_path(path, sizeof(path), dir))
        return ZCL_ERR(WLK_CREDENTIAL_IO,
                       "boot credential path exceeds internal bound");

    struct platform_positioned_file credential;
    platform_positioned_file_init(&credential);
    if (!platform_positioned_file_open_beneath(
            &credential, dir, "wallet-passphrase")) {
        if (platform_private_path_absent(path)) return ZCL_OK;
        return ZCL_ERR(WLK_CREDENTIAL_IO,
                       "boot credential could not be opened");
    }

    struct platform_positioned_file_snapshot before, after;
    if (!boot_credential_snapshot_valid(&credential, &before)) {
        platform_positioned_file_close(&credential);
        return ZCL_ERR(WLK_CREDENTIAL_MODE,
                       "boot credential is not a private bounded file");
    }

    char secret[WLK_MAX_PASS + 1];
    size_t need = (size_t)before.size;
    size_t off = boot_credential_read_secret(&credential, secret, need);
    bool stable = platform_positioned_file_snapshot(&credential, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&credential);
    if (off != need || !stable || memchr(secret, '\0', need) != NULL) {
        memory_cleanse(secret, sizeof(secret));
        return ZCL_ERR(WLK_CREDENTIAL_IO,
                       "boot credential read was incomplete or invalid");
    }
    secret[need] = '\0';
    struct zcl_result registered = wallet_lock_unlock(NULL, NULL, secret);
    memory_cleanse(secret, sizeof(secret));
    return registered;
}

bool wallet_lock_timeout_valid(int64_t timeout_seconds)
{
    return timeout_seconds >= WALLET_LOCK_TIMEOUT_MIN_SECONDS &&
           timeout_seconds <= WALLET_LOCK_TIMEOUT_MAX_SECONDS;
}

struct zcl_result wallet_lock_arm_timeout(struct wallet *w,
                                          uint32_t timeout_seconds)
{
    /* Every failure path re-locks before refusing: callers such as the
     * walletunlock RPC handler arm after unlocking, so an unarmed
     * refusal must never leave the wallet unlocked with no timer. */
    if (!wallet_lock_timeout_valid(timeout_seconds)) {
        wallet_lock_lock(w);
        return ZCL_ERR(WLK_TIMEOUT_RANGE,
                       "unlock timeout must be between 1 and 3600 seconds");
    }
    struct wallet_lock_timer *timer =
        zcl_malloc(sizeof(*timer), "wallet_lock_timer");
    if (!timer) {
        wallet_lock_lock(w);
        return ZCL_ERR(WLK_TIMER_FAIL, "unlock timer allocation failed");
    }

    pthread_mutex_lock(&g_mu);
    timer->wallet = w;
    timer->timeout_seconds = timeout_seconds;
    timer->generation = ++g_timeout_generation;
    pthread_mutex_unlock(&g_mu);

    // thread-supervision-ok:bounded-one-shot autolock timer exits after its finite deadline
    if (thread_registry_spawn("zcl_wallet_lock", wallet_lock_timer_main,
                              timer, NULL) != 0) {
        free(timer);
        wallet_lock_lock(w);
        return ZCL_ERR(WLK_TIMER_FAIL,
                       "unlock timer could not start; wallet re-locked");
    }
    return ZCL_OK;
}

bool wallet_lock_startup_publication_begin(int64_t deadline_ms)
{
    if (deadline_ms <= 0) return false;
    pthread_mutex_lock(&g_transition);
    int64_t now = platform_time_monotonic_ms();
    pthread_mutex_lock(&g_mu);
    bool ok = now > 0 && now < deadline_ms && g_encrypted_at_rest &&
              !g_unlock_loading && effective_pass_locked() != NULL;
    pthread_mutex_unlock(&g_mu);
    if (!ok) pthread_mutex_unlock(&g_transition);
    return ok;
}

void wallet_lock_startup_publication_end(void)
{
    pthread_mutex_unlock(&g_transition);
}

void wallet_lock_lock(struct wallet *w)
{
    pthread_mutex_lock(&g_transition);
    pthread_mutex_lock(&g_mu);
    bool encrypted = wallet_lock_apply_locked();
    pthread_mutex_unlock(&g_mu);
    wallet_lock_wipe_memory(w, encrypted);
    wallet_sqlite_key_crypto_reset();
    pthread_mutex_unlock(&g_transition);
}

void wallet_lock_status_json(struct json_value *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_mu);
    bool encrypted = g_encrypted_at_rest;
    bool unlocked = !g_encrypted_at_rest || (effective_pass_locked() != NULL);
    const char *source;
    if (!encrypted)                 source = "plaintext";
    else if (g_force_locked)        source = "locked";
    else if (g_have_runtime_pass)   source = "runtime";
    else                            source = "locked";
    pthread_mutex_unlock(&g_mu);

    json_push_kv_bool(out, "encrypted_at_rest", encrypted);
    json_push_kv_bool(out, "unlocked", unlocked);
    json_push_kv_bool(out, "locked", !unlocked);
    json_push_kv_str(out, "source", source);
}

#ifdef ZCL_TESTING
void wallet_lock_flip_after_unlock_checks_for_test(uint32_t n)
{
    pthread_mutex_lock(&g_mu);
    g_flip_after_unlock_checks = n;
    pthread_mutex_unlock(&g_mu);
}

uint32_t wallet_lock_unlock_entries_for_test(void)
{
    pthread_mutex_lock(&g_mu);
    uint32_t entries = g_unlock_entries;
    pthread_mutex_unlock(&g_mu);
    return entries;
}
#endif

void wallet_lock_reset_for_test(void)
{
    pthread_mutex_lock(&g_mu);
    memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
    g_have_runtime_pass = false;
    g_force_locked = false;
    g_unlock_loading = false;
#ifdef ZCL_TESTING
    g_flip_after_unlock_checks = 0;
    g_unlock_entries = 0;
    g_unlock_observer = NULL;
#endif
    g_encrypted_at_rest = false;
    g_live_wallet = false;
    g_timeout_generation++;
    pthread_mutex_unlock(&g_mu);
    wallet_sqlite_key_crypto_reset();
}
