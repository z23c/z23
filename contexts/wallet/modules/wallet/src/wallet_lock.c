/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet lock/unlock — implementation.  See wallet_lock.h for the model. */

#include "wallet/wallet_lock.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_sqlite_key_crypto.h"
#include "wallet/keystore.h"

#include "platform/positioned_file.h"
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

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* All fields guarded by g_mu. */
static char  g_runtime_pass[WLK_MAX_PASS + 1];
static bool  g_have_runtime_pass;   /* an unlock cached a passphrase */
static bool  g_force_locked;        /* an explicit lock — wins over env */
static bool  g_encrypted_at_rest;   /* the wallet uses WKS1 at-rest wrapping */
static uint64_t g_timeout_generation;

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

static void wallet_lock_apply_locked(struct wallet *w)
{
    memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
    g_have_runtime_pass = false;
    g_force_locked = true;
    g_timeout_generation++;
    if (w)
        keystore_wipe_private_keys(&w->keystore);
}

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
    pthread_mutex_lock(&g_mu);
    if (!thread_registry_shutdown_requested() && remaining == 0 &&
        timer->generation == g_timeout_generation) {
        wallet_lock_apply_locked(timer->wallet);
        locked_now = true;
    }
    pthread_mutex_unlock(&g_mu);
    if (locked_now)
        wallet_sqlite_key_crypto_reset();
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

bool wallet_lock_encrypted_at_rest(void)
{
    pthread_mutex_lock(&g_mu);
    bool v = g_encrypted_at_rest;
    pthread_mutex_unlock(&g_mu);
    return v;
}

bool wallet_lock_is_unlocked(void)
{
    pthread_mutex_lock(&g_mu);
    /* A plaintext wallet has nothing to unlock — always "unlocked". An
     * encrypted wallet is unlocked only while an effective passphrase is
     * available. */
    bool unlocked = !g_encrypted_at_rest || (effective_pass_locked() != NULL);
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

struct zcl_result wallet_lock_unlock(struct wallet *w, struct wallet_sqlite *ws,
                                     const char *passphrase)
{
    if (!passphrase)
        return ZCL_ERR(WLK_NULL_ARG, "unlock: passphrase is NULL");
    size_t plen = strlen(passphrase);
    if (plen == 0)
        return ZCL_ERR(WLK_EMPTY_PASS, "unlock: passphrase is empty");
    if (plen > WLK_MAX_PASS)
        return ZCL_ERR(WLK_PASS_TOO_LONG,
                       "unlock: passphrase exceeds %d bytes", WLK_MAX_PASS);

    /* A new unlock attempt must never reuse a DEK cached under an older or
     * wrong passphrase. The wrapper is authenticated again below. */
    wallet_sqlite_key_crypto_reset();

    /* Snapshot prior state so a wrong passphrase leaves NO trace. */
    pthread_mutex_lock(&g_mu);
    bool  prev_have = g_have_runtime_pass;
    bool  prev_force = g_force_locked;
    char  prev_pass[WLK_MAX_PASS + 1];
    memcpy(prev_pass, g_runtime_pass, sizeof(prev_pass));

    memcpy(g_runtime_pass, passphrase, plen);
    g_runtime_pass[plen] = '\0';
    g_have_runtime_pass = true;
    g_force_locked = false;
    pthread_mutex_unlock(&g_mu);

    /* Register-only unlock (no keystore wired / unit test): accept. */
    if (!w || !ws) {
        memory_cleanse(prev_pass, sizeof(prev_pass));
        return ZCL_OK;
    }

    /* Reload transparent + Sapling keys from disk under the new passphrase.
     * read_keys_r decrypts WKS1/WKD1 via wallet_lock_effective_passphrase
     * (now the just-cached value); a wrong passphrase drops every encrypted
     * row and loads zero keys. */
    struct wallet_sqlite_health before = wallet_sqlite_get_health(ws, 0);
    int rows = before.row_count;

    keystore_wipe_private_keys(&w->keystore);
    struct zcl_result rr = wallet_sqlite_read_keys_r(ws, w);
    (void)wallet_sqlite_read_sapling_keys(ws, w);

    int loaded = (int)w->keystore.num_keys;

    /* Wrong passphrase: rows exist on disk but none decrypted. Roll the
     * whole subsystem back to its pre-unlock state and scrub. */
    if (!rr.ok || (rows > 0 && loaded == 0)) {
        keystore_wipe_private_keys(&w->keystore);
        pthread_mutex_lock(&g_mu);
        memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
        memcpy(g_runtime_pass, prev_pass, sizeof(prev_pass));
        g_have_runtime_pass = prev_have;
        g_force_locked = prev_force;
        pthread_mutex_unlock(&g_mu);
        wallet_sqlite_key_crypto_reset();
        memory_cleanse(prev_pass, sizeof(prev_pass));
        return ZCL_ERR(WLK_WRONG_PASS,
            "unlock: passphrase did not decrypt any of %d on-disk key row(s)",
            rows);
    }

    memory_cleanse(prev_pass, sizeof(prev_pass));
    return ZCL_OK;
}

struct zcl_result wallet_lock_register_boot_credential(void)
{
    const char *dir = getenv("CREDENTIALS_DIRECTORY");
    if (!dir || !dir[0])
        return ZCL_OK;

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/wallet-passphrase", dir);
    if (n < 0 || (size_t)n >= sizeof(path))
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
    if (!platform_positioned_file_snapshot(&credential, &before) ||
        !platform_positioned_file_is_current_user_only(&credential) ||
        before.size == 0 || before.size > WLK_MAX_PASS) {
        platform_positioned_file_close(&credential);
        return ZCL_ERR(WLK_CREDENTIAL_MODE,
                       "boot credential is not a private bounded file");
    }

    char secret[WLK_MAX_PASS + 1];
    size_t need = (size_t)before.size;
    size_t off = 0;
    while (off < need) {
        int64_t got = platform_positioned_file_read(
            &credential, secret + off, need - off, off);
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    bool stable = platform_positioned_file_snapshot(&credential, &after) &&
        before.size == after.size &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds &&
        before.volume == after.volume && before.file_low == after.file_low &&
        before.file_high == after.file_high;
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

struct zcl_result wallet_lock_arm_timeout(struct wallet *w,
                                          uint32_t timeout_seconds)
{
    if (timeout_seconds < 1 || timeout_seconds > 3600)
        return ZCL_ERR(WLK_TIMEOUT_RANGE,
                       "unlock timeout must be between 1 and 3600 seconds");
    struct wallet_lock_timer *timer =
        zcl_malloc(sizeof(*timer), "wallet_lock_timer");
    if (!timer)
        return ZCL_ERR(WLK_TIMER_FAIL, "unlock timer allocation failed");

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

void wallet_lock_lock(struct wallet *w)
{
    pthread_mutex_lock(&g_mu);
    wallet_lock_apply_locked(w);
    pthread_mutex_unlock(&g_mu);
    wallet_sqlite_key_crypto_reset();
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

void wallet_lock_reset_for_test(void)
{
    pthread_mutex_lock(&g_mu);
    memory_cleanse(g_runtime_pass, sizeof(g_runtime_pass));
    g_have_runtime_pass = false;
    g_force_locked = false;
    g_encrypted_at_rest = false;
    g_timeout_generation++;
    pthread_mutex_unlock(&g_mu);
    wallet_sqlite_key_crypto_reset();
}
