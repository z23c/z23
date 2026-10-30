// one-result-type-ok:config-defaults-fill-caller-struct — E2 (one way out):
// wallet_backup_config_defaults() fills a CALLER-owned config and cannot
// report failure. The service-owned password installation path in this TU
// is fallible and returns struct zcl_result.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: wallet-backup configuration defaults and the
 * WALLET_BACKUP_PASSWORD environment encryption policy.
 *
 * Split out of contexts/wallet/services/src/wallet_backup_service.c when the
 * lifecycle half passed the 800-line shape ceiling. This TU owns one seam:
 * how caller-supplied configuration becomes service-owned configuration,
 * including allocation and retirement of the full-length encryption
 * password. It touches no module state, mutex, or database — the caller
 * supplies every ownership slot. The thread, status snapshot, supervisor
 * contract, and diagnostics dumper stay in wallet_backup_service.c; the
 * one-shot snapshot primitive is wallet_backup_run.c; rotation is
 * wallet_backup_rotation.c; the WBE1 crypto is wallet_backup_crypto.c.
 *
 * The public defaults entry point stays in wallet_backup_service.h. Password
 * ownership helpers are private to the wallet-backup service module.
 */

#include "services/wallet_backup_internal.h"
#include "core/serialize.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

static const char wbs_alloc_label[] = "wallet_backup_password";

/* WALLET_BACKUP_PASSWORD env policy: non-empty => encrypt; absent or
 * empty => plaintext with a one-time warning (the service is the
 * key-loss safety net, so it must not refuse to run). This pointer is a
 * borrowed process-environment view used only until wallet_backup_start()
 * makes the service-owned full-length copy. Keeping allocation and cleanup
 * in the service avoids immortal copies while preserving exact password
 * bytes for the documented restore path. */
static void wbs_config_apply_env_password(struct wallet_backup_config *cfg)
{
    static bool warned_plaintext;
    const char *env_pw = getenv("WALLET_BACKUP_PASSWORD");
    if (!env_pw || !*env_pw) {
        if (!warned_plaintext) {
            warned_plaintext = true;
            LOG_WARN("wallet_backup",
                     "WALLET_BACKUP_PASSWORD not set — wallet backups will "
                     "be written in cleartext (set it to enable encryption)");
        }
        return;
    }
    cfg->encrypt = true;
    cfg->encrypt_password = env_pw;
}

void wallet_backup_config_defaults(struct wallet_backup_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->interval_seconds = WALLET_BACKUP_DEFAULT_INTERVAL_SEC;
    cfg->max_versions     = WALLET_BACKUP_DEFAULT_MAX_VERSIONS;
    cfg->encrypt          = false;
    /* Fleet-wide encryption policy rides the env var so every
     * config_defaults caller (boot included) inherits it. */
    wbs_config_apply_env_password(cfg);
}

static bool wbs_fmt(char *out, size_t cap, const char *base, const char *sub)
{
    int n = sub ? snprintf(out, cap, "%s/wallet_backups/%s", base, sub)
                : snprintf(out, cap, "%s/wallet_backups", base);
    return n > 0 && (size_t)n < cap;
}

static bool wbs_is_mainnet(const char *network_id)
{
    return network_id && strcmp(network_id, "main") == 0;
}

/* A non-mainnet id becomes ONE path component: 1-15 chars of [a-z0-9] only,
 * so "", ".", "..", "a/b" or "Test" can never resolve to (or above) the
 * mainnet directory. */
static bool wbs_network_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static bool wbs_valid_network_component(const char *id)
{
    size_t n = id ? strlen(id) : 0;
    size_t i = 0;
    while (i < n && wbs_network_char_ok(id[i])) i++;
    return n >= 1 && n <= 15 && i == n; // raw-return-ok:pure-validator-no-io
}

bool wallet_backup_default_dir(const char *home, const char *network_id,
                               char *out, size_t cap,
                               char *parent_out, size_t parent_cap)
{
    if (!out || !cap) return false;
    if (parent_out && parent_cap) parent_out[0] = '\0';
    const char *base = home && home[0] ? home : ".";
    if (wbs_is_mainnet(network_id)) return wbs_fmt(out, cap, base, NULL);
    if (!wbs_valid_network_component(network_id))
        return false; // raw-return-ok:pure-validator-caller-logs
    if (!wbs_fmt(out, cap, base, network_id)) return false;
    if (!parent_out || !parent_cap) return true;
    return wbs_fmt(parent_out, parent_cap, base, NULL);
}

#ifdef ZCL_TESTING
static _Atomic(wbs_stop_test_observer) g_wbs_stop_observer;

void wbs_test_stop_observer_set(wbs_stop_test_observer observer)
{
    atomic_store(&g_wbs_stop_observer, observer);
}

bool wbs_test_stop_observe(enum wbs_stop_test_stage stage)
{
    wbs_stop_test_observer observer = atomic_load(&g_wbs_stop_observer);
    return observer ? observer(stage) : true;
}

static _Atomic size_t g_wbs_password_retired_len;
static _Atomic bool g_wbs_password_retired_zero;

void wallet_backup_test_password_retirement_reset(void)
{
    atomic_store(&g_wbs_password_retired_len, 0);
    atomic_store(&g_wbs_password_retired_zero, false);
}

bool wallet_backup_test_password_retirement_snapshot(size_t *retired_len)
{
    if (retired_len)
        *retired_len = atomic_load(&g_wbs_password_retired_len);
    return atomic_load(&g_wbs_password_retired_zero);
}

static void wbs_test_observe_password_retirement(const char *password,
                                                 size_t password_cap)
{
    bool all_zero = true;
    for (size_t i = 0; i < password_cap; i++)
        all_zero = all_zero && password[i] == '\0';
    atomic_store(&g_wbs_password_retired_len, password_cap);
    atomic_store(&g_wbs_password_retired_zero, all_zero);
}
#endif

void wbs_config_retire_password(struct wallet_backup_config *cfg,
                                char **owned_password,
                                size_t *owned_password_cap)
{
    char *password = *owned_password;
    size_t password_cap = *owned_password_cap;
    *owned_password = NULL;
    *owned_password_cap = 0;
    cfg->encrypt_password = NULL;
    if (!password)
        return;
    memory_cleanse(password, password_cap);
#ifdef ZCL_TESTING
    wbs_test_observe_password_retirement(password, password_cap);
#endif
    /* Adopt the already-cleansed allocation for the shared buffer releaser. */
    struct byte_stream retired = {
        .data = (unsigned char *)password,
        .owns_data = true,
    };
    stream_free(&retired);
}

struct zcl_result wbs_config_install(
    const struct wallet_backup_config *source,
    struct wallet_backup_config *destination,
    char **owned_password,
    size_t *owned_password_cap)
{
    char *password = NULL;
    size_t password_cap = 0;
    if (source->encrypt) {
        size_t password_len = strlen(source->encrypt_password);
        if (password_len == SIZE_MAX)
            return ZCL_ERR(-25, "start: encryption password is too long");
        password_cap = password_len + 1;
        password = zcl_malloc(password_cap, wbs_alloc_label);
        if (!password)
            return ZCL_ERR(-25,
                           "start: cannot allocate encryption password");
        memcpy(password, source->encrypt_password, password_cap);
    }
    wbs_config_retire_password(destination, owned_password,
                               owned_password_cap);
    *destination = *source;
    *owned_password = password;
    *owned_password_cap = password_cap;
    destination->encrypt_password = password;
    return ZCL_OK;
}
