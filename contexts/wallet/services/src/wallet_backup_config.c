// one-result-type-ok:config-defaults-fill-caller-struct — E2 (one way out):
// this TU owns no fallible service surface. Both entry points return void
// and fill a CALLER-owned struct wallet_backup_config; the single failure
// they can meet (OOM copying WALLET_BACKUP_PASSWORD) is deliberately
// encoded as encrypt=true with a NULL password so wallet_backup_start
// refuses LOUDLY with a typed struct zcl_result (-24) instead of silently
// writing plaintext. Every fallible wallet-backup surface (start, now,
// now_encrypted, run_once) already returns struct zcl_result.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: wallet-backup configuration defaults and the
 * WALLET_BACKUP_PASSWORD environment encryption policy.
 *
 * Split out of contexts/wallet/services/src/wallet_backup_service.c when the lifecycle
 * half passed the 800-line shape ceiling. This TU owns exactly one seam:
 * how a caller-supplied struct wallet_backup_config is filled in before the
 * service is started. It touches no module state, no mutex, and no database
 * — the thread, status snapshot, supervisor contract, and diagnostics
 * dumper stay in wallet_backup_service.c; the one-shot snapshot primitive
 * is wallet_backup_run.c; rotation is wallet_backup_rotation.c; the WBE1
 * crypto is wallet_backup_crypto.c.
 *
 * wallet_backup_config_defaults() is already declared in
 * services/wallet_backup_service.h, so this is a pure move with no linkage
 * change.
 */

#include "services/wallet_backup_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* WALLET_BACKUP_PASSWORD env policy: non-empty => encrypt; absent or
 * empty => plaintext with a one-time warning (the service is the
 * key-loss safety net, so it must not refuse to run). The password is
 * kept as a FULL-LENGTH heap copy: the --decrypt-wallet-backup restore
 * path derives its key from the raw env string, so truncating here
 * (e.g. into a fixed buffer) would encrypt every backup under a key
 * the documented recovery path can never re-derive. The copy is cached
 * and never freed — a running service's shallow config copy may still
 * reference it. */
static void wbs_config_apply_env_password(struct wallet_backup_config *cfg)
{
    static char *cached_pw;
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
    if (!cached_pw || strcmp(cached_pw, env_pw) != 0) {
        size_t len = strlen(env_pw) + 1;
        char *copy = zcl_malloc(len, "wallet_backup_env_pw");
        if (!copy) {
            /* encrypt=true with a NULL password makes
             * wallet_backup_start fail loudly (-24) instead of
             * silently writing plaintext against operator intent. */
            LOG_WARN("wallet_backup",
                     "cannot copy WALLET_BACKUP_PASSWORD (OOM) — backup "
                     "start will refuse rather than fall back to plaintext");
            cfg->encrypt = true;
            cfg->encrypt_password = NULL;
            return;
        }
        memcpy(copy, env_pw, len);
        cached_pw = copy;   /* old copy (if any) intentionally leaked */
    }
    cfg->encrypt = true;
    cfg->encrypt_password = cached_pw;
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
