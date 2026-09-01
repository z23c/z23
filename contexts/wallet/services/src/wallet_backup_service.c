// wallet_backup_dump_state_json, implements the diagnostics_dump_fn typedef
// (CLAUDE.md "Adding state introspection": `bool <name>_dump_state_json(...)`)
// mandated by the g_dumpers[] dispatch table in
// engine/controllers/src/diagnostics_registry.c; every other dumper in the
// codebase has the same bool signature for the same reason, so this is not
// a candidate for struct zcl_result conversion.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Backup Service — LIFECYCLE half: config, the background thread,
 * the status snapshot, the diagnostics dumper, and the supervisor liveness
 * contract. See the header for rationale.
 *
 * The one-shot snapshot primitive and its all-eight-tables verification
 * live in wallet_backup_run.c (declared in wallet_backup_internal.h);
 * rotation/listing in wallet_backup_rotation.c; the WBE1 crypto in
 * wallet_backup_crypto.c. The split happened when verification grew from
 * one table to eight and this file passed the 800-line shape ceiling.
 */

#include "base/result.h"
#include "base/text_fit.h"
#include "crypto/sha3.h"
#include "models/wallet_backup_receipt.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "services/wallet_backup_internal.h"
#include "services/wallet_backup_service.h"
#include "event/event.h"
#include "json/json.h"
#include "supervisors/domains.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#define WALLET_BACKUP_SUPERVISOR_DEADLINE_SEC 60
/* ── Module state ───────────────────────────────────────────── */
struct wallet_backup_service_state {
    pthread_mutex_t lock;
    pthread_t       thread;
    bool            thread_running;
    bool            stop_requested;
    struct wallet_backup_config cfg;
    struct node_db             *db;
    /* Snapshot counters */
    int64_t total_runs;
    int64_t total_failures;
    int64_t last_run_unix;
    int64_t last_size_bytes;
    int64_t last_key_count;
    int64_t last_duration_ms;
    int     last_tables_verified;
    char    last_missing_tables[WBS_MISSING_TABLES_MAX];
    char    last_path[512];
    int64_t last_encrypted_run_unix;
    int64_t last_encrypted_key_count;
    int     last_encrypted_tables_verified;
    char    last_encrypted_path[512];
    char    last_error[256];
    /* Debounced event trigger (D4: plan §5.4).
     * Set by wallet_backup_service_on_key_change; cleared by the
     * thread after running a debounce-eligible backup. */
    bool    key_change_pending;
    int64_t total_triggers;     /* total on_key_change calls (all, incl. coalesced) */
    int64_t total_trigger_runs; /* backups that actually ran due to a trigger */
    _Atomic supervisor_child_id supervisor_id;
};
static struct wallet_backup_service_state g_wbs = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};
static struct liveness_contract g_wbs_contract;
/* ── Helpers ────────────────────────────────────────────────── */
static bool wbs_same_snapshot(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a && b && a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}
static bool wbs_path_char_equal(char a, char b)
{
#ifdef _WIN32
    if (a == '\\') a = '/';
    if (b == '\\') b = '/';
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
#endif
    return a == b; // raw-return-ok:path-comparison
}
static bool wbs_canonical_backup_path(const char *backup_dir,
                                      const char *canonical_path)
{
    char probe[WALLET_BACKUP_RECEIPT_PATH_MAX];
    char resolved[WALLET_BACKUP_RECEIPT_PATH_MAX];
    char canonical_root[WALLET_BACKUP_RECEIPT_PATH_MAX];
    int n = snprintf(probe, sizeof(probe), "%s/%s", backup_dir,
                     ".z23-wallet-backup-root-probe");
    if (n <= 0 || (size_t)n >= sizeof(probe) ||
        !platform_private_destination_resolve(
            probe, resolved, sizeof(resolved), canonical_root,
            sizeof(canonical_root)))
        return false;
    size_t root_len = strlen(canonical_root);
    size_t path_len = strlen(canonical_path);
    if (path_len <= root_len + 1)
        return false;
    for (size_t i = 0; i < root_len; i++)
        if (!wbs_path_char_equal(canonical_root[i], canonical_path[i]))
            return false; // raw-return-ok: not under the root
    if (!wbs_path_char_equal(canonical_path[root_len], '/'))
        return false; // raw-return-ok: root is not a whole component
    const char *leaf = canonical_path + root_len + 1;
    if (strchr(leaf, '/') || strchr(leaf, '\\') ||
        strncmp(leaf, WALLET_BACKUP_FILENAME_PREFIX,
                strlen(WALLET_BACKUP_FILENAME_PREFIX)) != 0)
        return false;
    size_t leaf_len = strlen(leaf);
    size_t suffix_len = strlen(WALLET_BACKUP_FILENAME_SUFFIX_ENC);
    return leaf_len >= suffix_len &&
           strcmp(leaf + leaf_len - suffix_len,
                  WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0;
}
/* Hash through one private, no-reparse handle and prove its canonical handle
 * path is a direct policy-named child of the validated backup root. */
static bool wbs_hash_regular_file(const char *backup_dir, const char *path,
                                  uint8_t out[32], int64_t *size_out,
                                  char *canonical_out, size_t canonical_cap)
{
    if (!backup_dir || !path || !out || !size_out || !canonical_out ||
        canonical_cap == 0)
        return false; /* raw-return-ok:input validation predicate */
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false; /* raw-return-ok:unreadable receipt is not authority */
    struct platform_positioned_file_snapshot before, after;
    char canonical[WALLET_BACKUP_RECEIPT_PATH_MAX];
    if (!platform_positioned_file_is_private(&file) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > INT64_MAX ||
        !platform_positioned_file_path(&file, canonical, sizeof(canonical)) ||
        !wbs_canonical_backup_path(backup_dir, canonical)) {
        platform_positioned_file_close(&file);
        return false; /* raw-return-ok:not a stable regular backup file */
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[65536];
    uint64_t total = 0;
    bool ok = true;
    while (total < before.size) {
        size_t wanted = before.size - total > sizeof(buf)
            ? sizeof(buf) : (size_t)(before.size - total);
        int64_t n = platform_positioned_file_read(
            &file, buf, wanted, total);
        if (n > 0) {
            sha3_256_write(&sha, buf, (size_t)n);
            total += (uint64_t)n;
            continue;
        }
        ok = false;
        break;
    }
    if (!platform_positioned_file_snapshot(&file, &after) ||
        !wbs_same_snapshot(&before, &after) || total != before.size)
        ok = false;
    platform_positioned_file_close(&file);
    if (!ok)
        return false; /* raw-return-ok:file changed or read failed */
    sha3_256_finalize(&sha, out);
    *size_out = (int64_t)total;
    int copied = snprintf(canonical_out, canonical_cap, "%s", canonical);
    if (copied <= 0 || (size_t)copied >= canonical_cap)
        return false;
    return true;
}
static void wbs_clear_encrypted_authority_locked(void)
{
    g_wbs.last_encrypted_run_unix = 0;
    g_wbs.last_encrypted_key_count = 0;
    g_wbs.last_encrypted_tables_verified = 0;
    g_wbs.last_encrypted_path[0] = '\0';
}
static void wbs_restore_encrypted_authority_locked(void)
{
    wbs_clear_encrypted_authority_locked();
    struct wallet_backup_receipt receipt;
    if (!db_wallet_backup_receipt_find(g_wbs.db, &receipt))
        return;
    size_t table_count = 0;
    (void)wallet_backup_tables(&table_count);
    uint8_t digest[32];
    int64_t size = 0;
    char canonical[WALLET_BACKUP_RECEIPT_PATH_MAX];
    if (receipt.tables_verified != (int)table_count ||
        !wbs_hash_regular_file(g_wbs.cfg.backup_dir, receipt.backup_path,
                               digest, &size, canonical,
                               sizeof(canonical)) ||
        size != receipt.size_bytes ||
        memcmp(digest, receipt.file_sha3, sizeof(digest)) != 0) {
        LOG_WARN("wallet_backup",
                 "durable encrypted-backup receipt did not verify; "
                 "send readiness remains blocked");
        return;
    }
    g_wbs.last_encrypted_run_unix = receipt.completed_unix;
    g_wbs.last_encrypted_key_count = receipt.key_count;
    g_wbs.last_encrypted_tables_verified = receipt.tables_verified;
    snprintf(g_wbs.last_encrypted_path,
             sizeof(g_wbs.last_encrypted_path), "%s", canonical);
}
static struct zcl_result wbs_record_encrypted_authority_locked(
    const char *path)
{
    struct wallet_backup_receipt receipt = {
        .completed_unix = g_wbs.last_run_unix,
        .key_count = g_wbs.last_key_count,
        .tables_verified = g_wbs.last_tables_verified,
    };
    char canonical[WALLET_BACKUP_RECEIPT_PATH_MAX];
    if (!wbs_hash_regular_file(g_wbs.cfg.backup_dir, path,
                               receipt.file_sha3, &receipt.size_bytes,
                               canonical, sizeof(canonical)))
        return ZCL_ERR(-13, "encrypted backup bytes could not be verified");
    if (snprintf(receipt.backup_path, sizeof(receipt.backup_path), "%s",
                 canonical) <= 0 ||
        strlen(canonical) >= sizeof(receipt.backup_path))
        return ZCL_ERR(-13, "encrypted backup path exceeds receipt bound");
    if (!db_wallet_backup_receipt_save(g_wbs.db, &receipt))
        return ZCL_ERR(-13, "encrypted backup receipt could not be persisted");
    g_wbs.last_encrypted_run_unix = receipt.completed_unix;
    g_wbs.last_encrypted_key_count = receipt.key_count;
    g_wbs.last_encrypted_tables_verified = receipt.tables_verified;
    snprintf(g_wbs.last_encrypted_path,
             sizeof(g_wbs.last_encrypted_path), "%s", receipt.backup_path);
    g_wbs.last_size_bytes = receipt.size_bytes;
    return ZCL_OK;
}
static int64_t wbs_progress_marker(void)
{
    if (pthread_mutex_trylock(&g_wbs.lock) != 0)
        return 0;
    int64_t marker = g_wbs.total_runs + g_wbs.total_failures;
    pthread_mutex_unlock(&g_wbs.lock);
    return marker;
}
static void wbs_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_wbs.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, wbs_progress_marker());
}
static void wbs_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int64_t runs = -1;
    int64_t failures = -1;
    if (pthread_mutex_trylock(&g_wbs.lock) == 0) {
        runs = g_wbs.total_runs;
        failures = g_wbs.total_failures;
        pthread_mutex_unlock(&g_wbs.lock);
    }
    LOG_WARN("wallet_backup",
             "[wallet_backup] supervisor stall reason=%s runs=%lld failures=%lld",
             reason, (long long)runs, (long long)failures);
    event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                "source=wallet_backup decision=worker_stall "
                "reason=%s runs=%lld failures=%lld",
                reason, (long long)runs, (long long)failures);
}
static struct zcl_result wbs_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-30, "wallet_backup: supervisor_start failed");
    supervisor_child_id id = atomic_load(&g_wbs.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, WALLET_BACKUP_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, wbs_progress_marker());
        supervisor_tick(id);
        return ZCL_OK;
    }
    liveness_contract_init(&g_wbs_contract, "wallet.backup");
    atomic_store(&g_wbs_contract.period_secs, 0);
    atomic_store(&g_wbs_contract.deadline_secs,
                 WALLET_BACKUP_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_wbs_contract.progress_max_quiet_us, 0);
    g_wbs_contract.on_stall = wbs_on_stall;
    supervisor_domains_init();
    id = supervisor_register_in_domain(g_op_sup, &g_wbs_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-31, "wallet_backup: supervisor_register failed");
    atomic_store(&g_wbs.supervisor_id, id);
    supervisor_progress(id, wbs_progress_marker());
    supervisor_tick(id);
    return ZCL_OK;
}

/* Config defaults + the WALLET_BACKUP_PASSWORD env encryption policy
 * (wallet_backup_config_defaults) live in wallet_backup_config.c. */

void wallet_backup_status_snapshot(struct wallet_backup_status *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_wbs.lock);
    out->running          = g_wbs.thread_running;
    out->total_runs       = g_wbs.total_runs;
    out->total_failures   = g_wbs.total_failures;
    out->last_run_unix    = g_wbs.last_run_unix;
    out->last_size_bytes  = g_wbs.last_size_bytes;
    out->last_key_count   = g_wbs.last_key_count;
    out->last_duration_ms = g_wbs.last_duration_ms;
    out->last_tables_verified = g_wbs.last_tables_verified;
    size_t n_tables = 0;
    (void)wallet_backup_tables(&n_tables);
    out->wallet_table_count = (int)n_tables;
    snprintf(out->last_missing_tables, sizeof(out->last_missing_tables), "%s",
             g_wbs.last_missing_tables);
    snprintf(out->last_path,  sizeof(out->last_path),  "%s", g_wbs.last_path);
    out->last_encrypted_run_unix = g_wbs.last_encrypted_run_unix;
    out->last_encrypted_key_count = g_wbs.last_encrypted_key_count;
    out->last_encrypted_tables_verified =
        g_wbs.last_encrypted_tables_verified;
    snprintf(out->last_encrypted_path, sizeof(out->last_encrypted_path), "%s",
             g_wbs.last_encrypted_path);
    snprintf(out->last_error, sizeof(out->last_error), "%s", g_wbs.last_error);
    pthread_mutex_unlock(&g_wbs.lock);
}
/* See CLAUDE.md "Adding state introspection". Reentrant-safe: reuses the
 * lock-guarded snapshot that RPC/agent callers already read. */
bool wallet_backup_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    struct wallet_backup_status st;
    wallet_backup_status_snapshot(&st);
    bool backup_available = st.last_run_unix > 0 && st.last_path[0] != '\0';
    bool encrypted_backup_available =
        st.last_encrypted_run_unix > 0 &&
        st.last_encrypted_path[0] != '\0';
    json_push_kv_bool(out, "running", st.running);
    json_push_kv_bool(out, "healthy", st.total_failures == 0 &&
                                      st.last_error[0] == '\0');
    json_push_kv_bool(out, "backup_available", backup_available);
    json_push_kv_bool(out, "encrypted_backup_available",
                      encrypted_backup_available);
    json_push_kv_int(out, "total_runs", st.total_runs);
    json_push_kv_int(out, "total_failures", st.total_failures);
    json_push_kv_int(out, "last_run_unix", st.last_run_unix);
    json_push_kv_int(out, "last_size_bytes", st.last_size_bytes);
    json_push_kv_int(out, "last_key_count", st.last_key_count);
    json_push_kv_int(out, "last_duration_ms", st.last_duration_ms);
    /* Verification breadth. last_tables_verified counts the wallet tables
     * whose backup row count matched the source on the last run; the rest
     * are named in last_missing_tables (absent from the SOURCE, so nothing
     * to copy — not a failure, but the operator is told rather than left to
     * discover it at restore time). */
    json_push_kv_int(out, "last_tables_verified", st.last_tables_verified);
    json_push_kv_int(out, "wallet_table_count", st.wallet_table_count);
    json_push_kv_str(out, "last_missing_tables", st.last_missing_tables);
    json_push_kv_int(out, "last_encrypted_run_unix",
                     st.last_encrypted_run_unix);
    json_push_kv_int(out, "last_encrypted_key_count",
                     st.last_encrypted_key_count);
    json_push_kv_int(out, "last_encrypted_tables_verified",
                     st.last_encrypted_tables_verified);
    json_push_kv_bool(out, "last_error_present", st.last_error[0] != '\0');
    json_push_kv_str(out, "next_action",
                     encrypted_backup_available
                         ? "none"
                         : "run core.wallet.backup.now with encryption before "
                           "enabling real-money sends");
    return true;
}
/* Rotation / listing (wallet_backup_list, wallet_backup_rotate) live
 * in wallet_backup_rotation.c. */
/* ── Synchronous entry points ───────────────────────────────── */
static struct zcl_result wbs_run_one_locked(void)
{
    int64_t started_ms = platform_time_monotonic_ms();
    char path[512] = "";
    char err[256]  = "";
    int64_t key_count = -1;
    struct wbs_verify_out vout;
    struct zcl_result res = wbs_run_once_impl(g_wbs.cfg.backup_dir, g_wbs.db,
                                      path, sizeof(path),
                                      &key_count,
                                      err, sizeof(err), &vout);
    bool ok = res.ok;
    int64_t elapsed = platform_time_monotonic_ms() - started_ms;
    g_wbs.last_tables_verified = vout.tables_verified;
    snprintf(g_wbs.last_missing_tables, sizeof(g_wbs.last_missing_tables),
             "%s", vout.missing);
    if (ok) {
        g_wbs.total_runs++;
        g_wbs.last_run_unix    = platform_time_wall_unix();
        g_wbs.last_key_count   = key_count;
        g_wbs.last_duration_ms = elapsed;
        snprintf(g_wbs.last_path, sizeof(g_wbs.last_path), "%s", path);
        g_wbs.last_error[0] = '\0';
        struct stat st;
        g_wbs.last_size_bytes =
            stat(path, &st) == 0 ? (int64_t)st.st_size : -1;
        /* Encryption step. Order: write → verify rowcount (both done
         * inside wallet_backup_run_once, on the plaintext) → encrypt →
         * unlink plaintext → rotate. An encrypt failure KEEPS the
         * verified plaintext — never delete the only fresh backup —
         * and reports loudly instead. */
        if (g_wbs.cfg.encrypt && g_wbs.cfg.encrypt_password &&
            *g_wbs.cfg.encrypt_password) {
            char enc_path[576];
            size_t plen = strlen(path);
            size_t slen = strlen(WALLET_BACKUP_FILENAME_SUFFIX);
            int base = plen >= slen ? (int)(plen - slen) : (int)plen;
            snprintf(enc_path, sizeof(enc_path), "%.*s%s", base, path,
                     WALLET_BACKUP_FILENAME_SUFFIX_ENC);
            struct zcl_result er = wallet_backup_encrypt_file(
                path, enc_path, g_wbs.cfg.encrypt_password);
            if (er.ok) {
                if (unlink(path) != 0)
                    LOG_WARN("wallet_backup",
                             "encrypt: unlink plaintext %s failed: %s",
                             path, strerror(errno));
                snprintf(g_wbs.last_path, sizeof(g_wbs.last_path),
                         "%.511s", enc_path);
                struct zcl_result receipt =
                    wbs_record_encrypted_authority_locked(enc_path);
                if (!receipt.ok) {
                    g_wbs.total_failures++;
                    snprintf(g_wbs.last_error, sizeof(g_wbs.last_error),
                             "%s", receipt.message);
                    LOG_WARN("wallet_backup", "%s", receipt.message);
                    event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                                "reason=encrypted_receipt_failed detail=%s",
                                receipt.message);
                    res = receipt;
                }
            } else {
                g_wbs.total_failures++;
                /* "encrypt_failed: " (16) + er.message (up to
                 * ZCL_RESULT_MSG_MAX-1 = 255) is 271 bytes into a 256-byte
                 * field. Mark and log the overflow instead of handing the
                 * operator a wallet-backup failure reason that stops mid-word. */
                char full[16 + ZCL_RESULT_MSG_MAX];
                snprintf(full, sizeof(full), "encrypt_failed: %s", er.message);
                (void)zcl_text_fit(g_wbs.last_error, sizeof(g_wbs.last_error),
                                   full, "wallet_backup",
                                   "wallet_backup.last_error");
                LOG_WARN("wallet_backup",
                         "encrypt failed, keeping plaintext %s: %s",
                         path, er.message);
                event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                            "path=%s reason=encrypt_failed detail=%s",
                            path, er.message);
            }
        }
        /* Rotate after success — never lose the newest backup. */
        int max = g_wbs.cfg.max_versions > 0
            ? g_wbs.cfg.max_versions
            : WALLET_BACKUP_DEFAULT_MAX_VERSIONS;
        (void)wallet_backup_rotate(g_wbs.cfg.backup_dir, max);
    } else {
        g_wbs.total_failures++;
        snprintf(g_wbs.last_error, sizeof(g_wbs.last_error), "%s", err);
    }
    return res;
}
struct zcl_result wallet_backup_now(void)
{
    pthread_mutex_lock(&g_wbs.lock);
    if (!g_wbs.db || !g_wbs.cfg.backup_dir) {
        struct zcl_result r = ZCL_ERR(-10,
                "backup_now: service not initialized (db=%p dir=%s)",
                (void *)g_wbs.db, g_wbs.cfg.backup_dir ? g_wbs.cfg.backup_dir : "NULL");
        pthread_mutex_unlock(&g_wbs.lock);
        return r;
    }
    struct zcl_result res = wbs_run_one_locked();
    pthread_mutex_unlock(&g_wbs.lock);
    return res;
}
struct zcl_result wallet_backup_now_encrypted(const char *password)
{
    if (!password || !password[0])
        return ZCL_ERR(-11, "backup_now_encrypted: password is empty");
    pthread_mutex_lock(&g_wbs.lock);
    if (!g_wbs.db || !g_wbs.cfg.backup_dir) {
        struct zcl_result r = ZCL_ERR(-10,
                "backup_now_encrypted: service not initialized");
        pthread_mutex_unlock(&g_wbs.lock);
        return r;
    }
    bool saved_encrypt = g_wbs.cfg.encrypt;
    const char *saved_password = g_wbs.cfg.encrypt_password;
    int64_t failures_before = g_wbs.total_failures;
    g_wbs.cfg.encrypt = true;
    g_wbs.cfg.encrypt_password = password;
    struct zcl_result res = wbs_run_one_locked();
    g_wbs.cfg.encrypt = saved_encrypt;
    g_wbs.cfg.encrypt_password = saved_password;
    size_t path_len = strlen(g_wbs.last_path);
    size_t suffix_len = strlen(WALLET_BACKUP_FILENAME_SUFFIX_ENC);
    bool encrypted = res.ok && g_wbs.total_failures == failures_before &&
        path_len >= suffix_len &&
        strcmp(g_wbs.last_path + path_len - suffix_len,
               WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0;
    pthread_mutex_unlock(&g_wbs.lock);
    if (!encrypted)
        return ZCL_ERR(-12,
            "backup_now_encrypted: verified encrypted backup was not created");
    return res;
}
/* ── Thread loop ────────────────────────────────────────────── */
static void *wbs_thread_fn(void *arg)
{
    (void)arg;
    wbs_supervisor_heartbeat();
    pthread_mutex_lock(&g_wbs.lock);
    int interval = g_wbs.cfg.interval_seconds > 0
        ? g_wbs.cfg.interval_seconds
        : WALLET_BACKUP_DEFAULT_INTERVAL_SEC;
    pthread_mutex_unlock(&g_wbs.lock);
    /* Do one immediate backup on start so the user always has a
     * fresh copy within a few seconds of boot — the worst failure
     * is the boot that hasn't reached its first hourly tick yet. */
    (void)wallet_backup_now();
    wbs_supervisor_heartbeat();
    int64_t next_at_ms = platform_time_monotonic_ms() + (int64_t)interval * 1000;
    while (true) {
        pthread_mutex_lock(&g_wbs.lock);
        bool stop = g_wbs.stop_requested;
        bool pending = g_wbs.key_change_pending;
        int64_t last_ok = g_wbs.last_run_unix;
        pthread_mutex_unlock(&g_wbs.lock);
        if (stop) break;
        bool ran_this_tick = false;
        if (platform_time_monotonic_ms() >= next_at_ms) {
            (void)wallet_backup_now();
            wbs_supervisor_heartbeat();
            ran_this_tick = true;
            /* Re-read interval in case config was updated. */
            pthread_mutex_lock(&g_wbs.lock);
            interval = g_wbs.cfg.interval_seconds > 0
                ? g_wbs.cfg.interval_seconds
                : WALLET_BACKUP_DEFAULT_INTERVAL_SEC;
            pthread_mutex_unlock(&g_wbs.lock);
            next_at_ms = platform_time_monotonic_ms() + (int64_t)interval * 1000;
        } else if (pending) {
            /* Debounced trigger path: fire if the last backup (of any
             * kind) is older than WALLET_BACKUP_TRIGGER_MIN_INTERVAL_SEC.
             * Multiple triggers that arrive inside the window collapse
             * into this single run. */
            int64_t now_s = platform_time_wall_unix();
            if (last_ok == 0 ||
                now_s >= last_ok + WALLET_BACKUP_TRIGGER_MIN_INTERVAL_SEC) {
                (void)wallet_backup_now();
                wbs_supervisor_heartbeat();
                ran_this_tick = true;
                pthread_mutex_lock(&g_wbs.lock);
                g_wbs.total_trigger_runs++;
                pthread_mutex_unlock(&g_wbs.lock);
            }
        }
        if (ran_this_tick) {
            pthread_mutex_lock(&g_wbs.lock);
            g_wbs.key_change_pending = false;
            pthread_mutex_unlock(&g_wbs.lock);
        }
        /* Sleep in small increments so stop_requested is honoured
         * without waiting up to `interval` seconds. */
        wbs_supervisor_heartbeat();
        platform_sleep_ms(200);
    }
    pthread_mutex_lock(&g_wbs.lock);
    g_wbs.thread_running = false;
    pthread_mutex_unlock(&g_wbs.lock);
    return NULL;
}
struct zcl_result wallet_backup_start(const struct wallet_backup_config *cfg,
                          struct node_db *db)
{
    if (!cfg || !db || !cfg->backup_dir)
        return ZCL_ERR(-20, "start: NULL config, db, or backup_dir");
    /* Explicit encrypt without a password must fail loudly here —
     * silently falling back to plaintext would betray the operator's
     * stated intent. (config_defaults sets cfg->encrypt only when
     * WALLET_BACKUP_PASSWORD is non-empty, so this guard fires on
     * misconfigured direct callers — or on the OOM path above that
     * deliberately leaves encrypt=true with no password.
     * ZCL_SERVICE_OPTIONAL keeps it a kernel WARNING, not a boot
     * failure.) */
    if (cfg->encrypt && (!cfg->encrypt_password || !*cfg->encrypt_password)) {
        struct zcl_result r = ZCL_ERR(-24,
            "start: encrypt=true but encrypt_password is empty "
            "(set WALLET_BACKUP_PASSWORD)");
        LOG_WARN("wallet_backup", "%s", r.message);
        return r;
    }
    pthread_mutex_lock(&g_wbs.lock);
    if (g_wbs.thread_running) {
        pthread_mutex_unlock(&g_wbs.lock);
        return ZCL_OK;
    }
    /* Refuse to back up into the same datadir as the source — the
     * whole point is an *external* copy. We detect this by
     * comparing the backup_dir to the directory containing the
     * source db file. */
    char src_path[1024];
    if (wbs_source_path(db, src_path, sizeof(src_path)).ok) {
        char src_dir[1024];
        snprintf(src_dir, sizeof(src_dir), "%s", src_path);
        char *slash = strrchr(src_dir, '/');
#if defined(_WIN32)
        char *backslash = strrchr(src_dir, '\\');
        if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
        if (slash) *slash = '\0';
        char src_real[WALLET_BACKUP_RECEIPT_PATH_MAX];
        char backup_real[WALLET_BACKUP_RECEIPT_PATH_MAX];
        const char *src_compare = platform_directory_canonical_real(
                                       src_dir, src_real, sizeof(src_real))
            ? src_real : src_dir;
        const char *backup_compare = platform_directory_canonical_real(
                                         cfg->backup_dir, backup_real,
                                         sizeof(backup_real))
            ? backup_real : cfg->backup_dir;
        if (strcmp(src_compare, backup_compare) == 0) {
            struct zcl_result r = ZCL_ERR(-21,
                "start: refusing to back up into source dir %s", src_dir);
            pthread_mutex_unlock(&g_wbs.lock);
            return r;
        }
    }
    struct zcl_result dir_r = wbs_ensure_backup_dir(cfg->backup_dir);
    if (!dir_r.ok) {
        struct zcl_result r = ZCL_ERR(-22, "start: %s", dir_r.message);
        pthread_mutex_unlock(&g_wbs.lock);
        return r;
    }
    g_wbs.cfg = *cfg;
    g_wbs.db = db;
    g_wbs.stop_requested = false;
    wbs_restore_encrypted_authority_locked();
    g_wbs.thread_running = true;
    int rc = thread_registry_spawn("zcl_wallet_bk", wbs_thread_fn, NULL,
                                       &g_wbs.thread);
    if (rc != 0) {
        g_wbs.thread_running = false;
        struct zcl_result r = ZCL_ERR(-23,
                "start: thread_registry_spawn failed (%d)", rc);
        pthread_mutex_unlock(&g_wbs.lock);
        return r;
    }
    pthread_mutex_unlock(&g_wbs.lock);
    struct zcl_result sup_r = wbs_register_supervisor();
    if (!sup_r.ok) {
        wallet_backup_stop();
        return sup_r;
    }
    return ZCL_OK;
}
void wallet_backup_stop(void)
{
    pthread_t th;
    bool joinable = false;
    supervisor_child_id id = atomic_load(&g_wbs.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    pthread_mutex_lock(&g_wbs.lock);
    if (g_wbs.thread_running) {
        g_wbs.stop_requested = true;
        th = g_wbs.thread;
        joinable = true;
    }
    pthread_mutex_unlock(&g_wbs.lock);
    if (joinable) {
        pthread_join(th, NULL);
        pthread_mutex_lock(&g_wbs.lock);
        g_wbs.thread_running = false;
        g_wbs.stop_requested = false;
        g_wbs.db = NULL;
        g_wbs.key_change_pending = false;
        pthread_mutex_unlock(&g_wbs.lock);
    }
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_wbs.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}
/* ── Event triggers (D4: plan §5.4) ─────────────────────────── */
void wallet_backup_service_on_key_change(void)
{
    pthread_mutex_lock(&g_wbs.lock);
    /* Count every call, even coalesced ones, for debugging /
     * test visibility. Only set the pending flag if the thread is
     * running — otherwise the next wallet_backup_start() will do a
     * first-run immediately and pick up the state anyway. */
    g_wbs.total_triggers++;
    if (g_wbs.thread_running) {
        g_wbs.key_change_pending = true;
    }
    pthread_mutex_unlock(&g_wbs.lock);
}
void wallet_backup_service_on_keypool_topup(void)
{
    wallet_backup_service_on_key_change();
}
