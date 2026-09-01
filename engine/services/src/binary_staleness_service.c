/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Binary Staleness — see header for rationale and the detection trick.
 *
 * Uses handle-bound metadata for the cheap per-tick probe and SHA3-256 for
 * the boot baseline + any re-hash triggered by a metadata change. Polls in
 * a background pthread with small sleep increments so stop() returns
 * promptly, same shape as disk_monitor.c.
 */
// one-result-type-ok:predicate-and-json-dump-bool — binary_staleness_is_stale
// is a lock-free hot-path predicate (an answer, not a failure);
// binary_staleness_dump_state_json is the mandated *_dump_state_json bool
// contract (CLAUDE.md "Adding state introspection"). capture_boot_stamp and
// check_now return bool by the same fixed-signature convention used across
// this file's siblings (disk_monitor.c, wallet_backup_service.c) — no
// genuinely fallible multi-reason surface to convert to zcl_result beyond
// the one already-typed binary_staleness_start().

#include "platform/time_compat.h"
#include "services/binary_staleness_service.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "util/log_macros.h"

/* Supervisor deadline (sec): 3x the default poll interval gives ample
 * slack before a genuine wedge fires, same margin disk_monitor uses. */
#define BINARY_STALENESS_SUPERVISOR_DEADLINE_SEC \
    (BINARY_STALENESS_DEFAULT_POLL_SECONDS * 3)

#define BS_HASH_READ_CHUNK (64 * 1024)

/* ── Module state ───────────────────────────────────────────── */

struct bs_state {
    pthread_mutex_t lock;
    pthread_t       thread;
    bool            thread_running;
    bool            stop_requested;
    int             poll_seconds;

    bool    boot_captured;
    bool    path_valid;
    char    exe_path[512];
    unsigned char boot_digest[32];
    char    boot_digest_hex[65];
    unsigned char last_disk_digest[32];
    char    last_disk_digest_hex[65];
    int64_t boot_mtime;
    int64_t boot_size;
    int64_t last_probe_mtime;
    int64_t last_probe_size;
    uint64_t last_probe_volume;
    uint64_t last_probe_file_low;
    uint64_t last_probe_file_high;
    bool last_probe_identity_valid;
    bool    probed_once;
    int64_t last_check_unix;
    int64_t check_count;
    int64_t rehash_count;
    int64_t stale_transitions;
    int64_t probe_failures;

    _Atomic bool atomic_stale;

    _Atomic supervisor_child_id supervisor_id;
    _Atomic int64_t             loop_ticks;

#ifdef ZCL_TESTING
    bool    test_boot_override_active;
    bool    test_probe_override_active;
    unsigned char test_probe_digest[32];
    int64_t test_probe_mtime;
    int64_t test_probe_size;
#endif
};

static struct bs_state g_bs = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .boot_mtime = -1,
    .boot_size = -1,
    .last_probe_mtime = -1,
    .last_probe_size = -1,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_bs_contract;

/* Trailing " (deleted)" is how the kernel marks a readlink(/proc/self/exe)
 * result whose original dentry no longer exists (unlinked, or replaced by
 * a create-new-file-at-same-name deploy rather than an in-place rename).
 * Strip it so later stat()/fopen() calls target the real pathname, not a
 * synthetic label that will never resolve. */
static void bs_strip_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    size_t plen = strlen(path);
    size_t slen = sizeof(suffix) - 1;
    if (plen > slen && strcmp(path + plen - slen, suffix) == 0)
        path[plen - slen] = '\0';
}

/* ── Hashing primitives ─────────────────────────────────────── */

static bool bs_hash_fp(FILE *fp, unsigned char digest[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[BS_HASH_READ_CHUNK];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(&ctx, buf, n);
    if (ferror(fp))
        return false;
    sha3_256_finalize(&ctx, digest);
    return true;
}

/* Hashes the RUNNING image — always the exact bytes mapped by this
 * process, immune to a later on-disk replacement (see header rationale).
 * Routed through platform/os_proc.h (Rung 1 ADR: platform/modules/platform is the one
 * blessed home for direct /proc reads) rather than a raw fopen here. */
static bool bs_hash_running_image(unsigned char digest[32])
{
    FILE *fp = os_proc_open_self_exe();
    if (!fp)
        return false;
    bool ok = bs_hash_fp(fp, digest);
    fclose(fp);
    return ok;
}

/* Hashes whatever content currently sits at `path` (ordinary pathname
 * resolution — picks up a replaced file). */
static bool bs_hash_positioned(
    const struct platform_positioned_file *file, uint64_t size,
    unsigned char digest[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buffer[BS_HASH_READ_CHUNK];
    uint64_t offset = 0;
    while (offset < size) {
        size_t wanted = size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        int64_t got = platform_positioned_file_read(file, buffer, wanted,
                                                    offset);
        if (got <= 0 || (uint64_t)got > wanted) return false;
        sha3_256_write(&ctx, buffer, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    return true;
}

static bool bs_snapshot_equal(
    const struct platform_positioned_file_snapshot *left,
    const struct platform_positioned_file_snapshot *right)
{
    return left->size == right->size &&
           left->modified_seconds == right->modified_seconds &&
           left->modified_nanoseconds == right->modified_nanoseconds &&
           left->changed_seconds == right->changed_seconds &&
           left->changed_nanoseconds == right->changed_nanoseconds &&
           left->volume == right->volume &&
           left->file_low == right->file_low &&
           left->file_high == right->file_high;
}

/* ── Supervisor liveness ────────────────────────────────────── */

static void bs_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_bs.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_bs.loop_ticks));
}

static void bs_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("binary_staleness",
             "[binary_staleness] supervisor stall reason=%s ticks=%lld",
             reason, (long long)atomic_load(&g_bs.loop_ticks));
}

static struct zcl_result bs_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-5, "binary_staleness: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_bs.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, BINARY_STALENESS_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, atomic_load(&g_bs.loop_ticks));
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_bs_contract, "op.binary_staleness");
    atomic_store(&g_bs_contract.period_secs, 0);
    atomic_store(&g_bs_contract.deadline_secs,
                 BINARY_STALENESS_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_bs_contract.progress_max_quiet_us, 0);
    g_bs_contract.on_stall = bs_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_op_sup, &g_bs_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-6, "binary_staleness: supervisor_register failed");
    atomic_store(&g_bs.supervisor_id, id);
    supervisor_progress(id, atomic_load(&g_bs.loop_ticks));
    supervisor_tick(id);
    return ZCL_OK;
}

/* ── Defaults ───────────────────────────────────────────────── */

void binary_staleness_config_defaults(struct binary_staleness_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->poll_seconds = BINARY_STALENESS_DEFAULT_POLL_SECONDS;
}

/* ── Boot capture ───────────────────────────────────────────── */

bool binary_staleness_capture_boot_stamp(void)
{
    pthread_mutex_lock(&g_bs.lock);

#ifdef ZCL_TESTING
    if (g_bs.test_boot_override_active) {
        /* Already installed by binary_staleness_test_force_boot_stamp;
         * nothing else to do. */
        pthread_mutex_unlock(&g_bs.lock);
        return true;
    }
#endif

    char resolved[sizeof(g_bs.exe_path)];
    if (!os_proc_exe_path(resolved, sizeof(resolved))) {
        pthread_mutex_unlock(&g_bs.lock);
        LOG_FAIL("binary_staleness",
                 "os_proc_exe_path() failed: %s", strerror(errno));
    }
    bs_strip_deleted_suffix(resolved);
    snprintf(g_bs.exe_path, sizeof(g_bs.exe_path), "%s", resolved);

    unsigned char digest[32];
    if (!bs_hash_running_image(digest)) {
        pthread_mutex_unlock(&g_bs.lock);
        LOG_FAIL("binary_staleness",
                 "failed to hash running image via /proc/self/exe: %s",
                 strerror(errno));
    }
    memcpy(g_bs.boot_digest, digest, sizeof(digest));
    zcl_hex_encode(digest, sizeof(digest), g_bs.boot_digest_hex);

    struct platform_positioned_file named;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&named);
    if (platform_positioned_file_open(&named, g_bs.exe_path) &&
        platform_positioned_file_snapshot(&named, &snapshot) &&
        snapshot.size <= INT64_MAX) {
        g_bs.boot_mtime = snapshot.modified_seconds;
        g_bs.boot_size  = (int64_t)snapshot.size;
        g_bs.last_probe_mtime = g_bs.boot_mtime;
        g_bs.last_probe_size  = g_bs.boot_size;
        g_bs.last_probe_volume = snapshot.volume;
        g_bs.last_probe_file_low = snapshot.file_low;
        g_bs.last_probe_file_high = snapshot.file_high;
        g_bs.last_probe_identity_valid = true;
        g_bs.probed_once = true;
        g_bs.path_valid = true;
    } else {
        /* Rare: the file already vanished between exec() and this call.
         * The running-image hash above is still valid; ticks simply have
         * nothing to compare against yet until the path resolves again. */
        g_bs.boot_mtime = -1;
        g_bs.boot_size  = -1;
        g_bs.last_probe_identity_valid = false;
        g_bs.probed_once = false;
        g_bs.path_valid = false;
        LOG_WARN("binary_staleness",
                 "open/metadata(%s) failed at boot capture: %s (staleness checks "
                 "will retry on tick)", g_bs.exe_path, strerror(errno));
    }
    platform_positioned_file_close(&named);

    g_bs.boot_captured = true;
    pthread_mutex_unlock(&g_bs.lock);
    return true;
}

/* ── Check cycle ────────────────────────────────────────────── */

bool binary_staleness_check_now(void)
{
    pthread_mutex_lock(&g_bs.lock);
    if (!g_bs.boot_captured) {
        pthread_mutex_unlock(&g_bs.lock);
        return false;
    }

    int64_t cur_mtime = 0, cur_size = 0;
    unsigned char probe_digest[32] = {0};
    bool digest_known = false;

#ifdef ZCL_TESTING
    if (g_bs.test_probe_override_active) {
        memcpy(probe_digest, g_bs.test_probe_digest, sizeof(probe_digest));
        cur_mtime = g_bs.test_probe_mtime;
        cur_size  = g_bs.test_probe_size;
        digest_known = true;
        g_bs.path_valid = true;
    }
#endif
    if (!digest_known) {
        struct platform_positioned_file named;
        struct platform_positioned_file_snapshot before;
        platform_positioned_file_init(&named);
        if (!platform_positioned_file_open(&named, g_bs.exe_path) ||
            !platform_positioned_file_snapshot(&named, &before) ||
            before.size > INT64_MAX) {
            platform_positioned_file_close(&named);
            g_bs.probe_failures++;
            g_bs.path_valid = false;
            g_bs.check_count++;
            g_bs.last_check_unix = (int64_t)platform_time_wall_time_t();
            bool stale_now = atomic_load(&g_bs.atomic_stale);
            pthread_mutex_unlock(&g_bs.lock);
            return stale_now;
        }
        cur_mtime = before.modified_seconds;
        cur_size  = (int64_t)before.size;
        g_bs.path_valid = true;
        bool changed = !g_bs.probed_once ||
                       cur_mtime != g_bs.last_probe_mtime ||
                       cur_size != g_bs.last_probe_size ||
                       !g_bs.last_probe_identity_valid ||
                       before.volume != g_bs.last_probe_volume ||
                       before.file_low != g_bs.last_probe_file_low ||
                       before.file_high != g_bs.last_probe_file_high;
        if (!changed) {
            platform_positioned_file_close(&named);
            g_bs.check_count++;
            g_bs.last_check_unix = (int64_t)platform_time_wall_time_t();
            bool stale_now = atomic_load(&g_bs.atomic_stale);
            pthread_mutex_unlock(&g_bs.lock);
            return stale_now;
        }
        struct platform_positioned_file_snapshot after;
        if (!bs_hash_positioned(&named, before.size, probe_digest) ||
            !platform_positioned_file_snapshot(&named, &after) ||
            !bs_snapshot_equal(&before, &after)) {
            platform_positioned_file_close(&named);
            g_bs.probe_failures++;
            bool stale_now = atomic_load(&g_bs.atomic_stale);
            pthread_mutex_unlock(&g_bs.lock);
            return stale_now;
        }
        platform_positioned_file_close(&named);
        g_bs.last_probe_volume = after.volume;
        g_bs.last_probe_file_low = after.file_low;
        g_bs.last_probe_file_high = after.file_high;
        g_bs.last_probe_identity_valid = true;
        g_bs.rehash_count++;
    }

    g_bs.check_count++;
    g_bs.last_check_unix = (int64_t)platform_time_wall_time_t();

    bool changed = !g_bs.probed_once ||
                   cur_mtime != g_bs.last_probe_mtime ||
                   cur_size  != g_bs.last_probe_size;
    if (!changed && digest_known) {
        bool stale_now = atomic_load(&g_bs.atomic_stale);
        pthread_mutex_unlock(&g_bs.lock);
        return stale_now;
    }

    g_bs.last_probe_mtime = cur_mtime;
    g_bs.last_probe_size  = cur_size;
    g_bs.probed_once = true;
    memcpy(g_bs.last_disk_digest, probe_digest, sizeof(probe_digest));
    zcl_hex_encode(probe_digest, sizeof(probe_digest), g_bs.last_disk_digest_hex);

    bool new_stale = memcmp(probe_digest, g_bs.boot_digest,
                            sizeof(probe_digest)) != 0;
    bool prev_stale = atomic_load(&g_bs.atomic_stale);
    atomic_store(&g_bs.atomic_stale, new_stale);
    if (new_stale && !prev_stale)
        g_bs.stale_transitions++;

    char running_short[13], disk_short[13];
    snprintf(running_short, sizeof(running_short), "%.12s", g_bs.boot_digest_hex);
    snprintf(disk_short, sizeof(disk_short), "%.12s", g_bs.last_disk_digest_hex);
    char exe_path_copy[sizeof(g_bs.exe_path)];
    snprintf(exe_path_copy, sizeof(exe_path_copy), "%s", g_bs.exe_path);
    int64_t mtime_copy = cur_mtime, size_copy = cur_size;

    pthread_mutex_unlock(&g_bs.lock);

    if (new_stale != prev_stale) {
        if (new_stale) {
            struct blocker_record rec;
            char reason[BLOCKER_REASON_MAX];
            snprintf(reason, sizeof(reason),
                     "running=%s on_disk=%s path=%.100s mtime=%lld size=%lld "
                     "— on-disk binary was replaced; restart the service "
                     "to pick up the deployed build",
                     running_short, disk_short, exe_path_copy,
                     (long long)mtime_copy, (long long)size_copy);
            blocker_init(&rec, BINARY_STALENESS_BLOCKER_ID,
                        BINARY_STALENESS_OWNER, BLOCKER_TRANSIENT, reason);
            blocker_set(&rec);
        } else {
            blocker_clear(BINARY_STALENESS_BLOCKER_ID);
        }
    }

    return new_stale;
}

/* ── Thread loop ────────────────────────────────────────────── */

static void *bs_thread_fn(void *arg)
{
    (void)arg;
    int poll_seconds;

    pthread_mutex_lock(&g_bs.lock);
    poll_seconds = g_bs.poll_seconds;
    pthread_mutex_unlock(&g_bs.lock);

    struct timespec now;
    platform_time_monotonic_timespec(&now);
    int64_t now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    int64_t next_at_ms = now_ms + (int64_t)poll_seconds * 1000;

    while (true) {
        pthread_mutex_lock(&g_bs.lock);
        bool stop = g_bs.stop_requested;
        pthread_mutex_unlock(&g_bs.lock);
        if (stop) break;

        atomic_fetch_add(&g_bs.loop_ticks, 1);
        bs_supervisor_heartbeat();

        platform_time_monotonic_timespec(&now);
        now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
        if (now_ms >= next_at_ms) {
            binary_staleness_check_now();
            pthread_mutex_lock(&g_bs.lock);
            poll_seconds = g_bs.poll_seconds;
            pthread_mutex_unlock(&g_bs.lock);
            next_at_ms = now_ms + (int64_t)poll_seconds * 1000;
        }
        platform_sleep_ms(100);
    }

    pthread_mutex_lock(&g_bs.lock);
    g_bs.thread_running = false;
    pthread_mutex_unlock(&g_bs.lock);
    return NULL;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result binary_staleness_start(
    const struct binary_staleness_config *cfg)
{
    struct binary_staleness_config resolved;
    if (cfg) {
        resolved = *cfg;
    } else {
        binary_staleness_config_defaults(&resolved);
    }
    if (resolved.poll_seconds <= 0)
        resolved.poll_seconds = BINARY_STALENESS_DEFAULT_POLL_SECONDS;

    pthread_mutex_lock(&g_bs.lock);
    if (g_bs.thread_running) {
        pthread_mutex_unlock(&g_bs.lock);
        return ZCL_ERR(-1, "binary_staleness_start: already running");
    }
    g_bs.poll_seconds = resolved.poll_seconds;
    pthread_mutex_unlock(&g_bs.lock);

    if (!binary_staleness_capture_boot_stamp())
        return ZCL_ERR(-2, "binary_staleness_start: boot capture failed");

    /* Synchronous first tick so a caller can read a real status right
     * after start returns, same as disk_monitor's first synchronous
     * poll — with an unchanged baseline this is a stat() only, no hash. */
    binary_staleness_check_now();

    pthread_mutex_lock(&g_bs.lock);
    g_bs.stop_requested = false;
    g_bs.thread_running = true;
    int rc = thread_registry_spawn("zcl_binary_staleness", bs_thread_fn,
                                   NULL, &g_bs.thread);
    if (rc != 0) {
        g_bs.thread_running = false;
        pthread_mutex_unlock(&g_bs.lock);
        return ZCL_ERR(-3, "binary_staleness_start: thread_registry_spawn "
                       "failed (%d)", rc);
    }
    pthread_mutex_unlock(&g_bs.lock);

    struct zcl_result sup_r = bs_register_supervisor();
    if (!sup_r.ok) {
        binary_staleness_stop();
        return sup_r;
    }
    return ZCL_OK;
}

void binary_staleness_stop(void)
{
    pthread_t th;
    bool joinable = false;

    supervisor_child_id id = atomic_load(&g_bs.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);

    pthread_mutex_lock(&g_bs.lock);
    if (g_bs.thread_running) {
        g_bs.stop_requested = true;
        th = g_bs.thread;
        joinable = true;
    }
    pthread_mutex_unlock(&g_bs.lock);

    if (joinable) {
        pthread_join(th, NULL);
        pthread_mutex_lock(&g_bs.lock);
        g_bs.thread_running = false;
        g_bs.stop_requested = false;
        pthread_mutex_unlock(&g_bs.lock);
    }
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_bs.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}

/* ── Status / queries ───────────────────────────────────────── */

void binary_staleness_status_snapshot(struct binary_staleness_status *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_bs.lock);
    out->running        = g_bs.thread_running;
    out->boot_captured  = g_bs.boot_captured;
    out->stale          = atomic_load(&g_bs.atomic_stale);
    out->path_valid     = g_bs.path_valid;
    snprintf(out->exe_path, sizeof(out->exe_path), "%s", g_bs.exe_path);
    snprintf(out->boot_digest_hex, sizeof(out->boot_digest_hex),
             "%s", g_bs.boot_digest_hex);
    snprintf(out->last_disk_digest_hex, sizeof(out->last_disk_digest_hex),
             "%s", g_bs.last_disk_digest_hex);
    out->boot_mtime        = g_bs.boot_mtime;
    out->boot_size         = g_bs.boot_size;
    out->last_probe_mtime  = g_bs.last_probe_mtime;
    out->last_probe_size   = g_bs.last_probe_size;
    out->last_check_unix   = g_bs.last_check_unix;
    out->check_count       = g_bs.check_count;
    out->rehash_count      = g_bs.rehash_count;
    out->stale_transitions = g_bs.stale_transitions;
    out->probe_failures    = g_bs.probe_failures;
    pthread_mutex_unlock(&g_bs.lock);
}

bool binary_staleness_is_stale(void)
{
    return atomic_load(&g_bs.atomic_stale);
}

/* `binary_staleness` — folded into the existing `boot` dumpstate
 * subsystem (see chain_restore_dump_state_json). Reentrant-safe (the
 * snapshot takes the brief status lock). See CLAUDE.md "Adding state
 * introspection". */
bool binary_staleness_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct binary_staleness_status st;
    binary_staleness_status_snapshot(&st);

    json_push_kv_bool(out, "running", st.running);
    json_push_kv_bool(out, "boot_captured", st.boot_captured);
    json_push_kv_bool(out, "stale", st.stale);
    json_push_kv_bool(out, "path_valid", st.path_valid);
    json_push_kv_str (out, "exe_path", st.exe_path);
    json_push_kv_str (out, "boot_digest_hex", st.boot_digest_hex);
    json_push_kv_str (out, "last_disk_digest_hex", st.last_disk_digest_hex);
    json_push_kv_int (out, "boot_mtime", st.boot_mtime);
    json_push_kv_int (out, "boot_size", st.boot_size);
    json_push_kv_int (out, "last_probe_mtime", st.last_probe_mtime);
    json_push_kv_int (out, "last_probe_size", st.last_probe_size);
    json_push_kv_int (out, "last_check_unix", st.last_check_unix);
    json_push_kv_int (out, "check_count", st.check_count);
    json_push_kv_int (out, "rehash_count", st.rehash_count);
    json_push_kv_int (out, "stale_transitions", st.stale_transitions);
    json_push_kv_int (out, "probe_failures", st.probe_failures);
    return true;
}

/* ── Test hooks ────────────────────────────────────────────── */

#ifdef ZCL_TESTING
void binary_staleness_reset_for_testing(void)
{
    pthread_mutex_lock(&g_bs.lock);
    memset(&g_bs.boot_captured, 0,
           sizeof(g_bs) - offsetof(struct bs_state, boot_captured));
    /* memset above zeroed everything from boot_captured through the end
     * of the struct, including the lock-adjacent fields we want reset —
     * the pthread_mutex_t itself (declared before boot_captured) is left
     * untouched, so the lock stays valid. Re-seed the non-zero defaults. */
    g_bs.boot_mtime = -1;
    g_bs.boot_size = -1;
    g_bs.last_probe_mtime = -1;
    g_bs.last_probe_size = -1;
    atomic_store(&g_bs.atomic_stale, false);
    atomic_store(&g_bs.supervisor_id, SUPERVISOR_INVALID_ID);
    atomic_store(&g_bs.loop_ticks, 0);
    pthread_mutex_unlock(&g_bs.lock);
    blocker_clear(BINARY_STALENESS_BLOCKER_ID);
}

void binary_staleness_test_force_boot_stamp(const char *digest_hex,
                                            int64_t mtime, int64_t size,
                                            const char *path)
{
    unsigned char digest[32];
    if (!zcl_hex_decode(digest_hex, digest, 32)) {
        LOG_WARN("binary_staleness",
                 "test_force_boot_stamp: invalid digest_hex (want 64 hex "
                 "chars): %s", digest_hex ? digest_hex : "(null)");
        return;
    }
    pthread_mutex_lock(&g_bs.lock);
    memcpy(g_bs.boot_digest, digest, sizeof(digest));
    zcl_hex_encode(digest, sizeof(digest), g_bs.boot_digest_hex);
    g_bs.boot_mtime = mtime;
    g_bs.boot_size = size;
    g_bs.last_probe_mtime = mtime;
    g_bs.last_probe_size = size;
    g_bs.probed_once = true;
    g_bs.path_valid = true;
    snprintf(g_bs.exe_path, sizeof(g_bs.exe_path), "%s",
            path ? path : "(test)");
    g_bs.boot_captured = true;
    g_bs.test_boot_override_active = true;
    atomic_store(&g_bs.atomic_stale, false);
    pthread_mutex_unlock(&g_bs.lock);
}

void binary_staleness_test_force_probe(const char *digest_hex,
                                       int64_t mtime, int64_t size)
{
    unsigned char digest[32];
    if (!zcl_hex_decode(digest_hex, digest, 32)) {
        LOG_WARN("binary_staleness",
                 "test_force_probe: invalid digest_hex (want 64 hex "
                 "chars): %s", digest_hex ? digest_hex : "(null)");
        return;
    }
    pthread_mutex_lock(&g_bs.lock);
    memcpy(g_bs.test_probe_digest, digest, sizeof(digest));
    g_bs.test_probe_mtime = mtime;
    g_bs.test_probe_size = size;
    g_bs.test_probe_override_active = true;
    pthread_mutex_unlock(&g_bs.lock);
}

void binary_staleness_test_clear_probe_override(void)
{
    pthread_mutex_lock(&g_bs.lock);
    g_bs.test_probe_override_active = false;
    pthread_mutex_unlock(&g_bs.lock);
}
#endif
