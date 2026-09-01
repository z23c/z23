/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_bundle_admission.c — receipt-gated ROM catalog admission. Contract +
 * threat model: config/rom_bundle_admission.h. */

#include "config/rom_bundle_admission.h"

#include "config/consensus_state_replay_receipt.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "net/rom_seed.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"

#if defined(_WIN32)

#include <stdio.h>

enum rom_bundle_admission_result rom_bundle_admission_register(
    const char *dir, const char *filename, struct rom_artifact *out)
{
    (void)dir;
    (void)filename;
    (void)out;
    fprintf(stderr,
            "REFUSED: ROM bundle admission is unavailable on Windows until "
            "scan, hash, receipt, and registration share one validated "
            "directory capability\n");
    return ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT;
}

int rom_bundle_admission_scan(const char *dir)
{
    (void)dir;
    return 0;
}

void rom_bundle_admission_start_scan(const char *dir)
{
    (void)dir;
}

void rom_bundle_admission_stop_scan(void) { }

#else

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#define RBA_SUBSYS "rom_bundle_admission"

/* Never walk more directory entries than rom_seed's own scan bound. */
#define RBA_SCAN_ENTRY_CAP 4096

/* A registerable filename is a bare basename: no separators, no traversal,
 * non-empty. Same rule net/rom_seed.c's rom_filename_ok enforces (duplicated
 * here rather than exported — it is a one-line guard and this module must
 * validate BEFORE its own I/O, ahead of ever calling into rom_seed). */
static bool rba_filename_ok(const char *filename)
{
    if (!filename || !filename[0])
        return false;
    if (strchr(filename, '/'))
        return false;
    if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
        return false;
    if (strstr(filename, ".."))
        return false;
    return true;
}

/* Whole-file SHA3-256, streamed in fixed chunks — independent of rom_seed's
 * own registration-time digest pass so the receipt gate can be evaluated
 * BEFORE anything is written into the shared, concurrently-served registry. */
static bool rba_sha3_file(const char *path, uint8_t out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_WARN(RBA_SUBSYS, "hash: open '%s' failed errno=%d", path, errno);
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[65536];
    bool ok = true;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            sha3_256_write(&ctx, buf, (size_t)n);
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        LOG_WARN(RBA_SUBSYS, "hash: read '%s' failed errno=%d", path, errno);
        ok = false;
        break;
    }
    close(fd);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, out);
    return true;
}

enum rom_bundle_admission_result rom_bundle_admission_register(
    const char *dir, const char *filename, struct rom_artifact *out)
{
    if (!dir || !dir[0] || !rba_filename_ok(filename)) {
        LOG_WARN(RBA_SUBSYS, "register: bad args (dir/filename)");
        return ROM_BUNDLE_ADMIT_ERR_ARGS;
    }

    if (rom_seed_classify(filename) != ROM_ARTIFACT_CONSENSUS_BUNDLE) {
        LOG_WARN(RBA_SUBSYS, "register: '%s' does not classify as a "
                             "consensus-state bundle; receipt-gated admission "
                             "only applies to that artifact kind", filename);
        return ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE;
    }

    char path[1024];
    int pn = snprintf(path, sizeof(path), "%s/%s", dir, filename);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) {
        LOG_WARN(RBA_SUBSYS, "register: path overflow for '%s'", filename);
        return ROM_BUNDLE_ADMIT_ERR_ARGS;
    }

    uint8_t digest[32];
    if (!rba_sha3_file(path, digest))
        return ROM_BUNDLE_ADMIT_ERR_HASH;

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        LOG_WARN(RBA_SUBSYS, "register: opendir '%s' failed errno=%d", dir,
                 errno);
        return ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT;
    }
    struct consensus_state_replay_receipt_binding binding;
    bool bound = consensus_state_replay_receipt_bundle_binding_verified(
        dir_fd, digest, &binding);
    close(dir_fd);

    if (!bound) {
        LOG_WARN(RBA_SUBSYS, "register: '%s' refused — no valid replay "
                             "receipt bound to this exact bundle content "
                             "(fail-closed: no receipt, no serve)", filename);
        return ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT;
    }

    enum rom_register_result rc =
        rom_seed_register(dir, filename, digest, out);
    if (rc != ROM_REG_OK) {
        LOG_WARN(RBA_SUBSYS, "register: '%s' passed the receipt gate but "
                             "rom_seed_register refused (rc=%d)", filename,
                             (int)rc);
        return ROM_BUNDLE_ADMIT_ERR_REGISTER;
    }

    char digest_hex[65];
    HexStr(digest, 32, false, digest_hex, sizeof(digest_hex));
    LOG_INFO(RBA_SUBSYS, "admitted '%s' digest=%s height=%d utxo=%llu "
                         "anchors=%llu nullifiers=%llu (receipt-verified)",
             filename, digest_hex, binding.height,
             (unsigned long long)binding.utxo_count,
             (unsigned long long)binding.anchor_count,
             (unsigned long long)binding.nullifier_count);
    return ROM_BUNDLE_ADMIT_OK;
}

int rom_bundle_admission_scan(const char *dir)
{
    if (!dir || !dir[0]) {
        LOG_WARN(RBA_SUBSYS, "scan: empty dir");
        return 0;
    }
    DIR *d = opendir(dir);
    if (!d) {
        LOG_WARN(RBA_SUBSYS, "scan: opendir '%s' failed errno=%d", dir, errno);
        return 0;
    }

    int admitted = 0;
    unsigned seen = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (++seen > RBA_SCAN_ENTRY_CAP)
            break;
        if (rom_seed_classify(e->d_name) != ROM_ARTIFACT_CONSENSUS_BUNDLE)
            continue;
        if (rom_bundle_admission_register(dir, e->d_name, NULL) ==
            ROM_BUNDLE_ADMIT_OK)
            admitted++;
    }
    closedir(d);

    if (admitted > 0)
        LOG_INFO(RBA_SUBSYS, "scan: admitted %d bundle(s) from '%s'",
                 admitted, dir);
    return admitted;
}

/* ── Background scan lifecycle (mirrors net/rom_seed.c's scan thread) ──── */

static pthread_t g_scan_thread;
static bool      g_scan_started = false;
static char      g_scan_dir[1024];
static pthread_mutex_t g_scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct thread_liveness_child g_scan_liveness = { .id = SUPERVISOR_INVALID_ID };

static void *rba_scan_thread(void *arg)
{
    (void)arg;
    char dir[1024];
    pthread_mutex_lock(&g_scan_mutex);
    snprintf(dir, sizeof(dir), "%s", g_scan_dir);
    pthread_mutex_unlock(&g_scan_mutex);

    int admitted = rom_bundle_admission_scan(dir);

    /* Single-shot worker — the scan above IS its one dispatch. */
    thread_liveness_beat(&g_scan_liveness, admitted);
    return NULL;
}

void rom_bundle_admission_start_scan(const char *dir)
{
    if (!dir || !dir[0])
        return;
    pthread_mutex_lock(&g_scan_mutex);
    if (g_scan_started) {
        pthread_mutex_unlock(&g_scan_mutex);
        return;
    }
    snprintf(g_scan_dir, sizeof(g_scan_dir), "%s", dir);
    if (thread_registry_spawn("zcl_rombundleadmit", rba_scan_thread, NULL,
                              &g_scan_thread) == 0) {
        g_scan_started = true;
        thread_liveness_register(&g_scan_liveness, "zcl_rombundleadmit", 0, 0);
    } else {
        LOG_WARN(RBA_SUBSYS, "start_scan: failed to spawn scan thread");
    }
    pthread_mutex_unlock(&g_scan_mutex);
}

void rom_bundle_admission_stop_scan(void)
{
    pthread_t t;
    bool have = false;
    pthread_mutex_lock(&g_scan_mutex);
    if (g_scan_started) {
        t = g_scan_thread;
        g_scan_started = false;
        have = true;
    }
    pthread_mutex_unlock(&g_scan_mutex);
    if (!have)
        return;
    /* Single-shot: the scan itself is bounded (RBA_SCAN_ENTRY_CAP entries,
     * each a bounded whole-file hash) and does not poll a cancel flag — join
     * runs it to completion, mirroring rom_seed_stop_scan's shape for a
     * worker whose one dispatch is already in flight rather than looping. */
    pthread_join(t, NULL);
    thread_liveness_retire(&g_scan_liveness);
}

#endif
