/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact seeding registry + free-tier serve policy + caps. See
 * net/rom_seed.h for the contract and trust model.
 *
 * Everything wire- or disk-derived is bounded and validated here. Registration
 * re-derives every digest from the bytes on disk in one pass (never a sidecar).
 * The serve caps are in-memory DDoS bounds only — nothing here is persisted or
 * a consensus predicate. */
#include "rom_seed_internal.h"

#include "platform/time_compat.h"
#include "platform/positioned_file.h"
#include "net/rom_seed.h"
#include "net/file_market.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define ROM_SUBSYS "rom_seed"
/* ROM_SEED_SCAN_ENTRY_CAP lives in net/rom_seed.h — see the note there.
 * Measured 2026-08-19: the canonical node's datadir root held 5,686 entries
 * with block_index.bin at readdir position 4,499, so a silent cap of 4,096
 * hid the header seed from every fresh node and the C3 instant-on install
 * could never arm. See rom_seed_exact_names in
 * rom_seed_classify.c. */

/* ── Registry ───────────────────────────────────────────────────────── */
static struct rom_artifact g_artifacts[ROM_SEED_MAX_ARTIFACTS];
static pthread_mutex_t g_reg_mutex = PTHREAD_MUTEX_INITIALIZER;
/* ── Config (read from serve threads; set at boot) ──────────────────── */
static _Atomic bool     g_enabled = true;
static _Atomic uint32_t g_max_inflight_per_peer = ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER;
static _Atomic uint64_t g_peer_bps_cap   = ROM_SEED_DEFAULT_PEER_BPS_CAP;
static _Atomic uint64_t g_global_bps_cap = ROM_SEED_DEFAULT_GLOBAL_BPS_CAP;
/* ── Caps + stats state (one mutex) ─────────────────────────────────── */
struct rom_peer_stat {
    uint8_t  ip[16];
    bool     used;
    bool     ever_served;
    uint32_t concurrent;   /* active in-flight serves for this peer   */
    int64_t  win_start;    /* rolling 1-second byte-rate window start  */
    uint64_t win_bytes;    /* bytes charged in the current window      */
    int64_t  last_seen;    /* LRU eviction when the table is full      */
};
static struct rom_peer_stat g_peers[ROM_SEED_PEER_TABLE_CAP];
static pthread_mutex_t g_caps_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t  g_global_win_start = 0;
static uint64_t g_global_win_bytes = 0;

/* ── Background scan lifecycle ──────────────────────────────────────── */
static pthread_t g_scan_thread;
static bool      g_scan_started = false;
static uint16_t  g_scan_fs_port = 0;
static char      g_scan_datadir[1024];
static _Atomic bool g_scan_cancel = false;
static pthread_mutex_t g_scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct thread_liveness_child g_scan_liveness = { .id = SUPERVISOR_INVALID_ID };

static uint64_t g_chunks_served = 0;
static uint64_t g_bytes_served_total = 0;
static uint64_t g_unique_peers_served = 0;

/* ── Registration ───────────────────────────────────────────────────── */

/* Insert (or replace by filename) into the registry. Caller holds g_reg_mutex.
 * Returns the slot index, or -1 if full. */
static int reg_slot_locked(const char *filename)
{
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
        if (g_artifacts[i].used &&
            strcmp(g_artifacts[i].filename, filename) == 0)
            return (int)i;
    }
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
        if (!g_artifacts[i].used)
            return (int)i;
    }
    return -1;
}

enum rom_register_result rom_seed_register(const char *datadir,
                                           const char *filename,
                                           const uint8_t *expected_whole_sha3,
                                           struct rom_artifact *out)
{
    if (!datadir || !datadir[0] || !rom_filename_ok(filename)) {
        LOG_WARN(ROM_SUBSYS, "register: bad args (datadir/filename)");
        return ROM_REG_ERR_ARGS;
    }

    enum rom_artifact_kind kind = rom_seed_classify(filename);
    if (kind == ROM_ARTIFACT_UNKNOWN) {
        LOG_WARN(ROM_SUBSYS, "register: unknown kind for '%s'", filename);
        return ROM_REG_ERR_UNKNOWN_KIND;
    }

    char path[1024];
    int pn = snprintf(path, sizeof(path), "%s/%s", datadir, filename);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) {
        LOG_WARN(ROM_SUBSYS, "register: path overflow for '%s'", filename);
        return ROM_REG_ERR_ARGS;
    }

    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, datadir, filename)) {
        LOG_WARN(ROM_SUBSYS, "register: validated open '%s' failed", path);
        return ROM_REG_ERR_NOT_FOUND;
    }

    struct platform_positioned_file_snapshot snapshot;
    if (!platform_positioned_file_snapshot(&file, &snapshot)) {
        platform_positioned_file_close(&file);
        LOG_WARN(ROM_SUBSYS, "register: snapshot '%s' failed / not a file", path);
        return ROM_REG_ERR_NOT_FOUND;
    }
    uint64_t size_bytes = snapshot.size;
    if (size_bytes < ROM_SEED_MIN_ARTIFACT_BYTES) {
        platform_positioned_file_close(&file);
        LOG_WARN(ROM_SUBSYS, "register: '%s' too small (%llu bytes)",
                 filename, (unsigned long long)size_bytes);
        return ROM_REG_ERR_TOO_SMALL;
    }
    if (size_bytes > ROM_SEED_MAX_ARTIFACT_BYTES) {
        platform_positioned_file_close(&file);
        LOG_WARN(ROM_SUBSYS, "register: '%s' too large (%llu bytes)",
                 filename, (unsigned long long)size_bytes);
        return ROM_REG_ERR_TOO_LARGE;
    }

    uint32_t num_chunks =
        (uint32_t)((size_bytes + ROM_SEED_CHUNK_SIZE - 1) / ROM_SEED_CHUNK_SIZE);
    if (num_chunks == 0 || num_chunks > ROM_SEED_MAX_CHUNKS) {
        platform_positioned_file_close(&file);
        LOG_WARN(ROM_SUBSYS, "register: '%s' chunk count %u out of range",
                 filename, num_chunks);
        return ROM_REG_ERR_TOO_LARGE;
    }

    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_seed_reg_buf");
    if (!buf) {
        platform_positioned_file_close(&file);
        LOG_WARN(ROM_SUBSYS, "register: alloc chunk buffer failed");
        return ROM_REG_ERR_IO;
    }

    struct rom_artifact art;
    memset(&art, 0, sizeof(art));
    art.kind = kind;
    snprintf(art.filename, sizeof(art.filename), "%s", filename);
    art.size_bytes = size_bytes;
    art.chunk_size = ROM_SEED_CHUNK_SIZE;
    art.num_chunks = num_chunks;

    struct sha3_256_ctx whole_ctx;
    sha3_256_init(&whole_ctx);
    struct sha3_256_ctx root_ctx;   /* absorbs each per-chunk digest */
    sha3_256_init(&root_ctx);

    enum rom_register_result rc = ROM_REG_OK;
    uint64_t total_read = 0;
    for (uint32_t ci = 0; ci < num_chunks; ci++) {
        /* Read exactly one chunk (short only for the final chunk). */
        uint32_t want = ROM_SEED_CHUNK_SIZE;
        uint64_t remaining = size_bytes - total_read;
        if (remaining < want)
            want = (uint32_t)remaining;

        uint32_t got = 0;
        while (got < want) {
            int64_t r = platform_positioned_file_read(
                &file, buf + got, want - got, total_read + got);
            if (r < 0) {
                rc = ROM_REG_ERR_IO;
                break;
            }
            if (r == 0) { /* unexpected EOF vs stat size → corrupt */
                rc = ROM_REG_ERR_CORRUPT;
                break;
            }
            got += (uint32_t)r;
        }
        if (rc != ROM_REG_OK)
            break;

        /* Content check on the first bytes of chunk 0. */
        if (ci == 0 &&
            !rom_seed_kind_content_ok(kind, buf, got < 16 ? got : 16,
                                      size_bytes)) {
            rc = ROM_REG_ERR_CORRUPT;
            break;
        }

        sha3_256_write(&whole_ctx, buf, got);
        sha3_256(buf, got, art.chunk_sha3[ci]);
        sha3_256_write(&root_ctx, art.chunk_sha3[ci], 32);
        total_read += got;
    }

    free(buf);
    platform_positioned_file_close(&file);

    if (rc != ROM_REG_OK) {
        LOG_WARN(ROM_SUBSYS, "register: '%s' failed rc=%d", filename, (int)rc);
        return rc;
    }

    sha3_256_finalize(&whole_ctx, art.whole_sha3);
    sha3_256_finalize(&root_ctx, art.chunk_root);

    if (expected_whole_sha3 &&
        memcmp(art.whole_sha3, expected_whole_sha3, 32) != 0) {
        LOG_WARN(ROM_SUBSYS, "register: '%s' whole-file digest mismatch "
                 "(corrupt / not the expected artifact)", filename);
        return ROM_REG_ERR_CORRUPT;
    }

    art.registered_at = (int64_t)platform_time_wall_time_t();
    art.used = true;

    pthread_mutex_lock(&g_reg_mutex);
    int slot = reg_slot_locked(filename);
    if (slot < 0) {
        pthread_mutex_unlock(&g_reg_mutex);
        LOG_WARN(ROM_SUBSYS, "register: registry full (%u), dropping '%s'",
                 ROM_SEED_MAX_ARTIFACTS, filename);
        return ROM_REG_ERR_FULL;
    }
    g_artifacts[slot] = art;
    pthread_mutex_unlock(&g_reg_mutex);

    if (out)
        *out = art;

    char root_hex[65];
    HexStr(art.chunk_root, 32, false, root_hex, sizeof(root_hex));
    LOG_INFO(ROM_SUBSYS, "registered '%s' size=%llu chunks=%u root=%s",
             filename, (unsigned long long)art.size_bytes, art.num_chunks,
             root_hex);
    return ROM_REG_OK;
}

/* Bare basename of a registerable name: "bundles/foo.sqlite" -> "foo.sqlite",
 * "foo.sqlite" -> "foo.sqlite". Pure — mirrors the basename rule the classifier
 * uses so deregister matches an entry regardless of which shape it was
 * registered under. */
static const char *rom_basename(const char *name)
{
    const char *slash = strrchr(name, '/');
    return slash ? slash + 1 : name;
}

enum rom_register_result rom_seed_deregister(const char *datadir,
                                             const char *filename)
{
    if (!datadir || !datadir[0] || !rom_filename_ok(filename)) {
        LOG_WARN(ROM_SUBSYS, "deregister: bad args (datadir/filename)");
        return ROM_REG_ERR_ARGS;
    }
    const char *want = rom_basename(filename);
    pthread_mutex_lock(&g_reg_mutex);
    /* Match by bare basename so either the "bundles/<name>" reseed shape or a
     * plain basename resolves the same entry. The registry is tiny
     * (ROM_SEED_MAX_ARTIFACTS) and heights are unique, so at most one slot
     * matches; the loop still clears every match to stay idempotent. */
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
        if (g_artifacts[i].used &&
            strcmp(rom_basename(g_artifacts[i].filename), want) == 0) {
            LOG_INFO(ROM_SUBSYS, "deregistered '%s' (matched '%s')",
                     g_artifacts[i].filename, filename);
            memset(&g_artifacts[i], 0, sizeof(g_artifacts[i]));
        }
    }
    pthread_mutex_unlock(&g_reg_mutex);
    return ROM_REG_OK; /* idempotent: OK whether or not a slot matched */
}

/* Bounded scan of <datadir>/ROM_SEED_BUNDLES_SUBDIR ("bundles/"): register
 * every entry whose bare basename classifies as a known artifact kind,
 * storing the registered filename as "bundles/<name>" so rom_seed_read_chunk's
 * "<datadir>/<filename>" resolution finds it on disk. This is where
 * boot_bundle_fetch.c lands verified swarm downloads and where the unified
 * installer deliberately RETAINS the source .sqlite after install (its only
 * unlinkat removes a stale prior-generation OUTPUT artifact, never the
 * source) — so a bundle this node fetched or installed from keeps seeding the
 * swarm. Absence of the bundles/ subdirectory (most nodes, most of the time)
 * is normal, not an error — no LOG_WARN on ENOENT. Bounded by the same
 * per-directory entry cap + ROM_SEED_MAX_ARTIFACTS as the root scan. */
/* The entry cap fired. An artifact this node holds may be sitting past it, so
 * the short list is a measurement failure, not an inventory — say which
 * directory and how far the walk got instead of returning quietly. */
static void rom_seed_scan_capped(const char *dirpath, unsigned seen)
{
    LOG_WARN(ROM_SUBSYS,
             "scan: '%s' has more than %u entries (stopped after %u) — any "
             "pattern-named artifact past that point was NOT examined and is "
             "not being offered; exactly-named artifacts are unaffected "
             "(they are looked up by name, not walked for)",
             dirpath, (unsigned)ROM_SEED_SCAN_ENTRY_CAP, seen - 1u);
}

static int rom_seed_scan_bundles_subdir(const char *datadir)
{
    char dirpath[1024];
    int dn = snprintf(dirpath, sizeof(dirpath), "%s/%s", datadir,
                      ROM_SEED_BUNDLES_SUBDIR);
    if (dn <= 0 || (size_t)dn >= sizeof(dirpath))
        return 0;

    DIR *d = opendir(dirpath);
    if (!d)
        return 0; /* no bundles/ subdir yet — normal, not an error */

    int registered = 0;
    unsigned seen = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (atomic_load(&g_scan_cancel))
            break;
        if (++seen > ROM_SEED_SCAN_ENTRY_CAP) {
            rom_seed_scan_capped(dirpath, seen);
            break;
        }
        if (rom_seed_classify(e->d_name) == ROM_ARTIFACT_UNKNOWN)
            continue;
        if (rom_seed_count() >= (int)ROM_SEED_MAX_ARTIFACTS)
            break;

        char relname[ROM_SEED_NAME_MAX];
        int rn = snprintf(relname, sizeof(relname), "%s/%s",
                          ROM_SEED_BUNDLES_SUBDIR, e->d_name);
        if (rn <= 0 || (size_t)rn >= sizeof(relname))
            continue;

        if (rom_seed_register(datadir, relname, NULL, NULL) == ROM_REG_OK)
            registered++;
    }
    closedir(d);
    return registered;
}

int rom_seed_scan_datadir(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        LOG_WARN(ROM_SUBSYS, "scan: empty datadir");
        return 0;
    }
    /* Exactly-named artifacts FIRST, by name. A datadir root grows without
     * bound and readdir order is arbitrary, so leaving these to the walk means
     * a node silently stops offering one the day its datadir gets big enough —
     * which is exactly how the header seed went missing. Registration replaces
     * by filename, so finding the same name again in the walk below is a
     * no-op. */
    int registered = 0;
    for (size_t i = 0; i < rom_seed_exact_name_count; i++) {
        if (rom_seed_count() >= (int)ROM_SEED_MAX_ARTIFACTS)
            break;
        /* Absent is the normal case on a node that has never synced — check
         * before asking to register, so an ordinary fresh datadir does not
         * warn about a file it was never supposed to have. */
        char probe[1024];
        int pn = snprintf(probe, sizeof(probe), "%s/%s", datadir,
                          rom_seed_exact_names[i]);
        struct stat pst;
        if (pn <= 0 || (size_t)pn >= sizeof(probe) || stat(probe, &pst) != 0)
            continue;
        if (rom_seed_register(datadir, rom_seed_exact_names[i], NULL, NULL) ==
            ROM_REG_OK)
            registered++;
    }

    DIR *d = opendir(datadir);
    if (!d) {
        LOG_WARN(ROM_SUBSYS, "scan: opendir '%s' failed errno=%d", datadir, errno);
        return registered;
    }

    unsigned seen = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (atomic_load(&g_scan_cancel))
            break;
        if (++seen > ROM_SEED_SCAN_ENTRY_CAP) {
            rom_seed_scan_capped(datadir, seen);
            break;
        }
        if (rom_seed_classify(e->d_name) == ROM_ARTIFACT_UNKNOWN)
            continue;
        if (rom_seed_is_exact_name(e->d_name))
            continue;   /* already looked up by name above */
        if (rom_seed_count() >= (int)ROM_SEED_MAX_ARTIFACTS)
            break;
        if (rom_seed_register(datadir, e->d_name, NULL, NULL) == ROM_REG_OK)
            registered++;
    }
    closedir(d);

    /* One level into <datadir>/bundles/ — see rom_seed_scan_bundles_subdir. */
    registered += rom_seed_scan_bundles_subdir(datadir);

    if (registered > 0)
        LOG_INFO(ROM_SUBSYS, "scan: registered %d artifact(s) in '%s'",
                 registered, datadir);
    return registered;
}

/* ── Registry queries ───────────────────────────────────────────────── */

void rom_seed_reset(void)
{
    pthread_mutex_lock(&g_reg_mutex);
    memset(g_artifacts, 0, sizeof(g_artifacts));
    pthread_mutex_unlock(&g_reg_mutex);

    pthread_mutex_lock(&g_caps_mutex);
    memset(g_peers, 0, sizeof(g_peers));
    g_global_win_start = 0;
    g_global_win_bytes = 0;
    g_chunks_served = 0;
    g_bytes_served_total = 0;
    g_unique_peers_served = 0;
    pthread_mutex_unlock(&g_caps_mutex);

    /* Restore default config so a serving session (or a test) starts from a
     * known clean slate — enabled, default caps. */
    atomic_store(&g_enabled, true);
    atomic_store(&g_max_inflight_per_peer, ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER);
    atomic_store(&g_peer_bps_cap, ROM_SEED_DEFAULT_PEER_BPS_CAP);
    atomic_store(&g_global_bps_cap, ROM_SEED_DEFAULT_GLOBAL_BPS_CAP);
}

int rom_seed_count(void)
{
    int c = 0;
    pthread_mutex_lock(&g_reg_mutex);
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++)
        if (g_artifacts[i].used) c++;
    pthread_mutex_unlock(&g_reg_mutex);
    return c;
}

int rom_seed_list(struct rom_artifact *out, size_t max)
{
    if (!out || max == 0) return 0;
    int c = 0;
    pthread_mutex_lock(&g_reg_mutex);
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS && (size_t)c < max; i++)
        if (g_artifacts[i].used)
            out[c++] = g_artifacts[i];
    pthread_mutex_unlock(&g_reg_mutex);
    return c;
}

bool rom_seed_find_by_root(const uint8_t root_hash[32], struct rom_artifact *out)
{
    if (!root_hash) return false;
    bool found = false;
    pthread_mutex_lock(&g_reg_mutex);
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
        if (g_artifacts[i].used &&
            memcmp(g_artifacts[i].chunk_root, root_hash, 32) == 0) {
            if (out) *out = g_artifacts[i];
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_reg_mutex);
    return found;
}

bool rom_seed_read_chunk(const struct rom_artifact *a, const char *datadir,
                         uint32_t idx, uint8_t *buf, uint32_t buf_cap,
                         uint32_t *out_sz)
{
    if (!a || !datadir || !buf || !out_sz)
        LOG_FAIL(ROM_SUBSYS, "read_chunk: null arg");
    if (idx >= a->num_chunks)
        LOG_FAIL(ROM_SUBSYS, "read_chunk: idx %u >= num_chunks %u",
                 idx, a->num_chunks);

    uint64_t offset = (uint64_t)idx * (uint64_t)a->chunk_size;
    if (offset >= a->size_bytes)
        LOG_FAIL(ROM_SUBSYS, "read_chunk: offset past EOF");
    uint64_t remaining = a->size_bytes - offset;
    uint32_t want = a->chunk_size;
    if (remaining < want)
        want = (uint32_t)remaining;
    if (want > buf_cap)
        LOG_FAIL(ROM_SUBSYS, "read_chunk: buf_cap %u < chunk %u", buf_cap, want);

    if (!rom_filename_ok(a->filename))
        LOG_FAIL(ROM_SUBSYS, "read_chunk: unsafe filename");
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(
            &file, datadir, a->filename))
        LOG_FAIL(ROM_SUBSYS, "read_chunk: validated open failed");
    uint64_t current_size = 0;
    if (!platform_positioned_file_size(&file, &current_size) ||
        current_size != a->size_bytes) {
        platform_positioned_file_close(&file);
        LOG_FAIL(ROM_SUBSYS, "read_chunk: registered size changed");
    }

    uint32_t got = 0;
    while (got < want) {
        int64_t r = platform_positioned_file_read(
            &file, buf + got, want - got, offset + got);
        if (r < 0) {
            platform_positioned_file_close(&file);
            LOG_FAIL(ROM_SUBSYS, "read_chunk: positioned read failed");
        }
        if (r == 0) {
            platform_positioned_file_close(&file);
            LOG_FAIL(ROM_SUBSYS, "read_chunk: short read (file changed?)");
        }
        got += (uint32_t)r;
    }
    platform_positioned_file_close(&file);

    uint8_t h[32];
    sha3_256(buf, got, h);
    if (memcmp(h, a->chunk_sha3[idx], 32) != 0)
        LOG_FAIL(ROM_SUBSYS, "read_chunk: idx %u digest mismatch (on-disk "
                 "corruption)", idx);

    *out_sz = got;
    return true;
}

/* ── Free-tier serve policy ─────────────────────────────────────────── */

enum rom_serve_verdict rom_seed_serve_lookup(const uint8_t root_hash[32],
                                             uint32_t chunk_index,
                                             struct rom_artifact *out)
{
    if (!atomic_load(&g_enabled))
        return ROM_SERVE_DISABLED;
    struct rom_artifact a;
    if (!rom_seed_find_by_root(root_hash, &a))
        return ROM_SERVE_NOT_ARTIFACT;
    if (chunk_index >= a.num_chunks)
        return ROM_SERVE_OUT_OF_RANGE;
    if (out) *out = a;
    return ROM_SERVE_FREE_OK;
}

bool rom_seed_offer_is_free(const uint8_t root_hash[32])
{
    return rom_seed_find_by_root(root_hash, NULL);
}

/* ── Caps ───────────────────────────────────────────────────────────── */

void rom_seed_set_enabled(bool on) { atomic_store(&g_enabled, on); }
bool rom_seed_enabled(void) { return atomic_load(&g_enabled); }

void rom_seed_set_max_inflight_per_peer(uint32_t n)
{
    if (n == 0) n = 1;
    atomic_store(&g_max_inflight_per_peer, n);
}
void rom_seed_set_peer_bps_cap(uint64_t bps)
{
    atomic_store(&g_peer_bps_cap, bps ? bps : 1);
}
void rom_seed_set_global_bps_cap(uint64_t bps)
{
    atomic_store(&g_global_bps_cap, bps ? bps : 1);
}

/* Find-or-allocate the peer slot (caller holds g_caps_mutex). Evicts the LRU
 * idle slot when full; never evicts a slot with active in-flight serves. */
static struct rom_peer_stat *peer_slot_locked(const uint8_t ip[16], int64_t now)
{
    struct rom_peer_stat *lru = NULL;
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].used && memcmp(g_peers[i].ip, ip, 16) == 0)
            return &g_peers[i];
        if (!g_peers[i].used)
            return &g_peers[i];
    }
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].concurrent == 0 &&
            (!lru || g_peers[i].last_seen < lru->last_seen))
            lru = &g_peers[i];
    }
    if (!lru)
        return NULL;   /* table full and every slot has an active serve: fail
                          closed rather than corrupt a live slot's in-flight
                          count. Callers deny the serve on NULL. */
    memset(lru, 0, sizeof(*lru));
    (void)now;
    return lru;
}

bool rom_seed_peer_acquire(const uint8_t peer_ip[16])
{
    if (!peer_ip) return false;
    if (!atomic_load(&g_enabled)) return false;
    uint32_t cap = atomic_load(&g_max_inflight_per_peer);
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = false;
    pthread_mutex_lock(&g_caps_mutex);
    struct rom_peer_stat *s = peer_slot_locked(peer_ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, peer_ip, 16);
            s->win_start = now;
        }
        s->last_seen = now;
        if (s->concurrent < cap) {
            s->concurrent++;
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_caps_mutex);
    return ok;
}

void rom_seed_peer_release(const uint8_t peer_ip[16])
{
    if (!peer_ip) return;
    pthread_mutex_lock(&g_caps_mutex);
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].used && memcmp(g_peers[i].ip, peer_ip, 16) == 0) {
            if (g_peers[i].concurrent > 0)
                g_peers[i].concurrent--;
            break;
        }
    }
    pthread_mutex_unlock(&g_caps_mutex);
}

bool rom_seed_rate_charge(const uint8_t peer_ip[16], uint64_t n, int64_t now)
{
    if (!peer_ip) return false;
    uint64_t peer_cap = atomic_load(&g_peer_bps_cap);
    uint64_t global_cap = atomic_load(&g_global_bps_cap);
    bool ok = true;

    pthread_mutex_lock(&g_caps_mutex);

    /* Global rolling-1s window. */
    if (now != g_global_win_start) {
        g_global_win_start = now;
        g_global_win_bytes = 0;
    }
    if (g_global_win_bytes > UINT64_MAX - n) g_global_win_bytes = UINT64_MAX;
    else g_global_win_bytes += n;
    if (g_global_win_bytes > global_cap) ok = false;

    /* Per-peer rolling-1s window. */
    struct rom_peer_stat *s = peer_slot_locked(peer_ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, peer_ip, 16);
            s->win_start = now;
            s->win_bytes = 0;
        }
        if (now != s->win_start) {
            s->win_start = now;
            s->win_bytes = 0;
        }
        s->last_seen = now;
        if (s->win_bytes > UINT64_MAX - n) s->win_bytes = UINT64_MAX;
        else s->win_bytes += n;
        if (s->win_bytes > peer_cap) ok = false;

        if (ok) {
            if (!s->ever_served) {
                s->ever_served = true;
                g_unique_peers_served++;
            }
            g_bytes_served_total += n;
        }
    } else {
        ok = false;
    }

    pthread_mutex_unlock(&g_caps_mutex);
    return ok;
}

void rom_seed_note_chunk_served(void)
{
    pthread_mutex_lock(&g_caps_mutex);
    g_chunks_served++;
    pthread_mutex_unlock(&g_caps_mutex);
}

/* ── Announce ───────────────────────────────────────────────────────── */

static const char *kind_name(enum rom_artifact_kind k)
{
    switch (k) {
    case ROM_ARTIFACT_CONSENSUS_BUNDLE: return "consensus_bundle";
    case ROM_ARTIFACT_HEADER_SEED:      return "header_seed";
    case ROM_ARTIFACT_UNKNOWN:
    default:                            return "unknown";
    }
}

bool rom_seed_build_offer(const struct rom_artifact *a,
                          const uint8_t self_ip[16], uint16_t fs_port,
                          struct file_offer *out)
{
    if (!a || !out)
        LOG_FAIL(ROM_SUBSYS, "build_offer: null arg");
    memset(out, 0, sizeof(*out));
    memcpy(out->root_hash, a->chunk_root, 32);
    snprintf(out->filename, sizeof(out->filename), "%s", a->filename);
    out->size_bytes = a->size_bytes;
    out->num_chunks = a->num_chunks;
    out->price_per_mb = 0;              /* free tier — no payment gate */
    if (self_ip) memcpy(out->peer_ip, self_ip, 16);
    out->peer_port = fs_port;
    out->ttl = FILE_MARKET_MAX_TTL;
    out->last_seen = (int64_t)platform_time_wall_time_t();
    return true;
}

/* Parse the height out of a canonical bundle name
 * "consensus-state-bundle-<N>.sqlite" (matched on the bare basename, so the
 * "bundles/<name>" shape resolves the same). Returns 0 for the header seed, an
 * unknown kind, or any non-canonical name — the download-cosmetic default that
 * a legacy directory (no "height" field) also parses to. Pure, no I/O. */
static int64_t rom_bundle_height_from_name(const char *filename)
{
    if (!filename || !filename[0])
        return 0;
    const char *base = rom_basename(filename);
    static const char pfx[] = "consensus-state-bundle-";
    static const char sfx[] = ".sqlite";
    size_t bl = strlen(base), pl = sizeof(pfx) - 1, sl = sizeof(sfx) - 1;
    if (bl <= pl + sl || strncmp(base, pfx, pl) != 0 ||
        strcmp(base + bl - sl, sfx) != 0)
        return 0;
    const char *d = base + pl;
    size_t dcount = bl - pl - sl;
    if (dcount == 0 || dcount >= 19) /* fits int64 without overflow */
        return 0;
    int64_t h = 0;
    for (size_t i = 0; i < dcount; i++) {
        if (d[i] < '0' || d[i] > '9')
            return 0;
        h = h * 10 + (d[i] - '0');
    }
    return h;
}

size_t rom_seed_directory_json(char *buf, size_t max)
{
    if (!buf || max == 0) return 0;
    struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);

    size_t off = 0;
    int w = snprintf(buf + off, max - off, "[");
    if (w < 0 || (size_t)w >= max - off) return 0;
    off += (size_t)w;

    int emitted = 0;
    for (int i = 0; i < n; i++) {
        char digest_hex[65];
        HexStr(arts[i].chunk_root, 32, false, digest_hex, sizeof(digest_hex));
        char whole_hex[65];
        HexStr(arts[i].whole_sha3, 32, false, whole_hex, sizeof(whole_hex));
        w = snprintf(buf + off, max - off,
                     "%s{\"kind\":\"%s\",\"digest\":\"%s\",\"whole_sha3\":\"%s\","
                     "\"size\":%llu,\"chunk_size\":%u,\"chunks\":%u,"
                     "\"height\":%lld}",
                     emitted ? "," : "", kind_name(arts[i].kind),
                     digest_hex, whole_hex,
                     (unsigned long long)arts[i].size_bytes,
                     arts[i].chunk_size, arts[i].num_chunks,
                     (long long)rom_bundle_height_from_name(arts[i].filename));
        if (w < 0 || (size_t)w >= max - off) {
            /* Overflow — close the array at what we have so the JSON stays
             * well-formed rather than truncating mid-object. */
            break;
        }
        off += (size_t)w;
        emitted++;
    }

    w = snprintf(buf + off, max - off, "]");
    if (w < 0 || (size_t)w >= max - off) return 0;
    off += (size_t)w;
    return off;
}

/* ── Background scan lifecycle ──────────────────────────────────────── */

/* Announce every registered artifact as a price-0 offer into the in-memory
 * market so it surfaces in zmarket_list and the gossip re-broadcast path. */
static void rom_seed_announce_all(uint16_t fs_port)
{
    struct rom_artifact *arts = zcl_calloc(ROM_SEED_MAX_ARTIFACTS,
                                           sizeof(*arts),
                                           "rom_seed_announce_artifacts");
    if (!arts) {
        LOG_WARN(ROM_SUBSYS, "announce: artifact snapshot allocation failed");
        return;
    }
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    uint8_t zero_ip[16] = {0};
    for (int i = 0; i < n; i++) {
        struct file_offer offer;
        if (rom_seed_build_offer(&arts[i], zero_ip, fs_port, &offer))
            (void)file_market_add_offer(&offer);
    }
    free(arts);
}

static void *rom_seed_scan_thread(void *arg)
{
    (void)arg;
    char dir[1024];
    uint16_t fs_port;
    pthread_mutex_lock(&g_scan_mutex);
    snprintf(dir, sizeof(dir), "%s", g_scan_datadir);
    fs_port = g_scan_fs_port;
    pthread_mutex_unlock(&g_scan_mutex);

    int reg = 0;
    if (atomic_load(&g_enabled))
        reg = rom_seed_scan_datadir(dir);
    if (reg > 0)
        rom_seed_announce_all(fs_port);

    /* Single-shot worker — the scan above IS its one dispatch. */
    thread_liveness_beat(&g_scan_liveness, reg);
    return NULL;
}

void rom_seed_start_scan(const char *datadir, uint16_t fs_port)
{
    if (!datadir || !datadir[0])
        return;
    pthread_mutex_lock(&g_scan_mutex);
    if (g_scan_started) {
        pthread_mutex_unlock(&g_scan_mutex);
        return;
    }
    atomic_store(&g_scan_cancel, false);
    snprintf(g_scan_datadir, sizeof(g_scan_datadir), "%s", datadir);
    g_scan_fs_port = fs_port;
    if (thread_registry_spawn("zcl_romseed", rom_seed_scan_thread, NULL,
                              &g_scan_thread) == 0) {
        g_scan_started = true;
        thread_liveness_register(&g_scan_liveness, "zcl_romseed", 0, 0);
    } else {
        LOG_WARN(ROM_SUBSYS, "start_scan: failed to spawn scan thread");
    }
    pthread_mutex_unlock(&g_scan_mutex);
}

void rom_seed_stop_scan(void)
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
    atomic_store(&g_scan_cancel, true);   /* stop between directory entries */
    pthread_join(t, NULL);
    thread_liveness_retire(&g_scan_liveness);
}

/* ── Introspection ──────────────────────────────────────────────────── */

bool rom_seed_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    json_push_kv_bool(out, "enabled", atomic_load(&g_enabled));
    json_push_kv_int(out, "max_inflight_per_peer",
                     (int64_t)atomic_load(&g_max_inflight_per_peer));
    json_push_kv_int(out, "peer_bps_cap",
                     (int64_t)atomic_load(&g_peer_bps_cap));
    json_push_kv_int(out, "global_bps_cap",
                     (int64_t)atomic_load(&g_global_bps_cap));

    uint64_t chunks_served, bytes_total, unique_peers, cur_bps;
    int64_t now = (int64_t)platform_time_wall_time_t();
    pthread_mutex_lock(&g_caps_mutex);
    chunks_served = g_chunks_served;
    bytes_total = g_bytes_served_total;
    unique_peers = g_unique_peers_served;
    cur_bps = (now == g_global_win_start) ? g_global_win_bytes : 0;
    pthread_mutex_unlock(&g_caps_mutex);

    json_push_kv_int(out, "chunks_served", (int64_t)chunks_served);
    json_push_kv_int(out, "bytes_served_total", (int64_t)bytes_total);
    json_push_kv_int(out, "unique_peers_served", (int64_t)unique_peers);
    json_push_kv_int(out, "current_bps", (int64_t)cur_bps);

    struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    json_push_kv_int(out, "artifact_count", n);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value o = {0};
        json_set_object(&o);
        char digest_hex[65];
        HexStr(arts[i].chunk_root, 32, false, digest_hex, sizeof(digest_hex));
        json_push_kv_str(&o, "kind", kind_name(arts[i].kind));
        json_push_kv_str(&o, "filename", arts[i].filename);
        json_push_kv_str(&o, "digest", digest_hex);
        json_push_kv_int(&o, "size", (int64_t)arts[i].size_bytes);
        json_push_kv_int(&o, "chunk_size", (int64_t)arts[i].chunk_size);
        json_push_kv_int(&o, "chunks", (int64_t)arts[i].num_chunks);
        json_push_kv_int(&o, "registered_at", arts[i].registered_at);
        json_push_back(&arr, &o);
        json_free(&o);
    }
    json_push_kv(out, "artifacts", &arr);
    json_free(&arr);

    bool ok = atomic_load(&g_enabled);
    diag_push_health(out, ok,
                     ok ? "seeding enabled" : "seeding disabled by config");
    return true;
}

/* ── WF2 artifact-protocol: per-chunk manifest serialization ──────────
 *
 * Pure serializer over a's per-chunk digests, which registration already
 * derived from the bytes on disk (a->chunk_sha3). Layout, all little-endian:
 *   [u32 version=1][u32 num_chunks][num_chunks × 32B chunk_sha3]
 * bounded by ROM_SEED_MANIFEST_BLOB_MAX. Returns the byte length, or 0 on NULL
 * args / an out-of-range chunk count / insufficient capacity (0 == "no
 * manifest", the client's fall-back-to-whole-file signal). */
size_t rom_seed_manifest_blob(const struct rom_artifact *a,
                              uint8_t *buf, size_t cap)
{
    if (!a || !buf || cap == 0)
        return 0;
    if (a->num_chunks == 0 || a->num_chunks > ROM_SEED_MAX_CHUNKS)
        return 0;

    size_t need = 8u + (size_t)a->num_chunks * 32u;
    if (need > cap || need > ROM_SEED_MANIFEST_BLOB_MAX)
        return 0;

    uint32_t version = 1u;
    uint32_t nc = a->num_chunks;
    buf[0] = (uint8_t)(version);
    buf[1] = (uint8_t)(version >> 8);
    buf[2] = (uint8_t)(version >> 16);
    buf[3] = (uint8_t)(version >> 24);
    buf[4] = (uint8_t)(nc);
    buf[5] = (uint8_t)(nc >> 8);
    buf[6] = (uint8_t)(nc >> 16);
    buf[7] = (uint8_t)(nc >> 24);
    for (uint32_t i = 0; i < nc; i++)
        memcpy(buf + 8u + (size_t)i * 32u, a->chunk_sha3[i], 32);
    return need;
}
