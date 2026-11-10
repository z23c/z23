/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Derived public projection fixture. These events reproduce retained rows;
 * they do not attest original event history or verify every Equihash proof. */
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/block_index_projection.h"
#include "storage/block_index_db.h"

static bool csi_derived_stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
static bool csi_derived_hash(const char *path, const uint8_t expected[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); struct stat a, b;
    if (fd < 0) return false;
    bool ok = fstat(fd, &a) == 0 && S_ISREG(a.st_mode) && a.st_uid == geteuid();
    struct sha256_ctx ctx; sha256_init(&ctx); uint8_t data[65536], hash[32];
    while (ok) {
        ssize_t n = read(fd, data, sizeof(data));
        if (!n) break;
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        sha256_write(&ctx, data, (size_t)n);
    }
    if (ok && (fstat(fd, &b) || !csi_derived_stat_same(&a, &b))) ok = false;
    if (close(fd)) ok = false;
    sha256_finalize(&ctx, hash);
    return ok && !memcmp(hash, expected, 32);
}
static bool csi_derived_private_parent(const char *path)
{
    char resolved[PATH_MAX], parent[PATH_MAX]; struct stat st;
    if (!path || path[0] != '/' || !realpath(path, resolved) || strcmp(path, resolved)) return false;
    int n = snprintf(parent, sizeof(parent), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(parent)) return false;
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return false;
    *slash = '\0';
    return lstat(parent, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077);
}
static bool csi_derived_no_sidecars(const char *path)
{
    char sidecar[PATH_MAX]; struct stat st;
    const char *suffix[] = {"-wal", "-shm"};
    for (size_t i = 0; i < 2; ++i) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", path, suffix[i]);
        if (n < 0 || (size_t)n >= sizeof(sidecar) || lstat(sidecar, &st) == 0 || errno != ENOENT) return false;
    }
    return true;
}
static bool csi_derived_wire(const uint8_t hash[32], const struct disk_block_index *d,
                             uint8_t *wire, size_t cap, size_t *size)
{
    if (d->nSolutionSize > EV_BLOCK_HEADER_MAX_SOLUTION || d->nSolutionSize > UINT16_MAX) return false;
    struct ev_block_header h = {0};
    memcpy(h.hash, hash, 32); memcpy(h.hashPrev, d->hashPrev.data, 32);
    h.height = d->nHeight; h.nStatus = d->nStatus; h.nTx = d->nTx;
    h.nFile = d->nFile; h.nDataPos = d->nDataPos; h.nUndoPos = d->nUndoPos;
    h.nVersion = d->nVersion; h.nTime = d->nTime; h.nBits = d->nBits;
    memcpy(h.hashMerkleRoot, d->hashMerkleRoot.data, 32);
    memcpy(h.hashFinalSaplingRoot, d->hashFinalSaplingRoot.data, 32);
    memcpy(h.nNonce, d->nNonce.data, 32); h.nSolutionSize = (uint16_t)d->nSolutionSize;
    return ev_block_header_serialize(&h, d->nSolutionSize ? d->nSolution : NULL, wire, cap, size);
}
struct csi_derived_rows { event_log_t *log; block_index_projection_t *other; uint64_t count; bool ok; };
static bool csi_derived_emit(const uint8_t hash[32], const struct disk_block_index *d, void *opaque)
{
    struct csi_derived_rows *c = opaque; uint8_t wire[256 + MAX_SOLUTION_SIZE]; size_t n = 0;
    c->ok = csi_derived_wire(hash, d, wire, sizeof(wire), &n) &&
        event_log_append(c->log, EV_BLOCK_HEADER, wire, n) != UINT64_MAX;
    if (c->ok) ++c->count;
    return c->ok;
}
static bool csi_derived_compare(const uint8_t hash[32], const struct disk_block_index *d, void *opaque)
{
    struct csi_derived_rows *c = opaque; struct disk_block_index other;
    uint8_t a[256 + MAX_SOLUTION_SIZE], b[256 + MAX_SOLUTION_SIZE]; size_t an = 0, bn = 0;
    c->ok = block_index_projection_get_strict(c->other, hash, &other) &&
        csi_derived_wire(hash, d, a, sizeof(a), &an) && csi_derived_wire(hash, &other, b, sizeof(b), &bn) &&
        an == bn && !memcmp(a, b, an);
    if (c->ok) ++c->count;
    return c->ok;
}
static bool csi_derived_anchor(const char *dir, block_index_projection_t *projection)
{
    struct block_index_flat_cursor *flat = NULL; uint8_t low[32], high[32], compact[32];
    bool ok = block_index_flat_cursor_open(dir, &flat).ok &&
        block_index_flat_cursor_best_ancestor(flat, 64854, low).ok &&
        block_index_flat_cursor_best_ancestor(flat, 64855, high).ok &&
        block_index_flat_cursor_best_ancestor(flat, 60586, compact).ok;
    struct disk_block_index a, b, c;
    ok = ok && block_index_projection_get_strict(projection, low, &a) &&
        block_index_projection_get_strict(projection, high, &b) &&
        block_index_projection_get_strict(projection, compact, &c) &&
        a.nHeight == 64854 && b.nHeight == 64855 && !memcmp(b.hashPrev.data, low, 32) &&
        c.nHeight == 60586 && c.nSolutionSize == 0;
    block_index_flat_cursor_close(flat); return ok;
}
static bool csi_derived_copy_checked(const char *src, const char *flat, const char *backup,
    const char *flatcopy, const uint8_t proj_hash[32], const uint8_t flat_hash[32])
{
    return csi_derived_no_sidecars(src) && csi_derived_hash(src, proj_hash) && csi_derived_hash(flat, flat_hash) &&
        csi_real_copy(src, backup) && csi_real_copy(flat, flatcopy) &&
        csi_derived_hash(backup, proj_hash) && csi_derived_hash(flatcopy, flat_hash) &&
        csi_derived_no_sidecars(src) && csi_derived_hash(src, proj_hash) && csi_derived_hash(flat, flat_hash);
}
static bool csi_derived_prepare_paths(const char *root, const char *data, const char *src,
    const char *flat, char backup[PATH_MAX], char flatcopy[PATH_MAX], char logpath[PATH_MAX],
    char targetpath[PATH_MAX], const uint8_t proj_hash[32], const uint8_t flat_hash[32])
{
    return csi_derived_private_parent(src) && csi_derived_private_parent(flat) &&
        csi_real_path(backup, PATH_MAX, root, "source-projection.db") &&
        csi_real_path(flatcopy, PATH_MAX, root, "block_index.bin") &&
        csi_real_path(logpath, PATH_MAX, data, "event_log.dat") &&
        csi_real_path(targetpath, PATH_MAX, data, "block_index_projection.db") &&
        csi_derived_copy_checked(src, flat, backup, flatcopy, proj_hash, flat_hash);
}
static bool csi_derived_compare_projections(const char *root, event_log_t *log,
    block_index_projection_t *source, block_index_projection_t *target, uint64_t count)
{
    struct csi_derived_rows rows = {.log = log, .ok = true};
    event_log_set_deferred_sync(log, true);
    bool ok = count > 0 && block_index_projection_iterate(source, csi_derived_emit, &rows) == 0 &&
        rows.ok && rows.count == count && event_log_flush(log) &&
        block_index_projection_catch_up(target) != UINT64_MAX && block_index_projection_count(target) == count;
    if (ok) { rows = (struct csi_derived_rows){.other = target, .ok = true};
        ok = block_index_projection_iterate(source, csi_derived_compare, &rows) == 0 && rows.ok && rows.count == count; }
    if (ok) { rows = (struct csi_derived_rows){.other = source, .ok = true};
        ok = block_index_projection_iterate(target, csi_derived_compare, &rows) == 0 && rows.ok && rows.count == count &&
            csi_derived_anchor(root, target); }
    return ok;
}
static bool csi_derived_projection(const char *root, const char *data)
{
    static const uint8_t proj_hash[32] = {0x54,0x2e,0x87,0xbf,0x8a,0xeb,0x6a,0x0b,0xa1,0x74,0xdd,0xc2,0xfa,0xe6,0xd7,0x26,0x5a,0x0d,0xde,0xd8,0x1d,0x91,0x7b,0x8b,0xf2,0x27,0x41,0xa0,0x4b,0x64,0xcc,0x58};
    static const uint8_t flat_hash[32] = {0xbd,0xf6,0xb7,0x65,0x0b,0x78,0xb0,0x38,0x48,0x84,0xb0,0x31,0x8b,0x4a,0xb8,0x43,0x52,0x0d,0xaf,0xa2,0x51,0x64,0x94,0x51,0x9c,0x2e,0x66,0xb1,0x19,0xf5,0x57,0x5e};
    const char *src = getenv("ZCL_TEST_PUBLIC_PROJECTION"), *flat = getenv("ZCL_TEST_PUBLIC_FLAT");
    char backup[PATH_MAX], flatcopy[PATH_MAX], logpath[PATH_MAX], targetpath[PATH_MAX];
    if (!csi_derived_prepare_paths(root, data, src, flat, backup, flatcopy, logpath,
                                   targetpath, proj_hash, flat_hash)) return false;
    int lease = open(backup, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (lease < 0) return false;
    if (flock(lease, LOCK_EX | LOCK_NB)) { close(lease); return false; }
    event_log_t *log = event_log_open(logpath);
    block_index_projection_t *source = block_index_projection_open(backup, NULL);
    block_index_projection_t *target = log ? block_index_projection_open(targetpath, log) : NULL;
    bool ok = log && source && target && csi_derived_anchor(root, source);
    uint64_t count = ok ? block_index_projection_count(source) : 0;
    if (ok) ok = csi_derived_compare_projections(root, log, source, target, count);
    if (target) block_index_projection_close(target);
    if (source) block_index_projection_close(source);
    if (log) event_log_close(log);
    if (flock(lease, LOCK_UN)) ok = false;
    if (close(lease)) ok = false;
    return ok;
}
