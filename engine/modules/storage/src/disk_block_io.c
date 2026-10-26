/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#include "storage/disk_block_io.h"
#include "disk_block_io_internal.h"
#include "core/serialize.h"
#include "core/hash.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "platform/file_metadata.h"
#include "platform/directory_compat.h"
#include "platform/file_advice.h"
#include "platform/positioned_io.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include "util/safe_alloc.h"
#include "platform/windows_path.h"
#if defined(_WIN32)
#include <io.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* Plain CRT open first, so a short ASCII path keeps today's success. When
 * that loses a long path or a non-ASCII UTF-8 name, one retry uses the wide
 * Win32 seam. Block bytes stay binary. */
#if defined(_WIN32)
/* The three binary modes this file opens, as _wopen flags; -1 otherwise. */
static int block_wide_flags(const char *mode)
{
    if (strcmp(mode, "rb+") == 0)
        return _O_BINARY | _O_RDWR;
    if (strcmp(mode, "wb+") == 0)
        return _O_BINARY | _O_RDWR | _O_CREAT | _O_TRUNC;
    if (strcmp(mode, "rb") == 0)
        return _O_BINARY | _O_RDONLY;
    return -1;
}

static FILE *block_fopen_wide(const char *path, const char *mode)
{
    wchar_t wide[32768];
    if (!path || !mode || !platform_windows_wide_path(path, wide)) {
        errno = EINVAL;
        return NULL;
    }
    int flags = block_wide_flags(mode);
    if (flags < 0) {
        errno = EINVAL;
        return NULL;
    }
    int fd = _wopen(wide, flags, 0666);
    if (fd < 0)
        return NULL;
    FILE *file = _fdopen(fd, mode);
    if (!file)
        _close(fd);
    return file;
}
#endif

static FILE *block_fopen(const char *path, const char *mode)
{
    FILE *file = fopen(path, mode);
#if defined(_WIN32)
    if (!file)
        file = block_fopen_wide(path, mode);
#endif
    return file;
}

static int block_open(const char *path, int flags)
{
    int fd = open(path, flags | O_BINARY);
#if defined(_WIN32)
    if (fd < 0) {
        wchar_t wide[32768];
        if (platform_windows_wide_path(path, wide))
            fd = _wopen(wide, flags | _O_BINARY, 0666);
    }
#endif
    return fd;
}

/* De-storm absent-body reads from blocks-less bundles and residual missing or
 * stale blk positions. Without this bound, millions of expected open/pread
 * failures produced >1 GB of logs and could fill a nearly full disk before
 * tip. One global throttle identity intentionally collapses interleaved file
 * walkers; each 60-second keep-alive carries the suppressed count and sample. */
static struct log_throttle g_open_fail_throttle = LOG_THROTTLE_INIT;
static struct log_throttle g_readfail_throttle  = LOG_THROTTLE_INIT;
/* Same, for a DANGLING position (foreign writer, torn import): every sweep. */
static struct log_throttle g_locate_fail_throttle = LOG_THROTTLE_INIT;

/* Durable body-completion hook (see disk_block_io.h). Set once at boot,
 * cleared at shutdown; read on the persist thread under the same lock.
 * Admission is counted so shutdown can drain callbacks that copied the
 * registration before the clear and are still running while their consumer
 * context is being torn down. */
static pthread_mutex_t g_have_data_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_have_data_hook_drained = PTHREAD_COND_INITIALIZER;
static disk_block_have_data_hook_fn g_have_data_hook;
static void *g_have_data_hook_ctx;
static unsigned g_have_data_hook_inflight;
static bool g_have_data_hook_admission = true;

void disk_block_io_set_have_data_hook(disk_block_have_data_hook_fn fn,
                                      void *ctx)
{
    pthread_mutex_lock(&g_have_data_hook_lock);
    g_have_data_hook = fn;
    g_have_data_hook_ctx = ctx;
    pthread_mutex_unlock(&g_have_data_hook_lock);
}

void disk_block_io_quiesce_have_data_hook(void)
{
    pthread_mutex_lock(&g_have_data_hook_lock);
    g_have_data_hook = NULL;
    g_have_data_hook_ctx = NULL;
    g_have_data_hook_admission = false;
    while (g_have_data_hook_inflight > 0)
        pthread_cond_wait(&g_have_data_hook_drained, &g_have_data_hook_lock);
    pthread_mutex_unlock(&g_have_data_hook_lock);
}

static void disk_block_io_fire_have_data_hook(void)
{
    disk_block_have_data_hook_fn fn;
    void *ctx;

    pthread_mutex_lock(&g_have_data_hook_lock);
    if (!g_have_data_hook_admission || !g_have_data_hook) {
        pthread_mutex_unlock(&g_have_data_hook_lock);
        return;
    }
    fn = g_have_data_hook;
    ctx = g_have_data_hook_ctx;
    g_have_data_hook_inflight++;
    pthread_mutex_unlock(&g_have_data_hook_lock);

    fn(ctx);

    pthread_mutex_lock(&g_have_data_hook_lock);
    if (--g_have_data_hook_inflight == 0)
        pthread_cond_broadcast(&g_have_data_hook_drained);
    pthread_mutex_unlock(&g_have_data_hook_lock);
}

#if defined(ZCL_TESTING)
void disk_block_io_test_fire_have_data_hook(void)
{
    disk_block_io_fire_have_data_hook();
}
#endif

/* A missing directory is always invalid. Do not infer pointer lifetime from
 * path bytes: POSIX permits every non-NUL byte inside a path component except
 * '/', and inspecting a pointer after its lifetime ended is already undefined
 * behavior. Long-lived readers must own their datadir bytes. */
static struct log_throttle g_datadir_invalid_throttle = LOG_THROTTLE_INIT;

void get_block_pos_filename(char *buf, size_t buflen,
                            const char *datadir,
                            const struct disk_block_pos *pos,
                            const char *prefix)
{
    if (!datadir || !datadir[0]) {
        /* Fail closed: an empty path opens/stats/unlinks nowhere, so every
         * caller's existing refusal fires instead of touching a wrong file. */
        if (buflen)
            buf[0] = '\0';
        uint64_t reps = 0;
        if (log_throttle_should_emit(&g_datadir_invalid_throttle, 0u,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_ERROR("disk_block_io",
                      "get_block_pos_filename: datadir is NULL/empty; "
                      "refusing file=%d prefix=%s "
                      "(%llu suppressed repeats)",
                      pos ? pos->nFile : -1, prefix ? prefix : "(nil)",
                      (unsigned long long)reps);
        return;
    }
    if (pos->nFile == 255)
        snprintf(buf, buflen, "%s/blocks/%s_sync.dat", datadir, prefix);
    else
        snprintf(buf, buflen, "%s/blocks/%s%05d.dat", datadir, prefix, pos->nFile);
}

static bool ensure_directory(const char *path)
{
    return platform_directory_ensure(path, 0755);
}

/* A hardlinked blk file may have a live foreign appender. Warn once per file;
 * append allocation rotates away and opened-file validation refuses writes. */
static uint8_t g_hardlink_warned[10000 / 8 + 1];

/* Sequential IBD append hint.  write_block_to_disk serializes append
 * allocation under g_file_cache_mutex, so the last successfully flushed
 * end position is a safe candidate for the next body.  We still stat the
 * candidate on every use: size drift, replacement, truncation, or a newly
 * added hard link invalidates the hint and falls back to the full scan.
 *
 * This removes an O(number-of-blk-files) directory/stat walk per block from
 * the hot path.  That walk is especially costly on Windows (NTFS metadata +
 * Defender interception) once a datadir has accumulated many blk files. */
static bool g_append_hint_valid;
static int g_append_hint_file = -1;
static unsigned int g_append_hint_size;
static char g_append_hint_datadir[512];

static void append_hint_invalidate(void)
{
    g_append_hint_valid = false;
    g_append_hint_file = -1;
    g_append_hint_size = 0;
    g_append_hint_datadir[0] = '\0';
}

static bool append_hint_try(struct disk_block_pos *pos, uint32_t block_size,
                            const char *datadir)
{
    if (!g_append_hint_valid ||
        strcmp(g_append_hint_datadir, datadir) != 0)
        return false;

    char path[512];
    struct disk_block_pos probe = {
        .nFile = g_append_hint_file,
        .nPos = 0
    };
    get_block_pos_filename(path, sizeof(path), datadir, &probe, "blk");
    struct platform_file_metadata metadata = {0};
    if (platform_file_metadata_read(path, &metadata) !=
            PLATFORM_FILE_METADATA_OK ||
        metadata.links != 1 ||
        metadata.size != (uint64_t)g_append_hint_size ||
        (uint64_t)g_append_hint_size + block_size + 8u > 0x8000000u) {
        append_hint_invalidate();
        return false;
    }

    pos->nFile = g_append_hint_file;
    pos->nPos = g_append_hint_size;
    return true;
}

static void append_hint_record(const char *datadir, int file,
                               uint64_t next_size)
{
    size_t n = strlen(datadir);
    if (file < 0 || file > 9999 || next_size > UINT32_MAX ||
        n >= sizeof(g_append_hint_datadir)) {
        append_hint_invalidate();
        return;
    }
    memcpy(g_append_hint_datadir, datadir, n + 1);
    g_append_hint_file = file;
    g_append_hint_size = (unsigned int)next_size;
    g_append_hint_valid = true;
}

static void hardlink_warn_once(int file_idx, const char *path,
                               unsigned long nlink)
{
    uint8_t mask = (uint8_t)(1u << (file_idx & 7));
    if (g_hardlink_warned[file_idx >> 3] & mask)
        return; /* benign race: a duplicate warning is harmless */
    g_hardlink_warned[file_idx >> 3] |= mask;
    fprintf(stderr,  // obs-ok:hardlink-tripwire-boot-time-foreign-writer-warning
            "[disk_block_io] %s has %lu hard links — shared blk "
            "file quarantined from writes\n",
            path, nlink);
}

static bool choose_append_block_pos(struct disk_block_pos *pos,
                                    uint32_t block_size,
                                    const char *datadir,
                                    bool allow_hint)
{
    if (!pos || !datadir)
        return false;

    char blocks_dir[4096];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    if (!ensure_directory(blocks_dir))
        return false;

    if (allow_hint && append_hint_try(pos, block_size, datadir))
        return true;

    int last_file = 0;
    unsigned int last_size = 0;
    bool last_shared = false;
    for (int i = 0; i <= 9999; i++) {
        char path[512];
        struct disk_block_pos probe = { .nFile = i, .nPos = 0 };
        get_block_pos_filename(path, sizeof(path), datadir, &probe, "blk");
        struct platform_file_metadata metadata = {0};
        enum platform_file_metadata_result metadata_result =
            platform_file_metadata_read(path, &metadata);
        if (metadata_result == PLATFORM_FILE_METADATA_MISSING)
            break;
        if (metadata_result != PLATFORM_FILE_METADATA_OK ||
            metadata.size > UINT32_MAX)
            return false;
        last_shared = metadata.links > 1;
        if (last_shared)
            hardlink_warn_once(i, path, (unsigned long)metadata.links);
        last_file = i;
        last_size = (unsigned int)metadata.size;
    }

    if (last_shared || last_size + block_size + 8u > 0x8000000u) {
        last_file++;
        last_size = 0;
    }
    if (last_file > 9999)
        return false;

    pos->nFile = last_file;
    pos->nPos = last_size;
    return true;
}

/* ── Read-only file handle cache ──────────────────────────────────
 * During sequential IBD, consecutive blocks are almost always in the
 * same blk*.dat file. Keeping the last-opened read-only FILE* avoids
 * ~99% of open/close syscalls. Write paths bypass the cache.
 * Protected by mutex for thread safety (bg_validation, P2P, RPC). */
static pthread_mutex_t g_file_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_cached_file = NULL;
static int   g_cached_nfile = -1;
static char  g_cached_prefix[8] = {0};

/* ── Deferred block-body fdatasync (see storage/disk_block_io.h) ──────
 * When g_deferred_sync is set, write_block_to_disk() records the file it
 * wrote here instead of fdatasync()ing it inline; disk_block_io_sync_pending()
 * flushes the set at the drain-batch boundary. Both the flag and the set are
 * guarded by g_file_cache_mutex (already held across the write). The cap is
 * far larger than any batch touches (128 MB per blk file * 64 = 8 GB of
 * bodies) so overflow is unreachable in practice; it still falls back to an
 * inline sync rather than dropping a file on the floor. */
#define DEFERRED_MAX_FILES 64
static bool g_deferred_sync = false;
static char g_pending_paths[DEFERRED_MAX_FILES][512];
static int  g_pending_count = 0;

/* Add `path` to the pending set (dedup). Caller holds g_file_cache_mutex.
 * Returns false only when the set is full (caller must sync inline instead). */
static bool deferred_record_pending_locked(const char *path)
{
    for (int i = 0; i < g_pending_count; i++)
        if (strcmp(g_pending_paths[i], path) == 0)
            return true; /* already pending — one sync covers all writes */
    if (g_pending_count >= DEFERRED_MAX_FILES)
        return false;
    snprintf(g_pending_paths[g_pending_count], sizeof(g_pending_paths[0]),
             "%s", path);
    g_pending_count++;
    return true;
}

void disk_block_io_set_deferred_sync(bool enabled)
{
    pthread_mutex_lock(&g_file_cache_mutex);
    g_deferred_sync = enabled;
    pthread_mutex_unlock(&g_file_cache_mutex);
}

bool disk_block_io_deferred_sync_enabled(void)
{
    pthread_mutex_lock(&g_file_cache_mutex);
    bool v = g_deferred_sync;
    pthread_mutex_unlock(&g_file_cache_mutex);
    return v;
}

bool disk_block_io_sync_pending(void)
{
    pthread_mutex_lock(&g_file_cache_mutex);
    bool all_ok = true;
    int keep = 0;
    for (int i = 0; i < g_pending_count; i++) {
#if defined(_WIN32)
        /* Windows _commit()/FlushFileBuffers requires a write-capable handle,
         * so open the blk file for read-write even though we only sync. */
        int fd = block_open(g_pending_paths[i], O_RDWR);
#else
        int fd = block_open(g_pending_paths[i], O_RDONLY);
#endif
        bool synced = (fd >= 0 && platform_data_sync(fd) == 0);
        if (fd >= 0)
            close(fd);
        if (!synced) {
            /* Keep the entry so a retry re-attempts the sync — clearing it
             * would let a later commit succeed while these bytes are still
             * unsynced, breaking the ordering invariant. */
            all_ok = false;
            fprintf(stderr,  // obs-ok:sync-failure-vetoes-commit-via-precommit-hook
                    "disk_block_io_sync_pending: fdatasync %s failed: %s\n",
                    g_pending_paths[i], strerror(errno));
            if (keep != i)
                memcpy(g_pending_paths[keep], g_pending_paths[i],
                       sizeof(g_pending_paths[0]));
            keep++;
        }
    }
    g_pending_count = keep;
    pthread_mutex_unlock(&g_file_cache_mutex);
    return all_ok;
}

/* Expose mutex for callers that read block/undo files directly
 * (e.g., transaction_controller, bg_validation undo reads).
 * All fread/fseek/fclose on blk*.dat and rev*.dat MUST be wrapped
 * in lock/unlock to prevent SIGSEGV from concurrent FILE* access. */
void disk_block_io_lock(void)
{
    pthread_mutex_lock(&g_file_cache_mutex);
}

void disk_block_io_unlock(void)
{
    pthread_mutex_unlock(&g_file_cache_mutex);
}

/* Caller-owned-lock variant: used from paths that already hold
 * g_file_cache_mutex (e.g. block_pruning_service during the
 * invalidate-then-unlink sequence, where re-entering the lock
 * would self-deadlock on a NORMAL mutex). */
static void disk_block_io_close_cache_locked(void)
{
    if (g_cached_file) {
        fclose(g_cached_file);
        g_cached_file = NULL;
        g_cached_nfile = -1;
    }
}

void disk_block_io_close_cache(void)
{
    pthread_mutex_lock(&g_file_cache_mutex);
    disk_block_io_close_cache_locked();
    pthread_mutex_unlock(&g_file_cache_mutex);
}

void disk_block_io_close_cache_while_locked(void)
{
    disk_block_io_close_cache_locked();
}

/* A failed update open permits creation only when the path was absent. */
static bool disk_file_creation_allowed(bool read_only)
{
    return !read_only && errno == ENOENT;
}

/* Read-only cache hit: reuse the cached handle when it covers this
 * (nFile, prefix) and still seeks to the position. NULL on any miss. */
static FILE *cached_read_handle(const struct disk_block_pos *pos,
                                const char *prefix)
{
    if (!g_cached_file ||
        g_cached_nfile != pos->nFile ||
        strcmp(g_cached_prefix, prefix) != 0)
        return NULL;
    if (fseek(g_cached_file, (long)pos->nPos, SEEK_SET) == 0)
        return g_cached_file;
    /* Seek failed — close and reopen */
    disk_block_io_close_cache_locked();
    return NULL;
}

/* Drop the cached read handle when the same file opens for writing. */
static void drop_cached_handle_for_write(const struct disk_block_pos *pos,
                                         const char *prefix)
{
    if (g_cached_file && g_cached_nfile == pos->nFile &&
        strcmp(g_cached_prefix, prefix) == 0) {
        disk_block_io_close_cache_locked();
    }
}

/* Update open first; a failed update open permits creation only when the
 * path was absent (see disk_file_creation_allowed). */
static FILE *open_block_file_at_path(const char *path, bool read_only)
{
    FILE *file = block_fopen(path, "rb+");
    if (!file && disk_file_creation_allowed(read_only))
        file = block_fopen(path, "wb+");
    return file;
}

/* Cache read-only handles for sequential access */
static void cache_read_handle(FILE *file, const struct disk_block_pos *pos,
                              const char *prefix)
{
    /* Close any previous cached handle. Reaching here means the
     * cache-hit test above missed, so the cached handle (if any) is
     * for a different (nFile, prefix) pair — note blk and rev files
     * share numbers, so comparing nFile alone would leak the old
     * handle when only the prefix differs. */
    if (g_cached_file)
        fclose(g_cached_file);
    g_cached_file = file;
    g_cached_nfile = pos->nFile;
    snprintf(g_cached_prefix, sizeof(g_cached_prefix), "%s", prefix);
}

FILE *open_disk_file(const char *datadir,
                     const struct disk_block_pos *pos,
                     const char *prefix, bool read_only)
{
    if (pos->nFile < 0)
        return NULL;

    char blocks_dir[4096];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    ensure_directory(blocks_dir);

    /* Try the read-only cache: same file number and prefix → reuse handle */
    if (read_only) {
        FILE *cached = cached_read_handle(pos, prefix);
        if (cached)
            return cached;
    }

    /* Invalidate cache if opening same file for writing — prevents
     * stale stdio buffers after the write handle modifies the file. */
    if (!read_only)
        drop_cached_handle_for_write(pos, prefix);

    char path[4096];
    get_block_pos_filename(path, sizeof(path), datadir, pos, prefix);

    FILE *file = open_block_file_at_path(path, read_only);
    if (!file) {
        fprintf(stderr, "open_disk_file: cannot open %s: %s\n",
                path, strerror(errno));
        return NULL;
    }

    if (pos->nPos) {
        if (fseek(file, (long)pos->nPos, SEEK_SET)) {
            fprintf(stderr, "open_disk_file: fseek to %u failed in %s: %s\n",
                    pos->nPos, path, strerror(errno));
            fclose(file);
            return NULL;
        }
    }

    /* Cache read-only handles for sequential access */
    if (read_only)
        cache_read_handle(file, pos, prefix);

    return file;
}

/* Allocate an append position only when the caller did not pin one
 * (pos->nFile < 0); a pinned position passes through untouched. */
static bool ensure_append_block_pos(struct disk_block_pos *pos,
                                    uint32_t block_size,
                                    const char *datadir,
                                    bool append_allocated)
{
    return !append_allocated ||
        choose_append_block_pos(pos, block_size, datadir, g_deferred_sync);
}

/* An opened blk file is writable only as a lone regular file: a hardlinked
 * blk file may have a live foreign appender. Always fills opened_out and
 * links_out so the caller can log exactly what it refused. */
static bool opened_blk_file_is_safe(FILE *file, const char *datadir,
                                    const struct disk_block_pos *pos,
                                    struct stat *opened_out,
                                    unsigned long *links_out)
{
    bool opened_safe = fstat(fileno(file), opened_out) == 0 &&
        S_ISREG(opened_out->st_mode);
#if defined(_WIN32)
    /* UCRT's stat/fstat reports st_nlink=1 for an NTFS hard link.  Ask the
     * UTF-8 -> CreateFileW metadata seam for the real handle-backed link
     * count; ordinary POSIX hosts retain fstat's race-free answer. */
    char opened_path[512];
    struct platform_file_metadata opened_metadata = {0};
    get_block_pos_filename(opened_path, sizeof(opened_path), datadir, pos,
                           "blk");
    opened_safe = opened_safe &&
        platform_file_metadata_read(opened_path, &opened_metadata) ==
            PLATFORM_FILE_METADATA_OK;
    *links_out = (unsigned long)opened_metadata.links;
#else
    (void)datadir;
    (void)pos;
    *links_out = (unsigned long)opened_out->st_nlink;
#endif
    return opened_safe && *links_out == 1;
}

/* Which step of the framed write failed, so the caller logs its own
 * message at its own site. */
enum block_write_result {
    BLOCK_WRITE_OK,
    BLOCK_WRITE_FTELL_FAILED,
    BLOCK_WRITE_HEADER_FAILED,
    BLOCK_WRITE_DATA_POS_RANGE,
    BLOCK_WRITE_DATA_FAILED
};

/* Write the 8-byte magic+size frame header, then the serialized block body.
 * On success *data_pos_out is the payload offset; on a data-position range
 * failure it holds the out-of-range value for the caller's log line. */
static enum block_write_result write_block_frame(FILE *file,
                                                 const unsigned char message_start[4],
                                                 uint32_t nSize,
                                                 const struct byte_stream *s,
                                                 long *data_pos_out)
{
    long file_pos = ftell(file);
    if (file_pos < 0)
        return BLOCK_WRITE_FTELL_FAILED;

    if (fwrite(message_start, 1, 4, file) != 4 || // disk-io-lock: held (internal)
        fwrite(&nSize, sizeof(nSize), 1, file) != 1)
        return BLOCK_WRITE_HEADER_FAILED;

    long data_pos = ftell(file);
    if (data_pos < 0 || (unsigned long)data_pos > UINT32_MAX) {
        *data_pos_out = data_pos;
        return BLOCK_WRITE_DATA_POS_RANGE;
    }

    if (fwrite(s->data, 1, s->size, file) != s->size) // disk-io-lock: held (internal)
        return BLOCK_WRITE_DATA_FAILED;

    *data_pos_out = data_pos;
    return BLOCK_WRITE_OK;
}

/* Which durability step failed, so the caller logs its own message at its
 * own site. */
enum block_sync_result {
    BLOCK_SYNC_OK,
    BLOCK_SYNC_FFLUSH_FAILED,
    BLOCK_SYNC_DATASYNC_FAILED
};

/* Flush to disk before reporting success — prevents silent data loss
 * on power failure. fdatasync skips metadata update (faster).
 *
 * Deferred mode (reducer fold / catch-up drain): push the stdio buffer to
 * the kernel now (fflush) so a concurrent reader sees the bytes, but defer
 * the fdatasync to the drain-batch boundary (disk_block_io_sync_pending,
 * fired before the stage COMMIT). Record the file as pending; on set
 * overflow fall back to an inline fdatasync so a file is never left
 * unsynced. Both g_deferred_sync and the pending set are under the mutex
 * held here. */
static enum block_sync_result flush_and_sync_block_file(FILE *file,
                                                        const char *datadir,
                                                        const struct disk_block_pos *pos)
{
    if (fflush(file) != 0)
        return BLOCK_SYNC_FFLUSH_FAILED;
    bool sync_now = true;
    if (g_deferred_sync) {
        char wpath[512];
        get_block_pos_filename(wpath, sizeof(wpath), datadir, pos, "blk");
        if (deferred_record_pending_locked(wpath))
            sync_now = false; /* synced later at the drain-batch boundary */
    }
    if (sync_now && platform_data_sync(fileno(file)) != 0)
        return BLOCK_SYNC_DATASYNC_FAILED;
    return BLOCK_SYNC_OK;
}

/* Only record position AFTER data is confirmed on disk.
 * If we crash before this, caller retries from scratch — safe. */
static void finish_block_write(struct disk_block_pos *pos, long data_pos,
                               const char *datadir, struct byte_stream *s,
                               FILE *file, bool append_allocated)
{
    pos->nPos = (unsigned int)data_pos;
    if (append_allocated && g_deferred_sync)
        append_hint_record(datadir, pos->nFile,
                           (uint64_t)data_pos + (uint64_t)s->size);
    else
        append_hint_invalidate();

    fclose(file);
    pthread_mutex_unlock(&g_file_cache_mutex);
    stream_free(s);
}

bool write_block_to_disk(struct block *b, struct disk_block_pos *pos,
                         const char *datadir,
                         const unsigned char message_start[4])
{
    /* Serialize first (outside lock) to minimize lock hold time */
    struct byte_stream s;
    stream_init(&s, 4096);
    if (!block_serialize(b, &s)) {
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: block serialization failed");
    }
    uint32_t nSize = (uint32_t)s.size;

    /* Hold mutex for entire file operation to prevent concurrent
     * read_block_from_disk from seeing partial writes or getting a
     * stale cached FILE* handle. */
    pthread_mutex_lock(&g_file_cache_mutex);
    bool append_allocated = pos->nFile < 0;
    if (!ensure_append_block_pos(pos, nSize, datadir, append_allocated)) {
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: append position allocation failed");
    }

    FILE *file = open_block_file(datadir, pos, false);
    if (!file) {
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: open_block_file failed for file=%d", pos->nFile);
    }

    struct stat opened = {0};
    unsigned long opened_links = 0;
    if (!opened_blk_file_is_safe(file, datadir, pos, &opened, &opened_links)) {
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io",
                 "write_block: refusing unsafe file=%d regular=%d nlink=%lu",
                 pos->nFile, S_ISREG(opened.st_mode),
                 opened_links);
    }

    long data_pos = 0;
    enum block_write_result write_result =
        write_block_frame(file, message_start, nSize, &s, &data_pos);
    if (write_result == BLOCK_WRITE_FTELL_FAILED) {
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: ftell failed");
    }

    if (write_result == BLOCK_WRITE_HEADER_FAILED) {
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: fwrite header failed for file=%d", pos->nFile);
    }

    if (write_result == BLOCK_WRITE_DATA_POS_RANGE) {
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: data position out of range (pos=%ld)", data_pos);
    }

    if (write_result == BLOCK_WRITE_DATA_FAILED) {
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        LOG_FAIL("disk_block_io", "write_block: fwrite block data failed (size=%zu)", s.size);
    }

    enum block_sync_result sync_result =
        flush_and_sync_block_file(file, datadir, pos);
    if (sync_result == BLOCK_SYNC_FFLUSH_FAILED) {
        fprintf(stderr, "write_block_to_disk: fflush failed: %s\n",
                strerror(errno));
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        return false;
    }
    if (sync_result == BLOCK_SYNC_DATASYNC_FAILED) {
        fprintf(stderr, "write_block_to_disk: fdatasync failed: %s\n",
                strerror(errno));
        fclose(file);
        pthread_mutex_unlock(&g_file_cache_mutex);
        stream_free(&s);
        return false;
    }

    finish_block_write(pos, data_pos, datadir, &s, file, append_allocated);
    return true;
}

bool read_block_from_disk(struct block *b, const struct disk_block_pos *pos,
                          const char *datadir)
{
    /* Delegate to pread()-based implementation — thread-safe without
     * the shared FILE* cache or mutex. All callers automatically
     * benefit from concurrent-safe reads. */
    return read_block_from_disk_pread(b, pos, datadir);
}

bool read_block_from_disk_index(struct block *b,
                                const struct block_index *pindex,
                                const char *datadir)
{
    /* Delegate to pread()-based implementation — thread-safe. */
    return read_block_from_disk_index_pread(b, pindex, datadir);
}

/* ── Thread-safe pread()-based I/O ───────────────────────────────
 * No shared state, no mutex, no FILE* cache. Safe for concurrent
 * use from any number of threads simultaneously. */

/* ── sequential readahead for an ordered walk ─────────────────────────
 *
 * The boot repair passes sort every entry they will read into (nFile,
 * nDataPos) order and then read 36 bytes from each. On flash that is fine.
 * On a 7200 rpm disk it is one head movement per block with nothing in
 * flight, and a field box spent 90 minutes of boot in D state doing exactly
 * that. The walk already knows the file and the byte range it is about to
 * cover, so it can say so before it starts reading.
 *
 * Advisory in every sense: a failure to open the file, or a platform with no
 * equivalent hint, leaves the walk exactly as fast as it was. Never an error
 * path — a readahead hint that did not happen changes nothing but timing. */
void disk_block_io_advise_range(const char *datadir, int nFile,
                               const char *prefix, int64_t offset,
                               int64_t length)
{
    if (!datadir || !datadir[0] || nFile < 0 || length <= 0)
        return;
    struct disk_block_pos pos = { .nFile = nFile, .nPos = 0 };
    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, &pos, prefix);
    int fd = block_open(path, O_RDONLY);
    if (fd < 0)
        return;
    platform_file_advise_sequential(fd, offset + length);
    platform_file_advise_willneed(fd, offset, length);
    close(fd);
}

ssize_t disk_block_pread(const char *datadir, const struct disk_block_pos *pos,

                         const char *prefix, uint8_t *buf, size_t len)
{
    if (!datadir || !pos || !buf || pos->nFile < 0)
        LOG_ERR("disk_block_io", "pread: invalid arguments (datadir=%p pos=%p buf=%p)",
                (const void *)datadir, (const void *)pos, (const void *)buf);

    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, pos, prefix);

    int fd = block_open(path, O_RDONLY);
    if (fd < 0) {
        /* Throttled per nFile (see g_open_fail_throttle rationale above). The
         * boot-time pprev-repair (block_index_integrity.c) walks EVERY had-data
         * entry through here; on a blocks-less bundle that is ~3.1M absent-file
         * opens before the snapshot repair clears the stale flags. */
        uint64_t reps = 0;
        if (log_throttle_should_emit(&g_open_fail_throttle,
                                     0u,  /* single global key (see throttle rationale above) */
                                     platform_time_wall_unix(), 60, &reps))
            fprintf(stderr, "[disk_block_io] disk_block_pread: cannot open %s "
                    "(%llu suppressed repeats since last log)\n",
                    path, (unsigned long long)reps);
        return -1;
    }

    int64_t nread = platform_positioned_read(fd, buf, len, pos->nPos);
    close(fd);
    return nread;
}

/* ── Thread-local read fd cache (pread fast path) ─────────────────────
 * read_block_from_disk_pread_profiled() open()+close()es the blk*.dat file per
 * block. During a stage drain nearly every read hits the same one or two files,
 * so keep the last-opened read fd per thread and reuse it. pread is positional
 * (no shared file offset), so a reused fd is safe without a lock. Thread-local
 * preserves the pread path's lock-free, no-shared-state contract; a
 * pthread_key destructor closes the fd when the owning thread exits.
 *
 * The cache is OPT-IN, scoped by disk_block_io_read_fd_cache_enter()/exit()
 * around the reducer's forward-fold drain. There blk*.dat files are strictly
 * append-only and never unlinked/recreated (body_fetch already wrote them; no
 * writer runs on the drive thread during the read loop), so a path-keyed fd is
 * safe. Outside that scope every reader (import, tests that rewrite a blk path,
 * bg_validation, RPC) keeps the stateless open/close so a replaced file at a
 * reused path can never be read through a stale fd. */
struct read_fd_cache {
    int  fd;
    char path[512];
};
static pthread_key_t  g_read_fd_key;
static pthread_once_t g_read_fd_once = PTHREAD_ONCE_INIT;
static _Thread_local bool g_read_fd_cache_enabled = false;

static void read_fd_cache_destroy(void *p)
{
    struct read_fd_cache *c = p;
    if (!c)
        return;
    if (c->fd >= 0)
        close(c->fd);
    free(c);
}

static void read_fd_key_init(void)
{
    (void)pthread_key_create(&g_read_fd_key, read_fd_cache_destroy);
}

static void read_fd_cache_close_locked(void)
{
    struct read_fd_cache *c = pthread_getspecific(g_read_fd_key);
    if (c && c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
        c->path[0] = '\0';
    }
}

void disk_block_io_read_fd_cache_enter(void)
{
    pthread_once(&g_read_fd_once, read_fd_key_init);
    g_read_fd_cache_enabled = true;
}

void disk_block_io_read_fd_cache_exit(void)
{
    g_read_fd_cache_enabled = false;
    pthread_once(&g_read_fd_once, read_fd_key_init);
    read_fd_cache_close_locked();
}

/* Return a read-only fd for `path`. On a thread-local cache hit *cached_out is
 * true and the caller must NOT close the fd (the cache owns it). Otherwise the
 * fd is caller-owned (close it) or -1 on open failure. */
static int read_fd_cache_get(const char *path, bool *cached_out)
{
    *cached_out = false;
    if (!g_read_fd_cache_enabled)
        return block_open(path, O_RDONLY);  /* stateless path — caller-owned fd */

    pthread_once(&g_read_fd_once, read_fd_key_init);
    struct read_fd_cache *c = pthread_getspecific(g_read_fd_key);
    if (c) {
        if (c->fd >= 0 && strcmp(c->path, path) == 0) {
            *cached_out = true;
            return c->fd;
        }
    } else {
        c = zcl_malloc(sizeof(*c), "disk_block_io/read_fd_cache");
        if (c) {
            c->fd = -1;
            c->path[0] = '\0';
            if (pthread_setspecific(g_read_fd_key, c) != 0) {
                free(c);
                c = NULL;
            }
        }
    }
    if (!c)
        return block_open(path, O_RDONLY);  /* alloc/TLS failure — caller-owned fd */
    if (c->fd >= 0)
        close(c->fd);
    c->fd = block_open(path, O_RDONLY);
    if (c->fd < 0) {
        c->path[0] = '\0';
        return -1;
    }
    snprintf(c->path, sizeof(c->path), "%s", path);
    *cached_out = true;
    return c->fd;
}

bool read_block_from_disk_pread(struct block *b,
                                const struct disk_block_pos *pos,
                                const char *datadir)
{
    return read_block_from_disk_pread_profiled(b, pos, datadir, NULL, NULL);
}

bool read_block_from_disk_pread_profiled(struct block *b,
                                         const struct disk_block_pos *pos,
                                         const char *datadir,
                                         uint64_t *read_us_out,
                                         uint64_t *parse_us_out)
{
    int64_t read_started = platform_time_monotonic_us();
    block_init(b);

    if (!datadir || !pos || pos->nFile < 0)
        LOG_FAIL("disk_block_io",
                 "read_block_pread: invalid arguments (datadir=%p pos=%p)",
                 (const void *)datadir, (const void *)pos);

    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, pos, "blk");

    bool fd_cached = false;
    int fd = read_fd_cache_get(path, &fd_cached);
    if (fd < 0) {
        /* Throttled: a blocks-less bundle would otherwise emit this per block
         * (~3.1M lines). Still logs context (the path) on the throttled emit. */
        uint64_t reps = 0;
        if (log_throttle_should_emit(&g_open_fail_throttle,
                                     0u,  /* single global key (see throttle rationale above) */
                                     platform_time_wall_unix(), 60, &reps))
            fprintf(stderr, "[disk_block_io] read_block_pread: cannot open %s "
                    "(%llu suppressed repeats since last log)\n",
                    path, (unsigned long long)reps);
        return false;
    }

    uint32_t payload_pos = pos->nPos;
    size_t bufsize = 2000000u;
    if (!disk_block_locate_payload(fd, pos, &payload_pos, &bufsize)) {
        if (!fd_cached) close(fd);
        uint64_t reps = 0;  /* throttled: see g_locate_fail_throttle above */
        if (log_throttle_should_emit(&g_locate_fail_throttle, 0u,
                                     platform_time_wall_unix(), 60, &reps))
            fprintf(stderr, "read_block_pread_no_frame: file=%d pos=%u "
                    "(no frame at pos-8 or pos; %llu suppressed)\n",
                    pos->nFile, pos->nPos, (unsigned long long)reps);
        return false;  // raw-return-ok:throttled-named-refusal-replaces-LOG_FAIL
    }

    unsigned char *buf = zcl_malloc(bufsize, "read_block_pread_buf");
    if (!buf) {
        if (!fd_cached) close(fd);
        LOG_FAIL("disk_block_io", "read_block_pread: malloc(%zu) failed", bufsize);
    }

    int64_t nread = platform_positioned_read(fd, buf, bufsize, payload_pos);
    if (!fd_cached) close(fd);

    if (nread <= 0) {
        free(buf);
        LOG_FAIL("disk_block_io", "read_block_pread: positioned read returned %lld for file=%d pos=%u",
                 (long long)nread, pos->nFile, payload_pos);
    }
    if (read_us_out)
        *read_us_out = (uint64_t)(platform_time_monotonic_us() - read_started);

    int64_t parse_started = platform_time_monotonic_us();
    struct byte_stream s;
    stream_init_from_data(&s, buf, (size_t)nread);
    bool ok = block_deserialize(b, &s);
    stream_free(&s);
    free(buf);
    if (parse_us_out)
        *parse_us_out = (uint64_t)(platform_time_monotonic_us() - parse_started);
    return ok;
}

bool read_block_from_disk_index_pread(struct block *b,
                                      const struct block_index *pindex,
                                      const char *datadir)
{
    if (!pindex)
        LOG_FAIL("disk_block_io", "read_block_from_disk_index_pread: pindex is NULL");

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!block_index_disk_pos_snapshot(pindex, &pos, NULL))
        return false;

    if (!read_block_from_disk_pread(b, &pos, datadir)) {
        /* Throttled per nFile (see g_open_fail_throttle rationale above). */
        uint64_t reps = 0;
        if (log_throttle_should_emit(&g_readfail_throttle,
                                     0u,  /* single global key (see throttle rationale above) */
                                     platform_time_wall_unix(), 60, &reps))
            fprintf(stderr, "read_block_pread_fail: h=%d file=%d pos=%u "
                    "(%llu suppressed repeats since last log)\n",
                    pindex->nHeight, pos.nFile, pos.nPos,
                    (unsigned long long)reps);
        return false;
    }

    struct uint256 block_hash;
    block_get_hash(b, &block_hash);
    if (pindex->phashBlock &&
        uint256_cmp(&block_hash, pindex->phashBlock) != 0) {
        char got[65], want[65];
        uint256_get_hex(&block_hash, got);
        uint256_get_hex(pindex->phashBlock, want);
        fprintf(stderr, "read_block_pread_hash_mismatch: h=%d got=%.16s want=%.16s\n",
                pindex->nHeight, got, want);
        block_free(b);
        return false;
    }
    return true;
}

bool block_index_have_data_readable(const struct block_index *pindex,
                                    const char *datadir)
{
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!pindex || !datadir || !pindex->phashBlock ||
        !block_index_disk_pos_snapshot(pindex, &pos, NULL))
        return false;

    struct block blk;
    block_init(&blk);
    bool ok = read_block_from_disk_index_pread(&blk, pindex, datadir);
    block_free(&blk);
    return ok;
}

bool block_index_set_have_data_verified(struct block_index *pindex,
                                        const struct disk_block_pos *pos,
                                        const char *datadir)
{
    if (!pindex || !pos || !datadir || pos->nFile < 0)
        LOG_FAIL("disk_block_io",
                 "set_have_data_verified: invalid argument (pindex=%p pos=%p)",
                 (void *)pindex, (const void *)pos);
    if (!pindex->phashBlock)
        LOG_FAIL("disk_block_io",
                 "set_have_data_verified: missing block hash at h=%d",
                 pindex->nHeight);

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_pread(&blk, pos, datadir)) {
        block_free(&blk);
        LOG_FAIL("disk_block_io",
                 "set_have_data_verified: read-back failed h=%d file=%d pos=%u",
                 pindex->nHeight, pos->nFile, pos->nPos);
    }

    struct uint256 got;
    block_get_hash(&blk, &got);
    bool hash_ok = uint256_cmp(&got, pindex->phashBlock) == 0;
    block_free(&blk);
    if (!hash_ok) {
        char got_hex[65], want_hex[65];
        uint256_get_hex(&got, got_hex);
        uint256_get_hex(pindex->phashBlock, want_hex);
        LOG_FAIL("disk_block_io",
                 "set_have_data_verified: hash mismatch h=%d got=%.16s want=%.16s",
                 pindex->nHeight, got_hex, want_hex);
    }

    block_index_disk_pos_store(pindex, pos->nFile, pos->nPos);
    block_index_status_fetch_or(pindex, BLOCK_HAVE_DATA);
    disk_block_io_fire_have_data_hook();
    return true;
}
