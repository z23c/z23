/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Download and verify offered state with durable resume. */
#define _POSIX_C_SOURCE 200809L
#include "config/state_offer_link_receive.h"
#if defined(_WIN32)
enum sol_receive_result state_offer_link_receive(const struct rom_fetch_manifest *m,
    const char *out_dir, sol_object_reader reader, void *reader_ctx,
    rom_fetch_progress_cb progress, void *progress_ctx, char *landed, size_t landed_cap)
{
    (void)m; (void)out_dir; (void)reader; (void)reader_ctx;
    (void)progress; (void)progress_ctx;
    if (landed && landed_cap) landed[0] = 0;
    return SOL_RECEIVE_UNAVAILABLE;
}
#else
#include "base/safe_alloc.h"
#include "net/rom_journal.h"
#include "net/rom_seed.h"
#include "platform/rename_compat.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static enum sol_receive_result read_result(enum sol_read_result r)
{
    switch (r) {
    case SOL_READ_OK: return SOL_RECEIVE_OK;
    case SOL_READ_UNAVAILABLE: return SOL_RECEIVE_UNAVAILABLE;
    case SOL_READ_BAD_DATA: return SOL_RECEIVE_BAD_DATA;
    case SOL_READ_CANCELLED: return SOL_RECEIVE_CANCELLED;
    }
    return SOL_RECEIVE_LOCAL_IO;
}
static bool io_at(int fd, uint8_t *buf, size_t len, off_t off, bool write_data)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write_data ? pwrite(fd, buf + done, len - done, off + (off_t)done)
                               : pread(fd, buf + done, len - done, off + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static uint32_t chunk_size(const struct rom_fetch_manifest *m, uint32_t i)
{
    uint64_t left = m->size_bytes - (uint64_t)i * m->chunk_size;
    return left < m->chunk_size ? (uint32_t)left : m->chunk_size;
}
static bool resume_valid(int fd, struct rom_journal *journal,
                         const struct rom_fetch_manifest *m, uint8_t *buf,
                         const uint8_t (*hashes)[32])
{
    for (uint32_t i = 0; i < m->num_chunks; ++i) {
        if (!rom_journal_is_done(journal, i)) continue;
        uint32_t n = chunk_size(m, i);
        if (!io_at(fd, buf, n, (off_t)((uint64_t)i * m->chunk_size), false) ||
            !rom_fetch_verify_chunk(buf, n, hashes[i])) return false;
    }
    return true;
}
static enum sol_receive_result fetch_chunks(int fd, struct rom_journal *j,
    const struct rom_fetch_manifest *m, uint8_t *buf, const uint8_t (*hashes)[32],
    sol_object_reader reader, void *ctx, rom_fetch_progress_cb progress, void *progress_ctx)
{
    uint64_t done_bytes = 0;
    for (uint32_t i = 0; i < m->num_chunks; ++i) {
        uint32_t want = chunk_size(m, i), got = 0;
        if (!rom_journal_is_done(j, i)) {
            enum sol_receive_result r = read_result(reader(ctx, SOL_OBJECT_CHUNK, m->chunk_root,
                                                            i, buf, want, &got));
            if (r != SOL_RECEIVE_OK) return r;
            if (got != want || !rom_fetch_verify_chunk(buf, got, hashes[i])) return SOL_RECEIVE_BAD_DATA;
            if (!io_at(fd, buf, got, (off_t)((uint64_t)i * m->chunk_size), true) ||
                fdatasync(fd) || !rom_journal_mark(j, i)) return SOL_RECEIVE_LOCAL_IO;
        }
        done_bytes += want;
        if (progress && !progress(rom_journal_count_done(j), m->num_chunks, done_bytes, progress_ctx))
            return SOL_RECEIVE_CANCELLED;
    }
    return SOL_RECEIVE_OK;
}

static bool same_directory(int fd, const char *path)
{
    struct stat a, b;
    return !fstat(fd, &a) && !lstat(path, &b) && S_ISDIR(b.st_mode) &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static bool existing_final(int dir, const char *path, const struct rom_fetch_manifest *m)
{
    struct stat before, after;
    int fd = openat(dir, m->filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && before.st_nlink == 1 && !(before.st_mode & 0222) &&
        rom_fetch_verify_file(path, m) && !fstatat(dir, m->filename, &after, AT_SYMLINK_NOFOLLOW) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && !fsync(fd);
    close(fd);
    return ok;
}

struct receive_job {
    const struct rom_fetch_manifest *m;
    const char *dir_path;
    sol_object_reader reader;
    void *reader_ctx;
    rom_fetch_progress_cb progress;
    void *progress_ctx;
    char part[ROM_FETCH_NAME_MAX + 16], journal_name[ROM_FETCH_NAME_MAX + 32];
    char journal_path[1200], final_path[1200];
    int dir, fd;
    struct rom_journal *journal;
    uint8_t *buf, (*hashes)[32];
    bool readonly, published;
};
static bool prepare_paths(struct receive_job *s, size_t landed_cap)
{
    return snprintf(s->part, sizeof(s->part), "%s.part", s->m->filename) < (int)sizeof(s->part) &&
        snprintf(s->journal_name, sizeof(s->journal_name), "%s.journal", s->part) < (int)sizeof(s->journal_name) &&
        snprintf(s->journal_path, sizeof(s->journal_path), "%s/%s", s->dir_path, s->journal_name) < (int)sizeof(s->journal_path) &&
        snprintf(s->final_path, sizeof(s->final_path), "%s/%s", s->dir_path, s->m->filename) < (int)sizeof(s->final_path) &&
        strlen(s->final_path) + 1 <= landed_cap;
}
static bool journal_path_safe(struct receive_job *s)
{
    struct stat st;
    if (fstatat(s->dir, s->journal_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
        return S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1;
    return errno == ENOENT;
}
static struct rom_journal *open_journal(struct receive_job *s)
{
    return rom_journal_open(s->journal_path, s->m->chunk_root, s->m->whole_sha3,
                            s->m->chunk_size, s->m->num_chunks);
}
static bool open_partial(struct receive_job *s)
{
    struct stat st;
    s->fd = openat(s->dir, s->part, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    return s->fd >= 0 && !fstat(s->fd, &st) && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1;
}
static bool reset_resume(struct receive_job *s)
{
    rom_journal_close(s->journal); s->journal = NULL;
    if (!same_directory(s->dir, s->dir_path) || !rom_journal_discard(s->journal_path)) return false;
    s->journal = open_journal(s);
    return s->journal != NULL;
}
static bool prepare_journal(struct receive_job *s)
{
    if (!journal_path_safe(s) || !same_directory(s->dir, s->dir_path)) return false;
    s->journal = open_journal(s);
    if (!s->journal || !open_partial(s)) return false;
    if (rom_journal_count_done(s->journal) &&
        !resume_valid(s->fd, s->journal, s->m, s->buf, (const uint8_t (*)[32])s->hashes) &&
        !reset_resume(s)) return false;
    return rom_journal_count_done(s->journal) || (!ftruncate(s->fd, 0) && !fdatasync(s->fd));
}
static bool verify_partial(struct receive_job *s)
{
    char path[1200];
    if (ftruncate(s->fd, (off_t)s->m->size_bytes) || fdatasync(s->fd) ||
        snprintf(path, sizeof(path), "%s/%s", s->dir_path, s->part) >= (int)sizeof(path)) return false;
    return same_directory(s->dir, s->dir_path) && rom_fetch_verify_file(path, s->m) &&
        same_directory(s->dir, s->dir_path) && !fchmod(s->fd, 0444);
}
static bool publish_partial(struct receive_job *s)
{
    struct stat a, b;
    if (fstat(s->fd, &a) || fstatat(s->dir, s->part, &b, AT_SYMLINK_NOFOLLOW) ||
        a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_nlink != 1 || fdatasync(s->fd) ||
        platform_renameat_noreplace(s->dir, s->part, s->dir, s->m->filename)) return false;
    s->published = true;
    if (fsync(s->dir)) return false;
    rom_journal_close(s->journal); s->journal = NULL;
    return rom_journal_discard(s->journal_path) && !fsync(s->dir) && same_directory(s->dir, s->dir_path);
}
static bool publish_file(struct receive_job *s)
{
    if (!verify_partial(s)) return false;
    s->readonly = true;
    return publish_partial(s);
}
static enum sol_receive_result receive_body(struct receive_job *s)
{
    s->buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "state_offer_receive_buffer");
    s->hashes = zcl_malloc(ROM_SEED_MAX_CHUNKS * 32u, "state_offer_receive_hashes");
    if (!s->buf || !s->hashes) return SOL_RECEIVE_LOCAL_IO;
    uint32_t len = 0, count = 0;
    enum sol_receive_result r = read_result(s->reader(s->reader_ctx, SOL_OBJECT_MANIFEST,
        s->m->chunk_root, 0, s->buf, ROM_SEED_MANIFEST_BLOB_MAX, &len));
    if (r != SOL_RECEIVE_OK) return r;
    if (len > ROM_SEED_MANIFEST_BLOB_MAX || !rom_fetch_parse_manifest_blob(s->buf, len,
        s->m->chunk_root, s->hashes, ROM_SEED_MAX_CHUNKS, &count) || count != s->m->num_chunks)
        return SOL_RECEIVE_BAD_DATA;
    if (!prepare_journal(s)) return SOL_RECEIVE_LOCAL_IO;
    r = fetch_chunks(s->fd, s->journal, s->m, s->buf, (const uint8_t (*)[32])s->hashes,
                     s->reader, s->reader_ctx, s->progress, s->progress_ctx);
    if (r != SOL_RECEIVE_OK) return r;
    return publish_file(s) ? SOL_RECEIVE_OK : SOL_RECEIVE_LOCAL_IO;
}
static bool receive_args_valid(const struct rom_fetch_manifest *m, const char *out_dir,
                               sol_object_reader reader, char *landed, size_t landed_cap)
{
    if (!m || !out_dir || !reader || !landed || !landed_cap) return false;
    return m->filename[0] && memchr(m->filename, '\0', sizeof(m->filename)) && rom_fetch_manifest_sane(m);
}
static enum sol_receive_result receive_opened(struct receive_job *s)
{
    struct stat st;
    if (fstat(s->dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0022) ||
        !same_directory(s->dir, s->dir_path)) return SOL_RECEIVE_LOCAL_IO;
    if (!fstatat(s->dir, s->m->filename, &st, AT_SYMLINK_NOFOLLOW)) {
        if (existing_final(s->dir, s->final_path, s->m) &&
            same_directory(s->dir, s->dir_path) && !fsync(s->dir)) return SOL_RECEIVE_OK;
        return SOL_RECEIVE_LOCAL_IO;
    }
    return errno == ENOENT ? receive_body(s) : SOL_RECEIVE_LOCAL_IO;
}
static void receive_close(struct receive_job *s)
{
    if (s->fd >= 0) {
        if (s->readonly && !s->published) (void)fchmod(s->fd, 0600);
        close(s->fd);
    }
    rom_journal_close(s->journal); free(s->hashes); free(s->buf); close(s->dir);
}
enum sol_receive_result state_offer_link_receive(const struct rom_fetch_manifest *m,
    const char *out_dir, sol_object_reader reader, void *reader_ctx,
    rom_fetch_progress_cb progress, void *progress_ctx, char *landed, size_t landed_cap)
{
    if (landed && landed_cap) landed[0] = '\0';
    if (!receive_args_valid(m, out_dir, reader, landed, landed_cap)) return SOL_RECEIVE_LOCAL_IO;
    struct receive_job s = {.m = m, .dir_path = out_dir, .reader = reader, .reader_ctx = reader_ctx,
        .progress = progress, .progress_ctx = progress_ctx, .fd = -1, .dir = -1};
    if (!prepare_paths(&s, landed_cap)) return SOL_RECEIVE_LOCAL_IO;
    s.dir = open(out_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (s.dir < 0) return SOL_RECEIVE_LOCAL_IO;
    enum sol_receive_result r = receive_opened(&s);
    if (r == SOL_RECEIVE_OK) memcpy(landed, s.final_path, strlen(s.final_path) + 1);
    receive_close(&s);
    return r;
}
#endif
