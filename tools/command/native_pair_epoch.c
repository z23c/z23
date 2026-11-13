/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ops.mesh.device.pair.export and ops.mesh.device.pair.import.
 * Export copies ONE client pairing epoch directory (state_dir/<peer>-e<N>:
 * the client route, the epoch profile and any secret files) into a
 * deterministic length-prefixed record stream whose header records the
 * original absolute profile path, so an import on another host can rewrite
 * client.json's directory to the destination root. Import verifies the
 * archive against a caller-supplied sha256, materializes the epoch
 * owner-only (0700 directories, 0600 files) under a caller-supplied state
 * root and refuses to overwrite. Pure filesystem + sha256: no network, no
 * ssh, no fork/exec; no secret byte is ever read into a reply or a log. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "command/native_pair_common.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "util/authority_receipt.h"
#include "util/log_macros.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)

#define PE_TAG "native.pair_epoch"
#define PE_NAME_MAX 512
#define PE_DEPTH_MAX 4
#define PE_FILES_MAX 256
#define PE_FILE_MAX (32u << 20)
#define PE_TOTAL_MAX (64u << 20)
#define PE_EPOCH_MAX 999999u
#define PE_MAGIC "Z23PEA01"
#define PE_ROUTE_TEXT_MAX 4096

static void pe_fail(struct zcl_command_reply *reply, const char *code, const char *phase, const char *message,
                    bool mutated)
{
    LOG_ERROR(PE_TAG, "%s (%s): %s", code, phase, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED, code, phase, false, mutated,
                           message, "ops mesh device pair status lists the epochs each side holds");
}

/* ── bounded byte buffer: the whole archive is assembled, hashed, written ── */

struct pe_buf {
    uint8_t *bytes;
    size_t len, cap;
};

static bool pe_buf_put(struct pe_buf *buf, const void *data, size_t n)
{
    if (!n) return true;
    if (n > PE_TOTAL_MAX || buf->len + n > PE_TOTAL_MAX) LOG_FAIL(PE_TAG, "the archive exceeds its %u MiB bound", (unsigned)(PE_TOTAL_MAX >> 20));
    if (buf->len + n > buf->cap) {
        size_t cap = buf->cap ? buf->cap : 4096;
        while (cap < buf->len + n) cap *= 2;
        uint8_t *grown = zcl_realloc(buf->bytes, cap, "pair_epoch.archive");
        if (!grown) LOG_FAIL(PE_TAG, "an archive buffer of %zu bytes could not be grown", cap);
        buf->bytes = grown;
        buf->cap = cap;
    }
    memcpy(buf->bytes + buf->len, data, n);
    buf->len += n;
    return true;
}

static bool pe_buf_u32(struct pe_buf *buf, uint32_t v)
{
    uint8_t wire[4];
    zcl_write_u32_le(wire, v);
    return pe_buf_put(buf, wire, sizeof(wire));
}

static bool pe_buf_u64(struct pe_buf *buf, uint64_t v)
{
    uint8_t wire[8];
    zcl_write_u64_le(wire, v);
    return pe_buf_put(buf, wire, sizeof(wire));
}

static bool pe_buf_str(struct pe_buf *buf, const char *text)
{
    size_t n = strlen(text);
    if (n > 0xffffu) LOG_FAIL(PE_TAG, "an archive field of %zu bytes exceeds the 65535 byte field bound", n);
    return pe_buf_u32(buf, (uint32_t)n) && pe_buf_put(buf, text, n);
}

/* ── export: bounded walk of one epoch directory ─────────────────────── */

struct pe_file {
    char *name;
    uint32_t mode;
    uint64_t size;
};

struct pe_scan {
    struct pe_file *files;
    size_t count, cap;
    uint64_t total;
};

static void pe_scan_free(struct pe_scan *scan)
{
    for (size_t i = 0; i < scan->count; ++i) free(scan->files[i].name);
    free(scan->files);
    scan->files = NULL;
    scan->count = scan->cap = 0;
}

static bool pe_entry_ok(const char *name)
{
    size_t n = strlen(name);
    if (!n || n >= PE_NAME_MAX || !strcmp(name, ".") || !strcmp(name, "..")) return false;
    for (const char *p = name; *p; ++p)
        if ((unsigned char)*p < 0x20 || *p == '/') return false;
    return true;
}

static bool pe_walk(const char *dir, const char *rel, int depth, struct pe_scan *scan);

static bool pe_scan_push(struct pe_scan *scan, const char *name, const struct stat *info)
{
    if (scan->count >= PE_FILES_MAX || (uint64_t)info->st_size > PE_FILE_MAX ||
        scan->total + (uint64_t)info->st_size > PE_TOTAL_MAX)
        LOG_FAIL(PE_TAG, "the epoch holds more than %d files or more than %u MiB; it cannot be exported in one archive",
                 (int)PE_FILES_MAX, (unsigned)(PE_TOTAL_MAX >> 20));
    if (scan->count == scan->cap) {
        size_t cap = scan->cap ? scan->cap * 2 : 16;
        struct pe_file *grown = zcl_realloc(scan->files, cap * sizeof(*grown), "pair_epoch.file_list");
        if (!grown) LOG_FAIL(PE_TAG, "a file list of %zu entries could not be grown", cap);
        scan->files = grown;
        scan->cap = cap;
    }
    struct pe_file *slot = &scan->files[scan->count];
    slot->name = zcl_malloc(strlen(name) + 1, "pair_epoch.file_name");
    if (!slot->name) LOG_FAIL(PE_TAG, "the name of %s could not be recorded", name);
    memcpy(slot->name, name, strlen(name) + 1);
    slot->mode = (uint32_t)(info->st_mode & 07777);
    slot->size = (uint64_t)info->st_size;
    scan->total += slot->size;
    ++scan->count;
    return true;
}

static bool pe_visit_entry(const char *dir, const char *rel, const char *name, int depth, struct pe_scan *scan)
{
    char path[PAIR_PATH_MAX + PE_NAME_MAX], child[PE_NAME_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    int cn = snprintf(child, sizeof(child), "%s%s%s", rel, rel[0] ? "/" : "", name);
    struct stat info;
    if (n < 0 || (size_t)n >= sizeof(path) || cn < 0 || (size_t)cn >= sizeof(child) || !pe_entry_ok(name)) {
        LOG_ERROR(PE_TAG, "%s/%s does not fit an archive record name", dir, name);
        return false;
    }
    if (lstat(path, &info) != 0) {
        LOG_ERROR(PE_TAG, "%s could not be stat'd (errno %d)", path, errno);
        return false;
    }
    if (S_ISDIR(info.st_mode)) return pe_walk(path, child, depth + 1, scan);
    if (S_ISREG(info.st_mode)) return pe_scan_push(scan, child, &info);
    LOG_ERROR(PE_TAG, "%s is neither a regular file nor a directory; symlinked or special epoch entries are refused", path);
    return false;
}

static bool pe_walk(const char *dir, const char *rel, int depth, struct pe_scan *scan)
{
    if (depth > PE_DEPTH_MAX) LOG_FAIL(PE_TAG, "%s nests deeper than %d levels", dir, (int)PE_DEPTH_MAX);
    DIR *handle = opendir(dir);
    if (!handle) LOG_FAIL(PE_TAG, "%s is unreadable (errno %d)", dir, errno);
    bool ok = true;
    for (const struct dirent *entry = readdir(handle); ok && entry; entry = readdir(handle)) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        ok = pe_visit_entry(dir, rel, entry->d_name, depth, scan);
    }
    closedir(handle);
    return ok;
}

static int pe_file_cmp(const void *a, const void *b)
{
    return strcmp(((const struct pe_file *)a)->name, ((const struct pe_file *)b)->name);
}

/* Best-effort rollback of a half-materialized epoch directory after a
 * failed import, so the next attempt is not stuck behind
 * IMPORT_EPOCH_EXISTS. Depth-capped like the walk it mirrors; every entry
 * here was created by pe_write_record from archive-validated names, so no
 * symlink or special file can be present. */
static void pe_rmtree(const char *dir, int depth)
{
    if (depth > PE_DEPTH_MAX) return;
    DIR *handle = opendir(dir);
    if (!handle) return;
    char child[PAIR_PATH_MAX + PE_NAME_MAX + 8];
    struct dirent *entry;
    while ((entry = readdir(handle)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        int n = snprintf(child, sizeof(child), "%s/%s", dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;
        struct stat info;
        if (lstat(child, &info) == 0 && S_ISDIR(info.st_mode)) pe_rmtree(child, depth + 1);
        else unlink(child);
    }
    closedir(handle);
    rmdir(dir);
}

static bool pe_read_file(const char *path, uint64_t size, struct pe_buf *buf)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) LOG_FAIL(PE_TAG, "%s is unreadable (errno %d)", path, errno);
    bool ok = true;
    uint64_t done = 0;
    while (ok && done < size) {
        uint8_t block[65536];
        uint64_t want = size - done < sizeof(block) ? size - done : sizeof(block);
        ssize_t got;
        do got = read(fd, block, (size_t)want); while (got < 0 && errno == EINTR);
        if (got <= 0) {
            LOG_ERROR(PE_TAG, "%s ended short of its recorded %llu bytes", path, (unsigned long long)size);
            ok = false;
            break;
        }
        ok = pe_buf_put(buf, block, (size_t)got);
        done += (uint64_t)got;
    }
    close(fd);
    return ok;
}

/* ── the record stream: magic, header, sorted name/mode/size/bytes rows ── */

struct pe_header {
    char origin[PAIR_PATH_MAX], peer[PAIR_NAME_MAX], route_id[64];
    uint32_t epoch;
};

struct pe_record {
    char name[PE_NAME_MAX];
    uint32_t mode;
    uint64_t offset, size;
};

static bool pe_assemble(struct pe_buf *buf, const struct pe_header *head, const struct pe_scan *scan, const char *dir)
{
    bool ok = pe_buf_put(buf, PE_MAGIC, 8) && pe_buf_str(buf, head->origin) && pe_buf_str(buf, head->peer) &&
              pe_buf_str(buf, head->route_id) && pe_buf_u32(buf, head->epoch) &&
              pe_buf_u32(buf, (uint32_t)scan->count);
    for (size_t i = 0; ok && i < scan->count; ++i) {
        const struct pe_file *file = &scan->files[i];
        char path[PAIR_PATH_MAX + PE_NAME_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, file->name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            LOG_ERROR(PE_TAG, "%s does not fit an epoch path", file->name);
            return false;
        }
        ok = pe_buf_str(buf, file->name) && pe_buf_u32(buf, file->mode) && pe_buf_u64(buf, file->size) &&
             (file->size == 0 || pe_read_file(path, file->size, buf));
    }
    return ok;
}

static bool pe_write_dest(const char *dest, const uint8_t *bytes, size_t len)
{
    int fd = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) LOG_FAIL(PE_TAG, "%s could not be created exclusively (errno %d)", dest, errno);
    bool ok = true;
    for (size_t done = 0; ok && done < len;) {
        ssize_t put = write(fd, bytes + done, len - done);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) {
            LOG_ERROR(PE_TAG, "%s could not take byte %zu (errno %d)", dest, done, errno);
            ok = false;
            break;
        }
        done += (size_t)put;
    }
    close(fd);
    return ok && chmod(dest, 0600) == 0;
}

/* ── bounded reader for the import side ──────────────────────────────── */

struct pe_view {
    const uint8_t *bytes;
    size_t len, pos;
};

static bool pe_take(struct pe_view *r, const void **out, size_t n)
{
    if (n > r->len - r->pos) LOG_FAIL(PE_TAG, "the archive ended %zu bytes short", n - (r->len - r->pos));
    *out = r->bytes + r->pos;
    r->pos += n;
    return true;
}

static bool pe_take_u32(struct pe_view *r, uint32_t *out)
{
    const uint8_t *b;
    if (!pe_take(r, (const void **)&b, 4)) return false;
    *out = zcl_read_u32_le(b);
    return true;
}

static bool pe_take_u64(struct pe_view *r, uint64_t *out)
{
    const uint8_t *b;
    if (!pe_take(r, (const void **)&b, 8)) return false;
    *out = zcl_read_u64_le(b);
    return true;
}

static bool pe_take_str(struct pe_view *r, char *out, size_t cap)
{
    uint32_t n;
    const uint8_t *b;
    if (!pe_take_u32(r, &n)) return false;
    if (n >= cap || !pe_take(r, (const void **)&b, n)) {
        LOG_FAIL(PE_TAG, "an archive field of %u bytes is truncated or does not fit %zu", (unsigned)n, cap);
        return false; /* b is unassigned here; the old fall-through read it
                        uninitialized and could write past cap */
    }
    memcpy(out, b, n);
    out[n] = 0;
    return true;
}

static bool pe_component_ok(const char *start, size_t part)
{
    return part > 0 && part < PE_NAME_MAX && strncmp(start, ".", part) && strncmp(start, "..", part);
}

static bool pe_name_ok(const char *name)
{
    size_t len = strlen(name);
    if (!len || len >= PE_NAME_MAX || name[0] == '/') return false;
    const char *start = name;
    for (const char *p = name;; ++p) {
        bool boundary = !*p || *p == '/';
        if (!boundary && (*p == 0x7f || (unsigned char)*p < 0x20)) return false;
        if (!boundary) continue;
        if (!pe_component_ok(start, (size_t)(p - start))) return false;
        if (!*p) return true;
        start = p + 1;
    }
}

static bool pe_header_fields(struct pe_view *r, struct pe_header *head, uint32_t *rows)
{
    const void *magic = NULL;
    bool ok = pe_take(r, &magic, 8) && !memcmp(magic, PE_MAGIC, 8) && pe_take_str(r, head->origin, sizeof(head->origin)) &&
              pe_take_str(r, head->peer, sizeof(head->peer)) && pe_take_str(r, head->route_id, sizeof(head->route_id)) &&
              pe_take_u32(r, &head->epoch) && pe_take_u32(r, rows);
    if (!ok) LOG_FAIL(PE_TAG, "the archive header is truncated or not a %s archive", PE_MAGIC);
    return true;
}

static bool pe_header_valid(const struct pe_header *head, uint32_t rows)
{
    if (!pair_name_ok(head->peer) || head->epoch < 1 || head->epoch > PE_EPOCH_MAX ||
        strlen(head->route_id) >= sizeof(head->route_id) || (head->origin[0] && !pair_path_ok(head->origin)))
        LOG_FAIL(PE_TAG, "the archive header names an invalid peer, epoch, route id or origin path");
    if (rows > PE_FILES_MAX)
        LOG_FAIL(PE_TAG, "the archive declares %u records, above the %d row bound", (unsigned)rows, (int)PE_FILES_MAX);
    return true;
}

static bool pe_parse_records(struct pe_view *r, uint32_t rows, struct pe_record *records)
{
    uint64_t total = 0;
    for (uint32_t i = 0; i < rows; ++i) {
        const void *raw = NULL;
        if (!pe_take_str(r, records[i].name, sizeof(records[i].name)) || !pe_name_ok(records[i].name) ||
            !pe_take_u32(r, &records[i].mode) || !pe_take_u64(r, &records[i].size) ||
            records[i].size > PE_FILE_MAX || total + records[i].size > PE_TOTAL_MAX ||
            !pe_take(r, &raw, (size_t)records[i].size))
            LOG_FAIL(PE_TAG, "archive record %u is malformed, oversized or names an unsafe path", (unsigned)i);
        records[i].offset = r->pos - records[i].size;
        total += records[i].size;
    }
    return true;
}

static bool pe_parse(const uint8_t *bytes, size_t len, struct pe_header *head, struct pe_record **out, uint32_t *rows_out)
{
    struct pe_view r = {.bytes = bytes, .len = len};
    uint32_t rows = 0;
    if (!pe_header_fields(&r, head, &rows)) return false;
    if (!pe_header_valid(head, rows)) return false;
    struct pe_record *records = zcl_calloc(rows, sizeof(*records), "pair_epoch.records");
    if (!records) LOG_FAIL(PE_TAG, "%u archive records could not be indexed", (unsigned)rows);
    if (!pe_parse_records(&r, rows, records)) {
        free(records);
        return false;
    }
    *out = records;
    *rows_out = rows;
    return true;
}

/* ── import: materialize owner-only under the caller's state root ────── */

/* The caller's state root is created owner-only when absent; existing roots are kept. */
static bool pe_ensure_root(const char *root)
{
    char path[PAIR_PATH_MAX];
    size_t n = strlen(root);
    if (!n || n >= sizeof(path)) LOG_FAIL(PE_TAG, "the state root does not fit a bounded path");
    memcpy(path, root, n + 1);
    for (char *p = path + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            LOG_FAIL(PE_TAG, "%s could not be created owner-private (errno %d)", path, errno);
        *p = '/';
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        LOG_FAIL(PE_TAG, "%s could not be created owner-private (errno %d)", path, errno);
    return true;
}

static bool pe_mkdir_parents(const char *epoch_dir, const char *name)
{
    char path[PAIR_PATH_MAX + PE_NAME_MAX];
    int n = snprintf(path, sizeof(path), "%s/", epoch_dir);
    if (n < 0 || (size_t)n + strlen(name) >= sizeof(path))
        LOG_FAIL(PE_TAG, "%s/%s does not fit a bounded path", epoch_dir, name);
    const char *p = name;
    for (;;) {
        const char *slash = strchr(p, '/');
        if (!slash) return true;
        size_t used = strlen(path);
        if (used + (size_t)(slash - p) + 2 > sizeof(path)) LOG_FAIL(PE_TAG, "%s nests past the bounded path", path);
        memcpy(path + used, p, (size_t)(slash - p));
        path[used + (slash - p)] = 0;
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            LOG_FAIL(PE_TAG, "%s could not be created owner-private (errno %d)", path, errno);
        path[used + (slash - p)] = '/';
        path[used + (slash - p) + 1] = 0;
        p = slash + 1;
    }
}

static bool pe_write_record(const char *epoch_dir, const char *name, const uint8_t *bytes, size_t len)
{
    if (!pe_mkdir_parents(epoch_dir, name)) return false;
    char path[PAIR_PATH_MAX + PE_NAME_MAX + 8];
    int n = snprintf(path, sizeof(path), "%s/%s", epoch_dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) LOG_FAIL(PE_TAG, "%s/%s does not fit a bounded path", epoch_dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) LOG_FAIL(PE_TAG, "%s could not be created owner-only (errno %d)", path, errno);
    bool ok = true;
    for (size_t done = 0; ok && done < len;) {
        ssize_t put = write(fd, bytes + done, len - done);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) {
            LOG_ERROR(PE_TAG, "%s could not take byte %zu (errno %d)", path, done, errno);
            ok = false;
            break;
        }
        done += (size_t)put;
    }
    close(fd);
    return ok && chmod(path, 0600) == 0;
}

/* The whole point of the archive header: the epoch arrives bound to the client
 * host's profile path and leaves bound to the destination host's own path. */
static bool pe_rebind_directory(const uint8_t *bytes, size_t len, const char *directory, char *out, size_t cap)
{
    struct json_value route = {0}, fresh = {0};
    if (!json_read(&route, (const char *)bytes, len) || route.type != JSON_OBJ) {
        json_free(&route);
        LOG_FAIL(PE_TAG, "the archive's client route is not a JSON object");
    }
    json_set_object(&fresh);
    bool ok = true;
    for (size_t i = 0; ok && i < route.num_children; ++i)
        ok = !strcmp(route.keys[i], "directory") ? json_push_kv_str(&fresh, "directory", directory)
                                                 : json_push_kv(&fresh, route.keys[i], &route.children[i]);
    ok = ok && json_write(&fresh, out, cap) > 0;
    json_free(&route);
    json_free(&fresh);
    if (!ok) LOG_FAIL(PE_TAG, "the rewritten client route did not fit its %zu byte buffer", cap);
    return true;
}

static bool pe_read_exact(int fd, uint8_t *bytes, size_t size, const char *path)
{
    size_t done = 0;
    while (done < size) {
        ssize_t got;
        do got = read(fd, bytes + done, size - done); while (got < 0 && errno == EINTR);
        if (got <= 0) {
            LOG_ERROR(PE_TAG, "%s ended short of its %zu bytes", path, size);
            return false;
        }
        done += (size_t)got;
    }
    ssize_t extra;
    do extra = read(fd, bytes + size, 1); while (extra < 0 && errno == EINTR);
    if (extra != 0) LOG_ERROR(PE_TAG, "%s grew past its %zu recorded bytes while it was read", path, size);
    return extra == 0;
}

static bool pe_read_all(const char *path, uint8_t **out, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (fd < 0) LOG_FAIL(PE_TAG, "%s is unreadable (errno %d)", path, errno);
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 || (uint64_t)info.st_size > PE_TOTAL_MAX) {
        close(fd);
        LOG_FAIL(PE_TAG, "%s is not a regular file within the %u MiB archive bound", path, (unsigned)(PE_TOTAL_MAX >> 20));
    }
    size_t size = (size_t)info.st_size;
    uint8_t *bytes = zcl_malloc(size + 1, "pair_epoch.archive_input");
    if (!bytes) {
        close(fd);
        LOG_FAIL(PE_TAG, "a %zu byte archive could not be read into memory", size);
    }
    bool ok = pe_read_exact(fd, bytes, size, path);
    close(fd);
    if (!ok) {
        free(bytes);
        LOG_FAIL(PE_TAG, "%s could not be read exactly once", path);
    }
    *out = bytes;
    *len = size;
    return true;
}

/* ── input parsing ───────────────────────────────────────────────────── */

static bool pe_path_in(const struct json_value *in, const char *key, char *out, size_t cap)
{
    const struct json_value *value = json_get(in, key);
    if (!value) return true;
    if (value->type != JSON_STR || strlen(json_get_str(value)) >= cap || !pair_path_ok(json_get_str(value))) return false;
    memcpy(out, json_get_str(value), strlen(json_get_str(value)) + 1);
    return true;
}

static bool pe_peer_in(const struct json_value *in, char out[PAIR_NAME_MAX])
{
    const struct json_value *value = json_get(in, "peer");
    const char *name = value && value->type == JSON_STR ? json_get_str(value) : "r2";
    if (strlen(name) >= PAIR_NAME_MAX || !pair_name_ok(name)) return false;
    memcpy(out, name, strlen(name) + 1);
    return true;
}

static bool pe_state_in(const struct json_value *in, char *out, size_t cap)
{
    if (json_get(in, "state_dir")) return pe_path_in(in, "state_dir", out, cap) && pair_path_ok(out);
    const char *home = getenv("HOME");
    return home && snprintf(out, cap, "%s/.local/state/z23-tunnel", home) < (int)cap && pair_path_ok(out);
}

struct pe_export_in {
    char state[PAIR_PATH_MAX], dest[PAIR_PATH_MAX], peer[PAIR_NAME_MAX];
    uint32_t epoch;
    bool have_epoch;
};

static bool pe_export_parse(const struct json_value *in, struct pe_export_in *out)
{
    memset(out, 0, sizeof(*out));
    const struct json_value *epoch = json_get(in, "epoch");
    if (epoch && (epoch->type != JSON_INT || json_get_int(epoch) < 1 || json_get_int(epoch) > (int64_t)PE_EPOCH_MAX)) return false;
    out->have_epoch = epoch != NULL;
    out->epoch = epoch ? (uint32_t)json_get_int(epoch) : 0;
    return pe_peer_in(in, out->peer) && pe_state_in(in, out->state, sizeof(out->state)) &&
           pe_path_in(in, "destination", out->dest, sizeof(out->dest)) && out->dest[0] != 0;
}

struct pe_import_in {
    char archive[PAIR_PATH_MAX], root[PAIR_PATH_MAX], sha[65];
    uint8_t sha_bytes[32];
};

static bool pe_import_parse(const struct json_value *in, struct pe_import_in *out)
{
    memset(out, 0, sizeof(*out));
    const struct json_value *sha = json_get(in, "expected_sha256");
    if (!sha || sha->type != JSON_STR || strlen(json_get_str(sha)) != 64 || !zcl_hex_decode(json_get_str(sha), out->sha_bytes, 32))
        return false;
    memcpy(out->sha, json_get_str(sha), 64);
    return pe_path_in(in, "archive", out->archive, sizeof(out->archive)) && out->archive[0] != 0 &&
           pe_path_in(in, "state_root", out->root, sizeof(out->root)) && out->root[0] != 0;
}

/* ── ops.mesh.device.pair.export ─────────────────────────────────────── */

struct pe_export_run {
    struct pe_export_in in;
    struct pair_epoch epoch;
    uint32_t which;
};

static bool pe_export_resolve(struct pe_export_run *run, struct zcl_command_reply *reply)
{
    if (!run->in.have_epoch) {
        uint32_t epochs[PAIR_EPOCH_LIST_MAX];
        size_t count = pair_epoch_list(run->in.state, run->in.peer, epochs, PAIR_EPOCH_LIST_MAX);
        if (!count) {
            pe_fail(reply, "EXPORT_EPOCH_UNREADABLE", "state", "no readable client epoch for this peer exists under state_dir; pair a first epoch", false);
            return false;
        }
        run->which = epochs[count - 1];
    }
    if (!pair_epoch_load(run->in.state, run->in.peer, run->which, &run->epoch)) {
        pe_fail(reply, "EXPORT_EPOCH_UNREADABLE", "state", "the epoch directory, its client route or its grant is unreadable for this peer", false);
        return false;
    }
    return true;
}

static void pe_header_fill(struct pe_header *head, const struct pe_export_run *run)
{
    memset(head, 0, sizeof(*head));
    snprintf(head->origin, sizeof(head->origin), "%s", run->epoch.profile);
    snprintf(head->peer, sizeof(head->peer), "%s", run->in.peer);
    snprintf(head->route_id, sizeof(head->route_id), "%s", run->epoch.route_id);
    head->epoch = run->which;
}

static bool pe_export_emit(struct zcl_command_reply *reply, const struct pe_export_in *in, const struct pair_epoch *epoch,
                           uint32_t which, const struct pe_scan *scan, const struct pe_buf *buf, const char *digest_hex)
{
    json_set_object(&reply->data);
    reply->error.mutated = true;
    bool ok = json_push_kv_str(&reply->data, "schema", "zcl.device.pair.export.v1") &&
              json_push_kv_str(&reply->data, "archive", in->dest) &&
              json_push_kv_int(&reply->data, "bytes", (int64_t)buf->len) && json_push_kv_str(&reply->data, "sha256", digest_hex) &&
              json_push_kv_int(&reply->data, "epoch", (int64_t)which) && json_push_kv_str(&reply->data, "peer", in->peer) &&
              json_push_kv_str(&reply->data, "route_id", epoch->route_id) &&
              json_push_kv_str(&reply->data, "directory", epoch->profile) &&
              json_push_kv_int(&reply->data, "files", (int64_t)scan->count);
    if (!ok) pe_fail(reply, "EXPORT_SERIALIZE_FAILED", "emit", "the archive is written but its result did not fit the bounded reply", true);
    return ok;
}

void zcl_native_handle_ops_mesh_device_pair_export(const struct zcl_command_request *request,
                                                   struct zcl_command_reply *reply)
{
    struct pe_export_run run;
    struct pe_buf buf = {0};
    struct pe_scan scan = {0};
    struct pe_header head;
    if (!reply) return;
    memset(&run, 0, sizeof(run));
    memset(&head, 0, sizeof(head));
    if (!request || !request->input || request->input->type != JSON_OBJ || !pe_export_parse(request->input, &run.in)) {
        pe_fail(reply, "EXPORT_INPUT_REFUSED", "normalize",
                "state_dir and destination must be absolute simple paths, peer a short lowercase name and epoch 1..999999", false);
        return;
    }
    run.which = run.in.epoch;
    if (!pe_export_resolve(&run, reply)) return;
    if (access(run.in.dest, F_OK) == 0) {
        pe_fail(reply, "EXPORT_DEST_EXISTS", "write", "the destination path already exists; choose an absent destination", false);
        return;
    }
    pe_header_fill(&head, &run);
    if (!pe_walk(run.epoch.dir, "", 1, &scan)) {
        pe_fail(reply, "EXPORT_ENTRY_REFUSED", "scan", "the epoch directory holds an entry this archive format refuses to carry", false);
        goto done;
    }
    qsort(scan.files, scan.count, sizeof(scan.files[0]), pe_file_cmp);
    if (!pe_assemble(&buf, &head, &scan, run.epoch.dir)) {
        pe_fail(reply, "EXPORT_TOO_LARGE", "assemble", "the epoch did not fit the bounded archive buffer", false);
        goto done;
    }
    uint8_t digest[SHA256_OUTPUT_SIZE];
    char hex[65];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, buf.bytes, buf.len);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, SHA256_OUTPUT_SIZE, hex);
    if (!pe_write_dest(run.in.dest, buf.bytes, buf.len)) {
        /* Remove any partial destination so a retry is not stuck behind
         * EXPORT_DEST_EXISTS. */
        unlink(run.in.dest);
        pe_fail(reply, "EXPORT_WRITE_FAILED", "write", "the archive could not be written exclusively at mode 0600 to the destination; any partial archive was removed", false);
        goto done;
    }
    (void)pe_export_emit(reply, &run.in, &run.epoch, run.which, &scan, &buf, hex);
done:
    pe_scan_free(&scan);
    /* The export buffer held the PSK file's bytes: wipe before free. */
    if (buf.bytes) memory_cleanse(buf.bytes, buf.len);
    free(buf.bytes);
}

/* ── ops.mesh.device.pair.import ─────────────────────────────────────── */

static bool pe_import_inputs_ok(const struct zcl_command_request *request, struct pe_import_in *in)
{
    return request && request->input && request->input->type == JSON_OBJ && pe_import_parse(request->input, in);
}

static bool pe_import_digest_ok(const struct pe_import_in *in, const uint8_t *bytes, size_t len)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, bytes, len);
    sha256_finalize(&ctx, digest);
    return !memcmp(digest, in->sha_bytes, SHA256_OUTPUT_SIZE);
}

static const struct pe_record *pe_import_route(const struct pe_record *records, uint32_t rows)
{
    for (uint32_t i = 0; i < rows; ++i)
        if (!strcmp(records[i].name, "client.json")) return &records[i];
    return NULL;
}

static bool pe_import_epoch_dir(const struct pe_import_in *in, const struct pe_header *head, char *epoch_dir, size_t cap,
                                char *name, size_t name_cap)
{
    if (snprintf(name, name_cap, "%s-e%u", head->peer, (unsigned)head->epoch) >= (int)name_cap ||
        snprintf(epoch_dir, cap, "%s/%s", in->root, name) >= (int)cap)
        return false;
    return true;
}

static bool pe_import_write_client(const char *epoch_dir, const struct pe_record *route, const uint8_t *bytes)
{
    char rewritten[PE_ROUTE_TEXT_MAX], directory[PAIR_PATH_MAX];
    if (snprintf(directory, sizeof(directory), "%s/profile", epoch_dir) >= (int)sizeof(directory)) return false;
    if (!pe_rebind_directory(bytes + route->offset, (size_t)route->size, directory, rewritten, sizeof(rewritten)))
        return false;
    return pe_write_record(epoch_dir, route->name, (const uint8_t *)rewritten, strlen(rewritten));
}

static bool pe_import_records(const char *epoch_dir, const struct pe_record *records, uint32_t rows,
                              const struct pe_record *route, const uint8_t *bytes)
{
    for (uint32_t i = 0; i < rows; ++i) {
        bool ok = &records[i] == route
                      ? pe_import_write_client(epoch_dir, route, bytes)
                      : pe_write_record(epoch_dir, records[i].name, bytes + records[i].offset, (size_t)records[i].size);
        if (!ok) return false;
    }
    return true;
}

static bool pe_import_emit(struct zcl_command_reply *reply, const struct pe_header *head, const char *epoch_dir,
                           const char *name, const char *archive, size_t len, uint32_t rows)
{
    json_set_object(&reply->data);
    reply->error.mutated = true;
    bool ok = json_push_kv_str(&reply->data, "schema", "zcl.device.pair.import.v1") &&
              json_push_kv_int(&reply->data, "epoch", (int64_t)head->epoch) && json_push_kv_str(&reply->data, "peer", head->peer) &&
              json_push_kv_str(&reply->data, "route_id", head->route_id) &&
              json_push_kv_str(&reply->data, "directory", epoch_dir) && json_push_kv_str(&reply->data, "epoch_directory", name) &&
              json_push_kv_str(&reply->data, "archive", archive) && json_push_kv_int(&reply->data, "bytes", (int64_t)len) &&
              json_push_kv_int(&reply->data, "files", (int64_t)rows);
    if (!ok) pe_fail(reply, "IMPORT_SERIALIZE_FAILED", "emit", "the epoch is materialized but its result did not fit the bounded reply", true);
    return ok;
}

static void pe_import_sha_logged(const struct pe_import_in *in, const uint8_t *bytes, size_t len)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    char got[65];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, bytes, len);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, SHA256_OUTPUT_SIZE, got);
    LOG_ERROR(PE_TAG, "expected %s, the archive digests to %s", in->sha, got);
}

void zcl_native_handle_ops_mesh_device_pair_import(const struct zcl_command_request *request,
                                                   struct zcl_command_reply *reply)
{
    struct pe_import_in in;
    struct pe_header head;
    struct pe_record *records = NULL;
    uint32_t rows = 0;
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (!reply) return;
    memset(&head, 0, sizeof(head));
    if (!pe_import_inputs_ok(request, &in)) {
        pe_fail(reply, "IMPORT_INPUT_REFUSED", "normalize",
                "archive and state_root must be absolute simple paths and expected_sha256 exactly 64 hex digits", false);
        return;
    }
    if (!pe_read_all(in.archive, &bytes, &len)) {
        pe_fail(reply, "IMPORT_ARCHIVE_UNREADABLE", "read", "the archive is not a readable regular file within the archive bound", false);
        return;
    }
    if (!pe_import_digest_ok(&in, bytes, len)) {
        pe_import_sha_logged(&in, bytes, len);
        pe_fail(reply, "IMPORT_SHA_MISMATCH", "verify", "the archive does not digest to the expected_sha256 the caller supplied", false);
        goto done;
    }
    if (!pe_parse(bytes, len, &head, &records, &rows)) {
        pe_fail(reply, "IMPORT_FORMAT_REFUSED", "parse", "the bytes are not a well-formed pairing epoch archive", false);
        goto done;
    }
    const struct pe_record *route = pe_import_route(records, rows);
    if (!route) {
        pe_fail(reply, "IMPORT_ROUTE_REFUSED", "parse", "the archive carries no client.json record; it is not a client epoch", false);
        goto done;
    }
    char epoch_dir[PAIR_PATH_MAX], name[PAIR_NAME_MAX + 16];
    if (!pe_import_epoch_dir(&in, &head, epoch_dir, sizeof(epoch_dir), name, sizeof(name))) {
        pe_fail(reply, "IMPORT_INPUT_REFUSED", "normalize", "the epoch directory name does not fit its bound under this state root", false);
        goto done;
    }
    if (access(epoch_dir, F_OK) == 0) {
        pe_fail(reply, "IMPORT_EPOCH_EXISTS", "preflight", "an epoch directory for this peer and epoch already exists under state_root", false);
        goto done;
    }
    if (!pe_ensure_root(in.root) || mkdir(epoch_dir, 0700) != 0) {
        pe_fail(reply, "IMPORT_WRITE_FAILED", "preflight", "the state root or epoch directory could not be created owner-private", false);
        goto done;
    }
    if (!pe_import_records(epoch_dir, records, rows, route, bytes)) {
        /* Roll the half-materialized epoch back so the next attempt is not
         * stuck behind IMPORT_EPOCH_EXISTS. */
        pe_rmtree(epoch_dir, 0);
        pe_fail(reply, "IMPORT_WRITE_FAILED", "materialize", "an epoch record could not be created owner-only under the new epoch directory; the partial epoch was removed", true);
        goto done;
    }
    (void)pe_import_emit(reply, &head, epoch_dir, name, in.archive, len, rows);
done:
    free(records);
    /* The import view held the PSK file's bytes: wipe before free. */
    if (bytes) memory_cleanse(bytes, len);
    free(bytes);
}
#else
typedef int native_pair_epoch_unsupported_on_windows;
#endif
