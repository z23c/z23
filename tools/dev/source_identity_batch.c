/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Native NUL-path batch hashing and mode capture for source_identity.v2.
 * Output remains byte-identical to GNU sha256sum --zero and stat -c %f.
 *
 * The `token` submode additionally derives the inventory and mutation
 * preimages in one process. It reproduces byte-for-byte what
 * tools/dev/source-identity.sh builds from the same path set:
 *
 *   zcl.dev_source_inventory.v1\0  S\0<path>\0  [G\0<state>\0]
 *   zcl.dev_source_mutation.v1\0   P\0<path>\0  (G\0<state>\0 |
 *      E\0<dev>:<ino>:<size>:<mode-%x>:<mtime-%y>:<ctime-%z>\0 | D\0)
 *
 * `token identity` assembles the v2 identity preimage from a precomputed
 * digest table; `token capture-identity` emits the identical preimage while
 * hashing each regular file at classification time, removing the table and
 * the shell's per-record validation pass from the authoritative capture.
 * The metadata line matches GNU stat --printf='%d:%i:%s:%f:%y:%z' exactly,
 * including the local-timezone human timestamps with untrimmed nanoseconds
 * and the lstat view (a symlink entry describes the link itself). Gitlink
 * states arrive as `path\0state\0` pairs in the sidecar file; membership in
 * that file is the same test as the shell's GITLINK_STATE associative array.
 *
 * The enumeration submodes replace the shell's per-record index parsing:
 * `check-tags` applies the hidden-index-bit refusal to `ls-files -v -z`
 * output, `split-index` splits `ls-files --stage -z` into regular paths
 * (stdout) and nested gitlinks (a sidecar the shell recurses over), and
 * `prefix` joins a path stream onto a gitlink prefix. Their refusal messages
 * and exit status 3 are the shell's own fail() verdicts, byte-for-byte.
 */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "zsha256/zsha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID
#error "source identity batch input id is required"
#endif

typedef enum {
    BATCH_HASH,
    BATCH_MODE,
    BATCH_TOKEN_INVENTORY,
    BATCH_TOKEN_MUTATION,
    BATCH_TOKEN_IDENTITY,
    BATCH_CAPTURE_IDENTITY,
    BATCH_CHECK_TAGS,
    BATCH_SPLIT_INDEX,
    BATCH_PREFIX,
} batch_mode;

static int report_path_error(const char *action, const char *path)
{
    fprintf(stderr, "source-identity-batch: %s %s: %s\n",
            action, path, strerror(errno));
    return 1;
}

static int read_path(char **buffer, size_t *capacity, bool *at_eof)
{
    size_t length = 0;
    *at_eof = false;
    for (;;) {
        int byte = fgetc(stdin);
        if (byte == EOF) {
            if (ferror(stdin)) {
                fprintf(stderr, "source-identity-batch: stdin read failed\n");
                return -1;
            }
            if (length != 0) {
                fprintf(stderr,
                        "source-identity-batch: unterminated NUL record\n");
                return -1;
            }
            *at_eof = true;
            return 0;
        }
        if (byte == 0) {
            if (length == 0) {
                fprintf(stderr, "source-identity-batch: empty path record\n");
                return -1;
            }
            (*buffer)[length] = '\0';
            return 0;
        }
        if (length + 1 >= *capacity) {
            if (*capacity > SIZE_MAX / 2) {
                fprintf(stderr, "source-identity-batch: path is too long\n");
                return -1;
            }
            size_t next_capacity = *capacity * 2;
            char *next = zcl_realloc(*buffer, next_capacity,
                                     "source identity path");
            if (next == nullptr) {
                fprintf(stderr,
                        "source-identity-batch: path allocation failed\n");
                return -1;
            }
            *buffer = next;
            *capacity = next_capacity;
        }
        (*buffer)[length++] = (char)(unsigned char)byte;
    }
}

static bool same_snapshot(const struct stat *left, const struct stat *right)
{
    bool same = left->st_dev == right->st_dev &&
                left->st_ino == right->st_ino &&
                left->st_mode == right->st_mode &&
                left->st_size == right->st_size;
#if defined(__APPLE__)
    return same &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return same && left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static uint64_t g_content_bytes_read;
static uint64_t g_content_bytes_reused;
static int g_allow_reuse = 1;
static int g_report_bytes;
static int g_cache_ready;
static char g_cache_path[4096];
static int g_publish_repo_counter;

struct digest_row {
    char *path;
    uint64_t dev;
    uint64_t ino;
    uint32_t mode;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int64_t ctime_sec;
    int64_t ctime_nsec;
    uint8_t digest[ZSHA256_DIGEST_LEN];
};

static struct digest_row *g_rows;
static size_t g_row_count;
static size_t g_row_cap;
static int g_rows_sorted;
static int g_cache_dirty;

static void row_apply(struct stat *st, const struct digest_row *row)
{
    memset(st, 0, sizeof(*st));
    st->st_dev = (dev_t)row->dev;
    st->st_ino = (ino_t)row->ino;
    st->st_mode = (mode_t)row->mode;
    st->st_size = (off_t)row->size;
#if defined(__APPLE__)
    st->st_mtimespec.tv_sec = (time_t)row->mtime_sec;
    st->st_mtimespec.tv_nsec = row->mtime_nsec;
    st->st_ctimespec.tv_sec = (time_t)row->ctime_sec;
    st->st_ctimespec.tv_nsec = row->ctime_nsec;
#else
    st->st_mtim.tv_sec = (time_t)row->mtime_sec;
    st->st_mtim.tv_nsec = row->mtime_nsec;
    st->st_ctim.tv_sec = (time_t)row->ctime_sec;
    st->st_ctim.tv_nsec = row->ctime_nsec;
#endif
}

static void row_fill(struct digest_row *row, const char *path,
                     const struct stat *st, const uint8_t digest[ZSHA256_DIGEST_LEN])
{
    row->path = strdup(path);
    row->dev = (uint64_t)st->st_dev;
    row->ino = (uint64_t)st->st_ino;
    row->mode = (uint32_t)st->st_mode;
    row->size = (uint64_t)st->st_size;
#if defined(__APPLE__)
    row->mtime_sec = (int64_t)st->st_mtimespec.tv_sec;
    row->mtime_nsec = (int64_t)st->st_mtimespec.tv_nsec;
    row->ctime_sec = (int64_t)st->st_ctimespec.tv_sec;
    row->ctime_nsec = (int64_t)st->st_ctimespec.tv_nsec;
#else
    row->mtime_sec = (int64_t)st->st_mtim.tv_sec;
    row->mtime_nsec = (int64_t)st->st_mtim.tv_nsec;
    row->ctime_sec = (int64_t)st->st_ctim.tv_sec;
    row->ctime_nsec = (int64_t)st->st_ctim.tv_nsec;
#endif
    if (digest != nullptr)
        memcpy(row->digest, digest, ZSHA256_DIGEST_LEN);
}

static int row_cmp(const void *left, const void *right)
{
    const struct digest_row *a = left;
    const struct digest_row *b = right;
    return strcmp(a->path, b->path);
}

static int row_matches(const struct digest_row *row, const struct stat *st)
{
    struct stat cached;
    row_apply(&cached, row);
    return same_snapshot(&cached, st);
}

static void cache_load(void)
{
    if (g_cache_ready)
        return;
    g_cache_ready = 1;
    FILE *file = fopen(g_cache_path, "r");
    if (file == nullptr)
        return;
    char line[8192];
    while (fgets(line, sizeof line, file) != nullptr) {
        struct digest_row row;
        char hex[2 * ZSHA256_DIGEST_LEN + 1u];
        char path[4096];
        unsigned long long dev = 0, ino = 0, size = 0;
        unsigned int mode = 0;
        long long mtime_sec = 0, mtime_nsec = 0, ctime_sec = 0, ctime_nsec = 0;
        int matched = sscanf(line,
                             "%llu %llu %u %llu %lld %lld %lld %lld %64s %4095[^\n]",
                             &dev, &ino, &mode, &size, &mtime_sec, &mtime_nsec,
                             &ctime_sec, &ctime_nsec, hex, path);
        if (matched != 10 || strlen(hex) != 2 * ZSHA256_DIGEST_LEN)
            continue;
        if (strchr(path, '\n') != nullptr)
            continue;
        memset(&row, 0, sizeof row);
        row.path = strdup(path);
        if (row.path == nullptr)
            continue;
        row.dev = (uint64_t)dev;
        row.ino = (uint64_t)ino;
        row.mode = mode;
        row.size = (uint64_t)size;
        row.mtime_sec = (int64_t)mtime_sec;
        row.mtime_nsec = (int64_t)mtime_nsec;
        row.ctime_sec = (int64_t)ctime_sec;
        row.ctime_nsec = (int64_t)ctime_nsec;
        if (!zcl_hex_decode(hex, row.digest, ZSHA256_DIGEST_LEN)) {
            free(row.path);
            continue;
        }
        if (g_row_count == g_row_cap) {
            size_t next = g_row_cap == 0 ? 64 : g_row_cap * 2;
            struct digest_row *grown = zcl_realloc(g_rows, next * sizeof(*g_rows),
                                                   "digest cache");
            if (grown == nullptr) {
                free(row.path);
                continue;
            }
            g_rows = grown;
            g_row_cap = next;
        }
        g_rows[g_row_count++] = row;
    }
    fclose(file);
    if (g_row_count > 1)
        qsort(g_rows, g_row_count, sizeof(*g_rows), row_cmp);
    g_rows_sorted = 1;
}

static struct digest_row *cache_find(const char *path)
{
    if (!g_rows_sorted || g_row_count == 0)
        return nullptr;
    struct digest_row key;
    key.path = (char *)path;
    return bsearch(&key, g_rows, g_row_count, sizeof(*g_rows), row_cmp);
}

static void cache_remember(const char *path, const struct stat *st,
                           const uint8_t digest[ZSHA256_DIGEST_LEN])
{
    if (strchr(path, '\n') != nullptr)
        return;
    struct digest_row *found = cache_find(path);
    if (found != nullptr) {
        char *copy = strdup(path);
        if (copy == nullptr)
            return;
        free(found->path);
        row_fill(found, path, st, digest);
        free(found->path);
        found->path = copy;
        g_cache_dirty = 1;
        return;
    }
    if (g_row_count == g_row_cap) {
        size_t next = g_row_cap == 0 ? 64 : g_row_cap * 2;
        struct digest_row *grown = zcl_realloc(g_rows, next * sizeof(*g_rows),
                                               "digest cache");
        if (grown == nullptr)
            return;
        g_rows = grown;
        g_row_cap = next;
    }
    struct digest_row row;
    memset(&row, 0, sizeof row);
    row_fill(&row, path, st, digest);
    if (row.path == nullptr)
        return;
    g_rows[g_row_count++] = row;
    if (g_row_count > 1)
        qsort(g_rows, g_row_count, sizeof(*g_rows), row_cmp);
    g_rows_sorted = 1;
    g_cache_dirty = 1;
}

static void cache_save(void)
{
    if (!g_cache_dirty || g_cache_path[0] == '\0')
        return;
    if (g_row_count > 1)
        qsort(g_rows, g_row_count, sizeof(*g_rows), row_cmp);
    g_rows_sorted = 1;
    char tmp[4200];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", g_cache_path);
    if (n <= 0 || (size_t)n >= sizeof tmp)
        return;
    FILE *file = fopen(tmp, "w");
    if (file == nullptr)
        return;
    for (size_t i = 0; i < g_row_count; i++) {
        const struct digest_row *row = &g_rows[i];
        char hex[2 * ZSHA256_DIGEST_LEN + 1u];
        zcl_hex_encode(row->digest, ZSHA256_DIGEST_LEN, hex);
        if (fprintf(file, "%" PRIu64 " %" PRIu64 " %" PRIu32 " %" PRIu64
                           " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64
                           " %s %s\n",
                    row->dev, row->ino, row->mode, row->size,
                    row->mtime_sec, row->mtime_nsec,
                    row->ctime_sec, row->ctime_nsec, hex, row->path) < 0) {
            fclose(file);
            unlink(tmp);
            return;
        }
    }
    if (fclose(file) != 0) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, g_cache_path) != 0)
        unlink(tmp);
    else
        g_cache_dirty = 0;
}

static void publish_content_bytes(void)
{
    cache_save();
    if (g_report_bytes) {
        fprintf(stderr, "content_bytes_read=%" PRIu64 "\n", g_content_bytes_read);
        fprintf(stderr, "content_bytes_reused=%" PRIu64 "\n", g_content_bytes_reused);
    }
    if (!g_publish_repo_counter)
        return;
    /* Only record the counter inside an ignored build directory. Writing it
     * into a sandbox that tracks build/ would change a file the capture is
     * hashing. */
    if (system("git check-ignore -q build >/dev/null 2>&1") != 0)
        return;
    mkdir("build", 0755);
    mkdir("build/identity", 0755);
    FILE *file = fopen("build/identity/content-bytes-read", "w");
    if (file == nullptr)
        return;
    fprintf(file, "content_bytes_read=%" PRIu64 "\ncontent_bytes_reused=%" PRIu64 "\n",
            g_content_bytes_read, g_content_bytes_reused);
    fclose(file);
}

static void cache_init(const char *path, int report_bytes, int publish)
{
    if (g_cache_path[0] != '\0')
        return;
    if (path == nullptr || path[0] == '\0') {
        snprintf(g_cache_path, sizeof g_cache_path,
                 "build/identity/content-digest-cache");
        g_publish_repo_counter = publish;
    } else {
        snprintf(g_cache_path, sizeof g_cache_path, "%s", path);
        g_publish_repo_counter = 0;
    }
    g_report_bytes = report_bytes;
    static int hooked;
    if (!hooked) {
        atexit(publish_content_bytes);
        hooked = 1;
    }
}

static int digest_fd(int fd, const char *path,
                     uint8_t digest[ZSHA256_DIGEST_LEN], uint64_t *read_bytes)
{
    zsha256_ctx hash;
    zsha256_init(&hash);
    unsigned char bytes[64 * 1024];
    uint64_t total = 0;
    for (;;) {
        ssize_t count = read(fd, bytes, sizeof bytes);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            errno = saved;
            return report_path_error("could not read", path);
        }
        if (count == 0)
            break;
        if (total > UINT64_MAX / 8u - (uint64_t)count) {
            fprintf(stderr, "source-identity-batch: file is too large: %s\n",
                    path);
            return 1;
        }
        total += (uint64_t)count;
        zsha256_update(&hash, bytes, (size_t)count);
    }
    zsha256_final(&hash, digest);
    if (read_bytes != nullptr)
        *read_bytes = total;
    return 0;
}

static int emit_hash(const char *path,
                     const uint8_t digest[ZSHA256_DIGEST_LEN])
{
    char hex[2 * ZSHA256_DIGEST_LEN + 1u];
    zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, hex);
    size_t path_length = strlen(path);
    if (fwrite(hex, 1, sizeof hex - 1u, stdout) != sizeof hex - 1u ||
        fwrite("  ", 1, 2, stdout) != 2 ||
        fwrite(path, 1, path_length, stdout) != path_length ||
        fputc(0, stdout) == EOF) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

static int reuse_snapshot(const char *path, const struct stat *before,
                          uint8_t digest[ZSHA256_DIGEST_LEN])
{
    if (g_cache_path[0] == '\0')
        cache_init(nullptr, 0, 1);
    cache_load();
    struct digest_row *cached = cache_find(path);
    if (!g_allow_reuse || cached == nullptr || !row_matches(cached, before))
        return 0;
    memcpy(digest, cached->digest, ZSHA256_DIGEST_LEN);
    g_content_bytes_reused += (uint64_t)before->st_size;
    return 1;
}

static void record_fresh_digest(const char *path, const struct stat *before,
                                const uint8_t digest[ZSHA256_DIGEST_LEN],
                                uint64_t read_bytes)
{
    g_content_bytes_read += read_bytes;
    cache_remember(path, before, digest);
}

static int open_hash_fd(const char *path, const struct stat *before)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        report_path_error("could not open", path);
        return -1;
    }
    struct stat opened;
    if (fstat(fd, &opened) == 0 && same_snapshot(before, &opened))
        return fd;
    int saved = errno;
    close(fd);
    errno = saved;
    fprintf(stderr,
            "source-identity-batch: file changed before hashing: %s\n",
            path);
    return -1;
}

static int hash_file(const char *path,
                     uint8_t digest[ZSHA256_DIGEST_LEN])
{
    struct stat before;
    if (lstat(path, &before) != 0)
        return report_path_error("could not stat", path);
    if (!S_ISREG(before.st_mode)) {
        fprintf(stderr,
                "source-identity-batch: hash input is not regular: %s\n",
                path);
        return 1;
    }
    if (reuse_snapshot(path, &before, digest))
        return 0;

    int fd = open_hash_fd(path, &before);
    if (fd < 0)
        return 1;

    uint64_t read_bytes = 0;
    int status = digest_fd(fd, path, digest, &read_bytes);
    struct stat after;
    if (status == 0 &&
        (fstat(fd, &after) != 0 || !same_snapshot(&before, &after))) {
        fprintf(stderr,
                "source-identity-batch: file changed while hashing: %s\n",
                path);
        status = 1;
    }
    if (close(fd) != 0 && status == 0)
        status = report_path_error("could not close", path);
    struct stat path_after;
    if (status == 0 &&
        (lstat(path, &path_after) != 0 ||
         !same_snapshot(&before, &path_after))) {
        fprintf(stderr,
                "source-identity-batch: path changed while hashing: %s\n",
                path);
        status = 1;
    }
    if (status == 0)
        record_fresh_digest(path, &before, digest, read_bytes);
    return status;
}

static int hash_path(const char *path)
{
    uint8_t digest[ZSHA256_DIGEST_LEN];
    int status = hash_file(path, digest);
    return status == 0 ? emit_hash(path, digest) : status;
}

static int mode_path(const char *path)
{
    struct stat metadata;
    if (lstat(path, &metadata) != 0)
        return report_path_error("could not stat", path);
    if (printf("%" PRIxMAX "\n", (uintmax_t)metadata.st_mode) < 0) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

/* ── token submode ────────────────────────────────────────────────────── */

struct gitlink_state {
    char *path;
    char *state;
};

struct content_digest {
    char *path;
    char hex[2 * ZSHA256_DIGEST_LEN + 1u];
};

struct token_run {
    batch_mode mode;
    FILE *preimage;
    FILE *record;               /* mutation only; NULL otherwise */
    char *record_path;          /* owned companion of `record` */
    zsha256_ctx hash;
    struct gitlink_state *gitlinks;
    size_t gitlink_count;
    struct content_digest *digests;   /* identity only; NULL otherwise */
    size_t digest_count;
};

/* Read one NUL-terminated record from `source` into *buffer (grown as
 * needed). Returns 1 when a record was read, 0 on clean EOF before any
 * byte, and -1 on error (diagnostic already printed). */
static int read_delimited_record(FILE *source, char **buffer,
                                 size_t *capacity)
{
    size_t length = 0;
    for (;;) {
        int byte = fgetc(source);
        if (byte == EOF) {
            if (ferror(source)) {
                fprintf(stderr,
                        "source-identity-batch: record stream read failed\n");
                return -1;
            }
            if (length != 0) {
                fprintf(stderr,
                        "source-identity-batch: record stream is unterminated\n");
                return -1;
            }
            return 0;
        }
        if (byte == 0) {
            if (length == 0) {
                fprintf(stderr,
                        "source-identity-batch: record stream has an empty record\n");
                return -1;
            }
            (*buffer)[length] = '\0';
            return 1;
        }
        if (length + 1 >= *capacity) {
            char *next = zcl_realloc(*buffer, *capacity * 2,
                                     "identity record field");
            if (next == nullptr) {
                fprintf(stderr,
                        "source-identity-batch: record allocation failed\n");
                return -1;
            }
            *buffer = next;
            *capacity *= 2;
        }
        (*buffer)[length++] = (char)(unsigned char)byte;
    }
}

/* Read the whole sidecar as `path\0state\0` pairs. Pair count is tiny
 * (one per initialized/absent gitlink), so plain doubling is enough. */
static int load_gitlink_sidecar(const char *sidecar_path,
                                struct gitlink_state **out, size_t *out_count)
{
    *out = nullptr;
    *out_count = 0;
    FILE *sidecar = fopen(sidecar_path, "rb");
    if (sidecar == nullptr) {
        fprintf(stderr,
                "source-identity-batch: could not open gitlink sidecar %s: %s\n",
                sidecar_path, strerror(errno));
        return 1;
    }
    size_t capacity = 0;
    size_t count = 0;
    char *field = nullptr;
    size_t field_capacity = 256;
    field = zcl_malloc(field_capacity, "gitlink sidecar field");
    if (field == nullptr) {
        fprintf(stderr,
                "source-identity-batch: gitlink sidecar allocation failed\n");
        fclose(sidecar);
        return 1;
    }
    int status = 0;
    for (int want_path = 1;; want_path = !want_path) {
        int record = read_delimited_record(sidecar, &field, &field_capacity);
        if (record <= 0) {
            status = record < 0 ? 1 : 0;
            break;
        }
        if (want_path && count == capacity) {
            size_t next_capacity = capacity == 0 ? 8 : capacity * 2;
            struct gitlink_state *next =
                zcl_realloc(*out, next_capacity * sizeof **out,
                            "gitlink sidecar pairs");
            if (next == nullptr) {
                fprintf(stderr,
                        "source-identity-batch: gitlink sidecar allocation failed\n");
                status = 1;
                break;
            }
            *out = next;
            capacity = next_capacity;
        }
        char *copied = zcl_strdup(field, "gitlink sidecar field copy");
        if (copied == nullptr) {
            fprintf(stderr,
                    "source-identity-batch: gitlink sidecar allocation failed\n");
            status = 1;
            break;
        }
        if (want_path) {
            (*out)[count].path = copied;
        } else {
            (*out)[count].state = copied;
            count++;
        }
    }
    free(field);
    fclose(sidecar);
    if (status != 0) {
        for (size_t i = 0; i < count; i++) {
            free((*out)[i].path);
            free((*out)[i].state);
        }
        free(*out);
        *out = nullptr;
        return 1;
    }
    *out_count = count;
    return 0;
}

static const struct gitlink_state *find_gitlink(const struct token_run *run,
                                                const char *path)
{
    for (size_t i = 0; i < run->gitlink_count; i++) {
        if (strcmp(run->gitlinks[i].path, path) == 0)
            return &run->gitlinks[i];
    }
    return nullptr;
}

/* Parse the `hash` mode's output (GNU sha256sum --zero shape) into a
 * path-keyed digest table for the identity pass. */
/* Read one `digest  path\0` row. Returns 1 on a row, 0 on clean EOF, -1 on
 * a malformed row (diagnostic printed). `hex` receives 64 chars NUL-terminated
 * into 65 bytes; `path` grows through `capacity`. */
static int read_digest_record(FILE *table, char hex[65], char **path,
                              size_t *capacity)
{
    for (size_t i = 0; i < 64; i++) {
        int byte = fgetc(table);
        if (byte == EOF) {
            if (ferror(table)) {
                fprintf(stderr,
                        "source-identity-batch: digest table read failed\n");
                return -1;
            }
            return i == 0 ? 0 : -1;
        }
        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'a' && byte <= 'f'))) {
            fprintf(stderr,
                    "source-identity-batch: digest table record is malformed\n");
            return -1;
        }
        hex[i] = (char)byte;
    }
    hex[64] = '\0';
    char separator[2];
    if (fread(separator, 1, 2, table) != 2 ||
        !(separator[0] == ' ' &&
          (separator[1] == ' ' || separator[1] == '*'))) {
        fprintf(stderr,
                "source-identity-batch: digest table separator is malformed\n");
        return -1;
    }
    return read_delimited_record(table, path, capacity);
}

static int load_digest_table(const char *digests_path,
                             struct content_digest **out, size_t *out_count)
{
    *out = nullptr;
    *out_count = 0;
    FILE *table = fopen(digests_path, "rb");
    if (table == nullptr) {
        fprintf(stderr,
                "source-identity-batch: could not open digest table %s: %s\n",
                digests_path, strerror(errno));
        return 1;
    }
    size_t capacity = 0;
    size_t count = 0;
    char *path = nullptr;
    size_t path_capacity = 256;
    path = zcl_malloc(path_capacity, "digest table path");
    if (path == nullptr) {
        fprintf(stderr,
                "source-identity-batch: digest table allocation failed\n");
        fclose(table);
        return 1;
    }
    int status = 0;
    for (;;) {
        char hex[65];
        int record = read_digest_record(table, hex, &path, &path_capacity);
        if (record <= 0) {
            status = record < 0 ? 1 : 0;
            break;
        }
        if (count == capacity) {
            size_t next_capacity = capacity == 0 ? 64 : capacity * 2;
            struct content_digest *next =
                zcl_realloc(*out, next_capacity * sizeof **out,
                            "digest table entries");
            if (next == nullptr) {
                fprintf(stderr,
                        "source-identity-batch: digest table allocation failed\n");
                status = 1;
                break;
            }
            *out = next;
            capacity = next_capacity;
        }
        (*out)[count].path = zcl_strdup(path, "digest table entry");
        if ((*out)[count].path == nullptr) {
            fprintf(stderr,
                    "source-identity-batch: digest table allocation failed\n");
            status = 1;
            break;
        }
        memcpy((*out)[count].hex, hex, sizeof (*out)[count].hex);
        count++;
    }
    free(path);
    fclose(table);
    if (status != 0) {
        for (size_t i = 0; i < count; i++)
            free((*out)[i].path);
        free(*out);
        *out = nullptr;
        return 1;
    }
    *out_count = count;
    return 0;
}

static const struct content_digest *find_digest(const struct token_run *run,
                                                const char *path)
{
    for (size_t i = 0; i < run->digest_count; i++) {
        if (strcmp(run->digests[i].path, path) == 0)
            return &run->digests[i];
    }
    return nullptr;
}

/* Collapse a raw mode into the three Git-representable canonical modes the
 * shell's canonical_source_mode() admits, with the same type validation. */
static int canonical_mode(char out[8], const struct stat *metadata, char kind,
                          const char *path)
{
    mode_t type = metadata->st_mode & S_IFMT;
    if (kind == 'L') {
        if (type != S_IFLNK) {
            fprintf(stderr,
                    "source-identity-batch: noncanonical symlink mode: %s\n",
                    path);
            return -1;
        }
        memcpy(out, "120000", 7);
        return 0;
    }
    if (type != S_IFREG) {
        fprintf(stderr,
                "source-identity-batch: noncanonical regular-file mode: %s\n",
                path);
        return -1;
    }
    if ((metadata->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)
        memcpy(out, "100755", 7);
    else
        memcpy(out, "100644", 7);
    return 0;
}

/* Mirror GNU stat --printf='%y' or '%z': local time, untrimmed nanoseconds,
 * and the timezone offset belonging to that broken-down local time. */
static int format_time(char out[80], const struct timespec *when)
{
    struct tm broken;
    time_t seconds = when->tv_sec;
    if (localtime_r(&seconds, &broken) == nullptr)
        return -1;
    char offset[8];
    if (strftime(offset, sizeof(offset), "%z", &broken) != 5)
        return -1;
    int length = snprintf(out, 80,
                          "%04d-%02d-%02d %02d:%02d:%02d.%09ld %s",
                          broken.tm_year + 1900, broken.tm_mon + 1,
                          broken.tm_mday, broken.tm_hour, broken.tm_min,
                          broken.tm_sec, when->tv_nsec, offset);
    return length > 0 && length < 80 ? 0 : -1;
}

/* Mirror GNU stat --printf='%d:%i:%s:%f:%y:%z' on the followed view. */
static int format_metadata(char out[200], const struct stat *metadata)
{
    struct timespec mtime;
    struct timespec ctime;
#if defined(__APPLE__)
    mtime = metadata->st_mtimespec;
    ctime = metadata->st_ctimespec;
#else
    mtime = metadata->st_mtim;
    ctime = metadata->st_ctim;
#endif
    char mtime_text[80];
    char ctime_text[80];
    if (format_time(mtime_text, &mtime) != 0 ||
        format_time(ctime_text, &ctime) != 0)
        return -1;
    int length = snprintf(out, 200,
                          "%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIxMAX
                          ":%s:%s",
                          (uintmax_t)metadata->st_dev,
                          (uintmax_t)metadata->st_ino,
                          (uintmax_t)metadata->st_size,
                          (uintmax_t)metadata->st_mode, mtime_text, ctime_text);
    return length > 0 && length < 200 ? 0 : -1;
}

static int emit_bytes(struct token_run *run, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    if (fwrite(bytes, 1, length, run->preimage) != length)
        return -1;
    zsha256_update(&run->hash, bytes, length);
    return 0;
}

/* One `field\0` record: the shell builds each preimage from exactly these
 * tag/value NUL-terminated writes. */
static int emit_field(struct token_run *run, const char *text)
{
    if (emit_bytes(run, text, strlen(text)) != 0)
        return -1;
    return emit_bytes(run, "\0", 1);
}

static int emit_record(struct token_run *run, const char *path,
                       const char *type, const char *metadata)
{
    if (run->record != nullptr &&
        (fprintf(run->record, "%s%c%s%c%s%c", path, 0, type, 0,
                 metadata == nullptr ? "" : metadata, 0) < 0))
        return -1;
    return 0;
}

static int token_inventory_path(struct token_run *run, const char *path,
                                const struct gitlink_state *gitlink)
{
    if (emit_field(run, "S") != 0 || emit_field(run, path) != 0)
        return -1;
    if (gitlink != nullptr &&
        (emit_field(run, "G") != 0 || emit_field(run, gitlink->state) != 0))
        return -1;
    return 0;
}

static int token_identity_symlink(struct token_run *run, const char *path,
                                  const struct stat *link_view)
{
    char mode[8];
    if (canonical_mode(mode, link_view, 'L', path) != 0)
        return 1;
    char target[4096];
    ssize_t target_length = readlink(path, target, sizeof target);
    if (target_length < 0) {
        fprintf(stderr,
                "source-identity-batch: could not read symlink: %s: %s\n",
                path, strerror(errno));
        return 1;
    }
    if ((size_t)target_length == sizeof target) {
        fprintf(stderr,
                "source-identity-batch: symlink target is too long: %s\n",
                path);
        return 1;
    }
    uint8_t digest[ZSHA256_DIGEST_LEN];
    zsha256_ctx target_hash;
    zsha256_init(&target_hash);
    zsha256_update(&target_hash, (const unsigned char *)target,
                   (size_t)target_length);
    zsha256_final(&target_hash, digest);
    char hex[2 * ZSHA256_DIGEST_LEN + 1u];
    zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, hex);
    if (emit_field(run, "L") != 0 || emit_field(run, mode) != 0 ||
        emit_field(run, hex) != 0)
        return -1;
    return 0;
}

static int token_identity_path(struct token_run *run, const char *path,
                               const struct gitlink_state *gitlink)
{
    if (emit_field(run, "P") != 0 || emit_field(run, path) != 0)
        return -1;
    if (gitlink != nullptr) {
        if (emit_field(run, "G") != 0 || emit_field(run, gitlink->state) != 0)
            return -1;
        return 0;
    }

    struct stat link_view;
    if (lstat(path, &link_view) != 0)
        return emit_field(run, "D") != 0 ? -1 : 0;
    if (S_ISLNK(link_view.st_mode))
        return token_identity_symlink(run, path, &link_view);
    if (S_ISREG(link_view.st_mode)) {
        char mode[8];
        if (canonical_mode(mode, &link_view, 'F', path) != 0)
            return 1;
        const struct content_digest *digest = find_digest(run, path);
        if (digest == nullptr) {
            fprintf(stderr,
                    "source-identity-batch: regular-file hash batch was "
                    "incomplete: %s\n",
                    path);
            return 1;
        }
        if (emit_field(run, "F") != 0 || emit_field(run, mode) != 0 ||
            emit_field(run, digest->hex) != 0)
            return -1;
        return 0;
    }
    fprintf(stderr,
            "source-identity-batch: unsupported dirty source type: %s\n",
            path);
    return 1;
}

/* The `E` record. GNU stat --printf is lstat semantics: a symlink entry
 * carries the LINK's own device/inode/size/mode, never its target's. The
 * shell's type test is still `[ -L ] || [ -f ]` (test -f follows), so a
 * symlink to anything and a plain regular file both land here with the
 * lstat view below. */
static int emit_mutation_existing(struct token_run *run, const char *path,
                                  const struct stat *link_view)
{
    char line[200];
    if (format_metadata(line, link_view) != 0) {
        fprintf(stderr,
                "source-identity-batch: could not format metadata: %s\n",
                path);
        return 1;
    }
    if (emit_field(run, "E") != 0 || emit_field(run, line) != 0)
        return -1;
    return emit_record(run, path, "E", line);
}

static int token_mutation_path(struct token_run *run, const char *path,
                               const struct gitlink_state *gitlink)
{
    if (emit_field(run, "P") != 0 || emit_field(run, path) != 0)
        return -1;
    if (gitlink != nullptr) {
        if (emit_field(run, "G") != 0 || emit_field(run, gitlink->state) != 0)
            return -1;
        return emit_record(run, path, "G", gitlink->state);
    }

    struct stat link_view;
    bool have_link = lstat(path, &link_view) == 0;
    bool is_link = have_link && S_ISLNK(link_view.st_mode);
    struct stat followed;
    int followed_status = stat(path, &followed);
    if (is_link || (followed_status == 0 && S_ISREG(followed.st_mode)))
        return emit_mutation_existing(run, path, &link_view);
    if (followed_status != 0) {
        if (emit_field(run, "D") != 0)
            return -1;
        return emit_record(run, path, "D", nullptr);
    }
    fprintf(stderr,
            "source-identity-batch: unsupported source type while capturing "
            "mutation token: %s\n",
            path);
    return 1;
}

/* capture-identity: the identity pass without the intermediate digest
 * table.  Each regular file is hashed at classification time, under the
 * same before/after snapshot race checks the `hash` mode applies, and the
 * digest enters the preimage directly.  Emitted bytes are identical to the
 * two-step `hash` + `token identity` pipeline over the same path set. */
static int capture_identity_path(struct token_run *run, const char *path,
                                 const struct gitlink_state *gitlink)
{
    if (emit_field(run, "P") != 0 || emit_field(run, path) != 0)
        return -1;
    if (gitlink != nullptr) {
        if (emit_field(run, "G") != 0 || emit_field(run, gitlink->state) != 0)
            return -1;
        return 0;
    }

    struct stat link_view;
    if (lstat(path, &link_view) != 0)
        return emit_field(run, "D") != 0 ? -1 : 0;
    if (S_ISLNK(link_view.st_mode))
        return token_identity_symlink(run, path, &link_view);
    if (S_ISREG(link_view.st_mode)) {
        char mode[8];
        if (canonical_mode(mode, &link_view, 'F', path) != 0)
            return 1;
        uint8_t digest[ZSHA256_DIGEST_LEN];
        if (hash_file(path, digest) != 0)
            return 1;
        char hex[2 * ZSHA256_DIGEST_LEN + 1u];
        zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, hex);
        if (emit_field(run, "F") != 0 || emit_field(run, mode) != 0 ||
            emit_field(run, hex) != 0)
            return -1;
        return 0;
    }
    fprintf(stderr,
            "source-identity-batch: unsupported dirty source type: %s\n",
            path);
    return 1;
}

static int token_path(struct token_run *run, const char *path)
{
    const struct gitlink_state *gitlink = find_gitlink(run, path);
    if (run->mode == BATCH_TOKEN_INVENTORY)
        return token_inventory_path(run, path, gitlink);
    if (run->mode == BATCH_TOKEN_IDENTITY)
        return token_identity_path(run, path, gitlink);
    if (run->mode == BATCH_CAPTURE_IDENTITY)
        return capture_identity_path(run, path, gitlink);
    return token_mutation_path(run, path, gitlink);
}

/* Map the submode word onto its enum; 0 means the word is unknown. */
static batch_mode parse_token_mode(const char *mode_text, bool *wants_record)
{
    if (strcmp(mode_text, "inventory") == 0) {
        *wants_record = false;
        return BATCH_TOKEN_INVENTORY;
    }
    if (strcmp(mode_text, "mutation") == 0) {
        *wants_record = true;
        return BATCH_TOKEN_MUTATION;
    }
    if (strcmp(mode_text, "identity") == 0) {
        *wants_record = false;
        return BATCH_TOKEN_IDENTITY;
    }
    if (strcmp(mode_text, "capture-identity") == 0) {
        *wants_record = false;
        return BATCH_CAPTURE_IDENTITY;
    }
    return BATCH_HASH;
}

static const char *token_header(batch_mode mode)
{
    if (mode == BATCH_TOKEN_INVENTORY)
        return "zcl.dev_source_inventory.v1";
    if (mode == BATCH_TOKEN_MUTATION)
        return "zcl.dev_source_mutation.v1";
    return "zcl.dev_source_identity.v2";
}

/* capture-identity produces the identity preimage without consuming a
 * digest table; the two-step `identity` mode still requires one. */
static bool token_mode_wants_digests(batch_mode mode)
{
    return mode == BATCH_TOKEN_IDENTITY;
}

/* Open the mutation `path\0type\0meta\0` companion beside the preimage. */
static char *open_record_path(const char *preimage_path, FILE **record)
{
    *record = nullptr;
    size_t preimage_length = strlen(preimage_path);
    char *record_path = zcl_malloc(preimage_length + sizeof ".record",
                                   "mutation record path");
    if (record_path == nullptr) {
        fprintf(stderr,
                "source-identity-batch: record path allocation failed\n");
        return nullptr;
    }
    memcpy(record_path, preimage_path, preimage_length);
    memcpy(record_path + preimage_length, ".record", sizeof ".record");
    *record = fopen(record_path, "wb");
    if (*record == nullptr) {
        fprintf(stderr,
                "source-identity-batch: could not open mutation record %s: %s\n",
                record_path, strerror(errno));
        free(record_path);
        return nullptr;
    }
    return record_path;
}

/* Stream stdin's path list through the per-mode emitter, then seal the
 * digest to stdout. `run` must already carry its open outputs. */
static int emit_token_stream(struct token_run *run)
{
    size_t capacity = 256;
    char *path = zcl_malloc(capacity, "source identity path");
    int status = 0;
    if (path == nullptr) {
        fprintf(stderr, "source-identity-batch: path allocation failed\n");
        return 1;
    }
    if (emit_field(run, token_header(run->mode)) != 0) {
        fprintf(stderr, "source-identity-batch: preimage write failed\n");
        free(path);
        return 1;
    }
    while (status == 0) {
        bool at_eof;
        if (read_path(&path, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        int token_status = token_path(run, path);
        if (token_status != 0) {
            status = token_status > 0 ? token_status : 1;
            break;
        }
    }
    free(path);
    if (status != 0)
        return status;
    uint8_t digest[ZSHA256_DIGEST_LEN];
    zsha256_final(&run->hash, digest);
    char hex[2 * ZSHA256_DIGEST_LEN + 1u];
    zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, hex);
    if (printf("%s\n", hex) < 0) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

static void free_token_inputs(struct gitlink_state *gitlinks,
                              size_t gitlink_count,
                              struct content_digest *digests,
                              size_t digest_count)
{
    for (size_t i = 0; i < gitlink_count; i++) {
        free(gitlinks[i].path);
        free(gitlinks[i].state);
    }
    free(gitlinks);
    for (size_t i = 0; i < digest_count; i++)
        free(digests[i].path);
    free(digests);
}

/* Load the gitlink sidecar and (for identity) the digest table. Returns 0
 * and fills the out-arrays; on failure everything is freed and 1 returns. */
static int load_token_inputs(batch_mode mode, const char *sidecar_path,
                             const char *digests_path,
                             struct gitlink_state **gitlinks,
                             size_t *gitlink_count,
                             struct content_digest **digests,
                             size_t *digest_count)
{
    *gitlinks = nullptr;
    *gitlink_count = 0;
    *digests = nullptr;
    *digest_count = 0;
    if (load_gitlink_sidecar(sidecar_path, gitlinks, gitlink_count) != 0)
        return 1;
    if (token_mode_wants_digests(mode) &&
        load_digest_table(digests_path, digests, digest_count) != 0) {
        free_token_inputs(*gitlinks, *gitlink_count, nullptr, 0);
        *gitlinks = nullptr;
        *gitlink_count = 0;
        return 1;
    }
    return 0;
}

/* Open both outputs and bind the fully-loaded run. Returns 0 with `run`
 * ready, or 1 after every opened resource was closed/freed. */
static int open_token_run(struct token_run *run, batch_mode mode,
                          bool wants_record, const char *preimage_path,
                          struct gitlink_state *gitlinks,
                          size_t gitlink_count,
                          struct content_digest *digests, size_t digest_count)
{
    FILE *preimage = fopen(preimage_path, "wb");
    if (preimage == nullptr) {
        fprintf(stderr,
                "source-identity-batch: could not open preimage %s: %s\n",
                preimage_path, strerror(errno));
        return 1;
    }
    char *record_path = nullptr;
    FILE *record = nullptr;
    if (wants_record) {
        record_path = open_record_path(preimage_path, &record);
        if (record_path == nullptr) {
            fclose(preimage);
            return 1;
        }
    }
    *run = (struct token_run) {
        .mode = mode,
        .preimage = preimage,
        .record = record,
        .record_path = record_path,
        .gitlinks = gitlinks,
        .gitlink_count = gitlink_count,
        .digests = digests,
        .digest_count = digest_count,
    };
    return 0;
}

static int run_tokens(const char *mode_text, const char *preimage_path,
                      const char *sidecar_path, const char *digests_path)
{
    bool wants_record = false;
    batch_mode mode = parse_token_mode(mode_text, &wants_record);
    if ((mode == BATCH_HASH) ||
        (token_mode_wants_digests(mode) && digests_path == nullptr) ||
        (mode == BATCH_CAPTURE_IDENTITY && digests_path != nullptr)) {
        fprintf(stderr,
                "usage: source-identity-batch token inventory|mutation|identity "
                "<preimage> <gitlink-sidecar> [digest-table]\n"
                "       source-identity-batch token capture-identity "
                "<preimage> <gitlink-sidecar>\n");
        return 2;
    }

    struct gitlink_state *gitlinks = nullptr;
    size_t gitlink_count = 0;
    struct content_digest *digests = nullptr;
    size_t digest_count = 0;
    if (load_token_inputs(mode, sidecar_path, digests_path, &gitlinks,
                          &gitlink_count, &digests, &digest_count) != 0)
        return 1;

    struct token_run run;
    if (open_token_run(&run, mode, wants_record, preimage_path, gitlinks,
                       gitlink_count, digests, digest_count) != 0) {
        free_token_inputs(gitlinks, gitlink_count, digests, digest_count);
        return 1;
    }
    zsha256_init(&run.hash);

    int status = emit_token_stream(&run);
    if (fflush(run.preimage) != 0 || fclose(run.preimage) != 0) {
        fprintf(stderr, "source-identity-batch: preimage flush failed\n");
        status = 1;
    }
    if (run.record != nullptr) {
        if (fflush(run.record) != 0 || fclose(run.record) != 0) {
            fprintf(stderr,
                    "source-identity-batch: mutation record flush failed\n");
            status = 1;
        }
    }
    free(run.record_path);
    free_token_inputs(run.gitlinks, run.gitlink_count, run.digests,
                      run.digest_count);
    if (fflush(stdout) != 0) {
        fprintf(stderr, "source-identity-batch: output flush failed\n");
        status = 1;
    }
    return status;
}

/* Stream stdin's NUL paths through the hash/mode per-path actions. */
static int batch_path_main(batch_mode mode)
{
    size_t capacity = 256;
    char *path = zcl_malloc(capacity, "source identity path");
    if (path == nullptr) {
        fprintf(stderr, "source-identity-batch: path allocation failed\n");
        return 1;
    }
    if (setvbuf(stdout, nullptr, _IOFBF, 64 * 1024) != 0) {
        fprintf(stderr, "source-identity-batch: output buffering failed\n");
        free(path);
        return 1;
    }

    int status = 0;
    for (;;) {
        bool at_eof;
        if (read_path(&path, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        status = mode == BATCH_HASH ? hash_path(path) : mode_path(path);
        if (status != 0)
            break;
    }
    if (status == 0 && fflush(stdout) != 0) {
        fprintf(stderr, "source-identity-batch: output flush failed\n");
        status = 1;
    }
    free(path);
    return status;
}

/* ── enumeration submodes ───────────────────────────────────────────────
 * One native pass over git's NUL-delimited index reports replaces the
 * shell's per-record parsing loops. The consumed byte formats are git's own
 * (`ls-files -v -z` and `ls-files --stage -z`); the refusal messages and the
 * exit status 3 reproduce source-identity.sh's fail() verdicts exactly, so a
 * native enumeration and the legacy loop are interchangeable under set -e. */
static int enumeration_usage(void)
{
    fprintf(stderr,
            "usage: source-identity-batch check-tags [gitlink-prefix]\n"
            "       source-identity-batch split-index <gitlink-out> "
            "[gitlink-prefix]\n"
            "       source-identity-batch prefix <prefix>\n");
    return 2;
}

/* check-tags: a skip-worktree ('S') or assume-unchanged (any lowercase tag)
 * bit hides content from `git diff`, so the shell refuses the whole capture
 * on the first such record. */
static int check_tags_main(const char *prefix)
{
    size_t capacity = 256;
    char *record = zcl_malloc(capacity, "index tag record");
    if (record == nullptr) {
        fprintf(stderr, "source-identity-batch: record allocation failed\n");
        return 1;
    }
    int status = 0;
    for (;;) {
        bool at_eof;
        if (read_path(&record, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        char tag = record[0];
        size_t length = strlen(record);
        const char *path = record + (length >= 2 ? 2 : length);
        if (tag == 'S' || (tag >= 'a' && tag <= 'z')) {
            if (prefix != nullptr)
                fprintf(stderr,
                        "source-identity: hidden Git index bit in gitlink "
                        "path: %s/%s\n", prefix, path);
            else
                fprintf(stderr,
                        "source-identity: hidden Git index bit on path: %s "
                        "(clear skip-worktree/assume-unchanged before "
                        "publication)\n", path);
            status = 3;
            break;
        }
    }
    free(record);
    return status;
}

/* split-index: one `<mode> SP <oid> SP <stage> TAB <path>` NUL record each.
 * Stage records are the shell's exact verdicts; regular/symlink modes append
 * `[prefix/]path\0` to stdout, gitlinks to the sidecar file the shell then
 * recurses over. The refusal wording differs between the plain and gitlink
 * forms beyond the prefix itself, so each verdict has its own helper. */
static int split_index_refuse_stage(const char *prefix, const char *stage,
                                    const char *path)
{
    if (prefix != nullptr)
        fprintf(stderr,
                "source-identity: unmerged gitlink index stage %s "
                "for path: %s/%s\n", stage, prefix, path);
    else
        fprintf(stderr,
                "source-identity: unmerged index stage %s for path: %s\n",
                stage, path);
    return 3;
}

static int split_index_refuse_mode(const char *prefix, const char *mode,
                                   const char *path)
{
    if (prefix != nullptr)
        fprintf(stderr,
                "source-identity: unsupported gitlink index mode %s "
                "for path: %s/%s\n", mode, prefix, path);
    else
        fprintf(stderr,
                "source-identity: unsupported tracked index mode %s "
                "for path: %s\n", mode, path);
    return 3;
}

/* Write `[prefix/]path\0`. Returns false only on a stream error. */
static bool split_index_emit(FILE *out, const char *prefix, const char *path)
{
    if (prefix != nullptr &&
        (fwrite(prefix, 1, strlen(prefix), out) != strlen(prefix) ||
         fputc('/', out) == EOF))
        return false;
    return fwrite(path, 1, strlen(path), out) == strlen(path) &&
           fputc(0, out) != EOF;
}

/* Handle one stage record. Returns 0 on emit, 1 on a malformed record or a
 * stream error, 3 on a refused verdict (message already printed). */
static int split_index_record(char *record, const char *prefix, FILE *gitlinks)
{
    size_t length = strlen(record);
    char *tab = memchr(record, '\t', length);
    char *space = memchr(record, ' ', length);
    char *stage = nullptr;
    if (tab != nullptr && space != nullptr && space < tab) {
        for (char *cursor = tab; cursor > record;) {
            cursor--;
            if (*cursor == ' ') {
                stage = cursor + 1;
                break;
            }
        }
    }
    if (stage == nullptr || stage == tab) {
        fprintf(stderr, "source-identity-batch: index record is malformed\n");
        return 1;
    }
    *space = '\0';
    *tab = '\0';
    const char *mode = record;
    const char *path = tab + 1;
    if (strcmp(stage, "0") != 0)
        return split_index_refuse_stage(prefix, stage, path);
    FILE *out = stdout;
    if (strcmp(mode, "100644") != 0 && strcmp(mode, "100755") != 0 &&
        strcmp(mode, "120000") != 0) {
        if (strcmp(mode, "160000") == 0)
            out = gitlinks;
        else
            return split_index_refuse_mode(prefix, mode, path);
    }
    if (!split_index_emit(out, prefix, path)) {
        fprintf(stderr, "source-identity-batch: output write failed\n");
        return 1;
    }
    return 0;
}

static int split_index_main(const char *gitlink_out_path, const char *prefix)
{
    FILE *gitlinks = fopen(gitlink_out_path, "wb");
    if (gitlinks == nullptr) {
        fprintf(stderr,
                "source-identity-batch: could not open gitlink output %s: %s\n",
                gitlink_out_path, strerror(errno));
        return 1;
    }
    if (setvbuf(stdout, nullptr, _IOFBF, 64 * 1024) != 0) {
        fprintf(stderr, "source-identity-batch: output buffering failed\n");
        fclose(gitlinks);
        return 1;
    }
    size_t capacity = 256;
    char *record = zcl_malloc(capacity, "index stage record");
    if (record == nullptr) {
        fprintf(stderr, "source-identity-batch: record allocation failed\n");
        fclose(gitlinks);
        return 1;
    }
    int status = 0;
    for (;;) {
        bool at_eof;
        if (read_path(&record, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        status = split_index_record(record, prefix, gitlinks);
        if (status != 0)
            break;
    }
    free(record);
    if (fclose(gitlinks) != 0 && status == 0) {
        fprintf(stderr,
                "source-identity-batch: gitlink output flush failed\n");
        status = 1;
    }
    if (status == 0 && fflush(stdout) != 0) {
        fprintf(stderr, "source-identity-batch: output flush failed\n");
        status = 1;
    }
    return status;
}

/* prefix: map a NUL path stream to `prefix/path\0`, the shell's
 * append_prefixed_nul(). */
static int prefix_main(const char *prefix)
{
    if (setvbuf(stdout, nullptr, _IOFBF, 64 * 1024) != 0) {
        fprintf(stderr, "source-identity-batch: output buffering failed\n");
        return 1;
    }
    size_t capacity = 256;
    char *path = zcl_malloc(capacity, "source identity path");
    if (path == nullptr) {
        fprintf(stderr, "source-identity-batch: path allocation failed\n");
        return 1;
    }
    size_t prefix_length = strlen(prefix);
    int status = 0;
    for (;;) {
        bool at_eof;
        if (read_path(&path, &capacity, &at_eof) != 0) {
            status = 1;
            break;
        }
        if (at_eof)
            break;
        size_t path_length = strlen(path);
        if (fwrite(prefix, 1, prefix_length, stdout) != prefix_length ||
            fputc('/', stdout) == EOF ||
            fwrite(path, 1, path_length, stdout) != path_length ||
            fputc(0, stdout) == EOF) {
            fprintf(stderr, "source-identity-batch: output write failed\n");
            status = 1;
            break;
        }
    }
    free(path);
    if (status == 0 && fflush(stdout) != 0) {
        fprintf(stderr, "source-identity-batch: output flush failed\n");
        status = 1;
    }
    return status;
}

static int enumeration_main(int argc, char **argv)
{
    if (strcmp(argv[1], "check-tags") == 0) {
        if (argc == 2)
            return check_tags_main(nullptr);
        if (argc == 3)
            return check_tags_main(argv[2]);
    } else if (strcmp(argv[1], "split-index") == 0) {
        if (argc == 3)
            return split_index_main(argv[2], nullptr);
        if (argc == 4)
            return split_index_main(argv[2], argv[3]);
    } else if (argc == 3 && strcmp(argv[1], "prefix") == 0) {
        return prefix_main(argv[2]);
    }
    return enumeration_usage();
}

static int hash_command(int argc, char **argv)
{
    const char *cache = nullptr;
    int report = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--report-bytes") == 0) {
            report = 1;
            continue;
        }
        if (strcmp(argv[i], "--cache") == 0 && i + 1 < argc) {
            cache = argv[++i];
            continue;
        }
        fprintf(stderr,
                "usage: source-identity-batch hash [--cache FILE] "
                "[--report-bytes]\n");
        return 2;
    }
    cache_init(cache, report, cache == nullptr);
    return batch_path_main(BATCH_HASH);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "identity") == 0) {
        printf("zcl.source_identity_batch.v1 %s\n",
               ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID);
        return ferror(stdout) ? 1 : 0;
    }
    if (argv[1] != nullptr && strcmp(argv[1], "token") == 0) {
        if (argc == 5)
            return run_tokens(argv[2], argv[3], argv[4], nullptr);
        if (argc == 6)
            return run_tokens(argv[2], argv[3], argv[4], argv[5]);
        fprintf(stderr,
                "usage: source-identity-batch token inventory|mutation|identity "
                "<preimage> <gitlink-sidecar> [digest-table]\n");
        return 2;
    }
    if (argv[1] != nullptr && strcmp(argv[1], "hash") == 0)
        return hash_command(argc, argv);
    if (argc == 2 && strcmp(argv[1], "mode") == 0)
        return batch_path_main(BATCH_MODE);
    if (argc >= 2)
        return enumeration_main(argc, argv);
    fprintf(stderr,
            "usage: source-identity-batch hash|mode|identity|token|"
            "check-tags|split-index|prefix ...\n");
    return 2;
}
