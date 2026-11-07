/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_vcs_torn_history — a read never destroys a copy's history, and a write
 * open never silently loses the bytes it drops.
 *
 * Fixture: an isolated ZVCS repo with two snapshots. The test records the
 * valid commits.log bytes itself, then damages the log in two ways:
 *   tail  bytes the test chose are appended after the last whole record;
 *   head  one payload byte of the FIRST record is flipped and the verified-
 *         prefix receipt removed, so no byte of the log is a whole record
 *         (the observed 528 -> 0 case).
 * Read path (vcs_open_readonly): refused, and the log stays byte-identical
 * (size + SHA3-256) with no new file beside it.
 * Write path (vcs_open, event_log_open_keep_torn): the log keeps exactly its
 * valid prefix and one quarantine sibling commits.log.torn-<valid size>...
 * holds exactly the dropped bytes.
 * Plain event_log_open() (every node, wallet and engine log): still cuts the
 * torn tail and writes no quarantine. Run from test_vcs_core (vcs_core). */

#include "test/test_core.h"

#include "storage/event_log.h"
#include "vcs/vcs.h"
#include "crypto/sha3.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int test_vcs_torn_history(const char *root);

#define VT_CHECK(name, expr) do {                                          \
    if (expr) { printf("  vcs_core: torn history: %s... OK\n", (name)); }  \
    else { printf("  vcs_core: torn history: %s... FAIL\n", (name));       \
           failures++; }                                                   \
} while (0)

static const char k_vt_tail[] = "ZVCS torn tail: these bytes are not a record";

struct vt_bytes {
    uint8_t *data;
    size_t len;
};

static void vt_bytes_free(struct vt_bytes *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

static bool vt_read(const char *path, struct vt_bytes *out)
{
    out->data = NULL;
    out->len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct stat st;
    bool ok = fstat(fileno(f), &st) == 0 && st.st_size >= 0;
    size_t len = ok ? (size_t)st.st_size : 0;
    out->data = ok ? malloc(len ? len : 1u) : NULL;
    ok = out->data && (len == 0 || fread(out->data, 1, len, f) == len);
    fclose(f);
    if (!ok) {
        vt_bytes_free(out);
        return false;
    }
    out->len = len;
    return true;
}

static bool vt_write(const char *path, const void *data, size_t len,
                     const char *mode)
{
    FILE *f = fopen(path, mode);
    if (!f)
        return false;
    bool ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static void vt_sha3(const struct vt_bytes *b, uint8_t out[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, b->data, b->len);
    sha3_256_finalize(&h, out);
}

/* The file at path holds exactly want: same size, same SHA3-256. */
static bool vt_same(const char *path, const struct vt_bytes *want)
{
    struct vt_bytes got;
    if (!vt_read(path, &got))
        return false;
    uint8_t a[32], b[32];
    vt_sha3(&got, a);
    vt_sha3(want, b);
    bool same = got.len == want->len && memcmp(a, b, 32) == 0;
    vt_bytes_free(&got);
    return same;
}

/* Entries of dir whose name starts with prefix; the last one found is
 * copied to name. */
static int vt_count(const char *dir, const char *prefix, char *name,
                    size_t cap)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int count = 0;
    size_t plen = strlen(prefix);
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            strncmp(e->d_name, prefix, plen) != 0)
            continue;
        count++;
        if (name)
            (void)snprintf(name, cap, "%s", e->d_name);
    }
    closedir(d);
    return count;
}

static bool vt_count_cb(const struct vcs_commit *c, const uint8_t id[32],
                        void *user)
{
    (void)c;
    (void)id;
    ++*(size_t *)user;
    return true;
}

/* Two snapshots in a fresh repo at dir; valid gets the whole log. */
static bool vt_make_repo(const char *dir, char *log, size_t cap,
                         struct vt_bytes *valid)
{
    char path[1024];
    (void)snprintf(log, cap, "%s/.zvcs/commits.log", dir);
    (void)snprintf(path, sizeof(path), "%s/readme.txt", dir);
    if (mkdir(dir, 0700) != 0 || !vt_write(path, "one\n", 4, "wb"))
        return false;
    struct vcs_repo *r = vcs_open(dir);
    struct vcs_snapshot_meta meta = {.phase = "g"};
    uint8_t c1[32], c2[32];
    bool ok = r && vcs_snapshot(r, &meta, c1) == VCS_OK &&
              vt_write(path, "two\n", 4, "wb") &&
              vcs_snapshot(r, &meta, c2) == VCS_OK;
    vcs_close(r);
    return ok && vt_read(log, valid) && valid->len > 32;
}

/* The read-only open refuses the damaged log and changes nothing. */
static int vt_read_path(const char *dir, const char *zvcs, const char *log,
                        const struct vt_bytes *damaged)
{
    int failures = 0;
    int entries = vt_count(zvcs, "", NULL, 0);
    struct vcs_repo *ro = vcs_open_readonly(dir);
    VT_CHECK("read-only open of a damaged log is refused", ro == NULL);
    vcs_close(ro);
    VT_CHECK("read leaves the log byte-identical (size + sha3)",
             vt_same(log, damaged));
    VT_CHECK("read creates no file beside the log",
             vt_count(zvcs, "", NULL, 0) == entries &&
             vt_count(zvcs, "commits.log.torn", NULL, 0) == 0);
    return failures;
}

/* The write open keeps the valid prefix and quarantines the rest. */
static int vt_write_path(const char *dir, const char *zvcs, const char *log,
                         const struct vt_bytes *kept,
                         const struct vt_bytes *dropped, size_t want_commits)
{
    int failures = 0;
    struct vcs_repo *r = vcs_open(dir);
    size_t commits = 0;
    VT_CHECK("write open recovers the valid prefix",
             r && vcs_log(r, 0, vt_count_cb, &commits) == VCS_OK &&
             commits == want_commits);
    vcs_close(r);
    VT_CHECK("write open leaves exactly the valid prefix", vt_same(log, kept));

    char prefix[64], name[256] = {0}, path[1400];
    (void)snprintf(prefix, sizeof(prefix), "commits.log.torn-%zu", kept->len);
    VT_CHECK("exactly one quarantine named for the cut offset",
             vt_count(zvcs, prefix, name, sizeof(name)) == 1);
    (void)snprintf(path, sizeof(path), "%s/%s", zvcs, name);
    VT_CHECK("quarantine holds exactly the dropped bytes",
             name[0] && strstr(name, ".tmp") == NULL &&
             vt_same(path, dropped));
    return failures;
}

static int vt_torn_tail(const char *root)
{
    int failures = 0;
    char dir[700], zvcs[800], log[900];
    struct vt_bytes valid = {0}, damaged = {0};
    (void)snprintf(dir, sizeof(dir), "%s/tail", root);
    (void)snprintf(zvcs, sizeof(zvcs), "%s/.zvcs", dir);
    bool made = vt_make_repo(dir, log, sizeof(log), &valid);
    VT_CHECK("tail fixture: two snapshots", made);
    made = made && vt_write(log, k_vt_tail, sizeof(k_vt_tail) - 1u, "ab") &&
           vt_read(log, &damaged) &&
           damaged.len == valid.len + sizeof(k_vt_tail) - 1u;
    VT_CHECK("tail fixture: chosen bytes appended", made);
    if (made) {
        struct vt_bytes tail = {(uint8_t *)k_vt_tail, sizeof(k_vt_tail) - 1u};
        failures += vt_read_path(dir, zvcs, log, &damaged);
        failures += vt_write_path(dir, zvcs, log, &valid, &tail, 2);
    }
    vt_bytes_free(&valid);
    vt_bytes_free(&damaged);
    return failures;
}

static int vt_torn_head(const char *root)
{
    int failures = 0;
    char dir[700], zvcs[800], log[900], side[1000];
    struct vt_bytes valid = {0}, damaged = {0};
    (void)snprintf(dir, sizeof(dir), "%s/head", root);
    (void)snprintf(zvcs, sizeof(zvcs), "%s/.zvcs", dir);
    bool made = vt_make_repo(dir, log, sizeof(log), &valid);
    VT_CHECK("head fixture: two snapshots", made);
    /* Byte 16 is the first payload byte of the first record (16-byte
     * header): flipping it breaks that record's CRC. */
    (void)snprintf(side, sizeof(side), "%s.verified", log);
    made = made && (unlink(side) == 0 || access(side, F_OK) != 0);
    if (made) {
        valid.data[16] ^= 0x5au;
        made = vt_write(log, valid.data, valid.len, "wb") &&
               vt_read(log, &damaged) && damaged.len == valid.len;
    }
    VT_CHECK("head fixture: first record damaged", made);
    if (made) {
        struct vt_bytes empty = {(uint8_t *)"", 0};
        failures += vt_read_path(dir, zvcs, log, &damaged);
        failures += vt_write_path(dir, zvcs, log, &empty, &damaged, 0);
    }
    vt_bytes_free(&valid);
    vt_bytes_free(&damaged);
    return failures;
}

/* The shared event_log_open() keeps main's behavior for every node, wallet
 * and engine log: it cuts the torn tail and writes no quarantine. */
static int vt_plain_open(const char *root)
{
    int failures = 0;
    char dir[700], zvcs[800], log[900];
    struct vt_bytes valid = {0};
    (void)snprintf(dir, sizeof(dir), "%s/plain", root);
    (void)snprintf(zvcs, sizeof(zvcs), "%s/.zvcs", dir);
    bool made = vt_make_repo(dir, log, sizeof(log), &valid) &&
                vt_write(log, k_vt_tail, sizeof(k_vt_tail) - 1u, "ab");
    VT_CHECK("plain fixture: chosen bytes appended", made);
    if (made) {
        event_log_t *el = event_log_open(log);
        VT_CHECK("plain event_log_open still opens a torn log", el != NULL);
        event_log_close(el);
        VT_CHECK("plain event_log_open cuts to the valid prefix and writes no "
                 "quarantine",
                 vt_same(log, &valid) &&
                 vt_count(zvcs, "commits.log.torn", NULL, 0) == 0);
    }
    vt_bytes_free(&valid);
    return failures;
}

int test_vcs_torn_history(const char *root)
{
    int failures = 0;
    failures += vt_torn_tail(root);
    failures += vt_torn_head(root);
    failures += vt_plain_open(root);
    return failures;
}
