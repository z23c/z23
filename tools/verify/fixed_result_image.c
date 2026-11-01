/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The fixed-result image core: materializes host paths into a
 *          root-layout image with fixed modes, rewrites absolute links to
 *          relative ones that resolve inside the image, refuses missing,
 *          unreadable, special and escaping inputs, re-hashes every input
 *          and output, and emits the sorted manifest and tree roots. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"
#include "tree_closure.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRI_MAX_HOPS 40u

static bool fri_fail(struct zcl_fri_image *img, const char *why,
                     const char *path)
{
    if (!img->why) {
        img->why = why;
        snprintf(img->why_path, sizeof(img->why_path), "%s", path ? path : "");
    }
    return false;
}

static bool fri_join(char out[PATH_MAX], const char *a, const char *b)
{
    size_t la = strlen(a);
    bool slash = la > 0 && a[la - 1] == '/';
    int n = snprintf(out, PATH_MAX, "%s%s%s", a, (slash || !*b) ? "" : "/", b);
    return n >= 0 && n < PATH_MAX;
}

static bool fri_host(const struct zcl_fri_image *img, const char *path,
                     char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s%s", img->host_root, path);
    return n >= 0 && n < PATH_MAX;
}

static bool fri_img(const struct zcl_fri_image *img, const char *rel,
                    char out[PATH_MAX])
{
    return fri_join(out, img->root, rel);
}

/* "/usr/bin" -> "usr/bin"; "/" -> "". */
static const char *fri_rel(const char *abs)
{
    while (*abs == '/') abs++;
    return abs;
}

static void fri_parent(char path[PATH_MAX])
{
    char *slash = strrchr(path, '/');
    if (!slash || slash == path) {
        path[0] = '/'; /* fixed two-byte literal into PATH_MAX bytes */
        path[1] = '\0';
        return;
    }
    *slash = '\0';
}

static unsigned fri_depth(const char *physical)
{
    unsigned depth = 0;
    bool in_name = false;
    for (const char *p = physical; *p; p++) {
        if (*p == '/') { in_name = false; continue; }
        if (!in_name) depth++;
        in_name = true;
    }
    return depth;
}

const struct zcl_fri_entry *zcl_fri_find(const struct zcl_fri_image *img,
                                         const char *rel)
{
    for (size_t i = 0; i < img->count; i++)
        if (strcmp(img->entries[i].path, rel) == 0) return &img->entries[i];
    return NULL;
}

static bool fri_same(const struct zcl_fri_entry *e, char kind,
                     const char *target, const char *source)
{
    if (e->kind != kind) return false;
    if (kind == 'L') return strcmp(e->target, target) == 0;
    if (kind == 'F') return source && e->source && strcmp(e->source, source) == 0;
    return true;
}

static struct zcl_fri_entry *fri_push(struct zcl_fri_image *img,
                                      const char *rel, char kind,
                                      unsigned mode)
{
    if (img->count == ZCL_FRI_MAX_ENTRIES) {
        fri_fail(img, ZCL_FRI_WHY_LIMIT, rel);
        return NULL;
    }
    if (img->count == img->cap) {
        size_t next = img->cap ? img->cap * 2u : 64u;
        struct zcl_fri_entry *grown = zcl_realloc(
            img->entries, next * sizeof(*grown), "fri_entries");
        if (!grown) { fri_fail(img, ZCL_FRI_WHY_ALLOC, rel); return NULL; }
        img->entries = grown;
        img->cap = next;
    }
    struct zcl_fri_entry *e = &img->entries[img->count];
    memset(e, 0, sizeof(*e));
    e->path = zcl_strdup(rel, "fri_entry_path");
    if (!e->path) { fri_fail(img, ZCL_FRI_WHY_ALLOC, rel); return NULL; }
    e->kind = kind;
    e->mode = mode;
    img->count++;
    return e;
}

static bool fri_mkdir_one(struct zcl_fri_image *img, const char *rel)
{
    const struct zcl_fri_entry *have = zcl_fri_find(img, rel);
    if (have) return have->kind == 'D' || fri_fail(img, ZCL_FRI_WHY_CONFLICT, rel);
    char path[PATH_MAX];
    if (!fri_img(img, rel, path)) return fri_fail(img, ZCL_FRI_WHY_LIMIT, rel);
    if (mkdir(path, 0700) != 0 || chmod(path, 0755) != 0)
        return fri_fail(img, ZCL_FRI_WHY_WRITE, path);
    return fri_push(img, rel, 'D', 0755) != NULL;
}

bool zcl_fri_add_dir(struct zcl_fri_image *img, const char *rel)
{
    char prefix[PATH_MAX];
    size_t n = strlen(rel);
    if (n == 0 || n >= PATH_MAX || rel[0] == '/')
        return fri_fail(img, ZCL_FRI_WHY_ARGS, rel);
    for (size_t i = 0; i <= n; i++) {
        if (rel[i] != '/' && rel[i] != '\0') continue;
        memcpy(prefix, rel, i);
        prefix[i] = '\0';
        if (i && !fri_mkdir_one(img, prefix)) return false;
    }
    return true;
}

static bool fri_parent_dir(struct zcl_fri_image *img, const char *rel)
{
    char parent[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", rel);
    char *slash = strrchr(parent, '/');
    if (!slash) return true;
    *slash = '\0';
    return zcl_fri_add_dir(img, parent);
}

bool zcl_fri_sha3_file(const char *path, uint8_t out[32], uint64_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    uint64_t got = 0;
    unsigned char buf[65536];
    while (ok) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) ok = false;
        if (n <= 0) break;
        sha3_256_write(&h, buf, (size_t)n);
        got += (uint64_t)n;
    }
    if (close(fd) != 0) ok = false;
    if (!ok) return false;
    sha3_256_finalize(&h, out);
    if (size) *size = got;
    return true;
}

static bool fri_stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int fri_open_input(struct zcl_fri_image *img, const char *host_file,
                          struct stat *st)
{
    int fd = open(host_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        const char *why = errno == ENOENT ? ZCL_FRI_WHY_MISSING :
                          errno == ELOOP ? ZCL_FRI_WHY_SPECIAL :
                          ZCL_FRI_WHY_UNREADABLE;
        fri_fail(img, why, host_file);
        return -1;
    }
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        fri_fail(img, ZCL_FRI_WHY_SPECIAL, host_file);
        return -1;
    }
    if ((uint64_t)st->st_size > ZCL_FRI_MAX_FILE ||
        (uint64_t)st->st_size > ZCL_FRI_MAX_BYTES - img->bytes) {
        close(fd);
        fri_fail(img, ZCL_FRI_WHY_LIMIT, host_file);
        return -1;
    }
    return fd;
}

static bool fri_write_all(int fd, const unsigned char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* Streams src to dst, hashing the bytes read. */
static const char *fri_stream(int src, int dst, const struct stat *before,
                              uint8_t sha3[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    unsigned char buf[65536];
    uint64_t got = 0;
    for (;;) {
        ssize_t n = read(src, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return ZCL_FRI_WHY_UNREADABLE;
        if (n == 0) break;
        got += (uint64_t)n;
        if (got > (uint64_t)before->st_size) return ZCL_FRI_WHY_CHANGED;
        sha3_256_write(&h, buf, (size_t)n);
        if (!fri_write_all(dst, buf, (size_t)n)) return ZCL_FRI_WHY_WRITE;
    }
    struct stat after;
    if (got != (uint64_t)before->st_size || fstat(src, &after) != 0 ||
        !fri_stat_same(before, &after)) return ZCL_FRI_WHY_CHANGED;
    sha3_256_finalize(&h, sha3);
    return NULL;
}

static bool fri_record_copy(struct zcl_fri_image *img, const char *rel,
                            const char *host_file, unsigned mode,
                            const struct stat *st, const uint8_t sha3[32])
{
    struct zcl_fri_entry *e = fri_push(img, rel, 'F', mode);
    if (!e) return false;
    e->source = zcl_strdup(host_file, "fri_entry_source");
    if (!e->source) return fri_fail(img, ZCL_FRI_WHY_ALLOC, rel);
    e->size = (uint64_t)st->st_size;
    memcpy(e->sha3, sha3, 32u);
    img->bytes += e->size;
    if (img->after_copy) img->after_copy(img->hook_ctx, host_file);
    return true;
}

/* mode 0 derives 0555/0444 from the input's execute bits. */
static bool fri_copy(struct zcl_fri_image *img, const char *rel,
                     const char *host_file, unsigned mode)
{
    const struct zcl_fri_entry *have = zcl_fri_find(img, rel);
    if (have) return fri_same(have, 'F', NULL, host_file) ||
                     fri_fail(img, ZCL_FRI_WHY_CONFLICT, rel);
    if (!fri_parent_dir(img, rel)) return false;
    struct stat st;
    int src = fri_open_input(img, host_file, &st);
    if (src < 0) return false;
    char path[PATH_MAX];
    int dst = fri_img(img, rel, path)
        ? open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)
        : -1;
    if (dst < 0) { close(src); return fri_fail(img, ZCL_FRI_WHY_WRITE, rel); }
    uint8_t sha3[32];
    const char *why = fri_stream(src, dst, &st, sha3);
    if (!mode) mode = (st.st_mode & 0111) ? 0555u : 0444u;
    if (!why && fchmod(dst, mode) != 0) why = ZCL_FRI_WHY_WRITE;
    if (close(dst) != 0 && !why) why = ZCL_FRI_WHY_WRITE;
    close(src);
    if (why) return fri_fail(img, why, host_file);
    return fri_record_copy(img, rel, host_file, mode, &st, sha3);
}

bool zcl_fri_add_copy(struct zcl_fri_image *img, const char *rel,
                      const char *host_file)
{
    if (!rel || !*rel || rel[0] == '/' || !host_file || host_file[0] != '/')
        return fri_fail(img, ZCL_FRI_WHY_ARGS, rel);
    return fri_copy(img, rel, host_file, 0);
}

bool zcl_fri_add_empty(struct zcl_fri_image *img, const char *rel,
                       unsigned mode)
{
    const struct zcl_fri_entry *have = zcl_fri_find(img, rel);
    if (have) return fri_fail(img, ZCL_FRI_WHY_CONFLICT, rel);
    if (!fri_parent_dir(img, rel)) return false;
    char path[PATH_MAX];
    int fd = fri_img(img, rel, path)
        ? open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)
        : -1;
    bool ok = fd >= 0 && fchmod(fd, mode) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (!ok) return fri_fail(img, ZCL_FRI_WHY_WRITE, rel);
    struct zcl_fri_entry *e = fri_push(img, rel, 'F', mode);
    if (!e) return false;
    zcl_sha3_256((const unsigned char *)"", 0, e->sha3);
    return true;
}

static bool fri_resolve(struct zcl_fri_image *img, const char *path,
                        unsigned hops, bool from_link,
                        char physical[PATH_MAX]);

/* The link's stored target: an absolute target climbs to the image root
 * from the link's physical directory; a relative one is kept verbatim. */
static bool fri_link_target(char out[PATH_MAX], const char *dir,
                            const char *target)
{
    if (target[0] != '/') {
        return snprintf(out, PATH_MAX, "%s", target) < PATH_MAX;
    }
    size_t used = 0;
    unsigned depth = fri_depth(dir);
    out[0] = '\0';
    for (unsigned i = 0; i < depth; i++) {
        int n = snprintf(out + used, PATH_MAX - used, "%s..", i ? "/" : "");
        if (n < 0 || (size_t)n >= PATH_MAX - used) return false;
        used += (size_t)n;
    }
    const char *rest = fri_rel(target);
    int n = snprintf(out + used, PATH_MAX - used, "%s%s",
                     (used && *rest) ? "/" : "", *rest ? rest : (used ? "" : "."));
    return n >= 0 && (size_t)n < PATH_MAX - used;
}

static bool fri_visit_link(struct zcl_fri_image *img, const char *next,
                           const char *host, char cur[PATH_MAX],
                           unsigned hops)
{
    char target[PATH_MAX], stored[PATH_MAX], abs[PATH_MAX];
    ssize_t n = readlink(host, target, sizeof(target));
    if (n <= 0 || n >= (ssize_t)sizeof(target))
        return fri_fail(img, ZCL_FRI_WHY_UNREADABLE, next);
    target[n] = '\0';
    if (hops >= FRI_MAX_HOPS) return fri_fail(img, ZCL_FRI_WHY_LOOP, next);
    if (!fri_link_target(stored, cur, target) ||
        !(target[0] == '/' ? snprintf(abs, sizeof(abs), "%s", target) < PATH_MAX
                           : fri_join(abs, cur, target)))
        return fri_fail(img, ZCL_FRI_WHY_LIMIT, next);
    const char *rel = fri_rel(next);
    const struct zcl_fri_entry *have = zcl_fri_find(img, rel);
    if (have && !fri_same(have, 'L', stored, NULL))
        return fri_fail(img, ZCL_FRI_WHY_CONFLICT, rel);
    if (!have) {
        char path[PATH_MAX];
        if (!fri_img(img, rel, path) || symlink(stored, path) != 0)
            return fri_fail(img, ZCL_FRI_WHY_WRITE, rel);
        struct zcl_fri_entry *e = fri_push(img, rel, 'L', 0777);
        if (!e) return false;
        e->target = zcl_strdup(stored, "fri_entry_target");
        if (!e->target) return fri_fail(img, ZCL_FRI_WHY_ALLOC, rel);
    }
    return fri_resolve(img, abs, hops + 1u, true, cur);
}

static bool fri_visit(struct zcl_fri_image *img, const char *next, bool last,
                      unsigned hops, char cur[PATH_MAX])
{
    char host[PATH_MAX];
    struct stat st;
    if (!fri_host(img, next, host)) return fri_fail(img, ZCL_FRI_WHY_LIMIT, next);
    if (lstat(host, &st) != 0) {
        const char *why = errno == ENOENT ? ZCL_FRI_WHY_MISSING :
                          errno == ENOTDIR ? ZCL_FRI_WHY_NOT_DIR :
                          ZCL_FRI_WHY_UNREADABLE;
        return fri_fail(img, why, next);
    }
    if (S_ISLNK(st.st_mode)) return fri_visit_link(img, next, host, cur, hops);
    if (S_ISDIR(st.st_mode)) {
        if (!zcl_fri_add_dir(img, fri_rel(next))) return false;
        snprintf(cur, PATH_MAX, "%s", next);
        return true;
    }
    if (!S_ISREG(st.st_mode)) return fri_fail(img, ZCL_FRI_WHY_SPECIAL, next);
    if (!last) return fri_fail(img, ZCL_FRI_WHY_NOT_DIR, next);
    if (!fri_copy(img, fri_rel(next), host, 0)) return false;
    snprintf(cur, PATH_MAX, "%s", next);
    return true;
}

static bool fri_component(const char **p, char comp[NAME_MAX + 1], bool *last)
{
    while (**p == '/') (*p)++;
    if (!**p) return false;
    const char *end = strchr(*p, '/');
    size_t n = end ? (size_t)(end - *p) : strlen(*p);
    if (n > NAME_MAX) n = NAME_MAX;
    memcpy(comp, *p, n);
    comp[n] = '\0';
    *p += n;
    const char *rest = *p;
    while (*rest == '/') rest++;
    *last = *rest == '\0';
    return true;
}

static bool fri_resolve(struct zcl_fri_image *img, const char *path,
                        unsigned hops, bool from_link,
                        char physical[PATH_MAX])
{
    if (path[0] != '/') return fri_fail(img, ZCL_FRI_WHY_ARGS, path);
    char cur[PATH_MAX] = "/", comp[NAME_MAX + 1], next[PATH_MAX];
    const char *p = path;
    bool last = false;
    while (fri_component(&p, comp, &last)) {
        if (strcmp(comp, ".") == 0) continue;
        if (strcmp(comp, "..") == 0) {
            /* ".." at "/" stays at "/" in a jail, but a link that climbs
             * past its root would resolve outside the image on the host. */
            if (from_link && strcmp(cur, "/") == 0)
                return fri_fail(img, ZCL_FRI_WHY_ESCAPES, path);
            fri_parent(cur);
            continue;
        }
        if (!fri_join(next, cur, comp)) return fri_fail(img, ZCL_FRI_WHY_LIMIT, path);
        if (!fri_visit(img, next, last, hops, cur)) return false;
    }
    snprintf(physical, PATH_MAX, "%s", cur);
    return true;
}

bool zcl_fri_add_host_path(struct zcl_fri_image *img, const char *host_path,
                           char physical[PATH_MAX])
{
    char ignored[PATH_MAX];
    if (!host_path || host_path[0] != '/')
        return fri_fail(img, ZCL_FRI_WHY_ARGS, host_path);
    return fri_resolve(img, host_path, 0, false, physical ? physical : ignored);
}

bool zcl_fri_image_begin(struct zcl_fri_image *img, const char *root,
                         const char *host_root)
{
    memset(img, 0, sizeof(*img));
    if (!root || root[0] != '/' ||
        snprintf(img->root, sizeof(img->root), "%s", root) >= PATH_MAX ||
        snprintf(img->host_root, sizeof(img->host_root), "%s",
                 host_root ? host_root : "") >= PATH_MAX)
        return fri_fail(img, ZCL_FRI_WHY_ARGS, root);
    size_t n = strlen(img->host_root);
    if (n && img->host_root[n - 1] == '/') img->host_root[n - 1] = '\0';
    if (mkdir(img->root, 0700) != 0)
        return fri_fail(img, errno == EEXIST ? ZCL_FRI_WHY_ROOT_EXISTS
                                             : ZCL_FRI_WHY_WRITE, root);
    char real[PATH_MAX];
    if (chmod(img->root, 0755) != 0 || !realpath(img->root, real) ||
        strcmp(real, img->root) != 0)
        return fri_fail(img, ZCL_FRI_WHY_ROOT_UNSAFE, root);
    return true;
}

void zcl_fri_image_free(struct zcl_fri_image *img)
{
    for (size_t i = 0; i < img->count; i++) {
        free(img->entries[i].path);
        free(img->entries[i].target);
        free(img->entries[i].source);
    }
    free(img->entries);
    img->entries = NULL;
    img->count = img->cap = 0;
}

static bool fri_bytes_match(const char *path, const struct zcl_fri_entry *e)
{
    uint8_t sha3[32];
    uint64_t size = 0;
    return zcl_fri_sha3_file(path, sha3, &size) && size == e->size &&
           memcmp(sha3, e->sha3, 32u) == 0;
}

static bool fri_link_matches(const char *path, const struct zcl_fri_entry *e)
{
    char target[PATH_MAX];
    ssize_t n = readlink(path, target, sizeof(target) - 1u);
    if (n < 0) return false;
    target[n] = '\0';
    return strcmp(target, e->target) == 0;
}

static bool fri_verify_entry(struct zcl_fri_image *img,
                             const struct zcl_fri_entry *e)
{
    char path[PATH_MAX];
    struct stat st;
    if (!fri_img(img, e->path, path)) return fri_fail(img, ZCL_FRI_WHY_LIMIT, e->path);
    if (e->kind == 'F' && e->source && !fri_bytes_match(e->source, e))
        return fri_fail(img, ZCL_FRI_WHY_CHANGED, e->source);
    bool same = e->kind == 'F' ? fri_bytes_match(path, e)
              : e->kind == 'L' ? fri_link_matches(path, e)
              : lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
                (st.st_mode & 07777) == e->mode;
    return same || fri_fail(img, ZCL_FRI_WHY_IMAGE_CHANGED, e->path);
}

bool zcl_fri_image_finish(struct zcl_fri_image *img,
                          struct zcl_fri_roots *roots)
{
    memset(roots, 0, sizeof(*roots));
    if (img->why) return false;
    for (size_t i = 0; i < img->count; i++)
        if (!fri_verify_entry(img, &img->entries[i])) return false;
    struct zcl_tree_closure_roots measured, predicted;
    uid_t owner = geteuid(), zero = 0;
    const char *why = zcl_tree_closure_hash(img->root, owner, NULL, &measured);
    if (!why) why = zcl_tree_closure_hash(img->root, owner, &zero, &predicted);
    if (why) return fri_fail(img, why, img->root);
    if (measured.entries != img->count + 1u ||
        memcmp(measured.content_sha3, predicted.content_sha3, 32u) != 0)
        return fri_fail(img, ZCL_FRI_WHY_EXTRA, img->root);
    memcpy(roots->tree_sha3, measured.tree_sha3, 32u);
    memcpy(roots->content_sha3, measured.content_sha3, 32u);
    memcpy(roots->root_tree_sha3, predicted.tree_sha3, 32u);
    roots->owner = owner;
    roots->entries = measured.entries;
    roots->bytes = measured.bytes;
    return true;
}

static int fri_entry_order(const void *a, const void *b)
{
    const struct zcl_fri_entry *const *x = a, *const *y = b;
    return strcmp((*x)->path, (*y)->path);
}

static bool fri_manifest_entry(const struct zcl_fri_entry *e, FILE *out)
{
    char hex[65];
    if (e->kind == 'D') return fprintf(out, "D %04o %s\n", e->mode, e->path) > 0;
    if (e->kind == 'L') return fprintf(out, "L %s -> %s\n", e->path, e->target) > 0;
    zcl_hex_encode(e->sha3, 32u, hex);
    return fprintf(out, "F %04o %llu %s %s\n", e->mode,
                   (unsigned long long)e->size, hex, e->path) > 0;
}

bool zcl_fri_manifest_write(const struct zcl_fri_image *img, const char *kind,
                            const struct zcl_fri_roots *roots, FILE *out)
{
    const struct zcl_fri_entry **order =
        zcl_malloc(img->count ? img->count * sizeof(*order) : 1u,
                   "fri_manifest_order");
    if (!order) return false;
    unsigned files = 0, links = 0, dirs = 0;
    for (size_t i = 0; i < img->count; i++) {
        order[i] = &img->entries[i];
        files += img->entries[i].kind == 'F';
        links += img->entries[i].kind == 'L';
        dirs += img->entries[i].kind == 'D';
    }
    qsort(order, img->count, sizeof(*order), fri_entry_order);
    bool ok = fprintf(out, "z23verify.fixed_result.image.v1\nkind=%s\n", kind) > 0;
    for (size_t i = 0; ok && i < img->count; i++)
        ok = fri_manifest_entry(order[i], out);
    free(order);
    char tree[65], content[65], root_tree[65];
    zcl_hex_encode(roots->tree_sha3, 32u, tree);
    zcl_hex_encode(roots->content_sha3, 32u, content);
    zcl_hex_encode(roots->root_tree_sha3, 32u, root_tree);
    return ok && fprintf(out,
        "entries=%u files=%u links=%u dirs=%u bytes=%llu\n"
        "content_sha3=%s\ntree_sha3=%s owner_uid=%u\nroot_tree_sha3=%s\n",
        roots->entries, files, links, dirs, (unsigned long long)roots->bytes,
        content, tree, (unsigned)roots->owner, root_tree) > 0;
}

/* ── chroot-style lookup inside a finished image ─────────────────────── */

struct fri_walk {
    char cur[PATH_MAX];   /* image-relative physical directory, "" = root */
    char rest[PATH_MAX];  /* components still to resolve */
    unsigned hops;
};

static bool fri_walk_link(struct fri_walk *w, const char *link_path)
{
    char target[PATH_MAX], rest[PATH_MAX];
    ssize_t n = readlink(link_path, target, sizeof(target) - 1u);
    if (n <= 0 || ++w->hops > FRI_MAX_HOPS) return false;
    target[n] = '\0';
    snprintf(rest, sizeof(rest), "%s", w->rest);
    if (target[0] == '/') w->cur[0] = '\0';
    return snprintf(w->rest, sizeof(w->rest), "%s/%s", target, rest) < PATH_MAX;
}

static char fri_walk_step(struct fri_walk *w, const char *image_root,
                          const char *comp, bool last)
{
    char rel[PATH_MAX], path[PATH_MAX];
    struct stat st;
    if (strcmp(comp, "..") == 0) {
        char *slash = strrchr(w->cur, '/');
        if (slash) *slash = '\0'; else w->cur[0] = '\0';
        return 'D';
    }
    if (snprintf(rel, sizeof(rel), "%s%s%s", w->cur, *w->cur ? "/" : "", comp)
            >= PATH_MAX || !fri_join(path, image_root, rel) ||
        lstat(path, &st) != 0) return 0;
    if (S_ISLNK(st.st_mode)) return fri_walk_link(w, path) ? 'D' : 'L';
    snprintf(w->cur, sizeof(w->cur), "%s", rel);
    if (S_ISDIR(st.st_mode)) return 'D';
    return (S_ISREG(st.st_mode) && last) ? 'F' : 0;
}

char zcl_fri_image_lookup(const char *image_root, const char *path,
                          char rel[PATH_MAX])
{
    struct fri_walk w = {0};
    if (!path || path[0] != '/' ||
        snprintf(w.rest, sizeof(w.rest), "%s", path) >= PATH_MAX) return 0;
    char kind = 'D', comp[NAME_MAX + 1];
    for (;;) {
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s", w.rest);
        const char *p = buf;
        bool last = false;
        if (!fri_component(&p, comp, &last)) break;
        snprintf(w.rest, sizeof(w.rest), "%s", p);
        if (strcmp(comp, ".") == 0) continue;
        kind = fri_walk_step(&w, image_root, comp, last);
        if (kind == 0 || kind == 'L') return kind;
        if (kind == 'F') break;
    }
    snprintf(rel, PATH_MAX, "%s", w.cur);
    return kind;
}
