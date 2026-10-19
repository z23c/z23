/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Legacy seed driver: refusals, the datadir in-use probe, stage and finish.
 * The walker and copier live in legacy_seed_walk.c and legacy_seed_copy.c. */

#ifndef _WIN32

#define _GNU_SOURCE

#include "command/legacy_seed_priv.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static struct lseed_hooks g_hooks;

struct lseed_hooks *lseed_hooks(void)
{
    return &g_hooks;
}

static const char *const k_names[LSEED_REFUSAL_COUNT] = {
    [LSEED_OK] = "ok",
    [LSEED_BAD_INPUT] = "bad_input",
    [LSEED_SOURCE_MISSING] = "source_missing",
    [LSEED_SOURCE_SYMLINK] = "source_symlink",
    [LSEED_TARGET_SYMLINK] = "target_symlink",
    [LSEED_TARGET_EXISTS] = "target_exists",
    [LSEED_OWNER_MISMATCH] = "owner_mismatch",
    [LSEED_SOURCE_RUNNING] = "source_running",
    [LSEED_SOURCE_LOCKED] = "source_locked",
    [LSEED_GAP_EXCEEDED] = "gap_exceeded",
    [LSEED_INSUFFICIENT_SPACE] = "insufficient_space",
    [LSEED_SYMLINK_IN_TREE] = "symlink_in_tree",
    [LSEED_SPECIAL_FILE] = "special_file",
    [LSEED_TMP_MISMATCH] = "tmp_mismatch",
    [LSEED_PLAN_MISMATCH] = "plan_mismatch",
    [LSEED_COPY_FAILED] = "copy_failed",
    [LSEED_RECEIPT_FAILED] = "receipt_failed",
    [LSEED_SOURCE_LOCK_MISSING] = "source_lock_missing",
};

const char *lseed_refusal_name(enum lseed_refusal code)
{
    return (unsigned)code < LSEED_REFUSAL_COUNT ? k_names[code] : "unknown";
}

void lseed_request_defaults(struct lseed_request *req)
{
    memset(req, 0, sizeof(*req));
    req->max_gap = LSEED_DEFAULT_MAX_GAP;
    req->source_height = -1;
    req->z23_height = -1;
    req->margin_bytes = (uint64_t)LSEED_DEFAULT_MARGIN_MIB << 20;
    req->workers = LSEED_DEFAULT_WORKERS;
}

static void lseed_hex32(const unsigned char *in, char out[65])
{
    for (size_t i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", in[i]);
}

static void lseed_parent_of(const char *path, char *out, size_t cap);

/* Everything else the plan is bound to, as fixed-width little records. */
static void lseed_plan_bind(struct sha3_256_ctx *ctx, const struct lseed_request *req)
{
    char parent[LSEED_PATH_MAX];
    struct stat st;
    long long vals[8] = { 0 };
    vals[0] = req->source_height;
    vals[1] = req->z23_height;
    vals[2] = req->workers;
    vals[3] = (long long)req->margin_bytes;
    if (lstat(req->source, &st) == 0) {
        vals[4] = (long long)st.st_dev;
        vals[5] = (long long)st.st_ino;
    }
    lseed_parent_of(req->target, parent, sizeof(parent));
    if (lstat(parent, &st) == 0) {
        vals[6] = (long long)st.st_dev;
        vals[7] = (long long)st.st_ino;
    }
    sha3_256_write(ctx, (const unsigned char *)vals, sizeof(vals));
}

void lseed_plan_id(const struct lseed_request *req, char out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char d[32];
    char tail[32];
    static const char tag[] = "z23.legacy_seed.plan.v1";
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)tag, sizeof(tag));
    sha3_256_write(&ctx, (const unsigned char *)req->source,
                   strlen(req->source) + 1);
    sha3_256_write(&ctx, (const unsigned char *)req->target,
                   strlen(req->target) + 1);
    (void)snprintf(tail, sizeof(tail), "%lld", (long long)req->max_gap);
    sha3_256_write(&ctx, (const unsigned char *)tail, strlen(tail) + 1);
    lseed_plan_bind(&ctx, req);
    sha3_256_finalize(&ctx, d);
    lseed_hex32(d, out);
}

/* ---- in-use probe ---------------------------------------------------- */

static bool lseed_pid_alive(const char *datadir, long *pid_out)
{
    char path[LSEED_PATH_MAX + 32];
    long pid = 0;
    (void)snprintf(path, sizeof(path), "%s/zclassicd.pid", datadir);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    bool got = fscanf(f, "%ld", &pid) == 1 && pid > 1;
    fclose(f);
    if (got && (kill((pid_t)pid, 0) == 0 || errno == EPERM)) {
        if (pid_out)
            *pid_out = pid;
        return true;
    }
    return false;
}

static int lseed_open_lock(const char *datadir)
{
    char path[LSEED_PATH_MAX + 32];
    (void)snprintf(path, sizeof(path), "%s/.lock", datadir);
    return open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
}

/* Takes the lock for the caller to hold (fd out) or just probes (fd NULL). */
static bool lseed_lock_taken(int fd, int *hold)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
        return true;
    if (hold) {
        if (fcntl(fd, F_OFD_SETLK, &fl) != 0) {
            flock(fd, LOCK_UN);
            return true;
        }
        *hold = fd;
        return false;
    }
    flock(fd, LOCK_UN);
    fl.l_pid = 0;
    return fcntl(fd, F_OFD_GETLK, &fl) != 0 || fl.l_type != F_UNLCK;
}

bool lseed_datadir_in_use(const char *datadir, long *pid_out)
{
    if (lseed_pid_alive(datadir, pid_out))
        return true;
    int fd = lseed_open_lock(datadir);
    if (fd < 0)
        return false;
    bool taken = lseed_lock_taken(fd, NULL);
    close(fd);
    return taken;
}

/* ---- preflight -------------------------------------------------------- */

static enum lseed_refusal lseed_refuse(char *why, size_t cap, enum lseed_refusal rc,
                                 const char *text)
{
    (void)snprintf(why, cap, "%s", text);
    return rc;
}

static uid_t lseed_want_uid(void)
{
    return g_hooks.owner_override ? (uid_t)g_hooks.owner_uid : geteuid();
}

static enum lseed_refusal lseed_check_source(const char *path, char *why, size_t cap)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return lseed_refuse(why, cap, LSEED_SOURCE_MISSING, "source does not exist");
    if (S_ISLNK(st.st_mode))
        return lseed_refuse(why, cap, LSEED_SOURCE_SYMLINK, "source is a symlink");
    if (!S_ISDIR(st.st_mode))
        return lseed_refuse(why, cap, LSEED_SOURCE_MISSING, "source is not a directory");
    if (st.st_uid != lseed_want_uid())
        return lseed_refuse(why, cap, LSEED_OWNER_MISMATCH,
                      "source is not owned by the invoking user");
    return LSEED_OK;
}

static void lseed_parent_of(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    size_t len = slash ? (size_t)(slash - path) : 0;
    (void)snprintf(out, cap, "%.*s", (int)(len ? len : 1), len ? path : "/");
}

static enum lseed_refusal lseed_check_target(const struct lseed_request *req,
                                       char *why, size_t cap)
{
    struct stat st;
    char parent[LSEED_PATH_MAX];
    lseed_parent_of(req->target, parent, sizeof(parent));
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode))
        return lseed_refuse(why, cap, S_ISLNK(st.st_mode) ? LSEED_TARGET_SYMLINK
                                                    : LSEED_BAD_INPUT,
                      "target parent is missing or a symlink");
    if (st.st_uid != lseed_want_uid())
        return lseed_refuse(why, cap, LSEED_OWNER_MISMATCH,
                      "target parent is not owned by the invoking user");
    if (lstat(req->target, &st) == 0)
        return lseed_refuse(why, cap, S_ISLNK(st.st_mode) ? LSEED_TARGET_SYMLINK
                                                    : LSEED_TARGET_EXISTS,
                      "target already exists; seeding never overwrites");
    return LSEED_OK;
}

static void lseed_tmp_path(const struct lseed_request *req, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s.tmp", req->target);
}

static enum lseed_refusal lseed_check_tmp(const struct lseed_request *req,
                                    struct lseed_plan *plan, char *why,
                                    size_t cap)
{
    char tmp[LSEED_PATH_MAX + 8], marker[LSEED_PATH_MAX + 32], got[LSEED_PATH_MAX];
    struct stat st;
    lseed_tmp_path(req, tmp, sizeof(tmp));
    if (lstat(tmp, &st) != 0)
        return LSEED_OK;
    plan->tmp_present = true;
    if (!S_ISDIR(st.st_mode) || st.st_uid != lseed_want_uid())
        return lseed_refuse(why, cap, LSEED_TMP_MISMATCH,
                      "target.tmp is not a directory owned by this user");
    (void)snprintf(marker, sizeof(marker), "%s/%s", tmp, LSEED_MARKER_NAME);
    FILE *f = fopen(marker, "r");
    bool same = f && fgets(got, sizeof(got), f) &&
                (got[strcspn(got, "\n")] = '\0', strcmp(got, req->source) == 0);
    if (f)
        fclose(f);
    return same ? LSEED_OK
                : lseed_refuse(why, cap, LSEED_TMP_MISMATCH,
                         "target.tmp belongs to another source or has no "
                         "marker; remove it first");
}

static int64_t lseed_free_space(const struct lseed_request *req)
{
    char parent[LSEED_PATH_MAX];
    struct statvfs sv;
    lseed_parent_of(req->target, parent, sizeof(parent));
    if (g_hooks.free_bytes)
        return g_hooks.free_bytes(g_hooks.ctx, parent);
    if (statvfs(parent, &sv) != 0)
        return -1;
    return (int64_t)((uint64_t)sv.f_bavail * sv.f_frsize);
}

static enum lseed_refusal lseed_check_gap(const struct lseed_request *req, char *why,
                                    size_t cap)
{
    if (req->source_height < 0 || req->z23_height < 0)
        return LSEED_OK;
    if (req->z23_height - req->source_height <= req->max_gap)
        return LSEED_OK;
    (void)snprintf(why, cap, "source trails the z23 tip by %lld blocks (max %lld)",
                   (long long)(req->z23_height - req->source_height),
                   (long long)req->max_gap);
    return LSEED_GAP_EXCEEDED;
}

static enum lseed_refusal lseed_check_space(const struct lseed_request *req,
                                      struct lseed_plan *plan, char *why,
                                      size_t cap)
{
    int64_t avail = lseed_free_space(req);
    if (avail < 0)
        return lseed_refuse(why, cap, LSEED_INSUFFICIENT_SPACE,
                      "cannot determine free space; refusing");
    plan->free_bytes = (uint64_t)avail;
    if ((uint64_t)avail >= plan->bytes + req->margin_bytes)
        return LSEED_OK;
    (void)snprintf(why, cap, "free %llu bytes < source %llu + margin %llu",
                   (unsigned long long)avail, (unsigned long long)plan->bytes,
                   (unsigned long long)req->margin_bytes);
    return LSEED_INSUFFICIENT_SPACE;
}

static enum lseed_refusal lseed_check_paths(const struct lseed_request *req, char *why,
                                      size_t cap)
{
    if (req->source[0] != '/' || req->target[0] != '/' ||
        strcmp(req->source, req->target) == 0 || req->max_gap < 0)
        return lseed_refuse(why, cap, LSEED_BAD_INPUT,
                      "source and target must be distinct absolute paths");
    return LSEED_OK;
}

static enum lseed_refusal lseed_survey(const struct lseed_request *req,
                                 struct lseed_plan *plan, char *why, size_t cap)
{
    struct lseed_tree tree;
    int fd = open(req->source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return lseed_refuse(why, cap, LSEED_SOURCE_SYMLINK, "cannot open source");
    enum lseed_refusal rc = lseed_walk(fd, &tree, why, cap);
    close(fd);
    if (rc != LSEED_OK)
        return rc;
    for (size_t i = 0; i < tree.n; i++) {
        plan->files += tree.e[i].dir ? 0 : 1;
        plan->immutable_files += (!tree.e[i].dir && !tree.e[i].tail) ? 1 : 0;
    }
    plan->bytes = tree.bytes;
    plan->excluded_files = tree.excluded;
    plan->tail_pair = tree.tail_pair;
    lseed_tree_free(&tree);
    return LSEED_OK;
}

enum lseed_refusal lseed_preflight(const struct lseed_request *req,
                                   bool require_stopped,
                                   struct lseed_plan *plan, char *why,
                                   size_t why_cap)
{
    enum lseed_refusal rc;
    memset(plan, 0, sizeof(*plan));
    why[0] = '\0';
    lseed_plan_id(req, plan->plan_id);
    if ((rc = lseed_check_paths(req, why, why_cap)) != LSEED_OK ||
        (rc = lseed_check_source(req->source, why, why_cap)) != LSEED_OK ||
        (rc = lseed_check_target(req, why, why_cap)) != LSEED_OK ||
        (rc = lseed_check_tmp(req, plan, why, why_cap)) != LSEED_OK ||
        (rc = lseed_survey(req, plan, why, why_cap)) != LSEED_OK ||
        (rc = lseed_check_gap(req, why, why_cap)) != LSEED_OK ||
        (rc = lseed_check_space(req, plan, why, why_cap)) != LSEED_OK)
        return rc;
    plan->source_running = lseed_datadir_in_use(req->source, NULL);
    if (require_stopped && plan->source_running)
        return lseed_refuse(why, why_cap, LSEED_SOURCE_RUNNING,
                      "source is running (pid file or datadir lock); stop it");
    return LSEED_OK;
}

/* ---- stage and finish --------------------------------------------------- */

static int lseed_make_tmp(const struct lseed_request *req, char *tmp, size_t cap)
{
    char marker[LSEED_PATH_MAX + 32];
    lseed_tmp_path(req, tmp, cap);
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
        return -1;
    int dfd = open(tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0)
        return -1;
    (void)snprintf(marker, sizeof(marker), "%s", LSEED_MARKER_NAME);
    int mfd = openat(dfd, marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (mfd >= 0) {
        char line[LSEED_PATH_MAX + 2];
        int n = snprintf(line, sizeof(line), "%s\n", req->source);
        bool ok = write(mfd, line, (size_t)n) == n && fsync(mfd) == 0;
        close(mfd);
        if (!ok) {
            close(dfd);
            return -1;
        }
    } else if (errno != EEXIST) {
        close(dfd);
        return -1;
    }
    return dfd;
}

enum lseed_refusal lseed_stage(const struct lseed_request *req,
                               struct lseed_result *res, char *why,
                               size_t why_cap)
{
    struct lseed_plan plan;
    struct lseed_tree tree;
    struct lseed_counts counts = { 0 };
    char tmp[LSEED_PATH_MAX + 8];
    memset(res, 0, sizeof(*res));
    enum lseed_refusal rc = lseed_preflight(req, false, &plan, why, why_cap);
    if (rc != LSEED_OK)
        return rc;
    int64_t t0 = platform_time_monotonic_ms();
    int dst = lseed_make_tmp(req, tmp, sizeof(tmp));
    int src = open(req->source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dst < 0 || src < 0 ||
        (rc = lseed_walk(src, &tree, why, why_cap)) != LSEED_OK) {
        if (rc == LSEED_OK)
            rc = lseed_refuse(why, why_cap, LSEED_COPY_FAILED, "cannot open stage dirs");
        goto out;
    }
    rc = lseed_copy_tree(src, dst, &tree, lseed_want_stage, req->workers,
                         &counts, why, why_cap);
    if (rc == LSEED_OK && !lseed_sync_dirs(dst, &tree))
        rc = lseed_refuse(why, why_cap, LSEED_COPY_FAILED, "directory fsync failed");
    lseed_tree_free(&tree);
out:
    if (src >= 0)
        close(src);
    if (dst >= 0)
        close(dst);
    res->files = plan.files;
    res->bytes = counts.bytes;
    res->copied_files = counts.copied;
    res->resumed_files = counts.resumed;
    res->cloned_files = counts.cloned;
    res->excluded_files = plan.excluded_files;
    res->stage_ms = (uint64_t)(platform_time_monotonic_ms() - t0);
    return rc;
}

static bool lseed_write_receipt(const struct lseed_request *req, int dst,
                          struct lseed_tree *tree, struct lseed_result *res)
{
    struct sha3_256_ctx ctx;
    unsigned char d[32];
    char line[LSEED_PATH_MAX + 96], buf[4096];
    struct json_value doc;
    sha3_256_init(&ctx);
    for (size_t i = 0; i < tree->n; i++) {
        if (tree->e[i].dir)
            continue;
        int n = snprintf(line, sizeof(line), "%s\t%llu\t%s\n", tree->e[i].rel,
                         (unsigned long long)tree->e[i].size, tree->e[i].sha3);
        sha3_256_write(&ctx, (const unsigned char *)line, (size_t)n);
    }
    sha3_256_finalize(&ctx, d);
    lseed_hex32(d, res->manifest_sha3);
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_str(&doc, "schema", "zcl.legacy_seed_receipt.v1");
    (void)json_push_kv_str(&doc, "source", req->source);
    (void)json_push_kv_str(&doc, "target", req->target);
    (void)json_push_kv_int(&doc, "files", (int64_t)res->files);
    (void)json_push_kv_int(&doc, "bytes", (int64_t)res->bytes);
    (void)json_push_kv_str(&doc, "manifest_sha3", res->manifest_sha3);
    (void)json_push_kv_int(&doc, "z23_height", req->z23_height);
    (void)json_push_kv_int(&doc, "source_height", req->source_height);
    (void)json_push_kv_int(&doc, "created_unix", platform_time_wall_unix());
    (void)json_push_kv_int(&doc, "phase_b_ms", (int64_t)res->phase_b_ms);
    size_t len = json_write(&doc, buf, sizeof(buf) - 1);
    json_free(&doc);
    int fd = len > 0 && len < sizeof(buf) - 1
                 ? openat(dst, LSEED_RECEIPT_NAME,
                          O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                          0600)
                 : -1;
    bool ok = fd >= 0 && write(fd, buf, len) == (ssize_t)len &&
              write(fd, "\n", 1) == 1 && fsync(fd) == 0;
    if (fd >= 0)
        close(fd);
    return ok;
}

static enum lseed_refusal lseed_publish(const struct lseed_request *req,
                                  const char *tmp, int dst, char *why,
                                  size_t cap)
{
    char parent[LSEED_PATH_MAX];
    (void)unlinkat(dst, LSEED_MARKER_NAME, 0);
    if (fsync(dst) != 0 ||
        renameat2(AT_FDCWD, tmp, AT_FDCWD, req->target,
                RENAME_NOREPLACE) != 0)
        return lseed_refuse(why, cap, LSEED_COPY_FAILED,
                      "atomic rename to target failed; target.tmp kept");
    lseed_parent_of(req->target, parent, sizeof(parent));
    int pfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (pfd >= 0) {
        (void)fsync(pfd);
        close(pfd);
    }
    return LSEED_OK;
}

/* Copy everything under the held lock; the downtime window is this call. */
static enum lseed_refusal lseed_copy_stopped(const struct lseed_request *req, int src,
                                       int dst, struct lseed_tree *tree,
                                       struct lseed_counts *counts, char *why,
                                       size_t cap)
{
    enum lseed_refusal rc = lseed_walk(src, tree, why, cap);
    if (rc != LSEED_OK)
        return rc;
    rc = lseed_copy_tree(src, dst, tree, lseed_want_all, req->workers, counts,
                         why, cap);
    if (rc == LSEED_OK &&
        (!lseed_prune_extra(dst, tree) || !lseed_sync_dirs(dst, tree)))
        rc = lseed_refuse(why, cap, LSEED_COPY_FAILED, "prune or fsync failed");
    return rc;
}

enum lseed_refusal lseed_finish(const struct lseed_request *req,
                                struct lseed_result *res, char *why,
                                size_t why_cap)
{
    struct lseed_plan plan;
    struct lseed_tree tree = { 0 };
    struct lseed_counts counts = { 0 };
    char tmp[LSEED_PATH_MAX + 8];
    int hold = -1;
    memset(res, 0, sizeof(*res));
    enum lseed_refusal rc = lseed_preflight(req, true, &plan, why, why_cap);
    if (rc != LSEED_OK)
        return rc;
    int lockfd = lseed_open_lock(req->source);
    if (lockfd < 0)
        return lseed_refuse(why, why_cap, LSEED_SOURCE_LOCK_MISSING,
                      "source has no readable .lock file, so a stopped source cannot be proven; start and cleanly stop it once, then retry");
    if (lseed_lock_taken(lockfd, &hold)) {
        close(lockfd);
        return lseed_refuse(why, why_cap, LSEED_SOURCE_LOCKED,
                      "source datadir lock is held by another process");
    }
    int64_t t0 = platform_time_monotonic_ms();
    int dst = lseed_make_tmp(req, tmp, sizeof(tmp));
    int src = open(req->source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    rc = (dst >= 0 && src >= 0)
             ? lseed_copy_stopped(req, src, dst, &tree, &counts, why, why_cap)
             : lseed_refuse(why, why_cap, LSEED_COPY_FAILED, "cannot open finish dirs");
    res->phase_b_ms = (uint64_t)(platform_time_monotonic_ms() - t0);
    if (hold >= 0)
        close(hold); /* releases flock and the OFD lock */
    if (rc == LSEED_OK) {
        int64_t h0 = platform_time_monotonic_ms();
        res->files = plan.files;
        res->bytes = tree.bytes;
        res->copied_files = counts.copied;
        res->resumed_files = counts.resumed;
        res->cloned_files = counts.cloned;
        res->excluded_files = tree.excluded;
        if (!lseed_hash_tree(dst, &tree, req->workers) ||
            !lseed_write_receipt(req, dst, &tree, res))
            rc = lseed_refuse(why, why_cap, LSEED_RECEIPT_FAILED,
                        "manifest hash or receipt write failed; target.tmp kept");
        res->hash_ms = (uint64_t)(platform_time_monotonic_ms() - h0);
    }
    if (rc == LSEED_OK)
        rc = lseed_publish(req, tmp, dst, why, why_cap);
    if (rc == LSEED_OK)
        (void)snprintf(res->receipt_path, sizeof(res->receipt_path), "%s/%s",
                       req->target, LSEED_RECEIPT_NAME);
    lseed_tree_free(&tree);
    if (src >= 0)
        close(src);
    if (dst >= 0)
        close(dst);
    return rc;
}

#else

typedef int lseed_posix_only_unused; /* empty on Windows */

#endif /* _WIN32 */
