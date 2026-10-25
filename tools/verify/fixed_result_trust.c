/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Descriptor-walk custody and trust loading for the fixed-result
 *          signer and publisher. See fixed_result_trust.h. */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verify/fixed_result_trust.h"

#include "base/safe_alloc.h"
#include "dev/verify_store.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRT_SMALL_MAX 4096u
#define FRT_PROFILE_MAX 65536u
#define FRT_POLICY_HEAD "z23verify.store.v1\nsigner_uid="
#define FRT_POLICY_TAIL "\npublisher_uid=0\n"

static void frt_why(const char **why, const char *token)
{
    if (why) *why = token;
}

static bool frt_dir_ok(const struct stat *st, uint32_t owner, bool private_dir)
{
    return S_ISDIR(st->st_mode) && (st->st_uid == owner || st->st_uid == 0) &&
           (st->st_mode & (private_dir ? 0077u : 0022u)) == 0;
}

int zcl_frt_open_root(const char **why)
{
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && fstat(fd, &st) == 0 && frt_dir_ok(&st, 0u, false))
        return fd;
    if (fd >= 0) (void)close(fd);
    frt_why(why, ZCL_FRT_WHY_PATH_UNSAFE);
    return -1;
}

int zcl_frt_open_dir(int parent, const char *name, uint32_t owner,
                     bool private_dir, const char **why)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);
    struct stat st;
    if (fd < 0) {
        frt_why(why, errno == ENOENT ? ZCL_FRT_WHY_FILE_MISSING
                                     : ZCL_FRT_WHY_PATH_UNSAFE);
        return -1;
    }
    /* A directory owned by `owner` passes frt_dir_ok's root clause only
     * when `owner` is itself root; otherwise require the exact owner. */
    if (fstat(fd, &st) != 0 || !frt_dir_ok(&st, owner, private_dir) ||
        (owner != 0 && st.st_uid != owner)) {
        (void)close(fd);
        frt_why(why, ZCL_FRT_WHY_PATH_UNSAFE);
        return -1;
    }
    return fd;
}

int zcl_frt_open_path(int start, const char *path, uint32_t owner,
                      const char **why)
{
    char part[PATH_MAX];
    size_t len = path ? strlen(path) : 0u;
    if (len == 0 || len >= sizeof(part) || path[0] == '/') {
        frt_why(why, ZCL_FRT_WHY_ARGUMENTS);
        return -1;
    }
    memcpy(part, path, len + 1u);
    int fd = dup(start);
    for (char *name = part, *next; fd >= 0 && name; name = next) {
        next = strchr(name, '/');
        if (next) *next++ = '\0';
        struct stat st;
        int child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                         O_CLOEXEC);
        (void)close(fd);
        fd = child;
        if (fd >= 0 && (fstat(fd, &st) != 0 || !frt_dir_ok(&st, owner, false))) {
            (void)close(fd);
            fd = -1;
        }
    }
    if (fd < 0) frt_why(why, ZCL_FRT_WHY_PATH_UNSAFE);
    return fd;
}

static bool frt_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_uid == b->st_uid && a->st_mode == b->st_mode &&
           a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static const char *frt_custody_check(const struct stat *st,
                                     const struct zcl_frt_custody *c)
{
    uint32_t perm = (uint32_t)st->st_mode & 07777u;
    if (!S_ISREG(st->st_mode) || st->st_uid != c->owner ||
        st->st_nlink != 1 || (perm & 0022u) != 0 ||
        (c->mode != 0 && perm != c->mode))
        return ZCL_FRT_WHY_FILE_UNSAFE;
    if (st->st_size < 0 || (uint64_t)st->st_size > c->max)
        return ZCL_FRT_WHY_FILE_LIMIT;
    return NULL;
}

static const char *frt_read_all(int fd, uint8_t *buf, size_t len)
{
    size_t at = 0;
    while (at < len) {
        ssize_t n = pread(fd, buf + at, len - at, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return ZCL_FRT_WHY_FILE_CHANGED;
        at += (size_t)n;
    }
    uint8_t extra;
    ssize_t more = pread(fd, &extra, 1u, (off_t)len);
    return more == 0 ? NULL : ZCL_FRT_WHY_FILE_CHANGED;
}

/* Custody first, then every byte, then the same inode and size again. */
static const char *frt_read_checked(int fd,
                                    const struct zcl_frt_custody *custody,
                                    uint8_t **buf, size_t *size)
{
    struct stat before, after;
    if (fstat(fd, &before) != 0) return ZCL_FRT_WHY_FILE_UNSAFE;
    const char *reason = frt_custody_check(&before, custody);
    if (reason) return reason;
    *size = (size_t)before.st_size;
    *buf = zcl_malloc(*size ? *size : 1u, "frt file");
    if (!*buf) return ZCL_FRT_WHY_NO_MEMORY;
    reason = frt_read_all(fd, *buf, *size);
    if (!reason && (fstat(fd, &after) != 0 || !frt_same(&before, &after)))
        reason = ZCL_FRT_WHY_FILE_CHANGED;
    return reason;
}

bool zcl_frt_read_fd(int fd, const struct zcl_frt_custody *custody,
                     uint8_t **out, size_t *len, const char **why)
{
    if (!out || !len || !custody || fd < 0) {
        frt_why(why, ZCL_FRT_WHY_ARGUMENTS);
        return false;
    }
    *out = NULL;
    *len = 0;
    uint8_t *buf = NULL;
    size_t size = 0;
    const char *reason = frt_read_checked(fd, custody, &buf, &size);
    if (reason) {
        free(buf);
        frt_why(why, reason);
        return false;
    }
    *out = buf;
    *len = size;
    return true;
}

bool zcl_frt_read_file(int dir, const char *name,
                       const struct zcl_frt_custody *custody,
                       uint8_t **out, size_t *len, const char **why)
{
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        frt_why(why, errno == ENOENT ? ZCL_FRT_WHY_FILE_MISSING
                                     : ZCL_FRT_WHY_FILE_UNSAFE);
        return false;
    }
    bool ok = zcl_frt_read_fd(fd, custody, out, len, why);
    (void)close(fd);
    return ok;
}

bool zcl_frt_box_parse(const uint8_t *bytes, size_t len,
                       struct zcl_verify_attest_box_key *out)
{
    memset(out, 0, sizeof(*out));
    if (len == 5u && memcmp(bytes, "none\n", 5u) == 0) {
        out->known = true;
        return true;
    }
    if (len != 65u || bytes[64] != '\n' ||
        !zcl_verify_attest_pubkey_parse(bytes, len, out->pubkey))
        return false;
    out->known = true;
    out->present = true;
    return true;
}

static bool frt_parse_uid(const uint8_t *p, size_t n, uint32_t *out)
{
    uint64_t value = 0;
    if (n == 0 || n > 10u || (n > 1u && p[0] == '0')) return false;
    for (size_t i = 0; i < n; i++) {
        if (!isdigit(p[i])) return false;
        value = value * 10u + (uint64_t)(p[i] - '0');
    }
    if (value > UINT32_MAX) return false;
    *out = (uint32_t)value;
    return true;
}

/* "z23verify.store.v1\nsigner_uid=<decimal>\npublisher_uid=0\n", the same
 * bytes the receiver reads; production also requires signer UID 60092. */
static const char *frt_policy_parse(const uint8_t *p, size_t n,
                                    struct zcl_frt_trust *t)
{
    size_t head = sizeof(FRT_POLICY_HEAD) - 1u;
    size_t tail = sizeof(FRT_POLICY_TAIL) - 1u;
    if (n <= head + tail || memcmp(p, FRT_POLICY_HEAD, head) != 0 ||
        memcmp(p + n - tail, FRT_POLICY_TAIL, tail) != 0 ||
        !frt_parse_uid(p + head, n - head - tail, &t->signer_uid))
        return ZCL_FRT_WHY_POLICY_MALFORMED;
    if (t->signer_uid != ZCL_FRT_SIGNER_UID) return ZCL_FRT_WHY_POLICY_UIDS;
    t->publisher_uid = ZCL_FRT_PUBLISHER_UID;
    t->launcher_uid = ZCL_FRT_LAUNCHER_UID;
    return NULL;
}

static const char *frt_profile_check(const struct zcl_frt_trust *t)
{
    uint8_t hash[32];
    zcl_sha3_256(t->profile, t->profile_len, hash);
    return memcmp(hash, t->pins.profile_args, 32u) == 0
               ? NULL : ZCL_FRT_WHY_PROFILE_MISMATCH;
}

static const char *frt_read_small(int dir, const char *name, uint32_t owner,
                                  uint32_t mode, uint8_t **out, size_t *len)
{
    const struct zcl_frt_custody c = {owner, mode, FRT_SMALL_MAX};
    const char *why = NULL;
    return zcl_frt_read_file(dir, name, &c, out, len, &why) ? NULL : why;
}

static const char *frt_load_profile(int dir, uint32_t owner,
                                    struct zcl_frt_trust *t)
{
    const struct zcl_frt_custody c = {owner, 0444u, FRT_PROFILE_MAX};
    const char *why = NULL;
    if (!zcl_frt_read_file(dir, ZCL_FRT_PROFILE, &c, &t->profile,
                           &t->profile_len, &why))
        return why;
    return frt_profile_check(t);
}

static const char *frt_load_keys(int dir, uint32_t owner,
                                 struct zcl_frt_trust *t)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    const char *why = frt_read_small(dir, ZCL_FRT_BOX_PUB, owner, 0u,
                                     &bytes, &len);
    if (!why && !zcl_frt_box_parse(bytes, len, &t->box))
        why = ZCL_FRT_WHY_PUBKEY_MALFORMED;
    free(bytes);
    bytes = NULL;
    if (!why)
        why = frt_read_small(dir, ZCL_FRT_VERIFIER_PUB, owner, 0u, &bytes,
                             &len);
    if (!why && !zcl_verify_attest_pubkey_parse(bytes, len,
                                                t->verifier_pubkey))
        why = ZCL_FRT_WHY_PUBKEY_MALFORMED;
    free(bytes);
    if (!why && t->box.present &&
        memcmp(t->box.pubkey, t->verifier_pubkey, 32u) == 0)
        why = ZCL_FRT_WHY_VERIFIER_IS_BOX;
    return why;
}

/* The profile and both public keys from one trusted directory; the pins
 * were already loaded through the store reader's root-custody loader. */
static const char *frt_load_dir(int dir, uint32_t owner,
                                struct zcl_frt_trust *t)
{
    const char *why = frt_load_profile(dir, owner, t);
    if (!why) why = frt_load_keys(dir, owner, t);
    return why;
}

static bool frt_finish(struct zcl_frt_trust *t, const char *reason,
                       const char **why)
{
    if (reason) zcl_frt_release(t);
    frt_why(why, reason);
    return reason == NULL;
}

bool zcl_frt_load_production(struct zcl_frt_trust *out, const char **why)
{
    if (!out) return frt_finish(NULL, ZCL_FRT_WHY_ARGUMENTS, why);
    memset(out, 0, sizeof(*out));
    const char *reason = NULL;
    int root = zcl_frt_open_root(&reason);
    int dir = root >= 0 ? zcl_frt_open_path(root, ZCL_FRT_ETC_DIR, 0u,
                                            &reason) : -1;
    uint8_t *policy = NULL;
    size_t policy_len = 0;
    if (dir >= 0)
        reason = frt_read_small(dir, ZCL_FRT_POLICY, 0u, 0444u, &policy,
                                &policy_len);
    if (dir >= 0 && !reason)
        reason = frt_policy_parse(policy, policy_len, out);
    free(policy);
    if (dir >= 0 && !reason &&
        !zcl_verify_store_pins_load(&out->pins, &reason) && !reason)
        reason = ZCL_FRT_WHY_FILE_UNSAFE;
    if (dir >= 0 && !reason) reason = frt_load_dir(dir, 0u, out);
    if (dir >= 0) (void)close(dir);
    if (root >= 0) (void)close(root);
    return frt_finish(out, reason, why);
}

void zcl_frt_release(struct zcl_frt_trust *trust)
{
    if (!trust) return;
    free(trust->profile);
    memset(trust, 0, sizeof(*trust));
}

#ifdef ZCL_TESTING
bool zcl_frt_load_fixture(const struct zcl_frt_fixture *fixture,
                          struct zcl_frt_trust *out, const char **why)
{
    /* Zero first: the refusal path releases `out`, which must not free the
     * caller's uninitialised profile pointer. */
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !fixture || !fixture->etc_dir || fixture->etc_dir[0] != '/')
        return frt_finish(out, ZCL_FRT_WHY_ARGUMENTS, why);
    out->signer_uid = fixture->signer_uid;
    out->publisher_uid = fixture->publisher_uid;
    out->launcher_uid = fixture->launcher_uid;
    const char *reason = NULL;
    int dir = open(fixture->etc_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                         O_CLOEXEC);
    struct stat st;
    if (dir < 0 || fstat(dir, &st) != 0 ||
        !frt_dir_ok(&st, fixture->owner, false))
        reason = ZCL_FRT_WHY_PATH_UNSAFE;
    if (!reason)
        reason = zcl_verify_store_pins_load_fixture(
            fixture->etc_dir, fixture->owner, fixture->owner, &out->pins);
    if (!reason) reason = frt_load_dir(dir, fixture->owner, out);
    if (dir >= 0) (void)close(dir);
    return frt_finish(out, reason, why);
}
#endif

#else
/* The verifier scope is one Linux x86-64 translation unit. */
typedef int zcl_fixed_result_trust_linux_only;
#endif
