/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin and verify a private downloaded history under a lease. */
#include "services/wallet_history_capability.h"
#include "services/wallet_history_manifest.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#if defined(__linux__)
#include "platform/fd_path.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct history_cancel {
    bool (*check)(void *);
    void *context;
    bool observed, io_error;
};
static bool stopped(struct history_cancel *c)
{
    if (c->check && c->check(c->context)) c->observed = true;
    return c->observed;
}
static struct platform_positioned_file_snapshot stat_snapshot(const struct stat *st)
{
    return (struct platform_positioned_file_snapshot){
        .size = (uint64_t)st->st_size, .volume = (uint64_t)st->st_dev,
        .file_low = (uint64_t)st->st_ino,
        .modified_seconds = (int64_t)st->st_mtim.tv_sec,
        .modified_nanoseconds = (uint32_t)st->st_mtim.tv_nsec,
        .changed_seconds = (int64_t)st->st_ctim.tv_sec,
        .changed_nanoseconds = (uint32_t)st->st_ctim.tv_nsec
    };
}
static bool same(const struct stat *a, const struct stat *b)
{
    struct platform_positioned_file_snapshot left = stat_snapshot(a), right = stat_snapshot(b);
    return a->st_uid == b->st_uid && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        platform_positioned_file_snapshot_equal(&left, &right);
}
static bool block_name(const char *text, unsigned count)
{
    unsigned n; char extra, name[16];
    return sscanf(text, "blk%5u.dat%c", &n, &extra) == 1 && n < count &&
        snprintf(name, sizeof(name), "blk%05u.dat", n) == 12 && !strcmp(name, text);
}
static bool inventory_name(const char *text, bool root, unsigned count)
{
    if (root) return !strcmp(text, "blocks") || !strcmp(text, "block_index.bin");
    return block_name(text, count);
}
static bool inventory(int fd, bool root, unsigned count, struct history_cancel *cancel)
{
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    DIR *dir = copy < 0 ? NULL : fdopendir(copy);
    if (!dir) { if (copy >= 0) close(copy); return false; }
    unsigned seen = 0; bool ok = true; struct dirent *e;
    for (;;) {
        if (stopped(cancel)) { ok = false; break; }
        errno = 0; e = readdir(dir);
        if (!e) { if (errno) { cancel->io_error = true; ok = false; } break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!inventory_name(e->d_name, root, count)) { cancel->io_error = true; ok = false; break; }
        seen++;
    }
    if (closedir(dir)) { cancel->io_error = true; ok = false; }
    return ok && seen == (root ? 2u : count);
}
static bool named_same(int dir, const char *name, const struct stat *expected)
{
    struct stat now;
    return fstatat(dir, name, &now, AT_SYMLINK_NOFOLLOW) == 0 && same(expected, &now);
}
static bool pin_file(int dir, const char *leaf, struct platform_positioned_file *file,
                     struct stat *saved)
{
    char path[96];
    if (!platform_dirfd_child_path(path, sizeof(path), dir, leaf) ||
        !platform_positioned_file_open(file, path)) {
        LOG_WARN("wallet_history", "cannot open retained history file %s", leaf);
        return false;
    }
    int fd = (int)platform_positioned_file_native_fd(file);
    return !fstat(fd, saved) && S_ISREG(saved->st_mode) && saved->st_uid == geteuid() &&
        saved->st_nlink == 1 && (saved->st_mode & 077) == 0 && saved->st_size > 0 &&
        named_same(dir, leaf, saved);
}
#if defined(ZCL_TESTING)
static void (*history_after_manifest_hook)(void);
void wallet_history_capability_test_after_manifest(void (*hook)(void))
{ history_after_manifest_hook = hook; }
#endif
struct history_files {
    struct stat dirs[2], files[254];
    struct platform_positioned_file pins[254];
};
static int file_location(struct wallet_history_capability *cap, unsigned i, unsigned count, char name[16])
{
    if (i == count) { memcpy(name, "block_index.bin", sizeof("block_index.bin")); return (int)cap->root.native; }
    (void)snprintf(name, 16, "blk%05u.dat", i);
    return (int)cap->blocks.native;
}
static bool pin_all(struct wallet_history_capability *cap, unsigned count, struct history_files *f,
                    struct history_cancel *cancel)
{
    int dir = (int)cap->root.native, blocks = (int)cap->blocks.native;
    if (fstat(dir, &f->dirs[0]) || fstat(blocks, &f->dirs[1]) ||
        !inventory(dir, true, count, cancel) || !inventory(blocks, false, count, cancel)) return false;
    for (unsigned i = 0; i <= count; i++) {
        if (stopped(cancel)) return false;
        char name[16]; int location = file_location(cap, i, count, name);
        if (!pin_file(location, name, &f->pins[i], &f->files[i])) return false;
    }
    return true;
}
static bool verify_files(struct wallet_history_capability *cap, unsigned count, struct history_files *f,
                         struct history_cancel *cancel)
{
    for (unsigned i = 0; i <= count; i++) {
        if (stopped(cancel)) return false;
        char name[16]; struct stat after; int location = file_location(cap, i, count, name);
        if (fstat((int)platform_positioned_file_native_fd(&f->pins[i]), &after) ||
            !same(&f->files[i], &after) || !named_same(location, name, &f->files[i])) return false;
    }
    return true;
}
static bool verify_dirs(struct wallet_history_capability *cap, unsigned count, struct history_files *f,
                        struct history_cancel *cancel)
{
    struct stat after; int dir = (int)cap->root.native, blocks = (int)cap->blocks.native;
    return !fstat(dir, &after) && same(&f->dirs[0], &after) &&
        !fstat(blocks, &after) && same(&f->dirs[1], &after) &&
        named_same(dir, "blocks", &f->dirs[1]) && inventory(dir, true, count, cancel) &&
        inventory(blocks, false, count, cancel);
}
static bool verify(struct wallet_history_capability *cap, unsigned count, const uint8_t root[32],
                   struct history_cancel *cancel, uint8_t verified[32])
{
    struct history_files f;
    for (unsigned i = 0; i <= count; i++) platform_positioned_file_init(&f.pins[i]);
    struct file_manifest manifest;
    bool ok = !stopped(cancel) && pin_all(cap, count, &f, cancel);
    if (ok) {
        struct zcl_result result = wallet_history_manifest_build_cancelable(
            &manifest, cap->path, count, cancel->check, cancel->context);
        if (!result.ok && result.code == WALLET_HISTORY_MANIFEST_CANCELLED) cancel->observed = true;
        else if (!result.ok) cancel->io_error = true;
        ok = result.ok && memcmp(manifest.root_hash, root, 32) == 0;
    }
#if defined(ZCL_TESTING)
    if (ok && history_after_manifest_hook) history_after_manifest_hook();
#endif
    if (ok) ok = verify_files(cap, count, &f, cancel) && verify_dirs(cap, count, &f, cancel);
    for (unsigned i = 0; i <= count; i++) platform_positioned_file_close(&f.pins[i]);
    if (ok) memcpy(verified, manifest.root_hash, 32);
    return ok;
}
#endif
void wallet_history_capability_init(struct wallet_history_capability *cap)
{
    if (!cap) return;
    platform_directory_transaction_init(&cap->parent);
    platform_directory_transaction_init(&cap->root);
    platform_directory_transaction_init(&cap->blocks);
    platform_directory_lock_init(&cap->lease);
    cap->path[0] = 0;
    memset(cap->verified_root, 0, sizeof(cap->verified_root));
    cap->verified = false;
}
void wallet_history_capability_release(struct wallet_history_capability *cap)
{
    if (!cap) return;
    cap->path[0] = 0;
    memset(cap->verified_root, 0, sizeof(cap->verified_root));
    cap->verified = false;
    platform_directory_transaction_close(&cap->blocks);
    platform_directory_transaction_close(&cap->root);
    platform_directory_lock_release(&cap->lease);
    platform_directory_transaction_close(&cap->parent);
}
const char *wallet_history_capability_path(const struct wallet_history_capability *cap)
{ return cap && cap->path[0] ? cap->path : NULL; }
struct zcl_result wallet_history_capability_matches(const struct wallet_history_capability *cap, const uint8_t root[32])
{
    if (!cap || !root || !cap->verified || !cap->path[0] || memcmp(cap->verified_root, root, 32))
        return ZCL_ERR(-1, "history capability: verified root does not match");
    return ZCL_OK;
}
struct zcl_result wallet_history_capability_matches_path(const struct wallet_history_capability *cap, const char *path)
{
#if defined(__linux__)
    if (!cap || !cap->verified || !cap->path[0] || !path)
        return ZCL_ERR(-1, "history capability: path check requires a held capability");
    uintptr_t handle;
    if (!platform_private_directory_open_validated_traverse(path, &handle))
        return ZCL_ERR(-1, "history capability: cannot open private history path");
    struct stat held, named;
    bool ok = !fstat((int)cap->root.native, &held) && !fstat((int)handle, &named) &&
        held.st_dev == named.st_dev && held.st_ino == named.st_ino;
    platform_private_directory_close(handle);
    if (!ok) return ZCL_ERR(-1, "history capability: history path does not match retained root");
    return ZCL_OK;
#else
    (void)cap; (void)path; return ZCL_ERR(-1, "history capability: unsupported host");
#endif
}
#if defined(__linux__)
static bool valid_leaf(const char *s)
{ return s && s[0] && !strchr(s, '/') && strcmp(s, ".") && strcmp(s, ".."); }
static bool descriptors_distinct(const struct platform_directory_transaction *parent,
    const struct platform_directory_transaction *root, const struct platform_directory_lock *lease)
{
    return parent->native != UINTPTR_MAX && root->native != UINTPTR_MAX && lease->native != UINTPTR_MAX &&
        parent->native != root->native && parent->native != lease->native && root->native != lease->native;
}
static bool inputs_valid(struct wallet_history_capability *cap,
    struct platform_directory_transaction *parent, struct platform_directory_transaction *retained_root,
    struct platform_directory_lock *lease, unsigned count, const uint8_t root[32])
{
    if (!cap || !parent || !retained_root || parent == retained_root || !lease || !root || !count || count > 253) return false;
    if (!descriptors_distinct(parent, retained_root, lease)) return false;
    return cap->parent.native == UINTPTR_MAX && cap->root.native == UINTPTR_MAX &&
        cap->blocks.native == UINTPTR_MAX && cap->lease.native == UINTPTR_MAX;
}
static bool lock_verified(struct wallet_history_capability *cap, const char *leaf, struct stat *st)
{
    return !fstat((int)cap->lease.native, st) && S_ISREG(st->st_mode) &&
        st->st_uid == geteuid() && st->st_nlink == 1 && !(st->st_mode & 077) &&
        named_same((int)cap->parent.native, leaf, st);
}
static bool root_verified(struct wallet_history_capability *cap, const char *leaf, struct stat *st)
{
    return !fstat((int)cap->root.native, st) && S_ISDIR(st->st_mode) &&
        st->st_uid == geteuid() && !(st->st_mode & 077) &&
        named_same((int)cap->parent.native, leaf, st);
}
static bool verify_capability(struct wallet_history_capability *cap, const char *leaf,
                              const char *lock, unsigned count, const uint8_t root[32], struct history_cancel *cancel)
{
    struct stat lock_stat, root_stat; uint8_t verified[32];
    if (stopped(cancel) || !lock_verified(cap, lock, &lock_stat) || !root_verified(cap, leaf, &root_stat) ||
        platform_directory_transaction_open_child(&cap->root, "blocks", false, &cap->blocks) != PLATFORM_DIRECTORY_OK)
        return false;
    bool ok = platform_fd_path(cap->path, sizeof(cap->path), (int)cap->root.native, NULL) &&
        verify(cap, count, root, cancel, verified) &&
        named_same((int)cap->parent.native, leaf, &root_stat) &&
        named_same((int)cap->parent.native, lock, &lock_stat);
    if (ok) { memcpy(cap->verified_root, verified, sizeof(verified)); cap->verified = true; }
    return ok;
}
#endif
struct zcl_result wallet_history_capability_acquire_cancelable(struct wallet_history_capability *cap,
    struct platform_directory_transaction *parent, struct platform_directory_transaction *retained_root,
    struct platform_directory_lock *lease, const char *leaf, const char *lock, unsigned count, const uint8_t root[32],
    bool (*cancelled)(void *), void *context)
{
#if defined(__linux__)
    if (!valid_leaf(leaf) || !valid_leaf(lock) || !inputs_valid(cap, parent, retained_root, lease, count, root))
        return ZCL_ERR(-1, "history capability: invalid input or already acquired");
    cap->parent = *parent; platform_directory_transaction_init(parent);
    cap->root = *retained_root; platform_directory_transaction_init(retained_root);
    cap->lease = *lease; platform_directory_lock_init(lease);
    struct history_cancel cancel = { .check = cancelled, .context = context };
    if (verify_capability(cap, leaf, lock, count, root, &cancel)) return ZCL_OK;
    wallet_history_capability_release(cap);
    if (cancel.observed && !cancel.io_error) return ZCL_ERR(WALLET_HISTORY_CAPABILITY_CANCELLED, "history capability: cancelled");
    return ZCL_ERR(-1, "history capability: lease, inventory, identity or manifest refused");
#else
    (void)cap; (void)parent; (void)retained_root; (void)lease; (void)leaf; (void)lock; (void)count; (void)root; (void)cancelled; (void)context;
    return ZCL_ERR(-1, "history capability: unsupported host");
#endif
}

struct zcl_result wallet_history_capability_acquire(struct wallet_history_capability *cap,
    struct platform_directory_transaction *parent, struct platform_directory_transaction *retained_root,
    struct platform_directory_lock *lease, const char *leaf, const char *lock, unsigned count, const uint8_t root[32])
{
    return wallet_history_capability_acquire_cancelable(cap, parent, retained_root, lease, leaf, lock, count,
                                                         root, NULL, NULL);
}
