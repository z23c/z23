/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif
#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "services/wallet_history_capability.h"
#include "crypto/sha3.h"
#include <stdio.h>
#if defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct history_fixture { char parent[PATH_MAX], root[PATH_MAX], blocks[PATH_MAX], index[PATH_MAX], block[PATH_MAX], lock[PATH_MAX], other[PATH_MAX]; };
static bool path(char *out, const char *base, const char *leaf)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", base, leaf);
    return n >= 0 && n < PATH_MAX;
}
static bool put(const char *name, const char *bytes)
{
    int fd = open(name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t size = strlen(bytes);
    bool ok = write(fd, bytes, size) == (ssize_t)size;
    return close(fd) == 0 && ok;
}
static bool fixture(struct history_fixture *f)
{
    if (!test_mkdtemp(f->parent, sizeof(f->parent), "history_cap")) return false;
    return path(f->root, f->parent, "root") && path(f->blocks, f->root, "blocks") &&
        path(f->index, f->root, "block_index.bin") && path(f->block, f->blocks, "blk00000.dat") &&
        path(f->lock, f->parent, "lock") && path(f->other, f->parent, "other") &&
        !mkdir(f->root, 0700) && !mkdir(f->blocks, 0700) &&
        put(f->index, "index") && put(f->block, "block") && put(f->lock, "lock");
}
static int remove_entry(const char *name, const struct stat *st, int type, struct FTW *info)
{ (void)st; (void)type; (void)info; return remove(name); }
static void cleanup(struct history_fixture *f)
{ if (f->parent[0]) (void)nftw(f->parent, remove_entry, 16, FTW_DEPTH | FTW_PHYS); }
static void expected(uint8_t out[32])
{
    uint8_t chunks[64]; struct sha3_256_ctx h;
    sha3_256_init(&h); sha3_256_write(&h, (const uint8_t *)"block", 5); sha3_256_finalize(&h, chunks);
    sha3_256_init(&h); sha3_256_write(&h, (const uint8_t *)"index", 5); sha3_256_finalize(&h, chunks + 32);
    sha3_256_init(&h); sha3_256_write(&h, chunks, sizeof(chunks)); sha3_256_finalize(&h, out);
}
static int fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); if (!d) return -1;
    int n = 0; while (readdir(d)) n++;
    if (closedir(d)) return -1;
    return n;
}
static bool open_lease(struct history_fixture *f, struct platform_directory_transaction *p,
                       struct platform_directory_lock *l)
{
    platform_directory_transaction_init(p); platform_directory_lock_init(l);
    if (!platform_directory_transaction_open(p, f->parent)) return false;
    if (platform_directory_lock_acquire(p, "lock", false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, l) == PLATFORM_DIRECTORY_OK)
        return true;
    platform_directory_transaction_close(p); return false;
}
static bool free_lease(struct history_fixture *f)
{
    struct platform_directory_transaction p; struct platform_directory_lock l;
    if (!open_lease(f, &p, &l)) return false;
    platform_directory_lock_release(&l); platform_directory_transaction_close(&p); return true;
}
static bool contended(struct history_fixture *f)
{
    struct platform_directory_transaction p; struct platform_directory_lock l;
    if (!open_lease(f, &p, &l)) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close((int)l.native); close((int)p.native);
        platform_directory_transaction_init(&p); platform_directory_lock_init(&l);
        if (!platform_directory_transaction_open(&p, f->parent)) _exit(2);
        enum platform_directory_result result = platform_directory_lock_acquire(
            &p, "lock", false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &l);
        platform_directory_lock_release(&l); platform_directory_transaction_close(&p);
        _exit(result == PLATFORM_DIRECTORY_REFUSED ? 0 : 1);
    }
    int status = 0; bool ok = pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status);
    platform_directory_lock_release(&l); platform_directory_transaction_close(&p);
    return ok && free_lease(f);
}
static bool invalid_preserves(struct history_fixture *f)
{
    struct platform_directory_transaction p, root; struct platform_directory_lock l;
    struct wallet_history_capability cap; wallet_history_capability_init(&cap);
    if (!open_lease(f, &p, &l)) return false;
    platform_directory_transaction_init(&root);
    bool opened = platform_directory_transaction_open_child(&p, "root", false, &root) == PLATFORM_DIRECTORY_OK;
    uint8_t hash[32]; expected(hash);
    bool refused = opened && !wallet_history_capability_acquire(&cap, &p, &root, &l, "root", "lock", 0, hash).ok;
    bool preserved = p.native != UINTPTR_MAX && root.native != UINTPTR_MAX && l.native != UINTPTR_MAX;
    wallet_history_capability_release(&cap); platform_directory_transaction_close(&root);
    platform_directory_lock_release(&l); platform_directory_transaction_close(&p);
    return refused && preserved;
}
static bool alias_refused(struct platform_directory_transaction p,
                          struct platform_directory_transaction root,
                          struct platform_directory_lock lease, unsigned pair)
{
    struct wallet_history_capability cap; wallet_history_capability_init(&cap);
    if (pair == 0) root.native = p.native;
    else if (pair == 1) lease.native = p.native;
    else lease.native = root.native;
    uintptr_t parent_fd = p.native, root_fd = root.native, lease_fd = lease.native;
    uint8_t hash[32]; expected(hash);
    bool refused = !wallet_history_capability_acquire(&cap, &p, &root, &lease, "root", "lock", 1, hash).ok;
    bool preserved = p.native == parent_fd && root.native == root_fd && lease.native == lease_fd;
    wallet_history_capability_release(&cap);
    return refused && preserved;
}
static bool aliases_preserved(struct history_fixture *f)
{
    struct platform_directory_transaction p, root; struct platform_directory_lock l;
    if (!open_lease(f, &p, &l)) return false;
    platform_directory_transaction_init(&root);
    bool ok = platform_directory_transaction_open_child(&p, "root", false, &root) == PLATFORM_DIRECTORY_OK;
    for (unsigned i = 0; ok && i < 3; i++) ok = alias_refused(p, root, l, i);
    platform_directory_transaction_close(&root); platform_directory_lock_release(&l);
    platform_directory_transaction_close(&p); return ok;
}
static struct history_fixture *replace_fixture;
static void replace_root(void)
{
    if (rename(replace_fixture->root, replace_fixture->other) || mkdir(replace_fixture->root, 0700))
        replace_fixture = NULL;
}
static bool alter_first(struct history_fixture *f, unsigned which)
{
    char temp[PATH_MAX];
    switch (which) {
    case 0: return true;
    case 1: return path(temp, f->root, "extra") && put(temp, "x");
    case 2: return path(temp, f->blocks, "notes") && put(temp, "x");
    case 3: return !unlink(f->block);
    case 4: return path(temp, f->blocks, "blk00001.dat") && !rename(f->block, temp);
    case 5: return !unlink(f->block) && !symlink("../block_index.bin", f->block);
    default: return false;
    }
}
static bool alter(struct history_fixture *f, unsigned which)
{
    if (which <= 5) return alter_first(f, which);
    switch (which) {
    case 6: return !unlink(f->block) && !mkfifo(f->block, 0600);
    case 7: return !link(f->block, f->other);
    case 8: return !chmod(f->block, 0644);
    case 9: return true;
    case 10: return true;
    default: return false;
    }
}
struct case_snapshot { struct stat index, block; bool index_exists, block_exists; };
static struct case_snapshot snapshot(struct history_fixture *f)
{
    struct case_snapshot s = {0};
    s.index_exists = lstat(f->index, &s.index) == 0;
    s.block_exists = lstat(f->block, &s.block) == 0;
    return s;
}
static bool same_entry(bool exists, bool now_exists, const struct stat *before, const struct stat *after)
{
    if (exists != now_exists) return false;
    return !exists || (before->st_ino == after->st_ino && before->st_dev == after->st_dev);
}
static bool preserved_files(struct history_fixture *f, const struct case_snapshot *before)
{
    struct case_snapshot after = snapshot(f);
    return same_entry(before->index_exists, after.index_exists, &before->index, &after.index) &&
        same_entry(before->block_exists, after.block_exists, &before->block, &after.block);
}
static bool valid_path(struct wallet_history_capability *cap, struct history_fixture *f)
{
    char found[PATH_MAX]; struct stat a, b;
    const char *root = wallet_history_capability_path(cap);
    return root && path(found, root, "block_index.bin") && !stat(found, &a) &&
        !stat(f->index, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static bool check_matching_paths(struct wallet_history_capability *cap, struct history_fixture *f)
{
    char blocks[PATH_MAX], index[PATH_MAX], block[PATH_MAX], linkpath[PATH_MAX];
    if (!path(blocks, f->other, "blocks") || !path(index, f->other, "block_index.bin") ||
        !path(block, blocks, "blk00000.dat") || !path(linkpath, f->parent, "root-link")) return false;
    if (mkdir(f->other, 0700) || mkdir(blocks, 0700) || !put(index, "index") || !put(block, "block") ||
        symlink(f->root, linkpath)) return false;
    return wallet_history_capability_matches_path(cap, f->root) &&
        !wallet_history_capability_matches_path(cap, f->other) &&
        !wallet_history_capability_matches_path(cap, linkpath) &&
        !wallet_history_capability_matches_path(cap, NULL);
}
static bool binding_result(struct wallet_history_capability *cap, const uint8_t hash[32],
                           const struct zcl_result *result, bool consumed, unsigned which)
{
    uint8_t other[32]; memcpy(other, hash, sizeof(other)); other[0] ^= 1;
    if (which == 0) return result->ok && consumed && wallet_history_capability_matches(cap, hash) &&
        !wallet_history_capability_matches(cap, other);
    return !result->ok && consumed && !wallet_history_capability_path(cap) &&
        !wallet_history_capability_matches(cap, hash);
}
static bool empty_binding(struct wallet_history_capability *cap, const uint8_t hash[32], const char *path)
{
    return !wallet_history_capability_matches(cap, hash) && !wallet_history_capability_matches_path(cap, path);
}
static bool execute_case(struct history_fixture *f, unsigned which)
{
    struct wallet_history_capability cap; struct platform_directory_transaction p, retained_root;
    struct platform_directory_lock l; uint8_t hash[32]; expected(hash);
    wallet_history_capability_init(&cap);
    if (!empty_binding(&cap, hash, f->root)) return false;
    if (!open_lease(f, &p, &l)) return false;
    platform_directory_transaction_init(&retained_root);
    if (platform_directory_transaction_open_child(&p, "root", false, &retained_root) != PLATFORM_DIRECTORY_OK) {
        platform_directory_lock_release(&l); platform_directory_transaction_close(&p); return false;
    }
    if (which == 9) hash[0] ^= 1;
    if (which == 10) { replace_fixture = f; wallet_history_capability_test_after_manifest(replace_root); }
    struct zcl_result result = wallet_history_capability_acquire(&cap, &p, &retained_root, &l, "root", "lock", 1, hash);
    wallet_history_capability_test_after_manifest(NULL);
    bool consumed = p.native == UINTPTR_MAX && retained_root.native == UINTPTR_MAX && l.native == UINTPTR_MAX;
    bool ok = binding_result(&cap, hash, &result, consumed, which);
    if (which == 0) ok = ok && valid_path(&cap, f) && check_matching_paths(&cap, f);
    if (which == 10 && !replace_fixture) ok = false;
    wallet_history_capability_release(&cap); wallet_history_capability_release(&cap);
    return ok && empty_binding(&cap, hash, f->root);
}
static bool run_case(unsigned which)
{
    struct history_fixture f = {0}; int before = fd_count(); bool ok = false;
    if (before < 0 || !fixture(&f) || !alter(&f, which)) goto done;
    struct case_snapshot prior = snapshot(&f);
    ok = execute_case(&f, which);
    if (which != 10) ok = ok && preserved_files(&f, &prior);
    struct stat present;
    ok = ok && !lstat(which == 10 ? f.other : f.root, &present) && free_lease(&f) && fd_count() == before;
done:
    cleanup(&f); return ok;
}
struct cancel_counter { unsigned calls, stop_at; };
static bool cancel_once(void *arg)
{
    struct cancel_counter *counter = arg;
    counter->calls++;
    return counter->stop_at && counter->calls == counter->stop_at;
}
static bool cancel_result_valid(unsigned stop_at, const struct zcl_result *result,
                                struct wallet_history_capability *cap)
{
    if (stop_at) return !result->ok && result->code == WALLET_HISTORY_CAPABILITY_CANCELLED && !wallet_history_capability_path(cap);
    return result->ok && wallet_history_capability_path(cap);
}
static bool cancel_case(unsigned stop_at, unsigned *calls)
{
    struct history_fixture f = {0}; struct wallet_history_capability cap;
    struct platform_directory_transaction p, root; struct platform_directory_lock l;
    struct cancel_counter counter = { .stop_at = stop_at }; uint8_t hash[32];
    int before = fd_count(); bool ok = false; expected(hash); wallet_history_capability_init(&cap);
    if (before < 0 || !fixture(&f) || !open_lease(&f, &p, &l)) goto done;
    platform_directory_transaction_init(&root);
    if (platform_directory_transaction_open_child(&p, "root", false, &root) != PLATFORM_DIRECTORY_OK) {
        platform_directory_lock_release(&l); platform_directory_transaction_close(&p); goto done;
    }
    struct zcl_result result = wallet_history_capability_acquire_cancelable(
        &cap, &p, &root, &l, "root", "lock", 1, hash, cancel_once, &counter);
    bool consumed = p.native == UINTPTR_MAX && root.native == UINTPTR_MAX && l.native == UINTPTR_MAX;
    ok = cancel_result_valid(stop_at, &result, &cap);
    wallet_history_capability_release(&cap);
    struct stat st;
    ok = ok && consumed && !lstat(f.block, &st) && !lstat(f.index, &st) && free_lease(&f) && fd_count() == before;
    *calls = counter.calls;
done:
    cleanup(&f); return ok;
}
static bool cancel_cases(void)
{
    unsigned calls = 0;
    if (!cancel_case(0, &calls) || !calls) return false;
    for (unsigned i = 1; i <= calls; i++) {
        unsigned observed = 0;
        if (!cancel_case(i, &observed) || observed < i) return false;
    }
    return true;
}

int test_wallet_history_capability(void)
{
    int failures = 0;
    for (unsigned i = 0; i <= 10; i++) if (!run_case(i)) { printf("history capability case %u failed\n", i); failures++; }
    if (!cancel_cases()) { printf("history capability cancellation failed\n"); failures++; }
    struct history_fixture f = {0};
    if (!fixture(&f) || !contended(&f) || !invalid_preserves(&f) || !aliases_preserved(&f)) { printf("history capability lock contention failed\n"); failures++; }
    cleanup(&f);
    return failures;
}
#else
int test_wallet_history_capability(void)
{
    struct wallet_history_capability cap; wallet_history_capability_init(&cap);
    struct zcl_result r = wallet_history_capability_acquire(&cap, NULL, NULL, NULL, NULL, NULL, 0, NULL);
    wallet_history_capability_release(&cap);
    if (r.ok) { printf("history capability unsupported host unexpectedly succeeded\n"); return 1; }
    return 0;
}
#endif
