/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: a retained, owner-verified directory handle (opened O_NOFOLLOW,
 * checked to be owned by the current user with no group/other bits) used for
 * openat-relative child create/open/read/write/replace/unlink/lock/list, so
 * every operation binds to the checked directory rather than a re-resolved
 * path, and every mutating call fsyncs the directory entry for crash
 * durability. POSIX and Windows (NtCreateFile) share this contract. */
#ifndef ZCL_PLATFORM_DIRECTORY_TRANSACTION_H
#define ZCL_PLATFORM_DIRECTORY_TRANSACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_directory_transaction { uintptr_t native; };
#define PLATFORM_DIRECTORY_CHILD_LEAF_MAX 255u
struct platform_directory_child {
    uintptr_t native;
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
};
struct platform_directory_child_info {
    uint64_t size, volume, file_low, file_high;
    uint64_t link_count;
    int64_t modified_seconds, changed_seconds;
    uint32_t modified_nanoseconds, changed_nanoseconds;
    bool current_user_only;
};
struct platform_directory_names { char **items; size_t count; };
enum platform_directory_result {
    PLATFORM_DIRECTORY_OK = 0,
    PLATFORM_DIRECTORY_MISSING,
    PLATFORM_DIRECTORY_EXISTS,
    PLATFORM_DIRECTORY_REFUSED,
    PLATFORM_DIRECTORY_IO,
    PLATFORM_DIRECTORY_INVALID,
    /* The namespace move completed, but the post-move identity or directory
     * durability proof failed. The caller must treat both the source and
     * destination names as observational only and must not clean either one
     * up by name until it re-establishes retained identity authority. */
    PLATFORM_DIRECTORY_OUTCOME_UNKNOWN
};
enum platform_directory_lock_mode {
    PLATFORM_DIRECTORY_LOCK_SHARED = 0,
    PLATFORM_DIRECTORY_LOCK_EXCLUSIVE
};
struct platform_directory_lock { uintptr_t native; };

void platform_directory_transaction_init(struct platform_directory_transaction *d);
bool platform_directory_transaction_open(struct platform_directory_transaction *d,
                                         const char *private_path);
void platform_directory_transaction_close(struct platform_directory_transaction *d);
bool platform_directory_transaction_flush(struct platform_directory_transaction *d);
enum platform_directory_result platform_directory_transaction_open_child(
    struct platform_directory_transaction *parent, const char *leaf,
    bool create, struct platform_directory_transaction *child);
/* Bootstrap one private child beneath an existing canonical owner-controlled
 * parent (POSIX: current uid, no group/other write bits; 0755 is allowed).
 * Never chmod the parent or an existing child. create=false does no writes
 * and reports MISSING only after validating the parent. create=true flushes
 * the parent before success; any failure may follow creation, so the caller
 * must report possible mutation. child must be empty on entry and is empty
 * on failure; only a validated private child is returned. No parent capability
 * escapes. Reject noncanonical aliases rather than silently resolving them.
 * Earlier ancestor replacement is not prevented by this pathname API.
 * Windows refuses until equivalent parent ACL policy is qualified. */
enum platform_directory_result platform_directory_transaction_bootstrap_child(
    const char *canonical_parent, const char *leaf, bool create,
    struct platform_directory_transaction *child);

void platform_directory_child_init(struct platform_directory_child *f);
bool platform_directory_child_open(struct platform_directory_transaction *d,
                                   const char *leaf,
                                   struct platform_directory_child *f);
bool platform_directory_child_create(struct platform_directory_transaction *d,
                                     const char *leaf,
                                     struct platform_directory_child *f);
enum platform_directory_result platform_directory_child_open_result(
    struct platform_directory_transaction *d, const char *leaf, bool create,
    bool open_existing, struct platform_directory_child *f, bool *created);
void platform_directory_child_close(struct platform_directory_child *f);
bool platform_directory_child_info(struct platform_directory_child *f,
                                   struct platform_directory_child_info *out);
int64_t platform_directory_child_read(struct platform_directory_child *f,
                                      void *data, size_t size, uint64_t offset);
bool platform_directory_child_write(struct platform_directory_child *f,
                                    const void *data, size_t size,
                                    uint64_t offset);
bool platform_directory_child_truncate(struct platform_directory_child *f,
                                       uint64_t size);
bool platform_directory_child_flush(struct platform_directory_child *f);
bool platform_directory_child_read_exact(struct platform_directory_child *f,
                                         void *data, size_t size,
                                         uint64_t offset);
bool platform_directory_child_write_exact(struct platform_directory_child *f,
                                          const void *data, size_t size,
                                          uint64_t offset);
bool platform_directory_child_replace(struct platform_directory_transaction *d,
                                      struct platform_directory_child *staged,
                                      const char *destination, bool no_clobber);
/* Move `source` from its retained source directory into a retained destination
 * directory on the same volume. Both leaf names are validated, the source
 * name is re-opened relative to source_dir and required to identify the exact
 * retained child, the destination is re-opened and identity-checked after the
 * atomic move, and both directory capabilities are flushed. No pathname is
 * reconstructed or re-resolved.
 *
 * OUTCOME_UNKNOWN means the namespace operation succeeded but the subsequent
 * identity/durability proof did not. In that case source->leaf names the
 * requested destination, but callers must not infer which directory entry is
 * durable or unlink either spelling by name. */
enum platform_directory_result platform_directory_child_move_between(
    struct platform_directory_transaction *source_dir,
    struct platform_directory_child *source,
    struct platform_directory_transaction *destination_dir,
    const char *destination_leaf, bool no_clobber);
bool platform_directory_child_unlink(struct platform_directory_transaction *d,
                                     const char *leaf, bool missing_ok);
enum platform_directory_result platform_directory_child_unlink_result(
    struct platform_directory_transaction *d, const char *leaf);
bool platform_directory_transaction_list_regular(
    struct platform_directory_transaction *d, struct platform_directory_names *out);
void platform_directory_names_free(struct platform_directory_names *names);

void platform_directory_lock_init(struct platform_directory_lock *lock);
enum platform_directory_result platform_directory_lock_acquire(
    struct platform_directory_transaction *d, const char *leaf, bool create,
    enum platform_directory_lock_mode mode, struct platform_directory_lock *lock);
void platform_directory_lock_release(struct platform_directory_lock *lock);

#ifdef ZCL_TESTING
/* Return and reset this thread's calls to the native listing sort. */
size_t platform_directory_names_test_take_sort_calls(void);
/* One-shot seam proving that a successful rename followed by an unprovable
 * directory flush reports OUTCOME_UNKNOWN rather than ordinary failure. */
void platform_directory_child_move_test_fail_durability_once(void);
#endif
#if defined(_WIN32)
/* Narrow namespace capability: retained named no-reparse directory with
 * DELETE and enumeration rights. Ordinary open_child retains traverse only. */
enum platform_directory_result platform_directory_transaction_open_child_namespace(
    struct platform_directory_transaction *parent, const char *leaf,
    bool create, struct platform_directory_transaction *child);
bool platform_directory_transaction_parent(const char *path,
    struct platform_directory_transaction *parent,
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u]);
int platform_directory_result_errno(enum platform_directory_result result);
int platform_directory_child_duplicate_fd(uintptr_t native, int flags);
int platform_directory_transaction_read_fd(const char *path, bool private_owner_only);
bool platform_directory_transaction_write_atomic(const char *path, const void *data, size_t size);
bool platform_directory_transaction_remove_tree(const char *path);
/* Remove only beneath this exact namespace-capable private directory, then
 * remove that directory by retained handle. Refuse every reparse point and
 * bound recursion/enumeration. The caller retains and closes its capability. */
bool platform_directory_transaction_remove_retained(
    struct platform_directory_transaction *directory, unsigned depth);
/* Move the exact namespace-capable source directory to an absent leaf. Both
 * parent capabilities must be ordinary traverse-only transactions. Windows
 * may refuse a DELETE-bearing destination capability because its internal
 * relative rename open has incompatible sharing. OUTCOME_UNKNOWN means the
 * move completed but post-move identity/durability proof failed: preserve all
 * involved names and reconcile by a fresh exact observation before cleanup. */
enum platform_directory_result platform_directory_transaction_move_directory(
    struct platform_directory_transaction *source_parent, const char *source_leaf,
    struct platform_directory_transaction *source,
    struct platform_directory_transaction *destination_parent, const char *destination_leaf);
bool platform_directory_transaction_replace_path(const char *staging, const char *destination);
#endif
#if defined(_WIN32) && defined(ZCL_TESTING)
void platform_directory_transaction_move_directory_test_fail_durability_once(void);
#endif
#endif
