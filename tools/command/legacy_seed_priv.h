/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal seams between the legacy seed walker, copier and driver. */
#ifndef ZCL_COMMAND_LEGACY_SEED_PRIV_H
#define ZCL_COMMAND_LEGACY_SEED_PRIV_H

#include "command/legacy_seed.h"

#include <sys/types.h>

struct lseed_ent {
    char rel[LSEED_PATH_MAX];
    uint64_t size;
    int64_t mtime_s;
    long mtime_ns;
    mode_t mode;
    bool dir;
    bool tail;  /* blk/rev of the highest-numbered pair, or a non-pair file */
    bool force; /* LevelDB metadata or newest table/log: always recopied in phase B */
    char sha3[65];
};

struct lseed_tree {
    struct lseed_ent *e;
    size_t n;
    size_t cap;
    uint64_t excluded;
    uint64_t bytes;
    int64_t tail_pair;
};

struct lseed_counts {
    uint64_t copied;
    uint64_t resumed;
    uint64_t cloned;
    uint64_t bytes;
};

/* Names that are wallets or keys and are never copied. */
bool lseed_is_secret(const char *name);

/* Enumerate blocks/ and chainstate/ under rootfd with O_NOFOLLOW. Sorted by
 * path; marks the tail pair. Refuses symlinks and special files. */
enum lseed_refusal lseed_walk(int rootfd, struct lseed_tree *tree, char *why,
                              size_t why_cap);
void lseed_tree_free(struct lseed_tree *tree);

/* openat that cannot traverse or end in a symlink (openat2 when available). */
int lseed_open_beneath(int rootfd, const char *rel, int flags, mode_t mode);

typedef bool (*lseed_want_fn)(const struct lseed_ent *ent);
bool lseed_want_all(const struct lseed_ent *ent); /* every file, both phases */

/* Create every directory entry under dstroot, then copy the wanted files with
 * `workers` processes. Files already matching size and mtime are skipped,
 * except forced ones when recopy_forced is set (phase B). */
enum lseed_refusal lseed_copy_tree(int srcroot, int dstroot,
                                   struct lseed_tree *tree, lseed_want_fn want,
                                   bool recopy_forced, int workers,
                                   struct lseed_counts *counts,
                                   char *why, size_t why_cap);

/* fsync every directory of the tree and the root. */
bool lseed_sync_dirs(int dstroot, const struct lseed_tree *tree);

/* Remove files under dstroot that the source no longer has. */
bool lseed_prune_extra(int dstroot, const struct lseed_tree *tree);

/* SHA3-256 each file of the tree under dstroot (parallel). */
bool lseed_hash_tree(int dstroot, struct lseed_tree *tree, int workers);

#endif /* ZCL_COMMAND_LEGACY_SEED_PRIV_H */
