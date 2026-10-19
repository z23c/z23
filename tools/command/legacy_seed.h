/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Seed a NEW legacy zclassicd datadir from a synced one (the consensus-parity
 * oracle) without ever overwriting a datadir and without copying a wallet or
 * key file. Two phases keep the oracle's downtime to what changed:
 *
 *   stage   (source may be RUNNING) copy every file of blocks/ and chainstate/
 *           (blk/rev, the LevelDB trees, everything) into <target>.tmp.
 *           Resumable: a file whose size and mtime already match is skipped.
 *   finish  (source STOPPED, lock free) hold the datadir lock, recopy only
 *           files that are new or whose size or mtime changed since stage,
 *           plus LevelDB's MANIFEST-*, CURRENT, LOG and the newest table and
 *           log of each LevelDB directory (always), delete target files the
 *           source no longer has (confined to the target tree), fsync, release
 *           the lock, hash a (path, size, sha3) manifest, write the receipt
 *           (phase_b_ms, phase_b_files, phase_b_bytes) and rename <target>.tmp
 *           to <target> with RENAME_NOREPLACE.
 *
 * Every refusal is a stable code (lseed_refusal_name). The engine reads the
 * file system only through the seams in struct lseed_hooks so tests inject
 * free space, ownership, copy strategy and a mid-copy failure.
 */
#ifndef ZCL_COMMAND_LEGACY_SEED_H
#define ZCL_COMMAND_LEGACY_SEED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LSEED_PATH_MAX 1024
#define LSEED_DEFAULT_WORKERS 4
#define LSEED_MAX_WORKERS 16
#define LSEED_DEFAULT_MAX_GAP 2
#define LSEED_DEFAULT_MARGIN_MIB 1024
#define LSEED_RECEIPT_NAME "seed-receipt.json"
#define LSEED_MARKER_NAME ".seed-source"

enum lseed_refusal {
    LSEED_OK = 0,
    LSEED_BAD_INPUT,
    LSEED_SOURCE_MISSING,
    LSEED_SOURCE_SYMLINK,
    LSEED_TARGET_SYMLINK,
    LSEED_TARGET_EXISTS,
    LSEED_OWNER_MISMATCH,
    LSEED_SOURCE_RUNNING,
    LSEED_SOURCE_LOCKED,
    LSEED_GAP_EXCEEDED,
    LSEED_INSUFFICIENT_SPACE,
    LSEED_SYMLINK_IN_TREE,
    LSEED_SPECIAL_FILE,
    LSEED_TMP_MISMATCH,
    LSEED_PLAN_MISMATCH,
    LSEED_COPY_FAILED,
    LSEED_RECEIPT_FAILED,
    LSEED_SOURCE_LOCK_MISSING,
    LSEED_REFUSAL_COUNT
};

const char *lseed_refusal_name(enum lseed_refusal code);

struct lseed_request {
    char source[LSEED_PATH_MAX];
    char target[LSEED_PATH_MAX];
    int64_t max_gap;       /* blocks the source may trail the z23 tip */
    int64_t source_height; /* -1 unknown */
    int64_t z23_height;    /* -1 unknown */
    uint64_t margin_bytes; /* free space required beyond the source size */
    int workers;
};

void lseed_request_defaults(struct lseed_request *req);

/* Test seams. Zero value = production behaviour. */
struct lseed_hooks {
    int64_t (*free_bytes)(void *ctx, const char *path); /* <0: unknown */
    void *ctx;
    int copy_mode;        /* 0 auto, 1 read/write only, 2 no reflink */
    int fail_after_files; /* >0: fail with EIO after that many file copies */
    bool owner_override;  /* pretend files must be owned by owner_uid */
    uint32_t owner_uid;
};
struct lseed_hooks *lseed_hooks(void);

struct lseed_plan {
    uint64_t files;
    uint64_t bytes;
    uint64_t immutable_files;
    uint64_t excluded_files; /* wallet and key files never copied */
    uint64_t free_bytes;
    int64_t tail_pair; /* highest blk number, -1 none */
    bool source_running;
    bool tmp_present;
    char plan_id[65];
};

/* Stateless plan id: SHA3-256 over the schema tag, source, target, max_gap,
 * both heights, workers, margin and the identity (device and inode) of the
 * source datadir and of the target parent, so a plan made for other inputs or
 * for a replaced directory is refused. Repeat the same inputs at every step. */
void lseed_plan_id(const struct lseed_request *req, char out[65]);

/* All static refusals. require_stopped=false is the stage/plan view (a
 * running source is reported, not refused). */
enum lseed_refusal lseed_preflight(const struct lseed_request *req,
                                   bool require_stopped,
                                   struct lseed_plan *plan, char *why,
                                   size_t why_cap);

struct lseed_result {
    uint64_t files;
    uint64_t bytes;
    uint64_t copied_files;
    uint64_t resumed_files; /* skipped: size and mtime already matched */
    uint64_t cloned_files;  /* FICLONE reflinks */
    uint64_t excluded_files;
    uint64_t stage_ms;
    uint64_t phase_b_ms; /* oracle downtime: lock held to copy fsynced */
    uint64_t phase_b_files; /* files copied while the source was stopped */
    uint64_t phase_b_bytes; /* bytes copied while the source was stopped */
    uint64_t hash_ms;
    char manifest_sha3[65];
    char receipt_path[LSEED_PATH_MAX];
};

enum lseed_refusal lseed_stage(const struct lseed_request *req,
                               struct lseed_result *res, char *why,
                               size_t why_cap);
enum lseed_refusal lseed_finish(const struct lseed_request *req,
                                struct lseed_result *res, char *why,
                                size_t why_cap);

/* Is the datadir in use? pid file (kill 0) OR a flock or fcntl/OFD lock on
 * <datadir>/.lock. Never creates the lock file. */
bool lseed_datadir_in_use(const char *datadir, long *pid_out);

#endif /* ZCL_COMMAND_LEGACY_SEED_H */
