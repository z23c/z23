/* Internal contracts shared by the contained consensus-state exporter. */

#ifndef ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_INTERNAL_H
#define ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_INTERNAL_H

#include "config/consensus_state_snapshot_export.h"
#include "platform/fd_path.h"
#include "platform/rename_compat.h"
#include "storage/consensus_state_bundle_codec.h"

#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONSENSUS_EXPORT_NAME_MAX 256

/* Darwin staging is a NAMED sibling of the final output inside the same pinned
 * 0700 datadir directory, created O_CREAT|O_EXCL and published by an atomic
 * no-replace rename. The dot prefix + unique suffix keep it out of every
 * listing walk the publisher itself performs, and the ".zcl-consensus-candidate-"
 * prefix is the leak detector the candidate test group counts (a stage file
 * left behind after publish or refusal is a bug). Linux stages anonymously
 * (O_TMPFILE) and never uses this name. */
#define CONSENSUS_STATE_STAGE_PREFIX ".zcl-consensus-candidate-"

struct consensus_export_output_binding {
    int dirfd;
    int temp_fd;
    char final_name[CONSENSUS_EXPORT_NAME_MAX];
    /* Darwin only: the staging name this binding owns (empty on Linux, where
     * the staging inode is anonymous for its whole life). */
    char stage_name[CONSENSUS_EXPORT_NAME_MAX + 48];
    bool stage_created;
    bool published;
    dev_t temp_dev;
    ino_t temp_ino;
    sqlite3_vfs vfs;
    sqlite3_vfs *base_vfs;
    char vfs_name[64];
    bool vfs_registered;
    bool abandon_on_close;
};

/* Private SQLite file object that performs all database I/O through the
 * retained anonymous staging inode. */
int consensus_export_fd_file_size(void);
int consensus_export_fd_file_open(sqlite3_file *file, int retained_fd,
                                  int flags, int *out_flags);
/* Register the per-binding descriptor VFS (consensus_state_snapshot_export_
 * vfs.c) and prove a handle is fully retired. */
bool consensus_export_output_vfs_register(
    struct consensus_export_output_binding *output);
bool consensus_export_output_sqlite_close_strict(
    struct consensus_export_output_binding *output, sqlite3 **db);
/* Replace the last owned writable staging descriptor with an exact O_RDONLY
 * description of the same anonymous inode.  Call only after every SQLite
 * writer is strictly closed. */
bool consensus_export_seal_readonly(
    struct consensus_export_output_binding *output, struct stat *sealed);
bool consensus_export_descriptor_digest(int fd, uint8_t out[32]);

bool consensus_export_fail(struct consensus_state_export_result *result,
                           enum consensus_state_export_status status,
                           const char *fmt, ...);

/* Observability-only: a monotonic millisecond clock plus a "[export] <msg>"
 * stderr+LOG_INFO emitter, shared by the prove (consensus_state_snapshot_
 * export_proof.c) and write (consensus_state_snapshot_export_write.c) passes
 * so the long full-history -export-consensus-bundle run is never silent
 * between named phases. Never used in any gate decision. */
int64_t consensus_export_clock_ms(void);
void consensus_export_progress_emit(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

bool consensus_export_prove_source(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_source_receipt *receipt,
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    struct consensus_state_export_result *result);

/* Reducer-stage row-scan proof descriptor + the fixed k_stages fixture table
 * (validate_headers..tip_finalize) and the two O(H)-row scan proofs
 * (consensus_export_prove_header_chain / consensus_export_prove_stage_rows).
 * Defined in consensus_state_snapshot_export_proof_rows.c — split out of
 * consensus_state_snapshot_export_proof.c along the file-size ceiling seam
 * (E1); consensus_export_prove_source there orchestrates these two scans
 * plus its own fast, non-scanning checks. */
struct export_stage_proof {
    const char *name;
    const char *table;
    bool served_tip_cursor;
    const char *hash_column;
    bool profile_bound;
    bool source_epoch_bound;
};
#define CONSENSUS_EXPORT_STAGE_COUNT (CONSENSUS_STATE_BUNDLE_PROOF_COUNT - 1)
extern const struct export_stage_proof k_stages[CONSENSUS_EXPORT_STAGE_COUNT];

bool consensus_export_prove_header_chain(sqlite3 *db, int32_t height,
                                         const uint8_t expected_hash[32],
                                         uint8_t source_digest[32]);
bool consensus_export_prove_stage_rows(
    sqlite3 *db, const struct export_stage_proof *stage, int32_t height,
    uint64_t cursor, uint8_t validation_profile,
    const uint8_t source_epoch_digest[32],
    struct consensus_state_bundle_proof_summary *summary);

bool consensus_export_write_bundle(
    sqlite3 *source, sqlite3 *destination,
    struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt,
    const struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    struct consensus_state_export_result *result);

bool consensus_export_open_temp(struct consensus_export_output_binding *output,
                                sqlite3 **destination,
                                struct consensus_state_export_result *result);

/* Remove this binding's Darwin staging name, but only if it still resolves to
 * the exact staged inode (a swapped or recreated name is never deleted).
 * Linux calls it nothing: its staging inode dies with the descriptor. */
void consensus_export_staging_discard(
    struct consensus_export_output_binding *output);

/* The staging link count a seal/reopen point must observe. Linux stages an
 * anonymous O_TMPFILE inode, so 0 proves no pathname reaches the bytes. Darwin
 * stages a named O_EXCL file, so 1 proves the staging name is still the ONLY
 * link — a hardlink captured during the staging window shows up as 2 and is
 * refused. This is the per-OS form of the invariant checked at every point
 * where the pre-darwin port asserted nlink==0. */
static inline bool consensus_export_staging_nlink_valid(
    const struct consensus_export_output_binding *output, nlink_t links)
{
#if defined(__APPLE__)
    (void)output;
    return links == 1;
#else
    (void)output;
    return links == 0;
#endif
}

/* Publish the staged inode under the final name without ever replacing an
 * existing name: Linux links the still-anonymous inode by descriptor path
 * (linkat AT_SYMLINK_FOLLOW fails if the name exists), Darwin renames the
 * staging name with RENAME_EXCL. Both fail closed when the final name appeared
 * during staging, leaving the pre-existing name untouched. */
static inline bool consensus_export_staging_publish(
    struct consensus_export_output_binding *output)
{
#if defined(__APPLE__)
    return platform_renameat_noreplace(output->dirfd, output->stage_name,
                                       output->dirfd,
                                       output->final_name) == 0;
#else
    char source[PATH_MAX];
    if (!platform_fd_path(source, sizeof(source), output->temp_fd, NULL))
        return false;
    return linkat(AT_FDCWD, source, output->dirfd, output->final_name,
                  AT_SYMLINK_FOLLOW) == 0;
#endif
}

bool consensus_export_finalize_temp(
    struct consensus_export_output_binding *output,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result);

/* Shared by the offline-mint and live exporter entry TUs
 * (consensus_state_snapshot_export.c + _live.c). */
void consensus_export_output_init(struct consensus_export_output_binding *output);
bool consensus_export_output_open(
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_export_result *result);
void consensus_export_output_close(struct consensus_export_output_binding *output);
void consensus_export_run_after_bind_hook(void);
bool consensus_export_digest_nonzero(const uint8_t digest[32]);

/* Shared derive+write core used by BOTH exporter entries. Runs the proof,
 * opens the anonymous staging inode, writes the bundle, and strictly closes
 * the dest. The CALLER owns the SOURCE read transaction. */
bool consensus_export_prove_write(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result);

/* Fill the EXPORTED result on success — identical for both entries. */
void consensus_export_fill_success(
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result);

#endif /* ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_INTERNAL_H */
