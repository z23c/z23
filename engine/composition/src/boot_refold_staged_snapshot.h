/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the private cross-TU contract between boot_refold_staged.c and
 * boot_refold_staged_snapshot.c: the named steps of the
 * -load-snapshot-at-own-height loader and its resume repair, moved out of
 * boot_refold_staged.c unchanged to keep it under its file-size ceiling.
 * Only those two files may include this. */

#ifndef ZCL_COMPOSITION_BOOT_REFOLD_STAGED_SNAPSHOT_H
#define ZCL_COMPOSITION_BOOT_REFOLD_STAGED_SNAPSHOT_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct block_index;
struct boot_snapshot_apply_result;
struct main_state;
struct node_db;
struct uss_handle;
struct uss_header;

/* Outcome of the pre-rebuild applied-height publication. */
enum boot_applied_step {
    BOOT_APPLIED_OK = 0,
    BOOT_APPLIED_BEGIN_FAILED,
    BOOT_APPLIED_SET_FAILED,
    BOOT_APPLIED_COMMIT_FAILED,
};

struct block_index *boot_refold_snapshot_resume_resolve_anchor(
    struct main_state *ms, int32_t authority_h);
bool boot_refold_snapshot_resume_stamp_cursors(sqlite3 *rpdb,
                                               int32_t authority_h);
void boot_refold_snapshot_resume_warn_incomplete(bool after_ok, int32_t after,
                                                 int32_t authority_h,
                                                 int32_t hstar,
                                                 int32_t seed_h);

void boot_refold_snapshot_preflight(const char *path, struct main_state *ms);
struct uss_handle *boot_refold_snapshot_open_verified(
    const char *path, struct uss_header *hdr_out, uint8_t artifact_sha256[32]);
bool boot_refold_snapshot_anchor_bind(struct uss_handle *h,
                                      struct main_state *ms,
                                      const struct uss_header *hdr,
                                      int32_t seed_h, int32_t *hdr_tip_out);
void boot_refold_snapshot_reopen_check(
    struct uss_handle *h, const struct uss_header *hdr,
    const struct uss_header *hdr2, const uint8_t artifact_sha256[32],
    const char *err2, bool after_apply_retry);
void boot_refold_snapshot_load_failed_die(
    const struct boot_snapshot_apply_result *ar, uint64_t want);
void boot_refold_snapshot_repair_bodiless_above_seed(
    struct main_state *ms, const char *datadir, int32_t seed_h,
    bool trust_existing_block_files);
enum boot_applied_step boot_refold_snapshot_publish_applied_height(
    sqlite3 *rpdb, int32_t seed_h, bool retry_used, char **aherr);
void boot_refold_snapshot_applied_height_die(enum boot_applied_step step,
                                             int32_t seed_h, char *aherr);
bool boot_refold_snapshot_install_embedded_frontier(
    struct node_db *ndb, struct main_state *ms, int32_t seed_h,
    uint8_t *embedded_frontier, uint32_t embedded_frontier_len);
void boot_refold_snapshot_rebuild_sapling_tree(struct node_db *ndb,
                                               struct main_state *ms);
void boot_refold_snapshot_cursor_arm_die(int32_t seed_h);
void boot_refold_snapshot_seal_install(sqlite3 *rpdb,
                                       const struct uss_header *hdr,
                                       const uint8_t artifact_sha256[32],
                                       int32_t seed_h, bool frontier_installed);

#endif
