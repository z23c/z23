/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the ACTIVATE mode's private cross-TU contract — the log subsystem
 * tag plus the prior-generation backup entry point and the two progress-store
 * identity/version probes the cutover fence reads.
 *
 * consensus_state_snapshot_install_activate.c owns the CUTOVER: the row
 * stream, the atomic install transaction, destination + terminal
 * verification, and the entry point.
 * consensus_state_snapshot_install_activate_backup.c owns the PRIOR
 * GENERATION: the store health/identity probes and the VACUUM INTO capture
 * that makes the pre-install image physically restorable. The split happened
 * when the combined file passed the 800-line shape ceiling. These four
 * declarations are all that crosses that seam, so they live here and nowhere
 * else — nothing outside those two translation units may include this header.
 */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_SNAPSHOT_INSTALL_ACTIVATE_INTERNAL_H
#define ZCL_CONFIG_CONSENSUS_STATE_SNAPSHOT_INSTALL_ACTIVATE_INTERNAL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>

#define ACTIVATE_SUBSYS "consensus_bundle_activate"

/* True iff `db`'s main database still resolves to the same file the handle was
 * opened on (no rename/replace under the live store).  Defined in
 * consensus_state_snapshot_install_activate_backup.c. */
bool activate_progress_file_unmoved(sqlite3 *db);

/* Read SQLITE_FCNTL_DATA_VERSION for the main database — the fence the cutover
 * compares across its BEGIN IMMEDIATE.  Defined in
 * consensus_state_snapshot_install_activate_backup.c. */
bool activate_data_version(sqlite3 *db, sqlite3_int64 *version);

/* Capture a physically restorable prior generation through the retained
 * directory capability.  Defined in
 * consensus_state_snapshot_install_activate_backup.c; the full contract is the
 * comment on its definition there. */
bool activate_backup_prior_generation(sqlite3 *progress_db,
                                      int datadir_fd,
                                      const char *datadir_display,
                                      char *out_path, size_t out_cap,
                                      sqlite3_int64 *data_version_out,
                                      sqlite3_int64 *changes_out);

#endif /* ZCL_CONFIG_CONSENSUS_STATE_SNAPSHOT_INSTALL_ACTIVATE_INTERNAL_H */
