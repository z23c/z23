/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare the -mint-anchor drive-loop backoff, Sapling-rebuild wait,
 * and balanced teardown used by boot_mint_anchor_run. */
#ifndef ZCL_CONFIG_BOOT_MINT_ANCHOR_DRIVE_H
#define ZCL_CONFIG_BOOT_MINT_ANCHOR_DRIVE_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Sleep the drive loop between no-progress rounds. */
void mint_drive_nap_ms(long ms);

/* Seconds to wait for the deferred Sapling rebuild before failing closed.
 * ZCL_MINT_REBUILD_WAIT_MAX_S overrides; 0 disables the wait entirely. */
int mint_rebuild_wait_max_s(void);

/* Set progress.kv's WAL auto-checkpoint threshold (pages; 0 disables). */
void mint_wal_autocheckpoint(struct sqlite3 *pdb, int pages);

/* Balanced teardown for every drive-loop exit SHORT of the anchor. */
void mint_drive_stop(struct sqlite3 *pdb, bool mint_sync_off, bool wal_manual,
                     bool lookahead);

/* Carried across drive-loop rounds; zero-initialise, and re-zero on progress
 * so a later pause gets a fresh budget. */
struct mint_rebuild_wait_state {
    int64_t started_us;   /* >0 while the pause is up */
    bool    logged;       /* the one-shot explanatory line has been printed */
};

enum mint_rebuild_wait_result {
    MINT_REBUILD_WAIT_WAITING,   /* still rebuilding; the loop should nap */
    MINT_REBUILD_WAIT_TIMEOUT,   /* budget exhausted; fail closed */
};

/* Account one drive-loop round spent inside the Sapling rebuild pause. Naps
 * internally, so the caller only decides what to do with the result. */
enum mint_rebuild_wait_result boot_mint_anchor_drive_rebuild_wait(
    struct mint_rebuild_wait_state *st);

#endif /* ZCL_CONFIG_BOOT_MINT_ANCHOR_DRIVE_H */
