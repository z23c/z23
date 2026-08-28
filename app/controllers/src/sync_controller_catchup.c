/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* sync_controller_catchup: long-running maintenance jobs.
 *
 *   - sapling_tree_rebuild: replay all shielded outputs from block
 *     files to rebuild the Sapling commitment tree.
 *   - node_db_sync_catchup: bulk-index blocks (sqlite_tip+1 → chain_tip)
 *     into SQLite, optionally scanning for wallet transactions.
 *   - catchup + import job machinery (thread spawn / join / status).
 *   - wallet_keys copy (idempotent).
 *   - mempool save/load (on shutdown / startup).
 *
 * sync_controller_internal.h owns cross-file glue for the catchup/import
 * controller siblings. */

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "util/boot_progress.h"
#include "services/recovery_policy.h"
#include "services/node_db_catchup_service.h"
#include "models/db_txn.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chain.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "keys/key.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "storage/dbwrapper.h"
#include "storage/coins_db.h"
#include "coins/undo.h"
#include "validation/chainstate.h"
#include "validation/txmempool.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"
#include "event/event.h"
#include "config/runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

extern volatile sig_atomic_t g_shutdown_requested;

/* sync_block_lean (lean block header + txid index) moved with the catchup
 * orchestration into app/services/src/node_db_catchup_service.c. */

/* Index drop/rebuild delegated to node_db_ibd_turbo_mode/normal_mode. */

void sync_block_file_mapping_init(struct sync_block_file_mapping *mapping)
{
    if (!mapping) return;
    mapping->fd = -1;
    platform_read_mapping_init(&mapping->view);
}

void sync_block_file_mapping_close(struct sync_block_file_mapping *mapping)
{
    if (!mapping) return;
    platform_read_mapping_close(&mapping->view);
    if (mapping->fd >= 0) close(mapping->fd);
    sync_block_file_mapping_init(mapping);
}

bool sync_block_file_mapping_open(struct sync_block_file_mapping *mapping,
                                  const char *datadir, int file_num)
{
    if (!mapping || !datadir || file_num < 0) return false;
    sync_block_file_mapping_close(mapping);

    char path[512];
    int path_len = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                            datadir, file_num);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        LOG_WARN("sync", "map_block_file: path too long for file %d", file_num);
        return false;
    }
    int flags = O_RDONLY;
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        LOG_WARN("sync", "map_block_file: open failed for %s", path);
        return false;
    }
    struct stat fst;
    if (fstat(fd, &fst) != 0 || fst.st_size <= 0 ||
        (uintmax_t)fst.st_size > (uintmax_t)SIZE_MAX) {
        close(fd);
        LOG_WARN("sync", "map_block_file: invalid size for %s", path);
        return false;
    }
    if (!platform_read_mapping_open(&mapping->view, fd,
                                    (size_t)fst.st_size)) {
        close(fd);
        LOG_WARN("sync", "map_block_file: mapping failed for file %d", file_num);
        return false;
    }
    mapping->fd = fd;
    platform_read_mapping_advise_sequential(&mapping->view);
    return true;
}

/* catchup_try_sapling_decrypt (try-decrypt Sapling outputs into SQLite)
 * moved with the catchup orchestration into
 * app/services/src/node_db_catchup_service.c. */

int node_db_sync_catchup(struct node_db *ndb,
                         const struct active_chain *chain,
                         struct wallet *w,
                         const char *datadir)
{
    /* Parse/validate front matter: the controller boundary rejects a bad
     * handle here so the failure logs with controller context. The whole
     * orchestration (turbo scope, DB verify, Sapling-tree init, the
     * transaction/commit block loop, turbo end) now lives in the
     * node_db_catchup_service. */
    if (!ndb || !ndb->open || !chain)
        LOG_ERR("sync", "catchup: invalid args (ndb=%p, chain=%p)", (void *)ndb, (void *)chain);

    return node_db_catchup_service_run(ndb, chain, w, datadir);
}
