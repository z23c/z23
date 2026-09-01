/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot projection storage — the event_log + reducer read-model projections.
 *
 * Opens the append-only event log + the per-domain projections (mempool,
 * peers, block_index, znam, wallet, contacts, onion-announcements, hodl-history)
 * during boot and tears them down in reverse on shutdown. The handles live in
 * module-static pointers so they can be freed regardless of singleton state.
 *
 * boot_ensure_event_log / boot_ensure_block_index_projection stay extern —
 * boot.c opens them early (the event-log singleton must be published before the
 * coins read view + the other projections bind; first-opener wins). The
 * canonical UTXO set is the kernel coins store (coins_kv), read live through
 * coins_view_kv — there is no separate event-log-fed UTXO projection.
 */

#include "config/boot_internal.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "storage/mempool_projection.h"
#include "storage/peers_projection.h"
#include "storage/block_index_projection.h"
#include "storage/znam_projection.h"
#include "storage/wallet_projection.h"
#include "storage/small_projections.h"
#include "storage/topology_store.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

static event_log_t               *g_phase4_event_log = NULL;
static mempool_projection_t      *g_phase4_mempool_projection = NULL;
static peers_projection_t        *g_phase4_peers_projection = NULL;
static block_index_projection_t  *g_phase4_block_index_projection = NULL;
static znam_projection_t         *g_phase4_znam_projection = NULL;
static wallet_projection_t       *g_phase4_wallet_projection = NULL;
static contacts_projection_t     *g_phase4_contacts_projection = NULL;
static onion_ann_projection_t    *g_phase4_onion_ann_projection = NULL;
static hodl_history_projection_t *g_phase4_hodl_history_projection = NULL;

/* Idempotent open of the append-only event_log. boot.c must publish this
 * handle (event_log_set_singleton non-NULL) before it builds the coins_tip
 * read view (coins_view_kv) and before the other per-domain projections bind,
 * which is well before app_init_services runs. So this is hoisted here and
 * called twice: once early from app_init and once from
 * boot_start_projection_storage (the rest of the projection fan-out). The
 * second call is a no-op reuse — first opener wins, one handle, no
 * split-brain. Returns true once the event log is open and published. */
bool boot_ensure_event_log(const char *datadir)
{
    if (g_phase4_event_log)
        return true;
    if (!datadir || !datadir[0])
        return false;

    char event_path[PATH_MAX];
    int ne = snprintf(event_path, sizeof(event_path), "%s/event_log.dat",
                      datadir);
    if (ne <= 0 || (size_t)ne >= sizeof(event_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log path too long\n");
        return false;
    }

    g_phase4_event_log = event_log_open(event_path);
    if (!g_phase4_event_log) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log unavailable; projections disabled\n");
        return false;
    }
    event_log_set_singleton(g_phase4_event_log);

    /* Stamp the coins_kv migration marker on existing forward-built datadirs so
     * the read path is recognised as canonical. No-op before progress.kv opens
     * (retried on the later fan-out call) and on an empty coins_kv, which
     * re-derives from block bodies via the normal fold (pre-1.0: legacy
     * datadirs may re-derive). */
    (void)coins_kv_boot_rebuild_if_needed(progress_store_db());
    return true;
}

/* Idempotent open of the block_index_projection (the log-derived
 * authoritative source for load_block_index_from_projection). Like
 * boot_ensure_event_log
 * this is hoisted so boot.c can open + publish + catch up the projection
 * BEFORE the block-index load (which optionally rebuilds from it under
 * -rebuildfromlog), well before app_init_services runs. Called twice: once
 * early from boot.c and once (no-op reuse) from boot_start_projection_storage.
 * First opener wins — one handle, no split-brain. Requires the event log
 * to already be published (boot_ensure_event_log first).
 * Returns the published projection or NULL. */
block_index_projection_t *boot_ensure_block_index_projection(const char *datadir)
{
    block_index_projection_t *existing = block_index_projection_singleton();
    if (existing)
        return existing;
    if (!datadir || !datadir[0])
        return NULL;
    if (!g_phase4_event_log)
        return NULL;  /* event log must be published first */

    char bip_path[PATH_MAX];
    int n5 = snprintf(bip_path, sizeof(bip_path),
                      "%s/block_index_projection.db", datadir);
    if (n5 <= 0 || (size_t)n5 >= sizeof(bip_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] block_index_projection path too long\n");
        return NULL;
    }
    g_phase4_block_index_projection =
        block_index_projection_open(bip_path, g_phase4_event_log);
    if (!g_phase4_block_index_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] block_index_projection unavailable\n");
        return NULL;
    }
    block_index_projection_set_singleton(g_phase4_block_index_projection);
    (void)block_index_projection_catch_up(g_phase4_block_index_projection);
    return g_phase4_block_index_projection;
}

void boot_start_projection_storage(const char *datadir)
{
    if (!datadir || !datadir[0])
        return;

    /* Wave A2 (D4) split: open the SECOND handle to the already-open
     * progress.kv (progress_store opened it back in app_init), giving the
     * address_index / txindex / created_outputs co-writers their OWN connection
     * + tx lock so their BEGIN IMMEDIATE never serialises on the reducer drive's
     * kernel tx lock. Non-fatal — a projection fold that finds no handle just
     * idles its tick; the kernel fold is unaffected. */
    if (!projection_store_open(datadir))
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] projection_store unavailable; projection folds idle\n");

    char mempool_path[PATH_MAX];
    char peers_path[PATH_MAX];
    int n2 = snprintf(mempool_path, sizeof(mempool_path),
                      "%s/mempool_projection.db", datadir);
    int n3 = snprintf(peers_path, sizeof(peers_path),
                      "%s/peers_projection.db", datadir);
    if (n2 <= 0 || (size_t)n2 >= sizeof(mempool_path) ||
        n3 <= 0 || (size_t)n3 >= sizeof(peers_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] projection storage paths too long\n");
        return;
    }

    /* Open (or reuse, if boot.c already opened it for the coins read view) the
     * event_log. After this g_phase4_event_log is published. */
    if (!boot_ensure_event_log(datadir)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log unavailable; projections disabled\n");
        return;
    }

    mempool_projection_set_event_log(g_phase4_event_log);
    g_phase4_mempool_projection =
        mempool_projection_open(mempool_path, g_phase4_event_log);
    if (!g_phase4_mempool_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] mempool_projection unavailable; projection disabled\n");
    } else {
        uint64_t off =
            mempool_projection_catch_up(g_phase4_mempool_projection);
        if (off == UINT64_MAX) {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] mempool_projection catch_up failed\n");
        } else {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] mempool_projection caught up to offset=%llu\n",
                    (unsigned long long)off);
        }
    }

    peers_projection_set_event_log(g_phase4_event_log);
    g_phase4_peers_projection =
        peers_projection_open(peers_path, g_phase4_event_log);
    if (!g_phase4_peers_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] peers_projection unavailable; projection disabled\n");
        return;
    }
    uint64_t off = peers_projection_catch_up(g_phase4_peers_projection);
    if (off == UINT64_MAX) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] peers_projection catch_up failed\n");
    } else {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] peers_projection caught up to offset=%llu\n",
                (unsigned long long)off);
    }

    /* topology_store: the addr-gossip / crawler-result GRAPH ("who
     * advertises whom"). Its own dedicated file, no event log — best-effort,
     * never blocks the rest of projection setup. */
    if (!topology_store_open(datadir))
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] topology_store unavailable; graph disabled\n");

    /* The canonical UTXO set is the kernel coins store (coins_kv), read live
     * through coins_view_kv and authored in-txn by the utxo_apply stage; there
     * is no separate event-log-fed UTXO projection to open or anchor-seed. */

    /* block_index_projection is opened or reused via the hoisted helper;
     * first opener wins when boot.c already opened it for -rebuildfromlog. */
    if (!boot_ensure_block_index_projection(datadir)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] block_index_projection unavailable\n");
        return;
    }

    /* ZNAM projection replay. */
    char znam_path[PATH_MAX];
    int n6 = snprintf(znam_path, sizeof(znam_path),
                      "%s/znam_projection.db", datadir);
    if (n6 <= 0 || (size_t)n6 >= sizeof(znam_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] znam_projection path too long\n");
        return;
    }
    znam_projection_set_event_log(g_phase4_event_log);
    g_phase4_znam_projection =
        znam_projection_open(znam_path, g_phase4_event_log);
    if (!g_phase4_znam_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] znam_projection unavailable; projection disabled\n");
        return;
    }
    uint64_t zoff = znam_projection_catch_up(g_phase4_znam_projection);
    if (zoff == UINT64_MAX) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] znam_projection catch_up failed\n");
    } else {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] znam_projection caught up to offset=%llu\n",
                (unsigned long long)zoff);
    }

    /* Wallet-view projection replay. Set the event-log emitter only after
     * initial replay so boot catch-up cannot race new wallet view events. */
    char wallet_path[PATH_MAX];
    int n7 = snprintf(wallet_path, sizeof(wallet_path),
                      "%s/wallet_projection.db", datadir);
    if (n7 <= 0 || (size_t)n7 >= sizeof(wallet_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] wallet_projection path too long\n");
        return;
    }
    g_phase4_wallet_projection =
        wallet_projection_open(wallet_path, g_phase4_event_log);
    if (!g_phase4_wallet_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] wallet_projection unavailable; projection disabled\n");
        return;
    }
    uint64_t woff = wallet_projection_catch_up(g_phase4_wallet_projection);
    if (woff == UINT64_MAX) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] wallet_projection catch_up failed\n");
    } else {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] wallet_projection caught up to offset=%llu\n",
                (unsigned long long)woff);
    }
    wallet_projection_set_event_log(g_phase4_event_log);

    /* Small-batch projection replay. */
    char contacts_path[PATH_MAX];
    char onion_ann_path[PATH_MAX];
    char hodl_history_path[PATH_MAX];
    int n8 = snprintf(contacts_path, sizeof(contacts_path),
                      "%s/contacts_projection.db", datadir);
    int n9 = snprintf(onion_ann_path, sizeof(onion_ann_path),
                      "%s/onion_announcements_projection.db", datadir);
    int n10 = snprintf(hodl_history_path, sizeof(hodl_history_path),
                       "%s/hodl_history_projection.db", datadir);
    if (n8 <= 0 || (size_t)n8 >= sizeof(contacts_path) ||
        n9 <= 0 || (size_t)n9 >= sizeof(onion_ann_path) ||
        n10 <= 0 || (size_t)n10 >= sizeof(hodl_history_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] small projection paths too long\n");
        return;
    }

    contacts_projection_set_event_log(g_phase4_event_log);
    g_phase4_contacts_projection =
        contacts_projection_open(contacts_path, g_phase4_event_log);
    if (!g_phase4_contacts_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] contacts_projection unavailable; projection disabled\n");
    } else {
        uint64_t coff =
            contacts_projection_catch_up(g_phase4_contacts_projection);
        if (coff == UINT64_MAX) {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] contacts_projection catch_up failed\n");
        } else {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] contacts_projection caught up to offset=%llu\n",
                    (unsigned long long)coff);
        }
    }

    onion_ann_projection_set_event_log(g_phase4_event_log);
    g_phase4_onion_ann_projection =
        onion_ann_projection_open(onion_ann_path, g_phase4_event_log);
    if (!g_phase4_onion_ann_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] onion_announcements_projection unavailable; "
                "projection disabled\n");
    } else {
        uint64_t aoff =
            onion_ann_projection_catch_up(g_phase4_onion_ann_projection);
        if (aoff == UINT64_MAX) {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] onion_announcements_projection catch_up failed\n");
        } else {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] onion_announcements_projection caught up to "
                    "offset=%llu\n",
                    (unsigned long long)aoff);
        }
    }

    hodl_history_projection_set_event_log(g_phase4_event_log);
    g_phase4_hodl_history_projection =
        hodl_history_projection_open(hodl_history_path, g_phase4_event_log);
    if (!g_phase4_hodl_history_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] hodl_history_projection unavailable; "
                "projection disabled\n");
    } else {
        uint64_t hoff =
            hodl_history_projection_catch_up(g_phase4_hodl_history_projection);
        if (hoff == UINT64_MAX) {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] hodl_history_projection catch_up failed\n");
        } else {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] hodl_history_projection caught up to "
                    "offset=%llu\n",
                    (unsigned long long)hoff);
        }
    }
}

void boot_stop_projection_storage(void)
{
    /* Order: detach emitters before closing the projections so no
     * in-flight emit lands on a stale handle. Then close projections
     * before the event log they point to. */
    mempool_projection_set_event_log(NULL);
    peers_projection_set_event_log(NULL);
    wallet_projection_set_event_log(NULL);
    contacts_projection_set_event_log(NULL);
    onion_ann_projection_set_event_log(NULL);
    hodl_history_projection_set_event_log(NULL);
    if (g_phase4_mempool_projection) {
        mempool_projection_close(g_phase4_mempool_projection);
        g_phase4_mempool_projection = NULL;
    }
    if (g_phase4_peers_projection) {
        peers_projection_close(g_phase4_peers_projection);
        g_phase4_peers_projection = NULL;
    }
    znam_projection_set_event_log(NULL);
    if (g_phase4_znam_projection) {
        znam_projection_close(g_phase4_znam_projection);
        g_phase4_znam_projection = NULL;
    }
    if (g_phase4_wallet_projection) {
        wallet_projection_close(g_phase4_wallet_projection);
        g_phase4_wallet_projection = NULL;
    }
    if (g_phase4_contacts_projection) {
        contacts_projection_close(g_phase4_contacts_projection);
        g_phase4_contacts_projection = NULL;
    }
    if (g_phase4_onion_ann_projection) {
        onion_ann_projection_close(g_phase4_onion_ann_projection);
        g_phase4_onion_ann_projection = NULL;
    }
    if (g_phase4_hodl_history_projection) {
        hodl_history_projection_close(g_phase4_hodl_history_projection);
        g_phase4_hodl_history_projection = NULL;
    }
    topology_store_close();
    block_index_projection_set_singleton(NULL);
    if (g_phase4_block_index_projection) {
        block_index_projection_close(g_phase4_block_index_projection);
        g_phase4_block_index_projection = NULL;
    }
    event_log_set_singleton(NULL);
    if (g_phase4_event_log) {
        event_log_close(g_phase4_event_log);
        g_phase4_event_log = NULL;
    }
    /* Close the Wave A2 projection handle to progress.kv (no-op if unopened).
     * progress_store's own close still owns the WAL checkpoint of the file. */
    projection_store_close();
}
