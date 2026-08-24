/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal header shared between boot.c, boot_index.c, boot_services.c.
 * Not for use outside config/src/. */

#ifndef ZCL_BOOT_INTERNAL_H
#define ZCL_BOOT_INTERNAL_H

#include "config/boot.h"
#include "config/boot_flyclient.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "validation/main_state.h"
#include "storage/coins_view_sqlite.h"
#include "coins/coins_view.h"
#include "validation/txmempool.h"
#include "net/connman.h"
#include "net/msgprocessor.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "mining/gen.h"
#include "metrics/metrics.h"
#include "storage/block_index_db.h"
#include "models/database.h"
#include "controllers/sync_controller.h"
#include "controllers/snapshot_controller.h"
#include "net/snapshot_sync_contract.h"
#include "services/bg_validation_service.h"
#include "services/bg_hash_verification_service.h"
#include "services/block_index_loader.h"
#include "services/chain_state_validator.h"
#include "kernel/service_kernel.h"
#include "event/event.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <sqlite3.h>

/* All boot globals remain static in boot.c to avoid LTO conflicts
 * with pointer aliases in wallet_helpers.c. Functions in boot_index.c
 * and boot_services.c receive what they need via parameters. */

void boot_wallet_migrate_envelopes_or_exit(
    const char *datadir, struct wallet_sqlite *wallet_db,
    struct wallet *wallet);
void boot_wallet_read_keypool_or_exit(struct wallet_sqlite *wallet_db,
                                      struct wallet *wallet);
void boot_wallet_top_up_legacy_keypool_or_exit(
    int64_t pre_open_key_rows, struct wallet_sqlite *wallet_db,
    struct wallet *wallet);

/* ── boot_index.c ───────────────────────────────────────────── */

/* Block index load/save moved to services/block_index_loader.{h,c}.
 * Coins/chain validation moved to services/chain_state_validator.{h,c}.
 * Remaining boot_index.c functions: chainstate rebuild, reindex,
 * address backfill, block file scanning. */

bool fast_rebuild_chainstate(struct coins_view_sqlite *cvs,
                              struct coins_view_cache *cvtip,
                              const char *datadir);
bool reindex_chainstate(struct main_state *ms,
                          struct coins_view_sqlite *cvs,
                          struct coins_view_cache *cvtip,
                          struct node_db *ndb,
                          const char *datadir);

/* Clear the persisted coins state (utxos + coins_best_block + commitments) so
 * the UTXO set can be rebuilt from block data. Used by reindex_chainstate and
 * by the pre-integrity-gate path in app_init (a torn anchor would otherwise
 * FATAL boot before -reindex-chainstate can run). Idempotent. */
bool boot_index_clear_coins_state(struct node_db *ndb);

/* True iff a from-genesis -reindex-chainstate replay can actually read block
 * bodies from blocks/ (the reindex reads every block from h=0 and cannot skip a
 * missing one). Prefers the loaded active chain (h=0/1 probe); at the early
 * boot-storage gates — which run before the in-memory index is loaded — it
 * resolves genesis from the block tree DB (btdb, open iff btdb_open) and
 * attempts the real body read, since a cold-import datadir can persist
 * BLOCK_HAVE_DATA with no body. Returns false when genesis readability cannot be
 * proven — the caller must then NOT wipe the coins state / arm a reindex. */
bool boot_index_reindex_replay_executable(struct main_state *ms,
                                          struct block_tree_db *btdb,
                                          bool btdb_open,
                                          const char *datadir);

/* Fail-closed reset used only by the immutable anchor producer lane. */
bool boot_mint_anchor_genesis_reset(struct node_db *ndb);

/* -full-fold (GENESIS-FOLD-TO-TIP) setup. Runs at the boot.c mint-anchor reset
 * site when ctx->full_fold. Determines the local header TIP (highest connected
 * block that has a body on disk), sets the header_admit fold ceiling to it, and
 * ARMS the mint driver's full-fold override (target=tip, skip the terminal
 * checkpoint ceremony). Resumable by default: continues from the persisted
 * utxo_apply cursor; ZCL_FULL_FOLD_FROM_GENESIS=1 forces a genesis reset first.
 * No compiled-checkpoint requirement — the fold reaches whatever height local
 * headers+bodies allow, naming a typed blocker if a body is missing. */
void boot_full_fold_reset(struct node_db *ndb, struct main_state *state);

/* full-fold driver override, consumed by boot_mint_anchor_run. When armed, the
 * mint driver folds toward *out_target (the header tip) instead of the compiled
 * SHA3 checkpoint and returns success at the target WITHOUT the checkpoint
 * snapshot/assert/export ceremony. Default disarmed (a normal -mint-anchor run
 * never calls _arm, so its behavior is unchanged). */
void boot_full_fold_arm(int32_t tip_target);
bool boot_full_fold_is_armed(int32_t *out_target);

/* Terminal -full-fold verdict, called by boot_mint_anchor_run in place of the
 * checkpoint ceremony (boot_full_fold.c). Returns true iff the fold reached the
 * tip target; otherwise names the walled stage via the typed-blocker reporter. */
bool boot_full_fold_finish(struct sqlite3 *pdb, int32_t through, int64_t count,
                           int32_t target, int stall_limit);

/* One-shot tip-height consensus-state bundle export at the end of a REACHED
 * -full-fold run (boot_full_fold.c): the checkpoint mint's producer-END
 * sequence — source receipt finalize, earned sovereign markers, bundle export —
 * bound to the header TIP the fold reached instead of cp->height. Callable only
 * by the binary that ran the fold (the receipt's running-binary binding);
 * refuses (false, fail-loud) on any gate so main.c surfaces a non-zero exit. */
bool boot_full_fold_export_bundle(struct sqlite3 *pdb, const char *datadir,
                                  int32_t target);

/* The whole -full-fold terminal path (verdict + conditional tip bundle
 * export), called by boot_mint_anchor_run in place of the checkpoint
 * ceremony. Returns the REACHED verdict; an export refusal turns it false. */
bool boot_full_fold_conclude(struct sqlite3 *pdb, const char *datadir,
                             int32_t through, int64_t count, int32_t target,
                             int stall_limit);

/* Seed a verified Sapling frontier after snapshot/refold reset. */
void boot_seed_sapling_anchor_frontier_after_reset(struct main_state *state);

/* -reindex-explorer driver: truncate every explorer projection + on-chain
 * ZNAM table and rewind the shared node.db catchup tip to the "no tip"
 * sentinel so the existing 0..tip backfill walk re-emits every projection
 * row (all INSERT OR REPLACE). node.db ONLY — touches no coins_kv /
 * progress.kv / block-index / consensus state; worst case is an incomplete
 * explorer table, never a divergence. Logs and continues on error. */
bool boot_reindex_explorer(struct node_db *ndb);

/* -backfill-zslp one-shot: re-derive the zslp_* tables from the existing
 * op_returns(is_slp=1) rows, resolving recipients from tx_outputs — no full
 * genesis..tip re-walk. node.db ONLY. Logs and continues on error. */
bool boot_backfill_zslp(struct node_db *ndb);

/* CSR-gated boot tip promotion (defined in boot.c; shared with
 * boot_index.c). Commits `tip` as the active tip + coins-best through the
 * chain_state_repository under a boot-repair rollback authorization. */
bool boot_promote_tip_via_csr(struct block_index *tip,
                              const char *reason,
                              bool persist_coins_best);
bool boot_promote_tip_preserving_header_via_csr(
    struct block_index *tip,
    const char *reason,
    bool persist_coins_best);

/* The legacy coins/tip consistency safety check (post-restore): promote a
 * durable UTXO anchor when the coins cursor proves a higher snapshot, and
 * reconcile coins_best vs the active tip — every real-block promotion
 * gated by utxo_recovery_block_trust_rooted (Invariant A index half). */
void boot_index_verify_coins_tip_consistency(struct main_state *ms,
                                             struct coins_view_sqlite *cvs,
                                             struct node_db *ndb);
void *backfill_addresses_thread(void *arg);

/* Scan block files (blk*.dat), parse ZClassic block headers,
 * create block_index entries for unknown blocks, mark BLOCK_HAVE_DATA,
 * set nTx, and propagate nChainTx. If params is NULL, only marks
 * blocks already in the index (no creation). */
int scan_block_files_mark_data(struct main_state *ms, const char *datadir,
                                const struct chain_params *params);

/* Propagate nChainTx and nChainWork for all blocks in the index.
 * Call after scan_block_files_mark_data or any operation that sets
 * BLOCK_HAVE_DATA. Returns count of blocks updated. */
int propagate_nchaintx(struct main_state *ms);

/* ── boot_block_index_ancestry.c ────────────────────────────── */
/* Block-index ancestry repair, called only by the block-file scan
 * (boot_block_file_scan.c). Shared across those two config/src TUs. */

/* Recompute every reachable block's height + cumulative metadata from the
 * genesis pprev chain, ignoring existing (possibly stale) height labels.
 * Returns the number of fields fixed (heights + chain_work + chain_tx). */
int recompute_index_from_genesis(struct main_state *ms,
                                 const struct chain_params *params);

/* After all block files are scanned and every block is in the map, resolve
 * orphan pprev links by reading hashPrevBlock from disk, then propagate
 * heights from genesis outward. Returns the number of pprev links resolved. */
int resolve_orphan_pprev_from_disk(struct main_state *ms,
                                   const char *datadir,
                                   const struct chain_params *params);

/* ── boot_services.c ────────────────────────────────────────── */

struct boot_svc_ctx {
    struct main_state *state;
    struct coins_view_sqlite *coins_sqlite;
    struct coins_view_cache *coins_tip;
    struct tx_mempool *mempool;
    struct rpc_table *rpc_table;
    struct msg_processor *msg_processor;
    struct connman *connman;
    struct wallet *wallet;
    struct gen_context *gen;
    struct wallet_sqlite *wallet_sqlite;
    struct node_db *node_db;
    struct db_service *db_service;
    struct metrics_context *metrics;
    _Atomic bool *running;
    const char *datadir;
    const struct app_context *app_ctx;
    const struct chain_params *params;
    pthread_t params_thread;
    bool params_thread_started;
    _Atomic bool *params_loaded;
    bool block_tree_open;
    struct block_tree_db *block_tree;
    struct zcl_service_kernel service_kernel;
    struct zcl_service_kernel network_kernel;
    struct zcl_service_kernel runtime_kernel;
    struct zcl_service_kernel frontend_kernel;
    /* Composition-owned runtime passed into long-lived services. */
    struct app_runtime_context runtime;
    struct snapshot_sync_service snapshot_sync;
    struct node_db_sync_catchup_job catchup_job;
    pthread_t payment_thread;
    bool payment_thread_started;
    pthread_t replay_thread;
    bool replay_thread_started;
    pthread_t offer_thread;
    bool offer_thread_started;
    pthread_t address_backfill_thread;
    bool address_backfill_thread_started;
    pthread_t hodl_history_thread;
    bool hodl_history_thread_started;
    _Atomic bool hodl_history_thread_stop;
    pthread_t projection_backfill_thread;
    bool projection_backfill_thread_started;
    _Atomic bool projection_backfill_thread_stop;
    struct snapshot_tx_index_job tx_index_job;
    bool want_address_backfill;
    bool want_snapshot_tx_index;
    bool defer_payment_service;
    bool defer_offer_service;
    struct bg_validation_service bg_validation;
    struct bg_hash_verification_service bg_hash_verify;
    /* sync_watchdog now uses the lib/health periodic ring instead of
     * its own pthread_t — see sync_watchdog_start()/stop(). */
};

bool app_init_services(struct app_context *ctx,
                        const struct chain_params *params,
                        struct boot_svc_ctx *svc);
void boot_stop_db_service_kernel(void);

/* K3 block-body read-ahead worker wiring (config/src/boot_block_prefetch.c).
 * start is a no-op unless ctx->prefetch_blocks (-prefetch-blocks); stop is
 * idempotent + safe without a prior start. */
struct main_state;
void boot_block_prefetch_start(const struct app_context *ctx,
                               struct main_state *ms);
void boot_block_prefetch_stop(void);

/* ── boot_services.c accessors shared with boot_background_workers.c ──
 * The background-worker unit (config/src/boot_background_workers.c) was lifted
 * out of boot_services.c but its worker bodies still reach the boot context
 * through these accessors, which stay in boot_services.c (they have 30+ call
 * sites there). Declared here so the two config/src TUs share one definition. */
struct node_db *boot_node_db(struct boot_svc_ctx *svc);
struct db_service *boot_db_service(struct boot_svc_ctx *svc);
bool boot_running(const struct boot_svc_ctx *svc);
bool boot_profile_has_file_service(const struct app_context *ctx);

/* ── boot_frontend_services.c ───────────────────────────────────
 * Clearnet frontend service lifecycle (file server, JSON-RPC HTTP, explorer
 * API cache, HTTPS explorer, miner, embedded Tor, store payment processor)
 * and the spec-table registrar that wires them into svc->frontend_kernel.
 * Not part of the SIGTERM shutdown sequence — the frontend kernel is torn
 * down by zcl_service_kernel_stop_all() from the boot_services.c shutdown
 * path. The runtime-profile gate accessors below STAY in boot_services.c
 * (several staying app_init call sites read them); they are declared here so
 * the frontend TU resolves them across the boundary. */
bool boot_profile_has_explorer(const struct app_context *ctx);
bool boot_profile_has_store(const struct app_context *ctx);
bool boot_profile_has_onion(const struct app_context *ctx);

/* The rpc_http service spec as registered into the frontend kernel. Exported
 * so the restart regression test (lib/test/src/test_rpc_service_restart.c)
 * can cycle stop_all -> start_all over the REAL start/stop hooks in
 * isolation. Its start hook clears RPC warmup; its stop hook re-arms it. */
struct zcl_service_spec boot_frontend_rpc_http_spec(struct boot_svc_ctx *svc);

/* FIX 1 (loader_owns_seed) — PURE seam for the daily-driver seed-clobber guard
 * at app_init_services (boot_services.c). When -load-snapshot-at-own-height is
 * set the loader at boot.c ALREADY re-seeded coins_kv from the body-digest-
 * verified assisted snapshot at its OWN height, forced the 8 stage cursors
 * there, and raised the tip_finalize trusted base; it is the selected
 * operational seed for this boot, not sovereign state. Both
 * fallback seeders (boot_refold_from_anchor_arm_if_torn AND
 * block_index_loader_seed_stages_from_cold_import) would CLOBBER it — dropping
 * the trusted base back to the compiled checkpoint and re-wedging forward sync.
 * Returns true iff this boot must SKIP both fallbacks (ctx non-NULL AND
 * ctx->load_snapshot_at_own_height != NULL). Behavior-identical to the inline
 * `svc->app_ctx && svc->app_ctx->load_snapshot_at_own_height != NULL`. */
bool boot_loader_owns_seed(const struct app_context *ctx);

/* Point explorer + API-cache RPC backends at the local JSON-RPC endpoint.
 * Called by the frontend api_cache / https_explorer starts and once directly
 * from app_init_services (boot_services.c). */
void boot_configure_frontend_rpc(struct boot_svc_ctx *svc);
void boot_register_store_buyer_rpc(struct boot_svc_ctx *svc);

/* Register every clearnet frontend service into svc->frontend_kernel.
 * Called once from app_init_services before the frontend kernel starts. */
bool boot_register_frontend_services(struct boot_svc_ctx *svc);

/* Thin boot_svc_ctx-to-job wrappers stay in boot_services.c beside the
 * app_init/shutdown call sites that own &svc->catchup_job; the
 * projection-backfill worker in boot_background_workers.c drives them
 * forward. The actual start/join/reap POLICY lives in
 * app/services/src/catchup_lifecycle_service.c (catchup_lifecycle_start/
 * _join/_reap) — it takes the job + inputs directly, not boot_svc_ctx. */
bool boot_start_catchup_service(struct boot_svc_ctx *svc, const char *datadir);
bool boot_reap_catchup_service(struct boot_svc_ctx *svc);
void boot_join_catchup_service(struct boot_svc_ctx *svc);

/* The single boot service context, owned by boot.c's g_svc. The public
 * app_add_node / app_start_metrics / app_stop_metrics entry points (declared
 * in boot.h, called from main.c with no svc in scope) reach the live context
 * through this accessor instead of a boot_services.c file-static alias.
 * Valid only after app_init builds g_svc; returns the same pointer that is
 * passed to app_init_services / app_shutdown_svc. */
struct boot_svc_ctx *boot_active_svc(void);

/* Register the standing UTXO parity service into the runtime kernel (defined
 * in boot_utxo_parity.c). Kept out of boot_services.c so that mega-file gains
 * only one call. Returns false on registration failure. */
bool boot_utxo_parity_register(struct boot_svc_ctx *svc);

/* Register the soak attestation service into the runtime kernel (defined
 * in boot_soak_attestation.c). Writes one JSON line per 60 s to
 * <datadir>/soak_attestation.jsonl — persistent evidence for MVP criterion 7.
 * Always returns true (non-fatal if the supervisor registration misses). */
bool boot_soak_attestation_register(struct boot_svc_ctx *svc);

/* Register the replay-canary sentinel watch into the runtime kernel (defined
 * in boot_canary_watch.c). 60 s supervised scan of the canary verdict dir;
 * a FAIL sentinel pages via the replay_canary_failed Condition. Quiet no-op
 * on boxes that never ran the canary. */
bool boot_canary_watch_register(struct boot_svc_ctx *svc);

/* ── boot_runtime_sync_services.c ───────────────────────────────
 * Runtime service-kernel start/stop adapters for the sync-adjacent services
 * that influence the tip / header path (header_probe, legacy_mirror, gap_fill,
 * zclassicd_oracle, rolling_anchor). Registered by
 * boot_register_runtime_services() (boot_services.c spec table); they operate
 * only on the boot_svc_ctx passed as ctx — no file-statics — and are NOT part
 * of the SIGTERM shutdown sequence. */
/* THE network predicate for every service that dials a co-located zclassicd.
 * Returns NULL when this node is on mainnet, otherwise the network's name
 * ("regtest" / "testnet" / whatever chainparams calls it) — so a caller both
 * decides and NAMES its skip from one place.
 *
 * Exists because that decision was being made three different ways, and one of
 * the three was not being made at all: on 2026-07-28 a sealed `-regtest`
 * fixture polled the operator's LIVE zclassicd on 127.0.0.1:8232, three log
 * lines after the legacy mirror had correctly skipped for exactly that reason.
 * The zclassicd on 8232 is a MAINNET daemon; comparing a non-mainnet node
 * against it is a guaranteed false compare AND an outbound dial out of a
 * fixture that was supposed to be sealed. Implemented in
 * boot_runtime_sync_services.c. */
const char *boot_nonmain_network_name(const struct boot_svc_ctx *svc);

bool boot_header_probe_start(void *ctx);     /* init probe + register poll Job */
void boot_header_probe_stop(void *ctx);      /* header_probe runtime stop */
bool boot_legacy_mirror_start(void *ctx);    /* always-on legacy mirror sync */
void boot_legacy_mirror_stop(void *ctx);     /* legacy mirror sync stop */
bool boot_gap_fill_start(void *ctx);         /* background body gap-fill */
void boot_gap_fill_stop(void *ctx);          /* body gap-fill stop */
bool boot_zclassicd_oracle_start(void *ctx); /* external zclassicd height oracle */
void boot_zclassicd_oracle_stop(void *ctx);  /* zclassicd oracle stop */
bool boot_rolling_anchor_start(void *ctx);   /* rolling SHA3 anchor contract */
void boot_rolling_anchor_stop(void *ctx);    /* rolling SHA3 anchor stop */

/* ── segment_sealer (boot_runtime_sync_services.c) ──────────────
 * Sealed-history ROM sealer: seals finalized (fully-below-frontier) 10k block
 * segments into <datadir>/segments so the fold's block reader serves those
 * bodies from the hash-verified segment store instead of an unverified blk*.dat
 * re-read. OFF BY DEFAULT (ZCL_SEGMENT_SEALER=1 to enable) — the supervised
 * thread still runs + heartbeats, but seals nothing, so default on-disk state
 * is unchanged. Registered into the runtime kernel by boot_segment_sealer_register()
 * (called from boot_register_runtime_services); the start/stop adapters + the
 * file-static service instance are private to that TU. */
bool boot_segment_sealer_register(struct boot_svc_ctx *svc);

/* ── boot_bg_verification.c ─────────────────────────────────────
 * Runtime service-kernel start/stop adapters for the two background
 * re-verification services. Registered by boot_register_runtime_services()
 * (boot_services.c spec table); operate on svc->bg_validation /
 * svc->bg_hash_verify only — no file-statics. */
bool boot_bg_validation_start(void *ctx);   /* full proof/script re-validation */
void boot_bg_validation_stop(void *ctx);
bool boot_bg_hash_verify_start(void *ctx);   /* historical block hash verify */
void boot_bg_hash_verify_stop(void *ctx);

/* ── boot_sd_watchdog.c ─────────────────────────────────────────
 * systemd watchdog heartbeat start/stop adapters (the periodic collect
 * tick + the dedicated pet thread stay private to that TU). Registered by
 * boot_register_runtime_services() (boot_services.c spec table). */
bool boot_sd_watchdog_start(void *ctx);   /* arm WATCHDOG=1 heartbeat ring */
void boot_sd_watchdog_stop(void *ctx);
/* True when onion was requested (or is running) but DESCRIPTOR
 * PUBLICATION has not been observed — READY=1 must wait. */
bool boot_sd_watchdog_onion_blocks_ready(void);

#ifdef ZCL_TESTING
/* Test seam for the pure pet decision (lib/test/src/test_sd_notify.c). */
bool boot_sd_watchdog_test_pet_decide(bool supervisor_alive, bool have_verdict,
                                      int64_t verdict_age_us,
                                      bool recent_progress,
                                      int64_t grace_left_us,
                                      int64_t verdict_bound_us);
bool boot_sd_watchdog_test_keepalive_supervisor(bool runtime_alive,
                                                bool sweep_alive,
                                                bool recent_progress);
#endif

/* ── boot_supervisor_backstop.c ──────────────────────────────────
 * Registers the independent supervisor-sweep-heartbeat watcher (Pillar 7
 * — "supervise the supervisor"; see util/supervisor_backstop.h) into the
 * runtime service kernel. The watcher's own thread + freeze decision
 * live in lib/util/src/supervisor_backstop.c; this unit is only the
 * boot-composition glue, same one-call pattern as
 * boot_mem_pressure_register(). Called from
 * boot_register_runtime_services() (boot_services.c). */
bool boot_supervisor_backstop_register(struct boot_svc_ctx *svc);

/* ── boot_mem_pressure.c ────────────────────────────────────────
 * Memory-pressure organ (Rung 1 follow-on, docs/adr/0003-os-substrate-
 * verdict.md): registers lib/util/mem_pressure's poll on the SAME health
 * periodic ring as boot_sd_watchdog — no dedicated thread. Called from
 * boot_register_runtime_services() (the boot_canary_watch.c pattern). */
bool boot_mem_pressure_register(struct boot_svc_ctx *svc);

/* ── utxo_mirror_sync (boot_runtime_sync_services.c) ────────────
 * Keep node.db's explorer `utxos` mirror synced to the authoritative
 * coins_kv set (process_block_flush_coins, its only forward writer, is dead
 * code, so the mirror otherwise freezes at the cold-import seed height). The
 * service is additive + node.db-only — never touches the consensus coins_kv
 * write path. Registered into the runtime kernel by
 * boot_utxo_mirror_sync_register() (called from boot_register_runtime_services). */
bool boot_utxo_mirror_sync_register(struct boot_svc_ctx *svc);
bool boot_utxo_mirror_sync_start(void *ctx);
void boot_utxo_mirror_sync_stop(void *ctx);

/* ── boot_node_utilities.c ──────────────────────────────────────
 * Async observer that logs sync-pipeline transitions; wired by
 * app_init_services (boot_services.c) via event_observe_async(). The public
 * app_add_node / app_start_metrics / app_stop_metrics entry points (declared
 * in boot.h) also live in this TU. */
void boot_sync_state_logger(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx);

/* Wire the process_block tip-publication hooks + gap-fill kick (defined in
 * boot_tip_hooks.c) into the validation engine. Called once from
 * app_init_services. The teardown counterpart stays inline in app_shutdown_svc
 * since it passes NULLs and references no moved symbol. */
void boot_register_process_block_hooks(struct boot_svc_ctx *svc);

/* Open / close the reducer projection storage — the event_log + per-domain
 * projections — defined in boot_projections.c. Called once from
 * app_init_services / app_shutdown_svc. */
void boot_start_projection_storage(const char *datadir);
void boot_stop_projection_storage(void);

/* Idempotent open of the append-only event_log. Called early from app_init so
 * the event-log singleton is published before the coins_tip read view
 * (coins_view_kv) and the other per-domain projections bind, then again (no-op
 * reuse) from the phase-4 fan-out. Returns true once the log is open. */
bool boot_ensure_event_log(const char *datadir);

/* Idempotent open of the block_index_projection (log-derived source for the
 * event-log boot rebuild). Hoisted so boot.c can open + publish + catch
 * up before the block-index load; the phase-4 fan-out call is a no-op reuse.
 * Requires the event log already published. Returns the projection or NULL. */
struct block_index_projection;
struct block_index_projection *boot_ensure_block_index_projection(
    const char *datadir);

/* Shutdown phase order:
 * 1. stop externally visible services
 * 2. persist fast-restart state
 * 3. quiesce network and flush chainstate
 * 4. persist runtime-owned stores
 * 5. clear runtime registry and free owned resources
 */
void app_shutdown_svc(struct boot_svc_ctx *svc);

/* ── config/src/boot_services_shutdown.c ──────────────────────────────────── *
 * Drain background workers before app_shutdown_offline's destructive frees;
 * dependencies remain owned until every worker has actually exited. */
void boot_offline_join_workers_or_exit(const char *datadir);
/* Persist and close offline-mode stores after all writers are joined. Every
 * failed durability operation is logged; false forbids the clean marker. */
bool boot_offline_persist_runtime(struct node_db *ndb);
/* Mint the clean marker + stage receipt or terminate loudly with ownership
 * retained. This is the offline equivalent of app_shutdown_svc's barrier. */
void boot_offline_complete_durability_or_exit(const char *datadir,
                                               bool durability_ok);

/* ── config/src/boot_anchor_snapshot_reachability.c ─────────────────────── *
 * Shared between it and boot_refold_staged.c's real loaders/AUTO-ARM so path
 * resolution and reachability can never disagree about which file/checkpoint
 * they mean. See config/boot.h for the public predicate
 * (boot_refold_from_anchor_artifact_available[_ex]) these two back. */
bool boot_anchor_snapshot_path_resolve(struct node_db *ndb, char *buf,
                                       size_t cap);
struct sha3_utxo_checkpoint;
bool anchor_snapshot_verified_reachable(struct node_db *ndb,
                                        const struct sha3_utxo_checkpoint *cp);

/* Park the process alive-but-degraded after a boot-storage gate names its
 * blocker: never _exit()s into a Restart=always crash-loop, blocks until a
 * shutdown signal is observed, then returns false so the caller (app_init)
 * exits cleanly. Never returns true. Defined in boot.c; shared here so
 * other boot-storage-gate call sites (boot_node_db_gate.c) use the SAME
 * park path instead of duplicating the wait loop. */
bool boot_park_until_shutdown(const char *gate_name);

/* ── config/src/boot_node_db_gate.c ──────────────────────────────────────
 * #7 supervision-coverage fix: node.db failing to open used to log a
 * warning and continue booting RAM-only (silently dropping wallet/chain
 * persistence). Names a PERMANENT blocker + parks alive-degraded like the
 * sibling boot-storage gates (crypto_params_missing, coins_view_integrity,
 * progress_kv_open). Always returns false (never advances past the gate);
 * app_init does `return boot_node_db_open_failed_gate(ctx->datadir);`. */
bool boot_node_db_open_failed_gate(const char *datadir);

/* ── config/src/boot_regtest_shielded.c ─────────────────────────────────
 * -regtestshielded: activate Overwinter+Sapling from genesis on a REGTEST
 * node's runtime chain params only (the zcashd -nuparams equivalent).
 * No-op unless enabled; warns and does nothing without -regtest. */
void boot_apply_regtest_shielded(bool enabled, bool regtest);

bool boot_wallet_identity_ensure(struct node_db *ndb,
                                 const uint8_t network_genesis[32],
                                 const char *operator_lane);

void boot_wallet_credential_register_or_die(void);

#endif
