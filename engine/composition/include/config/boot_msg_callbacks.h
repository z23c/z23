/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Message-processor / connman / observer callback unit for app_init_services.
 *
 * These callbacks are registered with the msg_processor, the block generator,
 * and the block-connected/peer-vote observers in app_init_services
 * (boot_services.c). Each takes the threaded boot svc handle as its void *ctx
 * (or a typed param) and reaches only external subsystem APIs plus svc-> fields
 * — they are S-accessor-free. Extracted verbatim out of boot_services.c to
 * shrink the composition-root mega-file. Internal-only to engine/composition/src/. */

#ifndef ZCL_BOOT_MSG_CALLBACKS_H
#define ZCL_BOOT_MSG_CALLBACKS_H

#include "config/boot_internal.h"
#include "net/msgprocessor.h"

/* Block submission paths (generator + p2p + compact). */
bool boot_submit_mined_block(struct block *block, void *ctx);
bool boot_submit_p2p_block(struct block *block,
                           struct validation_state *state,
                           void *ctx);
bool boot_submit_compact_block(struct block *block,
                               struct validation_state *state,
                               void *ctx);
int boot_drain_catchup_reducer(void *ctx);
void boot_begin_catchup_batch(void *ctx);
void boot_end_catchup_batch(void *ctx);

/* Snapshot-sync state + anchor accessors. */
bool boot_snapshot_active(void *ctx);
struct block_index *boot_snapshot_anchor_get(void *ctx);
void boot_snapshot_anchor_set(struct block_index *anchor, void *ctx);

/* Header-activation hooks. */
void boot_request_header_activation(enum msg_activation_request_source source,
                                    void *ctx);
void boot_clear_header_activation_anchor(const char *reason, void *ctx);
void boot_repair_header_post_activation_anchor(void *ctx);

/* Header block-index hooks. */
int boot_scan_header_block_files(void *ctx);
bool boot_header_block_index_heights_repaired(void *ctx);

/* Header chainstate hooks. */
bool boot_commit_header_tip(struct block_index *header_tip, void *ctx);
bool boot_recommit_snapshot_anchor(struct block_index *anchor,
                                   int from_height,
                                   void *ctx);

/* Observers. */
void boot_block_connected_observer(int height, void *ctx);
void boot_record_peer_header_vote(uint32_t peer_id,
                                  int height,
                                  const char hash_hex[65],
                                  void *ctx);
void boot_wallet_tx_accepted(const struct transaction *tx, void *ctx);

/* Persistence callbacks (peer advisory, zmsg, file offer, file service). */
void boot_save_peer_advisory(const struct p2p_node *node, void *ctx);
bool boot_save_zmsg(const struct zmsg_message *msg, void *ctx);
bool boot_save_file_offer(const struct file_offer *offer, void *ctx);
int boot_ingest_file_payment(const struct file_payment *payment,
                             int64_t peer_id, int64_t now_unix, void *ctx);
void boot_wire_file_market(struct msg_processor *mp,
                           struct boot_svc_ctx *svc);
bool boot_save_zswap_ad(const struct zswap_yardsale_ad *ad, void *ctx);
/* Port-seam adapter: the msgprocessor yardsale ingest port (core/modules/net must
 * not name contexts/market/modules/zswap symbols) wired to zswap_yardsale_ingest_wire. */
int boot_zswap_ad_ingest(const uint8_t *wire, size_t wire_len,
                         const uint8_t expected_network_genesis[32],
                         int64_t peer_id, int64_t now_unix,
                         struct zswap_yardsale_ad *out_ad, void *ctx);
/* One-call wiring of the zswap yardsale platform/ports/callbacks (keeps
 * boot_services.c flat against its file-size baseline). */
void boot_wire_zswap_yardsale(struct msg_processor *mp,
                              struct boot_svc_ctx *svc);
/* One-call wiring of the yardsale swap-ceremony ports (zswapaccept /
 * zswappartial ingress plus the buyer's outbound flood port). */
void boot_wire_zswap_ceremony(struct msg_processor *mp,
                              struct boot_svc_ctx *svc);
bool boot_save_file_service(const uint8_t ip[16],
                            uint16_t port,
                            uint16_t p2p_port,
                            int64_t last_seen,
                            bool is_zcl23,
                            void *ctx);

#endif /* ZCL_BOOT_MSG_CALLBACKS_H */
