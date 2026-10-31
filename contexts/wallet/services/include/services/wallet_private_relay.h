/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private broadcast of this wallet's own sends.
 *
 * A wallet send is validated by the full accept_to_mempool gate into a
 * private pool that no P2P handler reads, so `mempool`, `getdata`, trickle,
 * Dandelion fluff and block templates cannot reveal it. After a random delay
 * the transaction is pushed once, as an unsolicited `tx`, to one outbound
 * onion peer. With no such peer it is held; it never falls back to clearnet.
 * When the network offers the transaction back, or a block contains it, the
 * pending state clears and ordinary relay applies.
 *
 * Scope: only the wallet's own send paths (sendtoaddress, sendmany,
 * z_sendmany). Vault, ZSLP, ZDIR, ZNAM, ZID, blog, swap, multisig and raw
 * transaction paths keep public relay.
 *
 * Not solved here: timing correlation by an observer of both the node's Tor
 * circuits and the network, and a malicious first onion peer, which learns
 * that this node originated the transaction. */

#ifndef ZCL_WALLET_PRIVATE_RELAY_H
#define ZCL_WALLET_PRIVATE_RELAY_H

#include "core/uint256.h"
#include "base/result.h"
#include "util/sync.h"
#include "validation/txmempool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct chain_params;
struct coins_view_cache;
struct connman;
struct main_state;
struct p2p_node;
struct transaction;
struct wallet;

/* Uniform random delay before each push, drawn from the CSPRNG. */
#define WPR_DELAY_MIN_MS 2000
#define WPR_DELAY_MAX_MS 20000
/* A pushed transaction not seen back within this time goes to a different
 * onion peer after a fresh delay. The receiving peer stems for at most one
 * Dandelion embargo (30 s) per hop, so 180 s covers several hops while still
 * allowing about seven distinct peers before a 20-block expiry. */
#define WPR_RESEND_AFTER_S 180
/* Spacing between revalidation attempts of a restored transaction whose
 * inputs the chain view cannot yet show, and between expiry rollback
 * retries. */
#define WPR_RETRY_S 30
#define WPR_SEEN_RETAIN_S 600
#define WPR_MAX_ENTRIES 256
#define WPR_MAX_TRIED 8

enum wpr_mode {
    WPR_MODE_PUBLIC = 0,
    WPR_MODE_PRIVATE = 1,
};

enum wpr_state {
    WPR_WAITING_FOR_ROUTE = 0,
    WPR_SCHEDULED = 1,
    WPR_SENT = 2,
    WPR_SEEN = 3,
};

/* Chain and peer authorities. Every pointer must outlive the relay. */
struct wpr_env {
    struct wallet *wallet;
    struct connman *connman;
    struct coins_view_cache *coins_tip;
    struct main_state *main_state;
    const struct chain_params *params;
    const char *datadir;
    int64_t min_relay_fee;
};

struct wpr_entry {
    bool used;
    bool in_pool;     /* validated into the private pool */
    bool expired;     /* reported for wallet rollback */
    bool has_expiry;
    uint32_t expiry_height;
    uint32_t attempts;
    enum wpr_state state;
    struct uint256 txid;
    int64_t last_attempt_ms;  /* -1 before the first push */
    int64_t due_ms;
    int64_t retry_ms;
    int64_t seen_ms;
    uint32_t tried[WPR_MAX_TRIED];
    uint8_t num_tried;
    uint8_t tried_next;
};

struct wpr {
    zcl_mutex_t lock;
    enum wpr_mode mode;
    struct wpr_env env;
    char datadir[1024];
    struct tx_mempool pool;
    struct wpr_entry entries[WPR_MAX_ENTRIES];
    /* Injection points: tests replace both; production uses the monotonic
     * clock and the kernel CSPRNG. */
    int64_t (*now_ms)(void);
    bool (*random_bytes)(uint8_t *out, size_t n);
};

struct wpr_tick_result {
    struct uint256 expired[WPR_MAX_ENTRIES];
    size_t num_expired;
    size_t pushed;
};

struct wpr_status_entry {
    struct uint256 txid;
    enum wpr_state state;
    uint32_t attempts;
    int64_t seconds_since_attempt;  /* -1 before the first push */
};

struct wpr_status {
    enum wpr_mode mode;
    size_t pending;
    size_t eligible_peers;
    size_t num_entries;
    struct wpr_status_entry entries[WPR_MAX_ENTRIES];
};

void wpr_init(struct wpr *r);
void wpr_free(struct wpr *r);
/* The process-wide relay used by the node. */
struct wpr *wpr_global(void);

void wpr_configure(struct wpr *r, enum wpr_mode mode,
                   const struct wpr_env *env);
enum wpr_mode wpr_get_mode(struct wpr *r);
struct tx_mempool *wpr_pool(struct wpr *r);

const char *wpr_state_name(enum wpr_state state);
const char *wpr_mode_name(enum wpr_mode mode);

/* Eligible means an outbound, handshaked, still-connected onion peer that
 * relays transactions. Inbound Tor peers appear as loopback and never
 * qualify. */
bool wpr_peer_eligible(const struct p2p_node *peer);
size_t wpr_count_eligible_peers(struct connman *cm);

/* Track a transaction already admitted to the private pool. Schedules the
 * first push after a random delay and records it durably. */
struct zcl_result wpr_enqueue(struct wpr *r, const struct transaction *tx);

/* The network offered the transaction back and the node accepted it. */
void wpr_note_seen(struct wpr *r, const struct uint256 *txid);

/* Drop a pending transaction after the wallet rolled it back. */
void wpr_forget(struct wpr *r, const struct uint256 *txid);

/* Read the durable pending set after a restart: admit each wallet
 * transaction to the private pool and schedule it with a fresh delay.
 * Nothing is sent here. */
struct zcl_result wpr_resume(struct wpr *r);

/* Advance the state machine once. Pushes due transactions, clears confirmed
 * ones and reports expired ones for wallet rollback. */
void wpr_tick(struct wpr *r, int tip_height, struct wpr_tick_result *out);

void wpr_status_snapshot(struct wpr *r, struct wpr_status *out);

#endif /* ZCL_WALLET_PRIVATE_RELAY_H */
