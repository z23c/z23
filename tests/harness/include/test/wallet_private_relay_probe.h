/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Hook from the Sapling shielded-send test into the private-relay group. */

#ifndef ZCL_TEST_WALLET_PRIVATE_RELAY_PROBE_H
#define ZCL_TEST_WALLET_PRIVATE_RELAY_PROBE_H

struct simnet;
struct transaction;
struct rpc_table;
struct node_db;
struct key_id;
struct script;
struct tx_mempool;
struct main_state;
struct coins_view_cache;
struct wallet;
struct wallet_sqlite;

/* Take one fully proved and verified shielded transaction through the
 * private pool, a delayed push to one onion peer, and acceptance by a second
 * node's message processor. Returns the number of failed checks. */
int wallet_private_relay_shielded_probe(struct simnet *s,
                                        struct transaction *tx);

/* The real wallet state a shielded send runs against. */
struct wallet_private_relay_leg {
    struct rpc_table *tbl;
    struct wallet *wallet;
    struct wallet_sqlite *wsql;
    struct node_db *ndb;
    struct coins_view_cache *coins_tip;
    struct main_state *ms;
    struct tx_mempool *main_pool;
    const struct key_id *funding_kid;
    const struct script *funding_script;
    const char *from_addr;
    const char *zaddr;
    const char *datadir;
    int funding_height;
};

/* Send a second shielded payment through the real wallet RPC in private
 * mode: private pool, delayed push to one onion peer, no clearnet bytes,
 * acceptance by a second node. Returns the number of failed checks. */
int wallet_private_relay_gate_leg(const struct wallet_private_relay_leg *l);

#endif
