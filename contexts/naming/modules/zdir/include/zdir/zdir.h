/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDIR — the on-chain relay/node directory overlay.
 *
 * A node publishes ONE fact on-chain: "this v3 onion hostname is a node, and
 * this t-address paid for saying so." Everything that churns — clearnet
 * endpoints, bandwidth, liveness — stays off-chain in signed gossip
 * (vcs/zdesc_swarm.h, core/modules/net addr gossip). The chain is a land registry, not
 * a message bus (docs/spec/sovereign-identity-layer.md §A3).
 *
 * WHY THIS EXISTS. The previous "chain scan" for onion peers
 * (blog_discover_onion_peers) read db_wallet_tx_recent_raw() — the LOCAL
 * WALLET table — and recovered a hostname by parsing a zero-token_id ZSLP SEND
 * and skipping push fields until something ended in ".onion". A node with an
 * empty wallet discovered nothing, and no node could ever see another node's
 * announcement. That is a scrape of your own wallet, not a protocol. ZDIR is
 * the protocol: a lokad-tagged OP_RETURN any node folds out of block history
 * into a rebuildable projection (contexts/naming/models/src/explorer_index_zdir.c).
 *
 * WHAT A ZDIR RECORD IS NOT. It is a HINT ABOUT WHERE TO LOOK, never proof of
 * who is there (docs/work/NAT_AND_ONION_TRANSPORT.md). A poisoned or squatted
 * record can only ever waste one connection attempt: the directory is an
 * ADDITIONAL source merged alongside DNS seeds, fixed seeds, addrman and the
 * signed-descriptor source (net/onion_peer_merge.h), and it has no path to
 * exclude a peer. Reputation weighting, if ever wired, is bounded to a
 * [1.0, 4.0] dial-chance multiplier (addrman_publish_reputation_weights).
 *
 * Lokad ID: "ZDIR". OP_RETURN payload (PUSH fields after 0x6a):
 *   [PUSH "ZDIR"     (4)]   lokad id
 *   [PUSH version    (1)]   = ZDIR_VERSION (1)
 *   [PUSH command    (1)]   1=REGISTER, 2=DEREGISTER
 *   [PUSH hostname  (62)]   the v3 onion hostname, exact — 56 base32 + ".onion"
 *   [PUSH pubkey (0|32)]    optional ed25519 master key binding this hostname
 *                           to a zid identity; empty push = unbound. MUST be
 *                           empty on DEREGISTER.
 * No trailing bytes are permitted. Maximum encoded size is 106 bytes, well
 * inside MAX_OP_RETURN_RELAY (223).
 *
 * Command byte 3 is RESERVED for TRANSFER (spec §A3) and is deliberately NOT
 * defined in this version: transferring a relay record is expressible today as
 * DEREGISTER by the current owner followed by REGISTER from the new one, and a
 * parsed-but-unhandled command would be a silent stub. zdir_parse REJECTS it.
 *
 * BOTH HALVES ARE NOW WIRED. The read half was always here: zdir_parse +
 * contexts/naming/models/src/explorer_index_zdir.c fold any ZDIR OP_RETURN already in
 * block history into the onion_directory projection, and
 * blog_discover_onion_peers_chain dials from it.
 *
 * The write half is contexts/naming/controllers/src/zdir_controller.c (the zdir_register
 * / zdir_deregister RPCs) and tools/command/native_zdir_command.c (`core zdir
 * register` / `core zdir deregister`). They compose a transaction carrying
 * the record, sign it and broadcast it through the node's wallet; with no
 * wallet loaded, or no node running, they hand the operator op_return_hex to
 * include themselves. Ownership on a mutation is the tx's SOLE input, built
 * through zslp_command_build_owner_base_tx so the signer is provably the
 * owner explorer_index_apply_zdir_overlay recorded.
 *
 * It is an OPERATOR SURFACE, not an announcer. Nothing calls it from boot,
 * from a timer, or from any background service, and there is no re-announce
 * cadence: publishing spends a real UTXO, so it stays an explicit decision.
 * register_zdir_rpc_commands has exactly one caller (engine/composition/src/
 * boot_services.c) and that call only registers the verbs.
 *
 * The unsigned wallet scrape beside it (net/onion_peer_merge.h) is still
 * wired, and still not dead weight: the chain source only contributes what
 * nodes have actually published, which on a young network is nothing yet.
 *
 * Pure: no clock, no RNG, no I/O, no alloc. */

#ifndef ZCL_ZDIR_H
#define ZCL_ZDIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZDIR_LOKAD_BYTES "ZDIR"
#define ZDIR_VERSION     1

#define ZDIR_CMD_INVALID     0
#define ZDIR_CMD_REGISTER    1
#define ZDIR_CMD_DEREGISTER  2

/* A Tor v3 onion hostname is exactly 56 base32 chars + ".onion". */
#define ZDIR_HOSTNAME_LEN 62
#define ZDIR_PUBKEY_LEN   32

/* Largest well-formed ZDIR script: see the grammar above. */
#define ZDIR_SCRIPT_MAX 106

struct zdir_message {
    uint8_t version;
    uint8_t command;                        /* ZDIR_CMD_* (never INVALID) */
    char    hostname[ZDIR_HOSTNAME_LEN + 1];/* NUL-terminated */
    bool    has_pubkey;
    uint8_t pubkey[ZDIR_PUBKEY_LEN];        /* valid iff has_pubkey */
};

/* True iff c is a defined, handled command byte. */
bool zdir_command_valid(uint8_t c);

/* Human name for a command byte ("register"/"deregister"/"unknown"). */
const char *zdir_command_name(uint8_t c);

/* Parse an OP_RETURN script into a ZDIR message. Strict: the lokad, the
 * version, the command byte, the exact hostname length AND the v3 onion
 * hostname rule (onion_hostname_valid, net/onion_peer_merge.h — the ONE copy
 * of that rule the node has), the 0-or-32-byte pubkey push, an all-zero
 * pubkey, a pubkey on DEREGISTER, and any trailing bytes all reject. Returns
 * true only on a fully well-formed record. */
bool zdir_parse(const uint8_t *script, size_t script_len,
                struct zdir_message *msg);

/* Build a REGISTER script into out. `hostname` must pass the v3 onion rule;
 * `pubkey` may be NULL (unbound) and must be non-zero when present. Returns
 * bytes written, or 0 on invalid input, an undersized buffer, or a script that
 * would exceed MAX_OP_RETURN_RELAY. */
size_t zdir_build_register(uint8_t *out, size_t out_len, const char *hostname,
                           const uint8_t pubkey[ZDIR_PUBKEY_LEN]);

/* Build a DEREGISTER script into out. Same rules; never carries a pubkey. */
size_t zdir_build_deregister(uint8_t *out, size_t out_len,
                             const char *hostname);

#endif /* ZCL_ZDIR_H */
