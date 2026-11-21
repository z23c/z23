/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "board" stream lane's authority questions
 * (boot_fleet_board_authority.c), shared by the answering and asking halves
 * (boot_fleet_board_fleet.c) and the push (boot_fleet_board_push.c), so each
 * asks exactly the same thing. */

#ifndef ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H

#include "config/boot_fleet_board.h"

#include <stdbool.h>
#include <stdint.h>

struct db_mesh_pairing;
struct node_db;
struct vcs_zcode_dht_delegation;

/* The board store this box serves from and commits into, or NULL
 * (boot_fleet_board_fleet.c). */
struct node_db *board_db(void);
/* The lane's clock, in Unix seconds. */
int64_t board_now(void);
/* The network genesis every pairing and roster proof is bound to. */
bool board_network_genesis(uint8_t out[32]);
/* The paired peer's delegation, as the lane resolves it. */
bool board_peer_delegation(const struct db_mesh_pairing *row,
                           struct vcs_zcode_dht_delegation *out);
/* The pairing row for one Noise static, from a bounded read. */
bool board_pairing_for_peer(struct node_db *ndb,
                            const uint8_t peer_noise_static[32],
                            struct db_mesh_pairing *out);
/* The peer's delegation is still current on chain; refusals are counted. */
bool board_delegation_current(struct node_db *ndb,
                              const struct db_mesh_pairing *row,
                              const struct vcs_zcode_dht_delegation *peer,
                              const uint8_t session_noise_static[32],
                              int64_t now);
/* The key holds a role granting FLEET_BOARD_FLEET_READ_LEAF here; refusals
 * are counted. */
bool board_peer_may_read(const uint8_t signer[32]);
/* The fleet roster admits this board key here. */
bool board_roster_admits(const uint8_t online_pubkey[32]);
/* Everything the answering half proves before it reads a post for a peer:
 * a pairing row, a current delegation, the read role and the roster. */
bool board_accept_authorized(const uint8_t peer_noise_static[32]);
/* Fill delegation_refused and role_refused. */
void board_authority_counts(struct boot_fleet_board_fleet_counts *out);

#endif /* ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H */
