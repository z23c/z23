/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "board" stream lane's authority questions
 * (boot_fleet_board_authority.c), shared by the answering and asking halves
 * (boot_fleet_board_fleet.c) and the push (boot_fleet_board_push.c), so each
 * asks exactly the same thing. */

#ifndef ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H

#include "config/boot_fleet_board.h"

#include <stdbool.h>
#include <stddef.h>
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
/* The disclosure decision judges at most this many pairing rows for one
 * Noise static: the newest that grant the status capability now (the push's
 * receiving half proves at most as many board keys, PUSH_PUSHER_KEYS_MAX). */
#define FLEET_BOARD_DISCLOSURE_ROWS_MAX 4u
/* The peer's delegation is still current on chain; refusals are counted. */
bool board_delegation_current(struct node_db *ndb,
                              const struct db_mesh_pairing *row,
                              const struct vcs_zcode_dht_delegation *peer,
                              const uint8_t session_noise_static[32],
                              int64_t now);
/* The key holds a role granting FLEET_BOARD_FLEET_READ_LEAF here; refusals
 * are counted. */
bool board_peer_may_read(const uint8_t signer[32]);
/* The same question with nothing counted or logged (the push's sending
 * half). */
bool board_push_may_read(const uint8_t signer[32]);
/* The fleet roster admits this board key here. */
bool board_roster_admits(const uint8_t online_pubkey[32]);
/* Everything the answering half proves before it reads a post for a peer:
 * one of the newest pairing rows for its Noise static that grant the status
 * capability now (at most FLEET_BOARD_DISCLOSURE_ROWS_MAX) passes on its own
 * a current delegation bound to this session, the read role and the roster.
 * A refused decision is counted and logged once. */
bool board_accept_authorized(const uint8_t peer_noise_static[32]);
/* The push's sending half: the very decision board_accept_authorized makes
 * for a pull from this Noise static (same function, same rows, same clock),
 * with nothing counted or logged. Returns FLEET_BOARD_PUSH_REFUSALS when a
 * pull would be served, with the board key the newest serving row's
 * delegation proves in `online_out` (may be NULL), else the check the newest
 * row refused on (PAIRING when no row grants the capability now). */
enum fleet_board_push_refusal board_push_disclosure(
    const uint8_t peer_noise_static[32], uint8_t online_out[32]);
/* The push's receiving half, which counts and logs nothing (the push names
 * its own refusals). judge_peer: on one pairing row, the status capability,
 * a delegation that resolves and is current on that row's Noise static, and
 * the roster: the checks the asking half (board_peer_due in
 * boot_fleet_board_fleet.c) makes on any row before this box pulls from that
 * peer. The read role is not asked: it governs what this box discloses, and
 * a pusher is disclosed nothing. Returns FLEET_BOARD_PUSH_REFUSALS when every
 * check passes, with the peer's board key in `online_out` (may be NULL),
 * else the check that failed. pusher_keys: the board keys of every row for
 * `peer_noise_static` that grants the status capability now and passes,
 * newest first, distinct, at most `cap`; when none, `why` names the check
 * the newest allowing row failed, PAIRING when no row allows. */
enum fleet_board_push_refusal board_push_judge_peer(
    const struct db_mesh_pairing *row, int64_t now, uint8_t online_out[32]);
size_t board_push_pusher_keys(struct node_db *ndb,
                              const uint8_t peer_noise_static[32], int64_t now,
                              uint8_t (*keys)[32], size_t cap,
                              enum fleet_board_push_refusal *why);
/* Fill delegation_refused and role_refused. */
void board_authority_counts(struct boot_fleet_board_fleet_counts *out);

#endif /* ZCL_BOOT_FLEET_BOARD_AUTHORITY_INTERNAL_H */
