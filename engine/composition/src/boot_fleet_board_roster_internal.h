/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The private contract between the fleet carriage lane
 * (boot_fleet_board_fleet.c) and its roster path
 * (boot_fleet_board_roster.c): carriage between machines the owner sealed
 * onto the fleet roster, with no pairing row. The public description is in
 * config/boot_fleet_board.h. */

#ifndef ZCL_BOOT_FLEET_BOARD_ROSTER_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_ROSTER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct node_db;

/* Which half of a stream a proof speaks for, so an asking proof can never be
 * replayed as an answering one. */
enum fleet_board_roster_side {
    FLEET_BOARD_ROSTER_SIDE_ASK = 1,
    FLEET_BOARD_ROSTER_SIDE_ANSWER = 2,
};

/* Everything one proof is bound to. The transcript and the connection
 * generation name this exact Noise session on both ends, so a proof seen on
 * one session proves nothing on another, and needs no clock. */
struct fleet_board_roster_bind {
    uint8_t network_genesis[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    int64_t after;
};

/* Sign `out` (FLEET_BOARD_ROSTER_PROOF_BYTES: the board signing key, then its
 * signature) with this node's own board identity. */
bool fleet_board_roster_proof_make(enum fleet_board_roster_side side,
                                   const struct fleet_board_roster_bind *bind,
                                   uint8_t *out);
bool fleet_board_roster_proof_check(enum fleet_board_roster_side side,
                                    const struct fleet_board_roster_bind *bind,
                                    const uint8_t *proof);

/* The answering half: does this session's peer still stand on the roster?
 * False for a peer with any pairing row (the pairing path decides for it, a
 * revoked row included), an unreadable pairing list, or anything but a MEMBER
 * verdict for `key`. Never verifies a signature. Refusals are counted. */
bool fleet_board_roster_standing(struct node_db *pairings,
                                 struct node_db *store,
                                 const uint8_t peer_noise[32],
                                 const uint8_t key[32], int64_t now);

/* The answering half at OPEN: standing, then the asking proof. */
bool fleet_board_roster_admit(struct node_db *pairings, struct node_db *store,
                              const struct fleet_board_roster_bind *bind,
                              const uint8_t peer_noise[32],
                              const uint8_t *proof, int64_t now);

/* The asking half, on this lane's tick: judge the answering proof at the head
 * of `rows`, and strip it so what remains is a plain answer. `*roster_only`
 * is true while this box holds no armed roster of its own: only sealed roster
 * rows are then taken from the answer, which is how a member first arms. */
bool fleet_board_roster_answer_open(struct node_db *ndb,
                                    const struct fleet_board_roster_bind *bind,
                                    uint8_t *rows, size_t *len, int64_t now,
                                    bool *roster_only);

/* Remember the peer of a session that proved a member key to this box, so the
 * pull goes back over the session it dialled (a box behind NAT has no onion
 * to be dialled at). Bounded; the oldest entry goes first. */
void fleet_board_roster_learn(const uint8_t peer_noise[32],
                              const uint8_t key[32]);
void fleet_board_roster_forget(void);

/* The Noise statics this lane may send a roster pull to right now: the
 * established session whose address is a sealed roster line's onion, or one
 * that already proved a member key here. Never any other peer, and none at
 * all without a fleet root, or with a gate switched off or a root the chain
 * refuses. A peer with a pairing row stays on the pairing lane. */
size_t fleet_board_roster_targets(struct boot_svc_ctx *svc,
                                  struct node_db *pairings,
                                  struct node_db *store, int64_t now,
                                  uint8_t (*out)[32], size_t cap);

uint64_t fleet_board_roster_refused_count(void);

#endif /* ZCL_BOOT_FLEET_BOARD_ROSTER_INTERNAL_H */
