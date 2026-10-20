/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet ROSTER and its relay gate (ZRC 0012 step 2).
 *
 * WHAT A ROSTER ROW IS. The operator-sealed machine line `fleet admit`
 * already writes (tools/dev/fleet_enrol.h), carried unchanged as the text of a
 * FLEET-scope note whose agent is "fleet-roster". No new row kind, no new
 * codec, no new frame: an older node stores it as the ordinary fleet-private
 * note it is, and never relays it on the public path.
 *
 * A NOTE, NOT A WIKI PAGE, ON PURPOSE. A wiki revision would not expire, but
 * the role catalog (engine/composition/roles.def) lets a worker key post
 * note and not wiki, and test_fleet_roles pins that: a foreign key's wiki is
 * refused here. A note is the kind the manager's key is already allowed to
 * send, so it travels the same paired stream every other fleet post does. The
 * price is the 30 day TTL (FLEET_BOARD_TTL_MAX): the manager writes each line
 * again every 10 days, so one copy is live as long as its node runs and for
 * 20 more days after it stops. After that the roster lapses and the gate is
 * UNARMED again, which is today's pairing-plus-role behaviour, not wider.
 *
 * WHO IS A MEMBER. A board signing key (the DHT online key) is a member when
 * a roster row that verifies under the fleet root names it as the
 * `signer_pubkey` of its receipt. Only a root-sealed line ever adds a key,
 * and only a root-sealed line is ever STORED as a roster row: every ingest
 * path (mesh stream, P2P POST, local publish) verifies it first, so a
 * stranger who may post a note adds nobody and cannot fill the roster page
 * or force a rebuild with junk.
 *
 * ARMING IS EXPLICIT. Nothing is published until the operator starts the
 * manager's node with -fleetrostergate. A box enforces only once sealed roster
 * rows it verified are in its store, so a fleet whose manager never opts in
 * behaves exactly as before this step. Arming (INFO, with the member count)
 * and every way back to UNARMED (WARN: the notes expired, or the box was
 * switched off) are logged once each. -fleetrostergate=0 is the member-side
 * escape hatch: this box stops enforcing and says so.
 *
 * THE GATE has three states, and only one of them changes behaviour today:
 *
 *   UNARMED        this box trusts no fleet root, or no row sealed by it has
 *                  arrived while the root is ACTIVE or never anchored (a
 *                  rotated, revoked or unreadable root is UNVERIFIABLE even
 *                  with no live row). Fleet-scope carriage is exactly what it was
 *                  before this step: paired, current and holding the read
 *                  role. Never "relay to all".
 *   MEMBER /       a root is trusted and at least one sealed row is held:
 *   NOT_MEMBER     fleet-scope posts are served to, pulled from, and
 *                  accepted from roster members only.
 *   UNVERIFIABLE   a root is trusted and its rows cannot be accepted: the
 *                  root is rotated, revoked or its chain state unreadable
 *                  (see anchor rule below), the recorded root is unreadable,
 *                  or the scan could not tell. NO fleet-scope relay at all.
 *
 * ANCHOR RULE. The root's verdict comes from the zid_identities projection
 * through the one mapping boot_endpoint_anchor_from_db. A root that is
 * anchored is bound by the chain: ACTIVE passes, ROTATED and REVOKED
 * refuse. A root that was never anchored is tolerated, so a fleet that has
 * not spent an anchor fee keeps working; a projection that cannot be read
 * refuses. The pure verdict is fleet_root_anchor_refusal (tools/dev), called
 * with require = (state != NOT_ANCHORED). A stricter "require the anchor
 * even before the first anchor" is a policy this step leaves OPEN.
 *
 * PUBLIC SCOPE is never consulted here. */

#ifndef ZCL_CONFIG_BOOT_FLEET_ROSTER_H
#define ZCL_CONFIG_BOOT_FLEET_ROSTER_H

#include "session/fleet_board_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

#define BOOT_FLEET_ROSTER_AGENT "fleet-roster"

enum {
    /* Members one roster holds: the relay-port range the enrolment
     * assigns from, so a fleet cannot enrol more machines than this. */
    BOOT_FLEET_ROSTER_MAX = 64,
    /* Stored roster notes one scan reads. */
    BOOT_FLEET_ROSTER_SCAN_ROWS = 256,
    /* A built roster is reused this long (seconds) unless a roster row
     * arrives; it must stay under one pull interval so a revocation does
     * not wait more than a gossip round on the cache. */
    BOOT_FLEET_ROSTER_TTL_S = 10,
    /* Rows the manager publishes in one pass, under the per-key window. */
    BOOT_FLEET_ROSTER_PUBLISH_PER_PASS = 8,
    BOOT_FLEET_ROSTER_PUBLISH_PERIOD_S = 30,
    /* A roster note lives FLEET_BOARD_TTL_MAX (30 days) and is written again
     * once its newest copy is this old, so a live copy always exists while
     * the manager's node runs, and for 20 more days after it stops. */
    BOOT_FLEET_ROSTER_REPUBLISH_S = 10 * 24 * 3600,
    /* One refusal log line per kind per this many seconds; the rest are
     * counted and reported on the next line. */
    BOOT_FLEET_ROSTER_LOG_WINDOW_S = 60,
};

enum boot_fleet_roster_verdict {
    BOOT_FLEET_ROSTER_UNARMED = 0,
    BOOT_FLEET_ROSTER_MEMBER,
    BOOT_FLEET_ROSTER_NOT_MEMBER,
    BOOT_FLEET_ROSTER_UNVERIFIABLE,
};

/* THE OPT-IN. -fleetrostergate[=1] turns the manager's publishing ON and
 * enforces; -fleetrostergate=0 is the member-side escape hatch: enforcement
 * is off on this box, it is logged, and fleet-scope carriage is exactly
 * pairing plus role again. Without the flag (DEFAULT) nothing is published
 * and a box enforces only once sealed roster rows it verified are in its
 * store, so a fleet whose manager never opts in behaves exactly as before
 * this step. */
enum boot_fleet_roster_gate {
    BOOT_FLEET_ROSTER_GATE_DEFAULT = 0,
    BOOT_FLEET_ROSTER_GATE_ON,
    BOOT_FLEET_ROSTER_GATE_OFF,
};
void boot_fleet_roster_set_gate(enum boot_fleet_roster_gate gate);
enum boot_fleet_roster_gate boot_fleet_roster_gate(void);

/* Is `key` (a board signing key) a member of the roster this node holds? */
enum boot_fleet_roster_verdict boot_fleet_roster_check(
    struct node_db *ndb, const uint8_t key[32], int64_t now);

/* True when `post` is a roster row by shape: a fleet-scope note whose agent
 * is the roster agent. Shape only; the seal decides. */
bool boot_fleet_roster_is_row(const struct fleet_board_post *post);

/* May this node accept `post` into its store? The one question every ingest
 * path asks (mesh stream, P2P POST, local publish), answered with the
 * refusal to use.
 *
 *   public / legacy scope   FLEET_BOARD_OK, always.
 *   a roster row            On a box that trusts a fleet root: FLEET_BOARD_OK
 *                           only when its seal verifies under that root (one
 *                           Ed25519 verify, roster rows only, none when the
 *                           row is already held). Not sealed by it:
 *                           FLEET_BOARD_ERR_SIGNATURE, final, and the row is
 *                           never stored, so junk can neither fill the roster
 *                           page nor flush the cache. Genuinely sealed but
 *                           refused by the root's chain state, or a recorded
 *                           root that cannot be read: FLEET_BOARD_ERR_ROLE,
 *                           which can clear. On a box with NO root: OK, an
 *                           ordinary note, as before this step (it gates
 *                           nothing, and a scan verifies the row if a root
 *                           appears later).
 *   any other fleet post    FLEET_BOARD_OK from a roster member or while
 *                           UNARMED; FLEET_BOARD_ERR_ROLE otherwise, and
 *                           never while the roster is UNVERIFIABLE. */
enum fleet_board_result boot_fleet_roster_screen_post(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now);

/* boot_fleet_roster_screen_post() == FLEET_BOARD_OK. */
bool boot_fleet_roster_admits_post(struct node_db *ndb,
                                   const struct fleet_board_post *post,
                                   int64_t now);

/* May this node serve, or pull from, the peer whose delegation names `key`
 * as its online (board signing) key? UNARMED and MEMBER: yes. NOT_MEMBER and
 * UNVERIFIABLE: no, counted. This is the one question both halves of the
 * paired board stream ask. */
bool boot_fleet_roster_admits_peer(struct node_db *ndb, const uint8_t key[32],
                                   int64_t now);

/* A roster row was stored: drop the cached roster so the next question
 * re-reads it. */
void boot_fleet_roster_invalidate(void);

/* The manager's half: publish every sealed line of this box's own machine
 * roster onto the board as a roster row, if the board does not already hold
 * that exact line. Only the box whose own key IS the fleet root publishes.
 * Returns how many rows were written (at most one pass's worth). */
size_t boot_fleet_roster_publish(struct node_db *ndb, int64_t now);

/* Refusal log lines are rate limited: one per kind per
 * BOOT_FLEET_ROSTER_LOG_WINDOW_S, and the lines that were left out are
 * counted. True when the caller should log now; `*skipped` (optional) then
 * receives how many were left out since the last line. */
enum boot_fleet_roster_log_kind {
    BOOT_FLEET_ROSTER_LOG_POST_DROPPED = 0,
    BOOT_FLEET_ROSTER_LOG_PEER_REFUSED,
    BOOT_FLEET_ROSTER_LOG_DEFERRED,
    BOOT_FLEET_ROSTER_LOG_KINDS
};
bool boot_fleet_roster_log_due(enum boot_fleet_roster_log_kind kind,
                               int64_t now, uint64_t *skipped);

/* Refusals since the process started, for logs and tests. */
struct boot_fleet_roster_counts {
    uint64_t non_member;       /* a peer or post refused as not a member */
    uint64_t unverifiable;     /* refused because the roster could not be trusted */
    uint64_t bad_rows;         /* roster rows whose seal did not verify */
    uint64_t verifies;         /* Ed25519 verifies the roster has run */
    uint64_t rebuilds;         /* cached rosters rebuilt from the store */
    uint64_t armed_events;     /* UNARMED to armed transitions logged */
    uint64_t lapse_events;     /* armed to UNARMED transitions logged */
};
void boot_fleet_roster_counts(struct boot_fleet_roster_counts *out);

#ifdef ZCL_TESTING
/* Forget the cached roster and the counters. */
void boot_fleet_roster_test_reset(void);

/* Make every rebuild take this many extra milliseconds (0 = none). */
void boot_fleet_roster_test_build_delay_ms(int ms);
#endif

#endif /* ZCL_CONFIG_BOOT_FLEET_ROSTER_H */
