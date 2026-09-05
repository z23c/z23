/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixture for the mesh terminal lane's test groups: one responder
 * Noise static serving two independently paired peers (one status-read
 * only, one carrying the commit-time terminal-exec capability) over real
 * in-process Noise transports driven buffer-to-buffer, a real node.db
 * seeded with the connected chain rows the pairing verifier demands, and
 * the delegation/ZID/key material both sides need. Test-only: nothing in
 * production includes this header.
 */

#ifndef ZCL_TEST_MESH_TERM_FIXTURE_H
#define ZCL_TEST_MESH_TERM_FIXTURE_H

#include "session/mesh_terminal_proto.h"

#include "models/database.h"
#include "models/mesh_pairing.h"
#include "net/noise_transport.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mesh_term_peer {
    struct vcs_zcode_dht_delegation delegation;
    uint8_t noise_pub[32];
    struct noise_transport *ini;
    struct noise_transport_snapshot res_snap; /* responder-side session */
    struct db_mesh_pairing pairing;
};

struct mesh_term_fixture {
    struct node_db ndb;
    uint8_t genesis[32];
    uint8_t resp_master_pub[32];
    uint8_t resp_online_seed[32];
    uint8_t resp_online_pub[32];
    uint8_t resp_noise_pub[32];
    struct noise_transport *res_status; /* status peer's responder side */
    struct noise_transport *res_term;   /* terminal peer's responder side */
    struct mesh_term_peer status_peer; /* pairing: STATUS_READ only */
    struct mesh_term_peer term_peer;   /* pairing: STATUS_READ|TERMINAL_EXEC */
};

/* Opens the full fixture (identities, handshakes, node.db, chain rows,
 * delegations, ZID projections, responder keypairs). */
bool mesh_term_fixture_open(struct mesh_term_fixture *f, const char *dir);
void mesh_term_fixture_close(struct mesh_term_fixture *f);

/* The open as a legitimate requester composes it: bound to the live
 * session snapshot and the peer's own delegation identity. */
void mesh_term_compose_open(const struct mesh_term_fixture *f,
                            const struct mesh_term_peer *peer,
                            const uint8_t pairing_id[32], uint64_t issued,
                            uint64_t expires, uint64_t capability,
                            struct mesh_terminal_open_v1 *out);

/* Files a pairing row for this peer with the given capability mask,
 * answering inside [2000, 3000]. */
bool mesh_term_pair_accept(struct mesh_term_fixture *f,
                           struct mesh_term_peer *peer,
                           uint64_t capability_mask);

/* Files the pairing row the accept ceremony would leave, over a
 * caller-chosen validity window — for the lanes that read the row on the
 * real clock rather than on the fixture's fixed one. */
bool mesh_term_pair_row(struct mesh_term_fixture *f,
                        struct mesh_term_peer *peer, uint64_t capability_mask,
                        int64_t paired_at, int64_t expires_at);

/* Seal frame bytes on `from` and deliver them to `to`; plaintext must
 * equal the input byte-for-byte with no wire reply. */
bool mesh_term_frame_roundtrip(struct noise_transport *from,
                               struct noise_transport *to,
                               const uint8_t *frame, size_t frame_len,
                               uint8_t *delivered, size_t delivered_cap);

/* NUL-terminate capsule bytes so plain strstr can pin exact rendered JSON
 * members without a JSON parser or GNU memmem. */
bool mesh_term_capsule_text(const uint8_t *capsule, size_t capsule_len,
                            char *text, size_t text_cap);

void mesh_term_fill32(uint8_t out[32], uint8_t value);

#endif /* ZCL_TEST_MESH_TERM_FIXTURE_H */
