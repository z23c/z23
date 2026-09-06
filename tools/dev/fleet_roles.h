/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet ROLES — the closed role/grant catalog from
 * engine/composition/roles.def, and the local signed grant/revoke store
 * that binds a key's fingerprint to a role on THIS node.
 *
 * Every enrolled key could call every leaf before this file existed. Now a
 * leaf that accepts a signed request from a key other than this node's own
 * checks that key's fingerprint against this store: an unknown key, or a
 * key with no active grant naming the leaf, is refused before the leaf
 * runs. Local, unsigned CLI use by this node's own operator key is
 * unaffected — that key holds `role_operator` implicitly and is never
 * looked up here.
 *
 * The store is one signed chainlog per node, under
 * `<datadir>/fleet_roles/roles.chain`. Only this node's own operator key
 * ever writes to it (a grant or a revoke is always self-signed by the
 * granting node), so resolving a role never trusts a remote statement:
 * "who this box trusts" is this box's own decision, never a fact carried
 * in from elsewhere. That is the same doctrine the fleet ledger already
 * follows — no central referee, every node decides whom it trusts. */

#ifndef ZCL_FLEET_ROLES_H
#define ZCL_FLEET_ROLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_ROLE_FP_BYTES  32u
#define ZCL_ROLE_SEED_BYTES 32u
#define ZCL_ROLE_SIG_BYTES 64u
#define ZCL_ROLE_LEAF_MAX  96u

/* ── catalog (engine/composition/roles.def) ─────────────────────────── */

enum zcl_role_id {
    ZCL_ROLE_OPERATOR = 1,
#define Z23_ROLE(role_, why_) ZCL_ROLE_CAT2(ZCL_ROLE_, role_),
#define ZCL_ROLE_CAT2(a_, b_) ZCL_ROLE_CAT(a_, b_)
#define ZCL_ROLE_CAT(a_, b_) a_##b_
#include "../../engine/composition/roles.def"
#undef Z23_ROLE
#undef ZCL_ROLE_CAT2
#undef ZCL_ROLE_CAT
    ZCL_ROLE_ID_COUNT_MARKER
};

/* `operator` occupies value 1 above; the .def-declared roles start at 2 and
 * upward in declaration order, so ZCL_ROLE_OPERATOR is always distinct from
 * every catalog role even though it is never itself declared in the .def. */

const char *zcl_role_name(uint8_t role);
bool zcl_role_from_name(const char *name, uint8_t *role_out);
size_t zcl_role_count(void); /* catalog roles only; excludes operator */
const char *zcl_role_at(size_t index);

/* True when `role` (which must not be ZCL_ROLE_OPERATOR — that role is
 * checked by identity, never by a grant lookup) is granted `leaf`, and
 * `kind` (NULL when the leaf carries no board kind) is inside the grant's
 * kind list. */
bool zcl_role_leaf_allowed(uint8_t role, const char *leaf, const char *kind);

/* SHA3-256("zcl.fleet_role_fingerprint.v1" || pubkey), so a fingerprint
 * here can never collide with a hash minted for another purpose. */
void zcl_role_fingerprint(const uint8_t pubkey[32],
                          uint8_t out[ZCL_ROLE_FP_BYTES]);
/* First 4 bytes of a fingerprint, as 8 lowercase hex characters, for a
 * refusal message a person reads. */
void zcl_role_fingerprint_short(const uint8_t fp[ZCL_ROLE_FP_BYTES],
                                char out[9]);

/* ── store ───────────────────────────────────────────────────────────── */

enum zcl_role_status {
    ZCL_ROLE_OK = 0,
    ZCL_ROLE_ARGUMENT,     /* a NULL, or a field over its bound */
    ZCL_ROLE_IO,           /* the file system, or the chainlog, said no */
    ZCL_ROLE_MALFORMED,    /* stored bytes are not a row of this version */
    ZCL_ROLE_SIG_INVALID,  /* a row's signature does not verify */
    ZCL_ROLE_UNKNOWN_ROLE, /* a role id outside the closed catalog */
    ZCL_ROLE_NOT_GRANTED,  /* the fingerprint holds no active grant of it */
    ZCL_ROLE_FULL          /* the in-memory grant table has no free slot */
};

const char *zcl_role_status_label(enum zcl_role_status s);

struct zcl_role_entry {
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    uint8_t role;
    bool active;         /* granted and not since revoked */
    int64_t changed_at;  /* ts of the row that set this state */
};

struct zcl_role_report {
    enum zcl_role_status status;
    uint64_t rows;
};

struct zcl_role_store;

/* Opens (creating if absent) `<datadir>/fleet_roles/roles.chain` and folds
 * every row in chain order into the in-memory grant table. A row whose own
 * signature fails to verify refuses the whole open — a role store that
 * silently dropped one tampered row could not be trusted for the rows
 * around it either. */
struct zcl_role_store *zcl_role_store_open(const char *datadir,
                                           struct zcl_role_report *report);
void zcl_role_store_close(struct zcl_role_store *store);

/* Appends a grant or revoke row, signed by (seed, operator_pub) — this
 * node's own operator identity. `role` must be a catalog role, never
 * ZCL_ROLE_OPERATOR: that role is not something a row can name. */
enum zcl_role_status zcl_role_store_grant(
    struct zcl_role_store *store, const uint8_t target_fp[ZCL_ROLE_FP_BYTES],
    uint8_t role, const uint8_t operator_pub[32], const uint8_t seed[32],
    int64_t now, uint64_t *out_seq);
enum zcl_role_status zcl_role_store_revoke(
    struct zcl_role_store *store, const uint8_t target_fp[ZCL_ROLE_FP_BYTES],
    uint8_t role, const uint8_t operator_pub[32], const uint8_t seed[32],
    int64_t now, uint64_t *out_seq);

bool zcl_role_store_has_role(const struct zcl_role_store *store,
                             const uint8_t fp[ZCL_ROLE_FP_BYTES],
                             uint8_t role);

/* Every (fingerprint, role) pair the store has ever seen, active or not,
 * newest state per pair. Returns the count written, capped at `cap`. */
size_t zcl_role_store_list(const struct zcl_role_store *store,
                           struct zcl_role_entry *out, size_t cap);

/* The one choke-point call: does `fp` (NULL means "this node's own
 * operator key", which always passes) hold a role granting `leaf`/`kind`?
 * On refusal, `why` (when non-NULL, at least 96 bytes) is filled with the
 * exact typed message the caller should print or reply with. */
bool zcl_role_check(const struct zcl_role_store *store,
                    const uint8_t fp[ZCL_ROLE_FP_BYTES], bool is_operator,
                    const char *leaf, const char *kind, char *why,
                    size_t why_cap);

#endif /* ZCL_FLEET_ROLES_H */
