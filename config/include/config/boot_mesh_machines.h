/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet view — project every durable pairing with live reachability.
 *
 * `ops mesh machines` answers "what machines are paired with this node, and
 * what is each one doing right now" without dropping a single record: every
 * durable pairing row (active, expired, revoked) appears exactly once, and
 * each active record is probed over the existing mesh status lane
 * (boot_mesh_status.h) with a bounded collective budget. No dial is ever
 * attempted; a peer without a live established v2 session is UNREACHABLE,
 * not reconnected. Nothing is written — the command is a pure read.
 *
 * Reachability is derived, never stored: there is no persistent
 * reachability history to drift from reality. The state enum below is the
 * complete honest vocabulary; `mesh_machine_derive_state` is the single
 * pure function that maps (record state, begin verdict, poll outcome,
 * receipt status) to one of them, so the wire group test drives the exact
 * production mapping without sockets.
 *
 * Bounded everywhere: at most MESH_MACHINES_FLEET_MAX actives are probed
 * (further actives report UNKNOWN with detail "fleet_cap_not_probed" and
 * raise `truncated`), the collective wait never exceeds
 * MESH_MACHINES_COLLECT_BUDGET_MS inside the RPC worker, and the status
 * lane's own 30 s request lifetime bounds each individual probe. The RPC
 * watchdog extends only this method's deadline (RPC_MESH_COLLECT_TIMEOUT_MS)
 * so the collective wait is never killed mid-reply. */

#ifndef ZCL_CONFIG_BOOT_MESH_MACHINES_H
#define ZCL_CONFIG_BOOT_MESH_MACHINES_H

#include "config/boot_mesh_status.h"
#include "services/mesh_pairing_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rpc_table;

/* Probe fan-out cap and the collective wait budget. 8 machines at 50 ms
 * poll rounds fit comfortably inside 12 s even when every peer is offline;
 * the RPC server deadline for this method is RPC_MESH_COLLECT_TIMEOUT_MS
 * (20 s) so the budget always wins the race. */
#define MESH_MACHINES_FLEET_MAX 8u
#define MESH_MACHINES_COLLECT_BUDGET_MS 12000
#define MESH_MACHINES_COLLECT_POLL_MS 50

#define MESH_MACHINE_DETAIL_LEN 96
#define MESH_MACHINE_BLOCKER_LEN 192

enum mesh_machine_state {
    MESH_MACHINE_ONLINE = 0,  /* signed OK receipt inside the budget */
    MESH_MACHINE_REFUSED,     /* signed receipt carrying a named refusal */
    MESH_MACHINE_UNREACHABLE, /* no live v2 session / v2 transport disabled */
    MESH_MACHINE_TIMEOUT,     /* no receipt before budget or request expiry */
    MESH_MACHINE_UNKNOWN,     /* probe could not be honestly classified */
    MESH_MACHINE_EXPIRED,     /* durable record past its expiry, never probed */
    MESH_MACHINE_REVOKED,     /* durable record revoked, never probed */
};

const char *mesh_machine_state_string(enum mesh_machine_state state);

struct mesh_machines_counts {
    int64_t total;
    int64_t online;
    int64_t refused;
    int64_t unreachable;
    int64_t timeout;
    int64_t expired;
    int64_t revoked;
    /* UNKNOWN rows count only into total: an unknown is the absence of an
     * honest verdict, not a verdict. */
};

struct mesh_machine_row {
    struct mesh_pairing_public_view view; /* redacted durable record */
    enum mesh_machine_state state;
    char detail[MESH_MACHINE_DETAIL_LEN]; /* "" or the named cause */
    int capsule_slot; /* ONLINE only: index into the report's capsules, -1 else */
    uint64_t observed_unix;               /* ONLINE only */
    uint8_t responder_noise_fingerprint[32]; /* ONLINE only (zeroed on error) */
};

struct mesh_machines_report {
    bool records_observed; /* false: pairing store unreadable — honest empty */
    char blocker[MESH_MACHINE_BLOCKER_LEN]; /* set iff !records_observed */
    bool truncated;        /* list cap or probe cap left rows out/unprobed */
    int64_t generated_unix;
    struct mesh_machines_counts counts;
    size_t row_count;
    struct mesh_machine_row rows[MESH_PAIRING_LIST_MAX];
    /* Capsule bytes are large (up to 4 KiB each), so only the probed rows
     * can carry one, and only ONLINE rows do. */
    size_t capsule_count;
    size_t capsule_lens[MESH_MACHINES_FLEET_MAX];
    uint8_t capsules[MESH_MACHINES_FLEET_MAX][MESH_STATUS_CAPSULE_MAX];
};

/* Pure state derivation: the single mapping from observations to verdicts.
 * `record_state` is the durable record's state token ("active"/"expired"/
 * "revoked"); expired and revoked records are never probed, so begin/poll
 * are ignored for them. For active records `begin` is the begin verdict
 * (MESH_STATUS_BEGIN_*), `poll` the terminal poll outcome
 * (MESH_STATUS_POLL_PENDING means the collective budget ran out first), and
 * `receipt_status` the receipt's status when poll is OK/REFUSED.
 * detail_out receives "" or a short static cause string (for REFUSED it is
 * the hyphenated receipt status token). Never NULL on return. */
enum mesh_machine_state mesh_machine_derive_state(
    const char *record_state, enum boot_mesh_status_begin_result begin,
    enum boot_mesh_status_poll_state poll,
    enum mesh_status_receipt_status receipt_status, const char **detail_out);

/* Pure probe planning: probes_out[i] is set for the first `probe_cap`
 * "active" records, in record order. truncated_out reports whether more
 * actives exist than the cap allows. Returns the number of probes planned. */
size_t mesh_machines_plan_probes(const char *const *record_states,
                                 size_t count, size_t probe_cap,
                                 bool *probes_out, bool *truncated_out);

/* Pure count rollup over finalized rows. */
void mesh_machines_tally(const struct mesh_machine_row *rows, size_t count,
                         struct mesh_machines_counts *out);

/* Live collection: list every durable pairing, probe up to
 * MESH_MACHINES_FLEET_MAX actives through the status lane, wait
 * collectively for at most MESH_MACHINES_COLLECT_BUDGET_MS, then derive
 * and tally. Runs in the caller's thread (the RPC worker) and touches no
 * network thread. Always returns true with a fully initialized report —
 * an unreadable pairing store yields records_observed=false and a named
 * blocker with zero counts rather than an RPC failure. Returns false only
 * on a NULL out pointer. */
bool boot_mesh_machines_collect(struct mesh_machines_report *out);

/* Registers the mesh_machines RPC method (category "mesh"). */
void boot_mesh_machines_register_rpc(struct rpc_table *table);

#endif /* ZCL_CONFIG_BOOT_MESH_MACHINES_H */
