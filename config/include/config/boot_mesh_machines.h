/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet view — one surface pairing durable verified evidence with a
 * bounded live probe.
 *
 * `ops mesh machines` answers "what machines are paired with this node, what
 * did each last prove, and what is each doing right now". Two evidence
 * classes, kept distinct in every row:
 *
 *   - Durable: the pairing record plus the latest VERIFIED signed status
 *     receipt persisted in the schema-v77 observation store
 *     (models/mesh_machine_observation.h). Fresh/stale/never-seen is derived
 *     from `now`; a stale receipt is evidence of the past, never a claim of
 *     current reachability. Older or equivocal receipts cannot replace a
 *     row; an exact replay is idempotent.
 *   - Live: a bounded probe fan-out over the existing mesh status lane
 *     (boot_mesh_status.h) — up to MESH_MACHINES_FLEET_MAX actives, one
 *     collective budget of MESH_MACHINES_COLLECT_BUDGET_MS, run inside the
 *     RPC worker thread. Terminal receipts enter the observation store
 *     through boot_mesh_status_receipt_persist, the serialized db_service
 *     writer the single-machine poll and the background refresh scheduler
 *     also use, so every writer funnels into the same store handoff; there
 *     is no parallel verdict-only truth.
 *
 * A current signed endpoint may trigger a bounded direct dial. Endpoint bytes
 * remain untrusted: no request is sent until the live Noise static and current
 * delegation uniquely match the pairing. Offline machines stay listed. Public
 * keys never leave the surface — fingerprints only. The pure mapping from
 * (record state, begin verdict, poll outcome, receipt status) to a verdict
 * is mesh_machine_derive_state, so the wire group test drives the exact
 * production mapping without sockets.
 *
 * Bounds: at most MESH_MACHINES_FLEET_MAX actives are probed (further
 * actives report UNKNOWN "fleet_cap_not_probed" and raise `truncated`), and
 * MESH_MACHINES_FLEET_MAX <= MESH_STATUS_PENDING_MAX is pinned at compile
 * time so a fleet burst can never self-congest the pending table. The
 * rendered row list is bounded at MESH_MACHINES_VIEW_MAX. The RPC watchdog
 * extends only this method's deadline (RPC_MESH_COLLECT_TIMEOUT_MS) so the
 * collective wait is never killed mid-reply. */

#ifndef ZCL_CONFIG_BOOT_MESH_MACHINES_H
#define ZCL_CONFIG_BOOT_MESH_MACHINES_H

#include "config/boot_mesh_status.h"
#include "services/mesh_pairing_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct node_db;
struct db_service;
struct rpc_table;

/* Probe fan-out cap and the collective wait budget. 8 machines at 50 ms
 * poll rounds fit comfortably inside 12 s even when every peer is offline;
 * the RPC server deadline for this method is RPC_MESH_COLLECT_TIMEOUT_MS
 * (20 s) so the budget always wins the race. */
#define MESH_MACHINES_FLEET_MAX 8u
#define MESH_MACHINES_COLLECT_BUDGET_MS 12000
#define MESH_MACHINES_COLLECT_POLL_MS 50

/* Rendered row cap for the durable projection. */
#define MESH_MACHINES_VIEW_MAX 16u

#define MESH_MACHINE_DETAIL_LEN 96
#define MESH_MACHINE_BLOCKER_LEN 192

enum mesh_machine_state {
    MESH_MACHINE_ONLINE = 0,  /* signed OK receipt inside the budget */
    MESH_MACHINE_REFUSED,     /* signed receipt carrying a named refusal */
    MESH_MACHINE_UNREACHABLE, /* no live Noise session / Noise transport disabled */
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

/* One live-probe sidecar row: the verdict from THIS call's probe, matched
 * to the durable row by pairing_id. Identity fields beyond the id are set
 * only for ONLINE rows. */
struct mesh_machine_row {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    bool probed; /* a probe was attempted this call (false for cap overflow) */
    enum mesh_machine_state state;
    char detail[MESH_MACHINE_DETAIL_LEN]; /* "" or the named cause */
    uint64_t observed_unix;                  /* ONLINE only */
    uint8_t responder_noise_fingerprint[32]; /* ONLINE only (zeroed on error) */
};

struct mesh_machines_report {
    bool records_observed; /* false: pairing store unreadable — honest empty */
    char blocker[MESH_MACHINE_BLOCKER_LEN]; /* set iff !records_observed */
    bool truncated;        /* more actives exist than the probe cap allows */
    int64_t generated_unix;
    struct mesh_machines_counts counts;
    size_t row_count;
    struct mesh_machine_row rows[MESH_PAIRING_LIST_MAX];
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

/* Fill a live row's ONLINE identity fields from a verified terminal
 * receipt: observed time and the responder Noise fingerprint. Exported so
 * the wire group test proves the live row and the persisted observation
 * derive from the same verified receipt. Returns false (with a logged
 * cause) when the fingerprint cannot be derived; the row then carries a
 * zeroed fingerprint, never an invented one. */
bool mesh_machines_fill_live_identity(
    struct mesh_machine_row *row, const struct mesh_status_receipt_v1 *receipt);

/* Live refresh: list every durable pairing, probe up to
 * MESH_MACHINES_FLEET_MAX actives through the status lane, persist every
 * verified terminal receipt via boot_mesh_status_receipt_persist on the
 * serialized db_service writer (dbsvc must be non-NULL for persistence;
 * a NULL dbsvc logs once per receipt and the live verdict still stands),
 * wait collectively for at most MESH_MACHINES_COLLECT_BUDGET_MS, then derive
 * and tally. Runs in the caller's thread (the RPC worker) and touches no
 * network thread. Always returns true with a fully initialized report — an
 * unreadable pairing store yields records_observed=false and a named
 * blocker with zero counts. Returns false only on a NULL argument. */
bool boot_mesh_machines_refresh(struct node_db *ndb, struct db_service *dbsvc,
                                struct mesh_machines_report *out);

/* Render the unified fleet document (zcl.mesh.machines.v1): every pairing
 * row from the durable observation projection (fresh/stale/never-seen
 * evidence), with the live sidecar merged by pairing_id when `live` is
 * non-NULL. A NULL live report renders the durable evidence alone — the
 * shape the test hook drives without a network. */
void boot_mesh_machines_render(struct node_db *ndb, int64_t now,
                               const struct mesh_machines_report *live,
                               struct json_value *result);

/* Registers the mesh_machines RPC method (category "mesh"). */
void boot_mesh_machines_register_rpc(struct rpc_table *table);

#endif /* ZCL_CONFIG_BOOT_MESH_MACHINES_H */
