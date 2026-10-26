/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet refresh — list durable pairings, probe actives over the
 * mesh status lane, persist every verified terminal receipt into the
 * observation store, derive honest per-machine live verdicts.
 *
 * The pure half (derive/plan/tally/fill) is exported from the header so the
 * wire group test drives the exact production mapping without sockets; the
 * live half (boot_mesh_machines_refresh) is the only function that touches
 * the pairing store or the status lane. It may request a bounded direct route
 * from a current signed endpoint, but the route grants no status authority.
 * Receipt persistence goes through boot_mesh_status_receipt_persist — the
 * serialized db_service writer the single-machine poll and the background
 * refresh scheduler share — so the fleet refresh is a writer of the one
 * observation store, not a parallel truth. */

#include "config/boot_mesh_machines.h"

#include "config/runtime.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define MESH_MACHINES_TAG "net.mesh_machines"

const char *mesh_machine_state_string(enum mesh_machine_state state)
{
    switch (state) {
    case MESH_MACHINE_ONLINE: return "online";
    case MESH_MACHINE_REFUSED: return "refused";
    case MESH_MACHINE_UNREACHABLE: return "unreachable";
    case MESH_MACHINE_TIMEOUT: return "timeout";
    case MESH_MACHINE_UNKNOWN: return "unknown";
    case MESH_MACHINE_EXPIRED: return "expired";
    case MESH_MACHINE_REVOKED: return "revoked";
    }
    return "unknown";
}

/* How a listed pairing record state classifies for verdict derivation. */
enum mesh_machine_record_class {
    MESH_MACHINE_RECORD_ACTIVE,
    MESH_MACHINE_RECORD_EXPIRED,
    MESH_MACHINE_RECORD_REVOKED,
    MESH_MACHINE_RECORD_UNRECOGNIZED
};

/* Classify the record state as the store listed it; the checks keep the
 * order the refresh observed the records in. */
static enum mesh_machine_record_class mesh_machine_classify_record_state(
    const char *record_state)
{
    if (record_state && strcmp(record_state, "expired") == 0)
        return MESH_MACHINE_RECORD_EXPIRED;
    if (record_state && strcmp(record_state, "revoked") == 0)
        return MESH_MACHINE_RECORD_REVOKED;
    if (!record_state || strcmp(record_state, "active") != 0)
        return MESH_MACHINE_RECORD_UNRECOGNIZED;
    return MESH_MACHINE_RECORD_ACTIVE;
}

/* Map a begin result onto the machine state and detail its fresher truth
 * dictates; codes not listed keep the default pair preset below. */
static void mesh_machine_verdict_from_begin(
    enum boot_mesh_status_begin_result begin,
    enum mesh_machine_state *state_out, const char **detail_out)
{
    static const struct {
        enum boot_mesh_status_begin_result begin;
        enum mesh_machine_state state;
        const char *detail;
    } verdicts[] = {
        { MESH_STATUS_BEGIN_PEER_NOT_CONNECTED, MESH_MACHINE_UNREACHABLE,
          "no_live_noise_session" },
        { MESH_STATUS_BEGIN_ROUTE_PENDING, MESH_MACHINE_TIMEOUT,
          "route_acquisition_pending" },
        { MESH_STATUS_BEGIN_ROUTE_IDENTITY_MISMATCH, MESH_MACHINE_REFUSED,
          "route-identity-mismatch" },
        { MESH_STATUS_BEGIN_ROUTE_DOWNGRADE, MESH_MACHINE_REFUSED,
          "route-plaintext-downgrade" },
        { MESH_STATUS_BEGIN_NOISE_DISABLED, MESH_MACHINE_UNREACHABLE,
          "noise_transport_disabled" },
        { MESH_STATUS_BEGIN_REVOKED, MESH_MACHINE_REVOKED,
          "record_revoked_before_probe" },
        { MESH_STATUS_BEGIN_EXPIRED, MESH_MACHINE_EXPIRED,
          "record_expired_before_probe" },
        { MESH_STATUS_BEGIN_NOT_PAIRED, MESH_MACHINE_UNKNOWN,
          "record_vanished_before_probe" },
        { MESH_STATUS_BEGIN_BUSY, MESH_MACHINE_UNKNOWN,
          "pending_table_full" },
        { MESH_STATUS_BEGIN_SEND_FAILED, MESH_MACHINE_UNKNOWN,
          "send_failed" },
        { MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE, MESH_MACHINE_UNKNOWN,
          "local_identity_unavailable" },
        /* The peer IS connected (a live session exists), but it has no
         * unique active ZID delegation bound to that session — an
         * authority gap, not a transport gap, so not UNREACHABLE. */
        { MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE, MESH_MACHINE_UNKNOWN,
          "peer_identity_unavailable" }
    };
    *state_out = MESH_MACHINE_UNKNOWN;
    *detail_out = "status_lane_unavailable";
    for (size_t i = 0; i < sizeof(verdicts) / sizeof(verdicts[0]); i++) {
        if (verdicts[i].begin == begin) {
            *state_out = verdicts[i].state;
            *detail_out = verdicts[i].detail;
            return;
        }
    }
}

/* Map a collected poll state onto the machine state and detail it earned. */
static void mesh_machine_verdict_from_poll(
    enum boot_mesh_status_poll_state poll,
    enum mesh_status_receipt_status receipt_status,
    enum mesh_machine_state *state_out, const char **detail_out)
{
    switch (poll) {
    case MESH_STATUS_POLL_OK:
        *state_out = MESH_MACHINE_ONLINE;
        break;
    case MESH_STATUS_POLL_REFUSED:
        *state_out = MESH_MACHINE_REFUSED;
        *detail_out = mesh_status_receipt_status_string(receipt_status);
        break;
    case MESH_STATUS_POLL_EXPIRED:
        *state_out = MESH_MACHINE_TIMEOUT;
        *detail_out = "request_expired_unanswered";
        break;
    case MESH_STATUS_POLL_PENDING:
        *state_out = MESH_MACHINE_TIMEOUT;
        *detail_out = "collect_budget_exhausted";
        break;
    default:
        *detail_out = "request_lost";
        break;
    }
}

enum mesh_machine_state mesh_machine_derive_state(
    const char *record_state, enum boot_mesh_status_begin_result begin,
    enum boot_mesh_status_poll_state poll,
    enum mesh_status_receipt_status receipt_status, const char **detail_out)
{
    const char *detail = "";
    enum mesh_machine_state state = MESH_MACHINE_UNKNOWN;
    enum mesh_machine_record_class record =
        mesh_machine_classify_record_state(record_state);

    if (record == MESH_MACHINE_RECORD_EXPIRED) {
        state = MESH_MACHINE_EXPIRED;
    } else if (record == MESH_MACHINE_RECORD_REVOKED) {
        state = MESH_MACHINE_REVOKED;
    } else if (record == MESH_MACHINE_RECORD_UNRECOGNIZED) {
        detail = "unrecognized_record_state";
    } else if (begin != MESH_STATUS_BEGIN_OK) {
        /* Begin re-checks the pairing record live, so a verdict that
         * contradicts the just-listed record state is reported as that
         * fresher truth rather than masked. */
        mesh_machine_verdict_from_begin(begin, &state, &detail);
    } else {
        mesh_machine_verdict_from_poll(poll, receipt_status, &state,
                                       &detail);
    }
    if (detail_out)
        *detail_out = detail;
    return state;
}

size_t mesh_machines_plan_probes(const char *const *record_states,
                                 size_t count, size_t probe_cap,
                                 bool *probes_out, bool *truncated_out)
{
    if (!record_states || !probes_out || !truncated_out)
        return 0;
    memset(probes_out, 0, count * sizeof(bool));
    *truncated_out = false;
    size_t planned = 0;
    for (size_t i = 0; i < count; i++) {
        if (!record_states[i] || strcmp(record_states[i], "active") != 0)
            continue;
        if (planned < probe_cap) {
            probes_out[i] = true;
            planned++;
        } else {
            *truncated_out = true;
        }
    }
    return planned;
}

void mesh_machines_tally(const struct mesh_machine_row *rows, size_t count,
                         struct mesh_machines_counts *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!rows)
        return;
    out->total = (int64_t)count;
    for (size_t i = 0; i < count; i++) {
        switch (rows[i].state) {
        case MESH_MACHINE_ONLINE: out->online++; break;
        case MESH_MACHINE_REFUSED: out->refused++; break;
        case MESH_MACHINE_UNREACHABLE: out->unreachable++; break;
        case MESH_MACHINE_TIMEOUT: out->timeout++; break;
        case MESH_MACHINE_EXPIRED: out->expired++; break;
        case MESH_MACHINE_REVOKED: out->revoked++; break;
        default: break; /* UNKNOWN counts only into total */
        }
    }
}

bool mesh_machines_fill_live_identity(
    struct mesh_machine_row *row, const struct mesh_status_receipt_v1 *receipt)
{
    if (!row || !receipt)
        return false;
    row->observed_unix = receipt->observed_unix;
    if (!v2_identity_public_fingerprint(receipt->responder_noise_static,
                                        row->responder_noise_fingerprint)) {
        LOG_ERROR(MESH_MACHINES_TAG,
                  "refresh: responder fingerprint derivation failed");
        memset(row->responder_noise_fingerprint, 0, 32);
        return false;
    }
    return true;
}

/* Per-probe bookkeeping for the collective wait. Only probed rows get one. */
struct mesh_machine_probe {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    uint8_t request_id[32];
    enum boot_mesh_status_begin_result begin;
    enum boot_mesh_status_poll_state poll;
    enum mesh_status_receipt_status receipt_status;
    bool outstanding;
    bool route_pending;
};

/* A fleet burst must fit the status lane's pending table on an empty table:
 * admission refuses a still-full table instead of evicting the oldest live
 * request, so a cap above PENDING_MAX would make a machines call
 * self-congest its own probes into BUSY. The wire test pins the same
 * relationship at run time. */
_Static_assert(MESH_MACHINES_FLEET_MAX <= MESH_STATUS_PENDING_MAX,
               "fleet probe burst must fit the mesh status pending table");

static void mesh_machines_block(struct mesh_machines_report *out,
                                const char *blocker)
{
    snprintf(out->blocker, sizeof(out->blocker), "%s", blocker);
}

/* Outcome of advancing one probe a single collect pass. */
enum mesh_machine_probe_outcome {
    /* Nothing to persist this pass: idle, still waiting on a route or a
     * reply, or retired without a verified receipt. */
    MESH_MACHINE_PROBE_QUIET,
    /* Terminal poll carrying a signed receipt; an ONLINE one also carries
     * the live identity. */
    MESH_MACHINE_PROBE_ONLINE,
    MESH_MACHINE_PROBE_REFUSED
};

/* Copy the listed pairing ids into the report rows and flag honest
 * truncation when the store holds more records than the bounded view. */
static void mesh_machines_copy_listed_rows(
    struct mesh_machines_report *out,
    const struct mesh_pairing_public_view *views, size_t view_count,
    const struct db_mesh_pairing_counts *store_counts)
{
    /* The list view is bounded at MESH_PAIRING_LIST_MAX rows; more records
     * in the store means the probe plan is honestly truncated. */
    if ((int64_t)view_count < store_counts->total)
        out->truncated = true;
    for (size_t i = 0; i < view_count; i++)
        snprintf(out->rows[i].pairing_id, sizeof(out->rows[i].pairing_id),
                 "%s", views[i].pairing_id);
}

/* Plan the bounded probe budget, then fan out begins; returns the number
 * of probes launched. */
static size_t mesh_machines_plan_and_begin_probes(
    const struct mesh_pairing_public_view *views, size_t view_count,
    struct mesh_machine_probe *probes, int *probe_of_row,
    struct mesh_machine_row *rows, bool *truncated_out)
{
    const char *record_states[MESH_PAIRING_LIST_MAX];
    bool probe_plan[MESH_PAIRING_LIST_MAX];
    memset(record_states, 0, sizeof(record_states));
    for (size_t i = 0; i < view_count; i++)
        record_states[i] = views[i].state;
    bool plan_truncated = false;
    (void)mesh_machines_plan_probes(record_states, view_count,
                                    MESH_MACHINES_FLEET_MAX, probe_plan,
                                    &plan_truncated);
    if (plan_truncated)
        *truncated_out = true;

    /* Fan out begins. A begin verdict is itself an observation (the lane
     * re-checks the record and the live session), so it is recorded even
     * when no request goes out. */
    size_t probe_count = 0;
    for (size_t i = 0; i < view_count; i++) {
        probe_of_row[i] = -1;
        if (!probe_plan[i])
            continue;
        struct mesh_machine_probe *probe = &probes[probe_count];
        probe->poll = MESH_STATUS_POLL_PENDING;
        probe->receipt_status = MESH_STATUS_RECEIPT_INTERNAL;
        probe->begin = boot_mesh_status_begin(views[i].pairing_id,
                                              probe->request_id);
        memcpy(probe->pairing_id, views[i].pairing_id,
               MESH_PAIRING_ID_HEX + 1u);
        probe->route_pending =
            probe->begin == MESH_STATUS_BEGIN_ROUTE_PENDING;
        probe->outstanding = probe->begin == MESH_STATUS_BEGIN_OK ||
                             probe->route_pending;
        probe_of_row[i] = (int)probe_count;
        rows[i].probed = true;
        probe_count++;
    }
    return probe_count;
}

/* Advance one probe a single collect pass: retry a pending route, poll a
 * live request, record any terminal outcome. Probes still waiting are
 * counted toward the sweep's outstanding total as the pass goes. */
static enum mesh_machine_probe_outcome mesh_machine_advance_probe(
    struct mesh_machine_probe *probe, struct mesh_status_receipt_v1 *receipt,
    size_t *outstanding)
{
    if (!probe->outstanding)
        return MESH_MACHINE_PROBE_QUIET;
    if (probe->route_pending) {
        probe->begin = boot_mesh_status_begin(probe->pairing_id,
                                              probe->request_id);
        probe->route_pending =
            probe->begin == MESH_STATUS_BEGIN_ROUTE_PENDING;
        if (probe->route_pending) {
            (*outstanding)++;
            return MESH_MACHINE_PROBE_QUIET;
        }
        if (probe->begin != MESH_STATUS_BEGIN_OK) {
            probe->outstanding = false;
            return MESH_MACHINE_PROBE_QUIET;
        }
    }
    enum boot_mesh_status_poll_state polled =
        boot_mesh_status_poll(probe->request_id, receipt);
    if (polled == MESH_STATUS_POLL_PENDING) {
        (*outstanding)++;
        return MESH_MACHINE_PROBE_QUIET;
    }
    probe->outstanding = false;
    probe->poll = polled;
    if (polled != MESH_STATUS_POLL_OK &&
        polled != MESH_STATUS_POLL_REFUSED)
        return MESH_MACHINE_PROBE_QUIET;
    probe->receipt_status = receipt->status;
    if (polled == MESH_STATUS_POLL_OK)
        return MESH_MACHINE_PROBE_ONLINE;
    return MESH_MACHINE_PROBE_REFUSED;
}

/* Record an online probe's verified receipt identity into its row. */
static void mesh_machine_record_online_identity(
    struct mesh_machine_row *rows, const int *probe_of_row,
    size_t view_count, size_t probe_index,
    const struct mesh_status_receipt_v1 *receipt,
    enum mesh_machine_probe_outcome outcome)
{
    if (outcome != MESH_MACHINE_PROBE_ONLINE)
        return;
    size_t row = 0;
    for (size_t i = 0; i < view_count; i++) {
        if (probe_of_row[i] == (int)probe_index) {
            row = i;
            break;
        }
    }
    (void)mesh_machines_fill_live_identity(&rows[row], receipt);
}

/* True when the collective wait is over: nothing outstanding, or the
 * collect budget's deadline has passed. */
static bool mesh_machines_collect_finished(size_t outstanding,
                                           int64_t deadline)
{
    if (outstanding == 0)
        return true;
    return platform_time_monotonic_ms() >= deadline;
}

/* Derive each row's verdict from its recorded observations. */
static void mesh_machines_derive_row_states(
    struct mesh_machine_row *rows, size_t view_count,
    const struct mesh_pairing_public_view *views,
    const struct mesh_machine_probe *probes, const int *probe_of_row)
{
    for (size_t i = 0; i < view_count; i++) {
        struct mesh_machine_row *row = &rows[i];
        const char *detail = "";
        if (probe_of_row[i] >= 0) {
            const struct mesh_machine_probe *probe = &probes[probe_of_row[i]];
            row->state = mesh_machine_derive_state(
                views[i].state, probe->begin, probe->poll,
                probe->receipt_status, &detail);
        } else if (strcmp(views[i].state, "active") == 0) {
            row->state = MESH_MACHINE_UNKNOWN;
            detail = "fleet_cap_not_probed";
        } else {
            /* Expired/revoked/unrecognized records are never probed; the
             * begin/poll arguments are ignored for them. */
            row->state = mesh_machine_derive_state(
                views[i].state, MESH_STATUS_BEGIN_UNAVAILABLE,
                MESH_STATUS_POLL_UNKNOWN, MESH_STATUS_RECEIPT_INTERNAL,
                &detail);
        }
        snprintf(row->detail, sizeof(row->detail), "%s", detail);
    }
}

bool boot_mesh_machines_refresh(struct node_db *ndb, struct db_service *dbsvc,
                                struct mesh_machines_report *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->generated_unix = (int64_t)platform_time_wall_time_t();

    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR(MESH_MACHINES_TAG, "refresh: node_db unavailable");
        mesh_machines_block(out, "node_db unavailable");
        return true;
    }
    if (out->generated_unix <= 0) {
        LOG_ERROR(MESH_MACHINES_TAG, "refresh: wall clock unavailable");
        mesh_machines_block(out, "wall clock unavailable");
        return true;
    }

    struct mesh_pairing_public_view views[MESH_PAIRING_LIST_MAX];
    size_t view_count = 0;
    struct db_mesh_pairing_counts store_counts;
    memset(&store_counts, 0, sizeof(store_counts));
    if (!mesh_pairing_service_list(ndb, out->generated_unix, views,
                                   MESH_PAIRING_LIST_MAX, &view_count,
                                   &store_counts)) {
        LOG_ERROR(MESH_MACHINES_TAG, "refresh: pairing list failed");
        mesh_machines_block(out, "pairing records unreadable");
        return true;
    }
    out->records_observed = true;
    out->row_count = view_count;
    mesh_machines_copy_listed_rows(out, views, view_count, &store_counts);

    struct mesh_machine_probe probes[MESH_MACHINES_FLEET_MAX];
    memset(probes, 0, sizeof(probes));
    int probe_of_row[MESH_PAIRING_LIST_MAX];
    size_t probe_count = mesh_machines_plan_and_begin_probes(
        views, view_count, probes, probe_of_row, out->rows,
        &out->truncated);

    /* Collective wait in the RPC worker thread: one stack receipt per poll
     * call; terminal outcomes are recorded AND persisted into the durable
     * observation store through the lane's single handoff. A persist
     * failure never changes the live verdict — the signed receipt was
     * observed either way — but it is logged loud. */
    int64_t deadline =
        platform_time_monotonic_ms() + MESH_MACHINES_COLLECT_BUDGET_MS;
    for (;;) {
        size_t outstanding = 0;
        for (size_t p = 0; p < probe_count; p++) {
            struct mesh_status_receipt_v1 receipt;
            enum mesh_machine_probe_outcome outcome =
                mesh_machine_advance_probe(&probes[p], &receipt,
                                           &outstanding);
            if (outcome == MESH_MACHINE_PROBE_QUIET)
                continue;
            if (!boot_mesh_status_receipt_persist(dbsvc, &receipt)) {
                LOG_ERROR(MESH_MACHINES_TAG,
                          "refresh: verified receipt could not be persisted "
                          "on the db_service lane; the live verdict stands "
                          "but the durable evidence was not updated");
            }
            mesh_machine_record_online_identity(out->rows, probe_of_row,
                                                view_count, p, &receipt,
                                                outcome);
        }
        if (mesh_machines_collect_finished(outstanding, deadline))
            break; /* survivors stay PENDING → timeout, honestly */
        platform_sleep_ms(MESH_MACHINES_COLLECT_POLL_MS);
    }

    mesh_machines_derive_row_states(out->rows, view_count, views, probes,
                                    probe_of_row);
    mesh_machines_tally(out->rows, out->row_count, &out->counts);
    return true;
}
