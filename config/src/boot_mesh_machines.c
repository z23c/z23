/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet refresh — list durable pairings, probe actives over the
 * mesh status lane, persist every verified terminal receipt into the
 * observation store, derive honest per-machine live verdicts.
 *
 * The pure half (derive/plan/tally/fill) is exported from the header so the
 * wire group test drives the exact production mapping without sockets; the
 * live half (boot_mesh_machines_refresh) is the only function that touches
 * the pairing store or the status lane, and it never dials. Receipt
 * persistence goes through boot_mesh_status_receipt_persist — the
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

enum mesh_machine_state mesh_machine_derive_state(
    const char *record_state, enum boot_mesh_status_begin_result begin,
    enum boot_mesh_status_poll_state poll,
    enum mesh_status_receipt_status receipt_status, const char **detail_out)
{
    const char *detail = "";
    enum mesh_machine_state state = MESH_MACHINE_UNKNOWN;

    if (record_state && strcmp(record_state, "expired") == 0) {
        state = MESH_MACHINE_EXPIRED;
    } else if (record_state && strcmp(record_state, "revoked") == 0) {
        state = MESH_MACHINE_REVOKED;
    } else if (!record_state || strcmp(record_state, "active") != 0) {
        detail = "unrecognized_record_state";
    } else if (begin != MESH_STATUS_BEGIN_OK) {
        /* Begin re-checks the pairing record live, so a verdict that
         * contradicts the just-listed record state is reported as that
         * fresher truth rather than masked. */
        switch (begin) {
        case MESH_STATUS_BEGIN_PEER_NOT_CONNECTED:
            state = MESH_MACHINE_UNREACHABLE;
            detail = "no_live_noise_session";
            break;
        case MESH_STATUS_BEGIN_NOISE_DISABLED:
            state = MESH_MACHINE_UNREACHABLE;
            detail = "noise_transport_disabled";
            break;
        case MESH_STATUS_BEGIN_REVOKED:
            state = MESH_MACHINE_REVOKED;
            detail = "record_revoked_before_probe";
            break;
        case MESH_STATUS_BEGIN_EXPIRED:
            state = MESH_MACHINE_EXPIRED;
            detail = "record_expired_before_probe";
            break;
        case MESH_STATUS_BEGIN_NOT_PAIRED:
            detail = "record_vanished_before_probe";
            break;
        case MESH_STATUS_BEGIN_BUSY:
            detail = "pending_table_full";
            break;
        case MESH_STATUS_BEGIN_SEND_FAILED:
            detail = "send_failed";
            break;
        case MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE:
            detail = "local_identity_unavailable";
            break;
        case MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE:
            /* The peer IS connected (a live session exists), but it has no
             * unique active ZID delegation bound to that session — an
             * authority gap, not a transport gap, so not UNREACHABLE. */
            detail = "peer_identity_unavailable";
            break;
        default:
            detail = "status_lane_unavailable";
            break;
        }
    } else {
        switch (poll) {
        case MESH_STATUS_POLL_OK:
            state = MESH_MACHINE_ONLINE;
            break;
        case MESH_STATUS_POLL_REFUSED:
            state = MESH_MACHINE_REFUSED;
            detail = mesh_status_receipt_status_string(receipt_status);
            break;
        case MESH_STATUS_POLL_EXPIRED:
            state = MESH_MACHINE_TIMEOUT;
            detail = "request_expired_unanswered";
            break;
        case MESH_STATUS_POLL_PENDING:
            state = MESH_MACHINE_TIMEOUT;
            detail = "collect_budget_exhausted";
            break;
        default:
            detail = "request_lost";
            break;
        }
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
    uint8_t request_id[32];
    enum boot_mesh_status_begin_result begin;
    enum boot_mesh_status_poll_state poll;
    enum mesh_status_receipt_status receipt_status;
    bool outstanding;
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
    /* The list view is bounded at MESH_PAIRING_LIST_MAX rows; more records
     * in the store means the probe plan is honestly truncated. */
    if ((int64_t)view_count < store_counts.total)
        out->truncated = true;

    for (size_t i = 0; i < view_count; i++)
        snprintf(out->rows[i].pairing_id, sizeof(out->rows[i].pairing_id),
                 "%s", views[i].pairing_id);

    const char *record_states[MESH_PAIRING_LIST_MAX];
    bool probe_plan[MESH_PAIRING_LIST_MAX];
    for (size_t i = 0; i < view_count; i++)
        record_states[i] = views[i].state;
    bool plan_truncated = false;
    (void)mesh_machines_plan_probes(record_states, view_count,
                                    MESH_MACHINES_FLEET_MAX, probe_plan,
                                    &plan_truncated);
    if (plan_truncated)
        out->truncated = true;

    /* Fan out begins. A begin verdict is itself an observation (the lane
     * re-checks the record and the live session), so it is recorded even
     * when no request goes out. */
    struct mesh_machine_probe probes[MESH_MACHINES_FLEET_MAX];
    memset(probes, 0, sizeof(probes));
    int probe_of_row[MESH_PAIRING_LIST_MAX];
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
        probe->outstanding = (probe->begin == MESH_STATUS_BEGIN_OK);
        probe_of_row[i] = (int)probe_count;
        out->rows[i].probed = true;
        probe_count++;
    }

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
            struct mesh_machine_probe *probe = &probes[p];
            if (!probe->outstanding)
                continue;
            struct mesh_status_receipt_v1 receipt;
            enum boot_mesh_status_poll_state polled =
                boot_mesh_status_poll(probe->request_id, &receipt);
            if (polled == MESH_STATUS_POLL_PENDING) {
                outstanding++;
                continue;
            }
            probe->outstanding = false;
            probe->poll = polled;
            if (polled != MESH_STATUS_POLL_OK &&
                polled != MESH_STATUS_POLL_REFUSED)
                continue;
            probe->receipt_status = receipt.status;
            if (!boot_mesh_status_receipt_persist(dbsvc, &receipt)) {
                LOG_ERROR(MESH_MACHINES_TAG,
                          "refresh: verified receipt for pairing %.8s could "
                          "not be persisted on the db_service lane; the live "
                          "verdict stands but the durable evidence was not "
                          "updated",
                          receipt.pairing_id);
            }
            if (polled == MESH_STATUS_POLL_OK) {
                size_t row = 0;
                for (size_t i = 0; i < view_count; i++) {
                    if (probe_of_row[i] == (int)p) {
                        row = i;
                        break;
                    }
                }
                (void)mesh_machines_fill_live_identity(&out->rows[row],
                                                       &receipt);
            }
        }
        if (outstanding == 0)
            break;
        if (platform_time_monotonic_ms() >= deadline)
            break; /* survivors stay PENDING → timeout, honestly */
        platform_sleep_ms(MESH_MACHINES_COLLECT_POLL_MS);
    }

    /* Derive each row's verdict from its recorded observations. */
    for (size_t i = 0; i < view_count; i++) {
        struct mesh_machine_row *row = &out->rows[i];
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

    mesh_machines_tally(out->rows, out->row_count, &out->counts);
    return true;
}
