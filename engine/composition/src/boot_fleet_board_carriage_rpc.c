/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "carriage" object of the read-only `fleet_board op=status`
 * reply: the fleet carriage lane's pull and push counters
 * (struct boot_fleet_board_fleet_counts), each under its own name, so an
 * operator sees pushes queued, opened, stored, held, deferred, refused and
 * skipped by reason, what became of each delivery hint, and the pull's
 * refusals, without a test build. Bounded: a fixed set of keys per counter
 * group, and the primitive's close reasons only where one was counted.
 * Exact peer and post queries also render the latest matching observations.
 */

#include "boot_fleet_board_carriage_peers_internal.h"
#include "boot_fleet_board_push_internal.h"
#include "boot_fleet_board_rpc_internal.h"

#include "base/hex.h"
#include "config/boot_fleet_board.h"
#include "config/boot_mesh_status.h"
#include "config/mesh_stream.h"
#include "json/json.h"
#include "models/fleet_board_post.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static const char *const k_verdicts[FLEET_BOARD_PUSH_VERDICTS] = {
    "stored", "held", "deferred", "refused",
};

static const char *const k_refusals[FLEET_BOARD_PUSH_REFUSALS] = {
    "pairing", "delegation", "role", "roster",
};

typedef const char *(*carriage_name_fn)(unsigned i);

static const char *carriage_verdict(unsigned i)
{
    return i < FLEET_BOARD_PUSH_VERDICTS ? k_verdicts[i] : "unknown";
}

static const char *carriage_refusal(unsigned i)
{
    return i < FLEET_BOARD_PUSH_REFUSALS ? k_refusals[i] : "unknown";
}

static const char *carriage_hint(unsigned i)
{
    return boot_fleet_board_push_hint_name((enum fleet_board_push_hint)i);
}

static const char *carriage_closed(unsigned i)
{
    return mesh_stream_refusal_string((enum mesh_stream_refusal)i);
}

/* Counters [first, n) of `v` by name, as one object `key` in `into`; with
 * `nonzero`, only the ones that moved. */
static bool carriage_group(struct json_value *into, const char *key,
                           const uint64_t *v, size_t first, size_t n,
                           carriage_name_fn name_of, bool nonzero)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = true;
    for (size_t i = first; i < n && ok; i++)
        if (!nonzero || v[i] != 0)
            ok = json_push_kv_int(&o, name_of((unsigned)i), (int64_t)v[i]);
    ok = ok && json_push_kv(into, key, &o);
    json_free(&o);
    return ok;
}

static bool carriage_pull(struct json_value *into,
                          const struct boot_fleet_board_fleet_counts *c)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_int(&o, "stored", (int64_t)c->stored) &&
              json_push_kv_int(&o, "deferred", (int64_t)c->deferred) &&
              json_push_kv_int(&o, "inbox_full", (int64_t)c->inbox_full) &&
              json_push_kv_int(&o, "answer_refused",
                               (int64_t)c->answer_refused) &&
              json_push_kv_int(&o, "delegation_refused",
                               (int64_t)c->delegation_refused) &&
              json_push_kv_int(&o, "role_refused", (int64_t)c->role_refused) &&
              json_push_kv_int(&o, "roster_refused",
                               (int64_t)c->roster_refused) &&
              json_push_kv(into, "pull", &o);
    json_free(&o);
    return ok;
}

/* The sending half: what was queued and opened, why posts were not pushed,
 * what each receipt said, and what became of each hint. */
static bool carriage_push_out(struct json_value *into,
                              const struct boot_fleet_board_fleet_counts *c)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok =
        json_push_kv_int(&o, "queued", (int64_t)c->push_queued) &&
        json_push_kv_int(&o, "opened", (int64_t)c->push_opened) &&
        carriage_group(&o, "skipped", c->push_skipped, 0,
                       FLEET_BOARD_PUSH_SKIPS, board_push_skip_name, false) &&
        carriage_group(&o, "closed", c->push_closed, 0, 16, carriage_closed,
                       true) &&
        carriage_group(&o, "receipt", c->push_receipt, 0,
                       FLEET_BOARD_PUSH_CODES, board_push_code_name, false) &&
        carriage_group(&o, "receipt_records", c->push_receipt_records, 0,
                       FLEET_BOARD_PUSH_VERDICTS, carriage_verdict, false) &&
        carriage_group(&o, "refused", c->push_refused_out, 0,
                       FLEET_BOARD_PUSH_REFUSALS, carriage_refusal, false) &&
        carriage_group(&o, "hint", c->push_hint, FLEET_BOARD_PUSH_HINT_QUEUED,
                       FLEET_BOARD_PUSH_HINTS, carriage_hint, false) &&
        json_push_kv(into, "push_out", &o);
    json_free(&o);
    return ok;
}

/* The receiving half: how each push was answered, each record's verdict,
 * and the pushers refused at their commit. */
static bool carriage_push_in(struct json_value *into,
                             const struct boot_fleet_board_fleet_counts *c)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok =
        carriage_group(&o, "answered", c->push_in, 0, FLEET_BOARD_PUSH_CODES,
                       board_push_code_name, false) &&
        carriage_group(&o, "records", c->push_in_records, 0,
                       FLEET_BOARD_PUSH_VERDICTS, carriage_verdict, false) &&
        json_push_kv_int(&o, "dropped", (int64_t)c->push_in_dropped) &&
        json_push_kv_int(&o, "data_refused", (int64_t)c->push_data_refused) &&
        carriage_group(&o, "refused", c->push_refused_in, 0,
                       FLEET_BOARD_PUSH_REFUSALS, carriage_refusal, false) &&
        json_push_kv(into, "push_in", &o);
    json_free(&o);
    return ok;
}

/* One paired peer: its short fingerprint (the first 12 hex digits of the
 * peer_master_fingerprint `ops mesh pair list` shows), the last pull tried and the last answer drained (0: never),
 * its counts, and the reason the last pull did not happen or land ("" when
 * none is on record). */
static bool carriage_peer_row(struct json_value *peers,
                              const struct board_carriage_peer *p)
{
    char hex[65], reason[BOARD_CARRIAGE_DETAIL_MAX + 40];
    boot_mesh_status_key_fingerprint("zcl.mesh.master.fingerprint.v1", p->peer,
                                     hex);
    hex[12] = '\0';
    (void)snprintf(reason, sizeof reason, "%s%s%s",
                   board_carriage_reason_name(p->reason),
                   p->detail[0] ? ":" : "", p->detail);
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_str(&o, "peer", hex) &&
              json_push_kv_int(&o, "last_pull_attempt_at",
                               p->last_pull_attempt_at) &&
              json_push_kv_int(&o, "last_answer_at", p->last_answer_at) &&
              json_push_kv_str(&o, "last_skip_reason", reason) &&
              json_push_kv_int(&o, "pulls", (int64_t)p->pulls) &&
              json_push_kv_int(&o, "answers", (int64_t)p->answers) &&
              json_push_kv_int(&o, "stored", (int64_t)p->stored) &&
              json_push_kv_int(&o, "refused", (int64_t)p->refused) &&
              json_push_back(peers, &o);
    json_free(&o);
    return ok;
}

/* The per-peer pull state and its totals: why "messages do not travel" is
 * answered here, one row per peer the pull lane has decided about. */
static bool carriage_peers(struct json_value *into)
{
    struct board_carriage_peer rows[FLEET_BOARD_FLEET_PEERS_MAX];
    size_t n = board_carriage_snapshot(rows, FLEET_BOARD_FLEET_PEERS_MAX);
    struct board_carriage_peer total = {0};
    struct json_value peers;
    json_init(&peers);
    json_set_array(&peers);
    bool ok = true;
    for (size_t i = 0; i < n && i < FLEET_BOARD_FLEET_PEERS_MAX && ok; i++) {
        total.pulls += rows[i].pulls;
        total.answers += rows[i].answers;
        total.stored += rows[i].stored;
        total.refused += rows[i].refused;
        ok = carriage_peer_row(&peers, &rows[i]);
    }
    struct json_value t;
    json_init(&t);
    json_set_object(&t);
    ok = ok && json_push_kv_int(&t, "peers", (int64_t)n) &&
         json_push_kv_int(&t, "pulls", (int64_t)total.pulls) &&
         json_push_kv_int(&t, "answers", (int64_t)total.answers) &&
         json_push_kv_int(&t, "stored", (int64_t)total.stored) &&
         json_push_kv_int(&t, "refused", (int64_t)total.refused) &&
         json_push_kv(into, "peers", &peers) &&
         json_push_kv(into, "totals", &t);
    json_free(&t);
    json_free(&peers);
    return ok;
}

bool fb_render_carriage(struct json_value *result)
{
    struct boot_fleet_board_fleet_counts c = {0};
    boot_fleet_board_fleet_counts(&c);
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = carriage_peers(&o) && carriage_pull(&o, &c) &&
              carriage_push_out(&o, &c) && carriage_push_in(&o, &c) &&
              json_push_kv(result, "carriage", &o);
    json_free(&o);
    return ok;
}

static const char *fb_observation_phase(enum boot_fleet_board_observation_phase phase)
{
    static const char *const names[] = {
        [FLEET_BOARD_OBS_OPEN_ATTEMPT] = "open_attempt",
        [FLEET_BOARD_OBS_OPEN_FAILURE] = "open_failure",
        [FLEET_BOARD_OBS_CLOSE] = "close",
        [FLEET_BOARD_OBS_INGEST] = "ingest",
        [FLEET_BOARD_OBS_GATE] = "gate_refusal",
        [FLEET_BOARD_OBS_ANSWER_REFUSED] = "answer_refused",
        [FLEET_BOARD_OBS_ANSWER_DEFERRED] = "answer_deferred",
        [FLEET_BOARD_OBS_CURSOR_RESET] = "cursor_reset",
    };
    return (unsigned)phase < sizeof names / sizeof names[0] ? names[phase] : "unknown";
}

static bool fb_observation_ingest(struct json_value *o,
                                  const struct boot_fleet_board_observation *v)
{
    enum fleet_board_result r = (enum fleet_board_result)v->result;
    const char *disposition = v->stored ? "stored" : v->retryable ? "deferred" :
                              r == FLEET_BOARD_OK ? "held" : "refused";
    return json_push_kv_int(o, "arrival", v->arrival) &&
           json_push_kv_str(o, "disposition", disposition) &&
           json_push_kv_str(o, "result", fleet_board_result_string(r));
}

static bool fb_observation_deferred(struct json_value *o, int result)
{
    static const struct { const char *reason, *action; } outcomes[] = {
        [FLEET_BOARD_ANSWER_INBOX_FULL] = {"inbox_full", "wait_for_board_inbox"},
        [FLEET_BOARD_ANSWER_ALLOCATION_FAILED] = {"allocation_failed", "inspect_node_memory"},
    };
    unsigned r = (unsigned)result;
    if (r >= sizeof outcomes / sizeof outcomes[0] || !outcomes[r].reason)
        return json_push_kv_str(o, "reason", "unknown");
    return json_push_kv_str(o, "reason", outcomes[r].reason) &&
           json_push_kv_str(o, "next_action", outcomes[r].action);
}

static bool fb_observation_detail(struct json_value *o,
                                  const struct boot_fleet_board_observation *v)
{
    static const char *const gate_reasons[] = {
        [FLEET_BOARD_GATE_PAIRING] = "pairing",
        [FLEET_BOARD_GATE_DELEGATION_UNRESOLVED] = "delegation_unresolved",
        [FLEET_BOARD_GATE_DELEGATION_REFUSED] = "delegation_refused",
        [FLEET_BOARD_GATE_ROSTER] = "roster",
    };
    if (v->phase == FLEET_BOARD_OBS_GATE) {
        unsigned reason = (unsigned)v->result;
        return json_push_kv_str(o, "reason", reason < sizeof gate_reasons / sizeof gate_reasons[0]
                                ? gate_reasons[reason] : "unknown");
    }
    if (v->phase == FLEET_BOARD_OBS_ANSWER_REFUSED)
        return json_push_kv_str(o, "reason", "malformed");
    if (v->phase == FLEET_BOARD_OBS_ANSWER_DEFERRED)
        return fb_observation_deferred(o, v->result);
    if (v->phase == FLEET_BOARD_OBS_CURSOR_RESET) {
        const char *reason = v->result == FLEET_BOARD_CURSOR_EPOCH_CHANGED
            ? "epoch_changed" : "epoch_unobserved";
        return json_push_kv_str(o, "reason", reason) &&
               json_push_kv_str(o, "next_action", "await_next_pull");
    }
    if (v->phase == FLEET_BOARD_OBS_INGEST)
        return fb_observation_ingest(o, v);
    if (v->phase == FLEET_BOARD_OBS_OPEN_ATTEMPT)
        return true;
    return json_push_kv_str(o, "reason", mesh_stream_refusal_string(
                            (enum mesh_stream_refusal)v->result));
}

/* Advice is descriptive only; the lane still owns all retry decisions. */
static const char *fb_observation_ingest_action(const struct boot_fleet_board_observation *v)
{
    static const char *const actions[] = {
        [FLEET_BOARD_ERR_ROLE] = "inspect_writer_role_and_roster",
        [FLEET_BOARD_ERR_FUTURE] = "inspect_clock",
        [FLEET_BOARD_ERR_QUOTA] = "inspect_author_quota",
        [FLEET_BOARD_ERR_WIKI_QUOTA] = "wait_for_quota_window",
        [FLEET_BOARD_ERR_WIKI_FULL] = "inspect_wiki_capacity",
        [FLEET_BOARD_ERR_CAPACITY] = "inspect_board_capacity",
        [FLEET_BOARD_ERR_BUSY] = "wait_for_board_store",
        [FLEET_BOARD_ERR_STORAGE] = "inspect_board_store",
        [FLEET_BOARD_ERR_SIGNATURE] = "inspect_post_signature",
    };
    unsigned r = (unsigned)v->result;
    if (v->stored || r == FLEET_BOARD_OK || r > FLEET_BOARD_ERR_WIKI_FULL)
        return NULL;
    if (r < sizeof actions / sizeof actions[0] && actions[r]) return actions[r];
    return "inspect_post_refusal";
}

static const char *fb_observation_stream_action(int result)
{
    static const char *const actions[] = {
        [MESH_STREAM_REFUSED_LINK_NOT_NOISE] = "inspect_peer_noise_session",
        [MESH_STREAM_REFUSED_PEER_UNPAIRED] = "inspect_peer_pairing_and_capability",
        [MESH_STREAM_REFUSED_SERVICE_UNKNOWN] = "inspect_peer_board_protocol",
        [MESH_STREAM_REFUSED_CAP] = "inspect_stream_availability",
        [MESH_STREAM_REFUSED_CREDIT_EXCEEDED] = "inspect_peer_board_protocol",
        [MESH_STREAM_REFUSED_MALFORMED] = "inspect_peer_board_protocol",
        [MESH_STREAM_REFUSED_ID_PARITY] = "inspect_peer_board_protocol",
        [MESH_STREAM_REFUSED_ID_IN_USE] = "inspect_peer_board_protocol",
        [MESH_STREAM_REFUSED_RATE] = "inspect_stream_availability",
        [MESH_STREAM_REFUSED_UNAVAILABLE] = "inspect_stream_availability",
        [MESH_STREAM_REFUSED_PEER_NOT_CONNECTED] = "inspect_peer_connection",
        [MESH_STREAM_ENDED_IDLE] = "inspect_peer_connection",
        [MESH_STREAM_ENDED_SESSION_LOST] = "inspect_peer_connection",
        [MESH_STREAM_ENDED_SHUTDOWN] = "inspect_peer_connection",
    };
    unsigned r = (unsigned)result;
    return r < sizeof actions / sizeof actions[0] ? actions[r] : NULL;
}

static const char *fb_observation_action(const struct boot_fleet_board_observation *v)
{
    static const char *const gates[] = {
        [FLEET_BOARD_GATE_PAIRING] = "inspect_peer_pairing",
        [FLEET_BOARD_GATE_DELEGATION_UNRESOLVED] = "inspect_peer_delegation",
        [FLEET_BOARD_GATE_DELEGATION_REFUSED] = "inspect_peer_delegation",
        [FLEET_BOARD_GATE_ROSTER] = "inspect_peer_roster",
    };
    if (v->phase == FLEET_BOARD_OBS_ANSWER_REFUSED)
        return "inspect_peer_board_protocol";
    if (v->phase == FLEET_BOARD_OBS_GATE) {
        unsigned r = (unsigned)v->result;
        return r < sizeof gates / sizeof gates[0] ? gates[r] : NULL;
    }
    if (v->phase == FLEET_BOARD_OBS_INGEST)
        return fb_observation_ingest_action(v);
    if (v->phase != FLEET_BOARD_OBS_OPEN_FAILURE && v->phase != FLEET_BOARD_OBS_CLOSE)
        return NULL;
    return fb_observation_stream_action(v->result);
}

static bool fb_observation_fields(struct json_value *o,
                                  const struct boot_fleet_board_observation *v)
{
    bool ok = json_push_kv_int(o, "sequence", (int64_t)v->sequence) &&
              json_push_kv_str(o, "phase", fb_observation_phase(v->phase));
    if (v->phase != FLEET_BOARD_OBS_GATE)
        ok = ok && json_push_kv_int(o, "after", v->after);
    ok = ok && fb_observation_detail(o, v);
    const char *action = fb_observation_action(v);
    if (action) ok = ok && json_push_kv_str(o, "next_action", action);
    if (v->epoch_set) {
        char hex[33];
        zcl_hex_encode(v->epoch, sizeof v->epoch, hex);
        ok = ok && json_push_kv_str(o, "epoch", hex);
    }
    return ok;
}

/* The caller supplies both exact identifiers; no inventory is exposed. */
bool fb_status_observation(struct json_value *result, const char *key,
                           const struct boot_fleet_board_observation *v)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_bool(&o, "observed", v->found);
    if (v->found) ok = ok && fb_observation_fields(&o, v);
    else if (strcmp(key, "post_ingest") == 0)
        ok = ok && json_push_kv_str(&o, "retention", "shared_process_local_volatile") &&
             json_push_kv_int(&o, "capacity", FLEET_BOARD_OBSERVATION_CAPACITY) &&
             json_push_kv_str(&o, "reason", "not_observed_or_evicted") &&
             json_push_kv_str(&o, "explanation", "Other traffic can evict this observation, and a restart clears it. Delivery history is unknown. Check this post ID with fleet_board op=show on the receiver.") &&
             json_push_kv_str(&o, "next_action", "inspect_exact_durable_post");
    ok = ok && json_push_kv(result, key, &o);
    json_free(&o);
    return ok;
}

/* One bounded ring snapshot serves both full status and the opt-in projection. */
bool fb_status_observations(struct json_value *result,
                                   const uint8_t peer[32], const uint8_t post[32])
{
    struct boot_fleet_board_observation attempt, ingest;
    boot_fleet_board_observe_query(peer, post, &attempt, &ingest);
    return fb_status_observation(result, "peer_attempt", &attempt) &&
           fb_status_observation(result, "post_ingest", &ingest);
}

bool fb_status_filter_parse(const struct json_value *in,
                                   struct json_value *result,
                                   struct fb_status_filter *filter)
{
    const char *peer = fb_str(in, "peer", NULL);
    const char *post = fb_str(in, "post", NULL);
    if ((json_get(in, "peer") || json_get(in, "post")) && (!peer || !post ||
        !fleet_board_id_from_hex(peer, filter->peer) ||
        !fleet_board_id_from_hex(post, filter->post))) {
        fb_error(result, "INVALID_FILTER", "peer and post must both be 32-byte hex identifiers");
        return false;
    }
    const struct json_value *only = json_get(in, "observations_only");
    if (only && (only->type != JSON_BOOL || (json_get_bool(only) && !peer))) {
        fb_error(result, "INVALID_FILTER",
                 "observations_only must be boolean and true requires both peer and post");
        return false;
    }
    filter->filtered = peer != NULL;
    filter->only = only && json_get_bool(only);
    return true;
}
