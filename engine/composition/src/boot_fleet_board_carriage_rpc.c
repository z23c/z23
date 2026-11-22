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

#include "boot_fleet_board_push_internal.h"
#include "boot_fleet_board_rpc_internal.h"

#include "base/hex.h"
#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"
#include "json/json.h"
#include "models/fleet_board_post.h"

#include <stddef.h>
#include <stdint.h>

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

bool fb_render_carriage(struct json_value *result)
{
    struct boot_fleet_board_fleet_counts c = {0};
    boot_fleet_board_fleet_counts(&c);
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = carriage_pull(&o, &c) && carriage_push_out(&o, &c) &&
              carriage_push_in(&o, &c) && json_push_kv(result, "carriage", &o);
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
    if (v->phase == FLEET_BOARD_OBS_INGEST)
        return fb_observation_ingest(o, v);
    if (v->phase == FLEET_BOARD_OBS_OPEN_ATTEMPT)
        return true;
    return json_push_kv_str(o, "reason", mesh_stream_refusal_string(
                            (enum mesh_stream_refusal)v->result));
}

static bool fb_observation_fields(struct json_value *o,
                                  const struct boot_fleet_board_observation *v)
{
    bool ok = json_push_kv_int(o, "sequence", (int64_t)v->sequence) &&
              json_push_kv_str(o, "phase", fb_observation_phase(v->phase));
    if (v->phase != FLEET_BOARD_OBS_GATE)
        ok = ok && json_push_kv_int(o, "after", v->after);
    ok = ok && fb_observation_detail(o, v);
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
    ok = ok && json_push_kv(result, key, &o);
    json_free(&o);
    return ok;
}
