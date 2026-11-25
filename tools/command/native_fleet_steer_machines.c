/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded machine projection from canonical fleet read replies. */

#include "command/native_fleet_steer_machines.h"

#include <stdint.h>
#include <string.h>

#define FM_UNKNOWN 0
#define FM_FRESH 1
#define FM_STALE 2
#define FM_METRIC_COUNT 4u

#define FM_PUT_NULL(object, key) do { \
    struct json_value fm_null_value = {0}; \
    json_set_null(&fm_null_value); \
    ok = json_push_kv((object), (key), &fm_null_value) && ok; \
    json_free(&fm_null_value); \
} while (0)

#define FM_PUT_INT(object, key, number) do { \
    int64_t fm_int_value = (int64_t)(number); \
    if (fm_int_value >= 0) \
        ok = json_push_kv_int((object), (key), fm_int_value) && ok; \
    else \
        FM_PUT_NULL((object), (key)); \
} while (0)

#define FM_PUT_TEXT(object, key, text) do { \
    const char *fm_text_value = (text); \
    if (fm_text_value && fm_text_value[0]) \
        ok = json_push_kv_str((object), (key), fm_text_value) && ok; \
    else \
        FM_PUT_NULL((object), (key)); \
} while (0)

static const char *const fm_metric_names[FM_METRIC_COUNT] = {
    "box.load1", "box.cores", "box.ram_used_mib", "box.ram_total_mib"
};

struct fm_metric {
    int64_t seq;
    int64_t timestamp;
    int64_t value;
    int64_t cadence;
    bool seen;
    bool present;
};

struct fm_history {
    const struct json_value *reply;
    struct fm_metric metrics[FM_METRIC_COUNT];
    int64_t head;
    int64_t heartbeat_seq;
    int64_t heartbeat_timestamp;
    const char *delegation;
    const char *verification;
    bool available;
    bool discrepancy;
    bool usable;
};

static const struct json_value *fm_field(const struct json_value *object,
                                         const char *key,
                                         enum json_type type)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == type ? value : NULL;
}

static int64_t fm_number(const struct json_value *object, const char *key,
                         int64_t fallback)
{
    const struct json_value *value = fm_field(object, key, JSON_INT);
    return value ? json_get_int(value) : fallback;
}

static const char *fm_text(const struct json_value *object, const char *key)
{
    const struct json_value *value = fm_field(object, key, JSON_STR);
    return value ? json_get_str(value) : NULL;
}

static bool fm_boolean(const struct json_value *object, const char *key,
                       bool *present)
{
    const struct json_value *value = fm_field(object, key, JSON_BOOL);
    *present = value != NULL;
    return value && json_get_bool(value);
}

static bool fm_hex64(const char *text)
{
    if (!text || strlen(text) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

static int64_t fm_age(long long now, int64_t timestamp)
{
    if (now < 0 || timestamp < 0 || (int64_t)now < timestamp)
        return -1;
    return (int64_t)now - timestamp;
}

static int fm_freshness(const struct fm_metric *metric, long long now,
                        long long window, int64_t *age)
{
    *age = metric->seen ? fm_age(now, metric->timestamp) : -1;
    if (!metric->seen || *age < 0)
        return FM_UNKNOWN;
    int64_t cadence = metric->cadence > 0 ? metric->cadence : 0;
    int64_t threshold = cadence > INT64_MAX / 2 ? INT64_MAX : 2 * cadence;
    if ((int64_t)window > threshold)
        threshold = (int64_t)window;
    return *age <= threshold ? FM_FRESH : FM_STALE;
}

static const char *fm_state_name(int state)
{
    if (state == FM_FRESH)
        return "FRESH";
    if (state == FM_STALE)
        return "STALE";
    return "UNKNOWN";
}

static int fm_metric_index(const char *name)
{
    for (size_t i = 0; i < FM_METRIC_COUNT; i++)
        if (name && strcmp(name, fm_metric_names[i]) == 0)
            return (int)i;
    return -1;
}

static void fm_history_reset(struct fm_history *history)
{
    memset(history, 0, sizeof(*history));
    history->head = -1;
    history->heartbeat_seq = -1;
    history->heartbeat_timestamp = -1;
    history->delegation = "UNKNOWN";
    history->verification = "UNKNOWN";
}

static bool fm_history_row(struct fm_history *history,
                           const struct json_value *row, int64_t *maximum)
{
    const struct json_value *seq_value = fm_field(row, "seq", JSON_INT);
    const struct json_value *time_value = fm_field(row, "timestamp", JSON_INT);
    const struct json_value *cadence_value = fm_field(row, "cadence_s", JSON_INT);
    const char *metric_name = fm_text(row, "metric");
    bool present = false, have_present = false;
    if (!seq_value || !time_value || !cadence_value || !metric_name)
        return false;
    present = fm_boolean(row, "present", &have_present);
    if (!have_present)
        return false;
    int64_t seq = json_get_int(seq_value);
    if (seq <= 0 || seq <= *maximum || seq > history->head)
        return false;
    if (present && !fm_field(row, "value", JSON_INT))
        return false;
    *maximum = seq;
    history->heartbeat_seq = seq;
    history->heartbeat_timestamp = json_get_int(time_value);
    int index = fm_metric_index(metric_name);
    if (index < 0)
        return true;
    struct fm_metric *metric = &history->metrics[index];
    metric->seen = true;
    metric->present = present;
    metric->seq = seq;
    metric->timestamp = json_get_int(time_value);
    metric->cadence = json_get_int(cadence_value);
    metric->value = present ? fm_number(row, "value", 0) : 0;
    return true;
}

static bool fm_history_provenance(struct fm_history *history)
{
    const struct json_value *reply = history->reply;
    const char *verification = fm_text(reply, "verification");
    const char *delegation = fm_text(reply, "delegation");
    history->head = fm_number(reply, "snapshot_head", -1);
    if (delegation && strcmp(delegation, "not_evaluated") == 0)
        history->delegation = delegation;
    if (!verification || strcmp(verification, "signature_chain_only") != 0)
        return false;
    history->verification = verification;
    return true;
}

static void fm_history_validate(struct fm_history *history)
{
    const struct json_value *reply = history->reply;
    const struct json_value *rows = fm_field(reply, "rows", JSON_ARR);
    bool more = fm_boolean(reply, "more", &(bool){0});
    bool found = fm_boolean(reply, "found", &(bool){0});
    bool have_more = fm_field(reply, "more", JSON_BOOL) != NULL;
    bool have_found = fm_field(reply, "found", JSON_BOOL) != NULL;
    if (!rows || !fm_history_provenance(history) || !have_more || more ||
        !have_found || !found || history->head < 0)
        return;
    int64_t maximum = 0;
    for (size_t i = 0; i < json_size(rows); i++)
        if (!fm_history_row(history, json_at(rows, i), &maximum))
            return;
    if (maximum != history->head)
        return;
    history->usable = true;
}

static bool fm_different_text(const char *left, const char *right)
{
    return (!left != !right) || (left && right && strcmp(left, right) != 0);
}

static void fm_history_merge(struct fm_history *history,
                             const struct json_value *candidate)
{
    const char *verification = fm_text(candidate, "verification");
    const char *delegation = fm_text(candidate, "delegation");
    if (history->available) {
        history->discrepancy = true;
        if (fm_different_text(verification,
                              fm_text(history->reply, "verification")) ||
            fm_different_text(delegation,
                              fm_text(history->reply, "delegation"))) {
            history->verification = "UNKNOWN";
            history->delegation = "UNKNOWN";
        }
        return;
    }
    history->available = true;
    history->reply = candidate;
    if (verification && strcmp(verification, "signature_chain_only") == 0)
        history->verification = verification;
    if (delegation && strcmp(delegation, "not_evaluated") == 0)
        history->delegation = delegation;
}

static void fm_history_for(struct fm_history *history,
                           const struct json_value *histories, const char *box)
{
    fm_history_reset(history);
    if (!histories || histories->type != JSON_ARR || !fm_hex64(box))
        return;
    for (size_t i = 0; i < json_size(histories); i++) {
        const struct json_value *candidate = json_at(histories, i);
        const char *candidate_box = fm_text(candidate, "box");
        if (candidate_box && strcmp(candidate_box, box) == 0)
            fm_history_merge(history, candidate);
    }
    if (history->available && !history->discrepancy)
        fm_history_validate(history);
}

static bool fm_emit_metric(struct json_value *object, const char *name,
                           const struct fm_metric *metric, long long now,
                           long long window, int *state, int64_t *current)
{
    bool ok = true;
    int64_t age = -1;
    *state = fm_freshness(metric, now, window, &age);
    *current = *state == FM_FRESH && metric->present ? metric->value : -1;
    struct json_value row = {0};
    json_set_object(&row);
    FM_PUT_INT(&row, "seq", metric->seen ? metric->seq : -1);
    FM_PUT_INT(&row, "timestamp", metric->seen ? metric->timestamp : -1);
    FM_PUT_INT(&row, "age_s", age);
    FM_PUT_INT(&row, "cadence_s", metric->seen ? metric->cadence : -1);
    ok = json_push_kv_str(&row, "state", fm_state_name(*state)) && ok;
    ok = json_push_kv_bool(&row, "present", metric->seen && metric->present) && ok;
    FM_PUT_INT(&row, "value", *current);
    ok = json_push_kv(object, name, &row) && ok;
    json_free(&row);
    return ok;
}

static bool fm_metric_complete(size_t index, int state, bool present,
                               int64_t value)
{
    if (state != FM_FRESH || !present || value < 0)
        return false;
    return index != 1 || value > 0;
}

static int64_t fm_ram_available(const int states[FM_METRIC_COUNT],
                                const int64_t values[FM_METRIC_COUNT])
{
    if (states[2] != FM_FRESH || states[3] != FM_FRESH || values[2] < 0 ||
        values[3] < values[2])
        return -1;
    return values[3] - values[2];
}

static bool fm_emit_vitals(struct json_value *machine,
                           const struct fm_history *history, long long now,
                           long long window, bool *all_fresh)
{
    bool ok = true;
    int states[FM_METRIC_COUNT];
    int64_t values[FM_METRIC_COUNT];
    struct json_value vitals = {0};
    json_set_object(&vitals);
    *all_fresh = history->usable;
    for (size_t i = 0; i < FM_METRIC_COUNT; i++) {
        struct fm_metric empty = {.seq = -1, .timestamp = -1};
        const struct fm_metric *metric = history->usable
                                             ? &history->metrics[i]
                                             : &empty;
        if (metric->seen && metric->timestamp > history->heartbeat_timestamp)
            metric = &empty;
        ok = fm_emit_metric(&vitals, fm_metric_names[i], metric, now, window,
                            &states[i], &values[i]) && ok;
        if (!fm_metric_complete(i, states[i], metric->present, values[i]))
            *all_fresh = false;
    }
    ok = json_push_kv(machine, "metrics", &vitals) && ok;
    json_free(&vitals);
    FM_PUT_INT(machine, "load1_centi", values[0]);
    FM_PUT_INT(machine, "cpus", values[1]);
    FM_PUT_INT(machine, "ram_used_mib", values[2]);
    FM_PUT_INT(machine, "ram_total_mib", values[3]);
    int64_t available = fm_ram_available(states, values);
    if (available < 0)
        *all_fresh = false;
    FM_PUT_INT(machine, "ram_avail_mib", available);
    return ok;
}

static const char *fm_worker_signer(const struct json_value *worker)
{
    const char *post = fm_text(worker, "board_post");
    const char *signer = fm_text(worker, "board_signer");
    return fm_hex64(post) && fm_hex64(signer) ? signer : NULL;
}

static size_t fm_roster_box_count(const struct json_value *roster_rows,
                                  const char *box)
{
    size_t matches = 0;
    for (size_t i = 0; roster_rows && i < json_size(roster_rows); i++) {
        const struct json_value *verified = fm_field(json_at(roster_rows, i),
                                                     "verified", JSON_OBJ);
        const char *candidate = fm_text(verified, "box_pubkey");
        if (box && candidate && strcmp(candidate, box) == 0)
            matches++;
    }
    return matches;
}

static bool fm_emit_agent(struct json_value *agents,
                          const struct json_value *worker)
{
    bool ok = true;
    struct json_value row = {0};
    json_set_object(&row);
    FM_PUT_TEXT(&row, "name", fm_text(worker, "name"));
    FM_PUT_TEXT(&row, "current_ref", fm_text(worker, "current_ref"));
    FM_PUT_TEXT(&row, "stage", fm_text(worker, "stage"));
    FM_PUT_TEXT(&row, "state", fm_text(worker, "state"));
    FM_PUT_TEXT(&row, "last_seen_ts", fm_text(worker, "last_seen_ts"));
    FM_PUT_TEXT(&row, "workspace_head", fm_text(worker, "workspace_head"));
    FM_PUT_TEXT(&row, "workspace_selector", fm_text(worker, "workspace_selector"));
    FM_PUT_TEXT(&row, "board_post", fm_text(worker, "board_post"));
    ok = json_push_kv_str(&row, "source", "signed_board_mail") && ok;
    ok = json_push_kv_str(&row, "task_evidence", "worker_self_report") && ok;
    ok = json_push_back(agents, &row) && ok;
    json_free(&row);
    return ok;
}

static bool fm_worker_matches(const struct json_value *worker, const char *box,
                              bool duplicate_box)
{
    const char *candidate = fm_worker_signer(worker);
    return !duplicate_box && candidate && box && strcmp(candidate, box) == 0;
}

static bool fm_emit_agents(struct json_value *machine,
                           const struct json_value *workers,
                           const char *box, bool duplicate_box, bool workers_complete,
                           size_t unbound_workers)
{
    bool ok = true;
    size_t bound = 0;
    struct json_value agents = {0};
    json_set_array(&agents);
    for (size_t i = 0; workers && workers->type == JSON_ARR &&
                       i < json_size(workers); i++) {
        const struct json_value *worker = json_at(workers, i);
        if (!fm_worker_matches(worker, box, duplicate_box))
            continue;
        bound++;
        ok = fm_emit_agent(&agents, worker) && ok;
    }
    ok = json_push_kv(machine, "agents", &agents) && ok;
    json_free(&agents);
    const char *state = !duplicate_box && workers_complete && unbound_workers == 0
                            ? "BOUND"
                            : (bound > 0 ? "PARTIAL" : "UNKNOWN");
    ok = json_push_kv_str(machine, "agents_state", state) && ok;
    ok = json_push_kv_int(machine, "agents_unbound_total",
                          (int64_t)unbound_workers) && ok;
    return ok;
}

static bool fm_same_box(const struct json_value *rows, size_t index,
                        const char *box)
{
    for (size_t i = 0; rows && i < json_size(rows); i++) {
        if (i == index)
            continue;
        const struct json_value *verified = fm_field(json_at(rows, i),
                                                     "verified", JSON_OBJ);
        const char *candidate = fm_text(verified, "box_pubkey");
        if (candidate && box && strcmp(candidate, box) == 0)
            return true;
    }
    return false;
}

static bool fm_same_name(const struct json_value *rows, size_t index,
                         const char *name)
{
    for (size_t i = 0; rows && i < json_size(rows); i++) {
        if (i == index)
            continue;
        const struct json_value *verified = fm_field(json_at(rows, i),
                                                     "verified", JSON_OBJ);
        const char *candidate = fm_text(verified, "name");
        if (candidate && name && strcmp(candidate, name) == 0)
            return true;
    }
    return false;
}

static bool fm_emit_roster(struct json_value *machine,
                           const struct json_value *source, const char *name,
                           const char *box, bool duplicate_box,
                           bool duplicate_name, const struct fm_history *history)
{
    bool ok = true;
    FM_PUT_TEXT(machine, "name", name);
    FM_PUT_TEXT(machine, "box_pubkey", box);
    FM_PUT_INT(machine, "roster_rows", fm_number(source, "rows", -1));
    ok = json_push_kv_bool(machine, "duplicate_box", duplicate_box) && ok;
    ok = json_push_kv_bool(machine, "name_discrepancy", duplicate_name) && ok;
    ok = json_push_kv_str(machine, "roster_evidence",
                          "operator_signature_verified") && ok;
    ok = json_push_kv_str(machine, "vitals_evidence",
                          history->verification) && ok;
    FM_PUT_TEXT(machine, "vitals_delegation", history->delegation);
    FM_PUT_INT(machine, "history_snapshot_head", history->head);
    ok = json_push_kv_bool(machine, "history_complete", history->usable) && ok;
    ok = json_push_kv_bool(machine, "history_discrepancy",
                           history->discrepancy) && ok;
    return ok;
}

static int fm_emit_heartbeat(struct json_value *machine,
                             const struct fm_history *history, long long now,
                             long long window, bool *all_ok)
{
    bool ok = true;
    int state = FM_UNKNOWN;
    int64_t age = -1;
    if (history->usable && history->heartbeat_seq > 0) {
        struct fm_metric beat = {.seen = true,
                                 .timestamp = history->heartbeat_timestamp,
                                 .cadence = 0};
        state = fm_freshness(&beat, now, window, &age);
    }
    FM_PUT_INT(machine, "heartbeat_seq", history->heartbeat_seq);
    FM_PUT_INT(machine, "heartbeat_ts", history->heartbeat_timestamp);
    FM_PUT_INT(machine, "heartbeat_age_s", age);
    *all_ok = json_push_kv_str(machine, "heartbeat_state",
                               state == FM_FRESH
                                   ? "LIVE"
                                   : (state == FM_STALE ? "STALE" : "UNKNOWN")) &&
              ok && *all_ok;
    return state;
}

static bool fm_emit_machine(struct zcl_fmc_machines *view,
                            const struct json_value *roster_rows, size_t index,
                            const struct json_value *histories,
                            const struct json_value *workers, long long now,
                            long long window)
{
    bool ok = true;
    const struct json_value *source = json_at(roster_rows, index);
    const struct json_value *verified = fm_field(source, "verified", JSON_OBJ);
    if (!verified) {
        view->complete = false;
        return true;
    }
    const char *name = fm_text(verified, "name");
    const char *box = fm_text(verified, "box_pubkey");
    bool duplicate_box = fm_same_box(roster_rows, index, box);
    bool duplicate_name = fm_same_name(roster_rows, index, name);
    struct fm_history history;
    fm_history_for(&history, histories, box);
    if (!name || !name[0] || !fm_hex64(box) || !history.usable || duplicate_box ||
        duplicate_name)
        view->complete = false;

    struct json_value machine = {0};
    json_set_object(&machine);
    ok = fm_emit_roster(&machine, source, name, box, duplicate_box,
                        duplicate_name, &history) && ok;
    int heartbeat_state = fm_emit_heartbeat(&machine, &history, now, window, &ok);
    if (heartbeat_state != FM_FRESH)
        view->complete = false;

    bool all_fresh = false;
    ok = fm_emit_vitals(&machine, &history, now, window, &all_fresh) && ok;
    if (!all_fresh)
        view->complete = false;
    ok = fm_emit_agents(&machine, workers, box, duplicate_box, view->workers_complete,
                        view->unbound_workers) && ok;
    ok = json_push_back(&view->rows, &machine) && ok;
    json_free(&machine);
    return ok;
}

void zcl_fmc_machines_init(struct zcl_fmc_machines *view)
{
    memset(view, 0, sizeof(*view));
    json_init(&view->rows);
    json_set_array(&view->rows);
}

void zcl_fmc_machines_free(struct zcl_fmc_machines *view)
{
    json_free(&view->rows);
    memset(view, 0, sizeof(*view));
}

struct fm_roster_page {
    const struct json_value *rows;
    size_t count;
    int64_t total;
    int64_t returned;
    int64_t offset;
    int64_t next_offset;
    int64_t unverifiable;
    bool have_truncated;
    bool truncated;
};

static bool fm_roster_whole(const struct fm_roster_page *page)
{
    return page->rows && page->total >= 0 &&
           (uint64_t)page->total == page->count && page->returned >= 0 &&
           (uint64_t)page->returned == page->count && page->offset == 0 &&
           page->next_offset == -1 && page->unverifiable == 0 &&
           page->have_truncated && !page->truncated;
}

static void fm_roster_state(struct zcl_fmc_machines *view,
                            const struct json_value *roster,
                            struct fm_roster_page *page)
{
    memset(page, 0, sizeof(*page));
    page->rows = fm_field(roster, "machines", JSON_ARR);
    page->count = page->rows ? json_size(page->rows) : 0;
    page->total = fm_number(roster, "total", -1);
    page->returned = fm_number(roster, "returned", -1);
    page->offset = fm_number(roster, "offset", -1);
    page->next_offset = fm_number(roster, "next_offset", -2);
    page->unverifiable = fm_number(roster, "unverifiable", -1);
    page->truncated = fm_boolean(roster, "truncated", &page->have_truncated);
    view->total = page->total >= 0 && (uint64_t)page->total >= page->count
                      ? (size_t)page->total
                      : page->count;
    view->roster_ok = fm_roster_whole(page);
    view->truncated = view->total > ZCL_FMC_MACHINE_CAP ||
                      (page->have_truncated && page->truncated) ||
                      view->total > page->count;
}

static void fm_count_unbound_workers(struct zcl_fmc_machines *view,
                                     const struct json_value *rows,
                                     const struct json_value *workers)
{
    if (!workers || workers->type != JSON_ARR) {
        view->unbound_workers = 1;
        return;
    }
    for (size_t i = 0; i < json_size(workers); i++) {
        const char *signer = fm_worker_signer(json_at(workers, i));
        if (!signer || fm_roster_box_count(rows, signer) != 1)
            view->unbound_workers++;
    }
}

bool zcl_fmc_machines_project(struct zcl_fmc_machines *view,
    const struct json_value *roster, const struct json_value *histories,
    const struct json_value *workers, bool workers_complete,
    long long now, long long heartbeat_window_s)
{
    if (!view || heartbeat_window_s < 0)
        return false;
    json_free(&view->rows);
    json_init(&view->rows);
    json_set_array(&view->rows);
    struct fm_roster_page page;
    fm_roster_state(view, roster, &page);
    view->unbound_workers = 0;
    view->workers_complete = workers_complete && workers &&
                             workers->type == JSON_ARR;
    view->complete = view->roster_ok && view->workers_complete &&
                     view->total > 0;
    if (view->truncated || !view->workers_complete)
        view->complete = false;
    fm_count_unbound_workers(view, page.rows, workers);
    if (view->unbound_workers > 0)
        view->complete = false;

    bool ok = true;
    size_t limit = page.count > ZCL_FMC_MACHINE_CAP ? ZCL_FMC_MACHINE_CAP
                                                    : page.count;
    for (size_t i = 0; page.rows && i < limit; i++)
        ok = fm_emit_machine(view, page.rows, i, histories, workers, now,
                             heartbeat_window_s) && ok;
    return ok;
}

static bool fm_unique_machine_boxes(const struct zcl_fmc_machines *view)
{
    for (size_t i = 0; i < json_size(&view->rows); i++)
        if (json_get_bool(json_get(json_at(&view->rows, i), "duplicate_box")))
            return false;
    return true;
}

bool zcl_fmc_machines_emit(const struct zcl_fmc_machines *view,
    struct json_value *data)
{
    if (!view || !data || data->type != JSON_OBJ)
        return false;
    bool ok = json_push_kv(data, "machines", &view->rows);
    ok = json_push_kv_int(data, "machines_total", (int64_t)view->total) && ok;
    ok = json_push_kv_bool(data, "machines_truncated", view->truncated) && ok;
    ok = json_push_kv_bool(data, "machines_complete", view->complete) && ok;
    ok = json_push_kv_bool(data, "machine_agents_complete",
                           view->roster_ok && !view->truncated &&
                               fm_unique_machine_boxes(view) && view->workers_complete &&
                               view->unbound_workers == 0) && ok;
    ok = json_push_kv_int(data, "machine_agents_unbound_total",
                          (int64_t)view->unbound_workers) && ok;
    ok = json_push_kv_str(data, "machines_reason",
        view->complete
            ? "verified roster, fresh signed vitals and board-bound workers"
            : "machine heartbeat, vitals or agent evidence is missing, stale, discrepant or unbound") && ok;
    return ok;
}
