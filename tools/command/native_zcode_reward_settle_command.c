/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-8 `zcode reward` settlement leaves —
 * the SIMULATED ZCODE reward flow (placeholder token id only; never the
 * real token; no on-chain payout in v1 — the real ZSLP transfer is the
 * owner-reviewed slice-14 flow and is NOT built here):
 *
 *   zcode reward queue    inspect the daily settlement queue: per-state
 *                         tallies and bounded pages over the durable
 *                         queue records (queued/planned/settled/rejected)
 *   zcode reward plan     assemble ONE settlement window batch from the
 *                         eligible queued entries, applying the slice-7
 *                         period caps against the reward-history ledger;
 *                         every exclusion names its exact rule; the only
 *                         mutation is the persisted plan id
 *   zcode reward commit   settle a planned batch SIMULATED under the
 *                         placeholder token id: ledger facts + queue
 *                         transitions + the commit record (the idempotence
 *                         authority, written last — a crash between commit
 *                         and ledger write replays safely, and re-settling
 *                         the same plan is a named duplicate, never a
 *                         double-pay). Unknown/stale plans are rejected
 *                         with named rules
 *   zcode reward receipt  the durable receipt for a settled batch —
 *                         entries, points, placeholder token id, window —
 *                         the evidence for the future real transfer
 *
 * Truth discipline (unchanged from slices 3-7): durable wires under
 * <datadir>/zcode/rewards are the only reward truth; the ledger is
 * replayed into memory on every call, so a one-shot CLI agrees with a
 * node. Claims (manual categories) queue with their evidence root but are
 * blocked from settlement with owner-review-required until slice 14. */

#include "base/hex.h"
#include "command/native_command.h"

#include "json/json.h"
#include "vcs/package_reward.h"

#include <stdio.h>
#include <string.h>

/* Display page bound (the zcode list budget). */
#define ZS8_PAGE_CAP 32u
#define ZS8_PLAN_ROWS_CAP 64u

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zs8_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zs8_datadir(const struct zcl_command_request *request)
{
    const char *dd = zs8_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve the datadir and load the replayed reward ledger, or fail the
 * reply with a named error. */
static struct vcs_reward_ledger *zs8_ledger_load(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *command)
{
    const char *datadir = zs8_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return NULL;
    }
    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return NULL;
    }
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode_dir);
    if (!l) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LEDGER_LOAD",
                               "execute", false, false,
                               "the reward ledger could not be replayed",
                               zcode_dir);
        return NULL;
    }
    return l;
}

static bool zs8_plan_id_input(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply,
                              uint8_t plan_id[32])
{
    const char *hex = zs8_input_str(request->input, "plan_id");
    if (!hex || !zcl_hex_decode(hex, plan_id, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PLAN_ID",
                               "normalize", false, false,
                               "plan_id must be a 64-hex settlement plan id",
                               hex ? hex : "");
        return false;
    }
    return true;
}

/* A bounded paging window over `total` rows. */
static size_t zs8_page(const struct json_value *input, size_t total,
                       size_t *limit_out, bool *truncated_out)
{
    size_t limit = 16;
    const struct json_value *lv = json_get(input, "limit");
    if (lv && json_get_int(lv) > 0)
        limit = (size_t)json_get_int(lv);
    if (limit > ZS8_PAGE_CAP)
        limit = ZS8_PAGE_CAP;
    size_t offset = 0;
    const struct json_value *ov = json_get(input, "offset");
    if (ov && json_get_int(ov) > 0)
        offset = (size_t)json_get_int(ov);
    if (offset > total)
        offset = total;
    size_t shown = total - offset;
    if (shown > limit)
        shown = limit;
    *limit_out = shown;
    *truncated_out = offset + shown < total;
    return offset;
}

static void zs8_push_entry_row(struct json_value *row,
                               const struct vcs_reward_entry *e)
{
    char hex[67];
    zcl_hex_encode(e->entry_id, 32, hex);
    (void)json_push_kv_str(row, "entry_id", hex);
    zcl_hex_encode(e->release_root, 32, hex);
    (void)json_push_kv_str(row, "release_root", hex);
    zcl_hex_encode(e->contributor, 33, hex);
    (void)json_push_kv_str(row, "contributor", hex);
    (void)json_push_kv_str(row, "kind", vcs_reward_kind_string(e->kind));
    (void)json_push_kv_str(row, "category",
                           vcs_reward_category_string(e->category));
    (void)json_push_kv_int(row, "points", (int64_t)e->points);
    (void)json_push_kv_str(row, "state",
                           vcs_reward_state_string(e->state));
    if (e->has_evidence_root) {
        zcl_hex_encode(e->evidence_root, 32, hex);
        (void)json_push_kv_str(row, "evidence_root", hex);
    }
    if (e->state == VCS_REWARD_STATE_PLANNED) {
        zcl_hex_encode(e->planned_by, 32, hex);
        (void)json_push_kv_str(row, "planned_by", hex);
    }
    if (e->state == VCS_REWARD_STATE_SETTLED) {
        zcl_hex_encode(e->settled_by_plan, 32, hex);
        (void)json_push_kv_str(row, "settled_by", hex);
        (void)json_push_kv_int(row, "settled_day",
                               (int64_t)e->settled_day);
    }
    if (e->state == VCS_REWARD_STATE_REJECTED)
        (void)json_push_kv_str(row, "rejected_rule", e->rejected_rule);
}

/* The state filter index for a queue state name, or -1 when unknown. */
static int zs8_queue_state_index(const char *state)
{
    for (int s = 0; s <= (int)VCS_REWARD_STATE_REJECTED; s++) {
        if (strcmp(state, vcs_reward_state_string(
                              (enum vcs_reward_state)s)) == 0)
            return s;
    }
    return -1;
}

static void zs8_push_queue_summary(struct json_value *data,
                                   struct vcs_reward_ledger *l)
{
    struct vcs_reward_queue_tally tally;
    vcs_reward_queue_tally(l, &tally);
    (void)json_push_kv_int(data, "total_entries",
                           (int64_t)vcs_reward_ledger_entry_count(l));
    (void)json_push_kv_int(data, "settled_facts",
                           (int64_t)vcs_reward_ledger_fact_count(l));
    struct json_value tallies;
    json_init(&tallies);
    json_set_object(&tallies);
    (void)json_push_kv_int(&tallies, "queued", (int64_t)tally.queued);
    (void)json_push_kv_int(&tallies, "planned", (int64_t)tally.planned);
    (void)json_push_kv_int(&tallies, "settled", (int64_t)tally.settled);
    (void)json_push_kv_int(&tallies, "rejected", (int64_t)tally.rejected);
    (void)json_push_kv(data, "tallies", &tallies);
    json_free(&tallies);
}

static size_t zs8_queue_match_count(struct vcs_reward_ledger *l,
                                    int state_filter)
{
    size_t matches = 0;
    for (size_t i = 0; i < vcs_reward_ledger_entry_count(l); i++) {
        const struct vcs_reward_entry *e = vcs_reward_ledger_entry_at(l, i);
        if (state_filter >= 0 && (int)e->state != state_filter)
            continue;
        matches++;
    }
    return matches;
}

/* Push the bounded page of queue rows; returns how many were emitted. */
static size_t zs8_push_queue_rows(struct json_value *data,
                                  struct vcs_reward_ledger *l,
                                  int state_filter, size_t offset,
                                  size_t shown)
{
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    size_t seen = 0, emitted = 0;
    for (size_t i = 0; i < vcs_reward_ledger_entry_count(l) &&
                        emitted < shown; i++) {
        const struct vcs_reward_entry *e = vcs_reward_ledger_entry_at(l, i);
        if (state_filter >= 0 && (int)e->state != state_filter)
            continue;
        if (seen++ < offset)
            continue;
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        zs8_push_entry_row(&row, e);
        (void)json_push_back(&rows, &row);
        json_free(&row);
        emitted++;
    }
    (void)json_push_kv(data, "rows", &rows);
    json_free(&rows);
    return emitted;
}

/* The plan-persist failure reply; the caller frees the ledger and plan
 * before calling. */
static void zs8_plan_persist_fail(struct zcl_command_reply *reply,
                                  enum vcs_reward_plan_persist_error perr)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL,
                           perr == VCS_REWARD_PLAN_PERSIST_FULL
                               ? "PLAN_STORE_FULL"
                               : "PLAN_PERSIST_IO",
                           "execute", false, false,
                           perr == VCS_REWARD_PLAN_PERSIST_FULL
                               ? "the plan store reached its bound"
                               : "the plan wire could not be persisted",
                           "rewards/plans");
}

static uint32_t zs8_plan_recipients(struct vcs_reward_ledger *l,
                                    struct vcs_reward_plan *plan)
{
    uint32_t recipients = 0;
    for (size_t i = 0; i < plan->row_count; i++) {
        if (plan->rows[i].disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, plan->rows[i].entry_id);
        if (!e)
            continue;
        bool seen = false;
        for (size_t j = 0; j < i && !seen; j++) {
            if (plan->rows[j].disposition != VCS_REWARD_DISP_PLANNED)
                continue;
            const struct vcs_reward_entry *p =
                vcs_reward_ledger_find(l, plan->rows[j].entry_id);
            if (p && memcmp(p->contributor, e->contributor, 33) == 0)
                seen = true;
        }
        if (!seen)
            recipients++;
    }
    return recipients;
}

/* Push the bounded batch of planned rows; returns how many were emitted. */
static size_t zs8_plan_push_batch(struct json_value *data,
                                  struct vcs_reward_ledger *l,
                                  struct vcs_reward_plan *plan)
{
    char hex[67];
    struct json_value batch;
    json_init(&batch);
    json_set_array(&batch);
    size_t emitted = 0;
    for (size_t i = 0; i < plan->row_count && emitted < ZS8_PLAN_ROWS_CAP;
         i++) {
        if (plan->rows[i].disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, plan->rows[i].entry_id);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        zcl_hex_encode(plan->rows[i].entry_id, 32, hex);
        (void)json_push_kv_str(&row, "entry_id", hex);
        if (e) {
            zcl_hex_encode(e->contributor, 33, hex);
            (void)json_push_kv_str(&row, "contributor", hex);
            (void)json_push_kv_str(&row, "category",
                                   vcs_reward_category_string(e->category));
        }
        (void)json_push_kv_int(&row, "points_requested",
                               (int64_t)plan->rows[i].points_requested);
        (void)json_push_kv_int(&row, "points_settled",
                               (int64_t)plan->rows[i].points_settled);
        if (plan->rows[i].weekly_cap_clamped)
            (void)json_push_kv_bool(&row, "weekly_cap_clamped", true);
        (void)json_push_back(&batch, &row);
        json_free(&row);
        emitted++;
    }
    (void)json_push_kv(data, "batch", &batch);
    json_free(&batch);
    return emitted;
}

/* Push the bounded exclusion rows; returns how many were emitted. */
static size_t zs8_plan_push_exclusions(struct json_value *data,
                                       struct vcs_reward_plan *plan)
{
    char hex[67];
    struct json_value exclusions;
    json_init(&exclusions);
    json_set_array(&exclusions);
    size_t emitted = 0;
    for (size_t i = 0; i < plan->row_count && emitted < ZS8_PLAN_ROWS_CAP;
         i++) {
        if (plan->rows[i].disposition == VCS_REWARD_DISP_PLANNED)
            continue;
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        zcl_hex_encode(plan->rows[i].entry_id, 32, hex);
        (void)json_push_kv_str(&row, "entry_id", hex);
        (void)json_push_kv_str(
            &row, "disposition",
            vcs_reward_disposition_string(plan->rows[i].disposition));
        (void)json_push_kv_str(&row, "rule", plan->rows[i].rule);
        (void)json_push_kv_int(&row, "points_requested",
                               (int64_t)plan->rows[i].points_requested);
        (void)json_push_back(&exclusions, &row);
        json_free(&row);
        emitted++;
    }
    (void)json_push_kv(data, "exclusions", &exclusions);
    json_free(&exclusions);
    return emitted;
}

/* ── zcode reward queue ─────────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_queue(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct vcs_reward_ledger *l =
        zs8_ledger_load(request, reply, "zcode.reward.queue");
    if (!l)
        return;

    /* Optional state filter. */
    int state_filter = -1;
    const char *state = zs8_input_str(request->input, "state");
    if (state && state[0]) {
        state_filter = zs8_queue_state_index(state);
        if (state_filter < 0) {
            vcs_reward_ledger_free(l);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "BAD_STATE_FILTER", "normalize", false,
                                   false,
                                   "state must be queued, planned, settled, "
                                   "or rejected", state);
            return;
        }
    }

    zs8_push_queue_summary(&reply->data, l);

    /* Filtered matching count, then the bounded page. */
    size_t matches = zs8_queue_match_count(l, state_filter);
    size_t shown = 0;
    bool truncated = false;
    size_t offset = zs8_page(request->input, matches, &shown, &truncated);
    size_t emitted = zs8_push_queue_rows(&reply->data, l, state_filter,
                                         offset, shown);
    (void)json_push_kv_int(&reply->data, "total_matches", (int64_t)matches);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)emitted);
    (void)json_push_kv_bool(&reply->data, "items_truncated", truncated);
    (void)json_push_kv_int(&reply->data, "corrupt_wires",
                           (int64_t)vcs_reward_ledger_corrupt_count(l));
    (void)json_push_kv_bool(&reply->data, "store_truncated",
                            vcs_reward_ledger_truncated(l));
    (void)json_push_kv_str(
        &reply->data, "queue_note",
        "the durable queue records under <datadir>/zcode/rewards replay on "
        "every call; planned is derived (named by an uncommitted plan); "
        "claims stay queued with owner-review-required until slice 14");
    vcs_reward_ledger_free(l);
}

/* ── zcode reward plan ──────────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct vcs_reward_ledger *l =
        zs8_ledger_load(request, reply, "zcode.reward.plan");
    if (!l)
        return;

    const struct json_value *dayv = json_get(request->input, "day");
    if (!dayv) {
        vcs_reward_ledger_free(l);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DAY",
                               "normalize", false, false,
                               "day (the settlement window, a civil day "
                               "number) is required — an explicit window "
                               "keeps the batch deterministic", "");
        return;
    }
    int64_t day = json_get_int(dayv);
    if (day < 0) {
        vcs_reward_ledger_free(l);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_DAY",
                               "normalize", false, false,
                               "day must be a non-negative civil day number",
                               "day");
        return;
    }

    struct vcs_reward_plan plan;
    if (!vcs_reward_plan_build(l, day, &plan)) {
        vcs_reward_ledger_free(l);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "PLAN_BUILD",
                               "execute", false, false,
                               "the settlement batch could not be assembled",
                               "day");
        return;
    }
    enum vcs_reward_plan_persist_error perr =
        vcs_reward_plan_persist(l, &plan);
    if (perr != VCS_REWARD_PLAN_PERSIST_OK &&
        perr != VCS_REWARD_PLAN_PERSIST_DUPLICATE) {
        vcs_reward_plan_free(&plan);
        vcs_reward_ledger_free(l);
        zs8_plan_persist_fail(reply, perr);
        return;
    }

    char hex[67];
    zcl_hex_encode(plan.plan_id, 32, hex);
    (void)json_push_kv_str(&reply->data, "plan_id", hex);
    (void)json_push_kv_int(&reply->data, "day", (int64_t)plan.day);
    (void)json_push_kv_bool(&reply->data, "already_persisted",
                            perr == VCS_REWARD_PLAN_PERSIST_DUPLICATE);
    (void)json_push_kv_int(&reply->data, "entries_planned",
                           (int64_t)plan.planned_count);
    (void)json_push_kv_int(&reply->data, "entries_deferred",
                           (int64_t)plan.deferred_count);
    (void)json_push_kv_int(&reply->data, "entries_blocked",
                           (int64_t)plan.blocked_count);
    (void)json_push_kv_int(&reply->data, "entries_duplicate",
                           (int64_t)plan.duplicate_count);
    (void)json_push_kv_int(&reply->data, "points_total",
                           (int64_t)plan.points_total);

    /* Distinct recipients in the batch. */
    uint32_t recipients = zs8_plan_recipients(l, &plan);
    (void)json_push_kv_int(&reply->data, "recipients", (int64_t)recipients);

    /* The batch (planned rows), bounded. */
    size_t emitted = zs8_plan_push_batch(&reply->data, l, &plan);
    (void)json_push_kv_bool(&reply->data, "batch_truncated",
                            plan.planned_count > emitted);

    /* Every exclusion with its named rule, bounded. */
    size_t excluded = plan.deferred_count + plan.blocked_count +
                      plan.duplicate_count;
    emitted = zs8_plan_push_exclusions(&reply->data, &plan);
    (void)json_push_kv_bool(&reply->data, "exclusions_truncated",
                            excluded > emitted);

    char token_hex[65];
    vcs_reward_placeholder_token_id_hex(token_hex);
    (void)json_push_kv_str(&reply->data, "placeholder_token_id", token_hex);
    (void)json_push_kv_bool(&reply->data, "simulated", true);
    (void)json_push_kv_str(
        &reply->data, "settlement_note",
        "SIMULATED settlement: one batched send per settlement window under "
        "the placeholder token id — never the real ZCODE token; no ZCL fee "
        "is spent and no ZSLP transfer is built here (the owner-reviewed "
        "real transfer, with the exact fee preview, is slice 14)");
    (void)json_push_kv_str(
        &reply->data, "caps_note",
        "the slice-7 period caps were applied against the durable "
        "reward-history ledger batch-atomically; deferred entries stay "
        "queued for a later window; blocked entries are claims awaiting "
        "owner review");
    vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(l);
}

/* ── zcode reward commit ────────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct vcs_reward_ledger *l =
        zs8_ledger_load(request, reply, "zcode.reward.commit");
    if (!l)
        return;
    uint8_t plan_id[32];
    if (!zs8_plan_id_input(request, reply, plan_id)) {
        vcs_reward_ledger_free(l);
        return;
    }
    char plan_hex[65];
    zcl_hex_encode(plan_id, 32, plan_hex);

    char detail[256];
    struct vcs_reward_commit_result result;
    enum vcs_reward_commit_error cerr =
        vcs_reward_commit(l, plan_id, &result, detail, sizeof(detail));
    if (cerr != VCS_REWARD_COMMIT_OK) {
        const char *code = "COMMIT_FAILED";
        const char *message = "the settlement batch could not be committed";
        const char *evidence = plan_hex;
        switch (cerr) {
        case VCS_REWARD_COMMIT_UNKNOWN_PLAN:
            code = "UNKNOWN_PLAN";
            message = "no persisted plan names this plan id";
            break;
        case VCS_REWARD_COMMIT_ALREADY_SETTLED:
            code = "ALREADY_SETTLED";
            message = "this window was already settled: the commit record "
                      "exists, so re-settling is a duplicate — never a "
                      "double-pay; read the receipt for the original batch";
            break;
        case VCS_REWARD_COMMIT_STALE:
            code = "STALE_PLAN";
            message = "the plan no longer matches the queue (an entry is "
                      "missing, rejected, or settled by another plan); "
                      "re-plan the window";
            evidence = detail[0] ? detail : plan_hex;
            break;
        case VCS_REWARD_COMMIT_CAPS_CHANGED:
            code = "CAPS_CHANGED";
            message = "the reward-history ledger moved since this plan was "
                      "made; the recomputed caps disagree — re-plan the "
                      "window";
            evidence = detail[0] ? detail : plan_hex;
            break;
        case VCS_REWARD_COMMIT_IO:
            code = "COMMIT_IO";
            message = "a durable write failed mid-commit; the partial "
                      "state is resumable — re-commit the same plan id";
            break;
        case VCS_REWARD_COMMIT_OK: break;
        }
        vcs_reward_ledger_free(l);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               cerr == VCS_REWARD_COMMIT_ALREADY_SETTLED,
                               false, message, evidence);
        return;
    }

    (void)json_push_kv_str(&reply->data, "plan_id", plan_hex);
    (void)json_push_kv_int(&reply->data, "settled_count",
                           (int64_t)result.settled_count);
    (void)json_push_kv_int(&reply->data, "rejected_count",
                           (int64_t)result.rejected_count);
    (void)json_push_kv_int(&reply->data, "points_settled",
                           (int64_t)result.points_settled);
    (void)json_push_kv_bool(&reply->data, "resumed", result.resumed);
    /* The receipt doubles as the day/window lookup. */
    struct vcs_reward_receipt receipt;
    if (vcs_reward_receipt_load(l, plan_id, &receipt) ==
        VCS_REWARD_RECEIPT_OK) {
        (void)json_push_kv_int(&reply->data, "day",
                               (int64_t)receipt.day);
        vcs_reward_receipt_free(&receipt);
    }
    char token_hex[65];
    vcs_reward_placeholder_token_id_hex(token_hex);
    (void)json_push_kv_str(&reply->data, "placeholder_token_id", token_hex);
    (void)json_push_kv_bool(&reply->data, "simulated", true);
    (void)json_push_kv_bool(&reply->data, "receipt_available", true);
    (void)json_push_kv_str(
        &reply->data, "settlement_note",
        "SIMULATED settlement under the placeholder token id: ledger facts "
        "are durable and re-settling this plan id is a named duplicate, "
        "never a double-pay; no ZSLP transfer exists (slice 14)");
    vcs_reward_ledger_free(l);
}

/* ── zcode reward receipt ───────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_receipt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct vcs_reward_ledger *l =
        zs8_ledger_load(request, reply, "zcode.reward.receipt");
    if (!l)
        return;
    uint8_t plan_id[32];
    if (!zs8_plan_id_input(request, reply, plan_id)) {
        vcs_reward_ledger_free(l);
        return;
    }
    char plan_hex[65];
    zcl_hex_encode(plan_id, 32, plan_hex);

    struct vcs_reward_receipt receipt;
    enum vcs_reward_receipt_error rerr =
        vcs_reward_receipt_load(l, plan_id, &receipt);
    if (rerr != VCS_REWARD_RECEIPT_OK) {
        const char *code = "RECEIPT_IO";
        const char *message = "the commit record is unreadable";
        switch (rerr) {
        case VCS_REWARD_RECEIPT_UNKNOWN_PLAN:
            code = "UNKNOWN_PLAN";
            message = "no persisted plan names this plan id";
            break;
        case VCS_REWARD_RECEIPT_NOT_SETTLED:
            code = "NOT_SETTLED";
            message = "the plan exists but was never committed: no settled "
                      "batch, no receipt";
            break;
        case VCS_REWARD_RECEIPT_OK:
        case VCS_REWARD_RECEIPT_IO: break;
        }
        vcs_reward_ledger_free(l);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               false, false, message, plan_hex);
        return;
    }

    (void)json_push_kv_str(&reply->data, "plan_id", plan_hex);
    (void)json_push_kv_int(&reply->data, "day", (int64_t)receipt.day);
    char token_hex[65];
    zcl_hex_encode(receipt.token_id, 32, token_hex);
    (void)json_push_kv_str(&reply->data, "placeholder_token_id", token_hex);
    (void)json_push_kv_int(&reply->data, "settled_count",
                           (int64_t)receipt.settled_count);
    (void)json_push_kv_int(&reply->data, "rejected_count",
                           (int64_t)receipt.rejected_count);
    (void)json_push_kv_int(&reply->data, "points_total",
                           (int64_t)receipt.points_total);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < receipt.row_count; i++) {
        const struct vcs_reward_receipt_row *r = &receipt.rows[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        char hex[67];
        zcl_hex_encode(r->entry_id, 32, hex);
        (void)json_push_kv_str(&row, "entry_id", hex);
        zcl_hex_encode(r->contributor, 33, hex);
        (void)json_push_kv_str(&row, "contributor", hex);
        (void)json_push_kv_str(&row, "category",
                               vcs_reward_category_string(r->category));
        (void)json_push_kv_str(&row, "outcome",
                               r->outcome == VCS_REWARD_RECEIPT_SETTLED
                                   ? "settled"
                                   : "rejected");
        if (r->outcome == VCS_REWARD_RECEIPT_REJECTED)
            (void)json_push_kv_str(&row, "rule", r->rule);
        (void)json_push_kv_int(&row, "points", (int64_t)r->points);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "entries", &rows);
    json_free(&rows);
    (void)json_push_kv_bool(&reply->data, "simulated", true);
    (void)json_push_kv_str(
        &reply->data, "receipt_note",
        "the durable evidence of one SIMULATED batched settlement window "
        "under the placeholder token id: when the owner-reviewed slice-14 "
        "flow makes the real ZSLP transfer, this receipt is the batch it "
        "must reproduce — one send, these recipients, these amounts");
    vcs_reward_receipt_free(&receipt);
    vcs_reward_ledger_free(l);
}
