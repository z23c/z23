/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One chainlog per box, with bounded indexes over verified rows.
 * Chainlog operations hold exclusive whole-file locks only during the
 * operation; ledger handles retain neither an open chainlog nor its lock.
 * Append re-reads the tail under that lock before assigning the next sequence.
 *
 * Opening verifies every held chain. load_us measures that work separately
 * from index_us, which measures the subsequent in-memory query.
 *
 * The day index retains ZCL_FLEET_INDEX_DAYS of detail. Older cells fold
 * into series remainders. Rows without a free day cell also enter their
 * remainder and increment index_overflow, exposing incomplete daily detail.
 * Latest-vitals slots retain row sequence, timestamp and explicit absence
 * independently of day aggregation.
 */

#include "fleetledger/fleet_ledger.h"
#include "fleet_ledger_replay.h"
#include "fleet_ledger_experiment.h"

#include "util/fleet_role_check.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "chainlog/chainlog.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_CHAINLOG_KIND 1u
#define FLEET_DIR_PEER "peer"
#define FLEET_SELF_FILE "self.chainlog"

/* One (box, kind, subject, day) cell. `value` is combined by each key's
 * declared merge class, and `state` is the byte that keeps a measured zero
 * apart from a key no row ever carried. */
struct fleet_cell {
    bool used;
    uint8_t box;      /* index into ledger->box[] */
    uint8_t kind;
    uint16_t subject;
    uint32_t day;
    uint64_t rows;
    int64_t last_ts;
    int64_t value[ZCL_FLEET_PAIR_KEY_MAX + 1];
    uint8_t state[ZCL_FLEET_PAIR_KEY_MAX + 1];
};

/* One (box, kind, subject) whole-history remainder: everything outside the
 * day window, so a total never depends on the window. */
struct fleet_series {
    bool used;
    uint8_t box;
    uint8_t kind;
    uint16_t subject;
    uint64_t rows;
    int64_t last_ts;
    int64_t value[ZCL_FLEET_PAIR_KEY_MAX + 1];
    uint8_t state[ZCL_FLEET_PAIR_KEY_MAX + 1];
};

struct fleet_box {
    bool used;
    bool is_self;
    uint8_t id[ZCL_FLEET_ID_BYTES];
    uint64_t rows;
    uint64_t last_seq;
    int64_t last_ts;
    uint8_t head_hash[ZCL_FLEET_HASH_BYTES];
};

struct zcl_fleet_ledger {
    char dir[512];
    bool read_only;
    bool have_self;
    uint8_t self_id[ZCL_FLEET_ID_BYTES];
    uint8_t self_signer[ZCL_FLEET_ID_BYTES];
    struct fleet_box box[ZCL_FLEET_BOXES_MAX];
    struct fleet_cell *cell;     /* ZCL_FLEET_INDEX_CELLS */
    struct fleet_series *series; /* ZCL_FLEET_INDEX_SERIES */
    struct fleet_experiment_event *experiment;
    uint32_t experiment_count;
    uint64_t experiment_overflow;
    struct zcl_fleet_vital_latest *latest;
    size_t latest_subjects;
    uint32_t newest_day;
    uint64_t overflow;
    struct history_collect *history;
};

/* ── paths and stream ids ────────────────────────────────────────────── */

/* A chain's stream id binds the file to the box it is a log OF, so a
 * replica file copied over another box's replica is STREAM_MISMATCH rather
 * than a silent adoption of someone else's history. */
static void chain_stream(const uint8_t box_id[ZCL_FLEET_ID_BYTES],
                         uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"zcl.fleet_ledger.chain.v1",
                   sizeof("zcl.fleet_ledger.chain.v1"));
    sha3_256_write(&ctx, (const unsigned char *)box_id, ZCL_FLEET_ID_BYTES);
    sha3_256_finalize(&ctx, (unsigned char *)out);
}

static bool chain_path(const struct zcl_fleet_ledger *l,
                       const uint8_t box_id[ZCL_FLEET_ID_BYTES], char *out,
                       size_t cap)
{
    if (l->have_self && memcmp(box_id, l->self_id, ZCL_FLEET_ID_BYTES) == 0)
        return (size_t)snprintf(out, cap, "%s/%s", l->dir, FLEET_SELF_FILE) <
               cap;
    char hex[2 * ZCL_FLEET_ID_BYTES + 1] = { 0 };
    zcl_hex_encode(box_id, ZCL_FLEET_ID_BYTES, hex);
    return (size_t)snprintf(out, cap, "%s/%s/%s.chainlog", l->dir,
                            FLEET_DIR_PEER, hex) < cap;
}

/* ── box table ───────────────────────────────────────────────────────── */

static struct fleet_box *box_find(struct zcl_fleet_ledger *l,
                                  const uint8_t id[ZCL_FLEET_ID_BYTES])
{
    for (size_t i = 0; i < ZCL_FLEET_BOXES_MAX; i++)
        if (l->box[i].used &&
            memcmp(l->box[i].id, id, ZCL_FLEET_ID_BYTES) == 0)
            return &l->box[i];
    return NULL;
}

static struct fleet_box *box_intern(struct zcl_fleet_ledger *l,
                                    const uint8_t id[ZCL_FLEET_ID_BYTES],
                                    bool is_self)
{
    struct fleet_box *found = box_find(l, id);
    if (found)
        return found;
    for (size_t i = 0; i < ZCL_FLEET_BOXES_MAX; i++) {
        if (l->box[i].used)
            continue;
        l->box[i].used = true;
        l->box[i].is_self = is_self;
        memcpy(l->box[i].id, id, ZCL_FLEET_ID_BYTES);
        return &l->box[i];
    }
    return NULL;
}

static uint8_t box_index(const struct zcl_fleet_ledger *l,
                         const struct fleet_box *box)
{
    return (uint8_t)(box - l->box);
}

/* ── index ───────────────────────────────────────────────────────────── */

static struct fleet_series *series_for(struct zcl_fleet_ledger *l, uint8_t box,
                                       uint8_t kind, uint16_t subject)
{
    struct fleet_series *free_slot = NULL;
    for (size_t i = 0; i < ZCL_FLEET_INDEX_SERIES; i++) {
        struct fleet_series *s = &l->series[i];
        if (!s->used) {
            if (!free_slot)
                free_slot = s;
            continue;
        }
        if (s->box == box && s->kind == kind && s->subject == subject)
            return s;
    }
    if (!free_slot)
        return NULL;
    free_slot->used = true;
    free_slot->box = box;
    free_slot->kind = kind;
    free_slot->subject = subject;
    return free_slot;
}

/* Apply one row's pairs by their declared merge class. A COUNTER adds; an
 * LWW or OWNER_ONLY key takes the latest statement. "Latest" is the row
 * that arrives last, and rows only ever arrive in chain order — load walks
 * seq ascending, append writes seq+1, replicate appends ascending — so the
 * chain's own order decides, never the writer's clock. */
static void accumulate(int64_t *value, uint8_t *state,
                       const struct zcl_fleet_row *row)
{
    for (size_t i = 0; i < row->pair_count; i++) {
        uint8_t key = row->pair[i].key;
        enum zcl_fleet_merge merge =
            zcl_fleet_pair_merge(row->kind, row->subject, key);
        if (merge == ZCL_FLEET_MERGE_COUNTER &&
            state[key] == ZCL_FLEET_FIELD_PRESENT)
            value[key] += row->pair[i].value;
        else
            value[key] = row->pair[i].value;
        state[key] = ZCL_FLEET_FIELD_PRESENT;
    }
}

/* Fold one cell into its series remainder and free the slot. The remainder
 * is combined by the same classes: a counter's days add, and a gauge's
 * remainder keeps the newest day it saw rather than a meaningless total. */
static void cell_fold(struct zcl_fleet_ledger *l, struct fleet_cell *c)
{
    struct fleet_series *s = series_for(l, c->box, c->kind, c->subject);
    if (s) {
        s->rows += c->rows;
        bool newer = c->last_ts >= s->last_ts;
        if (newer)
            s->last_ts = c->last_ts;
        for (size_t k = 0; k <= ZCL_FLEET_PAIR_KEY_MAX; k++) {
            if (c->state[k] != ZCL_FLEET_FIELD_PRESENT)
                continue;
            enum zcl_fleet_merge merge =
                zcl_fleet_pair_merge(c->kind, c->subject, (uint8_t)k);
            if (merge == ZCL_FLEET_MERGE_COUNTER &&
                s->state[k] == ZCL_FLEET_FIELD_PRESENT)
                s->value[k] += c->value[k];
            else if (merge == ZCL_FLEET_MERGE_COUNTER ||
                     s->state[k] != ZCL_FLEET_FIELD_PRESENT || newer)
                s->value[k] = c->value[k];
            s->state[k] = ZCL_FLEET_FIELD_PRESENT;
        }
    }
    memset(c, 0, sizeof(*c));
}

/* Every cell older than the window is folded. Runs only when the newest day
 * advances, so the cost is one pass per day rather than one per row. */
static void index_age_out(struct zcl_fleet_ledger *l)
{
    if (l->newest_day + 1 < ZCL_FLEET_INDEX_DAYS)
        return;
    uint32_t oldest = l->newest_day + 1 - ZCL_FLEET_INDEX_DAYS;
    for (size_t i = 0; i < ZCL_FLEET_INDEX_CELLS; i++)
        if (l->cell[i].used && l->cell[i].day < oldest)
            cell_fold(l, &l->cell[i]);
}

static void latest_index_row(struct zcl_fleet_ledger *l, uint8_t box,
                              const struct zcl_fleet_row *row)
{
    if (row->kind == ZCL_FLEET_KIND_VITALS &&
        row->subject < l->latest_subjects && box < ZCL_FLEET_BOXES_MAX) {
        struct zcl_fleet_vital_latest *v =
            &l->latest[(size_t)box * l->latest_subjects + row->subject];
        if (row->seq > v->seq) {
            memset(v, 0, sizeof *v);
            memcpy(v->box_id, row->box_id, sizeof v->box_id);
            v->subject = row->subject;
            v->seq = row->seq;
            v->ts_unix = row->ts_unix;
            for (size_t i = 0; i < row->pair_count; i++) {
                if (row->pair[i].key == ZCL_FLEET_PAIR_VALUE) {
                    v->present = true;
                    v->value = row->pair[i].value;
                }
            }
        }
    }
}

static void cell_touch(struct fleet_cell *c, const struct zcl_fleet_row *row)
{
    c->rows++;
    if (row->ts_unix > c->last_ts)
        c->last_ts = row->ts_unix;
    accumulate(c->value, c->state, row);
}

/* True when the row landed in a day cell (existing or fresh). */
static bool index_cell_row(struct zcl_fleet_ledger *l, uint8_t box,
                           const struct zcl_fleet_row *row, uint32_t day)
{
    struct fleet_cell *free_slot = NULL;
    for (size_t i = 0; i < ZCL_FLEET_INDEX_CELLS; i++) {
        struct fleet_cell *c = &l->cell[i];
        if (!c->used) {
            if (!free_slot)
                free_slot = c;
            continue;
        }
        if (c->box == box && c->kind == row->kind &&
            c->subject == row->subject && c->day == day) {
            cell_touch(c, row);
            return true;
        }
    }
    if (free_slot) {
        free_slot->used = true;
        free_slot->box = box;
        free_slot->kind = row->kind;
        free_slot->subject = row->subject;
        free_slot->day = day;
        free_slot->rows = 0;
        free_slot->last_ts = row->ts_unix;
        cell_touch(free_slot, row);
        return true;
    }
    /* The pool is full. The row still counts toward its total; what is
     * lost is the per-day detail, and that loss is counted. */
    l->overflow++;
    return false;
}

static void index_row(struct zcl_fleet_ledger *l, uint8_t box,
                      const struct zcl_fleet_row *row, bool *cellular)
{
    latest_index_row(l, box, row);
    uint32_t day = zcl_fleet_day_of(row->ts_unix);
    if (day > l->newest_day) {
        l->newest_day = day;
        index_age_out(l);
    }
    bool in_window = l->newest_day + 1 < ZCL_FLEET_INDEX_DAYS ||
                     day >= l->newest_day + 1 - ZCL_FLEET_INDEX_DAYS;
    if (in_window && index_cell_row(l, box, row, day)) {
        if (cellular)
            *cellular = true;
        return;
    }
    struct fleet_series *s = series_for(l, box, row->kind, row->subject);
    if (!s) {
        l->overflow++;
        return;
    }
    s->rows++;
    if (row->ts_unix > s->last_ts)
        s->last_ts = row->ts_unix;
    accumulate(s->value, s->state, row);
}

static int64_t pair_value(const struct zcl_fleet_row *row, uint8_t key,
                          bool *present)
{
    for (size_t i = 0; i < row->pair_count; i++) {
        if (row->pair[i].key == key) {
            *present = true;
            return row->pair[i].value;
        }
    }
    *present = false;
    return 0;
}

/* Keep one event per experiment row so stats can take medians and pair
 * predict against result by task_id. Merged day cells cannot do that. */
/* One pair, read once and never re-derived: `*have_out` is exactly whether
 * the row carried `key`, and `*val_out` is its value or 0 when absent. */
static void ev_pair(const struct zcl_fleet_row *row, uint8_t key,
                    bool *have_out, int64_t *val_out)
{
    bool present = false;
    int64_t v = pair_value(row, key, &present);
    *have_out = present;
    *val_out = v;
}

/* Everything export needs that stats does not: the box, the free-text
 * story, the closed-vocabulary executor/harness/effort, and each token and
 * change-size counter kept separately rather than summed. Split out of
 * `index_experiment` so neither function needs to reason about the other's
 * fields to stay under the complexity bound. */
static void index_experiment_extra(struct fleet_experiment_event *e,
                                   const struct zcl_fleet_row *row)
{
    e->ts_unix = row->ts_unix;
    memcpy(e->box_id, row->box_id, ZCL_FLEET_ID_BYTES);
    e->story_len = row->story_len;
    if (row->story_len)
        memcpy(e->story, row->story, row->story_len);
    bool have = false;
    int64_t v = 0;
    ev_pair(row, ZCL_FLEET_PAIR_EXECUTOR, &have, &v);
    e->have_executor = have;
    e->executor = (uint8_t)v;
    ev_pair(row, ZCL_FLEET_PAIR_HARNESS, &e->have_harness, &v);
    e->harness = (uint8_t)v;
    ev_pair(row, ZCL_FLEET_PAIR_EFFORT, &e->have_effort, &v);
    e->effort = (uint8_t)v;
    ev_pair(row, ZCL_FLEET_PAIR_TOKENS_IN, &e->have_tokens_in, &e->tokens_in);
    ev_pair(row, ZCL_FLEET_PAIR_TOKENS_OUT, &e->have_tokens_out,
           &e->tokens_out);
    ev_pair(row, ZCL_FLEET_PAIR_TOKENS_CACHED, &e->have_tokens_cache,
           &e->tokens_cache);
    ev_pair(row, ZCL_FLEET_PAIR_TOKENS_REASONING, &e->have_tokens_reasoning,
           &e->tokens_reasoning);
    ev_pair(row, ZCL_FLEET_PAIR_TOOL_USES, &e->have_tool_uses,
           &e->tool_uses);
    ev_pair(row, ZCL_FLEET_PAIR_TURNS, &e->have_turns, &e->turns);
    ev_pair(row, ZCL_FLEET_PAIR_LINES_ADDED, &e->have_lines_added,
           &e->lines_added);
    ev_pair(row, ZCL_FLEET_PAIR_LINES_REMOVED, &e->have_lines_removed,
           &e->lines_removed);
    ev_pair(row, ZCL_FLEET_PAIR_DEFECTS, &e->have_defects, &e->defects);
}

static void index_experiment(struct zcl_fleet_ledger *l,
                             const struct zcl_fleet_row *row)
{
    if (row->kind != ZCL_FLEET_KIND_EXPERIMENT)
        return;
    if (l->experiment_count >= FLEET_EXPERIMENT_EVENTS_MAX) {
        l->experiment_overflow++;
        return;
    }
    struct fleet_experiment_event *e = &l->experiment[l->experiment_count++];
    memset(e, 0, sizeof(*e));
    e->phase = (uint8_t)row->subject;
    e->note_len = row->note_len;
    if (row->note_len)
        memcpy(e->note, row->note, row->note_len);
    bool present = false;
    e->task_class = (uint8_t)pair_value(row, ZCL_FLEET_PAIR_TASK_CLASS, &present);
    e->model = (uint8_t)pair_value(row, ZCL_FLEET_PAIR_MODEL, &present);
    e->outcome = (uint8_t)pair_value(row, ZCL_FLEET_PAIR_OUTCOME, &present);
    int64_t tokens = 0;
    bool have = false;
    int64_t v = pair_value(row, ZCL_FLEET_PAIR_TOKENS_IN, &present);
    if (present) {
        tokens += v;
        have = true;
    }
    v = pair_value(row, ZCL_FLEET_PAIR_TOKENS_OUT, &present);
    if (present) {
        tokens += v;
        have = true;
    }
    /* Reasoning is already in output, and cached input already in input.
     * Those subsets alone cannot establish a measured total. */
    e->tokens = tokens;
    e->have_tokens = have;
    e->wall_s = pair_value(row, ZCL_FLEET_PAIR_WALL_S, &present);
    e->have_wall = present;
    index_experiment_extra(e, row);
}

uint64_t zcl_fleet_ledger_index_overflow(const struct zcl_fleet_ledger *l)
{
    return l ? l->overflow : 0;
}

/* ── loading one chain ───────────────────────────────────────────────── */

static bool chain_absent(const struct zcl_fleet_ledger *l, const char *path)
{
    return l->read_only && platform_private_path_absent(path);
}

static enum zcl_fleet_status chain_open_error(enum zcl_chainlog_status status)
{
    return status == ZCL_CHAINLOG_BROKEN_CHAIN ? ZCL_FLEET_CHAIN_BROKEN
                                               : ZCL_FLEET_IO;
}

static struct zcl_chainlog *ledger_chain_open(const struct zcl_fleet_ledger *l,
    const char *path, const uint8_t stream[32], struct zcl_chainlog_report *rep)
{
    struct zcl_chainlog *log = l->read_only
        ? zcl_chainlog_open_readonly(path, stream, rep)
        : zcl_chainlog_open(path, stream, rep);
    /* A status result cannot silently hide an interrupted append. Leave the
     * tail for the writer's normal recovery and refuse this observation. */
    if (l->read_only && log && rep->torn_bytes) {
        zcl_chainlog_close(log);
        rep->status = ZCL_CHAINLOG_IO;
        return NULL;
    }
    return log;
}

static bool chain_frame_read(struct zcl_chainlog *log, uint64_t seq,
    uint8_t *buf, size_t cap, size_t *len)
{
    uint32_t kind = 0;
    return zcl_chainlog_read(log, seq, &kind, buf, cap, len) ==
               ZCL_CHAINLOG_OK && kind == FLEET_CHAINLOG_KIND;
}

/* Read every frame of one box's chain, verify each row's signature and its
 * link to the row before it, and put it in the index. A refusal names the
 * sequence number and stops: a chain that was altered is evidence, and
 * skipping past the alteration would throw the evidence away. */
static enum zcl_fleet_status chain_load(struct zcl_fleet_ledger *l,
                                        struct fleet_box *box,
                                        struct zcl_fleet_report *report)
{
    char path[600];
    if (!chain_path(l, box->id, path, sizeof path))
        return ZCL_FLEET_ARGUMENT;
    uint8_t stream[32];
    chain_stream(box->id, stream);

    struct zcl_chainlog_report rep;
    if (chain_absent(l, path))
        return ZCL_FLEET_OK;
    struct zcl_chainlog *log = ledger_chain_open(l, path, stream, &rep);
    if (!log) {
        memcpy(report->bad_box, box->id, ZCL_FLEET_ID_BYTES);
        report->first_bad_seq = rep.first_bad_seq;
        LOG_ERROR("fleet.ledger", "chain open refused: %s",
                  zcl_chainlog_status_label(rep.status));
        return chain_open_error(rep.status);
    }

    enum zcl_fleet_status status = ZCL_FLEET_OK;
    uint64_t total = zcl_chainlog_count(log);
    fleet_replay_history_begin(l->history, box->id);
    uint8_t expect[ZCL_FLEET_HASH_BYTES] = { 0 };
    uint8_t buf[ZCL_FLEET_ROW_MAX_BYTES];
    for (uint64_t seq = 1; seq <= total; seq++) {
        size_t len = 0;
        if (!chain_frame_read(log, seq, buf, sizeof buf, &len)) {
            status = ZCL_FLEET_IO;
            report->first_bad_seq = seq;
            memcpy(report->bad_box, box->id, ZCL_FLEET_ID_BYTES);
            break;
        }
        struct zcl_fleet_row row;
        status = fleet_replay_verify_row(buf, len, seq, box->id, expect, &row);
        if (status != ZCL_FLEET_OK) {
            report->first_bad_seq = seq;
            memcpy(report->bad_box, box->id, ZCL_FLEET_ID_BYTES);
            break;
        }
        zcl_fleet_row_hash(buf, len, expect);
        fleet_replay_history_row(l->history, &row, expect);
        bool cellular = false;
        index_row(l, box_index(l, box), &row, &cellular);
        index_experiment(l, &row);
        if (cellular)
            report->indexed++;
        else
            report->folded++;
        report->rows++;
        box->rows++;
        box->last_seq = row.seq;
        box->last_ts = row.ts_unix;
    }
    memcpy(box->head_hash, expect, ZCL_FLEET_HASH_BYTES);
    zcl_chainlog_close(log);
    return status;
}

/* ── open / close ────────────────────────────────────────────────────── */

static bool ledger_directory(const char *path, bool read_only)
{
    if (!read_only) return platform_private_directory_ensure(path);
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated_traverse(path, &retained))
        return false;
    platform_private_directory_close(retained);
    return true;
}

/* Every peer replica in `<dir>/peer` whose name is a 64-hex box id. A name
 * that is not one is not adopted: a file this store did not write is not a
 * box, and guessing would let anything dropped in the directory become one. */
static enum zcl_fleet_status load_peers(struct zcl_fleet_ledger *l,
                                        struct zcl_fleet_report *report)
{
    char peerdir[540];
    if ((size_t)snprintf(peerdir, sizeof peerdir, "%s/%s", l->dir,
                         FLEET_DIR_PEER) >= sizeof peerdir)
        return ZCL_FLEET_ARGUMENT;
    if (l->read_only && platform_private_path_absent(peerdir))
        return ZCL_FLEET_OK;
    if (!ledger_directory(peerdir, l->read_only))
        return ZCL_FLEET_IO;

    struct platform_directory_list files;
    memset(&files, 0, sizeof files);
    if (!platform_directory_list_regular_sorted(peerdir, &files))
        return ZCL_FLEET_IO;

    enum zcl_fleet_status status = ZCL_FLEET_OK;
    static const char suffix[] = ".chainlog";
    const size_t name_len = 2 * ZCL_FLEET_ID_BYTES + sizeof suffix - 1;
    for (size_t i = 0; i < files.count && status == ZCL_FLEET_OK; i++) {
        const char *name = files.entries[i].name;
        if (!name || strlen(name) != name_len ||
            strcmp(name + 2 * ZCL_FLEET_ID_BYTES, suffix) != 0)
            continue;
        char hex[2 * ZCL_FLEET_ID_BYTES + 1];
        memcpy(hex, name, 2 * ZCL_FLEET_ID_BYTES);
        hex[2 * ZCL_FLEET_ID_BYTES] = '\0';
        uint8_t id[ZCL_FLEET_ID_BYTES];
        if (!zcl_hex_decode_lower(hex, id, ZCL_FLEET_ID_BYTES))
            continue;
        struct fleet_box *box = box_intern(l, id, false);
        if (!box) {
            status = ZCL_FLEET_FULL;
            break;
        }
        status = chain_load(l, box, report);
        if (status == ZCL_FLEET_OK)
            report->boxes++;
    }
    platform_directory_list_free(&files);
    return status;
}

static struct zcl_fleet_ledger *ledger_allocate(struct zcl_fleet_report *report)
{
    struct zcl_fleet_ledger *l = zcl_calloc(1, sizeof *l, "fleet_ledger");
    if (!l) {
        report->status = ZCL_FLEET_IO;
        return NULL;
    }
    l->cell = zcl_calloc(ZCL_FLEET_INDEX_CELLS, sizeof *l->cell,
                         "fleet_ledger_cells");
    l->series = zcl_calloc(ZCL_FLEET_INDEX_SERIES, sizeof *l->series,
                           "fleet_ledger_series");
    l->experiment = zcl_calloc(FLEET_EXPERIMENT_EVENTS_MAX,
                               sizeof *l->experiment, "fleet_experiment_events");
    l->latest_subjects = zcl_fleet_vital_count();
    l->latest = zcl_calloc(ZCL_FLEET_BOXES_MAX * l->latest_subjects,
                           sizeof *l->latest, "fleet_vitals_latest");
    if (!l->cell || !l->series || !l->experiment || !l->latest) {
        report->status = ZCL_FLEET_IO;
        zcl_fleet_ledger_close(l);
        return NULL;
    }
    return l;
}

static struct zcl_fleet_ledger *ledger_open(
    const char *dir, const uint8_t self_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t self_signer[ZCL_FLEET_ID_BYTES],
    struct zcl_fleet_report *report, bool read_only,
    struct history_collect *history)
{
    if (!report) return NULL;
    memset(report, 0, sizeof(*report));
    /* A relative directory or half an identity cannot name this store. */
    if ((self_box_id && !self_signer) || !dir || dir[0] != '/') {
        report->status = ZCL_FLEET_ARGUMENT;
        return NULL;
    }
    int64_t start = platform_time_monotonic_us();
    struct zcl_fleet_ledger *l = ledger_allocate(report);
    if (!l) return NULL;
    if ((size_t)snprintf(l->dir, sizeof l->dir, "%s", dir) >= sizeof l->dir) {
        report->status = ZCL_FLEET_ARGUMENT;
        zcl_fleet_ledger_close(l);
        return NULL;
    }
    l->read_only = read_only;
    l->history = history;
    if (!ledger_directory(l->dir, read_only)) {
        report->status = ZCL_FLEET_IO;
        zcl_fleet_ledger_close(l);
        return NULL;
    }

    if (self_box_id) {
        l->have_self = true;
        memcpy(l->self_id, self_box_id, ZCL_FLEET_ID_BYTES);
        memcpy(l->self_signer, self_signer, ZCL_FLEET_ID_BYTES);
        struct fleet_box *self = box_intern(l, self_box_id, true);
        if (!self) {
            report->status = ZCL_FLEET_FULL;
            zcl_fleet_ledger_close(l);
            return NULL;
        }
        report->status = chain_load(l, self, report);
        if (report->status != ZCL_FLEET_OK) {
            zcl_fleet_ledger_close(l);
            return NULL;
        }
        report->boxes++;
    }

    report->status = load_peers(l, report);
    if (report->status != ZCL_FLEET_OK) {
        zcl_fleet_ledger_close(l);
        return NULL;
    }
    int64_t end = platform_time_monotonic_us();
    report->load_us = end > start ? (uint64_t)(end - start) : 0u;
    return l;
}

struct zcl_fleet_ledger *zcl_fleet_ledger_open(
    const char *dir, const uint8_t self_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t self_signer[ZCL_FLEET_ID_BYTES], struct zcl_fleet_report *report)
{
    return ledger_open(dir, self_box_id, self_signer, report, false, NULL);
}

struct zcl_fleet_ledger *zcl_fleet_ledger_open_readonly(
    const char *dir, const uint8_t self_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t self_signer[ZCL_FLEET_ID_BYTES], struct zcl_fleet_report *report)
{
    return ledger_open(dir, self_box_id, self_signer, report, true, NULL);
}

struct zcl_fleet_ledger *fleet_replay_open_readonly(
    const char *dir, const uint8_t *self_box, const uint8_t *self_signer,
    struct zcl_fleet_report *report, struct history_collect *history)
{
    return ledger_open(dir, self_box, self_signer, report, true, history);
}

void zcl_fleet_ledger_close(struct zcl_fleet_ledger *ledger)
{
    if (!ledger)
        return;
    free(ledger->latest);
    free(ledger->cell);
    free(ledger->series);
    free(ledger->experiment);
    free(ledger);
}

/* ── append ──────────────────────────────────────────────────────────── */

static bool ledger_writable(const struct zcl_fleet_ledger *l)
{
    return l && !l->read_only;
}

/* The tail of a chain, read inside the chainlog's own exclusive lock. This
 * is what makes two appending processes safe: whoever holds the lock sees
 * the other's row before composing its own. */
static enum zcl_fleet_status chain_tail(struct zcl_chainlog *log,
                                        uint64_t *seq_out,
                                        uint8_t hash_out[ZCL_FLEET_HASH_BYTES])
{
    uint64_t count = zcl_chainlog_count(log);
    *seq_out = count;
    memset(hash_out, 0, ZCL_FLEET_HASH_BYTES);
    if (count == 0)
        return ZCL_FLEET_OK;
    uint8_t buf[ZCL_FLEET_ROW_MAX_BYTES];
    uint32_t kind = 0;
    size_t len = 0;
    if (zcl_chainlog_read(log, count, &kind, buf, sizeof buf, &len) !=
            ZCL_CHAINLOG_OK ||
        kind != FLEET_CHAINLOG_KIND)
        return ZCL_FLEET_IO;
    zcl_fleet_row_hash(buf, len, hash_out);
    return ZCL_FLEET_OK;
}

static enum zcl_fleet_status append_check_args(
    const struct zcl_fleet_ledger *ledger, uint8_t kind,
    const struct zcl_fleet_pair *pairs, size_t pair_count, const char *note,
    const char *story, const uint8_t *seed)
{
    if (!ledger_writable(ledger) || !seed || (!pairs && pair_count))
        return ZCL_FLEET_ARGUMENT;
    if (!ledger->have_self)
        return ZCL_FLEET_ARGUMENT;
    if (!zcl_fleet_kind_name(kind))
        return ZCL_FLEET_KIND_UNKNOWN;
    if (!zcl_fleet_kind_writable(kind))
        return ZCL_FLEET_KIND_NOT_WRITABLE;
    if (pair_count > ZCL_FLEET_PAIRS_MAX)
        return ZCL_FLEET_ARGUMENT;
    size_t note_len = note ? strlen(note) : 0;
    if (note_len > ZCL_FLEET_NOTE_MAX)
        return ZCL_FLEET_ARGUMENT;
    size_t story_len = story ? strlen(story) : 0;
    if (story_len > ZCL_FLEET_STORY_MAX)
        return ZCL_FLEET_ARGUMENT;
    return ZCL_FLEET_OK;
}

/* Fill the unsigned row from already-validated arguments; false when the
 * wall clock is not usable. */
static bool append_row_fill(struct zcl_fleet_row *row,
                            const struct zcl_fleet_ledger *ledger,
                            uint8_t kind, uint16_t subject,
                            const struct zcl_fleet_pair *pairs,
                            size_t pair_count, const char *note,
                            const char *story)
{
    size_t note_len = note ? strlen(note) : 0;
    size_t story_len = story ? strlen(story) : 0;
    memset(row, 0, sizeof *row);
    row->version = ZCL_FLEET_ROW_VERSION;
    row->kind = kind;
    row->subject = subject;
    row->pair_count = (uint8_t)pair_count;
    row->note_len = (uint8_t)note_len;
    if (note_len)
        memcpy(row->note, note, note_len);
    row->story_len = (uint8_t)story_len;
    if (story_len)
        memcpy(row->story, story, story_len);
    for (size_t i = 0; i < pair_count; i++)
        row->pair[i] = pairs[i];
    memcpy(row->box_id, ledger->self_id, ZCL_FLEET_ID_BYTES);
    memcpy(row->signer, ledger->self_signer, ZCL_FLEET_ID_BYTES);
    row->ts_unix = (int64_t)platform_time_wall_time_t();
    return row->ts_unix > 0;
}

/* Sign, encode and append the row under the chainlog's own lock. */
static enum zcl_fleet_status append_row_store(
    const struct zcl_fleet_ledger *ledger, struct zcl_fleet_row *row,
    const uint8_t seed[ZCL_FLEET_SEED_BYTES],
    uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES], size_t *len)
{
    char path[600];
    if (!chain_path(ledger, ledger->self_id, path, sizeof path))
        return ZCL_FLEET_ARGUMENT;
    uint8_t stream[32];
    chain_stream(ledger->self_id, stream);
    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &rep);
    if (!log)
        return ZCL_FLEET_IO;

    uint64_t tail_seq = 0;
    enum zcl_fleet_status status = chain_tail(log, &tail_seq, row->prev_hash);
    if (status == ZCL_FLEET_OK) {
        row->seq = tail_seq + 1;
        status = zcl_fleet_row_sign(row, seed);
    }
    *len = 0;
    if (status == ZCL_FLEET_OK) {
        *len = zcl_fleet_row_encode(row, encoded, ZCL_FLEET_ROW_MAX_BYTES);
        if (*len == 0)
            status = ZCL_FLEET_MALFORMED;
    }
    if (status == ZCL_FLEET_OK &&
        zcl_chainlog_append(log, FLEET_CHAINLOG_KIND, encoded, *len, NULL,
                            NULL) != ZCL_CHAINLOG_OK)
        status = ZCL_FLEET_IO;
    zcl_chainlog_close(log);
    return status;
}

enum zcl_fleet_status zcl_fleet_ledger_append(
    struct zcl_fleet_ledger *ledger, uint8_t kind, uint16_t subject,
    const struct zcl_fleet_pair *pairs, size_t pair_count, const char *note,
    const char *story, const uint8_t seed[ZCL_FLEET_SEED_BYTES],
    uint64_t *out_seq)
{
    uint64_t unused_seq;
    if (!out_seq)
        out_seq = &unused_seq;
    *out_seq = 0;
    enum zcl_fleet_status status = append_check_args(
        ledger, kind, pairs, pair_count, note, story, seed);
    if (status != ZCL_FLEET_OK)
        return status;

    struct zcl_fleet_row row;
    if (!append_row_fill(&row, ledger, kind, subject, pairs, pair_count, note,
                         story))
        return ZCL_FLEET_ARGUMENT;

    uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES];
    size_t len = 0;
    status = append_row_store(ledger, &row, seed, encoded, &len);
    if (status != ZCL_FLEET_OK)
        return status;

    struct fleet_box *box = box_find(ledger, ledger->self_id);
    if (box) {
        box->rows++;
        box->last_seq = row.seq;
        box->last_ts = row.ts_unix;
        zcl_fleet_row_hash(encoded, len, box->head_hash);
        index_row(ledger, box_index(ledger, box), &row, NULL);
        index_experiment(ledger, &row);
    }
    *out_seq = row.seq;
    return ZCL_FLEET_OK;
}

/* ── serving and receiving a pull ────────────────────────────────────── */

uint64_t zcl_fleet_ledger_peer_seq(const struct zcl_fleet_ledger *ledger,
                                   const uint8_t box_id[ZCL_FLEET_ID_BYTES])
{
    if (!ledger || !box_id)
        return 0;
    const struct fleet_box *box =
        box_find((struct zcl_fleet_ledger *)ledger, box_id);
    return box ? box->last_seq : 0;
}

enum zcl_fleet_status zcl_fleet_ledger_read_since(
    struct zcl_fleet_ledger *ledger, const uint8_t box_id[ZCL_FLEET_ID_BYTES],
    uint64_t since_seq, uint8_t *out, size_t cap, size_t *len,
    uint64_t *last_seq)
{
    if (!ledger || !box_id || !out || !len)
        return ZCL_FLEET_ARGUMENT;
    *len = 0;
    if (last_seq)
        *last_seq = since_seq;
    char path[600];
    if (!chain_path(ledger, box_id, path, sizeof path))
        return ZCL_FLEET_ARGUMENT;
    uint8_t stream[32];
    chain_stream(box_id, stream);
    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = ledger_chain_open(ledger, path, stream, &rep);
    if (!log)
        return ZCL_FLEET_IO;

    enum zcl_fleet_status status = ZCL_FLEET_OK;
    uint64_t total = zcl_chainlog_count(log);
    size_t written = 0;
    uint64_t sent = 0;
    for (uint64_t seq = since_seq + 1;
         seq <= total && sent < ZCL_FLEET_BATCH_MAX; seq++) {
        uint32_t kind = 0;
        size_t row_len = 0;
        uint8_t buf[ZCL_FLEET_ROW_MAX_BYTES];
        if (zcl_chainlog_read(log, seq, &kind, buf, sizeof buf, &row_len) !=
                ZCL_CHAINLOG_OK ||
            kind != FLEET_CHAINLOG_KIND) {
            status = ZCL_FLEET_IO;
            break;
        }
        if (written + row_len > cap)
            break; /* a short answer, not a truncated row */
        memcpy(out + written, buf, row_len);
        written += row_len;
        sent++;
        if (last_seq)
            *last_seq = seq;
    }
    zcl_chainlog_close(log);
    if (status == ZCL_FLEET_OK)
        *len = written;
    return status;
}

/* Does the key that signed this batch hold a role granting replication of
 * this row's KIND on this box? Asked through the seam, so this module never
 * learns where the grant store lives — and refused when nothing answers.
 *
 * `kinds_seen` remembers the kinds already allowed inside ONE batch. Every
 * row in a batch carries the same signer (the caller has just proven that),
 * so the only thing that varies is the kind, and the closed kind vocabulary
 * is smaller than the bitmap. That turns a 64-row batch into at most one
 * store lookup per distinct kind instead of one per row. */
static bool replicate_role_allows(const uint8_t signer[ZCL_FLEET_ID_BYTES],
                                  uint8_t kind, uint32_t *kinds_seen)
{
    uint32_t bit = kind < 32u ? (uint32_t)1u << kind : 0u;
    if (bit && (*kinds_seen & bit))
        return true;
    char why[ZCL_FLEET_ROLE_WHY_MAX];
    if (!zcl_fleet_role_allows(signer, ZCL_FLEET_LEAF_LEDGER_REPLICATE,
                               zcl_fleet_kind_name(kind), why, sizeof why)) {
        /* The reason names the key by fingerprint prefix and the leaf, and
         * nothing about the rows: what a peer measured is the owner's
         * private data and a log is not private. */
        LOG_WARN("fleet.ledger", "%s", why);
        return false;
    }
    *kinds_seen |= bit;
    return true;
}

/* Everything about one decoded row that must hold before ANY byte of the
 * batch is written, in the order that answers the cheapest question first.
 * Three different refusals, because they are three different problems: a
 * row claiming another machine is a peer writing outside its own ownership;
 * a row signed by a key this peer's delegation does not delegate is a link
 * carrying somebody else's authority; and a row from a key with no role is
 * a key this box has simply never decided to accept writes from. */
static enum zcl_fleet_status replicate_row_admissible(
    const struct zcl_fleet_row *row,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t peer_signer[ZCL_FLEET_ID_BYTES], uint32_t *kinds_seen)
{
    if (memcmp(row->box_id, peer_box_id, ZCL_FLEET_ID_BYTES) != 0)
        return ZCL_FLEET_NOT_OWNER;
    if (memcmp(row->signer, peer_signer, ZCL_FLEET_ID_BYTES) != 0)
        return ZCL_FLEET_PEER_UNPAIRED;
    if (!replicate_role_allows(row->signer, row->kind, kinds_seen))
        return ZCL_FLEET_ROLE_REFUSED;
    return ZCL_FLEET_OK;
}

/* Does this row continue the chain exactly where the last one left off, and
 * is it signed? */
static enum zcl_fleet_status replicate_row_links(
    const struct zcl_fleet_row *row, uint64_t next_seq,
    const uint8_t expect[ZCL_FLEET_HASH_BYTES])
{
    if (row->seq != next_seq)
        return ZCL_FLEET_SEQUENCE;
    if (memcmp(row->prev_hash, expect, ZCL_FLEET_HASH_BYTES) != 0)
        return ZCL_FLEET_CHAIN_BROKEN;
    return zcl_fleet_row_verify(row);
}

/* Validation reads an existing head or an empty one; it owns no peer slot. */
static enum zcl_fleet_status replicate_validate(
    const struct fleet_box *box,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t peer_signer[ZCL_FLEET_ID_BYTES], const uint8_t *rows,
    size_t len, struct zcl_fleet_row batch[ZCL_FLEET_BATCH_MAX],
    size_t *validated)
{
    size_t count = 0;
    *validated = 0;
    size_t offset = 0;
    uint8_t expect[ZCL_FLEET_HASH_BYTES];
    memcpy(expect, box->head_hash, ZCL_FLEET_HASH_BYTES);
    uint64_t next_seq = box->last_seq + 1;
    uint32_t kinds_seen = 0;

    while (offset < len) {
        if (count >= ZCL_FLEET_BATCH_MAX)
            return ZCL_FLEET_FULL;
        struct zcl_fleet_row row;
        size_t used = 0;
        enum zcl_fleet_status st =
            zcl_fleet_row_decode(rows + offset, len - offset, &row, &used);
        if (st != ZCL_FLEET_OK)
            return st;
        offset += used;
        st = replicate_row_admissible(&row, peer_box_id, peer_signer,
                                      &kinds_seen);
        if (st != ZCL_FLEET_OK)
            return st;
        if (row.seq < next_seq)
            continue; /* already held: a second pull is a no-op */
        st = replicate_row_links(&row, next_seq, expect);
        if (st != ZCL_FLEET_OK)
            return st;
        uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES];
        size_t enc = zcl_fleet_row_encode(&row, encoded, sizeof encoded);
        if (enc == 0)
            return ZCL_FLEET_MALFORMED;
        zcl_fleet_row_hash(encoded, enc, expect);
        batch[count++] = row;
        next_seq++;
    }
    *validated = count;
    return ZCL_FLEET_OK;
}

/* Reserve storage only after the complete nonempty batch has qualified. */
static enum zcl_fleet_status replicate_store(
    struct zcl_fleet_ledger *ledger,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const struct zcl_fleet_row *batch, size_t count, size_t *accepted)
{
    struct fleet_box *box = box_intern(ledger, peer_box_id, false);
    if (!box)
        return ZCL_FLEET_FULL;
    char path[600];
    if (!chain_path(ledger, peer_box_id, path, sizeof path))
        return ZCL_FLEET_ARGUMENT;
    uint8_t stream[32];
    chain_stream(peer_box_id, stream);
    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &rep);
    if (!log)
        return ZCL_FLEET_IO;
    /* The tail is re-read under the lock: another process may have taken
     * the same rows while this batch was being checked. */
    uint64_t tail_seq = 0;
    uint8_t tail_hash[ZCL_FLEET_HASH_BYTES];
    enum zcl_fleet_status status = chain_tail(log, &tail_seq, tail_hash);
    size_t stored = 0;
    for (size_t i = 0; i < count && status == ZCL_FLEET_OK; i++) {
        if (batch[i].seq <= tail_seq)
            continue;
        if (batch[i].seq != tail_seq + 1 ||
            memcmp(batch[i].prev_hash, tail_hash, ZCL_FLEET_HASH_BYTES) != 0) {
            status = ZCL_FLEET_CHAIN_BROKEN;
            break;
        }
        uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES];
        size_t enc = zcl_fleet_row_encode(&batch[i], encoded, sizeof encoded);
        if (enc == 0 ||
            zcl_chainlog_append(log, FLEET_CHAINLOG_KIND, encoded, enc, NULL,
                                NULL) != ZCL_CHAINLOG_OK) {
            status = ZCL_FLEET_IO;
            break;
        }
        zcl_fleet_row_hash(encoded, enc, tail_hash);
        tail_seq = batch[i].seq;
        index_row(ledger, box_index(ledger, box), &batch[i], NULL);
        index_experiment(ledger, &batch[i]);
        box->rows++;
        box->last_seq = batch[i].seq;
        box->last_ts = batch[i].ts_unix;
        memcpy(box->head_hash, tail_hash, ZCL_FLEET_HASH_BYTES);
        stored++;
    }
    zcl_chainlog_close(log);
    if (status == ZCL_FLEET_OK && accepted)
        *accepted = stored;
    return status;
}

enum zcl_fleet_status zcl_fleet_ledger_replicate(
    struct zcl_fleet_ledger *ledger,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t peer_signer[ZCL_FLEET_ID_BYTES], const uint8_t *rows,
    size_t len, size_t *accepted)
{
    if (!ledger_writable(ledger) || !peer_box_id || !peer_signer || (!rows && len))
        return ZCL_FLEET_ARGUMENT;
    if (accepted)
        *accepted = 0;
    if (ledger->have_self &&
        memcmp(peer_box_id, ledger->self_id, ZCL_FLEET_ID_BYTES) == 0)
        return ZCL_FLEET_PEER_UNPAIRED;

    struct fleet_box empty = { 0 };
    struct fleet_box *box = box_find(ledger, peer_box_id);
    if (!box)
        box = &empty;
    struct zcl_fleet_row batch[ZCL_FLEET_BATCH_MAX];
    size_t count = 0;
    enum zcl_fleet_status status = replicate_validate(
        box, peer_box_id, peer_signer, rows, len, batch, &count);
    if (status != ZCL_FLEET_OK || count == 0)
        return status;
    return replicate_store(ledger, peer_box_id, batch, count, accepted);
}

/* ── querying ────────────────────────────────────────────────────────── */

size_t zcl_fleet_ledger_boxes(const struct zcl_fleet_ledger *ledger,
                              struct zcl_fleet_box_status *out, size_t cap)
{
    if (!ledger || !out)
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < ZCL_FLEET_BOXES_MAX && n < cap; i++) {
        if (!ledger->box[i].used)
            continue;
        memcpy(out[n].box_id, ledger->box[i].id, ZCL_FLEET_ID_BYTES);
        out[n].is_self = ledger->box[i].is_self;
        out[n].rows = ledger->box[i].rows;
        out[n].last_seq = ledger->box[i].last_seq;
        out[n].last_ts = ledger->box[i].last_ts;
        n++;
    }
    return n;
}

static struct zcl_fleet_bucket *bucket_for(struct zcl_fleet_bucket *out,
                                           size_t cap, size_t *count,
                                           const uint8_t box_id[32],
                                           uint16_t subject)
{
    for (size_t i = 0; i < *count; i++)
        if (out[i].subject == subject &&
            memcmp(out[i].box_id, box_id, ZCL_FLEET_ID_BYTES) == 0)
            return &out[i];
    if (*count >= cap)
        return NULL;
    struct zcl_fleet_bucket *b = &out[(*count)++];
    memset(b, 0, sizeof(*b));
    memcpy(b->box_id, box_id, ZCL_FLEET_ID_BYTES);
    b->subject = subject;
    return b;
}

static bool query_cell_selected(const struct zcl_fleet_ledger *ledger,
                                const struct fleet_cell *c,
                                const struct zcl_fleet_query *query,
                                uint32_t oldest, uint32_t today)
{
    if (!c->used || c->kind != query->kind)
        return false;
    if (c->day < oldest || c->day > today)
        return false;
    if (query->have_subject && c->subject != query->subject)
        return false;
    return !query->have_box ||
           memcmp(ledger->box[c->box].id, query->box_id,
                  ZCL_FLEET_ID_BYTES) == 0;
}

static void query_add_cell(struct zcl_fleet_bucket *b, const struct fleet_cell *c)
{
    b->rows += c->rows;
    /* Cells are visited in pool order, not day order, so an LWW key
     * takes the cell with the newest timestamp rather than the last one
     * the walk happened to reach. Within a cell the chain's order
     * already decided; between cells of one series, the day does. */
    bool newer = c->last_ts >= b->last_ts;
    if (newer)
        b->last_ts = c->last_ts;
    for (size_t k = 0; k <= ZCL_FLEET_PAIR_KEY_MAX; k++) {
        if (c->state[k] != ZCL_FLEET_FIELD_PRESENT)
            continue;
        enum zcl_fleet_merge merge =
            zcl_fleet_pair_merge(c->kind, c->subject, (uint8_t)k);
        if (merge == ZCL_FLEET_MERGE_COUNTER &&
            b->state[k] == ZCL_FLEET_FIELD_PRESENT)
            b->value[k] += c->value[k];
        else if (merge == ZCL_FLEET_MERGE_COUNTER ||
                 b->state[k] != ZCL_FLEET_FIELD_PRESENT || newer)
            b->value[k] = c->value[k];
        b->state[k] = ZCL_FLEET_FIELD_PRESENT;
    }
}

enum zcl_fleet_status zcl_fleet_ledger_query(
    const struct zcl_fleet_ledger *ledger, const struct zcl_fleet_query *query,
    struct zcl_fleet_bucket *out, size_t cap, size_t *count,
    uint64_t *index_us)
{
    if (!ledger || !query || !out || !count)
        return ZCL_FLEET_ARGUMENT;
    *count = 0;
    if (index_us)
        *index_us = 0;
    if (query->days == 0 || query->days > ZCL_FLEET_INDEX_DAYS)
        return ZCL_FLEET_WINDOW;
    if (!zcl_fleet_kind_name(query->kind))
        return ZCL_FLEET_KIND_UNKNOWN;

    /* Cells only. No file is opened and no lock is taken; this is the walk
     * whose cost the caller prints. */
    int64_t start = platform_time_monotonic_us();
    uint32_t today = zcl_fleet_day_of(query->now_unix);
    uint32_t oldest = query->days - 1 <= today ? today - (query->days - 1) : 0;
    enum zcl_fleet_status status = ZCL_FLEET_OK;

    for (size_t i = 0; i < ZCL_FLEET_INDEX_CELLS; i++) {
        const struct fleet_cell *c = &ledger->cell[i];
        if (!query_cell_selected(ledger, c, query, oldest, today))
            continue;
        const struct fleet_box *box = &ledger->box[c->box];
        struct zcl_fleet_bucket *b =
            bucket_for(out, cap, count, box->id, c->subject);
        if (!b) {
            status = ZCL_FLEET_FULL;
            break;
        }
        query_add_cell(b, c);
    }
    int64_t end = platform_time_monotonic_us();
    if (index_us)
        *index_us = end > start ? (uint64_t)(end - start) : 0u;
    return status;
}

uint64_t zcl_fleet_ledger_experiment_overflow(const struct zcl_fleet_ledger *l)
{
    return l ? l->experiment_overflow : 0;
}

enum zcl_fleet_status zcl_fleet_ledger_experiment_stats(
    const struct zcl_fleet_ledger *ledger,
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint64_t *unpredicted, uint64_t *index_us)
{
    if (!ledger || !out || !count)
        return ZCL_FLEET_ARGUMENT;
    *count = 0;
    if (unpredicted)
        *unpredicted = 0;
    if (index_us)
        *index_us = 0;
    int64_t start = platform_time_monotonic_us();
    uint64_t unmatched = 0;
    enum zcl_fleet_status status = fleet_experiment_groups(
        ledger->experiment, ledger->experiment_count, out, cap, count,
        &unmatched);

    if (unpredicted)
        *unpredicted = unmatched;
    int64_t end = platform_time_monotonic_us();
    if (index_us)
        *index_us = end > start ? (uint64_t)(end - start) : 0u;
    return status;
}

enum zcl_fleet_status zcl_fleet_ledger_experiment_rows(
    const struct zcl_fleet_ledger *ledger, int64_t since_unix,
    const uint8_t box_id[ZCL_FLEET_ID_BYTES], bool have_box,
    struct zcl_fleet_experiment_row *out, size_t cap, size_t *count)
{
    if (!ledger || !out || !count)
        return ZCL_FLEET_ARGUMENT;
    *count = 0;
    return fleet_experiment_rows(ledger->experiment, ledger->experiment_count,
                                 since_unix, box_id, have_box, out, cap, count);
}

static enum zcl_fleet_status latest_box_rows(
    const struct zcl_fleet_ledger *ledger, size_t box, int subject,
    struct zcl_fleet_vital_latest *out, size_t cap, size_t *count)
{
    for (size_t s = 0; s < ledger->latest_subjects; s++) {
        if (subject >= 0 && s != (size_t)subject)
            continue;
        const struct zcl_fleet_vital_latest *v =
            &ledger->latest[box * ledger->latest_subjects + s];
        if (!v->seq)
            continue;
        if (*count == cap)
            return ZCL_FLEET_FULL;
        out[(*count)++] = *v;
    }
    return ZCL_FLEET_OK;
}

/* The dense box/catalog product has a slot for every admitted series. */
enum zcl_fleet_status zcl_fleet_ledger_vitals_latest(
    const struct zcl_fleet_ledger *ledger, const uint8_t *box_id, int subject,
    struct zcl_fleet_vital_latest *out, size_t cap, size_t *count)
{
    if (count)
        *count = 0;
    if (!ledger || !count || (cap && !out) || subject < -1)
        return ZCL_FLEET_ARGUMENT;
    if (subject >= 0 && (size_t)subject >= ledger->latest_subjects)
        return ZCL_FLEET_VITAL_UNKNOWN;
    for (size_t b = 0; b < ZCL_FLEET_BOXES_MAX; b++) {
        if (!ledger->box[b].used ||
            (box_id && memcmp(box_id, ledger->box[b].id,
                              ZCL_FLEET_ID_BYTES) != 0))
            continue;
        enum zcl_fleet_status status =
            latest_box_rows(ledger, b, subject, out, cap, count);
        if (status != ZCL_FLEET_OK)
            return status;
    }
    return ZCL_FLEET_OK;
}
