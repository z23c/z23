/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The store: one chainlog per box, one index over all of them.
 *
 * NO FILE IS HELD OPEN.
 * ---------------------
 * A chainlog takes an EXCLUSIVE whole-file lock that WAITS. That is exactly
 * right for a log with one writer, and exactly wrong for a handle kept for
 * the life of a process: the node would hold the lock forever and the
 * owner's `z23 fleet usage` would block on it until the node stopped.
 *
 * So every operation here opens, does its one thing, and closes. The node's
 * mesh service and an operator's command are two processes over one store,
 * and the lock is what makes them safe rather than what makes one of them
 * wait for the other's lifetime. An append re-reads the chain's tail INSIDE
 * that lock, so two processes appending at once produce two dense rows
 * rather than two rows claiming the same sequence number.
 *
 * The cost is that opening the ledger reads every chain once. That cost is
 * reported (`load_us`) and kept apart from the query cost (`index_us`),
 * because "the answer is instant" is a claim about the second number and
 * saying so honestly means never adding them together.
 *
 * THE INDEX IS BOUNDED, AND SAYS WHEN IT IS.
 * ------------------------------------------
 * Per-day detail is kept for ZCL_FLEET_INDEX_DAYS days per series; older
 * days are folded into that series' remainder, which keeps every TOTAL
 * exact while the per-day table stays a fixed size. A row that could not be
 * given a cell because the pool was full is still counted in its remainder
 * and is also counted in `index_overflow`, so a per-day answer that is
 * incomplete can be printed as incomplete instead of as a smaller number.
 */

#include "fleetledger/fleet_ledger.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "chainlog/chainlog.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
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

#define FLEET_EXPERIMENT_EVENTS_MAX 1024u

struct fleet_experiment_event {
    uint8_t phase;
    uint8_t task_class;
    uint8_t model;
    uint8_t outcome;
    uint8_t note_len;
    bool have_tokens;
    bool have_wall;
    char note[ZCL_FLEET_NOTE_MAX];
    int64_t tokens;
    int64_t wall_s;
};

struct zcl_fleet_ledger {
    char dir[512];
    bool have_self;
    uint8_t self_id[ZCL_FLEET_ID_BYTES];
    uint8_t self_signer[ZCL_FLEET_ID_BYTES];
    struct fleet_box box[ZCL_FLEET_BOXES_MAX];
    struct fleet_cell *cell;     /* ZCL_FLEET_INDEX_CELLS */
    struct fleet_series *series; /* ZCL_FLEET_INDEX_SERIES */
    struct fleet_experiment_event *experiment;
    uint32_t experiment_count;
    uint64_t experiment_overflow;
    uint32_t newest_day;
    uint64_t overflow;
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

static void index_row(struct zcl_fleet_ledger *l, uint8_t box,
                      const struct zcl_fleet_row *row, bool *cellular)
{
    uint32_t day = zcl_fleet_day_of(row->ts_unix);
    if (day > l->newest_day) {
        l->newest_day = day;
        index_age_out(l);
    }
    bool in_window = l->newest_day + 1 < ZCL_FLEET_INDEX_DAYS ||
                     day >= l->newest_day + 1 - ZCL_FLEET_INDEX_DAYS;
    if (in_window) {
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
                c->rows++;
                if (row->ts_unix > c->last_ts)
                    c->last_ts = row->ts_unix;
                accumulate(c->value, c->state, row);
                if (cellular)
                    *cellular = true;
                return;
            }
        }
        if (free_slot) {
            free_slot->used = true;
            free_slot->box = box;
            free_slot->kind = row->kind;
            free_slot->subject = row->subject;
            free_slot->day = day;
            free_slot->rows = 1;
            free_slot->last_ts = row->ts_unix;
            accumulate(free_slot->value, free_slot->state, row);
            if (cellular)
                *cellular = true;
            return;
        }
        /* The pool is full. The row still counts toward its total; what is
         * lost is the per-day detail, and that loss is counted. */
        l->overflow++;
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
    v = pair_value(row, ZCL_FLEET_PAIR_TOKENS_REASONING, &present);
    if (present) {
        tokens += v;
        have = true;
    }
    e->tokens = tokens;
    e->have_tokens = have;
    e->wall_s = pair_value(row, ZCL_FLEET_PAIR_WALL_S, &present);
    e->have_wall = present;
}

uint64_t zcl_fleet_ledger_index_overflow(const struct zcl_fleet_ledger *l)
{
    return l ? l->overflow : 0;
}

/* ── loading one chain ───────────────────────────────────────────────── */

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
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &rep);
    if (!log) {
        LOG_ERROR("fleet.ledger", "chain open refused: %s",
                  zcl_chainlog_status_label(rep.status));
        return rep.status == ZCL_CHAINLOG_BROKEN_CHAIN ? ZCL_FLEET_CHAIN_BROKEN
                                                       : ZCL_FLEET_IO;
    }

    enum zcl_fleet_status status = ZCL_FLEET_OK;
    uint64_t total = zcl_chainlog_count(log);
    uint8_t expect[ZCL_FLEET_HASH_BYTES] = { 0 };
    uint8_t buf[ZCL_FLEET_ROW_MAX_BYTES];
    for (uint64_t seq = 1; seq <= total && status == ZCL_FLEET_OK; seq++) {
        uint32_t kind = 0;
        size_t len = 0;
        if (zcl_chainlog_read(log, seq, &kind, buf, sizeof buf, &len) !=
                ZCL_CHAINLOG_OK ||
            kind != FLEET_CHAINLOG_KIND) {
            status = ZCL_FLEET_IO;
            report->first_bad_seq = seq;
            break;
        }
        struct zcl_fleet_row row;
        status = zcl_fleet_row_decode(buf, len, &row, NULL);
        if (status == ZCL_FLEET_OK && row.seq != seq)
            status = ZCL_FLEET_SEQUENCE;
        if (status == ZCL_FLEET_OK &&
            memcmp(row.box_id, box->id, ZCL_FLEET_ID_BYTES) != 0)
            status = ZCL_FLEET_NOT_OWNER;
        if (status == ZCL_FLEET_OK &&
            memcmp(row.prev_hash, expect, ZCL_FLEET_HASH_BYTES) != 0)
            status = ZCL_FLEET_CHAIN_BROKEN;
        if (status == ZCL_FLEET_OK)
            status = zcl_fleet_row_verify(&row);
        if (status != ZCL_FLEET_OK) {
            report->first_bad_seq = seq;
            memcpy(report->bad_box, box->id, ZCL_FLEET_ID_BYTES);
            break;
        }
        zcl_fleet_row_hash(buf, len, expect);
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
    if (!platform_private_directory_ensure(peerdir))
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

struct zcl_fleet_ledger *zcl_fleet_ledger_open(
    const char *dir, const uint8_t self_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t self_signer[ZCL_FLEET_ID_BYTES],
    struct zcl_fleet_report *report)
{
    if (!report)
        return NULL;
    memset(report, 0, sizeof(*report));
    if (self_box_id && !self_signer) {
        /* A box that can write must say which key will sign; a reader with
         * no identity passes neither. Half an identity is not one. */
        report->status = ZCL_FLEET_ARGUMENT;
        return NULL;
    }
    if (!dir || dir[0] != '/') {
        /* A relative datadir has bitten this tree before: the writer and
         * the reader resolve it against different working directories and
         * quietly use two different stores. Absolute or nothing. */
        report->status = ZCL_FLEET_ARGUMENT;
        return NULL;
    }
    int64_t start = platform_time_monotonic_us();

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
    if (!l->cell || !l->series || !l->experiment) {
        report->status = ZCL_FLEET_IO;
        zcl_fleet_ledger_close(l);
        return NULL;
    }
    if ((size_t)snprintf(l->dir, sizeof l->dir, "%s", dir) >= sizeof l->dir) {
        report->status = ZCL_FLEET_ARGUMENT;
        zcl_fleet_ledger_close(l);
        return NULL;
    }
    if (!platform_private_directory_ensure(l->dir)) {
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

void zcl_fleet_ledger_close(struct zcl_fleet_ledger *ledger)
{
    if (!ledger)
        return;
    free(ledger->cell);
    free(ledger->series);
    free(ledger->experiment);
    free(ledger);
}

/* ── append ──────────────────────────────────────────────────────────── */

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

enum zcl_fleet_status zcl_fleet_ledger_append(
    struct zcl_fleet_ledger *ledger, uint8_t kind, uint16_t subject,
    const struct zcl_fleet_pair *pairs, size_t pair_count, const char *note,
    const uint8_t seed[ZCL_FLEET_SEED_BYTES], uint64_t *out_seq)
{
    if (!ledger || !seed || (!pairs && pair_count))
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

    struct zcl_fleet_row row;
    memset(&row, 0, sizeof row);
    row.kind = kind;
    row.subject = subject;
    row.pair_count = (uint8_t)pair_count;
    row.note_len = (uint8_t)note_len;
    if (note_len)
        memcpy(row.note, note, note_len);
    for (size_t i = 0; i < pair_count; i++)
        row.pair[i] = pairs[i];
    memcpy(row.box_id, ledger->self_id, ZCL_FLEET_ID_BYTES);
    memcpy(row.signer, ledger->self_signer, ZCL_FLEET_ID_BYTES);
    row.ts_unix = (int64_t)platform_time_wall_time_t();
    if (row.ts_unix <= 0)
        return ZCL_FLEET_ARGUMENT;

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
    enum zcl_fleet_status status = chain_tail(log, &tail_seq, row.prev_hash);
    if (status == ZCL_FLEET_OK) {
        row.seq = tail_seq + 1;
        status = zcl_fleet_row_sign(&row, seed);
    }
    uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES];
    size_t len = 0;
    if (status == ZCL_FLEET_OK) {
        len = zcl_fleet_row_encode(&row, encoded, sizeof encoded);
        if (len == 0)
            status = ZCL_FLEET_MALFORMED;
    }
    if (status == ZCL_FLEET_OK &&
        zcl_chainlog_append(log, FLEET_CHAINLOG_KIND, encoded, len, NULL,
                            NULL) != ZCL_CHAINLOG_OK)
        status = ZCL_FLEET_IO;
    zcl_chainlog_close(log);
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
    if (out_seq)
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
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &rep);
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

enum zcl_fleet_status zcl_fleet_ledger_replicate(
    struct zcl_fleet_ledger *ledger,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t peer_signer[ZCL_FLEET_ID_BYTES], const uint8_t *rows,
    size_t len, size_t *accepted)
{
    if (!ledger || !peer_box_id || !peer_signer || (!rows && len))
        return ZCL_FLEET_ARGUMENT;
    if (accepted)
        *accepted = 0;
    if (ledger->have_self &&
        memcmp(peer_box_id, ledger->self_id, ZCL_FLEET_ID_BYTES) == 0)
        return ZCL_FLEET_PEER_UNPAIRED; /* nobody replicates our own chain */

    struct fleet_box *box = box_intern(ledger, peer_box_id, false);
    if (!box)
        return ZCL_FLEET_FULL;

    /* PASS ONE: decode and check everything. Not one byte is written until
     * the entire batch has been proven, so a forged row late in a batch
     * leaves the replica exactly as it was. */
    struct zcl_fleet_row batch[ZCL_FLEET_BATCH_MAX];
    size_t count = 0;
    size_t offset = 0;
    uint8_t expect[ZCL_FLEET_HASH_BYTES];
    memcpy(expect, box->head_hash, ZCL_FLEET_HASH_BYTES);
    uint64_t next_seq = box->last_seq + 1;

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
        /* Two different refusals, because they are two different problems.
         * A row claiming another machine is a peer writing outside its own
         * ownership; a row signed by a key this peer's delegation does not
         * delegate is a link carrying somebody else's authority. */
        if (memcmp(row.box_id, peer_box_id, ZCL_FLEET_ID_BYTES) != 0)
            return ZCL_FLEET_NOT_OWNER;
        if (memcmp(row.signer, peer_signer, ZCL_FLEET_ID_BYTES) != 0)
            return ZCL_FLEET_PEER_UNPAIRED;
        if (row.seq < next_seq)
            continue; /* already held: a second pull is a no-op */
        if (row.seq != next_seq)
            return ZCL_FLEET_SEQUENCE;
        if (memcmp(row.prev_hash, expect, ZCL_FLEET_HASH_BYTES) != 0)
            return ZCL_FLEET_CHAIN_BROKEN;
        st = zcl_fleet_row_verify(&row);
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
    if (count == 0)
        return ZCL_FLEET_OK;

    /* PASS TWO: write. */
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
        if (!c->used || c->kind != query->kind)
            continue;
        if (c->day < oldest || c->day > today)
            continue;
        if (query->have_subject && c->subject != query->subject)
            continue;
        const struct fleet_box *box = &ledger->box[c->box];
        if (query->have_box &&
            memcmp(box->id, query->box_id, ZCL_FLEET_ID_BYTES) != 0)
            continue;
        struct zcl_fleet_bucket *b =
            bucket_for(out, cap, count, box->id, c->subject);
        if (!b) {
            status = ZCL_FLEET_FULL;
            break;
        }
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
    int64_t end = platform_time_monotonic_us();
    if (index_us)
        *index_us = end > start ? (uint64_t)(end - start) : 0u;
    return status;
}

uint64_t zcl_fleet_ledger_experiment_overflow(const struct zcl_fleet_ledger *l)
{
    return l ? l->experiment_overflow : 0;
}

static bool notes_equal(const struct fleet_experiment_event *a,
                        const struct fleet_experiment_event *b)
{
    return a->note_len == b->note_len &&
           memcmp(a->note, b->note, a->note_len) == 0;
}

static struct zcl_fleet_experiment_group *exp_group(
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint8_t task_class, uint8_t model)
{
    for (size_t i = 0; i < *count; i++)
        if (out[i].task_class == task_class && out[i].model == model)
            return &out[i];
    if (*count >= cap)
        return NULL;
    struct zcl_fleet_experiment_group *g = &out[(*count)++];
    memset(g, 0, sizeof(*g));
    g->task_class = task_class;
    g->model = model;
    return g;
}

static int64_t median_i64(int64_t *v, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        int64_t t = v[i];
        size_t j = i;
        while (j > 0 && v[j - 1] > t) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = t;
    }
    return v[(n - 1) / 2];
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
    enum zcl_fleet_status status = ZCL_FLEET_OK;

    for (uint32_t i = 0; i < ledger->experiment_count; i++) {
        const struct fleet_experiment_event *e = &ledger->experiment[i];
        struct zcl_fleet_experiment_group *g =
            exp_group(out, cap, count, e->task_class, e->model);
        if (!g) {
            status = ZCL_FLEET_FULL;
            break;
        }
        if (e->phase == ZCL_FLEET_EXPERIMENT_PREDICT)
            g->predicts++;
        else if (e->phase == ZCL_FLEET_EXPERIMENT_RESULT) {
            g->results++;
            if (e->outcome == 1) /* LAND */
                g->lands++;
            bool found = false;
            for (uint32_t j = 0; j < ledger->experiment_count; j++) {
                const struct fleet_experiment_event *p = &ledger->experiment[j];
                if (p->phase == ZCL_FLEET_EXPERIMENT_PREDICT &&
                    notes_equal(p, e)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                g->unpredicted++;
                unmatched++;
            }
        }
    }

    for (size_t gi = 0; gi < *count && status == ZCL_FLEET_OK; gi++) {
        int64_t walls[FLEET_EXPERIMENT_EVENTS_MAX];
        int64_t tokens[FLEET_EXPERIMENT_EVENTS_MAX];
        size_t nw = 0, nt = 0;
        int64_t pred_sum = 0, act_sum = 0;
        bool have_ratio = false;
        struct zcl_fleet_experiment_group *g = &out[gi];
        for (uint32_t i = 0; i < ledger->experiment_count; i++) {
            const struct fleet_experiment_event *e = &ledger->experiment[i];
            if (e->task_class != g->task_class || e->model != g->model)
                continue;
            if (e->phase != ZCL_FLEET_EXPERIMENT_RESULT)
                continue;
            if (e->have_wall && nw < FLEET_EXPERIMENT_EVENTS_MAX)
                walls[nw++] = e->wall_s;
            if (e->have_tokens && nt < FLEET_EXPERIMENT_EVENTS_MAX)
                tokens[nt++] = e->tokens;
            for (uint32_t j = 0; j < ledger->experiment_count; j++) {
                const struct fleet_experiment_event *p = &ledger->experiment[j];
                if (p->phase != ZCL_FLEET_EXPERIMENT_PREDICT ||
                    !notes_equal(p, e) || !p->have_tokens || !e->have_tokens)
                    continue;
                pred_sum += p->tokens;
                act_sum += e->tokens;
                have_ratio = true;
                break;
            }
        }
        if (nw > 0) {
            g->median_wall_s = median_i64(walls, nw);
            g->have_median_wall = 1;
        }
        if (nt > 0) {
            g->median_tokens = median_i64(tokens, nt);
            g->have_median_tokens = 1;
        }
        if (have_ratio && act_sum > 0) {
            g->pred_actual_bp = (pred_sum * 10000) / act_sum;
            g->have_pred_actual = 1;
        }
    }

    /* Stable order: task_class then model, so a fixture has one answer. */
    for (size_t i = 1; i < *count; i++) {
        struct zcl_fleet_experiment_group t = out[i];
        size_t j = i;
        while (j > 0 &&
               (out[j - 1].task_class > t.task_class ||
                (out[j - 1].task_class == t.task_class &&
                 out[j - 1].model > t.model))) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = t;
    }

    if (unpredicted)
        *unpredicted = unmatched;
    int64_t end = platform_time_monotonic_us();
    if (index_us)
        *index_us = end > start ? (uint64_t)(end - start) : 0u;
    return status;
}
