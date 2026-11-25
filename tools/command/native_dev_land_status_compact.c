/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the compact outcome projection of `dev land status`; see the header. */

#include "command/native_dev_land_status_compact.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

size_t dlsc_first(size_t n)
{
    return n > DLSC_ROWS ? n - DLSC_ROWS : 0;
}

/* Copy at most DLSC_DETAIL_MAX bytes, backing up to a character boundary and
 * marking the cut, so the pushed text stays valid UTF-8. */
static void dlsc_cap_detail(const char *in, char out[DLSC_DETAIL_MAX + 4])
{
    size_t n = strlen(in);
    if (n <= DLSC_DETAIL_MAX) {
        memcpy(out, in, n + 1);
        return;
    }
    n = DLSC_DETAIL_MAX;
    while (n > 0 && ((unsigned char)in[n] & 0xC0u) == 0x80u)
        n--;
    memcpy(out, in, n);
    memcpy(out + n, "...", 4);
}

static bool dlsc_push_short(struct json_value *item, const char *key,
                            const char *hex)
{
    char shortv[13];
    (void)snprintf(shortv, sizeof(shortv), "%.12s", hex);
    return json_push_kv_str(item, key, shortv);
}

static bool dlsc_push_failure(struct json_value *item, const struct dl_row *r)
{
    char detail[DLSC_DETAIL_MAX + 4];
    char next[1100];
    dlsc_cap_detail(r->detail, detail);
    return json_push_kv_str(item, "dimension", r->dimension) &&
           json_push_kv_str(item, "detail", detail) &&
           json_push_kv_str(item, "log_path", r->log_path) &&
           (!dl_row_next_text(r, r->state, next, sizeof(next)) ||
            json_push_kv_str(item, "next_action", next));
}

bool dlsc_push_row(struct json_value *arr, const struct dl_row *r)
{
    struct json_value item;
    bool landed = strcmp(r->state, "landed") == 0;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "state", r->state) &&
         dlsc_push_short(&item, "tip", r->tip) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         (!landed || dlsc_push_short(&item, "tip_pushed", r->pushed)) &&
         (landed || dlsc_push_failure(&item, r)) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

bool dlsc_push_notes(struct json_value *data, size_t nrows)
{
    return json_push_kv_int(data, "outcomes_omitted",
                            (int64_t)dlsc_first(nrows)) &&
           json_push_kv_str(data, "outcomes_full",
                            "z23-dev dev land status --input='{\"json\":true}' returns every "
                            "outcome row with signatures and full tips");
}

/* ── "did MY submission land?" ─────────────────────────────────────────── */

static bool dlsc_hex_prefix(const char *s)
{
    size_t n = strlen(s);
    if (n < 12 || n > 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static const char *dlsc_str_in(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_STR && json_get_str(v)[0] ? json_get_str(v)
                                                          : NULL;
}

void dlsc_hit_init(struct dlsc_hit *hit, const struct json_value *input)
{
    const struct json_value *v;
    const char *tip, *note;
    memset(hit, 0, offsetof(struct dlsc_hit, o_row));
    if (!input)
        return;
    v = json_get(input, "seq");
    if (v && v->type == JSON_INT && json_get_int(v) >= 1)
        hit->seq = json_get_int(v);
    tip = hit->seq ? NULL : dlsc_str_in(input, "tip");
    note = hit->seq || tip ? NULL : dlsc_str_in(input, "note");
    if (tip && dlsc_hex_prefix(tip))
        (void)snprintf(hit->tip, sizeof(hit->tip), "%s", tip);
    else if (tip)
        hit->bad_tip = true;
    if (note)
        (void)snprintf(hit->note, sizeof(hit->note), "%s", note);
    hit->active = hit->seq || hit->tip[0] || hit->bad_tip || hit->note[0];
}

static bool dlsc_matches(const struct dlsc_hit *hit, const struct dl_row *r)
{
    if (hit->seq)
        return r->seq == hit->seq;
    if (hit->tip[0])
        return strncmp(r->tip, hit->tip, strlen(hit->tip)) == 0;
    return hit->note[0] && strcmp(r->note, hit->note) == 0;
}

void dlsc_hit_queue(struct dlsc_hit *hit, const struct dl_row *r)
{
    bool live = strcmp(r->state, "queued") == 0 ||
                strcmp(r->state, "inflight") == 0;
    if (!hit->active || !live || !dlsc_matches(hit, r) ||
        (hit->q_found && r->seq < hit->q_seq))
        return;
    hit->q_found = true;
    hit->q_seq = r->seq;
    (void)snprintf(hit->q_state, sizeof(hit->q_state), "%s", r->state);
}

void dlsc_hit_outcome(struct dlsc_hit *hit, const struct dl_row *r)
{
    if (!hit->active || !dlsc_matches(hit, r) ||
        (hit->o_found && r->seq < hit->o_row.seq))
        return;
    hit->o_found = true;
    hit->o_row = *r;
}

enum dlsc_where dlsc_hit_where(const struct dlsc_hit *hit)
{
    if (hit->q_found && (!hit->o_found || hit->q_seq >= hit->o_row.seq))
        return strcmp(hit->q_state, "inflight") == 0 ? DLSC_IN_FLIGHT
                                                     : DLSC_QUEUED;
    return hit->o_found ? DLSC_OUTCOME : DLSC_UNKNOWN;
}

bool dlsc_hit_is_listed(const struct dlsc_hit *hit, const struct dl_row *r)
{
    return hit->active && dlsc_hit_where(hit) == DLSC_OUTCOME &&
           hit->o_row.seq == r->seq;
}

static const char *dlsc_where_name(enum dlsc_where w)
{
    static const char *const names[] = {"unknown", "queued", "in_flight",
                                        "outcome"};
    return names[w];
}

static const char *dlsc_where_hint(const struct dlsc_hit *hit, enum dlsc_where w)
{
    if (w == DLSC_OUTCOME)
        return "this submission's row is listed first in outcomes; match by "
               "seq or tip (the submitted commit), never tip_pushed";
    if (w == DLSC_UNKNOWN)
        return hit->bad_tip ? "tip must be at least 12 lowercase hex "
                              "characters of the submitted commit"
                            : "no queue row or outcome matches: not submitted "
                              "here, or the seq/tip/note is wrong";
    return "still in the queue: poll status again; no outcome exists yet";
}

static const struct json_value *dlsc_train_member(const struct json_value *data,
                                                   int64_t seq)
{
    const struct json_value *flight = json_get(data, "in_flight");
    const struct json_value *members = flight ? json_get(flight, "train_members") : NULL;
    const struct json_value *head = flight ? json_get(flight, "seq") : NULL;
    const struct json_value *phase = flight ? json_get(flight, "phase") : NULL;
    if (!members || members->type != JSON_ARR || !head || head->type != JSON_INT ||
        json_get_int(head) <= 0 || !phase || phase->type != JSON_STR)
        return NULL;
    for (size_t i = 0; i < json_size(members); i++) {
        const struct json_value *item = json_at(members, i);
        if (item && item->type == JSON_INT && json_get_int(item) == seq)
            return flight;
    }
    return NULL;
}

bool dlsc_push_mine(struct json_value *data, const struct dlsc_hit *hit)
{
    struct json_value obj;
    enum dlsc_where w = dlsc_hit_where(hit);
    long long seq = hit->seq;
    const char *state = "unknown";
    bool ok;
    if (!hit->active)
        return true;
    if (w == DLSC_OUTCOME) {
        seq = hit->o_row.seq;
        state = hit->o_row.state;
    } else if (w != DLSC_UNKNOWN) {
        seq = hit->q_seq;
        state = hit->q_state;
    }
    const struct json_value *train = w == DLSC_QUEUED
                                      ? dlsc_train_member(data, seq) : NULL;
    json_init(&obj);
    json_set_object(&obj);
    ok = (seq <= 0 || json_push_kv_int(&obj, "seq", seq)) &&
         json_push_kv_str(&obj, "where", dlsc_where_name(w)) &&
         json_push_kv_str(&obj, "state", state) &&
         json_push_kv_str(&obj, "hint", train ? "train member: see in_flight for the exact candidate and proof phase" : dlsc_where_hint(hit, w)) &&
         (!train || (json_push_kv_int(&obj, "train_head_seq", json_get_int(json_get(train, "seq"))) &&
                     json_push_kv_str(&obj, "train_phase", json_get_str(json_get(train, "phase"))))) &&
         json_push_kv(data, "mine", &obj);
    json_free(&obj);
    return ok;
}
