/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Index exact typed-read candidates while leaving grant checks to callers. */
#include "command/native_fleet_typed_index.h"
#include "base/safe_alloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct typed_key {
    const char *from, *to, *ref, *stream, *sha;
    int64_t offset, seq;
};
struct zcl_fleet_typed_entry {
    struct json_value row;
    struct typed_key key;
    int64_t order;
    size_t insertion;
};
static const char *typed_str(const struct json_value *r, const char *name)
{
    const struct json_value *v = json_get(r, name);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}
static int64_t typed_int(const struct json_value *r, const char *name)
{
    const struct json_value *v = json_get(r, name);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}
static int typed_key_cmp(const struct typed_key *a, const struct typed_key *b)
{
    int c;
#define CMP_TEXT(member) do { c = strcmp(a->member, b->member); if (c) return c; } while (0)
    CMP_TEXT(from); CMP_TEXT(to); CMP_TEXT(ref); CMP_TEXT(stream); CMP_TEXT(sha);
#undef CMP_TEXT
    if (a->offset != b->offset) return a->offset < b->offset ? -1 : 1;
    return (a->seq > b->seq) - (a->seq < b->seq);
}
static int typed_entry_cmp(const struct zcl_fleet_typed_entry *a,
                           const struct zcl_fleet_typed_entry *b)
{
    int c = typed_key_cmp(&a->key, &b->key);
    if (c) return c;
    if (a->order != b->order) return a->order > b->order ? -1 : 1;
    return (a->insertion > b->insertion) - (a->insertion < b->insertion);
}
static void typed_result_key(struct zcl_fleet_typed_entry *e)
{
    const struct json_value *r = &e->row;
    e->key = (struct typed_key){typed_str(r, "from"), typed_str(r, "to"),
        typed_str(r, "ref"), typed_str(r, "observed_stream"), typed_str(r, "observed_sha3"),
        typed_int(r, "observed_offset"), typed_int(r, "observed_seq")};
    e->order = typed_int(r, "row_offset");
}
static bool typed_candidate(const struct json_value *r)
{
    const struct json_value *seq = json_get(r, "seq");
    const char *d = typed_str(r, "observed_disposition");
    return r && r->type == JSON_OBJ && seq && seq->type == JSON_INT &&
        !strcmp(typed_str(r, "kind"), "result") && !strcmp(typed_str(r, "stream"), "outbox.jsonl") &&
        d[0] && strcmp(d, "UNVERIFIED") && typed_str(r, "sender_binding")[0] &&
        typed_int(r, "row_offset") >= 0;
}
static bool typed_add_bytes(size_t *total, size_t n, size_t limit)
{
    if (n > limit || *total > limit - n) return false;
    *total += n;
    return true;
}
static bool typed_add_string(size_t *total, const char *s, size_t limit)
{
    size_t left = limit - *total;
    size_t n = strnlen(s, left);
    return n < left && typed_add_bytes(total, n + 1, limit);
}
/* json_copy_checked allocates one value and key slot per child. */
static bool typed_json_bytes(const struct json_value *v, size_t *total, size_t limit, unsigned depth)
{
    if (depth > 256) return false; /* Match the JSON parser's nesting bound. */
    if (v->type == JSON_STR && v->val.s && !typed_add_string(total, v->val.s, limit)) return false;
    if (v->num_children > SIZE_MAX / (sizeof(*v->children) + sizeof(*v->keys))) return false;
    if (!typed_add_bytes(total, v->num_children * (sizeof(*v->children) + sizeof(*v->keys)), limit)) return false;
    for (size_t i = 0; i < v->num_children; ++i) {
        if (v->keys && v->keys[i] && !typed_add_string(total, v->keys[i], limit)) return false;
        if (!typed_json_bytes(&v->children[i], total, limit, depth + 1)) return false;
    }
    return true;
}
void zcl_fleet_typed_index_init(struct zcl_fleet_typed_index *ix, size_t rows, size_t bytes)
{
    if (ix) *ix = (struct zcl_fleet_typed_index){.row_limit = rows, .byte_limit = bytes};
}
void zcl_fleet_typed_index_free(struct zcl_fleet_typed_index *ix)
{
    if (!ix) return;
    for (size_t i = 0; i < ix->count; ++i) json_free(&ix->entries[i].row);
    free(ix->entries);
    *ix = (struct zcl_fleet_typed_index){0};
}
static bool typed_reserve(struct zcl_fleet_typed_index *ix, size_t bytes)
{
    if (ix->count >= ix->row_limit || ix->count == SIZE_MAX / sizeof(*ix->entries)) return false;
    if (ix->count == ix->capacity) {
        size_t n = ix->capacity ? ix->capacity * 2 : 16;
        if (n < ix->capacity || n > ix->row_limit) n = ix->row_limit;
        size_t room = (ix->byte_limit - ix->bytes - bytes) / sizeof(*ix->entries);
        if (n - ix->capacity > room) n = ix->capacity + room;
        if (n <= ix->count) return false;
        if (n > SIZE_MAX / sizeof(*ix->entries)) return false;
        size_t reserve = (n - ix->capacity) * sizeof(*ix->entries);
        if (reserve > ix->byte_limit - ix->bytes - bytes) return false;
        void *p = zcl_realloc(ix->entries, n * sizeof(*ix->entries), "fleet typed index");
        if (!p) return false;
        ix->entries = p; ix->capacity = n; ix->bytes += reserve;
    }
    return true;
}
bool zcl_fleet_typed_index_append(struct zcl_fleet_typed_index *ix, const struct json_value *row)
{
    if (!ix || ix->poisoned) return false;
    if (!row) goto fail;
    if (!typed_candidate(row)) return true;
    size_t bytes = 0;
    if (ix->bytes > ix->byte_limit || !typed_json_bytes(row, &bytes, ix->byte_limit - ix->bytes, 0) ||
        !typed_reserve(ix, bytes)) goto fail;
    struct zcl_fleet_typed_entry e = {0};
    if (!json_copy_checked(&e.row, row)) { json_free(&e.row); goto fail; }
    e.insertion = ix->count;
    typed_result_key(&e);
    size_t lo = 0, hi = ix->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (typed_entry_cmp(&ix->entries[mid], &e) < 0) lo = mid + 1; else hi = mid;
    }
    memmove(&ix->entries[lo + 1], &ix->entries[lo], (ix->count - lo) * sizeof(e));
    ix->entries[lo] = e;
    ix->count++; ix->bytes += bytes;
    return true;
fail:
    ix->poisoned = true;
    return false;
}
bool zcl_fleet_typed_index_build(struct zcl_fleet_typed_index *ix, const struct json_value *rows)
{
    if (!ix || ix->poisoned || !rows || rows->type != JSON_ARR || ix->count) {
        if (ix) ix->poisoned = true;
        return false;
    }
    for (size_t i = 0; i < json_size(rows); ++i)
        if (!zcl_fleet_typed_index_append(ix, json_at(rows, i))) return false;
    return true;
}
static bool typed_key_from_locator(const struct zcl_fleet_typed_locator *d,
                                   struct typed_key *key)
{
    if (!d->from || !d->to || !d->ref || !d->stream || !d->row_sha3)
        return false;
    *key = (struct typed_key){d->to, d->from, d->ref, d->stream, d->row_sha3,
                              d->row_offset, d->seq};
    return true;
}
bool zcl_fleet_typed_index_visit_key(struct zcl_fleet_typed_index *ix,
                                     const struct zcl_fleet_typed_locator *d,
                                     zcl_fleet_typed_visit visit, void *ctx)
{
    if (!ix || ix->poisoned || !d || !visit || !d->kind) return false;
    if (strcmp(d->kind, "directive")) return true;
    struct typed_key key;
    if (!typed_key_from_locator(d, &key)) return false;
    size_t lo = 0, hi = ix->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (typed_key_cmp(&ix->entries[mid].key, &key) < 0) lo = mid + 1; else hi = mid;
    }
    while (lo < ix->count && !typed_key_cmp(&ix->entries[lo].key, &key)) {
        if (visit(&ix->entries[lo].row, ctx)) break;
        ++lo;
    }
    return true;
}
bool zcl_fleet_typed_index_visit(struct zcl_fleet_typed_index *ix,
                                  const struct json_value *d, zcl_fleet_typed_visit visit, void *ctx)
{
    if (!ix || ix->poisoned || !d || d->type != JSON_OBJ || !visit) return false;
    if (strcmp(typed_str(d, "kind"), "directive")) return true;
    const struct json_value *seq = json_get(d, "seq");
    if (!seq || seq->type != JSON_INT) return false;
    struct zcl_fleet_typed_locator key = {typed_str(d, "from"), typed_str(d, "to"),
        typed_str(d, "ref"), typed_str(d, "stream"), typed_str(d, "row_sha3"),
        typed_int(d, "row_offset"), json_get_int(seq), "directive"};
    return zcl_fleet_typed_index_visit_key(ix, &key, visit, ctx);
}
