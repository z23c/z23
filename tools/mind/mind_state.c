/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve, write and read the per-node mind's registry, heartbeat
 * and peer capsule. */

#include "mind.h"

#include "json/json.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A heartbeat that does not fit is a heartbeat nobody can read; the cap is
 * generous against ZCL_MIND_CHECKOUTS_MAX rows and checked on write. */
#define MIND_DOC_MAX 16384

bool zcl_mind_state_dir(char *out, size_t cap)
{
    char root[ZCL_MIND_PATH_MAX];
    if (!out || !platform_state_root(root, sizeof(root)))
        return false;
    int n = snprintf(out, cap, "%s/mind", root);
    return n > 0 && (size_t)n < cap && platform_private_directory_ensure(out);
}

static bool mind_leaf(char *out, size_t cap, const char *leaf)
{
    char dir[ZCL_MIND_PATH_MAX];
    if (!zcl_mind_state_dir(dir, sizeof(dir)))
        return false;
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

bool zcl_mind_lock_path(char *out, size_t cap)
{ return mind_leaf(out, cap, "mind.lock"); }

bool zcl_mind_heartbeat_path(char *out, size_t cap)
{ return mind_leaf(out, cap, "heartbeat.json"); }

bool zcl_mind_registry_path(char *out, size_t cap)
{ return mind_leaf(out, cap, "checkouts.v1"); }

/* Whole-file replace. Half a heartbeat read as a whole one would be a lie
 * about a checkout, so nothing is ever appended in place. */
static bool mind_publish(const char *path, const char *text, size_t len)
{
    char tmp[ZCL_MIND_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("mind", "state path too long");
    FILE *f = fopen(tmp, "wb");
    if (!f) LOG_FAIL("mind", "open %s for write", tmp);
    bool ok = fwrite(text, 1, len, f) == len;
    ok = fflush(f) == 0 && ok;
    ok = fclose(f) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) {
        (void)remove(tmp);
        LOG_FAIL("mind", "publish %s", path);
    }
    return true;
}

static char *mind_slurp(const char *path, size_t *len_out)
{
    if (len_out) *len_out = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(MIND_DOC_MAX + 1u);
    if (!buf) { (void)fclose(f); return NULL; }
    size_t n = fread(buf, 1, MIND_DOC_MAX, f);
    (void)fclose(f);
    buf[n] = '\0';
    if (len_out) *len_out = n;
    return buf;
}

/* ── the registry ────────────────────────────────────────────────────────
 * One header line naming the schema, then one line per checkout:
 *
 *   zcl.mind_registry.v1
 *   zcl.mind_checkout.v1 /home/user/github/zclassic23
 *
 * Typed on purpose: an untyped list of paths is indistinguishable from a
 * truncated one, and a resident that guessed would claim a checkout nobody
 * registered. */
bool zcl_mind_registry_load(struct zcl_mind_registry *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    char path[ZCL_MIND_PATH_MAX];
    if (!zcl_mind_registry_path(path, sizeof(path)))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;                  /* absent: the retire signal */
    char line[ZCL_MIND_PATH_MAX + 64];
    bool header = false;
    while (fgets(line, (int)sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n == 0 || line[0] == '#') continue;
        if (!header) {
            header = strcmp(line, ZCL_MIND_REGISTRY_MAGIC) == 0;
            if (!header) break;            /* not our file: claim nothing */
            continue;
        }
        const char *tag = ZCL_MIND_CHECKOUT_MAGIC " ";
        size_t taglen = strlen(tag);
        if (strncmp(line, tag, taglen) != 0) continue;
        const char *root = line + taglen;
        if (root[0] != '/') continue;      /* relative roots break writers */
        if (out->count >= ZCL_MIND_CHECKOUTS_MAX) break;
        size_t rl = strlen(root);
        if (rl == 0 || rl >= ZCL_MIND_PATH_MAX) continue;
        memcpy(out->roots[out->count], root, rl + 1u);
        out->count++;
    }
    (void)fclose(f);
    return header;
}

bool zcl_mind_registry_write(const struct zcl_mind_registry *reg)
{
    if (!reg) return false;
    char path[ZCL_MIND_PATH_MAX];
    if (!zcl_mind_registry_path(path, sizeof(path)))
        LOG_FAIL("mind", "resolve registry path");
    char *text = malloc(MIND_DOC_MAX);
    if (!text) LOG_FAIL("mind", "registry buffer");
    int used = snprintf(text, MIND_DOC_MAX, "%s\n", ZCL_MIND_REGISTRY_MAGIC);
    bool ok = used > 0 && (size_t)used < MIND_DOC_MAX;
    for (size_t i = 0; ok && i < reg->count; i++) {
        int n = snprintf(text + used, MIND_DOC_MAX - (size_t)used, "%s %s\n",
                         ZCL_MIND_CHECKOUT_MAGIC, reg->roots[i]);
        ok = n > 0 && (size_t)(used + n) < MIND_DOC_MAX;
        if (ok) used += n;
    }
    ok = ok && mind_publish(path, text, (size_t)used);
    free(text);
    return ok;
}

/* ── the heartbeat ── */
static bool heartbeat_json(const struct zcl_mind_heartbeat *beat,
                           struct json_value *doc)
{
    json_init(doc);
    json_set_object(doc);
    bool ok = json_push_kv_str(doc, "schema", ZCL_MIND_HEARTBEAT_SCHEMA) &&
              json_push_kv_int(doc, "pid", beat->pid) &&
              json_push_kv_int(doc, "started_unix", beat->started_unix) &&
              json_push_kv_int(doc, "beat_unix", beat->beat_unix) &&
              json_push_kv_int(doc, "last_rebuild_ms", beat->last_rebuild_ms);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; ok && i < beat->checkout_count; i++) {
        const struct zcl_mind_checkout *c = &beat->checkouts[i];
        struct json_value row, groups;
        json_init(&row);
        json_set_object(&row);
        json_init(&groups);
        json_set_array(&groups);
        for (size_t g = 0; ok && g < c->group_count; g++) {
            struct json_value grow;
            json_init(&grow);
            json_set_object(&grow);
            ok = json_push_kv_str(&grow, "name", c->groups[g].name) &&
                 json_push_kv_int(&grow, "files", c->groups[g].files) &&
                 json_push_back(&groups, &grow);
            json_free(&grow);
        }
        ok = ok && json_push_kv(&row, "groups", &groups);
        json_free(&groups);
        ok = ok && json_push_kv_str(&row, "root", c->root) &&
             json_push_kv_str(&row, "index_root", c->index_root) &&
             json_push_kv_int(&row, "index_age_s", c->index_age_s) &&
             json_push_kv_int(&row, "last_rebuild_ms", c->last_rebuild_ms) &&
             json_push_kv_int(&row, "last_rebuild_unix", c->last_rebuild_unix) &&
             json_push_kv_int(&row, "rebuilds", c->rebuilds) &&
             json_push_kv_bool(&row, "indexed", c->indexed) &&
             json_push_kv_bool(&row, "stale", c->stale) &&
             json_push_back(&rows, &row);
        json_free(&row);
    }
    ok = ok && json_push_kv(doc, "checkouts", &rows);
    json_free(&rows);
    if (!ok) json_free(doc);
    return ok;
}

bool zcl_mind_heartbeat_write(const struct zcl_mind_heartbeat *beat)
{
    char path[ZCL_MIND_PATH_MAX];
    if (!beat || !zcl_mind_heartbeat_path(path, sizeof(path)))
        LOG_FAIL("mind", "resolve heartbeat path");
    struct json_value doc;
    if (!heartbeat_json(beat, &doc))
        LOG_FAIL("mind", "render heartbeat");
    char *text = malloc(MIND_DOC_MAX);
    size_t n = text ? json_write(&doc, text, MIND_DOC_MAX) : 0;
    json_free(&doc);
    bool ok = text && n > 0 && n < MIND_DOC_MAX &&
              mind_publish(path, text, n);
    free(text);
    return ok;
}

static long long doc_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_INT ? (long long)json_get_int(v) : 0;
}

static bool doc_bool(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static void doc_str(const struct json_value *obj, const char *key, char *out,
                    size_t cap)
{
    const struct json_value *v = json_get(obj, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s) { if (cap) out[0] = '\0'; return; }
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1u;
    memcpy(out, s, n);
    out[n] = '\0';
}

bool zcl_mind_heartbeat_read(struct zcl_mind_heartbeat *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    char path[ZCL_MIND_PATH_MAX];
    if (!zcl_mind_heartbeat_path(path, sizeof(path)))
        return false;
    size_t len = 0;
    char *raw = mind_slurp(path, &len);
    if (!raw) return false;
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, raw, len) && doc.type == JSON_OBJ;
    free(raw);
    const struct json_value *schema = ok ? json_get(&doc, "schema") : NULL;
    ok = ok && schema && schema->type == JSON_STR &&
         strcmp(json_get_str(schema), ZCL_MIND_HEARTBEAT_SCHEMA) == 0;
    if (!ok) { json_free(&doc); return false; }
    out->pid = doc_int(&doc, "pid");
    out->started_unix = doc_int(&doc, "started_unix");
    out->beat_unix = doc_int(&doc, "beat_unix");
    out->last_rebuild_ms = doc_int(&doc, "last_rebuild_ms");
    const struct json_value *rows = json_get(&doc, "checkouts");
    size_t count = rows && rows->type == JSON_ARR ? json_size(rows) : 0;
    for (size_t i = 0; i < count && out->checkout_count < ZCL_MIND_CHECKOUTS_MAX;
         i++) {
        const struct json_value *row = json_at(rows, i);
        if (!row || row->type != JSON_OBJ) continue;
        struct zcl_mind_checkout *c = &out->checkouts[out->checkout_count++];
        doc_str(row, "root", c->root, sizeof(c->root));
        doc_str(row, "index_root", c->index_root, sizeof(c->index_root));
        c->index_age_s = doc_int(row, "index_age_s");
        c->last_rebuild_ms = doc_int(row, "last_rebuild_ms");
        c->last_rebuild_unix = doc_int(row, "last_rebuild_unix");
        c->rebuilds = doc_int(row, "rebuilds");
        c->indexed = doc_bool(row, "indexed");
        c->stale = doc_bool(row, "stale");
        const struct json_value *groups = json_get(row, "groups");
        size_t gn = groups && groups->type == JSON_ARR ? json_size(groups) : 0;
        for (size_t g = 0; g < gn && c->group_count < ZCL_MIND_GROUPS_MAX; g++) {
            const struct json_value *grow = json_at(groups, g);
            if (!grow || grow->type != JSON_OBJ) continue;
            struct zcl_mind_group_row *dst = &c->groups[c->group_count++];
            doc_str(grow, "name", dst->name, sizeof(dst->name));
            dst->files = doc_int(grow, "files");
        }
    }
    json_free(&doc);
    return true;
}

/* ── the peer capsule ────────────────────────────────────────────────────
 * This object rides INSIDE the existing signed, expiring mesh-status capsule
 * (cognition/modules/session/src/mesh_status_proto.c). It carries no
 * signature and no lifetime of its own precisely so it cannot be replayed
 * outside the receipt that signs it: a mind row is only ever as trustworthy,
 * and only ever as fresh, as the receipt it arrived in. */
bool zcl_mind_capsule_render(struct json_value *out)
{
    struct zcl_mind_heartbeat beat;
    if (!out || !zcl_mind_heartbeat_read(&beat) || beat.checkout_count == 0)
        return false;
    /* One node, one answer: the FIRST registered checkout is the one this
     * node speaks for. A node that answered for several would need a way to
     * say which, and that is a shard map, not a capsule field. */
    const struct zcl_mind_checkout *c = &beat.checkouts[0];
    json_init(out);
    json_set_object(out);
    bool ok = json_push_kv_str(out, "schema", ZCL_MIND_CAPSULE_SCHEMA) &&
              json_push_kv_str(out, "index_root", c->index_root) &&
              json_push_kv_int(out, "index_age_s", c->index_age_s) &&
              json_push_kv_int(out, "checkouts",
                               (int64_t)beat.checkout_count);
    struct json_value groups;
    json_init(&groups);
    json_set_array(&groups);
    for (size_t g = 0; ok && g < c->group_count; g++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        ok = json_push_kv_str(&row, "name", c->groups[g].name) &&
             json_push_kv_int(&row, "files", c->groups[g].files) &&
             json_push_back(&groups, &row);
        json_free(&row);
    }
    ok = ok && json_push_kv(out, "groups", &groups);
    json_free(&groups);
    if (!ok) json_free(out);
    return ok;
}

bool zcl_mind_capsule_parse(const struct json_value *capsule,
                            struct zcl_mind_peer *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!capsule || capsule->type != JSON_OBJ) return false;
    const struct json_value *mind = json_get(capsule, "mind");
    if (!mind || mind->type != JSON_OBJ) return false;
    const struct json_value *schema = json_get(mind, "schema");
    if (!schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), ZCL_MIND_CAPSULE_SCHEMA) != 0)
        return false;
    doc_str(mind, "index_root", out->index_root, sizeof(out->index_root));
    out->index_age_s = doc_int(mind, "index_age_s");
    out->checkouts = doc_int(mind, "checkouts");
    const struct json_value *groups = json_get(mind, "groups");
    size_t count = groups && groups->type == JSON_ARR ? json_size(groups) : 0;
    for (size_t i = 0; i < count && out->group_count < ZCL_MIND_GROUPS_MAX;
         i++) {
        const struct json_value *row = json_at(groups, i);
        if (!row || row->type != JSON_OBJ) continue;
        struct zcl_mind_group_row *g = &out->groups[out->group_count++];
        doc_str(row, "name", g->name, sizeof(g->name));
        g->files = doc_int(row, "files");
    }
    return out->index_root[0] != '\0';
}
