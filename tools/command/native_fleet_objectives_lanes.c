/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The agent-to-lane index behind tokens_per_landed_commit. Each
 *          worker agent leaves agent-<id>.meta.json beside its transcript
 *          under the Claude projects root; its "description" is the job
 *          label, `write:<lane>`, `cx:<lane>`, `review:<lane>`,
 *          `review1:<lane>`, `review2:<lane>`, `fix:<lane>`, `design:<lane>`
 *          or `check:<lane>` (a lane's design and citation-check agents count
 *          toward its cost). This leaf maps agent id to lane for those labels
 *          only; any other label is research and is not indexed.
 *
 * The scan is bounded: a directory depth cap, a cap on meta files read, and
 * a 64 KiB size limit per file. It only ever opens files for reading.
 */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LANES_MAX_DEPTH 8
#define LANES_META_BYTES 65536u
#define LANES_PATH_MAX 1024u

static const char *const lanes_prefixes[] = {
    "write:",   "cx:",     "review:", "review1:", "review2:",
    "fix:",     "design:", "check:"};

/* The lane named by a job label, or NULL for a research label. */
static const char *lanes_of_label(const char *label, char *kind)
{
    if (!label)
        return NULL;
    for (size_t i = 0; i < sizeof(lanes_prefixes) / sizeof(lanes_prefixes[0]);
         i++) {
        size_t n = strlen(lanes_prefixes[i]);
        if (strncmp(label, lanes_prefixes[i], n) == 0 && label[n] != '\0') {
            memcpy(kind, lanes_prefixes[i], n - 1u);
            kind[n - 1u] = '\0';
            return label + n;
        }
    }
    return NULL;
}

/* `agent-<id>.meta.json` -> id in `id`; false for any other name. */
static bool lanes_meta_id(const char *name, char *id, size_t cap)
{
    static const char suffix[] = ".meta.json";
    size_t len = strlen(name), sl = sizeof(suffix) - 1u;
    if (len <= 6u + sl || strncmp(name, "agent-", 6) != 0 ||
        strcmp(name + len - sl, suffix) != 0 || len - 6u - sl >= cap)
        return false;
    memcpy(id, name + 6, len - 6u - sl);
    id[len - 6u - sl] = '\0';
    return true;
}

static bool lanes_push(struct zcl_agent_index *ix, const char *id,
                       const char *lane, const char *kind)
{
    if (ix->n == ix->cap) {
        size_t cap = ix->cap ? ix->cap * 2u : 1024u;
        struct zcl_agent_lane *grown = zcl_realloc(ix->items, cap * sizeof(*grown), "agent_lane_index");
        if (!grown) {
            ix->oom = true;
            return false;
        }
        ix->items = grown;
        ix->cap = cap;
    }
    (void)snprintf(ix->items[ix->n].id, sizeof(ix->items[ix->n].id), "%s", id);
    (void)snprintf(ix->items[ix->n].lane, sizeof(ix->items[ix->n].lane), "%s",
                   lane);
    (void)snprintf(ix->items[ix->n].kind, sizeof(ix->items[ix->n].kind), "%s",
                   kind);
    ix->n++;
    return true;
}

/* Reads one meta file (<= 64 KiB) and indexes it when its label names a lane. */
static void lanes_read_meta(struct zcl_agent_index *ix, const char *path,
                            const char *id)
{
    char *buf = zcl_malloc(LANES_META_BYTES + 1u, "agent_meta_buf");
    FILE *f = buf ? fopen(path, "rb") : NULL;
    size_t got;
    struct json_value doc;
    const char *lane;
    char kind[8] = "";
    if (!buf) {
        ix->oom = true;
        return;
    }
    if (!f) {
        free(buf);
        return;
    }
    got = fread(buf, 1, LANES_META_BYTES + 1u, f);
    (void)fclose(f);
    if (got > 0 && got <= LANES_META_BYTES) {
        json_init(&doc);
        if (json_read(&doc, buf, got) && doc.type == JSON_OBJ) {
            lane = lanes_of_label(json_get_str(json_get(&doc, "description")), kind);
            if (lane)
                (void)lanes_push(ix, id, lane, kind);
        }
        json_free(&doc);
    }
    free(buf);
}

static void lanes_walk(struct zcl_agent_index *ix, const char *dir, int depth);

/* One regular file: read it when it is an in-size agent meta file. */
static void lanes_file(struct zcl_agent_index *ix, const char *path,
                       const char *name, const struct stat *st)
{
    char id[48];
    if (!lanes_meta_id(name, id, sizeof(id)) || st->st_size <= 0 ||
        (size_t)st->st_size > LANES_META_BYTES)
        return;
    if (ix->files >= ZCL_AGENT_INDEX_FILE_CAP) {
        ix->capped = true;
        return;
    }
    ix->files++;
    lanes_read_meta(ix, path, id);
}

static void lanes_walk(struct zcl_agent_index *ix, const char *dir, int depth)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[LANES_PATH_MAX];
    struct stat st;
    while (d && !ix->oom && !ix->capped && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >=
                (int)sizeof(path) ||
            lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode) && depth < LANES_MAX_DEPTH)
            lanes_walk(ix, path, depth + 1);
        else if (S_ISREG(st.st_mode))
            lanes_file(ix, path, e->d_name, &st);
    }
    if (d)
        (void)closedir(d);
}

static int lanes_cmp(const void *a, const void *b)
{
    return strcmp(((const struct zcl_agent_lane *)a)->id,
                  ((const struct zcl_agent_lane *)b)->id);
}

bool zcl_objectives_agent_index_build(struct zcl_agent_index *ix)
{
    const char *root = getenv("Z23_AGENT_META_ROOT");
    const char *home = getenv("HOME");
    char buf[LANES_PATH_MAX];
    memset(ix, 0, sizeof(*ix));
    if (root && root[0]) {
        lanes_walk(ix, root, 0);
    } else if (home && home[0] &&
               snprintf(buf, sizeof(buf), "%s/.claude/projects", home) <
                   (int)sizeof(buf)) {
        lanes_walk(ix, buf, 0);
    }
    if (ix->oom)
        return false;
    qsort(ix->items, ix->n, sizeof(*ix->items), lanes_cmp);
    return true;
}

const char *zcl_objectives_agent_lane(const struct zcl_agent_index *ix,
                                      const char *id)
{
    struct zcl_agent_lane key;
    const struct zcl_agent_lane *hit;
    if (!ix->n)
        return NULL;
    (void)snprintf(key.id, sizeof(key.id), "%s", id);
    hit = bsearch(&key, ix->items, ix->n, sizeof(*ix->items), lanes_cmp);
    return hit ? hit->lane : NULL;
}

const char *zcl_objectives_agent_kind(const struct zcl_agent_index *ix,
                                      const char *id)
{
    struct zcl_agent_lane key;
    const struct zcl_agent_lane *hit;
    if (!ix->n)
        return NULL;
    (void)snprintf(key.id, sizeof(key.id), "%s", id);
    hit = bsearch(&key, ix->items, ix->n, sizeof(*ix->items), lanes_cmp);
    return hit ? hit->kind : NULL;
}

void zcl_objectives_agent_index_free(struct zcl_agent_index *ix)
{
    free(ix->items);
    memset(ix, 0, sizeof(*ix));
}
