/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: plugin_dev, the one-call developer loop (key, publisher, pack,
 * install, switch) over the existing plugin store functions. */

#include "plugin/plugin_dev.h"

#include "plugin_internal.h"

#include <stdio.h>
#include <string.h>

#define PD_DEFAULT_VERSION "0.0.0-dev"
#define PD_KEY_LEAF "plugin_dev.key"

const char *plugin_dev_step_name(enum plugin_dev_step step)
{
    static const char *const names[PLUGIN_DEV_STEP_COUNT] = {
        "key", "pack", "publisher", "install", "switch"
    };
    return (unsigned)step < PLUGIN_DEV_STEP_COUNT ? names[step] : "unknown";
}

/* The last path component of dir, ignoring trailing slashes. */
static bool pd_leaf(const char *dir, char *out, size_t cap)
{
    size_t end = strlen(dir);
    while (end > 1 && dir[end - 1] == '/')
        end--;
    size_t start = end;
    while (start > 0 && dir[start - 1] != '/')
        start--;
    size_t len = end - start;
    if (len == 0 || len >= cap)
        return false;
    memcpy(out, dir + start, len);
    out[len] = '\0';
    return true;
}

/* The directory that holds root, "." when root has no slash. */
static bool pd_default_key(const char *root, char *out, size_t cap)
{
    size_t end = strlen(root);
    while (end > 1 && root[end - 1] == '/')
        end--;
    while (end > 0 && root[end - 1] != '/')
        end--;
    while (end > 1 && root[end - 1] == '/')
        end--;
    char parent[PLUGIN_PATH_MAX];
    if (end == 0 || end >= sizeof(parent))
        return false;
    memcpy(parent, root, end);
    parent[end] = '\0';
    return plugin_join(out, cap, parent, PD_KEY_LEAF, NULL, NULL);
}

static bool pd_args(const struct plugin_dev_request *rq,
                    struct plugin_dev_result *res, const char **version)
{
    if (!rq || !res || !rq->root || !rq->dir || !*rq->dir)
        return false;
    *version = rq->version ? rq->version : PD_DEFAULT_VERSION;
    if (rq->name) {
        if (snprintf(res->name, sizeof(res->name), "%s", rq->name) >= (int)sizeof(res->name))
            return false;
    } else if (!pd_leaf(rq->dir, res->name, sizeof(res->name))) {
        return false;
    }
    if (!plugin_name_valid(res->name) || !plugin_version_valid(*version))
        return false;
    if (rq->key_path)
        return snprintf(res->key_path, sizeof(res->key_path), "%s", rq->key_path) <
               (int)sizeof(res->key_path);
    return pd_default_key(rq->root, res->key_path, sizeof(res->key_path));
}

/* Creates the key unless one is already there; an existing key is reused. */
static enum plugin_status pd_key(struct plugin_dev_result *res, bool default_key)
{
    char pub[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (default_key) {
        char parent[PLUGIN_PATH_MAX];
        snprintf(parent, sizeof(parent), "%s", res->key_path);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = '\0';
            if (!plugin_mkdirs(parent))
                return PLUGIN_ERR_IO;
        }
    }
    enum plugin_status st = plugin_keygen(res->key_path, pub);
    if (st == PLUGIN_ERR_KEY_EXISTS)
        return PLUGIN_OK;
    res->key_created = st == PLUGIN_OK;
    return st;
}

static enum plugin_status pd_pack(const struct plugin_dev_request *rq,
                                  struct plugin_dev_result *res,
                                  const char *version)
{
    char exe[PLUGIN_PATH_MAX], dist[PLUGIN_PATH_MAX];
    if (!plugin_join(exe, sizeof(exe), rq->dir, res->name, NULL, NULL) ||
        !plugin_join(dist, sizeof(dist), rq->dir, "dist", NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    struct plugin_pack_request pack = {
        .exe_path = exe, .name = res->name, .version = version,
        .key_path = res->key_path, .out_dir = dist,
        .capabilities = rq->capabilities, .interface_version = rq->interface_version,
    };
    struct plugin_pack_result packed;
    enum plugin_status st = plugin_pack(&pack, &packed);
    if (st != PLUGIN_OK)
        return st;
    snprintf(res->public_key, sizeof(res->public_key), "%s", packed.public_key);
    snprintf(res->manifest_path, sizeof(res->manifest_path), "%s", packed.manifest_path);
    snprintf(res->generation, sizeof(res->generation), "%s", packed.generation);
    return PLUGIN_OK;
}

static size_t pd_sequence(const char *root, const char *name)
{
    struct plugin_info *infos = NULL;
    size_t count = 0, seq = 0;
    if (plugin_store_list(root, &infos, &count) != PLUGIN_OK)
        return 0;
    for (size_t i = 0; i < count; i++)
        if (strcmp(infos[i].name, name) == 0)
            seq = infos[i].generation_count;
    plugin_store_list_free(infos, count);
    return seq;
}

static enum plugin_status pd_install(const char *root, struct plugin_dev_result *res)
{
    struct plugin_manifest m;
    int present = 0;
    enum plugin_status st = plugin_store_install(root, res->manifest_path, &m, &present);
    if (st != PLUGIN_OK)
        return st;
    snprintf(res->generation, sizeof(res->generation), "%s", m.generation);
    res->already_present = present != 0;
    res->sequence = pd_sequence(root, res->name);
    return PLUGIN_OK;
}

enum plugin_status plugin_dev(const struct plugin_dev_request *rq,
                              struct plugin_dev_result *res)
{
    const char *version = NULL;
    if (!res)
        return PLUGIN_ERR_ARGUMENT;
    memset(res, 0, sizeof(*res));
    if (!pd_args(rq, res, &version))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = pd_key(res, rq->key_path == NULL);
    res->failed = PLUGIN_DEV_STEP_KEY;
    if (st != PLUGIN_OK)
        return st;
    res->steps_done = 1;
    res->failed = PLUGIN_DEV_STEP_PACK;
    st = pd_pack(rq, res, version);
    if (st != PLUGIN_OK)
        return st;
    res->failed = PLUGIN_DEV_STEP_PUBLISHER;
    int listed = 0;
    st = plugin_store_add_key(rq->root, res->public_key, &listed);
    if (st != PLUGIN_OK)
        return st;
    res->publisher_added = listed == 0;
    res->steps_done = 3;
    res->failed = PLUGIN_DEV_STEP_INSTALL;
    st = pd_install(rq->root, res);
    if (st != PLUGIN_OK)
        return st;
    res->steps_done = 4;
    res->failed = PLUGIN_DEV_STEP_SWITCH;
    st = plugin_store_switch(rq->root, res->name, res->generation);
    if (st == PLUGIN_OK)
        res->steps_done = 5;
    return st;
}
