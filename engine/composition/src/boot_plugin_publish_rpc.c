/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resident plugin_publish_commit. A CLI signs a release offline and
 *          sends it with the license text; the node refreshes its own package
 *          store, verifies the release, re-hashes the plugin from its own
 *          plugin store, refuses a name or root mismatch before any write and
 *          commits with plugin_dist_commit. Owner-only and local: the RPC
 *          listener is local and cookie-authenticated. The datadir, plugin
 *          store and any path are never taken from input, and key bytes are
 *          never accepted. */

#include "config/boot_plugin_publish.h"

#include "config/boot_zcode_swarm.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "json/json.h"
#include "platform/private_directory.h"
#include "plugin/plugin_dist.h"
#include "rpc/server.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PUB_HEX_GENERATION 128u

struct pub_input {
    const char *name, *generation, *spdx, *license, *release_hex;
    size_t license_len;
};

static void pub_error(struct json_value *result, const char *code, const char *message,
                      const char *next_action)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
    if (next_action && next_action[0])
        json_push_kv_str(result, "next_action", next_action);
}

static void pub_dist_error(struct json_value *result, enum plugin_dist_status st, const char *detail)
{
    pub_error(result, plugin_dist_status_code(st), detail && detail[0] ? detail : "refused",
              plugin_dist_status_next_action(st));
}

static bool pub_key_allowed(const char *key)
{
    static const char *const allowed[] = { "name", "generation", "spdx", "license", "release" };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (strcmp(key, allowed[i]) == 0)
            return true;
    return false;
}

/* Only the five named fields; a datadir, plugins_dir, path or key is refused. */
static bool pub_parse(const struct json_value *in, struct pub_input *p)
{
    memset(p, 0, sizeof(*p));
    if (!in || in->type != JSON_OBJ)
        return false;
    for (size_t i = 0; i < in->num_children; i++)
        if (!in->keys || !in->keys[i] || !pub_key_allowed(in->keys[i]))
            return false;
    p->name = json_get_str(json_get(in, "name"));
    p->generation = json_get_str(json_get(in, "generation"));
    p->spdx = json_get_str(json_get(in, "spdx"));
    p->license = json_get_str(json_get(in, "license"));
    p->release_hex = json_get_str(json_get(in, "release"));
    if (!p->name || !p->generation || !p->spdx || !p->license || !p->release_hex)
        return false;
    p->license_len = strlen(p->license);
    return strlen(p->generation) == PUB_HEX_GENERATION && p->license_len > 0;
}

/* Writes the request license text to a private file the prepare step reads. */
static bool pub_license_file(const char *scratch_dir, const char *text, size_t len,
                             char path[PATH_MAX])
{
    if (!scratch_dir || !platform_private_directory_ensure(scratch_dir) ||
        snprintf(path, PATH_MAX, "%s/license.XXXXXX", scratch_dir) >= PATH_MAX)
        return false;
    int fd = mkstemp(path);
    if (fd < 0)
        return false;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    bool ok = off == len;
    if (close(fd) != 0)
        ok = false;
    if (!ok)
        (void)unlink(path);
    return ok;
}

static void pub_reply(struct json_value *result, const struct plugin_dist_published *pub)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "name", pub->name);
    json_push_kv_str(result, "version", pub->version);
    json_push_kv_str(result, "root", pub->root_hex);
    json_push_kv_str(result, "manifest_sha3", pub->generation);
    json_push_kv_int(result, "files", (int64_t)pub->files);
    json_push_kv_int(result, "bytes", (int64_t)pub->bytes);
}

/* Hex to bytes, parsed and verified; false (result filled) when it is not a
 * validly signed release envelope. */
static bool pub_release(const struct pub_input *p, uint8_t **wire, size_t *wire_len,
                        struct json_value *result)
{
    struct vcs_package_release rel;
    *wire = zcl_calloc(1, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, "plugin_publish_release");
    if (!*wire) {
        pub_dist_error(result, PLUGIN_DIST_ERR_STORE, "out of memory");
        return false;
    }
    if (!zcl_hex_decode_n(p->release_hex, *wire, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, wire_len) ||
        vcs_package_release_parse(*wire, *wire_len, &rel) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&rel) != VCS_PACKAGE_RELEASE_OK) {
        free(*wire);
        *wire = NULL;
        pub_dist_error(result, PLUGIN_DIST_ERR_RELEASE,
                       "the release is not a validly signed release envelope");
        return false;
    }
    return true;
}

static enum plugin_dist_status pub_prepare(const struct pub_input *p, const char *plugins_dir,
                                           const char *scratch_dir, char license[PATH_MAX],
                                           struct plugin_dist_prepared **prep,
                                           struct plugin_dist_published *pub)
{
    license[0] = '\0';
    if (!pub_license_file(scratch_dir, p->license, p->license_len, license)) {
        memset(pub, 0, sizeof(*pub));
        snprintf(pub->detail, sizeof(pub->detail), "cannot stage the license text");
        return PLUGIN_DIST_ERR_IO;
    }
    struct plugin_dist_publish_request rq = {
        .plugins_dir = plugins_dir, .name = p->name, .generation = p->generation,
        .license_file = license, .spdx = p->spdx
    };
    return plugin_dist_prepare(&rq, prep, pub);
}

void boot_plugin_publish_commit_run(const struct json_value *in, struct vcs_package_store *store,
                                    const char *plugins_dir, const char *scratch_dir,
                                    struct json_value *result)
{
    struct pub_input p;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct plugin_dist_prepared *prep = NULL;
    struct plugin_dist_published pub;
    char license[PATH_MAX] = "";
    if (!pub_parse(in, &p)) {
        pub_error(result, "PLUGIN_DIST_ARGUMENT",
                  "one input object with name, generation (128 hex), spdx, license and release "
                  "(hex) is required; datadir, plugins_dir, paths and keys are not accepted",
                  "pass exactly those five fields");
        return;
    }
    if (p.license_len > VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES) {
        pub_dist_error(result, PLUGIN_DIST_ERR_LICENSE, "the license text is over the size cap");
        return;
    }
    if (!store || !plugins_dir) {
        pub_error(result, "PLUGIN_PUBLISH_NO_STORE", "package hosting is not running on this node",
                  "start the node with -packagehost=1, or publish with the offline CLI");
        return;
    }
    if (!vcs_package_store_refresh(store)) {
        pub_dist_error(result, PLUGIN_DIST_ERR_STORE, "the package store could not be refreshed");
        return;
    }
    if (!pub_release(&p, &wire, &wire_len, result))
        return;
    enum plugin_dist_status st = pub_prepare(&p, plugins_dir, scratch_dir, license, &prep, &pub);
    if (st == PLUGIN_DIST_OK)
        st = plugin_dist_commit(store, prep, wire, wire_len, &pub);
    if (st == PLUGIN_DIST_OK)
        pub_reply(result, &pub);
    else
        pub_dist_error(result, st, pub.detail);
    /* The chunks are read from the license copy at commit time, so it goes last. */
    if (license[0])
        (void)unlink(license);
    plugin_dist_prepared_free(prep);
    free(wire);
}

static bool pub_rpc(const struct json_value *params, bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result, "plugin_publish_commit {name,generation,spdx,license,release}");
        return true;
    }
    const struct json_value *in = params && json_size(params) ? json_at(params, 0) : NULL;
    char plugins[PATH_MAX], scratch[PATH_MAX];
    struct vcs_package_store *store = vcs_package_store_global();
    const char *root = store ? vcs_package_store_root_dir(store) : NULL;
    if (!root || !zcl_native_plugin_root(plugins, PATH_MAX) ||
        snprintf(scratch, PATH_MAX, "%s/plugin-dist", root) >= PATH_MAX)
        store = NULL;
    boot_plugin_publish_commit_run(in, store, plugins, scratch, result);
    if (json_get(result, "ok") && json_get_bool(json_get(result, "ok")))
        boot_zcode_swarm_request_tick();
    return true;
}

void boot_plugin_publish_register_rpc(struct rpc_table *table)
{
    static const struct rpc_command command = { "plugin", "plugin_publish_commit", pub_rpc, true };
    rpc_table_must_append(table, &command);
}
