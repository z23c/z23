/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the developer loop for one plugin in one call. plugin_dev creates
 * the developer signing key when it is missing, lists its public key as a
 * publisher key, packs <dir>/NAME into <dir>/dist, installs the packed
 * generation and makes it current, so a running supervisor takes it up on
 * SIGHUP. It calls the store and pack functions directly. A failed step
 * leaves the current generation as it was and is named in the result.
 * docs/dev/PLUGINS.md describes the command. */
#ifndef ZCL_PLUGIN_DEV_H
#define ZCL_PLUGIN_DEV_H

#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>

enum plugin_dev_step {
    PLUGIN_DEV_STEP_KEY = 0,
    PLUGIN_DEV_STEP_PACK,
    PLUGIN_DEV_STEP_PUBLISHER,
    PLUGIN_DEV_STEP_INSTALL,
    PLUGIN_DEV_STEP_SWITCH,
    PLUGIN_DEV_STEP_COUNT
};

/* "key", "pack", "publisher", "install" or "switch", in the order they run. */
const char *plugin_dev_step_name(enum plugin_dev_step step);

struct plugin_dev_request {
    const char *root;         /* plugin store, normally ~/.z23/plugins */
    const char *dir;          /* holds the built executable NAME */
    const char *name;         /* NULL means the last component of dir */
    const char *version;      /* NULL means "0.0.0-dev" */
    const char *key_path;     /* NULL means plugin_dev.key beside root */
    unsigned capabilities;
    int interface_version;    /* 0 means 1 */
};

struct plugin_dev_result {
    char name[PLUGIN_NAME_MAX + 1];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    char public_key[PLUGIN_HEX_PUBLIC_KEY + 1];
    char key_path[4096];
    char manifest_path[4096];
    size_t sequence;          /* generations stored for NAME, this one included */
    bool key_created;
    bool publisher_added;
    bool already_present;
    unsigned steps_done;      /* steps finished, in enum order */
    enum plugin_dev_step failed; /* valid when the call did not return PLUGIN_OK */
};

enum plugin_status plugin_dev(const struct plugin_dev_request *request,
                              struct plugin_dev_result *result);

#endif
