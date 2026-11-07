/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared leaf runner for the app.seed groups (app_seed and
 * app_seed_skycombat). A leaf runs as the CLI and MCP run it: the registry
 * input contract, the handler, the reply budget. Plan/confirm leaves are
 * driven through the returned plan_id. */
#ifndef ZCL_TEST_APP_SEED_FIXTURE_H
#define ZCL_TEST_APP_SEED_FIXTURE_H

#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdbool.h>

struct asf_leaf {
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply out;
};

void asf_open(struct asf_leaf *l);
void asf_close(struct asf_leaf *l);
const struct zcl_command_spec *asf_spec(const char *path);

/* Input contract, then handler; false when the leaf is missing, the input
 * is refused by its contract or the reply is over budget. */
bool asf_exec(const char *path, struct asf_leaf *l);
/* asf_exec and the reply passed. */
bool asf_pass(const char *path, struct asf_leaf *l);
/* The reply refused with exactly this code. */
bool asf_refusal(const struct asf_leaf *l, const char *code);
/* A string field of the reply data ("" when absent). */
const char *asf_get(const struct asf_leaf *l, const char *key);
bool asf_flag(const struct asf_leaf *l, const char *key);
/* Plan, then repeat with the plan_id and confirm:true; both must pass. */
bool asf_plan_confirm(const char *path, struct asf_leaf *l);

/* Write text to dir/rel (parents must exist). */
bool asf_put(const char *dir, const char *rel, const char *text);

/* app.seed {app, source, datadir} planned and confirmed; the confirm reply
 * stays in l. */
bool asf_seed(struct asf_leaf *l, const char *app, const char *source,
              const char *datadir);
/* zcode.package.adopt of release into datadir; copy receives its absolute
 * directory. */
bool asf_adopt(const char *release, const char *datadir, char *copy,
               size_t cap);
/* app.build {copy, datadir} planned and confirmed; the reply stays in l. */
bool asf_build(struct asf_leaf *l, const char *copy, const char *datadir);

#endif /* ZCL_TEST_APP_SEED_FIXTURE_H */
