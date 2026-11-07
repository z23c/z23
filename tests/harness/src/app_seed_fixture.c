/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the app.seed groups' leaf runner (test/app_seed_fixture.h). */

#include "test/app_seed_fixture.h"

#include "config/command_catalog.h"

#include <stdio.h>
#include <string.h>

#define ASF_SCHEMA "zcl.test.app_seed.v1"

void asf_open(struct asf_leaf *l)
{
    memset(l, 0, sizeof(*l));
    json_init(&l->in);
    json_set_object(&l->in);
    zcl_command_reply_init(&l->out, ASF_SCHEMA);
}

void asf_close(struct asf_leaf *l)
{
    zcl_command_reply_free(&l->out);
    json_free(&l->in);
}

const struct zcl_command_spec *asf_spec(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

bool asf_exec(const char *path, struct asf_leaf *l)
{
    char why[256] = "no such leaf";
    const struct zcl_command_spec *spec = asf_spec(path);
    if (!spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &l->in, why, sizeof(why))) {
        printf("  [%s not runnable: %s]\n", path, why);
        return false;
    }
    l->req.spec = spec;
    l->req.input = &l->in;
    l->req.invoked_name = spec->path;
    spec->handler(&l->req, &l->out);
    size_t bytes = json_write(&l->out.data, NULL, 0) + 1024u;
    if (spec->budget_bytes && bytes > (size_t)spec->budget_bytes) {
        printf("  [%s reply %zu bytes over its budget]\n", path, bytes);
        return false;
    }
    return true;
}

bool asf_pass(const char *path, struct asf_leaf *l)
{
    if (!asf_exec(path, l))
        return false;
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [%s refused %s: %s]\n", path, l->out.error.code,
               l->out.error.message);
    return l->out.status == ZCL_COMMAND_STATUS_PASSED;
}

bool asf_refusal(const struct asf_leaf *l, const char *code)
{
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        strcmp(l->out.error.code, code) == 0)
        return true;
    printf("  [expected %s; status=%d code=%s: %s]\n", code,
           (int)l->out.status, l->out.error.code, l->out.error.message);
    return false;
}

const char *asf_get(const struct asf_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

bool asf_flag(const struct asf_leaf *l, const char *key)
{
    const struct json_value *v = json_get(&l->out.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

bool asf_plan_confirm(const char *path, struct asf_leaf *l)
{
    char plan[65];
    if (!asf_pass(path, l) || strlen(asf_get(l, "plan_id")) != 64)
        return false;
    (void)snprintf(plan, sizeof(plan), "%s", asf_get(l, "plan_id"));
    zcl_command_reply_free(&l->out);
    zcl_command_reply_init(&l->out, ASF_SCHEMA);
    (void)json_push_kv_str(&l->in, "plan_id", plan);
    (void)json_push_kv_bool(&l->in, "confirm", true);
    return asf_pass(path, l);
}

bool asf_put(const char *dir, const char *rel, const char *text)
{
    char path[1200];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
}

bool asf_seed(struct asf_leaf *l, const char *app, const char *source,
              const char *datadir)
{
    asf_open(l);
    (void)json_push_kv_str(&l->in, "app", app);
    if (source)
        (void)json_push_kv_str(&l->in, "source", source);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    return asf_plan_confirm("app.seed", l);
}

bool asf_adopt(const char *release, const char *datadir, char *copy,
               size_t cap)
{
    struct asf_leaf l;
    asf_open(&l);
    (void)json_push_kv_str(&l.in, "root", release);
    (void)json_push_kv_str(&l.in, "datadir", datadir);
    bool ok = asf_plan_confirm("zcode.package.adopt", &l);
    (void)snprintf(copy, cap, "%s", asf_get(&l, "copy"));
    asf_close(&l);
    return ok && copy[0] == '/';
}

bool asf_build(struct asf_leaf *l, const char *copy, const char *datadir)
{
    asf_open(l);
    (void)json_push_kv_str(&l->in, "copy", copy);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    return asf_plan_confirm("app.build", l);
}
