/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TEST_FIXTURE_ENVIRONMENT_H
#define ZCL_TEST_FIXTURE_ENVIRONMENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture_env {
    const char *name;
    char *value;
};

static inline bool fixture_env_save(struct fixture_env *env, const char *name)
{
    const char *value = getenv(name);
    env->value = value ? strdup(value) : NULL;
    if (value && !env->value)
        return false;
    env->name = name;
    return true;
}

static inline bool fixture_env_restore(struct fixture_env *env)
{
    if (!env->name)
        return true;
    int rc = env->value ? setenv(env->name, env->value, 1) : unsetenv(env->name);
    free(env->value);
    *env = (struct fixture_env){0};
    return rc == 0;
}

static inline bool fixture_path_prepend(const char *dir)
{
    const char *old = getenv("PATH");
    if (!old)
        return setenv("PATH", dir, 1) == 0;
    int length = snprintf(NULL, 0, "%s:%s", dir, old);
    if (length < 0)
        return false;
    size_t capacity = (size_t)length + 1;
    char *path = malloc(capacity);
    if (!path)
        return false;
    bool ok = snprintf(path, capacity, "%s:%s", dir, old) == length &&
              setenv("PATH", path, 1) == 0;
    free(path);
    return ok;
}
#endif
