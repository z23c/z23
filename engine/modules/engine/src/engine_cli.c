/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_cli — which arguments an installed agent CLI receives.
 *
 * This used to be a fixed array inside tools/engine_unit.c, shaped around the
 * one CLI the tree happened to dispatch to. That is why the second one never
 * arrived: the owner's machine held a working subscription to it, and the
 * only thing standing in the way was seven hard-coded strings in a program no
 * test links. A row in a table cannot go missing that way.
 *
 * See engine/engine.h for the placeholder vocabulary and why a flag a vendor
 * lacks is ABSENT from its row rather than mapped onto something close.
 */

#include "engine/engine.h"

#include "base/log_macros.h"

#include <string.h>

/* Resolve one template element. A literal returns itself. A placeholder
 * returns the caller's value, or NULL when the caller did not supply one —
 * which is a refusal, not an empty argument. */
static const char *resolve(const char *slot,
                           const struct engine_cli_inputs *in,
                           bool *unknown)
{
    *unknown = false;
    if (slot[0] != '{')
        return slot;
    if (strcmp(slot, ENGINE_CLI_PROMPT_TOKEN) == 0)  return in->prompt;
    if (strcmp(slot, ENGINE_CLI_WORKDIR_TOKEN) == 0) return in->workdir;
    if (strcmp(slot, ENGINE_CLI_TURNS_TOKEN) == 0)   return in->turns;
    if (strcmp(slot, ENGINE_CLI_MODEL_TOKEN) == 0)   return in->model;
    /* A brace-shaped slot this file does not know is not passed through as a
     * literal. A CLI receiving the six characters {mdoel} would treat them as
     * a value and do something confident and wrong. */
    *unknown = true;
    return NULL;
}

size_t engine_cli_argv_build(const struct engine_vendor *v,
                             const struct engine_cli_inputs *in,
                             const char **out, size_t cap)
{
    if (!v || !in || !out || cap == 0)
        LOG_RETURN(0, "engine", "bad arguments to engine_cli_argv_build");
    if (!v->program || !v->program[0])
        LOG_RETURN(0, "engine", "engine %s names no program to run", v->id);
    if (!v->cli_argv)
        LOG_RETURN(0, "engine", "engine %s carries no argv template", v->id);

    /* An argument-mode prompt is bounded well below the prompt ceiling,
     * because the kernel bounds a single argv string far below it. Refused
     * here, with its real reason, rather than surfacing later as a failure to
     * launch the program. */
    if (v->cli_prompt == ENGINE_CLI_PROMPT_ARG && in->prompt
        && strlen(in->prompt) > ENGINE_CLI_ARG_PROMPT_MAX)
        LOG_RETURN(0, "engine",
                   "engine %s takes its prompt as an argument and this one is "
                   "%zu bytes, over the %u-byte limit a single argument may "
                   "hold; refusing rather than truncating",
                   v->id, strlen(in->prompt),
                   (unsigned)ENGINE_CLI_ARG_PROMPT_MAX);

    size_t n = 0;
    out[n++] = v->program;
    for (size_t i = 0; v->cli_argv[i]; i++) {
        bool unknown = false;
        const char *value = resolve(v->cli_argv[i], in, &unknown);
        if (unknown)
            LOG_RETURN(0, "engine",
                       "engine %s names the argv placeholder %s, which this "
                       "build does not know", v->id, v->cli_argv[i]);
        if (!value || !value[0])
            LOG_RETURN(0, "engine",
                       "engine %s needs a value for %s and none was supplied",
                       v->id, v->cli_argv[i]);
        /* +1 for the terminator, which is written after the loop. */
        if (n + 1 >= cap)
            LOG_RETURN(0, "engine",
                       "engine %s needs more than %zu argv slots", v->id, cap);
        out[n++] = value;
    }
    out[n] = NULL;
    return n;
}
