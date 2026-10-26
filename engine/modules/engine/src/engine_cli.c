/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_cli — which arguments an installed agent CLI receives.
 *
 * Each CLI is a row in a table; adding one needs no code change.
 *
 * See engine/engine.h for the placeholder vocabulary and why a flag a vendor
 * lacks is ABSENT from its row rather than mapped onto something close.
 */

#include "engine/engine.h"

#include "base/log_macros.h"

#include <string.h>

bool engine_reasoning_effort_valid(const char *effort)
{
    return !effort || !effort[0] ||
           strcmp(effort, ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT) == 0 ||
           strcmp(effort, "low") == 0 || strcmp(effort, "medium") == 0 ||
           strcmp(effort, "high") == 0 || strcmp(effort, "xhigh") == 0;
}

bool engine_reasoning_effort_explicit(const char *effort)
{
    return effort && effort[0] &&
           strcmp(effort, ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT) != 0;
}

bool engine_resume_session_id_valid(const char *id)
{
    if (!id)
        return true;
    if (strlen(id) != 36u)
        return false;
    for (size_t i = 0; i < 36u; i++) {
        if (i == 8u || i == 13u || i == 18u || i == 23u) {
            if (id[i] != '-')
                return false;
            continue;
        }
        const char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

bool engine_cli_turns_parse(const char *text, int *out)
{
    if (!text || !out || !text[0])
        return false;
    unsigned value = 0;
    for (size_t i = 0; text[i]; i++) {
        const unsigned char c = (unsigned char)text[i];
        if (c < (unsigned char)'0' || c > (unsigned char)'9')
            return false;
        value = value * 10u + (unsigned)(c - (unsigned char)'0');
        if (value > 256u)
            return false;
    }
    if (value < 1u)
        return false;
    *out = (int)value;
    return true;
}

bool engine_cli_accepts_turns(const struct engine_vendor *v)
{
    if (!v || v->wire != ENGINE_WIRE_LOCAL_CLI || !v->start_argv)
        return false;
    for (size_t i = 0; v->start_argv[i]; i++)
        if (strcmp(v->start_argv[i], ENGINE_CLI_TURNS_TOKEN) == 0)
            return true;
    return false;
}

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
    if (strcmp(slot, ENGINE_CLI_RESUME_TOKEN) == 0) return in->resume_session_id;
    /* A brace-shaped slot this file does not know is not passed through as a
     * literal. A CLI receiving the six characters {mdoel} would treat them as
     * a value and do something confident and wrong. */
    *unknown = true;
    return NULL;
}

const char *engine_cli_launch_cwd(const struct engine_vendor *v,
                                  const struct engine_cli_inputs *in)
{
    if (!v || !in || !v->cli_cwd_is_workdir || !in->workdir || !in->workdir[0])
        return NULL;
    return in->workdir;
}

/* A report unit runs the row's read-only form when it has one. A row with
 * none keeps its editing form, and REPORT_EDITED remains the check there. */
static const char *const *argv_template(const struct engine_vendor *v,
                                        const struct engine_cli_inputs *in)
{
    if (in->read_only && v->report_start_argv)
        return v->report_start_argv;
    return v->start_argv;
}

/* Why a build refused, in the order the checks run. The three
 * out-of-room refusals share one code because they print one message. */
enum argv_fill_status {
    ARGV_FILL_OK,
    ARGV_FILL_BAD_ARGS,
    ARGV_FILL_NO_PROGRAM,
    ARGV_FILL_NO_TEMPLATE,
    ARGV_FILL_PROMPT_TOO_LONG,
    ARGV_FILL_UNKNOWN_PLACEHOLDER,
    ARGV_FILL_MISSING_VALUE,
    ARGV_FILL_NO_ROOM,
    ARGV_FILL_BAD_EFFORT,
    ARGV_FILL_NO_EFFORT_FLAG,
    ARGV_FILL_BAD_RESUME_ID,
    ARGV_FILL_NO_RESUME_ARGV,
    ARGV_FILL_BAD_RESUME_TEMPLATE,
};

static enum argv_fill_status argv_check_vendor(const struct engine_vendor *v)
{
    if (!v->program || !v->program[0])
        return ARGV_FILL_NO_PROGRAM;
    if (!v->start_argv)
        return ARGV_FILL_NO_TEMPLATE;
    return ARGV_FILL_OK;
}

/* An argument-mode prompt is bounded well below the prompt ceiling,
 * because the kernel bounds a single argv string far below it. Refused
 * here, with its real reason, rather than surfacing later as a failure to
 * launch the program. */
static enum argv_fill_status
argv_check_prompt_arg(const struct engine_vendor *v,
                      const struct engine_cli_inputs *in)
{
    if (v->cli_prompt == ENGINE_CLI_PROMPT_ARG && in->prompt
        && strlen(in->prompt) > ENGINE_CLI_ARG_PROMPT_MAX)
        return ARGV_FILL_PROMPT_TOO_LONG;
    return ARGV_FILL_OK;
}

/* Resolve and append the chosen template, recording in *bad_slot the
 * element that refused so the caller can name it in its log line. */
static enum argv_fill_status
argv_fill_template(const char *const *tpl,
                   const struct engine_cli_inputs *in, const char **out,
                   size_t cap, size_t *n, const char **bad_slot)
{
    for (size_t i = 0; tpl[i]; i++) {
        bool unknown = false;
        const char *value = resolve(tpl[i], in, &unknown);
        if (unknown) {
            *bad_slot = tpl[i];
            return ARGV_FILL_UNKNOWN_PLACEHOLDER;
        }
        if (!value || !value[0]) {
            *bad_slot = tpl[i];
            return ARGV_FILL_MISSING_VALUE;
        }
        /* +1 for the terminator, which is written after the loop. */
        if (*n + 1 >= cap)
            return ARGV_FILL_NO_ROOM;
        out[(*n)++] = value;
    }
    return ARGV_FILL_OK;
}

static enum argv_fill_status
argv_append_effort(const struct engine_vendor *v,
                   const struct engine_cli_inputs *in, const char **out,
                   size_t cap, size_t *n)
{
    if (!engine_reasoning_effort_valid(in->reasoning_effort))
        return ARGV_FILL_BAD_EFFORT;
    if (!engine_reasoning_effort_explicit(in->reasoning_effort))
        return ARGV_FILL_OK;
    if (!v->cli_reasoning_effort_flag)
        return ARGV_FILL_NO_EFFORT_FLAG;
    if (*n + 3 > cap)
        return ARGV_FILL_NO_ROOM;
    out[(*n)++] = v->cli_reasoning_effort_flag;
    out[(*n)++] = in->reasoning_effort;
    return ARGV_FILL_OK;
}

static enum argv_fill_status
argv_append_resume(const struct engine_vendor *v,
                   const struct engine_cli_inputs *in, const char **out,
                   size_t cap, size_t *n)
{
    if (!engine_resume_session_id_valid(in->resume_session_id))
        return ARGV_FILL_BAD_RESUME_ID;
    if (!in->resume_session_id)
        return ARGV_FILL_OK;
    if (!v->resume_argv)
        return ARGV_FILL_NO_RESUME_ARGV;
    if (*n + 3 > cap)
        return ARGV_FILL_NO_ROOM;
    for (size_t i = 0; v->resume_argv[i]; i++) {
        bool unknown = false;
        const char *value = resolve(v->resume_argv[i], in, &unknown);
        if (unknown || !value || !value[0] || *n + 1 >= cap)
            return ARGV_FILL_BAD_RESUME_TEMPLATE;
        out[(*n)++] = value;
    }
    return ARGV_FILL_OK;
}

/* Run every check and append in the order engine_cli_argv_build always
 * ran them, stopping at the first refusal; the caller turns the code into
 * the same log line it prints today. */
static enum argv_fill_status
argv_fill(const struct engine_vendor *v, const struct engine_cli_inputs *in,
          const char **out, size_t cap, size_t *n, const char **bad_slot)
{
    if (!v || !in || !out || cap == 0)
        return ARGV_FILL_BAD_ARGS;
    enum argv_fill_status st = argv_check_vendor(v);
    if (st != ARGV_FILL_OK)
        return st;
    const char *const *tpl = argv_template(v, in);
    st = argv_check_prompt_arg(v, in);
    if (st != ARGV_FILL_OK)
        return st;
    *n = 0;
    out[(*n)++] = v->program;
    st = argv_fill_template(tpl, in, out, cap, n, bad_slot);
    if (st != ARGV_FILL_OK)
        return st;
    st = argv_append_effort(v, in, out, cap, n);
    if (st != ARGV_FILL_OK)
        return st;
    return argv_append_resume(v, in, out, cap, n);
}

size_t engine_cli_argv_build(const struct engine_vendor *v,
                             const struct engine_cli_inputs *in,
                             const char **out, size_t cap)
{
    size_t n = 0;
    const char *bad_slot = NULL;
    const enum argv_fill_status st =
        argv_fill(v, in, out, cap, &n, &bad_slot);
    if (st == ARGV_FILL_BAD_ARGS)
        LOG_RETURN(0, "engine", "bad arguments to engine_cli_argv_build");
    if (st == ARGV_FILL_NO_PROGRAM)
        LOG_RETURN(0, "engine", "engine %s names no program to run", v->id);
    if (st == ARGV_FILL_NO_TEMPLATE)
        LOG_RETURN(0, "engine", "engine %s carries no argv template", v->id);
    if (st == ARGV_FILL_PROMPT_TOO_LONG)
        LOG_RETURN(0, "engine",
                   "engine %s takes its prompt as an argument and this one is "
                   "%zu bytes, over the %u-byte limit a single argument may "
                   "hold; refusing rather than truncating",
                   v->id, strlen(in->prompt),
                   (unsigned)ENGINE_CLI_ARG_PROMPT_MAX);
    if (st == ARGV_FILL_UNKNOWN_PLACEHOLDER)
        LOG_RETURN(0, "engine",
                   "engine %s names the argv placeholder %s, which this "
                   "build does not know", v->id, bad_slot);
    if (st == ARGV_FILL_MISSING_VALUE)
        LOG_RETURN(0, "engine",
                   "engine %s needs a value for %s and none was supplied",
                   v->id, bad_slot);
    if (st == ARGV_FILL_NO_ROOM)
        LOG_RETURN(0, "engine",
                   "engine %s needs more than %zu argv slots", v->id, cap);
    if (st == ARGV_FILL_BAD_EFFORT)
        LOG_RETURN(0, "engine", "invalid reasoning effort");
    if (st == ARGV_FILL_NO_EFFORT_FLAG)
        LOG_RETURN(0, "engine", "engine %s accepts no reasoning effort",
                   v->id);
    if (st == ARGV_FILL_BAD_RESUME_ID)
        LOG_RETURN(0, "engine", "invalid resume session id");
    if (st == ARGV_FILL_NO_RESUME_ARGV)
        LOG_RETURN(0, "engine", "engine %s accepts no resume session",
                   v->id);
    if (st == ARGV_FILL_BAD_RESUME_TEMPLATE)
        LOG_RETURN(0, "engine", "invalid resume argv template");
    out[n] = NULL;
    return n;
}

bool engine_accepts_model_override(const struct engine_vendor *v,
                                   const char *model)
{
    if (!model || !model[0])
        return true;
    return v && !v->cli_no_model_arg;
}
