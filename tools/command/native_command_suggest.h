/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The answer to an unknown command: the standard zcl.result.v1 failure
 * envelope, whose next[] names up to three real nearest commands computed
 * from the registry itself, then the search pointer, then the one command
 * that lists the surrounding group. Pure: it reads only the registry. */
#ifndef ZCL_TOOLS_NATIVE_COMMAND_SUGGEST_H
#define ZCL_TOOLS_NATIVE_COMMAND_SUGGEST_H

#include <stddef.h>

struct zcl_command_registry;

struct zcl_unknown_command {
    const char *command;  /* envelope "command" (what the operator typed) */
    const char *message;  /* envelope message, kept as each caller had it */
    const char *evidence; /* envelope evidence */
    const char *query;    /* the wrong word, for the discover.search pointer */
    const char *const *words; /* typed words; scanning stops at a flag */
    size_t count;
};

/* Writes the UNKNOWN_COMMAND envelope JSON; returns its length, 0 when it
 * does not fit `cap`. */
size_t zcl_native_unknown_command_json(const struct zcl_command_registry *reg,
                                       const struct zcl_unknown_command *u,
                                       char *out, size_t cap);

#endif
