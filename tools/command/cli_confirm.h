/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * cli_confirm — the one y/N question a front-door verb (`z23 app copy`,
 * `z23 app share`, `z23 app open FILE.z23share`, ...) asks a human before it
 * runs the confirm half of an owner composite.
 *
 * The answer is a CONVENIENCE for the person at the terminal, never an
 * authority boundary: every leaf a composite runs keeps its own authority,
 * and MCP never reaches the owner composites at all (they are AUTH_OWNER).
 *
 *   --yes             proceed without asking (scripted HUMAN use only);
 *   stdin and stdout  both a terminal: print the question on stderr and read
 *                     one line; only "y" or "yes" (any case) proceeds, so an
 *                     empty line, EOF or anything else is No;
 *   otherwise         PLAN ONLY: the caller runs the plan halves, prints the
 *                     plan and the next step, and mutates nothing.
 *
 * Tests inject the answer through `ask` instead of a terminal. */

#ifndef ZCL_CLI_CONFIRM_H
#define ZCL_CLI_CONFIRM_H

#include <stdbool.h>
#include <stdio.h>

enum zcl_cli_confirm_mode {
    ZCL_CLI_CONFIRM_PLAN_ONLY = 0, /* no terminal and no --yes */
    ZCL_CLI_CONFIRM_ASK,           /* a terminal: ask y/N */
    ZCL_CLI_CONFIRM_YES,           /* --yes */
};

struct zcl_cli_confirm {
    enum zcl_cli_confirm_mode mode;
    /* ASK only: the injected answer (tests). NULL reads the terminal. */
    bool (*ask)(void *ctx, const char *question);
    void *ctx;
};

/* --yes wins; else ASK when stdin and stdout are both terminals; else
 * PLAN_ONLY. */
struct zcl_cli_confirm zcl_cli_confirm_resolve(bool yes_flag);

/* True when the caller may run the confirm half. PLAN_ONLY is always false
 * and asks nothing; YES is always true; ASK prints `question` followed by
 * " [y/N] " on stderr and reads one answer. */
bool zcl_cli_confirm_ask(const struct zcl_cli_confirm *c,
                         const char *question);

/* Read one answer line from `in`: true only for y or yes, any case, with
 * surrounding blanks ignored. EOF, an empty line or a longer line is No. */
bool zcl_cli_confirm_read_answer(FILE *in);

#endif /* ZCL_CLI_CONFIRM_H */
