/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * cli_confirm — the front door's y/N question (see cli_confirm.h). */

#include "command/cli_confirm.h"

#include <ctype.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#else
#include <io.h>
#define isatty _isatty
#endif

struct zcl_cli_confirm zcl_cli_confirm_resolve(bool yes_flag)
{
    struct zcl_cli_confirm c = {.mode = ZCL_CLI_CONFIRM_PLAN_ONLY};
    if (yes_flag)
        c.mode = ZCL_CLI_CONFIRM_YES;
    else if (isatty(0) && isatty(1))
        c.mode = ZCL_CLI_CONFIRM_ASK;
    return c;
}

bool zcl_cli_confirm_read_answer(FILE *in)
{
    char line[16];
    if (!in || !fgets(line, sizeof(line), in))
        return false;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] != '\n' && !feof(in))
        return false; /* longer than any yes */
    char *s = line;
    while (*s == ' ' || *s == '\t')
        s++;
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    for (size_t i = 0; i < len; i++)
        s[i] = (char)tolower((unsigned char)s[i]);
    return strcmp(s, "y") == 0 || strcmp(s, "yes") == 0;
}

bool zcl_cli_confirm_ask(const struct zcl_cli_confirm *c,
                         const char *question)
{
    if (!c || c->mode == ZCL_CLI_CONFIRM_PLAN_ONLY)
        return false;
    if (c->mode == ZCL_CLI_CONFIRM_YES)
        return true;
    if (c->ask)
        return c->ask(c->ctx, question ? question : "");
    fprintf(stderr, "%s [y/N] ", question ? question : "Continue?");
    fflush(stderr);
    return zcl_cli_confirm_read_answer(stdin);
}
