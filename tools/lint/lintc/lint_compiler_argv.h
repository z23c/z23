/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
/* purpose: Parse bounded compiler argument lists for native lint gates. */
#ifndef Z23_LINT_COMPILER_ARGV_H
#define Z23_LINT_COMPILER_ARGV_H

#include <stddef.h>
#include <string.h>
#include <unistd.h>

enum { LINT_CC_MAX_ARGS = 32 };

/* Write at most LINT_CC_MAX_ARGS words into argv. Caller appends its flags and NULL. */
static inline int lint_parse_compiler_argv(char *command, char **argv, size_t *count)
{
    *count = 0;
    size_t n = 0;
    if (!strpbrk(command, " \t\r\n") || access(command, X_OK) == 0) {
        if (*command) argv[n++] = command;
    } else {
        char *save = NULL;
        for (char *word = strtok_r(command, " \t\r\n", &save); word;
             word = strtok_r(NULL, " \t\r\n", &save)) {
            if (n >= LINT_CC_MAX_ARGS || strspn(word, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:+,=%-") != strlen(word))
                return 2;
            argv[n++] = word;
        }
    }
    *count = n;
    return n ? 0 : 2;
}

#endif
