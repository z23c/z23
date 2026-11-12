/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host tool Make recipes exec. Its recipe is not itself wrapped
 *          in the checkout lock. Arguments match the retired shell tool:
 *          checkout-lock {foreground|watcher} LOCK_FILE -- CMD... */

#include "checkout_lock.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int cmd;
    if (argc < 4)
        return zcl_checkout_lock_run(NULL, NULL, NULL, STDERR_FILENO);
    cmd = 3;
    if (strcmp(argv[cmd], "--") == 0)
        cmd++;
    if (cmd >= argc)
        return zcl_checkout_lock_run(argv[1], argv[2], NULL, STDERR_FILENO);
    return zcl_checkout_lock_run(argv[1], argv[2],
                                 (const char *const *)(argv + cmd),
                                 STDERR_FILENO);
}
