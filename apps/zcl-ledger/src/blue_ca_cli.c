/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_ca.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "generate") != 0) {
        fprintf(stderr, "Usage: %s generate PRIVATE_KEY_FILE\n", argv[0]);
        return 2;
    }
    if (blue_ca_generate(argv[2]) < 0) {
        fputs("Cannot create a new private key file; existing files are never overwritten.\n",
              stderr);
        return 1;
    }
    puts("Ledger Blue CA key created with owner-only access.");
    return 0;
}
