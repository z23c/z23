/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Curated `make help` and the check that every named target exists. */

#ifndef ZCL_MAKE_HELP_H
#define ZCL_MAKE_HELP_H

/* Prints the curated help for repo/Makefile. argv[0] equal to "--self-test"
 * checks that every documented target heads a rule, that the existence
 * detector rejects zcl-target-that-cannot-exist, and that the help table
 * names no duration. Returns 0 on success, 1 when the self-test fails, and
 * 2 when repo is missing. */
int zcl_make_help(const char *repo, int argc, char **argv);

#endif
