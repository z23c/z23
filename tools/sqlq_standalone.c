/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Standalone build/bin/sqlq for hosts without the argv0 symlink (Windows):
 * the same query tool as `z23 sqlq`, kept as its own binary. */

#include "multicall.h"

int main(int argc, char **argv)
{
    return sqlq_main(argc, argv);
}
