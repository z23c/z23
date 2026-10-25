/* purpose: standalone build/bin/sqlq entry point that delegates to sqlq_main */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Standalone build/bin/sqlq, built on every host: the same query tool as
 * `z23 sqlq`, kept as its own binary so no gate depends on the release z23. */

#include "multicall.h"

int main(int argc, char **argv)
{
    return sqlq_main(argc, argv);
}
