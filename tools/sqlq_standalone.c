/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Standalone build/bin/sqlq: the same query CLI as `z23 sqlq`, kept as its
 * own binary because operator scripts and gates name build/bin/sqlq. */

#include "multicall.h"

int main(int argc, char **argv)
{
    return sqlq_main(argc, argv);
}
