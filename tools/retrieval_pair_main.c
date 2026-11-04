/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: enter the standalone maintained retrieval command transport. */
#include "command/native_retrieval_cli.h"
int main(int argc, char **argv)
{
    return zcl_retrieval_cli_main(argc, argv);
}
