/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone fixture node for manual z23-wallet runs: serves one
 * scenario on 127.0.0.1 and records its port in <datadir>/.rpcport. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../harness/src/z23wallet_mock_node.h"

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: mock_node <scenario_dir> <datadir> [seconds]\n");
        return 2;
    }
    if (!zw_mock_write_cookie(argv[2], "__cookie__:fixturecookie0123456789")) {
        fprintf(stderr, "cannot write the fixture cookie into %s\n", argv[2]);
        return 1;
    }
    uint16_t port = 0;
    struct zw_mock *m = zw_mock_start(argv[1], argv[2], &port);
    if (!m) {
        fprintf(stderr, "cannot start the mock node\n");
        return 1;
    }
    char p[600];
    snprintf(p, sizeof(p), "%s/.rpcport", argv[2]);
    FILE *f = fopen(p, "wb");
    if (f) { fprintf(f, "%u", (unsigned)port); fclose(f); }
    printf("mock node on 127.0.0.1:%u\n", (unsigned)port);
    fflush(stdout);
    int secs = argc > 3 ? atoi(argv[3]) : 600;
    struct timespec ts = { 1, 0 };
    for (int i = 0; i < secs; i++) nanosleep(&ts, NULL);
    zw_mock_stop(m);
    return 0;
}
