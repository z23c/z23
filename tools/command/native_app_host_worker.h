/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Reserved same-image app-only hosting entry before normal configuration. */
#ifndef ZCL_NATIVE_APP_HOST_WORKER_H
#define ZCL_NATIVE_APP_HOST_WORKER_H
#include "chain/chainparamsbase.h"
const char *app_host_chain_token(enum chain_network network);
/* Reserved exit belongs only to a normally expired host window. */
#define APP_HOST_EXIT_EXPIRED 73
/* Reserved flag is handled even when argv is malformed; never fall through
 * to node/config startup. Private Tor startup remains an explicit dependency. */
int app_host_worker_main(int argc, char **argv);
#if defined(ZCL_TESTING) && !defined(_WIN32)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool zcl_test_app_host_bootstrap_port(bool (*fill)(uint8_t *, size_t), uint16_t *);
/* Changes cwd: test only in a disposable child. */
bool zcl_test_app_host_enter_scratch(const char *, uint64_t, uint64_t);
bool zcl_test_app_host_store_carrier(const uint8_t *, size_t, char root[65]);
bool zcl_test_app_host_verify_carrier(const char *, const char *, const char *, const char *, const char *, uint64_t);
#endif
#endif
