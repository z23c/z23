/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded test-only client for a semantic sensor session. */
#ifndef ZCL_TEST_SEMANTIC_FUZZ_SESSION_H
#define ZCL_TEST_SEMANTIC_FUZZ_SESSION_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
struct sfz_session { pid_t pid; int input, output, owner; unsigned seq; bool busy; };
bool sfz_session_start(struct sfz_session *, const struct sfz_session *, const char *, const char *, const char *const *, const char *, int64_t, int);
bool sfz_session_stop(struct sfz_session *);
bool sfz_session_exchange(struct sfz_session *, const char *const *, unsigned, int64_t);
#endif
