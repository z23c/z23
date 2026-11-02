/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared by msg_headers.c and msg_headers_getheaders.c.
 * NOT part of the public API. Declares the file-scope state and helper that
 * the outbound getheaders request builders (msg_headers_getheaders.c) read and
 * update while msg_headers.c keeps the serve-side and receive-side halves.
 * The counters are shared with msg_headers_get_stats(), which reports them. */

#ifndef ZCL_NET_MSG_HEADERS_INTERNAL_H
#define ZCL_NET_MSG_HEADERS_INTERNAL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Rising edge of a suppression streak: true the first call after `streak`
 * was cleared, false while the streak persists. Defined in msg_headers.c. */
bool getheaders_suppress_rising_edge(_Atomic bool *streak);

/* Suppression counters surfaced through msg_headers_get_stats(). */
extern _Atomic uint64_t g_getheaders_suppressed_no_hash;
extern _Atomic uint64_t g_getheaders_suppressed_snapshot;
extern _Atomic uint64_t g_push_getheaders_suppressed_snapshot;
extern _Atomic uint64_t g_push_getheaders_span_suppressed_snapshot;
extern _Atomic uint64_t g_push_getheaders_span_alloc_fail;

#endif /* ZCL_NET_MSG_HEADERS_INTERNAL_H */
