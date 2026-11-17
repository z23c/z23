/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Parse one explicit public app catalog or offer URL. */
#ifndef ZCL_NATIVE_APP_NETWORK_LINK_H
#define ZCL_NATIVE_APP_NETWORK_LINK_H
#include <stdbool.h>
struct app_network_link
{
    char onion[63]; char post_id[65]; bool exact; unsigned port;
};
/* The canonical URL, or a bare 62-char v3 onion optionally "host:port";
 * no decoding, credentials, query or fragment. port is nonzero only for
 * the bare host:port form; the board fetch dials the endpoint's default
 * port, so consumers refuse a nonzero port rather than silently re-dial. */
bool app_network_link_parse(const char *text, struct app_network_link *out);
#endif
