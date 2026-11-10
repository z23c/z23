/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Parse one explicit public app catalog or offer URL. */
#ifndef ZCL_NATIVE_APP_NETWORK_LINK_H
#define ZCL_NATIVE_APP_NETWORK_LINK_H
#include <stdbool.h>
struct app_network_link { char onion[63]; char post_id[65]; bool exact; };
/* Whole canonical URL only; no decoding, credentials, query or fragment. */
bool app_network_link_parse(const char *text, struct app_network_link *out);
#endif
