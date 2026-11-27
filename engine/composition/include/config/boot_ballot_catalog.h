/* purpose: Load an explicitly pinned test-network ballot catalog at boot. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_CONFIG_BOOT_BALLOT_CATALOG_H
#define ZCL_CONFIG_BOOT_BALLOT_CATALOG_H
#include <stdbool.h>
struct app_context;
/* Called after chain selection and datadir locking, before network services. */
bool boot_ballot_catalog_load(struct app_context *ctx);
#endif
