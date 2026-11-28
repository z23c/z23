/* purpose: Load an explicitly pinned test-network ballot catalog at boot. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_CONFIG_BOOT_BALLOT_CATALOG_H
#define ZCL_CONFIG_BOOT_BALLOT_CATALOG_H
#include <stdbool.h>
struct app_context;
/* A research node boot creates, chmods or publishes nothing in its datadir
 * before catalog consent is present in argv or config (main_research_bind);
 * the prologue check remains authoritative for in-process boots. */
/* Valid only after argv and config parsing. */
bool boot_ballot_catalog_consent_present(void);
extern const char boot_ballot_catalog_consent_refusal[];
bool boot_ballot_catalog_consent(const struct app_context *ctx);
/* Called after chain selection and datadir locking, before network services. */
bool boot_ballot_catalog_load(struct app_context *ctx);
/* Select the profile named by ctx->testnet_profile; Windows supports none. */
bool boot_research_profile_select(const struct app_context *ctx);
#endif
