/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Parse-cache budget boot adapter — declares the RAM-class env default for
 * the block parse cache's resident byte ceiling (ZCL_PARSE_CACHE_MAX_BYTES,
 * engine/modules/storage/src/block_parse_cache.c) and the boot_services.c
 * entry point that registers the parse_cache service.
 * See engine/composition/src/boot_parse_cache.c for the decision table. */

#ifndef ZCL_BOOT_PARSE_CACHE_H
#define ZCL_BOOT_PARSE_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/hw_profile.h"

struct boot_svc_ctx;

/* Parse-cache resident byte ceiling per RAM class. LOW 64 MiB; MEDIUM
 * 128 MiB (the engine flag default, made explicit so the effective-limits
 * log line reports the applied value); HIGH refuses (the engine default
 * stands, byte-identical behavior). */
struct boot_parse_cache_limits {
    int64_t max_bytes;
};

/* Pure per-class decision — no env reads, no hardware probing. Returns
 * true and fills *out for LOW and MEDIUM; returns false for HIGH (and
 * refuses a NULL out), leaving *out untouched. */
bool boot_parse_cache_limits_for_class(enum hw_profile_ram_class cls,
                                       struct boot_parse_cache_limits *out);

/* Sets the ceiling env var ONLY when it is absent, so an explicit operator
 * env always wins. An empty value counts as present: the cache's own
 * parser then falls back to its compiled default, exactly as it does
 * today. HIGH sets nothing and returns true; a failed setenv logs and
 * returns false. */
bool boot_parse_cache_limits_apply_class(enum hw_profile_ram_class cls);

/* Registers the parse_cache service on svc->service_kernel (beside
 * net_budgets, before the mempool_limits adapter's start_all, so the env
 * default is in place before any sync stage can trigger the cache's
 * lazy first-use read). Returns false (with a FATAL message already
 * printed) on register failure — app_init_services must abort boot in
 * that case. */
bool boot_start_parse_cache_service(struct boot_svc_ctx *svc);

#endif /* ZCL_BOOT_PARSE_CACHE_H */
