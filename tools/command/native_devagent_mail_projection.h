/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private bridge for rebuildable compact-mail history projection. */
#ifndef ZCL_NATIVE_DEVAGENT_MAIL_PROJECTION_H
#define ZCL_NATIVE_DEVAGENT_MAIL_PROJECTION_H
#include "command/native_dev_mail_projection.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
struct json_value;
enum dvm_projection_line { DVM_PROJECTION_OK, DVM_PROJECTION_LONG, DVM_PROJECTION_PARTIAL, DVM_PROJECTION_EOF };
enum dvm_projection_line dvm_projection_read_line(FILE *f, char *buf, size_t cap);
bool dvm_projection_stream_name(const char *name);
/* False means malformed row or projection failure; callers must distinguish
 * malformed rows during rebuilding from failure during exact materialization. */
bool dvm_projection_parse(const char *raw, size_t len, const char *stream,
                          int64_t offset, struct dev_mail_locator *loc, struct json_value *json);
bool dvm_projection_exact(const char *dir, const char *stream,
                          const struct dev_mail_locator *loc, struct json_value *json);
/* All-or-fallback: result valid only on true; rows contains an ordered array. */
bool dvm_projection_refs(const char *const *refs, size_t nrefs, struct json_value *rows);
/* Explicit native maintenance, never called by the feed read path. NULL root
 * uses the current native state root; otherwise the operator's state-root.
 * Counts describe a complete descriptor/hash-verified rebuild only on true. */
bool dvm_projection_rebuild_history(const char *state_root,size_t *streams,int64_t *bytes);
#ifdef ZCL_TESTING
size_t dvm_projection_test_warm_hits(bool reset);
size_t dvm_projection_test_tail_updates(bool reset);
size_t dvm_projection_test_hash_bytes(bool reset);
void dvm_projection_test_before_parse(void (*hook)(void));
void dvm_projection_test_after_rebuild(void (*hook)(void));
bool zcl_fleet_steer_test_projection_ref(const char *directive, const char *candidate,
                                         bool *matches_original, bool *matches_expansion);
#endif
#endif
