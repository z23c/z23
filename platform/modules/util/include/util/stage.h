/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Forwarding header — the reducer stage machinery moved to core/modules/sync, which
 * already owns the reducer state machines. It is the one part of platform/modules/util
 * that read from engine/modules/storage (progress_store_*), and that back edge was
 * what held util inside the module-graph cycle. New code should include
 * "sync/stage.h" directly. */

#ifndef ZCL_UTIL_STAGE_FORWARD_H
#define ZCL_UTIL_STAGE_FORWARD_H

#include "sync/stage.h"

#endif /* ZCL_UTIL_STAGE_FORWARD_H */
