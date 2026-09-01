/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Forwarding header. The LOG_* / GUARD* macros moved to platform/modules/base (the
 * in-tree dependency sink: it references nothing but libc). ~63% of the
 * tree includes this path, so it stays put — new code should include
 * "base/log_macros.h" directly. */

#ifndef ZCL_LOG_MACROS_FORWARD_H
#define ZCL_LOG_MACROS_FORWARD_H

#include "base/log_macros.h"

#endif /* ZCL_LOG_MACROS_FORWARD_H */
