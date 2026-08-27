/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable compiler attributes shared by production C23 code. */

#ifndef ZCLASSIC_BASE_COMPILER_H
#define ZCLASSIC_BASE_COMPILER_H

#if defined(__APPLE__)
#define ZCL_WEAK_IMPORT __attribute__((weak_import))
#else
#define ZCL_WEAK_IMPORT __attribute__((weak))
#endif

#endif
