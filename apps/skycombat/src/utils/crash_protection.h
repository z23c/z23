/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: signal-handler crash reporting.
 */

#ifndef CRASH_PROTECTION_H
#define CRASH_PROTECTION_H

#include <stddef.h>

// Initialize crash protection system
void init_crash_protection(void);

// Execute a function with crash protection
int safe_execute(int (*func)(void));

// Safe memory operations
void* safe_malloc(size_t size);
void safe_free(void* ptr);

// Safe array access
void* safe_array_get(void* array, size_t elem_size, size_t index, size_t max_index);

#endif // CRASH_PROTECTION_H