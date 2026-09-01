/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: write at an exact absolute offset on an already-open CRT
 * descriptor without disturbing the caller's file pointer, so two writers
 * sharing a descriptor cannot move each other's cursor. */
#ifndef ZCL_PLATFORM_POSITIONED_IO_H
#define ZCL_PLATFORM_POSITIONED_IO_H

#include <stddef.h>
#include <stdint.h>

/* Exact-cursor-independent write against an already-open CRT descriptor.
 * Returns bytes written, or -1 without changing the descriptor cursor. */
int64_t platform_positioned_write(int fd, const void *data, size_t size,
                                  uint64_t offset);
int64_t platform_positioned_read(int fd, void *data, size_t size,
                                 uint64_t offset);

#endif
