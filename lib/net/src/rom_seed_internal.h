/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: rom_seed's private cross-TU contract — the three names
 * rom_seed_classify.c defines and rom_seed.c consumes.
 *
 * rom_seed.c owns everything with state: the artifact registry,
 * registration, the datadir scan, the serve caps and per-peer rate limits,
 * and the announce/introspection surface. rom_seed_classify.c owns the pure
 * half: what a filename is allowed to look like, what kind of artifact a
 * name denotes, and whether a file's leading bytes match that kind. The
 * split happened when the combined file passed the 800-line shape ceiling.
 * The public entry points are in net/rom_seed.h; only these three cross the
 * private seam, so they live here and nowhere else — nothing outside those
 * two translation units may include this header.
 */

#ifndef ZCL_NET_ROM_SEED_INTERNAL_H
#define ZCL_NET_ROM_SEED_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

/* True for a name rom_seed is willing to register: a bare basename, or a
 * one-level "bundles/<basename>" relative path. Refuses traversal, a leading
 * or second '/', a different subdirectory, and anything at or over
 * ROM_SEED_NAME_MAX. */
bool rom_filename_ok(const char *filename);

/* The artifacts whose name is EXACT rather than a pattern. rom_seed.c looks
 * these up by name before walking the datadir, because readdir order is
 * arbitrary and a big datadir root can otherwise hide one. */
extern const char *const rom_seed_exact_names[];
extern const size_t rom_seed_exact_name_count;

/* True for a basename the by-name pass above already owns; the directory
 * walk uses it to skip those rather than register them twice. */
bool rom_seed_is_exact_name(const char *base);

#endif /* ZCL_NET_ROM_SEED_INTERNAL_H */
