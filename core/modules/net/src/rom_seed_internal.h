/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: rom_seed's private cross-TU contract — the handful of names the
 * four rom_seed translation units share and nothing outside them may see.
 *
 * rom_seed.c owns the artifact registry, registration, the datadir scan and
 * the background scan lifecycle. rom_seed_classify.c owns the pure half: what
 * a filename is allowed to look like, what kind of artifact a name denotes,
 * and whether a file's leading bytes match that kind. rom_seed_throttle.c
 * owns a complete state group of its own — the enable flag, the cap knobs,
 * the per-peer accounting table, its mutex and the serve counters — none of
 * which is visible outside that file. rom_seed_report.c owns the outward
 * description of an artifact (market offer, directory JSON, state dump) and
 * holds no state at all. Each split happened when the combined file passed
 * the 800-line shape ceiling.
 *
 * The public entry points are in net/rom_seed.h; only the names below cross
 * the private seam, so they live here and nowhere else — nothing outside
 * those four translation units may include this header.
 */

#ifndef ZCL_NET_ROM_SEED_INTERNAL_H
#define ZCL_NET_ROM_SEED_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

/* ── rom_seed_classify.c: pure name rules ───────────────────────────── */

/* True for a name rom_seed is willing to register: a bare basename, or a
 * one-level "bundles/<basename>" relative path. Refuses traversal, a leading
 * or second '/', a different subdirectory, and anything at or over
 * ROM_SEED_NAME_MAX. */
bool rom_filename_ok(const char *filename);

/* Bare basename of a registerable name: "bundles/foo.sqlite" -> "foo.sqlite",
 * "foo.sqlite" -> "foo.sqlite". Pure — mirrors the basename rule the
 * classifier uses, so deregister matches an entry and the bundle-height
 * parser reads a height regardless of which shape the name was registered
 * under. Never returns NULL for a non-NULL argument. */
const char *rom_basename(const char *name);

/* The artifacts whose name is EXACT rather than a pattern. rom_seed.c looks
 * these up by name before walking the datadir, because readdir order is
 * arbitrary and a big datadir root can otherwise hide one. */
extern const char *const rom_seed_exact_names[];
extern const size_t rom_seed_exact_name_count;

/* True for a basename the by-name pass above already owns; the directory
 * walk uses it to skip those rather than register them twice. */
bool rom_seed_is_exact_name(const char *base);

/* ── rom_seed_throttle.c: the caps state group ──────────────────────── */

/* The caps half of rom_seed_reset(): clears the peer table, the rolling rate
 * windows and the serve counters, then restores the default config. Takes and
 * releases the caps mutex internally; the caller must hold NO rom_seed lock
 * when it calls this — rom_seed_reset() calls it after it has released the
 * registry mutex, which is the only lock order that has ever existed here. */
void rom_seed_throttle_reset(void);

/* Append the caps half of the state dump to `out` (already a JSON object):
 * the enable flag and three cap knobs, then one snapshot of the four serve
 * counters taken under the caps mutex. Same fields, same order the combined
 * file emitted them in. Takes and releases the caps mutex internally; the
 * caller must hold NO rom_seed lock. */
struct json_value;
void rom_seed_throttle_push_json(struct json_value *out);

#endif /* ZCL_NET_ROM_SEED_INTERNAL_H */
