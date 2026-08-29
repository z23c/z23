/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact NAME and CONTENT classification — the pure half of rom_seed.
 *
 * Split out of rom_seed.c along the file-size ceiling seam. Nothing here
 * touches the registry, the caps, a mutex, a file descriptor or any
 * process-wide state: every function is a total function of its arguments,
 * which is exactly why it is the half worth reading on its own. rom_seed.c
 * keeps everything that has state — the registry, registration, the datadir
 * scan, the serve caps, the announce/introspection surface.
 *
 * The public entry points stay declared in net/rom_seed.h; the names the
 * other rom_seed translation units reach back for are declared in
 * rom_seed_internal.h.
 */
#include "net/rom_seed.h"

#include "rom_seed_internal.h"

#include <string.h>

/* ── Small helpers ──────────────────────────────────────────────────── */

/* A registerable filename is a bare basename — no separators, no traversal,
 * non-empty, short enough to store — OR a one-level-deep
 * "ROM_SEED_BUNDLES_SUBDIR/<basename>" (i.e. "bundles/<basename>") relative
 * path: the ONE subdirectory rom_seed ever reaches into (see the constant's
 * doc comment). Any other separator shape — a leading '/', a second '/', or a
 * different subdir name — is refused exactly like today's bare-basename rule. */
bool rom_filename_ok(const char *filename)
{
    if (!filename || !filename[0])
        return false;
    size_t n = strlen(filename);
    if (n >= ROM_SEED_NAME_MAX)
        return false;
    if (strstr(filename, ".."))
        return false;

    const char *slash = strchr(filename, '/');
    const char *base = filename;
    if (slash) {
        static const char subdir[] = ROM_SEED_BUNDLES_SUBDIR;
        size_t prefix_len = (size_t)(slash - filename);
        if (prefix_len != strlen(subdir) ||
            strncmp(filename, subdir, prefix_len) != 0)
            return false;
        base = slash + 1;
        if (!base[0] || strchr(base, '/'))
            return false;
    }
    if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        return false;
    return true;
}

/* Bare basename of a registerable name: "bundles/foo.sqlite" -> "foo.sqlite",
 * "foo.sqlite" -> "foo.sqlite". Pure — mirrors the basename rule the classifier
 * below uses, so a caller matches the same entry regardless of which shape the
 * name was registered under. */
const char *rom_basename(const char *name)
{
    const char *slash = strrchr(name, '/');
    return slash ? slash + 1 : name;
}

/* Case-sensitive "does `s` start with `prefix`". */
static bool str_has_prefix(const char *s, const char *prefix)
{
    size_t pl = strlen(prefix);
    return strncmp(s, prefix, pl) == 0;
}

static bool str_has_suffix(const char *s, const char *suffix)
{
    size_t sl = strlen(s), fl = strlen(suffix);
    return sl >= fl && strcmp(s + (sl - fl), suffix) == 0;
}

/* ── Classification + content check ─────────────────────────────────── */

enum rom_artifact_kind rom_seed_classify(const char *filename)
{
    if (!filename || !filename[0])
        return ROM_ARTIFACT_UNKNOWN;
    /* Classify on the basename: a caller may pass a bare name (the datadir-
     * root scan) or a "bundles/<name>" relative path (the bundles/ subdir
     * scan / a freshly fetched bundle) — the artifact kind rules are
     * identical either way. */
    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;
    if (str_has_prefix(base, "consensus-state-bundle-") &&
        str_has_suffix(base, ".sqlite"))
        return ROM_ARTIFACT_CONSENSUS_BUNDLE;
    if (strcmp(base, "block_index.bin") == 0)
        return ROM_ARTIFACT_HEADER_SEED;
    return ROM_ARTIFACT_UNKNOWN;
}

/* Artifacts whose name is EXACT, not a pattern. These are looked up by name
 * instead of being waited for in a directory walk: a datadir root is an
 * ordinary directory that grows without bound, readdir order is arbitrary,
 * and an artifact that happens to sort late must not become invisible. The
 * pattern-named kinds (consensus-state-bundle-*.sqlite) still need the walk.
 * rom_seed_classify stays the one authority on what a name means; this list
 * only says which names are worth trying directly. */
const char *const rom_seed_exact_names[] = {
    "block_index.bin",      /* ROM_ARTIFACT_HEADER_SEED */
};

/* The element count, published alongside the table: rom_seed.c's by-name
 * pass sees only an incomplete `extern` array, so sizeof() there would not
 * compile. Derived from the table itself, never written out by hand, so
 * adding a row above cannot leave the two out of step. */
const size_t rom_seed_exact_name_count =
    sizeof(rom_seed_exact_names) / sizeof(rom_seed_exact_names[0]);

/* True for a basename the exactly-named pass already owns. The directory walk
 * uses this to skip those names rather than register them a second time. */
bool rom_seed_is_exact_name(const char *base)
{
    for (size_t i = 0; i < rom_seed_exact_name_count; i++)
        if (strcmp(base, rom_seed_exact_names[i]) == 0)
            return true;
    return false;
}

enum rom_artifact_kind rom_seed_kind_from_name(const char *name)
{
    if (!name || !name[0])
        return ROM_ARTIFACT_UNKNOWN;
    /* Mirror the tokens kind_name() emits in rom_seed_directory_json. */
    if (strcmp(name, "consensus_bundle") == 0)
        return ROM_ARTIFACT_CONSENSUS_BUNDLE;
    if (strcmp(name, "header_seed") == 0)
        return ROM_ARTIFACT_HEADER_SEED;
    return ROM_ARTIFACT_UNKNOWN;
}

bool rom_seed_kind_content_ok(enum rom_artifact_kind kind,
                              const uint8_t *header, size_t n,
                              uint64_t size_bytes)
{
    if (size_bytes < ROM_SEED_MIN_ARTIFACT_BYTES ||
        size_bytes > ROM_SEED_MAX_ARTIFACT_BYTES)
        return false;
    switch (kind) {
    case ROM_ARTIFACT_CONSENSUS_BUNDLE: {
        /* The bundle is a SQLite database — the file must begin with the
         * canonical 16-byte magic. A truncated/garbage/non-SQLite file fails
         * here and is never offered. */
        static const uint8_t sqlite_magic[16] = "SQLite format 3";
        if (!header || n < 16)
            return false;
        return memcmp(header, sqlite_magic, 16) == 0;
    }
    case ROM_ARTIFACT_HEADER_SEED:
        /* Header seed has no strong magic; the size band is the guard. */
        return true;
    case ROM_ARTIFACT_UNKNOWN:
    default:
        return false;
    }
}
