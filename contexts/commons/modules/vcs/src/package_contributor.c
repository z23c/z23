/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_contributor — implementation of the contributor profile
 * projection declared in vcs/package_contributor.h. Pure read over the
 * package index; no allocation, no I/O, no mutation. */

#include "vcs/package_contributor.h"

#include <stdio.h>
#include <string.h>

bool vcs_zcode_contributor_from_index(
    const struct vcs_package_index *index, const char *publisher_hex,
    struct vcs_zcode_contributor *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!index || !publisher_hex)
        return false;
    snprintf(out->publisher_hex, sizeof(out->publisher_hex), "%s",
             publisher_hex);

    const struct vcs_package_index_entry *latest = NULL;
    uint32_t count = 0;
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *e =
            vcs_package_index_at(index, i);
        if (!e || strcmp(e->publisher_hex, publisher_hex) != 0)
            continue;
        count++;
        if (!latest || e->publisher_sequence > latest->publisher_sequence)
            latest = e;
    }
    out->release_count = count;
    if (!latest)
        return false;
    out->latest_sequence = latest->publisher_sequence;
    snprintf(out->latest_name, sizeof(out->latest_name), "%s", latest->name);
    snprintf(out->latest_semver, sizeof(out->latest_semver), "%s",
             latest->semver);
    snprintf(out->latest_release_id_hex,
             sizeof(out->latest_release_id_hex), "%s",
             latest->release_id_hex);
    snprintf(out->latest_license, sizeof(out->latest_license), "%s",
             latest->license);
    snprintf(out->reward_address, sizeof(out->reward_address), "%s",
             latest->reward_address);
    out->has_znam_pointer = latest->has_znam;
    if (latest->has_znam)
        snprintf(out->znam_pointer, sizeof(out->znam_pointer), "%s",
                 latest->znam);
    return true;
}
