/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * disk_block_datadir_guard -- implementation. See
 * storage/disk_block_datadir_guard.h for why this refusal exists and why it
 * is a net rather than a cure. */

#include "storage/disk_block_datadir_guard.h"

#include "platform/time_compat.h"
#include "support/log_throttle.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Throttled like the neighbouring block-read refusals: a broken caller inside
 * a fold loop would otherwise emit one line per block. */
static struct log_throttle g_bad_datadir_throttle = LOG_THROTTLE_INIT;

bool disk_block_datadir_is_plausible(const char *datadir)
{
    if (!datadir || datadir[0] == '\0')
        return false;
    for (size_t i = 0; i < 512u; i++) {
        unsigned char c = (unsigned char)datadir[i];
        if (c == '\0')
            return true;
        if (c < 0x20u || c >= 0x7fu)
            return false;
    }
    return false;  /* no terminator inside a path-sized window */
}

/* Render the first bytes of a rejected datadir as hex so the refusal names
 * WHAT was handed over (a stack address, a heap pointer, a lone byte) rather
 * than emitting unprintable bytes into the log. Stops at the first NUL. */
static void datadir_hex_preview(const char *datadir, char *out, size_t outlen)
{
    size_t w = 0;
    for (size_t i = 0; i < 8u && datadir[i] != '\0'; i++) {
        if (w + 3u >= outlen)
            break;
        w += (size_t)snprintf(out + w, outlen - w, "%02x",
                              (unsigned)(unsigned char)datadir[i]);
    }
    if (w == 0 && outlen > 0)
        snprintf(out, outlen, "<empty>");
}

bool disk_block_datadir_ok_or_refuse(const char *datadir, int file, unsigned pos)
{
    if (disk_block_datadir_is_plausible(datadir))
        return true;
    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_bad_datadir_throttle, 0u,
                                 platform_time_wall_unix(), 60, &reps)) {
        char preview[24];
        datadir_hex_preview(datadir, preview, sizeof(preview));
        fprintf(stderr,  // obs-ok:throttled-caller-memory-safety-refusal
                "[disk_block_io] read_block_pread: refusing implausible "
                "datadir ptr=%p bytes=%s file=%d pos=%u — the caller handed a "
                "dead or non-string pointer (%llu suppressed repeats since "
                "last log)\n",
                (const void *)datadir, preview, file, pos,
                (unsigned long long)reps);
    }
    return false;
}
