/* Point-in-time copy of a live zclassicd chainstate LevelDB.
 *
 * A plain cp of a LevelDB under active write tears — MANIFEST, SSTs
 * and the .log are copied at different instants, and leveldb_open on
 * the copy "succeeds" with holes: an imported UTXO set can silently lack a
 * coin created below the anchor, whose first spend wedges the reducer
 * with prevout_unresolved. The copy here is provably point-in-time: signature the
 * source dir before and after the copy and retry until nothing
 * changed mid-copy. zclassicd flushes its chainstate at block cadence
 * (~minutes), so a clean window is the common case.
 */

#include "utxo_recovery_internal.h"
#if !defined(_WIN32)
#include "util/log_macros.h"
#include "util/file_tree_ops.h"

#include <dirent.h>
#endif
#include <stdint.h>
#if !defined(_WIN32)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* FNV-1a signature over (name, size, mtime_ns) of every entry in a
 * LevelDB directory. Two equal signatures taken around a copy prove no
 * file changed while the copy ran — i.e. the copy is a point-in-time
 * image. Returns 0 only on opendir failure. */
#if !defined(_WIN32)
static uint64_t chainstate_dir_signature(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return 0;
    uint64_t sig = 14695981039346656037ULL;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char fp[1400];
        int n = snprintf(fp, sizeof(fp), "%s/%s", path, e->d_name);
        if (n <= 0 || (size_t)n >= sizeof(fp))
            continue;
        struct stat st;
        if (stat(fp, &st) != 0)
            continue;
        const char *c = e->d_name;
        while (*c) { sig ^= (uint8_t)*c++; sig *= 1099511628211ULL; }
        uint64_t fields[3] = { (uint64_t)st.st_size,
                               (uint64_t)st.st_mtim.tv_sec,
                               (uint64_t)st.st_mtim.tv_nsec };
        const uint8_t *b = (const uint8_t *)fields;
        for (size_t i = 0; i < sizeof(fields); i++) {
            sig ^= b[i];
            sig *= 1099511628211ULL;
        }
    }
    closedir(d);
    return sig;
}
#endif

struct zcl_result utxo_recovery_copy_chainstate_stable(const char *cs_path,
                                                       const char *import_path)
{
    if (!cs_path || !import_path)
        return ZCL_ERR(-3, "copy_chainstate_stable: NULL path");

#if defined(_WIN32)
    return ZCL_ERR(
        -3,
        "copy_chainstate_stable: Windows recovery copy is disabled until "
        "directory-handle-relative, reparse-safe stable copying qualifies");
#else
    const int max_copy_attempts = 6;
    for (int attempt = 1; attempt <= max_copy_attempts; attempt++) {
        uint64_t sig_before = chainstate_dir_signature(cs_path);
        /* `rm -rf import_path && cp -a cs_path import_path`, via the single
         * fd-based tree walker (no shell). ZCL_COPY_PRESERVE_TIMES is
         * LOAD-BEARING: correctness is proven structurally, not by the copy's
         * return code — (1) the source did not change during the copy
         * (point-in-time, which no copy return can attest), and (2) the
         * destination is a COMPLETE image of it. chainstate_dir_signature
         * folds (name,size,mtime_ns) over every entry, so dest_sig == source
         * sig only when the copy preserved mtime_ns exactly (what PRESERVE_TIMES
         * guarantees, matching the old `cp -a`); a torn/failed copy (vanished
         * SST, disk-full) does not match. The copy's own error return is still
         * logged as a hint, but the signature comparison below is the gate. */
        (void)zcl_tree_remove(import_path);
        struct zcl_result cp = zcl_tree_copy(cs_path, import_path,
                                             ZCL_COPY_PRESERVE_TIMES,
                                             NULL, NULL);
        if (!cp.ok)
            LOG_WARN("utxo_recovery",
                     "chainstate copy attempt %d/%d reported: %s",
                     attempt, max_copy_attempts, cp.message);
        uint64_t sig_after = chainstate_dir_signature(cs_path);
        uint64_t dest_sig  = chainstate_dir_signature(import_path);
        if (sig_before != 0 && sig_before == sig_after && dest_sig == sig_after)
            return ZCL_OK;   /* point-in-time source + complete destination */

        const char *why =
            (sig_before != sig_after) ? "source changed during copy"
            : (dest_sig != sig_after) ? "destination incomplete (cp raced/failed)"
                                      : "source unreadable";
        printf("chainstate copy not yet point-in-time (attempt %d/%d: %s) — "
               "retrying...\n", attempt, max_copy_attempts, why);
        fflush(stdout);
        if (attempt < max_copy_attempts)
            sleep(2);
    }
    return ZCL_ERR(-3,
        "copy_chainstate_stable: could not capture a complete point-in-time "
        "copy of %s across %d attempts — refusing a torn import (retry when "
        "the source is idle)", cs_path, max_copy_attempts);
#endif
}
