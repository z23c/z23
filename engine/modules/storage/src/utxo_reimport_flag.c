/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_reimport_flag - implementation. See header for the contract.
 *
 * Owns the durable `<datadir>/needs_reimport` sentinel shared by validation
 * self-heal and boot recovery. Validation decides when to set it; boot checks
 * and clears it exactly once before chain mutators start.
 */

#include "storage/utxo_reimport_flag.h"

#include <stdio.h>
#include <string.h>

bool utxo_reimport_flag_check_and_clear(const char *datadir)
{
    if (!datadir)
        return false;

    char flag_path[512];
    snprintf(flag_path, sizeof(flag_path),
             "%s/needs_reimport", datadir);

    FILE *flag = fopen(flag_path, "r");
    if (!flag)
        return false;

    char buf[8] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, flag);
    (void)n;  /* tolerate short / empty reads — content drives the bool */
    fclose(flag);
    /* Unconditional clear: even if the byte was not '1' we remove the
     * marker so a malformed write cannot loop forever. */
    remove(flag_path);

    if (buf[0] == '1') {
        fprintf(stderr,  // obs-ok:storage-primitive-info
                "[storage] utxo_reimport_flag: set — cleared "
                "and signalling reimport (datadir=%s)\n", datadir);
        return true;
    }
    return false;
}

bool utxo_reimport_flag_set(const char *datadir)
{
    if (!datadir)
        return false;

    char flag_path[512];
    snprintf(flag_path, sizeof(flag_path),
             "%s/needs_reimport", datadir);

    FILE *flag = fopen(flag_path, "w");
    if (!flag) {
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[storage] utxo_reimport_flag_set: fopen(%s) failed\n",
                flag_path);
        return false;
    }
    /* Preserve the exact 2-byte "1\n" payload the previous inline
     * writer produced — keeps the on-disk format identical. */
    size_t want = 2;
    size_t got = fwrite("1\n", 1, want, flag);
    int close_rc = fclose(flag);
    if (got != want || close_rc != 0) {
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[storage] utxo_reimport_flag_set: short write or "
                "fclose failed (path=%s got=%zu want=%zu rc=%d)\n",
                flag_path, got, want, close_rc);
        return false;
    }
    return true;
}
