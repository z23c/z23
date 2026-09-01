/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_verify_rom.c — the -verify-rom verb: a TERMINAL read-only verifier that
 * re-derives the canonical coins_kv commitment + count and compares them to the
 * compiled SHA3 UTXO checkpoint (the ROM baked into the binary). It closes the
 * observability half of W4-3b: the compiled checkpoint is otherwise consumed by
 * the frontier fold only as a numeric HEIGHT floor
 * (engine/reducer/jobs/src/reducer_frontier.c), so its sha3_hash is never re-checked
 * against the live coins_kv content. This verb lets an operator re-check on
 * demand.
 *
 * It reuses the ONE shared verifier coins_kv_verify_against_checkpoint (which
 * folds via coins_kv_commitment — the same canonical-order SHA3 the ratify verb
 * and the -refold-from-anchor hard-assert use); there is no second digest here.
 * A PASS is expected only on a datadir positioned AT the checkpoint height
 * (applied == cp->height + 1) — the same precondition as -ratify-mint-anchor. On
 * a tip datadir the live coins set is NOT the checkpoint-height set, so the verb
 * prints a NOTE and reports FAIL (the mismatch is expected there, not
 * necessarily corruption). Reads the DURABLE set (refuses if the coins_ram
 * overlay is active); stamps NOTHING. Every path _exit()s. Contract declared in
 * config/boot.h. */

#include "config/boot.h"

#include "chain/checkpoints.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define VERIFY_ROM_SUBSYS "verify_rom"

static void verify_rom_hex32(char out[65], const uint8_t in[32])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", in[i]);
}

void boot_verify_rom(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        fprintf(stderr, "FAIL: -verify-rom: empty datadir\n");
        LOG_WARN(VERIFY_ROM_SUBSYS, "empty datadir");
        _exit(EXIT_FAILURE);
    }
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "FAIL: -verify-rom: no compiled SHA3 UTXO checkpoint to "
                        "verify against\n");
        LOG_WARN(VERIFY_ROM_SUBSYS, "no compiled checkpoint");
        _exit(EXIT_FAILURE);
    }
    sqlite3 *pdb = progress_store_db();
    if (!pdb) {
        fprintf(stderr, "FAIL: -verify-rom: progress store not open\n");
        LOG_WARN(VERIFY_ROM_SUBSYS, "progress store not open");
        _exit(EXIT_FAILURE);
    }

    /* A live RAM overlay would shadow coins_kv_commitment/count with an
     * un-flushed set; verify runs terminally with no fold, so the overlay must
     * be inert (mirrors the ratify verb's refusal). */
    if (coins_ram_active()) {
        fprintf(stderr, "FAIL: -verify-rom: coins RAM overlay is active; verify "
                        "reads the durable set\n");
        LOG_WARN(VERIFY_ROM_SUBSYS, "coins_ram overlay active");
        _exit(EXIT_FAILURE);
    }

    int32_t applied = -1;
    bool applied_found = false;
    (void)coins_kv_get_applied_height(pdb, &applied, &applied_found);

    uint8_t got_root[32] = {0};
    int64_t got_count = -1;
    char reason[256] = {0};
    bool pass = coins_kv_verify_against_checkpoint(pdb, cp, got_root, &got_count,
                                                   reason, sizeof reason);

    char got_hex[65], want_hex[65];
    verify_rom_hex32(got_hex, got_root);
    verify_rom_hex32(want_hex, cp->sha3_hash);

    if (pass) {
        fprintf(stderr,
                "PASS: -verify-rom: coins_kv reproduces the compiled SHA3 UTXO "
                "checkpoint at h=%d\n"
                "  sha3    = %s\n"
                "  count   = %lld (baked %llu)\n"
                "  applied = %s%d\n",
                cp->height, got_hex, (long long)got_count,
                (unsigned long long)cp->utxo_count,
                applied_found ? "" : "absent:", applied);
        LOG_INFO(VERIFY_ROM_SUBSYS, "PASS h=%d count=%lld", cp->height,
                 (long long)got_count);
        _exit(EXIT_SUCCESS);
    }

    bool at_checkpoint = applied_found && applied == cp->height + 1;
    fprintf(stderr,
            "FAIL: -verify-rom: %s\n"
            "  sha3 got  = %s\n"
            "  sha3 want = %s\n"
            "  count got = %lld want = %llu\n"
            "  applied   = %s%d (checkpoint frame = %d)\n",
            reason, got_hex, want_hex, (long long)got_count,
            (unsigned long long)cp->utxo_count,
            applied_found ? "" : "absent:", applied, cp->height + 1);
    if (!at_checkpoint)
        fprintf(stderr,
                "  NOTE: coins_kv is NOT positioned at the checkpoint height "
                "(applied %s%d != cp->height+1 = %d); a PASS is only expected on "
                "a datadir parked AT the checkpoint (a producer / anchor-seed "
                "datadir). This mismatch is expected on a tip node, not "
                "necessarily corruption.\n",
                applied_found ? "" : "absent:", applied, cp->height + 1);
    LOG_WARN(VERIFY_ROM_SUBSYS, "FAIL: %s", reason);
    _exit(EXIT_FAILURE);
}
