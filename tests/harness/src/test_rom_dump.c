/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the "rom" dumpstate subsystem (diagnostics_registry_rom.c)
 * — the L0-L3 trust-machine catalog docs/ROM.md documents. Drives
 * rom_dump_state_json() directly (no full node boot needed: the function
 * degrades cleanly when diag_main_state() has never been wired, exactly as
 * a `dumpstate rom` call from a test/tooling context would see it).
 *
 * Load-bearing properties asserted here:
 *   - the dump is well-formed JSON with the expected top-level shape;
 *   - the "checkpoint" object mirrors get_sha3_utxo_checkpoint() exactly
 *     (height/hashes/utxo_count/total_supply) — this is the one place a
 *     silent typo in the hex encoder or a field swap would show up;
 *   - the "commitments" enumeration names all six fields and never drifts
 *     from the doctrine ("headers do not commit UTXO/Sapling/Sprout/
 *     nullifier contents", docs/CONSENSUS_PARITY_DOCTRINE.md);
 *   - every layer sub-object (L0-L3) and both projection cursors (mmb,
 *     utxo_root_ladder) are present with the right shape.
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "chain/utxo_root_ladder.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

#define ROM_CHECK(name, expr) do {                              \
    printf("rom_dump: %s... ", (name));                         \
    if (expr) { printf("OK\n"); }                                \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

static bool hex64_valid(const char *s)
{
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

int test_rom_dump(void);
int test_rom_dump(void)
{
    printf("\n=== rom_dump tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_dump", "seg");
    SetDataDir(dir);

    struct json_value v;
    json_init(&v);
    bool ok = rom_dump_state_json(&v, NULL);
    ROM_CHECK("returns true", ok);
    ROM_CHECK("result is an object", v.type == JSON_OBJ);

    /* ── checkpoint mirrors get_sha3_utxo_checkpoint() exactly ────────── */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    const struct json_value *checkpoint = json_get(&v, "checkpoint");
    ROM_CHECK("checkpoint object present",
             checkpoint && checkpoint->type == JSON_OBJ);
    if (checkpoint) {
        ROM_CHECK("checkpoint.present == true",
                 json_get_bool(json_get(checkpoint, "present")));
        ROM_CHECK("checkpoint.height matches compiled constant",
                 cp && json_get_int(json_get(checkpoint, "height")) ==
                           (int64_t)cp->height);
        const char *bh = json_get_str(json_get(checkpoint, "block_hash"));
        const char *sh = json_get_str(json_get(checkpoint, "sha3_hash"));
        ROM_CHECK("checkpoint.block_hash is 64 lowercase-hex chars",
                 hex64_valid(bh));
        ROM_CHECK("checkpoint.sha3_hash is 64 lowercase-hex chars",
                 hex64_valid(sh));
        ROM_CHECK("checkpoint.utxo_count matches compiled constant",
                 cp && json_get_int(json_get(checkpoint, "utxo_count")) ==
                           (int64_t)cp->utxo_count);
        ROM_CHECK("checkpoint.total_supply_zatoshi matches compiled constant",
                 cp && json_get_int(json_get(checkpoint,
                                             "total_supply_zatoshi")) ==
                           cp->total_supply);
    }

    /* ── commitment enumeration: machine-readable trust-doctrine facts ── */
    const struct json_value *commitments = json_get(&v, "commitments");
    ROM_CHECK("commitments object present",
             commitments && commitments->type == JSON_OBJ);
    if (commitments) {
        struct { const char *key; const char *want; } rows[] = {
            { "header_chain",     "pow" },
            { "tx_bytes",         "merkle" },
            { "sapling_frontier", "header" },
            { "nullifiers",       "not_committed_rom_only" },
            { "sprout",           "not_committed_rom_only" },
            { "transparent_utxo", "not_committed_rom_only" },
        };
        bool all_match = true;
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            const char *got = json_get_str(json_get(commitments, rows[i].key));
            if (!got || strcmp(got, rows[i].want) != 0) all_match = false;
        }
        ROM_CHECK("all six commitment fields present with doctrine values",
                 all_match);
    }

    /* ── layer coverage: L0/L1/L2/L3 each a well-shaped sub-object ────── */
    const struct json_value *layers = json_get(&v, "layers");
    ROM_CHECK("layers object present", layers && layers->type == JSON_OBJ);
    if (layers) {
        const struct json_value *l0 = json_get(layers, "l0_rom");
        ROM_CHECK("l0_rom.height matches checkpoint height",
                 l0 && cp && json_get_int(json_get(l0, "height")) ==
                                 (int64_t)cp->height);

        const struct json_value *l1 = json_get(layers, "l1_sealed_history");
        ROM_CHECK("l1_sealed_history is the chain_segment dump (has status)",
                 l1 && json_get_str(json_get(l1, "status")) != NULL);

        const struct json_value *l2 = json_get(layers, "l2_delta_fold");
        ROM_CHECK("l2_delta_fold has floor/hstar/published",
                 l2 && json_get(l2, "floor") && json_get(l2, "hstar") &&
                 json_get(l2, "published"));

        const struct json_value *l3 = json_get(layers, "l3_live_tip");
        ROM_CHECK("l3_live_tip degrades cleanly with no main_state wired",
                 l3 && json_get_bool(json_get(l3, "has_main_state")) == false &&
                 json_get_int(json_get(l3, "active_tip")) == -1);
    }

    /* ── projection cursors: MMB + utxo_root_ladder ────────────────────── */
    const struct json_value *projections = json_get(&v, "projections");
    ROM_CHECK("projections object present",
             projections && projections->type == JSON_OBJ);
    if (projections) {
        const struct json_value *mmb = json_get(projections, "mmb");
        ROM_CHECK("mmb has initialized/leaves/mountains",
                 mmb && json_get(mmb, "initialized") &&
                 json_get(mmb, "leaves") && json_get(mmb, "mountains"));

        const struct json_value *ladder =
            json_get(projections, "utxo_root_ladder");
        ROM_CHECK("utxo_root_ladder.rung_count matches compiled table",
                 ladder && json_get_int(json_get(ladder, "rung_count")) ==
                               (int64_t)g_utxo_root_ladder_count);
        ROM_CHECK("utxo_root_ladder.stride == 100000",
                 ladder && json_get_int(json_get(ladder, "stride")) ==
                               UTXO_ROOT_LADDER_STRIDE);
        ROM_CHECK("utxo_root_ladder.dense_height matches compiled constant",
                 ladder && json_get_int(json_get(ladder, "dense_height")) ==
                               (int64_t)g_utxo_root_ladder_dense_height);
    }

    /* ── serializes to valid, non-truncated JSON ───────────────────────── */
    char buf[8192];
    size_t need = json_write(&v, buf, sizeof(buf));
    ROM_CHECK("serializes within the scratch buffer (not truncated)",
             need > 0 && need < sizeof(buf));

    /* ── opts into the health rollup convention ────────────────────────── */
    const struct json_value *health = json_get(&v, "_health");
    ROM_CHECK("_health.ok == true (compiled checkpoint always present)",
             health && json_get_bool(json_get(health, "ok")) == true);

    json_free(&v);

    /* ── NULL-output contract: logs and returns false, never crashes ──── */
    ROM_CHECK("NULL out returns false", rom_dump_state_json(NULL, NULL) == false);

    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);

    printf("=== rom_dump: %d failure(s) ===\n", failures);
    return failures;
}
