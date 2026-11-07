/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

static bool csi_v2_validate(sqlite3 *db, struct consensus_state_bundle_manifest *m)
{
    struct consensus_state_install_result result;
    memset(&result, 0, sizeof(result));
    return consensus_state_bundle_validate(db, m, &result);
}

static bool csi_v2_set_digest(sqlite3 *db,
                              struct consensus_state_bundle_manifest *m)
{
    uint8_t digest[32];
    consensus_state_bundle_artifact_digest(m, digest);
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, "UPDATE bundle_meta SET artifact_digest=?", -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_blob(st, 1, digest, sizeof(digest), SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    if (st && sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static int csi_v2_shape_cases(sqlite3 *db)
{
    int failures = 0;
    struct consensus_state_bundle_manifest m;
    CSI_CHECK("v2: unsupported schema refuses", exec_ok(db, "UPDATE bundle_meta SET schema='zcl.consensus_state_bundle.v3'") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: missing both totals refuses", exec_ok(db, "UPDATE bundle_meta SET schema='zcl.consensus_state_bundle.v2'") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: missing sapling refuses", exec_ok(db, "ALTER TABLE bundle_meta ADD COLUMN sprout_pool_total INTEGER NOT NULL DEFAULT 7") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: second total added", exec_ok(db, "ALTER TABLE bundle_meta ADD COLUMN sapling_pool_total INTEGER NOT NULL DEFAULT 9"));
    return failures;
}

static int csi_v2_bad_total_cases(sqlite3 *db)
{
    int failures = 0;
    struct consensus_state_bundle_manifest m;
    CSI_CHECK("v2: text total refuses", exec_ok(db, "UPDATE bundle_meta SET sprout_pool_total='bad'") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: floating total refuses", exec_ok(db, "UPDATE bundle_meta SET sprout_pool_total=7,sapling_pool_total=1.5") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: negative total refuses", exec_ok(db, "UPDATE bundle_meta SET sapling_pool_total=-1") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: missing sprout refuses", exec_ok(db, "ALTER TABLE bundle_meta DROP COLUMN sprout_pool_total") && !csi_v2_validate(db, &m));
    return failures;
}

static int csi_v2_rom_binding_cases(
    sqlite3 *db, const struct csi_fixture *f,
    const struct consensus_state_bundle_manifest *original)
{
    int failures = 0;
    struct rom_state_checkpoint rom;
    rom_keystone_from_fixture(f, &rom);
    rom.format_version = ROM_STATE_CHECKPOINT_V2;
    rom.sprout_pool_total = 7;
    rom.sapling_pool_total = 9;
    checkpoints_set_rom_state_override_for_test(&rom);
    struct consensus_state_bundle_manifest m = *original;
    struct consensus_state_bundle_manifest parsed;
    CSI_CHECK("v2: matching ROM validates", csi_v2_validate(db, &parsed));
    m.sprout_pool_total = 8;
    CSI_CHECK("v2: changed Sprout with recomputed digest refuses ROM",
              exec_ok(db, "UPDATE bundle_meta SET sprout_pool_total=8") &&
              csi_v2_set_digest(db, &m) && !csi_v2_validate(db, &parsed));
    m = *original;
    m.sapling_pool_total = 10;
    CSI_CHECK("v2: changed Sapling with recomputed digest refuses ROM",
              exec_ok(db, "UPDATE bundle_meta SET sprout_pool_total=7,sapling_pool_total=10") &&
              csi_v2_set_digest(db, &m) && !csi_v2_validate(db, &parsed));
    m = *original;
    CSI_CHECK("v2: matching manifest restored",
              exec_ok(db, "UPDATE bundle_meta SET sapling_pool_total=9") &&
              csi_v2_set_digest(db, &m));
    rom.format_version = ROM_STATE_CHECKPOINT_V1;
    CSI_CHECK("v2: V1 ROM cannot authenticate V2", !csi_v2_validate(db, &parsed));
    checkpoints_reset_rom_state_override_for_test();
    return failures;
}

static int csi_v2_validation_tests(void)
{
    int failures = 0;
    char root[300];
    test_make_tmpdir(root, sizeof(root), "consensus_bundle_v2", "validation");
    struct csi_fixture f;
    memset(&f, 0, sizeof(f));
    sqlite3 *db = NULL;
    struct consensus_state_bundle_manifest m;
    bool ready = fixture_init(&f, root, "v2", 0x21, 44, true) &&
                 write_bundle(&f, CSI_VALID) && chmod(f.path, 0600) == 0 &&
                 sqlite3_open(f.path, &db) == SQLITE_OK;
    CSI_CHECK("v2: V1 fixture opens", ready);
    if (!ready) goto done;
    bool v1 = csi_v2_validate(db, &m);
    CSI_CHECK("v2: V1 remains explicit unknown", v1 && m.format_version == CONSENSUS_STATE_BUNDLE_V1);
    if (!v1) goto done;
    struct consensus_state_bundle_manifest v1_manifest = m;
    failures += csi_v2_shape_cases(db);
    m = v1_manifest;
    m.format_version = CONSENSUS_STATE_BUNDLE_V2;
    m.sprout_pool_total = 7;
    m.sapling_pool_total = 9;
    CSI_CHECK("v2: digest updated", csi_v2_set_digest(db, &m));
    CSI_CHECK("v2: nonzero totals accepted exactly", csi_v2_validate(db, &m) && m.format_version == CONSENSUS_STATE_BUNDLE_V2 && m.sprout_pool_total == 7 && m.sapling_pool_total == 9);
    failures += csi_v2_rom_binding_cases(db, &f, &m);
    CSI_CHECK("v2: empty metadata refuses", exec_ok(db, "SAVEPOINT v2_empty; DELETE FROM bundle_meta") && !csi_v2_validate(db, &m));
    CSI_CHECK("v2: metadata restored", exec_ok(db, "ROLLBACK TO v2_empty; RELEASE v2_empty"));
    failures += csi_v2_bad_total_cases(db);
done:
    if (db) sqlite3_close(db);
    fixture_free(&f);
    test_rm_rf_recursive(root);
    return failures;
}
