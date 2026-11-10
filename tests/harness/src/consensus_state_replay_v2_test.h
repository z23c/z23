/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

static bool rr_test_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool rr_test_make_v2(struct csi_fixture *f)
{
    sqlite3 *db = NULL;
    struct consensus_state_bundle_manifest m;
    struct consensus_state_install_result result;
    sqlite3_stmt *st = NULL;
    bool ok = write_bundle(f, CSI_VALID) && chmod(f->path, 0600) == 0 &&
              sqlite3_open(f->path, &db) == SQLITE_OK &&
              consensus_state_bundle_validate(db, &m, &result) &&
              rr_test_sql(db, "ALTER TABLE bundle_meta ADD COLUMN sprout_pool_total INTEGER NOT NULL DEFAULT 7;"
                              "ALTER TABLE bundle_meta ADD COLUMN sapling_pool_total INTEGER NOT NULL DEFAULT 9;"
                              "UPDATE bundle_meta SET schema='zcl.consensus_state_bundle.v2'");
    if (ok) {
        m.format_version = CONSENSUS_STATE_BUNDLE_V2;
        m.sprout_pool_total = 7;
        m.sapling_pool_total = 9;
        uint8_t digest[32];
        consensus_state_bundle_artifact_digest(&m, digest);
        ok = sqlite3_prepare_v2(db, "UPDATE bundle_meta SET artifact_digest=?", -1, &st, NULL) == SQLITE_OK &&
             sqlite3_bind_blob(st, 1, digest, sizeof(digest), SQLITE_TRANSIENT) == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st && sqlite3_finalize(st) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok && chmod(f->path, 0400) == 0;
}

static bool rr_test_clone(sqlite3 *source, sqlite3 **out)
{
    *out = NULL;
    if (sqlite3_open(":memory:", out) != SQLITE_OK) return false;
    sqlite3_backup *backup = sqlite3_backup_init(*out, "main", source, "main");
    if (!backup) return false;
    int rc = sqlite3_backup_step(backup, -1);
    return sqlite3_backup_finish(backup) == SQLITE_OK && rc == SQLITE_DONE &&
           rr_test_sql(*out, "CREATE TABLE IF NOT EXISTS shielded_pool_totals ("
                              "height INTEGER PRIMARY KEY, sprout INTEGER NOT NULL,"
                              "sapling INTEGER NOT NULL)");
}

static bool rr_test_verified_receipt(sqlite3 *clone, struct csi_activate_scene *s,
    struct consensus_state_replay_result *result, const struct consensus_state_bundle_manifest *manifest,
    const uint8_t file_digest[32])
{
    return consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, result) &&
        result->verified && consensus_state_replay_receipt_authority_available(manifest, file_digest, s->active_dir_fd);
}
static int csi_replay_v2_test(struct csi_activate_scene *s)
{
    int failures = 0;
    sqlite3 *clone = NULL;
    struct consensus_state_replay_result vres;
    struct consensus_state_artifact_evidence *ev = NULL;
    struct consensus_state_bundle_manifest manifest;
    uint8_t file_digest[32];
    bool ok = rr_test_make_v2(s->b) && rr_test_clone(s->pdb, &clone);
    CSI_CHECK("replay v2: fixture and independent fold clone", ok);
    if (!ok) goto done;
    struct zcl_result opened = consensus_state_artifact_evidence_open(s->b->path, -1, &ev);
    ok = opened.ok && ev && consensus_state_artifact_evidence_manifest_copy(ev, &manifest) &&
         consensus_state_artifact_evidence_file_digest(ev, file_digest);
    CSI_CHECK("replay v2: validated bundle metadata", ok);
    if (!ok) goto done;
    CSI_CHECK("replay v2: V1 receipt cannot authorize V2", !consensus_state_replay_receipt_authority_available(&manifest, file_digest, s->active_dir_fd));
    char sql[256];
    snprintf(sql, sizeof(sql), "DELETE FROM shielded_pool_totals WHERE height=%d", s->b->height);
    CSI_CHECK("replay v2: missing local totals refuse", rr_test_sql(clone, sql) && !consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, &vres));
    snprintf(sql, sizeof(sql), "INSERT INTO shielded_pool_totals(height,sprout,sapling) VALUES(%d,'bad',9)", s->b->height);
    CSI_CHECK("replay v2: malformed local totals refuse", rr_test_sql(clone, sql) && !consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, &vres));
    snprintf(sql, sizeof(sql), "UPDATE shielded_pool_totals SET sprout=-1 WHERE height=%d", s->b->height);
    CSI_CHECK("replay v2: negative local totals refuse", rr_test_sql(clone, sql) && !consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, &vres));
    snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO shielded_pool_totals(height,sprout,sapling) VALUES(%d,7,8)", s->b->height);
    CSI_CHECK("replay v2: mismatch fixture", rr_test_sql(clone, sql));
    CSI_CHECK("replay v2: mismatched local totals refuse", !consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, &vres) && !vres.verified);
    snprintf(sql, sizeof(sql), "UPDATE shielded_pool_totals SET sapling=9 WHERE height=%d", s->b->height);
    CSI_CHECK("replay v2: matching local totals", rr_test_sql(clone, sql));
    CSI_CHECK("replay v2: independently matched receipt authorizes", rr_test_verified_receipt(clone, s, &vres, &manifest, file_digest));
    struct consensus_state_bundle_manifest tampered = manifest;
    tampered.sapling_pool_total++;
    consensus_state_bundle_artifact_digest(&tampered, tampered.artifact_digest);
    CSI_CHECK("replay v2: recomputed tampered manifest refused", !consensus_state_replay_receipt_authority_available(&tampered, file_digest, s->active_dir_fd));
    CSI_CHECK("replay v2: same-binding V1 fixture written", consensus_state_replay_receipt_test_downgrade(s->active_dir, s->active_dir_fd));
    CSI_CHECK("replay v2: same-binding V1 receipt refuses V2", !consensus_state_replay_receipt_authority_available(&manifest, file_digest, s->active_dir_fd));
    CSI_CHECK("replay v2: existing transaction refused and retained", rr_test_sql(clone, "BEGIN") && !consensus_state_replay_verify_and_write_receipt(clone, s->b->path, s->active_dir, &vres) && !sqlite3_get_autocommit(clone));
    CSI_CHECK("replay v2: caller transaction rolls back", rr_test_sql(clone, "ROLLBACK"));
done:
    if (ev) consensus_state_artifact_evidence_free(ev);
    if (clone) sqlite3_close(clone);
    CSI_CHECK("replay v2: V1 fixture restored", write_bundle(s->b, CSI_VALID));
    CSI_CHECK("replay v2: V1 receipt restored", consensus_state_replay_verify_and_write_receipt(s->pdb, s->b->path, s->active_dir, &vres));
    return failures;
}
