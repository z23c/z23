/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API access control: rejected HTTP methods, the operator-private route
 * classifier, and the wallet route gate.
 */

#include "test/api_test_fixtures.h"

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

/* A rejected HTTP method must still be answered by the router, with 405. */
static bool method_rejected_as_405(const char *method)
{
    uint8_t resp[8192];
    size_t n = api_handle_request(method, "/api/blocks", NULL, 0,
                                  resp, sizeof(resp));
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
    return (n > 0 && strstr((char *)resp, "405") != NULL);
}

/* True only at a path boundary (next char '\0', '/', '?'). */
static bool route_classifier_flags_private_paths(void)
{
    return api_route_is_operator_private("/api/wallet") &&
           api_route_is_operator_private("/api/v1/wallet") &&
           api_route_is_operator_private("/api/wallet/") &&
           api_route_is_operator_private("/api/v1/wallet/") &&
           api_route_is_operator_private("/api/wallet?x=1") &&
           api_route_is_operator_private("/api/v1/wallet?x=1") &&
           api_route_is_operator_private("/api/wallet/keys") &&
           api_route_is_operator_private("/api/messages") &&
           api_route_is_operator_private("/api/messages/thread/1") &&
           api_route_is_operator_private("/api/v1/messages") &&
           api_route_is_operator_private("/api/v1/swaps") &&
           api_route_is_operator_private("/api/swaps") &&
           api_route_is_operator_private("/api/swaps/contracts");
}

/* Public routes must stay public — swap chain discovery must not be
 * captured by the private /api/swaps resource prefix. */
static bool route_classifier_clears_public_paths(void)
{
    return !api_route_is_operator_private("/api/swap_chains") &&
           !api_route_is_operator_private("/api/v1/swap_chains") &&
           !api_route_is_operator_private("/api/swaps/chains") &&
           !api_route_is_operator_private("/api/v1/swaps/chains") &&
           !api_route_is_operator_private("/api/swaps/chains?x=1") &&
           !api_route_is_operator_private("/api/swaps/chains/zcl") &&
           !api_route_is_operator_private("/api/blocks") &&
           !api_route_is_operator_private("/api/v1/blocks") &&
           !api_route_is_operator_private("/api/stats") &&
           !api_route_is_operator_private("/api/walletfoo") &&
           !api_route_is_operator_private(NULL);
}

static bool route_classifier_flags_expected_private_paths(void)
{
    bool ok = route_classifier_flags_private_paths();
    ok = ok && route_classifier_clears_public_paths();
    return ok;
}

/* /api/wallet must report the projection freshness of the durable tip. */
static bool wallet_route_reports_fresh_projection(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    uint8_t resp[8192];
    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_access", "wallet");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

    bool ok = node_db_open(&ndb, dbpath);
    ok = ok && api_test_save_model_block(&ndb, 4, 0x94);
    ok = ok && api_test_seed_durable_tip(dbdir, 4);
    reducer_frontier_provable_tip_reset();
    api_set_state(NULL, NULL, NULL, &ndb, dbdir);

    size_t n = api_handle_request("GET", "/api/wallet", NULL, 0,
                                  resp, sizeof(resp));
    const char *body = api_test_body(resp, n, sizeof(resp));
    struct json_value root;
    json_init(&root);
    ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
    ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.wallet_status.v1") == 0;
    ok = ok && api_test_expect_freshness(&root, "wallet_projection",
                                         4, 4, true);
    ok = ok && json_get_int(json_get(&root, "height")) == 4;
    ok = ok && json_size(json_get(&root, "activity")) == 0;
    json_free(&root);

    api_set_state(NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    node_db_close(&ndb);

    ok &= fixture_rm_ok(dbdir);

    return ok;
}

static bool router_serves_wallet_route(void)
{
    uint8_t resp[8192];
    size_t n = api_handle_request("GET", "/api/wallet", NULL, 0,
                                  resp, sizeof(resp));
    return n > 0;
}

/* Build "<root>/status" and create it; a NULL root means do nothing. */
static bool status_dir_created(const char *root, char *status_dir,
                               size_t status_dir_len)
{
    return root != NULL &&
        snprintf(status_dir, status_dir_len, "%s/status", root) <
            (int)status_dir_len && mkdir(status_dir, 0700) == 0;
}

/* Write one passed-lane status file per lane, tagged with an external
 * commit. */
static bool write_lane_status_files(const char *status_dir,
                                    char paths[3][640])
{
    const char *lanes[3] = {"fuzz", "coverage", "tests"};
    bool ok = true;
    for (size_t i = 0; ok && i < 3; i++) {
        ok = snprintf(paths[i], sizeof(paths[i]), "%s/%s.json",
                      status_dir, lanes[i]) < (int)sizeof(paths[i]);
        FILE *f = ok ? fopen(paths[i], "wb") : NULL;
        ok = f != NULL;
        if (f) {
            fprintf(f,
                    "{\"schema\":\"zcl.background_quality_lane.v1\","
                    "\"lane\":\"%s\",\"status\":\"passed\","
                    "\"commit\":\"external\"}\n", lanes[i]);
            ok = fclose(f) == 0;
        }
    }
    return ok;
}

/* The scan must report three valid files, all from unknown sources. */
static bool quality_json_reports_unknown_source(struct json_value *quality)
{
    bool ok = strcmp(json_get_str(json_get(quality, "summary")),
                     "background_quality_identity_unknown") == 0;
    ok = ok && json_get_int(json_get(quality,
                                     "status_files_valid")) == 3;
    ok = ok && json_get_int(json_get(quality,
                                     "unknown_source_id_count")) == 3;
    ok = ok && json_get_int(json_get(quality,
                                     "current_source_id_count")) == 0;
    return ok;
}

/* Best-effort cleanup of the temporary lane files and directories. */
static void delete_lane_status_files(char paths[3][640],
                                     const char *status_dir,
                                     const char *root)
{
    for (size_t i = 0; i < 3; i++)
        if (paths[i][0])
            unlink(paths[i]);
    rmdir(status_dir);
    rmdir(root);
}

/* Lane status files tagged with an unknown commit must be counted as
 * unknown sources. */
static bool background_quality_reports_unknown_source(void)
{
    char tmp[] = "/tmp/zcl_quality_unknown_XXXXXX";
    char status_dir[512] = {0};
    char paths[3][640] = {{0}};
    const char *old = getenv("ZCL_QUALITY_STATE_DIR");
    char old_copy[4096] = {0};
    bool old_set = old != NULL;
    bool ok = !old_set ||
        snprintf(old_copy, sizeof(old_copy), "%s", old) <
            (int)sizeof(old_copy);
    char *root = ok ? mkdtemp(tmp) : NULL;
    ok = ok && status_dir_created(root, status_dir,
                                  sizeof(status_dir)) &&
        write_lane_status_files(status_dir, paths);
    ok = ok && setenv("ZCL_QUALITY_STATE_DIR", root, 1) == 0;
    struct json_value quality;
    json_init(&quality);
    if (ok)
        agent_build_background_quality_status(&quality);
    ok = ok && quality_json_reports_unknown_source(&quality);
    json_free(&quality);
    if (old_set)
        setenv("ZCL_QUALITY_STATE_DIR", old_copy, 1);
    else
        unsetenv("ZCL_QUALITY_STATE_DIR");
    if (root)
        delete_lane_status_files(paths, status_dir, root);
    return ok;
}

int api_access_focused_tests(void)
{
    int failures = 0;

    printf("api: DELETE method returns 405... ");
    if (method_rejected_as_405("DELETE")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: PUT method returns 405... ");
    if (method_rejected_as_405("PUT")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: operator-private classifier boundary-matches... ");
    if (route_classifier_flags_expected_private_paths()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: wallet route exposes projection freshness... ");
    if (wallet_route_reports_fresh_projection()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* The router itself still serves /api/wallet — enforcement is
     * LISTENER-side (https_server 403s operator-private paths before
     * dispatch; in-process callers like wallet_gui stay trusted). See
     * the SECURITY INVARIANT note at api_handle_request. */
    printf("api: router still serves /api/wallet (gate is listener-side)... ");
    if (router_serves_wallet_route()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: background quality rejects unknown source identities... ");
    if (background_quality_reports_unknown_source()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
