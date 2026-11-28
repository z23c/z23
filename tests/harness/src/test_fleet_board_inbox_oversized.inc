/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

static int test_fbi_cli_oversized_wire(void)
{
    int failures = 0;
    TEST("board inbox CLI: serialized oversized first row refuses without a partial page") {
        struct fbi_fixture f;
        struct fleet_board_post parent, post;
        struct json_value input, result, node;
        char text[FLEET_BOARD_TEXT_MAX + 1], wire[8192];
        ASSERT(fbi_open(&f, "oversized-wire"));
        memset(text, '"', sizeof(text) - 1);
        text[sizeof(text) - 1] = '\0';
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "question", NULL, NULL, f.now, f.now, &parent));
        ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-b", text, parent.id, NULL, f.now, f.now, &post));
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "op", "inbox") &&
               json_push_kv_str(&input, "agent", "lane-a") &&
               json_push_kv_int(&input, "text_max", FLEET_BOARD_TEXT_MAX));
        ASSERT(fbi_rpc(&f, &input, &node));
        ASSERT_EQ(json_size(json_get(&node, "rows")), 1u);
        ASSERT(json_write(json_at(json_get(&node, "rows"), 0), NULL, 0) > 4096);
        json_free(&node);
        json_free(&input);
        g_fbi_table = &f.table;
        node_rpc_client_set_test_hook(fbi_hook);
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(reg, "fleet.board.inbox", NULL);
        struct zcl_command_context ctx = {.registry = reg,
            .granted_capabilities = ~(uint64_t)0, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
        ASSERT(spec);
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "agent", "lane-a") &&
               json_push_kv_str(&input, "text_max", "2048"));
        enum zcl_command_exit rc;
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
            false, "fleet.board.inbox", "normal", 4096, 0, NULL,
            wire, sizeof(wire), &rc);
        fprintf(stderr, "oversized inbox wire=%zu rc=%d: %s\n", n, (int)rc, wire);
        ASSERT(n > 0 && n <= 4096 && rc == ZCL_COMMAND_EXIT_FAILED);
        json_init(&result);
        ASSERT(json_read(&result, wire, n));
        const struct json_value *error = json_get(&result, "error");
        ASSERT_STR_EQ(json_get_str(json_get(error, "code")), "BOARD_PAGE_BUDGET");
        ASSERT_STR_EQ(json_get_str(json_get(error, "message")),
                      "the inbox page could not fit or be allocated; lower text_max");
        ASSERT(!json_get(&result, "data"));
        fprintf(stderr, "oversized inbox refusal: %s\n", json_get_str(json_get(error, "message")));
        json_free(&result);
        json_free(&input);
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "agent", "lane-a"));
        n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
            false, "fleet.board.inbox", "normal", 4096, 0, NULL,
            wire, sizeof(wire), &rc);
        ASSERT(n > 0 && n <= 4096 && rc == ZCL_COMMAND_EXIT_OK);
        json_init(&result);
        ASSERT(json_read(&result, wire, n));
        const struct json_value *data = json_get(&result, "data");
        ASSERT_EQ(json_get_int(json_get(data, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(data, 0), &post));
        json_free(&result);
        json_free(&input);
        node_rpc_client_set_test_hook(NULL);
        g_fbi_table = NULL;
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}
