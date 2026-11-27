/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* The boot scanner must resynchronize to the selected network only. */
static int test_scan_network_magic(const unsigned char selected[4], const char *label)
{
    char dir[256];
    make_test_dir(dir, sizeof(dir));
    struct main_state ms;
    main_state_init(&ms);
    struct chain_params params = *chain_params_get();
    memcpy(params.pchMessageStart, selected, 4);
    struct block_index *entries[4] = {0};
    bool ok = true;
    for (int i = 0; ok && i < 4; i++) {
        struct block b;
        build_test_block(&b, 910000u + (uint32_t)i);
        struct uint256 hash;
        block_get_hash(&b, &hash);
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        const unsigned char *frame = (i % 2) ? selected : TEST_MSG_START;
        ok = write_block_to_disk(&b, &pos, dir, frame);
        block_free(&b);
        entries[i] = chainstate_insert_block_index((struct chainstate *)&ms, &hash);
        ok = ok && entries[i];
    }
    if (ok) ok = scan_block_files_mark_data(&ms, dir, &params) > 0;
    for (int i = 0; ok && i < 4; i++)
        ok = !!(entries[i]->nStatus & BLOCK_HAVE_DATA) == !!(i % 2);
    if (!ok) printf("FAIL: scanner selected network frames (%s)\n", label);
    main_state_free(&ms);
    cleanup_test_dir(dir);
    return ok ? 0 : 1;
}
