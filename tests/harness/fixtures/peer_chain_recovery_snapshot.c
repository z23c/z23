/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>
#include "platform/time_compat.h"
static sqlite3 *writer;
static int writes, steps, mode;
static int64_t ticks = 1;
[[maybe_unused]] static int64_t test_time_ms(void) { return ticks; }
static int test_backup_step(sqlite3_backup *backup, int pages)
{
    int rc = sqlite3_backup_step(backup, pages);
    if (rc == SQLITE_OK) {
        steps++;
        if (sqlite3_exec(writer, "UPDATE unrelated SET value=value||'x' WHERE id=1",
                         NULL, NULL, NULL) != SQLITE_OK) return SQLITE_ERROR;
        writes++;
        if ((mode == 2 && steps >= 4) || steps >= 20) return SQLITE_ERROR;
        ticks += mode == 2 ? 31000 : 20000;
    }
    return rc;
}
#define platform_time_monotonic_ms test_time_ms
#define sqlite3_backup_step test_backup_step
#define peer_chain_recovery_main test_recovery_main
#include "../../../tools/peer_chain_recovery.c"
#undef peer_chain_recovery_main
#undef sqlite3_backup_step
#undef platform_time_monotonic_ms
static int test_root_pairs(void)
{
    static const struct {
        int table, index, owners;
        bool valid;
    } cases[] = {
        {2, 3, 2, true}, {3, 2, 2, true}, {2, 2, 2, false},
        {1, 3, 2, false}, {3, 1, 2, false}, {2, 3, 3, false},
        {2, 3, 1, false},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (recovery_root_pair_ok(cases[i].table, cases[i].index,
                                  cases[i].owners) != cases[i].valid) {
            fprintf(stderr, "unexpected recovery verdict for roots %d,%d with %d owners\n",
                    cases[i].table, cases[i].index, cases[i].owners);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "roots") == 0) return test_root_pairs();
    if (argc != 4) return 2;
    mode = strcmp(argv[1], "stall") == 0 ? 2 : 1;
    if (sqlite3_open(argv[2], &writer) != SQLITE_OK) return 3;
    char *args[] = { argv[0], argv[2], argv[3], NULL };
    int rc = test_recovery_main(3, args);
    if (sqlite3_close(writer) != SQLITE_OK) return 4;
    if (writes < 2 || steps < 2) return 5;
    if (mode == 2 && rc == 1 && steps == 2 && ticks >= 62001) {
        puts("repeated restarts reached stall deadline");
        return 0;
    }
    return mode == 2 ? 6 : (ticks >= 40001 ? rc : 7);
}
