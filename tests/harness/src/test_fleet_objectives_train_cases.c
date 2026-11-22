/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Acceptance cases for the two landing objectives
 *          (tools/command/native_fleet_objectives_read.c): a landed row ends
 *          its train, so a long-lived lane that lands many times under one
 *          note reports only the rows since its previous landing. Called
 *          from test_fleet_objectives. */

#include "test/test_core.h"

#include "command/native_fleet_objectives.h"

#include <stdio.h>
#include <string.h>

struct ftr_case {
    const char *name;
    const char *ledger;
    int64_t attempts;
    int64_t latency;
};

/* ts 00:01:40 = 100 s, 00:16:40 = 1000 s, 00:17:40 = 1060 s. */
static const struct ftr_case ftr_cases[] = {
    {"landing train: an earlier landed row of the same note ends the train "
     "(rows carry seq)",
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":1,"
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1,"
     "\"landed_at\":200}\n"
     "{\"note\":\"lane\",\"state\":\"failed\",\"seq\":2,"
     "\"ts\":\"1970-01-01T00:16:40Z\",\"attempt\":1,\"started\":2}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":3,"
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n",
     2, 600},
    {"landing train: legacy rows without seq or landed_at still split "
     "at the earlier landed row",
     "{\"note\":\"lane\",\"state\":\"landed\","
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1}\n"
     "{\"note\":\"lane\",\"state\":\"failed\","
     "\"ts\":\"1970-01-01T00:16:40Z\",\"attempt\":1,\"started\":2}\n"
     "{\"note\":\"lane\",\"state\":\"landed\","
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n",
     2, 600},
    {"landing train: back-to-back landings of one note are one attempt each",
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":1,"
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1,"
     "\"landed_at\":200}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":2,"
     "\"ts\":\"1970-01-01T00:16:40Z\",\"attempt\":1,\"started\":2,"
     "\"landed_at\":1100}\n",
     1, 100},
    {"landing train: a re-appended identical landed row is the same landing "
     "and an earlier distinct landing still ends the train",
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":1,"
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1,"
     "\"landed_at\":200}\n"
     "{\"note\":\"lane\",\"state\":\"failed\",\"seq\":2,"
     "\"ts\":\"1970-01-01T00:16:40Z\",\"attempt\":1,\"started\":2}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":3,"
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":3,"
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n",
     2, 600},
    {"landing train: an older row without seq is a different landing from "
     "the newest row that has seq",
     "{\"note\":\"lane\",\"state\":\"landed\","
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1,"
     "\"landed_at\":200}\n"
     "{\"note\":\"lane\",\"state\":\"failed\","
     "\"ts\":\"1970-01-01T00:16:40Z\",\"attempt\":1,\"started\":2}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":3,"
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n",
     2, 600},
    {"landing train: another note's landing never ends this train",
     "{\"note\":\"lane\",\"state\":\"failed\",\"seq\":1,"
     "\"ts\":\"1970-01-01T00:01:40Z\",\"attempt\":1,\"started\":1}\n"
     "{\"note\":\"other\",\"state\":\"landed\",\"seq\":2,"
     "\"ts\":\"1970-01-01T00:05:00Z\",\"attempt\":1,\"started\":2,"
     "\"landed_at\":400}\n"
     "{\"note\":\"lane\",\"state\":\"landed\",\"seq\":3,"
     "\"ts\":\"1970-01-01T00:17:40Z\",\"attempt\":2,\"started\":3,"
     "\"landed_at\":1600}\n",
     2, 1500},
};

static int ftr_case_run(const char *path, const struct ftr_case *c)
{
    int failures = 0;
    struct zcl_objectives_options o = {0};
    o.outcomes = path;
    TEST(c->name) {
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        size_t len = strlen(c->ledger);
        bool wrote = fwrite(c->ledger, 1, len, f) == len;
        ASSERT(fclose(f) == 0 && wrote);
        struct zcl_objective_value a =
            zcl_objectives_measure(&o, "landing_attempts_per_train");
        ASSERT(a.measured);
        ASSERT_EQ(a.value, c->attempts);
        struct zcl_objective_value l =
            zcl_objectives_measure(&o, "landing_latency_s");
        ASSERT(l.measured);
        ASSERT_EQ(l.value, c->latency);
        PASS();
    }
_test_next:;
    return failures;
}

int fox_train_cases(void);
int fox_train_cases(void)
{
    int failures = 0;
    char root[512], path[1024];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "train_cases");
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", root);
    for (size_t i = 0; i < sizeof(ftr_cases) / sizeof(ftr_cases[0]); i++)
        failures += ftr_case_run(path, &ftr_cases[i]);
    (void)test_rm_rf_recursive(root);
    return failures;
}
