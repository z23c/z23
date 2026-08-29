/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "vcs/zcode_sovereignty_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void policy_value_text(uint8_t out[32], const char *text)
{
  memset(out, 0, 32);
  (void)snprintf((char *)out, 32, "%s", text);
}

static void policy_cleanup(const char *datadir)
{
  char path[512];
  (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                 VCS_ZCODE_SOVEREIGNTY_POLICY_FILE);
  (void)unlink(path);
  (void)snprintf(path, sizeof(path), "%s/zcode/policy", datadir);
  (void)rmdir(path);
  (void)snprintf(path, sizeof(path), "%s/zcode", datadir);
  (void)rmdir(path);
  (void)rmdir(datadir);
}

static int test_policy_precedence(void)
{
  int failures = 0;
  TEST("zcode sovereignty: unknown defaults and local block precedence") {
    uint8_t genesis[32];
    memset(genesis, 0x11, 32);
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(genesis);
    ASSERT(policy != NULL);
    struct vcs_zcode_sovereignty_subject subject;
    memset(&subject, 0, sizeof(subject));
    memset(subject.semantic_root, 0x61, 32);
    (void)snprintf(subject.service_type, sizeof(subject.service_type),
                   "science.study");
    ASSERT(vcs_zcode_sovereignty_policy_check(
               policy, VCS_ZCODE_SOVEREIGNTY_DISCOVER, &subject)
               .allow);
    ASSERT(!vcs_zcode_sovereignty_policy_check(
                policy, VCS_ZCODE_SOVEREIGNTY_FETCH, &subject)
                .allow);
    ASSERT(!vcs_zcode_sovereignty_policy_check(
                policy, VCS_ZCODE_SOVEREIGNTY_SERVE, &subject)
                .allow);
    ASSERT(!vcs_zcode_sovereignty_policy_check(
                policy, VCS_ZCODE_SOVEREIGNTY_EXECUTE, &subject)
                .allow);

    uint8_t value[32];
    policy_value_text(value, "science.study");
    struct vcs_zcode_sovereignty_rule allow;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &allow, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_ALLOW,
                  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_STORE), value),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &allow),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(vcs_zcode_sovereignty_policy_check(
               policy, VCS_ZCODE_SOVEREIGNTY_STORE, &subject)
               .allow);

    struct vcs_zcode_sovereignty_rule block;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &block, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_FULL_ROOT,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_STORE),
                  subject.semantic_root),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    struct vcs_zcode_sovereignty_decision decision =
        vcs_zcode_sovereignty_policy_check(
            policy, VCS_ZCODE_SOVEREIGNTY_STORE, &subject);
    ASSERT(!decision.allow && !decision.defaulted);
    ASSERT(memcmp(decision.rule_id, block.id, 32) == 0);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_remove(policy, block.id),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT(vcs_zcode_sovereignty_policy_check(
               policy, VCS_ZCODE_SOVEREIGNTY_STORE, &subject)
               .allow);
    vcs_zcode_sovereignty_policy_free(policy);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_policy_advisory(void)
{
  int failures = 0;
  TEST("zcode sovereignty: shared blocklists are advisory and opt-in") {
    uint8_t genesis[32], publisher[32];
    memset(genesis, 0x11, 32);
    memset(publisher, 0x77, 32);
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(genesis);
    ASSERT(policy != NULL);
    struct vcs_zcode_sovereignty_rule local_allow, advisory_block;
    uint8_t service[32];
    policy_value_text(service, "science.study");
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &local_allow, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_ALLOW,
                  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_DISCOVER), service),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &advisory_block, VCS_ZCODE_SOVEREIGNTY_ADVISORY,
                  VCS_ZCODE_SOVEREIGNTY_BLOCK,
                  VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID,
                  (uint8_t)(1u << VCS_ZCODE_SOVEREIGNTY_DISCOVER), publisher),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &local_allow),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(policy, &advisory_block),
              VCS_ZCODE_SOVEREIGNTY_OK);
    struct vcs_zcode_sovereignty_subject subject;
    memset(&subject, 0, sizeof(subject));
    memcpy(subject.publisher_zid, publisher, 32);
    memcpy(subject.service_type, service, 32);
    ASSERT(vcs_zcode_sovereignty_policy_check(
               policy, VCS_ZCODE_SOVEREIGNTY_DISCOVER, &subject)
               .allow);
    vcs_zcode_sovereignty_policy_set_advisory(policy, true);
    struct vcs_zcode_sovereignty_decision decision =
        vcs_zcode_sovereignty_policy_check(
            policy, VCS_ZCODE_SOVEREIGNTY_DISCOVER, &subject);
    ASSERT(!decision.allow && decision.advisory);
    vcs_zcode_sovereignty_policy_free(policy);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_policy_restart(void)
{
  int failures = 0;
  TEST("zcode sovereignty: canonical local policy survives restart and tamper") {
    uint8_t genesis[32], value[32];
    memset(genesis, 0x11, 32);
    policy_value_text(value, "trusted.lab");
    struct vcs_zcode_sovereignty_policy *before =
        vcs_zcode_sovereignty_policy_create(genesis);
    struct vcs_zcode_sovereignty_policy *after =
        vcs_zcode_sovereignty_policy_create(genesis);
    ASSERT(before != NULL && after != NULL);
    struct vcs_zcode_sovereignty_rule rule;
    ASSERT_EQ(vcs_zcode_sovereignty_rule_build(
                  &rule, VCS_ZCODE_SOVEREIGNTY_LOCAL,
                  VCS_ZCODE_SOVEREIGNTY_ALLOW,
                  VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION,
                  (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_FETCH) |
                            (1u << VCS_ZCODE_SOVEREIGNTY_INDEX)),
                  value),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_add(before, &rule),
              VCS_ZCODE_SOVEREIGNTY_OK);
    vcs_zcode_sovereignty_policy_set_advisory(before, true);
    /* Absolute: the atomic write this save goes through refuses a relative
     * parent by design, so a relative fixture path fails before it starts. */
    char datadir[PATH_MAX];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_sovereignty", "save");
    char error[160] = {0};
    ASSERT_EQ(vcs_zcode_sovereignty_policy_save(before, datadir, error,
                                                 sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_load(after, datadir, error,
                                                 sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_count(after), 1);
    ASSERT(vcs_zcode_sovereignty_policy_advisory(after));
    struct vcs_zcode_sovereignty_rule loaded[1];
    ASSERT_EQ(vcs_zcode_sovereignty_policy_rules(after, loaded, 1), 1);
    ASSERT(memcmp(loaded[0].id, rule.id, 32) == 0);

    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                   VCS_ZCODE_SOVEREIGNTY_POLICY_FILE);
    struct stat st;
    ASSERT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    ASSERT(fd >= 0);
    uint8_t byte = 0;
    ASSERT(pread(fd, &byte, 1, 90) == 1);
    byte ^= 1;
    ASSERT(pwrite(fd, &byte, 1, 90) == 1);
    ASSERT(close(fd) == 0);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_load(after, datadir, error,
                                                 sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_CORRUPT);
    ASSERT_EQ(vcs_zcode_sovereignty_policy_count(after), 1);
    vcs_zcode_sovereignty_policy_free(after);
    vcs_zcode_sovereignty_policy_free(before);
    policy_cleanup(datadir);
    PASS();
  }
  _test_next:;
  return failures;
}

static int test_policy_load_is_read_only(void)
{
  int failures = 0;
  TEST("zcode sovereignty: loading absent policy creates no directories") {
    uint8_t genesis[32];
    memset(genesis, 0x11, sizeof(genesis));
    struct vcs_zcode_sovereignty_policy *policy =
        vcs_zcode_sovereignty_policy_create(genesis);
    ASSERT(policy != NULL);
    char datadir[] = "test-tmp/zcode_sovereignty_read_XXXXXX";
    ASSERT(mkdtemp(datadir) != NULL);
    char error[160] = {0};
    ASSERT_EQ(vcs_zcode_sovereignty_policy_load(policy, datadir, error,
                                                sizeof(error)),
              VCS_ZCODE_SOVEREIGNTY_OK);
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/zcode", datadir);
    ASSERT(access(path, F_OK) != 0 && errno == ENOENT);
    vcs_zcode_sovereignty_policy_free(policy);
    ASSERT(rmdir(datadir) == 0);
    PASS();
  }
  _test_next:;
  return failures;
}

int test_zcode_sovereignty_policy(void)
{
  int failures = 0;
  failures += test_policy_precedence();
  failures += test_policy_advisory();
  failures += test_policy_restart();
  failures += test_policy_load_is_read_only();
  printf("=== zcode_sovereignty_policy: %d failures ===\n", failures);
  return failures;
}
