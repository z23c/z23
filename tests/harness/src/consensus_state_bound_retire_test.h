/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Verify identity-safe retirement of bound install requests. */
static bool bound_retire_replaced;
static void bound_retire_replace(const char *path)
{
    char old[1024];
    int n = snprintf(old, sizeof(old), "%s.old", path);
    if (n < 0 || (size_t)n >= sizeof(old) || rename(path, old)) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return;
    const char text[] = "replacement\n";
    bound_retire_replaced = write(fd, text, sizeof(text) - 1) == (ssize_t)(sizeof(text) - 1);
    if (close(fd)) bound_retire_replaced = false;
}
static int bound_retire_fields(const char *dir, const struct boot_bound_bundle_observation *current)
{
    int failures = 0;
    for (unsigned i = 0; i < 7; ++i) {
        struct boot_bound_bundle_observation stale = *current;
        switch (i) {
        case 0: stale.bundle_path[1] ^= 1; break;
        case 1: stale.private_history_path[1] ^= 1; break;
        case 2: stale.snapshot_sha3[0] ^= 1; break;
        case 3: stale.endpoint_hash[0] ^= 1; break;
        case 4: stale.history_manifest_root[0] ^= 1; break;
        case 5: stale.endpoint_height++; break;
        case 6: stale.attempts++; break;
        }
        CSIR_CHECK("stale bound retirement refuses", boot_install_bound_bundle_retire(dir, &stale) == BOOT_BOUND_RETIRE_STALE);
    }
    struct boot_bound_bundle_observation after;
    CSIR_CHECK("stale retirement preserves request", boot_install_bound_bundle_read(dir, &after) == BOOT_BOUND_READ_READY &&
        !memcmp(&after, current, sizeof(after)));
    return failures;
}
static int bound_retire_cases(const char *dir, const struct boot_bound_bundle_request *request)
{
    int failures = 0; struct boot_bound_bundle_observation current = {0};
    char path[512], backup[520];
    snprintf(path, sizeof(path), "%s/install_bundle_request", dir);
    snprintf(backup, sizeof(backup), "%s.old", path);
    boot_install_bundle_clear(dir);
    CSIR_CHECK("absent retirement is idempotent", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_ABSENT);
    CSIR_CHECK("retirement fixture published", boot_install_bound_bundle_request(dir, request, NULL) == BOOT_BUNDLE_ARM_CREATED &&
        boot_install_bound_bundle_read(dir, &current) == BOOT_BOUND_READ_READY);
    failures += bound_retire_fields(dir, &current);
    bound_retire_replaced = false;
    boot_install_bound_retire_test_hook(bound_retire_replace, false);
    CSIR_CHECK("replacement reports uncertain retirement", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_UNKNOWN && bound_retire_replaced);
    boot_install_bound_retire_test_hook(NULL, false);
    char text[32] = {0}; FILE *f = fopen(path, "rb");
    size_t n = f ? fread(text, 1, sizeof(text) - 1, f) : 0;
    bool closed = f && fclose(f) == 0;
    CSIR_CHECK("replacement is not deleted", closed && n == strlen("replacement\n") && !strcmp(text, "replacement\n"));
    CSIR_CHECK("malformed replacement is error", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_ERROR);
    unlink(path); unlink(backup);
    CSIR_CHECK("uncertain fixture published", boot_install_bound_bundle_request(dir, request, NULL) == BOOT_BUNDLE_ARM_CREATED &&
        boot_install_bound_bundle_read(dir, &current) == BOOT_BOUND_READ_READY);
    boot_install_bound_retire_test_hook(NULL, true);
    CSIR_CHECK("parent flush failure is unknown", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_UNKNOWN);
    boot_install_bound_retire_test_hook(NULL, false);
    CSIR_CHECK("unknown readback is absent", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_ABSENT);
    CSIR_CHECK("success fixture published", boot_install_bound_bundle_request(dir, request, NULL) == BOOT_BUNDLE_ARM_CREATED &&
        boot_install_bound_bundle_read(dir, &current) == BOOT_BOUND_READ_READY);
    CSIR_CHECK("exact retirement succeeds", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_DONE);
    CSIR_CHECK("success is idempotently absent", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_ABSENT);
    CSIR_CHECK("unreadable shape fixture", mkdir(path, 0700) == 0);
    CSIR_CHECK("unreadable shape is error", boot_install_bound_bundle_retire(dir, &current) == BOOT_BOUND_RETIRE_ERROR);
    CSIR_CHECK("unreadable shape cleanup", rmdir(path) == 0);
    return failures;
}
