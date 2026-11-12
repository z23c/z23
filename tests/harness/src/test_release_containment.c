/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_release_invoke: the refusal, a real archive check, and the
 * fail-closed verify errors. gpg is a PATH stub; openssl and tar are real. */

#include "test/test_core.h"

#include "release_containment.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char k_rc_refuse[] =
    "REFUSING: stable release build/package/sign/publish is contained.\n"
    "Required first: exact immutable quality evidence, complete canonical security posture,\n"
    "clean parity/soak, two-builder byte identity, SBOM/provenance, signature quorum,\n"
    "offline verification, upgrade, and rollback proof.\n"
    "Unsigned output is local-development-only; use ordinary build targets for local binaries.\n";

static const char k_rc_pass[] =
    "legacy_local_artifact_verification=PASS\n"
    "stable_release_verification=NOT_IMPLEMENTED\n"
    "publishable=false\n";

static int rc_fit(int n, int cap)
{
    return n > 0 && n < cap;
}

static int rc_put(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return 0;
}

static int rc_command(const char *cmd)
{
    int status = system(cmd);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static char *rc_dup(const char *text)
{
    size_t n = strlen(text) + 1;
    char *out = malloc(n);
    if (out)
        memcpy(out, text, n);
    return out;
}

static int rc_digest(const char *archive, char *out, size_t cap)
{
    char cmd[1024];
    char line[512];
    char *last = NULL;
    char *tok;
    FILE *pipe;
    int status;
    int n = snprintf(cmd, sizeof cmd, "openssl dgst -sha3-256 '%s'", archive);
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    pipe = popen(cmd, "r");
    if (!pipe || !fgets(line, (int)sizeof line, pipe)) {
        if (pipe)
            pclose(pipe);
        return -1;
    }
    status = pclose(pipe);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    for (tok = strtok(line, " \t\r\n"); tok; tok = strtok(NULL, " \t\r\n"))
        last = tok;
    if (!last || strlen(last) != 64 || strlen(last) + 1 > cap)
        return -1;
    memcpy(out, last, 65);
    return 0;
}

static void rc_upper(char *text)
{
    for (; *text; text++)
        if (*text >= 'a' && *text <= 'z')
            *text = (char)(*text - 'a' + 'A');
}

static int rc_gpg_stub(const char *path, int code)
{
    char body[64];
    int n = snprintf(body, sizeof body, "#!/bin/sh\nexit %d\n", code);
    if (n < 0 || (size_t)n >= sizeof body || rc_put(path, body) != 0)
        return -1;
    return chmod(path, 0755) == 0 ? 0 : -1;
}

static int rc_capture(int argc, char **argv, const char *log, char *got,
                      size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_release_invoke(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd);
    file = fopen(log, "r");
    if (!file)
        return -1;
    used = fread(got, 1, cap - 1, file);
    got[used] = '\0';
    fclose(file);
    return 0;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int test_release_containment_cases(const char *dir)
{
    int failures = 0;
    char *saved_path = NULL;
    TEST("release containment: refuse, verify, and fail closed") {
        char payload[1024], archive[1024], bad[1024], orphan[1024];
        char sha3[1024], sig[1024], bin[1024], gpg[1024], log[1024];
        char cmd[1200], manifest[256], digest[80], upper[80], got[2048];
        char prefixed[4096];
        char *argv_prog[] = {"release", NULL};
        char *argv_usage[] = {"release-tool", "--verify", NULL};
        char *argv_extra[] = {"release", "--verify", archive, "extra", NULL};
        char *argv_archive[] = {"release", "--verify", archive, NULL};
        char *argv_bad[] = {"release", "--verify", bad, NULL};
        char *argv_orphan[] = {"release", "--verify", orphan, NULL};
        const char *old = getenv("PATH");
        int rc = 0;
        int n;
        if (old != NULL)
            saved_path = rc_dup(old);
        ASSERT(old != NULL);
        ASSERT(saved_path != NULL);
        n = snprintf(payload, sizeof payload, "%s/payload.txt", dir);
        ASSERT(rc_fit(n, (int)sizeof payload));
        n = snprintf(archive, sizeof archive, "%s/ok.tar.gz", dir);
        ASSERT(rc_fit(n, (int)sizeof archive));
        n = snprintf(sha3, sizeof sha3, "%s/ok.sha3", dir);
        ASSERT(rc_fit(n, (int)sizeof sha3));
        n = snprintf(sig, sizeof sig, "%s/ok.sha3.sig", dir);
        ASSERT(rc_fit(n, (int)sizeof sig));
        n = snprintf(bad, sizeof bad, "%s/bad.tar.gz", dir);
        ASSERT(rc_fit(n, (int)sizeof bad));
        n = snprintf(orphan, sizeof orphan, "%s/orphan.tar.gz", dir);
        ASSERT(rc_fit(n, (int)sizeof orphan));
        n = snprintf(bin, sizeof bin, "%s/bin", dir);
        ASSERT(rc_fit(n, (int)sizeof bin));
        n = snprintf(gpg, sizeof gpg, "%s/bin/gpg", dir);
        ASSERT(rc_fit(n, (int)sizeof gpg));
        n = snprintf(log, sizeof log, "%s/capture.out", dir);
        ASSERT(rc_fit(n, (int)sizeof log));
        ASSERT(rc_put(payload, "release-containment-payload\n") == 0);
        n = snprintf(cmd, sizeof cmd, "tar -czf '%s' -C '%s' payload.txt",
                     archive, dir);
        ASSERT(rc_fit(n, (int)sizeof cmd));
        ASSERT(rc_command(cmd) == 1);
        ASSERT(rc_digest(archive, digest, sizeof digest) == 0);
        memcpy(upper, digest, sizeof digest);
        rc_upper(upper);
        n = snprintf(manifest, sizeof manifest, "%s  payload.txt\n", upper);
        ASSERT(rc_fit(n, (int)sizeof manifest));
        ASSERT(rc_put(sha3, manifest) == 0);
        ASSERT(rc_put(sig, "not-a-real-signature\n") == 0);
        ASSERT(mkdir(bin, 0700) == 0);
        ASSERT(rc_gpg_stub(gpg, 0) == 0);
        n = snprintf(prefixed, sizeof prefixed, "%s:%s", bin, saved_path);
        ASSERT(rc_fit(n, (int)sizeof prefixed));
        ASSERT(setenv("PATH", prefixed, 1) == 0);

        ASSERT(rc_capture(1, argv_prog, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT_STR_EQ(got, k_rc_refuse);

        ASSERT(rc_capture(2, argv_usage, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got,
                      "ERROR: usage: release-tool --verify <archive.tar.gz>\n");

        {
            char missing[1024];
            char *argv_gone[] = {"release", "--verify", missing, NULL};
            n = snprintf(missing, sizeof missing, "%s/missing.tar.gz", dir);
            ASSERT(rc_fit(n, (int)sizeof missing));
            ASSERT(rc_capture(3, argv_gone, log, got, sizeof got, &rc) == 0);
            ASSERT(rc == 1);
            ASSERT(strstr(got, "ERROR: archive not found: ") == got);
            ASSERT(strstr(got, missing) != NULL);
        }

        ASSERT(rc_capture(4, argv_extra, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "ERROR: usage: release --verify <archive.tar.gz>\n")
               != NULL);

        ASSERT(rc_capture(3, argv_archive, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_rc_pass);

        ASSERT(rc_put(sha3, "00000000000000000000000000000000"
                            "00000000000000000000000000000000  payload.txt\n")
               == 0);
        ASSERT(rc_capture(3, argv_archive, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        n = snprintf(manifest, sizeof manifest,
                     "ERROR: SHA3-256 mismatch: expected=%s actual=%s\n",
                     "00000000000000000000000000000000"
                     "00000000000000000000000000000000",
                     digest);
        ASSERT(rc_fit(n, (int)sizeof manifest));
        ASSERT_STR_EQ(got, manifest);

        n = snprintf(manifest, sizeof manifest, "%s  payload.txt\n", upper);
        ASSERT(rc_fit(n, (int)sizeof manifest));
        ASSERT(rc_put(sha3, manifest) == 0);
        ASSERT(rc_gpg_stub(gpg, 1) == 0);
        ASSERT(rc_capture(3, argv_archive, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got, "ERROR: GPG signature verification failed\n");

        ASSERT(rc_put(bad, "not-a-tar\n") == 0);
        ASSERT(rc_digest(bad, digest, sizeof digest) == 0);
        n = snprintf(manifest, sizeof manifest, "%s  bad\n", digest);
        ASSERT(rc_fit(n, (int)sizeof manifest));
        n = snprintf(sha3, sizeof sha3, "%s/bad.sha3", dir);
        ASSERT(rc_fit(n, (int)sizeof sha3));
        n = snprintf(sig, sizeof sig, "%s/bad.sha3.sig", dir);
        ASSERT(rc_fit(n, (int)sizeof sig));
        ASSERT(rc_put(sha3, manifest) == 0);
        ASSERT(rc_put(sig, "not-a-real-signature\n") == 0);
        ASSERT(rc_gpg_stub(gpg, 0) == 0);
        ASSERT(rc_capture(3, argv_bad, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got, "ERROR: archive structure is invalid\n");

        ASSERT(rc_put(orphan, "orphan\n") == 0);
        ASSERT(rc_capture(3, argv_orphan, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "ERROR: required SHA3 manifest missing: ") == got);

        PASS();
    } _test_next:
    if (saved_path) {
        (void)setenv("PATH", saved_path, 1);
        free(saved_path);
    }
    return failures;
}

int test_release_containment(void);
int test_release_containment(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "release_containment", "root");
    failures = test_release_containment_cases(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_release_containment: all passed\n");
    else
        printf("test_release_containment: %d FAILED\n", failures);
    return failures;
}
