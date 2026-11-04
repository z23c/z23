#include "test/test_core.h"
#include "engine/engine_verdict.h"
#include "json/json.h"
#include "util/spawn.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>

struct capture_fixture {
    char directory[512];
    char bin[640], executable[768], task[640], reply[640];
};

static bool capture_path(char *out, size_t cap, const char *root, const char *leaf)
{
    int length = snprintf(out, cap, "%s/%s", root, leaf);
    return length > 0 && (size_t)length < cap;
}

static bool capture_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool written = fwrite(text, 1, strlen(text), file) == strlen(text);
    return fclose(file) == 0 && written;
}

static bool capture_read(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t size = fread(out, 1, cap - 1, file);
    bool complete = feof(file) && !ferror(file);
    out[size] = '\0';
    return fclose(file) == 0 && complete;
}

static int capture_spawn(const char *const argv[], int deadline)
{
    char output[16384];
    struct zcl_spawn_binary_observation observation = {0};
    (void)zcl_spawn_capture_binary_merged(argv, output, sizeof(output), deadline,
                                         &observation);
    if (!observation.eof || !observation.exit_observed || observation.overflow ||
        observation.timed_out) return -1;
    return observation.exit_code;
}

static bool capture_setup(struct capture_fixture *fixture)
{
    char relative[512];
    test_make_tmpdir(relative, sizeof(relative), "engine-capture", "native");
    if (!test_abs_path(relative, fixture->directory, sizeof(fixture->directory)))
        return false;
    if (!capture_path(fixture->bin, sizeof(fixture->bin), fixture->directory, "bin") ||
        !capture_path(fixture->executable, sizeof(fixture->executable), fixture->bin, "make") ||
        !capture_path(fixture->task, sizeof(fixture->task), fixture->directory, "task") ||
        !capture_path(fixture->reply, sizeof(fixture->reply), fixture->directory, "reply"))
        return false;
    if (mkdir(fixture->bin, 0700) != 0) return false;
    const char *const compiler[] = {"cc", "-std=c23", "-O0", "-Wall", "-Wextra",
        "-Werror", "tests/fixtures/engine/gate_capture.c", "-o", fixture->executable, NULL};
    return capture_spawn(compiler, 30000) == 0 &&
        capture_write(fixture->task, "kind: fix-gate\n\nApply a local fixture edit.\n") &&
        capture_write(fixture->reply, "{\"choices\":[{\"message\":{\"content\":"
            "\"Z23-BEGIN-FILE note.txt\\nfixture edit\\nZ23-END-FILE\\n\"}}],"
            "\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}");
}

static bool capture_feedback(const char *state, const char *gate_text)
{
    char path[1024], text[16384];
    static const char token[] = "sk-" "fixture012345678901234567890123456789";
    if (!strstr(gate_text, "fixture-marker-after-nul") ||
        strstr(gate_text, token)) return false;
    if (!capture_path(path, sizeof(path), state, "prompt.txt") ||
        !capture_read(path, text, sizeof(text))) return false;
    return strstr(text, "fixture-marker-after-nul") != NULL &&
        strstr(text, token) == NULL;
}

static bool capture_artifacts(const char *state, const char *verdict,
                              bool feedback, bool incomplete)
{
    char path[1024], text[16384];
    if (!capture_path(path, sizeof(path), state, "receipt.json") ||
        !capture_read(path, text, sizeof(text))) return false;
    struct json_value receipt = {0};
    bool matches = json_read(&receipt, text, strlen(text)) &&
        strcmp(json_get_str(json_get(&receipt, "verdict")), verdict) == 0;
    if (!matches)
        fprintf(stderr, "engine_gate_capture: expected %s, observed %s\n",
                verdict, json_get_str(json_get(&receipt, "verdict")));
    json_free(&receipt);
    if (!matches || !capture_path(path, sizeof(path), state, "gate.log") ||
        !capture_read(path, text, sizeof(text))) return false;
    if (incomplete) {
        struct engine_gate_reading reading;
        if (!strstr(text, "INCOMPLETE gate capture") ||
            !engine_gate_read(text, strlen(text), &reading) ||
            engine_verdict_of(&reading, 1, false, true) == ENGINE_VERDICT_PASS)
            return false;
    }
    return !feedback || capture_feedback(state, text);
}

static bool capture_seed_gate(const char *state)
{
    char path[1024];
    return capture_path(path, sizeof(path), state, "gate.log") &&
        capture_write(path, "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0\n"
                            "ALL TESTS PASSED — 0/1 groups failed\n");
}

static bool capture_write_refusal(const char *state)
{
    char path[1024];
    if (chmod(state, 0700) != 0 ||
        !capture_path(path, sizeof(path), state, "gate.log")) return false;
    FILE *file = fopen(path, "rb");
    if (file) {
        (void)fclose(file);
        return false;
    }
    return errno == ENOENT;
}

struct capture_paths {
    char worktree[1024], state[1024];
    char path_env[4096], case_env[128], state_env[1200];
};

static bool capture_case_paths(const struct capture_fixture *fixture,
                                const char *mode, bool feedback,
                                struct capture_paths *paths)
{
    char root[768], tag[128];
    int length = snprintf(tag, sizeof(tag), "%s-%s", mode, feedback ? "feedback" : "once");
    if (length < 0 || (size_t)length >= sizeof(tag) ||
        !capture_path(root, sizeof(root), fixture->directory, tag) ||
        !capture_path(paths->worktree, sizeof(paths->worktree), root, "wt") ||
        !capture_path(paths->state, sizeof(paths->state), root, "state")) return false;
    if (mkdir(root, 0700) != 0 || mkdir(paths->worktree, 0700) != 0 ||
        mkdir(paths->state, 0700) != 0) return false;
    const char *const init[] = {"git", "-C", paths->worktree, "init", "--quiet", NULL};
    return capture_spawn(init, 10000) == 0;
}

static bool capture_environment(const struct capture_fixture *fixture,
                                 const char *mode, struct capture_paths *paths)
{
    int length = snprintf(paths->path_env, sizeof(paths->path_env), "PATH=%s:%s", fixture->bin,
                       getenv("PATH") ? getenv("PATH") : "");
    if (length < 0 || (size_t)length >= sizeof(paths->path_env)) return false;
    length = snprintf(paths->case_env, sizeof(paths->case_env), "GATE_CAPTURE_CASE=%s", mode);
    if (length < 0 || (size_t)length >= sizeof(paths->case_env)) return false;
    length = snprintf(paths->state_env, sizeof(paths->state_env), "GATE_CAPTURE_STATE=%s", paths->state);
    return length >= 0 && (size_t)length < sizeof(paths->state_env);
}

static bool capture_case(const struct capture_fixture *fixture, const char *mode,
                          const char *verdict, bool feedback, bool incomplete)
{
    struct capture_paths paths;
    if (!capture_case_paths(fixture, mode, feedback, &paths) ||
        !capture_environment(fixture, mode, &paths)) return false;
    bool write_failure = strcmp(mode, "overflow-write-failure") == 0;
    if (write_failure && !capture_seed_gate(paths.state)) return false;
    const char *const command[] = {"env", paths.path_env, paths.case_env, paths.state_env,
        "build/bin/z23-engine-unit", "--engine", "fixture", "--task", fixture->task,
        "--group", "engine_gate_capture", "--yes-dispatch", "--worktree", paths.worktree,
        "--state-dir", paths.state, "--fixture-reply", fixture->reply, "--rounds",
        feedback ? "2" : "1", "--gate-timeout", "1", NULL};
    int status = capture_spawn(command, 20000);
    if (write_failure) {
        bool missing = capture_write_refusal(paths.state);
        return status == 1 && missing;
    }
    int expected = strcmp(verdict, "PASS") == 0 ? 0 : 1;
    return status == expected && capture_artifacts(paths.state, verdict, feedback, incomplete);
}
#endif

int test_engine_gate_capture(void);
int test_engine_gate_capture(void)
{
#if defined(_WIN32)
    printf("engine_gate_capture: UNAVAILABLE on native Windows "
           "(POSIX subprocess and permission fixture)\n");
    return 1;
#else
    struct capture_fixture fixture = {0};
    int failures = 0;
    if (!capture_setup(&fixture)) {
        fprintf(stderr, "engine_gate_capture: fixture setup failed\n");
        test_rm_rf(fixture.directory);
        return 1;
    }
    static const struct {
        const char *mode, *verdict;
        bool feedback, incomplete;
    } cases[] = {
        {"ordinary-pass", "PASS", false, false},
        {"ordinary-fail", "FAIL", false, false},
        {"nul-before-pass", "PASS", false, false},
        {"nul-before-fail", "FAIL", false, false},
        {"overflow-before-fail", "REFUSED", false, true},
        {"timeout", "TIMEOUT", false, true},
        {"nul-before-fail", "FAIL", true, false},
        {"overflow-write-failure", "REFUSED", false, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool ok = capture_case(&fixture, cases[i].mode, cases[i].verdict,
                                 cases[i].feedback, cases[i].incomplete);
        printf("engine_gate_capture: %s%s... %s\n", cases[i].mode,
               cases[i].feedback ? " feedback" : "", ok ? "OK" : "FAIL");
        if (!ok) failures++;
    }
    test_rm_rf(fixture.directory);
    return failures;
#endif
}
