/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: run the build-epoch integrity probes as two private native pool
 * steps. Their real Make/source-identity reads have no finite cache premise;
 * every invocation executes both and keeps the pool's status and diagnostics.
 */
#include "lintc.h"
#include "lintc_commands.h"
#include "run_priv.h"

static const struct {
    const char *name;
    const char *command;
} probes[] = {
    { "check-build-epoch-selftest", "tools/dev/build-epoch-selftest.sh" },
    { "check-make-depfile-scope-selftest", "tools/dev/make-depfile-scope-selftest.sh" },
};

static int resolve_probe(void *ctx, const char *name, char *command, size_t cap)
{
    (void)ctx;
    for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++) {
        if (strcmp(name, probes[i].name) != 0)
            continue;
        int n = snprintf(command, cap, "%s", probes[i].command);
        return n < 0 || (size_t)n >= cap ? 2 : 0;
    }
    return 2;
}

int lint_epoch_probes_main(int argc, char **argv)
{
    (void)argv;
    if (argc != 0)
        return die("usage: z23-lint epoch-probes\n", "");
    const char *dir = getenv("ZCL_LINT_TIMING_DIR");
    if (!dir || !*dir)
        dir = ".cache/build-epoch-integrity/probes";
    struct lr_opts opts = {
        .jobs = 2, .state_dir = dir, .lint_bin = g_lint_argv0,
        .bin_dir = "build/bin", .budget_sec = 75,
        .out = stdout, .err = stderr, .resolve = resolve_probe,
    };
    char *names[sizeof probes / sizeof probes[0]];
    for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++)
        names[i] = (char *)probes[i].name;
    return lr_execute(&opts, names, (int)(sizeof probes / sizeof probes[0]));
}
