/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: command declarations shared by the lint dispatcher and implementations. */
#ifndef Z23_LINTC_COMMANDS_H
#define Z23_LINTC_COMMANDS_H
/* `z23-lint precheck [--base=DIR]`: precheck.c, precheck_base.c. */
int lint_precheck_main(int argc, char **argv);
/* `z23-lint run`: the C23 lint driver, run_main.c. */
int lint_run_main(int argc, char **argv);
/* Run both build-epoch probes through the native pool, without reuse. */
int lint_epoch_probes_main(int argc, char **argv);
#endif
