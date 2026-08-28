/* Headless acceptance for redirected Windows CLI rendering. */
#include "command/cli_render.h"

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int descriptors[2] = {-1, -1};
    if (_pipe(descriptors, 256, _O_BINARY) != 0) {
        fputs("cli_render_env_acceptance: pipe creation failed\n", stderr);
        return 1;
    }
    if (_putenv_s("ZCL_HUMAN", "1") != 0 ||
        _putenv_s("COLUMNS", "211") != 0 ||
        _putenv_s("NO_COLOR", "1") != 0) {
        fputs("cli_render_env_acceptance: environment setup failed\n",
              stderr);
        return 1;
    }
    struct zcl_cli_render_env env =
        zcl_cli_render_resolve(descriptors[1]);
    _close(descriptors[0]);
    _close(descriptors[1]);
    if (!env.human || env.ansi || env.width != 80) {
        fprintf(stderr,
                "cli_render_env_acceptance: redirected result %d/%d/%d\n",
                env.human, env.ansi, env.width);
        return 1;
    }
    puts("cli_render_env_acceptance: PASS");
    return 0;
}
