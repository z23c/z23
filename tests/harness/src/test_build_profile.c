/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compiler-speed development profile: the unsippable `z23.dev` name never
 * leaks into release flags, and `make ship` / `make deploy` refuse it. */

#include "test/test_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_build_profile(void);

static bool slurp_cmd(const char *cmd, char *buf, size_t cap)
{
    FILE *fp;
    size_t n;

    if (!cmd || !buf || cap < 2)
        return false;
    fp = popen(cmd, "r");
    if (!fp)
        return false;
    n = fread(buf, 1, cap - 1, fp);
    buf[n] = '\0';
    if (pclose(fp) != 0)
        return false;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return n > 0;
}

static bool file_has_line_prefix(const char *path, const char *prefix)
{
    FILE *fp;
    char line[4096];
    size_t plen = strlen(prefix);

    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof line, fp)) {
        if (strncmp(line, prefix, plen) == 0) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool file_contains(const char *path, const char *needle)
{
    FILE *fp;
    char line[4096];

    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof line, fp)) {
        if (strstr(line, needle)) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

int test_build_profile(void)
{
    int failures = 0;
    char flags[196608];
    char guard[8192];
    char *cflags;
    char *dev_cflags;
    char *ldflags;

    TEST("Makefile names the unsippable compiler-speed binary z23.dev") {
        ASSERT(file_has_line_prefix("Makefile",
                                    "Z23_DEV_UNSHIPPABLE_BIN = $(BIN_DIR)/z23.dev"));
        ASSERT(file_has_line_prefix("Makefile",
                                    "dev: $(Z23_DEV_UNSHIPPABLE_BIN)"));
        PASS();
    }

    TEST("make ship and make deploy refuse the dev profile and .dev names") {
        ASSERT(file_contains("Makefile",
                             "ship: REFUSE: ZCL_PROFILE=dev"));
        ASSERT(file_contains("Makefile",
                             "deploy: REFUSE: ZCL_PROFILE=dev"));
        ASSERT(file_contains("Makefile",
                             "frozen candidate is the unsippable .dev binary"));
        ASSERT(file_contains("tools/ship.sh",
                             "ZCL_PROFILE=dev produces the unsippable"));
        PASS();
    }

    TEST("ship.sh refuses the dev artifact under every alias and reach") {
        ASSERT(file_contains("tools/ship.sh",
                             "unsippable z23.dev dev artifact"));
        ASSERT(file_contains("tools/ship.sh",
                             "ship_refuse_dev_artifact build/bin/z23"));
        ASSERT(file_contains("tools/ship.sh",
                             "ship_refuse_dev_artifact build/bin/zclassic23"));
        ASSERT(file_contains("tools/ship.sh",
                             "dev/epochs/*/zclassic23-dev"));
        ASSERT(slurp_cmd("tools/ship.sh --selftest-dev-guard",
                         guard, sizeof guard));
        ASSERT(strstr(guard, "dev-artifact guard selftest PASS") != NULL);
        ASSERT(strstr(guard, "hardlink") != NULL);
        ASSERT(strstr(guard, "copied name") != NULL);
        ASSERT(strstr(guard, "stale epoch copy") != NULL);
        PASS();
    }

    TEST("release CFLAGS still carry whole-program LTO; DEV_CFLAGS do not") {
        ASSERT(file_contains("Makefile",
                             "CFLAGS = -std=$(ZCL_C_STD) -g -O3 $(ZCL_ARCH_CFLAGS) $(ZCL_LTO_FLAG)"));
        ASSERT(file_contains("Makefile",
                             "RELEASE_CFLAGS := $(CFLAGS)"));
        ASSERT(file_contains("Makefile",
                             "filter-out -O3 -g $(ZCL_LTO_FLAG)"));
        ASSERT(file_contains("Makefile", "-DZCL_DEV_BUILD"));
        PASS();
    }

    TEST("print-build-flags matches the Makefile: release has LTO, dev does not") {
        char *dev_line;
        char *ld_line;

        ASSERT(slurp_cmd("make -s --no-print-directory print-build-flags",
                         flags, sizeof flags));
        cflags = strstr(flags, "CFLAGS=");
        dev_cflags = strstr(flags, "DEV_CFLAGS=");
        ldflags = strstr(flags, "LDFLAGS=");
        ASSERT(cflags != NULL);
        ASSERT(dev_cflags != NULL);
        ASSERT(ldflags != NULL);
        ASSERT(cflags < dev_cflags);
        ASSERT(dev_cflags < ldflags);
        dev_line = strchr(cflags, '\n');
        if (dev_line)
            *dev_line = '\0';
        ld_line = strchr(dev_cflags, '\n');
        if (ld_line)
            *ld_line = '\0';
        ASSERT(strstr(cflags, "-flto") != NULL);
        ASSERT(strstr(cflags, "-O3") != NULL);
        ASSERT(strstr(cflags, "-Werror") != NULL);
        ASSERT(strstr(cflags, "-DZCL_DEV_BUILD") == NULL);
        ASSERT(strstr(dev_cflags, "-flto") == NULL);
        ASSERT(strstr(dev_cflags, "-O3") == NULL);
        ASSERT(strstr(dev_cflags, "-DZCL_DEV_BUILD") != NULL);
        ASSERT(strstr(dev_cflags, "-g1") != NULL);
        ASSERT(strstr(dev_cflags, "-pipe") != NULL);
        ASSERT(strstr(dev_cflags, "-fno-omit-frame-pointer") != NULL);
        ASSERT(strstr(dev_cflags, "-Werror") != NULL);
        ASSERT(strstr(ldflags, "-flto") != NULL);
        PASS();
    }

_test_next:
    return failures;
}
