/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the hermetic X11 standalone-tools
 * selftest port (from the former shell self-test script,
 * deleted). stl_x11_selftest_run() rebuilds the script's private fixture,
 * runs every case with the same report lines on stdout and stderr and the
 * same exit codes; it must be invoked with the repository root as cwd,
 * exactly like the script was.
 */
#ifndef STL_STANDALONE_TOOLS_LINK_X11_H
#define STL_STANDALONE_TOOLS_LINK_X11_H

enum { STL_X11_PATH = 1024, STL_X11_TEXT = 4096 };

struct stl_x11_ctx {
    char tmp[STL_X11_PATH], fixture[STL_X11_PATH], out[STL_X11_PATH];
    char err[STL_X11_PATH], lint[STL_X11_PATH], realcc[STL_X11_PATH];
    char cclog[STL_X11_PATH], mk[STL_X11_PATH], mkgood[STL_X11_PATH];
    char ccbin[STL_X11_PATH], driver[STL_X11_PATH];
    int cases;
};

enum stl_x11_mk {
    STL_X11_MK_COPY,
    STL_X11_MK_DROP_DHT,
    STL_X11_MK_INVALID_DHT,
    STL_X11_MK_FUZZCI
};

extern const char k_stl_x11_good[];
/* Set by the suite so the fixture gates it runs never start the suite again. */
static const char k_stl_x11_nested[] = "Z23_X11_SELFTEST_NESTED";

int stl_x11_fixture(struct stl_x11_ctx *c);
int stl_x11_make_from(struct stl_x11_ctx *c, enum stl_x11_mk kind);
int stl_x11_selftest_run(void);

#endif
