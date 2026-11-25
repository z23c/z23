/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: command-line option table and parsing (UTF-8 argv). */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

const char *zw_args_help(void)
{
    return "z23-wallet - lightweight Z23 wallet window\n"
           "  --datadir=<dir>     node data folder (holds .cookie)\n"
           "  --rpcport=<n>       node RPC port (default: .rpcport, then 18232)\n"
           "  --node=auto|z23|zclassicd\n"
           "  --backend=auto|win32|x11|cocoa|headless\n"
           "  --size=WxH          window size in logical px (default 1100x720)\n"
           "  --scale=F           headless scale factor\n"
           "  --script=<file>     headless input script\n"
           "  --shot=<png> [--shot-after-ms=N] [--exit-after-shot]\n"
           "  --shot-dir=<dir>    where script shots are written\n"
           "  --qa-frames=N       present N frames then exit 0 (self test)\n"
           "  --bench=<file>      write one key=value bench line\n"
           "  --log=<file>        lifecycle log (no secrets)\n"
           "  --z23=<path>        z23 binary for later write actions\n"
           "  --version  --help\n";
}

static bool copy_path(char *dst, const char *v, char *err, size_t cap, const char *name)
{
    if (strlen(v) >= ZW_PATH) {
        snprintf(err, cap, "%s is too long", name);
        return false;
    }
    snprintf(dst, ZW_PATH, "%s", v);
    return true;
}

static bool parse_size(const char *v, struct zw_options *o)
{
    char *x;
    long w = strtol(v, &x, 10);
    if (*x != 'x' && *x != 'X') return false;
    long h = strtol(x + 1, &x, 10);
    if (*x || w < 320 || h < 240 || w > 7680 || h > 4320) return false;
    o->width = (int32_t)w;
    o->height = (int32_t)h;
    return true;
}

static bool parse_enum(const char *name, const char *v, struct zw_options *o, char *err, size_t cap)
{
    bool ok = true;
    if (!strcmp(name, "node")) {
        if (!strcmp(v, "auto")) o->profile = ZW_PROFILE_AUTO;
        else if (!strcmp(v, "z23")) o->profile = ZW_PROFILE_Z23;
        else if (!strcmp(v, "zclassicd")) o->profile = ZW_PROFILE_ZCLASSICD;
        else ok = false;
    } else {
        if (!strcmp(v, "auto")) o->backend = GUI_BACKEND_AUTO;
        else if (!strcmp(v, "win32")) o->backend = GUI_BACKEND_WIN32;
        else if (!strcmp(v, "x11")) o->backend = GUI_BACKEND_X11;
        else if (!strcmp(v, "cocoa")) o->backend = GUI_BACKEND_COCOA;
        else if (!strcmp(v, "headless")) o->backend = GUI_BACKEND_HEADLESS;
        else ok = false;
    }
    if (!ok) snprintf(err, cap, "--%s=%s is not a valid choice", name, v);
    return ok;
}

static bool parse_numeric(const char *name, const char *v, struct zw_options *o, char *err, size_t cap, bool *known)
{
    *known = true;
    if (!strcmp(name, "rpcport")) {
        long p = strtol(v, NULL, 10);
        if (p < 1 || p > 65535) { snprintf(err, cap, "--rpcport must be 1..65535"); return false; }
        o->rpcport = (uint16_t)p;
        return true;
    }
    if (!strcmp(name, "size")) {
        if (!parse_size(v, o)) { snprintf(err, cap, "--size must look like 1100x720"); return false; }
        return true;
    }
    if (!strcmp(name, "scale")) {
        o->scale = (float)atof(v);
        if (o->scale < 0.5f || o->scale > 4.0f) { snprintf(err, cap, "--scale must be 0.5..4"); return false; }
        return true;
    }
    if (!strcmp(name, "shot-after-ms")) { o->shot_after_ms = atoi(v); return o->shot_after_ms >= 0; }
    if (!strcmp(name, "qa-frames")) { o->qa_frames = atoi(v); return o->qa_frames > 0; }
    *known = false;
    return false;
}

static const struct { const char *name; size_t off; } k_paths[] = {
    { "datadir", offsetof(struct zw_options, datadir) }, { "script", offsetof(struct zw_options, script) },
    { "shot", offsetof(struct zw_options, shot) }, { "shot-dir", offsetof(struct zw_options, shot_dir) },
    { "bench", offsetof(struct zw_options, bench) }, { "log", offsetof(struct zw_options, log) },
    { "z23", offsetof(struct zw_options, z23) },
};

static bool parse_one(const char *name, const char *v, struct zw_options *o, char *err, size_t cap)
{
    for (size_t i = 0; i < sizeof(k_paths) / sizeof(k_paths[0]); i++)
        if (!strcmp(name, k_paths[i].name)) return copy_path((char *)o + k_paths[i].off, v, err, cap, name);
    if (!strcmp(name, "node") || !strcmp(name, "backend")) return parse_enum(name, v, o, err, cap);
    bool known;
    bool ok = parse_numeric(name, v, o, err, cap, &known);
    if (!known) snprintf(err, cap, "unknown option --%s (try --help)", name);
    return ok;
}

bool zw_args_parse(int argc, char **argv, struct zw_options *o, char *err, size_t cap)
{
    memset(o, 0, sizeof(*o));
    o->width = 1100;
    o->height = 720;
    o->scale = 0.0f;
    err[0] = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--version")) { o->version = true; continue; }
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { o->help = true; continue; }
        if (!strcmp(a, "--exit-after-shot")) { o->exit_after_shot = true; continue; }
        if (strncmp(a, "--", 2) != 0) { snprintf(err, cap, "unexpected argument %s", a); return false; }
        char name[32];
        const char *eq = strchr(a + 2, '=');
        if (!eq || (size_t)(eq - a - 2) >= sizeof(name)) {
            snprintf(err, cap, "option %s needs --name=value form", a);
            return false;
        }
        memcpy(name, a + 2, (size_t)(eq - a - 2));
        name[eq - a - 2] = 0;
        if (!parse_one(name, eq + 1, o, err, cap)) return false;
    }
    if (o->shot[0] && o->shot_after_ms == 0 && !o->script[0]) o->shot_after_ms = 1500;
    return true;
}
