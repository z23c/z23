/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/state_root.h"
#include "platform/private_directory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
bool platform_state_root(char *out, size_t cap)
{
    PWSTR wide = NULL; char base[32768], z23[32768];
    if (!out || !cap || FAILED(SHGetKnownFolderPath(
            &FOLDERID_LocalAppData, KF_FLAG_DEFAULT, NULL, &wide))) return false;
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                base, sizeof(base), NULL, NULL);
    CoTaskMemFree(wide);
    if (n <= 1 || snprintf(z23, sizeof(z23), "%s/z23", base) <= 0 ||
        !platform_private_directory_ensure(z23)) return false;
    n = snprintf(out, cap, "%s/dev", z23);
    return n > 0 && (size_t)n < cap && platform_private_directory_ensure(out);
}
#else
#include <errno.h>
#include <sys/stat.h>
static bool ensure_parent(const char *path)
{
    char copy[4096];
    size_t length = path ? strlen(path) : 0;
    if (!length || length >= sizeof(copy)) return false;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p; *p = '\0';
        if (copy[0] && mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        struct stat info;
        if (copy[0] && (lstat(copy, &info) != 0 ||
                        !S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode)))
            return false;
        *p = saved;
        if (!saved) break;
    }
    return true;
}
bool platform_state_root(char *out, size_t cap)
{
    const char *xdg=getenv("XDG_STATE_HOME"), *home=getenv("HOME");
    char base[4096], z23[4096]; int n;
    if (xdg&&xdg[0]) n=snprintf(base,sizeof(base),"%s",xdg);
    else if (home&&home[0]) { n=snprintf(base,sizeof(base),"%s/.local/state",home); }
    else return false;
    if(n<=0||(size_t)n>=sizeof(base)||!ensure_parent(base)||
       snprintf(z23,sizeof(z23),"%s/z23",base)<=0||
       !platform_private_directory_ensure(z23)) return false;
    n=snprintf(out,cap,"%s/dev",z23);
    return n>0&&(size_t)n<cap&&platform_private_directory_ensure(out);
}
#endif
