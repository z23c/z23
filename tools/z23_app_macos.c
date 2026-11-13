/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Finder document launcher for the owner-controlled Z23 app flows. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "z23_app_macos_install.h"

#include <mach-o/dyld.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define Z23_APP_CHILD_MAX 32u
static pid_t children[Z23_APP_CHILD_MAX];
static size_t child_count;
static char runtime_path[PATH_MAX];
static char profile_arg[PATH_MAX];
extern char **environ;

static id send_id(id obj, const char *selector)
{ return ((id (*)(id, SEL))objc_msgSend)(obj, sel_registerName(selector)); }
static void send_void(id obj, const char *selector)
{ ((void (*)(id, SEL))objc_msgSend)(obj, sel_registerName(selector)); }
static void send_object(id obj, const char *selector, id value)
{ ((void (*)(id, SEL, id))objc_msgSend)(obj, sel_registerName(selector), value); }
static id text(const char *s)
{
    return ((id (*)(id, SEL, const char *))objc_msgSend)(
        (id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), s);
}
static void alert(const char *detail)
{
    id box = send_id((id)objc_getClass("NSAlert"), "alloc");
    box = send_id(box, "init");
    send_object(box, "setMessageText:", text("Z23 could not open the app"));
    send_object(box, "setInformativeText:", text(detail));
    (void)((long (*)(id, SEL))objc_msgSend)(box, sel_registerName("runModal"));
    send_void(box, "release");
}
static bool path_parent(char *path)
{
    char *slash = strrchr(path, '/');
    if (!slash || slash == path) return false;
    *slash = 0;
    return true;
}
static bool launcher_paths(void)
{
    char original[PATH_MAX], resolved[PATH_MAX];
    uint32_t size = sizeof(original);
    if (_NSGetExecutablePath(original, &size) != 0 || !realpath(original, resolved)) return false;
    /* Executable -> MacOS -> Contents -> bundle -> generation. */
    for (unsigned i = 0; i < 4; ++i)
        if (!path_parent(resolved)) return false;
    int n = snprintf(runtime_path, sizeof(runtime_path), "%s/z23", resolved);
    if (n < 0 || (size_t)n >= sizeof(runtime_path)) return false;
    struct stat st;
    if (stat(runtime_path, &st) != 0 || !S_ISREG(st.st_mode) || access(runtime_path, X_OK) != 0) return false;
    const char *home = getenv("HOME");
    if (!home || home[0] != '/') return false;
    n = snprintf(profile_arg, sizeof(profile_arg), "--datadir=%s/.local/share/z23-app-data", home);
    return n >= 0 && (size_t)n < sizeof(profile_arg);
}
static bool spawn_app(const char *file)
{
    if (child_count >= Z23_APP_CHILD_MAX) { alert("Too many app windows are already open."); return false; }
    char file_arg[PATH_MAX + 8u];
    if (file) {
        if (file[0] != '/') { alert("The shared file path is not absolute."); return false; }
        int n = snprintf(file_arg, sizeof(file_arg), "--file=%s", file);
        if (n < 0 || (size_t)n >= sizeof(file_arg)) { alert("The shared file path is too long."); return false; }
    }
    char *receive[] = {runtime_path, "app", "receive", "--preview", profile_arg, file_arg, NULL};
    char *library[] = {runtime_path, "app", "library", profile_arg, NULL};
    pid_t pid;
    int error = posix_spawn(&pid, runtime_path, NULL, NULL, file ? receive : library, environ);
    if (error) { alert(strerror(error)); return false; }
    children[child_count++] = pid;
    return true;
}
static const char *file_path(id path)
{ return path ? ((const char *(*)(id, SEL))objc_msgSend)(path, sel_registerName("UTF8String")) : NULL; }
static BOOL open_file(id self, SEL selector, id app, id path)
{
    (void)self; (void)selector; (void)app;
    const char *file = file_path(path);
    if (!file) { alert("The shared file path could not be read."); return NO; }
    return spawn_app(file) ? YES : NO;
}
static void open_files(id self, SEL selector, id app, id paths)
{
    (void)self; (void)selector;
    unsigned long count = ((unsigned long (*)(id, SEL))objc_msgSend)(paths, sel_registerName("count"));
    bool ok = count > 0;
    for (unsigned long i = 0; i < count; ++i) {
        id path = ((id (*)(id, SEL, unsigned long))objc_msgSend)(paths, sel_registerName("objectAtIndex:"), i);
        const char *file = file_path(path);
        if (!file) { alert("A shared file path could not be read."); ok = false; continue; }
        if (!spawn_app(file)) ok = false;
    }
    ((void (*)(id, SEL, unsigned long))objc_msgSend)(app, sel_registerName("replyToOpenOrPrint:"), ok ? 0ul : 1ul);
}
static BOOL open_untitled(id self, SEL selector, id app)
{ (void)self; (void)selector; (void)app; return spawn_app(NULL) ? YES : NO; }
static void reap_children(id self, SEL selector, id timer)
{
    (void)self; (void)selector; (void)timer;
    for (size_t i = 0; i < child_count;) {
        int status;
        pid_t done = waitpid(children[i], &status, WNOHANG);
        if (done == 0 || (done < 0 && errno == EINTR)) { ++i; continue; }
        if (done < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            alert("The Z23 app window did not finish successfully.");
        children[i] = children[--child_count];
    }
    if (!child_count) {
        id app = send_id((id)objc_getClass("NSApplication"), "sharedApplication");
        send_object(app, "terminate:", nil);
    }
}
static void finished(id self, SEL selector, id notification)
{
    (void)selector; (void)notification;
    ((id (*)(id, SEL, double, id, SEL, id, BOOL))objc_msgSend)(
        (id)objc_getClass("NSTimer"), sel_registerName("scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:"),
        0.25, self, sel_registerName("z23Reap:"), nil, YES);
}
static bool add_method(Class cls, const char *selector, IMP method, const char *types)
{ return class_addMethod(cls, sel_registerName(selector), method, types) != 0; }
int main(int argc, char **argv)
{
    if (argc > 1) return z23_app_macos_install(argc, argv);
    id pool = send_id(send_id((id)objc_getClass("NSAutoreleasePool"), "alloc"), "init");
    id app = send_id((id)objc_getClass("NSApplication"), "sharedApplication");
    if (!launcher_paths()) {
        alert("The installed Z23 runtime or home directory is unavailable.");
        send_void(pool, "release"); return 1;
    }
    Class cls = objc_allocateClassPair(objc_getClass("NSObject"), "Z23AppsDelegate", 0);
    if (!cls || !add_method(cls, "application:openFile:", (IMP)open_file, "B@:@@") ||
        !add_method(cls, "application:openFiles:", (IMP)open_files, "v@:@@") ||
        !add_method(cls, "applicationOpenUntitledFile:", (IMP)open_untitled, "B@:@") ||
        !add_method(cls, "applicationDidFinishLaunching:", (IMP)finished, "v@:@") ||
        !add_method(cls, "z23Reap:", (IMP)reap_children, "v@:@")) {
        if (cls) objc_disposeClassPair(cls);
        alert("The Z23 application could not initialize.");
        send_void(pool, "release"); return 1;
    }
    objc_registerClassPair(cls);
    id delegate = send_id((id)cls, "new");
    send_object(app, "setDelegate:", delegate);
    send_void(app, "run");
    send_object(app, "setDelegate:", nil);
    send_void(delegate, "release");
    send_void(pool, "release");
    return 0;
}
