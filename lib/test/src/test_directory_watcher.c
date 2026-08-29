/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves platform_directory_watcher_* observes real change on a
 * directory it opened: the stop predicate is honoured, a file created inside
 * the root reports CHANGED, and a rename followed by an unlink reports
 * CHANGED again.
 *
 * Rehomed from lib/platform/tests/test_directory_watcher.c, which NOTHING
 * read: it was in no windows_acceptance.mk row, no Makefile rule and not in
 * the files list of lib/platform/zcode-package.json. As a registered group it
 * executes on every suite run, and it is the only thing that drives the POSIX
 * (inotify) arm of lib/platform/src/directory_watcher.c -- every production
 * caller of that module sits behind #if defined(_WIN32).
 *
 * Every assertion is the original verbatim, in the original order. The single
 * change is where the watched root comes from: the standalone program built
 * its own directory with mkdtemp("/tmp/...") (or GetTempPathA on Windows)
 * because it had no harness; here test_make_tmpdir() supplies the suite's
 * own scratch root under test-tmp/ so parallel groups cannot collide and the
 * tree is cleaned up on failure. The final rmdir/RemoveDirectory assertion is
 * kept: it still proves the watcher released the directory and left nothing
 * behind. */
#include "test/test_core.h"

#include "platform/directory_watcher.h"

#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#endif

static bool stop_now(void *opaque) { (void)opaque; return true; }

static int directory_watcher_probe(const char *root)
{
    char first[1200], second[1200];
    (void)snprintf(first,sizeof(first),"%s/%s",root,"edit.tmp");
    (void)snprintf(second,sizeof(second),"%s/%s",root,"renamed.tmp");
    struct platform_directory_watcher watcher; platform_directory_watcher_init(&watcher);
    if(!platform_directory_watcher_open(&watcher,root) ||
       platform_directory_watcher_wait(&watcher,10,stop_now,NULL)!=PLATFORM_DIRECTORY_WATCH_STOPPED) return 1;
#if defined(_WIN32)
    HANDLE f=CreateFileA(first,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE) return 1; DWORD wrote=0; (void)WriteFile(f,"x",1,&wrote,NULL); CloseHandle(f);
#else
    int f=open(first,O_CREAT|O_EXCL|O_WRONLY,0600); if(f<0) return 1; (void)write(f,"x",1); close(f);
#endif
    if(platform_directory_watcher_wait(&watcher,2000,NULL,NULL)!=PLATFORM_DIRECTORY_WATCH_CHANGED) return 1;
#if defined(_WIN32)
    if(!MoveFileA(first,second)||!DeleteFileA(second)) return 1;
#else
    if(rename(first,second)||unlink(second)) return 1;
#endif
    if(platform_directory_watcher_wait(&watcher,2000,NULL,NULL)!=PLATFORM_DIRECTORY_WATCH_CHANGED) return 1;
    platform_directory_watcher_close(&watcher);
#if defined(_WIN32)
    if(!RemoveDirectoryA(root)) return 1;
#else
    if(rmdir(root)) return 1;
#endif
    return 0;
}

int test_directory_watcher(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "directory_watcher", "recursive");
    printf("directory_watcher: stop predicate honoured, create and "
           "rename+unlink each report CHANGED... ");
    if (directory_watcher_probe(dir) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    (void)test_rm_rf_recursive(dir);
    return failures;
}
