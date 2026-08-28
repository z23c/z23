#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
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

int main(void)
{
    char root[1024], first[1200], second[1200];
#if defined(_WIN32)
    char base[MAX_PATH]; DWORD n=GetTempPathA(sizeof(base),base);
    if(!n||n>=sizeof(base)) return 1;
    if(snprintf(root,sizeof(root),"%sz23-watch-%lu",base,(unsigned long)GetCurrentProcessId())<=0 ||
       !CreateDirectoryA(root,NULL)) return 1;
#else
    strcpy(root,"/tmp/z23-watch-XXXXXX"); if(!mkdtemp(root)) return 1;
#endif
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
