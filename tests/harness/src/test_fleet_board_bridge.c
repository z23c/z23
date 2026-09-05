/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "test/test_core.h"
#include "json/json.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *bridge_bin(void)
{
    const char *p=getenv("ZCL_FLEET_BOARD_BRIDGE_BIN");
    return p&&*p?p:"build/bin/fleet-board-bridge";
}
static int run(const char *dir,const char *const args[],char *out,size_t cap,
               const char *agent,const char *ref)
{
    int pipefd[2];if(pipe(pipefd)!=0)return -1;pid_t pid=fork();if(pid<0){close(pipefd[0]);close(pipefd[1]);return -1;}
    if(pid==0){(void)dup2(pipefd[1],STDOUT_FILENO);close(pipefd[0]);close(pipefd[1]);
        if(agent)setenv("BOARD_AGENT",agent,1);else unsetenv("BOARD_AGENT");
        if(ref)setenv("BOARD_REF",ref,1);else unsetenv("BOARD_REF");
        char *av[24];size_t n=0;av[n++]=(char*)bridge_bin();av[n++]="--board-dir";av[n++]=(char*)dir;
        for (size_t i = 0; args[i] && n + 1 < 24; i++)
            av[n++] = (char *)args[i];
        av[n] = NULL;
        execv(av[0], av);
        _exit(127);
    }
    close(pipefd[1]);size_t used=0;while(used+1<cap){ssize_t n=read(pipefd[0],out+used,cap-1-used);if(n<0)continue;if(!n)break;used+=(size_t)n;}out[used]=0;close(pipefd[0]);int status=0;
    return waitpid(pid,&status,0)==pid&&WIFEXITED(status)?WEXITSTATUS(status):-1;
}
static int run_with_temp_collisions(const char *dir,const char *peer,
                                    const char *incoming,char *out,size_t cap,
                                    pid_t *child_out)
{
    int pipefd[2];if(pipe(pipefd)!=0)return -1;
    pid_t pid=fork();if(pid<0){close(pipefd[0]);close(pipefd[1]);return -1;}
    if(pid==0){
        (void)dup2(pipefd[1],STDOUT_FILENO);close(pipefd[0]);close(pipefd[1]);
        for(unsigned attempt=0;attempt<64;attempt++){
            char path[PATH_MAX];
            if(snprintf(path,sizeof(path),"%s/.%s.merge.%ld.%u",dir,peer,
                        (long)getpid(),attempt)>=(int)sizeof(path))_exit(126);
            int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
            if(fd<0||write(fd,"sentinel",8)!=8||close(fd)!=0)_exit(126);
        }
        char *av[]={(char*)bridge_bin(),"--board-dir",(char*)dir,"merge",
                    (char*)peer,(char*)incoming,NULL};
        execv(av[0],av);_exit(127);
    }
    *child_out=pid;close(pipefd[1]);size_t used=0;
    while(used+1<cap){ssize_t n=read(pipefd[0],out+used,cap-1-used);if(n<0&&errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;}
    out[used]=0;close(pipefd[0]);int status=0;
    return waitpid(pid,&status,0)==pid&&WIFEXITED(status)?WEXITSTATUS(status):-1;
}
static bool put(const char *dir,const char *name,const char *text)
{
    char p[PATH_MAX];if(snprintf(p,sizeof(p),"%s/%s",dir,name)>=(int)sizeof(p))return false;
    int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(fd<0)return false;size_t n=strlen(text);bool ok=write(fd,text,n)==(ssize_t)n&&close(fd)==0;return ok;
}
static bool get(const char *dir,const char *name,char *out,size_t cap)
{
    char p[PATH_MAX];if(!cap||snprintf(p,sizeof(p),"%s/%s",dir,name)>=(int)sizeof(p))return false;
    int fd=open(p,O_RDONLY|O_CLOEXEC);if(fd<0)return false;size_t used=0;bool ok=true;
    while(used+1<cap){ssize_t n=read(fd,out+used,cap-1-used);if(n<0&&errno==EINTR)continue;if(n<0){ok=false;break;}if(!n)break;used+=(size_t)n;}
    char extra;ssize_t more=ok?read(fd,&extra,1):-1;if(more!=0)ok=false;out[used]=0;if(close(fd)!=0)ok=false;return ok;
}
static bool put_fill(const char *dir,const char *name,size_t count)
{
    char p[PATH_MAX];if(snprintf(p,sizeof(p),"%s/%s",dir,name)>=(int)sizeof(p))return false;
    int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(fd<0)return false;
    char block[1024];memset(block,'x',sizeof(block));bool ok=true;
    while(ok&&count){size_t n=count<sizeof(block)?count:sizeof(block);ssize_t w=write(fd,block,n);if(w<0&&errno==EINTR)continue;if(w<=0)ok=false;else count-=(size_t)w;}
    if(ok)ok=write(fd,"\n",1)==1;
    if(close(fd)!=0)ok=false;
    return ok;
}
static bool host_name(char out[128])
{
    if(gethostname(out,128)!=0)return false;
    out[127]=0;char *dot=strchr(out,'.');if(dot)*dot=0;return out[0]!=0;
}
static bool cleanup(const char *root)
{
    DIR *d=opendir(root);if(!d)return false;bool ok=true;struct dirent *e;while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;char p[PATH_MAX];if(snprintf(p,sizeof(p),"%s/%s",root,e->d_name)>=(int)sizeof(p)||unlink(p)!=0)ok=false;}if(closedir(d)!=0)ok=false;return rmdir(root)==0&&ok;
}
#define ROW(ts,id,host,kind,ref,text) "{\"ts\":\"" ts "\",\"id\":\"" id "\",\"host\":\"" host "\",\"agent\":\"worker\",\"kind\":\"" kind "\",\"ref\":\"" ref "\",\"text\":\"" text "\"}\n"
static size_t lines(const char *s){size_t n=0;for(;*s;s++)if(*s=='\n')n++;return n;}

static int test_fleet_board_bridge_basics(void)
{
    int failures=0;
    TEST("fleet board bridge: checked JSON, ordering, open refs, and writers") {
        char root[]="/tmp/zcl-fleet-board-bridge.XXXXXX",out[65536];ASSERT(mkdtemp(root)!=NULL);
        const char *post[]={"--json","post","note","quoted \"word\" and line\nbreak",NULL};
        ASSERT(run(root,post,out,sizeof(out),"test-agent",NULL)==0);ASSERT(strlen(out)>1);
        const char *list_json[]={"--json","list",NULL};ASSERT(run(root,list_json,out,sizeof(out),NULL,NULL)==0);
        struct json_value parsed;json_init(&parsed);char *nl=strchr(out,'\n');ASSERT(nl!=NULL);*nl=0;
        ASSERT(json_read(&parsed,out,strlen(out)));ASSERT_STR_EQ(json_get_str(json_get(&parsed,"text")),"quoted \"word\" and line\nbreak");json_free(&parsed);

        ASSERT(put(root,"ordered.jsonl",ROW("2026-09-05T00:00:01Z","one","alpha","need","","one") ROW("2026-09-05T00:00:02Z","two","alpha","need","","two") ROW("2026-09-05T00:00:03Z","three","alpha","need","","three")));
        const char *latest[]={"list","--host","alpha","-n","2",NULL};ASSERT(run(root,latest,out,sizeof(out),NULL,NULL)==0);
        ASSERT(strstr(out,"one")==NULL);char *two=strstr(out,"two"),*three=strstr(out,"three");ASSERT(two&&three&&two<three);
        const char *badn[]={"list","-n","2x",NULL};ASSERT(run(root,badn,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(put(root,"legacy.jsonl",
            "{\"ts\":\"2026-09-05T00:00:04Z\",\"id\":\"legacy-cost\","
            "\"host\":\"alpha\",\"agent\":\"agent with spaces\","
            "\"kind\":\"cost\",\"ref\":\"scope/with/slashes\","
            "\"text\":\"legacy metric\"}\n"));
        const char *legacy[]={"list","--kind","cost",NULL};
        ASSERT(run(root,legacy,out,sizeof(out),NULL,NULL)==0);
        ASSERT(strstr(out,"legacy metric")!=NULL);

        ASSERT(put(root,"open-a.jsonl",ROW("2026-09-05T01:00:00Z","need-a","alpha","need","","claimed need") ROW("2026-09-05T01:00:01Z","problem-a","alpha","problem","","still open") ROW("2026-09-05T01:00:02Z","note-a","alpha","note","","ordinary note")));
        ASSERT(put(root,"open-b.jsonl",ROW("2026-09-05T01:00:03Z","claim-b","beta","claim","need-a","cross host claim")));
        const char *open[]={"list","--open","--host","alpha",NULL};ASSERT(run(root,open,out,sizeof(out),NULL,NULL)==0);
        ASSERT(strstr(out,"still open")&& !strstr(out,"claimed need")&&!strstr(out,"ordinary note"));

        pid_t kids[8];for(size_t i=0;i<8;i++){kids[i]=fork();ASSERT(kids[i]>=0);if(kids[i]==0){char tmp[256];const char *p[]={"post","note","parallel",NULL};_exit(run(root,p,tmp,sizeof(tmp),"parallel-agent",NULL));}}
        for(size_t i=0;i<8;i++){int st=0;ASSERT(waitpid(kids[i],&st,0)==kids[i]);ASSERT(WIFEXITED(st)&&WEXITSTATUS(st)==0);}
        const char *parallel[]={"list","--kind","note","-n","20",NULL};ASSERT(run(root,parallel,out,sizeof(out),NULL,NULL)==0);ASSERT(lines(out)>=9);

        ASSERT(put(root,"bad.jsonl","{not-json}\n"));ASSERT(run(root,list_json,out,sizeof(out),NULL,NULL)!=0);char p[PATH_MAX];snprintf(p,sizeof(p),"%s/bad.jsonl",root);ASSERT(unlink(p)==0);
        snprintf(p,sizeof(p),"%s/link.jsonl",root);ASSERT(symlink("/dev/null",p)==0);ASSERT(run(root,list_json,out,sizeof(out),NULL,NULL)!=0);ASSERT(unlink(p)==0);
        ASSERT(cleanup(root));PASS();
    } _test_next:;
    return failures;
}
static int test_fleet_board_bridge_merge(void)
{
    int failures=0;
    TEST("fleet board bridge: snapshot merge is monotonic, idempotent, and fail closed") {
        char root[]="/tmp/zcl-fleet-board-merge.XXXXXX",out[65536],before[65536],after[65536];
        ASSERT(mkdtemp(root)!=NULL);
        ASSERT(put(root,"beta.jsonl",
            ROW("2026-09-05T02:00:00Z","beta-old","beta","note","","old")
            ROW("2026-09-05T02:00:02Z","beta-new","beta","status","","newer local copy")));
        ASSERT(put(root,"stale.snapshot",
            ROW("2026-09-05T02:00:00Z","beta-old","beta","note","","old")));
        const char *merge_stale[]={"merge","beta","",NULL};
        char incoming[PATH_MAX];ASSERT(snprintf(incoming,sizeof(incoming),"%s/stale.snapshot",root)<(int)sizeof(incoming));
        merge_stale[2]=incoming;
        ASSERT(run(root,merge_stale,out,sizeof(out),NULL,NULL)==0);
        ASSERT(get(root,"beta.jsonl",before,sizeof(before)));ASSERT(lines(before)==2);
        ASSERT(strstr(before,"newer local copy")!=NULL);
        ASSERT(run(root,merge_stale,out,sizeof(out),NULL,NULL)==0);
        ASSERT(get(root,"beta.jsonl",after,sizeof(after)));ASSERT_STR_EQ(after,before);

        ASSERT(put(root,"conflict.snapshot",
            ROW("2026-09-05T02:00:00Z","beta-old","beta","note","","changed")));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/conflict.snapshot",root)<(int)sizeof(incoming));
        const char *merge_conflict[]={"merge","beta",incoming,NULL};
        ASSERT(run(root,merge_conflict,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(get(root,"beta.jsonl",after,sizeof(after)));ASSERT_STR_EQ(after,before);
        ASSERT(put(root,"cross.snapshot",
            ROW("2026-09-05T02:00:03Z","wrong-host","alpha","note","","wrong")));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/cross.snapshot",root)<(int)sizeof(incoming));
        const char *merge_cross[]={"merge","beta",incoming,NULL};
        ASSERT(run(root,merge_cross,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(get(root,"beta.jsonl",after,sizeof(after)));ASSERT_STR_EQ(after,before);
        ASSERT(put(root,"malformed.snapshot","{not-json}\n"));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/malformed.snapshot",root)<(int)sizeof(incoming));
        const char *merge_bad[]={"merge","beta",incoming,NULL};
        ASSERT(run(root,merge_bad,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(get(root,"beta.jsonl",after,sizeof(after)));ASSERT_STR_EQ(after,before);
        char linked[PATH_MAX];ASSERT(snprintf(linked,sizeof(linked),"%s/linked.snapshot",root)<(int)sizeof(linked));
        ASSERT(symlink("stale.snapshot",linked)==0);
        const char *merge_link[]={"merge","beta",linked,NULL};
        ASSERT(run(root,merge_link,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(get(root,"beta.jsonl",after,sizeof(after)));ASSERT_STR_EQ(after,before);

        char own[128],own_row[1024];ASSERT(host_name(own));
        ASSERT(snprintf(own_row,sizeof(own_row),
            "{\"ts\":\"2026-09-05T02:00:04Z\",\"id\":\"own-id\",\"host\":\"%s\",\"agent\":\"worker\",\"kind\":\"note\",\"ref\":\"\",\"text\":\"own\"}\n",own)<(int)sizeof(own_row));
        ASSERT(put(root,"own.snapshot",own_row));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/own.snapshot",root)<(int)sizeof(incoming));
        const char *merge_own[]={"merge",own,incoming,NULL};
        ASSERT(run(root,merge_own,out,sizeof(out),NULL,NULL)!=0);

        ASSERT(put(root,"gamma.snapshot",
            ROW("2026-09-05T02:00:05Z","gamma-id","gamma","offer","","shared")));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/gamma.snapshot",root)<(int)sizeof(incoming));
        pid_t kids[8];
        for(size_t i=0;i<8;i++){kids[i]=fork();ASSERT(kids[i]>=0);if(kids[i]==0){char tmp[256];if(i<4){const char *a[]={"merge","gamma",incoming,NULL};_exit(run(root,a,tmp,sizeof(tmp),NULL,NULL));}const char *a[]={"post","note","during merge",NULL};_exit(run(root,a,tmp,sizeof(tmp),"merge-test",NULL));}}
        for(size_t i=0;i<8;i++){int st=0;ASSERT(waitpid(kids[i],&st,0)==kids[i]);ASSERT(WIFEXITED(st)&&WEXITSTATUS(st)==0);}
        ASSERT(get(root,"gamma.jsonl",after,sizeof(after)));ASSERT(lines(after)==1);
        const char *list_notes[]={"list","--kind","note","-n","20",NULL};
        ASSERT(run(root,list_notes,out,sizeof(out),NULL,NULL)==0);ASSERT(lines(out)>=5);
        ASSERT(cleanup(root));PASS();
    } _test_next:;
    return failures;
}
static int test_fleet_board_bridge_merge_bounds(void)
{
    int failures=0;
    TEST("fleet board bridge: snapshot merge preserves bounds and target type") {
        char root[]="/tmp/zcl-fleet-board-merge-bounds.XXXXXX",out[1024],incoming[PATH_MAX],target[PATH_MAX];
        ASSERT(mkdtemp(root)!=NULL);ASSERT(put_fill(root,"large.snapshot",32769));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/large.snapshot",root)<(int)sizeof(incoming));
        const char *merge_large[]={"merge","delta",incoming,NULL};
        ASSERT(run(root,merge_large,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/pipe.snapshot",root)<(int)sizeof(incoming));
        ASSERT(mkfifo(incoming,0600)==0);
        const char *merge_fifo[]={"merge","delta",incoming,NULL};
        ASSERT(run(root,merge_fifo,out,sizeof(out),NULL,NULL)!=0);
        ASSERT(put(root,"valid.snapshot",ROW("2026-09-05T03:00:00Z","delta-id","delta","note","","valid")));
        ASSERT(snprintf(incoming,sizeof(incoming),"%s/valid.snapshot",root)<(int)sizeof(incoming));
        pid_t collision_pid=0;
        ASSERT(run_with_temp_collisions(root,"delta",incoming,out,sizeof(out),&collision_pid)!=0);
        for(unsigned attempt=0;attempt<64;attempt++){
            char name[192],contents[32];
            ASSERT(snprintf(name,sizeof(name),".delta.merge.%ld.%u",
                            (long)collision_pid,attempt)<(int)sizeof(name));
            ASSERT(get(root,name,contents,sizeof(contents)));
            ASSERT_STR_EQ(contents,"sentinel");
        }
        ASSERT(snprintf(target,sizeof(target),"%s/delta.jsonl",root)<(int)sizeof(target));
        ASSERT(symlink("/dev/null",target)==0);
        const char *merge_target[]={"merge","delta",incoming,NULL};
        ASSERT(run(root,merge_target,out,sizeof(out),NULL,NULL)!=0);
        struct stat st;ASSERT(lstat(target,&st)==0&&S_ISLNK(st.st_mode));
        ASSERT(cleanup(root));PASS();
    } _test_next:;
    return failures;
}
static int test_fleet_board_bridge_post_file_bound(void)
{
    int failures=0;
    TEST("fleet board bridge: post preserves file cap and existing local projection") {
        char root[]="/tmp/zcl-fleet-board-post-bound.XXXXXX",out[1024];
        char own[128],local[160],path[PATH_MAX];
        ASSERT(mkdtemp(root)!=NULL);ASSERT(host_name(own));
        ASSERT(snprintf(local,sizeof(local),"%s.jsonl",own)<(int)sizeof(local));
        for(unsigned i=0;i<256;i++) {
            char name[160];
            ASSERT(snprintf(name,sizeof(name),"bound-%u.jsonl",i)<(int)sizeof(name));
            ASSERT(strcmp(name,local)!=0);ASSERT(put(root,name,""));
        }
        const char *post[]={"post","note","bounded append",NULL};
        ASSERT(run(root,post,out,sizeof(out),"bound-test",NULL)!=0);
        ASSERT(snprintf(path,sizeof(path),"%s/%s",root,local)<(int)sizeof(path));
        struct stat st;ASSERT(lstat(path,&st)!=0&&errno==ENOENT);
        ASSERT(snprintf(path,sizeof(path),"%s/bound-0.jsonl",root)<(int)sizeof(path));
        ASSERT(unlink(path)==0);
        ASSERT(run(root,post,out,sizeof(out),"bound-test",NULL)==0);
        ASSERT(run(root,post,out,sizeof(out),"bound-test",NULL)==0);
        ASSERT(get(root,local,out,sizeof(out)));ASSERT(lines(out)==2);
        ASSERT(cleanup(root));PASS();
    } _test_next:;
    return failures;
}
int test_fleet_board_bridge(void)
{
    return test_fleet_board_bridge_basics()+test_fleet_board_bridge_merge()+
           test_fleet_board_bridge_merge_bounds()+test_fleet_board_bridge_post_file_bound();
}
