/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "base/safe_alloc.h"
#include "json/json.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PATH_CAP 1024u
#define TEXT_CAP (16u * 1024u)
#define LINE_CAP (32u * 1024u)
#define FILE_CAP 256u
#define BYTE_CAP (64u * 1024u * 1024u)
#define ROW_CAP 50000u

struct row {
    char ts[32], id[128], host[128], agent[256], kind[16], ref[128];
    char *text;
};
struct rows { struct row *v; size_t n, cap; };

static void error(const char *s) { fprintf(stderr, "fleet-board-bridge: %s\n", s); }
static bool copy(char *d, size_t cap, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (!s || n >= cap) return false;
    memcpy(d, s, n + 1); return true;
}
static bool atom(const char *s, size_t cap, bool empty)
{
    size_t n = s ? strlen(s) : 0;
    if ((!empty && !n) || n >= cap) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return false;
    }
    return true;
}
static bool timestamp(const char *s)
{
    if (!s || strlen(s) != 20) return false;
    for (size_t i = 0; i < 20; i++) {
        char want = i == 4 || i == 7 ? '-' : i == 10 ? 'T' :
                    i == 13 || i == 16 ? ':' : i == 19 ? 'Z' : 0;
        if (want ? s[i] != want : (s[i] < '0' || s[i] > '9')) return false;
    }
    return true;
}
static bool kind_ok(const char *s)
{
    static const char *const kinds[] = {
        "problem", "need", "offer", "claim", "result", "note", "directive",
        "cost", "packet", "status"
    };
    for (size_t i = 0; s && i < sizeof(kinds) / sizeof(kinds[0]); i++)
        if (!strcmp(s, kinds[i])) return true;
    return false;
}
static bool lock_fd(int fd, short type)
{
    struct flock l = {.l_type=type, .l_whence=SEEK_SET};
    while (fcntl(fd, F_SETLKW, &l) != 0) if (errno != EINTR) return false;
    return true;
}
static void rows_free(struct rows *r)
{
    for (size_t i = 0; i < r->n; i++) free(r->v[i].text);
    free(r->v); memset(r, 0, sizeof(*r));
}
static bool rows_add(struct rows *r, struct row *x)
{
    if (r->n == ROW_CAP) return false;
    if (r->n == r->cap) {
        size_t cap = r->cap ? r->cap * 2 : 128;
        if (cap > ROW_CAP) cap = ROW_CAP;
        struct row *p = zcl_realloc(r->v, cap * sizeof(*p), "board_rows");
        if (!p) return false;
        r->v = p; r->cap = cap;
    }
    r->v[r->n++] = *x; x->text = NULL; return true;
}
static const char *jstr(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}
static bool parse_row(char *line, size_t n, struct row *r, const char **reason)
{
    struct json_value o; json_init(&o);
    bool ok = json_read(&o, line, n) && o.type == JSON_OBJ;
    const char *ts = ok ? jstr(&o,"ts") : NULL, *id = ok ? jstr(&o,"id") : NULL;
    const char *host = ok ? jstr(&o,"host") : NULL, *agent = ok ? jstr(&o,"agent") : NULL;
    const char *kind = ok ? jstr(&o,"kind") : NULL, *ref = ok ? jstr(&o,"ref") : NULL;
    const char *text = ok ? jstr(&o,"text") : NULL;
    if (!ok) *reason = "invalid JSON object";
    else if (!timestamp(ts)) *reason = "invalid timestamp";
    else if (!atom(id,sizeof(r->id),false)) *reason = "invalid id";
    else if (!atom(host,sizeof(r->host),false)) *reason = "invalid host";
    else if (!agent || !agent[0] || strlen(agent) >= sizeof(r->agent))
        *reason = "missing or oversized agent";
    else if (!kind_ok(kind)) *reason = "unknown kind";
    else if (!ref || strlen(ref) >= sizeof(r->ref))
        *reason = "missing or oversized ref";
    else if (!text || strlen(text) > TEXT_CAP)
        *reason = "missing or oversized text";
    else *reason = NULL;
    ok = *reason == NULL;
    if (ok) ok = copy(r->ts,sizeof(r->ts),ts) && copy(r->id,sizeof(r->id),id) &&
        copy(r->host,sizeof(r->host),host) && copy(r->agent,sizeof(r->agent),agent) &&
        copy(r->kind,sizeof(r->kind),kind) && copy(r->ref,sizeof(r->ref),ref);
    if (ok) { r->text = zcl_strdup(text,"board_text"); ok = r->text != NULL; }
    json_free(&o); return ok;
}
static bool load_open_file(int fd, const char *name, struct rows *r,
                           uint64_t max_bytes,uint64_t *bytes_out)
{
    struct stat before, after;
    bool ok=fstat(fd,&before)==0&&S_ISREG(before.st_mode)&&before.st_size>=0&&
            (uint64_t)before.st_size<=max_bytes;
    if (!ok) {
        fprintf(stderr,"fleet-board-bridge: %s: not a bounded regular file\n",name);
        close(fd);
        return false;
    }
    if (!lock_fd(fd,F_RDLCK)) {
        fprintf(stderr,"fleet-board-bridge: %s: cannot acquire read lock\n",name);
        close(fd);
        return false;
    }
    FILE *f=fdopen(fd,"r");
    if (!f) {
        fprintf(stderr,"fleet-board-bridge: %s: not a bounded regular file\n",name);
        close(fd);
        return false;
    }
    char line[LINE_CAP+2]; uint64_t readn=0; size_t line_number=0;
    while (ok && fgets(line,sizeof(line),f)) {
        line_number++;
        size_t n=strlen(line); readn+=n;
        if (!n || line[n-1]!='\n' || n-1>LINE_CAP || readn>(uint64_t)before.st_size) {
            fprintf(stderr,"fleet-board-bridge: %s:%zu: unterminated, oversized, or changing row\n",name,line_number);
            ok=false;break;
        }
        line[n-1]=0; struct row x={0};
        const char *reason = NULL;
        if (!parse_row(line,n-1,&x,&reason) || !rows_add(r,&x)) {
            fprintf(stderr,"fleet-board-bridge: %s:%zu: %s\n",name,line_number,
                    reason ? reason : "row capacity or allocation failure");
            free(x.text);
            ok=false;
            break;
        }
    }
    if (ferror(f) || (ok && (fstat(fd,&after)!=0 || after.st_size!=before.st_size ||
                             readn!=(uint64_t)before.st_size))) {
        fprintf(stderr,"fleet-board-bridge: %s: read error or file changed during snapshot\n",name);
        ok=false;
    }
    if (fclose(f)!=0) ok=false;
    if (ok) *bytes_out = readn;
    return ok;
}
static bool load_file(int dirfd, const char *name, struct rows *r, uint64_t *total)
{
    if (*total>BYTE_CAP) return false;
    int fd = openat(dirfd,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr,"fleet-board-bridge: %s: cannot open safely: %s\n",
                name,strerror(errno));
        return false;
    }
    uint64_t bytes = 0;
    if (!load_open_file(fd,name,r,BYTE_CAP-*total,&bytes)) return false;
    *total += bytes;
    return true;
}
static int row_cmp(const void *a, const void *b)
{
    const struct row *x=a,*y=b; int c=strcmp(x->ts,y->ts); return c?c:strcmp(x->id,y->id);
}
static bool load_all(int dirfd, struct rows *r, uint64_t *bytes_out,
                     size_t *files_out)
{
    int dfd=dup(dirfd); DIR *d=dfd>=0?fdopendir(dfd):NULL;
    if (!d) {if(dfd>=0)close(dfd);return false;}
    uint64_t total=0; size_t files=0; bool ok=true; struct dirent *e;
    while (ok) {
        errno=0;e=readdir(d);
        if(!e){if(errno)ok=false;break;}
        size_t n=strlen(e->d_name);
        if (n<7 || strcmp(e->d_name+n-6,".jsonl")) continue;
        if (++files>FILE_CAP || !load_file(dirfd,e->d_name,r,&total)) ok=false;
    }
    if (closedir(d)!=0) ok=false;
    if (ok) {
        qsort(r->v,r->n,sizeof(*r->v),row_cmp);
        *bytes_out=total;
        if (files_out) *files_out=files;
    }
    return ok;
}
static int string_ptr_cmp(const void *left, const void *right)
{
    const char *const *a = left;
    const char *const *b = right;
    return strcmp(*a, *b);
}
static bool closed(char *const *refs, size_t ref_count, const char *id)
{
    return bsearch(&id, refs, ref_count, sizeof(*refs), string_ptr_cmp) != NULL;
}
static bool matches(char *const *refs,size_t ref_count,const struct row *r,
                    const char *kind,const char *host,bool open)
{
    if ((kind&&strcmp(kind,r->kind)) || (host&&strcmp(host,r->host))) return false;
    if (!open) return true;
    return (!strcmp(r->kind,"need") || !strcmp(r->kind,"problem")) &&
           !closed(refs,ref_count,r->id);
}
static bool emit(const struct row *r,bool json)
{
    if (!json) return printf("%s %s [%s] %s: %s\n",r->ts,r->host,r->kind,r->agent,r->text)>=0;
    struct json_value o; json_init(&o);json_set_object(&o);
    bool ok=json_push_kv_str(&o,"ts",r->ts)&&json_push_kv_str(&o,"id",r->id)&&
      json_push_kv_str(&o,"host",r->host)&&json_push_kv_str(&o,"agent",r->agent)&&
      json_push_kv_str(&o,"kind",r->kind)&&json_push_kv_str(&o,"ref",r->ref)&&
      json_push_kv_str(&o,"text",r->text);
    size_t n=ok?json_write(&o,NULL,0):0; char *buf=n<=LINE_CAP?zcl_malloc(n+1,"board_json"):NULL;
    if (!buf) ok=false;
    if(ok) ok=json_write(&o,buf,n+1)==n && fwrite(buf,1,n,stdout)==n && fputc('\n',stdout)!=EOF;
    free(buf);json_free(&o);return ok;
}
static bool write_all(int fd,const char *p,size_t n)
{
    while(n){ssize_t w=write(fd,p,n);if(w<0&&errno==EINTR)continue;if(w<=0)return false;p+=w;n-=(size_t)w;}return true;
}
static bool row_equal(const struct row *a, const struct row *b)
{
    return !strcmp(a->ts,b->ts) && !strcmp(a->id,b->id) &&
           !strcmp(a->host,b->host) && !strcmp(a->agent,b->agent) &&
           !strcmp(a->kind,b->kind) && !strcmp(a->ref,b->ref) &&
           !strcmp(a->text,b->text);
}
struct row_index { const struct row **v; size_t n; };
static int row_id_ptr_cmp(const void *left,const void *right)
{
    const struct row *const *a=left,*const *b=right;
    return strcmp((*a)->id,(*b)->id);
}
static bool row_index_build(const struct rows *rows,struct row_index *index)
{
    index->v=zcl_malloc((rows->n?rows->n:1)*sizeof(*index->v),"board_id_index");
    if(!index->v)return false;
    index->n=rows->n;
    for(size_t i=0;i<rows->n;i++)index->v[i]=&rows->v[i];
    qsort(index->v,index->n,sizeof(*index->v),row_id_ptr_cmp);
    for(size_t i=1;i<index->n;i++)
        if(!strcmp(index->v[i-1]->id,index->v[i]->id)&&
           !row_equal(index->v[i-1],index->v[i]))return false;
    return true;
}
static const struct row *row_index_find(const struct row_index *index,const char *id)
{
    size_t lo=0,hi=index->n;
    while(lo<hi){size_t mid=lo+(hi-lo)/2;int c=strcmp(index->v[mid]->id,id);
        if(c<0)lo=mid+1;else hi=mid;}
    return lo<index->n&&!strcmp(index->v[lo]->id,id)?index->v[lo]:NULL;
}
static bool row_clone_add(struct rows *rows, const struct row *src)
{
    struct row copy_row=*src;
    copy_row.text=zcl_strdup(src->text,"board_merge_text");
    if (!copy_row.text) return false;
    if (!rows_add(rows,&copy_row)) { free(copy_row.text); return false; }
    return true;
}
static char *encode_row(const struct row *r, size_t *len_out)
{
    struct json_value o;json_init(&o);json_set_object(&o);
    bool ok=json_push_kv_str(&o,"ts",r->ts)&&json_push_kv_str(&o,"id",r->id)&&
      json_push_kv_str(&o,"host",r->host)&&json_push_kv_str(&o,"agent",r->agent)&&
      json_push_kv_str(&o,"kind",r->kind)&&json_push_kv_str(&o,"ref",r->ref)&&
      json_push_kv_str(&o,"text",r->text);
    size_t n=ok?json_write(&o,NULL,0):0;
    char *buf=n&&n+1<=LINE_CAP?zcl_malloc(n+2,"board_merge_json"):NULL;
    if (buf) {
        ok=json_write(&o,buf,n+1)==n;
        buf[n]='\n';
    } else ok=false;
    json_free(&o);
    if (!ok) { free(buf); return NULL; }
    *len_out=n+1;
    return buf;
}
static bool local_host(char host[128])
{
    if (gethostname(host,128)!=0) return false;
    host[127]=0;
    char *dot=strchr(host,'.');
    if(dot)*dot=0;
    return atom(host,128,false);
}
static bool identity(char ts[32],char id[128],char host[128])
{
    struct timespec t;struct tm tm;char compact[17];
    if(!local_host(host)||clock_gettime(CLOCK_REALTIME,&t)!=0||!gmtime_r(&t.tv_sec,&tm))return false;
    if(strftime(ts,32,"%Y-%m-%dT%H:%M:%SZ",&tm)!=20||strftime(compact,17,"%Y%m%dT%H%M%S",&tm)!=15)return false;
    int n=snprintf(id,128,"%s-%s-%ld-%09ld",compact,host,(long)getpid(),t.tv_nsec);
    return n>0&&n<128;
}
static bool id_exists(const struct rows *rows, const char *id)
{
    for (size_t i = 0; i < rows->n; i++) if (!strcmp(rows->v[i].id,id)) return true;
    return false;
}
static bool target_state(int dirfd,const char *name,bool *exists);
static int post(int dirfd,const char *kind,const char *text,uint64_t board_bytes,
                size_t board_files,const struct rows *prior)
{
    if(!kind_ok(kind)||!text||!*text||strlen(text)>TEXT_CAP){error("invalid kind or text bound");return 1;}
    char ts[32],id[128],host[128],agent[256],ref[128]={0},name[160];
    const char *a=getenv("BOARD_AGENT");if(!a||!*a)a=getenv("SYSTEMD_UNIT");if(!a||!*a)a=getenv("USER");
    const char *rr=getenv("BOARD_REF");
    if(!identity(ts,id,host)||id_exists(prior,id)||!a||!*a||strlen(a)>=sizeof(agent)||!copy(agent,sizeof(agent),a)||
       (rr&&*rr&&(strlen(rr)>=sizeof(ref)||!copy(ref,sizeof(ref),rr)))){error("invalid local identity or BOARD_REF");return 1;}
    int nn=snprintf(name,sizeof(name),"%s.jsonl",host);if(nn<=0||(size_t)nn>=sizeof(name))return 1;
    bool exists=false;
    if(!target_state(dirfd,name,&exists)||board_files>FILE_CAP||
       (!exists&&board_files==FILE_CAP)){
        error("post refused: invalid local projection or board file capacity");
        return 1;
    }
    struct json_value o;json_init(&o);json_set_object(&o);
    bool ok=json_push_kv_str(&o,"ts",ts)&&json_push_kv_str(&o,"id",id)&&json_push_kv_str(&o,"host",host)&&
      json_push_kv_str(&o,"agent",agent)&&json_push_kv_str(&o,"kind",kind)&&json_push_kv_str(&o,"ref",ref)&&json_push_kv_str(&o,"text",text);
    size_t n=ok?json_write(&o,NULL,0):0;char *line=n&&n+1<=LINE_CAP&&
      board_bytes<=BYTE_CAP&&n+1<=BYTE_CAP-board_bytes?zcl_malloc(n+2,"board_line"):NULL;
    if (!line) ok = false;
    if (ok) {
        ok = json_write(&o, line, n + 1) == n;
        line[n] = '\n';
    }
    json_free(&o);
    int fd=ok?openat(dirfd,name,O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600):-1;struct stat st;off_t old=0;bool wrote=false;
    ok=fd>=0&&fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>=0&&lock_fd(fd,F_WRLCK)&&
       (uint64_t)st.st_size<=BYTE_CAP&&n+1<=BYTE_CAP-(uint64_t)st.st_size;if(ok)old=st.st_size;
    if(ok){wrote=true;ok=write_all(fd,line,n+1)&&fsync(fd)==0;}
    if (!ok && fd >= 0 && wrote) {
        int rollback_rc = ftruncate(fd, old);
        int sync_rc = fsync(fd);
        if (rollback_rc != 0 || sync_rc != 0)
            error("failed append could not be rolled back cleanly");
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    free(line);
    if(!ok){error("append refused or failed");return 1;}
    if(fsync(dirfd)!=0){error("append saved; directory durability is uncertain");return 1;}
    puts(id);return 0;
}
static bool target_state(int dirfd,const char *name,bool *exists)
{
    struct stat st;
    if (fstatat(dirfd,name,&st,AT_SYMLINK_NOFOLLOW)==0) {
        *exists=true;
        return S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode);
    }
    *exists=false;
    return errno==ENOENT;
}
static int merge_snapshot(int dirfd,const char *peer,const char *incoming_path,
                          uint64_t board_bytes,size_t board_files,
                          const struct rows *all)
{
    char own[128],target[160];
    int nn=snprintf(target,sizeof(target),"%s.jsonl",peer);
    if (!atom(peer,128,false)||!local_host(own)||!strcmp(peer,own)||nn<=0||
        (size_t)nn>=sizeof(target)) {
        error("invalid peer alias or refusal to import own host");
        return 1;
    }
    bool target_exists=false;
    if (!target_state(dirfd,target,&target_exists)) {
        error("peer projection target is not a regular file");
        return 1;
    }
    struct rows prior={0},incoming={0},merged={0};uint64_t prior_bytes=0,incoming_bytes=0;
    bool ok=true;
    if (target_exists) {
        ok=load_file(dirfd,target,&prior,&prior_bytes);
    }
    int input_fd=ok?open(incoming_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK):-1;
    if (ok&&input_fd<0) {
        fprintf(stderr,"fleet-board-bridge: %s: cannot open incoming snapshot safely: %s\n",
                incoming_path,strerror(errno));
        ok=false;
    }
    if (ok) ok=load_open_file(input_fd,incoming_path,&incoming,BYTE_CAP,&incoming_bytes);
    struct row_index all_ids={0},prior_ids={0},incoming_ids={0};
    if(ok)ok=row_index_build(all,&all_ids)&&row_index_build(&prior,&prior_ids)&&
             row_index_build(&incoming,&incoming_ids);
    for(size_t i=0;ok&&i<prior.n;i++)if(strcmp(prior.v[i].host,peer))ok=false;
    for(size_t i=0;ok&&i<incoming.n;i++)if(strcmp(incoming.v[i].host,peer))ok=false;
    for(size_t i=0;ok&&i<prior_ids.n;i++)
        if(!i||strcmp(prior_ids.v[i-1]->id,prior_ids.v[i]->id))
            ok=row_clone_add(&merged,prior_ids.v[i]);
    for(size_t i=0;ok&&i<incoming_ids.n;i++) {
        const struct row *row=incoming_ids.v[i];
        if(i&& !strcmp(incoming_ids.v[i-1]->id,row->id))continue;
        const struct row *global=row_index_find(&all_ids,row->id);
        const struct row *seen=row_index_find(&prior_ids,row->id);
        if((global&&!row_equal(global,row))||(seen&&!row_equal(seen,row)))ok=false;
        else if(!global&&!seen)ok=row_clone_add(&merged,row);
    }
    if (!ok) error("merge refused: malformed ownership, conflicting id, or allocation failure");
    if (ok&&(board_bytes<prior_bytes||board_files>FILE_CAP||
             (!target_exists&&board_files==FILE_CAP)||
             prior.n>all->n||merged.n>ROW_CAP-(all->n-prior.n))) {
        error("merge refused: board file or row capacity");ok=false;
    }
    if (ok) qsort(merged.v,merged.n,sizeof(*merged.v),row_cmp);
    char temp[192]={0};int temp_fd=-1;bool temp_owned=false;
    for (unsigned attempt=0;ok&&attempt<64&&temp_fd<0;attempt++) {
        nn=snprintf(temp,sizeof(temp),".%s.merge.%ld.%u",peer,(long)getpid(),attempt);
        if(nn<=0||(size_t)nn>=sizeof(temp)){ok=false;break;}
        temp_fd=openat(dirfd,temp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if(temp_fd>=0)temp_owned=true;
        if(temp_fd<0&&errno!=EEXIST)ok=false;
    }
    if(ok&&temp_fd<0)ok=false;
    uint64_t new_bytes=0,other_bytes=ok?board_bytes-prior_bytes:0;
    for(size_t i=0;ok&&i<merged.n;i++) {
        size_t n=0;char *line=encode_row(&merged.v[i],&n);
        if(!line||new_bytes>BYTE_CAP-other_bytes||n>BYTE_CAP-other_bytes-new_bytes)ok=false;
        if(ok)ok=write_all(temp_fd,line,n);
        free(line);if(ok)new_bytes+=n;
    }
    if(ok)ok=fsync(temp_fd)==0;
    if(temp_fd>=0&&close(temp_fd)!=0)ok=false;
    if(ok&&!target_state(dirfd,target,&target_exists))ok=false;
    bool published=false;
    if(ok){ok=renameat(dirfd,temp,dirfd,target)==0;published=ok;}
    if(published)temp_owned=false;
    if(ok)ok=fsync(dirfd)==0;
    if(temp_owned&&unlinkat(dirfd,temp,0)!=0&&errno!=ENOENT)ok=false;
    size_t merged_count=merged.n;
    free(all_ids.v);free(prior_ids.v);free(incoming_ids.v);
    rows_free(&prior);rows_free(&incoming);rows_free(&merged);
    if(!ok){error(published?"merge renamed peer projection; directory durability is uncertain":"merge publication failed; peer projection was not replaced");return 1;}
    printf("%zu\n",merged_count);
    return 0;
}
static bool limit_parse(const char *s,size_t *out)
{
    uint64_t n=0;if(!s||!*s)return false;for(size_t i=0;s[i];i++){if(s[i]<'0'||s[i]>'9')return false;n=n*10+(uint64_t)(s[i]-'0');if(n>ROW_CAP)return false;}if(!n)return false;*out=(size_t)n;return true;
}
static char *join(int ac,char **av,int first)
{
    size_t n=1;for(int i=first;i<ac;i++){size_t m=strlen(av[i]);if(m>TEXT_CAP||n>TEXT_CAP+1-m-(i>first))return NULL;n+=m+(i>first);}
    char *s=zcl_malloc(n,"board_text");if(!s)return NULL;size_t at=0;for(int i=first;i<ac;i++){if(i>first)s[at++]=' ';size_t m=strlen(av[i]);memcpy(s+at,av[i],m);at+=m;}s[at]=0;return s;
}
static void help(void){puts("usage: fleet-board-bridge [--board-dir DIR] [--json] post KIND TEXT...\n       fleet-board-bridge [--board-dir DIR] [--json] list [-n N] [--kind KIND] [--host HOST] [--open]\n       fleet-board-bridge [--board-dir DIR] merge PEER_ALIAS INCOMING_FILE");}
int main(int ac,char **av)
{
    const char *dir=NULL,*kind=NULL,*host=NULL;bool json=false,open_only=false;size_t lim=40;int i=1;
    while(i<ac){if(!strcmp(av[i],"--help")){help();return 0;}if(!strcmp(av[i],"--json")){json=true;i++;continue;}if(!strcmp(av[i],"--board-dir")&&i+1<ac){dir=av[i+1];i+=2;continue;}break;}
    if(i>=ac){help();return 1;}const char *cmd=av[i++];char path[PATH_CAP];
    if(dir){if(!copy(path,sizeof(path),dir)){error("path too long");return 1;}}else{const char *h=getenv("HOME");if(!h||snprintf(path,sizeof(path),"%s/.local/state/zclassic23/board",h)>=(int)sizeof(path))return 1;}
    struct stat st;if(lstat(path,&st)!=0||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)){error("board directory must be a real directory");return 1;}
    int dfd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(dfd<0){error("cannot open board directory");return 1;}
    /* This lock coordinates native bridge processes; external writers do not honor it. */
    int guard=openat(dfd,".fleet-board-bridge.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    struct stat gst;if(guard<0||fstat(guard,&gst)!=0||!S_ISREG(gst.st_mode)){if(guard>=0)close(guard);close(dfd);error("cannot lock board snapshot");return 1;}
    if(!strcmp(cmd,"post")){if(i>=ac){close(guard);close(dfd);help();return 1;}kind=av[i++];char *text=join(ac,av,i);struct rows prior={0};uint64_t bytes=0;size_t files=0;bool ready=text&&lock_fd(guard,F_WRLCK)&&load_all(dfd,&prior,&bytes,&files)&&prior.n<ROW_CAP;int rc=ready?post(dfd,kind,text,bytes,files,&prior):1;rows_free(&prior);if(!ready)error("invalid text or board capacity");free(text);close(guard);close(dfd);return rc;}
    if(!strcmp(cmd,"merge")){
        if(i+2!=ac){close(guard);close(dfd);help();return 1;}
        const char *peer=av[i],*incoming_path=av[i+1];struct rows all={0};
        uint64_t bytes=0;size_t files=0;
        bool ready=lock_fd(guard,F_WRLCK)&&load_all(dfd,&all,&bytes,&files);
        int rc=ready?merge_snapshot(dfd,peer,incoming_path,bytes,files,&all):1;
        if(!ready)error("malformed, oversized, changing, or unreadable board");
        rows_free(&all);close(guard);close(dfd);return rc;
    }
    bool ok=!strcmp(cmd,"list");while(ok&&i<ac){if(!strcmp(av[i],"-n")&&i+1<ac){ok=limit_parse(av[i+1],&lim);i+=2;}else if(!strcmp(av[i],"--kind")&&i+1<ac){kind=av[i+1];ok=kind_ok(kind);i+=2;}else if(!strcmp(av[i],"--host")&&i+1<ac){host=av[i+1];ok=atom(host,128,false);i+=2;}else if(!strcmp(av[i],"--open")){open_only=true;i++;}else ok=false;}
    if(!ok){close(guard);close(dfd);help();return 1;}struct rows all={0};uint64_t bytes=0;if(!lock_fd(guard,F_RDLCK)||!load_all(dfd,&all,&bytes,NULL)){close(guard);close(dfd);rows_free(&all);error("malformed, oversized, changing, or unreadable board");return 1;}close(guard);close(dfd);
    char **refs = zcl_malloc((all.n ? all.n : 1) * sizeof(*refs), "board_refs");
    if (!refs) { rows_free(&all); return 1; }
    size_t ref_count = 0;
    for (size_t x = 0; x < all.n; x++) {
        if ((!strcmp(all.v[x].kind,"claim") || !strcmp(all.v[x].kind,"result")) &&
            all.v[x].ref[0]) refs[ref_count++] = all.v[x].ref;
    }
    qsort(refs,ref_count,sizeof(*refs),string_ptr_cmp);
    size_t count=0;for(size_t x=0;x<all.n;x++)if(matches(refs,ref_count,&all.v[x],kind,host,open_only))count++;size_t skip=count>lim?count-lim:0,seen=0;
    for (size_t x = 0; ok && x < all.n; x++) {
        if (matches(refs, ref_count, &all.v[x], kind, host, open_only) && seen++ >= skip)
            ok = emit(&all.v[x], json);
    }
    free(refs);
    rows_free(&all);
    return ok ? 0 : 1;
}
