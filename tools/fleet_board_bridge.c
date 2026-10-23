/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Read and append bounded records in the private fleet board projection. */
#define _POSIX_C_SOURCE 200809L
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
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

/* Field order of a board record on the wire and in parse/encode helpers. */
enum row_field { ROWF_TS, ROWF_ID, ROWF_HOST, ROWF_AGENT, ROWF_KIND, ROWF_REF, ROWF_TEXT, ROWF_COUNT };
static const char *const row_keys[ROWF_COUNT] = {"ts","id","host","agent","kind","ref","text"};

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
        "cost", "packet", "status", "chat", "ask"
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
static void row_fields(const struct json_value *o, const char *f[ROWF_COUNT])
{
    for (size_t i = 0; i < ROWF_COUNT; i++) f[i] = jstr(o, row_keys[i]);
}
static const char *row_reason(const struct row *r, const char *const f[ROWF_COUNT])
{
    if (!timestamp(f[ROWF_TS])) return "invalid timestamp";
    if (!atom(f[ROWF_ID],sizeof(r->id),false)) return "invalid id";
    if (!atom(f[ROWF_HOST],sizeof(r->host),false)) return "invalid host";
    if (!f[ROWF_AGENT] || !f[ROWF_AGENT][0] || strlen(f[ROWF_AGENT]) >= sizeof(r->agent))
        return "missing or oversized agent";
    if (!kind_ok(f[ROWF_KIND])) return "unknown kind";
    if (!f[ROWF_REF] || strlen(f[ROWF_REF]) >= sizeof(r->ref))
        return "missing or oversized ref";
    if (!f[ROWF_TEXT] || strlen(f[ROWF_TEXT]) > TEXT_CAP)
        return "missing or oversized text";
    return NULL;
}
static bool row_copy(struct row *r, const char *const f[ROWF_COUNT])
{
    if (!(copy(r->ts,sizeof(r->ts),f[ROWF_TS]) && copy(r->id,sizeof(r->id),f[ROWF_ID]) &&
          copy(r->host,sizeof(r->host),f[ROWF_HOST]) && copy(r->agent,sizeof(r->agent),f[ROWF_AGENT]) &&
          copy(r->kind,sizeof(r->kind),f[ROWF_KIND]) && copy(r->ref,sizeof(r->ref),f[ROWF_REF])))
        return false;
    r->text = zcl_strdup(f[ROWF_TEXT],"board_text");
    return r->text != NULL;
}
static bool parse_row(char *line, size_t n, struct row *r, const char **reason)
{
    struct json_value o; json_init(&o);
    bool ok = json_read(&o, line, n) && o.type == JSON_OBJ;
    const char *f[ROWF_COUNT] = {0};
    if (ok) row_fields(&o, f);
    if (!ok) *reason = "invalid JSON object";
    else *reason = row_reason(r, f);
    ok = *reason == NULL;
    if (ok) ok = row_copy(r, f);
    json_free(&o); return ok;
}
static bool bounded_regular_fd(int fd, struct stat *st, uint64_t max_bytes)
{
    return fstat(fd,st)==0&&S_ISREG(st->st_mode)&&st->st_size>=0&&
           (uint64_t)st->st_size<=max_bytes;
}
static bool reject_fd(int fd, const char *name, const char *why)
{
    fprintf(stderr,"fleet-board-bridge: %s: %s\n",name,why);
    close(fd);
    return false;
}
static bool snapshot_changed(int fd, const struct stat *before, uint64_t readn)
{
    struct stat after;
    return fstat(fd,&after)!=0||after.st_size!=before->st_size||
           readn!=(uint64_t)before->st_size;
}
static bool line_bounded(const char *line, size_t n, uint64_t readn, uint64_t size)
{
    return n&&line[n-1]=='\n'&&n-1<=LINE_CAP&&readn<=size;
}
static bool load_row(const char *name, size_t line_number, char *line, size_t n, struct rows *r)
{
    struct row x={0}; const char *reason=NULL;
    line[n-1]=0;
    if (!parse_row(line,n-1,&x,&reason) || !rows_add(r,&x)) {
        fprintf(stderr,"fleet-board-bridge: %s:%zu: %s\n",name,line_number,
                reason ? reason : "row capacity or allocation failure");
        free(x.text);
        return false;
    }
    return true;
}
static bool load_open_file(int fd, const char *name, struct rows *r,
                           uint64_t max_bytes,uint64_t *bytes_out)
{
    struct stat before;
    if (!bounded_regular_fd(fd,&before,max_bytes))
        return reject_fd(fd,name,"not a bounded regular file");
    if (!lock_fd(fd,F_RDLCK))
        return reject_fd(fd,name,"cannot acquire read lock");
    FILE *f=fdopen(fd,"r");
    if (!f) return reject_fd(fd,name,"not a bounded regular file");
    char line[LINE_CAP+2]; uint64_t readn=0; size_t line_number=0; bool ok=true;
    while (ok && fgets(line,sizeof(line),f)) {
        line_number++;
        size_t n=strlen(line); readn+=n;
        if (!line_bounded(line,n,readn,(uint64_t)before.st_size)) {
            fprintf(stderr,"fleet-board-bridge: %s:%zu: unterminated, oversized, or changing row\n",name,line_number);
            ok=false;break;
        }
        if (!load_row(name,line_number,line,n,r)) { ok=false; break; }
    }
    if (ferror(f) || (ok && snapshot_changed(fd,&before,readn))) {
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
/* r->v stays NULL until the first row is added, so an empty board (or a
 * merge whose every incoming row is already known) reaches the sort with
 * v == NULL and n == 0 — UB on qsort's nonnull base even though the sort
 * is a no-op at that size. Guard centrally; the comparator order for
 * n >= 2 is unchanged. */
static void rows_sort(struct rows *r)
{
    if (r->n > 1)
        qsort(r->v, r->n, sizeof(*r->v), row_cmp);
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
        rows_sort(r);
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
    if (!local_host(host) || platform_time_realtime_timespec(&t) != 0 ||
        t.tv_sec <= 0 || !platform_time_utc_tm(t.tv_sec, &tm)) return false;
    if(strftime(ts,32,"%Y-%m-%dT%H:%M:%SZ",&tm)!=20||strftime(compact,17,"%Y%m%dT%H%M%S",&tm)!=15)return false;
    int n=snprintf(id,128,"%s-%s-%ld-%09ld",compact,host,(long)getpid(),t.tv_nsec);
    return n>0&&n<128;
}
static bool id_exists(const struct rows *rows, const char *id)
{
    for (size_t i = 0; i < rows->n; i++) if (!strcmp(rows->v[i].id,id)) return true;
    return false;
}
static const char *board_agent(void)
{
    const char *a=getenv("BOARD_AGENT");
    if(!a||!*a)a=getenv("SYSTEMD_UNIT");
    if(!a||!*a)a=getenv("USER");
    return a;
}
static bool post_identity(const struct rows *prior,char ts[32],char id[128],char host[128],
                          char agent[256],char ref[128])
{
    const char *a=board_agent();
    const char *rr=getenv("BOARD_REF");
    if (!identity(ts,id,host) || id_exists(prior,id)) return false;
    if (!a || !*a || strlen(a)>=256 || !copy(agent,256,a)) return false;
    return !rr || !*rr || (strlen(rr)<128 && copy(ref,128,rr));
}
static bool projection_name(const char *host,char name[160])
{
    int nn=snprintf(name,160,"%s.jsonl",host);
    return nn>0&&(size_t)nn<160;
}
static char *post_line(const char *const f[ROWF_COUNT],uint64_t board_bytes,size_t *len_out)
{
    struct json_value o;json_init(&o);json_set_object(&o);
    bool ok=true;
    for(size_t i=0;ok&&i<ROWF_COUNT;i++)ok=json_push_kv_str(&o,row_keys[i],f[i]);
    size_t n=ok?json_write(&o,NULL,0):0;
    char *line=n&&n+1<=LINE_CAP&&board_bytes<=BYTE_CAP&&n+1<=BYTE_CAP-board_bytes?zcl_malloc(n+2,"board_line"):NULL;
    if(!line)ok=false;
    if(ok)ok=json_write(&o,line,n+1)==n;
    json_free(&o);
    if(!ok){free(line);return NULL;}
    line[n]='\n';
    *len_out=n;
    return line;
}
static bool append_target_ok(int fd,size_t n,off_t *old)
{
    struct stat st;
    if(fd<0||fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<0||!lock_fd(fd,F_WRLCK))return false;
    if((uint64_t)st.st_size>BYTE_CAP||n+1>BYTE_CAP-(uint64_t)st.st_size)return false;
    *old=st.st_size;
    return true;
}
static bool append_bytes(int fd,const char *line,size_t n,off_t old)
{
    if(write_all(fd,line,n+1)&&fsync(fd)==0)return true;
    int rollback_rc=ftruncate(fd,old);
    int sync_rc=fsync(fd);
    if(rollback_rc!=0||sync_rc!=0)error("failed append could not be rolled back cleanly");
    return false;
}
static bool append_record(int dirfd,const char *name,const char *line,size_t n)
{
    off_t old=0;
    int fd=openat(dirfd,name,O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    bool ok=append_target_ok(fd,n,&old)&&append_bytes(fd,line,n,old);
    if(fd>=0&&close(fd)!=0)ok=false;
    return ok;
}
static bool target_state(int dirfd,const char *name,bool *exists);
static bool board_room(int dirfd,const char *name,size_t board_files)
{
    bool exists=false;
    if(!target_state(dirfd,name,&exists))return false;
    return board_files<=FILE_CAP&&!(!exists&&board_files==FILE_CAP);
}
static int post(int dirfd,const char *kind,const char *text,uint64_t board_bytes,
                size_t board_files,const struct rows *prior)
{
    if(!kind_ok(kind)||!text||!*text||strlen(text)>TEXT_CAP){error("invalid kind or text bound");return 1;}
    char ts[32],id[128],host[128],agent[256],ref[128]={0},name[160];
    if(!post_identity(prior,ts,id,host,agent,ref)){error("invalid local identity or BOARD_REF");return 1;}
    if(!projection_name(host,name))return 1;
    if(!board_room(dirfd,name,board_files)){
        error("post refused: invalid local projection or board file capacity");
        return 1;
    }
    const char *f[ROWF_COUNT]={[ROWF_TS]=ts,[ROWF_ID]=id,[ROWF_HOST]=host,[ROWF_AGENT]=agent,
                               [ROWF_KIND]=kind,[ROWF_REF]=ref,[ROWF_TEXT]=text};
    size_t n=0;char *line=post_line(f,board_bytes,&n);
    bool ok=line&&append_record(dirfd,name,line,n);
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
struct merge_state {
    struct rows prior, incoming, merged;
    uint64_t prior_bytes, incoming_bytes;
    struct row_index all_ids, prior_ids, incoming_ids;
    char temp[192];
    int temp_fd;
    bool temp_owned, published;
};
static bool load_incoming(const char *incoming_path,struct rows *incoming,uint64_t *bytes)
{
    int input_fd=open(incoming_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(input_fd<0){
        fprintf(stderr,"fleet-board-bridge: %s: cannot open incoming snapshot safely: %s\n",
                incoming_path,strerror(errno));
        return false;
    }
    return load_open_file(input_fd,incoming_path,incoming,BYTE_CAP,bytes);
}
static bool load_merge_inputs(int dirfd,const char *target,bool target_exists,
                              const char *incoming_path,struct merge_state *s)
{
    if (target_exists && !load_file(dirfd,target,&s->prior,&s->prior_bytes)) return false;
    return load_incoming(incoming_path,&s->incoming,&s->incoming_bytes);
}
static bool merge_index(struct merge_state *s,const struct rows *all)
{
    return row_index_build(all,&s->all_ids) && row_index_build(&s->prior,&s->prior_ids) &&
           row_index_build(&s->incoming,&s->incoming_ids);
}
static bool rows_owned_by(const struct rows *r,const char *peer)
{
    for (size_t i = 0; i < r->n; i++) if (strcmp(r->v[i].host,peer)) return false;
    return true;
}
static bool clone_prior(struct merge_state *s)
{
    for (size_t i = 0; i < s->prior_ids.n; i++) {
        const struct row *row = s->prior_ids.v[i];
        if ((!i || strcmp(s->prior_ids.v[i-1]->id,row->id)) && !row_clone_add(&s->merged,row))
            return false;
    }
    return true;
}
static bool merge_incoming(struct merge_state *s)
{
    for (size_t i = 0; i < s->incoming_ids.n; i++) {
        const struct row *row = s->incoming_ids.v[i];
        const struct row *global, *seen;
        if (i && !strcmp(s->incoming_ids.v[i-1]->id,row->id)) continue;
        global = row_index_find(&s->all_ids,row->id);
        seen = row_index_find(&s->prior_ids,row->id);
        if ((global&&!row_equal(global,row))||(seen&&!row_equal(seen,row))) return false;
        if (!global && !seen && !row_clone_add(&s->merged,row)) return false;
    }
    return true;
}
static bool build_merge(struct merge_state *s,const struct rows *all,const char *peer)
{
    return merge_index(s,all) && rows_owned_by(&s->prior,peer) &&
           rows_owned_by(&s->incoming,peer) && clone_prior(s) && merge_incoming(s);
}
static bool capacity_ok(const struct merge_state *s,const struct rows *all,uint64_t board_bytes,
                        size_t board_files,bool target_exists)
{
    return !(board_bytes<s->prior_bytes||board_files>FILE_CAP||
             (!target_exists&&board_files==FILE_CAP)||s->prior.n>all->n||
             s->merged.n>ROW_CAP-(all->n-s->prior.n));
}
static void merge_state_free(struct merge_state *s)
{
    free(s->all_ids.v);free(s->prior_ids.v);free(s->incoming_ids.v);
    rows_free(&s->prior);rows_free(&s->incoming);rows_free(&s->merged);
}
static int create_merge_temp(int dirfd,const char *peer,char temp[192])
{
    for (unsigned attempt=0;attempt<64;attempt++) {
        int nn=snprintf(temp,192,".%s.merge.%ld.%u",peer,(long)getpid(),attempt);
        if (nn<=0||(size_t)nn>=192) return -1;
        int fd=openat(dirfd,temp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if (fd>=0||errno!=EEXIST) return fd;
    }
    return -1;
}
static bool sync_close(int fd,bool ok)
{
    if(ok)ok=fsync(fd)==0;
    if(fd>=0&&close(fd)!=0)ok=false;
    return ok;
}
static bool write_rows(int fd,const struct rows *merged,uint64_t other_bytes)
{
    uint64_t new_bytes=0;
    for (size_t i=0;i<merged->n;i++) {
        size_t n=0;char *line=encode_row(&merged->v[i],&n);
        if (!line||new_bytes>BYTE_CAP-other_bytes||n>BYTE_CAP-other_bytes-new_bytes) {
            free(line);
            return false;
        }
        bool ok=write_all(fd,line,n);
        free(line);
        if (!ok) return false;
        new_bytes+=n;
    }
    return true;
}
static bool stage_merge(int dirfd,const char *peer,uint64_t board_bytes,bool ok,struct merge_state *s)
{
    if (ok) s->temp_fd=create_merge_temp(dirfd,peer,s->temp);
    if (ok && s->temp_fd<0) ok=false;
    s->temp_owned=s->temp_fd>=0;
    if (ok) ok=write_rows(s->temp_fd,&s->merged,board_bytes-s->prior_bytes);
    return sync_close(s->temp_fd,ok);
}
static bool commit_merge(int dirfd,const char *target,bool ok,struct merge_state *s)
{
    bool exists=false;
    if (ok && !target_state(dirfd,target,&exists)) ok=false;
    if (ok) { ok=renameat(dirfd,s->temp,dirfd,target)==0; s->published=ok; }
    if (s->published) s->temp_owned=false;
    if (ok) ok=fsync(dirfd)==0;
    if (s->temp_owned && unlinkat(dirfd,s->temp,0)!=0 && errno!=ENOENT) ok=false;
    return ok;
}
static bool peer_target(const char *peer,char target[160])
{
    char own[128];
    return atom(peer,128,false)&&local_host(own)&&strcmp(peer,own)!=0&&projection_name(peer,target);
}
static int merge_snapshot(int dirfd,const char *peer,const char *incoming_path,
                          uint64_t board_bytes,size_t board_files,
                          const struct rows *all)
{
    char target[160];
    if (!peer_target(peer,target)) {
        error("invalid peer alias or refusal to import own host");
        return 1;
    }
    bool target_exists=false;
    if (!target_state(dirfd,target,&target_exists)) {
        error("peer projection target is not a regular file");
        return 1;
    }
    struct merge_state s={.temp_fd=-1};
    bool ok=load_merge_inputs(dirfd,target,target_exists,incoming_path,&s);
    if (ok) ok=build_merge(&s,all,peer);
    if (!ok) error("merge refused: malformed ownership, conflicting id, or allocation failure");
    if (ok&&!capacity_ok(&s,all,board_bytes,board_files,target_exists)) {
        error("merge refused: board file or row capacity");
        ok=false;
    }
    if (ok) rows_sort(&s.merged);
    ok=stage_merge(dirfd,peer,board_bytes,ok,&s);
    ok=commit_merge(dirfd,target,ok,&s);
    size_t merged_count=s.merged.n;
    bool published=s.published;
    merge_state_free(&s);
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
struct list_opts { const char *kind,*host; size_t lim; bool open_only,json; };
static bool list_args(int ac,char **av,int i,struct list_opts *o)
{
    bool ok=true;
    while(ok&&i<ac){
        if(!strcmp(av[i],"-n")&&i+1<ac){ok=limit_parse(av[i+1],&o->lim);i+=2;}
        else if(!strcmp(av[i],"--kind")&&i+1<ac){o->kind=av[i+1];ok=kind_ok(o->kind);i+=2;}
        else if(!strcmp(av[i],"--host")&&i+1<ac){o->host=av[i+1];ok=atom(o->host,128,false);i+=2;}
        else if(!strcmp(av[i],"--open")){o->open_only=true;i++;}
        else ok=false;
    }
    return ok;
}
static size_t collect_refs(const struct rows *all,char **refs)
{
    size_t ref_count=0;
    for(size_t x=0;x<all->n;x++)
        if((!strcmp(all->v[x].kind,"claim")||!strcmp(all->v[x].kind,"result"))&&all->v[x].ref[0])
            refs[ref_count++]=all->v[x].ref;
    return ref_count;
}
static size_t count_matches(char *const *refs,size_t ref_count,const struct rows *all,const struct list_opts *o)
{
    size_t count=0;
    for(size_t x=0;x<all->n;x++)
        if(matches(refs,ref_count,&all->v[x],o->kind,o->host,o->open_only))count++;
    return count;
}
static bool emit_tail(char *const *refs,size_t ref_count,const struct rows *all,
                      const struct list_opts *o,size_t skip)
{
    size_t seen=0;bool ok=true;
    for(size_t x=0;ok&&x<all->n;x++)
        if(matches(refs,ref_count,&all->v[x],o->kind,o->host,o->open_only)&&seen++>=skip)
            ok=emit(&all->v[x],o->json);
    return ok;
}
static int cmd_list(int dfd,int guard,const struct list_opts *o)
{
    struct rows all={0};uint64_t bytes=0;
    if(!lock_fd(guard,F_RDLCK)||!load_all(dfd,&all,&bytes,NULL)){close(guard);close(dfd);rows_free(&all);error("malformed, oversized, changing, or unreadable board");return 1;}
    close(guard);close(dfd);
    char **refs = zcl_malloc((all.n ? all.n : 1) * sizeof(*refs), "board_refs");
    if (!refs) { rows_free(&all); return 1; }
    size_t ref_count=collect_refs(&all,refs);
    qsort(refs,ref_count,sizeof(*refs),string_ptr_cmp);
    size_t count=count_matches(refs,ref_count,&all,o);
    size_t skip=count>o->lim?count-o->lim:0;
    bool ok=emit_tail(refs,ref_count,&all,o,skip);
    free(refs);
    rows_free(&all);
    return ok?0:1;
}
static int cmd_post(int dfd,int guard,int ac,char **av,int i)
{
    if(i>=ac){close(guard);close(dfd);help();return 1;}
    const char *kind=av[i++];char *text=join(ac,av,i);
    struct rows prior={0};uint64_t bytes=0;size_t files=0;
    bool ready=text&&lock_fd(guard,F_WRLCK)&&load_all(dfd,&prior,&bytes,&files)&&prior.n<ROW_CAP;
    int rc=ready?post(dfd,kind,text,bytes,files,&prior):1;
    rows_free(&prior);if(!ready)error("invalid text or board capacity");
    free(text);close(guard);close(dfd);return rc;
}
static int cmd_merge(int dfd,int guard,int ac,char **av,int i)
{
    if(i+2!=ac){close(guard);close(dfd);help();return 1;}
    const char *peer=av[i],*incoming_path=av[i+1];struct rows all={0};
    uint64_t bytes=0;size_t files=0;
    bool ready=lock_fd(guard,F_WRLCK)&&load_all(dfd,&all,&bytes,&files);
    int rc=ready?merge_snapshot(dfd,peer,incoming_path,bytes,files,&all):1;
    if(!ready)error("malformed, oversized, changing, or unreadable board");
    rows_free(&all);close(guard);close(dfd);return rc;
}
static int board_path(const char *dir,char path[PATH_CAP])
{
    if(dir){
        if(copy(path,PATH_CAP,dir))return 0;
        error("path too long");
        return 1;
    }
    const char *h=getenv("HOME");
    return !h||snprintf(path,PATH_CAP,"%s/.local/state/zclassic23/board",h)>=(int)PATH_CAP;
}
static int open_board_dir(const char *path)
{
    struct stat st;
    if(lstat(path,&st)!=0||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)){error("board directory must be a real directory");return -1;}
    int dfd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(dfd<0){error("cannot open board directory");return -1;}
    return dfd;
}
static int open_guard(int dfd)
{
    struct stat gst;
    int guard=openat(dfd,".fleet-board-bridge.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(guard<0||fstat(guard,&gst)!=0||!S_ISREG(gst.st_mode)){if(guard>=0)close(guard);return -1;}
    return guard;
}
int main(int ac,char **av)
{
    const char *dir=NULL;bool json=false;int i=1;
    while(i<ac){if(!strcmp(av[i],"--help")){help();return 0;}if(!strcmp(av[i],"--json")){json=true;i++;continue;}if(!strcmp(av[i],"--board-dir")&&i+1<ac){dir=av[i+1];i+=2;continue;}break;}
    if(i>=ac){help();return 1;}
    const char *cmd=av[i++];char path[PATH_CAP];
    if(board_path(dir,path)!=0)return 1;
    int dfd=open_board_dir(path);
    if(dfd<0)return 1;
    /* This lock coordinates native bridge processes; external writers do not honor it. */
    int guard=open_guard(dfd);
    if(guard<0){close(dfd);error("cannot lock board snapshot");return 1;}
    if(!strcmp(cmd,"post"))return cmd_post(dfd,guard,ac,av,i);
    if(!strcmp(cmd,"merge"))return cmd_merge(dfd,guard,ac,av,i);
    struct list_opts lo={.lim=40,.json=json};
    if(strcmp(cmd,"list")||!list_args(ac,av,i,&lo)){close(guard);close(dfd);help();return 1;}
    return cmd_list(dfd,guard,&lo);
}
