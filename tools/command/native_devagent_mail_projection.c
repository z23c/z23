/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: disposable, descriptor-verified compact mail locator projection. */
#include "command/native_devagent_mail_projection.h"
#include "command/native_dev_index_ingest.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_boot.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/state_root.h"
#include "platform/file_watch_compat.h"
#include "sha3/sha3.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef ZCL_TESTING
static size_t s_warm_hits;
static size_t s_tail_updates;
static void (*s_before_parse)(void);
static void (*s_after_rebuild)(void);
#endif

#if defined(__linux__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#define MP_STREAMS 16u
#define MP_ROWS 4096u
#define MP_LINE 8192u
#define MP_PATH 4096u
#define MP_EXT_FAMILY_MAGIC 0xef53
#define MP_TMPFS_MAGIC 0x01021994

struct mp_stream {
    char name[DEV_MAIL_STREAM_MAX+1];
    int fd;
    struct dev_mail_tuple tuple, prior;
    struct sha3_256_ctx prefix;
    bool append_ready;
    struct platform_private_file lock;
    size_t first, count, at;
};
struct mp_entry { struct dev_mail_locator loc; struct json_value row; };
struct mp_context {
    char state[MP_PATH], mail[MP_PATH], index[MP_PATH], boot[37];
    uintptr_t maildir, indexdir;
    struct platform_private_file post_lock;
    bool mail_open, index_open, post_locked, locks_held;
    sqlite3 *db;
    int index_fd, watch_fd;
    struct stat index_stat;
    struct mp_stream stream[MP_STREAMS];
    size_t nstream, nentry;
    struct mp_entry *entries;
};

static bool mp_local_fd(int fd)
{
    struct statfs fs;
    return fstatfs(fd,&fs)==0 && ((unsigned long)fs.f_type==MP_EXT_FAMILY_MAGIC ||
                                  (unsigned long)fs.f_type==MP_TMPFS_MAGIC);
}
static bool mp_watch_add(struct mp_context *c,int fd,bool directory)
{
    uint32_t mask=IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_DELETE_SELF|IN_MOVE_SELF;
    if (directory) mask|=IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_ONLYDIR;
    return platform_file_watch_fd(c->watch_fd,fd,mask)>=0;
}
static bool mp_watch_quiet(struct mp_context *c)
{
    char buf[4096]; ssize_t n;
    do { n=read(c->watch_fd,buf,sizeof(buf)); } while (n<0 && errno==EINTR);
    return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
}
static bool mp_hash_range(int fd,int64_t start,int64_t length,struct sha3_256_ctx *hash)
{
    unsigned char buf[65536];
    while (length>0) {
        size_t want=length>(int64_t)sizeof(buf) ? sizeof(buf) : (size_t)length;
        ssize_t n;
        do { n=pread(fd,buf,want,(off_t)start); } while (n<0 && errno==EINTR);
        if (n<=0 || (size_t)n>want) return false;
        sha3_256_write(hash,buf,(size_t)n); start+=n; length-=n;
    }
    return true;
}
static bool mp_hash_stream(struct mp_stream *s)
{
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    if (!mp_hash_range(s->fd,0,s->tuple.size,&hash)) return false;
    unsigned char extra; ssize_t n;
    do { n=pread(s->fd,&extra,1,(off_t)s->tuple.size); } while (n<0 && errno==EINTR);
    if (n!=0) return false;
    sha3_256_finalize(&hash,s->tuple.source_sha3); return true;
}
static bool mp_recheck_hashes(struct mp_context *c)
{
    for (size_t i=0;i<c->nstream;i++) {
        unsigned char expected[32];
        memcpy(expected,c->stream[i].tuple.source_sha3,32);
        if (!mp_hash_stream(&c->stream[i]) || memcmp(expected,c->stream[i].tuple.source_sha3,32)) return false;
    }
    return true;
}
static bool mp_file_private(const struct stat *s)
{
    return S_ISREG(s->st_mode) && s->st_uid==geteuid() && (s->st_mode & 07777)==0600 && s->st_nlink==1;
}
static bool mp_ns(time_t sec, long ns, int64_t *out)
{
    if (sec<0 || (uint64_t)sec>(uint64_t)(INT64_MAX/1000000000LL) || ns<0 || ns>=1000000000L) return false;
    int64_t base=(int64_t)sec*1000000000LL;
    if (base>INT64_MAX-ns) return false;
    *out=base+ns; return true;
}
static bool mp_tuple(struct mp_context *c, struct mp_stream *s, struct dev_mail_tuple *out)
{
    struct stat st,named;
    if (fstat(s->fd,&st)!=0 || !mp_file_private(&st) || !mp_local_fd(s->fd) ||
        fstatat((int)c->maildir,s->name,&named,AT_SYMLINK_NOFOLLOW)!=0 || !mp_file_private(&named) ||
        st.st_dev!=named.st_dev || st.st_ino!=named.st_ino || st.st_size<0 ||
        (uint64_t)st.st_dev>INT64_MAX || (uint64_t)st.st_ino>INT64_MAX) return false;
    memset(out,0,sizeof(*out)); memcpy(out->boot,c->boot,37);
    out->dev=(int64_t)st.st_dev; out->inode=(int64_t)st.st_ino; out->size=(int64_t)st.st_size;
    out->frontier=out->size;
    return mp_ns(st.st_mtim.tv_sec,st.st_mtim.tv_nsec,&out->mtime_ns) &&
           mp_ns(st.st_ctim.tv_sec,st.st_ctim.tv_nsec,&out->ctime_ns);
}
static bool mp_same(const struct dev_mail_tuple *a,const struct dev_mail_tuple *b)
{
    return !strcmp(a->boot,b->boot) && a->dev==b->dev && a->inode==b->inode && a->size==b->size &&
           a->mtime_ns==b->mtime_ns && a->ctime_ns==b->ctime_ns && a->frontier==b->frontier;
}
static int mp_name_cmp(const void *a,const void *b) { return strcmp(((const struct mp_stream *)a)->name,((const struct mp_stream *)b)->name); }
static bool mp_enumerate(struct mp_context *c, struct mp_stream *out, size_t *count)
{
    int fd=openat((int)c->maildir,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if (fd<0) return false;
    DIR *d=fdopendir(fd); if (!d) { close(fd); return false; }
    size_t n=0; bool ok=true; struct dirent *ent;
    errno=0;
    while ((ent=readdir(d))) {
        const char *name=ent->d_name; size_t len=strlen(name);
        if (len<6 || strcmp(name+len-6,".jsonl")) continue;
        if (!dvm_projection_stream_name(name) || n==MP_STREAMS) { ok=false; break; }
        (void)snprintf(out[n].name,sizeof(out[n].name),"%s",name); n++;
    }
    if (errno) ok=false;
    if (closedir(d)!=0) ok=false;
    if (!ok) return false;
    qsort(out,n,sizeof(*out),mp_name_cmp); *count=n; return true;
}
static bool mp_names_same(struct mp_context *c)
{
    struct mp_stream names[MP_STREAMS]={0}; size_t n=0;
    if (!mp_enumerate(c,names,&n) || n!=c->nstream) return false;
    for (size_t i=0;i<n;i++) if (strcmp(names[i].name,c->stream[i].name)) return false;
    return true;
}
static bool mp_snapshot(struct mp_context *c)
{
    if (!mp_names_same(c) || !mp_watch_quiet(c)) return false;
    for (size_t i=0;i<c->nstream;i++) {
        struct dev_mail_tuple now;
        if (!mp_tuple(c,&c->stream[i],&now) || !mp_same(&now,&c->stream[i].tuple)) return false;
    }
    return true;
}
static bool mp_open_streams(struct mp_context *c)
{
    if (!mp_enumerate(c,c->stream,&c->nstream)) return false;
    for (size_t i=0;i<c->nstream;i++) { c->stream[i].fd=-1; platform_private_file_init(&c->stream[i].lock); }
    for (size_t i=0;i<c->nstream;i++) {
        struct mp_stream *s=&c->stream[i];
        s->fd=openat((int)c->maildir,s->name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if (s->fd<0 || !mp_watch_add(c,s->fd,false) || !mp_tuple(c,s,&s->tuple)) return false;
    }
    return mp_names_same(c);
}
static bool mp_index_file(struct mp_context *c,const char *path,bool create,bool *created)
{
    c->index_fd=create ? openat((int)c->indexdir,"index.db",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600) : -1;
    if (c->index_fd>=0) *created=true;
    else if (!create || errno==EEXIST) c->index_fd=openat((int)c->indexdir,"index.db",O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if (c->index_fd<0 || fstat(c->index_fd,&c->index_stat)!=0 || !mp_file_private(&c->index_stat)) return false;
    if (sqlite3_open_v2(path,&c->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) return false;
    sqlite3_busy_timeout(c->db,0);
    struct stat named;
    return fstatat((int)c->indexdir,"index.db",&named,AT_SYMLINK_NOFOLLOW)==0 && mp_file_private(&named) &&
        named.st_dev==c->index_stat.st_dev && named.st_ino==c->index_stat.st_ino;
}
static bool mp_index_open(struct mp_context *c,bool create)
{
    char dir[MP_PATH], path[MP_PATH];
    int n=snprintf(dir,sizeof(dir),"%s/index",c->state);
    if (n<=0 || (size_t)n>=sizeof(dir) || (create && !platform_private_directory_ensure(dir)) ||
        !platform_private_directory_open_validated_traverse(dir,&c->indexdir)) return false;
    c->index_open=true;
    if (!mp_local_fd((int)c->indexdir)) return false;
    n=snprintf(path,sizeof(path),"%s/index.db",dir);
    if (n<=0 || (size_t)n>=sizeof(path)) return false;
    bool created=false;
    return mp_index_file(c,path,create,&created) && dev_mail_projection_index_prepare(c->db,created);
}
static void mp_close(struct mp_context *c)
{
    if (c->entries) { for (size_t i=0;i<c->nentry;i++) json_free(&c->entries[i].row); free(c->entries); }
    if (c->db) sqlite3_close(c->db);
    if (c->index_fd>=0) close(c->index_fd);
    if (c->watch_fd>=0) close(c->watch_fd);
    for (size_t i=0;i<c->nstream;i++) {
        platform_private_file_close(&c->stream[i].lock);
        if (c->stream[i].fd>=0) close(c->stream[i].fd);
    }
    if (c->post_locked) platform_private_file_close(&c->post_lock);
    if (c->index_open) platform_private_directory_close(c->indexdir);
    if (c->mail_open) platform_private_directory_close(c->maildir);
}
static bool mp_lock_inbox(struct mp_context *c,struct mp_stream *s)
{
    char path[MP_PATH]; int n=snprintf(path,sizeof(path),"%s/%s",c->mail,s->name);
    if (n<=0 || (size_t)n>=sizeof(path) || !platform_private_file_open_observation(path,&s->lock) ||
        !platform_private_file_validate_owner_private(&s->lock)) return false;
    struct stat locked,opened;
    return fstat((int)s->lock.native,&locked)==0 && fstat(s->fd,&opened)==0 &&
        locked.st_dev==opened.st_dev && locked.st_ino==opened.st_ino;
}
static bool mp_lock_streams(struct mp_context *c)
{
    if (c->locks_held) return mp_snapshot(c);
    char path[MP_PATH];
    int n; bool outbox=false;
    for (size_t i=0;i<c->nstream;i++) if (!strcmp(c->stream[i].name,"outbox.jsonl")) outbox=true;
    if (outbox) {
        n=snprintf(path,sizeof(path),"%s/post.lock",c->mail);
        if (n<=0 || (size_t)n>=sizeof(path) || !platform_private_file_open_observation(path,&c->post_lock)) return false;
        c->post_locked=true;
        if (!platform_private_file_validate_owner_private(&c->post_lock)) return false;
    }
    for (size_t i=0;i<c->nstream;i++) {
        struct mp_stream *s=&c->stream[i];
        if (!strcmp(s->name,"outbox.jsonl")) continue;
        if (!mp_lock_inbox(c,s)) return false;
    }
    if (!mp_snapshot(c)) return false;
    c->locks_held=true;
    return true;
}

static bool mp_cached_tuple(struct mp_context *c,struct mp_stream *s)
{
    struct dev_mail_tuple stored;
    if (!dev_mail_projection_get(c->db,s->name,&stored) || !mp_same(&stored,&s->tuple) ||
        memcmp(stored.source_sha3,s->tuple.source_sha3,32)) return false;
    s->tuple.skipped=stored.skipped;
    return true;
}
static bool mp_blank(const char *line,size_t n)
{
    while (n && (line[n-1]=='\n' || line[n-1]=='\r')) n--;
    return n==0;
}
static bool mp_scan_row(struct mp_stream *s,struct dev_mail_rebuild *tx,const char *line,size_t len,off_t start)
{
    if (mp_blank(line,len)) return true;
    struct dev_mail_locator row;
#ifdef ZCL_TESTING
    if (s_before_parse) s_before_parse();
#endif
    return dvm_projection_parse(line,len,s->name,(int64_t)start,&row,NULL) &&
        (row.seq<=0 || dev_mail_projection_add(tx,&row));
}
static bool mp_scan_lines(FILE *f,struct mp_stream *s,struct dev_mail_rebuild *tx,
                          struct sha3_256_ctx *hash,int64_t *skipped,size_t max_rows)
{
    char line[MP_LINE]; size_t seen=0;
    for (;;) {
        off_t start=ftello(f); if (start<0) return false;
        enum dvm_projection_line kind=dvm_projection_read_line(f,line,sizeof(line));
        if (kind==DVM_PROJECTION_EOF) return !ferror(f) && start==s->tuple.size;
        if (kind==DVM_PROJECTION_PARTIAL || seen++==max_rows) return false;
        off_t end=ftello(f); if (end<start || end>s->tuple.size) return false;
        if (!mp_hash_range(s->fd,(int64_t)start,(int64_t)(end-start),hash)) return false;
        if (kind==DVM_PROJECTION_LONG) {
            if (*skipped==INT64_MAX) return false;
            (*skipped)++; continue;
        }
        size_t len=strlen(line);
        if ((uint64_t)(end-start)!=len) {
            if (*skipped==INT64_MAX) return false;
            (*skipped)++; continue;
        }
        /* Parse refusal may be allocation failure, so never commit an omission. */
        if (!mp_scan_row(s,tx,line,len,start)) return false;
    }
}
static bool mp_scan_finish(struct mp_context *c,struct mp_stream *s,struct dev_mail_rebuild *tx,
                           struct sha3_256_ctx *hash,int64_t skipped,bool ok)
{
    unsigned char scanned[32]; sha3_256_finalize(hash,scanned);
    if (memcmp(scanned,s->tuple.source_sha3,32)) ok=false;
    struct dev_mail_tuple now;
    if (!mp_tuple(c,s,&now) || !mp_same(&now,&s->tuple) || !mp_names_same(c) || !mp_watch_quiet(c)) ok=false;
    if (!ok) { dev_mail_projection_abort(tx); return false; }
    now.skipped=skipped; memcpy(now.source_sha3,s->tuple.source_sha3,32);
    if (!dev_mail_projection_commit_scanned(tx,&now)) return false;
    s->tuple.skipped=skipped;
    return true;
}
static bool mp_scan_one(struct mp_context *c,struct mp_stream *s,
                        const struct dev_mail_tuple *before,struct sha3_256_ctx *prefix,size_t max_rows)
{
    int fd=dup(s->fd); if (fd<0) return false;
    FILE *f=fdopen(fd,"rb"); if (!f) { close(fd); return false; }
    int64_t start_at=before ? before->frontier : 0;
    if (fseeko(f,(off_t)start_at,SEEK_SET)!=0) { fclose(f); return false; }
    struct dev_mail_tuple after=s->tuple;
    if (before) after.skipped=before->skipped;
    struct dev_mail_rebuild *tx=before ? dev_mail_projection_begin_append(c->db,s->name,before,&after) :
                                         dev_mail_projection_begin(c->db,s->name,&after);
    if (!tx) { fclose(f); return false; }
    int64_t skipped=before ? before->skipped : 0; struct sha3_256_ctx hash;
    if (prefix) hash=*prefix; else sha3_256_init(&hash);
    bool ok=mp_scan_lines(f,s,tx,&hash,&skipped,max_rows);
    if (fclose(f)!=0) ok=false;
    return mp_scan_finish(c,s,tx,&hash,skipped,ok);
}

static bool mp_prepare_append(struct mp_context *c,struct mp_stream *s)
{
    struct dev_mail_tuple *before=&s->prior;
    if (!dev_mail_projection_get(c->db,s->name,before) || strcmp(before->boot,s->tuple.boot) ||
        before->dev!=s->tuple.dev || before->inode!=s->tuple.inode || before->frontier>s->tuple.size ||
        s->tuple.size-before->frontier>32768) return false;
    sha3_256_init(&s->prefix);
    if (!mp_hash_range(s->fd,0,before->frontier,&s->prefix)) return false;
    struct sha3_256_ctx copy=s->prefix; unsigned char digest[32];
    sha3_256_finalize(&copy,digest);
    s->append_ready=memcmp(digest,before->source_sha3,32)==0;
    return s->append_ready;
}

static bool mp_rebuild_one(struct mp_context *c,struct mp_stream *s)
{
    return mp_scan_one(c,s,NULL,NULL,SIZE_MAX);
}
static void mp_unlock_streams(struct mp_context *c)
{
    for (size_t i=0;i<c->nstream;i++) platform_private_file_close(&c->stream[i].lock);
    if (c->post_locked) platform_private_file_close(&c->post_lock);
    c->post_locked=false; c->locks_held=false;
}
static bool mp_advance(struct mp_context *c)
{
    /* Verify old bytes before taking writer-facing locks. The watch and
     * descriptor snapshot must still match after those locks are acquired. */
    for (size_t i=0;i<c->nstream;i++)
        if (!mp_cached_tuple(c,&c->stream[i]) && !mp_prepare_append(c,&c->stream[i])) return false;
    if (!mp_lock_streams(c)) return false;
    bool ok=true;
    for (size_t i=0;ok && i<c->nstream;i++) {
        struct mp_stream *s=&c->stream[i];
        if (!s->append_ready) continue;
        ok=mp_scan_one(c,s,&s->prior,&s->prefix,64);
#ifdef ZCL_TESTING
        if (ok) s_tail_updates++;
#endif
    }
    ok=ok && mp_snapshot(c);
    /* Exact materialization and final full hashes remain watch-validated,
     * but need not exclude native writers for their duration. */
    mp_unlock_streams(c);
    return ok;
}
static int mp_locator_cmp(const void *a,const void *b)
{
    const struct mp_entry *x=a,*y=b;
    return (x->loc.offset>y->loc.offset)-(x->loc.offset<y->loc.offset);
}
static enum dev_mail_probe_result mp_fetch_stream(struct mp_context *c,struct mp_stream *s,
                            const char *const *refs,size_t nrefs,
                            struct dev_mail_locator *scratch)
{
    s->first=c->nentry;
    for (size_t i=0;i<nrefs;i++) {
        size_t n=0, room=MP_ROWS-c->nentry;
        if (!dev_mail_projection_find(c->db,s->name,&s->tuple,refs[i],scratch,room,&n)) {
            enum dev_mail_probe_result why=dev_mail_projection_probe(c->db,s->name,&s->tuple,refs[i],room);
            return why==DEV_MAIL_PROBE_CORRUPT ? why : DEV_MAIL_PROBE_UNKNOWN;
        }
        for (size_t j=0;j<n;j++) {
            c->entries[c->nentry].loc=scratch[j];
            json_init(&c->entries[c->nentry].row);
            c->nentry++;
        }
    }
    s->count=c->nentry-s->first;
    qsort(c->entries+s->first,s->count,sizeof(*c->entries),mp_locator_cmp);
    for (size_t i=0;i<s->count;i++) {
        struct mp_entry *e=&c->entries[s->first+i];
        if (i && e[-1].loc.offset==e->loc.offset) return DEV_MAIL_PROBE_UNKNOWN;
        if (!dvm_projection_exact(c->mail,s->name,&e->loc,&e->row)) return DEV_MAIL_PROBE_UNKNOWN;
    }
    return DEV_MAIL_PROBE_CLEAN;
}

static const char *mp_text(const struct json_value *v,const char *key)
{
    const struct json_value *x=json_get(v,key);
    return x && x->type==JSON_STR && json_get_str(x) ? json_get_str(x) : "";
}
static int mp_row_cmp(const struct json_value *a,const struct json_value *b)
{
    int c=strcmp(mp_text(a,"ts"),mp_text(b,"ts")); if (c) return c;
    c=strcmp(mp_text(a,"from"),mp_text(b,"from")); if (c) return c;
    int64_t x=json_get_int(json_get(a,"seq")), y=json_get_int(json_get(b,"seq"));
    return (x>y)-(x<y);
}
static bool mp_merge(struct mp_context *c,struct json_value *result)
{
    for (;;) {
        struct mp_stream *best=NULL;
        for (size_t i=0;i<c->nstream;i++) {
            struct mp_stream *s=&c->stream[i];
            if (s->at==s->count) continue;
            if (!best || mp_row_cmp(&c->entries[s->first+s->at].row,
                                    &c->entries[best->first+best->at].row)<0) best=s;
        }
        if (!best) return true;
        if (!json_push_back(result,&c->entries[best->first+best->at].row)) return false;
        best->at++;
    }
}
static bool mp_index_same(struct mp_context *c)
{
    struct stat fd,named;
    return fstat(c->index_fd,&fd)==0 && fstatat((int)c->indexdir,"index.db",&named,AT_SYMLINK_NOFOLLOW)==0 &&
           mp_file_private(&fd) && mp_file_private(&named) && fd.st_dev==c->index_stat.st_dev &&
           fd.st_ino==c->index_stat.st_ino && named.st_dev==fd.st_dev && named.st_ino==fd.st_ino;
}
static bool mp_open_mail(struct mp_context *c,const char *root)
{
    c->index_fd=-1; c->watch_fd=-1; platform_private_file_init(&c->post_lock);
    int copied=root ? snprintf(c->state,sizeof(c->state),"%s",root) : 0;
    bool ok=root ? copied>0 && (size_t)copied<sizeof(c->state) :
                   platform_state_root_existing(c->state,sizeof(c->state));
    ok=ok && os_proc_boot_id(c->boot);
    int n=ok ? snprintf(c->mail,sizeof(c->mail),"%s/mail",c->state) : -1;
    ok=ok && n>0 && (size_t)n<sizeof(c->mail) &&
       platform_private_directory_open_validated_traverse(c->mail,&c->maildir);
    if (ok) {
        c->mail_open=true; c->watch_fd=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        ok=c->watch_fd>=0 && mp_local_fd((int)c->maildir) && mp_watch_add(c,(int)c->maildir,true) && mp_open_streams(c);
    }
    return ok;
}
static bool mp_can_advance(struct mp_context *c)
{
    for (size_t i=0;i<c->nstream;i++) {
        struct dev_mail_tuple stored;
        struct mp_stream *stream=&c->stream[i];
        if (!dev_mail_projection_get(c->db,stream->name,&stored) ||
            strcmp(stored.boot,stream->tuple.boot) || stored.dev!=stream->tuple.dev ||
            stored.inode!=stream->tuple.inode || stored.frontier>stream->tuple.size ||
            stream->tuple.size-stored.frontier>32768) return false;
    }
    return true;
}
static bool mp_prepare_context(struct mp_context *c,const char *root,bool maintenance)
{
    /* No cold scan, schema creation or unbounded catch-up on a feed read. */
    bool ok=mp_open_mail(c,root) && mp_index_open(c,maintenance) &&
        (maintenance || mp_can_advance(c));
    for (size_t i=0;ok && i<c->nstream;i++) ok=mp_hash_stream(&c->stream[i]);
    if (ok) ok=mp_snapshot(c);
    return ok;
}
static enum dev_mail_probe_result mp_fetch_all(struct mp_context *c,const char *const *refs,
                                               size_t nrefs,struct dev_mail_locator *scratch)
{
    for (size_t i=0;i<c->nstream;i++) {
        enum dev_mail_probe_result result=mp_fetch_stream(c,&c->stream[i],refs,nrefs,scratch);
        if (result!=DEV_MAIL_PROBE_CLEAN) return result;
    }
    return DEV_MAIL_PROBE_CLEAN;
}
static bool mp_all_cached(struct mp_context *c)
{
    for (size_t i=0;i<c->nstream;i++) if (!mp_cached_tuple(c,&c->stream[i])) return false;
    return true;
}
static bool mp_collect(struct mp_context *c,const char *const *refs,size_t nrefs,bool *was_cached)
{
    bool ok=true;
    bool cached=mp_all_cached(c);
    if (ok && !cached) ok=mp_advance(c);
#ifdef ZCL_TESTING
    if (ok && !cached && s_after_rebuild) s_after_rebuild();
#endif
    c->entries=ok ? zcl_calloc(MP_ROWS,sizeof(*c->entries),"mail_projection.entries") : NULL;
    struct dev_mail_locator *scratch=ok ? zcl_calloc(MP_ROWS,sizeof(*scratch),"mail_projection.locators") : NULL;
    if (ok && (!c->entries || !scratch)) ok=false;
    enum dev_mail_probe_result fetched=DEV_MAIL_PROBE_CLEAN;
    if (ok) { fetched=mp_fetch_all(c,refs,nrefs,scratch); ok=fetched==DEV_MAIL_PROBE_CLEAN; }

    free(scratch);
    *was_cached=cached;
    return ok;
}
static bool mp_projection_refs(const char *const *refs,size_t nrefs,struct json_value *rows)
{
    if (!refs || !nrefs || !rows) return false;
    struct mp_context *c=zcl_calloc(1,sizeof(*c),"mail_projection.context");
    if (!c) return false;
    bool cached=false;
    bool ok=mp_prepare_context(c,NULL,false) && mp_collect(c,refs,nrefs,&cached);
    struct json_value result; json_init(&result); json_set_array(&result);
    if (ok) ok=mp_snapshot(c) && mp_index_same(c) && mp_merge(c,&result) &&
               mp_recheck_hashes(c) && mp_snapshot(c) && mp_index_same(c);
    if (ok) { json_free(rows); *rows=result; }
    else json_free(&result);
#ifdef ZCL_TESTING
    if (ok && cached) s_warm_hits++;
#endif
    mp_close(c); free(c);
    return ok;
}
static bool mp_projection_rebuild_history(const char *root,size_t *streams,int64_t *bytes)
{
    if (!streams || !bytes) return false;
    *streams=0; *bytes=0;
    struct mp_context *c=zcl_calloc(1,sizeof(*c),"mail_projection.maintenance");
    if (!c) return false;
    bool ok=mp_prepare_context(c,root,true) && mp_lock_streams(c);
    int64_t total=0;
    for (size_t i=0;ok && i<c->nstream;i++) {
        if (c->stream[i].tuple.size>INT64_MAX-total) ok=false;
        else total+=c->stream[i].tuple.size;
    }
    /* Explicit maintenance may discard only the disposable mail projection.
     * Generic index rows/cursors and raw mail are not changed. */
    if (ok) ok=dev_mail_projection_reset(c->db);
    for (size_t i=0;ok && i<c->nstream;i++) ok=mp_rebuild_one(c,&c->stream[i]);
    if (ok) ok=mp_recheck_hashes(c) && mp_snapshot(c) && mp_index_same(c);
    if (ok) { *streams=c->nstream; *bytes=total; }
    mp_close(c); free(c); return ok;
}

#endif

#ifdef ZCL_TESTING
size_t dvm_projection_test_warm_hits(bool reset)
{
    size_t n=s_warm_hits; if (reset) s_warm_hits=0; return n;
}
size_t dvm_projection_test_tail_updates(bool reset)
{
    size_t n=s_tail_updates; if (reset) s_tail_updates=0; return n;
}
void dvm_projection_test_before_parse(void (*hook)(void)) { s_before_parse=hook; }
void dvm_projection_test_after_rebuild(void (*hook)(void)) { s_after_rebuild=hook; }
#endif

bool dvm_projection_refs(const char *const *refs,size_t nrefs,struct json_value *rows)
{
#if defined(__linux__)
    return mp_projection_refs(refs,nrefs,rows);
#else
    (void)refs; (void)nrefs; (void)rows; return false;
#endif
}
bool dvm_projection_rebuild_history(const char *root,size_t *streams,int64_t *bytes)
{
#if defined(__linux__)
    return mp_projection_rebuild_history(root,streams,bytes);
#else
    (void)root; if (streams) *streams=0; if (bytes) *bytes=0; return false;
#endif
}
