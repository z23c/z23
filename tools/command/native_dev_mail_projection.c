/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: disposable authenticated mail projection in the dev.index store. */
#include "command/native_dev_mail_projection.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "util/ar_step_readonly.h"
#include "platform/os_boot.h"
#include "sha3/sha3.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool dmp_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK; // raw-sql-ok:index-store
}

bool dev_mail_projection_reset(sqlite3 *db)
{
    if (!db || !dmp_exec(db,"BEGIN IMMEDIATE")) return false;
    bool ok=dmp_exec(db,"DROP TABLE IF EXISTS mail_projection_streams") &&
            dmp_exec(db,"DROP TABLE IF EXISTS mail_projection_nodes") &&
            dmp_exec(db,"DROP TABLE IF EXISTS mail_projection_meta");
    if (ok && dmp_exec(db,"COMMIT")) return true;
    (void)dmp_exec(db,"ROLLBACK");
    return false;
}

/* Content addresses bind the exact versioned encoding. Missing, duplicate,
 * malformed or altered nodes are cache misses, never proof of absence. */
#define DMP_NODE_MAX 512
static bool dmp_node_shape(const void *bytes,size_t n)
{
    return bytes && n && n<=DMP_NODE_MAX;
}
static void dmp_node_hash(const unsigned char *bytes, size_t n, unsigned char hash[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"z23.mail.node.v1", 16);
    sha3_256_write(&ctx, bytes, n);
    sha3_256_finalize(&ctx, hash);
}


/* Statements belong to one rebuild transaction, never to a process-global
 * connection map. Each use releases all bindings before calling another
 * graph operation, so recursive traversal cannot retain borrowed row data. */
enum dmp_statement_slot {
    DMP_INSERT, DMP_GET, DMP_COUNT, DMP_INCREMENT, DMP_DECREMENT, DMP_DELETE,
    DMP_STATEMENTS
};
struct dmp_statements { sqlite3_stmt *slot[DMP_STATEMENTS]; };

static bool dmp_statement(sqlite3 *db, struct dmp_statements *cache,
    enum dmp_statement_slot slot, const char *sql, sqlite3_stmt **out)
{
    *out=cache ? cache->slot[slot] : NULL;
    if (*out) return true;
    if (sqlite3_prepare_v2(db,sql,-1,out,NULL)!=SQLITE_OK) return false;
    if (cache) cache->slot[slot]=*out;
    return true;
}

static bool dmp_statement_release(struct dmp_statements *cache, sqlite3_stmt *st)
{
    if (!cache) return sqlite3_finalize(st)==SQLITE_OK;
    int reset=sqlite3_reset(st);
    int clear=sqlite3_clear_bindings(st);
    return reset==SQLITE_OK && clear==SQLITE_OK;
}

static void dmp_statements_close(struct dmp_statements *cache)
{
    for (size_t i=0;i<DMP_STATEMENTS;i++) {
        sqlite3_finalize(cache->slot[i]);
        cache->slot[i]=NULL;
    }
}

static bool dmp_node_get(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32],
                         unsigned char bytes[DMP_NODE_MAX], size_t *n);
static bool dmp_retain_children(sqlite3 *db, struct dmp_statements *cache, const unsigned char *bytes, size_t n);

static bool dmp_node_put(sqlite3 *db, struct dmp_statements *cache, const unsigned char *bytes, size_t n,
                         unsigned char hash[32])
{
    if (!dmp_node_shape(bytes,n)) return false;
    dmp_node_hash(bytes,n,hash);
    sqlite3_stmt *st = NULL;
    if (!dmp_statement(db,cache,DMP_INSERT,"INSERT OR IGNORE INTO mail_projection_nodes(hash,body,refs) VALUES(?1,?2,0)",&st)) return false;
    bool ok = sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)==SQLITE_OK &&
              sqlite3_bind_blob(st,2,bytes,(int)n,SQLITE_STATIC)==SQLITE_OK &&
              sqlite3_step(st)==SQLITE_DONE; // raw-sql-ok:index-store
    int inserted=ok ? sqlite3_changes(db) : -1;
    if (!dmp_statement_release(cache,st)) ok=false;
    unsigned char stored[DMP_NODE_MAX]; size_t stored_n = 0;
    return ok && (inserted==0 || inserted==1) && dmp_node_get(db,cache,hash,stored,&stored_n) &&
           stored_n == n && memcmp(stored,bytes,n) == 0 &&
           (!inserted || dmp_retain_children(db,cache,bytes,n));
}

static bool dmp_node_get(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32],
                         unsigned char bytes[DMP_NODE_MAX], size_t *n)
{
    sqlite3_stmt *st = NULL;
    *n = 0;
    if (!dmp_statement(db,cache,DMP_GET,"SELECT body,refs FROM mail_projection_nodes WHERE hash=?1",&st)) return false;
    bool ok = sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)==SQLITE_OK &&
              ar_step_checked(st,"mail projection select",NULL)==ZCL_STEP_ROW && sqlite3_column_type(st,0)==SQLITE_BLOB &&
              sqlite3_column_type(st,1)==SQLITE_INTEGER && sqlite3_column_int64(st,1)>=0; // raw-sql-ok:index-store
    int len = ok ? sqlite3_column_bytes(st,0) : 0;
    const void *data = ok ? sqlite3_column_blob(st,0) : NULL;
    if (!dmp_node_shape(data,(size_t)len)) ok = false;
    if (ok) { memcpy(bytes,data,(size_t)len); *n=(size_t)len; }
    if (ok) ok = ar_step_checked(st,"mail projection select",NULL)==ZCL_STEP_DONE;
    if (!dmp_statement_release(cache,st)) ok=false;
    unsigned char actual[32];
    if (ok) { dmp_node_hash(bytes,*n,actual); ok = memcmp(actual,hash,32)==0; }
    if (!ok) *n=0;
    return ok;
}

static void dmp_u64_put(unsigned char out[8], uint64_t v)
{
    for (int i=7; i>=0; i--) { out[i]=(unsigned char)v; v >>= 8; }
}

static uint64_t dmp_u64_get(const unsigned char in[8])
{
    uint64_t v=0;
    for (int i=0; i<8; i++) v=(v<<8)|in[i];
    return v;
}

static unsigned dmp_key_bit(const unsigned char key[32], unsigned bit)
{
    return (key[bit/8] >> (7-(bit%8))) & 1u;
}

/* A branch stores only bits strictly before its branch bit. */
static void dmp_prefix(unsigned char out[32], const unsigned char key[32], unsigned bit)
{
    memset(out,0,32);
    for (unsigned i=0; i<bit; i++)
        if (dmp_key_bit(key,i)) out[i/8] |= (unsigned char)(1u << (7-(i%8)));
}

static bool dmp_zero_hash(const unsigned char hash[32])
{
    unsigned char v=0;
    for (size_t i=0; i<32; i++) v |= hash[i];
    return v==0;
}

struct dmp_branch {
    unsigned bit;
    unsigned char prefix[32], child[2][32];
};

static bool dmp_branch_decode(const unsigned char *p, size_t n, struct dmp_branch *b)
{
    if (n!=99 || p[0]!='B') return false;
    b->bit=((unsigned)p[1]<<8)|p[2];
    if (b->bit>=256) return false;
    memcpy(b->prefix,p+3,32); memcpy(b->child[0],p+35,32); memcpy(b->child[1],p+67,32);
    unsigned char canonical[32];
    dmp_prefix(canonical,b->prefix,b->bit);
    return !memcmp(canonical,b->prefix,32) && !dmp_zero_hash(b->child[0]) &&
           !dmp_zero_hash(b->child[1]) && memcmp(b->child[0],b->child[1],32);
}

static bool dmp_branch_put(sqlite3 *db, struct dmp_statements *cache, const struct dmp_branch *b, unsigned char hash[32])
{
    unsigned char p[99];
    p[0]='B'; p[1]=(unsigned char)(b->bit>>8); p[2]=(unsigned char)b->bit;
    memcpy(p+3,b->prefix,32); memcpy(p+35,b->child[0],32); memcpy(p+67,b->child[1],32);
    struct dmp_branch verified;
    return dmp_branch_decode(p,sizeof(p),&verified) && dmp_node_put(db,cache,p,sizeof(p),hash) && !dmp_zero_hash(hash);
}

struct dmp_leaf {
    unsigned char key[32], head[32];
    char ref[DEV_MAIL_REF_MAX+1];
    uint64_t count;
};

static void dmp_ref_key(const char *ref, size_t n, unsigned char key[32])
{
    sha3_256((const unsigned char *)ref,n,key);
}

static bool dmp_leaf_decode(const unsigned char *p, size_t n, struct dmp_leaf *leaf)
{
    if (n < 75 || p[0]!='L') return false;
    size_t len=((size_t)p[33]<<8)|p[34];
    if (len>DEV_MAIL_REF_MAX || n!=75+len || memchr(p+35,0,len)) return false;
    memcpy(leaf->key,p+1,32); memcpy(leaf->ref,p+35,len); leaf->ref[len]=0;
    memcpy(leaf->head,p+35+len,32); leaf->count=dmp_u64_get(p+67+len);
    unsigned char key[32]; dmp_ref_key(leaf->ref,len,key);
    return !memcmp(key,leaf->key,32) && leaf->count>0 && !dmp_zero_hash(leaf->head);
}

static bool dmp_leaf_put(sqlite3 *db, struct dmp_statements *cache, const struct dmp_leaf *leaf, unsigned char hash[32])
{
    unsigned char p[DMP_NODE_MAX]; size_t len=strnlen(leaf->ref,sizeof(leaf->ref));
    if (len>DEV_MAIL_REF_MAX) return false;
    p[0]='L'; memcpy(p+1,leaf->key,32); p[33]=(unsigned char)(len>>8); p[34]=(unsigned char)len;
    memcpy(p+35,leaf->ref,len); memcpy(p+35+len,leaf->head,32); dmp_u64_put(p+67+len,leaf->count);
    struct dmp_leaf check;
    return dmp_leaf_decode(p,75+len,&check) && dmp_node_put(db,cache,p,75+len,hash) && !dmp_zero_hash(hash);
}

static bool dmp_hash_bytes(const char *hex, unsigned char bytes[32])
{
    return strnlen(hex,65)==64 && zcl_hex_decode_lower(hex,bytes,32);
}

static bool dmp_post_put(sqlite3 *db, struct dmp_statements *cache, const struct dev_mail_locator *row,
                         const unsigned char previous[32], unsigned char hash[32])
{
    unsigned char p[89];
    if (row->offset<0 || row->end<=row->offset || row->seq<=0 || !dmp_hash_bytes(row->sha3,p+25)) return false;
    p[0]='P'; dmp_u64_put(p+1,(uint64_t)row->offset); dmp_u64_put(p+9,(uint64_t)row->end);
    dmp_u64_put(p+17,(uint64_t)row->seq); memcpy(p+57,previous,32);
    return dmp_node_put(db,cache,p,sizeof(p),hash) && !dmp_zero_hash(hash);
}

static bool dmp_node_live(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32],
                          unsigned char body[DMP_NODE_MAX], size_t *n);
static bool dmp_ref_count(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32], int64_t *refs);

static bool dmp_post_get(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32],
                         struct dev_mail_locator *row, unsigned char previous[32])
{
    unsigned char p[DMP_NODE_MAX]; size_t n;
    if (!dmp_node_live(db,cache,hash,p,&n) || n!=89 || p[0]!='P') return false;
    uint64_t off=dmp_u64_get(p+1), end=dmp_u64_get(p+9), seq=dmp_u64_get(p+17);
    if (off>INT64_MAX || end>INT64_MAX || seq>INT64_MAX || end<=off || seq==0) return false;
    row->offset=(int64_t)off; row->end=(int64_t)end; row->seq=(int64_t)seq;
    zcl_hex_encode(p+25,32,row->sha3); memcpy(previous,p+57,32);
    return true;
}

static bool dmp_branch_live_children(sqlite3 *db, struct dmp_statements *cache, const struct dmp_branch *b)
{
    int64_t refs;
    return dmp_ref_count(db,cache,b->child[0],&refs) && dmp_ref_count(db,cache,b->child[1],&refs);
}

static bool dmp_children(const unsigned char *p, size_t n, unsigned char children[2][32], size_t *count)
{
    *count=0;
    if (p[0]=='B') {
        struct dmp_branch b;
        if (!dmp_branch_decode(p,n,&b)) return false;
        memcpy(children,b.child,sizeof(b.child)); *count=2; return true;
    }
    if (p[0]=='L') {
        struct dmp_leaf leaf;
        if (!dmp_leaf_decode(p,n,&leaf)) return false;
        memcpy(children[0],leaf.head,32); *count=1; return true;
    }
    if (p[0]!='P' || n!=89) return false;
    uint64_t off=dmp_u64_get(p+1), end=dmp_u64_get(p+9), seq=dmp_u64_get(p+17);
    if (off>INT64_MAX || end>INT64_MAX || seq>INT64_MAX || end<=off || !seq) return false;
    if (!dmp_zero_hash(p+57)) { memcpy(children[0],p+57,32); *count=1; }
    return true;
}

static bool dmp_ref_update(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32], bool add)
{
    sqlite3_stmt *st=NULL;
    const char *sql=add ? "UPDATE mail_projection_nodes SET refs=refs+1 WHERE hash=?1 AND typeof(refs)='integer' AND refs>=0 AND refs<9223372036854775807" :
                          "UPDATE mail_projection_nodes SET refs=refs-1 WHERE hash=?1 AND typeof(refs)='integer' AND refs>1";
    if (!dmp_statement(db,cache,add ? DMP_INCREMENT : DMP_DECREMENT,sql,&st)) return false;
    bool ok=sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)==SQLITE_OK && sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(db)==1; // raw-sql-ok:index-store
    if (!dmp_statement_release(cache,st)) ok=false;
    return ok;
}

static bool dmp_retain_children(sqlite3 *db, struct dmp_statements *cache, const unsigned char *bytes, size_t n)
{
    unsigned char children[2][32]; size_t count;
    if (!dmp_children(bytes,n,children,&count)) return false;
    for (size_t i=0;i<count;i++) if (!dmp_ref_update(db,cache,children[i],true)) return false;
    return true;
}

static bool dmp_ref_count(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32], int64_t *refs)
{
    sqlite3_stmt *st=NULL;
    if (!dmp_statement(db,cache,DMP_COUNT,"SELECT refs FROM mail_projection_nodes WHERE hash=?1",&st)) return false;
    bool ok=sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)==SQLITE_OK && ar_step_checked(st,"mail projection select",NULL)==ZCL_STEP_ROW &&
            sqlite3_column_type(st,0)==SQLITE_INTEGER && sqlite3_column_int64(st,0)>0; // raw-sql-ok:index-store
    if (ok) *refs=sqlite3_column_int64(st,0);
    if (ok) ok=ar_step_checked(st,"mail projection refcount",NULL)==ZCL_STEP_DONE;
    if (!dmp_statement_release(cache,st)) ok=false;
    return ok;
}

static bool dmp_node_live(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32],
                          unsigned char body[DMP_NODE_MAX], size_t *n)
{
    int64_t refs;
    return dmp_node_get(db,cache,hash,body,n) && dmp_ref_count(db,cache,hash,&refs);
}

static bool dmp_node_delete(sqlite3 *db, struct dmp_statements *cache, const unsigned char hash[32])
{
    sqlite3_stmt *st=NULL;
    if (!dmp_statement(db,cache,DMP_DELETE,"DELETE FROM mail_projection_nodes WHERE hash=?1 AND refs=1",&st)) return false;
    bool ok=sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)==SQLITE_OK && sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(db)==1; // raw-sql-ok:index-store
    if (!dmp_statement_release(cache,st)) ok=false;
    return ok;
}

/* DFS holds at most one sibling per radix bit; posting chains add no siblings. */
static bool dmp_release(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32])
{
    unsigned char stack[258][32]; size_t used=0;
    if (dmp_zero_hash(root)) return true;
    memcpy(stack[used++],root,32);
    while (used) {
        unsigned char hash[32], body[DMP_NODE_MAX], children[2][32]; size_t n, count;
        int64_t refs;
        memcpy(hash,stack[--used],32);
        if (!dmp_node_get(db,cache,hash,body,&n) || !dmp_ref_count(db,cache,hash,&refs)) return false;
        if (refs>1) { if (!dmp_ref_update(db,cache,hash,false)) return false; continue; }
        if (!dmp_children(body,n,children,&count) || used+count>258 || !dmp_node_delete(db,cache,hash)) return false;
        for (size_t i=0;i<count;i++) memcpy(stack[used++],children[i],32);
    }
    return true;
}

static bool dmp_child_valid(const unsigned char key[32], unsigned parent,
                            const unsigned char parent_prefix[32], unsigned side)
{
    unsigned char prefix[32]; dmp_prefix(prefix,key,parent);
    return !memcmp(prefix,parent_prefix,32) && dmp_key_bit(key,parent)==side;
}

static bool dmp_lookup_leaf(const unsigned char *p, size_t n, const char *ref,
                            const unsigned char key[32], int parent,
                            const unsigned char parent_prefix[32], unsigned side,
                            struct dmp_leaf *leaf, bool *found)
{
    if (!dmp_leaf_decode(p,n,leaf)) return false;
    if (parent>=0 && !dmp_child_valid(leaf->key,(unsigned)parent,parent_prefix,side)) return false;
    if (memcmp(key,leaf->key,32)) return true;
    if (strcmp(ref,leaf->ref)) return false;
    *found=true;
    return true;
}

/* The caller may accept absent only for a root made by a complete trusted
 * scan and correctly maintained under writer locks. */
static bool dmp_trie_lookup(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32], const char *ref,
                            struct dmp_leaf *leaf, bool *found)
{
    unsigned char key[32], current[32], parent_prefix[32];
    size_t len=strnlen(ref,DEV_MAIL_REF_MAX+1);
    if (len>DEV_MAIL_REF_MAX) return false;
    dmp_ref_key(ref,len,key); memcpy(current,root,32);
    *found=false;
    if (dmp_zero_hash(current)) return true;
    int parent=-1; unsigned side=0;
    memset(parent_prefix,0,sizeof(parent_prefix));
    for (unsigned depth=0; depth<=256; depth++) {
        unsigned char p[DMP_NODE_MAX]; size_t n;
        if (!dmp_node_live(db,cache,current,p,&n)) return false;
        if (p[0]=='L') {
            return dmp_lookup_leaf(p,n,ref,key,parent,parent_prefix,side,leaf,found);
        }
        struct dmp_branch b;
        if (!dmp_branch_decode(p,n,&b) || !dmp_branch_live_children(db,cache,&b) ||
            (parent>=0 && b.bit<=(unsigned)parent)) return false;
        if (parent>=0 && !dmp_child_valid(b.prefix,(unsigned)parent,parent_prefix,side)) return false;
        unsigned char prefix[32]; dmp_prefix(prefix,key,b.bit);
        if (memcmp(prefix,b.prefix,32)) return true;
        parent=(int)b.bit; side=dmp_key_bit(key,b.bit);
        memcpy(parent_prefix,b.prefix,32); memcpy(current,b.child[side],32);
    }
    return false;
}

static unsigned dmp_first_difference(const unsigned char a[32], const unsigned char b[32], unsigned limit)
{
    for (unsigned i=0; i<limit; i++) if (dmp_key_bit(a,i)!=dmp_key_bit(b,i)) return i;
    return limit;
}

struct dmp_path_entry { struct dmp_branch branch; unsigned side; };

static bool dmp_existing_branch(sqlite3 *db, struct dmp_statements *cache, const unsigned char *p, size_t n,
                                struct dmp_path_entry path[256], size_t depth,
                                struct dmp_branch *b)
{
    if (!dmp_branch_decode(p,n,b) || !dmp_branch_live_children(db,cache,b)) return false;
    if (!depth) return true;
    return b->bit>path[depth-1].branch.bit && dmp_child_valid(b->prefix,path[depth-1].branch.bit,
           path[depth-1].branch.prefix,path[depth-1].side);
}

/* -1 refuses, 0 splits here, 1 descends, 2 replaces a matching leaf. */
static int dmp_replace_probe(sqlite3 *db, struct dmp_statements *cache, const unsigned char *p, size_t n,
                             const struct dmp_leaf *replacement,
                             struct dmp_path_entry path[256], size_t *depth,
                             unsigned char current[32], unsigned char existing_key[32], unsigned *split)
{
    if (p[0]=='B') {
        struct dmp_branch b;
        if (!dmp_existing_branch(db,cache,p,n,path,*depth,&b)) return -1;
        *split=dmp_first_difference(replacement->key,b.prefix,b.bit);
        if (*split!=b.bit) { memcpy(existing_key,b.prefix,32); return 0; }
        if (*depth==256) return -1;
        path[*depth].branch=b; path[*depth].side=dmp_key_bit(replacement->key,b.bit);
        memcpy(current,b.child[path[*depth].side],32); (*depth)++; return 1;
    }
    if (p[0]!='L') return -1;
    struct dmp_leaf old;
    if (!dmp_leaf_decode(p,n,&old)) return -1;
    if (*depth && !dmp_child_valid(old.key,path[*depth-1].branch.bit,
                                    path[*depth-1].branch.prefix,path[*depth-1].side)) return -1;
    *split=dmp_first_difference(replacement->key,old.key,256);
    if (*split==256) return strcmp(replacement->ref,old.ref) ? -1 : 2;
    memcpy(existing_key,old.key,32); return 0;
}

static bool dmp_trie_replace(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32],
                             const struct dmp_leaf *replacement, unsigned char result[32])
{
    struct dmp_path_entry path[256]; size_t depth=0;
    unsigned char current[32], new_leaf[32], next[32];
    if (!dmp_leaf_put(db,cache,replacement,new_leaf)) return false;
    memcpy(current,root,32);
    if (dmp_zero_hash(current)) { memcpy(result,new_leaf,32); return true; }
    for (;;) {
        unsigned char p[DMP_NODE_MAX], existing_key[32]; size_t n; unsigned split;
        if (!dmp_node_live(db,cache,current,p,&n)) return false;
        int action=dmp_replace_probe(db,cache,p,n,replacement,path,&depth,current,existing_key,&split);
        if (action<0) return false;
        if (action==1) continue;
        if (action==2) { memcpy(current,new_leaf,32); break; }
        if (depth && split<=path[depth-1].branch.bit) return false;
        struct dmp_branch inserted = {.bit=split};
        dmp_prefix(inserted.prefix,replacement->key,split);
        unsigned side=dmp_key_bit(replacement->key,split);
        if (side==dmp_key_bit(existing_key,split)) return false;
        memcpy(inserted.child[side],new_leaf,32); memcpy(inserted.child[1-side],current,32);
        if (!dmp_branch_put(db,cache,&inserted,current)) return false;
        break;
    }
    while (depth) {
        struct dmp_path_entry *entry=&path[--depth];
        memcpy(entry->branch.child[entry->side],current,32);
        if (!dmp_branch_put(db,cache,&entry->branch,next)) return false;
        memcpy(current,next,32);
    }
    memcpy(result,current,32); return true;
}

static bool dmp_trie_append(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32],
                            const struct dev_mail_locator *row, unsigned char result[32])
{
    struct dmp_leaf leaf; bool found;
    if (!dmp_trie_lookup(db,cache,root,row->ref,&leaf,&found)) return false;
    if (!found) {
        memset(&leaf,0,sizeof(leaf));
        (void)snprintf(leaf.ref,sizeof(leaf.ref),"%s",row->ref);
        dmp_ref_key(leaf.ref,strlen(leaf.ref),leaf.key);
    } else {
        struct dev_mail_locator head; unsigned char previous[32];
        if (leaf.count==UINT64_MAX || !dmp_post_get(db,cache,leaf.head,&head,previous) || head.end>row->offset) return false;
    }
    unsigned char next[32];
    if (!dmp_post_put(db,cache,row,leaf.head,next)) return false;
    memcpy(leaf.head,next,32); leaf.count++;
    return dmp_trie_replace(db,cache,root,&leaf,result);
}

static bool dmp_schema(sqlite3 *db)
{
    return dmp_exec(db, "CREATE TABLE IF NOT EXISTS mail_projection_meta(version INTEGER NOT NULL)") &&
        dmp_exec(db, "CREATE TABLE IF NOT EXISTS mail_projection_streams("
        "stream TEXT PRIMARY KEY,boot TEXT NOT NULL,dev INTEGER NOT NULL,ino INTEGER NOT NULL,"
        "size INTEGER NOT NULL,mt INTEGER NOT NULL,ct INTEGER NOT NULL,frontier INTEGER NOT NULL,"
        "skipped INTEGER NOT NULL,partial INTEGER NOT NULL,root BLOB NOT NULL,"
        "entry_count INTEGER NOT NULL,seal BLOB NOT NULL,source_sha3 BLOB NOT NULL)") &&
        dmp_exec(db, "CREATE TABLE IF NOT EXISTS mail_projection_nodes(hash BLOB PRIMARY KEY,body BLOB NOT NULL,refs INTEGER NOT NULL)") &&
        dmp_exec(db, "INSERT INTO mail_projection_meta SELECT 4 WHERE NOT EXISTS(SELECT 1 FROM mail_projection_meta) AND NOT EXISTS(SELECT 1 FROM mail_projection_streams) AND NOT EXISTS(SELECT 1 FROM mail_projection_nodes)");
}

static bool dmp_version(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT version FROM mail_projection_meta", -1, &st, NULL) != SQLITE_OK) return false;
    bool ok = ar_step_checked(st,"mail projection select",NULL)==ZCL_STEP_ROW && sqlite3_column_type(st,0) == SQLITE_INTEGER &&
              sqlite3_column_int64(st,0) == 4 && ar_step_checked(st,"mail projection version",NULL)==ZCL_STEP_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool dmp_valid(const char *stream, const struct dev_mail_tuple *t)
{
    char boot[37];
    return stream && stream[0] && strnlen(stream, DEV_MAIL_STREAM_MAX + 1) <= DEV_MAIL_STREAM_MAX && t &&
        strnlen(t->boot, sizeof(t->boot)) == 36 &&
        os_proc_boot_id_normalize(t->boot, 36, boot) && !strcmp(boot, t->boot) && t->dev >= 0 && t->inode > 0 &&
        t->size >= 0 && t->frontier == t->size && t->skipped >= 0 && !t->partial;
}

static void dmp_meta_seal(const char *stream, const struct dev_mail_tuple *t,
                          const unsigned char root[32], uint64_t count, unsigned char seal[32])
{
    struct sha3_256_ctx ctx; unsigned char num[8];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx,(const unsigned char *)"z23.mail.meta.v4",16);
    dmp_u64_put(num,strlen(stream)); sha3_256_write(&ctx,num,8);
    sha3_256_write(&ctx,(const unsigned char *)stream,strlen(stream));
    sha3_256_write(&ctx,(const unsigned char *)t->boot,36);
    const int64_t fields[]={t->dev,t->inode,t->size,t->mtime_ns,t->ctime_ns,t->frontier,t->skipped};
    for (size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
        dmp_u64_put(num,(uint64_t)fields[i]); sha3_256_write(&ctx,num,8);
    }
    sha3_256_write(&ctx,t->source_sha3,32);
    sha3_256_write(&ctx,root,32); dmp_u64_put(num,count); sha3_256_write(&ctx,num,8);
    sha3_256_finalize(&ctx,seal);
}

static bool dmp_match(sqlite3 *db, const char *stream, const struct dev_mail_tuple *t)
{
    struct dev_mail_tuple v;
    return dev_mail_projection_get(db,stream,&v) && !strcmp(v.boot,t->boot) &&
        v.dev==t->dev && v.inode==t->inode && v.size==t->size && v.mtime_ns==t->mtime_ns &&
        v.ctime_ns==t->ctime_ns && v.frontier==t->frontier && v.skipped==t->skipped &&
        !memcmp(v.source_sha3,t->source_sha3,32);
}

static bool dmp_bind_tuple(sqlite3_stmt *st, const char *stream, const struct dev_mail_tuple *t)
{
    return sqlite3_bind_text(st,1,stream,-1,SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(st,2,t->boot,-1,SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_int64(st,3,t->dev) == SQLITE_OK && sqlite3_bind_int64(st,4,t->inode) == SQLITE_OK &&
        sqlite3_bind_int64(st,5,t->size) == SQLITE_OK && sqlite3_bind_int64(st,6,t->mtime_ns) == SQLITE_OK &&
        sqlite3_bind_int64(st,7,t->ctime_ns) == SQLITE_OK && sqlite3_bind_int64(st,8,t->frontier) == SQLITE_OK &&
        sqlite3_bind_int64(st,9,t->skipped) == SQLITE_OK;
}
static bool dmp_save(sqlite3 *db, const char *stream, const struct dev_mail_tuple *t,
                     const unsigned char root[32], uint64_t count)
{
    sqlite3_stmt *st = NULL;
    if (count>INT64_MAX) return false;
    unsigned char seal[32]; dmp_meta_seal(stream,t,root,count,seal);
    if (sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO mail_projection_streams VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?13)",-1,&st,NULL) != SQLITE_OK) return false;
    bool ok = dmp_bind_tuple(st,stream,t) && sqlite3_bind_blob(st,10,root,32,SQLITE_STATIC)==SQLITE_OK &&
        sqlite3_bind_int64(st,11,(int64_t)count)==SQLITE_OK && sqlite3_bind_blob(st,12,seal,32,SQLITE_STATIC)==SQLITE_OK &&
        sqlite3_bind_blob(st,13,t->source_sha3,32,SQLITE_STATIC)==SQLITE_OK &&
        sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:index-store
    sqlite3_finalize(st); return ok;
}

static bool dmp_append_valid(const char *stream, const struct dev_mail_tuple *before,
                             const struct dev_mail_tuple *after)
{
    return !before || (dmp_valid(stream,before) && !strcmp(before->boot,after->boot) &&
        before->dev == after->dev && before->inode == after->inode &&
        before->size <= after->size && before->skipped <= after->skipped);
}

struct dev_mail_rebuild {
    sqlite3 *db;
    struct dmp_statements statements;
    char stream[DEV_MAIL_STREAM_MAX + 1];
    struct dev_mail_tuple after;
    int64_t previous;
    unsigned char root[32];
    unsigned char old_root[32];
    uint64_t count;
    bool ok;
};

static bool dmp_load(sqlite3 *db, const char *stream, struct dev_mail_tuple *out,
                     unsigned char root[32], uint64_t *count);

/* A missing row is valid only for a new stream; an existing invalid row must
 * never be overwritten as though it owned no root. */
static bool dmp_old_root(sqlite3 *db, const char *stream, unsigned char root[32])
{
    sqlite3_stmt *st=NULL; memset(root,0,32);
    if (sqlite3_prepare_v2(db,"SELECT 1 FROM mail_projection_streams WHERE stream=?1",-1,&st,NULL)!=SQLITE_OK) return false;
    bool ok=sqlite3_bind_text(st,1,stream,-1,SQLITE_STATIC)==SQLITE_OK;
    enum zcl_step rc=ok ? ar_step_checked(st,"mail projection old root",NULL) : ZCL_STEP_ERROR;
    sqlite3_finalize(st);
    if (rc==ZCL_STEP_DONE) return true;
    if (rc!=ZCL_STEP_ROW) return false;
    struct dev_mail_tuple old; uint64_t count;
    if (!dmp_load(db,stream,&old,root,&count)) return false;
    if (dmp_zero_hash(root)) return true;
    unsigned char body[DMP_NODE_MAX]; size_t n;
    return dmp_node_live(db,NULL,root,body,&n);
}

static bool dmp_retain_root(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32]);

struct dev_mail_rebuild *dev_mail_projection_begin(sqlite3 *db, const char *stream,
                                                    const struct dev_mail_tuple *after)
{
    if (!db || !dmp_valid(stream,after)) return NULL;
    struct dev_mail_rebuild *tx = zcl_calloc(1,sizeof(*tx),"mail_projection.rebuild");
    if (!tx) return NULL;
    tx->db = db; tx->after = *after;
    (void)snprintf(tx->stream,sizeof(tx->stream),"%s",stream);
    if (!dmp_exec(db,"BEGIN IMMEDIATE")) { free(tx); return NULL; }
    if (!dmp_schema(db) || !dmp_version(db) || !dmp_old_root(db,stream,tx->old_root)) {
        dmp_statements_close(&tx->statements);
        (void)dmp_exec(db,"ROLLBACK"); free(tx); return NULL;
    }
    tx->ok = true;
    return tx;
}

struct dev_mail_rebuild *dev_mail_projection_begin_append(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *before, const struct dev_mail_tuple *after)
{
    if (!db || !before || !dmp_valid(stream,after) || !dmp_append_valid(stream,before,after)) return NULL;
    struct dev_mail_rebuild *tx=zcl_calloc(1,sizeof(*tx),"mail_projection.append");
    if (!tx) return NULL;
    tx->db=db; tx->after=*after; tx->previous=before->frontier;
    (void)snprintf(tx->stream,sizeof(tx->stream),"%s",stream);
    if (!dmp_exec(db,"BEGIN IMMEDIATE")) { free(tx); return NULL; }
    struct dev_mail_tuple stored;
    if (!dmp_version(db) || !dmp_load(db,stream,&stored,tx->root,&tx->count) ||
        !dmp_match(db,stream,before) || !dmp_retain_root(db,&tx->statements,tx->root)) {
        dmp_statements_close(&tx->statements);
        (void)dmp_exec(db,"ROLLBACK"); free(tx); return NULL;
    }
    memcpy(tx->old_root,tx->root,32); tx->ok=true; return tx;
}

bool dev_mail_projection_add(struct dev_mail_rebuild *tx, const struct dev_mail_locator *row)
{
    if (!tx || !tx->ok || !row) { if (tx) tx->ok = false; return false; }
    unsigned char root[32];
    tx->ok = tx->count<INT64_MAX && row->offset>=tx->previous && row->end<=tx->after.frontier &&
             dmp_trie_append(tx->db,&tx->statements,tx->root,row,root);
    if (tx->ok) tx->ok = dmp_ref_update(tx->db,&tx->statements,root,true) && dmp_release(tx->db,&tx->statements,tx->root);
    if (tx->ok) { tx->previous = row->end; tx->count++; memcpy(tx->root,root,32); }
    return tx->ok;
}

bool dev_mail_projection_commit(struct dev_mail_rebuild *tx)
{
    if (!tx) return false;
    bool ok = tx->ok && dmp_save(tx->db,tx->stream,&tx->after,tx->root,tx->count) &&
              dmp_release(tx->db,&tx->statements,tx->old_root) && dmp_exec(tx->db,"COMMIT");
    if (!ok) (void)dmp_exec(tx->db,"ROLLBACK");
    dmp_statements_close(&tx->statements);
    free(tx);
    return ok;
}

bool dev_mail_projection_commit_scanned(struct dev_mail_rebuild *tx,
                                        const struct dev_mail_tuple *final)
{
    if (!tx) return false;
    const struct dev_mail_tuple *initial=&tx->after;
    bool same=final && dmp_valid(tx->stream,final) && !strcmp(initial->boot,final->boot) &&
        initial->dev==final->dev && initial->inode==final->inode && initial->size==final->size &&
        initial->mtime_ns==final->mtime_ns && initial->ctime_ns==final->ctime_ns && initial->frontier==final->frontier &&
        !memcmp(initial->source_sha3,final->source_sha3,32);
    if (!same) { dev_mail_projection_abort(tx); return false; }
    tx->after.skipped=final->skipped;
    return dev_mail_projection_commit(tx);
}

void dev_mail_projection_abort(struct dev_mail_rebuild *tx)
{
    if (!tx) return;
    dmp_statements_close(&tx->statements);
    (void)dmp_exec(tx->db,"ROLLBACK");
    free(tx);
}

static bool dmp_tuple_read(sqlite3_stmt *st, const char *stream, struct dev_mail_tuple *out)
{
    for (int i=1;i<9;i++) if (sqlite3_column_type(st,i)!=SQLITE_INTEGER) return false;
    const char *boot=(const char *)sqlite3_column_text(st,0);
    if (sqlite3_column_type(st,0)!=SQLITE_TEXT || !boot || sqlite3_column_bytes(st,0)!=36) return false;
    memcpy(out->boot,boot,36); out->boot[36]=0;
    out->dev=sqlite3_column_int64(st,1); out->inode=sqlite3_column_int64(st,2);
    out->size=sqlite3_column_int64(st,3); out->mtime_ns=sqlite3_column_int64(st,4);
    out->ctime_ns=sqlite3_column_int64(st,5); out->frontier=sqlite3_column_int64(st,6);
    out->skipped=sqlite3_column_int64(st,7); out->partial=sqlite3_column_int64(st,8)!=0;
    return dmp_valid(stream,out);
}

static bool dmp_seal_read(sqlite3_stmt *st, const char *stream, const struct dev_mail_tuple *out,
                          unsigned char root[32], uint64_t *count)
{
    if (sqlite3_column_type(st,9)!=SQLITE_BLOB || sqlite3_column_bytes(st,9)!=32 ||
        sqlite3_column_type(st,10)!=SQLITE_INTEGER || sqlite3_column_int64(st,10)<0 ||
        sqlite3_column_type(st,11)!=SQLITE_BLOB || sqlite3_column_bytes(st,11)!=32) return false;
    const void *root_blob=sqlite3_column_blob(st,9), *seal_blob=sqlite3_column_blob(st,11);
    if (!root_blob || !seal_blob) return false;
    memcpy(root,root_blob,32); *count=(uint64_t)sqlite3_column_int64(st,10);
    unsigned char seal[32]; dmp_meta_seal(stream,out,root,*count,seal);
    return dmp_zero_hash(root)==(*count==0) && !memcmp(seal,seal_blob,32);
}

static bool dmp_load_row(sqlite3_stmt *st,const char *stream,struct dev_mail_tuple *out,
                         unsigned char root[32],uint64_t *count)
{
    if (!dmp_tuple_read(st,stream,out) || sqlite3_column_type(st,12)!=SQLITE_BLOB ||
        sqlite3_column_bytes(st,12)!=32 || !sqlite3_column_blob(st,12)) return false;
    memcpy(out->source_sha3,sqlite3_column_blob(st,12),32);
    return dmp_seal_read(st,stream,out,root,count) && ar_step_checked(st,"mail projection metadata",NULL)==ZCL_STEP_DONE;
}
static bool dmp_load(sqlite3 *db, const char *stream, struct dev_mail_tuple *out,
                     unsigned char root[32], uint64_t *count)
{
    if (!out) return false;
    memset(out,0,sizeof(*out));
    if (!db || !stream || !stream[0] || strnlen(stream,DEV_MAIL_STREAM_MAX+1)>DEV_MAIL_STREAM_MAX || !dmp_version(db)) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,"SELECT boot,dev,ino,size,mt,ct,frontier,skipped,partial,root,entry_count,seal,source_sha3 FROM mail_projection_streams WHERE stream=?1",-1,&st,NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(st,1,stream,-1,SQLITE_STATIC) == SQLITE_OK && ar_step_checked(st,"mail projection select",NULL)==ZCL_STEP_ROW;
    if (ok) ok=dmp_load_row(st,stream,out,root,count);
    sqlite3_finalize(st);
    if (!ok) memset(out,0,sizeof(*out));
    return ok;
}

bool dev_mail_projection_get(sqlite3 *db, const char *stream, struct dev_mail_tuple *out)
{
    unsigned char root[32]; uint64_t count;
    return dmp_load(db,stream,out,root,&count);
}

static bool dmp_retain_root(sqlite3 *db, struct dmp_statements *cache, const unsigned char root[32])
{
    if (dmp_zero_hash(root)) return true;
    unsigned char body[DMP_NODE_MAX]; size_t n;
    return dmp_node_live(db,cache,root,body,&n) && dmp_ref_update(db,cache,root,true);
}

bool dev_mail_projection_rebuild(sqlite3 *db, const char *stream, const struct dev_mail_tuple *after,
                                  const struct dev_mail_locator *rows, size_t count)
{
    if (count && !rows) return false;
    struct dev_mail_rebuild *tx=dev_mail_projection_begin(db,stream,after);
    if (!tx) return false;
    for (size_t i=0;i<count;i++) if (!dev_mail_projection_add(tx,&rows[i])) {
        dev_mail_projection_abort(tx); return false;
    }
    return dev_mail_projection_commit(tx);
}
bool dev_mail_projection_append(sqlite3 *db, const char *stream, const struct dev_mail_tuple *before,
                                 const struct dev_mail_tuple *after, const struct dev_mail_locator *rows, size_t count)
{
    if (count && !rows) return false;
    struct dev_mail_rebuild *tx=dev_mail_projection_begin_append(db,stream,before,after);
    if (!tx) return false;
    for (size_t i=0;i<count;i++) if (!dev_mail_projection_add(tx,&rows[i])) {
        dev_mail_projection_abort(tx); return false;
    }
    return dev_mail_projection_commit(tx);
}

static bool dmp_postings(sqlite3 *db, const struct dmp_leaf *leaf, int64_t frontier,
                         struct dev_mail_locator *out, size_t capacity, size_t *count)
{
    if (leaf->count>capacity) return false;
    unsigned char current[32]; memcpy(current,leaf->head,32);
    int64_t upper=frontier;
    for (uint64_t i=leaf->count; i>0; i--) {
        unsigned char prev[32]; struct dev_mail_locator *r=&out[i-1];
        if (dmp_zero_hash(current) || !dmp_post_get(db,NULL,current,r,prev) || r->end>upper) return false;
        (void)snprintf(r->ref,sizeof(r->ref),"%s",leaf->ref);
        upper=r->offset; memcpy(current,prev,32);
    }
    if (!dmp_zero_hash(current)) return false;
    *count=(size_t)leaf->count;
    return true;
}

static bool dmp_find_input(sqlite3 *db, const char *stream, const struct dev_mail_tuple *expected,
                           const char *ref, const struct dev_mail_locator *out, size_t capacity)
{
    return db && dmp_valid(stream,expected) && ref &&
           strnlen(ref,DEV_MAIL_REF_MAX+1)<=DEV_MAIL_REF_MAX && (!capacity || out);
}

bool dev_mail_projection_find(sqlite3 *db, const char *stream, const struct dev_mail_tuple *expected,
                              const char *ref, struct dev_mail_locator *out, size_t capacity, size_t *count)
{
    if (!count) return false;
    *count=0;
    if (!dmp_find_input(db,stream,expected,ref,out,capacity) || !dmp_exec(db,"BEGIN")) return false;
    struct dev_mail_tuple stored; unsigned char root[32]; uint64_t total=0;
    struct dmp_leaf leaf; bool found=false; size_t n=0;
    bool ok=dmp_load(db,stream,&stored,root,&total) && dmp_match(db,stream,expected) &&
            dmp_trie_lookup(db,NULL,root,ref,&leaf,&found);
    if (ok && found) ok=leaf.count<=total && dmp_postings(db,&leaf,expected->frontier,out,capacity,&n);
    if (ok && dmp_exec(db,"COMMIT")) { *count=n; return true; }
    (void)dmp_exec(db,"ROLLBACK"); return false;
}

/* This diagnostic does not turn an unavailable query into an answer. It only
 * proves particular authenticated-node defects so a caller holding every
 * native stream lock may discard the derived cache. */
static enum dev_mail_probe_result dmp_probe_fetch(sqlite3 *db,const unsigned char hash[32],
                                                   unsigned char body[DMP_NODE_MAX],size_t *n)
{
    sqlite3_stmt *st=NULL; *n=0;
    if (sqlite3_prepare_v2(db,"SELECT body,refs FROM mail_projection_nodes WHERE hash=?1",-1,&st,NULL)!=SQLITE_OK) return DEV_MAIL_PROBE_UNKNOWN;
    if (sqlite3_bind_blob(st,1,hash,32,SQLITE_STATIC)!=SQLITE_OK) { sqlite3_finalize(st); return DEV_MAIL_PROBE_UNKNOWN; }
    enum zcl_step rc=ar_step_checked(st,"mail projection probe",NULL);
    if (rc==ZCL_STEP_DONE) { sqlite3_finalize(st); return DEV_MAIL_PROBE_CORRUPT; }
    if (rc!=ZCL_STEP_ROW) { sqlite3_finalize(st); return DEV_MAIL_PROBE_UNKNOWN; }
    bool shape=sqlite3_column_type(st,0)==SQLITE_BLOB && sqlite3_column_type(st,1)==SQLITE_INTEGER && sqlite3_column_int64(st,1)>0;
    int len=shape ? sqlite3_column_bytes(st,0) : 0;
    if (!shape || len<=0 || len>DMP_NODE_MAX) { sqlite3_finalize(st); return DEV_MAIL_PROBE_CORRUPT; }
    const void *p=sqlite3_column_blob(st,0);
    if (!p) { sqlite3_finalize(st); return DEV_MAIL_PROBE_UNKNOWN; }
    memcpy(body,p,(size_t)len); *n=(size_t)len;
    rc=ar_step_checked(st,"mail projection probe",NULL);
    sqlite3_finalize(st);
    if (rc!=ZCL_STEP_DONE) return rc==ZCL_STEP_ROW ? DEV_MAIL_PROBE_CORRUPT : DEV_MAIL_PROBE_UNKNOWN;
    unsigned char actual[32]; dmp_node_hash(body,*n,actual);
    return memcmp(actual,hash,32) ? DEV_MAIL_PROBE_CORRUPT : DEV_MAIL_PROBE_CLEAN;
}

static enum dev_mail_probe_result dmp_probe_postings(sqlite3 *db,const struct dmp_leaf *leaf,
                                                      int64_t frontier,size_t cap)
{
    if (leaf->count>cap) return DEV_MAIL_PROBE_UNKNOWN;
    unsigned char current[32]; memcpy(current,leaf->head,32); int64_t upper=frontier;
    for (uint64_t i=0;i<leaf->count;i++) {
        unsigned char body[DMP_NODE_MAX]; size_t n;
        if (dmp_zero_hash(current)) return DEV_MAIL_PROBE_CORRUPT;
        enum dev_mail_probe_result r=dmp_probe_fetch(db,current,body,&n);
        if (r!=DEV_MAIL_PROBE_CLEAN) return r;
        unsigned char children[2][32]; size_t count;
        if (!dmp_children(body,n,children,&count) || body[0]!='P') return DEV_MAIL_PROBE_CORRUPT;
        uint64_t off=dmp_u64_get(body+1), end=dmp_u64_get(body+9);
        if (end>(uint64_t)upper) return DEV_MAIL_PROBE_CORRUPT;
        upper=(int64_t)off; memcpy(current,body+57,32);
    }
    return dmp_zero_hash(current) ? DEV_MAIL_PROBE_CLEAN : DEV_MAIL_PROBE_CORRUPT;
}

static enum dev_mail_probe_result dmp_probe_leaf(sqlite3 *db,const unsigned char *body,size_t n,
    const unsigned char key[32],const char *ref,int parent,const unsigned char prefix[32],
    unsigned side,int64_t frontier,uint64_t total,size_t cap)
{
    struct dmp_leaf leaf;
    if (!dmp_leaf_decode(body,n,&leaf) ||
        (parent>=0 && !dmp_child_valid(leaf.key,(unsigned)parent,prefix,side))) return DEV_MAIL_PROBE_CORRUPT;
    if (memcmp(key,leaf.key,32)) return DEV_MAIL_PROBE_CLEAN;
    if (strcmp(ref,leaf.ref)) return DEV_MAIL_PROBE_UNKNOWN;
    if (leaf.count>total) return DEV_MAIL_PROBE_CORRUPT;
    return dmp_probe_postings(db,&leaf,frontier,cap);
}
static enum dev_mail_probe_result dmp_probe_walk(sqlite3 *db,const unsigned char root[32],
                                                 const char *ref,int64_t frontier,uint64_t total,size_t cap)
{
    unsigned char key[32],current[32],parent_prefix[32]={0};
    dmp_ref_key(ref,strlen(ref),key); memcpy(current,root,32);
    if (dmp_zero_hash(current)) return DEV_MAIL_PROBE_CLEAN;
    int parent=-1; unsigned side=0;
    for (unsigned depth=0;depth<=256;depth++) {
        unsigned char body[DMP_NODE_MAX]; size_t n;
        enum dev_mail_probe_result r=dmp_probe_fetch(db,current,body,&n);
        if (r!=DEV_MAIL_PROBE_CLEAN) return r;
        if (body[0]=='L') return dmp_probe_leaf(db,body,n,key,ref,parent,parent_prefix,side,frontier,total,cap);
        struct dmp_branch b;
        if (!dmp_branch_decode(body,n,&b) || (parent>=0 && b.bit<=(unsigned)parent) ||
            (parent>=0 && !dmp_child_valid(b.prefix,(unsigned)parent,parent_prefix,side))) return DEV_MAIL_PROBE_CORRUPT;
        for (size_t i=0;i<2;i++) {
            unsigned char child[DMP_NODE_MAX]; size_t child_n;
            r=dmp_probe_fetch(db,b.child[i],child,&child_n);
            if (r!=DEV_MAIL_PROBE_CLEAN) return r;
        }
        unsigned char prefix[32]; dmp_prefix(prefix,key,b.bit);
        if (memcmp(prefix,b.prefix,32)) return DEV_MAIL_PROBE_CLEAN;
        parent=(int)b.bit; side=dmp_key_bit(key,b.bit);
        memcpy(parent_prefix,b.prefix,32); memcpy(current,b.child[side],32);
    }
    return DEV_MAIL_PROBE_CORRUPT;
}

enum dev_mail_probe_result dev_mail_projection_probe(sqlite3 *db,const char *stream,
    const struct dev_mail_tuple *expected,const char *ref,size_t cap)
{
    if (!db || !dmp_valid(stream,expected) || !ref || strnlen(ref,DEV_MAIL_REF_MAX+1)>DEV_MAIL_REF_MAX || !dmp_exec(db,"BEGIN")) return DEV_MAIL_PROBE_UNKNOWN;
    struct dev_mail_tuple stored; unsigned char root[32]; uint64_t total=0;
    enum dev_mail_probe_result result=DEV_MAIL_PROBE_UNKNOWN;
    if (dmp_load(db,stream,&stored,root,&total) && dmp_match(db,stream,expected))
        result=dmp_probe_walk(db,root,ref,expected->frontier,total,cap);
    if (!dmp_exec(db,"COMMIT")) { (void)dmp_exec(db,"ROLLBACK"); return DEV_MAIL_PROBE_UNKNOWN; }
    return result;
}
