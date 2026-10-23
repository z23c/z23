/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded native-C support for the Arena product journey. */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "json/json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define INPUT_MAX (4u * 1024u * 1024u)
#define CONTACT_HEADER 78u
#define CONTACT_ENTRY 303u

static bool read_stream(FILE *f, uint8_t **out, size_t *len)
{
    size_t cap=4096, used=0;
    uint8_t *p=zcl_malloc(cap, "arena_product_journey_stream");
    if (!p) return false;
    for (;;) {
        if (used==cap) { if (cap>=INPUT_MAX) { free(p); return false; }
            size_t nc=cap*2; if (nc>INPUT_MAX) nc=INPUT_MAX;
            uint8_t *q=zcl_realloc(p,nc, "arena_product_journey_stream");
            if (!q) { free(p); return false; } p=q; cap=nc; }
        size_t n=fread(p+used,1,cap-used,f); used+=n;
        if (n==0) { if (ferror(f)) { free(p); return false; } break; }
    }
    *out=p; *len=used; return true;
}
static bool read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f=fopen(path,"rb"); if (!f) return false;
    bool ok=read_stream(f,out,len); if (fclose(f)!=0) ok=false; return ok;
}
static bool write_file(const char *path, const uint8_t *p, size_t n)
{
    FILE *f=fopen(path,"wb"); if (!f) return false;
    bool ok=(n==0 || fwrite(p,1,n,f)==n); return fclose(f)==0 && ok;
}
static bool parse_text(const char *s, struct json_value *v)
{ json_init(v); return s && json_read(v,s,strlen(s)); }
static bool parse_stdin(struct json_value *v)
{
    uint8_t *p=NULL; size_t n=0; bool ok=read_stream(stdin,&p,&n);
    json_init(v); if (ok) ok=json_read(v,(const char *)p,n); free(p); return ok;
}
static const struct json_value *path_get(const struct json_value *v,const char *path)
{
    char part[128]; const char *p=path;
    while (v && p && *p) {
        const char *dot=strchr(p,'.'); size_t n=dot?(size_t)(dot-p):strlen(p);
        if (!n || n>=sizeof(part)) return NULL;
        memcpy(part,p,n); part[n]='\0';
        if (v->type==JSON_OBJ) v=json_get(v,part);
        else if (v->type==JSON_ARR) { char *end=NULL; errno=0;
            unsigned long x=strtoul(part,&end,10); if (errno||!end||*end) return NULL;
            v=json_at(v,(size_t)x); }
        else return NULL;
        p=dot?dot+1:NULL;
    }
    return v;
}
static bool print_value(const struct json_value *v)
{
    if (!v) return false;
    switch (v->type) {
    case JSON_BOOL: puts(v->val.b?"True":"False"); return true;
    case JSON_INT: printf("%" PRId64 "\n",v->val.i); return true;
    case JSON_REAL: printf("%.17g\n",v->val.d); return true;
    case JSON_STR: puts(v->val.s?v->val.s:""); return true;
    case JSON_NULL: puts("null"); return true;
    default: { size_t n=json_write(v,NULL,0); char *s=zcl_malloc(n+1, "arena_product_journey_json"); if(!s)return false;
        bool ok=json_write(v,s,n+1)==n; if(ok) puts(s); free(s); return ok; }
    }
}
static bool get_i(const struct json_value *v,const char *p,int64_t *out)
{ const struct json_value *x=path_get(v,p); if(!x||x->type!=JSON_INT)return false; *out=x->val.i; return true; }
static bool get_b(const struct json_value *v,const char *p,bool *out)
{ const struct json_value *x=path_get(v,p); if(!x||x->type!=JSON_BOOL)return false; *out=x->val.b; return true; }
static const char *get_s(const struct json_value *v,const char *p)
{ const struct json_value *x=path_get(v,p); return x&&x->type==JSON_STR?x->val.s:NULL; }

static int json_get_mode(int argc,char **argv)
{
    struct json_value v; if(argc<3||!parse_stdin(&v)) return 1;
    const struct json_value *x=path_get(&v,argv[2]); bool ok;
    if (!x && argc>=4) { puts(argv[3]); ok=true; } else ok=print_value(x);
    json_free(&v); return ok?0:1;
}
static int rpc_result(int argc,char **argv)
{
    (void)argc;(void)argv;
    struct json_value v; if(!parse_stdin(&v))return 1;
    const struct json_value *e=json_get(&v,"error"),*r=json_get(&v,"result");
    bool ok=e&&e->type==JSON_NULL&&print_value(r); json_free(&v); return ok?0:2;
}
static bool hex32(const char *s,uint8_t out[32])
{
    return s && zcl_hex_decode_lower(s, out, 32);
}
static int ids_distinct(int argc,char **argv)
{
    if(argc!=9)return 2;
    for(int i=2;i<9;i++){uint8_t x[32];if(!hex32(argv[i],x))return 1;
        for(int j=2;j<i;j++)if(strcmp(argv[i],argv[j])==0)return 1;} return 0;
}
static int xor_cmp(const uint8_t a[32],const uint8_t b[32],const uint8_t t[32])
{ for(size_t i=0;i<32;i++){uint8_t x=a[i]^t[i],y=b[i]^t[i];if(x!=y)return x>y?1:-1;} return memcmp(a,b,32); }
static int xor_order(int argc,char **argv)
{
    if(argc!=9)return 2;
    uint8_t id[7][32]; int order[6]={0,1,2,3,4,5};
    for(int i=0;i<7;i++)if(!hex32(argv[i+2],id[i]))return 1;
    for(int i=0;i<6;i++)for(int j=i+1;j<6;j++)if(xor_cmp(id[order[i]],id[order[j]],id[6])<0){int q=order[i];order[i]=order[j];order[j]=q;}
    for(int i=0;i<6;i++)printf("%d ",order[i]);
    puts("6"); return 0;
}
static int open_listener(int family,uint16_t port,bool loopback)
{
    int fd=socket(family,SOCK_STREAM,0),one=1;
    if(fd<0)return -1;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))<0)goto failed;
    if(family==AF_INET6){
        struct sockaddr_in6 a={.sin6_family=AF_INET6,.sin6_port=htons(port)};
        a.sin6_addr=loopback?in6addr_loopback:in6addr_any;
        if(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))<0||
           bind(fd,(struct sockaddr*)&a,sizeof(a))<0)goto failed;
    }else{
        struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(loopback?INADDR_LOOPBACK:INADDR_ANY),.sin_port=htons(port)};
        if(bind(fd,(struct sockaddr*)&a,sizeof(a))<0)goto failed;
    }
    if(listen(fd,1)<0)goto failed;
    return fd;
failed:
    close(fd);return -1;
}
static uint16_t listener_port(int fd,int family)
{
    if(family==AF_INET6){
        struct sockaddr_in6 a; socklen_t len=sizeof(a);
        return getsockname(fd,(struct sockaddr*)&a,&len)<0?0:ntohs(a.sin6_port);
    }
    struct sockaddr_in a; socklen_t len=sizeof(a);
    return getsockname(fd,(struct sockaddr*)&a,&len)<0?0:ntohs(a.sin_port);
}
/* BSD stacks let a wildcard bind succeed beside a listener on a specific
 * address under SO_REUSEADDR; binding the loopback address first detects that
 * holder. Linux fails both binds for any holder. */
static int open_unheld_listener(int family,uint16_t port)
{
    int held=open_listener(family,port,true);
    if(held<0)return -1;
    close(held);
    return open_listener(family,port,false);
}
static int ports_rebind(int argc,char **argv)
{
    if(argc<3)return 2;
    size_t count=(size_t)(argc-2)*2;
    int *fds=zcl_calloc(count,sizeof(*fds),"arena_product_journey_fds");
    if(!fds)return 1;
    for(size_t i=0;i<count;i++)fds[i]=-1;
    int rc=0;
    for(int i=2;i<argc;i++){
        char *e=NULL; long port=strtol(argv[i],&e,10);
        if(!e||*e||port<1||port>65535){rc=1;break;}
        for(int family=0;family<2;family++){
            int fd=open_unheld_listener(family?AF_INET6:AF_INET,(uint16_t)port);
            if(fd<0){rc=1;break;}
            fds[(size_t)(i-2)*2+(size_t)family]=fd;
        }
        if(rc)break;
    }
    for(size_t i=0;i<count;i++)if(fds[i]>=0)close(fds[i]);
    free(fds);return rc;
}
static int listen_report(int argc,char **argv)
{
    if(argc!=3 && (argc!=4 || strcmp(argv[3],"v6")))return 2;
    int family=argc==4?AF_INET6:AF_INET;
    int fd=open_listener(family,0,true);
    if(fd<0)return 1;
    uint16_t port=listener_port(fd,family);
    if(!port){close(fd);return 1;}
    char tmp[4096];if(snprintf(tmp,sizeof(tmp),"%s.tmp",argv[2])<1)return 1;FILE*f=fopen(tmp,"w");if(!f)return 1;
    bool ok=fprintf(f,"%ld %u\n",(long)getpid(),(unsigned)port)>0&&fclose(f)==0&&rename(tmp,argv[2])==0;if(!ok)return 1;for(;;)pause();
}
static int chain_loaded(int argc,char **argv)
{
    if(argc!=3)return 2;
    struct json_value v;if(!parse_stdin(&v))return 1;int64_t blocks=0;long tip=strtol(argv[2],NULL,10);
    const struct json_value *ibd=path_get(&v,"result.initialblockdownload");
    bool explicitly_ibd=ibd&&ibd->type==JSON_BOOL&&ibd->val.b;
    bool ok=get_i(&v,"result.blocks",&blocks)&&blocks==tip&&!explicitly_ibd;
    json_free(&v);puts(ok?"True":"False");return 0;
}
static bool load_json_arg(const char*s,struct json_value*v){return parse_text(s,v);}
static const struct json_value *find_rows(const struct json_value *v)
{
    bool yes=false;const struct json_value *rows=path_get(v,"data.node_ids");
    return get_b(v,"ok",&yes)&&yes&&rows&&rows->type==JSON_ARR&&rows->num_children==2?rows:NULL;
}
static bool find_hex_args(char **argv,uint8_t t[32],uint8_t a[32],uint8_t b[32])
{
    return hex32(argv[3],t)&&hex32(argv[4],a)&&hex32(argv[5],b);
}
static bool find_pair_ok(const struct json_value *rows,const char *lo,const char *hi,const uint8_t t[32])
{
    const char*x=get_s(rows,"0"),*y=get_s(rows,"1");uint8_t hx[32],hy[32];
    bool ok=x&&y&&((strcmp(x,lo)==0&&strcmp(y,hi)==0)||(strcmp(x,hi)==0&&strcmp(y,lo)==0));
    return ok&&hex32(x,hx)&&hex32(y,hy)&&xor_cmp(hx,hy,t)<=0;
}
static int find_check(int argc,char **argv)
{
    if(argc!=6)return 2;
    struct json_value v;if(!load_json_arg(argv[2],&v))return 1;uint8_t t[32],a[32],b[32];
    const struct json_value *rows=find_rows(&v);
    bool ok=rows&&find_hex_args(argv,t,a,b)&&find_pair_ok(rows,argv[4],argv[5],t);
    json_free(&v);return ok?0:1;
}
static int contacts_check(int argc,char **argv)
{
    if(argc!=5)return 2;
    uint8_t*p=NULL,self[32];size_t n=0;long want=strtol(argv[4],NULL,10);if(!read_file(argv[2],&p,&n)||!hex32(argv[3],self)){free(p);return 1;}
    bool ok=n>=CONTACT_HEADER&&!memcmp(p,"ZCDHTC\r\n",8)&&zcl_read_u16_le(p+8)==2&&!memcmp(p+42,self,32);uint32_t count=ok?zcl_read_u32_le(p+74):0;ok=ok&&count==(uint32_t)want&&n==CONTACT_HEADER+(size_t)count*CONTACT_ENTRY;
    for(uint32_t i=1;ok&&i<count;i++)ok=memcmp(p+CONTACT_HEADER+(i-1)*CONTACT_ENTRY,p+CONTACT_HEADER+i*CONTACT_ENTRY,32)<0;
    free(p);return ok?0:1;
}
static int contact_reduce(int argc,char **argv)
{
    if(argc!=4)return 2;
    uint8_t*p=NULL,want[32];size_t n=0;if(!read_file(argv[2],&p,&n)||!hex32(argv[3],want)||n<CONTACT_HEADER){free(p);return 1;}uint32_t c=zcl_read_u32_le(p+74);if(c<3||n!=CONTACT_HEADER+(size_t)c*CONTACT_ENTRY){free(p);return 1;}
    uint8_t*found=NULL;for(uint32_t i=0;i<c;i++){uint8_t*e=p+CONTACT_HEADER+i*CONTACT_ENTRY;if(i&&memcmp(e-CONTACT_ENTRY,e,32)>=0){free(p);return 1;}if(!memcmp(e,want,32)){if(found){free(p);return 1;}found=e;}}
    if(!found){free(p);return 1;}uint8_t out[CONTACT_HEADER+CONTACT_ENTRY];memcpy(out,p,74);zcl_write_u32_le(out+74,1);memcpy(out+CONTACT_HEADER,found,CONTACT_ENTRY);free(p);return write_file(argv[2],out,sizeof(out))?0:1;
}
static int array_match_get(int argc,char **argv)
{
    if(argc!=7)return 2;
    struct json_value v;if(!parse_stdin(&v))return 1;const struct json_value*a=path_get(&v,argv[2]);const struct json_value*out=NULL;
    if(a&&a->type==JSON_ARR)for(size_t i=0;i<a->num_children;i++){const struct json_value*m=json_get(&a->children[i],argv[3]);if(m&&m->type==JSON_STR&&!strcmp(m->val.s,argv[4])){out=json_get(&a->children[i],argv[5]);break;}}
    bool ok=print_value(out);json_free(&v);return ok?0:1;
}
static bool array_has_string(const struct json_value *a,const char *s)
{if(!a||a->type!=JSON_ARR)return false;for(size_t i=0;i<a->num_children;i++)if(a->children[i].type==JSON_STR&&!strcmp(a->children[i].val.s,s))return true;return false;}
static const char *const attack_keys[6]={"malformed","identity","replay","unsolicited","expired","poisoned-contacts"};
static const int64_t attack_want[6]={2,1,1,1,1,1};
static bool attack_named_deltas(const struct json_value *b,const struct json_value *a)
{
    bool ok=true;
    for(size_t i=0;i<6;i++){char p[128];int64_t x=0,y=0;snprintf(p,sizeof(p),"data.frames_rejected.%s",attack_keys[i]);ok=ok&&get_i(b,p,&x)&&get_i(a,p,&y)&&y-x==attack_want[i];}
    return ok;
}
static bool attack_entry_ok(const struct json_value *bo,const struct json_value *ao,size_t i)
{
    const struct json_value *bv=json_get(bo,ao->keys[i]);
    bool named=false;for(size_t j=0;j<6;j++)if(!strcmp(ao->keys[i],attack_keys[j]))named=true;
    return bv&&bv->type==JSON_INT&&ao->children[i].type==JSON_INT&&(named||ao->children[i].val.i-bv->val.i==0);
}
static bool attack_rejected_ok(const struct json_value *b,const struct json_value *a)
{
    const struct json_value *bo=path_get(b,"data.frames_rejected"),*ao=path_get(a,"data.frames_rejected");
    bool ok=bo&&ao&&bo->type==JSON_OBJ&&ao->type==JSON_OBJ&&bo->num_children==ao->num_children;
    for(size_t i=0;ok&&i<ao->num_children;i++)ok=attack_entry_ok(bo,ao,i);
    return ok;
}
static int attack_deltas(int argc,char **argv)
{
    if(argc!=4)return 2;
    struct json_value b,a;if(!parse_text(argv[2],&b)||!parse_text(argv[3],&a))return 1;
    bool ok=attack_named_deltas(&b,&a)&&attack_rejected_ok(&b,&a);
    int64_t x=0,y=0;ok=ok&&get_i(&b,"data.frames_accepted",&x)&&get_i(&a,"data.frames_accepted",&y)&&y-x>=1;json_free(&b);json_free(&a);return ok?0:1;
}
static bool journey_target_ok(const struct json_value *r,const char *target,int64_t min_rounds)
{
    bool yes=false;int64_t rounds=0;const char*t=get_s(r,"data.termination");const struct json_value*ids=path_get(r,"data.node_ids");
    return get_b(r,"ok",&yes)&&yes&&t&&!strcmp(t,"target_authenticated")&&get_i(r,"data.rounds",&rounds)&&rounds>=min_rounds&&array_has_string(ids,target);
}
static bool sparse_progress_ok(const struct json_value *r)
{
    int64_t progress=0;
    return get_i(r,"data.xor_progress",&progress)&&progress>=3;
}
static bool sparse_traffic_ok(const struct json_value *b,const struct json_value *a)
{
    int64_t bs=0,as=0,bf=0,af=0;
    return get_i(b,"data.find_node_sent",&bs)&&get_i(a,"data.find_node_sent",&as)&&as-bs<=24&&get_i(b,"data.frames_accepted",&bf)&&get_i(a,"data.frames_accepted",&af)&&af-bf<=64;
}
static int sparse_proof(int argc,char **argv)
{
    if(argc!=6)return 2;
    struct json_value r,b,a;if(!parse_text(argv[2],&r)||!parse_text(argv[3],&b)||!parse_text(argv[4],&a))return 1;
    bool ok=journey_target_ok(&r,argv[5],3)&&sparse_progress_ok(&r)&&sparse_traffic_ok(&b,&a);
    json_free(&r);json_free(&b);json_free(&a);return ok?0:1;
}
static int begin_fields(int argc,char **argv)
{if(argc!=3)return 2;uint8_t*p=NULL;size_t n=0;if(!read_file(argv[2],&p,&n))return 1;struct json_value v;json_init(&v);bool ok=json_read(&v,(char*)p,n);free(p);if(!ok)return 1;const char*x=get_s(&v,"data.lookup_id"),*y=get_s(&v,"data.owner_token");if(x&&y)printf("%s %s\n",x,y);else ok=false;json_free(&v);return ok?0:1;}
static bool burst_copy_begin(const struct json_value *v,char id[64],char owner[64])
{
    bool yes=false;
    const char *state=get_s(v,"data.state"),*lookup=get_s(v,"data.lookup_id"),*token=get_s(v,"data.owner_token");
    bool ok=get_b(v,"ok",&yes)&&yes&&state&&!strcmp(state,"pending")&&lookup&&token&&strlen(lookup)<64&&strlen(token)<64;
    if(ok){strcpy(id,lookup);strcpy(owner,token);}
    return ok;
}
static bool burst_load_begin(const char *dir,int index,char id[64],char owner[64])
{
    char path[4096];uint8_t*p=NULL;size_t n=0;struct json_value v;
    snprintf(path,sizeof(path),"%s/%d.begin.json",dir,index+1);json_init(&v);
    if(!read_file(path,&p,&n))return false;
    bool parsed=json_read(&v,(char*)p,n);free(p);
    bool ok=parsed&&burst_copy_begin(&v,id,owner);
    json_free(&v);return ok;
}
static bool burst_unique_at(char ids[8][64],char owners[8][64],int i)
{
    for(int j=0;j<i;j++)if(!strcmp(ids[i],ids[j])||!strcmp(owners[i],owners[j]))return false;
    return true;
}
static bool burst_begins_ok(const char *dir)
{
    char ids[8][64],owners[8][64];
    for(int i=0;i<8;i++)if(!burst_load_begin(dir,i,ids[i],owners[i])||!burst_unique_at(ids,owners,i))return false;
    return true;
}
static bool burst_queue_ok(const char *text)
{
    struct json_value s;int64_t q=0,a=0;
    if(!parse_text(text,&s))return false;
    bool ok=get_i(&s,"data.queued_lookups",&q)&&q==8&&get_i(&s,"data.active_queries",&a)&&a==3;
    json_free(&s);
    return ok;
}
static int burst_proof(int argc,char **argv)
{
    if(argc!=4)return 2;
    return burst_begins_ok(argv[2])&&burst_queue_ok(argv[3])?0:1;
}
static bool cold_reach_ok(const struct json_value *b,const struct json_value *a)
{
    int64_t entries=0,br=0,ar=0,bd=0,ad=0,auth=0;
    return get_i(a,"data.reachability.entries",&entries)&&entries>=6&&get_i(b,"data.reachability.requests_enqueued",&br)&&get_i(a,"data.reachability.requests_enqueued",&ar)&&get_i(b,"data.reachability.dials_queued",&bd)&&get_i(a,"data.reachability.dials_queued",&ad)&&ad-bd>=2&&ad-bd<=entries-1&&ar-br==ad-bd&&get_i(a,"data.connected_authenticated",&auth)&&auth>=1;
}
static int cold_proof(int argc,char **argv)
{
    if(argc!=6)return 2;
    struct json_value r,b,a;if(!parse_text(argv[2],&r)||!parse_text(argv[3],&b)||!parse_text(argv[4],&a))return 1;
    bool ok=journey_target_ok(&r,argv[5],2)&&cold_reach_ok(&b,&a);
    json_free(&r);json_free(&b);json_free(&a);return ok?0:1;
}
static int evidence_check(int argc,char **argv)
{
    if(argc!=3)return 2;
    struct json_value v;if(!parse_text(argv[2],&v))return 1;bool yes=false,policy=false;const char*authority=get_s(&v,"data.authority");const char*keys[]={"local_submit_us","peer_discovery_us","transfer_us","remote_queue_us","remote_execution_us","receipt_verification_us","total_background_proof_us"};bool ok=get_b(&v,"ok",&yes)&&yes&&get_b(&v,"data.async_timings_available",&yes)&&yes&&get_b(&v,"data.policy_satisfied",&policy)&&policy&&authority&&strcmp(authority,"UNTRUSTED");for(size_t i=0;i<7;i++){char p[128];int64_t x=0;snprintf(p,sizeof(p),"data.latency.%s",keys[i]);ok=ok&&get_i(&v,p,&x)&&x>=0;}json_free(&v);return ok?0:1;
}
static bool replace_once(char **text,size_t *len,const char*old,const char*new)
{
    char*p=strstr(*text,old);if(!p||strstr(p+1,old))return false;size_t a=strlen(old),b=strlen(new),off=(size_t)(p-*text);char*q=zcl_malloc(*len-a+b+1, "arena_product_journey_edit");if(!q)return false;
    memcpy(q,*text,off);memcpy(q+off,new,b);memcpy(q+off+b,p+a,*len-off-a);q[*len-a+b]='\0';free(*text);*text=q;*len=*len-a+b;return true;
}
static bool edit_file(const char*path,const char*const*old,const char*const*new,size_t count)
{uint8_t*p=NULL;size_t n=0;if(!read_file(path,&p,&n))return false;char*s=zcl_malloc(n+1, "arena_product_journey_edit_file");if(!s){free(p);return false;}memcpy(s,p,n);s[n]='\0';free(p);for(size_t i=0;i<count;i++)if(!replace_once(&s,&n,old[i],new[i])){free(s);return false;}bool ok=write_file(path,(uint8_t*)s,n);free(s);return ok;}
static int zdogace_correct(int argc,char **argv)
{
    if(argc!=3)return 2;
    char src[4096],test[4096];if(snprintf(src,sizeof(src),"%s/src/zdogace.c",argv[2])<1||snprintf(test,sizeof(test),"%s/tests/test_zdogace.c",argv[2])<1)return 1;
    const char*so[]={"    /* cross > 0: enemy to the right -> bank right (positive roll). */","    out->roll = clamp15(2 * cross);","    /* Elevation error: normalized rel_y minus own pitch sine. */","    int32_t ep = ryq - zdog_sin16(obs->pitch);\n    out->pitch = clamp15(2 * ep);"};
    const char*sn[]={"    /* cross = sin(yaw - bearing): cross < 0 means the enemy is to the\n     * RIGHT (bearing > yaw), and the sim turns right (yaw increases)\n     * when roll is POSITIVE — so steer roll opposite to cross. */","    out->roll = clamp15(-2 * cross);","    /* Elevation: the sim's forward vertical component is -sin(pitch),\n     * so steer pitch toward -(normalized rel_y + sin(own pitch)). */","    int32_t ep = ryq + zdog_sin16(obs->pitch);\n    out->pitch = clamp15(-2 * ep);"};
    const char*to[]={"    /* Lateral error steers: enemy off to one side gives a non-zero\n     * roll, and the mirror-image bearing gives the exact opposite roll.\n     * (The absolute sign is pinned against the sim's roll->yaw\n     * convention by the arena integration match, not here.) */","    CHECK(a.roll != 0);","    CHECK(b.roll == (int16_t)-a.roll || b.roll == (int16_t)(-a.roll + 1) ||\n          b.roll == (int16_t)(-a.roll - 1));","    /* Enemy above: pitch up. */","    CHECK(a.pitch > 0);"};
    const char*tn[]={"    /* Lateral steering, sign pinned against the sim convention\n     * (positive roll increases yaw, rotating forward from +z toward\n     * +x): enemy at +x while facing +z is to the RIGHT -> roll > 0;\n     * the mirror bearing gives the mirror control. */","    CHECK(a.roll > 0);","    CHECK(b.roll < 0);","    /* Elevation, sign pinned against the sim (forward vertical\n     * component is -sin(pitch)): enemy above -> pitch < 0 (climb). */","    CHECK(a.pitch < 0);"};
    return edit_file(src,so,sn,4)&&edit_file(test,to,tn,5)?0:1;
}
static int zdogace_tamper(int argc,char **argv)
{if(argc!=3)return 2;uint8_t*p=NULL;size_t n=0;if(!read_file(argv[2],&p,&n))return 1;char*s=zcl_malloc(n+1, "arena_product_journey_tamper");if(!s){free(p);return 1;}memcpy(s,p,n);s[n]='\0';free(p);const char*a="clamp15(-2 * cross)",*b="clamp15(2 * cross)";const char*o=strstr(s,a)?a:b,*q=o==a?b:a;bool ok=replace_once(&s,&n,o,q)&&write_file(argv[2],(uint8_t*)s,n);free(s);return ok?0:1;}
static int flip_byte(int argc,char **argv)
{if(argc!=4)return 2;int fd=open(argv[2],O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 1;struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<1){close(fd);return 1;}off_t off=!strcmp(argv[3],"last")?st.st_size-1:(off_t)strtoll(argv[3],NULL,10);uint8_t b;if(off<0||off>=st.st_size||pread(fd,&b,1,off)!=1){close(fd);return 1;}b^=1;bool ok=pwrite(fd,&b,1,off)==1&&fsync(fd)==0&&close(fd)==0;return ok?0:1;}

static int usage(const char*p){fprintf(stderr,"usage: %s MODE ...\n",p);return 2;}
struct journey_mode { const char *name; int (*run)(int argc,char **argv); };
static const struct journey_mode journey_modes[]={
    {"json-get",json_get_mode},{"rpc-result",rpc_result},{"ids-distinct",ids_distinct},
    {"xor-order",xor_order},{"ports-rebind",ports_rebind},{"listen-report",listen_report},
    {"chain-loaded",chain_loaded},{"find-check",find_check},{"contacts-check",contacts_check},
    {"contact-reduce",contact_reduce},{"array-match-get",array_match_get},{"attack-deltas",attack_deltas},
    {"sparse-proof",sparse_proof},{"begin-fields",begin_fields},{"burst-proof",burst_proof},
    {"cold-proof",cold_proof},{"evidence-check",evidence_check},{"zdogace-correct",zdogace_correct},
    {"zdogace-tamper",zdogace_tamper},{"flip-byte",flip_byte},
};
int main(int argc,char **argv)
{
    if(argc<2)return usage(argv[0]);
    for(size_t i=0;i<sizeof(journey_modes)/sizeof(journey_modes[0]);i++)
        if(!strcmp(argv[1],journey_modes[i].name))return journey_modes[i].run(argc,argv);
    return usage(argv[0]);
}
