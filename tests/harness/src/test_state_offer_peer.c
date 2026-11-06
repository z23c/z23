/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exercise state offer discovery, transport, and lifecycle over peer queues. */
#define _POSIX_C_SOURCE 200809L
#include "config/state_offer_peer.h"
#include "config/boot_internal.h"
#include "config/boot_zcode_swarm.h"
#include "config/state_offer_link.h"
#include "config/state_offer_link_session.h"
#include "config/state_offer_store.h"
#include "net/fast_sync.h"
#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "base/serialize_le.h"
#include "net/net.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "chain/chainparams.h"
#include "test/test_core.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr,"peer test line %d: %s\n",__LINE__,#x); goto done; } } while (0)
static bool frame_in(struct msg_processor *mp, struct p2p_node *node, struct state_offer_link_frame *f)
{
    uint8_t wire[STATE_OFFER_LINK_FRAME_MAX]; size_t n = 0;
    return state_offer_link_encode(f, wire, sizeof(wire), &n) && state_offer_peer_frame(mp,node,wire,n);
}
static bool frame_out(struct p2p_node *node, struct send_segment *sentinel, struct state_offer_link_frame *f,
                      uint8_t *copy, size_t cap)
{
    struct send_segment *seg = sentinel->next;
    if (!seg || seg->size < MSG_HEADER_SIZE || seg->size - MSG_HEADER_SIZE > cap) return false;
    size_t n = seg->size - MSG_HEADER_SIZE;
    memcpy(copy, seg->data + MSG_HEADER_SIZE, n);
    sentinel->next = seg->next;
    if (node->send_tail == seg) node->send_tail = sentinel;
    node->send_size -= seg->size;
    send_segment_free(seg);
    return state_offer_link_decode(copy,n,f);
}
static void pause_ms(void) { struct timespec t = {0, 1000000}; (void)nanosleep(&t,NULL); }
struct read_test { uint64_t peer; uint8_t root[32], data[32]; uint32_t len; enum sol_read_result result; atomic_bool done; };
static void *read_thread(void *arg)
{
    struct read_test *t = arg;
    t->result = sol_client_read(&t->peer,SOL_OBJECT_CHUNK,t->root,0,t->data,sizeof(t->data),&t->len);
    atomic_store(&t->done,true);
    return NULL;
}
#define PEER_EXTRA 3u
struct peer_fixture {
    struct net_manager nm;
    struct msg_processor mp;
    struct boot_svc_ctx svc;
    struct p2p_node *node, *extra[PEER_EXTRA], *list[1+PEER_EXTRA];
    struct send_segment *sentinel, *extra_sentinel[PEER_EXTRA];
    struct rom_artifact *artifact;
    uint8_t *wire, *batch_wire;
    char dir[256], path[512], bench_path[512];
    bool started, thread_started;
    pthread_t thread;
    struct read_test read;
};
#define CHECK_PHASE(x) do { if (!(x)) { fprintf(stderr,"peer test line %d: %s\n",__LINE__,#x); return false; } } while (0)
/* Exercise the network hook and emitted version on an eligible peer. */
static bool peer_setup(struct peer_fixture *p)
{
    test_make_tmpdir(p->dir,sizeof(p->dir),"state_offer_peer","adapter");
    snprintf(p->path,sizeof(p->path),"%s/consensus-state-bundle-100.sqlite",p->dir);
    p->artifact=calloc(1,sizeof(*p->artifact)); p->wire=malloc(STATE_OFFER_LINK_FRAME_MAX);
    p->batch_wire=malloc(STATE_OFFER_LINK_FRAME_MAX); net_manager_init(&p->nm);
    p->mp.params=chain_params_get(); p->mp.net_mgr=&p->nm; p->svc.msg_processor=&p->mp;
    struct net_address addr={0}; p->node=p2p_node_create(&p->nm,ZCL_INVALID_SOCKET,&addr,"onion",true);
    p->sentinel=calloc(1,sizeof(*p->sentinel));
    CHECK_PHASE(p->artifact && p->wire && p->batch_wire && p->node && p->sentinel);
    boot_zcode_swarm_wire_network(&p->svc);
    CHECK_PHASE((p->nm.local_services & NODE_STATE_OFFER_LINK) && p->mp.zcode_swarm_frame && p->mp.zcode_swarm_tick);
    p->node->send_head=p->node->send_tail=p->sentinel;
    push_version(&p->mp,p->node);
    struct send_segment *v=p->sentinel->next;
    CHECK_PHASE(v && v->size >= MSG_HEADER_SIZE+12);
    CHECK_PHASE(zcl_read_u64_le(v->data+MSG_HEADER_SIZE+4) & NODE_STATE_OFFER_LINK);
    p->sentinel->next=v->next; p->node->send_tail=p->sentinel; p->node->send_size-=v->size; send_segment_free(v);
    p->node->version=1; p->node->services=NODE_ZCL23; atomic_store(&p->node->state,PEER_HANDSHAKE_COMPLETE);
    p->list[0]=p->node; p->nm.nodes=p->list; p->nm.num_nodes=1;
    state_offer_store_reset(); rom_seed_reset(); rom_seed_set_enabled(true);
    int fd=open(p->path,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if (fd<0) return false;
    bool ok=write(fd,"SQLite format 3",16)==16 && !ftruncate(fd,131072);
    close(fd); CHECK_PHASE(ok);
    CHECK_PHASE(rom_seed_register(p->dir,"consensus-state-bundle-100.sqlite",NULL,p->artifact)==ROM_REG_OK);
    CHECK_PHASE(state_offer_peer_start(p->dir)); p->started=true;
    return true;
}
/* A signed discovery reply is accepted from a capable zero-IP peer. */
static bool peer_discovery(struct peer_fixture *p)
{
    state_offer_peer_tick(&p->mp,p->node); CHECK_PHASE(!p->sentinel->next);
    p->node->services|=NODE_STATE_OFFER_LINK; state_offer_peer_tick(&p->mp,p->node);
    struct state_offer_link_frame f;
    CHECK_PHASE(frame_out(p->node,p->sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX));
    CHECK_PHASE(f.kind==STATE_OFFER_LINK_OFFER_REQUEST);
    uint64_t nonce=f.nonce;
    struct state_offer_batch_v1 batch={.version=STATE_OFFER_VERSION,.count=1,.offerer_tip_height=100};
    struct state_offer_v1 *o=&batch.offers[0];
    o->version=STATE_OFFER_VERSION; o->bundle_height=o->offerer_tip_height=100;
    o->chunk_size=STATE_OFFER_CHUNK_SIZE_BYTES; o->content_bytes=131072; o->num_chunks=1;
    o->kind=ROM_ARTIFACT_CONSENSUS_BUNDLE; o->issued_unix=1800000000;
    const char *name="consensus-state-bundle-100.sqlite"; o->filename_len=(uint16_t)strlen(name);
    memcpy(o->filename,name,o->filename_len); memcpy(o->chunk_tree_root,p->artifact->chunk_root,32);
    memset(o->header_hash,1,32); memset(o->content_digest,2,32); memset(o->mmb_peaks_digest,3,32);
    memset(o->producer_receipt_id,4,32); uint8_t seed[32]; memset(seed,7,32);
    CHECK_PHASE(state_offer_v1_sign(o,seed)==STATE_OFFER_OK);
    size_t n=0; CHECK_PHASE(state_offer_batch_v1_encode(&batch,p->batch_wire,STATE_OFFER_LINK_FRAME_MAX,&n)==STATE_OFFER_OK);
    f=(struct state_offer_link_frame){.kind=STATE_OFFER_LINK_OFFER_REPLY,.nonce=nonce,.total=(uint32_t)n,.size=(uint32_t)n,.data=p->batch_wire};
    CHECK_PHASE(frame_in(&p->mp,p->node,&f)); struct state_offer_record chosen;
    CHECK_PHASE(state_offer_store_decide(0,&chosen)==STATE_OFFER_DECIDE_FETCH && chosen.peer_link && chosen.peer_id==p->node->id);
    return true;
}
/* Drain the registered object while a busy request receives a refusal. */
static bool peer_transfer(struct peer_fixture *p)
{
    struct state_offer_link_frame f={.kind=STATE_OFFER_LINK_CHUNK_REQUEST,.nonce=55,.total=ROM_SEED_CHUNK_SIZE};
    memcpy(f.digest,p->artifact->chunk_root,32); CHECK_PHASE(frame_in(&p->mp,p->node,&f));
    struct state_offer_link_frame busy=f; busy.nonce=57; busy.index=1;
    CHECK_PHASE(frame_in(&p->mp,p->node,&busy));
    CHECK_PHASE(frame_out(p->node,p->sentinel,&busy,p->wire,STATE_OFFER_LINK_FRAME_MAX));
    CHECK_PHASE(busy.kind==STATE_OFFER_LINK_REFUSAL && busy.nonce==57 && !busy.index);
    unsigned parts=0; uint32_t bytes=0;
    for (int i=0;i<10000 && bytes<131072;i++) {
        state_offer_peer_pump(&p->mp);
        while (frame_out(p->node,p->sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX)) {
            CHECK_PHASE(f.kind==STATE_OFFER_LINK_CHUNK_PART && f.nonce==55 && f.offset==bytes && f.total==131072);
            bytes+=f.size; parts++;
        }
        if (bytes<131072) pause_ms();
    }
    CHECK_PHASE(bytes==131072 && parts>=3); return true;
}
/* Further eligible connections, each with its own captured send queue. */
static bool peer_add_nodes(struct peer_fixture *p, size_t count)
{
    struct net_address addr={0};
    for (size_t k=0;k<count && k<PEER_EXTRA;k++) {
        if (!p->extra[k]) {
            p->extra[k]=p2p_node_create(&p->nm,ZCL_INVALID_SOCKET,&addr,"onion",true);
            p->extra_sentinel[k]=calloc(1,sizeof(*p->extra_sentinel[k]));
            CHECK_PHASE(p->extra[k] && p->extra_sentinel[k]);
            p->extra[k]->send_head=p->extra[k]->send_tail=p->extra_sentinel[k];
            p->extra[k]->version=1; p->extra[k]->services=NODE_ZCL23|NODE_STATE_OFFER_LINK;
            atomic_store(&p->extra[k]->state,PEER_HANDSHAKE_COMPLETE);
        }
        p->list[k+1]=p->extra[k];
    }
    p->nm.num_nodes=1+(count<PEER_EXTRA?count:PEER_EXTRA); return true;
}
/* Drain node's queue; count parts of nonce and return true on any other frame. */
static bool peer_collect(struct peer_fixture *p, struct p2p_node *node, struct send_segment *sentinel,
                         uint64_t nonce, uint32_t *bytes)
{
    struct state_offer_link_frame f; bool stray=false;
    while (frame_out(node,sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX)) {
        if (f.kind==STATE_OFFER_LINK_CHUNK_PART && f.nonce==nonce && f.offset==*bytes) *bytes+=f.size;
        else stray=true;
    }
    return stray;
}
/* A connection whose send queue stays full keeps only its own stream; another
 * connection is admitted and completes, then the stalled one resumes. */
static bool peer_parallel(struct peer_fixture *p)
{
    CHECK_PHASE(peer_add_nodes(p,1));
    struct state_offer_link_frame f={.kind=STATE_OFFER_LINK_CHUNK_REQUEST,.nonce=60,.total=ROM_SEED_CHUNK_SIZE};
    memcpy(f.digest,p->artifact->chunk_root,32);
    size_t held=p->node->send_size; p->node->send_size=1024u*1024u;
    CHECK_PHASE(frame_in(&p->mp,p->node,&f));
    f.nonce=61; CHECK_PHASE(frame_in(&p->mp,p->extra[0],&f));
    uint32_t a=0,b=0; bool stray=false;
    for (int i=0;i<10000 && b<131072 && !stray;i++) {
        state_offer_peer_pump(&p->mp);
        stray=peer_collect(p,p->extra[0],p->extra_sentinel[0],61,&b);
        if (b<131072) pause_ms();
    }
    CHECK_PHASE(!stray && b==131072 && !p->sentinel->next);
    p->node->send_size=held;
    for (int i=0;i<10000 && a<131072 && !stray;i++) {
        state_offer_peer_pump(&p->mp);
        stray=peer_collect(p,p->node,p->sentinel,60,&a);
        if (a<131072) pause_ms();
    }
    CHECK_PHASE(!stray && a==131072);
    p->list[1]=NULL; p->nm.num_nodes=1; return true;
}
/* Optional measurement (ZCL_STATE_OFFER_BENCH=1): each of `peers` connections
 * fetches every chunk of a 4-chunk (32 MiB) bundle one object at a time, as the
 * client does, through the real request, slot, pump and send-queue path. The
 * fixture empties each send queue at once, so sockets and Tor are excluded and
 * the figure is the server-side ceiling. Rate caps are lifted because every
 * test connection shares the zero address. */
#define BENCH_CHUNKS 4u
struct bench_peer { struct p2p_node *node; struct send_segment *sentinel; uint32_t chunk, bytes; };
static bool bench_ask(struct peer_fixture *p, struct bench_peer *b, const uint8_t root[32])
{
    struct state_offer_link_frame f={.kind=STATE_OFFER_LINK_CHUNK_REQUEST,.nonce=1000+b->chunk,
        .index=b->chunk,.total=ROM_SEED_CHUNK_SIZE};
    memcpy(f.digest,root,32); b->bytes=0;
    return frame_in(&p->mp,b->node,&f);
}
static bool bench_run(struct peer_fixture *p, const uint8_t root[32], size_t peers, double *mib_s)
{
    struct bench_peer b[1+PEER_EXTRA]={{p->node,p->sentinel,0,0}};
    for (size_t k=1;k<peers;k++) b[k]=(struct bench_peer){p->extra[k-1],p->extra_sentinel[k-1],0,0};
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    for (size_t k=0;k<peers;k++) CHECK_PHASE(bench_ask(p,&b[k],root));
    size_t done=0;
    for (long i=0;i<2000000 && done<peers;i++) {
        state_offer_peer_pump(&p->mp); done=0;
        for (size_t k=0;k<peers;k++) {
            if (b[k].chunk<BENCH_CHUNKS) CHECK_PHASE(!peer_collect(p,b[k].node,b[k].sentinel,1000+b[k].chunk,&b[k].bytes));
            if (b[k].chunk<BENCH_CHUNKS && b[k].bytes==ROM_SEED_CHUNK_SIZE && ++b[k].chunk<BENCH_CHUNKS)
                CHECK_PHASE(bench_ask(p,&b[k],root));
            done+=b[k].chunk==BENCH_CHUNKS;
        }
        if (done<peers) { struct timespec t={0,100000}; (void)nanosleep(&t,NULL); } /* real-clock: opt-in bench yields to disk workers; the iteration cap only stops a hang and the figure is printed, never asserted */
    }
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double s=(double)(t1.tv_sec-t0.tv_sec)+(double)(t1.tv_nsec-t0.tv_nsec)/1e9;
    *mib_s=s>0 ? (double)peers*BENCH_CHUNKS*8.0/s : 0;
    return done==peers;
}
static bool peer_bench(struct peer_fixture *p)
{
    const char *on=getenv("ZCL_STATE_OFFER_BENCH");
    if (!on || strcmp(on,"1")) return true;
    snprintf(p->bench_path,sizeof(p->bench_path),"%s/consensus-state-bundle-300.sqlite",p->dir);
    int fd=open(p->bench_path,O_WRONLY|O_CREAT|O_TRUNC,0600);
    CHECK_PHASE(fd>=0);
    bool ok=write(fd,"SQLite format 3",16)==16 && !ftruncate(fd,(off_t)BENCH_CHUNKS*ROM_SEED_CHUNK_SIZE);
    close(fd); CHECK_PHASE(ok);
    struct rom_artifact *art=calloc(1,sizeof(*art)); CHECK_PHASE(art);
    ok=rom_seed_register(p->dir,"consensus-state-bundle-300.sqlite",NULL,art)==ROM_REG_OK;
    rom_seed_set_peer_bps_cap(UINT64_C(1)<<40); rom_seed_set_global_bps_cap(UINT64_C(1)<<40);
    double one=0,four=0;
    ok=ok && peer_add_nodes(p,PEER_EXTRA) && bench_run(p,art->chunk_root,1,&one) && bench_run(p,art->chunk_root,4,&four);
    printf("state_offer_peer bench: 1 peer %.0f MiB/s, 4 peers %.0f MiB/s aggregate (%u x 8 MiB chunks each)\n",
           one,four,BENCH_CHUNKS);
    rom_seed_set_peer_bps_cap(ROM_SEED_DEFAULT_PEER_BPS_CAP); rom_seed_set_global_bps_cap(ROM_SEED_DEFAULT_GLOBAL_BPS_CAP);
    for (size_t k=1;k<=PEER_EXTRA;k++) p->list[k]=NULL;
    p->nm.num_nodes=1; free(art); return ok;
}
/* A throttled request refuses and disconnect clears the server owner. */
static bool peer_refuse_disconnect(struct peer_fixture *p)
{
    rom_seed_set_peer_bps_cap(1);
    struct state_offer_link_frame f={.kind=STATE_OFFER_LINK_CHUNK_REQUEST,.nonce=58,.total=ROM_SEED_CHUNK_SIZE};
    memcpy(f.digest,p->artifact->chunk_root,32); CHECK_PHASE(frame_in(&p->mp,p->node,&f));
    bool refused=false;
    for (int i=0;i<5000 && !refused;i++) {
        state_offer_peer_pump(&p->mp);
        if (frame_out(p->node,p->sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX))
            refused=f.kind==STATE_OFFER_LINK_REFUSAL && f.nonce==58;
        if (!refused) pause_ms();
    }
    rom_seed_set_peer_bps_cap(ROM_SEED_DEFAULT_PEER_BPS_CAP); CHECK_PHASE(refused);
    f=(struct state_offer_link_frame){.kind=STATE_OFFER_LINK_CHUNK_REQUEST,.nonce=56,.total=ROM_SEED_CHUNK_SIZE};
    memcpy(f.digest,p->artifact->chunk_root,32); CHECK_PHASE(frame_in(&p->mp,p->node,&f));
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS];
    CHECK_PHASE(state_offer_link_server_peers(held,STATE_OFFER_LINK_SERVER_SLOTS)==1 && held[0]==(uint64_t)p->node->id+1);
    atomic_store(&p->node->disconnect,true); state_offer_peer_pump(&p->mp);
    for (int i=0;i<5000 && state_offer_link_server_peers(held,STATE_OFFER_LINK_SERVER_SLOTS);i++) pause_ms();
    CHECK_PHASE(!state_offer_link_server_peers(held,STATE_OFFER_LINK_SERVER_SLOTS));
    atomic_store(&p->node->disconnect,false); return true;
}
/* A pending object read is cancelled when its connection disappears. */
static bool peer_client_disconnect(struct peer_fixture *p)
{
    p->read.peer=(uint64_t)p->node->id+1; memcpy(p->read.root,p->artifact->chunk_root,32);
    CHECK_PHASE(state_offer_peer_begin(p->read.peer));
    CHECK_PHASE(!pthread_create(&p->thread,NULL,read_thread,&p->read)); p->thread_started=true;
    for (int i=0;i<5000 && !p->sentinel->next;i++) { state_offer_peer_pump(&p->mp); pause_ms(); }
    CHECK_PHASE(p->sentinel->next); atomic_store(&p->node->disconnect,true); state_offer_peer_pump(&p->mp);
    for (int i=0;i<5000 && !atomic_load(&p->read.done);i++) pause_ms();
    CHECK_PHASE(atomic_load(&p->read.done)); CHECK_PHASE(!pthread_join(p->thread,NULL)); p->thread_started=false;
    CHECK_PHASE(p->read.result==SOL_READ_CANCELLED); state_offer_peer_end(p->read.peer); return true;
}
/* Shutdown cancels a pending reader and suppresses late callbacks. */
static bool peer_shutdown(struct peer_fixture *p)
{
    struct state_offer_link_frame f;
    while (frame_out(p->node,p->sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX)) { }
    atomic_store(&p->node->disconnect,false); atomic_store(&p->read.done,false);
    CHECK_PHASE(state_offer_peer_begin(p->read.peer));
    CHECK_PHASE(!pthread_create(&p->thread,NULL,read_thread,&p->read)); p->thread_started=true;
    for (int i=0;i<5000 && !p->sentinel->next;i++) { state_offer_peer_pump(&p->mp); pause_ms(); }
    CHECK_PHASE(p->sentinel->next);
    CHECK_PHASE(frame_out(p->node,p->sentinel,&f,p->wire,STATE_OFFER_LINK_FRAME_MAX));
    boot_zcode_swarm_shutdown(); p->started=false;
    CHECK_PHASE(!pthread_join(p->thread,NULL)); p->thread_started=false;
    CHECK_PHASE(p->read.result==SOL_READ_CANCELLED);
    f=(struct state_offer_link_frame){.kind=STATE_OFFER_LINK_OFFER_REQUEST,.nonce=88}; size_t n=0;
    CHECK_PHASE(state_offer_link_encode(&f,p->wire,STATE_OFFER_LINK_FRAME_MAX,&n));
    CHECK_PHASE(p->mp.zcode_swarm_frame(&p->mp,p->node,p->wire,n,&p->svc));
    p->mp.zcode_swarm_tick(&p->mp,p->node,&p->svc); CHECK_PHASE(!p->sentinel->next); return true;
}
/* Release all fixture resources even after a failed phase. */
static void peer_cleanup(struct peer_fixture *p)
{
    if (p->started) state_offer_peer_shutdown();
    rom_seed_set_peer_bps_cap(ROM_SEED_DEFAULT_PEER_BPS_CAP);
    if (p->thread_started) (void)pthread_join(p->thread,NULL);
    if (p->node && p->sentinel) {
        while (p->sentinel->next) { struct send_segment *s=p->sentinel->next; p->sentinel->next=s->next; send_segment_free(s); }
        p->node->send_head=p->node->send_tail=NULL; free(p->sentinel);
    } else free(p->sentinel);
    for (size_t k=0;k<PEER_EXTRA;k++) {
        struct send_segment *head=p->extra_sentinel[k];
        while (head && head->next) { struct send_segment *s=head->next; head->next=s->next; send_segment_free(s); }
        if (p->extra[k]) p->extra[k]->send_head=p->extra[k]->send_tail=NULL;
        free(head);
    }
    p->nm.nodes=NULL; p->nm.num_nodes=0;
    for (size_t k=0;k<PEER_EXTRA;k++) if (p->extra[k]) p2p_node_free(p->extra[k]);
    if (p->node) p2p_node_free(p->node);
    net_manager_free(&p->nm); rom_seed_reset(); state_offer_store_reset();
    unlink(p->path); if (p->bench_path[0]) unlink(p->bench_path); rmdir(p->dir); free(p->artifact); free(p->wire); free(p->batch_wire);
}
int test_state_offer_peer(void)
{
    struct peer_fixture p={0};
    bool ok=peer_setup(&p) && peer_discovery(&p) && peer_transfer(&p) && peer_parallel(&p) && peer_bench(&p) &&
        peer_refuse_disconnect(&p) && peer_client_disconnect(&p) && peer_shutdown(&p);
    peer_cleanup(&p); return ok ? 0 : 1;
}
