/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Reject malformed HUD byte arrays and alternate literal encodings. */
#include "test/test_core.h"
#include <stdarg.h>
static unsigned use_diag_events;
static int use_diagnostic(FILE *stream,const char *format,...)
{
 if(stream==stderr){++use_diag_events;}va_list args;va_start(args,format);
 int result=vfprintf(stream,format,args);va_end(args);return result;
}
#define fprintf use_diagnostic
#include "../../../apps/skycombat/part/expr_validate.c"
#include "../../../apps/skycombat/part/expr_eval.c"
#include "../../../apps/skycombat/part/expr_draw.c"
#include "platform/positioned_file.h"
enum { ADMIT_PROBE_NONE,ADMIT_PROBE_PARTIAL,ADMIT_PROBE_EOF,ADMIT_PROBE_ERROR,
 ADMIT_PROBE_OVERRUN,ADMIT_PROBE_STAT,ADMIT_PROBE_CHANGED,ADMIT_PROBE_STAT_AFTER };
static unsigned admit_probe_mode,admit_probe_reads,admit_probe_stats,admit_probe_closes;
static int64_t admit_probe_read(const struct platform_positioned_file *f,void *b,size_t n,uint64_t off)
{
 ++admit_probe_reads;
 if(admit_probe_mode==ADMIT_PROBE_EOF)return 0;
 if(admit_probe_mode==ADMIT_PROBE_ERROR)return -1;
 if(admit_probe_mode==ADMIT_PROBE_OVERRUN)return (int64_t)n+1;
 if(admit_probe_mode==ADMIT_PROBE_PARTIAL && n>3)n=3;
 return platform_positioned_file_read(f,b,n,off);
}
static bool admit_probe_snapshot(const struct platform_positioned_file *f,struct platform_positioned_file_snapshot *s)
{
 ++admit_probe_stats;
 if(admit_probe_mode==ADMIT_PROBE_STAT ||
    (admit_probe_mode==ADMIT_PROBE_STAT_AFTER && admit_probe_stats==2))return false;
 bool ok=platform_positioned_file_snapshot(f,s);
 if(ok && admit_probe_mode==ADMIT_PROBE_CHANGED && admit_probe_stats==2)++s->size;
 return ok;
}
static void admit_probe_close(struct platform_positioned_file *f)
{ ++admit_probe_closes;platform_positioned_file_close(f); }
/* Test-only syscall observations/faults; production API has no callbacks. */
#define platform_positioned_file_read admit_probe_read
#define platform_positioned_file_snapshot(...) admit_probe_snapshot(__VA_ARGS__)
#define platform_positioned_file_close admit_probe_close
#include "../../../apps/skycombat/part/expr_admit.c"
#undef platform_positioned_file_read
#undef platform_positioned_file_snapshot
#undef platform_positioned_file_close
#undef fprintf

#include "crypto/sha256.h"
#include <math.h>
static const uint8_t expr_empty[32]={'H','U','D','X',0,0,32,0,1};
static const uint8_t expr_rect[88]={
 [0]='H',[1]='U',[2]='D',[3]='X',[6]=32,[8]=1,[12]=2,[14]=1,
 [32]=1,[34]=255,[35]=255,[36]=255,[37]=255,[38]=255,[39]=255,
 [48]=2,[50]=255,[51]=255,[52]=255,[53]=255,[54]=255,[55]=255,[56]=13,
 [64]=1,[66]=1,[82]=255,[83]=255};
static const uint8_t expr_literal[53]={
 [0]='H',[1]='U',[2]='D',[3]='X',[6]=32,[8]=1,[16]=1,[18]=1,[20]=1,
 [34]=1,[40]=1,[42]=255,[43]=255,[48]=1,[52]='A'};
static int expr_expect(const uint8_t *b, size_t n, enum expr_status want)
{
 struct expr_info info, before; memset(&info,0x5a,sizeof info); before=info;
 struct expr_error error={0}; enum expr_status got=expr_validate(b,n,&info,&error);
 bool ok=got==want && error.code==got && error.reason &&
         (got==EX_OK || !memcmp(&before,&info,sizeof info));
 if(!ok) printf("expr bytes n=%zu expected=%u got=%u reason=%s atomic=%d\n",
               n,(unsigned)want,(unsigned)got,error.reason?error.reason:"missing",
               !memcmp(&before,&info,sizeof info));
 return !ok;
}
static int expr_headers(void)
{
 int failures=expr_expect(expr_empty,32,EX_OK); uint8_t b[33];
 for(size_t n=0;n<32;n++) failures+=expr_expect(expr_empty,n,EX_BOUNDS);
 const unsigned offsets[]={0,4,5,6,7,8,9,10,11,24,25,26,27,28,29,30,31};
 for(size_t j=0;j<sizeof offsets/sizeof *offsets;j++) {
  memcpy(b,expr_empty,32); b[offsets[j]]^=1; failures+=expr_expect(b,32,EX_FORMAT);
 }
 const unsigned at[]={12,14,16,18,20}; const unsigned over[]={257,65,65,257,1025};
 for(unsigned j=0;j<5;j++) {
  memcpy(b,expr_empty,32); zcl_write_u32_le(b+at[j],over[j]);
  failures+=expr_expect(b,32,EX_LIMIT);
 }
 memcpy(b,expr_empty,32); b[32]=0; failures+=expr_expect(b,33,EX_BOUNDS);
 uint8_t too_large[EXPR_MAX_BYTES+1]={0};
 failures+=expr_expect(too_large,sizeof too_large,EX_LIMIT);
 memcpy(b,expr_empty,32); b[20]=1; b[32]='A'; failures+=expr_expect(b,33,EX_LITERAL);
 failures+=expr_expect(NULL,32,EX_ARGUMENT);
 struct expr_error e; failures+=expr_validate(expr_empty,32,NULL,&e)!=EX_ARGUMENT;
 return failures;
}
static int expr_records(void)
{
 int failures=expr_expect(expr_rect,88,EX_OK); uint8_t b[88];
 for(size_t n=32;n<88;n++) failures+=expr_expect(expr_rect,n,EX_BOUNDS);
 const unsigned pos[]={32,33,34,36,38,44,56,56,64,65,66,68,82,84};
 const uint8_t val[]={0,1,0,0,0,1,16,255,5,1,0,1,0,1};
 const enum expr_status want[]={EX_OPCODE,EX_FORMAT,EX_REFERENCE,EX_REFERENCE,
  EX_REFERENCE,EX_FORMAT,EX_FIELD_ID,EX_FIELD_ID,EX_SCHEMA,EX_FORMAT,EX_TYPE,
  EX_TYPE,EX_SCHEMA,EX_FORMAT};
 for(unsigned j=0;j<sizeof pos/sizeof *pos;j++) {
  memcpy(b,expr_rect,88); b[pos[j]]=val[j]; failures+=expr_expect(b,88,want[j]);
 }
 for(unsigned field=0;field<16;field++) {
  memcpy(b,expr_rect,64); b[14]=0; b[56]=(uint8_t)field;
  failures+=expr_expect(b,64,EX_OK);
  memcpy(b,expr_rect,88); b[56]=(uint8_t)field;
  failures+=expr_expect(b,88,field>=13?EX_OK:EX_TYPE);
 }
 /* Every arity/type rule: two I32 constants, BOOL field, then this opcode. */
 uint8_t ops[96]={0}; memcpy(ops,expr_rect,64); ops[12]=4; ops[14]=0;
 memcpy(ops+64,expr_rect+32,16); ops[64]=EX_FIELD; ops[72]=13;
 for(unsigned op=3;op<=15;op++) {
  ops[80]=(uint8_t)op; zcl_write_u32_le(ops+88,0);
  static const unsigned arities[16]={0,0,0,2,2,2,2,3,3,2,2,2,2,2,1,3};
  unsigned arity=arities[op], a=op>=12?2:0, br=op==EX_SELECT?0:a;
  zcl_write_u16_le(ops+82,(uint16_t)a);
  zcl_write_u16_le(ops+84,arity>1?(uint16_t)br:EXPR_NONE);
  zcl_write_u16_le(ops+86,arity>2?0:EXPR_NONE);
  /* Expression 1 is changed from FIELD to an independent I32 constant. */
  memcpy(ops+48,expr_rect+32,16);
  failures+=expr_expect(ops,96,EX_OK);
  ops[88]=1; failures+=expr_expect(ops,96,EX_FORMAT); ops[88]=0;
  zcl_write_u16_le(ops+82,3); failures+=expr_expect(ops,96,EX_REFERENCE);
  zcl_write_u16_le(ops+82,(uint16_t)(a==2?0:2));
  failures+=expr_expect(ops,96,EX_TYPE);
 }
 memcpy(b,expr_rect,88); b[40]=1; failures+=expr_expect(b,88,EX_SCHEMA);
 for(unsigned kind=2;kind<=4;kind++) {
  memcpy(b,expr_rect,88); b[64]=(uint8_t)kind;
  failures+=expr_expect(b,88,kind==2?EX_OK:EX_SCHEMA);
 }
 return failures;
}
static int expr_text_cases(void)
{
 int failures=expr_expect(expr_literal,53,EX_OK); uint8_t b[66];
 struct expr_info info={0}; failures+=expr_validate(expr_literal,53,&info,NULL)!=EX_OK;
 failures+=info.texts!=1 || info.pieces!=1 || info.literal_bytes!=1 || info.worst_text!=1 || info.worst_draw_text!=0;
 const unsigned pos[]={32,34,36,40,41,42,44,48,52};
 const uint8_t val[]={1,0,1,3,1,0,2,2,31};
 const enum expr_status want[]={EX_REFERENCE,EX_REFERENCE,EX_FORMAT,EX_OPCODE,
  EX_FORMAT,EX_LITERAL,EX_LITERAL,EX_LITERAL,EX_LITERAL};
 for(unsigned j=0;j<sizeof pos/sizeof *pos;j++) {
  memcpy(b,expr_literal,53); b[pos[j]]=val[j]; failures+=expr_expect(b,53,want[j]);
 }
 memcpy(b,expr_literal,53); b[20]=2; b[44]=1; b[52]='B'; b[53]='A';
 failures+=expr_expect(b,54,EX_LITERAL); /* B1: same template A, unused prefix. */
 b[44]=0; failures+=expr_expect(b,54,EX_LITERAL); /* unused suffix */
 memcpy(b,expr_literal,53); b[18]=2; b[34]=2; b[20]=2;
 memcpy(b+52,b+40,12); b[64]='A'; b[65]='B';
 failures+=expr_expect(b,66,EX_LITERAL); /* shared/overlapping ranges */
 b[44]=1; b[56]=0; failures+=expr_expect(b,66,EX_LITERAL); /* reversed */
 b[44]=0; b[56]=1; failures+=expr_expect(b,66,EX_OK);
 b[48]=0; b[56]=0; b[20]=1; b[64]='B';
 failures+=expr_expect(b,65,EX_OK); /* zero-length at cursor */
 b[44]=1; failures+=expr_expect(b,65,EX_LITERAL); /* alternate zero offset */
 memcpy(b,expr_literal,53); b[20]=0; b[48]=0; failures+=expr_expect(b,52,EX_OK);
 b[40]=2; failures+=expr_expect(b,52,EX_TYPE); /* missing DECIMAL ref */
 return failures;
}
static int expr_limits(void)
{
 uint8_t b[EXPR_MAX_BYTES]={0}; memcpy(b,expr_empty,32);
 zcl_write_u16_le(b+12,256); b[14]=64; b[16]=64; zcl_write_u16_le(b+18,256);
 zcl_write_u32_le(b+20,1024); size_t at=32;
 for(unsigned i=0;i<256;i++,at+=16) memcpy(b+at,expr_rect+32,16);
 b[48]=2; b[56]=13;
 for(unsigned i=0;i<64;i++,at+=8) {zcl_write_u16_le(b+at,(uint16_t)(4*i)); b[at+2]=4;}
 for(unsigned i=0;i<256;i++,at+=12) {
  b[at]=1; b[at+2]=255; b[at+3]=255;
  zcl_write_u32_le(b+at+4,16*((i+3)/4)); if(i%4==0) b[at+8]=16;
 }
 size_t draws=at;
 for(unsigned i=0;i<64;i++,at+=24) memcpy(b+at,expr_rect+64,24);
 memset(b+at,'A',1024); int failures=expr_expect(b,sizeof b,EX_OK);
 for(unsigned i=0;i<64;i++) { b[draws+24*i]=3; zcl_write_u16_le(b+draws+24*i+18,0); }
 failures+=expr_expect(b,sizeof b,EX_OK); /* repeated 16-byte template: 1024 */
 struct expr_info info={0}; failures+=expr_validate(b,sizeof b,&info,NULL)!=EX_OK;
 failures+=info.expressions!=256 || info.draws!=64 || info.texts!=64 ||
           info.pieces!=256 || info.literal_bytes!=1024 || info.worst_text!=1024 || info.worst_draw_text!=1024;
 const size_t pieces=32+4096+512;
 b[pieces+12]=2; zcl_write_u16_le(b+pieces+14,0); zcl_write_u32_le(b+pieces+16,0);
 failures+=expr_expect(b,sizeof b,EX_TEXT_BUDGET); /* DECIMAL adds 11 */
 b[pieces+12]=1; zcl_write_u16_le(b+pieces+14,EXPR_NONE); zcl_write_u32_le(b+pieces+16,16);
 b[pieces+8]=17; b[pieces+252*12+8]=15;
 for(unsigned i=1;i<=252;i++) zcl_write_u32_le(b+pieces+12*i+4,16*((i+3)/4)+1);
 failures+=expr_expect(b,sizeof b,EX_TEXT_BUDGET); /* 64 repeated 17-byte draws */
 b[pieces+8]=16; b[pieces+252*12+8]=16;
 for(unsigned i=1;i<=252;i++) zcl_write_u32_le(b+pieces+12*i+4,16*((i+3)/4));
 b[draws+14]=1; failures+=expr_expect(b,sizeof b,EX_TYPE); /* font BOOL */
 return failures;
}
static void eval_leaf(uint8_t *r,unsigned op,int32_t immediate)
{
 memset(r,0,16);r[0]=(uint8_t)op;
 for(unsigned j=0;j<3;j++)zcl_write_u16_le(r+2+2*j,EXPR_NONE);
 zcl_write_i32_le(r+8,immediate);
}
static bool eval_result_ok(const uint8_t *b,size_t n,const struct expr_values *out,int32_t last)
{
 if(!b || n<32 || out->count>256)return false;
 return out->count==zcl_read_u16_le(b+12) && out->steps==out->count &&
  (!out->count || out->value[out->count-1]==last);
}
static int eval_expect(const uint8_t *b,size_t n,const double *fields,unsigned budget,
 enum expr_status want,int32_t last)
{
 struct expr_values out,before;memset(&out,0x5a,sizeof out);before=out;
 struct expr_error e={0};enum expr_status got=expr_evaluate(b,n,fields,budget,&out,&e);
 bool ok=got==want && e.code==got && e.reason;
 if(got==EX_OK)ok=ok && eval_result_ok(b,n,&out,last);
 else ok=ok && !memcmp(&out,&before,sizeof out);
 if(!ok)printf("eval want=%u got=%u last=%d expected=%d\n",(unsigned)want,(unsigned)got,
  got==EX_OK && out.count<=256 && out.count?out.value[out.count-1]:0,last);
 return !ok;
}
static void eval_program(uint8_t b[128],unsigned op,int32_t a,int32_t bv,int32_t c)
{
 memset(b,0,128);memcpy(b,expr_empty,32);b[12]=6;
 eval_leaf(b+32,EX_CONST_I32,a);eval_leaf(b+48,EX_CONST_I32,bv);
 eval_leaf(b+64,EX_CONST_I32,c);eval_leaf(b+80,EX_FIELD,XF_SHIELD);
 eval_leaf(b+96,EX_FIELD,XF_CONNECTED);eval_leaf(b+112,op,0);
 static const unsigned arities[16]={0,0,0,2,2,2,2,3,3,2,2,2,2,2,1,3};
 unsigned arity=arities[op],left=op>=EX_AND?3:0,right=op>=EX_AND?4:1;
 if(op==EX_SELECT){left=3;right=0;}
 zcl_write_u16_le(b+114,(uint16_t)left);
 if(arity>1)zcl_write_u16_le(b+116,(uint16_t)right);
 if(arity>2)zcl_write_u16_le(b+118,(uint16_t)(op==EX_SELECT?1:2));
}
static int eval_operators(void)
{
 uint8_t b[128];double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 const int32_t expected[]={10,4,3,7,7,2,0,0,0,0,1,0,7};int failures=0;
 for(unsigned op=EX_ADD_SAT;op<=EX_SELECT;op++) {
  eval_program(b,op,7,3,9);
  failures+=eval_expect(b,128,fields,6,EX_OK,expected[op-EX_ADD_SAT]);
 }
 struct {unsigned op;int32_t a,b,c,result;} cases[]={
  {EX_ADD_SAT,INT32_MAX,1,0,INT32_MAX},{EX_ADD_SAT,INT32_MIN,-1,0,INT32_MIN},
  {EX_SUB_SAT,INT32_MIN,1,0,INT32_MIN},{EX_SUB_SAT,INT32_MAX,-1,0,INT32_MAX},
  {EX_MIN,-5,-3,0,-5},{EX_MAX,-5,-3,0,-3},{EX_CLAMP,-5,0,9,0},
  {EX_CLAMP,20,0,9,9},{EX_CLAMP,5,5,5,5},{EX_MULDIV,-7,3,2,-10},
  {EX_MULDIV,INT32_MIN,INT32_MIN,-1,INT32_MIN},
  {EX_MULDIV,INT32_MIN,-1,1,INT32_MAX},{EX_LT,3,7,0,1},
  {EX_LE,7,7,0,1},{EX_EQ,7,7,0,1}};
 for(unsigned i=0;i<sizeof cases/sizeof *cases;i++) {
  eval_program(b,cases[i].op,cases[i].a,cases[i].b,cases[i].c);
  failures+=eval_expect(b,128,fields,6,EX_OK,cases[i].result);
 }
 fields[XF_SHIELD]=0;fields[XF_CONNECTED]=1;
 for(unsigned op=EX_AND;op<=EX_SELECT;op++) {
  eval_program(b,op,7,3,9);
  failures+=eval_expect(b,128,fields,6,EX_OK,op==EX_SELECT?3:op==EX_AND?0:1);
 }
 eval_program(b,EX_EQ,0,0,0);zcl_write_u16_le(b+114,3);zcl_write_u16_le(b+116,4);
 failures+=eval_expect(b,128,fields,6,EX_OK,0);
 fields[XF_SHIELD]=1;failures+=eval_expect(b,128,fields,6,EX_OK,1);
 eval_program(b,EX_SELECT,0,0,0);zcl_write_u16_le(b+116,4);zcl_write_u16_le(b+118,3);
 failures+=eval_expect(b,128,fields,6,EX_OK,1);
 return failures;
}
static int eval_domains(void)
{
 uint8_t b[144];double fields[XF_COUNT]={0};int failures=0;
 eval_program(b,EX_MULDIV,7,3,0);failures+=eval_expect(b,128,fields,6,EX_DIV_ZERO,0);
 /* The failing expression is unused and precedes a SELECT. Evaluation is eager. */
 b[12]=7;eval_leaf(b+128,EX_SELECT,0);zcl_write_u16_le(b+130,3);
 zcl_write_u16_le(b+132,0);zcl_write_u16_le(b+134,1);
 failures+=eval_expect(b,144,fields,7,EX_DIV_ZERO,0);
 eval_program(b,EX_CLAMP,7,3,2);failures+=eval_expect(b,128,fields,6,EX_RANGE,0);
 eval_program(b,EX_ADD_SAT,7,3,0);
 failures+=eval_expect(b,128,fields,5,EX_EVAL_BUDGET,0);
 failures+=eval_expect(b,128,fields,0,EX_EVAL_BUDGET,0);
 failures+=eval_expect(b,128,fields,257,EX_LIMIT,0);
 failures+=eval_expect(b,128,fields,256,EX_OK,10);
 const double bad[]={(double)NAN,(double)INFINITY,-(double)INFINITY,
                     2147483648.0,-2147483649.0,0.5};
 for(unsigned j=0;j<sizeof bad/sizeof *bad;j++) {
  fields[XF_SCORE_3]=bad[j];failures+=eval_expect(b,128,fields,6,EX_SNAPSHOT,0);
 }
 fields[XF_SCORE_3]=0;
 fields[XF_FLASH]=2;failures+=eval_expect(b,128,fields,6,EX_SNAPSHOT,0);
 fields[XF_FLASH]=-1;failures+=eval_expect(b,128,fields,6,EX_SNAPSHOT,0);
 fields[XF_FLASH]=0;
 failures+=eval_expect(NULL,128,fields,6,EX_ARGUMENT,0);
 failures+=eval_expect(b,128,NULL,6,EX_ARGUMENT,0);
 failures+=eval_expect(b,127,fields,6,EX_BOUNDS,0);
 b[114]=5;failures+=eval_expect(b,128,fields,6,EX_REFERENCE,0);
 struct expr_error e={0};failures+=expr_evaluate(b,128,fields,6,NULL,&e)!=EX_ARGUMENT;
 failures+=eval_expect(expr_empty,32,fields,0,EX_OK,0);
 return failures;
}
static int eval_bounds(void)
{
 uint8_t b[4128];memset(b,0,sizeof b);memcpy(b,expr_empty,32);zcl_write_u16_le(b+12,256);
 eval_leaf(b+32,EX_CONST_I32,1);
 for(unsigned i=1;i<256;i++) {
  eval_leaf(b+32+16*i,EX_ADD_SAT,0);
  zcl_write_u16_le(b+34+16*i,(uint16_t)(i-1));zcl_write_u16_le(b+36+16*i,0);
 }
 double fields[XF_COUNT]={0};int failures=eval_expect(b,sizeof b,fields,256,EX_OK,256);
 failures+=eval_expect(b,sizeof b,fields,255,EX_EVAL_BUDGET,0);
 b[4114]=255;b[4115]=255;failures+=eval_expect(b,sizeof b,fields,256,EX_REFERENCE,0);
 memset(b,0,288);memcpy(b,expr_empty,32);b[12]=16;
 for(unsigned i=0;i<16;i++) {eval_leaf(b+32+16*i,EX_FIELD,(int32_t)i);fields[i]=i<13?-17+(double)i:(double)(i&1);}
 struct expr_values out={0};bool success=expr_evaluate(b,288,fields,16,&out,NULL)==EX_OK;
 failures+=!success;
 for(unsigned i=0;i<16;i++)failures+=!success || out.value[i]!=(int32_t)fields[i];
 fields[0]=INT32_MIN;fields[1]=INT32_MAX;
 failures+=expr_evaluate(b,288,fields,16,&out,NULL)!=EX_OK;
 failures+=out.value[0]!=INT32_MIN || out.value[1]!=INT32_MAX;
 return failures;
}

static int eval_defensive_bounds(void)
{
 uint8_t b[64]={0};eval_leaf(b+32,EX_FIELD,XF_COUNT);
 struct expr_eval_table t={b,sizeof b,48,1};const uint8_t *r=NULL;
 struct expr_error e={0};int failures=0;
 failures+=eval_record(&t,1,&r,&e)!=EX_REFERENCE;
 t.count=257;failures+=eval_record(&t,256,&r,&e)!=EX_REFERENCE;t.count=1;
 t.end=47;failures+=eval_record(&t,0,&r,&e)!=EX_BOUNDS;
 t.end=65;failures+=eval_record(&t,0,&r,&e)!=EX_BOUNDS;
 t.end=31;failures+=eval_record(&t,0,&r,&e)!=EX_BOUNDS;t.end=48;
 int32_t fields[XF_COUNT]={0},values[256]={0},args[3]={0};
 failures+=eval_one(&t,0,fields,values,&e)!=EX_FIELD_ID;
 eval_leaf(b+32,EX_ADD_SAT,0);zcl_write_u16_le(b+34,2);zcl_write_u16_le(b+36,0);
 t.count=2;failures+=eval_args(&t,3,b+32,values,args,&e)!=EX_REFERENCE;
 t.count=4;zcl_write_u16_le(b+34,3);
 failures+=eval_args(&t,3,b+32,values,args,&e)!=EX_REFERENCE;
 t.count=300;zcl_write_u16_le(b+34,256);
 failures+=eval_args(&t,300,b+32,values,args,&e)!=EX_REFERENCE;
 int32_t value=42;
 failures+=eval_math(16,args,&value,0,&e)!=EX_OPCODE || value!=42;
 failures+=eval_logic(16,args,&value,0,&e)!=EX_OPCODE || value!=42;
 return failures;
}

static size_t draw_fixture(uint8_t *b,unsigned kind,unsigned draws)
{
 memset(b,0,2048);memcpy(b,expr_empty,32);b[12]=8;b[14]=(uint8_t)draws;
 const int32_t value[]={0,0,10,20,30,40,-1,12};
 for(unsigned i=0;i<8;i++)eval_leaf(b+32+16*i,EX_CONST_I32,value[i]);
 eval_leaf(b+48,EX_FIELD,XF_SHIELD);
 size_t at=160;
 if(kind>=3) {
  b[16]=1;b[18]=2;b[20]=3;b[at+2]=2;at+=8;
  b[at]=1;zcl_write_u16_le(b+at+2,EXPR_NONE);b[at+8]=3;at+=12;
  b[at]=2;b[at+2]=2;at+=12;
 }
 for(unsigned i=0;i<draws;i++,at+=24) {
  b[at]=(uint8_t)kind;b[at+2]=1;b[at+4]=2;b[at+6]=3;
  b[at+8]=(uint8_t)(kind==3?0:4);b[at+10]=(uint8_t)(kind==3?0:5);
  b[at+12]=6;b[at+14]=(uint8_t)(kind>=3?7:0);
  zcl_write_u16_le(b+at+18,kind>=3?0:EXPR_NONE);
 }
 if(kind>=3){memcpy(b+at,"HUD",3);at+=3;}
 return at;
}
static struct expr_values draw_values(void)
{
 struct expr_values v={.count=8,.steps=8,.value={0,1,10,20,30,40,-1,12}};return v;
}
static int draw_expect(const void *b,size_t n,const struct expr_values *v,
 unsigned ops,unsigned text,enum expr_status want)
{
 struct sky_hud_recipe_v1 out,before;memset(&out,0x5a,sizeof out);before=out;
 struct expr_error e={0};enum expr_status got=expr_build_draws(b,n,v,ops,text,&out,&e);
 bool ok=got==want && e.code==got && e.reason &&
  (got==EX_OK || !memcmp(&out,&before,sizeof out));
 if(got==EX_OK)ok=ok && out.op_count<=ops && out.text_used<=text && memcmp(&out,&before,sizeof out);
 if(!ok)printf("draw expected=%u got=%u atomic=%d\n",want,got,!memcmp(&out,&before,sizeof out));
 return !ok;
}
static int draw_geometry_result(const struct sky_hud_recipe_v1 *out,unsigned kind,bool success)
{
 const struct sky_hud_op_v1 *o=&out->ops[0];int failures=0;
 success=success && out->op_count==1 && o->kind==kind;
 failures+=!success || out->op_count!=1 || o->kind!=kind;
 failures+=!success || o->x!=10 || o->y!=20 || o->rgba!=UINT32_MAX;
 failures+=!success || o->w!=(kind==3?0:30) || o->h!=(kind==3?0:40);
 return failures;
}
static int draw_text_result(const struct sky_hud_recipe_v1 *out,unsigned kind,bool success)
{
 const struct sky_hud_op_v1 *o=&out->ops[0];int failures=0;
 success=success && out->op_count==1 && o->kind==kind;
 failures+=!success || o->font_px!=(kind>=3?12u:0u) || o->align!=0;
 failures+=!success || out->text_used!=(kind>=3?5u:0u) || o->text_off!=0 || o->text_len!=(kind>=3?5u:0u);
 failures+=!success || (kind>=3 && memcmp(out->text,"HUD10",5));
 return failures;
}
static int draw_kinds(void)
{
 uint8_t b[2048];struct expr_values v=draw_values();int failures=0;
 for(unsigned kind=1;kind<=4;kind++) {
  size_t n=draw_fixture(b,kind,1);struct sky_hud_recipe_v1 out={0};struct expr_error e={0};
  bool success=expr_build_draws(b,n,&v,64,1024,&out,&e)==EX_OK;
  failures+=!success;
  failures+=draw_geometry_result(&out,kind,success)+draw_text_result(&out,kind,success);
  v.value[1]=0;failures+=draw_expect(b,n,&v,0,0,EX_OK);v.value[1]=1;
 }
 size_t n=draw_fixture(b,3,2);struct sky_hud_recipe_v1 out={0};
 bool success=expr_build_draws(b,n,&v,2,10,&out,NULL)==EX_OK;
 failures+=!success || out.op_count!=2 || out.text_used!=10 || out.ops[1].text_off!=5 || out.ops[1].text_len!=5;
 const int32_t numbers[]={0,-42,INT32_MIN,INT32_MAX};
 const char *const strings[]={"HUD0","HUD-42","HUD-2147483648","HUD2147483647"};
 n=draw_fixture(b,3,1);
 for(unsigned i=0;i<4;i++) {
  v.value[2]=numbers[i];success=expr_build_draws(b,n,&v,1,14,&out,NULL)==EX_OK;
  failures+=!success || out.text_used!=strlen(strings[i]) || memcmp(out.text,strings[i],strlen(strings[i]));
 }
 v=draw_values();n=draw_fixture(b,3,1);b[208]=2; /* align ref is numeric expression 2. */
 v.value[2]=2;success=expr_build_draws(b,n,&v,1,5,&out,NULL)==EX_OK;
 failures+=!success || out.ops[0].align!=2;
 struct expr_values empty={0};
 failures+=draw_expect(expr_empty,32,&empty,0,0,EX_OK);
 return failures;
}
static int draw_refusals(void)
{
 uint8_t b[2048];struct expr_values v=draw_values();size_t n=draw_fixture(b,3,1);int failures=0;
 failures+=draw_expect(NULL,n,&v,64,1024,EX_ARGUMENT);
 failures+=draw_expect(b,n,NULL,64,1024,EX_ARGUMENT);
 struct expr_error e={0};failures+=expr_build_draws(b,n,&v,64,1024,NULL,&e)!=EX_ARGUMENT;
 failures+=draw_expect(b,n,&v,65,1024,EX_LIMIT);
 failures+=draw_expect(b,n,&v,64,1025,EX_LIMIT);
 failures+=draw_expect(b,n-1,&v,64,1024,EX_BOUNDS);
 v.count=7;failures+=draw_expect(b,n,&v,64,1024,EX_VALUES);v.count=8;
 v.steps=7;failures+=draw_expect(b,n,&v,64,1024,EX_VALUES);v.steps=8;
 v.value[1]=2;failures+=draw_expect(b,n,&v,64,1024,EX_VALUES);v.value[1]=1;
 for(unsigned i=0;i<2;i++) {
  v.value[7]=i?4097:0;failures+=draw_expect(b,n,&v,64,1024,EX_RANGE);
 }
 v.value[7]=12;b[208]=2;
 for(unsigned i=0;i<2;i++) {v.value[2]=i?3:-1;failures+=draw_expect(b,n,&v,64,1024,EX_RANGE);}
 v=draw_values();n=draw_fixture(b,1,1);
 v.value[4]=-1;failures+=draw_expect(b,n,&v,64,1024,EX_RANGE);v.value[4]=30;
 v.value[5]=-1;failures+=draw_expect(b,n,&v,64,1024,EX_RANGE);v.value[5]=40;
 b[162]=8;failures+=draw_expect(b,n,&v,64,1024,EX_TYPE);
 n=draw_fixture(b,3,1);b[210]=1;failures+=draw_expect(b,n,&v,64,1024,EX_SCHEMA);
 n=draw_fixture(b,3,1);b[172]=1;failures+=draw_expect(b,n,&v,64,1024,EX_LITERAL);
 n=draw_fixture(b,1,1);b[160]=5;failures+=draw_expect(b,n,&v,64,1024,EX_SCHEMA);
 return failures;
}
static int draw_capacity(void)
{
 uint8_t b[2048];struct expr_values v=draw_values();size_t n=draw_fixture(b,1,64);int failures=0;
 struct sky_hud_recipe_v1 out={0};bool success=expr_build_draws(b,n,&v,64,1024,&out,NULL)==EX_OK;
 failures+=!success || out.op_count!=64 || out.ops[63].kind!=1;
 failures+=draw_expect(b,n,&v,63,1024,EX_OUTPUT);
 n=draw_fixture(b,3,2);failures+=draw_expect(b,n,&v,2,9,EX_OUTPUT);
 failures+=draw_expect(b,n,&v,1,10,EX_OUTPUT);
 n=draw_fixture(b,3,1);failures+=draw_expect(b,n,&v,1,4,EX_OUTPUT);
 failures+=draw_expect(b,n,&v,1,5,EX_OK);
 /* One canonical literal consumes the entire ABI arena, without a terminator. */
 b[18]=1;zcl_write_u32_le(b+20,1024);b[162]=1;zcl_write_u32_le(b+176,1024);
 memmove(b+180,b+192,24);memset(b+204,'Z',1024);n=1228;
 success=expr_build_draws(b,n,&v,1,1024,&out,NULL)==EX_OK;
 failures+=!success || out.text_used!=1024 || out.ops[0].text_len!=1024 || out.text[1023]!='Z';
 failures+=draw_expect(b,n,&v,1,1023,EX_OUTPUT);
 return failures;
}

static int draw_followups(void)
{
 uint8_t b[2048];size_t n=draw_fixture(b,3,1);double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 struct expr_values v={0};struct sky_hud_recipe_v1 out,zero={0};memset(&out,0x5a,sizeof out);
 bool evaluated=expr_evaluate(b,n,fields,8,&v,NULL)==EX_OK;int failures=0;
 bool success=expr_build_draws(b,n,&v,64,1024,&out,NULL)==EX_OK;
 failures+=!evaluated || !success;
 failures+=draw_geometry_result(&out,3,success)+draw_text_result(&out,3,success);
 failures+=!success || memcmp(out.ops+1,zero.ops+1,63*sizeof out.ops[0]);
 failures+=!success || memcmp(out.text+5,zero.text+5,1019);
 /* Empty pool, one zero-length literal: no NUL or out-of-table byte is read. */
 b[18]=1;b[20]=0;b[162]=1;b[176]=0;memmove(b+180,b+192,24);n=204;
 success=expr_build_draws(b,n,&v,1,0,&out,NULL)==EX_OK;
 failures+=!success || out.op_count!=1 || out.text_used!=0 || out.ops[0].text_len!=0;
 return failures;
}
static int draw_defensive(void)
{
 uint8_t b[2048];size_t n=draw_fixture(b,3,1);struct expr_values v=draw_values();
 struct draw_table t={b,n,{160,168,192,216},{1,2,1,3},&v,8,64,1024};
 struct sky_hud_recipe_v1 out={0};struct expr_error e={0};const uint8_t *p=NULL;int32_t value=0;int failures=0;
 failures+=draw_read(&t,4,0,&p,&e)!=EX_REFERENCE;
 failures+=draw_read(&t,0,1,&p,&e)!=EX_REFERENCE;
 t.base[0]=n+1;failures+=draw_read(&t,0,0,&p,&e)!=EX_BOUNDS;
 t.base[0]=n-7;failures+=draw_read(&t,0,0,&p,&e)!=EX_BOUNDS;
 t.base[0]=160;t.count[0]=9;failures+=draw_read(&t,0,8,&p,&e)!=EX_BOUNDS;t.count[0]=1;
 t.expressions=7;failures+=draw_value(&t,7,&value,&e)!=EX_REFERENCE;t.expressions=8;
 v.count=7;failures+=draw_value(&t,7,&value,&e)!=EX_REFERENCE;v.count=257;t.expressions=257;
 failures+=draw_value(&t,256,&value,&e)!=EX_REFERENCE;v.count=8;t.expressions=8;
 b[172]=4;failures+=draw_piece(&t,0,&out,&e)!=EX_LITERAL;b[172]=0;
 b[176]=4;failures+=draw_piece(&t,0,&out,&e)!=EX_LITERAL;b[176]=3;
 t.base[3]=n;failures+=draw_piece(&t,0,&out,&e)!=EX_BOUNDS;t.base[3]=216;
 b[168]=3;failures+=draw_piece(&t,0,&out,&e)!=EX_OPCODE;b[168]=1;
 b[182]=8;failures+=draw_piece(&t,1,&out,&e)!=EX_REFERENCE;b[182]=2;
 b[160]=3;failures+=draw_text(&t,0,&out,&out.ops[0],&e)!=EX_REFERENCE;b[160]=0;
 b[162]=3;failures+=draw_text(&t,0,&out,&out.ops[0],&e)!=EX_REFERENCE;b[162]=2;
 b[192]=5;failures+=draw_emit(&t,0,&out,&e)!=EX_SCHEMA;
 out.text_used=1025;failures+=draw_append(&t,&out,NULL,0,&e)!=EX_OUTPUT;
 return failures;
}

static int admit_expect(const char *path,const uint8_t pin[32],const double fields[XF_COUNT],
 unsigned budget,unsigned ops,unsigned text,enum expr_admit_status want,enum expr_status detail)
{
 struct expr_part current,before;memset(&current,0x5a,sizeof current);before=current;
 struct expr_admit_error e={0};enum expr_admit_status got=expr_admit_file(path,pin,fields,budget,ops,text,&current,&e);
 bool ok=got==want && e.stage==got && e.detail.code==detail && e.detail.reason &&
  (got==EX_ADMIT_OK?memcmp(&current,&before,sizeof current)!=0:!memcmp(&current,&before,sizeof current));
 if(!ok)printf("admit expected=%u/%u got=%u/%u atomic=%d\n",(unsigned)want,(unsigned)detail,(unsigned)got,(unsigned)e.detail.code,!memcmp(&before,&current,sizeof current));
 return !ok;
}
static bool admit_fixture_write(const char *path,const void *b,size_t n,uint8_t pin[32])
{
 FILE *f=fopen(path,"wb");if(!f){perror("admit fixture open");return false;}
 size_t got=fwrite(b,1,n,f);int closed=fclose(f);
 if(got!=n || closed){fprintf(stderr,"admit fixture write/close failure\n");return false;}
 struct sha256_ctx hash;sha256_init(&hash);sha256_write(&hash,b,n);sha256_finalize(&hash,pin);return true;
}
static int admit_success(const char *path,const uint8_t *b,size_t n,const uint8_t pin[32],const double *fields)
{
 struct expr_part out;memset(&out,0x5a,sizeof out);struct expr_admit_error e={0};int failures=0;
 if(expr_admit_file(path,pin,fields,256,64,1024,&out,&e)!=EX_ADMIT_OK)return 1;
 failures+=out.length!=n;failures+=memcmp(out.bytes,b,n)!=0;failures+=memcmp(out.sha256,pin,32)!=0;
 failures+=out.recipe.op_count!=1;failures+=out.recipe.text_used!=5;
 failures+=memcmp(out.recipe.text,"HUD10",5)!=0;
 for(size_t i=n;i<EXPR_MAX_BYTES;i++)failures+=out.bytes[i]!=0;
 const struct sky_hud_recipe_v1 zero={0};
 failures+=memcmp(out.recipe.ops+1,zero.ops+1,sizeof zero.ops-sizeof zero.ops[0])!=0;
 failures+=memcmp(out.recipe.text+5,zero.text+5,sizeof zero.text-5)!=0;
 failures+=expr_admit_file(path,pin,fields,256,64,1024,&out,NULL)!=EX_ADMIT_OK;
 return failures;
}
static int admit_stage_cases(const char *path,uint8_t pin[32],double *fields)
{
 int failures=0;struct expr_admit_error e={0};
 pin[0]^=1;failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_PIN,EX_FORMAT);pin[0]^=1;
 failures+=admit_expect(path,pin,fields,7,64,1024,EX_ADMIT_EVALUATE,EX_EVAL_BUDGET);
 fields[XF_SHIELD]=2;failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_EVALUATE,EX_SNAPSHOT);fields[XF_SHIELD]=1;
 failures+=admit_expect(path,pin,fields,256,0,1024,EX_ADMIT_DRAW,EX_OUTPUT);
 failures+=admit_expect(path,pin,fields,256,64,4,EX_ADMIT_DRAW,EX_OUTPUT);
 failures+=admit_expect(path,pin,fields,256,65,1024,EX_ADMIT_DRAW,EX_LIMIT);
 failures+=admit_expect(path,pin,fields,256,64,1025,EX_ADMIT_DRAW,EX_LIMIT);
 failures+=admit_expect(path,pin,fields,257,64,1024,EX_ADMIT_EVALUATE,EX_LIMIT);
 failures+=admit_expect(NULL,pin,fields,256,64,1024,EX_ADMIT_ARGUMENT,EX_ARGUMENT);
 failures+=admit_expect("",pin,fields,256,64,1024,EX_ADMIT_ARGUMENT,EX_ARGUMENT);
 failures+=admit_expect(path,NULL,fields,256,64,1024,EX_ADMIT_ARGUMENT,EX_ARGUMENT);
 failures+=admit_expect(path,pin,NULL,256,64,1024,EX_ADMIT_ARGUMENT,EX_ARGUMENT);
 failures+=expr_admit_file(path,pin,fields,256,64,1024,NULL,&e)!=EX_ADMIT_ARGUMENT;
 return failures;
}
static int admit_probe_cases(const char *path,const uint8_t pin[32],const double *fields,size_t n)
{
 int failures=0;
 admit_probe_mode=ADMIT_PROBE_PARTIAL;admit_probe_reads=admit_probe_closes=admit_probe_stats=0;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_OK,EX_OK);
 failures+=admit_probe_reads!=(n+2)/3;failures+=admit_probe_stats!=2;failures+=admit_probe_closes!=1;
 for(unsigned mode=ADMIT_PROBE_EOF;mode<=ADMIT_PROBE_STAT_AFTER;mode++) {
  admit_probe_mode=mode;admit_probe_reads=admit_probe_closes=admit_probe_stats=0;
  failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_READ,EX_IO);
  failures+=admit_probe_closes!=1;
  if(mode==ADMIT_PROBE_STAT_AFTER)failures+=admit_probe_stats!=2 || admit_probe_reads!=1;
 }
 admit_probe_mode=ADMIT_PROBE_NONE;return failures;
}
static int admit_wire_cases(const char *path,uint8_t *b,size_t n,uint8_t pin[32],const double *fields)
{
 int failures=0;
 if(!admit_fixture_write(path,b,n-1,pin))return 1;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_VALIDATE,EX_BOUNDS);
 b[0]='X';if(!admit_fixture_write(path,b,n,pin))return failures+1;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_VALIDATE,EX_FORMAT);
 if(!admit_fixture_write(path,b,EXPR_MAX_BYTES+1,pin))return failures+1;
 admit_probe_reads=0;failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_READ,EX_LIMIT);
 failures+=admit_probe_reads!=0;
 if(!admit_fixture_write(path,b,0,pin))return failures+1;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_VALIDATE,EX_BOUNDS);
 n=draw_fixture(b,1,1);zcl_write_u32_le(b+104,UINT32_MAX);
 if(!admit_fixture_write(path,b,n,pin))return failures+1;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_DRAW,EX_RANGE);
 memset(b,0,80);memcpy(b,expr_empty,32);b[12]=3;
 eval_leaf(b+32,EX_CONST_I32,10);eval_leaf(b+48,EX_CONST_I32,0);eval_leaf(b+64,EX_MULDIV,0);
 zcl_write_u16_le(b+66,0);zcl_write_u16_le(b+68,0);zcl_write_u16_le(b+70,1);
 if(!admit_fixture_write(path,b,80,pin))return failures+1;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_EVALUATE,EX_DIV_ZERO);
 return failures;
}
static int admit_path_cases(const char *path,uint8_t pin[32],const double *fields)
{
 char dir[512],link[520];int failures=0;
 if(!test_mkdtemp(dir,sizeof dir,"expr_admit_dir"))return 1;
 failures+=admit_expect(dir,pin,fields,256,64,1024,EX_ADMIT_READ,EX_IO);
 if(snprintf(link,sizeof link,"%s/link",dir)<0){test_cleanup_tmpdir(dir);return failures+1;}
#if !defined(_WIN32)
 if(symlink(path,link)){perror("admit fixture symlink");test_cleanup_tmpdir(dir);return failures+1;}
 failures+=admit_expect(link,pin,fields,256,64,1024,EX_ADMIT_READ,EX_IO);
 if(unlink(link)){perror("admit symlink unlink");failures++;}
#endif
 test_cleanup_tmpdir(dir);
 if(unlink(path)){perror("admit fixture unlink");return failures+1;}
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_READ,EX_IO);
 return failures;
}
static int admit_limit_case(const char *path,uint8_t pin[32],const double *fields)
{
 uint8_t b[EXPR_MAX_BYTES]={0};memcpy(b,expr_empty,32);
 zcl_write_u16_le(b+12,256);b[14]=64;b[16]=64;zcl_write_u16_le(b+18,256);
 zcl_write_u32_le(b+20,1024);size_t at=32;
 for(unsigned i=0;i<256;i++,at+=16)memcpy(b+at,expr_rect+32,16);
 b[48]=EX_FIELD;b[56]=XF_SHIELD;
 for(unsigned i=0;i<64;i++,at+=8){zcl_write_u16_le(b+at,(uint16_t)(4*i));b[at+2]=4;}
 for(unsigned i=0;i<256;i++,at+=12) {
  b[at]=1;zcl_write_u16_le(b+at+2,EXPR_NONE);
  zcl_write_u32_le(b+at+4,16*((i+3)/4));if(i%4==0)b[at+8]=16;
 }
 for(unsigned i=0;i<64;i++,at+=24)memcpy(b+at,expr_rect+64,24);
 memset(b+at,'A',1024);
 if(!admit_fixture_write(path,b,sizeof b,pin))return 1;
 struct expr_part out={0};struct expr_admit_error e={0};int failures=0;
 failures+=admit_expect(path,pin,fields,256,64,1024,EX_ADMIT_OK,EX_OK);
 if(expr_admit_file(path,pin,fields,256,64,1024,&out,&e)!=EX_ADMIT_OK)return failures+1;
 failures+=out.length!=EXPR_MAX_BYTES;failures+=memcmp(out.bytes,b,sizeof b)!=0;
 failures+=out.recipe.op_count!=64;return failures;
}

static int admit_file_cases(void)
{
 char path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"expr_admit");
 if(fd<0){perror("admit fixture create");return 1;}
 if(close(fd)){perror("admit fixture close");unlink(path);return 1;}
 uint8_t b[EXPR_MAX_BYTES+1]={0},pin[32];double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 size_t n=draw_fixture(b,3,1);int failures=0;
 if(!admit_fixture_write(path,b,n,pin)){unlink(path);return 1;}
 failures+=admit_success(path,b,n,pin,fields);failures+=admit_stage_cases(path,pin,fields);
 failures+=admit_probe_cases(path,pin,fields,n);failures+=admit_wire_cases(path,b,n,pin,fields);
 failures+=admit_limit_case(path,pin,fields);failures+=admit_path_cases(path,pin,fields);
 return failures;
}

/* Trace only the raylib calls made by the production recipe renderer. */
#include <raylib.h>
static char use_trace[4096];static size_t use_trace_at;
static void use_trace_append(const char *format,...)
{
 va_list args;va_start(args,format);
 int n=vsnprintf(use_trace+use_trace_at,sizeof use_trace-use_trace_at,format,args);va_end(args);
 if(n<0 || (size_t)n>=sizeof use_trace-use_trace_at){fprintf(stderr,"HUD trace overflow\n");abort();}
 use_trace_at+=(size_t)n;
}

static void use_shape(char kind,Rectangle r,Color c)
{ use_trace_append("%c %.1f %.1f %.1f %.1f %u %u %u %u\n",kind,(double)r.x,(double)r.y,(double)r.width,(double)r.height,(unsigned)c.r,(unsigned)c.g,(unsigned)c.b,(unsigned)c.a); }
static void use_rect(Rectangle r,Color c){use_shape('R',r,c);}
static float use_line_thickness;
static void use_lines(Rectangle r,float thick,Color c){use_line_thickness=thick;use_shape('L',r,c);}
static Font use_font(void) {return (Font){.baseSize=10,.texture={.id=1}};}
static float use_measure_spacing,use_draw_spacing,use_measure_size,use_draw_size;
static Font use_measured_font,use_drawn_font;static Color use_drawn_color;
static bool use_metric_override;static float use_metric_width;
static Vector2 use_measure_ex(Font font,const char *text,float px,float spacing)
{
 use_measured_font=font;use_measure_spacing=spacing;use_measure_size=px;size_t n=strlen(text);
 return (Vector2){use_metric_override?use_metric_width:(float)n*px+(n?(float)(n-1)*spacing:0.0f),px};
}
[[maybe_unused]] static int use_measure(const char *text,int px)
{ if(px<10)px=10;return (int)use_measure_ex(use_font(),text,(float)px,(float)(px/10)).x; }

static void use_text(Font f,const char *text,Vector2 at,float px,float spacing,Color c)
{ use_drawn_font=f;use_drawn_color=c;use_draw_spacing=spacing;use_draw_size=px;use_trace_append("T %s %.1f %.1f %.1f\n",text,(double)at.x,(double)at.y,(double)px); }
#define DrawRectangleRec use_rect
#define DrawRectangleLinesEx use_lines
#define GetFontDefault use_font
#define MeasureText use_measure
#define MeasureTextEx use_measure_ex
#define DrawTextEx use_text
static unsigned reload_pin_opens,reload_pin_closes;
static bool reload_pin_open(struct platform_positioned_file *f,const char *path)
{ bool ok=platform_positioned_file_open(f,path);if(ok)++reload_pin_opens;return ok; }
static void reload_pin_close(struct platform_positioned_file *f)
{ ++reload_pin_closes;platform_positioned_file_close(f); }

#define platform_positioned_file_open reload_pin_open
#define platform_positioned_file_close reload_pin_close
#define platform_positioned_file_read admit_probe_read
#define platform_positioned_file_snapshot(...) admit_probe_snapshot(__VA_ARGS__)
#define fprintf use_diagnostic
#include "../../../apps/skycombat/part/expr_use.h"
#undef fprintf
#undef platform_positioned_file_open
#undef platform_positioned_file_close
#undef platform_positioned_file_read
#undef platform_positioned_file_snapshot
#undef DrawRectangleRec
#undef DrawRectangleLinesEx
#undef GetFontDefault
#undef MeasureText
#undef MeasureTextEx
#undef DrawTextEx
static void use_builtin(void *context)
{ const char *s=context;use_trace_append("%s",s); }
static int use_option_cases(void)
{
 struct sky_expr_option option,before;memset(&option,0x5a,sizeof option);char good[100];memset(good,'0',sizeof good);
 memcpy(good,"--hud-part=",11);good[75]=':';memcpy(good+76,"hud.bin",8);
 char *args[]={"skycombat",good,NULL};int failures=0;
 failures+=!sky_expr_option_parse(1,args,&option) || option.path!=NULL;
 failures+=!sky_expr_option_parse(2,args,&option) || !option.path || strcmp(option.path,"hud.bin");
 const char *bad[]={"--hud-part=","--hud-part=00:file","--bogus","--bad-part=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:file","--hud-part=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:","--hud-part=gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg:file"};
 for(unsigned i=0;i<sizeof bad/sizeof *bad;i++) {
  before=option;args[1]=(char *)bad[i];
  failures+=sky_expr_option_parse(2,args,&option) || memcmp(&before,&option,sizeof option)!=0;
 }
 args[1]=good;before=option;
 failures+=sky_expr_option_parse(3,args,&option) || memcmp(&before,&option,sizeof option)!=0;
 good[75]='!';failures+=sky_expr_option_parse(2,args,&option) || memcmp(&before,&option,sizeof option)!=0;good[75]=':';
 memset(good+11,'A',64);args[1]=good;
 failures+=!sky_expr_option_parse(2,args,&option) || option.pin[0]!=0xaa || option.pin[31]!=0xaa;
 return failures;
}
static int use_file_cases(void)
{
 char path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"use_hud");if(fd<0)return 1;
 if(close(fd)){unlink(path);return 1;}
 uint8_t b[2048]={0},pin[32];size_t n=draw_fixture(b,3,1);
 if(!admit_fixture_write(path,b,n,pin)){unlink(path);return 1;}
 struct sky_expr_option option={.path=path};memcpy(option.pin,pin,32);
 double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;struct sky_expr_hud hud={0};int failures=0;
 sky_expr_start(&option,fields,&hud);failures+=!hud.active;
 use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,"T HUD10 10.0 20.0 12.0\n")!=0;
 /* A frame does not reopen the path or re-admit; captured recipe remains. */
 unlink(path);use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,"T HUD10 10.0 20.0 12.0\n")!=0;
 if(!admit_fixture_write(path,b,n,pin)){return 1;}option.pin[0]^=1;sky_expr_start(&option,fields,&hud);failures+=hud.active;
 use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,"BUILTIN\n")!=0;unlink(path);
 return failures;
}

static int use_box_case(void)
{
 char path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"use_box");if(fd<0)return 1;
 if(close(fd)){unlink(path);return 1;}
 uint8_t b[2048]={0},pin[32];size_t n=draw_fixture(b,4,1);
 zcl_write_u32_le(b+32+16*6+8,0x11223344);
 if(!admit_fixture_write(path,b,n,pin)){unlink(path);return 1;}
 struct sky_expr_option option={.path=path};memcpy(option.pin,pin,32);
 double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;struct sky_expr_hud hud={0};
 sky_expr_start(&option,fields,&hud);int failures=!hud.active;
 use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,"R -52.0 20.0 124.0 40.0 17 34 51 68\n")!=0;
 unlink(path);return failures;
}

static int use_refusal_cases(void)
{
 char path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"use_refusal");if(fd<0)return 1;
 if(close(fd)){unlink(path);return 1;}
 int failures=0;uint8_t b[2048]={0},pin[32];
 for(unsigned mode=0;mode<5;mode++) {
  size_t n=draw_fixture(b,3,1);double fields[XF_COUNT]={0};fields[XF_SHIELD]=mode==2?2:1;
  if(mode==1){b[0]=0;}if(mode==3){zcl_write_u32_le(b+32+16*7+8,0);}
  if(!admit_fixture_write(path,b,n,pin)){unlink(path);return 1;}
  struct sky_expr_option option={.path=path};memcpy(option.pin,pin,32);
  if(mode==0){option.pin[0]^=1;}if(mode==4){unlink(path);}
  struct sky_expr_hud hud={0};unsigned before=use_diag_events;sky_expr_start(&option,fields,&hud);
  failures+=hud.active || use_diag_events!=before+1;
  use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
  failures+=strcmp(use_trace,"BUILTIN\n")!=0 || use_diag_events!=before+1;
 }
 unlink(path);return failures;
}
static int use_render_cases(void)
{
 struct sky_hud_recipe_v1 recipe={.op_count=1,.text_used=5};memcpy(recipe.text,"HUD10",5);
 struct sky_hud_op_v1 *op=recipe.ops;
 *op=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_TEXT,.x=10,.y=20,.rgba=0x11223344,.font_px=13,.text_len=5};
 int failures=0;
 const char *expected[]={"T HUD10 10.0 20.0 13.0\n","T HUD10 -24.0 20.0 13.0\n","T HUD10 -59.0 20.0 13.0\n"};
 for(unsigned align=0;align<3;align++) {
  op->align=align;use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&recipe,op);
  failures+=strcmp(use_trace,expected[align])!=0;
  failures+=use_drawn_color.r!=17 || use_drawn_color.g!=34 || use_drawn_color.b!=51 || use_drawn_color.a!=68;
 }
 op->align=0;op->kind=SKY_HUD_OP_TEXT_BOX;op->w=30;op->h=40;
 use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&recipe,op);
 failures+=strcmp(use_trace,"R -54.0 20.0 129.0 40.0 17 34 51 68\n")!=0;
 op->text_len=0;op->font_px=0;op->kind=SKY_HUD_OP_RECT;use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&recipe,op);
 failures+=strcmp(use_trace,"R 10.0 20.0 30.0 40.0 17 34 51 68\n")!=0;
 op->kind=SKY_HUD_OP_RECT_LINES;use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&recipe,op);
 failures+=strcmp(use_trace,"L 10.0 20.0 30.0 40.0 17 34 51 68\n")!=0;
 failures+=use_line_thickness!=1.0f;
 return failures;
}

static int use_multiple_ops(void)
{
 struct sky_expr_hud hud={.active=true};struct sky_hud_recipe_v1 *r=&hud.part.recipe;r->op_count=2;
 r->ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT,.x=1,.y=2,.w=3,.h=4,.rgba=0x11223344};
 r->ops[1]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT_LINES,.x=5,.y=6,.w=7,.h=8,.rgba=0x55667788};
 use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 return strcmp(use_trace,"R 1.0 2.0 3.0 4.0 17 34 51 68\nL 5.0 6.0 7.0 8.0 85 102 119 136\n")!=0;
}

static int use_metric_cases(void)
{
 struct sky_hud_recipe_v1 r={.op_count=1,.text_used=5};memcpy(r.text,"HUD10",5);
 struct sky_hud_op_v1 *op=r.ops;
 *op=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_TEXT,.x=10,.y=20,.font_px=25,.text_len=5,.align=SKY_HUD_ALIGN_RIGHT};
 const unsigned sizes[]={25,7};const char *expected[]={"T HUD10 -119.0 20.0 25.0\n","T HUD10 -29.0 20.0 7.0\n"};int failures=0;
 for(unsigned i=0;i<2;i++) {
  op->font_px=sizes[i];use_measure_spacing=-1;use_draw_spacing=-2;use_measure_size=-1;use_draw_size=-2;
  use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&r,op);
  failures+=strcmp(use_trace,expected[i])!=0;failures+=use_measure_spacing!=use_draw_spacing;
  failures+=use_measure_size!=use_draw_size;
  failures+=use_measured_font.baseSize!=10 || use_drawn_font.baseSize!=10;
  failures+=use_measured_font.texture.id!=1 || use_drawn_font.texture.id!=1;
 }
 op->font_px=25;op->kind=SKY_HUD_OP_TEXT_BOX;op->w=30;op->h=40;
 use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&r,op);
 failures+=strcmp(use_trace,"R -84.0 20.0 189.0 40.0 0 0 0 0\n")!=0;
 return failures;
}

static int use_metric_range_cases(void)
{
 struct sky_hud_recipe_v1 r={.op_count=1,.text_used=1};r.text[0]='A';
 struct sky_hud_op_v1 op={.kind=SKY_HUD_OP_TEXT,.x=10,.y=20,.font_px=25,.text_len=1,.align=SKY_HUD_ALIGN_RIGHT};
 const float widths[]={NAN,INFINITY,-INFINITY,-1.0f,2147483648.0f};int failures=0;
 use_metric_override=true;
 for(unsigned i=0;i<sizeof widths/sizeof *widths;i++) {
  use_metric_width=widths[i];use_trace_at=0;use_trace[0]=0;sky_expr_draw_op(&r,&op);
  failures+=strcmp(use_trace,"T A 10.0 20.0 25.0\n")!=0;
 }
 use_metric_override=false;return failures;
}

 /* This helper owns isolated regular pin files, not shell or node state. */
static int reload_write_pin(const char *path,const uint8_t pin[32],bool newline)
{
 char hex[66];zcl_hex_encode(pin,32,hex);hex[64]='\n';
 FILE *f=fopen(path,"wb");if(!f){perror("reload pin fixture");return 1;}
 bool ok=fwrite(hex,1,newline?65:64,f)==(newline?65:64);
 return fclose(f)!=0 || !ok;
}
static int reload_option_cases(void)
{
 char part[100];memset(part,'0',sizeof part);memcpy(part,"--hud-part=",11);
 part[75]=':';memcpy(part+76,"hud.bin",8);
 char *args[]={"game",part,"--hud-pin-file=pin.txt","extra"};struct sky_expr_option out={0},before;
 int failures=!sky_expr_option_parse(3,args,&out) || !out.pin_path || strcmp(out.pin_path,"pin.txt");
 before=out;failures+=sky_expr_option_parse(4,args,&out) || memcmp(&before,&out,sizeof out);
 args[2]="--hud-pin-file=";
 failures+=sky_expr_option_parse(3,args,&out) || memcmp(&before,&out,sizeof out);
 args[2]="--bogus=pin.txt";failures+=sky_expr_option_parse(3,args,&out);
 args[1]="--hud-pin-file=pin.txt";failures+=sky_expr_option_parse(2,args,&out);
 return failures;
}
static int reload_bad_pin(const char *path,unsigned mode)
{
 FILE *f=fopen(path,"wb");if(!f){perror("bad pin fixture");return 1;}
 const char *bad=mode==1?"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg":"short";
 bool ok=fwrite(bad,1,strlen(bad),f)==strlen(bad);return fclose(f)!=0 || !ok;
}
static int reload_refusal_prepare(const char *path,const char *pin_path,unsigned mode)
{
 uint8_t bytes[2048]={0},pin[32];size_t n=draw_fixture(bytes,3,1);
 if(mode==5){bytes[0]=0;}if(mode==7){zcl_write_u32_le(bytes+32+16*7+8,0);}
 if(!admit_fixture_write(path,bytes,n,pin))return 1;
 int failures=reload_write_pin(pin_path,pin,false);
 if(mode==0)unlink(pin_path);
 if(mode==1 || mode==2)failures+=reload_bad_pin(pin_path,mode);
 if(mode==3)unlink(path);
 if(mode==4){pin[0]^=1;failures+=reload_write_pin(pin_path,pin,false);}
 return failures;
}
static int reload_preserved(const struct sky_expr_option *option,const double fields[XF_COUNT],struct sky_expr_hud *hud,enum expr_admit_status want)
{
 struct sky_expr_hud before;memcpy(&before,hud,sizeof before);
 use_trace_at=0;use_trace[0]=0;sky_expr_render(hud,use_builtin,"BUILTIN\n");
 char drawing[4096];memcpy(drawing,use_trace,sizeof drawing);unsigned events=use_diag_events;
 int failures=sky_expr_reload(option,fields,hud)!=want;
 failures+=memcmp(hud,&before,sizeof before)!=0;failures+=use_diag_events!=events+1;
 use_trace_at=0;use_trace[0]=0;sky_expr_render(hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,drawing)!=0;failures+=use_diag_events!=events+1;
 return failures;
}
static int reload_thousand(const struct sky_expr_option *option,struct sky_expr_hud *hud)
{
 double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;uint8_t bytes[2048]={0},pin[32];int failures=0;
 unsigned opens=reload_pin_opens,closes=reload_pin_closes,part_closes=admit_probe_closes;
 for(unsigned i=0;i<1000;i++) {
  size_t n=draw_fixture(bytes,3,1);zcl_write_u32_le(bytes+32+16*2+8,i%2?25:35);
  failures+=!admit_fixture_write(option->path,bytes,n,pin);failures+=reload_write_pin(option->pin_path,pin,i%2);
  failures+=sky_expr_reload(option,fields,hud)!=EX_ADMIT_OK;failures+=hud->part.recipe.ops[0].x!=(i%2?25:35);
 }
 failures+=reload_pin_opens-opens!=1000;failures+=reload_pin_closes-closes!=1000;
 failures+=admit_probe_closes-part_closes!=1000;return failures;
}

static int reload_pin_faults(const struct sky_expr_option *option,const double fields[XF_COUNT],struct sky_expr_hud *hud)
{
 const unsigned modes[]={ADMIT_PROBE_EOF,ADMIT_PROBE_ERROR,ADMIT_PROBE_OVERRUN,ADMIT_PROBE_STAT,ADMIT_PROBE_CHANGED,ADMIT_PROBE_STAT_AFTER};
 int failures=0;
 for(unsigned i=0;i<sizeof modes/sizeof *modes;i++) {
  admit_probe_mode=modes[i];admit_probe_reads=0;admit_probe_stats=0;
  unsigned closes=reload_pin_closes,part_closes=admit_probe_closes;
  failures+=reload_preserved(option,fields,hud,EX_ADMIT_READ);
  failures+=reload_pin_closes!=closes+1;failures+=admit_probe_closes!=part_closes;
 }
 admit_probe_mode=ADMIT_PROBE_PARTIAL;admit_probe_reads=0;
 failures+=sky_expr_reload(option,fields,hud)!=EX_ADMIT_OK;failures+=admit_probe_reads<=2;
 admit_probe_mode=ADMIT_PROBE_NONE;return failures;
}
static int reload_pin_formats(const struct sky_expr_option *option,const uint8_t pin[32],const double fields[XF_COUNT],struct sky_expr_hud *hud)
{
 int failures=0;char hex[67];zcl_hex_encode(pin,32,hex);
 for(unsigned mode=0;mode<4;mode++) {
  size_t length=mode==3?0:mode==1?66:mode==2?64:65;
  hex[64]='\r';hex[65]='\n';if(mode==2)hex[0]=0;
  FILE *f=fopen(option->pin_path,"wb");if(!f){perror("pin format fixture");return failures+1;}
  bool ok=fwrite(hex,1,length,f)==length;if(fclose(f) || !ok)return failures+1;
  failures+=reload_preserved(option,fields,hud,EX_ADMIT_PIN);
 }
 failures+=reload_write_pin(option->pin_path,pin,true);return failures;
}
static int reload_fresh_fields(const struct sky_expr_option *option,struct sky_expr_hud *hud)
{
 uint8_t bytes[2048]={0},pin[32];size_t n=draw_fixture(bytes,3,1);
 eval_leaf(bytes+32+16*2,EX_FIELD,XF_SCREEN_W);
 if(!admit_fixture_write(option->path,bytes,n,pin))return 1;
 int failures=reload_write_pin(option->pin_path,pin,true);double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 fields[XF_SCREEN_W]=51;failures+=sky_expr_reload(option,fields,hud)!=EX_ADMIT_OK;
 failures+=hud->part.recipe.ops[0].x!=51;
 fields[XF_SCREEN_W]=61;failures+=sky_expr_reload(option,fields,hud)!=EX_ADMIT_OK;
 failures+=hud->part.recipe.ops[0].x!=61;
 struct sky_expr_hud empty={0};failures+=sky_expr_reload(option,fields,&empty)!=EX_ADMIT_OK;
 failures+=!empty.active;failures+=empty.part.recipe.ops[0].x!=61;
 failures+=reload_pin_formats(option,pin,fields,hud);
 failures+=reload_pin_faults(option,fields,hud);return failures;
}

static int reload_cases(void)
{
 char path[PATH_MAX],pin_path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"reload_part");if(fd<0)return 1;
 if(close(fd)){unlink(path);return 1;}fd=test_mkstemp(pin_path,sizeof pin_path,"reload_pin");
 if(fd<0){unlink(path);return 1;}if(close(fd)){unlink(path);unlink(pin_path);return 1;}
 uint8_t bytes[2048]={0},pin[32];double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 size_t n=draw_fixture(bytes,3,1);int failures=0;
 if(!admit_fixture_write(path,bytes,n,pin)){unlink(path);unlink(pin_path);return 1;}
 struct sky_expr_option option={.path=path,.pin_path=pin_path};memcpy(option.pin,pin,32);
 struct sky_expr_hud hud={0};sky_expr_start(&option,fields,&hud);
 /* A changed valid recipe and fresh pin replace the captured original. */
 zcl_write_u32_le(bytes+32+16*2+8,25);
 failures+=!admit_fixture_write(path,bytes,n,pin) || reload_write_pin(pin_path,pin,true);
 failures+=sky_expr_reload(&option,fields,&hud)!=EX_ADMIT_OK;
 use_trace_at=0;use_trace[0]=0;sky_expr_render(&hud,use_builtin,"BUILTIN\n");
 failures+=strcmp(use_trace,"T HUD25 25.0 20.0 12.0\n")!=0;
 const enum expr_admit_status want[]={EX_ADMIT_READ,EX_ADMIT_PIN,EX_ADMIT_PIN,EX_ADMIT_READ,EX_ADMIT_PIN,EX_ADMIT_VALIDATE,EX_ADMIT_EVALUATE,EX_ADMIT_DRAW};
 for(unsigned mode=0;mode<8;mode++) {
  fields[XF_SHIELD]=mode==6?2:1;failures+=reload_refusal_prepare(path,pin_path,mode);
  failures+=reload_preserved(&option,fields,&hud,want[mode]);
 }
 failures+=reload_fresh_fields(&option,&hud);
 failures+=reload_thousand(&option,&hud);
 unlink(path);unlink(pin_path);return failures;
}

/* Manual display selection must never reread or mutate the admitted part. */
static int toggle_trace(const struct sky_expr_hud *hud,const char *want)
{
 use_trace_at=0;use_trace[0]=0;sky_expr_render(hud,use_builtin,"BUILTIN\n");
 return strcmp(use_trace,want)!=0;
}
static int toggle_recipe_cases(void)
{
 struct sky_expr_hud hud={0},empty={0};struct sky_expr_hud before_empty;
 memcpy(&before_empty,&empty,sizeof empty);sky_expr_toggle(&empty);
 int failures=memcmp(&empty,&before_empty,sizeof empty)!=0;
 failures+=sky_expr_custom_selected(&empty);failures+=toggle_trace(&empty,"BUILTIN\n");
 hud.active=true;hud.part.length=1;hud.part.bytes[0]=0xa5;hud.part.sha256[0]=0x7f;
 hud.part.recipe.op_count=1;
 hud.part.recipe.ops[0]=(struct sky_hud_op_v1){.kind=SKY_HUD_OP_RECT,.x=10,.y=20,.w=30,.h=40,.rgba=0x11223344};
 struct expr_part before;memcpy(&before,&hud.part,sizeof before);
 unsigned opens=reload_pin_opens,closes=reload_pin_closes,part_closes=admit_probe_closes,events=use_diag_events;
 failures+=!sky_expr_custom_selected(&hud);
 for(unsigned i=0;i<1000;i++) {
  sky_expr_toggle(&hud);bool builtin=i%2==0;
  failures+=hud.builtin_selected!=builtin;failures+=sky_expr_custom_selected(&hud)==builtin;
  failures+=toggle_trace(&hud,builtin?"BUILTIN\n":"R 10.0 20.0 30.0 40.0 17 34 51 68\n");
  failures+=memcmp(&before,&hud.part,sizeof before)!=0;
 }
 failures+=reload_pin_opens!=opens;failures+=reload_pin_closes!=closes;
 failures+=admit_probe_closes!=part_closes;failures+=use_diag_events!=events;
 return failures;
}
static int toggle_file_cases(void)
{
 char path[PATH_MAX],pin_path[PATH_MAX];int fd=test_mkstemp(path,sizeof path,"toggle_part");if(fd<0)return 1;
 if(close(fd)){unlink(path);return 1;}fd=test_mkstemp(pin_path,sizeof pin_path,"toggle_pin");
 if(fd<0){unlink(path);return 1;}if(close(fd)){unlink(path);unlink(pin_path);return 1;}
 uint8_t bytes[2048]={0},pin[32];double fields[XF_COUNT]={0};fields[XF_SHIELD]=1;
 size_t n=draw_fixture(bytes,3,1);int failures=0;
 if(!admit_fixture_write(path,bytes,n,pin)){unlink(path);unlink(pin_path);return 1;}
 struct sky_expr_option option={.path=path,.pin_path=pin_path};memcpy(option.pin,pin,32);
 struct sky_expr_hud hud={.builtin_selected=true};sky_expr_start(&option,fields,&hud);
 failures+=!hud.active || hud.builtin_selected;sky_expr_toggle(&hud);
 failures+=!hud.builtin_selected;failures+=toggle_trace(&hud,"BUILTIN\n");
 if(unlink(path) || unlink(pin_path)){perror("toggle unlink fixture");return failures+1;}
 unsigned opens=reload_pin_opens,closes=reload_pin_closes,part_closes=admit_probe_closes;
 sky_expr_toggle(&hud);failures+=toggle_trace(&hud,"T HUD10 10.0 20.0 12.0\n");
 sky_expr_toggle(&hud);failures+=toggle_trace(&hud,"BUILTIN\n");
 failures+=reload_pin_opens!=opens || reload_pin_closes!=closes || admit_probe_closes!=part_closes;
 failures+=reload_preserved(&option,fields,&hud,EX_ADMIT_READ);
 zcl_write_u32_le(bytes+32+16*2+8,25);
 failures+=!admit_fixture_write(path,bytes,n,pin) || reload_write_pin(pin_path,pin,true);
 failures+=sky_expr_reload(&option,fields,&hud)!=EX_ADMIT_OK;
 failures+=!hud.builtin_selected;failures+=toggle_trace(&hud,"BUILTIN\n");
 sky_expr_toggle(&hud);failures+=toggle_trace(&hud,"T HUD25 25.0 20.0 12.0\n");
 unlink(path);unlink(pin_path);return failures;
}

/* Reload feedback is separate from the admitted HUD and expires by frame time. */
static int notice_state_cases(void)
{
 struct sky_expr_notice notice={0};struct sky_expr_hud hud={.active=true};
 struct sky_expr_hud before;memcpy(&before,&hud,sizeof hud);int failures=0;
 const enum expr_admit_status stage[]={EX_ADMIT_ARGUMENT,EX_ADMIT_READ,EX_ADMIT_PIN,
  EX_ADMIT_VALIDATE,EX_ADMIT_EVALUATE,EX_ADMIT_DRAW,(enum expr_admit_status)99};
 const char *message[]={"HUD kept: invalid reload request","HUD kept: file could not be read",
  "HUD kept: pin mismatch or invalid","HUD kept: invalid HUD data",
  "HUD kept: values could not be evaluated","HUD kept: drawing could not be assembled",
  "HUD kept: invalid reload request"};
 for(unsigned i=0;i<sizeof stage/sizeof *stage;i++) {
  sky_expr_notice_set(&notice,stage[i]);failures+=notice.remaining!=5.0f || notice.status!=stage[i];
  failures+=strcmp(sky_expr_notice_message(&notice,&hud),message[i])!=0;
 }
 sky_expr_notice_set(&notice,EX_ADMIT_OK);
 failures+=strcmp(sky_expr_notice_message(&notice,&hud),"HUD updated")!=0;
 failures+=memcmp(&before,&hud,sizeof hud)!=0;sky_expr_toggle(&hud);
 failures+=strcmp(sky_expr_notice_message(&notice,&hud),"HUD updated (F7 to show)")!=0;
 sky_expr_toggle(&hud);failures+=strcmp(sky_expr_notice_message(&notice,&hud),"HUD updated")!=0;
 sky_expr_notice_tick(&notice,1.25f);failures+=notice.remaining!=3.75f;
 sky_expr_notice_tick(&notice,-1.0f);sky_expr_notice_tick(&notice,NAN);
 sky_expr_notice_tick(&notice,INFINITY);sky_expr_notice_tick(&notice,0.0f);
 failures+=notice.remaining!=3.75f;sky_expr_notice_tick(&notice,3.75f);failures+=notice.remaining!=0.0f;
 sky_expr_notice_tick(&notice,1.0f);failures+=notice.remaining!=0.0f;
 sky_expr_notice_set(&notice,EX_ADMIT_PIN);failures+=notice.remaining!=5.0f || notice.status!=EX_ADMIT_PIN;
 sky_expr_notice_tick(&notice,1000.0f);failures+=notice.remaining!=0.0f;
 return failures;
}
static int notice_draw_cases(void)
{
 struct sky_expr_notice notice={0};struct sky_expr_hud hud={.active=true};int failures=0;
 unsigned opens=reload_pin_opens,closes=reload_pin_closes,part_closes=admit_probe_closes,events=use_diag_events;
 use_trace_at=0;use_trace[0]=0;sky_expr_notice_render(&notice,&hud);failures+=use_trace_at!=0;
 sky_expr_notice_set(&notice,EX_ADMIT_PIN);sky_expr_notice_render(&notice,&hud);
 failures+=strcmp(use_trace,"T HUD kept: pin mismatch or invalid 12.0 67.0 18.0\nT HUD kept: pin mismatch or invalid 10.0 65.0 18.0\n")!=0;
 Color want=ORANGE;Font font=use_font();failures+=memcmp(&use_drawn_color,&want,sizeof want)!=0;
 failures+=memcmp(&use_drawn_font,&font,sizeof font)!=0 || use_draw_size!=18.0f || use_draw_spacing!=1.0f;
 sky_expr_notice_set(&notice,EX_ADMIT_OK);hud.builtin_selected=true;use_trace_at=0;use_trace[0]=0;
 sky_expr_notice_render(&notice,&hud);
 failures+=strcmp(use_trace,"T HUD updated (F7 to show) 12.0 67.0 18.0\nT HUD updated (F7 to show) 10.0 65.0 18.0\n")!=0;
 want=GREEN;failures+=memcmp(&use_drawn_color,&want,sizeof want)!=0;
 sky_expr_notice_tick(&notice,5.0f);use_trace_at=0;use_trace[0]=0;
 sky_expr_notice_render(&notice,&hud);failures+=use_trace_at!=0;
 failures+=reload_pin_opens!=opens || reload_pin_closes!=closes || admit_probe_closes!=part_closes;
 failures+=use_diag_events!=events;return failures;
}


int test_skycombat_expr(void);
int test_skycombat_expr(void)
{
 int failures=expr_headers()+expr_records()+expr_text_cases()+expr_limits();
 failures+=eval_operators()+eval_domains()+eval_bounds()+eval_defensive_bounds();
 failures+=draw_kinds()+draw_refusals()+draw_capacity()+draw_followups()+draw_defensive();
 failures+=use_metric_cases()+use_metric_range_cases();
 failures+=reload_option_cases()+reload_cases();
 failures+=toggle_recipe_cases()+toggle_file_cases();
 failures+=notice_state_cases()+notice_draw_cases();
 failures+=admit_file_cases();failures+=use_option_cases()+use_file_cases()+use_box_case()+use_refusal_cases()+use_render_cases()+use_multiple_ops();
 printf("test_skycombat_expr: %s (%d failures)\n",failures?"FAILED":"PASS",failures);
 return failures;
}
