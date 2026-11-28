/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit one pinned bounded HUD data file without changing prior state on refusal. */
#include "expr_format.h"
#include "platform/positioned_file.h"
#include "zsha256/zsha256.h"
#include <stdio.h>
#include <string.h>
static enum expr_admit_status admit_fail(struct expr_admit_error *error,
 enum expr_admit_status stage,struct expr_error detail)
{
 if(error)*error=(struct expr_admit_error){stage,detail};
 if (stage < EX_ADMIT_VALIDATE) {
  fprintf(stderr, "HUD admission: stage=%u code=%u record=%u: %s\n",
          (unsigned)stage, (unsigned)detail.code, detail.index, detail.reason);
 }
 return stage;
}
static enum expr_status admit_read_bytes(const struct platform_positioned_file *file,
 uint8_t bytes[EXPR_MAX_BYTES],size_t n)
{
 size_t at=0;
 while(at<n) {
  int64_t got=platform_positioned_file_read(file,bytes+at,n-at,at);
  if(got<=0 || (uint64_t)got>n-at)return EX_IO;
  at+=(size_t)got;
 }
 return EX_OK;
}
static enum expr_status admit_read_file(const char *path,struct expr_part *part)
{
 struct platform_positioned_file file;platform_positioned_file_init(&file);
 if(!platform_positioned_file_open(&file,path))return EX_IO;
 struct platform_positioned_file_snapshot before,after;
 enum expr_status status=EX_IO;
 if(platform_positioned_file_snapshot(&file,&before)) {
  status=EX_LIMIT;
  if(before.size<=EXPR_MAX_BYTES) {
   part->length=(size_t)before.size;
   status=admit_read_bytes(&file,part->bytes,part->length);
   if(status==EX_OK && (!platform_positioned_file_snapshot(&file,&after) ||
      !platform_positioned_file_snapshot_equal(&before,&after)))status=EX_IO;
  }
 }
 platform_positioned_file_close(&file);return status;
}
enum expr_admit_status expr_admit_file(const char *path,const uint8_t pin[32],
 const double fields[XF_COUNT],unsigned budget,unsigned ops,unsigned text,
 struct expr_part *current,struct expr_admit_error *error)
{
 if(!path || !*path || !pin || !fields || !current)
  return admit_fail(error,EX_ADMIT_ARGUMENT,(struct expr_error){EX_ARGUMENT,0,"null or empty admission argument"});
 struct expr_part candidate={0};
 enum expr_status status=admit_read_file(path,&candidate);
 if(status!=EX_OK)return admit_fail(error,EX_ADMIT_READ,(struct expr_error){status,0,"bounded regular-file read"});
 zsha256(candidate.bytes,candidate.length,candidate.sha256);
 if(zsha256_compare(candidate.sha256,pin))
  return admit_fail(error,EX_ADMIT_PIN,(struct expr_error){EX_FORMAT,0,"SHA-256 pin mismatch"});
 struct expr_info info;struct expr_error detail={0};
 status=expr_validate(candidate.bytes,candidate.length,&info,&detail);
 if(status!=EX_OK)return admit_fail(error,EX_ADMIT_VALIDATE,detail);
 struct expr_values values;
 status=expr_evaluate(candidate.bytes,candidate.length,fields,budget,&values,&detail);
 if(status!=EX_OK)return admit_fail(error,EX_ADMIT_EVALUATE,detail);
 status=expr_build_draws(candidate.bytes,candidate.length,&values,ops,text,&candidate.recipe,&detail);
 if(status!=EX_OK)return admit_fail(error,EX_ADMIT_DRAW,detail);
 *current=candidate;
 if(error)*error=(struct expr_admit_error){EX_ADMIT_OK,{EX_OK,0,"pinned HUD part admitted"}};
 return EX_ADMIT_OK;
}
