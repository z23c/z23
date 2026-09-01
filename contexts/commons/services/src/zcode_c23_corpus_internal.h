/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private fixed labels for the pure C23 corpus status island. */

#ifndef ZCL_ZCODE_C23_CORPUS_INTERNAL_H
#define ZCL_ZCODE_C23_CORPUS_INTERNAL_H

#define ZCODE_C23_CORPUS_STAGE_MISSING "checkpoint_missing"
#define ZCODE_C23_CORPUS_STAGE_INVALID "checkpoint_invalid"
#define ZCODE_C23_CORPUS_STAGE_BELOW_50M "below_50m"
#define ZCODE_C23_CORPUS_STAGE_HOSTING "hosting_incomplete"
#define ZCODE_C23_CORPUS_STAGE_DURABLE_50M "durable_50m_lower_bound"
#define ZCODE_C23_CORPUS_STAGE_DURABLE_100M "durable_100m_lower_bound"
#define ZCODE_C23_CORPUS_NEXT_VERIFY "zcode commons corpus verify"
#define ZCODE_C23_CORPUS_NEXT_CREATE "zcode package guide"
#define ZCODE_C23_CORPUS_NEXT_HOST "zcode storage status"
#define ZCODE_C23_CORPUS_NEXT_IMPACT "zcode commons impact status"
#define ZCODE_C23_IMPACT_MISSING_WORK "blocked:proven_work_missing"
#define ZCODE_C23_IMPACT_MISSING_ACCEPTANCE "blocked:acceptance_missing"
#define ZCODE_C23_IMPACT_MISSING_RELEASE "blocked:signed_release_missing"
#define ZCODE_C23_IMPACT_MISSING_ADMISSION "blocked:family_admission_missing"
#define ZCODE_C23_IMPACT_MISSING_PACKAGE "blocked:package_unavailable"
#define ZCODE_C23_IMPACT_STALE "blocked:basis_stale"
#define ZCODE_C23_IMPACT_READY "ready:shareable"

#endif /* ZCL_ZCODE_C23_CORPUS_INTERNAL_H */
