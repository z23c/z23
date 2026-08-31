/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Private bounded storage shared by ontology evaluator tiers. */
#ifndef ZCL_ONTOLOGY_INTERNAL_H
#define ZCL_ONTOLOGY_INTERNAL_H

#include "ontology/ontology.h"

enum { ZCL_ONTOLOGY_EVALUATOR_MAGIC = 0x6f6e7431u };

struct zcl_ontology_horn_fact {
    uint8_t arity;
    uint8_t polarity;
    uint8_t reserved[2];
    uint8_t context_root[32];
    uint8_t predicate_root[32];
    uint8_t argument_roots[ZCL_ONTOLOGY_MAX_ARITY][32];
};

struct zcl_ontology_evaluator {
    uint32_t magic;
    bool bound[ZCL_ONTOLOGY_MAX_VARIABLES];
    uint8_t bindings[ZCL_ONTOLOGY_MAX_VARIABLES][32];
    uint8_t predicate_roots[ZCL_ONTOLOGY_MAX_PREDICATES][32];
    size_t horn_fact_count;
    struct zcl_ontology_horn_fact horn_facts[ZCL_ONTOLOGY_MAX_HORN_FACTS];
};

#endif /* ZCL_ONTOLOGY_INTERNAL_H */
