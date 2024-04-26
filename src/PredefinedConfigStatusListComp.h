/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PredefinedConfigStatusListComp_H_
#define	_PredefinedConfigStatusListComp_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PredefinedConfigSetsWithDifferentValueTag.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PredefinedConfigStatusListVarSz;

/* PredefinedConfigStatusListComp */
typedef struct PredefinedConfigStatusListComp {
	PredefinedConfigSetsWithDifferentValueTag_t	 setsWithDifferentValueTag;
	struct PredefinedConfigStatusListVarSz	*otherEntries	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PredefinedConfigStatusListComp_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PredefinedConfigStatusListComp;
extern asn_SEQUENCE_specifics_t asn_SPC_PredefinedConfigStatusListComp_specs_1;
extern asn_TYPE_member_t asn_MBR_PredefinedConfigStatusListComp_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _PredefinedConfigStatusListComp_H_ */
#include <asn_internal.h>
