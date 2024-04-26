/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_AlgorithmSpecificInfo_H_
#define	_AlgorithmSpecificInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RFC2507-Info.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AlgorithmSpecificInfo_PR {
	AlgorithmSpecificInfo_PR_NOTHING,	/* No components present */
	AlgorithmSpecificInfo_PR_rfc2507_Info
} AlgorithmSpecificInfo_PR;

/* AlgorithmSpecificInfo */
typedef struct AlgorithmSpecificInfo {
	AlgorithmSpecificInfo_PR present;
	union AlgorithmSpecificInfo_u {
		RFC2507_Info_t	 rfc2507_Info;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AlgorithmSpecificInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AlgorithmSpecificInfo;
extern asn_CHOICE_specifics_t asn_SPC_AlgorithmSpecificInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_AlgorithmSpecificInfo_1[1];
extern asn_per_constraints_t asn_PER_type_AlgorithmSpecificInfo_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _AlgorithmSpecificInfo_H_ */
#include <asn_internal.h>
