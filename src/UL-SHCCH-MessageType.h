/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Class-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_SHCCH_MessageType_H_
#define	_UL_SHCCH_MessageType_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PUSCHCapacityRequest.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_SHCCH_MessageType_PR {
	UL_SHCCH_MessageType_PR_NOTHING,	/* No components present */
	UL_SHCCH_MessageType_PR_puschCapacityRequest,
	UL_SHCCH_MessageType_PR_spare
} UL_SHCCH_MessageType_PR;

/* UL-SHCCH-MessageType */
typedef struct UL_SHCCH_MessageType {
	UL_SHCCH_MessageType_PR present;
	union UL_SHCCH_MessageType_u {
		PUSCHCapacityRequest_t	 puschCapacityRequest;
		NULL_t	 spare;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_SHCCH_MessageType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_SHCCH_MessageType;
extern asn_CHOICE_specifics_t asn_SPC_UL_SHCCH_MessageType_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_SHCCH_MessageType_1[2];
extern asn_per_constraints_t asn_PER_type_UL_SHCCH_MessageType_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_SHCCH_MessageType_H_ */
#include <asn_internal.h>
