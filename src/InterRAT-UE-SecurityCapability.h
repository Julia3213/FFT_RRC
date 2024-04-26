/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterRAT_UE_SecurityCapability_H_
#define	_InterRAT_UE_SecurityCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GsmSecurityCapability.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterRAT_UE_SecurityCapability_PR {
	InterRAT_UE_SecurityCapability_PR_NOTHING,	/* No components present */
	InterRAT_UE_SecurityCapability_PR_gsm
} InterRAT_UE_SecurityCapability_PR;

/* InterRAT-UE-SecurityCapability */
typedef struct InterRAT_UE_SecurityCapability {
	InterRAT_UE_SecurityCapability_PR present;
	union InterRAT_UE_SecurityCapability_u {
		struct InterRAT_UE_SecurityCapability__gsm {
			GsmSecurityCapability_t	 gsmSecurityCapability;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} gsm;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRAT_UE_SecurityCapability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRAT_UE_SecurityCapability;
extern asn_CHOICE_specifics_t asn_SPC_InterRAT_UE_SecurityCapability_specs_1;
extern asn_TYPE_member_t asn_MBR_InterRAT_UE_SecurityCapability_1[1];
extern asn_per_constraints_t asn_PER_type_InterRAT_UE_SecurityCapability_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _InterRAT_UE_SecurityCapability_H_ */
#include <asn_internal.h>