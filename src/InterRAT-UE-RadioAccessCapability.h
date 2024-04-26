/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterRAT_UE_RadioAccessCapability_H_
#define	_InterRAT_UE_RadioAccessCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GSM-Classmark2.h"
#include "GSM-Classmark3.h"
#include <constr_SEQUENCE.h>
#include "CDMA2000-MessageList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterRAT_UE_RadioAccessCapability_PR {
	InterRAT_UE_RadioAccessCapability_PR_NOTHING,	/* No components present */
	InterRAT_UE_RadioAccessCapability_PR_gsm,
	InterRAT_UE_RadioAccessCapability_PR_cdma2000
} InterRAT_UE_RadioAccessCapability_PR;

/* InterRAT-UE-RadioAccessCapability */
typedef struct InterRAT_UE_RadioAccessCapability {
	InterRAT_UE_RadioAccessCapability_PR present;
	union InterRAT_UE_RadioAccessCapability_u {
		struct InterRAT_UE_RadioAccessCapability__gsm {
			GSM_Classmark2_t	 gsm_Classmark2;
			GSM_Classmark3_t	 gsm_Classmark3;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} gsm;
		struct InterRAT_UE_RadioAccessCapability__cdma2000 {
			CDMA2000_MessageList_t	 cdma2000_MessageList;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} cdma2000;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRAT_UE_RadioAccessCapability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRAT_UE_RadioAccessCapability;
extern asn_CHOICE_specifics_t asn_SPC_InterRAT_UE_RadioAccessCapability_specs_1;
extern asn_TYPE_member_t asn_MBR_InterRAT_UE_RadioAccessCapability_1[2];
extern asn_per_constraints_t asn_PER_type_InterRAT_UE_RadioAccessCapability_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _InterRAT_UE_RadioAccessCapability_H_ */
#include <asn_internal.h>
